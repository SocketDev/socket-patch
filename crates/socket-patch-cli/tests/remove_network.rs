//! Network-path tests for `remove`'s internal rollback.
//!
//! `remove` rolls back files before deleting from the manifest, and
//! rollback fetches any missing `beforeHash` blobs from the API. Two
//! contractual behaviours are exercised here against a wiremock server:
//!
//!   1. **online (default):** a missing `beforeHash` blob is downloaded,
//!      rollback succeeds (no package installed → nothing to restore),
//!      and the manifest entry is dropped.
//!   2. **`--offline`:** the strict-airgap contract ("never contact the
//!      network on *any* command") must hold. With a missing blob,
//!      `remove --offline` must refuse to roll back rather than reach out,
//!      and therefore must leave the manifest entry intact.
//!
//! Regression guard: `remove` previously hard-coded `offline = false`
//! when delegating to `rollback_patches`, so `--offline` was silently
//! ignored — the binary would contact the mock, succeed, and delete the
//! entry. Test (2) fails loudly if that bug returns.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const PURL: &str = "pkg:npm/remove-network-test@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_manifest(socket: &Path, before_hash: &str, after_hash: &str) {
    std::fs::create_dir_all(socket).expect("create .socket");
    let body = format!(
        r#"{{
  "patches": {{
    "{PURL}": {{
      "uuid": "{UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash":  "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "remove network test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), body).expect("write manifest");
}

fn manifest_has_entry(socket: &Path) -> bool {
    let body = std::fs::read_to_string(socket.join("manifest.json")).expect("read manifest");
    let v: serde_json::Value = serde_json::from_str(&body).expect("parse manifest");
    v["patches"]
        .as_object()
        .map(|m| m.contains_key(PURL))
        .unwrap_or(false)
}

/// Mount the blob endpoint that rollback's `fetch_blobs_by_hash` hits for
/// the missing `beforeHash`. Serving the real bytes lets the online path
/// (and, if the offline bug regressed, the offline path too) succeed.
async fn mount_before_blob(mock: &MockServer, before: &[u8], before_hash: &str) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{before_hash}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(before.to_vec()))
        .mount(mock)
        .await;
}

fn run_remove(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String) {
    let mut argv: Vec<&str> = vec!["remove", PURL, "--json", "--yes"];
    argv.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&argv)
        .current_dir(cwd)
        .env("SOCKET_API_URL", api_url)
        .env("SOCKET_API_TOKEN", "fake-token-for-test")
        .env("SOCKET_ORG_SLUG", ORG_SLUG)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

/// Online sanity: a missing beforeHash blob is fetched, rollback finds no
/// installed package (nothing to restore → success), and the entry is
/// removed. Establishes that the mock can satisfy the download, which is
/// what gives the `--offline` regression test (below) its teeth.
#[tokio::test]
async fn remove_online_downloads_missing_before_blob_then_removes() {
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let mock = MockServer::start().await;
    mount_before_blob(&mock, before, &before_hash).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    write_manifest(&socket, &before_hash, &after_hash);

    let (code, stdout) = run_remove(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "online remove must succeed; stdout=\n{stdout}");
    assert!(
        !manifest_has_entry(&socket),
        "online remove must drop the manifest entry; stdout=\n{stdout}"
    );

    // The whole point of this test (and what gives the `--offline` test its
    // teeth) is that the online path ACTUALLY downloads the missing blob.
    // Verify the mock was hit for the exact beforeHash; a path that succeeds
    // without ever fetching would otherwise leave this guarantee unproven.
    let blob_path = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{before_hash}");
    let reqs = mock
        .received_requests()
        .await
        .expect("wiremock request recording must be enabled");
    let fetched = reqs.iter().filter(|r| r.url.path() == blob_path).count();
    assert!(
        fetched >= 1,
        "online remove must fetch the missing beforeHash blob ({blob_path}); \
         observed request paths={:?}",
        reqs.iter().map(|r| r.url.path().to_string()).collect::<Vec<_>>()
    );
}

/// `--offline` must NOT contact the network: with the beforeHash blob
/// missing, rollback cannot proceed, so `remove --offline` aborts and
/// leaves the manifest entry in place. The mock IS armed to serve the
/// blob — if `--offline` were ignored (the original bug) the binary would
/// download it, succeed, and delete the entry, flipping both assertions.
#[tokio::test]
async fn remove_offline_does_not_fetch_and_keeps_entry() {
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let mock = MockServer::start().await;
    mount_before_blob(&mock, before, &before_hash).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    write_manifest(&socket, &before_hash, &after_hash);

    let (code, stdout) = run_remove(tmp.path(), &mock.uri(), &["--offline"]);
    assert_eq!(
        code, 1,
        "remove --offline with a missing blob must fail rollback; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["error"]["code"], "rollback_failed");
    assert!(
        manifest_has_entry(&socket),
        "remove --offline must NOT delete the entry when rollback can't run; stdout=\n{stdout}"
    );

    // The strict-airgap contract is "never contact the network on ANY
    // command". Exit code + preserved entry alone don't prove that: a
    // regressed binary could fetch the (armed) blob and still fail rollback
    // downstream for some other reason. Assert the mock saw NO traffic at
    // all — this is what actually makes the test name ("does_not_fetch")
    // true and catches the original `offline = false` hardcode.
    let reqs = mock
        .received_requests()
        .await
        .expect("wiremock request recording must be enabled");
    assert!(
        reqs.is_empty(),
        "remove --offline must not contact the network at all; observed requests={:?}",
        reqs.iter()
            .map(|r| (r.method.to_string(), r.url.path().to_string()))
            .collect::<Vec<_>>()
    );
}
