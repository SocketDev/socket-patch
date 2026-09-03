//! Regression: a corrupt `.socket/vendor/state.json` must not defeat the
//! vendored prune safeguards. With the ledger unreadable, BOTH protection
//! legs used to degrade to empty — `vendored_ledger_supplement` (discovery)
//! silently returned no packages, so the vendored purls never entered
//! `scanned_purls`, and core's `vendored_purl_keys` prune exemption is
//! fail-open by contract — so `scan --prune` deleted a still-vendored
//! package's manifest entry and swept its blobs while the committed
//! artifacts remained. The fix recovers the vendored set from the committed
//! ground truth: manifest entries whose patch uuid owns a live
//! `.socket/vendor/<eco>/<uuid>` artifact dir.
//!
//! Modeled on `scan_vendor_e2e.rs` (mock API + real fixture through the
//! built binary).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
/// The vendored cargo patch: uuid + purl of the entry that must survive.
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const CARGO_PURL: &str = "pkg:cargo/foo@1.0.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// One installed npm package so the crawl finds ≥1 package and scan does
/// not take the zero-package early return (which skips the GC entirely).
fn write_npm_fixture(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "corrupt-ledger-test", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// The committed state of a vendored cargo dependency: manifest entry +
/// referenced blob + the contract-path artifact dir — plus a corrupt
/// vendor ledger (a bad merge-conflict resolution / truncation).
fn seed_vendored_cargo_with_corrupt_ledger(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            CARGO_PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "src/lib.rs": {
                        "beforeHash": git_sha256(BEFORE),
                        "afterHash": git_sha256(AFTER),
                    }
                },
                "vulnerabilities": {},
                "description": "vendored cargo patch",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // The committed artifact at the contract path.
    let artifact = socket.join(format!("vendor/cargo/{UUID}/foo-1.0.0"));
    std::fs::create_dir_all(&artifact).unwrap();
    std::fs::write(artifact.join("Cargo.toml"), b"[package]\nname = \"foo\"\n").unwrap();

    // Truncated ledger: not valid JSON, so load_state errs (fail-closed).
    std::fs::write(socket.join("vendor/state.json"), b"{\"entries\": {").unwrap();
}

/// Spawn the built binary in `root` with the ambient `SOCKET_*` surface
/// scrubbed and telemetry killed (same posture as `scan_vendor_e2e.rs`).
fn run_cli(root: &Path, argv: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(argv).current_dir(root);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A batch endpoint reporting NO available patches for the scanned set.
async fn mount_empty_discovery(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

/// `scan --prune` on a fresh clone whose vendor ledger is corrupt: the
/// vendored package's manifest entry and blob must survive the GC. Before
/// the fix, discovery's ledger supplement silently returned empty, the
/// prune exemption was also empty, and the entry + blob were deleted while
/// the committed artifacts remained.
#[tokio::test]
async fn corrupt_ledger_scan_prune_keeps_vendored_manifest_entry() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_npm_fixture(tmp.path());
    seed_vendored_cargo_with_corrupt_ledger(tmp.path());

    let uri = mock.uri();
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &[
            "scan",
            "--json",
            "--prune",
            "--api-url",
            &uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");

    // The GC must not report the vendored entry as pruned…
    let pruned = v["gc"]["prunedManifestEntries"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        !pruned.iter().any(|p| p == CARGO_PURL),
        "corrupt ledger: the vendored entry must not be pruned; gc={}",
        v["gc"]
    );

    // …the manifest entry must survive on disk…
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(
        manifest["patches"][CARGO_PURL].is_object(),
        "vendored manifest entry deleted despite committed artifacts; manifest={manifest}"
    );

    // …and its blob must not be swept as an orphan.
    assert!(
        tmp.path()
            .join(".socket/blobs")
            .join(git_sha256(AFTER))
            .is_file(),
        "vendored entry's blob was swept"
    );
}
