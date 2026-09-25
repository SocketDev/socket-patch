//! `vendor --vendor-source build` on a gem the project only has in its
//! lockfile.
//!
//! The local gem build needs the eval-able stub gemspec rubygems writes
//! into `<gem home>/specifications/` when the gem is INSTALLED — a bundler
//! path source will not load without one, and a downloaded `.gem` carries
//! its gemspec only as YAML in `metadata.gz` (the vendoring service's
//! converter is what turns that into the Ruby form, and serves it as the
//! `gem-stub-gemspec` second artifact). So build mode cannot vendor a
//! fetched gem, ever — yet the auto-fetch rung downloaded the `.gem` from
//! the registry first and only then hit the backend's `gem_spec_missing`
//! refusal. The download is pure waste on every run.
//!
//! The refusal now happens BEFORE the fetch, with a message that says why
//! and what to do. `auto` (and `service`) still fetch: the service path
//! needs the staged dir, and that is the mode that CAN vendor this gem.
//!
//! Hermetic: a `wiremock` stand-in for the rubygems download host, named by
//! the lock's `remote:`, and a `.socket/blobs` entry so patch staging never
//! reaches the API.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A name nothing on the developer's machine can have installed, so the
/// crawler always reports the package missing.
const NAME: &str = "socketfixturegem";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:gem/socketfixturegem@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const LIB: &str = "lib/socketfixturegem.rb";
const PRISTINE: &[u8] = b"module SocketFixtureGem; VERSION = '1.0.0'; end\n";
const PATCHED: &[u8] = b"module SocketFixtureGem; VERSION = '1.0.0'; SAFE = true; end\n";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// A minimal `.gem`: an uncompressed tar whose only entry the fetcher reads
/// is `data.tar.gz`, itself a gzipped tar of the gem's files at the root.
fn make_gem() -> Vec<u8> {
    let mut data = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(PRISTINE.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    data.append_data(&mut header, LIB, PRISTINE).unwrap();
    let data_tar = data.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &data_tar).unwrap();
    let data_tar_gz = gz.finish().unwrap();

    let mut gem = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(data_tar_gz.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    gem.append_data(&mut header, "data.tar.gz", data_tar_gz.as_slice())
        .unwrap();
    gem.into_inner().unwrap()
}

/// Gemfile + a bundler >= 2.6 Gemfile.lock resolving the gem against
/// `remote` with a CHECKSUMS pin (the fetch layer refuses an entry with no
/// verifier, so without this nothing would ever be downloaded), plus the
/// manifest and staged after-blob.
fn write_fixture(root: &Path, remote: &str, gem_sha256: &str) {
    std::fs::write(
        root.join("Gemfile"),
        format!("source \"{remote}\"\ngem \"{NAME}\"\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: {remote}\n  specs:\n    {NAME} ({VERSION})\n\n\
             PLATFORMS\n  ruby\n\n\
             DEPENDENCIES\n  {NAME}\n\n\
             CHECKSUMS\n  {NAME} ({VERSION}) sha256={gem_sha256}\n\n\
             BUNDLED WITH\n   2.6.2\n"
        ),
    )
    .unwrap();

    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    LIB: {
                        "beforeHash": git_sha256(PRISTINE),
                        "afterHash": git_sha256(PATCHED),
                    }
                },
                "vulnerabilities": {},
                "description": "synthetic gem vendor test patch",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(PATCHED)), PATCHED).unwrap();
}

async fn mount_gem_download(mock: &MockServer, gem: Vec<u8>) {
    Mock::given(method("GET"))
        .and(wm_path(format!("/downloads/{NAME}-{VERSION}.gem")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(gem))
        .mount(mock)
        .await;
}

/// `vendor --json --vendor-source <source>` through the built binary, with
/// every ambient `SOCKET_*` var scrubbed and the API pointed at a
/// guaranteed-dead endpoint (patch staging is satisfied from
/// `.socket/blobs`, so nothing should reach it).
fn run_vendor(root: &Path, source: &str, api_url: &str) -> (i32, serde_json::Value, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "vendor",
        "--json",
        "--vendor-source",
        source,
        "--api-url",
        api_url,
        "--proxy-url",
        api_url,
        "--api-token",
        "fake-token",
        "--org",
        "test-org",
    ])
    .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch vendor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("vendor --json must emit JSON: {e}\n{stdout}\n{stderr}"));
    (out.status.code().unwrap_or(-1), v, stderr)
}

/// A guaranteed-unreachable local endpoint: bind an ephemeral port, then
/// release it, so every request fails fast with connection-refused.
fn dead_endpoint() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("http://127.0.0.1:{port}")
}

fn failed_event(v: &serde_json::Value) -> &serde_json::Value {
    v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|e| e["action"] == "failed")
        .unwrap_or_else(|| panic!("expected a failed event in:\n{v:#}"))
}

#[tokio::test]
async fn build_mode_refuses_a_lockfile_only_gem_before_downloading_it() {
    let mock = MockServer::start().await;
    let gem = make_gem();
    let sha = hex::encode(Sha256::digest(&gem));
    mount_gem_download(&mock, gem).await;

    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), &mock.uri(), &sha);

    let (code, v, stderr) = run_vendor(tmp.path(), "build", &dead_endpoint());

    assert_eq!(code, 1, "the refusal fails the run: {v:#}\n{stderr}");
    assert!(
        mock.received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "build mode cannot use a fetched gem, so it must not download one"
    );
    let failed = failed_event(&v);
    assert_eq!(failed["purl"], PURL, "{v:#}");
    assert_eq!(
        failed["errorCode"], "gem_spec_missing",
        "the backend's own refusal code, raised earlier: {v:#}"
    );
    let detail = failed["error"].as_str().unwrap_or_default();
    assert!(
        detail.contains("not installed") && detail.contains("--vendor-source"),
        "the refusal must say why and name the remedy: {detail}"
    );
    assert!(
        !tmp.path().join(".socket/vendor").exists(),
        "nothing is written: {v:#}"
    );
    let lock = std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap();
    assert!(lock.contains("GEM\n"), "the lock is untouched: {lock}");
}

/// The gate is scoped to build-only runs: `auto` may still vendor this gem
/// through the patch service, and the service path needs the fetched copy
/// staged, so the download must still happen there.
#[tokio::test]
async fn auto_mode_still_fetches_a_lockfile_only_gem() {
    let mock = MockServer::start().await;
    let gem = make_gem();
    let sha = hex::encode(Sha256::digest(&gem));
    mount_gem_download(&mock, gem).await;

    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), &mock.uri(), &sha);

    // The patch service is unreachable, so `auto` falls back to the local
    // build and lands on the same refusal — AFTER the fetch, which is the
    // behavior this mode needs.
    let (code, v, stderr) = run_vendor(tmp.path(), "auto", &dead_endpoint());

    assert_eq!(code, 1, "{v:#}\n{stderr}");
    assert_eq!(failed_event(&v)["purl"], PURL, "{v:#}");
    assert_eq!(
        mock.received_requests().await.unwrap_or_default().len(),
        1,
        "auto must still stage the pristine gem for the service path"
    );
}

/// The gate is also scoped to gems a fetch would actually be attempted for.
/// A gem that no lockfile resolves and no ledger entry recovers has nothing
/// to fetch and nothing to say about gemspecs: it keeps the calm
/// `package_not_installed` skip, not a gemspec refusal.
#[tokio::test]
async fn a_gem_that_resolves_from_nowhere_still_reports_not_installed() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), "https://rubygems.org", &"0".repeat(64));
    // No lockfile at all: nothing resolves the gem.
    std::fs::remove_file(tmp.path().join("Gemfile.lock")).unwrap();

    let (code, v, stderr) = run_vendor(tmp.path(), "build", &dead_endpoint());

    assert_eq!(code, 1, "{v:#}\n{stderr}");
    let event = v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|e| e["purl"] == PURL)
        .unwrap_or_else(|| panic!("expected an event for {PURL} in:\n{v:#}"));
    assert_eq!(event["action"], "skipped", "{v:#}");
    assert_eq!(event["errorCode"], "package_not_installed", "{v:#}");
}
