//! A diff archive only carries deltas for files that exist before the
//! patch: a file the patch CREATES (empty `beforeHash`) has nothing to
//! diff against, so the patch service leaves it out and the pipeline can
//! only apply it from its after-blob (or a package archive). These tests
//! pin that the disk stager and `repair` both treat a diff archive as
//! covering only the files it can actually patch:
//!
//!   - `apply --offline` with just the diff archive on disk fails closed
//!     with the "no local source" report and leaves every file untouched,
//!     instead of passing the gate and failing mid-apply;
//!   - online `apply` with the diff archive cached still fetches the
//!     created file's blob;
//!   - a default (diff-mode) `repair` also downloads the created file's
//!     blob, so a later `apply --offline` succeeds.

use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::write::GzEncoder;
use flate2::Compression;
use qbsdiff::Bsdiff;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";
const UUID: &str = "67676767-6767-4767-8767-676767676767";
const PURL: &str = "pkg:npm/created-file-test@1.0.0";
const BEFORE: &[u8] = b"module.exports = 'before, and long enough to diff';\n";
const AFTER: &[u8] = b"module.exports = 'after!, and long enough to diff';\n";
const CREATED: &[u8] = b"module.exports = 'a brand new file';\n";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn run_cli(root: &Path, argv: &[&str], mock_uri: Option<&str>) -> (i32, String, String) {
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
    // Offline runs get a dead endpoint: any request they make fails.
    let api_url = mock_uri.unwrap_or("http://127.0.0.1:1");
    cmd.env("SOCKET_API_URL", api_url)
        .env("SOCKET_API_TOKEN", "fake-token-for-test")
        .env("SOCKET_ORG_SLUG", ORG_SLUG);
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The diff archive the service serves for this patch: a bsdiff delta for
/// the modified file and nothing for the created one.
fn diff_archive() -> Vec<u8> {
    let mut delta = Vec::new();
    Bsdiff::new(BEFORE, AFTER)
        .compare(std::io::Cursor::new(&mut delta))
        .unwrap();
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    let mut header = tar::Header::new_gnu();
    header.set_size(delta.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "index.js", delta.as_slice())
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

/// An npm project with the unpatched package installed and a manifest
/// whose patch modifies `index.js` and creates `new.js` (sorted after
/// `index.js`, so a mid-apply failure would leave `index.js` patched). Returns the
/// installed package dir.
fn seed_project(root: &Path) -> PathBuf {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"created-file-root","version":"0.0.0"}"#,
    )
    .unwrap();
    let pkg = root.join("node_modules").join("created-file-test");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"created-file-test","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "patches": {
                PURL: {
                    "uuid": UUID,
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": {
                        "package/index.js": {
                            "beforeHash": git_sha256(BEFORE),
                            "afterHash": git_sha256(AFTER),
                        },
                        "package/new.js": {
                            "beforeHash": "",
                            "afterHash": git_sha256(CREATED),
                        }
                    },
                    "vulnerabilities": {},
                    "description": "creates a file",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    pkg
}

fn seed_cached_diff_archive(root: &Path) {
    let diffs = root.join(".socket").join("diffs");
    std::fs::create_dir_all(&diffs).unwrap();
    std::fs::write(diffs.join(format!("{UUID}.tar.gz")), diff_archive()).unwrap();
}

async fn mount_blob(mock: &MockServer, content: &'static [u8]) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{}",
            git_sha256(content)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .mount(mock)
        .await;
}

fn assert_fully_patched(pkg: &Path) {
    assert_eq!(std::fs::read(pkg.join("index.js")).unwrap(), AFTER);
    assert_eq!(std::fs::read(pkg.join("new.js")).unwrap(), CREATED);
}

#[test]
fn offline_apply_with_only_a_diff_archive_reports_the_created_file_gap() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = seed_project(tmp.path());
    seed_cached_diff_archive(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &["apply", "--offline"], None);

    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        std::fs::read(pkg.join("index.js")).unwrap(),
        BEFORE,
        "a patch that cannot fully apply must not be applied partway"
    );
    assert!(!pkg.join("new.js").exists());
    assert!(
        stderr.contains("1 patch has no local source and --offline is set:")
            && stderr.contains(PURL)
            && stderr.contains("socket-patch repair"),
        "the offline gate names the patch and the remedy; stderr={stderr}"
    );
}

#[tokio::test]
async fn online_apply_with_a_cached_diff_archive_fetches_the_created_files_blob() {
    let mock = MockServer::start().await;
    mount_blob(&mock, CREATED).await;

    let tmp = tempfile::tempdir().unwrap();
    let pkg = seed_project(tmp.path());
    seed_cached_diff_archive(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &["apply"], Some(&mock.uri()));

    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert_fully_patched(&pkg);
    let requested: Vec<String> = mock
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    assert!(
        !requested
            .iter()
            .any(|p| p.contains("/patches/blob/") && p.ends_with(&git_sha256(AFTER))),
        "the modified file's blob is not needed: its delta applies; requested={requested:?}"
    );
}

#[tokio::test]
async fn default_repair_downloads_the_created_files_blob_for_offline_apply() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/diff/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(diff_archive()))
        .mount(&mock)
        .await;
    mount_blob(&mock, CREATED).await;

    let tmp = tempfile::tempdir().unwrap();
    let pkg = seed_project(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &["repair"], Some(&mock.uri()));
    assert_eq!(code, 0, "repair: stdout={stdout}\nstderr={stderr}");
    let blobs = tmp.path().join(".socket").join("blobs");
    assert!(
        blobs.join(git_sha256(CREATED)).exists(),
        "repair must cache the created file's blob; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        !blobs.join(git_sha256(AFTER)).exists(),
        "the modified file's delta covers it; its blob is not downloaded"
    );

    let (code, stdout, stderr) = run_cli(tmp.path(), &["apply", "--offline"], None);
    assert_eq!(code, 0, "apply: stdout={stdout}\nstderr={stderr}");
    assert_fully_patched(&pkg);
}

#[test]
fn offline_repair_names_the_created_files_missing_blob() {
    let tmp = tempfile::tempdir().unwrap();
    seed_project(tmp.path());
    seed_cached_diff_archive(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &["repair", "--offline"], None);

    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("All diff archives are present locally."),
        "stdout={stdout}"
    );
    let short: String = git_sha256(CREATED).chars().take(12).collect();
    assert!(
        stderr.contains("Warning: 1 blob is missing (offline mode - not downloading):")
            && stderr.contains(&short),
        "the created file's blob is still missing; stderr={stderr}"
    );
}

#[tokio::test]
async fn repair_json_reports_the_created_blob_download_once_as_file_mode() {
    let mock = MockServer::start().await;
    mount_blob(&mock, CREATED).await;
    let tmp = tempfile::tempdir().unwrap();
    seed_project(tmp.path());
    seed_cached_diff_archive(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &["repair", "--json"], Some(&mock.uri()));
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let downloads: Vec<&serde_json::Value> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "downloaded")
        .collect();
    assert_eq!(downloads.len(), 1, "{v:#}");
    assert_eq!(downloads[0]["details"]["downloadMode"], "file", "{v:#}");
    assert_eq!(downloads[0]["details"]["count"], 1, "{v:#}");
}
