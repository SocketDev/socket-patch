//! In-process full-apply test for the cargo (Rust) ecosystem.
//!
//! Adds `cfg-if = "=1.0.0"` to a Cargo.toml, runs `cargo fetch` against
//! an isolated `CARGO_HOME`, then mocks a synthetic patch over the
//! real downloaded `src/lib.rs` bytes and runs in-process apply.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "14141414-1414-4141-8141-141414141414";
const CRATE_NAME: &str = "cfg-if";
const CRATE_VERSION: &str = "1.0.0";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn has_cargo() -> bool {
    Command::new("cargo")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Create a small Cargo project with `cfg-if` as a dep, then `cargo
/// fetch` to populate `CARGO_HOME/registry/src/`. Returns the path
/// to the downloaded `src/lib.rs` and the isolated CARGO_HOME.
fn fetch_cfg_if(tmp: &Path) -> (PathBuf, PathBuf) {
    let project = tmp.join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("Cargo.toml"),
        format!(
            r#"[package]
name = "e2e"
version = "0.0.1"
edition = "2021"

[dependencies]
{CRATE_NAME} = "={CRATE_VERSION}"
"#
        ),
    )
    .unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(project.join("src/main.rs"), "fn main() {}\n").unwrap();

    let cargo_home = tmp.join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();

    let status = Command::new("cargo")
        .args(["fetch", "--manifest-path"])
        .arg(project.join("Cargo.toml"))
        .env("CARGO_HOME", &cargo_home)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("cargo fetch");
    assert!(
        status.status.success(),
        "cargo fetch failed: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    // Find the crate's src/lib.rs under CARGO_HOME/registry/src/<index>/cfg-if-1.0.0/src/lib.rs
    let src_root = cargo_home.join("registry/src");
    for entry in std::fs::read_dir(&src_root).expect("registry/src").flatten() {
        let candidate = entry
            .path()
            .join(format!("{CRATE_NAME}-{CRATE_VERSION}"))
            .join("src/lib.rs");
        if candidate.exists() {
            return (candidate, cargo_home);
        }
    }
    panic!(
        "{CRATE_NAME}-{CRATE_VERSION}/src/lib.rs not found under {}",
        src_root.display()
    );
}

async fn setup_cargo_apply_mock(
    server: &MockServer,
    before_hash: &str,
    after_hash: &str,
    patched_bytes: &[u8],
) {
    let purl = format!("pkg:cargo/{CRATE_NAME}@{CRATE_VERSION}");
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(patched_bytes);

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "low", "title": "cargo e2e fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    // file path "package/src/lib.rs" — npm-style prefix because the
    // crawler returns the crate dir as pkg_path, and normalize_file_path
    // strips "package/" to leave "src/lib.rs".
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/src/lib.rs": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "cargo e2e fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// Read-only files in cargo's registry need to be made writable before
/// apply can overwrite them. The apply code does this on Unix but the
/// test's setup can also pre-emptively chmod.
fn make_writable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mut perms = meta.permissions();
            let mode = perms.mode();
            perms.set_mode(mode | 0o200);
            let _ = std::fs::set_permissions(path, perms);
        }
    }
}

#[tokio::test]
#[serial]
async fn cargo_fetch_scan_sync_patches_real_file() {
    if !has_cargo() {
        println!("SKIP: cargo not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let (lib_file, cargo_home) = fetch_cfg_if(tmp.path());
    let original = std::fs::read(&lib_file).expect("read lib.rs");
    let before_hash = git_sha256(&original);
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-E2E-MARKER\n");
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    setup_cargo_apply_mock(&server, &before_hash, &after_hash, &patched).await;

    // Cargo's registry source files are read-only by default; make
    // writable so apply can overwrite.
    make_writable(&lib_file);

    let args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().join("proj"),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: true,
            // use global registry; cargo crawler then probes CARGO_HOME
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["cargo".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: true,
        all_releases: false,
        vex: Default::default(),
    };
    // CARGO_HOME must be set in this process's env so the cargo crawler
    // probes the isolated location (not the developer's real ~/.cargo).
    std::env::set_var("CARGO_HOME", &cargo_home);

    let code = scan_run(args).await;
    assert!(code == 0 || code == 1, "scan --sync exit: {code}");

    let after = std::fs::read(&lib_file).expect("read after");
    // The marker should be in the file. If the apply path didn't run
    // through (e.g., crawler scoped elsewhere), this fails loudly.
    assert!(
        after.windows(b"SOCKET-PATCH-E2E-MARKER".len())
            .any(|w| w == b"SOCKET-PATCH-E2E-MARKER"),
        "marker not found in {} after apply; file size: {}",
        lib_file.display(),
        after.len(),
    );

    // Restore the env var (don't leak across tests).
    std::env::remove_var("CARGO_HOME");
}

#[tokio::test]
#[serial]
async fn cargo_crawler_finds_real_fetched_crate() {
    if !has_cargo() {
        println!("SKIP: cargo not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, cargo_home) = fetch_cfg_if(tmp.path());

    let server = MockServer::start().await;
    let purl = format!("pkg:cargo/{CRATE_NAME}@{CRATE_VERSION}");
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "low",
                    "title": "discovery sanity"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    std::env::set_var("CARGO_HOME", &cargo_home);
    let args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().join("proj"),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: true,
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["cargo".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
        all_releases: false,
        vex: Default::default(),
    };
    assert_eq!(scan_run(args).await, 0);
    std::env::remove_var("CARGO_HOME");
}
