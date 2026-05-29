//! In-process full-apply test for the gem (Ruby) ecosystem.
//!
//! Real `gem install` → hash real installed file → mock patch with
//! matching hashes → in-process `scan --sync` → assert marker in
//! installed gem file on disk.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "13131313-1313-4131-8131-131313131313";
const GEM_NAME: &str = "colorize";
const GEM_VERSION: &str = "1.1.0";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn has_gem() -> bool {
    Command::new("gem")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ruby_version() -> Option<String> {
    let out = Command::new("ruby")
        .arg("-e")
        .arg(r#"puts RUBY_VERSION.split('.').take(2).join('.') + '.0'"#)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

/// Install a small gem into `<tmp>/vendor/bundle/ruby/<ver>/` and
/// return the path to the gem's main lib file.
fn install_colorize(tmp: &Path) -> PathBuf {
    let ver = ruby_version().expect("ruby not on PATH");
    let install_dir = tmp.join(format!("vendor/bundle/ruby/{ver}"));
    std::fs::create_dir_all(&install_dir).expect("create install dir");

    let status = Command::new("gem")
        .args([
            "install",
            "--no-document",
            "--install-dir",
            install_dir.to_str().unwrap(),
            GEM_NAME,
            "-v",
            GEM_VERSION,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("gem install");
    assert!(
        status.status.success(),
        "gem install failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );

    let gem_dir = install_dir
        .join("gems")
        .join(format!("{GEM_NAME}-{GEM_VERSION}"));
    let lib_file = gem_dir.join("lib/colorize.rb");
    assert!(
        lib_file.exists(),
        "expected installed file at {}",
        lib_file.display()
    );
    lib_file
}

async fn setup_gem_apply_mock(
    server: &MockServer,
    file_in_patch: &str,
    before_hash: &str,
    after_hash: &str,
    patched_bytes: &[u8],
) {
    let purl = format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}");
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(patched_bytes);

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": UUID, "purl": purl,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "medium", "title": "gem e2e fixture"
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

    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                file_in_patch: {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "gem e2e fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// Real install → scan --sync → verify marker on disk
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn gem_install_scan_sync_patches_real_file() {
    if !has_gem() {
        println!("SKIP: gem not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let lib_file = install_colorize(tmp.path());
    let original = std::fs::read(&lib_file).expect("read colorize.rb");
    let before_hash = git_sha256(&original);

    let mut patched = original.clone();
    patched.extend_from_slice(b"\n# SOCKET-PATCH-E2E-MARKER\n");
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    // gem patches use `package/<rel>` prefix per the normalize_file_path
    // convention (strip "package/" before joining with the gem dir).
    setup_gem_apply_mock(
        &server,
        "package/lib/colorize.rb",
        &before_hash,
        &after_hash,
        &patched,
    )
    .await;

    let args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["gem".to_string()]),
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
    let code = scan_run(args).await;
    assert!(code == 0 || code == 1, "scan --sync exit: {code}");

    let after = std::fs::read(&lib_file).expect("read after");
    assert!(
        after.windows(b"SOCKET-PATCH-E2E-MARKER".len())
            .any(|w| w == b"SOCKET-PATCH-E2E-MARKER"),
        "marker not found in {}", lib_file.display()
    );
}

#[tokio::test]
#[serial]
async fn gem_crawler_finds_real_installed_gem() {
    if !has_gem() {
        println!("SKIP: gem not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().expect("tempdir");
    let _ = install_colorize(tmp.path());

    let server = MockServer::start().await;
    let purl = format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}");
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

    let args = ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["gem".to_string()]),
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
}
