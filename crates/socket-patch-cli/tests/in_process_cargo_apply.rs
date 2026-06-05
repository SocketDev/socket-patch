#![cfg(feature = "cargo")]
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

    // Sanity: the fixture must actually change the file, otherwise the
    // "marker present" assertion below would be vacuously satisfiable.
    assert_ne!(original, patched, "patched fixture must differ from original");
    assert_ne!(before_hash, after_hash, "before/after hashes must differ");
    // Pristine pre-check: the marker must NOT already be on disk, so its
    // later presence can only come from a real apply writing `patched`.
    assert!(
        !original
            .windows(b"SOCKET-PATCH-E2E-MARKER".len())
            .any(|w| w == b"SOCKET-PATCH-E2E-MARKER"),
        "fixture file already contained the marker before apply"
    );

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
    // A successful sync-apply over a writable registry file must exit 0.
    // Accepting `0 || 1` would let a fully-failed apply pass.
    assert_eq!(code, 0, "scan --sync should succeed (exit 0)");

    // Prove the real apply path ran end-to-end: the crawler must have
    // discovered cfg-if (POST batch), and the apply must have fetched the
    // patch blob (GET view/<uuid>). Without these, a no-op that left the
    // file untouched could otherwise sneak through.
    let requests = server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let purl = format!("pkg:cargo/{CRATE_NAME}@{CRATE_VERSION}");
    let hit_batch = requests.iter().any(|r| {
        r.url.path().ends_with("/patches/batch")
            && String::from_utf8_lossy(&r.body).contains(&purl)
    });
    let hit_view = requests
        .iter()
        .any(|r| r.url.path().ends_with(&format!("/patches/view/{UUID}")));
    assert!(hit_batch, "crawler never sent cfg-if to the batch endpoint");
    assert!(hit_view, "apply never fetched the patch blob (view/<uuid>)");

    let after = std::fs::read(&lib_file).expect("read after");
    // The applied file must be byte-for-byte the patched fixture (not just
    // "contains the marker somewhere" — that tolerates partial/garbled
    // writes), and its git-sha256 must equal the advertised afterHash.
    assert_eq!(
        after,
        patched,
        "applied file does not match the patched fixture (size: {})",
        after.len()
    );
    assert_eq!(
        git_sha256(&after),
        after_hash,
        "applied file hash does not match afterHash"
    );

    // Restore the env var (don't leak across tests).
    std::env::remove_var("CARGO_HOME");
}

/// Safety gate: when the patch's advertised `beforeHash` does NOT match the
/// on-disk file, apply must REFUSE to write (it cannot trust that the blob is
/// a valid successor of whatever is actually on disk). The positive test
/// above only ever feeds a correct `beforeHash`, so a regression that made
/// apply blindly clobber the file regardless of its current content would
/// sail through it. This test pins the refusal: the file must be left
/// byte-for-byte untouched and the run must NOT report success.
#[tokio::test]
#[serial]
async fn cargo_apply_refuses_on_before_hash_mismatch() {
    if !has_cargo() {
        println!("SKIP: cargo not on PATH");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let (lib_file, cargo_home) = fetch_cfg_if(tmp.path());
    let original = std::fs::read(&lib_file).expect("read lib.rs");

    // Advertise a `beforeHash` that deliberately does NOT match the on-disk
    // file. The real file hashes to `git_sha256(&original)`; we lie and claim
    // it should hash to the digest of unrelated bytes.
    let bogus_before_hash = git_sha256(b"this is not what is on disk");
    assert_ne!(
        bogus_before_hash,
        git_sha256(&original),
        "test bug: bogus beforeHash accidentally matches the real file"
    );

    // The "patched" content the mock would write IF apply ignored the gate.
    let mut patched = original.clone();
    patched.extend_from_slice(b"\n// SOCKET-PATCH-SHOULD-NOT-BE-WRITTEN\n");
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    setup_cargo_apply_mock(&server, &bogus_before_hash, &after_hash, &patched).await;

    make_writable(&lib_file);

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
            // force MUST stay false: with --force, a hash mismatch is
            // deliberately downgraded to "ready" and the file WOULD be
            // overwritten. We are asserting the safe default refuses.
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: true,
        all_releases: false,
        vex: Default::default(),
    };
    std::env::set_var("CARGO_HOME", &cargo_home);

    let code = scan_run(args).await;

    // Confirm the real apply path actually ran (it discovered the crate and
    // fetched the blob) — otherwise the "file untouched" assertion below
    // would be vacuously satisfied by a scan that simply did nothing.
    let requests = server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let purl = format!("pkg:cargo/{CRATE_NAME}@{CRATE_VERSION}");
    let hit_batch = requests.iter().any(|r| {
        r.url.path().ends_with("/patches/batch")
            && String::from_utf8_lossy(&r.body).contains(&purl)
    });
    assert!(hit_batch, "crawler never sent cfg-if to the batch endpoint");

    // THE safety guarantee: the on-disk file must be byte-for-byte unchanged.
    // If apply ignored the beforeHash gate and wrote the blob, this fails.
    let after = std::fs::read(&lib_file).expect("read after");
    assert_eq!(
        after, original,
        "apply clobbered a file whose content did NOT match the advertised \
         beforeHash — the hash-verification safety gate has regressed"
    );
    assert!(
        !after
            .windows(b"SOCKET-PATCH-SHOULD-NOT-BE-WRITTEN".len())
            .any(|w| w == b"SOCKET-PATCH-SHOULD-NOT-BE-WRITTEN"),
        "the should-not-be-written marker leaked onto disk"
    );

    // A run that refused to apply its only patch must NOT report success.
    assert_ne!(
        code, 0,
        "scan --sync reported success (exit 0) even though its only patch was \
         rejected for a beforeHash mismatch and nothing was applied"
    );

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

    // Exit 0 alone is NOT proof of discovery: a scan that crawled the
    // wrong location and found ZERO cargo packages also exits 0. Assert
    // the crawler actually discovered the fetched crate by confirming the
    // batch endpoint received a request whose body carries the cfg-if purl.
    let requests = server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    let batch_bodies: Vec<String> = requests
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert!(
        !batch_bodies.is_empty(),
        "crawler never queried the batch endpoint — nothing was discovered"
    );
    assert!(
        batch_bodies
            .iter()
            .any(|b| b.contains(&purl)),
        "batch request bodies did not contain the fetched crate purl {purl}; bodies: {batch_bodies:?}"
    );

    std::env::remove_var("CARGO_HOME");
}
