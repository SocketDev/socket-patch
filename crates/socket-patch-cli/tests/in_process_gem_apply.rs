//! In-process full-apply test for the gem (Ruby) ecosystem.
//!
//! Real `gem install` → hash real installed file → mock patch with
//! matching hashes → in-process `scan --sync` → assert marker in
//! installed gem file on disk.

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use serial_test::serial;
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "13131313-1313-4131-8131-131313131313";
const GEM_NAME: &str = "colorize";
const GEM_VERSION: &str = "1.1.0";

#[path = "common/mod.rs"]
mod common;
use common::{cache_env, git_sha256};

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
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Install a small gem into `<tmp>/vendor/bundle/ruby/<ver>/` and
/// return the path to the gem's main lib file.
fn install_colorize(tmp: &Path) -> PathBuf {
    let ver = ruby_version().expect("ruby not on PATH");
    let install_dir = tmp.join(format!("vendor/bundle/ruby/{ver}"));
    std::fs::create_dir_all(&install_dir).expect("create install dir");

    // `--install-dir` keeps the gem itself out of the user's gem environment,
    // but RubyGems still writes its spec cache under the home directory. The
    // sandbox catches that; `--install-dir` is a flag, so it is unaffected.
    let mut cmd = Command::new("gem");
    cmd.args([
        "install",
        "--no-document",
        "--install-dir",
        install_dir.to_str().unwrap(),
        GEM_NAME,
        "-v",
        GEM_VERSION,
    ]);
    cache_env::isolate(&mut cmd);
    let status = cmd
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
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
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
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: Some(server.uri()),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["gem".to_string()]),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        prune: false,
        sync: true,
        mode: None,
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    };
    let code = scan_run(args).await;
    assert_eq!(
        code, 0,
        "scan --sync should succeed when the patch applies cleanly"
    );

    // The apply must have driven the REAL code path end to end:
    //   crawler discovers the gem -> POSTs its purl to /batch -> fetches the
    //   blob from /view/{UUID} -> writes it. Assert every link so the apply
    //   cannot "pass" via an incidental fetch or a short-circuit.
    let requests = server
        .received_requests()
        .await
        .expect("mock server recorded requests");
    let purl = format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}");
    let batch_path = format!("/v0/orgs/{ORG}/patches/batch");
    let discovered = requests.iter().any(|r| {
        r.url.path() == batch_path && String::from_utf8_lossy(&r.body).contains(purl.as_str())
    });
    assert!(
        discovered,
        "crawler did not discover the installed gem: no batch request carried {purl}"
    );
    let view_path = format!("/v0/orgs/{ORG}/patches/view/{UUID}");
    let view_hits = requests
        .iter()
        .filter(|r| r.url.path() == view_path)
        .count();
    assert!(
        view_hits >= 1,
        "view endpoint never fetched — apply short-circuited (paths seen: {:?})",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );

    // Verify the file on disk is EXACTLY the patched fixture, byte-for-byte.
    // A substring/marker search would tolerate a partial or corrupted write;
    // exact equality (derived independently from `original` + marker) does not.
    let after = std::fs::read(&lib_file).expect("read after");
    assert_ne!(after, original, "file unchanged — patch was not applied");
    assert_eq!(
        after, patched,
        "applied file does not match the patched fixture byte-for-byte"
    );
    // And the on-disk content must hash to the patch's declared afterHash.
    assert_eq!(
        git_sha256(&after),
        after_hash,
        "post-apply file hash does not match the patch afterHash"
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
    let lib_file = install_colorize(tmp.path());
    // A bare scan (hosted mode) rewires lockfiles only; capture the installed
    // file so we can prove it is left byte-for-byte untouched.
    let before_scan = std::fs::read(&lib_file).expect("read colorize.rb before scan");

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
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: Some(server.uri()),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["gem".to_string()]),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        prune: false,
        sync: false,
        mode: None,
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    };
    assert_eq!(scan_run(args).await, 0);

    // Exit 0 alone is vacuous: a scan that discovers NOTHING also exits 0.
    // Prove the crawler actually found the installed gem by asserting the
    // batch request carried its purl. Without discovery, no such request
    // (or an empty one) would have been sent.
    let requests = server
        .received_requests()
        .await
        .expect("mock server recorded requests");
    let batch_path = format!("/v0/orgs/{ORG}/patches/batch");
    let discovered = requests.iter().any(|r| {
        r.url.path() == batch_path && String::from_utf8_lossy(&r.body).contains(purl.as_str())
    });
    assert!(
        discovered,
        "crawler did not discover the installed gem: no batch request carried {purl}"
    );

    // A bare scan (hosted mode) must never write the installed gem copy.
    let after_scan = std::fs::read(&lib_file).expect("read colorize.rb after scan");
    assert_eq!(
        after_scan,
        before_scan,
        "read-only scan mutated the installed gem file at {}",
        lib_file.display()
    );
}

// ---------------------------------------------------------------------------
// A re-scan that replaces the recorded gem patch with another one (#2096)
// ---------------------------------------------------------------------------

/// Make the mock serve exactly one patch for the gem: `uuid`, changing
/// `files` (`(path in the gem, original bytes, patched bytes)`). Replaces
/// whatever it served before.
async fn serve_gem_patch(server: &MockServer, uuid: &str, files: &[(&str, &[u8], Vec<u8>)]) {
    let purl = format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}");
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    server.reset().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid, "purl": purl,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "medium", "title": "gem replacement fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    let files: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(file, before, after)| {
            (
                format!("package/{file}"),
                serde_json::json!({
                    "beforeHash": git_sha256(before),
                    "afterHash": git_sha256(after),
                    "blobContent": b64(after),
                    "beforeBlobContent": b64(before),
                }),
            )
        })
        .collect();
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": files,
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(server)
        .await;
}

async fn gem_agent_scan(cwd: &Path, server: &MockServer) -> i32 {
    scan_run(ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            api_url: Some(server.uri()),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["gem".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        prune: false,
        sync: true,
        mode: None,
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    })
    .await
}

/// Patch A changes `lib/colorize.rb` and `lib/colorize/version.rb`; the
/// patch that replaces it changes `lib/colorize/version.rb` only. The
/// re-scan must give `lib/colorize.rb` back: once the record is patch
/// B's, no command lists, checks or restores that file.
#[tokio::test]
#[serial]
async fn gem_rescan_replacing_a_patch_restores_the_file_the_new_patch_dropped() {
    if !has_gem() {
        println!("SKIP: gem not on PATH");
        return;
    }
    const UUID_B: &str = "23232323-2323-4232-8232-232323232323";
    let marked = |bytes: &[u8], marker: &str| {
        let mut patched = bytes.to_vec();
        patched.extend_from_slice(format!("\n# {marker}\n").as_bytes());
        patched
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let lib_file = install_colorize(tmp.path());
    let version_file = lib_file.parent().unwrap().join("colorize/version.rb");
    let lib_original = std::fs::read(&lib_file).expect("read colorize.rb");
    let version_original = std::fs::read(&version_file).expect("read colorize/version.rb");
    let lib_a = marked(&lib_original, "PATCH-A");
    let version_a = marked(&version_original, "PATCH-A");
    let version_b = marked(&version_original, "PATCH-B");

    let server = MockServer::start().await;
    serve_gem_patch(
        &server,
        UUID,
        &[
            ("lib/colorize.rb", &lib_original, lib_a.clone()),
            (
                "lib/colorize/version.rb",
                &version_original,
                version_a.clone(),
            ),
        ],
    )
    .await;
    assert_eq!(gem_agent_scan(tmp.path(), &server).await, 0);
    assert_eq!(std::fs::read(&lib_file).unwrap(), lib_a);
    assert_eq!(std::fs::read(&version_file).unwrap(), version_a);

    serve_gem_patch(
        &server,
        UUID_B,
        &[(
            "lib/colorize/version.rb",
            &version_original,
            version_b.clone(),
        )],
    )
    .await;
    assert_eq!(gem_agent_scan(tmp.path(), &server).await, 0);

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    let purl = format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}");
    assert_eq!(manifest["patches"][purl.as_str()]["uuid"], UUID_B);
    assert_eq!(
        std::fs::read(&version_file).unwrap(),
        version_b,
        "the new patch's file is patched"
    );
    assert_eq!(
        std::fs::read(&lib_file).unwrap(),
        lib_original,
        "the file only the replaced patch changed must be put back"
    );
}
