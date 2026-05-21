//! End-to-end tests for `scan` against a local `wiremock` server.
//!
//! These tests spawn the real `socket-patch` binary as a subprocess and
//! point it at a mock HTTP server bound to an ephemeral port. They
//! exercise the full network code path — URL construction, header
//! handling, JSON deserialization, the action-decision logic — without
//! depending on the live Socket API. The real-API end-to-end suite
//! lives in `e2e_scan.rs` (gated behind `#[ignore]`).

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";

/// Write a minimal npm fixture under `<root>/node_modules/<name>/`.
/// scan's npm crawler walks node_modules and reads each package.json
/// to derive the installed PURL.
fn write_npm_package(root: &Path, name: &str, version: &str) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).expect("create pkg dir");
    let pkg_json = format!(
        r#"{{ "name": "{name}", "version": "{version}" }}"#
    );
    std::fs::write(pkg_dir.join("package.json"), pkg_json).expect("write pkg json");
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-test-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
}

/// Run `socket-patch scan` against the given mock server URL.
fn run_scan(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "scan",
        "--json",
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-test",
        "--org",
        ORG_SLUG,
    ];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .current_dir(cwd)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// ---------------------------------------------------------------------------
// Discovery — no installed packages, no API calls expected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_with_no_installed_packages_reports_zero() {
    let mock = MockServer::start().await;
    // Even with no packages, scan still hits the batch endpoint with an
    // empty body if the crawler returns anything. Register a permissive
    // mock so the test doesn't fail on an unexpected call.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());

    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "scan with no packages must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["scannedPackages"], 0);
    assert_eq!(v["packagesWithPatches"], 0);
    assert_eq!(v["totalPatches"], 0);
}

// ---------------------------------------------------------------------------
// Discovery — installed package matches an available patch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_reports_available_patch_for_installed_package() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "purl": purl,
                    "tier": "free",
                    "cveIds": ["CVE-2021-44906"],
                    "ghsaIds": ["GHSA-xvch-5gv4-984h"],
                    "severity": "high",
                    "title": "Prototype Pollution"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "scan must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["packagesWithPatches"], 1);
    assert_eq!(v["totalPatches"], 1);
    assert_eq!(v["freePatches"], 1);
    assert_eq!(v["paidPatches"], 0);

    // The packages array carries per-package patch metadata.
    let packages = v["packages"].as_array().expect("packages array");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0]["purl"], purl);
    let patches = packages[0]["patches"].as_array().unwrap();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"], "11111111-1111-4111-8111-111111111111");
    assert_eq!(patches[0]["severity"], "high");
}

// ---------------------------------------------------------------------------
// Discovery — `updates[]` diff detection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_emits_updates_entry_when_newer_uuid_available() {
    // Pre-populate the manifest with an older UUID, then have the API
    // return a NEWER UUID for the same PURL. scan must add an entry to
    // `updates` showing the diff.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let new_uuid = "99999999-9999-4999-8999-999999999999";
    let old_uuid = "11111111-1111-4111-8111-111111111111";
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": new_uuid,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "Newer patch"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    // Manifest with the older UUID — scan should detect the diff.
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{old_uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "old",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();

    let (code, stdout, _) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let updates = v["updates"].as_array().expect("updates array");
    assert_eq!(updates.len(), 1, "one PURL changed UUID");
    assert_eq!(updates[0]["purl"], purl);
    assert_eq!(updates[0]["oldUuid"], old_uuid);
    assert_eq!(updates[0]["newUuid"], new_uuid);
}

// ---------------------------------------------------------------------------
// Discovery — no manifest, no `updates` field (nothing to diff against)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_with_no_manifest_emits_empty_updates() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": "22222222-2222-4222-8222-222222222222",
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "low",
                    "title": "Some patch"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    // No .socket/manifest.json on disk.

    let (code, stdout, _) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // Without a baseline manifest, every patch found is "new" — but
    // scan's `updates` field is the *diff against an existing manifest*,
    // so it should be empty (nothing to compare against). The patches
    // themselves are in `packages[*].patches[*]`.
    assert_eq!(
        v["updates"].as_array().map(|a| a.len()),
        Some(0),
        "updates should be empty when no manifest exists; got: {v}"
    );
    assert_eq!(v["packagesWithPatches"], 1);
}

// ---------------------------------------------------------------------------
// GC field omission contract — `gc` is OPT-IN via --prune / --sync
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_without_prune_omits_gc_field() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let (_, stdout, _) = run_scan(tmp.path(), &mock.uri(), &[]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v.as_object().unwrap().get("gc").is_none(),
        "scan without --prune/--sync must NOT emit `gc`; got: {v}"
    );
}

// ---------------------------------------------------------------------------
// API failure paths
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// --apply --dry-run — synthesizes per-patch actions without writing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_apply_dry_run_with_empty_manifest_emits_added_action() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let new_uuid = "11111111-1111-4111-8111-111111111111";

    // batch search response
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": new_uuid,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "Prototype Pollution"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // by-package search (used by --apply mode for full PatchSearchResult)
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/pkg%3Anpm%2Fminimist%401.2.2"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": new_uuid,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Fixes prototype pollution",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--apply", "--dry-run", "--yes"],
    );
    assert_eq!(
        code, 0,
        "scan --apply --dry-run must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
    let apply = v["apply"]
        .as_object()
        .expect("apply object present in --apply mode");
    assert_eq!(apply["dryRun"], true);
    assert_eq!(apply["found"], 1);
    assert_eq!(apply["added"], 1);
    assert_eq!(apply["updated"], 0);
    assert_eq!(apply["skipped"], 0);
    let patches = apply["patches"].as_array().expect("patches array");
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["action"], "added");
    assert_eq!(patches[0]["uuid"], new_uuid);
    assert_eq!(patches[0]["purl"], purl);

    // CRITICAL: dry-run must not write the manifest.
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "scan --apply --dry-run must not write .socket/manifest.json"
    );
}

#[tokio::test]
async fn scan_apply_dry_run_with_existing_uuid_emits_skipped_action() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let same_uuid = "11111111-1111-4111-8111-111111111111";

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": same_uuid,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "low",
                    "title": "Some patch"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/pkg%3Anpm%2Fminimist%401.2.2"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": same_uuid,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    // Manifest already has the SAME UUID — scan --apply must skip it.
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{same_uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "existing",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();

    let (code, stdout, _) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--apply", "--dry-run", "--yes"],
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let apply = &v["apply"];
    assert_eq!(apply["skipped"], 1);
    assert_eq!(apply["added"], 0);
    assert_eq!(apply["updated"], 0);
    let patches = apply["patches"].as_array().unwrap();
    assert_eq!(patches[0]["action"], "skipped");
}

#[tokio::test]
async fn scan_apply_dry_run_with_different_uuid_emits_updated_action() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let new_uuid = "99999999-9999-4999-8999-999999999999";
    let old_uuid = "11111111-1111-4111-8111-111111111111";

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": new_uuid,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "Newer patch"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/pkg%3Anpm%2Fminimist%401.2.2"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": new_uuid,
                "purl": purl,
                "publishedAt": "2024-02-01T00:00:00Z",
                "description": "newer",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{old_uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "older",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();

    let (code, stdout, _) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--apply", "--dry-run", "--yes"],
    );
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let apply = &v["apply"];
    assert_eq!(apply["updated"], 1);
    assert_eq!(apply["added"], 0);
    assert_eq!(apply["skipped"], 0);
    let patches = apply["patches"].as_array().unwrap();
    assert_eq!(patches[0]["action"], "updated");
    assert_eq!(patches[0]["oldUuid"], old_uuid);
    assert_eq!(patches[0]["uuid"], new_uuid);
}

// ---------------------------------------------------------------------------
// --prune / --sync — GC field reporting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_prune_dry_run_reports_prunable_manifest_entries() {
    // Manifest has a patch for a PURL whose package is NOT installed.
    // `--prune --dry-run` should report it as prunable without removing.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Install a real package so scan's crawler has something to scan —
    // the early "no packages" return path skips the prune block entirely.
    write_npm_package(tmp.path(), "fresh-pkg", "1.0.0");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{
  "patches": {
    "pkg:npm/uninstalled@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "stranded entry",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--prune", "--dry-run", "--yes"],
    );
    assert_eq!(code, 0, "expected exit 0; stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let gc = v["gc"].as_object().unwrap_or_else(|| {
        panic!("--prune must emit gc field; full envelope was: {v}")
    });
    // Dry-run uses the *prunable*/* orphan* preview field names per the
    // CLI contract.
    let prunable = gc["prunableManifestEntries"]
        .as_array()
        .expect("prunableManifestEntries present in dry-run gc");
    assert_eq!(prunable.len(), 1);
    assert_eq!(prunable[0], "pkg:npm/uninstalled@1.0.0");

    // Manifest must not have been mutated.
    let body = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(manifest["patches"].as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn scan_prune_removes_stale_manifest_entries() {
    // Same setup as the dry-run test, but without `--dry-run` — the
    // stale entry should be REMOVED from the manifest.
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "fresh-pkg", "1.0.0");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{
  "patches": {
    "pkg:npm/uninstalled@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "stranded",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#,
    )
    .unwrap();

    let (code, stdout, _) = run_scan(tmp.path(), &mock.uri(), &["--prune", "--yes"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let gc = &v["gc"];
    let pruned = gc["prunedManifestEntries"]
        .as_array()
        .expect("prunedManifestEntries present in apply-mode gc");
    assert_eq!(pruned.len(), 1);

    let body = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        manifest["patches"].as_object().unwrap().len(),
        0,
        "stale entry must be pruned from manifest"
    );
}

// ---------------------------------------------------------------------------
// API failure paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_handles_api_500_error_gracefully() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    let (code, _stdout, _stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    // Scan tolerates batch search failure: it reports an empty result
    // rather than crashing. Exit code may be 0 or 1 depending on
    // whether the error is fatal — both are acceptable; we just want
    // to confirm the binary doesn't panic.
    assert!(
        code == 0 || code == 1,
        "scan must not crash on 500; got exit code {code}"
    );
}
