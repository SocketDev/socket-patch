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
    let pkg_json = format!(r#"{{ "name": "{name}", "version": "{version}" }}"#);
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
// Request-inspection helpers.
//
// The mocks above match on METHOD + PATH only — they ignore the request
// body. Without inspecting what the binary actually *sent*, a regression
// that crawled the wrong package, encoded PURLs incorrectly, or skipped
// the network call entirely would still see the canned (path-keyed)
// response and stay green. These helpers let each test pin the real
// network code path the module doc claims to exercise: URL construction
// and the PURLs carried in the batch request body.
// ---------------------------------------------------------------------------

async fn recorded(mock: &MockServer) -> Vec<wiremock::Request> {
    mock.received_requests()
        .await
        .expect("wiremock records requests by default")
}

fn batch_posts(reqs: &[wiremock::Request]) -> Vec<&wiremock::Request> {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/batch"))
        .collect()
}

fn by_package_gets(reqs: &[wiremock::Request]) -> usize {
    reqs.iter()
        .filter(|r| {
            format!("{}", r.method) == "GET" && r.url.path().contains("/patches/by-package/")
        })
        .count()
}

fn body_text(req: &wiremock::Request) -> String {
    String::from_utf8_lossy(&req.body).into_owned()
}

/// Assert that exactly one batch POST was sent and its body mentions the
/// given PURL verbatim. This is what proves scan constructed the request
/// from the *crawled* package rather than fabricating the response.
fn assert_single_batch_carries_purl(reqs: &[wiremock::Request], purl: &str) {
    let posts = batch_posts(reqs);
    assert_eq!(
        posts.len(),
        1,
        "expected exactly one batch POST; saw {}",
        posts.len()
    );
    let body = body_text(posts[0]);
    assert!(
        body.contains(purl),
        "batch request body must carry the crawled purl {purl}; body was: {body}"
    );
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

    // A project with no installed dependencies crawls zero packages, so
    // scan must never query the batch API. The zeroed counters above are
    // *also* what a regression that silently swallowed an API failure
    // would emit — pinning "0 batch POSTs" distinguishes "nothing to
    // scan" from "scanned but lost the results".
    let reqs = recorded(&mock).await;
    assert!(
        batch_posts(&reqs).is_empty(),
        "empty project must not query the batch API; saw {} POST(s)",
        batch_posts(&reqs).len()
    );
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

    // The mock answers minimist patches on ANY batch POST, so the
    // counters above prove only that correlation worked — not that scan
    // *sent* the crawled PURL. Pin the request body so a PURL-encoding
    // regression (wrong purl / empty body / no call) fails loudly.
    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, purl);
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

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, purl);
}

#[tokio::test]
async fn scan_update_candidate_is_the_highest_ranked_patch() {
    // `updates[].newUuid` must name the patch `--apply` would install —
    // the highest-ranked one (merged → severity → recency), NOT whatever
    // the server listed first. The two are computed by different code over
    // different API shapes (`detect_updates` over the batch response,
    // `select_patches` over by-package), so they can drift.
    //
    // The fixture is the reported bug in miniature: the low-severity patch
    // is listed first AND is the more recently published, but the critical
    // one must win. Severities are uppercase and dates are RFC 2822, as
    // production emits them.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let manifest_uuid = "11111111-1111-4111-8111-111111111111";
    let low_uuid = "22222222-2222-4222-8222-222222222222";
    let critical_uuid = "99999999-9999-4999-8999-999999999999";
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [
                    {
                        "uuid": low_uuid, "purl": purl, "tier": "free",
                        "cveIds": [], "ghsaIds": [],
                        "severity": "LOW", "title": "Low, but newest",
                        "publishedAt": "Mon, 03 Aug 2026 20:23:06 GMT",
                    },
                    {
                        "uuid": critical_uuid, "purl": purl, "tier": "free",
                        "cveIds": [], "ghsaIds": [],
                        "severity": "CRITICAL", "title": "Critical, but older",
                        "publishedAt": "Wed, 01 Jan 2025 00:00:00 GMT",
                    }
                ]
            }],
            "canAccessPaidPatches": true,
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
      "uuid": "{manifest_uuid}",
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
    assert_eq!(updates.len(), 1, "one PURL changed UUID; got {v}");
    assert_eq!(
        updates[0]["newUuid"], critical_uuid,
        "the update candidate must be the critical patch, not the newer low one; got {v}"
    );

    // The `packages[].patches` array the operator reads is ordered the same
    // way, so the listing and the decision agree.
    let listed = v["packages"][0]["patches"]
        .as_array()
        .expect("patches array");
    assert_eq!(
        listed[0]["uuid"], critical_uuid,
        "listed patches must be best-first; got {v}"
    );
}

// ---------------------------------------------------------------------------
// Discovery — `updates[]` bridges the two PURL spellings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_emits_updates_entry_for_scoped_purl_despite_manifest_percent_encoding() {
    // Regression: for a SCOPED package the two purl spellings diverge.
    //   * manifest keys are written verbatim from the *patch* purl, which
    //     the API serves percent-encoded (`pkg:npm/%40scope/...`) — see
    //     in_process_vendor.rs `vendor_resolves_percent_encoded_scope_purl`.
    //   * the batch *package* key comes back in the crawler's literal
    //     spelling (`pkg:npm/@scope/...`) — the public-proxy path builds it
    //     from the purls we requested (`assemble_batch_from_individual`).
    // `detect_updates` looked the manifest up by the raw batch purl, so a
    // scoped package with a newer patch never reached `updates[]` (nor the
    // table's `[UPDATE]` marker) — the operator silently kept the old patch.
    let mock = MockServer::start().await;
    let crawler_purl = "pkg:npm/@scope/left-pad@1.3.0";
    let api_purl = "pkg:npm/%40scope/left-pad@1.3.0";
    let new_uuid = "99999999-9999-4999-8999-999999999999";
    let old_uuid = "11111111-1111-4111-8111-111111111111";
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": crawler_purl,
                "patches": [{
                    "uuid": new_uuid,
                    "purl": api_purl,
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
    write_npm_package(tmp.path(), "@scope/left-pad", "1.3.0");
    // Manifest keyed by the ENCODED purl — exactly what `get`/`scan --apply`
    // write for a scoped package.
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{api_purl}": {{
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

    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let updates = v["updates"].as_array().expect("updates array");
    assert_eq!(
        updates.len(),
        1,
        "the scoped package's newer UUID must be reported; got: {v}"
    );
    assert_eq!(updates[0]["purl"], crawler_purl);
    assert_eq!(updates[0]["oldUuid"], old_uuid);
    assert_eq!(updates[0]["newUuid"], new_uuid);

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, crawler_purl);
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

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, purl);
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
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "scan must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
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

    let (code, stdout, stderr) =
        run_scan(tmp.path(), &mock.uri(), &["--apply", "--dry-run", "--yes"]);
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

    // --apply mode must query BOTH endpoints: the batch search (carrying
    // the crawled PURL) and the per-package detail fetch. The "added"
    // action above is only trustworthy if it was synthesized from a real
    // detail fetch, not fabricated.
    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, purl);
    assert!(
        by_package_gets(&reqs) >= 1,
        "scan --apply must fetch per-package patch details; saw {} by-package GET(s)",
        by_package_gets(&reqs)
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

    let (code, stdout, _) = run_scan(tmp.path(), &mock.uri(), &["--apply", "--dry-run", "--yes"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let apply = &v["apply"];
    assert_eq!(apply["skipped"], 1);
    assert_eq!(apply["added"], 0);
    assert_eq!(apply["updated"], 0);
    let patches = apply["patches"].as_array().unwrap();
    assert_eq!(patches[0]["action"], "skipped");

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, purl);
    assert!(
        by_package_gets(&reqs) >= 1,
        "scan --apply must fetch per-package patch details; saw {} by-package GET(s)",
        by_package_gets(&reqs)
    );
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

    let (code, stdout, _) = run_scan(tmp.path(), &mock.uri(), &["--apply", "--dry-run", "--yes"]);
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

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, purl);
    assert!(
        by_package_gets(&reqs) >= 1,
        "scan --apply must fetch per-package patch details; saw {} by-package GET(s)",
        by_package_gets(&reqs)
    );
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

    let (code, stdout, stderr) =
        run_scan(tmp.path(), &mock.uri(), &["--prune", "--dry-run", "--yes"]);
    assert_eq!(code, 0, "expected exit 0; stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let gc = v["gc"]
        .as_object()
        .unwrap_or_else(|| panic!("--prune must emit gc field; full envelope was: {v}"));
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

    // The prune decision must be grounded in a real crawl: the batch
    // query carries the *installed* package (fresh-pkg), and "uninstalled"
    // is prunable precisely because it was NOT among the crawled packages.
    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, "pkg:npm/fresh-pkg@1.0.0");
    assert!(
        !body_text(batch_posts(&reqs)[0]).contains("pkg:npm/uninstalled@1.0.0"),
        "the uninstalled (prunable) PURL must not appear in the crawl-driven batch query"
    );
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

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, "pkg:npm/fresh-pkg@1.0.0");
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
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);

    // The binary must still emit a well-formed JSON envelope (no panic /
    // no garbage on stdout) even when the API is down.
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("scan must emit valid JSON even on API failure; err={e}; stdout={stdout}; stderr={stderr}")
    });

    // CONTRACT (scan.rs:598-600): "If every batch errored, surface this as
    // a full scan failure rather than silently reporting zero patches
    // (which historically looked identical to 'no patches for these
    // packages')." Here there is exactly one package → exactly one batch,
    // and it returns 500, so EVERY batch failed. scan must therefore NOT
    // present this as a clean success. A scan that emits status="success"
    // / exit 0 with scannedPackages=1, totalPatches=0 is reporting the
    // failure as "scanned the package, found no patches" — the precise
    // masquerade the comment promises not to do.
    assert_ne!(
        v["status"], "success",
        "scan must NOT report status=success when every API batch failed (500); \
         envelope={v}; stderr={stderr}"
    );
    assert_ne!(
        code, 0,
        "scan must exit non-zero when every API batch failed (500); \
         got exit code {code}; envelope={v}; stderr={stderr}"
    );
    // It must not crash, either — a panic/abort would surface as 101 or a
    // negative/signal code, never the deliberate failure exit.
    assert!(
        code > 0 && code < 100,
        "scan must fail cleanly (not crash) on 500; got exit code {code}; stderr={stderr}"
    );
}

/// Mount a batch endpoint that reports one patched package, plus a
/// per-package detail endpoint that fails with a 500 for it. This is the
/// "batch phase fine, detail phase totally down" shape that drives
/// `discover_selected` into its all-queries-failed bail.
async fn mount_batch_ok_details_500(mock: &MockServer, purl: &str, uuid: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid,
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
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/pkg%3Anpm%2Fminimist%401.2.2"
        )))
        .respond_with(ResponseTemplate::new(500).set_body_string("detail endpoint down"))
        .mount(mock)
        .await;
}

/// CONTRACT (CLI_CONTRACT.md, "JSON output shapes"): *every* `--json`
/// invocation emits a single JSON object on stdout. `scan`'s other total
/// failures honor that — `--offline` and the all-batches-failed bail both
/// print `{"status": "error", "error": ...}`. The all-detail-queries-failed
/// bail did not: it returned exit 1 straight out of `discover_selected`
/// with EMPTY stdout, so a bot parsing `scan --json --apply` got a JSON
/// parse error instead of a diagnosable failure envelope.
#[tokio::test]
async fn scan_apply_all_detail_queries_failed_emits_json_error_envelope() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_ok_details_500(&mock, purl, "11111111-1111-4111-8111-111111111111").await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &["--apply", "--yes"]);

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "scan --json --apply must emit a JSON envelope even when every \
             patch-detail query fails; err={e}; stdout={stdout:?}; stderr={stderr}"
        )
    });
    assert_eq!(
        v["status"], "error",
        "a total detail-phase failure must be reported as status=error; envelope={v}"
    );
    assert!(
        v["error"].is_string() && !v["error"].as_str().unwrap().is_empty(),
        "the error envelope must carry a diagnosable message; envelope={v}"
    );
    assert_ne!(code, 0, "exit code must stay non-zero; envelope={v}");
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "a fully-failed detail phase must not write a manifest"
    );
}

/// Same contract, vendored mode: `run_vendor_json_path` calls the same
/// `discover_selected` and had the same bare `return code` with no stdout.
#[tokio::test]
async fn scan_vendored_all_detail_queries_failed_emits_json_error_envelope() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    mount_batch_ok_details_500(&mock, purl, "11111111-1111-4111-8111-111111111111").await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    let (code, stdout, stderr) =
        run_scan(tmp.path(), &mock.uri(), &["--mode", "vendored", "--yes"]);

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "scan --json --mode vendored must emit a JSON envelope even when every \
             patch-detail query fails; err={e}; stdout={stdout:?}; stderr={stderr}"
        )
    });
    assert_eq!(
        v["status"], "error",
        "a total detail-phase failure must be reported as status=error; envelope={v}"
    );
    assert!(
        v["error"].is_string() && !v["error"].as_str().unwrap().is_empty(),
        "the error envelope must carry a diagnosable message; envelope={v}"
    );
    assert_ne!(code, 0, "exit code must stay non-zero; envelope={v}");
}

// ---------------------------------------------------------------------------
// Lifecycle: withdrawn patches and patch updates
// ---------------------------------------------------------------------------

/// Defensive scoping test for `--prune`: a manifest entry whose package
/// is still installed but for which the API now returns *no* patches
/// (e.g. the upstream withdrew the only patch but the package itself is
/// still present in the project) MUST NOT be silently pruned. The
/// current prune semantics target manifest entries whose PURL is no
/// longer in the crawl results — not entries the API has fallen silent
/// on. If we ever change that, we want to do it deliberately.
#[tokio::test]
async fn scan_prune_keeps_entry_when_package_installed_but_api_silent() {
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
    // The package is still installed locally — only its patch is gone.
    write_npm_package(tmp.path(), "still-installed", "1.0.0");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let original_manifest = r#"{
  "patches": {
    "pkg:npm/still-installed@1.0.0": {
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "still here, just no patch this scan",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;
    std::fs::write(socket.join("manifest.json"), original_manifest).unwrap();

    let (code, _stdout, _stderr) = run_scan(tmp.path(), &mock.uri(), &["--prune", "--yes"]);
    assert_eq!(code, 0);

    let body = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        manifest["patches"].as_object().unwrap().len(),
        1,
        "entry for still-installed package must survive prune when API is silent"
    );
    assert!(
        manifest["patches"]["pkg:npm/still-installed@1.0.0"]
            .as_object()
            .is_some(),
        "the original PURL/UUID record must remain intact"
    );

    // The survival is only meaningful if the package was actually crawled
    // and queried this run — otherwise the entry would survive trivially
    // because prune never ran. Pin that the installed PURL was in the
    // batch query.
    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, "pkg:npm/still-installed@1.0.0");
}

/// Withdrawn-patch lifecycle: a patch present in the manifest for a
/// package that has since been *uninstalled* (no longer in crawl
/// results) must be pruned by `--prune`. This complements
/// `scan_prune_removes_stale_manifest_entries` by additionally placing
/// a stub blob file on disk for the to-be-withdrawn patch and asserting
/// the manifest no longer references it (so `repair` can subsequently
/// GC the blob).
#[tokio::test]
async fn scan_prune_removes_withdrawn_patch_entry() {
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
    // Only a different package is now present — the previously patched
    // package was uninstalled, simulating withdrawal.
    write_npm_package(tmp.path(), "unrelated", "1.0.0");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{
  "patches": {
    "pkg:npm/withdrawn-pkg@1.0.0": {
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "withdrawn from upstream",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#,
    )
    .unwrap();
    // Drop a stub blob on disk so we can confirm subsequent `repair`
    // would GC it. Real blob name uses content hash; for prune's
    // purposes the file's mere presence is enough.
    std::fs::write(
        socket.join("blobs").join("stub-blob"),
        b"placeholder bytes for withdrawn patch",
    )
    .unwrap();

    let (code, _stdout, _stderr) = run_scan(tmp.path(), &mock.uri(), &["--prune", "--yes"]);
    assert_eq!(code, 0);

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["patches"].as_object().unwrap().len(),
        0,
        "withdrawn entry must be removed"
    );

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, "pkg:npm/unrelated@1.0.0");
}

/// Update detection: when the API returns a different UUID for the
/// same PURL that's in the manifest, `scan` surfaces that in the
/// `updates` array even without `--apply`. Sibling to
/// `scan_emits_updates_entry_when_newer_uuid_available` but exercised
/// with a stub blob on disk so we pin the read-only behavior: scan
/// alone never mutates files.
#[tokio::test]
async fn scan_detects_update_without_touching_existing_blobs() {
    const OLD_UUID: &str = "44444444-4444-4444-8444-444444444444";
    const NEW_UUID: &str = "55555555-5555-4555-8555-555555555555";

    let purl = "pkg:npm/lodash@4.17.20";
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": NEW_UUID,
                    "purl": purl,
                    "tier": "free",
                    "cveIds": [],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "Updated lodash patch",
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "lodash", "4.17.20");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "pkg:npm/lodash@4.17.20": {{
      "uuid": "{OLD_UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "Original lodash patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();
    // Marker blob: scan without --apply must leave it untouched.
    let marker = socket.join("blobs").join("untouched-by-scan");
    std::fs::write(&marker, b"original contents").unwrap();

    let (code, stdout, _stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0);

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let updates = v["updates"].as_array().expect("updates array present");
    assert_eq!(updates.len(), 1, "exactly one update detected");
    assert_eq!(updates[0]["purl"], "pkg:npm/lodash@4.17.20");
    assert_eq!(updates[0]["oldUuid"], OLD_UUID);
    assert_eq!(updates[0]["newUuid"], NEW_UUID);

    // Critical: scan is read-only. The manifest still records the OLD
    // UUID and the marker blob is byte-for-byte unchanged.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert_eq!(
        manifest["patches"]["pkg:npm/lodash@4.17.20"]["uuid"], OLD_UUID,
        "scan without --apply must not rewrite the manifest"
    );
    assert_eq!(
        std::fs::read(&marker).unwrap(),
        b"original contents",
        "scan without --apply must not touch existing blobs"
    );

    let reqs = recorded(&mock).await;
    assert_single_batch_carries_purl(&reqs, purl);
}

// ---------------------------------------------------------------------------
// Cross-mode visibility warnings — agent-mode scan over another mode's state
// ---------------------------------------------------------------------------
//
// Additive run-level `warnings[]` (top-level `{code, detail}` entries on the
// scan `--json` envelope) — NEVER a status or exit-code change. Two blind
// spots they close:
//
// * `vendored_ownership_retained`: agent-mode apply partitions vendor-owned
//   purls into `apply.patches[]` skip records (`skipped`/`vendored`), which
//   a `--json` consumer only finds by digging into the per-patch array; the
//   requested mode change silently did not happen at the envelope level.
// * `hosted_wiring_retained`: agent-mode scan over a live hosted redirect
//   (lockfile still pinned to the patch server + redirect ledger records
//   live) applies in place and reports success with zero hint that the
//   hosted wiring was NOT unwound (no hosted revert exists for npm/yarn).

const AGENT_WARN_UUID: &str = "33333333-3333-4333-8333-333333333333";

/// Mount the batch + by-package mocks for one purl/uuid pair.
async fn mount_patch_discovery(mock: &MockServer, purl: &str, encoded: &str, uuid: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": purl,
                "patches": [{
                    "uuid": uuid,
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
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid,
                "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "Fixes prototype pollution",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

fn find_warning<'a>(v: &'a serde_json::Value, code: &str) -> Option<&'a serde_json::Value> {
    v["warnings"]
        .as_array()
        .and_then(|ws| ws.iter().find(|w| w["code"] == code))
}

#[tokio::test]
async fn scan_agent_over_vendored_purl_surfaces_run_level_warning() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    // The vendor ledger owns the purl.
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { purl: {
                "ecosystem": "npm",
                "basePurl": purl,
                "uuid": AGENT_WARN_UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{AGENT_WARN_UUID}/minimist-1.2.2.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &["--mode", "agent", "--yes"]);
    assert_eq!(
        code, 0,
        "additive warning must NOT change the exit code; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"], "success",
        "additive warning must NOT change status; envelope={v}"
    );

    // The per-patch skip record is unchanged (contract-pinned elsewhere)…
    let patches = v["apply"]["patches"]
        .as_array()
        .expect("apply.patches array");
    assert_eq!(patches.len(), 1, "envelope={v}");
    assert_eq!(patches[0]["errorCode"], "vendored", "envelope={v}");

    // …and the NEW top-level run warning names the retained ownership.
    let w = find_warning(&v, "vendored_ownership_retained").unwrap_or_else(|| {
        panic!(
            "agent-mode scan skipping vendor-owned purl(s) must surface a \
             top-level vendored_ownership_retained warning; envelope={v}"
        )
    });
    let detail = w["detail"].as_str().expect("warning detail is a string");
    assert!(
        detail.contains("pkg:npm/minimist@1.2.2"),
        "must name the purl: {detail}"
    );
    assert!(
        detail.contains("socket-patch remove") && detail.contains("vendor --revert"),
        "must name the real migration path: {detail}"
    );
    // Mirrored to stderr (not silent).
    assert!(
        stderr.contains("vendored_ownership_retained"),
        "warning must be mirrored to stderr when not silent: {stderr}"
    );
}

/// Write a hosted redirect ledger + a yarn.lock the ledger claims to have
/// edited, whose resolved URL still pins the patch server (the live-wiring
/// proof `hosted_wiring_live` reads).
fn seed_live_hosted_wiring(root: &Path, purl: &str, uuid: &str, with_record: bool) {
    let hosted_url =
        format!("https://patch.socket.dev/patch/npm/minimist/1.2.2/tok/{uuid}/minimist-1.2.2.tgz");
    std::fs::write(
        root.join("yarn.lock"),
        format!(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\n\n\
             minimist@^1.2.2:\n  version \"1.2.2\"\n  \
             resolved \"{hosted_url}#aaaa\"\n  integrity sha512-fake==\n"
        ),
    )
    .unwrap();
    let vendor_dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    let mut state = serde_json::json!({
        "version": 1,
        "mode": "hosted",
        "edits": [{
            "path": "yarn.lock",
            "kind": "redirect_yarn_entry",
            "action": "rewritten",
            "key": "minimist@1.2.2",
            "original": "minimist@^1.2.2:\n  version \"1.2.2\"\n  resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.2.tgz#bbbb\"\n  integrity sha512-orig==\n"
        }],
    });
    if with_record {
        state["records"] = serde_json::json!({ purl: {
            "uuid": uuid,
            "exportedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "hosted patch",
            "license": "MIT",
            "tier": "free"
        }});
    }
    std::fs::write(
        vendor_dir.join("redirect-state.json"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn scan_agent_over_live_hosted_wiring_surfaces_run_level_warning() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );

    // --dry-run keeps the run cheap (no artifact download mocks needed);
    // the warning is a STATE probe — the hosted wiring is live whether or
    // not this particular run wrote anything.
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--mode", "agent", "--dry-run", "--yes"],
    );
    assert_eq!(
        code, 0,
        "additive warning must NOT change the exit code; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"], "success",
        "additive warning must NOT change status; envelope={v}"
    );

    let w = find_warning(&v, "hosted_wiring_retained").unwrap_or_else(|| {
        panic!(
            "agent-mode scan over live hosted wiring must surface a \
             top-level hosted_wiring_retained warning; envelope={v}"
        )
    });
    let detail = w["detail"].as_str().expect("warning detail is a string");
    assert!(
        detail.contains("pkg:npm/minimist@1.2.2"),
        "must name the purl: {detail}"
    );
    assert!(
        detail.contains("scan --mode vendored"),
        "must name the migration path: {detail}"
    );
    assert!(
        detail.contains("Do not delete"),
        "must warn against hand-deleting the ledger (it holds the only \
         revert originals): {detail}"
    );
    assert!(
        stderr.contains("hosted_wiring_retained"),
        "warning must be mirrored to stderr when not silent: {stderr}"
    );
}

/// Coordination guard (lane B: hosted→vendored pre-revert): once another
/// flow retires the redirect ledger RECORDS for a purl, the agent-flow
/// warning must stay silent — it keys on records still live at scan time,
/// never on leftover `edits` (which are append-only revert data and
/// legitimately outlive the records).
#[tokio::test]
async fn scan_agent_hosted_warning_silent_once_ledger_records_are_gone() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    // Ledger with edits but NO records (the post-pre-revert shape) — and
    // the lock text still carrying the uuid must not resurrect the warning.
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ false,
    );

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--mode", "agent", "--dry-run", "--yes"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        find_warning(&v, "hosted_wiring_retained").is_none(),
        "no ledger records ⇒ no hosted_wiring_retained warning; envelope={v}"
    );
}

/// Registry-clean lock (hosted wiring NOT live) with a leftover record:
/// the live lock is the truth source — no warning.
#[tokio::test]
async fn scan_agent_hosted_warning_silent_when_lock_is_registry_clean() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );
    // Overwrite the lock with a registry-clean entry (no uuid, no patch host).
    std::fs::write(
        tmp.path().join("yarn.lock"),
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n\
         minimist@^1.2.2:\n  version \"1.2.2\"\n  \
         resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.2.tgz#bbbb\"\n  \
         integrity sha512-orig==\n",
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--mode", "agent", "--dry-run", "--yes"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        find_warning(&v, "hosted_wiring_retained").is_none(),
        "registry-clean lock ⇒ no hosted_wiring_retained warning; envelope={v}"
    );
}

// ---------------------------------------------------------------------------
// Read-only cross-mode visibility — the `redirectState` envelope block
// ---------------------------------------------------------------------------
//
// The `hosted_wiring_retained` warning above only rides the AGENT-mode
// envelope, and report-only `scan --json` (the documented read-only state
// probe) said nothing at all about a live hosted redirect: a hosted-wired
// project's `scan --json` was byte-identical to a never-touched project's
// (verified against production on bundler 1.17/2.7/4.0 — the gem live-matrix
// D3 defect). These pin the additive top-level `redirectState` block: the
// redirect ledger's records (project STATE, not an anomaly — so a block, not
// a warning) plus the scanned purls whose hosted lockfile wiring the live
// lock still proves.

/// Report-only `scan --json` over live hosted wiring must carry the
/// `redirectState` block — records AND the live-wiring proof — with no
/// status/exit change and no agent-flow conversion warning.
#[tokio::test]
async fn report_only_scan_json_surfaces_hosted_redirect_state() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );

    // No mode flag: the read-only discovery envelope.
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(
        code, 0,
        "report-only scan must stay exit 0; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");

    let state = &v["redirectState"];
    assert!(
        state.is_object(),
        "report-only scan --json over a hosted-wired project must carry the \
         redirectState block; envelope={v}"
    );
    assert_eq!(state["mode"], "hosted", "envelope={v}");
    assert_eq!(
        state["ledger"], ".socket/vendor/redirect-state.json",
        "the block must name the ledger it reports; envelope={v}"
    );
    let records = state["records"].as_array().expect("records array");
    assert_eq!(records.len(), 1, "envelope={v}");
    assert_eq!(records[0]["purl"], purl, "envelope={v}");
    assert_eq!(records[0]["uuid"], AGENT_WARN_UUID, "envelope={v}");
    let live: Vec<&str> = state["wiringLive"]
        .as_array()
        .expect("wiringLive array")
        .iter()
        .map(|p| p.as_str().expect("purl string"))
        .collect();
    assert_eq!(
        live,
        vec![purl],
        "the live lock still pins the patch server, so the wiring-live proof \
         must name the purl; envelope={v}"
    );
    // The conversion warning stays agent-scoped: a read-only scan converts
    // nothing, so hosted state is reported as state, never as a warning.
    assert!(
        find_warning(&v, "hosted_wiring_retained").is_none(),
        "report-only scan must not fire the agent-flow conversion warning; \
         envelope={v}"
    );
}

/// The block keys on ledger RECORDS: an edits-only ledger (the post-takeover
/// / degraded shape) and a ledger-less project both omit it entirely.
#[tokio::test]
async fn report_only_scan_json_omits_redirect_state_without_ledger_records() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    // Edits-only ledger (records retired), live-looking lock text.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ false,
    );
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v.get("redirectState").is_none(),
        "an edits-only ledger asserts no records ⇒ no redirectState block; \
         envelope={v}"
    );

    // No ledger at all: the key must stay absent (additive contract).
    let clean = tempfile::tempdir().expect("tempdir");
    write_root_package_json(clean.path());
    write_npm_package(clean.path(), "minimist", "1.2.2");
    let (code, stdout, stderr) = run_scan(clean.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v.get("redirectState").is_none(),
        "no ledger ⇒ no redirectState block; envelope={v}"
    );
}

/// Records with a registry-clean lock: the block still lists the records
/// (the ledger is real state) but `wiringLive` is empty — the records/proof
/// split mirrors the agent warning's live-lock gate.
#[tokio::test]
async fn report_only_scan_json_redirect_state_splits_records_from_live_proof() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );
    // Registry-clean lock: the ledger record outlived the wiring.
    std::fs::write(
        tmp.path().join("yarn.lock"),
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n\
         minimist@^1.2.2:\n  version \"1.2.2\"\n  \
         resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.2.tgz#bbbb\"\n  \
         integrity sha512-orig==\n",
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let state = &v["redirectState"];
    assert!(
        state.is_object(),
        "records exist ⇒ block exists; envelope={v}"
    );
    assert_eq!(
        state["records"].as_array().map(Vec::len),
        Some(1),
        "envelope={v}"
    );
    assert_eq!(
        state["wiringLive"].as_array().map(Vec::len),
        Some(0),
        "registry-clean lock ⇒ empty wiringLive (never guess from ledger \
         presence alone); envelope={v}"
    );
}

/// Agent-mode runs carry the block too, alongside the conversion warning —
/// the state block is descriptive, the warning is the conversion-incomplete
/// diagnostic; neither replaces the other.
#[tokio::test]
async fn scan_agent_json_carries_redirect_state_alongside_warning() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--mode", "agent", "--dry-run", "--yes"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        find_warning(&v, "hosted_wiring_retained").is_some(),
        "the agent-flow warning is unchanged; envelope={v}"
    );
    assert_eq!(v["redirectState"]["mode"], "hosted", "envelope={v}");
    assert_eq!(
        v["redirectState"]["records"][0]["purl"], purl,
        "envelope={v}"
    );
}

/// Mount the hosted reference endpoint with NO grants: every uuid comes back
/// missing, so each selected patch lands as a per-patch `not_found` skip and
/// the hosted run still emits its full envelope — all the omission tests
/// below need.
async fn mount_empty_reference(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": {} })),
        )
        .mount(mock)
        .await;
}

/// Hosted-mode envelopes never carry `redirectState`: the nested `redirect`
/// block reports this run's own result and `run_redirect` re-persists the
/// ledger mid-run, so a pre-run snapshot would go stale. Pinned on BOTH the
/// zero-discovery and the ≥1-package paths.
#[tokio::test]
async fn hosted_mode_envelopes_omit_redirect_state() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;
    mount_empty_reference(&mock).await;

    // Zero-discovery: ledger records present, nothing installed.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );
    std::fs::remove_file(tmp.path().join("yarn.lock")).unwrap();
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &["--mode", "hosted", "--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v["redirect"].is_object(),
        "hosted zero-discovery envelope keeps its no-op redirect block; \
         envelope={v}"
    );
    assert!(
        v.get("redirectState").is_none(),
        "hosted-mode envelopes must not carry redirectState; envelope={v}"
    );

    // ≥1 package: the full hosted pipeline (empty grants ⇒ not_found skips).
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &["--mode", "hosted", "--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v["redirect"].is_object(),
        "hosted run reports its own result under redirect; envelope={v}"
    );
    assert!(
        v.get("redirectState").is_none(),
        "hosted-mode envelopes must not carry redirectState; envelope={v}"
    );
}

/// Vendored-mode envelopes never carry `redirectState` either: the vendored
/// takeover reconciliation may retire ledger records mid-run (the
/// `vendor_supersedes_redirect` warning covers that state), so a pre-run
/// snapshot would go stale. The zero-discovery leg is the regression pin —
/// the early-return used to gate the block on `!hosted` alone, leaking it
/// into `scan --mode vendored --json` over an empty crawl.
#[tokio::test]
async fn vendored_mode_envelopes_omit_redirect_state() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    // Zero-discovery (the leak): ledger records present, nothing installed.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );
    std::fs::remove_file(tmp.path().join("yarn.lock")).unwrap();
    let (code, stdout, stderr) =
        run_scan(tmp.path(), &mock.uri(), &["--mode", "vendored", "--yes"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v.get("redirectState").is_none(),
        "vendored-mode zero-discovery envelope must not carry redirectState; \
         envelope={v}"
    );

    // ≥1 package (dry-run keeps it network-light past discovery).
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &mock.uri(),
        &["--mode", "vendored", "--dry-run", "--yes"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v["vendor"].is_object(),
        "vendored dry-run envelope carries its vendor block; envelope={v}"
    );
    assert!(
        v.get("redirectState").is_none(),
        "vendored-mode envelopes must not carry redirectState; envelope={v}"
    );
}

/// The malformed-ledger degradation warning is advisory, so `--silent`
/// ("errors only") must mute it — on the report-only path like everywhere
/// else. The envelope itself is unchanged either way (no redirectState from
/// a ledger that cannot be read).
#[tokio::test]
async fn silent_gates_scan_malformed_ledger_warning() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("redirect-state.json"), "{ torn ledger").unwrap();

    // Control: without --silent the corruption is surfaced on stderr.
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        stderr.contains("malformed"),
        "a malformed ledger must be surfaced when not silent: {stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v.get("redirectState").is_none(),
        "an unreadable ledger asserts nothing; envelope={v}"
    );

    // --silent mutes the advisory warning; the run is otherwise identical.
    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &["--silent"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    assert!(
        !stderr.contains("malformed"),
        "--silent must mute the malformed-ledger warning: {stderr}"
    );
}

/// `wiringLive` (like the agent warning) only ever names packages this run
/// actually counted: an `--ecosystems` filter that excludes the hosted
/// ecosystem leaves the records listed — the ledger is still real state —
/// with an EMPTY wiringLive ("purl not crawled/queried this run" is a
/// documented silent cause, distinct from "wiring unwound"). This also pins
/// the zero-discovery envelope carrying the block at all.
#[tokio::test]
async fn ecosystems_filter_keeps_records_but_not_wiring_live() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/minimist@1.2.2";
    let encoded = "pkg%3Anpm%2Fminimist%401.2.2";
    mount_patch_discovery(&mock, purl, encoded, AGENT_WARN_UUID).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    // Live hosted wiring — provable, but out of this run's scope below.
    seed_live_hosted_wiring(
        tmp.path(),
        purl,
        AGENT_WARN_UUID,
        /*with_record=*/ true,
    );

    let (code, stdout, stderr) = run_scan(tmp.path(), &mock.uri(), &["--ecosystems", "pypi"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let state = &v["redirectState"];
    assert!(
        state.is_object(),
        "records exist ⇒ the block rides even the filtered/zero-discovery \
         envelope; envelope={v}"
    );
    assert_eq!(
        state["records"].as_array().map(Vec::len),
        Some(1),
        "envelope={v}"
    );
    assert_eq!(
        state["wiringLive"],
        serde_json::json!([]),
        "a purl this run did not crawl/query must not be claimed live — \
         even though the lock provably pins the patch server; envelope={v}"
    );
}
