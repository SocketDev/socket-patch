//! Batch coverage for `commands::get::run` branches the existing
//! `get_invariants.rs` / `get_edge_cases_e2e.rs` suites don't drive.
//! Each test mocks the minimum endpoint surface needed to push the
//! command through a specific JSON envelope shape, then asserts on
//! the envelope.
//!
//! These tests assert the EXACT envelope status / exit code the
//! production code emits for each path, and pin the mocked endpoint
//! with `.expect(1)` so a wrong URL (which would otherwise 404 → look
//! like an empty result) is caught instead of silently passing.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const UUID_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/// Run `socket-patch get <identifier>` with `--json --save-only --yes`
/// against `api_url` (authenticated mode). Returns (code, stdout, stderr).
fn run_get_auth(cwd: &Path, api_url: &str, identifier: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![
        "get",
        identifier,
        "--json",
        "--save-only",
        "--yes",
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
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// ── selection_required ────────────────────────────────────────────

/// Multiple FREE patches for one package + JSON mode + no explicit
/// selection: emits `status: selection_required` with the full
/// candidate list. Covers the `JsonModeNeedsExplicit` arm of
/// `select_patches` (commands/get.rs ~481-517).
///
/// NOTE: `canAccessPaidPatches` MUST be false here. With paid access the
/// command auto-picks the newest patch and never reaches the
/// selection-required branch — so a `true` here would silently exercise
/// a completely different (download) path while still "passing" a loose
/// assertion.
#[tokio::test]
async fn get_by_purl_with_multiple_patches_emits_selection_required() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/multipatch@1.0.0";
    let encoded = "pkg%3Anpm%2Fmultipatch%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID_A, "purl": purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "Patch A", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                },
                {
                    "uuid": UUID_B, "purl": purl,
                    "publishedAt": "2024-02-01T00:00:00Z",
                    "description": "Patch B", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _stderr) = run_get_auth(tmp.path(), &mock.uri(), purl, &[]);

    // Exact contract: JSON-mode multi-free-patch with no explicit
    // selection must exit 1 with a `selection_required` envelope.
    assert_eq!(
        code, 1,
        "multi free-patch in JSON mode must exit 1; stdout={stdout}"
    );
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON envelope");
    assert_eq!(
        v["status"], "selection_required",
        "must surface selection_required; got {}",
        v["status"]
    );
    assert_eq!(v["purl"], purl, "envelope must echo the queried purl");

    // The candidate list must be complete and name both UUIDs so a
    // consumer can pick one — not an empty/partial list.
    let opts = v["options"].as_array().expect("options must be an array");
    assert_eq!(opts.len(), 2, "both candidate patches must be listed");
    let uuids: HashSet<&str> = opts.iter().filter_map(|o| o["uuid"].as_str()).collect();
    assert!(
        uuids.contains(UUID_A) && uuids.contains(UUID_B),
        "options must list both candidate UUIDs; got {uuids:?}"
    );

    // The error text must instruct the user how to disambiguate.
    let err = v["error"].as_str().unwrap_or("");
    assert!(
        err.contains("--id"),
        "selection_required error must instruct the user to specify --id; got {err:?}"
    );
}

/// `--id` is a BOOLEAN flag (force-treat-identifier-as-UUID), not a
/// value-taking selector. Supplying it a value must be rejected as a CLI
/// usage error: exit code 2, a clap error on stderr naming the stray
/// argument, and crucially NO JSON envelope on stdout.
///
/// Production inconsistency (reported, not fixed here): the
/// `selection_required` message instructs users to "Specify --id <UUID>",
/// which contradicts `--id` being a boolean flag — there is no
/// value-taking UUID selector to drive a "specified UUID didn't match a
/// candidate" branch. This test locks the *actual* CLI contract.
#[tokio::test]
async fn get_id_flag_does_not_accept_a_value() {
    let mock = MockServer::start().await; // must never be reached
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_get_auth(
        tmp.path(),
        &mock.uri(),
        "pkg:npm/idmiss@1.0.0",
        &["--id", UUID_B],
    );
    assert_eq!(
        code, 2,
        "passing a value to the boolean --id flag must be a clap usage error (exit 2)"
    );
    assert!(
        stdout.trim().is_empty(),
        "a usage error must not emit a JSON envelope; stdout={stdout}"
    );
    assert!(
        stderr.contains(UUID_B) || stderr.to_lowercase().contains("unexpected"),
        "stderr must report the unexpected argument; stderr={stderr}"
    );
}

// ── fetch by UUID error branches ────────────────────────────────────

/// UUID fetch returning 404 → clean `not_found` envelope, exit 0.
#[tokio::test]
async fn get_uuid_returning_404_emits_not_found() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_A}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _stderr) = run_get_auth(tmp.path(), &mock.uri(), UUID_A, &[]);
    // 404 means "patch absent", which is a clean no-op: exit 0.
    assert_eq!(code, 0, "404 (patch absent) must exit 0; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "not_found", "404 must surface as not_found");
    // The empty-result envelope shape is part of the contract.
    assert_eq!(v["found"], 0);
    assert_eq!(v["downloaded"], 0);
    assert_eq!(v["applied"], 0);
    assert!(
        v["patches"].as_array().expect("patches array").is_empty(),
        "not_found must carry an empty patches list"
    );
}

/// UUID fetch returning 500 → `error` envelope (exit 1) surfacing the
/// HTTP status; must not be swallowed or retried into a not_found.
#[tokio::test]
async fn get_uuid_returning_500_emits_error() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_A}")))
        .respond_with(ResponseTemplate::new(500).set_body_string("server exploded"))
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _stderr) = run_get_auth(tmp.path(), &mock.uri(), UUID_A, &[]);
    assert_eq!(code, 1, "5xx must exit 1; stdout={stdout}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON error envelope");
    assert_eq!(v["status"], "error", "5xx must surface as error");
    let err = v["error"].as_str().expect("error envelope must carry an error string");
    assert!(
        err.contains("500"),
        "error must surface the HTTP status code; got {err:?}"
    );
}

/// UUID fetch returning malformed JSON → `error` status (exit 1); the
/// parse failure must surface in the envelope, not panic or be silently
/// downgraded to not_found.
#[tokio::test]
async fn get_uuid_returning_malformed_json_emits_error() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_A}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("{ this is not json"),
        )
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _stderr) = run_get_auth(tmp.path(), &mock.uri(), UUID_A, &[]);
    assert_eq!(code, 1, "malformed body must exit 1; stdout={stdout}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON error envelope");
    assert_eq!(v["status"], "error", "parse failure must surface as error");
    let err = v["error"].as_str().expect("error envelope must carry an error string");
    assert!(
        err.to_lowercase().contains("parse"),
        "error must describe a parse failure; got {err:?}"
    );
}

// ── CVE / GHSA search no-results ─────────────────────────────────

/// CVE search returning empty patch list → `not_found` envelope, exit 0.
/// (The search path emits `not_found`; `no_match` is only produced by the
/// package-name fuzzy-match path, so it must NOT appear here.)
#[tokio::test]
async fn get_by_cve_with_no_patches_emits_no_match() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            r"^/v0/orgs/{ORG_SLUG}/patches/by-cve/CVE-2099-9999$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": true,
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _stderr) =
        run_get_auth(tmp.path(), &mock.uri(), "CVE-2099-9999", &[]);
    assert_eq!(code, 0, "empty CVE search is a clean no-op; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"], "not_found",
        "empty CVE search must emit not_found; got {}",
        v["status"]
    );
    assert_eq!(v["found"], 0);
    assert!(v["patches"].as_array().expect("patches array").is_empty());
}

/// GHSA search returning empty patch list → `not_found` envelope, exit 0.
#[tokio::test]
async fn get_by_ghsa_with_no_patches_emits_no_match() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            r"^/v0/orgs/{ORG_SLUG}/patches/by-ghsa/GHSA-xxxx-xxxx-xxxx$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": true,
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _stderr) =
        run_get_auth(tmp.path(), &mock.uri(), "GHSA-xxxx-xxxx-xxxx", &[]);
    assert_eq!(code, 0, "empty GHSA search is a clean no-op; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"], "not_found",
        "empty GHSA search must emit not_found; got {}",
        v["status"]
    );
    assert_eq!(v["found"], 0);
    assert!(v["patches"].as_array().expect("patches array").is_empty());
}
