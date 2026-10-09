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

use crate::common::binary;

use std::collections::HashSet;
use std::path::Path;

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";
const UUID_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const UUID_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

/// Run `socket-patch get <identifier>` with `--json --save-only --yes`
/// against `api_url` (authenticated mode). Returns (code, stdout, stderr).
fn run_get_auth(
    cwd: &Path,
    api_url: &str,
    identifier: &str,
    extra: &[&str],
) -> (i32, String, String) {
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
    let mut cmd = crate::common::hermetic_command(&binary());
    cmd.args(&args).current_dir(cwd);
    let out = cmd.output().expect("run socket-patch");
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
/// `select_patches` (commands/get.rs).
///
/// NOTE: `canAccessPaidPatches` MUST be false here. With paid access the
/// command auto-picks the top-ranked patch (see api::ranking) and never reaches the
/// selection-required branch — so a `true` here would silently exercise
/// a completely different (download) path while still "passing" a loose
/// assertion.
#[tokio::test]
async fn get_by_purl_with_multiple_patches_emits_selection_required() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/multipatch@1.0.0";
    let encoded = "pkg%3Anpm%2Fmultipatch%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
        )))
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
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON envelope");
    assert_eq!(
        v["status"], "selectionRequired",
        "must surface selection_required; got {}",
        v["status"]
    );
    assert_eq!(v["purl"], purl, "envelope must echo the queried purl");

    // The candidate list must be complete and name both UUIDs so a
    // consumer can pick one — not an empty/partial list.
    let opts = v["options"].as_array().expect("options must be an array");
    assert_eq!(opts.len(), 2, "both candidate patches must be listed");
    let uuids: HashSet<&str> = opts.iter().filter_map(|o| o["uuid"].as_str()).collect();
    // Name the UUIDs, never print them (CodeQL rust/cleartext-logging).
    assert!(
        uuids.contains(UUID_A) && uuids.contains(UUID_B),
        "options must list both candidate UUIDs"
    );

    // Each option must carry the full disambiguation payload — tier, the
    // human description, and the publish timestamp — so a degenerate
    // "just the uuid" shape (which would make the prompt useless) fails.
    let descriptions: HashSet<&str> = opts
        .iter()
        .filter_map(|o| o["description"].as_str())
        .collect();
    assert!(
        descriptions.contains("Patch A") && descriptions.contains("Patch B"),
        "options must echo each patch description; got {descriptions:?}"
    );
    for o in opts {
        assert_eq!(
            o["tier"], "free",
            "each listed candidate must be the free patch we mocked; got {}",
            o["tier"]
        );
        assert!(
            o["publishedAt"].as_str().is_some_and(|s| !s.is_empty()),
            "each option must carry a non-empty published_at; got {}",
            o["publishedAt"]
        );
    }

    // The error text must instruct the user how to disambiguate — and the
    // instruction must be one the CLI actually accepts. `--id` is a boolean
    // type-tag (see get_id_flag_does_not_accept_a_value below), so selection
    // happens by re-running with the chosen UUID as the positional
    // identifier; a "Specify --id <UUID>" instruction would send users
    // straight into a clap usage error.
    let err = v["error"]["message"].as_str().unwrap_or("");
    assert!(
        !err.contains("--id <"),
        "error must not instruct the value-taking `--id <UUID>` form the CLI rejects; got {err:?}"
    );
    assert!(
        err.to_lowercase().contains("re-run") && err.to_lowercase().contains("uuid"),
        "error must direct the user to re-run with one of the listed UUIDs; got {err:?}"
    );
}

/// `--id` is a BOOLEAN flag (force-treat-identifier-as-UUID), not a
/// value-taking selector. Supplying it a value must be rejected as a CLI
/// usage error: exit code 2, a clap error on stderr naming the stray
/// argument, and crucially NO JSON envelope on stdout.
///
/// This contract is why the `selection_required` wording matters:
/// selection happens by re-running with the chosen UUID as the positional
/// identifier (`get <uuid> --id`), never by passing a value to `--id`.
/// The selection test above pins the instruction, and this test locks the
/// boolean CLI contract it depends on.
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
    // Strict: the clap error must both name the stray value AND flag it as
    // unexpected. An OR here would accept any old usage error (e.g. a missing
    // required arg) and stop policing that it's specifically `--id` refusing
    // a value.
    assert!(
        stderr.contains(UUID_B),
        "stderr must name the stray value; stderr={stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("unexpected"),
        "stderr must report it as an unexpected argument; stderr={stderr}"
    );

    // A usage error is detected during arg parsing, before any API call: the
    // command must never have reached the server.
    let received = mock
        .received_requests()
        .await
        .expect("wiremock request recording must be enabled");
    assert!(
        received.is_empty(),
        "a CLI usage error must short-circuit before any HTTP request; got {} request(s)",
        received.len()
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
    assert_eq!(v["status"], "notFound", "404 must surface as not_found");
    // The empty-result envelope shape is part of the contract.
    assert_eq!(v["events"], serde_json::json!([]));
    assert_eq!(v["summary"]["downloaded"], 0);
    assert_eq!(v["summary"]["applied"], 0);
    assert!(
        v["events"].as_array().expect("patches array").is_empty(),
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
    let err = v["error"]["message"]
        .as_str()
        .expect("error envelope must carry an error string");
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
        .respond_with(ResponseTemplate::new(200).set_body_string("{ this is not json"))
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, _stderr) = run_get_auth(tmp.path(), &mock.uri(), UUID_A, &[]);
    assert_eq!(code, 1, "malformed body must exit 1; stdout={stdout}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON error envelope");
    assert_eq!(v["status"], "error", "parse failure must surface as error");
    let err = v["error"]["message"]
        .as_str()
        .expect("error envelope must carry an error string");
    assert!(
        err.to_lowercase().contains("parse"),
        "error must describe a parse failure; got {err:?}"
    );
}

// ── CVE / GHSA search no-results ─────────────────────────────────

/// CVE search returning empty patch list → `not_found` envelope, exit 0.
/// (The search path emits `not_found`; `no_match` is only produced by the
/// package-name fuzzy-match path, so it must NOT appear here. v3.6 adds a
/// third distinct status: `not_installed`, for a NON-empty search whose
/// every version was narrowed out — also never spelled `no_match`.)
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
    let (code, stdout, _stderr) = run_get_auth(tmp.path(), &mock.uri(), "CVE-2099-9999", &[]);
    assert_eq!(
        code, 0,
        "empty CVE search is a clean no-op; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"], "notFound",
        "empty CVE search must emit not_found (NOT no_match, which is the \
         fuzzy package-name path); got {}",
        v["status"]
    );
    assert_eq!(v["events"], serde_json::json!([]));
    assert_eq!(
        v["summary"]["downloaded"], 0,
        "no patches downloaded on empty search"
    );
    assert_eq!(
        v["summary"]["applied"], 0,
        "no patches applied on empty search"
    );
    assert!(v["events"].as_array().expect("patches array").is_empty());
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
    let (code, stdout, _stderr) = run_get_auth(tmp.path(), &mock.uri(), "GHSA-xxxx-xxxx-xxxx", &[]);
    assert_eq!(
        code, 0,
        "empty GHSA search is a clean no-op; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["status"], "notFound",
        "empty GHSA search must emit not_found (NOT no_match, which is the \
         fuzzy package-name path); got {}",
        v["status"]
    );
    assert_eq!(v["events"], serde_json::json!([]));
    assert_eq!(
        v["summary"]["downloaded"], 0,
        "no patches downloaded on empty search"
    );
    assert_eq!(
        v["summary"]["applied"], 0,
        "no patches applied on empty search"
    );
    assert!(v["events"].as_array().expect("patches array").is_empty());
}
