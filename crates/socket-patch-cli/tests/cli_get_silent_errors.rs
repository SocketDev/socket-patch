//! `get --silent` must still surface errors.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only" — informational
//! chatter is suppressed, errors are not. Regression guard: the download
//! loop in `download_and_apply_patches` gated its per-patch failure lines
//! (`[fail] …`) on `!silent` alongside the informational prints, so
//! `get <purl> --silent` against a failing patch fetch exited 1 with ZERO
//! output anywhere — no stdout (correct) and no stderr (the bug). The
//! by-uuid path (`save_and_apply_patch`) already kept its blob errors
//! visible under `--silent`; the search path must match.
//!
//! Hermetic: the search endpoint answers with one free patch and the
//! patch view endpoint answers 500, all on a local wiremock; ambient API
//! URLs are pinned to a dead port.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const UUID: &str = "22222222-2222-4222-8222-222222222222";
const PURL: &str = "pkg:npm/silent-error-pkg@1.0.0";
const PURL_ENCODED: &str = "pkg%3Anpm%2Fsilent-error-pkg%401.0.0";

/// A dead local port: whatever the run resolves from the env must not be
/// reachable, so only the `--api-url` flag can route to the mock.
const DEAD_URL: &str = "http://127.0.0.1:1";

fn dead_env<'a>() -> Vec<(&'a str, &'a str)> {
    vec![
        ("SOCKET_API_URL", DEAD_URL),
        ("SOCKET_PROXY_URL", DEAD_URL),
        ("SOCKET_ORG_SLUG", ORG),
        ("SOCKET_TELEMETRY_DISABLED", "1"),
    ]
}

/// Search succeeds (one free patch) but the patch view fails: the run
/// reaches `download_and_apply_patches`' failure branch and must exit 1.
async fn mount_search_ok_view_500(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/{PURL_ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "silent-error fixture",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {},
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(500))
        .mount(mock)
        .await;
}

fn get_args<'a>(uri: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "get",
        PURL,
        "--yes",
        "--api-url",
        uri,
        "--api-token",
        "flag-token",
        "--org",
        ORG,
    ];
    args.extend_from_slice(extra);
    args
}

#[tokio::test]
async fn get_silent_download_failure_still_prints_the_error() {
    let mock = MockServer::start().await;
    mount_search_ok_view_500(&mock).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let uri = mock.uri();
    let (code, stdout, stderr) =
        common::run_with_env(tmp.path(), &get_args(&uri, &["--silent"]), &dead_env());

    assert_eq!(
        code, 1,
        "a failed patch fetch must exit 1; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );
    // The contract's "Errors only": the per-patch failure must reach
    // stderr even under --silent — an exit 1 with zero output is mute.
    assert!(
        stderr.contains("[fail]") && stderr.contains(PURL),
        "--silent must still print the download failure to stderr; got {stderr:?}"
    );
    // Informational chatter stays suppressed: the fix must not turn
    // --silent failures into fully loud runs.
    assert!(
        !stderr.contains("Downloading"),
        "--silent must keep suppressing informational lines; got {stderr:?}"
    );
}

#[tokio::test]
async fn get_loud_download_failure_prints_the_error_control() {
    // Control: the same scenario WITHOUT --silent prints the failure —
    // otherwise the silent assertion above could pass vacuously against
    // a reworded error path.
    let mock = MockServer::start().await;
    mount_search_ok_view_500(&mock).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let uri = mock.uri();
    let (code, _stdout, stderr) =
        common::run_with_env(tmp.path(), &get_args(&uri, &[]), &dead_env());

    assert_eq!(code, 1, "control run must exit 1; stderr={stderr:?}");
    assert!(
        stderr.contains("[fail]") && stderr.contains(PURL),
        "non-silent run must print the download failure; got {stderr:?}"
    );
}
