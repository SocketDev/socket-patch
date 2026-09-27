//! Coverage-gap e2e for `api::client` env/org-resolution UX paths that need
//! process-level stderr assertions (2026-09 coverage audit).
//!
//! The core inline tests (`org_auto_resolution_401_with_hash_shaped_token_hint_arm`)
//! pin the resulting client *state*; this suite pins the operator-facing
//! stderr *text* — the "you configured the sha512- storage hash, not the
//! token" hint — which only a spawned process can observe.

use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UUID: &str = "11111111-1111-4111-8111-111111111111";

fn binary() -> std::path::PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Parse the command's stdout as JSON, failing with the raw bytes on error
/// (same discipline as `api_client_errors_e2e::json_stdout`).
fn json_stdout(out: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected valid JSON on stdout, got parse error {e}; \
             stdout={stdout:?} stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Run `get <UUID> --save-only --yes` plus `extra` flags with a hash-shaped
/// `--api-token` (the dashboard's stored `sha512-...` value) and no `--org`,
/// against a fresh mock that 401s org auto-resolution exactly once and
/// 404s the slug-less authenticated view route exactly once.
async fn run_get_with_hash_shaped_token(extra: &[&str]) -> std::process::Output {
    let mock = MockServer::start().await;
    // Org auto-resolution: exactly one 401. `.expect(1)` proves the
    // resolution round-trip actually fired (no ambient slug short-circuit).
    Mock::given(method("GET"))
        .and(path("/v0/organizations"))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .expect(1)
        .mount(&mock)
        .await;
    // After failed resolution the slug is unset → the view route falls back
    // to the `default` slug segment; a 404 there is a graceful not-found.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/default/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = mock.uri();
    let mut args = vec!["get", UUID];
    args.extend_from_slice(extra);
    args.extend_from_slice(&[
        "--save-only",
        "--yes",
        "--api-url",
        &uri,
        "--proxy-url",
        &uri,
        "--api-token",
        "sha512-deadbeefdeadbeef",
    ]);
    // `mock` is dropped (and its `.expect(1)`s verified) on return.
    Command::new(binary())
        .args(&args)
        // Ambient state must not short-circuit auto-resolution: no env
        // slug, no offline gate, no socket-cli config (`socket login`).
        .env_remove("SOCKET_ORG_SLUG")
        .env_remove("SOCKET_OFFLINE")
        .env_remove("SOCKET_API_TOKEN")
        .env("SOCKET_NO_CONFIG", "1")
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch get")
}

/// The warning text both output modes must print for the 401: the
/// "Could not auto-detect organization" warning WITH the stored-hash hint
/// naming the `sha512-` prefix and the raw `sktsec_..._api` shape, plus
/// the pre-flight token-shape warning.
fn assert_hash_token_warnings(stderr: &str, mode: &str) {
    assert!(
        stderr.contains("Warning: Could not auto-detect organization"),
        "[{mode}] the failed resolution must warn; stderr={stderr}"
    );
    assert!(
        stderr.contains("Hint: --api-token starts with `sha512-`"),
        "[{mode}] the 401 + hash-shaped token must trigger the stored-hash \
         hint naming the prefix and the flag the token came from; stderr={stderr}"
    );
    assert!(
        stderr.contains("Warning: --api-token does not look like a Socket API token"),
        "[{mode}] the shape warning names the flag, not SOCKET_API_TOKEN; stderr={stderr}"
    );
    assert!(
        stderr.contains("Set it to the raw `sktsec_..._api` value instead."),
        "[{mode}] the hint must tell the operator what to configure; stderr={stderr}"
    );
    assert!(
        stderr.contains("looks like an SRI-format hash"),
        "[{mode}] the token-shape warning must print; stderr={stderr}"
    );
}

/// Human mode: the 401 produces the stored-hash hint on stderr, and the
/// command degrades gracefully (slug-less authenticated fetch → 404 →
/// not found, exit 0) instead of crashing.
#[tokio::test]
async fn get_with_hash_shaped_token_prints_stored_hash_hint_on_401() {
    let out = run_get_with_hash_shaped_token(&[]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_hash_token_warnings(&stderr, "human");
    assert_eq!(
        out.status.code(),
        Some(0),
        "graceful not-found must exit 0; stderr={stderr}"
    );
}

/// `--json` keeps stdout machine-readable but does not mute warnings: the
/// same hint and token-shape warning reach stderr, and stdout is a valid
/// `not_found` envelope.
#[tokio::test]
async fn get_with_hash_shaped_token_under_json_keeps_warnings_and_envelope() {
    let out = run_get_with_hash_shaped_token(&["--json"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_hash_token_warnings(&stderr, "json");
    assert_eq!(
        out.status.code(),
        Some(0),
        "graceful not-found must exit 0; stderr={stderr}"
    );
    let v = json_stdout(&out);
    assert_eq!(
        v["status"], "not_found",
        "404 after failed org resolution maps to not_found, got: {v}"
    );
    assert_eq!(v["found"], 0, "not_found envelope reports zero found: {v}");
}

/// `--silent` is "errors only": the same misconfiguration prints neither
/// the token-shape warning nor the org auto-detect warning, and the
/// command still degrades to exit 0.
#[tokio::test]
async fn get_with_hash_shaped_token_under_silent_prints_no_warnings() {
    let out = run_get_with_hash_shaped_token(&["--json", "--silent"]).await;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Could not auto-detect organization"),
        "--silent must mute the org auto-detect warning; stderr={stderr}"
    );
    assert!(
        !stderr.contains("SRI-format hash"),
        "--silent must mute the token-shape warning; stderr={stderr}"
    );
    assert_eq!(out.status.code(), Some(0), "stderr={stderr}");
    assert_eq!(json_stdout(&out)["status"], "not_found");
}
