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

/// A hash-shaped `--api-token` (the dashboard's stored `sha512-...` value)
/// with no `--org` forces org auto-resolution; the mocked 401 on
/// `GET /v0/organizations` must produce the "Could not auto-detect
/// organization" warning WITH the stored-hash hint naming the `sha512-`
/// prefix and the raw `sktsec_..._api` shape — and the command must still
/// degrade gracefully (slug-less authenticated fetch → 404 → not_found,
/// exit 0), not crash.
#[tokio::test]
async fn get_with_hash_shaped_token_prints_stored_hash_hint_on_401() {
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
    let out = Command::new(binary())
        .args([
            "get",
            UUID,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--proxy-url",
            &mock.uri(),
            "--api-token",
            "sha512-deadbeefdeadbeef",
        ])
        // Ambient state must not short-circuit auto-resolution: no env
        // slug, no offline gate, no socket-cli config (`socket login`).
        .env_remove("SOCKET_ORG_SLUG")
        .env_remove("SOCKET_OFFLINE")
        .env_remove("SOCKET_API_TOKEN")
        .env("SOCKET_NO_CONFIG", "1")
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch get");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Warning: Could not auto-detect organization"),
        "the failed resolution must warn; stderr={stderr}"
    );
    assert!(
        stderr.contains("Hint: SOCKET_API_TOKEN starts with `sha512-`"),
        "the 401 + hash-shaped token must trigger the stored-hash hint \
         naming the prefix; stderr={stderr}"
    );
    assert!(
        stderr.contains("Set it to the raw `sktsec_..._api` value instead."),
        "the hint must tell the operator what to configure; stderr={stderr}"
    );

    // The command itself degrades gracefully: 404 on the slug-less
    // authenticated view route → not_found envelope, exit 0.
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "graceful not-found must exit 0; stderr={stderr}");
    let v = json_stdout(&out);
    assert_eq!(
        v["status"], "not_found",
        "404 after failed org resolution maps to not_found, got: {v}"
    );
    assert_eq!(v["found"], 0, "not_found envelope reports zero found: {v}");
}
