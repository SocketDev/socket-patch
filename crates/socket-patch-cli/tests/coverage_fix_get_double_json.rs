//! Subprocess regression test: agent-mode `get <search-id> --json` must
//! print exactly ONE JSON document when the download engine hits a HARD
//! error (here: an unreadable manifest). The engine's fail-closed paths
//! in `download_and_apply_patches` print the `{status: "error"}`
//! envelope themselves via `report_error` and return it; `run()`'s agent
//! path then pretty-printed the SAME envelope again, putting two JSON
//! documents on stdout — violating get's one-document `--json` contract
//! (the vendored search path already guards this with its
//! `result["status"] == "error"` early return).
//!
//! Subprocess (not in-process) because the defect is precisely what the
//! spawned binary PRINTS. Same harness recipe as `get_modes_e2e.rs`.

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const GHSA: &str = "GHSA-dbld-json-once";
const UUID1: &str = "44444444-4444-4444-8444-444444444444";
const PURL1: &str = "pkg:npm/double-json-pkg@1.0.0";

/// `by-ghsa/{GHSA}` returning ONE free patch, so `select_patches`
/// auto-selects without prompting and the `--json` confirm auto-accepts.
/// No `view/{uuid}` mock is needed: the manifest read fails before any
/// per-patch fetch.
async fn mock_ghsa_single_free(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID1, "purl": PURL1,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "double-json fixture", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// A search-path `get --save-only --json` whose engine run dies on the
/// fail-closed corrupt-manifest read must emit ONE error envelope, not
/// the engine's copy followed by `run()`'s re-print of the same value.
/// `--save-only` keeps the run narrowing-exempt so the flow reaches the
/// engine without needing an installed project.
#[tokio::test]
async fn search_get_json_engine_hard_error_prints_one_document() {
    let server = MockServer::start().await;
    mock_ghsa_single_free(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    // A manifest that EXISTS but cannot be parsed trips the engine's
    // fail-closed read (`Failed to read manifest: ...`).
    std::fs::write(socket.join("manifest.json"), "{not json").unwrap();

    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &[
            "get",
            GHSA,
            "--save-only",
            "--json",
            "--api-url",
            &server.uri(),
            "--api-token",
            "fake-token-for-tests",
            "--org",
            ORG,
        ],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );

    assert_eq!(
        code, 1,
        "an unreadable manifest must fail the run.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // `serde_json::from_str` rejects trailing data, so a second envelope
    // on the stream fails this parse loudly.
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must be exactly one JSON document: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(v["status"], "error", "envelope drifted: {v}");
    assert!(
        v["error"]
            .as_str()
            .is_some_and(|m| m.contains("Failed to read manifest")),
        "error message drifted: {v}"
    );
}
