//! Coverage-gap e2e for `socket_patch_core::utils::socket_cli_config`.
//!
//! Targets the one uncovered prod line in that module: the `SOCKET_DEBUG`
//! provenance diagnostic printed when `resolve_api_base_url` sources
//! `apiBaseUrl` from the socket-cli config file (the `inspect` closure in
//! `resolve_api_base_url`). It has to be exercised at the binary layer:
//! in-crate it would require `load()`, whose `OnceLock` cache is
//! process-global and would poison sibling lib tests.
//!
//! Harness cloned from `cli_config_fallback.rs` (helpers there are private
//! to that suite, so the minimal subset is reproduced here): hermetic
//! `SOCKET_*` scrub, data dir pointed at a tempdir fixture, empty npm
//! project so scan makes exactly the org auto-resolve round-trip.

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BINARY: &str = env!("CARGO_BIN_EXE_socket-patch");

/// The platform env var that positions the socket-cli data dir.
const DATA_DIR_VAR: &str = if cfg!(windows) {
    "LOCALAPPDATA"
} else {
    "XDG_DATA_HOME"
};

/// A shape-valid API token (`sktsec_<44 chars>_api`) so the token-shape
/// warning never muddies stderr assertions.
fn token(filler: char) -> String {
    format!("sktsec_{}_api", filler.to_string().repeat(44))
}

/// Write a socket-cli `config.json` fixture (base64-encoded, as the real
/// tool persists it) under `data_dir/socket/settings/`.
fn write_config(data_dir: &Path, json: &serde_json::Value) {
    let dir = data_dir.join("socket").join("settings");
    std::fs::create_dir_all(&dir).unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(json.to_string());
    std::fs::write(dir.join("config.json"), encoded).unwrap();
}

/// Build a hermetic `socket-patch scan --json -e npm` command: every
/// ambient `SOCKET_*` var is scrubbed (including the workspace-level
/// `SOCKET_NO_CONFIG=1` guard — re-enabled with an explicit falsy value),
/// the data dir points at `data_dir`, telemetry stays off.
fn scan_cmd(project: &Path, data_dir: &Path) -> Command {
    let mut cmd = Command::new(BINARY);
    cmd.args(["scan", "--json", "-e", "npm", "--cwd"])
        .arg(project);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env(DATA_DIR_VAR, data_dir);
    cmd.env("SOCKET_NO_CONFIG", "0");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

/// Empty npm project: a lone package.json with no dependencies, so the
/// crawler discovers zero packages and scan exits 0 without a batch POST.
fn write_empty_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-config-debug-fixture", "version": "0.0.0" }"#,
    )
    .unwrap();
}

/// Mock `GET /v0/organizations` (the org auto-resolve round-trip that fires
/// on authenticated client construction when no org slug is configured).
async fn mock_organizations(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v0/organizations"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "organizations": {
                "org-1": {
                    "id": "org-1",
                    "name": "Covgap Fixture Org",
                    "image": null,
                    "plan": "free",
                    "slug": "covgap-fixture-org"
                }
            }
        })))
        .mount(server)
        .await;
}

struct RunOutput {
    code: Option<i32>,
    stderr: String,
}

fn run(mut cmd: Command) -> RunOutput {
    let out = cmd.output().expect("run socket-patch");
    RunOutput {
        code: out.status.code(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// With `SOCKET_DEBUG=1` and `apiBaseUrl` resolved from the socket-cli
/// config (no `SOCKET_API_URL` in the env — the scrub in `scan_cmd`
/// guarantees the env layer misses), the provenance diagnostic names the
/// chosen URL and its source on stderr; without the debug flag the same
/// run stays silent about it. Covers the `inspect` closure in
/// `resolve_api_base_url` (`utils/socket_cli_config.rs`).
#[tokio::test]
async fn debug_names_config_api_base_url_provenance() {
    let server = MockServer::start().await;
    mock_organizations(&server).await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());
    write_config(
        data.path(),
        &serde_json::json!({ "apiToken": token('c'), "apiBaseUrl": server.uri() }),
    );

    let provenance = format!("api base url: `{}` from socket-cli config", server.uri());

    // Debug on: the provenance line must appear, and the run still works
    // end-to-end (the config URL really was chosen — the fixture got hit).
    let mut cmd = scan_cmd(project.path(), data.path());
    cmd.env("SOCKET_DEBUG", "1");
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        out.stderr.contains(&provenance),
        "SOCKET_DEBUG=1 must print the apiBaseUrl provenance line \
         ({provenance:?}); stderr:\n{}",
        out.stderr
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .any(|r| r.url.path() == "/v0/organizations"),
        "control: the config apiBaseUrl must actually be used, or the \
         provenance line under test is asserting a lie"
    );

    // Debug off (scrubbed env): the very same run prints no provenance —
    // the diagnostic is gated on SOCKET_DEBUG, not on the config source.
    let out = run(scan_cmd(project.path(), data.path()));
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        !out.stderr.contains("api base url:"),
        "without SOCKET_DEBUG the provenance diagnostic must stay silent; \
         stderr:\n{}",
        out.stderr
    );
}
