//! E2E tests for the socket-cli config fallback layer.
//!
//! The binary reads the JS socket-cli's persisted login state
//! (`<data dir>/socket/settings/config.json`, base64-encoded JSON) as the
//! resolution layer below env vars for `apiToken` / `defaultOrg` /
//! `apiBaseUrl` (see `socket_patch_core::utils::socket_cli_config`), plus
//! the `SOCKET_CLI_*` peer env aliases and the `SOCKET_NO_CONFIG` /
//! `SOCKET_NO_API_TOKEN` toggles.
//!
//! These run the compiled binary as a subprocess: the config file is read
//! once per process (`OnceLock`), so in-process testing could not exercise
//! different fixtures, and the data-dir env vars are process-global. Each
//! test points the platform data-dir env var (`XDG_DATA_HOME`, or
//! `%LOCALAPPDATA%` on Windows) at a private tempdir fixture.
//!
//! NOTE: the workspace `.cargo/config.toml` exports `SOCKET_NO_CONFIG=1` so
//! a developer's real `socket login` can never leak into the test suite;
//! tests here that exercise the layer explicitly re-enable it with a falsy
//! `SOCKET_NO_CONFIG=0` on the child.

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
/// warning never muddies stderr assertions. Distinct fillers distinguish
/// which layer supplied the token in Authorization-header assertions.
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
/// ambient `SOCKET_*` var is scrubbed (including the inherited
/// `SOCKET_NO_CONFIG=1` guard — tests re-add exactly what they need), the
/// data dir points at `data_dir`, and the project dir is an empty npm
/// project so the crawl finds nothing and no batch request fires.
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
    // Ambient VIRTUAL_ENV would be harmless under `-e npm`, but scrub it
    // anyway to mirror the other scan harnesses.
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env(DATA_DIR_VAR, data_dir);
    // Re-enable the config layer (the workspace-level SOCKET_NO_CONFIG=1
    // guard was scrubbed above; set an explicit falsy value so the intent
    // is visible). Gate tests override this with "1".
    cmd.env("SOCKET_NO_CONFIG", "0");
    // Telemetry is fire-and-forget to the *real* proxy when a run is
    // unauthenticated — keep these tests off the network. The one test
    // that exercises telemetry-follows-config re-enables it explicitly.
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

/// Empty npm project: a lone package.json with no dependencies, so the
/// crawler discovers zero packages and scan exits 0 without a batch POST.
fn write_empty_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "config-fallback-fixture", "version": "0.0.0" }"#,
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
                    "name": "Config Fixture Org",
                    "image": null,
                    "plan": "free",
                    "slug": "config-fixture-org"
                }
            }
        })))
        .mount(server)
        .await;
}

struct RunOutput {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(mut cmd: Command) -> RunOutput {
    let out = cmd.output().expect("run socket-patch");
    RunOutput {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Authorization header of the (single expected) `/v0/organizations` call.
async fn recorded_bearer(server: &MockServer) -> Option<String> {
    let reqs = server.received_requests().await.unwrap_or_default();
    reqs.iter()
        .find(|r| r.url.path() == "/v0/organizations")
        .and_then(|r| r.headers.get("authorization"))
        .map(|v| v.to_str().unwrap_or_default().to_string())
}

/// The public-proxy notice that must appear iff no token was resolved.
const PROXY_NOTICE: &str = "No SOCKET_API_TOKEN set";

/// A config-supplied token + apiBaseUrl authenticate the client: with no
/// org anywhere the binary must hit the fixture's `/v0/organizations` with
/// the config token as bearer.
#[tokio::test]
async fn config_token_and_api_base_url_authenticate() {
    let server = MockServer::start().await;
    mock_organizations(&server).await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());
    write_config(
        data.path(),
        &serde_json::json!({ "apiToken": token('c'), "apiBaseUrl": server.uri() }),
    );

    let out = run(scan_cmd(project.path(), data.path()));
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        !out.stderr.contains(PROXY_NOTICE),
        "config token must select the authenticated path; stderr:\n{}",
        out.stderr
    );
    assert_eq!(
        recorded_bearer(&server).await.as_deref(),
        Some(format!("Bearer {}", token('c')).as_str()),
        "org auto-resolve must hit the config apiBaseUrl with the config token"
    );
}

/// `defaultOrg` from the config skips the org auto-resolve round-trip —
/// and telemetry (deliberately enabled here) follows the same config
/// resolution: the event POSTs to the config `apiBaseUrl` under the
/// config org with the config token. This pins the shared
/// `resolve_api_base_url` chain between client construction and
/// `resolve_telemetry_endpoint`.
#[tokio::test]
async fn config_default_org_skips_auto_resolve_and_telemetry_follows() {
    let server = MockServer::start().await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());
    write_config(
        data.path(),
        &serde_json::json!({
            "apiToken": token('c'),
            "apiBaseUrl": server.uri(),
            "defaultOrg": "cfg-org"
        }),
    );

    let mut cmd = scan_cmd(project.path(), data.path());
    cmd.env("SOCKET_TELEMETRY_DISABLED", "0");
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    let reqs = server.received_requests().await.unwrap_or_default();
    assert!(
        !reqs.iter().any(|r| r.url.path() == "/v0/organizations"),
        "defaultOrg from config must skip org auto-resolve; saw {reqs:?}"
    );
    let telemetry = reqs
        .iter()
        .find(|r| r.url.path() == "/v0/orgs/cfg-org/telemetry")
        .expect("telemetry must POST to the config apiBaseUrl under the config org");
    assert_eq!(
        telemetry
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap_or_default().to_string())
            .as_deref(),
        Some(format!("Bearer {}", token('c')).as_str()),
        "telemetry must carry the config token"
    );
}

/// The env var beats the config file for the same key — but only for that
/// key: the token comes from `SOCKET_API_TOKEN` while `apiBaseUrl` still
/// resolves from the config (per-key layering).
#[tokio::test]
async fn env_token_beats_config_token_per_key() {
    let server = MockServer::start().await;
    mock_organizations(&server).await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());
    write_config(
        data.path(),
        &serde_json::json!({ "apiToken": token('c'), "apiBaseUrl": server.uri() }),
    );

    let mut cmd = scan_cmd(project.path(), data.path());
    cmd.env("SOCKET_API_TOKEN", token('e'));
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert_eq!(
        recorded_bearer(&server).await.as_deref(),
        Some(format!("Bearer {}", token('e')).as_str()),
        "env token must beat the config token while apiBaseUrl still comes from config"
    );
}

/// `SOCKET_CLI_API_TOKEN` (the socket-cli peer alias) is honored when the
/// canonical name is unset — and loses to it when both are set.
#[tokio::test]
async fn socket_cli_alias_token_honored_canonical_wins() {
    let server = MockServer::start().await;
    mock_organizations(&server).await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());

    // Alias alone authenticates.
    let mut cmd = scan_cmd(project.path(), data.path());
    cmd.env("SOCKET_CLI_API_TOKEN", token('l'))
        .env("SOCKET_API_URL", server.uri());
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert_eq!(
        recorded_bearer(&server).await.as_deref(),
        Some(format!("Bearer {}", token('l')).as_str()),
        "SOCKET_CLI_API_TOKEN alone must authenticate"
    );

    // Canonical beats alias.
    server.reset().await;
    mock_organizations(&server).await;
    let mut cmd = scan_cmd(project.path(), data.path());
    cmd.env("SOCKET_CLI_API_TOKEN", token('l'))
        .env("SOCKET_API_TOKEN", token('e'))
        .env("SOCKET_API_URL", server.uri());
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert_eq!(
        recorded_bearer(&server).await.as_deref(),
        Some(format!("Bearer {}", token('e')).as_str()),
        "canonical SOCKET_API_TOKEN must win over the SOCKET_CLI_ alias"
    );
}

/// A corrupt config file warns on stderr, is treated as absent (public
/// proxy), and never pollutes `--json` stdout.
#[tokio::test]
async fn corrupt_config_warns_and_keeps_json_stdout_clean() {
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());
    let dir = data.path().join("socket").join("settings");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), "!!! neither base64 nor json").unwrap();

    let out = run(scan_cmd(project.path(), data.path()));
    assert_eq!(
        out.code,
        Some(0),
        "a corrupt config must never break the run"
    );
    assert!(
        out.stderr.contains("could not parse socket-cli config")
            && out.stderr.contains("config.json"),
        "stderr must carry the parse warning naming the file; got:\n{}",
        out.stderr
    );
    assert!(
        out.stderr.contains(PROXY_NOTICE),
        "with the config unusable the run falls back to the public proxy; stderr:\n{}",
        out.stderr
    );
    serde_json::from_str::<serde_json::Value>(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "--json stdout must stay parseable despite the warning ({e}); stdout:\n{}",
            out.stdout
        )
    });
}

/// `SOCKET_NO_CONFIG=1` disables the layer: a fully valid login fixture is
/// ignored and the run uses the public proxy without touching the network.
#[tokio::test]
async fn socket_no_config_ignores_valid_login() {
    let server = MockServer::start().await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());
    write_config(
        data.path(),
        &serde_json::json!({ "apiToken": token('c'), "apiBaseUrl": server.uri() }),
    );

    let mut cmd = scan_cmd(project.path(), data.path());
    cmd.env("SOCKET_NO_CONFIG", "1");
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        out.stderr.contains(PROXY_NOTICE),
        "SOCKET_NO_CONFIG=1 must ignore the config token; stderr:\n{}",
        out.stderr
    );
    let reqs = server.received_requests().await.unwrap_or_default();
    assert!(
        reqs.is_empty(),
        "no request may reach the config apiBaseUrl"
    );
}

/// `SOCKET_NO_API_TOKEN=1` vetoes ambient tokens — both the config file's
/// and the env var's — forcing the public proxy.
#[tokio::test]
async fn socket_no_api_token_vetoes_ambient_tokens() {
    let server = MockServer::start().await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());
    write_config(
        data.path(),
        &serde_json::json!({ "apiToken": token('c'), "apiBaseUrl": server.uri() }),
    );

    for ambient_env_token in [None, Some(token('e'))] {
        let mut cmd = scan_cmd(project.path(), data.path());
        cmd.env("SOCKET_NO_API_TOKEN", "1");
        if let Some(t) = &ambient_env_token {
            cmd.env("SOCKET_API_TOKEN", t);
        }
        let out = run(cmd);
        assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
        assert!(
            out.stderr.contains(PROXY_NOTICE),
            "SOCKET_NO_API_TOKEN must veto ambient tokens (env token set: {}); stderr:\n{}",
            ambient_env_token.is_some(),
            out.stderr
        );
    }
    let reqs = server.received_requests().await.unwrap_or_default();
    assert!(reqs.is_empty(), "vetoed runs must not authenticate");
}

/// An explicit `--api-token` flag survives the veto — `SOCKET_NO_API_TOKEN`
/// only suppresses *ambient* tokens.
#[tokio::test]
async fn explicit_flag_token_survives_veto() {
    let server = MockServer::start().await;
    mock_organizations(&server).await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());

    let mut cmd = scan_cmd(project.path(), data.path());
    cmd.args(["--api-token", &token('f')])
        .env("SOCKET_NO_API_TOKEN", "1")
        .env("SOCKET_API_URL", server.uri());
    let out = run(cmd);
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        !out.stderr.contains(PROXY_NOTICE),
        "an explicit --api-token must authenticate despite the veto; stderr:\n{}",
        out.stderr
    );
    assert_eq!(
        recorded_bearer(&server).await.as_deref(),
        Some(format!("Bearer {}", token('f')).as_str()),
    );
}

/// A missing config file is completely silent — no warning, public proxy.
#[tokio::test]
async fn missing_config_is_silent() {
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_project(project.path());

    let out = run(scan_cmd(project.path(), data.path()));
    assert_eq!(out.code, Some(0), "stderr:\n{}", out.stderr);
    assert!(
        !out.stderr.contains("socket-cli config"),
        "a missing config must not warn; stderr:\n{}",
        out.stderr
    );
    assert!(out.stderr.contains(PROXY_NOTICE));
}
