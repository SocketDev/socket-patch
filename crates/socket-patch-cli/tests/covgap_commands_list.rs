//! Coverage-gap tests for `commands/list.rs` (audit of 2026-09, commit
//! d5e1815): the `--debug` provenance echoes for config-sourced telemetry
//! credentials (`telemetry_credentials`'s two `inspect` closures ran under
//! the config-fallback tests, but never with `--debug`), and the
//! human-readable listing's sparse-record branches — a vulnerability with
//! no CVE ids (GHSA-only advisories are a real production shape), and a
//! record with zero vulnerabilities / zero files, whose section headers
//! must be omitted entirely.
//!
//! Binary-driven. The debug-echo test mirrors
//! cli_config_fallback.rs::list_telemetry_follows_socket_cli_login (its
//! hermetic command builder and config fixture are copied here — do not
//! edit that file); the human-mode test mirrors the `list` section of
//! output_modes_e2e.rs through `common::run_with_env`.

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use wiremock::MockServer;

#[path = "common/mod.rs"]
mod common;

// ---------------------------------------------------------------------------
// `--debug` provenance echoes (list.rs telemetry_credentials, config layer)
// ---------------------------------------------------------------------------

const BINARY: &str = env!("CARGO_BIN_EXE_socket-patch");

/// The platform env var that positions the socket-cli data dir.
const DATA_DIR_VAR: &str = if cfg!(windows) {
    "LOCALAPPDATA"
} else {
    "XDG_DATA_HOME"
};

/// A shape-valid API token (`sktsec_<44 chars>_api`) so the token-shape
/// warning never muddies the stderr assertions below.
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

/// An empty manifest, so `list` exits 0 without needing anything but the
/// credential resolution under test.
fn write_empty_manifest(root: &Path) {
    let dir = root.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("manifest.json"), r#"{ "patches": {} }"#).unwrap();
}

/// `socket-patch list` against `project`, hermetic like
/// cli_config_fallback.rs's `list_cmd`: every ambient `SOCKET_*` scrubbed,
/// the data dir pointed at the fixture, the config layer re-enabled,
/// telemetry off (the provenance test re-enables it), the update notifier
/// off. `debug` adds the `--debug` flag under test.
fn list_cmd(project: &Path, data_dir: &Path, debug: bool) -> Command {
    let mut cmd = Command::new(BINARY);
    cmd.arg("list");
    if debug {
        cmd.arg("--debug");
    }
    cmd.arg("--cwd").arg(project);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env(DATA_DIR_VAR, data_dir);
    cmd.env("SOCKET_NO_CONFIG", "0");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd.env("SOCKET_NO_UPDATE_CHECK", "1");
    cmd
}

/// With credentials resolved from the socket-cli config layer (no flag, no
/// env var), `--debug` must echo the resolution source for BOTH the api
/// token and the org slug — the documented provenance contract of
/// `telemetry_credentials` — and the echoes must tell the truth: the
/// telemetry POST actually goes out under those config credentials.
#[tokio::test]
async fn list_debug_echoes_config_credential_provenance() {
    let server = MockServer::start().await;
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_manifest(project.path());
    write_config(
        data.path(),
        &serde_json::json!({
            "apiToken": token('c'),
            "apiBaseUrl": server.uri(),
            "defaultOrg": "cfg-org"
        }),
    );

    let mut cmd = list_cmd(project.path(), data.path(), true);
    cmd.env("SOCKET_TELEMETRY_DISABLED", "0");
    // Pin the anonymous fallback at the fixture too, so a run that skips
    // the config layer is caught below instead of escaping to the real
    // public proxy.
    cmd.env("SOCKET_PROXY_URL", server.uri());
    let out = cmd.output().expect("run socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");

    assert!(
        stderr.contains("[socket-patch debug] api token: from socket-cli config (`socket login`)"),
        "--debug must echo the api-token resolution source; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("[socket-patch debug] org slug: `cfg-org` from socket-cli config"),
        "--debug must echo the org-slug resolution source (naming the slug); stderr:\n{stderr}"
    );

    // Control: the echoes describe credentials that were actually USED —
    // the telemetry event must have POSTed to the config org's endpoint
    // with the config token, never to the anonymous proxy path.
    let reqs = server.received_requests().await.unwrap_or_default();
    let paths: Vec<&str> = reqs.iter().map(|r| r.url.path()).collect();
    let telemetry = reqs
        .iter()
        .find(|r| r.url.path() == "/v0/orgs/cfg-org/telemetry")
        .unwrap_or_else(|| {
            panic!(
                "list telemetry must POST to the org endpoint the debug echo \
                 attributed; requests seen: {paths:?}"
            )
        });
    assert_eq!(
        telemetry
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap_or_default().to_string())
            .as_deref(),
        Some(format!("Bearer {}", token('c')).as_str()),
        "telemetry must carry the config token the debug echo attributed"
    );
    assert!(
        !paths.contains(&"/patch/telemetry"),
        "the echoed config credentials must preempt the anonymous proxy; \
         requests seen: {paths:?}"
    );
}

/// Without `--debug`, the same config-resolved run stays quiet: the
/// provenance echoes are debug-gated, not unconditional.
#[tokio::test]
async fn list_without_debug_omits_provenance_echoes() {
    let data = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    write_empty_manifest(project.path());
    write_config(
        data.path(),
        &serde_json::json!({ "apiToken": token('c'), "defaultOrg": "cfg-org" }),
    );

    let mut cmd = list_cmd(project.path(), data.path(), false);
    let out = cmd.output().expect("run socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "stderr:\n{stderr}");
    assert!(
        !stderr.contains("[socket-patch debug]"),
        "provenance echoes must be gated on --debug; stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// human-readable listing — sparse-record branches
// ---------------------------------------------------------------------------

/// Raw camelCase manifest with two deliberately sparse records (the shared
/// `write_manifest` fixtures always carry a CVE-bearing vuln and a file, so
/// they can never reach these branches):
///   A `pkg:npm/ghsa-only@1.0.0` — one advisory with an EMPTY `cves` list
///     (a GHSA-only advisory) plus one file entry;
///   B `pkg:npm/bare@1.0.0` — zero vulnerabilities, zero files.
fn write_sparse_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let bh = "b".repeat(64);
    let ah = "a".repeat(64);
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "pkg:npm/ghsa-only@1.0.0": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{bh}",
          "afterHash": "{ah}"
        }}
      }},
      "vulnerabilities": {{
        "GHSA-test-0001-0001": {{
          "cves": [],
          "summary": "GHSA-only advisory",
          "severity": "high",
          "description": "d"
        }}
      }},
      "description": "Fixes an advisory with no CVE id",
      "license": "MIT",
      "tier": "free"
    }},
    "pkg:npm/bare@1.0.0": {{
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();
}

/// The human-readable block for `purl`: from its `Package:` line up to the
/// next `Package:` line (or end of output).
fn package_block<'a>(stdout: &'a str, purl: &str) -> &'a str {
    let header = format!("Package: {purl}");
    let start = stdout
        .find(&header)
        .unwrap_or_else(|| panic!("no block for {purl}; stdout:\n{stdout}"));
    let rest = &stdout[start + header.len()..];
    match rest.find("Package: ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

/// Human-mode listing of sparse records: a CVE-less advisory prints its id
/// with NO parenthesized CVE suffix, and a record with zero vulnerabilities
/// / zero files omits both section headers instead of printing empty ones.
#[test]
fn list_non_json_minimal_record_omits_empty_sections() {
    let tmp = tempfile::tempdir().unwrap();
    write_sparse_manifest(tmp.path());

    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &["list"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(
        stdout.contains("Found 2 patch(es)"),
        "both records must list; got: {stdout}"
    );

    // A: the GHSA-only advisory prints bare — the exact line ends at the id
    // (println! terminates it), so an empty cves list must add no " (...)".
    assert!(
        stdout.contains("    - GHSA-test-0001-0001\n"),
        "a CVE-less advisory must print its bare id; got: {stdout}"
    );
    assert!(
        !stdout.contains("GHSA-test-0001-0001 ("),
        "an empty cves list must not print a parenthesized suffix; got: {stdout}"
    );
    // Control: the A block does carry both populated sections, so the
    // omission assertions on B below cannot pass vacuously.
    let ghsa_block = package_block(&stdout, "pkg:npm/ghsa-only@1.0.0");
    assert!(
        ghsa_block.contains("Vulnerabilities (1):") && ghsa_block.contains("Severity: high"),
        "the populated record must print its vulnerability section; got: {ghsa_block}"
    );
    assert!(
        ghsa_block.contains("Files patched (1):") && ghsa_block.contains("package/index.js"),
        "the populated record must print its files section; got: {ghsa_block}"
    );

    // B: zero vulnerabilities / zero files ⇒ neither header appears in the
    // bare record's block.
    let bare_block = package_block(&stdout, "pkg:npm/bare@1.0.0");
    assert!(
        bare_block.contains("UUID: 22222222-2222-4222-8222-222222222222"),
        "sanity: the bare record's block must be real; got: {bare_block}"
    );
    assert!(
        !bare_block.contains("Vulnerabilities ("),
        "a zero-vulnerability record must omit the section header; got: {bare_block}"
    );
    assert!(
        !bare_block.contains("Files patched ("),
        "a zero-file record must omit the section header; got: {bare_block}"
    );
    // An empty description is likewise omitted (same sparse-record posture).
    assert!(
        !bare_block.contains("Description:"),
        "an empty description must be omitted; got: {bare_block}"
    );
}
