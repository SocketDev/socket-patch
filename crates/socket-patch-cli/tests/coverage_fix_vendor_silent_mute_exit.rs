//! `vendor --silent` sources-unavailable error-output contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only" — never "nothing":
//! an exit-1 run with zero output is undiagnosable. The in-memory staging
//! layer (`fetch_stage::stage_vendor_sources_in_memory`) muted its online
//! fetch-failure diagnostics under `--silent`:
//!
//! - `vendor --silent` whose per-patch content fetches all fail (dead
//!   endpoint) exited 1 with zero bytes on stdout+stderr (the "could not
//!   fetch patch content" summary and the per-file "no blob content
//!   served" line were gated on `!quiet`, i.e. muted by `--silent`),
//!   because the caller (`vendor.rs`) only marks the envelope — which
//!   prints exclusively under `--json`.
//!
//! Same class fixed for the DISK stager's arms in
//! `coverage_fix_apply_silent_mute_exit.rs`; the offline arm is shared
//! (`report_offline_missing`) and is pinned here for vendor too.
//!
//! Under `--json` the diagnostics stay off stderr — the envelope is the
//! machine channel (`error.code = no_local_source`, as `in_process_vendor.rs`
//! pins for the offline flavor).

use std::path::{Path, PathBuf};
use std::process::Command;

use socket_patch_cli::args::GLOBAL_ARG_ENV_VARS;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Run `socket-patch vendor` in `cwd` with a scrubbed SOCKET_* environment
/// so ambient developer/CI configuration (tokens, silent toggles) can't
/// change the branch under test.
fn run_vendor(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("vendor").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch vendor");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Non-error stderr lines: drop the unconditional core API-token warning
/// (both its lead line and its "Got: ... Continuing anyway" continuation)
/// and blank lines, keep everything else.
fn stderr_chatter(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| {
            !l.contains("SOCKET_API_TOKEN")
                && !l.contains("Continuing anyway")
                && !l.trim().is_empty()
        })
        .map(|l| l.to_string())
        .collect()
}

/// Valid manifest with one npm patch entry and NO blob/diff/package
/// artifact anywhere under `.socket/` (and no committed vendor artifact
/// to harvest) — the mem stager must fetch, or fail.
fn write_sourceless_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/left-pad@1.3.0": {
                "uuid": "11111111-1111-4111-8111-111111111111",
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "index.js": {
                    "beforeHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "afterHash":  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }},
                "vulnerabilities": {}, "description": "x",
                "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();
}

/// A guaranteed-unreachable local endpoint: bind an ephemeral port, then
/// release it, so every request fails fast with connection-refused.
fn dead_endpoint() -> String {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    format!("http://127.0.0.1:{port}")
}

/// `vendor --silent --offline` with a manifest patch that has no local
/// source must keep the shared offline error diagnostics (errors only,
/// never nothing) — the mem stager routes through the same
/// `report_offline_missing` as apply's disk stager.
#[test]
fn vendor_silent_offline_missing_source_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_vendor(tmp.path(), &["--silent", "--offline"]);
    assert_eq!(code, 1, "offline + no local source must fail: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.iter().any(|l| l.contains("no local source")),
        "--silent must keep the offline no-source error (errors only, \
         never nothing); stderr was: {stderr:?}"
    );
}

/// Online `vendor --silent` where every patch-content fetch fails (dead
/// endpoint) must keep the fetch-failure error output — the caller only
/// marks the envelope, which never prints in human mode, so a muted
/// stager means exit 1 with zero output.
#[test]
fn vendor_silent_online_fetch_failure_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let url = dead_endpoint();
    let token = format!("sktsec_{}_api", "x".repeat(44));
    let (code, stdout, stderr) = run_vendor(
        tmp.path(),
        &[
            "--silent",
            "--api-url",
            &url,
            "--proxy-url",
            &url,
            "--api-token",
            &token,
            "--org",
            "test-org",
        ],
    );
    assert_eq!(code, 1, "failed fetches + no source must fail: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains("could not fetch patch content")),
        "--silent must keep the fetch-failure error (errors only, \
         never nothing); stderr was: {stderr:?}"
    );
}

/// Overshoot guard: under `--json` the envelope is the machine channel —
/// the staging diagnostics must NOT leak to stderr, and the envelope
/// carries vendor's pinned `no_local_source` hard error.
#[test]
fn vendor_json_online_fetch_failure_keeps_stderr_clean() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let url = dead_endpoint();
    let token = format!("sktsec_{}_api", "x".repeat(44));
    let (code, stdout, stderr) = run_vendor(
        tmp.path(),
        &[
            "--json",
            "--api-url",
            &url,
            "--proxy-url",
            &url,
            "--api-token",
            &token,
            "--org",
            "test-org",
        ],
    );
    assert_eq!(code, 1, "failed fetches + no source must fail: {stderr}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("vendor --json must emit valid JSON");
    assert_eq!(
        v["error"]["code"], "no_local_source",
        "the pinned envelope error for the unavailable bail, got {v}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--json suppresses the staging diagnostics on stderr (the \
         envelope is the machine channel); stderr was: {stderr:?}"
    );
}
