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
//! `apply/apply_silent_staging_errors.rs`; the offline arm is shared
//! (`report_offline_missing`) and is pinned here for vendor too.
//!
//! Under `--json` the diagnostics stay off stderr — the envelope is the
//! machine channel: one `failed` event for the patch with
//! `errorCode = apply_failed`.

use std::path::Path;

use serde_json::json;

use crate::common::envelope::{find_event, json_string, parse_json_envelope};
use crate::npm_fixture::{patch_record, run_cli, PURL, REG_RESOLVED};

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

/// Valid npm project and manifest with one patch entry and NO
/// blob/diff/package artifact anywhere under `.socket/` (and no committed
/// vendor artifact to harvest): the mem stager must fetch, or fail.
fn write_sourceless_manifest(root: &Path) {
    let write_json = |rel: &str, value: serde_json::Value| {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    };
    write_json(
        "package.json",
        json!({ "name": "fixture", "version": "1.0.0" }),
    );
    write_json(
        "package-lock.json",
        json!({
            "lockfileVersion": 3,
            "packages": {
                "": {},
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": REG_RESOLVED,
                    "integrity": "sha512-original"
                }
            }
        }),
    );
    write_json(
        ".socket/manifest.json",
        json!({ "patches": { PURL: patch_record(&"a".repeat(64), &"b".repeat(64)) } }),
    );
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

/// `vendor <mode> --api-url <dead> ...` with a syntactically valid token,
/// so every patch-content fetch fails at connect.
fn run_vendor_dead_endpoint(root: &Path, mode: &str) -> (i32, String, String) {
    let url = dead_endpoint();
    let token = format!("sktsec_{}_api", "x".repeat(44));
    run_cli(
        root,
        &[
            "vendor",
            mode,
            "--api-url",
            &url,
            "--proxy-url",
            &url,
            "--api-token",
            &token,
            "--org",
            "test-org",
        ],
        &[],
    )
}

/// `vendor --silent --offline` with a manifest patch that has no local
/// source must keep the shared offline error diagnostics (errors only,
/// never nothing) — the mem stager routes through the same
/// `report_offline_missing` as apply's disk stager.
#[test]
fn vendor_silent_offline_missing_source_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_cli(tmp.path(), &["vendor", "--silent", "--offline"], &[]);
    assert_eq!(code, 1, "offline + no local source must fail: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains(PURL) && l.contains("--offline")),
        "--silent must keep the offline no-source error naming the patch \
         (errors only, never nothing); stderr was: {stderr:?}"
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

    let (code, stdout, stderr) = run_vendor_dead_endpoint(tmp.path(), "--silent");
    assert_eq!(code, 1, "failed fetches + no source must fail: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains(PURL) && l.contains("request")),
        "--silent must keep the fetch-failure error naming the patch \
         (errors only, never nothing); stderr was: {stderr:?}"
    );
}

/// Overshoot guard: under `--json` the envelope is the machine channel —
/// the staging diagnostics must NOT leak to stderr, and the envelope
/// carries a `failed` / `apply_failed` event for the patch.
#[test]
fn vendor_json_online_fetch_failure_keeps_stderr_clean() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_vendor_dead_endpoint(tmp.path(), "--json");
    assert_eq!(code, 1, "failed fetches + no source must fail: {stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(json_string(&v, "status"), Some("partialFailure"), "{v}");
    let failed = find_event(&v, "failed", Some("apply_failed"));
    assert_eq!(failed["purl"], PURL, "{v}");
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--json suppresses the staging diagnostics on stderr (the \
         envelope is the machine channel); stderr was: {stderr:?}"
    );
}
