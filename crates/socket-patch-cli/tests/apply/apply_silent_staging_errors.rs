//! `apply --silent` sources-unavailable error-output contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only" — never "nothing":
//! an exit-1 run with zero output is undiagnosable. The staging layer
//! (`fetch_stage::stage_patch_sources`) muted BOTH of its `Unavailable`
//! diagnostics under `--silent`:
//!
//! 1. `apply --silent --offline` with a manifest patch that has no local
//!    blob/diff/package source exited 1 with zero bytes on stdout+stderr
//!    (`report_offline_missing` returned early on `silent || json`).
//! 2. Online `apply --silent` whose downloads all fail (dead endpoint)
//!    exited 1 with zero output (the "Some artifacts could not be
//!    downloaded" line was gated on `!quiet`, i.e. muted by `--silent`).
//!
//! Sibling suites: `cli_apply_silent.rs` (other apply paths) and
//! `cli_rollback_silent.rs` (the same rule for rollback).
//!
//! Under `--json` both diagnostics stay off stderr — the envelope is the
//! machine channel, and `apply_invariants.rs` pins its exact shape for
//! this path (partialFailure, empty events, NO top-level error record —
//! unlike vendor, which records a `failed` / `apply_failed` event for the
//! patch; see `vendor/vendor_silent_errors.rs`).

use std::path::Path;

use serde_json::json;

use crate::apply_fixture::{patch_record, run_apply, write_manifest};
use crate::common::envelope::{json_string, parse_json_envelope};

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
/// artifact anywhere under `.socket/`: staging has no usable source.
fn write_sourceless_manifest(root: &Path) {
    write_manifest(
        root,
        json!({
            "pkg:npm/left-pad@1.3.0": patch_record(
                "11111111-1111-4111-8111-111111111111",
                json!({ "index.js": { "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64) } }),
            )
        }),
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

/// `apply --silent --offline` with a manifest patch that has no local
/// source must keep the offline error diagnostics ("errors only", never
/// "nothing" — exit 1 with no output is undiagnosable in the npm
/// postinstall hook that runs `apply` silently).
#[test]
fn apply_silent_offline_missing_source_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--silent", "--offline"], &[]);
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

/// Online `apply --silent` where every artifact download fails (dead
/// endpoint) must keep the download-failure error output.
#[test]
fn apply_silent_online_download_failure_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let url = dead_endpoint();
    let token = format!("sktsec_{}_api", "x".repeat(44));
    let (code, stdout, stderr) = run_apply(
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
        &[],
    );
    assert_eq!(code, 1, "failed downloads + no source must fail: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains("could not be downloaded")),
        "--silent must keep the download-failure error (errors only, \
         never nothing); stderr was: {stderr:?}"
    );
    assert!(
        chatter.iter().any(|l| l.contains("Failed to download")),
        "--silent must keep the per-blob failure reasons with the error; \
         stderr was: {stderr:?}"
    );
}

/// Overshoot guard: under `--json` the envelope is the machine channel —
/// the staging diagnostics must NOT leak to stderr, and the envelope
/// keeps the exact shape `apply_invariants.rs` pins for this path
/// (partialFailure, no top-level error record).
#[test]
fn apply_json_offline_missing_source_keeps_stderr_clean() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    assert_eq!(code, 1, "offline + no local source must fail: {stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&v, "status"),
        Some("partialFailure"),
        "the pinned envelope shape for the offline bail, got {v}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--json suppresses the staging diagnostics on stderr (the \
         envelope is the machine channel); stderr was: {stderr:?}"
    );
}
