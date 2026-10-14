//! `vendor --silent` error-output contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only" — never "nothing":
//! an exit-1 run with zero output is undiagnosable. These pin that a
//! patch vendor can't source still prints its per-patch `Error:` line
//! under `--silent`, both offline (the service source needs the network)
//! and online when every patch-service request fails (dead endpoint).
//! Vendor's caller marks the envelope too, but the envelope prints only
//! under `--json`, so a muted error line means exit 1 with zero output.
//!
//! Apply's staging-layer twin is `apply/apply_silent_staging_errors.rs`.
//!
//! Under `--json` the error lines stay off stderr — the envelope is the
//! machine channel: one `failed` event for the patch with
//! `errorCode = apply_failed`.

use std::path::Path;

use serde_json::json;

use crate::common::envelope::{find_event, parse_json_envelope};
use crate::common::hermetic;
use crate::npm_fixture::{dead_endpoint, patch_record, PURL, REG_RESOLVED};

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

/// Whether some stderr line is the per-patch error for [`PURL`].
fn has_patch_error_line(chatter: &[String]) -> bool {
    chatter
        .iter()
        .any(|l| l.starts_with("Error:") && l.contains(PURL))
}

/// Valid npm project and manifest with one patch entry and NO
/// blob/diff/package artifact anywhere under `.socket/` (and no committed
/// vendor artifact to harvest): vendor must fetch the patch, or fail.
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

/// `socket-patch vendor <args>` in `cwd` through the hermetic binary
/// command (every ambient `SOCKET_*` var scrubbed), with no fixture patch
/// service, so no configured vendor URL changes the branch under test.
fn run_vendor(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out = hermetic::binary_command()
        .arg("vendor")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("run socket-patch vendor");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vendor <mode>` with the patch API and proxy on a dead endpoint, so
/// every patch-service request fails at connect. The token has the real
/// `sktsec_<44 chars>_api` shape: a placeholder such as the siblings'
/// `sktsec_placeholder_value_for_tests_api` draws the token-shape warning
/// on stderr, which the `--json` test requires to stay clean.
fn run_vendor_dead_endpoint(root: &Path, mode: &str) -> (i32, String, String) {
    let url = dead_endpoint();
    let token = format!("sktsec_{}_api", "x".repeat(44));
    run_vendor(
        root,
        &[
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
    )
}

/// `vendor --silent --offline` with a manifest patch that has no local
/// source must keep the per-patch error line (errors only, never nothing).
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
    assert!(
        has_patch_error_line(&stderr_chatter(&stderr)),
        "--silent must keep the per-patch error line (errors only, never \
         nothing); stderr was: {stderr:?}"
    );
}

/// Online `vendor --silent` where every patch-service request fails (dead
/// endpoint) must keep the per-patch error line.
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
    assert!(
        has_patch_error_line(&stderr_chatter(&stderr)),
        "--silent must keep the per-patch error line (errors only, never \
         nothing); stderr was: {stderr:?}"
    );
}

/// Overshoot guard: under `--json` the envelope is the machine channel —
/// the error lines must NOT leak to stderr, and the envelope carries a
/// `failed` / `apply_failed` event for the patch.
#[test]
fn vendor_json_online_fetch_failure_keeps_stderr_clean() {
    let tmp = tempfile::tempdir().unwrap();
    write_sourceless_manifest(tmp.path());

    let (code, stdout, stderr) = run_vendor_dead_endpoint(tmp.path(), "--json");
    assert_eq!(code, 1, "failed fetches + no source must fail: {stderr}");
    let v = parse_json_envelope(&stdout);
    let failed = find_event(&v, "failed", Some("apply_failed"));
    assert_eq!(failed["purl"], PURL, "{v}");
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--json keeps the error lines off stderr (the envelope is the \
         machine channel); stderr was: {stderr:?}"
    );
}
