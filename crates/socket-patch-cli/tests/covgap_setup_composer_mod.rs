//! Coverage-gap tests for `setup/composer/mod.rs` driven through the built
//! binary: the malformed-composer.json contract.
//!
//! `is_hook_present` deliberately reads unparseable JSON as "not configured"
//! (mod.rs line 75) while `composer_add` / `composer_remove` error loudly on
//! the same bytes — so on one and the same broken file `setup --check` reports
//! needs-configuration (run setup to fix) and `setup` / `setup --remove`
//! refuse with an error instead of a silent success. That asymmetry is only
//! observable end-to-end at the binary level; the healthy setup/check/remove
//! round trip already lives in
//! `covgap_commands_setup.rs::composer_setup_check_remove_round_trip`.

use std::path::Path;

#[path = "common/mod.rs"]
mod common;

/// A composer.json that does not parse. The check probe must classify it, the
/// editing paths must refuse it — and nobody may crash, wedge, or rewrite it.
const MALFORMED_COMPOSER_JSON: &str = "{ oops, this is not JSON\n";

fn write(path: &Path, content: &str) {
    std::fs::write(path, content).expect("write file");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read file")
}

/// Run the binary through the shared hermetic runner (`SOCKET_*` scrubbed,
/// telemetry disabled), asserting stdout is one JSON document.
fn run_json(cwd: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let (code, stdout, stderr) =
        common::run_with_env(cwd, args, &[("SOCKET_TELEMETRY_DISABLED", "1")]);
    let v = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be JSON ({e}); stdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (code, v)
}

/// The single `files[]` entry with kind `composer` (panics on 0 or >1).
fn composer_entry(v: &serde_json::Value) -> &serde_json::Value {
    let matches: Vec<&serde_json::Value> = v["files"]
        .as_array()
        .unwrap_or_else(|| panic!("files must be an array: {v}"))
        .iter()
        .filter(|f| f["kind"] == "composer")
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one composer entry, got {}: {v}",
        matches.len()
    );
    matches[0]
}

/// `setup --check` on a malformed composer.json: the probe (is_hook_present)
/// classifies the unparseable file as needs-configuration — no crash, no
/// error entry (the read succeeded; only the parse failed), exit 1 so CI
/// still flags the project as unwired.
#[test]
fn check_malformed_composer_json_reports_needs_configuration() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("composer.json"), MALFORMED_COMPOSER_JSON);

    let (code, v) = run_json(cwd, &["setup", "--check", "--json"]);
    assert_eq!(code, 1, "an unwired project must fail the check: {v}");
    assert_eq!(v["status"], "needs_configuration", "{v}");
    let entry = composer_entry(&v);
    assert_eq!(
        entry["status"], "needs_configuration",
        "malformed JSON must read as not-configured, not crash the probe: {v}"
    );
    assert!(
        entry["error"].is_null(),
        "the check probe carries no error for a readable-but-unparseable file \
         (the parse failure surfaces when `setup` runs): {v}"
    );
    assert_eq!(
        read(&cwd.join("composer.json")),
        MALFORMED_COMPOSER_JSON,
        "--check must never write"
    );
}

/// `setup` on the very same malformed file: the edit path refuses loudly —
/// entry status `error` naming the parse failure, envelope status `error`,
/// exit 1 — and leaves the user's broken file byte-identical (no clobber,
/// no "helpful" rewrite).
#[test]
fn setup_malformed_composer_json_errors_loudly_and_leaves_file_untouched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("composer.json"), MALFORMED_COMPOSER_JSON);

    let (code, v) = run_json(cwd, &["setup", "--yes", "--json"]);
    assert_eq!(code, 1, "setup on a malformed composer.json must fail: {v}");
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["updated"], 0, "{v}");
    assert_eq!(v["errors"], 1, "{v}");
    let entry = composer_entry(&v);
    assert_eq!(entry["status"], "error", "{v}");
    assert!(
        entry["error"]
            .as_str()
            .is_some_and(|e| e.contains("Invalid composer.json")),
        "the entry must carry the parse error, naming the file kind: {v}"
    );
    assert_eq!(
        read(&cwd.join("composer.json")),
        MALFORMED_COMPOSER_JSON,
        "a refused setup must leave the malformed file byte-identical"
    );
}

/// `setup --remove` on a malformed composer.json is the same loud refusal —
/// NOT a silent "nothing to remove" no-op (which would report success while
/// `--check` on the same file says needs-configuration). Mirrors the inline
/// `test_remove_non_object_root_is_error` contract at the binary level.
#[test]
fn remove_malformed_composer_json_errors_not_silent_noop() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cwd = tmp.path();
    write(&cwd.join("composer.json"), MALFORMED_COMPOSER_JSON);

    let (code, v) = run_json(cwd, &["setup", "--remove", "--yes", "--json"]);
    assert_eq!(code, 1, "remove on a malformed composer.json must fail: {v}");
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["removed"], 0, "{v}");
    assert_eq!(v["errors"], 1, "{v}");
    let entry = composer_entry(&v);
    assert_eq!(entry["status"], "error", "{v}");
    assert!(
        entry["error"]
            .as_str()
            .is_some_and(|e| e.contains("Invalid composer.json")),
        "the entry must carry the parse error: {v}"
    );
    assert_eq!(
        read(&cwd.join("composer.json")),
        MALFORMED_COMPOSER_JSON,
        "a refused remove must leave the malformed file byte-identical"
    );
}
