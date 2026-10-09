//! Readers for `rollback --json` (v5.0: the unified envelope).
//!
//! Every rollback outcome is an event; these project the events back into
//! the per-leg views tests assert on (which purls each leg rolled back,
//! which failed, which manifest entries left), so a test reads one call
//! instead of re-filtering `events[]`. Each view is a JSON array, so
//! `assert_eq!(view, serde_json::json!([...]))` and `view[0]["purl"]` work.
//!
//! Include with `#[path = "common/rollback_json.rs"] mod rollback_json;`
//! (`"../common/rollback_json.rs"` from a test directory).

#![allow(dead_code)]

use serde_json::{json, Value};

fn events(v: &Value) -> &[Value] {
    v["events"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| panic!("no `events` array in:\n{v:#}"))
}

fn mode(e: &Value) -> Option<&str> {
    e["details"]["mode"].as_str()
}

/// A restore (`rolledBack`, or its `verified` dry-run preview) — never a
/// manifest-removal preview.
fn is_restore(e: &Value) -> bool {
    (e["action"] == "rolledBack" || e["action"] == "verified") && e["details"]["manifest"] != true
}

fn purls<'a>(it: impl Iterator<Item = &'a Value>) -> Value {
    Value::Array(it.map(|e| e["purl"].clone()).collect())
}

/// `summary.<action>` as a number.
pub fn summary(v: &Value, action: &str) -> u64 {
    v["summary"][action]
        .as_u64()
        .unwrap_or_else(|| panic!("no summary.{action} in:\n{v:#}"))
}

/// Manifest entries the run dropped (`removed`, or `verified` on a dry
/// run, with `details.manifest: true`), in event order.
pub fn manifest_removed(v: &Value) -> Value {
    purls(
        events(v)
            .iter()
            .filter(|e| e["details"]["manifest"] == true),
    )
}

/// Agent-leg (in-place) restores: purls with a `rolledBack` (wet) or
/// `verified` (dry run) event and no `details.mode`.
pub fn agent_rolled_back(v: &Value) -> Value {
    purls(
        events(v)
            .iter()
            .filter(|e| is_restore(e) && mode(e).is_none()),
    )
}

/// The agent-leg event for `purl` with `action`; panics when absent.
pub fn agent_event<'a>(v: &'a Value, action: &str, purl: &str) -> &'a Value {
    events(v)
        .iter()
        .find(|e| {
            e["action"] == action
                && e["purl"] == purl
                && mode(e).is_none()
                && e["details"]["manifest"] != true
        })
        .unwrap_or_else(|| panic!("no agent `{action}` event for {purl} in:\n{v:#}"))
}

/// `skipped` events with `errorCode == code`, as purls.
pub fn skipped_with(v: &Value, code: &str) -> Value {
    purls(
        events(v)
            .iter()
            .filter(|e| e["action"] == "skipped" && e["errorCode"] == code),
    )
}

/// How many packages were already original (`skipped` `already_original`).
pub fn already_original(v: &Value) -> usize {
    skipped_with(v, "already_original")
        .as_array()
        .unwrap()
        .len()
}

/// In-scope manifest entries with no installed package.
pub fn not_installed(v: &Value) -> Value {
    skipped_with(v, "package_not_installed")
}

/// Vendored entries reverted (artifact deleted), previewed on a dry run.
pub fn vendored_reverted(v: &Value) -> Value {
    purls(events(v).iter().filter(|e| {
        is_restore(e) && mode(e) == Some("vendored") && e["details"]["preserved"] != true
    }))
}

/// `--preserve-state` vendored entries: unwired, artifact + ledger kept.
pub fn vendored_preserved(v: &Value) -> Value {
    purls(events(v).iter().filter(|e| {
        is_restore(e) && mode(e) == Some("vendored") && e["details"]["preserved"] == true
    }))
}

fn failed_view(v: &Value, pick: impl Fn(&Value) -> bool, key: &str) -> Value {
    Value::Array(
        events(v)
            .iter()
            .filter(|e| e["action"] == "failed" && pick(e))
            .map(|e| json!({ "purl": e["purl"], key: e["error"], "errorCode": e["errorCode"] }))
            .collect(),
    )
}

/// Vendored drift-keeps as `[{purl, reason, errorCode}]`.
pub fn vendored_kept(v: &Value) -> Value {
    failed_view(
        v,
        |e| mode(e) == Some("vendored") && e["errorCode"] == "vendor_revert_kept",
        "reason",
    )
}

/// Vendored revert failures as `[{purl, error, errorCode}]`.
pub fn vendored_failed(v: &Value) -> Value {
    failed_view(
        v,
        |e| mode(e) == Some("vendored") && e["errorCode"] != "vendor_revert_kept",
        "error",
    )
}

/// Hosted pins restored to upstream (previewed on a dry run).
pub fn hosted_reverted(v: &Value) -> Value {
    purls(
        events(v)
            .iter()
            .filter(|e| is_restore(e) && mode(e) == Some("hosted")),
    )
}

/// Hosted-leg failures as `[{purl, error, errorCode}]` (`purl` null for
/// the artifact-level `hosted_write_failed` / `hosted_wiring_contested`).
pub fn hosted_failed(v: &Value) -> Value {
    failed_view(v, |e| mode(e) == Some("hosted"), "error")
}

/// Every failed event as `[{purl, error, errorCode}]`.
pub fn failed(v: &Value) -> Value {
    failed_view(v, |_| true, "error")
}

/// The run-level warning codes.
pub fn warning_codes(v: &Value) -> Vec<String> {
    v["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w["code"].as_str().map(str::to_string))
        .collect()
}

/// The shared-envelope invariants every rollback document keeps:
/// `command: "rollback"`, a camelCase status, `summary` == event counts,
/// no snake_case top-level key.
pub fn assert_rollback_envelope(v: &Value) {
    assert_eq!(v["command"], "rollback", "{v:#}");
    let status = v["status"].as_str().expect("status string");
    assert!(
        ["success", "partialFailure", "error"].contains(&status),
        "status {status}: {v:#}"
    );
    for key in v.as_object().expect("object").keys() {
        assert!(!key.contains('_'), "snake_case key {key}: {v:#}");
    }
    for action in [
        "discovered",
        "downloaded",
        "applied",
        "updated",
        "skipped",
        "failed",
        "removed",
        "verified",
        "rebuilt",
        "rolledBack",
    ] {
        let n = events(v).iter().filter(|e| e["action"] == action).count() as u64;
        assert_eq!(summary(v, action), n, "summary.{action}: {v:#}");
    }
}

/// Every event whose `details.mode` is `mode` (`vendored` / `hosted`).
pub fn events_with_mode<'a>(v: &'a Value, mode_name: &str) -> Vec<&'a Value> {
    events(v)
        .iter()
        .filter(|e| mode(e) == Some(mode_name))
        .collect()
}
