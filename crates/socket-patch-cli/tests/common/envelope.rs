//! Readers for the `--json` envelope every command prints (#1089).
//!
//! Tests assert on stable codes, not sentences: parse stdout once with
//! [`parse_json_envelope`], then read `events[]`, their `errorCode`s and the
//! `warnings[]` codes through these helpers instead of a private copy.
//!
//! Files that don't need the rest of `common` pull this in on its own with
//! `#[path = "common/envelope.rs"] mod envelope;`.

#![allow(dead_code)]

use serde_json::Value;

/// `stdout` parsed as JSON; panics with the raw output when it isn't.
pub fn parse_json_envelope(stdout: &str) -> Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("failed to parse JSON envelope: {e}\nstdout:\n{stdout}"))
}

/// A top-level string field (`status`, …), or `None` when it is missing
/// or not a string.
pub fn json_string<'a>(env: &'a Value, key: &str) -> Option<&'a str> {
    env.get(key).and_then(|v| v.as_str())
}

/// `env.error.code`: the envelope nests a top-level failure under `error`
/// (`{"error": {"code": "lock_held", "message": "..."}}`).
pub fn envelope_error_code(env: &Value) -> Option<&str> {
    env.get("error")?.get("code")?.as_str()
}

/// `env.error.message`, the companion of [`envelope_error_code`].
pub fn envelope_error_message(env: &Value) -> Option<&str> {
    env.get("error")?.get("message")?.as_str()
}

/// The envelope's `events[]`; panics when the array is missing (every
/// command envelope serializes it, empty or not).
pub fn events(envelope: &Value) -> &[Value] {
    envelope["events"]
        .as_array()
        .unwrap_or_else(|| panic!("no `events` array in:\n{envelope:#}"))
}

/// The first `action` event (with `errorCode == code` when given); panics
/// with the envelope when there is none.
pub fn find_event<'a>(envelope: &'a Value, action: &str, error_code: Option<&str>) -> &'a Value {
    events(envelope)
        .iter()
        .find(|e| e["action"] == action && error_code.is_none_or(|c| e["errorCode"] == c))
        .unwrap_or_else(|| {
            panic!("expected a `{action}` event (errorCode={error_code:?}) in:\n{envelope:#}")
        })
}

/// Each event as `(purl, action, errorCode)`, absent fields as `""`.
pub fn event_triples(envelope: &Value) -> Vec<(String, String, String)> {
    events(envelope)
        .iter()
        .map(|e| {
            let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
            (s("purl"), s("action"), s("errorCode"))
        })
        .collect()
}

/// The `errorCode` of every event that has one; empty when `events` is
/// missing.
pub fn event_codes(envelope: &Value) -> Vec<String> {
    envelope["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["errorCode"].as_str().map(str::to_string))
        .collect()
}

/// The `code` of every entry of a warnings array (`&env["warnings"]`,
/// `&env["redirect"]["warnings"]`, …); empty when `list` isn't an array.
pub fn codes_in(list: &Value) -> Vec<String> {
    list.as_array()
        .into_iter()
        .flatten()
        .filter_map(|w| w["code"].as_str().map(str::to_string))
        .collect()
}

/// Every `code` and `errorCode` string anywhere in `doc`, depth first.
pub fn all_codes(doc: &Value) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, v) in map {
                    if k == "code" || k == "errorCode" {
                        if let Some(s) = v.as_str() {
                            out.push(s.to_string());
                        }
                    }
                    walk(v, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(doc, &mut out);
    out
}

/// The top-level `warnings[]` codes (every command, v5.0: warnings are only
/// ever top level).
pub fn warning_codes(envelope: &Value) -> Vec<String> {
    codes_in(&envelope["warnings"])
}

/// The events of one leg: those whose `details.mode` is `mode`
/// (`"hosted"` / `"vendored"`; agent-mode events carry no mode).
pub fn mode_events<'a>(envelope: &'a Value, mode: &str) -> Vec<&'a Value> {
    events(envelope)
        .iter()
        .filter(|e| e["details"]["mode"] == mode)
        .collect()
}

/// `(purl, uuid)` of every hosted pin the run wrote — or, on a dry run,
/// would write: the `applied` / `verified` events with
/// `details.mode: "hosted"` (v5.0's `redirect.patches[]` `pinned` /
/// `would_pin` rows).
pub fn hosted_pins(envelope: &Value) -> Vec<(String, String)> {
    mode_events(envelope, "hosted")
        .into_iter()
        .filter(|e| e["action"] == "applied" || e["action"] == "verified")
        .map(|e| {
            (
                e["purl"].as_str().unwrap_or_default().to_string(),
                e["uuid"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// The `{purl, uuid, reason, detail}` rows of the hosted `skipped` events
/// (v5.0's `redirect.skipped[]`: `reason` is the event's `errorCode`).
pub fn hosted_skips(envelope: &Value) -> Vec<(String, String)> {
    mode_events(envelope, "hosted")
        .into_iter()
        .filter(|e| e["action"] == "skipped")
        .map(|e| {
            (
                e["purl"].as_str().unwrap_or_default().to_string(),
                e["errorCode"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// The shared envelope invariants every `--json` document holds: `command`
/// is `command`, `status` is a camelCase `Status`, `dryRun` a bool,
/// `events` an array, every counted `summary` field equals its event count
/// (`uncounted` skipped events — the vendor engine's advisories — are
/// allowed on top of `summary.skipped`), `error` is `{code, message}` iff
/// `status` is `error` or `selectionRequired`, and no top-level key or event
/// action is snake_case.
pub fn assert_envelope_invariants(envelope: &Value, command: &str) {
    assert_eq!(envelope["command"], command, "{envelope:#}");
    let status = envelope["status"].as_str().expect("status");
    assert!(
        [
            "success",
            "partialFailure",
            "error",
            "noManifest",
            "paidRequired",
            "notFound",
            "notInstalled",
            "noMatch",
            "noPackages",
            "selectionRequired",
        ]
        .contains(&status),
        "status {status:?} is not a Status: {envelope:#}"
    );
    assert!(envelope["dryRun"].is_boolean(), "{envelope:#}");
    let evs = events(envelope);
    let summary = &envelope["summary"];
    for (field, action) in [
        ("discovered", "discovered"),
        ("downloaded", "downloaded"),
        ("applied", "applied"),
        ("updated", "updated"),
        ("failed", "failed"),
        ("removed", "removed"),
        ("verified", "verified"),
        ("rebuilt", "rebuilt"),
        ("rolledBack", "rolledBack"),
    ] {
        let n = evs.iter().filter(|e| e["action"] == action).count() as u64;
        assert_eq!(summary[field], n, "summary.{field} vs events: {envelope:#}");
    }
    let skipped = evs.iter().filter(|e| e["action"] == "skipped").count() as u64;
    assert!(
        summary["skipped"].as_u64().unwrap() <= skipped,
        "summary.skipped exceeds the skipped events: {envelope:#}"
    );
    if summary["failed"].as_u64().unwrap() > 0 {
        assert!(
            matches!(status, "partialFailure" | "error"),
            "a failed event must not leave {status:?}: {envelope:#}"
        );
    }
    let has_error = envelope.get("error").is_some();
    assert_eq!(
        has_error,
        matches!(status, "error" | "selectionRequired"),
        "`error` iff status error/selectionRequired: {envelope:#}"
    );
    if has_error {
        assert!(envelope["error"]["code"].is_string(), "{envelope:#}");
        assert!(envelope["error"]["message"].is_string(), "{envelope:#}");
    }
    for key in envelope.as_object().unwrap().keys() {
        assert!(
            !key.contains('_'),
            "snake_case top-level key {key:?}: {envelope:#}"
        );
    }
    for e in evs {
        let action = e["action"].as_str().expect("action");
        assert!(!action.contains('_'), "snake_case action {action:?}");
        assert!(e.get("dryRun").is_none(), "nested dryRun in an event: {e}");
    }
    for w in envelope["warnings"].as_array().into_iter().flatten() {
        assert!(
            w["code"].is_string() && w["detail"].is_string() && w.as_object().unwrap().len() == 2,
            "a warning is exactly {{code, detail}}: {w}"
        );
    }
}
