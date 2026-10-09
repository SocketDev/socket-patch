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
