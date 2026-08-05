//! Shared serde helpers.

use serde::de::{self, Deserializer, Unexpected};
use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};

/// Serialize a `HashMap` with its keys in sorted order so the emitted JSON
/// is deterministic across runs. Used by every git-committed ledger the
/// tool writes (`.socket/manifest.json`, `.socket/vendor/state.json`):
/// `HashMap`'s randomized iteration order would otherwise re-shuffle the
/// keys on every write, producing spurious diffs and merge conflicts. This
/// mirrors the `BTreeMap` choice in `vex::schema`, made for the same
/// "easier diffing across runs" reason. The public field type stays
/// `HashMap` (so callers and deserialization are unaffected); only the
/// on-the-wire ordering is pinned.
pub fn serialize_sorted<S, V>(map: &HashMap<String, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    map.iter().collect::<BTreeMap<_, _>>().serialize(serializer)
}

/// `skip_serializing_if` companion for `bool` fields that default to false —
/// keeps them out of the emitted JSON entirely rather than writing
/// `"merged": false` on every record.
pub fn is_false(b: &bool) -> bool {
    !*b
}

/// Deserialize a marker flag whose on-the-wire *type* is not pinned.
///
/// The patch API's upstream-merge marker is expected to arrive as a plain
/// `true`/`false`, but the same signal is equally likely to ship as a
/// nullable timestamp (`"mergedAt": "Fri, 27 Mar 2026 …"`). Typing the
/// field as `bool` alone would make a string payload a hard deserialize
/// error, which would take down the *entire* patch-list response — a
/// server-side field-type choice must never be able to break the client
/// that way.
///
/// So: `true` / a non-empty string / a non-zero number all mean "set";
/// `false` / `null` / an empty string / `0` / an absent key all mean
/// "unset". Anything structurally unexpected (an array, an object) is a
/// genuine contract violation and still errors.
pub fn de_truthy_flag<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        None | Some(serde_json::Value::Null) => Ok(false),
        Some(serde_json::Value::Bool(b)) => Ok(b),
        Some(serde_json::Value::String(s)) => Ok(!s.is_empty()),
        Some(serde_json::Value::Number(n)) => Ok(n.as_f64().map(|f| f != 0.0).unwrap_or(true)),
        Some(other) => Err(de::Error::invalid_type(
            match &other {
                serde_json::Value::Array(_) => Unexpected::Seq,
                _ => Unexpected::Map,
            },
            &"a boolean, string, number, or null",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    struct Holder {
        #[serde(default, deserialize_with = "de_truthy_flag")]
        merged: bool,
    }

    fn parse(json: &str) -> bool {
        serde_json::from_str::<Holder>(json)
            .expect("deserialize")
            .merged
    }

    #[test]
    fn absent_key_is_false() {
        // The state of the world today: no server emits this field yet.
        assert!(!parse("{}"));
    }

    #[test]
    fn booleans_pass_through() {
        assert!(parse(r#"{"merged":true}"#));
        assert!(!parse(r#"{"merged":false}"#));
    }

    #[test]
    fn null_is_false() {
        assert!(!parse(r#"{"merged":null}"#));
    }

    #[test]
    fn timestamp_string_is_truthy() {
        // The `mergedAt`-shaped payload: a string means "merged at that
        // time", an empty string means nothing.
        assert!(parse(r#"{"merged":"Fri, 27 Mar 2026 19:12:42 GMT"}"#));
        assert!(parse(r#"{"merged":"2026-03-27T19:12:42Z"}"#));
        assert!(!parse(r#"{"merged":""}"#));
    }

    #[test]
    fn numbers_follow_zero_is_false() {
        assert!(parse(r#"{"merged":1}"#));
        assert!(parse(r#"{"merged":1743102762}"#));
        assert!(!parse(r#"{"merged":0}"#));
    }

    #[test]
    fn structural_mismatches_still_error() {
        // A tolerant type coercion must not become "accept anything" —
        // an array or object here means the contract genuinely drifted.
        assert!(serde_json::from_str::<Holder>(r#"{"merged":[]}"#).is_err());
        assert!(serde_json::from_str::<Holder>(r#"{"merged":{}}"#).is_err());
    }

    #[test]
    fn is_false_gates_serialization() {
        assert!(is_false(&false));
        assert!(!is_false(&true));
    }
}
