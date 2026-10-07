//! Shared serde helpers.

use serde::{Serialize, Serializer};
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
