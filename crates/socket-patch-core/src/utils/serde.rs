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

/// Strip a leading UTF-8 BOM. npm and Node tolerate (and strip) a BOM in
/// package.json, and cargo accepts one in Cargo.toml — files saved by Windows
/// editors commonly carry one — but serde_json (and vex's TOML line scanner)
/// reject it, so every parse of user-supplied manifest content must go through
/// this first or toolchain-valid manifests error out.
pub(crate) fn strip_bom(content: &str) -> &str {
    content.strip_prefix('\u{feff}').unwrap_or(content)
}
