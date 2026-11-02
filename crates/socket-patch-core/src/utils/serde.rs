//! Shared serde helpers.

use serde::{Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};

/// Serialize a `HashMap` with its keys sorted, so a git-committed ledger
/// does not re-shuffle (and conflict) on every write.
pub fn serialize_sorted<S, V>(map: &HashMap<String, V>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    map.iter().collect::<BTreeMap<_, _>>().serialize(serializer)
}
