//! `packages.lock.json`: the one reader every NuGet lock walker shares —
//! the vendored pin, the hosted redirect, the hosted upstream restore and
//! VEX discovery.
//!
//! A lock is `{"dependencies": {"<tfm>": {"<Id>": {"resolved": …,
//! "contentHash": …}}}}`. NuGet matches ids case-insensitively, and one
//! multi-targeting project can resolve the same id at a different version
//! per framework, so a walker that pins a patched `<Id> <version>` must
//! match the id AND the version: an entry at another version is a
//! different package that the patched bytes must never replace (#593).
//!
//! dotnet restores a lock that starts with a UTF-8 BOM (one saved by a
//! Windows editor or Windows PowerShell 5.1), so the parse reads past it
//! (#623). Writers keep it: the vendored and upstream-restore edits are
//! string surgery on the hash value, and the hosted rewrite re-renders in
//! the original layout.

use serde_json::{Map, Value};

use crate::vendor::nuget_feed::normalize_nuget_version;

/// The lock NuGet writes beside a project under its default name.
pub(crate) const PACKAGES_LOCK: &str = "packages.lock.json";

/// One `dependencies.<tfm>.<id>` entry that restores from a source: its raw
/// id key, `resolved` and `contentHash` strings.
#[derive(Debug, Clone, Copy)]
pub(crate) struct NugetLockEntry<'a> {
    pub(crate) id: &'a str,
    pub(crate) resolved: &'a str,
    pub(crate) content_hash: Option<&'a str>,
}

/// Parse a lock's text as dotnet does, reading past a leading UTF-8 BOM.
pub(crate) fn parse_lock(text: &str) -> serde_json::Result<Value> {
    serde_json::from_str(crate::formats::text::strip_bom(text))
}

/// Every entry of a parsed lock, target framework by target framework, in
/// document-key order. Frameworks that are not objects and entries without
/// a string `resolved` (`type: "Project"` references, which nothing
/// restores from a source) are skipped; strings are raw (callers trim /
/// normalize / compare ids as they need).
pub(crate) fn nuget_lock_entries(doc: &Value) -> impl Iterator<Item = NugetLockEntry<'_>> {
    doc.get("dependencies")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|frameworks| frameworks.values())
        .filter_map(Value::as_object)
        .flatten()
        .filter_map(|(id, entry)| {
            Some(NugetLockEntry {
                id,
                resolved: entry.get("resolved").and_then(Value::as_str)?,
                content_hash: entry.get("contentHash").and_then(Value::as_str),
            })
        })
}

/// The entries of package `id` (case-insensitive) whose `resolved`
/// normalizes to `version_norm` ([`normalize_nuget_version`]): the entries
/// a patch of `id version_norm` replaces.
pub(crate) fn locked_at<'a>(
    doc: &'a Value,
    id: &'a str,
    version_norm: &'a str,
) -> impl Iterator<Item = NugetLockEntry<'a>> {
    nuget_lock_entries(doc).filter(move |e| {
        e.id.eq_ignore_ascii_case(id) && normalize_nuget_version(e.resolved) == version_norm
    })
}

/// [`locked_at`] for editing: `(id key, entry object)` of every matching
/// entry, framework by framework.
pub(crate) fn locked_at_mut<'a>(
    doc: &'a mut Value,
    id: &'a str,
    version_norm: &'a str,
) -> Vec<(&'a str, &'a mut Map<String, Value>)> {
    doc.get_mut("dependencies")
        .and_then(Value::as_object_mut)
        .into_iter()
        .flat_map(|frameworks| frameworks.values_mut())
        .filter_map(Value::as_object_mut)
        .flat_map(|fw| fw.iter_mut())
        .filter(|(key, _)| key.eq_ignore_ascii_case(id))
        .filter_map(|(key, entry)| Some((key.as_str(), entry.as_object_mut()?)))
        .filter(|(_, entry)| {
            entry
                .get("resolved")
                .and_then(Value::as_str)
                .is_some_and(|r| normalize_nuget_version(r) == version_norm)
        })
        .collect()
}

/// The other versions the lock resolves `id` at, normalized, sorted and
/// deduplicated. Both writers route the WHOLE id to a feed that serves only
/// the patched version (`packageSourceMapping` patterns name ids, never
/// versions), so a framework that resolves the id at another version could
/// no longer restore it: the writers refuse such a lock rather than break
/// that framework or re-pin it to the patched version.
pub(crate) fn other_versions(doc: &Value, id: &str, version_norm: &str) -> Vec<String> {
    let mut out: Vec<String> = nuget_lock_entries(doc)
        .filter(|e| e.id.eq_ignore_ascii_case(id))
        .map(|e| normalize_nuget_version(e.resolved))
        .filter(|v| v != version_norm)
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The refusal detail both writers give for [`other_versions`].
pub(crate) fn other_versions_detail(
    lock_rel: &str,
    id: &str,
    version_norm: &str,
    others: &[String],
) -> String {
    format!(
        "{lock_rel} also resolves {id} at {}; the patch for {version_norm} would route every \
         version of {id} to a feed that serves only {version_norm}, so those target frameworks \
         could not restore. Align {id} on {version_norm} in every target framework (or patch \
         each version), restore, and re-run",
        others.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTI: &str = r#"{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": { "type": "Direct", "requested": "[12.0.3, )", "resolved": "12.0.3", "contentHash": "OLD12==" }
    },
    "net8.0": {
      "newtonsoft.json": { "type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3", "contentHash": "OLD13==" },
      "App.Lib": { "type": "Project" }
    }
  }
}"#;

    #[test]
    fn bom_lock_parses_like_dotnet_reads_it() {
        let bom = format!("\u{feff}{MULTI}");
        assert!(serde_json::from_str::<Value>(&bom).is_err());
        assert_eq!(parse_lock(&bom).unwrap(), parse_lock(MULTI).unwrap());
    }

    #[test]
    fn locked_at_matches_id_and_version() {
        let doc = parse_lock(MULTI).unwrap();
        let hits: Vec<_> = locked_at(&doc, "Newtonsoft.Json", "13.0.3").collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].content_hash, Some("OLD13=="));
        let mut doc = doc;
        let hits = locked_at_mut(&mut doc, "NEWTONSOFT.JSON", "13.0.3");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, "newtonsoft.json");
    }

    #[test]
    fn other_versions_names_every_other_resolution() {
        let doc = parse_lock(MULTI).unwrap();
        assert_eq!(
            other_versions(&doc, "newtonsoft.json", "13.0.3"),
            ["12.0.3"]
        );
        assert!(other_versions(&doc, "newtonsoft.json", "12.0.3") == ["13.0.3"]);
        assert!(other_versions(&doc, "App.Lib", "1.0.0").is_empty());
        // A spelling of the same version is not another version.
        let doc = parse_lock(&MULTI.replace("\"12.0.3\"", "\"13.0.3.0\"")).unwrap();
        assert!(other_versions(&doc, "Newtonsoft.Json", "13.0.3").is_empty());
    }
}
