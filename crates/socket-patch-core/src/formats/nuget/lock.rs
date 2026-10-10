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

/// MSBuild project files NuGet restores `PackageReference`s for.
const PROJECT_EXTENSIONS: [&str; 3] = [".csproj", ".fsproj", ".vbproj"];

/// Whether `name` (a basename) is an MSBuild project file.
pub(crate) fn is_project_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    PROJECT_EXTENSIONS
        .iter()
        .any(|ext| lower.len() > ext.len() && lower.ends_with(ext))
}

/// The locks a project tree restores into, as root-relative `/` paths
/// (#353, #514). Every project under the root inherits the root
/// `nuget.config`, so the Socket source and mapping wired there reach every
/// one of them, and each lock they restore must be pinned with it:
///
/// * the root `packages.lock.json`, when present (a project file NuGet
///   restores from the root, or a lock with no project beside it);
/// * per project, the lock NuGet reads: a literal `NuGetLockFilePath`
///   (relative to the project), else `packages.<ProjectName>.lock.json`
///   beside it (spaces in the name become `_`) when that file exists, else
///   `packages.lock.json` beside it.
///
/// Only existing locks are returned. A `NuGetLockFilePath` this reader cannot
/// evaluate (an MSBuild property or item reference, a `Condition`, an
/// absolute path or one leaving the root) is returned in `unresolved` as
/// `(project, detail)`: the writers refuse rather than leave a lock they
/// cannot find on its upstream hash.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct GovernedLocks {
    pub(crate) locks: Vec<String>,
    pub(crate) unresolved: Vec<(String, String)>,
}

/// [`GovernedLocks`] of `projects` (`(root-relative project path, text)`),
/// asking `exists` whether a root-relative file exists.
pub(crate) fn governed_locks(
    projects: &[(String, String)],
    exists: impl Fn(&str) -> bool,
) -> GovernedLocks {
    let mut out = GovernedLocks::default();
    if exists(PACKAGES_LOCK) {
        out.locks.push(PACKAGES_LOCK.to_string());
    }
    for (project, text) in projects {
        let (dir, file) = match project.rsplit_once('/') {
            Some((dir, file)) => (dir, file),
            None => ("", project.as_str()),
        };
        let join = |leaf: &str| {
            if dir.is_empty() {
                leaf.to_string()
            } else {
                format!("{dir}/{leaf}")
            }
        };
        let lock = match lock_file_path_property(text) {
            Some(Err(detail)) => {
                out.unresolved.push((project.clone(), detail));
                continue;
            }
            Some(Ok(value)) => {
                match resolve_relative(dir, &value) {
                    Some(rel) => rel,
                    None => {
                        out.unresolved.push((
                        project.clone(),
                        format!("NuGetLockFilePath `{value}` is absolute or leaves the project root"),
                    ));
                        continue;
                    }
                }
            }
            None => {
                let stem = &file[..file.rfind('.').unwrap_or(file.len())];
                let named = join(&format!("packages.{}.lock.json", stem.replace(' ', "_")));
                if exists(&named) {
                    named
                } else {
                    join(PACKAGES_LOCK)
                }
            }
        };
        if exists(&lock) && !out.locks.contains(&lock) {
            out.locks.push(lock);
        }
    }
    out
}

/// The project's literal `NuGetLockFilePath`: `None` when it sets none,
/// `Some(Err)` when it sets one this reader cannot evaluate.
fn lock_file_path_property(text: &str) -> Option<Result<String, String>> {
    const OPEN: &str = "<NuGetLockFilePath";
    const CLOSE: &str = "</NuGetLockFilePath>";
    let text = strip_xml_comments(text);
    let mut value: Option<Result<String, String>> = None;
    let mut rest = text.as_str();
    while let Some(at) = rest.find(OPEN) {
        let after = &rest[at + OPEN.len()..];
        // `<NuGetLockFilePathX>` is another property.
        if !after.starts_with(['>', ' ', '\t', '\r', '\n', '/']) {
            rest = after;
            continue;
        }
        let Some(gt) = after.find('>') else {
            return Some(Err("an unterminated NuGetLockFilePath element".to_string()));
        };
        let attrs = after[..gt].trim();
        if attrs.ends_with('/') {
            // `<NuGetLockFilePath />`: an empty value, NuGet's default.
            value = None;
            rest = &after[gt + 1..];
            continue;
        }
        let Some(end) = after[gt + 1..].find(CLOSE) else {
            return Some(Err("an unterminated NuGetLockFilePath element".to_string()));
        };
        let raw = after[gt + 1..gt + 1 + end].trim();
        rest = &after[gt + 1 + end + CLOSE.len()..];
        if raw.is_empty() && attrs.is_empty() {
            value = None;
            continue;
        }
        value = Some(if !attrs.is_empty() {
            Err(format!(
                "NuGetLockFilePath `{raw}` is conditional ({attrs}); its value depends on the build"
            ))
        } else if raw.contains("$(") || raw.contains("@(") || raw.contains("%(") {
            Err(format!(
                "NuGetLockFilePath `{raw}` references MSBuild properties or items"
            ))
        } else {
            Ok(raw.to_string())
        });
    }
    value
}

fn strip_xml_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("<!--") {
        out.push_str(&rest[..at]);
        match rest[at + 4..].find("-->") {
            Some(end) => rest = &rest[at + 4 + end + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// `value` (a project-relative path, either separator) resolved against
/// the root-relative `dir`; `None` when it is absolute or leaves the root.
fn resolve_relative(dir: &str, value: &str) -> Option<String> {
    let value = value.replace('\\', "/");
    if value.starts_with('/') || value.as_bytes().get(1) == Some(&b':') {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for seg in value.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            seg => parts.push(seg),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
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

    fn exists_in(files: &'static [&'static str]) -> impl Fn(&str) -> bool {
        move |p| files.contains(&p)
    }

    #[test]
    fn member_and_named_locks_are_governed() {
        let projects = vec![
            ("src/App/App.csproj".to_string(), "<Project />".to_string()),
            (
                "src/Lib/My Lib.fsproj".to_string(),
                "<Project />".to_string(),
            ),
            ("tests/T/T.vbproj".to_string(), "<Project />".to_string()),
        ];
        let got = governed_locks(
            &projects,
            exists_in(&[
                "packages.lock.json",
                "src/App/packages.lock.json",
                "src/Lib/packages.My_Lib.lock.json",
                "src/Lib/packages.lock.json",
            ]),
        );
        assert_eq!(
            got.locks,
            [
                "packages.lock.json",
                "src/App/packages.lock.json",
                "src/Lib/packages.My_Lib.lock.json"
            ]
        );
        assert!(got.unresolved.is_empty());
    }

    #[test]
    fn lock_file_path_property_is_honored_or_refused() {
        let project = |body: &str| {
            vec![(
                "src/App/App.csproj".to_string(),
                format!("<Project><PropertyGroup>{body}</PropertyGroup></Project>"),
            )]
        };
        let got = governed_locks(
            &project("<NuGetLockFilePath>..\\locks/app.lock.json</NuGetLockFilePath>"),
            exists_in(&["src/locks/app.lock.json", "src/App/packages.lock.json"]),
        );
        assert_eq!(got.locks, ["src/locks/app.lock.json"]);
        // A commented-out property is not set.
        let got = governed_locks(
            &project("<!-- <NuGetLockFilePath>x.json</NuGetLockFilePath> -->"),
            exists_in(&["src/App/packages.lock.json"]),
        );
        assert_eq!(got.locks, ["src/App/packages.lock.json"]);
        for body in [
            "<NuGetLockFilePath>$(MSBuildProjectDirectory)/l.json</NuGetLockFilePath>",
            "<NuGetLockFilePath Condition=\"'$(CI)'=='true'\">l.json</NuGetLockFilePath>",
            "<NuGetLockFilePath>../../../outside.json</NuGetLockFilePath>",
            "<NuGetLockFilePath>/abs/l.json</NuGetLockFilePath>",
        ] {
            let got = governed_locks(&project(body), exists_in(&[]));
            assert!(got.locks.is_empty(), "{body}");
            assert_eq!(got.unresolved.len(), 1, "{body}");
        }
    }

    #[test]
    fn project_files_are_recognized_by_extension() {
        assert!(is_project_file("App.csproj"));
        assert!(is_project_file("App.FSPROJ"));
        assert!(!is_project_file(".csproj"));
        assert!(!is_project_file("App.sln"));
    }
}
