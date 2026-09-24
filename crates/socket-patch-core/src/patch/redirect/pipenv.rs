use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use serde::Serialize;
use serde_json::{json, Value};

use super::{DepOverride, FileEdit, RewriteResult, RewriteWarning};
use crate::crawlers::python_crawler::canonicalize_pypi_name;

struct Property {
    name: String,
    range: Range<usize>,
    value: Value,
}

fn properties(text: &str, offset: usize) -> Result<Vec<Property>, String> {
    let mut index = offset + 1;
    let mut names = BTreeSet::new();
    let mut result = Vec::new();
    loop {
        while text
            .as_bytes()
            .get(index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            index += 1;
        }
        if text.as_bytes().get(index) == Some(&b'}') {
            return Ok(result);
        }
        let mut keys = serde_json::Deserializer::from_str(&text[index..]).into_iter::<String>();
        let name = keys
            .next()
            .ok_or("missing JSON key")?
            .map_err(|e| e.to_string())?;
        if !names.insert(name.clone()) {
            return Err("duplicate JSON key".into());
        }
        index += keys.byte_offset();
        while text
            .as_bytes()
            .get(index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            index += 1;
        }
        if text.as_bytes().get(index) != Some(&b':') {
            return Err("missing JSON colon".into());
        }
        index += 1;
        while text
            .as_bytes()
            .get(index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            index += 1;
        }
        let start = index;
        let mut values = serde_json::Deserializer::from_str(&text[index..]).into_iter::<Value>();
        let value = values
            .next()
            .ok_or("missing JSON value")?
            .map_err(|e| e.to_string())?;
        index += values.byte_offset();
        result.push(Property {
            name,
            range: start..index,
            value,
        });
        while text
            .as_bytes()
            .get(index)
            .is_some_and(u8::is_ascii_whitespace)
        {
            index += 1;
        }
        match text.as_bytes().get(index) {
            Some(b',') => index += 1,
            Some(b'}') => return Ok(result),
            _ => return Err("invalid JSON object".into()),
        }
    }
}

fn entries(text: &str) -> Result<Vec<(String, Property)>, String> {
    // A UTF-8 BOM (Windows editors) is not JSON; parse past it. Offsets
    // below come from `text.find('{')`, so they stay byte-accurate.
    let value =
        crate::vendor::lock_inventory::pypi::parse_pipfile_lock(text).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("Pipfile.lock is not an object".into());
    }
    if value.pointer("/_meta/pipfile-spec").and_then(Value::as_u64) != Some(6) {
        return Err("only pipfile-spec 6 supports patch file references".into());
    }
    let mut result = Vec::new();
    for section in properties(text, text.find('{').ok_or("missing root")?)? {
        if section.name == "_meta" {
            continue;
        }
        if !section.value.is_object() {
            return Err(format!("{} is not a category object", section.name));
        }
        for entry in properties(text, section.range.start)? {
            if entry.value.is_object() {
                properties(text, entry.range.start)?;
            }
            result.push((section.name.clone(), entry));
        }
    }
    Ok(result)
}

fn format_entry(value: &Value, text: &str, start: usize) -> Result<String, String> {
    let mut bytes = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    value
        .serialize(&mut serde_json::Serializer::with_formatter(
            &mut bytes, formatter,
        ))
        .map_err(|e| e.to_string())?;
    let formatted = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    let line_start = text[..start].rfind('\n').map_or(0, |i| i + 1);
    let indent: String = text[line_start..start]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect();
    let ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
    Ok(formatted.replace('\n', &format!("{ending}{indent}")))
}

/// Whether `live` is `ours` as Pipenv itself re-serializes it: the same
/// `file`/`path` reference string (it carries the uuid and the `#sha256=`
/// pin, so an identical string is positive evidence the entry is the redirect
/// we wrote) with only the fields a relock rewrites — `hashes`, `version`,
/// `index` — allowed to differ. Pipenv 2023+ relocks an entry excluded by its
/// marker by keeping our reference and restoring the registry `hashes` and
/// `version`; `--keep-outdated` re-adds `version`/`index`. Anything else that
/// changed (a marker, an extra, the reference itself) is a hand edit or a
/// foreign source: drift.
pub(super) fn reserialized_around_reference(live: &Value, ours: &Value) -> bool {
    let (Some(live), Some(ours)) = (live.as_object(), ours.as_object()) else {
        return false;
    };
    let reference = |object: &serde_json::Map<String, Value>| {
        object
            .get("file")
            .or_else(|| object.get("path"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let Some(our_reference) = reference(ours) else {
        return false;
    };
    if reference(live) != Some(our_reference) {
        return false;
    }
    const RELOCK_REWRITES: [&str; 5] = ["hashes", "version", "index", "file", "path"];
    live.keys()
        .chain(ours.keys())
        .filter(|key| !RELOCK_REWRITES.contains(&key.as_str()))
        .all(|key| live.get(key) == ours.get(key))
}

pub(super) fn restore(text: &str, edit: &FileEdit) -> Result<String, String> {
    if edit.path != "Pipfile.lock" {
        return Err("Pipenv edit must target Pipfile.lock".into());
    }
    let [section, name]: [String; 2] =
        serde_json::from_str(edit.key.as_deref().ok_or("missing Pipenv key")?)
            .map_err(|e| e.to_string())?;
    let original = edit
        .original
        .as_ref()
        .and_then(Value::as_str)
        .ok_or("missing Pipenv original")?;
    // The ledger is committed and tamper-able: only a JSON object may be
    // spliced back into the lock (never arbitrary text that would corrupt
    // it or smuggle in extra entries).
    if !serde_json::from_str::<Value>(original).is_ok_and(|value| value.is_object()) {
        return Err("Pipenv original is not a JSON object".into());
    }
    let new = edit
        .new
        .as_ref()
        .and_then(Value::as_str)
        .ok_or("missing Pipenv replacement")?;
    let Some((_, entry)) = entries(text)?
        .into_iter()
        .find(|(category, entry)| category == &section && entry.name == name)
    else {
        // A relock that DROPPED the entry (`pipenv uninstall <pkg>`, a Pipfile
        // edit + `pipenv lock`): the redirect is gone with it — nothing to
        // unwind, the edit retires.
        return Ok(text.into());
    };
    let live = &text[entry.range.clone()];
    let ending = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let original_value: Value = serde_json::from_str(original).map_err(|e| e.to_string())?;
    let new_value: Option<Value> = serde_json::from_str(new).ok();
    // Comparisons are SEMANTIC (parsed JSON), so a line-ending conversion of
    // the whole file (git autocrlf, a cross-OS checkout) or a re-serialization
    // that only moved whitespace is neither drift nor a reason to refuse.
    if live == original || entry.value == original_value {
        return Ok(text.into());
    }
    // "Still ours": Pipenv re-serialized the entry around the very reference
    // we wrote (see [`reserialized_around_reference`]).
    let same_reference = new_value
        .as_ref()
        .is_some_and(|new_value| reserialized_around_reference(&entry.value, new_value));
    if live != new && new_value.as_ref() != Some(&entry.value) && !same_reference {
        // A relock (`pipenv lock`, `pipenv update`, `pipenv install <other>`
        // on <= 2023) regenerates the entry to registry shape: the redirect
        // is already gone and the user's fresh resolution is the desired end
        // state, so the edit is retired instead of holding every pypi revert
        // hostage forever. A DIFFERENT `file`/`path` reference (a user's own
        // source, a hand edit) is real drift and still refuses.
        let registry_shaped = entry
            .value
            .as_object()
            .is_some_and(|object| !object.contains_key("file") && !object.contains_key("path"));
        if registry_shaped {
            return Ok(text.into());
        }
        return Err(format!("Pipenv entry {section}.{name} drifted"));
    }
    // Still our reference (byte-identical, re-serialized by Pipenv, or a
    // `--keep-outdated` hybrid that kept our `file`/`path`): splice the
    // recorded original back, in the live file's line ending.
    let restored = if ending == "\r\n" {
        original.replace("\r\n", "\n").replace('\n', "\r\n")
    } else {
        original.replace("\r\n", "\n")
    };
    let mut result = text.to_owned();
    result.replace_range(entry.range, &restored);
    Ok(result)
}

/// Whether any pypi override names a package this `Pipfile.lock` pins — the
/// cheap pre-check that decides whether the installer probe
/// (`pipenv --version`, up to 10 s) is worth running and whether its
/// absence is worth a warning. An absent or unparseable lock targets nothing.
pub(super) fn lock_targets(files: &BTreeMap<String, String>, overrides: &[DepOverride]) -> bool {
    let Some(text) = files.get("Pipfile.lock") else {
        return false;
    };
    let Ok(entries) = entries(text) else {
        return false;
    };
    overrides
        .iter()
        .filter(|dep| dep.ecosystem == "pypi")
        .any(|dep| {
            let wanted = canonicalize_pypi_name(&dep.name);
            entries
                .iter()
                .any(|(_, entry)| canonicalize_pypi_name(&entry.name) == wanted)
        })
}

pub(super) fn rewrite(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    pipenv_major: Option<u32>,
    result: &mut RewriteResult,
) {
    let Some(original) = files.get("Pipfile.lock") else {
        return;
    };
    let mut text = original.clone();
    for dep in overrides.iter().filter(|dep| dep.ecosystem == "pypi") {
        let planned = plan(&text, dep, pipenv_major);
        match planned {
            Ok((rewritten, edits)) => {
                result.confirmed_pipenv_uuids.insert(dep.patch_uuid.clone());
                text = rewritten;
                result.edits.extend(edits);
            }
            // A CONFLICT (another version pinned, a foreign source, a VCS /
            // path dependency) means the project's Pipenv install would not
            // pick the patch up even if a sibling requirements.txt / uv.lock
            // were repointed — so the sibling rewriters are vetoed too and
            // nothing is half-redirected. Anything else (no entry for the
            // package, an old pipfile-spec, an unparseable or BOM-prefixed
            // lock, a patch without a digest) says nothing about the files
            // the project installs from: warn and leave the siblings alone,
            // or a stale Pipfile.lock left behind in a uv / Poetry /
            // requirements project blocks every hosted redirect.
            // …but only for a LIVE lock. A Pipfile.lock with no Pipfile
            // beside it is abandoned (nothing installs from it), so even a
            // conflicting pin says nothing about the project's real install
            // files: refuse this file, leave the siblings alone.
            Err(PlanError::Conflict(detail)) if files.contains_key("Pipfile") => {
                result.refused_pipenv_uuids.insert(dep.patch_uuid.clone());
                result.warnings.push(RewriteWarning {
                    code: "redirect_pipenv_refused".into(),
                    detail,
                });
            }
            Err(PlanError::Conflict(detail)) => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pipenv_refused".into(),
                    detail: format!("{detail} (no Pipfile beside the lock: the sibling Python files are still redirected)"),
                });
            }
            Err(PlanError::Skip(detail)) => {
                result.warnings.push(RewriteWarning {
                    code: "redirect_pipenv_skipped".into(),
                    detail,
                });
            }
        }
    }
    if &text != original {
        result.files.insert("Pipfile.lock".into(), text);
    }
}

/// Whether `value` is a Socket-issued hosted reference for `dep` — served
/// from the same origin as the grant's own artifact URL (patch.socket.dev,
/// or a `--patch-server-url` host), with the `/patch/pypi/<name>/<version>/
/// <grant>/<uuid>/<wheel>` shape for this package and version. Such an entry
/// is ours to rotate; anything else is a user's or a fork's source.
fn owned_url(value: &str, dep: &DepOverride) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    let Ok(ours) = reqwest::Url::parse(&dep.artifact_url) else {
        return false;
    };
    let same_origin = url.scheme() == ours.scheme()
        && url.host_str() == ours.host_str()
        && url.port_or_known_default() == ours.port_or_known_default();
    let parts: Vec<_> = url.path().split('/').collect();
    (same_origin
        || (url.scheme() == "https" && url.host_str() == Some(super::SOCKET_PATCH_SERVER_HOST)))
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && parts.len() == 8
        && parts[1] == "patch"
        && parts[2] == "pypi"
        && canonicalize_pypi_name(parts[3]) == canonicalize_pypi_name(&dep.name)
        && parts[4] == dep.version
        && !parts[5].is_empty()
        && !parts[6].is_empty()
        && parts[7].ends_with(".whl")
        && parts[7]
            .split('-')
            .next()
            .is_some_and(|name| canonicalize_pypi_name(name) == canonicalize_pypi_name(&dep.name))
        && parts[7].split('-').nth(1) == Some(dep.version.as_str())
}

/// Why a Pipfile.lock plan did not happen. Only a [`PlanError::Conflict`]
/// vetoes the sibling Python rewriters (see [`rewrite`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PlanError {
    /// The lock pins another version or a non-registry / foreign source for
    /// the package: the project's install cannot pick the patch up.
    Conflict(String),
    /// Nothing to do here (no entry, unsupported spec, unparseable lock,
    /// no digest): says nothing about the project's other install files.
    Skip(String),
}

impl From<String> for PlanError {
    fn from(detail: String) -> Self {
        PlanError::Skip(detail)
    }
}

impl From<&str> for PlanError {
    fn from(detail: &str) -> Self {
        PlanError::Skip(detail.to_owned())
    }
}

fn plan(
    text: &str,
    dep: &DepOverride,
    pipenv_major: Option<u32>,
) -> Result<(String, Vec<FileEdit>), PlanError> {
    let sha = dep
        .integrity
        .sha256
        .as_deref()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("Pipenv patch requires a SHA-256 digest")?;
    let url = format!(
        "{}#sha256={sha}",
        dep.artifact_url
            .split('#')
            .next()
            .ok_or("missing artifact URL")?
    );
    let targets: Vec<_> = entries(text)?
        .into_iter()
        .filter(|(_, entry)| {
            canonicalize_pypi_name(&entry.name) == canonicalize_pypi_name(&dep.name)
        })
        .collect();
    if targets.is_empty() {
        return Err(PlanError::Skip(format!(
            "Pipfile.lock has no entry for {}",
            dep.name
        )));
    }
    let source_key = if pipenv_major.is_some_and(|major| (7..2018).contains(&major)) {
        "path"
    } else {
        "file"
    };
    let mut changes = Vec::new();
    for (section, entry) in targets {
        let object = entry
            .value
            .as_object()
            .ok_or("Pipenv dependency is not an object")?;
        if ["git", "hg", "svn", "bzr", "editable"]
            .iter()
            .any(|key| object.contains_key(*key))
            || (object.contains_key("file") && object.contains_key("path"))
        {
            return Err(PlanError::Conflict(format!(
                "Pipenv source for {} is not a registry package",
                dep.name
            )));
        }
        if let Some(file) = object.get("file").or_else(|| object.get("path")) {
            if !file.as_str().is_some_and(|value| owned_url(value, dep)) {
                return Err(PlanError::Conflict(format!(
                    "Pipenv source for {} already exists",
                    dep.name
                )));
            }
            // Ours. A `version` Pipenv re-added next to it (`pipenv lock
            // --keep-outdated`, `install --keep-outdated <pkg>` on 2022
            // write a file+version+index hybrid that still installs) must
            // still name the patched release; then the entry is simply
            // re-planned to the canonical shape.
            if let Some(pinned) = object.get("version").and_then(Value::as_str) {
                if pinned != format!("=={}", dep.version) {
                    return Err(PlanError::Conflict(format!(
                        "Pipenv version for {} does not match {}",
                        dep.name, dep.version
                    )));
                }
            }
            if object.get(source_key).and_then(Value::as_str) == Some(&url)
                && object.get("hashes") == Some(&json!([format!("sha256:{sha}")]))
                && !object.contains_key("version")
                && !object.contains_key("index")
            {
                continue;
            }
        } else if object.get("version").and_then(Value::as_str)
            != Some(format!("=={}", dep.version).as_str())
        {
            return Err(PlanError::Conflict(format!(
                "Pipenv version for {} does not match {}",
                dep.name, dep.version
            )));
        }
        let mut new = object.clone();
        new.remove("version");
        new.remove("index");
        new.remove("file");
        new.remove("path");
        new.insert(source_key.into(), Value::String(url.clone()));
        new.insert("hashes".into(), json!([format!("sha256:{sha}")]));
        let mut new = Value::Object(new);
        new.sort_all_objects();
        let replacement = format_entry(&new, text, entry.range.start)?;
        let edit = FileEdit {
            path: "Pipfile.lock".into(),
            kind: "redirect_pipenv_entry".into(),
            action: "rewritten".into(),
            key: Some(json!([section, entry.name]).to_string()),
            original: Some(Value::String(text[entry.range.clone()].into())),
            new: Some(Value::String(replacement.clone())),
        };
        changes.push((entry.range, replacement, edit));
    }
    let mut rewritten = text.to_owned();
    let mut edits = Vec::new();
    for (range, replacement, edit) in changes.into_iter().rev() {
        rewritten.replace_range(range, &replacement);
        edits.push(edit);
    }
    Ok((rewritten, edits))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn dependency(name: &str, version: &str, uuid: &str) -> DepOverride {
        serde_json::from_value(json!({
            "ecosystem":"pypi", "name":name, "version":version,
            "patchUuid":uuid,"token":"token",
            "artifactUrl":format!("https://patch.socket.dev/patch/pypi/{name}/{version}/token/{uuid}/{name}-{version}-py3-none-any.whl"),
            "integrity":{"sha256":"a".repeat(64)}
        })).unwrap()
    }

    pub(super) fn lock() -> String {
        let mut value = json!({"_meta":{"pipfile-spec":6,"hash":{"sha256":"unchanged"}},"default":{"urllib3":{"version":"==1.26.18","index":"pypi","hashes":["old"],"extras":["socks"],"markers":"python_version < '4'"}},"develop":{},"tests":{"urllib3":{"version":"==1.26.18"}}});
        value.sort_all_objects();
        format_entry(&value, "{", 0).unwrap() + "\n"
    }

    #[test]
    fn all_categories_preserve_extras_markers_metadata_and_repeat_bytes() {
        for ending in ["\n", "\r\n"] {
            let original = lock().replace('\n', ending);
            let dep = dependency("URLLib3", "1.26.18", "patch-one");
            let (text, edits) = plan(&original, &dep, None).unwrap();
            assert_eq!(edits.len(), 2);
            let value: Value = serde_json::from_str(&text).unwrap();
            let before: Value = serde_json::from_str(&original).unwrap();
            assert_eq!(value["_meta"], before["_meta"]);
            for field in ["extras", "markers"] {
                assert_eq!(
                    value["default"]["urllib3"][field],
                    before["default"]["urllib3"][field]
                );
            }
            assert_eq!(plan(&text, &dep, None).unwrap(), (text.clone(), Vec::new()));
            let mut restored = text;
            for edit in edits.iter().rev() {
                restored = restore(&restored, edit).unwrap();
            }
            assert_eq!(restored, original);
        }
    }

    #[test]
    fn refusal_is_atomic_across_categories() {
        let dep = dependency("urllib3", "1.26.18", "patch-one");
        for bad in [
            json!({"version":"==2.0"}),
            json!({"version":"*"}),
            json!({"file":"https://example.org/fork.whl"}),
            json!({"version":"==1.26.18","git":"https://example.org/fork"}),
            json!({"version":"==1.26.18","editable":false}),
            json!(null),
            json!({"version":"==1.26.18","path":"./fork"}),
        ] {
            let mut value: Value = serde_json::from_str(&lock()).unwrap();
            let is_null = bad.is_null();
            value["tests"]["urllib3"] = bad;
            let original = serde_json::to_string(&value).unwrap();
            // A live lock (Pipfile beside it): conflicts veto the siblings.
            let files = BTreeMap::from([
                ("Pipfile".to_string(), "[packages]\nurllib3 = \"*\"\n".to_string()),
                ("Pipfile.lock".to_string(), original),
            ]);
            let mut result = RewriteResult::default();
            rewrite(&files, std::slice::from_ref(&dep), None, &mut result);
            assert!(result.files.is_empty());
            assert!(result.edits.is_empty());
            assert!(result.confirmed_pipenv_uuids.is_empty());
            assert_eq!(result.warnings.len(), 1);
            // A pin / source CONFLICT vetoes the sibling Python rewriters; a
            // malformed (non-object) entry is merely skipped.
            if is_null {
                assert_eq!(result.warnings[0].code, "redirect_pipenv_skipped");
                assert!(result.refused_pipenv_uuids.is_empty());
            } else {
                assert_eq!(result.warnings[0].code, "redirect_pipenv_refused");
                assert!(result.refused_pipenv_uuids.contains("patch-one"));
            }
        }
    }

    /// Only conflicts veto the sibling rewriters (Bugbot HIGH on #242): a
    /// Pipfile.lock without the package, an old pipfile-spec, an unparseable
    /// lock or a digest-less patch is SKIPPED with `redirect_pipenv_skipped`
    /// and the requirements.txt / uv.lock rewrite still lands.
    #[test]
    fn non_conflict_refusals_do_not_veto_sibling_rewriters() {
        let dep = dependency("urllib3", "1.26.18", "patch-one");
        let stale_locks = [
            // no entry for the package at all
            lock().replace("\"urllib3\"", "\"other-package\""),
            // pipfile-spec 5
            lock().replace("\"pipfile-spec\": 6", "\"pipfile-spec\": 5"),
            // unparseable
            "{".to_owned(),
            // BOM-prefixed but otherwise fine is NOT a skip: it must plan.
        ];
        for stale in &stale_locks {
            let files = BTreeMap::from([
                ("Pipfile.lock".to_string(), stale.clone()),
                ("requirements.txt".to_string(), "urllib3==1.26.18\n".to_string()),
            ]);
            let result = super::super::rewrite_registry_redirect(&files, std::slice::from_ref(&dep));
            assert!(
                !result.refused_pipenv_uuids.contains("patch-one"),
                "a non-conflict must not veto: {stale}"
            );
            assert!(
                result.warnings.iter().any(|w| w.code == "redirect_pipenv_skipped"),
                "{:?}",
                result.warnings
            );
            assert!(
                result.files.get("requirements.txt").is_some_and(|t| t.contains("patch.socket.dev")),
                "requirements.txt must still be redirected past a stale Pipfile.lock: {result:?}"
            );
            assert!(!result.files.contains_key("Pipfile.lock"));
        }
        // A digest-less patch is a skip too (the other rewriters decide for
        // themselves whether they need one).
        let mut no_digest = dep.clone();
        no_digest.integrity.sha256 = None;
        let mut result = RewriteResult::default();
        rewrite(
            &BTreeMap::from([("Pipfile.lock".to_string(), lock())]),
            std::slice::from_ref(&no_digest),
            None,
            &mut result,
        );
        assert!(result.refused_pipenv_uuids.is_empty());
        assert_eq!(result.warnings[0].code, "redirect_pipenv_skipped");
    }

    #[test]
    fn bom_prefixed_lock_is_rewritten_and_restored_with_the_bom_intact() {
        let dep = dependency("urllib3", "1.26.18", "patch-one");
        let original = format!("\u{feff}{}", lock());
        let (text, edits) = plan(&original, &dep, None).unwrap();
        assert!(text.starts_with('\u{feff}'), "the BOM is preserved");
        assert!(text.contains("patch.socket.dev"));
        let mut restored = text;
        for edit in edits.iter().rev() {
            restored = restore(&restored, edit).unwrap();
        }
        assert_eq!(restored, original);
    }

    #[test]
    fn malformed_duplicate_and_unsupported_locks_refuse() {
        let dep = dependency("urllib3", "1.26.18", "patch-one");
        for text in [
            "null".to_owned(),
            "[]".into(),
            "{".into(),
            lock().replace("\"pipfile-spec\": 6", "\"pipfile-spec\": 5"),
            lock().replace("\"default\": {", "\"default\": {}, \"default\": {"),
            lock().replace(
                "\"version\": \"==1.26.18\"",
                "\"version\": \"==2.0\", \"version\": \"==1.26.18\"",
            ),
        ] {
            assert!(plan(&text, &dep, None).is_err(), "{text}");
        }
        let mut missing_hash = dep.clone();
        missing_hash.integrity.sha256 = None;
        assert!(plan(&lock(), &missing_hash, None).is_err());
    }

    /// `pipenv lock` (and `update`, and `install <other>` before 2024)
    /// regenerates the redirected entry to registry shape. That is the
    /// desired end state of a rollback, so the edit retires cleanly instead
    /// of refusing forever; a foreign `file`/`path` reference is still drift.
    /// A re-scan after the relock (second edit on the same key) unwinds
    /// newest-first to the relocked text.
    #[test]
    fn relocked_registry_entry_retires_the_edit_instead_of_refusing() {
        let dep = dependency("urllib3", "1.26.18", "patch-one");
        // One category, so the relock below regenerates the ONLY redirect.
        let mut value: Value = serde_json::from_str(&lock()).unwrap();
        value.as_object_mut().unwrap().remove("tests");
        let original = format_entry(&value, "{", 0).unwrap() + "\n";
        let (redirected, edits) = plan(&original, &dep, None).unwrap();
        assert_eq!(edits.len(), 1);
        let redirected_entry = edits[0].new.as_ref().unwrap().as_str().unwrap();
        let relocked_entry = format_entry(
            &json!({"hashes": ["sha256:relocked"], "index": "pypi", "version": "==1.26.18"}),
            &redirected,
            redirected.find(redirected_entry).unwrap(),
        )
        .unwrap();
        let relocked = redirected.replacen(redirected_entry, &relocked_entry, 1);
        assert_eq!(
            restore(&relocked, &edits[0]).unwrap(),
            relocked,
            "a registry-shaped entry is already unwound"
        );
        let foreign = redirected.replacen(
            redirected_entry,
            &format_entry(&json!({"file": "https://example.org/fork.whl"}), &redirected, 0).unwrap(),
            1,
        );
        assert!(restore(&foreign, &edits[0]).is_err(), "a foreign reference is drift");

        // Re-scan after the relock, then roll back newest-first.
        let (again, second) = plan(&relocked, &dep, None).unwrap();
        let mut current = again;
        for edit in second.iter().chain(edits.iter()) {
            current = restore(&current, edit).unwrap();
        }
        assert_eq!(current, relocked);
    }

    #[test]
    fn lock_targets_requires_a_matching_pin_in_a_parseable_lock() {
        let dep = dependency("URLlib3", "1.26.18", "patch-one");
        let other = dependency("six", "1.16.0", "patch-two");
        let files = |text: &str| BTreeMap::from([("Pipfile.lock".to_string(), text.to_string())]);
        assert!(lock_targets(&files(&lock()), std::slice::from_ref(&dep)));
        assert!(!lock_targets(&files(&lock()), std::slice::from_ref(&other)));
        assert!(!lock_targets(&files("{ not json"), std::slice::from_ref(&dep)));
        assert!(!lock_targets(&BTreeMap::new(), std::slice::from_ref(&dep)));
        let mut npm = dep.clone();
        npm.ecosystem = "npm".into();
        assert!(!lock_targets(&files(&lock()), std::slice::from_ref(&npm)));
    }

    /// `pipenv lock --keep-outdated` (2022) rewrites our entry into a
    /// file+version+index hybrid that Pipenv still installs from: it is
    /// ours, so it is re-planned to the canonical shape instead of being
    /// refused as a foreign source (which also vetoed the sibling rewriters);
    /// a hybrid naming ANOTHER version is a real conflict.
    #[test]
    fn owned_hybrid_entries_are_replanned_not_refused() {
        let dep = dependency("urllib3", "1.26.18", "patch-one");
        let (redirected, _) = plan(&lock(), &dep, None).unwrap();
        let mut value: Value = serde_json::from_str(&redirected).unwrap();
        value["default"]["urllib3"]["version"] = json!("==1.26.18");
        value["default"]["urllib3"]["index"] = json!("pypi");
        let hybrid = serde_json::to_string_pretty(&value).unwrap();
        let (fixed, edits) = plan(&hybrid, &dep, None).unwrap();
        assert!(!edits.is_empty(), "the hybrid is re-planned");
        let entry: Value = serde_json::from_str(&fixed).unwrap();
        assert!(entry["default"]["urllib3"].get("version").is_none());
        assert!(entry["default"]["urllib3"].get("index").is_none());
        assert!(entry["default"]["urllib3"]["file"].as_str().unwrap().contains("patch-one"));

        value["default"]["urllib3"]["version"] = json!("==2.0.0");
        let conflicting = serde_json::to_string(&value).unwrap();
        assert!(matches!(
            plan(&conflicting, &dep, None),
            Err(PlanError::Conflict(detail)) if detail.contains("does not match")
        ));
    }

    /// The Socket origin comes from the grant's own artifact URL, so a
    /// `--patch-server-url` deployment recognizes its previous references
    /// (rotation, idempotency) exactly like patch.socket.dev; a fork on
    /// another host is never ours.
    #[test]
    fn owned_url_follows_the_grant_origin() {
        let mut dep = dependency("urllib3", "1.26.18", "patch-one");
        let public = "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/tok/patch-one/urllib3-1.26.18-py3-none-any.whl";
        assert!(owned_url(public, &dep));
        assert!(!owned_url("https://example.org/patch/pypi/urllib3/1.26.18/tok/patch-one/urllib3-1.26.18-py3-none-any.whl", &dep));
        dep.artifact_url = "https://patches.internal.example:8443/patch/pypi/urllib3/1.26.18/tok/patch-one/urllib3-1.26.18-py3-none-any.whl".into();
        assert!(owned_url(&dep.artifact_url, &dep), "the grant's own origin is ours");
        assert!(owned_url(public, &dep), "and so is the public service");
        assert!(!owned_url("https://patches.internal.example:8443/patch/pypi/urllib3/1.26.19/tok/patch-one/urllib3-1.26.19-py3-none-any.whl", &dep), "another version is not");
        // Rotation on the custom origin restores through the chain.
        let original = lock();
        let (first, edits) = plan(&original, &dep, None).unwrap();
        dep.artifact_url = dep.artifact_url.replace("/tok/", "/rotated/");
        let (second, rotation) = plan(&first, &dep, None).unwrap();
        let mut restored = second;
        for edit in rotation.iter().chain(edits.iter()) {
            restored = restore(&restored, edit).unwrap();
        }
        assert_eq!(restored, original);
    }

    #[test]
    fn restore_refuses_a_non_object_ledger_original() {
        let dep = dependency("urllib3", "1.26.18", "patch-one");
        let (text, edits) = plan(&lock(), &dep, None).unwrap();
        for bad in ["\"just a string\"", "[1, 2]", "not json at all", "{\"a\": 1}, \"injected\": {}"] {
            let mut edit = edits[0].clone();
            edit.original = Some(Value::String(bad.to_string()));
            assert!(restore(&text, &edit).is_err(), "{bad}");
        }
    }

    #[test]
    fn rollback_is_per_entry_preserves_unrelated_edits_and_refuses_drift() {
        let mut value: Value = serde_json::from_str(&lock()).unwrap();
        value["default"]["six"] = json!({"version":"==1.16.0"});
        let original = serde_json::to_string_pretty(&value).unwrap();
        let first = dependency("urllib3", "1.26.18", "patch-one");
        let second = dependency("six", "1.16.0", "patch-two");
        let (one, first_edits) = plan(&original, &first, None).unwrap();
        let (two, second_edits) = plan(&one, &second, None).unwrap();
        for first_removed in [true, false] {
            let mut current = two.replace("unchanged", "unrelated-edit");
            let edits = if first_removed {
                first_edits
                    .iter()
                    .chain(second_edits.iter())
                    .collect::<Vec<_>>()
            } else {
                second_edits.iter().chain(first_edits.iter()).collect()
            };
            for edit in edits {
                current = restore(&current, edit).unwrap();
            }
            assert_eq!(current, original.replace("unchanged", "unrelated-edit"));
        }
        for edit in &first_edits {
            let replacement = edit.new.as_ref().unwrap().as_str().unwrap();
            // A tampered reference (its `#sha256=` pin) is drift…
            let drift = two.replacen(replacement, &replacement.replace("#sha256=", "#sha256=0"), 1);
            assert!(restore(&drift, edit).is_err());
            // …while a re-serialized entry that kept our reference (Pipenv
            // 2023+ relocking a marker-excluded entry restores the registry
            // `hashes` and `version` next to it) is still ours and restores.
            let mut value: Value = serde_json::from_str(&two).unwrap();
            let section: &str = serde_json::from_str::<[String; 2]>(edit.key.as_deref().unwrap()).unwrap()[0].clone().leak();
            value[section]["urllib3"]["hashes"] = json!(["sha256:upstream-a", "sha256:upstream-b"]);
            value[section]["urllib3"]["version"] = json!("==1.26.18");
            let kept = serde_json::to_string_pretty(&value).unwrap();
            let restored: Value = serde_json::from_str(&restore(&kept, edit).unwrap()).unwrap();
            assert!(restored[section]["urllib3"].get("file").is_none(), "{restored}");
            let mut unsafe_edit = edit.clone();
            unsafe_edit.path = "../Pipfile.lock".into();
            assert!(restore(&two, &unsafe_edit).is_err());
        }
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    #[test]
    fn rotates_owned_grants_and_preserves_rollback_chain() {
        let mut dep = super::tests::dependency("urllib3", "1.26.18", "patch-one");
        for major in [Some(7), Some(11), Some(2018), Some(2026), None] {
            let original = super::tests::lock();
            let (first, edits) = plan(&original, &dep, major).unwrap();
            let parsed: Value = serde_json::from_str(&first).unwrap();
            let field = if major.is_some_and(|value| value < 2018) {
                "path"
            } else {
                "file"
            };
            assert!(parsed["default"]["urllib3"][field].is_string());
            dep.artifact_url = dep.artifact_url.replace("/token/", "/rotated/");
            let (second, rotation) = plan(&first, &dep, major).unwrap();
            let mut restored = second;
            for edit in rotation.iter().chain(edits.iter()) {
                restored = restore(&restored, edit).unwrap();
            }
            assert_eq!(restored, original);
            dep.artifact_url = dep.artifact_url.replace("/rotated/", "/token/");
        }
    }

    #[test]
    fn conflicting_pipenv_pin_cannot_partially_redirect_requirements() {
        let dep = super::tests::dependency("urllib3", "1.26.18", "patch-one");
        let files = BTreeMap::from([
            ("Pipfile".into(), "[packages]\nurllib3 = \"==2.0\"\n".into()),
            (
                "Pipfile.lock".into(),
                super::tests::lock().replace("==1.26.18", "==2.0"),
            ),
            ("requirements.txt".into(), "urllib3==1.26.18\n".into()),
        ]);
        let result = super::super::rewrite_registry_redirect(&files, std::slice::from_ref(&dep));
        assert!(result.files.is_empty());
        assert!(result.edits.is_empty());
        assert!(result.refused_pipenv_uuids.contains("patch-one"));

        // The same conflicting lock with NO Pipfile beside it is abandoned:
        // the requirements pin is what installs, so it is redirected.
        let mut abandoned = files.clone();
        abandoned.remove("Pipfile");
        let result = super::super::rewrite_registry_redirect(&abandoned, &[dep]);
        assert!(!result.refused_pipenv_uuids.contains("patch-one"));
        assert!(result.files["requirements.txt"].contains("patch.socket.dev"));
        assert!(!result.files.contains_key("Pipfile.lock"));
        assert!(result.warnings.iter().any(|w| w.code == "redirect_pipenv_refused" && w.detail.contains("no Pipfile")));
    }

    /// Rollback survives what git and Pipenv do to the lock between the
    /// redirect and the revert: a whole-file CRLF<->LF conversion, Pipenv
    /// re-serializing our entry (a `--keep-outdated` hybrid that kept our
    /// reference), and a relock that dropped the entry altogether.
    #[test]
    fn rollback_tolerates_line_ending_conversion_hybrids_and_dropped_entries() {
        let dep = super::tests::dependency("urllib3", "1.26.18", "patch-one");
        let original = super::tests::lock();
        let (redirected, edits) = plan(&original, &dep, None).unwrap();
        // CRLF conversion of the redirected file → restores the original in CRLF.
        let crlf = redirected.replace('\n', "\r\n");
        let mut restored = crlf;
        for edit in edits.iter().rev() {
            restored = restore(&restored, edit).unwrap();
        }
        assert_eq!(restored, original.replace('\n', "\r\n"));
        // LF file, CRLF-recorded edits (the redirect ran on a CRLF checkout).
        let crlf_original = original.replace('\n', "\r\n");
        let (crlf_redirected, crlf_edits) = plan(&crlf_original, &dep, None).unwrap();
        let mut restored = crlf_redirected.replace("\r\n", "\n");
        for edit in crlf_edits.iter().rev() {
            restored = restore(&restored, edit).unwrap();
        }
        assert_eq!(restored, original);
        // Hybrid: Pipenv re-added version/index next to our reference.
        let mut value: Value = serde_json::from_str(&redirected).unwrap();
        value["default"]["urllib3"]["version"] = json!("==1.26.18");
        value["default"]["urllib3"]["index"] = json!("pypi");
        let hybrid = serde_json::to_string_pretty(&value).unwrap();
        let default_edit = edits.iter().find(|e| e.key.as_deref() == Some(r#"["default","urllib3"]"#)).unwrap();
        let restored = restore(&hybrid, default_edit).unwrap();
        let value: Value = serde_json::from_str(&restored).unwrap();
        assert_eq!(value["default"]["urllib3"]["version"], json!("==1.26.18"));
        assert!(value["default"]["urllib3"].get("file").is_none(), "{restored}");
        // Dropped entry (`pipenv uninstall`): nothing to unwind, retires.
        let mut value: Value = serde_json::from_str(&redirected).unwrap();
        value["default"].as_object_mut().unwrap().remove("urllib3");
        let dropped = serde_json::to_string_pretty(&value).unwrap();
        assert_eq!(restore(&dropped, default_edit).unwrap(), dropped);
        // A foreign reference is still drift.
        let mut value: Value = serde_json::from_str(&redirected).unwrap();
        value["default"]["urllib3"]["file"] = json!("https://example.org/fork.whl");
        let foreign = serde_json::to_string_pretty(&value).unwrap();
        assert!(restore(&foreign, default_edit).is_err());
    }
}
