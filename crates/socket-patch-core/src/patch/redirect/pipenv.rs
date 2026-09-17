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
    let value: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
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
    let new = edit
        .new
        .as_ref()
        .and_then(Value::as_str)
        .ok_or("missing Pipenv replacement")?;
    let (_, entry) = entries(text)?
        .into_iter()
        .find(|(category, entry)| category == &section && entry.name == name)
        .ok_or("Pipenv entry missing")?;
    let live = &text[entry.range.clone()];
    if live == original {
        return Ok(text.into());
    }
    if live != new {
        return Err(format!("Pipenv entry {section}.{name} drifted"));
    }
    let mut result = text.to_owned();
    result.replace_range(entry.range, original);
    Ok(result)
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
            Err(detail) => {
                result.refused_pipenv_uuids.insert(dep.patch_uuid.clone());
                result.warnings.push(RewriteWarning {
                    code: "redirect_pipenv_refused".into(),
                    detail,
                });
            }
        }
    }
    if &text != original {
        result.files.insert("Pipfile.lock".into(), text);
    }
}

fn owned_url(value: &str, dep: &DepOverride) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    let parts: Vec<_> = url.path().split('/').collect();
    url.scheme() == "https"
        && url.host_str() == Some("patch.socket.dev")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
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

fn plan(
    text: &str,
    dep: &DepOverride,
    pipenv_major: Option<u32>,
) -> Result<(String, Vec<FileEdit>), String> {
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
        return Err(format!("Pipfile.lock has no entry for {}", dep.name));
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
            return Err(format!(
                "Pipenv source for {} is not a registry package",
                dep.name
            ));
        }
        if let Some(file) = object.get("file").or_else(|| object.get("path")) {
            if !file.as_str().is_some_and(|value| owned_url(value, dep))
                || object.contains_key("version")
                || object.contains_key("index")
            {
                return Err(format!("Pipenv source for {} already exists", dep.name));
            }
            if object.get(source_key).and_then(Value::as_str) == Some(&url)
                && object.get("hashes") == Some(&json!([format!("sha256:{sha}")]))
            {
                continue;
            }
        } else if object.get("version").and_then(Value::as_str)
            != Some(format!("=={}", dep.version).as_str())
        {
            return Err(format!(
                "Pipenv version for {} does not match {}",
                dep.name, dep.version
            ));
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
            value["tests"]["urllib3"] = bad;
            let original = serde_json::to_string(&value).unwrap();
            let files = BTreeMap::from([("Pipfile.lock".into(), original)]);
            let mut result = RewriteResult::default();
            rewrite(&files, std::slice::from_ref(&dep), None, &mut result);
            assert!(result.files.is_empty());
            assert!(result.edits.is_empty());
            assert!(result.confirmed_pipenv_uuids.is_empty());
            assert_eq!(result.warnings.len(), 1);
        }
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
            let drift = two.replacen(
                replacement,
                &replacement.replace("sha256:", &format!("sha256:{}", "0")),
                1,
            );
            assert!(restore(&drift, edit).is_err());
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
            (
                "Pipfile.lock".into(),
                super::tests::lock().replace("==1.26.18", "==2.0"),
            ),
            ("requirements.txt".into(), "urllib3==1.26.18\n".into()),
        ]);
        let result = super::super::rewrite_registry_redirect(&files, &[dep]);
        assert!(result.files.is_empty());
        assert!(result.edits.is_empty());
        assert!(result.refused_pipenv_uuids.contains("patch-one"));
    }
}
