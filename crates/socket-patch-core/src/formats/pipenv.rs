//! `Pipfile.lock` (pipfile-spec 6) as text: the byte span of every
//! package entry, and the one way an entry is re-rendered in Pipenv's own
//! layout. Hosted rewrites, upstream restore and the vendored backend all
//! splice entries through this module, so every other byte of the lock is
//! left exactly as Pipenv (or the user) wrote it.

use std::collections::BTreeSet;
use std::ops::Range;

use serde::Serialize;
use serde_json::Value;

/// One `"name": value` member of a JSON object in the lock text.
pub(crate) struct Property {
    pub(crate) name: String,
    /// Where the member's quoted key starts.
    pub(crate) key_start: usize,
    /// The byte span of the member's value.
    pub(crate) range: Range<usize>,
    pub(crate) value: Value,
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
        let key_start = index;
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
            key_start,
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

pub(crate) fn entries(text: &str) -> Result<Vec<(String, Property)>, String> {
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

/// Render `value` as Pipenv writes it at byte `start` of `text`: 4-space
/// indent continued from the line it sits on, the lock's line ending, and
/// non-ASCII as `\uXXXX` escapes (Pipenv's `json.dumps` keeps the default
/// `ensure_ascii`) unless the lock already spells some character raw
/// (a leading BOM does not count).
pub(crate) fn format_entry(value: &Value, text: &str, start: usize) -> Result<String, String> {
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
    // A BOM is the editor's, not Pipenv's spelling of a character.
    let formatted = if super::text::strip_bom(text).is_ascii() {
        super::json::escape_non_ascii(&formatted)
    } else {
        formatted
    };
    let ending = crate::utils::line_endings::terminator(text);
    Ok(formatted.replace('\n', &format!("{ending}{indent}")))
}

/// Replace (`Some`) or remove (`None`) the entry `name` of category
/// `section`, leaving every other byte of the lock as it was. A removed
/// entry takes its separating comma with it; removing a category's only
/// entry leaves `{}`, as Pipenv writes an empty category. `_meta` is not a
/// package category and is never edited. The caller
/// renders `value` in the key order it wants (Pipenv sorts every object).
pub(crate) fn splice_entry(
    text: &str,
    section: &str,
    name: &str,
    value: Option<&Value>,
) -> Result<String, String> {
    let categories = properties(text, text.find('{').ok_or("missing root")?)?;
    let category = categories
        .iter()
        .find(|category| category.name == section && section != "_meta")
        .filter(|category| category.value.is_object())
        .ok_or_else(|| format!("no {section} category object"))?;
    let members = properties(text, category.range.start)?;
    let index = members
        .iter()
        .position(|member| member.name == name)
        .ok_or_else(|| format!("no {section} entry {name}"))?;
    let member = &members[index];
    let mut out = text.to_owned();
    match value {
        Some(value) => {
            let rendered = format_entry(value, text, member.range.start)?;
            out.replace_range(member.range.clone(), &rendered);
        }
        None => {
            let span = if let Some(next) = members.get(index + 1) {
                member.key_start..next.key_start
            } else if let Some(previous) = index.checked_sub(1).map(|i| &members[i]) {
                previous.range.end..member.range.end
            } else {
                category.range.start + 1..category.range.end - 1
            };
            out.replace_range(span, "");
        }
    }
    Ok(out)
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
pub(crate) fn reserialized_around_reference(live: &Value, ours: &Value) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// #815: a re-rendered entry takes the lock's majority line ending.
    #[test]
    fn formatted_entry_takes_the_majority_line_ending() {
        let value = json!({"a": 1, "b": 2});
        let lf_majority = "{\r\n    \"x\": {\n    }\n}\n";
        assert_eq!(
            format_entry(&value, lf_majority, 0).unwrap(),
            "{\n    \"a\": 1,\n    \"b\": 2\n}"
        );
        let crlf_majority = "{\r\n    \"x\": {\r\n    }\n}\r\n";
        assert_eq!(
            format_entry(&value, crlf_majority, 0).unwrap(),
            "{\r\n    \"a\": 1,\r\n    \"b\": 2\r\n}"
        );
    }

    fn lock(develop: &str) -> String {
        format!(
            "{{\n    \"_meta\": {{\n        \"pipfile-spec\": 6\n    }},\n    \"develop\": {develop}\n}}\n"
        )
    }

    /// The one splicer replaces an entry in place and removes one with its
    /// separator, wherever it sits, leaving `{}` for an emptied category.
    #[test]
    fn splice_entry_replaces_and_removes_at_every_position() {
        let three = lock("{\n        \"a\": {},\n        \"b\": {},\n        \"c\": {}\n    }");
        let removed = |name| splice_entry(&three, "develop", name, None).unwrap();
        assert_eq!(
            removed("a"),
            lock("{\n        \"b\": {},\n        \"c\": {}\n    }")
        );
        assert_eq!(
            removed("b"),
            lock("{\n        \"a\": {},\n        \"c\": {}\n    }")
        );
        assert_eq!(
            removed("c"),
            lock("{\n        \"a\": {},\n        \"b\": {}\n    }")
        );
        let one = lock("{\n        \"a\": {}\n    }");
        assert_eq!(
            splice_entry(&one, "develop", "a", None).unwrap(),
            lock("{}")
        );

        let replaced = splice_entry(&three, "develop", "b", Some(&json!({"version": "==1"})));
        assert_eq!(
            replaced.unwrap(),
            lock("{\n        \"a\": {},\n        \"b\": {\n            \"version\": \"==1\"\n        },\n        \"c\": {}\n    }")
        );
        assert!(splice_entry(&three, "develop", "z", None).is_err());
        assert!(splice_entry(&three, "default", "a", None).is_err());
        assert!(splice_entry(&three, "_meta", "pipfile-spec", None).is_err());
    }

    /// Pipenv's `json.dumps` escapes non-ASCII; a lock that already spells a
    /// character raw was written by something else and keeps raw text.
    #[test]
    fn formatted_entry_follows_the_lock_s_unicode_spelling() {
        let value = json!({"path": "./caf\u{e9}"});
        assert_eq!(
            format_entry(&value, "{}", 0).unwrap(),
            "{\n    \"path\": \"./caf\\u00e9\"\n}"
        );
        assert_eq!(
            format_entry(&value, "{\"x\": \"\u{e9}\"}", 0).unwrap(),
            "{\n    \"path\": \"./caf\u{e9}\"\n}"
        );
        assert_eq!(
            format_entry(&value, "\u{feff}{}", 0).unwrap(),
            "{\n    \"path\": \"./caf\\u00e9\"\n}",
            "a BOM alone does not make the lock raw-Unicode"
        );
    }
}
