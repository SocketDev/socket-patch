//! Composer upstream restore: a hosted `composer.lock` entry's `dist` goes
//! back to what packagist serves for the version (`type`, `url`,
//! `reference`, `shasum`), and the `source` block the hosted rewriter
//! deleted (`redirect_composer_dist`) is re-inserted right before it — both
//! re-derived from packagist's composer v2 metadata (`p2/<name>.json`, or
//! `p2/<name>~dev.json` for a branch version), the document composer itself
//! resolved the entry from.
//!
//! The rewrite keeps `dist.reference` (the upstream commit), so it is the
//! cross-check: packagist must still serve that exact reference for the
//! version, or the lock pinned something packagist no longer describes (a
//! moved tag, another repository) and the pin is refused.
//!
//! Only packagist-sourced entries are restored: the entry must carry
//! packagist's `notification-url`, or — composer omits it for hand-trimmed
//! and some older locks — `composer.json` must declare no custom
//! `repositories`. Anything else may have come from a private repository
//! whose metadata this restore cannot read, so it is refused.
//!
//! The lock is edited as text so every other byte stays composer's: the
//! blocks are rebuilt in composer's key order at the indent the entry
//! already uses, with the file's own slash style (`\/` in locks written by
//! composer versions that escaped slashes) and line endings.
//! `content-hash` hashes composer.json, not the lock, and is untouched.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{Ctx, FormatResult, HostedPin, View};
use crate::crawlers::composer_crawler::normalize_version;
use crate::formats::composer::hosted::{
    find_composer_entry, find_composer_member, json_string_field, ComposerEntry,
};
use crate::utils::redact::url_hostname;

const COMPOSER_LOCK: &str = "composer.lock";
/// The `notification-url` composer records for packagist packages.
const PACKAGIST_NOTIFY: &str = "https://packagist.org/downloads/";

/// One hosted entry to restore.
struct Hit {
    uuid: String,
    /// Lowercase `vendor/package` (the purl name; packagist's key).
    name: String,
    /// The version as the lock spells it (`v2.0.0`, `dev-main`).
    locked_version: String,
    /// The purl version, for re-locating the entry.
    purl_version: String,
    /// The lock's surviving `dist.reference`.
    reference: Option<String>,
}

/// Whether composer resolves `version` from the `~dev` metadata file
/// (branch versions: `dev-<branch>` and `<x.y>.x-dev`).
fn is_dev_version(version: &str) -> bool {
    let lower = version.to_ascii_lowercase();
    lower.starts_with("dev-") || lower.ends_with("-dev")
}

/// The `[start, end]` byte range of the entry's `"dist": {…}` object.
fn dist_range(content: &str, entry: (usize, usize)) -> Option<(usize, usize)> {
    let member = find_composer_member(content, entry, "dist")
        .filter(|member| content.as_bytes()[member.value_start] == b'{')?;
    Some((member.key_start, member.value_end))
}

/// A JSON string literal in the lock's style: `\/` when the lock escapes
/// slashes (older composer), plain otherwise (composer 2's
/// `JSON_UNESCAPED_SLASHES`).
fn json_str(value: &str, escaped_slashes: bool) -> String {
    let lit = Value::String(value.to_string()).to_string();
    if escaped_slashes {
        lit.replace('/', "\\/")
    } else {
        lit
    }
}

/// `"<key>": {` + the string fields of `obj` named in `keys` (in that order,
/// absent ones skipped) at `inner`, closed at `outer` — composer's pretty
/// print. `None` when `obj` lacks a string `type` or `url`.
fn render_block(
    key: &str,
    obj: &serde_json::Map<String, Value>,
    keys: &[&str],
    inner: &str,
    outer: &str,
    eol: &str,
    escaped: bool,
) -> Option<String> {
    for required in ["type", "url"] {
        obj.get(required)?.as_str()?;
    }
    let fields: Vec<String> = keys
        .iter()
        .filter_map(|k| {
            let v = obj.get(*k)?.as_str()?;
            Some(format!("{inner}\"{k}\": {}", json_str(v, escaped)))
        })
        .collect();
    Some(format!(
        "\"{key}\": {{{eol}{}{eol}{outer}}}",
        fields.join(&format!(",{eol}"))
    ))
}

/// Leading whitespace of the line holding byte `at`.
fn indent_at(content: &str, at: usize) -> &str {
    let line_start = content[..at].rfind('\n').map_or(0, |i| i + 1);
    let line = &content[line_start..];
    &line[..line.len() - line.trim_start_matches([' ', '\t']).len()]
}

/// Whether `composer.json` points composer at anything but packagist.
/// `Err` when it exists but cannot be read as JSON (the refusal reason).
fn declares_custom_repositories(composer_json: Option<&str>) -> Result<bool, String> {
    let Some(text) = composer_json else {
        return Ok(false);
    };
    let doc: Value =
        serde_json::from_str(text).map_err(|e| format!("composer.json is not JSON: {e}"))?;
    Ok(match doc.get("repositories") {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(_) => true,
    })
}

/// Whether `composer.json` redeclares packagist with `options` (an
/// `http.proxy`, `ssl` settings). Composer copies a repository's options
/// into the `transport-options` of the lock entries it resolves from that
/// repository only, and this restore only restores packagist-origin
/// entries, so these are the only options a restored entry can have lost
/// (the hosted rewrite drops them; packagist's metadata cannot give them
/// back). Options on another repository belong to that repository's
/// entries, which the restore refuses.
fn packagist_declares_options(composer_json: Option<&str>) -> bool {
    let Some(doc) = composer_json.and_then(|t| serde_json::from_str::<Value>(t).ok()) else {
        return false;
    };
    let packagist_with_options = |r: &Value| {
        r.get("options").is_some_and(|o| !o.is_null())
            && r.get("url")
                .and_then(Value::as_str)
                .and_then(url_hostname)
                .is_some_and(|host| {
                    let host = host.to_ascii_lowercase();
                    host == "packagist.org" || host.ends_with(".packagist.org")
                })
    };
    match doc.get("repositories") {
        Some(Value::Array(a)) => a.iter().any(packagist_with_options),
        Some(Value::Object(o)) => o.values().any(packagist_with_options),
        _ => false,
    }
}

/// The packagist version entry that locked `locked` (exact pretty version
/// first, then composer's leading-`v` normalization).
fn pick_version<'v>(versions: &'v [Value], locked: &str) -> Result<&'v Value, String> {
    let version_of = |v: &&Value| v.get("version").and_then(Value::as_str).map(str::to_string);
    let exact: Vec<&Value> = versions
        .iter()
        .filter(|v| version_of(v).as_deref() == Some(locked))
        .collect();
    let candidates = if exact.is_empty() {
        versions
            .iter()
            .filter(|v| {
                version_of(v).is_some_and(|x| normalize_version(&x) == normalize_version(locked))
            })
            .collect()
    } else {
        exact
    };
    match candidates.as_slice() {
        [one] => Ok(one),
        [] => Err(format!("packagist does not list version {locked}")),
        _ => Err(format!("packagist lists version {locked} more than once")),
    }
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    _files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let content = match view.read(COMPOSER_LOCK).await {
        Ok(Some(text)) => text,
        Ok(None) => {
            for pin in pins {
                result.refuse(&pin.uuid, "composer.lock no longer exists");
            }
            return result;
        }
        Err(e) => {
            for pin in pins {
                result.refuse(&pin.uuid, e.clone());
            }
            return result;
        }
    };
    let composer_json = view.read("composer.json").await.ok().flatten();
    let custom_repos = declares_custom_repositories(composer_json.as_deref());
    let repo_options = packagist_declares_options(composer_json.as_deref());

    let mut hits: Vec<Hit> = Vec::new();
    for pin in pins {
        let Some((name, version)) = pin.name_version() else {
            result.refuse(&pin.uuid, format!("{} is not a composer purl", pin.purl));
            continue;
        };
        let ComposerEntry::Found(start, end) = find_composer_entry(&content, &name, &version)
        else {
            continue;
        };
        let entry = &content[start..=end];
        let Some((d_start, d_end)) = dist_range(&content, (start, end)) else {
            continue;
        };
        let dist = &content[d_start..=d_end];
        let wired = json_string_field(dist, "url")
            .and_then(|u| ctx.hosted_uuid(u))
            .is_some_and(|u| u == pin.uuid);
        if !wired {
            continue;
        }
        // Packagist gate (module docs).
        match json_string_field(entry, "notification-url").map(|u| u.replace("\\/", "/")) {
            Some(u) if u == PACKAGIST_NOTIFY => {}
            Some(u) => {
                result.refuse(
                    &pin.uuid,
                    format!("{name} was locked from {u}, not packagist, whose metadata this restore cannot read"),
                );
                continue;
            }
            None => match &custom_repos {
                Ok(false) => {}
                Ok(true) => {
                    result.refuse(
                        &pin.uuid,
                        format!(
                            "composer.json declares custom repositories and the {name} lock \
                             entry does not record packagist as its origin"
                        ),
                    );
                    continue;
                }
                Err(why) => {
                    result.refuse(&pin.uuid, why.clone());
                    continue;
                }
            },
        }
        let Some(locked_version) = json_string_field(entry, "version") else {
            continue;
        };
        hits.push(Hit {
            uuid: pin.uuid.clone(),
            name: name.to_ascii_lowercase(),
            locked_version: locked_version.to_string(),
            purl_version: version,
            reference: json_string_field(dist, "reference").map(|r| r.replace("\\/", "/")),
        });
    }
    if hits.is_empty() {
        return result;
    }

    let lookups = hits.iter().map(|h| async move {
        (
            h.uuid.clone(),
            ctx.client
                .packagist_versions(&h.name, is_dev_version(&h.locked_version))
                .await,
        )
    });
    let metadata: BTreeMap<String, Result<Vec<Value>, String>> =
        futures_util::future::join_all(lookups)
            .await
            .into_iter()
            .collect();

    let escaped = content.contains("\\/");
    let eol = crate::utils::line_endings::terminator(&content);
    let mut content = content;
    let mut changed = false;
    for hit in &hits {
        let label = format!("{}@{}", hit.name, hit.locked_version);
        let versions = match metadata.get(&hit.uuid) {
            Some(Ok(v)) => v,
            Some(Err(why)) => {
                result.refuse(&hit.uuid, format!("{label}: {why}"));
                continue;
            }
            None => continue,
        };
        let upstream = match pick_version(versions, &hit.locked_version) {
            Ok(v) => v,
            Err(why) => {
                result.refuse(&hit.uuid, format!("{label}: {why}"));
                continue;
            }
        };
        let Some(dist) = upstream.get("dist").and_then(Value::as_object) else {
            result.refuse(
                &hit.uuid,
                format!("{label}: packagist serves no dist for it"),
            );
            continue;
        };
        let upstream_ref = dist.get("reference").and_then(Value::as_str);
        if upstream_ref != hit.reference.as_deref() {
            result.refuse(
                &hit.uuid,
                format!(
                    "{label}: the lock pins dist.reference {:?} but packagist now serves {:?}",
                    hit.reference.as_deref().unwrap_or("<none>"),
                    upstream_ref.unwrap_or("<none>")
                ),
            );
            continue;
        }
        // Offsets moved with every earlier hit's edit: locate again.
        let ComposerEntry::Found(start, end) =
            find_composer_entry(&content, &hit.name, &hit.purl_version)
        else {
            continue;
        };
        let Some((d_start, d_end)) = dist_range(&content, (start, end)) else {
            continue;
        };
        let outer = indent_at(&content, d_start).to_string();
        let block = &content[d_start..=d_end];
        let inner = block
            .split('\n')
            .nth(1)
            .map(|l| &l[..l.len() - l.trim_start_matches([' ', '\t']).len()])
            .filter(|i| !i.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{outer}    "));
        let Some(dist_text) = render_block(
            "dist",
            dist,
            &["type", "url", "reference", "shasum"],
            &inner,
            &outer,
            eol,
            escaped,
        ) else {
            result.refuse(
                &hit.uuid,
                format!("{label}: packagist's dist has no type or url"),
            );
            continue;
        };
        // Re-insert the source the rewriter dropped — unless the entry
        // still carries one (a lock redirected before the drop, or a
        // source it could not remove).
        let has_source = find_composer_member(&content, (start, end), "source").is_some();
        let source_text = match upstream.get("source").and_then(Value::as_object) {
            Some(source) if !has_source => {
                match render_block(
                    "source",
                    source,
                    &["type", "url", "reference"],
                    &inner,
                    &outer,
                    eol,
                    escaped,
                ) {
                    Some(text) => format!("{text},{eol}{outer}"),
                    None => {
                        result.refuse(
                            &hit.uuid,
                            format!("{label}: packagist's source has no type or url"),
                        );
                        continue;
                    }
                }
            }
            _ => String::new(),
        };
        content.replace_range(d_start..=d_end, &format!("{source_text}{dist_text}"));
        changed = true;
        result.handled.insert(hit.uuid.clone());
        if repo_options {
            result.warnings.push((
                "upstream_composer_transport_options_not_restored",
                format!(
                    "{label}: composer.json gives packagist repository options, but the \
                     transport-options the hosted rewrite removed from this lock entry \
                     cannot be restored; re-lock {} at {} to record them again (a plain \
                     `composer update` may also move it and its dependents to newer versions)",
                    hit.name, hit.locked_version
                ),
            ));
        }
    }
    if changed {
        view.write(COMPOSER_LOCK, content);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dev_versions_use_the_dev_metadata_file() {
        assert!(is_dev_version("dev-main"));
        assert!(is_dev_version("2.x-dev"));
        assert!(is_dev_version("2.1.x-DEV"));
        assert!(!is_dev_version("v2.0.0"));
        assert!(!is_dev_version("2.0.0-beta1"));
    }

    #[test]
    fn blocks_render_in_composer_order_and_slash_style() {
        let dist = json!({
            "shasum": "",
            "url": "https://api.github.com/repos/a/b/zipball/abc",
            "type": "zip",
            "reference": "abc",
            "mirrors": [{"url": "x"}]
        });
        let obj = dist.as_object().unwrap();
        let keys = ["type", "url", "reference", "shasum"];
        assert_eq!(
            render_block(
                "dist",
                obj,
                &keys,
                "                ",
                "            ",
                "\n",
                false
            )
            .unwrap(),
            "\"dist\": {\n                \"type\": \"zip\",\n                \"url\": \
             \"https://api.github.com/repos/a/b/zipball/abc\",\n                \
             \"reference\": \"abc\",\n                \"shasum\": \"\"\n            }"
        );
        let escaped = render_block("dist", obj, &keys, "  ", "", "\r\n", true).unwrap();
        assert!(escaped.contains("\"https:\\/\\/api.github.com\\/repos\\/a\\/b\\/zipball\\/abc\""));
        assert!(escaped.contains(",\r\n  \"reference\""));
        // No shasum upstream: the key stays absent (fixture no-shasum-key).
        let bare = json!({"type": "zip", "url": "u", "reference": "r"});
        assert!(!render_block(
            "dist",
            bare.as_object().unwrap(),
            &keys,
            " ",
            "",
            "\n",
            false
        )
        .unwrap()
        .contains("shasum"));
        assert!(render_block(
            "dist",
            json!({"url": "u"}).as_object().unwrap(),
            &keys,
            "",
            "",
            "\n",
            false
        )
        .is_none());
    }

    #[test]
    fn custom_repositories_gate() {
        assert_eq!(declares_custom_repositories(None), Ok(false));
        assert_eq!(declares_custom_repositories(Some("{}")), Ok(false));
        assert_eq!(
            declares_custom_repositories(Some(r#"{"repositories": []}"#)),
            Ok(false)
        );
        assert_eq!(
            declares_custom_repositories(Some(
                r#"{"repositories": [{"type": "vcs", "url": "https://git.example/x"}]}"#
            )),
            Ok(true)
        );
        assert_eq!(
            declares_custom_repositories(Some(r#"{"repositories": {"packagist.org": false}}"#)),
            Ok(true)
        );
        assert!(declares_custom_repositories(Some("{")).is_err());
    }

    #[test]
    fn packagist_options_gate() {
        assert!(!packagist_declares_options(None));
        assert!(!packagist_declares_options(Some("{")));
        assert!(!packagist_declares_options(Some(
            r#"{"repositories": [{"type": "composer", "url": "https://repo.packagist.org"}]}"#
        )));
        assert!(packagist_declares_options(Some(
            r#"{"repositories": [{"type": "composer", "url": "https://repo.packagist.org",
                "options": {"http": {"proxy": "http://proxy:3128"}}}]}"#
        )));
        // Options on a private repository belong to its own entries, which
        // the restore refuses: no warning for packagist-origin restores.
        assert!(!packagist_declares_options(Some(
            r#"{"repositories": {"private": {"type": "composer", "url": "https://r.example",
                "options": {"http": {"header": ["X-Token: t"]}}}}}"#
        )));
        assert!(packagist_declares_options(Some(
            r#"{"repositories": [{"type": "composer", "url": "https://u:p@repo.packagist.org",
                "options": {"ssl": {"verify_peer": false}}}]}"#
        )));
        assert!(!packagist_declares_options(Some(
            r#"{"repositories": [{"type": "composer", "url": "https://packagist.org.evil.example",
                "options": {"http": {"header": ["X-Token: t"]}}}]}"#
        )));
    }

    #[test]
    fn version_pick_prefers_the_pretty_spelling() {
        let versions = vec![
            json!({"version": "2.0.0"}),
            json!({"version": "v2.0.0"}),
            json!({"version": "1.0.0"}),
        ];
        assert_eq!(
            pick_version(&versions, "v2.0.0").unwrap()["version"],
            "v2.0.0"
        );
        assert_eq!(
            pick_version(&versions, "1.0.0").unwrap()["version"],
            "1.0.0"
        );
        assert_eq!(
            pick_version(&[json!({"version": "v3.0.0"})], "3.0.0").unwrap()["version"],
            "v3.0.0"
        );
        assert!(pick_version(&versions, "9.9.9").is_err());
        let dup = vec![json!({"version": "2.0.0"}), json!({"version": "2.0.0"})];
        assert!(pick_version(&dup, "2.0.0").is_err());
    }
}
