//! The hosted planner's `composer.lock` leg: repoint a package's `dist` at
//! its Socket-hosted archive (url + `shasum`, dropping the `source` block
//! composer would otherwise prefer) as a byte splice over composer's own
//! pretty-printed JSON, so every untouched byte — key order, escapes, line
//! endings — survives. A serde round trip cannot give those offsets, which
//! is why this scanner is separate from the read model in the parent.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;

use crate::utils::composer_version::composer_versions_equivalent;
use super::source as composer_source;
use crate::patch::redirect::{
    artifact_url_present, full_name, DepOverride, RewriteResult, RewriteWarning,
};

/// Byte offset of the `}` closing the JSON object that CONTAINS `from`, which
/// must be a position inside that object. Brace counting skips string literals,
/// so a brace inside a description or URL cannot move the boundary.
///
/// Walks bytes, not chars: every byte it acts on is ASCII, and no byte of a
/// multi-byte UTF-8 sequence is, so the offsets are the char walk's (an
/// escaped multi-byte char clears `escaped` on its lead byte).
pub(crate) fn json_object_end_from(text: &str, from: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, &byte) in text.as_bytes()[from..].iter().enumerate() {
        if in_string {
            match byte {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' if depth == 0 => return Some(from + offset),
            b'}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Value of the first `"<key>": "<value>"` pair in `text` (composer writes its
/// lock with exactly one space after the colon, the same shape the surgical
/// `dist` regexes below assume).
pub(crate) fn json_string_field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let pattern = format!("\"{key}\": \"");
    let start = text.find(&pattern)? + pattern.len();
    let end = text[start..].find('"')? + start;
    Some(&text[start..end])
}

/// Outcome of locating a package entry in a composer.lock.
pub(crate) enum ComposerEntry {
    /// Inclusive byte range from the entry's `"name"` key to the `}` closing
    /// the entry — composer writes `name` first, so this covers every key the
    /// rewriter edits.
    Found(usize, usize),
    /// The name matched but the lock pins this OTHER version.
    VersionMismatch(String),
    NotFound,
}

/// Locate `pkg`'s entry in a composer.lock (either `packages[]` or
/// `packages-dev[]` — the scan is over the whole file).
///
/// Names match CASE-INSENSITIVELY, the way the composer crawler and the vendor
/// backend already match them: packagist canonicalizes to lowercase, but
/// hand-written mixed-case locks install fine and would otherwise silently miss
/// the redirect. The locked version must match the patched one by composer
/// release identity (locks carry the pretty `v6.4.1`, PURLs the bare `6.4.1`
/// or padded `6.4.1.0`); matching on name alone repointed whatever version the
/// lock happened to hold at a patch built for a different one.
pub(crate) fn find_composer_entry(content: &str, pkg: &str, version: &str) -> ComposerEntry {
    let mut mismatched: Option<String> = None;
    for (name_idx, _) in content.match_indices("\"name\": \"") {
        // The name is the value at `name_idx` — the entry's first field —
        // and its closing quote precedes any `}` the object walk can stop
        // at, so test it before walking to the end of the object: most
        // occurrences name some other package.
        if !json_string_field(&content[name_idx..], "name")
            .is_some_and(|n| n.eq_ignore_ascii_case(pkg))
        {
            continue;
        }
        let Some(end) = json_object_end_from(content, name_idx) else {
            continue;
        };
        let entry = &content[name_idx..=end];
        // Every package entry carries `version`; an `authors[]`/`support`
        // object that happens to have a matching `name` does not.
        let Some(locked) = json_string_field(entry, "version") else {
            continue;
        };
        if composer_versions_equivalent(locked, version) {
            return ComposerEntry::Found(name_idx, end);
        }
        mismatched = Some(locked.to_string());
    }
    match mismatched {
        Some(locked) => ComposerEntry::VersionMismatch(locked),
        None => ComposerEntry::NotFound,
    }
}

/// Append `"shasum": "<sha1>"` as the last key of a `"dist": { … }` block,
/// indented like the keys already in it. VCS/zipball dists omit `shasum`
/// entirely; redirecting such a block without inserting the pin left the hosted
/// artifact unverified, so composer would install whatever the URL returned.
/// `block` is the whole dist object and already holds at least a `url`.
pub(crate) fn append_composer_shasum(block: &str, sha1: &str) -> String {
    let Some(close) = block.rfind('}') else {
        return block.to_string();
    };
    let head = block[..close].trim_end();
    let indent: String = head[head.rfind('\n').map_or(0, |i| i + 1)..]
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    format!(
        "{head},\n{indent}\"shasum\": \"{sha1}\"{}",
        &block[head.len()..]
    )
}

pub(crate) static COMPOSER_DIST_TYPE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"("type": ")[^"]*(")"#).expect("static dist type regex is valid")
});
pub(crate) static COMPOSER_DIST_URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"("url": ")[^"]*(")"#).expect("static dist url regex is valid"));
pub(crate) static COMPOSER_DIST_SHASUM_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"("shasum": ")[^"]*(")"#).expect("static dist shasum regex is valid")
});

pub(crate) fn rewrite_composer_lock(
    files: &BTreeMap<String, String>,
    overrides: &[DepOverride],
    result: &mut RewriteResult,
) {
    let composer: Vec<&DepOverride> = overrides
        .iter()
        .filter(|o| o.ecosystem == "composer")
        .collect();
    if composer.is_empty() {
        return;
    }
    // Parity with `redirect_npm_no_lockfile`: a granted dep the project has
    // no lock to pin must be SAID, not silently dropped from the redirected
    // count (a composer.json + installed vendor tree without a lock is
    // discovered and granted like any other).
    if !files.contains_key("composer.lock") {
        result.warnings.push(RewriteWarning {
            code: "redirect_composer_no_lockfile".into(),
            detail: "no composer.lock present; composer redirect skipped".into(),
        });
        return;
    }
    const DIST_KEY: &str = "\"dist\": {";
    let mut content = files["composer.lock"].clone();
    let type_re: &Regex = &COMPOSER_DIST_TYPE_RE;
    let url_re: &Regex = &COMPOSER_DIST_URL_RE;
    let shasum_re: &Regex = &COMPOSER_DIST_SHASUM_RE;
    let mut changed = false;
    for dep in &composer {
        let composer_name = full_name(dep);
        let Some(sha1) = dep.integrity.sha1.clone() else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_missing_sha1".into(),
                detail: format!("{composer_name} has no sha1 (dist.shasum) integrity"),
            });
            continue;
        };
        let (entry_start, entry_end) =
            match find_composer_entry(&content, &composer_name, &dep.version) {
                ComposerEntry::Found(start, end) => (start, end),
                ComposerEntry::VersionMismatch(locked) => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_composer_version_mismatch".into(),
                        detail: format!(
                            "composer.lock pins {composer_name}@{locked}, not the patched {}",
                            dep.version
                        ),
                    });
                    continue;
                }
                ComposerEntry::NotFound => {
                    result.warnings.push(RewriteWarning {
                        code: "redirect_composer_pkg_not_found".into(),
                        detail: format!(
                            "no composer.lock package named {composer_name}@{}",
                            dep.version
                        ),
                    });
                    continue;
                }
            };
        // The dist block MUST belong to the located entry. Scanning forward
        // from the name for the next `"dist": {` walked into the FOLLOWING
        // package whenever the target was installed from source, repointing a
        // bystander's url + shasum — a checksum-clean install of the wrong
        // code. A target with no dist of its own pins nothing: fail closed.
        let Some(dist_start) = content[entry_start..=entry_end]
            .find(DIST_KEY)
            .map(|offset| entry_start + offset)
        else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_no_dist".into(),
                detail: format!("{composer_name} has no dist block"),
            });
            continue;
        };
        let Some(dist_end) = json_object_end_from(&content, dist_start + DIST_KEY.len()) else {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_lock_malformed".into(),
                detail: format!("{composer_name}'s dist block is unterminated"),
            });
            continue;
        };
        // The dist's own members only: a `mirrors` entry listed before the
        // dist `url` would otherwise take the redirected url and then be
        // dropped with the mirrors, leaving the upstream url pinned to the
        // patched sha1.
        let current = &content[dist_start..=dist_end];
        let block =
            composer_source::strip_dist_mirrors(current).unwrap_or_else(|| current.to_string());
        // Already redirected (either slash spelling): only the source/mirrors
        // heal applies, so a re-run over a healed lock records no edit and
        // the ledger never grows.
        let already_redirected =
            artifact_url_present(&block, &dep.artifact_url) && block.contains(&sha1);
        if !already_redirected && !block.contains("\"url\": \"") {
            result.warnings.push(RewriteWarning {
                code: "redirect_composer_no_dist_url".into(),
                detail: format!("{composer_name}'s dist block has no url to redirect"),
            });
            continue;
        }
        let mut rewritten = type_re.replace(&block, "${1}zip${2}").to_string();
        rewritten = url_re
            .replace(
                &rewritten,
                format!("${{1}}{}${{2}}", dep.artifact_url).as_str(),
            )
            .to_string();
        rewritten = if rewritten.contains("\"shasum\": \"") {
            shasum_re
                .replace(&rewritten, format!("${{1}}{sha1}${{2}}").as_str())
                .to_string()
        } else {
            append_composer_shasum(&rewritten, &sha1)
        };
        let rewritten = (!already_redirected).then_some(rewritten);
        // Drops the entry's `source` wherever it sits and the dist's
        // `mirrors` (see `composer_source`); the edit spans both, so the
        // ledger's fragment revert restores them byte-for-byte.
        let span = composer_source::DistSpan {
            entry_start,
            entry_end,
            dist_start,
            dist_end,
        };
        if let Some(edit) = composer_source::apply_dist_edit(
            &mut content,
            span,
            rewritten.as_deref(),
            &composer_name,
            &mut result.warnings,
        ) {
            changed = true;
            result.edits.push(edit);
        }
    }
    if changed {
        result.files.insert("composer.lock".into(), content);
    }
}
