//! The hosted planner's `composer.lock` leg: repoint a package's `dist` at
//! its Socket-hosted archive (url + `shasum`, dropping the `source` block
//! composer would otherwise prefer) as a byte splice over composer's own
//! pretty-printed JSON, so every untouched byte — key order, escapes, line
//! endings — survives. A serde round trip cannot give those offsets, which
//! is why this scanner is separate from the read model in the parent.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::crawlers::composer_crawler::normalize_version;
use crate::patch::redirect::{
    artifact_url_present, full_name, DepOverride, FileEdit, RewriteResult, RewriteWarning,
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
/// the redirect. The locked version must match the patched one through
/// composer's leading-`v` normalization (locks carry the pretty `v6.4.1`, PURLs
/// the bare `6.4.1`); matching on name alone would repoint whatever version
/// the lock happened to hold at a patch built for a different one.
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
        if normalize_version(locked) == normalize_version(version) {
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
/// entirely; redirecting such a block without inserting the pin would leave the
/// hosted artifact unverified, so composer would install whatever the URL returned.
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

/// Byte offset of the entry's `"source": {` key when that object is the
/// dist block's IMMEDIATE predecessor (only `,` + whitespace between them) —
/// the layout composer itself always writes (`source` then `dist`).
/// `None` when the entry has no source object there.
pub(crate) fn composer_source_before_dist(
    content: &str,
    entry_start: usize,
    dist_start: usize,
) -> Option<usize> {
    const SOURCE_KEY: &str = "\"source\": {";
    let source_start = entry_start + content[entry_start..dist_start].rfind(SOURCE_KEY)?;
    let source_end = json_object_end_from(content, source_start + SOURCE_KEY.len())?;
    (source_end < dist_start && content[source_end + 1..dist_start].trim() == ",")
        .then_some(source_start)
}

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
        // from the name for the next `"dist": {` would walk into the FOLLOWING
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
        let block = content[dist_start..=dist_end].to_string();
        // Already redirected (either slash spelling): recording an edit whose
        // `original` IS the hosted url would grow the ledger on every re-run
        // and poison a future revert.
        if artifact_url_present(&block, &dep.artifact_url) && block.contains(&sha1) {
            continue;
        }
        if !block.contains("\"url\": \"") {
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
        // Drop the entry's `source` (the vendored backend does the same):
        // when the dist download fails — checksum mismatch, an expired grant
        // token, a patch-server outage — composer 1 and composer 2 before its
        // source-fallback cutoff (2.2 LTS included) print "Now trying to
        // download from source" and silently install the PRISTINE upstream
        // commit from git, and `--prefer-source` / `preferred-install:
        // source` always does. With the source gone the hosted archive is
        // the only way to install the package, so a failed fetch fails the
        // install instead of shipping the vulnerable code. The edit then
        // spans `"source": {…},\n<indent>"dist": {…}`, so the ledger's
        // fragment revert puts both blocks back byte-for-byte.
        let (edit_start, original) =
            match composer_source_before_dist(&content, entry_start, dist_start) {
                Some(source_start) => (source_start, content[source_start..=dist_end].to_string()),
                None => {
                    if content[entry_start..=entry_end].contains("\"source\": {") {
                        result.warnings.push(RewriteWarning {
                            code: "redirect_composer_source_kept".into(),
                            detail: format!(
                                "{composer_name}'s source block does not directly precede its \
                                 dist and was left in place; a failed hosted download may fall \
                                 back to it"
                            ),
                        });
                    }
                    (dist_start, block.clone())
                }
            };
        if rewritten != original {
            // In place: a fresh whole-lock copy per edit would hold one
            // lock-sized buffer per redirected dep.
            content.replace_range(edit_start..=dist_end, &rewritten);
            changed = true;
            result.edits.push(FileEdit {
                path: "composer.lock".into(),
                kind: "redirect_composer_dist".into(),
                action: "rewritten".into(),
                key: Some(composer_name),
                original: Some(Value::String(original)),
                new: Some(Value::String(rewritten)),
            });
        }
    }
    if changed {
        result.files.insert("composer.lock".into(), content);
    }
}
