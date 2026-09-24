use toml_edit::{value, Array, DocumentMut, InlineTable, Item, Table, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::preserve_line_endings;

pub fn lock_version(lock: &DocumentMut) -> Result<&str, String> {
    let version = lock
        .get("metadata")
        .and_then(|metadata| metadata.get("lock_version"))
        .and_then(Item::as_str)
        .ok_or("missing PDM lock_version")?;
    if matches!(version, "2" | "4.3" | "4.4" | "4.4.1" | "4.5.0" | "4.5.1") {
        Ok(version)
    } else {
        Err(format!("unsupported PDM lock_version {version:?}"))
    }
}

pub fn validate_strategy(lock: &DocumentMut) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    let Some(metadata) = lock.get("metadata") else {
        return Ok(result);
    };
    if let Some(strategy) = metadata.get("strategy") {
        // lock_version >= 4.4: the strategy is an array of flag strings.
        for item in strategy.as_array().ok_or("invalid PDM strategy")? {
            let value = item.as_str().ok_or("invalid PDM strategy flag")?;
            if !matches!(
                value,
                "inherit_metadata" | "static_urls" | "cross_platform" | "direct_minimal_versions"
            ) {
                return Err(format!("unsupported PDM lock strategy {value:?}"));
            }
            result.push(value.to_string());
        }
    } else {
        // lock_version 4.3 (PDM 2.8-2.9) spells the strategy as `[metadata]`
        // booleans instead of an array. Mirror PDM's own normalization so the
        // flag set is recorded (and gated) identically to the array spelling.
        for flag in ["cross_platform", "static_urls"] {
            if let Some(item) = metadata.get(flag) {
                if item.as_bool().ok_or("invalid PDM strategy flag")? {
                    result.push(flag.to_string());
                }
            }
        }
    }
    // A lock_version >= 4.4.1 without `inherit_metadata` (what `pdm lock
    // --strategy no_inherit_metadata` writes) stores no per-package group or
    // candidate metadata, so PDM ~2.12-2.23 re-resolves the lock at sync time
    // and cannot match a package we rewrote to a `url`/`path` source
    // (CandidateNotFound). Refuse rather than emit a lock that installs only on
    // the exact PDM that wrote it. lock_version "4.4"/"4.3"/"2" predate the
    // requirement (their default locks omit it) and stay allowed.
    if matches!(lock_version(lock), Ok("4.4.1" | "4.5.0" | "4.5.1"))
        && !result.iter().any(|flag| flag == "inherit_metadata")
    {
        return Err("PDM lock strategy lacks inherit_metadata; re-lock without \
                    `--strategy no_inherit_metadata`"
            .into());
    }
    Ok(result)
}

/// Mirror PDM's `safe_name(name).lower()`, which derives the legacy
/// `[metadata.files]` keys (lock_version "2", PDM 0.12-1.5). `safe_name`
/// collapses runs of characters outside `[A-Za-z0-9.]` to a single `-` but
/// PRESERVES dots — unlike PEP 503 canonicalization, which folds `.` into `-`.
/// So a dotted-name package such as `zope.interface` is keyed
/// `"zope.interface <version>"`, not `"zope-interface <version>"`.
fn pdm_files_key_name(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    let mut in_separator_run = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' {
            in_separator_run = false;
            result.push(ch.to_ascii_lowercase());
        } else if !in_separator_run {
            result.push('-');
            in_separator_run = true;
        }
    }
    result
}

pub fn legacy_files_key(package: &Table) -> Option<String> {
    let name = pdm_files_key_name(package.get("name")?.as_str()?);
    let version = package.get("version")?.as_str()?;
    let mut extras: Vec<&str> = package
        .get("extras")
        .and_then(Item::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    extras.sort();
    let suffix = if extras.is_empty() {
        String::new()
    } else {
        format!("[{}]", extras.join(","))
    };
    Some(format!("{name}{suffix} {version}"))
}

pub fn files_for<'a>(lock: &'a DocumentMut, package: &'a Table) -> Option<&'a Array> {
    package.get("files").and_then(Item::as_array).or_else(|| {
        lock.get("metadata")?
            .get("files")?
            .get(&legacy_files_key(package)?)?
            .as_array()
    })
}

pub fn wheel_matches(filename: &str, name: &str, version: &str) -> bool {
    let parts: Vec<_> = filename.split('-').collect();
    filename.ends_with(".whl")
        && !filename.contains(['/', '\\'])
        && matches!(parts.len(), 5 | 6)
        && canonicalize_pypi_name(parts[0]) == canonicalize_pypi_name(name)
        && parts[1] == version
}

/// Whether `existing` is an earlier hosted redirect of the SAME artifact:
/// same origin (`scheme://host[:port]`) and same trailing wheel filename as the
/// current artifact URL, fragments ignored. Grant tokens and patch uuids live
/// in the path between them, so a rotated token or a superseded patch (new
/// uuid) takes over the stale pin in place instead of being refused as a
/// foreign source (the poetry / bun rewriters make the same call).
fn is_prior_hosted_url(existing: &str, current: &str) -> bool {
    fn origin_and_leaf(url: &str) -> Option<(&str, &str)> {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return None;
        }
        let url = url.split('#').next()?;
        let scheme_end = url.find("://")? + 3;
        let path_start = url[scheme_end..].find('/')? + scheme_end;
        let leaf = url[path_start..]
            .rsplit('/')
            .next()
            .filter(|leaf| !leaf.is_empty())?;
        Some((&url[..path_start], leaf))
    }
    match (origin_and_leaf(existing), origin_and_leaf(current)) {
        (Some(old), Some(new)) => old == new,
        _ => false,
    }
}

pub fn rewrite_pdm_lock(
    text: &str,
    name: &str,
    version: &str,
    source: (&str, &str),
    filename: &str,
    sha256: &str,
) -> Result<String, String> {
    Ok(rewrite_pdm_lock_with_edits(text, name, version, source, filename, sha256)?.text)
}

/// A successful [`rewrite_pdm_lock_with_edits`].
pub struct PdmLockRewrite<'a> {
    /// The rewritten lock text.
    pub text: String,
    original: &'a str,
    name: &'a str,
    /// The original's fragments, already taken to build `text`.
    before: Vec<String>,
    /// The fragment edits, when `text` is byte-identical to the rendered
    /// document they were derived against (the common case: toml_edit
    /// round-trips the untouched bytes) — then they are also the edits
    /// against `text`.
    known_edits: Option<Vec<(String, String)>>,
}

impl PdmLockRewrite<'_> {
    /// Exactly `pdm_lock_edits(original, &self.text, name)`, without
    /// re-deriving what the rewrite already did.
    pub fn edits(&self) -> Result<Vec<(String, String)>, String> {
        if let Some(edits) = &self.known_edits {
            return Ok(edits.clone());
        }
        let after = pdm_lock_fragments(&self.text, self.name)?;
        pair_pdm_lock_fragments(self.original, &self.before, &self.text, after)
    }
}

/// [`rewrite_pdm_lock`], also handing back what the caller needs to record
/// the rewrite's fragment edits ([`PdmLockRewrite::edits`]).
pub fn rewrite_pdm_lock_with_edits<'a>(
    text: &'a str,
    name: &'a str,
    version: &str,
    source: (&str, &str),
    filename: &str,
    sha256: &str,
) -> Result<PdmLockRewrite<'a>, String> {
    let (kind, location) = source;
    if !matches!(kind, "url" | "path")
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid PDM artifact source or SHA-256".into());
    }
    if !wheel_matches(filename, name, version) {
        return Err("PDM patch wheel does not match package".into());
    }
    let mut lock: DocumentMut = text.parse().map_err(|e| format!("invalid PDM lock: {e}"))?;
    lock_version(&lock)?;
    validate_strategy(&lock)?;
    let packages = lock
        .get("package")
        .and_then(Item::as_array_of_tables)
        .ok_or("missing PDM packages")?;
    let indices: Vec<_> = packages
        .iter()
        .enumerate()
        .filter(|(_, package)| {
            package
                .get("name")
                .and_then(Item::as_str)
                .is_some_and(|candidate| {
                    canonicalize_pypi_name(candidate) == canonicalize_pypi_name(name)
                })
        })
        .map(|(index, _)| index)
        .collect();
    if indices.is_empty() {
        return Err("missing PDM package".into());
    }
    // A marker/multi-target lock (PDM >= 2.17 `pdm lock --append`) can carry the
    // same package at several versions, one per resolution fork. A single
    // surgical rewrite would patch one fork and leave the others pinned to the
    // registry, so refuse the whole lock ahead of the per-unit version check —
    // the target version IS present, so the plain "version differs" below would
    // misdirect the user to re-lock.
    let locked_versions: std::collections::BTreeSet<&str> = indices
        .iter()
        .filter_map(|&index| packages.get(index)?.get("version").and_then(Item::as_str))
        .collect();
    if locked_versions.len() > 1 {
        return Err("PDM lock resolves this package at multiple versions (a marker or \
                    multi-target fork); patching one fork would leave the others unpatched"
            .into());
    }
    let mut variants = std::collections::BTreeSet::new();
    let mut edits = Vec::new();
    for index in indices {
        let package = packages.get(index).ok_or("missing PDM package")?;
        if package.get("version").and_then(Item::as_str) != Some(version) {
            return Err("PDM locked version differs from installed version".into());
        }
        let mut extras = Vec::new();
        if let Some(value) = package.get("extras") {
            for extra in value.as_array().ok_or("invalid PDM extras")? {
                extras.push(extra.as_str().ok_or("invalid PDM extra")?.to_string());
            }
        }
        extras.sort();
        if !variants.insert(extras) {
            return Err("forked PDM package".into());
        }
        for field in [
            "url", "path", "git", "hg", "svn", "bzr", "editable", "source",
        ] {
            if let Some(existing) = package.get(field) {
                let same_target = field == kind && existing.as_str() == Some(location);
                // A prior socket-hosted `url` (rotated grant token or a
                // superseded patch uuid — same origin and wheel leaf) is taken
                // over in place; foreign urls and every other source refuse.
                let prior_hosted = field == kind
                    && kind == "url"
                    && existing
                        .as_str()
                        .is_some_and(|existing| is_prior_hosted_url(existing, location));
                if !same_target && !prior_hosted {
                    return Err(format!("refusing existing PDM {field} source"));
                }
            }
        }
        let original_files = files_for(&lock, package).ok_or("missing PDM file hashes")?;
        if original_files.is_empty()
            || original_files.iter().any(|file| {
                !file
                    .as_inline_table()
                    .and_then(|file| file.get("hash"))
                    .and_then(Value::as_str)
                    .is_some_and(|hash| {
                        hash.strip_prefix("sha256:").is_some_and(|hex| {
                            hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                    })
            })
        {
            return Err("invalid PDM file hashes".into());
        }
        let files_key = legacy_files_key(package).ok_or("missing PDM files key")?;
        edits.push((index, package.contains_key("files"), files_key));
    }
    for (index, inline_files, files_key) in edits {
        let mut file = InlineTable::new();
        file.insert("file", Value::from(filename));
        file.insert(
            "hash",
            Value::from(format!("sha256:{}", sha256.to_ascii_lowercase())),
        );
        let mut files = Array::new();
        files.push(file);
        let package = lock
            .get_mut("package")
            .and_then(Item::as_array_of_tables_mut)
            .and_then(|packages| packages.get_mut(index))
            .ok_or("missing PDM package")?;
        package.insert(kind, value(location));
        if inline_files {
            package.insert("files", value(files));
        } else {
            let table = lock
                .get_mut("metadata")
                .and_then(|metadata| metadata.get_mut("files"))
                .and_then(Item::as_table_like_mut)
                .ok_or("missing PDM metadata.files")?;
            table.insert(&files_key, value(files));
        }
    }
    let rendered = preserve_line_endings(text, lock.to_string());
    let before = pdm_lock_fragments(text, name)?;
    let after = pdm_lock_fragments(&rendered, name)?;
    let edits = pair_pdm_lock_fragments(text, &before, &rendered, after)?;
    let mut result = text.to_string();
    for (old, new) in &edits {
        result = result.replacen(old, new, 1);
    }
    let known_edits = (result == rendered).then_some(edits);
    Ok(PdmLockRewrite {
        text: result,
        original: text,
        name,
        before,
        known_edits,
    })
}

/// End (exclusive, before its line break) of the first top-level TOML header
/// line at or after `from`, skipping blank/comment lines; `text.len()` at EOF;
/// `from` itself when the next non-blank line is not a header (a shape PDM never
/// writes — the fragment then ends where it used to). Kept local, like this
/// module's own `extend_span`.
fn next_header_end(text: &str, from: usize) -> usize {
    let mut pos = from;
    for line in text[from..].split_inclusive('\n') {
        let content = line.trim_end_matches(['\r', '\n']);
        if content.trim().is_empty() || content.trim_start().starts_with('#') {
            pos += line.len();
            continue;
        }
        if content.starts_with('[') {
            return pos + content.len();
        }
        return from;
    }
    text.len()
}

pub fn pdm_lock_edits(
    original: &str,
    rewritten: &str,
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    let before = pdm_lock_fragments(original, name)?;
    let after = pdm_lock_fragments(rewritten, name)?;
    pair_pdm_lock_fragments(original, &before, rewritten, after)
}

/// The fragments of `text` for `name` that [`pdm_lock_edits`] pairs up:
/// every `[[package]]` unit and each legacy `[metadata.files]` entry.
fn pdm_lock_fragments(text: &str, name: &str) -> Result<Vec<String>, String> {
    let lock = toml_edit::Document::parse(text).map_err(|e| e.to_string())?;
    let packages = lock
        .get("package")
        .and_then(Item::as_array_of_tables)
        .ok_or("missing PDM packages")?;
    let mut result = Vec::new();
    let mut integrity_keys = std::collections::BTreeSet::new();
    for package in packages.iter().filter(|package| {
        package
            .get("name")
            .and_then(Item::as_str)
            .is_some_and(|candidate| {
                canonicalize_pypi_name(candidate) == canonicalize_pypi_name(name)
            })
    }) {
        fn extend_span(table: &Table, span: &mut std::ops::Range<usize>) {
            for (_, item) in table.iter() {
                if let Some(own) = item.span() {
                    span.start = span.start.min(own.start);
                    span.end = span.end.max(own.end);
                }
                if let Some(child) = item.as_table() {
                    extend_span(child, span);
                }
            }
        }
        let mut span = package.span().ok_or("missing PDM package span")?;
        extend_span(package, &mut span);
        span.end += text[span.end..]
            .find(['\r', '\n'])
            .unwrap_or(text.len() - span.end);
        // Carry the unit's BOUNDARY (blank line(s) after it plus the next
        // top-level header, or EOF): the rewrite APPENDS `url` to the unit,
        // so for a lock_version-2 unit — whose body carries no inline
        // `files` to diverge — the pristine fragment would otherwise be a
        // strict prefix of the rewritten one, and replay's "already
        // converged" guard (`!new.contains(original)`) could never fire for
        // a relocked lock.
        span.end = next_header_end(text, span.end);
        result.push(text[span].to_string());
        if !package.contains_key("files") {
            let key = legacy_files_key(package).ok_or("missing PDM files key")?;
            if !integrity_keys.insert(key.clone()) {
                continue;
            }
            let table = lock
                .get("metadata")
                .and_then(|metadata| metadata.get("files"))
                .and_then(Item::as_table)
                .ok_or("missing PDM metadata.files")?;
            let start = table
                .key(&key)
                .and_then(|key| key.span())
                .ok_or("missing PDM files key")?
                .start;
            let end = table
                .get(&key)
                .and_then(Item::span)
                .ok_or("missing PDM files span")?
                .end;
            result.push(text[start..end].to_string());
        }
    }
    if result.is_empty() {
        return Err("missing PDM package fragments".into());
    }
    Ok(result)
}

/// [`pdm_lock_edits`] over fragments already taken from both sides.
fn pair_pdm_lock_fragments(
    original: &str,
    before: &[String],
    rewritten: &str,
    after: Vec<String>,
) -> Result<Vec<(String, String)>, String> {
    if before.len() != after.len() {
        return Err("PDM package fragments changed shape".into());
    }
    let mut edits = Vec::new();
    for (old, new) in before.iter().zip(after) {
        if *old == new {
            continue;
        }
        if original.matches(old.as_str()).count() != 1 || rewritten.matches(&new).count() != 1 {
            return Err("ambiguous PDM rollback fragment".into());
        }
        edits.push((old.clone(), new));
    }
    Ok(edits)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHEEL: &str = "urllib3-1.26.18-py2.py3-none-any.whl";
    const PATH: &str = "./.socket/vendor/pypi/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/pdm-native")
                .join(format!("{name}.lock")),
        )
        .unwrap()
    }

    #[test]
    fn native_formats_rewrite_and_reverse_byte_exactly() {
        for version in [
            "0.12.3",
            "2.8.2",
            "2.9.3",
            "2.10.4",
            "2.11.2",
            "2.17.3",
            "2.29.2",
            "0.12.3-extras",
            "2.29.2-extras",
        ] {
            for ending in ["\n", "\r\n"] {
                let original = fixture(version).replace('\n', ending);
                for (kind, source) in [("path", PATH), ("path", &PATH.replace('/', "\\")), ("url", "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl")] {
                    let rewritten = rewrite_pdm_lock(&original, "urllib3", "1.26.18", (kind, source), WHEEL, &"a".repeat(64)).unwrap();
                    let lock: DocumentMut = rewritten.parse().unwrap();
                    let old: DocumentMut = original.parse().unwrap();
                    assert_eq!(old["metadata"]["content_hash"].as_str(), lock["metadata"]["content_hash"].as_str());
                    for pkg in lock["package"].as_array_of_tables().unwrap() {
                        if pkg["name"].as_str() != Some("urllib3") { continue; }
                        assert_eq!(pkg[kind].as_str(), Some(source));
                        let files = files_for(&lock, pkg).unwrap();
                        assert_eq!(files.len(), 1);
                        assert_eq!(files.get(0).unwrap().as_inline_table().unwrap()["hash"].as_str(), Some(format!("sha256:{}", "a".repeat(64)).as_str()));
                    }
                    assert_eq!(rewrite_pdm_lock(&rewritten, "urllib3", "1.26.18", (kind, source), WHEEL, &"a".repeat(64)).unwrap(), rewritten);
                    let mut reverted = rewritten.clone();
                    for (before, after) in pdm_lock_edits(&original, &rewritten, "urllib3").unwrap().into_iter().rev() {
                        reverted = reverted.replacen(&after, &before, 1);
                    }
                    assert_eq!(reverted, original);
                    if ending == "\r\n" { assert!(!rewritten.replace("\r\n", "").contains('\n')); }
                }
            }
        }
    }

    #[test]
    fn native_installers_that_lose_source_identity_refuse() {
        for version in ["1.15.5", "2.0.3", "2.1.5", "2.3.4", "2.6.1", "2.7.4"] {
            let original = fixture(version);
            assert!(rewrite_pdm_lock(
                &original,
                "urllib3",
                "1.26.18",
                ("path", PATH),
                WHEEL,
                &"a".repeat(64)
            )
            .unwrap_err()
            .contains("unsupported PDM lock_version"));
        }
    }

    #[test]
    fn unsafe_sources_forks_and_integrity_refuse_transactionally() {
        let original = fixture("2.29.2");
        for field in [
            "url = 'https://example.com/archive.whl'",
            "path = '../custom.whl'",
            "git = 'https://example.com/repo'",
            "hg = 'https://example.com/repo'",
            "svn = 'https://example.com/repo'",
            "bzr = 'https://example.com/repo'",
            "editable = false",
            "source = 'private'",
        ] {
            let text = original.replace(
                "name = \"urllib3\"",
                &format!("name = \"urllib3\"\n{field}"),
            );
            assert!(
                rewrite_pdm_lock(
                    &text,
                    "urllib3",
                    "1.26.18",
                    ("path", PATH),
                    WHEEL,
                    &"a".repeat(64)
                )
                .is_err(),
                "{field}"
            );
        }
        let duplicate = format!("{original}\n[[package]]\nname = 'urllib3'\nversion = '1.26.18'\n");
        assert!(rewrite_pdm_lock(
            &duplicate,
            "urllib3",
            "1.26.18",
            ("path", PATH),
            WHEEL,
            &"a".repeat(64)
        )
        .is_err());
        for text in [
            original.replace("sha256:", "md5:"),
            original.replace("4.5.1", "4.6.0"),
            original.replace("inherit_metadata", "unknown"),
            original.replace("version = \"1.26.18\"", "version = '1.26.19'"),
            original.replace("files = [", "files = 42\ninvalid = ["),
        ] {
            assert!(rewrite_pdm_lock(
                &text,
                "urllib3",
                "1.26.18",
                ("path", PATH),
                WHEEL,
                &"a".repeat(64)
            )
            .is_err());
        }
        assert!(rewrite_pdm_lock(
            &original,
            "requests",
            "1.26.18",
            ("path", PATH),
            WHEEL,
            &"a".repeat(64)
        )
        .is_err());
        assert!(rewrite_pdm_lock(
            &original,
            "urllib3",
            "1.26.18",
            ("path", PATH),
            WHEEL,
            "invalid"
        )
        .is_err());
    }

    fn doc(text: &str) -> DocumentMut {
        text.parse().unwrap()
    }

    #[test]
    fn strategy_boolean_spelling_and_inherit_metadata_gate() {
        // lock_version 4.3 (PDM 2.8-2.9) spells strategy as [metadata] booleans.
        assert_eq!(
            validate_strategy(&doc(&fixture("2.8.2"))).unwrap(),
            vec!["cross_platform".to_string()],
            "4.3 booleans are read (static_urls=false is not recorded)"
        );
        // 4.4 (2.10.4) default lock has no inherit_metadata and is still allowed.
        assert!(validate_strategy(&doc(&fixture("2.10.4"))).is_ok());
        // A 4.5.0 lock whose strategy drops inherit_metadata (what
        // `pdm lock --strategy no_inherit_metadata` writes) is refused — PDM
        // re-resolves such a lock and cannot round-trip our url/path source.
        let stripped = fixture("2.17.3").replace("[\"inherit_metadata\"]", "[\"cross_platform\"]");
        let err = validate_strategy(&doc(&stripped)).unwrap_err();
        assert!(err.contains("inherit_metadata"), "{err}");
        // The default 4.4.1/4.5.x locks keep inherit_metadata → allowed.
        for v in ["2.11.2", "2.29.2"] {
            assert!(validate_strategy(&doc(&fixture(v))).is_ok(), "{v}");
        }
    }

    #[test]
    fn multiple_locked_versions_refuse_as_a_fork() {
        // A marker/multi-target lock holding urllib3 at two versions is refused
        // ahead of the per-unit version check, with an accurate message.
        let forked = format!(
            "{}\n[[package]]\nname = \"urllib3\"\nversion = \"2.2.3\"\ngroups = [\"default\"]\nfiles = [\n    {{file = \"urllib3-2.2.3-py3-none-any.whl\", hash = \"sha256:{}\"}},\n]\n",
            fixture("2.29.2").trim_end(),
            "b".repeat(64)
        );
        let err = rewrite_pdm_lock(
            &forked,
            "urllib3",
            "1.26.18",
            ("path", PATH),
            WHEEL,
            &"a".repeat(64),
        )
        .unwrap_err();
        assert!(err.contains("multiple versions"), "{err}");
    }

    #[test]
    fn supersedes_a_prior_socket_hosted_url_in_place() {
        let base = "https://patch.socket.dev/patch/pypi/urllib3/1.26.18";
        let stale = format!("{base}/OLDTOKEN/OLDUUID/{WHEEL}");
        let fresh = format!("{base}/NEWTOKEN/NEWUUID/{WHEEL}");
        // A lock already routing through an earlier Socket url (rotated token /
        // new uuid, same origin + wheel leaf) is superseded, not refused.
        let wired = rewrite_pdm_lock(
            &fixture("2.29.2"),
            "urllib3",
            "1.26.18",
            ("url", &stale),
            WHEEL,
            &"a".repeat(64),
        )
        .unwrap();
        let rewired = rewrite_pdm_lock(
            &wired,
            "urllib3",
            "1.26.18",
            ("url", &fresh),
            WHEEL,
            &"a".repeat(64),
        )
        .unwrap();
        assert!(rewired.contains(&fresh) && !rewired.contains(&stale), "{rewired}");
        // A foreign (non-Socket) existing url is still refused.
        let foreign = fixture("2.29.2").replace(
            "name = \"urllib3\"",
            "name = \"urllib3\"\nurl = \"https://example.com/urllib3-1.26.18-py2.py3-none-any.whl\"",
        );
        assert!(rewrite_pdm_lock(
            &foreign,
            "urllib3",
            "1.26.18",
            ("url", &fresh),
            WHEEL,
            &"a".repeat(64)
        )
        .is_err());
    }

    #[test]
    fn legacy_files_key_preserves_dotted_names() {
        // PDM 0.12-1.5 key [metadata.files] with safe_name(name).lower(), which
        // keeps dots — unlike PEP 503 canonicalization.
        let table: Table = "name = \"Zope.Interface\"\nversion = \"6.0\"\n"
            .parse::<DocumentMut>()
            .unwrap()
            .as_table()
            .clone();
        assert_eq!(
            legacy_files_key(&table).as_deref(),
            Some("zope.interface 6.0")
        );
    }

    /// The edits a rewrite hands back are exactly `pdm_lock_edits` of its
    /// input and output — whether reused from the rewrite or re-derived.
    #[test]
    fn rewrite_edits_equal_pdm_lock_edits() {
        let mut rewritten = 0;
        for name in [
            "0.12.3",
            "0.12.3-extras",
            "1.15.5",
            "2.0.3",
            "2.8.2",
            "2.10.4",
            "2.17.3",
            "2.29.2",
        ] {
            for crlf in [false, true] {
                let mut text = fixture(name).replace("\r\n", "\n");
                if crlf {
                    text = text.replace('\n', "\r\n");
                }
                // Formats the rewriter refuses (lock_version 3.1) have no edits.
                let Ok(rewrite) = rewrite_pdm_lock_with_edits(
                    &text,
                    "urllib3",
                    "1.26.18",
                    ("path", PATH),
                    WHEEL,
                    &"a".repeat(64),
                ) else {
                    continue;
                };
                rewritten += 1;
                let want = pdm_lock_edits(&text, &rewrite.text, "urllib3");
                assert_eq!(rewrite.edits(), want, "{name} crlf={crlf}");
                let rederived = PdmLockRewrite {
                    known_edits: None,
                    ..rewrite
                };
                assert_eq!(rederived.edits(), want, "{name} crlf={crlf} re-derived");
            }
        }
        assert!(
            rewritten >= 10,
            "the corpus exercises the rewrite ({rewritten})"
        );
    }
}
