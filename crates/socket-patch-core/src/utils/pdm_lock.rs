#[cfg(test)]
use toml_edit::DocumentMut;
use toml_edit::{value, Array, InlineTable, Item, Table, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::lock_fragments::{
    extend_span, finish, fragments_of, next_header_end, pair_fragments, rewrite_batch,
    FragmentRewrite, LockParse,
};
pub use crate::utils::lock_fragments::{LockBatch, LockStep};
use crate::utils::python_lock::is_prior_hosted_url;

pub fn lock_version(lock: &Table) -> Result<&str, String> {
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

pub fn validate_strategy(lock: &Table) -> Result<Vec<String>, String> {
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

pub fn files_for<'a>(lock: &'a Table, package: &'a Table) -> Option<&'a Array> {
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

/// A successful [`rewrite_pdm_lock_with_edits`]; its
/// [`edits`](FragmentRewrite::edits) are exactly
/// `pdm_lock_edits(original, &text, name)`.
pub type PdmLockRewrite<'a> = FragmentRewrite<'a>;

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
    rewrite_pdm_lock_in(
        &mut PdmLockParse::default(),
        text,
        name,
        version,
        source,
        filename,
        sha256,
    )
}

/// The parse of the `pdm.lock` text last seen or produced, carried between
/// calls (see [`LockParse`]).
pub type PdmLockParse = LockParse;

/// [`rewrite_pdm_lock_with_edits`], reusing (and refreshing) `parse`.
pub fn rewrite_pdm_lock_in<'a>(
    parse: &mut PdmLockParse,
    text: &'a str,
    name: &'a str,
    version: &str,
    source: (&str, &str),
    filename: &str,
    sha256: &str,
) -> Result<PdmLockRewrite<'a>, String> {
    let (kind, location) = source;
    check_pdm_artifact(name, version, kind, filename, sha256)?;
    let doc = parse.take(text, "PDM")?;
    let edits = match plan_pdm_rewrite(&doc, name, version, kind, location) {
        Ok(edits) => edits,
        Err(detail) => {
            // Nothing was mutated: the parse still describes `text`.
            parse.restore(doc);
            return Err(detail);
        }
    };
    // The original's fragments come from the same parse; an error surfaces
    // where a fresh parse would raise it, after the rewrite.
    let before = pdm_lock_fragments_in(&doc, text, name);
    let mut lock = doc.into_mut();
    mutate_pdm_lock(&mut lock, edits, source, filename, sha256)?;
    finish(
        "PDM",
        parse,
        text,
        name,
        lock.to_string(),
        before,
        pdm_lock_fragments_in::<String>,
    )
}

/// The rewrite's own refusals, settled before the lock is read.
fn check_pdm_artifact(
    name: &str,
    version: &str,
    kind: &str,
    filename: &str,
    sha256: &str,
) -> Result<(), String> {
    if !matches!(kind, "url" | "path")
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid PDM artifact source or SHA-256".into());
    }
    if !crate::vendor::pypi_distribution::matches(filename, name, version) {
        return Err("PDM patch wheel does not match package".into());
    }
    Ok(())
}

/// Apply a planned rewrite (the units [`plan_pdm_rewrite`] settled) to the
/// parsed lock.
fn mutate_pdm_lock(
    lock: &mut toml_edit::DocumentMut,
    edits: Vec<(usize, bool, String)>,
    (kind, location): (&str, &str),
    filename: &str,
    sha256: &str,
) -> Result<(), String> {
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
    Ok(())
}

/// One dep of a [`rewrite_pdm_lock_all`]: the arguments of
/// [`rewrite_pdm_lock_in`] past the lock text.
pub struct PdmLockDep<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub source: (&'a str, &'a str),
    pub filename: &'a str,
    pub sha256: &'a str,
}

/// Every dep's [`rewrite_pdm_lock_in`] over `text`, each against the
/// previous one's output: one parse and one render of the lock for all of
/// them when the batch can vouch for the step-by-step result, else step by
/// step. A dep's step is never [`LockStep::NotFound`]: PDM refuses a
/// package its lock lacks.
pub fn rewrite_pdm_lock_all(text: &str, deps: &[PdmLockDep]) -> LockBatch {
    rewrite_pdm_lock_batch(text, deps).unwrap_or_else(|| rewrite_pdm_lock_steps(text, deps))
}

/// [`rewrite_pdm_lock_all`] over one parse and one render, or `None` (see
/// [`rewrite_batch`]).
fn rewrite_pdm_lock_batch(text: &str, deps: &[PdmLockDep]) -> Option<LockBatch> {
    let names: Vec<&str> = deps.iter().map(|dep| dep.name).collect();
    rewrite_batch(
        text,
        &names,
        |index, lock| {
            let dep = &deps[index];
            check_pdm_artifact(
                dep.name,
                dep.version,
                dep.source.0,
                dep.filename,
                dep.sha256,
            )?;
            let units = plan_pdm_rewrite(lock, dep.name, dep.version, dep.source.0, dep.source.1)?;
            Ok(Some((units, index)))
        },
        |lock, (units, index)| {
            let dep = &deps[index];
            mutate_pdm_lock(lock, units, dep.source, dep.filename, dep.sha256)
        },
        pdm_lock_fragments_in::<String>,
    )
}

/// [`rewrite_pdm_lock_all`] one dep at a time.
fn rewrite_pdm_lock_steps(text: &str, deps: &[PdmLockDep]) -> LockBatch {
    let mut content = text.to_string();
    let mut parse = PdmLockParse::default();
    let mut steps = Vec::with_capacity(deps.len());
    for dep in deps {
        let rewrite = rewrite_pdm_lock_in(
            &mut parse,
            &content,
            dep.name,
            dep.version,
            dep.source,
            dep.filename,
            dep.sha256,
        );
        let step = match rewrite.and_then(|rewrite| Ok((rewrite.edits()?, rewrite.text))) {
            Ok((edits, rewritten)) => {
                let step = if rewritten == content {
                    LockStep::Unchanged
                } else {
                    LockStep::Rewritten(edits)
                };
                content = rewritten;
                step
            }
            Err(detail) => LockStep::Refused(detail),
        };
        steps.push(step);
    }
    LockBatch {
        text: content,
        steps,
    }
}

/// Every refusal of [`rewrite_pdm_lock_in`], read from the parsed lock before
/// it mutates anything: the `(package index, inline files, legacy files key)`
/// of each unit to rewrite.
fn plan_pdm_rewrite(
    lock: &Table,
    name: &str,
    version: &str,
    kind: &str,
    location: &str,
) -> Result<Vec<(usize, bool, String)>, String> {
    lock_version(lock)?;
    validate_strategy(lock)?;
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
        return Err(
            "PDM lock resolves this package at multiple versions (a marker or \
                    multi-target fork); patching one fork would leave the others unpatched"
                .into(),
        );
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
        let original_files = files_for(lock, package).ok_or("missing PDM file hashes")?;
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
    Ok(edits)
}

pub fn pdm_lock_edits(
    original: &str,
    rewritten: &str,
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    let before = pdm_lock_fragments(original, name)?;
    let after = pdm_lock_fragments(rewritten, name)?;
    pair_fragments("PDM", original, &before, rewritten, after)
}

/// The fragments of `text` for `name` that [`pdm_lock_edits`] pairs up:
/// every `[[package]]` unit and each legacy `[metadata.files]` entry.
fn pdm_lock_fragments(text: &str, name: &str) -> Result<Vec<String>, String> {
    fragments_of(text, name, pdm_lock_fragments_in::<String>)
}

/// [`pdm_lock_fragments`] of `text` from its (spanned) parse `lock`.
fn pdm_lock_fragments_in<S>(
    lock: &toml_edit::Document<S>,
    text: &str,
    name: &str,
) -> Result<Vec<String>, String> {
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

#[cfg(test)]
pub(crate) mod tests {
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
        assert!(
            rewired.contains(&fresh) && !rewired.contains(&stale),
            "{rewired}"
        );
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

    /// When the splice does not reproduce the rendered document (a mixed
    /// line-ending lock: the renderer keeps no CRLF, the splice leaves the
    /// untouched CRLF lines alone), the rewrite's own edits are not kept and
    /// `edits()` re-derives them against the output.
    /// `text` with every line break spelled `base`, except the patched
    /// unit's `name = "urllib3"` line(s), spelled `odd`.
    pub(crate) fn mixed_endings(text: &str, base: &str, odd: &str) -> String {
        text.replace("\r\n", "\n")
            .split_inclusive('\n')
            .map(|line| {
                let ending = if line.starts_with("name = \"urllib3\"") {
                    odd
                } else {
                    base
                };
                line.replace('\n', ending)
            })
            .collect()
    }

    /// Breaks spelled `ending` (bare `\n` for LF) in `text`.
    pub(crate) fn count_breaks(text: &str, ending: &str) -> usize {
        let crlf = text.matches("\r\n").count();
        if ending == "\r\n" {
            crlf
        } else {
            text.matches('\n').count() - crlf
        }
    }

    /// #695: a mixed-ending lock's rewritten unit takes the ending most of
    /// its own lines had, every other line keeps its own, and the recorded
    /// edits replay back byte for byte (hosted `url` and vendored `path`).
    #[test]
    fn mixed_line_ending_unit_keeps_its_majority_ending() {
        let url = "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
        for version in [
            "0.12.3",
            "2.8.2",
            "2.11.2",
            "2.17.3",
            "2.29.2",
            "2.29.2-extras",
        ] {
            for (base, odd) in [("\r\n", "\n"), ("\n", "\r\n")] {
                let original = mixed_endings(&fixture(version), base, odd);
                assert!(count_breaks(&original, odd) > 0);
                for source in [("path", PATH), ("url", url)] {
                    let rewrite = rewrite_pdm_lock_with_edits(
                        &original,
                        "urllib3",
                        "1.26.18",
                        source,
                        WHEEL,
                        &"a".repeat(64),
                    )
                    .unwrap();
                    assert_eq!(
                        count_breaks(&rewrite.text, odd),
                        0,
                        "{version} {source:?} base {base:?}: {:?}",
                        rewrite.text
                    );
                    let edits = rewrite.edits().unwrap();
                    assert_eq!(
                        edits,
                        pdm_lock_edits(&original, &rewrite.text, "urllib3").unwrap()
                    );
                    let mut reverted = rewrite.text.clone();
                    for (before, after) in edits.into_iter().rev() {
                        reverted = reverted.replacen(&after, &before, 1);
                    }
                    assert_eq!(reverted, original, "{version} {source:?}");
                }
            }
        }
    }

    /// #694: the shared pairing refuses fragments that changed shape.
    #[test]
    fn pairing_refuses_a_fragment_shape_change() {
        let original = fixture("2.29.2");
        let before = pdm_lock_fragments(&original, "urllib3").unwrap();
        assert_eq!(
            pair_fragments("PDM", &original, &before, &original, Vec::new()),
            Err("PDM package fragments changed shape".to_string())
        );
    }

    #[test]
    fn rewrite_edits_are_rederived_when_the_splice_differs_from_the_document() {
        let mut rederived = 0;
        for name in ["0.12.3", "1.15.5", "2.0.3", "2.8.2", "2.17.3", "2.29.2"] {
            let crlf = fixture(name).replace("\r\n", "\n").replace('\n', "\r\n");
            let first = crlf.find("\r\n").unwrap();
            let text = format!("{}\n{}", &crlf[..first], &crlf[first + 2..]);
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
            rederived += 1;
            assert!(rewrite.known_edits.is_none(), "{name}: splice must differ");
            assert_eq!(
                rewrite.edits(),
                pdm_lock_edits(&text, &rewrite.text, "urllib3"),
                "{name}"
            );
        }
        assert!(
            rederived >= 4,
            "the corpus exercises the re-derive ({rederived})"
        );
    }
}

#[cfg(test)]
pub(crate) mod parse_reuse_tests {
    //! Shared by the pdm parse-reuse sweeps: the native fixtures grown to
    //! several packages, and the dep steps rewritten over them.
    use super::*;

    /// Every native pdm lock generation in `tests/fixtures/pdm-native`.
    pub(crate) fn fixtures() -> Vec<(String, String)> {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pdm-native");
        let mut out: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "lock"))
            .map(|path| {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read_to_string(&path).unwrap())
            })
            .collect();
        out.sort();
        assert!(out.len() >= 15, "every native pdm lock generation");
        out
    }

    /// `lock` (LF) with every `urllib3` package unit cloned as `pkg0`..,
    /// and — when `[metadata.files]` closes the file — its legacy entries.
    pub(crate) fn grown(lock: &str, extra: usize) -> String {
        let lines: Vec<&str> = lock.split_inclusive('\n').collect();
        let is_top_header = |l: &str| {
            l.starts_with("[[package]]") || (l.starts_with('[') && !l.starts_with("[package."))
        };
        let mut blocks: Vec<(usize, usize)> = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].starts_with("[[package]]") {
                let start = i;
                i += 1;
                while i < lines.len() && !is_top_header(lines[i]) {
                    i += 1;
                }
                blocks.push((start, i));
            } else {
                i += 1;
            }
        }
        let Some(&(_, last_end)) = blocks.last() else {
            return lock.to_string();
        };
        let mut clones = String::new();
        for n in 0..extra {
            for &(start, end) in &blocks {
                let block: String = lines[start..end].concat();
                if block.contains("name = \"urllib3\"") {
                    let mut block =
                        block.replace("name = \"urllib3\"", &format!("name = \"pkg{n}\""));
                    if !block.ends_with("\n\n") {
                        block.push_str(if block.ends_with('\n') { "\n" } else { "\n\n" });
                    }
                    clones.push_str(&block);
                }
            }
        }
        let mut out: String = lines[..last_end].concat();
        if !out.ends_with("\n\n") {
            out.push_str(if out.ends_with('\n') { "\n" } else { "\n\n" });
        }
        out.push_str(&clones);
        out.push_str(&lines[last_end..].concat());
        let last_header = lines.iter().rev().find(|l| l.starts_with('['));
        if last_header.is_some_and(|l| l.starts_with("[metadata.files]")) {
            let mut entries = String::new();
            let mut j = 0;
            while j < lines.len() {
                if lines[j].starts_with("\"urllib3") {
                    let start = j;
                    while j < lines.len() && !lines[j].starts_with(']') {
                        j += 1;
                    }
                    let entry: String = lines[start..=j.min(lines.len() - 1)].concat();
                    for n in 0..extra {
                        entries.push_str(&entry.replacen("\"urllib3", &format!("\"pkg{n}"), 1));
                    }
                }
                j += 1;
            }
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&entries);
        }
        out
    }

    const SHA: &str = "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07";

    /// The step sequence: landing deps, a re-run, a rotated-token takeover,
    /// and refusals (other version, bad hash, foreign path source) between.
    pub(crate) fn steps(extra: usize) -> Vec<(String, String, (String, String), String)> {
        let url = |name: &str, tag: &str, version: &str| {
            format!("https://patch.socket.dev/patch/pypi/{name}/{tag}/{name}-{version}-py3-none-any.whl")
        };
        let hosted = |name: &str, tag: &str, version: &str, sha: &str| {
            (
                name.to_string(),
                version.to_string(),
                ("url".to_string(), url(name, tag, version)),
                sha.to_string(),
            )
        };
        let mut out = vec![hosted("urllib3", "a", "1.26.18", SHA)];
        for n in 0..extra {
            out.push(hosted(&format!("pkg{n}"), "a", "1.26.18", SHA));
        }
        out.push(hosted("PySocks", "a", "1.7.1", SHA));
        out.push(hosted("absent", "a", "1.0.0", SHA));
        out.push(hosted("urllib3", "a", "9.9.9", SHA));
        out.push(hosted("urllib3", "a", "1.26.18", "not-a-sha"));
        out.push(hosted("urllib3", "a", "1.26.18", SHA));
        out.push(hosted("urllib3", "rotated", "1.26.18", SHA));
        out.push((
            "urllib3".into(),
            "1.26.18".into(),
            (
                "path".into(),
                "./.socket/vendor/pypi/u/urllib3-1.26.18-py3-none-any.whl".into(),
            ),
            SHA.into(),
        ));
        if extra > 1 {
            out.push(hosted("pkg1", "b", "1.26.18", &SHA.to_ascii_uppercase()));
        }
        out
    }

    #[test]
    fn reused_parse_matches_golden() {
        let mut golden = crate::golden::Golden::new(
            "pdm_lock_reused_parse",
            "One rewrite step over a grown pdm.lock: the text and edits, or the refusal.",
        );
        let mut landed = 0;
        for (_, lock) in fixtures() {
            for extra in [0, 3] {
                for crlf in [false, true] {
                    let mut lock = grown(&lock.replace("\r\n", "\n"), extra);
                    if crlf {
                        lock = lock.replace('\n', "\r\n");
                    }
                    let mut got_text = lock;
                    let mut parse = PdmLockParse::default();
                    for (name, version, (kind, location), sha) in steps(extra).iter() {
                        let filename = location.rsplit('/').next().unwrap();
                        let source = (kind.as_str(), location.as_str());
                        let got = rewrite_pdm_lock_in(
                            &mut parse, &got_text, name, version, source, filename, sha,
                        );
                        golden.next(
                            &(&got_text, name, version, kind, location, sha),
                            &format!("{:?}", got.as_ref().map(|r| (&r.text, r.edits()))),
                        );
                        if let Ok(g) = got {
                            landed += 1;
                            got_text = g.text;
                        }
                    }
                }
            }
        }
        assert!(landed > 100, "only {landed} rewrites landed");
        golden.finish();
    }

    /// A parse is reused only for byte-identical text.
    #[test]
    fn reused_parse_misses_on_changed_text() {
        let lock = grown(&fixtures().pop().unwrap().1.replace("\r\n", "\n"), 2);
        let mut parse = PdmLockParse::default();
        let url = "https://patch.socket.dev/patch/pypi/pkg0/a/pkg0-1.26.18-py3-none-any.whl";
        let first = rewrite_pdm_lock_in(
            &mut parse,
            &lock,
            "pkg0",
            "1.26.18",
            ("url", url),
            "pkg0-1.26.18-py3-none-any.whl",
            SHA,
        )
        .unwrap();
        let edited = first.text.replace("name = \"pkg1\"", "name = \"gone\"");
        let url = "https://patch.socket.dev/patch/pypi/pkg1/a/pkg1-1.26.18-py3-none-any.whl";
        let got = rewrite_pdm_lock_in(
            &mut parse,
            &edited,
            "pkg1",
            "1.26.18",
            ("url", url),
            "pkg1-1.26.18-py3-none-any.whl",
            SHA,
        );
        assert_eq!(got.err().as_deref(), Some("missing PDM package"));
        // `parsed` likewise re-parses changed text.
        let names = |parse: &mut PdmLockParse, text: &str| -> Vec<String> {
            parse.parsed(text).unwrap()["package"]
                .as_array_of_tables()
                .unwrap()
                .iter()
                .filter_map(|p| p.get("name")?.as_str().map(str::to_string))
                .collect()
        };
        assert!(names(&mut parse, &edited).contains(&"gone".to_string()));
        assert!(names(&mut parse, &first.text).contains(&"pkg1".to_string()));
    }
}

#[cfg(test)]
mod batch_equivalence_tests {
    //! [`rewrite_pdm_lock_all`]'s one-render batch against the step-by-step
    //! rewrite it replaces (#762): whenever the batch answers, its text and
    //! every dep's step are the step-by-step ones.
    use super::parse_reuse_tests::{fixtures, grown};
    use super::*;

    const SHA: &str = "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07";

    struct Dep {
        name: String,
        version: &'static str,
        kind: &'static str,
        location: String,
        sha256: String,
    }

    fn dep(name: &str, version: &'static str, tag: &str) -> Dep {
        Dep {
            name: name.into(),
            version,
            kind: "url",
            location: format!(
                "https://patch.socket.dev/patch/pypi/{name}/{tag}/{name}-{version}-py3-none-any.whl"
            ),
            sha256: SHA.into(),
        }
    }

    fn lock_deps(deps: &[Dep]) -> Vec<PdmLockDep<'_>> {
        deps.iter()
            .map(|dep| PdmLockDep {
                name: &dep.name,
                version: dep.version,
                source: (dep.kind, &dep.location),
                filename: dep.location.rsplit('/').next().unwrap(),
                sha256: &dep.sha256,
            })
            .collect()
    }

    /// The dep mixes run over each lock: every package (adjacent units),
    /// every other one, reversed, interleaved with refusals, and a package
    /// rewritten twice (which the batch hands back).
    fn mixes(extra: usize) -> Vec<(Vec<Dep>, bool)> {
        let all = || {
            std::iter::once(dep("urllib3", "1.26.18", "a"))
                .chain((0..extra).map(|i| dep(&format!("pkg{i}"), "1.26.18", "a")))
        };
        let mut every_other: Vec<Dep> = all().step_by(2).collect();
        every_other.push(dep("absent", "1.0.0", "a"));
        let mut reversed: Vec<Dep> = all().collect();
        reversed.reverse();
        let mut mixed: Vec<Dep> = vec![dep("urllib3", "9.9.9", "a")];
        for (n, next) in all().enumerate() {
            mixed.push(next);
            if n == 1 {
                mixed.push(Dep {
                    sha256: "not-a-sha".into(),
                    ..dep("pkg0", "1.26.18", "b")
                });
                mixed.push(Dep {
                    kind: "path",
                    location: "./.socket/vendor/pypi/u/pkg0-1.26.18-py3-none-any.whl".into(),
                    ..dep("pkg0", "1.26.18", "a")
                });
            }
        }
        mixed.push(dep("urllib3", "9.9.9", "a"));
        let mut twice: Vec<Dep> = all().collect();
        twice.push(dep("urllib3", "1.26.18", "rotated"));
        vec![
            (all().collect(), true),
            (every_other, true),
            (reversed, true),
            (mixed, true),
            (twice, false),
        ]
    }

    #[test]
    fn batch_matches_the_step_by_step_rewrite() {
        let mut batched = 0;
        let mut rendered = 0;
        for (fixture, lock) in fixtures() {
            for extra in [0, 1, 4] {
                for style in ["lf", "crlf", "mixed"] {
                    let mut lock = grown(&lock.replace("\r\n", "\n"), extra);
                    match style {
                        "crlf" => lock = lock.replace('\n', "\r\n"),
                        "mixed" => lock = lock.replacen('\n', "\r\n", 1),
                        _ => {}
                    }
                    for (mix, (deps, batchable)) in mixes(extra).into_iter().enumerate() {
                        let deps = lock_deps(&deps);
                        let what = format!("{fixture} extra={extra} {style} mix={mix}");
                        let first = rewrite_pdm_lock_steps(&lock, &deps);
                        let lands = first
                            .steps
                            .iter()
                            .any(|step| matches!(step, LockStep::Rewritten(_)));
                        // And again over the output: the idempotent re-scan.
                        for (rerun, text) in
                            [lock.clone(), first.text.clone()].into_iter().enumerate()
                        {
                            let steps = rewrite_pdm_lock_steps(&text, &deps);
                            let batch = rewrite_pdm_lock_batch(&text, &deps);
                            if let Some(batch) = &batch {
                                batched += 1;
                                rendered += usize::from(lands);
                                assert_eq!(batch, &steps, "{what}");
                            }
                            assert_eq!(rewrite_pdm_lock_all(&text, &deps), steps, "{what}");
                            if !lands {
                                continue; // an unsupported generation: all refused
                            }
                            if style == "mixed" {
                                // (The first rewrite may respell the lone CRLF
                                // line, leaving the re-run's lock all LF.)
                                assert!(
                                    rerun == 1 || batch.is_none(),
                                    "{what}: the batch must hand back"
                                );
                            } else if batchable {
                                assert!(batch.is_some(), "{what}: the batch must answer");
                            } else {
                                assert!(batch.is_none(), "{what}: the batch must hand back");
                            }
                        }
                    }
                }
            }
        }
        assert!(
            rendered > 200,
            "only {rendered} landing cases batched ({batched})"
        );
    }
}
