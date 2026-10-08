//! Shared `poetry.lock` rewriter for hosted (URL source) and vendored (file
//! source) patches across every lock generation Poetry has written:
//!
//! * format `"0"` — Poetry 0.12: no `lock-version`, hashes in `[metadata.hashes]`
//! * `"1.0"` / `"1.1"` — Poetry 1.0–1.2: per-package files in `[metadata.files]`
//! * `"2.x"` — Poetry 1.3+: `files = [...]` inside each `[[package]]`
//!
//! Every edit is computed on a parsed `toml_edit` document and then spliced
//! back into the ORIGINAL text as verbatim fragment replacements, so untouched
//! bytes (formatting, comments, line endings) survive and rollback can replay
//! the recorded fragments. A malformed lock (user-editable input) must never
//! panic: every table access here is guarded and degrades to an `Err`, which
//! callers surface as a refusal warning.

use toml_edit::{value, Array, DocumentMut, InlineTable, Item, Table, TableLike, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::lock_fragments::{
    extend_span, finish, fragments_of, next_header_end, pair_fragments, rewrite_batch,
    FragmentRewrite, LockParse,
};
pub use crate::utils::lock_fragments::{LockBatch, LockStep};
use crate::utils::python_lock::{is_prior_hosted_url, table_likes};

/// The `{file, hash}` tables Poetry records in `package`'s own
/// `files = [...]` (lock 2.x; also written into 1.0/1.1 locks). Read by the
/// lock inventory and lockfile discovery alike.
pub(crate) fn package_files(package: &Table) -> Vec<&dyn TableLike> {
    table_likes(package.get("files"))
}

/// The lock-wide `[metadata.files]` entry for package `name` (lock
/// 1.0/1.1; keys compared PEP 503-canonical).
pub(crate) fn metadata_files<'d>(lock: &'d DocumentMut, name: &str) -> Vec<&'d dyn TableLike> {
    let canon = canonicalize_pypi_name(name);
    let entry = lock
        .get("metadata")
        .and_then(Item::as_table_like)
        .and_then(|metadata| metadata.get("files"))
        .and_then(Item::as_table_like)
        .and_then(|files| {
            files
                .iter()
                .find(|(key, _)| canonicalize_pypi_name(key) == canon)
                .map(|(_, item)| item)
        });
    table_likes(entry)
}

/// Whether a `[metadata.files]` entry is laid out one file per line, which is
/// how Poetry 1.0/1.1 write every NON-empty entry (tomlkit `multiline(True)`);
/// an empty one is `[]`.
pub(crate) fn is_multiline_array(item: &Item) -> bool {
    item.as_array().is_some_and(|array| {
        let has_break = |raw: Option<&str>| raw.is_some_and(|s| s.contains('\n'));
        has_break(array.trailing().as_str())
            || array
                .iter()
                .any(|v| has_break(v.decor().prefix().and_then(|p| p.as_str())))
    })
}

/// The patched `[metadata.files]` entry (lock 1.0/1.1) replacing
/// `table[name]`, laid out as the entry it replaces: one file per line
/// (Poetry's own rendering) when that entry listed files, inline when it was
/// Poetry's empty `[]` (what Poetry 1.0/1.1 record against today's PyPI JSON
/// API). The layout is the only record of which the lock had: the hosted
/// restore (`patch::redirect::upstream::pypi_locks`) reads it back to put
/// either the full release list or `[]` back. A `rewritten` package (one
/// already carrying a source: a rotated hosted url) keeps the layout of the
/// entry it has, which is the original's bit, so re-runs are idempotent.
fn legacy_files_entry(table: &dyn TableLike, name: &str, files: Array, rewritten: bool) -> Item {
    let canon = canonicalize_pypi_name(name);
    let existing = table.get(name).or_else(|| {
        table
            .iter()
            .find(|(key, _)| canonicalize_pypi_name(key) == canon)
            .map(|(_, item)| item)
    });
    let populated = if rewritten {
        existing.is_some_and(is_multiline_array)
    } else {
        existing
            .and_then(Item::as_array)
            .is_some_and(|existing| !existing.is_empty())
    };
    if !populated {
        return value(files);
    }
    multiline_files(files)
}

/// `files` laid out one file per line, Poetry's own rendering of a non-empty
/// files array (tomlkit `multiline(True)`):
///
/// ```toml
/// files = [
///     {file = "<wheel>", hash = "sha256:<hex>"},
/// ]
/// ```
fn multiline_files(files: Array) -> Item {
    let entries: Vec<String> = files
        .iter()
        .filter_map(Value::as_inline_table)
        .map(|entry| {
            let field = |key: &str| {
                entry
                    .get(key)
                    .map(|v| {
                        let mut v = v.clone();
                        v.decor_mut().clear();
                        v.to_string()
                    })
                    .unwrap_or_default()
            };
            format!(
                "    {{file = {}, hash = {}}},\n",
                field("file"),
                field("hash")
            )
        })
        .collect();
    match format!("[\n{}]", entries.concat()).parse::<Value>() {
        Ok(mut multiline) => {
            multiline.decor_mut().clear();
            Item::Value(multiline)
        }
        Err(_) => value(files),
    }
}

/// The lock generation: `"0"`, `"1.0"`, `"1.1"`, or any `"2.<minor>"` (Poetry
/// bumps the minor additively — 2.0 → 2.1 kept every shape we rewrite, and the
/// vendored loader already accepts newer minors with an advisory; the hosted
/// path must not refuse what the vendored path accepts).
pub fn lock_version(lock: &DocumentMut) -> Result<&str, String> {
    lock_version_of(lock)
}

/// [`lock_version`] of a parsed lock's root table (a `DocumentMut` or a
/// spanned `Document`).
fn lock_version_of(lock: &Table) -> Result<&str, String> {
    let metadata = lock
        .get("metadata")
        .filter(|item| item.is_table_like())
        .ok_or("missing Poetry lock metadata")?;
    match metadata.get("lock-version").and_then(Item::as_str) {
        Some(version @ ("1.0" | "1.1")) => Ok(version),
        Some(version) if is_2x(version) => Ok(version),
        Some(version) => Err(format!(
            "unsupported Poetry lock-version {version:?} (supported: legacy metadata.hashes, 1.0, \
             1.1 and 2.x)"
        )),
        None if metadata
            .get("hashes")
            .and_then(Item::as_table_like)
            .is_some() =>
        {
            Ok("0")
        }
        None => Err(
            "poetry.lock has neither a [metadata] lock-version nor a [metadata.hashes] table"
                .into(),
        ),
    }
}

fn is_2x(version: &str) -> bool {
    version
        .strip_prefix("2.")
        .is_some_and(|minor| !minor.is_empty() && minor.bytes().all(|b| b.is_ascii_digit()))
}

/// The `# This file is automatically @generated by Poetry X.Y.Z …` header
/// Poetry writes from 1.4 on (1.3 writes the sentence without a version).
/// Advisory only — a lock can be consumed by a different Poetry than the one
/// that wrote it — but it lets warnings about the WRITER's installer be
/// precise instead of blaming every lock-2.0 project for Poetry 1.3.
pub fn generated_by_version(lock_text: &str) -> Option<(u64, u64)> {
    let first = lock_text.lines().next()?;
    let rest = first.split("@generated by Poetry ").nth(1)?;
    let version = rest.split_whitespace().next()?;
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Rewrite the `[[package]]` for `name`@`version` to install the wheel at
/// `source_url` (`source_type` `"url"` for hosted, `"file"` for vendored),
/// pinning `sha256`. Returns `Ok(None)` when the lock has no such entry (or
/// resolves another version) — the caller decides whether that is a warning.
/// Returns `Err` for inputs the rewriter must refuse without writing.
pub fn rewrite_poetry_lock(
    text: &str,
    name: &str,
    version: &str,
    source_type: &str,
    source_url: &str,
    filename: &str,
    sha256: &str,
) -> Result<Option<String>, String> {
    Ok(rewrite_poetry_lock_with_edits(
        text,
        name,
        version,
        source_type,
        source_url,
        filename,
        sha256,
    )?
    .map(|rewrite| rewrite.text))
}

/// A successful [`rewrite_poetry_lock_with_edits`]; its
/// [`edits`](FragmentRewrite::edits) are exactly
/// `poetry_lock_edits(original, &text, name)`.
pub type PoetryLockRewrite<'a> = FragmentRewrite<'a>;

/// [`rewrite_poetry_lock`], also handing back what the caller needs to
/// record the rewrite's fragment edits ([`PoetryLockRewrite::edits`]).
pub fn rewrite_poetry_lock_with_edits<'a>(
    text: &'a str,
    name: &'a str,
    version: &str,
    source_type: &str,
    source_url: &str,
    filename: &str,
    sha256: &str,
) -> Result<Option<PoetryLockRewrite<'a>>, String> {
    rewrite_poetry_lock_in(
        &mut PoetryLockParse::default(),
        text,
        name,
        version,
        source_type,
        source_url,
        filename,
        sha256,
    )
}

/// The parse of the `poetry.lock` text a [`rewrite_poetry_lock_in`] call
/// last saw or produced, handed to the next call (see [`LockParse`]).
pub type PoetryLockParse = LockParse;

/// Where [`rewrite_poetry_lock_in`] rewrites, settled before it mutates.
struct PoetryLockPlan {
    format: String,
    effective_url: String,
    index: usize,
    package_name: String,
}

/// [`rewrite_poetry_lock_with_edits`], reusing (and refreshing) `parse`.
#[allow(clippy::too_many_arguments)]
pub fn rewrite_poetry_lock_in<'a>(
    parse: &mut PoetryLockParse,
    text: &'a str,
    name: &'a str,
    version: &str,
    source_type: &str,
    source_url: &str,
    filename: &str,
    sha256: &str,
) -> Result<Option<PoetryLockRewrite<'a>>, String> {
    let sha256 = checked_sha256(name, version, source_type, filename, sha256)?;
    let doc = parse.take(text, "Poetry")?;
    let plan = match plan_poetry_rewrite(&doc, name, version, source_type, source_url, &sha256) {
        Ok(Some(plan)) => plan,
        verdict => {
            // Nothing was mutated: the parse still describes `text`.
            parse.restore(doc);
            return verdict.map(|_| None);
        }
    };
    // The original's fragments come from the same parse; an error surfaces
    // where a fresh parse would raise it, after the rewrite.
    let before = poetry_lock_fragments_in(&doc, text, name);
    let mut lock = doc.into_mut();
    mutate_poetry_lock(&mut lock, plan, source_type, filename, &sha256)?;
    finish(
        "Poetry",
        parse,
        text,
        name,
        lock.to_string(),
        before,
        poetry_lock_fragments_in::<String>,
    )
    .map(Some)
}

/// The rewrite's own refusals, settled before the lock is read: the
/// lowercase `sha256` to pin.
fn checked_sha256(
    name: &str,
    version: &str,
    source_type: &str,
    filename: &str,
    sha256: &str,
) -> Result<String, String> {
    if !matches!(source_type, "file" | "url")
        || sha256.len() != 64
        || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid Poetry artifact source or SHA-256".into());
    }
    if !crate::vendor::pypi_distribution::matches(filename, name, version) {
        return Err("Poetry patch wheel does not match the locked package".into());
    }
    // Poetry compares the lock's `sha256:<hex>` against `hashlib`'s lowercase
    // hexdigest as strings, so an uppercase digest would fail every install.
    Ok(sha256.to_ascii_lowercase())
}

/// Apply a planned rewrite to the parsed lock.
fn mutate_poetry_lock(
    lock: &mut DocumentMut,
    plan: PoetryLockPlan,
    source_type: &str,
    filename: &str,
    sha256: &str,
) -> Result<(), String> {
    let PoetryLockPlan {
        format,
        effective_url,
        index,
        package_name,
    } = plan;
    let package = lock
        .get_mut("package")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|packages| packages.get_mut(index))
        .ok_or("missing Poetry package")?;
    let mut entry = InlineTable::new();
    entry.insert("file", Value::from(filename));
    entry.insert("hash", Value::from(format!("sha256:{sha256}")));
    let mut files = Array::new();
    files.push(entry);
    let mut source = Table::new();
    source.insert("type", value(source_type));
    source.insert("url", value(effective_url));
    if matches!(format.as_str(), "0" | "1.0") {
        // Poetry 0.12 / 1.0 read `source.reference` unconditionally (KeyError
        // without it), even for archive sources.
        source.insert("reference", value(""));
    }
    let rewritten = package.contains_key("source");
    package.insert("source", Item::Table(source));
    if matches!(format.as_str(), "1.0" | "1.1") && source_type == "url" {
        // Poetry >= 1.2 verifies url sources against the package's own
        // `files` (it never reads `metadata.files` hashes for them), Poetry
        // 1.0/1.1 against `metadata.files` — write both so whichever installer
        // consumes this legacy lock enforces the patched hash. Poetry 1.0/1.1
        // ignore the extra package key (measured on 1.0.10; 1.2.2 rejects a
        // tampered package `files` hash on a lock-1.0 file only when it is
        // present).
        package.insert("files", value(files.clone()));
    }
    if format.starts_with('2') {
        // Poetry 2.x writes every package's `files` one file per line;
        // hosted and vendored rewrites both keep that shape.
        package.insert("files", multiline_files(files));
    } else {
        let field = if format == "0" { "hashes" } else { "files" };
        let table = lock
            .get_mut("metadata")
            .and_then(Item::as_table_like_mut)
            .ok_or("missing Poetry lock metadata")?
            .get_mut(field)
            .ok_or_else(|| format!("missing Poetry integrity table [metadata.{field}]"))?
            .as_table_like_mut()
            .ok_or_else(|| format!("[metadata.{field}] is not a table"))?;
        if format == "0" {
            let mut hashes = Array::new();
            hashes.push(sha256);
            table.insert(&package_name, value(hashes));
        } else {
            let entry = legacy_files_entry(table, &package_name, files, rewritten);
            table.insert(&package_name, entry);
        }
    }
    Ok(())
}

/// One dep of a [`rewrite_poetry_lock_all`]: the arguments of
/// [`rewrite_poetry_lock_in`] past the lock text.
pub struct PoetryLockDep<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub source_type: &'a str,
    pub source_url: &'a str,
    pub filename: &'a str,
    pub sha256: &'a str,
}

/// Every dep's [`rewrite_poetry_lock_in`] over `text`, each against the
/// previous one's output: one parse and one render of the lock for all of
/// them when the batch can vouch for the step-by-step result, else step by
/// step.
pub fn rewrite_poetry_lock_all(text: &str, deps: &[PoetryLockDep]) -> LockBatch {
    rewrite_poetry_lock_batch(text, deps).unwrap_or_else(|| rewrite_poetry_lock_steps(text, deps))
}

/// [`rewrite_poetry_lock_all`] over one parse and one render, or `None` (see
/// [`rewrite_batch`]).
fn rewrite_poetry_lock_batch(text: &str, deps: &[PoetryLockDep]) -> Option<LockBatch> {
    let names: Vec<&str> = deps.iter().map(|dep| dep.name).collect();
    rewrite_batch(
        text,
        &names,
        |index, lock| {
            let dep = &deps[index];
            let sha256 = checked_sha256(
                dep.name,
                dep.version,
                dep.source_type,
                dep.filename,
                dep.sha256,
            )?;
            let plan = plan_poetry_rewrite(
                lock,
                dep.name,
                dep.version,
                dep.source_type,
                dep.source_url,
                &sha256,
            )?;
            Ok(plan.map(|plan| (plan, index, sha256)))
        },
        |lock, (plan, index, sha256)| {
            let dep = &deps[index];
            mutate_poetry_lock(lock, plan, dep.source_type, dep.filename, &sha256)
        },
        poetry_lock_fragments_in::<String>,
    )
}

/// [`rewrite_poetry_lock_all`] one dep at a time.
fn rewrite_poetry_lock_steps(text: &str, deps: &[PoetryLockDep]) -> LockBatch {
    let mut content = text.to_string();
    let mut parse = PoetryLockParse::default();
    let mut steps = Vec::with_capacity(deps.len());
    for dep in deps {
        let step = match rewrite_poetry_lock_in(
            &mut parse,
            &content,
            dep.name,
            dep.version,
            dep.source_type,
            dep.source_url,
            dep.filename,
            dep.sha256,
        ) {
            Ok(Some(rewrite)) if rewrite.text != content => match rewrite.edits() {
                Ok(edits) => {
                    let text = rewrite.text;
                    content = text;
                    LockStep::Rewritten(edits)
                }
                Err(detail) => LockStep::Refused(detail),
            },
            Ok(Some(_)) => LockStep::Unchanged,
            Ok(None) => LockStep::NotFound,
            Err(detail) => LockStep::Refused(detail),
        };
        steps.push(step);
    }
    LockBatch {
        text: content,
        steps,
    }
}

/// Every refusal and not-applicable verdict of [`rewrite_poetry_lock_in`]
/// that precedes its first mutation, read from the parsed lock.
fn plan_poetry_rewrite(
    lock: &Table,
    name: &str,
    version: &str,
    source_type: &str,
    source_url: &str,
    sha256: &str,
) -> Result<Option<PoetryLockPlan>, String> {
    let format = lock_version_of(lock)?.to_string();
    if format == "0" && source_type == "url" {
        return Err("Poetry 0.x ignores URL sources; hosted patches require Poetry >= 1.0".into());
    }
    let effective_url = if format == "1.0" && source_type == "url" {
        // Poetry 1.0 hands pip `<url>#egg=<name>` unconditionally; the trailing
        // `&` keeps `sha256=<hex>` a complete fragment parameter when `#egg=`
        // is appended (pip >= 22 would otherwise read `<hex>#egg=<name>` as the
        // digest and hard-fail the install).
        format!("{source_url}#sha256={sha256}&")
    } else {
        source_url.to_string()
    };
    let packages = lock
        .get("package")
        .and_then(Item::as_array_of_tables)
        .ok_or("missing Poetry packages")?;
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
        return Ok(None);
    }
    if indices.len() != 1 {
        return Err("forked Poetry package requires an unambiguous source".into());
    }
    let package = packages.get(indices[0]).ok_or("missing Poetry package")?;
    if package.get("version").and_then(Item::as_str) != Some(version) {
        return Ok(None);
    }
    let package_name = package
        .get("name")
        .and_then(Item::as_str)
        .unwrap_or(name)
        .to_string();
    if let Some(source) = package.get("source") {
        let existing_type = source.get("type").and_then(Item::as_str);
        let existing_url = source.get("url").and_then(Item::as_str).unwrap_or("");
        let same_target = existing_type == Some(source_type) && existing_url == effective_url;
        let prior_hosted = source_type == "url"
            && existing_type == Some("url")
            && is_prior_hosted_url(existing_url, &effective_url);
        if !same_target && !prior_hosted {
            return Err(format!(
                "refusing to replace an existing Poetry source ({} {}) for {package_name}",
                existing_type.unwrap_or("unknown"),
                existing_url
            ));
        }
    }
    Ok(Some(PoetryLockPlan {
        format,
        effective_url,
        index: indices[0],
        package_name,
    }))
}

/// The verbatim `(original, replacement)` fragments that turn `original` into
/// `rewritten` for `name`: the package's `[[package]]` unit (with its
/// sub-tables) and, for legacy formats, its `[metadata.files]` /
/// `[metadata.hashes]` entry. Each fragment must occur exactly once on both
/// sides so a textual splice — and its rollback — can never hit the wrong
/// place.
pub fn poetry_lock_edits(
    original: &str,
    rewritten: &str,
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    let before = poetry_lock_fragments(original, name)?;
    let after = poetry_lock_fragments(rewritten, name)?;
    pair_fragments("Poetry", original, &before, rewritten, after)
}

/// The fragments of `text` for `name` that [`poetry_lock_edits`] pairs up:
/// the `[[package]]` unit and, for legacy formats, the integrity entry.
fn poetry_lock_fragments(text: &str, name: &str) -> Result<Vec<String>, String> {
    fragments_of(text, name, poetry_lock_fragments_in::<String>)
}

/// [`poetry_lock_fragments`] of `text` from its (spanned) parse `lock`.
fn poetry_lock_fragments_in<S>(
    lock: &toml_edit::Document<S>,
    text: &str,
    name: &str,
) -> Result<Vec<String>, String> {
    let package = lock
        .get("package")
        .and_then(Item::as_array_of_tables)
        .and_then(|packages| {
            packages.iter().find(|package| {
                package
                    .get("name")
                    .and_then(Item::as_str)
                    .is_some_and(|value| {
                        canonicalize_pypi_name(value) == canonicalize_pypi_name(name)
                    })
            })
        })
        .ok_or("missing Poetry package")?;
    let mut span = package.span().ok_or("missing Poetry package span")?;
    extend_span(package, &mut span);
    span.end += text[span.end..]
        .find(['\r', '\n'])
        .unwrap_or(text.len() - span.end);
    // Carry the unit's BOUNDARY: the blank line(s) after it plus the next
    // top-level header (`[[package]]`, `[metadata]`, `[extras]`, …) or
    // EOF. The rewrite APPENDS `[package.source]` to the unit, so without
    // the boundary the pristine fragment would be a strict prefix of every
    // rewritten (or later relocked) unit: rollback's "already converged"
    // check could never fire for lock 1.0, and a relock that dropped the
    // inserted `files` line but kept the source block would match the
    // pristine prefix and report a successful rollback while the lock
    // still redirected. With the header included, the pristine fragment
    // matches only a unit that really ends where it ended.
    span.end = next_header_end(text, span.end);
    let mut result = vec![text[span].to_string()];
    let metadata = lock
        .get("metadata")
        .filter(|item| item.is_table_like())
        .ok_or("missing Poetry metadata")?;
    let format = metadata
        .get("lock-version")
        .and_then(Item::as_str)
        .unwrap_or("0");
    if !format.starts_with('2') {
        let field = if format == "0" { "hashes" } else { "files" };
        let table = metadata
            .get(field)
            .and_then(Item::as_table)
            .ok_or_else(|| format!("missing Poetry integrity table [metadata.{field}]"))?;
        let package_name = package
            .get("name")
            .and_then(Item::as_str)
            .ok_or("missing package name")?;
        let key_start = table
            .key(package_name)
            .and_then(|key| key.span())
            .ok_or("missing Poetry integrity key")?
            .start;
        // Anchor the fragment at the preceding line break so a
        // suffix-named sibling entry (`pyurllib3 = […]` vs `urllib3 = […]`)
        // holding the same value can never contain it.
        let start = text[..key_start].rfind('\n').unwrap_or(key_start);
        let end = table
            .get(package_name)
            .and_then(Item::span)
            .ok_or("missing Poetry integrity span")?
            .end;
        result.push(text[start..end].to_string());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WHEEL: &str = "urllib3-1.26.18-py2.py3-none-any.whl";
    const URL: &str = "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/7e52b8b6-53f2-4dc8-860a-1ae7ebd8be0e/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";

    fn fixture(version: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/poetry/{version}/poetry.lock",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
        .replace("\r\n", "\n")
    }

    fn sha() -> String {
        "a".repeat(64)
    }

    fn hosted(text: &str) -> Result<Option<String>, String> {
        rewrite_poetry_lock(text, "urllib3", "1.26.18", "url", URL, WHEEL, &sha())
    }

    /// Hosted and vendored rewrites of a 2.x lock write the package's
    /// `files` one file per line, the shape Poetry itself writes (#936).
    #[test]
    fn lock_2x_files_keep_poetrys_multiline_shape() {
        let expected = format!(
            "files = [\n    {{file = \"{WHEEL}\", hash = \"sha256:{}\"}},\n]\n",
            sha()
        );
        for version in ["1.3.2", "1.8.5", "2.4.3"] {
            let original = fixture(version);
            for (source_type, url) in [("url", URL), ("file", ".socket/vendor/pypi/x/w.whl")] {
                let text = rewrite_poetry_lock(
                    &original,
                    "urllib3",
                    "1.26.18",
                    source_type,
                    url,
                    WHEEL,
                    &sha(),
                )
                .unwrap()
                .unwrap();
                assert!(text.contains(&expected), "{version} {source_type}:\n{text}");
                assert!(!text.contains("files = [{"), "{version} {source_type}");
                // Idempotent: a re-run over its own output changes nothing.
                assert_eq!(
                    rewrite_poetry_lock(
                        &text,
                        "urllib3",
                        "1.26.18",
                        source_type,
                        url,
                        WHEEL,
                        &sha(),
                    )
                    .unwrap()
                    .as_deref(),
                    Some(text.as_str()),
                    "{version} {source_type}"
                );
            }
        }
    }

    /// #695: a mixed-ending lock's rewritten unit (and legacy integrity
    /// entry) takes the ending most of its own lines had, every other line
    /// keeps its own, and the recorded edits replay back byte for byte
    /// (hosted `url` and vendored `file`).
    #[test]
    fn mixed_line_ending_unit_keeps_its_majority_ending() {
        use crate::utils::pdm_lock::tests::{count_breaks, mixed_endings};
        let path = "./.socket/vendor/pypi/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
        for version in [
            "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.8.5", "2.0.1", "2.4.3",
        ] {
            for (base, odd) in [("\r\n", "\n"), ("\n", "\r\n")] {
                let original = mixed_endings(&fixture(version), base, odd);
                assert!(count_breaks(&original, odd) > 0);
                for (kind, source) in [("file", path), ("url", URL)] {
                    if version == "0.12.17" && kind == "url" {
                        continue;
                    }
                    let rewrite = rewrite_poetry_lock_with_edits(
                        &original,
                        "urllib3",
                        "1.26.18",
                        kind,
                        source,
                        WHEEL,
                        &sha(),
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(
                        count_breaks(&rewrite.text, odd),
                        0,
                        "{version} {kind} base {base:?}: {:?}",
                        rewrite.text
                    );
                    let edits = rewrite.edits().unwrap();
                    assert_eq!(
                        edits,
                        poetry_lock_edits(&original, &rewrite.text, "urllib3").unwrap()
                    );
                    let mut reverted = rewrite.text.clone();
                    for (before, after) in edits.into_iter().rev() {
                        reverted = reverted.replacen(&after, &before, 1);
                    }
                    assert_eq!(reverted, original, "{version} {kind}");
                }
            }
        }
    }

    /// #694: the shared pairing refuses fragments that changed shape.
    #[test]
    fn pairing_refuses_a_fragment_shape_change() {
        let original = fixture("1.2.2");
        let before = poetry_lock_fragments(&original, "urllib3").unwrap();
        assert_eq!(before.len(), 2);
        assert_eq!(
            pair_fragments(
                "Poetry",
                &original,
                &before,
                &original,
                before[..1].to_vec()
            ),
            Err("Poetry package fragments changed shape".to_string())
        );
    }

    /// A user-editable lock with a malformed integrity table must be refused,
    /// never panic (no `IndexMut` straight into `metadata.files`).
    #[test]
    fn malformed_integrity_tables_are_refused_without_panicking() {
        let lock = fixture("1.2.2");
        let array_of_tables = lock.replace("[metadata.files]", "[[metadata.files]]");
        let scalar = {
            let start = lock.find("[metadata.files]").unwrap();
            format!("{}files = \"oops\"\n", &lock[..start])
        };
        let missing = {
            let start = lock.find("\n[metadata.files]").unwrap();
            lock[..start + 1].to_string()
        };
        let metadata_array = lock.replace("[metadata]", "[[metadata]]");
        for (label, text) in [
            ("array-of-tables", array_of_tables),
            ("scalar", scalar),
            ("missing", missing),
            ("metadata-array", metadata_array),
        ] {
            match hosted(&text) {
                Err(err) => assert!(!err.is_empty(), "{label}"),
                Ok(other) => panic!("{label}: expected a refusal, got {other:?}"),
            }
            // The vendored (file-source) spelling takes the same guarded path.
            match rewrite_poetry_lock(
                &text,
                "urllib3",
                "1.26.18",
                "file",
                ".socket/vendor/pypi/x/urllib3-1.26.18-py2.py3-none-any.whl",
                WHEEL,
                &sha(),
            ) {
                Err(err) => assert!(!err.is_empty(), "{label}"),
                Ok(other) => panic!("{label}: expected a refusal, got {other:?}"),
            }
        }
    }

    /// Poetry bumps the 2.x minor additively; the vendored loader accepts a
    /// newer minor with an advisory, so the shared rewriter must too — the
    /// same lock must get the same treatment on every path (LF vendored, CRLF
    /// vendored, hosted).
    #[test]
    fn newer_2x_minor_is_rewritten_like_2_1() {
        let lock = fixture("2.4.3").replace("lock-version = \"2.1\"", "lock-version = \"2.2\"");
        let rewritten = hosted(&lock).unwrap().unwrap();
        assert!(rewritten.contains(URL));
        assert!(rewritten.contains("lock-version = \"2.2\""));
        for bad in ["3.0", "2", "2.x", "1.2"] {
            let lock = fixture("2.4.3").replace(
                "lock-version = \"2.1\"",
                &format!("lock-version = \"{bad}\""),
            );
            let err = hosted(&lock).unwrap_err();
            assert!(err.contains(bad), "{bad}: {err}");
        }
    }

    /// An earlier hosted redirect of the same wheel (rotated grant token,
    /// republished patch) is superseded in place; a foreign url source is not.
    #[test]
    fn prior_hosted_url_is_superseded_but_foreign_sources_are_refused() {
        let lock = fixture("2.4.3");
        let first = hosted(&lock).unwrap().unwrap();
        let rotated = URL.replace("7e52b8b6", "00000000");
        let second =
            rewrite_poetry_lock(&first, "urllib3", "1.26.18", "url", &rotated, WHEEL, &sha())
                .unwrap()
                .unwrap();
        assert!(second.contains(&rotated) && !second.contains(URL));
        // Idempotent: the same URL again changes nothing.
        assert_eq!(hosted(&first).unwrap().unwrap(), first);
        // Poetry 1.0 carries a `#sha256=…&` fragment; the comparison ignores it.
        let lock10 = fixture("1.0.10");
        let first10 = hosted(&lock10).unwrap().unwrap();
        let second10 = rewrite_poetry_lock(
            &first10,
            "urllib3",
            "1.26.18",
            "url",
            &rotated,
            WHEEL,
            &"b".repeat(64),
        )
        .unwrap()
        .unwrap();
        assert!(second10.contains(&format!("{rotated}#sha256={}&", "b".repeat(64))));
        // A user's own url source on another origin stays untouched.
        let foreign = first.replace("https://patch.socket.dev", "https://mirror.example");
        assert!(hosted(&foreign)
            .unwrap_err()
            .contains("existing Poetry source"));
        // A vendored file source is never taken over by the hosted path here.
        let vendored = rewrite_poetry_lock(
            &lock,
            "urllib3",
            "1.26.18",
            "file",
            ".socket/vendor/pypi/x/urllib3-1.26.18-py2.py3-none-any.whl",
            WHEEL,
            &sha(),
        )
        .unwrap()
        .unwrap();
        assert!(hosted(&vendored)
            .unwrap_err()
            .contains("existing Poetry source"));
    }

    #[test]
    fn sha256_is_written_lowercase() {
        let lock = fixture("2.4.3");
        let upper = "A".repeat(64);
        let rewritten = rewrite_poetry_lock(&lock, "urllib3", "1.26.18", "url", URL, WHEEL, &upper)
            .unwrap()
            .unwrap();
        assert!(rewritten.contains(&format!("sha256:{}", "a".repeat(64))));
        assert!(!rewritten.contains(&upper));
    }

    /// The `[metadata.files]` fragment is anchored at its line break, so a
    /// sibling whose key ends in the same characters and holds the same value
    /// cannot make the splice ambiguous.
    #[test]
    fn suffix_named_sibling_with_identical_integrity_does_not_refuse() {
        let lock = fixture("1.2.2");
        let files_entry = {
            let start = lock.find("urllib3 = [\n").unwrap();
            let end = lock[start..].find("\n]\n").unwrap() + start + 3;
            lock[start..end].to_string()
        };
        let sibling = files_entry.replacen("urllib3 = [", "pyurllib3 = [", 1);
        let lock = format!("{lock}{sibling}");
        let rewritten = hosted(&lock).unwrap().unwrap();
        assert!(rewritten.contains(URL));
        assert!(
            rewritten.contains(&sibling),
            "sibling entry must survive verbatim"
        );
        let edits = poetry_lock_edits(&lock, &rewritten, "urllib3").unwrap();
        assert_eq!(edits.len(), 2);
        assert!(edits[1].0.starts_with('\n'));
    }

    /// The package fragment ends with the NEXT top-level header, so the
    /// pristine fragment is never a prefix of the rewritten one (the source
    /// block sits between the unit and that header).
    #[test]
    fn package_fragment_carries_its_boundary_header() {
        for version in ["1.0.10", "1.2.2", "2.4.3"] {
            let lock = fixture(version);
            let rewritten = hosted(&lock).unwrap().unwrap();
            let edits = poetry_lock_edits(&lock, &rewritten, "urllib3").unwrap();
            let (original, new) = &edits[0];
            assert!(
                original.ends_with("[metadata]") || original.ends_with("[extras]"),
                "{version}: {original:?}"
            );
            assert!(new.ends_with("[metadata]") || new.ends_with("[extras]"));
            assert!(
                !new.contains(original.as_str()),
                "{version}: pristine must not be a prefix of new"
            );
            // A relock that keeps `[package.source]` but drops the inserted
            // `files` line must NOT contain the pristine fragment either.
            let drifted: String = rewritten
                .lines()
                .filter(|l| !l.starts_with("files = [{ file"))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(!drifted.contains(original.as_str()), "{version}");
        }
        // Two adjacent packages: the first fragment ends with the second's
        // header, the second starts with it; both splice independently.
        let lock = fixture("2.4.3");
        let mut doc: DocumentMut = lock.parse().unwrap();
        let mut second = doc["package"]
            .as_array_of_tables()
            .unwrap()
            .get(0)
            .unwrap()
            .clone();
        second["name"] = value("six");
        second["version"] = value("1.16.0");
        second.set_position(None);
        second.remove("extras");
        doc["package"]
            .as_array_of_tables_mut()
            .unwrap()
            .push(second);
        let two = doc.to_string();
        let first = hosted(&two).unwrap().unwrap();
        let edits = poetry_lock_edits(&two, &first, "urllib3").unwrap();
        assert!(edits[0].0.ends_with("[[package]]"), "{:?}", edits[0].0);
        assert_eq!(two.matches(edits[0].0.as_str()).count(), 1);
    }

    #[test]
    fn absent_or_other_version_yields_none_not_error() {
        let lock = fixture("2.4.3");
        assert_eq!(
            rewrite_poetry_lock(
                &lock,
                "six",
                "1.16.0",
                "url",
                &URL.replace("urllib3", "six").replace("1.26.18", "1.16.0"),
                "six-1.16.0-py2.py3-none-any.whl",
                &sha()
            )
            .unwrap(),
            None
        );
        assert_eq!(
            rewrite_poetry_lock(
                &lock,
                "urllib3",
                "1.26.17",
                "url",
                &URL.replace("1.26.18", "1.26.17"),
                "urllib3-1.26.17-py2.py3-none-any.whl",
                &sha()
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn generated_by_header_is_parsed_when_present() {
        assert_eq!(generated_by_version(&fixture("1.8.5")), Some((1, 8)));
        assert_eq!(generated_by_version(&fixture("2.4.3")), Some((2, 4)));
        assert_eq!(generated_by_version(&fixture("1.3.2")), None);
        assert_eq!(generated_by_version(&fixture("1.2.2")), None);
    }

    /// The edits a rewrite hands back are exactly `poetry_lock_edits` of its
    /// input and output — whether reused from the rewrite or re-derived.
    #[test]
    fn rewrite_edits_equal_poetry_lock_edits() {
        for version in [
            "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.8.5", "2.0.1", "2.4.3",
        ] {
            for crlf in [false, true] {
                let mut text = fixture(version);
                if crlf {
                    text = text.replace('\n', "\r\n");
                }
                let rewrite = rewrite_poetry_lock_with_edits(
                    &text,
                    "urllib3",
                    "1.26.18",
                    "file",
                    ".socket/vendor/pypi/x/urllib3-1.26.18-py2.py3-none-any.whl",
                    WHEEL,
                    &sha(),
                )
                .unwrap()
                .unwrap();
                let want = poetry_lock_edits(&text, &rewrite.text, "urllib3");
                assert_eq!(rewrite.edits(), want, "{version} crlf={crlf}");
                let rederived = PoetryLockRewrite {
                    known_edits: None,
                    ..rewrite
                };
                assert_eq!(rederived.edits(), want, "{version} crlf={crlf} re-derived");
            }
        }
    }

    /// When the splice does not reproduce the serialized document (a mixed
    /// line-ending lock: the serializer rewrites every line to CRLF, the
    /// splice leaves the untouched LF lines alone), the rewrite's own edits
    /// are not kept and `edits()` re-derives them against the output.
    #[test]
    fn rewrite_edits_are_rederived_when_the_splice_differs_from_the_document() {
        for version in ["0.12.17", "1.0.10", "1.2.2", "2.4.3"] {
            let crlf = fixture(version).replace('\n', "\r\n");
            // `[metadata] content-hash` is in no fragment of the package.
            let hash = crlf.find("content-hash").unwrap();
            let eol = hash + crlf[hash..].find("\r\n").unwrap();
            let text = format!("{}\n{}", &crlf[..eol], &crlf[eol + 2..]);
            let rewrite = rewrite_poetry_lock_with_edits(
                &text,
                "urllib3",
                "1.26.18",
                "file",
                ".socket/vendor/pypi/x/urllib3-1.26.18-py2.py3-none-any.whl",
                WHEEL,
                &sha(),
            )
            .unwrap()
            .unwrap();
            assert!(
                rewrite.known_edits.is_none(),
                "{version}: splice must differ"
            );
            assert_eq!(
                rewrite.edits(),
                poetry_lock_edits(&text, &rewrite.text, "urllib3"),
                "{version}"
            );
        }
    }
}

#[cfg(test)]
mod parse_reuse_equivalence_tests {
    //! The single-parse rewrite ([`rewrite_poetry_lock_in`], reusing the
    //! previous rewrite's parsed output): verdicts, texts and edits at every
    //! step of a dep sequence, on every lock generation, LF and CRLF, with
    //! refusals and re-runs in between, pinned by golden (blessed against
    //! #257's fresh-parse rewrite).
    use super::*;

    const VERSIONS: &[&str] = &[
        "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.5.1", "1.6.1", "1.7.1",
        "1.8.5", "2.0.1", "2.1.4", "2.2.1", "2.3.4", "2.4.3",
    ];
    const SHA: &str = "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07";

    /// The native fixture grown to `extra` more packages (clones of its
    /// urllib3 unit, with their legacy integrity entries), one of them
    /// forked into two versions.
    fn grown(version: &str, extra: usize) -> String {
        let lock = std::fs::read_to_string(format!(
            "{}/tests/fixtures/poetry/{version}/poetry.lock",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
        .replace("\r\n", "\n");
        let meta = lock.find("\n[metadata]").unwrap();
        let first = lock.find("[[package]]").unwrap();
        let unit = &lock[first..meta];
        let mut out = lock[..meta].to_string();
        for i in 0..extra {
            out.push('\n');
            out.push_str(&unit.replace("name = \"urllib3\"", &format!("name = \"pkg{i}\"")));
        }
        out.push('\n');
        out.push_str(&unit.replace("name = \"urllib3\"", "name = \"forked\""));
        out.push('\n');
        out.push_str(
            &unit
                .replace("name = \"urllib3\"", "name = \"forked\"")
                .replace("version = \"1.26.18\"", "version = \"2.0.0\""),
        );
        let mut tail = lock[meta..].to_string();
        let entries: String = (0..extra).map(|i| format!("\npkg{i} = []")).collect();
        tail = tail.replacen("\nurllib3 = []", &format!("\nurllib3 = []{entries}"), 1);
        out + &tail
    }

    type Step<'a> = (&'a str, &'a str, &'a str, String);

    fn steps(extra: usize) -> Vec<Step<'static>> {
        let url = |name: &str, tag: &str| {
            format!("https://patch.socket.dev/patch/pypi/{name}/{tag}/{name}-1.26.18-py2.py3-none-any.whl")
        };
        let mut out: Vec<Step> = vec![("urllib3", "1.26.18", "url", url("urllib3", "a"))];
        let names: &[&'static str] = &["pkg0", "pkg1", "pkg2", "pkg3"];
        for name in names.iter().take(extra) {
            out.push((name, "1.26.18", "url", url(name, "a")));
        }
        out.push(("absent", "1.26.18", "url", url("absent", "a"))); // not found
        out.push(("forked", "1.26.18", "url", url("forked", "a"))); // refused
        out.push(("urllib3", "9.9.9", "url", url("urllib3", "a"))); // wheel mismatch
        out.push(("urllib3", "1.26.18", "url", url("urllib3", "a"))); // re-run
        out.push(("urllib3", "1.26.18", "url", url("urllib3", "rotated"))); // superseded
        out.push((
            "urllib3",
            "1.26.18",
            "file",
            ".socket/vendor/x/urllib3-1.26.18-py2.py3-none-any.whl".into(),
        )); // foreign source
        if extra > 0 {
            out.push((
                "pkg0",
                "1.26.18",
                "file",
                ".socket/vendor/y/pkg0-1.26.18-py2.py3-none-any.whl".into(),
            ));
        }
        out
    }

    #[test]
    fn reused_parse_matches_golden() {
        let mut golden = crate::golden::Golden::new(
            "poetry_lock_reused_parse",
            "One rewrite step over a grown poetry.lock: the text and edits, none, or the refusal.",
        );
        let mut landed = 0;
        for version in VERSIONS {
            for extra in [0, 2, 4] {
                for crlf in [false, true] {
                    let mut lock = grown(version, extra);
                    if crlf {
                        lock = lock.replace('\n', "\r\n");
                    }
                    let mut got_text = lock;
                    let mut parse = PoetryLockParse::default();
                    for (name, version, source_type, url) in steps(extra).iter() {
                        let filename = url.rsplit('/').next().unwrap();
                        let got = rewrite_poetry_lock_in(
                            &mut parse,
                            &got_text,
                            name,
                            version,
                            source_type,
                            url,
                            filename,
                            SHA,
                        );
                        golden.next(
                            &(&got_text, name, version, source_type, url),
                            &format!(
                                "{:?}",
                                got.as_ref()
                                    .map(|r| r.as_ref().map(|r| (&r.text, r.edits())))
                            ),
                        );
                        if let Ok(Some(g)) = got {
                            landed += 1;
                            got_text = g.text;
                        }
                    }
                }
            }
        }
        assert!(landed > 200, "only {landed} rewrites landed");
        golden.finish();
    }

    /// A parse is reused only for byte-identical text: an external edit
    /// between two calls is parsed afresh.
    #[test]
    fn reused_parse_misses_on_changed_text() {
        let lock = grown("2.4.3", 2);
        let url = "https://patch.socket.dev/patch/pypi/pkg0/a/pkg0-1.26.18-py2.py3-none-any.whl";
        let mut parse = PoetryLockParse::default();
        let first = rewrite_poetry_lock_in(
            &mut parse,
            &lock,
            "pkg0",
            "1.26.18",
            "url",
            url,
            "pkg0-1.26.18-py2.py3-none-any.whl",
            SHA,
        )
        .unwrap()
        .unwrap();
        // pkg1 dropped from the lock behind the parse's back.
        let edited = first.text.replace("name = \"pkg1\"", "name = \"gone\"");
        let url1 = "https://patch.socket.dev/patch/pypi/pkg1/a/pkg1-1.26.18-py2.py3-none-any.whl";
        let got = rewrite_poetry_lock_in(
            &mut parse,
            &edited,
            "pkg1",
            "1.26.18",
            "url",
            url1,
            "pkg1-1.26.18-py2.py3-none-any.whl",
            SHA,
        );
        assert!(matches!(got, Ok(None)), "the stale parse was reused");
    }
}

#[cfg(test)]
mod batch_equivalence_tests {
    //! [`rewrite_poetry_lock_all`]'s one-render batch against the
    //! step-by-step rewrite it replaces (#760): whenever the batch answers,
    //! its text and every dep's step are the step-by-step ones.
    use super::*;

    const VERSIONS: &[&str] = &[
        "0.12.17", "1.0.10", "1.1.15", "1.2.2", "1.3.2", "1.4.2", "1.5.1", "1.6.1", "1.7.1",
        "1.8.5", "2.0.1", "2.1.4", "2.2.1", "2.3.4", "2.4.3",
    ];
    const SHA: &str = "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07";

    /// The native fixture with `extra` clones of its urllib3 unit, adjacent
    /// to it, each with its own legacy integrity entry.
    fn grown(version: &str, extra: usize) -> String {
        let lock = std::fs::read_to_string(format!(
            "{}/tests/fixtures/poetry/{version}/poetry.lock",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
        .replace("\r\n", "\n");
        let meta = lock.find("\n[metadata]").unwrap();
        let first = lock.find("[[package]]").unwrap();
        let unit = &lock[first..meta];
        let mut out = lock[..meta].to_string();
        for i in 0..extra {
            out.push('\n');
            out.push_str(&unit.replace("name = \"urllib3\"", &format!("name = \"pkg{i}\"")));
        }
        let mut tail = lock[meta..].to_string();
        for key in ["\nurllib3 = [\n", "\nurllib3 = []"] {
            if let Some(start) = tail.find(key) {
                let end = start + tail[start + 1..].find('\n').unwrap() + 1;
                let end = if key.ends_with("[\n") {
                    start + tail[start..].find("\n]").unwrap() + 2
                } else {
                    end
                };
                let entry = tail[start..end].to_string();
                let clones: String = (0..extra)
                    .map(|i| entry.replacen("urllib3 =", &format!("pkg{i} ="), 1))
                    .collect();
                tail.insert_str(end, &clones);
                break;
            }
        }
        out + &tail
    }

    struct Dep {
        name: String,
        version: &'static str,
        source_type: &'static str,
        url: String,
        sha256: String,
    }

    fn dep(name: &str, version: &'static str, tag: &str) -> Dep {
        Dep {
            name: name.into(),
            version,
            source_type: "url",
            url: format!(
                "https://patch.socket.dev/patch/pypi/{name}/{tag}/{name}-{version}-py2.py3-none-any.whl"
            ),
            sha256: SHA.into(),
        }
    }

    fn lock_deps(deps: &[Dep]) -> Vec<PoetryLockDep<'_>> {
        deps.iter()
            .map(|dep| PoetryLockDep {
                name: &dep.name,
                version: dep.version,
                source_type: dep.source_type,
                source_url: &dep.url,
                filename: dep.url.rsplit('/').next().unwrap(),
                sha256: &dep.sha256,
            })
            .collect()
    }

    /// The dep mixes run over each lock: every package (adjacent units),
    /// every other one, reversed, interleaved with refusals and not-found
    /// verdicts, and a package rewritten twice (which the batch hands back).
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
        for (n, dep) in all().enumerate() {
            mixed.push(dep);
            if n == 1 {
                mixed.push(Dep {
                    sha256: "not-a-sha".into(),
                    ..super::batch_equivalence_tests::dep("pkg0", "1.26.18", "b")
                });
                mixed.push(Dep {
                    source_type: "file",
                    url: ".socket/vendor/x/pkg0-1.26.18-py2.py3-none-any.whl".into(),
                    ..super::batch_equivalence_tests::dep("pkg0", "1.26.18", "a")
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
        let mut cases = 0;
        for version in VERSIONS {
            for extra in [0, 1, 4] {
                for style in ["lf", "crlf", "mixed"] {
                    let mut lock = grown(version, extra);
                    match style {
                        "crlf" => lock = lock.replace('\n', "\r\n"),
                        "mixed" => lock = lock.replacen('\n', "\r\n", 1),
                        _ => {}
                    }
                    for (mix, (deps, batchable)) in mixes(extra).into_iter().enumerate() {
                        let deps = lock_deps(&deps);
                        let what = format!("{version} extra={extra} {style} mix={mix}");
                        let steps = rewrite_poetry_lock_steps(&lock, &deps);
                        // And again over the output: the idempotent re-scan.
                        for (rerun, text) in
                            [lock.clone(), steps.text.clone()].into_iter().enumerate()
                        {
                            cases += 1;
                            let steps = rewrite_poetry_lock_steps(&text, &deps);
                            let batch = rewrite_poetry_lock_batch(&text, &deps);
                            if let Some(batch) = &batch {
                                batched += 1;
                                assert_eq!(batch, &steps, "{what}");
                            }
                            assert_eq!(rewrite_poetry_lock_all(&text, &deps), steps, "{what}");
                            // Poetry 0.12 refuses every URL source: nothing to
                            // render, so the batch answers.
                            if style == "mixed" {
                                // (The first rewrite may respell the lone CRLF
                                // line, leaving the re-run's lock all LF.)
                                assert!(
                                    rerun == 1 || batch.is_none(),
                                    "{what}: the batch must hand back"
                                );
                            } else if version.starts_with("0.") {
                                assert!(batch.is_some(), "{what}: nothing rewritten");
                            } else if !batchable {
                                assert!(batch.is_none(), "{what}: the batch must hand back");
                            } else {
                                assert!(batch.is_some(), "{what}: the batch must answer");
                            }
                        }
                    }
                }
            }
        }
        assert!(
            batched * 2 > cases,
            "only {batched} of {cases} cases batched"
        );
    }
}
