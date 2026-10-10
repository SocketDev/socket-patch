//! Poetry and PDM upstream restores.
//!
//! * `poetry.lock` (`utils::poetry_lock::rewrite_poetry_lock`): the hosted
//!   rewrite adds `[package.source] type = "url"` (lock 1.0 also a
//!   `reference = ""` and a `#sha256=…&` url fragment) and replaces the
//!   package's files with the patched wheel — `files = [...]` on lock 2.x,
//!   `[metadata.files].<name>` on 1.0/1.1, where it ALSO adds a package-level
//!   `files` no Poetry 1.x lock carries. The restore drops the source table
//!   (a package without one is a PyPI package — the rewriter refuses every
//!   pre-existing source) and re-derives every release file from PyPI.
//!   A 1.0/1.1 `[metadata.files]` entry is either every release file (a
//!   lock written while PyPI's JSON API still fed old Poetry its files) or
//!   `[]` (what Poetry 1.0/1.1 record against today's PyPI), and the
//!   registry cannot say which. The rewriter keeps that bit in the patched
//!   entry's layout (`utils::poetry_lock::legacy_files_entry`): one file
//!   per line, as Poetry renders a non-empty entry, when the original listed
//!   files; inline when it was `[]`. The restore reads the layout back and
//!   writes the full release list or `[]`, so every generation round-trips
//!   byte-exactly.
//! * `pdm.lock` (`utils::pdm_lock::rewrite_pdm_lock`): the rewrite adds a
//!   package `url` and replaces its files, inline or in the lock_version 2
//!   `[metadata.files]."<name>[extras] <version>"` table, in every extras
//!   variant. A lock without `cross_platform` keeps only the files its
//!   targets install; which ones is re-derivable only when every wheel is
//!   pure Python 3 ([`super::pypi::universal_release`]), otherwise the pin
//!   is refused.
//!
//! Both edit a parsed `toml_edit` document, so every byte outside the
//! restored package entries is the file's own.

use std::collections::BTreeSet;

use toml_edit::{DocumentMut, Item};

use super::client::PypiFile;
use super::pypi::{
    fetch_release_files, is_pypi_simple, multiline_toml_array, pin_of, toml_quote, toml_value,
    universal_release,
};
use super::{by_uuid, read_or_refuse, refuse_all_in, Ctx, FormatResult, HostedPin, View};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::poetry_lock::is_multiline_array;
use crate::utils::python_lock::preserve_line_endings;

/// One hosted package entry of a TOML lock.
struct LockHit {
    /// Index into the lock's `[[package]]` array.
    index: usize,
    uuid: String,
    name: String,
    version: String,
}

/// The `files` array value Poetry / PDM write for `release`: one
/// `{<key> = …, hash = "sha256:…"}` per file.
fn files_value(release: &[PypiFile], by_url: bool) -> Option<toml_edit::Value> {
    let key = if by_url { "url" } else { "file" };
    let mut located: Vec<(&str, &PypiFile)> = release
        .iter()
        .map(|f| {
            (
                if by_url {
                    f.url.as_str()
                } else {
                    f.filename.as_str()
                },
                f,
            )
        })
        .collect();
    // PDM orders each entry's files by the location it writes: a `static_urls`
    // lock by URL (so an sdist under `0c/…` precedes a wheel under `b0/…`),
    // a plain lock by filename.
    located.sort_by(|a, b| a.0.cmp(b.0));
    let entries: Vec<String> = located
        .iter()
        .map(|(location, f)| {
            format!(
                "{{{key} = {}, hash = {}}}",
                toml_quote(location),
                toml_quote(&format!("sha256:{}", f.sha256))
            )
        })
        .collect();
    toml_value(&multiline_toml_array(&entries))
}

/// Replace `key`'s value in place (keeping the key and its position), or
/// insert it.
fn set_value(table: &mut dyn toml_edit::TableLike, key: &str, value: toml_edit::Value) {
    match table.get_mut(key) {
        Some(item) => *item = Item::Value(value),
        None => {
            table.insert(key, Item::Value(value));
        }
    }
}

/// Parse `rel`'s lock; a malformed one refuses every pin wired in it.
async fn parse_lock(
    view: &mut View<'_>,
    rel: &str,
    pins: &std::collections::BTreeMap<&str, &HostedPin>,
    result: &mut FormatResult,
) -> Option<(String, DocumentMut)> {
    let text = read_or_refuse(view, rel, pins, result).await?;
    match text.parse::<DocumentMut>() {
        Ok(doc) => Some((text, doc)),
        Err(e) => {
            refuse_all_in(pins, rel, result, format!("{rel} is not valid TOML: {e}"));
            None
        }
    }
}

/// The hosted entries of a lock's `[[package]]` array: `location` reads a
/// package's install location (Poetry's `[package.source]` url, PDM's
/// `url`). An entry naming another package or version than its pin
/// refuses it.
fn lock_hits(
    doc: &DocumentMut,
    rel: &str,
    pins: &std::collections::BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    location: impl Fn(&toml_edit::Table) -> Option<&str>,
    result: &mut FormatResult,
) -> Vec<LockHit> {
    let mut hits = Vec::new();
    let Some(packages) = doc.get("package").and_then(Item::as_array_of_tables) else {
        return hits;
    };
    for (index, package) in packages.iter().enumerate() {
        let Some(pin) = location(package).and_then(|l| pin_of(l, pins, ctx)) else {
            continue;
        };
        let name = package.get("name").and_then(Item::as_str).unwrap_or("");
        let version = package.get("version").and_then(Item::as_str).unwrap_or("");
        let agrees = pin.name_version().is_some_and(|(n, v)| {
            canonicalize_pypi_name(&n) == canonicalize_pypi_name(name) && v == version
        });
        if !agrees {
            result.refuse(
                &pin.uuid,
                format!(
                    "{rel}: the entry wiring it names {name:?} {version:?}, not {}",
                    pin.purl
                ),
            );
            continue;
        }
        hits.push(LockHit {
            index,
            uuid: pin.uuid.clone(),
            name: name.to_string(),
            version: version.to_string(),
        });
    }
    hits
}

fn wanted(hits: &[LockHit], result: &FormatResult) -> BTreeSet<(String, String, String)> {
    hits.iter()
        .filter(|h| !result.refused.contains_key(&h.uuid))
        .map(|h| {
            (
                h.uuid.clone(),
                canonicalize_pypi_name(&h.name),
                h.version.clone(),
            )
        })
        .collect()
}

/// Write `doc` back when any hit survived, marking the survivors handled.
fn finish(
    view: &mut View<'_>,
    rel: &str,
    text: &str,
    doc: &DocumentMut,
    restored: BTreeSet<String>,
    result: &mut FormatResult,
) {
    if restored.iter().all(|u| result.refused.contains_key(u)) {
        return;
    }
    view.write(rel, preserve_line_endings(text, doc.to_string()));
    result.handled.extend(restored);
}

// ── poetry.lock ──────────────────────────────────────────────────────────────

pub(crate) async fn restore_poetry(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some((text, mut doc)) = parse_lock(view, rel, &pins, &mut result).await else {
            continue;
        };
        let hits = lock_hits(
            &doc,
            rel,
            &pins,
            ctx,
            |package| {
                let source = package.get("source")?;
                (source.get("type").and_then(Item::as_str) == Some("url"))
                    .then(|| source.get("url").and_then(Item::as_str))
                    .flatten()
            },
            &mut result,
        );
        if hits.is_empty() {
            continue;
        }
        let format = match crate::utils::poetry_lock::lock_version(&doc) {
            Ok("0") => Err("Poetry 0.12 locks (format \"0\") ignore url sources".to_string()),
            Ok(format) => Ok(format.to_string()),
            Err(e) => Err(e),
        };
        let format = match format {
            Ok(format) => format,
            Err(why) => {
                for hit in &hits {
                    result.refuse(&hit.uuid, format!("{rel}: {why}"));
                }
                continue;
            }
        };
        let released = fetch_release_files(&wanted(&hits, &result), ctx, &mut result).await;
        let legacy = !format.starts_with('2');
        // Poetry 1.x locks keep files in `[metadata.files]` only; the
        // package-level copy is the rewriter's unless a package it never
        // touched (no source table) has one too.
        let siblings_carry_files = doc
            .get("package")
            .and_then(Item::as_array_of_tables)
            .is_some_and(|packages| {
                packages
                    .iter()
                    .any(|p| !p.contains_key("source") && p.contains_key("files"))
            });
        let mut restored = BTreeSet::new();
        for hit in &hits {
            if result.refused.contains_key(&hit.uuid) {
                continue;
            }
            let Some(release) =
                released.get(&(canonicalize_pypi_name(&hit.name), hit.version.clone()))
            else {
                continue;
            };
            let Some(value) = files_value(release, false) else {
                result.refuse(&hit.uuid, "the release file list does not render as TOML");
                continue;
            };
            if legacy {
                let canon = canonicalize_pypi_name(&hit.name);
                let table = doc
                    .get_mut("metadata")
                    .and_then(Item::as_table_like_mut)
                    .and_then(|m| m.get_mut("files"))
                    .and_then(Item::as_table_like_mut);
                let key = table.as_ref().and_then(|t| {
                    t.iter()
                        .find(|(k, _)| canonicalize_pypi_name(k) == canon)
                        .map(|(k, _)| k.to_string())
                });
                let (Some(table), Some(key)) = (table, key) else {
                    result.refuse(
                        &hit.uuid,
                        format!("{rel} has no [metadata.files] entry for {}", hit.name),
                    );
                    continue;
                };
                // The rewriter lays the patched entry out one file per line
                // only when the original listed files; an inline one
                // replaced Poetry's empty `[]`.
                let listed = table.get(&key).is_some_and(is_multiline_array);
                let entry = if listed {
                    value.clone()
                } else {
                    toml_edit::Value::Array(toml_edit::Array::new())
                };
                set_value(table, &key, entry);
            }
            let Some(package) = doc
                .get_mut("package")
                .and_then(Item::as_array_of_tables_mut)
                .and_then(|p| p.get_mut(hit.index))
            else {
                continue;
            };
            package.remove("source");
            if legacy && !siblings_carry_files {
                package.remove("files");
            } else {
                set_value(package, "files", value);
            }
            restored.insert(hit.uuid.clone());
        }
        finish(view, rel, &text, &doc, restored, &mut result);
    }
    result
}

// ── pdm.lock ─────────────────────────────────────────────────────────────────

/// The `url`s of a `static_urls` lock's file entries outside `skip` (the
/// hosted packages): inline `files` and lock_version 2 `[metadata.files]`.
fn pdm_file_urls(doc: &DocumentMut, skip: &BTreeSet<usize>) -> Vec<String> {
    fn urls_in(item: Option<&Item>, out: &mut Vec<String>) {
        let Some(files) = item.and_then(Item::as_array) else {
            return;
        };
        for file in files.iter().filter_map(|f| f.as_inline_table()) {
            if let Some(url) = file.get("url").and_then(|u| u.as_str()) {
                out.push(url.to_string());
            }
        }
    }
    let mut out = Vec::new();
    if let Some(packages) = doc.get("package").and_then(Item::as_array_of_tables) {
        for (index, package) in packages.iter().enumerate() {
            if !skip.contains(&index) {
                urls_in(package.get("files"), &mut out);
            }
        }
    }
    out
}

/// Whether `url` is one of PyPI's own file hosts.
fn is_pypi_file_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|u| {
        u.scheme() == "https"
            && matches!(
                u.host_str(),
                Some("files.pythonhosted.org" | "pypi.org" | "pypi.python.org")
            )
    })
}

/// Why a `static_urls` `pdm.lock` cannot get PyPI's file URLs back (#413):
/// such a lock records where PDM downloaded every file, and the restore
/// only knows PyPI's. When the project installs from another index — a
/// `[[tool.pdm.source]]` in its `pyproject.toml` (one named `pypi`
/// replaces PyPI; any other may have served the package), a project
/// `pypi.url` (`.pdm.toml`, then `pdm.toml`), or, failing both, the index
/// the lock's other packages were downloaded from — writing PyPI's URLs
/// would make `pdm sync` bypass that mirror (or fail where only the mirror
/// is reachable).
/// Like the uv and Pipenv restores, refuse rather than guess.
async fn pdm_static_index_refusal(
    view: &mut View<'_>,
    rel: &str,
    doc: &DocumentMut,
    hits: &[LockHit],
) -> Option<String> {
    let dir = match rel.rfind('/') {
        Some(i) => &rel[..=i],
        None => "",
    };
    let mut foreign: Vec<(String, String)> = Vec::new();
    let pyproject = format!("{dir}pyproject.toml");
    if let Ok(Some(text)) = view.read(&pyproject).await {
        if let Ok(project) = text.parse::<DocumentMut>() {
            let sources = project
                .get("tool")
                .and_then(|t| t.get("pdm"))
                .and_then(|p| p.get("source"))
                .and_then(Item::as_array_of_tables);
            for source in sources.into_iter().flatten() {
                let url = source.get("url").and_then(Item::as_str).unwrap_or("");
                if !is_pypi_simple(url) {
                    foreign.push((
                        url.to_string(),
                        format!("`[[tool.pdm.source]]` in {pyproject}"),
                    ));
                }
            }
        }
    }
    // PDM overlays the legacy `.pdm.toml` on `pdm.toml`, so the first of
    // the two that sets `pypi.url` is the project's.
    for name in [".pdm.toml", "pdm.toml"] {
        let config_rel = format!("{dir}{name}");
        let Ok(Some(text)) = view.read(&config_rel).await else {
            continue;
        };
        let Ok(config) = text.parse::<DocumentMut>() else {
            continue;
        };
        let Some(url) = config
            .get("pypi")
            .and_then(|p| p.get("url"))
            .and_then(Item::as_str)
        else {
            continue;
        };
        if !is_pypi_simple(url) {
            foreign.push((url.to_string(), format!("`pypi.url` in {config_rel}")));
        }
        break;
    }
    if foreign.is_empty() {
        let skip: BTreeSet<usize> = hits.iter().map(|h| h.index).collect();
        if let Some(url) = pdm_file_urls(doc, &skip)
            .into_iter()
            .find(|u| !is_pypi_file_url(u))
        {
            foreign.push((url, format!("another package's file in {rel}")));
        }
    }
    let (url, origin) = foreign.into_iter().next()?;
    Some(format!(
        "{rel} is a static_urls lock and the project installs from {url} ({origin}), not \
         PyPI; the restore can only re-derive PyPI's file URLs, which would make `pdm sync` \
         bypass that index, so the original URLs are not derivable"
    ))
}

pub(crate) async fn restore_pdm(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    use crate::utils::pdm_lock::{legacy_files_key, lock_version, validate_strategy};
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        let Some((text, mut doc)) = parse_lock(view, rel, &pins, &mut result).await else {
            continue;
        };
        let hits = lock_hits(
            &doc,
            rel,
            &pins,
            ctx,
            |package| package.get("url").and_then(Item::as_str),
            &mut result,
        );
        if hits.is_empty() {
            continue;
        }
        let shape = lock_version(doc.as_table()).and_then(|version| {
            let flags = validate_strategy(doc.as_table())?;
            Ok((version.to_string(), flags))
        });
        let (version, flags) = match shape {
            Ok(shape) => shape,
            Err(why) => {
                for hit in &hits {
                    result.refuse(&hit.uuid, format!("{rel}: {why}"));
                }
                continue;
            }
        };
        let static_urls = flags.iter().any(|f| f == "static_urls");
        if static_urls {
            if let Some(why) = pdm_static_index_refusal(view, rel, &doc, &hits).await {
                for hit in &hits {
                    result.refuse(&hit.uuid, why.clone());
                }
                continue;
            }
        }
        // lock_version 2 (PDM 0.x/1.x) always recorded every release file.
        let cross_platform = version == "2" || flags.iter().any(|f| f == "cross_platform");
        let released = fetch_release_files(&wanted(&hits, &result), ctx, &mut result).await;
        let mut restored = BTreeSet::new();
        for hit in &hits {
            if result.refused.contains_key(&hit.uuid) {
                continue;
            }
            let Some(release) =
                released.get(&(canonicalize_pypi_name(&hit.name), hit.version.clone()))
            else {
                continue;
            };
            if !cross_platform && !universal_release(release) {
                result.refuse(
                    &hit.uuid,
                    format!(
                        "{rel} (lock_version {version}, no cross_platform strategy) records only \
                         the files its lock targets install, and {}=={} ships platform- or \
                         interpreter-specific wheels, so which ones it kept is not derivable",
                        hit.name, hit.version
                    ),
                );
                continue;
            }
            let Some(value) = files_value(release, static_urls) else {
                result.refuse(&hit.uuid, "the release file list does not render as TOML");
                continue;
            };
            let Some(package) = doc
                .get_mut("package")
                .and_then(Item::as_array_of_tables_mut)
                .and_then(|p| p.get_mut(hit.index))
            else {
                continue;
            };
            if package.contains_key("files") {
                package.remove("url");
                set_value(package, "files", value);
            } else {
                let key = legacy_files_key(package);
                package.remove("url");
                let table = doc
                    .get_mut("metadata")
                    .and_then(Item::as_table_like_mut)
                    .and_then(|m| m.get_mut("files"))
                    .and_then(Item::as_table_like_mut);
                let (Some(table), Some(key)) = (table, key) else {
                    result.refuse(
                        &hit.uuid,
                        format!("{rel} has no [metadata.files] entry for {}", hit.name),
                    );
                    continue;
                };
                set_value(table, &key, value);
            }
            restored.insert(hit.uuid.clone());
        }
        finish(view, rel, &text, &doc, restored, &mut result);
    }
    result
}
