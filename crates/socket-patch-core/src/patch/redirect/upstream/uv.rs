//! uv upstream restore: `uv.lock`, PEP 723 script locks (`<script>.py.lock`)
//! and PEP 751 `pylock.toml` / `pylock.<name>.toml`, plus the paired
//! metadata the hosted rewrite edits (`pyproject.toml`'s `[tool.uv]`, a
//! script's PEP 723 block).
//!
//! What the hosted rewrite (`utils::python_lock` + `utils::python_script`)
//! changed, and how each piece comes back:
//!
//! * the entry's `source = { registry = R }` became `{ url = <artifact> }`
//!   (pylock: `index = R` was dropped) — R is the ONE registry every other
//!   registry package of the lock names, and must be PyPI's simple index;
//!   no sibling, or several registries, refuses. A pylock from
//!   `uv pip compile` records no `index` at all: siblings without one whose
//!   files are all on `files.pythonhosted.org` show PyPI, and the entry is
//!   restored without one too;
//! * `sdist` / `wheels` were replaced by the patched wheel (pylock: an
//!   `archive`) — re-derived from PyPI's JSON API in the artifact shape a
//!   sibling registry package shows (which of `size` / `upload-time` (or
//!   uv 0.6.15–0.6.17's `upload_time`) /
//!   `hashes` this uv release records, one wheel per line or not; pylock
//!   `upload-time`s in whole seconds unless a sibling shows a fraction). uv keeps
//!   only the wheels its `requires-python` and environments can install, so
//!   a release with any wheel that is not pure Python 3 is refused, as is a
//!   lock whose `[options]` / `[tool.uv]` filter files (`exclude-newer`,
//!   `no-binary`, `no-build`). PEP 751 allows both TOML spellings of the
//!   artifacts: uv's inline `wheels = [{ … }]`, and the standard tables
//!   `pip lock` writes (`[[packages.wheels]]` with a
//!   `[packages.wheels.hashes]` sub-table, `[packages.sdist]`); the entry
//!   comes back in its siblings' spelling. `pip lock` records only the one
//!   artifact pip selected — the wheel, or the sdist of a release with no
//!   wheel — so a pip release with several wheels is refused;
//! * `[package.metadata]` (the patched wheel's metadata) was added — removed;
//! * dependents' `{ name, source = { registry = R } }` references were
//!   repointed at the url — pointed back;
//! * the root package's `requires-dist` / `requires-dev` entries, the
//!   `[manifest]` `constraints` / `build-constraints` / `requirements` and
//!   `overrides` entries lost their `specifier` for the url — re-derived
//!   from the paired metadata's declarations in uv's spelling (a
//!   multi-clause specifier only when another entry of the lock shows how
//!   this uv joins clauses). The declaration is the one uv lowered the
//!   entry from: PEP 735 `include-group` members are expanded, and when one
//!   name has several specifiers the entry's marker picks one (its
//!   `extra == '<x>'` terms name the extra, the rest is the declaration's
//!   own marker). An `overrides` entry the rewrite added for
//!   a transitive dependency is removed with its `override-dependencies`
//!   line — the one under the rewrite's ownership comment
//!   (`python_script::HOSTED_OVERRIDE_MARK`); a user's own pin of the same
//!   release has none and is kept (#411);
//! * the metadata's `[tool.uv.sources].<name> = { url }` is removed.
//!
//! uv 0.2 `[[distribution]]` locks are refused (their artifact grammar
//! changed across 0.2.x releases).

use std::collections::{BTreeMap, BTreeSet};

use toml_edit::{DocumentMut, Item, TableLike, Value};

use super::client::PypiFile;
use super::pypi::{
    by_uuid, fetch_release_files, is_pypi_simple, pin_of, read_or_refuse, refuse_all_in,
    toml_quote, toml_value, universal_release,
};
use super::{Ctx, FormatResult, HostedPin, View};
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::python_lock::{paired_metadata_rel, preserve_line_endings, UvSource};
use crate::vendor::common::pep508_name;

/// One hosted entry of a lock.
struct Hit {
    index: usize,
    uuid: String,
    /// PEP 503 canonical name.
    name: String,
    version: String,
}

/// How the lock's other registry packages record their artifacts.
struct Shape {
    /// The one registry index they name.
    registry: String,
    /// pylock: they record that registry in an `index` key (`uv export`
    /// does, `uv pip compile` does not).
    index: bool,
    /// pylock: their `upload-time`s are whole seconds (uv truncates them
    /// in pylock files; uv.lock keeps milliseconds).
    whole_seconds: bool,
    /// Artifact table keys, in order (`url`, `hash`, `size`, …).
    keys: Vec<String>,
    /// `upload-time` is a TOML datetime (pylock), not a string (uv.lock).
    datetime: bool,
    /// `wheels` puts one entry per line.
    multiline: bool,
    /// pylock: artifacts are standard tables (`[[packages.wheels]]`,
    /// `[packages.sdist]`), as `pip lock` writes them, not inline ones.
    tables: bool,
    /// With `tables`: `hashes` is a sub-table (`[packages.wheels.hashes]`).
    hash_tables: bool,
    /// pylock: the lock records only the artifact its writer selected
    /// (`created-by = "pip"`), not every file of the release.
    selected_only: bool,
    /// A sibling package's key order (pylock re-places `index` by it).
    package_keys: Vec<String>,
}

pub(crate) async fn restore(
    view: &mut View<'_>,
    pins: &[&HostedPin],
    files: &[String],
    ctx: &Ctx<'_>,
) -> FormatResult {
    let mut result = FormatResult::default();
    let pins = by_uuid(pins);
    for rel in files {
        restore_lock(view, rel, &pins, ctx, &mut result).await;
    }
    result
}

async fn restore_lock(
    view: &mut View<'_>,
    rel: &str,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) {
    let Some(text) = read_or_refuse(view, rel, pins, result).await else {
        return;
    };
    let mut doc = match text.parse::<DocumentMut>() {
        Ok(doc) => doc,
        Err(e) => {
            refuse_all_in(pins, rel, result, format!("{rel} is not valid TOML: {e}"));
            return;
        }
    };
    let (collection, pep751) = crate::utils::python_lock::lock_package_collection(&doc);
    let hits = lock_hits(&doc, collection, pep751, rel, pins, ctx, result);
    if hits.is_empty() {
        return;
    }
    let refuse_hits = |result: &mut FormatResult, why: &str| {
        for hit in &hits {
            result.refuse(&hit.uuid, format!("{rel}: {why}"));
        }
    };
    if collection == "distribution" {
        return refuse_hits(
            result,
            "uv 0.2 `[[distribution]]` locks changed their artifact grammar across releases; \
             which one this lock follows is not derivable",
        );
    }
    let version_ok = if pep751 {
        doc.get("lock-version").and_then(Item::as_str) == Some("1.0")
    } else {
        doc.get("version").and_then(Item::as_integer) == Some(1)
    };
    if !version_ok {
        return refuse_hits(result, "unsupported lock version");
    }
    if doc
        .get("options")
        .and_then(Item::as_table_like)
        .is_some_and(|o| o.contains_key("exclude-newer"))
    {
        return refuse_hits(
            result,
            "the lock's `exclude-newer` option filters release files by upload time",
        );
    }
    let shape = match lock_shape(&doc, collection, pep751, &hits) {
        Ok(shape) => shape,
        Err(why) => return refuse_hits(result, &why),
    };

    // The paired metadata (a project lock with no pyproject beside it was
    // edited alone).
    let metadata_rel = if pep751 {
        None
    } else {
        paired_metadata_rel(rel.rsplit('/').next().unwrap_or(rel)).map(|leaf| {
            match rel.rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/{leaf}"),
                None => leaf.to_string(),
            }
        })
    };
    let script = crate::utils::python_lock::is_script_lock_name(rel);
    let mut metadata = match &metadata_rel {
        Some(m) => match load_metadata(view, m, script).await {
            Ok(meta) => meta,
            Err(why) => return refuse_hits(result, &why),
        },
        None => None,
    };
    if let Some(meta) = &metadata {
        let uv = tool_uv(&meta.doc);
        if uv.is_some_and(|uv| {
            uv.iter()
                .any(|(k, _)| k.starts_with("no-binary") || k.starts_with("no-build"))
        }) {
            return refuse_hits(
                result,
                "the project's uv `no-binary` / `no-build` settings change which artifacts \
                 the lock records",
            );
        }
    }

    let wanted = hits
        .iter()
        .filter(|h| !result.refused.contains_key(&h.uuid))
        .map(|h| (h.uuid.clone(), h.name.clone(), h.version.clone()))
        .collect();
    let released = fetch_release_files(&wanted, ctx, result).await;
    let styles = SpecStyle::learn(&doc, metadata.as_ref());

    let mut restored: BTreeSet<String> = BTreeSet::new();
    for hit in &hits {
        if result.refused.contains_key(&hit.uuid) {
            continue;
        }
        let Some(release) = released.get(&(hit.name.clone(), hit.version.clone())) else {
            continue;
        };
        let artifacts = match render_artifacts(release, &shape) {
            Ok(artifacts) => artifacts,
            Err(why) => {
                result.refuse(
                    &hit.uuid,
                    format!("{rel}: {}=={}: {why}", hit.name, hit.version),
                );
                continue;
            }
        };
        // A refused hit leaves the lock as it was: its entry and every
        // requirement array are restored together or not at all.
        let before = doc.clone();
        let restore = if pep751 {
            restore_pylock_entry(&mut doc, hit, &shape, artifacts)
        } else {
            restore_uv_entry(&mut doc, hit, &shape, artifacts, ctx)
                .and_then(|()| restore_requirements(&mut doc, hit, metadata.as_ref(), &styles, ctx))
        };
        if let Err(why) = restore {
            doc = before;
            result.refuse(&hit.uuid, format!("{rel}: {why}"));
            continue;
        }
        if let Some(meta) = metadata.as_mut() {
            if restore_metadata(meta, hit, ctx) {
                result.warnings.push((
                    "upstream_uv_override_removed",
                    format!(
                        "{}: removed the `{}=={}` override-dependencies entry the hosted run \
                         adds for a transitive dependency",
                        meta.rel, hit.name, hit.version
                    ),
                ));
            }
        }
        restored.insert(hit.uuid.clone());
    }
    if restored.is_empty() {
        return;
    }
    view.write(rel, preserve_line_endings(&text, doc.to_string()));
    if let Some(meta) = metadata {
        if let Some(next) = meta.render() {
            if next != meta.text {
                view.write(&meta.rel, next);
            }
        }
    }
    result.handled.extend(restored);
}

/// The hosted entries of the lock; an entry naming another package or
/// version than its pin refuses it.
fn lock_hits(
    doc: &DocumentMut,
    collection: &str,
    pep751: bool,
    rel: &str,
    pins: &BTreeMap<&str, &HostedPin>,
    ctx: &Ctx<'_>,
    result: &mut FormatResult,
) -> Vec<Hit> {
    let mut hits = Vec::new();
    let Some(packages) = doc.get(collection).and_then(Item::as_array_of_tables) else {
        return hits;
    };
    for (index, package) in packages.iter().enumerate() {
        let location = if pep751 {
            package
                .get("archive")
                .and_then(Item::as_table_like)
                .and_then(|a| a.get("url"))
                .and_then(Item::as_str)
        } else {
            UvSource::of(package).and_then(UvSource::url)
        };
        let Some(pin) = location.and_then(|l| pin_of(l, pins, ctx)) else {
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
        hits.push(Hit {
            index,
            uuid: pin.uuid.clone(),
            name: canonicalize_pypi_name(name),
            version: version.to_string(),
        });
    }
    hits
}

/// The registry a sibling package resolves from.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SiblingRegistry<'a> {
    /// Its `source = { registry }` (uv.lock) or `index` (pylock).
    Named(&'a str),
    /// A pylock entry with no `index` whose artifacts are all PyPI files.
    PypiFiles,
    /// A pylock entry with no `index` whose artifacts come from this host.
    Files(String),
}

impl SiblingRegistry<'_> {
    fn describe(&self) -> String {
        match self {
            Self::Named(r) => r.to_string(),
            Self::PypiFiles => "PyPI files with no `index`".to_string(),
            Self::Files(host) => format!("files on {host}"),
        }
    }
}

/// A package's `wheels` and `sdist` artifact tables, in either PEP 751
/// spelling: inline (`wheels = [{ … }]`, as uv writes them) or standard
/// tables (`[[packages.wheels]]` / `[packages.sdist]`, as `pip lock` does).
fn artifact_tables(package: &toml_edit::Table) -> Vec<&dyn TableLike> {
    let mut tables: Vec<&dyn TableLike> = Vec::new();
    match package.get("wheels") {
        Some(Item::Value(Value::Array(wheels))) => tables.extend(
            wheels
                .iter()
                .filter_map(Value::as_inline_table)
                .map(|t| t as &dyn TableLike),
        ),
        Some(Item::ArrayOfTables(wheels)) => {
            tables.extend(wheels.iter().map(|t| t as &dyn TableLike))
        }
        _ => {}
    }
    tables.extend(package.get("sdist").and_then(Item::as_table_like));
    tables
}

/// The lowercased `host[:port]` of `url` (never its userinfo).
fn url_host(url: &str) -> String {
    crate::utils::redact::url_host(url)
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Where a pylock entry without an `index` resolves from: PyPI when every
/// artifact is a PyPI file (what `uv pip compile` writes for the default
/// index); `None` for an entry with no registry artifacts (a `vcs`,
/// `directory` or `archive` package).
fn pylock_unindexed_registry(package: &toml_edit::Table) -> Option<SiblingRegistry<'static>> {
    let urls: Vec<&str> = artifact_tables(package)
        .into_iter()
        .filter_map(|a| a.get("url")?.as_str())
        .collect();
    let other = urls
        .iter()
        .map(|u| url_host(u))
        .find(|host| host != "files.pythonhosted.org");
    match (urls.is_empty(), other) {
        (true, _) => None,
        (false, None) => Some(SiblingRegistry::PypiFiles),
        (false, Some(host)) => Some(SiblingRegistry::Files(host)),
    }
}

/// The registry and artifact shape the lock's other registry packages show.
fn lock_shape(
    doc: &DocumentMut,
    collection: &str,
    pep751: bool,
    hits: &[Hit],
) -> Result<Shape, String> {
    let hit_indices: BTreeSet<usize> = hits.iter().map(|h| h.index).collect();
    let packages = doc
        .get(collection)
        .and_then(Item::as_array_of_tables)
        .ok_or("the lock has no package array")?;
    let mut registries: BTreeSet<SiblingRegistry> = BTreeSet::new();
    // (keys, datetime, multiline, tables, hash_tables, package_keys)
    type Learned = (Vec<String>, bool, bool, bool, bool, Vec<String>);
    let mut shape: Option<Learned> = None;
    let mut fractional_seconds = false;
    for (i, package) in packages.iter().enumerate() {
        if hit_indices.contains(&i) {
            continue;
        }
        let registry = if pep751 {
            match package.get("index").and_then(Item::as_str) {
                Some(index) => Some(SiblingRegistry::Named(index)),
                None => pylock_unindexed_registry(package),
            }
        } else {
            UvSource::of(package)
                .and_then(UvSource::registry)
                .map(SiblingRegistry::Named)
        };
        let Some(registry) = registry else {
            continue;
        };
        registries.insert(registry);
        let artifacts = artifact_tables(package);
        fractional_seconds |= artifacts.iter().any(|a| {
            upload_time_value(*a)
                .and_then(Item::as_datetime)
                .is_some_and(|t| t.to_string().contains('.'))
        });
        if shape.is_some() {
            continue;
        }
        // The first wheel, else the sdist.
        let Some(artifact) = artifacts.first() else {
            continue;
        };
        let keys: Vec<String> = artifact.iter().map(|(k, _)| k.to_string()).collect();
        let datetime = upload_time_value(*artifact).is_some_and(|v| v.as_datetime().is_some());
        let multiline = package
            .get("wheels")
            .and_then(Item::as_array)
            .is_none_or(|a| a.to_string().contains('\n'));
        let tables = match package.get("wheels") {
            Some(Item::ArrayOfTables(wheels)) => !wheels.is_empty(),
            Some(Item::Value(Value::Array(wheels))) if !wheels.is_empty() => false,
            _ => package.get("sdist").is_some_and(Item::is_table),
        };
        let hash_tables = artifact.get("hashes").is_some_and(Item::is_table);
        let package_keys = package.iter().map(|(k, _)| k.to_string()).collect();
        shape = Some((keys, datetime, multiline, tables, hash_tables, package_keys));
    }
    if registries.len() > 1 {
        return Err(format!(
            "the lock's packages come from several registries ({}); the entry's is \
             ambiguous",
            registries
                .iter()
                .map(SiblingRegistry::describe)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let (registry, index) = match registries.pop_first() {
        None => {
            return Err(
                "no sibling registry package shows the registry and artifact fields the lock \
                 records"
                    .to_string(),
            )
        }
        Some(SiblingRegistry::Named(registry)) => (registry.to_string(), true),
        Some(SiblingRegistry::PypiFiles) => ("https://pypi.org/simple".to_string(), false),
        Some(SiblingRegistry::Files(host)) => {
            return Err(format!(
                "the lock's packages record no `index` and carry files from {host}, which is \
                 not PyPI, so its release files cannot be re-derived"
            ))
        }
    };
    if !is_pypi_simple(&registry) {
        return Err(format!(
            "the lock's registry {registry} is not PyPI, so its release files cannot be \
             re-derived"
        ));
    }
    let (keys, datetime, multiline, tables, hash_tables, package_keys) = shape.ok_or(
        "no sibling registry package records an artifact, so which artifact fields the lock \
         records is not derivable",
    )?;
    let known = ["url", "hash", "hashes", "size", "name"];
    if let Some(unknown) = keys
        .iter()
        .find(|k| !known.contains(&k.as_str()) && !UPLOAD_TIME_KEYS.contains(&k.as_str()))
    {
        return Err(format!(
            "sibling artifacts carry an unknown field `{unknown}`"
        ));
    }
    Ok(Shape {
        registry,
        index,
        whole_seconds: pep751 && !fractional_seconds,
        keys,
        datetime,
        multiline,
        tables,
        hash_tables,
        selected_only: pep751 && doc.get("created-by").and_then(Item::as_str) == Some("pip"),
        package_keys,
    })
}

/// The artifact timestamp key, in both spellings uv has written:
/// `upload_time` (uv 0.6.15–0.6.17, lock revision 2) and `upload-time`
/// (uv 0.7.0 and later, and PEP 751 pylock files). A re-derived artifact
/// keeps the spelling its sibling shows.
const UPLOAD_TIME_KEYS: [&str; 2] = ["upload-time", "upload_time"];

/// An artifact's timestamp, under whichever spelling it records.
fn upload_time_value(artifact: &dyn TableLike) -> Option<&Item> {
    UPLOAD_TIME_KEYS.iter().find_map(|k| artifact.get(k))
}

/// uv's timestamp of a PyPI `upload_time_iso_8601`: milliseconds in
/// uv.lock (`2023-10-17T17:46:21.184066Z` → `2023-10-17T17:46:21.184Z`;
/// trailing fractional zeros are not printed), truncated to whole seconds
/// in pylock files (`2023-10-17T17:46:21Z`).
fn upload_time(iso: &str, whole_seconds: bool) -> Option<String> {
    let iso = iso.strip_suffix('Z')?;
    let (seconds, fraction) = iso.split_once('.').unwrap_or((iso, ""));
    if seconds.len() != 19 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if whole_seconds {
        return Some(format!("{seconds}Z"));
    }
    let mut millis: String = fraction.chars().take(3).collect();
    while millis.ends_with('0') {
        millis.pop();
    }
    Some(if millis.is_empty() {
        format!("{seconds}Z")
    } else {
        format!("{seconds}.{millis}Z")
    })
}

/// One artifact inline table in the sibling shape.
fn render_artifact(file: &PypiFile, shape: &Shape) -> Result<String, String> {
    let mut fields = Vec::with_capacity(shape.keys.len());
    for key in &shape.keys {
        let value = match key.as_str() {
            "url" => toml_quote(&file.url),
            "name" => toml_quote(&file.filename),
            "hash" => toml_quote(&format!("sha256:{}", file.sha256)),
            "hashes" => format!("{{ sha256 = {} }}", toml_quote(&file.sha256)),
            "size" => file
                .size
                .ok_or_else(|| format!("PyPI reports no size for {}", file.filename))?
                .to_string(),
            key if UPLOAD_TIME_KEYS.contains(&key) => {
                let time = file
                    .upload_time
                    .as_deref()
                    .and_then(|iso| upload_time(iso, shape.whole_seconds))
                    .ok_or_else(|| format!("PyPI reports no upload time for {}", file.filename))?;
                if shape.datetime {
                    time
                } else {
                    toml_quote(&time)
                }
            }
            other => return Err(format!("unknown artifact field `{other}`")),
        };
        fields.push(format!("{key} = {value}"));
    }
    Ok(format!("{{ {} }}", fields.join(", ")))
}

/// `(sdist, wheels)` items for a release, in the sibling shape.
fn render_artifacts(
    release: &[PypiFile],
    shape: &Shape,
) -> Result<(Option<Item>, Option<Item>), String> {
    if !universal_release(release) {
        return Err(
            "the release ships platform- or interpreter-specific wheels, and which of them uv \
             kept (requires-python and environment filtering) is not derivable"
                .to_string(),
        );
    }
    let (wheels, sdists): (Vec<&PypiFile>, Vec<&PypiFile>) =
        release.iter().partition(|f| f.filename.ends_with(".whl"));
    let (wheels, sdists) = match (shape.selected_only, wheels.len()) {
        (false, _) | (true, 0) => (wheels, sdists),
        // pip installs a wheel over the sdist, and records only it.
        (true, 1) => (wheels, Vec::new()),
        (true, _) => {
            return Err(
                "`pip lock` records only the one wheel pip selected, and which of this \
                 release's several wheels that is depends on the interpreter that ran it"
                    .to_string(),
            )
        }
    };
    let sdist = match sdists.as_slice() {
        [] => None,
        [one] => Some(render_artifact(one, shape)?),
        _ => return Err("the release has several source distributions".to_string()),
    };
    if shape.tables {
        let table = |text: &str| -> Result<toml_edit::Table, String> {
            toml_value(text)
                .and_then(|v| v.as_inline_table().cloned())
                .map(|t| standard_table(t, shape.hash_tables))
                .ok_or("an artifact does not render as TOML".to_string())
        };
        let sdist = sdist.as_deref().map(table).transpose()?.map(Item::Table);
        let mut array = toml_edit::ArrayOfTables::new();
        for wheel in &wheels {
            array.push(table(&render_artifact(wheel, shape)?)?);
        }
        let wheels = (!array.is_empty()).then_some(Item::ArrayOfTables(array));
        return Ok((sdist, wheels));
    }
    let wheels = if wheels.is_empty() {
        None
    } else {
        let entries = wheels
            .iter()
            .map(|f| render_artifact(f, shape))
            .collect::<Result<Vec<_>, _>>()?;
        Some(if shape.multiline {
            super::pypi::multiline_toml_array(&entries)
        } else {
            format!("[{}]", entries.join(", "))
        })
    };
    let parse = |text: Option<String>| -> Result<Option<Item>, String> {
        text.map(|t| {
            toml_value(&t)
                .map(Item::Value)
                .ok_or("an artifact does not render as TOML".to_string())
        })
        .transpose()
    };
    Ok((parse(sdist)?, parse(wheels)?))
}

/// An inline artifact table as a standard table in default layout; its
/// inline sub-tables (`hashes`) become sub-tables too when `sub_tables`.
fn standard_table(inline: toml_edit::InlineTable, sub_tables: bool) -> toml_edit::Table {
    let mut table = toml_edit::Table::new();
    for (key, mut value) in inline {
        let item = match value {
            Value::InlineTable(sub) if sub_tables => Item::Table(standard_table(sub, false)),
            _ => {
                value.decor_mut().clear();
                Item::Value(value)
            }
        };
        table.insert(&key, item);
    }
    table
}

fn inline_source(registry: &str) -> Value {
    toml_value(&format!("{{ registry = {} }}", toml_quote(registry)))
        .expect("a registry source renders as TOML")
}

/// Replace `item`'s value, keeping its decor.
fn replace_keeping_decor(slot: &mut Value, mut value: Value) {
    *value.decor_mut() = slot.decor().clone();
    *slot = value;
}

/// The package entry itself, and every dependent reference to it.
fn restore_uv_entry(
    doc: &mut DocumentMut,
    hit: &Hit,
    shape: &Shape,
    (sdist, wheels): (Option<Item>, Option<Item>),
    ctx: &Ctx<'_>,
) -> Result<(), String> {
    let package = doc
        .get_mut("package")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|p| p.get_mut(hit.index))
        .ok_or("the package entry vanished")?;
    match package.get_mut("source").and_then(Item::as_value_mut) {
        Some(slot) => replace_keeping_decor(slot, inline_source(&shape.registry)),
        None => return Err("the package source is not an inline table".to_string()),
    }
    for key in ["sdist", "wheels", "wheel", "archive"] {
        package.remove(key);
    }
    if let Some(sdist) = sdist {
        package.insert("sdist", sdist);
    }
    if let Some(wheels) = wheels {
        package.insert("wheels", wheels);
    }
    package.remove("metadata");
    restore_refs(doc.as_item_mut(), hit, &shape.registry, ctx);
    Ok(())
}

/// Dependents' `{ name, source = { url } }` references back to the registry.
fn restore_refs(item: &mut Item, hit: &Hit, registry: &str, ctx: &Ctx<'_>) {
    match item {
        Item::Value(value) => restore_ref_value(value, hit, registry, ctx),
        Item::Table(table) => {
            for (_, item) in table.iter_mut() {
                restore_refs(item, hit, registry, ctx);
            }
        }
        Item::ArrayOfTables(tables) => {
            for table in tables.iter_mut() {
                for (_, item) in table.iter_mut() {
                    restore_refs(item, hit, registry, ctx);
                }
            }
        }
        Item::None => {}
    }
}

fn restore_ref_value(value: &mut Value, hit: &Hit, registry: &str, ctx: &Ctx<'_>) {
    match value {
        Value::Array(array) => {
            for value in array.iter_mut() {
                restore_ref_value(value, hit, registry, ctx);
            }
        }
        Value::InlineTable(table) => {
            let names_hit = table
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|n| canonicalize_pypi_name(n) == hit.name);
            let hosted = table
                .get("source")
                .and_then(Value::as_inline_table)
                .and_then(|s| s.get("url"))
                .and_then(Value::as_str)
                .and_then(|u| ctx.hosted_uuid(u))
                .is_some_and(|u| u == hit.uuid);
            if names_hit && hosted {
                if let Some(slot) = table.get_mut("source") {
                    replace_keeping_decor(slot, inline_source(registry));
                }
            }
            for (_, value) in table.iter_mut() {
                restore_ref_value(value, hit, registry, ctx);
            }
        }
        _ => {}
    }
}

/// The pylock entry: `archive` out, `index` + `sdist` + `wheels` back in the
/// sibling's key order.
fn restore_pylock_entry(
    doc: &mut DocumentMut,
    hit: &Hit,
    shape: &Shape,
    (sdist, wheels): (Option<Item>, Option<Item>),
) -> Result<(), String> {
    let package = doc
        .get_mut("packages")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|p| p.get_mut(hit.index))
        .ok_or("the package entry vanished")?;
    package.remove("archive");
    if shape.index {
        package.insert("index", toml_edit::value(shape.registry.clone()));
    }
    if let Some(sdist) = sdist {
        package.insert("sdist", sdist);
    }
    if let Some(wheels) = wheels {
        package.insert("wheels", wheels);
    }
    // Keys the sibling orders sort by its order; any other key keeps its
    // place after the known key before it.
    let rank = |key: &str| shape.package_keys.iter().position(|k| k == key);
    let current: Vec<String> = package.iter().map(|(k, _)| k.to_string()).collect();
    let mut ranks: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut last = 0;
    for (i, key) in current.iter().enumerate() {
        if let Some(r) = rank(key) {
            last = r;
        }
        ranks.insert(
            key.clone(),
            (last, if rank(key).is_some() { 0 } else { 1 + i }),
        );
    }
    package.sort_values_by(|a, _, b, _| ranks.get(a.get()).cmp(&ranks.get(b.get())));
    Ok(())
}

// ── requirement specifiers ───────────────────────────────────────────────────

/// The paired metadata document: a pyproject, or a script's PEP 723 block.
struct Metadata {
    rel: String,
    text: String,
    script: bool,
    doc: DocumentMut,
}

impl Metadata {
    /// The new file text; `None` when it no longer renders.
    fn render(&self) -> Option<String> {
        let body = self.doc.to_string();
        if self.script {
            crate::utils::python_script::replace_script_metadata(&self.text, &body).ok()
        } else {
            Some(preserve_line_endings(&self.text, body))
        }
    }
}

async fn load_metadata(
    view: &mut View<'_>,
    rel: &str,
    script: bool,
) -> Result<Option<Metadata>, String> {
    let Some(text) = view.read(rel).await? else {
        return if script {
            Err(format!(
                "the script {rel} the lock belongs to no longer exists"
            ))
        } else {
            Ok(None)
        };
    };
    let body = if script {
        crate::utils::python_script::script_metadata(&text)
            .map_err(|e| format!("{rel}: {e}"))?
            .1
    } else {
        text.clone()
    };
    let doc = body
        .parse::<DocumentMut>()
        .map_err(|e| format!("{rel} is not valid TOML: {e}"))?;
    Ok(Some(Metadata {
        rel: rel.to_string(),
        text,
        script,
        doc,
    }))
}

fn tool_uv(doc: &DocumentMut) -> Option<&dyn TableLike> {
    doc.get("tool")
        .and_then(Item::as_table_like)
        .and_then(|t| t.get("uv"))
        .and_then(Item::as_table_like)
}

fn strings(item: Option<&Item>) -> Vec<&str> {
    item.and_then(Item::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

/// Which declarations a lock requirement array mirrors.
#[derive(Clone, Copy)]
enum Declared<'a> {
    /// Root `requires-dist`: `[project]` dependencies and extras.
    Dist,
    /// Root `requires-dev.<group>`: a PEP 735 group or uv's legacy
    /// `dev-dependencies` (group `dev`).
    Dev(&'a str),
    /// `[manifest] <key>` ↔ `[tool.uv] <key>` (a script's `dependencies`
    /// for `requirements`).
    Manifest(&'a str),
}

/// One declaration a lock requirement entry can mirror: the PEP 508 string
/// and, for a `[project.optional-dependencies]` member, its extra (PEP 685
/// normalized) — uv lowers that into the entry's marker as `extra == '<x>'`.
struct Declaration<'d> {
    spec: &'d str,
    extra: Option<String>,
}

/// Every declaration `declared` covers in the metadata.
fn declarations<'d>(meta: &'d Metadata, declared: Declared<'_>) -> Vec<Declaration<'d>> {
    let doc = &meta.doc;
    let uv = tool_uv(doc);
    let plain = |specs: Vec<&'d str>| {
        specs
            .into_iter()
            .map(|spec| Declaration { spec, extra: None })
            .collect()
    };
    match declared {
        Declared::Dist => {
            let project = doc.get("project");
            let mut out: Vec<Declaration<'d>> =
                plain(strings(project.and_then(|p| p.get("dependencies"))));
            if let Some(extras) = project
                .and_then(|p| p.get("optional-dependencies"))
                .and_then(Item::as_table_like)
            {
                for (extra, group) in extras.iter() {
                    let extra = canonicalize_pypi_name(extra);
                    out.extend(strings(Some(group)).into_iter().map(|spec| Declaration {
                        spec,
                        extra: Some(extra.clone()),
                    }));
                }
            }
            out
        }
        Declared::Dev(group) => {
            let mut out = Vec::new();
            group_members(
                doc.get("dependency-groups").and_then(Item::as_table_like),
                group,
                &mut Vec::new(),
                &mut out,
            );
            if group == "dev" {
                out.extend(strings(uv.and_then(|u| u.get("dev-dependencies"))));
            }
            plain(out)
        }
        Declared::Manifest("requirements") => plain(strings(doc.get("dependencies"))),
        Declared::Manifest(key) => {
            let key = match key {
                "constraints" => "constraint-dependencies",
                "build-constraints" => "build-constraint-dependencies",
                "overrides" => "override-dependencies",
                other => other,
            };
            plain(strings(uv.and_then(|u| u.get(key))))
        }
    }
}

/// A PEP 735 group's requirement strings, with its `{ include-group = … }`
/// members expanded the way uv expands them into the lock (group names
/// compare normalized; a group already being expanded is not re-entered).
fn group_members<'d>(
    groups: Option<&'d dyn TableLike>,
    group: &str,
    expanding: &mut Vec<String>,
    out: &mut Vec<&'d str>,
) {
    let canon = canonicalize_pypi_name(group);
    if expanding.contains(&canon) {
        return;
    }
    let Some(members) = groups
        .into_iter()
        .flat_map(|g| g.iter())
        .find(|(name, _)| canonicalize_pypi_name(name) == canon)
        .and_then(|(_, item)| item.as_array())
    else {
        return;
    };
    expanding.push(canon);
    for member in members.iter() {
        if let Some(spec) = member.as_str() {
            out.push(spec);
        } else if let Some(included) = member
            .as_inline_table()
            .and_then(|t| t.get("include-group"))
            .and_then(Value::as_str)
        {
            group_members(groups, included, expanding, out);
        }
    }
    expanding.pop();
}

/// The extras an entry's marker names (`extra == '<x>'`), normalized.
fn marker_extras(marker: &str) -> BTreeSet<String> {
    static EXTRA: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"\bextra\s*==\s*['"]([^'"]+)['"]"#).expect("static extra regex")
    });
    EXTRA
        .captures_iter(marker)
        .map(|c| canonicalize_pypi_name(&c[1]))
        .collect()
}

/// A comparison key for a PEP 508 marker as uv records it in the lock:
/// `and`-joined atoms with `extra` terms dropped, quotes and spacing
/// normalized, sorted, and `python_version` comparisons spelled as the
/// `python_full_version` bounds uv rewrites them into. A marker with `or`
/// or parentheses is compared as normalized text.
fn marker_key(marker: &str) -> String {
    static ATOM: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"^([A-Za-z_][A-Za-z0-9_.]*)\s*(===|==|!=|~=|<=|>=|<|>)\s*(?:'([^']*)'|"([^"]*)")$"#,
        )
        .expect("static marker atom regex")
    });
    static AND: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\s+and\s+").expect("static and regex"));
    let text = marker.trim();
    if text.contains('(') || text.split_whitespace().any(|w| w == "or") {
        return text
            .replace('"', "'")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
    }
    let mut atoms: Vec<String> = AND
        .split(text)
        .filter(|atom| !atom.trim().is_empty())
        .filter_map(|atom| {
            let atom = atom.trim();
            let Some(c) = ATOM.captures(atom) else {
                return Some(atom.replace('"', "'").split_whitespace().collect());
            };
            let (var, op) = (&c[1], &c[2]);
            let value = c.get(3).or_else(|| c.get(4)).map_or("", |m| m.as_str());
            if var == "extra" {
                return None;
            }
            if var == "python_version" {
                if let Some((major, minor)) = value
                    .split_once('.')
                    .and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?)))
                {
                    let next = format!("{major}.{}", minor + 1);
                    let full = |op: &str, v: &str| format!("python_full_version {op} '{v}'");
                    return Some(match op {
                        "<" | ">=" => full(op, value),
                        "<=" => full("<", &next),
                        ">" => full(">=", &next),
                        "==" | "!=" => full(op, &format!("{value}.*")),
                        _ => format!("{var} {op} '{value}'"),
                    });
                }
            }
            Some(format!("{var} {op} '{value}'"))
        })
        .collect();
    atoms.sort();
    atoms.join(" and ")
}

/// The normalized version clauses of a PEP 508 registry requirement (`[]`
/// when unconstrained), or why uv's spelling of them is not derivable.
fn spec_clauses(spec: &str) -> Result<Vec<String>, String> {
    static VERSION: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"^[0-9]+(\.[0-9]+)*(\.\*)?((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?$",
        )
        .expect("static version regex is valid")
    });
    let name = pep508_name(spec);
    let mut rest = spec.trim_start()[name.len()..].trim_start();
    if rest.starts_with('[') {
        rest = rest[rest.find(']').map_or(rest.len(), |i| i + 1)..].trim_start();
    }
    let constraint = rest.split(';').next().unwrap_or("").trim();
    let constraint = constraint
        .strip_prefix('(')
        .and_then(|c| c.strip_suffix(')'))
        .unwrap_or(constraint);
    let compact: String = constraint.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Ok(Vec::new());
    }
    if compact.starts_with('@') {
        return Err(format!("{spec:?} is a direct reference"));
    }
    compact
        .split(',')
        .map(|clause| {
            let op = ["==", "!=", "~=", "<=", ">=", "<", ">"]
                .into_iter()
                .find(|op| clause.starts_with(op) && !clause.starts_with("==="))
                .ok_or_else(|| format!("uv's spelling of {spec:?} is not derivable"))?;
            let version = clause[op.len()..].to_ascii_lowercase();
            if !VERSION.is_match(&version) {
                return Err(format!("uv's spelling of {spec:?} is not derivable"));
            }
            Ok(format!("{op}{version}"))
        })
        .collect()
}

/// How this uv joins a multi-clause specifier, learned from the lock's own
/// multi-clause entries against their declarations.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SpecStyle {
    separator: &'static str,
    sorted: bool,
}

impl SpecStyle {
    const CANDIDATES: [SpecStyle; 4] = [
        SpecStyle {
            separator: ", ",
            sorted: false,
        },
        SpecStyle {
            separator: ",",
            sorted: false,
        },
        SpecStyle {
            separator: ", ",
            sorted: true,
        },
        SpecStyle {
            separator: ",",
            sorted: true,
        },
    ];

    fn join(self, clauses: &[String]) -> String {
        let mut clauses = clauses.to_vec();
        if self.sorted {
            clauses.sort();
        }
        clauses.join(self.separator)
    }

    /// The styles every multi-clause lock entry agrees with; empty when the
    /// lock shows none.
    fn learn(doc: &DocumentMut, meta: Option<&Metadata>) -> Vec<SpecStyle> {
        let Some(meta) = meta else {
            return Vec::new();
        };
        let mut evidence: Vec<(String, Vec<String>)> = Vec::new();
        for (declared, array) in requirement_arrays_ref(doc) {
            for entry in array.iter().filter_map(Value::as_inline_table) {
                let (Some(name), Some(specifier)) = (
                    entry.get("name").and_then(Value::as_str),
                    entry.get("specifier").and_then(Value::as_str),
                ) else {
                    continue;
                };
                if !specifier.contains(',') {
                    continue;
                }
                let marker = entry.get("marker").and_then(Value::as_str);
                if let Ok(Some(clauses)) = declared_clauses(meta, declared, name, marker) {
                    evidence.push((specifier.to_string(), clauses));
                }
            }
        }
        if evidence.is_empty() {
            return Vec::new();
        }
        Self::CANDIDATES
            .into_iter()
            .filter(|style| evidence.iter().all(|(s, c)| style.join(c) == *s))
            .collect()
    }
}

/// The clause list of the declaration of `name` in `declared` that a lock
/// entry with `marker` mirrors; `Ok(None)` when nothing declares it.
///
/// When every declaration agrees, that is the answer whatever the marker.
/// Otherwise uv's lowering picks one: the marker's `extra == '<x>'` terms
/// name the extras it came from (or a declaration-owned simple equality),
/// and the rest of the marker is the declaration's own. More complex
/// declaration-owned extra predicates can lower to the same marker, so
/// differing clauses remain ambiguous and are refused for those shapes.
fn declared_clauses(
    meta: &Metadata,
    declared: Declared<'_>,
    name: &str,
    marker: Option<&str>,
) -> Result<Option<Vec<String>>, String> {
    let canon = canonicalize_pypi_name(name);
    let named: Vec<Declaration<'_>> = declarations(meta, declared)
        .into_iter()
        .filter(|d| canonicalize_pypi_name(pep508_name(d.spec)) == canon)
        .collect();
    if named.is_empty() {
        return Ok(None);
    }
    let agreed = |set: &[&Declaration<'_>]| -> Result<Option<Vec<String>>, String> {
        let mut found: Option<Vec<String>> = None;
        for d in set {
            let clauses = spec_clauses(d.spec)?;
            match &found {
                Some(prior) if *prior != clauses => return Ok(None),
                _ => found = Some(clauses),
            }
        }
        Ok(found)
    };
    let mut set: Vec<&Declaration<'_>> = named.iter().collect();
    // The matcher understands a declaration-owned `extra == '<name>'`,
    // but uv can lower other predicates (including reversed equality) to
    // that same marker. Without their erased specifiers, keep differing
    // clauses ambiguous rather than discard a possible declaration.
    static SIMPLE_EXTRA: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"^\s*extra\s*==\s*(?:'[A-Za-z0-9._-]+'|"[A-Za-z0-9._-]+")\s*$"#)
            .expect("static simple extra regex")
    });
    let unsupported_extra = named.iter().any(|d| {
        d.spec.split_once(';').is_some_and(|(_, marker)| {
            marker
                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .any(|token| token == "extra")
                && !SIMPLE_EXTRA.is_match(marker)
        })
    });
    let marker = marker.unwrap_or("");
    let extras = marker_extras(marker);
    let narrowings: [&dyn Fn(&Declaration<'_>) -> bool; 2] = [
        // A `dependencies` line can carry its own `extra == '<x>'` marker
        // (uv accepts it), so its lock entry looks like one from extra `x`.
        &|d| match &d.extra {
            Some(extra) => extras.contains(extra),
            None => marker_extras(d.spec.split_once(';').map_or("", |(_, m)| m)) == extras,
        },
        &|d| {
            let own = d.spec.split_once(';').map_or("", |(_, m)| m);
            marker_key(own) == marker_key(marker)
        },
    ];
    for narrow in narrowings {
        if let Ok(Some(clauses)) = agreed(&set) {
            return Ok(Some(clauses));
        }
        if unsupported_extra {
            break;
        }
        let narrowed: Vec<&Declaration<'_>> = set.iter().copied().filter(|d| narrow(d)).collect();
        if narrowed.is_empty() {
            break;
        }
        set = narrowed;
    }
    agreed(&set)?.map(Some).ok_or_else(|| {
        format!(
            "{} declares {name} with different specifiers; which one each lock entry \
             mirrors is not derivable",
            meta.rel
        )
    })
}

/// Which lock requirement array a vendored revert is restoring an entry
/// of, for [`respell_lock_specifier`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum LockRequirementArray<'a> {
    /// The root `requires-dist`: `[project]` dependencies and extras.
    RequiresDist,
    /// The root `requires-dev.<group>`.
    RequiresDev(&'a str),
    /// `[manifest] constraints` / `build-constraints`.
    Manifest(&'a str),
}

/// The `specifier` a vendored revert should restore for `name`'s entry
/// in `array`, given the one it recorded when vendoring (`None` when the
/// entry had none) and the entry's `marker`.
///
/// A path source records no specifier, so a user who changes the
/// declaration while the package is vendored (`uv add "six>=1.16"`)
/// leaves uv.lock byte-identical, and the recorded specifier goes stale
/// (#840). The entry's declaration is picked the way hosted unwind picks
/// it ([`declared_clauses`]: by the extra and environment marker uv
/// lowered into the entry). Returns:
/// * `Ok(None)`: keep the recorded entry as it is. The declaration still
///   agrees with it, nothing declares the name, or no declaration of it is
///   a plain version range (the recorded spelling was uv's own, so it
///   stays the best answer);
/// * `Ok(Some(spec))`: write `spec` instead, in uv's spelling (`None` is no
///   specifier at all);
/// * `Err`: the declaration changed but uv's spelling of it can't be
///   derived (a multi-clause range), or which declaration the entry
///   mirrors is ambiguous, so restoring any spelling may break `--locked`.
pub(crate) fn respell_lock_specifier(
    pyproject_text: &str,
    array: LockRequirementArray<'_>,
    name: &str,
    recorded: Option<&str>,
    marker: Option<&str>,
) -> Result<Option<Option<String>>, String> {
    let Ok(doc) = pyproject_text.parse::<DocumentMut>() else {
        return Ok(None);
    };
    let meta = Metadata {
        rel: "pyproject.toml".to_string(),
        text: String::new(),
        script: false,
        doc,
    };
    let declared = match array {
        LockRequirementArray::RequiresDist => Declared::Dist,
        LockRequirementArray::RequiresDev(group) => Declared::Dev(group),
        LockRequirementArray::Manifest(key) => Declared::Manifest(key),
    };
    let canon = canonicalize_pypi_name(name);
    let recorded = match recorded {
        None => Vec::new(),
        Some(r) => match spec_clauses(&format!("{canon}{r}")) {
            Ok(clauses) => clauses,
            Err(_) => return Ok(None),
        },
    };
    let clauses = match declared_clauses(&meta, declared, name, marker) {
        Ok(Some(clauses)) => clauses,
        Ok(None) => return Ok(None),
        // Not one declaration of the name is a plain version range: the
        // recorded spelling was uv's own, so it stays the best answer.
        // Otherwise the marker narrowing left an unreadable or conflicting
        // set, which is ambiguous: fail closed.
        Err(reason) => {
            let all_unreadable = declarations(&meta, declared)
                .iter()
                .filter(|d| canonicalize_pypi_name(pep508_name(d.spec)) == canon)
                .all(|d| spec_clauses(d.spec).is_err());
            return if all_unreadable {
                Ok(None)
            } else {
                Err(reason)
            };
        }
    };
    let sorted = |clauses: &[String]| {
        let mut c = clauses.to_vec();
        c.sort();
        c
    };
    if sorted(&clauses) == sorted(&recorded) {
        return Ok(None);
    }
    match clauses.as_slice() {
        [] => Ok(Some(None)),
        [one] => Ok(Some(Some(one.clone()))),
        // How uv orders and joins clauses differs between releases (0.8
        // orders them by version: `>=20,!=21.1.0,<30`), and the lock no
        // longer shows this entry's spelling, so any guess may break
        // `--locked`.
        _ => Err(format!(
            "pyproject.toml now declares {name} with a multi-clause specifier, whose \
             spelling in uv.lock is not derivable"
        )),
    }
}

/// Every lock requirement array with the declarations it mirrors
/// (read-only twin of [`restore_requirements`]'s walk).
fn requirement_arrays_ref(doc: &DocumentMut) -> Vec<(Declared<'_>, &toml_edit::Array)> {
    let mut out = Vec::new();
    for package in doc
        .get("package")
        .and_then(Item::as_array_of_tables)
        .into_iter()
        .flatten()
    {
        let Some(metadata) = package.get("metadata").and_then(Item::as_table_like) else {
            continue;
        };
        if let Some(array) = metadata.get("requires-dist").and_then(Item::as_array) {
            out.push((Declared::Dist, array));
        }
        if let Some(groups) = metadata.get("requires-dev").and_then(Item::as_table_like) {
            for (group, item) in groups.iter() {
                if let Some(array) = item.as_array() {
                    out.push((Declared::Dev(group), array));
                }
            }
        }
    }
    if let Some(manifest) = doc.get("manifest").and_then(Item::as_table_like) {
        for key in [
            "requirements",
            "constraints",
            "build-constraints",
            "overrides",
        ] {
            if let Some(array) = manifest.get(key).and_then(Item::as_array) {
                out.push((Declared::Manifest(key), array));
            }
        }
    }
    out
}

/// The hosted requirement entries of one array: `url` out, the declared
/// `specifier` back; an `overrides` entry with no declaration left is the
/// rewrite's own and is dropped.
fn restore_requirement_array(
    array: &mut toml_edit::Array,
    declared: Declared<'_>,
    hit: &Hit,
    meta: Option<&Metadata>,
    styles: &[SpecStyle],
    ctx: &Ctx<'_>,
    transitive_override: bool,
) -> Result<(), String> {
    let mut drop: Vec<usize> = Vec::new();
    for (i, value) in array.iter_mut().enumerate() {
        let Some(entry) = value.as_inline_table_mut() else {
            continue;
        };
        let names_hit = entry
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| canonicalize_pypi_name(n) == hit.name);
        let hosted = entry
            .get("url")
            .and_then(Value::as_str)
            .and_then(|u| ctx.hosted_uuid(u))
            .is_some_and(|u| u == hit.uuid);
        if !names_hit || !hosted {
            continue;
        }
        if matches!(declared, Declared::Manifest("overrides")) && transitive_override {
            drop.push(i);
            continue;
        }
        let meta = meta.ok_or(
            "the lock's requirement entries name the hosted artifact but its paired metadata \
             file is missing, so their specifiers are not derivable",
        )?;
        let marker = entry.get("marker").and_then(Value::as_str);
        let clauses = declared_clauses(meta, declared, &hit.name, marker)?.ok_or_else(|| {
            format!(
                "{} no longer declares {}, so the lock entry's specifier is not derivable",
                meta.rel, hit.name
            )
        })?;
        let specifier = match clauses.as_slice() {
            [] => None,
            [one] => Some(one.clone()),
            _ => match styles {
                [style, ..] => Some(style.join(&clauses)),
                [] => {
                    return Err(format!(
                        "no other entry of the lock shows how this uv spells a multi-clause \
                         specifier such as {}'s",
                        hit.name
                    ))
                }
            },
        };
        entry.remove("url");
        if let Some(specifier) = specifier {
            entry.insert("specifier", Value::from(specifier));
        }
    }
    for i in drop.into_iter().rev() {
        array.remove(i);
    }
    Ok(())
}

/// Every requirement array of the lock (root metadata, `[manifest]`).
fn restore_requirements(
    doc: &mut DocumentMut,
    hit: &Hit,
    meta: Option<&Metadata>,
    styles: &[SpecStyle],
    ctx: &Ctx<'_>,
) -> Result<(), String> {
    // A transitive dependency's `overrides` entry is the rewrite's own when
    // the metadata's `override-dependencies` holds the pin it adds, under
    // its ownership comment; a user's own pin is restored like any other
    // declaration.
    let transitive_override = meta.is_some_and(|m| pushed_override(m, hit).is_some());
    for package in doc
        .get_mut("package")
        .and_then(Item::as_array_of_tables_mut)
        .into_iter()
        .flat_map(|p| p.iter_mut())
    {
        let Some(metadata) = package
            .get_mut("metadata")
            .and_then(Item::as_table_like_mut)
        else {
            continue;
        };
        if let Some(array) = metadata
            .get_mut("requires-dist")
            .and_then(Item::as_array_mut)
        {
            restore_requirement_array(array, Declared::Dist, hit, meta, styles, ctx, false)?;
        }
        if let Some(groups) = metadata
            .get_mut("requires-dev")
            .and_then(Item::as_table_like_mut)
        {
            for (group, item) in groups.iter_mut() {
                let group = group.get().to_string();
                if let Some(array) = item.as_array_mut() {
                    restore_requirement_array(
                        array,
                        Declared::Dev(&group),
                        hit,
                        meta,
                        styles,
                        ctx,
                        false,
                    )?;
                }
            }
        }
    }
    let mut emptied_manifest = false;
    if let Some(manifest) = doc.get_mut("manifest").and_then(Item::as_table_like_mut) {
        for key in [
            "requirements",
            "constraints",
            "build-constraints",
            "overrides",
        ] {
            let Some(array) = manifest.get_mut(key).and_then(Item::as_array_mut) else {
                continue;
            };
            restore_requirement_array(
                array,
                Declared::Manifest(key),
                hit,
                meta,
                styles,
                ctx,
                transitive_override,
            )?;
            if key == "overrides" && array.is_empty() {
                manifest.remove(key);
            }
        }
        emptied_manifest = manifest.is_empty();
    }
    if emptied_manifest {
        doc.remove("manifest");
    }
    Ok(())
}

// ── paired metadata ──────────────────────────────────────────────────────────

/// Whether the metadata declares `hit` directly (the rewrite adds an
/// override only for a transitive dependency).
fn declares_directly(meta: &Metadata, hit: &Hit) -> bool {
    let names = |spec: &&str| canonicalize_pypi_name(pep508_name(spec)) == hit.name;
    if meta.script {
        return strings(meta.doc.get("dependencies")).iter().any(names);
    }
    crate::vendor::common::pyproject_dependency_specs(&meta.doc)
        .iter()
        .any(|(_, spec)| names(spec))
        || strings(tool_uv(&meta.doc).and_then(|u| u.get("dev-dependencies")))
            .iter()
            .any(names)
}

/// The index of the `override-dependencies` entry the rewrite added for a
/// transitive `hit` (`<name>==<version>` under
/// [`HOSTED_OVERRIDE_MARK`](crate::utils::python_script::HOSTED_OVERRIDE_MARK)),
/// when present. Hosted mode keeps no ledger, so that comment is the only
/// evidence of ownership: an unmarked entry of the same spelling is the
/// user's own pin (the rewrite reuses it rather than adding one) and stays,
/// along with the lock's `[manifest] overrides` record of it (#411).
fn pushed_override(meta: &Metadata, hit: &Hit) -> Option<usize> {
    if declares_directly(meta, hit) {
        return None;
    }
    let want = format!("{}=={}", hit.name, hit.version);
    tool_uv(&meta.doc)
        .and_then(|u| u.get("override-dependencies"))
        .and_then(Item::as_array)?
        .iter()
        .position(|value| {
            let Some(spec) = value.as_str() else {
                return false;
            };
            let compact: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
            canonicalize_pypi_name(pep508_name(&compact)) == hit.name
                && compact[pep508_name(&compact).len()..] == want[hit.name.len()..]
                && crate::utils::python_script::is_hosted_override(value)
        })
}

/// Remove the metadata's hosted `[tool.uv.sources]` entry for `hit` and,
/// for a transitive dependency, the override the rewrite added; tables left
/// empty go too. `true` when an override was removed.
fn restore_metadata(meta: &mut Metadata, hit: &Hit, ctx: &Ctx<'_>) -> bool {
    let pushed = pushed_override(meta, hit);
    let Some(tool) = meta.doc.get_mut("tool").and_then(Item::as_table_like_mut) else {
        return false;
    };
    let Some(uv) = tool.get_mut("uv").and_then(Item::as_table_like_mut) else {
        return false;
    };
    if let Some(sources) = uv.get_mut("sources").and_then(Item::as_table_like_mut) {
        let key = sources
            .iter()
            .find(|(k, v)| {
                canonicalize_pypi_name(k) == hit.name
                    && v.as_table_like()
                        .and_then(|t| t.get("url"))
                        .and_then(Item::as_str)
                        .and_then(|u| ctx.hosted_uuid(u))
                        .is_some_and(|u| u == hit.uuid)
            })
            .map(|(k, _)| k.to_string());
        if let Some(key) = key {
            sources.remove(&key);
        }
        if sources.is_empty() {
            uv.remove("sources");
        }
    }
    // Adding a key to a header-less parent (one only implied by
    // `[tool.uv.sources.<pkg>]` sub-tables) printed its header; once just
    // sub-tables remain, the header is the rewrite's own bytes (#524).
    if let Some(Item::Table(sources)) = uv.get_mut("sources") {
        hide_header_over_sub_tables(sources);
    }
    let mut removed = false;
    if let Some(index) = pushed {
        if let Some(overrides) = uv
            .get_mut("override-dependencies")
            .and_then(Item::as_array_mut)
        {
            overrides.remove(index);
            removed = true;
            if overrides.is_empty() {
                uv.remove("override-dependencies");
            }
        }
    }
    if uv.is_empty() {
        tool.remove("uv");
    }
    if let Some(Item::Table(uv)) = tool.get_mut("uv") {
        hide_header_over_sub_tables(uv);
    }
    if tool.is_empty() {
        meta.doc.remove("tool");
    }
    removed
}

/// Make a standard table implicit again when it holds only sub-tables, so
/// it renders as the `[parent.<sub>]` headers alone — the spelling it had
/// before the hosted rewrite added (and restore removed) a key under it.
fn hide_header_over_sub_tables(table: &mut toml_edit::Table) {
    if !table.is_dotted()
        && !table.is_empty()
        && table
            .iter()
            .all(|(_, item)| matches!(item, Item::Table(t) if !t.is_dotted()))
    {
        table.set_implicit(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_times_are_milliseconds_without_trailing_zeros() {
        assert_eq!(
            upload_time("2023-10-17T17:46:21.184066Z", false).as_deref(),
            Some("2023-10-17T17:46:21.184Z")
        );
        assert_eq!(
            upload_time("2023-10-17T17:46:21.100Z", false).as_deref(),
            Some("2023-10-17T17:46:21.1Z")
        );
        assert_eq!(
            upload_time("2023-10-17T17:46:21.000400Z", false).as_deref(),
            Some("2023-10-17T17:46:21Z")
        );
        assert_eq!(
            upload_time("2023-10-17T17:46:21Z", false).as_deref(),
            Some("2023-10-17T17:46:21Z")
        );
        assert_eq!(upload_time("2023-10-17 17:46", false), None);
    }

    #[test]
    fn pylock_upload_times_truncate_to_whole_seconds() {
        assert_eq!(
            upload_time("2021-05-05T14:18:17.237000Z", true).as_deref(),
            Some("2021-05-05T14:18:17Z")
        );
        assert_eq!(
            upload_time("2021-05-05T14:18:18.999Z", true).as_deref(),
            Some("2021-05-05T14:18:18Z")
        );
        assert_eq!(upload_time("2023-10-17 17:46", true), None);
    }

    #[test]
    fn specifier_clauses_normalize_or_refuse() {
        assert_eq!(
            spec_clauses("urllib3[socks] >= 1.26 , <2 ; python_version>'3'").unwrap(),
            [">=1.26", "<2"]
        );
        assert_eq!(spec_clauses("urllib3 (==1.26.18)").unwrap(), ["==1.26.18"]);
        assert!(spec_clauses("urllib3").unwrap().is_empty());
        assert_eq!(spec_clauses("x~=2.0.dev1").unwrap(), ["~=2.0.dev1"]);
        assert!(spec_clauses("x===1.0").is_err());
        assert!(spec_clauses("x>=1.0+local").is_err());
        assert!(spec_clauses("x @ https://h/x.whl").is_err());
    }

    const HOSTED_SIX: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/g/e828efa5-5c6d-43f3-9909-03f5ac232b98/six-1.16.0-py2.py3-none-any.whl";

    /// Hosted rewrite of `six` into `original`, then `restore_metadata`:
    /// the pyproject must come back byte-identically (#524).
    fn assert_metadata_round_trips(original: &str) {
        metadata_round_trip(original, false);
    }

    /// [`assert_metadata_round_trips`] for a project or (`script`) a PEP 723
    /// script; whether the restore reported removing an override.
    fn metadata_round_trip(original: &str, script: bool) -> bool {
        use crate::utils::python_lock::ArtifactSource;
        let rewrite = if script {
            crate::utils::python_script::rewrite_script_metadata
        } else {
            crate::utils::python_script::rewrite_project_metadata
        };
        let rewritten = rewrite(original, "six", "1.16.0", ArtifactSource::Url(HOSTED_SIX))
            .unwrap()
            .expect("the rewrite adds a source");
        assert!(rewritten.contains(HOSTED_SIX), "{rewritten}");
        let body = if script {
            crate::utils::python_script::script_metadata(&rewritten)
                .unwrap()
                .1
        } else {
            rewritten.clone()
        };
        let mut meta = Metadata {
            rel: "pyproject.toml".into(),
            text: rewritten.clone(),
            script,
            doc: body.parse().unwrap(),
        };
        let hit = Hit {
            index: 0,
            uuid: "e828efa5-5c6d-43f3-9909-03f5ac232b98".into(),
            name: "six".into(),
            version: "1.16.0".into(),
        };
        let client = super::super::UpstreamClient::new(true);
        let ctx = Ctx {
            client: &client,
            origins: &[],
            bun_lockb: false,
        };
        let removed = restore_metadata(&mut meta, &hit, &ctx);
        assert_eq!(
            meta.render().unwrap(),
            original,
            "rewritten was:\n{rewritten}"
        );
        removed
    }

    const DATEUTIL_HEAD: &str = "[project]\nname = \"uvp\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [\"python-dateutil==2.8.2\"]\n";

    /// #411: the user's own `override-dependencies` pin of the exact release
    /// being patched is reused by the hosted rewrite, so the restore must
    /// leave it (and report no removal) instead of guessing it was added.
    #[test]
    fn restore_keeps_a_user_authored_override_of_the_patched_release() {
        for overrides in [
            "override-dependencies = [\"six==1.16.0\"]\n",
            "override-dependencies = [\"idna==3.7\", \"six==1.16.0\"]\n",
            "override-dependencies = [\n    \"six==1.16.0\",\n]\n",
        ] {
            let original = format!("{DATEUTIL_HEAD}\n[tool.uv]\n{overrides}");
            assert!(
                !metadata_round_trip(&original, false),
                "a user-authored override is not the rewrite's to remove:\n{original}"
            );
        }
        let script = "# /// script\n# dependencies = [\"python-dateutil==2.8.2\"]\n#\n# [tool.uv]\n# override-dependencies = [\"six==1.16.0\"]\n# ///\nimport six\n";
        assert!(!metadata_round_trip(script, true));
    }

    /// The override the hosted rewrite adds for a transitive dependency
    /// carries its ownership comment and is removed again, into an existing
    /// user array as well as a new one.
    #[test]
    fn restore_removes_the_override_the_rewrite_added() {
        for tool_uv in [
            "",
            "\n[tool.uv]\noverride-dependencies = [\"idna==3.7\"]\n",
            "\n[tool.uv]\noverride-dependencies = [\n    \"idna==3.7\",\n]\n",
        ] {
            let original = format!("{DATEUTIL_HEAD}{tool_uv}");
            assert!(metadata_round_trip(&original, false), "{original}");
        }
        let script =
            "# /// script\n# dependencies = [\"python-dateutil==2.8.2\"]\n# ///\nimport six\n";
        assert!(metadata_round_trip(script, true));
    }

    const SUB_TABLE_SOURCES: &str = "[tool.uv.sources.idna]\nurl = \"https://files.pythonhosted.org/packages/e5/3e/idna-3.7-py3-none-any.whl\"\n";

    #[test]
    fn restore_drops_sources_header_made_explicit_over_sub_tables() {
        assert_metadata_round_trips(&format!(
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\", \"idna==3.7\"]\n\n{SUB_TABLE_SOURCES}"
        ));
    }

    #[test]
    fn restore_drops_headers_made_explicit_over_sub_tables_transitive() {
        // six is transitive, so the rewrite also adds an override under the
        // header-less `[tool.uv]` parent.
        assert_metadata_round_trips(&format!(
            "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"idna==3.7\"]\n\n{SUB_TABLE_SOURCES}"
        ));
    }

    #[test]
    fn restore_drops_sources_header_made_explicit_over_sub_tables_crlf() {
        assert_metadata_round_trips(
            &format!(
                "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\", \"idna==3.7\"]\n\n{SUB_TABLE_SOURCES}"
            )
            .replace('\n', "\r\n"),
        );
    }

    #[test]
    fn restore_keeps_user_sources_spellings() {
        let head = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\", \"idna==3.7\"]\n\n";
        for sources in [
            "[tool.uv.sources]\nidna = { url = \"https://h/idna-3.7-py3-none-any.whl\" }\n",
            "[tool.uv]\nsources.idna = { url = \"https://h/idna-3.7-py3-none-any.whl\" }\n",
            "[tool.uv]\nsources.idna.url = \"https://h/idna-3.7-py3-none-any.whl\"\n",
            "[tool.uv]\ndev-dependencies = []\n\n[tool.uv.sources.idna]\nurl = \"https://h/idna-3.7-py3-none-any.whl\"\n",
        ] {
            assert_metadata_round_trips(&format!("{head}{sources}"));
        }
    }

    #[test]
    fn spec_style_joins() {
        let clauses = vec![">=1".to_string(), "<2".to_string()];
        assert_eq!(SpecStyle::CANDIDATES[0].join(&clauses), ">=1, <2");
        assert_eq!(SpecStyle::CANDIDATES[3].join(&clauses), "<2,>=1");
    }
}

/// The hosted unwind re-derives each requirement entry's specifier from the
/// declaration uv lowered it from: by extra and marker when one name has
/// several specifiers (#606), through PEP 735 `include-group` (#473).
#[cfg(test)]
mod declaration_tests {
    use super::*;

    const UUID: &str = "e828efa5-5c6d-43f3-9909-03f5ac232b98";
    const HOSTED: &str = "https://patch.socket.dev/patch/pypi/six/1.16.0/g/e828efa5-5c6d-43f3-9909-03f5ac232b98/six-1.16.0-py2.py3-none-any.whl";

    /// A hosted entry for six with an optional `marker`.
    fn six(marker: Option<&str>) -> String {
        match marker {
            Some(m) => format!("{{ name = \"six\", marker = \"{m}\", url = \"{HOSTED}\" }}"),
            None => format!("{{ name = \"six\", url = \"{HOSTED}\" }}"),
        }
    }

    /// The registry entry the unwind should write back.
    fn spec(specifier: &str, marker: Option<&str>) -> String {
        match marker {
            Some(m) => {
                format!("{{ name = \"six\", marker = \"{m}\", specifier = \"{specifier}\" }}")
            }
            None => format!("{{ name = \"six\", specifier = \"{specifier}\" }}"),
        }
    }

    fn lock(requires_dist: &[String], requires_dev: &[(&str, Vec<String>)]) -> String {
        let mut out = String::from(
            "version = 1\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"uvp\"\n\
             version = \"0.1.0\"\nsource = { editable = \".\" }\n\n[package.metadata]\n",
        );
        out.push_str(&format!("requires-dist = [{}]\n", requires_dist.join(", ")));
        if !requires_dev.is_empty() {
            out.push_str("\n[package.metadata.requires-dev]\n");
            for (group, entries) in requires_dev {
                out.push_str(&format!("{group} = [{}]\n", entries.join(", ")));
            }
        }
        out
    }

    /// Run the requirement unwind for six over `lock_text` with `pyproject`.
    fn unwind(pyproject: &str, lock_text: &str) -> Result<String, String> {
        let mut doc: DocumentMut = lock_text.parse().unwrap();
        let meta = Metadata {
            rel: "pyproject.toml".into(),
            text: pyproject.into(),
            script: false,
            doc: pyproject.parse().unwrap(),
        };
        let hit = Hit {
            index: 0,
            uuid: UUID.into(),
            name: "six".into(),
            version: "1.16.0".into(),
        };
        let client = super::super::UpstreamClient::new(true);
        let ctx = Ctx {
            client: &client,
            origins: &[],
            bun_lockb: false,
        };
        restore_requirements(&mut doc, &hit, Some(&meta), &[], &ctx)?;
        Ok(doc.to_string())
    }

    const HEAD: &str =
        "[project]\nname = \"uvp\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\n";

    /// #411: the lock's `[manifest] overrides` record of a user's own
    /// `override-dependencies` pin gets its specifier back instead of being
    /// dropped as the rewrite's; the one the rewrite added (its pin under
    /// the ownership comment) is still dropped.
    #[test]
    fn manifest_override_of_a_user_pin_is_restored_not_dropped() {
        let lock_text = format!(
            "{}\n[manifest]\noverrides = [{}]\n",
            lock(
                &[spec("==2.8.2", None).replace("six", "python-dateutil")],
                &[]
            ),
            six(None)
        );
        let user = format!(
            "{HEAD}dependencies = [\"python-dateutil==2.8.2\"]\n\n[tool.uv]\n\
             override-dependencies = [\"six==1.16.0\"]\n"
        );
        let out = unwind(&user, &lock_text).unwrap();
        assert!(
            out.contains(&format!("overrides = [{}]", spec("==1.16.0", None))),
            "{out}"
        );
        let added = format!(
            "{HEAD}dependencies = [\"python-dateutil==2.8.2\"]\n\n[tool.uv]\n\
             override-dependencies = [\n    {}\n    \"six==1.16.0\",\n]\n",
            crate::utils::python_script::HOSTED_OVERRIDE_MARK
        );
        let out = unwind(&added, &lock_text).unwrap();
        assert!(!out.contains("[manifest]"), "{out}");
    }

    /// #606 (a): a pin in `dependencies` and a floor in an extra.
    #[test]
    fn dependencies_and_extra_with_different_specifiers() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six==1.16.0\", \"idna==3.7\"]\n\n\
             [project.optional-dependencies]\nextra = [\"six>=1.15\"]\n"
        );
        let idna = "{ name = \"idna\", specifier = \"==3.7\" }".to_string();
        let hosted = lock(
            &[idna.clone(), six(None), six(Some("extra == 'extra'"))],
            &[],
        );
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(
                &[
                    idna,
                    spec("==1.16.0", None),
                    spec(">=1.15", Some("extra == 'extra'"))
                ],
                &[]
            )
        );
    }

    /// A declaration-owned extra predicate can collide with uv's lowering
    /// of optional group membership. Different clauses must remain refused.
    #[test]
    fn declaration_owned_extra_predicates_keep_ambiguity() {
        for own in [
            "extra == 'x'",
            "'x' == extra",
            "extra != 'y'",
            "extra in 'x,y'",
            "extra not in 'y'",
            "(extra == 'x' or extra == 'y')",
        ] {
            let pyproject = format!(
                "{HEAD}dependencies = [\"six>=1.10; {own}\"]\n\n\
                 [project.optional-dependencies]\nx = [\"six==1.16.0\"]\n"
            );
            let marker = "extra == 'x'";
            let hosted = lock(&[six(Some(marker)), six(Some(marker))], &[]);
            let err = unwind(&pyproject, &hosted).unwrap_err();
            assert!(err.contains("different specifiers"), "{own}: {err}");
        }
    }

    /// Matching version clauses need no provenance inference, even when
    /// an explicit extra predicate and a lowered group have the same marker.
    #[test]
    fn declaration_owned_extra_with_agreed_clauses_restores() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six==1.16.0; 'x' == extra\"]\n\n\
             [project.optional-dependencies]\nx = [\"six==1.16.0\"]\n"
        );
        let marker = "extra == 'x'";
        let hosted = lock(&[six(Some(marker))], &[]);
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(&[spec("==1.16.0", Some(marker))], &[])
        );
    }

    /// #606 (c): two extras with different floors.
    #[test]
    fn two_extras_with_different_specifiers() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"idna==3.7\"]\n\n[project.optional-dependencies]\n\
             a = [\"six==1.16.0\"]\nb = [\"six>=1.10\"]\n"
        );
        let hosted = lock(&[six(Some("extra == 'a'")), six(Some("extra == 'b'"))], &[]);
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(
                &[
                    spec("==1.16.0", Some("extra == 'a'")),
                    spec(">=1.10", Some("extra == 'b'"))
                ],
                &[]
            )
        );
    }

    /// Extras sharing one specifier lower to one entry naming both.
    #[test]
    fn extras_merged_into_one_entry() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six>=1.10\"]\n\n[project.optional-dependencies]\n\
             a = [\"six==1.16.0\"]\nc = [\"six==1.16.0\"]\n"
        );
        let marker = "extra == 'a' or extra == 'c'";
        let hosted = lock(&[six(None), six(Some(marker))], &[]);
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(&[spec(">=1.10", None), spec("==1.16.0", Some(marker))], &[])
        );
    }

    /// #606 (e): marker-split specifiers in `dependencies`, in both of
    /// uv's spellings of a `python_version` marker.
    #[test]
    fn marker_split_dependencies() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"idna==3.7\", \"six>=1.10; python_version < \\\"3.10\\\"\", \
             \"six==1.16.0; python_version >= \\\"3.10\\\"\"]\n"
        );
        for (lt, ge) in [
            (
                "python_full_version < '3.10'",
                "python_full_version >= '3.10'",
            ),
            ("python_version < '3.10'", "python_version >= '3.10'"),
        ] {
            let hosted = lock(&[six(Some(lt)), six(Some(ge))], &[]);
            assert_eq!(
                unwind(&pyproject, &hosted).unwrap(),
                lock(&[spec(">=1.10", Some(lt)), spec("==1.16.0", Some(ge))], &[]),
                "{lt} / {ge}"
            );
        }
    }

    /// uv rewrites `<=` / `>` / `==` on `python_version` into
    /// `python_full_version` bounds.
    #[test]
    fn python_version_operators_match_uvs_rewrite() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six>=1.10; python_version <= '3.9'\", \
             \"six==1.16.0; python_version > '3.9' and sys_platform == 'linux'\", \
             \"six>=1.12; python_version == '3.12' and sys_platform != 'linux'\"]\n"
        );
        let le = "python_full_version < '3.10'";
        let gt = "python_full_version >= '3.10' and sys_platform == 'linux'";
        let eq = "python_full_version == '3.12.*' and sys_platform != 'linux'";
        let hosted = lock(&[six(Some(le)), six(Some(gt)), six(Some(eq))], &[]);
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(
                &[
                    spec(">=1.10", Some(le)),
                    spec("==1.16.0", Some(gt)),
                    spec(">=1.12", Some(eq))
                ],
                &[]
            )
        );
    }

    /// A marker inside an extra lowers to `<marker> and extra == '<x>'`.
    #[test]
    fn marker_inside_an_extra() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six==1.16.0\"]\n\n[project.optional-dependencies]\n\
             win = [\"six>=1.15; sys_platform == 'win32'\"]\n"
        );
        let marker = "sys_platform == 'win32' and extra == 'win'";
        let hosted = lock(&[six(None), six(Some(marker))], &[]);
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(&[spec("==1.16.0", None), spec(">=1.15", Some(marker))], &[])
        );
    }

    /// An entry no declaration lowers to is still refused.
    #[test]
    fn unmatched_marker_still_refuses() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six>=1.10; python_version < '3.10'\", \
             \"six==1.16.0; python_version >= '3.10'\"]\n"
        );
        let hosted = lock(&[six(Some("sys_platform == 'linux'"))], &[]);
        let err = unwind(&pyproject, &hosted).unwrap_err();
        assert!(err.contains("different specifiers"), "{err}");
    }

    /// A `dependencies` line with its own `extra == 'x'` marker lowers to
    /// the same marker as extra `x`'s member: with different specifiers,
    /// which entry mirrors which is not derivable, so the unwind refuses
    /// rather than restore both from one declaration.
    #[test]
    fn dependency_with_its_own_extra_marker_is_ambiguous() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six>=1.10; extra == 'x'\"]\n\n\
             [project.optional-dependencies]\nx = [\"six==1.16.0\"]\n"
        );
        let hosted = lock(&[six(Some("extra == 'x'")), six(Some("extra == 'x'"))], &[]);
        let err = unwind(&pyproject, &hosted).unwrap_err();
        assert!(err.contains("different specifiers"), "{err}");
    }

    /// Unambiguous when the dependency's own extra is not also declared.
    #[test]
    fn dependency_with_its_own_extra_marker() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"six>=1.10; extra == 'x'\"]\n\n\
             [project.optional-dependencies]\ny = [\"six==1.16.0\"]\n"
        );
        let hosted = lock(&[six(Some("extra == 'x'")), six(Some("extra == 'y'"))], &[]);
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(
                &[
                    spec(">=1.10", Some("extra == 'x'")),
                    spec("==1.16.0", Some("extra == 'y'"))
                ],
                &[]
            )
        );
    }

    /// #473: a group reaching six through `include-group`.
    #[test]
    fn include_group_member() {
        let pyproject = format!(
            "{HEAD}dependencies = [\"python-dateutil==2.8.2\"]\n\n[dependency-groups]\n\
             test = [\"six==1.16.0\"]\ndev = [\"idna==3.7\", {{include-group = \"test\"}}]\n"
        );
        let idna = "{ name = \"idna\", specifier = \"==3.7\" }".to_string();
        let dateutil = "{ name = \"python-dateutil\", specifier = \"==2.8.2\" }".to_string();
        let hosted = lock(
            &[dateutil.clone()],
            &[
                ("dev", vec![idna.clone(), six(None)]),
                ("test", vec![six(None)]),
            ],
        );
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(
                &[dateutil],
                &[
                    ("dev", vec![idna, spec("==1.16.0", None)]),
                    ("test", vec![spec("==1.16.0", None)]),
                ]
            )
        );
    }

    /// Nested and cyclic `include-group`s (uv rejects a cycle, but the
    /// unwind must not loop on one) and PEP 735 group-name normalization.
    #[test]
    fn nested_and_cyclic_include_groups() {
        let pyproject = format!(
            "{HEAD}dependencies = []\n\n[dependency-groups]\n\
             Unit_Tests = [\"six==1.16.0\", {{include-group = \"all\"}}]\n\
             qa = [{{include-group = \"unit-tests\"}}]\n\
             all = [{{include-group = \"qa\"}}]\n"
        );
        let hosted = lock(&[], &[("all", vec![six(None)]), ("qa", vec![six(None)])]);
        assert_eq!(
            unwind(&pyproject, &hosted).unwrap(),
            lock(
                &[],
                &[
                    ("all", vec![spec("==1.16.0", None)]),
                    ("qa", vec![spec("==1.16.0", None)]),
                ]
            )
        );
    }
}
