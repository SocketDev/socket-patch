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
//!   no sibling, or several registries, refuses;
//! * `sdist` / `wheels` were replaced by the patched wheel (pylock: an
//!   `archive`) — re-derived from PyPI's JSON API in the artifact shape a
//!   sibling registry package shows (which of `size` / `upload-time` /
//!   `hashes` this uv release records, one wheel per line or not). uv keeps
//!   only the wheels its `requires-python` and environments can install, so
//!   a release with any wheel that is not pure Python 3 is refused, as is a
//!   lock whose `[options]` / `[tool.uv]` filter files (`exclude-newer`,
//!   `no-binary`, `no-build`);
//! * `[package.metadata]` (the patched wheel's metadata) was added — removed;
//! * dependents' `{ name, source = { registry = R } }` references were
//!   repointed at the url — pointed back;
//! * the root package's `requires-dist` / `requires-dev` entries, the
//!   `[manifest]` `constraints` / `build-constraints` / `requirements` and
//!   `overrides` entries lost their `specifier` for the url — re-derived
//!   from the paired metadata's declarations in uv's spelling (a
//!   multi-clause specifier only when another entry of the lock shows how
//!   this uv joins clauses), and an `overrides` entry the rewrite added for
//!   a transitive dependency is removed with its `override-dependencies`
//!   line;
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
    /// Artifact table keys, in order (`url`, `hash`, `size`, …).
    keys: Vec<String>,
    /// `upload-time` is a TOML datetime (pylock), not a string (uv.lock).
    datetime: bool,
    /// `wheels` puts one entry per line.
    multiline: bool,
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
        let restore = if pep751 {
            restore_pylock_entry(&mut doc, hit, &shape, artifacts)
        } else {
            restore_uv_entry(&mut doc, hit, &shape, artifacts, ctx)
                .and_then(|()| restore_requirements(&mut doc, hit, metadata.as_ref(), &styles, ctx))
        };
        if let Err(why) = restore {
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
    let mut registries: BTreeSet<&str> = BTreeSet::new();
    let mut shape: Option<(Vec<String>, bool, bool, Vec<String>)> = None;
    for (i, package) in packages.iter().enumerate() {
        if hit_indices.contains(&i) {
            continue;
        }
        let registry = if pep751 {
            package.get("index").and_then(Item::as_str)
        } else {
            UvSource::of(package).and_then(UvSource::registry)
        };
        let Some(registry) = registry else {
            continue;
        };
        registries.insert(registry);
        if shape.is_some() {
            continue;
        }
        let first = package
            .get("wheels")
            .and_then(Item::as_array)
            .and_then(|a| a.iter().next())
            .or_else(|| package.get("sdist").and_then(Item::as_value));
        let Some(artifact) = first.and_then(Value::as_inline_table) else {
            continue;
        };
        let keys: Vec<String> = artifact.iter().map(|(k, _)| k.to_string()).collect();
        let datetime = artifact
            .get("upload-time")
            .is_some_and(|v| v.as_datetime().is_some());
        let multiline = package
            .get("wheels")
            .and_then(Item::as_array)
            .is_none_or(|a| a.to_string().contains('\n'));
        let package_keys = package.iter().map(|(k, _)| k.to_string()).collect();
        shape = Some((keys, datetime, multiline, package_keys));
    }
    let registry = match registries.len() {
        0 => {
            return Err(
                "no sibling registry package shows the registry and artifact fields this uv \
                 release records"
                    .to_string(),
            )
        }
        1 => registries
            .into_iter()
            .next()
            .unwrap_or_default()
            .to_string(),
        _ => {
            return Err(format!(
                "the lock's packages come from several registries ({}); the entry's is \
                 ambiguous",
                registries.into_iter().collect::<Vec<_>>().join(", ")
            ))
        }
    };
    if !is_pypi_simple(&registry) {
        return Err(format!(
            "the lock's registry {registry} is not PyPI, so its release files cannot be \
             re-derived"
        ));
    }
    let (keys, datetime, multiline, package_keys) = shape.ok_or(
        "no sibling registry package records an artifact, so which artifact fields this uv \
         release records is not derivable",
    )?;
    let known = ["url", "hash", "hashes", "size", "upload-time", "name"];
    if let Some(unknown) = keys.iter().find(|k| !known.contains(&k.as_str())) {
        return Err(format!(
            "sibling artifacts carry an unknown field `{unknown}`"
        ));
    }
    Ok(Shape {
        registry,
        keys,
        datetime,
        multiline,
        package_keys,
    })
}

/// uv's millisecond timestamp of a PyPI `upload_time_iso_8601`
/// (`2023-10-17T17:46:21.184066Z` → `2023-10-17T17:46:21.184Z`; trailing
/// fractional zeros are not printed).
fn upload_time(iso: &str) -> Option<String> {
    let iso = iso.strip_suffix('Z')?;
    let (seconds, fraction) = iso.split_once('.').unwrap_or((iso, ""));
    if seconds.len() != 19 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
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
            "upload-time" => {
                let time = file
                    .upload_time
                    .as_deref()
                    .and_then(upload_time)
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

/// `(sdist, wheels)` values for a release, in the sibling shape.
fn render_artifacts(
    release: &[PypiFile],
    shape: &Shape,
) -> Result<(Option<Value>, Option<Value>), String> {
    if !universal_release(release) {
        return Err(
            "the release ships platform- or interpreter-specific wheels, and which of them uv \
             kept (requires-python and environment filtering) is not derivable"
                .to_string(),
        );
    }
    let (wheels, sdists): (Vec<&PypiFile>, Vec<&PypiFile>) =
        release.iter().partition(|f| f.filename.ends_with(".whl"));
    let sdist = match sdists.as_slice() {
        [] => None,
        [one] => Some(render_artifact(one, shape)?),
        _ => return Err("the release has several source distributions".to_string()),
    };
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
    let parse = |text: Option<String>| -> Result<Option<Value>, String> {
        text.map(|t| toml_value(&t).ok_or("an artifact does not render as TOML".to_string()))
            .transpose()
    };
    Ok((parse(sdist)?, parse(wheels)?))
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
    (sdist, wheels): (Option<Value>, Option<Value>),
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
        package.insert("sdist", Item::Value(sdist));
    }
    if let Some(wheels) = wheels {
        package.insert("wheels", Item::Value(wheels));
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
    (sdist, wheels): (Option<Value>, Option<Value>),
) -> Result<(), String> {
    let package = doc
        .get_mut("packages")
        .and_then(Item::as_array_of_tables_mut)
        .and_then(|p| p.get_mut(hit.index))
        .ok_or("the package entry vanished")?;
    package.remove("archive");
    package.insert("index", toml_edit::value(shape.registry.clone()));
    if let Some(sdist) = sdist {
        package.insert("sdist", Item::Value(sdist));
    }
    if let Some(wheels) = wheels {
        package.insert("wheels", Item::Value(wheels));
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

/// Every declaration string `declared` covers in the metadata.
fn declarations<'d>(meta: &'d Metadata, declared: Declared<'_>) -> Vec<&'d str> {
    let doc = &meta.doc;
    let uv = tool_uv(doc);
    match declared {
        Declared::Dist => {
            let project = doc.get("project");
            let mut out = strings(project.and_then(|p| p.get("dependencies")));
            if let Some(extras) = project
                .and_then(|p| p.get("optional-dependencies"))
                .and_then(Item::as_table_like)
            {
                for (_, group) in extras.iter() {
                    out.extend(strings(Some(group)));
                }
            }
            out
        }
        Declared::Dev(group) => {
            let mut out = strings(
                doc.get("dependency-groups")
                    .and_then(Item::as_table_like)
                    .and_then(|g| g.get(group)),
            );
            if group == "dev" {
                out.extend(strings(uv.and_then(|u| u.get("dev-dependencies"))));
            }
            out
        }
        Declared::Manifest("requirements") => strings(doc.get("dependencies")),
        Declared::Manifest(key) => {
            let key = match key {
                "constraints" => "constraint-dependencies",
                "build-constraints" => "build-constraint-dependencies",
                "overrides" => "override-dependencies",
                other => other,
            };
            strings(uv.and_then(|u| u.get(key)))
        }
    }
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
                if let Ok(Some(clauses)) = declared_clauses(meta, declared, name) {
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

/// The one clause list every declaration of `name` in `declared` agrees
/// on; `Ok(None)` when nothing declares it.
fn declared_clauses(
    meta: &Metadata,
    declared: Declared<'_>,
    name: &str,
) -> Result<Option<Vec<String>>, String> {
    let canon = canonicalize_pypi_name(name);
    let mut found: Option<Vec<String>> = None;
    for spec in declarations(meta, declared) {
        if canonicalize_pypi_name(pep508_name(spec)) != canon {
            continue;
        }
        let clauses = spec_clauses(spec)?;
        match &found {
            Some(prior) if *prior != clauses => {
                return Err(format!(
                    "{} declares {name} with different specifiers; which one each lock entry \
                     mirrors is not derivable",
                    meta.rel
                ))
            }
            _ => found = Some(clauses),
        }
    }
    Ok(found)
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
        let clauses = declared_clauses(meta, declared, &hit.name)?.ok_or_else(|| {
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
    // the metadata's `override-dependencies` holds exactly the pin it adds.
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

/// The index of the `override-dependencies` entry the rewrite adds for a
/// transitive `hit` (`<name>==<version>`), when present.
fn pushed_override(meta: &Metadata, hit: &Hit) -> Option<usize> {
    if declares_directly(meta, hit) {
        return None;
    }
    let want = format!("{}=={}", hit.name, hit.version);
    strings(tool_uv(&meta.doc).and_then(|u| u.get("override-dependencies")))
        .iter()
        .position(|spec| {
            let compact: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
            canonicalize_pypi_name(pep508_name(&compact)) == hit.name
                && compact[pep508_name(&compact).len()..] == want[hit.name.len()..]
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
    if tool.is_empty() {
        meta.doc.remove("tool");
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_times_are_milliseconds_without_trailing_zeros() {
        assert_eq!(
            upload_time("2023-10-17T17:46:21.184066Z").as_deref(),
            Some("2023-10-17T17:46:21.184Z")
        );
        assert_eq!(
            upload_time("2023-10-17T17:46:21.100Z").as_deref(),
            Some("2023-10-17T17:46:21.1Z")
        );
        assert_eq!(
            upload_time("2023-10-17T17:46:21.000400Z").as_deref(),
            Some("2023-10-17T17:46:21Z")
        );
        assert_eq!(
            upload_time("2023-10-17T17:46:21Z").as_deref(),
            Some("2023-10-17T17:46:21Z")
        );
        assert_eq!(upload_time("2023-10-17 17:46"), None);
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

    #[test]
    fn spec_style_joins() {
        let clauses = vec![">=1".to_string(), "<2".to_string()];
        assert_eq!(SpecStyle::CANDIDATES[0].join(&clauses), ">=1, <2");
        assert_eq!(SpecStyle::CANDIDATES[3].join(&clauses), "<2,>=1");
    }
}
