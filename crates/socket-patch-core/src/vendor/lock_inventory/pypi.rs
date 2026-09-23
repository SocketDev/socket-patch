//! pypi locks (uv / PEP 751 / PEP 723 script locks, poetry, pdm, Pipfile,
//! requirements): the registry views, with the Pipfile.lock entry walk
//! lockfile discovery shares ([`pipfile_lock_entries`]).

use std::path::Path;

use serde_json::Value;
use toml_edit::{DocumentMut, Item, TableLike};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::read_regular_to_string;
use crate::utils::purl::{percent_decode_purl_component, pypi_purl};
use crate::utils::python_lock::{lock_package_collection, package_artifacts, UvSource};
use crate::utils::requirements::archive_filename_coords;

use crate::utils::digest::{sha256_hex, sha256_prefixed};

use super::{dedup_prefer_integrity, http_url, LockIntegrity, LockfileEntry, SourceKind};

// pypi purls and lock entries compare in PEP 503 normalized form
// (`Foo._Bar` → `foo-bar`) — see `canonicalize_pypi_name`.

// ── entry model ──

/// One package entry of a parsed `Pipfile.lock` (see
/// [`pipfile_lock_entries`]).
pub(crate) struct PipfileLockEntry<'a> {
    /// `default`, `develop`, or a custom Pipfile category.
    pub(crate) category: &'a str,
    /// The package name as the lock spells it.
    pub(crate) name: &'a str,
    pub(crate) entry: &'a serde_json::Map<String, Value>,
}

impl<'a> PipfileLockEntry<'a> {
    /// The `file` / `path` references the entry carries, in that order
    /// (Pipenv writes at most one; Pipenv 7.x–2017 spell the hosted one
    /// `path`).
    pub(crate) fn references(&self) -> Vec<&'a str> {
        ["file", "path"]
            .iter()
            .filter_map(|key| self.entry.get(*key).and_then(Value::as_str))
            .collect()
    }

    /// Whether the entry installs from a VCS checkout or an editable
    /// source — nothing registry-shaped.
    pub(crate) fn is_vcs(&self) -> bool {
        ["git", "hg", "svn", "bzr", "editable"]
            .iter()
            .any(|key| self.entry.contains_key(*key))
    }

    /// The version of an exact `version: "==X"` pin (trimmed; possibly
    /// empty), `None` for a range or no `version` at all.
    pub(crate) fn exact_pin(&self) -> Option<&'a str> {
        self.entry
            .get("version")
            .and_then(Value::as_str)
            .and_then(|v| v.trim().strip_prefix("=="))
            .map(str::trim)
    }

    /// The raw hex of every `hashes: ["sha256:<hex>", …]` digest
    /// (unvalidated).
    pub(crate) fn sha256_hashes(&self) -> Vec<&'a str> {
        self.entry
            .get("hashes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter_map(|h| h.strip_prefix("sha256:"))
            .collect()
    }
}

/// Parse a `Pipfile.lock`. Leading UTF-8 BOMs (Windows editors) are not
/// JSON and are skipped — the one BOM policy of every Pipfile.lock reader
/// (this inventory, the hosted Pipenv rewriter, lockfile discovery).
pub(crate) fn parse_pipfile_lock(text: &str) -> serde_json::Result<Value> {
    serde_json::from_str(text.trim_start_matches('\u{feff}'))
}

/// Every package entry of a parsed `Pipfile.lock` (pipfile-spec 6): each
/// category other than `_meta` maps `name → {…}`; non-object categories
/// and entries are skipped. `None` when the document is not a JSON object.
/// The one walk the inventory and lockfile discovery
/// (`vex::discover::pypi_other`) share.
pub(crate) fn pipfile_lock_entries(doc: &Value) -> Option<Vec<PipfileLockEntry<'_>>> {
    let mut out = Vec::new();
    for (category, entries) in doc.as_object()? {
        if category == "_meta" {
            continue;
        }
        for (name, entry) in entries.as_object().into_iter().flatten() {
            if let Some(entry) = entry.as_object() {
                out.push(PipfileLockEntry {
                    category,
                    name,
                    entry,
                });
            }
        }
    }
    Some(out)
}

/// The coordinates a hosted pypi artifact url names — the ONE hosted-url
/// grammar the inventory ([`socket_reference_coords`]) and lockfile
/// discovery (`vex::discover::pypi_other`) read.
pub(crate) struct HostedArtifactUrl {
    /// The url's `<name>` level, else the artifact's distribution (as
    /// spelled; callers canonicalize).
    pub(crate) name: String,
    pub(crate) version: String,
    /// The `<uuid>` level of a
    /// `…/patch/pypi/<name>/<version>/<grant>/<uuid>/<artifact>` tail;
    /// `None` when the path has no such tail.
    pub(crate) uuid_level: Option<String>,
}

/// Read a hosted pypi artifact url: parsed as a url (any scheme), path
/// segments percent-decoded, the artifact leaf a wheel or sdist
/// ([`archive_filename_coords`]), and the patch-server tail matched from
/// the END (a configured origin may carry a path prefix) — whose
/// coordinates must agree with the artifact's. `Err` is the user-facing
/// reason.
pub(crate) fn hosted_artifact_url(url: &str) -> Result<HostedArtifactUrl, String> {
    let parsed = reqwest::Url::parse(url.trim()).map_err(|e| format!("{url:?}: {e}"))?;
    let segments: Vec<String> = parsed
        .path_segments()
        .into_iter()
        .flatten()
        .map(|s| percent_decode_purl_component(s).into_owned())
        .collect();
    let leaf = segments.last().map(String::as_str).unwrap_or("");
    let Some((dist, leaf_version)) = archive_filename_coords(leaf) else {
        return Err(format!(
            "{url:?} does not name a Python wheel or sdist artifact"
        ));
    };
    let n = segments.len();
    if n >= 7 && segments[n - 7] == "patch" && segments[n - 6] == "pypi" {
        let (name, version) = (&segments[n - 5], &segments[n - 4]);
        if canonicalize_pypi_name(name) != canonicalize_pypi_name(dist) || version != leaf_version {
            return Err(format!(
                "{url:?}: the url's coordinates {name}=={version} disagree with its artifact \
                 {leaf:?}"
            ));
        }
        return Ok(HostedArtifactUrl {
            name: name.clone(),
            version: version.clone(),
            uuid_level: Some(segments[n - 2].clone()),
        });
    }
    Ok(HostedArtifactUrl {
        name: dist.to_string(),
        version: leaf_version.to_string(),
        uuid_level: None,
    })
}

// ── registry view ──

/// Inventory the pypi lock the project carries. Fetchable resolution
/// (URL + sha256 of a pure `py3-none-any` wheel) comes from `uv.lock`;
/// `poetry.lock` and `--hash`-pinned `requirements.txt` contribute
/// DISCOVERY-only entries (no recorded URL; platform-independent wheel
/// choice is not derivable offline). `pdm.lock` contributes discovery-only
/// entries. Pipfile.lock contributes entries whose integrity is its digest SET
/// (see `inventory_pipfile_lock`).
pub(super) async fn inventory_pypi_locks(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    inventory_pypi_locks_raw(project_root)
        .await
        .map(dedup_prefer_integrity)
}

/// [`inventory_pypi_locks`] before its collapse: every instance
/// ([`super::inventory_project_every_lock`]).
pub(super) async fn inventory_pypi_locks_raw(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let mut out = Vec::new();
    let mut found = false;
    let mut uv_lock = false;
    if let Ok(paths) = crate::utils::python_lock::python_lock_paths(project_root) {
        for path in paths {
            let Ok(text) = read_regular_to_string(&project_root.join(&path)).await else {
                continue;
            };
            if let Some(entries) = python_lock_inventory(&text) {
                found = true;
                uv_lock |= path == "uv.lock";
                out.extend(entries);
            }
        }
    }
    // A PARSEABLE uv.lock stays the EXCLUSIVE project inventory (its
    // precedence over poetry.lock / requirements.txt predates standalone-lock
    // support). Exclusivity is keyed on parse SUCCESS, not on the file's
    // presence: an unparseable uv.lock contributed nothing above, so it falls
    // through to poetry.lock / requirements.txt exactly like a package-less
    // poetry.lock does (`depless_poetry_lock_falls_through_to_requirements`).
    // Keying on presence would hide every requirements pin behind a corrupt
    // lock AND diverge from hosted, which skips an unparseable uv.lock with
    // `redirect_uv_lock_unsupported` and still reads the other pins. A
    // PEP 723 script lock or a PEP 751 lock is scoped to its own install,
    // so it SUPPLEMENTS the project's tool lock: a stray `tool.py.lock`
    // must not hide every poetry.lock / requirements.txt pin from scan's
    // lockfile supplement and vendor's lookup.
    if !uv_lock {
        if let Some(entries) = inventory_poetry_lock(project_root).await {
            found = true;
            out.extend(entries);
        } else if let Some(entries) = inventory_pdm_lock(project_root).await {
            found = true;
            out.extend(entries);
        } else {
            // Pipfile.lock and requirements.txt are read TOGETHER: Pipenv
            // projects routinely ship both (`pipenv requirements` exports the
            // same pins — deduplicated below), and a stale Pipfile.lock left in
            // a requirements project must not hide the pins the project
            // actually installs from (the hosted rewriter judges each file on
            // its own).
            if let Some(entries) = inventory_pipfile_lock(project_root).await {
                found = true;
                out.extend(entries);
            }
            if let Some(entries) = inventory_requirements_txt(project_root).await {
                found = true;
                out.extend(entries);
            }
        }
    }
    found.then_some(out)
}

/// The first fetchable pure-Python wheel of a lock package — `archive`,
/// then `wheels[]` / `wheel` (read with the shared lock model,
/// [`crate::utils::python_lock::package_artifacts`]): an http(s) url ending
/// `-none-any.whl` with a sha256 pin, as `(url, sha256)`.
fn python_package_archive(package: &dyn TableLike) -> Option<(String, String)> {
    package_artifacts(package, &["archive", "wheels", "wheel"])
        .into_iter()
        .find_map(|artifact| {
            let url = artifact.url?;
            if !url.split(['?', '#']).next()?.ends_with("-none-any.whl") {
                return None;
            }
            Some((http_url(url)?, artifact.sha256?))
        })
}

pub(super) fn python_lock_inventory(text: &str) -> Option<Vec<LockfileEntry>> {
    let document: DocumentMut = text.parse().ok()?;
    let (collection, pep751) = lock_package_collection(&document);
    // Only the lock formats the fetch layer understands.
    let supported = if pep751 {
        document.get("lock-version").and_then(Item::as_str) == Some("1.0")
    } else {
        document.get("version").and_then(Item::as_integer) == Some(1)
    };
    if !supported {
        return None;
    }
    let mut out = Vec::new();
    let packages = document.get(collection)?.as_array_of_tables()?;
    for package in packages.iter() {
        let Some(name) = package
            .get("name")
            .and_then(Item::as_str)
            .map(canonicalize_pypi_name)
        else {
            continue;
        };
        let Some(version) = package.get("version").and_then(Item::as_str) else {
            continue;
        };
        let Some(purl) = pypi_purl(&name, version) else {
            continue;
        };
        let remote = if pep751 {
            !package.contains_key("vcs")
                && !package.contains_key("directory")
                && !package
                    .get("archive")
                    .and_then(Item::as_table_like)
                    .is_some_and(|archive| archive.contains_key("path"))
        } else {
            UvSource::of(package).is_some_and(UvSource::is_remote)
        };
        if !remote {
            continue;
        }
        let (resolved, integrity) = match python_package_archive(package) {
            Some((url, sha)) => (Some(url), LockIntegrity::Sha256Hex(sha)),
            None => (None, LockIntegrity::None),
        };
        out.push(LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            purl,
            name,
            version: version.to_string(),
            resolved,
            integrity,
        });
    }
    Some(out)
}

/// poetry.lock: `[[package]]` tables with `name`/`version`. The lock records
/// file hashes but no URLs and no platform choice, so an entry carries the
/// sha256 of the package's pure-Python (`-none-any.whl`) wheel when the lock
/// lists one — its own `files = [...]` (lock 2.x) or its `[metadata.files]`
/// entry (lock 1.0/1.1), read through the shared poetry lock helpers — and
/// the pypi fetcher then resolves the matching file through PyPI's JSON
/// API; it stays discovery-only otherwise (Poetry 0.12's
/// `[metadata.hashes]` lists bare digests without filenames, so no wheel
/// can be chosen there). A lock that is not TOML contributes nothing.
async fn inventory_poetry_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("poetry.lock"))
        .await
        .ok()?;
    let document: DocumentMut = text.parse().ok()?;
    let pure_wheel_sha = |files: Vec<&dyn TableLike>| {
        files.into_iter().find_map(|entry| {
            let file = entry.get("file")?.as_str()?;
            if !file.ends_with("-none-any.whl") {
                return None;
            }
            sha256_prefixed(entry.get("hash")?.as_str()?)
        })
    };
    let mut out = Vec::new();
    for (name, version, purl, package) in toml_package_coords(&document) {
        let integrity = pure_wheel_sha(crate::utils::poetry_lock::package_files(package))
            .or_else(|| pure_wheel_sha(crate::utils::poetry_lock::metadata_files(&document, &name)))
            .map(LockIntegrity::Sha256Hex)
            .unwrap_or(LockIntegrity::None);
        out.push(LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            purl,
            name,
            version,
            resolved: None,
            integrity,
        });
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// `(canonical name, version, purl, table)` of every path-safe `[[package]]`
/// of a poetry.lock / pdm.lock document.
fn toml_package_coords(document: &DocumentMut) -> Vec<(String, String, String, &toml_edit::Table)> {
    let Some(packages) = document.get("package").and_then(Item::as_array_of_tables) else {
        return Vec::new();
    };
    packages
        .iter()
        .filter_map(|package| {
            let name = canonicalize_pypi_name(package.get("name")?.as_str()?);
            let version = package.get("version")?.as_str()?.to_string();
            let purl = pypi_purl(&name, &version)?;
            Some((name, version, purl, package))
        })
        .collect()
}

/// `https://pypi.org/simple`, `https://pypi.python.org/simple`,
/// `https://files.pythonhosted.org/…`: the public index PyPI's JSON API
/// describes.
pub(super) fn is_public_pypi_url(url: &str) -> bool {
    let host = url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .unwrap_or("")
        .to_ascii_lowercase();
    let host = host.rsplit('@').next().unwrap_or(&host);
    matches!(
        host,
        "pypi.org" | "www.pypi.org" | "pypi.python.org" | "files.pythonhosted.org"
    )
}

/// The `(canonical name, version)` a Socket-written Pipfile.lock reference
/// stands for: a hosted url with the patch-server tail
/// `…/patch/pypi/<name>/<version>/<grant>/<uuid>/<artifact>[#…]` (the shared
/// [`hosted_artifact_url`] grammar — any scheme, a path-prefixed origin,
/// a wheel or sdist leaf) or a root-anchored vendored path
/// `[./].socket/vendor/pypi/<uuid>/<wheel>` (coordinates from the shared
/// vendored-leaf table, [`crate::vendor::path::leaf_to_purl`]). `None` for
/// a user's own file/path reference.
pub(super) fn socket_reference_coords(reference: &str) -> Option<(String, String)> {
    if reference.contains("://") {
        let url = hosted_artifact_url(reference).ok()?;
        url.uuid_level.as_ref()?;
        return Some((canonicalize_pypi_name(&url.name), url.version));
    }
    let rel = reference.split('#').next().unwrap_or(reference);
    if !rel
        .trim_start_matches("./")
        .starts_with(".socket/vendor/pypi/")
    {
        return None;
    }
    let parts = crate::vendor::path::parse_vendor_path(rel)?;
    let purl = crate::vendor::path::leaf_to_purl("pypi", &parts.leaf)?;
    let (name, version) = purl.strip_prefix("pkg:pypi/")?.rsplit_once('@')?;
    if !version.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    Some((canonicalize_pypi_name(name), version.to_string()))
}

/// Pipfile.lock (pipfile-spec 6): every category other than `_meta` holds
/// `name: {"version": "==X", "hashes": ["sha256:<hex>", …], …}` entries.
/// Registry pins (`==` version) become entries whose integrity is the SET of
/// recorded digests — Pipenv lists every release file's hash without
/// filenames, so the pure-Python wheel is selected by digest at fetch time
/// ([`LockIntegrity::Sha256AnyOf`]). VCS / path / file / editable sources and
/// range pins are skipped (nothing registry-shaped to vendor over), as are
/// our own already-wired file references. An unparseable lock contributes
/// nothing, so the caller falls through to requirements.txt like an absent
/// lock would.
async fn inventory_pipfile_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("Pipfile.lock"))
        .await
        .ok()?;
    let value = parse_pipfile_lock(&text).ok()?;
    let root = value.as_object()?;
    // Digests are only fetchable through PyPI's JSON API when the lock
    // resolves from PyPI: a lock whose `_meta.sources` name only private
    // indexes must not leak its package names to pypi.org (and would not find
    // its files there anyway) — its entries stay discovery-only.
    let public_index = root
        .get("_meta")
        .and_then(|m| m.get("sources"))
        .and_then(serde_json::Value::as_array)
        .is_none_or(|sources| {
            sources.is_empty()
                || sources.iter().any(|source| {
                    source
                        .get("url")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(is_public_pypi_url)
                })
        });
    let mut out = Vec::new();
    for pkg in pipfile_lock_entries(&value)? {
        // Socket's own references (a hosted `file` URL, a vendored
        // `./.socket/vendor/pypi/<uuid>/<wheel>` path) stay DISCOVERABLE
        // as the package they replace, so a re-scan of an already
        // redirected lock-only checkout still lists (and re-confirms /
        // attests) it instead of reporting zero packages.
        if let Some(reference) = pkg.references().first() {
            if let Some((n, v)) = socket_reference_coords(reference) {
                if let Some(purl) = pypi_purl(&n, &v) {
                    out.push(LockfileEntry {
                        ecosystem: "pypi",
                        source_kind: SourceKind::Unspecified,
                        purl,
                        name: n,
                        version: v,
                        resolved: None,
                        integrity: LockIntegrity::None,
                    });
                }
            }
            continue;
        }
        if pkg.is_vcs() {
            continue;
        }
        let Some(version) = pkg.exact_pin().filter(|v| !v.is_empty()) else {
            continue;
        };
        let n = canonicalize_pypi_name(pkg.name);
        let Some(purl) = pypi_purl(&n, version) else {
            continue;
        };
        let hashes: Vec<String> = pkg
            .sha256_hashes()
            .into_iter()
            .filter_map(sha256_hex)
            .collect();
        let integrity = if hashes.is_empty() || !public_index {
            LockIntegrity::None
        } else {
            LockIntegrity::Sha256AnyOf(hashes)
        };
        out.push(LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            purl,
            name: n,
            version: version.to_string(),
            resolved: None,
            integrity,
        });
    }
    Some(out)
}

/// `pdm.lock`: `[[package]]` blocks with `name`/`version`, DISCOVERY-only. This
/// surfaces the project's PyPI coordinates so a hosted lock-only checkout (no
/// installed package) can be redirected — the hosted rewrite pins the API
/// grant's URL and does not need a lock-derived hash. It stays discovery-only
/// (`LockIntegrity::None`) so vendored keeps refusing a lock-only checkout
/// (`vendor_fetch_unverifiable`): vendoring rebuilds the wheel from the
/// INSTALLED package, and PDM installs into a `__pypackages__` tree the crawler
/// does not probe, so a lock-only vendored path would not survive a re-scan.
async fn inventory_pdm_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("pdm.lock"))
        .await
        .ok()?;
    let document: DocumentMut = text.parse().ok()?;
    let out: Vec<LockfileEntry> = toml_package_coords(&document)
        .into_iter()
        .map(|(name, version, purl, _)| LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            purl,
            name,
            version,
            resolved: None,
            integrity: LockIntegrity::None,
        })
        .collect();
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// requirements.txt with exact `==` pins — discovery only. Read as pip's
/// logical lines with the shared requirements lexer
/// ([`crate::utils::requirements`]: continuations joined, comments cut, one
/// leading BOM dropped), the same one the planner and discovery use.
async fn inventory_requirements_txt(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("requirements.txt"))
        .await
        .ok()?;
    let mut out = Vec::new();
    for line in crate::utils::requirements::logical_lines(&text) {
        let t = crate::utils::requirements::strip_comment(&line.text).trim();
        if t.is_empty() || t.starts_with('-') {
            continue;
        }
        // `name==version` (extras, env markers, hash options stripped) —
        // the shared exact-pin rule discovery reads requirements with.
        let Some((raw_name, version)) = crate::utils::requirements::exact_pin(t) else {
            continue;
        };
        let name = canonicalize_pypi_name(raw_name);
        let version = version.to_string();
        let Some(purl) = pypi_purl(&name, &version) else {
            continue;
        };
        out.push(LockfileEntry {
            ecosystem: "pypi",
            source_kind: SourceKind::Unspecified,
            purl,
            name,
            version,
            resolved: None,
            integrity: LockIntegrity::None,
        });
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}
