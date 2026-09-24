//! pypi locks (uv / pylock, poetry, pdm, Pipfile, requirements): the
//! registry views.

use std::collections::HashMap;
use std::path::Path;

use toml_edit::{DocumentMut, Item, TableLike, Value as TomlValue};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::patch::path_safety;
use crate::utils::fs::read_regular_to_string;

use super::{dedup_prefer_integrity, http_url, is_hex_of_len, LockIntegrity, LockfileEntry};

// pypi purls and lock entries compare in PEP 503 normalized form
// (`Foo._Bar` → `foo-bar`) — see `canonicalize_pypi_name`.

/// Inventory the pypi lock the project carries. Fetchable resolution
/// (URL + sha256 of a pure `py3-none-any` wheel) comes from `uv.lock`;
/// `poetry.lock` and `--hash`-pinned `requirements.txt` contribute
/// DISCOVERY-only entries (no recorded URL; platform-independent wheel
/// choice is not derivable offline). `pdm.lock` contributes discovery-only
/// entries. Pipfile.lock contributes entries whose integrity is its digest SET
/// (see `inventory_pipfile_lock`).
pub(super) async fn inventory_pypi_locks(project_root: &Path) -> Option<Vec<LockfileEntry>> {
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
    found.then(|| dedup_prefer_integrity(out))
}

fn python_archive(archive: &dyn TableLike) -> Option<(String, String)> {
    let url = archive.get("url")?.as_str()?;
    if !url.split(['?', '#']).next()?.ends_with("-none-any.whl") {
        return None;
    }
    let sha = archive
        .get("hash")
        .and_then(Item::as_str)
        .and_then(|value| value.strip_prefix("sha256:"))
        .or_else(|| {
            archive
                .get("hashes")?
                .as_table_like()?
                .get("sha256")?
                .as_str()
        })?;
    if !is_hex_of_len(sha, 64) {
        return None;
    }
    Some((http_url(url)?, sha.to_ascii_lowercase()))
}

fn python_package_archive(package: &dyn TableLike) -> Option<(String, String)> {
    if let Some(archive) = package
        .get("archive")
        .and_then(Item::as_table_like)
        .and_then(python_archive)
    {
        return Some(archive);
    }
    if let Some(wheels) = package.get("wheels").and_then(Item::as_array) {
        for wheel in wheels.iter().filter_map(TomlValue::as_inline_table) {
            if let Some(archive) = python_archive(wheel) {
                return Some(archive);
            }
        }
    }
    if let Some(wheels) = package.get("wheel").and_then(Item::as_array_of_tables) {
        for wheel in wheels.iter() {
            if let Some(archive) = python_archive(wheel) {
                return Some(archive);
            }
        }
    }
    None
}

pub(super) fn python_lock_inventory(text: &str) -> Option<Vec<LockfileEntry>> {
    let document: DocumentMut = text.parse().ok()?;
    let pep751 = document.get("lock-version").is_some();
    let collection = if pep751 {
        if document.get("lock-version").and_then(Item::as_str) != Some("1.0") {
            return None;
        }
        "packages"
    } else {
        if document.get("version").and_then(Item::as_integer) != Some(1) {
            return None;
        }
        if document.contains_key("distribution") {
            "distribution"
        } else {
            "package"
        }
    };
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
        if !path_safety::is_safe_single_segment(&name)
            || !path_safety::is_safe_single_segment(version)
        {
            continue;
        }
        let remote = if pep751 {
            !package.contains_key("vcs")
                && !package.contains_key("directory")
                && !package
                    .get("archive")
                    .and_then(Item::as_table_like)
                    .is_some_and(|archive| archive.contains_key("path"))
        } else {
            package.get("source").is_some_and(|source| {
                source.as_str().is_some_and(|value| {
                    value.starts_with("registry+") || value.starts_with("direct+")
                }) || source.as_table_like().is_some_and(|table| {
                    table.contains_key("registry") || table.contains_key("url")
                })
            })
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
            purl: format!("pkg:pypi/{name}@{version}"),
            name,
            version: version.to_string(),
            resolved,
            integrity,
        });
    }
    Some(out)
}

/// The sha256 of each package's pure-Python (`-none-any.whl`) wheel as the
/// lock records it — `files = [...]` inside `[[package]]` (lock 2.x) or the
/// `[metadata.files]` entry (lock 1.0/1.1). Poetry 0.12's `[metadata.hashes]`
/// lists bare digests without filenames, so no wheel can be chosen there.
/// Keyed by canonical name. An unparseable lock contributes nothing (the
/// line-based name/version walk below still runs).
fn poetry_pure_wheel_hashes(text: &str) -> HashMap<String, String> {
    fn pure_wheel_sha(files: &Item) -> Option<String> {
        let files = files.as_array()?;
        files
            .iter()
            .filter_map(TomlValue::as_inline_table)
            .find_map(|entry| {
                let file = entry.get("file")?.as_str()?;
                if !file.ends_with("-none-any.whl") {
                    return None;
                }
                let sha = entry.get("hash")?.as_str()?.strip_prefix("sha256:")?;
                is_hex_of_len(sha, 64).then(|| sha.to_ascii_lowercase())
            })
    }
    let mut out = HashMap::new();
    let Ok(document) = text.parse::<DocumentMut>() else {
        return out;
    };
    if let Some(packages) = document.get("package").and_then(Item::as_array_of_tables) {
        for package in packages.iter() {
            let Some(name) = package.get("name").and_then(Item::as_str) else {
                continue;
            };
            if let Some(sha) = package.get("files").and_then(pure_wheel_sha) {
                out.entry(canonicalize_pypi_name(name)).or_insert(sha);
            }
        }
    }
    if let Some(files) = document
        .get("metadata")
        .and_then(|m| m.get("files"))
        .and_then(Item::as_table_like)
    {
        for (name, entry) in files.iter() {
            if let Some(sha) = pure_wheel_sha(entry) {
                out.entry(canonicalize_pypi_name(name)).or_insert(sha);
            }
        }
    }
    out
}

/// poetry.lock: `[[package]]` blocks with `name`/`version`. The lock records
/// file hashes but no URLs and no platform choice, so an entry carries the
/// pure-Python wheel's sha256 when the lock lists one (the pypi fetcher then
/// resolves the matching file through PyPI's JSON API) and stays
/// discovery-only otherwise.
async fn inventory_poetry_lock(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("poetry.lock"))
        .await
        .ok()?;
    let hashes = poetry_pure_wheel_hashes(&text);
    let mut out = Vec::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            in_package = true;
            name = None;
            continue;
        }
        if t.starts_with('[') && t != "[[package]]" {
            in_package = false;
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(v) = t.strip_prefix("name = ") {
            name = Some(canonicalize_pypi_name(v.trim_matches('"')));
        } else if let Some(v) = t.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                let v = v.trim_matches('"').to_string();
                if path_safety::is_safe_single_segment(&n)
                    && path_safety::is_safe_single_segment(&v)
                {
                    let integrity = hashes
                        .get(&n)
                        .map(|sha| LockIntegrity::Sha256Hex(sha.clone()))
                        .unwrap_or(LockIntegrity::None);
                    out.push(LockfileEntry {
                        ecosystem: "pypi",
                        purl: format!("pkg:pypi/{n}@{v}"),
                        name: n,
                        version: v,
                        resolved: None,
                        integrity,
                    });
                }
            }
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(dedup_prefer_integrity(out))
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
/// stands for: a hosted URL
/// `https://<host>/patch/pypi/<name>/<version>/<grant>/<uuid>/<wheel>[#…]`
/// (coordinates from the path) or a vendored path
/// `[./].socket/vendor/pypi/<uuid>/<name>-<version>-…whl` (coordinates from
/// the wheel filename). `None` for a user's own file/path reference.
pub(super) fn socket_reference_coords(reference: &str) -> Option<(String, String)> {
    let reference = reference.split('#').next().unwrap_or(reference);
    if let Some(rest) = reference.strip_prefix("https://") {
        let path = rest.split_once('/')?.1;
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() == 7
            && parts[0] == "patch"
            && parts[1] == "pypi"
            && parts[6].ends_with(".whl")
        {
            return Some((canonicalize_pypi_name(parts[2]), parts[3].to_string()));
        }
        return None;
    }
    let rel = reference.trim_start_matches("./");
    let rest = rel.strip_prefix(".socket/vendor/pypi/")?;
    let (_uuid, wheel) = rest.split_once('/')?;
    let stem = wheel.strip_suffix(".whl")?;
    let mut fields = stem.split('-');
    let name = fields.next()?;
    let version = fields.next()?;
    if name.is_empty() || version.is_empty() || !version.starts_with(|c: char| c.is_ascii_digit()) {
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
    let value: serde_json::Value =
        serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
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
    for (section, entries) in root {
        if section == "_meta" {
            continue;
        }
        let Some(entries) = entries.as_object() else {
            continue;
        };
        for (name, entry) in entries {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            // Socket's own references (a hosted `file` URL, a vendored
            // `./.socket/vendor/pypi/<uuid>/<wheel>` path) stay DISCOVERABLE
            // as the package they replace, so a re-scan of an already
            // redirected lock-only checkout still lists (and re-confirms /
            // attests) it instead of reporting zero packages.
            if let Some(reference) = entry
                .get("file")
                .or_else(|| entry.get("path"))
                .and_then(serde_json::Value::as_str)
            {
                if let Some((n, v)) = socket_reference_coords(reference) {
                    if path_safety::is_safe_single_segment(&n)
                        && path_safety::is_safe_single_segment(&v)
                    {
                        out.push(LockfileEntry {
                            ecosystem: "pypi",
                            purl: format!("pkg:pypi/{n}@{v}"),
                            name: n,
                            version: v,
                            resolved: None,
                            integrity: LockIntegrity::None,
                        });
                    }
                }
                continue;
            }
            if ["git", "hg", "svn", "bzr", "editable"]
                .iter()
                .any(|key| entry.contains_key(*key))
            {
                continue;
            }
            let Some(version) = entry
                .get("version")
                .and_then(serde_json::Value::as_str)
                .and_then(|v| v.strip_prefix("=="))
                .map(str::trim)
                .filter(|v| !v.is_empty())
            else {
                continue;
            };
            let n = canonicalize_pypi_name(name);
            if !path_safety::is_safe_single_segment(&n)
                || !path_safety::is_safe_single_segment(version)
            {
                continue;
            }
            let hashes: Vec<String> = entry
                .get("hashes")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(serde_json::Value::as_str)
                .filter_map(|h| h.strip_prefix("sha256:"))
                .filter(|h| is_hex_of_len(h, 64))
                .map(|h| h.to_ascii_lowercase())
                .collect();
            let integrity = if hashes.is_empty() || !public_index {
                LockIntegrity::None
            } else {
                LockIntegrity::Sha256AnyOf(hashes)
            };
            out.push(LockfileEntry {
                ecosystem: "pypi",
                purl: format!("pkg:pypi/{n}@{version}"),
                name: n,
                version: version.to_string(),
                resolved: None,
                integrity,
            });
        }
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
    let mut out = Vec::new();
    let mut in_package = false;
    let mut name: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            in_package = true;
            name = None;
            continue;
        }
        if t.starts_with('[') && t != "[[package]]" {
            in_package = false;
            continue;
        }
        if !in_package {
            continue;
        }
        if let Some(v) = t.strip_prefix("name = ") {
            name = Some(canonicalize_pypi_name(v.trim_matches('"')));
        } else if let Some(v) = t.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                let v = v.trim_matches('"').to_string();
                if path_safety::is_safe_single_segment(&n)
                    && path_safety::is_safe_single_segment(&v)
                {
                    out.push(LockfileEntry {
                        ecosystem: "pypi",
                        purl: format!("pkg:pypi/{n}@{v}"),
                        name: n,
                        version: v,
                        resolved: None,
                        integrity: LockIntegrity::None,
                    });
                }
            }
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(dedup_prefer_integrity(out))
}

/// requirements.txt with exact `==` pins — discovery only.
async fn inventory_requirements_txt(project_root: &Path) -> Option<Vec<LockfileEntry>> {
    let text = read_regular_to_string(&project_root.join("requirements.txt"))
        .await
        .ok()?;
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with('-') {
            continue;
        }
        // `name==version` (strip extras, env markers, hash continuations).
        let spec = t.split(';').next().unwrap_or(t).trim();
        let spec = spec.split_whitespace().next().unwrap_or(spec);
        let Some((raw_name, version)) = spec.split_once("==") else {
            continue;
        };
        let name = canonicalize_pypi_name(raw_name.split('[').next().unwrap_or(raw_name).trim());
        let version = version.trim().to_string();
        if name.is_empty()
            || !path_safety::is_safe_single_segment(&name)
            || !path_safety::is_safe_single_segment(&version)
            || !version.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            continue;
        }
        out.push(LockfileEntry {
            ecosystem: "pypi",
            purl: format!("pkg:pypi/{name}@{version}"),
            name,
            version,
            resolved: None,
            integrity: LockIntegrity::None,
        });
    }
    if out.is_empty() {
        return None;
    }
    Some(dedup_prefer_integrity(out))
}
