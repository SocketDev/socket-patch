use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::listing::list_dir_sync;
use super::types::{CrawledPackage, CrawlerOptions};
use crate::utils::fs::{
    is_dir, is_dir_sync, read_regular_to_string, read_regular_to_string_sync, run_blocking,
};
use crate::utils::process::{CommandRunner, SystemCommandRunner};

#[cfg(test)]
mod oracle;

// ---------------------------------------------------------------------------
// Python command discovery
// ---------------------------------------------------------------------------

/// Find a working Python command on the system.
///
/// Tries `python3`, `python`, and `py` (Windows launcher) in order,
/// returning the first one that responds to `--version`.
fn find_python_command() -> Option<&'static str> {
    find_python_command_with(&SystemCommandRunner)
}

/// Version of `find_python_command` that accepts an injected
/// `CommandRunner`. Tests inject a `MockCommandRunner` that returns
/// `Some(...)` for `python3 --version` to exercise the success arm
/// without a real Python on PATH.
pub fn find_python_command_with(runner: &dyn CommandRunner) -> Option<&'static str> {
    ["python3", "python", "py"]
        .into_iter()
        .find(|cmd| runner.run(cmd, &["--version"]).is_some())
}

// ---------------------------------------------------------------------------
// PEP 503 name canonicalization
// ---------------------------------------------------------------------------

/// Canonicalize a Python package name per PEP 503.
///
/// Lowercases, trims, and replaces runs of `[-_.]` with a single `-`.
pub(crate) fn canonicalize_pypi_name(name: &str) -> String {
    let trimmed = name.trim().to_lowercase();
    let mut result = String::with_capacity(trimmed.len());
    let mut in_separator_run = false;

    for ch in trimmed.chars() {
        if ch == '-' || ch == '_' || ch == '.' {
            if !in_separator_run {
                result.push('-');
                in_separator_run = true;
            }
            // else: skip consecutive separators
        } else {
            in_separator_run = false;
            result.push(ch);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Helpers: read Python metadata from dist-info
// ---------------------------------------------------------------------------

/// Read `Name` and `Version` for a `.dist-info` directory.
///
/// Primary source is the `.dist-info/METADATA` header block. When that
/// file is missing or malformed (no usable `Name`/`Version`), fall back
/// to the `<name>-<version>.dist-info` directory name so a corrupt or
/// partially-written install does not make the package invisible to the
/// crawler — a real risk for a tool whose job is to find and patch
/// packages. The fallback only fires for an actual directory, guarding
/// against a stray `*.dist-info` file masquerading as an install.
pub async fn read_python_metadata(dist_info_path: &Path) -> Option<(String, String)> {
    if let Some(found) = parse_metadata_headers(dist_info_path).await {
        return Some(found);
    }
    dist_info_dir_name_fallback(dist_info_path, is_dir(dist_info_path).await)
}

/// Parse the `Name`/`Version` headers from `<dist-info>/METADATA`.
///
/// Returns `None` if the file is absent, unreadable, or does not yield a
/// non-empty `Name` and `Version` before the header/body separator.
async fn parse_metadata_headers(dist_info_path: &Path) -> Option<(String, String)> {
    let metadata_path = dist_info_path.join("METADATA");
    // The path lives inside the (untrusted) package tree: a planted FIFO
    // would make a plain `read_to_string` open block forever waiting for a
    // writer, wedging scan (crawl_all) and apply (find_by_purls). Read via
    // `read_regular_to_string` — non-blocking open on Unix, rejecting
    // FIFOs/devices/directories (see its docs).
    let content = read_regular_to_string(&metadata_path).await.ok()?;
    parse_metadata_text(&content)
}

/// Blocking twin of [`read_python_metadata`] for the walk-pool scan: the
/// same FIFO-safe METADATA read, header parse and directory-name fallback.
fn read_python_metadata_sync(dist_info_path: &Path) -> Option<(String, String)> {
    let metadata_path = dist_info_path.join("METADATA");
    if let Some(found) = read_regular_to_string_sync(&metadata_path)
        .ok()
        .and_then(|content| parse_metadata_text(&content))
    {
        return Some(found);
    }
    dist_info_dir_name_fallback(dist_info_path, is_dir_sync(dist_info_path))
}

/// The `<name>-<version>.dist-info` directory-name fallback both readers
/// take once METADATA has yielded nothing — written once so a change to
/// the rule cannot split the wheel-verification path from the crawl path.
/// `is_dir` is the caller's own (symlink-following) stat of
/// `dist_info_path`: the fallback fires only for an actual directory, so
/// a stray `*.dist-info` FILE cannot masquerade as an install.
fn dist_info_dir_name_fallback(dist_info_path: &Path, is_dir: bool) -> Option<(String, String)> {
    if !is_dir {
        return None;
    }
    let dir_name = dist_info_path.file_name()?.to_string_lossy();
    parse_dist_info_dir_name(&dir_name)
}

/// Read `Name` and `Version` for a legacy `.egg-info` entry: the layout
/// pip < 23.1 writes when it builds an sdist without `wheel`
/// (`setup.py install`), and the one distutils and distro packages
/// (Debian's `python3-*`) ship. Two shapes:
///
/// * a DIRECTORY holding `PKG-INFO` (the same `Name:`/`Version:` header
///   block as `METADATA`), falling back to the
///   `<name>-<version>[-pyX.Y].egg-info` directory name like the
///   `.dist-info` reader does;
/// * a bare FILE that IS the `PKG-INFO` (distutils). It has no directory
///   to vouch for it, so it counts only when its headers parse.
pub async fn read_egg_info_metadata(egg_info_path: &Path) -> Option<(String, String)> {
    if is_dir(egg_info_path).await {
        let content = read_regular_to_string(&egg_info_path.join("PKG-INFO"))
            .await
            .ok();
        return content
            .and_then(|c| parse_metadata_text(&c))
            .or_else(|| parse_egg_info_dir_name(&egg_info_path.file_name()?.to_string_lossy()));
    }
    // FIFO-safe like the METADATA read: the regular-file reader rejects
    // FIFOs, devices and directories.
    let content = read_regular_to_string(egg_info_path).await.ok()?;
    parse_metadata_text(&content)
}

/// Blocking twin of [`read_egg_info_metadata`] for the walk-pool scan.
fn read_egg_info_metadata_sync(egg_info_path: &Path) -> Option<(String, String)> {
    if is_dir_sync(egg_info_path) {
        let content = read_regular_to_string_sync(&egg_info_path.join("PKG-INFO")).ok();
        return content
            .and_then(|c| parse_metadata_text(&c))
            .or_else(|| parse_egg_info_dir_name(&egg_info_path.file_name()?.to_string_lossy()));
    }
    let content = read_regular_to_string_sync(egg_info_path).ok()?;
    parse_metadata_text(&content)
}

/// Derive `(name, version)` from a `<name>-<version>[-pyX.Y].egg-info`
/// name. setuptools and distutils escape `-` to `_` in both the name and
/// the version (`to_filename`), so the FIRST `-` ends the name and the
/// second one (if any) starts the `-pyX.Y` interpreter tag.
fn parse_egg_info_dir_name(dir_name: &str) -> Option<(String, String)> {
    let base = dir_name.strip_suffix(".egg-info")?;
    let mut parts = base.split('-');
    let name = parts.next()?;
    let version = parts.next()?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// The `Name`/`Version` header parse of a METADATA body (see
/// [`parse_metadata_headers`]).
fn parse_metadata_text(content: &str) -> Option<(String, String)> {
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for line in content.lines() {
        // The header block ends at the first blank line; everything after
        // it is the free-text description (commonly a README that can
        // contain literal `Name:`/`Version:` lines). Stop unconditionally
        // so a malformed METADATA missing both headers falls back to the
        // reliable `<name>-<version>.dist-info` directory name rather than
        // mis-parsing prose into a bogus package identity.
        if line.trim().is_empty() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Name:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Version:") {
            version = Some(rest.trim().to_string());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }

    match (name, version) {
        (Some(n), Some(v)) if !n.is_empty() && !v.is_empty() => Some((n, v)),
        _ => None,
    }
}

/// Derive `(name, version)` from a `<name>-<version>.dist-info` directory
/// name. A PEP 440 version never contains `-` (pre-release and local
/// segments normalize to `aN`/`+local`), so the final `-` is the
/// name/version boundary even when the distribution name itself contains
/// a `-` (older pip kept the raw name; newer pip escapes it to `_`).
/// Either way the caller canonicalizes the name. Returns `None` when the
/// directory name carries no version segment.
fn parse_dist_info_dir_name(dir_name: &str) -> Option<(String, String)> {
    let base = dir_name.strip_suffix(".dist-info")?;
    let idx = base.rfind('-')?;
    let name = &base[..idx];
    let version = &base[idx + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

// ---------------------------------------------------------------------------
// Helpers: find Python directories with wildcard matching
// ---------------------------------------------------------------------------

/// Find directories matching a path pattern with wildcard segments.
///
/// Supported wildcards:
/// - `"python3.*"` — matches the minor-versioned interpreter dirs
///   (`python3.11`, `python3.12`, …) AND the bare `python3` dir.
///   The bare form is what Debian/Ubuntu use for apt-installed system
///   modules (`/usr/lib/python3/dist-packages`); a `python3.`-prefix
///   test (requiring the dot) would silently skip it, hiding every
///   distro-packaged module from a crawler whose job is to patch them.
/// - `"*"` — matches any directory entry
///
/// All other segments are treated as literal path components.
pub async fn find_python_dirs(base_path: &Path, segments: &[&str]) -> Vec<PathBuf> {
    let mut results = Vec::new();

    // Check that base_path is a directory
    match tokio::fs::metadata(base_path).await {
        Ok(m) if m.is_dir() => {}
        _ => return results,
    }

    if segments.is_empty() {
        results.push(base_path.to_path_buf());
        return results;
    }

    let first = segments[0];
    let rest = &segments[1..];

    if first == "python3.*" {
        // Wildcard: list directory and match `python3.X` entries plus the
        // bare `python3` dir (Debian/Ubuntu `dist-packages` layout). The
        // exact-match arm avoids over-matching `python3foo` while still
        // catching the dotless distro form.
        for entry in crate::utils::fs::list_dir_entries(base_path).await {
            if !crate::utils::fs::entry_is_dir(&entry).await {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str == "python3" || name_str.starts_with("python3.") {
                let sub =
                    Box::pin(find_python_dirs(&base_path.join(entry.file_name()), rest)).await;
                results.extend(sub);
            }
        }
    } else if first == "*" {
        // Generic wildcard: match any directory entry
        for entry in crate::utils::fs::list_dir_entries(base_path).await {
            if !crate::utils::fs::entry_is_dir(&entry).await {
                continue;
            }
            let sub = Box::pin(find_python_dirs(&base_path.join(entry.file_name()), rest)).await;
            results.extend(sub);
        }
    } else {
        // Literal segment: just check if it exists
        let sub = Box::pin(find_python_dirs(&base_path.join(first), rest)).await;
        results.extend(sub);
    }

    results
}

// ---------------------------------------------------------------------------
// Helpers: site-packages discovery
// ---------------------------------------------------------------------------

/// Find `site-packages` (or `dist-packages`) directories under a base dir.
///
/// Handles both Unix (`lib/python3.X/site-packages`) and macOS/Linux layouts.
async fn find_site_packages_under(
    base_dir: &Path,
    sub_dir_type: &str, // "site-packages" or "dist-packages"
) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        find_python_dirs(base_dir, &["Lib", sub_dir_type]).await
    }
    #[cfg(not(windows))]
    {
        find_python_dirs(base_dir, &["lib", "python3.*", sub_dir_type]).await
    }
}

/// Find local virtual environment `site-packages` directories.
///
/// Checks (in order):
/// 0. The env the project's package manager records for it, which that
///    manager uses ahead of an activated venv or a stray `./.venv` (see
///    [`package_manager_recorded_site_packages`]): PDM's `.pdm-python`
///    interpreter (its venv, or `__pypackages__` for PEP 582) and uv's
///    `UV_PROJECT_ENVIRONMENT`
/// 1. `VIRTUAL_ENV` environment variable (for a Pipenv, Poetry or PDM
///    project, only when that tool itself would use it; Poetry also takes a
///    conda `CONDA_PREFIX`)
/// 2. For a Pipenv project, the venv(s) Pipenv resolves for it (see
///    [`pipenv_project_site_packages`]), and nothing else
/// 3. Poetry's out-of-tree virtualenv(s), when Poetry itself would not use
///    `./.venv` for the project (see [`find_poetry_virtualenv_site_packages`])
/// 4. `.venv` directory in `cwd`
/// 5. `venv` directory in `cwd`
pub async fn find_local_venv_site_packages(cwd: &Path) -> Vec<PathBuf> {
    let var = |name: &str| std::env::var(name).ok();
    find_local_venv_site_packages_with(cwd, &var).await
}

/// [`find_local_venv_site_packages`] over an explicit environment (tests pass
/// a closure instead of mutating the process environment).
async fn find_local_venv_site_packages_with(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    let mut results = Vec::new();

    // 0. PDM and uv record where they install a project, and that record
    // beats both an activated `VIRTUAL_ENV` and a `./.venv` they don't use.
    if let Some(found) = package_manager_recorded_site_packages(cwd, var).await {
        return found;
    }

    let pipenv = is_pipenv_project(cwd);
    let poetry = if pipenv {
        None
    } else {
        load_poetry_project(cwd, var).await
    };

    // Poetry versions can use different placeholder roots. Apply its
    // recorded-env / active-shell / in-project precedence within each
    // compatible placement, then retain their ordered union.
    if let Some(project) = &poetry {
        let found = poetry_project_site_packages(cwd, project, var).await;
        if !found.is_empty() {
            return found;
        }
    } else {
        let pdm_ignores_active =
            pdm_env_flag(var, "PDM_IGNORE_ACTIVE_VENV") && pdm_drives_project(cwd).await;
        let active_prefix = if !pdm_ignores_active && (!pipenv || pipenv_uses_virtual_env(var)) {
            var("VIRTUAL_ENV")
        } else {
            None
        };
        if let Some(prefix) = active_prefix {
            let found = find_site_packages_under(Path::new(&prefix), "site-packages").await;
            if !found.is_empty() {
                return found;
            }
        }
    }

    // 2. A Pipenv project's venv is whatever Pipenv resolves, which is not
    // the generic probe order below: Pipenv never uses `venv/`, and its
    // in-project settings can rule out an existing `./.venv`. When Pipenv
    // has no venv yet there is nothing to patch, so the generic probes must
    // not fall back to a tree Pipenv will never use.
    if pipenv {
        return pipenv_project_site_packages(cwd, var).await;
    }

    // 4. Check .venv and venv in cwd
    for venv_dir in &[".venv", "venv"] {
        let venv_path = cwd.join(venv_dir);
        let matches = find_site_packages_under(&venv_path, "site-packages").await;
        results.extend(matches);
    }

    // 5. A PDM project with no recorded interpreter and no venv for PDM to
    // pick (an activated one, `./.venv`) is a PEP 582 project (PDM 1.x's
    // default): its packages live in `__pypackages__/<X.Y>/lib`.
    if results.is_empty() && pdm_drives_project(cwd).await {
        results = pdm_pep582_dirs(cwd).await;
    }

    results
}

/// The `site-packages` of the env the project's package manager records for
/// `cwd`, when that env exists. `None` means the manager records nothing
/// (or nothing installed yet), and the generic probes decide.
///
/// - **PDM** installs into the interpreter saved in `.pdm-python` (PDM
///   2.x; `[python] path` in `.pdm.toml` before that), ahead of an
///   activated venv. That interpreter's venv is the env (an out-of-tree
///   `venv.in_project = false` venv, or one picked with `pdm use`). An
///   interpreter that is not a venv means PEP 582: PDM installs into
///   `__pypackages__/<X.Y>/lib`, which PDM 1.x also uses with no saved
///   interpreter at all.
/// - **uv** syncs a project into `UV_PROJECT_ENVIRONMENT` (absolute, or
///   relative to the project) instead of `./.venv`, and ignores an
///   activated `VIRTUAL_ENV` for project commands.
async fn package_manager_recorded_site_packages(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<Vec<PathBuf>> {
    if let Some(found) = pdm_project_site_packages(cwd, var).await {
        return Some(found);
    }
    uv_project_environment_site_packages(cwd, var).await
}

/// The env of PDM's interpreter for `cwd` (see
/// [`package_manager_recorded_site_packages`]): `PDM_PYTHON`, else the saved
/// one unless `PDM_IGNORE_SAVED_PYTHON`. With neither, PDM picks an active
/// or project venv first, so the generic probes decide (PEP 582 is their
/// last resort, see [`find_local_venv_site_packages_with`]).
async fn pdm_project_site_packages(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<Vec<PathBuf>> {
    if !pdm_drives_project(cwd).await {
        return None;
    }
    // `PDM_PYTHON` outranks the saved interpreter. The first of them that
    // is an environment (a venv, or a conda env PDM reuses) is where PDM
    // installs; a base interpreter (CI often points `PDM_PYTHON` at the
    // system Python) only picks the Python a venv is made from.
    let overridden = var("PDM_PYTHON")
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(|python| cwd.join(python));
    let saved = if pdm_env_flag(var, "PDM_IGNORE_SAVED_PYTHON") {
        None
    } else {
        pdm_saved_interpreter(cwd).await
    };
    let interpreters: Vec<PathBuf> = overridden.into_iter().chain(saved).collect();
    if let Some(root) = interpreters.iter().find_map(|i| env_root_of_interpreter(i)) {
        let found = find_site_packages_under(&root, "site-packages").await;
        return (!found.is_empty()).then_some(found);
    }
    // A base interpreter means PEP 582 only with `python.use_venv` off;
    // with it on (PDM 2.x's default) PDM uses a venv the generic probes
    // find, with `__pypackages__` as their last resort.
    if interpreters.is_empty() || pdm_uses_venv(cwd, var).await {
        return None;
    }
    let found = pdm_pep582_dirs(cwd).await;
    (!found.is_empty()).then_some(found)
}

/// PDM's `python.use_venv` for `cwd`: `PDM_USE_VENV`, else `[python]
/// use_venv` in the project's `pdm.toml` (PDM 2.x) or legacy `.pdm.toml`.
/// Unset, it is on, except for a legacy PDM 1.x project (a `.pdm.toml` and
/// no `.pdm-python`), where it defaulted to off.
async fn pdm_uses_venv(cwd: &Path, var: &impl Fn(&str) -> Option<String>) -> bool {
    if var("PDM_USE_VENV").is_some() {
        return pdm_env_flag(var, "PDM_USE_VENV");
    }
    for config in ["pdm.toml", ".pdm.toml"] {
        let Ok(text) = read_regular_to_string(&cwd.join(config)).await else {
            continue;
        };
        let setting = text
            .parse::<toml_edit::DocumentMut>()
            .ok()
            .and_then(|doc| doc.get("python")?.get("use_venv")?.as_bool());
        if let Some(on) = setting {
            return on;
        }
    }
    !cwd.join(".pdm.toml").is_file() || cwd.join(".pdm-python").is_file()
}

/// A boolean PDM environment setting, parsed like PDM's `ensure_boolean`:
/// set and non-empty, and not `false` / `no` / `0` (any case).
fn pdm_env_flag(var: &impl Fn(&str) -> Option<String>, name: &str) -> bool {
    var(name).is_some_and(|v| {
        !v.is_empty() && !matches!(v.to_ascii_lowercase().as_str(), "false" | "no" | "0")
    })
}

/// Whether PDM installs the project at `cwd`: a PDM project (see
/// [`is_pdm_project`], or a `.pdm-python`) with no `uv.lock` or
/// `poetry.lock`, which drive installs ahead of `pdm.lock` (the hosted
/// rewriters' precedence).
async fn pdm_drives_project(cwd: &Path) -> bool {
    if cwd.join("uv.lock").is_file() || cwd.join("poetry.lock").is_file() {
        return false;
    }
    cwd.join(".pdm-python").is_file() || is_pdm_project(cwd).await
}

/// PEP 582 package dirs: `__pypackages__/<X.Y>/lib`.
async fn pdm_pep582_dirs(cwd: &Path) -> Vec<PathBuf> {
    find_python_dirs(&cwd.join("__pypackages__"), &["*", "lib"]).await
}

/// The interpreter PDM saved for `cwd`: `.pdm-python` (PDM 2.x), else
/// `[python] path` in the legacy `.pdm.toml`. A relative path is taken
/// against the project.
async fn pdm_saved_interpreter(cwd: &Path) -> Option<PathBuf> {
    let saved = match read_regular_to_string(&cwd.join(".pdm-python")).await {
        Ok(text) => text.trim().to_string(),
        Err(_) => {
            let text = read_regular_to_string(&cwd.join(".pdm.toml"))
                .await
                .ok()?;
            let doc = text.parse::<toml_edit::DocumentMut>().ok()?;
            doc.get("python")?.get("path")?.as_str()?.trim().to_string()
        }
    };
    (!saved.is_empty()).then(|| cwd.join(saved))
}

/// Whether `cwd` is a PDM project: `pdm.lock`, `.pdm.toml`, or a
/// `[tool.pdm]` table in `pyproject.toml` with settings beyond `build` (a
/// `[tool.pdm.build]` table alone only configures the pdm-backend build
/// backend, which projects driven by other managers use too).
async fn is_pdm_project(cwd: &Path) -> bool {
    if cwd.join("pdm.lock").is_file() || cwd.join(".pdm.toml").is_file() {
        return true;
    }
    let Ok(text) = read_regular_to_string(&cwd.join("pyproject.toml")).await else {
        return false;
    };
    text.parse::<toml_edit::DocumentMut>()
        .ok()
        .and_then(|doc| {
            let pdm = doc.get("tool")?.get("pdm")?.as_table_like()?;
            pdm.iter().any(|(key, _)| key != "build").then_some(())
        })
        .is_some()
}

/// The environment a Python interpreter path belongs to: a venv
/// (`<root>/bin/python…` or `<root>\Scripts\python.exe` with a
/// `<root>/pyvenv.cfg`), or a conda env (`conda-meta/` at `<root>`, whose
/// interpreter is `<root>/bin/python…` or `<root>\python.exe`). The path is
/// not resolved, since a venv's interpreter is a symlink to its base Python.
fn env_root_of_interpreter(python: &Path) -> Option<PathBuf> {
    let parent = python.parent()?;
    let grandparent = parent.parent();
    if let Some(root) = grandparent.filter(|root| root.join("pyvenv.cfg").is_file()) {
        return Some(root.to_path_buf());
    }
    grandparent
        .into_iter()
        .chain(std::iter::once(parent))
        .find(|root| root.join("conda-meta").is_dir())
        .map(Path::to_path_buf)
}

/// uv's `UV_PROJECT_ENVIRONMENT` for a uv project at `cwd` (see
/// [`package_manager_recorded_site_packages`]). Ambient in shells and
/// images, so it only counts for a project uv drives: one with `uv.lock`,
/// or a `pyproject.toml` that no other manager's lock or record claims.
async fn uv_project_environment_site_packages(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<Vec<PathBuf>> {
    let env = var("UV_PROJECT_ENVIRONMENT").filter(|v| !v.trim().is_empty())?;
    let other_lock = [
        "poetry.lock",
        "poetry.toml",
        "pdm.lock",
        ".pdm-python",
        "Pipfile",
        "Pipfile.lock",
    ]
    .iter()
    .any(|marker| cwd.join(marker).exists());
    // A lockless Poetry (`[tool.poetry]`) or PDM project is still theirs.
    let other_manager = other_lock
        || is_pdm_project(cwd).await
        || read_regular_to_string(&cwd.join("pyproject.toml"))
            .await
            .is_ok_and(|text| text.contains("[tool.poetry"));
    let uv_project =
        cwd.join("uv.lock").is_file() || (cwd.join("pyproject.toml").is_file() && !other_manager);
    if !uv_project {
        return None;
    }
    let found = find_site_packages_under(&cwd.join(env), "site-packages").await;
    (!found.is_empty()).then_some(found)
}

/// Whether `cwd` is a Pipenv project: a `Pipfile` or a `Pipfile.lock`.
fn is_pipenv_project(cwd: &Path) -> bool {
    cwd.join("Pipfile").is_file() || cwd.join("Pipfile.lock").is_file()
}

/// Pipenv's `get_from_env(arg)` for a boolean setting: `PIPENV_<arg>`, else
/// the negated `PIPENV_NO_<arg>`. `Ok` for a value Pipenv's `env_to_bool`
/// understands (`1/true/yes/on`, `0/false/no/off`, any case), `Err` with the
/// raw text otherwise (Pipenv then keeps the string), `None` when unset.
fn pipenv_env_setting(
    var: &impl Fn(&str) -> Option<String>,
    arg: &str,
) -> Option<Result<bool, String>> {
    let parse = |value: String| match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(value),
    };
    if let Some(value) = var(&format!("PIPENV_{arg}")) {
        return Some(parse(value));
    }
    var(&format!("PIPENV_NO_{arg}")).map(|value| parse(value).map(|flag| !flag))
}

/// Whether Pipenv would take `VIRTUAL_ENV` as the project's venv: only when
/// `PIPENV_ACTIVE` is absent (any value counts) and
/// `bool(PIPENV_IGNORE_VIRTUALENVS)` is false. The same test in every Pipenv
/// from 2018.11 through 2026.8 (`Project.virtualenv_location`, later
/// `VenvLocator.location`).
fn pipenv_uses_virtual_env(var: &impl Fn(&str) -> Option<String>) -> bool {
    let ignore = match pipenv_env_setting(var, "IGNORE_VIRTUALENVS") {
        Some(Ok(flag)) => flag,
        Some(Err(text)) => !text.is_empty(),
        None => false,
    };
    var("PIPENV_ACTIVE").is_none() && !ignore
}

/// An explicit in-project choice for the Pipenv project at `cwd`, if any:
/// `PIPENV_VENV_IN_PROJECT` (or `PIPENV_NO_VENV_IN_PROJECT`) first, then
/// Pipenv 2026.2+'s Pipfile `[pipenv] venv_in_project`. A non-boolean,
/// non-empty variable counts as "yes", as `setting or <auto-detect>` did
/// through Pipenv 2026.1.
fn pipenv_venv_in_project(cwd: &Path, var: &impl Fn(&str) -> Option<String>) -> Option<bool> {
    match pipenv_env_setting(var, "VENV_IN_PROJECT") {
        Some(Ok(flag)) => return Some(flag),
        Some(Err(text)) if !text.is_empty() => return Some(true),
        _ => {}
    }
    // Non-blocking, regular-files-only read: a FIFO `Pipfile` (a lock alone
    // marks the project) must not wedge discovery.
    let text = read_regular_to_string_sync(&cwd.join("Pipfile")).ok()?;
    let doc = text.parse::<toml_edit::DocumentMut>().ok()?;
    let value = doc.get("pipenv")?.get("venv_in_project")?.as_value()?;
    // Python's `bool(value)` for the scalar shapes a Pipfile can hold.
    match value {
        toml_edit::Value::Boolean(flag) => Some(*flag.value()),
        toml_edit::Value::Integer(number) => Some(*number.value() != 0),
        toml_edit::Value::String(text) => Some(!text.value().is_empty()),
        _ => None,
    }
}

/// `site-packages` of the venv(s) Pipenv uses for the project at `cwd`
/// (`VenvLocator.get_location`, `VIRTUAL_ENV` aside), most likely first:
///
/// - No `./.venv` directory: Pipenv's own placement (a `.venv` file pointer
///   or `$WORKON_HOME/<name>-<hash>`, see
///   [`find_pipenv_virtualenv_site_packages`]). An explicit "in project"
///   with no `./.venv` means Pipenv has no venv yet, so nothing.
/// - A `./.venv` directory and an explicit "in project": `./.venv` only.
/// - A `./.venv` directory and an explicit "not in project": the
///   WORKON_HOME venv only (Pipenv 2023+ ignores `./.venv` then).
/// - A `./.venv` directory and nothing explicit: Pipenv up to 2026.1 uses
///   it, 2026.2+ prefers an existing WORKON_HOME venv. Without running
///   Pipenv the version is unknown, so both are returned, WORKON_HOME
///   first, and whichever one the installed Pipenv uses gets patched.
///
/// Never `./venv`: no Pipenv release uses it.
async fn pipenv_project_site_packages(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    let in_project = pipenv_venv_in_project(cwd, var);
    let dot_venv = cwd.join(".venv");
    if !dot_venv.is_dir() {
        if in_project == Some(true) && !dot_venv.exists() {
            return Vec::new();
        }
        return find_pipenv_virtualenv_site_packages_with(cwd, var).await;
    }
    let in_tree = find_site_packages_under(&dot_venv, "site-packages").await;
    if in_project == Some(true) {
        return in_tree;
    }
    let mut results = find_pipenv_virtualenv_site_packages_with(cwd, var).await;
    if in_project.is_none() {
        results.extend(in_tree);
    }
    results
}

/// Poetry's `virtualenvs.*` settings that decide where a project's virtualenv
/// lives. Precedence mirrors Poetry's: `POETRY_VIRTUALENVS_*` environment
/// variables, then the project-local `poetry.toml`, then the user
/// `config.toml`, then the defaults.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PoetryVirtualenvConfig {
    /// `virtualenvs.create` — `false` means Poetry installs into the
    /// interpreter it runs under (a container's system Python), which the
    /// project-marker global fallback already covers.
    create: Option<bool>,
    /// `virtualenvs.in-project` — `true` means `./.venv` once it exists;
    /// until then Poetry keeps using its out-of-tree env.
    in_project: Option<bool>,
    /// `virtualenvs.path` — may carry `{key}` placeholders (see
    /// [`poetry_process`]) and a leading `~`.
    path: Option<String>,
    /// `cache-dir` — the parent of the default `virtualenvs` root. Goes
    /// through the same placeholder processing as `path`.
    cache_dir: Option<String>,
    /// `data-dir` (defaulted since Poetry 2.1) — what `{data-dir}` expands to; see
    /// [`poetry_default_data_dirs`].
    data_dir: Option<String>,
}

impl PoetryVirtualenvConfig {
    /// Layer `other` (lower precedence) under `self`: only unset keys take
    /// the lower layer's value.
    fn or(mut self, other: PoetryVirtualenvConfig) -> Self {
        self.create = self.create.or(other.create);
        self.in_project = self.in_project.or(other.in_project);
        self.path = self.path.or(other.path);
        self.cache_dir = self.cache_dir.or(other.cache_dir);
        self.data_dir = self.data_dir.or(other.data_dir);
        self
    }

    fn from_env(var: impl Fn(&str) -> Option<String>) -> Self {
        let flag = |name: &str| {
            var(name).map(|v| {
                let v = v.trim().to_ascii_lowercase();
                matches!(v.as_str(), "1" | "true" | "yes" | "on")
            })
        };
        Self {
            create: flag("POETRY_VIRTUALENVS_CREATE"),
            in_project: flag("POETRY_VIRTUALENVS_IN_PROJECT"),
            path: var("POETRY_VIRTUALENVS_PATH").filter(|v| !v.trim().is_empty()),
            cache_dir: var("POETRY_CACHE_DIR").filter(|v| !v.trim().is_empty()),
            data_dir: var("POETRY_DATA_DIR").filter(|v| !v.trim().is_empty()),
        }
    }

    /// `[virtualenvs]` (poetry.toml / config.toml) and the top-level
    /// `cache-dir` key. A file that does not parse contributes nothing.
    fn from_toml(text: &str) -> Self {
        let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
            return Self::default();
        };
        let venvs = doc
            .get("virtualenvs")
            .and_then(toml_edit::Item::as_table_like);
        let get_bool = |key: &str| {
            venvs.and_then(|t| t.get(key)).and_then(|item| {
                item.as_bool().or_else(|| {
                    item.as_str().map(|s| {
                        matches!(
                            s.trim().to_ascii_lowercase().as_str(),
                            "1" | "true" | "yes" | "on"
                        )
                    })
                })
            })
        };
        Self {
            create: get_bool("create"),
            in_project: get_bool("in-project"),
            path: venvs
                .and_then(|t| t.get("path"))
                .and_then(toml_edit::Item::as_str)
                .map(str::to_string),
            cache_dir: doc
                .get("cache-dir")
                .and_then(toml_edit::Item::as_str)
                .map(str::to_string),
            data_dir: doc
                .get("data-dir")
                .and_then(toml_edit::Item::as_str)
                .map(str::to_string),
        }
    }
}

/// The user-level Poetry config file, per Poetry's own lookup:
/// `$POETRY_CONFIG_DIR/config.toml`, else the platform config dir
/// (`~/Library/Application Support/pypoetry` on macOS, `$XDG_CONFIG_HOME` or
/// `~/.config` + `/pypoetry` elsewhere on unix, `%APPDATA%\pypoetry` on
/// Windows).
fn poetry_user_config_path(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(dir) = var("POETRY_CONFIG_DIR").filter(|v| !v.trim().is_empty()) {
        return Some(PathBuf::from(dir).join("config.toml"));
    }
    let home = var("HOME")
        .or_else(|| var("USERPROFILE"))
        .map(PathBuf::from);
    let dir = if cfg!(windows) {
        var("APPDATA")
            .map(PathBuf::from)
            .or_else(|| home.map(|h| h.join("AppData").join("Roaming")))?
            .join("pypoetry")
    } else if cfg!(target_os = "macos") {
        home?
            .join("Library")
            .join("Application Support")
            .join("pypoetry")
    } else {
        var("XDG_CONFIG_HOME")
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|h| h.join(".config")))?
            .join("pypoetry")
    };
    Some(dir.join("config.toml"))
}

/// Poetry's default `cache-dir`: `~/Library/Caches/pypoetry` (macOS),
/// `$XDG_CACHE_HOME`/`~/.cache` + `/pypoetry` (other unix),
/// `%LOCALAPPDATA%\pypoetry\Cache` (Windows).
fn poetry_default_cache_dir(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let home = var("HOME")
        .or_else(|| var("USERPROFILE"))
        .map(PathBuf::from);
    if cfg!(windows) {
        Some(
            var("LOCALAPPDATA")
                .map(PathBuf::from)
                .or_else(|| home.map(|h| h.join("AppData").join("Local")))?
                .join("pypoetry")
                .join("Cache"),
        )
    } else if cfg!(target_os = "macos") {
        Some(home?.join("Library").join("Caches").join("pypoetry"))
    } else {
        Some(
            var("XDG_CACHE_HOME")
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from)
                .or_else(|| home.map(|h| h.join(".cache")))?
                .join("pypoetry"),
        )
    }
}

/// Poetry's virtualenv directory name for a project, minus the `-py<X.Y>`
/// suffix — `EnvManager.generate_env_name(name, cwd)`, unchanged from Poetry
/// 1.0 through 2.x: the lowercased project name with shell-hostile characters
/// replaced by `_` and truncated to 42 chars, a dash, then the first 8 chars
/// of the URL-safe base64 sha256 of `os.path.normcase(os.path.realpath(cwd))`.
/// `realpath` is resolved by the caller (`normalized_cwd` is the already
/// canonical path) so the pure function stays testable with fixed vectors.
fn poetry_env_name_prefix(project_name: &str, normalized_cwd: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let lowered = project_name.to_lowercase();
    let sanitized: String = lowered
        .chars()
        .map(|c| {
            if matches!(
                c,
                ' ' | '$' | '`' | '!' | '*' | '@' | '"' | '\\' | '\r' | '\n' | '\t'
            ) {
                '_'
            } else {
                c
            }
        })
        .take(42)
        .collect();
    let digest = Sha256::digest(normalized_cwd.as_bytes());
    let hash = base64::engine::general_purpose::URL_SAFE.encode(digest);
    format!("{sanitized}-{}", &hash[..8])
}

/// `os.path.normcase(os.path.realpath(cwd))` as Poetry hashes it: symlinks
/// resolved; on Windows see [`windows_normcase`], elsewhere unchanged.
fn poetry_normalized_cwd(cwd: &Path) -> String {
    let real = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let text = real.to_string_lossy().into_owned();
    if cfg!(windows) {
        windows_normcase(&text)
    } else {
        text
    }
}

/// Python's Windows `normcase(realpath(p))` for a path Rust canonicalized:
/// `realpath` drops the verbatim `\\?\` prefix that `std::fs::canonicalize`
/// adds (`\\?\UNC\server` becomes `\\server`), and `normcase` lowercases
/// and turns `/` into `\`. Hashing the verbatim form made every Windows
/// env-name hash miss.
fn windows_normcase(text: &str) -> String {
    strip_windows_verbatim_prefix(text)
        .replace('/', "\\")
        .to_lowercase()
}

/// `\\?\C:\x` -> `C:\x`, `\\?\UNC\srv\share` -> `\\srv\share`; anything
/// else unchanged.
fn strip_windows_verbatim_prefix(text: &str) -> String {
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        text.to_string()
    }
}

/// The project names Poetry may have derived the virtualenv name from, in
/// the order Poetry picks them. poetry-core 2.x takes `[project] name`, then
/// `[tool.poetry] name`, then `"non-package-mode"`. poetry-core 1.9 (Poetry
/// 1.8) ignores `[project]` and takes `[tool.poetry] name`, then
/// `"non-package-mode"`. Poetry canonicalizes the name (PEP 503); the raw
/// spelling follows each canonical one so a venv made before that
/// normalization still matches. Empty only when the file does not parse.
fn poetry_project_names(pyproject: &str) -> Vec<String> {
    let Ok(doc) = pyproject.parse::<toml_edit::DocumentMut>() else {
        return Vec::new();
    };
    let project_name = doc
        .get("project")
        .and_then(|p| p.get("name"))
        .and_then(toml_edit::Item::as_str);
    let poetry_name = doc
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("name"))
        .and_then(toml_edit::Item::as_str);
    let mut names: Vec<String> = Vec::new();
    let mut push = |raw: &str| {
        for name in [canonicalize_pypi_name(raw), raw.to_string()] {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    };
    project_name.into_iter().for_each(&mut push);
    match poetry_name {
        Some(name) => push(name),
        // Poetry 2 with no name at all, or Poetry 1.8 with only a
        // `[project] name`, both fall back to this placeholder.
        None => push("non-package-mode"),
    }
    names
}

/// The current model's path, for pure configuration tests. Discovery
/// considers every compatible placement instead of guessing the version
/// from the existence of a parent directory.
#[cfg(test)]
fn poetry_virtualenvs_root(
    cwd: &Path,
    config: &PoetryVirtualenvConfig,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    if config.create == Some(false) {
        return None;
    }
    poetry_virtualenvs_paths(cwd, config, var)
        .into_iter()
        .next()
}

/// Possible `Config.virtualenvs_path` values, most recent model first.
/// Older Poetry lacks the default data-dir setting, and older macOS
/// platformdirs ignores XDG_DATA_HOME. None of these roots wins merely
/// because a different project created its parent directory.
fn poetry_virtualenvs_paths(
    cwd: &Path,
    config: &PoetryVirtualenvConfig,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    let defaults = poetry_default_data_dirs(var);
    let mut candidates = Vec::new();
    for generation in [
        PoetryPlaceholders::Current,
        PoetryPlaceholders::NoDataDir,
        PoetryPlaceholders::Poetry11,
    ] {
        for data_dir in &defaults {
            if let Some(path) =
                poetry_virtualenvs_path_for(cwd, config, data_dir.as_deref(), generation, var)
            {
                if !candidates.contains(&path) {
                    candidates.push(path);
                }
            }
        }
    }
    candidates
}

/// Resolve only referenced settings. In particular an unused cyclic
/// data-dir must not invalidate an explicit virtualenvs.path. There are
/// only two supported keys; detecting a repeated key bounds recursion.
struct PoetryPathResolver<'a, F> {
    config: &'a PoetryVirtualenvConfig,
    default_data: Option<&'a Path>,
    generation: PoetryPlaceholders,
    var: &'a F,
    resolving: Vec<&'static str>,
}

impl<F: Fn(&str) -> Option<String>> PoetryPathResolver<'_, F> {
    fn process(&mut self, value: &str) -> Option<String> {
        let mut invalid = false;
        let generation = self.generation;
        let result = poetry_process(value, generation, |key| match self.resolve(key) {
            Ok(value) => value,
            Err(()) => {
                invalid = true;
                None
            }
        });
        (!invalid).then_some(result)
    }

    fn resolve(&mut self, key: &str) -> Result<Option<String>, ()> {
        let (key, raw) = match key {
            "cache-dir" => (
                "cache-dir",
                self.config.cache_dir.clone().or_else(|| {
                    poetry_default_cache_dir(self.var).map(|p| p.to_string_lossy().into_owned())
                }),
            ),
            "data-dir" => (
                "data-dir",
                self.config.data_dir.clone().or_else(|| {
                    // Explicit file/env keys work in older Poetry too; only
                    // the default setting was introduced in Poetry 2.1.
                    (self.generation == PoetryPlaceholders::Current)
                        .then(|| self.default_data.map(|p| p.to_string_lossy().into_owned()))
                        .flatten()
                }),
            ),
            _ => return Ok(None),
        };
        let Some(raw) = raw else {
            // A cache-dir exists in every supported generation. Without
            // its home/default we cannot infer a literal relative path.
            return if key == "cache-dir" {
                Err(())
            } else {
                Ok(None)
            };
        };
        if self.resolving.contains(&key) {
            return Err(());
        }
        self.resolving.push(key);
        let result = self.process(&raw).map(Some).ok_or(());
        self.resolving.pop();
        result
    }
}

fn poetry_virtualenvs_path_for(
    cwd: &Path,
    config: &PoetryVirtualenvConfig,
    data_dir: Option<&Path>,
    generation: PoetryPlaceholders,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    let mut resolver = PoetryPathResolver {
        config,
        default_data: data_dir,
        generation,
        var,
        resolving: Vec::new(),
    };
    let template = config.path.as_deref().unwrap_or("{cache-dir}/virtualenvs");
    let processed = resolver.process(template)?;
    let path = expand_home(&processed, var);
    Some(if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    })
}

/// How a Poetry generation treats `{key}` placeholders in a config value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoetryPlaceholders {
    /// Poetry >= 2.1: `{cache-dir}` and `{data-dir}` resolve, any other
    /// `{key}` is kept literally.
    Current,
    /// Poetry 1.2 - 2.0: no default `data-dir` setting; an explicit
    /// file/environment value still resolves like any configured key.
    NoDataDir,
    /// Poetry 1.1: an unknown `{key}` is replaced with nothing.
    Poetry11,
}

/// Poetry's `Config.process()`: every `{key}` (non-greedy, as in
/// `re.sub(r"{(.+?)}", ...)`) is replaced with the value `resolve` gives
/// for that config key. A key with no value is kept as-is, except on
/// Poetry 1.1, which drops it. Poetry has no `{project-dir}` key (#608).
fn poetry_process(
    value: &str,
    generation: PoetryPlaceholders,
    mut resolve: impl FnMut(&str) -> Option<String>,
) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        // `.+?` needs at least one character before the closing brace.
        let close = after
            .char_indices()
            .skip(1)
            .find(|&(_, c)| c == '}')
            .map(|(i, _)| i);
        let Some(close) = close else {
            break;
        };
        out.push_str(&rest[..open]);
        let key = &after[..close];
        match resolve(key) {
            Some(resolved) => out.push_str(&resolved),
            None if generation == PoetryPlaceholders::Poetry11 => {}
            None => {
                out.push('{');
                out.push_str(key);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

/// Config defaults differ from the installer: current macOS
/// platformdirs honors XDG_DATA_HOME, but older supported releases use
/// Library/Application Support. Keep both until project evidence resolves
/// placement; POETRY_HOME overrides either dependency generation.
fn poetry_default_data_dirs(var: &impl Fn(&str) -> Option<String>) -> Vec<Option<PathBuf>> {
    let installer = poetry_installer_data_dir(var);
    let mut dirs = Vec::new();
    if cfg!(target_os = "macos") && var("POETRY_HOME").is_none_or(|v| v.trim().is_empty()) {
        if let Some(xdg) = var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            dirs.push(Some(xdg.join("pypoetry")));
        }
    }
    if !dirs.contains(&installer) {
        dirs.push(installer);
    }
    dirs
}

/// The official installer's data directory: POETRY_HOME, otherwise its
/// platform default. On macOS the installer itself uses Library even
/// when Poetry's platformdirs dependency honors XDG_DATA_HOME.
fn poetry_installer_data_dir(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(home) = var("POETRY_HOME").filter(|v| !v.trim().is_empty()) {
        return Some(expand_home(&home, var));
    }
    let home = var("HOME")
        .or_else(|| var("USERPROFILE"))
        .map(PathBuf::from);
    let base = if cfg!(windows) {
        var("APPDATA")
            .filter(|v| !v.trim().is_empty())
            .map(PathBuf::from)
            .or_else(|| home.map(|h| h.join("AppData").join("Roaming")))?
    } else if cfg!(target_os = "macos") {
        home?.join("Library").join("Application Support")
    } else {
        var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| home.map(|h| h.join(".local").join("share")))?
    };
    Some(base.join("pypoetry"))
}

fn expand_home(raw: &str, var: &impl Fn(&str) -> Option<String>) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\")) {
        if let Some(home) = var("HOME").or_else(|| var("USERPROFILE")) {
            return PathBuf::from(home).join(rest);
        }
    }
    if raw == "~" {
        if let Some(home) = var("HOME").or_else(|| var("USERPROFILE")) {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(raw)
}

/// `site-packages` of every virtualenv Poetry created for the project at
/// `cwd` under its `virtualenvs.path` (`<name>-<hash>-py<X.Y>`; one per
/// interpreter minor the user ran `poetry env use` with). Empty for
/// non-Poetry projects and whenever Poetry's configuration says the
/// virtualenv is in-project, disabled, or unresolvable. Read-only: nothing is
/// executed, no `poetry` binary is needed.
pub async fn find_poetry_virtualenv_site_packages(cwd: &Path) -> Vec<PathBuf> {
    let var = |name: &str| std::env::var(name).ok();
    match load_poetry_project(cwd, &var).await {
        Some(project) => poetry_virtualenv_site_packages(&project).await,
        None => Vec::new(),
    }
}

/// One compatible placement, with its activation record kept in the
/// same root. Version-dependent roots must never share an activated minor.
struct PoetryPlacement {
    root: PathBuf,
    activated: Option<String>,
    env_names: Vec<String>,
}

struct PoetryProject {
    config: PoetryVirtualenvConfig,
    placements: Vec<PoetryPlacement>,
}

impl PoetryProject {
    /// An existing `./.venv` wins unless `in-project` is explicitly false.
    /// Setting it true with no directory still allows an out-of-tree env.
    fn in_project_venv_exists(&self, cwd: &Path) -> bool {
        self.config.in_project != Some(false) && cwd.join(".venv").is_dir()
    }
}

/// EnvManager.get takes VIRTUAL_ENV, then a non-base CONDA_PREFIX, only
/// when this placement has no `poetry env use` record for the project.
fn poetry_active_prefix(
    placement: Option<&PoetryPlacement>,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    if placement.is_some_and(|p| p.activated.is_some()) {
        return None;
    }
    let prefix = var("VIRTUAL_ENV").or_else(|| var("CONDA_PREFIX"))?;
    (var("CONDA_DEFAULT_ENV").as_deref() != Some("base")).then_some(prefix)
}

/// Read this root's first matching `[<name>-<hash>] minor = "X.Y"`
/// record. An activation must never borrow a minor from another root.
async fn poetry_activated_env(cwd: &Path, names: &[String], root: &Path) -> Option<String> {
    let text = read_regular_to_string(&root.join("envs.toml")).await.ok()?;
    let doc = text.parse::<toml_edit::DocumentMut>().ok()?;
    let normalized = poetry_normalized_cwd(cwd);
    names.iter().find_map(|name| {
        let base = poetry_env_name_prefix(name, &normalized);
        let minor = doc.get(&base)?.get("minor")?.as_str()?.trim().to_string();
        (!minor.is_empty()).then(|| format!("{base}-py{minor}"))
    })
}

/// `None` for a non-Poetry project or unreadable/unparseable pyproject.
async fn load_poetry_project(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<PoetryProject> {
    let has = |leaf: &str| cwd.join(leaf).is_file();
    let pyproject = read_regular_to_string(&cwd.join("pyproject.toml"))
        .await
        .ok()?;
    let poetry_project =
        has("poetry.lock") || has("poetry.toml") || pyproject.contains("[tool.poetry");
    if !poetry_project {
        return None;
    }
    let names = poetry_project_names(&pyproject);
    if names.is_empty() {
        return None;
    }
    let local = match read_regular_to_string(&cwd.join("poetry.toml")).await {
        Ok(text) => PoetryVirtualenvConfig::from_toml(&text),
        Err(_) => PoetryVirtualenvConfig::default(),
    };
    let user = match poetry_user_config_path(var) {
        Some(path) => match read_regular_to_string(&path).await {
            Ok(text) => PoetryVirtualenvConfig::from_toml(&text),
            Err(_) => PoetryVirtualenvConfig::default(),
        },
        None => PoetryVirtualenvConfig::default(),
    };
    let config = PoetryVirtualenvConfig::from_env(var).or(local).or(user);
    let mut placements = Vec::new();
    for root in poetry_virtualenvs_paths(cwd, &config, var) {
        let activated = poetry_activated_env(cwd, &names, &root).await;
        let env_names = match &activated {
            Some(name) => vec![name.clone()],
            None => poetry_env_names(cwd, &names, &root).await,
        };
        // A missing root may still use the active shell in that Poetry
        // generation. Keep its precedence independent of another root's
        // activation, but only enumerate envs owned by this project.
        placements.push(PoetryPlacement {
            root,
            activated,
            env_names,
        });
    }
    Some(PoetryProject { config, placements })
}

/// Matching environment directories for the first project-name spelling
/// present in one root, preserving Poetry's existing name precedence.
async fn poetry_env_names(cwd: &Path, names: &[String], root: &Path) -> Vec<String> {
    let Ok(mut entries) = tokio::fs::read_dir(root).await else {
        return Vec::new();
    };
    let mut dir_names = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if crate::utils::fs::entry_is_dir(&entry).await {
            if let Some(name) = entry.file_name().to_str() {
                dir_names.push(name.to_string());
            }
        }
    }
    let normalized = poetry_normalized_cwd(cwd);
    let mut matched = names
        .iter()
        .map(|name| format!("{}-py", poetry_env_name_prefix(name, &normalized)))
        .map(|prefix| {
            dir_names
                .iter()
                .filter(|name| name.starts_with(&prefix))
                .cloned()
                .collect::<Vec<_>>()
        })
        .find(|found| !found.is_empty())
        .unwrap_or_default();
    matched.sort();
    matched
}

async fn poetry_placement_site_packages(placement: &PoetryPlacement) -> Vec<PathBuf> {
    let mut results = Vec::new();
    for name in &placement.env_names {
        results.extend(find_site_packages_under(&placement.root.join(name), "site-packages").await);
    }
    results
}

async fn poetry_virtualenv_site_packages(project: &PoetryProject) -> Vec<PathBuf> {
    if project.config.create == Some(false) {
        return Vec::new();
    }
    let mut results = Vec::new();
    for placement in &project.placements {
        for path in poetry_placement_site_packages(placement).await {
            if !results.contains(&path) {
                results.push(path);
            }
        }
    }
    results
}

/// Apply EnvManager.get's precedence separately for each compatible root.
/// With no recorded environment anywhere, the ordinary active/in-project
/// rules still apply once. Unioning only afterwards preserves both
/// runtimes when one Poetry generation recorded an env and another uses
/// the active shell; single-root activation still vetoes an unrelated shell.
async fn poetry_project_site_packages(
    cwd: &Path,
    project: &PoetryProject,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    let placements: Vec<Option<&PoetryPlacement>> = if project.placements.is_empty() {
        vec![None]
    } else {
        project.placements.iter().map(Some).collect()
    };
    let mut results = Vec::new();
    for placement in placements {
        let mut found = Vec::new();
        if let Some(active) = poetry_active_prefix(placement, var) {
            found = find_site_packages_under(Path::new(&active), "site-packages").await;
        }
        if found.is_empty() {
            if project.in_project_venv_exists(cwd) {
                found = find_site_packages_under(&cwd.join(".venv"), "site-packages").await;
            } else if project.config.create != Some(false) {
                if let Some(placement) = placement {
                    found = poetry_placement_site_packages(placement).await;
                }
            }
        }
        for path in found {
            if !results.contains(&path) {
                results.push(path);
            }
        }
    }
    results
}

/// `site-packages` of the virtualenv Pipenv would use for the project at
/// `cwd` when it is not in-project: the `.venv` FILE pointer (a path relative
/// to the project or a name under `WORKON_HOME`), `PIPENV_CUSTOM_VENV_NAME`,
/// or Pipenv's derived name `<sanitized dir name>-<8-char hash>` with any
/// `-<PIPENV_PYTHON>` suffix. Empty for non-Pipenv projects and whenever the
/// placement cannot be resolved. Read-only: nothing is executed, no `pipenv`
/// binary is needed.
pub async fn find_pipenv_virtualenv_site_packages(cwd: &Path) -> Vec<PathBuf> {
    let var = |name: &str| std::env::var(name).ok();
    find_pipenv_virtualenv_site_packages_with(cwd, &var).await
}

/// [`find_pipenv_virtualenv_site_packages`] over an explicit environment
/// (tests pass a closure instead of mutating the process environment).
async fn find_pipenv_virtualenv_site_packages_with(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    if !is_pipenv_project(cwd) {
        return Vec::new();
    }
    let mut venvs: Vec<PathBuf> = Vec::new();
    // A `.venv` FILE names the virtualenv (Pipenv 2018+): a path (contains a
    // separator) is relative to the project, anything else is a directory
    // name under WORKON_HOME; an empty file means the default placement.
    let dot_venv = cwd.join(".venv");
    if dot_venv.is_file() {
        if let Ok(text) = std::fs::read_to_string(&dot_venv) {
            let name = text.trim();
            if !name.is_empty() {
                if name.contains('/') || name.contains('\\') {
                    venvs.push(cwd.join(name));
                } else if let Some(home) = pipenv_workon_home(var) {
                    venvs.push(home.join(name));
                }
            }
        }
    }
    if venvs.is_empty() {
        if let Some(home) = pipenv_workon_home(var) {
            venvs.extend(pipenv_workon_home_venvs(cwd, &home, var));
        }
    }
    let mut results = Vec::new();
    for venv in venvs {
        let direct = find_site_packages_under(&venv, "site-packages").await;
        if !direct.is_empty() {
            results.extend(direct);
            continue;
        }
        // Pipenv 2018–2021 append the FULL `PIPENV_PYTHON` string to the
        // name (`<name>-<hash>-/usr/bin/python3`), so the virtualenv lives at
        // the bottom of a directory chain under WORKON_HOME; 2022+ append the
        // basename. Walk the chain down to the first directory that holds a
        // site-packages (bounded, never following symlinks).
        results.extend(find_nested_venv_site_packages(&venv, 12).await);
    }
    results
}

/// The site-packages of the virtualenv(s) at the bottom of a directory
/// chain rooted at `dir` (see the caller): every directory that itself holds
/// a `site-packages` stops the descent there, and the depth is bounded.
async fn find_nested_venv_site_packages(dir: &Path, depth: usize) -> Vec<PathBuf> {
    if depth == 0 {
        return Vec::new();
    }
    let mut results = Vec::new();
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return results;
    };
    let mut children = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let Ok(kind) = entry.file_type().await else {
            continue;
        };
        if !kind.is_dir() {
            continue;
        }
        // No name-based pruning: the chain literally contains `bin/python`
        // when PIPENV_PYTHON pointed at an interpreter, and the descent stops
        // at the first directory that holds a site-packages anyway.
        children.push(entry.path());
    }
    children.sort();
    for child in children {
        let here = find_site_packages_under(&child, "site-packages").await;
        if !here.is_empty() {
            results.extend(here);
        } else {
            results.extend(Box::pin(find_nested_venv_site_packages(&child, depth - 1)).await);
        }
    }
    results
}

/// Pipenv's `WORKON_HOME`: the environment variable (with `~`, `$VAR`,
/// `${VAR}` and, on Windows, `%VAR%` expanded the way Pipenv's
/// `expandvars`/`expanduser` do), else `$XDG_DATA_HOME/virtualenvs` or
/// `~/.local/share/virtualenvs` (POSIX) / `~/.virtualenvs` (Windows) —
/// unchanged from the pew era (Pipenv 7) through 2026.
fn pipenv_workon_home(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(raw) = var("WORKON_HOME").filter(|v| !v.trim().is_empty()) {
        return Some(pipenv_expand_path(raw.trim(), var));
    }
    let home = pipenv_home_dir(var)?;
    if cfg!(windows) {
        return Some(home.join(".virtualenvs"));
    }
    let data_home = var("XDG_DATA_HOME")
        .filter(|v| !v.trim().is_empty())
        .map(|v| pipenv_expand_path(v.trim(), var))
        .unwrap_or_else(|| home.join(".local").join("share"));
    Some(data_home.join("virtualenvs"))
}

/// `os.path.expanduser("~")` as Pipenv's Python sees it: `USERPROFILE` (then
/// `HOMEDRIVE`+`HOMEPATH`) on Windows — Python 3.8+ ignores `HOME` there, so a
/// Git-Bash `HOME=/c/Users/u` must not win — and `HOME` elsewhere.
fn pipenv_home_dir(var: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let non_empty = |v: String| (!v.trim().is_empty()).then_some(v);
    if cfg!(windows) {
        var("USERPROFILE")
            .and_then(non_empty)
            .or_else(|| {
                let drive = var("HOMEDRIVE").and_then(non_empty)?;
                let path = var("HOMEPATH").and_then(non_empty)?;
                Some(format!("{drive}{path}"))
            })
            .or_else(|| var("HOME").and_then(non_empty))
            .map(PathBuf::from)
    } else {
        var("HOME").and_then(non_empty).map(PathBuf::from)
    }
}

/// `os.path.expanduser(os.path.expandvars(raw))`: `$NAME` / `${NAME}` (and
/// `%NAME%` on Windows) from the environment — unknown names stay as written,
/// like Python — then a leading `~` from the home directory.
fn pipenv_expand_path(raw: &str, var: &impl Fn(&str) -> Option<String>) -> PathBuf {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '$' {
            if chars.get(i + 1) == Some(&'{') {
                if let Some(end) = chars[i + 2..].iter().position(|&ch| ch == '}') {
                    let name: String = chars[i + 2..i + 2 + end].iter().collect();
                    match var(&name) {
                        Some(v) => out.push_str(&v),
                        None => out.push_str(&format!("${{{name}}}")),
                    }
                    i += end + 3;
                    continue;
                }
            }
            let start = i + 1;
            let mut end = start;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            if end > start {
                let name: String = chars[start..end].iter().collect();
                match var(&name) {
                    Some(v) => out.push_str(&v),
                    None => {
                        out.push('$');
                        out.push_str(&name);
                    }
                }
                i = end;
                continue;
            }
        } else if c == '%' && cfg!(windows) {
            if let Some(end) = chars[i + 1..].iter().position(|&ch| ch == '%') {
                let name: String = chars[i + 1..i + 1 + end].iter().collect();
                if !name.is_empty() {
                    match var(&name) {
                        Some(v) => out.push_str(&v),
                        None => out.push_str(&format!("%{name}%")),
                    }
                    i += end + 2;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    if out == "~" {
        if let Some(home) = pipenv_home_dir(var) {
            return home;
        }
    }
    if let Some(rest) = out.strip_prefix("~/").or_else(|| out.strip_prefix("~\\")) {
        if let Some(home) = pipenv_home_dir(var) {
            return home.join(rest);
        }
    }
    PathBuf::from(out)
}

/// `Project._sanitize`: shell-hostile characters become `_` and the name is
/// cut to 42 characters. Pipenv 2022+ also replaces `& ( ) [ ]` (`wide`);
/// both spellings are tried so a virtualenv created by either generation is
/// found.
fn pipenv_sanitize(name: &str, wide: bool) -> String {
    name.chars()
        .map(|c| {
            let narrow = matches!(
                c,
                ' ' | '$' | '`' | '!' | '*' | '@' | '"' | '\\' | '\r' | '\n' | '\t'
            );
            let extra = wide && matches!(c, '&' | '(' | ')' | '[' | ']');
            if narrow || extra {
                '_'
            } else {
                c
            }
        })
        .take(42)
        .collect()
}

/// The 8-character virtualenv suffix — `Project._get_virtualenv_hash`: the
/// first 6 bytes of `sha256(pipfile_location)`, URL-safe base64. Stable from
/// Pipenv 7 through 2026 and pinned by known-answer vectors in the tests.
fn pipenv_venv_hash(pipfile_location: &str) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(pipfile_location.as_bytes());
    base64::engine::general_purpose::URL_SAFE.encode(&digest[..6])
}

/// The path string Pipenv hashes: on Windows the verbatim `\\?\` prefix is
/// dropped and the drive letter upper-cased (`normalize_drive`); elsewhere
/// the path as displayed.
fn pipenv_path_string(path: &Path) -> String {
    let mut text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        text = strip_windows_verbatim_prefix(&text);
        let mut chars: Vec<char> = text.chars().collect();
        if chars.len() >= 2 && chars[1] == ':' && chars[0].is_ascii_lowercase() {
            chars[0] = chars[0].to_ascii_uppercase();
            text = chars.into_iter().collect();
        }
    }
    text
}

/// `(project name, Pipfile location)` pairs Pipenv may have derived the
/// virtualenv name from, most likely first: `PIPENV_PIPFILE` as given (made
/// absolute), the Pipfile under the symlink-resolved project directory
/// (`find_pipfile` walks `Path.cwd().resolve()` — the physical path), then
/// the lexical absolute path.
fn pipenv_project_identities(
    cwd: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |pipfile: PathBuf| {
        let name = pipfile
            .parent()
            .and_then(Path::file_name)
            .map(|n| n.to_string_lossy().into_owned());
        let Some(name) = name else {
            return;
        };
        let location = pipenv_path_string(&pipfile);
        if !out.iter().any(|(_, l)| l == &location) {
            out.push((name, location));
        }
    };
    if let Some(explicit) = var("PIPENV_PIPFILE").filter(|v| !v.trim().is_empty()) {
        let p = PathBuf::from(explicit.trim());
        push(if p.is_absolute() { p } else { cwd.join(p) });
    }
    if let Ok(real) = std::fs::canonicalize(cwd) {
        push(real.join("Pipfile"));
    }
    let lexical = if cwd.is_absolute() {
        cwd.to_path_buf()
    } else {
        std::path::absolute(cwd).unwrap_or_else(|_| cwd.to_path_buf())
    };
    push(lexical.join("Pipfile"));
    out
}

/// Every directory under `workon_home` that Pipenv could have created for the
/// project at `cwd`: `PIPENV_CUSTOM_VENV_NAME` verbatim, else
/// `<sanitized name>-<hash>` optionally followed by `-<PIPENV_PYTHON>`
/// (matched as a `-` suffix rather than reproduced — the suffix's spelling
/// changed across releases), plus Pipenv's case-insensitive-filesystem
/// fallback (a same-name-different-case directory whose hash was computed
/// over the recased location). Sorted; never follows the entries.
fn pipenv_workon_home_venvs(
    cwd: &Path,
    workon_home: &Path,
    var: &impl Fn(&str) -> Option<String>,
) -> Vec<PathBuf> {
    if let Some(custom) = var("PIPENV_CUSTOM_VENV_NAME").filter(|v| !v.trim().is_empty()) {
        return vec![workon_home.join(custom.trim())];
    }
    let identities = pipenv_project_identities(cwd, var);
    if identities.is_empty() {
        return Vec::new();
    }
    let mut exact: Vec<String> = Vec::new();
    for (name, location) in &identities {
        let hash = pipenv_venv_hash(location);
        for wide in [true, false] {
            let candidate = format!("{}-{hash}", pipenv_sanitize(name, wide));
            if !exact.contains(&candidate) {
                exact.push(candidate);
            }
        }
    }
    let Ok(entries) = std::fs::read_dir(workon_home) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(leaf) = file_name.to_str() else {
            continue;
        };
        let direct = exact.iter().any(|c| {
            leaf == c
                || leaf
                    .strip_prefix(c.as_str())
                    .is_some_and(|rest| rest.starts_with('-'))
        });
        if direct {
            found.push(entry.path());
            continue;
        }
        // Case-insensitive fallback: `<Recased>-<hash>` where the hash was
        // computed over the location with the recased name spliced in.
        let Some((env_name, hash)) = leaf.rsplit_once('-') else {
            continue;
        };
        if hash.len() != 8 {
            continue;
        }
        for (name, location) in &identities {
            let sanitized = pipenv_sanitize(name, true);
            if env_name.eq_ignore_ascii_case(&sanitized)
                && env_name != sanitized
                && pipenv_venv_hash(&location.replace(name.as_str(), env_name)) == hash
            {
                found.push(entry.path());
                break;
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// What the interpreter query below depends on besides the interpreter
/// itself: the whole process environment (`PATH` picks the interpreter;
/// `HOME`, `PYTHONUSERBASE`, `PYTHONHOME`, … shape its answer) and the
/// working directory.
type SiteQueryKey = (
    Vec<(std::ffi::OsString, std::ffi::OsString)>,
    Option<PathBuf>,
);

fn site_query_key() -> SiteQueryKey {
    let mut env: Vec<_> = std::env::vars_os().collect();
    env.sort();
    (env, std::env::current_dir().ok())
}

/// The last successful `(key, answer)` of an expensive query, re-run
/// whenever the key differs. A failed query (`None`) is never stored, so the
/// next ask runs it again exactly as an unmemoized caller would: a transient
/// spawn failure during the crawl cannot blank the vendor phase's answer.
struct KeyedMemo<K, V> {
    slot: std::sync::Mutex<Option<(K, V)>>,
}

impl<K: PartialEq, V: Clone> KeyedMemo<K, V> {
    const fn new() -> Self {
        Self {
            slot: std::sync::Mutex::new(None),
        }
    }

    fn get_or_run(&self, key: K, run: impl FnOnce() -> Option<V>) -> Option<V> {
        let lock = || {
            self.slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        if let Some((cached, value)) = lock().as_ref() {
            if *cached == key {
                return Some(value.clone());
            }
        }
        let value = run()?;
        *lock() = Some((key, value.clone()));
        Some(value)
    }
}

/// The interpreter's site-packages answer (the `find_python_command` probe
/// plus the `site` query — two process spawns), per [`SiteQueryKey`]: a
/// scan asks it once for its crawl and again when it vendors, in the same
/// environment, so the second ask re-spawned both processes for the same
/// output. Only a successful answer is kept (see [`KeyedMemo`]).
static SITE_QUERY_MEMO: KeyedMemo<SiteQueryKey, String> = KeyedMemo::new();

/// The unmemoized interpreter query: probe for a python and ask it for its
/// site-packages. [`SITE_QUERY_MEMO`] wraps this; tests call it directly as
/// the oracle the memoized answer must equal.
fn run_site_query() -> Option<String> {
    let python_cmd = find_python_command()?;
    let runner = SystemCommandRunner;
    runner.run(
        python_cmd,
        &[
            "-c",
            "import site; print('\\n'.join(site.getsitepackages())); print(site.getusersitepackages())",
        ],
    )
}

/// Get global/system Python `site-packages` directories.
///
/// Queries `python3` for site-packages paths, then checks well-known system
/// locations including Homebrew, conda, uv tools and interpreters, pipx
/// venvs, Poetry's installer venv, PDM's global project and interpreters,
/// pip --user, etc.
pub async fn get_global_python_site_packages() -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    fn add_path(p: PathBuf, seen: &mut HashSet<PathBuf>, results: &mut Vec<PathBuf>) {
        let resolved = if p.is_absolute() {
            p
        } else {
            std::path::absolute(&p).unwrap_or(p)
        };
        if seen.insert(resolved.clone()) {
            results.push(resolved);
        }
    }

    // 1. Ask Python for site-packages (subprocesses: on the blocking pool)
    let site_output =
        run_blocking(|| SITE_QUERY_MEMO.get_or_run(site_query_key(), run_site_query)).await;
    if let Some(stdout) = site_output {
        for p in parse_python_site_packages_output(&stdout) {
            add_path(p, &mut seen, &mut results);
        }
    }

    // 2. Well-known system paths
    let home_dir = crate::utils::fs::home_dir();

    // Helper closure to scan base/{lib,lib64}/python3.*/[dist|site]-packages.
    // `lib64` is the multilib dir on RHEL/Fedora/SUSE where compiled
    // (C-extension) packages land — pure-Python ones go to `lib`, so both
    // hold real, distinct packages. Scanning only `lib` would miss every
    // native package on those distros.
    async fn scan_well_known(
        base: &Path,
        pkg_type: &str,
        seen: &mut HashSet<PathBuf>,
        results: &mut Vec<PathBuf>,
    ) {
        let mut matches = find_python_dirs(base, &["lib", "python3.*", pkg_type]).await;
        matches.extend(find_python_dirs(base, &["lib64", "python3.*", pkg_type]).await);
        for m in matches {
            add_path(m, seen, results);
        }
    }

    #[cfg(not(windows))]
    {
        // Debian/Ubuntu
        scan_well_known(Path::new("/usr"), "dist-packages", &mut seen, &mut results).await;
        scan_well_known(Path::new("/usr"), "site-packages", &mut seen, &mut results).await;
        // Debian pip / most distros / macOS
        scan_well_known(
            Path::new("/usr/local"),
            "dist-packages",
            &mut seen,
            &mut results,
        )
        .await;
        scan_well_known(
            Path::new("/usr/local"),
            "site-packages",
            &mut seen,
            &mut results,
        )
        .await;
        // pip --user on Unix
        let user_local = home_dir.join(".local");
        scan_well_known(&user_local, "site-packages", &mut seen, &mut results).await;
    }

    // macOS-specific
    #[cfg(target_os = "macos")]
    {
        scan_well_known(
            Path::new("/opt/homebrew"),
            "site-packages",
            &mut seen,
            &mut results,
        )
        .await;

        // Python.org framework: /Library/Frameworks/Python.framework/Versions/
        // holds bare version dirs (`3.11`, `3.12`, `Current`) — NOT `python3.X`
        // — so the version segment must be matched with `*`, not `python3.*`.
        let fw_matches = find_python_dirs(
            Path::new("/Library/Frameworks/Python.framework"),
            &["Versions", "*", "lib", "python3.*", "site-packages"],
        )
        .await;
        for m in fw_matches {
            add_path(m, &mut seen, &mut results);
        }

        // pip --user on macOS. Framework builds (Apple's /usr/bin/python3 AND
        // Homebrew's python3) use the `osx_framework_user` install scheme:
        // ~/Library/Python/<X.Y>/lib/python/site-packages — one tree per
        // interpreter MINOR VERSION, with a BARE `python` leaf, so the version
        // segment needs `*` and the leaf must NOT be matched with `python3.*`.
        // This is the macOS counterpart of the `~/.local` (Unix) and
        // `%APPDATA%\Python` (Windows) user scans; without it the only thing
        // that ever surfaced a `pip3 install --user` package was the
        // `site.getusersitepackages()` query above, which reports just the one
        // interpreter first on PATH — so on a stock Mac with both Apple's
        // python3 and a Homebrew/pyenv python3, user installs under every
        // other interpreter were invisible.
        let user_fw_matches = find_python_dirs(
            &home_dir.join("Library").join("Python"),
            &["*", "lib", "python", "site-packages"],
        )
        .await;
        for m in user_fw_matches {
            add_path(m, &mut seen, &mut results);
        }
    }

    // Windows-specific
    #[cfg(windows)]
    {
        // pip --user on Windows: %APPDATA%\Python\PythonXY\site-packages
        if let Ok(appdata) = std::env::var("APPDATA") {
            let appdata_python = PathBuf::from(&appdata).join("Python");
            for entry in crate::utils::fs::list_dir_entries(&appdata_python).await {
                let p = appdata_python.join(entry.file_name()).join("site-packages");
                if tokio::fs::metadata(&p).await.is_ok() {
                    add_path(p, &mut seen, &mut results);
                }
            }
        }
        // Common Windows Python install locations
        for base in &["C:\\Python", "C:\\Program Files\\Python"] {
            for entry in crate::utils::fs::list_dir_entries(Path::new(base)).await {
                let sp = PathBuf::from(base)
                    .join(entry.file_name())
                    .join("Lib")
                    .join("site-packages");
                if tokio::fs::metadata(&sp).await.is_ok() {
                    add_path(sp, &mut seen, &mut results);
                }
            }
        }
        // Microsoft Store / python.org via LocalAppData
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let programs_python = PathBuf::from(&local).join("Programs").join("Python");
            for entry in crate::utils::fs::list_dir_entries(&programs_python).await {
                let sp = programs_python
                    .join(entry.file_name())
                    .join("Lib")
                    .join("site-packages");
                if tokio::fs::metadata(&sp).await.is_ok() {
                    add_path(sp, &mut seen, &mut results);
                }
            }
        }
    }

    // pyenv (works on macOS and Linux)
    #[cfg(not(windows))]
    {
        let pyenv_root = std::env::var("PYENV_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home_dir.join(".pyenv"));
        let pyenv_versions = pyenv_root.join("versions");
        let pyenv_matches =
            find_python_dirs(&pyenv_versions, &["*", "lib", "python3.*", "site-packages"]).await;
        for m in pyenv_matches {
            add_path(m, &mut seen, &mut results);
        }
    }

    // Conda
    let anaconda = home_dir.join("anaconda3");
    scan_well_known(&anaconda, "site-packages", &mut seen, &mut results).await;
    let miniconda = home_dir.join("miniconda3");
    scan_well_known(&miniconda, "site-packages", &mut seen, &mut results).await;

    // uv tool envs (`uv tool install`): one venv per tool under every
    // root uv may use (see `uv_dir_candidates`).
    for tools in uv_dir_candidates(&home_dir, "UV_TOOL_DIR", "tools") {
        for m in find_child_env_site_packages(&tools).await {
            add_path(m, &mut seen, &mut results);
        }
    }

    // pipx app venvs (`pipx install hatch`): one venv per app under
    // `<pipx home>/venvs/<app>`. Every candidate home that exists is
    // scanned, not just the one pipx would pick today: an app installed
    // under an older default is still a real install, and `seen` dedups
    // overlaps (e.g. PIPX_HOME set to the default).
    for pipx_home in pipx_home_candidates(&home_dir) {
        let venvs = pipx_home.join("venvs");
        #[cfg(not(windows))]
        let mut matches =
            find_python_dirs(&venvs, &["*", "lib", "python3.*", "site-packages"]).await;
        #[cfg(not(windows))]
        matches
            .extend(find_python_dirs(&venvs, &["*", "lib64", "python3.*", "site-packages"]).await);
        #[cfg(windows)]
        let matches = find_python_dirs(&venvs, &["*", "Lib", "site-packages"]).await;
        for m in matches {
            add_path(m, &mut seen, &mut results);
        }
    }

    // Poetry's own venv from the official installer
    // (`install.python-poetry.org`): `<data dir>/venv`, where the data dir
    // is `$POETRY_HOME` or the installer's platform default (#640). Both are
    // scanned: an install made before `POETRY_HOME` was set (or unset) is
    // still a real install.
    {
        let var = |name: &str| std::env::var(name).ok();
        let without_poetry_home = |name: &str| {
            if name == "POETRY_HOME" {
                None
            } else {
                std::env::var(name).ok()
            }
        };
        let data_dirs = [
            poetry_installer_data_dir(&var),
            poetry_installer_data_dir(&without_poetry_home),
        ];
        for data_dir in data_dirs.into_iter().flatten() {
            for m in find_env_site_packages(&data_dir.join("venv")).await {
                add_path(m, &mut seen, &mut results);
            }
        }
    }

    // uv-managed Python interpreters (`uv python install 3.X`), one per
    // child of uv's python dir (`cpython-3.X.*-<platform>`). The typical
    // flow is `uv venv` + `uv pip install`, where the venv layout is
    // already covered by `find_local_venv_site_packages`. But power users
    // can install packages directly into the managed interpreter (e.g. via
    // `uv pip install --system --python <uv-python>`), and globally
    // discovered crawls should surface those.
    for python in uv_dir_candidates(&home_dir, "UV_PYTHON_INSTALL_DIR", "python") {
        for m in find_child_env_site_packages(&python).await {
            add_path(m, &mut seen, &mut results);
        }
    }

    // PDM's global project (`pdm add -g`) and PDM-managed interpreters
    // (`pdm python install`).
    for m in pdm_global_site_packages(&home_dir).await {
        add_path(m, &mut seen, &mut results);
    }

    results
}

/// `site-packages` of every environment directly under `parent`:
/// `<parent>/<env>/lib{,64}/python3.X/site-packages` on Unix and
/// `<parent>\<env>\Lib\site-packages` on Windows.
async fn find_child_env_site_packages(parent: &Path) -> Vec<PathBuf> {
    #[cfg(not(windows))]
    {
        let mut matches =
            find_python_dirs(parent, &["*", "lib", "python3.*", "site-packages"]).await;
        matches
            .extend(find_python_dirs(parent, &["*", "lib64", "python3.*", "site-packages"]).await);
        matches
    }
    #[cfg(windows)]
    {
        find_python_dirs(parent, &["*", "Lib", "site-packages"]).await
    }
}

/// `site-packages` of the one environment (venv or interpreter) whose
/// prefix is `prefix`, in the same layouts as
/// [`find_child_env_site_packages`].
async fn find_env_site_packages(prefix: &Path) -> Vec<PathBuf> {
    #[cfg(not(windows))]
    {
        let mut matches = find_python_dirs(prefix, &["lib", "python3.*", "site-packages"]).await;
        matches.extend(find_python_dirs(prefix, &["lib64", "python3.*", "site-packages"]).await);
        matches
    }
    #[cfg(windows)]
    {
        find_python_dirs(prefix, &["Lib", "site-packages"]).await
    }
}

/// `$var` as a directory when it is set to an absolute path. platformdirs
/// and uv both ignore a relative `XDG_*` value, per the XDG spec.
#[cfg(not(windows))]
fn absolute_env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// The directories uv may keep `bucket` (`tools` or `python`) in, most
/// specific first.
///
/// uv (`StateStore::from_settings`) uses `$override_var` (`UV_TOOL_DIR`
/// or `UV_PYTHON_INSTALL_DIR`) when set, made absolute against the cwd.
/// Otherwise it uses `<data dir>/uv/<bucket>`, where the data dir is
/// `$XDG_DATA_HOME` (absolute only) or `~/.local/share` on Linux and
/// macOS, and `%APPDATA%` on Windows (`uv tool dir` prints
/// `%APPDATA%\uv\tools` there). The legacy roots that older layouts used
/// are returned too: `~/Library/Application Support/uv` on macOS, and
/// `%LOCALAPPDATA%\uv`, which earlier socket-patch releases scanned, on
/// Windows. Callers skip the ones that don't exist.
#[cfg_attr(windows, allow(unused_variables))]
fn uv_dir_candidates(home_dir: &Path, override_var: &str, bucket: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = std::env::var_os(override_var).filter(|v| !v.is_empty()) {
        let dir = PathBuf::from(dir);
        dirs.push(std::path::absolute(&dir).unwrap_or(dir));
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = absolute_env_dir("XDG_DATA_HOME") {
            dirs.push(xdg.join("uv").join(bucket));
        }
        dirs.push(
            home_dir
                .join(".local")
                .join("share")
                .join("uv")
                .join(bucket),
        );
    }
    #[cfg(target_os = "macos")]
    dirs.push(
        home_dir
            .join("Library")
            .join("Application Support")
            .join("uv")
            .join(bucket),
    );
    #[cfg(windows)]
    for var in ["APPDATA", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(var).filter(|v| !v.is_empty()) {
            dirs.push(PathBuf::from(base).join("uv").join(bucket));
        }
    }
    dirs
}

/// The directories platformdirs may resolve for PDM's per-user config
/// (`xdg_var` = `XDG_CONFIG_HOME`, `unix_default` = `.config`) or data
/// (`XDG_DATA_HOME`, `.local/share`) dir, most specific first:
/// `$xdg_var/pdm` (absolute only; platformdirs 4.4+ also honors it on
/// macOS), `~/<unix_default>/pdm` on Linux,
/// `~/Library/Application Support/pdm` on macOS, and
/// `%LOCALAPPDATA%\pdm\pdm` on Windows.
#[cfg_attr(windows, allow(unused_variables))]
fn pdm_dir_candidates(home_dir: &Path, xdg_var: &str, unix_default: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    #[cfg(not(windows))]
    if let Some(xdg) = absolute_env_dir(xdg_var) {
        dirs.push(xdg.join("pdm"));
    }
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    dirs.push(home_dir.join(unix_default).join("pdm"));
    #[cfg(target_os = "macos")]
    dirs.push(
        home_dir
            .join("Library")
            .join("Application Support")
            .join("pdm"),
    );
    #[cfg(windows)]
    if let Some(local) = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()) {
        dirs.push(PathBuf::from(local).join("pdm").join("pdm"));
    }
    dirs
}

/// `site-packages` of PDM's global installs:
///
/// - The global project's environment (`pdm add -g`). The project lives
///   at the `global_project.path` setting, by default
///   `<user config dir>/pdm/global-project`. Its environment is the
///   in-project `.venv`, an out-of-tree venv under `venv.location`
///   (default `<user data dir>/pdm/venvs`) named
///   `<project dir name>-<hash>-<python>`, or whatever interpreter
///   `pdm use -g` recorded in its `.pdm-python`.
/// - PDM-managed interpreters (`pdm python install`), one per child of
///   `python.install_root` (default `<user data dir>/pdm/python`).
///
/// The settings come from PDM's global config file, `$PDM_CONFIG_FILE`
/// or `<user config dir>/pdm/config.toml`. Every candidate is collected,
/// and the ones that don't exist yield nothing.
async fn pdm_global_site_packages(home_dir: &Path) -> Vec<PathBuf> {
    let config_dirs = pdm_dir_candidates(home_dir, "XDG_CONFIG_HOME", Path::new(".config"));
    let data_dirs = pdm_dir_candidates(
        home_dir,
        "XDG_DATA_HOME",
        &Path::new(".local").join("share"),
    );

    let mut config_files: Vec<PathBuf> = std::env::var_os("PDM_CONFIG_FILE")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .into_iter()
        .collect();
    config_files.extend(config_dirs.iter().map(|d| d.join("config.toml")));

    let mut projects = Vec::new();
    let mut install_roots = Vec::new();
    let mut venv_roots = Vec::new();
    // PDM expands `~` with Python's `expanduser`, which reads USERPROFILE
    // on Windows and ignores HOME there (Python 3.8+), so a Git Bash HOME
    // must not decide where a relocated setting points.
    let var = |name: &str| {
        if cfg!(windows) && name == "HOME" {
            return None;
        }
        std::env::var(name).ok()
    };
    for file in &config_files {
        let Ok(text) = read_regular_to_string(file).await else {
            continue;
        };
        let Ok(doc) = text.parse::<toml_edit::DocumentMut>() else {
            continue;
        };
        let setting = |table: &str, key: &str| {
            doc.get(table)
                .and_then(|t| t.get(key))
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty())
                .map(|v| expand_home(v, &var))
        };
        projects.extend(setting("global_project", "path"));
        install_roots.extend(setting("python", "install_root"));
        venv_roots.extend(setting("venv", "location"));
    }
    projects.extend(config_dirs.iter().map(|d| d.join("global-project")));
    install_roots.extend(data_dirs.iter().map(|d| d.join("python")));
    venv_roots.extend(data_dirs.iter().map(|d| d.join("venvs")));

    let mut results = Vec::new();
    for project in &projects {
        results.extend(find_env_site_packages(&project.join(".venv")).await);
        if let Some(name) = project.file_name().and_then(|n| n.to_str()) {
            let prefix = format!("{name}-");
            for root in &venv_roots {
                for entry in crate::utils::fs::list_dir_entries(root).await {
                    if entry.file_name().to_string_lossy().starts_with(&prefix) {
                        results.extend(find_env_site_packages(&root.join(entry.file_name())).await);
                    }
                }
            }
        }
        // `.pdm-python` names the interpreter: `<prefix>/bin/python3` in a
        // venv or Unix install, `<prefix>\Scripts\python.exe` in a Windows
        // venv, `<prefix>\python.exe` in a Windows install.
        if let Ok(text) = read_regular_to_string(&project.join(".pdm-python")).await {
            let interpreter = PathBuf::from(text.trim());
            let prefixes = interpreter.is_absolute().then_some(&interpreter);
            for prefix in prefixes
                .into_iter()
                .flat_map(|i| i.ancestors().skip(1).take(2))
            {
                results.extend(find_env_site_packages(prefix).await);
            }
        }
    }
    for root in &install_roots {
        results.extend(find_child_env_site_packages(root).await);
    }
    results
}

/// The directories pipx may use as its home, most specific first.
///
/// pipx (>= 1.3, `pipx/paths.py`) uses `$PIPX_HOME` when set, otherwise
/// its legacy home `~/.local/pipx` if that exists, otherwise platformdirs'
/// user data dir: `$XDG_DATA_HOME/pipx` (default `~/.local/share/pipx`) on
/// Linux, `~/Library/Application Support/pipx` on macOS, and
/// `%USERPROFILE%\pipx` on Windows (with `%LOCALAPPDATA%\pipx\pipx` as its
/// platformdirs fallback). All of them are returned; callers skip the ones
/// that don't exist.
fn pipx_home_candidates(home_dir: &Path) -> Vec<PathBuf> {
    let mut homes = Vec::new();
    if let Some(pipx_home) = std::env::var_os("PIPX_HOME").filter(|v| !v.is_empty()) {
        homes.push(PathBuf::from(pipx_home));
    }
    homes.push(home_dir.join(".local").join("pipx"));
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    {
        // platformdirs ignores a relative XDG_DATA_HOME, per the XDG spec.
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            homes.push(xdg.join("pipx"));
        }
        homes.push(home_dir.join(".local").join("share").join("pipx"));
    }
    #[cfg(target_os = "macos")]
    homes.push(
        home_dir
            .join("Library")
            .join("Application Support")
            .join("pipx"),
    );
    #[cfg(windows)]
    {
        homes.push(home_dir.join("pipx"));
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            homes.push(PathBuf::from(local).join("pipx").join("pipx"));
        }
    }
    homes
}

/// Returns true if `cwd` looks like a Python project root.
///
/// Used by `PythonCrawler::get_site_packages_paths` to decide
/// whether to fall back to the global-discovery path when no venv
/// was found. Mirrors `is_dotnet_project` in nuget_crawler and
/// `RubyCrawler::has_bundler_manifest` (Gemfile / Gemfile.lock / gems.rb /
/// gems.locked) in ruby_crawler.
///
/// The list intentionally covers all major Python toolchains:
///   * `pyproject.toml` — PEP 518 / 621 (poetry, hatch, uv, flit,
///     setuptools-PEP-517, pdm, etc. — anything modern)
///   * `setup.py` / `setup.cfg` — legacy setuptools
///   * `requirements.txt` — pip-compile / bare requirements
///   * `uv.lock` — uv-managed projects (PEP 751 export sibling is
///     `pylock.toml` but in practice `uv.lock` is what ships)
///   * `Pipfile` / `Pipfile.lock` — pipenv projects, which commonly
///     ship NEITHER pyproject.toml nor requirements.txt and keep
///     their venvs out-of-tree (`~/.local/share/virtualenvs`)
pub async fn is_python_project(cwd: &Path) -> bool {
    let markers = [
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "uv.lock",
        "Pipfile",
        "Pipfile.lock",
    ];
    for m in &markers {
        if tokio::fs::metadata(cwd.join(m)).await.is_ok() {
            return true;
        }
    }
    crate::utils::python_lock::python_lock_paths(cwd).is_ok_and(|paths| !paths.is_empty())
}

// ---------------------------------------------------------------------------
// PythonCrawler
// ---------------------------------------------------------------------------

/// Python ecosystem crawler for discovering packages in `site-packages`.
pub struct PythonCrawler;

impl PythonCrawler {
    /// Create a new `PythonCrawler`.
    pub fn new() -> Self {
        Self
    }

    /// Get `site-packages` paths based on options.
    ///
    /// Local-mode discovery has two stages:
    ///   1. `find_local_venv_site_packages` — handles `VIRTUAL_ENV`,
    ///      `.venv`, and `venv` directories, then Poetry's and Pipenv's
    ///      out-of-tree virtualenvs.
    ///   2. If no venv was found AND the cwd looks like a Python
    ///      project (see `is_python_project`), fall through
    ///      to `get_global_python_site_packages`. This mirrors the
    ///      cargo / ruby / go pattern where a project marker
    ///      indicates "scan this ecosystem globally for this project".
    ///
    /// Without the marker fallback, a fresh clone with
    /// `pyproject.toml` + `uv.lock` but no `.venv` would silently
    /// return zero packages.
    pub async fn get_site_packages_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(get_global_python_site_packages().await);
        }
        let venv_paths = find_local_venv_site_packages(&options.cwd).await;
        if !venv_paths.is_empty() {
            return Ok(venv_paths);
        }
        if is_python_project(&options.cwd).await {
            return Ok(get_global_python_site_packages().await);
        }
        Ok(Vec::new())
    }

    /// Crawl all discovered `site-packages` and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let sp_paths = self
            .get_site_packages_paths(options)
            .await
            .unwrap_or_default();

        for sp_path in &sp_paths {
            for (name, version) in list_dist_info_packages(sp_path).await {
                let purl = format!("pkg:pypi/{name}@{version}");
                if !seen.insert(purl.clone()) {
                    continue;
                }
                packages.push(CrawledPackage {
                    name,
                    version,
                    namespace: None,
                    purl,
                    path: sp_path.clone(),
                });
            }
        }

        packages
    }

    /// Find specific packages by PURL.
    ///
    /// Accepts base PURLs (no qualifiers) — the caller should strip qualifiers
    /// before calling.
    pub async fn find_by_purls(
        &self,
        site_packages_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        // Build lookup: canonicalized-name@version -> purl. The API serves
        // purls percent-encoded (a PEP 440 local/epoch version carries
        // `+`/`!`, arriving as `%2B`/`%21`), and `parse_pypi_purl` decodes
        // the coordinates — undecoded, the installed package never matches.
        let purl_lookup = purl_lookup(purls);
        // A lookup with no parseable PURL never lists the directory.
        if purl_lookup.is_empty() {
            return Ok(HashMap::new());
        }
        let listing = list_dist_info_packages(site_packages_path).await;
        Ok(match_listing(&purl_lookup, site_packages_path, &listing))
    }

    /// [`Self::find_by_purls`] over an ALREADY-LISTED `site_packages_path`
    /// — the same matching over the same listing shape, for a caller that
    /// lists a site once and asks about it for many packages.
    pub fn find_by_purls_listed(
        &self,
        site_packages_path: &Path,
        listing: &[(String, String)],
        purls: &[String],
    ) -> HashMap<String, CrawledPackage> {
        let purl_lookup = purl_lookup(purls);
        if purl_lookup.is_empty() {
            return HashMap::new();
        }
        match_listing(&purl_lookup, site_packages_path, listing)
    }
}

/// `canonicalized-name@version -> purl` for every parseable PURL in
/// `purls`; see [`PythonCrawler::find_by_purls`] for the decoding.
fn purl_lookup(purls: &[String]) -> HashMap<String, &str> {
    let mut lookup: HashMap<String, &str> = HashMap::new();
    for purl in purls {
        if let Some((name, version)) = crate::utils::purl::parse_pypi_purl(purl) {
            let key = format!("{}@{}", canonicalize_pypi_name(&name), version);
            lookup.insert(key, purl.as_str());
        }
    }
    lookup
}

/// The listed packages `purl_lookup` names, in listing order (a later
/// listing entry overwrites an earlier one under the same key).
fn match_listing(
    purl_lookup: &HashMap<String, &str>,
    site_packages_path: &Path,
    listing: &[(String, String)],
) -> HashMap<String, CrawledPackage> {
    let mut result = HashMap::new();
    for (name, version) in listing {
        let key = format!("{name}@{version}");
        if let Some(&matched_purl) = purl_lookup.get(&key) {
            result.insert(
                matched_purl.to_string(),
                CrawledPackage {
                    name: name.clone(),
                    version: version.clone(),
                    namespace: None,
                    purl: matched_purl.to_string(),
                    path: site_packages_path.to_path_buf(),
                },
            );
        }
    }
    result
}

impl PythonCrawler {
    /// [`Self::find_by_purls`] for each of `purls` ON ITS OWN — element `i`
    /// is what `find_by_purls(site, &[purls[i]])` returns for that PURL —
    /// from ONE listing of `site_packages_path` instead of one per PURL.
    /// (A batched `find_by_purls` is not the same thing: two PURLs whose
    /// canonical `name@version` coincide share one lookup slot there, and
    /// only the last one is found.)
    pub async fn find_each_by_purl(
        &self,
        site_packages_path: &Path,
        purls: &[String],
    ) -> Vec<Option<CrawledPackage>> {
        let keys: Vec<Option<String>> = purls
            .iter()
            .map(|purl| {
                let (name, version) = crate::utils::purl::parse_pypi_purl(purl)?;
                Some(format!("{}@{}", canonicalize_pypi_name(&name), version))
            })
            .collect();
        // A lookup with no parseable PURL never lists the directory.
        if keys.iter().all(Option::is_none) {
            return vec![None; purls.len()];
        }

        // key -> the LAST listed entry with that key (find_by_purls's
        // insert-overwrites order).
        let mut installed: HashMap<String, (String, String)> = HashMap::new();
        for (name, version) in list_dist_info_packages(site_packages_path).await {
            installed.insert(format!("{name}@{version}"), (name, version));
        }
        keys.into_iter()
            .zip(purls)
            .map(|(key, purl)| {
                let (name, version) = installed.get(key.as_ref()?)?.clone();
                Some(CrawledPackage {
                    name,
                    version,
                    namespace: None,
                    purl: purl.clone(),
                    path: site_packages_path.to_path_buf(),
                })
            })
            .collect()
    }
}

/// Scan a `site-packages` directory for installed distributions — the
/// `.dist-info` entries wheels install, and the legacy `.egg-info`
/// entries an sdist built without `wheel`, distutils or a distro package
/// leaves — returning `(canonicalized name, version)` for each one that
/// yields metadata, in listing order. One blocking-pool task for the
/// listing and every metadata read, rather than a runtime hop per open,
/// read and stat.
pub(crate) async fn list_dist_info_packages(site_packages_path: &Path) -> Vec<(String, String)> {
    let site_packages_path = site_packages_path.to_path_buf();
    run_blocking(move || list_dist_info_packages_sync(&site_packages_path)).await
}

/// Blocking body of [`list_dist_info_packages`].
fn list_dist_info_packages_sync(site_packages_path: &Path) -> Vec<(String, String)> {
    list_dir_sync(site_packages_path)
        .into_iter()
        .filter_map(|entry| {
            let name_str = entry.name.to_string_lossy();
            let path = site_packages_path.join(&*name_str);
            if name_str.ends_with(".dist-info") {
                read_python_metadata_sync(&path)
            } else if name_str.ends_with(".egg-info") {
                read_egg_info_metadata_sync(&path)
            } else {
                None
            }
        })
        .map(|(raw_name, version)| (canonicalize_pypi_name(&raw_name), version))
        .collect()
}

impl Default for PythonCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure parser for `python -c "import site; print(...);
/// print(site.getusersitepackages())"` stdout. Splits the output on
/// newlines, trims each line, discards empty lines, and returns the
/// remaining lines as `PathBuf`s. Extracted so the path-derivation
/// logic is unit-testable without a real Python interpreter.
pub fn parse_python_site_packages_output(stdout: &str) -> Vec<PathBuf> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::purl::parse_pypi_purl;

    // ── Pipenv out-of-tree virtualenv discovery ─────────────────────────────

    /// Known-answer vectors computed with Pipenv's own algorithm
    /// (`base64.urlsafe_b64encode(hashlib.sha256(location.encode()).digest()[:6])`).
    #[test]
    fn pipenv_venv_hash_matches_pipenv_get_virtualenv_hash() {
        assert_eq!(pipenv_venv_hash("/tmp/proj/Pipfile"), "9zRXrcHj");
        assert_eq!(pipenv_venv_hash("/Users/dev/My App/Pipfile"), "OhBEiq15");
        assert_eq!(pipenv_venv_hash(r"C:\Users\dev\app\Pipfile"), "6E88tlV3");
    }

    #[test]
    fn pipenv_sanitize_replaces_shell_hostile_characters_and_caps_at_42() {
        assert_eq!(pipenv_sanitize("My App", true), "My_App");
        assert_eq!(pipenv_sanitize("a(b)[c]&d", true), "a_b__c__d");
        assert_eq!(pipenv_sanitize("a(b)[c]&d", false), "a(b)[c]&d");
        assert_eq!(
            pipenv_sanitize("we$ird`na!me*@\"x\\", false),
            "we_ird_na_me___x_"
        );
        let long = "p".repeat(60);
        assert_eq!(pipenv_sanitize(&long, true).chars().count(), 42);
        // Case is preserved (Pipenv does not lowercase the project name).
        assert_eq!(pipenv_sanitize("MixedCase", true), "MixedCase");
    }

    #[test]
    fn pipenv_expand_path_expands_variables_and_home_like_python() {
        let var = |name: &str| match name {
            "HOME" => Some("/home/u".to_string()),
            "X" => Some("/x".to_string()),
            _ => None,
        };
        assert_eq!(
            pipenv_expand_path("$X/venvs", &var),
            PathBuf::from("/x/venvs")
        );
        assert_eq!(pipenv_expand_path("${X}/v", &var), PathBuf::from("/x/v"));
        assert_eq!(pipenv_expand_path("~/w", &var), PathBuf::from("/home/u/w"));
        assert_eq!(pipenv_expand_path("~", &var), PathBuf::from("/home/u"));
        assert_eq!(
            pipenv_expand_path("$UNSET/v", &var),
            PathBuf::from("$UNSET/v"),
            "unknown names stay as written"
        );
        assert_eq!(pipenv_expand_path("/plain", &var), PathBuf::from("/plain"));
    }

    #[test]
    fn pipenv_workon_home_honours_env_then_xdg_then_default() {
        let with = |workon: Option<&str>, xdg: Option<&str>| {
            let workon = workon.map(str::to_string);
            let xdg = xdg.map(str::to_string);
            let var = move |name: &str| match name {
                "HOME" | "USERPROFILE" => Some("/home/u".to_string()),
                "WORKON_HOME" => workon.clone(),
                "XDG_DATA_HOME" => xdg.clone(),
                _ => None,
            };
            pipenv_workon_home(&var)
        };
        assert_eq!(
            with(Some("~/envs"), None),
            Some(PathBuf::from("/home/u/envs"))
        );
        if cfg!(windows) {
            assert_eq!(
                with(None, None),
                Some(PathBuf::from("/home/u").join(".virtualenvs"))
            );
            // USERPROFILE wins over a Git-Bash style HOME, like Python's expanduser.
            let var = |name: &str| match name {
                "HOME" => Some("/c/Users/u".to_string()),
                "USERPROFILE" => Some(r"C:\Users\u".to_string()),
                _ => None,
            };
            assert_eq!(
                pipenv_workon_home(&var),
                Some(PathBuf::from(r"C:\Users\u").join(".virtualenvs"))
            );
        } else {
            assert_eq!(
                with(None, None),
                Some(PathBuf::from("/home/u/.local/share/virtualenvs"))
            );
            assert_eq!(
                with(None, Some("/data")),
                Some(PathBuf::from("/data/virtualenvs"))
            );
        }
        assert!(
            with(Some("  "), None).is_some(),
            "blank WORKON_HOME falls through"
        );
        let no_home = |_: &str| None::<String>;
        assert_eq!(pipenv_workon_home(&no_home), None);
    }

    /// Lay a fake virtualenv at `workon_home/<leaf>` and return its
    /// site-packages (platform layout).
    fn fake_venv(workon_home: &Path, leaf: &str) -> PathBuf {
        let site = if cfg!(windows) {
            workon_home.join(leaf).join("Lib").join("site-packages")
        } else {
            workon_home
                .join(leaf)
                .join("lib")
                .join("python3.12")
                .join("site-packages")
        };
        std::fs::create_dir_all(&site).unwrap();
        site
    }

    /// A venv at `root` as the crawler sees it: `pyvenv.cfg`, an interpreter
    /// path under `bin/` (`Scripts\\` on Windows), and its site-packages.
    /// Returns `(interpreter, site_packages)`.
    fn fake_venv_root(root: &Path) -> (PathBuf, PathBuf) {
        let parent = root.parent().unwrap();
        let leaf = root.file_name().unwrap().to_str().unwrap();
        let site = fake_venv(parent, leaf);
        std::fs::write(root.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
        let python = if cfg!(windows) {
            root.join("Scripts").join("python.exe")
        } else {
            root.join("bin").join("python")
        };
        (python, site)
    }

    fn env_of(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect();
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        }
    }

    /// #502: PDM installs into the interpreter saved in `.pdm-python` (an
    /// out-of-tree `venv.in_project = false` venv, or one bound with
    /// `pdm use`), ahead of a stray `./.venv` and an activated venv.
    #[tokio::test]
    async fn pdm_saved_interpreter_venv_is_the_project_env() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\n[tool.pdm]\ndistribution = false\n",
        )
        .unwrap();
        std::fs::write(project.join("pdm.lock"), "[metadata]\n").unwrap();
        let (python, pdm_site) =
            fake_venv_root(&tmp.path().join("pdm-venvs").join("app-AbCd-3.12"));
        std::fs::write(
            project.join(".pdm-python"),
            format!("{}\n", python.display()),
        )
        .unwrap();
        let no_env = env_of(&[]);

        // Out-of-tree venv, nothing else around: found (was: skipped).
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![pdm_site.clone()]
        );

        // A stray `./.venv` PDM does not use is not patched.
        let stray = fake_venv(&project, ".venv");
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![pdm_site.clone()]
        );

        // PDM prefers its saved interpreter over an activated venv.
        let other = tempfile::tempdir().unwrap();
        fake_venv(other.path(), "tool-venv");
        let activated = env_of(&[(
            "VIRTUAL_ENV",
            other
                .path()
                .join("tool-venv")
                .to_string_lossy()
                .into_owned(),
        )]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &activated).await,
            vec![pdm_site.clone()]
        );

        // `PDM_IGNORE_SAVED_PYTHON` makes PDM disregard `.pdm-python`.
        let ignored = env_of(&[("PDM_IGNORE_SAVED_PYTHON", "1".to_string())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &ignored).await,
            vec![stray.clone()]
        );
        // ...a boolean PDM parses: false values keep `.pdm-python`.
        for falsy in ["0", "false", "NO"] {
            let kept = env_of(&[("PDM_IGNORE_SAVED_PYTHON", falsy.to_string())]);
            assert_eq!(
                find_local_venv_site_packages_with(&project, &kept).await,
                vec![pdm_site.clone()],
                "PDM_IGNORE_SAVED_PYTHON={falsy:?}"
            );
        }

        // A base `PDM_PYTHON` (CI's system Python) does not displace the
        // saved venv PDM installs into.
        let system = tmp.path().join("usr").join("bin").join("python3");
        let base_override = env_of(&[("PDM_PYTHON", system.to_string_lossy().into_owned())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &base_override).await,
            vec![pdm_site.clone()]
        );

        // A conda env PDM reuses (`conda-meta/`, no pyvenv.cfg) is an env.
        let conda = tmp.path().join("conda").join("envs").join("app");
        let conda_site = fake_venv(conda.parent().unwrap(), "app");
        std::fs::create_dir_all(conda.join("conda-meta")).unwrap();
        let conda_python = if cfg!(windows) {
            conda.join("python.exe")
        } else {
            conda.join("bin").join("python")
        };
        let conda_env = env_of(&[("PDM_PYTHON", conda_python.to_string_lossy().into_owned())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &conda_env).await,
            vec![conda_site]
        );

        // `PDM_PYTHON` outranks `.pdm-python`.
        let (ci_python, ci_site) = fake_venv_root(&tmp.path().join("ci-venv"));
        let pinned = env_of(&[("PDM_PYTHON", ci_python.to_string_lossy().into_owned())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &pinned).await,
            vec![ci_site]
        );

        // Next to `uv.lock` or `poetry.lock` (which drive installs ahead of
        // `pdm.lock`) a leftover PDM record is not the project's env.
        for lock in ["uv.lock", "poetry.lock"] {
            std::fs::write(project.join(lock), "").unwrap();
            assert_eq!(
                find_local_venv_site_packages_with(&project, &no_env).await,
                vec![stray.clone()],
                "{lock}"
            );
            std::fs::remove_file(project.join(lock)).unwrap();
        }

        // Legacy PDM (`.pdm.toml` `[python] path`) records the same thing.
        std::fs::remove_file(project.join(".pdm-python")).unwrap();
        let mut doc = toml_edit::DocumentMut::new();
        doc["python"]["path"] = toml_edit::value(python.to_string_lossy().into_owned());
        std::fs::write(project.join(".pdm.toml"), doc.to_string()).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![pdm_site.clone()]
        );
        std::fs::remove_file(project.join(".pdm.toml")).unwrap();

        // Saved interpreter whose venv is gone: the generic probes decide.
        std::fs::write(
            project.join(".pdm-python"),
            tmp.path()
                .join("gone")
                .join("bin")
                .join("python")
                .display()
                .to_string(),
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![stray]
        );
    }

    /// #528: a PDM interpreter that is not a venv means PEP 582, and PDM
    /// installs into `__pypackages__/<X.Y>/lib` (PDM 1.x does so with no
    /// saved interpreter at all). The PATH Python is never the env.
    #[tokio::test]
    async fn pdm_pep582_pypackages_is_the_project_env() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("demo");
        let lib = project.join("__pypackages__").join("3.11").join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"demo\"\n",
        )
        .unwrap();
        std::fs::write(project.join("pdm.lock"), "[metadata]\n").unwrap();
        // A base interpreter (no pyvenv.cfg next to it) with
        // `pdm config -l python.use_venv false`, as in #528.
        let base = tmp.path().join("usr").join("bin").join("python3.11");
        std::fs::create_dir_all(base.parent().unwrap()).unwrap();
        std::fs::write(project.join(".pdm-python"), base.display().to_string()).unwrap();
        std::fs::write(project.join("pdm.toml"), "[python]\nuse_venv = false\n").unwrap();
        let no_env = env_of(&[]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![lib.clone()]
        );
        // ...even beside a `./.venv` PDM does not use.
        let unused = fake_venv(&project, ".venv");
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![lib.clone()]
        );
        // With `use_venv` on (PDM 2.x's default, or PDM_USE_VENV), a base
        // interpreter only seeds the venv: `./.venv` is the env.
        std::fs::remove_file(project.join("pdm.toml")).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![unused.clone()]
        );
        let env_off = env_of(&[("PDM_USE_VENV", "0".to_string())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &env_off).await,
            vec![lib.clone()]
        );
        std::fs::write(project.join("pdm.toml"), "[python]\nuse_venv = false\n").unwrap();
        let env_on = env_of(&[("PDM_USE_VENV", "1".to_string())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &env_on).await,
            vec![unused]
        );
        std::fs::remove_dir_all(project.join(".venv")).unwrap();

        // PDM 1.x: no saved interpreter, still a PDM project.
        std::fs::remove_file(project.join(".pdm-python")).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![lib.clone()]
        );

        // With no saved interpreter (or one PDM ignores), PDM picks an
        // activated venv or `./.venv` before PEP 582.
        let other = tempfile::tempdir().unwrap();
        let active_site = fake_venv(other.path(), "active");
        let active = env_of(&[(
            "VIRTUAL_ENV",
            other.path().join("active").to_string_lossy().into_owned(),
        )]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &active).await,
            vec![active_site.clone()]
        );
        // ...unless PDM_IGNORE_ACTIVE_VENV tells PDM to skip it.
        let opted_out = env_of(&[
            (
                "VIRTUAL_ENV",
                other.path().join("active").to_string_lossy().into_owned(),
            ),
            ("PDM_IGNORE_ACTIVE_VENV", "1".to_string()),
        ]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &opted_out).await,
            vec![lib.clone()]
        );
        // PDM parses the flag as a boolean: false values keep the venv.
        for falsy in ["0", "false", "No", ""] {
            let kept = env_of(&[
                (
                    "VIRTUAL_ENV",
                    other.path().join("active").to_string_lossy().into_owned(),
                ),
                ("PDM_IGNORE_ACTIVE_VENV", falsy.to_string()),
            ]);
            assert_eq!(
                find_local_venv_site_packages_with(&project, &kept).await,
                vec![active_site.clone()],
                "PDM_IGNORE_ACTIVE_VENV={falsy:?}"
            );
        }
        let dot_venv = fake_venv(&project, ".venv");
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![dot_venv]
        );
        std::fs::write(project.join(".pdm-python"), base.display().to_string()).unwrap();
        let ignored = env_of(&[("PDM_IGNORE_SAVED_PYTHON", "1".to_string())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &ignored).await,
            vec![fake_venv(&project, ".venv")]
        );
        // ...while a saved base interpreter still means PEP 582.
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_env).await,
            vec![lib.clone()]
        );
        std::fs::remove_file(project.join(".pdm-python")).unwrap();
        std::fs::remove_dir_all(project.join(".venv")).unwrap();

        // A lockless PDM project's `__pypackages__` is not handed to an
        // ambient UV_PROJECT_ENVIRONMENT.
        std::fs::remove_file(project.join("pdm.lock")).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"demo\"\n[tool.pdm]\ndistribution = false\n",
        )
        .unwrap();
        fake_venv(&tmp.path().join("uv-env"), "venv");
        let uv_env = env_of(&[(
            "UV_PROJECT_ENVIRONMENT",
            tmp.path().join("uv-env").join("venv").to_string_lossy().into_owned(),
        )]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &uv_env).await,
            vec![lib.clone()]
        );
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"demo\"\n",
        )
        .unwrap();
        std::fs::write(project.join("pdm.lock"), "[metadata]\n").unwrap();

        // A uv project with a leftover PDM lock is uv's, not PEP 582.
        std::fs::write(project.join("uv.lock"), "version = 1\n").unwrap();
        assert!(find_local_venv_site_packages_with(&project, &no_env)
            .await
            .is_empty());
        std::fs::remove_file(project.join("uv.lock")).unwrap();

        // `__pypackages__` outside a PDM project is not PDM's.
        std::fs::remove_file(project.join("pdm.lock")).unwrap();
        assert!(find_local_venv_site_packages_with(&project, &no_env)
            .await
            .is_empty());
    }

    /// #525: uv syncs a project into `UV_PROJECT_ENVIRONMENT` (absolute, or
    /// relative to the project) instead of `./.venv`, ignoring an
    /// activated venv; the variable means nothing outside a uv project.
    #[tokio::test]
    async fn uv_project_environment_is_the_project_env() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("app");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\n",
        )
        .unwrap();
        std::fs::write(project.join("uv.lock"), "version = 1\n").unwrap();
        let abs_site = fake_venv(&tmp.path().join("opt"), "venv");
        let abs = tmp.path().join("opt").join("venv");
        let rel_site = fake_venv(&project, ".venv-ci");
        let stray = fake_venv(&project, ".venv");
        let other = tempfile::tempdir().unwrap();
        fake_venv(other.path(), "tool-venv");
        let activated = other
            .path()
            .join("tool-venv")
            .to_string_lossy()
            .into_owned();

        let abs_env = env_of(&[("UV_PROJECT_ENVIRONMENT", abs.to_string_lossy().into_owned())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![abs_site.clone()]
        );
        let rel_env = env_of(&[
            ("UV_PROJECT_ENVIRONMENT", ".venv-ci".to_string()),
            ("VIRTUAL_ENV", activated.clone()),
        ]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &rel_env).await,
            vec![rel_site.clone()]
        );

        // Lock-less uv project (just pyproject.toml) counts too.
        std::fs::remove_file(project.join("uv.lock")).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![abs_site.clone()]
        );

        // A lockless Poetry project (`[tool.poetry]`, or `poetry.toml`) is
        // Poetry's: an ambient UV_PROJECT_ENVIRONMENT does not take it over.
        std::fs::write(
            project.join("pyproject.toml"),
            "[tool.poetry]\nname = \"app\"\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![stray.clone()]
        );
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\n",
        )
        .unwrap();
        std::fs::write(project.join("poetry.toml"), "").unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![stray.clone()]
        );
        std::fs::remove_file(project.join("poetry.toml")).unwrap();

        // A lockless PDM project is PDM's, while a `[tool.pdm.build]` table
        // alone (the pdm-backend build backend) does not make one.
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\n[tool.pdm]\ndistribution = false\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![stray.clone()]
        );
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\n[tool.pdm.build]\nincludes = [\"app\"]\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![abs_site.clone()]
        );
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\n",
        )
        .unwrap();

        // ...but not a project another manager drives, nor a non-project.
        std::fs::write(project.join("poetry.lock"), "").unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![stray.clone()]
        );
        std::fs::remove_file(project.join("poetry.lock")).unwrap();
        std::fs::remove_file(project.join("pyproject.toml")).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &abs_env).await,
            vec![stray.clone()]
        );

        // An env that does not exist yet leaves the generic probes in charge.
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"app\"\n",
        )
        .unwrap();
        let missing = env_of(&[("UV_PROJECT_ENVIRONMENT", "not-synced".to_string())]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &missing).await,
            vec![stray]
        );
    }

    /// The end-to-end shape: a Pipenv project with NO in-project venv and
    /// Pipenv's default out-of-tree placement under WORKON_HOME is found by
    /// name+hash (with and without the `-<PIPENV_PYTHON>` suffix), while a
    /// sibling with another hash, a non-Pipenv project, and a project whose
    /// WORKON_HOME is empty all stay invisible.
    #[tokio::test]
    async fn pipenv_out_of_tree_virtualenv_is_discovered_by_name_and_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("My App");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("Pipfile"), "[packages]\n").unwrap();
        let workon = tmp.path().join("wh");
        std::fs::create_dir_all(&workon).unwrap();
        let workon_str = workon.to_string_lossy().into_owned();
        let var = move |name: &str| match name {
            "WORKON_HOME" => Some(workon_str.clone()),
            "HOME" | "USERPROFILE" => Some("/nonexistent-home".to_string()),
            _ => None,
        };

        // Pipenv hashes the Pipfile under the RESOLVED project directory.
        let real = std::fs::canonicalize(&project).unwrap();
        let hash = pipenv_venv_hash(&pipenv_path_string(&real.join("Pipfile")));
        let plain = fake_venv(&workon, &format!("My_App-{hash}"));
        let suffixed = fake_venv(&workon, &format!("My_App-{hash}-python3.12"));
        let _other = fake_venv(&workon, "My_App-AAAAAAAA");
        let _unrelated = fake_venv(&workon, "other-BBBBBBBB");

        let mut found = find_pipenv_virtualenv_site_packages_with(&project, &var).await;
        found.sort();
        let mut want = vec![plain.clone(), suffixed.clone()];
        want.sort();
        assert_eq!(
            found, want,
            "name+hash (and the PIPENV_PYTHON-suffixed twin) only"
        );

        // Not a Pipenv project → nothing, even with a matching directory.
        let plain_dir = tmp.path().join("plain");
        std::fs::create_dir_all(&plain_dir).unwrap();
        assert!(find_pipenv_virtualenv_site_packages_with(&plain_dir, &var)
            .await
            .is_empty());

        // The lock alone marks a Pipenv project (fresh checkouts often
        // commit both, but a lock-only clone must still resolve).
        std::fs::remove_file(project.join("Pipfile")).unwrap();
        std::fs::write(project.join("Pipfile.lock"), "{}").unwrap();
        assert_eq!(
            find_pipenv_virtualenv_site_packages_with(&project, &var)
                .await
                .len(),
            2
        );

        // Unresolvable WORKON_HOME (no env, no home) → nothing.
        let no_env = |_: &str| None::<String>;
        assert!(find_pipenv_virtualenv_site_packages_with(&project, &no_env)
            .await
            .is_empty());
    }

    /// Pipenv 2018–2021 with an absolute PIPENV_PYTHON append the whole
    /// interpreter path to the venv name, so the virtualenv sits at the
    /// bottom of `<workon>/<name>-<hash>-/<abs>/<python>/`; the crawler must
    /// walk down to it.
    #[tokio::test]
    async fn pipenv_nested_interpreter_suffix_venv_is_discovered() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("Pipfile"), "[packages]\n").unwrap();
        let workon = tmp.path().join("wh");
        std::fs::create_dir_all(&workon).unwrap();
        let real = std::fs::canonicalize(&project).unwrap();
        let hash = pipenv_venv_hash(&pipenv_path_string(&real.join("Pipfile")));
        let nested = fake_venv(
            &workon,
            &format!("project-{hash}-/opt/tools/2018.11.26/bin/python"),
        );
        let workon_str = workon.to_string_lossy().into_owned();
        let var = move |name: &str| match name {
            "WORKON_HOME" => Some(workon_str.clone()),
            _ => None,
        };
        assert_eq!(
            find_pipenv_virtualenv_site_packages_with(&project, &var).await,
            vec![nested]
        );
    }

    #[tokio::test]
    async fn pipenv_custom_name_and_dot_venv_file_pointer_are_honoured() {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("svc");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("Pipfile"), "[packages]\n").unwrap();
        let workon = tmp.path().join("wh");
        std::fs::create_dir_all(&workon).unwrap();
        let workon_str = workon.to_string_lossy().into_owned();

        // PIPENV_CUSTOM_VENV_NAME wins over the derived name.
        let custom = fake_venv(&workon, "my-custom-env");
        let w = workon_str.clone();
        let var = move |name: &str| match name {
            "WORKON_HOME" => Some(w.clone()),
            "PIPENV_CUSTOM_VENV_NAME" => Some("my-custom-env".to_string()),
            _ => None,
        };
        assert_eq!(
            find_pipenv_virtualenv_site_packages_with(&project, &var).await,
            vec![custom]
        );

        // A `.venv` FILE naming a WORKON_HOME directory.
        let named = fake_venv(&workon, "named-env");
        std::fs::write(project.join(".venv"), "named-env\n").unwrap();
        let w = workon_str.clone();
        let var = move |name: &str| match name {
            "WORKON_HOME" => Some(w.clone()),
            _ => None,
        };
        assert_eq!(
            find_pipenv_virtualenv_site_packages_with(&project, &var).await,
            vec![named]
        );

        // A `.venv` FILE holding a project-relative path.
        let rel = fake_venv(&project, "envs/here");
        std::fs::write(project.join(".venv"), "envs/here").unwrap();
        assert_eq!(
            find_pipenv_virtualenv_site_packages_with(&project, &var).await,
            vec![rel]
        );
    }

    /// A Pipenv project `proj` with Pipenv's default WORKON_HOME venv laid
    /// out, plus an environment closure over `extra` (and WORKON_HOME).
    /// Returns `(tmp, project, workon site-packages, var)`.
    fn pipenv_project_with_workon_venv(
        extra: &[(&'static str, String)],
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        impl Fn(&str) -> Option<String>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("Pipfile"), "[packages]\nsix = \"==1.16.0\"\n").unwrap();
        let workon = tmp.path().join("wh");
        let real = std::fs::canonicalize(&project).unwrap();
        let hash = pipenv_venv_hash(&pipenv_path_string(&real.join("Pipfile")));
        let site = fake_venv(&workon, &format!("proj-{hash}"));
        let mut env: Vec<(&'static str, String)> =
            vec![("WORKON_HOME", workon.to_string_lossy().into_owned())];
        env.extend(extra.iter().cloned());
        let var = move |name: &str| {
            env.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };
        (tmp, project, site, var)
    }

    /// #384: Pipenv uses `VIRTUAL_ENV` only when neither `PIPENV_ACTIVE` nor
    /// `PIPENV_IGNORE_VIRTUALENVS` is set (`VenvLocator.location` /
    /// `Project.virtualenv_location`, 2022.12 through 2026.8). With either
    /// opt-out, the activated venv belongs to something else (another
    /// project's `pipenv shell`, a tool venv) and must not be patched.
    #[tokio::test]
    async fn pipenv_opt_outs_keep_virtual_env_from_hijacking_the_project() {
        let other = tempfile::tempdir().unwrap();
        let other_site = fake_venv(other.path(), "tool-venv");
        let other_env = other
            .path()
            .join("tool-venv")
            .to_string_lossy()
            .into_owned();

        for opt_out in [
            ("PIPENV_IGNORE_VIRTUALENVS", "1"),
            ("PIPENV_IGNORE_VIRTUALENVS", "true"),
            ("PIPENV_IGNORE_VIRTUALENVS", "anything"),
            ("PIPENV_NO_IGNORE_VIRTUALENVS", "0"),
            ("PIPENV_ACTIVE", "1"),
            ("PIPENV_ACTIVE", ""),
        ] {
            let (_tmp, project, site, var) = pipenv_project_with_workon_venv(&[
                ("VIRTUAL_ENV", other_env.clone()),
                (opt_out.0, opt_out.1.to_string()),
            ]);
            assert_eq!(
                find_local_venv_site_packages_with(&project, &var).await,
                vec![site],
                "{}={:?} must send discovery to Pipenv's own venv",
                opt_out.0,
                opt_out.1
            );
        }

        // Opt-out set but Pipenv has no venv yet: still never the activated
        // venv (Pipenv would create a new one, not reuse it).
        let (_tmp, project, site, var) = pipenv_project_with_workon_venv(&[
            ("VIRTUAL_ENV", other_env.clone()),
            ("PIPENV_IGNORE_VIRTUALENVS", "1".to_string()),
        ]);
        std::fs::remove_dir_all(site.ancestors().nth(3).unwrap()).unwrap();
        assert!(!find_local_venv_site_packages_with(&project, &var)
            .await
            .contains(&other_site));

        // Controls: without an opt-out (or with a falsy one) Pipenv does use
        // VIRTUAL_ENV, and a non-Pipenv project always does.
        for extra in [
            vec![],
            vec![("PIPENV_IGNORE_VIRTUALENVS", "0".to_string())],
            vec![("PIPENV_NO_IGNORE_VIRTUALENVS", "1".to_string())],
        ] {
            let mut env = vec![("VIRTUAL_ENV", other_env.clone())];
            env.extend(extra);
            let (_tmp, project, _site, var) = pipenv_project_with_workon_venv(&env);
            assert_eq!(
                find_local_venv_site_packages_with(&project, &var).await,
                vec![other_site.clone()]
            );
        }
        let (tmp, _project, _site, var) = pipenv_project_with_workon_venv(&[
            ("VIRTUAL_ENV", other_env.clone()),
            ("PIPENV_IGNORE_VIRTUALENVS", "1".to_string()),
        ]);
        let plain = tmp.path().join("plain");
        std::fs::create_dir_all(&plain).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&plain, &var).await,
            vec![other_site.clone()]
        );
    }

    /// #334: Pipenv never uses a `venv/` directory, so a stray one must not
    /// shadow the WORKON_HOME venv Pipenv installed into.
    #[tokio::test]
    async fn pipenv_stray_venv_dir_does_not_shadow_the_workon_home_venv() {
        let (_tmp, project, site, var) = pipenv_project_with_workon_venv(&[]);
        let _stray = fake_venv(&project, "venv");
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![site]
        );
    }

    /// #334: when Pipenv has no venv yet, discovery must not fall back to a
    /// tree Pipenv will never use: a stray `venv/`, or a `./.venv` that an
    /// explicit "not in project" rules out.
    #[tokio::test]
    async fn pipenv_without_its_venv_does_not_fall_back_to_stray_trees() {
        let (_tmp, project, site, var) = pipenv_project_with_workon_venv(&[]);
        std::fs::remove_dir_all(site.ancestors().nth(3).unwrap()).unwrap();
        let _stray = fake_venv(&project, "venv");
        assert!(find_local_venv_site_packages_with(&project, &var)
            .await
            .is_empty());

        let (_tmp, project, site, var) =
            pipenv_project_with_workon_venv(&[("PIPENV_VENV_IN_PROJECT", "0".to_string())]);
        std::fs::remove_dir_all(site.ancestors().nth(3).unwrap()).unwrap();
        let _dot = fake_venv(&project, ".venv");
        assert!(find_local_venv_site_packages_with(&project, &var)
            .await
            .is_empty());
    }

    /// #334: an explicit "not in project" (`PIPENV_VENV_IN_PROJECT` falsy,
    /// `PIPENV_NO_VENV_IN_PROJECT` truthy, or Pipenv 2026.2+'s Pipfile
    /// `[pipenv] venv_in_project = false`) makes Pipenv ignore a `./.venv`
    /// directory. An explicit "in project" makes it use `./.venv` only, and
    /// the environment variable beats the Pipfile.
    #[tokio::test]
    async fn pipenv_venv_in_project_settings_decide_about_dot_venv() {
        for env in [
            ("PIPENV_VENV_IN_PROJECT", "0"),
            ("PIPENV_VENV_IN_PROJECT", "false"),
            ("PIPENV_VENV_IN_PROJECT", "Off"),
            ("PIPENV_NO_VENV_IN_PROJECT", "1"),
        ] {
            let (_tmp, project, site, var) =
                pipenv_project_with_workon_venv(&[(env.0, env.1.to_string())]);
            let _dot = fake_venv(&project, ".venv");
            assert_eq!(
                find_local_venv_site_packages_with(&project, &var).await,
                vec![site],
                "{}={:?} must skip ./.venv",
                env.0,
                env.1
            );
        }

        let (_tmp, project, site, var) = pipenv_project_with_workon_venv(&[]);
        let dot = fake_venv(&project, ".venv");
        std::fs::write(
            project.join("Pipfile"),
            "[packages]\nsix = \"==1.16.0\"\n\n[pipenv]\nvenv_in_project = false\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![site.clone()],
            "Pipfile venv_in_project = false must skip ./.venv"
        );
        std::fs::write(
            project.join("Pipfile"),
            "[packages]\nsix = \"==1.16.0\"\n\n[pipenv]\nvenv_in_project = true\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![dot.clone()],
            "Pipfile venv_in_project = true must use ./.venv only"
        );

        for env in [
            ("PIPENV_VENV_IN_PROJECT", "1"),
            ("PIPENV_NO_VENV_IN_PROJECT", "0"),
        ] {
            let (_tmp, project, _site, var) =
                pipenv_project_with_workon_venv(&[(env.0, env.1.to_string())]);
            let dot = fake_venv(&project, ".venv");
            std::fs::write(
                project.join("Pipfile"),
                "[packages]\n\n[pipenv]\nvenv_in_project = false\n",
            )
            .unwrap();
            assert_eq!(
                find_local_venv_site_packages_with(&project, &var).await,
                vec![dot],
                "{}={:?} beats the Pipfile and uses ./.venv only",
                env.0,
                env.1
            );
        }
    }

    /// #334: with nothing explicit, Pipenv up to 2026.1 uses an existing
    /// `./.venv` directory, while 2026.2+ prefers a WORKON_HOME venv that
    /// already exists. The crawler cannot tell the versions apart without
    /// running Pipenv, so it returns both (Pipenv 2026.2+'s choice first),
    /// and either version's venv is patched. With only one of them present,
    /// that one is the answer.
    #[tokio::test]
    async fn pipenv_auto_detected_dot_venv_and_workon_home_venv_are_both_returned() {
        let (_tmp, project, site, var) = pipenv_project_with_workon_venv(&[]);
        let dot = fake_venv(&project, ".venv");
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![site.clone(), dot.clone()]
        );
        std::fs::remove_dir_all(site.ancestors().nth(3).unwrap()).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![dot]
        );
    }

    #[tokio::test]
    async fn pipenv_case_insensitive_fallback_matches_recased_directory() {
        // Pipenv on a case-insensitive filesystem reuses `<Recased>-<hash>`
        // where the hash was computed over the location with the recased
        // name spliced in (`_get_virtualenv_hash`'s fallback loop).
        let tmp = tempfile::tempdir().unwrap();
        // Pipenv's fallback (mirrored here) splits the directory name at its
        // LAST dash, so a hash that contains a dash is invisible to Pipenv
        // itself; pick a project name whose recased hash has none.
        let (project, recased_hash) = (0..64)
            .map(|i| {
                let project = tmp.path().join(format!("proj{i}"));
                std::fs::create_dir_all(&project).unwrap();
                let real = std::fs::canonicalize(&project).unwrap();
                let location = pipenv_path_string(&real.join("Pipfile"));
                let recased = location.replace(&format!("proj{i}"), &format!("Proj{i}"));
                (project, pipenv_venv_hash(&recased))
            })
            .find(|(_, hash)| !hash.contains('-'))
            .expect("some project name yields a dash-free hash");
        let name = project.file_name().unwrap().to_string_lossy().into_owned();
        std::fs::write(project.join("Pipfile"), "[packages]\n").unwrap();
        let workon = tmp.path().join("wh");
        std::fs::create_dir_all(&workon).unwrap();
        let recased_name = name.replacen("proj", "Proj", 1);
        let recased = fake_venv(&workon, &format!("{recased_name}-{recased_hash}"));
        let _wrong = fake_venv(&workon, &format!("{recased_name}-CCCCCCCC"));
        let workon_str = workon.to_string_lossy().into_owned();
        let var = move |name: &str| match name {
            "WORKON_HOME" => Some(workon_str.clone()),
            _ => None,
        };
        assert_eq!(
            find_pipenv_virtualenv_site_packages_with(&project, &var).await,
            vec![recased]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hatch_discovery_does_not_block_on_fifo_configuration() {
        for filename in ["pyproject.toml", "poetry.toml"] {
            let directory = tempfile::tempdir().unwrap();
            let fifo = directory.path().join(filename);
            if filename == "poetry.toml" {
                std::fs::write(
                    directory.path().join("pyproject.toml"),
                    "[tool.poetry]\nname='hatch-project'\n",
                )
                .unwrap();
            }
            assert!(tokio::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .await
                .unwrap()
                .success());
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                find_poetry_virtualenv_site_packages(directory.path()),
            )
            .await;
            if result.is_err() {
                let release = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&fifo)
                    .unwrap();
                drop(release);
            }
            assert!(result.unwrap().is_empty(), "{filename}");
        }
    }

    /// A `Pipfile.lock` alone marks a Pipenv project, so a FIFO `Pipfile`
    /// beside it reaches the `[pipenv] venv_in_project` lookup, which must
    /// not block on it.
    #[cfg(unix)]
    #[tokio::test]
    async fn pipenv_discovery_does_not_block_on_fifo_pipfile() {
        let (_tmp, project, site, var) = pipenv_project_with_workon_venv(&[]);
        let _dot = fake_venv(&project, ".venv");
        std::fs::remove_file(project.join("Pipfile")).unwrap();
        std::fs::write(project.join("Pipfile.lock"), "{}").unwrap();
        let fifo = project.join("Pipfile");
        assert!(tokio::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .await
            .unwrap()
            .success());
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            find_local_venv_site_packages_with(&project, &var),
        )
        .await;
        if result.is_err() {
            let release = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&fifo)
                .unwrap();
            drop(release);
        }
        let found = result.expect("discovery blocked on a FIFO Pipfile");
        assert_eq!(found.first(), Some(&site));
    }

    // ── Poetry out-of-tree virtualenv discovery ─────────────────────────────

    /// Known-answer vectors computed with Poetry's own algorithm
    /// (`EnvManager.generate_env_name`): lowercase, shell-hostile characters
    /// to `_`, 42-char cap, `-`, first 8 chars of url-safe-b64(sha256(cwd)).
    #[test]
    fn poetry_env_name_prefix_matches_poetry_generate_env_name() {
        assert_eq!(
            poetry_env_name_prefix("poetry-patch-fixture", "/tmp/socket-patch-poetry-fixture"),
            "poetry-patch-fixture-SmzYEVFn"
        );
        assert_eq!(
            poetry_env_name_prefix("My.Project", "/Users/dev/My Project"),
            "my.project-0aTnNZ0w"
        );
        let long = "a".repeat(60);
        let prefix = poetry_env_name_prefix(&format!("we ird$name`{long}"), "/x");
        assert!(prefix.starts_with("we_ird_name_"));
        assert_eq!(prefix.rsplit_once('-').unwrap().0.chars().count(), 42);
        assert_eq!(prefix.rsplit_once('-').unwrap().1.len(), 8);
    }

    /// poetry-core 2.x: `[project] name`, then `[tool.poetry] name`, then
    /// `"non-package-mode"` (#327 cases 1 and 2). The `[tool.poetry]` /
    /// placeholder candidates stay in the list for Poetry 1.8, which ignores
    /// `[project]`.
    #[test]
    fn poetry_project_names_follow_poetry_core_precedence() {
        assert_eq!(
            poetry_project_names(
                "[tool.poetry]\nname = \"Flask_Login\"\n[project]\nname = \"other\"\n"
            ),
            vec![
                "other".to_string(),
                "flask-login".to_string(),
                "Flask_Login".to_string()
            ]
        );
        assert_eq!(
            poetry_project_names("[tool.poetry]\nname = \"Flask_Login\"\n"),
            vec!["flask-login".to_string(), "Flask_Login".to_string()]
        );
        assert_eq!(
            poetry_project_names(
                "[project]\nname = \"my-app\"\n[tool.poetry]\npackage-mode = false\n"
            ),
            vec!["my-app".to_string(), "non-package-mode".to_string()]
        );
        assert_eq!(
            poetry_project_names("[tool.poetry]\npackage-mode = false\n"),
            vec!["non-package-mode".to_string()]
        );
        assert!(poetry_project_names("not toml [").is_empty());
    }

    /// Known answers from CPython's `ntpath.normcase` and Poetry's
    /// `generate_env_name`: the verbatim `\\?\` prefix `canonicalize` adds on
    /// Windows must not reach the hash (#329).
    #[test]
    fn windows_normcase_drops_the_verbatim_prefix_like_python_realpath() {
        let local = r"\\?\C:\Users\RunnerAdmin\AppData\Local\Temp\agent-named";
        assert_eq!(
            windows_normcase(local),
            r"c:\users\runneradmin\appdata\local\temp\agent-named"
        );
        assert_eq!(
            poetry_env_name_prefix("probe-named", &windows_normcase(local)),
            "probe-named-vC9KVdIy"
        );
        let unc = r"\\?\UNC\Server\Share\Proj";
        assert_eq!(windows_normcase(unc), r"\\server\share\proj");
        assert_eq!(
            poetry_env_name_prefix("probe-named", &windows_normcase(unc)),
            "probe-named-KJ5ISM87"
        );
        assert_eq!(windows_normcase("C:/Work/Proj"), r"c:\work\proj");
    }

    #[cfg(windows)]
    #[test]
    fn poetry_normalized_cwd_has_no_verbatim_prefix_on_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let normalized = poetry_normalized_cwd(tmp.path());
        assert!(!normalized.starts_with(r"\\?\"), "{normalized}");
        assert_eq!(normalized, normalized.to_lowercase());
    }

    #[test]
    fn poetry_virtualenv_config_layers_and_templates() {
        let local = PoetryVirtualenvConfig::from_toml(
            "[virtualenvs]\nin-project = false\npath = \"{cache-dir}/venvs\"\n",
        );
        let user = PoetryVirtualenvConfig::from_toml(
            "cache-dir = \"/srv/poetry-cache\"\n[virtualenvs]\ncreate = false\n",
        );
        let env = PoetryVirtualenvConfig::from_env(|k| match k {
            "POETRY_VIRTUALENVS_CREATE" => Some("true".into()),
            _ => None,
        });
        let merged = env.or(local).or(user);
        assert_eq!(merged.create, Some(true), "env beats config.toml");
        assert_eq!(merged.in_project, Some(false));
        assert_eq!(merged.path.as_deref(), Some("{cache-dir}/venvs"));
        assert_eq!(merged.cache_dir.as_deref(), Some("/srv/poetry-cache"));
        let var = |k: &str| match k {
            "HOME" => Some("/home/dev".to_string()),
            _ => None,
        };
        let cwd = Path::new("/home/dev/proj");
        assert_eq!(
            poetry_virtualenvs_root(cwd, &merged, &var),
            Some(PathBuf::from("/srv/poetry-cache/venvs"))
        );
        // Poetry has no `{project-dir}` key, so `Config.process()` keeps
        // the text and the relative result lands under the cwd (#608).
        let project_local = PoetryVirtualenvConfig {
            path: Some("{project-dir}/.envs".into()),
            ..Default::default()
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &project_local, &var),
            Some(PathBuf::from("/home/dev/proj/{project-dir}/.envs"))
        );
        let tilde = PoetryVirtualenvConfig {
            path: Some("~/venvs".into()),
            ..Default::default()
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &tilde, &var),
            Some(PathBuf::from("/home/dev/venvs"))
        );
        for disabled in [PoetryVirtualenvConfig {
            create: Some(false),
            ..Default::default()
        }] {
            assert_eq!(poetry_virtualenvs_root(cwd, &disabled, &var), None);
        }
        // `in-project = true` does not move the root (#476).
        let in_project = PoetryVirtualenvConfig {
            in_project: Some(true),
            ..Default::default()
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &in_project, &var),
            poetry_virtualenvs_root(cwd, &PoetryVirtualenvConfig::default(), &var)
        );
        // Defaults resolve against the platform cache dir; with no home at all
        // there is nothing to resolve against.
        let default = PoetryVirtualenvConfig::default();
        assert!(poetry_virtualenvs_root(cwd, &default, &var).is_some());
        assert_eq!(
            poetry_virtualenvs_root(cwd, &default, &|_: &str| None),
            None
        );
    }

    /// `virtualenvs.path` and `cache-dir` go through Poetry's
    /// `Config.process()`: `{cache-dir}` and `{data-dir}` (Poetry >= 2.1)
    /// are substituted, any other `{key}` is kept literally (#608).
    #[test]
    fn poetry_virtualenvs_path_mirrors_config_process() {
        let cwd = Path::new("/home/dev/proj");
        let root = |config: PoetryVirtualenvConfig, vars: &[(&str, &str)]| {
            let vars: Vec<(String, String)> = vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let var = move |k: &str| {
                vars.iter()
                    .find(|(name, _)| name == k)
                    .map(|(_, v)| v.clone())
            };
            poetry_virtualenvs_root(cwd, &config, &var)
        };
        let path = |p: &str| PoetryVirtualenvConfig {
            path: Some(p.into()),
            ..Default::default()
        };

        // `{data-dir}` follows the `data-dir` setting (POETRY_DATA_DIR, then
        // the config files), then POETRY_HOME.
        let env = |k: &str| match k {
            "POETRY_DATA_DIR" => Some("/srv/pd".to_string()),
            _ => None,
        };
        assert_eq!(
            root(
                PoetryVirtualenvConfig::from_env(env).or(path("{data-dir}/venvs")),
                &[("HOME", "/home/dev"), ("POETRY_HOME", "/opt/poetry")]
            ),
            Some(PathBuf::from("/srv/pd/venvs"))
        );
        assert_eq!(
            root(
                path("{data-dir}/venvs"),
                &[("HOME", "/home/dev"), ("POETRY_HOME", "/opt/poetry")]
            ),
            Some(PathBuf::from("/opt/poetry/venvs"))
        );
        let from_toml = PoetryVirtualenvConfig::from_toml(
            "data-dir = \"~/pdata\"\n[virtualenvs]\npath = \"{data-dir}/venvs\"\n",
        );
        assert_eq!(
            root(
                from_toml,
                &[("HOME", "/home/dev"), ("POETRY_HOME", "/opt/poetry")]
            ),
            Some(PathBuf::from("/home/dev/pdata/venvs"))
        );
        let env = PoetryVirtualenvConfig::from_env(|k| match k {
            "POETRY_DATA_DIR" => Some("/env/pd".into()),
            _ => None,
        });
        assert_eq!(env.data_dir.as_deref(), Some("/env/pd"));

        // `cache-dir` is processed too, so `{data-dir}` inside it moves
        // the default `<cache-dir>/virtualenvs` root.
        let cache = PoetryVirtualenvConfig {
            cache_dir: Some("{data-dir}/cache".into()),
            ..Default::default()
        };
        assert_eq!(
            root(cache, &[("HOME", "/home/dev"), ("POETRY_HOME", "/srv/pd")]),
            Some(PathBuf::from("/srv/pd/cache/virtualenvs"))
        );

        // Unknown keys stay literal; `{cache-dir}` still resolves next to
        // them.
        let unknown = PoetryVirtualenvConfig {
            cache_dir: Some("/c".into()),
            ..path("{cache-dir}/{nope}/venvs")
        };
        assert_eq!(
            root(unknown, &[("HOME", "/home/dev")]),
            Some(PathBuf::from("/c/{nope}/venvs"))
        );
    }

    /// Poetry's default data dir is platformdirs' roaming user data dir.
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    #[test]
    fn poetry_data_dir_defaults_to_xdg_data_home_on_linux() {
        let cwd = Path::new("/home/dev/proj");
        let config = PoetryVirtualenvConfig {
            path: Some("{data-dir}/venvs".into()),
            ..Default::default()
        };
        let home_only = |k: &str| (k == "HOME").then(|| "/home/dev".to_string());
        assert_eq!(
            poetry_virtualenvs_root(cwd, &config, &home_only),
            Some(PathBuf::from("/home/dev/.local/share/pypoetry/venvs"))
        );
        let xdg = |k: &str| match k {
            "HOME" => Some("/home/dev".to_string()),
            "XDG_DATA_HOME" => Some("/xdg".to_string()),
            _ => None,
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &config, &xdg),
            Some(PathBuf::from("/xdg/pypoetry/venvs"))
        );
        // platformdirs ignores a relative XDG_DATA_HOME.
        let relative = |k: &str| match k {
            "HOME" => Some("/home/dev".to_string()),
            "XDG_DATA_HOME" => Some("rel".to_string()),
            _ => None,
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &config, &relative),
            Some(PathBuf::from("/home/dev/.local/share/pypoetry/venvs"))
        );
    }

    /// Poetry 1.1 drops unknown placeholders. Its project-owned env must
    /// remain visible even if an unrelated literal-generation parent exists.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn poetry_virtualenvs_path_falls_back_to_poetry_1_1_placement() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, legacy, prefix) = poetry_fixture(tmp.path(), "", &["3.11"]);
        let template = format!("{{project-dir}}{}", legacy.display());
        std::fs::write(
            project.join("poetry.toml"),
            format!("[virtualenvs]\npath = {template:?}\n"),
        )
        .unwrap();
        std::fs::create_dir_all(project.join(&template)).unwrap();
        let var = poetry_env(tmp.path(), &[]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![poetry_site(
                &legacy.join(format!("{prefix}-py3.11")),
                "3.11"
            )]
        );
    }

    /// End to end against the filesystem: a Poetry project with no `.venv`
    /// finds the virtualenv(s) Poetry placed under `virtualenvs.path`, every
    /// interpreter minor, and stops looking once the project opts into
    /// `in-project` venvs.
    #[tokio::test]
    #[serial_test::serial]
    async fn poetry_out_of_tree_virtualenvs_are_discovered_without_a_dot_venv() {
        struct Guard(Vec<(&'static str, Option<String>)>);
        impl Guard {
            fn new(overrides: &[(&'static str, Option<&str>)]) -> Self {
                let prev = overrides
                    .iter()
                    .map(|(k, v)| {
                        let old = std::env::var(k).ok();
                        match v {
                            Some(v) => std::env::set_var(k, v),
                            None => std::env::remove_var(k),
                        }
                        (*k, old)
                    })
                    .collect();
                Guard(prev)
            }
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                for (k, old) in &self.0 {
                    match old {
                        Some(v) => std::env::set_var(k, v),
                        None => std::env::remove_var(k),
                    }
                }
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[tool.poetry]\nname = \"Poetry_Patch.Fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(project.join("poetry.lock"), "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n[metadata]\nlock-version = \"2.1\"\n").unwrap();
        let venvs = tmp.path().join("venvs");
        let prefix =
            poetry_env_name_prefix("poetry-patch-fixture", &poetry_normalized_cwd(&project));
        let site = |venv: &Path, minor: &str| {
            if cfg!(windows) {
                venv.join("Lib").join("site-packages")
            } else {
                venv.join("lib")
                    .join(format!("python{minor}"))
                    .join("site-packages")
            }
        };
        let venv312 = venvs.join(format!("{prefix}-py3.12"));
        let venv311 = venvs.join(format!("{prefix}-py3.11"));
        let other = venvs.join("someone-else-AAAAAAAA-py3.12");
        for (venv, minor) in [(&venv312, "3.12"), (&venv311, "3.11"), (&other, "3.12")] {
            std::fs::create_dir_all(site(venv, minor)).unwrap();
        }
        let _guard = Guard::new(&[
            ("VIRTUAL_ENV", None),
            ("POETRY_VIRTUALENVS_PATH", Some(venvs.to_str().unwrap())),
            ("POETRY_VIRTUALENVS_IN_PROJECT", None),
            ("POETRY_VIRTUALENVS_CREATE", None),
            ("POETRY_CACHE_DIR", None),
            (
                "POETRY_CONFIG_DIR",
                Some(tmp.path().join("no-config").to_str().unwrap()),
            ),
        ]);

        let found = find_local_venv_site_packages(&project).await;
        assert_eq!(
            found,
            vec![site(&venv311, "3.11"), site(&venv312, "3.12")],
            "{found:?}"
        );

        // A project-local `.venv` wins and the out-of-tree probe is skipped.
        std::fs::create_dir_all(site(&project.join(".venv"), "3.12")).unwrap();
        assert_eq!(
            find_local_venv_site_packages(&project).await,
            vec![site(&project.join(".venv"), "3.12")]
        );
        std::fs::remove_dir_all(project.join(".venv")).unwrap();

        // `poetry.toml` opting into in-project venvs with no `./.venv` yet
        // keeps Poetry on its existing out-of-tree env (#476); disabling
        // creation means Poetry never used the shared root.
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\nin-project = true\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages(&project).await,
            vec![site(&venv311, "3.11"), site(&venv312, "3.12")]
        );
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\ncreate = false\n",
        )
        .unwrap();
        assert!(find_local_venv_site_packages(&project).await.is_empty());
        std::fs::remove_file(project.join("poetry.toml")).unwrap();

        // #327 case 3: an explicit `in-project = false` means Poetry never
        // uses `./.venv`, even when one exists; the stray `.venv` loses.
        std::fs::create_dir_all(site(&project.join(".venv"), "3.12")).unwrap();
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\nin-project = false\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages(&project).await,
            vec![site(&venv311, "3.11"), site(&venv312, "3.12")]
        );
        std::fs::remove_file(project.join("poetry.toml")).unwrap();
        std::fs::remove_dir_all(project.join(".venv")).unwrap();

        // Poetry never looks at `./venv`: with no `./.venv` its out-of-tree
        // env is still the one it installed into.
        std::fs::create_dir_all(site(&project.join("venv"), "3.12")).unwrap();
        assert_eq!(
            find_local_venv_site_packages(&project).await,
            vec![site(&venv311, "3.11"), site(&venv312, "3.12")]
        );
        // ...but a `./venv` still serves when Poetry has no env at all.
        let venv_only = tmp.path().join("venv-only");
        std::fs::create_dir_all(site(&venv_only.join("venv"), "3.12")).unwrap();
        std::fs::write(
            venv_only.join("pyproject.toml"),
            "[tool.poetry]\nname = \"venv-only\"\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages(&venv_only).await,
            vec![site(&venv_only.join("venv"), "3.12")]
        );
        std::fs::remove_dir_all(project.join("venv")).unwrap();

        // #327 case 1: a nameless `package-mode = false` project. Poetry
        // names its env `non-package-mode-<hash>-py<X.Y>`.
        std::fs::write(
            project.join("pyproject.toml"),
            "[tool.poetry]\npackage-mode = false\n",
        )
        .unwrap();
        let nameless = venvs.join(format!(
            "{}-py3.12",
            poetry_env_name_prefix("non-package-mode", &poetry_normalized_cwd(&project))
        ));
        std::fs::create_dir_all(site(&nameless, "3.12")).unwrap();
        assert_eq!(
            find_local_venv_site_packages(&project).await,
            vec![site(&nameless, "3.12")]
        );

        // #327 case 2: Poetry 2 names the env after `[project] name` when both
        // tables carry one, even though `[tool.poetry] name` has a venv too.
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"pep-name\"\n[tool.poetry]\nname = \"poetry-patch-fixture\"\n",
        )
        .unwrap();
        let pep = venvs.join(format!(
            "{}-py3.12",
            poetry_env_name_prefix("pep-name", &poetry_normalized_cwd(&project))
        ));
        std::fs::create_dir_all(site(&pep, "3.12")).unwrap();
        assert_eq!(
            find_local_venv_site_packages(&project).await,
            vec![site(&pep, "3.12")]
        );
        // With only the legacy-named env on disk (Poetry 1.8 ignores
        // `[project]`), that one is found.
        std::fs::remove_dir_all(&pep).unwrap();
        assert_eq!(
            find_local_venv_site_packages(&project).await,
            vec![site(&venv311, "3.11"), site(&venv312, "3.12")]
        );

        // Not a Poetry project (no lock, no [tool.poetry]): untouched.
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"poetry-patch-fixture\"\n",
        )
        .unwrap();
        std::fs::remove_file(project.join("poetry.lock")).unwrap();
        assert!(find_local_venv_site_packages(&project).await.is_empty());
    }

    /// A Poetry project at `<tmp>/proj` whose `poetry.toml` points
    /// `virtualenvs.path` at `<tmp>/venvs` (plus `extra_config` lines under
    /// `[virtualenvs]`), with one out-of-tree env per minor in `minors`.
    /// Returns `(project, venvs root, env name prefix)`.
    fn poetry_fixture(
        tmp: &Path,
        extra_config: &str,
        minors: &[&str],
    ) -> (PathBuf, PathBuf, String) {
        let project = tmp.join("proj");
        let venvs = tmp.join("venvs");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("pyproject.toml"),
            "[tool.poetry]\nname = \"envmulti\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            project.join("poetry.toml"),
            format!(
                "[virtualenvs]\npath = {:?}\n{extra_config}",
                venvs.to_string_lossy()
            ),
        )
        .unwrap();
        let prefix = poetry_env_name_prefix("envmulti", &poetry_normalized_cwd(&project));
        for minor in minors {
            std::fs::create_dir_all(poetry_site(
                &venvs.join(format!("{prefix}-py{minor}")),
                minor,
            ))
            .unwrap();
        }
        (project, venvs, prefix)
    }

    fn poetry_site(venv: &Path, minor: &str) -> PathBuf {
        if cfg!(windows) {
            venv.join("Lib").join("site-packages")
        } else {
            venv.join("lib")
                .join(format!("python{minor}"))
                .join("site-packages")
        }
    }

    /// An environment with nothing set but a home that holds no Poetry
    /// config, so only the fixture's `poetry.toml` decides.
    fn poetry_env<'a>(
        tmp: &'a Path,
        extra: &'a [(&'a str, String)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |name: &str| {
            if let Some((_, v)) = extra.iter().find(|(k, _)| *k == name) {
                return Some(v.clone());
            }
            match name {
                "HOME" => Some(tmp.join("home").to_string_lossy().into_owned()),
                "POETRY_CONFIG_DIR" => Some(tmp.join("no-config").to_string_lossy().into_owned()),
                _ => None,
            }
        }
    }

    /// #526: with several `<name>-<hash>-py*` envs, Poetry uses the one
    /// `poetry env use` recorded in `<virtualenvs.path>/envs.toml`, not the
    /// alphabetically first one.
    #[tokio::test]
    #[serial_test::serial]
    async fn poetry_envs_toml_activated_env_is_the_only_one_probed() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, venvs, prefix) =
            poetry_fixture(tmp.path(), "", &["3.10", "3.11", "3.12", "3.9"]);
        let var = poetry_env(tmp.path(), &[]);
        for minor in ["3.12", "3.9", "3.11"] {
            std::fs::write(
                venvs.join("envs.toml"),
                format!("[{prefix}]\nminor = \"{minor}\"\npatch = \"{minor}.4\"\n\n[other-AAAAAAAA]\nminor = \"3.10\"\n"),
            )
            .unwrap();
            assert_eq!(
                find_local_venv_site_packages_with(&project, &var).await,
                vec![poetry_site(
                    &venvs.join(format!("{prefix}-py{minor}")),
                    minor
                )],
                "activated {minor}"
            );
        }
        // An envs.toml that names other projects only changes nothing: every
        // env of this project is still a candidate.
        std::fs::write(
            venvs.join("envs.toml"),
            "[other-AAAAAAAA]\nminor = \"3.10\"\n",
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var)
                .await
                .len(),
            4
        );
    }

    /// #526 (second trigger): once `envs.toml` names the project, Poetry
    /// ignores an unrelated activated `VIRTUAL_ENV`; without an entry it
    /// still uses it. A conda `base` env does not count as "in a venv".
    #[tokio::test]
    #[serial_test::serial]
    async fn poetry_envs_toml_entry_overrides_virtual_env() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, venvs, prefix) = poetry_fixture(tmp.path(), "", &["3.11", "3.12"]);
        let other = tmp.path().join("other");
        std::fs::create_dir_all(poetry_site(&other, "3.11")).unwrap();
        let active = [("VIRTUAL_ENV", other.to_string_lossy().into_owned())];
        let var = poetry_env(tmp.path(), &active);
        std::fs::write(
            venvs.join("envs.toml"),
            format!("[{prefix}]\nminor = \"3.12\"\n"),
        )
        .unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![poetry_site(&venvs.join(format!("{prefix}-py3.12")), "3.12")]
        );
        std::fs::remove_file(venvs.join("envs.toml")).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![poetry_site(&other, "3.11")]
        );
        // Poetry treats `CONDA_PREFIX` like `VIRTUAL_ENV`, except in conda's
        // `base` env.
        let conda = [
            ("CONDA_PREFIX", other.to_string_lossy().into_owned()),
            ("CONDA_DEFAULT_ENV", "work".to_string()),
        ];
        assert_eq!(
            find_local_venv_site_packages_with(&project, &poetry_env(tmp.path(), &conda)).await,
            vec![poetry_site(&other, "3.11")]
        );
        let base = [
            ("CONDA_PREFIX", other.to_string_lossy().into_owned()),
            ("CONDA_DEFAULT_ENV", "base".to_string()),
        ];
        assert_eq!(
            find_local_venv_site_packages_with(&project, &poetry_env(tmp.path(), &base))
                .await
                .len(),
            2,
            "conda base is not an activated venv for Poetry"
        );
    }

    /// #476: `virtualenvs.in-project = true` only means `./.venv` when it
    /// exists (`EnvManager.in_project_venv_exists`); otherwise Poetry keeps
    /// installing into its existing out-of-tree env.
    #[tokio::test]
    #[serial_test::serial]
    async fn poetry_in_project_true_without_dot_venv_keeps_the_out_of_tree_env() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, venvs, prefix) = poetry_fixture(tmp.path(), "in-project = true\n", &["3.11"]);
        let env311 = poetry_site(&venvs.join(format!("{prefix}-py3.11")), "3.11");
        let var = poetry_env(tmp.path(), &[]);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![env311.clone()]
        );
        // The same through POETRY_VIRTUALENVS_IN_PROJECT.
        std::fs::write(
            project.join("poetry.toml"),
            format!("[virtualenvs]\npath = {:?}\n", venvs.to_string_lossy()),
        )
        .unwrap();
        let flag = [("POETRY_VIRTUALENVS_IN_PROJECT", "true".to_string())];
        assert_eq!(
            find_local_venv_site_packages_with(&project, &poetry_env(tmp.path(), &flag)).await,
            vec![env311.clone()]
        );
        // Once `./.venv` exists it is the project's env.
        let dot_venv = poetry_site(&project.join(".venv"), "3.12");
        std::fs::create_dir_all(&dot_venv).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &poetry_env(tmp.path(), &flag)).await,
            vec![dot_venv]
        );
    }

    #[test]
    fn poetry_data_dir_recursively_resolves_only_referenced_settings() {
        let cwd = Path::new("/project");
        let var = |key: &str| (key == "HOME").then(|| "/home/dev".to_string());
        let config = PoetryVirtualenvConfig::from_toml(
            "cache-dir = '/cache'\ndata-dir = '{cache-dir}/data'\n[virtualenvs]\npath = '{data-dir}/venvs'\n",
        );
        assert_eq!(
            poetry_virtualenvs_root(cwd, &config, &var),
            Some(PathBuf::from("/cache/data/venvs"))
        );
        // Explicit settings exist even in generations without a default
        // data-dir. Each model therefore resolves to the same path.
        assert_eq!(
            poetry_virtualenvs_paths(cwd, &config, &var),
            vec![PathBuf::from("/cache/data/venvs")]
        );
        let cyclic = PoetryVirtualenvConfig::from_toml(
            "cache-dir = '{data-dir}/cache'\ndata-dir = '{cache-dir}/data'\n[virtualenvs]\npath = '{data-dir}/venvs'\n",
        );
        assert_eq!(poetry_virtualenvs_root(cwd, &cyclic, &var), None);
        let explicit = PoetryVirtualenvConfig {
            path: Some("/explicit/venvs".into()),
            ..cyclic
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &explicit, &var),
            Some(PathBuf::from("/explicit/venvs")),
            "an unused cyclic key must not invalidate an explicit path"
        );
    }

    #[tokio::test]
    async fn poetry_placeholder_generations_keep_each_project_env_and_activation() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, _, prefix) = poetry_fixture(tmp.path(), "", &[]);
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\npath = '{data-dir}/venvs'\n",
        )
        .unwrap();
        let data = tmp.path().join("data");
        let current = data.join("venvs");
        let legacy = project.join("{data-dir}").join("venvs");
        let modern311 = poetry_site(&current.join(format!("{prefix}-py3.11")), "3.11");
        let modern312 = poetry_site(&current.join(format!("{prefix}-py3.12")), "3.12");
        let legacy311 = poetry_site(&legacy.join(format!("{prefix}-py3.11")), "3.11");
        let legacy312 = poetry_site(&legacy.join(format!("{prefix}-py3.12")), "3.12");
        std::fs::create_dir_all(&legacy311).unwrap();
        std::fs::create_dir_all(&legacy312).unwrap();
        std::fs::create_dir_all(poetry_site(&current.join("other-AAAAAAAA-py3.11"), "3.11"))
            .unwrap();
        std::fs::write(
            current.join("envs.toml"),
            "[other-AAAAAAAA]\nminor = '3.11'\n",
        )
        .unwrap();
        let env = [("POETRY_HOME", data.to_string_lossy().into_owned())];
        let var = poetry_env(tmp.path(), &env);
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![legacy311.clone(), legacy312.clone()],
            "an unrelated current-generation parent must not hide the legacy project's env"
        );
        // Both versions can be installed and keep environments for the same
        // project. Each envs.toml must select a minor only within its own root.
        std::fs::create_dir_all(&modern311).unwrap();
        std::fs::create_dir_all(&modern312).unwrap();
        std::fs::write(
            current.join("envs.toml"),
            format!("[{prefix}]\nminor = '3.12'\n"),
        )
        .unwrap();
        std::fs::write(
            legacy.join("envs.toml"),
            format!("[{prefix}]\nminor = '3.11'\n"),
        )
        .unwrap();
        let expected = vec![modern312.clone(), legacy311.clone()];
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            expected
        );
        let active = tmp.path().join("unrelated-active");
        let active_site = poetry_site(&active, "3.11");
        std::fs::create_dir_all(&active_site).unwrap();
        let env = [
            ("POETRY_HOME", data.to_string_lossy().into_owned()),
            ("VIRTUAL_ENV", active.to_string_lossy().into_owned()),
        ];
        let var = poetry_env(tmp.path(), &env);
        // A different generation can use the active shell even when its
        // root has never been created. Only the legacy activation remains.
        std::fs::remove_dir_all(&current).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![active_site.clone(), legacy311.clone()]
        );
        let no_active = [("POETRY_HOME", data.to_string_lossy().into_owned())];
        let no_active_var = poetry_env(tmp.path(), &no_active);
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\npath = '{data-dir}/venvs'\ncreate = false\n",
        )
        .unwrap();
        assert!(find_local_venv_site_packages_with(&project, &no_active_var)
            .await
            .is_empty());
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\npath = '{data-dir}/venvs'\n",
        )
        .unwrap();
        let local = poetry_site(&project.join(".venv"), "3.11");
        std::fs::create_dir_all(&local).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &no_active_var).await,
            vec![local]
        );
        std::fs::remove_dir_all(project.join(".venv")).unwrap();
        std::fs::remove_file(legacy.join("envs.toml")).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![active_site]
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn poetry_data_dir_keeps_current_and_legacy_macos_platformdirs_envs() {
        let tmp = tempfile::tempdir().unwrap();
        let (project, _, prefix) = poetry_fixture(tmp.path(), "", &[]);
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\npath = '{data-dir}/venvs'\n",
        )
        .unwrap();
        let xdg = tmp.path().join("xdg");
        let current = xdg.join("pypoetry").join("venvs");
        let legacy = tmp
            .path()
            .join("home/Library/Application Support/pypoetry/venvs");
        let current_site = poetry_site(&current.join(format!("{prefix}-py3.11")), "3.11");
        let legacy_site = poetry_site(&legacy.join(format!("{prefix}-py3.12")), "3.12");
        std::fs::create_dir_all(&current_site).unwrap();
        let env = [("XDG_DATA_HOME", xdg.to_string_lossy().into_owned())];
        let var = poetry_env(tmp.path(), &env);
        assert_eq!(
            poetry_installer_data_dir(&var),
            Some(tmp.path().join("home/Library/Application Support/pypoetry")),
            "the official macOS installer does not use XDG_DATA_HOME"
        );
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![current_site.clone()]
        );
        // The same supported Poetry version may use an older platformdirs
        // dependency. Retain that project's Library placement too.
        std::fs::create_dir_all(&legacy_site).unwrap();
        assert_eq!(
            find_local_venv_site_packages_with(&project, &var).await,
            vec![current_site, legacy_site]
        );
    }

    #[test]
    fn test_canonicalize_pypi_name_basic() {
        assert_eq!(canonicalize_pypi_name("Requests"), "requests");
        assert_eq!(canonicalize_pypi_name("my_package"), "my-package");
        assert_eq!(canonicalize_pypi_name("My.Package"), "my-package");
        assert_eq!(canonicalize_pypi_name("My-._Package"), "my-package");
    }

    #[test]
    fn test_canonicalize_pypi_name_runs() {
        // Runs of separators collapse to single -
        assert_eq!(canonicalize_pypi_name("a__b"), "a-b");
        assert_eq!(canonicalize_pypi_name("a-.-b"), "a-b");
        assert_eq!(canonicalize_pypi_name("a_._-b"), "a-b");
    }

    #[test]
    fn test_canonicalize_pypi_name_trim() {
        assert_eq!(canonicalize_pypi_name("  requests  "), "requests");
    }

    // `find_by_purls` delegates purl parsing to the shared
    // `crate::utils::purl::parse_pypi_purl`; these pin the behaviors the
    // crawler depends on (qualifier/subpath stripping, non-pypi rejection).

    #[test]
    fn test_parse_pypi_purl() {
        let (name, ver) = parse_pypi_purl("pkg:pypi/requests@2.28.0").unwrap();
        assert_eq!(name, "requests");
        assert_eq!(ver, "2.28.0");
    }

    #[test]
    fn test_parse_pypi_purl_with_qualifiers() {
        let (name, ver) = parse_pypi_purl("pkg:pypi/requests@2.28.0?artifact_id=abc").unwrap();
        assert_eq!(name, "requests");
        assert_eq!(ver, "2.28.0");
    }

    /// The PURL grammar is `pkg:type/ns/name@version?qualifiers#subpath`;
    /// a subpath can appear WITHOUT a preceding qualifier. Cutting only at
    /// `?` lets a bare `#subpath` leak into the version (`2.28.0#src/...`),
    /// silently failing the installed-package match.
    #[test]
    fn test_parse_pypi_purl_with_subpath() {
        let (name, ver) = parse_pypi_purl("pkg:pypi/requests@2.28.0#src/requests").unwrap();
        assert_eq!(name, "requests");
        assert_eq!(ver, "2.28.0");

        // Qualifier + subpath together (subpath follows qualifiers).
        let (name, ver) = parse_pypi_purl("pkg:pypi/requests@2.28.0?artifact_id=abc#src").unwrap();
        assert_eq!(name, "requests");
        assert_eq!(ver, "2.28.0");
    }

    #[test]
    fn test_parse_pypi_purl_invalid() {
        assert!(parse_pypi_purl("pkg:npm/lodash@4.17.21").is_none());
        assert!(parse_pypi_purl("not-a-purl").is_none());
    }

    #[tokio::test]
    async fn test_read_python_metadata_valid() {
        let dir = tempfile::tempdir().unwrap();
        let dist_info = dir.path().join("requests-2.28.0.dist-info");
        tokio::fs::create_dir_all(&dist_info).await.unwrap();
        tokio::fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: Requests\nVersion: 2.28.0\n\nSome description",
        )
        .await
        .unwrap();

        let result = read_python_metadata(&dist_info).await;
        assert!(result.is_some());
        let (name, version) = result.unwrap();
        assert_eq!(name, "Requests");
        assert_eq!(version, "2.28.0");
    }

    #[tokio::test]
    async fn test_read_python_metadata_missing() {
        let dir = tempfile::tempdir().unwrap();
        let dist_info = dir.path().join("nonexistent.dist-info");
        assert!(read_python_metadata(&dist_info).await.is_none());
    }

    #[test]
    fn test_parse_egg_info_dir_name() {
        assert_eq!(
            parse_egg_info_dir_name("six-1.16.0-py3.11.egg-info"),
            Some(("six".into(), "1.16.0".into()))
        );
        assert_eq!(
            parse_egg_info_dir_name("Flask_SQLAlchemy-3.0.5.egg-info"),
            Some(("Flask_SQLAlchemy".into(), "3.0.5".into()))
        );
        assert!(parse_egg_info_dir_name("noversion.egg-info").is_none());
        assert!(parse_egg_info_dir_name("-1.0.egg-info").is_none());
        assert!(parse_egg_info_dir_name("six-1.16.0.dist-info").is_none());
    }

    /// Legacy `.egg-info` installs (#447): a `PKG-INFO` directory, a
    /// headerless directory (named fallback), and a bare distutils FILE are
    /// installs; a bare file without headers is not.
    #[tokio::test]
    async fn egg_info_entries_are_listed() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path();
        let egg = sp.join("six-1.16.0-py3.11.egg-info");
        tokio::fs::create_dir_all(&egg).await.unwrap();
        tokio::fs::write(egg.join("PKG-INFO"), "Name: six\nVersion: 1.16.0\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(sp.join("zope.interface-5.4.0-py3.11.egg-info"))
            .await
            .unwrap();
        tokio::fs::write(
            sp.join("PyGObject-3.48.2.egg-info"),
            "Metadata-Version: 1.1\nName: PyGObject\nVersion: 3.48.2\n",
        )
        .await
        .unwrap();
        tokio::fs::write(sp.join("ghost-1.0.egg-info"), "not metadata")
            .await
            .unwrap();
        let mut listed = list_dist_info_packages(sp).await;
        listed.sort();
        assert_eq!(
            listed,
            vec![
                ("pygobject".to_string(), "3.48.2".to_string()),
                ("six".to_string(), "1.16.0".to_string()),
                ("zope-interface".to_string(), "5.4.0".to_string()),
            ]
        );
        let found = PythonCrawler::new()
            .find_by_purls(sp, &["pkg:pypi/six@1.16.0".to_string()])
            .await
            .unwrap();
        assert_eq!(found["pkg:pypi/six@1.16.0"].path, sp);
    }

    #[test]
    fn test_parse_dist_info_dir_name() {
        // Modern pip escapes `-` in the name to `_`.
        assert_eq!(
            parse_dist_info_dir_name("flask_sqlalchemy-3.0.5.dist-info"),
            Some(("flask_sqlalchemy".to_string(), "3.0.5".to_string()))
        );
        // Older pip kept the raw name with `-`; the final `-` is still the
        // version boundary because a normalized version never contains `-`.
        assert_eq!(
            parse_dist_info_dir_name("Flask-SQLAlchemy-3.0.5.dist-info"),
            Some(("Flask-SQLAlchemy".to_string(), "3.0.5".to_string()))
        );
        assert_eq!(
            parse_dist_info_dir_name("requests-2.28.0.dist-info"),
            Some(("requests".to_string(), "2.28.0".to_string()))
        );
        // No version segment, wrong suffix, and empty-name guards.
        assert!(parse_dist_info_dir_name("noversion.dist-info").is_none());
        assert!(parse_dist_info_dir_name("requests-2.28.0.egg-info").is_none());
        assert!(parse_dist_info_dir_name("-1.0.dist-info").is_none());
    }

    /// A `.dist-info` directory whose `METADATA` is missing must still be
    /// discoverable via the directory name — otherwise a corrupt/partial
    /// install silently hides a package the crawler is meant to patch.
    #[tokio::test]
    async fn test_read_python_metadata_falls_back_to_dir_name() {
        let dir = tempfile::tempdir().unwrap();
        let dist_info = dir.path().join("requests-2.28.0.dist-info");
        tokio::fs::create_dir_all(&dist_info).await.unwrap();
        // No METADATA file written at all.
        let (name, version) = read_python_metadata(&dist_info).await.unwrap();
        assert_eq!(name, "requests");
        assert_eq!(version, "2.28.0");
    }

    /// Malformed METADATA (present but missing the `Version` header) also
    /// falls back to the directory name rather than dropping the package.
    #[tokio::test]
    async fn test_read_python_metadata_falls_back_on_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let dist_info = dir.path().join("urllib3-2.0.7.dist-info");
        tokio::fs::create_dir_all(&dist_info).await.unwrap();
        tokio::fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: urllib3\n\nDescription body, no Version header\n",
        )
        .await
        .unwrap();
        let (name, version) = read_python_metadata(&dist_info).await.unwrap();
        assert_eq!(name, "urllib3");
        assert_eq!(version, "2.0.7");
    }

    /// A METADATA missing BOTH `Name` and `Version` headers must fall back to
    /// the directory name — even when the free-text description body contains
    /// literal `Name:`/`Version:` lines at column 0 (e.g. a README documenting
    /// those fields, or another package's headers pasted into a changelog).
    /// The parser must stop at the header/body separator (the first blank
    /// line) and never mistake prose for a header.
    #[tokio::test]
    async fn test_read_python_metadata_ignores_body_name_version() {
        let dir = tempfile::tempdir().unwrap();
        let dist_info = dir.path().join("requests-2.28.0.dist-info");
        tokio::fs::create_dir_all(&dist_info).await.unwrap();
        tokio::fs::write(
            dist_info.join("METADATA"),
            // No real Name/Version headers; the blank line ends the header
            // block, then the body opens with lines that look like headers.
            "Metadata-Version: 2.1\nSummary: a package\n\nName: evil\nVersion: 9.9.9\n",
        )
        .await
        .unwrap();

        // Falls back to the directory name, NOT the body's "evil"/"9.9.9".
        let (name, version) = read_python_metadata(&dist_info).await.unwrap();
        assert_eq!(name, "requests");
        assert_eq!(version, "2.28.0");
    }

    /// End-to-end via `crawl_all`: a package whose METADATA has no usable
    /// headers but whose description body looks like headers is recovered
    /// under its true (directory-name) identity, not the body's spoofed one.
    #[tokio::test]
    async fn test_crawl_all_not_poisoned_by_body_headers() {
        let dir = tempfile::tempdir().unwrap();
        let venv = dir.path().join(".venv");
        #[cfg(windows)]
        let sp = venv.join("Lib").join("site-packages");
        #[cfg(not(windows))]
        let sp = venv.join("lib").join("python3.11").join("site-packages");
        let dist_info = sp.join("urllib3-2.0.7.dist-info");
        tokio::fs::create_dir_all(&dist_info).await.unwrap();
        tokio::fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\n\nName: spoofed\nVersion: 6.6.6\n",
        )
        .await
        .unwrap();

        let crawler = PythonCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "urllib3");
        assert_eq!(packages[0].version, "2.0.7");
        assert_eq!(packages[0].purl, "pkg:pypi/urllib3@2.0.7");
    }

    /// A stray *file* named `*.dist-info` must NOT be surfaced as a package
    /// via the directory-name fallback.
    #[tokio::test]
    async fn test_read_python_metadata_ignores_stray_file() {
        let dir = tempfile::tempdir().unwrap();
        let stray = dir.path().join("ghost-1.0.dist-info");
        tokio::fs::write(&stray, b"not a dir").await.unwrap();
        assert!(read_python_metadata(&stray).await.is_none());
    }

    /// `crawl_all` recovers a package whose METADATA is missing by parsing
    /// the `.dist-info` directory name.
    #[tokio::test]
    async fn test_crawl_all_recovers_metadata_less_package() {
        let dir = tempfile::tempdir().unwrap();
        let venv = dir.path().join(".venv");
        #[cfg(windows)]
        let sp = venv.join("Lib").join("site-packages");
        #[cfg(not(windows))]
        let sp = venv.join("lib").join("python3.11").join("site-packages");
        tokio::fs::create_dir_all(&sp).await.unwrap();
        // dist-info dir exists but has no METADATA (partial install).
        tokio::fs::create_dir_all(sp.join("flask_sqlalchemy-3.0.5.dist-info"))
            .await
            .unwrap();

        let crawler = PythonCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "flask-sqlalchemy");
        assert_eq!(packages[0].version, "3.0.5");
        assert_eq!(packages[0].purl, "pkg:pypi/flask-sqlalchemy@3.0.5");
    }

    /// Regression for the macOS Python.framework layout: the `Versions/`
    /// directory holds bare version dirs (`3.11`), so the version segment
    /// must be matched with `*`. A `python3.*` pattern matches nothing.
    #[tokio::test]
    async fn test_find_python_dirs_framework_versions_layout() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir
            .path()
            .join("Versions")
            .join("3.11")
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&sp).await.unwrap();

        // Correct pattern (`*` for the version dir) finds it.
        let ok = find_python_dirs(
            &dir.path().join("Versions"),
            &["*", "lib", "python3.*", "site-packages"],
        )
        .await;
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0], sp);

        // The buggy pattern (`python3.*` for the version dir) matches nothing.
        let buggy = find_python_dirs(
            &dir.path().join("Versions"),
            &["python3.*", "lib", "python3.*", "site-packages"],
        )
        .await;
        assert!(buggy.is_empty());
    }

    /// Debian/Ubuntu apt-installed modules live in the BARE `python3`
    /// interpreter dir (`/usr/lib/python3/dist-packages`), not a
    /// minor-versioned one. The `python3.*` segment must match it; a
    /// `python3.`-prefix test (requiring the dot) silently hid every
    /// distro-packaged module — exactly the bug this guards.
    #[tokio::test]
    async fn test_find_python_dirs_matches_bare_python3() {
        let dir = tempfile::tempdir().unwrap();
        let dist = dir.path().join("lib").join("python3").join("dist-packages");
        tokio::fs::create_dir_all(&dist).await.unwrap();

        let results = find_python_dirs(dir.path(), &["lib", "python3.*", "dist-packages"]).await;
        assert_eq!(results, vec![dist]);
    }

    /// The bare-`python3` arm must be an EXACT match, not a loose prefix:
    /// `python3` and `python3.12` are interpreters, but `python3foo` /
    /// `python311` are not and must be ignored so the `python3.*` segment
    /// never over-matches an unrelated directory.
    #[tokio::test]
    async fn test_find_python_dirs_bare_python3_exact_not_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let lib = dir.path().join("lib");
        for v in ["python3", "python3.12", "python3foo", "python311"] {
            tokio::fs::create_dir_all(lib.join(v).join("site-packages"))
                .await
                .unwrap();
        }

        let results = find_python_dirs(dir.path(), &["lib", "python3.*", "site-packages"]).await;
        let mut got: Vec<String> = results
            .iter()
            .map(|p| {
                p.parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        got.sort();
        // Only the real interpreter dirs — `python3` and `python3.12`.
        assert_eq!(got, vec!["python3", "python3.12"]);
    }

    /// `lib` and `lib64` coexist on RHEL/Fedora/SUSE and hold distinct
    /// packages (pure-Python vs compiled). `scan_well_known` scans both;
    /// the `lib64` segment is a plain literal, so this proves the matcher
    /// reaches a `lib64/python3.X/site-packages` tree at all.
    #[tokio::test]
    async fn test_find_python_dirs_lib64_layout() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir
            .path()
            .join("lib64")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&sp).await.unwrap();

        let results = find_python_dirs(dir.path(), &["lib64", "python3.*", "site-packages"]).await;
        assert_eq!(results, vec![sp]);
    }

    #[tokio::test]
    async fn test_find_python_dirs_literal() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir
            .path()
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&target).await.unwrap();

        let results = find_python_dirs(dir.path(), &["lib", "python3.*", "site-packages"]).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], target);
    }

    #[tokio::test]
    async fn test_find_python_dirs_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        let sp1 = dir
            .path()
            .join("lib")
            .join("python3.10")
            .join("site-packages");
        let sp2 = dir
            .path()
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&sp1).await.unwrap();
        tokio::fs::create_dir_all(&sp2).await.unwrap();

        // Also create a non-matching dir
        let non_match = dir.path().join("lib").join("ruby3.0").join("site-packages");
        tokio::fs::create_dir_all(&non_match).await.unwrap();

        let results = find_python_dirs(dir.path(), &["lib", "python3.*", "site-packages"]).await;
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_find_python_dirs_star_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        let sp1 = dir
            .path()
            .join("tools")
            .join("mytool")
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&sp1).await.unwrap();

        let results = find_python_dirs(
            dir.path(),
            &["tools", "*", "lib", "python3.*", "site-packages"],
        )
        .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], sp1);
    }

    #[tokio::test]
    async fn test_find_python_dirs_pyenv_layout() {
        // Create a pyenv-like layout: versions/3.11.5/lib/python3.11/site-packages
        let dir = tempfile::tempdir().unwrap();
        let sp1 = dir
            .path()
            .join("versions")
            .join("3.11.5")
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        let sp2 = dir
            .path()
            .join("versions")
            .join("3.12.0")
            .join("lib")
            .join("python3.12")
            .join("site-packages");
        tokio::fs::create_dir_all(&sp1).await.unwrap();
        tokio::fs::create_dir_all(&sp2).await.unwrap();

        let results = find_python_dirs(
            &dir.path().join("versions"),
            &["*", "lib", "python3.*", "site-packages"],
        )
        .await;
        assert_eq!(results.len(), 2);
        assert!(results.contains(&sp1));
        assert!(results.contains(&sp2));
    }

    #[tokio::test]
    async fn test_crawl_all_python() {
        let dir = tempfile::tempdir().unwrap();
        let venv = dir.path().join(".venv");
        #[cfg(windows)]
        let sp = venv.join("Lib").join("site-packages");
        #[cfg(not(windows))]
        let sp = venv.join("lib").join("python3.11").join("site-packages");
        tokio::fs::create_dir_all(&sp).await.unwrap();

        // Create a dist-info dir with METADATA
        let dist_info = sp.join("requests-2.28.0.dist-info");
        tokio::fs::create_dir_all(&dist_info).await.unwrap();
        tokio::fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: Requests\nVersion: 2.28.0\n",
        )
        .await
        .unwrap();

        let crawler = PythonCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "requests");
        assert_eq!(packages[0].version, "2.28.0");
        assert_eq!(packages[0].purl, "pkg:pypi/requests@2.28.0");
        assert!(packages[0].namespace.is_none());
    }

    #[test]
    fn test_find_python_command() {
        // On any platform with Python installed, this should return Some
        // In CI environments, Python is typically available
        let cmd = find_python_command();
        // We don't assert Some because Python may not be installed,
        // but if it is, the command should be valid
        if let Some(c) = cmd {
            assert!(
                ["python3", "python", "py"].contains(&c),
                "unexpected command: {c}"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn test_home_dir_detection() {
        // Verify the shared fallback chain (HOME -> USERPROFILE -> "~")
        // yields a real path, not the "~" sentinel, on any CI or dev machine.
        // `serial`: other tests in this binary mutate HOME (go_crawler's
        // gomodcache fallback chain, utils::fs's empty-HOME regression) —
        // reading home_dir() while one of them holds HOME="" would see the
        // "~" sentinel and fail spuriously.
        let home = crate::utils::fs::home_dir();
        assert_ne!(home, PathBuf::from("~"), "expected a real home directory");
        assert!(!home.as_os_str().is_empty());
    }

    /// Global discovery must honor `PYENV_ROOT`: a pyenv install tree at
    /// `$PYENV_ROOT/versions/<v>/lib/python3.X/site-packages` has to surface
    /// in `get_global_python_site_packages`. Unlike the other well-known
    /// roots (which are hardwired system paths), the pyenv root is
    /// injectable via the env var, so a tempdir fixture reaches the pyenv
    /// match-collection loop on any host. Containment-only assertion — the
    /// function also scans real system dirs, so the full result vec is not
    /// deterministic across machines.
    #[cfg(not(windows))]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_pyenv_root_env_var_site_packages_discovered() {
        // Save/restore guard so a panicking assertion cannot leak the
        // override into other #[serial] env-var tests.
        struct EnvGuard {
            key: &'static str,
            prev: Option<String>,
        }
        impl EnvGuard {
            fn set(key: &'static str, value: &str) -> Self {
                let prev = std::env::var(key).ok();
                std::env::set_var(key, value);
                Self { key, prev }
            }
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let sp = dir
            .path()
            .join("versions")
            .join("3.11.5")
            .join("lib")
            .join("python3.11")
            .join("site-packages");
        tokio::fs::create_dir_all(&sp).await.unwrap();

        let _pyenv_root = EnvGuard::set("PYENV_ROOT", dir.path().to_str().unwrap());
        let results = get_global_python_site_packages().await;
        assert!(
            results.contains(&sp),
            "PYENV_ROOT site-packages {sp:?} missing from global discovery: {results:?}"
        );
    }

    #[tokio::test]
    async fn test_find_by_purls_python() {
        let dir = tempfile::tempdir().unwrap();
        let sp = dir.path().to_path_buf();

        // Create dist-info
        let dist_info = sp.join("requests-2.28.0.dist-info");
        tokio::fs::create_dir_all(&dist_info).await.unwrap();
        tokio::fs::write(
            dist_info.join("METADATA"),
            "Metadata-Version: 2.1\nName: Requests\nVersion: 2.28.0\n",
        )
        .await
        .unwrap();

        let crawler = PythonCrawler::new();
        let purls = vec![
            "pkg:pypi/requests@2.28.0".to_string(),
            "pkg:pypi/flask@3.0.0".to_string(),
        ];

        let result = crawler.find_by_purls(&sp, &purls).await.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:pypi/requests@2.28.0"));
        assert!(!result.contains_key("pkg:pypi/flask@3.0.0"));
    }

    // ── Equivalence with the per-call async scan (oracle) ─────────────

    mod equivalence {
        use super::super::oracle::{self, LegacyPythonCrawler};
        use super::*;
        use crate::crawlers::oracle_support::{
            fifo, map_rows, mkdir, rows, symlink, write, write_bytes, PermGuard, Rng,
        };

        const NAMES: &[&str] = &["requests", "Flask_Cors", "zope.interface", "dup", "Dup"];
        const VERSIONS: &[&str] = &["1.0", "2.31.0", "1.0+local", "3.0a1"];

        fn site(rng: &mut Rng, root: &Path, outside: &Path, perms: &mut PermGuard) {
            mkdir(root);
            for i in 0..rng.below(24) {
                let name = rng.pick(NAMES);
                let version = rng.pick(VERSIONS);
                let dir = root.join(format!("{name}-{version}.dist-info"));
                let metadata = dir.join("METADATA");
                match rng.below(14) {
                    0 => mkdir(&dir),
                    1 => write(&metadata, &format!("Name: {name}\n\nVersion: {version}\n")),
                    2 => write(&metadata, &format!("Metadata-Version: 2.1\r\nName: {name}\r\nVersion: {version}\r\n\r\nbody")),
                    3 => fifo(&metadata),
                    4 => mkdir(&metadata),
                    5 => {
                        write_bytes(&metadata, b"Name: \xff\nVersion: 1\n");
                    }
                    6 => write(&dir, "stray file"),
                    7 => {
                        let target = outside.join(format!("t{i}-{}", rng.next()));
                        if rng.chance(70) {
                            write(&target.join("METADATA"), &format!("Name: {name}\nVersion: {version}\n"));
                        }
                        symlink(&target, &dir);
                    }
                    8 => {
                        write(&metadata, &format!("Name: {name}\nVersion: {version}\n"));
                        perms.plan(&dir, 0o000);
                    }
                    9 => write(
                        &root.join(format!("{name}-{version}.egg-info")).join("PKG-INFO"),
                        "Name: x\nVersion: 1\n",
                    ),
                    10 => mkdir(&root.join(format!("{name}.dist-info"))),
                    _ => write(&metadata, &format!("Name: {name}\nVersion: {version}\n\nName: other\n")),
                }
            }
        }

        #[tokio::test]
        async fn randomized_site_packages_match_the_async_oracle() {
            let (mut crawled, mut found) = (0, 0);
            for seed in 0..64u64 {
                let tmp = tempfile::tempdir().unwrap();
                let mut perms = PermGuard::default();
                let mut rng = Rng::new(seed);
                let root = tmp.path().join("site-packages");
                site(&mut rng, &root, &tmp.path().join("outside"), &mut perms);
                perms.apply();

                assert_eq!(
                    list_dist_info_packages(&root).await,
                    oracle::list_dist_info_packages(&root).await,
                    "seed {seed}: listing"
                );
                let options = CrawlerOptions {
                    cwd: tmp.path().to_path_buf(),
                    global: false,
                    global_prefix: Some(root.clone()),
                };
                let new = PythonCrawler::new().crawl_all(&options).await;
                let old = LegacyPythonCrawler::crawl_all(&options).await;
                assert_eq!(rows(&new), rows(&old), "seed {seed}: crawl_all");

                let mut purls: Vec<String> = old.iter().map(|p| p.purl.clone()).collect();
                purls.push("pkg:pypi/Flask-Cors@1.0".to_string());
                purls.push("pkg:pypi/requests@1.0%2Blocal".to_string());
                purls.push("pkg:pypi/DUP@1.0".to_string());
                purls.push("pkg:pypi/dup@1.0".to_string());
                purls.push("pkg:npm/dup@1.0".to_string());
                let found_new = PythonCrawler::new()
                    .find_by_purls(&root, &purls)
                    .await
                    .unwrap();
                let found_old = LegacyPythonCrawler::find_by_purls(&root, &purls).await;
                assert_eq!(map_rows(&found_new), map_rows(&found_old));
                // Each PURL on its own, from one listing.
                let each = PythonCrawler::new().find_each_by_purl(&root, &purls).await;
                for (purl, got) in purls.iter().zip(&each) {
                    let single =
                        LegacyPythonCrawler::find_by_purls(&root, std::slice::from_ref(purl)).await;
                    assert_eq!(
                        got.as_ref().map(|p| rows(std::slice::from_ref(p))),
                        single.get(purl).map(|p| rows(std::slice::from_ref(p))),
                        "seed {seed}: find_each_by_purl {purl}"
                    );
                }
                crawled += old.len();
                found += found_new.len();
            }
            assert!(
                crawled > 100 && found > 100,
                "vacuous fixtures: {crawled}/{found}"
            );
        }
    }

    /// DC-6: the interpreter query memo answers from its slot only for the
    /// exact key it was filled under, re-runs on any other key (a changed
    /// environment or working directory), and never keeps a failed query's
    /// `None`: the next ask with the same key runs the query again, as an
    /// unmemoized caller would.
    #[test]
    fn keyed_memo_reruns_only_on_a_different_key() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let memo: KeyedMemo<(u32, &str), String> = KeyedMemo::new();
        let runs = AtomicUsize::new(0);
        let run = |out: Option<&str>| {
            runs.fetch_add(1, Ordering::SeqCst);
            out.map(str::to_string)
        };
        assert_eq!(
            memo.get_or_run((1, "a"), || run(Some("x"))),
            Some("x".into())
        );
        assert_eq!(
            memo.get_or_run((1, "a"), || run(Some("stale"))),
            Some("x".into())
        );
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        // A failure is returned but not stored: the same key re-runs.
        assert_eq!(memo.get_or_run((2, "a"), || run(None)), None);
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert_eq!(
            memo.get_or_run((2, "a"), || run(Some("y"))),
            Some("y".into())
        );
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        assert_eq!(
            memo.get_or_run((2, "a"), || run(Some("stale"))),
            Some("y".into())
        );
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        // A failure under a new key leaves nothing cached for the old one
        // to be served from, and the old key re-runs.
        assert_eq!(memo.get_or_run((3, "a"), || run(None)), None);
        assert_eq!(
            memo.get_or_run((1, "a"), || run(Some("z"))),
            Some("z".into())
        );
        assert_eq!(runs.load(Ordering::SeqCst), 5);
    }

    /// DC-6: the memoized site query is wired to the whole environment.
    /// Under two different `PYTHONUSERBASE` values (the interpreter's
    /// `getusersitepackages` follows it) the memoized answer equals the
    /// unmemoized oracle each time, and a repeat ask in the same
    /// environment still equals it. A constant memo key fails the second
    /// comparison. `#[serial]`: it mutates the process environment, and so
    /// does every other env test in this binary.
    #[test]
    #[serial_test::serial]
    fn site_query_memo_follows_the_environment() {
        struct EnvGuard {
            key: &'static str,
            prev: Option<std::ffi::OsString>,
        }
        impl EnvGuard {
            fn set(key: &'static str, value: &Path) -> Self {
                let prev = std::env::var_os(key);
                std::env::set_var(key, value);
                Self { key, prev }
            }
        }
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.prev {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
        let memoized = || SITE_QUERY_MEMO.get_or_run(site_query_key(), run_site_query);

        let base_a = tempfile::tempdir().unwrap();
        let base_b = tempfile::tempdir().unwrap();
        for base in [&base_a, &base_b] {
            let _env = EnvGuard::set("PYTHONUSERBASE", base.path());
            let oracle = run_site_query();
            assert_eq!(memoized(), oracle);
            assert_eq!(memoized(), oracle);
            if let Some(out) = &oracle {
                // Non-vacuous whenever an interpreter is present: the
                // answer really carries this environment's user base.
                let needle = base.path().file_name().unwrap().to_string_lossy();
                assert!(out.contains(needle.as_ref()), "{out}");
            }
        }
    }
}
