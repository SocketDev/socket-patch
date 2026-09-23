use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::utils::fs::read_regular_to_string;
use crate::utils::process::{CommandRunner, SystemCommandRunner};

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

    let is_dir = tokio::fs::metadata(dist_info_path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if !is_dir {
        return None;
    }
    let dir_name = dist_info_path.file_name()?.to_string_lossy();
    parse_dist_info_dir_name(&dir_name)
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
/// 1. `VIRTUAL_ENV` environment variable
/// 2. `.venv` directory in `cwd`
/// 3. `venv` directory in `cwd`
/// 4. Poetry's out-of-tree virtualenv(s) for a Poetry project (see
///    [`find_poetry_virtualenv_site_packages`])
pub async fn find_local_venv_site_packages(cwd: &Path) -> Vec<PathBuf> {
    let mut results = Vec::new();

    // 1. Check VIRTUAL_ENV env var
    if let Ok(virtual_env) = std::env::var("VIRTUAL_ENV") {
        let venv_path = PathBuf::from(&virtual_env);
        let matches = find_site_packages_under(&venv_path, "site-packages").await;
        results.extend(matches);
        if !results.is_empty() {
            return results;
        }
    }

    // 2. Check .venv and venv in cwd
    for venv_dir in &[".venv", "venv"] {
        let venv_path = cwd.join(venv_dir);
        let matches = find_site_packages_under(&venv_path, "site-packages").await;
        results.extend(matches);
    }

    // 3. Poetry keeps its virtualenv OUTSIDE the project by default, so a plain
    // `poetry install` leaves nothing above to find and the crawl used to fall
    // through to the global interpreter (patching the wrong site-packages, or
    // nothing, and reporting success).
    if results.is_empty() {
        results.extend(find_poetry_virtualenv_site_packages(cwd).await);
    }

    // 4. Pipenv keeps its virtualenv OUTSIDE the project by default
    // (`$WORKON_HOME/<dir>-<hash>`), so a plain `pipenv install` leaves
    // nothing above to find and the crawl used to fall through to the global
    // interpreter's site-packages — patching the wrong Python (or nothing)
    // and reporting success. Measured on real Pipenv 11.10.4, 2018.11.26 and
    // 2026.8.0.
    if results.is_empty() {
        results.extend(find_pipenv_virtualenv_site_packages(cwd).await);
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
    /// `virtualenvs.in-project` — `true` means `./.venv`, already probed.
    in_project: Option<bool>,
    /// `virtualenvs.path` — may carry Poetry's `{cache-dir}` /
    /// `{project-dir}` placeholders and a leading `~`.
    path: Option<String>,
    /// `cache-dir` — the parent of the default `virtualenvs` root.
    cache_dir: Option<String>,
}

impl PoetryVirtualenvConfig {
    /// Layer `other` (lower precedence) under `self`: only unset keys take
    /// the lower layer's value.
    fn or(mut self, other: PoetryVirtualenvConfig) -> Self {
        self.create = self.create.or(other.create);
        self.in_project = self.in_project.or(other.in_project);
        self.path = self.path.or(other.path);
        self.cache_dir = self.cache_dir.or(other.cache_dir);
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
/// resolved; on Windows lowercased with forward slashes turned into
/// backslashes, elsewhere unchanged.
fn poetry_normalized_cwd(cwd: &Path) -> String {
    let real = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let text = real.to_string_lossy().into_owned();
    if cfg!(windows) {
        text.replace('/', "\\").to_lowercase()
    } else {
        text
    }
}

/// The project name Poetry derives its virtualenv name from: `[tool.poetry]
/// name`, else PEP 621 `[project] name`. Poetry canonicalizes it (PEP 503) —
/// both spellings are returned so a lock written before that normalization
/// still matches.
fn poetry_project_names(pyproject: &str) -> Vec<String> {
    let Ok(doc) = pyproject.parse::<toml_edit::DocumentMut>() else {
        return Vec::new();
    };
    let raw = doc
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("name"))
        .and_then(toml_edit::Item::as_str)
        .or_else(|| {
            doc.get("project")
                .and_then(|p| p.get("name"))
                .and_then(toml_edit::Item::as_str)
        });
    let Some(raw) = raw else {
        return Vec::new();
    };
    let mut names = vec![canonicalize_pypi_name(raw)];
    if !names.contains(&raw.to_string()) {
        names.push(raw.to_string());
    }
    names
}

/// The root directory Poetry would place this project's virtualenvs under,
/// or `None` when Poetry would not create one (`virtualenvs.create = false`,
/// `virtualenvs.in-project = true`, or no home to resolve the default against).
fn poetry_virtualenvs_root(
    cwd: &Path,
    config: &PoetryVirtualenvConfig,
    var: &impl Fn(&str) -> Option<String>,
) -> Option<PathBuf> {
    if config.create == Some(false) || config.in_project == Some(true) {
        return None;
    }
    let cache_dir = config
        .cache_dir
        .as_deref()
        .map(|c| expand_home(c, var))
        .or_else(|| poetry_default_cache_dir(var))?;
    match config.path.as_deref() {
        Some(template) => {
            let expanded = template
                .replace("{cache-dir}", &cache_dir.to_string_lossy())
                .replace("{project-dir}", &cwd.to_string_lossy());
            let path = expand_home(&expanded, var);
            Some(if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            })
        }
        None => Some(cache_dir.join("virtualenvs")),
    }
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
    let has = |leaf: &str| cwd.join(leaf).is_file();
    let pyproject = match read_regular_to_string(&cwd.join("pyproject.toml")).await {
        Ok(text) => text,
        Err(_) => return Vec::new(),
    };
    let poetry_project =
        has("poetry.lock") || has("poetry.toml") || pyproject.contains("[tool.poetry");
    if !poetry_project {
        return Vec::new();
    }
    let names = poetry_project_names(&pyproject);
    if names.is_empty() {
        return Vec::new();
    }
    let local = match read_regular_to_string(&cwd.join("poetry.toml")).await {
        Ok(text) => PoetryVirtualenvConfig::from_toml(&text),
        Err(_) => PoetryVirtualenvConfig::default(),
    };
    let user = match poetry_user_config_path(&var) {
        Some(path) => match read_regular_to_string(&path).await {
            Ok(text) => PoetryVirtualenvConfig::from_toml(&text),
            Err(_) => PoetryVirtualenvConfig::default(),
        },
        None => PoetryVirtualenvConfig::default(),
    };
    let config = PoetryVirtualenvConfig::from_env(var).or(local).or(user);
    let Some(root) = poetry_virtualenvs_root(cwd, &config, &var) else {
        return Vec::new();
    };
    let normalized = poetry_normalized_cwd(cwd);
    let prefixes: Vec<String> = names
        .iter()
        .map(|name| format!("{}-py", poetry_env_name_prefix(name, &normalized)))
        .collect();
    let Ok(mut entries) = tokio::fs::read_dir(&root).await else {
        return Vec::new();
    };
    let mut venvs = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if prefixes.iter().any(|prefix| name.starts_with(prefix)) {
            venvs.push(entry.path());
        }
    }
    venvs.sort();
    let mut results = Vec::new();
    for venv in venvs {
        results.extend(find_site_packages_under(&venv, "site-packages").await);
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
    let is_file = |leaf: &str| cwd.join(leaf).is_file();
    if !is_file("Pipfile") && !is_file("Pipfile.lock") {
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
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            text = format!(r"\\{rest}");
        } else if let Some(rest) = text.strip_prefix(r"\\?\") {
            text = rest.to_string();
        }
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

/// Get global/system Python `site-packages` directories.
///
/// Queries `python3` for site-packages paths, then checks well-known system
/// locations including Homebrew, conda, uv tools, pip --user, etc.
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

    // 1. Ask Python for site-packages
    if let Some(python_cmd) = find_python_command() {
        let runner = SystemCommandRunner;
        if let Some(stdout) = runner.run(
            python_cmd,
            &[
                "-c",
                "import site; print('\\n'.join(site.getsitepackages())); print(site.getusersitepackages())",
            ],
        ) {
            for p in parse_python_site_packages_output(&stdout) {
                add_path(p, &mut seen, &mut results);
            }
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

    // uv tools — platform-specific install root.
    #[cfg(target_os = "macos")]
    {
        // Legacy/secondary location only: uv follows XDG conventions on
        // macOS (`uv tool dir` → ~/.local/share/uv/tools, covered by the
        // not(windows) scan below), but older layouts used the platform
        // data dir, so keep scanning it too.
        let uv_base = home_dir
            .join("Library")
            .join("Application Support")
            .join("uv")
            .join("tools");
        let uv_matches =
            find_python_dirs(&uv_base, &["*", "lib", "python3.*", "site-packages"]).await;
        for m in uv_matches {
            add_path(m, &mut seen, &mut results);
        }
    }
    #[cfg(windows)]
    {
        // %LOCALAPPDATA%\uv\tools
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let uv_base = PathBuf::from(local).join("uv").join("tools");
            let uv_matches = find_python_dirs(&uv_base, &["*", "Lib", "site-packages"]).await;
            for m in uv_matches {
                add_path(m, &mut seen, &mut results);
            }
        }
    }
    #[cfg(not(windows))]
    {
        // uv uses XDG paths on BOTH Linux and macOS (`uv tool dir` →
        // ~/.local/share/uv/tools; verified against a real uv install —
        // macOS does NOT get an Application Support tool dir).
        let uv_base = home_dir
            .join(".local")
            .join("share")
            .join("uv")
            .join("tools");
        let uv_matches =
            find_python_dirs(&uv_base, &["*", "lib", "python3.*", "site-packages"]).await;
        for m in uv_matches {
            add_path(m, &mut seen, &mut results);
        }
    }

    // uv-managed Python interpreters (`uv python install 3.X`) live at:
    //   Linux/macOS: ~/.local/share/uv/python/cpython-3.X.*/lib/python3.X/site-packages/
    //   Windows:     %LOCALAPPDATA%\uv\python\cpython-3.X.*\Lib\site-packages\
    // The typical flow is `uv venv` + `uv pip install`, where the venv layout
    // is already covered by `find_local_venv_site_packages`. But power users
    // can install packages directly into the managed interpreter (e.g. via
    // `<uv-python>/bin/pip install ...`), and globally-discovered crawls
    // should surface those.
    #[cfg(not(windows))]
    {
        let uv_python = home_dir
            .join(".local")
            .join("share")
            .join("uv")
            .join("python");
        let uv_matches =
            find_python_dirs(&uv_python, &["*", "lib", "python3.*", "site-packages"]).await;
        for m in uv_matches {
            add_path(m, &mut seen, &mut results);
        }
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let uv_python = PathBuf::from(local).join("uv").join("python");
            let uv_matches = find_python_dirs(&uv_python, &["*", "Lib", "site-packages"]).await;
            for m in uv_matches {
                add_path(m, &mut seen, &mut results);
            }
        }
    }

    results
}

/// Returns true if `cwd` looks like a Python project root.
///
/// Used by `PythonCrawler::get_site_packages_paths` to decide
/// whether to fall back to the global-discovery path when no venv
/// was found. Mirrors `is_dotnet_project` in nuget_crawler and the
/// `has_gemfile || has_gemfile_lock` check in ruby_crawler.
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
    ///      `.venv`, and `venv` directories (covers the common case
    ///      of an activated or project-local venv).
    ///   2. If no venv was found AND the cwd looks like a Python
    ///      project (`pyproject.toml`, `setup.py`, `setup.cfg`,
    ///      `requirements.txt`, or `uv.lock` present), fall through
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
        let mut result = HashMap::new();

        // Build lookup: canonicalized-name@version -> purl. The API serves
        // purls percent-encoded (a PEP 440 local/epoch version carries
        // `+`/`!`, arriving as `%2B`/`%21`), so decode the coordinates
        // before keying or the installed package never matches.
        let mut purl_lookup: HashMap<String, &str> = HashMap::new();
        for purl in purls {
            if let Some((name, version)) = crate::utils::purl::parse_pypi_purl(purl) {
                let name = crate::utils::purl::percent_decode_purl_component(name);
                let version = crate::utils::purl::percent_decode_purl_component(version);
                let key = format!("{}@{}", canonicalize_pypi_name(&name), version);
                purl_lookup.insert(key, purl.as_str());
            }
        }

        if purl_lookup.is_empty() {
            return Ok(result);
        }

        for (name, version) in list_dist_info_packages(site_packages_path).await {
            let key = format!("{name}@{version}");
            if let Some(&matched_purl) = purl_lookup.get(&key) {
                result.insert(
                    matched_purl.to_string(),
                    CrawledPackage {
                        name,
                        version,
                        namespace: None,
                        purl: matched_purl.to_string(),
                        path: site_packages_path.to_path_buf(),
                    },
                );
            }
        }

        Ok(result)
    }
}

/// Scan a `site-packages` directory for `.dist-info` entries, returning
/// `(canonicalized name, version)` for each package that yields metadata.
async fn list_dist_info_packages(site_packages_path: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in crate::utils::fs::list_dir_entries(site_packages_path).await {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.ends_with(".dist-info") {
            continue;
        }
        let dist_info_path = site_packages_path.join(&*name_str);
        if let Some((raw_name, version)) = read_python_metadata(&dist_info_path).await {
            out.push((canonicalize_pypi_name(&raw_name), version));
        }
    }
    out
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

    /// The crawler's public entry point wires step 3 in: with no VIRTUAL_ENV
    /// and no in-project venv, `find_local_venv_site_packages` returns the
    /// out-of-tree Pipenv venv instead of nothing (which used to trigger the
    /// global fallback).
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

    #[test]
    fn poetry_project_names_prefer_tool_poetry_and_return_both_spellings() {
        assert_eq!(
            poetry_project_names(
                "[tool.poetry]\nname = \"Flask_Login\"\n[project]\nname = \"other\"\n"
            ),
            vec!["flask-login".to_string(), "Flask_Login".to_string()]
        );
        assert_eq!(
            poetry_project_names(
                "[project]\nname = \"my-app\"\n[tool.poetry]\npackage-mode = false\n"
            ),
            vec!["my-app".to_string()]
        );
        assert!(poetry_project_names("[tool.poetry]\nversion = \"1\"\n").is_empty());
        assert!(poetry_project_names("not toml [").is_empty());
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
        let project_local = PoetryVirtualenvConfig {
            path: Some("{project-dir}/.envs".into()),
            ..Default::default()
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &project_local, &var),
            Some(PathBuf::from("/home/dev/proj/.envs"))
        );
        let tilde = PoetryVirtualenvConfig {
            path: Some("~/venvs".into()),
            ..Default::default()
        };
        assert_eq!(
            poetry_virtualenvs_root(cwd, &tilde, &var),
            Some(PathBuf::from("/home/dev/venvs"))
        );
        for disabled in [
            PoetryVirtualenvConfig {
                create: Some(false),
                ..Default::default()
            },
            PoetryVirtualenvConfig {
                in_project: Some(true),
                ..Default::default()
            },
        ] {
            assert_eq!(poetry_virtualenvs_root(cwd, &disabled, &var), None);
        }
        // Defaults resolve against the platform cache dir; with no home at all
        // there is nothing to resolve against.
        let default = PoetryVirtualenvConfig::default();
        assert!(poetry_virtualenvs_root(cwd, &default, &var).is_some());
        assert_eq!(
            poetry_virtualenvs_root(cwd, &default, &|_: &str| None),
            None
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

        // `poetry.toml` opting into in-project venvs (or disabling creation)
        // means Poetry never used the shared root: nothing is probed.
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\nin-project = true\n",
        )
        .unwrap();
        assert!(find_local_venv_site_packages(&project).await.is_empty());
        std::fs::write(
            project.join("poetry.toml"),
            "[virtualenvs]\ncreate = false\n",
        )
        .unwrap();
        assert!(find_local_venv_site_packages(&project).await.is_empty());
        std::fs::remove_file(project.join("poetry.toml")).unwrap();

        // Not a Poetry project (no lock, no [tool.poetry]): untouched.
        std::fs::write(
            project.join("pyproject.toml"),
            "[project]\nname = \"poetry-patch-fixture\"\n",
        )
        .unwrap();
        std::fs::remove_file(project.join("poetry.lock")).unwrap();
        assert!(find_local_venv_site_packages(&project).await.is_empty());
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
    /// must be matched with `*`. A `python3.*` pattern matches nothing —
    /// which is exactly the bug that was fixed.
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
}
