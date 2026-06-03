use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::utils::process::{CommandRunner, SystemCommandRunner};

// ---------------------------------------------------------------------------
// Python command discovery
// ---------------------------------------------------------------------------

/// Find a working Python command on the system.
///
/// Tries `python3`, `python`, and `py` (Windows launcher) in order,
/// returning the first one that responds to `--version`.
pub fn find_python_command() -> Option<&'static str> {
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

/// Default batch size for crawling.
const _DEFAULT_BATCH_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// PEP 503 name canonicalization
// ---------------------------------------------------------------------------

/// Canonicalize a Python package name per PEP 503.
///
/// Lowercases, trims, and replaces runs of `[-_.]` with a single `-`.
pub fn canonicalize_pypi_name(name: &str) -> String {
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
    let content = tokio::fs::read_to_string(&metadata_path).await.ok()?;

    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for line in content.lines() {
        if name.is_some() && version.is_some() {
            break;
        }
        if let Some(rest) = line.strip_prefix("Name:") {
            name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Version:") {
            version = Some(rest.trim().to_string());
        }
        // Stop at first empty line (end of headers)
        if line.trim().is_empty() && (name.is_some() || version.is_some()) {
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
/// - `"python3.*"` — matches directory entries starting with `python3.`
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
        // Wildcard: list directory and match python3.X entries
        for entry in crate::utils::fs::list_dir_entries(base_path).await {
            if !crate::utils::fs::entry_is_dir(&entry).await {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("python3.") {
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
pub async fn find_site_packages_under(
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

    results
}

/// Get global/system Python `site-packages` directories.
///
/// Queries `python3` for site-packages paths, then checks well-known system
/// locations including Homebrew, conda, uv tools, pip --user, etc.
pub async fn get_global_python_site_packages() -> Vec<PathBuf> {
    let mut results = Vec::new();
    let mut seen = HashSet::new();

    let add_path = |p: PathBuf, seen: &mut HashSet<PathBuf>, results: &mut Vec<PathBuf>| {
        let resolved = if p.is_absolute() {
            p
        } else {
            std::path::absolute(&p).unwrap_or(p)
        };
        if seen.insert(resolved.clone()) {
            results.push(resolved);
        }
    };

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
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "~".to_string());

    // Helper closure to scan base/lib/python3.*/[dist|site]-packages
    async fn scan_well_known(
        base: &Path,
        pkg_type: &str,
        seen: &mut HashSet<PathBuf>,
        results: &mut Vec<PathBuf>,
    ) {
        let matches = find_python_dirs(base, &["lib", "python3.*", pkg_type]).await;
        for m in matches {
            let resolved = if m.is_absolute() {
                m
            } else {
                std::path::absolute(&m).unwrap_or(m)
            };
            if seen.insert(resolved.clone()) {
                results.push(resolved);
            }
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
        let user_local = PathBuf::from(&home_dir).join(".local");
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
            .unwrap_or_else(|_| PathBuf::from(&home_dir).join(".pyenv"));
        let pyenv_versions = pyenv_root.join("versions");
        let pyenv_matches =
            find_python_dirs(&pyenv_versions, &["*", "lib", "python3.*", "site-packages"]).await;
        for m in pyenv_matches {
            add_path(m, &mut seen, &mut results);
        }
    }

    // Conda
    let anaconda = PathBuf::from(&home_dir).join("anaconda3");
    scan_well_known(&anaconda, "site-packages", &mut seen, &mut results).await;
    let miniconda = PathBuf::from(&home_dir).join("miniconda3");
    scan_well_known(&miniconda, "site-packages", &mut seen, &mut results).await;

    // uv tools — platform-specific install root.
    #[cfg(target_os = "macos")]
    {
        let uv_base = PathBuf::from(&home_dir)
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
    #[cfg(all(not(target_os = "macos"), not(windows)))]
    {
        let uv_base = PathBuf::from(&home_dir)
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
        let uv_python = PathBuf::from(&home_dir)
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
pub async fn is_python_project(cwd: &Path) -> bool {
    let markers = [
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "uv.lock",
    ];
    for m in &markers {
        if tokio::fs::metadata(cwd.join(m)).await.is_ok() {
            return true;
        }
    }
    false
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
            let found = self.scan_site_packages(sp_path, &mut seen).await;
            packages.extend(found);
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

        // Build lookup: canonicalized-name@version -> purl
        let mut purl_lookup: HashMap<String, &str> = HashMap::new();
        for purl in purls {
            if let Some((name, version)) = Self::parse_pypi_purl(purl) {
                let key = format!("{}@{}", canonicalize_pypi_name(&name), version);
                purl_lookup.insert(key, purl.as_str());
            }
        }

        if purl_lookup.is_empty() {
            return Ok(result);
        }

        // Scan all .dist-info dirs
        for entry in crate::utils::fs::list_dir_entries(site_packages_path).await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.ends_with(".dist-info") {
                continue;
            }

            let dist_info_path = site_packages_path.join(&*name_str);
            if let Some((raw_name, version)) = read_python_metadata(&dist_info_path).await {
                let canon_name = canonicalize_pypi_name(&raw_name);
                let key = format!("{canon_name}@{version}");

                if let Some(&matched_purl) = purl_lookup.get(&key) {
                    result.insert(
                        matched_purl.to_string(),
                        CrawledPackage {
                            name: canon_name,
                            version,
                            namespace: None,
                            purl: matched_purl.to_string(),
                            path: site_packages_path.to_path_buf(),
                        },
                    );
                }
            }
        }

        Ok(result)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Scan a `site-packages` directory for `.dist-info` directories.
    async fn scan_site_packages(
        &self,
        site_packages_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for entry in crate::utils::fs::list_dir_entries(site_packages_path).await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.ends_with(".dist-info") {
                continue;
            }

            let dist_info_path = site_packages_path.join(&*name_str);
            if let Some((raw_name, version)) = read_python_metadata(&dist_info_path).await {
                let canon_name = canonicalize_pypi_name(&raw_name);
                let purl = format!("pkg:pypi/{canon_name}@{version}");

                if seen.contains(&purl) {
                    continue;
                }
                seen.insert(purl.clone());

                results.push(CrawledPackage {
                    name: canon_name,
                    version,
                    namespace: None,
                    purl,
                    path: site_packages_path.to_path_buf(),
                });
            }
        }

        results
    }

    /// Parse a PyPI PURL string to extract name and version.
    /// Strips qualifiers before parsing.
    fn parse_pypi_purl(purl: &str) -> Option<(String, String)> {
        // Strip qualifiers
        let base = match purl.find('?') {
            Some(idx) => &purl[..idx],
            None => purl,
        };

        let rest = base.strip_prefix("pkg:pypi/")?;
        let at_idx = rest.rfind('@')?;
        let name = &rest[..at_idx];
        let version = &rest[at_idx + 1..];

        if name.is_empty() || version.is_empty() {
            return None;
        }

        Some((name.to_string(), version.to_string()))
    }
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

    #[test]
    fn test_parse_pypi_purl() {
        let (name, ver) = PythonCrawler::parse_pypi_purl("pkg:pypi/requests@2.28.0").unwrap();
        assert_eq!(name, "requests");
        assert_eq!(ver, "2.28.0");
    }

    #[test]
    fn test_parse_pypi_purl_with_qualifiers() {
        let (name, ver) =
            PythonCrawler::parse_pypi_purl("pkg:pypi/requests@2.28.0?artifact_id=abc").unwrap();
        assert_eq!(name, "requests");
        assert_eq!(ver, "2.28.0");
    }

    #[test]
    fn test_parse_pypi_purl_invalid() {
        assert!(PythonCrawler::parse_pypi_purl("pkg:npm/lodash@4.17.21").is_none());
        assert!(PythonCrawler::parse_pypi_purl("not-a-purl").is_none());
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
            batch_size: 100,
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
            batch_size: 100,
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
    fn test_home_dir_detection() {
        // Verify the fallback chain works: HOME -> USERPROFILE -> "~"
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "~".to_string());
        // On any CI or dev machine, we should get a real path, not "~"
        assert_ne!(home, "~", "expected a real home directory");
        assert!(!home.is_empty());
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
