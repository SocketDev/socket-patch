use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::types::{CrawledPackage, CrawlerOptions};

// ---------------------------------------------------------------------------
// Python command discovery
// ---------------------------------------------------------------------------

/// Find a working Python command on the system.
///
/// Tries `python3`, `python`, and `py` (Windows launcher) in order,
/// returning the first one that responds to `--version`.
pub fn find_python_command() -> Option<&'static str> {
    ["python3", "python", "py"].into_iter().find(|cmd| {
        Command::new(cmd)
            .args(["--version"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    })
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

/// Read `Name` and `Version` from a `.dist-info/METADATA` file.
pub async fn read_python_metadata(dist_info_path: &Path) -> Option<(String, String)> {
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
        if let Ok(mut entries) = tokio::fs::read_dir(base_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let ft = match entry.file_type().await {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if !ft.is_dir() {
                    continue;
                }
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.starts_with("python3.") {
                    let sub = Box::pin(find_python_dirs(
                        &base_path.join(entry.file_name()),
                        rest,
                    ))
                    .await;
                    results.extend(sub);
                }
            }
        }
    } else if first == "*" {
        // Generic wildcard: match any directory entry
        if let Ok(mut entries) = tokio::fs::read_dir(base_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let ft = match entry.file_type().await {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if !ft.is_dir() {
                    continue;
                }
                let sub = Box::pin(find_python_dirs(
                    &base_path.join(entry.file_name()),
                    rest,
                ))
                .await;
                results.extend(sub);
            }
        }
    } else {
        // Literal segment: just check if it exists
        let sub =
            Box::pin(find_python_dirs(&base_path.join(first), rest)).await;
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
    if cfg!(windows) {
        find_python_dirs(base_dir, &["Lib", sub_dir_type]).await
    } else {
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
        if let Ok(output) = Command::new(python_cmd)
            .args([
                "-c",
                "import site; print('\\n'.join(site.getsitepackages())); print(site.getusersitepackages())",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let p = line.trim();
                    if !p.is_empty() {
                        add_path(PathBuf::from(p), &mut seen, &mut results);
                    }
                }
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

    if !cfg!(windows) {
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
    if cfg!(target_os = "macos") {
        scan_well_known(
            Path::new("/opt/homebrew"),
            "site-packages",
            &mut seen,
            &mut results,
        )
        .await;

        // Python.org framework
        let fw_matches = find_python_dirs(
            Path::new("/Library/Frameworks/Python.framework/Versions"),
            &["python3.*", "lib", "python3.*", "site-packages"],
        )
        .await;
        for m in fw_matches {
            add_path(m, &mut seen, &mut results);
        }

        let fw_matches2 = find_python_dirs(
            Path::new("/Library/Frameworks/Python.framework"),
            &["Versions", "*", "lib", "python3.*", "site-packages"],
        )
        .await;
        for m in fw_matches2 {
            add_path(m, &mut seen, &mut results);
        }
    }

    // Windows-specific
    if cfg!(windows) {
        // pip --user on Windows: %APPDATA%\Python\PythonXY\site-packages
        if let Ok(appdata) = std::env::var("APPDATA") {
            let appdata_python = PathBuf::from(&appdata).join("Python");
            if let Ok(mut entries) = tokio::fs::read_dir(&appdata_python).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let p = appdata_python.join(entry.file_name()).join("site-packages");
                    if tokio::fs::metadata(&p).await.is_ok() {
                        add_path(p, &mut seen, &mut results);
                    }
                }
            }
        }
        // Common Windows Python install locations
        for base in &["C:\\Python", "C:\\Program Files\\Python"] {
            if let Ok(mut entries) = tokio::fs::read_dir(base).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let sp = PathBuf::from(base)
                        .join(entry.file_name())
                        .join("Lib")
                        .join("site-packages");
                    if tokio::fs::metadata(&sp).await.is_ok() {
                        add_path(sp, &mut seen, &mut results);
                    }
                }
            }
        }
        // Microsoft Store / python.org via LocalAppData
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let programs_python = PathBuf::from(&local).join("Programs").join("Python");
            if let Ok(mut entries) = tokio::fs::read_dir(&programs_python).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
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
    }

    // Conda
    let anaconda = PathBuf::from(&home_dir).join("anaconda3");
    scan_well_known(&anaconda, "site-packages", &mut seen, &mut results).await;
    let miniconda = PathBuf::from(&home_dir).join("miniconda3");
    scan_well_known(&miniconda, "site-packages", &mut seen, &mut results).await;

    // uv tools
    if cfg!(target_os = "macos") {
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
    } else if cfg!(windows) {
        // %LOCALAPPDATA%\uv\tools
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let uv_base = PathBuf::from(local).join("uv").join("tools");
            let uv_matches =
                find_python_dirs(&uv_base, &["*", "Lib", "site-packages"]).await;
            for m in uv_matches {
                add_path(m, &mut seen, &mut results);
            }
        }
    } else {
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

    results
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
    pub async fn get_site_packages_paths(&self, options: &CrawlerOptions) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(get_global_python_site_packages().await);
        }
        Ok(find_local_venv_site_packages(&options.cwd).await)
    }

    /// Crawl all discovered `site-packages` and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let sp_paths = self.get_site_packages_paths(options).await.unwrap_or_default();

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
        let entries = match tokio::fs::read_dir(site_packages_path).await {
            Ok(rd) => {
                let mut entries = rd;
                let mut v = Vec::new();
                while let Ok(Some(entry)) = entries.next_entry().await {
                    v.push(entry);
                }
                v
            }
            Err(_) => return Ok(result),
        };

        for entry in entries {
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

        let entries = match tokio::fs::read_dir(site_packages_path).await {
            Ok(rd) => {
                let mut entries = rd;
                let mut v = Vec::new();
                while let Ok(Some(entry)) = entries.next_entry().await {
                    v.push(entry);
                }
                v
            }
            Err(_) => return results,
        };

        for entry in entries {
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

    #[tokio::test]
    async fn test_find_python_dirs_literal() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("lib").join("python3.11").join("site-packages");
        tokio::fs::create_dir_all(&target).await.unwrap();

        let results =
            find_python_dirs(dir.path(), &["lib", "python3.*", "site-packages"]).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], target);
    }

    #[tokio::test]
    async fn test_find_python_dirs_wildcard() {
        let dir = tempfile::tempdir().unwrap();
        let sp1 = dir.path().join("lib").join("python3.10").join("site-packages");
        let sp2 = dir.path().join("lib").join("python3.11").join("site-packages");
        tokio::fs::create_dir_all(&sp1).await.unwrap();
        tokio::fs::create_dir_all(&sp2).await.unwrap();

        // Also create a non-matching dir
        let non_match = dir.path().join("lib").join("ruby3.0").join("site-packages");
        tokio::fs::create_dir_all(&non_match).await.unwrap();

        let results =
            find_python_dirs(dir.path(), &["lib", "python3.*", "site-packages"]).await;
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
    async fn test_crawl_all_python() {
        let dir = tempfile::tempdir().unwrap();
        let venv = dir.path().join(".venv");
        let sp = if cfg!(windows) {
            venv.join("Lib").join("site-packages")
        } else {
            venv.join("lib").join("python3.11").join("site-packages")
        };
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
