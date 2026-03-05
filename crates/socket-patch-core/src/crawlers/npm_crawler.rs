use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use super::types::{CrawledPackage, CrawlerOptions};

/// Default batch size for crawling.
#[cfg(test)]
const DEFAULT_BATCH_SIZE: usize = 100;

/// Directories to skip when searching for workspace node_modules.
const SKIP_DIRS: &[&str] = &[
    "dist",
    "build",
    "coverage",
    "tmp",
    "temp",
    "__pycache__",
    "vendor",
];

// ---------------------------------------------------------------------------
// Helper: read and parse package.json
// ---------------------------------------------------------------------------

/// Minimal fields we need from package.json.
#[derive(Deserialize)]
struct PackageJsonPartial {
    name: Option<String>,
    version: Option<String>,
}

/// Read and parse a `package.json` file, returning `(name, version)` if valid.
pub async fn read_package_json(pkg_json_path: &Path) -> Option<(String, String)> {
    let content = tokio::fs::read_to_string(pkg_json_path).await.ok()?;
    let pkg: PackageJsonPartial = serde_json::from_str(&content).ok()?;
    let name = pkg.name?;
    let version = pkg.version?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

// ---------------------------------------------------------------------------
// Helper: parse package name into (namespace, name)
// ---------------------------------------------------------------------------

/// Parse a full npm package name into optional namespace and bare name.
///
/// Examples:
/// - `"@types/node"` -> `(Some("@types"), "node")`
/// - `"lodash"` -> `(None, "lodash")`
pub fn parse_package_name(full_name: &str) -> (Option<String>, String) {
    if full_name.starts_with('@') {
        if let Some(slash_idx) = full_name.find('/') {
            let namespace = full_name[..slash_idx].to_string();
            let name = full_name[slash_idx + 1..].to_string();
            return (Some(namespace), name);
        }
    }
    (None, full_name.to_string())
}

// ---------------------------------------------------------------------------
// Helper: build PURL
// ---------------------------------------------------------------------------

/// Build a PURL string for an npm package.
pub fn build_npm_purl(namespace: Option<&str>, name: &str, version: &str) -> String {
    match namespace {
        Some(ns) => format!("pkg:npm/{ns}/{name}@{version}"),
        None => format!("pkg:npm/{name}@{version}"),
    }
}

// ---------------------------------------------------------------------------
// Global prefix detection helpers
// ---------------------------------------------------------------------------

/// Get the npm global `node_modules` path via `npm root -g`.
pub fn get_npm_global_prefix() -> Result<String, String> {
    let output = Command::new("npm")
        .args(["root", "-g"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to run `npm root -g`: {e}"))?;

    if !output.status.success() {
        return Err(
            "Failed to determine npm global prefix. Ensure npm is installed and in PATH."
                .to_string(),
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Get the yarn global `node_modules` path via `yarn global dir`.
pub fn get_yarn_global_prefix() -> Option<String> {
    let output = Command::new("yarn")
        .args(["global", "dir"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(PathBuf::from(dir).join("node_modules").to_string_lossy().to_string())
}

/// Get the pnpm global `node_modules` path via `pnpm root -g`.
pub fn get_pnpm_global_prefix() -> Option<String> {
    let output = Command::new("pnpm")
        .args(["root", "-g"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(path)
}

/// Get the bun global `node_modules` path via `bun pm bin -g`.
pub fn get_bun_global_prefix() -> Option<String> {
    let output = Command::new("bun")
        .args(["pm", "bin", "-g"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let bin_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if bin_path.is_empty() {
        return None;
    }

    let bun_root = PathBuf::from(&bin_path);
    let bun_root = bun_root.parent()?;
    Some(
        bun_root
            .join("install")
            .join("global")
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Helpers: synchronous wildcard directory resolver
// ---------------------------------------------------------------------------

/// Resolve a path with `"*"` wildcard segments synchronously.
///
/// Each segment is either a literal directory name or `"*"` which matches any
/// directory entry. Symlinks are followed via `std::fs::metadata`.
fn find_node_dirs_sync(base: &Path, segments: &[&str]) -> Vec<PathBuf> {
    if !base.is_dir() {
        return Vec::new();
    }
    if segments.is_empty() {
        return vec![base.to_path_buf()];
    }

    let first = segments[0];
    let rest = &segments[1..];

    if first == "*" {
        let mut results = Vec::new();
        if let Ok(entries) = std::fs::read_dir(base) {
            for entry in entries.flatten() {
                // Follow symlinks: use metadata() not symlink_metadata()
                let is_dir = entry
                    .metadata()
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if is_dir {
                    results.extend(find_node_dirs_sync(&base.join(entry.file_name()), rest));
                }
            }
        }
        results
    } else {
        find_node_dirs_sync(&base.join(first), rest)
    }
}

// ---------------------------------------------------------------------------
// NpmCrawler
// ---------------------------------------------------------------------------

/// NPM ecosystem crawler for discovering packages in `node_modules`.
pub struct NpmCrawler;

impl NpmCrawler {
    /// Create a new `NpmCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get `node_modules` paths based on options.
    ///
    /// In global mode returns well-known global paths; in local mode walks
    /// the project tree looking for `node_modules` directories (including
    /// workspace packages).
    pub async fn get_node_modules_paths(&self, options: &CrawlerOptions) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(self.get_global_node_modules_paths());
        }

        Ok(self.find_local_node_modules_dirs(&options.cwd).await)
    }

    /// Crawl all discovered `node_modules` and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let nm_paths = self.get_node_modules_paths(options).await.unwrap_or_default();

        for nm_path in &nm_paths {
            let found = self.scan_node_modules(nm_path, &mut seen).await;
            packages.extend(found);
        }

        packages
    }

    /// Find specific packages by PURL inside a single `node_modules` tree.
    ///
    /// This is an efficient O(n) lookup where n = number of PURLs: we parse
    /// each PURL to derive the expected directory path, then do a direct stat
    /// + `package.json` read.
    pub async fn find_by_purls(
        &self,
        node_modules_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        // Parse each PURL to extract the directory key and expected version.
        struct Target {
            namespace: Option<String>,
            name: String,
            version: String,
            #[allow(dead_code)] purl: String,
            dir_key: String,
        }

        let purl_set: HashSet<&str> = purls.iter().map(|s| s.as_str()).collect();
        let mut targets: Vec<Target> = Vec::new();

        for purl in purls {
            if let Some((ns, name, version)) = Self::parse_purl_components(purl) {
                let dir_key = match &ns {
                    Some(ns_str) => format!("{ns_str}/{name}"),
                    None => name.clone(),
                };
                targets.push(Target {
                    namespace: ns,
                    name,
                    version,
                    purl: purl.clone(),
                    dir_key,
                });
            }
        }

        for target in &targets {
            let pkg_path = node_modules_path.join(&target.dir_key);
            let pkg_json_path = pkg_path.join("package.json");

            if let Some((_, version)) = read_package_json(&pkg_json_path).await {
                if version == target.version {
                    let purl = build_npm_purl(
                        target.namespace.as_deref(),
                        &target.name,
                        &version,
                    );
                    if purl_set.contains(purl.as_str()) {
                        result.insert(
                            purl.clone(),
                            CrawledPackage {
                                name: target.name.clone(),
                                version,
                                namespace: target.namespace.clone(),
                                purl,
                                path: pkg_path.clone(),
                            },
                        );
                    }
                }
            }
        }

        Ok(result)
    }

    // ------------------------------------------------------------------
    // Private helpers – global paths
    // ------------------------------------------------------------------

    /// Collect global `node_modules` paths from all known package managers.
    fn get_global_node_modules_paths(&self) -> Vec<PathBuf> {
        let mut seen = HashSet::new();
        let mut paths = Vec::new();

        let mut add = |p: PathBuf| {
            if p.is_dir() && seen.insert(p.clone()) {
                paths.push(p);
            }
        };

        if let Ok(npm_path) = get_npm_global_prefix() {
            add(PathBuf::from(npm_path));
        }
        if let Some(pnpm_path) = get_pnpm_global_prefix() {
            add(PathBuf::from(pnpm_path));
        }
        if let Some(yarn_path) = get_yarn_global_prefix() {
            add(PathBuf::from(yarn_path));
        }
        if let Some(bun_path) = get_bun_global_prefix() {
            add(PathBuf::from(bun_path));
        }

        // macOS-specific fallback paths
        if cfg!(target_os = "macos") {
            let home = std::env::var("HOME").unwrap_or_default();

            // Homebrew Apple Silicon
            add(PathBuf::from("/opt/homebrew/lib/node_modules"));
            // Homebrew Intel / default npm
            add(PathBuf::from("/usr/local/lib/node_modules"));

            if !home.is_empty() {
                // nvm
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".nvm/versions/node"),
                    &["*", "lib", "node_modules"],
                ) {
                    add(p);
                }
                // volta
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".volta/tools/image/node"),
                    &["*", "lib", "node_modules"],
                ) {
                    add(p);
                }
                // fnm
                for p in find_node_dirs_sync(
                    &PathBuf::from(&home).join(".fnm/node-versions"),
                    &["*", "installation", "lib", "node_modules"],
                ) {
                    add(p);
                }
            }
        }

        paths
    }

    // ------------------------------------------------------------------
    // Private helpers – local node_modules discovery
    // ------------------------------------------------------------------

    /// Find `node_modules` directories within the project root.
    /// Recursively searches for workspace `node_modules` but stays within the
    /// project.
    async fn find_local_node_modules_dirs(&self, start_path: &Path) -> Vec<PathBuf> {
        let mut results = Vec::new();

        // Direct node_modules in start_path
        let direct = start_path.join("node_modules");
        if is_dir(&direct).await {
            results.push(direct);
        }

        // Recursively search for workspace node_modules
        Self::find_workspace_node_modules(start_path, &mut results).await;

        results
    }

    /// Recursively find `node_modules` in subdirectories (for monorepos / workspaces).
    /// Skips symlinks, hidden dirs, and well-known non-workspace dirs.
    fn find_workspace_node_modules<'a>(
        dir: &'a Path,
        results: &'a mut Vec<PathBuf>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async move {
            let mut entries = match tokio::fs::read_dir(dir).await {
                Ok(rd) => rd,
                Err(_) => return,
            };

            let mut entry_list = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                entry_list.push(entry);
            }

            for entry in entry_list {
                let file_type = match entry.file_type().await {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };

                if !file_type.is_dir() {
                    continue;
                }

                let name = entry.file_name();
                let name_str = name.to_string_lossy();

                // Skip node_modules, hidden dirs, and well-known build dirs
                if name_str == "node_modules"
                    || name_str.starts_with('.')
                    || SKIP_DIRS.contains(&name_str.as_ref())
                {
                    continue;
                }

                let full_path = dir.join(&name);

                // Check if this subdirectory has its own node_modules
                let sub_nm = full_path.join("node_modules");
                if is_dir(&sub_nm).await {
                    results.push(sub_nm);
                }

                // Recurse
                Self::find_workspace_node_modules(&full_path, results).await;
            }
        })
    }

    // ------------------------------------------------------------------
    // Private helpers – scanning
    // ------------------------------------------------------------------

    /// Scan a `node_modules` directory, returning all valid packages found.
    async fn scan_node_modules(
        &self,
        node_modules_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        let mut entries = match tokio::fs::read_dir(node_modules_path).await {
            Ok(rd) => rd,
            Err(_) => return results,
        };

        let mut entry_list = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            entry_list.push(entry);
        }

        for entry in entry_list {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_string();

            // Skip hidden files and node_modules
            if name_str.starts_with('.') || name_str == "node_modules" {
                continue;
            }

            let file_type = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };

            // Allow both directories and symlinks (pnpm uses symlinks)
            if !file_type.is_dir() && !file_type.is_symlink() {
                continue;
            }

            let entry_path = node_modules_path.join(&name_str);

            if name_str.starts_with('@') {
                // Scoped packages
                let scoped =
                    Self::scan_scoped_packages(&entry_path, seen).await;
                results.extend(scoped);
            } else {
                // Regular package
                if let Some(pkg) = Self::check_package(&entry_path, seen).await {
                    results.push(pkg);
                }
                // Nested node_modules only for real directories (not symlinks)
                if file_type.is_dir() {
                    let nested =
                        Self::scan_nested_node_modules(&entry_path, seen).await;
                    results.extend(nested);
                }
            }
        }

        results
    }

    /// Scan a scoped packages directory (`@scope/`).
    fn scan_scoped_packages<'a>(
        scope_path: &'a Path,
        seen: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<CrawledPackage>> + 'a>> {
        Box::pin(async move {
            let mut results = Vec::new();

            let mut entries = match tokio::fs::read_dir(scope_path).await {
                Ok(rd) => rd,
                Err(_) => return results,
            };

            let mut entry_list = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                entry_list.push(entry);
            }

            for entry in entry_list {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                if name_str.starts_with('.') {
                    continue;
                }

                let file_type = match entry.file_type().await {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };

                if !file_type.is_dir() && !file_type.is_symlink() {
                    continue;
                }

                let pkg_path = scope_path.join(&name_str);
                if let Some(pkg) = Self::check_package(&pkg_path, seen).await {
                    results.push(pkg);
                }

                // Nested node_modules only for real directories
                if file_type.is_dir() {
                    let nested =
                        Self::scan_nested_node_modules(&pkg_path, seen).await;
                    results.extend(nested);
                }
            }

            results
        })
    }

    /// Scan nested `node_modules` inside a package (if it exists).
    fn scan_nested_node_modules<'a>(
        pkg_path: &'a Path,
        seen: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Vec<CrawledPackage>> + 'a>> {
        Box::pin(async move {
            let nested_nm = pkg_path.join("node_modules");

            let mut entries = match tokio::fs::read_dir(&nested_nm).await {
                Ok(rd) => rd,
                Err(_) => return Vec::new(),
            };

            let mut results = Vec::new();

            let mut entry_list = Vec::new();
            while let Ok(Some(entry)) = entries.next_entry().await {
                entry_list.push(entry);
            }

            for entry in entry_list {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                if name_str.starts_with('.') || name_str == "node_modules" {
                    continue;
                }

                let file_type = match entry.file_type().await {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };

                if !file_type.is_dir() && !file_type.is_symlink() {
                    continue;
                }

                let entry_path = nested_nm.join(&name_str);

                if name_str.starts_with('@') {
                    let scoped =
                        Self::scan_scoped_packages(&entry_path, seen).await;
                    results.extend(scoped);
                } else {
                    if let Some(pkg) = Self::check_package(&entry_path, seen).await {
                        results.push(pkg);
                    }
                    // Recursively check deeper nested node_modules
                    let deeper =
                        Self::scan_nested_node_modules(&entry_path, seen).await;
                    results.extend(deeper);
                }
            }

            results
        })
    }

    /// Check a package directory and return `CrawledPackage` if valid.
    /// Deduplicates by PURL via the `seen` set.
    async fn check_package(
        pkg_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Option<CrawledPackage> {
        let pkg_json_path = pkg_path.join("package.json");
        let (full_name, version) = read_package_json(&pkg_json_path).await?;
        let (namespace, name) = parse_package_name(&full_name);
        let purl = build_npm_purl(namespace.as_deref(), &name, &version);

        if seen.contains(&purl) {
            return None;
        }
        seen.insert(purl.clone());

        Some(CrawledPackage {
            name,
            version,
            namespace,
            purl,
            path: pkg_path.to_path_buf(),
        })
    }

    // ------------------------------------------------------------------
    // Private helpers – PURL parsing
    // ------------------------------------------------------------------

    /// Parse a PURL string to extract namespace, name, and version.
    fn parse_purl_components(purl: &str) -> Option<(Option<String>, String, String)> {
        // Strip qualifiers
        let base = match purl.find('?') {
            Some(idx) => &purl[..idx],
            None => purl,
        };

        let rest = base.strip_prefix("pkg:npm/")?;
        let at_idx = rest.rfind('@')?;
        let name_part = &rest[..at_idx];
        let version = &rest[at_idx + 1..];

        if name_part.is_empty() || version.is_empty() {
            return None;
        }

        if name_part.starts_with('@') {
            let slash_idx = name_part.find('/')?;
            let namespace = name_part[..slash_idx].to_string();
            let name = name_part[slash_idx + 1..].to_string();
            if name.is_empty() {
                return None;
            }
            Some((Some(namespace), name, version.to_string()))
        } else {
            Some((None, name_part.to_string(), version.to_string()))
        }
    }
}

impl Default for NpmCrawler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// Check whether a path is a directory (follows symlinks).
async fn is_dir(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_package_name_scoped() {
        let (ns, name) = parse_package_name("@types/node");
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
    }

    #[test]
    fn test_parse_package_name_unscoped() {
        let (ns, name) = parse_package_name("lodash");
        assert!(ns.is_none());
        assert_eq!(name, "lodash");
    }

    #[test]
    fn test_build_npm_purl_scoped() {
        assert_eq!(
            build_npm_purl(Some("@types"), "node", "20.0.0"),
            "pkg:npm/@types/node@20.0.0"
        );
    }

    #[test]
    fn test_build_npm_purl_unscoped() {
        assert_eq!(
            build_npm_purl(None, "lodash", "4.17.21"),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn test_parse_purl_components_scoped() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/@types/node@20.0.0").unwrap();
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
        assert_eq!(ver, "20.0.0");
    }

    #[test]
    fn test_parse_purl_components_unscoped() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/lodash@4.17.21").unwrap();
        assert!(ns.is_none());
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn test_parse_purl_components_invalid() {
        assert!(NpmCrawler::parse_purl_components("pkg:pypi/requests@2.0").is_none());
        assert!(NpmCrawler::parse_purl_components("not-a-purl").is_none());
    }

    #[tokio::test]
    async fn test_read_package_json_valid() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        tokio::fs::write(
            &pkg_json,
            r#"{"name": "test-pkg", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let result = read_package_json(&pkg_json).await;
        assert!(result.is_some());
        let (name, version) = result.unwrap();
        assert_eq!(name, "test-pkg");
        assert_eq!(version, "1.0.0");
    }

    #[tokio::test]
    async fn test_read_package_json_missing() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        assert!(read_package_json(&pkg_json).await.is_none());
    }

    #[tokio::test]
    async fn test_read_package_json_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        tokio::fs::write(&pkg_json, "not json").await.unwrap();
        assert!(read_package_json(&pkg_json).await.is_none());
    }

    #[tokio::test]
    async fn test_crawl_all_basic() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let pkg_dir = nm.join("foo");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.2.3"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: DEFAULT_BATCH_SIZE,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[0].version, "1.2.3");
        assert_eq!(packages[0].purl, "pkg:npm/foo@1.2.3");
        assert!(packages[0].namespace.is_none());
    }

    #[tokio::test]
    async fn test_crawl_all_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let scope_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&scope_dir).await.unwrap();
        tokio::fs::write(
            scope_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: DEFAULT_BATCH_SIZE,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "node");
        assert_eq!(packages[0].namespace.as_deref(), Some("@types"));
        assert_eq!(packages[0].purl, "pkg:npm/@types/node@20.0.0");
    }

    #[test]
    fn test_find_node_dirs_sync_wildcard() {
        // Create an nvm-like layout: base/v18.0.0/lib/node_modules
        let dir = tempfile::tempdir().unwrap();
        let nm1 = dir.path().join("v18.0.0/lib/node_modules");
        let nm2 = dir.path().join("v20.1.0/lib/node_modules");
        std::fs::create_dir_all(&nm1).unwrap();
        std::fs::create_dir_all(&nm2).unwrap();

        let results = find_node_dirs_sync(dir.path(), &["*", "lib", "node_modules"]);
        assert_eq!(results.len(), 2);
        assert!(results.contains(&nm1));
        assert!(results.contains(&nm2));
    }

    #[test]
    fn test_find_node_dirs_sync_empty() {
        // Non-existent base path should return empty
        let results = find_node_dirs_sync(Path::new("/nonexistent/path/xyz"), &["*", "lib"]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_find_node_dirs_sync_literal() {
        // All literal segments (no wildcard)
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("lib/node_modules");
        std::fs::create_dir_all(&target).unwrap();

        let results = find_node_dirs_sync(dir.path(), &["lib", "node_modules"]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], target);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_get_global_node_modules_paths_no_panic() {
        let crawler = NpmCrawler::new();
        // Should not panic, even if no package managers are installed
        let _paths = crawler.get_global_node_modules_paths();
    }

    #[tokio::test]
    async fn test_find_by_purls() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        // Create foo@1.0.0
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Create @types/node@20.0.0
        let types_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&types_dir).await.unwrap();
        tokio::fs::write(
            types_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purls = vec![
            "pkg:npm/foo@1.0.0".to_string(),
            "pkg:npm/@types/node@20.0.0".to_string(),
            "pkg:npm/not-installed@0.0.1".to_string(),
        ];

        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("pkg:npm/foo@1.0.0"));
        assert!(result.contains_key("pkg:npm/@types/node@20.0.0"));
        assert!(!result.contains_key("pkg:npm/not-installed@0.0.1"));
    }
}
