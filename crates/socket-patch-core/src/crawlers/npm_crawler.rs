use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::is_dir;
use crate::utils::purl::{percent_decode_purl_component, strip_purl_qualifiers};

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

use crate::utils::process::{CommandRunner, SystemCommandRunner};

/// Get the npm global `node_modules` path via `npm root -g`.
pub fn get_npm_global_prefix() -> Result<String, String> {
    get_npm_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_npm_global_prefix` that accepts an injected
/// `CommandRunner`. Tests use this with a `MockCommandRunner` to
/// exercise the success arm (binary present, stdout parsed) without
/// requiring npm on the host's PATH.
pub fn get_npm_global_prefix_with(runner: &dyn CommandRunner) -> Result<String, String> {
    parse_npm_root_output(runner.run("npm", &["root", "-g"]).as_deref().unwrap_or("")).ok_or_else(
        || {
            "Failed to determine npm global prefix. Ensure npm is installed and in PATH."
                .to_string()
        },
    )
}

/// Pure parser for `npm root -g` stdout. Returns the trimmed path or
/// `None` on empty input. Extracted so the helper logic is unit-
/// testable without shelling out.
pub fn parse_npm_root_output(stdout: &str) -> Option<String> {
    let path = stdout.trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

/// Get the yarn global `node_modules` path via `yarn global dir`.
pub fn get_yarn_global_prefix() -> Option<String> {
    get_yarn_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_yarn_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_yarn_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_yarn_dir_output(
        runner
            .run("yarn", &["global", "dir"])
            .as_deref()
            .unwrap_or(""),
    )
}

/// Pure parser for `yarn global dir` stdout. Returns `<dir>/node_modules`
/// or `None` on empty input. Extracted so the path-derivation logic is
/// unit-testable without shelling out.
pub fn parse_yarn_dir_output(stdout: &str) -> Option<String> {
    let dir = stdout.trim().to_string();
    if dir.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(dir)
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

/// Get the pnpm global `node_modules` path via `pnpm root -g`.
pub fn get_pnpm_global_prefix() -> Option<String> {
    get_pnpm_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_pnpm_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_pnpm_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_pnpm_root_output(runner.run("pnpm", &["root", "-g"]).as_deref().unwrap_or(""))
}

/// Pure parser for `pnpm root -g` stdout. Returns the trimmed path or
/// `None` on empty input.
pub fn parse_pnpm_root_output(stdout: &str) -> Option<String> {
    let path = stdout.trim().to_string();
    if path.is_empty() {
        return None;
    }
    Some(path)
}

/// Get the bun global `node_modules` path via `bun pm bin -g`.
pub fn get_bun_global_prefix() -> Option<String> {
    get_bun_global_prefix_with(&SystemCommandRunner)
}

/// Version of `get_bun_global_prefix` that accepts an injected
/// `CommandRunner`. See `get_npm_global_prefix_with`.
pub fn get_bun_global_prefix_with(runner: &dyn CommandRunner) -> Option<String> {
    parse_bun_bin_output(
        runner
            .run("bun", &["pm", "bin", "-g"])
            .as_deref()
            .unwrap_or(""),
    )
}

/// Pure parser for `bun pm bin -g` stdout. Extracted so the
/// derive-the-global-node_modules-path logic is unit-testable
/// without shelling out.
///
/// Given output like `"/Users/foo/.bun/bin\n"` returns
/// `Some("/Users/foo/.bun/install/global/node_modules")`. Returns
/// `None` on empty input or a root-only path with no parent.
pub fn parse_bun_bin_output(stdout: &str) -> Option<String> {
    let bin_path = stdout.trim().to_string();
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
///
/// Production callers live inside `#[cfg(target_os = "macos")]` blocks of
/// `get_global_node_modules_paths` (Homebrew/nvm/volta/fnm fallbacks).
/// `#[allow(dead_code)]` keeps the function visible to the inline
/// `#[cfg(test)] mod tests` callers on every target without tripping
/// `-D dead_code` on non-macOS clippy runs.
#[allow(dead_code)]
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
                // Follow symlinks: `DirEntry::metadata()` does NOT traverse
                // symlinks (it stats the link itself), so a symlinked version
                // dir — fnm's per-version layout, nvm `default`/`current`
                // aliases — would be missed. Stat the joined path with the
                // free `std::fs::metadata`, which resolves the link target.
                let child = base.join(entry.file_name());
                let is_dir = std::fs::metadata(&child)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if is_dir {
                    results.extend(find_node_dirs_sync(&child, rest));
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
    pub async fn get_node_modules_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
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

        let nm_paths = self
            .get_node_modules_paths(options)
            .await
            .unwrap_or_default();

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
        //
        // `purl` is the *verbatim* caller-supplied PURL, including any
        // `?qualifiers`. The result map is keyed by this exact string: the
        // dispatcher drives npm with `passthrough_purls` + `merge_first_wins`,
        // so it looks results back up under the PURL it handed in. Keying by a
        // reconstructed/stripped PURL silently loses every qualified PURL
        // (e.g. `pkg:npm/foo@1.0.0?vcs_url=...`).
        struct Target {
            namespace: Option<String>,
            name: String,
            version: String,
            purl: String,
            dir_key: String,
        }

        let mut targets: Vec<Target> = Vec::new();

        for purl in purls {
            if let Some((ns, name, version)) = Self::parse_purl_components(purl) {
                // SECURITY: `ns`/`name` come straight from the (untrusted)
                // manifest PURL and are joined onto `node_modules_path` below,
                // then patched in place. A real npm scope/name is a single
                // path segment, so reject any that could traverse out of the
                // tree (`pkg:npm/../../evil@1.0.0`). Fail closed — twin of the
                // deno/go/maven coordinate gates.
                let ns_safe = ns.as_deref().map(is_safe_npm_component).unwrap_or(true);
                if !ns_safe || !is_safe_npm_component(&name) {
                    continue;
                }
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
                    result.insert(
                        target.purl.clone(),
                        CrawledPackage {
                            name: target.name.clone(),
                            version,
                            namespace: target.namespace.clone(),
                            purl: target.purl.clone(),
                            path: pkg_path.clone(),
                        },
                    );
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
        #[cfg(target_os = "macos")]
        {
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
            for entry in crate::utils::fs::list_dir_entries(dir).await {
                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
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

        for entry in crate::utils::fs::list_dir_entries(node_modules_path).await {
            let name = entry.file_name();
            let name_str = name.to_string_lossy().to_string();

            // Skip hidden files and node_modules
            if name_str.starts_with('.') || name_str == "node_modules" {
                continue;
            }

            let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                continue;
            };

            // Allow both directories and symlinks (pnpm uses symlinks)
            if !file_type.is_dir() && !file_type.is_symlink() {
                continue;
            }

            let entry_path = node_modules_path.join(&name_str);

            if name_str.starts_with('@') {
                // Scoped packages
                let scoped = Self::scan_scoped_packages(&entry_path, seen).await;
                results.extend(scoped);
            } else {
                // Regular package
                if let Some(pkg) = Self::check_package(&entry_path, seen).await {
                    results.push(pkg);
                }
                // Nested node_modules only for real directories (not symlinks)
                if file_type.is_dir() {
                    let nested = Self::scan_nested_node_modules(&entry_path, seen).await;
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

            for entry in crate::utils::fs::list_dir_entries(scope_path).await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                if name_str.starts_with('.') {
                    continue;
                }

                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
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
                    let nested = Self::scan_nested_node_modules(&pkg_path, seen).await;
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
            let mut results = Vec::new();

            for entry in crate::utils::fs::list_dir_entries(&nested_nm).await {
                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                if name_str.starts_with('.') || name_str == "node_modules" {
                    continue;
                }

                let Some(file_type) = crate::utils::fs::entry_file_type(&entry).await else {
                    continue;
                };

                if !file_type.is_dir() && !file_type.is_symlink() {
                    continue;
                }

                let entry_path = nested_nm.join(&name_str);

                if name_str.starts_with('@') {
                    let scoped = Self::scan_scoped_packages(&entry_path, seen).await;
                    results.extend(scoped);
                } else {
                    if let Some(pkg) = Self::check_package(&entry_path, seen).await {
                        results.push(pkg);
                    }
                    // Recurse into deeper nested node_modules only for real
                    // directories (not symlinks) — matching the invariant in
                    // `scan_node_modules`/`scan_scoped_packages`. Following a
                    // symlink here would walk into pnpm's content-addressed
                    // store (or an `npm link` target outside the project).
                    if file_type.is_dir() {
                        let deeper = Self::scan_nested_node_modules(&entry_path, seen).await;
                        results.extend(deeper);
                    }
                }
            }

            results
        })
    }

    /// Check a package directory and return `CrawledPackage` if valid.
    /// Deduplicates by PURL via the `seen` set.
    async fn check_package(pkg_path: &Path, seen: &mut HashSet<String>) -> Option<CrawledPackage> {
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
        let base = strip_purl_qualifiers(purl);

        let rest = base.strip_prefix("pkg:npm/")?;
        let at_idx = rest.rfind('@')?;
        let name_part = &rest[..at_idx];
        let version = &rest[at_idx + 1..];

        if name_part.is_empty() || version.is_empty() {
            return None;
        }

        // SECURITY: components are percent-decoded AFTER the `/`/`@` splits
        // above (so an encoded `%2f` cannot create a new path segment here)
        // and BEFORE the `is_safe_npm_component` guards in `find_by_purls`
        // (so `%2e%2e` cannot smuggle a traversal past them). The API serves
        // scoped purls as `pkg:npm/%40scope/name@version`, which must match
        // the literal `node_modules/@scope/name` install.
        let version = percent_decode_purl_component(version);

        if let Some(slash_idx) = name_part.find('/') {
            let namespace = percent_decode_purl_component(&name_part[..slash_idx]);
            let name = percent_decode_purl_component(&name_part[slash_idx + 1..]);
            // An npm namespace is always an `@scope` (checked post-decode).
            if name.is_empty() || !namespace.starts_with('@') {
                return None;
            }
            Some((
                Some(namespace.into_owned()),
                name.into_owned(),
                version.into_owned(),
            ))
        } else {
            let name = percent_decode_purl_component(name_part);
            // A bare `@scope` with no `/name` is not a package name.
            if name.starts_with('@') {
                return None;
            }
            Some((None, name.into_owned(), version.into_owned()))
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

/// Whether a PURL-derived path component is safe to join onto the
/// `node_modules` root. An npm package's scope (`@types`) and bare name
/// (`node`) are each a single path segment, so a real one never contains a
/// separator, a `.`/`..` segment, a backslash, a colon, or a NUL.
/// `find_by_purls` joins these straight from the (untrusted) manifest PURL
/// onto the `node_modules` root and then patches the resolved package in
/// place, so a tampered PURL like `pkg:npm/../../evil@1.0.0` would otherwise
/// read (and later write) out of tree. Delegates to
/// [`path_safety::is_safe_single_segment`], which also rejects `:` — a
/// Windows drive-relative component (`C:evil`) joins as an absolute path.
/// Fails closed. Twin of the deno (`is_safe_jsr_component`), go, and maven
/// coordinate gates.
fn is_safe_npm_component(component: &str) -> bool {
    path_safety::is_safe_single_segment(component)
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
        let (ns, name, ver) = NpmCrawler::parse_purl_components("pkg:npm/lodash@4.17.21").unwrap();
        assert!(ns.is_none());
        assert_eq!(name, "lodash");
        assert_eq!(ver, "4.17.21");
    }

    #[test]
    fn test_parse_purl_components_invalid() {
        assert!(NpmCrawler::parse_purl_components("pkg:pypi/requests@2.0").is_none());
        assert!(NpmCrawler::parse_purl_components("not-a-purl").is_none());
    }

    /// The `?qualifier` is stripped *before* `rfind('@')` splits the
    /// version, so an `@` living inside a qualifier value
    /// (`vcs_url=git@github.com:...`) must not be mistaken for the
    /// version separator. Reordering those two steps would parse the
    /// version as `github.com:...` and break apply/rollback for any
    /// PURL whose qualifier carries an `@`.
    #[test]
    fn test_parse_purl_components_qualifier_with_at_sign() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/foo@1.0.0?vcs_url=git@github.com:x/y.git")
                .unwrap();
        assert!(ns.is_none());
        assert_eq!(name, "foo");
        assert_eq!(ver, "1.0.0");

        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/@types/node@20.0.0?maintainer=a@b.com")
                .unwrap();
        assert_eq!(ns.as_deref(), Some("@types"));
        assert_eq!(name, "node");
        assert_eq!(ver, "20.0.0");
    }

    #[tokio::test]
    async fn test_read_package_json_valid() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_json = dir.path().join("package.json");
        tokio::fs::write(&pkg_json, r#"{"name": "test-pkg", "version": "1.0.0"}"#)
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

    /// Regression: a wildcard segment that matches a *symlinked*
    /// directory must be followed. `DirEntry::metadata()` stats the link
    /// itself (reports `is_dir == false`), so the resolver previously
    /// skipped symlinked version dirs — exactly the layout fnm produces
    /// and the `current`/`default` aliases nvm creates. The fix stats the
    /// joined path with `std::fs::metadata`, which resolves the target.
    #[cfg(unix)]
    #[test]
    fn test_find_node_dirs_sync_follows_symlinked_segment() {
        use std::os::unix::fs::symlink;

        // Real version layout lives in its own tree, away from `base`,
        // so the only way to reach it is through the symlink.
        let real = tempfile::tempdir().unwrap();
        let real_nm = real.path().join("lib").join("node_modules");
        std::fs::create_dir_all(&real_nm).unwrap();

        // `base` holds only a symlink standing in for a version dir.
        let base = tempfile::tempdir().unwrap();
        let alias = base.path().join("current");
        symlink(real.path(), &alias).unwrap();

        let results = find_node_dirs_sync(base.path(), &["*", "lib", "node_modules"]);
        assert_eq!(
            results.len(),
            1,
            "a symlinked version dir must be followed, not skipped"
        );
        assert_eq!(results[0], alias.join("lib").join("node_modules"));
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

    /// Regression: the patches API serves scoped purls percent-encoded
    /// (`pkg:npm/%40scope/name@version`) and `scan` stores them verbatim as
    /// manifest keys. `find_by_purls` must decode the components to match
    /// the literal `node_modules/@scope/name` install — while keeping the
    /// result keyed by the *verbatim* encoded input (downstream contract).
    #[test]
    fn test_parse_purl_components_percent_encoded_scope() {
        let (ns, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/%40modelcontextprotocol/sdk@1.12.0")
                .unwrap();
        assert_eq!(ns.as_deref(), Some("@modelcontextprotocol"));
        assert_eq!(name, "sdk");
        assert_eq!(ver, "1.12.0");
        // An encoded bare scope with no `/name` is still not a package.
        assert!(NpmCrawler::parse_purl_components("pkg:npm/%40scope@1.0.0").is_none());
        // A `#subpath` without a qualifier must not bleed into the version.
        let (_, name, ver) =
            NpmCrawler::parse_purl_components("pkg:npm/foo@1.0.0#lib/util").unwrap();
        assert_eq!(name, "foo");
        assert_eq!(ver, "1.0.0");
    }

    #[tokio::test]
    async fn test_find_by_purls_percent_encoded_scope_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        let sdk_dir = nm.join("@modelcontextprotocol").join("sdk");
        tokio::fs::create_dir_all(&sdk_dir).await.unwrap();
        tokio::fs::write(
            sdk_dir.join("package.json"),
            r#"{"name": "@modelcontextprotocol/sdk", "version": "1.12.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let encoded = "pkg:npm/%40modelcontextprotocol/sdk@1.12.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&encoded))
            .await
            .unwrap();

        assert_eq!(result.len(), 1, "encoded scope must resolve: {result:?}");
        let pkg = result
            .get(&encoded)
            .expect("result keyed by the verbatim encoded input purl");
        assert_eq!(pkg.path, sdk_dir);
        assert_eq!(pkg.name, "sdk");
        assert_eq!(pkg.namespace.as_deref(), Some("@modelcontextprotocol"));
    }

    /// SECURITY regression: percent-encoded traversal sequences must be
    /// rejected by the post-decode guards — `%2e%2e` decodes to `..` and
    /// `%2f` to `/`, so guarding the *encoded* form would be a bypass.
    #[tokio::test]
    async fn test_find_by_purls_rejects_encoded_traversal() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        // A real scope dir so a scoped traversal's kernel walk could resolve.
        tokio::fs::create_dir_all(nm.join("@x")).await.unwrap();

        // A victim package OUTSIDE node_modules, reachable only via `..`.
        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let purls = vec![
            "pkg:npm/%2e%2e/evil@1.0.0".to_string(),
            "pkg:npm/@x/%2e%2e@1.0.0".to_string(),
            "pkg:npm/@x/%2e%2e%2f%2e%2e%2fevil@1.0.0".to_string(),
            "pkg:npm/..%2fevil@1.0.0".to_string(),
        ];
        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert!(
            result.is_empty(),
            "encoded traversal must not escape node_modules; got {result:?}"
        );
    }

    /// Regression: a qualified PURL (carrying `?qualifiers`) must resolve and
    /// be keyed by the *verbatim* input PURL — not a reconstructed, stripped
    /// form. The dispatcher drives npm with `passthrough_purls` +
    /// `merge_first_wins`, so it looks the result back up under the exact PURL
    /// it passed in. Keying by the stripped PURL silently dropped every
    /// qualified npm PURL from apply/rollback.
    #[tokio::test]
    async fn test_find_by_purls_resolves_qualified_purl_keyed_by_input() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");

        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        // Scoped package with a qualifier too.
        let types_dir = nm.join("@types").join("node");
        tokio::fs::create_dir_all(&types_dir).await.unwrap();
        tokio::fs::write(
            types_dir.join("package.json"),
            r#"{"name": "@types/node", "version": "20.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let unscoped_q = "pkg:npm/foo@1.0.0?vcs_url=https://github.com/x/foo".to_string();
        let scoped_q = "pkg:npm/@types/node@20.0.0?repository_url=https://npmjs.org".to_string();
        let purls = vec![unscoped_q.clone(), scoped_q.clone()];

        let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        // Keyed by the verbatim qualified input, and the stored PURL matches.
        let foo = result
            .get(&unscoped_q)
            .expect("qualified unscoped resolved");
        assert_eq!(foo.purl, unscoped_q);
        assert_eq!(foo.name, "foo");
        assert_eq!(foo.version, "1.0.0");

        let node = result.get(&scoped_q).expect("qualified scoped resolved");
        assert_eq!(node.purl, scoped_q);
        assert_eq!(node.namespace.as_deref(), Some("@types"));
        assert_eq!(node.name, "node");
    }

    /// Two distinct qualifiers over the same base package must each resolve
    /// to their own entry (the dispatcher passes them through verbatim).
    #[tokio::test]
    async fn test_find_by_purls_distinct_qualifiers_same_base() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let q1 = "pkg:npm/foo@1.0.0?a=1".to_string();
        let q2 = "pkg:npm/foo@1.0.0?b=2".to_string();

        let crawler = NpmCrawler::new();
        let result = crawler
            .find_by_purls(&nm, &[q1.clone(), q2.clone()])
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result.get(&q1).unwrap().path, foo_dir);
        assert_eq!(result.get(&q2).unwrap().path, foo_dir);
    }

    /// SECURITY regression: a tampered manifest PURL whose *name* carries a
    /// `..` traversal must not let `find_by_purls` resolve a package outside
    /// the `node_modules` root. The crawler joins the PURL-derived directory
    /// key straight onto `node_modules_path` and the resolved path is then
    /// patched in place, so an unguarded join would read (and later write)
    /// out of tree. Twin of the deno/go/maven `is_safe_*_coordinate` gates.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_in_name() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        tokio::fs::create_dir_all(&nm).await.unwrap();

        // A victim package living OUTSIDE node_modules, reachable only via
        // `..`. `node_modules/../evil` == `<root>/evil`.
        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let traversal = "pkg:npm/../evil@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&traversal))
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "a `..` in the PURL name must not escape node_modules; got {result:?}"
        );
    }

    /// SECURITY regression: a `..` smuggled through the *name* half of a
    /// scoped PURL must also be rejected. `@x/../../evil` parses to scope
    /// `@x` + name `../../evil`; with a real `@x` dir on disk for the kernel
    /// to walk, the join climbs clean out of node_modules to `<root>/evil`.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_via_scope() {
        let root = tempfile::tempdir().unwrap();
        let nm = root.path().join("node_modules");
        // A real scope dir so the kernel can resolve the leading `@x` before
        // the `..` segments climb — otherwise the walk would ENOENT and the
        // test would pass vacuously.
        tokio::fs::create_dir_all(nm.join("@x")).await.unwrap();

        let evil_dir = root.path().join("evil");
        tokio::fs::create_dir_all(&evil_dir).await.unwrap();
        tokio::fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let traversal = "pkg:npm/@x/../../evil@1.0.0".to_string();
        let result = crawler
            .find_by_purls(&nm, std::slice::from_ref(&traversal))
            .await
            .unwrap();

        assert!(
            result.is_empty(),
            "a `..` smuggled through the scope must not escape node_modules; got {result:?}"
        );
    }

    #[test]
    fn test_is_safe_npm_component() {
        // Legitimate components.
        assert!(is_safe_npm_component("lodash"));
        assert!(is_safe_npm_component("@types"));
        assert!(is_safe_npm_component("node"));
        assert!(is_safe_npm_component("some.pkg"));

        // Traversal / separator / NUL / empty.
        assert!(!is_safe_npm_component(""));
        assert!(!is_safe_npm_component("."));
        assert!(!is_safe_npm_component(".."));
        assert!(!is_safe_npm_component("../evil"));
        assert!(!is_safe_npm_component("a/b"));
        assert!(!is_safe_npm_component("a\\b"));
        assert!(!is_safe_npm_component("a\0b"));
        // Windows drive-relative escape: a `:` (e.g. `C:evil`) makes the
        // joined path absolute under `Path::join`.
        assert!(!is_safe_npm_component("C:evil"));
        assert!(!is_safe_npm_component("c:"));
    }

    /// A PURL whose version is not the one on disk must be skipped, while a
    /// sibling PURL for the installed version is kept.
    #[tokio::test]
    async fn test_find_by_purls_skips_absent_version_keeps_present() {
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("node_modules");
        let foo_dir = nm.join("foo");
        tokio::fs::create_dir_all(&foo_dir).await.unwrap();
        tokio::fs::write(
            foo_dir.join("package.json"),
            r#"{"name": "foo", "version": "1.0.0"}"#,
        )
        .await
        .unwrap();

        let crawler = NpmCrawler::new();
        let result = crawler
            .find_by_purls(
                &nm,
                &[
                    "pkg:npm/foo@1.0.0".to_string(),
                    "pkg:npm/foo@9.9.9".to_string(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:npm/foo@1.0.0"));
        assert!(!result.contains_key("pkg:npm/foo@9.9.9"));
    }
}
