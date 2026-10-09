use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::listing::list_dir_sync;
use super::types::{CrawledPackage, CrawlerOptions};
use crate::formats::cargo::manifest::package_name_version;
use crate::formats::cargo::CargoLock;
use crate::patch::path_safety;
use crate::utils::fs::{is_dir, is_dir_sync, run_blocking};

#[cfg(test)]
mod oracle;

// ---------------------------------------------------------------------------
// CargoCrawler
// ---------------------------------------------------------------------------

/// Cargo/Rust ecosystem crawler for discovering crates in the local
/// vendor directory or the Cargo registry cache (`$CARGO_HOME/registry/src/`).
pub struct CargoCrawler;

impl CargoCrawler {
    /// Create a new `CargoCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get crate source paths based on options.
    ///
    /// In local mode, checks `<cwd>/vendor/` first, then falls back to
    /// `$CARGO_HOME/registry/src/` index directories — but only if the
    /// `cwd` actually contains a `Cargo.toml` or `Cargo.lock` (i.e. is a
    /// Rust project). This prevents scanning the global cargo registry
    /// when patching a non-Rust project.
    ///
    /// In global mode, returns `$CARGO_HOME/registry/src/` index directories
    /// (or the `--global-prefix` override).
    pub async fn get_crate_source_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        Ok(source_roots(options).await.0)
    }

    /// Crawl all discovered crate source directories and return every
    /// package found.
    ///
    /// A `vendor/` tree, a `--global-prefix` and the global registry cache
    /// are walked. The registry cache of a local project with a
    /// `Cargo.lock` is only looked up for the registry packages the lock
    /// resolves ([`lock_scope`], [`locate_crates`]), so a crate another
    /// project left in `$CARGO_HOME/registry/src` is never crawled, and
    /// the crawl no longer reads every cached crate's `Cargo.toml`.
    ///
    /// The scan runs as one blocking-pool task (a registry cache holds
    /// thousands of crates, and one runtime hop per stat and `Cargo.toml`
    /// read dominated the crawl), walked roots in listing order and located
    /// ones in lock order, so the first root to yield a PURL wins. (Reading
    /// the manifests in parallel on the walk pool measured no faster and
    /// cost the pool's thread start-up in system time.)
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let (src_paths, project_registry) = source_roots(options).await;
        if src_paths.is_empty() {
            return Vec::new();
        }
        let scope = if project_registry {
            lock_scope(&options.cwd).await
        } else {
            None
        };

        run_blocking(move || {
            let mut packages = Vec::new();
            let mut seen = HashSet::new();
            for src_path in &src_paths {
                match &scope {
                    Some(locked) => packages.extend(locate_crates(src_path, locked, &mut seen)),
                    None => packages.extend(scan_crate_source(src_path, &mut seen)),
                }
            }
            packages
        })
        .await
    }

    /// Find specific packages by PURL inside a single crate source directory.
    ///
    /// Supports two layouts:
    /// - **Registry**: `<name>-<version>/Cargo.toml`
    /// - **Vendor**: `<name>/Cargo.toml` (version verified from file contents)
    pub async fn find_by_purls(
        &self,
        src_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            if let Some((name, version)) = crate::utils::purl::parse_cargo_purl(purl) {
                let (name, version) = (name.as_ref(), version.as_ref());
                // Both coordinates are joined onto the scanned source root
                // below and the resolved crate dir is patched IN PLACE, so a
                // tampered PURL must not be able to traverse out of the
                // root. Reject before touching the filesystem —
                // `verify_crate_at_path` is no defense, since it compares
                // against the escaped directory's own Cargo.toml.
                if !path_safety::is_safe_name_version(name, version) {
                    continue;
                }

                // Registry layout first (<name>-<version>/), then vendor (<name>/).
                for dir in [
                    src_path.join(format!("{name}-{version}")),
                    src_path.join(name),
                ] {
                    if self.verify_crate_at_path(&dir, name, version).await {
                        result.insert(
                            purl.clone(),
                            CrawledPackage {
                                name: name.to_string(),
                                version: version.to_string(),
                                namespace: None,
                                purl: purl.clone(),
                                path: dir,
                            },
                        );
                        break;
                    }
                }
            }
        }

        Ok(result)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// List subdirectories of `$CARGO_HOME/registry/src/`.
    ///
    /// Each subdirectory corresponds to a registry index
    /// (e.g. `index.crates.io-6f17d22bba15001f/`).
    async fn get_registry_src_paths() -> Vec<PathBuf> {
        let Some(cargo_home) = Self::cargo_home() else {
            return Vec::new();
        };
        let registry_src = cargo_home.join("registry").join("src");

        let mut paths = Vec::new();
        for entry in crate::utils::fs::list_dir_entries(&registry_src).await {
            if crate::utils::fs::entry_is_dir(&entry).await {
                paths.push(registry_src.join(entry.file_name()));
            }
        }
        paths
    }

    /// Verify that a crate directory contains a Cargo.toml with the expected
    /// name and version.
    async fn verify_crate_at_path(&self, path: &Path, name: &str, version: &str) -> bool {
        let cargo_toml_path = path.join("Cargo.toml");
        let content = match crate::utils::fs::read_regular_to_string(&cargo_toml_path).await {
            Ok(c) => c,
            Err(_) => return false,
        };

        match package_name_version(&content) {
            Some((n, v)) => n == name && v == version,
            // Fallback: check directory name
            None => path
                .file_name()
                .and_then(|n| Self::parse_dir_name_version(&n.to_string_lossy()))
                .is_some_and(|(n, v)| n == name && v == version),
        }
    }

    /// Parse a registry directory name into (name, version).
    ///
    /// Registry directories follow the pattern `<crate-name>-<version>`.
    /// Both halves are ambiguous from the bare string: crate names can
    /// contain hyphens (`serde-json`) and even hyphen-then-digit runs
    /// (`sha-1`), while versions can carry hyphenated pre-release / build
    /// metadata (`1.0.0-rc.1`, `0.11.0+wasi-snapshot-preview1`, and the
    /// legal-but-rare numeric pre-release `1.0.0-2`).
    ///
    /// Heuristic: the version begins at a `-` immediately followed by a
    /// digit. Prefer the *first* such boundary whose leading component
    /// (up to the next `-`) is dotted — the common `major.minor.patch`
    /// shape — so `crate-1.0.0-2` keeps `1.0.0-2` as the version rather
    /// than splitting off the trailing `2`. When no candidate version is
    /// dotted (e.g. a single-integer version like `crate-5`), fall back
    /// to the *last* hyphen-before-digit, which keeps hyphenated names
    /// like `sha-1-5` parsing as (`sha-1`, `5`).
    ///
    /// This is only a fallback for when `Cargo.toml` itself cannot be
    /// parsed; for registry crates the manifest is authoritative.
    fn parse_dir_name_version(dir_name: &str) -> Option<(String, String)> {
        let mut first_dotted: Option<usize> = None;
        let mut last_any: Option<usize> = None;
        for (i, _) in dir_name.match_indices('-') {
            let rest = &dir_name[i + 1..];
            if !rest.starts_with(|c: char| c.is_ascii_digit()) {
                continue;
            }
            last_any = Some(i);
            if first_dotted.is_none() {
                let component_end = rest.find('-').unwrap_or(rest.len());
                if rest[..component_end].contains('.') {
                    first_dotted = Some(i);
                }
            }
        }
        let idx = first_dotted.or(last_any)?;
        let name = &dir_name[..idx];
        let version = &dir_name[idx + 1..];
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_string(), version.to_string()))
    }

    /// Get `CARGO_HOME`, defaulting to `$HOME/.cargo` (`None` with no
    /// home). An empty value means unset (the env_non_empty convention) —
    /// `PathBuf::from("")` would otherwise resolve `registry/src` against
    /// the CWD and silently crawl nothing.
    fn cargo_home() -> Option<PathBuf> {
        match std::env::var("CARGO_HOME") {
            Ok(v) if !v.trim().is_empty() => Some(PathBuf::from(v)),
            _ => crate::utils::fs::home_dir().map(|home| home.join(".cargo")),
        }
    }
}

/// [`CargoCrawler::get_crate_source_paths`], and whether those roots are
/// the shared registry cache of a local Cargo project (the roots
/// [`lock_scope`] narrows).
async fn source_roots(options: &CrawlerOptions) -> (Vec<PathBuf>, bool) {
    if options.global || options.global_prefix.is_some() {
        if let Some(ref custom) = options.global_prefix {
            return (vec![custom.clone()], false);
        }
        return (CargoCrawler::get_registry_src_paths().await, false);
    }

    // Local mode is gated on this actually being a Cargo project. A
    // bare `vendor/` directory is NOT cargo-specific — it is the
    // standard layout for Composer (PHP) and Go — so we must confirm
    // a `Cargo.toml`/`Cargo.lock` is present in `cwd` *before*
    // treating `vendor/` (or the global registry) as cargo crate
    // sources. Checking `vendor/` first would misclassify a non-Rust
    // project's vendor tree as cargo sources, violating the contract
    // documented above.
    let has_cargo_toml = tokio::fs::metadata(options.cwd.join("Cargo.toml"))
        .await
        .is_ok();
    let has_cargo_lock = tokio::fs::metadata(options.cwd.join("Cargo.lock"))
        .await
        .is_ok();

    if !(has_cargo_toml || has_cargo_lock) {
        // Not a Cargo project — return empty.
        return (Vec::new(), false);
    }

    // Cargo project: prefer a vendored source tree if present, else
    // fall back to the global registry cache.
    let vendor_dir = options.cwd.join("vendor");
    if is_dir(&vendor_dir).await {
        return (vec![vendor_dir], false);
    }

    (CargoCrawler::get_registry_src_paths().await, true)
}

/// The `(name, version)` of every registry-sourced `[[package]]` in
/// `<cwd>/Cargo.lock` (`LockedPackage::from_registry`), in lock order.
/// `None` when there is no readable lock or it is not TOML: the crawl then
/// keeps walking the whole cache.
async fn lock_scope(cwd: &Path) -> Option<Vec<(String, String)>> {
    let text = crate::utils::fs::read_regular_to_string(&cwd.join("Cargo.lock"))
        .await
        .ok()?;
    let lock = CargoLock::parse(&text).ok()?;
    Some(
        lock.packages()
            .iter()
            .filter(|p| p.from_registry())
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect(),
    )
}

/// Look up each `locked` crate in registry index directory `src_path`
/// (`<name>-<version>/`) instead of walking it. A crate is reported under
/// the identity its `Cargo.toml` declares, as [`scan_crate_source`] would
/// report the same directory, and only when that is the locked
/// `(name, version)`.
fn locate_crates(
    src_path: &Path,
    locked: &[(String, String)],
    seen: &mut HashSet<String>,
) -> Vec<CrawledPackage> {
    let mut results = Vec::new();
    for (name, version) in locked {
        // The lock is project content joined onto the cache root: the
        // same traversal guard `find_by_purls` applies.
        if !path_safety::is_safe_name_version(name, version) {
            continue;
        }
        let dir_name = format!("{name}-{version}");
        let crate_path = src_path.join(&dir_name);
        if !is_dir_sync(&crate_path) {
            continue;
        }
        match read_crate_cargo_toml(&crate_path, &dir_name) {
            Some((n, v)) if n == *name && v == *version => {}
            _ => continue,
        }
        let purl = crate::utils::purl::build_cargo_purl(name, version);
        if !seen.insert(purl.clone()) {
            continue;
        }
        results.push(CrawledPackage {
            name: name.clone(),
            version: version.clone(),
            namespace: None,
            purl,
            path: crate_path,
        });
    }
    results
}

/// Scan a crate source directory (either a registry index directory or
/// a vendor directory) and return all valid crate packages found.
fn scan_crate_source(src_path: &Path, seen: &mut HashSet<String>) -> Vec<CrawledPackage> {
    let mut results = Vec::new();
    for entry in list_dir_sync(src_path) {
        if !entry.is_dir(src_path) {
            continue;
        }

        let dir_name_str = entry.name.to_string_lossy();

        // Skip hidden directories
        if dir_name_str.starts_with('.') {
            continue;
        }

        let crate_path = src_path.join(&*dir_name_str);
        let Some((name, version)) = read_crate_cargo_toml(&crate_path, &dir_name_str) else {
            continue;
        };
        let purl = crate::utils::purl::build_cargo_purl(&name, &version);
        if !seen.insert(purl.clone()) {
            continue;
        }
        results.push(CrawledPackage {
            name,
            version,
            namespace: None,
            purl,
            path: crate_path,
        });
    }
    results
}

/// Read `Cargo.toml` from a crate directory and return its name and
/// version. Falls back to parsing name+version from the directory name
/// when the Cargo.toml has `version.workspace = true`.
fn read_crate_cargo_toml(crate_path: &Path, dir_name: &str) -> Option<(String, String)> {
    let cargo_toml_path = crate_path.join("Cargo.toml");
    let content = crate::utils::fs::read_regular_to_string_sync(&cargo_toml_path).ok()?;

    // Fallback: parse directory name as <name>-<version>
    package_name_version(&content)
        .or_else(|| CargoCrawler::parse_dir_name_version(dir_name))
}

impl Default for CargoCrawler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dir_name_version() {
        assert_eq!(
            CargoCrawler::parse_dir_name_version("serde-1.0.200"),
            Some(("serde".to_string(), "1.0.200".to_string()))
        );
        assert_eq!(
            CargoCrawler::parse_dir_name_version("serde-json-1.0.120"),
            Some(("serde-json".to_string(), "1.0.120".to_string()))
        );
        assert_eq!(
            CargoCrawler::parse_dir_name_version("tokio-1.38.0"),
            Some(("tokio".to_string(), "1.38.0".to_string()))
        );
        assert!(CargoCrawler::parse_dir_name_version("no-version-here").is_none());
        assert!(CargoCrawler::parse_dir_name_version("noversion").is_none());
    }

    #[tokio::test]
    async fn test_find_by_purls_registry_layout() {
        let dir = tempfile::tempdir().unwrap();
        let serde_dir = dir.path().join("serde-1.0.200");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let purls = vec![
            "pkg:cargo/serde@1.0.200".to_string(),
            "pkg:cargo/tokio@1.38.0".to_string(),
        ];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:cargo/serde@1.0.200"));
        assert!(!result.contains_key("pkg:cargo/tokio@1.38.0"));
    }

    #[tokio::test]
    async fn test_find_by_purls_vendor_layout() {
        let dir = tempfile::tempdir().unwrap();
        let serde_dir = dir.path().join("serde");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let purls = vec!["pkg:cargo/serde@1.0.200".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:cargo/serde@1.0.200"));
    }

    #[tokio::test]
    async fn test_crawl_all_tempdir() {
        let dir = tempfile::tempdir().unwrap();

        // Create fake crate directories
        let serde_dir = dir.path().join("serde-1.0.200");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        let tokio_dir = dir.path().join("tokio-1.38.0");
        tokio::fs::create_dir_all(&tokio_dir).await.unwrap();
        tokio::fs::write(
            tokio_dir.join("Cargo.toml"),
            "[package]\nname = \"tokio\"\nversion = \"1.38.0\"\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:cargo/serde@1.0.200"));
        assert!(purls.contains("pkg:cargo/tokio@1.38.0"));
    }

    #[tokio::test]
    async fn test_crawl_all_deduplication() {
        let dir = tempfile::tempdir().unwrap();

        // Create two directories that would resolve to the same PURL
        let dir1 = dir.path().join("serde-1.0.200");
        tokio::fs::create_dir_all(&dir1).await.unwrap();
        tokio::fs::write(
            dir1.join("Cargo.toml"),
            "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        // This would be found if we scan the parent twice
        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:cargo/serde@1.0.200");
    }

    #[tokio::test]
    async fn test_crawl_workspace_version_fallback() {
        let dir = tempfile::tempdir().unwrap();

        // Create a crate with workspace version — should fall back to dir name parsing
        let crate_dir = dir.path().join("my-crate-0.5.0");
        tokio::fs::create_dir_all(&crate_dir).await.unwrap();
        tokio::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"my-crate\"\nversion.workspace = true\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:cargo/my-crate@0.5.0");
    }

    #[tokio::test]
    async fn test_vendor_layout_via_get_crate_source_paths() {
        let dir = tempfile::tempdir().unwrap();
        let vendor = dir.path().join("vendor");
        tokio::fs::create_dir_all(&vendor).await.unwrap();

        let serde_dir = vendor.join("serde");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        // A cargo-vendored project always carries a root Cargo.toml; the
        // vendor tree is only honored once we've confirmed this is a Rust
        // project.
        tokio::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let paths = crawler.get_crate_source_paths(&options).await.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vendor);
    }

    /// Regression: a `vendor/` directory in a *non-Rust* project (here a
    /// stand-in for Composer/Go, which both use `vendor/`) must NOT be
    /// claimed by the cargo crawler. Without a `Cargo.toml`/`Cargo.lock`
    /// in `cwd` the crawler is required to return no paths — otherwise it
    /// would walk an unrelated ecosystem's vendor tree as cargo sources.
    #[tokio::test]
    async fn test_vendor_dir_in_non_cargo_project_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let vendor = dir.path().join("vendor");
        // Mimic a Composer layout: vendor/<org>/<pkg>/composer.json
        let pkg = vendor.join("monolog").join("monolog");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        tokio::fs::write(pkg.join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let paths = crawler.get_crate_source_paths(&options).await.unwrap();
        assert!(
            paths.is_empty(),
            "non-Rust project's vendor/ must not be scanned as cargo sources, got {paths:?}"
        );
    }

    /// A `Cargo.lock` alone (no `Cargo.toml`) is still a Rust project, so
    /// the vendor tree should be honored.
    #[tokio::test]
    async fn test_vendor_dir_honored_with_only_cargo_lock() {
        let dir = tempfile::tempdir().unwrap();
        let vendor = dir.path().join("vendor");
        tokio::fs::create_dir_all(&vendor).await.unwrap();
        tokio::fs::write(dir.path().join("Cargo.lock"), "version = 3\n")
            .await
            .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let paths = crawler.get_crate_source_paths(&options).await.unwrap();
        assert_eq!(paths, vec![vendor]);
    }

    /// `--global-prefix` must override the local-mode Cargo-project gate:
    /// an explicit prefix is honored regardless of whether `cwd` looks
    /// like a Rust project.
    #[tokio::test]
    async fn test_global_prefix_bypasses_cargo_project_gate() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("custom-registry");
        tokio::fs::create_dir_all(&prefix).await.unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(), // no Cargo.toml/Cargo.lock here
            global: false,
            global_prefix: Some(prefix.clone()),
        };

        let paths = crawler.get_crate_source_paths(&options).await.unwrap();
        assert_eq!(paths, vec![prefix]);
    }

    /// Dir name `"-1.0.0"` — the loop finds `i=0` (first `-` is at index 0,
    /// followed by `1`), split_idx = Some(0), name slice = empty string.
    /// The empty-name guard at the bottom of parse_dir_name_version must
    /// reject this — the function is defensive against malformed inputs
    /// even though no normal cargo registry would produce such a name.
    #[test]
    fn test_parse_dir_name_version_empty_name_guard() {
        assert_eq!(CargoCrawler::parse_dir_name_version("-1.0.0"), None);
    }

    // --- regression: table-header parsing tolerance --------------------

    /// A `[package]` header with a trailing inline comment is valid TOML.
    /// The parser must still recognize it and read name/version — a
    /// too-strict `== "[package]"` would drop the crate, and in the
    /// vendor layout (dir name carries no version) that crate would
    /// become undiscoverable.
    #[test]
    fn test_parse_cargo_toml_header_with_inline_comment() {
        let content = r#"
[package] # the main package
name = "serde"
version = "1.0.200"
"#;
        let (name, version) = package_name_version(content).unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.200");
    }

    #[test]
    fn test_parse_cargo_toml_header_with_inner_spaces() {
        let content = "[ package ]\nname = \"tokio\"\nversion = \"1.38.0\"\n";
        let (name, version) = package_name_version(content).unwrap();
        assert_eq!(name, "tokio");
        assert_eq!(version, "1.38.0");
    }

    /// A `[package.metadata]` subtable still terminates bare-key scanning.
    #[test]
    fn test_parse_cargo_toml_stops_at_package_subtable() {
        let content = r#"
[package]
name = "foo"

[package.metadata.docs.rs]
version = "fake"
"#;
        // `version` lives under the metadata subtable, not [package].
        assert!(package_name_version(content).is_none());
    }

    // --- regression: single-quoted (literal) string values -------------

    /// TOML literal strings use single quotes and are valid in a
    /// `Cargo.toml`. The reader must read `name`/`version` from
    /// them just as it does from basic (double-quoted) strings.
    #[test]
    fn test_parse_cargo_toml_single_quoted_values() {
        let content = "[package]\nname = 'serde'\nversion = '1.0.200'\n";
        let (name, version) = package_name_version(content).unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.200");
    }

    /// A manifest may legally mix the two string flavors.
    #[test]
    fn test_parse_cargo_toml_mixed_quote_values() {
        let content = "[package]\nname = 'tokio'\nversion = \"1.38.0\"\n";
        let (name, version) = package_name_version(content).unwrap();
        assert_eq!(name, "tokio");
        assert_eq!(version, "1.38.0");
    }

    /// A `#` inside the closing-quote pair is part of the value; a
    /// trailing comment after the literal string is ignored. (The `'`
    /// flavor must find its matching `'`, not a stray `"`.)
    #[test]
    fn test_parse_cargo_toml_single_quoted_with_comment() {
        let content = "[package]\nname = 'serde' # the lib\nversion = '1.0.200'\n";
        let (name, version) = package_name_version(content).unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.200");
    }

    /// `version.workspace = true` must still short-circuit to `None`
    /// regardless of the quote-handling change (no quotes are involved).
    #[test]
    fn test_parse_cargo_toml_workspace_still_none_after_quote_fix() {
        let content = "[package]\nname = 'my-crate'\nversion.workspace = true\n";
        assert!(package_name_version(content).is_none());
    }

    /// End-to-end: a vendored crate whose `Cargo.toml` uses single-quoted
    /// values must still be located by `find_by_purls`. The vendor
    /// directory name (`serde`) carries no version, so the version can
    /// only come from the manifest — this is the layout where the
    /// double-quote-only bug made the crate undiscoverable.
    #[tokio::test]
    async fn test_find_by_purls_vendor_single_quoted_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let serde_dir = dir.path().join("serde");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package]\nname = 'serde'\nversion = '1.0.200'\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let purls = vec!["pkg:cargo/serde@1.0.200".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:cargo/serde@1.0.200"));
        assert_eq!(result["pkg:cargo/serde@1.0.200"].version, "1.0.200");
    }

    /// End-to-end via `crawl_all`: a single-quoted registry manifest is
    /// parsed from the manifest (not just the dir name), proving the
    /// value is read rather than recovered by the dir-name fallback.
    #[tokio::test]
    async fn test_crawl_all_single_quoted_manifest() {
        let dir = tempfile::tempdir().unwrap();
        // Dir name deliberately disagrees with the manifest version so a
        // pass can only come from reading the single-quoted manifest.
        let crate_dir = dir.path().join("serde-9.9.9");
        tokio::fs::create_dir_all(&crate_dir).await.unwrap();
        tokio::fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = 'serde'\nversion = '1.0.200'\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:cargo/serde@1.0.200");
    }

    // --- regression: dir-name version splitting ------------------------

    /// A numeric pre-release segment (legal SemVer) must stay part of the
    /// version; a "last hyphen-before-digit" heuristic would split
    /// `mycrate-1.0.0-2` into (`mycrate-1.0.0`, `2`).
    #[test]
    fn test_parse_dir_name_version_numeric_prerelease() {
        assert_eq!(
            CargoCrawler::parse_dir_name_version("mycrate-1.0.0-2"),
            Some(("mycrate".to_string(), "1.0.0-2".to_string()))
        );
    }

    #[test]
    fn test_parse_dir_name_version_alpha_prerelease() {
        assert_eq!(
            CargoCrawler::parse_dir_name_version("crate-1.0.0-rc.1"),
            Some(("crate".to_string(), "1.0.0-rc.1".to_string()))
        );
    }

    #[test]
    fn test_parse_dir_name_version_build_metadata() {
        assert_eq!(
            CargoCrawler::parse_dir_name_version("wasi-0.11.0+wasi-snapshot-preview1"),
            Some((
                "wasi".to_string(),
                "0.11.0+wasi-snapshot-preview1".to_string()
            ))
        );
    }

    /// Crate name that itself ends in a hyphen-digit run (`sha-1`) must not
    /// be split inside the name when the version is dotted.
    #[test]
    fn test_parse_dir_name_version_hyphen_digit_name() {
        assert_eq!(
            CargoCrawler::parse_dir_name_version("sha-1-1.0.0"),
            Some(("sha-1".to_string(), "1.0.0".to_string()))
        );
    }

    /// Dot-less single-integer version falls back to the last
    /// hyphen-before-digit, keeping hyphenated names intact.
    #[test]
    fn test_parse_dir_name_version_dotless_fallback() {
        assert_eq!(
            CargoCrawler::parse_dir_name_version("crate-5"),
            Some(("crate".to_string(), "5".to_string()))
        );
        assert_eq!(
            CargoCrawler::parse_dir_name_version("sha-1-5"),
            Some(("sha-1".to_string(), "5".to_string()))
        );
    }

    // --- regression: header-comment tolerance end-to-end ---------------

    /// A vendored crate whose Cargo.toml header carries an inline comment
    /// must still be found by `find_by_purls`. The vendor layout has no
    /// version in the directory name, so the version can only come from
    /// parsing the manifest — exercising the header-tolerance fix.
    #[tokio::test]
    async fn test_find_by_purls_vendor_header_comment() {
        let dir = tempfile::tempdir().unwrap();
        let serde_dir = dir.path().join("serde");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package] # serde\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let purls = vec!["pkg:cargo/serde@1.0.200".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:cargo/serde@1.0.200"));
    }

    /// SECURITY regression: a tampered manifest PURL whose name or version
    /// carries a `..`/separator must NOT resolve to a directory outside the
    /// scanned crate source root. `find_by_purls` joins the PURL-derived
    /// name/version onto `src_path` (`<name>-<version>` registry dirs,
    /// bare `<name>` vendor dirs) and the resolved directory is patched IN
    /// PLACE — so an escape means an arbitrary out-of-tree write.
    /// `verify_crate_at_path` is no defense: it compares against the
    /// escaped directory's own `Cargo.toml`, which the attacker controls.
    /// Twin of the nuget/maven/go/deno/npm/ruby crawler coordinate guards.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_coordinate() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("registry");
        tokio::fs::create_dir_all(&src).await.unwrap();

        // An out-of-tree crate dir whose Cargo.toml matches the traversal
        // PURL's coordinates, so the only thing standing between the
        // attacker and a match is the coordinate guard.
        let escaped = root.path().join("evil");
        tokio::fs::create_dir_all(&escaped).await.unwrap();
        tokio::fs::write(
            escaped.join("Cargo.toml"),
            "[package]\nname = \"../evil\"\nversion = \"1.0.0\"\n",
        )
        .await
        .unwrap();

        let purls = vec![
            // name traversal, vendor-layout probe: registry/../evil
            "pkg:cargo/../evil@1.0.0".to_string(),
            // version traversal (joined into the registry-layout dir name)
            "pkg:cargo/pwn@../../evil".to_string(),
        ];

        let crawler = CargoCrawler::new();
        let result = crawler.find_by_purls(&src, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "traversal PURL must not resolve to an out-of-tree directory, got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_crawl_all_registry_header_comment() {
        let dir = tempfile::tempdir().unwrap();
        let serde_dir = dir.path().join("serde-1.0.200");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package]   # main\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:cargo/serde@1.0.200");
    }

    // ── Project-mode registry scope (#595) ──────────────────────────────

    mod lock_scope {
        use super::*;
        use crate::crawlers::oracle_support::{mkdir, write};

        const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

        /// Points `CARGO_HOME` at a temp dir for one test, restoring it on drop.
        struct CargoHome(Option<std::ffi::OsString>);
        impl CargoHome {
            fn set(path: &Path) -> Self {
                let prev = std::env::var_os("CARGO_HOME");
                std::env::set_var("CARGO_HOME", path);
                CargoHome(prev)
            }
        }
        impl Drop for CargoHome {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("CARGO_HOME", v),
                    None => std::env::remove_var("CARGO_HOME"),
                }
            }
        }

        fn stage(src: &Path, name: &str, version: &str) {
            write(
                &src.join(format!("{name}-{version}")).join("Cargo.toml"),
                &format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
            );
        }

        fn lock(entries: &[(&str, &str, Option<&str>)]) -> String {
            let mut out = String::from("version = 3\n");
            for (name, version, source) in entries {
                out.push_str(&format!(
                    "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n"
                ));
                if let Some(source) = source {
                    out.push_str(&format!("source = \"{source}\"\n"));
                }
            }
            out
        }

        /// A cargo home with two index dirs; the project's own crates and
        /// crates other projects left behind are cached side by side.
        fn cache(home: &Path) -> (PathBuf, PathBuf) {
            let src = home.join("registry").join("src");
            let crates_io = src.join("index.crates.io-6f17d22bba15001f");
            let other = src.join("example.com-0123456789abcdef");
            stage(&crates_io, "serde", "1.0.200");
            stage(&crates_io, "unrelated", "0.1.0");
            stage(&crates_io, "serde", "1.0.100");
            stage(&other, "tokio", "1.38.0");
            stage(&other, "unrelated-too", "2.0.0");
            (crates_io, other)
        }

        fn local(cwd: &Path) -> CrawlerOptions {
            CrawlerOptions {
                cwd: cwd.to_path_buf(),
                global: false,
                global_prefix: None,
            }
        }

        fn purls(pkgs: &[CrawledPackage]) -> Vec<&str> {
            let mut out: Vec<&str> = pkgs.iter().map(|p| p.purl.as_str()).collect();
            out.sort_unstable();
            out
        }

        /// The fix: a locked project's crawl reports only the registry
        /// crates its `Cargo.lock` resolves, from whichever index dir holds
        /// them; path, git and unsourced entries are never looked up.
        #[tokio::test]
        #[serial_test::serial]
        async fn locked_project_crawls_only_its_locked_registry_crates() {
            let home = tempfile::tempdir().unwrap();
            let (crates_io, other) = cache(home.path());
            stage(&crates_io, "gitdep", "0.3.0");
            stage(&crates_io, "member", "0.1.0");
            let _g = CargoHome::set(home.path());

            let project = tempfile::tempdir().unwrap();
            write(
                &project.path().join("Cargo.toml"),
                "[package]\nname = \"member\"\n",
            );
            write(
                &project.path().join("Cargo.lock"),
                &lock(&[
                    ("member", "0.1.0", None),
                    ("serde", "1.0.200", Some(CRATES_IO)),
                    ("tokio", "1.38.0", Some("sparse+https://example.com/index/")),
                    ("gitdep", "0.3.0", Some("git+https://example.com/g#abc")),
                    ("missing", "9.9.9", Some(CRATES_IO)),
                ]),
            );

            let pkgs = CargoCrawler::new().crawl_all(&local(project.path())).await;
            assert_eq!(
                purls(&pkgs),
                ["pkg:cargo/serde@1.0.200", "pkg:cargo/tokio@1.38.0"]
            );
            let tokio = pkgs.iter().find(|p| p.name == "tokio").unwrap();
            assert_eq!(tokio.path, other.join("tokio-1.38.0"));
            assert_eq!(tokio.version, "1.38.0");
            assert_eq!(tokio.namespace, None);

            // `get_crate_source_paths` (agent apply, VEX) still names every
            // index dir: only the crawl is scoped.
            let mut roots = CargoCrawler::new()
                .get_crate_source_paths(&local(project.path()))
                .await
                .unwrap();
            roots.sort();
            assert_eq!(roots, vec![other, crates_io]);
        }

        /// A cached dir whose manifest names another crate or version, or
        /// a lock coordinate that would leave the index dir, is not reported.
        #[tokio::test]
        #[serial_test::serial]
        async fn located_crate_must_declare_the_locked_identity() {
            let home = tempfile::tempdir().unwrap();
            let (crates_io, _) = cache(home.path());
            write(
                &crates_io.join("liar-1.0.0").join("Cargo.toml"),
                "[package]\nname = \"liar\"\nversion = \"2.0.0\"\n",
            );
            stage(home.path(), "escape", "1.0.0");
            let _g = CargoHome::set(home.path());

            let project = tempfile::tempdir().unwrap();
            write(
                &project.path().join("Cargo.lock"),
                &lock(&[
                    ("liar", "1.0.0", Some(CRATES_IO)),
                    ("..", "x", Some(CRATES_IO)),
                    ("../../../escape", "1.0.0", Some(CRATES_IO)),
                    ("serde", "1.0.200", Some(CRATES_IO)),
                ]),
            );

            let pkgs = CargoCrawler::new().crawl_all(&local(project.path())).await;
            assert_eq!(purls(&pkgs), ["pkg:cargo/serde@1.0.200"]);
        }

        /// Without a usable lock (none, or not TOML) the cache is walked
        /// as before; so is a `vendor/` tree and the global cache.
        #[tokio::test]
        #[serial_test::serial]
        async fn walks_without_a_lock_for_vendor_and_globally() {
            let home = tempfile::tempdir().unwrap();
            cache(home.path());
            let _g = CargoHome::set(home.path());
            let every = [
                "pkg:cargo/serde@1.0.100",
                "pkg:cargo/serde@1.0.200",
                "pkg:cargo/tokio@1.38.0",
                "pkg:cargo/unrelated-too@2.0.0",
                "pkg:cargo/unrelated@0.1.0",
            ];
            let crawler = CargoCrawler::new();

            let no_lock = tempfile::tempdir().unwrap();
            write(&no_lock.path().join("Cargo.toml"), "[workspace]\n");
            assert_eq!(
                purls(&crawler.crawl_all(&local(no_lock.path())).await),
                every
            );

            let bad_lock = tempfile::tempdir().unwrap();
            write(&bad_lock.path().join("Cargo.lock"), "[[package]\nname = ");
            assert_eq!(
                purls(&crawler.crawl_all(&local(bad_lock.path())).await),
                every
            );

            let locked = lock(&[("serde", "1.0.200", Some(CRATES_IO))]);
            let global = tempfile::tempdir().unwrap();
            write(&global.path().join("Cargo.lock"), &locked);
            let options = CrawlerOptions {
                global: true,
                ..local(global.path())
            };
            assert_eq!(purls(&crawler.crawl_all(&options).await), every);

            let vendored = tempfile::tempdir().unwrap();
            write(&vendored.path().join("Cargo.lock"), &locked);
            stage(&vendored.path().join("vendor"), "unlocked", "1.0.0");
            mkdir(&vendored.path().join("vendor").join(".hidden"));
            assert_eq!(
                purls(&crawler.crawl_all(&local(vendored.path())).await),
                ["pkg:cargo/unlocked@1.0.0"]
            );
        }

        /// A lock with no registry packages resolves nothing from the cache.
        #[tokio::test]
        #[serial_test::serial]
        async fn lock_without_registry_packages_crawls_nothing() {
            let home = tempfile::tempdir().unwrap();
            cache(home.path());
            let _g = CargoHome::set(home.path());
            let project = tempfile::tempdir().unwrap();
            write(
                &project.path().join("Cargo.lock"),
                &lock(&[("member", "0.1.0", None)]),
            );
            assert!(CargoCrawler::new()
                .crawl_all(&local(project.path()))
                .await
                .is_empty());
        }
    }

    // ── Equivalence with the per-call async scan (oracle) ─────────────

    mod equivalence {
        use super::super::oracle::LegacyCargoCrawler;
        use super::*;
        use crate::crawlers::oracle_support::{mkdir, rows, symlink, write, PermGuard, Rng};

        const NAMES: &[&str] = &["serde", "serde-json", "sha-1", "tokio", "dup", "a_b"];
        const VERSIONS: &[&str] = &["1.0.0", "1.0.0-rc.1", "0.2.3", "5", "1.0.0+build"];

        fn manifest(rng: &mut Rng, name: &str, version: &str) -> String {
            match rng.below(8) {
                0 => format!("[package]\nname = \"{name}\"\nversion.workspace = true\n"),
                1 => format!("[package]\nname = '{name}'\nversion = '{version}'\n"),
                2 => "[dependencies]\nfoo = \"1\"\n".to_string(),
                3 => format!("[ package ] # c\nname = \"{name}\"\n\n[lib]\nversion = \"9\"\n"),
                4 => format!("[package]\nversion = \"{version}\"\nname = \"other\"\n"),
                _ => format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\n"),
            }
        }

        fn tree(rng: &mut Rng, root: &Path, outside: &Path, perms: &mut PermGuard) {
            mkdir(root);
            for i in 0..rng.below(24) {
                let name = rng.pick(NAMES);
                let version = rng.pick(VERSIONS);
                let dir_name = match rng.below(4) {
                    0 => name.to_string(),
                    1 => format!(".{name}-{version}"),
                    _ => format!("{name}-{version}"),
                };
                let dir = root.join(&dir_name);
                match rng.below(14) {
                    0 => write(&dir, "not a dir"),
                    1 => {
                        let target = outside.join(format!("t{i}-{}", rng.next()));
                        if rng.chance(70) {
                            write(&target.join("Cargo.toml"), &manifest(rng, name, version));
                        }
                        symlink(&target, &dir);
                    }
                    2 => mkdir(&dir.join("Cargo.toml")),
                    3 => {
                        mkdir(&dir);
                        let _ =
                            std::fs::write(dir.join("Cargo.toml"), b"[package]\nname = \"\xff\"\n");
                    }
                    4 => {
                        write(&dir.join("Cargo.toml"), &manifest(rng, name, version));
                        perms.plan(&dir, 0o000);
                    }
                    5 => mkdir(&dir),
                    _ => write(&dir.join("Cargo.toml"), &manifest(rng, name, version)),
                }
            }
        }

        #[tokio::test]
        async fn randomized_sources_match_the_async_oracle() {
            let mut total = 0;
            for seed in 0..64u64 {
                let tmp = tempfile::tempdir().unwrap();
                let mut perms = PermGuard::default();
                let mut rng = Rng::new(seed);
                let root = tmp.path().join("src");
                tree(&mut rng, &root, &tmp.path().join("outside"), &mut perms);
                perms.apply();
                let options = CrawlerOptions {
                    cwd: tmp.path().to_path_buf(),
                    global: false,
                    global_prefix: Some(root.clone()),
                };
                let new = CargoCrawler::new().crawl_all(&options).await;
                let old = LegacyCargoCrawler::crawl_all(&options).await;
                assert_eq!(rows(&new), rows(&old), "seed {seed}");
                total += old.len();
            }
            assert!(total > 200, "vacuous fixtures: {total}");
        }

        /// Local mode: a Cargo project with a `vendor/` tree.
        #[tokio::test]
        async fn vendor_tree_matches_the_async_oracle() {
            let tmp = tempfile::tempdir().unwrap();
            let mut perms = PermGuard::default();
            let mut rng = Rng::new(7);
            write(&tmp.path().join("Cargo.toml"), "[workspace]\n");
            tree(
                &mut rng,
                &tmp.path().join("vendor"),
                &tmp.path().join("outside"),
                &mut perms,
            );
            perms.apply();
            let options = CrawlerOptions {
                cwd: tmp.path().to_path_buf(),
                global: false,
                global_prefix: None,
            };
            let new = CargoCrawler::new().crawl_all(&options).await;
            let old = LegacyCargoCrawler::crawl_all(&options).await;
            assert!(!old.is_empty());
            assert_eq!(rows(&new), rows(&old));
        }
    }

    /// mkfifo(2) directly (no child process; spawning `mkfifo` flakes
    /// under heavy parallel load).
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// On timeout the open is wedged in a blocking-pool thread that the
    /// runtime waits for on shutdown; connecting a writer releases it so
    /// the test FAILS instead of hanging the whole suite.
    #[cfg(unix)]
    async fn within_deadline<F: std::future::Future>(fifo: &Path, what: &str, fut: F) -> F::Output {
        match tokio::time::timeout(std::time::Duration::from_secs(5), fut).await {
            Ok(out) => out,
            Err(_) => {
                // O_NONBLOCK: with no reader blocked on the FIFO (the
                // timeout had another cause) a blocking writer open would
                // itself hang; non-blocking it just fails with ENXIO.
                use std::os::unix::fs::OpenOptionsExt;
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(fifo);
                panic!("{what} must not block on a FIFO at {}", fifo.display());
            }
        }
    }

    /// Regression (#592): a FIFO at `vendor/<crate>/Cargo.toml` in the
    /// project tree used to wedge `crawl_all` (blocking-pool
    /// `read_crate_cargo_toml`) and `find_by_purls` (`verify_crate_at_path`)
    /// in open(2). Both now go through the FIFO-safe reader and skip the
    /// unreadable crate, exactly like any other unreadable manifest.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_crate_manifest_is_skipped_not_blocked_on() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
        )
        .await
        .unwrap();
        let vendor = dir.path().join("vendor");
        let left = vendor.join("left-1.0.0");
        tokio::fs::create_dir_all(&left).await.unwrap();
        let fifo = left.join("Cargo.toml");
        make_fifo(&fifo);
        // A readable crate beside the FIFO proves the crawl continues.
        let serde_dir = vendor.join("serde");
        tokio::fs::create_dir_all(&serde_dir).await.unwrap();
        tokio::fs::write(
            serde_dir.join("Cargo.toml"),
            "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
        )
        .await
        .unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let packages = within_deadline(&fifo, "crawl_all", crawler.crawl_all(&options)).await;
        let purls: Vec<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(purls, vec!["pkg:cargo/serde@1.0.200"]);

        let found = within_deadline(
            &fifo,
            "find_by_purls",
            crawler.find_by_purls(
                &vendor,
                &[
                    "pkg:cargo/left@1.0.0".to_string(),
                    "pkg:cargo/serde@1.0.200".to_string(),
                ],
            ),
        )
        .await
        .unwrap();
        assert!(!found.contains_key("pkg:cargo/left@1.0.0"));
        assert!(found.contains_key("pkg:cargo/serde@1.0.200"));
    }
}
