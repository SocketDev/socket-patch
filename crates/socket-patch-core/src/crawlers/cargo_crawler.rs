use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};

// ---------------------------------------------------------------------------
// Cargo.toml minimal parser
// ---------------------------------------------------------------------------

/// Parse `name` and `version` from a `Cargo.toml` `[package]` section.
///
/// Uses a simple line-based parser — no TOML crate dependency.
/// Handles `name = "..."` and `version = "..."` within the `[package]` table.
/// Returns `None` if `version.workspace = true` or fields are missing.
pub fn parse_cargo_toml_name_version(content: &str) -> Option<(String, String)> {
    let mut in_package = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        // Track table headers. Use `parse_table_header` rather than an
        // exact `== "[package]"` comparison so a header carrying a
        // trailing inline comment (`[package] # ...`) or whitespace
        // inside the brackets (`[ package ]`) is still recognized —
        // both are valid TOML and a too-strict match would silently
        // drop the package's name/version.
        if trimmed.starts_with('[') {
            if let Some(table) = parse_table_header(trimmed) {
                if table == "package" {
                    in_package = true;
                } else if in_package {
                    // We left the [package] section (a sibling table or
                    // a `[package.*]` subtable — bare keys can no longer
                    // follow per TOML, so stop scanning).
                    break;
                }
            }
            continue;
        }

        if !in_package {
            continue;
        }

        if let Some(val) = extract_string_value(trimmed, "name") {
            name = Some(val);
        } else if let Some(val) = extract_string_value(trimmed, "version") {
            version = Some(val);
        } else if trimmed.starts_with("version") && trimmed.contains("workspace") {
            // version.workspace = true — cannot determine version from this file
            return None;
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

/// Extract the table name from a TOML header line.
///
/// `[package]` -> `Some("package")`, `[package] # comment` ->
/// `Some("package")`, `[ package ]` -> `Some("package")`. Returns
/// `None` for a line that is not a `[...]` header. Anything after the
/// closing `]` (typically an inline comment) is ignored.
fn parse_table_header(line: &str) -> Option<&str> {
    let rest = line.strip_prefix('[')?;
    let end = rest.find(']')?;
    Some(rest[..end].trim())
}

/// Extract a quoted string value from a `key = "value"` line.
fn extract_string_value(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

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
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(Self::get_registry_src_paths().await);
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
            return Ok(Vec::new());
        }

        // Cargo project: prefer a vendored source tree if present, else
        // fall back to the global registry cache.
        let vendor_dir = options.cwd.join("vendor");
        if is_dir(&vendor_dir).await {
            return Ok(vec![vendor_dir]);
        }

        Ok(Self::get_registry_src_paths().await)
    }

    /// Crawl all discovered crate source directories and return every
    /// package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let src_paths = self
            .get_crate_source_paths(options)
            .await
            .unwrap_or_default();

        for src_path in &src_paths {
            let found = self.scan_crate_source(src_path, &mut seen).await;
            packages.extend(found);
        }

        packages
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
                // Try registry layout: <name>-<version>/
                let registry_dir = src_path.join(format!("{name}-{version}"));
                if self
                    .verify_crate_at_path(&registry_dir, name, version)
                    .await
                {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: None,
                            purl: purl.clone(),
                            path: registry_dir,
                        },
                    );
                    continue;
                }

                // Try vendor layout: <name>/
                let vendor_dir = src_path.join(name);
                if self.verify_crate_at_path(&vendor_dir, name, version).await {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: None,
                            purl: purl.clone(),
                            path: vendor_dir,
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

    /// List subdirectories of `$CARGO_HOME/registry/src/`.
    ///
    /// Each subdirectory corresponds to a registry index
    /// (e.g. `index.crates.io-6f17d22bba15001f/`).
    async fn get_registry_src_paths() -> Vec<PathBuf> {
        let cargo_home = Self::cargo_home();
        let registry_src = cargo_home.join("registry").join("src");

        let mut paths = Vec::new();
        for entry in crate::utils::fs::list_dir_entries(&registry_src).await {
            if crate::utils::fs::entry_is_dir(&entry).await {
                paths.push(registry_src.join(entry.file_name()));
            }
        }
        paths
    }

    /// Scan a crate source directory (either a registry index directory or
    /// a vendor directory) and return all valid crate packages found.
    async fn scan_crate_source(
        &self,
        src_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for entry in crate::utils::fs::list_dir_entries(src_path).await {
            if !crate::utils::fs::entry_is_dir(&entry).await {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            // Skip hidden directories
            if dir_name_str.starts_with('.') {
                continue;
            }

            let crate_path = src_path.join(&*dir_name_str);
            if let Some(pkg) = self
                .read_crate_cargo_toml(&crate_path, &dir_name_str, seen)
                .await
            {
                results.push(pkg);
            }
        }

        results
    }

    /// Read `Cargo.toml` from a crate directory, returning a `CrawledPackage`
    /// if valid. Falls back to parsing name+version from the directory name
    /// when the Cargo.toml has `version.workspace = true`.
    async fn read_crate_cargo_toml(
        &self,
        crate_path: &Path,
        dir_name: &str,
        seen: &mut HashSet<String>,
    ) -> Option<CrawledPackage> {
        let cargo_toml_path = crate_path.join("Cargo.toml");
        let content = tokio::fs::read_to_string(&cargo_toml_path).await.ok()?;

        let (name, version) = match parse_cargo_toml_name_version(&content) {
            Some(nv) => nv,
            None => {
                // Fallback: parse directory name as <name>-<version>
                Self::parse_dir_name_version(dir_name)?
            }
        };

        let purl = crate::utils::purl::build_cargo_purl(&name, &version);

        if seen.contains(&purl) {
            return None;
        }
        seen.insert(purl.clone());

        Some(CrawledPackage {
            name,
            version,
            namespace: None,
            purl,
            path: crate_path.to_path_buf(),
        })
    }

    /// Verify that a crate directory contains a Cargo.toml with the expected
    /// name and version.
    async fn verify_crate_at_path(&self, path: &Path, name: &str, version: &str) -> bool {
        let cargo_toml_path = path.join("Cargo.toml");
        let content = match tokio::fs::read_to_string(&cargo_toml_path).await {
            Ok(c) => c,
            Err(_) => return false,
        };

        match parse_cargo_toml_name_version(&content) {
            Some((n, v)) => n == name && v == version,
            None => {
                // Fallback: check directory name
                let dir_name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if let Some((parsed_name, parsed_version)) = Self::parse_dir_name_version(&dir_name)
                {
                    parsed_name == name && parsed_version == version
                } else {
                    false
                }
            }
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
    pub(crate) fn parse_dir_name_version(dir_name: &str) -> Option<(String, String)> {
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

    /// Get `CARGO_HOME`, defaulting to `$HOME/.cargo`.
    fn cargo_home() -> PathBuf {
        if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
            return PathBuf::from(cargo_home);
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "~".to_string());
        PathBuf::from(home).join(".cargo")
    }
}

impl Default for CargoCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether a path is a directory.
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
    fn test_parse_cargo_toml_basic() {
        let content = r#"
[package]
name = "serde"
version = "1.0.200"
edition = "2021"
"#;
        let (name, version) = parse_cargo_toml_name_version(content).unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.200");
    }

    #[test]
    fn test_parse_cargo_toml_with_comments() {
        let content = r#"
# This is a comment
[package]
name = "tokio" # inline comment ignored since we stop at first "
version = "1.38.0"
"#;
        let (name, version) = parse_cargo_toml_name_version(content).unwrap();
        assert_eq!(name, "tokio");
        assert_eq!(version, "1.38.0");
    }

    #[test]
    fn test_parse_cargo_toml_workspace_version() {
        let content = r#"
[package]
name = "my-crate"
version.workspace = true
"#;
        assert!(parse_cargo_toml_name_version(content).is_none());
    }

    #[test]
    fn test_parse_cargo_toml_missing_fields() {
        let content = r#"
[package]
name = "incomplete"
"#;
        assert!(parse_cargo_toml_name_version(content).is_none());
    }

    #[test]
    fn test_parse_cargo_toml_no_package_section() {
        let content = r#"
[dependencies]
serde = "1.0"
"#;
        assert!(parse_cargo_toml_name_version(content).is_none());
    }

    #[test]
    fn test_parse_cargo_toml_stops_at_next_section() {
        let content = r#"
[package]
name = "foo"

[dependencies]
version = "fake"
"#;
        // Should not find version since it's under [dependencies]
        assert!(parse_cargo_toml_name_version(content).is_none());
    }

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
            batch_size: 100,
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
            batch_size: 100,
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
            batch_size: 100,
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
            batch_size: 100,
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
        tokio::fs::write(pkg.join("composer.json"), "{}").await.unwrap();

        let crawler = CargoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: 100,
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
            batch_size: 100,
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
            batch_size: 100,
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

    #[test]
    fn test_parse_table_header_variants() {
        assert_eq!(parse_table_header("[package]"), Some("package"));
        assert_eq!(
            parse_table_header("[package] # main crate"),
            Some("package")
        );
        assert_eq!(parse_table_header("[ package ]"), Some("package"));
        assert_eq!(
            parse_table_header("[package.metadata]"),
            Some("package.metadata")
        );
        // Not a header line.
        assert_eq!(parse_table_header("name = \"x\""), None);
        // Array value lines don't start with '[' once trimmed by the caller,
        // but a bare unterminated bracket is rejected.
        assert_eq!(parse_table_header("[oops"), None);
    }

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
        let (name, version) = parse_cargo_toml_name_version(content).unwrap();
        assert_eq!(name, "serde");
        assert_eq!(version, "1.0.200");
    }

    #[test]
    fn test_parse_cargo_toml_header_with_inner_spaces() {
        let content = "[ package ]\nname = \"tokio\"\nversion = \"1.38.0\"\n";
        let (name, version) = parse_cargo_toml_name_version(content).unwrap();
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
        assert!(parse_cargo_toml_name_version(content).is_none());
    }

    // --- regression: dir-name version splitting ------------------------

    /// A numeric pre-release segment (legal SemVer) must stay part of the
    /// version. Previously the "last hyphen-before-digit" heuristic split
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
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:cargo/serde@1.0.200");
    }
}
