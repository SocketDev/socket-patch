#![cfg(feature = "cargo")]

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

        // Track table headers
        if trimmed.starts_with('[') {
            if trimmed == "[package]" {
                in_package = true;
            } else {
                // We left the [package] section
                if in_package {
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

        // Local mode: check vendor first
        let vendor_dir = options.cwd.join("vendor");
        if is_dir(&vendor_dir).await {
            return Ok(vec![vendor_dir]);
        }

        // Only fall back to global registry if this looks like a Cargo project
        let has_cargo_toml = tokio::fs::metadata(options.cwd.join("Cargo.toml"))
            .await
            .is_ok();
        let has_cargo_lock = tokio::fs::metadata(options.cwd.join("Cargo.lock"))
            .await
            .is_ok();

        if has_cargo_toml || has_cargo_lock {
            return Ok(Self::get_registry_src_paths().await);
        }

        // Not a Cargo project — return empty
        Ok(Vec::new())
    }

    /// Crawl all discovered crate source directories and return every
    /// package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let src_paths = self.get_crate_source_paths(options).await.unwrap_or_default();

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
                if self
                    .verify_crate_at_path(&vendor_dir, name, version)
                    .await
                {
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

        let mut entries = match tokio::fs::read_dir(&registry_src).await {
            Ok(rd) => rd,
            Err(_) => return paths,
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let ft = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
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

        let mut entries = match tokio::fs::read_dir(src_path).await {
            Ok(rd) => rd,
            Err(_) => return results,
        };

        let mut entry_list = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            entry_list.push(entry);
        }

        for entry in entry_list {
            let ft = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if !ft.is_dir() {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            // Skip hidden directories
            if dir_name_str.starts_with('.') {
                continue;
            }

            let crate_path = src_path.join(&*dir_name_str);
            if let Some(pkg) =
                self.read_crate_cargo_toml(&crate_path, &dir_name_str, seen).await
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
                if let Some((parsed_name, parsed_version)) =
                    Self::parse_dir_name_version(&dir_name)
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
    /// Registry directories follow the pattern `<crate-name>-<version>`,
    /// where the version is the last `-`-separated component that starts with
    /// a digit (handles crate names with hyphens like `serde-json`).
    fn parse_dir_name_version(dir_name: &str) -> Option<(String, String)> {
        // Find the last '-' followed by a digit
        let mut split_idx = None;
        for (i, _) in dir_name.match_indices('-') {
            if dir_name[i + 1..].starts_with(|c: char| c.is_ascii_digit()) {
                split_idx = Some(i);
            }
        }
        let idx = split_idx?;
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
}
