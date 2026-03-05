use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::types::{CrawledPackage, CrawlerOptions};

/// PHP/Composer ecosystem crawler for discovering packages in Composer
/// vendor directories.
pub struct ComposerCrawler;

/// Composer 2 installed.json format: `{"packages": [...]}`
#[derive(Deserialize)]
struct InstalledJsonV2 {
    packages: Vec<ComposerPackageEntry>,
}

/// A single package entry from installed.json.
#[derive(Deserialize)]
struct ComposerPackageEntry {
    name: String,
    version: String,
}

impl ComposerCrawler {
    /// Create a new `ComposerCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get vendor paths based on options.
    ///
    /// In global mode, checks `$COMPOSER_HOME/vendor/` (env var, command
    /// fallback, or platform defaults).
    ///
    /// In local mode, checks `<cwd>/vendor/` but only if the directory
    /// contains `composer/installed.json` and the cwd looks like a PHP
    /// project (`composer.json` or `composer.lock` present).
    pub async fn get_vendor_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(Self::get_global_vendor_paths().await);
        }

        // Local mode
        let vendor_dir = options.cwd.join("vendor");
        let installed_json = vendor_dir.join("composer").join("installed.json");

        if !is_dir(&vendor_dir).await || !is_file(&installed_json).await {
            return Ok(Vec::new());
        }

        // Only return if this looks like a PHP project
        let has_composer_json = is_file(&options.cwd.join("composer.json")).await;
        let has_composer_lock = is_file(&options.cwd.join("composer.lock")).await;

        if has_composer_json || has_composer_lock {
            Ok(vec![vendor_dir])
        } else {
            Ok(Vec::new())
        }
    }

    /// Crawl all discovered vendor paths and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let vendor_paths = self.get_vendor_paths(options).await.unwrap_or_default();

        for vendor_path in &vendor_paths {
            let entries = read_installed_json(vendor_path).await;
            for entry in entries {
                if let Some((namespace, name)) = entry.name.split_once('/') {
                    let purl =
                        crate::utils::purl::build_composer_purl(namespace, name, &entry.version);

                    if seen.contains(&purl) {
                        continue;
                    }
                    seen.insert(purl.clone());

                    let pkg_path = vendor_path.join(namespace).join(name);

                    packages.push(CrawledPackage {
                        name: name.to_string(),
                        version: entry.version,
                        namespace: Some(namespace.to_string()),
                        purl,
                        path: pkg_path,
                    });
                }
            }
        }

        packages
    }

    /// Find specific packages by PURL inside a single vendor directory.
    pub async fn find_by_purls(
        &self,
        vendor_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        // Build a name -> version lookup from installed.json
        let entries = read_installed_json(vendor_path).await;
        let installed: HashMap<String, String> = entries
            .into_iter()
            .map(|e| (e.name, e.version))
            .collect();

        for purl in purls {
            if let Some(((namespace, name), version)) =
                crate::utils::purl::parse_composer_purl(purl)
            {
                let full_name = format!("{namespace}/{name}");
                let pkg_dir = vendor_path.join(namespace).join(name);

                if !is_dir(&pkg_dir).await {
                    continue;
                }

                // Verify version matches installed.json
                if let Some(installed_version) = installed.get(&full_name) {
                    if installed_version == version {
                        result.insert(
                            purl.clone(),
                            CrawledPackage {
                                name: name.to_string(),
                                version: version.to_string(),
                                namespace: Some(namespace.to_string()),
                                purl: purl.clone(),
                                path: pkg_dir,
                            },
                        );
                    }
                }
            }
        }

        Ok(result)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Get global Composer vendor paths.
    async fn get_global_vendor_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        if let Some(composer_home) = get_composer_home().await {
            let vendor_dir = composer_home.join("vendor");
            if is_dir(&vendor_dir).await {
                paths.push(vendor_dir);
            }
        }

        paths
    }
}

impl Default for ComposerCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the Composer home directory.
///
/// Checks `$COMPOSER_HOME`, then runs `composer global config home`,
/// then falls back to platform defaults.
async fn get_composer_home() -> Option<PathBuf> {
    // Check env var first
    if let Ok(home) = std::env::var("COMPOSER_HOME") {
        let path = PathBuf::from(home);
        if is_dir(&path).await {
            return Some(path);
        }
    }

    // Try `composer global config home`
    if let Ok(output) = std::process::Command::new("composer")
        .args(["global", "config", "home"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !stdout.is_empty() {
                let path = PathBuf::from(&stdout);
                if is_dir(&path).await {
                    return Some(path);
                }
            }
        }
    }

    // Platform defaults
    let home_dir = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    let home = PathBuf::from(home_dir);

    let candidates = [
        home.join(".composer"),
        home.join(".config").join("composer"),
    ];

    for candidate in &candidates {
        if is_dir(candidate).await {
            return Some(candidate.clone());
        }
    }

    None
}

/// Read and parse `vendor/composer/installed.json`.
///
/// Supports both Composer 1 (flat JSON array) and Composer 2 (`{"packages": [...]}`) formats.
async fn read_installed_json(vendor_path: &Path) -> Vec<ComposerPackageEntry> {
    let installed_path = vendor_path.join("composer").join("installed.json");

    let content = match tokio::fs::read_to_string(&installed_path).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    // Try Composer 2 format first (object with packages key)
    if let Ok(v2) = serde_json::from_str::<InstalledJsonV2>(&content) {
        return v2.packages;
    }

    // Fall back to Composer 1 format (flat array)
    if let Ok(v1) = serde_json::from_str::<Vec<ComposerPackageEntry>>(&content) {
        return v1;
    }

    Vec::new()
}

/// Check whether a path is a directory.
async fn is_dir(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

/// Check whether a path is a file.
async fn is_file(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.is_file())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_crawl_all_composer() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        // Create installed.json (v2 format)
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "symfony/console", "version": "6.4.1"}
            ]}"#,
        )
        .await
        .unwrap();

        // Create package directories
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();

        // Create composer.json so it's recognized as a PHP project
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:composer/monolog/monolog@3.5.0"));
        assert!(purls.contains("pkg:composer/symfony/console@6.4.1"));

        // Verify namespace is set
        let monolog = packages.iter().find(|p| p.name == "monolog").unwrap();
        assert_eq!(monolog.namespace, Some("monolog".to_string()));
    }

    #[tokio::test]
    async fn test_find_by_purls_composer() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        // Create installed.json
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "symfony/console", "version": "6.4.1"}
            ]}"#,
        )
        .await
        .unwrap();

        // Create package directories
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let purls = vec![
            "pkg:composer/monolog/monolog@3.5.0".to_string(),
            "pkg:composer/symfony/console@6.4.1".to_string(),
            "pkg:composer/guzzle/guzzle@7.0.0".to_string(), // not installed
        ];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("pkg:composer/monolog/monolog@3.5.0"));
        assert!(result.contains_key("pkg:composer/symfony/console@6.4.1"));
        assert!(!result.contains_key("pkg:composer/guzzle/guzzle@7.0.0"));
    }

    #[tokio::test]
    async fn test_installed_json_v1_format() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        // Create installed.json in Composer 1 format (flat array)
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"[
                {"name": "monolog/monolog", "version": "2.9.1"},
                {"name": "psr/log", "version": "3.0.0"}
            ]"#,
        )
        .await
        .unwrap();

        let entries = read_installed_json(vendor_dir).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "monolog/monolog");
        assert_eq!(entries[0].version, "2.9.1");
        assert_eq!(entries[1].name, "psr/log");
        assert_eq!(entries[1].version, "3.0.0");
    }

    #[tokio::test]
    async fn test_installed_json_v2_format() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        // Create installed.json in Composer 2 format
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "symfony/console", "version": "v6.4.1"},
                {"name": "symfony/string", "version": "v6.4.0"}
            ]}"#,
        )
        .await
        .unwrap();

        let entries = read_installed_json(vendor_dir).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "symfony/console");
        assert_eq!(entries[0].version, "v6.4.1");
    }

    #[tokio::test]
    async fn test_non_php_project_returns_empty() {
        let dir = tempfile::tempdir().unwrap();

        // Create vendor dir with installed.json but no composer.json/lock
        let vendor_dir = dir.path().join("vendor");
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "foo/bar", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert!(packages.is_empty());
    }

    #[tokio::test]
    async fn test_find_by_purls_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "monolog/monolog", "version": "3.5.0"}]}"#,
        )
        .await
        .unwrap();

        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        // Request a different version than installed
        let purls = vec!["pkg:composer/monolog/monolog@2.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert!(result.is_empty());
    }
}
