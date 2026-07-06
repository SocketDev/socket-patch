use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::{is_dir, is_file};
use crate::utils::process::{CommandRunner, SystemCommandRunner};

/// PHP/Composer ecosystem crawler for discovering packages in Composer
/// vendor directories.
pub struct ComposerCrawler;

/// A single package entry distilled from installed.json. Only the two
/// fields the crawler needs are retained; everything else (source,
/// dist, autoload, ...) is ignored.
struct ComposerPackageEntry {
    name: String,
    version: String,
}

impl ComposerCrawler {
    /// Create a new `ComposerCrawler`.
    pub fn new() -> Self {
        Self
    }

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
            let mut paths = Vec::new();
            if let Some(composer_home) = get_composer_home().await {
                let vendor_dir = composer_home.join("vendor");
                if is_dir(&vendor_dir).await {
                    paths.push(vendor_dir);
                }
            }
            return Ok(paths);
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
                    // Skip packages that installed.json lists but that are
                    // not actually on disk (stale metadata, custom install
                    // paths). This keeps crawl_all consistent with
                    // find_by_purls, which only returns packages whose
                    // vendor directory exists.
                    let pkg_path = vendor_path.join(namespace).join(name);
                    if !is_dir(&pkg_path).await {
                        continue;
                    }

                    // Composer's installed.json stores the *pretty*
                    // version (often `v6.4.1`); PURLs use the bare numeric
                    // version, so normalize before building the PURL.
                    let version = normalize_version(&entry.version).to_string();

                    // Composer/Packagist treat package names
                    // case-insensitively and the canonical PURL is
                    // lowercase, but installed.json records the *pretty*
                    // (case-preserved) name. Lowercase the namespace/name
                    // for the PURL so it matches the canonical form Socket's
                    // catalog uses; the on-disk `path` keeps the original
                    // casing (Composer writes the vendor dir with the pretty
                    // name, which matters on case-sensitive filesystems).
                    let ns_canon = namespace.to_ascii_lowercase();
                    let name_canon = name.to_ascii_lowercase();
                    let purl =
                        crate::utils::purl::build_composer_purl(&ns_canon, &name_canon, &version);

                    if !seen.insert(purl.clone()) {
                        continue;
                    }

                    packages.push(CrawledPackage {
                        name: name_canon,
                        version,
                        namespace: Some(ns_canon),
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

        // Build a case-insensitive lookup from installed.json. Composer
        // package names are case-insensitive and the canonical PURL is
        // lowercase, but installed.json records the *pretty* (case-preserved)
        // name and Composer writes the vendor directory with that same
        // casing. Key the map by the lowercased name and carry the original
        // name so the real on-disk path can be reconstructed even on
        // case-sensitive filesystems.
        let entries = read_installed_json(vendor_path).await;
        let installed: HashMap<String, (String, String)> = entries
            .into_iter()
            .map(|e| (e.name.to_ascii_lowercase(), (e.name, e.version)))
            .collect();

        for purl in purls {
            if let Some(((namespace, name), version)) =
                crate::utils::purl::parse_composer_purl(purl)
            {
                let full_name = format!("{namespace}/{name}").to_ascii_lowercase();

                let Some((installed_name, installed_version)) = installed.get(&full_name) else {
                    continue;
                };

                // Verify version matches installed.json. Compare on the
                // normalized version so a `v`-prefixed installed.json
                // version (`v6.4.1`) matches a bare PURL version (`6.4.1`)
                // and vice versa.
                if normalize_version(installed_version) != normalize_version(version) {
                    continue;
                }

                // Resolve the on-disk directory using the original casing
                // recorded in installed.json, which is what Composer wrote to
                // disk — the canonical (lowercase) PURL name would miss it on
                // a case-sensitive filesystem.
                let pkg_dir = match installed_name.split_once('/') {
                    Some((ns, n)) => vendor_path.join(ns).join(n),
                    None => continue,
                };

                if !is_dir(&pkg_dir).await {
                    continue;
                }

                result.insert(
                    purl.clone(),
                    CrawledPackage {
                        name: name.to_ascii_lowercase(),
                        version: version.to_string(),
                        namespace: Some(namespace.to_ascii_lowercase()),
                        purl: purl.clone(),
                        path: pkg_dir,
                    },
                );
            }
        }

        Ok(result)
    }
}

impl Default for ComposerCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure parser for `composer global config home` stdout. Returns
/// the trimmed path as a `PathBuf` or `None` on empty input.
/// Extracted so the path-derivation logic is unit-testable without
/// the composer CLI installed.
pub fn parse_composer_home_output(stdout: &str) -> Option<PathBuf> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
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
    if let Some(stdout) = SystemCommandRunner.run("composer", &["global", "config", "home"]) {
        if let Some(path) = parse_composer_home_output(&stdout) {
            if is_dir(&path).await {
                return Some(path);
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

/// Normalize a Composer version string for PURL identity.
///
/// Composer's `installed.json` records the *pretty* version, which for
/// many packages (symfony, twig, ...) carries a leading `v` taken from
/// the upstream git tag (e.g. `v6.4.1`). PURLs use the bare numeric
/// version (`6.4.1`), so strip a single leading `v`/`V` when it
/// directly precedes a digit. Versions that don't fit that shape (e.g.
/// `dev-main`, `1.0.x-dev`) are returned untouched.
///
/// Also used by the composer vendor backend
/// (`patch::vendor::composer_lock`) to match lock versions against PURL
/// versions through the same normalization.
pub(crate) fn normalize_version(version: &str) -> &str {
    let mut chars = version.chars();
    if matches!(chars.next(), Some('v') | Some('V'))
        && chars.next().map(|c| c.is_ascii_digit()).unwrap_or(false)
    {
        return &version[1..];
    }
    version
}

/// Whether an installed.json package name is safe to join onto the
/// vendor root. Both `crawl_all` and `find_by_purls` split the recorded
/// name at `/` and join the pieces onto the vendor directory, and the
/// resolved directory is later patched in place — so a tampered
/// installed.json name like `../evil` would otherwise read (and later
/// write) out of tree. Every `/`-separated segment must be a safe single
/// segment ([`path_safety::is_safe_multi_segment`]), which also rejects
/// `.`/`..`, backslashes, colons (a Windows drive-relative `C:evil`
/// joins as an absolute path), NULs, and empty segments. Fails closed.
/// Twin of the npm/deno/go/cargo/maven/nuget coordinate gates.
fn is_safe_composer_name(name: &str) -> bool {
    path_safety::is_safe_multi_segment(name)
}

/// Read and parse `vendor/composer/installed.json`.
///
/// Supports both Composer 1 (flat JSON array) and Composer 2
/// (`{"packages": [...]}`) formats. Parsing is intentionally lenient:
/// the file is read as untyped JSON and entries are extracted one at a
/// time, so a single malformed entry (missing/non-string `name` or
/// `version`, or extra unexpected fields) is skipped rather than
/// discarding every package in the file.
async fn read_installed_json(vendor_path: &Path) -> Vec<ComposerPackageEntry> {
    let installed_path = vendor_path.join("composer").join("installed.json");

    let content = match tokio::fs::read_to_string(&installed_path).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let root: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    // Composer 2 wraps the list in `{"packages": [...]}`; Composer 1 is
    // a bare top-level array.
    let entries = match root.get("packages").and_then(|p| p.as_array()) {
        Some(arr) => arr,
        None => match root.as_array() {
            Some(arr) => arr,
            None => return Vec::new(),
        },
    };

    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let version = entry.get("version")?.as_str()?;
            if name.is_empty() || version.is_empty() || !is_safe_composer_name(name) {
                return None;
            }
            Some(ComposerPackageEntry {
                name: name.to_string(),
                version: version.to_string(),
            })
        })
        .collect()
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
        };

        let packages = crawler.crawl_all(&options).await;
        assert!(packages.is_empty());
    }

    #[test]
    fn test_normalize_version() {
        // `v`-prefixed semver versions get the prefix stripped.
        assert_eq!(normalize_version("v6.4.1"), "6.4.1");
        assert_eq!(normalize_version("V6.4.1"), "6.4.1");
        // Bare versions pass through untouched.
        assert_eq!(normalize_version("6.4.1"), "6.4.1");
        // A leading `v` not followed by a digit is part of the version
        // and must be preserved.
        assert_eq!(normalize_version("dev-main"), "dev-main");
        assert_eq!(normalize_version("vendor-tag"), "vendor-tag");
        assert_eq!(normalize_version("v"), "v");
        assert_eq!(normalize_version(""), "");
    }

    #[tokio::test]
    async fn test_crawl_all_strips_v_prefix_from_purl() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // symfony tags releases as `v6.4.1`; installed.json keeps that.
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "symfony/console", "version": "v6.4.1"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        // The emitted PURL and version are the bare (canonical) form.
        assert_eq!(packages[0].purl, "pkg:composer/symfony/console@6.4.1");
        assert_eq!(packages[0].version, "6.4.1");
    }

    #[tokio::test]
    async fn test_find_by_purls_matches_v_prefixed_installed_version() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "symfony/console", "version": "v6.4.1"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        // A canonical (bare) PURL must match the `v`-prefixed installed
        // version, and a `v`-prefixed PURL must match too.
        let purls = vec![
            "pkg:composer/symfony/console@6.4.1".to_string(),
            "pkg:composer/symfony/console@v6.4.1".to_string(),
        ];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("pkg:composer/symfony/console@6.4.1"));
        assert!(result.contains_key("pkg:composer/symfony/console@v6.4.1"));
    }

    #[tokio::test]
    async fn test_read_installed_json_skips_malformed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // One valid entry surrounded by malformed neighbours: an entry
        // missing `version`, one missing `name`, and a non-object. A
        // single bad entry must not discard the whole file.
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "good/pkg", "version": "1.0.0"},
                {"name": "bad/no-version"},
                {"version": "2.0.0"},
                "not-an-object"
            ]}"#,
        )
        .await
        .unwrap();

        let entries = read_installed_json(vendor_dir).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "good/pkg");
        assert_eq!(entries[0].version, "1.0.0");
    }

    #[tokio::test]
    async fn test_crawl_all_skips_package_missing_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // installed.json lists two packages but only one has a vendor
        // directory on disk.
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "ghost/pkg", "version": "1.0.0"}
            ]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "monolog");
    }

    #[tokio::test]
    async fn test_crawl_all_composer_v1_flat_array_end_to_end() {
        // crawl_all was only covered with the Composer 2 `{"packages": [...]}`
        // wrapper; pin the Composer 1 bare-array path end-to-end (discovery,
        // on-disk check, PURL build) so a regression in the v1 fallback in
        // read_installed_json is caught at the public-API level.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"[
                {"name": "monolog/monolog", "version": "2.9.1"},
                {"name": "psr/log", "version": "v3.0.0"}
            ]"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("psr").join("log"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.lock"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:composer/monolog/monolog@2.9.1"));
        // The `v` prefix is normalized away even via the v1 array path.
        assert!(purls.contains("pkg:composer/psr/log@3.0.0"));
    }

    #[tokio::test]
    async fn test_read_installed_json_missing_or_invalid_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        // No composer/installed.json at all -> empty, no panic.
        assert!(read_installed_json(vendor_dir).await.is_empty());

        // Present but not valid JSON -> empty, no panic.
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(composer_dir.join("installed.json"), "{ not json")
            .await
            .unwrap();
        assert!(read_installed_json(vendor_dir).await.is_empty());

        // Valid JSON but the wrong shape (neither a bare array nor a
        // `{"packages": [...]}` object) -> empty.
        tokio::fs::write(composer_dir.join("installed.json"), r#"{"packages": 42}"#)
            .await
            .unwrap();
        assert!(read_installed_json(vendor_dir).await.is_empty());
    }

    #[tokio::test]
    async fn test_find_by_purls_requires_installed_json() {
        // A package directory present on disk but with NO installed.json
        // must not be returned: the crawler cannot corroborate the version,
        // so it stays consistent with crawl_all (which also yields nothing
        // without installed.json) rather than blindly trusting the path.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        // Note: deliberately no vendor/composer/installed.json.

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/monolog/monolog@3.5.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_find_by_purls_skips_package_missing_on_disk() {
        // installed.json lists the package at the requested version, but its
        // vendor directory is absent (e.g. a metapackage or a custom install
        // path). find_by_purls must skip it — there are no files to patch.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "meta/package", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        // Deliberately do not create vendor/meta/package.

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/meta/package@1.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_crawl_all_dedups_repeated_normalized_purls() {
        // Two installed.json entries that normalize to the same PURL (one
        // `v`-prefixed, one bare) must collapse to a single CrawledPackage so
        // the same on-disk package isn't reported twice.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "symfony/console", "version": "v6.4.1"},
                {"name": "symfony/console", "version": "6.4.1"}
            ]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:composer/symfony/console@6.4.1");
    }

    #[tokio::test]
    async fn test_crawl_all_canonicalizes_uppercase_name_to_lowercase_purl() {
        // Composer/Packagist treat package names case-insensitively and the
        // canonical PURL is lowercase, but installed.json records the pretty
        // (case-preserved) name. crawl_all must emit a lowercase canonical
        // PURL so it matches Socket's catalog — otherwise an uppercase pretty
        // name silently produces an unmatchable PURL and the vuln is missed.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "Foo/Bar", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        // Composer writes the vendor directory using the pretty (case-
        // preserved) name.
        tokio::fs::create_dir_all(vendor_dir.join("Foo").join("Bar"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        // PURL, name and namespace are the canonical lowercase form...
        assert_eq!(packages[0].purl, "pkg:composer/foo/bar@1.0.0");
        assert_eq!(packages[0].name, "bar");
        assert_eq!(packages[0].namespace, Some("foo".to_string()));
        // ...but the on-disk path keeps the original casing Composer wrote.
        assert_eq!(packages[0].path, vendor_dir.join("Foo").join("Bar"));
    }

    #[tokio::test]
    async fn test_find_by_purls_canonical_purl_matches_case_preserved_install() {
        // A canonical (lowercase) PURL must resolve a package whose
        // installed.json name and on-disk directory carry uppercase letters.
        // The lookup is case-insensitive and the on-disk path is rebuilt from
        // the original installed.json casing so it resolves even on a
        // case-sensitive filesystem.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "Foo/Bar", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("Foo").join("Bar"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/foo/bar@1.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = result.get("pkg:composer/foo/bar@1.0.0").unwrap();
        // The resolved path points at the real (case-preserved) directory.
        assert_eq!(pkg.path, vendor_dir.join("Foo").join("Bar"));
        assert_eq!(pkg.namespace, Some("foo".to_string()));
        assert_eq!(pkg.name, "bar");
    }

    #[tokio::test]
    async fn test_crawl_all_rejects_traversal_name_from_installed_json() {
        // installed.json is part of the (untrusted) project being scanned.
        // A tampered name like `../evil` joins onto the vendor root and
        // resolves to a directory OUTSIDE it; apply would later write patch
        // content there. The crawler must drop such entries — twin of the
        // npm/cargo/maven/nuget/deno/go coordinate gates.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "../evil", "version": "1.0.0"}
            ]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        // The traversal target exists OUTSIDE the vendor root, so the
        // on-disk `is_dir` corroboration alone does not stop it.
        tokio::fs::create_dir_all(dir.path().join("evil"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(
            packages.len(),
            1,
            "traversal entry must be dropped, got: {:?}",
            packages.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
        assert_eq!(packages[0].name, "monolog");
    }

    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_name_from_installed_json() {
        // Same threat via the lookup path: a manifest purl whose
        // namespace/name mirror a tampered installed.json entry would
        // resolve a package directory outside the vendor root and hand it
        // to apply as a patch target.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "../evil", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(dir.path().join("evil"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/../evil@1.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "traversal name escaped the vendor root: {:?}",
            result.values().map(|p| &p.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_is_safe_composer_name() {
        // Real composer names (vendor/name, case-preserved, dots/dashes).
        assert!(is_safe_composer_name("monolog/monolog"));
        assert!(is_safe_composer_name("Foo/Bar"));
        assert!(is_safe_composer_name("symfony/polyfill-php80"));
        assert!(is_safe_composer_name("phpunit/php-code-coverage"));
        // Traversal, separators, absolute/drive forms, empties.
        assert!(!is_safe_composer_name("../evil"));
        assert!(!is_safe_composer_name("evil/.."));
        assert!(!is_safe_composer_name("./evil"));
        assert!(!is_safe_composer_name("/abs/path"));
        assert!(!is_safe_composer_name("a//b"));
        assert!(!is_safe_composer_name("a\\b/c"));
        assert!(!is_safe_composer_name("C:evil/x"));
        assert!(!is_safe_composer_name(""));
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
