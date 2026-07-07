use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::{entry_is_dir, home_dir, is_dir, list_dir_entries};
use crate::utils::process::{CommandRunner, SystemCommandRunner};

/// Ruby/RubyGems ecosystem crawler for discovering gems in Bundler vendor
/// directories or global gem installation paths.
pub struct RubyCrawler;

impl RubyCrawler {
    /// Create a new `RubyCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get gem installation paths based on options.
    ///
    /// In local mode, checks `vendor/bundle/ruby/*/gems/` first (Bundler
    /// deployment layout), but only if `Gemfile` or `Gemfile.lock` exists
    /// in the cwd. Falls back to querying `gem env gemdir`.
    ///
    /// In global mode, queries `gem env gemdir` and `gem env gempath`, plus
    /// well-known fallback paths for rbenv, rvm, Homebrew, and system Ruby.
    pub async fn get_gem_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(Self::get_global_gem_paths().await);
        }

        // Local mode: check vendor/bundle first
        let vendor_gems = Self::get_vendor_bundle_paths(&options.cwd).await;
        if !vendor_gems.is_empty() {
            return Ok(vendor_gems);
        }

        // Only fall back to global gem paths if this looks like a Ruby project
        let has_gemfile = tokio::fs::metadata(options.cwd.join("Gemfile"))
            .await
            .is_ok();
        let has_gemfile_lock = tokio::fs::metadata(options.cwd.join("Gemfile.lock"))
            .await
            .is_ok();

        if has_gemfile || has_gemfile_lock {
            // Try gem env gemdir
            if let Some(gemdir) = Self::run_gem_env("gemdir").await {
                let gems_path = PathBuf::from(gemdir).join("gems");
                if is_dir(&gems_path).await {
                    return Ok(vec![gems_path]);
                }
            }
        }

        // Not a Ruby project — return empty
        Ok(Vec::new())
    }

    /// Crawl all discovered gem paths and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let gem_paths = self.get_gem_paths(options).await.unwrap_or_default();

        for gem_path in &gem_paths {
            let found = self.scan_gem_dir(gem_path, &mut seen).await;
            packages.extend(found);
        }

        packages
    }

    /// Find specific packages by PURL inside a single gem directory.
    ///
    /// Gem directories follow the `<name>-<version>` pattern.
    pub async fn find_by_purls(
        &self,
        gem_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            if let Some((name, version)) = crate::utils::purl::parse_gem_purl(purl) {
                // SECURITY: name/version come straight from the (untrusted)
                // manifest PURL and are formatted into a `<name>-<version>`
                // dir name joined onto `gem_path` below. A real gem
                // coordinate is a single path segment, so reject any that
                // could traverse out of the gem root (`..`/`.`, a separator,
                // an absolute path, NUL). `verify_gem_at_path` only checks
                // for `lib/`/`.gemspec` and gems patch in place, so fail
                // closed here — same as the deno/go/maven/npm/nuget guards.
                if !is_safe_gem_coordinate(name, version) {
                    continue;
                }
                // The purl is the base PURL (qualifiers stripped upstream).
                // Resolve it to the installed gem dir, which may carry a
                // `-<platform>` suffix for platform gems.
                if let Some(gem_dir) = self.locate_gem_dir(gem_path, name, version).await {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: None,
                            purl: purl.clone(),
                            path: gem_dir,
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

    /// Find `vendor/bundle/ruby/*/gems/` directories.
    async fn get_vendor_bundle_paths(cwd: &Path) -> Vec<PathBuf> {
        let vendor_ruby = cwd.join("vendor").join("bundle").join("ruby");
        let mut paths = Vec::new();

        for entry in list_dir_entries(&vendor_ruby).await {
            if !entry_is_dir(&entry).await {
                continue;
            }
            let gems_dir = vendor_ruby.join(entry.file_name()).join("gems");
            if is_dir(&gems_dir).await {
                paths.push(gems_dir);
            }
        }
        paths
    }

    /// Get global gem paths by querying `gem env` and checking well-known locations.
    async fn get_global_gem_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = HashSet::new();

        // gem env gemdir
        if let Some(gemdir) = Self::run_gem_env("gemdir").await {
            let gems_path = PathBuf::from(gemdir).join("gems");
            if is_dir(&gems_path).await && seen.insert(gems_path.clone()) {
                paths.push(gems_path);
            }
        }

        // gem env gempath lists several gem homes separated by the OS path
        // separator (`:` on Unix, `;` on Windows). Splitting on a hardcoded
        // `:` shreds Windows drive-letter paths (`C:\Ruby\...;D:\...`) into
        // `["C", "\Ruby\...;D", "\..."]`, so defer to `split_paths`, which
        // honors the platform separator — same as the Go crawler's GOPATH.
        if let Some(gempath) = Self::run_gem_env("gempath").await {
            for gems_path in gem_homes_to_gems_dirs(&gempath) {
                if is_dir(&gems_path).await && seen.insert(gems_path.clone()) {
                    paths.push(gems_path);
                }
            }
        }

        // Fallback well-known paths
        let home = home_dir();

        let fallback_globs = [
            home.join(".gem").join("ruby"),
            home.join(".rbenv").join("versions"),
            home.join(".rvm").join("gems"),
        ];

        for base in &fallback_globs {
            for entry in list_dir_entries(base).await {
                if !entry_is_dir(&entry).await {
                    continue;
                }

                let entry_path = base.join(entry.file_name());

                // ~/.gem/ruby/*/gems/
                let gems_dir = entry_path.join("gems");
                if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                    paths.push(gems_dir);
                    continue;
                }

                // ~/.rbenv/versions/*/lib/ruby/gems/*/gems/
                let lib_ruby_gems = entry_path.join("lib").join("ruby").join("gems");
                for sub_entry in list_dir_entries(&lib_ruby_gems).await {
                    let gems_dir = lib_ruby_gems.join(sub_entry.file_name()).join("gems");
                    if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                        paths.push(gems_dir);
                    }
                }
            }
        }

        // System paths
        let system_bases = [
            PathBuf::from("/usr/lib/ruby/gems"),
            PathBuf::from("/usr/local/lib/ruby/gems"),
            PathBuf::from("/opt/homebrew/lib/ruby/gems"),
        ];

        for base in &system_bases {
            for entry in list_dir_entries(base).await {
                let gems_dir = base.join(entry.file_name()).join("gems");
                if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                    paths.push(gems_dir);
                }
            }
        }

        paths
    }

    /// Run `gem env <key>` and return the trimmed stdout.
    async fn run_gem_env(key: &str) -> Option<String> {
        let stdout = SystemCommandRunner.run("gem", &["env", key]);
        parse_gem_env_output(stdout.as_deref().unwrap_or(""))
    }

    /// Scan a gem directory and return all valid gem packages found.
    async fn scan_gem_dir(
        &self,
        gem_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for entry in list_dir_entries(gem_path).await {
            if !entry_is_dir(&entry).await {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            // Skip hidden directories
            if dir_name_str.starts_with('.') {
                continue;
            }

            let gem_dir = gem_path.join(&*dir_name_str);

            // Parse name-version from directory name
            if let Some((name, version)) = Self::parse_dir_name_version(&dir_name_str) {
                // Verify it looks like a gem (has .gemspec or lib/)
                if !self.verify_gem_at_path(&gem_dir).await {
                    continue;
                }

                let purl = crate::utils::purl::build_gem_purl(&name, &version);

                if !seen.insert(purl.clone()) {
                    continue;
                }

                results.push(CrawledPackage {
                    name,
                    version,
                    namespace: None,
                    purl,
                    path: gem_dir,
                });
            }
        }

        results
    }

    /// Verify that a directory looks like an installed gem.
    /// Checks for a `.gemspec` file or a `lib/` directory.
    async fn verify_gem_at_path(&self, path: &Path) -> bool {
        if !is_dir(path).await {
            return false;
        }

        // Check for lib/ directory
        if is_dir(&path.join("lib")).await {
            return true;
        }

        // Check for any .gemspec file
        for entry in list_dir_entries(path).await {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".gemspec") {
                    return true;
                }
            }
        }

        false
    }

    /// Parse a gem directory name into its base `(name, version)`.
    ///
    /// Gem directories follow `<name>-<version>` (ruby-platform gems) or
    /// `<name>-<version>-<platform>` (platform gems, e.g.
    /// `nokogiri-1.16.5-x86_64-linux`). The name/version boundary is the
    /// **first** `-` followed by a digit. A RubyGems version is dash-free
    /// (prerelease dashes render as `.pre.`), so the version is the run up
    /// to the next `-`; anything after that is the platform suffix, which
    /// we drop — the installed platform is resolved later by hashing the
    /// gem's files (the same model as PyPI's `artifact_id`). The qualified
    /// `?platform=` PURL is only ever carried in the manifest/API.
    fn parse_dir_name_version(dir_name: &str) -> Option<(String, String)> {
        let idx = dir_name
            .match_indices('-')
            .find(|(i, _)| dir_name[i + 1..].starts_with(|c: char| c.is_ascii_digit()))
            .map(|(i, _)| i)?;
        let name = &dir_name[..idx];
        let rest = &dir_name[idx + 1..];
        // Version is the leading dash-free token; drop any `-<platform>`.
        let version = rest.split('-').next().unwrap_or(rest);
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_string(), version.to_string()))
    }

    /// Locate an installed gem directory for a base `name`/`version`.
    ///
    /// Plain (ruby-platform) gems live in `<name>-<version>/`; platform
    /// gems append a `-<platform>` suffix
    /// (`<name>-<version>-x86_64-linux/`). Only one platform is installed
    /// per environment, so we return the exact dir when present, otherwise
    /// the first verifying `<name>-<version>-*` directory.
    async fn locate_gem_dir(&self, gem_path: &Path, name: &str, version: &str) -> Option<PathBuf> {
        let exact = gem_path.join(format!("{name}-{version}"));
        if self.verify_gem_at_path(&exact).await {
            return Some(exact);
        }
        let prefix = format!("{name}-{version}-");
        for entry in list_dir_entries(gem_path).await {
            let file_name = entry.file_name();
            let dir_name = file_name.to_string_lossy();
            if dir_name.starts_with(&prefix) {
                let dir = gem_path.join(&*dir_name);
                if self.verify_gem_at_path(&dir).await {
                    return Some(dir);
                }
            }
        }
        None
    }
}

impl Default for RubyCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure parser for `gem env <key>` stdout. Returns the trimmed path
/// string or `None` on empty input. Extracted so the helper logic is
/// unit-testable without shelling out to the gem CLI.
pub fn parse_gem_env_output(stdout: &str) -> Option<String> {
    let s = stdout.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Split a `gem env gempath` value into the `<home>/gems` directories it
/// names. Each entry is one gem home; the installed gems live under its
/// `gems/` subdirectory. Splitting uses [`std::env::split_paths`] so the
/// OS path separator (`:` on Unix, `;` on Windows) is honored — a hardcoded
/// `:` would mangle Windows drive-letter paths. Empty segments are dropped.
fn gem_homes_to_gems_dirs(gempath: &str) -> Vec<PathBuf> {
    std::env::split_paths(gempath)
        .filter(|segment| !segment.as_os_str().is_empty())
        .map(|segment| segment.join("gems"))
        .collect()
}

/// Whether a PURL-derived gem coordinate is safe to join onto the gem root.
/// SECURITY: `find_by_purls` formats name/version into a `<name>-<version>`
/// directory name joined onto `gem_path`, and a real gem name/version is
/// dash/dot/word characters only — never a separator, colon, NUL, or bare
/// dot segment. `verify_gem_at_path` only checks for `lib/`/`.gemspec` and
/// gems are patched in place, so a tampered manifest PURL (`pkg:gem/../x@1.0`,
/// an absolute name, a `/`-bearing version) must be rejected here, fail
/// closed. Delegates to [`path_safety::is_safe_single_segment`], which also
/// rejects `:` — a Windows drive-relative coordinate (`C:evil`) joins as an
/// absolute path. Mirrors the deno/go/maven/npm/nuget crawler coordinate
/// guards.
fn is_safe_gem_coordinate(name: &str, version: &str) -> bool {
    path_safety::is_safe_single_segment(name) && path_safety::is_safe_single_segment(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gem_dir_name() {
        assert_eq!(
            RubyCrawler::parse_dir_name_version("rails-7.1.0"),
            Some(("rails".to_string(), "7.1.0".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("activerecord-7.1.3.2"),
            Some(("activerecord".to_string(), "7.1.3.2".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("net-http-0.4.1"),
            Some(("net-http".to_string(), "0.4.1".to_string()))
        );
        assert!(RubyCrawler::parse_dir_name_version("no-version-here").is_none());
        assert!(RubyCrawler::parse_dir_name_version("noversion").is_none());
    }

    #[test]
    fn test_parse_gem_dir_name_platform_gems() {
        // Platform gems append `-<platform>` to the base name-version; the
        // platform must be stripped so the base PURL matches the manifest.
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5-x86_64-linux"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5-arm64-darwin"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("sassc-2.4.0-java"),
            Some(("sassc".to_string(), "2.4.0".to_string()))
        );
        // Platform with a trailing OS version number must not leak into
        // the gem version (regression: a "last dash-digit" parser would
        // split on `-21`).
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5-universal-darwin-21"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        // A name with an embedded version-like number resolves at the
        // first dash-digit boundary.
        assert_eq!(
            RubyCrawler::parse_dir_name_version("libv8-node-18.16.0.0-x86_64-linux"),
            Some(("libv8-node".to_string(), "18.16.0.0".to_string()))
        );
    }

    #[tokio::test]
    async fn test_find_by_purls_gem() {
        let dir = tempfile::tempdir().unwrap();
        let rails_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(rails_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec![
            "pkg:gem/rails@7.1.0".to_string(),
            "pkg:gem/nokogiri@1.16.5".to_string(),
        ];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:gem/rails@7.1.0"));
        assert!(!result.contains_key("pkg:gem/nokogiri@1.16.5"));
    }

    #[tokio::test]
    async fn test_crawl_all_gems() {
        let dir = tempfile::tempdir().unwrap();

        // Create fake gem directories with lib/
        let rails_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(rails_dir.join("lib"))
            .await
            .unwrap();

        let nokogiri_dir = dir.path().join("nokogiri-1.16.5");
        tokio::fs::create_dir_all(nokogiri_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:gem/rails@7.1.0"));
        assert!(purls.contains("pkg:gem/nokogiri@1.16.5"));
    }

    #[tokio::test]
    async fn test_get_gem_paths_with_vendor_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_gems = dir
            .path()
            .join("vendor")
            .join("bundle")
            .join("ruby")
            .join("3.2.0")
            .join("gems");
        tokio::fs::create_dir_all(&vendor_gems).await.unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths(dir.path()).await;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vendor_gems);
    }

    #[tokio::test]
    async fn test_deduplication() {
        let dir = tempfile::tempdir().unwrap();

        // Create a single gem directory
        let rails_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(rails_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:gem/rails@7.1.0");
    }

    #[tokio::test]
    async fn test_verify_gem_with_gemspec() {
        let dir = tempfile::tempdir().unwrap();
        let gem_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(&gem_dir).await.unwrap();
        tokio::fs::write(gem_dir.join("rails.gemspec"), "# gemspec")
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        assert!(crawler.verify_gem_at_path(&gem_dir).await);
    }

    #[tokio::test]
    async fn test_verify_gem_empty_dir_fails() {
        let dir = tempfile::tempdir().unwrap();
        let gem_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(&gem_dir).await.unwrap();

        let crawler = RubyCrawler::new();
        assert!(!crawler.verify_gem_at_path(&gem_dir).await);
    }

    /// `"-1.0.0"` — match_indices finds `i=0` (followed by `1`), the
    /// name slice is empty. The defensive empty-name guard at the
    /// bottom of parse_dir_name_version rejects rather than producing
    /// a `Gem("", "1.0.0")` ghost.
    #[test]
    fn test_parse_dir_name_version_empty_name_guard() {
        assert_eq!(RubyCrawler::parse_dir_name_version("-1.0.0"), None);
    }

    // ── platform-suffix resolution end-to-end ─────────────────────

    /// `find_by_purls` must resolve a base PURL to a platform gem dir
    /// that carries a `-<platform>` suffix on disk. Exercises the
    /// `locate_gem_dir` prefix-scan fallback, which the original
    /// suite only covered for the exact (plain-platform) case.
    #[tokio::test]
    async fn find_by_purls_resolves_platform_suffixed_dir() {
        let dir = tempfile::tempdir().unwrap();
        let plat_dir = dir.path().join("nokogiri-1.16.5-x86_64-linux");
        tokio::fs::create_dir_all(plat_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/nokogiri@1.16.5".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = result.get("pkg:gem/nokogiri@1.16.5").unwrap();
        assert_eq!(pkg.version, "1.16.5");
        assert_eq!(pkg.path, plat_dir);
    }

    /// A base PURL must NOT resolve to a platform dir whose version is
    /// merely a prefix of the requested one (`1.0` vs `1.0.0`).
    #[tokio::test]
    async fn find_by_purls_rejects_version_prefix_collision() {
        let dir = tempfile::tempdir().unwrap();
        let plat_dir = dir.path().join("foo-1.0.0-x86_64-linux");
        tokio::fs::create_dir_all(plat_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        // Request version "1.0" — must not match the installed "1.0.0".
        let purls = vec!["pkg:gem/foo@1.0".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "1.0 must not match foo-1.0.0-*; got {result:?}"
        );
    }

    /// `crawl_all` must strip the platform suffix when building the
    /// PURL while keeping `path` pointed at the real (platform) dir.
    #[tokio::test]
    async fn crawl_all_strips_platform_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let plat_dir = dir.path().join("nokogiri-1.16.5-arm64-darwin");
        tokio::fs::create_dir_all(plat_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };
        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:gem/nokogiri@1.16.5");
        assert_eq!(packages[0].version, "1.16.5");
        assert_eq!(packages[0].path, plat_dir);
    }

    /// A plain `<name>-<version>` dir must win over any platform
    /// sibling when both are present (exact match short-circuits).
    #[tokio::test]
    async fn locate_gem_dir_prefers_exact_over_platform() {
        let dir = tempfile::tempdir().unwrap();
        let exact = dir.path().join("rails-7.1.0");
        let plat = dir.path().join("rails-7.1.0-x86_64-linux");
        tokio::fs::create_dir_all(exact.join("lib")).await.unwrap();
        tokio::fs::create_dir_all(plat.join("lib")).await.unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/rails@7.1.0".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();
        assert_eq!(result.get("pkg:gem/rails@7.1.0").unwrap().path, exact);
    }

    // ── gem env gempath splitting (OS path separator) ─────────────

    /// `gem env gempath` lists several gem homes joined by the OS path
    /// separator. The splitter must use the platform separator, not a
    /// hardcoded `:` — otherwise Windows drive-letter paths (`C:\…;D:\…`)
    /// are shredded. Building the input with `std::env::join_paths` makes
    /// this assertion exercise the real platform separator: a regression
    /// to `split(':')` fails on Windows (join uses `;`) while staying
    /// correct on Unix.
    #[test]
    fn gem_homes_split_honors_os_separator() {
        let home_a = PathBuf::from(if cfg!(windows) {
            r"C:\rubies\3.2.0"
        } else {
            "/opt/rubies/3.2.0"
        });
        let home_b = PathBuf::from(if cfg!(windows) {
            r"D:\gems\global"
        } else {
            "/home/dev/.gem/ruby/3.2.0"
        });
        let joined = std::env::join_paths([&home_a, &home_b]).unwrap();
        let joined = joined.to_str().unwrap();

        let dirs = gem_homes_to_gems_dirs(joined);
        assert_eq!(
            dirs,
            vec![home_a.join("gems"), home_b.join("gems")],
            "gempath {joined:?} must split on the OS separator into per-home gems/ dirs"
        );
    }

    /// Empty segments (leading/trailing/double separators) are dropped so
    /// we never probe a bare `gems/` relative to the cwd.
    #[test]
    fn gem_homes_split_drops_empty_segments() {
        let sep = if cfg!(windows) { ';' } else { ':' };
        let only = if cfg!(windows) {
            r"C:\rubies\3.2.0"
        } else {
            "/opt/rubies/3.2.0"
        };
        let input = format!("{sep}{only}{sep}{sep}");
        let dirs = gem_homes_to_gems_dirs(&input);
        assert_eq!(dirs, vec![PathBuf::from(only).join("gems")]);
        assert!(gem_homes_to_gems_dirs("").is_empty());
    }

    // ── crawl/parse robustness regressions ────────────────────────

    /// A base PURL must not resolve to a *plain* dir whose version merely
    /// shares the requested version as a dotted prefix (`1.0` vs `1.0.0`).
    /// Complements the platform-suffixed collision test.
    #[tokio::test]
    async fn find_by_purls_rejects_plain_version_prefix_collision() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        let crawler = RubyCrawler::new();
        let result = crawler
            .find_by_purls(dir.path(), &["pkg:gem/foo@1.0".to_string()])
            .await
            .unwrap();
        assert!(
            result.is_empty(),
            "1.0 wrongly matched plain foo-1.0.0: {result:?}"
        );
    }

    /// `crawl_all` must skip dirs that parse as `<name>-<version>` but are
    /// not gems (no `lib/`, no `.gemspec`) and must ignore `.gem` cache
    /// files that string-match the `<name>-<version>` pattern.
    #[tokio::test]
    async fn crawl_all_skips_non_gem_dirs_and_cache_files() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("rails-7.1.0").join("lib"))
            .await
            .unwrap();
        // Parses as a gem name but has no lib/ or gemspec — not a gem.
        tokio::fs::create_dir_all(dir.path().join("junk-1.0.0"))
            .await
            .unwrap();
        // A cached `.gem` archive (a file, not a dir) that matches the pattern.
        tokio::fs::write(dir.path().join("rails-7.1.0.gem"), b"x")
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };
        let packages = crawler.crawl_all(&options).await;
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(purls, HashSet::from(["pkg:gem/rails@7.1.0"]));
    }

    /// A requested version that is *longer* than what is installed must
    /// not resolve. The prefix scan keys on `<name>-<version>-`, so a
    /// requested `1.0.0` must reject both a plain `foo-1.0/` and a
    /// platform `foo-1.0-x86_64-linux/` (installed version `1.0`). Guards
    /// against a future change that compares versions bidirectionally.
    #[tokio::test]
    async fn find_by_purls_rejects_longer_requested_version() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("foo-1.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join("foo-1.0-x86_64-linux").join("lib"))
            .await
            .unwrap();
        let crawler = RubyCrawler::new();
        let result = crawler
            .find_by_purls(dir.path(), &["pkg:gem/foo@1.0.0".to_string()])
            .await
            .unwrap();
        assert!(
            result.is_empty(),
            "1.0.0 must not match installed 1.0 dirs: {result:?}"
        );
    }

    /// The exact-match arm of `locate_gem_dir` must *verify gem content*,
    /// not merely accept that `<name>-<version>/` exists on disk. When the
    /// exact dir is present but empty (no `lib/`, no `.gemspec` — a
    /// malformed/partial install), resolution must fall through to a valid
    /// platform sibling rather than returning the hollow exact dir.
    #[tokio::test]
    async fn locate_gem_dir_skips_invalid_exact_for_valid_platform() {
        let dir = tempfile::tempdir().unwrap();
        // Exact dir exists but is hollow — not a real gem.
        tokio::fs::create_dir_all(dir.path().join("nokogiri-1.16.5"))
            .await
            .unwrap();
        // Valid platform sibling.
        let plat = dir.path().join("nokogiri-1.16.5-x86_64-linux");
        tokio::fs::create_dir_all(plat.join("lib")).await.unwrap();

        let crawler = RubyCrawler::new();
        let result = crawler
            .find_by_purls(dir.path(), &["pkg:gem/nokogiri@1.16.5".to_string()])
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("pkg:gem/nokogiri@1.16.5").unwrap().path, plat);
    }

    /// `parse_gem_env_output` is the pure parser for `gem env <key>`
    /// stdout: empty/whitespace-only input yields `None` (gem absent or no
    /// path), and surrounding whitespace/newlines are trimmed off a real
    /// path so it joins cleanly with `gems/`.
    #[test]
    fn parse_gem_env_output_contract() {
        assert_eq!(parse_gem_env_output(""), None);
        assert_eq!(parse_gem_env_output("   \n\t "), None);
        assert_eq!(
            parse_gem_env_output("  /usr/lib/ruby/gems/3.2.0\n"),
            Some("/usr/lib/ruby/gems/3.2.0".to_string())
        );
    }

    /// Local mode must not walk the global gem store for a non-Ruby
    /// project: with no `vendor/bundle/ruby/` and neither `Gemfile` nor
    /// `Gemfile.lock` present, `get_gem_paths` returns empty (it never even
    /// shells out to `gem env`). This pins the project-detection gate that
    /// keeps a JS/Python checkout from being scanned as Ruby.
    #[tokio::test]
    async fn get_gem_paths_empty_for_non_ruby_project() {
        let dir = tempfile::tempdir().unwrap();
        // A decoy non-Ruby file; no Gemfile, no vendor/bundle/ruby.
        tokio::fs::write(dir.path().join("package.json"), b"{}")
            .await
            .unwrap();
        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let paths = crawler.get_gem_paths(&options).await.unwrap();
        assert!(
            paths.is_empty(),
            "non-Ruby project must yield no gem paths: {paths:?}"
        );
    }

    // ── PURL coordinate traversal (untrusted manifest input) ──────

    /// A tampered manifest PURL whose name carries `..` must not resolve
    /// to a directory outside the gem root. `locate_gem_dir` joins
    /// `<name>-<version>` straight onto `gem_path`, and
    /// `verify_gem_at_path` only checks for `lib/`/`.gemspec`, so without
    /// a coordinate gate `pkg:gem/../outside@1.0.0` escapes the gem store
    /// and the patch applies in place out of tree.
    #[tokio::test]
    async fn find_by_purls_rejects_traversal_coordinates() {
        let dir = tempfile::tempdir().unwrap();
        let gems = dir.path().join("gems");
        tokio::fs::create_dir_all(&gems).await.unwrap();
        // A verifying "gem" OUTSIDE the gem root that `..` escapes to.
        tokio::fs::create_dir_all(dir.path().join("outside-1.0.0").join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/../outside@1.0.0".to_string()];
        let result = crawler.find_by_purls(&gems, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "`..` name must not escape the gem root: {result:?}"
        );
    }

    /// An absolute path smuggled in as the gem name replaces the gem root
    /// wholesale in `Path::join` — must be rejected fail-closed.
    #[tokio::test]
    async fn find_by_purls_rejects_absolute_coordinates() {
        let dir = tempfile::tempdir().unwrap();
        let gems = dir.path().join("gems");
        tokio::fs::create_dir_all(&gems).await.unwrap();
        let outside = dir.path().join("abs");
        tokio::fs::create_dir_all(outside.join("evil-1.0.0").join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purl = format!("pkg:gem/{}@1.0.0", outside.join("evil").display());
        let result = crawler.find_by_purls(&gems, &[purl]).await.unwrap();
        assert!(
            result.is_empty(),
            "absolute name must not replace the gem root: {result:?}"
        );
    }

    /// A separator smuggled into the *version* half of the coordinate is
    /// just as dangerous as one in the name — both halves are formatted
    /// into the joined `<name>-<version>` segment.
    #[tokio::test]
    async fn find_by_purls_rejects_separator_in_version() {
        let dir = tempfile::tempdir().unwrap();
        let gems = dir.path().join("gems");
        tokio::fs::create_dir_all(&gems).await.unwrap();
        // `foo-1.0/../../outside-1.0.0` needs `foo-1.0` to traverse through.
        tokio::fs::create_dir_all(gems.join("foo-1.0"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join("outside-1.0.0").join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/foo@1.0/../../outside-1.0.0".to_string()];
        let result = crawler.find_by_purls(&gems, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "version with separators must not escape the gem root: {result:?}"
        );
    }

    /// Unit contract for the coordinate gate: real gem names/versions pass,
    /// anything with a separator, NUL, or bare dot segment fails closed.
    #[test]
    fn test_is_safe_gem_coordinate() {
        assert!(is_safe_gem_coordinate("rails", "7.1.0"));
        assert!(is_safe_gem_coordinate("aws-sdk-s3", "1.143.0"));
        assert!(is_safe_gem_coordinate("ruby2_keywords", "0.0.5"));
        assert!(is_safe_gem_coordinate("nokogiri", "1.16.5.pre.rc1"));

        assert!(!is_safe_gem_coordinate("", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", ""));
        assert!(!is_safe_gem_coordinate("..", "1.0.0"));
        assert!(!is_safe_gem_coordinate(".", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", ".."));
        assert!(!is_safe_gem_coordinate("../outside", "1.0.0"));
        assert!(!is_safe_gem_coordinate("a/b", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", "1.0/../../x"));
        assert!(!is_safe_gem_coordinate("a\\b", "1.0.0"));
        assert!(!is_safe_gem_coordinate("a\0b", "1.0.0"));
        assert!(!is_safe_gem_coordinate("/abs/evil", "1.0.0"));
        // Windows drive-relative escape: a `:` (e.g. `C:evil`) makes the
        // joined path absolute under `Path::join`.
        assert!(!is_safe_gem_coordinate("C:evil", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", "C:1.0.0"));
    }

    /// Gem names with embedded underscores/digits and multi-dash names
    /// must keep their full name; the version starts at the first
    /// dash-then-digit boundary.
    #[test]
    fn parse_dir_name_version_name_shapes() {
        assert_eq!(
            RubyCrawler::parse_dir_name_version("ruby2_keywords-0.0.5"),
            Some(("ruby2_keywords".to_string(), "0.0.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("aws-sdk-s3-1.143.0"),
            Some(("aws-sdk-s3".to_string(), "1.143.0".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("concurrent-ruby-1.2.3"),
            Some(("concurrent-ruby".to_string(), "1.2.3".to_string()))
        );
    }
}
