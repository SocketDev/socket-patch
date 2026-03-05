use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};

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
            let mut paths = Vec::new();
            if let Some(gemdir) = Self::run_gem_env("gemdir").await {
                let gems_path = PathBuf::from(gemdir).join("gems");
                if is_dir(&gems_path).await {
                    paths.push(gems_path);
                }
            }
            if !paths.is_empty() {
                return Ok(paths);
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
                let gem_dir = gem_path.join(format!("{name}-{version}"));
                if self.verify_gem_at_path(&gem_dir).await {
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

        let mut entries = match tokio::fs::read_dir(&vendor_ruby).await {
            Ok(rd) => rd,
            Err(_) => return paths,
        };

        while let Ok(Some(entry)) = entries.next_entry().await {
            let ft = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
                let gems_dir = vendor_ruby.join(entry.file_name()).join("gems");
                if is_dir(&gems_dir).await {
                    paths.push(gems_dir);
                }
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

        // gem env gempath (colon-separated)
        if let Some(gempath) = Self::run_gem_env("gempath").await {
            for segment in gempath.split(':') {
                let segment = segment.trim();
                if segment.is_empty() {
                    continue;
                }
                let gems_path = PathBuf::from(segment).join("gems");
                if is_dir(&gems_path).await && seen.insert(gems_path.clone()) {
                    paths.push(gems_path);
                }
            }
        }

        // Fallback well-known paths
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "~".to_string());
        let home = PathBuf::from(home);

        let fallback_globs = [
            home.join(".gem").join("ruby"),
            home.join(".rbenv").join("versions"),
            home.join(".rvm").join("gems"),
        ];

        for base in &fallback_globs {
            if let Ok(mut entries) = tokio::fs::read_dir(base).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let ft = match entry.file_type().await {
                        Ok(ft) => ft,
                        Err(_) => continue,
                    };
                    if !ft.is_dir() {
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
                    if let Ok(mut sub_entries) = tokio::fs::read_dir(&lib_ruby_gems).await {
                        while let Ok(Some(sub_entry)) = sub_entries.next_entry().await {
                            let gems_dir = lib_ruby_gems.join(sub_entry.file_name()).join("gems");
                            if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                                paths.push(gems_dir);
                            }
                        }
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
            if let Ok(mut entries) = tokio::fs::read_dir(base).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let gems_dir = base.join(entry.file_name()).join("gems");
                    if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                        paths.push(gems_dir);
                    }
                }
            }
        }

        paths
    }

    /// Run `gem env <key>` and return the trimmed stdout.
    async fn run_gem_env(key: &str) -> Option<String> {
        let output = std::process::Command::new("gem")
            .args(["env", key])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            None
        } else {
            Some(stdout)
        }
    }

    /// Scan a gem directory and return all valid gem packages found.
    async fn scan_gem_dir(
        &self,
        gem_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        let mut entries = match tokio::fs::read_dir(gem_path).await {
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

            let gem_dir = gem_path.join(&*dir_name_str);

            // Parse name-version from directory name
            if let Some((name, version)) = Self::parse_dir_name_version(&dir_name_str) {
                // Verify it looks like a gem (has .gemspec or lib/)
                if !self.verify_gem_at_path(&gem_dir).await {
                    continue;
                }

                let purl = crate::utils::purl::build_gem_purl(&name, &version);

                if seen.contains(&purl) {
                    continue;
                }
                seen.insert(purl.clone());

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
        if let Ok(mut entries) = tokio::fs::read_dir(path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".gemspec") {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Parse a gem directory name into (name, version).
    ///
    /// Gem directories follow the pattern `<name>-<version>`, where the
    /// version is the last `-`-separated component that starts with a digit.
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
}

impl Default for RubyCrawler {
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

    #[tokio::test]
    async fn test_find_by_purls_gem() {
        let dir = tempfile::tempdir().unwrap();
        let rails_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(rails_dir.join("lib")).await.unwrap();

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
        tokio::fs::create_dir_all(rails_dir.join("lib")).await.unwrap();

        let nokogiri_dir = dir.path().join("nokogiri-1.16.5");
        tokio::fs::create_dir_all(nokogiri_dir.join("lib")).await.unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
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
        tokio::fs::create_dir_all(rails_dir.join("lib")).await.unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
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
}
