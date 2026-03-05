#![cfg(feature = "golang")]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};

// ---------------------------------------------------------------------------
// Case-encoding helpers
// ---------------------------------------------------------------------------

/// Encode a Go module path for the filesystem.
///
/// Go's module cache uses case-encoding: uppercase letters are replaced
/// with `!` followed by the lowercase letter.
/// e.g., `"github.com/Azure/azure-sdk"` -> `"github.com/!azure/azure-sdk"`
pub fn encode_module_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for ch in path.chars() {
        if ch.is_ascii_uppercase() {
            encoded.push('!');
            encoded.push(ch.to_ascii_lowercase());
        } else {
            encoded.push(ch);
        }
    }
    encoded
}

/// Decode a case-encoded Go module path.
///
/// Reverses the encoding: `!` followed by a lowercase letter becomes the
/// uppercase letter.
/// e.g., `"github.com/!azure/azure-sdk"` -> `"github.com/Azure/azure-sdk"`
pub fn decode_module_path(encoded: &str) -> String {
    let mut decoded = String::with_capacity(encoded.len());
    let mut chars = encoded.chars();
    while let Some(ch) = chars.next() {
        if ch == '!' {
            if let Some(next) = chars.next() {
                decoded.push(next.to_ascii_uppercase());
            }
        } else {
            decoded.push(ch);
        }
    }
    decoded
}

/// Parse the `module` directive from a go.mod file.
///
/// Returns the module path, e.g., `"github.com/gin-gonic/gin"`.
pub fn parse_go_mod_module(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("module") {
            let rest = rest.trim();
            // Handle quoted module paths
            if rest.starts_with('"') && rest.ends_with('"') && rest.len() >= 2 {
                return Some(rest[1..rest.len() - 1].to_string());
            }
            // Unquoted module path
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// GoCrawler
// ---------------------------------------------------------------------------

/// Go module ecosystem crawler for discovering modules in the Go module cache
/// (`$GOMODCACHE` or `$GOPATH/pkg/mod/`).
pub struct GoCrawler;

impl GoCrawler {
    /// Create a new `GoCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get the Go module cache paths.
    ///
    /// In global mode (or with `--global-prefix`), returns the module cache
    /// directory directly.
    ///
    /// In local mode, only returns the cache path if the cwd contains a
    /// `go.mod` or `go.sum` file (i.e., is a Go project).
    pub async fn get_module_cache_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(Self::get_gomodcache().map_or_else(Vec::new, |p| vec![p]));
        }

        // Local mode: only scan if this looks like a Go project
        let has_go_mod = tokio::fs::metadata(options.cwd.join("go.mod"))
            .await
            .is_ok();
        let has_go_sum = tokio::fs::metadata(options.cwd.join("go.sum"))
            .await
            .is_ok();

        if has_go_mod || has_go_sum {
            return Ok(Self::get_gomodcache().map_or_else(Vec::new, |p| vec![p]));
        }

        // Not a Go project — return empty
        Ok(Vec::new())
    }

    /// Crawl the Go module cache and return all discovered packages.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let cache_paths = self
            .get_module_cache_paths(options)
            .await
            .unwrap_or_default();

        for cache_path in &cache_paths {
            let found = self.scan_module_cache(cache_path, &mut seen).await;
            packages.extend(found);
        }

        packages
    }

    /// Find specific packages by PURL in the module cache.
    pub async fn find_by_purls(
        &self,
        cache_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            if let Some((module_path, version)) = crate::utils::purl::parse_golang_purl(purl) {
                // Encode the module path for the filesystem
                let encoded = encode_module_path(module_path);

                // Go module cache layout: <encoded-module-path>@<version>/
                let module_dir = cache_path.join(format!("{encoded}@{version}"));

                if is_dir(&module_dir).await {
                    // Split module_path into namespace and name
                    let (namespace, name) = split_module_path(module_path);

                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: Some(namespace.to_string()),
                            purl: purl.clone(),
                            path: module_dir,
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

    /// Get `GOMODCACHE`, falling back to `$GOPATH/pkg/mod/` or `$HOME/go/pkg/mod/`.
    fn get_gomodcache() -> Option<PathBuf> {
        if let Ok(cache) = std::env::var("GOMODCACHE") {
            let p = PathBuf::from(cache);
            if !p.as_os_str().is_empty() {
                return Some(p);
            }
        }
        if let Ok(gopath) = std::env::var("GOPATH") {
            let p = PathBuf::from(gopath);
            if !p.as_os_str().is_empty() {
                return Some(p.join("pkg").join("mod"));
            }
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        Some(PathBuf::from(home).join("go").join("pkg").join("mod"))
    }

    /// Recursively scan the module cache directory tree.
    ///
    /// Go module cache has a hierarchical structure:
    /// `<cache>/github.com/user/project@v1.0.0/`
    ///
    /// We walk the tree looking for directories whose name contains `@`
    /// (the version separator), which marks a versioned module.
    async fn scan_module_cache(
        &self,
        cache_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();
        self.scan_dir_recursive(cache_path, cache_path, seen, &mut results)
            .await;
        results
    }

    fn scan_dir_recursive<'a>(
        &'a self,
        base_path: &'a Path,
        current_path: &'a Path,
        seen: &'a mut HashSet<String>,
        results: &'a mut Vec<CrawledPackage>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>> {
        Box::pin(async move {
            let mut entries = match tokio::fs::read_dir(current_path).await {
                Ok(rd) => rd,
                Err(_) => return,
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

                // Skip hidden directories and the cache metadata directory
                if dir_name_str.starts_with('.') || dir_name_str == "cache" {
                    continue;
                }

                let full_path = current_path.join(&*dir_name_str);

                // Check if this directory has `@` in its name (versioned module)
                if dir_name_str.contains('@') {
                    if let Some(pkg) =
                        self.parse_versioned_dir(base_path, &full_path, &dir_name_str, seen)
                    {
                        results.push(pkg);
                    }
                } else {
                    // Recurse into subdirectories
                    self.scan_dir_recursive(base_path, &full_path, seen, results)
                        .await;
                }
            }
        })
    }

    /// Parse a versioned directory (containing `@`) into a `CrawledPackage`.
    fn parse_versioned_dir(
        &self,
        base_path: &Path,
        dir_path: &Path,
        _dir_name: &str,
        seen: &mut HashSet<String>,
    ) -> Option<CrawledPackage> {
        // Get the relative path from the cache root
        let rel_path = dir_path.strip_prefix(base_path).ok()?;
        let rel_str = rel_path.to_string_lossy();

        // Find the last `@` to split module path and version
        let at_idx = rel_str.rfind('@')?;
        let encoded_module_path = &rel_str[..at_idx];
        let version = &rel_str[at_idx + 1..];

        if encoded_module_path.is_empty() || version.is_empty() {
            return None;
        }

        // Decode case-encoded path
        let module_path = decode_module_path(encoded_module_path);

        let purl = crate::utils::purl::build_golang_purl(&module_path, version);

        if seen.contains(&purl) {
            return None;
        }
        seen.insert(purl.clone());

        let (namespace, name) = split_module_path(&module_path);

        Some(CrawledPackage {
            name: name.to_string(),
            version: version.to_string(),
            namespace: Some(namespace.to_string()),
            purl,
            path: dir_path.to_path_buf(),
        })
    }
}

impl Default for GoCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Split a module path into (namespace, name).
///
/// e.g., `"github.com/gin-gonic/gin"` -> `("github.com/gin-gonic", "gin")`
/// e.g., `"golang.org/x/text"` -> `("golang.org/x", "text")`
fn split_module_path(module_path: &str) -> (&str, &str) {
    match module_path.rfind('/') {
        Some(idx) => (&module_path[..idx], &module_path[idx + 1..]),
        None => ("", module_path),
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
    fn test_encode_module_path_no_uppercase() {
        assert_eq!(
            encode_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
    }

    #[test]
    fn test_encode_module_path_with_uppercase() {
        assert_eq!(
            encode_module_path("github.com/Azure/azure-sdk-for-go"),
            "github.com/!azure/azure-sdk-for-go"
        );
    }

    #[test]
    fn test_encode_module_path_multiple_uppercase() {
        assert_eq!(
            encode_module_path("github.com/BurntSushi/toml"),
            "github.com/!burnt!sushi/toml"
        );
    }

    #[test]
    fn test_decode_module_path_no_encoding() {
        assert_eq!(
            decode_module_path("github.com/gin-gonic/gin"),
            "github.com/gin-gonic/gin"
        );
    }

    #[test]
    fn test_decode_module_path_with_encoding() {
        assert_eq!(
            decode_module_path("github.com/!azure/azure-sdk-for-go"),
            "github.com/Azure/azure-sdk-for-go"
        );
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = "github.com/Azure/azure-sdk-for-go";
        assert_eq!(decode_module_path(&encode_module_path(original)), original);

        let original2 = "github.com/BurntSushi/toml";
        assert_eq!(
            decode_module_path(&encode_module_path(original2)),
            original2
        );

        let original3 = "github.com/gin-gonic/gin";
        assert_eq!(
            decode_module_path(&encode_module_path(original3)),
            original3
        );
    }

    #[test]
    fn test_parse_go_mod_module_basic() {
        let content = "module github.com/gin-gonic/gin\n\ngo 1.21\n";
        assert_eq!(
            parse_go_mod_module(content),
            Some("github.com/gin-gonic/gin".to_string())
        );
    }

    #[test]
    fn test_parse_go_mod_module_quoted() {
        let content = "module \"github.com/gin-gonic/gin\"\n\ngo 1.21\n";
        assert_eq!(
            parse_go_mod_module(content),
            Some("github.com/gin-gonic/gin".to_string())
        );
    }

    #[test]
    fn test_parse_go_mod_module_missing() {
        let content = "go 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n";
        assert_eq!(parse_go_mod_module(content), None);
    }

    #[test]
    fn test_split_module_path() {
        let (ns, name) = split_module_path("github.com/gin-gonic/gin");
        assert_eq!(ns, "github.com/gin-gonic");
        assert_eq!(name, "gin");

        let (ns, name) = split_module_path("golang.org/x/text");
        assert_eq!(ns, "golang.org/x");
        assert_eq!(name, "text");

        let (ns, name) = split_module_path("gopkg.in/yaml.v3");
        assert_eq!(ns, "gopkg.in");
        assert_eq!(name, "yaml.v3");
    }

    #[tokio::test]
    async fn test_find_by_purls_basic() {
        let dir = tempfile::tempdir().unwrap();

        // Create a fake module directory: github.com/gin-gonic/gin@v1.9.1
        let module_dir = dir
            .path()
            .join("github.com")
            .join("gin-gonic")
            .join("gin@v1.9.1");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let purls = vec![
            "pkg:golang/github.com/gin-gonic/gin@v1.9.1".to_string(),
            "pkg:golang/github.com/missing/pkg@v0.1.0".to_string(),
        ];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:golang/github.com/gin-gonic/gin@v1.9.1"));
        assert!(!result.contains_key("pkg:golang/github.com/missing/pkg@v0.1.0"));

        let pkg = &result["pkg:golang/github.com/gin-gonic/gin@v1.9.1"];
        assert_eq!(pkg.name, "gin");
        assert_eq!(pkg.version, "v1.9.1");
        assert_eq!(pkg.namespace, Some("github.com/gin-gonic".to_string()));
    }

    #[tokio::test]
    async fn test_find_by_purls_case_encoded() {
        let dir = tempfile::tempdir().unwrap();

        // Create a case-encoded module directory
        let module_dir = dir
            .path()
            .join("github.com")
            .join("!azure")
            .join("azure-sdk-for-go@v1.0.0");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let purls = vec!["pkg:golang/github.com/Azure/azure-sdk-for-go@v1.0.0".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = &result["pkg:golang/github.com/Azure/azure-sdk-for-go@v1.0.0"];
        assert_eq!(pkg.name, "azure-sdk-for-go");
        assert_eq!(pkg.namespace, Some("github.com/Azure".to_string()));
    }

    #[tokio::test]
    async fn test_crawl_all_tempdir() {
        let dir = tempfile::tempdir().unwrap();

        // Create fake module directories
        let gin_dir = dir
            .path()
            .join("github.com")
            .join("gin-gonic")
            .join("gin@v1.9.1");
        tokio::fs::create_dir_all(&gin_dir).await.unwrap();

        let text_dir = dir.path().join("golang.org").join("x").join("text@v0.14.0");
        tokio::fs::create_dir_all(&text_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:golang/github.com/gin-gonic/gin@v1.9.1"));
        assert!(purls.contains("pkg:golang/golang.org/x/text@v0.14.0"));
    }

    #[tokio::test]
    async fn test_crawl_all_deduplication() {
        let dir = tempfile::tempdir().unwrap();

        // Create a single module
        let gin_dir = dir
            .path()
            .join("github.com")
            .join("gin-gonic")
            .join("gin@v1.9.1");
        tokio::fs::create_dir_all(&gin_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages[0].purl,
            "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
        );
    }

    #[tokio::test]
    async fn test_crawl_all_skips_cache_dir() {
        let dir = tempfile::tempdir().unwrap();

        // Create a real module
        let gin_dir = dir
            .path()
            .join("github.com")
            .join("gin-gonic")
            .join("gin@v1.9.1");
        tokio::fs::create_dir_all(&gin_dir).await.unwrap();

        // Create a "cache" dir (should be skipped)
        let cache_dir = dir.path().join("cache").join("download").join("sumdb");
        tokio::fs::create_dir_all(&cache_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
    }

    #[tokio::test]
    async fn test_local_mode_no_go_mod_returns_empty() {
        let dir = tempfile::tempdir().unwrap();

        // No go.mod or go.sum in cwd
        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: 100,
        };

        let paths = crawler.get_module_cache_paths(&options).await.unwrap();
        assert!(paths.is_empty());
    }

    #[tokio::test]
    async fn test_crawl_case_encoded_modules() {
        let dir = tempfile::tempdir().unwrap();

        // Create case-encoded module
        let azure_dir = dir
            .path()
            .join("github.com")
            .join("!azure")
            .join("azure-sdk-for-go@v1.0.0");
        tokio::fs::create_dir_all(&azure_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(
            packages[0].purl,
            "pkg:golang/github.com/Azure/azure-sdk-for-go@v1.0.0"
        );
        assert_eq!(packages[0].name, "azure-sdk-for-go");
        assert_eq!(
            packages[0].namespace,
            Some("github.com/Azure".to_string())
        );
    }
}
