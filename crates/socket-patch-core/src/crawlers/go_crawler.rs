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
            } else {
                // A lone trailing `!` is not a valid escape — Go's encoder
                // never emits one. Preserve it rather than silently dropping
                // it, so decoding an unexpected/corrupt directory name never
                // loses bytes from the path.
                decoded.push('!');
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
            // `module` must be a whole token: the directive is followed by
            // whitespace. Without this guard, lines like `modulepath = x`
            // would be misparsed as a module declaration.
            if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
                continue;
            }
            // Strip a trailing line comment (`module foo // note`). Module
            // paths never contain `//`, so the first occurrence is the comment.
            let rest = match rest.find("//") {
                Some(idx) => &rest[..idx],
                None => rest,
            };
            let rest = rest.trim();
            // Handle quoted module paths
            if rest.len() >= 2 && rest.starts_with('"') && rest.ends_with('"') {
                let inner = &rest[1..rest.len() - 1];
                // A quoted-but-empty path (`module ""`) is malformed: Go
                // module paths are never empty. Treat it as absent rather
                // than returning `Some("")`, which would later build a
                // bogus PURL like `pkg:golang/@<version>`. A go.mod has at
                // most one `module` directive, so skipping here falls
                // through to `None`.
                if inner.is_empty() {
                    continue;
                }
                return Some(inner.to_string());
            }
            // Unquoted module path. The `module` directive takes a SINGLE
            // token, so a line like `module foo bar` is malformed (Go rejects
            // it outright). Return only the first whitespace-delimited token
            // rather than the whole remainder (`"foo bar"`), which would build
            // a bogus PURL with a space in the module path and break the later
            // `split_module_path` namespace/name split.
            if let Some(token) = rest.split_whitespace().next() {
                return Some(token.to_string());
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
                // Encode the module path AND the version for the filesystem.
                // Go case-escapes both halves of the directory name, so a
                // version like `v1.0.0-RC1` must be looked up as
                // `v1.0.0-!r!c1` or the directory is never found.
                let encoded = encode_module_path(module_path);
                let encoded_version = encode_module_path(version);

                // Go module cache layout: <encoded-module-path>@<encoded-version>/
                let module_dir = cache_path.join(format!("{encoded}@{encoded_version}"));

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
            // GOPATH may list several directories separated by the OS path
            // separator (`:` on Unix, `;` on Windows). Go uses the FIRST
            // entry for the module cache, so split rather than treating the
            // whole value as a single path.
            if let Some(first) = std::env::split_paths(&gopath).find(|p| !p.as_os_str().is_empty())
            {
                return Some(first.join("pkg").join("mod"));
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
            for entry in crate::utils::fs::list_dir_entries(current_path).await {
                if !crate::utils::fs::entry_is_dir(&entry).await {
                    continue;
                }

                let dir_name = entry.file_name();
                let dir_name_str = dir_name.to_string_lossy();

                // Skip hidden directories anywhere, and the module cache's
                // `cache/` metadata directory — but ONLY at the cache root.
                // The download cache lives at `<root>/cache`; a `cache` path
                // component deeper in the tree is a legitimate module name
                // (e.g. `github.com/go-redis/cache/v9@v9.0.0`) and must not be
                // pruned, or the versioned dir beneath it is never discovered.
                if dir_name_str.starts_with('.')
                    || (dir_name_str == "cache" && current_path == base_path)
                {
                    continue;
                }

                // Build the child path from the raw `OsStr` rather than the
                // lossy UTF-8 rendering, so non-UTF-8 directory names still
                // resolve to the correct on-disk path.
                let full_path = current_path.join(entry.file_name());

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
        // Get the relative path from the cache root.
        // Normalize to forward slashes so PURLs are correct on Windows.
        let rel_path = dir_path.strip_prefix(base_path).ok()?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");

        // Find the last `@` to split module path and version
        let at_idx = rel_str.rfind('@')?;
        let encoded_module_path = &rel_str[..at_idx];
        let version = &rel_str[at_idx + 1..];

        if encoded_module_path.is_empty() || version.is_empty() {
            return None;
        }

        // Decode case-encoding. Go escapes uppercase letters in BOTH the
        // module path and the version, so a pre-release tag such as
        // `v1.0.0-RC1` lands on disk as `v1.0.0-!r!c1`. Decoding only the
        // path would leave an escaped version in the PURL.
        let module_path = decode_module_path(encoded_module_path);
        let version = decode_module_path(version);

        let purl = crate::utils::purl::build_golang_purl(&module_path, &version);

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
    fn test_parse_go_mod_module_empty_quoted_path() {
        // A quoted-but-empty module path is malformed and must not yield
        // `Some("")` (which would later build a bogus `pkg:golang/@...`
        // PURL). Mirrors the bare-`module` empty-path regression test.
        assert_eq!(parse_go_mod_module("module \"\"\n\ngo 1.21\n"), None);
        // Whitespace-padded variant is equally malformed.
        assert_eq!(parse_go_mod_module("  module \"\"  \n"), None);
    }

    #[test]
    fn test_parse_go_mod_module_multi_token_unquoted() {
        // `module` takes a single token; a multi-token unquoted line is
        // malformed. We must not return the whole remainder (`"foo bar"`),
        // which would build a bogus PURL with an embedded space. Take the
        // first token only.
        assert_eq!(
            parse_go_mod_module("module github.com/foo/bar extra junk\ngo 1.21\n"),
            Some("github.com/foo/bar".to_string())
        );
        // Trailing whitespace alone must not be treated as a second token.
        assert_eq!(
            parse_go_mod_module("module github.com/foo/bar   \n"),
            Some("github.com/foo/bar".to_string())
        );
    }

    #[test]
    fn test_decode_module_path_lone_trailing_bang_preserved() {
        // A lone trailing `!` is not a valid Go escape. Decoding must not
        // silently drop it (data loss on a corrupt directory name) — it is
        // preserved verbatim instead.
        assert_eq!(decode_module_path("foo!"), "foo!");
        assert_eq!(decode_module_path("github.com/foo!"), "github.com/foo!");
        // A valid escape followed by a lone trailing `!` keeps both.
        assert_eq!(decode_module_path("!azure!"), "Azure!");
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
        assert_eq!(packages[0].namespace, Some("github.com/Azure".to_string()));
    }

    /// `rel_str = "@v1.0.0"` — the dir literally lives at the cache
    /// root with a leading `@`. `rfind('@')` returns 0,
    /// `encoded_module_path = ""`. The empty-prefix guard in
    /// parse_versioned_dir must return None rather than emit a
    /// `("", "v1.0.0")` ghost package with an empty module path.
    #[test]
    fn test_parse_versioned_dir_empty_module_path_guard() {
        let base = std::path::Path::new("/cache");
        let dir = std::path::Path::new("/cache/@v1.0.0");
        let mut seen = HashSet::new();
        let crawler = GoCrawler;
        let result = crawler.parse_versioned_dir(base, dir, "@v1.0.0", &mut seen);
        assert!(
            result.is_none(),
            "empty encoded module path must yield None"
        );
    }

    // -- Regression tests -------------------------------------------------

    #[test]
    fn test_parse_go_mod_module_trailing_comment() {
        // A trailing line comment must not leak into the module path.
        let content = "module github.com/gin-gonic/gin // indirect note\n\ngo 1.21\n";
        assert_eq!(
            parse_go_mod_module(content),
            Some("github.com/gin-gonic/gin".to_string())
        );
    }

    #[test]
    fn test_parse_go_mod_module_word_boundary() {
        // `module` must be a whole token; `modulepath` is not the directive.
        let content = "modulepath github.com/should/not/match\ngo 1.21\n";
        assert_eq!(parse_go_mod_module(content), None);
    }

    #[tokio::test]
    async fn test_crawl_finds_module_with_cache_path_component() {
        // The `cache` skip must only apply at the cache root, not to a
        // legitimate `cache` segment inside a module path. Without the
        // fix, `github.com/go-redis/cache/v9@v9.0.0` is pruned entirely.
        let dir = tempfile::tempdir().unwrap();

        let cache_module = dir
            .path()
            .join("github.com")
            .join("go-redis")
            .join("cache")
            .join("v9@v9.0.0");
        tokio::fs::create_dir_all(&cache_module).await.unwrap();

        // And the real top-level `cache/` metadata dir must still be skipped.
        let metadata = dir.path().join("cache").join("download").join("sumdb");
        tokio::fs::create_dir_all(&metadata).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(packages.len(), 1, "only the real module should be found");
        assert!(purls.contains("pkg:golang/github.com/go-redis/cache/v9@v9.0.0"));
    }

    #[tokio::test]
    async fn test_crawl_decodes_uppercase_version() {
        // Go case-escapes uppercase letters in the version too. A pre-release
        // tag `v1.0.0-RC1` is stored on disk as `v1.0.0-!r!c1` and must be
        // decoded back when forming the PURL.
        let dir = tempfile::tempdir().unwrap();

        let module_dir = dir
            .path()
            .join("github.com")
            .join("foo")
            .join("bar@v1.0.0-!r!c1");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].version, "v1.0.0-RC1");
        assert_eq!(packages[0].purl, "pkg:golang/github.com/foo/bar@v1.0.0-RC1");
    }

    #[tokio::test]
    async fn test_find_by_purls_uppercase_version() {
        // Lookup must escape the version to match the on-disk directory.
        let dir = tempfile::tempdir().unwrap();

        let module_dir = dir
            .path()
            .join("github.com")
            .join("foo")
            .join("bar@v1.0.0-!r!c1");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let purls = vec!["pkg:golang/github.com/foo/bar@v1.0.0-RC1".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = &result["pkg:golang/github.com/foo/bar@v1.0.0-RC1"];
        assert_eq!(pkg.name, "bar");
        assert_eq!(pkg.version, "v1.0.0-RC1");
    }
}
