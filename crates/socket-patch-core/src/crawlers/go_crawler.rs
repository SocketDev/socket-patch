use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::is_dir;

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
            self.scan_dir_recursive(cache_path, cache_path, &mut seen, &mut packages)
                .await;
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
                // SECURITY: `module_path`/`version` come straight from the
                // (untrusted) manifest PURL and are joined onto the cache root
                // below. In global mode the resolved directory is patched IN
                // PLACE (no `replace`-redirect backend stands between the
                // crawler and disk), so a tampered PURL with a `..` segment
                // must not be able to escape the cache. Reject fail-closed
                // before the `is_dir` probe — the twin of the deno crawler's
                // `is_safe_jsr_component` gate.
                if !is_safe_module_coordinate(module_path, version) {
                    continue;
                }
                // Encode the module path AND the version for the filesystem.
                // Go case-escapes both halves of the directory name, so a
                // version like `v1.0.0-RC1` must be looked up as
                // `v1.0.0-!r!c1` or the directory is never found.
                let encoded = encode_module_path(module_path);
                let encoded_version = encode_module_path(version);

                // Go module cache layout: <encoded-module-path>@<encoded-version>/
                let module_dir = cache_path.join(format!("{encoded}@{encoded_version}"));

                if is_dir(&module_dir).await {
                    if is_partially_extracted(cache_path, &encoded, &encoded_version).await {
                        continue;
                    }
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
                let full_path = current_path.join(&dir_name);

                // Check if this directory has `@` in its name (versioned module)
                if dir_name_str.contains('@') {
                    if let Some(pkg) = self.parse_versioned_dir(base_path, &full_path, seen).await {
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
    async fn parse_versioned_dir(
        &self,
        base_path: &Path,
        dir_path: &Path,
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

        // `version` is still the ENCODED on-disk form here, which is what
        // the marker path is keyed by.
        if is_partially_extracted(base_path, encoded_module_path, version).await {
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

/// Whether a `(module_path, version)` pair parsed from an untrusted PURL is
/// safe to join onto the module-cache root in [`GoCrawler::find_by_purls`].
///
/// A Go module path legitimately contains `/` separators
/// (`github.com/foo/bar`), so it is validated per segment via
/// [`path_safety::is_safe_multi_segment`] — a real path never has an empty,
/// `.`, or `..` segment, and absolute paths are rejected too. A version is a
/// single segment ([`path_safety::is_safe_single_segment`]). Both helpers
/// reject backslashes, NULs, and `:` — a Windows drive-relative coordinate
/// (`C:evil`, `C:/evil`) joins as an absolute path. This mirrors the
/// `go_redirect` coordinate guard and fails closed so a tampered manifest PURL
/// cannot traverse out of the cache.
fn is_safe_module_coordinate(module_path: &str, version: &str) -> bool {
    path_safety::is_safe_multi_segment(module_path) && path_safety::is_safe_single_segment(version)
}

/// Whether Go's partial-extraction marker exists for an (encoded) module
/// coordinate under `cache_path`.
///
/// Go (≥1.14.2) extracts a module zip in place at its final
/// `<path>@<version>` location, creating
/// `cache/download/<path>/@v/<version>.partial` first and removing it only
/// after extraction succeeds (`cmd/go/internal/modfetch/fetch.go` — the
/// marker exists "to prevent other processes from reading the directory if
/// we crash"). A dir whose marker survives is incomplete: Go treats it as
/// not downloaded (`DownloadDirPartialError`) and deletes + re-extracts it
/// on next use, destroying anything patched into it. Both the scan and the
/// PURL lookup must therefore skip it. Mirrors Go's `os.Stat(partialPath)`
/// succeeded check in `DownloadDir`; both halves of the coordinate are the
/// case-ENCODED on-disk forms, matching Go's `CachePath(mod, "partial")`.
async fn is_partially_extracted(
    cache_path: &Path,
    encoded_module: &str,
    encoded_version: &str,
) -> bool {
    let marker = cache_path
        .join("cache")
        .join("download")
        .join(encoded_module)
        .join("@v")
        .join(format!("{encoded_version}.partial"));
    tokio::fs::metadata(&marker).await.is_ok()
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
    #[tokio::test]
    async fn test_parse_versioned_dir_empty_module_path_guard() {
        let base = std::path::Path::new("/cache");
        let dir = std::path::Path::new("/cache/@v1.0.0");
        let mut seen = HashSet::new();
        let crawler = GoCrawler;
        let result = crawler.parse_versioned_dir(base, dir, &mut seen).await;
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

    #[tokio::test]
    async fn test_crawl_finds_v2_submodule_beside_v1() {
        // A `/vN` major-version submodule lives at
        // `<mod>/v2@<ver>/`, which forces a *plain* `<mod>` directory to
        // exist alongside the versioned `<mod>@<ver>` leaf. The walk must
        // descend into the plain `bar/` dir (no `@`) to reach `v2@v2.0.0`
        // while still parsing the sibling `bar@v1.0.0` leaf — i.e. hitting
        // a versioned directory must not abort the walk of its siblings.
        let dir = tempfile::tempdir().unwrap();

        let v1 = dir.path().join("github.com").join("foo").join("bar@v1.0.0");
        tokio::fs::create_dir_all(&v1).await.unwrap();

        let v2 = dir
            .path()
            .join("github.com")
            .join("foo")
            .join("bar")
            .join("v2@v2.0.0");
        tokio::fs::create_dir_all(&v2).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(packages.len(), 2, "both v1 leaf and v2 submodule found");
        assert!(purls.contains("pkg:golang/github.com/foo/bar@v1.0.0"));
        assert!(purls.contains("pkg:golang/github.com/foo/bar/v2@v2.0.0"));
    }

    #[tokio::test]
    async fn test_crawl_finds_multiple_versions_of_same_module() {
        // Two versions of one module are distinct sibling directories and
        // must both surface as separate packages (dedup keys on the full
        // versioned PURL, not the module path).
        let dir = tempfile::tempdir().unwrap();

        for v in ["gin@v1.9.0", "gin@v1.9.1"] {
            let d = dir.path().join("github.com").join("gin-gonic").join(v);
            tokio::fs::create_dir_all(&d).await.unwrap();
        }

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(packages.len(), 2);
        assert!(purls.contains("pkg:golang/github.com/gin-gonic/gin@v1.9.0"));
        assert!(purls.contains("pkg:golang/github.com/gin-gonic/gin@v1.9.1"));
    }

    #[tokio::test]
    async fn test_parse_versioned_dir_empty_version_guard() {
        // A dir name with a trailing `@` and no version (`foo@`) is
        // malformed metadata: the empty-version guard must yield None
        // rather than emit a package with an empty version that would
        // build a dangling `pkg:golang/foo@` PURL.
        let base = std::path::Path::new("/cache");
        let dir = std::path::Path::new("/cache/github.com/foo/bar@");
        let mut seen = HashSet::new();
        let crawler = GoCrawler;
        let result = crawler.parse_versioned_dir(base, dir, &mut seen).await;
        assert!(result.is_none(), "empty version must yield None");
    }

    #[tokio::test]
    async fn test_find_by_purls_qualified_purl_keys_by_input() {
        // A PURL carrying `?` qualifiers must still resolve the on-disk
        // dir (qualifiers stripped before parsing) AND be keyed in the
        // result map by the *exact* input string the caller passed.
        let dir = tempfile::tempdir().unwrap();
        let module_dir = dir
            .path()
            .join("github.com")
            .join("gin-gonic")
            .join("gin@v1.9.1");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let qualified = "pkg:golang/github.com/gin-gonic/gin@v1.9.1?type=module".to_string();
        let result = crawler
            .find_by_purls(dir.path(), std::slice::from_ref(&qualified))
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&qualified));
        assert_eq!(result[&qualified].name, "gin");
    }

    #[tokio::test]
    async fn test_find_by_purls_rejects_module_path_traversal() {
        // SECURITY: `module_path`/`version` come straight from the (untrusted)
        // manifest PURL and are joined onto the module-cache root. In global
        // mode the resolved directory is patched IN PLACE (no `replace`
        // redirect backend guards it), so a `..` segment must be rejected
        // fail-closed — otherwise a tampered PURL escapes the cache. Twin of
        // the deno crawler's `is_safe_jsr_component` gate.
        let parent = tempfile::tempdir().unwrap();
        let cache = parent.path().join("cache");
        tokio::fs::create_dir_all(&cache).await.unwrap();

        // A real directory one level ABOVE the cache root. With no guard,
        // `cache.join("../outside/evil@v1.0.0")` resolves straight to it, and
        // every intermediate component exists so the `is_dir` probe succeeds.
        let outside = parent.path().join("outside").join("evil@v1.0.0");
        tokio::fs::create_dir_all(&outside).await.unwrap();

        let crawler = GoCrawler::new();
        let purls = vec!["pkg:golang/../outside/evil@v1.0.0".to_string()];
        let result = crawler.find_by_purls(&cache, &purls).await.unwrap();

        assert!(
            result.is_empty(),
            "a `..` segment in the module path must be rejected, not resolved \
             to a directory outside the cache root"
        );
    }

    /// Unit contract for the coordinate gate: real module paths/versions
    /// pass; a `:` is rejected because a Windows drive-relative coordinate
    /// (`C:evil`, `C:/evil`) joins as an absolute path under `Path::join`.
    #[test]
    fn test_is_safe_module_coordinate_rejects_colon() {
        assert!(is_safe_module_coordinate("github.com/foo/bar", "v1.2.3"));
        assert!(!is_safe_module_coordinate("C:/evil", "v1.0.0"));
        assert!(!is_safe_module_coordinate(
            "github.com/C:evil/bar",
            "v1.0.0"
        ));
        assert!(!is_safe_module_coordinate("github.com/foo/bar", "C:v1.0.0"));
    }

    #[tokio::test]
    async fn test_crawl_skips_partially_extracted_module() {
        // Go (≥1.14.2) extracts a module zip IN PLACE at its final
        // `<path>@<version>` location, creating a
        // `cache/download/<path>/@v/<version>.partial` marker first and
        // removing it only after extraction succeeds. Per
        // `cmd/go/internal/modfetch/fetch.go`, the marker exists "to prevent
        // other processes from reading the directory if we crash" — a dir
        // whose marker survives is incomplete, and Go deletes + re-extracts
        // it on next use, destroying anything patched into it. The crawler
        // must treat it like Go does: not installed.
        let dir = tempfile::tempdir().unwrap();

        let complete = dir.path().join("github.com").join("foo").join("ok@v1.0.0");
        tokio::fs::create_dir_all(&complete).await.unwrap();

        let partial = dir.path().join("github.com").join("foo").join("bad@v2.0.0");
        tokio::fs::create_dir_all(&partial).await.unwrap();
        let marker_dir = dir
            .path()
            .join("cache")
            .join("download")
            .join("github.com")
            .join("foo")
            .join("bad")
            .join("@v");
        tokio::fs::create_dir_all(&marker_dir).await.unwrap();
        tokio::fs::write(marker_dir.join("v2.0.0.partial"), b"")
            .await
            .unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(
            purls.contains("pkg:golang/github.com/foo/ok@v1.0.0"),
            "the completely extracted module must still be found"
        );
        assert!(
            !purls.contains("pkg:golang/github.com/foo/bad@v2.0.0"),
            "a module dir with a surviving .partial marker is incomplete \
             and must be skipped"
        );
        assert_eq!(packages.len(), 1);
    }

    #[tokio::test]
    async fn test_find_by_purls_skips_partially_extracted_module() {
        // Same marker protocol as the scan test, exercised through the
        // lookup path — and with case-escaped coordinates, pinning that the
        // marker is probed at the ENCODED path and version
        // (`.../!azure/bar/@v/v1.0.0-!r!c1.partial`), exactly where Go's
        // `CachePath(mod, "partial")` writes it.
        let dir = tempfile::tempdir().unwrap();

        let module_dir = dir
            .path()
            .join("github.com")
            .join("!azure")
            .join("bar@v1.0.0-!r!c1");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();
        let marker_dir = dir
            .path()
            .join("cache")
            .join("download")
            .join("github.com")
            .join("!azure")
            .join("bar")
            .join("@v");
        tokio::fs::create_dir_all(&marker_dir).await.unwrap();
        tokio::fs::write(marker_dir.join("v1.0.0-!r!c1.partial"), b"")
            .await
            .unwrap();

        let crawler = GoCrawler::new();
        let purls = vec!["pkg:golang/github.com/Azure/bar@v1.0.0-RC1".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert!(
            result.is_empty(),
            "a half-extracted module (surviving .partial marker) must not \
             be returned as a patch target — Go will delete and re-extract \
             the dir, silently destroying any patch applied there"
        );
    }

    #[tokio::test]
    async fn test_find_by_purls_absent_returns_empty_ok() {
        // No matching directory on disk → Ok(empty map), never an Err.
        let dir = tempfile::tempdir().unwrap();
        let crawler = GoCrawler::new();
        let result = crawler
            .find_by_purls(
                dir.path(),
                &["pkg:golang/github.com/none/here@v0.0.1".to_string()],
            )
            .await
            .unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_crawl_ignores_stray_file_with_at_sign() {
        // Only directories are modules. A stray *file* whose name contains
        // `@` at the cache root (e.g. a leftover lock/marker) must not be
        // parsed into a ghost package.
        let dir = tempfile::tempdir().unwrap();

        let real = dir
            .path()
            .join("github.com")
            .join("gin-gonic")
            .join("gin@v1.9.1");
        tokio::fs::create_dir_all(&real).await.unwrap();
        tokio::fs::write(dir.path().join("stray@v0.0.0"), b"junk")
            .await
            .unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1, "the stray file must be ignored");
        assert_eq!(
            packages[0].purl,
            "pkg:golang/github.com/gin-gonic/gin@v1.9.1"
        );
    }
}
