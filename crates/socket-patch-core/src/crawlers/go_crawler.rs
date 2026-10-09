use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::listing::{list_dir_sync, ListedEntry};
use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::{is_dir_sync, run_blocking};
use crate::vendor::go_mod_edit;
use crate::vendor::go_sum_edit::go_sum_lines;

#[cfg(test)]
mod oracle;

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
    ///
    /// A local project with a `go.sum` and no Go workspace in effect only
    /// gets the modules its `go.sum` records, each looked up in the cache
    /// ([`go_sum_scope`], [`locate_module`]), so a module another project
    /// left in `GOMODCACHE` is never crawled and the cache tree is not
    /// walked. Everything else (`--global`, `--global-prefix`, no `go.sum`,
    /// a workspace) walks the whole cache.
    ///
    /// The whole crawl is one blocking-pool task (a module cache holds tens
    /// of thousands of directories; one runtime hop per readdir and stat
    /// dominated the crawl). The walk visits entries in the same
    /// depth-first, readdir order as before so the first-seen PURL dedup
    /// keeps the same winners; located modules come out in `go.sum` order.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let cache_paths = self
            .get_module_cache_paths(options)
            .await
            .unwrap_or_default();
        if cache_paths.is_empty() {
            return Vec::new();
        }
        let project =
            (!options.global && options.global_prefix.is_none()).then(|| options.cwd.clone());

        run_blocking(move || {
            let scope = project.as_deref().and_then(go_sum_scope);
            let mut packages = Vec::new();
            let mut seen = HashSet::new();
            for cache_path in &cache_paths {
                match &scope {
                    Some(recorded) => {
                        locate_recorded(cache_path, recorded, &mut seen, &mut packages)
                    }
                    None => scan_cache_sync(cache_path, &mut seen, &mut packages),
                }
            }
            packages
        })
        .await
    }

    /// Find specific packages by PURL in the module cache.
    ///
    /// The per-PURL probes (a stat plus the partial-extraction marker stat)
    /// run together as one blocking-pool task.
    pub async fn find_by_purls(
        &self,
        cache_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        if purls.is_empty() {
            return Ok(HashMap::new());
        }
        let cache_path = cache_path.to_path_buf();
        let purls = purls.to_vec();
        Ok(run_blocking(move || find_by_purls_sync(&cache_path, &purls)).await)
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
        // A set-but-empty HOME/USERPROFILE counts as unset, matching the
        // GOMODCACHE and GOPATH guards above: honoring `""` would yield the
        // RELATIVE path `go/pkg/mod`, pointing the crawl at a directory
        // inside the user's project instead of a real module cache.
        Some(
            crate::utils::fs::home_dir()?
                .join("go")
                .join("pkg")
                .join("mod"),
        )
    }

    /// The unit tests' entry point to [`parse_versioned_dir`] (the walk
    /// itself calls the free function on the blocking pool).
    #[cfg(test)]
    async fn parse_versioned_dir(
        &self,
        base_path: &Path,
        dir_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Option<CrawledPackage> {
        parse_versioned_dir(base_path, dir_path, seen)
    }
}

impl Default for GoCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking body of [`GoCrawler::find_by_purls`].
fn find_by_purls_sync(cache_path: &Path, purls: &[String]) -> HashMap<String, CrawledPackage> {
    let mut result: HashMap<String, CrawledPackage> = HashMap::new();

    for purl in purls {
        if let Some((module_path, version)) = crate::utils::purl::parse_golang_purl(purl) {
            if let Some(pkg) = locate_module(cache_path, &module_path, &version, purl.clone()) {
                result.insert(purl.clone(), pkg);
            }
        }
    }

    result
}

/// The extracted cache directory of `module_path@version` under
/// `cache_path`, reported under `purl`: the one lookup behind
/// [`GoCrawler::find_by_purls`] and the `go.sum`-scoped crawl.
fn locate_module(
    cache_path: &Path,
    module_path: &str,
    version: &str,
    purl: String,
) -> Option<CrawledPackage> {
    // SECURITY: `module_path`/`version` come straight from an untrusted
    // manifest PURL or project `go.sum` and are joined onto the cache root
    // below. In global mode the resolved directory is patched IN PLACE (no
    // `replace`-redirect backend stands between the crawler and disk), so
    // a tampered coordinate with a `..` segment must not be able to escape
    // the cache. Reject fail-closed before the `is_dir` probe — the twin
    // of the deno crawler's `is_safe_jsr_component` gate.
    if !is_safe_module_coordinate(module_path, version) {
        return None;
    }
    // Encode the module path AND the version for the filesystem.
    // Go case-escapes both halves of the directory name, so a
    // version like `v1.0.0-RC1` must be looked up as
    // `v1.0.0-!r!c1` or the directory is never found.
    let encoded = encode_module_path(module_path);
    let encoded_version = encode_module_path(version);

    // Go module cache layout: <encoded-module-path>@<encoded-version>/
    let module_dir = cache_path.join(format!("{encoded}@{encoded_version}"));

    if !is_dir_sync(&module_dir) || is_partially_extracted(cache_path, &encoded, &encoded_version) {
        return None;
    }
    let (namespace, name) = split_module_path(module_path);
    Some(CrawledPackage {
        name: name.to_string(),
        version: version.to_string(),
        namespace: Some(namespace.to_string()),
        purl,
        path: module_dir,
    })
}

/// The `(module, version)` of every module-zip line of `<cwd>/go.sum`
/// (`/go.mod` lines hash only a manifest and are skipped), in file order,
/// then every `require` of `<cwd>/go.mod` not already listed, sorted. The
/// requires keep a module the project still builds against when its own
/// go.sum lines are gone: a `replace`d module's go.sum records only the
/// replacement (the hosted rewrite drops the original's lines, as
/// `go mod tidy` does). `None` when a Go workspace is in effect
/// ([`workspace_in_effect`]: its build list spans other modules' `go.sum`
/// and `go.work.sum`) or there is no readable `go.sum`; the crawl then
/// walks the whole cache.
fn go_sum_scope(cwd: &Path) -> Option<Vec<(String, String)>> {
    if workspace_in_effect(cwd) {
        return None;
    }
    let text = crate::utils::fs::read_regular_to_string_sync(&cwd.join("go.sum")).ok()?;
    let mut scope: Vec<(String, String)> = go_sum_lines(&text)
        .filter(|line| !line.go_mod)
        .map(|line| (line.module.to_string(), line.version.to_string()))
        .collect();
    if let Ok(go_mod) = crate::utils::fs::read_regular_to_string_sync(&cwd.join("go.mod")) {
        let listed: HashSet<(String, String)> = scope.iter().cloned().collect();
        let mut required: Vec<(String, String)> =
            go_mod_edit::parse_required_versions(&go_mod_edit::normalize_for_read(&go_mod))
                .into_iter()
                .filter(|pair| !listed.contains(pair))
                .collect();
        required.sort();
        scope.extend(required);
    }
    Some(scope)
}

/// Whether the go command would build `cwd` in workspace mode: `GOWORK`
/// names a file, or (`GOWORK` unset or empty) a `go.work` exists in `cwd`
/// or an ancestor. `GOWORK=off` disables workspaces.
fn workspace_in_effect(cwd: &Path) -> bool {
    match std::env::var_os("GOWORK") {
        Some(v) if v == "off" => false,
        Some(v) if !v.is_empty() => true,
        _ => go_work_at_or_above(cwd, &std::env::current_dir().unwrap_or_default()),
    }
}

/// Whether a `go.work` exists in `cwd` or an ancestor, a relative `cwd`
/// taken against `base` first: the CLI's default `cwd` is `.`, whose
/// lexical ancestors stop at itself, so a parent `go.work` would be missed.
fn go_work_at_or_above(cwd: &Path, base: &Path) -> bool {
    base.join(cwd)
        .ancestors()
        .any(|dir| std::fs::symlink_metadata(dir.join("go.work")).is_ok())
}

/// Look up each `recorded` module in cache root `cache_path` instead of
/// walking it. A coordinate the walk could never report
/// ([`walk_reaches`]) is skipped, so the result is a subset of
/// [`scan_cache_sync`]'s.
fn locate_recorded(
    cache_path: &Path,
    recorded: &[(String, String)],
    seen: &mut HashSet<String>,
    results: &mut Vec<CrawledPackage>,
) {
    for (module_path, version) in recorded {
        if !walk_reaches(module_path, version) {
            continue;
        }
        let purl = crate::utils::purl::build_golang_purl(module_path, version);
        if seen.contains(&purl) {
            continue;
        }
        if let Some(pkg) = locate_module(cache_path, module_path, version, purl.clone()) {
            seen.insert(purl);
            results.push(pkg);
        }
    }
}

/// Whether [`scan_cache_sync`] can report `module_path@version`: no
/// segment is hidden, the first is not the root `cache/` metadata
/// directory, and neither half holds the `@` the walk splits on (Go allows
/// none of these in a real module coordinate).
fn walk_reaches(module_path: &str, version: &str) -> bool {
    !module_path.split('/').any(|s| s.starts_with('.'))
        && module_path.split('/').next() != Some("cache")
        && !module_path.contains('@')
        && !version.contains('@')
}

/// Walk one module cache root.
///
/// Go module cache has a hierarchical structure:
/// `<cache>/github.com/user/project@v1.0.0/`
///
/// We walk the tree looking for directories whose name contains `@`
/// (the version separator), which marks a versioned module. Depth-first
/// in readdir order with an explicit stack (each frame is one directory's
/// listing and the index of its next entry), so packages come out in the
/// order the recursive walk produced them.
fn scan_cache_sync(
    base_path: &Path,
    seen: &mut HashSet<String>,
    results: &mut Vec<CrawledPackage>,
) {
    let mut stack: Vec<(std::path::PathBuf, Vec<ListedEntry>, usize)> =
        vec![(base_path.to_path_buf(), list_dir_sync(base_path), 0)];
    while let Some((current_path, entries, next)) = stack.last_mut() {
        let Some(entry) = entries.get(*next) else {
            stack.pop();
            continue;
        };
        *next += 1;
        if !entry.is_dir(current_path) {
            continue;
        }

        let name = &entry.name;
        let dir_name_str = name.to_string_lossy();

        // Skip hidden directories anywhere, and the module cache's
        // `cache/` metadata directory — but ONLY at the cache root.
        // The download cache lives at `<root>/cache`; a `cache` path
        // component deeper in the tree is a legitimate module name
        // (e.g. `github.com/go-redis/cache/v9@v9.0.0`) and must not be
        // pruned, or the versioned dir beneath it is never discovered.
        if dir_name_str.starts_with('.')
            || (dir_name_str == "cache" && current_path.as_path() == base_path)
        {
            continue;
        }

        // Build the child path from the raw `OsStr` rather than the
        // lossy UTF-8 rendering, so non-UTF-8 directory names still
        // resolve to the correct on-disk path.
        let full_path = current_path.join(name);

        // Check if this directory has `@` in its name (versioned module)
        let versioned = dir_name_str.contains('@');
        drop(dir_name_str);
        if versioned {
            if let Some(pkg) = parse_versioned_dir(base_path, &full_path, seen) {
                results.push(pkg);
            }
        } else {
            // Descend into subdirectories
            let listing = list_dir_sync(&full_path);
            stack.push((full_path, listing, 0));
        }
    }
}

/// Parse a versioned directory (containing `@`) into a `CrawledPackage`.
fn parse_versioned_dir(
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
    if is_partially_extracted(base_path, encoded_module_path, version) {
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
fn is_partially_extracted(cache_path: &Path, encoded_module: &str, encoded_version: &str) -> bool {
    let marker = cache_path
        .join("cache")
        .join("download")
        .join(encoded_module)
        .join("@v")
        .join(format!("{encoded_version}.partial"));
    std::fs::metadata(&marker).is_ok()
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

        // A module path with NO slash is legal (e.g. `gotest.tools` through
        // v2): the whole path is the name and the namespace is empty.
        let (ns, name) = split_module_path("gotest.tools");
        assert_eq!(ns, "");
        assert_eq!(name, "gotest.tools");
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

    /// Canonical purls percent-encode `+` in a version
    /// (`v2.0.0%2Bincompatible`); the lookup must decode it before
    /// case-escaping, or a `+incompatible` module is never found.
    #[tokio::test]
    async fn test_find_by_purls_percent_encoded_version() {
        let dir = tempfile::tempdir().unwrap();
        let module_dir = dir
            .path()
            .join("github.com")
            .join("foo")
            .join("bar@v2.0.0+incompatible");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let purl = "pkg:golang/github.com/foo/bar@v2.0.0%2Bincompatible".to_string();
        let result = crawler
            .find_by_purls(dir.path(), std::slice::from_ref(&purl))
            .await
            .unwrap();

        assert_eq!(result.len(), 1, "encoded purl must resolve: {result:?}");
        assert_eq!(result[&purl].version, "v2.0.0+incompatible");
        assert_eq!(result[&purl].path, module_dir);
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

    // ---- Project-mode go.sum scope (#595) ----

    mod go_sum_scope {
        use super::*;
        use crate::crawlers::oracle_support::{mkdir, write};

        const H1: &str = "h1:mU9vN/n1hbXktM62lJ6MbRKOk3aI8NDH+szCf62RXtE=";

        /// A project dir and a module cache, with `GOMODCACHE` pointed at
        /// the cache and `GOWORK` unset for the test's lifetime.
        struct Fixture {
            _tmp: tempfile::TempDir,
            project: PathBuf,
            cache: PathBuf,
            _env: (EnvGuard, EnvGuard),
        }

        impl Fixture {
            fn new() -> Self {
                let tmp = tempfile::tempdir().unwrap();
                let project = tmp.path().join("project");
                let cache = tmp.path().join("modcache");
                mkdir(&project);
                mkdir(&cache);
                write(&project.join("go.mod"), "module example.com/app\n");
                let env = (
                    EnvGuard::set("GOMODCACHE", cache.to_str().unwrap()),
                    EnvGuard::unset("GOWORK"),
                );
                Fixture {
                    _tmp: tmp,
                    project,
                    cache,
                    _env: env,
                }
            }

            /// Extract `<encoded module>@<encoded version>/` into the cache.
            fn stage(&self, module: &str, version: &str) -> &Self {
                let dir = self.cache.join(format!(
                    "{}@{}",
                    encode_module_path(module),
                    encode_module_path(version)
                ));
                write(&dir.join("go.mod"), &format!("module {module}\n"));
                self
            }

            /// Write `go.sum` with a zip and a `/go.mod` line per module,
            /// plus `/go.mod`-only lines for `manifest_only`.
            fn go_sum(&self, modules: &[(&str, &str)], manifest_only: &[(&str, &str)]) -> &Self {
                let mut text = String::new();
                for (m, v) in modules {
                    text.push_str(&format!("{m} {v} {H1}\n{m} {v}/go.mod {H1}\n"));
                }
                for (m, v) in manifest_only {
                    text.push_str(&format!("{m} {v}/go.mod {H1}\n"));
                }
                write(&self.project.join("go.sum"), &text);
                self
            }

            async fn crawl(&self) -> Vec<String> {
                let options = CrawlerOptions {
                    cwd: self.project.clone(),
                    global: false,
                    global_prefix: None,
                };
                let mut purls: Vec<String> = GoCrawler::new()
                    .crawl_all(&options)
                    .await
                    .into_iter()
                    .map(|p| p.purl)
                    .collect();
                purls.sort();
                purls
            }
        }

        fn sorted(purls: &[&str]) -> Vec<String> {
            let mut v: Vec<String> = purls.iter().map(|p| p.to_string()).collect();
            v.sort();
            v
        }

        /// The cache holds modules of other projects, another version of a
        /// recorded module and a module go.sum only hashes the go.mod of;
        /// only the recorded zips are crawled.
        fn stage_shared_cache(f: &Fixture) {
            f.stage("github.com/gin-gonic/gin", "v1.9.1")
                .stage("github.com/gin-gonic/gin", "v1.8.0")
                .stage("github.com/Azure/azure-sdk-for-go", "v1.0.0-RC1")
                .stage("golang.org/x/text", "v0.14.0")
                .stage("example.com/unrelated", "v0.1.0")
                .go_sum(
                    &[
                        ("github.com/gin-gonic/gin", "v1.9.1"),
                        ("github.com/Azure/azure-sdk-for-go", "v1.0.0-RC1"),
                        ("example.com/not-downloaded", "v1.0.0"),
                    ],
                    &[("golang.org/x/text", "v0.14.0")],
                );
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn a_project_crawls_only_the_modules_its_go_sum_records() {
            let f = Fixture::new();
            stage_shared_cache(&f);
            assert_eq!(
                f.crawl().await,
                sorted(&[
                    "pkg:golang/github.com/Azure/azure-sdk-for-go@v1.0.0-RC1",
                    "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                ])
            );
        }

        /// The scoped crawl and `find_by_purls` share `locate_module`:
        /// for every recorded coordinate they report the same directory
        /// and identity, including the case-encoded ones.
        #[tokio::test]
        #[serial_test::serial]
        async fn the_scoped_crawl_reports_what_find_by_purls_finds() {
            let f = Fixture::new();
            stage_shared_cache(&f);
            let options = CrawlerOptions {
                cwd: f.project.clone(),
                global: false,
                global_prefix: None,
            };
            let crawled = GoCrawler::new().crawl_all(&options).await;
            let purls: Vec<String> = crawled.iter().map(|p| p.purl.clone()).collect();
            let found = GoCrawler::new()
                .find_by_purls(&f.cache, &purls)
                .await
                .unwrap();
            assert_eq!(found.len(), crawled.len());
            for pkg in &crawled {
                let hit = &found[&pkg.purl];
                assert_eq!(
                    (&hit.name, &hit.version, &hit.namespace, &hit.path),
                    (&pkg.name, &pkg.version, &pkg.namespace, &pkg.path)
                );
            }
            // And the walk reports the same rows for those directories.
            let walked = GoCrawler::new()
                .crawl_all(&CrawlerOptions {
                    cwd: f.project.clone(),
                    global: false,
                    global_prefix: Some(f.cache.clone()),
                })
                .await;
            for pkg in &crawled {
                let w = walked.iter().find(|w| w.purl == pkg.purl).unwrap();
                assert_eq!(
                    (&w.name, &w.version, &w.namespace, &w.path),
                    (&pkg.name, &pkg.version, &pkg.namespace, &pkg.path)
                );
            }
        }

        #[tokio::test]
        #[serial_test::serial]
        async fn without_a_go_sum_the_whole_cache_is_walked() {
            let f = Fixture::new();
            f.stage("github.com/gin-gonic/gin", "v1.9.1")
                .stage("example.com/unrelated", "v0.1.0");
            assert_eq!(
                f.crawl().await,
                sorted(&[
                    "pkg:golang/example.com/unrelated@v0.1.0",
                    "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                ])
            );
        }

        /// A workspace's build list spans other modules' go.sum files and
        /// go.work.sum, so a go.work in cwd or an ancestor, or a GOWORK
        /// file, keeps the walk; GOWORK=off scopes again.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_workspace_keeps_the_walk_unless_gowork_is_off() {
            let f = Fixture::new();
            f.stage("github.com/gin-gonic/gin", "v1.9.1")
                .stage("example.com/unrelated", "v0.1.0")
                .go_sum(&[("github.com/gin-gonic/gin", "v1.9.1")], &[]);
            let scoped = sorted(&["pkg:golang/github.com/gin-gonic/gin@v1.9.1"]);
            let walked = sorted(&[
                "pkg:golang/example.com/unrelated@v0.1.0",
                "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
            ]);
            assert_eq!(f.crawl().await, scoped);

            // go.work in an ancestor of cwd.
            let parent_work = f.project.parent().unwrap().join("go.work");
            write(&parent_work, "go 1.22\nuse ./project\n");
            assert_eq!(f.crawl().await, walked);
            {
                let _off = EnvGuard::set("GOWORK", "off");
                assert_eq!(f.crawl().await, scoped);
            }
            std::fs::remove_file(&parent_work).unwrap();

            // go.work in cwd.
            write(&f.project.join("go.work"), "go 1.22\nuse .\n");
            assert_eq!(f.crawl().await, walked);
            std::fs::remove_file(f.project.join("go.work")).unwrap();

            // GOWORK naming a file elsewhere.
            let _gowork = EnvGuard::set("GOWORK", "/elsewhere/go.work");
            assert_eq!(f.crawl().await, walked);
        }

        /// A relative `cwd` (the CLI passes `.`) still finds a parent
        /// go.work, resolved against the process's directory.
        #[test]
        fn a_relative_cwd_still_sees_a_parent_workspace() {
            let tmp = tempfile::tempdir().unwrap();
            let project = tmp.path().join("ws").join("project");
            mkdir(&project);
            assert!(!go_work_at_or_above(Path::new("."), &project));
            write(&tmp.path().join("ws").join("go.work"), "go 1.22\n");
            assert!(go_work_at_or_above(Path::new("."), &project));
            assert!(go_work_at_or_above(
                Path::new("project"),
                &tmp.path().join("ws")
            ));
            // An absolute cwd ignores the base.
            assert!(go_work_at_or_above(&project, Path::new("/elsewhere")));
        }

        /// go.sum is project content joined onto the cache root: traversal
        /// coordinates are refused, and a partially extracted module, a
        /// hidden segment or the root `cache/` directory is not reported
        /// (the walk never reports them either).
        #[tokio::test]
        #[serial_test::serial]
        async fn unsafe_unreachable_and_partial_coordinates_are_not_located() {
            let f = Fixture::new();
            f.stage("github.com/gin-gonic/gin", "v1.9.1")
                .stage("github.com/half/done", "v1.0.0")
                .stage("cache/download/x", "v1.0.0")
                .stage("github.com/.hidden/mod", "v1.0.0");
            write(
                &f.cache
                    .join("cache/download/github.com/half/done/@v/v1.0.0.partial"),
                "",
            );
            // A directory outside the cache that `..` would reach.
            mkdir(&f.cache.parent().unwrap().join("escape@v1.0.0"));
            f.go_sum(
                &[
                    ("github.com/gin-gonic/gin", "v1.9.1"),
                    ("github.com/half/done", "v1.0.0"),
                    ("cache/download/x", "v1.0.0"),
                    ("github.com/.hidden/mod", "v1.0.0"),
                    ("../escape", "v1.0.0"),
                    ("github.com/gin-gonic/gin", "../../escape"),
                ],
                &[],
            );
            assert_eq!(
                f.crawl().await,
                sorted(&["pkg:golang/github.com/gin-gonic/gin@v1.9.1"])
            );
        }

        /// A `replace`d module's go.sum records only its replacement (the
        /// hosted rewrite drops the original's lines, as `go mod tidy`
        /// does), but go.mod still requires it: its cached copy is still
        /// crawled, as the whole-cache walk did.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_required_module_without_go_sum_lines_is_still_crawled() {
            let f = Fixture::new();
            f.stage("github.com/gin-gonic/gin", "v1.9.1")
                .stage("github.com/Azure/azure-sdk-for-go", "v1.0.0-RC1")
                .stage("example.com/unrelated", "v0.1.0")
                .go_sum(&[("github.com/gin-gonic/gin", "v1.9.1")], &[]);
            write(
                &f.project.join("go.mod"),
                "\u{feff}module example.com/app\n\nrequire (\n\t\"github.com/gin-gonic/gin\" v1.9.1\n\tgithub.com/Azure/azure-sdk-for-go v1.0.0-RC1 // indirect\n)\n\nreplace github.com/Azure/azure-sdk-for-go v1.0.0-RC1 => patch.socket.dev/gopatch/x v1.0.0-RC1-socketpatch.1\n",
            );
            assert_eq!(
                f.crawl().await,
                sorted(&[
                    "pkg:golang/github.com/Azure/azure-sdk-for-go@v1.0.0-RC1",
                    "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
                ])
            );
        }

        /// A duplicated go.sum line (a union merge) yields one package.
        #[tokio::test]
        #[serial_test::serial]
        async fn a_repeated_go_sum_line_is_crawled_once() {
            let f = Fixture::new();
            f.stage("github.com/gin-gonic/gin", "v1.9.1").go_sum(
                &[
                    ("github.com/gin-gonic/gin", "v1.9.1"),
                    ("github.com/gin-gonic/gin", "v1.9.1"),
                ],
                &[],
            );
            assert_eq!(
                f.crawl().await,
                sorted(&["pkg:golang/github.com/gin-gonic/gin@v1.9.1"])
            );
        }
    }

    // ---- get_gomodcache env tests ----

    /// Save and restore an env var around a test body.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prev }
        }
        fn unset(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn test_get_gomodcache_empty_env_fallback_chain() {
        // `std::env::var` yields `Ok("")` for a set-but-empty var (a CI
        // script exporting an unset variable). Every arm of the discovery
        // chain must treat empty as unset — honoring `""` would yield a
        // CWD-RELATIVE cache path (`go/pkg/mod` or `pkg/mod`), pointing the
        // crawl (and the in-place patcher) at a directory inside the user's
        // own project. Twin of `m2_repo_path`'s / `nuget_home`'s guards.
        let gopath_a = tempfile::tempdir().unwrap();
        let home_b = tempfile::tempdir().unwrap();

        // Case A: empty GOMODCACHE falls through to GOPATH, and the empty
        // FIRST GOPATH entry is skipped in favor of the next non-empty one
        // (GOPATH is an OS-separator-delimited list; Go uses the first
        // usable entry for the module cache).
        let gopath_list = std::env::join_paths(["".as_ref(), gopath_a.path().as_os_str()]).unwrap();
        let _gomodcache = EnvGuard::set("GOMODCACHE", "");
        let _gopath = EnvGuard::set("GOPATH", gopath_list.to_str().unwrap());
        let _home = EnvGuard::set("HOME", "/nonexistent-home-unused");
        let _userprofile = EnvGuard::unset("USERPROFILE");
        assert_eq!(
            GoCrawler::get_gomodcache(),
            Some(gopath_a.path().join("pkg").join("mod")),
            "empty GOMODCACHE must fall through to GOPATH, skipping the \
             empty first GOPATH entry"
        );

        // Case B: GOMODCACHE and GOPATH both set-but-empty fall all the way
        // through to the $HOME/go/pkg/mod default.
        let _gopath_empty = EnvGuard::set("GOPATH", "");
        let _home_b = EnvGuard::set("HOME", home_b.path().to_str().unwrap());
        assert_eq!(
            GoCrawler::get_gomodcache(),
            Some(home_b.path().join("go").join("pkg").join("mod")),
            "set-but-empty GOPATH must fall through to the HOME default"
        );

        // Case C: with HOME empty too (and USERPROFILE unset), discovery
        // must report NO cache rather than fabricate a relative path.
        let _home_empty = EnvGuard::set("HOME", "");
        assert_eq!(
            GoCrawler::get_gomodcache(),
            None,
            "all-empty env must yield None, never a CWD-relative path"
        );
    }

    #[tokio::test]
    async fn test_parse_versioned_dir_second_visit_same_purl_returns_none() {
        // The `seen` dedup contract: crawl_all threads one HashSet through
        // every parse so a module reachable twice (e.g. via multiple cache
        // roots) surfaces exactly once. The second visit of the SAME purl
        // must hit the seen-contains early-return and yield None.
        let base = std::path::Path::new("/cache");
        let dir = std::path::Path::new("/cache/github.com/foo/bar@v1.0.0");
        let mut seen = HashSet::new();
        let crawler = GoCrawler;

        let first = crawler.parse_versioned_dir(base, dir, &mut seen).await;
        let pkg = first.expect("first visit must parse the module");
        assert_eq!(pkg.purl, "pkg:golang/github.com/foo/bar@v1.0.0");

        let second = crawler.parse_versioned_dir(base, dir, &mut seen).await;
        assert!(
            second.is_none(),
            "second visit of an already-seen purl must be deduplicated"
        );
    }

    #[tokio::test]
    async fn test_crawl_all_slashless_module_path() {
        // A single-segment module path with no `/` is real: `gotest.tools`
        // (a widely-used assertion library) has a slashless module path
        // through v2, so its versioned dir sits directly at the cache root.
        let dir = tempfile::tempdir().unwrap();
        let module_dir = dir.path().join("gotest.tools@v2.3.0");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:golang/gotest.tools@v2.3.0");
        assert_eq!(packages[0].name, "gotest.tools");
        assert_eq!(packages[0].version, "v2.3.0");
        // Pins CURRENT behavior: split_module_path's no-slash arm returns an
        // empty namespace, which the CrawledPackage construction wraps as
        // `Some("")` rather than mapping to `None` (crawled_from_purl's
        // convention for namespace-less packages).
        assert_eq!(packages[0].namespace, Some(String::new()));
        assert_eq!(packages[0].path, module_dir);
    }

    #[tokio::test]
    async fn test_find_by_purls_slashless_module_path() {
        // Same slashless module path through the PURL lookup:
        // `parse_golang_purl` splits at the LAST `@`, so a no-slash name is
        // accepted and must resolve to the root-level versioned dir.
        let dir = tempfile::tempdir().unwrap();
        let module_dir = dir.path().join("gotest.tools@v2.3.0");
        tokio::fs::create_dir_all(&module_dir).await.unwrap();

        let crawler = GoCrawler::new();
        let purls = vec!["pkg:golang/gotest.tools@v2.3.0".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = &result["pkg:golang/gotest.tools@v2.3.0"];
        assert_eq!(pkg.name, "gotest.tools");
        assert_eq!(pkg.version, "v2.3.0");
        // Same Some("") pin as the crawl-side test above.
        assert_eq!(pkg.namespace, Some(String::new()));
        assert_eq!(pkg.path, module_dir);
    }

    // ── Equivalence with the per-call async walk (oracle) ─────────────

    mod equivalence {
        use super::super::oracle::LegacyGoCrawler;
        use super::*;
        use crate::crawlers::oracle_support::{
            map_rows, mkdir, rows, symlink, write, PermGuard, Rng,
        };

        const NAMES: &[&str] = &[
            "github.com",
            "golang.org",
            "x",
            "sub",
            "cache",
            ".hidden",
            "!azure",
            "Azure",
            "mod@v1.0.0",
            "mod@v1.0.0-!r!c1",
            "A@v1.2.0",
            "!a@v1.2.0",
            "a@b@v3.0.0",
            "x@",
            "@v2.0.0",
            "text@v0.14.0",
            "cache@v9.0.0",
        ];

        struct Gen {
            rng: Rng,
            root: PathBuf,
            outside: PathBuf,
            perms: PermGuard,
            versioned: Vec<String>,
        }

        impl Gen {
            fn dir(&mut self, dir: &Path, depth: usize) {
                mkdir(dir);
                for _ in 0..self.rng.below(6) {
                    let name = self.rng.pick(NAMES).to_string();
                    let child = dir.join(&name);
                    match self.rng.below(12) {
                        // A plain file (never a module, even with `@`).
                        0 => write(&child, "x"),
                        // A symlink to a real directory outside the root
                        // (holding modules), or a dangling one.
                        1 => {
                            let target = if self.rng.chance(70) {
                                let t = self.outside.join(format!("t{}", self.rng.next()));
                                mkdir(&t.join("linked@v1.0.0"));
                                mkdir(&t.join("deep").join("m@v0.1.0"));
                                t
                            } else {
                                self.outside.join("missing")
                            };
                            symlink(&target, &child);
                        }
                        // An unreadable or unsearchable directory.
                        2 if depth > 0 => {
                            mkdir(&child.join("in@v1.0.0"));
                            let mode = if self.rng.chance(50) { 0o000 } else { 0o600 };
                            self.perms.plan(&child, mode);
                        }
                        _ if name.contains('@') => {
                            mkdir(&child);
                            if let Ok(rel) = child.strip_prefix(&self.root) {
                                let rel = rel.to_string_lossy().replace('\\', "/");
                                self.versioned.push(rel.clone());
                                if self.rng.chance(20) {
                                    if let Some(at) = rel.rfind('@') {
                                        write(
                                            &self
                                                .root
                                                .join("cache")
                                                .join("download")
                                                .join(&rel[..at])
                                                .join("@v")
                                                .join(format!("{}.partial", &rel[at + 1..])),
                                            "",
                                        );
                                    }
                                }
                            }
                        }
                        _ if depth < 4 => self.dir(&child, depth + 1),
                        _ => mkdir(&child),
                    }
                }
                #[cfg(unix)]
                if self.rng.chance(5) {
                    use std::os::unix::ffi::OsStrExt as _;
                    let raw = std::ffi::OsStr::from_bytes(b"bad\xffname@v1.0.0");
                    let _ = std::fs::create_dir_all(dir.join(raw));
                }
            }
        }

        /// PURLs to probe: every versioned dir seen (decoded), plus
        /// case-variant and unsafe coordinates.
        fn probe_purls(gen: &Gen, crawled: &[CrawledPackage]) -> Vec<String> {
            let mut purls: Vec<String> = crawled.iter().map(|p| p.purl.clone()).collect();
            for rel in &gen.versioned {
                if let Some(at) = rel.rfind('@') {
                    purls.push(crate::utils::purl::build_golang_purl(
                        &decode_module_path(&rel[..at]),
                        &decode_module_path(&rel[at + 1..]),
                    ));
                }
            }
            purls.push("pkg:golang/github.com/../escape@v1.0.0".to_string());
            purls.push("pkg:golang/mod@v1.0.0-RC1".to_string());
            purls.push("pkg:golang/missing@v1.0.0".to_string());
            purls.push("pkg:npm/lodash@1.0.0".to_string());
            purls
        }

        /// Returns (packages crawled, PURLs found) so the caller can check
        /// the fixtures are not vacuous.
        async fn assert_equivalent(gen: &Gen, label: &str) -> (usize, usize) {
            let options = CrawlerOptions {
                cwd: gen.root.clone(),
                global: false,
                global_prefix: Some(gen.root.clone()),
            };
            let new = GoCrawler::new().crawl_all(&options).await;
            let old = LegacyGoCrawler::crawl_all(&options).await;
            assert_eq!(rows(&new), rows(&old), "{label}: crawl_all");

            let purls = probe_purls(gen, &old);
            let new_found = GoCrawler::new()
                .find_by_purls(&gen.root, &purls)
                .await
                .unwrap();
            let old_found = LegacyGoCrawler::find_by_purls(&gen.root, &purls).await;
            assert_eq!(
                map_rows(&new_found),
                map_rows(&old_found),
                "{label}: find_by_purls"
            );
            (old.len(), old_found.len())
        }

        #[tokio::test]
        async fn randomized_caches_match_the_async_oracle() {
            let (mut crawled, mut found) = (0, 0);
            // At least 48 seeds, and more until the fixtures clear the
            // non-vacuity bar below: a case-insensitive filesystem folds
            // `Azure`/`!azure`-style siblings together and Windows ignores
            // the permission modes (and may refuse the symlinks), so the
            // same seeds yield fewer modules there than on Unix.
            let mut seed = 0u64;
            while seed < 48 || ((crawled <= 100 || found <= 100) && seed < 480) {
                let tmp = tempfile::tempdir().unwrap();
                let mut gen = Gen {
                    rng: Rng::new(seed),
                    root: tmp.path().join("mod"),
                    outside: tmp.path().join("outside"),
                    perms: PermGuard::default(),
                    versioned: Vec::new(),
                };
                let root = gen.root.clone();
                gen.dir(&root, 0);
                gen.perms.apply();
                let (c, f) = assert_equivalent(&gen, &format!("seed {seed}")).await;
                crawled += c;
                found += f;
                seed += 1;
            }
            assert!(
                crawled > 100 && found > 100,
                "vacuous fixtures: {crawled}/{found}"
            );
        }

        #[tokio::test]
        async fn missing_cache_root_matches_the_async_oracle() {
            let tmp = tempfile::tempdir().unwrap();
            let gen = Gen {
                rng: Rng::new(0),
                root: tmp.path().join("absent"),
                outside: tmp.path().join("outside"),
                perms: PermGuard::default(),
                versioned: vec!["mod@v1.0.0".to_string()],
            };
            assert_equivalent(&gen, "absent root").await;
        }
    }
}
