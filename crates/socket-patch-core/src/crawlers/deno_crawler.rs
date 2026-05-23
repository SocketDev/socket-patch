//! Deno ecosystem crawler.
//!
//! Deno has two package surfaces, only ONE of which fits the
//! patch-by-PURL model:
//!
//!   1. **`deno install` with a `package.json`** (PATCHABLE) —
//!      populates a standard `node_modules/` directory at the
//!      project root. These packages are real npm packages from
//!      registry.npmjs.org and surface as `pkg:npm/<name>@<version>`
//!      PURLs handled by `NpmCrawler`. The DenoCrawler does NOT
//!      duplicate that walk — it just gates discovery on
//!      `deno.json` / `deno.jsonc` / `deno.lock` project markers so
//!      `socket-patch scan` from a Deno project root finds the
//!      node_modules tree.
//!
//!   2. **JSR registry packages** (LIMITED) — Deno's native registry
//!      (https://jsr.io). Real Deno (as of v2.x) caches JSR packages
//!      content-addressed at `$DENO_DIR/remote/https/jsr.io/<sha256>`
//!      with no scope/name/version structure on disk. The PURL
//!      `pkg:jsr/<scope>/<name>@<version>` cannot be mapped to a
//!      cache file by walking the filesystem — you'd need to compute
//!      SHA256 of `https://jsr.io/<scope>/<name>/<version>/<file>`
//!      and look up by content hash, which is fragile.
//!
//!      This crawler walks an *expected* layout of
//!      `<root>/<scope>/<name>/<version>/` so that:
//!        (a) synthetic test fixtures (`tests/crawler_deno_e2e.rs`)
//!            can stage scannable JSR-shaped trees, and
//!        (b) any future Deno that adopts a stable scope/name/version
//!            layout (or a third-party tool that materializes JSR
//!            packages this way) gets picked up automatically.
//!
//!      In the meantime, `socket-patch scan --global --ecosystems
//!      deno --global-prefix <path>` is what real users would invoke
//!      against a directory they've explicitly populated.
//!
//! HTTPS URL imports (`import "https://deno.land/..."`) are out of
//! scope: same content-addressed-by-hash storage as JSR, plus no
//! upstream PURL convention.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};

/// Deno (JSR) ecosystem crawler.
pub struct DenoCrawler;

impl DenoCrawler {
    /// Create a new `DenoCrawler`.
    pub fn new() -> Self {
        Self
    }

    /// Get the JSR cache root paths to scan.
    ///
    /// In global mode (or with `--global-prefix`), returns
    /// `$DENO_DIR/npm/jsr.io/` directly.
    ///
    /// In local mode, only returns paths when the cwd looks like a
    /// Deno project (`deno.json`, `deno.jsonc`, or `deno.lock`
    /// present). Mirrors the cargo / ruby / go project-marker gate.
    pub async fn get_jsr_cache_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            let cache = deno_dir().join("npm").join("jsr.io");
            if is_dir(&cache).await {
                return Ok(vec![cache]);
            }
            return Ok(Vec::new());
        }

        if !is_deno_project(&options.cwd).await {
            return Ok(Vec::new());
        }

        let cache = deno_dir().join("npm").join("jsr.io");
        if is_dir(&cache).await {
            Ok(vec![cache])
        } else {
            Ok(Vec::new())
        }
    }

    /// Crawl JSR cache(s) and return every `pkg:jsr/...` package
    /// present. JSR cache layout is
    /// `<root>/@<scope>/<name>/<version>/<package contents>`.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let cache_paths = self.get_jsr_cache_paths(options).await.unwrap_or_default();
        for cache_path in &cache_paths {
            scan_jsr_cache(cache_path, &mut seen, &mut packages).await;
        }

        packages
    }

    /// Find specific JSR packages by PURL inside a single JSR cache
    /// root. Non-`pkg:jsr/...` PURLs in the input are silently
    /// skipped — they belong to the npm crawler.
    pub async fn find_by_purls(
        &self,
        jsr_cache_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            let Some(((scope, name), version)) =
                crate::utils::purl::parse_jsr_purl(purl)
            else {
                continue;
            };
            // Cache layout: <root>/<scope>/<name>/<version>/
            let pkg_dir = jsr_cache_path.join(scope).join(name).join(version);
            if !is_dir(&pkg_dir).await {
                continue;
            }
            result.insert(
                purl.clone(),
                CrawledPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    namespace: Some(scope.to_string()),
                    purl: purl.clone(),
                    path: pkg_dir,
                },
            );
        }

        Ok(result)
    }
}

impl Default for DenoCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Walk `<root>/@<scope>/<name>/<version>/` and emit a
/// `CrawledPackage` per (scope, name, version) tuple found.
async fn scan_jsr_cache(
    root: &Path,
    seen: &mut HashSet<String>,
    out: &mut Vec<CrawledPackage>,
) {
    // Layer 1: scope dirs like `@std/`, `@luca/`.
    for scope_entry in crate::utils::fs::list_dir_entries(root).await {
        if !crate::utils::fs::entry_is_dir(&scope_entry).await {
            continue;
        }
        let scope_name = scope_entry.file_name();
        let scope_str = scope_name.to_string_lossy().to_string();
        if !scope_str.starts_with('@') {
            continue;
        }
        let scope_path = root.join(&scope_str);

        // Layer 2: package name dirs under the scope.
        for name_entry in crate::utils::fs::list_dir_entries(&scope_path).await {
            if !crate::utils::fs::entry_is_dir(&name_entry).await {
                continue;
            }
            let name_str = name_entry.file_name().to_string_lossy().to_string();
            let name_path = scope_path.join(&name_str);

            // Layer 3: version dirs under the package.
            for ver_entry in crate::utils::fs::list_dir_entries(&name_path).await {
                if !crate::utils::fs::entry_is_dir(&ver_entry).await {
                    continue;
                }
                let ver_str = ver_entry.file_name().to_string_lossy().to_string();
                let pkg_path = name_path.join(&ver_str);
                let purl =
                    crate::utils::purl::build_jsr_purl(&scope_str, &name_str, &ver_str);
                if seen.insert(purl.clone()) {
                    out.push(CrawledPackage {
                        name: name_str.clone(),
                        version: ver_str,
                        namespace: Some(scope_str.clone()),
                        purl,
                        path: pkg_path,
                    });
                }
            }
        }
    }
}

/// Returns true if `cwd` looks like a Deno project.
///
/// Markers checked: `deno.json`, `deno.jsonc`, `deno.lock`. None are
/// parsed — we just look for presence. Matches the `is_python_project`
/// / `is_dotnet_project` pattern elsewhere.
async fn is_deno_project(cwd: &Path) -> bool {
    let markers = ["deno.json", "deno.jsonc", "deno.lock"];
    for m in &markers {
        if tokio::fs::metadata(cwd.join(m)).await.is_ok() {
            return true;
        }
    }
    false
}

/// Resolve `$DENO_DIR`, falling back to platform defaults.
///
/// * `$DENO_DIR` env var wins.
/// * Linux/macOS: `$HOME/.cache/deno`.
/// * Windows: `%LOCALAPPDATA%\deno` (falling back to `~\.cache\deno`
///   if LOCALAPPDATA isn't set).
fn deno_dir() -> PathBuf {
    if let Ok(d) = std::env::var("DENO_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("deno");
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "~".to_string());
    PathBuf::from(home).join(".cache").join("deno")
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

    #[tokio::test]
    async fn is_deno_project_detects_deno_json() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("deno.json"), b"{}").await.unwrap();
        assert!(is_deno_project(tmp.path()).await);
    }

    #[tokio::test]
    async fn is_deno_project_detects_deno_jsonc() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("deno.jsonc"), b"{}").await.unwrap();
        assert!(is_deno_project(tmp.path()).await);
    }

    #[tokio::test]
    async fn is_deno_project_detects_deno_lock() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("deno.lock"), b"{}").await.unwrap();
        assert!(is_deno_project(tmp.path()).await);
    }

    #[tokio::test]
    async fn is_deno_project_rejects_unrelated_dir() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("package.json"), b"{}").await.unwrap();
        assert!(!is_deno_project(tmp.path()).await);
    }

    #[tokio::test]
    async fn deno_crawler_default_and_new_construct_cleanly() {
        let _a = DenoCrawler::default();
        let _b = DenoCrawler::new();
    }

    #[tokio::test]
    async fn crawl_all_empty_cache_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("npm").join("jsr.io");
        tokio::fs::create_dir_all(&cache).await.unwrap();
        let crawler = DenoCrawler;
        let opts = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: true,
            global_prefix: Some(cache),
            batch_size: 100,
        };
        assert!(crawler.crawl_all(&opts).await.is_empty());
    }
}
