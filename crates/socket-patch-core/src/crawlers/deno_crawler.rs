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
//!      `<root>/<scope>/<name>/<version>/` so that (a) synthetic
//!      test fixtures (`tests/crawler_deno_e2e.rs`) can stage
//!      scannable JSR-shaped trees, and (b) any future Deno that
//!      adopts a stable scope/name/version layout (or a third-party
//!      tool that materializes JSR packages this way) gets picked
//!      up automatically.
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
            let Some(((scope, name), version)) = crate::utils::purl::parse_jsr_purl(purl) else {
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
async fn scan_jsr_cache(root: &Path, seen: &mut HashSet<String>, out: &mut Vec<CrawledPackage>) {
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
                let purl = crate::utils::purl::build_jsr_purl(&scope_str, &name_str, &ver_str);
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
/// Deno itself derives its default cache root from the platform's
/// *system cache directory* (the `dirs::cache_dir()` convention), not
/// from a single hard-coded `~/.cache` path. We mirror that so global
/// JSR discovery looks where real Deno actually writes:
///
/// * `$DENO_DIR` env var wins (an empty value is treated as unset).
/// * macOS: `$HOME/Library/Caches/deno` (NOT `~/.cache/deno`).
/// * Linux/other Unix: `$XDG_CACHE_HOME/deno`, else `$HOME/.cache/deno`.
/// * Windows: `%LOCALAPPDATA%\deno` (falling back to `~\.cache\deno`
///   if LOCALAPPDATA isn't set).
fn deno_dir() -> PathBuf {
    if let Ok(d) = std::env::var("DENO_DIR") {
        if !d.is_empty() {
            return PathBuf::from(d);
        }
    }
    default_cache_root().join("deno")
}

/// Per-platform system cache root that Deno appends `deno` to.
#[cfg(target_os = "macos")]
fn default_cache_root() -> PathBuf {
    home_dir().join("Library").join("Caches")
}

/// Per-platform system cache root that Deno appends `deno` to.
#[cfg(windows)]
fn default_cache_root() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        if !local.is_empty() {
            return PathBuf::from(local);
        }
    }
    home_dir().join(".cache")
}

/// Per-platform system cache root that Deno appends `deno` to.
#[cfg(all(not(target_os = "macos"), not(windows)))]
fn default_cache_root() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg);
        }
    }
    home_dir().join(".cache")
}

/// Resolve the user's home directory, mirroring the `HOME` ->
/// `USERPROFILE` -> `~` fallback chain used by the other crawlers.
fn home_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "~".to_string());
    PathBuf::from(home)
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
        tokio::fs::write(tmp.path().join("deno.json"), b"{}")
            .await
            .unwrap();
        assert!(is_deno_project(tmp.path()).await);
    }

    #[tokio::test]
    async fn is_deno_project_detects_deno_jsonc() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("deno.jsonc"), b"{}")
            .await
            .unwrap();
        assert!(is_deno_project(tmp.path()).await);
    }

    #[tokio::test]
    async fn is_deno_project_detects_deno_lock() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("deno.lock"), b"{}")
            .await
            .unwrap();
        assert!(is_deno_project(tmp.path()).await);
    }

    #[tokio::test]
    async fn is_deno_project_rejects_unrelated_dir() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("package.json"), b"{}")
            .await
            .unwrap();
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

    // ── scan_jsr_cache layout behavior ─────────────────────────────

    /// Stage `<root>/<scope>/<name>/<version>/mod.ts`.
    async fn stage(root: &Path, scope: &str, name: &str, version: &str) {
        let pkg = root.join(scope).join(name).join(version);
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        tokio::fs::write(pkg.join("mod.ts"), b"export default 1;")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn scan_emits_every_version_of_a_package() {
        let tmp = tempfile::tempdir().unwrap();
        stage(tmp.path(), "@std", "path", "0.220.0").await;
        stage(tmp.path(), "@std", "path", "0.221.0").await;

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        scan_jsr_cache(tmp.path(), &mut seen, &mut out).await;

        let mut versions: Vec<&str> = out.iter().map(|p| p.version.as_str()).collect();
        versions.sort();
        assert_eq!(versions, vec!["0.220.0", "0.221.0"]);
        // Namespace keeps the leading `@`, matching the PURL convention.
        assert!(out.iter().all(|p| p.namespace.as_deref() == Some("@std")));
    }

    #[tokio::test]
    async fn scan_dedups_across_repeated_roots() {
        let tmp = tempfile::tempdir().unwrap();
        stage(tmp.path(), "@std", "path", "0.220.0").await;

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        // Same root scanned twice (mirrors two cache paths resolving to
        // the same package) must not yield a duplicate CrawledPackage.
        scan_jsr_cache(tmp.path(), &mut seen, &mut out).await;
        scan_jsr_cache(tmp.path(), &mut seen, &mut out).await;
        assert_eq!(out.len(), 1);
    }

    #[tokio::test]
    async fn scan_skips_files_at_scope_and_version_layers() {
        let tmp = tempfile::tempdir().unwrap();
        // A real package.
        stage(tmp.path(), "@std", "path", "0.220.0").await;
        // A stray `@`-prefixed file where a scope dir is expected.
        tokio::fs::write(tmp.path().join("@loose-file"), b"x")
            .await
            .unwrap();
        // A package dir whose only child is a file, not a version dir.
        let fs_dir = tmp.path().join("@std").join("fs");
        tokio::fs::create_dir_all(&fs_dir).await.unwrap();
        tokio::fs::write(fs_dir.join("readme.txt"), b"x")
            .await
            .unwrap();

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        scan_jsr_cache(tmp.path(), &mut seen, &mut out).await;

        // Only the real `@std/path@0.220.0` package is emitted; the stray
        // file at the scope layer and the version-less `@std/fs` (whose
        // only child is a file) are both skipped.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].purl, "pkg:jsr/@std/path@0.220.0");
    }

    #[tokio::test]
    async fn find_by_purls_resolves_qualified_purl_and_keys_by_input() {
        let tmp = tempfile::tempdir().unwrap();
        stage(tmp.path(), "@std", "path", "0.220.0").await;

        let qualified = "pkg:jsr/@std/path@0.220.0?repository_url=https://jsr.io";
        let crawler = DenoCrawler;
        let result = crawler
            .find_by_purls(tmp.path(), &[qualified.to_string()])
            .await
            .unwrap();

        // Resolved despite the qualifier, and keyed by the verbatim input
        // PURL (not the stripped form) so callers can look it back up.
        let entry = result.get(qualified).unwrap();
        assert_eq!(entry.name, "path");
        assert_eq!(entry.version, "0.220.0");
        assert_eq!(entry.namespace.as_deref(), Some("@std"));
    }

    #[tokio::test]
    async fn find_by_purls_skips_when_version_path_is_a_file() {
        // Malformed layout: the `<scope>/<name>/<version>` leaf is a
        // regular file, not the expected version directory. The `is_dir`
        // gate must reject it rather than emit a CrawledPackage whose
        // `path` points at a non-directory.
        let tmp = tempfile::tempdir().unwrap();
        let name_dir = tmp.path().join("@std").join("path");
        tokio::fs::create_dir_all(&name_dir).await.unwrap();
        tokio::fs::write(name_dir.join("0.220.0"), b"not a dir")
            .await
            .unwrap();

        let crawler = DenoCrawler;
        let result = crawler
            .find_by_purls(tmp.path(), &["pkg:jsr/@std/path@0.220.0".to_string()])
            .await
            .unwrap();
        assert!(
            result.is_empty(),
            "a file at the version path must not resolve, got {result:?}"
        );
    }

    #[tokio::test]
    async fn scan_tolerates_malformed_tree_without_emitting_phantoms() {
        // A grab-bag of malformed shapes that must all be skipped without
        // panicking: an empty scope dir, a scoped package with no version
        // dirs, and a non-`@` top-level dir holding a version-shaped tree.
        let tmp = tempfile::tempdir().unwrap();
        // The one real package.
        stage(tmp.path(), "@std", "path", "0.220.0").await;
        // Empty scope dir — no name children.
        tokio::fs::create_dir_all(tmp.path().join("@empty"))
            .await
            .unwrap();
        // Scoped package whose name dir has no version children.
        tokio::fs::create_dir_all(tmp.path().join("@std").join("nover"))
            .await
            .unwrap();
        // Non-`@` top-level dir with an otherwise-valid-looking subtree.
        tokio::fs::create_dir_all(tmp.path().join("bare").join("pkg").join("1.0.0"))
            .await
            .unwrap();

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        scan_jsr_cache(tmp.path(), &mut seen, &mut out).await;

        assert_eq!(out.len(), 1, "got {:?}", out);
        assert_eq!(out[0].purl, "pkg:jsr/@std/path@0.220.0");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn crawl_all_local_without_marker_returns_empty() {
        // crawl_all in LOCAL mode (no global / no prefix) must yield
        // nothing when the cwd has no Deno project marker, even if a
        // populated cache is reachable via DENO_DIR. Guards the
        // project-marker gate wiring through crawl_all, not just
        // get_jsr_cache_paths in isolation.
        let project = tempfile::tempdir().unwrap();
        let deno_home = tempfile::tempdir().unwrap();
        let jsr = deno_home.path().join("npm").join("jsr.io");
        stage(&jsr, "@std", "path", "0.220.0").await;
        let _g = EnvGuard::set("DENO_DIR", deno_home.path().to_str().unwrap());

        let crawler = DenoCrawler;
        let opts = CrawlerOptions {
            cwd: project.path().to_path_buf(), // no deno.json/.jsonc/.lock
            global: false,
            global_prefix: None,
            batch_size: 100,
        };
        assert!(crawler.crawl_all(&opts).await.is_empty());
    }

    #[tokio::test]
    async fn find_by_purls_skips_absent_version_keeps_present() {
        let tmp = tempfile::tempdir().unwrap();
        stage(tmp.path(), "@std", "path", "0.220.0").await;

        let crawler = DenoCrawler;
        let result = crawler
            .find_by_purls(
                tmp.path(),
                &[
                    "pkg:jsr/@std/path@0.220.0".to_string(),
                    // Same package, version not on disk — must be skipped.
                    "pkg:jsr/@std/path@9.9.9".to_string(),
                ],
            )
            .await
            .unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:jsr/@std/path@0.220.0"));
    }

    // ── deno_dir / cache-root resolution ───────────────────────────

    /// Save and restore an env var around a closure body.
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
    fn deno_dir_honors_explicit_env() {
        let _g = EnvGuard::set("DENO_DIR", "/tmp/custom-deno");
        assert_eq!(deno_dir(), PathBuf::from("/tmp/custom-deno"));
    }

    #[test]
    #[serial_test::serial]
    fn deno_dir_treats_empty_env_as_unset() {
        // Empty DENO_DIR must NOT resolve to PathBuf::from("") — it falls
        // through to the platform default, which always ends in `deno`.
        let _g = EnvGuard::set("DENO_DIR", "");
        let dir = deno_dir();
        assert_ne!(dir, PathBuf::from(""));
        assert!(dir.ends_with("deno"), "got {dir:?}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial_test::serial]
    fn deno_dir_uses_library_caches_on_macos() {
        let _g = EnvGuard::unset("DENO_DIR");
        let dir = deno_dir();
        // Regression: macOS must NOT use ~/.cache/deno.
        assert!(
            dir.ends_with("Library/Caches/deno"),
            "macOS default should live under Library/Caches, got {dir:?}"
        );
        assert!(!dir.to_string_lossy().contains("/.cache/"));
    }

    #[cfg(all(not(target_os = "macos"), not(windows)))]
    #[test]
    #[serial_test::serial]
    fn deno_dir_honors_xdg_cache_home_on_linux() {
        let _d = EnvGuard::unset("DENO_DIR");
        let _x = EnvGuard::set("XDG_CACHE_HOME", "/tmp/xdg-cache");
        assert_eq!(deno_dir(), PathBuf::from("/tmp/xdg-cache").join("deno"));
    }

    #[cfg(all(not(target_os = "macos"), not(windows)))]
    #[test]
    #[serial_test::serial]
    fn deno_dir_falls_back_to_dot_cache_on_linux() {
        let _d = EnvGuard::unset("DENO_DIR");
        let _x = EnvGuard::unset("XDG_CACHE_HOME");
        let dir = deno_dir();
        assert!(dir.ends_with(".cache/deno"), "got {dir:?}");
    }
}
