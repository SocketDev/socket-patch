//! Integration coverage for `crawlers::deno_crawler` paths the
//! docker e2e suite doesn't drive (project-marker gates, env-var
//! resolution, malformed cache layouts, etc.).

#![cfg(feature = "deno")]

use std::path::Path;

use serial_test::serial;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::DenoCrawler;

const ORG_PURL: &str = "pkg:jsr/@std/path@0.220.0";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
    }
}

/// Save/restore an env var around a test body, restoring even if the
/// body panics mid-assert (important: these tests are `#[serial]`, so a
/// leaked `DENO_DIR` would poison sibling tests' default-resolution).
struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
}
impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
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

/// Stage a JSR package: `<root>/<scope>/<name>/<version>/mod.ts`.
async fn stage_jsr_pkg(root: &Path, scope: &str, name: &str, version: &str) -> std::path::PathBuf {
    let pkg = root.join(scope).join(name).join(version);
    tokio::fs::create_dir_all(&pkg).await.unwrap();
    tokio::fs::write(pkg.join("mod.ts"), b"export default 1;")
        .await
        .unwrap();
    pkg
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_finds_jsr_package() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = stage_jsr_pkg(tmp.path(), "@std", "path", "0.220.0").await;

    let crawler = DenoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    let entry = result.get(ORG_PURL).unwrap();
    assert_eq!(entry.path, pkg);
    // The resolved path must actually point at the staged dir on disk,
    // not just be string-equal to an arbitrary join.
    assert!(entry.path.is_dir(), "resolved path must be a real dir");
    assert!(entry.path.join("mod.ts").is_file());
    assert_eq!(entry.name, "path");
    assert_eq!(entry.namespace.as_deref(), Some("@std"));
    assert_eq!(entry.version, "0.220.0");
    assert_eq!(entry.purl, ORG_PURL);
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // Cache is NOT empty: a *different* package is present. This proves
    // the empty result is selectivity (no match for the queried PURL),
    // not a "return-everything" / "return-nothing" implementation that
    // would also pass against a bare directory.
    stage_jsr_pkg(tmp.path(), "@std", "fs", "9.9.9").await;

    let crawler = DenoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "querying an absent PURL must not return the unrelated staged package"
    );
}

#[tokio::test]
async fn find_by_purls_non_jsr_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    // Stage a tree that an *ecosystem-blind* parser (one that ignored
    // the `pkg:jsr/` prefix and just split scope/name/version) would
    // happily resolve from the npm PURL below. A correct crawler skips
    // the PURL on the `jsr` gate and never looks here.
    stage_jsr_pkg(tmp.path(), "@types", "node", "1.0.0").await;

    let crawler = DenoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:npm/@types/node@1.0.0".to_string()])
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "non-jsr PURLs must be ignored by DenoCrawler even when a matching tree exists"
    );
}

/// The scope is part of the lookup key: a PURL must NOT resolve from a
/// package that exists on disk under a *different* scope. Guards a
/// regression that drops/ignores the scope segment when joining the
/// path (which would let `@other/path` satisfy a `@std/path` query).
#[tokio::test]
async fn find_by_purls_wrong_scope_not_resolved() {
    let tmp = tempfile::tempdir().unwrap();
    // Same name + version, but under `@other`, not the queried `@std`.
    stage_jsr_pkg(tmp.path(), "@other", "path", "0.220.0").await;

    let crawler = DenoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "a different-scope package must not satisfy the queried PURL, got {result:?}"
    );
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_enumerates_jsr_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let std_path = stage_jsr_pkg(tmp.path(), "@std", "path", "0.220.0").await;
    stage_jsr_pkg(tmp.path(), "@std", "fs", "0.220.0").await;
    stage_jsr_pkg(tmp.path(), "@luca", "flag", "1.0.0").await;

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let result = crawler.crawl_all(&opts).await;
    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert!(purls.contains(&"pkg:jsr/@std/path@0.220.0"));
    assert!(purls.contains(&"pkg:jsr/@std/fs@0.220.0"));
    assert!(purls.contains(&"pkg:jsr/@luca/flag@1.0.0"));
    assert_eq!(result.len(), 3);

    // The fully-decoded record for one package must be exact — guards a
    // regression that strips/mangles the scope or mis-maps the path.
    let entry = result
        .iter()
        .find(|p| p.purl == "pkg:jsr/@std/path@0.220.0")
        .expect("std/path must be enumerated");
    assert_eq!(entry.name, "path");
    assert_eq!(entry.namespace.as_deref(), Some("@std"));
    assert_eq!(entry.version, "0.220.0");
    assert_eq!(entry.path, std_path);
}

/// `crawl_all` in global mode WITHOUT `--global-prefix` must resolve
/// the cache from `$DENO_DIR/npm/jsr.io` and actually scan it. The
/// other DENO_DIR tests only exercise `get_jsr_cache_paths`; this one
/// guards the full `get_jsr_cache_paths -> scan_jsr_cache` wiring real
/// `scan --global --ecosystems deno` users hit, so a regression that
/// resolves the path but fails to feed it into the scan surfaces here.
#[tokio::test]
#[serial]
async fn crawl_all_global_via_deno_dir_env_scans_cache() {
    let deno_home = tempfile::tempdir().unwrap();
    let jsr = deno_home.path().join("npm").join("jsr.io");
    let pkg = stage_jsr_pkg(&jsr, "@std", "path", "0.220.0").await;
    let _g = EnvGuard::set("DENO_DIR", deno_home.path());

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        // cwd is irrelevant in global mode; point it somewhere with no
        // markers to prove the cache came from DENO_DIR, not the cwd.
        cwd: tempfile::tempdir().unwrap().path().to_path_buf(),
        global: true,
        global_prefix: None,
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 1, "got {:?}", result);
    assert_eq!(result[0].purl, ORG_PURL);
    assert_eq!(result[0].path, pkg);
}

/// The walk must stop AT the version layer: directory contents *inside*
/// a version dir (`mod.ts`, a nested `src/`, deeper version-shaped
/// dirs) are package payload, never separate packages. Guards against a
/// regression that adds a fourth descent level and emits phantom
/// packages like `pkg:jsr/@std/path@src`.
#[tokio::test]
async fn crawl_all_does_not_recurse_below_version_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = stage_jsr_pkg(tmp.path(), "@std", "path", "0.220.0").await;
    // Nested payload dirs under the version — one even shaped like a
    // version number to bait a fourth-layer walk.
    tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
    tokio::fs::create_dir_all(pkg.join("0.0.0")).await.unwrap();

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(
        result.len(),
        1,
        "only the version dir is a package; nested dirs are payload, got {:?}",
        result.iter().map(|p| p.purl.as_str()).collect::<Vec<_>>()
    );
    assert_eq!(result[0].purl, ORG_PURL);
}

#[tokio::test]
async fn crawl_all_skips_dirs_not_starting_with_at() {
    let tmp = tempfile::tempdir().unwrap();
    // Legitimate scope.
    stage_jsr_pkg(tmp.path(), "@std", "path", "0.220.0").await;
    // Bogus entry without an `@` prefix — must be ignored.
    tokio::fs::create_dir_all(tmp.path().join("notascope").join("foo").join("1.0.0"))
        .await
        .unwrap();

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let result = crawler.crawl_all(&opts).await;
    // Exactly the one legitimate package — not the bogus `notascope/foo`.
    assert_eq!(
        result.len(),
        1,
        "only the @-prefixed scope should survive, got {:?}",
        result.iter().map(|p| p.purl.as_str()).collect::<Vec<_>>()
    );
    let only = &result[0];
    assert_eq!(only.purl, "pkg:jsr/@std/path@0.220.0");
    assert_eq!(only.name, "path");
    assert_eq!(only.namespace.as_deref(), Some("@std"));
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(
        !names.contains(&"foo"),
        "non-`@`-prefixed dir must be skipped"
    );
}

// ── get_jsr_cache_paths ────────────────────────────────────────

#[tokio::test]
async fn get_jsr_cache_paths_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let paths = crawler.get_jsr_cache_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
#[serial]
async fn get_jsr_cache_paths_global_via_deno_dir_env() {
    let tmp = tempfile::tempdir().unwrap();
    let jsr = tmp.path().join("npm").join("jsr.io");
    tokio::fs::create_dir_all(&jsr).await.unwrap();

    let _g = EnvGuard::set("DENO_DIR", tmp.path());

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
    };
    let paths = crawler.get_jsr_cache_paths(&opts).await.unwrap();

    assert_eq!(paths, vec![jsr]);
}

#[tokio::test]
#[serial]
async fn get_jsr_cache_paths_global_deno_dir_missing_cache_returns_empty() {
    // Global mode + DENO_DIR set, but the `npm/jsr.io` cache dir does
    // NOT exist. The `is_dir` gate must filter it out — a regression
    // that returns the path unconditionally would surface here.
    let tmp = tempfile::tempdir().unwrap();
    let _g = EnvGuard::set("DENO_DIR", tmp.path());

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
    };
    let paths = crawler.get_jsr_cache_paths(&opts).await.unwrap();
    assert!(
        paths.is_empty(),
        "missing jsr.io cache dir must yield no paths, got {paths:?}"
    );
}

#[tokio::test]
#[serial]
async fn get_jsr_cache_paths_local_no_marker_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let deno_home = tempfile::tempdir().unwrap();
    // Point DENO_DIR at a REAL, populated jsr cache so the only thing
    // standing between the crawler and a non-empty result is the
    // project-marker gate. Without this, a regression that drops the
    // `is_deno_project` check would still return empty (because the
    // ambient cache doesn't exist) and the test would pass vacuously.
    let jsr = deno_home.path().join("npm").join("jsr.io");
    tokio::fs::create_dir_all(&jsr).await.unwrap();
    let _g = EnvGuard::set("DENO_DIR", deno_home.path());

    // No deno.json / .jsonc / .lock — not a Deno project.
    let crawler = DenoCrawler;
    let paths = crawler
        .get_jsr_cache_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(
        paths.is_empty(),
        "local mode without a Deno project marker must return no paths even when the cache exists, got {paths:?}"
    );
}

#[tokio::test]
#[serial]
async fn get_jsr_cache_paths_local_with_deno_json_falls_back_to_cache() {
    let project = tempfile::tempdir().unwrap();
    let deno_home = tempfile::tempdir().unwrap();
    tokio::fs::write(project.path().join("deno.json"), b"{}")
        .await
        .unwrap();
    let jsr = deno_home.path().join("npm").join("jsr.io");
    tokio::fs::create_dir_all(&jsr).await.unwrap();

    let _g = EnvGuard::set("DENO_DIR", deno_home.path());

    let crawler = DenoCrawler;
    let paths = crawler
        .get_jsr_cache_paths(&options_at(project.path()))
        .await
        .unwrap();

    assert_eq!(paths, vec![jsr]);
}
