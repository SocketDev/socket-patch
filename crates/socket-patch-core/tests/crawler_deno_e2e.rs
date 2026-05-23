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
        batch_size: 100,
    }
}

/// Stage a JSR package: `<root>/<scope>/<name>/<version>/mod.ts`.
async fn stage_jsr_pkg(
    root: &Path,
    scope: &str,
    name: &str,
    version: &str,
) -> std::path::PathBuf {
    let pkg = root.join(scope).join(name).join(version);
    tokio::fs::create_dir_all(&pkg).await.unwrap();
    tokio::fs::write(pkg.join("mod.ts"), b"export default 1;").await.unwrap();
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
    assert_eq!(entry.name, "path");
    assert_eq!(entry.namespace.as_deref(), Some("@std"));
    assert_eq!(entry.version, "0.220.0");
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = DenoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_non_jsr_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = DenoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:npm/lodash@4.17.21".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty(), "non-jsr PURLs must be ignored by DenoCrawler");
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_enumerates_jsr_packages() {
    let tmp = tempfile::tempdir().unwrap();
    stage_jsr_pkg(tmp.path(), "@std", "path", "0.220.0").await;
    stage_jsr_pkg(tmp.path(), "@std", "fs", "0.220.0").await;
    stage_jsr_pkg(tmp.path(), "@luca", "flag", "1.0.0").await;

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert!(purls.contains(&"pkg:jsr/@std/path@0.220.0"));
    assert!(purls.contains(&"pkg:jsr/@std/fs@0.220.0"));
    assert!(purls.contains(&"pkg:jsr/@luca/flag@1.0.0"));
    assert_eq!(result.len(), 3);
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
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"path"));
    assert!(!names.contains(&"foo"), "non-`@`-prefixed dir must be skipped");
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
        batch_size: 100,
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

    let prev = std::env::var("DENO_DIR").ok();
    std::env::set_var("DENO_DIR", tmp.path());

    let crawler = DenoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_jsr_cache_paths(&opts).await.unwrap();

    if let Some(v) = prev {
        std::env::set_var("DENO_DIR", v);
    } else {
        std::env::remove_var("DENO_DIR");
    }

    assert_eq!(paths, vec![jsr]);
}

#[tokio::test]
#[serial]
async fn get_jsr_cache_paths_local_no_marker_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No deno.json / .jsonc / .lock — not a Deno project.
    let crawler = DenoCrawler;
    let paths = crawler.get_jsr_cache_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty());
}

#[tokio::test]
#[serial]
async fn get_jsr_cache_paths_local_with_deno_json_falls_back_to_cache() {
    let project = tempfile::tempdir().unwrap();
    let deno_home = tempfile::tempdir().unwrap();
    tokio::fs::write(project.path().join("deno.json"), b"{}").await.unwrap();
    let jsr = deno_home.path().join("npm").join("jsr.io");
    tokio::fs::create_dir_all(&jsr).await.unwrap();

    let prev = std::env::var("DENO_DIR").ok();
    std::env::set_var("DENO_DIR", deno_home.path());

    let crawler = DenoCrawler;
    let paths = crawler.get_jsr_cache_paths(&options_at(project.path())).await.unwrap();

    if let Some(v) = prev {
        std::env::set_var("DENO_DIR", v);
    } else {
        std::env::remove_var("DENO_DIR");
    }

    assert_eq!(paths, vec![jsr]);
}
