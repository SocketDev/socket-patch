//! Integration coverage for `crawlers::go_crawler`.

#![cfg(feature = "golang")]

use std::path::Path;

use serial_test::serial;
use socket_patch_core::crawlers::go_crawler::{
    decode_module_path, encode_module_path, parse_go_mod_module,
};
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::GoCrawler;

const ORG_PURL: &str = "pkg:golang/github.com/gin-gonic/gin@v1.9.1";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

async fn stage_go_module(cache: &Path, module_path: &str, version: &str) -> std::path::PathBuf {
    let encoded = encode_module_path(module_path);
    let pkg = cache.join(format!("{encoded}@{version}"));
    tokio::fs::create_dir_all(&pkg).await.unwrap();
    pkg
}

// ── encode_module_path / decode_module_path ─────────────────────

#[test]
fn encode_module_path_lowercases_uppercase() {
    // Per Go module proxy spec, uppercase letters get encoded as
    // `!<lowercase>` so the filesystem lookup is unambiguous on
    // case-insensitive filesystems.
    let encoded = encode_module_path("github.com/Sirupsen/logrus");
    assert_eq!(encoded, "github.com/!sirupsen/logrus");
}

#[test]
fn encode_module_path_no_uppercase_passthrough() {
    let encoded = encode_module_path("github.com/gin-gonic/gin");
    assert_eq!(encoded, "github.com/gin-gonic/gin");
}

#[test]
fn decode_module_path_inverts_encode() {
    let encoded = encode_module_path("github.com/Sirupsen/logrus");
    assert_eq!(decode_module_path(&encoded), "github.com/Sirupsen/logrus");
}

#[test]
fn decode_module_path_no_bang_passthrough() {
    assert_eq!(
        decode_module_path("github.com/gin-gonic/gin"),
        "github.com/gin-gonic/gin"
    );
}

// ── parse_go_mod_module ────────────────────────────────────────

#[test]
fn parse_go_mod_well_formed() {
    let content = "module github.com/gin-gonic/gin\n\ngo 1.21\n";
    assert_eq!(
        parse_go_mod_module(content),
        Some("github.com/gin-gonic/gin".to_string())
    );
}

#[test]
fn parse_go_mod_missing_module_returns_none() {
    let content = "go 1.21\n";
    assert_eq!(parse_go_mod_module(content), None);
}

#[test]
fn parse_go_mod_empty_returns_none() {
    assert_eq!(parse_go_mod_module(""), None);
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_finds_module_in_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = stage_go_module(tmp.path(), "github.com/gin-gonic/gin", "v1.9.1").await;

    let crawler = GoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(ORG_PURL).unwrap().path, pkg);
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = GoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = GoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:not-golang/foo@1.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── get_module_cache_paths ─────────────────────────────────────

#[tokio::test]
async fn get_module_cache_paths_with_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = GoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let paths = crawler.get_module_cache_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
#[serial]
async fn get_module_cache_paths_local_no_go_mod_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = GoCrawler;
    let prev_cache = std::env::var("GOMODCACHE").ok();
    std::env::remove_var("GOMODCACHE");
    let paths = crawler.get_module_cache_paths(&options_at(tmp.path())).await.unwrap();
    if let Some(v) = prev_cache {
        std::env::set_var("GOMODCACHE", v);
    }
    assert!(paths.is_empty(), "non-Go dir must return empty paths");
}

#[tokio::test]
#[serial]
async fn get_module_cache_paths_with_go_mod_returns_cache() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("go.mod"), b"module example.com/test\n\ngo 1.21\n")
        .await
        .unwrap();
    let cache = tempfile::tempdir().unwrap();
    let prev = std::env::var("GOMODCACHE").ok();
    std::env::set_var("GOMODCACHE", cache.path());

    let crawler = GoCrawler;
    let paths = crawler.get_module_cache_paths(&options_at(tmp.path())).await.unwrap();

    std::env::remove_var("GOMODCACHE");
    if let Some(v) = prev {
        std::env::set_var("GOMODCACHE", v);
    }

    assert!(
        paths.iter().any(|p| p == cache.path()),
        "go.mod must trigger GOMODCACHE fallback; got {paths:?}"
    );
}

#[path = "common/mod.rs"]
mod common;

/// `scan_dir_recursive` short-circuits when read_dir returns Err.
#[cfg(unix)]
#[tokio::test]
async fn crawl_all_handles_unreadable_cache_path() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let cache = tmp.path().join("blocked-cache");
    tokio::fs::create_dir(&cache).await.unwrap();
    let _ = stage_go_module(&cache, "github.com/foo/bar", "v1.0.0").await;
    common::chmod_unreadable(&cache);

    let crawler = GoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(cache.clone()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&cache);

    assert!(result.is_empty(), "unreadable cache must yield empty");
}

/// `GoCrawler::default()` should forward to `new()`.
#[test]
fn go_crawler_default_and_new_construct_cleanly() {
    let _a = GoCrawler::default();
    let _b = GoCrawler::new();
}

/// A `module` directive with no path (`module`) must not match — the
/// guard at line 61 (`!rest.is_empty()`) keeps it from being returned.
#[test]
fn parse_go_mod_module_directive_with_empty_path_returns_none() {
    assert_eq!(parse_go_mod_module("module\n"), None);
}

/// Quoted module path with whitespace — the strip-quotes branch.
#[test]
fn parse_go_mod_module_quoted_path() {
    assert_eq!(
        parse_go_mod_module(r#"module "github.com/foo/bar""#),
        Some("github.com/foo/bar".to_string())
    );
}

/// `!` at the end of an encoded path with no following character — the
/// trailing-`!` arm of decode_module_path silently drops the bang
/// (line 38 inner `if let Some(next) = chars.next()` false arm).
#[test]
fn decode_module_path_trailing_bang_is_dropped() {
    assert_eq!(decode_module_path("github.com/foo!"), "github.com/foo");
}

/// `find_by_purls` with a directory matching the module name but the
/// path missing — exercise the `is_dir(module_dir)` false branch.
#[tokio::test]
async fn find_by_purls_module_dir_missing_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // Note: stage NO module dir for this purl.
    let crawler = GoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:golang/github.com/gin-gonic/gin@v1.9.1".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

/// `crawl_all` over a cache with a versioned subdir several levels deep
/// — exercises the recursive scan + parse_versioned_dir path.
#[tokio::test]
#[serial]
async fn crawl_all_finds_nested_versioned_module() {
    let tmp = tempfile::tempdir().unwrap();
    // Stage <cache>/github.com/gin-gonic/gin@v1.9.1/
    let module_dir = tmp.path().join("github.com").join("gin-gonic").join("gin@v1.9.1");
    tokio::fs::create_dir_all(&module_dir).await.unwrap();

    let crawler = GoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "gin");
    assert_eq!(result[0].version, "v1.9.1");
    assert_eq!(result[0].namespace.as_deref(), Some("github.com/gin-gonic"));
}

/// `cache` directory inside the module cache is metadata, must be
/// skipped (line 249 second arm).
#[tokio::test]
#[serial]
async fn crawl_all_skips_cache_metadata_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_meta = tmp.path().join("cache");
    tokio::fs::create_dir_all(cache_meta.join("download").join("module@v1.0.0")).await.unwrap();

    let crawler = GoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty(), "cache/ subtree must be skipped; got {result:?}");
}

/// With GOMODCACHE and GOPATH both unset, `get_gomodcache` falls
/// through to `$HOME/go/pkg/mod` (lines 194-197).
#[tokio::test]
#[serial]
async fn get_module_cache_paths_home_go_pkg_mod_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("go.mod"), b"module example.com/test\n\ngo 1.21\n")
        .await
        .unwrap();
    let prev_gomod = std::env::var("GOMODCACHE").ok();
    let prev_gopath = std::env::var("GOPATH").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::remove_var("GOMODCACHE");
    std::env::remove_var("GOPATH");
    std::env::set_var("HOME", tmp.path());

    let crawler = GoCrawler;
    let paths = crawler.get_module_cache_paths(&options_at(tmp.path())).await.unwrap();

    if let Some(v) = prev_gomod {
        std::env::set_var("GOMODCACHE", v);
    }
    if let Some(v) = prev_gopath {
        std::env::set_var("GOPATH", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    let expected = tmp.path().join("go").join("pkg").join("mod");
    assert!(
        paths.iter().any(|p| p == &expected),
        "HOME/go/pkg/mod fallback must work; got {paths:?}"
    );
}

#[tokio::test]
#[serial]
async fn get_module_cache_paths_gopath_fallback_when_gomodcache_unset() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("go.mod"), b"module example.com/test\n\ngo 1.21\n")
        .await
        .unwrap();
    let gopath = tempfile::tempdir().unwrap();
    let expected = gopath.path().join("pkg").join("mod");
    let prev_gomod = std::env::var("GOMODCACHE").ok();
    let prev_gopath = std::env::var("GOPATH").ok();
    std::env::remove_var("GOMODCACHE");
    std::env::set_var("GOPATH", gopath.path());

    let crawler = GoCrawler;
    let paths = crawler.get_module_cache_paths(&options_at(tmp.path())).await.unwrap();

    std::env::remove_var("GOPATH");
    if let Some(v) = prev_gomod {
        std::env::set_var("GOMODCACHE", v);
    }
    if let Some(v) = prev_gopath {
        std::env::set_var("GOPATH", v);
    }

    assert!(
        paths.iter().any(|p| p == &expected),
        "GOPATH/pkg/mod fallback must work; got {paths:?}"
    );
}
