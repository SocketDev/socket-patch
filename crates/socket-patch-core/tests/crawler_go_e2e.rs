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
