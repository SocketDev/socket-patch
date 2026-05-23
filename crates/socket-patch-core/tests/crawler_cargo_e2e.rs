//! Integration coverage for `crawlers::cargo_crawler`.

#![cfg(feature = "cargo")]

use std::path::Path;

use socket_patch_core::crawlers::cargo_crawler::parse_cargo_toml_name_version;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::CargoCrawler;

const ORG_PURL: &str = "pkg:cargo/serde@1.0.200";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

async fn stage_registry_crate(src: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg = src.join(format!("{name}-{version}"));
    tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
    let cargo_toml = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
    );
    tokio::fs::write(pkg.join("Cargo.toml"), cargo_toml).await.unwrap();
    tokio::fs::write(pkg.join("src").join("lib.rs"), b"// stub").await.unwrap();
    pkg
}

async fn stage_vendor_crate(src: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg = src.join(name);
    tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
    let cargo_toml = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
    );
    tokio::fs::write(pkg.join("Cargo.toml"), cargo_toml).await.unwrap();
    pkg
}

// ── parse_cargo_toml_name_version ──────────────────────────────

#[test]
fn parse_cargo_toml_well_formed() {
    let toml =
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\nedition = \"2021\"\n";
    assert_eq!(
        parse_cargo_toml_name_version(toml),
        Some(("serde".to_string(), "1.0.200".to_string()))
    );
}

#[test]
fn parse_cargo_toml_missing_name_returns_none() {
    let toml = "[package]\nversion = \"1.0.200\"\n";
    assert_eq!(parse_cargo_toml_name_version(toml), None);
}

#[test]
fn parse_cargo_toml_missing_version_returns_none() {
    let toml = "[package]\nname = \"serde\"\n";
    assert_eq!(parse_cargo_toml_name_version(toml), None);
}

#[test]
fn parse_cargo_toml_malformed_returns_none() {
    let toml = "this is not toml at all";
    assert_eq!(parse_cargo_toml_name_version(toml), None);
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_registry_layout_finds_crate() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = stage_registry_crate(tmp.path(), "serde", "1.0.200").await;

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(ORG_PURL).unwrap().path, pkg);
}

#[tokio::test]
async fn find_by_purls_vendor_layout_finds_crate() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = stage_vendor_crate(tmp.path(), "serde", "1.0.200").await;

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(ORG_PURL).unwrap().path, pkg);
}

#[tokio::test]
async fn find_by_purls_vendor_version_mismatch_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    stage_vendor_crate(tmp.path(), "serde", "1.0.200").await;

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:cargo/serde@99.99.99".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty(), "version mismatch in vendor must skip");
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:not-cargo/serde@1.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_via_registry_layout() {
    let tmp = tempfile::tempdir().unwrap();
    stage_registry_crate(tmp.path(), "serde", "1.0.200").await;
    stage_registry_crate(tmp.path(), "tokio", "1.40.0").await;

    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.len() >= 2);
}

#[tokio::test]
async fn crawl_all_empty_src_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty());
}

// ── get_crate_source_paths ─────────────────────────────────────

#[tokio::test]
async fn get_crate_source_paths_with_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let paths = crawler.get_crate_source_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
async fn get_crate_source_paths_with_vendor_dir_returns_vendor() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    tokio::fs::create_dir(&vendor).await.unwrap();

    let crawler = CargoCrawler;
    let paths = crawler.get_crate_source_paths(&options_at(tmp.path())).await.unwrap();
    assert_eq!(paths, vec![vendor]);
}

#[tokio::test]
async fn get_crate_source_paths_no_cargo_project_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No Cargo.toml, no Cargo.lock, no vendor.
    let crawler = CargoCrawler;
    let paths = crawler.get_crate_source_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty(), "non-Cargo dir must return empty paths");
}
