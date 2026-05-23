//! Integration coverage for `crawlers::composer_crawler`. Drives
//! branches the apply-CLI suite skips: get_vendor_paths discovery,
//! find_by_purls happy path, crawl_all via installed.json parsing,
//! malformed installed.json variants.

#![cfg(feature = "composer")]

use std::path::Path;

use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::ComposerCrawler;

const ORG_PURL: &str = "pkg:composer/monolog/monolog@3.5.0";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

/// Stage a composer vendor layout: <root>/vendor/<vendor>/<name>/
/// with `vendor/composer/installed.json` listing it.
async fn stage_composer_project(root: &Path, vendor_name: &str, pkg_name: &str, version: &str) {
    let vendor = root.join("vendor");
    let pkg = vendor.join(vendor_name).join(pkg_name);
    tokio::fs::create_dir_all(&pkg).await.unwrap();

    // composer/installed.json — what the crawler reads.
    let installed_dir = vendor.join("composer");
    tokio::fs::create_dir_all(&installed_dir).await.unwrap();
    let installed_json = format!(
        r#"{{
  "packages": [
    {{
      "name": "{vendor_name}/{pkg_name}",
      "version": "{version}",
      "version_normalized": "{version}.0"
    }}
  ]
}}"#
    );
    tokio::fs::write(installed_dir.join("installed.json"), installed_json).await.unwrap();

    // composer.json marker on the project root.
    tokio::fs::write(root.join("composer.json"), b"{}").await.unwrap();
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_finds_package_in_vendor() {
    let tmp = tempfile::tempdir().unwrap();
    stage_composer_project(tmp.path(), "monolog", "monolog", "3.5.0").await;

    let crawler = ComposerCrawler;
    let result = crawler
        .find_by_purls(&tmp.path().join("vendor"), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    let pkg = result.get(ORG_PURL).unwrap();
    assert_eq!(pkg.path, tmp.path().join("vendor").join("monolog").join("monolog"));
}

#[tokio::test]
async fn find_by_purls_no_installed_json_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    tokio::fs::create_dir(&vendor).await.unwrap();

    let crawler = ComposerCrawler;
    let result = crawler
        .find_by_purls(&vendor, &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    stage_composer_project(tmp.path(), "monolog", "monolog", "3.5.0").await;

    let crawler = ComposerCrawler;
    let result = crawler
        .find_by_purls(
            &tmp.path().join("vendor"),
            &["pkg:not-composer/foo@1.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_version_mismatch_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    stage_composer_project(tmp.path(), "monolog", "monolog", "3.5.0").await;

    let crawler = ComposerCrawler;
    let result = crawler
        .find_by_purls(
            &tmp.path().join("vendor"),
            &["pkg:composer/monolog/monolog@99.99.99".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty(), "version mismatch must skip");
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_via_installed_json_returns_packages() {
    let tmp = tempfile::tempdir().unwrap();
    stage_composer_project(tmp.path(), "monolog", "monolog", "3.5.0").await;

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().join("vendor")),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "monolog");
    assert_eq!(result[0].namespace.as_deref(), Some("monolog"));
}

#[tokio::test]
async fn crawl_all_with_corrupt_installed_json_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{ this is not json").await.unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}").await.unwrap();

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(vendor),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty(), "corrupt JSON must yield empty crawl");
}

// ── get_vendor_paths ──────────────────────────────────────────

#[tokio::test]
async fn get_vendor_paths_with_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
async fn get_vendor_paths_local_no_vendor_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = ComposerCrawler;
    let paths = crawler.get_vendor_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty());
}

#[tokio::test]
async fn get_vendor_paths_local_no_installed_json_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    tokio::fs::create_dir(&vendor).await.unwrap();
    // vendor exists but no installed.json inside.
    tokio::fs::write(tmp.path().join("composer.json"), b"{}").await.unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler.get_vendor_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty(), "vendor without installed.json must not match");
}

#[tokio::test]
async fn get_vendor_paths_local_no_composer_marker_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{\"packages\":[]}").await.unwrap();
    // No composer.json or composer.lock on the project root.

    let crawler = ComposerCrawler;
    let paths = crawler.get_vendor_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty(), "no composer.json must mean not-a-PHP-project");
}

#[tokio::test]
async fn get_vendor_paths_local_full_setup_returns_vendor() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{\"packages\":[]}").await.unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}").await.unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler.get_vendor_paths(&options_at(tmp.path())).await.unwrap();
    assert_eq!(paths, vec![vendor]);
}

#[tokio::test]
async fn get_vendor_paths_local_with_lock_marker_also_works() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{\"packages\":[]}").await.unwrap();
    tokio::fs::write(tmp.path().join("composer.lock"), b"{}").await.unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler.get_vendor_paths(&options_at(tmp.path())).await.unwrap();
    assert_eq!(paths, vec![vendor]);
}
