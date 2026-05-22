//! Integration coverage for the crawlers' empty/missing-path early
//! returns. Each crawler's `find_by_purls` and `crawl_all` short-
//! circuits when the discovery root doesn't exist or no PURLs match
//! its scheme — branches the apply-CLI suite doesn't naturally
//! exercise because those tests always pre-stage a layout.

use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::{NpmCrawler, PythonCrawler, RubyCrawler};
#[cfg(feature = "cargo")]
use socket_patch_core::crawlers::CargoCrawler;
#[cfg(feature = "golang")]
use socket_patch_core::crawlers::GoCrawler;
#[cfg(feature = "maven")]
use socket_patch_core::crawlers::MavenCrawler;
#[cfg(feature = "nuget")]
use socket_patch_core::crawlers::NuGetCrawler;
use std::path::PathBuf;

fn options_at(root: &std::path::Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

#[tokio::test]
async fn npm_crawler_find_by_purls_with_empty_purls_returns_empty_map() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[])
        .await
        .unwrap();
    assert!(result.is_empty(), "empty PURL list → empty result");
}

#[tokio::test]
async fn npm_crawler_find_by_purls_with_nonexistent_node_modules_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let nonexistent = tmp.path().join("missing_node_modules");
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(
            &nonexistent,
            &["pkg:npm/lodash@4.17.21".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty(), "nonexistent node_modules → empty");
}

#[tokio::test]
async fn npm_crawler_crawl_all_with_no_packages_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NpmCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;
    assert!(result.is_empty(), "no packages installed → empty crawl");
}

#[tokio::test]
async fn python_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = PythonCrawler;
    let result = crawler.find_by_purls(tmp.path(), &[]).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn python_crawler_crawl_all_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = PythonCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;
    assert!(result.is_empty());
}

#[tokio::test]
async fn ruby_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = RubyCrawler;
    let result = crawler.find_by_purls(tmp.path(), &[]).await.unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn ruby_crawler_crawl_all_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = RubyCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;
    assert!(result.is_empty());
}

#[cfg(feature = "cargo")]
#[tokio::test]
async fn cargo_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let result = crawler.find_by_purls(tmp.path(), &[]).await.unwrap();
    assert!(result.is_empty());
}

#[cfg(feature = "cargo")]
#[tokio::test]
async fn cargo_crawler_crawl_all_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;
    assert!(result.is_empty());
}

#[cfg(feature = "golang")]
#[tokio::test]
async fn go_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = GoCrawler;
    let result = crawler.find_by_purls(tmp.path(), &[]).await.unwrap();
    assert!(result.is_empty());
}

#[cfg(feature = "maven")]
#[tokio::test]
async fn maven_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = MavenCrawler;
    let result = crawler.find_by_purls(tmp.path(), &[]).await.unwrap();
    assert!(result.is_empty());
}

#[cfg(feature = "nuget")]
#[tokio::test]
async fn nuget_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NuGetCrawler;
    let result = crawler.find_by_purls(tmp.path(), &[]).await.unwrap();
    assert!(result.is_empty());
}

// Marker import suppress.
#[allow(dead_code)]
fn _path_marker(_p: PathBuf) {}
