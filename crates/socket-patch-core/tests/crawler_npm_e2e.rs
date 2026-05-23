//! Integration coverage for `crawlers::npm_crawler`. Drives the
//! local-discovery paths apply-CLI tests skip (parse_package_name,
//! read_package_json, find_by_purls scoped vs unscoped, crawl_all
//! over a synthetic node_modules tree).

use std::path::Path;

use socket_patch_core::crawlers::npm_crawler::{
    build_npm_purl, parse_package_name, read_package_json,
};
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::NpmCrawler;

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

/// Stage a package inside node_modules. `name` may include a `@scope/`
/// prefix.
async fn stage_npm_pkg(node_modules: &Path, name: &str, version: &str) {
    let pkg_dir = node_modules.join(name);
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    let pkg_json = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    tokio::fs::write(pkg_dir.join("package.json"), pkg_json).await.unwrap();
}

// ── parse_package_name ─────────────────────────────────────────

#[test]
fn parse_package_name_unscoped() {
    let (ns, name) = parse_package_name("lodash");
    assert_eq!(ns, None);
    assert_eq!(name, "lodash");
}

#[test]
fn parse_package_name_scoped() {
    let (ns, name) = parse_package_name("@types/node");
    assert_eq!(ns.as_deref(), Some("@types"));
    assert_eq!(name, "node");
}

#[test]
fn parse_package_name_at_only_no_slash() {
    // `@foo` with no `/` — treated as unscoped.
    let (ns, name) = parse_package_name("@oops");
    assert_eq!(ns, None);
    assert_eq!(name, "@oops");
}

// ── build_npm_purl ─────────────────────────────────────────────

#[test]
fn build_npm_purl_unscoped() {
    let purl = build_npm_purl(None, "lodash", "4.17.21");
    assert_eq!(purl, "pkg:npm/lodash@4.17.21");
}

#[test]
fn build_npm_purl_scoped() {
    let purl = build_npm_purl(Some("@types"), "node", "20.0.0");
    assert_eq!(purl, "pkg:npm/@types/node@20.0.0");
}

// ── read_package_json ──────────────────────────────────────────

#[tokio::test]
async fn read_package_json_well_formed() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"lodash","version":"4.17.21"}"#).await.unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(
        result,
        Some(("lodash".to_string(), "4.17.21".to_string()))
    );
}

#[tokio::test]
async fn read_package_json_missing_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let result = read_package_json(&tmp.path().join("nope.json")).await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn read_package_json_malformed_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, b"{ this is not json").await.unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn read_package_json_missing_name_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"version":"1.0.0"}"#).await.unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, None);
}

#[tokio::test]
async fn read_package_json_missing_version_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"lodash"}"#).await.unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, None);
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_unscoped_package() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/lodash@4.17.21".to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
}

#[tokio::test]
async fn find_by_purls_scoped_package() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "@types/node", "20.0.0").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/@types/node@20.0.0".to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
}

#[tokio::test]
async fn find_by_purls_version_mismatch_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/lodash@99.99.99".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty(), "version mismatch must skip");
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:not-npm/foo@1.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_discovers_unscoped_and_scoped() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;
    stage_npm_pkg(&nm, "@types/node", "20.0.0").await;

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"lodash"));
    assert!(names.contains(&"node"));
}

#[tokio::test]
async fn crawl_all_skips_dirs_without_package_json() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    tokio::fs::create_dir_all(nm.join("not_a_pkg")).await.unwrap();
    // No package.json — must be skipped.

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty());
}

#[tokio::test]
async fn crawl_all_skips_dirs_with_corrupt_package_json() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let bad = nm.join("broken");
    tokio::fs::create_dir_all(&bad).await.unwrap();
    tokio::fs::write(bad.join("package.json"), b"{ corrupt").await.unwrap();

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty());
}
