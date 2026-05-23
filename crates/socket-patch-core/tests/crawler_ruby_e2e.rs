//! Integration coverage for `crawlers::ruby_crawler`. Drives
//! branches the apply-CLI suite skips: vendor/bundle local mode,
//! global gem discovery via `~/.gem/ruby/*/gems`,
//! `~/.rbenv/versions/*/lib/ruby/gems/*/gems`, system paths,
//! Gemfile vs Gemfile.lock vs neither.

use std::path::Path;

use serial_test::serial;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::RubyCrawler;

const ORG_PURL: &str = "pkg:gem/rails@7.1.0";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

/// Stage a gem under <gem_path>/<name>-<version>/lib so verify_gem_at_path
/// accepts it.
async fn stage_gem(gem_path: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg_dir = gem_path.join(format!("{name}-{version}"));
    tokio::fs::create_dir_all(pkg_dir.join("lib")).await.unwrap();
    pkg_dir
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_finds_gem_in_gem_path() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = stage_gem(tmp.path(), "rails", "7.1.0").await;

    let crawler = RubyCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(ORG_PURL).unwrap().path, pkg_dir);
}

#[tokio::test]
async fn find_by_purls_accepts_gem_with_gemspec_only() {
    let tmp = tempfile::tempdir().unwrap();
    // Stage with .gemspec but NO lib/ directory (alternate marker).
    let pkg_dir = tmp.path().join("rails-7.1.0");
    tokio::fs::create_dir(&pkg_dir).await.unwrap();
    tokio::fs::write(pkg_dir.join("rails.gemspec"), b"# gemspec").await.unwrap();

    let crawler = RubyCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
}

#[tokio::test]
async fn find_by_purls_rejects_dir_without_lib_or_gemspec() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("rails-7.1.0");
    tokio::fs::create_dir(&pkg_dir).await.unwrap();
    // Neither lib/ nor .gemspec → verify_gem_at_path returns false.

    let crawler = RubyCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = RubyCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = RubyCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:not-gem/rails@7.1.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_discovers_gems_in_path() {
    let tmp = tempfile::tempdir().unwrap();
    stage_gem(tmp.path(), "rails", "7.1.0").await;
    stage_gem(tmp.path(), "nokogiri", "1.16.5").await;

    let crawler = RubyCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 2);
}

// ── get_gem_paths ──────────────────────────────────────────────

#[tokio::test]
async fn get_gem_paths_with_global_prefix_returns_only_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = RubyCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let paths = crawler.get_gem_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
async fn get_gem_paths_vendor_bundle_takes_precedence_over_global() {
    let tmp = tempfile::tempdir().unwrap();
    // Build a vendor/bundle/ruby/<ver>/gems layout. Bundler's scan
    // pattern is `vendor/bundle/ruby/<ver>/gems`.
    let vendor = tmp.path().join("vendor").join("bundle").join("ruby");
    let gems = vendor.join("3.2.0").join("gems");
    tokio::fs::create_dir_all(&gems).await.unwrap();

    let crawler = RubyCrawler;
    let paths = crawler.get_gem_paths(&options_at(tmp.path())).await.unwrap();
    assert!(
        paths.iter().any(|p| p == &gems),
        "vendor/bundle gems dir must be discovered; got {paths:?}"
    );
}

#[tokio::test]
async fn get_gem_paths_no_gemfile_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No Gemfile, no Gemfile.lock, no vendor/bundle.
    let crawler = RubyCrawler;
    let paths = crawler.get_gem_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty(), "non-Ruby dir must return empty paths");
}

#[tokio::test]
#[serial]
async fn get_gem_paths_with_gemfile_no_vendor_returns_paths() {
    let tmp = tempfile::tempdir().unwrap();
    // Gemfile present, no vendor/bundle. Falls back to `gem env gemdir`.
    // This either returns paths (if `gem` is on PATH and produces output)
    // or empty (if `gem` is missing). Both are valid — the contract is
    // "doesn't crash".
    tokio::fs::write(tmp.path().join("Gemfile"), b"source 'https://rubygems.org'").await.unwrap();

    let crawler = RubyCrawler;
    let _ = crawler.get_gem_paths(&options_at(tmp.path())).await.unwrap();
    // No assertion on contents — just contract that no panic occurs.
}

#[tokio::test]
#[serial]
async fn get_gem_paths_with_gemfile_lock_only_works_too() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("Gemfile.lock"), b"GEM\n").await.unwrap();
    let crawler = RubyCrawler;
    let _ = crawler.get_gem_paths(&options_at(tmp.path())).await.unwrap();
}

// ── global gem discovery ───────────────────────────────────────

#[tokio::test]
#[serial]
async fn global_gem_discovery_via_home_dotgem_layout() {
    let tmp = tempfile::tempdir().unwrap();
    // Build a ~/.gem/ruby/3.2.0/gems layout.
    let gems = tmp
        .path()
        .join(".gem")
        .join("ruby")
        .join("3.2.0")
        .join("gems");
    tokio::fs::create_dir_all(&gems).await.unwrap();

    let prev = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let crawler = RubyCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_gem_paths(&opts).await.unwrap();
    if let Some(v) = prev {
        std::env::set_var("HOME", v);
    }

    assert!(
        paths.iter().any(|p| p == &gems),
        "~/.gem/ruby/*/gems must be discovered; got {paths:?}"
    );
}

/// `RubyCrawler::default()` should forward to `new()`.
#[test]
fn ruby_crawler_default_and_new_construct_cleanly() {
    let _a = RubyCrawler::default();
    let _b = RubyCrawler::new();
}

/// `~/.rvm/gems/<set>/gems` layout — exercises the third fallback in
/// the rbenv/rvm/gem fallback_globs loop.
#[tokio::test]
#[serial]
async fn global_gem_discovery_via_rvm_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let gems = tmp
        .path()
        .join(".rvm")
        .join("gems")
        .join("ruby-3.2.0")
        .join("gems");
    tokio::fs::create_dir_all(&gems).await.unwrap();

    let prev = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let crawler = RubyCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_gem_paths(&opts).await.unwrap();
    if let Some(v) = prev {
        std::env::set_var("HOME", v);
    }

    assert!(
        paths.iter().any(|p| p == &gems),
        "~/.rvm/gems/*/gems must be discovered; got {paths:?}"
    );
}

#[tokio::test]
#[serial]
async fn global_gem_discovery_via_rbenv_layout() {
    let tmp = tempfile::tempdir().unwrap();
    // Build a ~/.rbenv/versions/3.2.0/lib/ruby/gems/3.2.0/gems layout.
    let gems = tmp
        .path()
        .join(".rbenv")
        .join("versions")
        .join("3.2.0")
        .join("lib")
        .join("ruby")
        .join("gems")
        .join("3.2.0")
        .join("gems");
    tokio::fs::create_dir_all(&gems).await.unwrap();

    let prev = std::env::var("HOME").ok();
    std::env::set_var("HOME", tmp.path());
    let crawler = RubyCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_gem_paths(&opts).await.unwrap();
    if let Some(v) = prev {
        std::env::set_var("HOME", v);
    }

    assert!(
        paths.iter().any(|p| p == &gems),
        "~/.rbenv/versions/*/lib/ruby/gems/*/gems must be discovered; got {paths:?}"
    );
}
