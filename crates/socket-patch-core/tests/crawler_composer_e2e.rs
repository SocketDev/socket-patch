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

// ── global mode discovery ──────────────────────────────────────

/// `get_vendor_paths(global=true, global_prefix=None)` falls through to
/// `get_global_vendor_paths` which checks `COMPOSER_HOME` env var.
/// Stubbing it to a fixture root with `<root>/vendor/` populated must
/// surface that path.
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_via_composer_home_env() {
    let tmp = tempfile::tempdir().unwrap();
    let composer_home = tmp.path();
    let vendor = composer_home.join("vendor");
    tokio::fs::create_dir_all(&vendor).await.unwrap();

    let prev_composer = std::env::var("COMPOSER_HOME").ok();
    std::env::set_var("COMPOSER_HOME", composer_home);

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();

    std::env::remove_var("COMPOSER_HOME");
    if let Some(v) = prev_composer {
        std::env::set_var("COMPOSER_HOME", v);
    }

    assert!(
        paths.iter().any(|p| p == &vendor),
        "COMPOSER_HOME-derived vendor dir must be returned; got {paths:?}"
    );
}

/// COMPOSER_HOME unset + HOME pointing at a tempdir with `.composer/`
/// must fall through to the HOME/.composer platform default.
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_via_home_dot_composer_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let dot_composer = tmp.path().join(".composer");
    let vendor = dot_composer.join("vendor");
    tokio::fs::create_dir_all(&vendor).await.unwrap();

    let prev_composer = std::env::var("COMPOSER_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::remove_var("COMPOSER_HOME");
    std::env::set_var("HOME", tmp.path());

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();

    if let Some(v) = prev_composer {
        std::env::set_var("COMPOSER_HOME", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    assert!(
        paths.iter().any(|p| p == &vendor),
        "HOME/.composer fallback vendor dir must be returned; got {paths:?}"
    );
}

/// HOME with `.config/composer/` but no `.composer/` exercises the
/// second candidate in the platform-default list.
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_via_home_xdg_config_composer_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join(".config").join("composer");
    let vendor = xdg.join("vendor");
    tokio::fs::create_dir_all(&vendor).await.unwrap();

    let prev_composer = std::env::var("COMPOSER_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::remove_var("COMPOSER_HOME");
    std::env::set_var("HOME", tmp.path());

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();

    if let Some(v) = prev_composer {
        std::env::set_var("COMPOSER_HOME", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    assert!(
        paths.iter().any(|p| p == &vendor),
        "HOME/.config/composer fallback vendor dir must be returned; got {paths:?}"
    );
}

/// `get_composer_home` returns `None` when COMPOSER_HOME is unset,
/// `composer` is not on PATH, and HOME points at a tempdir without
/// either `.composer/` or `.config/composer/`. Covers the L194-207
/// shell-out failure path (via PATH stubbing) plus the final L226
/// `None` arm.
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_no_composer_no_home_layout_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let empty_path = tempfile::tempdir().unwrap();

    let prev_composer = std::env::var("COMPOSER_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    let prev_path = std::env::var("PATH").ok();
    std::env::remove_var("COMPOSER_HOME");
    // HOME is set, but the temp HOME has no .composer / .config/composer.
    std::env::set_var("HOME", tmp.path());
    // PATH stubbed so the composer CLI cannot be spawned.
    std::env::set_var("PATH", empty_path.path());

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();

    if let Some(v) = prev_composer {
        std::env::set_var("COMPOSER_HOME", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }
    if let Some(v) = prev_path {
        std::env::set_var("PATH", v);
    } else {
        std::env::remove_var("PATH");
    }

    assert!(paths.is_empty(), "no composer source anywhere must yield empty; got {paths:?}");
}

#[cfg(unix)]
#[path = "common/mod.rs"]
mod common;

/// `read_installed_json` short-circuits when the file can't be read —
/// chmod 000 the installed.json and assert the crawler returns empty
/// rather than panicking.
#[cfg(unix)]
#[tokio::test]
async fn find_by_purls_handles_unreadable_installed_json() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    let installed = composer.join("installed.json");
    tokio::fs::write(&installed, r#"{"packages":[]}"#).await.unwrap();
    common::chmod_unreadable(&installed);

    let crawler = ComposerCrawler;
    let result = crawler
        .find_by_purls(&vendor, &[ORG_PURL.to_string()])
        .await
        .unwrap();
    common::chmod_readable(&installed);

    assert!(result.is_empty(), "unreadable installed.json must yield empty");
}

/// `crawl_all` should dedup packages discovered across multiple
/// vendor paths sharing the same installed package — exercises the
/// `seen.contains` early-continue arm.
#[tokio::test]
async fn crawl_all_dedups_across_vendor_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let custom_vendor = tmp.path().join("custom-vendor");
    let composer_dir = custom_vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    let pkg_dir = custom_vendor.join("monolog").join("monolog");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    let installed = r#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"},{"name":"monolog/monolog","version":"3.5.0"}]}"#;
    tokio::fs::write(composer_dir.join("installed.json"), installed).await.unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}").await.unwrap();

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(custom_vendor),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 1, "duplicates inside installed.json must dedup");
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
