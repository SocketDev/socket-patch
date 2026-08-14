//! Integration coverage for `crawlers::composer_crawler`. Drives
//! branches the apply-CLI suite skips: get_vendor_paths discovery,
//! find_by_purls happy path, crawl_all via installed.json parsing,
//! malformed installed.json variants.

use std::path::Path;

use socket_patch_core::crawlers::composer_crawler::parse_composer_home_output;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::ComposerCrawler;

#[test]
#[serial_test::parallel]
fn parse_composer_home_output_well_formed() {
    let p = parse_composer_home_output("/Users/foo/.composer\n").unwrap();
    assert_eq!(p, std::path::PathBuf::from("/Users/foo/.composer"));
}

#[test]
#[serial_test::parallel]
fn parse_composer_home_output_empty_returns_none() {
    assert_eq!(parse_composer_home_output(""), None);
    assert_eq!(parse_composer_home_output("   \n  "), None);
}

const ORG_PURL: &str = "pkg:composer/monolog/monolog@3.5.0";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
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
    tokio::fs::write(installed_dir.join("installed.json"), installed_json)
        .await
        .unwrap();

    // composer.json marker on the project root.
    tokio::fs::write(root.join("composer.json"), b"{}")
        .await
        .unwrap();
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
#[serial_test::parallel]
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
    // Assert the *full* distilled package, not just its path: a regression
    // that mislabels name/namespace/version/purl would otherwise stay green.
    assert_eq!(
        pkg.path,
        tmp.path().join("vendor").join("monolog").join("monolog")
    );
    assert_eq!(pkg.name, "monolog");
    assert_eq!(pkg.namespace.as_deref(), Some("monolog"));
    assert_eq!(pkg.version, "3.5.0");
    assert_eq!(pkg.purl, ORG_PURL);
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_no_installed_json_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    // Stage the package directory on disk so the ONLY thing missing is
    // installed.json. Without this, find_by_purls returns empty because the
    // pkg dir is absent (the `is_dir` guard) — masking whether the missing
    // installed.json actually gates the result. A control below proves the
    // dir is discoverable once installed.json exists.
    let pkg_dir = vendor.join("monolog").join("monolog");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();

    let crawler = ComposerCrawler;
    let result = crawler
        .find_by_purls(&vendor, &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "package on disk but no installed.json must not match; got {result:?}"
    );

    // Control: write installed.json listing the same package and confirm it
    // is now found. This proves the empty result above was caused by the
    // missing installed.json, not by an unrelated short-circuit.
    let composer_dir = vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    tokio::fs::write(
        composer_dir.join("installed.json"),
        br#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}]}"#,
    )
    .await
    .unwrap();
    let result = crawler
        .find_by_purls(&vendor, &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(
        result.len(),
        1,
        "control: same package must match once installed.json exists"
    );
}

#[tokio::test]
#[serial_test::parallel]
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
#[serial_test::parallel]
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
#[serial_test::parallel]
async fn crawl_all_via_installed_json_returns_packages() {
    let tmp = tempfile::tempdir().unwrap();
    stage_composer_project(tmp.path(), "monolog", "monolog", "3.5.0").await;

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().join("vendor")),
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "monolog");
    assert_eq!(result[0].namespace.as_deref(), Some("monolog"));
    assert_eq!(result[0].version, "3.5.0");
    assert_eq!(result[0].purl, ORG_PURL);
    assert_eq!(
        result[0].path,
        tmp.path().join("vendor").join("monolog").join("monolog")
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_with_corrupt_installed_json_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{ this is not json")
        .await
        .unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}")
        .await
        .unwrap();
    // Stage a real package directory on disk. If a regression ever made
    // crawl_all fall back to directory-walking when installed.json fails to
    // parse, this package would leak through — so its absence from the
    // result proves the corrupt JSON (not a missing dir) is what yields
    // empty. The control below confirms the dir is discoverable.
    let pkg_dir = vendor.join("monolog").join("monolog");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(vendor.clone()),
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty(), "corrupt JSON must yield empty crawl");

    // Control: replace the corrupt file with a valid one listing that same
    // package and confirm crawl_all now surfaces it.
    tokio::fs::write(
        composer.join("installed.json"),
        br#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}]}"#,
    )
    .await
    .unwrap();
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(
        result.len(),
        1,
        "control: valid installed.json over the same dir must surface the package"
    );
    assert_eq!(result[0].purl, ORG_PURL);
}

// ── get_vendor_paths ──────────────────────────────────────────

#[tokio::test]
#[serial_test::parallel]
async fn get_vendor_paths_with_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
#[serial_test::parallel]
async fn get_vendor_paths_local_no_vendor_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(paths.is_empty());
}

#[tokio::test]
#[serial_test::parallel]
async fn get_vendor_paths_local_no_installed_json_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    tokio::fs::create_dir(&vendor).await.unwrap();
    // vendor exists but no installed.json inside.
    tokio::fs::write(tmp.path().join("composer.json"), b"{}")
        .await
        .unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(
        paths.is_empty(),
        "vendor without installed.json must not match"
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn get_vendor_paths_local_no_composer_marker_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{\"packages\":[]}")
        .await
        .unwrap();
    // No composer.json or composer.lock on the project root.

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(
        paths.is_empty(),
        "no composer.json must mean not-a-PHP-project"
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn get_vendor_paths_local_full_setup_returns_vendor() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{\"packages\":[]}")
        .await
        .unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}")
        .await
        .unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
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
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();

    std::env::remove_var("COMPOSER_HOME");
    if let Some(v) = prev_composer {
        std::env::set_var("COMPOSER_HOME", v);
    }

    assert_eq!(
        paths,
        vec![vendor],
        "COMPOSER_HOME-derived vendor dir must be the sole returned path"
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
    // Stub PATH to a binary-free tempdir so `composer global config
    // home` can't short-circuit the HOME-based fallback on CI runners
    // where composer is installed.
    let empty_path = tempfile::tempdir().unwrap();

    let prev_composer = std::env::var("COMPOSER_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    let prev_path = std::env::var("PATH").ok();
    std::env::remove_var("COMPOSER_HOME");
    std::env::set_var("HOME", tmp.path());
    std::env::set_var("PATH", empty_path.path());

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
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

    assert_eq!(
        paths,
        vec![vendor],
        "HOME/.composer fallback vendor dir must be the sole returned path"
    );
}

/// HOME with `.config/composer/` but no `.composer/` exercises the
/// second candidate in the platform-default list.
///
/// PATH is stubbed to a binary-free tempdir so `composer global
/// config home` can't short-circuit the fallback chain — on CI
/// runners that have composer installed, the shell-out would
/// otherwise return a real home outside our test tempdir.
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_via_home_xdg_config_composer_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join(".config").join("composer");
    let vendor = xdg.join("vendor");
    tokio::fs::create_dir_all(&vendor).await.unwrap();
    let empty_path = tempfile::tempdir().unwrap();

    let prev_composer = std::env::var("COMPOSER_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    let prev_path = std::env::var("PATH").ok();
    std::env::remove_var("COMPOSER_HOME");
    std::env::set_var("HOME", tmp.path());
    std::env::set_var("PATH", empty_path.path());

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
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

    assert_eq!(
        paths,
        vec![vendor],
        "HOME/.config/composer fallback vendor dir must be the sole returned path"
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

    assert!(
        paths.is_empty(),
        "no composer source anywhere must yield empty; got {paths:?}"
    );
}

/// A set-but-empty `HOME` (stripped CI/container/sudo environments) must
/// be treated as unset, not honored: `PathBuf::from("")` turns the
/// `.composer` / `.config/composer` platform-default probes into
/// CWD-relative paths, so a `.composer/vendor/` directory inside the
/// user's project gets scanned as if it were the global composer home.
/// Twin of the `utils::fs::home_dir` empty-HOME fix.
#[tokio::test]
#[serial_test::serial]
async fn get_vendor_paths_global_empty_home_not_cwd_relative() {
    let tmp = tempfile::tempdir().unwrap();
    // Plant a project-local .composer/vendor inside what will be the CWD.
    tokio::fs::create_dir_all(tmp.path().join(".composer").join("vendor"))
        .await
        .unwrap();
    let empty_path = tempfile::tempdir().unwrap();

    let prev_composer = std::env::var("COMPOSER_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    let prev_profile = std::env::var("USERPROFILE").ok();
    let prev_path = std::env::var("PATH").ok();
    let prev_cwd = std::env::current_dir().unwrap();
    std::env::remove_var("COMPOSER_HOME");
    std::env::set_var("HOME", "");
    std::env::set_var("USERPROFILE", "");
    std::env::set_var("PATH", empty_path.path());
    std::env::set_current_dir(tmp.path()).unwrap();

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
    };
    let paths = crawler.get_vendor_paths(&opts).await.unwrap();

    std::env::set_current_dir(prev_cwd).unwrap();
    if let Some(v) = prev_composer {
        std::env::set_var("COMPOSER_HOME", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }
    if let Some(v) = prev_profile {
        std::env::set_var("USERPROFILE", v);
    } else {
        std::env::remove_var("USERPROFILE");
    }
    if let Some(v) = prev_path {
        std::env::set_var("PATH", v);
    } else {
        std::env::remove_var("PATH");
    }

    assert!(
        paths.is_empty(),
        "empty HOME must not resolve to CWD-relative .composer probes; got {paths:?}"
    );
}

#[path = "common/mod.rs"]
mod common;

/// `read_installed_json` short-circuits when the file can't be read —
/// chmod 000 the installed.json and assert the crawler returns empty
/// rather than panicking.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
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
    // List the requested package AND stage its dir on disk, so the only
    // barrier to a match is the unreadable file. With an empty
    // `{"packages":[]}` (the prior fixture) the result would be empty even
    // if the read succeeded, making the test vacuous.
    tokio::fs::write(
        &installed,
        br#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}]}"#,
    )
    .await
    .unwrap();
    tokio::fs::create_dir_all(vendor.join("monolog").join("monolog"))
        .await
        .unwrap();
    common::chmod_unreadable(&installed);

    let crawler = ComposerCrawler;
    let result = crawler
        .find_by_purls(&vendor, &[ORG_PURL.to_string()])
        .await
        .unwrap();

    assert!(
        result.is_empty(),
        "unreadable installed.json must yield empty even when the pkg dir exists; got {result:?}"
    );

    // Control: once readable, the same staged package must be found —
    // proving the empty result above was caused by the unreadable file.
    common::chmod_readable(&installed);
    let result = crawler
        .find_by_purls(&vendor, &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(
        result.len(),
        1,
        "control: readable installed.json must surface the staged package"
    );
}

/// `crawl_all` should dedup packages discovered across multiple
/// vendor paths sharing the same installed package — exercises the
/// `seen.contains` early-continue arm.
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_dedups_across_vendor_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let custom_vendor = tmp.path().join("custom-vendor");
    let composer_dir = custom_vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    let pkg_dir = custom_vendor.join("monolog").join("monolog");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    let installed = r#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"},{"name":"monolog/monolog","version":"3.5.0"}]}"#;
    tokio::fs::write(composer_dir.join("installed.json"), installed)
        .await
        .unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}")
        .await
        .unwrap();

    let crawler = ComposerCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(custom_vendor),
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(
        result.len(),
        1,
        "duplicates inside installed.json must dedup"
    );
    assert_eq!(result[0].purl, ORG_PURL);
    assert_eq!(result[0].name, "monolog");
    assert_eq!(result[0].namespace.as_deref(), Some("monolog"));
}

#[tokio::test]
#[serial_test::parallel]
async fn get_vendor_paths_local_with_lock_marker_also_works() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer = vendor.join("composer");
    tokio::fs::create_dir_all(&composer).await.unwrap();
    tokio::fs::write(composer.join("installed.json"), b"{\"packages\":[]}")
        .await
        .unwrap();
    tokio::fs::write(tmp.path().join("composer.lock"), b"{}")
        .await
        .unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert_eq!(paths, vec![vendor]);
}

// ── relocated vendor directories (config.vendor-dir / COMPOSER_VENDOR_DIR) ──

/// Stage a composer project whose vendor tree lives at `vendor_rel`
/// (relative to the project root) holding one package, exactly as Composer
/// lays it out: `<vendor_rel>/composer/installed.json` with an
/// `install-path` relative to that `composer/` directory, and the package
/// itself at `<vendor_rel>/<vendor>/<name>`. `config_vendor_dir` is written
/// into composer.json's `config` block when supplied.
async fn stage_relocated_project(
    root: &Path,
    vendor_rel: &str,
    config_vendor_dir: Option<&str>,
) -> std::path::PathBuf {
    let vendor = root.join(vendor_rel);
    tokio::fs::create_dir_all(vendor.join("monolog").join("monolog"))
        .await
        .unwrap();
    let composer_dir = vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    tokio::fs::write(
        composer_dir.join("installed.json"),
        br#"{"packages":[{"name":"monolog/monolog","version":"3.5.0","install-path":"../monolog/monolog"}]}"#,
    )
    .await
    .unwrap();

    let manifest = match config_vendor_dir {
        Some(dir) => format!(r#"{{"config":{{"vendor-dir":"{dir}"}}}}"#),
        None => "{}".to_string(),
    };
    tokio::fs::write(root.join("composer.json"), manifest)
        .await
        .unwrap();
    vendor
}

/// Composer relocates the ENTIRE vendor tree — `composer/installed.json`
/// included — when composer.json sets `config.vendor-dir`, so assuming
/// `<cwd>/vendor` finds nothing: scan then reports every installed package
/// as lockfile-only ("not yet installed") and apply resolves each one as
/// `package_not_found`. Verified against composer 2.10.2: `"vendor-dir":
/// "lib/deps"` puts installed.json at `lib/deps/composer/installed.json`.
#[tokio::test]
#[serial_test::parallel]
async fn config_vendor_dir_relocates_discovery() {
    let tmp = tempfile::tempdir().unwrap();
    // Nested (`lib/deps`), which composer allows and which also proves the
    // project root is still found for the install-path boundary check.
    let vendor = stage_relocated_project(tmp.path(), "lib/deps", Some("lib/deps")).await;
    // No `vendor/` anywhere: the only discoverable tree is the relocated one.
    assert!(!tmp.path().join("vendor").exists());

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert_eq!(paths, vec![vendor.clone()]);

    let packages = crawler.crawl_all(&options_at(tmp.path())).await;
    assert_eq!(
        packages.len(),
        1,
        "relocated vendor tree must be crawled; got {packages:?}"
    );
    assert_eq!(packages[0].purl, ORG_PURL);
    assert_eq!(packages[0].path, vendor.join("monolog").join("monolog"));
}

/// A trailing separator is legal in `config.vendor-dir` (Composer rtrims it
/// before use), so `"vendor-dir": "lib/deps/"` must resolve the same as
/// `"lib/deps"` — a naive join would produce an empty final segment and
/// fail the coordinate gate.
#[tokio::test]
#[serial_test::parallel]
async fn config_vendor_dir_trailing_slash_is_trimmed() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = stage_relocated_project(tmp.path(), "lib/deps", Some("lib/deps/")).await;

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert_eq!(paths, vec![vendor]);
}

/// `COMPOSER_VENDOR_DIR` outranks composer.json's `config.vendor-dir` in
/// Composer's own `Config::get`, so it must outrank it here too. Verified
/// against composer 2.10.2: `COMPOSER_VENDOR_DIR=third_party composer
/// install` writes `third_party/composer/installed.json`.
#[tokio::test]
#[serial_test::serial]
async fn composer_vendor_dir_env_outranks_config_and_default() {
    let tmp = tempfile::tempdir().unwrap();
    // composer.json points at `lib/deps` and a decoy `vendor/` tree exists;
    // the env var names a third directory, which must win over both.
    let vendor = stage_relocated_project(tmp.path(), "third_party", Some("lib/deps")).await;
    let decoy = tmp.path().join("vendor").join("composer");
    tokio::fs::create_dir_all(&decoy).await.unwrap();
    tokio::fs::write(decoy.join("installed.json"), b"{\"packages\":[]}")
        .await
        .unwrap();

    let prev = std::env::var("COMPOSER_VENDOR_DIR").ok();
    std::env::set_var("COMPOSER_VENDOR_DIR", "third_party");

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    let packages = crawler.crawl_all(&options_at(tmp.path())).await;

    match prev {
        Some(v) => std::env::set_var("COMPOSER_VENDOR_DIR", v),
        None => std::env::remove_var("COMPOSER_VENDOR_DIR"),
    }

    assert_eq!(paths, vec![vendor.clone()], "env var must win");
    assert_eq!(packages.len(), 1, "got {packages:?}");
    assert_eq!(packages[0].path, vendor.join("monolog").join("monolog"));
}

/// A set-but-empty `COMPOSER_VENDOR_DIR` counts as unset (twin of the
/// MAVEN_REPO_LOCAL / NUGET_PACKAGES rules): honoring `""` would resolve
/// the vendor tree to the project root itself, so `vendor/composer/` would
/// be looked for at `<root>/composer/`.
#[tokio::test]
#[serial_test::serial]
async fn empty_composer_vendor_dir_env_falls_back_to_default() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = stage_relocated_project(tmp.path(), "vendor", None).await;

    let prev = std::env::var("COMPOSER_VENDOR_DIR").ok();
    std::env::set_var("COMPOSER_VENDOR_DIR", "");

    let crawler = ComposerCrawler;
    let paths = crawler
        .get_vendor_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    match prev {
        Some(v) => std::env::set_var("COMPOSER_VENDOR_DIR", v),
        None => std::env::remove_var("COMPOSER_VENDOR_DIR"),
    }

    assert_eq!(paths, vec![vendor], "empty env var must not shadow vendor/");
}

/// composer.json belongs to the project being SCANNED and the vendor
/// directory it names is where apply later WRITES patch content, so a
/// `config.vendor-dir` that escapes the project is refused outright — and
/// refused fail-closed, NOT downgraded to `vendor/`, which would patch an
/// unrelated tree that Composer never installed into.
#[tokio::test]
#[serial_test::parallel]
async fn config_vendor_dir_escaping_project_is_refused() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("proj");
    tokio::fs::create_dir_all(&root).await.unwrap();
    // A fully staged vendor tree OUTSIDE the project, so the refusal is the
    // coordinate gate and not a missing directory.
    stage_relocated_project(outer.path(), "escaped", None).await;
    tokio::fs::write(
        root.join("composer.json"),
        br#"{"config":{"vendor-dir":"../escaped"}}"#,
    )
    .await
    .unwrap();
    // A conventional vendor/ tree also exists: the refusal must not silently
    // fall back to it either.
    let decoy = root.join("vendor").join("composer");
    tokio::fs::create_dir_all(&decoy).await.unwrap();
    tokio::fs::write(
        decoy.join("installed.json"),
        br#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}]}"#,
    )
    .await
    .unwrap();
    tokio::fs::create_dir_all(root.join("vendor").join("monolog").join("monolog"))
        .await
        .unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler.get_vendor_paths(&options_at(&root)).await.unwrap();
    assert!(
        paths.is_empty(),
        "escaping config.vendor-dir must fail closed; got {paths:?}"
    );
    let packages = crawler.crawl_all(&options_at(&root)).await;
    assert!(
        packages.is_empty(),
        "escaping config.vendor-dir must not fall back to vendor/; got {packages:?}"
    );
}

/// An ABSOLUTE `config.vendor-dir` is legal in Composer but refused here
/// for the same reason: it names an apply write target and composer.json is
/// tamperable. Discovery reports nothing, exactly as it did before custom
/// vendor directories were understood at all — no silent redirect.
#[tokio::test]
#[serial_test::parallel]
async fn absolute_config_vendor_dir_is_refused() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("proj");
    tokio::fs::create_dir_all(&root).await.unwrap();
    let absolute = stage_relocated_project(outer.path(), "abs-vendor", None).await;
    tokio::fs::write(
        root.join("composer.json"),
        format!(r#"{{"config":{{"vendor-dir":"{}"}}}}"#, absolute.display()),
    )
    .await
    .unwrap();

    let crawler = ComposerCrawler;
    let paths = crawler.get_vendor_paths(&options_at(&root)).await.unwrap();
    assert!(paths.is_empty(), "got {paths:?}");
}

// ── installed.json install-path ────────────────────────────────

const PLUGIN_PURL: &str = "pkg:composer/socket/probe-plugin@1.2.3";
const INSTALLERS_PURL: &str = "pkg:composer/composer/installers@2.3.0";

/// composer/installers (`type: wordpress-plugin`, `extra.installer-paths`)
/// installs packages OUTSIDE `vendor/<ns>/<name>`, and installed.json's
/// `install-path` is the only record of where they landed. Reconstructing
/// the conventional layout makes them invisible to scan and unpatchable by
/// apply, even though the metadata says exactly where they are.
///
/// The fixture mirrors composer 2.10.2 byte-for-byte: with
/// `"web/app/plugins/{$name}/"` mapped to `type:wordpress-plugin`, it wrote
/// `"install-path": "../../../web/app/plugins/probe-plugin"` (three levels
/// up from `lib/deps/composer/`) — and, for `composer/installers` itself,
/// the `./`-relative `"./installers"`.
#[tokio::test]
#[serial_test::parallel]
async fn install_path_resolves_package_outside_vendor() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer_dir = vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    tokio::fs::write(
        composer_dir.join("installed.json"),
        br#"{"packages":[
          {"name":"composer/installers","version":"v2.3.0","install-path":"./installers"},
          {"name":"socket/probe-plugin","version":"1.2.3","install-path":"../../web/app/plugins/probe-plugin"}
        ]}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}")
        .await
        .unwrap();

    let plugin_dir = tmp
        .path()
        .join("web")
        .join("app")
        .join("plugins")
        .join("probe-plugin");
    tokio::fs::create_dir_all(&plugin_dir).await.unwrap();
    let installers_dir = composer_dir.join("installers");
    tokio::fs::create_dir_all(&installers_dir).await.unwrap();
    // Control: NEITHER package sits at the conventional location, so a
    // reconstructed `vendor/<ns>/<name>` finds nothing to corroborate.
    assert!(!vendor.join("socket").join("probe-plugin").exists());

    let crawler = ComposerCrawler;
    let packages = crawler.crawl_all(&options_at(tmp.path())).await;
    assert_eq!(packages.len(), 2, "got {packages:?}");
    let plugin = packages.iter().find(|p| p.purl == PLUGIN_PURL).unwrap();
    assert_eq!(plugin.path, plugin_dir);
    // `./installers` (a CurDir component) resolves inside vendor/composer/.
    let installers = packages.iter().find(|p| p.purl == INSTALLERS_PURL).unwrap();
    assert_eq!(installers.path, installers_dir);

    // apply resolves through find_by_purls and must agree with the crawl —
    // otherwise the patch button offers a package apply can't locate.
    let found = crawler
        .find_by_purls(&vendor, &[PLUGIN_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(found.len(), 1, "got {found:?}");
    assert_eq!(found.get(PLUGIN_PURL).unwrap().path, plugin_dir);
}

/// installed.json is untrusted, tamperable input and the directory it names
/// is a patch WRITE target, so an `install-path` that leaves the project
/// must be dropped — by both the scan path and apply's resolver. The
/// boundary is the project, not the vendor root: a legitimate
/// composer/installers target lives outside `vendor/` (see the test above),
/// so `..` alone cannot be the signal.
#[tokio::test]
#[serial_test::parallel]
async fn install_path_escaping_project_root_is_rejected() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("proj");
    let vendor = root.join("vendor");
    let composer_dir = vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    tokio::fs::write(root.join("composer.json"), b"{}")
        .await
        .unwrap();

    // Both escape targets EXIST on disk, so the on-disk corroboration alone
    // does not stop them; only the containment gate does.
    let outside = outer.path().join("evil").join("pkg");
    tokio::fs::create_dir_all(&outside).await.unwrap();
    tokio::fs::create_dir_all(vendor.join("monolog").join("monolog"))
        .await
        .unwrap();
    tokio::fs::write(
        composer_dir.join("installed.json"),
        format!(
            r#"{{"packages":[
              {{"name":"monolog/monolog","version":"3.5.0","install-path":"../monolog/monolog"}},
              {{"name":"relative/evil","version":"1.0.0","install-path":"../../../evil/pkg"}},
              {{"name":"absolute/evil","version":"1.0.0","install-path":"{}"}}
            ]}}"#,
            outside.display()
        ),
    )
    .await
    .unwrap();

    let crawler = ComposerCrawler;
    let packages = crawler.crawl_all(&options_at(&root)).await;
    assert_eq!(
        packages.len(),
        1,
        "only the in-project package may survive; got {:?}",
        packages.iter().map(|p| &p.path).collect::<Vec<_>>()
    );
    assert_eq!(packages[0].purl, ORG_PURL);

    let found = crawler
        .find_by_purls(
            &vendor,
            &[
                "pkg:composer/relative/evil@1.0.0".to_string(),
                "pkg:composer/absolute/evil@1.0.0".to_string(),
            ],
        )
        .await
        .unwrap();
    assert!(
        found.is_empty(),
        "install-path escaped the project root: {:?}",
        found.values().map(|p| &p.path).collect::<Vec<_>>()
    );
}

/// A rejected `install-path` must NOT fall back to `vendor/<ns>/<name>`:
/// installed.json says the package lives elsewhere, so patching whatever
/// happens to sit at the conventional path would edit the wrong tree.
#[tokio::test]
#[serial_test::parallel]
async fn rejected_install_path_does_not_fall_back_to_conventional_dir() {
    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("proj");
    let vendor = root.join("vendor");
    let composer_dir = vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    tokio::fs::write(root.join("composer.json"), b"{}")
        .await
        .unwrap();
    // The conventional directory exists and would otherwise be accepted.
    tokio::fs::create_dir_all(vendor.join("monolog").join("monolog"))
        .await
        .unwrap();
    tokio::fs::create_dir_all(outer.path().join("elsewhere"))
        .await
        .unwrap();
    tokio::fs::write(
        composer_dir.join("installed.json"),
        br#"{"packages":[{"name":"monolog/monolog","version":"3.5.0","install-path":"../../../elsewhere"}]}"#,
    )
    .await
    .unwrap();

    let crawler = ComposerCrawler;
    assert!(
        crawler.crawl_all(&options_at(&root)).await.is_empty(),
        "a rejected install-path must not resolve to vendor/monolog/monolog"
    );
    assert!(crawler
        .find_by_purls(&vendor, &[ORG_PURL.to_string()])
        .await
        .unwrap()
        .is_empty());
}

// ── version normalization parity with the lockfile inventory ────

/// `V1.2.3` is a legal Composer tag. The crawler strips `v` AND `V` from
/// installed.json versions, so if the lockfile inventory strips only the
/// lowercase form the same package yields TWO different PURLs — one
/// installed `@1.2.3` row plus a phantom lockfile-only `@V1.2.3` row, both
/// POSTed to the API and both shown to the user. Pin the two normalizations
/// to the same output.
#[tokio::test]
#[serial_test::parallel]
async fn uppercase_v_version_normalizes_identically_in_crawl_and_lock_inventory() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    let composer_dir = vendor.join("composer");
    tokio::fs::create_dir_all(&composer_dir).await.unwrap();
    tokio::fs::create_dir_all(vendor.join("monolog").join("monolog"))
        .await
        .unwrap();
    tokio::fs::write(
        composer_dir.join("installed.json"),
        br#"{"packages":[{"name":"monolog/monolog","version":"V3.5.0","install-path":"../monolog/monolog"}]}"#,
    )
    .await
    .unwrap();
    tokio::fs::write(tmp.path().join("composer.json"), b"{}")
        .await
        .unwrap();
    tokio::fs::write(
        tmp.path().join("composer.lock"),
        br#"{"packages":[{"name":"monolog/monolog","version":"V3.5.0","dist":{"type":"zip","url":"https://example.com/m.zip","shasum":""}}]}"#,
    )
    .await
    .unwrap();

    let crawled = ComposerCrawler.crawl_all(&options_at(tmp.path())).await;
    assert_eq!(crawled.len(), 1, "got {crawled:?}");
    assert_eq!(crawled[0].purl, ORG_PURL);

    let inventoried =
        socket_patch_core::vendor::lock_inventory::inventory_project(tmp.path()).await;
    let composer_rows: Vec<_> = inventoried
        .iter()
        .filter(|e| e.ecosystem == "composer")
        .collect();
    assert_eq!(composer_rows.len(), 1, "got {composer_rows:?}");
    assert_eq!(
        composer_rows[0].purl, crawled[0].purl,
        "lockfile and installed rows must normalize to ONE purl, else the \
         package double-counts as installed + lockfile-only"
    );
}
