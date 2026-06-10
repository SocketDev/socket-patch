//! Integration coverage for `crawlers::ruby_crawler`. Drives
//! branches the apply-CLI suite skips: vendor/bundle local mode,
//! global gem discovery via `~/.gem/ruby/*/gems`,
//! `~/.rbenv/versions/*/lib/ruby/gems/*/gems`, system paths,
//! Gemfile vs Gemfile.lock vs neither.

use std::path::Path;

use serial_test::serial;
use socket_patch_core::crawlers::ruby_crawler::parse_gem_env_output;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::RubyCrawler;

#[test]
fn parse_gem_env_output_well_formed() {
    assert_eq!(
        parse_gem_env_output("/Users/foo/.gem/ruby/3.2.0\n").as_deref(),
        Some("/Users/foo/.gem/ruby/3.2.0")
    );
}

#[test]
fn parse_gem_env_output_empty_returns_none() {
    assert_eq!(parse_gem_env_output(""), None);
    assert_eq!(parse_gem_env_output("   \n  "), None);
}

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
    tokio::fs::create_dir_all(pkg_dir.join("lib"))
        .await
        .unwrap();
    pkg_dir
}

/// Install a fake `gem` executable into `bin_dir` that answers
/// `gem env gemdir` with `gemdir` and fails every other invocation.
/// Lets the local-mode `gem env gemdir` fallback be exercised
/// deterministically (asserting the resolved path) without a real Ruby
/// toolchain on the host — instead of the previous swallowed-result
/// "doesn't crash" smoke tests.
#[cfg(unix)]
fn install_fake_gem(bin_dir: &Path, gemdir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = env ] && [ \"$2\" = gemdir ]; then\n  printf '%s\\n' \"{}\"\n  exit 0\nfi\nexit 1\n",
        gemdir.display()
    );
    let bin = bin_dir.join("gem");
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
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
    let pkg = result.get(ORG_PURL).unwrap();
    assert_eq!(pkg.path, pkg_dir);
    assert_eq!(pkg.name, "rails");
    assert_eq!(pkg.version, "7.1.0");
    assert_eq!(pkg.purl, ORG_PURL);
    assert_eq!(pkg.namespace, None);
}

#[tokio::test]
async fn find_by_purls_accepts_gem_with_gemspec_only() {
    let tmp = tempfile::tempdir().unwrap();
    // Stage with .gemspec but NO lib/ directory (alternate marker).
    let pkg_dir = tmp.path().join("rails-7.1.0");
    tokio::fs::create_dir(&pkg_dir).await.unwrap();
    tokio::fs::write(pkg_dir.join("rails.gemspec"), b"# gemspec")
        .await
        .unwrap();

    let crawler = RubyCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    let pkg = result.get(ORG_PURL).unwrap();
    assert_eq!(
        pkg.path, pkg_dir,
        "gemspec-only dir must be the resolved path"
    );
    assert_eq!(pkg.name, "rails");
    assert_eq!(pkg.version, "7.1.0");
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
    // Stage a gem dir that WOULD match `rails@7.1.0` on disk. The only
    // reason the lookup must come back empty is that the non-gem PURL
    // type fails `parse_gem_purl` and is skipped — not because there's
    // nothing to find. Without the staged dir this test passes
    // vacuously even if the ecosystem prefix were ignored.
    stage_gem(tmp.path(), "rails", "7.1.0").await;

    let crawler = RubyCrawler;
    let non_gem = "pkg:not-gem/rails@7.1.0".to_string();
    let result = crawler
        .find_by_purls(tmp.path(), std::slice::from_ref(&non_gem))
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "non-gem PURL must be skipped despite a matching rails-7.1.0 dir; got {result:?}"
    );
    assert!(!result.contains_key(&non_gem));

    // Control: the SAME on-disk layout resolves when the PURL is a real
    // gem PURL — proves the staged dir is genuinely discoverable, so the
    // emptiness above is attributable to the bad ecosystem, not a missing
    // fixture.
    let gem_result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(gem_result.len(), 1, "control gem PURL must resolve");
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

    // len==2 alone would survive a regression that discovers two *wrong*
    // gems. Pin the exact (purl, name, version) set discovered.
    use std::collections::HashSet;
    let purls: HashSet<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert!(
        purls.contains("pkg:gem/rails@7.1.0"),
        "rails must be discovered; got {purls:?}"
    );
    assert!(
        purls.contains("pkg:gem/nokogiri@1.16.5"),
        "nokogiri must be discovered; got {purls:?}"
    );
    let rails = result.iter().find(|p| p.name == "rails").unwrap();
    assert_eq!(rails.version, "7.1.0");
    assert_eq!(rails.path, tmp.path().join("rails-7.1.0"));
    let noko = result.iter().find(|p| p.name == "nokogiri").unwrap();
    assert_eq!(noko.version, "1.16.5");
    assert_eq!(noko.path, tmp.path().join("nokogiri-1.16.5"));
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
    let paths = crawler
        .get_gem_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    // `options_at` is local mode. Vendor discovery short-circuits and
    // returns ONLY the vendor gems dir — it must NOT fall through to the
    // `gem env`/global fallback (which is what "takes precedence" means).
    // An `any(...)` check would tolerate global paths leaking in
    // alongside vendor; require the exact singleton instead.
    assert_eq!(
        paths,
        vec![gems.clone()],
        "vendor/bundle gems dir must be the sole result (no global fallthrough); got {paths:?}"
    );
}

#[tokio::test]
async fn get_gem_paths_no_gemfile_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No Gemfile, no Gemfile.lock, no vendor/bundle.
    let crawler = RubyCrawler;
    let paths = crawler
        .get_gem_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(paths.is_empty(), "non-Ruby dir must return empty paths");
}

/// With a Gemfile present and no vendor/bundle, local mode falls back
/// to `gem env gemdir` and returns `<gemdir>/gems`. Driven
/// deterministically with a fake `gem` on PATH so the success arm is
/// actually asserted (the old test swallowed the result with `let _`).
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn get_gem_paths_with_gemfile_no_vendor_returns_gemdir() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("Gemfile"), b"source 'https://rubygems.org'")
        .await
        .unwrap();

    // The dir the fake `gem env gemdir` reports; its `gems/` subdir is
    // what the crawler must return (it checks is_dir on `<gemdir>/gems`).
    let gemdir = tempfile::tempdir().unwrap();
    let gems = gemdir.path().join("gems");
    tokio::fs::create_dir_all(&gems).await.unwrap();

    let bin = tempfile::tempdir().unwrap();
    install_fake_gem(bin.path(), gemdir.path());

    let prev = std::env::var("PATH").ok();
    std::env::set_var("PATH", bin.path());

    let crawler = RubyCrawler;
    let result = crawler.get_gem_paths(&options_at(tmp.path())).await;

    if let Some(v) = prev {
        std::env::set_var("PATH", v);
    } else {
        std::env::remove_var("PATH");
    }

    let paths = result.unwrap();
    assert_eq!(
        paths,
        vec![gems.clone()],
        "Gemfile + `gem env gemdir` must yield exactly <gemdir>/gems; got {paths:?}"
    );
}

/// Same as above but only a Gemfile.lock is present — proves the lock
/// alone (not just a Gemfile) triggers the `gem env gemdir` fallback.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn get_gem_paths_with_gemfile_lock_only_returns_gemdir() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("Gemfile.lock"), b"GEM\n")
        .await
        .unwrap();

    let gemdir = tempfile::tempdir().unwrap();
    let gems = gemdir.path().join("gems");
    tokio::fs::create_dir_all(&gems).await.unwrap();

    let bin = tempfile::tempdir().unwrap();
    install_fake_gem(bin.path(), gemdir.path());

    let prev = std::env::var("PATH").ok();
    std::env::set_var("PATH", bin.path());

    let crawler = RubyCrawler;
    let result = crawler.get_gem_paths(&options_at(tmp.path())).await;

    if let Some(v) = prev {
        std::env::set_var("PATH", v);
    } else {
        std::env::remove_var("PATH");
    }

    let paths = result.unwrap();
    assert_eq!(
        paths,
        vec![gems.clone()],
        "Gemfile.lock alone must trigger `gem env gemdir`; got {paths:?}"
    );
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

#[path = "common/mod.rs"]
mod common;

/// `scan_gem_dir` short-circuits when the gem path is unreadable —
/// drives ruby_crawler.rs:270 read_dir Err arm.
#[cfg(unix)]
#[tokio::test]
async fn crawl_all_handles_unreadable_gem_dir() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let gem_dir = tmp.path().join("blocked-gems");
    tokio::fs::create_dir(&gem_dir).await.unwrap();
    let _ = stage_gem(&gem_dir, "rails", "7.1.0").await;
    common::chmod_unreadable(&gem_dir);

    let crawler = RubyCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(gem_dir.clone()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&gem_dir);

    assert!(result.is_empty(), "unreadable gem dir must yield empty");
}

/// `RubyCrawler::default()` should forward to `new()`.
#[test]
fn ruby_crawler_default_and_new_construct_cleanly() {
    let _a = RubyCrawler;
    let _b = RubyCrawler::new();
}

/// With a Gemfile present and `gem` not on PATH, the local-mode
/// `gem env gemdir` fallback at L56-64 must short-circuit cleanly
/// (run_gem_env returns None via the `.output().ok()?` arm). The
/// crawler then exits the if-block and returns an empty Vec.
#[tokio::test]
#[serial]
async fn get_gem_paths_local_gemfile_no_gem_binary_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(
        tmp.path().join("Gemfile"),
        b"source 'https://rubygems.org'\n",
    )
    .await
    .unwrap();

    let empty_path = tempfile::tempdir().unwrap();
    let prev = std::env::var("PATH").ok();
    std::env::set_var("PATH", empty_path.path());

    let crawler = RubyCrawler;
    let paths = crawler
        .get_gem_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    if let Some(v) = prev {
        std::env::set_var("PATH", v);
    } else {
        std::env::remove_var("PATH");
    }

    assert!(
        paths.is_empty(),
        "no gem binary + no vendor must yield empty"
    );
}

/// Global mode with `gem` not on PATH and HOME pointing at a tempdir
/// containing no gem layouts at all must yield an empty result. This
/// drives the `run_gem_env` Err arms for both `gemdir` and `gempath`,
/// and the fallback_globs loop's read_dir-Err arm for each candidate.
#[tokio::test]
#[serial]
async fn global_gem_discovery_no_binary_no_home_layout_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let empty_path = tempfile::tempdir().unwrap();

    let prev_path = std::env::var("PATH").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("PATH", empty_path.path());
    std::env::set_var("HOME", tmp.path());

    let crawler = RubyCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_gem_paths(&opts).await.unwrap();

    if let Some(v) = prev_path {
        std::env::set_var("PATH", v);
    } else {
        std::env::remove_var("PATH");
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    // The crawler also probes system paths like /usr/local/lib/ruby/gems;
    // those may or may not exist on the test host. The contract here is
    // that the crawler does not panic and returns *no* paths sourced from
    // HOME (which had nothing staged).
    assert!(
        paths.iter().all(|p| !p.starts_with(tmp.path())),
        "no HOME-derived path should be returned; got {paths:?}"
    );
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
