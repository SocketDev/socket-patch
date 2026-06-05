//! Monorepo discovery coverage for the NON-npm crawlers.
//!
//! npm is workspace-aware (it walks workspace-member `node_modules`), but the
//! gem / python / go / composer crawlers are **cwd-only**: they discover the
//! single project rooted at `options.cwd` and do not descend into
//! subdirectories. In a monorepo with several independent subprojects — each
//! with its own lockfile / installed packages in a subdir — crawling from the
//! repo root therefore finds none of them.
//!
//! Gem is the representative here (the case the request named); python
//! (multiple `.venv`), go (multiple `go.mod`), and composer (multiple
//! `composer.json`) share the identical cwd-only limitation.
//!
//! The first test is a GREEN pin: crawling with `cwd` pointed AT a subproject
//! discovers that subproject's gems — i.e. the per-subproject (one-invocation-
//! per-project) model works today, and proves the fixture layout is genuinely
//! discoverable. The second is a GAP pin (`#[ignore]`): crawling from the repo
//! root should aggregate every subproject's gems. It is the executable spec for
//! the intended multi-lockfile discovery; un-ignore it when that ships. See
//! CLI_CONTRACT.md "Setup command contract" → "Monorepo / multi-project
//! discovery model".

use std::path::Path;

use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::RubyCrawler;

fn local_opts_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

/// Stage a gem inside a subproject's Bundler `vendor/bundle` deployment layout:
/// `<subproject>/vendor/bundle/ruby/3.2.0/gems/<name>-<version>/lib`. A `Gemfile`
/// is written so the subproject is a realistic Bundler project.
async fn stage_vendor_gem(subproject: &Path, name: &str, version: &str) {
    let pkg = subproject
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.2.0")
        .join("gems")
        .join(format!("{name}-{version}"))
        .join("lib");
    tokio::fs::create_dir_all(&pkg).await.unwrap();
    // Realistic Bundler project marker (the subproject dir now exists).
    tokio::fs::write(subproject.join("Gemfile"), b"source 'https://rubygems.org'\n")
        .await
        .unwrap();
}

// ── GREEN: per-subproject crawl works (the cwd-scoped model) ──────────────

#[tokio::test]
async fn gem_crawl_from_subproject_cwd_finds_its_own_gems() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = tmp.path().join("backend");
    let frontend = tmp.path().join("frontend");
    stage_vendor_gem(&backend, "rails", "7.1.0").await;
    stage_vendor_gem(&frontend, "sinatra", "3.0.0").await;

    let crawler = RubyCrawler;
    // cwd = backend → discovers backend's vendor/bundle gems.
    let result = crawler.crawl_all(&local_opts_at(&backend)).await;
    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert!(
        purls.contains(&"pkg:gem/rails@7.1.0"),
        "crawling with cwd=backend must find backend's gem; got {purls:?}"
    );
    // And it does NOT leak the sibling subproject's gem (cwd-scoped).
    assert!(
        !purls.contains(&"pkg:gem/sinatra@3.0.0"),
        "cwd=backend must not discover frontend's gem; got {purls:?}"
    );
}

// ── GAP: aggregate crawl from the repo root (multi-lockfile) ──────────────

#[tokio::test]
#[ignore = "gap: non-npm crawlers (gem/python/go/composer) are cwd-only and do not discover per-subproject lockfiles from the repo root; see CLI_CONTRACT 'Setup command contract' → Monorepo / multi-project discovery model"]
async fn gem_crawl_from_repo_root_discovers_all_subproject_lockfiles() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = tmp.path().join("backend");
    let frontend = tmp.path().join("frontend");
    stage_vendor_gem(&backend, "rails", "7.1.0").await;
    stage_vendor_gem(&frontend, "sinatra", "3.0.0").await;

    let crawler = RubyCrawler;
    // cwd = repo root: intended behavior is to discover BOTH subprojects' gems.
    // Today the gem crawler only inspects <root>/vendor/bundle (absent here), so
    // it finds neither.
    let result = crawler.crawl_all(&local_opts_at(tmp.path())).await;
    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert!(
        purls.contains(&"pkg:gem/rails@7.1.0"),
        "root crawl must discover backend/'s gem (multi-lockfile monorepo); got {purls:?}"
    );
    assert!(
        purls.contains(&"pkg:gem/sinatra@3.0.0"),
        "root crawl must discover frontend/'s gem (multi-lockfile monorepo); got {purls:?}"
    );
}
