//! Integration coverage for `crawlers::nuget_crawler`. The
//! apply-CLI suite drives the global-cache `find_by_purls` happy
//! path with `SOCKET_EXPERIMENTAL_NUGET=1`; everything else here —
//! legacy `Packages/<Name>.<Version>` layout, case-insensitive
//! lookup, `crawl_all` directory scanning, `scan_package_dir`'s
//! hidden-dir skip, `get_nuget_package_paths` discovery branches —
//! goes uncovered without these tests.

#![cfg(feature = "nuget")]

use std::path::Path;

use serial_test::serial;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::NuGetCrawler;

const ORG_PURL_A: &str = "pkg:nuget/Newtonsoft.Json@13.0.3";
const ORG_PURL_B: &str = "pkg:nuget/Serilog@4.0.0";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

/// Stage a global-cache layout: <root>/<lowercase>/<version>/ with
/// a minimal `.nuspec` so verify_nuget_package returns true.
async fn stage_global_cache_pkg(root: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg_dir = root.join(name.to_lowercase()).join(version);
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join(format!("{}.nuspec", name.to_lowercase())),
        format!(
            r#"<?xml version="1.0"?><package><metadata><id>{name}</id><version>{version}</version></metadata></package>"#
        ),
    )
    .await
    .unwrap();
    pkg_dir
}

/// Stage a legacy <Name>.<Version> layout. Used by older
/// `packages.config` projects.
async fn stage_legacy_pkg(root: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg_dir = root.join(format!("{name}.{version}"));
    tokio::fs::create_dir_all(pkg_dir.join("lib")).await.unwrap();
    tokio::fs::write(
        pkg_dir.join(format!("{name}.nuspec")),
        format!(
            r#"<?xml version="1.0"?><package><metadata><id>{name}</id><version>{version}</version></metadata></package>"#
        ),
    )
    .await
    .unwrap();
    pkg_dir
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_global_cache_layout_finds_package() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = stage_global_cache_pkg(tmp.path(), "Newtonsoft.Json", "13.0.3").await;

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    let pkg = result.get(ORG_PURL_A).expect("must find by purl");
    assert_eq!(pkg.path, pkg_dir);
    assert_eq!(pkg.name, "Newtonsoft.Json");
    assert_eq!(pkg.version, "13.0.3");
}

#[tokio::test]
async fn find_by_purls_legacy_layout_finds_package() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = stage_legacy_pkg(tmp.path(), "Newtonsoft.Json", "13.0.3").await;

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(ORG_PURL_A).unwrap().path, pkg_dir);
}

/// PURL with a case-mismatched name. NuGet package names are
/// case-insensitive — the case-insensitive legacy scan must locate
/// the package even when only a differently-cased dir exists.
///
/// On case-insensitive filesystems (default macOS APFS), this exercises
/// the same fast-path `legacy_dir` branch since the filesystem itself
/// folds names. On case-sensitive filesystems (Linux ext4), the
/// case-insensitive scan branch fires.
#[tokio::test]
async fn find_by_purls_case_insensitive_legacy_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let _pkg_dir = stage_legacy_pkg(tmp.path(), "newtonsoft.json", "13.0.3").await;

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "package must be found via either fast or case-insensitive path");
    let found = result.get(ORG_PURL_A).unwrap();
    // Either casing is acceptable; the contract is "matched something".
    assert!(found.path.exists(), "returned path must exist; got {:?}", found.path);
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // Empty dir — no packages.
    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    stage_global_cache_pkg(tmp.path(), "Newtonsoft.Json", "13.0.3").await;
    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:not-nuget/Foo@1.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty(), "non-nuget PURLs must be skipped");
}

// ── crawl_all (scan_package_dir) ───────────────────────────────

#[tokio::test]
async fn crawl_all_discovers_global_cache_layout() {
    let tmp = tempfile::tempdir().unwrap();
    stage_global_cache_pkg(tmp.path(), "Newtonsoft.Json", "13.0.3").await;
    stage_global_cache_pkg(tmp.path(), "Serilog", "4.0.0").await;

    let crawler = NuGetCrawler;
    // Use --global-prefix to point at our staged root.
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 2);
    // The crawler lowercases the discovered name from the directory.
    let purls: Vec<String> = result
        .iter()
        .map(|p| p.purl.to_ascii_lowercase())
        .collect();
    assert!(purls.iter().any(|p| p.contains("newtonsoft.json")));
    assert!(purls.iter().any(|p| p.contains("serilog")));
}

#[tokio::test]
async fn crawl_all_discovers_legacy_layout() {
    let tmp = tempfile::tempdir().unwrap();
    stage_legacy_pkg(tmp.path(), "Newtonsoft.Json", "13.0.3").await;
    stage_legacy_pkg(tmp.path(), "Serilog", "4.0.0").await;

    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.len() >= 2, "legacy layout must be discovered; got {result:?}");
}

#[tokio::test]
async fn crawl_all_skips_hidden_directories() {
    let tmp = tempfile::tempdir().unwrap();
    // Real package.
    stage_global_cache_pkg(tmp.path(), "Newtonsoft.Json", "13.0.3").await;
    // Hidden dir that mimics a package layout — must be skipped.
    let hidden = tmp.path().join(".cache").join("13.0.3");
    tokio::fs::create_dir_all(&hidden).await.unwrap();
    tokio::fs::write(hidden.join(".cache.nuspec"), b"<package/>").await.unwrap();

    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    // Only the real package should show up.
    assert_eq!(result.len(), 1);
    assert!(
        result[0].purl.to_ascii_lowercase().contains("newtonsoft.json"),
        "expected newtonsoft.json; got {:?}",
        result[0].purl
    );
}

// ── get_nuget_package_paths ─────────────────────────────────────

#[tokio::test]
#[serial]
async fn get_nuget_package_paths_with_global_prefix_returns_only_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let paths = crawler.get_nuget_package_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
#[serial]
async fn get_nuget_package_paths_local_discovers_packages_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("packages");
    tokio::fs::create_dir_all(&pkg).await.unwrap();

    let crawler = NuGetCrawler;
    let paths = crawler.get_nuget_package_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.iter().any(|p| p == &pkg), "packages/ must be discovered; got {paths:?}");
}

#[tokio::test]
#[serial]
async fn get_nuget_package_paths_local_with_csproj_falls_back_to_global() {
    let tmp = tempfile::tempdir().unwrap();
    // Marker file that triggers .NET-project detection.
    tokio::fs::write(
        tmp.path().join("MyProj.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"></Project>"#,
    )
    .await
    .unwrap();
    // Stub NUGET_PACKAGES to a writable temp location.
    let nuget_root = tempfile::tempdir().unwrap();
    let prev = std::env::var("NUGET_PACKAGES").ok();
    std::env::set_var("NUGET_PACKAGES", nuget_root.path());

    let crawler = NuGetCrawler;
    let paths = crawler.get_nuget_package_paths(&options_at(tmp.path())).await.unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }

    assert!(
        paths.iter().any(|p| p == nuget_root.path()),
        "csproj must trigger global-cache fallback; got {paths:?}"
    );
}

#[tokio::test]
#[serial]
async fn get_nuget_package_paths_local_no_project_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No `packages/`, no `.csproj`, no `.sln`, no `obj/`.
    let crawler = NuGetCrawler;
    let paths = crawler.get_nuget_package_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty(), "non-.NET dir must return empty paths");
}

#[tokio::test]
#[serial]
async fn get_nuget_package_paths_with_sln_falls_back_to_global() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("MySolution.sln"), b"Microsoft Visual Studio Solution File")
        .await
        .unwrap();
    let nuget_root = tempfile::tempdir().unwrap();
    let prev = std::env::var("NUGET_PACKAGES").ok();
    std::env::set_var("NUGET_PACKAGES", nuget_root.path());

    let crawler = NuGetCrawler;
    let paths = crawler.get_nuget_package_paths(&options_at(tmp.path())).await.unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }

    assert!(
        paths.iter().any(|p| p == nuget_root.path()),
        ".sln must trigger global-cache fallback"
    );
}

// ── verify_nuget_package indirectly via find_by_purls ───────────

#[tokio::test]
async fn find_by_purls_rejects_dir_without_nuspec_or_lib() {
    let tmp = tempfile::tempdir().unwrap();
    // Create a global-cache-shaped dir but with neither .nuspec nor lib/ — verify fails.
    let pkg_dir = tmp.path().join("newtonsoft.json").join("13.0.3");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    // No .nuspec, no lib/ — just an unrelated file.
    tokio::fs::write(pkg_dir.join("README.md"), b"hello").await.unwrap();

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty(), "dir without nuspec or lib/ must not match");
}

#[tokio::test]
async fn find_by_purls_with_lib_dir_marker_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("newtonsoft.json").join("13.0.3");
    tokio::fs::create_dir_all(pkg_dir.join("lib")).await.unwrap();
    // No .nuspec but lib/ is present — verify accepts it.

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
}

// Marker so ORG_PURL_B import isn't unused.
#[allow(dead_code)]
fn _used_in_doc() -> &'static str {
    ORG_PURL_B
}
