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
    tokio::fs::create_dir_all(pkg_dir.join("lib"))
        .await
        .unwrap();
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
    let pkg = result.get(ORG_PURL_A).expect("must find by purl");
    assert_eq!(pkg.path, pkg_dir);
    assert_eq!(pkg.name, "Newtonsoft.Json");
    assert_eq!(pkg.version, "13.0.3");
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
    let staged = stage_legacy_pkg(tmp.path(), "newtonsoft.json", "13.0.3").await;

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert_eq!(
        result.len(),
        1,
        "package must be found via either fast or case-insensitive path"
    );
    let found = result.get(ORG_PURL_A).unwrap();
    // The reported name/version always preserve the PURL's original casing.
    assert_eq!(found.name, "Newtonsoft.Json");
    assert_eq!(found.version, "13.0.3");
    // Either casing of the on-disk dir is acceptable, but the returned path
    // must resolve to the one dir we actually staged — not some unrelated
    // path that merely happens to exist. canonicalize folds the case so the
    // assertion holds on both case-sensitive (Linux) and case-insensitive
    // (macOS/Windows) filesystems.
    let found_canon = std::fs::canonicalize(&found.path)
        .unwrap_or_else(|e| panic!("returned path must exist: {:?}: {e}", found.path));
    let staged_canon = std::fs::canonicalize(&staged).unwrap();
    assert_eq!(
        found_canon, staged_canon,
        "returned path must resolve to the staged package dir; got {:?}",
        found.path
    );
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
        .find_by_purls(tmp.path(), &["pkg:not-nuget/Foo@1.0".to_string()])
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
    // The crawler lowercases the discovered name from the directory, so the
    // emitted PURLs must be exactly the lowercased originals — substring
    // matching would accept a wrong version or a malformed PURL.
    let mut purls: Vec<String> = result.iter().map(|p| p.purl.clone()).collect();
    purls.sort_unstable();
    let mut expected = vec![ORG_PURL_A.to_ascii_lowercase(), ORG_PURL_B.to_ascii_lowercase()];
    expected.sort_unstable();
    assert_eq!(
        purls, expected,
        "expected exactly the two staged PURLs (lowercased); got {result:?}"
    );
    // Names and versions must round-trip too.
    let nj = result
        .iter()
        .find(|p| p.name == "newtonsoft.json")
        .expect("newtonsoft.json must be discovered");
    assert_eq!(nj.version, "13.0.3");
    let serilog = result
        .iter()
        .find(|p| p.name == "serilog")
        .expect("serilog must be discovered");
    assert_eq!(serilog.version, "4.0.0");
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
    // Legacy layout preserves the original folder casing in the name/version,
    // so the PURLs are the un-lowercased originals. Assert the exact set —
    // `>= 2` would tolerate phantom packages or a botched parse.
    let mut purls: Vec<String> = result.iter().map(|p| p.purl.clone()).collect();
    purls.sort_unstable();
    let mut expected = vec![ORG_PURL_A.to_string(), ORG_PURL_B.to_string()];
    expected.sort_unstable();
    assert_eq!(
        purls, expected,
        "legacy layout must yield exactly the two staged PURLs; got {result:?}"
    );
    let nj = result
        .iter()
        .find(|p| p.name == "Newtonsoft.Json")
        .expect("Newtonsoft.Json must be discovered with original casing");
    assert_eq!(nj.version, "13.0.3");
    let serilog = result
        .iter()
        .find(|p| p.name == "Serilog")
        .expect("Serilog must be discovered with original casing");
    assert_eq!(serilog.version, "4.0.0");
}

#[tokio::test]
async fn crawl_all_skips_hidden_directories() {
    let tmp = tempfile::tempdir().unwrap();
    // Real package.
    stage_global_cache_pkg(tmp.path(), "Newtonsoft.Json", "13.0.3").await;
    // Hidden dir that mimics a package layout — must be skipped.
    let hidden = tmp.path().join(".cache").join("13.0.3");
    tokio::fs::create_dir_all(&hidden).await.unwrap();
    tokio::fs::write(hidden.join(".cache.nuspec"), b"<package/>")
        .await
        .unwrap();

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
        result[0]
            .purl
            .to_ascii_lowercase()
            .contains("newtonsoft.json"),
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
    // `packages/` alone is NOT a NuGet marker — it is the conventional
    // JS/TS monorepo workspace layout — so local discovery is gated on a
    // .NET project marker. The legacy packages.config layout that owns
    // `packages/` ships a `packages.config`, so stage one here.
    tokio::fs::write(
        tmp.path().join("packages.config"),
        r#"<?xml version="1.0"?><packages/>"#,
    )
    .await
    .unwrap();

    let crawler = NuGetCrawler;
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(
        paths.iter().any(|p| p == &pkg),
        "packages/ must be discovered; got {paths:?}"
    );
}

/// Regression: a bare `packages/` directory (the JS/TS monorepo
/// workspace convention) with NO .NET project marker must NOT be
/// scanned. `crawl_all_ecosystems` runs the NuGet crawler against the
/// same `cwd` as every other ecosystem, so an ungated scan would
/// misclassify another ecosystem's workspace tree as NuGet sources.
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_local_ignores_packages_dir_without_marker() {
    let tmp = tempfile::tempdir().unwrap();
    // pnpm/lerna-style workspace: packages/<lib> but no .csproj/.sln/etc.
    tokio::fs::create_dir_all(tmp.path().join("packages").join("ui-kit"))
        .await
        .unwrap();

    let crawler = NuGetCrawler;
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(
        paths.is_empty(),
        "non-.NET project's packages/ must be ignored; got {paths:?}"
    );
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
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();

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
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(paths.is_empty(), "non-.NET dir must return empty paths");
}

#[tokio::test]
#[serial]
async fn get_nuget_package_paths_with_sln_falls_back_to_global() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(
        tmp.path().join("MySolution.sln"),
        b"Microsoft Visual Studio Solution File",
    )
    .await
    .unwrap();
    let nuget_root = tempfile::tempdir().unwrap();
    let prev = std::env::var("NUGET_PACKAGES").ok();
    std::env::set_var("NUGET_PACKAGES", nuget_root.path());

    let crawler = NuGetCrawler;
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();

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
    tokio::fs::write(pkg_dir.join("README.md"), b"hello")
        .await
        .unwrap();

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "dir without nuspec or lib/ must not match"
    );
}

#[tokio::test]
async fn find_by_purls_with_lib_dir_marker_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir = tmp.path().join("newtonsoft.json").join("13.0.3");
    tokio::fs::create_dir_all(pkg_dir.join("lib"))
        .await
        .unwrap();
    // No .nuspec but lib/ is present — verify accepts it.

    let crawler = NuGetCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL_A.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    let pkg = result.get(ORG_PURL_A).expect("lib/-only dir must match");
    // It must resolve to the global-cache dir we staged (lib/ marker path),
    // not some other coincidental match.
    assert_eq!(pkg.path, pkg_dir);
    assert_eq!(pkg.name, "Newtonsoft.Json");
    assert_eq!(pkg.version, "13.0.3");
}

#[path = "common/mod.rs"]
mod common;

/// `scan_package_dir` short-circuits when read_dir returns Err.
#[cfg(unix)]
#[tokio::test]
async fn crawl_all_handles_unreadable_pkg_path() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("blocked");
    tokio::fs::create_dir(&pkg).await.unwrap();
    let _ = stage_global_cache_pkg(&pkg, "newtonsoft.json", "13.0.3").await;
    common::chmod_unreadable(&pkg);

    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(pkg.clone()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&pkg);

    assert!(result.is_empty(), "unreadable pkg_path must yield empty");
}

/// `scan_global_cache_package` returns None when the per-name version
/// directory is unreadable — drives the inner read_dir Err arm at
/// nuget_crawler.rs:236.
#[cfg(unix)]
#[tokio::test]
async fn crawl_all_handles_unreadable_version_dir() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let pkg_name_dir = tmp.path().join("blocked-name");
    tokio::fs::create_dir(&pkg_name_dir).await.unwrap();
    // Stage a VALID version subdir DIRECTLY inside the name dir *before*
    // blocking it. `pkg_name_dir` is itself the package-name directory, so the
    // version folder must be its direct child (scan_global_cache_package
    // read_dir's it). Without the chmod this would be discovered as
    // `pkg:nuget/blocked-name@1.0.0`, proving the chmod — not an empty dir — is
    // what suppresses it. Otherwise the assertion would be vacuous.
    let ver_dir = pkg_name_dir.join("1.0.0");
    tokio::fs::create_dir_all(ver_dir.join("lib")).await.unwrap();
    common::chmod_unreadable(&pkg_name_dir);
    // Stage a readable sibling package so we prove the top-level scan actually
    // ran and only the blocked name dir was dropped — not that scanning bailed
    // out entirely.
    let _ = stage_global_cache_pkg(tmp.path(), "Serilog", "4.0.0").await;

    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&pkg_name_dir);

    // The blocked name dir contributes nothing; the readable sibling is found.
    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(
        purls,
        vec![ORG_PURL_B.to_ascii_lowercase().as_str()],
        "only the readable sibling must be discovered; got {result:?}"
    );
}

/// `scan_package_dir` skips entries that are not directories — covers
/// the `if !ft.is_dir()` continue arm at L183. Drive this by staging
/// a plain file alongside a valid global-cache package.
#[tokio::test]
async fn crawl_all_skips_files_at_top_level() {
    let tmp = tempfile::tempdir().unwrap();
    // Stage a real package so the scan actually runs.
    let _pkg = stage_global_cache_pkg(tmp.path(), "newtonsoft.json", "13.0.3").await;
    // Plain file at the top level — must be skipped.
    tokio::fs::write(tmp.path().join("readme.txt"), b"not a package")
        .await
        .unwrap();

    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names
        .iter()
        .any(|n| n.eq_ignore_ascii_case("newtonsoft.json")));
    assert_eq!(result.len(), 1, "plain file must be skipped");
}

/// `scan_package_dir` short-circuits when the package dir doesn't
/// exist — covers `read_dir(...).await` Err arm at L169.
#[tokio::test]
async fn crawl_all_missing_pkg_path_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        // Point global_prefix at a non-existent dir.
        global_prefix: Some(tmp.path().join("does-not-exist")),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty());
}

// ── NuGetCrawler construction ─────────────────────────────────

#[test]
fn nuget_crawler_default_and_new_construct_cleanly() {
    let _a = NuGetCrawler::default();
    let _b = NuGetCrawler::new();
}

// ── global mode ────────────────────────────────────────────────

/// `global=true` with no `global_prefix` falls through to `nuget_home`
/// which honors NUGET_PACKAGES. When the resulting home exists, the
/// crawler returns it as the only path (line 38-39).
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_global_mode_returns_nuget_home() {
    let tmp = tempfile::tempdir().unwrap();
    let nuget_root = tempfile::tempdir().unwrap();
    let prev = std::env::var("NUGET_PACKAGES").ok();
    std::env::set_var("NUGET_PACKAGES", nuget_root.path());

    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_nuget_package_paths(&opts).await.unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }

    assert_eq!(paths, vec![nuget_root.path().to_path_buf()]);
}

/// `global=true` but NUGET_PACKAGES points at a non-existent dir →
/// `is_dir` check fails and the crawler returns an empty list
/// (line 41).
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_global_mode_missing_home_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let prev = std::env::var("NUGET_PACKAGES").ok();
    let prev_home = std::env::var("HOME").ok();
    // Point both at a path that does not exist.
    let missing = tmp.path().join("does-not-exist");
    std::env::set_var("NUGET_PACKAGES", &missing);
    // HOME also pointed somewhere without .nuget — but NUGET_PACKAGES wins.
    std::env::set_var("HOME", tmp.path());

    let crawler = NuGetCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_nuget_package_paths(&opts).await.unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    assert!(
        paths.is_empty(),
        "missing global cache dir must yield empty; got {paths:?}"
    );
}

/// `is_dotnet_project` accepts a NuGet.Config marker without any
/// project file extensions — covers the L355 `if name == "NuGet.Config"`
/// branch.
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_with_nuget_config_falls_back_to_global() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("NuGet.Config"), b"<configuration/>")
        .await
        .unwrap();
    let nuget_root = tempfile::tempdir().unwrap();
    let prev = std::env::var("NUGET_PACKAGES").ok();
    std::env::set_var("NUGET_PACKAGES", nuget_root.path());

    let crawler = NuGetCrawler;
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }

    assert!(
        paths.iter().any(|p| p == nuget_root.path()),
        "NuGet.Config must trigger global-cache fallback"
    );
}

// ── project.assets.json discovery ─────────────────────────────

/// A staged `obj/project.assets.json` with a `packageFolders` map
/// must surface those folders alongside the global cache. Covers
/// `discover_paths_from_assets` and `parse_project_assets_package_folders`.
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_discovers_assets_json_package_folders() {
    let tmp = tempfile::tempdir().unwrap();
    let extra_packages = tempfile::tempdir().unwrap();
    let obj = tmp.path().join("obj");
    tokio::fs::create_dir_all(&obj).await.unwrap();
    // Build the assets.json body via serde_json so the path value is
    // properly escaped — on Windows, raw `format!`-embedded paths
    // contain unescaped backslashes that make the file invalid JSON,
    // which the production parser then silently drops.
    let mut folders = serde_json::Map::new();
    folders.insert(
        extra_packages.path().display().to_string(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    let assets = serde_json::json!({ "packageFolders": folders }).to_string();
    tokio::fs::write(obj.join("project.assets.json"), assets)
        .await
        .unwrap();
    // A project marker is required to satisfy the local-mode .NET gate.
    // `obj/project.assets.json` is a restore artifact that only ever
    // exists alongside a project file, so staging one is realistic.
    tokio::fs::write(
        tmp.path().join("MyProj.csproj"),
        r#"<Project Sdk="Microsoft.NET.Sdk"></Project>"#,
    )
    .await
    .unwrap();
    let nuget_root = tempfile::tempdir().unwrap();
    let prev = std::env::var("NUGET_PACKAGES").ok();
    std::env::set_var("NUGET_PACKAGES", nuget_root.path());

    let crawler = NuGetCrawler;
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }

    assert!(
        paths.iter().any(|p| p == extra_packages.path()),
        "assets.json packageFolders must be discovered; got {paths:?}"
    );
}

/// `project.assets.json` exists in a subdirectory (multi-project
/// solution) — `discover_paths_from_assets` walks one level deep.
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_discovers_assets_json_in_subproject() {
    let tmp = tempfile::tempdir().unwrap();
    let extra = tempfile::tempdir().unwrap();
    let sub_obj = tmp.path().join("WebApp").join("obj");
    tokio::fs::create_dir_all(&sub_obj).await.unwrap();
    // See companion test above — raw `format!` with Path::display()
    // produces invalid JSON on Windows.
    let mut folders = serde_json::Map::new();
    folders.insert(
        extra.path().display().to_string(),
        serde_json::Value::Object(serde_json::Map::new()),
    );
    let assets = serde_json::json!({ "packageFolders": folders }).to_string();
    tokio::fs::write(sub_obj.join("project.assets.json"), assets)
        .await
        .unwrap();
    // The solution root carries a `.sln` marker — required to satisfy
    // the local-mode .NET gate before subproject obj/ dirs are walked.
    tokio::fs::write(tmp.path().join("Solution.sln"), "")
        .await
        .unwrap();

    let prev = std::env::var("NUGET_PACKAGES").ok();
    let nuget_root = tempfile::tempdir().unwrap();
    std::env::set_var("NUGET_PACKAGES", nuget_root.path());

    let crawler = NuGetCrawler;
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }

    assert!(
        paths.iter().any(|p| p == extra.path()),
        "subproject obj/project.assets.json must be discovered; got {paths:?}"
    );
}

/// Empty `packageFolders` object in assets.json must not surface any
/// paths (line 447-448 `if result.is_empty()` arm).
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_assets_json_empty_packagefolders_yields_no_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = tmp.path().join("obj");
    tokio::fs::create_dir_all(&obj).await.unwrap();
    tokio::fs::write(obj.join("project.assets.json"), br#"{"packageFolders":{}}"#)
        .await
        .unwrap();

    let prev = std::env::var("NUGET_PACKAGES").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("NUGET_PACKAGES", tmp.path().join("nonexistent-cache"));
    std::env::set_var("HOME", tmp.path());

    let crawler = NuGetCrawler;
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    assert!(paths.is_empty(), "empty packageFolders must yield no paths");
}

/// Malformed JSON in project.assets.json must not crash — discovery
/// just skips it (line 442 `from_str.ok()?` arm).
#[tokio::test]
#[serial]
async fn get_nuget_package_paths_assets_json_malformed_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let obj = tmp.path().join("obj");
    tokio::fs::create_dir_all(&obj).await.unwrap();
    tokio::fs::write(obj.join("project.assets.json"), b"this is not json")
        .await
        .unwrap();

    let prev = std::env::var("NUGET_PACKAGES").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("NUGET_PACKAGES", tmp.path().join("nonexistent-cache"));
    std::env::set_var("HOME", tmp.path());

    let crawler = NuGetCrawler;
    // Must succeed with no panic, returning empty.
    let paths = crawler
        .get_nuget_package_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("NUGET_PACKAGES");
    if let Some(v) = prev {
        std::env::set_var("NUGET_PACKAGES", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    assert!(
        paths.is_empty(),
        "malformed assets.json must be skipped; got {paths:?}"
    );
}
