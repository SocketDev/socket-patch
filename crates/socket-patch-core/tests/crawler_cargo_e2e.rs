//! Integration coverage for `crawlers::cargo_crawler`.

#![cfg(feature = "cargo")]

use std::path::Path;

use socket_patch_core::crawlers::cargo_crawler::parse_cargo_toml_name_version;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::CargoCrawler;

const ORG_PURL: &str = "pkg:cargo/serde@1.0.200";

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

async fn stage_registry_crate(src: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg = src.join(format!("{name}-{version}"));
    tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
    let cargo_toml = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
    );
    tokio::fs::write(pkg.join("Cargo.toml"), cargo_toml).await.unwrap();
    tokio::fs::write(pkg.join("src").join("lib.rs"), b"// stub").await.unwrap();
    pkg
}

async fn stage_vendor_crate(src: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg = src.join(name);
    tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
    let cargo_toml = format!(
        "[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n"
    );
    tokio::fs::write(pkg.join("Cargo.toml"), cargo_toml).await.unwrap();
    pkg
}

// ── parse_cargo_toml_name_version ──────────────────────────────

#[test]
fn parse_cargo_toml_well_formed() {
    let toml =
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\nedition = \"2021\"\n";
    assert_eq!(
        parse_cargo_toml_name_version(toml),
        Some(("serde".to_string(), "1.0.200".to_string()))
    );
}

#[test]
fn parse_cargo_toml_missing_name_returns_none() {
    let toml = "[package]\nversion = \"1.0.200\"\n";
    assert_eq!(parse_cargo_toml_name_version(toml), None);
}

#[test]
fn parse_cargo_toml_missing_version_returns_none() {
    let toml = "[package]\nname = \"serde\"\n";
    assert_eq!(parse_cargo_toml_name_version(toml), None);
}

#[test]
fn parse_cargo_toml_malformed_returns_none() {
    let toml = "this is not toml at all";
    assert_eq!(parse_cargo_toml_name_version(toml), None);
}

/// Parser must stop scanning when it leaves the `[package]` table.
/// A `name =` or `version =` line under a later table must NOT be
/// picked up. Covers the "left package section" early-break arm
/// (cargo_crawler.rs:34-36).
#[test]
fn parse_cargo_toml_stops_at_next_section() {
    let toml = "[package]\nname = \"foo\"\nversion = \"1.0.0\"\n\n[dependencies]\nname = \"bar\"\n";
    assert_eq!(
        parse_cargo_toml_name_version(toml),
        Some(("foo".to_string(), "1.0.0".to_string()))
    );
}

/// Parser must ignore key=value lines that appear BEFORE [package]
/// (e.g. inside an earlier [profile.release] table).
#[test]
fn parse_cargo_toml_ignores_lines_before_package_section() {
    let toml = "[profile.release]\nname = \"wrong\"\n\n[package]\nname = \"foo\"\nversion = \"1.0.0\"\n";
    assert_eq!(
        parse_cargo_toml_name_version(toml),
        Some(("foo".to_string(), "1.0.0".to_string()))
    );
}

/// CargoCrawler's `Default` impl forwards to `new`. Exercise both
/// for symmetry.
#[test]
fn cargo_crawler_default_and_new_construct_cleanly() {
    let _a = CargoCrawler::default();
    let _b = CargoCrawler::new();
}

/// `cargo_home` fallback to `$HOME/.cargo` when CARGO_HOME is unset.
/// Exercised via `get_crate_source_paths(global=true)` which calls
/// `Self::get_registry_src_paths` → `cargo_home` internally.
#[tokio::test]
#[serial_test::serial]
async fn cargo_home_fallback_to_home_dot_cargo() {
    let tmp = tempfile::tempdir().unwrap();
    // Stage a fake registry tree at $HOME/.cargo/registry/src/.
    let stamp_dir = tmp
        .path()
        .join(".cargo")
        .join("registry")
        .join("src")
        .join("index.crates.io-1949cf8c6b5b557f");
    tokio::fs::create_dir_all(&stamp_dir).await.unwrap();

    let prev_cargo = std::env::var("CARGO_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::remove_var("CARGO_HOME");
    std::env::set_var("HOME", tmp.path());

    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_crate_source_paths(&opts).await.unwrap();

    if let Some(v) = prev_cargo {
        std::env::set_var("CARGO_HOME", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    }

    assert!(
        paths.iter().any(|p| p == &stamp_dir),
        "HOME/.cargo fallback registry must be discovered; got {paths:?}"
    );
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_registry_layout_finds_crate() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = stage_registry_crate(tmp.path(), "serde", "1.0.200").await;

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(ORG_PURL).unwrap().path, pkg);
}

#[tokio::test]
async fn find_by_purls_vendor_layout_finds_crate() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = stage_vendor_crate(tmp.path(), "serde", "1.0.200").await;

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(ORG_PURL).unwrap().path, pkg);
}

#[tokio::test]
async fn find_by_purls_vendor_version_mismatch_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    stage_vendor_crate(tmp.path(), "serde", "1.0.200").await;

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:cargo/serde@99.99.99".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty(), "version mismatch in vendor must skip");
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &[ORG_PURL.to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:not-cargo/serde@1.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_via_registry_layout() {
    let tmp = tempfile::tempdir().unwrap();
    stage_registry_crate(tmp.path(), "serde", "1.0.200").await;
    stage_registry_crate(tmp.path(), "tokio", "1.40.0").await;

    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.len() >= 2);
}

#[tokio::test]
async fn crawl_all_empty_src_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty());
}

// ── get_crate_source_paths ─────────────────────────────────────

#[tokio::test]
async fn get_crate_source_paths_with_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let paths = crawler.get_crate_source_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
async fn get_crate_source_paths_with_vendor_dir_returns_vendor() {
    let tmp = tempfile::tempdir().unwrap();
    let vendor = tmp.path().join("vendor");
    tokio::fs::create_dir(&vendor).await.unwrap();

    let crawler = CargoCrawler;
    let paths = crawler.get_crate_source_paths(&options_at(tmp.path())).await.unwrap();
    assert_eq!(paths, vec![vendor]);
}

#[tokio::test]
async fn get_crate_source_paths_no_cargo_project_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No Cargo.toml, no Cargo.lock, no vendor.
    let crawler = CargoCrawler;
    let paths = crawler.get_crate_source_paths(&options_at(tmp.path())).await.unwrap();
    assert!(paths.is_empty(), "non-Cargo dir must return empty paths");
}

// ── parse_dir_name_version fallback (via crawl_all) ────────────

/// Crate directory whose Cargo.toml has `version.workspace = true`
/// (no concrete `version =` field) — the crawler must fall back to
/// parsing `<name>-<version>` from the directory name. Exercises
/// `parse_dir_name_version` (cargo_crawler.rs:357-372).
#[tokio::test]
async fn crawl_all_falls_back_to_dir_name_when_workspace_version() {
    let tmp = tempfile::tempdir().unwrap();
    // <name>-<version> directory; Cargo.toml has workspace version.
    let pkg_dir = tmp.path().join("serde_json-1.0.120");
    tokio::fs::create_dir(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join("Cargo.toml"),
        "[package]\nname = \"serde_json\"\nversion.workspace = true\nedition = \"2021\"\n",
    )
    .await
    .unwrap();

    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].name, "serde_json");
    assert_eq!(result[0].version, "1.0.120");
}

#[tokio::test]
async fn crawl_all_skips_dir_without_cargo_toml() {
    let tmp = tempfile::tempdir().unwrap();
    // Directory shaped like a crate but no Cargo.toml — must be skipped.
    let pkg_dir = tmp.path().join("not_a_crate-1.0.0");
    tokio::fs::create_dir(&pkg_dir).await.unwrap();

    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty(), "dir without Cargo.toml must be skipped");
}

/// `verify_crate_at_path`'s fallback path: Cargo.toml has workspace
/// version, find_by_purls compares dir name. Exercises the
/// fallback arm in `verify_crate_at_path` (L335-L348).
#[tokio::test]
async fn find_by_purls_verify_fallback_via_dir_name() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("workspace-crate-0.1.0");
    tokio::fs::create_dir(&pkg).await.unwrap();
    // Cargo.toml has workspace version → triggers fallback.
    tokio::fs::write(
        pkg.join("Cargo.toml"),
        "[package]\nname = \"workspace-crate\"\nversion.workspace = true\n",
    )
    .await
    .unwrap();

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:cargo/workspace-crate@0.1.0".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "verify must fall back to dir name");
}
