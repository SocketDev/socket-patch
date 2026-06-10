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
    let cargo_toml =
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n");
    tokio::fs::write(pkg.join("Cargo.toml"), cargo_toml)
        .await
        .unwrap();
    tokio::fs::write(pkg.join("src").join("lib.rs"), b"// stub")
        .await
        .unwrap();
    pkg
}

async fn stage_vendor_crate(src: &Path, name: &str, version: &str) -> std::path::PathBuf {
    let pkg = src.join(name);
    tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
    let cargo_toml =
        format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n");
    tokio::fs::write(pkg.join("Cargo.toml"), cargo_toml)
        .await
        .unwrap();
    pkg
}

// ── parse_cargo_toml_name_version ──────────────────────────────

#[test]
fn parse_cargo_toml_well_formed() {
    let toml = "[package]\nname = \"serde\"\nversion = \"1.0.200\"\nedition = \"2021\"\n";
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
    let toml =
        "[profile.release]\nname = \"wrong\"\n\n[package]\nname = \"foo\"\nversion = \"1.0.0\"\n";
    assert_eq!(
        parse_cargo_toml_name_version(toml),
        Some(("foo".to_string(), "1.0.0".to_string()))
    );
}

/// CargoCrawler's `Default` impl forwards to `new`. Exercise both
/// for symmetry.
#[test]
fn cargo_crawler_default_and_new_construct_cleanly() {
    let _a = CargoCrawler;
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

    // Exactly the one staged index dir — proves the fallback resolved to
    // $HOME/.cargo (not some ambient CARGO_HOME) and listed nothing else.
    assert_eq!(
        paths,
        vec![stamp_dir],
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
    let found = result.get(ORG_PURL).unwrap();
    assert_eq!(found.path, pkg);
    assert_eq!(found.name, "serde");
    assert_eq!(found.version, "1.0.200");
    assert_eq!(found.purl, ORG_PURL);
    assert_eq!(found.namespace, None);
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
    let found = result.get(ORG_PURL).unwrap();
    assert_eq!(found.path, pkg);
    assert_eq!(found.name, "serde");
    assert_eq!(found.version, "1.0.200");
    assert_eq!(found.purl, ORG_PURL);
    // Vendor dir name carries no version, so this proves the version was
    // read from the manifest, not invented from the directory name.
}

#[tokio::test]
async fn find_by_purls_vendor_version_mismatch_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    stage_vendor_crate(tmp.path(), "serde", "1.0.200").await;

    let crawler = CargoCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:cargo/serde@99.99.99".to_string()])
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
        .find_by_purls(tmp.path(), &["pkg:not-cargo/serde@1.0".to_string()])
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
    // Exact contents, not just a `>= 2` floor: a regression that drops a
    // crate, mangles a version, or emits a spurious extra entry must fail.
    let mut found: Vec<(String, String, String)> = result
        .iter()
        .map(|p| (p.name.clone(), p.version.clone(), p.purl.clone()))
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            (
                "serde".to_string(),
                "1.0.200".to_string(),
                "pkg:cargo/serde@1.0.200".to_string()
            ),
            (
                "tokio".to_string(),
                "1.40.0".to_string(),
                "pkg:cargo/tokio@1.40.0".to_string()
            ),
        ],
        "crawl_all must surface exactly serde@1.0.200 and tokio@1.40.0; got {result:?}"
    );
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
    // `vendor/` is only treated as cargo sources once we've confirmed
    // this is a Rust project (`vendor/` is also Composer's and Go's
    // convention) — so a root Cargo.toml is required.
    tokio::fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
    )
    .await
    .unwrap();

    let crawler = CargoCrawler;
    let paths = crawler
        .get_crate_source_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert_eq!(paths, vec![vendor]);
}

/// Regression: a `vendor/` directory in a project with no Cargo
/// manifest (e.g. a Composer/Go project) must NOT be claimed by the
/// cargo crawler.
#[tokio::test]
async fn get_crate_source_paths_vendor_without_cargo_manifest_is_empty() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::create_dir(tmp.path().join("vendor"))
        .await
        .unwrap();

    let crawler = CargoCrawler;
    let paths = crawler
        .get_crate_source_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(
        paths.is_empty(),
        "vendor/ in a non-Rust project must not be scanned as cargo sources, got {paths:?}"
    );
}

#[tokio::test]
async fn get_crate_source_paths_no_cargo_project_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No Cargo.toml, no Cargo.lock, no vendor.
    let crawler = CargoCrawler;
    let paths = crawler
        .get_crate_source_paths(&options_at(tmp.path()))
        .await
        .unwrap();
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
    let purl = "pkg:cargo/workspace-crate@0.1.0";
    let result = crawler
        .find_by_purls(tmp.path(), &[purl.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "verify must fall back to dir name");
    let found = result.get(purl).unwrap();
    assert_eq!(found.path, pkg, "must resolve to the workspace crate dir");
    assert_eq!(found.name, "workspace-crate");
    assert_eq!(found.version, "0.1.0");
    assert_eq!(found.purl, purl);
}

/// `version.workspace = true` in a top-level `[package]` block must
/// bail (line 49-52): the crawler can't infer the actual version from
/// just this file. `find_by_purls` then has to fall back to dir-name
/// parsing — but `parse_cargo_toml_name_version` itself must return
/// None up front.
#[test]
fn parse_cargo_toml_version_workspace_returns_none() {
    let toml = "[package]\nname = \"foo\"\nversion.workspace = true\n";
    assert_eq!(parse_cargo_toml_name_version(toml), None);
}

/// `verify_crate_at_path` with a dir-name-only match (workspace
/// version) but a mismatched purl name — must return false. Exercises
/// the `parsed_name == name && parsed_version == version` false arm
/// (cargo_crawler.rs:344-346).
#[tokio::test]
async fn find_by_purls_verify_fallback_dir_name_mismatch_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("real-crate-1.0.0");
    tokio::fs::create_dir(&pkg).await.unwrap();
    tokio::fs::write(
        pkg.join("Cargo.toml"),
        "[package]\nname = \"real-crate\"\nversion.workspace = true\n",
    )
    .await
    .unwrap();

    let crawler = CargoCrawler;
    // Ask for a name that doesn't match the dir layout.
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:cargo/other-crate@1.0.0".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty(), "dir-name mismatch must reject");
}

/// Hidden directory entries inside the crate source root must be
/// skipped by `scan_crate_source` (line 274).
#[tokio::test]
async fn crawl_all_skips_hidden_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    // Stage a hidden dir that looks like a registry crate — must be skipped.
    let hidden = tmp.path().join(".hidden-crate-1.0.0");
    tokio::fs::create_dir(&hidden).await.unwrap();
    tokio::fs::write(
        hidden.join("Cargo.toml"),
        "[package]\nname = \"hidden-crate\"\nversion = \"1.0.0\"\n",
    )
    .await
    .unwrap();
    // Also stage a real one to confirm the scan actually runs.
    stage_registry_crate(tmp.path(), "real-crate", "1.0.0").await;

    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"real-crate"));
    assert!(
        !names.contains(&"hidden-crate"),
        "hidden dir must be skipped"
    );
}

/// `read_crate_cargo_toml` early-returns when the purl has already
/// been recorded in `seen` (line 310-311). Drive this by staging two
/// registry dirs for the same crate — the second one is deduped.
#[tokio::test]
async fn crawl_all_dedups_same_purl() {
    let tmp = tempfile::tempdir().unwrap();
    // Two physical dirs with identical Cargo.toml -> same purl.
    stage_registry_crate(tmp.path(), "foo", "1.0.0").await;
    let dup = tmp.path().join("dup-mirror");
    tokio::fs::create_dir(&dup).await.unwrap();
    tokio::fs::write(
        dup.join("Cargo.toml"),
        "[package]\nname = \"foo\"\nversion = \"1.0.0\"\n",
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
    assert_eq!(
        result.len(),
        1,
        "duplicate purls must dedup; got {result:?}"
    );
    assert_eq!(result[0].purl, "pkg:cargo/foo@1.0.0");
    assert_eq!(result[0].name, "foo");
    assert_eq!(result[0].version, "1.0.0");
}

/// `get_crate_source_paths` in local mode without a vendor dir but
/// with a Cargo.toml falls through to `get_registry_src_paths`. With
/// CARGO_HOME pointed at an empty tempdir, the registry/src subdir
/// doesn't exist → returns empty. Covers line 130.
#[tokio::test]
#[serial_test::serial]
async fn get_crate_source_paths_local_cargo_toml_falls_back_to_registry() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("Cargo.toml"), b"[package]\n")
        .await
        .unwrap();
    // CARGO_HOME points at an empty tempdir → no registry/src to scan.
    let cargo_home = tempfile::tempdir().unwrap();
    let prev = std::env::var("CARGO_HOME").ok();
    std::env::set_var("CARGO_HOME", cargo_home.path());

    let crawler = CargoCrawler;
    let paths = crawler
        .get_crate_source_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    if let Some(v) = prev {
        std::env::set_var("CARGO_HOME", v);
    } else {
        std::env::remove_var("CARGO_HOME");
    }

    assert!(
        paths.is_empty(),
        "missing registry/src must yield empty; got {paths:?}"
    );
}

/// `scan_crate_source` must skip plain-file entries inside the source
/// path — covers `!ft.is_dir()` continue arm (cargo_crawler.rs:266).
#[tokio::test]
async fn crawl_all_skips_top_level_files() {
    let tmp = tempfile::tempdir().unwrap();
    stage_registry_crate(tmp.path(), "real-crate", "1.0.0").await;
    tokio::fs::write(tmp.path().join("README"), b"not a crate")
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
    assert_eq!(result[0].name, "real-crate");
}

/// A crate directory with a broken `Cargo.toml` AND a non-conforming
/// directory name → `parse_cargo_toml_name_version` returns None
/// (broken toml) AND `parse_dir_name_version` returns None (no `-`
/// followed by digit), so the chain short-circuits at line 304 and
/// the package is silently skipped.
#[tokio::test]
async fn crawl_all_skips_crate_with_unparseable_toml_and_no_version_dir_name() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("no-version-suffix");
    tokio::fs::create_dir(&bad).await.unwrap();
    tokio::fs::write(bad.join("Cargo.toml"), b"this is not valid toml")
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
    assert!(
        result.is_empty(),
        "unparseable + no-version dir name must be skipped"
    );
}

#[path = "common/mod.rs"]
mod common;

/// `scan_crate_source` short-circuits when `read_dir` returns Err.
/// Drive by chmod 000-ing a tempdir then asking the crawler to scan
/// it. Skipped under root because chmod has no effect on uid 0.
#[cfg(unix)]
#[tokio::test]
async fn crawl_all_handles_unreadable_src_path() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let unreadable = tmp.path().join("blocked");
    tokio::fs::create_dir_all(&unreadable).await.unwrap();
    // Put a "crate" inside so we can prove the scan really stopped at
    // the unreadable barrier rather than just finding nothing.
    stage_registry_crate(&unreadable, "would-be-found", "1.0.0").await;
    common::chmod_unreadable(&unreadable);

    let crawler = CargoCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(unreadable.clone()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&unreadable);

    assert!(result.is_empty(), "unreadable src_path must yield empty");
}

/// `verify_crate_at_path` returns false when neither the Cargo.toml
/// parses NOR the dir-name parses — exercises the `else { false }`
/// arm at line 345-346.
#[tokio::test]
async fn find_by_purls_verify_fails_when_both_parsers_fail() {
    let tmp = tempfile::tempdir().unwrap();
    let bad = tmp.path().join("not-cargo-like-at-all");
    tokio::fs::create_dir(&bad).await.unwrap();
    tokio::fs::write(bad.join("Cargo.toml"), b"this is not toml")
        .await
        .unwrap();

    let crawler = CargoCrawler;
    // The strict registry dir for `pkg:cargo/foo@1.0.0` is
    // `tmp/foo-1.0.0/` (doesn't exist). The vendor dir `tmp/foo/`
    // also doesn't exist. So neither layout matches and we get empty.
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:cargo/foo@1.0.0".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

/// Same as above but with a registry/src tree staged — the discovered
/// index dirs must surface. Covers lines 228-235 (entry walk).
#[tokio::test]
#[serial_test::serial]
async fn get_crate_source_paths_local_cargo_toml_with_registry_src() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("Cargo.toml"), b"[package]\n")
        .await
        .unwrap();
    let cargo_home = tempfile::tempdir().unwrap();
    let index_dir = cargo_home
        .path()
        .join("registry")
        .join("src")
        .join("index.crates.io-stub");
    tokio::fs::create_dir_all(&index_dir).await.unwrap();

    let prev = std::env::var("CARGO_HOME").ok();
    std::env::set_var("CARGO_HOME", cargo_home.path());

    let crawler = CargoCrawler;
    let paths = crawler
        .get_crate_source_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    if let Some(v) = prev {
        std::env::set_var("CARGO_HOME", v);
    } else {
        std::env::remove_var("CARGO_HOME");
    }

    // Only one index dir was staged, so the result must be exactly it —
    // not merely "contains" it among arbitrary extras.
    assert_eq!(paths, vec![index_dir]);
}
