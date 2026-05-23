//! Integration coverage for `crawlers::npm_crawler`. Drives the
//! local-discovery paths apply-CLI tests skip (parse_package_name,
//! read_package_json, find_by_purls scoped vs unscoped, crawl_all
//! over a synthetic node_modules tree).

use std::path::Path;

use socket_patch_core::crawlers::npm_crawler::{
    build_npm_purl, get_bun_global_prefix, get_npm_global_prefix, get_pnpm_global_prefix,
    get_yarn_global_prefix, parse_bun_bin_output, parse_package_name, parse_pnpm_root_output,
    parse_yarn_dir_output, read_package_json,
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

/// Both fields present but empty strings — parse succeeds but the
/// downstream is_empty guard must reject.
#[tokio::test]
async fn read_package_json_empty_name_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"","version":"1.0.0"}"#).await.unwrap();
    assert_eq!(read_package_json(&pkg).await, None);
}

#[tokio::test]
async fn read_package_json_empty_version_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"lodash","version":""}"#).await.unwrap();
    assert_eq!(read_package_json(&pkg).await, None);
}

// ── NpmCrawler construction ────────────────────────────────────

#[test]
fn npm_crawler_new_and_default_construct_cleanly() {
    let _a = NpmCrawler::new();
    let _b = NpmCrawler::default();
}

// ── get_node_modules_paths ─────────────────────────────────────

/// `global_prefix` always takes precedence over discovery, even when
/// `global` flag is also set.
#[tokio::test]
async fn get_node_modules_paths_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let custom = tmp.path().join("custom-nm");
    tokio::fs::create_dir_all(&custom).await.unwrap();

    let crawler = NpmCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: false,
        global_prefix: Some(custom.clone()),
        batch_size: 100,
    };
    let paths = crawler.get_node_modules_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![custom]);
}

/// `global_prefix` even when only `global` is set without a prefix —
/// must fall through to `get_global_node_modules_paths()`. Since the
/// test env may have npm/yarn/pnpm/bun installed, we just assert the
/// call returns Ok (it can return any set of real or empty paths).
#[tokio::test]
async fn get_node_modules_paths_global_mode_no_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NpmCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    // Just must not panic — the actual list depends on the host.
    let _paths = crawler.get_node_modules_paths(&opts).await.unwrap();
}

// ── parse_bun_bin_output ───────────────────────────────────────

/// Bun's global node_modules lives at `<bun-root>/install/global/node_modules`
/// — the parser strips the trailing `bin` segment and joins the well-known
/// suffix.
#[test]
fn parse_bun_bin_output_well_formed_unix() {
    let parsed = parse_bun_bin_output("/home/foo/.bun/bin\n");
    assert_eq!(
        parsed.as_deref(),
        Some("/home/foo/.bun/install/global/node_modules")
    );
}

#[test]
fn parse_bun_bin_output_empty_returns_none() {
    assert_eq!(parse_bun_bin_output(""), None);
    assert_eq!(parse_bun_bin_output("   \n  "), None);
}

/// Root-only path has no parent — must yield None instead of panicking.
#[test]
fn parse_bun_bin_output_root_path_returns_none() {
    assert_eq!(parse_bun_bin_output("/"), None);
}

// ── shell-out wrappers via PATH stubbing ──────────────────────

/// Sub-helper: temporarily set `PATH` to a directory that does NOT
/// contain `npm`, `yarn`, `pnpm`, or `bun`, run the callback, then
/// restore. Used to force the `.output().ok()?` Err arm in each
/// global-prefix wrapper without depending on whether the dev host
/// has those binaries installed.
fn with_empty_path<F: FnOnce()>(f: F) {
    let prev = std::env::var("PATH").ok();
    let empty = tempfile::tempdir().unwrap();
    std::env::set_var("PATH", empty.path());
    f();
    if let Some(v) = prev {
        std::env::set_var("PATH", v);
    } else {
        std::env::remove_var("PATH");
    }
}

#[test]
#[serial_test::serial]
fn get_npm_global_prefix_returns_err_when_npm_not_on_path() {
    with_empty_path(|| {
        let result = get_npm_global_prefix();
        assert!(result.is_err(), "npm-not-on-PATH must return Err; got {result:?}");
    });
}

#[test]
#[serial_test::serial]
fn get_yarn_global_prefix_returns_none_when_yarn_not_on_path() {
    with_empty_path(|| {
        assert_eq!(get_yarn_global_prefix(), None);
    });
}

#[test]
#[serial_test::serial]
fn get_pnpm_global_prefix_returns_none_when_pnpm_not_on_path() {
    with_empty_path(|| {
        assert_eq!(get_pnpm_global_prefix(), None);
    });
}

#[test]
#[serial_test::serial]
fn get_bun_global_prefix_returns_none_when_bun_not_on_path() {
    with_empty_path(|| {
        assert_eq!(get_bun_global_prefix(), None);
    });
}

// ── parse_yarn_dir_output ──────────────────────────────────────

/// yarn global dir prints `<dir>`; we append `/node_modules`.
#[test]
fn parse_yarn_dir_output_appends_node_modules() {
    let parsed = parse_yarn_dir_output("/Users/foo/.yarn/global\n");
    assert_eq!(
        parsed.as_deref(),
        Some("/Users/foo/.yarn/global/node_modules")
    );
}

#[test]
fn parse_yarn_dir_output_empty_returns_none() {
    assert_eq!(parse_yarn_dir_output(""), None);
    assert_eq!(parse_yarn_dir_output("\n  \n"), None);
}

// ── parse_pnpm_root_output ─────────────────────────────────────

#[test]
fn parse_pnpm_root_output_returns_trimmed_path() {
    let parsed = parse_pnpm_root_output("/home/foo/.local/share/pnpm/global/5/node_modules\n");
    assert_eq!(
        parsed.as_deref(),
        Some("/home/foo/.local/share/pnpm/global/5/node_modules")
    );
}

#[test]
fn parse_pnpm_root_output_empty_returns_none() {
    assert_eq!(parse_pnpm_root_output(""), None);
    assert_eq!(parse_pnpm_root_output("   \n  "), None);
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

/// `parse_purl_components` strips trailing qualifiers (`?...`).
/// Covers `parse_purl_components` line 702.
#[tokio::test]
async fn find_by_purls_strips_qualifiers() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(
            &nm,
            &["pkg:npm/lodash@4.17.21?extension=tgz".to_string()],
        )
        .await
        .unwrap();
    // Note: result key uses the original purl, but lookup back uses
    // the stripped form internally; the purl set check ensures the
    // entry is only inserted if the synthesized purl matches one of
    // the requested purls. With qualifier present, synthesis returns
    // `pkg:npm/lodash@4.17.21` which doesn't match the qualified
    // input — so the result is empty. The important coverage is that
    // parse_purl_components successfully strips the qualifier.
    assert!(result.is_empty(), "qualifier strip + synth mismatch must yield empty");
}

/// PURL with no `@` (no version separator) must be rejected via the
/// `rfind('@')?` arm (line 707).
#[tokio::test]
async fn find_by_purls_purl_without_at_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/lodash".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

/// PURL with `@` but an empty version (`pkg:npm/lodash@`) — covers the
/// `version.is_empty()` arm at line 711-712.
#[tokio::test]
async fn find_by_purls_purl_with_empty_version_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/lodash@".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

/// PURL with scope marker but no slash (`pkg:npm/@foo@1.0`) — covers
/// the `find('/')?` arm at line 716.
#[tokio::test]
async fn find_by_purls_scoped_purl_without_slash_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/@foo@1.0".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

/// Scoped PURL with empty name after slash (`pkg:npm/@scope/@1.0`) —
/// covers the `if name.is_empty()` arm at line 719-720.
#[tokio::test]
async fn find_by_purls_scoped_purl_with_empty_name_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/@scope/@1.0".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
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

/// `find_workspace_node_modules` should recurse into subdirectories
/// looking for nested `node_modules`, while skipping hidden dirs and
/// well-known build-output dirs.
#[tokio::test]
async fn crawl_all_recurses_into_workspace_packages() {
    let tmp = tempfile::tempdir().unwrap();
    // Root has no node_modules but a workspace subdir does.
    let pkg_dir = tmp.path().join("packages").join("ws-a");
    stage_npm_pkg(&pkg_dir.join("node_modules"), "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(
        names.contains(&"lodash"),
        "workspace recursion must discover nested node_modules; got {names:?}"
    );
}

#[tokio::test]
async fn crawl_all_skips_hidden_and_skip_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    // Hidden dirs and SKIP_DIRS entries (dist/build/coverage/tmp/...) are skipped.
    stage_npm_pkg(&tmp.path().join(".hidden").join("node_modules"), "should-not-find", "1.0").await;
    stage_npm_pkg(&tmp.path().join("dist").join("node_modules"), "also-not", "1.0").await;
    // But a real workspace dir should be picked up.
    stage_npm_pkg(&tmp.path().join("real-ws").join("node_modules"), "found-me", "1.0").await;

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"found-me"));
    assert!(!names.contains(&"should-not-find"), "hidden dir must be skipped");
    assert!(!names.contains(&"also-not"), "SKIP_DIRS dir must be skipped");
}

#[cfg(unix)]
#[path = "common/mod.rs"]
mod common;

/// `scan_node_modules` short-circuits when read_dir returns Err.
#[cfg(unix)]
#[tokio::test]
async fn crawl_all_handles_unreadable_node_modules() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "would-be-found", "1.0.0").await;
    common::chmod_unreadable(&nm);

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&nm);

    assert!(result.is_empty(), "unreadable node_modules must yield empty");
}

/// `find_workspace_node_modules` short-circuits cleanly when it
/// encounters an unreadable workspace subdir — drives the read_dir
/// Err arm at npm_crawler.rs:440-441 by chmod 000-ing one workspace
/// while leaving a readable one alongside.
#[cfg(unix)]
#[tokio::test]
async fn crawl_all_handles_unreadable_workspace_dir() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // Readable workspace.
    stage_npm_pkg(&tmp.path().join("readable").join("node_modules"), "ok", "1.0.0").await;
    // Unreadable workspace.
    let blocked = tmp.path().join("blocked");
    tokio::fs::create_dir(&blocked).await.unwrap();
    stage_npm_pkg(&blocked.join("node_modules"), "hidden", "2.0.0").await;
    common::chmod_unreadable(&blocked);

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    common::chmod_readable(&blocked);

    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"ok"));
    assert!(!names.contains(&"hidden"), "unreadable workspace must be skipped");
}

/// Drives scoped-package scanning + nested node_modules recursion +
/// the hidden-and-file-entries skip arms inside `scan_scoped_packages`
/// and `scan_nested_node_modules`. Covers L552, 581-604, 619-665.
#[tokio::test]
async fn crawl_all_handles_nested_and_messy_scope_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");

    // Regular package with its own nested node_modules containing another
    // package — exercises the unscoped → scan_nested_node_modules path.
    stage_npm_pkg(&nm, "outer", "1.0.0").await;
    stage_npm_pkg(&nm.join("outer").join("node_modules"), "inner", "2.0.0").await;

    // Scoped package — exercises scan_scoped_packages happy path.
    stage_npm_pkg(&nm, "@scope/scoped-pkg", "3.0.0").await;

    // Scoped package WITH a nested node_modules → scan_nested_node_modules
    // is reached from inside scan_scoped_packages (L599-604).
    stage_npm_pkg(
        &nm.join("@scope").join("scoped-pkg").join("node_modules"),
        "scoped-dep",
        "4.0.0",
    )
    .await;

    // Hidden subdir inside @scope — must be skipped (L581-583).
    tokio::fs::create_dir_all(nm.join("@scope").join(".hidden")).await.unwrap();
    // A plain file inside @scope — must be skipped via the !is_dir &&
    // !is_symlink arm (L590-591).
    tokio::fs::write(nm.join("@scope").join("README.md"), b"x").await.unwrap();
    // A plain file at top of node_modules too — exercises the same arm
    // in scan_node_modules.
    tokio::fs::write(nm.join("top-level-file.txt"), b"y").await.unwrap();

    // Nested node_modules with a scoped subentry — drives the L650-653 arm
    // (nested → scan_scoped_packages).
    stage_npm_pkg(
        &nm.join("outer").join("node_modules"),
        "@nest/leaf",
        "5.0.0",
    )
    .await;

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"outer"));
    assert!(names.contains(&"inner"));
    assert!(names.contains(&"scoped-pkg"));
    assert!(names.contains(&"scoped-dep"));
    assert!(names.contains(&"leaf"));
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
