//! Integration coverage for `crawlers::npm_crawler`. Drives the
//! local-discovery paths apply-CLI tests skip (parse_package_name,
//! read_package_json, find_by_purls scoped vs unscoped, crawl_all
//! over a synthetic node_modules tree).

use std::path::Path;

use socket_patch_core::crawlers::npm_crawler::{
    build_npm_purl, get_bun_global_prefix, get_bun_global_prefix_with, get_npm_global_prefix,
    get_npm_global_prefix_with, get_pnpm_global_prefix, get_pnpm_global_prefix_with,
    get_yarn_global_prefix, get_yarn_global_prefix_with, parse_bun_bin_output,
    parse_npm_root_output, parse_package_name, parse_pnpm_root_output, parse_yarn_dir_output,
    read_package_json,
};
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::NpmCrawler;

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
    }
}

/// Stage a package inside node_modules. `name` may include a `@scope/`
/// prefix.
async fn stage_npm_pkg(node_modules: &Path, name: &str, version: &str) {
    let pkg_dir = node_modules.join(name);
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    let pkg_json = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    tokio::fs::write(pkg_dir.join("package.json"), pkg_json)
        .await
        .unwrap();
}

// ── parse_package_name ─────────────────────────────────────────

#[test]
#[serial_test::parallel]
fn parse_package_name_unscoped() {
    let (ns, name) = parse_package_name("lodash");
    assert_eq!(ns, None);
    assert_eq!(name, "lodash");
}

#[test]
#[serial_test::parallel]
fn parse_package_name_scoped() {
    let (ns, name) = parse_package_name("@types/node");
    assert_eq!(ns.as_deref(), Some("@types"));
    assert_eq!(name, "node");
}

#[test]
#[serial_test::parallel]
fn parse_package_name_at_only_no_slash() {
    // `@foo` with no `/` — treated as unscoped.
    let (ns, name) = parse_package_name("@oops");
    assert_eq!(ns, None);
    assert_eq!(name, "@oops");
}

// ── build_npm_purl ─────────────────────────────────────────────

#[test]
#[serial_test::parallel]
fn build_npm_purl_unscoped() {
    let purl = build_npm_purl(None, "lodash", "4.17.21");
    assert_eq!(purl, "pkg:npm/lodash@4.17.21");
}

#[test]
#[serial_test::parallel]
fn build_npm_purl_scoped() {
    let purl = build_npm_purl(Some("@types"), "node", "20.0.0");
    assert_eq!(purl, "pkg:npm/@types/node@20.0.0");
}

// ── read_package_json ──────────────────────────────────────────

#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_well_formed() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"lodash","version":"4.17.21"}"#)
        .await
        .unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, Some(("lodash".to_string(), "4.17.21".to_string())));
}

#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_missing_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let result = read_package_json(&tmp.path().join("nope.json")).await;
    assert_eq!(result, None);
}

#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_malformed_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, b"{ this is not json").await.unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, None);
}

#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_missing_name_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"version":"1.0.0"}"#)
        .await
        .unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, None);
}

#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_missing_version_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"lodash"}"#)
        .await
        .unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, None);
}

/// Both fields present but empty strings — parse succeeds but the
/// downstream is_empty guard must reject.
#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_empty_name_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"","version":"1.0.0"}"#)
        .await
        .unwrap();
    assert_eq!(read_package_json(&pkg).await, None);
}

#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_empty_version_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"lodash","version":""}"#)
        .await
        .unwrap();
    assert_eq!(read_package_json(&pkg).await, None);
}

// ── NpmCrawler construction ────────────────────────────────────

#[test]
#[serial_test::parallel]
fn npm_crawler_new_and_default_construct_cleanly() {
    let _a = NpmCrawler::new();
    let _b = NpmCrawler;
}

// ── get_node_modules_paths ─────────────────────────────────────

/// `global_prefix` always takes precedence over discovery, even when
/// `global` flag is also set.
#[tokio::test]
#[serial_test::parallel]
async fn get_node_modules_paths_global_prefix_passthrough() {
    let tmp = tempfile::tempdir().unwrap();
    let custom = tmp.path().join("custom-nm");
    tokio::fs::create_dir_all(&custom).await.unwrap();

    let crawler = NpmCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: false,
        global_prefix: Some(custom.clone()),
    };
    let paths = crawler.get_node_modules_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![custom]);
}

/// `global_prefix` even when only `global` is set without a prefix —
/// must fall through to `get_global_node_modules_paths()`. Since the
/// test env may have npm/yarn/pnpm/bun installed, we just assert the
/// call returns Ok (it can return any set of real or empty paths).
#[tokio::test]
#[serial_test::parallel]
async fn get_node_modules_paths_global_mode_no_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NpmCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
    };
    // Just must not panic — the actual list depends on the host.
    let _paths = crawler.get_node_modules_paths(&opts).await.unwrap();
}

// ── parse_bun_bin_output ───────────────────────────────────────

/// Bun's global node_modules lives at `<bun-root>/install/global/node_modules`
/// — the parser strips the trailing `bin` segment and joins the well-known
/// suffix.
///
/// Skipped on Windows: `PathBuf::join` uses `\` there, which produces
/// `/home/foo/.bun\install\global\node_modules` from Unix-style input.
/// The pure-parser semantics are still correct (parent stripping +
/// suffix join), just expressed in the host's path-separator. Real
/// bun installs on Windows would feed Windows-style paths into the
/// same parser.
#[cfg(unix)]
#[test]
#[serial_test::parallel]
fn parse_bun_bin_output_well_formed_unix() {
    let parsed = parse_bun_bin_output("/home/foo/.bun/bin\n");
    assert_eq!(
        parsed.as_deref(),
        Some("/home/foo/.bun/install/global/node_modules")
    );
}

#[test]
#[serial_test::parallel]
fn parse_bun_bin_output_empty_returns_none() {
    assert_eq!(parse_bun_bin_output(""), None);
    assert_eq!(parse_bun_bin_output("   \n  "), None);
}

/// Root-only path has no parent — must yield None instead of panicking.
#[test]
#[serial_test::parallel]
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
        assert!(
            result.is_err(),
            "npm-not-on-PATH must return Err; got {result:?}"
        );
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

// ── injected-CommandRunner success-arm tests ───────────────────

/// `get_npm_global_prefix_with` drives the success arm: a mock
/// runner returns canned stdout, and the helper returns the parsed
/// path. This covers the "binary present, returned valid output"
/// arm without needing npm on PATH.
#[test]
#[serial_test::parallel]
fn get_npm_global_prefix_with_mock_runner_returns_path() {
    let runner = common::MockCommandRunner::new().with_response(
        "npm",
        &["root", "-g"],
        Some("/usr/local/lib/node_modules\n"),
    );
    let result = get_npm_global_prefix_with(&runner);
    assert_eq!(result, Ok("/usr/local/lib/node_modules".to_string()));
}

#[test]
#[serial_test::parallel]
fn get_npm_global_prefix_with_mock_runner_empty_stdout_returns_err() {
    let runner = common::MockCommandRunner::new().with_response("npm", &["root", "-g"], Some(""));
    assert!(get_npm_global_prefix_with(&runner).is_err());
}

// Skipped on Windows: same path-separator reason as
// `parse_bun_bin_output_well_formed_unix` above.
#[cfg(unix)]
#[test]
#[serial_test::parallel]
fn get_yarn_global_prefix_with_mock_runner_success() {
    let runner = common::MockCommandRunner::new().with_response(
        "yarn",
        &["global", "dir"],
        Some("/Users/foo/.yarn/global\n"),
    );
    assert_eq!(
        get_yarn_global_prefix_with(&runner).as_deref(),
        Some("/Users/foo/.yarn/global/node_modules")
    );
}

#[test]
#[serial_test::parallel]
fn get_pnpm_global_prefix_with_mock_runner_success() {
    let runner = common::MockCommandRunner::new().with_response(
        "pnpm",
        &["root", "-g"],
        Some("/Users/foo/.pnpm-global\n"),
    );
    assert_eq!(
        get_pnpm_global_prefix_with(&runner).as_deref(),
        Some("/Users/foo/.pnpm-global")
    );
}

// Skipped on Windows: same path-separator reason as
// `parse_bun_bin_output_well_formed_unix` above.
#[cfg(unix)]
#[test]
#[serial_test::parallel]
fn get_bun_global_prefix_with_mock_runner_success() {
    let runner = common::MockCommandRunner::new().with_response(
        "bun",
        &["pm", "bin", "-g"],
        Some("/Users/foo/.bun/bin\n"),
    );
    assert_eq!(
        get_bun_global_prefix_with(&runner).as_deref(),
        Some("/Users/foo/.bun/install/global/node_modules")
    );
}

// ── parse_npm_root_output ──────────────────────────────────────

#[test]
#[serial_test::parallel]
fn parse_npm_root_output_well_formed() {
    assert_eq!(
        parse_npm_root_output("/usr/local/lib/node_modules\n").as_deref(),
        Some("/usr/local/lib/node_modules")
    );
}

#[test]
#[serial_test::parallel]
fn parse_npm_root_output_empty_returns_none() {
    assert_eq!(parse_npm_root_output(""), None);
    assert_eq!(parse_npm_root_output("  \n  "), None);
}

// ── parse_yarn_dir_output ──────────────────────────────────────

/// yarn global dir prints `<dir>`; we append `/node_modules`.
///
/// Skipped on Windows: same path-separator reason as the other
/// `_unix`-style tests above.
#[cfg(unix)]
#[test]
#[serial_test::parallel]
fn parse_yarn_dir_output_appends_node_modules() {
    let parsed = parse_yarn_dir_output("/Users/foo/.yarn/global\n");
    assert_eq!(
        parsed.as_deref(),
        Some("/Users/foo/.yarn/global/node_modules")
    );
}

#[test]
#[serial_test::parallel]
fn parse_yarn_dir_output_empty_returns_none() {
    assert_eq!(parse_yarn_dir_output(""), None);
    assert_eq!(parse_yarn_dir_output("\n  \n"), None);
}

// ── parse_pnpm_root_output ─────────────────────────────────────

#[test]
#[serial_test::parallel]
fn parse_pnpm_root_output_returns_trimmed_path() {
    let parsed = parse_pnpm_root_output("/home/foo/.local/share/pnpm/global/5/node_modules\n");
    assert_eq!(
        parsed.as_deref(),
        Some("/home/foo/.local/share/pnpm/global/5/node_modules")
    );
}

#[test]
#[serial_test::parallel]
fn parse_pnpm_root_output_empty_returns_none() {
    assert_eq!(parse_pnpm_root_output(""), None);
    assert_eq!(parse_pnpm_root_output("   \n  "), None);
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_unscoped_package() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/lodash@4.17.21".to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "exactly one match expected");
    // Map MUST be keyed by the requested purl, and the resolved package
    // must describe lodash@4.17.21 (not some other staged dir).
    let pkg = result
        .get("pkg:npm/lodash@4.17.21")
        .expect("result must be keyed by the requested purl");
    assert_eq!(pkg.name, "lodash");
    assert_eq!(pkg.version, "4.17.21");
    assert_eq!(pkg.namespace, None);
    assert_eq!(pkg.purl, "pkg:npm/lodash@4.17.21");
    assert_eq!(
        pkg.path,
        nm.join("lodash"),
        "path must point at the on-disk package dir"
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_scoped_package() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "@types/node", "20.0.0").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/@types/node@20.0.0".to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1, "exactly one match expected");
    let pkg = result
        .get("pkg:npm/@types/node@20.0.0")
        .expect("result must be keyed by the requested scoped purl");
    assert_eq!(pkg.name, "node");
    assert_eq!(pkg.version, "20.0.0");
    assert_eq!(pkg.namespace.as_deref(), Some("@types"));
    assert_eq!(pkg.purl, "pkg:npm/@types/node@20.0.0");
    assert_eq!(
        pkg.path,
        nm.join("@types").join("node"),
        "scoped path must include the @scope segment"
    );
}

#[tokio::test]
#[serial_test::parallel]
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

/// A qualified PURL (`pkg:npm/lodash@4.17.21?extension=tgz`) must resolve:
/// `parse_purl_components` strips the `?...` qualifier to locate the package
/// dir, and the entry is keyed by the *verbatim* input PURL (qualifier
/// included). The dispatcher looks results back up under the PURL it handed
/// in, so keying by a stripped/reconstructed PURL would silently drop every
/// qualified PURL.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_resolves_qualified_purl_keyed_by_input() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let qualified = "pkg:npm/lodash@4.17.21?extension=tgz".to_string();
    let result = crawler
        .find_by_purls(&nm, std::slice::from_ref(&qualified))
        .await
        .unwrap();

    // Resolved, keyed by the verbatim qualified input, and the stored
    // package carries that same verbatim PURL.
    assert_eq!(result.len(), 1, "qualified PURL must resolve");
    let pkg = result
        .get(&qualified)
        .expect("result must be keyed by the verbatim input PURL");
    assert_eq!(pkg.name, "lodash");
    assert_eq!(pkg.version, "4.17.21");
    assert_eq!(pkg.purl, qualified);
}

/// Regression: a qualifier value that itself contains an `@`
/// (`?vcs_url=git@github.com:...`) must NOT corrupt version parsing.
/// `parse_purl_components` strips the `?qualifier` *before* it calls
/// `rfind('@')` to split name from version. If those two steps were
/// reordered, `rfind('@')` would latch onto the `@` inside `git@github`
/// and parse a bogus version (`github.com:...`), so the package would
/// fail to match its on-disk `1.0.0` and silently drop out of
/// apply/rollback. The existing qualified-PURL tests only use
/// qualifiers WITHOUT an `@`, so they cannot catch a strip-order
/// regression — this pins it.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_qualifier_containing_at_does_not_corrupt_version() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "foo", "1.0.0").await;
    stage_npm_pkg(&nm, "@types/node", "20.0.0").await;

    let crawler = NpmCrawler;
    let unscoped_q = "pkg:npm/foo@1.0.0?vcs_url=git@github.com:x/y.git".to_string();
    let scoped_q = "pkg:npm/@types/node@20.0.0?maintainer=a@b.com".to_string();
    let result = crawler
        .find_by_purls(&nm, &[unscoped_q.clone(), scoped_q.clone()])
        .await
        .unwrap();

    assert_eq!(result.len(), 2, "both @-bearing qualifiers must resolve");
    let foo = result
        .get(&unscoped_q)
        .expect("@-in-qualifier unscoped PURL must resolve to foo@1.0.0");
    assert_eq!(foo.name, "foo");
    assert_eq!(foo.version, "1.0.0");
    assert_eq!(foo.purl, unscoped_q);

    let node = result
        .get(&scoped_q)
        .expect("@-in-qualifier scoped PURL must resolve to @types/node@20.0.0");
    assert_eq!(node.namespace.as_deref(), Some("@types"));
    assert_eq!(node.name, "node");
    assert_eq!(node.version, "20.0.0");
    assert_eq!(node.purl, scoped_q);
}

/// PURL with no `@` (no version separator) must be rejected via the
/// `rfind('@')?` arm (line 707).
#[tokio::test]
#[serial_test::parallel]
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
#[serial_test::parallel]
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
#[serial_test::parallel]
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
#[serial_test::parallel]
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
#[serial_test::parallel]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:not-npm/foo@1.0".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_discovers_unscoped_and_scoped() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;
    stage_npm_pkg(&nm, "@types/node", "20.0.0").await;

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    assert_eq!(
        result.len(),
        2,
        "exactly the two staged packages, no spurious entries; got {result:?}"
    );

    let lodash = result
        .iter()
        .find(|p| p.name == "lodash")
        .expect("lodash must be discovered");
    assert_eq!(lodash.version, "4.17.21");
    assert_eq!(lodash.namespace, None);
    assert_eq!(lodash.purl, "pkg:npm/lodash@4.17.21");

    let node = result
        .iter()
        .find(|p| p.name == "node")
        .expect("@types/node must be discovered");
    assert_eq!(node.version, "20.0.0");
    assert_eq!(node.namespace.as_deref(), Some("@types"));
    assert_eq!(
        node.purl, "pkg:npm/@types/node@20.0.0",
        "scoped purl must carry the namespace"
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_skips_dirs_without_package_json() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    tokio::fs::create_dir_all(nm.join("not_a_pkg"))
        .await
        .unwrap();
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
#[serial_test::parallel]
async fn crawl_all_recurses_into_workspace_packages() {
    let tmp = tempfile::tempdir().unwrap();
    // Root has no node_modules but a workspace subdir does.
    let pkg_dir = tmp.path().join("packages").join("ws-a");
    stage_npm_pkg(&pkg_dir.join("node_modules"), "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    let lodash = result
        .iter()
        .find(|p| p.name == "lodash")
        .unwrap_or_else(|| {
            panic!(
                "workspace recursion must discover nested node_modules; got {:?}",
                result.iter().map(|p| p.name.as_str()).collect::<Vec<_>>()
            )
        });
    assert_eq!(lodash.version, "4.17.21");
    assert_eq!(lodash.purl, "pkg:npm/lodash@4.17.21");
    assert_eq!(
        lodash.path,
        pkg_dir.join("node_modules").join("lodash"),
        "discovered path must be the nested workspace location"
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_skips_hidden_and_skip_dirs() {
    let tmp = tempfile::tempdir().unwrap();
    // Hidden dirs and SKIP_DIRS entries (dist/build/coverage/tmp/...) are skipped.
    stage_npm_pkg(
        &tmp.path().join(".hidden").join("node_modules"),
        "should-not-find",
        "1.0",
    )
    .await;
    stage_npm_pkg(
        &tmp.path().join("dist").join("node_modules"),
        "also-not",
        "1.0",
    )
    .await;
    // But a real workspace dir should be picked up.
    stage_npm_pkg(
        &tmp.path().join("real-ws").join("node_modules"),
        "found-me",
        "1.0",
    )
    .await;

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"found-me"));
    assert!(
        !names.contains(&"should-not-find"),
        "hidden dir must be skipped"
    );
    assert!(
        !names.contains(&"also-not"),
        "SKIP_DIRS dir must be skipped"
    );
    // Exactly the one real workspace package — proves the skips are not
    // merely absent-by-accident alongside unexpected extras.
    assert_eq!(
        result.len(),
        1,
        "only the real workspace package survives the skip rules; got {names:?}"
    );
}

#[path = "common/mod.rs"]
mod common;

/// `scan_node_modules` short-circuits when read_dir returns Err.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
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

    assert!(
        result.is_empty(),
        "unreadable node_modules must yield empty"
    );
}

/// `find_workspace_node_modules` short-circuits cleanly when it
/// encounters an unreadable workspace subdir — drives the read_dir
/// Err arm at npm_crawler.rs:440-441 by chmod 000-ing one workspace
/// while leaving a readable one alongside.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_handles_unreadable_workspace_dir() {
    if common::uid_is_root() {
        eprintln!("SKIP: chmod 000 is a no-op under root");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // Readable workspace.
    stage_npm_pkg(
        &tmp.path().join("readable").join("node_modules"),
        "ok",
        "1.0.0",
    )
    .await;
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
    assert!(
        !names.contains(&"hidden"),
        "unreadable workspace must be skipped"
    );
}

/// Drives scoped-package scanning + nested node_modules recursion +
/// the hidden-and-file-entries skip arms inside `scan_scoped_packages`
/// and `scan_nested_node_modules`. Covers L552, 581-604, 619-665.
#[tokio::test]
#[serial_test::parallel]
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
    tokio::fs::create_dir_all(nm.join("@scope").join(".hidden"))
        .await
        .unwrap();
    // A plain file inside @scope — must be skipped via the !is_dir &&
    // !is_symlink arm (L590-591).
    tokio::fs::write(nm.join("@scope").join("README.md"), b"x")
        .await
        .unwrap();
    // A plain file at top of node_modules too — exercises the same arm
    // in scan_node_modules.
    tokio::fs::write(nm.join("top-level-file.txt"), b"y")
        .await
        .unwrap();

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

    // Assert each expected package is present AT its staged version — a
    // regression that mis-mapped a dir to the wrong metadata, or that
    // surfaced the hidden/file entries as packages, would change this set.
    let ver = |n: &str| -> Option<&str> {
        result
            .iter()
            .find(|p| p.name == n)
            .map(|p| p.version.as_str())
    };
    assert_eq!(ver("outer"), Some("1.0.0"));
    assert_eq!(ver("inner"), Some("2.0.0"));
    assert_eq!(ver("scoped-pkg"), Some("3.0.0"));
    assert_eq!(ver("scoped-dep"), Some("4.0.0"));
    assert_eq!(ver("leaf"), Some("5.0.0"));

    // The scoped entries must retain their namespaces in the purl.
    let scoped = result.iter().find(|p| p.name == "scoped-pkg").unwrap();
    assert_eq!(scoped.namespace.as_deref(), Some("@scope"));
    assert_eq!(scoped.purl, "pkg:npm/@scope/scoped-pkg@3.0.0");
    let leaf = result.iter().find(|p| p.name == "leaf").unwrap();
    assert_eq!(leaf.namespace.as_deref(), Some("@nest"));
    assert_eq!(leaf.purl, "pkg:npm/@nest/leaf@5.0.0");

    // The hidden dir, README.md, and top-level-file.txt must NOT appear
    // as packages: exactly the five real packages, nothing else.
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        result.len(),
        5,
        "only the five real packages, no hidden/file entries; got {names:?}"
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_discovers_deeply_nested_transitive_deps() {
    // The npm crawler recurses `node_modules` at UNBOUNDED depth, so a patch
    // targeting a deeply-nested *transitive* dependency is discovered — and thus
    // patchable — exactly like a direct dependency (apply is path-agnostic). The
    // other nested tests stage only 2 levels; this pins 4, so a regression that
    // capped recursion depth (or stopped descending after the first nested
    // node_modules) would surface here. See CLI_CONTRACT "Setup command contract"
    // → "Monorepo / multi-project discovery model".
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");

    // a → b → c → d, each staged in the previous package's own node_modules.
    let a_nm = nm.join("a").join("node_modules");
    let b_nm = a_nm.join("b").join("node_modules");
    let c_nm = b_nm.join("c").join("node_modules");
    stage_npm_pkg(&nm, "a", "1.0.0").await;
    stage_npm_pkg(&a_nm, "b", "2.0.0").await;
    stage_npm_pkg(&b_nm, "c", "3.0.0").await;
    stage_npm_pkg(&c_nm, "d", "4.0.0").await;

    let crawler = NpmCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;

    let ver = |n: &str| -> Option<&str> {
        result
            .iter()
            .find(|p| p.name == n)
            .map(|p| p.version.as_str())
    };
    assert_eq!(ver("a"), Some("1.0.0"), "direct dep at depth 1");
    assert_eq!(ver("b"), Some("2.0.0"), "transitive at depth 2");
    assert_eq!(ver("c"), Some("3.0.0"), "transitive at depth 3");
    assert_eq!(
        ver("d"),
        Some("4.0.0"),
        "the depth-4 transitive dep must still be discovered (unbounded recursion)"
    );
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        result.len(),
        4,
        "exactly the four chained packages; got {names:?}"
    );
}

#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_skips_dirs_with_corrupt_package_json() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let bad = nm.join("broken");
    tokio::fs::create_dir_all(&bad).await.unwrap();
    tokio::fs::write(bad.join("package.json"), b"{ corrupt")
        .await
        .unwrap();

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty());
}

/// Regression: a symlinked package inside a nested `node_modules` (the
/// shape pnpm and `npm link` produce — top-level entries are symlinks
/// into a content-addressed store) must itself be recorded, but the
/// crawler must NOT recurse *through* the symlink into the store. Doing
/// so would surface store-internal packages that aren't part of the
/// project's dependency tree and could escape the project root
/// entirely. `scan_nested_node_modules` guards its deeper recursion with
/// `if file_type.is_dir()`, matching its sibling scanners; this pins
/// that behavior.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_does_not_recurse_through_symlinked_nested_package() {
    use std::os::unix::fs::symlink;

    // The "store" lives OUTSIDE the crawled cwd, so the only route to it
    // is through the symlink — not via workspace discovery.
    let store = tempfile::tempdir().unwrap();
    let linked_pkg = store.path().join("linked-pkg");
    stage_npm_pkg(store.path(), "linked-pkg", "2.0.0").await;
    // The store package has its own nested node_modules with a package
    // that must only be reachable by following the symlink.
    stage_npm_pkg(&linked_pkg.join("node_modules"), "buried", "3.0.0").await;

    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    // A real host package with a real nested node_modules...
    stage_npm_pkg(&nm, "host", "1.0.0").await;
    let host_nm = nm.join("host").join("node_modules");
    tokio::fs::create_dir_all(&host_nm).await.unwrap();
    // ...containing a SYMLINK to the out-of-tree store package.
    symlink(&linked_pkg, host_nm.join("linked-pkg")).unwrap();

    let crawler = NpmCrawler;
    let opts = options_at(tmp.path());
    let result = crawler.crawl_all(&opts).await;
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();

    assert!(names.contains(&"host"), "real host package must be found");
    assert!(
        names.contains(&"linked-pkg"),
        "the symlinked package itself must still be recorded"
    );
    assert!(
        !names.contains(&"buried"),
        "crawler must not recurse through the symlink into the store"
    );
}

// ── regression pins: metadata identity + nested lookup ─────────

/// Regression: npm (and Node's own loader) strip a leading UTF-8 BOM from
/// `package.json`, so a published package may legitimately ship one
/// (Windows-authored packages do). `serde_json::from_str` rejects the BOM,
/// which made the crawler silently skip the package — a vulnerable install
/// invisible to `scan` and unpatchable by `apply`. Same class as the
/// `strip_bom` fixes in `package_json/detect.rs`.
#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_tolerates_utf8_bom() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let pkg_dir = nm.join("bommed");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join("package.json"),
        "\u{feff}{\"name\":\"bommed\",\"version\":\"1.0.0\"}",
    )
    .await
    .unwrap();

    let result = read_package_json(&pkg_dir.join("package.json")).await;
    assert_eq!(
        result,
        Some(("bommed".to_string(), "1.0.0".to_string())),
        "a BOM'd package.json is npm-valid and must parse"
    );

    // The production symptom: the package must be visible to scan…
    let crawler = NpmCrawler;
    let crawled = crawler.crawl_all(&options_at(tmp.path())).await;
    assert_eq!(
        crawled.len(),
        1,
        "BOM'd package must be discovered by crawl_all; got {crawled:?}"
    );

    // …and resolvable by apply's lookup.
    let found = crawler
        .find_by_purls(&nm, &["pkg:npm/bommed@1.0.0".to_string()])
        .await
        .unwrap();
    assert!(
        found.contains_key("pkg:npm/bommed@1.0.0"),
        "BOM'd package must resolve in find_by_purls; got {found:?}"
    );
}

/// Regression: `find_by_purls` verified only the *version* of the
/// `package.json` it probed, never the *name*. An npm alias install
/// (`npm i foo@npm:bar@1.0.0`) puts package `bar` in `node_modules/foo`;
/// a patch for `foo@1.0.0` would then be "resolved" to bar's directory and
/// applied to a completely different package's files (with the default
/// mismatch policy applying the full patched blob of `foo` over `bar`).
/// The probe must require the on-disk name to match the PURL identity.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_rejects_alias_dir_with_matching_version() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");

    // `npm i foo@npm:bar@1.0.0` layout: dir name ≠ package.json name.
    let alias_dir = nm.join("foo");
    tokio::fs::create_dir_all(&alias_dir).await.unwrap();
    tokio::fs::write(
        alias_dir.join("package.json"),
        r#"{"name":"bar","version":"1.0.0"}"#,
    )
    .await
    .unwrap();

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/foo@1.0.0".to_string()])
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "an aliased dir holding a different package must not be identified \
         as the PURL target; got {result:?}"
    );

    // Scoped twin: @s/x aliasing some other package.
    let scoped_alias = nm.join("@s").join("x");
    tokio::fs::create_dir_all(&scoped_alias).await.unwrap();
    tokio::fs::write(
        scoped_alias.join("package.json"),
        r#"{"name":"@other/pkg","version":"2.0.0"}"#,
    )
    .await
    .unwrap();
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/@s/x@2.0.0".to_string()])
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "scoped alias must not be misidentified; got {result:?}"
    );
}

/// Regression: CLI_CONTRACT promises "deeply nested transitive dependencies
/// are fully supported … `apply` is path-agnostic … patched identically to a
/// direct one", and `crawl_all` (scan) discovers them at unbounded depth —
/// but `find_by_purls` (apply's resolver) probed only the tree root, so a
/// version that exists *only* nested (root holds a different major, the
/// classic hoisting-conflict layout) was scannable yet unpatchable: apply
/// reported "No packages found that match available patches".
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_resolves_nested_only_install() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");

    // Root: a@1.0.0 and the shadowing b@3.0.0. The patched b@2.0.0 lives
    // only at a/node_modules/b (npm's layout when siblings conflict).
    stage_npm_pkg(&nm, "a", "1.0.0").await;
    stage_npm_pkg(&nm, "b", "3.0.0").await;
    let a_nm = nm.join("a").join("node_modules");
    stage_npm_pkg(&a_nm, "b", "2.0.0").await;
    // Depth 3: a → b → c.
    let b_nm = a_nm.join("b").join("node_modules");
    stage_npm_pkg(&b_nm, "c", "5.0.0").await;
    // Nested scoped package.
    stage_npm_pkg(&a_nm, "@s/d", "1.0.0").await;

    let crawler = NpmCrawler;
    let purls = vec![
        "pkg:npm/b@2.0.0".to_string(),
        "pkg:npm/c@5.0.0".to_string(),
        "pkg:npm/@s/d@1.0.0".to_string(),
    ];
    let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

    let b = result
        .get("pkg:npm/b@2.0.0")
        .expect("nested-only b@2.0.0 must resolve (root b@3.0.0 shadows it)");
    assert_eq!(b.path, a_nm.join("b"), "must point at the nested copy");
    let c = result
        .get("pkg:npm/c@5.0.0")
        .expect("depth-3 transitive c@5.0.0 must resolve");
    assert_eq!(c.path, b_nm.join("c"));
    let d = result
        .get("pkg:npm/@s/d@1.0.0")
        .expect("nested scoped @s/d@1.0.0 must resolve");
    assert_eq!(d.path, a_nm.join("@s").join("d"));
}

/// Regression: a FIFO planted at a `package.json` path must be skipped
/// promptly, never opened blockingly. `tokio::fs::read_to_string` performs a
/// plain `open(2)`, which on a FIFO waits for a writer that never comes — so
/// one special file inside `node_modules` (a malicious package's postinstall
/// can create one; npm itself never extracts FIFOs) wedged `scan`
/// (crawl_all) and `apply` (find_by_purls) indefinitely, with no error and
/// no timeout. Same class as the `open_regular_file` guards in
/// `patch/file_hash.rs`, the cargo sidecar, and the vendor harvest/verify
/// readers.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn read_package_json_rejects_fifo_without_hanging() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let fifo_pkg = nm.join("fifo-pkg");
    tokio::fs::create_dir_all(&fifo_pkg).await.unwrap();
    let fifo = fifo_pkg.join("package.json");
    // mkfifo(2) directly, not the /usr/bin/mkfifo binary: spawning a child
    // here made the test flake under heavy parallel load (fork/exec
    // starvation panicked the fixture setup before the code under test
    // ever ran), and the syscall needs no process at all.
    let c_path = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no NUL")
    };
    let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
    assert_eq!(
        rc,
        0,
        "mkfifo(2) failed: {}",
        std::io::Error::last_os_error()
    );
    // A sibling real package proves the tree stays crawlable around the FIFO.
    stage_npm_pkg(&nm, "real-pkg", "1.0.0").await;

    // On timeout the open is wedged in a `spawn_blocking` thread that the
    // runtime waits for on shutdown; connect a writer to release it so the
    // test can FAIL instead of hanging the whole suite.
    let release_and_panic = |what: &str| -> ! {
        let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
        panic!("{what} must complete promptly with a FIFO package.json in the tree");
    };
    let deadline = std::time::Duration::from_secs(5);

    let Ok(direct) = tokio::time::timeout(deadline, read_package_json(&fifo)).await else {
        release_and_panic("read_package_json");
    };
    assert_eq!(direct, None, "a FIFO is not a valid package.json");

    let crawler = NpmCrawler;
    let Ok(crawled) =
        tokio::time::timeout(deadline, crawler.crawl_all(&options_at(tmp.path()))).await
    else {
        release_and_panic("crawl_all (scan)");
    };
    let names: Vec<&str> = crawled.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["real-pkg"],
        "the sibling real package must still be discovered, the FIFO skipped"
    );

    let Ok(found) = tokio::time::timeout(
        deadline,
        crawler.find_by_purls(&nm, &["pkg:npm/fifo-pkg@1.0.0".to_string()]),
    )
    .await
    else {
        release_and_panic("find_by_purls (apply's resolver)");
    };
    assert!(
        found.unwrap().is_empty(),
        "the FIFO-backed purl must resolve to nothing"
    );
}

// ── pnpm isolated-linker virtual store (.pnpm) ─────────────────

/// Hand-build the tree `pnpm install` (isolated linker) produces for a
/// project depending on mkdirp@0.5.5 (whose dep is minimist), plus a second
/// minimist version and a scoped transitive package:
///
/// ```text
/// node_modules/
///   mkdirp -> .pnpm/mkdirp@0.5.5/node_modules/mkdirp   (direct dep)
///   .pnpm/
///     mkdirp@0.5.5/node_modules/
///       mkdirp/                                        (real dir)
///       minimist -> ../../minimist@1.2.8/node_modules/minimist
///     minimist@1.2.8/node_modules/minimist/            (real dir)
///     minimist@0.0.8/node_modules/minimist/            (real dir)
///     @scope+leaf@2.0.0/node_modules/@scope/leaf/      (real dir)
///     node_modules/                                    (internal hoist dir)
///     .hidden-meta@1.0.0/…                             (store metadata)
/// ```
///
/// minimist (both versions) and @scope/leaf are *transitive-only*: their
/// sole physical home is the hidden `.pnpm` virtual store, with no
/// importer-root entry at all — yet they are runtime-loaded. Decoy packages
/// are planted where the traversal must NOT look (the internal hoist dir,
/// a hidden store child) so a policy regression turns the tests red.
#[cfg(unix)]
async fn stage_pnpm_isolated_tree(root: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::symlink;

    let nm = root.join("node_modules");
    let store = nm.join(".pnpm");

    stage_npm_pkg(
        &store.join("mkdirp@0.5.5").join("node_modules"),
        "mkdirp",
        "0.5.5",
    )
    .await;
    stage_npm_pkg(
        &store.join("minimist@1.2.8").join("node_modules"),
        "minimist",
        "1.2.8",
    )
    .await;
    stage_npm_pkg(
        &store.join("minimist@0.0.8").join("node_modules"),
        "minimist",
        "0.0.8",
    )
    .await;
    stage_npm_pkg(
        &store.join("@scope+leaf@2.0.0").join("node_modules"),
        "@scope/leaf",
        "2.0.0",
    )
    .await;

    // mkdirp's dependency: a sibling symlink inside its own store entry.
    symlink(
        store.join("minimist@1.2.8/node_modules/minimist"),
        store.join("mkdirp@0.5.5/node_modules/minimist"),
    )
    .unwrap();

    // Importer root: the direct dep is a symlink into the store.
    symlink(
        store.join("mkdirp@0.5.5/node_modules/mkdirp"),
        nm.join("mkdirp"),
    )
    .unwrap();

    // pnpm's internal hoist dir `.pnpm/node_modules`: symlinks into sibling
    // entries. A REAL decoy package is planted where the traversal would
    // land if the hoist-dir skip were dropped.
    let hoist = store.join("node_modules");
    tokio::fs::create_dir_all(&hoist).await.unwrap();
    symlink(
        store.join("minimist@1.2.8/node_modules/minimist"),
        hoist.join("minimist"),
    )
    .unwrap();
    stage_npm_pkg(&hoist.join("node_modules"), "hoist-decoy", "9.9.9").await;

    // Hidden store child (metadata): must never be probed.
    stage_npm_pkg(
        &store.join(".hidden-meta@1.0.0").join("node_modules"),
        "hidden-decoy",
        "9.9.9",
    )
    .await;
    // A plain file at the store top level (pnpm writes lock.yaml here).
    tokio::fs::write(store.join("lock.yaml"), b"lockfileVersion: 9\n")
        .await
        .unwrap();

    nm
}

/// Regression (pnpm 7–12, empirically confirmed): a transitive-only
/// dependency living solely at `.pnpm/<x>/node_modules/<name>` was invisible
/// to `find_by_purls` — apply reported `package_not_installed` for a package
/// that is installed and runtime-loaded. The virtual store must be probed;
/// the name@version match keeps two store versions of one package distinct;
/// the root-linked direct dep must still resolve at its importer-root path
/// (BFS root-first); and the hoist-dir/hidden decoys must stay unreachable.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_resolves_pnpm_virtual_store_transitives() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = stage_pnpm_isolated_tree(tmp.path()).await;
    let store = nm.join(".pnpm");

    let crawler = NpmCrawler;
    let purls = vec![
        "pkg:npm/mkdirp@0.5.5".to_string(),
        "pkg:npm/minimist@1.2.8".to_string(),
        "pkg:npm/minimist@0.0.8".to_string(),
        "pkg:npm/@scope/leaf@2.0.0".to_string(),
        "pkg:npm/hoist-decoy@9.9.9".to_string(),
        "pkg:npm/hidden-decoy@9.9.9".to_string(),
    ];
    let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

    // The direct dep resolves at the importer root (probed before any
    // .pnpm entry is dequeued), not at its store home.
    let mkdirp = result
        .get("pkg:npm/mkdirp@0.5.5")
        .expect("root-linked direct dep must resolve");
    assert_eq!(
        mkdirp.path,
        nm.join("mkdirp"),
        "root-linked install must win over the store copy"
    );

    // Transitive-only: reachable only via the virtual store. It may be
    // found through mkdirp's sibling symlink or its own store entry —
    // both name the same physical package.
    let m1 = result
        .get("pkg:npm/minimist@1.2.8")
        .expect("transitive-only minimist@1.2.8 must resolve via .pnpm");
    assert_eq!(
        std::fs::canonicalize(&m1.path).unwrap(),
        std::fs::canonicalize(store.join("minimist@1.2.8/node_modules/minimist")).unwrap(),
        "resolved path must be the store's physical minimist@1.2.8"
    );

    // Second store version of the same package stays distinct.
    let m0 = result
        .get("pkg:npm/minimist@0.0.8")
        .expect("second store version must resolve independently");
    assert_eq!(
        m0.path,
        store.join("minimist@0.0.8/node_modules/minimist"),
        "version match must bind each purl to its own store entry"
    );

    // Scoped transitive-only package.
    let leaf = result
        .get("pkg:npm/@scope/leaf@2.0.0")
        .expect("scoped transitive-only package must resolve via .pnpm");
    assert_eq!(
        leaf.path,
        store.join("@scope+leaf@2.0.0/node_modules/@scope/leaf")
    );

    // The hoist dir and hidden store children are never probed.
    assert!(
        !result.contains_key("pkg:npm/hoist-decoy@9.9.9"),
        "`.pnpm/node_modules` (internal hoist dir) must not be probed"
    );
    assert!(
        !result.contains_key("pkg:npm/hidden-decoy@9.9.9"),
        "hidden store children must not be probed"
    );
    assert_eq!(result.len(), 4, "exactly the four real packages resolve");
}

/// Scan twin of the resolver regression: `crawl_all` skipped `.pnpm` as
/// just-another-hidden-dir, so a transitive-only install never reached the
/// batch API request. Each package must be inventoried exactly once (the
/// root pass wins the `seen` dedup for the root-linked direct dep; store
/// entries are accepted only as real dirs so a sibling symlink cannot
/// double-count), both store versions surface, and the decoys stay out.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_inventories_pnpm_virtual_store_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = stage_pnpm_isolated_tree(tmp.path()).await;
    let store = nm.join(".pnpm");

    let crawler = NpmCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;

    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(
        result.len(),
        4,
        "exactly the four real packages, each once — no symlink double-hits, \
         no hoist/hidden decoys; got {purls:?}"
    );

    let by_purl = |purl: &str| -> &socket_patch_core::crawlers::types::CrawledPackage {
        result
            .iter()
            .find(|p| p.purl == purl)
            .unwrap_or_else(|| panic!("{purl} must be inventoried; got {purls:?}"))
    };

    // Root-linked direct dep is recorded at its importer-root path (the
    // root pass runs before the deferred store pass).
    assert_eq!(by_purl("pkg:npm/mkdirp@0.5.5").path, nm.join("mkdirp"));
    // Transitive-only packages are recorded at their physical store homes.
    assert_eq!(
        by_purl("pkg:npm/minimist@1.2.8").path,
        store.join("minimist@1.2.8/node_modules/minimist"),
        "store entry must be recorded at its real dir, not a sibling symlink"
    );
    assert_eq!(
        by_purl("pkg:npm/minimist@0.0.8").path,
        store.join("minimist@0.0.8/node_modules/minimist")
    );
    let leaf = by_purl("pkg:npm/@scope/leaf@2.0.0");
    assert_eq!(leaf.namespace.as_deref(), Some("@scope"));
    assert_eq!(
        leaf.path,
        store.join("@scope+leaf@2.0.0/node_modules/@scope/leaf")
    );
}

/// Perf/scope pin: with a pending target, `find_by_purls` enqueues only
/// `.pnpm` store entries whose dir name decodes to a PENDING package name
/// (a manifest routinely lists packages that simply aren't installed, and
/// probing a large monorepo store for them would be a readdir+stat storm
/// on every apply/rollback). Observable via a decoy: a store entry whose
/// *inner* package matches the requested name@version, but whose entry
/// name decodes to a different package, must never be probed — the result
/// set is unchanged by its presence.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_skips_pnpm_store_entry_decoding_to_non_pending_name() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".pnpm");

    // Entry advertises `decoy@1.0.0`, but its node_modules holds a package
    // that would match the pending target `wanted@1.0.0` if probed.
    stage_npm_pkg(
        &store.join("decoy@1.0.0").join("node_modules"),
        "wanted",
        "1.0.0",
    )
    .await;
    // Scoped twin.
    stage_npm_pkg(
        &store.join("@other+decoy@1.0.0").join("node_modules"),
        "@s/wanted",
        "1.0.0",
    )
    .await;

    let crawler = NpmCrawler;
    let purls = vec![
        "pkg:npm/wanted@1.0.0".to_string(),
        "pkg:npm/@s/wanted@1.0.0".to_string(),
    ];
    let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

    assert!(
        result.is_empty(),
        "store entries decoding to non-pending names must not be probed; \
         got {result:?}"
    );
}

/// The name filter's positive half: an entry whose (peer-suffixed) dir
/// name decodes to a pending target's name IS enqueued and its package
/// resolves. Uses a pnpm-9 paren peer suffix so the decode path — not a
/// literal string match — is what admits the entry.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_resolves_pnpm_store_entry_with_peer_suffix() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".pnpm");

    let entry_nm = store.join("wanted@1.0.0(peer@2.0.0)").join("node_modules");
    stage_npm_pkg(&entry_nm, "wanted", "1.0.0").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/wanted@1.0.0".to_string()])
        .await
        .unwrap();

    let pkg = result
        .get("pkg:npm/wanted@1.0.0")
        .expect("peer-suffixed store entry for a pending name must be probed");
    assert_eq!(pkg.path, entry_nm.join("wanted"));
}

/// The conservative fallback: pnpm truncates over-long dir names (the cut
/// can land anywhere) and appends `_<hash>`, so such an entry's identity
/// is unknowable from its name — it must STAY probeable, and a pending
/// target living inside it must resolve.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_probes_undecodable_pnpm_store_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".pnpm");

    // No `@X.Y.Z` tail survives the `_<hash>` strip → undecodable.
    let entry_nm = store
        .join("wanted-with-a-very-long-truncated_abc123def456")
        .join("node_modules");
    stage_npm_pkg(&entry_nm, "wanted2", "1.0.0").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/wanted2@1.0.0".to_string()])
        .await
        .unwrap();

    let pkg = result
        .get("pkg:npm/wanted2@1.0.0")
        .expect("undecodable (truncated/hash-suffixed) store entries must remain probeable");
    assert_eq!(pkg.path, entry_nm.join("wanted2"));
}

/// The store pass skips re-reading a root-linked direct dep's own
/// package.json (its decoded name@version already won the `seen` dedup at
/// the importer root), but must still walk INTO the entry: bundled
/// dependencies are real dirs nested inside the package itself, physically
/// present only there.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_inventories_bundled_dep_under_seen_store_entry() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let store = nm.join(".pnpm");

    let host_store_nm = store.join("host@1.0.0").join("node_modules");
    stage_npm_pkg(&host_store_nm, "host", "1.0.0").await;
    // Bundled dep: a REAL dir inside the package's own node_modules.
    stage_npm_pkg(
        &host_store_nm.join("host").join("node_modules"),
        "bundled",
        "3.3.3",
    )
    .await;
    // Root-linked direct dep (importer pass inventories it first).
    symlink(host_store_nm.join("host"), nm.join("host")).unwrap();

    let crawler = NpmCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;

    let host = result
        .iter()
        .find(|p| p.name == "host")
        .expect("root-linked host must be inventoried");
    assert_eq!(
        host.path,
        nm.join("host"),
        "importer-root path wins the seen dedup"
    );
    let bundled = result
        .iter()
        .find(|p| p.name == "bundled")
        .expect("bundled dep must be inventoried via the store walk even when its host's identity is already seen");
    assert_eq!(
        bundled.path,
        host_store_nm
            .join("host")
            .join("node_modules")
            .join("bundled")
    );
    let names: Vec<&str> = result.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(result.len(), 2, "exactly host + bundled; got {names:?}");
}

/// When the same `name@version` exists at the root *and* nested, the root
/// copy must win (shallowest-first), preserving the pre-existing behavior
/// for everything resolvable at the root.
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_prefers_root_copy_over_nested_duplicate() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "a", "1.0.0").await;
    stage_npm_pkg(&nm, "dup", "1.0.0").await;
    stage_npm_pkg(&nm.join("a").join("node_modules"), "dup", "1.0.0").await;

    let crawler = NpmCrawler;
    let result = crawler
        .find_by_purls(&nm, &["pkg:npm/dup@1.0.0".to_string()])
        .await
        .unwrap();
    assert_eq!(
        result.get("pkg:npm/dup@1.0.0").map(|p| p.path.clone()),
        Some(nm.join("dup")),
        "root copy must be preferred over the nested duplicate"
    );
}

// ── pnpm 4/5 NESTED virtual store (.pnpm/<registry-host>/…) ────

/// Byte-accurate replica of a captured real `pnpm@4.14.4` install
/// (layoutVersion 3, and the same shape synthetic pnpm-5 trees showed):
/// store entries are nested by registry host —
/// `.pnpm/registry.npmjs.org/<name>/<version>/node_modules/<name>` — so
/// the `.pnpm` child (`registry.npmjs.org`) has NO `node_modules` of its
/// own and the flat-entry walk finds nothing behind it:
///
/// ```text
/// node_modules/
///   mkdirp -> .pnpm/registry.npmjs.org/mkdirp/0.5.5/node_modules/mkdirp
///   .pnpm/
///     lock.yaml
///     node_modules/minimist -> …            (internal hoist dir)
///     registry.npmjs.org/
///       mkdirp/0.5.5/node_modules/
///         mkdirp/                            (real dir)
///         minimist -> ../../../minimist/1.2.8/node_modules/minimist
///       minimist/1.2.8/node_modules/minimist/   (real dir, TRANSITIVE-ONLY)
///       @scope/leaf/2.0.0/node_modules/@scope/leaf/  (real, transitive-only)
///       decoy/1.0.0/node_modules/wanted/     (advertises decoy, holds wanted)
///       loop -> ../..                        (symlink cycle bait)
/// ```
#[cfg(unix)]
async fn stage_pnpm4_nested_tree(root: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::symlink;

    let nm = root.join("node_modules");
    let store = nm.join(".pnpm");
    let host = store.join("registry.npmjs.org");

    stage_npm_pkg(&host.join("mkdirp/0.5.5/node_modules"), "mkdirp", "0.5.5").await;
    stage_npm_pkg(
        &host.join("minimist/1.2.8/node_modules"),
        "minimist",
        "1.2.8",
    )
    .await;
    // Scoped transitive-only package: one nesting level deeper
    // (host/@scope/name/version), the deepest shape the layout produces.
    stage_npm_pkg(
        &host.join("@scope/leaf/2.0.0/node_modules"),
        "@scope/leaf",
        "2.0.0",
    )
    .await;

    // mkdirp's dependency: a sibling symlink inside its own store entry
    // (relative, exactly as captured).
    symlink(
        Path::new("../../../minimist/1.2.8/node_modules/minimist"),
        host.join("mkdirp/0.5.5/node_modules/minimist"),
    )
    .unwrap();

    // Importer root: the direct dep is a symlink into the nested store.
    symlink(
        Path::new(".pnpm/registry.npmjs.org/mkdirp/0.5.5/node_modules/mkdirp"),
        nm.join("mkdirp"),
    )
    .unwrap();

    // pnpm 4's internal hoist dir `.pnpm/node_modules` (captured: symlinks
    // into the nested entries), plus a REAL decoy planted where the walk
    // would land if the hoist-dir skip were dropped.
    let hoist = store.join("node_modules");
    tokio::fs::create_dir_all(&hoist).await.unwrap();
    symlink(
        host.join("minimist/1.2.8/node_modules/minimist"),
        hoist.join("minimist"),
    )
    .unwrap();
    stage_npm_pkg(&hoist.join("node_modules"), "hoist-decoy", "9.9.9").await;

    // Store metadata file at the top level (pnpm 4 writes lock.yaml).
    tokio::fs::write(store.join("lock.yaml"), b"lockfileVersion: 5.1\n")
        .await
        .unwrap();

    // Decoy: a nested entry advertising `decoy/1.0.0` whose INNER package
    // is `wanted@1.0.0`. The resolver's pending-name filter must keep it
    // unprobed (the entry name is the advertisement, exactly like a flat
    // `decoy@1.0.0` entry).
    stage_npm_pkg(&host.join("decoy/1.0.0/node_modules"), "wanted", "1.0.0").await;

    // Symlink cycle inside the nested store: a link back up the tree. The
    // descent must never traverse symlinks — following this one would
    // recurse forever, so the tests *terminating* is itself the guard.
    symlink(Path::new("../.."), host.join("loop")).unwrap();

    nm
}

/// Regression (empirically confirmed on a real pnpm 4.14.4 tree, same on
/// synthetic pnpm-5): the `.pnpm` walk handled FLAT `name@version` entries
/// only. The nested `registry.npmjs.org` child has no `node_modules`, the
/// conservative fallback enqueued exactly `.pnpm/<entry>/node_modules`
/// (one level), so a transitive-only dep was silently skipped — apply
/// exited 0 claiming success while the file was never written. The nested
/// descent must find it; the pending-name filter must still hold (decoy);
/// the cycle symlink must not hang the walk.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_resolves_pnpm4_nested_store_transitives() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = stage_pnpm4_nested_tree(tmp.path()).await;
    let host = nm.join(".pnpm/registry.npmjs.org");

    let crawler = NpmCrawler;
    let purls = vec![
        "pkg:npm/mkdirp@0.5.5".to_string(),
        "pkg:npm/minimist@1.2.8".to_string(),
        "pkg:npm/@scope/leaf@2.0.0".to_string(),
        "pkg:npm/wanted@1.0.0".to_string(),
        "pkg:npm/hoist-decoy@9.9.9".to_string(),
    ];
    let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

    // Root-linked direct dep still wins at the importer root.
    assert_eq!(
        result.get("pkg:npm/mkdirp@0.5.5").map(|p| p.path.clone()),
        Some(nm.join("mkdirp")),
        "root-linked install must win over the store copy"
    );
    // Transitive-only dep: physically present ONLY in the nested store.
    let minimist = result
        .get("pkg:npm/minimist@1.2.8")
        .expect("transitive-only dep must resolve through the nested (pnpm 4/5) store layout");
    assert_eq!(
        minimist.path,
        host.join("minimist/1.2.8/node_modules/minimist")
    );
    // Scoped transitive-only dep: the deepest nesting the layout produces.
    let leaf = result
        .get("pkg:npm/@scope/leaf@2.0.0")
        .expect("scoped transitive-only dep must resolve through the nested store layout");
    assert_eq!(
        leaf.path,
        host.join("@scope/leaf/2.0.0/node_modules/@scope/leaf")
    );
    // The nested entry advertising a non-pending name is never probed, and
    // the hoist dir stays unreachable.
    assert!(
        !result.contains_key("pkg:npm/wanted@1.0.0"),
        "nested store entries advertising non-pending names must not be probed"
    );
    assert!(
        !result.contains_key("pkg:npm/hoist-decoy@9.9.9"),
        "`.pnpm/node_modules` (internal hoist dir) must not be probed"
    );
    assert_eq!(result.len(), 3);
}

/// Scan twin: `crawl_all` must inventory the nested-store packages exactly
/// once each. (`wanted` IS inventoried here — scan has no pending filter
/// and the package is genuinely installed; only the resolver's name filter
/// treats the advertising entry name as authoritative.)
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_inventories_pnpm4_nested_store_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = stage_pnpm4_nested_tree(tmp.path()).await;
    let host = nm.join(".pnpm/registry.npmjs.org");

    let crawler = NpmCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;

    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(
        result.len(),
        4,
        "mkdirp + minimist + @scope/leaf + wanted, each exactly once — no \
         symlink double-hits, no hoist decoy; got {purls:?}"
    );
    let by_purl = |purl: &str| -> &socket_patch_core::crawlers::types::CrawledPackage {
        result
            .iter()
            .find(|p| p.purl == purl)
            .unwrap_or_else(|| panic!("{purl} must be inventoried; got {purls:?}"))
    };
    // Root pass wins the seen dedup for the root-linked direct dep.
    assert_eq!(by_purl("pkg:npm/mkdirp@0.5.5").path, nm.join("mkdirp"));
    // Transitive-only packages surface at their physical store homes.
    assert_eq!(
        by_purl("pkg:npm/minimist@1.2.8").path,
        host.join("minimist/1.2.8/node_modules/minimist")
    );
    assert_eq!(
        by_purl("pkg:npm/@scope/leaf@2.0.0").path,
        host.join("@scope/leaf/2.0.0/node_modules/@scope/leaf")
    );
    assert_eq!(
        by_purl("pkg:npm/wanted@1.0.0").path,
        host.join("decoy/1.0.0/node_modules/wanted")
    );
    assert!(
        !purls.contains(&"pkg:npm/hoist-decoy@9.9.9"),
        "the internal hoist dir must not be scanned"
    );
}

// ── pnpm <=3 virtual store (node_modules/.registry.npmjs.org) ──

/// Byte-accurate replica of a captured real `pnpm@3.8.1` install
/// (layoutVersion 2 — pnpm 1.x and 2.x produce the identical shape): the
/// virtual store is a hidden `.registry.npmjs.org` dir directly under
/// `node_modules`, with NO `.pnpm` anywhere:
///
/// ```text
/// node_modules/
///   .modules.yaml, .pnpm-lock.yaml           (metadata FILES)
///   mkdirp -> .registry.npmjs.org/mkdirp/0.5.5/node_modules/mkdirp
///   .registry.npmjs.org/
///     mkdirp/0.5.5/node_modules/
///       mkdirp/                              (real dir)
///       minimist -> ../../../minimist/1.2.8/node_modules/minimist
///     minimist/1.2.8/node_modules/minimist/  (real dir, TRANSITIVE-ONLY)
///     loop -> ..                             (symlink cycle bait)
///   .not-a-store/wanted3/1.0.0/node_modules/wanted3/  (hidden decoy)
/// ```
///
/// The `.not-a-store` decoy pins the recognition rule: only
/// `.registry.*`-named hidden dirs are virtual stores; other hidden dirs
/// (caches, tool state) must stay skipped.
#[cfg(unix)]
async fn stage_pnpm3_legacy_tree(root: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::symlink;

    let nm = root.join("node_modules");
    let store = nm.join(".registry.npmjs.org");

    stage_npm_pkg(&store.join("mkdirp/0.5.5/node_modules"), "mkdirp", "0.5.5").await;
    stage_npm_pkg(
        &store.join("minimist/1.2.8/node_modules"),
        "minimist",
        "1.2.8",
    )
    .await;

    // mkdirp's dependency: relative sibling symlink, exactly as captured.
    symlink(
        Path::new("../../../minimist/1.2.8/node_modules/minimist"),
        store.join("mkdirp/0.5.5/node_modules/minimist"),
    )
    .unwrap();

    // Importer root: relative symlink into the hidden store (as captured).
    symlink(
        Path::new(".registry.npmjs.org/mkdirp/0.5.5/node_modules/mkdirp"),
        nm.join("mkdirp"),
    )
    .unwrap();

    // Metadata FILES at the node_modules root, as captured.
    tokio::fs::write(nm.join(".modules.yaml"), b"layoutVersion: 2\n")
        .await
        .unwrap();
    tokio::fs::write(nm.join(".pnpm-lock.yaml"), b"shrinkwrapVersion: 4\n")
        .await
        .unwrap();

    // Symlink cycle inside the store: never traversed (see pnpm4 stager).
    symlink(Path::new(".."), store.join("loop")).unwrap();

    // Hidden dir that is NOT a `.registry.*` store: must stay invisible.
    stage_npm_pkg(
        &nm.join(".not-a-store/wanted3/1.0.0/node_modules"),
        "wanted3",
        "1.0.0",
    )
    .await;

    nm
}

/// Regression (empirically confirmed on a real pnpm 3.8.1 tree; pnpm 1/2
/// captures show the identical layout): pre-`.pnpm` pnpm hides the virtual
/// store at `node_modules/.registry.npmjs.org`, which the walk skipped as
/// just-another-hidden-dir — a transitive-only dep was unresolvable, apply
/// exited 0 claiming success with nothing written.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn find_by_purls_resolves_pnpm3_legacy_registry_store_transitive() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = stage_pnpm3_legacy_tree(tmp.path()).await;
    let store = nm.join(".registry.npmjs.org");

    let crawler = NpmCrawler;
    let purls = vec![
        "pkg:npm/mkdirp@0.5.5".to_string(),
        "pkg:npm/minimist@1.2.8".to_string(),
        "pkg:npm/wanted3@1.0.0".to_string(),
    ];
    let result = crawler.find_by_purls(&nm, &purls).await.unwrap();

    assert_eq!(
        result.get("pkg:npm/mkdirp@0.5.5").map(|p| p.path.clone()),
        Some(nm.join("mkdirp")),
        "root-linked install must win over the store copy"
    );
    let minimist = result
        .get("pkg:npm/minimist@1.2.8")
        .expect("transitive-only dep must resolve through the pnpm<=3 `.registry.*` store");
    assert_eq!(
        minimist.path,
        store.join("minimist/1.2.8/node_modules/minimist")
    );
    assert!(
        !result.contains_key("pkg:npm/wanted3@1.0.0"),
        "hidden dirs that are not `.registry.*` stores must stay unprobed"
    );
    assert_eq!(result.len(), 2);
}

/// Scan twin: `crawl_all` must inventory the legacy store's packages
/// exactly once each — the root pass wins for the root-linked direct dep,
/// the transitive-only dep surfaces at its physical store home, and
/// non-store hidden dirs stay out of the inventory.
#[cfg(unix)]
#[tokio::test]
#[serial_test::parallel]
async fn crawl_all_inventories_pnpm3_legacy_registry_store_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = stage_pnpm3_legacy_tree(tmp.path()).await;
    let store = nm.join(".registry.npmjs.org");

    let crawler = NpmCrawler;
    let result = crawler.crawl_all(&options_at(tmp.path())).await;

    let purls: Vec<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert_eq!(
        result.len(),
        2,
        "exactly mkdirp + minimist, each once; got {purls:?}"
    );
    let by_purl = |purl: &str| -> &socket_patch_core::crawlers::types::CrawledPackage {
        result
            .iter()
            .find(|p| p.purl == purl)
            .unwrap_or_else(|| panic!("{purl} must be inventoried; got {purls:?}"))
    };
    assert_eq!(by_purl("pkg:npm/mkdirp@0.5.5").path, nm.join("mkdirp"));
    assert_eq!(
        by_purl("pkg:npm/minimist@1.2.8").path,
        store.join("minimist/1.2.8/node_modules/minimist"),
        "transitive-only dep must be inventoried at its physical store home"
    );
    assert!(
        !purls.contains(&"pkg:npm/wanted3@1.0.0"),
        "hidden dirs that are not `.registry.*` stores must stay unscanned"
    );
}
