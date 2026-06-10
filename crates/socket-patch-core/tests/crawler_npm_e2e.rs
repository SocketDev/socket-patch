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
        batch_size: 100,
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
    tokio::fs::write(&pkg, r#"{"name":"lodash","version":"4.17.21"}"#)
        .await
        .unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, Some(("lodash".to_string(), "4.17.21".to_string())));
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
    tokio::fs::write(&pkg, r#"{"version":"1.0.0"}"#)
        .await
        .unwrap();

    let result = read_package_json(&pkg).await;
    assert_eq!(result, None);
}

#[tokio::test]
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
async fn read_package_json_empty_name_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path().join("package.json");
    tokio::fs::write(&pkg, r#"{"name":"","version":"1.0.0"}"#)
        .await
        .unwrap();
    assert_eq!(read_package_json(&pkg).await, None);
}

#[tokio::test]
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
///
/// Skipped on Windows: `PathBuf::join` uses `\` there, which produces
/// `/home/foo/.bun\install\global\node_modules` from Unix-style input.
/// The pure-parser semantics are still correct (parent stripping +
/// suffix join), just expressed in the host's path-separator. Real
/// bun installs on Windows would feed Windows-style paths into the
/// same parser.
#[cfg(unix)]
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
fn get_npm_global_prefix_with_mock_runner_empty_stdout_returns_err() {
    let runner = common::MockCommandRunner::new().with_response("npm", &["root", "-g"], Some(""));
    assert!(get_npm_global_prefix_with(&runner).is_err());
}

// Skipped on Windows: same path-separator reason as
// `parse_bun_bin_output_well_formed_unix` above.
#[cfg(unix)]
#[test]
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
fn parse_npm_root_output_well_formed() {
    assert_eq!(
        parse_npm_root_output("/usr/local/lib/node_modules\n").as_deref(),
        Some("/usr/local/lib/node_modules")
    );
}

#[test]
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
async fn find_by_purls_resolves_qualified_purl_keyed_by_input() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    stage_npm_pkg(&nm, "lodash", "4.17.21").await;

    let crawler = NpmCrawler;
    let qualified = "pkg:npm/lodash@4.17.21?extension=tgz".to_string();
    let result = crawler
        .find_by_purls(&nm, &[qualified.clone()])
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
        .find_by_purls(tmp.path(), &["pkg:not-npm/foo@1.0".to_string()])
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
