//! Integration coverage for the crawlers' empty/missing-path early
//! returns. Each crawler's `find_by_purls` and `crawl_all` short-
//! circuits when the discovery root doesn't exist or no PURLs match
//! its scheme — branches the apply-CLI suite doesn't naturally
//! exercise because those tests always pre-stage a layout.
//!
//! NOTE on test design: a bare `assert!(result.is_empty())` is a
//! *vacuous* guarantee — a crawler hard-wired to always return an
//! empty result would satisfy every one of these. So each empty/
//! missing-path assertion below is PAIRED with a positive control
//! that stages a matching layout on the *same code path* and proves
//! the crawler returns the expected non-empty result. The empty
//! assertion is only meaningful as the negative half of that pair:
//! it demonstrates the emptiness is caused by the empty/missing
//! input, not by a crawler that can never find anything.

use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::CargoCrawler;
use socket_patch_core::crawlers::GoCrawler;
use socket_patch_core::crawlers::MavenCrawler;
use socket_patch_core::crawlers::NuGetCrawler;
use socket_patch_core::crawlers::{NpmCrawler, PythonCrawler, RubyCrawler};

/// `CrawlerOptions::default()` should populate cwd from
/// `std::env::current_dir`, default `global` to false, leave
/// `global_prefix` unset, and set `batch_size` to the documented 100.
/// Covers types.rs:143-150 (the `Default` impl, which the apply-CLI
/// tests never exercise because callers always build options
/// explicitly).
#[test]
fn crawler_options_default_populates_fields() {
    let opts = CrawlerOptions::default();
    // Pin the EXACT value, not just non-emptiness: a regression that
    // defaults cwd to "." or "/" or any other placeholder must fail.
    let expected_cwd = std::env::current_dir().expect("current_dir() must succeed in test env");
    assert_eq!(
        opts.cwd, expected_cwd,
        "cwd must default to env::current_dir() result, not a placeholder"
    );
    assert!(!opts.global, "global must default to false");
    assert!(
        opts.global_prefix.is_none(),
        "global_prefix must default to None"
    );
    assert_eq!(opts.batch_size, 100, "batch_size must default to 100");
}

fn options_at(root: &std::path::Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

#[tokio::test]
async fn npm_crawler_find_by_purls_with_empty_purls_returns_empty_map() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let pkg_dir = nm.join("lodash");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name": "lodash", "version": "4.17.21"}"#,
    )
    .await
    .unwrap();

    let crawler = NpmCrawler;

    // Positive control: the package IS discoverable on this exact path,
    // so an empty result below can ONLY be caused by the empty PURL list.
    let hit = crawler
        .find_by_purls(&nm, &["pkg:npm/lodash@4.17.21".to_string()])
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: matching PURL must be found");
    let pkg = hit
        .get("pkg:npm/lodash@4.17.21")
        .expect("control: lodash key present");
    assert_eq!(pkg.name, "lodash");
    assert_eq!(pkg.version, "4.17.21");
    assert!(pkg.namespace.is_none());

    // Negative: empty PURL list against the SAME populated tree → empty.
    let result = crawler.find_by_purls(&nm, &[]).await.unwrap();
    assert!(
        result.is_empty(),
        "empty PURL list → empty result even when packages exist"
    );
}

#[tokio::test]
async fn npm_crawler_find_by_purls_with_nonexistent_node_modules_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let nm = tmp.path().join("node_modules");
    let pkg_dir = nm.join("lodash");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name": "lodash", "version": "4.17.21"}"#,
    )
    .await
    .unwrap();

    let crawler = NpmCrawler;
    let purl = "pkg:npm/lodash@4.17.21".to_string();

    // Positive control: same PURL resolves against the real tree.
    let hit = crawler
        .find_by_purls(&nm, std::slice::from_ref(&purl))
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: PURL resolves on existing tree");

    // Negative: identical PURL against a nonexistent node_modules → empty.
    let nonexistent = tmp.path().join("missing_node_modules");
    let result = crawler
        .find_by_purls(&nonexistent, std::slice::from_ref(&purl))
        .await
        .unwrap();
    assert!(
        result.is_empty(),
        "nonexistent node_modules → empty even for a PURL that otherwise matches"
    );
}

#[tokio::test]
async fn npm_crawler_crawl_all_with_no_packages_returns_empty() {
    let crawler = NpmCrawler;

    // Positive control: a populated local node_modules yields the package.
    let populated = tempfile::tempdir().unwrap();
    let pkg_dir = populated.path().join("node_modules").join("foo");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name": "foo", "version": "1.2.3"}"#,
    )
    .await
    .unwrap();
    let found = crawler.crawl_all(&options_at(populated.path())).await;
    assert_eq!(found.len(), 1, "control: installed package must be crawled");
    assert_eq!(found[0].purl, "pkg:npm/foo@1.2.3");

    // Negative: an empty project tree → empty crawl.
    let empty = tempfile::tempdir().unwrap();
    let result = crawler.crawl_all(&options_at(empty.path())).await;
    assert!(result.is_empty(), "no packages installed → empty crawl");
}

// ---------------------------------------------------------------------------
// python
// ---------------------------------------------------------------------------

#[tokio::test]
async fn python_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let sp = tmp.path();
    let dist_info = sp.join("requests-2.28.0.dist-info");
    tokio::fs::create_dir_all(&dist_info).await.unwrap();
    tokio::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: Requests\nVersion: 2.28.0\n",
    )
    .await
    .unwrap();

    let crawler = PythonCrawler;

    // Positive control on the same site-packages path.
    let hit = crawler
        .find_by_purls(sp, &["pkg:pypi/requests@2.28.0".to_string()])
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: matching PURL must resolve");
    assert_eq!(hit["pkg:pypi/requests@2.28.0"].version, "2.28.0");

    // Negative: empty PURL list → empty.
    let result = crawler.find_by_purls(sp, &[]).await.unwrap();
    assert!(result.is_empty(), "empty PURL list → empty result");
}

#[tokio::test]
async fn python_crawler_crawl_all_empty_returns_empty() {
    let crawler = PythonCrawler;

    // Positive control: a populated .venv site-packages yields the package.
    let populated = tempfile::tempdir().unwrap();
    #[cfg(windows)]
    let sp = populated
        .path()
        .join(".venv")
        .join("Lib")
        .join("site-packages");
    #[cfg(not(windows))]
    let sp = populated
        .path()
        .join(".venv")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    let dist_info = sp.join("requests-2.28.0.dist-info");
    tokio::fs::create_dir_all(&dist_info).await.unwrap();
    tokio::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: Requests\nVersion: 2.28.0\n",
    )
    .await
    .unwrap();
    let found = crawler.crawl_all(&options_at(populated.path())).await;
    assert_eq!(found.len(), 1, "control: venv package must be crawled");
    assert_eq!(found[0].purl, "pkg:pypi/requests@2.28.0");

    // Negative: empty project tree → empty.
    let empty = tempfile::tempdir().unwrap();
    let result = crawler.crawl_all(&options_at(empty.path())).await;
    assert!(result.is_empty(), "no packages → empty crawl");
}

// ---------------------------------------------------------------------------
// ruby
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ruby_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let gem_path = tmp.path();
    tokio::fs::create_dir_all(gem_path.join("rails-7.1.0").join("lib"))
        .await
        .unwrap();

    let crawler = RubyCrawler;

    // Positive control on the same gems path.
    let hit = crawler
        .find_by_purls(gem_path, &["pkg:gem/rails@7.1.0".to_string()])
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: matching gem PURL must resolve");
    assert_eq!(hit["pkg:gem/rails@7.1.0"].version, "7.1.0");

    // Negative: empty PURL list → empty.
    let result = crawler.find_by_purls(gem_path, &[]).await.unwrap();
    assert!(result.is_empty(), "empty PURL list → empty result");
}

#[tokio::test]
async fn ruby_crawler_crawl_all_empty_returns_empty() {
    let crawler = RubyCrawler;

    // Positive control: a Bundler vendor/bundle layout yields the gem.
    let populated = tempfile::tempdir().unwrap();
    let gems = populated
        .path()
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.2.0")
        .join("gems");
    tokio::fs::create_dir_all(gems.join("rails-7.1.0").join("lib"))
        .await
        .unwrap();
    let found = crawler.crawl_all(&options_at(populated.path())).await;
    assert!(
        found.iter().any(|p| p.purl == "pkg:gem/rails@7.1.0"),
        "control: vendored gem must be crawled, got {:?}",
        found.iter().map(|p| &p.purl).collect::<Vec<_>>()
    );

    // Negative: empty project tree → empty.
    let empty = tempfile::tempdir().unwrap();
    let result = crawler.crawl_all(&options_at(empty.path())).await;
    assert!(result.is_empty(), "no gems → empty crawl");
}

// ---------------------------------------------------------------------------
// cargo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cargo_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let src_path = tmp.path();
    let serde_dir = src_path.join("serde-1.0.200");
    tokio::fs::create_dir_all(&serde_dir).await.unwrap();
    tokio::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .await
    .unwrap();

    let crawler = CargoCrawler;

    // Positive control on the same registry-src path.
    let hit = crawler
        .find_by_purls(src_path, &["pkg:cargo/serde@1.0.200".to_string()])
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: matching crate PURL must resolve");
    assert_eq!(hit["pkg:cargo/serde@1.0.200"].version, "1.0.200");

    // Negative: empty PURL list → empty.
    let result = crawler.find_by_purls(src_path, &[]).await.unwrap();
    assert!(result.is_empty(), "empty PURL list → empty result");
}

#[tokio::test]
async fn cargo_crawler_crawl_all_empty_returns_empty() {
    let crawler = CargoCrawler;

    // Positive control: a local vendor/ dir yields the crate.
    let populated = tempfile::tempdir().unwrap();
    let serde_dir = populated.path().join("vendor").join("serde");
    tokio::fs::create_dir_all(&serde_dir).await.unwrap();
    tokio::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .await
    .unwrap();
    // The vendor tree is only scanned when cwd is a Rust project.
    tokio::fs::write(
        populated.path().join("Cargo.toml"),
        "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
    )
    .await
    .unwrap();
    let found = crawler.crawl_all(&options_at(populated.path())).await;
    assert!(
        found.iter().any(|p| p.purl == "pkg:cargo/serde@1.0.200"),
        "control: vendored crate must be crawled, got {:?}",
        found.iter().map(|p| &p.purl).collect::<Vec<_>>()
    );

    // Negative: empty project tree → empty.
    let empty = tempfile::tempdir().unwrap();
    let result = crawler.crawl_all(&options_at(empty.path())).await;
    assert!(result.is_empty(), "no crates → empty crawl");
}

// ---------------------------------------------------------------------------
// golang
// ---------------------------------------------------------------------------

#[tokio::test]
async fn go_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let cache_path = tmp.path();
    let module_dir = cache_path
        .join("github.com")
        .join("gin-gonic")
        .join("gin@v1.9.1");
    tokio::fs::create_dir_all(&module_dir).await.unwrap();

    let crawler = GoCrawler;

    // Positive control on the same module-cache path.
    let hit = crawler
        .find_by_purls(
            cache_path,
            &["pkg:golang/github.com/gin-gonic/gin@v1.9.1".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: matching module PURL must resolve");
    let pkg = &hit["pkg:golang/github.com/gin-gonic/gin@v1.9.1"];
    assert_eq!(pkg.name, "gin");
    assert_eq!(pkg.version, "v1.9.1");
    assert_eq!(pkg.namespace.as_deref(), Some("github.com/gin-gonic"));

    // Negative: empty PURL list → empty.
    let result = crawler.find_by_purls(cache_path, &[]).await.unwrap();
    assert!(result.is_empty(), "empty PURL list → empty result");
}

// ---------------------------------------------------------------------------
// maven
// ---------------------------------------------------------------------------

#[tokio::test]
async fn maven_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let src_path = tmp.path();
    let pkg_dir = src_path
        .join("org")
        .join("apache")
        .join("commons")
        .join("commons-lang3")
        .join("3.12.0");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join("commons-lang3-3.12.0.pom"),
        "<project>\n  <groupId>org.apache.commons</groupId>\n  <artifactId>commons-lang3</artifactId>\n  <version>3.12.0</version>\n</project>",
    )
    .await
    .unwrap();

    let crawler = MavenCrawler;

    // Positive control on the same repo-layout path.
    let hit = crawler
        .find_by_purls(
            src_path,
            &["pkg:maven/org.apache.commons/commons-lang3@3.12.0".to_string()],
        )
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: matching maven PURL must resolve");
    let pkg = &hit["pkg:maven/org.apache.commons/commons-lang3@3.12.0"];
    assert_eq!(pkg.name, "commons-lang3");
    assert_eq!(pkg.version, "3.12.0");
    assert_eq!(pkg.namespace.as_deref(), Some("org.apache.commons"));

    // Negative: empty PURL list → empty.
    let result = crawler.find_by_purls(src_path, &[]).await.unwrap();
    assert!(result.is_empty(), "empty PURL list → empty result");
}

// ---------------------------------------------------------------------------
// nuget
// ---------------------------------------------------------------------------

#[tokio::test]
async fn nuget_crawler_find_by_purls_empty_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_path = tmp.path();
    // NuGet global cache lowercases both name and version on disk.
    let pkg_dir = pkg_path.join("newtonsoft.json").join("13.0.3");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    tokio::fs::write(
        pkg_dir.join("newtonsoft.json.nuspec"),
        r#"<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>"#,
    )
    .await
    .unwrap();

    let crawler = NuGetCrawler;

    // Positive control on the same global-cache path.
    let hit = crawler
        .find_by_purls(pkg_path, &["pkg:nuget/Newtonsoft.Json@13.0.3".to_string()])
        .await
        .unwrap();
    assert_eq!(hit.len(), 1, "control: matching nuget PURL must resolve");
    assert!(hit.contains_key("pkg:nuget/Newtonsoft.Json@13.0.3"));

    // Negative: empty PURL list → empty.
    let result = crawler.find_by_purls(pkg_path, &[]).await.unwrap();
    assert!(result.is_empty(), "empty PURL list → empty result");
}
