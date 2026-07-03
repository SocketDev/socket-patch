//! Integration coverage for `crawlers::maven_crawler`. Drives
//! branches the apply-CLI suite doesn't exercise: pom-marker
//! detection, gradle marker detection, m2_repo_path env-var
//! resolution, walkdir-based scanning.

use std::path::Path;

use serial_test::serial;
use socket_patch_core::crawlers::maven_crawler::parse_pom_group_artifact_version;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::MavenCrawler;

fn options_at(root: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: root.to_path_buf(),
        global: false,
        global_prefix: None,
        batch_size: 100,
    }
}

/// Stage a maven m2-layout package: <repo>/<group/path>/<artifact>/<version>/
/// with a minimal pom.xml.
async fn stage_maven_pkg(
    repo: &Path,
    group: &str,
    artifact: &str,
    version: &str,
) -> std::path::PathBuf {
    let group_path = group.replace('.', "/");
    let pkg_dir = repo.join(group_path).join(artifact).join(version);
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    let pom = format!(
        r#"<?xml version="1.0"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>{group}</groupId>
  <artifactId>{artifact}</artifactId>
  <version>{version}</version>
</project>"#
    );
    tokio::fs::write(pkg_dir.join(format!("{artifact}-{version}.pom")), pom)
        .await
        .unwrap();
    pkg_dir
}

// ── parse_pom_group_artifact_version ───────────────────────────

#[test]
fn parse_pom_well_formed_extracts_coordinates() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#;
    let result = parse_pom_group_artifact_version(pom);
    assert_eq!(
        result,
        Some((
            "org.apache.commons".to_string(),
            "commons-lang3".to_string(),
            "3.12.0".to_string()
        ))
    );
}

#[test]
fn parse_pom_missing_group_id_returns_none() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#;
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

#[test]
fn parse_pom_missing_version_returns_none() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
</project>"#;
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

#[test]
fn parse_pom_malformed_xml_returns_none() {
    let pom = "this is not XML at all";
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

#[test]
fn parse_pom_empty_string_returns_none() {
    assert_eq!(parse_pom_group_artifact_version(""), None);
}

/// Parent block supplies groupId when the project block doesn't —
/// exercise the `in_parent` arm that records `parent_group_id` and the
/// final `group_id.or(parent_group_id)` fallback (maven_crawler.rs:124).
#[test]
fn parse_pom_parent_groupid_fallback() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example.parent</groupId>
    <artifactId>parent-pom</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child-module</artifactId>
  <version>2.0.0</version>
</project>"#;
    let result = parse_pom_group_artifact_version(pom);
    assert_eq!(
        result,
        Some((
            "com.example.parent".to_string(),
            "child-module".to_string(),
            "2.0.0".to_string()
        ))
    );
}

/// Top-level `<groupId>${env.GROUP_ID}</groupId>` is a property
/// reference — the parser must bail out instead of treating the
/// literal placeholder as a value (line 100).
#[test]
fn parse_pom_property_reference_groupid_returns_none() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>${env.GROUP_ID}</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#;
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

#[test]
fn parse_pom_property_reference_artifactid_returns_none() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>org.apache</groupId>
  <artifactId>${env.ART}</artifactId>
  <version>3.12.0</version>
</project>"#;
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

#[test]
fn parse_pom_property_reference_version_returns_none() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>org.apache</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>${revision}</version>
</project>"#;
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

/// `<parent><groupId>${prop}</groupId></parent>` is a parent property
/// reference — must NOT be accepted as a fallback groupId (line 86-87
/// skip arm).
#[test]
fn parse_pom_missing_artifact_id_returns_none() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>org.apache.commons</groupId>
  <version>3.12.0</version>
</project>"#;
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

/// An XML element rendered across two lines (open on one, close on
/// another) — `extract_xml_value` returns None for both, the parser
/// can't extract a value, and the function returns None. Drives
/// `extract_xml_value` line 16 (close-tag not found on same line).
#[test]
fn parse_pom_split_tag_returns_none() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <groupId>org.apache
  </groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#;
    // groupId line doesn't have a closing tag — extract returns None.
    // Without top-level groupId and no <parent>, the function returns None.
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

/// `MavenCrawler::default()` should forward to `new()`.
#[test]
fn maven_crawler_default_and_new_construct_cleanly() {
    let _a = MavenCrawler;
    let _b = MavenCrawler::new();
}

/// `m2_repo_path` falls through to `$HOME/.m2/repository` when neither
/// MAVEN_REPO_LOCAL nor M2_HOME is set. We can't exercise this directly
/// (private fn) but can drive it via `get_maven_repo_paths` with a
/// build.gradle marker and both env vars cleared. The crawler should
/// then point at the staged `<HOME>/.m2/repository`.
#[tokio::test]
#[serial]
async fn get_maven_repo_paths_home_dot_m2_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    let m2 = tmp.path().join(".m2").join("repository");
    tokio::fs::create_dir_all(&m2).await.unwrap();
    tokio::fs::write(tmp.path().join("pom.xml"), b"<project/>")
        .await
        .unwrap();

    let prev_local = std::env::var("MAVEN_REPO_LOCAL").ok();
    let prev_m2 = std::env::var("M2_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::remove_var("MAVEN_REPO_LOCAL");
    std::env::remove_var("M2_HOME");
    std::env::set_var("HOME", tmp.path());

    let crawler = MavenCrawler;
    let paths = crawler
        .get_maven_repo_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    if let Some(v) = prev_local {
        std::env::set_var("MAVEN_REPO_LOCAL", v);
    }
    if let Some(v) = prev_m2 {
        std::env::set_var("M2_HOME", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    // Production returns exactly the single resolved repo path — assert the
    // whole vec, not just membership, so a stray extra/wrong path also fails.
    assert_eq!(
        paths,
        vec![m2],
        "HOME/.m2/repository fallback must be the sole discovered repo"
    );
}

/// `get_maven_repo_paths(global=true)` with a real m2 layout under
/// MAVEN_REPO_LOCAL returns just that repo (lines 205-208).
#[tokio::test]
#[serial]
async fn get_maven_repo_paths_global_mode_with_maven_repo_local() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("custom-m2");
    tokio::fs::create_dir_all(&repo).await.unwrap();

    let prev = std::env::var("MAVEN_REPO_LOCAL").ok();
    std::env::set_var("MAVEN_REPO_LOCAL", &repo);

    let crawler = MavenCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_maven_repo_paths(&opts).await.unwrap();

    if let Some(v) = prev {
        std::env::set_var("MAVEN_REPO_LOCAL", v);
    } else {
        std::env::remove_var("MAVEN_REPO_LOCAL");
    }

    assert_eq!(paths, vec![repo]);
}

/// `get_maven_repo_paths(global=true)` with no env vars set and no
/// HOME/.m2 either — `is_dir` check fails and the crawler returns
/// empty (line 209).
#[tokio::test]
#[serial]
async fn get_maven_repo_paths_global_mode_no_m2_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let prev_local = std::env::var("MAVEN_REPO_LOCAL").ok();
    let prev_m2 = std::env::var("M2_HOME").ok();
    let prev_home = std::env::var("HOME").ok();
    std::env::remove_var("MAVEN_REPO_LOCAL");
    std::env::remove_var("M2_HOME");
    std::env::set_var("HOME", tmp.path()); // No .m2/ inside

    let crawler = MavenCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
        batch_size: 100,
    };
    let paths = crawler.get_maven_repo_paths(&opts).await.unwrap();

    if let Some(v) = prev_local {
        std::env::set_var("MAVEN_REPO_LOCAL", v);
    }
    if let Some(v) = prev_m2 {
        std::env::set_var("M2_HOME", v);
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }

    assert!(
        paths.is_empty(),
        "no m2 anywhere must yield empty; got {paths:?}"
    );
}

/// `find_by_purls` for a version directory that contains a non-`.pom`
/// file but no `.pom` — exercise the `has_pom_file` return-false arm
/// (line 405) via verify_maven_at_path.
#[tokio::test]
async fn find_by_purls_version_dir_without_pom_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let group_path = "org/apache/commons";
    let pkg_dir = tmp
        .path()
        .join(group_path)
        .join("commons-lang3")
        .join("3.12.0");
    tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
    // Put a non-.pom file in there — has_pom_file must reject.
    tokio::fs::write(pkg_dir.join("commons-lang3-3.12.0.jar"), b"fake jar")
        .await
        .unwrap();

    let crawler = MavenCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:maven/org.apache.commons/commons-lang3@3.12.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty(), "missing .pom must skip the package");
}

#[test]
fn parse_pom_parent_property_reference_groupid_skipped() {
    let pom = r#"<?xml version="1.0"?>
<project>
  <parent>
    <groupId>${env.PARENT_GROUP}</groupId>
    <artifactId>parent-pom</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child-module</artifactId>
  <version>2.0.0</version>
</project>"#;
    // No top-level groupId and the parent's is a property ref → bail.
    assert_eq!(parse_pom_group_artifact_version(pom), None);
}

// ── find_by_purls ──────────────────────────────────────────────

#[tokio::test]
async fn find_by_purls_finds_package_in_m2_layout() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg_dir =
        stage_maven_pkg(tmp.path(), "org.apache.commons", "commons-lang3", "3.12.0").await;

    let crawler = MavenCrawler;
    let purl = "pkg:maven/org.apache.commons/commons-lang3@3.12.0";
    let result = crawler
        .find_by_purls(tmp.path(), &[purl.to_string()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    let pkg = result
        .get(purl)
        .expect("requested purl must be the map key");
    assert_eq!(pkg.path, pkg_dir, "path must point at the version dir");
    assert_eq!(pkg.name, "commons-lang3", "name = artifactId");
    assert_eq!(pkg.version, "3.12.0");
    assert_eq!(
        pkg.namespace,
        Some("org.apache.commons".to_string()),
        "namespace = groupId"
    );
    assert_eq!(pkg.purl, purl, "purl must round-trip the request");
}

#[tokio::test]
async fn find_by_purls_no_match_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = MavenCrawler;
    let result = crawler
        .find_by_purls(
            tmp.path(),
            &["pkg:maven/com.example/missing@1.0.0".to_string()],
        )
        .await
        .unwrap();
    assert!(result.is_empty());
}

#[tokio::test]
async fn find_by_purls_invalid_purl_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = MavenCrawler;
    let result = crawler
        .find_by_purls(tmp.path(), &["pkg:not-maven/foo@1.0".to_string()])
        .await
        .unwrap();
    assert!(result.is_empty());
}

// ── crawl_all ─────────────────────────────────────────────────

#[tokio::test]
async fn crawl_all_discovers_packages_in_repo() {
    let tmp = tempfile::tempdir().unwrap();
    stage_maven_pkg(tmp.path(), "org.apache.commons", "commons-lang3", "3.12.0").await;
    stage_maven_pkg(tmp.path(), "com.google.guava", "guava", "32.1.3-jre").await;

    let crawler = MavenCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    // `>= 2` would pass on garbage/duplicate packages — assert the exact
    // coordinates were discovered and nothing extra leaked in.
    let purls: std::collections::HashSet<&str> = result.iter().map(|p| p.purl.as_str()).collect();
    assert!(
        purls.contains("pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
        "commons-lang3 must be discovered; got {result:?}"
    );
    assert!(
        purls.contains("pkg:maven/com.google.guava/guava@32.1.3-jre"),
        "guava must be discovered; got {result:?}"
    );
    assert_eq!(
        result.len(),
        2,
        "exactly the two staged packages, no spurious extras; got {result:?}"
    );
    // Spot-check field decomposition on one entry.
    let lang3 = result
        .iter()
        .find(|p| p.purl == "pkg:maven/org.apache.commons/commons-lang3@3.12.0")
        .unwrap();
    assert_eq!(lang3.name, "commons-lang3");
    assert_eq!(lang3.version, "3.12.0");
    assert_eq!(lang3.namespace, Some("org.apache.commons".to_string()));
}

#[tokio::test]
async fn crawl_all_with_empty_repo_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = MavenCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let result = crawler.crawl_all(&opts).await;
    assert!(result.is_empty());
}

// ── get_maven_repo_paths ───────────────────────────────────────

#[tokio::test]
async fn get_maven_repo_paths_with_global_prefix_returns_only_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let crawler = MavenCrawler;
    let opts = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: Some(tmp.path().to_path_buf()),
        batch_size: 100,
    };
    let paths = crawler.get_maven_repo_paths(&opts).await.unwrap();
    assert_eq!(paths, vec![tmp.path().to_path_buf()]);
}

#[tokio::test]
#[serial]
async fn get_maven_repo_paths_no_marker_returns_empty() {
    let tmp = tempfile::tempdir().unwrap();
    // No pom.xml, no build.gradle — not a Java project.
    let crawler = MavenCrawler;
    let paths = crawler
        .get_maven_repo_paths(&options_at(tmp.path()))
        .await
        .unwrap();
    assert!(paths.is_empty(), "non-Java dir must return empty paths");
}

#[tokio::test]
#[serial]
async fn get_maven_repo_paths_with_pom_xml_returns_repo() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("pom.xml"), b"<project/>")
        .await
        .unwrap();
    let repo = tempfile::tempdir().unwrap();
    let prev = std::env::var("MAVEN_REPO_LOCAL").ok();
    std::env::set_var("MAVEN_REPO_LOCAL", repo.path());

    let crawler = MavenCrawler;
    let paths = crawler
        .get_maven_repo_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("MAVEN_REPO_LOCAL");
    if let Some(v) = prev {
        std::env::set_var("MAVEN_REPO_LOCAL", v);
    }

    assert_eq!(
        paths,
        vec![repo.path().to_path_buf()],
        "pom.xml marker + MAVEN_REPO_LOCAL must yield exactly that repo"
    );
}

#[tokio::test]
#[serial]
async fn get_maven_repo_paths_with_build_gradle_returns_repo() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("build.gradle"), b"plugins {}")
        .await
        .unwrap();
    let repo = tempfile::tempdir().unwrap();
    let prev = std::env::var("MAVEN_REPO_LOCAL").ok();
    std::env::set_var("MAVEN_REPO_LOCAL", repo.path());

    let crawler = MavenCrawler;
    let paths = crawler
        .get_maven_repo_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("MAVEN_REPO_LOCAL");
    if let Some(v) = prev {
        std::env::set_var("MAVEN_REPO_LOCAL", v);
    }

    assert_eq!(
        paths,
        vec![repo.path().to_path_buf()],
        "build.gradle marker + MAVEN_REPO_LOCAL must yield exactly that repo"
    );
}

#[tokio::test]
#[serial]
async fn get_maven_repo_paths_with_build_gradle_kts_returns_repo() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("build.gradle.kts"), b"plugins {}")
        .await
        .unwrap();
    let repo = tempfile::tempdir().unwrap();
    let prev = std::env::var("MAVEN_REPO_LOCAL").ok();
    std::env::set_var("MAVEN_REPO_LOCAL", repo.path());

    let crawler = MavenCrawler;
    let paths = crawler
        .get_maven_repo_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("MAVEN_REPO_LOCAL");
    if let Some(v) = prev {
        std::env::set_var("MAVEN_REPO_LOCAL", v);
    }

    assert_eq!(
        paths,
        vec![repo.path().to_path_buf()],
        "build.gradle.kts marker + MAVEN_REPO_LOCAL must yield exactly that repo"
    );
}

#[tokio::test]
#[serial]
async fn get_maven_repo_paths_m2_home_fallback() {
    let tmp = tempfile::tempdir().unwrap();
    tokio::fs::write(tmp.path().join("pom.xml"), b"<project/>")
        .await
        .unwrap();
    let m2_home = tempfile::tempdir().unwrap();
    let repo_dir = m2_home.path().join("repository");
    tokio::fs::create_dir(&repo_dir).await.unwrap();
    let prev_maven_repo = std::env::var("MAVEN_REPO_LOCAL").ok();
    let prev_m2 = std::env::var("M2_HOME").ok();
    std::env::remove_var("MAVEN_REPO_LOCAL");
    std::env::set_var("M2_HOME", m2_home.path());

    let crawler = MavenCrawler;
    let paths = crawler
        .get_maven_repo_paths(&options_at(tmp.path()))
        .await
        .unwrap();

    std::env::remove_var("M2_HOME");
    if let Some(v) = prev_maven_repo {
        std::env::set_var("MAVEN_REPO_LOCAL", v);
    }
    if let Some(v) = prev_m2 {
        std::env::set_var("M2_HOME", v);
    }

    assert_eq!(
        paths,
        vec![repo_dir],
        "M2_HOME/repository fallback must be the sole discovered repo; got {paths:?}"
    );
}
