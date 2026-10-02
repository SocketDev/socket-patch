//! Integration coverage for Gradle discovery: the `files-2.1` crawl
//! (`crawlers::gradle_cache`, the `GradleModules2` arms of
//! `MavenCrawler`). Every fixture is a tempdir tree laid out the way
//! Gradle caches downloads, each file under the hex sha1 of its own bytes.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};
use socket_patch_core::crawlers::gradle_cache;
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::MavenCrawler;

const COMMONS_TEXT: &str = "pkg:maven/org.apache.commons/commons-text@1.10.0";

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

/// Lay `files` out under `<files21>/<group>/<artifact>/<version>/<sha1>/<leaf>`,
/// naming each hash directory with `name(sha1)`. Returns the version dir.
fn cache_named(
    files21: &Path,
    gav: (&str, &str, &str),
    files: &[(&str, &[u8])],
    name: impl Fn(&str) -> String,
) -> PathBuf {
    let dir = files21.join(gav.0).join(gav.1).join(gav.2);
    for (leaf, bytes) in files {
        let hash_dir = dir.join(name(&sha1_hex(bytes)));
        std::fs::create_dir_all(&hash_dir).unwrap();
        std::fs::write(hash_dir.join(leaf), bytes).unwrap();
    }
    dir
}

fn cache(files21: &Path, gav: (&str, &str, &str), files: &[(&str, &[u8])]) -> PathBuf {
    cache_named(files21, gav, files, str::to_string)
}

/// A user home's `files-2.1`, created.
fn files21_of(home: &Path) -> PathBuf {
    let dir = home.join("caches/modules-2/files-2.1");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `commons-text:1.10.0` with its jar and pom (different hash dirs).
fn cache_commons_text(files21: &Path) -> PathBuf {
    cache(
        files21,
        ("org.apache.commons", "commons-text", "1.10.0"),
        &[
            ("commons-text-1.10.0.jar", b"jar bytes"),
            ("commons-text-1.10.0.pom", b"<project/>"),
        ],
    )
}

fn global_prefix(prefix: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: prefix.to_path_buf(),
        global: false,
        global_prefix: Some(prefix.to_path_buf()),
    }
}

async fn crawl_purls(options: &CrawlerOptions) -> Vec<(String, PathBuf)> {
    let mut out: Vec<(String, PathBuf)> = MavenCrawler
        .crawl_all(options)
        .await
        .into_iter()
        .map(|p| (p.purl, p.path))
        .collect();
    out.sort();
    out
}

// ── the files-2.1 crawl ─────────────────────────────────────────────────

/// Regression (#349): `scan --global-prefix …/files-2.1` finds the cached
/// modules again, one package per version dir.
#[tokio::test]
async fn global_prefix_files21() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    let version_dir = cache_commons_text(&files21);

    let found = crawl_purls(&global_prefix(&files21)).await;
    assert_eq!(found, vec![(COMMONS_TEXT.to_string(), version_dir.clone())]);

    let by_purl = MavenCrawler
        .find_by_purls(&files21, &[COMMONS_TEXT.to_string()])
        .await
        .unwrap();
    assert_eq!(by_purl[COMMONS_TEXT].path, version_dir);
    assert_eq!(by_purl[COMMONS_TEXT].name, "commons-text");
    assert_eq!(
        by_purl[COMMONS_TEXT].namespace.as_deref(),
        Some("org.apache.commons")
    );
}

/// A jar and its pom in different hash dirs are one package whose path is
/// the version dir; classifier jars ride along without becoming packages.
#[tokio::test]
async fn jar_and_pom_in_different_hash_dirs_are_one_package() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    let version_dir = cache(
        &files21,
        ("com.example", "lib", "2.0"),
        &[
            ("lib-2.0.jar", b"jar"),
            ("lib-2.0.pom", b"pom"),
            ("lib-2.0-sources.jar", b"sources"),
            ("lib-2.0-linux-x86_64.jar", b"native"),
        ],
    );
    let hash_dirs = std::fs::read_dir(&version_dir).unwrap().count();
    assert_eq!(hash_dirs, 4);

    let found = crawl_purls(&global_prefix(&files21)).await;
    assert_eq!(
        found,
        vec![("pkg:maven/com.example/lib@2.0".to_string(), version_dir)]
    );
}

/// A version dir holding only a `.module` (Gradle metadata) or only a
/// classifier jar: the `.module` is an installed module, a lone
/// classifier jar is not.
#[tokio::test]
async fn module_file_counts_and_lone_classifier_does_not() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    cache(
        &files21,
        ("com.example", "meta", "1.0"),
        &[("meta-1.0.module", b"{}")],
    );
    cache(
        &files21,
        ("com.example", "sources-only", "1.0"),
        &[("sources-only-1.0-sources.jar", b"src")],
    );
    let found: Vec<String> = crawl_purls(&global_prefix(&files21))
        .await
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    assert_eq!(found, vec!["pkg:maven/com.example/meta@1.0".to_string()]);
}

/// Metadata and lock files beside the module dirs, non-hex hash dirs and
/// stray files at each level are ignored.
#[tokio::test]
async fn bookkeeping_and_non_hex_dirs_are_ignored() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    let version_dir = cache_commons_text(&files21);
    std::fs::write(files21.join("modules-2.lock"), b"").unwrap();
    std::fs::write(files21.join("stray.jar"), b"").unwrap();
    for junk in ["metadata-2.106", "transforms-3", "jars-9"] {
        let dir = files21.join(junk).join("x").join("1.0").join("abc");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("x-1.0.jar"), b"").unwrap();
    }
    // A non-hex "hash" dir (upper case, too long, a word) holds nothing.
    for bad in ["ABCDEF", &"a".repeat(41), "notahash"] {
        let dir = files21.join("com.bad").join("bad").join("1.0").join(bad);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("bad-1.0.jar"), b"").unwrap();
    }
    std::fs::write(version_dir.join("stray.pom"), b"").unwrap();

    let found = crawl_purls(&global_prefix(&files21)).await;
    assert_eq!(found, vec![(COMMONS_TEXT.to_string(), version_dir)]);
}

/// Gradle may drop a sha1's leading zero from the hash dir name: a
/// 39-digit dir is crawled, and `hash_eq` / `pristine` hold for it.
#[tokio::test]
async fn hash_dir_with_stripped_leading_zero_is_crawled() {
    // Brute-force bytes whose sha1 starts with `0`.
    let bytes = (0u32..)
        .map(|i| format!("jar {i}").into_bytes())
        .find(|b| sha1_hex(b).starts_with('0') && !sha1_hex(b).starts_with("00"))
        .unwrap();
    let sha1 = sha1_hex(&bytes);
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    let version_dir = cache_named(
        &files21,
        ("com.example", "zero", "1.0"),
        &[("zero-1.0.jar", &bytes)],
        |s| s.trim_start_matches('0').to_string(),
    );
    let dir_name = sha1.trim_start_matches('0');
    assert_eq!(dir_name.len(), 39);
    assert!(version_dir.join(dir_name).join("zero-1.0.jar").is_file());

    let found = crawl_purls(&global_prefix(&files21)).await;
    assert_eq!(
        found,
        vec![("pkg:maven/com.example/zero@1.0".to_string(), version_dir)]
    );
    assert!(gradle_cache::hash_eq(dir_name, &sha1));
    assert!(gradle_cache::hash_eq(&sha1, dir_name));
    assert!(gradle_cache::pristine(dir_name, &bytes));
    assert!(!gradle_cache::pristine(dir_name, b"other bytes"));
}

/// A traversal-shaped PURL never resolves outside the cache, and an absent
/// version resolves to nothing.
#[tokio::test]
async fn find_by_purls_refuses_unsafe_and_absent_coordinates() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    cache_commons_text(&files21);
    let purls = [
        "pkg:maven/org.apache.commons/commons-text@..".to_string(),
        "pkg:maven/../commons-text@1.10.0".to_string(),
        "pkg:maven/org.apache.commons/commons-text@9.9".to_string(),
    ];
    let found = MavenCrawler.find_by_purls(&files21, &purls).await.unwrap();
    assert!(found.is_empty(), "{found:?}");
}

/// The walk lists every cached file, each in the hash dir its sha1 names.
#[tokio::test]
async fn walk_reports_every_entry_in_walk_order() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    cache_commons_text(&files21);
    let entries = gradle_cache::walk_files21(&files21);
    let leaves: HashSet<&str> = entries.iter().map(|e| e.leaf.as_str()).collect();
    assert_eq!(
        leaves,
        HashSet::from(["commons-text-1.10.0.jar", "commons-text-1.10.0.pom"])
    );
    for e in &entries {
        assert!(e.path(&files21).is_file());
        assert!(gradle_cache::pristine(
            &e.hash_dir,
            &std::fs::read(e.path(&files21)).unwrap()
        ));
    }
}
