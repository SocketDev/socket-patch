//! Integration coverage for Gradle discovery: the `files-2.1` crawl
//! (`crawlers::gradle_cache`, the `GradleModules2` arms of
//! `MavenCrawler`). Every fixture is a tempdir tree laid out the way
//! Gradle caches downloads, each file under the hex sha1 of its own bytes.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};
use socket_patch_core::crawlers::gradle_cache;
use socket_patch_core::crawlers::jvm_cache::{self, JvmCacheLayout, JvmCacheRoot};
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::MavenCrawler;
use socket_patch_core::manifest::schema::PatchFileInfo;

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

// ── installed copies ────────────────────────────────────────────────────

fn info(before: &[u8]) -> PatchFileInfo {
    PatchFileInfo {
        before_hash: sha1_hex(before),
        after_hash: "after".into(),
    }
}

/// A jar present in two hash dirs (a re-download whose bytes changed)
/// expands to two targets; the pom's own hash dir is a third; the
/// `package/` prefix is dropped from the keys.
#[test]
fn duplicate_leaf_gives_two_installed_copies() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    let gav = ("org.apache.commons", "commons-text", "1.10.0");
    let version_dir = cache(
        &files21,
        gav,
        &[
            ("commons-text-1.10.0.jar", b"first download"),
            ("commons-text-1.10.0.pom", b"<project/>"),
        ],
    );
    cache(
        &files21,
        gav,
        &[("commons-text-1.10.0.jar", b"second download")],
    );
    let files = HashMap::from([
        ("package/commons-text-1.10.0.jar".to_string(), info(b"x")),
        ("commons-text-1.10.0.pom".to_string(), info(b"y")),
    ]);

    let copies = gradle_cache::installed_copies(&version_dir, &files);
    let jar_dirs: Vec<&PathBuf> = copies
        .iter()
        .filter(|(_, f)| f.contains_key("commons-text-1.10.0.jar"))
        .map(|(d, _)| d)
        .collect();
    assert_eq!(jar_dirs.len(), 2, "{copies:?}");
    let mut want = vec![
        version_dir.join(sha1_hex(b"first download")),
        version_dir.join(sha1_hex(b"second download")),
    ];
    want.sort();
    let mut got: Vec<PathBuf> = jar_dirs.into_iter().cloned().collect();
    got.sort();
    assert_eq!(got, want);
    let pom_dir = version_dir.join(sha1_hex(b"<project/>"));
    assert!(copies
        .iter()
        .any(|(d, f)| *d == pom_dir && f.contains_key("commons-text-1.10.0.pom")));
    assert_eq!(copies.len(), 3);
    for (dir, files) in &copies {
        for leaf in files.keys() {
            assert!(dir.join(leaf).is_file(), "{}", dir.join(leaf).display());
        }
    }
}

/// Keys no hash dir holds (a jar member, a file the cache lacks) are
/// reported as missing, and the plain form keeps them on the version dir.
#[test]
fn missing_keys_are_reported_and_kept_on_the_version_dir() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    let version_dir = cache_commons_text(&files21);
    let files = HashMap::from([
        ("commons-text-1.10.0.jar".to_string(), info(b"x")),
        ("META-INF/NOTICE.txt".to_string(), info(b"y")),
        ("commons-text-1.10.0-tests.jar".to_string(), info(b"z")),
    ]);
    let detailed = gradle_cache::installed_copies_detailed(&version_dir, &files);
    assert_eq!(
        detailed.missing,
        vec![
            "META-INF/NOTICE.txt".to_string(),
            "commons-text-1.10.0-tests.jar".to_string()
        ]
    );
    assert_eq!(detailed.targets.len(), 1);

    let plain = gradle_cache::installed_copies(&version_dir, &files);
    let (dir, rest) = plain.last().unwrap();
    assert_eq!(*dir, version_dir);
    assert_eq!(rest.len(), 2);
    assert!(rest.contains_key("META-INF/NOTICE.txt"));
}

/// An m2 (or any non-Gradle) package path is its own single target.
#[test]
fn installed_copies_is_the_identity_for_an_m2_path() {
    let repo = tempfile::tempdir().unwrap();
    let pkg = repo.path().join("org/apache/commons/commons-text/1.10.0");
    std::fs::create_dir_all(&pkg).unwrap();
    let files = HashMap::from([("package/commons-text-1.10.0.jar".to_string(), info(b"x"))]);
    assert!(!gradle_cache::is_gradle_version_dir(&pkg));
    assert_eq!(
        gradle_cache::installed_copies(&pkg, &files),
        vec![(pkg.clone(), files.clone())]
    );
    let detailed = gradle_cache::installed_copies_detailed(&pkg, &files);
    assert_eq!(detailed.targets, vec![(pkg, files)]);
    assert!(detailed.missing.is_empty());
}

#[test]
fn is_gradle_version_dir_reads_the_spelling() {
    assert!(gradle_cache::is_gradle_version_dir(Path::new(
        "/h/.gradle/caches/modules-2/files-2.1/org.x/a/1.0"
    )));
    assert!(!gradle_cache::is_gradle_version_dir(Path::new(
        "/h/.gradle/caches/modules-2/files-2.1/org.x/a"
    )));
    assert!(!gradle_cache::is_gradle_version_dir(Path::new(
        "/h/.m2/repository/org/x/a/1.0"
    )));
}

// ── locate_artifact ─────────────────────────────────────────────────────

/// Every hash-dir copy in a Gradle cache, the one path in m2, classifier
/// jars by their own name.
#[test]
fn locate_artifact_finds_every_copy() {
    let home = tempfile::tempdir().unwrap();
    let files21 = files21_of(home.path());
    let gav = ("org.apache.commons", "commons-text", "1.10.0");
    let version_dir = cache(
        &files21,
        gav,
        &[
            ("commons-text-1.10.0.jar", b"one"),
            ("commons-text-1.10.0-sources.jar", b"src"),
        ],
    );
    cache(&files21, gav, &[("commons-text-1.10.0.jar", b"two")]);
    let gav = (
        "org.apache.commons".to_string(),
        "commons-text".to_string(),
        "1.10.0".to_string(),
    );
    let gradle = JvmCacheRoot::new(files21.clone(), JvmCacheLayout::GradleModules2);
    let mut want = vec![
        version_dir
            .join(sha1_hex(b"one"))
            .join("commons-text-1.10.0.jar"),
        version_dir
            .join(sha1_hex(b"two"))
            .join("commons-text-1.10.0.jar"),
    ];
    want.sort();
    assert_eq!(jvm_cache::locate_artifact(&gradle, &gav, None, "jar"), want);
    assert_eq!(
        jvm_cache::locate_artifact(&gradle, &gav, Some("sources"), "jar"),
        vec![version_dir
            .join(sha1_hex(b"src"))
            .join("commons-text-1.10.0-sources.jar")]
    );
    assert!(jvm_cache::locate_artifact(&gradle, &gav, None, "pom").is_empty());

    let repo = tempfile::tempdir().unwrap();
    let m2_dir = repo.path().join("org/apache/commons/commons-text/1.10.0");
    std::fs::create_dir_all(&m2_dir).unwrap();
    std::fs::write(m2_dir.join("commons-text-1.10.0.jar"), b"m2").unwrap();
    let m2 = JvmCacheRoot::new(repo.path().to_path_buf(), JvmCacheLayout::Maven2);
    assert_eq!(
        jvm_cache::locate_artifact(&m2, &gav, None, "jar"),
        vec![m2_dir.join("commons-text-1.10.0.jar")]
    );
    let evil = ("..".to_string(), "x".to_string(), "1".to_string());
    assert!(jvm_cache::locate_artifact(&gradle, &evil, None, "jar").is_empty());
    assert!(jvm_cache::locate_artifact(&m2, &gav, Some("../x"), "jar").is_empty());
}

// ── derived copies ──────────────────────────────────────────────────────

/// Instrumented / transformed copies of the jar outside files-2.1, by name
/// or by the pristine sha1, are found; unrelated files are not.
#[test]
fn stale_derived_copies_finds_transforms_and_instrumented_jars() {
    let home = tempfile::tempdir().unwrap();
    let caches = home.path().join("caches");
    let leaf = "victim-1.10.0.jar";
    let sha1 = sha1_hex(b"pristine");
    let hits = [
        caches.join("jars-9/abc123/victim-1.10.0.jar"),
        caches.join("transforms-3/f00d/transformed/instrumented-victim-1.10.0.jar"),
        caches.join(format!("8.14.3/transforms/{sha1}/transformed/renamed.jar")),
        caches.join(format!("transforms-4/{}.jar", sha1.trim_start_matches('0'))),
    ];
    let misses = [
        caches.join("jars-9/abc123/other-1.0.jar"),
        caches.join("8.14.3/kotlin-dsl/victim-1.10.0.jar"),
        caches.join("modules-2/files-2.1/g/victim/1.10.0/aa/victim-1.10.0.jar"),
    ];
    for p in hits.iter().chain(&misses) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }
    let mut want = hits.to_vec();
    want.sort();
    assert_eq!(
        gradle_cache::stale_derived_copies(home.path(), leaf, &sha1),
        want
    );
    assert!(gradle_cache::stale_derived_copies(&home.path().join("none"), leaf, &sha1).is_empty());
}
