//! Integration coverage for Gradle discovery: the `files-2.1` crawl
//! (`crawlers::gradle_cache`, the `GradleModules2` arms of
//! `MavenCrawler`). Every fixture is a tempdir tree laid out the way
//! Gradle caches downloads, each file under the hex sha1 of its own bytes.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};
use socket_patch_core::crawlers::gradle_cache;
use socket_patch_core::crawlers::jvm_cache::{self, JvmCacheLayout, JvmCacheRoot};
use socket_patch_core::crawlers::maven_crawler::{m2_gate, normalize_prefix, JvmEnv, M2Gate};
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::MavenCrawler;
use socket_patch_core::gradle::Os;
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

/// Copies of the jar outside files-2.1 that are provably pristine-derived
/// (identical bytes, or the pristine sha1 in a dir or stem) are stale;
/// same-named copies of other bytes (an instrumented jar, a copy Gradle
/// rebuilt from the patched jar) are only unknown; unrelated files are
/// neither.
#[test]
fn stale_derived_copies_finds_transforms_and_instrumented_jars() {
    let home = tempfile::tempdir().unwrap();
    let caches = home.path().join("caches");
    let leaf = "victim-1.10.0.jar";
    let sha1 = sha1_hex(b"pristine");
    let stale = [
        (
            caches.join("jars-9/abc123/victim-1.10.0.jar"),
            &b"pristine"[..],
        ),
        (
            caches.join(format!("8.14.3/transforms/{sha1}/transformed/renamed.jar")),
            b"x",
        ),
        (
            caches.join(format!("transforms-4/{}.jar", sha1.trim_start_matches('0'))),
            b"x",
        ),
    ];
    let unknown = [
        (
            caches.join("jars-9/def456/victim-1.10.0.jar"),
            &b"patched"[..],
        ),
        (
            caches.join("transforms-3/f00d/transformed/instrumented-victim-1.10.0.jar"),
            b"instrumented",
        ),
    ];
    let misses = [
        (caches.join("jars-9/abc123/other-1.0.jar"), &b"pristine"[..]),
        (
            caches.join("8.14.3/kotlin-dsl/victim-1.10.0.jar"),
            b"pristine",
        ),
        (
            caches.join("modules-2/files-2.1/g/victim/1.10.0/aa/victim-1.10.0.jar"),
            b"pristine",
        ),
    ];
    for (p, bytes) in stale.iter().chain(&unknown).chain(&misses) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    let sorted = |v: &[(PathBuf, &[u8])]| {
        let mut v: Vec<PathBuf> = v.iter().map(|(p, _)| p.clone()).collect();
        v.sort();
        v
    };
    let found = gradle_cache::stale_derived_copies(home.path(), leaf, &sha1);
    assert_eq!(found.stale, sorted(&stale));
    assert_eq!(found.unknown, sorted(&unknown));
    assert!(!found.incomplete);
    assert_eq!(
        gradle_cache::stale_derived_copies(&home.path().join("none"), leaf, &sha1),
        gradle_cache::DerivedCopies::default()
    );
}

/// A derived-cache walk cut short by its entry bound says so: an empty
/// `stale` from it is not evidence that no stale copy exists.
#[test]
fn stale_derived_copies_reports_a_truncated_walk() {
    let home = tempfile::tempdir().unwrap();
    let leaf = "victim-1.10.0.jar";
    let sha1 = sha1_hex(b"pristine");
    let deep = home
        .path()
        .join("caches/transforms-3/zz/transformed/victim-1.10.0.jar");
    for i in 0..8 {
        let p = home
            .path()
            .join(format!("caches/transforms-3/a{i}/transformed/x.jar"));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"x").unwrap();
    }
    std::fs::create_dir_all(deep.parent().unwrap()).unwrap();
    std::fs::write(&deep, b"pristine").unwrap();

    let full = gradle_cache::stale_derived_copies(home.path(), leaf, &sha1);
    assert_eq!(full.stale, vec![deep]);
    assert!(!full.incomplete);
    let cut = gradle_cache::stale_derived_copies_bounded(home.path(), leaf, &sha1, 4);
    assert!(cut.stale.is_empty(), "{cut:?}");
    assert!(cut.incomplete);
}

// ── cache roots: the Gradle user home, the read-only cache, #551 ────────

/// A fake machine: a user home holding `.gradle` and `.m2/repository`, and
/// a project dir. Everything comes from an explicit env, never the
/// process's.
struct Machine {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    project: PathBuf,
    env: HashMap<String, String>,
}

impl Machine {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let project = tmp.path().join("project");
        std::fs::create_dir_all(home.join(".m2/repository")).unwrap();
        files21_of(&home.join(".gradle"));
        std::fs::create_dir_all(&project).unwrap();
        Self {
            _tmp: tmp,
            env: HashMap::from([("HOME".to_string(), home.to_string_lossy().into_owned())]),
            home,
            project,
        }
    }

    fn set(&mut self, k: &str, v: &Path) {
        self.env
            .insert(k.to_string(), v.to_string_lossy().into_owned());
    }

    fn jvm_env(&self) -> JvmEnv {
        JvmEnv::resolve(&self.env, Os::current(), Some(&self.home))
    }

    fn gradle_files21(&self) -> PathBuf {
        self.home.join(".gradle/caches/modules-2/files-2.1")
    }

    fn m2(&self) -> PathBuf {
        self.home.join(".m2/repository")
    }

    fn write(&self, rel: &str, text: &str) {
        let path = self.project.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn options(&self, global: bool) -> CrawlerOptions {
        CrawlerOptions {
            cwd: self.project.clone(),
            global,
            global_prefix: None,
        }
    }

    async fn roots(&self, global: bool) -> Vec<PathBuf> {
        MavenCrawler
            .get_jvm_cache_roots_with(&self.options(global), &self.jvm_env())
            .await
            .into_iter()
            .map(|r| r.path)
            .collect()
    }

    fn gate(&self) -> M2Gate {
        m2_gate(&self.project, &self.jvm_env())
    }
}

const GRADLE_ONLY: &str = "plugins { id 'java' }\nrepositories { mavenCentral() }\n";

/// Gradle's user home: `-Dgradle.user.home` in GRADLE_OPTS beats JAVA_OPTS,
/// which beats GRADLE_USER_HOME, which beats `<home>/.gradle`; Maven's
/// local repository keeps its own precedence.
#[test]
fn home_precedence() {
    let m = Machine::new();
    let base = m.jvm_env();
    assert_eq!(base.gradle.as_ref().unwrap().files21, m.gradle_files21());
    assert_eq!(base.m2_repo, m.m2());

    let mut env = m.env.clone();
    env.insert("GRADLE_USER_HOME".into(), "/guh".into());
    env.insert("JAVA_OPTS".into(), "-Dgradle.user.home=/java".into());
    env.insert(
        "GRADLE_OPTS".into(),
        "-Xmx1g \"-Dgradle.user.home=/gradle opts\"".into(),
    );
    let home = |env: &HashMap<String, String>| {
        JvmEnv::resolve(env, Os::Unix, Some(&m.home))
            .gradle
            .unwrap()
            .user_home
    };
    assert_eq!(home(&env), PathBuf::from("/gradle opts"));
    env.remove("GRADLE_OPTS");
    assert_eq!(home(&env), PathBuf::from("/java"));
    env.remove("JAVA_OPTS");
    assert_eq!(home(&env), PathBuf::from("/guh"));
    env.insert("GRADLE_USER_HOME".into(), String::new());
    assert_eq!(home(&env), m.home.join(".gradle"));

    let mut env = m.env.clone();
    env.insert("MAVEN_REPO_LOCAL".into(), "/mrl".into());
    env.insert("M2_HOME".into(), "/m2home".into());
    assert_eq!(
        JvmEnv::resolve(&env, Os::Unix, None).m2_repo,
        PathBuf::from("/mrl")
    );
    env.remove("MAVEN_REPO_LOCAL");
    assert_eq!(
        JvmEnv::resolve(&env, Os::Unix, None).m2_repo,
        PathBuf::from("/m2home/repository")
    );
}

/// The read-only cache is scanned after the user home's, and is reported as
/// read-only.
#[tokio::test]
async fn ro_cache_is_a_root_after_the_user_home() {
    let mut m = Machine::new();
    let ro = m.home.join("ro-cache");
    let ro_files21 = ro.join("modules-2/files-2.1");
    std::fs::create_dir_all(&ro_files21).unwrap();
    let ro_version_dir = cache_commons_text(&ro_files21);
    m.set("GRADLE_RO_DEP_CACHE", &ro);
    m.write("build.gradle", GRADLE_ONLY);

    assert_eq!(
        m.roots(false).await,
        vec![m.gradle_files21(), ro_files21.clone()]
    );
    let env = m.jvm_env();
    assert!(env.is_ro_root(&ro_files21));
    assert!(!env.is_ro_root(&m.gradle_files21()));

    let found = MavenCrawler
        .find_by_purls(&ro_files21, &[COMMONS_TEXT.to_string()])
        .await
        .unwrap();
    assert_eq!(found[COMMONS_TEXT].path, ro_version_dir);
}

/// #551: a Gradle-only build without mavenLocal() does not read ~/.m2.
#[tokio::test]
async fn gradle_only_without_maven_local_has_no_m2() {
    let m = Machine::new();
    m.write("settings.gradle", "rootProject.name = 'p'\n");
    m.write("build.gradle", GRADLE_ONLY);
    assert_eq!(m.gate(), M2Gate::Ignored);
    assert_eq!(m.roots(false).await, vec![m.gradle_files21()]);
    // PURL lookups (vendor sourcing, apply's every-copy fan-out) still see
    // the m2 bytes; the Gradle caches only through the copy lookup, whose
    // callers expand version dirs.
    let copies = MavenCrawler
        .get_maven_copy_paths_with(&m.options(false), &m.jvm_env())
        .await
        .unwrap();
    assert_eq!(copies, vec![m.m2(), m.gradle_files21()]);
    let lookup = MavenCrawler
        .get_maven_repo_paths_with(&m.options(false), &m.jvm_env())
        .await
        .unwrap();
    assert_eq!(lookup, vec![m.m2()]);
}

/// The PURL lookup the existing join sites use (apply, rollback, vendor,
/// VEX) never hands out a Gradle version dir, which they would join file
/// keys onto as if it were an m2 package dir: a GAV only Gradle caches
/// stays "not installed" for them, also under `--global-prefix`.
#[tokio::test]
async fn repo_paths_leave_out_gradle_caches() {
    let m = Machine::new();
    m.write("build.gradle", GRADLE_ONLY);
    cache_commons_text(&m.gradle_files21());
    for options in [
        m.options(false),
        m.options(true),
        global_prefix(&m.gradle_files21()),
    ] {
        let lookup = MavenCrawler
            .get_maven_repo_paths_with(&options, &m.jvm_env())
            .await
            .unwrap();
        assert!(!lookup.contains(&m.gradle_files21()), "{lookup:?}");
        for root in lookup {
            let found = MavenCrawler
                .find_by_purls(&root, &[COMMONS_TEXT.to_string()])
                .await
                .unwrap();
            assert!(found.is_empty(), "{root:?}: {found:?}");
        }
    }
    let copies = MavenCrawler
        .get_maven_copy_paths_with(&global_prefix(&m.gradle_files21()), &m.jvm_env())
        .await
        .unwrap();
    assert_eq!(copies, vec![m.gradle_files21()]);
}

/// #551: mavenLocal() in a buildSrc convention plugin counts.
#[tokio::test]
async fn maven_local_in_buildsrc_convention_plugin_keeps_m2() {
    let m = Machine::new();
    m.write("settings.gradle.kts", "rootProject.name = \"p\"\n");
    m.write("build.gradle.kts", "plugins { id(\"conv\") }\n");
    m.write(
        "buildSrc/build.gradle.kts",
        "plugins { `kotlin-dsl` }\nrepositories { gradlePluginPortal() }\n",
    );
    m.write(
        "buildSrc/src/main/kotlin/conv.gradle.kts",
        "repositories {\n    mavenLocal()\n    mavenCentral()\n}\n",
    );
    assert!(matches!(m.gate(), M2Gate::Declared(at) if at.contains("conv.gradle.kts")));
    assert_eq!(m.roots(false).await, vec![m.gradle_files21(), m.m2()]);
}

/// #551: mavenLocal() in a Gradle user-home init script counts.
#[tokio::test]
async fn maven_local_in_user_home_init_d_keeps_m2() {
    let m = Machine::new();
    m.write("build.gradle", GRADLE_ONLY);
    let init_d = m.home.join(".gradle/init.d");
    std::fs::create_dir_all(&init_d).unwrap();
    std::fs::write(
        init_d.join("local.gradle"),
        "allprojects { repositories { mavenLocal() } }\n",
    )
    .unwrap();
    assert!(matches!(m.gate(), M2Gate::Declared(at) if at.ends_with("local.gradle")));
    assert_eq!(m.roots(false).await, vec![m.gradle_files21(), m.m2()]);
}

/// #551: a non-literal `apply from` might add mavenLocal(): m2 is kept and
/// the gate says why.
#[tokio::test]
async fn non_literal_apply_from_keeps_m2_undetermined() {
    let m = Machine::new();
    m.write(
        "build.gradle",
        "def common = rootProject.file('gradle/' + 'repos.gradle')\napply from: common\n",
    );
    assert!(
        matches!(m.gate(), M2Gate::Undetermined(_)),
        "{:?}",
        m.gate()
    );
    assert_eq!(m.roots(false).await, vec![m.gradle_files21(), m.m2()]);
}

/// An init script that is not UTF-8 cannot be ruled out either.
#[tokio::test]
async fn unreadable_init_script_keeps_m2_undetermined() {
    let m = Machine::new();
    m.write("build.gradle", GRADLE_ONLY);
    std::fs::write(m.home.join(".gradle/init.gradle"), b"\xff\xfe mavenLocal()").unwrap();
    assert!(matches!(m.gate(), M2Gate::Undetermined(why) if why.contains("init.gradle")));
}

/// The wrapper's own distribution: a custom one that is not unpacked yet
/// cannot be read (undetermined); once unpacked, its init.d is read; a
/// stock distribution ships no init scripts.
#[tokio::test]
async fn wrapper_distribution_init_d() {
    let m = Machine::new();
    m.write("build.gradle", GRADLE_ONLY);
    m.write(
        "gradle/wrapper/gradle-wrapper.properties",
        "distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\n\
         distributionUrl=https\\://corp.example/dists/gradle-8.14.3-corp.zip\n",
    );
    assert!(matches!(m.gate(), M2Gate::Undetermined(why) if why.contains("corp.example")));

    let init_d = m
        .home
        .join(".gradle/wrapper/dists/gradle-8.14.3-corp/abc123/gradle-8.14.3/init.d");
    std::fs::create_dir_all(&init_d).unwrap();
    assert_eq!(m.gate(), M2Gate::Ignored);
    std::fs::write(
        init_d.join("corp.gradle"),
        "allprojects { repositories { mavenLocal() } }",
    )
    .unwrap();
    assert!(matches!(m.gate(), M2Gate::Declared(at) if at.ends_with("corp.gradle")));

    // distributionBase=PROJECT unpacks under the build itself.
    m.write(
        "gradle/wrapper/gradle-wrapper.properties",
        "distributionBase=PROJECT\ndistributionPath=.dists\n\
         distributionUrl=https\\://corp.example/dists/gradle-9.8.0-corp.zip\n",
    );
    assert!(matches!(m.gate(), M2Gate::Undetermined(_)));
    m.write(
        ".dists/gradle-9.8.0-corp/h/gradle-9.8.0/init.d/x.gradle.kts",
        "repositories { mavenLocal() }",
    );
    assert!(matches!(m.gate(), M2Gate::Declared(at) if at.ends_with("x.gradle.kts")));

    m.write(
        "gradle/wrapper/gradle-wrapper.properties",
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.8.0-bin.zip\n",
    );
    assert_eq!(m.gate(), M2Gate::Ignored);
}

/// Wrapper properties are read as `java.util.Properties` reads them
/// (ISO-8859-1, whitespace separator, escapes): a Latin-1 comment or a
/// `distributionUrl <url>` line still names the custom distribution, so it
/// stays undetermined until unpacked. Properties that name no distribution
/// at all keep the gate undetermined too.
#[tokio::test]
async fn wrapper_properties_latin1_and_unparseable() {
    let m = Machine::new();
    m.write("build.gradle", GRADLE_ONLY);
    let props = m.project.join("gradle/wrapper/gradle-wrapper.properties");
    std::fs::create_dir_all(props.parent().unwrap()).unwrap();
    std::fs::write(
        &props,
        b"# \xa9 ACME\ndistributionUrl=https\\://repo.acme/gradle-8.5-acme.zip\n",
    )
    .unwrap();
    assert!(matches!(m.gate(), M2Gate::Undetermined(why) if why.contains("repo.acme")));
    m.write(
        "gradle/wrapper/gradle-wrapper.properties",
        "distributionUrl   https\\://repo.acme/gradle-8.5-acme.zip\n",
    );
    assert!(matches!(m.gate(), M2Gate::Undetermined(why) if why.contains("repo.acme")));
    let init_d = m
        .home
        .join(".gradle/wrapper/dists/gradle-8.5-acme/h/gradle-8.5/init.d");
    std::fs::create_dir_all(&init_d).unwrap();
    std::fs::write(
        init_d.join("acme.gradle"),
        "allprojects { repositories { mavenLocal() } }",
    )
    .unwrap();
    assert!(matches!(m.gate(), M2Gate::Declared(at) if at.ends_with("acme.gradle")));

    std::fs::remove_dir_all(m.home.join(".gradle/wrapper")).unwrap();
    m.write(
        "gradle/wrapper/gradle-wrapper.properties",
        "distributionBase=GRADLE_USER_HOME\n",
    );
    assert!(
        matches!(m.gate(), M2Gate::Undetermined(why) if why.contains("no distributionUrl")),
        "{:?}",
        m.gate()
    );
}

/// A subproject cwd (no settings of its own) is judged with the settings
/// of the build above it.
#[tokio::test]
async fn subproject_cwd_reads_the_root_settings() {
    let mut m = Machine::new();
    m.write(
        "settings.gradle",
        "dependencyResolutionManagement { repositories { mavenLocal() } }\ninclude 'app'\n",
    );
    m.write("app/build.gradle", "plugins { id 'java' }\n");
    m.project = m.project.join("app");
    assert!(matches!(m.gate(), M2Gate::Declared(at) if at == "settings.gradle"));
}

/// #551: a pom.xml beside the Gradle build reads m2 as always; both roots.
#[tokio::test]
async fn pom_and_gradle_get_both_roots() {
    let m = Machine::new();
    m.write("build.gradle", GRADLE_ONLY);
    m.write("pom.xml", "<project/>");
    assert_eq!(m.gate(), M2Gate::NotGradleOnly);
    assert_eq!(m.roots(false).await, vec![m.gradle_files21(), m.m2()]);
}

/// A pom-only project never reads the Gradle cache; a non-JVM cwd gets no
/// root at all unless the scan is global.
#[tokio::test]
async fn non_jvm_cwd_gets_no_gradle_root_unless_global() {
    let m = Machine::new();
    assert!(m.roots(false).await.is_empty());
    assert_eq!(m.roots(true).await, vec![m.gradle_files21(), m.m2()]);
    m.write("pom.xml", "<project/>");
    assert_eq!(m.roots(false).await, vec![m.m2()]);
}

/// `--global-prefix` with a Gradle user home, its `caches/modules-2`, a
/// read-only cache's `modules-2`, or `files-2.1` itself finds the cached
/// PURLs. A Maven repository that happens to be named `caches` stays one.
#[tokio::test]
async fn global_prefix_spellings_of_the_gradle_cache() {
    let m = Machine::new();
    let version_dir = cache_commons_text(&m.gradle_files21());
    let gradle_home = m.home.join(".gradle");
    for prefix in [
        gradle_home.clone(),
        gradle_home.join("caches/modules-2"),
        m.gradle_files21(),
    ] {
        assert_eq!(
            normalize_prefix(&prefix),
            m.gradle_files21(),
            "{}",
            prefix.display()
        );
        assert_eq!(
            crawl_purls(&global_prefix(&prefix)).await,
            vec![(COMMONS_TEXT.to_string(), version_dir.clone())],
            "{}",
            prefix.display()
        );
    }
    let ro = m.home.join("ro");
    let ro_files21 = ro.join("modules-2/files-2.1");
    std::fs::create_dir_all(&ro_files21).unwrap();
    let ro_dir = cache_commons_text(&ro_files21);
    assert_eq!(
        crawl_purls(&global_prefix(&ro.join("modules-2"))).await,
        vec![(COMMONS_TEXT.to_string(), ro_dir)]
    );

    // A Maven repository named `caches`: m2 layout, read as m2.
    let caches = m.home.join("caches");
    let pkg = caches.join("org/example/m2lib/1.0");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("m2lib-1.0.pom"),
        "<project><groupId>org.example</groupId><artifactId>m2lib</artifactId>\
         <version>1.0</version></project>",
    )
    .unwrap();
    assert_eq!(normalize_prefix(&caches), caches);
    assert_eq!(
        crawl_purls(&global_prefix(&caches)).await,
        vec![("pkg:maven/org.example/m2lib@1.0".to_string(), pkg)]
    );
}

/// Lock files never narrow discovery: with a lock file present, a cached
/// module no lock names (a buildscript classpath entry) is still reported;
/// the lock set only annotates.
#[tokio::test]
async fn unlocked_buildscript_dependency_is_reported_with_lockfiles() {
    let m = Machine::new();
    m.write(
        "build.gradle",
        "buildscript { dependencies { classpath 'com.example:build-plugin:1.0' } }\n\
         dependencies { implementation 'org.apache.commons:commons-text:1.10.0' }\n\
         dependencyLocking { lockAllConfigurations() }\n",
    );
    m.write(
        "gradle.lockfile",
        "# lock\norg.apache.commons:commons-text:1.10.0=compileClasspath,runtimeClasspath\nempty=\n",
    );
    cache_commons_text(&m.gradle_files21());
    cache(
        &m.gradle_files21(),
        ("com.example", "build-plugin", "1.0"),
        &[("build-plugin-1.0.jar", b"plugin")],
    );
    // The roots a scan of this build crawls, each crawled in full.
    let roots = m.roots(false).await;
    assert_eq!(roots, vec![m.gradle_files21()]);
    let mut purls: Vec<String> = Vec::new();
    for root in &roots {
        purls.extend(
            crawl_purls(&global_prefix(root))
                .await
                .into_iter()
                .map(|(p, _)| p),
        );
    }
    assert_eq!(
        purls,
        vec![
            "pkg:maven/com.example/build-plugin@1.0".to_string(),
            COMMONS_TEXT.to_string(),
        ]
    );
    let locked = gradle_cache::locked_gavs(&m.project);
    assert!(locked.contains(&(
        "org.apache.commons".to_string(),
        "commons-text".to_string(),
        "1.10.0".to_string()
    )));
    assert!(!locked.iter().any(|(_, a, _)| a == "build-plugin"));
}

/// A stray GRADLE_OPTS / GRADLE_USER_HOME in the process env does not reach
/// a fixture built from an explicit env.
#[tokio::test]
#[serial_test::serial]
async fn stray_process_gradle_opts_does_not_affect_fixtures() {
    let m = Machine::new();
    m.write("build.gradle", GRADLE_ONLY);
    let before = m.roots(false).await;
    let saved: Vec<(&str, Option<std::ffi::OsString>)> = ["GRADLE_OPTS", "GRADLE_USER_HOME"]
        .into_iter()
        .map(|k| (k, std::env::var_os(k)))
        .collect();
    std::env::set_var("GRADLE_OPTS", "-Dgradle.user.home=/nonexistent/stray");
    std::env::set_var("GRADLE_USER_HOME", "/nonexistent/stray2");
    let after = m.roots(false).await;
    let gate = m.gate();
    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    assert_eq!(before, vec![m.gradle_files21()]);
    assert_eq!(after, before);
    assert_eq!(gate, M2Gate::Ignored);
}

/// `$HOME` and the passwd home: the mismatch is reported only when Gradle
/// actually falls back to the account's home.
#[test]
fn home_mismatch_only_on_fallback() {
    use socket_patch_core::crawlers::gradle_cache::home_mismatch_with;
    let env = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    let pw = Path::new("/nonexistent/passwd-home");
    assert_eq!(
        home_mismatch_with(&env(&[("HOME", "/nonexistent/h")]), Os::Unix, Some(pw)),
        Some((PathBuf::from("/nonexistent/h"), pw.to_path_buf()))
    );
    assert_eq!(
        home_mismatch_with(
            &env(&[("HOME", "/nonexistent/passwd-home")]),
            Os::Unix,
            Some(pw)
        ),
        None
    );
    assert_eq!(
        home_mismatch_with(
            &env(&[("HOME", "/nonexistent/h"), ("GRADLE_USER_HOME", "/g")]),
            Os::Unix,
            Some(pw)
        ),
        None
    );
    assert_eq!(
        home_mismatch_with(&env(&[("HOME", "/nonexistent/h")]), Os::Windows, Some(pw)),
        None
    );
}

/// Every existing local cache, Gradle first for a Gradle build, m2 first
/// otherwise, mavenLocal() or not.
#[test]
fn all_local_roots_lists_every_cache() {
    let m = Machine::new();
    let env = m.jvm_env();
    let paths = |cwd: &Path| -> Vec<PathBuf> {
        jvm_cache::all_local_roots_with(cwd, &env)
            .into_iter()
            .map(|r| r.path)
            .collect()
    };
    assert_eq!(paths(&m.project), vec![m.m2(), m.gradle_files21()]);
    m.write("build.gradle", GRADLE_ONLY);
    assert_eq!(paths(&m.project), vec![m.gradle_files21(), m.m2()]);
}
