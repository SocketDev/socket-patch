//! The Coursier and Ivy arms of [`MavenCrawler`]: a Coursier cache
//! directory expands to its per-repository roots (each crawled with the
//! Maven2 logic), a repository root is crawled as Maven2, an Ivy root goes
//! through `ivy_cache`, the first root holding a PURL wins, and the serial
//! oracle only ever covers Maven2 roots.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::oracle::{crawl_all_content_first, LegacyMavenCrawler};
use super::MavenCrawler;
use crate::crawlers::jvm_cache::{JvmCacheLayout, JvmCacheRoot};
use crate::crawlers::types::{CrawledPackage, CrawlerOptions};

fn write(p: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

/// `g:a:v` in a Maven2 tree at `root`; the version directory.
fn m2(root: &Path, g: &str, a: &str, v: &str) -> PathBuf {
    let dir = root.join(g.replace('.', "/")).join(a).join(v);
    write(
        &dir.join(format!("{a}-{v}.pom")),
        format!("<project><groupId>{g}</groupId><artifactId>{a}</artifactId><version>{v}</version></project>").as_bytes(),
    );
    write(&dir.join(format!("{a}-{v}.jar")), b"jar");
    write(&dir.join(format!(".{a}-{v}.jar__sha1")), b"0");
    dir
}

/// `org:module:rev` in an Ivy cache at `root`; the artifact directory.
fn ivy(root: &Path, org: &str, module: &str, rev: &str) -> PathBuf {
    let dir = root.join(org).join(module);
    write(
        &dir.join(format!("ivy-{rev}.xml")),
        format!("<ivy-module><info organisation=\"{org}\" module=\"{module}\" revision=\"{rev}\"/></ivy-module>").as_bytes(),
    );
    write(&dir.join(format!("jars/{module}-{rev}.jar")), b"jar");
    dir.join("jars")
}

fn options(prefix: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: prefix.to_path_buf(),
        global: false,
        global_prefix: Some(prefix.to_path_buf()),
    }
}

fn rows(found: &[CrawledPackage]) -> Vec<(String, PathBuf)> {
    let mut rows: Vec<_> = found
        .iter()
        .map(|p| (p.purl.clone(), p.path.clone()))
        .collect();
    rows.sort();
    rows
}

/// A Coursier cache: Central and a corporate mirror both hold slf4j (the
/// mirror's host sorts first, so its copy wins), Central alone gson.
fn coursier_cache(tmp: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let cache = tmp.join("coursier/v1");
    let central = cache.join("https/repo1.maven.org/maven2");
    let mirror = cache.join("https/maven.corp/artifactory/libs");
    let slf4j = m2(&mirror, "org.slf4j", "slf4j-api", "1.7.36");
    m2(&central, "org.slf4j", "slf4j-api", "1.7.36");
    let gson = m2(&central, "com.google.code.gson", "gson", "2.8.9");
    (cache, central, slf4j, gson)
}

#[tokio::test]
async fn a_coursier_cache_dir_expands_to_its_repository_roots() {
    let tmp = tempfile::tempdir().unwrap();
    let (cache, _central, slf4j, gson) = coursier_cache(tmp.path());
    assert_eq!(JvmCacheLayout::classify(&cache), JvmCacheLayout::Coursier);
    let found = MavenCrawler::new().crawl_all(&options(&cache)).await;
    assert_eq!(
        rows(&found),
        vec![
            (
                "pkg:maven/com.google.code.gson/gson@2.8.9".to_string(),
                gson.clone()
            ),
            (
                "pkg:maven/org.slf4j/slf4j-api@1.7.36".to_string(),
                slf4j.clone()
            ),
        ],
        "first repository root wins the dedup"
    );
    let purls = [
        "pkg:maven/org.slf4j/slf4j-api@1.7.36".to_string(),
        "pkg:maven/com.google.code.gson/gson@2.8.9".to_string(),
        "pkg:maven/x/y@1".to_string(),
    ];
    let hits = MavenCrawler::new()
        .find_by_purls(&cache, &purls)
        .await
        .unwrap();
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[&purls[0]].path, slf4j);
    assert_eq!(hits[&purls[1]].path, gson);
}

#[tokio::test]
async fn a_coursier_repository_root_is_a_maven2_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let (_cache, central, _slf4j, gson) = coursier_cache(tmp.path());
    assert_eq!(JvmCacheLayout::classify(&central), JvmCacheLayout::Coursier);
    let found = MavenCrawler::new().crawl_all(&options(&central)).await;
    assert_eq!(found.len(), 2);
    let purl = "pkg:maven/com.google.code.gson/gson@2.8.9".to_string();
    let hits = MavenCrawler::new()
        .find_by_purls(&central, std::slice::from_ref(&purl))
        .await
        .unwrap();
    assert_eq!(hits[&purl].path, gson);
    // A `COURSIER_CACHE`-style directory whose name spells nothing still
    // resolves through the Maven2 logic (no `https/` child: not a cache).
    let plain = tmp.path().join("cs-plain");
    let dir = m2(&plain, "org.a", "b", "1");
    let hits = MavenCrawler::new()
        .find_by_purls(&plain, &["pkg:maven/org.a/b@1".to_string()])
        .await
        .unwrap();
    assert_eq!(hits["pkg:maven/org.a/b@1"].path, dir);
}

#[tokio::test]
async fn an_ivy_root_goes_through_the_ivy_crawler() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".ivy2/cache");
    let jars = ivy(&root, "org.slf4j", "slf4j-api", "1.7.36");
    assert_eq!(JvmCacheLayout::classify(&root), JvmCacheLayout::Ivy);
    let found = MavenCrawler::new().crawl_all(&options(&root)).await;
    assert_eq!(
        rows(&found),
        vec![(
            "pkg:maven/org.slf4j/slf4j-api@1.7.36".to_string(),
            jars.clone()
        )]
    );
    let purl = "pkg:maven/org.slf4j/slf4j-api@1.7.36".to_string();
    let hits = MavenCrawler::new()
        .find_by_purls(&root, std::slice::from_ref(&purl))
        .await
        .unwrap();
    assert_eq!(hits[&purl].path, jars);
}

#[test]
fn the_first_root_holding_a_purl_wins_across_layouts() {
    let tmp = tempfile::tempdir().unwrap();
    let m2_root = tmp.path().join("m2/repository");
    let m2_dir = m2(&m2_root, "org.slf4j", "slf4j-api", "1.7.36");
    let (cache, _central, _slf4j, gson) = coursier_cache(tmp.path());
    let ivy_root = tmp.path().join("ivy2/cache");
    ivy(&ivy_root, "com.google.code.gson", "gson", "2.8.9");
    let ivy_only = ivy(&ivy_root, "org.ivy", "only", "1");
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    for root in [
        JvmCacheRoot::new(m2_root, JvmCacheLayout::Maven2),
        JvmCacheRoot::new(cache, JvmCacheLayout::Coursier),
        JvmCacheRoot::new(ivy_root, JvmCacheLayout::Ivy),
    ] {
        found.extend(MavenCrawler.scan_cache_root(&root, &mut seen));
    }
    assert_eq!(
        rows(&found),
        vec![
            (
                "pkg:maven/com.google.code.gson/gson@2.8.9".to_string(),
                gson
            ),
            ("pkg:maven/org.ivy/only@1".to_string(), ivy_only),
            ("pkg:maven/org.slf4j/slf4j-api@1.7.36".to_string(), m2_dir),
        ]
    );
}

/// The serial oracle predates the Coursier and Ivy caches: it covers the
/// Maven2 roots only, so a Coursier cache directory or an Ivy root gives it
/// nothing while the crawler finds their packages.
#[tokio::test]
async fn the_oracle_covers_maven2_roots_only() {
    let tmp = tempfile::tempdir().unwrap();
    let (cache, ..) = coursier_cache(tmp.path());
    let ivy_root = tmp.path().join(".ivy2/cache");
    ivy(&ivy_root, "org.slf4j", "slf4j-api", "1.7.36");
    for prefix in [cache.as_path(), ivy_root.as_path()] {
        let options = options(prefix);
        assert!(LegacyMavenCrawler::crawl_all(&options).await.is_empty());
        assert!(crawl_all_content_first(&options).await.is_empty());
        assert!(!MavenCrawler::new().crawl_all(&options).await.is_empty());
    }
    // A Maven2 root is still covered.
    let m2_root = tmp.path().join("repository");
    m2(&m2_root, "org.a", "b", "1");
    let options = options(&m2_root);
    assert_eq!(
        rows(&LegacyMavenCrawler::crawl_all(&options).await),
        rows(&MavenCrawler::new().crawl_all(&options).await)
    );
}

/// A Coursier version directory holding only its pom (a version Coursier
/// considered and evicted) is no installed copy: neither crawled nor
/// resolved, at a repository root or a host-level one.
#[tokio::test]
async fn a_pom_only_coursier_directory_is_no_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let (cache, central, ..) = coursier_cache(tmp.path());
    let evicted = m2(&central, "org.slf4j", "slf4j-api", "1.7.30");
    std::fs::remove_file(evicted.join("slf4j-api-1.7.30.jar")).unwrap();
    std::fs::remove_file(evicted.join(".slf4j-api-1.7.30.jar__sha1")).unwrap();
    write(&evicted.join(".slf4j-api-1.7.30.pom__sha1"), b"0");
    let host = cache.join("https/host.example");
    let host_evicted = m2(&host, "org.h", "h", "1");
    std::fs::remove_file(host_evicted.join("h-1.jar")).unwrap();
    let purls = [
        "pkg:maven/org.slf4j/slf4j-api@1.7.30".to_string(),
        "pkg:maven/org.h/h@1".to_string(),
    ];
    for prefix in [&cache, &central, &host] {
        let found = MavenCrawler::new().crawl_all(&options(prefix)).await;
        assert!(
            !found.iter().any(|p| purls.contains(&p.purl)),
            "{prefix:?}: {:?}",
            rows(&found)
        );
        let hits = MavenCrawler::new()
            .find_by_purls(prefix, &purls)
            .await
            .unwrap();
        assert!(hits.is_empty(), "{prefix:?}: {hits:?}");
    }
    // A Maven local repository keeps its pom-only directories.
    let m2_root = tmp.path().join("m2/repository");
    let parent = m2(&m2_root, "org.p", "parent", "1");
    std::fs::remove_file(parent.join("parent-1.jar")).unwrap();
    let purl = "pkg:maven/org.p/parent@1".to_string();
    let hits = MavenCrawler::new()
        .find_by_purls(&m2_root, std::slice::from_ref(&purl))
        .await
        .unwrap();
    assert_eq!(hits[&purl].path, parent);
}

/// Points every JVM-cache environment source at `tmp` for a test's
/// duration (an empty home: the machine's own caches never join in), and
/// restores them after.
struct Hermetic(Vec<(&'static str, Option<String>)>);

impl Hermetic {
    fn new(home: &Path, vars: &[(&'static str, String)]) -> Self {
        const CLEARED: &[&str] = &[
            "XDG_CACHE_HOME",
            "LOCALAPPDATA",
            "JAVA_OPTS",
            "M2_HOME",
            "GRADLE_OPTS",
            "GRADLE_RO_DEP_CACHE",
        ];
        // Gradle's user home comes from the passwd entry on Unix, not
        // `HOME`: pin it into the stand-in home too.
        let mut keys: Vec<&'static str> = vec!["HOME", "USERPROFILE", "GRADLE_USER_HOME"];
        keys.extend(CLEARED);
        keys.extend(vars.iter().map(|(k, _)| *k));
        let saved = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();
        std::fs::create_dir_all(home).unwrap();
        std::env::set_var("HOME", home);
        std::env::set_var("USERPROFILE", home);
        std::env::set_var("GRADLE_USER_HOME", home.join(".gradle"));
        for key in CLEARED {
            std::env::remove_var(key);
        }
        for (key, value) in vars {
            std::env::set_var(key, value);
        }
        Hermetic(saved)
    }
}

impl Drop for Hermetic {
    fn drop(&mut self) {
        for (key, prev) in &self.0 {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

/// Discovery order: `~/.m2`, then Coursier's repository roots, then the
/// Ivy caches. Env-driven (`MAVEN_REPO_LOCAL`, `COURSIER_CACHE`,
/// `SBT_OPTS`, an empty `HOME`), so serialized with the other env-mutating
/// crawler tests.
#[tokio::test]
#[serial_test::serial]
async fn discovery_order_is_m2_then_coursier_then_ivy() {
    let tmp = tempfile::tempdir().unwrap();
    let m2_root = tmp.path().join("m2");
    m2(&m2_root, "org.socket.test", "order", "1");
    let cs = tmp.path().join("cs");
    let repo = cs.join("https/repo.example/maven2");
    m2(&repo, "org.socket.test", "order", "1");
    let host_repo = cs.join("https/host.example");
    m2(&host_repo, "org.socket.test", "host", "1");
    let ivy_home = tmp.path().join("ivy-home");
    ivy(&ivy_home.join("cache"), "org.socket.test", "order", "1");
    // An Ivy home whose path spells no Ivy layout is skipped.
    let odd = tmp.path().join("odd");
    ivy(&odd.join("cache"), "org.socket.test", "odd", "1");
    let vars = [
        ("MAVEN_REPO_LOCAL", m2_root.display().to_string()),
        ("COURSIER_CACHE", cs.display().to_string()),
        (
            "SBT_OPTS",
            format!(
                "-Dsbt.ivy.home={} -Divy.home={}",
                ivy_home.display(),
                odd.display()
            ),
        ),
    ];
    let _env = Hermetic::new(&tmp.path().join("home"), &vars);
    let options = CrawlerOptions {
        cwd: tmp.path().to_path_buf(),
        global: true,
        global_prefix: None,
    };
    let roots = MavenCrawler::new().get_jvm_cache_roots(&options).await;
    let ours: Vec<&JvmCacheRoot> = roots.iter().collect();
    assert_eq!(
        ours,
        vec![
            &JvmCacheRoot::new(m2_root.clone(), JvmCacheLayout::Maven2),
            // Hosts in name order; a host-level repository spells Maven2.
            &JvmCacheRoot::new(host_repo.clone(), JvmCacheLayout::Maven2),
            &JvmCacheRoot::new(repo.clone(), JvmCacheLayout::Coursier),
            &JvmCacheRoot::new(ivy_home.join("cache"), JvmCacheLayout::Ivy),
        ],
        "{roots:?}"
    );
    // The crawl: `~/.m2` wins the shared GAV; every layout contributes.
    let found = MavenCrawler::new().crawl_all(&options).await;
    assert!(found.iter().all(|p| p.path.starts_with(tmp.path())));
    let mine: Vec<_> = found
        .iter()
        .map(|p| (p.purl.as_str(), p.path.clone()))
        .collect();
    assert!(mine.contains(&(
        "pkg:maven/org.socket.test/order@1",
        m2_root.join("org/socket/test/order/1")
    )));
    assert!(mine.contains(&(
        "pkg:maven/org.socket.test/host@1",
        host_repo.join("org/socket/test/host/1")
    )));
    assert!(!mine.iter().any(|(purl, _)| purl.contains("/odd@")));
    assert_eq!(
        mine.iter()
            .filter(|(purl, _)| purl.contains("/order@"))
            .count(),
        1
    );
}

/// Locally, the Coursier / Ivy / evidence roots join `~/.m2` only for an
/// sbt, Mill or scala-cli project: a Maven or Gradle build never reads
/// them, so it neither crawls nor patches them.
#[tokio::test]
#[serial_test::serial]
async fn local_scala_caches_only_for_scala_tool_projects() {
    let tmp = tempfile::tempdir().unwrap();
    let m2_root = tmp.path().join("m2");
    m2(&m2_root, "org.socket.test", "order", "1");
    let cs = tmp.path().join("cs");
    let repo = cs.join("https/repo.example/maven2");
    m2(&repo, "org.socket.test", "order", "1");
    let _env = Hermetic::new(
        &tmp.path().join("home"),
        &[
            ("MAVEN_REPO_LOCAL", m2_root.display().to_string()),
            ("COURSIER_CACHE", cs.display().to_string()),
            ("SBT_OPTS", String::new()),
        ],
    );
    let roots_of = |marker: &str| {
        let project = tmp.path().join(format!("p-{}", marker.replace('/', "-")));
        write(&project.join(marker), b"");
        async move {
            MavenCrawler::new()
                .get_jvm_cache_roots(&CrawlerOptions {
                    cwd: project,
                    global: false,
                    global_prefix: None,
                })
                .await
        }
    };
    let m2_only = vec![JvmCacheRoot::new(m2_root.clone(), JvmCacheLayout::Maven2)];
    assert_eq!(roots_of("pom.xml").await, m2_only, "pom.xml");
    // A Gradle-only build without `mavenLocal()` does not even read `~/.m2`
    // (the Gradle caches are empty here); never the Scala caches.
    for marker in ["build.gradle", "settings.gradle.kts"] {
        assert_eq!(roots_of(marker).await, Vec::new(), "{marker}");
    }
    for marker in [
        "build.sbt",
        "build.mill",
        "build.sc",
        "project.scala",
        "project/build.properties",
    ] {
        let roots = roots_of(marker).await;
        if marker == "project/build.properties" {
            // Not a JVM project marker on its own (too generic a name).
            assert!(roots.is_empty(), "{marker}: {roots:?}");
            continue;
        }
        assert!(
            roots.contains(&JvmCacheRoot::new(repo.clone(), JvmCacheLayout::Coursier)),
            "{marker}: {roots:?}"
        );
    }
}

/// An Ivy artifact directory expands over its module's type dirs: the
/// jar in `jars/`, the sources jar in `srcs/`; a key no type dir holds
/// stays joined onto the crawled directory (reported not found).
#[test]
fn installed_copies_expands_an_ivy_artifact_dir() {
    use crate::crawlers::gradle_cache::{expands, installed_copies, installed_copies_detailed};
    use crate::manifest::schema::PatchFileInfo;
    use std::collections::HashMap;
    let tmp = tempfile::tempdir().unwrap();
    let jars = ivy(&tmp.path().join("ivy/cache"), "org.socket.test", "lib", "1");
    let module = jars.parent().unwrap().to_path_buf();
    write(&module.join("srcs/lib-1-sources.jar"), b"src");
    let info = |h: &str| PatchFileInfo {
        before_hash: h.repeat(64),
        after_hash: h.repeat(64),
    };
    let files: HashMap<String, PatchFileInfo> = [
        ("package/lib-1.jar", "a"),
        ("package/lib-1-sources.jar", "b"),
        ("package/lib-1.pom", "c"),
    ]
    .into_iter()
    .map(|(k, h)| (k.to_string(), info(h)))
    .collect();
    assert!(expands(&jars));
    assert!(!expands(&module), "the module dir is no package dir");
    let detailed = installed_copies_detailed(&jars, &files);
    let targets: Vec<(PathBuf, Vec<String>)> = detailed
        .targets
        .iter()
        .map(|(dir, files)| {
            let mut keys: Vec<String> = files.keys().cloned().collect();
            keys.sort();
            (dir.clone(), keys)
        })
        .collect();
    assert_eq!(
        targets,
        vec![
            (module.join("jars"), vec!["lib-1.jar".to_string()]),
            (module.join("srcs"), vec!["lib-1-sources.jar".to_string()]),
        ]
    );
    assert_eq!(detailed.missing, vec!["package/lib-1.pom".to_string()]);
    let all = installed_copies(&jars, &files);
    assert_eq!(all.len(), 3);
    assert_eq!(all[2].0, jars, "the missing pom stays on the crawled dir");
    // A Maven2 / Coursier version dir is joined as is.
    let repo = m2(
        &tmp.path().join("cs/https/h/maven2"),
        "org.socket.test",
        "lib",
        "1",
    );
    assert!(!expands(&repo));
    assert_eq!(
        installed_copies(&repo, &files),
        vec![(repo.clone(), files.clone())]
    );
}

/// `locate_artifact` finds a file's copy in a Coursier cache (through its
/// repository roots) and in an Ivy cache (in any artifact type dir).
#[test]
fn locate_artifact_reads_coursier_and_ivy_caches() {
    use crate::crawlers::jvm_cache::locate_artifact;
    let tmp = tempfile::tempdir().unwrap();
    let (cache, central, _, gson) = coursier_cache(tmp.path());
    let gav = (
        "com.google.code.gson".to_string(),
        "gson".to_string(),
        "2.8.9".to_string(),
    );
    let jar = gson.join("gson-2.8.9.jar");
    for root in [
        JvmCacheRoot::new(cache.clone(), JvmCacheLayout::Coursier),
        JvmCacheRoot::new(central.clone(), JvmCacheLayout::Coursier),
    ] {
        assert_eq!(locate_artifact(&root, &gav, None, "jar"), vec![jar.clone()]);
    }
    let ivy_root = tmp.path().join("ivy/cache");
    let jars = ivy(&ivy_root, "org.socket.test", "lib", "1");
    write(
        &jars.parent().unwrap().join("srcs/lib-1-sources.jar"),
        b"src",
    );
    let root = JvmCacheRoot::new(ivy_root, JvmCacheLayout::Ivy);
    let lib = (
        "org.socket.test".to_string(),
        "lib".to_string(),
        "1".to_string(),
    );
    assert_eq!(
        locate_artifact(&root, &lib, None, "jar"),
        vec![jars.join("lib-1.jar")]
    );
    assert_eq!(
        locate_artifact(&root, &lib, Some("sources"), "jar"),
        vec![jars.parent().unwrap().join("srcs/lib-1-sources.jar")]
    );
}
