//! Gradle discovery through the real `socket-patch scan --json`: packages
//! in a Gradle user home's `files-2.1` are found (#349), the Maven local
//! repository is left out of a Gradle-only build that never declares
//! `mavenLocal()` (#551) and the lock-membership annotation (`inLock`).
//!
//! The fabricated-cache tests run everywhere. The real-Gradle capstone
//! (`gradle_agent_349_scan_finds_gradle_cache`, `#[ignore]`) lets real
//! Gradle populate a fresh user home from the fake Central
//! (`jvm_fixture_repo`) and scans it; toolchain selection is
//! `gradle_build_common`'s `SOCKET_PATCH_GRADLE_E2E_*` knobs.

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

#[path = "gradle_build_common/mod.rs"]
mod gradle_build_common;

#[path = "jvm_fixture_repo/mod.rs"]
mod jvm_fixture_repo;

use std::path::{Path, PathBuf};

use gradle_build_common::{
    fixture_root, init_script, mirror_init_script, print_cp, print_cp_task, probe_report,
    write_project, Dsl, Gradle,
};
use prebuilt_common::fabricate_files21;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const SUITE: &str = "e2e_gradle_discovery_build";
const ORG: &str = "test-org";
const COMMONS_TEXT: &str = "pkg:maven/org.apache.commons/commons-text@1.10.0";
const BUILD_PLUGIN: &str = "pkg:maven/com.example/build-plugin@1.0";
const M2_ONLY: &str = "pkg:maven/com.example/m2-only@3.0";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// A batch endpoint that answers every queried purl with one free patch,
/// so each crawled package shows up in `packages[]`.
async fn mock_batch_all(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(|req: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let packages: Vec<serde_json::Value> = body["components"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c["purl"].as_str())
                .map(|purl| {
                    serde_json::json!({
                        "purl": purl,
                        "patches": [{
                            "uuid": "11111111-2222-4333-8444-555555555555",
                            "purl": purl, "tier": "free", "cveIds": [], "ghsaIds": [],
                            "severity": "high", "title": "gradle discovery fixture"
                        }]
                    })
                })
                .collect();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": packages, "canAccessPaidPatches": false,
            }))
        })
        .mount(server)
        .await;
}

struct Scan {
    env: serde_json::Value,
    /// Every purl the batch requests named.
    queried: Vec<String>,
    stderr: String,
}

impl Scan {
    fn warning(&self, code: &str) -> Option<String> {
        self.env["warnings"]
            .as_array()?
            .iter()
            .find(|w| w["code"] == code)
            .and_then(|w| w["detail"].as_str())
            .map(str::to_string)
    }

    /// The `level` of the run-level warning `code`.
    fn warning_level(&self, code: &str) -> Option<String> {
        self.env["warnings"]
            .as_array()?
            .iter()
            .find(|w| w["code"] == code)
            .and_then(|w| w["level"].as_str())
            .map(str::to_string)
    }

    fn package(&self, purl: &str) -> Option<&serde_json::Value> {
        self.env["packages"]
            .as_array()?
            .iter()
            .find(|p| p["purl"] == purl)
    }
}

/// `socket-patch scan --json` in `cwd` with the Gradle user home `gradle_home`
/// (`None` = no `GRADLE_USER_HOME`) and the Maven local repository `m2`,
/// plus `extra` arguments, against a mock API; every other JVM cache
/// scrubbed (`prebuilt_common::prepare_command`).
fn scan(cwd: &Path, gradle_home: Option<&Path>, m2: &Path, extra: &[&str]) -> Scan {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(async {
        let server = MockServer::start().await;
        mock_batch_all(&server).await;
        server
    });
    let mut cmd = hermetic::command(&binary());
    let uri = server.uri();
    let mut args = vec![
        "scan",
        "--json",
        "--api-url",
        uri.as_str(),
        "--api-token",
        "fake-token-for-test",
        "--org",
        ORG,
    ];
    args.extend_from_slice(extra);
    let env: Vec<(&str, &str)> = gradle_home
        .map(|h| ("GRADLE_USER_HOME", h.to_str().unwrap()))
        .into_iter()
        .collect();
    prebuilt_common::prepare_command(&mut cmd, cwd, &args, &env);
    let out = cmd
        .current_dir(cwd)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("MAVEN_REPO_LOCAL", m2)
        .env_remove("M2_HOME")
        .env_remove("VIRTUAL_ENV")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(out.status.code(), Some(0), "scan: {stdout}\n{stderr}");
    let env: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("scan: not JSON ({e})\n{stdout}\n{stderr}"));
    let mut queried: Vec<String> = rt
        .block_on(server.received_requests())
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/batch"))
        .flat_map(|r| {
            let body: serde_json::Value = serde_json::from_slice(&r.body).unwrap_or_default();
            body["components"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c["purl"].as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .collect();
    queried.sort();
    Scan {
        env,
        queried,
        stderr,
    }
}

/// A fixture machine: a project dir, a Gradle user home and an m2.
struct Fixture {
    _tmp: tempfile::TempDir,
    project: PathBuf,
    gradle_home: PathBuf,
    m2: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = fixture_root(&tmp);
        let fx = Self {
            project: root.join("project"),
            gradle_home: root.join("gradle-home"),
            m2: root.join("m2"),
            _tmp: tmp,
        };
        for dir in [&fx.project, &fx.gradle_home, &fx.m2] {
            std::fs::create_dir_all(dir).unwrap();
        }
        fx
    }

    fn write(&self, rel: &str, text: &str) {
        write_project(&self.project, &[(rel, text)]);
    }

    fn scan(&self) -> Scan {
        self.scan_with(&[])
    }

    fn scan_with(&self, extra: &[&str]) -> Scan {
        scan(&self.project, Some(&self.gradle_home), &self.m2, extra)
    }

    fn cache_commons_text(&self) -> PathBuf {
        fabricate_files21(
            &self.gradle_home,
            "org.apache.commons:commons-text:1.10.0",
            &[
                ("commons-text-1.10.0.jar", b"commons-text jar"),
                ("commons-text-1.10.0.pom", b"<project/>"),
            ],
        )
    }

    /// `<m2>/com/example/m2-only/3.0/m2-only-3.0.pom`.
    fn m2_only(&self) {
        let dir = self.m2.join("com/example/m2-only/3.0");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("m2-only-3.0.pom"),
            "<project><groupId>com.example</groupId><artifactId>m2-only</artifactId>\
             <version>3.0</version></project>",
        )
        .unwrap();
    }
}

const BUILD: &str = "plugins { id 'java' }\n\
                     repositories { mavenCentral() }\n\
                     dependencies { implementation 'org.apache.commons:commons-text:1.10.0' }\n";

/// `scan --json` on a fabricated GRADLE_USER_HOME with an empty m2 reports
/// the Gradle-cached package.
#[test]
fn scan_reports_gradle_user_home_packages_with_empty_m2() {
    let fx = Fixture::new();
    fx.write("settings.gradle", "rootProject.name = 'p'\n");
    fx.write("build.gradle", BUILD);
    let version_dir = fx.cache_commons_text();
    assert_eq!(crawled_path(&fx, COMMONS_TEXT), Some(version_dir));

    let scan = fx.scan();
    assert_eq!(scan.env["scannedPackages"], 1, "{}", scan.env);
    assert_eq!(scan.queried, vec![COMMONS_TEXT.to_string()]);
    assert!(scan.package(COMMONS_TEXT).is_some(), "{}", scan.env);
    assert_eq!(
        scan.warning("gradle_build_ignores_m2"),
        None,
        "{}",
        scan.env
    );
}

/// Lock files only annotate: a cached build-logic module no lock names is
/// still scanned (`inLock: false`), the locked one is `inLock: true`.
#[test]
fn scan_annotates_lock_membership_without_filtering() {
    let fx = Fixture::new();
    fx.write(
        "build.gradle",
        &format!(
            "buildscript {{ dependencies {{ classpath 'com.example:build-plugin:1.0' }} }}\n\
             {BUILD}dependencyLocking {{ lockAllConfigurations() }}\n"
        ),
    );
    fx.write(
        "gradle.lockfile",
        "# This is a Gradle generated file for dependency locking.\n\
         org.apache.commons:commons-text:1.10.0=compileClasspath,runtimeClasspath\n\
         empty=annotationProcessor\n",
    );
    fx.cache_commons_text();
    fabricate_files21(
        &fx.gradle_home,
        "com.example:build-plugin:1.0",
        &[("build-plugin-1.0.jar", b"plugin jar")],
    );

    let scan = fx.scan();
    assert_eq!(
        scan.queried,
        vec![BUILD_PLUGIN.to_string(), COMMONS_TEXT.to_string()]
    );
    assert_eq!(
        scan.package(COMMONS_TEXT).unwrap()["inLock"],
        true,
        "{}",
        scan.env
    );
    assert_eq!(
        scan.package(BUILD_PLUGIN).unwrap()["inLock"],
        false,
        "{}",
        scan.env
    );

    // A global run in the same build reads its locks too: `inLock` is
    // never a lock membership that was not computed.
    let files21 = fx.gradle_home.join(prebuilt_common::GRADLE_FILES21);
    for extra in [
        &["--global", "--ecosystems", "maven"][..],
        &["--global-prefix", files21.to_str().unwrap()],
    ] {
        let scan = fx.scan_with(extra);
        assert_eq!(
            scan.package(COMMONS_TEXT).unwrap()["inLock"],
            true,
            "{extra:?}: {}",
            scan.env
        );
        assert_eq!(
            scan.package(BUILD_PLUGIN).unwrap()["inLock"],
            false,
            "{extra:?}: {}",
            scan.env
        );
    }

    // Outside any Gradle build there are no locks to consult: no `inLock`.
    let elsewhere = fx.project.parent().unwrap().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let scan = crate::scan(
        &elsewhere,
        Some(&fx.gradle_home),
        &fx.m2,
        &["--global-prefix", files21.to_str().unwrap()],
    );
    let pkg = scan.package(COMMONS_TEXT).unwrap();
    assert_eq!(pkg.get("inLock"), None, "{}", scan.env);
}

/// With `--global-prefix` the cache is named outright, so the user home
/// Gradle would pick (here the passwd home, not the scrubbed `$HOME`) is
/// never mentioned.
#[test]
fn global_prefix_scan_says_nothing_about_the_user_home() {
    let fx = Fixture::new();
    fx.write("build.gradle", BUILD);
    let version_dir = fx.cache_commons_text();
    let files21 = version_dir.ancestors().nth(3).unwrap();
    let scan = scan(
        &fx.project,
        None,
        &fx.m2,
        &["--global-prefix", files21.to_str().unwrap()],
    );
    assert_eq!(scan.queried, vec![COMMONS_TEXT.to_string()], "{}", scan.env);
    assert_eq!(
        scan.warning("gradle_user_home_differs"),
        None,
        "{}",
        scan.env
    );
}

/// #551: a Gradle-only build without mavenLocal() does not scan m2, and a
/// locked module found only there is named in `gradle_build_ignores_m2`.
/// Declaring mavenLocal() brings m2 back.
#[test]
fn gradle_only_build_ignores_m2_and_says_so() {
    let fx = Fixture::new();
    fx.write("build.gradle", BUILD);
    fx.write(
        "gradle.lockfile",
        "com.example:m2-only:3.0=runtimeClasspath\n\
         org.apache.commons:commons-text:1.10.0=runtimeClasspath\n",
    );
    fx.cache_commons_text();
    fx.m2_only();

    let scan = fx.scan();
    assert_eq!(
        scan.queried,
        vec![COMMONS_TEXT.to_string()],
        "{}",
        scan.stderr
    );
    let detail = scan
        .warning("gradle_build_ignores_m2")
        .unwrap_or_else(|| panic!("no gradle_build_ignores_m2: {}", scan.env));
    assert!(detail.contains(M2_ONLY), "{detail}");
    assert!(!detail.contains(COMMONS_TEXT), "{detail}");
    assert_eq!(
        scan.warning_level("gradle_build_ignores_m2").as_deref(),
        Some("warn")
    );

    fx.write(
        "build.gradle",
        &BUILD.replace("mavenCentral()", "mavenLocal()\nmavenCentral()"),
    );
    let scan = fx.scan();
    assert_eq!(
        scan.queried,
        vec![M2_ONLY.to_string(), COMMONS_TEXT.to_string()]
    );
    assert_eq!(scan.warning("gradle_build_ignores_m2"), None);
    assert_eq!(scan.package(M2_ONLY).unwrap().get("inLock"), None);
}

/// #551: a script reference that cannot be followed keeps m2, with a note
/// saying why.
#[test]
fn undetermined_maven_local_keeps_m2_with_a_note() {
    let fx = Fixture::new();
    fx.write(
        "build.gradle",
        &format!("{BUILD}apply from: rootProject.file(System.getenv('REPOS') ?: 'r.gradle')\n"),
    );
    fx.m2_only();

    let scan = fx.scan();
    assert_eq!(scan.queried, vec![M2_ONLY.to_string()]);
    let detail = scan
        .warning("gradle_maven_local_undetermined")
        .unwrap_or_else(|| panic!("no gradle_maven_local_undetermined: {}", scan.env));
    assert!(detail.contains("mavenLocal()"), "{detail}");
    assert_eq!(
        scan.warning_level("gradle_maven_local_undetermined")
            .as_deref(),
        Some("info")
    );
}

// ── real Gradle ─────────────────────────────────────────────────────────

/// The path the crawler reports for `purl` in `fx`'s project: the first
/// root, in scan order, of `get_jvm_cache_roots_with` (under the fixture's
/// `GRADLE_USER_HOME` and m2, never the process env) that resolves it.
fn crawled_path(fx: &Fixture, purl: &str) -> Option<PathBuf> {
    use socket_patch_core::crawlers::maven_crawler::JvmEnv;
    use socket_patch_core::crawlers::types::CrawlerOptions;
    use socket_patch_core::crawlers::MavenCrawler;
    use socket_patch_core::gradle::Os;

    let env: std::collections::HashMap<String, String> = [
        ("GRADLE_USER_HOME", &fx.gradle_home),
        ("MAVEN_REPO_LOCAL", &fx.m2),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string_lossy().into_owned()))
    .collect();
    let env = JvmEnv::resolve(&env, Os::current(), None);
    let options = CrawlerOptions {
        cwd: fx.project.clone(),
        global: false,
        global_prefix: None,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for root in MavenCrawler.get_jvm_cache_roots_with(&options, &env).await {
                let found = MavenCrawler
                    .find_by_purls(&root.path, &[purl.to_string()])
                    .await
                    .unwrap_or_default();
                if let Some(pkg) = found.get(purl) {
                    return Some(pkg.path.clone());
                }
            }
            None
        })
}

/// #349 on real Gradle: Gradle resolves the fixture into a fresh user home,
/// `scan` reports the module from it (with an empty m2), and the version
/// dir the crawler reports expands to exactly the hash dir whose jar Gradle
/// put on the classpath (`victim-1.10.0.jar`'s sha1 starts with `0`, the
/// case some releases spell without the leading zero).
#[test]
#[ignore = "real Gradle (SOCKET_PATCH_GRADLE_E2E_*)"]
fn gradle_agent_349_scan_finds_gradle_cache() {
    use socket_patch_core::crawlers::gradle_cache;
    use socket_patch_core::manifest::schema::PatchFileInfo;

    let fx = Fixture::new();
    let Some(gradle) = Gradle::detect(SUITE, &fx.gradle_home) else {
        return;
    };
    let central = jvm_fixture_repo::FakeCentral::start();
    let victim = jvm_fixture_repo::victim_purl(jvm_fixture_repo::VICTIM_VERSION);
    let leaf = format!(
        "{}-{}.jar",
        jvm_fixture_repo::VICTIM,
        jvm_fixture_repo::VICTIM_VERSION
    );
    fx.write("settings.gradle", "rootProject.name = 'discovery'\n");
    fx.write(
        "build.gradle",
        &format!(
            "plugins {{ id 'java' }}\n\
             repositories {{ mavenCentral() }}\n\
             dependencies {{ implementation '{}:{}:{}' }}\n{}",
            jvm_fixture_repo::GROUP,
            jvm_fixture_repo::VICTIM,
            jvm_fixture_repo::VICTIM_VERSION,
            print_cp_task(Dsl::Groovy, "runtimeClasspath")
        ),
    );
    let init = init_script(
        &fx.project.parent().unwrap().join("init"),
        "mirror.gradle",
        &mirror_init_script(&central.uri(), None),
    );
    let out = gradle.run(
        &fx.project,
        &fx.gradle_home,
        &[&init[0], &init[1], "printRuntimeClasspath"],
    );
    let cp = print_cp(&out, "printRuntimeClasspath");
    let consumed = cp
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n == leaf.as_str()))
        .unwrap_or_else(|| panic!("no {leaf} on the classpath: {cp:?}"))
        .clone();

    let scan = fx.scan();
    assert!(
        scan.queried.contains(&victim),
        "scan did not report {victim}: {:?}\n{}",
        scan.queried,
        scan.stderr
    );
    assert!(scan.package(&victim).is_some(), "{}", scan.env);
    assert_eq!(scan.warning("gradle_build_ignores_m2"), None);

    // The crawler, over the roots this build scans (the fixture's caches,
    // in scan order), reports the version dir; installed_copies expands
    // it to the hash dir Gradle wrote and the build consumed.
    let files21 = fx.gradle_home.join(prebuilt_common::GRADLE_FILES21);
    let expected_dir = files21
        .join(jvm_fixture_repo::GROUP)
        .join(jvm_fixture_repo::VICTIM)
        .join(jvm_fixture_repo::VICTIM_VERSION);
    let version_dir = crawled_path(&fx, &victim)
        .unwrap_or_else(|| panic!("the crawler does not resolve {victim}"));
    assert_eq!(version_dir, expected_dir);
    assert!(gradle_cache::is_gradle_version_dir(&version_dir));
    let files = std::collections::HashMap::from([(
        leaf.clone(),
        PatchFileInfo {
            before_hash: "x".into(),
            after_hash: "y".into(),
        },
    )]);
    let copies = gradle_cache::installed_copies_detailed(&version_dir, &files);
    assert!(copies.missing.is_empty(), "{copies:?}");
    let consumed_dir = std::fs::canonicalize(consumed.parent().unwrap()).unwrap();
    let dirs: Vec<PathBuf> = copies
        .targets
        .iter()
        .map(|(d, _)| std::fs::canonicalize(d).unwrap())
        .collect();
    assert_eq!(dirs, vec![consumed_dir.clone()], "{copies:?}");
    let hash_dir = consumed_dir
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let jar = std::fs::read(&consumed).unwrap();
    assert!(gradle_cache::pristine(&hash_dir, &jar), "{hash_dir}");
    let sha1 = jvm_fixture_repo::sha1_hex(&jar);
    probe_report(
        &format!("{SUITE}-349-gradle-{}", gradle.version),
        &serde_json::json!({
            "gradle": gradle.version,
            "jvm": gradle.jvm,
            "jar": leaf,
            "sha1": sha1,
            "hashDir": hash_dir,
            "leadingZeroDropped": hash_dir.len() < 40,
        }),
    );
}
