//! Real-tool capstones for the v5 JVM vendored backend
//! (`docs/design/maven-vendoring.md`): Maven reactors and Gradle builds.
//!
//! Both start from the ACTUAL registry bytes of `commons-text:1.10.0` (see
//! `maven_build_common`), stage a marker patch on its `META-INF/NOTICE.txt`
//! (manifest + blob), run the real binary's `vendor --json --offline`, and:
//!
//! * **Maven reactor** — an aggregator root, a separate corp parent module
//!   and two modules (`a` declares the base literally, with CRLF + tabs;
//!   `b` reaches it only through sibling `a`). The plan's edits are asserted
//!   exactly (2-line `.mvn/maven.config`, the `maven2` tree, the corp
//!   parent's repository + pin, `a`'s rewrite, aggregator and `b`
//!   untouched). A fresh checkout with commons-text purged from the local
//!   repository then builds offline from the root and from `cd a`, and
//!   every resolved classpath carries the vendored suffixed jar with the
//!   patched NOTICE. `vendor --revert` restores every file byte-for-byte.
//! * **Gradle multi-project** — Kotlin DSL settings with
//!   `FAIL_ON_PROJECT_REPOS` and `mavenCentral()`, `app` → `lib`, STRICT
//!   `lockAllConfigurations()` with lockfiles written before vendoring. After
//!   vendoring the lockfiles are byte-unchanged, `:app` runtimeClasspath
//!   resolves the vendored jar online and `--offline`, a tampered vendored
//!   jar fails the build with the socket-patch message, and
//!   `vendor --revert` is byte-exact. It needs no Maven: the CLI reads the
//!   registry bytes from the Gradle cache the build fills.
//!
//! Gated like the other real-toolchain capstones: `#[ignore]` (network to
//! Maven Central), Maven via `SOCKET_PATCH_MAVEN_E2E_{MVN,VERSION,REQUIRED}`
//! (`maven_build_common`), Gradle via `SOCKET_PATCH_GRADLE_E2E_GRADLE` (the
//! launcher; default `gradle` on `PATH`), `SOCKET_PATCH_GRADLE_E2E_VERSION`
//! (the version it must report) and `SOCKET_PATCH_GRADLE_E2E_REQUIRED` (no
//! SKIP) (`gradle_build_common`). Scratch trees go under `TMPDIR`.

#[path = "common/mod.rs"]
mod common;
use common::{binary, git_sha256};

#[path = "maven_build_common/mod.rs"]
mod maven_build_common;

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

#[path = "gradle_build_common/mod.rs"]
mod gradle_build_common;

#[path = "jvm_fixture_repo/mod.rs"]
mod jvm_fixture_repo;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use gradle_build_common::{
    assert_patched, configuration_reused, fixture_root, gradle_classpath, gradle_skip, init_script,
    lockfiles, mirror_init_script, print_cp_task, probe_report, snapshot, write_both_dsls,
    write_project, Dsl, Gradle,
};
use maven_build_common::*;

const UUID: &str = "1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const SV: &str = "1.10.0-socket.1d3c1fd2";

/// The classpath probe. Not [`DEPENDENCY_PLUGIN`]: 3.6.x itself depends on
/// `commons-text:1.10.0` (3.5.0 on 1.3), so purging the fixture version from
/// the local repository would break the plugin realm, not the project.
const CLASSPATH_PLUGIN: &str = "org.apache.maven.plugins:maven-dependency-plugin:3.5.0";

/// `socket-patch <args>` with ambient `SOCKET_*` scrubbed, `m2` as the Maven
/// repo and, when given, `gradle_home` as the `GRADLE_USER_HOME` the CLI
/// crawls (and the fixture registry serves).
fn socket_in(
    cwd: &Path,
    m2: &Path,
    gradle_home: Option<&Path>,
    args: &[&str],
) -> (Option<i32>, serde_json::Value, String) {
    let mut cmd = Command::new(binary());
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    let mut caches = vec![("MAVEN_REPO_LOCAL", m2.to_str().unwrap())];
    if let Some(home) = gradle_home {
        caches.push(("GRADLE_USER_HOME", home.to_str().unwrap()));
    }
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, &caches);
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
    let env = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{args:?}: not JSON ({e})\n{stdout}\n{stderr}"));
    (out.status.code(), env, stderr)
}

fn vendor(proj: &Path, m2: &Path) -> serde_json::Value {
    vendor_in(proj, m2, None)
}

fn vendor_in(proj: &Path, m2: &Path, gradle_home: Option<&Path>) -> serde_json::Value {
    let (code, env, stderr) = socket_in(
        proj,
        m2,
        gradle_home,
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(0), "vendor: {env}\n{stderr}");
    assert_eq!(env["summary"]["failed"], 0, "{env}");
    env
}

fn revert(proj: &Path, m2: &Path) {
    revert_in(proj, m2, None)
}

fn revert_in(proj: &Path, m2: &Path, gradle_home: Option<&Path>) {
    let (code, env, stderr) = socket_in(
        proj,
        m2,
        gradle_home,
        &[
            "vendor",
            "--revert",
            "--json",
            "--offline",
            "--cwd",
            proj.to_str().unwrap(),
        ],
    );
    assert_eq!(code, Some(0), "vendor --revert: {env}\n{stderr}");
}

/// What `get` saves for an agent-mode patch: the manifest record + the
/// after-hash blob (so `vendor --offline` needs no network).
fn stage_manifest(proj: &Path, member_before: &[u8], member_after: &[u8]) {
    let record = serde_json::json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { MEMBER: {
            "beforeHash": git_sha256(member_before),
            "afterHash": git_sha256(member_after),
        } },
        "vulnerabilities": { "GHSA-vendor-jvm-real": {
            "cves": ["CVE-2026-7203"], "summary": "s", "severity": "high", "description": "d"
        } },
        "description": "jvm vendored capstone",
        "license": "MIT",
        "tier": "free",
    });
    let manifest = serde_json::json!({ "patches": { purl(): record } });
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    std::fs::write(
        proj.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        proj.join(".socket/blobs").join(git_sha256(member_after)),
        member_after,
    )
    .unwrap();
}

/// `(changed, added, removed)` paths from `before` to `after`.
fn diff(
    before: &BTreeMap<String, Vec<u8>>,
    after: &BTreeMap<String, Vec<u8>>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let changed = after
        .iter()
        .filter(|(k, v)| before.get(*k).is_some_and(|b| b != *v))
        .map(|(k, _)| k.clone())
        .collect();
    let added = after
        .keys()
        .filter(|k| !before.contains_key(*k))
        .cloned()
        .collect();
    let removed = before
        .keys()
        .filter(|k| !after.contains_key(*k))
        .cloned()
        .collect();
    (changed, added, removed)
}

fn assert_restored(proj: &Path, before: &BTreeMap<String, Vec<u8>>) {
    let after = snapshot(proj);
    let (changed, added, removed) = diff(before, &after);
    assert!(
        changed.is_empty() && added.is_empty() && removed.is_empty(),
        "revert must restore the tree byte-for-byte: changed {changed:?}, added {added:?}, \
         removed {removed:?}"
    );
}

/// A fresh checkout of `proj` in `dst`: every committable file, minus the
/// manifest and blobs (a vendored checkout builds without them).
fn fresh_checkout_all(proj: &Path, dst: &Path) {
    for (rel, bytes) in snapshot(proj) {
        if rel == ".socket/manifest.json" || rel.starts_with(".socket/blobs/") {
            continue;
        }
        let to = dst.join(&rel);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::write(to, bytes).unwrap();
    }
}

/// Drop the base and suffixed fixture versions from the local repository
/// (other commons-text versions stay: [`CLASSPATH_PLUGIN`] runs on one).
fn purge(m2: &Path) {
    for version in [VERSION, SV] {
        let dir = repo_dir(m2, version);
        if dir.exists() {
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).unwrap()
}

// ── P1: multi-module Maven reactor ──────────────────────────────────────

const AGGREGATOR_POM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>aggregator</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>corp-parent</module>
    <module>a</module>
    <module>b</module>
  </modules>
</project>
"#;

const CORP_PARENT_POM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <!-- the corp parent every module inherits -->
  <groupId>com.example</groupId>
  <artifactId>corp-parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <properties>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
</project>
"#;

const B_POM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>corp-parent</artifactId>
    <version>1.0.0</version>
    <relativePath>../corp-parent</relativePath>
  </parent>
  <artifactId>b</artifactId>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>a</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>
"#;

/// Module `a`: CRLF line endings and tab indentation, a comment, and the
/// patched library declared at its literal base version.
fn a_pom() -> String {
    [
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        r#"<project xmlns="http://maven.apache.org/POM/4.0.0">"#,
        "\t<modelVersion>4.0.0</modelVersion>",
        "\t<parent>",
        "\t\t<groupId>com.example</groupId>",
        "\t\t<artifactId>corp-parent</artifactId>",
        "\t\t<version>1.0.0</version>",
        "\t\t<relativePath>../corp-parent/pom.xml</relativePath>",
        "\t</parent>",
        "\t<artifactId>a</artifactId>",
        "\t<dependencies>",
        "\t\t<!-- text utilities -->",
        "\t\t<dependency>",
        "\t\t\t<groupId>org.apache.commons</groupId>",
        "\t\t\t<artifactId>commons-text</artifactId>",
        "\t\t\t<version>1.10.0</version>",
        "\t\t</dependency>",
        "\t</dependencies>",
        "</project>",
        "",
    ]
    .join("\r\n")
}

fn write_reactor(proj: &Path) {
    for (rel, body) in [
        ("pom.xml", AGGREGATOR_POM.to_string()),
        ("corp-parent/pom.xml", CORP_PARENT_POM.to_string()),
        ("a/pom.xml", a_pom()),
        ("b/pom.xml", B_POM.to_string()),
    ] {
        let path = proj.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }
}

fn maven_tree_rel() -> String {
    format!(".socket/vendor/maven2/{GROUP_PATH}/{ARTIFACT}/{SV}")
}

/// `package` + `build-classpath` into each module's `target/cp.txt`.
fn mvn_classpath(mvn: &Mvn, cwd: &Path, m2: &Path, settings: &Path, offline: bool) -> Output {
    let goal = format!("{CLASSPATH_PLUGIN}:build-classpath");
    let mut args = vec!["package", goal.as_str(), "-Dmdep.outputFile=target/cp.txt"];
    if offline {
        args.insert(0, "-o");
    }
    mvn.run(cwd, m2, settings, &args)
}

/// The commons-text entry of `<module>/target/cp.txt`.
fn classpath_entry(module_dir: &Path) -> PathBuf {
    let cp = std::fs::read_to_string(module_dir.join("target/cp.txt"))
        .unwrap_or_else(|e| panic!("{}: no target/cp.txt ({e})", module_dir.display()));
    let sep = if cfg!(windows) { ';' } else { ':' };
    let hits: Vec<&str> = cp
        .trim()
        .split(sep)
        .filter(|p| p.contains(ARTIFACT))
        .collect();
    assert_eq!(hits.len(), 1, "{}: classpath {cp}", module_dir.display());
    PathBuf::from(hits[0])
}

fn assert_vendored_on_classpath(module_dir: &Path, patched: &[u8], what: &str) {
    let entry = classpath_entry(module_dir);
    assert_eq!(
        entry.file_name().unwrap().to_string_lossy(),
        format!("{ARTIFACT}-{SV}.jar"),
        "{what}: resolved {}",
        entry.display()
    );
    let jar = std::fs::read(&entry).unwrap();
    assert_jar_patched(&jar, patched, what);
    println!("{what}: resolved {}", entry.display());
}

#[test]
#[ignore = "real Maven + Maven Central (fixture); run with --ignored"]
fn maven_reactor_vendor_fresh_checkout_offline_build_and_byte_exact_revert() {
    const SUITE: &str = "e2e_vendor_jvm_build::maven_reactor";
    let Some(mvn) = Mvn::detect(SUITE) else {
        return;
    };
    let tmp = tempfile::tempdir().unwrap();
    let root = fixture_root(&tmp);
    let m2 = root.join("m2");
    let proj = root.join("proj");
    let settings = root.join("settings.xml");
    write_settings(&settings, &[]);

    // Registry bytes + every plugin the offline builds need.
    let Some((jar, upstream_pom)) = warm_fixture(SUITE, &mvn, &root.join("warm"), &m2, &settings)
    else {
        return;
    };
    write_reactor(&proj);
    let out = mvn_classpath(&mvn, &proj, &m2, &settings, false);
    assert!(ok(&out), "pre-vendor reactor build:\n{}", dump(&out));
    let entry = classpath_entry(&proj.join("b"));
    assert_eq!(
        std::fs::read(&entry).unwrap(),
        jar,
        "pre-vendor `b` resolves Central's jar transitively"
    );
    // Maven 4 keeps its project-local repository in `.mvn/target/`.
    for dir in [
        "target",
        "corp-parent/target",
        "a/target",
        "b/target",
        ".mvn/target",
    ] {
        let _ = std::fs::remove_dir_all(proj.join(dir));
    }
    let _ = std::fs::remove_dir(proj.join(".mvn"));
    assert!(!proj.join(".mvn").exists(), "no .mvn before vendoring");

    let (orig, patched) = patched_member(&jar, UUID);
    stage_manifest(&proj, &orig, &patched);
    let before = snapshot(&proj);

    let env = vendor(&proj, &m2);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    println!("vendor envelope: {env}");
    let vendored = snapshot(&proj);
    let (changed, added, removed) = diff(&before, &vendored);
    let tree = maven_tree_rel();
    let mut want_added = vec![
        ".mvn/maven.config".to_string(),
        ".socket/vendor/maven2/.gitattributes".to_string(),
        format!("{tree}/{ARTIFACT}-{SV}.jar"),
        format!("{tree}/{ARTIFACT}-{SV}.jar.sha1"),
        format!("{tree}/{ARTIFACT}-{SV}.pom"),
        format!("{tree}/{ARTIFACT}-{SV}.pom.sha1"),
        format!("{tree}/socket-patch.vendor.json"),
        ".socket/vendor/state.json".to_string(),
    ];
    want_added.sort();
    assert_eq!(added, want_added, "added files");
    assert!(removed.is_empty(), "removed {removed:?}");
    assert_eq!(
        changed,
        vec!["a/pom.xml".to_string(), "corp-parent/pom.xml".to_string()],
        "only the literal module and the local root are edited (aggregator and `b` untouched)"
    );

    assert_eq!(
        text(&vendored[".mvn/maven.config"]),
        "-Daether.offline.protocols=file\n\
         -Dmaven.repo.local.tail=${session.rootDirectory}/.socket/vendor/maven2\n"
    );
    assert_eq!(
        text(&vendored[".socket/vendor/maven2/.gitattributes"]),
        "* -text\n"
    );
    let vendored_jar = &vendored[&format!("{tree}/{ARTIFACT}-{SV}.jar")];
    assert_jar_patched(vendored_jar, &patched, "vendored jar");
    assert_eq!(
        text(&vendored[&format!("{tree}/{ARTIFACT}-{SV}.jar.sha1")]),
        sha1_hex(vendored_jar)
    );
    let tree_pom = &vendored[&format!("{tree}/{ARTIFACT}-{SV}.pom")];
    assert_eq!(
        text(&vendored[&format!("{tree}/{ARTIFACT}-{SV}.pom.sha1")]),
        sha1_hex(tree_pom)
    );
    let tree_pom = text(tree_pom);
    assert!(
        tree_pom.contains(&format!("<version>{SV}</version>"))
            && tree_pom.contains("commons-lang3"),
        "suffixed pom keeps the upstream graph:\n{tree_pom}"
    );
    assert_eq!(
        tree_pom.replace(SV, VERSION),
        text(&upstream_pom),
        "the suffixed pom differs from upstream only in its version"
    );

    // `a`: exactly the version element rewritten; CRLF, tabs, comment kept.
    assert_eq!(
        text(&vendored["a/pom.xml"]),
        a_pom().replace(
            "<version>1.10.0</version>",
            &format!("<version>{SV}</version>")
        )
    );
    let corp = text(&vendored["corp-parent/pom.xml"]);
    assert!(
        corp.starts_with(&CORP_PARENT_POM[..CORP_PARENT_POM.find("</properties>").unwrap()]),
        "the corp parent's content before the insertions is untouched:\n{corp}"
    );
    for needle in [
        "<!-- socket-patch:begin -->",
        "<id>socket-patch-vendor</id>",
        "<url>file://${maven.multiModuleProjectDirectory}/.socket/vendor/maven2</url>",
        "<checksumPolicy>fail</checksumPolicy>",
        "<!-- socket-patch:end -->",
        "<dependencyManagement>",
        &format!("<version>{SV}</version>"),
    ] {
        assert!(corp.contains(needle), "corp parent lacks {needle}:\n{corp}");
    }
    assert_eq!(corp.matches("<repository>").count(), 1, "{corp}");
    assert_eq!(corp.matches(SV).count(), 1, "one pin:\n{corp}");

    // Idempotent: a second vendor run changes no project file.
    vendor(&proj, &m2);
    let again = snapshot(&proj);
    let (changed, added, removed) = diff(&vendored, &again);
    assert!(
        changed.iter().all(|p| p == ".socket/vendor/state.json")
            && added.is_empty()
            && removed.is_empty(),
        "re-vendor: changed {changed:?}, added {added:?}, removed {removed:?}"
    );

    // FRESH CHECKOUT: commons-text only from the committed tree.
    let fresh = root.join("fresh");
    fresh_checkout_all(&proj, &fresh);
    purge(&m2);
    let out = mvn_classpath(&mvn, &fresh, &m2, &settings, true);
    assert!(ok(&out), "fresh offline reactor build:\n{}", dump(&out));
    assert_vendored_on_classpath(&fresh.join("a"), &patched, "root build, module a");
    assert_vendored_on_classpath(
        &fresh.join("b"),
        &patched,
        "root build, module b (transitive via sibling a)",
    );
    let lang3 = std::fs::read_to_string(fresh.join("b/target/cp.txt")).unwrap();
    assert!(
        lang3.contains(TRANSITIVE_JAR),
        "the suffixed pom's transitive resolves: {lang3}"
    );
    let _ = std::fs::remove_dir_all(fresh.join("a/target"));
    purge(&m2);
    let goal = format!("{CLASSPATH_PLUGIN}:build-classpath");
    let out = mvn.run(
        &fresh.join("a"),
        &m2,
        &settings,
        &["-o", &goal, "-Dmdep.outputFile=target/cp.txt"],
    );
    assert!(ok(&out), "fresh offline `cd a` build:\n{}", dump(&out));
    assert_vendored_on_classpath(&fresh.join("a"), &patched, "cd a");

    // Byte-exact revert of the source project.
    revert(&proj, &m2);
    assert_restored(&proj, &before);
    assert!(!proj.join(".mvn").exists(), ".mvn residue");
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor residue"
    );
}

// ── P2: Gradle multi-project with dependency locking ────────────────────

const GRADLE_SETTINGS: &str = r#"buildscript {
    repositories { mavenCentral() }
    dependencies { classpath("org.apache.commons:commons-text:1.10.0") }
}
val socketSettingsJar = java.util.jar.JarFile(java.io.File(org.apache.commons.text.StringSubstitutor::class.java.protectionDomain.codeSource.location.toURI()))
println("SOCKET-SETTINGS-PATCHED " + socketSettingsJar.use { jar -> jar.getInputStream(jar.getJarEntry("META-INF/NOTICE.txt")).bufferedReader().readText().contains("SOCKET-PATCH-MAVEN-E2E-MARKER") })
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "jvm-e2e"
include("app", "lib")
"#;

const GRADLE_LIB: &str = r#"plugins {
    `java-library`
}

dependencies {
    api("org.apache.commons:commons-text:1.10.0")
}

dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}
"#;

const GRADLE_APP: &str = r#"plugins {
    java
}

dependencies {
    implementation(project(":lib"))
}

dependencyLocking {
    lockAllConfigurations()
    lockMode.set(LockMode.STRICT)
}

tasks.register("printRuntimeClasspath") {
    val runtime: FileCollection = files(configurations.named("runtimeClasspath"))
    doLast {
        runtime.files.forEach { println("SOCKET-CP " + it.absolutePath) }
    }
}
"#;

const APPLY_LINE: &str =
    r#"apply(from = ".socket/gradle/socket-patch.settings.gradle") // socket-patch"#;

fn write_gradle_project(proj: &Path) {
    write_project(
        proj,
        &[
            ("settings.gradle.kts", GRADLE_SETTINGS),
            ("lib/build.gradle.kts", GRADLE_LIB),
            ("app/build.gradle.kts", GRADLE_APP),
        ],
    );
}

/// The registry jar of the fixture GAV as the build cached it in
/// `gradle_home`'s `files-2.1` (the multi-project capstone's only copy).
fn gradle_cached_jar(gradle_home: &Path) -> Vec<u8> {
    let version_dir = gradle_home
        .join(prebuilt_common::GRADLE_FILES21)
        .join(GROUP)
        .join(ARTIFACT)
        .join(VERSION);
    let leaf = format!("{ARTIFACT}-{VERSION}.jar");
    let jars: Vec<PathBuf> = std::fs::read_dir(&version_dir)
        .unwrap_or_else(|e| panic!("{}: {e}", version_dir.display()))
        .map(|e| e.unwrap().path().join(&leaf))
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(jars.len(), 1, "one cached {leaf}: {jars:?}");
    std::fs::read(&jars[0]).unwrap()
}

fn gradle_tree_rel() -> String {
    format!(".socket/vendor/gradle/{GROUP_PATH}/{ARTIFACT}/{VERSION}")
}

fn assert_gradle_vendored(out: &Output, checkout: &Path, patched: &[u8], what: &str) {
    assert!(ok(out), "{what}:\n{}", dump(out));
    // A configuration-cache reuse (the CI `configuration-cache` rows) skips
    // the settings script; the run that stored the entry asserted it.
    assert!(
        configuration_reused(out)
            || String::from_utf8_lossy(&out.stdout).contains("SOCKET-SETTINGS-PATCHED true"),
        "{what}: settings buildscript must load the patched jar:\n{}",
        dump(out)
    );
    let cp = gradle_classpath(out);
    let hits: Vec<&PathBuf> = cp
        .iter()
        .filter(|p| p.to_string_lossy().contains(ARTIFACT))
        .collect();
    let want = checkout.join(format!("{}/{ARTIFACT}-{VERSION}.jar", gradle_tree_rel()));
    assert_eq!(
        hits,
        vec![&want],
        "{what}: :app runtimeClasspath must resolve the vendored jar:\n{cp:?}"
    );
    assert_jar_patched(&std::fs::read(&want).unwrap(), patched, what);
    assert!(
        cp.iter()
            .any(|p| p.file_name().is_some_and(|n| n == TRANSITIVE_JAR)),
        "{what}: the vendored pom's transitive resolves: {cp:?}"
    );
    println!("{what}: resolved {}", want.display());
}

#[test]
#[ignore = "real Gradle + Maven Central (fixture); run with --ignored"]
fn gradle_multi_project_vendor_locked_offline_tamper_and_byte_exact_revert() {
    const SUITE: &str = "e2e_vendor_jvm_build::gradle";
    let tmp = tempfile::tempdir().unwrap();
    let root = fixture_root(&tmp);
    let gradle_home = root.join("gradle-home");
    let Some(gradle) = Gradle::detect(SUITE, &gradle_home) else {
        return;
    };
    // No Maven seed: the crawler reads the Gradle cache the build fills, and
    // the vendor plan sources parent poms and BOM metadata from it offline.
    // `m2` stays empty so the user's own ~/.m2 is never consulted.
    let m2 = root.join("m2");
    std::fs::create_dir_all(&m2).unwrap();

    let proj = root.join("proj");
    write_gradle_project(&proj);
    let out = gradle.run(
        &proj,
        &gradle_home,
        &[":app:dependencies", ":lib:dependencies", "--write-locks"],
    );
    if !ok(&out) {
        gradle_skip(
            SUITE,
            &format!(
                "writing lockfiles against Maven Central failed:\n{}",
                dump(&out)
            ),
        );
        return;
    }
    let jar = gradle_cached_jar(&gradle_home);
    let locked = lockfiles(&proj);
    for project in ["app", "lib"] {
        assert!(
            locked
                .iter()
                .any(|(rel, body)| rel.starts_with(&format!("{project}/"))
                    && text(body).contains(&format!("{GROUP}:{ARTIFACT}:{VERSION}"))),
            "{project} locks the patched GAV: {:?}",
            locked.keys()
        );
    }
    let out = gradle.run(
        &proj,
        &gradle_home,
        &[
            ":app:printRuntimeClasspath",
            "--write-verification-metadata",
            "sha256",
        ],
    );
    assert!(ok(&out), "pre-vendor build:\n{}", dump(&out));
    assert!(
        gradle_classpath(&out)
            .iter()
            .any(|p| p.starts_with(&gradle_home) && p.to_string_lossy().contains(ARTIFACT)),
        "pre-vendor :app resolves Central's jar from the Gradle cache:\n{}",
        dump(&out)
    );

    // Remove parent entries to prove vendor adds the metadata needed by the local POM.
    let verification = proj.join("gradle/verification-metadata.xml");
    let verification_text = std::fs::read_to_string(&verification).unwrap();
    let parents = regex::Regex::new(r#"(?s)\s*<component (?:group="org.apache" name="apache" version="27"|group="org.apache.commons" name="commons-parent" version="54")[^>]*>.*?</component>"#).unwrap();
    std::fs::write(
        &verification,
        parents.replace_all(&verification_text, "").as_bytes(),
    )
    .unwrap();
    let (orig, patched) = patched_member(&jar, UUID);
    stage_manifest(&proj, &orig, &patched);
    let before = snapshot(&proj);

    let env = vendor_in(&proj, &m2, Some(&gradle_home));
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    println!("vendor envelope: {env}");
    let vendored = snapshot(&proj);
    let (changed, added, removed) = diff(&before, &vendored);
    let tree = gradle_tree_rel();
    let mut want_added = vec![
        socket_patch_core::vendor::jvm::gradle::SCRIPT_REL.to_string(),
        socket_patch_core::vendor::jvm::gradle::INDEX_REL.to_string(),
        ".socket/vendor/gradle/.gitattributes".to_string(),
        ".socket/gradle/.gitattributes".to_string(),
        ".socket/vendor/.gitattributes".to_string(),
        socket_patch_core::vendor::jvm::gradle::derived_metadata_rel(GROUP, ARTIFACT),
        format!("{tree}/{ARTIFACT}-{VERSION}.jar"),
        format!("{tree}/{ARTIFACT}-{VERSION}.pom"),
        format!("{tree}/socket-patch.vendor.json"),
        ".socket/vendor/state.json".to_string(),
    ];
    want_added.sort();
    assert_eq!(added, want_added, "added files");
    assert!(removed.is_empty(), "removed {removed:?}");
    assert_eq!(
        changed,
        vec!["gradle/verification-metadata.xml".to_string(), "settings.gradle.kts".to_string()],
        "settings and existing verification metadata are edited; lockfiles and build scripts stay byte-unchanged"
    );
    assert!(text(&vendored["settings.gradle.kts"]).ends_with(&format!("{APPLY_LINE}\n")));
    assert!(text(&vendored["settings.gradle.kts"]).contains("exclusiveContent"));
    assert_eq!(
        text(&vendored[socket_patch_core::vendor::jvm::gradle::SCRIPT_REL]),
        socket_patch_core::vendor::jvm::gradle::SCRIPT
    );
    let vendored_jar = &vendored[&format!("{tree}/{ARTIFACT}-{VERSION}.jar")];
    assert_jar_patched(vendored_jar, &patched, "vendored jar");
    assert_ne!(vendored_jar, &jar);
    assert_eq!(
        text(&vendored[socket_patch_core::vendor::jvm::gradle::INDEX_REL]),
        format!(
            "#socket-patch-gradle-index 1\n{GROUP}:{ARTIFACT}:{VERSION}\t{GROUP_PATH}/{ARTIFACT}/\
             {VERSION}/{ARTIFACT}-{VERSION}.jar\t{}\t{UUID}\n{GROUP}:{ARTIFACT}:{VERSION}\t\
             {GROUP_PATH}/{ARTIFACT}/{VERSION}/{ARTIFACT}-{VERSION}.pom\t{}\t{UUID}\n",
            sha256_hex(vendored_jar),
            sha256_hex(&vendored[&format!("{tree}/{ARTIFACT}-{VERSION}.pom")]),
        )
    );

    // Idempotent: a second vendor run changes no project file.
    vendor_in(&proj, &m2, Some(&gradle_home));
    let (changed, added, removed) = diff(&vendored, &snapshot(&proj));
    assert!(
        changed.iter().all(|p| p == ".socket/vendor/state.json")
            && added.is_empty()
            && removed.is_empty(),
        "re-vendor: changed {changed:?}, added {added:?}, removed {removed:?}"
    );

    // Fresh checkout (no manifest, blobs, .gradle or build output).
    let fresh = root.join("fresh");
    fresh_checkout_all(&proj, &fresh);
    let out = gradle.run(&fresh, &gradle_home, &[":app:printRuntimeClasspath"]);
    assert_gradle_vendored(&out, &fresh, &patched, "online");
    let out = gradle.run(
        &fresh,
        &gradle_home,
        &["--offline", ":app:printRuntimeClasspath"],
    );
    assert_gradle_vendored(&out, &fresh, &patched, "--offline");
    assert_eq!(
        lockfiles(&fresh),
        locked,
        "lockfiles unchanged by the vendored builds"
    );

    // A tampered vendored jar fails the build at configuration time.
    let jar_path = fresh.join(format!("{tree}/{ARTIFACT}-{VERSION}.jar"));
    let tampered = jar_with_member(vendored_jar, MEMBER, b"tampered\n");
    std::fs::write(&jar_path, &tampered).unwrap();
    let out = gradle.run(
        &fresh,
        &gradle_home,
        &["--offline", ":app:printRuntimeClasspath"],
    );
    let log = dump(&out);
    assert!(
        !ok(&out),
        "a tampered vendored jar must fail the build:\n{log}"
    );
    assert!(
        log.contains("Dependency verification failed") || log.contains("socket-patch:"),
        "unexpected tamper failure: {log}"
    );
    // The index remains enforced when the user's Gradle verification is off.
    let out = gradle.run(
        &fresh,
        &gradle_home,
        &[
            "--offline",
            "--dependency-verification=off",
            ":app:printRuntimeClasspath",
        ],
    );
    let log = dump(&out);
    assert!(
        !ok(&out),
        "the index must reject a tampered jar even with Gradle verification off: {log}"
    );
    // Java prints native separators, while a Windows PathBuf can retain the
    // forward slashes in the fixture's relative repository path.
    assert!(
        log.replace('\\', "/").contains(&format!(
            "socket-patch: {} has sha256 {}, pinned {}",
            jar_path.to_string_lossy().replace('\\', "/"),
            sha256_hex(&tampered),
            sha256_hex(vendored_jar)
        )),
        "the socket-patch integrity message:\n{log}"
    );
    std::fs::write(&jar_path, vendored_jar).unwrap();
    let out = gradle.run(
        &fresh,
        &gradle_home,
        &["--offline", ":app:printRuntimeClasspath"],
    );
    assert_gradle_vendored(&out, &fresh, &patched, "restored jar");
    println!("{SUITE}: Gradle {} green", gradle.version);

    // Byte-exact revert of the source project.
    revert_in(&proj, &m2, Some(&gradle_home));
    assert_restored(&proj, &before);
    assert!(
        !proj.join(".socket/vendor").exists(),
        ".socket/vendor residue"
    );
    assert!(
        !proj.join(".socket/gradle").exists(),
        ".socket/gradle residue"
    );
}

// ── P3: the fake Central through the mirror init script ─────────────────

/// Settings with a buildscript-classpath library whose class prints a
/// marker from build logic, and `FAIL_ON_PROJECT_REPOS` + `mavenCentral()`.
fn smoke_settings(dsl: Dsl) -> String {
    let (classpath, mode) = match dsl {
        Dsl::Groovy => (
            "classpath 'com.socketfixture:buildlogic-plugin:1.0'",
            "repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)",
        ),
        Dsl::Kotlin => (
            "classpath(\"com.socketfixture:buildlogic-plugin:1.0\")",
            "repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)",
        ),
    };
    let (name, include) = match dsl {
        Dsl::Groovy => ("rootProject.name = 'smoke'", "include 'app'"),
        Dsl::Kotlin => ("rootProject.name = \"smoke\"", "include(\"app\")"),
    };
    format!(
        "buildscript {{\n    repositories {{ mavenCentral() }}\n    dependencies {{ {classpath} }}\n}}\n\
         com.socketfixture.buildlogic.BuildLogic.print()\n\
         dependencyResolutionManagement {{\n    {mode}\n    repositories {{ mavenCentral() }}\n}}\n\
         {name}\n{include}\n"
    )
}

/// `:app` reaches the victim only through `consumer-range`'s pom range
/// `[1.9,1.11)`, so Gradle lists versions from the artifact-level
/// `maven-metadata.xml` and must pick 1.10.0 (the settings classpath
/// requests it literally, through `buildlogic-plugin`).
fn smoke_app(dsl: Dsl) -> String {
    let body = match dsl {
        Dsl::Groovy => {
            "plugins { id 'java' }\n\ndependencies {\n    \
             implementation 'com.socketfixture:consumer-range:2.0'\n}\n"
        }
        Dsl::Kotlin => {
            "plugins { java }\n\ndependencies {\n    \
             implementation(\"com.socketfixture:consumer-range:2.0\")\n}\n"
        }
    };
    format!("{body}\n{}", print_cp_task(dsl, "runtimeClasspath"))
}

#[test]
#[ignore = "real Gradle (the fake Central, no network); run with --ignored"]
fn gradle_multi_project_fake_central_mirror_smoke_both_dsls() {
    use jvm_fixture_repo::*;
    const SUITE: &str = "e2e_vendor_jvm_build::fake_central";
    let tmp = tempfile::tempdir().unwrap();
    let root = fixture_root(&tmp);
    let home = root.join("gradle-home");
    let Some(gradle) = Gradle::detect(SUITE, &home) else {
        return;
    };
    let central = FakeCentral::start();
    let init = init_script(
        &root.join("init"),
        "mirror.gradle",
        &mirror_init_script(&central.uri(), None),
    );
    let projects = write_both_dsls(&root.join("proj"), |dsl| {
        vec![
            (dsl.settings_file(), smoke_settings(dsl)),
            (format!("app/{}", dsl.build_file()), smoke_app(dsl)),
        ]
    });
    let pristine = notice(&format!("{GROUP}:{VICTIM}:{VICTIM_VERSION}"), "pristine");
    let jar = generate()[&repo_path(VICTIM, VICTIM_VERSION, None, "jar")].clone();
    for (dsl, proj) in projects {
        let what = format!("Gradle {} {} DSL", gradle.version, dsl.name());
        let out = gradle.run(
            &proj,
            &home,
            &[&init[0], &init[1], ":app:printRuntimeClasspath"],
        );
        let consumed = assert_patched(&out, VICTIM, NOTICE, pristine.as_bytes(), &what);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains(&format!(
                "{BUILDLOGIC_MARKER}{}",
                victim_marker(VICTIM_VERSION, "pristine")
            )),
            "{what}: the settings buildscript class prints the victim marker:\n{}",
            gradle_build_common::dump(&out)
        );
        let files21 = home.join("caches/modules-2/files-2.1");
        assert!(
            consumed.starts_with(&files21),
            "{what}: resolved into the per-test Gradle cache: {}",
            consumed.display()
        );
        assert_eq!(
            std::fs::read(&consumed).unwrap(),
            jar,
            "{what}: the fixture bytes"
        );
        let hash_dir = consumed
            .parent()
            .and_then(|p| p.file_name())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let sha1 = sha1_hex(&jar);
        assert_eq!(
            format!("{hash_dir:0>40}"),
            sha1,
            "{what}: the hash dir names the jar's sha1 (leading zeros may be dropped)"
        );
        probe_report(
            &format!("fake-central-smoke-{}-{}", gradle.version, dsl.name()),
            &serde_json::json!({
                "gradle": gradle.version,
                "jvm": gradle.jvm,
                "dsl": dsl.name(),
                "resolved": consumed.to_string_lossy(),
                "sha256": sha256_hex(&jar),
                "sha1": sha1,
                "hashDir": hash_dir,
                "leadingZeroKept": hash_dir.len() == 40,
            }),
        );
    }
    let requests = central.requests();
    for leaf in [
        repo_path(VICTIM, VICTIM_VERSION, None, "jar"),
        repo_path(BUILDLOGIC, BUILDLOGIC_VERSION, None, "jar"),
        format!("{GROUP_PATH}/{VICTIM}/maven-metadata.xml"),
    ] {
        assert!(
            requests.contains(&format!("/{leaf}")),
            "the fake Central served {leaf}: {requests:?}"
        );
    }
    println!("{SUITE}: Gradle {} green", gradle.version);
}

/// [`print_cp_task`] is configuration-cache safe in both DSLs: the store run
/// and the reuse run each print the classpath. This is what the
/// gradle-compatibility.yml `configuration-cache` rows rely on for every
/// suite's printRuntimeClasspath assertion.
#[test]
#[ignore = "real Gradle (the fake Central, no network); run with --ignored"]
fn gradle_multi_project_print_cp_configuration_cache_both_dsls() {
    use jvm_fixture_repo::*;
    const SUITE: &str = "e2e_vendor_jvm_build::print_cp_configuration_cache";
    let tmp = tempfile::tempdir().unwrap();
    let root = fixture_root(&tmp);
    let home = root.join("gradle-home");
    let Some(gradle) = Gradle::detect(SUITE, &home) else {
        return;
    };
    // Stable (and warning-free for the `java` plugin) from 8.1.
    if !gradle.at_least(8, 1) {
        println!(
            "{SUITE}: Gradle {} predates the stable configuration cache; nothing to check",
            gradle.version
        );
        return;
    }
    let central = FakeCentral::start();
    let init = init_script(
        &root.join("init"),
        "mirror.gradle",
        &mirror_init_script(&central.uri(), None),
    );
    let projects = write_both_dsls(&root.join("proj"), |dsl| {
        vec![
            (dsl.settings_file(), smoke_settings(dsl)),
            (format!("app/{}", dsl.build_file()), smoke_app(dsl)),
        ]
    });
    let pristine = notice(&format!("{GROUP}:{VICTIM}:{VICTIM_VERSION}"), "pristine");
    for (dsl, proj) in projects {
        for run in ["store", "reuse"] {
            let what = format!(
                "Gradle {} {} DSL configuration cache {run}",
                gradle.version,
                dsl.name()
            );
            let out = gradle.run(
                &proj,
                &home,
                &[
                    &init[0],
                    &init[1],
                    "--configuration-cache",
                    ":app:printRuntimeClasspath",
                ],
            );
            assert_patched(&out, VICTIM, NOTICE, pristine.as_bytes(), &what);
            let log = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let want = if run == "store" {
                "Configuration cache entry stored"
            } else {
                "Configuration cache entry reused"
            };
            assert!(
                log.contains(want),
                "{what}: expected `{want}`:\n{}",
                gradle_build_common::dump(&out)
            );
        }
    }
    println!("{SUITE}: Gradle {} green", gradle.version);
}
