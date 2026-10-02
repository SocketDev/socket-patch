//! Real-Gradle capstones for the vendored Gradle fixes of the v5 JVM
//! backend (`docs/design/maven-vendoring.md`): #395 #428 #429 #461 #487
//! #511 #533, offline sourcing from the Gradle cache, the configuration
//! cache, and ports of the bug-hunt scenarios.
//!
//! Every test resolves the deterministic fake Central
//! (`jvm_fixture_repo`) through the mirror init script, so no network is
//! needed (only `gradle_vendor_395_mixed_root` downloads Maven's own
//! plugins). A pre-vendor build fills the per-test Gradle user home, the
//! CLI vendors from it (`GRADLE_USER_HOME`, no Maven repository at all),
//! and a fresh checkout without the manifest or blobs is built again. The
//! assertion is always on the bytes Gradle consumed: the classpath entry's
//! `Victim.class` must be the patched one.
//!
//! Gated like the other real-Gradle suites: `#[ignore]`, the launcher from
//! `SOCKET_PATCH_GRADLE_E2E_GRADLE` (default `gradle` on `PATH`), the
//! version it must report from `SOCKET_PATCH_GRADLE_E2E_VERSION`, no SKIP
//! with `SOCKET_PATCH_GRADLE_E2E_REQUIRED` (`gradle_build_common`). Maven
//! for #395 via `SOCKET_PATCH_MAVEN_E2E_{MVN,VERSION,REQUIRED}`.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

#[path = "gradle_build_common/mod.rs"]
mod gradle_build_common;

#[path = "jvm_fixture_repo/mod.rs"]
mod jvm_fixture_repo;

#[path = "maven_build_common/mod.rs"]
mod maven_build_common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use gradle_build_common::{
    configuration_reused, dump, fixture_root, gradle_classpath, init_script, jar_member,
    mirror_init_script, ok, print_cp_task, snapshot, write_project, Dsl, Gradle, CP_MARKER,
};
use jvm_fixture_repo::{
    generate, public_keyring_gpg, repo_path, sha256_hex, victim_class, victim_purl, FakeCentral,
    CONSUMER, CONSUMER_VERSION, GROUP, GROUP_PATH, KEY_FINGERPRINT, NOTICE, PARENT, PARENT_VERSION,
    VICTIM, VICTIM_CLASS_MEMBER, VICTIM_VERSION,
};

const UUID: &str = "1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const UUID_2: &str = "9a8b7c6d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const DEP: &str = "com.socketfixture:victim:1.10.0";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
}

/// `Victim.class` in `state` (`pristine` upstream, `patched` vendored).
fn victim_member(state: &str) -> Vec<u8> {
    victim_class(VICTIM_VERSION, state)
}

/// The vendored tree of `artifact:version`, project-relative.
fn tree_rel(artifact: &str, version: &str) -> String {
    format!(".socket/vendor/gradle/{GROUP_PATH}/{artifact}/{version}")
}

/// One per-test world: a Gradle user home, the fake Central and the mirror
/// init script routing every repository to it.
struct World {
    root: PathBuf,
    home: PathBuf,
    gradle: Gradle,
    central: Option<FakeCentral>,
    init: [String; 2],
    _tmp: tempfile::TempDir,
}

impl World {
    /// A repositories block for a buildSrc build: Gradle before 8.0 does not
    /// apply init scripts to buildSrc, so it names the fake Central itself.
    fn buildsrc_repositories(&self) -> String {
        let uri = self.central.as_ref().unwrap().uri();
        format!("repositories {{ maven {{ url '{uri}'; allowInsecureProtocol = true }} }}\n")
    }

    fn new(suite: &str) -> Option<World> {
        let tmp = tempfile::tempdir().unwrap();
        let root = fixture_root(&tmp);
        let home = root.join("gradle-home");
        let gradle = Gradle::detect(suite, &home)?;
        let central = FakeCentral::start();
        let init = init_script(
            &root.join("init"),
            "mirror.gradle",
            &mirror_init_script(&central.uri(), None),
        );
        Some(World {
            root,
            home,
            gradle,
            central: Some(central),
            init,
            _tmp: tmp,
        })
    }

    /// `gradle <args>` in `dir` through the mirror.
    fn build(&self, dir: &Path, args: &[&str]) -> Output {
        let mut all: Vec<&str> = vec![&self.init[0], &self.init[1]];
        all.extend(args);
        self.gradle.run(dir, &self.home, &all)
    }

    /// `socket-patch <args> --json --cwd <cwd>` with the Gradle user home
    /// as the only JVM cache: `(exit, envelope)`.
    fn socket(&self, cwd: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value) {
        let mut cmd = Command::new(binary());
        for (k, _) in std::env::vars_os() {
            if k.to_string_lossy().starts_with("SOCKET_") {
                cmd.env_remove(&k);
            }
        }
        let mut all: Vec<&str> = args.to_vec();
        let cwd_text = cwd.to_string_lossy().into_owned();
        all.extend(["--json", "--cwd", &cwd_text]);
        let _fixture = prebuilt_common::prepare_command(
            &mut cmd,
            cwd,
            &all,
            &[("GRADLE_USER_HOME", self.home.to_str().unwrap())],
        );
        let out = cmd
            .current_dir(cwd)
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
            .env_remove("MAVEN_REPO_LOCAL")
            .env_remove("M2_HOME")
            .output()
            .expect("run socket-patch");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let env = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "{args:?}: not JSON ({e})\n{stdout}\n{}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
        (out.status.code(), env)
    }

    fn socket_ok(&self, cwd: &Path, args: &[&str]) -> serde_json::Value {
        let (code, env) = self.socket(cwd, args);
        assert_eq!(code, Some(0), "{args:?}: {env}");
        let failed = env["summary"].get("failed").unwrap_or(&env["failed"]);
        assert_eq!(failed, 0, "{args:?}: {env}");
        env
    }

    fn vendor(&self, proj: &Path) -> serde_json::Value {
        let env = self.socket_ok(proj, &["vendor"]);
        println!("vendor: {env}");
        env
    }
}

/// What `get` saves for an agent-mode patch of `purl`: the manifest record
/// (`member` from `before` to `after`) and the after blob. Several calls
/// accumulate records.
fn stage_patch(proj: &Path, purl: &str, uuid: &str, member: &str, before: &[u8], after: &[u8]) {
    let manifest_path = proj.join(".socket/manifest.json");
    let mut manifest: serde_json::Value = std::fs::read(&manifest_path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({ "patches": {} }));
    manifest["patches"][purl] = serde_json::json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { member: {
            "beforeHash": git_sha256(before),
            "afterHash": git_sha256(after),
        } },
        "vulnerabilities": { "GHSA-vend-grad-e2e1": {
            "cves": ["CVE-2026-7533"], "summary": "s", "severity": "high", "description": "d"
        } },
        "description": "vendored Gradle capstone",
        "license": "MIT",
        "tier": "free",
    });
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(proj.join(".socket/blobs").join(git_sha256(after)), after).unwrap();
}

/// The victim patch: `Victim.marker()` returns the patched marker.
fn stage_victim(proj: &Path) {
    stage_patch(
        proj,
        &victim_purl(VICTIM_VERSION),
        UUID,
        VICTIM_CLASS_MEMBER,
        &victim_member("pristine"),
        &victim_member("patched"),
    );
}

/// A checkout of `proj` in `dst`: every committable file, minus the
/// manifest, the blobs and build output (a vendored checkout builds
/// without them).
fn fresh_checkout(proj: &Path, dst: &Path) -> PathBuf {
    for (rel, bytes) in snapshot(proj) {
        if rel == ".socket/manifest.json" || rel.starts_with(".socket/blobs/") {
            continue;
        }
        let path = dst.join(&rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
    dst.to_path_buf()
}

/// The classpath entries of `artifact` (`<artifact>-<…>.jar`).
fn entries(out: &Output, artifact: &str, what: &str) -> Vec<PathBuf> {
    assert!(ok(out), "{what}:\n{}", dump(out));
    gradle_classpath(out)
        .into_iter()
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("{artifact}-")) && n.ends_with(".jar"))
        })
        .collect()
}

/// The one main victim jar on the classpath carries `Victim.class` in
/// `state`; when `vendored_in` is given it is that checkout's vendored
/// jar. Returns the consumed path.
fn assert_victim(out: &Output, state: &str, vendored_in: Option<&Path>, what: &str) -> PathBuf {
    let main = format!("{VICTIM}-{VICTIM_VERSION}.jar");
    let hits: Vec<PathBuf> = entries(out, VICTIM, what)
        .into_iter()
        .filter(|p| p.file_name().is_some_and(|n| n == main.as_str()))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{what}: one {main} on the classpath:\n{}",
        dump(out)
    );
    let jar = std::fs::read(&hits[0]).unwrap();
    let got = jar_member(&jar, VICTIM_CLASS_MEMBER)
        .unwrap_or_else(|| panic!("{what}: {} has no Victim.class", hits[0].display()));
    assert!(
        got == victim_member(state),
        "{what}: {} does not carry the {state} Victim.class",
        hits[0].display()
    );
    if let Some(checkout) = vendored_in {
        let want = checkout.join(format!("{}/{main}", tree_rel(VICTIM, VICTIM_VERSION)));
        assert_eq!(
            hits[0].canonicalize().unwrap(),
            want.canonicalize().unwrap(),
            "{what}: Gradle consumed the vendored jar"
        );
    }
    println!("{what}: consumed {}", hits[0].display());
    hits[0].clone()
}

fn groovy_app(deps: &str) -> String {
    format!(
        "plugins {{ id 'java' }}\nrepositories {{ mavenCentral() }}\ndependencies {{\n{deps}}}\n{}",
        print_cp_task(Dsl::Groovy, "runtimeClasspath")
    )
}

/// The standard single-project Groovy build depending on the victim.
fn simple_project(proj: &Path) {
    write_project(
        proj,
        &[
            ("settings.gradle", "rootProject.name = 'app'\n"),
            (
                "build.gradle",
                &groovy_app(&format!("    implementation '{DEP}'\n")),
            ),
        ],
    );
}

/// Pre-vendor build (fills the Gradle cache with the pristine victim),
/// then stage the victim patch.
fn prepare(world: &World, proj: &Path, task: &str) {
    let out = world.build(proj, &[task]);
    assert!(
        ok(&out),
        "pre-vendor build:\n{}\n{}",
        dump(&out),
        verification_report(proj)
    );
    assert_victim(&out, "pristine", None, "pre-vendor build");
    stage_victim(proj);
}

/// The text of Gradle's dependency-verification reports under `proj`
/// (markup stripped), for a failure message.
fn verification_report(proj: &Path) -> String {
    let reports = proj.join("build/reports/dependency-verification");
    let markup = regex::Regex::new(r"<[^>]*>").unwrap();
    let mut out = String::new();
    for dir in std::fs::read_dir(&reports).into_iter().flatten().flatten() {
        for file in std::fs::read_dir(dir.path())
            .into_iter()
            .flatten()
            .flatten()
        {
            let text = std::fs::read_to_string(file.path()).unwrap_or_default();
            let stripped = markup
                .replace_all(&text, " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            out.push_str(&stripped.chars().take(4000).collect::<String>());
        }
    }
    out
}

fn refusal(env: &serde_json::Value) -> (String, String) {
    let event = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "failed")
        .unwrap_or_else(|| panic!("no failed event: {env}"));
    (
        event["errorCode"].as_str().unwrap_or_default().to_string(),
        event["error"].as_str().unwrap_or_default().to_string(),
    )
}

/// `vendor` refuses with `reason` (naming `named`) and writes nothing.
fn assert_vendor_refused(world: &World, proj: &Path, reason: &str, named: &str) {
    let before = snapshot(proj);
    let (code, env) = world.socket(proj, &["vendor"]);
    assert_ne!(code, Some(0), "{env}");
    let (_, error) = refusal(&env);
    assert!(
        error.starts_with(&format!("reason: {reason}: ")) && error.contains(named),
        "{env}"
    );
    assert_eq!(snapshot(proj), before, "a refused vendor writes nothing");
}

// ── git ─────────────────────────────────────────────────────────────────

/// `git <args>` in `cwd`, ambient git environment and config scrubbed.
fn git(cwd: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            cmd.env_remove(&key);
        }
    }
    let global = cwd.join("..").join("e2e-empty.gitconfig");
    if !global.is_file() {
        let _ = std::fs::write(&global, "");
    }
    let out = cmd
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", &global)
        .args(["-c", "user.name=socket-patch-e2e"])
        .args(["-c", "user.email=e2e@socket.invalid"])
        .args(["-c", "init.defaultBranch=main"])
        .args(args)
        .output()
        .expect("spawn git");
    assert!(ok(&out), "git {args:?}:\n{}", dump(&out));
    out
}

/// Commit everything in `dir` (initializing the repository first).
fn commit(dir: &Path, message: &str) -> String {
    if !dir.join(".git").exists() {
        git(dir, &["init", "-q"]);
    }
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-q", "--allow-empty", "-m", message]);
    String::from_utf8(git(dir, &["rev-parse", "HEAD"]).stdout)
        .unwrap()
        .trim()
        .to_string()
}

/// Clone `src` to `dst`, with `core.autocrlf=true` when `autocrlf`.
fn clone(src: &Path, dst: &Path, autocrlf: bool) -> PathBuf {
    let flag = format!("core.autocrlf={autocrlf}");
    git(
        dst.parent().unwrap(),
        &[
            "-c",
            &flag,
            "clone",
            "-q",
            "--config",
            &flag,
            &src.to_string_lossy(),
            &dst.to_string_lossy(),
        ],
    );
    dst.to_path_buf()
}

/// The working tree of `dir` differs from commit `rev` in nothing (line
/// endings normalized the way the checkout's config does) and holds no
/// untracked file.
fn assert_tree_is(dir: &Path, rev: &str, what: &str) {
    let changed = git(dir, &["diff", "--name-status", rev]);
    let untracked = git(dir, &["ls-files", "--others", "--exclude-standard"]);
    assert!(
        changed.stdout.is_empty() && untracked.stdout.is_empty(),
        "{what}: the tree is not back at {rev}:\n{}{}",
        String::from_utf8_lossy(&changed.stdout),
        String::from_utf8_lossy(&untracked.stdout)
    );
}

const GITIGNORE: &str = ".gradle/\nbuild/\n";

/// Stands for [`World::buildsrc_repositories`] in a scenario's files.
const BUILDSRC_REPOS: &str = "@BUILDSRC_REPOSITORIES@\n";

// ── #395 ────────────────────────────────────────────────────────────────

/// #395: a `pom.xml` beside the Gradle build. Both builds of the fresh
/// checkout consume the patched jar: Gradle from the vendored Gradle tree,
/// Maven the suffixed version from the vendored maven2 tree.
#[test]
#[ignore = "real Gradle + Maven (Maven plugins from Central); run with --ignored"]
fn gradle_vendor_395_mixed_root() {
    const SUITE: &str = "e2e_vendor_gradle_build::395";
    let Some(world) = World::new(SUITE) else {
        return;
    };
    let Some(mvn) = maven_build_common::Mvn::detect(SUITE) else {
        return;
    };
    let proj = world.root.join("proj");
    simple_project(&proj);
    write_project(
        &proj,
        &[(
            "pom.xml",
            &format!(
                "<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  <modelVersion>4.0.0</modelVersion>\n  \
                 <groupId>com.example</groupId>\n  <artifactId>app</artifactId>\n  <version>1.0.0</version>\n  \
                 <dependencies>\n    <dependency>\n      <groupId>{GROUP}</groupId>\n      \
                 <artifactId>{VICTIM}</artifactId>\n      <version>{VICTIM_VERSION}</version>\n    \
                 </dependency>\n  </dependencies>\n</project>\n"
            ),
        )],
    );
    prepare(&world, &proj, "printRuntimeClasspath");
    let pristine = snapshot(&proj);
    let env = world.vendor(&proj);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let sv = format!("{VICTIM_VERSION}-socket.1d3c1fd2");
    let maven_jar = format!(".socket/vendor/maven2/{GROUP_PATH}/{VICTIM}/{sv}/{VICTIM}-{sv}.jar");
    let vendored = snapshot(&proj);
    assert!(
        vendored.contains_key(&maven_jar),
        "the Maven tree is vendored"
    );
    assert!(String::from_utf8_lossy(&vendored["pom.xml"]).contains(&sv));
    world.socket_ok(&proj, &["vendor", "--check"]);

    let fresh = fresh_checkout(&proj, &world.root.join("fresh"));
    let out = world.build(&fresh, &["printRuntimeClasspath"]);
    assert_victim(&out, "patched", Some(&fresh), "Gradle half");

    // Maven: the fake Central for the fixture, Central for Maven's plugins.
    let settings = world.root.join("settings.xml");
    let central = world.central.as_ref().unwrap().uri();
    std::fs::write(
        &settings,
        format!(
            "<settings xmlns=\"http://maven.apache.org/SETTINGS/1.0.0\">\n  <profiles>\n    <profile>\n      \
             <id>fixture</id>\n      <repositories>\n        <repository>\n          <id>fixture</id>\n          \
             <url>{central}</url>\n        </repository>\n      </repositories>\n    </profile>\n  </profiles>\n  \
             <activeProfiles>\n    <activeProfile>fixture</activeProfile>\n  </activeProfiles>\n</settings>\n"
        ),
    )
    .unwrap();
    let m2 = world.root.join("m2");
    let out = mvn.run(
        &fresh,
        &m2,
        &settings,
        &[
            "org.apache.maven.plugins:maven-dependency-plugin:3.5.0:build-classpath",
            "-Dmdep.outputFile=cp.txt",
        ],
    );
    assert!(ok(&out), "Maven half:\n{}", dump(&out));
    let cp = std::fs::read_to_string(fresh.join("cp.txt")).unwrap();
    let hit = std::env::split_paths(&cp)
        .find(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(&format!("{VICTIM}-")))
        })
        .unwrap_or_else(|| panic!("Maven classpath has no victim: {cp}"));
    assert!(
        hit.to_string_lossy().contains(&sv),
        "Maven resolves the suffixed version: {}",
        hit.display()
    );
    let jar = std::fs::read(&hit).unwrap();
    assert_eq!(
        jar_member(&jar, VICTIM_CLASS_MEMBER).unwrap(),
        victim_member("patched"),
        "Maven half consumes the patched jar"
    );
    let _ = std::fs::remove_file(fresh.join("cp.txt"));

    world.socket_ok(&proj, &["vendor", "--revert"]);
    let mut after = snapshot(&proj);
    after.retain(|rel, _| !rel.starts_with("build/"));
    assert_eq!(after, pristine, "byte-exact revert of both builds");
}

// ── #428 ────────────────────────────────────────────────────────────────

/// #428: vendoring from a subproject refuses with `not_build_root`; no
/// nested settings file appears and both invocations still build.
#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_428_subproject_refuses() {
    const SUITE: &str = "e2e_vendor_gradle_build::428";
    let Some(world) = World::new(SUITE) else {
        return;
    };
    let proj = world.root.join("proj");
    write_project(
        &proj,
        &[
            (
                "settings.gradle",
                "rootProject.name = 'root'\ninclude 'app'\n",
            ),
            (
                "build.gradle",
                "allprojects { repositories { mavenCentral() } }\n",
            ),
            (
                "app/build.gradle",
                &format!(
                    "plugins {{ id 'java' }}\ndependencies {{ implementation '{DEP}' }}\n{}",
                    print_cp_task(Dsl::Groovy, "runtimeClasspath")
                ),
            ),
        ],
    );
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    let app = proj.join("app");
    let out = world.build(&proj, &[":app:printRuntimeClasspath"]);
    assert_victim(&out, "pristine", None, "pre-vendor");
    stage_victim(&app);
    assert_vendor_refused(
        &world,
        &app,
        "not_build_root",
        "run vendor from Gradle root",
    );
    assert!(!app.join("settings.gradle").exists());
    let out = world.build(&app, &["printRuntimeClasspath"]);
    assert_victim(&out, "pristine", None, "`cd app && gradle` still builds");
}

// ── #429 ────────────────────────────────────────────────────────────────

/// #429: a `core.autocrlf=true` clone of a vendored checkout (buildSrc
/// included) passes `vendor --check`, builds the patched jar, and
/// `vendor --revert`, `remove` and `rollback` leave it at the pre-vendor
/// commit.
#[test]
#[ignore = "real Gradle (the fake Central) + git; run with --ignored"]
fn gradle_vendor_429_autocrlf_clone() {
    const SUITE: &str = "e2e_vendor_gradle_build::429";
    let Some(world) = World::new(SUITE) else {
        return;
    };
    let proj = world.root.join("proj");
    simple_project(&proj);
    write_project(
        &proj,
        &[
            (".gitignore", GITIGNORE),
            (
                "buildSrc/build.gradle",
                &format!(
                    "plugins {{ id 'java' }}\n{}dependencies {{ implementation '{DEP}' }}\n",
                    world.buildsrc_repositories()
                ),
            ),
        ],
    );
    prepare(&world, &proj, "printRuntimeClasspath");
    let pristine = commit(&proj, "pristine");
    world.vendor(&proj);
    commit(&proj, "vendored");

    for command in [
        &["vendor", "--revert"][..],
        &["remove", &victim_purl(VICTIM_VERSION)],
        &["rollback"],
    ] {
        let name = command.join("-").replace(['/', ':', '@'], "_");
        let win = clone(&proj, &world.root.join(format!("win-{name}")), true);
        let settings = std::fs::read(win.join("settings.gradle")).unwrap();
        assert!(
            settings.windows(2).any(|w| w == b"\r\n"),
            "the clone checks text files out with CRLF"
        );
        let env = world.socket_ok(&win, &["vendor", "--check"]);
        assert_eq!(env["summary"]["verified"], 1, "{env}");
        let out = world.build(&win, &["printRuntimeClasspath"]);
        assert_victim(&out, "patched", Some(&win), "autocrlf clone");
        world.socket_ok(&win, command);
        if command[0] != "vendor" {
            // `remove` and `rollback` drop the patch and its blob from the
            // manifest by design; everything else must be back.
            git(
                &win,
                &[
                    "checkout",
                    "-q",
                    &pristine,
                    "--",
                    ".socket/manifest.json",
                    ".socket/blobs",
                ],
            );
        }
        assert_tree_is(&win, &pristine, &format!("{command:?}"));
    }
}

// ── #461 ────────────────────────────────────────────────────────────────

const EXCLUSIVE: &str = "repositories {\n    exclusiveContent {\n        forRepository { mavenCentral() }\n        filter { includeGroup 'com.socketfixture' }\n    }\n    mavenCentral()\n}\n";

/// The build resolves through a user `exclusiveContent` rule for the
/// group in `files`; `vendor` refuses naming `named`, and the build still
/// works.
fn exclusive_case(suite: &str, files: &[(&str, String)], task: &str, named: &str) {
    let Some(world) = World::new(suite) else {
        return;
    };
    let proj = world.root.join("proj");
    let borrowed: Vec<(&str, &str)> = files.iter().map(|(r, b)| (*r, b.as_str())).collect();
    write_project(&proj, &borrowed);
    let out = world.build(&proj, &[task]);
    assert_victim(&out, "pristine", None, "pre-vendor");
    stage_victim(&proj);
    assert_vendor_refused(&world, &proj, "gradle_exclusive_content_conflict", named);
    let out = world.build(&proj, &[task]);
    assert_victim(&out, "pristine", None, "after the refusal");
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_461_sub() {
    exclusive_case(
        "e2e_vendor_gradle_build::461_sub",
        &[
            ("settings.gradle", "rootProject.name = 'root'\ninclude 'app'\n".into()),
            (
                "app/build.gradle",
                format!(
                    "plugins {{ id 'java' }}\n{EXCLUSIVE}dependencies {{ implementation '{DEP}' }}\n{}",
                    print_cp_task(Dsl::Groovy, "runtimeClasspath")
                ),
            ),
        ],
        ":app:printRuntimeClasspath",
        "app/build.gradle",
    );
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_461_conv() {
    exclusive_case(
        "e2e_vendor_gradle_build::461_conv",
        &[
            ("settings.gradle", "rootProject.name = 'root'\ninclude 'app'\n".into()),
            ("buildSrc/build.gradle", "plugins { id 'groovy-gradle-plugin' }\nrepositories { gradlePluginPortal() }\n".into()),
            ("buildSrc/src/main/groovy/bh.repos.gradle", EXCLUSIVE.into()),
            (
                "app/build.gradle",
                format!(
                    "plugins {{ id 'java'; id 'bh.repos' }}\ndependencies {{ implementation '{DEP}' }}\n{}",
                    print_cp_task(Dsl::Groovy, "runtimeClasspath")
                ),
            ),
        ],
        ":app:printRuntimeClasspath",
        "buildSrc/src/main/groovy/bh.repos.gradle",
    );
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_461_applyfrom() {
    exclusive_case(
        "e2e_vendor_gradle_build::461_applyfrom",
        &[
            ("settings.gradle", "rootProject.name = 'root'\n".into()),
            ("gradle/repos.gradle", EXCLUSIVE.into()),
            (
                "build.gradle",
                format!(
                    "plugins {{ id 'java' }}\napply from: 'gradle/repos.gradle'\ndependencies {{ implementation '{DEP}' }}\n{}",
                    print_cp_task(Dsl::Groovy, "runtimeClasspath")
                ),
            ),
        ],
        "printRuntimeClasspath",
        "gradle/repos.gradle",
    );
}

// ── #487 ────────────────────────────────────────────────────────────────

/// One `<artifact>`: the fixture key's signature (`pgp`) or the upstream
/// sha256.
fn vm_artifact(name: &str, pgp: bool) -> String {
    let body = if pgp {
        // Gradle before 8 compares key ids as written: the lowercase form.
        format!("<pgp value=\"{}\"/>", KEY_FINGERPRINT.to_lowercase())
    } else {
        let path = generate()
            .into_keys()
            .find(|p| p.ends_with(&format!("/{name}")))
            .unwrap();
        format!(
            "<sha256 value=\"{}\" origin=\"Generated by Gradle\"/>",
            sha256_hex(&generate()[&path])
        )
    };
    format!("         <artifact name=\"{name}\">\n            {body}\n         </artifact>\n")
}

/// A verification file with signature and metadata verification on: the
/// victim's entries and the parent's are pgp-only (`*_pgp`) or checksums,
/// and the fixture key is trusted for the other side.
fn verification(victim_pgp: bool, parent_pgp: bool) -> String {
    let key = KEY_FINGERPRINT.to_lowercase();
    let trusted = match (victim_pgp, parent_pgp) {
        (true, false) => format!("<trusted-key id=\"{key}\" group=\"{GROUP}\" name=\"{PARENT}\"/>"),
        _ => format!("<trusted-key id=\"{key}\" group=\"{GROUP}\" name=\"{VICTIM}\"/>"),
    };
    let v = VICTIM_VERSION;
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<verification-metadata xmlns=\"https://schema.gradle.org/dependency-verification\" \
         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" \
         xsi:schemaLocation=\"https://schema.gradle.org/dependency-verification https://schema.gradle.org/dependency-verification/dependency-verification-1.0.xsd\">\n   \
         <configuration>\n      <verify-metadata>true</verify-metadata>\n      <verify-signatures>true</verify-signatures>\n      \
         <trusted-keys>\n         {trusted}\n      </trusted-keys>\n   </configuration>\n   <components>\n      \
         <component group=\"{GROUP}\" name=\"{PARENT}\" version=\"{PARENT_VERSION}\">\n{}      </component>\n      \
         <component group=\"{GROUP}\" name=\"{VICTIM}\" version=\"{v}\">\n{}{}{}      </component>\n   \
         </components>\n</verification-metadata>\n",
        vm_artifact(&format!("{PARENT}-{PARENT_VERSION}.pom"), parent_pgp),
        vm_artifact(&format!("{VICTIM}-{v}.jar"), victim_pgp),
        vm_artifact(&format!("{VICTIM}-{v}.module"), victim_pgp),
        vm_artifact(&format!("{VICTIM}-{v}.pom"), victim_pgp),
    )
}

/// #487: with signature verification on, pgp-only entries of the vendored
/// metadata (`victim_pgp`: the victim's own pom and module; `parent_pgp`:
/// its parent pom) get a checksum, so the fresh checkout builds the
/// patched jar; the revert restores the file byte for byte.
fn pgp_case(suite: &str, victim_pgp: bool, parent_pgp: bool) {
    let Some(world) = World::new(suite) else {
        return;
    };
    let proj = world.root.join("proj");
    simple_project(&proj);
    let original = verification(victim_pgp, parent_pgp);
    write_project(&proj, &[("gradle/verification-metadata.xml", &original)]);
    std::fs::copy(
        public_keyring_gpg(),
        proj.join("gradle/verification-keyring.gpg"),
    )
    .unwrap();
    prepare(&world, &proj, "printRuntimeClasspath");
    world.vendor(&proj);
    let text = std::fs::read_to_string(proj.join("gradle/verification-metadata.xml")).unwrap();
    let pgp_left: Vec<&str> = text
        .split("<artifact ")
        .skip(1)
        .filter(|a| a.contains("<pgp ") && !a.contains("<sha256 "))
        .collect();
    assert!(pgp_left.is_empty(), "pgp-only entries remain:\n{text}");
    world.socket_ok(&proj, &["vendor", "--check"]);
    let fresh = fresh_checkout(&proj, &world.root.join("fresh"));
    let out = world.build(&fresh, &["printRuntimeClasspath"]);
    assert_victim(&out, "patched", Some(&fresh), "verified fresh checkout");
    world.socket_ok(&proj, &["vendor", "--revert"]);
    assert_eq!(
        std::fs::read_to_string(proj.join("gradle/verification-metadata.xml")).unwrap(),
        original
    );
}

#[test]
#[ignore = "real Gradle (the fake Central, signed); run with --ignored"]
fn gradle_vendor_487_pgp_parent() {
    pgp_case("e2e_vendor_gradle_build::487_parent", false, true);
}

#[test]
#[ignore = "real Gradle (the fake Central, signed); run with --ignored"]
fn gradle_vendor_487_pgp_ownpom() {
    pgp_case("e2e_vendor_gradle_build::487_ownpom", true, false);
}

// ── #511 ────────────────────────────────────────────────────────────────

/// #511: a range-shaped declaration that resolved the base version before
/// vendoring resolves the vendored, patched base after it (never the older
/// 1.9 the exclusive filter would leave).
fn range_case(suite: &str, files: Vec<(&str, String)>, min: (u32, u32)) {
    let Some(world) = World::new(suite) else {
        return;
    };
    if !world.gradle.at_least(min.0, min.1) {
        println!(
            "{suite}: Gradle {} predates this declaration",
            world.gradle.version
        );
        return;
    }
    let proj = world.root.join("proj");
    let borrowed: Vec<(&str, &str)> = files.iter().map(|(r, b)| (*r, b.as_str())).collect();
    write_project(&proj, &borrowed);
    prepare(&world, &proj, "printRuntimeClasspath");
    world.vendor(&proj);
    let metadata = std::fs::read_to_string(proj.join(format!(
        ".socket/vendor/gradle/{GROUP_PATH}/{VICTIM}/maven-metadata.xml"
    )))
    .unwrap();
    assert!(
        metadata.contains(&format!("<version>{VICTIM_VERSION}</version>")),
        "{metadata}"
    );
    let fresh = fresh_checkout(&proj, &world.root.join("fresh"));
    let out = world.build(&fresh, &["printRuntimeClasspath"]);
    assert_victim(&out, "patched", Some(&fresh), "range after vendoring");
    world.socket_ok(&proj, &["vendor", "--check"]);
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_511_range() {
    range_case(
        "e2e_vendor_gradle_build::511_range",
        vec![
            ("settings.gradle", "rootProject.name = 'app'\n".into()),
            (
                "build.gradle",
                groovy_app("    implementation 'com.socketfixture:victim:[1.9,1.10.0]'\n"),
            ),
        ],
        (6, 0),
    );
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_511_rich() {
    range_case(
        "e2e_vendor_gradle_build::511_rich",
        vec![
            ("settings.gradle", "rootProject.name = 'app'\n".into()),
            (
                "build.gradle",
                groovy_app("    implementation('com.socketfixture:victim') { version { strictly '[1.9,1.11)'; prefer '1.10.0' } }\n"),
            ),
        ],
        (6, 0),
    );
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_511_catalog() {
    range_case(
        "e2e_vendor_gradle_build::511_catalog",
        vec![
            ("settings.gradle.kts", "rootProject.name = \"app\"\n".into()),
            (
                "gradle/libs.versions.toml",
                "[versions]\nvictim = { strictly = \"[1.9,1.11)\", prefer = \"1.10.0\" }\n\n[libraries]\nvictim = { module = \"com.socketfixture:victim\", version.ref = \"victim\" }\n".into(),
            ),
            (
                "build.gradle.kts",
                format!(
                    "plugins {{ java }}\nrepositories {{ mavenCentral() }}\ndependencies {{ implementation(libs.victim) }}\n{}",
                    print_cp_task(Dsl::Kotlin, "runtimeClasspath")
                ),
            ),
        ],
        // Version catalogs are stable from 7.4.
        (7, 4),
    );
}

// ── #533 ────────────────────────────────────────────────────────────────

/// A task printing the sources jar an IDE sync resolves for each module of
/// `runtimeClasspath` (`ArtifactResolutionQuery`).
fn sources_task(dsl: Dsl) -> &'static str {
    match dsl {
        Dsl::Groovy => "tasks.register('printSources') {\n    doLast {\n        def ids = configurations.runtimeClasspath.incoming.resolutionResult.allComponents.collect { it.id }.findAll { it instanceof ModuleComponentIdentifier }\n        def r = dependencies.createArtifactResolutionQuery().forComponents(ids).withArtifacts(JvmLibrary, SourcesArtifact).execute()\n        r.resolvedComponents.each { c -> c.getArtifacts(SourcesArtifact).each { a -> if (a instanceof ResolvedArtifactResult) { println('SOCKET-SRC ' + a.file.absolutePath) } } }\n    }\n}\n",
        Dsl::Kotlin => "tasks.register(\"printSources\") {\n    doLast {\n        val ids = configurations.getByName(\"runtimeClasspath\").incoming.resolutionResult.allComponents.map { it.id }.filterIsInstance<ModuleComponentIdentifier>()\n        val r = dependencies.createArtifactResolutionQuery().forComponents(ids).withArtifacts(JvmLibrary::class.java, SourcesArtifact::class.java).execute()\n        r.resolvedComponents.forEach { c -> c.getArtifacts(SourcesArtifact::class.java).forEach { a -> if (a is ResolvedArtifactResult) println(\"SOCKET-SRC \" + a.file.absolutePath) } }\n    }\n}\n",
    }
}

/// #533: a declared `tests` classifier and the IDE sources of the patched
/// module still resolve after vendoring, from the vendored tree.
fn classifier_case(suite: &str, dsl: Dsl) {
    let Some(world) = World::new(suite) else {
        return;
    };
    let proj = world.root.join("proj");
    let (settings, build) = match dsl {
        Dsl::Groovy => (
            "rootProject.name = 'app'\n".to_string(),
            format!(
                "plugins {{ id 'java' }}\nrepositories {{ mavenCentral() }}\ndependencies {{\n    implementation '{DEP}'\n    testImplementation '{DEP}:tests'\n}}\n"
            ),
        ),
        Dsl::Kotlin => (
            "rootProject.name = \"app\"\n".to_string(),
            "plugins { java }\nrepositories { mavenCentral() }\ndependencies {\n    implementation(\"com.socketfixture:victim:1.10.0\")\n    testImplementation(group = \"com.socketfixture\", name = \"victim\", version = \"1.10.0\", classifier = \"tests\")\n}\n".to_string(),
        ),
    };
    let build = format!(
        "{build}{}{}",
        print_cp_task(dsl, "testRuntimeClasspath"),
        sources_task(dsl)
    );
    write_project(
        &proj,
        &[
            (dsl.settings_file().as_str(), &settings),
            (dsl.build_file().as_str(), &build),
        ],
    );
    let out = world.build(&proj, &["printRuntimeClasspath", "printSources"]);
    assert_victim(&out, "pristine", None, "pre-vendor");
    stage_victim(&proj);
    let env = world.vendor(&proj);
    assert!(
        !env.to_string().contains("ide_sources_unavailable"),
        "the cached sources jar is vendored: {env}"
    );
    let tree = proj.join(tree_rel(VICTIM, VICTIM_VERSION));
    for name in ["victim-1.10.0-tests.jar", "victim-1.10.0-sources.jar"] {
        assert_eq!(
            std::fs::read(tree.join(name)).unwrap(),
            generate()[&format!("{GROUP_PATH}/{VICTIM}/{VICTIM_VERSION}/{name}")],
            "{name} is vendored verbatim"
        );
    }
    let fresh = fresh_checkout(&proj, &world.root.join("fresh"));
    let out = world.build(&fresh, &["printRuntimeClasspath", "printSources"]);
    assert_victim(&out, "patched", Some(&fresh), "main jar");
    let tests: Vec<PathBuf> = entries(&out, VICTIM, "tests jar")
        .into_iter()
        .filter(|p| p.to_string_lossy().ends_with("victim-1.10.0-tests.jar"))
        .collect();
    assert_eq!(tests.len(), 1, "{}", dump(&out));
    assert_eq!(
        tests[0].canonicalize().unwrap(),
        fresh
            .join(tree_rel(VICTIM, VICTIM_VERSION))
            .join("victim-1.10.0-tests.jar")
            .canonicalize()
            .unwrap()
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout
            .lines()
            .filter_map(|l| l.strip_prefix("SOCKET-SRC "))
            .any(|p| p.ends_with("victim-1.10.0-sources.jar")),
        "IDE sources still resolve:\n{}",
        dump(&out)
    );
    world.socket_ok(&proj, &["vendor", "--check"]);
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_533_classifier_groovy_and_sources() {
    classifier_case("e2e_vendor_gradle_build::533_groovy", Dsl::Groovy);
}

#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_533_classifier_kotlin_and_sources() {
    classifier_case("e2e_vendor_gradle_build::533_kotlin", Dsl::Kotlin);
}

// ── offline sourcing ────────────────────────────────────────────────────

/// Vendoring needs no Maven repository: the pom and module come from the
/// Gradle cache's hash directories, and the fresh checkout then builds
/// `--offline` with the fake Central gone.
#[test]
#[ignore = "real Gradle (the fake Central); run with --ignored"]
fn gradle_vendor_offline_no_m2_seed() {
    const SUITE: &str = "e2e_vendor_gradle_build::offline_no_m2_seed";
    let Some(mut world) = World::new(SUITE) else {
        return;
    };
    let proj = world.root.join("proj");
    simple_project(&proj);
    prepare(&world, &proj, "printRuntimeClasspath");
    assert!(!world.root.join("m2").exists());
    world.vendor(&proj);
    let tree = proj.join(tree_rel(VICTIM, VICTIM_VERSION));
    for ext in ["pom", "module"] {
        assert_eq!(
            std::fs::read(tree.join(format!("{VICTIM}-{VICTIM_VERSION}.{ext}"))).unwrap(),
            generate()[&repo_path(VICTIM, VICTIM_VERSION, None, ext)],
            "the upstream {ext} verbatim"
        );
    }
    world.central = None;
    let fresh = fresh_checkout(&proj, &world.root.join("fresh"));
    let out = world.build(&fresh, &["--offline", "printRuntimeClasspath"]);
    assert_victim(&out, "patched", Some(&fresh), "--offline");
}

// ── configuration cache ─────────────────────────────────────────────────

/// Vendoring a second patch into a build whose configuration is cached
/// invalidates the entry (the index is a configuration input): the
/// rebuild consumes the second patched jar too.
#[test]
#[ignore = "real Gradle 8.1+ (the fake Central); run with --ignored"]
fn gradle_vendor_config_cache_second_patch() {
    const SUITE: &str = "e2e_vendor_gradle_build::config_cache";
    let Some(world) = World::new(SUITE) else {
        return;
    };
    if !world.gradle.at_least(8, 1) {
        println!(
            "{SUITE}: Gradle {} predates the stable configuration cache",
            world.gradle.version
        );
        return;
    }
    let proj = world.root.join("proj");
    write_project(
        &proj,
        &[
            ("settings.gradle", "rootProject.name = 'app'\n"),
            (
                "build.gradle",
                &groovy_app(&format!(
                    "    implementation '{DEP}'\n    implementation 'com.socketfixture:consumer:2.0'\n"
                )),
            ),
        ],
    );
    let cc = "--configuration-cache";
    prepare(&world, &proj, "printRuntimeClasspath");
    world.vendor(&proj);
    let out = world.build(&proj, &[cc, "printRuntimeClasspath"]);
    assert_victim(&out, "patched", Some(&proj), "first patch, cache stored");
    let out = world.build(&proj, &[cc, "printRuntimeClasspath"]);
    assert!(
        configuration_reused(&out),
        "the entry is reused:\n{}",
        dump(&out)
    );

    let consumer_jar = generate()[&repo_path(CONSUMER, CONSUMER_VERSION, None, "jar")].clone();
    let before = jar_member(&consumer_jar, NOTICE).unwrap();
    let after = [before.as_slice(), b"SOCKET-PATCH-SECOND\n"].concat();
    stage_patch(
        &proj,
        &format!("pkg:maven/{GROUP}/{CONSUMER}@{CONSUMER_VERSION}"),
        UUID_2,
        NOTICE,
        &before,
        &after,
    );
    let env = world.vendor(&proj);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let out = world.build(&proj, &[cc, "printRuntimeClasspath"]);
    assert!(
        !configuration_reused(&out),
        "a changed index must invalidate the entry:\n{}",
        dump(&out)
    );
    assert_victim(&out, "patched", Some(&proj), "first patch kept");
    let consumer: Vec<PathBuf> = entries(&out, CONSUMER, "consumer");
    assert_eq!(consumer.len(), 1, "{}", dump(&out));
    assert_eq!(
        jar_member(&std::fs::read(&consumer[0]).unwrap(), NOTICE).unwrap(),
        after,
        "the second patch is consumed: {}",
        consumer[0].display()
    );
}

// ── bug-hunt scenarios ──────────────────────────────────────────────────

/// A bug-hunt scenario end to end: vendor, commit, a clean clone without
/// the manifest passes `vendor --check` and builds the patched jar (with
/// `task`, from `cwd` below the clone), then `vendor --revert` leaves the
/// source checkout at its pre-vendor commit.
fn bughunt(suite: &str, files: &[(&str, String)], task: &str) {
    bughunt_with(suite, files, task, assert_victim);
}

/// What a scenario's task proves: `(output, state, vendored checkout,
/// what)`.
type Check = fn(&Output, &str, Option<&Path>, &str) -> PathBuf;

/// [`bughunt`] with its own consumption `check`.
fn bughunt_with(suite: &str, files: &[(&str, String)], task: &str, check: Check) {
    let Some(world) = World::new(suite) else {
        return;
    };
    let proj = world.root.join("proj");
    let files: Vec<(&str, String)> = files
        .iter()
        .map(|(r, b)| {
            (
                *r,
                b.replace(BUILDSRC_REPOS, &world.buildsrc_repositories()),
            )
        })
        .collect();
    let mut borrowed: Vec<(&str, &str)> = files.iter().map(|(r, b)| (*r, b.as_str())).collect();
    borrowed.push((".gitignore", GITIGNORE));
    write_project(&proj, &borrowed);
    let out = world.build(&proj, &[task]);
    check(&out, "pristine", None, "pre-vendor build");
    stage_victim(&proj);
    let pristine = commit(&proj, "pristine");
    world.vendor(&proj);
    commit(&proj, "vendored");
    let fresh = clone(&proj, &world.root.join("fresh"), false);
    std::fs::remove_file(fresh.join(".socket/manifest.json")).unwrap();
    let _ = std::fs::remove_dir_all(fresh.join(".socket/blobs"));
    world.socket_ok(&fresh, &["vendor", "--check"]);
    let out = world.build(&fresh, &[task]);
    check(&out, "patched", Some(&fresh), "fresh clone");
    world.socket_ok(&proj, &["vendor", "--revert"]);
    assert_tree_is(&proj, &pristine, "revert");
}

fn print_task_groovy() -> String {
    print_cp_task(Dsl::Groovy, "runtimeClasspath")
}

/// s1: a plain single-project Groovy build.
#[test]
#[ignore = "real Gradle (the fake Central) + git; run with --ignored"]
fn gradle_vendor_bughunt_s1() {
    bughunt(
        "e2e_vendor_gradle_build::bughunt_s1",
        &[
            ("settings.gradle", "rootProject.name = 's1'\n".into()),
            (
                "build.gradle",
                groovy_app(&format!("    implementation '{DEP}'\n")),
            ),
        ],
        "printRuntimeClasspath",
    );
}

/// s2: no settings file at all (vendor creates it).
#[test]
#[ignore = "real Gradle (the fake Central) + git; run with --ignored"]
fn gradle_vendor_bughunt_s2() {
    bughunt(
        "e2e_vendor_gradle_build::bughunt_s2",
        &[(
            "build.gradle",
            groovy_app(&format!("    implementation '{DEP}'\n")),
        )],
        "printRuntimeClasspath",
    );
}

/// s6: `pluginManagement` repositories and a last line without a newline.
#[test]
#[ignore = "real Gradle (the fake Central) + git; run with --ignored"]
fn gradle_vendor_bughunt_s6() {
    bughunt(
        "e2e_vendor_gradle_build::bughunt_s6",
        &[
            (
                "settings.gradle",
                "pluginManagement {\n  repositories { gradlePluginPortal() }\n}\nrootProject.name = 's6' // last line no newline".into(),
            ),
            ("build.gradle", groovy_app(&format!("    implementation '{DEP}'\n"))),
        ],
        "printRuntimeClasspath",
    );
}

/// s9: a multi-project build with `allprojects` repositories.
#[test]
#[ignore = "real Gradle (the fake Central) + git; run with --ignored"]
fn gradle_vendor_bughunt_s9() {
    bughunt(
        "e2e_vendor_gradle_build::bughunt_s9",
        &[
            (
                "settings.gradle",
                "rootProject.name='s9'\ninclude 'app'\n".into(),
            ),
            (
                "build.gradle",
                "allprojects { repositories { mavenCentral() } }\n".into(),
            ),
            (
                "app/build.gradle",
                format!(
                    "plugins {{ id 'java' }}\ndependencies {{ implementation '{DEP}' }}\n{}",
                    print_task_groovy()
                ),
            ),
        ],
        ":app:printRuntimeClasspath",
    );
}

/// The build-logic marker: `Victim.marker()` run from buildSrc code (the
/// class Gradle loads is an instrumented copy of the jar, so its bytes are
/// not compared).
fn assert_build_logic_marker(out: &Output, state: &str, _: Option<&Path>, what: &str) -> PathBuf {
    assert!(ok(out), "{what}:\n{}", dump(out));
    let want = format!(
        "SOCKET-MARKER {}",
        jvm_fixture_repo::victim_marker(VICTIM_VERSION, state)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l.trim() == want),
        "{what}: build logic prints `{want}`:\n{}",
        dump(out)
    );
    PathBuf::new()
}

/// s12: the patched library on the buildSrc classpath, loaded by build
/// logic: buildSrc gets its own wiring.
#[test]
#[ignore = "real Gradle (the fake Central) + git; run with --ignored"]
fn gradle_vendor_bughunt_s12() {
    bughunt_with(
        "e2e_vendor_gradle_build::bughunt_s12",
        &[
            ("settings.gradle", "rootProject.name='s12'\n".into()),
            (
                "build.gradle",
                "tasks.register('printMarker') { doLast { println 'SOCKET-MARKER ' + Loc.marker() } }\n".into(),
            ),
            (
                "buildSrc/build.gradle",
                format!("plugins {{ id 'groovy-gradle-plugin' }}\n{BUILDSRC_REPOS}dependencies {{ implementation '{DEP}' }}\n"),
            ),
            (
                "buildSrc/src/main/groovy/Loc.groovy",
                "class Loc { static String marker() { com.socketfixture.victim.Victim.marker() } }\n".into(),
            ),
        ],
        "printMarker",
        assert_build_logic_marker,
    );
}

/// s14: the classpath captured at configuration time.
#[test]
#[ignore = "real Gradle (the fake Central) + git; run with --ignored"]
fn gradle_vendor_bughunt_s14() {
    bughunt(
        "e2e_vendor_gradle_build::bughunt_s14",
        &[
            ("settings.gradle", "rootProject.name = 's14'\n".into()),
            (
                "build.gradle",
                format!(
                    "plugins {{ id 'java' }}\nrepositories {{ mavenCentral() }}\ndependencies {{ implementation '{DEP}' }}\n\
                     tasks.register('printRuntimeClasspath') {{ def cp = configurations.runtimeClasspath; doLast {{ cp.files.each {{ println '{CP_MARKER}' + it }} }} }}\n"
                ),
            ),
        ],
        "printRuntimeClasspath",
    );
}
