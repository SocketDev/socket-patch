//! A Maven artifact that Bazel builds through a rules_jvm_external hub:
//! `maven.install(artifacts = [...], lock_file = "//:maven_install.json")`
//! under Bzlmod, pinned with the ruleset's own `REPIN=1 bazel run
//! @fixture_maven//:pin`.
//!
//! Such a hub fetches each jar its lock names, with the sha256 the lock
//! holds, and reads no `pom.xml` and no Gradle file. So nothing
//! `socket-patch` does for a Maven artifact reaches a Bazel build yet, and
//! these flows hold what a user sees instead, on
//! the Bazel the run is given ([`FIXTURE`] says which ruleset goes with
//! its release):
//!
//! - [`a_pom_patch_beside_a_pinned_hub`]: a checkout that Maven builds
//!   too. `socket-patch get <purl> --mode hosted --yes` pins the artifact
//!   in `pom.xml` and reports it `applied`. The Bazel build before and
//!   after prints the upstream marker, and Bazel never asks for the
//!   patched jar. `rollback --yes` restores every file.
//! - [`a_tree_only_bazel_builds`]: the same checkout without a `pom.xml`.
//!   The same command writes nothing and reports the patch `skipped`
//!   (`redirect_unconfirmed`), and the build is as before.
//!
//! In both the command says what the build shows: one warning,
//! `maven_bazel_hub_unpatched`, that Bazel builds the artifact from
//! `maven_install.json`, with the hub and the line of its `maven.install`.
//! In the second it stands after `redirect_maven_no_pom`, "no pom.xml
//! present", which the command says as it does without a Bazel workspace.
//! The lock each ruleset release writes is the one socket-patch reads it
//! from ([`Lock`]).
//!
//! The artifacts are made here, for the run, under the group
//! `dev.socket.fixture`, which only the owner of `socket.dev` can publish
//! to Maven Central: `consumer:2.0`, the one artifact `MODULE.bazel` names,
//! and `victim:1.10.0`, which `consumer` depends on and the patch is for.
//! The victim's jar holds one file, the text `//:consumer` prints after
//! `OUT: `, with an id of the run in it, so no cache of an earlier run can
//! supply the jar. No lock is committed: a flow writes its stand-in's
//! origin into `MODULE.bazel` in the place of the hub's one repository
//! and pins, so the lock is the one the ruleset of the era writes (format
//! 3 from rules_jvm_external 6.10, format 2 before).
//!
//! One loopback server stands in for three hosts, by route prefix: the
//! Socket API at its own paths, the Maven repository of the two artifacts
//! (`/maven2`), and `patch.socket.dev` with the patched jar at the path of
//! the production patch registry. The pin runs Coursier, which the ruleset
//! starts and which asks the stand-in alone; the build fetches each jar
//! with Bazel's downloader from the URL in the lock.
//!
//! No pin and no build asks a public Maven repository. The hub is named
//! [`HUB`], not `maven`: other Bazel modules of the build add artifacts of
//! their own to a hub named `maven` (protobuf does), which a pin would
//! resolve from Maven Central, and nothing but the fixture adds to this
//! one. Its one repository is the stand-in, and [`Pinned::open`] holds
//! that the lock names the two artifacts and that repository, and nothing
//! else. A hub of the default name, whose lock also holds what other
//! modules added, is read without a Bazel in `e2e_bazel_maven_beside.rs`.
//!
//! What the stand-in lacks still comes from the network: the Bazel
//! registry, the ruleset archives, Coursier itself and the JDK that
//! rules_java downloads (each era's `.bazelrc` names the one its rules_java
//! runs javac on, so a build takes no Java from the machine and downloads
//! one JDK). rules_jvm_external before 6.8 (era `e7`) runs Coursier with
//! the Java of `JAVA_HOME`, else the `java` on `PATH`; later ones use the
//! Java embedded in Bazel.

use std::io::Write as _;
use std::time::Instant;

use serde_json::{json, Value};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use socket_patch_core::bazel::maven::{Lock, Pinned as Jar};

use crate::envelope::event_for;
use crate::harness::{changed, Cell, Fixture, Ran, StandIn, Tree, NOTHING};
use crate::hosted_memory_common::Patch;

/// The workspace the tests build, and the ruleset each Bazel release
/// builds it with. One era per way the ruleset names an artifact's
/// repository and writes its lock.
const FIXTURE: Fixture = Fixture {
    name: "maven::FIXTURE",
    dir: "rules_jvm_external/bzlmod",
    workflow: "bazel-maven.yml",
    eras: &[
        // rules_jvm_external 6.5 and rules_java 7.6.5: lock format 2.
        ((7, 0, 0)..(8, 0, 0), "e7"),
        // rules_jvm_external 6.9 and rules_java 8.13.0: lock format 2.
        ((8, 0, 0)..(9, 0, 0), "e8"),
        // rules_jvm_external 7.2 and rules_java 9.3.0: lock format 3.
        ((9, 0, 0)..(10, 0, 0), "e9"),
    ],
};

/// The group of the fixture's artifacts, and its directory in a Maven
/// repository.
const GROUP: &str = "dev.socket.fixture";
const GROUP_PATH: &str = "dev/socket/fixture";
/// The artifact the patch is for, which `consumer:2.0` depends on.
const VICTIM: &str = "victim";
const VERSION: &str = "1.10.0";
const PURL: &str = "pkg:maven/dev.socket.fixture/victim@1.10.0";
/// The file of the victim's jar that `App.java` prints.
const MARKER: &str = "dev/socket/fixture/victim/marker.txt";
/// The fixture's hub, under a name no other Bazel module adds to.
const HUB: &str = "fixture_maven";
/// The one repository of the fixture's `maven.install`, which a flow
/// replaces with its stand-in's.
const PLACEHOLDER: &str = "http://socket-fixture.invalid/maven2";
/// The route prefixes of the stand-in, one per host it plays.
const UPSTREAM: &str = "maven2";
const PATCH_HOST: &str = "patch.socket.dev";
/// The files hosted mode writes for a Maven pin.
const PINNED: [&str; 3] = [
    ".mvn/checksums/checksums.sha256",
    ".mvn/maven.config",
    "pom.xml",
];

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A jar of `files`, stored and with one fixed time.
fn jar(files: &[(&str, &str)]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .last_modified_time(
            zip::DateTime::from_date_and_time(2026, 1, 1, 0, 0, 0).expect("a date"),
        );
    let manifest = ("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n");
    for (name, text) in std::iter::once(&manifest).chain(files) {
        zip.start_file(*name, options).expect("a jar member");
        zip.write_all(text.as_bytes()).expect("a jar member");
    }
    zip.finish().expect("a jar").into_inner()
}

/// The victim's jar, whose one file holds `marker`.
fn victim(marker: &str) -> Vec<u8> {
    jar(&[(MARKER, &format!("{marker}\n"))])
}

/// The pom of `artifact` at `version`, which depends on `needs`.
fn pom(artifact: &str, version: &str, needs: Option<(&str, &str)>) -> String {
    let needs = needs.map_or_else(String::new, |(artifact, version)| {
        format!(
            "  <dependencies>\n    <dependency>\n      <groupId>{GROUP}</groupId>\n      \
             <artifactId>{artifact}</artifactId>\n      <version>{version}</version>\n    \
             </dependency>\n  </dependencies>\n"
        )
    });
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  <groupId>{GROUP}</groupId>\n  \
         <artifactId>{artifact}</artifactId>\n  <version>{version}</version>\n{needs}</project>\n"
    )
}

/// `<group>/<artifact>/<version>/<artifact>-<version>.<ext>`, the path of
/// a file in a Maven repository.
fn repo_path(artifact: &str, version: &str, ext: &str) -> String {
    format!("{GROUP_PATH}/{artifact}/{version}/{artifact}-{version}.{ext}")
}

/// A checkout whose hub is pinned, and what its flow reads afterwards.
struct Pinned {
    cell: Cell,
    standin: StandIn,
    /// Where the JVM tools of the machine keep artifacts: `m2`, the Maven
    /// local repository, with the victim in it as a Maven build of the
    /// checkout leaves it; `coursier`, the cache the ruleset's Coursier
    /// fills when it pins; `gradle`, which nothing fills.
    tools: tempfile::TempDir,
    uuid: String,
    /// The line of `maven.install` in the checkout's `MODULE.bazel`.
    install: usize,
    /// What `//:consumer` prints while Bazel builds the upstream jar.
    upstream: String,
    /// The routes of the upstream and of the patched jar on the stand-in.
    upstream_route: String,
    patched_route: String,
    started: Instant,
}

impl Pinned {
    /// Step 0 of both flows: the fixture's checkout for `test`, with a
    /// `pom.xml` that declares the victim when `maven` is set, pinned by
    /// the ruleset against a stand-in that has the two artifacts, the
    /// patched jar and the grant of its patch. `None` when no Bazel runs
    /// here.
    fn open(test: &str, maven: bool) -> Option<Pinned> {
        let started = Instant::now();
        let mut cell = Cell::open(test, &FIXTURE)?;
        // The cache of the Coursier that pins. Before 7.2 the ruleset
        // leaves the choice to Coursier, which without this takes the home
        // directory from the system, whatever `HOME` says.
        let tools = tempfile::tempdir().expect("the directories of the JVM tools");
        let coursier = tools.path().join("coursier").to_string_lossy().into_owned();
        cell.repo_env.push(("COURSIER_CACHE".to_string(), coursier));
        let run = uuid::Uuid::new_v4().to_string();
        let uuid = uuid::Uuid::new_v4().to_string();
        let token = uuid::Uuid::new_v4().to_string();
        let suffixed = format!("{VERSION}-socket.{}", &uuid[..8]);
        let upstream_jar = victim(&format!("PRISTINE {run}"));
        let patched_jar = victim(&format!("PATCHED {uuid}"));
        let victim_pom = pom(VICTIM, VERSION, None);
        let served_pom = pom(VICTIM, &suffixed, None);

        let standin = StandIn::start();
        let origin = standin.origin();
        let served: [(String, Vec<u8>); 4] = [
            (repo_path(VICTIM, VERSION, "jar"), upstream_jar.clone()),
            (repo_path(VICTIM, VERSION, "pom"), victim_pom.clone().into()),
            (repo_path("consumer", "2.0", "jar"), jar(&[])),
            (
                repo_path("consumer", "2.0", "pom"),
                pom("consumer", "2.0", Some((VICTIM, VERSION))).into(),
            ),
        ];
        for (path, bytes) in &served {
            // Coursier takes a file only with a checksum beside it.
            let (route, sha1) = (
                format!("/{UPSTREAM}/{path}"),
                hex::encode(Sha1::digest(bytes)),
            );
            standin.serve(5, &route, bytes);
            standin.serve(5, &format!("{route}.sha1"), sha1.as_bytes());
        }
        // The patch registry and the grant, as production has them: a
        // token and the patch id in the path, the version with the suffix
        // only that registry serves.
        let registry = format!("{PATCH_HOST}/patch-registry/maven/{token}/{uuid}/maven2");
        let patched_route = format!("/{registry}/{}", repo_path(VICTIM, &suffixed, "jar"));
        standin.serve(5, &patched_route, &patched_jar);
        let artifact = format!(
            "https://{PATCH_HOST}/patch/maven/{GROUP}/{VICTIM}/{VERSION}/{token}/{uuid}/{VICTIM}-{suffixed}.jar"
        );
        let reference = json!({
            "status": "granted",
            "url": artifact,
            "purl": PURL,
            "artifacts": [{
                "kind": "tarball",
                "url": artifact,
                "integrity": { "sha256": sha256_hex(&patched_jar) },
            }],
            "registryOverride": {
                "kind": "maven2",
                "indexUrl": format!("https://{registry}"),
                "identifiers": {
                    "name": format!("{GROUP}/{VICTIM}"),
                    "version": VERSION,
                    "mavenGroupId": GROUP,
                    "mavenArtifactId": VICTIM,
                    "mavenSuffixedVersion": suffixed,
                    "mavenPomSha256": sha256_hex(served_pom.as_bytes()),
                },
            },
        });
        standin.api(&[Patch {
            purl: PURL.to_string(),
            uuid: uuid.clone(),
            reference,
        }]);

        // The checkout: the hub's repository is the stand-in, the lock is
        // the empty file the ruleset's documentation starts from.
        let module = std::fs::read_to_string(cell.path("MODULE.bazel")).expect("MODULE.bazel");
        assert_eq!(module.matches(PLACEHOLDER).count(), 1, "{test}: {module}");
        let install = module.lines().position(|line| line == "maven.install(");
        let install = install.expect("the fixture's maven.install") + 1;
        let repository = format!("{origin}/{UPSTREAM}");
        cell.write("MODULE.bazel", module.replace(PLACEHOLDER, &repository));
        cell.write("maven_install.json", "");
        if maven {
            cell.write("pom.xml", pom("app", "1.0.0", Some((VICTIM, VERSION))));
        }
        for (ext, bytes) in [("jar", &upstream_jar[..]), ("pom", victim_pom.as_bytes())] {
            let file = tools
                .path()
                .join("m2")
                .join(repo_path(VICTIM, VERSION, ext));
            std::fs::create_dir_all(file.parent().expect("a directory")).expect("create it");
            std::fs::write(&file, bytes).expect("write the local repository");
        }

        // The ruleset's own relock. The lock it writes holds the victim,
        // which `MODULE.bazel` does not name, at the sha256 of this run's
        // jar, in the format of the era.
        let pin = cell.bazel_env("run", &[&format!("@{HUB}//:pin")], &[("REPIN", "1")]);
        assert!(pin.ok(), "{test}: {}", pin.dump());
        let lock = std::fs::read_to_string(cell.path("maven_install.json")).expect("the lock");
        let raw: Value = serde_json::from_str(&lock).expect("the lock is JSON");
        // Nothing else is in it: no other Bazel module added to the hub,
        // and its one repository is the stand-in.
        let keys = |of: &str| {
            let map = raw[of].as_object().expect("a map of the lock");
            map.keys().map(String::as_str).collect::<Vec<_>>().join(" ")
        };
        assert_eq!(
            (keys("artifacts"), keys("repositories")),
            (
                format!("{GROUP}:consumer {GROUP}:{VICTIM}"),
                format!("{repository}/")
            ),
            "{test}: {raw:#}"
        );
        let lock = Lock::parse(&lock).unwrap_or_else(|why| panic!("{test}: {why}:\n{lock}"));
        let format = if cell.numbers() >= (9, 0, 0) { 3 } else { 2 };
        let jar = Jar {
            version: VERSION.to_string(),
            jar_sha256: Some(sha256_hex(&upstream_jar)),
            fetched: true,
        };
        assert_eq!(
            (lock.format, lock.plain_jar(GROUP, VICTIM)),
            (format, Some(&jar)),
            "{test}: {lock:?}"
        );
        Some(Pinned {
            cell,
            standin,
            tools,
            uuid,
            install,
            upstream: format!("OUT: PRISTINE {run}"),
            upstream_route: format!("/{UPSTREAM}/{}", repo_path(VICTIM, VERSION, "jar")),
            patched_route,
            started,
        })
    }

    /// Step 1: the build prints the upstream marker, from a jar Bazel
    /// fetched from the stand-in. Gives the files of the checkout.
    fn builds_upstream(&self) -> Tree {
        let (test, route) = (&self.cell.test, &self.upstream_route);
        let pinned = self.standin.asked(route);
        let before = self.cell.builds_unpatched(&self.upstream);
        let fetched = self.standin.asked(route) > pinned;
        assert!(fetched, "{test}: the build did not fetch {route}");
        before
    }

    /// `socket-patch <args>` in the checkout, against the stand-in, with
    /// the directories of [`Pinned::tools`] in the place of the machine's.
    fn socket_patch(&self, args: &[&str]) -> Ran {
        let dir = |name: &str| self.tools.path().join(name).to_string_lossy().into_owned();
        let (m2, gradle, coursier) = (dir("m2"), dir("gradle"), dir("coursier"));
        let env = [
            ("MAVEN_REPO_LOCAL", m2.as_str()),
            ("GRADLE_USER_HOME", &gradle),
            ("COURSIER_CACHE", &coursier),
        ];
        self.cell.socket_patch(&self.standin.origin(), args, &env)
    }

    /// What the command says of the hub: one warning, that Bazel builds
    /// the victim from the lock that the hub's `maven.install` names,
    /// after the warnings `others` of the same run without a workspace.
    fn names_the_hub(&self, get: &Ran, others: &[Value]) {
        let detail = format!(
            "{PURL}: Bazel takes this artifact from maven_install.json (hub \"{HUB}\", \
             `maven.install` at MODULE.bazel:{}), which pins the upstream jar. socket-patch \
             does not patch a rules_jvm_external hub yet, so the Bazel build stays unpatched \
             whatever this command did for another build of the checkout",
            self.install
        );
        let warning = json!({ "code": "maven_bazel_hub_unpatched", "detail": detail });
        let (test, said) = (&self.cell.test, &get.dump);
        let warnings = [others, &[warning]].concat();
        assert_eq!(get.envelope["warnings"], json!(warnings), "{test}: {said}");
    }

    /// The step after the command: the build prints the upstream marker
    /// as before and changed no file of `after`, and no request for the
    /// patched jar reached the stand-in.
    fn still_builds_upstream(&self, after: &Tree) {
        let test = &self.cell.test;
        self.cell.builds(&self.upstream);
        assert_eq!(changed(after, &self.cell.tree()), NOTHING, "{test}");
        let asked = self.standin.asked(&self.patched_route);
        assert_eq!(asked, 0, "{test}: something fetched the patched jar");
    }
}

/// A Maven build and a Bazel build of one checkout: the command pins the
/// Maven build, reports the patch applied, and the Bazel build keeps the
/// upstream jar.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_pom_patch_beside_a_pinned_hub() {
    let test = "maven::a_pom_patch_beside_a_pinned_hub";
    let Some(flow) = Pinned::open(test, true) else {
        return;
    };
    let before = flow.builds_upstream();

    // The one command of hosted mode: the three files of a Maven pin, and
    // the warning about the hub whose lock still names the upstream jar.
    let get = flow.socket_patch(&["get", PURL, "--mode", "hosted", "--yes"]);
    let pinned = flow
        .cell
        .pinned_by(&get, PURL, &flow.uuid, &before, &PINNED);
    flow.names_the_hub(&get, &[]);
    flow.still_builds_upstream(&pinned);

    let undo = flow.socket_patch(&["rollback", "--yes"]);
    flow.cell
        .undone(&undo, "rolledBack", &before, &flow.upstream);
    println!(
        "{test}: Bazel {} built {:?} before and after `get --mode hosted` pinned {PURL} in \
         pom.xml, reported it applied and named the hub; {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.started.elapsed()
    );
}

/// The same checkout without a `pom.xml`: the command writes nothing,
/// says that there is no pom, and says which lock builds the artifact.
#[test]
#[ignore = "real Bazel; run with --ignored"]
fn a_tree_only_bazel_builds() {
    let test = "maven::a_tree_only_bazel_builds";
    let Some(flow) = Pinned::open(test, false) else {
        return;
    };
    let before = flow.builds_upstream();

    let get = flow.socket_patch(&["get", PURL, "--mode", "hosted", "--yes"]);
    let said = &get.dump;
    assert_eq!(get.code, 0, "{test}: {said}");
    let event = event_for(&get.envelope, PURL);
    assert_eq!(
        (&event["action"], &event["errorCode"]),
        (&json!("skipped"), &json!("redirect_unconfirmed")),
        "{test}: {said}"
    );
    let no_pom = "no pom.xml present; maven redirect skipped";
    flow.names_the_hub(
        &get,
        &[json!({ "code": "redirect_maven_no_pom", "detail": no_pom })],
    );
    assert_eq!(
        changed(&before, &flow.cell.tree()),
        NOTHING,
        "{test}: {said}"
    );
    flow.still_builds_upstream(&before);
    println!(
        "{test}: Bazel {} built {:?} before and after `get --mode hosted` skipped {PURL} \
         and named the hub; {:?}",
        flow.cell.release(),
        flow.upstream,
        flow.started.elapsed()
    );
}

/// Without a Bazel: the fixture's directories and the legs of its workflow
/// are those of the table, each era's `MODULE.bazel` has a hub of its own
/// name with the one repository a flow replaces, and a jar made here holds
/// what `App.java` reads.
#[test]
fn the_fixture_has_one_repository_to_replace_per_era() {
    FIXTURE.check();
    for (_, era) in FIXTURE.eras {
        let module = crate::harness::fixture_path(FIXTURE.dir)
            .join(era)
            .join("MODULE.bazel");
        let module = std::fs::read_to_string(&module).expect("MODULE.bazel");
        assert_eq!(module.matches(PLACEHOLDER).count(), 1, "{era}: {module}");
        // No other URL, and the hub is [`HUB`]: no pin resolves what other
        // modules add to a hub named `maven`, or asks a public repository.
        assert_eq!(module.matches("://").count(), 1, "{era}: {module}");
        for named in [
            format!("name = \"{HUB}\","),
            format!("use_repo(maven, \"{HUB}\")"),
        ] {
            assert!(module.contains(&named), "{era}: {named} is not in {module}");
        }
    }
    let build = crate::harness::fixture_path(FIXTURE.dir).join("common/BUILD.bazel");
    let build = std::fs::read_to_string(&build).expect("BUILD.bazel");
    let dep = format!("\"@{HUB}//:dev_socket_fixture_consumer\"");
    assert!(build.contains(&dep), "{build}");
    let app = crate::harness::fixture_path(FIXTURE.dir).join("common/App.java");
    let app = std::fs::read_to_string(&app).expect("App.java");
    assert!(app.contains(&format!("\"/{MARKER}\"")), "{app}");
    let jar = victim("PRISTINE of a run");
    let mut jar = zip::ZipArchive::new(std::io::Cursor::new(&jar[..])).expect("a jar");
    let mut marker = String::new();
    let mut file = jar.by_name(MARKER).expect("the marker");
    std::io::Read::read_to_string(&mut file, &mut marker).expect("its text");
    assert_eq!(marker, "PRISTINE of a run\n");
}
