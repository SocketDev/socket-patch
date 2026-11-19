//! A Maven project beside a Bazel workspace, without a Bazel: what
//! `socket-patch` says about a rules_jvm_external hub, and that it says and
//! writes nothing else.
//!
//! The first test is the one that holds "nothing changes": a hosted `get`
//! and an agent `apply` of a Maven patch print the same bytes and write the
//! same files in a checkout without a Bazel file, in one whose workspace
//! has no rules_jvm_external hub, and in one whose pinned hub does not hold
//! the artifact. A change that turns it red has changed what a project
//! that no hub builds gets. The others hold the one difference a hub
//! makes: a warning of the run, which takes the place of "no pom.xml" in a
//! tree that only Bazel builds when it names the hub, and none under
//! `--global`.
//!
//! The vendored twin is in `vendor_jvm_cli.rs`, which has the fixture of a
//! vendored Maven run. `e2e_bazel_build/maven.rs` holds the hosted flows
//! against what a real Bazel builds, with a hub of the fixture's own name
//! whose lock holds its two artifacts. Here the hub has the default name,
//! `maven`, and its lock also holds an artifact that another Bazel module
//! added, under two repositories ([`lock`]).

#[path = "common/envelope.rs"]
mod envelope;
#[path = "hosted_memory_common/mod.rs"]
mod hosted_memory_common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use envelope::{event_for, warning_codes};
use hosted_memory_common::{hermetic, mount_api, read_tree, Patch, ORG};
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes as git_sha256;

const PURL: &str = "pkg:maven/dev.socket.fixture/victim@1.10.0";
const UUID: &str = "5e0a7c1d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const SUFFIXED: &str = "1.10.0-socket.5e0a7c1d";
const POM: &str =
    "<project><modelVersion>4.0.0</modelVersion><groupId>dev.socket.fixture</groupId>\
                   <artifactId>victim</artifactId><version>1.10.0</version></project>\n";
const PATCHED_POM: &str = "<project><modelVersion>4.0.0</modelVersion><groupId>dev.socket.fixture\
                           </groupId><artifactId>victim</artifactId><version>1.10.0</version>\
                           <!-- socket --></project>\n";
/// The checkout's own build of the artifact.
const PROJECT_POM: &str = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
                           <groupId>com.example</groupId>\n  <artifactId>app</artifactId>\n  \
                           <version>1</version>\n  <dependencies>\n    <dependency>\n      \
                           <groupId>dev.socket.fixture</groupId>\n      \
                           <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    \
                           </dependency>\n  </dependencies>\n</project>\n";

/// A workspace whose hub is pinned, under the name a hub has when its tag
/// gives none: `maven`, the one other Bazel modules add to.
const HUB: &str = r#"bazel_dep(name = "rules_jvm_external", version = "7.2")

maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
maven.install(
    artifacts = ["dev.socket.fixture:consumer:2.0"],
    lock_file = "//:maven_install.json",
)
use_repo(maven, "maven")
"#;
/// A workspace whose only hub is another ruleset's.
const OTHER_HUB: &str = r#"bazel_dep(name = "rules_python", version = "1.4.1")

pip = use_extension("@rules_python//python/extensions:pip.bzl", "pip")
pip.parse(hub_name = "pypi", python_version = "3.11", requirements_lock = "//:maven_install.json")
use_repo(pip, "pypi")
"#;

/// A lock of format 3 as a pin of [`HUB`] writes it when another Bazel
/// module adds to the hub named `maven` too, which the real-Bazel flows do
/// not build: the jar of each of `jars`, an artifact of the group and its
/// version, beside one that the other module asked for, and every artifact
/// under each of the hub's two repositories.
fn lock(jars: &[(&str, &str)]) -> String {
    let pinned = |key: String, version: &str| {
        let pinned = json!({ "shasums": { "jar": "0".repeat(64) }, "version": version });
        (key, pinned)
    };
    let own = |jar: &(&str, &str)| pinned(format!("dev.socket.fixture:{}", jar.0), jar.1);
    let other = pinned("com.google.code.gson:gson".to_string(), "2.8.9");
    let artifacts: serde_json::Map<_, _> = jars.iter().map(own).chain([other]).collect();
    let listed: Vec<&String> = artifacts.keys().collect();
    let lock = json!({
        "artifacts": artifacts,
        "dependencies": {},
        "repositories": {
            "https://repo.example/maven2/": listed,
            "https://repo1.maven.org/maven2/": listed,
        },
        "version": "3",
    });
    format!("{lock:#}\n")
}

/// The Bazel files of the four checkouts: none; a workspace without a
/// rules_jvm_external hub, beside a lock that holds the artifact; a
/// pinned hub that holds another artifact, and the patched one at another
/// version; a pinned hub that builds it.
fn checkouts() -> [Vec<(&'static str, String)>; 4] {
    let module = |text: &str| ("MODULE.bazel", text.to_string());
    let locked = |jars: &[(&str, &str)]| ("maven_install.json", lock(jars));
    let builds = [("consumer", "2.0"), ("victim", "1.10.0")];
    [
        vec![],
        vec![module(OTHER_HUB), locked(&builds)],
        vec![
            module(HUB),
            locked(&[("consumer", "2.0"), ("victim", "1.9.0")]),
        ],
        vec![module(HUB), locked(&builds)],
    ]
}

/// What one command did.
#[derive(Debug, PartialEq)]
struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    /// The files of the checkout and of the Maven local repository that
    /// are not as they were before, with their bytes.
    wrote: BTreeMap<String, Vec<u8>>,
}

impl Ran {
    fn envelope(&self) -> Value {
        serde_json::from_str(&self.stdout).unwrap_or_else(|e| panic!("no envelope ({e}): {self:?}"))
    }
}

/// One directory for every checkout of a test, so that no path in an
/// output differs between two of them, and the Socket API of the patch.
struct Machine {
    root: PathBuf,
    api: wiremock::MockServer,
    // The server runs on it.
    _runtime: tokio::runtime::Runtime,
    _tmp: tempfile::TempDir,
}

impl Machine {
    fn start() -> Machine {
        let tmp = tempfile::tempdir().expect("a directory");
        let root = tmp.path().canonicalize().expect("its real path");
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let api = runtime.block_on(wiremock::MockServer::start());
        // The grant of the hosted patch: the maven2 registry override of
        // production, with the version only that registry serves.
        let index = format!("https://patch.socket.dev/patch-registry/maven/token/{UUID}/maven2");
        let url =
            format!("https://patch.socket.dev/patch/maven/token/{UUID}/victim-{SUFFIXED}.jar");
        let reference = json!({
            "status": "granted",
            "url": url,
            "purl": PURL,
            "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha256": "a".repeat(64) } }],
            "registryOverride": { "kind": "maven2", "indexUrl": index, "identifiers": {
                "name": "dev.socket.fixture/victim",
                "version": "1.10.0",
                "mavenGroupId": "dev.socket.fixture",
                "mavenArtifactId": "victim",
                "mavenSuffixedVersion": SUFFIXED,
                "mavenPomSha256": "b".repeat(64),
            } },
        });
        let patch = Patch {
            purl: PURL.to_string(),
            uuid: UUID.to_string(),
            reference,
        };
        runtime.block_on(mount_api(&api, &[patch]));
        Machine {
            root,
            api,
            _runtime: runtime,
            _tmp: tmp,
        }
    }

    /// Makes the checkout anew, with the Bazel files `bazel` and, when
    /// `maven` is set, its `pom.xml`; a manifest of an agent patch of the
    /// artifact's pom; and the Maven local repository as a build of the
    /// checkout leaves it. Then runs `socket-patch <args>` there.
    fn run(&self, bazel: &[(&str, String)], maven: bool, args: &[&str]) -> Ran {
        let (proj, m2) = (self.root.join("proj"), self.root.join("m2"));
        for dir in [&proj, &m2, &self.root.join("home")] {
            let _ = std::fs::remove_dir_all(dir);
        }
        let write = |path: PathBuf, bytes: &[u8]| {
            std::fs::create_dir_all(path.parent().expect("a directory")).expect("create it");
            std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        };
        std::fs::create_dir_all(proj.join(".git")).expect("a checkout");
        for (path, text) in bazel {
            write(proj.join(path), text.as_bytes());
        }
        if maven {
            write(proj.join("pom.xml"), PROJECT_POM.as_bytes());
        }
        let record = json!({ PURL: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/victim-1.10.0.pom": {
                "beforeHash": git_sha256(POM.as_bytes()),
                "afterHash": git_sha256(PATCHED_POM.as_bytes()),
            } },
            "vulnerabilities": {},
            "description": "a pom patch",
            "license": "MIT",
            "tier": "free",
        } });
        let manifest = format!("{:#}\n", json!({ "patches": record }));
        write(proj.join(".socket/manifest.json"), manifest.as_bytes());
        for bytes in [POM, PATCHED_POM].map(str::as_bytes) {
            write(proj.join(".socket/blobs").join(git_sha256(bytes)), bytes);
        }
        write(
            m2.join("dev/socket/fixture/victim/1.10.0/victim-1.10.0.pom"),
            POM.as_bytes(),
        );
        let before = self.files();

        // Nothing of the machine reaches the child: no tool on PATH, an
        // empty home, and the JVM caches a crawl reads in this directory.
        let mut cmd = hermetic::binary_command();
        cmd.env_clear()
            .envs(hermetic::FORCED_OPT_OUTS.iter().copied());
        for keep in [
            "SYSTEMROOT",
            "SystemRoot",
            "windir",
            "TMPDIR",
            "TEMP",
            "TMP",
        ] {
            cmd.envs(std::env::var_os(keep).map(|value| (keep, value)));
        }
        let home = self.root.join("home");
        std::fs::create_dir_all(&home).expect("a home");
        cmd.current_dir(&proj)
            .env("PATH", "")
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("MAVEN_REPO_LOCAL", &m2)
            .env("GRADLE_USER_HOME", home.join("gradle"))
            .env("COURSIER_CACHE", home.join("coursier"))
            .args(args)
            .args(["--org", ORG, "--api-token", "fake-token"])
            .args(["--api-url", &self.api.uri()]);
        let out = cmd.output().expect("spawn socket-patch");
        let wrote = self.files();
        let wrote = wrote
            .into_iter()
            .filter(|(path, bytes)| before.get(path) != Some(bytes));
        Ran {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            wrote: wrote.collect(),
        }
    }

    /// The files of the checkout and of the Maven local repository.
    fn files(&self) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        for dir in ["proj", "m2"] {
            let under = read_tree(&self.root.join(dir)).into_iter();
            files.extend(under.map(|(path, bytes)| (format!("{dir}/{path}"), bytes)));
        }
        files
    }
}

/// The commands of a run that patches the artifact: hosted and agent mode,
/// each as a program and as a person reads it, and as a dry run.
const COMMANDS: [&[&str]; 6] = [
    &["get", PURL, "--mode", "hosted", "--yes", "--json"],
    &["get", PURL, "--mode", "hosted", "--yes"],
    &["apply", "--offline", "--json"],
    &["apply", "--offline"],
    &[
        "get",
        PURL,
        "--mode",
        "hosted",
        "--yes",
        "--dry-run",
        "--json",
    ],
    &["apply", "--offline", "--dry-run", "--json"],
];

/// The warning of a run in the checkout whose hub builds the artifact.
const HUB_WARNING: &str = "pkg:maven/dev.socket.fixture/victim@1.10.0: Bazel takes this artifact \
    from maven_install.json (hub \"maven\", `maven.install` at MODULE.bazel:4), which pins the \
    upstream jar. socket-patch does not patch a rules_jvm_external hub yet, so the Bazel build \
    stays unpatched whatever this command did for another build of the checkout";

#[test]
fn a_maven_project_no_hub_builds_reports_as_without_bazel() {
    let machine = Machine::start();
    let [plain, other, elsewhere, _] = checkouts();
    for args in COMMANDS {
        let without = machine.run(&plain, true, args);
        // The run did its work: a pin in pom.xml, a patched pom. A dry
        // run writes neither.
        assert_eq!(without.code, Some(0), "{args:?}: {without:?}");
        let patched = match args[0] {
            "get" => "proj/pom.xml",
            _ => "m2/dev/socket/fixture/victim/1.10.0/victim-1.10.0.pom",
        };
        assert_eq!(
            without.wrote.contains_key(patched),
            !args.contains(&"--dry-run"),
            "{args:?}: {without:?}"
        );
        for bazel in [&other, &elsewhere] {
            let beside = machine.run(bazel, true, args);
            assert_eq!(beside, without, "{args:?} beside {:?}", bazel[0].1);
        }
    }
}

#[test]
fn a_hub_that_pins_the_artifact_adds_one_warning_and_nothing_else() {
    let machine = Machine::start();
    let [plain, _, _, hub] = checkouts();
    for args in COMMANDS {
        let (without, beside) = (
            machine.run(&plain, true, args),
            machine.run(&hub, true, args),
        );
        assert_eq!(
            (beside.code, &beside.wrote),
            (without.code, &without.wrote),
            "{args:?}: {beside:?}"
        );
        if args.contains(&"--json") {
            let (mut said, mut expected) = (beside.envelope(), without.envelope());
            let warning = json!({ "code": "maven_bazel_hub_unpatched", "detail": HUB_WARNING });
            let warnings = expected["warnings"].as_array().cloned().unwrap_or_default();
            assert_eq!(
                said["warnings"].take(),
                Value::Array([warnings, vec![warning]].concat()),
                "{args:?}: {beside:?}"
            );
            expected
                .as_object_mut()
                .expect("an envelope")
                .remove("warnings");
            said.as_object_mut()
                .expect("an envelope")
                .remove("warnings");
            assert_eq!(said, expected, "{args:?}");
            assert_eq!(beside.stderr, without.stderr, "{args:?}");
        } else {
            // One line more on stderr, and it is the warning.
            assert_eq!(beside.stdout, without.stdout, "{args:?}");
            let line = format!("Warning: {HUB_WARNING}");
            let (mut said, expected) = (beside.stderr.lines(), without.stderr.lines());
            let rest: Vec<&str> = said.by_ref().filter(|said| *said != line).collect();
            assert_eq!(rest, expected.collect::<Vec<_>>(), "{args:?}: {beside:?}");
            assert_eq!(
                beside.stderr.matches(&line).count(),
                1,
                "{args:?}: {beside:?}"
            );
        }
    }
}

#[test]
fn a_hub_only_tree_names_the_lock_that_builds_it() {
    let machine = Machine::start();
    let [plain, _, elsewhere, hub] = checkouts();
    let lockless = HUB.replace("    lock_file = \"//:maven_install.json\",\n", "");
    let unreadable = vec![("MODULE.bazel", lockless)];
    let json = COMMANDS[0];
    let no_pom = "redirect_maven_no_pom";
    for (bazel, codes) in [
        // Without a hub that holds it, the release's answer.
        (&plain, &[no_pom][..]),
        (&elsewhere, &[no_pom]),
        // A hub that is named for every Maven patch of the run takes its
        // place; one that could not be read stands beside it.
        (&hub, &["maven_bazel_hub_unpatched"]),
        (&unreadable, &[no_pom, "maven_bazel_unreadable"]),
    ] {
        let ran = machine.run(bazel, false, json);
        let envelope = ran.envelope();
        let event = event_for(&envelope, PURL);
        assert_eq!(
            (ran.code, &event["action"], &event["errorCode"]),
            (Some(0), &json!("skipped"), &json!("redirect_unconfirmed")),
            "{codes:?}: {ran:?}"
        );
        assert_eq!(warning_codes(&envelope), codes, "{ran:?}");
        assert_eq!(ran.wrote, BTreeMap::new(), "{codes:?}");
    }
    // A person is pointed at the warning, which is the one about the hub.
    let ran = machine.run(&hub, false, COMMANDS[1]);
    let pointed = "no lockfile entry pinning it could be rewritten (see the warning below)";
    assert!(ran.stderr.contains(pointed), "{ran:?}");
    assert!(
        ran.stderr.contains(&format!("Warning: {HUB_WARNING}")),
        "{ran:?}"
    );
    assert!(!ran.stderr.to_lowercase().contains("no pom.xml"), "{ran:?}");
    let detail = machine.run(&unreadable, false, json).envelope()["warnings"][1]["detail"].clone();
    let why = "pkg:maven/dev.socket.fixture/victim@1.10.0: socket-patch could not tell whether \
               Bazel takes this artifact from a rules_jvm_external hub: MODULE.bazel:4: hub \
               \"maven\" has no `lock_file`";
    assert_eq!(detail, why);
}

#[test]
fn a_global_run_says_nothing() {
    let machine = Machine::start();
    let [plain, _, _, hub] = checkouts();
    // A hub that builds the artifact, and one that cannot be read.
    let unpinned = vec![("MODULE.bazel", HUB.to_string())];
    let global = ["apply", "--offline", "--global", "--json"];
    for args in [&global[..], &global[..3]] {
        let without = machine.run(&plain, true, args);
        assert_eq!(without.code, Some(0), "{args:?}: {without:?}");
        assert!(!without.wrote.is_empty(), "{args:?}: {without:?}");
        for bazel in [&hub, &unpinned] {
            assert_eq!(machine.run(bazel, true, args), without, "{args:?}");
        }
    }
}
