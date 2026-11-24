//! A Maven project beside a Bazel workspace, without a Bazel: what
//! `socket-patch` says about a rules_jvm_external hub and writes for it,
//! and that it says and writes nothing else.
//!
//! The first test is the one that holds "nothing changes": a hosted `get`
//! and an agent `apply` of a Maven patch print the same bytes and write the
//! same files in a checkout without a Bazel file, in one whose workspace
//! has no rules_jvm_external hub, and in one whose pinned hub does not hold
//! the artifact. A change that turns it red has changed what a project
//! that no hub builds gets.
//!
//! The others hold what a hub that builds the artifact changes. A hosted
//! run writes one block at the end of the root `MODULE.bazel`, beside
//! whatever it pins for a Maven build, and `rollback` takes it out to the
//! byte; where it cannot show that the block would work it writes nothing
//! for the hub and gives one warning with the reason, in the place of "no
//! pom.xml" in a tree that only Bazel builds. An agent run patches no hub
//! and says so, unless the block already does. A `--global` run says
//! nothing.
//!
//! A hosted `scan` at the Bazel root takes the jars that the pinned hubs
//! fetch for packages of the project, at the versions of their locks, so
//! it finds the patch of one in a tree that only Bazel builds, also from a
//! root above other projects, and names a hub it could not read. A scan
//! in another mode, one that leaves Maven out, and one where no hub of the
//! ruleset is declared are the scans without Bazel.
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

use envelope::{event_for, event_triples, warning_codes};
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
/// That workspace with a file its `MODULE.bazel` includes and the checkout
/// lacks: something of it cannot be read, and nothing of it names the
/// ruleset of a Maven hub.
fn unread_other() -> Files {
    let module = format!("{OTHER_HUB}include(\"//:more.MODULE.bazel\")\n");
    vec![("MODULE.bazel", module)]
}

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
        Machine::serving(PURL)
    }

    /// A machine whose API has the patch under `purl`: the artifact's own,
    /// or the one of a jar of it with a classifier.
    fn serving(purl: &str) -> Machine {
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
            "purl": purl,
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
            purl: purl.to_string(),
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

    /// Makes the checkout anew ([`Machine::make`]) and runs `socket-patch
    /// <args>` there.
    fn run(&self, bazel: &[(&str, String)], maven: bool, args: &[&str]) -> Ran {
        self.make(bazel, maven, true);
        self.step(args)
    }

    /// Makes the checkout anew, with the Bazel files `bazel` and, when
    /// `maven` is set, its `pom.xml`; when `agent` is set, a manifest of
    /// an agent patch of the artifact's pom; and the Maven local
    /// repository as a build of the checkout leaves it.
    fn make(&self, bazel: &[(&str, String)], maven: bool, agent: bool) {
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
        if agent {
            write(proj.join(".socket/manifest.json"), manifest.as_bytes());
            for bytes in [POM, PATCHED_POM].map(str::as_bytes) {
                write(proj.join(".socket/blobs").join(git_sha256(bytes)), bytes);
            }
        }
        write(
            m2.join("dev/socket/fixture/victim/1.10.0/victim-1.10.0.pom"),
            POM.as_bytes(),
        );
    }

    /// Runs `socket-patch <args>` in the checkout as it is.
    fn step(&self, args: &[&str]) -> Ran {
        self.step_in(&self.root.join("proj"), args)
    }

    /// Runs `socket-patch <args>` in the directory `proj` of the checkout.
    fn step_in(&self, proj: &std::path::Path, args: &[&str]) -> Ran {
        let m2 = self.root.join("m2");
        let before = self.files();

        // Nothing of the machine reaches the child: no tool on PATH, an
        // empty home, and the JVM caches a crawl reads in this directory.
        // `LLVM_PROFILE_FILE` stays: a binary built for coverage writes
        // its profile where that names, and without it into the project
        // directory, where a test holds a run to the files it wrote.
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
            "LLVM_PROFILE_FILE",
        ] {
            cmd.envs(std::env::var_os(keep).map(|value| (keep, value)));
        }
        let home = self.root.join("home");
        std::fs::create_dir_all(&home).expect("a home");
        cmd.current_dir(proj)
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

/// The warning of an agent run in the checkout whose hub builds the
/// artifact.
const HUB_WARNING: &str = "pkg:maven/dev.socket.fixture/victim@1.10.0: Bazel takes this artifact \
    from maven_install.json (hub \"maven\", `maven.install` at MODULE.bazel:4), which pins the \
    upstream jar, and this command does not patch a rules_jvm_external hub: the Bazel build stays \
    unpatched whatever it did for another build of the checkout. `socket-patch get \
    pkg:maven/dev.socket.fixture/victim@1.10.0 --mode hosted` at the Bazel root patches a pinned \
    hub";

/// What a hosted run says after its reason when it writes no entry for a
/// hub.
const KEEPS: &str = "socket-patch wrote nothing to MODULE.bazel for it, so the Bazel build keeps \
                     the upstream jar";
/// Its reason in a checkout that names no Bazel release and has no
/// `MODULE.bazel.lock`.
const NO_RELEASE: &str = "no file of the checkout says that Bazel 7.4.0 or later builds it, and \
                          an older Bazel fails on the `override_repo` an entry needs: name the \
                          release in `.bazelversion`";

/// The warning of a hosted run that writes no entry, for the reason `why`.
fn declined(why: &str) -> String {
    format!("{PURL}: {why}. {KEEPS}")
}

/// The block a hosted run keeps at the end of `MODULE.bazel` for the
/// patch of the stand-in API, with its last line break.
const BLOCK: &str = r#"# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_http_file = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

socket_patch_maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")

# pkg:maven/dev.socket.fixture/victim@1.10.0, Socket patch 5e0a7c1d-7b4e-4c1a-9f0e-2a3b4c5d6e7f
socket_patch_http_file(
    name = "socket_patch_dev_socket_fixture_victim_1_10_0",
    downloaded_file_path = "v1/dev/socket/fixture/victim/1.10.0/victim-1.10.0.jar",
    sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    urls = ["https://patch.socket.dev/patch-registry/maven/token/5e0a7c1d-7b4e-4c1a-9f0e-2a3b4c5d6e7f/maven2/dev/socket/fixture/victim/1.10.0-socket.5e0a7c1d/victim-1.10.0-socket.5e0a7c1d.jar"],
)

# If Bazel stops at the next line ("does not generate repository"), the hub's lock no longer pins
# dev.socket.fixture:victim at 1.10.0: run `socket-patch rollback pkg:maven/dev.socket.fixture/victim@1.10.0`.
# Do not change it to inject_repo(): the build would pass without the patch.
override_repo(
    socket_patch_maven,
    dev_socket_fixture_victim_1_10_0 = "socket_patch_dev_socket_fixture_victim_1_10_0",
)
# <<< socket-patch <<<
"#;

/// The workspace whose pinned hub builds the artifact, with what says
/// which Bazel builds it and which release of the ruleset Bazel selected:
/// the one a hosted run writes its block for.
fn pinned() -> Files {
    let [.., mut hub] = checkouts();
    let bcr = "https://bcr.bazel.build/modules/rules_jvm_external";
    let lock = json!({ "lockFileVersion": 13, "registryFileHashes": {
        format!("{bcr}/6.5/MODULE.bazel"): "0",
        format!("{bcr}/7.2/MODULE.bazel"): "1",
        format!("{bcr}/7.2/source.json"): "2",
    } });
    hub.push((".bazelversion", "7.7.2\n".to_string()));
    hub.push(("MODULE.bazel.lock", format!("{lock:#}\n")));
    hub
}

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
        // An agent run patches no hub. A hosted run would, and says why it
        // does not here: nothing in this checkout names its Bazel.
        let (code, detail) = match args[0] {
            "get" => ("maven_bazel_release", declined(NO_RELEASE)),
            _ => ("maven_bazel_hub_unpatched", HUB_WARNING.to_string()),
        };
        if args.contains(&"--json") {
            let (mut said, mut expected) = (beside.envelope(), without.envelope());
            let warning = json!({ "code": code, "detail": detail });
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
            let line = format!("Warning: {detail}");
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
fn a_hub_only_tree_says_why_the_hub_is_not_patched() {
    let machine = Machine::start();
    let [plain, _, elsewhere, hub] = checkouts();
    let lockless = HUB.replace("    lock_file = \"//:maven_install.json\",\n", "");
    let unpinned = vec![("MODULE.bazel", lockless)];
    let json = COMMANDS[0];
    let no_pom = "redirect_maven_no_pom";
    for (bazel, codes) in [
        // Without a hub that holds it, the release's answer.
        (&plain, &[no_pom][..]),
        (&elsewhere, &[no_pom]),
        // What a hub builds has its own answer, in the place of that one.
        (&hub, &["maven_bazel_release"]),
        (&unpinned, &["maven_bazel_not_pinned"]),
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
    // A person is pointed at the one warning, which says why nothing was
    // pinned and what the Bazel build keeps.
    let pointed = "no lockfile entry pinning it could be rewritten (see the warning below)\n";
    let not_pinned =
        "MODULE.bazel:4: hub \"maven\" has no `lock_file`, so Bazel resolves its jars \
                      when it builds and none can be replaced: give the hub a `lock_file` and \
                      pin it (`REPIN=1 bazel run @maven//:pin`)";
    for (bazel, why) in [(&hub, NO_RELEASE), (&unpinned, not_pinned)] {
        let ran = machine.run(bazel, false, COMMANDS[1]);
        let warning = format!("Warning: {}\n", declined(why));
        let at = [pointed, &warning].map(|line| ran.stderr.find(line));
        assert!(at[0].is_some() && at[0] < at[1], "{ran:?}");
        assert_eq!(
            ran.stderr.matches("Warning: pkg:maven").count(),
            1,
            "{ran:?}"
        );
        assert!(!ran.stderr.contains("pom.xml"), "{ran:?}");
    }
}

/// The files of a Maven pin, and the block's.
const POM_FILES: [&str; 3] = [
    "proj/.mvn/checksums/checksums.sha256",
    "proj/.mvn/maven.config",
    "proj/pom.xml",
];
const MODULE: &str = "proj/MODULE.bazel";

#[test]
fn a_pinned_hub_gets_its_block_and_the_undo_takes_it_out() {
    let machine = Machine::start();
    let with_block = format!("{HUB}\n{BLOCK}");
    for maven in [false, true] {
        let mut files = vec![MODULE];
        if maven {
            files.extend(POM_FILES);
        }
        files.sort_unstable();
        let rewritten: Vec<&str> = files.iter().map(|file| &file["proj/".len()..]).collect();
        // A dry run says what the run will do, and writes nothing.
        machine.make(&pinned(), maven, false);
        let dry = machine.step(COMMANDS[4]);
        let envelope = dry.envelope();
        assert_eq!(event_for(&envelope, PURL)["action"], "verified", "{dry:?}");
        assert_eq!(
            envelope["redirect"]["rewrittenFiles"],
            json!(rewritten),
            "{dry:?}"
        );
        assert_eq!(
            (dry.code, &dry.wrote),
            (Some(0), &BTreeMap::new()),
            "{dry:?}"
        );

        // The run: applied, no warning, the block after one blank line.
        let get = machine.step(COMMANDS[0]);
        let envelope = get.envelope();
        assert_eq!(get.code, Some(0), "{get:?}");
        assert_eq!(event_for(&envelope, PURL)["action"], "applied", "{get:?}");
        assert_eq!(
            envelope["redirect"]["rewrittenFiles"],
            json!(rewritten),
            "{get:?}"
        );
        assert_eq!(envelope["warnings"], Value::Null, "{get:?}");
        assert_eq!(get.wrote.keys().collect::<Vec<_>>(), files, "{get:?}");
        assert_eq!(
            String::from_utf8_lossy(&get.wrote[MODULE]),
            with_block,
            "{get:?}"
        );

        // Again: still applied, and nothing to write.
        let again = machine.step(COMMANDS[0]);
        let envelope = again.envelope();
        assert_eq!(event_for(&envelope, PURL)["action"], "applied", "{again:?}");
        assert_eq!(
            envelope["redirect"]["rewrittenFiles"],
            json!([]),
            "{again:?}"
        );
        assert_eq!(
            (again.code, &again.wrote),
            (Some(0), &BTreeMap::new()),
            "{again:?}"
        );

        // A scan keeps the pin it finds in the file.
        let scan = machine.step(&["scan", "--mode", "hosted", "--yes", "--json"]);
        assert_eq!(
            (scan.code, &scan.wrote),
            (Some(0), &BTreeMap::new()),
            "{scan:?}"
        );

        // `list` reads the pin from the file, and `vex` attests it.
        let list = machine.step(&["list", "--json"]).envelope();
        let listed = event_for(&list, PURL);
        assert_eq!(listed["details"]["mode"], "hosted", "{list:#}");
        let pinned_in = listed["details"]["lockfiles"]
            .as_array()
            .expect("the files");
        assert!(pinned_in.contains(&json!("MODULE.bazel")), "{list:#}");
        let product = ["--product", "pkg:generic/proj"];
        let vex =
            machine.step(&[&["vex", "--json", "--output", "vex.json"], &product[..]].concat());
        let attested = vex.envelope();
        assert_eq!(
            event_for(&attested, PURL)["details"]["status"],
            "not_affected",
            "{vex:?}"
        );
        std::fs::remove_file(machine.root.join("proj/vex.json")).expect("the document");

        // The undo: every file is the one of before, to the byte.
        let undo = machine.step(&["rollback", "--yes", "--json"]);
        assert_eq!(undo.code, Some(0), "{undo:?}");
        assert_eq!(undo.envelope()["summary"]["rolledBack"], 1, "{undo:?}");
        let restored = |path: &str| String::from_utf8_lossy(&undo.wrote[path]).into_owned();
        assert_eq!(restored(MODULE), HUB, "{undo:?}");
        if maven {
            assert_eq!(restored("proj/pom.xml"), PROJECT_POM, "{undo:?}");
        }
        assert_eq!(undo.wrote.len(), 1 + usize::from(maven), "{undo:?}");
        let left = machine.files();
        let mvn = left.keys().any(|path| path.starts_with("proj/.mvn/"));
        assert!(!mvn, "{left:?}");
    }
    // `remove` takes the entry out as `rollback` does.
    machine.make(&pinned(), false, false);
    assert_eq!(machine.step(COMMANDS[0]).wrote.len(), 1);
    let removed = machine.step(&["remove", PURL, "--yes", "--json"]);
    assert_eq!(removed.code, Some(0), "{removed:?}");
    let restored = String::from_utf8_lossy(&removed.wrote[MODULE]);
    assert_eq!((removed.wrote.len(), &*restored), (1, HUB), "{removed:?}");

    // A person is told which file to commit.
    machine.make(&pinned(), false, false);
    let person = machine.step(COMMANDS[1]);
    assert!(person.stdout.contains("rewrote 1 file"), "{person:?}");
    assert!(person.stdout.contains("Commit MODULE.bazel"), "{person:?}");
    assert!(!person.stderr.contains("Warning: pkg:maven"), "{person:?}");
}

/// The Bazel files of a checkout, each with its text.
type Files = Vec<(&'static str, String)>;

/// A Maven pin is not always one edit of the root `pom.xml`. In a reactor
/// it goes to the module that selects the version, with the repository in
/// the root; a version that a property sets is pinned through the
/// property; and behind a mirror of the machine's Maven settings that
/// would take the Socket repository there is no pin at all, and the run
/// says so. Beside a pinned hub each of those runs still writes the hub's
/// block: Bazel fetches the jar of an entry by its URL, through no mirror
/// of Maven's. The pin is one, in the block and in every pom that holds
/// part of it, and the undo takes all of it out, to the byte.
#[test]
fn the_hub_gets_its_block_whatever_the_maven_pin_is() {
    let machine = Machine::start();
    let root = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  \
                <groupId>com.example</groupId>\n  <artifactId>root</artifactId>\n  \
                <version>1</version>\n  <packaging>pom</packaging>\n  <modules>\n    \
                <module>app</module>\n  </modules>\n</project>\n";
    let module = PROJECT_POM.replace(
        "  <groupId>com.example</groupId>\n  <artifactId>app</artifactId>\n  <version>1</version>\n",
        "  <parent>\n    <groupId>com.example</groupId>\n    <artifactId>root</artifactId>\n    \
         <version>1</version>\n  </parent>\n  <artifactId>app</artifactId>\n",
    );
    let property = PROJECT_POM
        .replace("<version>1.10.0<", "<version>${victim.version}<")
        .replace(
            "  <dependencies>\n",
            "  <properties>\n    <victim.version>1.10.0</victim.version>\n  </properties>\n  \
             <dependencies>\n",
        );
    assert!(module.contains("<parent>") && property.contains("<properties>"));
    let mirror = "<settings>\n  <mirrors>\n    <mirror>\n      <id>corp</id>\n      \
                  <mirrorOf>*</mirrorOf>\n      <url>https://repo.example/maven2</url>\n    \
                  </mirror>\n  </mirrors>\n</settings>\n";
    // The poms of the checkout, those of them that take part of the pin,
    // the settings of the machine, and what the run warns of.
    let rows: [(&str, Files, &[&str], Option<&str>, &[&str]); 3] = [
        (
            "a reactor",
            vec![("pom.xml", root.to_string()), ("app/pom.xml", module)],
            &["app/pom.xml", "pom.xml"],
            None,
            &[],
        ),
        (
            "a property",
            vec![("pom.xml", property)],
            &["pom.xml"],
            None,
            &[],
        ),
        (
            "a mirror",
            vec![("pom.xml", PROJECT_POM.to_string())],
            &[],
            Some(mirror),
            &["redirect_maven_mirror_captures_repository"],
        ),
    ];
    for (shape, poms, pinned_poms, settings, warns) in rows {
        machine.make(&[pinned(), poms].concat(), false, false);
        if let Some(settings) = settings {
            let m2 = machine.root.join("home/.m2");
            std::fs::create_dir_all(&m2).expect("the user's Maven directory");
            std::fs::write(m2.join("settings.xml"), settings).expect("the settings");
        }
        let before = machine.files();

        let get = machine.step(COMMANDS[0]);
        let envelope = get.envelope();
        assert_eq!(get.code, Some(0), "{shape}: {get:?}");
        assert_eq!(
            event_for(&envelope, PURL)["action"],
            "applied",
            "{shape}: {get:?}"
        );
        assert_eq!(warning_codes(&envelope), warns, "{shape}: {get:?}");
        // The block, the poms of the pin, and the checksum files of a
        // Maven pin when there is one.
        let pin: Vec<&str> = [&["MODULE.bazel"], pinned_poms].concat();
        let mut wrote: Vec<String> = pin.iter().map(|file| format!("proj/{file}")).collect();
        let checksums = &POM_FILES[..2 * usize::from(!pinned_poms.is_empty())];
        wrote.extend(checksums.iter().map(|file| file.to_string()));
        wrote.sort_unstable();
        assert_eq!(
            get.wrote.keys().collect::<Vec<_>>(),
            wrote.iter().collect::<Vec<_>>(),
            "{shape}: {get:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&get.wrote[MODULE]),
            format!("{HUB}\n{BLOCK}"),
            "{shape}"
        );

        // `list` shows one pin, in those files, and `vex` states it once.
        let of_the_patch = |envelope: &Value| -> Vec<Value> {
            let events = envelope::events(envelope).iter();
            events
                .filter(|event| event["purl"] == PURL)
                .cloned()
                .collect()
        };
        let listed = of_the_patch(&machine.step(&["list", "--json"]).envelope());
        assert_eq!(listed.len(), 1, "{shape}: {listed:?}");
        assert_eq!(
            listed[0]["details"]["lockfiles"],
            json!(pin),
            "{shape}: {listed:?}"
        );
        let vex = ["vex", "--json", "--output", "vex.json"];
        let vex = machine.step(&[&vex[..], &["--product", "pkg:generic/proj"]].concat());
        let stated = of_the_patch(&vex.envelope());
        assert_eq!(stated.len(), 1, "{shape}: {vex:?}");
        assert_eq!(
            stated[0]["details"]["status"], "not_affected",
            "{shape}: {vex:?}"
        );
        std::fs::remove_file(machine.root.join("proj/vex.json")).expect("the document");

        // A second run finds all of it in place, and the undo leaves none.
        let again = machine.step(COMMANDS[0]);
        assert_eq!(
            (again.code, &again.wrote),
            (Some(0), &BTreeMap::new()),
            "{shape}: {again:?}"
        );
        let undo = machine.step(&["rollback", "--yes", "--json"]);
        assert_eq!(undo.code, Some(0), "{shape}: {undo:?}");
        assert_eq!(
            undo.envelope()["summary"]["rolledBack"],
            1,
            "{shape}: {undo:?}"
        );
        assert_eq!(machine.files(), before, "{shape}: {undo:?}");
    }
}

/// Where the block cannot be shown to work the run writes nothing for
/// the hub and says why: alone in a tree only Bazel builds, and beside
/// the Maven pin, which still lands, in a tree that Maven builds too.
#[test]
fn a_decline_writes_nothing_for_the_hub_and_says_why() {
    let machine = Machine::start();
    let with = |change: &dyn Fn(&mut Files)| {
        let mut files = pinned();
        change(&mut files);
        files
    };
    let module = |text: String| move |files: &mut Files| files[0].1 = text.clone();
    let over = format!(
        "{HUB}maven.override(coordinates = \"dev.socket.fixture:victim\", target = \"//:own\")\n"
    );
    let edited = format!("{HUB}\n{}", BLOCK.replace("# Do not", "# Do"));
    let rows = [
        (
            with(&|files| files.truncate(2)),
            "maven_bazel_release",
            "name the release in `.bazelversion`",
        ),
        (
            with(&|files| files[2].1 = "7.3.1\n".to_string()),
            "maven_bazel_release",
            "the checkout names Bazel 7.3.1",
        ),
        (
            with(&|files| files.push((".bazelrc", "common --noenable_bzlmod\n".to_string()))),
            "maven_bazel_no_effect",
            ".bazelrc:1 names `--noenable_bzlmod`",
        ),
        (
            with(&|files| files.push((".bazelrc", "common --vendor_dir=v\n".to_string()))),
            "maven_bazel_download",
            ".bazelrc:1 names `--vendor_dir=v`",
        ),
        (
            with(&module(over)),
            "maven_bazel_no_effect",
            "MODULE.bazel:9: a `maven.override` gives",
        ),
        (
            with(&module(edited)),
            "maven_bazel_unreadable",
            "MODULE.bazel:10: the block that socket-patch keeps there was changed by hand",
        ),
    ];
    for (bazel, code, why) in &rows {
        for maven in [false, true] {
            let ran = machine.run(bazel, maven, COMMANDS[0]);
            let envelope = ran.envelope();
            let (action, files) = match maven {
                true => ("applied", POM_FILES.to_vec()),
                false => ("skipped", Vec::new()),
            };
            assert_eq!(ran.code, Some(0), "{code}: {ran:?}");
            assert_eq!(
                event_for(&envelope, PURL)["action"],
                action,
                "{code}: {ran:?}"
            );
            assert_eq!(
                ran.wrote.keys().collect::<Vec<_>>(),
                files,
                "{code}: {ran:?}"
            );
            assert_eq!(warning_codes(&envelope), [*code], "{ran:?}");
            let detail = envelope["warnings"][0]["detail"]
                .as_str()
                .expect("its text");
            let said = detail.starts_with(PURL) && detail.contains(why) && detail.ends_with(KEEPS);
            assert!(said, "{code}: {detail}");
        }
    }
    // A project below the root of its workspace: the file is not its own.
    machine.make(&pinned(), false, false);
    let below = machine.root.join("proj/services/billing");
    std::fs::create_dir_all(&below).expect("a project");
    let ran = machine.step_in(&below, COMMANDS[0]);
    assert_eq!(
        warning_codes(&ran.envelope()),
        ["maven_bazel_not_at_root"],
        "{ran:?}"
    );
    assert_eq!(ran.wrote, BTreeMap::new(), "{ran:?}");
}

/// A run that can no longer show that the block works leaves the entry
/// of an earlier run where it is, and says so: the patch is still pinned.
#[test]
fn a_decline_leaves_the_entry_of_an_earlier_run_in_place() {
    let machine = Machine::start();
    for maven in [false, true] {
        machine.make(&pinned(), maven, false);
        assert_eq!(machine.step(COMMANDS[0]).code, Some(0));
        for names_bazel in [".bazelversion", "MODULE.bazel.lock"] {
            std::fs::remove_file(machine.root.join("proj").join(names_bazel)).expect("the file");
        }
        let again = machine.step(COMMANDS[0]);
        let envelope = again.envelope();
        assert_eq!(
            (again.code, &again.wrote),
            (Some(0), &BTreeMap::new()),
            "{again:?}"
        );
        assert_eq!(event_for(&envelope, PURL)["action"], "applied", "{again:?}");
        assert_eq!(
            warning_codes(&envelope),
            ["maven_bazel_release"],
            "{again:?}"
        );
        let left = "socket-patch left the entry that MODULE.bazel holds for it as it is";
        assert_eq!(
            envelope["warnings"][0]["detail"],
            format!("{PURL}: {NO_RELEASE}. {left}"),
            "{again:?}"
        );
    }
}

/// A run below the Bazel root writes nothing. When the block of the root
/// already holds the entry of the patch, the Bazel build takes the patched
/// jar: the run says that the entry stands, and reports the patch as a
/// decline beside its own entry at the root does.
#[test]
fn a_run_below_the_root_says_that_the_entry_at_the_root_stands() {
    let machine = Machine::start();
    machine.make(&pinned(), false, false);
    assert_eq!(machine.step(COMMANDS[0]).wrote.len(), 1);
    let below = machine.root.join("proj/services/billing");
    std::fs::create_dir_all(&below).expect("a project");
    let ran = machine.step_in(&below, COMMANDS[0]);
    let envelope = ran.envelope();
    assert_eq!(
        (ran.code, &ran.wrote),
        (Some(0), &BTreeMap::new()),
        "{ran:?}"
    );
    assert_eq!(event_for(&envelope, PURL)["action"], "applied", "{ran:?}");
    assert_eq!(
        warning_codes(&envelope),
        ["maven_bazel_not_at_root"],
        "{ran:?}"
    );
    let detail = envelope["warnings"][0]["detail"]
        .as_str()
        .expect("its text");
    let stands = "run the command there. socket-patch left the entry that the MODULE.bazel at \
                  the root holds for it as it is";
    assert!(
        detail.starts_with(PURL) && detail.ends_with(stands),
        "{detail}"
    );
}

/// A decline beside the entry of another patch of the same jar: that entry
/// is not this run's to replace, so it remains, and the warning names it
/// in the place of "keeps the upstream jar".
#[test]
fn a_decline_names_the_entry_of_another_patch_that_remains() {
    let machine = Machine::start();
    let other = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    let mut files = pinned();
    files[0].1 = format!("{HUB}\n{}", BLOCK.replace(UUID, other));
    files.truncate(2);
    for maven in [false, true] {
        let ran = machine.run(&files, maven, COMMANDS[0]);
        let envelope = ran.envelope();
        let (action, wrote) = match maven {
            true => ("applied", POM_FILES.to_vec()),
            false => ("skipped", Vec::new()),
        };
        assert_eq!(ran.code, Some(0), "{ran:?}");
        assert_eq!(event_for(&envelope, PURL)["action"], action, "{ran:?}");
        assert_eq!(ran.wrote.keys().collect::<Vec<_>>(), wrote, "{ran:?}");
        assert_eq!(warning_codes(&envelope), ["maven_bazel_release"], "{ran:?}");
        let remains = format!(
            "{PURL}: {NO_RELEASE}. socket-patch wrote nothing to MODULE.bazel for it: the entry \
             of patch {other} remains there, and where the block is in effect the Bazel build \
             takes that patch's jar"
        );
        assert_eq!(envelope["warnings"][0]["detail"], remains, "{ran:?}");
    }
}

/// A block that was changed by hand, also in its first line alone, is no
/// pin that a command manages: `get` writes nothing to it, and `rollback`
/// and `list` refuse and name the file to restore.
#[test]
fn a_block_that_was_changed_by_hand_is_refused_by_the_undo() {
    let machine = Machine::start();
    let changed = "MODULE.bazel:10: the block that socket-patch keeps there was changed by hand";
    for edited in [
        BLOCK.replace("# Do not", "# Do"),
        BLOCK.replacen(") >>>\n", ") >>> \n", 1),
    ] {
        assert_ne!(edited, BLOCK);
        let mut files = pinned();
        files[0].1 = format!("{HUB}\n{edited}");
        machine.make(&files, false, false);
        let get = machine.step(COMMANDS[0]);
        let envelope = get.envelope();
        assert_eq!(
            warning_codes(&envelope),
            ["maven_bazel_unreadable"],
            "{get:?}"
        );
        let detail = envelope["warnings"][0]["detail"]
            .as_str()
            .expect("its text");
        assert!(detail.contains(changed), "{detail}");
        assert_eq!(get.wrote, BTreeMap::new(), "{get:?}");
        for args in [&["rollback", "--yes", "--json"][..], &["list", "--json"]] {
            let ran = machine.step(args);
            let error = &ran.envelope()["error"];
            let message = error["message"].as_str().unwrap_or_default();
            assert_eq!(
                (ran.code, &error["code"]),
                (Some(1), &json!("hosted_wiring_contested")),
                "{args:?}: {ran:?}"
            );
            let named =
                message.contains(changed) && message.contains("git checkout -- MODULE.bazel");
            assert!(named, "{args:?}: {message}");
            assert_eq!(ran.wrote, BTreeMap::new(), "{args:?}");
        }
    }
}

/// A patch of a jar with a classifier is not the jar that a hub's lock
/// names by group and artifact. Beside a pinned hub that builds the plain
/// jar, a hosted run for it is the run without Bazel: nothing is written
/// to `MODULE.bazel`, and nothing is said of the hub.
#[test]
fn a_patch_of_a_classifier_jar_gets_nothing_of_the_hub() {
    let purl = format!("{PURL}?classifier=tests");
    let machine = Machine::serving(&purl);
    let [plain, ..] = checkouts();
    for maven in [false, true] {
        for json in [true, false] {
            let mut args = vec!["get", purl.as_str(), "--mode", "hosted", "--yes"];
            args.extend(json.then_some("--json"));
            let without = machine.run(&plain, maven, &args);
            assert_eq!(without.code, Some(0), "{without:?}");
            assert_eq!(machine.run(&pinned(), maven, &args), without, "{args:?}");
        }
    }
}

/// The hub's lock moves on after the pin: Bazel then stops at the entry,
/// `vex` attests nothing for it, and the command the block names there
/// takes it out.
#[test]
fn an_entry_whose_jar_the_lock_no_longer_pins_is_undone_and_not_attested() {
    let machine = Machine::start();
    machine.make(&pinned(), false, false);
    assert_eq!(machine.step(COMMANDS[0]).wrote.len(), 1);
    let moved = lock(&[("consumer", "2.0"), ("victim", "1.11.0")]);
    std::fs::write(machine.root.join("proj/maven_install.json"), moved).expect("the lock");

    let vex = ["vex", "--json", "--output", "vex.json"];
    let vex = machine.step(&[&vex[..], &["--product", "pkg:generic/proj"]].concat());
    let said = vex.envelope();
    assert_eq!(said["events"], json!([]), "{vex:?}");
    assert_eq!(
        warning_codes(&said),
        ["patched_ref_unattributable"],
        "{vex:?}"
    );
    assert_eq!(vex.wrote, BTreeMap::new(), "{vex:?}");
    let list = machine.step(&["list", "--json"]).envelope();
    assert_eq!(
        event_for(&list, PURL)["details"]["mode"],
        "hosted",
        "{list:#}"
    );

    let undo = machine.step(&["rollback", PURL, "--yes", "--json"]);
    assert_eq!(undo.code, Some(0), "{undo:?}");
    assert_eq!(undo.envelope()["summary"]["rolledBack"], 1, "{undo:?}");
    assert_eq!(
        String::from_utf8_lossy(&undo.wrote[MODULE]),
        HUB,
        "{undo:?}"
    );
}

/// An agent run beside a hub that hosted mode has patched: the Bazel
/// build takes the block's jar, and nothing is said of the hub.
#[test]
fn an_agent_run_says_nothing_of_a_hub_the_block_patches() {
    let machine = Machine::start();
    let [plain, ..] = checkouts();
    for args in [COMMANDS[2], COMMANDS[3]] {
        let without = machine.run(&plain, true, args);
        let mut patched = pinned();
        patched[0].1 = format!("{HUB}\n{BLOCK}");
        let beside = machine.run(&patched, true, args);
        assert_eq!(beside, without, "{args:?}");
    }
}

/// A hosted scan, as a program reads it.
const SCAN: [&str; 5] = ["scan", "--mode", "hosted", "--yes", "--json"];

/// A hosted scan in a tree that only Bazel builds: the jars the pinned
/// hub's lock fetches are its packages, each one that no crawl found
/// installed, and the one with a patch gets its entry in the block.
#[test]
fn a_hosted_scan_takes_the_jars_of_a_pinned_hub_for_packages() {
    let machine = Machine::start();
    let with_block = format!("{HUB}\n{BLOCK}");
    machine.make(&pinned(), false, false);
    // A dry run says what the scan will do, and writes nothing.
    let dry = machine.step(&[&SCAN[..], &["--dry-run"]].concat());
    let action = |ran: &Ran| event_for(&ran.envelope(), PURL)["action"].clone();
    assert_eq!(action(&dry), "verified", "{dry:?}");
    assert_eq!(
        (dry.code, &dry.wrote),
        (Some(0), &BTreeMap::new()),
        "{dry:?}"
    );

    let scan = machine.step(&SCAN);
    let envelope = scan.envelope();
    assert_eq!(scan.code, Some(0), "{scan:?}");
    // The victim, the consumer and what another Bazel module added.
    let counted = ["scannedPackages", "lockfileOnlyPackages"].map(|count| &envelope[count]);
    assert_eq!(counted, [&json!(3), &json!(3)], "{scan:?}");
    let found = envelope["packages"].as_array().expect("the packages");
    let patched: Vec<_> = found.iter().map(|package| &package["purl"]).collect();
    assert_eq!(patched, [PURL], "{scan:?}");
    assert_eq!(found[0]["notInstalled"], true, "{scan:?}");
    assert_eq!(action(&scan), "applied", "{scan:?}");
    assert_eq!(
        envelope["redirect"]["rewrittenFiles"],
        json!(["MODULE.bazel"]),
        "{scan:?}"
    );
    assert_eq!(envelope["warnings"], Value::Null, "{scan:?}");
    assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), [MODULE], "{scan:?}");
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        with_block,
        "{scan:?}"
    );
    // Again: the pin stands, and nothing is written.
    let again = machine.step(&SCAN);
    assert_eq!(action(&again), "applied", "{again:?}");
    assert_eq!(
        (again.code, &again.wrote),
        (Some(0), &BTreeMap::new()),
        "{again:?}"
    );

    // A scan that names no mode is a hosted one, and a person is told
    // which file to commit.
    machine.make(&pinned(), false, false);
    let person = machine.step(&["scan", "--yes"]);
    assert_eq!(person.code, Some(0), "{person:?}");
    assert!(person.stdout.contains("Commit MODULE.bazel"), "{person:?}");
    assert!(!person.stdout.contains("No packages found"), "{person:?}");
    assert_eq!(
        String::from_utf8_lossy(&person.wrote[MODULE]),
        with_block,
        "{person:?}"
    );

    // A jar whose repository has no known name is a package too: the run
    // that finds a patch of it says why it gets no entry.
    let mut odd = pinned();
    odd[1].1 = lock(&[("consumer", "2.0"), ("victim", "1.10.0+local")]);
    machine.make(&odd, false, false);
    let scan = machine.step(&SCAN);
    assert_eq!(scan.envelope()["scannedPackages"], 3, "{scan:?}");
    assert_eq!(scan.wrote, BTreeMap::new(), "{scan:?}");
}

/// A Bazel root is often a project of another package manager too. The
/// jars of its hub join the packages its own lockfile names, and the root
/// is scanned once, above the projects below it.
#[test]
fn a_hosted_scan_takes_the_jars_of_a_hub_beside_a_lockfile_of_the_root() {
    let machine = Machine::start();
    let package = json!({ "name": "app", "version": "1.0.0" });
    let npm = json!({ "name": "app", "version": "1.0.0", "lockfileVersion": 3,
        "packages": { "": package, "node_modules/left-pad": { "version": "1.3.0" } } });
    let mut files = pinned();
    files.push(("package.json", package.to_string()));
    files.push(("package-lock.json", npm.to_string()));
    machine.make(&files, false, false);
    let scan = machine.step(&SCAN);
    let envelope = scan.envelope();
    // The npm package of the root's lock and the three jars of the hub's.
    let counted = ["scannedPackages", "lockfileOnlyPackages"].map(|count| &envelope[count]);
    assert_eq!(counted, [&json!(4), &json!(4)], "{scan:?}");
    assert_eq!(event_for(&envelope, PURL)["action"], "applied", "{scan:?}");
    assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), [MODULE], "{scan:?}");
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        format!("{HUB}\n{BLOCK}"),
        "{scan:?}"
    );

    // Above another project: the root has its one section, the first.
    files.push(("web/package.json", package.to_string()));
    files.push(("web/package-lock.json", npm.to_string()));
    machine.make(&files, false, false);
    let person = machine.step(&["scan", "--yes"]);
    let headings: Vec<&str> = person
        .stdout
        .lines()
        .filter(|l| l.starts_with("== "))
        .collect();
    assert_eq!(headings, ["== . ==", "== web =="], "{person:?}");
    assert_eq!(
        person.wrote.keys().collect::<Vec<_>>(),
        [MODULE],
        "{person:?}"
    );
}

/// The block for a patch `uuid` of the victim at `version`, as
/// socket-patch writes it.
/// A Gradle build that has nothing of the hub's jars.
const GRADLE: [(&str, &str); 3] = [
    ("settings.gradle", "rootProject.name = 'app'\n"),
    (
        "build.gradle",
        "plugins { id 'java' }\ndependencies { implementation 'com.example:other:1.0' }\n",
    ),
    (
        "gradle.lockfile",
        "com.example:other:1.0=compileClasspath\nempty=\n",
    ),
];

fn block_at(version: &str, uuid: &str) -> String {
    let name = version.replace('.', "_");
    let block = BLOCK.replace("1.10.0", version).replace("1_10_0", &name);
    block.replace(UUID, uuid).replace(&UUID[..8], &uuid[..8])
}

/// The hub's lock moves on after a pin, and Bazel stops at the entry of
/// the release it held. A hosted scan takes that entry out as `rollback
/// <purl>` does, says so, and pins the patch of the release the lock holds
/// now. It leaves the entry while a hub is in doubt, and a scan that reads
/// no hub leaves it too.
#[test]
fn a_hosted_scan_takes_a_stale_entry_out_of_the_block() {
    let machine = Machine::start();
    let old = "pkg:maven/dev.socket.fixture/victim@1.9.0";
    let old_uuid = "0a1b2c3d-1111-4222-8333-444455556666";
    let stale = "maven_bazel_entry_stale";
    let mut files = pinned();
    files[0].1 = format!("{HUB}\n{}", block_at("1.9.0", old_uuid));
    let triples = |ran: &Ran| event_triples(&ran.envelope());
    let event = |purl: &str, action: &str, code: &str| {
        (purl.to_string(), action.to_string(), code.to_string())
    };

    // The API has a patch of the release the lock holds: a dry run says
    // what the scan will do, and writes nothing.
    machine.make(&files, false, false);
    let dry = machine.step(&[&SCAN[..], &["--dry-run"]].concat());
    assert_eq!(
        triples(&dry),
        [event(old, "verified", stale), event(PURL, "verified", "")],
        "{dry:?}"
    );
    assert_eq!(
        (dry.code, &dry.wrote),
        (Some(0), &BTreeMap::new()),
        "{dry:?}"
    );
    let scan = machine.step(&SCAN);
    assert_eq!(
        triples(&scan),
        [event(old, "rolledBack", stale), event(PURL, "applied", "")],
        "{scan:?}"
    );
    let said = scan.envelope();
    let taken_out = &said["events"][0];
    assert_eq!(taken_out["uuid"], old_uuid, "{scan:?}");
    assert_eq!(
        taken_out["reason"],
        format!(
            "patch {old_uuid} is for a jar that no pinned rules_jvm_external hub of the Bazel \
             workspace fetches any more, so Bazel stops at its entry in MODULE.bazel; the pin \
             was restored to the upstream registry entry"
        ),
        "{scan:?}"
    );
    assert_eq!((scan.code, &said["warnings"]), (Some(0), &Value::Null));
    assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), [MODULE], "{scan:?}");
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        format!("{HUB}\n{BLOCK}"),
        "{scan:?}"
    );
    let again = machine.step(&SCAN);
    assert_eq!(triples(&again), [event(PURL, "applied", "")], "{again:?}");
    assert_eq!(again.wrote, BTreeMap::new(), "{again:?}");

    // No patch of the release the lock holds: the file is the one of
    // before the first pin, to the byte, and a person reads why.
    let moved = lock(&[("consumer", "2.0"), ("victim", "1.11.0")]);
    let bump = || {
        machine.make(&pinned(), false, false);
        assert_eq!(machine.step(COMMANDS[0]).wrote.len(), 1);
        std::fs::write(machine.root.join("proj/maven_install.json"), &moved).expect("the lock");
    };
    bump();
    let scan = machine.step(&SCAN);
    assert_eq!(
        triples(&scan),
        [event(PURL, "rolledBack", stale)],
        "{scan:?}"
    );
    assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), [MODULE], "{scan:?}");
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        HUB,
        "{scan:?}"
    );
    bump();
    let person = machine.step(&["scan", "--yes"]);
    let note = format!(
        "Note: patch {UUID} for {PURL} is for a jar that no pinned rules_jvm_external hub of \
         the Bazel workspace fetches any more, so Bazel stops at its entry in MODULE.bazel; \
         restoring its upstream registry entry\n"
    );
    assert_eq!(person.stderr.matches(&note).count(), 1, "{person:?}");
    let restored = format!("Restored {PURL} to its upstream registry entry\n");
    assert!(person.stdout.contains(&restored), "{person:?}");
    assert_eq!(
        String::from_utf8_lossy(&person.wrote[MODULE]),
        HUB,
        "{person:?}"
    );

    // A hub that fetches no jar at all: the scan has no package, and the
    // entry goes all the same.
    bump();
    let empty = json!({ "artifacts": {}, "dependencies": {}, "repositories": {}, "version": "3" });
    std::fs::write(
        machine.root.join("proj/maven_install.json"),
        empty.to_string(),
    )
    .expect("it");
    let scan = machine.step(&SCAN);
    assert_eq!(scan.envelope()["scannedPackages"], 0, "{scan:?}");
    assert_eq!(
        triples(&scan),
        [event(PURL, "rolledBack", stale)],
        "{scan:?}"
    );
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        HUB,
        "{scan:?}"
    );

    // While a hub is in doubt it may be the one that fetches the jar: the
    // entry stays. It stays in a scan that reads no hub, too.
    bump();
    let module = machine.root.join("proj/MODULE.bazel");
    let pinned_text = std::fs::read_to_string(&module).expect("MODULE.bazel");
    let doubted = format!("{pinned_text}maven.install(name = \"tools\")\n");
    std::fs::write(&module, doubted).expect("MODULE.bazel");
    let scan = machine.step(&SCAN);
    assert_eq!(triples(&scan), [], "{scan:?}");
    assert_eq!(
        warning_codes(&scan.envelope()),
        ["maven_bazel_hub_not_read"],
        "{scan:?}"
    );
    assert_eq!(scan.wrote, BTreeMap::new(), "{scan:?}");
    bump();
    let no_maven = machine.step(&[&SCAN[..], &["--ecosystems", "npm"]].concat());
    assert_eq!(
        (no_maven.code, &no_maven.wrote),
        (Some(0), &BTreeMap::new()),
        "{no_maven:?}"
    );

    // Beside a `pom.xml` that still selects the release: the pin of the
    // Maven build stays, and the entry alone goes.
    machine.make(&pinned(), true, false);
    assert_eq!(machine.step(COMMANDS[0]).wrote.len(), 4);
    std::fs::write(machine.root.join("proj/maven_install.json"), &moved).expect("the lock");
    let scan = machine.step(&SCAN);
    assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), [MODULE], "{scan:?}");
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        HUB,
        "{scan:?}"
    );
    assert_eq!(
        triples(&scan),
        [event(PURL, "rolledBack", stale), event(PURL, "applied", "")],
        "{scan:?}"
    );

    // Beside a Gradle build the same: the entry alone goes, and the pin
    // that the first scan wrote for Gradle stays for `list` to show and
    // for `rollback <purl>` to take out.
    let mut files = pinned();
    files.extend(GRADLE.iter().map(|(path, text)| (*path, text.to_string())));
    machine.make(&files, false, false);
    assert_eq!(machine.step(&SCAN).wrote.len(), 5);
    std::fs::write(machine.root.join("proj/maven_install.json"), &moved).expect("the lock");
    let scan = machine.step(&SCAN);
    assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), [MODULE], "{scan:?}");
    assert_eq!(
        triples(&scan),
        [event(PURL, "rolledBack", stale)],
        "{scan:?}"
    );
    let list = machine.step(&["list", "--json"]).envelope();
    assert_eq!(
        event_for(&list, PURL)["details"]["lockfiles"],
        json!([".socket/gradle/hosted-index.tsv"]),
        "{list:#}"
    );
}

/// A hosted scan that crawls nothing does two things, and they leave each
/// other alone. It takes a stale entry out of the Bazel workspace's block,
/// first and under the apply lock; and it takes what a pnpm registry route
/// left out of the pnpm files, after that and under a lock of its own. The
/// envelope holds both: the event of the entry, an event for each entry of
/// the route, and the route's files as what the run rewrote.
#[test]
fn an_empty_hosted_scan_takes_a_stale_entry_and_what_a_pnpm_route_left() {
    let machine = Machine::start();
    machine.make(&pinned(), false, false);
    assert_eq!(machine.step(COMMANDS[0]).wrote.len(), 1);
    let proj = machine.root.join("proj");
    // A hub that fetches no jar at all: the scan has no package.
    let empty = json!({ "artifacts": {}, "dependencies": {}, "repositories": {}, "version": "3" });
    std::fs::write(proj.join("maven_install.json"), empty.to_string()).expect("the lock");
    // What a routed scan left once its package was gone: the file it
    // created, with a registry and an override that no lock uses, and the
    // lock's record of that override.
    let (token, patch) = (
        "22222222-2222-4222-8222-222222222222",
        "aaaaaaaa-1111-4111-8111-111111111111",
    );
    let workspace = format!(
        "packages:\n  - '.'\nnamedRegistries:\n  socket-aaaaaaaa: \
         https://patch.socket.dev/patch/npm/gone/1.0.0/{token}/{patch}/\noverrides:\n  \
         'gone@1.0.0': 'socket-aaaaaaaa:1.0.0'\n"
    );
    std::fs::write(proj.join("pnpm-workspace.yaml"), workspace).expect("the workspace file");
    let bare = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n";
    let record = "overrides:\n  gone@1.0.0: socket-aaaaaaaa:1.0.0\n\nimporters:\n";
    std::fs::write(
        proj.join("pnpm-lock.yaml"),
        bare.replace("importers:\n", record),
    )
    .expect("the pnpm lock");

    let scan = machine.step(&SCAN);
    let envelope = scan.envelope();
    assert_eq!(scan.code, Some(0), "{scan:?}");
    assert_eq!(envelope["scannedPackages"], 0, "{scan:?}");
    // The entry of the block.
    let stale = (
        PURL.to_string(),
        "rolledBack".to_string(),
        "maven_bazel_entry_stale".to_string(),
    );
    assert!(event_triples(&envelope).contains(&stale), "{scan:?}");
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        HUB,
        "{scan:?}"
    );
    // The entries of the route.
    let unused = envelope["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter(|event| event["errorCode"] == "registry_entry_unused")
        .count();
    assert_eq!(unused, 3, "{scan:?}");
    assert_eq!(
        envelope["redirect"]["rewrittenFiles"],
        json!(["pnpm-lock.yaml", "pnpm-workspace.yaml"]),
        "{scan:?}"
    );
    let lock = std::fs::read_to_string(proj.join("pnpm-lock.yaml")).expect("the pnpm lock");
    assert_eq!(lock, bare, "{scan:?}");
    assert!(!proj.join("pnpm-workspace.yaml").exists(), "{scan:?}");
}

/// The socket.yml policy holds a stale entry as it holds the packages of
/// the run: a scan of a root that the policy filters, and one whose
/// policy filters the package, leave the entry where it is.
#[test]
fn a_hosted_scan_leaves_a_stale_entry_that_the_policy_filters() {
    let machine = Machine::start();
    let mut files = pinned();
    files[0].1 = format!(
        "{HUB}\n{}",
        block_at("1.9.0", "0a1b2c3d-1111-4222-8333-444455556666")
    );
    let below: Vec<(String, String)> = files
        .iter()
        .map(|(path, text)| (format!("legacy/{path}"), text.clone()))
        .collect();
    let mut below: Files = below
        .iter()
        .map(|(path, text)| (&*path.clone().leak(), text.clone()))
        .collect();
    let filtered = |policy: &str| ("socket.yml", format!("version: 2\npatches:\n  {policy}\n"));
    below.push(filtered("ignorePaths: [\"/legacy/\"]"));
    files.push(filtered(
        "ignorePackages: [\"pkg:maven/dev.socket.fixture/victim\"]",
    ));
    for (files, dir) in [(&below, "proj/legacy"), (&files, "proj")] {
        machine.make(files, false, false);
        let scan = machine.step_in(&machine.root.join(dir), &SCAN);
        let said = scan.envelope();
        assert_eq!(
            (scan.code, &said["events"], &scan.wrote),
            (Some(0), &json!([]), &BTreeMap::new()),
            "{dir}: {scan:?}"
        );
    }
}

/// A checkout that Gradle or Maven builds too. A hub's jar with a patch is
/// a patch of the run like one it found installed, so the scan writes for
/// it what `get <purl>` writes there: the Gradle pin beside the block, or
/// what the pom lane says of a `pom.xml` it cannot pin.
#[test]
fn a_hosted_scan_pins_a_hubs_jar_in_the_other_builds_as_get_does() {
    let machine = Machine::start();
    // A pom whose dependency is not in the Maven local repository: what
    // Maven selects cannot be told.
    let other = PROJECT_POM
        .replace("dev.socket.fixture", "com.example")
        .replace("victim", "other");
    let rows: [(&[(&str, &str)], &[&str], &[&str]); 2] = [
        (
            &GRADLE,
            &[
                "proj/.socket/gradle/.gitattributes",
                "proj/.socket/gradle/hosted-index.tsv",
                "proj/.socket/gradle/socket-patch.hosted.settings.gradle",
                MODULE,
                "proj/settings.gradle",
            ],
            &[
                "redirect_gradle_module_metadata_unavailable",
                "redirect_gradle_detached_configs_unguarded",
            ],
        ),
        (
            &[("pom.xml", &other)],
            &[MODULE],
            &["redirect_maven_selection_undetermined"],
        ),
    ];
    for (build, wrote, codes) in rows {
        let mut files = pinned();
        files.extend(build.iter().map(|(path, text)| (*path, text.to_string())));
        machine.make(&files, false, false);
        let get = machine.step(COMMANDS[0]);
        machine.make(&files, false, false);
        let scan = machine.step(&SCAN);
        assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), wrote, "{scan:?}");
        assert_eq!(scan.wrote, get.wrote, "{scan:?}");
        let (scan, get) = (scan.envelope(), get.envelope());
        assert_eq!(event_for(&scan, PURL)["action"], "applied", "{scan:#}");
        assert_eq!(warning_codes(&scan), codes, "{scan:#}");
        assert_eq!(scan["warnings"], get["warnings"], "{scan:#}");
    }
}

/// The version of a hub's jar is the lock's, whatever a `pom.xml` beside
/// the hub selects. Where Maven builds another release, the scan pins the
/// release Bazel builds, and says that it left the pom as it is.
#[test]
fn a_hosted_scan_pins_the_release_of_the_lock_beside_a_pom_of_another() {
    let machine = Machine::start();
    let mut files = pinned();
    files.push(("pom.xml", PROJECT_POM.replace("1.10.0", "1.9.0")));
    machine.make(&files, false, false);
    let scan = machine.step(&SCAN);
    let envelope = scan.envelope();
    assert_eq!(event_for(&envelope, PURL)["action"], "applied", "{scan:?}");
    let codes = warning_codes(&envelope);
    assert_eq!(codes, ["redirect_maven_version_not_selected"], "{scan:?}");
    assert_eq!(scan.wrote.keys().collect::<Vec<_>>(), [MODULE], "{scan:?}");
    assert_eq!(
        String::from_utf8_lossy(&scan.wrote[MODULE]),
        format!("{HUB}\n{BLOCK}"),
        "{scan:?}"
    );
}

/// The words of the warning for a hub that was not read, after where and
/// why.
const NOT_READ: &str = "so socket-patch does not know every Maven artifact that Bazel builds here \
                        through a rules_jvm_external hub: it looks for patches of the ones in the \
                        hub locks it read, and of no other";

/// No jar is guessed for a hub that cannot be read: the scan says once
/// what it did not read, and takes the jars of the hubs it read.
#[test]
fn a_hub_that_a_scan_could_not_read_is_named_once() {
    let machine = Machine::start();
    let scan = |bazel: &Files, args: &[&str]| {
        machine.make(bazel, false, false);
        machine.step(args)
    };
    let warned = |ran: &Ran| ran.envelope()["warnings"].clone();
    let not_read =
        |detail: String| json!([{ "code": "maven_bazel_hub_not_read", "detail": detail }]);
    // A hub without a lock, alone: no package, and how to pin it.
    let lockless = HUB.replace("    lock_file = \"//:maven_install.json\",\n", "");
    let unpinned = vec![("MODULE.bazel", lockless)];
    let detail = format!(
        "MODULE.bazel:4: hub \"maven\" has no `lock_file`, {NOT_READ}. Give the hub a \
         `lock_file` and pin it (`REPIN=1 bazel run @maven//:pin`)"
    );
    let ran = scan(&unpinned, &SCAN);
    assert_eq!(ran.envelope()["scannedPackages"], 0, "{ran:?}");
    assert_eq!(warned(&ran), not_read(detail.clone()), "{ran:?}");
    assert_eq!(
        (ran.code, &ran.wrote),
        (Some(0), &BTreeMap::new()),
        "{ran:?}"
    );
    // A person is pointed at the warning, not at an install.
    let person = scan(&unpinned, &["scan", "--yes"]);
    assert_eq!(person.stdout, "No packages found (see the warning).\n");
    let line = format!("Warning: {detail}\n");
    assert_eq!(person.stderr.matches(&line).count(), 1, "{person:?}");

    // A lock that is not there.
    let [.., mut missing] = checkouts();
    missing.truncate(1);
    let ran = scan(&missing, &SCAN);
    let detail = format!("maven_install.json: it does not exist, {NOT_READ}");
    assert_eq!(warned(&ran), not_read(detail), "{ran:?}");
    assert_eq!(ran.envelope()["scannedPackages"], 0, "{ran:?}");

    // A workspace that names no ruleset of a hub, with a file its reader
    // cannot have: beside a `maven_install.json` it may have a hub.
    let mut other = unread_other();
    other.push(("maven_install.json", lock(&[("victim", "1.10.0")])));
    let ran = scan(&other, &SCAN);
    let gone = "more.MODULE.bazel: it does not exist; MODULE.bazel:6 includes it";
    assert_eq!(
        warned(&ran),
        not_read(format!("{gone}, {NOT_READ}")),
        "{ran:?}"
    );
    assert_eq!(ran.envelope()["scannedPackages"], 0, "{ran:?}");

    // Beside a pinned hub: its jars are scanned, and the patch of one
    // gets no entry while the other hub may build the upstream jar.
    let mut beside = pinned();
    beside[0].1.push_str("maven.install(name = \"tools\")\n");
    let ran = scan(&beside, &SCAN);
    let envelope = ran.envelope();
    assert_eq!(envelope["scannedPackages"], 3, "{ran:?}");
    assert_eq!(
        warning_codes(&envelope),
        ["maven_bazel_hub_not_read", "maven_bazel_not_pinned"],
        "{ran:?}"
    );
    let named = envelope["warnings"][0]["detail"].as_str().expect("text");
    assert!(
        named.starts_with("MODULE.bazel:9: hub \"tools\" has no `lock_file`, so"),
        "{named}"
    );
    let event = event_for(&envelope, PURL);
    assert_eq!(
        (ran.code, &event["action"], &event["errorCode"], &ran.wrote),
        (
            Some(0),
            &json!("skipped"),
            &json!("redirect_unconfirmed"),
            &BTreeMap::new()
        ),
        "{ran:?}"
    );
}

/// A person's scan from the root of a checkout covers the project
/// directories below it, and the root when it is a project. The root of a
/// Bazel workspace needs no file that makes it one: it is a project of a
/// hosted scan when its hubs have jars, or one of them was not read. Of
/// any other scan it is none, as without Bazel.
#[test]
fn a_bare_scan_covers_a_bazel_root_above_other_projects() {
    let machine = Machine::start();
    let package = json!({ "name": "web", "version": "1.0.0" });
    let web = |mut bazel: Files| {
        let lock = json!({ "name": "web", "version": "1.0.0", "lockfileVersion": 3,
            "packages": { "": package, "node_modules/left-pad": { "version": "1.3.0" } } });
        bazel.push(("web/package.json", package.to_string()));
        bazel.push(("web/package-lock.json", lock.to_string()));
        bazel
    };
    let scan = |bazel: Files, args: &[&str]| {
        machine.make(&web(bazel), false, false);
        machine.step(args)
    };
    let headings = |ran: &Ran| -> Vec<String> {
        let lines = ran.stdout.lines().filter(|line| line.starts_with("== "));
        lines.map(String::from).collect()
    };
    let person = ["scan", "--yes"];
    let both = ["== . ==", "== web =="];

    let ran = scan(pinned(), &person);
    assert_eq!(ran.code, Some(0), "{ran:?}");
    assert_eq!(headings(&ran), both, "{ran:?}");
    assert_eq!(ran.wrote.keys().collect::<Vec<_>>(), [MODULE], "{ran:?}");
    assert_eq!(
        String::from_utf8_lossy(&ran.wrote[MODULE]),
        format!("{HUB}\n{BLOCK}"),
        "{ran:?}"
    );

    let lockless = HUB.replace("    lock_file = \"//:maven_install.json\",\n", "");
    let ran = scan(vec![("MODULE.bazel", lockless)], &person);
    assert_eq!(ran.code, Some(0), "{ran:?}");
    assert_eq!(headings(&ran), both, "{ran:?}");
    let named = "Warning: MODULE.bazel:4: hub \"maven\" has no `lock_file`, so";
    assert_eq!(ran.stderr.matches(named).count(), 1, "{ran:?}");
    assert_eq!(ran.wrote, BTreeMap::new(), "{ran:?}");

    // A hub that fetches no jar, and a stale entry of the block: the
    // root is scanned for that entry alone, and it goes.
    let empty = json!({ "artifacts": {}, "dependencies": {}, "repositories": {}, "version": "3" });
    let stale = vec![
        ("MODULE.bazel", format!("{HUB}\n{BLOCK}")),
        ("maven_install.json", empty.to_string()),
    ];
    let ran = scan(stale, &person);
    assert_eq!(headings(&ran), both, "{ran:?}");
    assert_eq!(String::from_utf8_lossy(&ran.wrote[MODULE]), HUB, "{ran:?}");

    // The root is `--cwd`, which the user named: it is scanned in a
    // directory that the built-in ignores leave out of a search, where
    // the project below it is left out.
    let under = |(path, text): (&str, String)| -> (&'static str, String) {
        (Box::leak(format!("testdata/{path}").into_boxed_str()), text)
    };
    let nested: Files = web(pinned()).into_iter().map(under).collect();
    machine.make(&nested, false, false);
    let ran = machine.step_in(&machine.root.join("proj/testdata"), &person);
    assert_eq!(headings(&ran), [""; 0], "{ran:?}");
    assert_eq!(
        String::from_utf8_lossy(&ran.wrote["proj/testdata/MODULE.bazel"]),
        format!("{HUB}\n{BLOCK}"),
        "{ran:?}"
    );

    let [plain, other, ..] = checkouts();
    let vendored = ["scan", "--mode", "vendored", "--yes"];
    let no_maven = ["scan", "--yes", "--ecosystems", "npm"];
    let rows: [(Files, &[&str]); 4] = [
        (other, &person),
        (unread_other(), &person),
        (pinned(), &vendored),
        (pinned(), &no_maven),
    ];
    for (bazel, args) in rows {
        let without = scan(plain.clone(), args);
        assert_eq!(without.code, Some(0), "{args:?}: {without:?}");
        assert_eq!(headings(&without), [""; 0], "{args:?}: {without:?}");
        assert_eq!(scan(bazel, args), without, "{args:?}");
    }
}

/// A scan that patches no hub does not take a hub's jars for packages:
/// one in vendored or agent mode, one that leaves Maven out. And a hosted
/// scan finds no hub where none is declared at the project: with a lock
/// of that name and no workspace file, with another ruleset's hub, and in
/// a project below the Bazel root. Each is the scan without Bazel.
#[test]
fn a_scan_that_reads_no_hub_reports_as_without_bazel() {
    let machine = Machine::start();
    let [plain, other, ..] = checkouts();
    let lock_alone = vec![("maven_install.json", lock(&[("victim", "1.10.0")]))];
    let no_maven = [&SCAN[..], &["--ecosystems", "npm"]].concat();
    let unread = unread_other();
    let rows: [(&Files, bool, &[&str]); 8] = [
        (&pinned(), false, &["scan", "--mode", "agent", "--json"]),
        (&pinned(), false, &["scan", "--mode", "vendored", "--json"]),
        (&pinned(), false, &no_maven),
        (&other, false, &SCAN),
        (&other, true, &SCAN),
        (&unread, false, &SCAN),
        (&lock_alone, false, &SCAN),
        (&lock_alone, true, &SCAN),
    ];
    for (bazel, maven, args) in rows {
        let scan = |bazel: &Files| {
            machine.make(bazel, maven, false);
            machine.step(args)
        };
        let without = scan(&plain);
        assert_eq!(without.code, Some(0), "{args:?}: {without:?}");
        assert_eq!(scan(bazel), without, "{args:?} beside {:?}", bazel[0].0);
    }
    let below = machine.root.join("proj/services/billing");
    let scan_below = |bazel: &Files| {
        machine.make(bazel, false, false);
        std::fs::create_dir_all(&below).expect("a project");
        machine.step_in(&below, &SCAN)
    };
    assert_eq!(scan_below(&pinned()), scan_below(&plain));
}

/// `get` by an advisory keeps, of the releases the advisory has patches
/// for, the ones the project has. In hosted mode the jars of a pinned hub
/// count, as they do for a hosted scan, and a hub that was not read is
/// named.
#[test]
fn a_hosted_get_by_advisory_keeps_the_release_a_pinned_hub_fetches() {
    use wiremock::matchers::{method, path};
    let machine = Machine::start();
    let ghsa = "GHSA-test-aaaa-bbbb";
    let found = json!({ "uuid": UUID, "purl": PURL, "publishedAt": "2024-01-01T00:00:00Z",
        "description": "fixture", "license": "MIT", "tier": "free", "vulnerabilities": {} });
    let answer = json!({ "patches": [found], "canAccessPaidPatches": false });
    let search = wiremock::Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{ghsa}")))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(answer));
    machine._runtime.block_on(search.mount(&machine.api));
    let get = |bazel: &Files| {
        machine.make(bazel, false, false);
        machine.step(&["get", ghsa, "--mode", "hosted", "--yes", "--json"])
    };
    let [plain, ..] = checkouts();
    let without = get(&plain);
    let event = event_for(&without.envelope(), PURL).clone();
    assert_eq!(
        (&event["action"], &event["errorCode"], &without.wrote),
        (
            &json!("skipped"),
            &json!("package_not_installed"),
            &BTreeMap::new()
        ),
        "{without:?}"
    );
    let beside = get(&pinned());
    let event = event_for(&beside.envelope(), PURL).clone();
    assert_eq!(
        (beside.code, &event["action"]),
        (Some(0), &json!("applied"))
    );
    assert_eq!(
        String::from_utf8_lossy(&beside.wrote[MODULE]),
        format!("{HUB}\n{BLOCK}"),
        "{beside:?}"
    );
    let lockless = HUB.replace("    lock_file = \"//:maven_install.json\",\n", "");
    let unread = get(&vec![("MODULE.bazel", lockless)]);
    let envelope = unread.envelope();
    let codes = warning_codes(&envelope);
    assert_eq!(codes, ["maven_bazel_hub_not_read"], "{unread:?}");
    assert_eq!(
        (&event_for(&envelope, PURL)["errorCode"], &unread.wrote),
        (&json!("package_not_installed"), &BTreeMap::new()),
        "{unread:?}"
    );

    // An advisory with no Maven artifact: the hub that was not read has
    // nothing to do with it, and is not named.
    let (npm, other) = ("pkg:npm/left-pad@1.3.0", "GHSA-test-cccc-dddd");
    let found = json!({ "uuid": UUID, "purl": npm, "publishedAt": "2024-01-01T00:00:00Z",
        "description": "fixture", "license": "MIT", "tier": "free", "vulnerabilities": {} });
    let answer = json!({ "patches": [found], "canAccessPaidPatches": false });
    let search = wiremock::Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{other}")))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(answer));
    machine._runtime.block_on(search.mount(&machine.api));
    let lockless = HUB.replace("    lock_file = \"//:maven_install.json\",\n", "");
    machine.make(&[("MODULE.bazel", lockless)], false, false);
    let unrelated = machine.step(&["get", other, "--mode", "hosted", "--yes", "--json"]);
    let envelope = unrelated.envelope();
    assert_eq!(
        (
            &envelope["warnings"],
            &event_for(&envelope, npm)["errorCode"]
        ),
        (&Value::Null, &json!("package_not_installed")),
        "{unrelated:?}"
    );
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
