//! CLI flows of the v5 JVM vendored backend over synthetic offline
//! fixtures: a reactor (an aggregator and one module) and a
//! Gradle multi-project, each fed by a fake local Maven repository.
//!
//! These pin the review findings that only show through the CLI's own
//! bookkeeping (ledger carry-forward, the stale-uuid sweep, per-package
//! rollback, repair, `vex`): two patches revert in any order, a patch
//! update re-wires and reverts to pristine, a re-run needs no jar source,
//! and a tampered ledger or an escaping symlink is refused.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;
use std::process::Command;

use sha2::{Digest as _, Sha256};

const FOO_UUID: &str = "1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const BAR_UUID: &str = "9a8b7c6d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const FOO_UPDATE_UUID: &str = "2e4d6f80-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const MEMBER: &str = "META-INF/NOTICE.txt";

#[derive(Clone, Copy, PartialEq)]
enum Shape {
    Reactor,
    Gradle,
}

fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
}

fn purl(name: &str) -> String {
    format!("pkg:maven/org.example/{name}@1.0")
}

fn jar(notice: &[u8]) -> Vec<u8> {
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in [
        ("META-INF/MANIFEST.MF", &b"Manifest-Version: 1.0\n"[..]),
        (MEMBER, notice),
    ] {
        zw.start_file(name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

/// `root/{m2,proj}` for `shape` depending on every `(name, uuid)` package.
fn fixture(root: &Path, shape: Shape, packages: &[(&str, &str)]) {
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".socket/blobs")).unwrap();
    let mut patches = serde_json::Map::new();
    for (name, uuid) in packages {
        let dir = root.join(format!("m2/org/example/{name}/1.0"));
        std::fs::create_dir_all(&dir).unwrap();
        let before = format!("NOTICE {name}\n").into_bytes();
        let after = [before.as_slice(), b"PATCHED\n"].concat();
        std::fs::write(dir.join(format!("{name}-1.0.jar")), jar(&before)).unwrap();
        std::fs::write(
            dir.join(format!("{name}-1.0.pom")),
            format!(
                "<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId>\
                 <artifactId>{name}</artifactId><version>1.0</version></project>\n"
            ),
        )
        .unwrap();
        std::fs::write(proj.join(".socket/blobs").join(git_sha256(&after)), &after).unwrap();
        patches.insert(
            purl(name),
            serde_json::json!({
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { MEMBER: {
                    "beforeHash": git_sha256(&before),
                    "afterHash": git_sha256(&after),
                } },
                "vulnerabilities": { "GHSA-xxxx-yyyy-zzzz": {
                    "cves": ["CVE-2026-0001"], "summary": "s", "severity": "high", "description": "d"
                } },
                "description": "x",
                "license": "MIT",
                "tier": "free",
            }),
        );
    }
    std::fs::write(
        proj.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
    match shape {
        Shape::Reactor => {
            std::fs::create_dir_all(proj.join(".mvn/wrapper")).unwrap();
            std::fs::write(
                proj.join(".mvn/wrapper/maven-wrapper.properties"),
                "distributionUrl=https://repo.maven.apache.org/apache-maven-3.9.16-bin.zip\n",
            )
            .unwrap();
            let deps: String = packages
                .iter()
                .map(|(name, _)| {
                    format!(
                        "\n    <dependency><groupId>org.example</groupId>\
                         <artifactId>{name}</artifactId><version>1.0</version></dependency>"
                    )
                })
                .collect();
            std::fs::write(
                proj.join("pom.xml"),
                "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.x</groupId>\
                 <artifactId>agg</artifactId><version>1</version><packaging>pom</packaging>\n  \
                 <modules>\n    <module>a</module>\n  </modules>\n</project>\n",
            )
            .unwrap();
            std::fs::create_dir_all(proj.join("a")).unwrap();
            std::fs::write(
                proj.join("a/pom.xml"),
                format!(
                    "<project>\r\n  <modelVersion>4.0.0</modelVersion>\r\n  <parent><groupId>com.x\
                     </groupId><artifactId>agg</artifactId><version>1</version></parent>\r\n  \
                     <artifactId>a</artifactId>\r\n  <dependencies>{deps}\r\n  </dependencies>\r\n\
                     </project>\r\n"
                ),
            )
            .unwrap();
        }
        Shape::Gradle => {
            std::fs::write(
                proj.join("settings.gradle"),
                "plugins {\n    id 'org.gradle.toolchains.foojay-resolver-convention' version '0.8.0'\n}\nrootProject.name = 'x'\ninclude 'app'\n",
            )
            .unwrap();
            std::fs::create_dir_all(proj.join("app")).unwrap();
            let deps: String = packages
                .iter()
                .map(|(name, _)| format!("  implementation 'org.example:{name}:1.0'\n"))
                .collect();
            std::fs::write(
                proj.join("app/build.gradle"),
                format!("plugins {{ id 'java' }}\nrepositories {{ mavenCentral() }}\ndependencies {{\n{deps}}}\n"),
            )
            .unwrap();
        }
    }
}

/// `socket-patch <args> --json --offline --cwd <root>/proj`; `(exit, envelope)`.
fn socket(root: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    let proj = root.join("proj");
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        &proj,
        args,
        &[("MAVEN_REPO_LOCAL", root.join("m2").to_str().unwrap())],
    );
    let out = cmd
        .args(["--json", "--cwd", proj.to_str().unwrap()])
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("MAVEN_REPO_LOCAL", root.join("m2"))
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

fn ok(root: &Path, args: &[&str]) -> serde_json::Value {
    let (code, env) = socket(root, args);
    assert_eq!(code, Some(0), "{args:?}: {env}");
    let failed = env["summary"].get("failed").unwrap_or(&env["failed"]);
    assert_eq!(failed, 0, "{args:?}: {env}");
    env
}

/// Every file and directory under `proj`, minus the manifest and blobs
/// (the inputs the tests edit).
fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == ".socket/manifest.json" || rel == ".socket/blobs" {
                continue;
            }
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                out.insert(format!("{rel}/"), None);
                walk(base, &path, out);
            } else {
                out.insert(rel, Some(std::fs::read(&path).unwrap()));
            }
        }
    }
    let proj = root.join("proj");
    let mut out = BTreeMap::new();
    walk(&proj, &proj, &mut out);
    out
}

fn wiring_text(root: &Path) -> String {
    snapshot(root)
        .into_iter()
        .filter(|(rel, _)| {
            !rel.starts_with(".socket/vendor/maven2/") && !rel.starts_with(".socket/vendor/gradle/")
        })
        .filter(|(rel, _)| rel != ".socket/vendor/state.json")
        .filter_map(|(_, bytes)| bytes.map(|b| String::from_utf8_lossy(&b).into_owned()))
        .collect()
}

fn events(env: &serde_json::Value) -> Vec<(String, String, String)> {
    env["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let s = |k: &str| e[k].as_str().unwrap_or_default().to_string();
            (s("purl"), s("action"), s("errorCode"))
        })
        .collect()
}

/// Rolling back one of two vendored packages leaves the other wired (a
/// re-vendor finds it in sync), and reverting the rest — with the switch
/// unset — restores every byte and directory.
#[test]
fn two_patches_roll_back_one_at_a_time_to_pristine() {
    for shape in [Shape::Reactor, Shape::Gradle] {
        for first in ["foo", "bar"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            fixture(root, shape, &[("foo", FOO_UUID), ("bar", BAR_UUID)]);
            let pristine = snapshot(root);
            let env = ok(root, &["vendor"]);
            assert_eq!(env["summary"]["applied"], 2, "{env}");
            ok(root, &["rollback", &purl(first)]);
            let other = if first == "foo" { "bar" } else { "foo" };
            let env = ok(root, &["vendor"]);
            assert_eq!(
                events(&env),
                [(
                    purl(other),
                    "skipped".to_string(),
                    "already_vendored".to_string()
                )],
                "{env}"
            );
            ok(root, &["vendor", "--revert"]);
            assert_eq!(snapshot(root), pristine, "first={first}");
        }
    }
}

/// A patch update (same GAV, new uuid) re-points every wiring fragment at
/// the new patch, sweeps the old Maven tree for real, and reverts to
/// pristine.
#[test]
fn patch_update_rewires_sweeps_and_reverts_to_pristine() {
    for shape in [Shape::Reactor, Shape::Gradle] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, shape, &[("foo", FOO_UUID)]);
        let pristine = snapshot(root);
        ok(root, &["vendor"]);
        let manifest_path = root.join("proj/.socket/manifest.json");
        let manifest = std::fs::read_to_string(&manifest_path).unwrap();
        std::fs::write(&manifest_path, manifest.replace(FOO_UUID, FOO_UPDATE_UUID)).unwrap();
        let env = ok(root, &["vendor"]);
        let removed = events(&env)
            .iter()
            .any(|(_, _, code)| code == "vendor_stale_artifact_removed");
        let old_tree = root.join("proj/.socket/vendor/maven2/org/example/foo/1.0-socket.1d3c1fd2");
        assert_eq!(removed, shape == Shape::Reactor, "{env}");
        assert!(!old_tree.exists());
        let wiring = wiring_text(root);
        assert!(
            !wiring.contains("1d3c1fd2"),
            "old uuid still wired:\n{wiring}"
        );
        assert!(wiring.contains(if shape == Shape::Reactor {
            "1.0-socket.2e4d6f80"
        } else {
            FOO_UPDATE_UUID
        }));
        ok(root, &["vendor", "--revert"]);
        assert_eq!(snapshot(root), pristine);
    }
}

/// A re-run over the committed tree needs no jar source (cold cache, even
/// `--vendor-source=service --offline`); `vex` attests the entry; a deleted
/// tree jar is rebuilt by `repair`; the whole thing still reverts clean.
#[test]
fn cold_cache_rerun_vex_repair_and_revert() {
    for shape in [Shape::Reactor, Shape::Gradle] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, shape, &[("foo", FOO_UUID)]);
        let pristine = snapshot(root);
        ok(root, &["vendor"]);
        let m2 = root.join("m2");
        let parked = root.join("m2-parked");
        std::fs::rename(&m2, &parked).unwrap();
        for args in [&["vendor"][..], &["vendor", "--vendor-source=service"]] {
            let env = ok(root, args);
            assert_eq!(
                events(&env),
                [(
                    purl("foo"),
                    "skipped".to_string(),
                    "already_vendored".to_string()
                )],
                "{args:?}: {env}"
            );
        }
        let vex = root.join("vex.json");
        ok(
            root,
            &[
                "vex",
                "-O",
                vex.to_str().unwrap(),
                "--product",
                "pkg:generic/x@1",
            ],
        );
        let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&vex).unwrap()).unwrap();
        assert_eq!(doc["statements"][0]["status"], "not_affected", "{doc}");
        std::fs::rename(&parked, &m2).unwrap();
        let tree_jar = if shape == Shape::Reactor {
            "proj/.socket/vendor/maven2/org/example/foo/1.0-socket.1d3c1fd2/foo-1.0-socket.1d3c1fd2.jar"
        } else {
            "proj/.socket/vendor/gradle/org/example/foo/1.0/foo-1.0.jar"
        };
        std::fs::remove_file(root.join(tree_jar)).unwrap();
        let env = ok(root, &["repair"]);
        assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
        assert!(root.join(tree_jar).is_file());
        let expected = std::fs::read(root.join(tree_jar)).unwrap();
        std::fs::write(root.join(tree_jar), jar(b"CORRUPT\n")).unwrap();
        let env = ok(root, &["repair"]);
        assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
        assert_eq!(std::fs::read(root.join(tree_jar)).unwrap(), expected);
        ok(root, &["vendor", "--revert"]);
        assert_eq!(snapshot(root), pristine);
    }
}

/// `rollback --preserve-state` keeps the tree and the ledger entry.
#[test]
fn preserve_state_keeps_the_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
    ok(root, &["vendor"]);
    ok(root, &["rollback", "--preserve-state"]);
    let proj = root.join("proj");
    assert!(proj
        .join(
            ".socket/vendor/maven2/org/example/foo/1.0-socket.1d3c1fd2/foo-1.0-socket.1d3c1fd2.jar"
        )
        .is_file());
    assert!(!std::fs::read_to_string(proj.join("a/pom.xml"))
        .unwrap()
        .contains("socket"));
    assert!(
        std::fs::read_to_string(proj.join(".socket/vendor/state.json"))
            .unwrap()
            .contains(FOO_UUID)
    );
}

/// A forged JVM ledger entry naming `.git/config` is refused before any
/// write, using only allowed JVM paths.
#[test]
fn forged_ledger_entries_touch_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
    let proj = root.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();
    std::fs::write(proj.join(".git/config"), "[core]\n").unwrap();
    std::fs::create_dir_all(proj.join("src")).unwrap();
    std::fs::write(proj.join("src/Main.java"), "class Main {}\n").unwrap();
    let sha = hex::encode(Sha256::digest(b"class Main {}\n"));
    for (uuid, wiring) in [
        (
            FOO_UUID,
            serde_json::json!([{ "file": ".git/config", "kind": "maven_pom_fragment",
                "action": "rewritten", "key": "repository",
                "new": { "op": "replace", "from": "[core]\n\tfsmonitor = touch PWNED\n", "to": "[core]\n" } }]),
        ),
        (
            "../../../NOT-A-UUID",
            serde_json::json!([{ "file": "src/Main.java", "kind": "jvm_vendor_tree",
                "action": "added", "new": sha }]),
        ),
    ] {
        let state = serde_json::json!({ "version": 1, "entries": { purl("foo"): {
            "ecosystem": "maven", "basePurl": purl("foo"), "uuid": uuid,
            "artifact": { "path": "x", "sha256": "" }, "wiring": wiring,
        } } });
        std::fs::create_dir_all(proj.join(".socket/vendor")).unwrap();
        std::fs::write(proj.join(".socket/vendor/state.json"), state.to_string()).unwrap();
        let (code, env) = socket(root, &["vendor", "--revert"]);
        assert_ne!(code, Some(0), "{env}");
        assert_eq!(
            std::fs::read(proj.join(".git/config")).unwrap(),
            b"[core]\n"
        );
        assert!(proj.join("src/Main.java").is_file());
    }
}

/// A build directory symlinked out of the checkout is refused with
/// `build_file_outside_root`, and nothing is written through it.
#[cfg(unix)]
#[test]
fn escaping_symlinks_are_refused() {
    for link in [".mvn", ".socket/vendor", "a"] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
        let proj = root.join("proj");
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        if link == ".mvn" {
            std::fs::remove_dir_all(proj.join(".mvn")).unwrap();
        }
        if link == "a" {
            std::fs::rename(proj.join("a/pom.xml"), outside.join("pom.xml")).unwrap();
            std::fs::remove_dir(proj.join("a")).unwrap();
        }
        std::os::unix::fs::symlink(&outside, proj.join(link)).unwrap();
        let before: Vec<_> = std::fs::read_dir(&outside)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        let (code, env) = socket(root, &["vendor"]);
        assert_ne!(code, Some(0), "{link}: {env}");
        assert_eq!(
            env["events"][0]["errorCode"], "vendor_jvm_shape_unsupported",
            "{link}: {env}"
        );
        assert!(
            env["events"][0]["error"]
                .as_str()
                .unwrap_or_default()
                .starts_with("reason: build_file_outside_root: "),
            "{link}: {env}"
        );
        let after: Vec<_> = std::fs::read_dir(&outside)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        assert_eq!(before, after, "{link}: wrote outside the checkout");
    }
}

#[test]
fn offline_check_detects_metadata_and_wiring_drift_without_writes() {
    for shape in [Shape::Reactor, Shape::Gradle] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, shape, &[("foo", FOO_UUID)]);
        ok(root, &["vendor"]);
        let before = snapshot(root);
        ok(root, &["vendor", "--check"]);
        assert_eq!(snapshot(root), before);
        let pom = match shape {
            Shape::Reactor => "proj/.socket/vendor/maven2/org/example/foo/1.0-socket.1d3c1fd2/foo-1.0-socket.1d3c1fd2.pom",
            Shape::Gradle => "proj/.socket/vendor/gradle/org/example/foo/1.0/foo-1.0.pom",
        };
        let original = std::fs::read(root.join(pom)).unwrap();
        std::fs::write(root.join(pom), b"tampered").unwrap();
        let corrupt = snapshot(root);
        let (code, env) = socket(root, &["vendor", "--check"]);
        assert_eq!(code, Some(1), "{env}");
        assert_eq!(snapshot(root), corrupt);
        std::fs::write(root.join(pom), original).unwrap();
        let wiring = if shape == Shape::Reactor {
            "proj/a/pom.xml"
        } else {
            "proj/settings.gradle"
        };
        let text = std::fs::read_to_string(root.join(wiring)).unwrap();
        let drifted = if shape == Shape::Reactor {
            text.replace("1.0-socket.1d3c1fd2", "1.0")
        } else {
            text.lines()
                .filter(|l| !l.contains("apply from:"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        std::fs::write(root.join(wiring), drifted).unwrap();
        let (code, env) = socket(root, &["vendor", "--check"]);
        assert_eq!(code, Some(1), "{env}");
    }
}

#[test]
fn maven_config_none_survives_rerun_and_checks_conflicting_local_cache() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
    let before = snapshot(root);
    ok(root, &["vendor", "--maven-config=none"]);
    assert!(!root.join("proj/.mvn/maven.config").exists());
    ok(root, &["vendor"]);
    assert!(!root.join("proj/.mvn/maven.config").exists());
    ok(root, &["vendor", "--check"]);
    let m2 = root.join("other-cache");
    let jar = m2.join("org/example/foo/1.0-socket.1d3c1fd2/foo-1.0-socket.1d3c1fd2.jar");
    std::fs::create_dir_all(jar.parent().unwrap()).unwrap();
    std::fs::write(&jar, b"conflicting bytes").unwrap();
    let (code, env) = socket(
        root,
        &["vendor", "--check", "--local-repo", m2.to_str().unwrap()],
    );
    assert_eq!(code, Some(1), "{env}");
    std::fs::remove_dir_all(m2).unwrap();
    ok(root, &["vendor", "--revert"]);
    assert_eq!(snapshot(root), before);
}

#[test]
fn gradle_old_wrapper_refuses_before_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    std::fs::create_dir_all(root.join("proj/gradle/wrapper")).unwrap();
    std::fs::write(
        root.join("proj/gradle/wrapper/gradle-wrapper.properties"),
        "distributionUrl=https\\://services.gradle.org/distributions/gradle-6.7.1-bin.zip\n",
    )
    .unwrap();
    let before = snapshot(root);
    let (code, env) = socket(root, &["vendor"]);
    assert_eq!(code, Some(1), "{env}");
    assert!(env.to_string().contains("gradle_below_6_8"), "{env}");
    assert_eq!(snapshot(root), before);
}

#[test]
fn gradle_verification_parents_and_boms_are_shared_and_revert_in_either_order() {
    for (first, components) in [
        ("foo", "<components>\n  </components>"),
        ("bar", "<components>\n  </components>"),
        ("foo", "<components/>"),
        ("bar", "<components/>"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Gradle, &[("foo", FOO_UUID), ("bar", BAR_UUID)]);
        for name in ["foo", "bar"] {
            std::fs::write(root.join(format!("m2/org/example/{name}/1.0/{name}-1.0.pom")), format!("<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>{name}</artifactId><version>1.0</version><properties><bom.version>2</bom.version></properties></project>")).unwrap();
        }
        for (name, body) in [
            ("parent", "<properties><bom.version>1</bom.version></properties><dependencyManagement><dependencies><dependency><groupId>org.example</groupId><artifactId>bom</artifactId><version>${bom.version}</version><scope>import</scope><type>pom</type></dependency></dependencies></dependencyManagement>"),
            ("bom", ""),
        ] {
            let version = if name == "bom" { "2" } else { "1" };
            let dir = root.join(format!("m2/org/example/{name}/{version}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(format!("{name}-{version}.pom")), format!("<project><groupId>org.example</groupId><artifactId>{name}</artifactId><version>{version}</version>{body}</project>")).unwrap();
        }
        let default_bom = root.join("m2/org/example/bom/1");
        std::fs::create_dir_all(&default_bom).unwrap();
        std::fs::write(default_bom.join("bom-1.pom"), "<project><groupId>org.example</groupId><artifactId>bom</artifactId><version>1</version></project>").unwrap();
        let verification = root.join("proj/gradle/verification-metadata.xml");
        std::fs::create_dir_all(verification.parent().unwrap()).unwrap();
        let original = format!("<verification-metadata>\n  <configuration><verify-metadata>true</verify-metadata></configuration>\n  {components}\n</verification-metadata>\n");
        std::fs::write(&verification, &original).unwrap();
        let before = snapshot(root);
        ok(root, &["vendor"]);
        ok(root, &["vendor", "--check"]);
        let text = std::fs::read_to_string(&verification).unwrap();
        assert!(text.contains("name=\"parent\""), "{text}");
        assert!(text.contains("name=\"bom\" version=\"1\""), "{text}");
        assert!(text.contains("name=\"bom\" version=\"2\""), "{text}");
        let drifted = text.replace("name=\"parent\"", "name=\"not-parent\"");
        std::fs::write(&verification, drifted).unwrap();
        let (code, env) = socket(root, &["vendor", "--check"]);
        assert_eq!(code, Some(1), "{env}");
        std::fs::write(&verification, &text).unwrap();
        ok(root, &["remove", &purl(first)]);
        assert!(std::fs::read_to_string(&verification)
            .unwrap()
            .contains("name=\"parent\""));
        ok(root, &["vendor", "--revert"]);
        assert_eq!(std::fs::read_to_string(&verification).unwrap(), original);
        // remove changes the manifest by design; all build wiring remains byte exact.
        let mut after = snapshot(root);
        let mut before = before;
        after.remove(".socket/manifest.json");
        before.remove(".socket/manifest.json");
        assert_eq!(after, before);
    }
}

#[test]
fn check_refuses_a_missing_ledger_and_honors_manifest_path() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    ok(root, &["vendor"]);
    let nested = root.join("proj/elsewhere");
    std::fs::create_dir_all(nested.join(".socket")).unwrap();
    std::fs::write(nested.join(".socket/manifest.json"), "{\"patches\":{}}").unwrap();
    // A manifest path selects its project root, even with a different --cwd.
    let env = ok(
        root,
        &[
            "vendor",
            "--check",
            "--manifest-path",
            "elsewhere/.socket/manifest.json",
        ],
    );
    assert_eq!(env["summary"]["verified"], 0);
    std::fs::remove_file(root.join("proj/.socket/manifest.json")).unwrap();
    std::fs::remove_file(root.join("proj/.socket/vendor/state.json")).unwrap();
    let before = snapshot(root);
    let (code, env) = socket(root, &["vendor", "--check"]);
    assert_eq!(code, Some(1), "{env}");
    assert!(env.to_string().contains("vendor_ledger_missing"), "{env}");
    assert_eq!(snapshot(root), before);
}

#[test]
fn vex_reports_an_unreadable_jvm_layout_instead_of_an_unwired_patch() {
    for shape in [Shape::Reactor, Shape::Gradle] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, shape, &[("foo", FOO_UUID)]);
        ok(root, &["vendor"]);
        let rel = if shape == Shape::Reactor {
            "proj/a/pom.xml"
        } else {
            "proj/.socket/vendor/gradle-index.tsv"
        };
        std::fs::write(root.join(rel), "INVALID").unwrap();
        let vex = root.join("vex.json");
        let (_, env) = socket(
            root,
            &[
                "vex",
                "-O",
                vex.to_str().unwrap(),
                "--product",
                "pkg:generic/x@1",
            ],
        );
        assert!(
            env.to_string().contains("vendor_jvm_shape_unsupported"),
            "{env}"
        );
        assert!(!env.to_string().contains("vendor_unwired"), "{env}");
        if let Ok(bytes) = std::fs::read(vex) {
            assert!(!String::from_utf8_lossy(&bytes).contains("not_affected"));
        }
    }
}

// ── Gradle: one case per vendored-Gradle issue (#395 #428 #429 #461 #487
// #511 #533), plus the repairs that restore what each adds ──

const FOO_JAR: &str = "proj/.socket/vendor/gradle/org/example/foo/1.0/foo-1.0.jar";
const FOO_TREE: &str = "proj/.socket/vendor/gradle/org/example/foo/1.0";
const FOO_METADATA: &str = "proj/.socket/vendor/gradle/org/example/foo/maven-metadata.xml";
const FOO_MAVEN_TREE: &str = "proj/.socket/vendor/maven2/org/example/foo/1.0-socket.1d3c1fd2";

/// `socket(root, args)` run from `cwd` (relative to `root`) instead of
/// the project root; the fixture service reads `cwd`'s manifest.
fn socket_in(root: &Path, cwd: &str, args: &[&str]) -> (Option<i32>, serde_json::Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&k);
        }
    }
    let dir = root.join(cwd);
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        &dir,
        args,
        &[("MAVEN_REPO_LOCAL", root.join("m2").to_str().unwrap())],
    );
    let out = cmd
        .args(["--json", "--cwd", dir.to_str().unwrap()])
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NO_CONFIG", "1")
        .env("MAVEN_REPO_LOCAL", root.join("m2"))
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

/// `vendor` refuses with `vendor_jvm_shape_unsupported` and `reason`, and
/// writes nothing.
fn assert_refused(root: &Path, reason: &str, also: &str) {
    let before = snapshot(root);
    let (code, env) = socket(root, &["vendor"]);
    assert_ne!(code, Some(0), "{env}");
    let event = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "failed")
        .unwrap_or_else(|| panic!("no failed event: {env}"));
    let error = event["error"].as_str().unwrap_or_default();
    assert!(
        error.starts_with(&format!("reason: {reason}: ")) && error.contains(also),
        "{env}"
    );
    assert_eq!(snapshot(root), before, "a refusal writes nothing");
}

fn write(root: &Path, rel: &str, body: &[u8]) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, body).unwrap();
}

fn crlf(text: &[u8]) -> Vec<u8> {
    String::from_utf8(text.to_vec())
        .unwrap()
        .replace("\r\n", "\n")
        .replace('\n', "\r\n")
        .into_bytes()
}

/// #395: a `pom.xml` beside the Gradle build vendors both builds in one
/// entry: the suffixed Maven tree and pin, and the Gradle tree and apply
/// line. `--check` and `vex` see both; the revert restores every byte.
#[test]
fn gradle_vendor_395_mixed_root_vendors_both_builds() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/pom.xml",
        b"<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.x</groupId>\n  <artifactId>app</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency><groupId>org.example</groupId><artifactId>foo</artifactId><version>1.0</version></dependency>\n  </dependencies>\n</project>\n",
    );
    let pristine = snapshot(root);
    let env = ok(root, &["vendor"]);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    assert!(root.join(FOO_JAR).is_file());
    assert!(root
        .join(FOO_MAVEN_TREE)
        .join("foo-1.0-socket.1d3c1fd2.jar")
        .is_file());
    assert!(std::fs::read_to_string(root.join("proj/pom.xml"))
        .unwrap()
        .contains("1.0-socket.1d3c1fd2"));
    assert!(std::fs::read_to_string(root.join("proj/settings.gradle"))
        .unwrap()
        .contains("apply from: '.socket/gradle/socket-patch.settings.gradle'"));
    ok(root, &["vendor", "--check"]);
    let vex = root.join("vex.json");
    ok(
        root,
        &[
            "vex",
            "-O",
            vex.to_str().unwrap(),
            "--product",
            "pkg:generic/x@1",
        ],
    );
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&vex).unwrap()).unwrap();
    assert_eq!(doc["statements"][0]["status"], "not_affected", "{doc}");
    std::fs::remove_file(vex).unwrap();
    ok(root, &["vendor", "--revert"]);
    assert_eq!(snapshot(root), pristine);
}

/// #395 repair: both trees of a mixed root come back from one download.
#[test]
fn gradle_vendor_395_repair_mixed_root() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/pom.xml",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>com.x</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.example</groupId><artifactId>foo</artifactId><version>1.0</version></dependency></dependencies></project>\n",
    );
    ok(root, &["vendor"]);
    let vendored = snapshot(root);
    std::fs::remove_dir_all(root.join(FOO_TREE)).unwrap();
    std::fs::remove_dir_all(root.join(FOO_MAVEN_TREE)).unwrap();
    let env = ok(root, &["repair"]);
    assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
    let mut repaired = snapshot(root);
    let mut want = vendored.clone();
    repaired.remove(".socket/vendor/state.json");
    want.remove(".socket/vendor/state.json");
    assert_eq!(repaired, want);
    ok(root, &["vendor", "--check"]);
}

/// #428: vendoring from a subproject refuses with `not_build_root` and
/// writes nothing, the nested settings file included.
#[test]
fn gradle_vendor_428_subproject_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    std::fs::create_dir_all(root.join("proj/.git")).unwrap();
    for name in ["manifest.json", "blobs"] {
        let from = root.join("proj/.socket").join(name);
        let to = root.join("proj/app/.socket").join(name);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        if from.is_dir() {
            std::fs::create_dir_all(&to).unwrap();
            for e in std::fs::read_dir(&from).unwrap() {
                let e = e.unwrap();
                std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
            }
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
    let before = snapshot(root);
    let (code, env) = socket_in(root, "proj/app", &["vendor"]);
    assert_ne!(code, Some(0), "{env}");
    let event = &env["events"][0];
    assert_eq!(event["errorCode"], "vendor_jvm_shape_unsupported", "{env}");
    assert!(
        event["error"]
            .as_str()
            .unwrap_or_default()
            .starts_with("reason: not_build_root: run vendor from Gradle root "),
        "{env}"
    );
    assert_eq!(snapshot(root), before);
    assert!(!root.join("proj/app/settings.gradle").exists());
}

/// #429: a `core.autocrlf=true` checkout (every text file CRLF) passes
/// `vendor --check`, and `vendor --revert` removes every owned file.
#[test]
fn gradle_vendor_429_crlf_checkout_checks_and_reverts_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/buildSrc/build.gradle",
        b"plugins { id 'groovy-gradle-plugin' }\n",
    );
    let mut pristine = snapshot(root);
    ok(root, &["vendor"]);
    let text_files = [
        "proj/settings.gradle",
        "proj/app/build.gradle",
        "proj/buildSrc/build.gradle",
        "proj/buildSrc/settings.gradle",
        "proj/.socket/gradle/socket-patch.settings.gradle",
        "proj/.socket/gradle/.gitattributes",
        "proj/.socket/vendor/.gitattributes",
        "proj/.socket/vendor/gradle-index.tsv",
        "proj/.socket/vendor/gradle/.gitattributes",
        FOO_METADATA,
    ];
    for rel in text_files {
        let bytes = std::fs::read(root.join(rel)).unwrap();
        std::fs::write(root.join(rel), crlf(&bytes)).unwrap();
        if let Some(Some(body)) = pristine.get_mut(rel.strip_prefix("proj/").unwrap()) {
            *body = crlf(body);
        }
    }
    let env = ok(root, &["vendor", "--check"]);
    assert_eq!(env["summary"]["verified"], 1, "{env}");
    ok(root, &["vendor", "--revert"]);
    assert_eq!(snapshot(root), pristine);
}

/// #461: an `exclusiveContent` rule for the group in a subproject's build
/// script refuses, naming that file.
#[test]
fn gradle_vendor_461_subproject_rule_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/app/build.gradle",
        b"plugins { id 'java' }\nrepositories {\n  exclusiveContent {\n    forRepository { mavenCentral() }\n    filter { includeGroup 'org.example' }\n  }\n}\ndependencies { implementation 'org.example:foo:1.0' }\n",
    );
    assert_refused(
        root,
        "gradle_exclusive_content_conflict",
        "app/build.gradle",
    );
}

/// #487: pgp-only verification entries of the vendored pom and its parent
/// get a `sha256` beside the `<pgp>`; `--check` passes and the revert is
/// byte-exact.
#[test]
fn gradle_vendor_487_pgp_only_entries_get_a_checksum() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    let foo_pom = b"<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>1</version></parent><artifactId>foo</artifactId><version>1.0</version></project>";
    write(root, "m2/org/example/foo/1.0/foo-1.0.pom", foo_pom);
    let parent_pom = b"<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>parent</artifactId><version>1</version><packaging>pom</packaging></project>";
    write(root, "m2/org/example/parent/1/parent-1.pom", parent_pom);
    let pgp = |name: &str| {
        format!("         <artifact name=\"{name}\">\n            <pgp value=\"DD0CDDD2B4838EC95727B94B4C77A9C911D46A19\"/>\n         </artifact>\n")
    };
    let original = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<verification-metadata>\n   <configuration>\n      <verify-metadata>true</verify-metadata>\n      <verify-signatures>true</verify-signatures>\n   </configuration>\n   <components>\n      <component group=\"org.example\" name=\"foo\" version=\"1.0\">\n{}{}      </component>\n      <component group=\"org.example\" name=\"parent\" version=\"1\">\n{}      </component>\n   </components>\n</verification-metadata>\n",
        pgp("foo-1.0.jar"),
        pgp("foo-1.0.pom"),
        pgp("parent-1.pom")
    );
    write(
        root,
        "proj/gradle/verification-metadata.xml",
        original.as_bytes(),
    );
    ok(root, &["vendor"]);
    let text = std::fs::read_to_string(root.join("proj/gradle/verification-metadata.xml")).unwrap();
    for (name, bytes) in [
        ("foo-1.0.pom", &foo_pom[..]),
        ("parent-1.pom", &parent_pom[..]),
    ] {
        let want = format!(
            "         <artifact name=\"{name}\">\n            <pgp value=\"DD0CDDD2B4838EC95727B94B4C77A9C911D46A19\"/>\n            <sha256 value=\"{}\" origin=\"socket-patch\"/>\n         </artifact>\n",
            hex::encode(Sha256::digest(bytes))
        );
        assert!(text.contains(&want), "{name}:\n{text}");
    }
    ok(root, &["vendor", "--check"]);
    ok(root, &["vendor", "--revert"]);
    assert_eq!(
        std::fs::read_to_string(root.join("proj/gradle/verification-metadata.xml")).unwrap(),
        original
    );
}

/// #511: the tree carries the GA's derived `maven-metadata.xml`; a
/// deleted one is repaired; a range admitting no vendored version
/// refuses.
#[test]
fn gradle_vendor_511_derived_metadata_repair_and_range_refusal() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/app/build.gradle",
        b"plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'org.example:foo:[0.9,1.1)' }\n",
    );
    let env = ok(root, &["vendor"]);
    assert!(
        env.to_string().contains("reason: range_declared:"),
        "the range is noted: {env}"
    );
    let metadata = std::fs::read_to_string(root.join(FOO_METADATA)).unwrap();
    assert!(
        metadata.contains("<versions>\n      <version>1.0</version>\n    </versions>"),
        "{metadata}"
    );
    std::fs::remove_file(root.join(FOO_METADATA)).unwrap();
    let env = ok(root, &["repair"]);
    assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
    assert_eq!(
        std::fs::read_to_string(root.join(FOO_METADATA)).unwrap(),
        metadata
    );
    ok(root, &["vendor", "--check"]);

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/app/build.gradle",
        b"plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'org.example:foo:[2.0,3.0)' }\n",
    );
    assert_refused(root, "gradle_range_excludes_vendored", "app/build.gradle");
}

/// #533: a declared classifier is vendored beside the jar (and a deleted
/// one repaired); one that exists nowhere refuses.
#[test]
fn gradle_vendor_533_repair_restores_classifier() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/app/build.gradle",
        b"plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies {\n  implementation 'org.example:foo:1.0'\n  testImplementation 'org.example:foo:1.0:tests'\n}\n",
    );
    let pristine = snapshot(root);
    assert_refused(root, "classifier_unavailable", "foo:1.0:tests");
    let tests_jar = jar(b"TESTS\n");
    write(root, "m2/org/example/foo/1.0/foo-1.0-tests.jar", &tests_jar);
    ok(root, &["vendor"]);
    let vendored = root.join(FOO_TREE).join("foo-1.0-tests.jar");
    assert_eq!(std::fs::read(&vendored).unwrap(), tests_jar);
    let index = std::fs::read_to_string(root.join("proj/.socket/vendor/gradle-index.tsv")).unwrap();
    assert!(
        index.contains("org/example/foo/1.0/foo-1.0-tests.jar\t"),
        "{index}"
    );
    ok(root, &["vendor", "--check"]);
    // A re-run keeps the committed classifier, declared or not (an
    // unindexed file in the tree would fail the build).
    let env = ok(root, &["vendor"]);
    assert_eq!(env["events"][0]["errorCode"], "already_vendored", "{env}");
    let declared = std::fs::read(root.join("proj/app/build.gradle")).unwrap();
    write(
        root,
        "proj/app/build.gradle",
        b"plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'org.example:foo:1.0' }\n",
    );
    ok(root, &["vendor"]);
    assert_eq!(std::fs::read(&vendored).unwrap(), tests_jar);
    ok(root, &["vendor", "--check"]);
    write(root, "proj/app/build.gradle", &declared);
    std::fs::remove_file(&vendored).unwrap();
    let env = ok(root, &["repair"]);
    assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
    assert_eq!(std::fs::read(&vendored).unwrap(), tests_jar);
    ok(root, &["vendor", "--revert"]);
    assert_eq!(snapshot(root), pristine);
}
