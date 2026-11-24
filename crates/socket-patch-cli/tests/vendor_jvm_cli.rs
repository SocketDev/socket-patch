//! CLI flows of the v5 JVM vendored backend over synthetic offline
//! fixtures: a reactor (an aggregator and one module) and a
//! Gradle multi-project, each fed by a fake local Maven repository.
//!
//! These pin the review findings that only show through the CLI's own
//! bookkeeping (ledger carry-forward, the stale-uuid sweep, per-package
//! rollback, repair, `vex`): two patches revert in any order, a patch
//! update re-wires and reverts to pristine, a re-run needs no jar source,
//! and a tampered ledger or an escaping symlink is refused.

#[path = "common/mod.rs"]
mod common;
use common::{git_sha256, hermetic};

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

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

/// `socket-patch <args> --offline --cwd <root>/proj`, with `--json` or as a
/// person runs it, and the download fixture it needs while it runs.
fn command(
    root: &Path,
    args: &[&str],
    json: bool,
) -> (std::process::Command, Option<prebuilt_common::Server>) {
    let mut cmd = hermetic::binary_command();
    let proj = root.join("proj");
    let fixture = prebuilt_common::prepare_command(
        &mut cmd,
        &proj,
        args,
        &[("MAVEN_REPO_LOCAL", root.join("m2").to_str().unwrap())],
    );
    cmd.args(json.then_some("--json"))
        .args(["--cwd", proj.to_str().unwrap()])
        .env("MAVEN_REPO_LOCAL", root.join("m2"))
        .env_remove("M2_HOME");
    (cmd, fixture)
}

/// What [`command`] printed and how it ended.
fn spawn(root: &Path, args: &[&str], json: bool) -> std::process::Output {
    let (mut cmd, _fixture) = command(root, args, json);
    cmd.output().expect("run socket-patch")
}

/// `socket-patch <args> --json --offline --cwd <root>/proj`; `(exit, envelope)`.
fn socket(root: &Path, args: &[&str]) -> (Option<i32>, serde_json::Value) {
    let out = spawn(root, args, true);
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

/// A jar over the limits jars once shared with Python wheels (10,000
/// entries, 64 MiB inflated) is vendored, held to upstream by an online
/// re-run, attested by `vex`, passes `vendor --check`, and is rebuilt by
/// `repair`. Each of those used to stop at the wheel reader's caps.
#[test]
fn a_jar_over_the_old_reader_limits_vendors_attests_and_repairs() {
    let big = {
        let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zw.start_file(MEMBER, opts).unwrap();
        zw.write_all(b"NOTICE foo\n").unwrap();
        let mut body = vec![0x5au8; 6800];
        for i in 0..10_001u64 {
            body[..8].copy_from_slice(&i.to_le_bytes());
            zw.start_file(format!("p/C{i}.class"), opts).unwrap();
            zw.write_all(&body).unwrap();
        }
        zw.finish().unwrap().into_inner()
    };
    assert!(big.len() > 64 * 1024 * 1024);
    for shape in [Shape::Reactor, Shape::Gradle] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, shape, &[("foo", FOO_UUID)]);
        std::fs::write(root.join("m2/org/example/foo/1.0/foo-1.0.jar"), &big).unwrap();
        let env = ok(root, &["vendor"]);
        assert_eq!(env["events"][0]["action"], "applied", "{env}");
        let tree_jar = root.join(if shape == Shape::Reactor {
            "proj/.socket/vendor/maven2/org/example/foo/1.0-socket.1d3c1fd2/foo-1.0-socket.1d3c1fd2.jar"
        } else {
            "proj/.socket/vendor/gradle/org/example/foo/1.0/foo-1.0.jar"
        });
        let vendored = std::fs::read(&tree_jar).unwrap();
        assert!(vendored.len() > 64 * 1024 * 1024);

        let env = ok(root, &["vendor"]);
        assert_eq!(
            events(&env),
            [(
                purl("foo"),
                "skipped".to_string(),
                "already_vendored".to_string()
            )],
            "{env}"
        );
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

        std::fs::remove_file(&tree_jar).unwrap();
        let env = ok(root, &["repair"]);
        assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
        assert!(std::fs::read(&tree_jar).unwrap() == vendored);
    }
}

/// #656: a file the index does not list in the vendored tree (a Finder
/// `.DS_Store`) fails the Gradle build and `vendor --check`. Re-running
/// `vendor`, the remedy the build error names, and `repair` both sweep
/// it instead of reporting the tree in sync.
#[test]
fn stray_tree_files_are_swept_by_vendor_and_repair() {
    for shape in [Shape::Reactor, Shape::Gradle] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, shape, &[("foo", FOO_UUID)]);
        ok(root, &["vendor"]);
        let vendored = snapshot(root);
        let tree = if shape == Shape::Reactor {
            "proj/.socket/vendor/maven2/org/example/foo/1.0-socket.1d3c1fd2"
        } else {
            "proj/.socket/vendor/gradle/org/example/foo/1.0"
        };
        let stray = root.join(tree).join(".DS_Store");

        std::fs::write(&stray, b"\0\0\0\x01Bud1").unwrap();
        // A stray symlink goes, not its target: vendor deletes it
        // directly, outside its group commit.
        let target = root.join("proj/keep.txt");
        std::fs::write(&target, b"keep").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, root.join(tree).join("link")).unwrap();
        let (code, env) = socket(root, &["vendor", "--check"]);
        assert_eq!(code, Some(1), "{env}");
        let env = ok(root, &["vendor", "--dry-run"]);
        assert!(
            !events(&env).iter().any(|(_, _, c)| c == "already_vendored"),
            "the dry run previews the sweep: {env}"
        );
        assert!(stray.exists(), "a dry run writes nothing");
        let env = ok(root, &["vendor"]);
        assert!(
            !events(&env).iter().any(|(_, _, c)| c == "already_vendored"),
            "{env}"
        );
        assert!(!stray.exists(), "vendor sweeps the stray file: {env}");
        assert!(std::fs::symlink_metadata(root.join(tree).join("link")).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        std::fs::remove_file(&target).unwrap();
        ok(root, &["vendor", "--check"]);
        let env = ok(root, &["vendor"]);
        assert_eq!(
            events(&env),
            [(
                purl("foo"),
                "skipped".to_string(),
                "already_vendored".to_string()
            )],
            "in sync after the sweep: {env}"
        );

        std::fs::write(&stray, b"\0\0\0\x01Bud1").unwrap();
        std::fs::create_dir_all(root.join(tree).join("backup")).unwrap();
        std::fs::write(root.join(tree).join("backup/old.jar"), b"x").unwrap();
        let env = ok(root, &["repair", "--dry-run"]);
        assert_eq!(
            env["events"][0]["details"]["wouldRemoveUnindexed"],
            serde_json::json!([
                format!("{}/.DS_Store", tree.strip_prefix("proj/").unwrap()),
                format!("{}/backup", tree.strip_prefix("proj/").unwrap()),
            ]),
            "{env}"
        );
        assert!(stray.exists(), "repair --dry-run writes nothing");
        let env = ok(root, &["repair"]);
        assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
        assert!(!stray.exists() && !root.join(tree).join("backup").exists());
        ok(root, &["vendor", "--check"]);
        let mut repaired = snapshot(root);
        let mut want = vendored.clone();
        repaired.remove(".socket/vendor/state.json");
        want.remove(".socket/vendor/state.json");
        assert_eq!(repaired, want);
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
/// `build_file_outside_root` (a linked `.socket/vendor` with the shared
/// `vendor_dir_symlink_unsupported`), and nothing is written through it.
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
        if link == ".socket/vendor" {
            // Every ecosystem refuses a linked vendor dir up front (#664).
            assert_eq!(
                env["events"][0]["errorCode"], "vendor_dir_symlink_unsupported",
                "{link}: {env}"
            );
        } else {
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
        }
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

/// B62: committed JVM trees with no JVM ledger entry are orphans even when
/// the ledger records OTHER ecosystems' entries — the guard used to fire
/// only on an entirely empty ledger.
#[test]
fn check_reports_jvm_trees_without_a_jvm_entry_beside_other_entries() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    ok(root, &["vendor"]);
    std::fs::remove_file(root.join("proj/.socket/manifest.json")).unwrap();
    let state_path = root.join("proj/.socket/vendor/state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let other = "1a2b3c4d-5e6f-4a1b-8c2d-9e0f1a2b3c4d";
    state["entries"] = serde_json::json!({
        "pkg:npm/left-pad@1.3.0": {
            "ecosystem": "npm",
            "basePurl": "pkg:npm/left-pad@1.3.0",
            "uuid": other,
            "artifact": {
                "path": format!(".socket/vendor/npm/{other}/left-pad-1.3.0.tgz"),
                "sha256": "",
            },
            "wiring": [],
        }
    });
    std::fs::write(&state_path, state.to_string()).unwrap();
    let before = snapshot(root);
    let (code, env) = socket(root, &["vendor", "--check"]);
    assert_eq!(code, Some(1), "{env}");
    let events = env["events"].as_array().expect("events");
    let orphan = events
        .iter()
        .find(|e| {
            e.to_string().contains("vendor_ledger_missing") && e["details"]["ecosystem"] == "maven"
        })
        .unwrap_or_else(|| panic!("no JVM orphan event: {env}"));
    // The event names the orphaned JVM layout itself, not the npm entry
    // (which fails `--check` on its own for its missing artifact).
    let path = orphan["details"]["path"].as_str().expect("orphan path");
    assert!(
        socket_patch_core::vendor::jvm::apply::LEDGER_OWNED_PATHS.contains(&path),
        "{path}: {env}"
    );
    assert!(root.join("proj").join(path).exists(), "{path}");
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
    let mut cmd = hermetic::binary_command();
    let dir = root.join(cwd);
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        &dir,
        args,
        &[("MAVEN_REPO_LOCAL", root.join("m2").to_str().unwrap())],
    );
    let out = cmd
        .args(["--json", "--cwd", dir.to_str().unwrap()])
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
        "proj/.socket/vendor/gradle/.gitignore",
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

/// #533 + VEX: a declared classifier holding its own unpatched copy of
/// the patched member is vendored with a degraded warning, and `vex`
/// does not attest the package (the build may consume that copy).
#[test]
fn gradle_vendor_533_unpatched_classifier_copy_withholds_vex() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/app/build.gradle",
        b"plugins { id 'java' }\nrepositories { mavenCentral() }\ndependencies { implementation 'org.example:foo:1.0:all' }\n",
    );
    write(
        root,
        "m2/org/example/foo/1.0/foo-1.0-all.jar",
        &jar(b"NOTICE foo\n"),
    );
    let env = ok(root, &["vendor"]);
    assert!(
        env.to_string()
            .contains("reason: classifier_unpatched_copy: foo-1.0-all.jar carries an unpatched copy of META-INF/NOTICE.txt"),
        "{env}"
    );
    ok(root, &["vendor", "--check"]);
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
    assert_eq!(
        events(&env),
        [(
            purl("foo"),
            "skipped".to_string(),
            "vendor_unwired".to_string()
        )],
        "{env}"
    );
    assert!(!vex.exists(), "{env}");
}

/// #513 / #459: a reactor `${prop}` version that can't be pinned with
/// certainty (undefined in the checkout, or raised by a profile) is left
/// as is with a warning, and `vex` does not attest the package the build
/// still takes unpatched. With nothing else to wire, `vendor` refuses
/// rather than counting the patch as applied (#513).
#[test]
fn maven_reactor_uncertain_property_version_withholds_vex() {
    let cases = [
        ("", "property_unresolved"),
        (
            "<properties><foo.version>1.0</foo.version></properties>\
             <profiles><profile><id>new</id><properties><foo.version>1.1</foo.version>\
             </properties></profile></profiles>",
            "conflicting_literal_version",
        ),
    ];
    // With a sibling module at the literal base, that module is rewritten
    // and the patch is wired, yet `a` still builds the base.
    for ((extra, reason), sibling) in cases
        .into_iter()
        .flat_map(|case| [(case, false), (case, true)])
    {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
        let pristine = std::fs::read_to_string(root.join("proj/a/pom.xml")).unwrap();
        let a = pristine
            .replace(
                "<version>1.0</version></dependency>",
                "<version>${foo.version}</version></dependency>",
            )
            .replace(
                "<artifactId>a</artifactId>",
                &format!("<artifactId>a</artifactId>{extra}"),
            );
        write(root, "proj/a/pom.xml", a.as_bytes());
        if sibling {
            let agg = std::fs::read_to_string(root.join("proj/pom.xml")).unwrap();
            let agg = agg.replace(
                "<module>a</module>",
                "<module>a</module>\n    <module>b</module>",
            );
            write(root, "proj/pom.xml", agg.as_bytes());
            std::fs::create_dir_all(root.join("proj/b")).unwrap();
            let b = pristine.replace("<artifactId>a</artifactId>", "<artifactId>b</artifactId>");
            write(root, "proj/b/pom.xml", b.as_bytes());
        }
        let vex = root.join("vex.json");
        if !sibling {
            assert_refused(root, "nothing_wired", reason);
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
            assert!(!env.to_string().contains("not_affected"), "{reason}: {env}");
            if let Ok(bytes) = std::fs::read(&vex) {
                let doc = String::from_utf8_lossy(&bytes);
                assert!(!doc.contains("not_affected"), "{reason}: {env}");
            }
            continue;
        }
        let env = ok(root, &["vendor"]);
        assert!(
            env.to_string().contains(&format!("reason: {reason}")),
            "{env}"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("proj/a/pom.xml")).unwrap(),
            a
        );
        assert!(wiring_text(root).contains("-socket."), "{reason}: wired");
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
        assert_eq!(
            events(&env),
            [(
                purl("foo"),
                "skipped".to_string(),
                "vendor_unwired".to_string()
            )],
            "{reason} (sibling: {sibling}): {env}"
        );
        assert!(!vex.exists(), "{env}");
    }
}

/// #584: a module added after vendoring that declares the base literally
/// builds the unpatched jar. `vendor --check` flags the drift and `vex`
/// withholds attestation until a re-vendor rewrites the module.
#[test]
fn maven_reactor_module_added_at_base_after_vendoring_withholds_vex() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
    let pristine = std::fs::read_to_string(root.join("proj/a/pom.xml")).unwrap();
    ok(root, &["vendor"]);
    let vex = root.join("vex.json");
    let vex_args = [
        "vex",
        "-O",
        vex.to_str().unwrap(),
        "--product",
        "pkg:generic/x@1",
    ];
    ok(root, &vex_args);
    std::fs::remove_file(&vex).unwrap();

    let agg = std::fs::read_to_string(root.join("proj/pom.xml")).unwrap();
    let agg = agg.replace(
        "<module>a</module>",
        "<module>a</module>\n    <module>b</module>",
    );
    write(root, "proj/pom.xml", agg.as_bytes());
    std::fs::create_dir_all(root.join("proj/b")).unwrap();
    let b = pristine.replace("<artifactId>a</artifactId>", "<artifactId>b</artifactId>");
    assert!(b.contains("<version>1.0</version></dependency>"), "{b}");
    write(root, "proj/b/pom.xml", b.as_bytes());

    let (code, env) = socket(root, &["vendor", "--check"]);
    assert_ne!(code, Some(0), "{env}");
    let (_, env) = socket(root, &vex_args);
    assert_eq!(
        events(&env),
        [(
            purl("foo"),
            "skipped".to_string(),
            "vendor_unwired".to_string()
        )],
        "{env}"
    );
    assert!(!vex.exists(), "{env}");

    // Re-vendoring wires `b` too, and the reactor attests again.
    ok(root, &["vendor"]);
    assert!(!std::fs::read_to_string(root.join("proj/b/pom.xml"))
        .unwrap()
        .contains("<version>1.0</version></dependency>"));
    ok(root, &vex_args);
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&vex).unwrap()).unwrap();
    assert_eq!(doc["statements"][0]["status"], "not_affected", "{doc}");
}

/// #429 repair: a deleted owned `.gitattributes` (and nothing else) is
/// rewritten by `repair` (no download), so the next autocrlf clone keeps the
/// script and index LF.
#[test]
fn gradle_vendor_429_repair_restores_missing_gitattributes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    ok(root, &["vendor"]);
    let vendored = snapshot(root);
    for rel in [
        "proj/.socket/gradle/.gitattributes",
        "proj/.socket/vendor/.gitattributes",
        "proj/.socket/vendor/gradle/.gitattributes",
    ] {
        std::fs::remove_file(root.join(rel)).unwrap();
    }
    let (code, env) = socket(root, &["vendor", "--check"]);
    assert_ne!(code, Some(0), "{env}");
    ok(root, &["repair"]);
    assert_eq!(snapshot(root), vendored);
    ok(root, &["vendor", "--check"]);
}

/// #428 repair: a JVM ledger entry under a subproject of the Gradle build
/// is not repaired there (the real build would never read the restored
/// tree); nothing is written.
#[test]
fn gradle_vendor_428_repair_from_subproject_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    std::fs::create_dir_all(root.join("proj/.git")).unwrap();
    ok(root, &["vendor"]);
    common::fs_tree::copy_tree(&root.join("proj/.socket"), &root.join("proj/app/.socket"));
    std::fs::remove_file(
        root.join("proj/app/.socket/vendor/gradle/org/example/foo/1.0/foo-1.0.jar"),
    )
    .unwrap();
    let before = snapshot(root);
    let (code, env) = socket_in(root, "proj/app", &["repair"]);
    assert_ne!(code, Some(0), "{env}");
    assert!(
        env.to_string()
            .contains("reason: not_build_root: run vendor from Gradle root "),
        "{env}"
    );
    assert_eq!(snapshot(root), before);
}

/// Plant the wiring the retired pre-v5 single-pom backend left in `proj`:
/// a `<repository>` before `</project>`, its `.socket/vendor/maven/<uuid>`
/// tree and a `maven_pom_repository` ledger entry for `foo`.
fn plant_legacy_single_pom(root: &Path, pom: &str) {
    let repo_id = format!("socket-patch-vendor-{FOO_UUID}");
    let tree = format!(".socket/vendor/maven/{FOO_UUID}");
    let at = pom.rfind("</project>").unwrap();
    let wired = format!(
        "{}  <repositories>\n    <repository>\n      <id>{repo_id}</id>\n      \
         <url>file://${{project.basedir}}/{tree}</url>\n      <releases>\n        \
         <enabled>true</enabled>\n        <checksumPolicy>fail</checksumPolicy>\n      \
         </releases>\n      <snapshots>\n        <enabled>false</enabled>\n      \
         </snapshots>\n    </repository>\n  </repositories>\n{}",
        &pom[..at],
        &pom[at..]
    );
    write(root, "proj/pom.xml", wired.as_bytes());
    let jar_rel = format!("{tree}/org/example/foo/1.0/foo-1.0.jar");
    let jar_bytes = jar(b"NOTICE foo\nPATCHED\n");
    write(root, &format!("proj/{jar_rel}"), &jar_bytes);
    let state = serde_json::json!({
        "version": 1,
        "entries": { purl("foo"): {
            "ecosystem": "maven",
            "basePurl": purl("foo"),
            "uuid": FOO_UUID,
            "artifact": {
                "path": jar_rel,
                "sha256": hex::encode(Sha256::digest(&jar_bytes)),
                "size": jar_bytes.len(),
            },
            "wiring": [{
                "file": "pom.xml",
                "kind": "maven_pom_repository",
                "action": "added",
                "key": repo_id,
                "original": pom,
                "new": wired,
            }],
        } },
    });
    write(
        root,
        "proj/.socket/vendor/state.json",
        serde_json::to_string_pretty(&state).unwrap().as_bytes(),
    );
}

/// #973: a root whose ledger still holds a pre-v5 single-pom entry is
/// refused whole (`legacy_maven_root`), alone or beside a Gradle build,
/// with nothing written. `vendor --revert` restores every byte, and the
/// next vendor plans the root through the suffixed planner.
#[test]
fn legacy_single_pom_entry_is_refused_until_reverted() {
    let pom = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.x</groupId>\n  <artifactId>app</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency><groupId>org.example</groupId><artifactId>foo</artifactId><version>1.0</version></dependency>\n  </dependencies>\n</project>\n";
    for mixed in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
        if !mixed {
            std::fs::remove_file(root.join("proj/settings.gradle")).unwrap();
            std::fs::remove_dir_all(root.join("proj/app")).unwrap();
        }
        write(root, "proj/pom.xml", pom.as_bytes());
        let pristine = snapshot(root);
        plant_legacy_single_pom(root, pom);
        assert_refused(root, "legacy_maven_root", "socket-patch vendor --revert");
        ok(root, &["vendor", "--revert"]);
        assert_eq!(snapshot(root), pristine, "mixed={mixed}");
        let env = ok(root, &["vendor"]);
        assert_eq!(env["summary"]["applied"], 1, "mixed={mixed}: {env}");
        assert!(root
            .join(FOO_MAVEN_TREE)
            .join("foo-1.0-socket.1d3c1fd2.jar")
            .is_file());
        let state = std::fs::read_to_string(root.join("proj/.socket/vendor/state.json")).unwrap();
        assert!(!state.contains("maven_pom_repository"), "{state}");
        ok(root, &["vendor", "--revert"]);
        assert_eq!(snapshot(root), pristine, "mixed={mixed}");
    }
}

/// #973: a lone single-module pom with no Maven Wrapper vendors through
/// the planner: suffixed tree and pin, `.mvn/maven.config`, both
/// wrapper-less warnings, `--check` and VEX pass, and the revert restores
/// every byte.
#[test]
fn single_module_pom_vendors_through_the_planner() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    std::fs::remove_file(root.join("proj/settings.gradle")).unwrap();
    std::fs::remove_dir_all(root.join("proj/app")).unwrap();
    write(
        root,
        "proj/pom.xml",
        b"<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>com.x</groupId>\n  <artifactId>app</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency><groupId>org.example</groupId><artifactId>foo</artifactId><version>1.0</version></dependency>\n  </dependencies>\n</project>\n",
    );
    let pristine = snapshot(root);
    let env = ok(root, &["vendor"]);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let text = env.to_string();
    for reason in ["maven_f_outside_root", "maven_mirror_of_all"] {
        assert!(
            text.contains(&format!("reason: {reason}: ")),
            "{reason}: {env}"
        );
    }
    assert!(!text.contains("vendor_maven_local_cache_shadow"), "{env}");
    assert!(root
        .join(FOO_MAVEN_TREE)
        .join("foo-1.0-socket.1d3c1fd2.jar")
        .is_file());
    assert!(std::fs::read_to_string(root.join("proj/pom.xml"))
        .unwrap()
        .contains("1.0-socket.1d3c1fd2"));
    assert!(root.join("proj/.mvn/maven.config").is_file());
    assert!(!root.join("proj/.socket/vendor/maven").exists());
    let again = snapshot(root);
    ok(root, &["vendor"]);
    assert_eq!(snapshot(root), again, "an in-sync re-run writes nothing");
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

/// #395 repair: a mixed root whose Gradle tree directory is a link out of
/// the checkout is not repaired through it (the swap would delete and
/// rewrite the directory outside); the outside copy stays untouched.
#[cfg(unix)]
#[test]
fn gradle_vendor_395_repair_refuses_a_linked_gradle_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Gradle, &[("foo", FOO_UUID)]);
    write(
        root,
        "proj/pom.xml",
        b"<project><modelVersion>4.0.0</modelVersion><groupId>com.x</groupId><artifactId>app</artifactId><version>1</version><dependencies><dependency><groupId>org.example</groupId><artifactId>foo</artifactId><version>1.0</version></dependency></dependencies></project>\n",
    );
    ok(root, &["vendor"]);
    let outside = root.join("outside");
    std::fs::rename(root.join("proj/.socket/vendor/gradle"), &outside).unwrap();
    std::fs::remove_file(outside.join("org/example/foo/1.0/foo-1.0.pom")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("proj/.socket/vendor/gradle")).unwrap();
    let listing = |dir: &Path| -> Vec<_> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect()
    };
    let before = listing(&outside.join("org/example/foo/1.0"));
    let (code, env) = socket(root, &["repair"]);
    assert_ne!(code, Some(0), "{env}");
    assert!(env.to_string().contains("vendor_path_unsafe"), "{env}");
    assert_eq!(listing(&outside.join("org/example/foo/1.0")), before);
}

/// A rules_jvm_external hub of a Bazel workspace builds the jar its own
/// lock pins, not the one vendored for Maven. Here nothing in the checkout
/// says which Bazel builds it, so `vendor` writes no entry for the hub
/// ([`vendor_gives_a_pinned_bazel_hub_the_patched_jar`] is the checkout
/// where it does): beside such a hub it warns once for each jar the hub
/// builds, with the reason, in the envelope or as a line a person
/// reads, and its events and every file it writes are those of the same
/// run without the workspace. A hub that does not build a vendored jar
/// adds nothing.
#[test]
fn a_bazel_hub_that_builds_a_vendored_jar_adds_one_warning_and_nothing_else() {
    let module = "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n\
                  maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
                  maven.install(lock_file = \"//:maven_install.json\")\n";
    let lock = |artifact: &str| {
        format!(
            "{{\"artifacts\": {{\"org.example:{artifact}\": {{\"shasums\": {{\"jar\": \"00\"}}, \
             \"version\": \"1.0\"}}}}, \"repositories\": {{\"https://repo1.maven.org/maven2/\": \
             [\"org.example:{artifact}\"]}}, \"version\": \"3\"}}\n"
        )
    };
    let checkout = |lock: Option<String>| {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(
            root,
            Shape::Reactor,
            &[("foo", FOO_UUID), ("bar", BAR_UUID)],
        );
        if let Some(lock) = lock {
            write(root, "proj/MODULE.bazel", module.as_bytes());
            write(root, "proj/maven_install.json", lock.as_bytes());
        }
        tmp
    };
    let vendor = |lock: Option<String>| {
        let tmp = checkout(lock);
        let root = tmp.path();
        let env = ok(root, &["vendor"]);
        let mut tree = snapshot(root);
        tree.retain(|rel, _| rel != "MODULE.bazel" && rel != "maven_install.json");
        let warnings = env["warnings"].as_array().cloned().unwrap_or_default();
        (events(&env), tree, warnings)
    };
    let without = vendor(None);
    let applied = without.0.iter().filter(|event| event.1 == "applied");
    assert_eq!(applied.count(), 2, "{:?}", without.0);
    assert_eq!(vendor(Some(lock("other"))), without);
    let (events, tree, warnings) = vendor(Some(lock("foo")));
    assert_eq!((&events, &tree), (&without.0, &without.1));
    let detail = format!(
        "{0}: no file of the checkout says that Bazel 7.4.0 or later builds it, and an older \
         Bazel fails on the `override_repo` an entry needs: name the release in `.bazelversion`. \
         socket-patch wrote nothing to MODULE.bazel for it, so the Bazel build keeps the \
         upstream jar",
        purl("foo")
    );
    let warning = serde_json::json!({ "code": "maven_bazel_release", "detail": detail });
    assert_eq!(warnings, [without.2, vec![warning]].concat());
    // A person reads it once, on stderr, and not under `--silent`; a
    // program reads it in the envelope alone.
    let line = format!("Warning: {detail}");
    for (args, json, times) in [
        (&["vendor"][..], false, 1),
        (&["vendor", "--silent"], false, 0),
        (&["vendor"], true, 0),
    ] {
        let tmp = checkout(Some(lock("foo")));
        let out = spawn(tmp.path(), args, json);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(stderr.matches(&line).count(), times, "{args:?}: {stderr}");
    }
    // And reads it above the summary of the run and its next steps: both
    // streams in one file, in the order they were written.
    let tmp = checkout(Some(lock("foo")));
    let (mut cmd, _fixture) = command(tmp.path(), &["vendor"], false);
    let log = std::fs::File::create(tmp.path().join("log")).unwrap();
    let status = cmd
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .status()
        .unwrap();
    let said = std::fs::read_to_string(tmp.path().join("log")).unwrap();
    assert!(status.success(), "{said}");
    let at = [line.as_str(), "Vendored 2 packages.", "Next steps:"].map(|text| said.find(text));
    assert!(at[0].is_some() && at[0] < at[1] && at[1] < at[2], "{said}");
    // A run whose `--ecosystems` leaves Maven out vendors no Maven patch
    // and says nothing of the hub, as without the workspace: here the one
    // npm patch of the manifest, whose package is not installed.
    let others = |lock: Option<String>| {
        let tmp = checkout(lock);
        let manifest = tmp.path().join("proj/.socket/manifest.json");
        let mut patches: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
        patches["patches"]["pkg:npm/left-pad@1.3.0"] = patches["patches"][purl("foo")].clone();
        std::fs::write(&manifest, patches.to_string()).unwrap();
        // No server: the run downloads nothing.
        let npm = ["vendor", "--ecosystems", "npm", "--offline"];
        let nowhere = ["--patch-server-url", "http://127.0.0.1:9"];
        let (_, env) = socket(tmp.path(), &[npm.as_slice(), &nowhere].concat());
        let about = env["events"].as_array().unwrap().iter();
        let about: Vec<_> = about.map(|event| event["purl"].clone()).collect();
        assert_eq!(about, ["pkg:npm/left-pad@1.3.0"], "{env}");
        env["warnings"].clone()
    };
    assert_eq!(others(Some(lock("foo"))), others(None));
}

/// Beside a Maven build, vendored mode ejects no hosted patch of a
/// rules_jvm_external hub. The entry that hosted mode keeps for a jar in
/// the block of `MODULE.bazel` is a hosted pin of that jar, and where
/// vendored mode writes no entry for the hub, `vendor` and `vendor
/// --revert` leave it as it is: the Bazel build keeps the patched jar.
/// Everything else is the run without the workspace, and nothing is said
/// of a hub that the block patches. That holds for an entry alone, and for
/// one whose patch a hosted run also pinned in the poms of the reactor:
/// `vendor` takes the poms' part of that pin over, as it does without the
/// workspace.
///
/// A hub that vendored mode can patch gets the vendored entry in the place
/// of the hosted one in the run that vendors the same patch for the Maven
/// build: one entry for the jar, which `vendor --revert` takes out.
///
/// In a checkout that only Bazel builds, the hub is the build `vendor`
/// patches: its entry takes the place of the hosted one, and where it can
/// write none the hosted entry stays and nothing is written.
#[test]
fn vendor_leaves_the_hosted_entry_of_a_bazel_hub_in_place() {
    let module = format!(
        r#"bazel_dep(name = "rules_jvm_external", version = "7.2")
maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")
maven.install(lock_file = "//:maven_install.json")

# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_http_file = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

socket_patch_maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")

# pkg:maven/org.example/foo@1.0, Socket patch {FOO_UUID}
socket_patch_http_file(
    name = "socket_patch_org_example_foo_1_0",
    downloaded_file_path = "v1/org/example/foo/1.0/foo-1.0.jar",
    sha256 = "{sum}",
    urls = ["https://patch.socket.dev/patch-registry/maven/token/{FOO_UUID}/maven2/org/example/foo/1.0-socket.1d3c1fd2/foo-1.0-socket.1d3c1fd2.jar"],
)

# If Bazel stops at the next line ("does not generate repository"), the hub's lock no longer pins
# org.example:foo at 1.0: run `socket-patch rollback pkg:maven/org.example/foo@1.0`.
# Do not change it to inject_repo(): the build would pass without the patch.
override_repo(
    socket_patch_maven,
    org_example_foo_1_0 = "socket_patch_org_example_foo_1_0",
)
# <<< socket-patch <<<
"#,
        sum = "a".repeat(64)
    );
    let lock = "{\"artifacts\": {\"org.example:foo\": {\"shasums\": {\"jar\": \"00\"}, \
                \"version\": \"1.0\"}}, \"repositories\": {\"https://repo1.maven.org/maven2/\": \
                [\"org.example:foo\"]}, \"version\": \"3\"}\n";
    // The pin `list` reads from the block, when there is one.
    let hosted = |root: &Path| {
        let (code, list) = socket(root, &["list"]);
        assert_eq!(code, Some(0), "{list}");
        let events = list["events"].as_array().unwrap().iter();
        let pin = |event: &&serde_json::Value| {
            event["purl"] == purl("foo") && event["details"]["mode"] == "hosted"
        };
        events
            .filter(pin)
            .map(|event| event["details"]["lockfiles"].clone())
            .collect::<Vec<_>>()
    };
    // The pin of a hosted run in the poms of the reactor: the version in
    // the module, the repository in the root.
    let repository = format!(
        "  <repositories>\n    <repository>\n      <id>socket-patch-{FOO_UUID}</id>\n      \
         <url>https://patch.socket.dev/patch-registry/maven/token/{FOO_UUID}/maven2</url>\n      \
         <releases>\n        <enabled>true</enabled>\n        \
         <checksumPolicy>fail</checksumPolicy>\n      </releases>\n      <snapshots>\n        \
         <enabled>false</enabled>\n      </snapshots>\n    </repository>\n  \
         </repositories>\n</project>"
    );
    let pin_poms = |root: &Path| {
        for (pom, from, to) in [
            (
                "proj/a/pom.xml",
                "<version>1.0<",
                "<version>1.0-socket.1d3c1fd2<",
            ),
            ("proj/pom.xml", "</project>", repository.as_str()),
        ] {
            let text = std::fs::read_to_string(root.join(pom)).unwrap();
            assert_eq!(text.matches(from).count(), 1, "{pom}");
            write(root, pom, text.replace(from, to).as_bytes());
        }
    };
    // The API of the patch record, which the eject of a hosted pin asks
    // for. Without a pin in the poms no record is asked for: an eject
    // would ask the port of `nowhere` for one.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let api = runtime.block_on(wiremock::MockServer::start());
    let serve_record = |root: &Path| {
        let manifest = std::fs::read(root.join("proj/.socket/manifest.json")).unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        let mut view = manifest["patches"][purl("foo")].clone();
        view["purl"] = purl("foo").into();
        view["publishedAt"] = view["exportedAt"].clone();
        let record = wiremock::ResponseTemplate::new(200).set_body_json(view);
        let asked = wiremock::Mock::given(wiremock::matchers::method("GET")).respond_with(record);
        runtime.block_on(asked.mount(&api));
        api.uri()
    };
    let nowhere = "http://127.0.0.1:9".to_string();
    let run = |bazel: bool, in_poms: bool| {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
        let mut pinned_in = Vec::new();
        if bazel {
            write(root, "proj/MODULE.bazel", module.as_bytes());
            write(root, "proj/maven_install.json", lock.as_bytes());
            pinned_in.push("MODULE.bazel");
        }
        let records = if in_poms {
            pin_poms(root);
            pinned_in.extend(["a/pom.xml", "pom.xml"]);
            serve_record(root)
        } else {
            nowhere.clone()
        };
        let pins = usize::from(bazel || in_poms);
        assert_eq!(hosted(root), [serde_json::json!(pinned_in)][..pins]);
        let mut steps = Vec::new();
        for args in [&["vendor"][..], &["vendor", "--revert"]] {
            let env = ok(root, &[args, &["--proxy-url", &records]].concat());
            let mut tree = snapshot(root);
            let module = tree.remove("MODULE.bazel").flatten();
            tree.remove("maven_install.json");
            steps.push((events(&env), env["warnings"].clone(), tree, module));
            // The entry is the hosted pin that is left, and all of it.
            let entry = [serde_json::json!(["MODULE.bazel"])];
            assert_eq!(hosted(root), entry[..usize::from(bazel)], "{args:?}");
        }
        steps
    };
    for in_poms in [false, true] {
        let (without, beside) = (run(false, in_poms), run(true, in_poms));
        let vendored = (purl("foo"), "applied".to_string(), String::new());
        assert!(without[0].0.contains(&vendored), "{:?}", without[0].0);
        for (beside, without) in beside.iter().zip(&without) {
            assert_eq!(
                (&beside.0, &beside.1, &beside.2),
                (&without.0, &without.1, &without.2),
                "{in_poms}"
            );
            assert_eq!(beside.3.as_deref(), Some(module.as_bytes()), "{in_poms}");
        }
    }

    // A hub that vendored mode can patch, beside the Maven build that the
    // run vendors the patch for (a patch of the manifest, and one that the
    // poms pin too): the vendored entry is in the place of the hosted one,
    // and the undo of the vendoring takes it out.
    for in_poms in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
        pinned_hub(root, "foo");
        write(root, "proj/MODULE.bazel", module.as_bytes());
        let records = match in_poms {
            true => {
                pin_poms(root);
                serve_record(root)
            }
            false => nowhere.clone(),
        };
        let held = || std::fs::read_to_string(root.join("proj/MODULE.bazel")).unwrap();
        ok(root, &["vendor", "--proxy-url", &records]);
        assert_eq!(held(), format!("{HUB_MODULE}\n{FOO_BLOCK}"), "{in_poms}");
        assert!(hosted(root).is_empty(), "{in_poms}");
        ok(root, &["vendor", "--revert", "--proxy-url", &records]);
        assert_eq!(held(), HUB_MODULE, "{in_poms}");
    }

    for declined in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
        only_bazel(root);
        pinned_hub(root, "foo");
        write(root, "proj/MODULE.bazel", module.as_bytes());
        // Nothing says which Bazel builds the checkout.
        for gone in ["proj/.bazelversion", "proj/MODULE.bazel.lock"] {
            if declined {
                std::fs::remove_file(root.join(gone)).unwrap();
            }
        }
        let (records, before) = (serve_record(root), snapshot(root));
        let (code, env) = socket(root, &["vendor", "--proxy-url", &records]);
        let (failed, after) = (&env["events"][0], snapshot(root));
        let pins = usize::from(declined);
        assert_eq!(code, Some(pins as i32), "{declined}: {env}");
        let entry = [serde_json::json!(["MODULE.bazel"])];
        assert_eq!(hosted(root), entry[..pins], "{declined}: {env}");
        if declined {
            assert_eq!(failed["errorCode"], "maven_bazel_release", "{env}");
            let left = "socket-patch left the entry that MODULE.bazel holds for it as it is";
            let why = failed["error"].as_str().unwrap_or_default();
            assert!(why.ends_with(left), "{env}");
            assert_eq!(after, before, "{env}");
        } else {
            let vendored = format!("{HUB_MODULE}\n{FOO_BLOCK}");
            let held = after["MODULE.bazel"].as_deref();
            assert_eq!(held, Some(vendored.as_bytes()), "{env}");
        }
    }
}

/// The module file of a checkout whose hub is pinned, and the files that
/// say which Bazel builds it and which release of the ruleset Bazel
/// selected: the checkout vendored mode writes its entry for.
const HUB_MODULE: &str = "bazel_dep(name = \"rules_jvm_external\", version = \"7.2\")\n\
                          maven = use_extension(\"@rules_jvm_external//:extensions.bzl\", \"maven\")\n\
                          maven.install(lock_file = \"//:maven_install.json\")\n";

fn pinned_hub(root: &Path, artifact: &str) {
    let lock = format!(
        "{{\"artifacts\": {{\"org.example:{artifact}\": {{\"shasums\": {{\"jar\": \"00\"}}, \
         \"version\": \"1.0\"}}}}, \"repositories\": {{\"https://repo.example/maven2/\": \
         [\"org.example:{artifact}\"]}}, \"version\": \"3\"}}\n"
    );
    let bcr = "https://bcr.bazel.build/modules/rules_jvm_external";
    let module_lock = format!(
        "{{\"lockFileVersion\": 13, \"registryFileHashes\": {{\"{bcr}/7.2/MODULE.bazel\": \"1\", \
         \"{bcr}/7.2/source.json\": \"2\"}}}}\n"
    );
    write(root, "proj/MODULE.bazel", HUB_MODULE.as_bytes());
    write(root, "proj/maven_install.json", lock.as_bytes());
    write(root, "proj/.bazelversion", b"7.7.2\n");
    write(root, "proj/MODULE.bazel.lock", module_lock.as_bytes());
}

/// The fixture without its Maven build: a checkout that only Bazel builds.
fn only_bazel(root: &Path) {
    for gone in ["proj/pom.xml", "proj/a/pom.xml"] {
        std::fs::remove_file(root.join(gone)).unwrap();
    }
    std::fs::remove_dir(root.join("proj/a")).unwrap();
    std::fs::remove_dir_all(root.join("proj/.mvn")).unwrap();
}

/// The directory vendored mode keeps for the hub's jar of `foo`, the
/// block that names it, with its last line break, and the pair of
/// `.bazelignore`.
const FOO_UNIT: &str = ".socket/vendor/maven/1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const FOO_BLOCK: &str = r#"# >>> socket-patch: Maven patches for Bazel (managed block: socket-patch writes and removes it) >>>
socket_patch_local_repository = use_repo_rule("@bazel_tools//tools/build_defs/repo:local.bzl", "local_repository")

socket_patch_maven = use_extension("@rules_jvm_external//:extensions.bzl", "maven")

# pkg:maven/org.example/foo@1.0, Socket patch 1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f
socket_patch_local_repository(
    name = "socket_patch_org_example_foo_1_0",
    path = ".socket/vendor/maven/1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f",
)

# If Bazel stops at the next line ("does not generate repository"), the hub's lock no longer pins
# org.example:foo at 1.0: run `socket-patch rollback pkg:maven/org.example/foo@1.0`.
# Do not change it to inject_repo(): the build would pass without the patch.
override_repo(
    socket_patch_maven,
    org_example_foo_1_0 = "socket_patch_org_example_foo_1_0",
)
# <<< socket-patch <<<
"#;
const JARS_IGNORED: &str =
    "# socket-patch: patched Maven jars for a Bazel hub, not Bazel packages \
                            (to opt out, comment out the next line)\n.socket/vendor/maven\n";

/// Vendored mode patches a pinned rules_jvm_external hub: `vendor` commits
/// the patched jar in a directory of its own, which the block at the end
/// of `MODULE.bazel` puts in the place of the hub's repository, and names
/// the directory in `.bazelignore`. That holds in a checkout only Bazel
/// builds, where the hub's jar is the vendored artifact, and beside a
/// Maven build, which is vendored exactly as without the workspace.
/// `vendor --check` fails for a committed jar that is not the patched one
/// and for a BUILD file that is not the one written; `list` and `vex` see
/// the patch; `vendor --revert` and `rollback` restore every byte.
#[test]
fn vendor_gives_a_pinned_bazel_hub_the_patched_jar() {
    for alone in [true, false] {
        // Without the workspace: what the Maven build alone gets.
        let without = tempfile::tempdir().unwrap();
        fixture(without.path(), Shape::Reactor, &[("foo", FOO_UUID)]);
        let maven_alone = (!alone).then(|| {
            let env = ok(without.path(), &["vendor"]);
            (
                events(&env),
                env["warnings"].clone(),
                snapshot(without.path()),
            )
        });

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
        if alone {
            only_bazel(root);
        }
        pinned_hub(root, "foo");
        let pristine = snapshot(root);
        let read = |rel: &str| std::fs::read(root.join("proj").join(rel)).ok();
        let text = |rel: &str| read(rel).map(|bytes| String::from_utf8(bytes).unwrap());

        // A dry run says what would be vendored and writes nothing.
        let env = ok(root, &["vendor", "--dry-run"]);
        assert_eq!(env["warnings"], serde_json::Value::Null, "{alone}: {env}");
        assert_eq!(snapshot(root), pristine, "{alone}");

        let env = ok(root, &["vendor"]);
        assert_eq!(env["summary"]["applied"], 1, "{alone}: {env}");
        assert_eq!(env["warnings"], serde_json::Value::Null, "{alone}: {env}");
        let module = text("MODULE.bazel").unwrap();
        assert_eq!(module, format!("{HUB_MODULE}\n{FOO_BLOCK}"), "{alone}");
        assert_eq!(
            text(".bazelignore").as_deref(),
            Some(JARS_IGNORED),
            "{alone}"
        );
        let build = "filegroup(\n    name = \"file\",\n    srcs = [\"foo-1.0.jar\"],\n    \
                     visibility = [\"//visibility:public\"],\n)\n";
        let unit = |rel: &str| format!("{FOO_UNIT}/{rel}");
        assert_eq!(text(&unit("file/BUILD.bazel")).as_deref(), Some(build));
        assert_eq!(text(&unit(".gitignore")).as_deref(), Some("!*\n"));
        let repo = text(&unit("REPO.bazel")).unwrap();
        assert!(repo.lines().all(|line| line.starts_with("# ")), "{repo}");
        let patched = jar(b"NOTICE foo\nPATCHED\n");
        let committed = read(&unit("file/foo-1.0.jar")).unwrap();
        let notice = |jar: &[u8]| {
            let mut zip = zip::ZipArchive::new(std::io::Cursor::new(jar)).unwrap();
            let mut text = String::new();
            std::io::Read::read_to_string(&mut zip.by_name(MEMBER).unwrap(), &mut text).unwrap();
            text
        };
        assert_eq!(notice(&committed), notice(&patched), "{alone}");
        // The ledger: the hub's jar as the artifact of a patch that only
        // the hub takes, and the Maven tree's beside a Maven build.
        let ledger: serde_json::Value =
            serde_json::from_slice(&read(".socket/vendor/state.json").unwrap()).unwrap();
        let entry = &ledger["entries"][purl("foo")];
        let recorded = [
            &entry["ecosystem"],
            &entry["flavor"],
            &entry["artifact"]["path"],
        ];
        let hub = [
            serde_json::json!("maven"),
            serde_json::json!("bazel"),
            serde_json::json!(unit("file/foo-1.0.jar")),
        ];
        match alone {
            true => assert_eq!(recorded, hub.each_ref(), "{ledger}"),
            false => assert_eq!(entry["ecosystem"], "jvm", "{ledger}"),
        }
        // Beside the Maven build: its events, and every file but those of
        // the hub, are the ones of the run without the workspace.
        if let Some((events_alone, warnings, tree)) = &maven_alone {
            assert_eq!((&events(&env), &env["warnings"]), (events_alone, warnings));
            let mut beside = snapshot(root);
            let of_the_hub = |rel: &String| {
                rel.starts_with(".socket/vendor/maven/")
                    || [
                        "MODULE.bazel",
                        "MODULE.bazel.lock",
                        "maven_install.json",
                        ".bazelversion",
                        ".bazelignore",
                    ]
                    .contains(&rel.as_str())
            };
            beside.retain(|rel, _| !of_the_hub(rel));
            assert_eq!(&beside, tree);
        }
        let vendored = snapshot(root);

        // A second run changes nothing, and the audit passes.
        let again = ok(root, &["vendor"]);
        let in_sync = (
            purl("foo"),
            "skipped".to_string(),
            "already_vendored".to_string(),
        );
        assert_eq!(events(&again), [in_sync], "{alone}: {again}");
        assert_eq!(snapshot(root), vendored, "{alone}");
        let (code, check) = socket(root, &["vendor", "--check"]);
        assert_eq!(code, Some(0), "{alone}: {check}");
        // And `repair` finds nothing to do: the directory that `MODULE.bazel`
        // names is the ledger entry's, also where that entry is the Maven
        // build's.
        let repaired = ok(root, &["repair"]);
        assert_eq!(snapshot(root), vendored, "{alone}: {repaired}");
        // `list` and `vex` see the patch.
        let (_, list) = socket(root, &["list"]);
        assert_eq!(list["events"][0]["purl"], purl("foo"), "{alone}: {list}");
        let vex = root.join("vex.json");
        let document = [
            "vex",
            "-O",
            vex.to_str().unwrap(),
            "--product",
            "pkg:generic/x@1",
        ];
        ok(root, &document);
        let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&vex).unwrap()).unwrap();
        assert_eq!(doc["statements"][0]["status"], "not_affected", "{doc}");

        // A committed jar that is not the patched one, one that carries
        // the file of the patch beside a member the patched jar has not,
        // and a BUILD file that names another jar: the audit fails for
        // each, and names it.
        let held = std::io::Cursor::new(committed.clone());
        let mut grown = zip::ZipWriter::new_append(held).unwrap();
        let plain = zip::write::SimpleFileOptions::default();
        grown.start_file("other/Other.class", plain).unwrap();
        let grown = grown.finish().unwrap().into_inner();
        assert_eq!(notice(&grown), notice(&patched));
        let planted = grown.clone();
        for (rel, other) in [
            ("file/foo-1.0.jar", jar(b"NOTICE foo\n")),
            ("file/foo-1.0.jar", grown),
            (
                "file/BUILD.bazel",
                build.replace("foo-1.0", "other").into_bytes(),
            ),
        ] {
            let held = read(&unit(rel)).unwrap();
            write(root, &format!("proj/{}", unit(rel)), &other);
            let (code, check) = socket(root, &["vendor", "--check"]);
            assert_eq!(code, Some(1), "{alone} {rel}: {check}");
            let failed = &check["events"][0];
            assert_eq!(failed["errorCode"], "vendor_check_failed", "{rel}: {check}");
            if !alone || rel.ends_with("BUILD.bazel") {
                let why = failed["reason"].as_str().unwrap_or_default();
                assert!(why.contains(&unit(rel)), "{alone} {rel}: {check}");
            }
            write(root, &format!("proj/{}", unit(rel)), &held);
        }
        // A `MODULE.bazel` without the entry, one whose block was changed
        // by hand, and a lock that no longer pins the jar at the version of
        // the patch: the Bazel build takes another jar or stops, and the
        // audit says which, with a remedy that works.
        let rollback = format!("run `socket-patch rollback {}`", purl("foo"));
        let lock = text("maven_install.json").unwrap();
        let bumped = lock.replace("\"version\": \"1.0\"", "\"version\": \"1.1\"");
        let edited = module.replace("# Do not change", "# Do change");
        for (file, held, other, why) in [
            (
                "MODULE.bazel",
                &module,
                HUB_MODULE,
                "MODULE.bazel no longer names",
            ),
            ("MODULE.bazel", &module, &edited, "changed by hand"),
            ("maven_install.json", &lock, &bumped, rollback.as_str()),
        ] {
            assert_ne!(held.as_str(), other, "{file}");
            write(root, &format!("proj/{file}"), other.as_bytes());
            let (code, check) = socket(root, &["vendor", "--check"]);
            assert_eq!(code, Some(1), "{alone} {why}: {check}");
            let reason = check["events"][0]["reason"].as_str().unwrap_or_default();
            assert!(reason.contains(why), "{alone} {why}: {check}");
            // The hub was the only build of the patch: `vendor` has nothing
            // to vendor it for, and names the same remedy.
            if alone && file == "maven_install.json" {
                let (code, env) = socket(root, &["vendor"]);
                let failed = &env["events"][0];
                assert_eq!(code, Some(1), "{env}");
                assert_eq!(failed["errorCode"], "vendor_jvm_shape_unsupported", "{env}");
                let error = failed["error"].as_str().unwrap_or_default();
                assert!(error.ends_with(why), "{env}");
            }
            write(root, &format!("proj/{file}"), held.as_bytes());
        }
        assert_eq!(snapshot(root), vendored, "{alone}");

        // Beside a Maven build `vex` hashes the jar of the Maven tree, as
        // it does without the workspace: one that is not the patched jar
        // is not attested, whatever the hub's copy holds.
        if !alone {
            let tree = format!("{FOO_MAVEN_TREE}/foo-1.0-socket.1d3c1fd2.jar");
            let held = std::fs::read(root.join(&tree)).unwrap();
            write(root, &tree, &jar(b"NOTICE foo\n"));
            let (_, env) = socket(root, &document);
            assert_eq!(env["summary"]["verified"], 0, "{env}");
            write(root, &tree, &held);
        }

        // A directory that is lost whole comes back with every file: by
        // `repair` where its jar is the vendored artifact, and by the next
        // `vendor` beside a Maven build, which gives the hub the jar of the
        // Maven tree again. That run also drops the directory an earlier
        // patch of the jar left behind, which nothing names any more.
        std::fs::remove_dir_all(root.join("proj").join(FOO_UNIT)).unwrap();
        let stale = ".socket/vendor/maven/0e77a000-0000-4000-8000-0000000000a1";
        if !alone {
            write(
                root,
                &format!("proj/{stale}/REPO.bazel"),
                b"# an earlier patch\n",
            );
            write(root, &format!("proj/{stale}/file/foo-1.0.jar"), b"jar");
        }
        let (code, check) = socket(root, &["vendor", "--check"]);
        assert_eq!(code, Some(1), "{alone}: {check}");
        let back = ok(root, if alone { &["repair"] } else { &["vendor"] });
        assert!(!root.join("proj").join(stale).exists(), "{alone}: {back}");
        if !alone {
            let rebuilt = (
                purl("foo"),
                "skipped".to_string(),
                "vendor_artifact_rebuilt".to_string(),
            );
            assert!(events(&back).contains(&rebuilt), "{back}");
        }
        let now = snapshot(root);
        let differ: Vec<&String> = now
            .keys()
            .chain(vendored.keys())
            .filter(|rel| now.get(*rel) != vendored.get(*rel))
            .collect();
        assert_eq!(differ, Vec::<&String>::new(), "{alone}: {back}");

        // The undo, by each command: every byte and directory of before.
        // `rollback` and `remove` also drop the patch from the run's
        // manifest, which is no file of the comparison and is put back.
        // The same after the hub's lock moved on, where Bazel stops at the
        // entry: the undo takes the stale entry out with its directory,
        // which no scan does.
        let manifest = root.join("proj/.socket/manifest.json");
        let patches = std::fs::read(&manifest).unwrap();
        let foo = purl("foo");
        let undos = [
            &["vendor", "--revert"][..],
            &["rollback", &foo],
            &["remove", &foo],
        ];
        for (undo, stale) in undos
            .iter()
            .flat_map(|undo| [(*undo, false), (*undo, true)])
        {
            std::fs::write(&manifest, &patches).unwrap();
            ok(root, &["vendor"]);
            assert_eq!(snapshot(root), vendored, "{alone} {undo:?}");
            if stale {
                write(root, "proj/maven_install.json", bumped.as_bytes());
            }
            let undone = ok(root, undo);
            write(root, "proj/maven_install.json", lock.as_bytes());
            assert_eq!(snapshot(root), pristine, "{alone} {undo:?} {stale}");
            // No installed tree holds the jar of a hub: nothing is said of
            // a package-manager install for a patch that only the hub took.
            let warned = undone["warnings"].as_array().cloned().unwrap_or_default();
            let reinstall = |warning: &serde_json::Value| warning["code"] == "reinstall_required";
            assert!(
                !alone || !warned.iter().any(reinstall),
                "{undo:?}: {undone}"
            );
        }

        // A jar that waits at the hub's path with no ledger entry is not
        // taken for the vendored one, although it carries the patch's
        // file: the run fetches the patch's own jar over it.
        if alone {
            std::fs::write(&manifest, &patches).unwrap();
            write(
                root,
                &format!("proj/{}", unit("file/foo-1.0.jar")),
                &planted,
            );
            ok(root, &["vendor"]);
            let taken = read(&unit("file/foo-1.0.jar")).unwrap();
            assert_eq!(taken, committed, "the planted jar was vendored");
            ok(root, &["vendor", "--revert"]);
            assert_eq!(snapshot(root), pristine);
        }

        // What a person reads: every file of the hub among those to commit,
        // the step that takes the jar where the hub is the only build, and
        // after the undo no step of a package manager.
        std::fs::write(&manifest, &patches).unwrap();
        let said = |args: &[&str]| {
            let out = spawn(root, args, false);
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            assert!(out.status.success(), "{args:?}: {stdout}");
            stdout
        };
        let (commit, step) = match alone {
            true => (
                "Commit MODULE.bazel, .bazelignore and .socket/vendor/ to",
                "Run `bazel build //...` so the build resolves the vendored artifacts \
                 (MODULE.bazel names their directory)",
            ),
            false => (
                "Commit MODULE.bazel, .bazelignore, .socket/vendor/ and the updated lockfiles",
                "Reinstall from the updated lockfile",
            ),
        };
        let vendoring = said(&["vendor"]);
        assert!(
            vendoring.contains(commit) && vendoring.contains(step),
            "{alone}: {vendoring}"
        );
        let reverting = said(&["vendor", "--revert"]);
        assert!(
            reverting.contains("Reverted 1 vendored package.") && !reverting.contains("resync"),
            "{alone}: {reverting}"
        );
        assert_eq!(snapshot(root), pristine, "{alone}");
    }
}

/// Beside a Maven build the hub's directory must survive the commit, as
/// every vendored artifact must: where a rule of the checkout ignores it,
/// the run vendors for the Maven build, writes nothing for the hub and
/// says why. An entry that names a directory git leaves out would fail
/// the Bazel build of every other checkout.
#[test]
fn vendor_beside_a_maven_build_skips_a_hub_directory_that_git_ignores() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root, Shape::Reactor, &[("foo", FOO_UUID)]);
    pinned_hub(root, "foo");
    let proj = root.join("proj");
    let init = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&proj)
        .output();
    if !init.is_ok_and(|out| out.status.success()) {
        return;
    }
    write(root, "proj/.gitignore", b".socket/vendor/maven/\n");
    let env = ok(root, &["vendor"]);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let said = (
        purl("foo"),
        "skipped".to_string(),
        "maven_bazel_hub_unpatched".to_string(),
    );
    assert!(events(&env).contains(&said), "{env}");
    let module = std::fs::read_to_string(proj.join("MODULE.bazel")).unwrap();
    assert_eq!(module, HUB_MODULE, "{env}");
    assert!(!proj.join(".socket/vendor/maven").exists(), "{env}");
}

/// Where vendored mode cannot show that an entry would work, it writes
/// none, with the code a hosted run gives the same checkout. In a checkout
/// only Bazel builds that is the failure of the patch, and nothing is
/// written; beside a Maven build it is a warning
/// ([`a_bazel_hub_that_builds_a_vendored_jar_adds_one_warning_and_nothing_else`]).
/// An option about downloads stands against a hosted entry and not against
/// a jar in the checkout. A jar no hub builds is refused as before.
#[test]
fn vendor_declines_for_a_hub_it_cannot_patch() {
    let checkout = |artifact: &str| {
        let tmp = tempfile::tempdir().unwrap();
        fixture(tmp.path(), Shape::Reactor, &[("foo", FOO_UUID)]);
        only_bazel(tmp.path());
        pinned_hub(tmp.path(), artifact);
        tmp
    };
    let keeps = "socket-patch wrote nothing to MODULE.bazel for it, so the Bazel build keeps the \
                 upstream jar";
    // Nothing says which Bazel builds the checkout.
    let tmp = checkout("foo");
    let root = tmp.path();
    for gone in ["proj/.bazelversion", "proj/MODULE.bazel.lock"] {
        std::fs::remove_file(root.join(gone)).unwrap();
    }
    let before = snapshot(root);
    let (code, env) = socket(root, &["vendor"]);
    assert_eq!(code, Some(1), "{env}");
    let why = format!(
        "no file of the checkout says that Bazel 7.4.0 or later builds it, and an older \
         Bazel fails on the `override_repo` an entry needs: name the release in `.bazelversion`. \
         {keeps}"
    );
    let failed = (
        purl("foo"),
        "failed".to_string(),
        "maven_bazel_release".to_string(),
    );
    assert_eq!(events(&env), [failed], "{env}");
    assert_eq!(env["events"][0]["error"], why, "{env}");
    assert_eq!(env["warnings"], serde_json::Value::Null, "{env}");
    // A person reads the purl once, before the reason.
    let out = spawn(root, &["vendor"], false);
    let line = format!("Error: Cannot vendor {}: {why}\n", purl("foo"));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(stderr.matches(&line).count(), 1, "{stderr}");
    assert_eq!(snapshot(root), before);

    // An option that leaves the entry without effect declines, and one
    // about downloads does not.
    let tmp = checkout("foo");
    let root = tmp.path();
    write(root, "proj/.bazelrc", b"common --ignore_dev_dependency\n");
    let (code, env) = socket(root, &["vendor"]);
    assert_eq!(code, Some(1), "{env}");
    assert_eq!(
        env["events"][0]["errorCode"], "maven_bazel_no_effect",
        "{env}"
    );
    write(
        root,
        "proj/.bazelrc",
        b"common --repository_disable_download\n",
    );
    let env = ok(root, &["vendor"]);
    assert_eq!(env["summary"]["applied"], 1, "{env}");

    // No hub builds the jar: the refusal of a tree without a JVM build.
    let tmp = checkout("other");
    assert_refused(tmp.path(), "no_build_file", "no pom.xml");
}
