//! CLI flows of the vendored sbt backend (`vendor/jvm/sbt.rs`) over
//! hermetic fixtures: no sbt, no JVM, no network. Each project is the
//! sbt 1.13.0 scoping-probe build with its real `target/` resolution
//! evidence (`sbt_common::copy_evidence`), and the installed jars sit in an
//! isolated Coursier cache (`COURSIER_CACHE`, found by the agent crawler),
//! so the run sees exactly what it would after a real `sbt update`.
//!
//! The patched GAs are ones that evidence resolves at a single version in
//! scope (gson 2.8.9 in `b`, junit 4.13.2 in `a`'s tests), so the suite
//! holds with the evidence gate live as well as stubbed.
//!
//! These pin what only shows through the CLI's own bookkeeping: the ledger
//! shape, revert in either order and after a patch update, `--check`
//! drift, `repair`, a forged ledger, an escaping symlink, the subproject
//! and build-edit refusals.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;
#[path = "sbt_common/mod.rs"]
mod sbt_common;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use sbt_common::{copy_evidence, record_pinned_resolution, write_coursier_artifact, Gav, SbtHome};
use socket_patch_core::formats::sbt::owned_file::{
    parse, render, SbtFileMode, SbtLine, SbtOwnedFile, SbtPin, HOSTED_FILE, VENDORED_FILE,
};

const GSON_UUID: &str = "1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const JUNIT_UUID: &str = "9a8b7c6d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const GSON_UPDATE_UUID: &str = "2e4d6f80-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const MEMBER: &str = "META-INF/NOTICE.txt";
const CENTRAL: &str = "repo1.maven.org/maven2";

const GSON: Gav<'static> = Gav {
    group: "com.google.code.gson",
    artifact: "gson",
    version: "2.8.9",
};
const JUNIT: Gav<'static> = Gav {
    group: "junit",
    artifact: "junit",
    version: "4.13.2",
};

const GSON_TREE: &str = ".socket/vendor/maven2/com/google/code/gson/gson/2.8.9-socket.1d3c1fd2";
const GSON_JAR: &str = ".socket/vendor/maven2/com/google/code/gson/gson/2.8.9-socket.1d3c1fd2/gson-2.8.9-socket.1d3c1fd2.jar";

fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
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

/// Every file under `dir`, recursively.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// Make every evidence file newer than the build sources (a copy writes
/// them in directory order, which could otherwise read as stale).
fn freshen_evidence(proj: &Path) {
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
    for path in files_under(proj) {
        let rel = path
            .strip_prefix(proj)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel.contains("target/") {
            let f = std::fs::File::options().write(true).open(&path).unwrap();
            f.set_modified(later).unwrap();
        }
    }
}

/// A test project: `root/proj` is the sbt build (at `project_dir` below it
/// the manifest and blobs), `root/sbt-home` the isolated caches with every
/// `(gav, uuid)` installed in its Maven repository.
struct Fixture {
    root: PathBuf,
    home: SbtHome,
}

impl Fixture {
    fn new(root: &Path, packages: &[(Gav<'_>, &str)]) -> Self {
        Self::at(root, "", packages)
    }

    fn at(root: &Path, project_dir: &str, packages: &[(Gav<'_>, &str)]) -> Self {
        let proj = root.join("proj");
        copy_evidence("1.13.0", "test-compile", &proj);
        freshen_evidence(&proj);
        let home = SbtHome::new(root);
        let manifest_root = if project_dir.is_empty() {
            proj.clone()
        } else {
            proj.join(project_dir)
        };
        std::fs::create_dir_all(manifest_root.join(".socket/blobs")).unwrap();
        let mut patches = serde_json::Map::new();
        for (gav, uuid) in packages {
            // Installed where sbt 1.3+ leaves it: the Coursier cache the
            // agent crawler finds through `COURSIER_CACHE`.
            let before = format!("NOTICE {}\n", gav.artifact).into_bytes();
            let after = [before.as_slice(), b"PATCHED\n"].concat();
            write_coursier_artifact(&home.coursier_cache(), CENTRAL, *gav, &jar(&before));
            std::fs::write(
                manifest_root.join(".socket/blobs").join(git_sha256(&after)),
                &after,
            )
            .unwrap();
            patches.insert(
                gav.purl(),
                serde_json::json!({
                    "uuid": uuid,
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": { MEMBER: {
                        "beforeHash": git_sha256(&before),
                        "afterHash": git_sha256(&after),
                    } },
                    "vulnerabilities": { "GHSA-xxxx-yyyy-zzzz": {
                        "cves": ["CVE-2026-0001"], "summary": "s", "severity": "high",
                        "description": "d"
                    } },
                    "description": "x",
                    "license": "MIT",
                    "tier": "free",
                }),
            );
        }
        std::fs::write(
            manifest_root.join(".socket/manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
        )
        .unwrap();
        Self {
            root: root.to_path_buf(),
            home,
        }
    }

    fn proj(&self) -> PathBuf {
        self.root.join("proj")
    }

    /// `socket-patch <args> --json --cwd <proj>/<dir>`; `(exit, envelope)`.
    fn run_in(&self, dir: &str, args: &[&str]) -> (Option<i32>, serde_json::Value) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy();
            if k.starts_with("SOCKET_") || k.starts_with("COURSIER_") {
                cmd.env_remove(&*k);
            }
        }
        let cwd = if dir.is_empty() {
            self.proj()
        } else {
            self.proj().join(dir)
        };
        // The download fixture serves the pristine artifacts from the
        // Coursier cache's Maven2 repository root.
        let repo = self.home.coursier_cache().join("https").join(CENTRAL);
        let _fixture = prebuilt_common::prepare_command(
            &mut cmd,
            &cwd,
            args,
            &[("MAVEN_REPO_LOCAL", repo.to_str().unwrap())],
        );
        for (k, v) in self.home.isolated_env() {
            cmd.env(k, v);
        }
        let out = cmd
            .args(["--json", "--cwd", cwd.to_str().unwrap()])
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .env("SOCKET_NO_CONFIG", "1")
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

    fn run(&self, args: &[&str]) -> (Option<i32>, serde_json::Value) {
        self.run_in("", args)
    }

    fn ok(&self, args: &[&str]) -> serde_json::Value {
        let (code, env) = self.run(args);
        assert_eq!(code, Some(0), "{args:?}: {env}");
        let failed = env["summary"].get("failed").unwrap_or(&env["failed"]);
        assert_eq!(failed, 0, "{args:?}: {env}");
        env
    }

    /// Every file and directory under `proj`, minus the manifest and blobs.
    fn snapshot(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                // sbt's own evidence under `target/` is rewritten by
                // [`Fixture::sbt_update`], never by socket-patch.
                if rel.ends_with(".socket/manifest.json")
                    || rel.ends_with(".socket/blobs")
                    || rel == "target"
                    || rel.ends_with("/target")
                    || rel.contains("target/")
                {
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
        let proj = self.proj();
        let mut out = BTreeMap::new();
        walk(&proj, &proj, &mut out);
        out
    }

    /// What `sbt update` records after vendoring: every evidence record
    /// that resolved `gav` now resolves its suffixed version from the
    /// vendored tree, dated after the generated file. A re-run then
    /// re-checks the existing pins (`gate::check_existing`), never the
    /// new-pin gate that would refuse the suffixed version as a conflict.
    fn sbt_update(&self, packages: &[(Gav<'_>, &str)]) {
        let proj = std::fs::canonicalize(self.proj()).unwrap();
        let pins: Vec<(Gav<'_>, String, PathBuf)> = packages
            .iter()
            .map(|(gav, uuid)| {
                let sv = format!("{}-socket.{}", gav.version, &uuid[..8]);
                let jar = proj
                    .join(".socket/vendor/maven2")
                    .join(gav.group_path())
                    .join(gav.artifact)
                    .join(&sv)
                    .join(format!("{}-{sv}.jar", gav.artifact));
                (*gav, sv, jar)
            })
            .collect();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(240);
        assert!(record_pinned_resolution(&proj, &pins, later) > 0);
        let doc = socket_patch_core::crawlers::sbt_evidence::distill(&proj);
        let res = doc.resolution.expect("the updated evidence parses");
        for (gav, uuid) in packages {
            let sv = format!("{}-socket.{}", gav.version, &uuid[..8]);
            assert_eq!(res.versions(gav.group, gav.artifact), [sv]);
        }
        assert!(!doc.stale && !doc.wiring_newer);
    }

    fn generated(&self) -> String {
        std::fs::read_to_string(self.proj().join(VENDORED_FILE)).unwrap()
    }

    fn state(&self) -> serde_json::Value {
        serde_json::from_slice(
            &std::fs::read(self.proj().join(".socket/vendor/state.json")).unwrap(),
        )
        .unwrap()
    }
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

/// The ledger entry, the generated file and the tree: every record a
/// planner can produce for the coordinates, no user file edited, and a
/// re-run (and `--check`) in sync.
#[test]
fn vendor_ledger_shape_and_generated_file() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    let before = fx.snapshot();
    let env = fx.ok(&["vendor"]);
    assert_eq!(env["summary"]["applied"], 1, "{env}");
    let after = fx.snapshot();
    for (rel, bytes) in &before {
        assert_eq!(after.get(rel), Some(bytes), "{rel} changed");
    }
    let added: Vec<&str> = after
        .keys()
        .filter(|k| !before.contains_key(*k))
        .map(String::as_str)
        .filter(|k| !k.ends_with('/'))
        .collect();
    assert_eq!(
        added,
        [
            ".socket/vendor/maven2/.gitattributes".to_string(),
            ".socket/vendor/maven2/.gitignore".to_string(),
            GSON_JAR.to_string(),
            format!("{GSON_JAR}.sha1"),
            format!("{GSON_TREE}/gson-2.8.9-socket.1d3c1fd2.pom"),
            format!("{GSON_TREE}/gson-2.8.9-socket.1d3c1fd2.pom.sha1"),
            format!("{GSON_TREE}/socket-patch.vendor.json"),
            ".socket/vendor/state.json".to_string(),
            VENDORED_FILE.to_string(),
        ]
    );
    assert_eq!(
        std::fs::read(fx.proj().join(".socket/vendor/maven2/.gitignore")).unwrap(),
        b"!*\n"
    );
    let file = parse(SbtFileMode::Vendored, &fx.generated()).unwrap();
    let pin = &file.pins[GSON_UUID];
    assert_eq!(pin.sv, "2.8.9-socket.1d3c1fd2");
    assert_eq!(
        pin.jar_sha256,
        hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
            std::fs::read(fx.proj().join(GSON_JAR)).unwrap()
        ))
    );

    let state = fx.state();
    let entry = &state["entries"][GSON.purl()];
    assert_eq!(entry["ecosystem"], "jvm", "{state}");
    assert_eq!(entry["artifact"]["path"], GSON_JAR, "{state}");
    let mut kinds: Vec<(String, String, String)> = entry["wiring"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] != "jvm_vendor_tree" && w["kind"] != "jvm_created_dir")
        .map(|w| {
            let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
            (s(&w["kind"]), s(&w["file"]), s(&w["key"]))
        })
        .collect();
    kinds.sort();
    assert_eq!(
        kinds,
        [
            (
                "jvm_owned_file".to_string(),
                ".socket/vendor/maven2/.gitattributes".to_string(),
                "owned".to_string()
            ),
            (
                "jvm_owned_file".to_string(),
                ".socket/vendor/maven2/.gitignore".to_string(),
                "owned".to_string()
            ),
            (
                "jvm_upstream_status".to_string(),
                GSON_JAR.to_string(),
                "upstream".to_string()
            ),
            (
                "sbt_build_fragment".to_string(),
                VENDORED_FILE.to_string(),
                "file".to_string()
            ),
            (
                "sbt_build_fragment".to_string(),
                VENDORED_FILE.to_string(),
                format!("pin:{GSON_UUID}")
            ),
        ],
        "{state}"
    );
    let tree = entry["wiring"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["kind"] == "jvm_vendor_tree")
        .count();
    assert_eq!(tree, 5, "{state}");

    fx.sbt_update(&[(GSON, GSON_UUID)]);
    let env = fx.ok(&["vendor"]);
    assert_eq!(
        events(&env),
        [(
            GSON.purl(),
            "skipped".to_string(),
            "already_vendored".to_string()
        )],
        "{env}"
    );
    let synced = fx.snapshot();
    fx.ok(&["vendor", "--check"]);
    assert_eq!(fx.snapshot(), synced);
    fx.ok(&["vendor", "--revert"]);
    assert_eq!(fx.snapshot(), before);
}

/// Rolling back one of two vendored packages leaves the other pinned (a
/// re-vendor finds it in sync), and reverting the rest restores every byte
/// and directory, in either order.
#[test]
fn vendor_two_patches_roll_back_in_either_order() {
    for first in [GSON, JUNIT] {
        let tmp = tempfile::tempdir().unwrap();
        let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID), (JUNIT, JUNIT_UUID)]);
        let pristine = fx.snapshot();
        let env = fx.ok(&["vendor"]);
        assert_eq!(env["summary"]["applied"], 2, "{env}");
        assert_eq!(
            parse(SbtFileMode::Vendored, &fx.generated())
                .unwrap()
                .pins
                .len(),
            2
        );
        fx.sbt_update(&[(GSON, GSON_UUID), (JUNIT, JUNIT_UUID)]);
        fx.ok(&["rollback", &first.purl()]);
        let other = if first.artifact == "gson" {
            JUNIT
        } else {
            GSON
        };
        let left = parse(SbtFileMode::Vendored, &fx.generated()).unwrap();
        assert_eq!(left.pins.len(), 1);
        assert_eq!(left.pins.values().next().unwrap().artifact, other.artifact);
        let env = fx.ok(&["vendor"]);
        assert_eq!(
            events(&env),
            [(
                other.purl(),
                "skipped".to_string(),
                "already_vendored".to_string()
            )],
            "{env}"
        );
        fx.ok(&["vendor", "--revert"]);
        assert_eq!(fx.snapshot(), pristine, "first={}", first.artifact);
    }
}

/// A patch update (same GAV, new uuid) replaces the pin, sweeps the old
/// tree and reverts to pristine.
#[test]
fn vendor_patch_update_replaces_the_pin_and_sweeps() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    let pristine = fx.snapshot();
    fx.ok(&["vendor"]);
    let manifest_path = fx.proj().join(".socket/manifest.json");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    std::fs::write(
        &manifest_path,
        manifest.replace(GSON_UUID, GSON_UPDATE_UUID),
    )
    .unwrap();
    let env = fx.ok(&["vendor"]);
    assert!(
        events(&env)
            .iter()
            .any(|(_, _, code)| code == "vendor_stale_artifact_removed"),
        "{env}"
    );
    assert!(!fx.proj().join(GSON_TREE).exists());
    let text = fx.generated();
    assert!(!text.contains("1d3c1fd2"), "{text}");
    assert!(text.contains("2.8.9-socket.2e4d6f80"), "{text}");
    fx.ok(&["vendor", "--check"]);
    fx.ok(&["vendor", "--revert"]);
    assert_eq!(fx.snapshot(), pristine);
}

/// `vendor --check` is read-only and catches an edited generated file, a
/// tampered tree file and a deleted generated file; a re-run with the
/// jar source gone needs none, and `repair` rebuilds a deleted tree jar.
#[test]
fn vendor_check_drift_rerun_and_repair() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    let pristine = fx.snapshot();
    fx.ok(&["vendor"]);
    fx.sbt_update(&[(GSON, GSON_UUID)]);
    let good = fx.generated();
    let path = fx.proj().join(VENDORED_FILE);
    let jar_path = fx.proj().join(GSON_JAR);
    let good_jar = std::fs::read(&jar_path).unwrap();
    for (what, tamper) in [("edited file", 0), ("tampered jar", 1), ("deleted file", 2)] {
        match tamper {
            0 => std::fs::write(&path, good.replace("// socket-patch ", "// mine ")).unwrap(),
            1 => std::fs::write(&jar_path, jar(b"EVIL\n")).unwrap(),
            _ => std::fs::remove_file(&path).unwrap(),
        }
        let corrupt = fx.snapshot();
        let (code, env) = fx.run(&["vendor", "--check"]);
        assert_eq!(code, Some(1), "{what}: {env}");
        assert_eq!(fx.snapshot(), corrupt, "{what}: --check wrote");
        std::fs::write(&path, &good).unwrap();
        std::fs::write(&jar_path, &good_jar).unwrap();
    }
    fx.ok(&["vendor", "--check"]);

    let cache = fx.home.coursier_cache();
    let parked = tmp.path().join("coursier-parked");
    std::fs::rename(&cache, &parked).unwrap();
    let env = fx.ok(&["vendor"]);
    assert_eq!(
        events(&env),
        [(
            GSON.purl(),
            "skipped".to_string(),
            "already_vendored".to_string()
        )],
        "{env}"
    );
    std::fs::rename(&parked, &cache).unwrap();
    std::fs::remove_file(&jar_path).unwrap();
    let env = fx.ok(&["repair"]);
    assert_eq!(env["events"][0]["action"], "rebuilt", "{env}");
    assert_eq!(std::fs::read(&jar_path).unwrap(), good_jar);
    fx.ok(&["vendor", "--revert"]);
    assert_eq!(fx.snapshot(), pristine);
}

/// A generated file left without its ledger, tree or manifest patch is an
/// orphan for `vendor --check`: the build would fail at load.
#[test]
fn vendor_check_flags_a_ledgerless_generated_file() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    fx.ok(&["vendor"]);
    std::fs::remove_file(fx.proj().join(".socket/vendor/state.json")).unwrap();
    std::fs::remove_dir_all(fx.proj().join(".socket/vendor/maven2")).unwrap();
    // No manifest patch either, so only the generated file can trip it.
    std::fs::write(
        fx.proj().join(".socket/manifest.json"),
        "{\"patches\":{}}\n",
    )
    .unwrap();
    let before = fx.snapshot();
    let (code, env) = fx.run(&["vendor", "--check"]);
    assert_eq!(code, Some(1), "{env}");
    assert!(env.to_string().contains("vendor_ledger_missing"), "{env}");
    assert_eq!(fx.snapshot(), before);
}

/// A forged sbt ledger entry naming a user file (or escaping the checkout)
/// is refused before any write.
#[test]
fn vendor_forged_ledger_touches_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    let proj = fx.proj();
    let build = std::fs::read(proj.join("build.sbt")).unwrap();
    for (file, kind) in [
        ("build.sbt", "sbt_build_fragment"),
        ("project/build.properties", "jvm_owned_file"),
        ("../outside.sbt", "sbt_build_fragment"),
    ] {
        let state = serde_json::json!({ "version": 1, "entries": { GSON.purl(): {
            "ecosystem": "jvm", "basePurl": GSON.purl(), "uuid": GSON_UUID,
            "artifact": { "path": GSON_JAR, "sha256": "" },
            "wiring": [{ "file": file, "kind": kind, "action": "added", "key": "file",
                "new": { "op": "create" } }],
        } } });
        std::fs::create_dir_all(proj.join(".socket/vendor")).unwrap();
        std::fs::write(proj.join(".socket/vendor/state.json"), state.to_string()).unwrap();
        let before = fx.snapshot();
        let (code, env) = fx.run(&["vendor", "--revert"]);
        assert_ne!(code, Some(0), "{file}: {env}");
        assert_eq!(fx.snapshot(), before, "{file}");
        assert_eq!(std::fs::read(proj.join("build.sbt")).unwrap(), build);
        assert!(proj.join("project/build.properties").is_file());
        assert!(!tmp.path().join("outside.sbt").exists());
    }
}

/// The generated file or the tree symlinked out of the checkout is refused
/// with `build_file_outside_root`, and nothing is written through it.
#[cfg(unix)]
#[test]
fn vendor_escaping_symlinks_are_refused() {
    for link in [VENDORED_FILE, ".socket/vendor"] {
        let tmp = tempfile::tempdir().unwrap();
        let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let target = if link == VENDORED_FILE {
            outside.join("x.sbt")
        } else {
            outside.clone()
        };
        std::os::unix::fs::symlink(&target, fx.proj().join(link)).unwrap();
        let (code, env) = fx.run(&["vendor"]);
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
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            0,
            "{link}: wrote outside the checkout"
        );
    }
}

/// Vendoring from a subproject directory refuses with `not_build_root`,
/// naming the build root.
#[test]
fn vendor_subproject_refuses_not_build_root() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::at(tmp.path(), "b", &[(GSON, GSON_UUID)]);
    std::fs::write(fx.proj().join("b/build.sbt"), "name := \"b\"\n").unwrap();
    let before = fx.snapshot();
    let (code, env) = fx.run_in("b", &["vendor"]);
    assert_ne!(code, Some(0), "{env}");
    assert_eq!(
        env["events"][0]["errorCode"], "vendor_jvm_shape_unsupported",
        "{env}"
    );
    let error = env["events"][0]["error"].as_str().unwrap_or_default();
    assert!(
        error.starts_with("reason: not_build_root: run vendor from sbt build root"),
        "{env}"
    );
    assert_eq!(fx.snapshot(), before);
}

/// Build edits that would defeat the pin, an ambiguous root and a hosted
/// pin of the same GA refuse before any write.
#[test]
fn vendor_refusals_write_nothing() {
    for (case, code) in [
        ("overrides", "vendor_sbt_overrides_assignment"),
        ("resolvers", "vendor_sbt_resolvers_assignment"),
        ("lock", "vendor_sbt_dependency_lock_present"),
        ("gradle", "vendor_jvm_build_ambiguous"),
        ("reactor", "vendor_jvm_build_ambiguous"),
        ("foreign", "vendor_sbt_owned_file_foreign"),
        ("old", "vendor_sbt_unsupported_version"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
        let proj = fx.proj();
        let append = |line: &str| {
            let mut text = std::fs::read_to_string(proj.join("build.sbt")).unwrap();
            text.push_str(line);
            std::fs::write(proj.join("build.sbt"), text).unwrap();
        };
        match case {
            "overrides" => append("ThisBuild / dependencyOverrides := Seq.empty\n"),
            "resolvers" => append("ThisBuild / resolvers := Seq.empty\n"),
            "lock" => std::fs::write(proj.join("build.sbt.lock"), "{}\n").unwrap(),
            "gradle" => std::fs::write(proj.join("build.gradle"), "").unwrap(),
            "reactor" => std::fs::write(
                proj.join("pom.xml"),
                "<project><modules><module>a</module></modules></project>\n",
            )
            .unwrap(),
            "foreign" => std::fs::write(proj.join(VENDORED_FILE), "// my settings\n").unwrap(),
            _ => std::fs::write(
                proj.join("project/build.properties"),
                "sbt.version=0.13.17\n",
            )
            .unwrap(),
        }
        let before = fx.snapshot();
        let (exit, env) = fx.run(&["vendor"]);
        assert_eq!(exit, Some(1), "{case}: {env}");
        assert_eq!(env["events"][0]["errorCode"], code, "{case}: {env}");
        assert_eq!(fx.snapshot(), before, "{case}");
    }
}

/// With no resolution evidence the run warns once, wires nothing and
/// still exits 0 (the evidence gate, `vendor/jvm/sbt_gate.rs`).
#[test]
fn vendor_no_evidence_warns_and_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    for path in files_under(&fx.proj()) {
        if path.to_string_lossy().contains("target") {
            std::fs::remove_file(path).unwrap();
        }
    }
    let before = fx.snapshot();
    let env = fx.ok(&["vendor"]);
    assert!(
        env.to_string()
            .contains("vendor_sbt_no_resolution_evidence"),
        "{env}"
    );
    // Skipped with the gate's code: nothing was vendored, so nothing is
    // counted applied.
    assert_eq!(env["summary"]["applied"], 0, "{env}");
    assert!(
        events(&env).contains(&(
            GSON.purl(),
            "skipped".to_string(),
            "vendor_sbt_no_resolution_evidence".to_string()
        )),
        "{env}"
    );
    assert!(!fx.proj().join(VENDORED_FILE).exists());
    let mut after = fx.snapshot();
    after.retain(|k, _| !k.starts_with(".socket/vendor"));
    let mut before = before;
    before.retain(|k, _| !k.starts_with(".socket/vendor"));
    assert_eq!(after, before);
}

/// The hosted `socket-patch.sbt` pinning gson (`uuid`), as `get --mode
/// hosted` writes it.
fn write_hosted_pin(proj: &Path, uuid: &str) -> Vec<u8> {
    let sv = format!("{}-socket.{}", GSON.version, &uuid[..8]);
    let pin = SbtPin {
        uuid: uuid.into(),
        group: GSON.group.into(),
        artifact: GSON.artifact.into(),
        base: GSON.version.into(),
        sv,
        pom_sha256: "a".repeat(64),
        jar_sha256: "b".repeat(64),
        deps_digest: "0123abcd".into(),
        index_url: Some(format!(
            "https://patch.socket.dev/patch-registry/maven/11111111-1111-4111-8111-111111111111/{uuid}/maven2"
        )),
    };
    let text = render(&SbtOwnedFile {
        mode: SbtFileMode::Hosted,
        line: SbtLine::Sbt1,
        crlf: false,
        pins: [(uuid.to_string(), pin)].into(),
    })
    .unwrap();
    std::fs::write(proj.join(HOSTED_FILE), &text).unwrap();
    text.into_bytes()
}

fn drop_evidence(proj: &Path) {
    for path in files_under(proj) {
        if path.to_string_lossy().contains("target") {
            std::fs::remove_file(path).unwrap();
        }
    }
}

/// A takeover (vendoring over a hosted pin) the vendored gate would skip
/// (no evidence: a fresh clone) is refused BEFORE the hosted pin is
/// restored: the project stays hosted, never neither hosted nor vendored.
#[test]
fn vendor_takeover_the_gate_would_skip_keeps_the_hosted_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    let hosted = write_hosted_pin(&fx.proj(), GSON_UUID);
    drop_evidence(&fx.proj());
    let (exit, env) = fx.run(&["vendor"]);
    assert_eq!(exit, Some(1), "{env}");
    assert!(
        events(&env).contains(&(
            GSON.purl(),
            "failed".to_string(),
            "vendor_sbt_no_resolution_evidence".to_string()
        )),
        "{env}"
    );
    assert_eq!(std::fs::read(fx.proj().join(HOSTED_FILE)).unwrap(), hosted);
    assert!(!fx.proj().join(VENDORED_FILE).exists());
}

/// A dry-run takeover previews (the restore is dry, so the hosted file
/// still pins the GA on disk; the planner's hosted-conflict refusal the wet
/// run never sees is not raised), and the wet run takes over.
#[test]
fn vendor_takeover_of_a_hosted_sbt_pin_dry_and_wet() {
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    let hosted = write_hosted_pin(&fx.proj(), GSON_UUID);
    let env = fx.ok(&["vendor", "--dry-run"]);
    assert!(
        env.to_string().contains("vendor_would_revert_redirect"),
        "{env}"
    );
    assert!(
        !env.to_string().contains("vendor_sbt_hosted_conflict"),
        "{env}"
    );
    assert_eq!(std::fs::read(fx.proj().join(HOSTED_FILE)).unwrap(), hosted);
    let env = fx.ok(&["vendor"]);
    assert!(
        env.to_string()
            .contains("vendor_takeover_reverted_redirect"),
        "{env}"
    );
    assert!(!fx.proj().join(HOSTED_FILE).exists(), "{env}");
    assert!(fx.generated().contains(GSON_UUID));
}

/// An eject (plain `vendor` in a hosted project) the vendored gate would
/// skip is refused whole before anything is restored.
#[test]
fn vendor_eject_the_gate_would_skip_is_refused() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let tmp = tempfile::tempdir().unwrap();
    let fx = Fixture::new(tmp.path(), &[(GSON, GSON_UUID)]);
    std::fs::remove_file(fx.proj().join(".socket/manifest.json")).unwrap();
    let hosted = write_hosted_pin(&fx.proj(), GSON_UUID);
    drop_evidence(&fx.proj());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let server = rt.block_on(MockServer::start());
    let view = serde_json::json!({
        "uuid": GSON_UUID, "purl": GSON.purl(), "publishedAt": "2024-01-01T00:00:00Z",
        "files": { MEMBER: {
            "beforeHash": git_sha256(b"NOTICE gson\n"),
            "afterHash": git_sha256(b"NOTICE gson\nPATCHED\n"),
        } },
        "vulnerabilities": {}, "description": "x", "license": "MIT", "tier": "free",
    });
    rt.block_on(
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/test-org/patches/view/{GSON_UUID}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view))
            .mount(&server),
    );
    let uri = server.uri();
    let (exit, env) = fx.run(&[
        "vendor",
        "--api-url",
        &uri,
        "--org",
        "test-org",
        "--api-token",
        "fake",
    ]);
    assert_eq!(exit, Some(1), "{env}");
    assert_eq!(env["error"]["code"], "eject_refused", "{env}");
    assert!(
        events(&env).contains(&(
            GSON.purl(),
            "failed".to_string(),
            "vendor_sbt_no_resolution_evidence".to_string()
        )),
        "{env}"
    );
    assert_eq!(std::fs::read(fx.proj().join(HOSTED_FILE)).unwrap(), hosted);
    assert!(!fx.proj().join(VENDORED_FILE).exists());
}
