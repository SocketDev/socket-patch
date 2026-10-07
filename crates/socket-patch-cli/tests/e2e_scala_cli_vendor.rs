//! Vendored scala-cli directory builds (`docs/design/sbt-support.md`,
//! "scala-cli vendored"): the owned root `socket-patch.scala`, the guard
//! inside `.socket/vendor/coursier/` and the same-GAV Coursier tree.
//!
//! Two groups:
//!
//! * **Hermetic** (default): a synthetic scala-cli project with the Bloop
//!   evidence scala-cli 1.17.1 writes (`.scala-build/.bloop/<p>.json`) and a
//!   fake local Maven repository as the installed copy. They pin the owned
//!   bytes, the ledger round trip (vendor, re-run, `--check`, two patches
//!   reverted in either order, byte-exact), the gate's run-level skips and
//!   refusals, and a forged ledger.
//! * **Real tool** (`#[ignore]`, `scala_cli_vendor_*`): the real scala-cli
//!   resolves `org.apache.commons:commons-text:1.10.0`, the CLI vendors a
//!   marker patch of its `pom.properties` (a code-only edit is stale until
//!   compiled, then current again), and the build then sees it from
//!   the project directory and from `/`, in `package --assembly`, and in a
//!   fresh clone whose `.gitignore` drops `*.jar`; deleting the tree fails
//!   the build (`File not found`), and revert restores every byte. The
//!   installed copy vendoring reads is the Coursier-cached jar copied into
//!   the isolated local Maven repository. Env:
//!   `SOCKET_PATCH_SCALA_CLI_E2E_BIN` (default `scala-cli` on `PATH`),
//!   `SOCKET_PATCH_SCALA_CLI_E2E_REQUIRED` (no SKIP), and
//!   `SOCKET_PATCH_SCALA_CLI_E2E_CACHE` (a shared Coursier cache; default
//!   under `TMPDIR`). Network to Maven Central. Run in the sbt docker image
//!   (`tests/docker/Dockerfile.sbt`) or any host with a JDK 17 and git.

#![cfg_attr(windows, allow(dead_code, unused_imports))]

#[path = "common/hermetic.rs"]
mod hermetic_spawn;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

#[path = "sbt_common/mod.rs"]
mod sbt_common;

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use sbt_common::{write_coursier_artifact, Gav, SbtHome};

const FOO_UUID: &str = "1d3c1fd2-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const BAR_UUID: &str = "9a8b7c6d-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
const MEMBER: &str = "META-INF/NOTICE.txt";
const CENTRAL: &str = "repo1.maven.org/maven2";
const ROOT_FILE: &str = "socket-patch.scala";
const GUARD: &str = ".socket/vendor/coursier/socket-patch.scala";
const ROOT_BYTES: &str =
    "// managed by socket-patch\n//> using file .socket/vendor/coursier/socket-patch.scala\n";
const GUARD_BYTES: &str = "// managed by socket-patch\n//> using repository file://${.}\n";
const INDEX: &str = ".socket/vendor/coursier-index.tsv";

fn git_sha256(bytes: &[u8]) -> String {
    socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(bytes)
}

fn purl(name: &str) -> String {
    format!("pkg:maven/org.example/{name}@1.0")
}

fn jar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zw = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in entries {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap().into_inner()
}

fn write(path: &Path, bytes: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn set_mtime(path: &Path, t: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

/// The manifest record + after-hash blob `get` saves for a patch of
/// `member` (so `vendor --offline` needs no network).
fn manifest_record(
    proj: &Path,
    uuid: &str,
    before: &[u8],
    after: &[u8],
    member: &str,
) -> serde_json::Value {
    write(&proj.join(".socket/blobs").join(git_sha256(after)), after);
    serde_json::json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { member: {
            "beforeHash": git_sha256(before),
            "afterHash": git_sha256(after),
        } },
        "vulnerabilities": { "GHSA-xxxx-yyyy-zzzz": {
            "cves": ["CVE-2026-0001"], "summary": "s", "severity": "high", "description": "d"
        } },
        "description": "scala-cli vendored fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// The Bloop project file scala-cli 1.17.1 writes (only the fields read).
fn bloop_json(
    workspace: &Path,
    sources: &[PathBuf],
    modules: &[(String, String, String, PathBuf)],
) -> String {
    let mods: Vec<serde_json::Value> = modules
        .iter()
        .map(|(g, a, v, path)| {
            serde_json::json!({ "organization": g, "name": a, "version": v,
                "artifacts": [{ "name": a, "path": path }] })
        })
        .collect();
    serde_json::json!({ "version": "1.4.0", "project": {
        "name": "proj_0123456789", "directory": workspace.join(".scala-build"),
        "workspaceDir": workspace, "sources": sources, "dependencies": [], "classpath": [],
        "resolution": { "modules": mods }, "tags": ["library"],
    } })
    .to_string()
}

/// `root/{sbt-home,proj}`: a scala-cli project (`project.scala`,
/// `main.scala`) depending on every `(name, uuid)` package, each installed
/// in the isolated Coursier cache, with Bloop evidence resolving
/// them at `evidence_version` (default 1.0) and newer than every source.
fn fixture(root: &Path, packages: &[(&str, &str)], evidence_version: Option<&str>) -> SbtHome {
    let home = SbtHome::new(root);
    let proj = root.join("proj");
    let mut patches = serde_json::Map::new();
    let mut modules = Vec::new();
    for (name, uuid) in packages {
        // Installed where scala-cli leaves it: the Coursier cache the agent
        // crawler finds through `COURSIER_CACHE`.
        let before = format!("NOTICE {name}\n").into_bytes();
        let after = [before.as_slice(), b"PATCHED\n"].concat();
        let gav = Gav {
            group: "org.example",
            artifact: name,
            version: "1.0",
        };
        let dir = write_coursier_artifact(
            &home.coursier_cache(),
            CENTRAL,
            gav,
            &jar(&[
                ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
                (MEMBER, &before),
            ]),
        );
        let jar_path = dir.join(format!("{name}-1.0.jar"));
        patches.insert(
            purl(name),
            manifest_record(&proj, uuid, &before, &after, MEMBER),
        );
        modules.push((
            "org.example".to_string(),
            name.to_string(),
            evidence_version.unwrap_or("1.0").to_string(),
            jar_path,
        ));
    }
    write(
        &proj.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
    );
    let deps: String = packages
        .iter()
        .map(|(name, _)| format!("//> using dep org.example:{name}:1.0\n"))
        .collect();
    write(
        &proj.join("project.scala"),
        format!("//> using scala 3.3.6\n{deps}"),
    );
    write(
        &proj.join("main.scala"),
        "@main def m() = println(\"hi\")\n",
    );
    let ws = proj.canonicalize().unwrap();
    let sources = vec![ws.join("main.scala"), ws.join("project.scala")];
    let ev = ws.join(".scala-build/.bloop/proj_0123456789.json");
    write(&ev, bloop_json(&ws, &sources, &modules));
    let past = SystemTime::now() - Duration::from_secs(3600);
    for s in &sources {
        set_mtime(s, past);
    }
    set_mtime(&ev, past + Duration::from_secs(60));
    home
}

/// `socket-patch <args> --json --cwd <root>/proj` in `home`'s isolated env;
/// `(exit, envelope)`.
fn socket(root: &Path, home: &SbtHome, args: &[&str]) -> (Option<i32>, serde_json::Value) {
    socket_in_cache(root, home, args, &home.coursier_cache())
}

/// [`socket`] with `COURSIER_CACHE` at `cache` (the real-tool test reads
/// the cache scala-cli itself resolved into); the download fixture serves
/// its Central repository root.
fn socket_in_cache(
    root: &Path,
    home: &SbtHome,
    args: &[&str],
    cache: &Path,
) -> (Option<i32>, serde_json::Value) {
    let mut cmd = hermetic_spawn::binary_command();
    for (k, _) in std::env::vars_os() {
        let k = k.to_string_lossy().into_owned();
        if k.starts_with("COURSIER_") {
            cmd.env_remove(&k);
        }
    }
    for (k, v) in home.isolated_env() {
        cmd.env(k, v);
    }
    cmd.env("COURSIER_CACHE", cache);
    let proj = root.join("proj");
    let repo = fixture_mirror(root, &cache.join("https").join(CENTRAL));
    let _fixture = prebuilt_common::prepare_command(
        &mut cmd,
        &proj,
        args,
        &[("MAVEN_REPO_LOCAL", repo.to_str().unwrap())],
    );
    let out = cmd
        .args(["--json", "--cwd", proj.to_str().unwrap()])
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

/// The download fixture's Maven2 repository: only the version directories
/// of the manifest's Maven purls, copied from `central`. The fixture serves
/// (and holds in memory) every file of its repository, and a shared cache's
/// Central root (the image's, warmed for several tools) would not fit.
fn fixture_mirror(root: &Path, central: &Path) -> PathBuf {
    let mirror = root.join("fixture-mirror");
    let manifest = std::fs::read(root.join("proj/.socket/manifest.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let purls: Vec<String> = manifest
        .as_ref()
        .and_then(|m| m["patches"].as_object())
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default();
    for purl in purls {
        let Some(gav) = purl.strip_prefix("pkg:maven/") else {
            continue;
        };
        let gav = gav.split('?').next().unwrap_or_default();
        let Some((ga, v)) = gav.rsplit_once('@') else {
            continue;
        };
        let Some((g, a)) = ga.split_once('/') else {
            continue;
        };
        let rel = Path::new(&g.replace('.', "/")).join(a).join(v);
        let Ok(entries) = std::fs::read_dir(central.join(&rel)) else {
            continue;
        };
        std::fs::create_dir_all(mirror.join(&rel)).unwrap();
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_file()) {
                std::fs::copy(entry.path(), mirror.join(&rel).join(entry.file_name())).unwrap();
            }
        }
    }
    std::fs::create_dir_all(&mirror).unwrap();
    mirror
}

fn ok(root: &Path, home: &SbtHome, args: &[&str]) -> serde_json::Value {
    let (code, env) = socket(root, home, args);
    assert_eq!(code, Some(0), "{args:?}: {env}");
    let failed = env["summary"].get("failed").unwrap_or(&env["failed"]);
    assert_eq!(failed, 0, "{args:?}: {env}");
    env
}

/// Every `code` / `errorCode` string anywhere in the envelope.
fn codes(env: &serde_json::Value) -> Vec<String> {
    fn walk(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, v) in m {
                    if k == "code" || k == "errorCode" {
                        if let Some(s) = v.as_str() {
                            out.push(s.to_string());
                        }
                    }
                    walk(v, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(env, &mut out);
    out
}

/// Every file under `proj`, minus the manifest, blobs and `.scala-build`
/// (the inputs the tests stage).
fn snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if [
                ".socket/manifest.json",
                ".socket/blobs",
                ".scala-build",
                ".git",
            ]
            .contains(&rel.as_str())
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
    let proj = root.join("proj");
    let mut out = BTreeMap::new();
    walk(&proj, &proj, &mut out);
    out
}

#[cfg(not(windows))]
mod hermetic {
    use super::*;

    #[test]
    fn vendor_wires_owned_files_and_reverts_byte_exact() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let home = fixture(root, &[("foo", FOO_UUID)], None);
        let pristine = snapshot(root);
        let env = ok(root, &home, &["vendor"]);
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        assert!(
            codes(&env).contains(&"vendor_scala_cli_directives_split".to_string()),
            "{env}"
        );
        let proj = root.join("proj");
        assert_eq!(
            std::fs::read_to_string(proj.join(ROOT_FILE)).unwrap(),
            ROOT_BYTES
        );
        assert_eq!(
            std::fs::read_to_string(proj.join(GUARD)).unwrap(),
            GUARD_BYTES
        );
        assert_eq!(
            std::fs::read_to_string(proj.join(".socket/vendor/coursier/.gitignore")).unwrap(),
            "!*\n"
        );
        let tree = proj.join(".socket/vendor/coursier/org/example/foo/1.0");
        let vendored = std::fs::read(tree.join("foo-1.0.jar")).unwrap();
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(vendored)).unwrap();
        let mut notice = String::new();
        std::io::Read::read_to_string(&mut zip.by_name(MEMBER).unwrap(), &mut notice).unwrap();
        assert_eq!(notice, "NOTICE foo\nPATCHED\n");
        for name in [
            "foo-1.0.pom",
            "foo-1.0.jar.sha1",
            "foo-1.0.pom.sha1",
            "socket-patch.vendor.json",
        ] {
            assert!(tree.join(name).is_file(), "{name}");
        }
        let index = std::fs::read_to_string(proj.join(INDEX)).unwrap();
        assert!(
            index.starts_with("#socket-patch-coursier-index 1\n"),
            "{index}"
        );
        assert_eq!(index.matches(FOO_UUID).count(), 2, "{index}");
        // The user's files are never edited.
        for f in ["project.scala", "main.scala"] {
            assert_eq!(snapshot(root)[f], pristine[f]);
        }
        ok(root, &home, &["vendor", "--check"]);
        ok(root, &home, &["vendor", "--revert"]);
        assert_eq!(snapshot(root), pristine);
    }

    #[test]
    fn rerun_is_a_noop_and_check_detects_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let home = fixture(root, &[("foo", FOO_UUID)], None);
        ok(root, &home, &["vendor"]);
        let wired = snapshot(root);
        let env = ok(root, &home, &["vendor"]);
        assert_eq!(env["summary"]["applied"], 0, "{env}");
        assert_eq!(snapshot(root), wired);
        let proj = root.join("proj");
        let jar = proj.join(".socket/vendor/coursier/org/example/foo/1.0/foo-1.0.jar");
        let original = std::fs::read(&jar).unwrap();
        std::fs::write(&jar, b"tampered").unwrap();
        let (code, env) = socket(root, &home, &["vendor", "--check"]);
        assert_eq!(code, Some(1), "{env}");
        std::fs::write(&jar, original).unwrap();
        ok(root, &home, &["vendor", "--check"]);
        std::fs::remove_file(proj.join(GUARD)).unwrap();
        let (code, env) = socket(root, &home, &["vendor", "--check"]);
        assert_eq!(code, Some(1), "a missing guard is drift: {env}");
    }

    #[test]
    fn two_patches_roll_back_one_at_a_time_to_pristine() {
        for first in ["foo", "bar"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let home = fixture(root, &[("foo", FOO_UUID), ("bar", BAR_UUID)], None);
            let pristine = snapshot(root);
            let env = ok(root, &home, &["vendor"]);
            assert_eq!(env["summary"]["applied"], 2, "{env}");
            ok(root, &home, &["rollback", &purl(first)]);
            let proj = root.join("proj");
            let other = if first == "foo" { "bar" } else { "foo" };
            let index = std::fs::read_to_string(proj.join(INDEX)).unwrap();
            assert!(
                index.contains(&format!("org.example:{other}:1.0")),
                "{index}"
            );
            assert!(
                !index.contains(&format!("org.example:{first}:1.0")),
                "{index}"
            );
            assert!(proj.join(ROOT_FILE).is_file() && proj.join(GUARD).is_file());
            ok(root, &home, &["vendor", "--check"]);
            ok(root, &home, &["vendor", "--revert"]);
            assert_eq!(snapshot(root), pristine, "first out: {first}");
        }
    }

    #[test]
    fn missing_or_stale_evidence_is_one_warning_and_exit_zero() {
        for case in ["missing", "stale", "server-false"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let home = fixture(root, &[("foo", FOO_UUID)], None);
            let proj = root.join("proj");
            match case {
                "missing" => std::fs::remove_dir_all(proj.join(".scala-build")).unwrap(),
                // A `--server=false` build leaves `.scala-build` without `.bloop`.
                "server-false" => {
                    std::fs::remove_dir_all(proj.join(".scala-build/.bloop")).unwrap()
                }
                _ => set_mtime(&proj.join("main.scala"), SystemTime::now()),
            }
            let before = snapshot(root);
            let env = ok(root, &home, &["vendor"]);
            let want = if case == "stale" {
                "vendor_scala_cli_resolution_stale"
            } else {
                "vendor_scala_cli_resolution_missing"
            };
            assert!(codes(&env).contains(&want.to_string()), "{case}: {env}");
            assert_eq!(
                env["summary"]["applied"], 0,
                "{case}: a skip is not applied: {env}"
            );
            assert_eq!(snapshot(root), before, "{case}: nothing is written");
        }
    }

    /// Once vendored, the committed tree keeps serving the patch: a fresh
    /// clone (`.scala-build` is gitignored) or an uncompiled edit re-plans
    /// it in sync, without a "not vendored" warning.
    #[test]
    fn a_vendored_gav_reruns_in_sync_without_fresh_evidence() {
        for case in ["missing", "stale"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let home = fixture(root, &[("foo", FOO_UUID)], None);
            let proj = root.join("proj");
            let env = ok(root, &home, &["vendor"]);
            assert_eq!(env["summary"]["applied"], 1, "{case}: {env}");
            match case {
                "missing" => std::fs::remove_dir_all(proj.join(".scala-build")).unwrap(),
                _ => set_mtime(
                    &proj.join("main.scala"),
                    SystemTime::now() + Duration::from_secs(3600),
                ),
            }
            let env = ok(root, &home, &["vendor"]);
            assert_eq!(env["summary"]["applied"], 0, "{case}: {env}");
            for code in [
                "vendor_scala_cli_resolution_missing",
                "vendor_scala_cli_resolution_stale",
            ] {
                assert!(!codes(&env).contains(&code.to_string()), "{case}: {env}");
            }
            ok(root, &home, &["vendor", "--check"]);
        }
    }

    #[test]
    fn gate_refusals_write_nothing() {
        for case in ["conflict", "directive", "modified"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let version = (case == "conflict").then_some("1.1");
            let home = fixture(root, &[("foo", FOO_UUID)], version);
            let proj = root.join("proj");
            match case {
                "directive" => {
                    let p = proj.join("project.scala");
                    let text = std::fs::read_to_string(&p).unwrap();
                    std::fs::write(&p, format!("//> using repository central\n{text}")).unwrap();
                    set_mtime(&p, SystemTime::now() - Duration::from_secs(3600));
                }
                "modified" => write(&proj.join(ROOT_FILE), "object Main\n"),
                _ => {}
            }
            let before = snapshot(root);
            let (code, env) = socket(root, &home, &["vendor"]);
            assert_eq!(code, Some(1), "{case}: {env}");
            let want = match case {
                "conflict" => "vendor_scala_cli_version_conflict",
                "directive" => "vendor_scala_cli_repository_shadowed",
                _ => "vendor_scala_cli_owned_file_modified",
            };
            assert!(codes(&env).contains(&want.to_string()), "{case}: {env}");
            assert_eq!(snapshot(root), before, "{case}: nothing is written");
        }
    }

    /// A forged ledger entry naming a user file as a tree file is refused
    /// before any write.
    #[test]
    fn forged_ledger_entries_touch_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let home = fixture(root, &[("foo", FOO_UUID)], None);
        ok(root, &home, &["vendor"]);
        let proj = root.join("proj");
        let state_path = proj.join(".socket/vendor/state.json");
        let mut state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        let main = std::fs::read(proj.join("main.scala")).unwrap();
        let sha = {
            use sha2::{Digest as _, Sha256};
            hex::encode(Sha256::digest(&main))
        };
        let entry = state["entries"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        entry["wiring"].as_array_mut().unwrap().push(
            serde_json::json!({ "file": "main.scala", "kind": "jvm_vendor_tree",
                "action": "added", "new": sha }),
        );
        std::fs::write(&state_path, state.to_string()).unwrap();
        let (code, env) = socket(root, &home, &["vendor", "--revert"]);
        assert_ne!(code, Some(0), "{env}");
        assert_eq!(std::fs::read(proj.join("main.scala")).unwrap(), main);
        assert!(proj.join(ROOT_FILE).is_file(), "nothing reverted");
    }
}

#[cfg(windows)]
#[test]
fn windows_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = fixture(root, &[("foo", FOO_UUID)], None);
    let before = snapshot(root);
    let (code, env) = socket(root, &home, &["vendor"]);
    assert_eq!(code, Some(1), "{env}");
    assert!(
        codes(&env).contains(&"vendor_scala_cli_windows_unsupported".to_string()),
        "{env}"
    );
    assert_eq!(snapshot(root), before);
}

// ── real scala-cli ─────────────────────────────────────────────────────────

mod real_tool {
    use super::*;

    const BIN_ENV: &str = "SOCKET_PATCH_SCALA_CLI_E2E_BIN";
    const REQUIRED_ENV: &str = "SOCKET_PATCH_SCALA_CLI_E2E_REQUIRED";
    const CACHE_ENV: &str = "SOCKET_PATCH_SCALA_CLI_E2E_CACHE";
    const PATCH_UUID: &str = "4c0f1a2b-7b4e-4c1a-9f0e-2a3b4c5d6e7f";
    const GROUP_PATH: &str = "org/apache/commons";
    const ARTIFACT: &str = "commons-text";
    const VERSION: &str = "1.10.0";
    const MARKER: &str = "socket-patch-e2e-marker=true";
    /// A resource only commons-text ships, so neither the classpath order
    /// nor an assembly merge can hide it.
    const PROPS: &str = "META-INF/maven/org.apache.commons/commons-text/pom.properties";

    /// The program: whether commons-text's `pom.properties` carries the
    /// marker.
    const MAIN_JAVA: &str = "public class Main {\n  public static void main(String[] a) throws Exception {\n    try (var in = Main.class.getResourceAsStream(\"/META-INF/maven/org.apache.commons/commons-text/pom.properties\")) {\n      String s = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);\n      System.out.println(\"PATCHED=\" + s.contains(\"socket-patch-e2e-marker\"));\n    }\n  }\n}\n";

    fn scala_cli() -> Option<String> {
        let bin = std::env::var(BIN_ENV).unwrap_or_else(|_| "scala-cli".into());
        let found = Command::new(&bin)
            .arg("version")
            .output()
            .is_ok_and(|o| o.status.success());
        if !found {
            assert!(
                std::env::var_os(REQUIRED_ENV).is_none(),
                "{REQUIRED_ENV} is set but `{bin} version` failed"
            );
            eprintln!("SKIP: scala-cli not found (set {BIN_ENV})");
            return None;
        }
        Some(bin)
    }

    fn cache() -> PathBuf {
        std::env::var_os(CACHE_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("socket-patch-scala-cli-e2e-cache"))
    }

    /// `scala-cli <args>` in `cwd`; `(success, stdout+stderr)`.
    fn run(bin: &str, cwd: &Path, args: &[&str]) -> (bool, String) {
        let mut cmd = Command::new(bin);
        for (k, _) in std::env::vars_os() {
            let k = k.to_string_lossy().into_owned();
            if k.starts_with("COURSIER_") || k == "JAVA_TOOL_OPTIONS" {
                cmd.env_remove(&k);
            }
        }
        let out = cmd
            .args(args)
            .current_dir(cwd)
            .env("COURSIER_CACHE", cache())
            .output()
            .expect("run scala-cli");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    }

    fn patched(bin: &str, cwd: &Path, input: &str) -> bool {
        let (ok, out) = run(bin, cwd, &["run", input]);
        assert!(ok, "scala-cli run {input}: {out}");
        if out.contains("PATCHED=true") {
            return true;
        }
        assert!(out.contains("PATCHED=false"), "{out}");
        false
    }

    fn member(jar: &[u8], name: &str) -> Vec<u8> {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(jar.to_vec())).unwrap();
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut zip.by_name(name).unwrap(), &mut out).unwrap();
        out
    }

    /// `socket-patch <args>` reading scala-cli's own Coursier cache.
    fn ok(root: &Path, home: &SbtHome, args: &[&str]) -> serde_json::Value {
        let (code, env) = socket_in_cache(root, home, args, &cache());
        assert_eq!(code, Some(0), "{args:?}: {env}");
        let failed = env["summary"].get("failed").unwrap_or(&env["failed"]);
        assert_eq!(failed, 0, "{args:?}: {env}");
        env
    }

    /// A built project depending on commons-text (cached by scala-cli in
    /// [`cache`], where vendoring finds the installed copy), and the marker
    /// patch of [`PROPS`] staged.
    fn project(bin: &str, root: &Path) -> SbtHome {
        let home = SbtHome::new(root);
        let proj = root.join("proj");
        write(
            &proj.join("project.scala"),
            format!("//> using dep org.apache.commons:{ARTIFACT}:{VERSION}\n"),
        );
        write(&proj.join("Main.java"), MAIN_JAVA);
        let (ok, out) = run(bin, &proj, &["compile", "."]);
        assert!(ok, "scala-cli compile: {out}");
        assert!(
            proj.join(".scala-build/.bloop").is_dir(),
            "no Bloop evidence"
        );
        // The installed copy vendoring reads is the one scala-cli cached:
        // the agent crawler finds it through `COURSIER_CACHE` ([`ok`]).
        let stem = format!("{ARTIFACT}-{VERSION}");
        let cached = walk_find(&cache(), &format!("{stem}.jar")).expect("jar in the cache");
        assert!(
            cached.starts_with(cache().join("https").join(CENTRAL)),
            "{}",
            cached.display()
        );
        let before = member(&std::fs::read(&cached).unwrap(), PROPS);
        let after = [before.as_slice(), format!("{MARKER}\n").as_bytes()].concat();
        let record = manifest_record(&proj, PATCH_UUID, &before, &after, PROPS);
        write(
            &proj.join(".socket/manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "patches": {
                format!("pkg:maven/org.apache.commons/{ARTIFACT}@{VERSION}"): record } }))
            .unwrap(),
        );
        home
    }

    fn walk_find(dir: &Path, name: &str) -> Option<PathBuf> {
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            let p = e.path();
            if p.is_dir() {
                if let Some(found) = walk_find(&p, name) {
                    return Some(found);
                }
            } else if p.file_name().is_some_and(|n| n == name)
                && p.to_string_lossy().contains("maven2")
            {
                return Some(p);
            }
        }
        None
    }

    fn git(cwd: &Path, args: &[&str]) {
        let out = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    #[ignore = "real scala-cli + network; see the module doc"]
    fn scala_cli_vendor_patches_directory_builds_and_reverts() {
        let Some(bin) = scala_cli() else { return };
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = project(&bin, &root);
        let proj = root.join("proj");
        assert!(!patched(&bin, &proj, "."), "baseline");
        let pristine = snapshot(&root);
        let env = ok(&root, &home, &["vendor", "--offline"]);
        assert_eq!(env["summary"]["applied"], 1, "{env}");
        assert!(patched(&bin, &proj, "."), "from the project directory");
        assert!(
            patched(&bin, Path::new("/"), proj.to_str().unwrap()),
            "from /"
        );
        // An in-sync re-run over the post-wiring evidence is a no-op.
        let env = ok(&root, &home, &["vendor", "--offline"]);
        assert_eq!(env["summary"]["applied"], 0, "{env}");
        ok(&root, &home, &["vendor", "--check"]);
        // A code-only edit leaves the Bloop project file alone; once it is
        // compiled the evidence is current again (dated by the compile).
        std::thread::sleep(Duration::from_millis(1100));
        write(&proj.join("Main.java"), format!("{MAIN_JAVA}// edited\n"));
        let stale = "vendor_scala_cli_resolution_stale".to_string();
        // The vendored GAV keeps being served: re-planned in sync, no
        // "not vendored" skip.
        let env = ok(&root, &home, &["vendor", "--offline"]);
        assert!(!codes(&env).contains(&stale), "edited, not compiled: {env}");
        assert_eq!(env["summary"]["applied"], 0, "{env}");
        let (built, out) = run(&bin, &proj, &["compile", "--test", "."]);
        assert!(built, "{out}");
        let env = ok(&root, &home, &["vendor", "--offline"]);
        assert!(
            !codes(&env).contains(&stale),
            "edited, then compiled: {env}"
        );
        assert_eq!(env["summary"]["applied"], 0, "{env}");
        write(&proj.join("Main.java"), MAIN_JAVA);
        // package --assembly carries the patched bytes.
        let assembly = root.join("app.jar");
        let (built, out) = run(
            &bin,
            &proj,
            &[
                "--power",
                "package",
                ".",
                "--assembly",
                "-f",
                "-o",
                assembly.to_str().unwrap(),
            ],
        );
        assert!(built, "{out}");
        let bytes = std::fs::read(&assembly).unwrap();
        // The assembly is a launcher script with the jar appended.
        let start = bytes
            .windows(4)
            .position(|w| w == b"PK\x03\x04")
            .unwrap_or(0);
        let props = member(&bytes[start..], PROPS);
        assert!(
            String::from_utf8_lossy(&props).contains(MARKER),
            "assembly {PROPS}"
        );
        // Deleting the tree deletes the guard: the build fails closed.
        let tree = proj.join(".socket/vendor/coursier");
        let aside = root.join("tree-aside");
        std::fs::rename(&tree, &aside).unwrap();
        let (built, out) = run(&bin, &proj, &["compile", "."]);
        assert!(!built && out.contains("File not found"), "{out}");
        std::fs::rename(&aside, &tree).unwrap();
        // A fresh clone whose .gitignore drops *.jar still carries the jar.
        write(&proj.join(".gitignore"), "*.jar\n.scala-build/\n.bsp/\n");
        git(&proj, &["init", "-q"]);
        git(&proj, &["add", "-A"]);
        git(
            &proj,
            &[
                "-c",
                "user.email=a@b",
                "-c",
                "user.name=a",
                "commit",
                "-qm",
                "x",
            ],
        );
        let clone = root.join("clone");
        let (from, to) = (proj.to_str().unwrap(), clone.to_str().unwrap());
        git(&root, &["clone", "-q", from, to]);
        let vendored = format!(
            ".socket/vendor/coursier/{GROUP_PATH}/{ARTIFACT}/{VERSION}/{ARTIFACT}-{VERSION}.jar"
        );
        assert!(clone.join(&vendored).is_file(), "{vendored}");
        assert!(patched(&bin, &clone, "."), "fresh clone");
        std::fs::remove_file(proj.join(".gitignore")).unwrap();
        // Revert restores every byte, and the build is upstream again.
        ok(&root, &home, &["vendor", "--revert"]);
        assert_eq!(snapshot(&root), pristine);
        assert!(!patched(&bin, &proj, "."), "after revert");
    }
}
