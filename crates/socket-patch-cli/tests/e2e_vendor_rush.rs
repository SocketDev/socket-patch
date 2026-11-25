//! Real-Rush capstone for vendored mode in a Rush monorepo — the proof that
//! what `socket-patch vendor` commits is what Rush itself accepts.
//!
//! Drives the REAL `@microsoft/rush` (fetched with `npm x`), which downloads
//! and runs the pnpm that `rush.json` pins:
//!   1. `rush update` on a three-project repo: `util` (folder depth 2) and
//!      `top` (depth 1) depend on minimist@0.0.8 directly, `app` reaches it
//!      through mkdirp@0.5.1.
//!   2. Hand-stage a `.socket/` manifest + blob from the ACTUAL installed
//!      bytes (a marker comment prepended to `index.js`).
//!   3. `socket-patch vendor --json --offline` — assert the wiring: the lock
//!      entry rekeyed to the tarball relative to `common/temp`, a
//!      parent-scoped `globalOverrides` entry in `pnpm-config.json` (its
//!      comments kept), and each directly-depending project's
//!      `package.json` spec moved to a `file:` path relative to that
//!      project.
//!   4. **Differential**: `rush update` runs again and must change none of
//!      those files. Rush re-resolves the lock from the config and
//!      manifests, so this holds only when the lock vendoring wrote is the
//!      one Rush writes.
//!   5. **Fresh-checkout proof**: copy only the committable files to a new
//!      directory and run `rush install`. Rush's own stale-lock check must
//!      pass (it compares every project's `package.json` with the lock —
//!      the reason direct dependents get a `package.json` edit), the patched
//!      bytes must be what lands for the two direct dependents and for
//!      mkdirp's copy, and pnpm must leave the lock as committed.
//!   6. `vendor --check` verifies the artifact and wiring offline, and
//!      `rush update --full` (a from-scratch resolve) keeps the wiring.
//!   7. **Revert proof**: `vendor --revert` restores every file byte for
//!      byte and removes the artifact, and `rush install` lands the
//!      registry bytes again.
//!
//! Two legs: pnpm 10 (Rush hands pnpm its overrides through
//! `common/temp/package.json`) and pnpm 11 (through a generated
//! `pnpm-workspace.yaml`; needs Node >= 22.13).
//!
//! `#[ignore]`d: network- and wall-bound (Rush, pnpm and four packages come
//! from the npm registry). The e2e CI legs run it on all three OSes with
//! `SOCKET_PATCH_PNPM_E2E_REQUIRED` set, where a missing toolchain or a
//! failed fixture install is a failure, never a skip.

#[path = "common/mod.rs"]
mod common;
use common::{binary, cache_env, git_sha256, hermetic};

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;
use std::process::{Output, Stdio};

const UUID: &str = "7c1d2e3f-4a5b-4c6d-8e7f-0a1b2c3d4e5f";
const MARKER: &str = "/* SOCKET-PATCHED */\n";
const PURL: &str = "pkg:npm/minimist@0.0.8";
const RUSH_VERSION: &str = "5.182.1";
const LOCK: &str = "common/config/rush/pnpm-lock.yaml";
const PNPM_CONFIG: &str = "common/config/rush/pnpm-config.json";
/// The files vendoring may edit, and nothing else of the repository.
const WIRED: [&str; 5] = [
    LOCK,
    PNPM_CONFIG,
    "apps/app/package.json",
    "libs/util/package.json",
    "top/package.json",
];

// ── self-contained helpers ────────────────────────────────────────────

/// Set by the CI legs that run this suite: a missing toolchain or a failed
/// fixture install is then a failure, never a skip. Empty (the value on
/// other legs) = unset.
fn pnpm_required() -> bool {
    std::env::var_os("SOCKET_PATCH_PNPM_E2E_REQUIRED").is_some_and(|v| !v.is_empty())
}

/// Print the SKIP line, or panic under [`pnpm_required`].
fn skip(msg: &str) {
    assert!(!pnpm_required(), "required toolchain unavailable: {msg}");
    println!("SKIP e2e_vendor_rush: {msg}");
}

fn has_command(cmd: &str) -> bool {
    let mut probe = hermetic::tool_command(cmd);
    probe.arg("--version");
    cache_env::isolate(&mut probe);
    probe
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run real Rush in `root`. Rush keeps the pnpm it downloads under
/// `global`, and rejects any `RUSH_`-prefixed variable it does not know.
fn rush(root: &Path, global: &Path, args: &[&str]) -> Output {
    let package = format!("@microsoft/rush@{RUSH_VERSION}");
    let mut cmd = hermetic::tool_command("npm");
    cmd.args(["x", "-y", package.as_str(), "--"]).args(args);
    hermetic::start_in(&mut cmd, root);
    hermetic::scrub_socket_vars(&mut cmd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv, hermetic::Extra::Pnpm]);
    cache_env::isolate(&mut cmd);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("RUSH_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("RUSH_GLOBAL_FOLDER", global);
    cmd.output().expect("failed to run rush via npm x")
}

/// Rush reports its errors on stdout.
fn shown(out: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn run_socket(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic::command(&binary());
    cmd.current_dir(cwd);
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv, hermetic::Extra::Pnpm]);
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, &[]);
    let out = cmd.output().expect("failed to run socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn read(root: &Path, rel: &str) -> String {
    std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// A minimal real Rush repository on `pnpm_version`.
fn write_repo(root: &Path, pnpm_version: &str) {
    write(
        root,
        "rush.json",
        &format!(
            r#"{{
  "rushVersion": "{RUSH_VERSION}",
  "pnpmVersion": "{pnpm_version}",
  "projectFolderMinDepth": 1,
  "projectFolderMaxDepth": 2,
  "projects": [
    {{ "packageName": "app", "projectFolder": "apps/app" }},
    {{ "packageName": "util", "projectFolder": "libs/util" }},
    {{ "packageName": "top", "projectFolder": "top" }}
  ]
}}
"#
        ),
    );
    // JSON with comments, as `rush init` writes it.
    write(
        root,
        PNPM_CONFIG,
        "/**\n * Rush pnpm settings.\n */\n{\n  \"useWorkspaces\": true,\n\n  /**\n   * Overrides for every project.\n   */\n  \"globalOverrides\": {\n    // \"example\": \"^1.0.0\"\n  }\n}\n",
    );
    write(
        root,
        "apps/app/package.json",
        "{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n    \"mkdirp\": \"0.5.1\",\n    \"util\": \"workspace:*\"\n  }\n}\n",
    );
    write(
        root,
        "libs/util/package.json",
        "{\n  \"name\": \"util\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n    \"minimist\": \"0.0.8\"\n  }\n}\n",
    );
    write(
        root,
        "top/package.json",
        "{\n  \"name\": \"top\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"devDependencies\": {\n    \"minimist\": \"0.0.8\"\n  }\n}\n",
    );
}

/// The manifest record and blob of a patch that prepends [`MARKER`] to
/// minimist's `index.js`.
fn stage_patch(root: &Path, before: &[u8], after: &[u8]) {
    let manifest = serde_json::json!({
        "patches": { PURL: {
            "uuid": UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": {
                "beforeHash": git_sha256(before),
                "afterHash": git_sha256(after),
            }},
            "vulnerabilities": { "GHSA-vend-rush-real": {
                "cves": ["CVE-2024-77777"],
                "summary": "capstone vuln",
                "severity": "high",
                "description": "d",
            }},
            "description": "capstone marker patch",
            "license": "MIT",
            "tier": "free",
        }}
    });
    write(
        root,
        ".socket/manifest.json",
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );
    let blob = root.join(".socket/blobs").join(git_sha256(after));
    std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
    std::fs::write(blob, after).unwrap();
}

fn wired_files(root: &Path) -> Vec<(&'static str, String)> {
    WIRED.iter().map(|rel| (*rel, read(root, rel))).collect()
}

/// What a commit of `from` carries, copied to `to`: everything but the
/// installs (`node_modules`), Rush's temp folder and its per-project state.
fn copy_committable(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let kind = entry.file_type().unwrap();
        let skipped = matches!(name.to_str(), Some("node_modules" | ".rush"))
            || entry.path().ends_with("common/temp");
        if skipped || kind.is_symlink() {
            continue;
        }
        let target = to.join(&name);
        if kind.is_dir() {
            copy_committable(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// The `index.js` a project's own `minimist` dependency resolves to.
fn direct_copy(root: &Path, project: &str) -> Vec<u8> {
    let path = root.join(project).join("node_modules/minimist/index.js");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `index.js` of the minimist that `app`'s mkdirp resolves: its sibling
/// in pnpm's virtual store.
fn transitive_copy(root: &Path) -> Vec<u8> {
    let mkdirp = std::fs::canonicalize(root.join("apps/app/node_modules/mkdirp"))
        .expect("app's mkdirp is installed");
    // Component by component: a canonical Windows path is verbatim, where
    // `/` is not a separator.
    let path = mkdirp.parent().unwrap().join("minimist").join("index.js");
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

// ── the capstone ──────────────────────────────────────────────────────

fn run_capstone(pnpm_version: &str) {
    if !has_command("npm") {
        return skip("npm unavailable");
    }
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path();
    let (root, fresh, global) = (
        base.join("repo"),
        base.join("fresh"),
        base.join("rush-global"),
    );
    write_repo(&root, pnpm_version);

    // 1. The baseline: Rush's own lock and install.
    let up = rush(&root, &global, &["update"]);
    if !up.status.success() {
        return skip(&format!("`rush update` failed (network?)\n{}", shown(&up)));
    }
    let pristine = direct_copy(&root, "libs/util");
    assert!(!pristine.starts_with(MARKER.as_bytes()));
    let patched = [MARKER.as_bytes(), pristine.as_slice()].concat();
    let baseline = wired_files(&root);

    // 2 + 3. Vendor.
    stage_patch(&root, &pristine, &patched);
    let (code, stdout, stderr) = run_socket(&root, &["vendor", "--json", "--offline"]);
    assert_eq!(
        code, 0,
        "vendor failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("vendor_rush_package_json_edited"),
        "the package.json edit must be announced:\n{stdout}"
    );
    let tgz = format!(".socket/vendor/npm/{UUID}/minimist-0.0.8.tgz");
    assert!(root.join(&tgz).is_file(), "the tarball is committed");

    let lock = read(&root, LOCK);
    assert!(
        lock.contains(&format!("\n  minimist@file:../../{tgz}:\n")),
        "the entry is rekeyed relative to common/temp:\n{lock}"
    );
    assert!(
        !lock.contains("\n  minimist@0.0.8:"),
        "no registry entry is left:\n{lock}"
    );
    assert!(
        lock.contains(&format!(
            "\noverrides:\n  mkdirp@0.5.1>minimist@0.0.8: file:../../{tgz}\n"
        )),
        "the transitive dependent gets a parent-scoped override:\n{lock}"
    );
    let config = read(&root, PNPM_CONFIG);
    assert!(
        config.contains(&format!(
            "\"mkdirp@0.5.1>minimist@0.0.8\": \"file:../../{tgz}\""
        )),
        "{config}"
    );
    for kept in [
        "/**\n * Rush pnpm settings.\n */",
        "// \"example\": \"^1.0.0\"",
    ] {
        assert!(config.contains(kept), "a comment was lost:\n{config}");
    }
    assert!(
        read(&root, "libs/util/package.json")
            .contains(&format!("\"minimist\": \"file:../../{tgz}\"")),
        "a depth-2 dependent's spec is relative to its folder"
    );
    assert!(
        read(&root, "top/package.json").contains(&format!("\"minimist\": \"file:../{tgz}\"")),
        "a depth-1 dependent's spec is relative to its folder"
    );
    assert_eq!(
        read(&root, "apps/app/package.json"),
        baseline[2].1,
        "a project that does not list the package is untouched"
    );
    let vendored = wired_files(&root);

    // 4. Differential: Rush resolves this same lock from the config and
    // manifests, so it has nothing to rewrite.
    let again = rush(&root, &global, &["update"]);
    assert!(
        again.status.success(),
        "`rush update` failed.\n{}",
        shown(&again)
    );
    assert_eq!(
        wired_files(&root),
        vendored,
        "`rush update` rewrote the vendored wiring"
    );

    // 5. A fresh checkout installs the patched bytes, and Rush's stale-lock
    // check accepts the commit.
    copy_committable(&root, &fresh);
    let install = rush(&fresh, &global, &["install"]);
    assert!(
        install.status.success(),
        "`rush install` must accept the vendored commit.\n{}",
        shown(&install)
    );
    for project in ["libs/util", "top"] {
        assert!(
            direct_copy(&fresh, project) == patched,
            "{project} must install the patched minimist"
        );
    }
    assert!(
        transitive_copy(&fresh) == patched,
        "mkdirp must resolve the patched minimist"
    );
    assert_eq!(
        read(&fresh, "common/temp/pnpm-lock.yaml"),
        read(&fresh, LOCK),
        "pnpm must leave the lock as committed"
    );

    // 6. The committed state verifies offline and survives a full resolve.
    let (code, stdout, stderr) = run_socket(&fresh, &["vendor", "--check", "--json"]);
    assert_eq!(
        code, 0,
        "vendor --check failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let full = rush(&fresh, &global, &["update", "--full"]);
    assert!(
        full.status.success(),
        "`rush update --full` failed.\n{}",
        shown(&full)
    );
    assert_eq!(
        wired_files(&fresh),
        vendored,
        "`rush update --full` dropped or rewrote the vendored wiring"
    );
    assert!(
        direct_copy(&fresh, "libs/util") == patched,
        "the full resolve must keep the patched minimist"
    );

    // 7. Revert restores every file and the registry install.
    let (code, stdout, stderr) = run_socket(&root, &["vendor", "--revert", "--yes", "--json"]);
    assert_eq!(
        code, 0,
        "vendor --revert failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        wired_files(&root),
        baseline,
        "revert must restore every wired file byte for byte"
    );
    assert!(
        !root.join(".socket/vendor/npm").join(UUID).exists(),
        "revert must remove the artifact"
    );
    let reinstall = rush(&root, &global, &["install"]);
    assert!(
        reinstall.status.success(),
        "`rush install` must accept the reverted repository.\n{}",
        shown(&reinstall)
    );
    assert!(
        direct_copy(&root, "libs/util") == pristine,
        "the reverted repository installs the registry minimist"
    );
}

#[test]
#[serial_test::serial]
#[ignore = "wall-bound real Rush + pnpm installs from the npm registry; runs as an e2e CI matrix leg"]
fn rush_pnpm10_vendor_real_rush_install_and_revert() {
    run_capstone("10.34.9");
}

/// pnpm 11 reads no `pnpm` field from `package.json`: Rush hands it the
/// overrides through the `pnpm-workspace.yaml` it generates in
/// `common/temp`.
#[test]
#[serial_test::serial]
#[ignore = "wall-bound real Rush + pnpm installs from the npm registry; runs as an e2e CI matrix leg"]
fn rush_pnpm11_vendor_real_rush_install_and_revert() {
    run_capstone("11.28.12");
}
