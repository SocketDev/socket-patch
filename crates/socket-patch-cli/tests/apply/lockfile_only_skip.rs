//! `apply` on a manifest whose targeted packages the project lockfile
//! resolves but the package manager deliberately did not install on this
//! host (#403): a platform-gated optional dependency (`fsevents` on Linux,
//! `@esbuild/<os>-<cpu>`) or a devDependency under `npm ci --omit=dev`.
//!
//! The tree is in its correct end state, so such a purl is a calm
//! `skipped`/`package_not_installed` that never fails the run — the same
//! treatment `scan --mode agent` gives lockfile-only packages. A purl with NO
//! lock evidence still fails the all-miss run (the wrong-`--cwd` guard).

use std::path::Path;

use serde_json::{json, Value};

use crate::common;

use common::{git_sha256, parse_json_envelope, run_with_env};

const BEFORE: &[u8] = b"pristine content\n";
const AFTER: &[u8] = b"patched content\n";

fn run_apply(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut argv: Vec<&str> = vec!["apply"];
    argv.extend_from_slice(args);
    run_with_env(cwd, &argv, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

fn record(uuid: &str) -> Value {
    json!({
        "uuid": uuid,
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": { "package/index.js": {
            "beforeHash": git_sha256(BEFORE),
            "afterHash": git_sha256(AFTER),
        }},
        "vulnerabilities": {},
        "description": "lockfile-only apply fixture",
        "license": "MIT",
        "tier": "free"
    })
}

/// `.socket/manifest.json` holding one record per purl, with the after
/// blob staged so the offline source guard is never what fires.
fn write_manifest(root: &Path, purls: &[&str]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();
    let mut patches = serde_json::Map::new();
    for (i, purl) in purls.iter().enumerate() {
        patches.insert(
            (*purl).to_string(),
            record(&format!("40340340-0000-4000-8000-00000000000{i}")),
        );
    }
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).unwrap(),
    )
    .unwrap();
}

fn install_npm_pkg(root: &Path, name: &str, version: &str) {
    let dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(dir.join("index.js"), BEFORE).unwrap();
}

/// npm v3 lock: `chokidar` installed, `fsevents` an `os: darwin` optional
/// dependency npm skips on every other host (never on disk here).
fn write_optional_skipped_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "app", "version": "1.0.0", "dependencies": { "chokidar": "3.6.0" } }"#,
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec_pretty(&json!({
            "name": "app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "chokidar": "3.6.0" } },
                "node_modules/chokidar": {
                    "version": "3.6.0",
                    "resolved": "https://registry.npmjs.org/chokidar/-/chokidar-3.6.0.tgz",
                    "optionalDependencies": { "fsevents": "~2.3.2" }
                },
                "node_modules/fsevents": {
                    "version": "2.3.3",
                    "resolved": "https://registry.npmjs.org/fsevents/-/fsevents-2.3.3.tgz",
                    "optional": true,
                    "os": ["darwin"]
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    install_npm_pkg(root, "chokidar", "3.6.0");
}

/// npm v3 lock after `npm ci --omit=dev`: `left-pad` (prod) installed,
/// `kind-of` (`dev: true`) resolved but not installed.
fn write_omit_dev_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "od", "version": "1.0.0",
             "dependencies": { "left-pad": "1.3.0" },
             "devDependencies": { "kind-of": "6.0.3" } }"#,
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        serde_json::to_vec_pretty(&json!({
            "name": "od",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": {
                    "name": "od", "version": "1.0.0",
                    "dependencies": { "left-pad": "1.3.0" },
                    "devDependencies": { "kind-of": "6.0.3" }
                },
                "node_modules/kind-of": {
                    "version": "6.0.3",
                    "resolved": "https://registry.npmjs.org/kind-of/-/kind-of-6.0.3.tgz",
                    "dev": true
                },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    install_npm_pkg(root, "left-pad", "1.3.0");
}

fn event<'a>(v: &'a Value, purl: &str) -> &'a Value {
    v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|e| e["purl"] == purl)
        .unwrap_or_else(|| panic!("no event for {purl}: {v}"))
}

/// #403: the only manifest patch targets a platform-skipped optional
/// dependency. `apply` exits 0 with a calm `package_not_installed` skip.
#[test]
fn platform_skipped_optional_dependency_is_a_calm_skip() {
    let tmp = tempfile::tempdir().unwrap();
    write_optional_skipped_project(tmp.path());
    write_manifest(tmp.path(), &["pkg:npm/fsevents@2.3.3"]);

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"]);
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        code, 0,
        "lock-resolved, host-skipped package must not fail; {v}\n{stderr}"
    );
    assert_eq!(v["status"], "success", "{v}");
    let ev = event(&v, "pkg:npm/fsevents@2.3.3");
    assert_eq!(ev["action"], "skipped", "{ev}");
    assert_eq!(ev["errorCode"], "package_not_installed", "{ev}");

    // Human path: a note, never the exit-flipping error.
    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        !stderr.contains("Error:"),
        "no error line for a calm skip; {stderr}"
    );
    assert!(
        stderr.contains("pkg:npm/fsevents@2.3.3") && stderr.contains("lockfile"),
        "the note names the purl and why it was skipped; {stderr}"
    );
}

/// #403: the hook-style `apply --silent` exits 0 and prints nothing.
#[test]
fn silent_apply_on_platform_skipped_optional_dependency_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    write_optional_skipped_project(tmp.path());
    write_manifest(tmp.path(), &["pkg:npm/fsevents@2.3.3"]);

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline", "--silent"]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.trim().is_empty(),
        "--silent prints errors only; {stderr}"
    );
}

/// #403 (`npm ci --omit=dev`): the only patch is for a devDependency the
/// production install left out. Exit 0, calm skip.
#[test]
fn omitted_dev_dependency_is_a_calm_skip() {
    let tmp = tempfile::tempdir().unwrap();
    write_omit_dev_project(tmp.path());
    write_manifest(tmp.path(), &["pkg:npm/kind-of@6.0.3"]);

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"]);
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        code, 0,
        "omitted devDependency must not fail; {v}\n{stderr}"
    );
    assert_eq!(v["status"], "success", "{v}");
    let ev = event(&v, "pkg:npm/kind-of@6.0.3");
    assert_eq!(ev["action"], "skipped", "{ev}");
    assert_eq!(ev["errorCode"], "package_not_installed", "{ev}");
}

/// Control: a purl the lock does NOT resolve still fails the all-miss run,
/// and the error lists only that purl (the lock-resolved one is a skip).
#[test]
fn unresolved_purl_still_fails_alongside_a_lock_resolved_one() {
    let tmp = tempfile::tempdir().unwrap();
    write_optional_skipped_project(tmp.path());
    write_manifest(
        tmp.path(),
        &["pkg:npm/fsevents@2.3.3", "pkg:npm/ghost@1.0.0"],
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--json"]);
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        code, 1,
        "a purl with no lock evidence still fails; {v}\n{stderr}"
    );
    assert_eq!(v["status"], "partialFailure", "{v}");
    for purl in ["pkg:npm/fsevents@2.3.3", "pkg:npm/ghost@1.0.0"] {
        assert_eq!(event(&v, purl)["errorCode"], "package_not_installed", "{v}");
    }

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("Error: The targeted manifest patch matched no installed package:")
            && stderr.contains("  - pkg:npm/ghost@1.0.0"),
        "the error names the unresolved purl; {stderr}"
    );
    let error_block: String = stderr
        .lines()
        .skip_while(|l| !l.starts_with("Error:"))
        .take_while(|l| !l.starts_with("Check that"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !error_block.contains("fsevents"),
        "the lock-resolved purl is not part of the error; {stderr}"
    );
}

/// Control: with no lockfile at all (e.g. the wrong `--cwd`), the all-miss
/// run fails exactly as before.
#[test]
fn no_lockfile_all_miss_still_fails() {
    let tmp = tempfile::tempdir().unwrap();
    write_optional_skipped_project(tmp.path());
    std::fs::remove_file(tmp.path().join("package-lock.json")).unwrap();
    write_manifest(tmp.path(), &["pkg:npm/fsevents@2.3.3"]);

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("Error: The targeted manifest patch matched no installed package:"),
        "{stderr}"
    );
}

// ---- Cargo: lock-resolved but not fetched is NOT a calm skip (#616) ----
//
// A Cargo.lock entry with no unpacked source in `$CARGO_HOME/registry/src`
// was not deliberately left out: cargo simply has not fetched it yet (a
// fresh CI runner / clone, or a pruned `registry/src`). The next `cargo
// build` downloads or re-extracts it UNPATCHED, so `apply` must fail the
// all-miss run like 4.0.0 did, and tell the user to `cargo fetch` first.

const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.0";

/// A binary crate locking `cfg-if 1.0.0` from crates.io.
fn write_cargo_project(root: &Path) {
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
         [dependencies]\ncfg-if = \"=1.0.0\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("Cargo.lock"),
        "# This file is automatically @generated by Cargo.\n\
         # It is not intended for manual editing.\n\
         version = 4\n\n\
         [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"cfg-if\",\n]\n\n\
         [[package]]\nname = \"cfg-if\"\nversion = \"1.0.0\"\n\
         source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"baf1de4339761588bc0d7c0e2b9b9d4ab8c4fa8c1f6c2fb5b9a6e7c3a7d2b0e1\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
}

fn run_cargo_apply(cwd: &Path, cargo_home: &Path, args: &[&str]) -> (i32, String, String) {
    let mut argv: Vec<&str> = vec!["apply"];
    argv.extend_from_slice(args);
    let home = cargo_home.to_str().unwrap();
    run_with_env(
        cwd,
        &argv,
        &[("SOCKET_TELEMETRY_DISABLED", "1"), ("CARGO_HOME", home)],
    )
}

fn assert_cold_cargo_apply_fails(project: &Path, cargo_home: &Path) {
    let (code, stdout, stderr) = run_cargo_apply(project, cargo_home, &["--offline", "--json"]);
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        code, 1,
        "an unfetched cargo crate must fail apply, not skip calmly; {v}\n{stderr}"
    );
    assert_eq!(v["status"], "partialFailure", "{v}");
    let ev = event(&v, CARGO_PURL);
    assert_eq!(ev["errorCode"], "package_not_installed", "{ev}");
    let detail = ev.to_string();
    assert!(
        detail.contains("cargo fetch") && !detail.contains("lockfile-only"),
        "the event must carry the cargo fetch remedy, not the calm lockfile-only detail; {ev}"
    );

    // Human path: the exit-flipping error plus the actionable remedy.
    let (code, _stdout, stderr) = run_cargo_apply(project, cargo_home, &["--offline"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(
        stderr.contains("Error: The targeted manifest patch matched no installed package:")
            && stderr.contains(&format!("  - {CARGO_PURL}"))
            && stderr.contains("cargo fetch"),
        "the error names the crate and tells the user to run `cargo fetch`; {stderr}"
    );

    // `--silent` (the hook / CI shape) still prints the error and exits 1.
    let (code, _stdout, stderr) = run_cargo_apply(project, cargo_home, &["--offline", "--silent"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("cargo fetch"), "{stderr}");
}

/// #616: an empty `$CARGO_HOME` (fresh CI runner): the crate is locked but
/// was never downloaded.
#[test]
fn cargo_crate_on_cold_registry_cache_fails_with_fetch_remedy() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("app");
    std::fs::create_dir_all(&project).unwrap();
    write_cargo_project(&project);
    write_manifest(&project, &[CARGO_PURL]);
    let cargo_home = tmp.path().join("cargo-home");
    std::fs::create_dir_all(&cargo_home).unwrap();

    assert_cold_cargo_apply_fails(&project, &cargo_home);
}

/// #616 pruned variant: the `.crate` archive is cached but `registry/src`
/// was pruned, so cargo re-extracts the pristine source on the next build.
#[test]
fn cargo_crate_with_pruned_registry_src_fails_with_fetch_remedy() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("app");
    std::fs::create_dir_all(&project).unwrap();
    write_cargo_project(&project);
    write_manifest(&project, &[CARGO_PURL]);
    let cargo_home = tmp.path().join("cargo-home");
    let cache = cargo_home.join("registry/cache/index.crates.io-1949cf8c6b5b557f");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("cfg-if-1.0.0.crate"), b"not a real archive").unwrap();
    std::fs::create_dir_all(cargo_home.join("registry/src/index.crates.io-1949cf8c6b5b557f"))
        .unwrap();

    assert_cold_cargo_apply_fails(&project, &cargo_home);
}
