//! `apply` in a Cargo project whose `Cargo.lock` takes a crate from a path,
//! git or `[patch]` source (#506).
//!
//! `$CARGO_HOME/registry/src` is shared machine-wide, so it can hold a
//! crates.io copy of `cfg-if-1.0.4` that this project's build never reads:
//! a `[patch.crates-io]` path override (in `Cargo.toml` or
//! `.cargo/config.toml`) or a git dependency replaces it. Patching that
//! copy in place reports success while cargo builds the user's unpatched
//! source, so agent mode must leave it alone. A registry-sourced lock entry
//! (the control) is still patched.

use std::path::Path;

use serde_json::{json, Value};

use crate::cargo_lock_source_fixture::{
    stage_registry_copy, write_project, Shape, AFTER, BEFORE, PURL,
};
use crate::common;

use common::{git_sha256, parse_json_envelope, run_with_env};

/// `.socket/manifest.json` with one agent-mode record for [`PURL`], and the
/// after blob staged so apply runs offline.
fn write_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();
    let manifest = json!({ "patches": { PURL: {
        "uuid": "50650650-0000-4000-8000-000000000506",
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": { "package/src/lib.rs": {
            "beforeHash": git_sha256(BEFORE),
            "afterHash": git_sha256(AFTER),
        }},
        "vulnerabilities": {},
        "description": "cargo lock source fixture",
        "license": "MIT",
        "tier": "free"
    }}});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// Stage `shape`, run `apply --offline --json`, and return the exit code,
/// the envelope and the registry copy's `src/lib.rs` afterwards.
fn apply(shape: Shape, extra: &[&str]) -> (i32, Value, Vec<u8>) {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("app");
    std::fs::create_dir_all(&project).unwrap();
    write_project(&project, shape);
    write_manifest(&project);
    let cargo_home = tmp.path().join("cargo-home");
    let lib = stage_registry_copy(&cargo_home, BEFORE);

    let mut argv = vec!["apply", "--offline", "--json"];
    argv.extend_from_slice(extra);
    let (code, stdout, stderr) = run_with_env(
        &project,
        &argv,
        &[
            ("SOCKET_TELEMETRY_DISABLED", "1"),
            ("CARGO_HOME", cargo_home.to_str().unwrap()),
        ],
    );
    let v = parse_json_envelope(&stdout);
    assert!(!v.is_null(), "{shape:?}: no envelope\n{stdout}\n{stderr}");
    (code, v, std::fs::read(&lib).unwrap())
}

/// Control: a crate the lock takes from crates.io is patched in the
/// registry cache, so the fixture really reaches the agent apply path.
#[test]
fn registry_sourced_crate_is_patched_in_the_registry_cache() {
    let (code, v, lib) = apply(Shape::Registry, &[]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(lib, AFTER, "the registry copy is the build's: {v}");
}

/// #506: a crate the lock resolves to a path, git or `[patch]` source is
/// never built from the registry cache, so apply must not patch that copy
/// or report it applied.
#[test]
fn crate_overridden_away_from_the_registry_is_not_patched() {
    for shape in [
        Shape::ManifestPatch,
        Shape::ConfigPatch,
        Shape::GitDependency,
        Shape::PathDependency,
        Shape::Replace,
    ] {
        let (code, v, lib) = apply(shape, &[]);
        assert_eq!(
            lib, BEFORE,
            "{shape:?}: the unused registry copy must stay untouched: {v}"
        );
        let ev = event(&v, shape);
        assert_eq!(ev["action"], "skipped", "{shape:?}: {v}");
        match shape {
            // The user's own `[patch]` or `[replace]` entry: the consent
            // gate's calm skip.
            Shape::ManifestPatch | Shape::ConfigPatch | Shape::Replace => {
                assert_eq!(code, 0, "{shape:?}: {v}");
                assert_eq!(ev["errorCode"], "user_patch_conflict", "{shape:?}: {ev}");
            }
            // Nothing else protects a git or path dependency: the crate is not
            // installed where agent mode patches, and the run says why.
            _ => {
                assert_eq!(code, 1, "{shape:?}: must not report success: {v}");
                assert_eq!(ev["errorCode"], "package_not_installed", "{shape:?}: {ev}");
                assert!(
                    ev.to_string().contains("path, git or [patch] source"),
                    "{shape:?}: the detail names the override case: {ev}"
                );
            }
        }
    }
}

/// #506: `--allow-patch-conflicts` lets apply try a crate the user's own
/// `[patch]` entry replaces, but the registry copy is still not the one
/// cargo builds, so it stays untouched and the run does not succeed.
#[test]
fn allowed_patch_conflict_still_leaves_the_unused_registry_copy() {
    for shape in [Shape::ManifestPatch, Shape::ConfigPatch, Shape::Replace] {
        let (code, v, lib) = apply(shape, &["--allow-patch-conflicts"]);
        assert_eq!(lib, BEFORE, "{shape:?}: {v}");
        assert_eq!(code, 1, "{shape:?}: must not report success: {v}");
        let ev = event(&v, shape);
        assert_eq!(ev["errorCode"], "package_not_installed", "{shape:?}: {ev}");
    }
}

fn event(v: &Value, shape: Shape) -> &Value {
    v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .find(|e| e["purl"] == PURL)
        .unwrap_or_else(|| panic!("{shape:?}: no event for {PURL}: {v}"))
}
