#![cfg(feature = "cargo")]
//! End-to-end coexistence test for the project-local cargo `[patch]`-redirect
//! backend.
//!
//! Proves that patching a registry crate for project A:
//!   * redirects A to a project-local patched copy under
//!     `A/.socket/cargo-patches/` via a managed `[patch.crates-io]` entry, and
//!   * leaves the *shared* registry crate pristine — so a sibling project B
//!     resolving the same crate still sees the unpatched source.
//!
//! Also covers the self-heal/idempotency hot path, rollback, reconcile of a
//! dropped patch, and the read-only `apply --check` auditor (including its
//! registry-independence). No network and no real `cargo` — a fake
//! `$CARGO_HOME/registry/src/` tree stands in for an extracted crate.

use std::path::{Path, PathBuf};

#[path = "common/mod.rs"]
mod common;

use common::{
    binary, cargo_run, git_sha256, has_command, json_string, parse_json_envelope, run_with_env,
    write_blob, write_minimal_manifest, PatchEntry,
};

/// The exact managed `[patch.crates-io]` entry apply must write — keying the
/// crate NAME to its version-specific copy path. Asserting the full `key = {
/// path = ... }` line (not two independent `contains()` substrings) closes the
/// loophole where a broken impl writes the `[patch.crates-io]` header plus the
/// copy path under the WRONG key (or no key) and still passes — cargo keys
/// `[patch]` by name, so the key↔path binding is what actually redirects.
const EXPECTED_PATCH_LINE: &str =
    "cfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.0\" }";

/// Parse an `apply --json` envelope and assert it reports a real, successful
/// patch of `PURL` (status=success, summary.applied≥1, an `applied` event for
/// the purl). Guards against an apply that exits 0 while reporting nothing
/// applied (or a failure) yet happens to leave plausible bytes on disk.
fn assert_applied_envelope(stdout: &str) {
    let env = parse_json_envelope(stdout);
    assert_eq!(
        json_string(&env, "status"),
        Some("success"),
        "apply envelope status must be success:\n{stdout}"
    );
    assert!(
        env["summary"]["applied"].as_u64().unwrap_or(0) >= 1,
        "summary.applied must be >= 1:\n{stdout}"
    );
    let events = env["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "applied" && e["purl"] == PURL),
        "expected an `applied` event for {PURL}:\n{stdout}"
    );
}

const CRATE: &str = "cfg-if";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:cargo/cfg-if@1.0.0";
const UUID: &str = "20202020-2020-4202-8202-202020202020";

const PRISTINE: &[u8] = b"pub fn cfg() -> u8 { 1 }\n";
const PATCHED: &[u8] = b"pub fn cfg() -> u8 { 2 } // patched\n";
const PATCHED_V2: &[u8] = b"pub fn cfg() -> u8 { 3 } // patched again\n";

/// Stage a fake extracted registry crate at
/// `<cargo_home>/registry/src/index.crates.io-test/<name>-<version>/` with the
/// given `lib` bytes + a valid-shaped `.cargo-checksum.json`. Returns the crate
/// dir.
fn stage_registry_crate(cargo_home: &Path, lib: &[u8]) -> PathBuf {
    let crate_dir = cargo_home
        .join("registry/src/index.crates.io-test")
        .join(format!("{CRATE}-{VERSION}"));
    std::fs::create_dir_all(crate_dir.join("src")).unwrap();
    std::fs::write(
        crate_dir.join("Cargo.toml"),
        format!("[package]\nname = \"{CRATE}\"\nversion = \"{VERSION}\"\n"),
    )
    .unwrap();
    std::fs::write(crate_dir.join("src/lib.rs"), lib).unwrap();
    std::fs::write(
        crate_dir.join(".cargo-checksum.json"),
        "{\"files\":{},\"package\":\"x\"}",
    )
    .unwrap();
    crate_dir
}

/// Stage a consumer project that depends on the crate (a `Cargo.toml` makes the
/// cargo crawler fall back to `$CARGO_HOME/registry/src`; no `vendor/` so the
/// redirect model engages).
fn stage_project(root: &Path) {
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        format!("[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{CRATE} = \"={VERSION}\"\n"),
    )
    .unwrap();
    std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
}

/// Write `.socket/manifest.json` + the after-hash blob for a patch turning
/// `PRISTINE` into `patched`.
fn stage_manifest(root: &Path, patched: &[u8]) -> (String, String) {
    let before = git_sha256(PRISTINE);
    let after = git_sha256(patched);
    let socket = root.join(".socket");
    write_minimal_manifest(
        &socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "package/src/lib.rs",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket, &after, patched);
    (before, after)
}

fn apply(root: &Path, cargo_home: &Path) -> (i32, String, String) {
    run_with_env(
        root,
        &[
            "apply",
            "--offline",
            "-e",
            "cargo",
            "--cwd",
            root.to_str().unwrap(),
            "--json",
        ],
        &[("CARGO_HOME", cargo_home.to_str().unwrap())],
    )
}

fn copy_lib(root: &Path) -> PathBuf {
    root.join(format!(
        ".socket/cargo-patches/{CRATE}-{VERSION}/src/lib.rs"
    ))
}

fn config_toml(root: &Path) -> PathBuf {
    root.join(".cargo/config.toml")
}

#[test]
fn apply_redirects_and_leaves_registry_pristine() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_home = tmp.path().join("cargo-home");
    let project = tmp.path().join("A");
    let crate_dir = stage_registry_crate(&cargo_home, PRISTINE);
    stage_project(&project);
    stage_manifest(&project, PATCHED);

    let (code, stdout, stderr) = apply(&project, &cargo_home);
    assert_eq!(
        code, 0,
        "apply failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The JSON envelope must actually report the patch as applied — not just
    // exit 0 while reporting nothing (or a partial failure).
    assert_applied_envelope(&stdout);

    // Project-local patched copy holds EXACTLY the patched bytes, and its
    // git-sha matches the manifest afterHash (independently derived from
    // PATCHED) — so the bytes aren't merely non-empty, they're the right ones.
    let copy_bytes = std::fs::read(copy_lib(&project)).unwrap();
    assert_eq!(copy_bytes, PATCHED);
    assert_eq!(git_sha256(&copy_bytes), git_sha256(PATCHED));
    // Managed [patch.crates-io] entry binds the crate NAME to the copy path.
    let cfg = std::fs::read_to_string(config_toml(&project)).unwrap();
    assert!(
        cfg.contains("[patch.crates-io]"),
        "config.toml missing [patch.crates-io] table:\n{cfg}"
    );
    assert!(
        cfg.contains(EXPECTED_PATCH_LINE),
        "config.toml missing the exact `{EXPECTED_PATCH_LINE}` entry \
         (key must bind to the version-specific copy path):\n{cfg}"
    );
    // apply also wires the build-time guard's [env] SOCKET_PATCH_ROOT — the
    // rollback test depends on this being present so it can prove rollback
    // leaves it intact. Pin it here at the source.
    assert!(
        cfg.contains("SOCKET_PATCH_ROOT"),
        "apply must wire [env] SOCKET_PATCH_ROOT for the guard:\n{cfg}"
    );
    // The SHARED registry crate is untouched — a sibling project sees pristine.
    assert_eq!(
        std::fs::read(crate_dir.join("src/lib.rs")).unwrap(),
        PRISTINE,
        "registry crate must NOT be mutated by the local redirect"
    );
    // The registry checksum sidecar is likewise pristine (the redirect model
    // must not rewrite the shared registry's .cargo-checksum.json).
    assert_eq!(
        std::fs::read_to_string(crate_dir.join(".cargo-checksum.json")).unwrap(),
        "{\"files\":{},\"package\":\"x\"}",
        "registry .cargo-checksum.json must NOT be mutated"
    );
}

#[test]
fn project_without_manifest_has_no_redirect() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_home = tmp.path().join("cargo-home");
    let project = tmp.path().join("B");
    stage_registry_crate(&cargo_home, PRISTINE);
    stage_project(&project); // no .socket/manifest.json

    let (code, stdout, _stderr) = apply(&project, &cargo_home);
    assert_eq!(
        code, 0,
        "apply on a manifest-less project should be a clean no-op"
    );
    // The envelope must say *why* it was a no-op: noManifest, nothing applied.
    // Otherwise a broken apply that silently did nothing (or errored) on a real
    // manifest would also look like a clean exit-0 here.
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&env, "status"),
        Some("noManifest"),
        "manifest-less apply must report status=noManifest:\n{stdout}"
    );
    assert_eq!(
        env["summary"]["applied"].as_u64().unwrap_or(u64::MAX),
        0,
        "manifest-less apply must apply nothing:\n{stdout}"
    );
    assert!(
        !config_toml(&project).exists(),
        "no manifest => no [patch] redirect written"
    );
    // And no patched copy materialised either.
    assert!(
        !project.join(".socket/cargo-patches").exists(),
        "no manifest => no patched copy tree"
    );
}

#[test]
fn reapply_in_sync_is_byte_identical() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_home = tmp.path().join("cargo-home");
    let project = tmp.path().join("A");
    stage_registry_crate(&cargo_home, PRISTINE);
    stage_project(&project);
    stage_manifest(&project, PATCHED);

    let (c1, out1, err1) = apply(&project, &cargo_home);
    assert_eq!(c1, 0, "first apply failed.\nstdout:\n{out1}\nstderr:\n{err1}");
    assert_applied_envelope(&out1);
    let lib1 = std::fs::read(copy_lib(&project)).unwrap();
    let cfg1 = std::fs::read_to_string(config_toml(&project)).unwrap();
    // The snapshot we're about to prove "byte-identical" must itself be the
    // CORRECT state — otherwise idempotently reproducing a *wrong* state (e.g.
    // an apply that never patched) would pass this test.
    assert_eq!(lib1, PATCHED, "first apply did not patch the copy");
    assert!(
        cfg1.contains(EXPECTED_PATCH_LINE),
        "first apply did not write the managed patch entry:\n{cfg1}"
    );

    // Second apply must hit the in-sync short-circuit: the envelope must report
    // the package as already-patched (skipped), NOT re-applied. A regression
    // that re-copies + re-patches every run would still leave byte-identical
    // files, so byte-equality alone can't detect it — assert the action.
    let (c2, out2, err2) = apply(&project, &cargo_home);
    assert_eq!(c2, 0, "resync apply failed.\nstdout:\n{out2}\nstderr:\n{err2}");
    let env2 = parse_json_envelope(&out2);
    assert_eq!(
        json_string(&env2, "status"),
        Some("success"),
        "resync status must be success:\n{out2}"
    );
    assert_eq!(
        env2["summary"]["applied"].as_u64().unwrap_or(u64::MAX),
        0,
        "resync must apply nothing (in-sync short-circuit):\n{out2}"
    );
    let events2 = env2["events"].as_array().expect("events array");
    assert!(
        events2
            .iter()
            .any(|e| e["action"] == "skipped" && e["purl"] == PURL),
        "resync must emit a `skipped` (already-patched) event for {PURL}:\n{out2}"
    );

    assert_eq!(
        std::fs::read(copy_lib(&project)).unwrap(),
        lib1,
        "copy bytes changed on resync"
    );
    assert_eq!(
        std::fs::read_to_string(config_toml(&project)).unwrap(),
        cfg1,
        "config changed on resync"
    );
}

#[test]
fn self_heal_regenerates_copy_when_manifest_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_home = tmp.path().join("cargo-home");
    let project = tmp.path().join("A");
    stage_registry_crate(&cargo_home, PRISTINE);
    stage_project(&project);
    stage_manifest(&project, PATCHED);
    assert_eq!(apply(&project, &cargo_home).0, 0);
    assert_eq!(std::fs::read(copy_lib(&project)).unwrap(), PATCHED);

    // Patch set changes (afterHash + content) — re-apply regenerates the copy.
    stage_manifest(&project, PATCHED_V2);
    let (code, stdout, stderr) = apply(&project, &cargo_home);
    assert_eq!(code, 0, "re-apply failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    // The manifest drifted from the committed copy, so this must be a real
    // re-apply (applied event), not an already-patched short-circuit.
    assert_applied_envelope(&stdout);
    let regenerated = std::fs::read(copy_lib(&project)).unwrap();
    assert_eq!(
        regenerated, PATCHED_V2,
        "copy must be regenerated to the new patched content"
    );
    // And distinct from the previous patched content — proves a genuine
    // regeneration, not a stale leftover that happens to read back.
    assert_ne!(regenerated, PATCHED, "copy is still the stale v1 content");
    assert_eq!(git_sha256(&regenerated), git_sha256(PATCHED_V2));
}

#[test]
fn rollback_removes_redirect_offline_without_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_home = tmp.path().join("cargo-home");
    let project = tmp.path().join("A");
    let crate_dir = stage_registry_crate(&cargo_home, PRISTINE);
    stage_project(&project);
    stage_manifest(&project, PATCHED);
    assert_eq!(apply(&project, &cargo_home).0, 0);
    assert!(copy_lib(&project).exists());

    let (code, stdout, stderr) = run_with_env(
        &project,
        &[
            "rollback",
            "--offline",
            "-e",
            "cargo",
            "--cwd",
            project.to_str().unwrap(),
            "--yes",
            "--json",
        ],
        &[("CARGO_HOME", cargo_home.to_str().unwrap())],
    );
    assert_eq!(
        code, 0,
        "rollback failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The rollback envelope must report a real removal (rolledBack >= 1), not
    // exit 0 having done nothing.
    let rb = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&rb, "status"),
        Some("success"),
        "rollback status must be success:\n{stdout}"
    );
    assert!(
        rb["rolledBack"].as_u64().unwrap_or(0) >= 1,
        "rollback must report >= 1 rolled-back package:\n{stdout}"
    );
    assert_eq!(
        rb["failed"].as_u64().unwrap_or(u64::MAX),
        0,
        "rollback must report no failures:\n{stdout}"
    );

    // Redirect copy + config entry are gone; the registry stayed pristine.
    assert!(
        !project
            .join(format!(".socket/cargo-patches/{CRATE}-{VERSION}"))
            .exists(),
        "copy dir should be removed on rollback"
    );
    // Read WITHOUT a default fallback: a wrongly-deleted config.toml must fail
    // loudly here, not collapse to "" and let the `!contains(CRATE)` check pass
    // vacuously (the SOCKET_PATCH_ROOT survival assert below is the only thing
    // that would otherwise catch a deletion — make the failure mode explicit).
    let cfg = std::fs::read_to_string(config_toml(&project))
        .expect("config.toml must survive rollback (it holds [env] setup state)");
    assert!(
        !cfg.contains(CRATE),
        "managed [patch] entry should be gone:\n{cfg}"
    );
    // Rollback removes patch state only — the [env] SOCKET_PATCH_ROOT setup
    // state (written by apply/setup, owned by setup --remove) must survive so
    // the guard stays wired.
    assert!(
        cfg.contains("SOCKET_PATCH_ROOT"),
        "rollback must NOT remove [env] SOCKET_PATCH_ROOT (setup state):\n{cfg}"
    );
    assert_eq!(
        std::fs::read(crate_dir.join("src/lib.rs")).unwrap(),
        PRISTINE
    );
}

#[test]
fn reconcile_prunes_dropped_patch() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_home = tmp.path().join("cargo-home");
    let project = tmp.path().join("A");
    stage_registry_crate(&cargo_home, PRISTINE);
    stage_project(&project);
    stage_manifest(&project, PATCHED);
    assert_eq!(apply(&project, &cargo_home).0, 0);
    assert!(copy_lib(&project).exists());

    // Drop the patch from the manifest, then re-apply: reconcile prunes the
    // now-orphan redirect even though the manifest lists zero cargo patches.
    let empty = serde_json::json!({ "patches": {} });
    std::fs::write(
        project.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&empty).unwrap(),
    )
    .unwrap();
    // The empty manifest takes the "nothing to apply" early-return path (today:
    // exit 1 / status=partialFailure; a future no-op-success fix would make it
    // exit 0), but reconcile runs BEFORE that return and prunes the orphan. We
    // deliberately don't pin the exact status (it's the early-return path, not
    // the contract under test) — but `rc_code >= 0` was vacuous: every normal
    // exit, INCLUDING a Rust panic (code 101), satisfies it, so it could not
    // actually catch the binary crashing before reconcile. Instead require the
    // apply pipeline to have RUN TO COMPLETION: a normal exit in {0,1} (rejects
    // panic=101 and signal=-1) AND a well-formed JSON envelope that applied
    // nothing. A panic/abort before reconcile yields no envelope (parse panics)
    // or a signal exit; a runaway re-apply would report applied>=1 — both fail
    // loudly here rather than silently passing the FS checks below.
    let (rc_code, rc_out, rc_err) = apply(&project, &cargo_home);
    assert!(
        rc_code == 0 || rc_code == 1,
        "empty-manifest apply must exit 0/1 (not crash), got {rc_code}.\nstdout:\n{rc_out}\nstderr:\n{rc_err}"
    );
    let rc_env = parse_json_envelope(&rc_out);
    assert!(
        matches!(json_string(&rc_env, "status"), Some("partialFailure") | Some("success")),
        "empty-manifest apply must reach a clean terminal status, got {:?}:\n{rc_out}",
        json_string(&rc_env, "status")
    );
    assert_eq!(
        rc_env["summary"]["applied"].as_u64().unwrap_or(u64::MAX),
        0,
        "reconcile/empty-manifest apply must apply nothing:\n{rc_out}"
    );

    assert!(
        !project
            .join(format!(".socket/cargo-patches/{CRATE}-{VERSION}"))
            .exists(),
        "orphan copy dir should be pruned by reconcile"
    );
    // config.toml must still EXIST (reconcile prunes patch entries but must keep
    // the [env] setup state) — read it WITHOUT a default fallback so a wrongly
    // deleted file fails loudly here instead of vacuously passing the !contains
    // check below.
    let cfg = std::fs::read_to_string(config_toml(&project))
        .expect("config.toml must survive reconcile (it holds [env] setup state)");
    assert!(
        !cfg.contains(CRATE),
        "orphan [patch] entry should be pruned:\n{cfg}"
    );
    // The [env] SOCKET_PATCH_ROOT setup state must NOT be dropped by reconcile —
    // it is owned by `setup`/`setup --remove`, independent of whether any
    // redirects remain (mirrors the production invariant).
    assert!(
        cfg.contains("SOCKET_PATCH_ROOT"),
        "reconcile must NOT remove [env] SOCKET_PATCH_ROOT (setup state):\n{cfg}"
    );
}

#[test]
fn check_detects_drift_and_is_registry_independent() {
    let tmp = tempfile::tempdir().unwrap();
    let cargo_home = tmp.path().join("cargo-home");
    let project = tmp.path().join("A");
    let crate_dir = stage_registry_crate(&cargo_home, PRISTINE);
    stage_project(&project);
    stage_manifest(&project, PATCHED);
    assert_eq!(apply(&project, &cargo_home).0, 0);

    // Drop the registry crate entirely — `--check` reads only manifest + copy
    // + config, so it must still work (fresh-clone / airgapped CI).
    std::fs::remove_dir_all(&crate_dir).unwrap();

    let check = |root: &Path| -> i32 {
        run_with_env(
            root,
            &[
                "apply",
                "--check",
                "--offline",
                "-e",
                "cargo",
                "--cwd",
                root.to_str().unwrap(),
            ],
            &[("CARGO_HOME", cargo_home.to_str().unwrap())],
        )
        .0
    };

    // In sync (no registry present) → exit 0.
    assert_eq!(
        check(&project),
        0,
        "in-sync --check should pass even with no registry crate"
    );

    // Mutate the manifest afterHash without re-applying → the committed copy
    // is now stale → `--check` must fail.
    stage_manifest(&project, PATCHED_V2);
    assert_eq!(
        check(&project),
        1,
        "drift should make --check exit non-zero"
    );
}

/// Real-cargo end-to-end: prove that the committed `[patch.crates-io]` entry
/// (relative path) + `[env] SOCKET_PATCH_ROOT` resolve correctly and that a
/// bare `cargo build` actually compiles the **patched copy**, not the pristine
/// registry crate. The patch appends a top-level `compile_error!`, so the build
/// FAILS with that marker iff the redirect resolved — an unambiguous signal.
///
/// `#[ignore]`d: needs real `cargo` + a network `cargo fetch` from crates.io.
/// Skips (rather than fails) when cargo is absent or the fetch fails offline.
#[test]
#[ignore]
fn real_cargo_resolves_to_patched_copy() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    let cargo_home = tmp.path().join("cargo-home");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        consumer.join("Cargo.toml"),
        format!("[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{CRATE} = \"={VERSION}\"\n"),
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.rs"), "fn main() {}\n").unwrap();

    // Populate the registry (network). Skip on failure (offline CI etc.).
    let fetch = cargo_run(
        &consumer,
        &["fetch"],
        &[("CARGO_HOME", cargo_home.to_str().unwrap())],
    );
    if !fetch.status.success() {
        eprintln!(
            "SKIP: cargo fetch failed (likely no network):\n{}",
            String::from_utf8_lossy(&fetch.stderr)
        );
        return;
    }

    // Locate the extracted crate + read its pristine lib.rs.
    let registry_src = cargo_home.join("registry/src");
    let mut lib_path = None;
    for entry in std::fs::read_dir(&registry_src).unwrap().flatten() {
        let candidate = entry
            .path()
            .join(format!("{CRATE}-{VERSION}"))
            .join("src/lib.rs");
        if candidate.exists() {
            lib_path = Some(candidate);
            break;
        }
    }
    let lib_path = lib_path.expect("cfg-if lib.rs after fetch");
    let pristine = std::fs::read(&lib_path).unwrap();
    let mut patched = pristine.clone();
    patched.extend_from_slice(b"\ncompile_error!(\"SOCKET_PATCH_APPLIED\");\n");

    // Stage a manifest/blob for the real pristine→patched transition.
    let before = git_sha256(&pristine);
    let after = git_sha256(&patched);
    let socket = consumer.join(".socket");
    write_minimal_manifest(
        &socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "package/src/lib.rs",
            before_hash: &before,
            after_hash: &after,
        }],
    );
    write_blob(&socket, &after, &patched);

    // Apply the redirect.
    let (code, stdout, stderr) = apply(&consumer, &cargo_home);
    assert_eq!(
        code, 0,
        "apply failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The pristine registry crate is untouched.
    assert_eq!(
        std::fs::read(&lib_path).unwrap(),
        pristine,
        "registry must stay pristine"
    );

    // A bare `cargo build` must resolve to the patched copy → the injected
    // compile_error fires. If the redirect didn't resolve, the pristine crate
    // builds cleanly and this assertion fails.
    let build = cargo_run(
        &consumer,
        &["build", "--offline"],
        &[("CARGO_HOME", cargo_home.to_str().unwrap())],
    );
    let build_err = String::from_utf8_lossy(&build.stderr);
    assert!(
        !build.status.success() && build_err.contains("SOCKET_PATCH_APPLIED"),
        "cargo build must compile the PATCHED copy (expected the injected \
         compile_error). success={}, stderr:\n{build_err}",
        build.status.success(),
    );
}

/// Real-cargo end-to-end **fail-closed** proof: with the guard wired (path dep +
/// `[env] SOCKET_PATCH_ROOT` + `SOCKET_PATCH_BIN` = the real cargo-enabled
/// binary), a `cargo build` whose committed patched copy is STALE relative to
/// `.socket/manifest.json` must FAIL at build-script time (the guard's
/// `apply --check` detects drift), so a stale/unpatched binary is never
/// produced — closing the 1-build-lag silent-stale hole.
///
/// `#[ignore]`d: needs real `cargo` + network. Skips when offline.
#[test]
#[ignore]
fn real_cargo_guard_fails_build_on_stale_patch() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let guard_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("socket-patch-guard");

    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    let cargo_home = tmp.path().join("cargo-home");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();
    std::fs::write(
        consumer.join("Cargo.toml"),
        format!("[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n{CRATE} = \"={VERSION}\"\nsocket-patch-guard = {{ path = {guard_dir:?} }}\n"),
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.rs"), "fn main() {}\n").unwrap();

    let fetch = cargo_run(
        &consumer,
        &["fetch"],
        &[("CARGO_HOME", cargo_home.to_str().unwrap())],
    );
    if !fetch.status.success() {
        eprintln!("SKIP: cargo fetch failed (likely no network)");
        return;
    }

    let registry_src = cargo_home.join("registry/src");
    let mut lib_path = None;
    for entry in std::fs::read_dir(&registry_src).unwrap().flatten() {
        let c = entry
            .path()
            .join(format!("{CRATE}-{VERSION}"))
            .join("src/lib.rs");
        if c.exists() {
            lib_path = Some(c);
            break;
        }
    }
    let lib_path = lib_path.expect("lib.rs after fetch");
    let pristine = std::fs::read(&lib_path).unwrap();
    let before = git_sha256(&pristine);
    let socket = consumer.join(".socket");

    // v1: benign API-compatible patch (an appended const) — must build clean.
    // (cfg-if has `#![deny(missing_docs)]`, so the item needs a doc comment.)
    let mut v1 = pristine.clone();
    v1.extend_from_slice(b"\n/// socket-patch test marker v1.\npub const __SOCKET_PATCH_V1: u8 = 1;\n");
    let after_v1 = git_sha256(&v1);
    write_minimal_manifest(
        &socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "package/src/lib.rs",
            before_hash: &before,
            after_hash: &after_v1,
        }],
    );
    write_blob(&socket, &after_v1, &v1);
    assert_eq!(apply(&consumer, &cargo_home).0, 0); // committed copy in sync

    let bin = binary();
    let env = [
        ("CARGO_HOME", cargo_home.to_str().unwrap()),
        ("SOCKET_PATCH_ROOT", consumer.to_str().unwrap()),
        ("SOCKET_PATCH_BIN", bin.to_str().unwrap()),
    ];

    // In sync → the guard's `apply --check` passes → build succeeds.
    let ok = cargo_run(&consumer, &["build", "--offline"], &env);
    assert!(
        ok.status.success(),
        "in-sync guarded build must succeed.\nstderr:\n{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    // Change the patch in the MANIFEST + blob (v2) but DON'T re-apply, so the
    // committed copy is now stale relative to the manifest.
    let mut v2 = pristine.clone();
    v2.extend_from_slice(b"\n/// socket-patch test marker v2.\npub const __SOCKET_PATCH_V2: u8 = 2;\n");
    let after_v2 = git_sha256(&v2);
    write_minimal_manifest(
        &socket,
        PURL,
        UUID,
        &[PatchEntry {
            file_name: "package/src/lib.rs",
            before_hash: &before,
            after_hash: &after_v2,
        }],
    );
    write_blob(&socket, &after_v2, &v2);

    // Guarded build with a stale committed patch → guard detects drift → build
    // FAILS (fail-closed; no stale artifact shipped). This v2 patch is API-
    // compatible, so the guard's heal reconciles it and the build fails with the
    // RECOVERABLE message ("regenerated … re-run the build"); the v1→v2 mismatch
    // is what makes the committed copy stale.
    let drift = cargo_run(&consumer, &["build", "--offline"], &env);
    let stderr = String::from_utf8_lossy(&drift.stderr);
    assert!(
        !drift.status.success(),
        "guarded build with a stale committed patch MUST fail (fail-closed).\nstderr:\n{stderr}"
    );
    // Assert the SPECIFIC recoverable-drift message, not a generic substring:
    // cargo's "failed to run custom build command for `socket-patch-guard …`"
    // boilerplate contains "socket-patch" on ANY build-script failure, which
    // would let this pass even if the guard failed for an unrelated reason.
    assert!(
        stderr.contains("regenerated") && stderr.to_lowercase().contains("re-run"),
        "failure must carry the guard's recoverable-drift message.\nstderr:\n{stderr}"
    );
}
