#![cfg(feature = "cargo")]
//! Integration test for `socket-patch-guard`'s build script under the single
//! **fail-closed** model: a real `cargo build` of a consumer that depends on the
//! guard runs `${SOCKET_PATCH_BIN} apply --check`. In sync → the build proceeds.
//! On drift → it heals (`apply`) then FAILS the build (recoverable → "rebuild";
//! unrecoverable → "could NOT be reconciled"). A missing CLI fails the build.
//! There is no `warn`/`off` escape.
//!
//! Uses a stub `SOCKET_PATCH_BIN` (a shell script) whose `apply --check` result
//! is controlled via env (`INITIAL_CHECK`, and whether the heal `apply` creates
//! a `HEALED_MARKER`). No real `socket-patch` / network. The guard is a zero-dep
//! path dependency, so `cargo build --offline` needs no downloads.
//!
//! `#[ignore]`d (shells out to `cargo`); `#[cfg(unix)]` for the shell stub.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Output;

#[path = "common/mod.rs"]
mod common;

use common::{cargo_run, has_command};

/// Scaffold a consumer that depends on the guard (path dep) + a stub
/// `socket-patch`. The stub records argv to `<tmp>/invoked.txt`; for
/// `apply --check` it exits 0 if `<tmp>/healed` exists else `$INITIAL_CHECK`
/// (default 0); a heal `apply` creates `<tmp>/healed` unless `HEAL_FAILS` is set.
/// Returns (tmp, consumer, cargo_home, stub, sentinel, healed_marker).
fn scaffold() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
    let guard_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("socket-patch-guard");
    assert!(guard_dir.join("Cargo.toml").exists(), "guard crate not found");

    let tmp = tempfile::tempdir().unwrap();
    let consumer = tmp.path().join("consumer");
    let cargo_home = tmp.path().join("cargo-home");
    std::fs::create_dir_all(consumer.join("src")).unwrap();
    std::fs::create_dir_all(&cargo_home).unwrap();

    std::fs::write(
        consumer.join("Cargo.toml"),
        format!(
            "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsocket-patch-guard = {{ path = {:?} }}\n",
            guard_dir
        ),
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.rs"), "fn main() {}\n").unwrap();

    let sentinel = tmp.path().join("invoked.txt");
    let healed = tmp.path().join("healed");
    let stub = tmp.path().join("stub-socket-patch.sh");
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {sentinel:?}\ncase \"$*\" in\n  *--check*)\n    if [ -f {healed:?} ]; then exit 0; fi\n    exit ${{INITIAL_CHECK:-0}} ;;\n  *)\n    if [ -z \"$HEAL_FAILS\" ]; then : > {healed:?}; fi\n    exit 0 ;;\nesac\n"
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    (tmp, consumer, cargo_home, stub, sentinel, healed)
}

fn build(consumer: &Path, cargo_home: &Path, stub: &Path, extra_env: &[(&str, &str)]) -> Output {
    let mut env: Vec<(&str, &str)> = vec![
        ("CARGO_HOME", cargo_home.to_str().unwrap()),
        ("SOCKET_PATCH_ROOT", consumer.to_str().unwrap()),
        ("SOCKET_PATCH_BIN", stub.to_str().unwrap()),
    ];
    env.extend_from_slice(extra_env);
    cargo_run(consumer, &["build", "--offline"], &env)
}

/// In sync (`apply --check` exits 0) → build succeeds; the guard probed via
/// `apply --check` and did NOT run a heal `apply`.
#[test]
#[ignore]
fn guard_in_sync_proceeds_without_heal() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let (tmp, consumer, cargo_home, stub, sentinel, _healed) = scaffold();
    let out = build(&consumer, &cargo_home, &stub, &[("INITIAL_CHECK", "0")]);
    assert!(
        out.status.success(),
        "in-sync build must succeed.\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let argv = std::fs::read_to_string(&sentinel).expect("guard should have probed");
    assert!(
        argv.lines().any(|l| l.contains("--check") && l.contains(consumer.to_str().unwrap())),
        "guard must probe via `apply --check ... --cwd <root>`:\n{argv}"
    );
    assert!(
        !argv.lines().any(|l| l.contains("apply") && !l.contains("--check")),
        "in-sync build must NOT run a heal `apply`:\n{argv}"
    );
    drop(tmp);
}

/// Recoverable drift: `apply --check` first fails, the heal `apply` fixes it, so
/// the re-check passes → the build FAILS with the "regenerated / re-run" message
/// (the heal happened; the retry is clean). Proves fail-closed + auto-heal.
#[test]
#[ignore]
fn guard_recoverable_drift_heals_then_fails_with_rebuild_message() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let (tmp, consumer, cargo_home, stub, sentinel, _healed) = scaffold();
    let out = build(&consumer, &cargo_home, &stub, &[("INITIAL_CHECK", "1")]);
    assert!(!out.status.success(), "drift must FAIL the build (fail-closed)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("regenerated") || stderr.contains("re-run"),
        "recoverable drift should report regenerate + rebuild.\nstderr:\n{stderr}"
    );
    // Probed, healed, then re-probed (3 invocations).
    let argv = std::fs::read_to_string(&sentinel).unwrap_or_default();
    assert!(argv.matches("--check").count() >= 2, "should probe before and after heal:\n{argv}");
    assert!(
        argv.lines().any(|l| l.contains("apply") && !l.contains("--check")),
        "should run a heal `apply`:\n{argv}"
    );
    drop(tmp);
}

/// Unrecoverable drift: the heal can't reconcile (re-check still fails) → the
/// build FAILS with the "could NOT be reconciled" message.
#[test]
#[ignore]
fn guard_unrecoverable_drift_fails_closed() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let (tmp, consumer, cargo_home, stub, sentinel, _healed) = scaffold();
    let out = build(
        &consumer,
        &cargo_home,
        &stub,
        &[("INITIAL_CHECK", "1"), ("HEAL_FAILS", "1")],
    );
    assert!(!out.status.success(), "unrecoverable drift must FAIL the build");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Assert the SPECIFIC unrecoverable message, not a generic substring: cargo's
    // "failed to run custom build command for `socket-patch-guard …`" boilerplate
    // contains "socket-patch" on ANY build-script failure, so `|| "socket-patch"`
    // would pass even if the guard failed for an unrelated reason.
    assert!(
        stderr.contains("could NOT be reconciled"),
        "unrecoverable drift should report it can't reconcile.\nstderr:\n{stderr}"
    );
    // Prove it reached the unrecoverable classification via heal-then-reprobe (not
    // an incidental build failure): ≥2 `--check` probes + a heal `apply` ran.
    let argv = std::fs::read_to_string(&sentinel).unwrap_or_default();
    assert!(
        argv.matches("--check").count() >= 2,
        "should probe before and after the heal:\n{argv}"
    );
    assert!(
        argv.lines().any(|l| l.contains("apply") && !l.contains("--check")),
        "should run a heal `apply`:\n{argv}"
    );
    drop(tmp);
}

/// Missing CLI → the probe can't run → fail-closed (no escape hatch).
#[test]
#[ignore]
fn guard_missing_cli_fails_closed() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let (tmp, consumer, cargo_home, _stub, _sentinel, _healed) = scaffold();
    let missing = tmp.path().join("does-not-exist-socket-patch");
    let out = build(&consumer, &cargo_home, &missing, &[]);
    assert!(!out.status.success(), "a missing CLI must FAIL the build (fail-closed)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Deterministic probe-error string only (the `|| "socket-patch"` escape that
    // cargo's per-crate failure boilerplate always satisfies is dropped).
    assert!(
        stderr.contains("could not run `apply --check`"),
        "missing CLI should report it can't run the check.\nstderr:\n{stderr}"
    );
    drop(tmp);
}
