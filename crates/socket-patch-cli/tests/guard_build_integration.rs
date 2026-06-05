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

/// Read the stub's recorded invocations (one `$*` line per call), in order.
/// Fails loudly if the stub was never invoked at all.
fn invocations(sentinel: &Path) -> Vec<String> {
    std::fs::read_to_string(sentinel)
        .expect("guard should have invoked the stub at least once")
        .lines()
        .map(str::to_string)
        .collect()
}

fn is_check(line: &str) -> bool {
    line.contains("--check")
}

fn is_heal(line: &str) -> bool {
    line.contains("apply") && !line.contains("--check")
}

/// Assert an invocation carries the *full* expected arg set for `root`, not just
/// an incidental `--check`/`apply` substring. `check` selects probe vs heal.
fn assert_full_args(line: &str, root: &str, check: bool) {
    for needle in ["apply", "--offline", "--ecosystems", "cargo", "--cwd", root] {
        assert!(line.contains(needle), "invocation missing `{needle}`:\n{line}");
    }
    assert_eq!(
        line.contains("--check"),
        check,
        "unexpected --check presence (expected check={check}):\n{line}"
    );
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
    // Exactly one invocation — the read-only probe — and nothing else: an
    // in-sync build must probe once and must NOT heal. Counting (not just
    // "any heal line") closes the loophole of a duplicate/extra probe slipping
    // through, and `assert_full_args` verifies the real `apply --check
    // --offline --ecosystems cargo --cwd <root>` arg set, not a bare substring.
    let inv = invocations(&sentinel);
    assert_eq!(
        inv.len(),
        1,
        "in-sync build must probe exactly once with no heal:\n{inv:#?}"
    );
    assert!(is_check(&inv[0]), "the sole invocation must be the `apply --check` probe:\n{}", inv[0]);
    assert_full_args(&inv[0], consumer.to_str().unwrap(), true);
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
    // Assert the SPECIFIC recoverable message (a single AND, not a disjunction):
    // the heal succeeded and the user is told to re-run. Crucially it must NOT be
    // the unrecoverable message — a guard that misclassified a healed state as
    // unrecoverable would still fail the build, so checking only "did it fail"
    // (or an OR that also accepts the unrecoverable text) would let that pass.
    assert!(
        stderr.contains("regenerated"),
        "recoverable drift should report the patches were regenerated.\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("could NOT be reconciled"),
        "a recovered heal must NOT report the unrecoverable message.\nstderr:\n{stderr}"
    );
    // Exact sequence: probe (drift) → heal `apply` → re-probe (now in sync).
    // Asserting the ordered triple (not just counts) proves the heal ran
    // *between* the two probes, which is the whole recoverable contract.
    let inv = invocations(&sentinel);
    assert_eq!(inv.len(), 3, "recoverable drift = probe, heal, re-probe (3 calls):\n{inv:#?}");
    assert!(is_check(&inv[0]), "1st call must be the probe:\n{}", inv[0]);
    assert!(is_heal(&inv[1]), "2nd call must be the heal `apply`:\n{}", inv[1]);
    assert!(is_check(&inv[2]), "3rd call must be the re-probe:\n{}", inv[2]);
    let root = consumer.to_str().unwrap();
    assert_full_args(&inv[0], root, true);
    assert_full_args(&inv[1], root, false);
    assert_full_args(&inv[2], root, true);
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
    // ...and emphatically NOT the recoverable "regenerated, re-run" message — a
    // guard that healed but still reports success-style text would be wrong.
    assert!(
        !stderr.contains("regenerated"),
        "unrecoverable drift must NOT claim the patches were regenerated.\nstderr:\n{stderr}"
    );
    // Prove it reached the unrecoverable classification via the exact
    // heal-then-reprobe sequence (probe → heal → re-probe, still drift), not an
    // incidental build failure that merely happened to mention socket-patch.
    let inv = invocations(&sentinel);
    assert_eq!(inv.len(), 3, "unrecoverable drift = probe, heal, re-probe (3 calls):\n{inv:#?}");
    assert!(is_check(&inv[0]), "1st call must be the probe:\n{}", inv[0]);
    assert!(is_heal(&inv[1]), "2nd call must be the heal `apply`:\n{}", inv[1]);
    assert!(is_check(&inv[2]), "3rd call must be the re-probe:\n{}", inv[2]);
    let root = consumer.to_str().unwrap();
    assert_full_args(&inv[0], root, true);
    assert_full_args(&inv[1], root, false);
    assert_full_args(&inv[2], root, true);
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
    let (tmp, consumer, cargo_home, _stub, sentinel, _healed) = scaffold();
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
    // It must be the probe-error path, NOT a heal/drift path: with no runnable
    // CLI the guard cannot heal or reconcile anything.
    assert!(
        !stderr.contains("regenerated") && !stderr.contains("could NOT be reconciled"),
        "missing-CLI failure must be the probe-error path, not a heal path.\nstderr:\n{stderr}"
    );
    // The real (missing) bin can never have recorded an invocation; the stub
    // from scaffold() is a different path and must stay untouched.
    assert!(
        !sentinel.exists(),
        "an unrunnable CLI cannot have recorded any invocation"
    );
    drop(tmp);
}
