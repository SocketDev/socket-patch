#![cfg(feature = "cargo")]
//! Integration test for `socket-patch-guard`'s build script under the
//! **fail-closed** model: a real `cargo build` of a consumer that depends on
//! the guard runs `${SOCKET_PATCH_BIN} apply --check` and, on drift, FAILS the
//! build by default (so a stale/unpatched binary is never produced).
//!
//! Uses a stub `SOCKET_PATCH_BIN` (a shell script) whose `apply --check` exit
//! code is controlled via `CHECK_EXIT`, so no real `socket-patch` or network is
//! involved. The guard is a zero-dep path dependency, so `cargo build
//! --offline` needs no downloads.
//!
//! `#[ignore]`d because it shells out to `cargo`; `#[cfg(unix)]` for the
//! shell-script stub.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Output;

#[path = "common/mod.rs"]
mod common;

use common::{cargo_run, has_command};

/// Scaffold a consumer crate that depends on the guard (path dep) + a stub
/// `socket-patch` that records every invocation's argv to `<tmp>/invoked.txt`
/// and exits `CHECK_EXIT` (default 0) for `apply --check`, 0 otherwise.
/// Returns (tmp, consumer_dir, cargo_home, stub_path, sentinel_path).
fn scaffold() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf, PathBuf) {
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
    let stub = tmp.path().join("stub-socket-patch.sh");
    // Record argv; `apply --check` exits $CHECK_EXIT (default 0); other apply
    // invocations (the warn-mode heal) exit 0.
    std::fs::write(
        &stub,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {sentinel:?}\ncase \"$*\" in\n  *--check*) exit ${{CHECK_EXIT:-0}} ;;\n  *) exit 0 ;;\nesac\n"
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    (tmp, consumer, cargo_home, stub, sentinel)
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

/// In sync (`apply --check` exits 0) → build succeeds and the guard probed via
/// `apply --check` (NOT a bare heal `apply`).
#[test]
#[ignore]
fn guard_in_sync_build_succeeds_and_probes_with_check() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let (tmp, consumer, cargo_home, stub, sentinel) = scaffold();
    let out = build(&consumer, &cargo_home, &stub, &[("CHECK_EXIT", "0")]);
    assert!(
        out.status.success(),
        "in-sync build must succeed.\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let argv = std::fs::read_to_string(&sentinel).expect("guard should have run the probe");
    assert!(
        argv.lines().any(|l| l.contains("apply")
            && l.contains("--check")
            && l.contains("--ecosystems")
            && l.contains("cargo")
            && l.contains(consumer.to_str().unwrap())),
        "guard must probe via `apply --check ... --cwd <root>`; got:\n{argv}"
    );
    drop(tmp);
}

/// Drift (`apply --check` exits non-zero) under the default (strict) mode →
/// `cargo build` FAILS, and the guard does NOT heal (no bare `apply`). This is
/// the load-bearing fail-closed proof: a stale binary is never produced.
#[test]
#[ignore]
fn guard_drift_fails_build_by_default() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let (tmp, consumer, cargo_home, stub, sentinel) = scaffold();
    let out = build(&consumer, &cargo_home, &stub, &[("CHECK_EXIT", "1")]);
    assert!(
        !out.status.success(),
        "drift must FAIL the build under the default (strict) guard"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("out of sync") || stderr.contains("socket-patch"),
        "build failure should carry the guard's drift message; stderr:\n{stderr}"
    );
    // Strict mode must NOT heal: only the `--check` probe was invoked.
    let argv = std::fs::read_to_string(&sentinel).unwrap_or_default();
    assert!(argv.contains("--check"), "guard should have probed: {argv:?}");
    assert!(
        !argv.lines().any(|l| l.contains("apply") && !l.contains("--check")),
        "strict mode must NOT run a heal `apply`; got:\n{argv}"
    );
    drop(tmp);
}

/// Drift under `SOCKET_PATCH_GUARD=warn` → build SUCCEEDS, the guard heals via a
/// bare `apply`, and a `cargo:warning` is emitted (the pre-fix lazy behavior,
/// now opt-in).
#[test]
#[ignore]
fn guard_drift_in_warn_mode_heals_and_continues() {
    if !has_command("cargo") {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let (tmp, consumer, cargo_home, stub, sentinel) = scaffold();
    let out = build(
        &consumer,
        &cargo_home,
        &stub,
        &[("CHECK_EXIT", "1"), ("SOCKET_PATCH_GUARD", "warn")],
    );
    assert!(
        out.status.success(),
        "warn mode must NOT fail on drift.\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let argv = std::fs::read_to_string(&sentinel).expect("guard should have run");
    assert!(argv.contains("--check"), "guard probes first: {argv:?}");
    assert!(
        argv.lines().any(|l| l.contains("apply") && !l.contains("--check")),
        "warn mode must run a heal `apply` after drift; got:\n{argv}"
    );
    drop(tmp);
}
