//! R&D artifact (NOT shipped behavior): empirically verifies the *same-tick
//! auto-heal* mechanism for the project-local cargo patch backend.
//!
//! Question: if a patched **copy** has a normal dependency on the guard, and the
//! guard's `build.rs` rewrites the copy's source (the "heal"), does cargo compile
//! the *healed* source in the **same** `cargo build` — or only on the next one?
//!
//! This scaffolds a minimal 3-crate workspace that models the mechanism without
//! any `socket-patch` / network involvement:
//!   * `g` stands in for `socket-patch-guard`; its `build.rs` reads `value.txt`
//!     (the "manifest") and rewrites `c/src/lib.rs` (the "heal"), then proceeds.
//!   * `c` stands in for a patched copy; it has `[dependencies] g`, so cargo runs
//!     `g`'s build script *before* compiling `c`.
//!   * `consumer` depends on `c` and prints `c::v()`.
//!
//! Empirical result (cargo 1.93.1, macOS): build #1 prints the value `g` wrote
//! (`111`) — NOT the `0` that was on disk — proving cargo compiled the healed
//! source same-tick. Changing `value.txt` and building once flips the printed
//! value in a single build. With no change, `c` is a cached no-op (no recompile),
//! so steady-state builds carry zero overhead. See `SAME_TICK_HEAL_RND.md`.
//!
//! `#[ignore]`d because it shells out to a real `cargo`. `#[cfg(unix)]` only to
//! keep path/permission handling simple; the mechanism is not platform-specific.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

fn has_cargo() -> bool {
    Command::new("cargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// The body `g`'s build.rs derives for a given manifest value. Mirrors the
/// `format!` in the inline build script so the test's expectation is computed
/// independently of whatever happens to be on disk (not copied from output).
fn healed_body(value: &str) -> String {
    format!("pub fn v() -> u32 {{ {value} }}\n")
}

/// Build the consumer; return (stdout of the run binary, stderr of `cargo build`).
fn build_and_run(ws: &Path) -> (String, String) {
    let build = Command::new("cargo")
        .args(["build", "-p", "consumer"])
        .current_dir(ws)
        .output()
        .expect("cargo build");
    assert!(
        build.status.success(),
        "cargo build failed:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let run = Command::new(ws.join("target/debug/consumer"))
        .output()
        .expect("run consumer");
    (
        String::from_utf8_lossy(&run.stdout).trim().to_string(),
        String::from_utf8_lossy(&build.stderr).to_string(),
    )
}

#[test]
#[ignore = "R&D spike; shells out to a real cargo"]
fn copy_dep_on_guard_heals_same_tick() {
    if !has_cargo() {
        eprintln!("SKIP: cargo not on PATH");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path();
    for d in ["g/src", "c/src", "consumer/src"] {
        std::fs::create_dir_all(ws.join(d)).unwrap();
    }

    write(
        &ws.join("Cargo.toml"),
        "[workspace]\nmembers = [\"g\", \"c\", \"consumer\"]\nresolver = \"2\"\n",
    );
    // The "manifest": the value the heal should propagate into the copy.
    write(&ws.join("value.txt"), "111\n");

    write(
        &ws.join("g/Cargo.toml"),
        "[package]\nname = \"g\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    );
    write(&ws.join("g/src/lib.rs"), "");
    // The guard's heal: rewrite the copy's source from the manifest, idempotently,
    // then proceed. `rerun-if-changed=value.txt` makes it a cached no-op when the
    // manifest is unchanged.
    write(
        &ws.join("g/build.rs"),
        r#"use std::io::Write;
fn main() {
    let v = std::fs::read_to_string("../value.txt").unwrap().trim().to_string();
    let body = format!("pub fn v() -> u32 {{ {v} }}\n");
    let target = "../c/src/lib.rs";
    if std::fs::read_to_string(target).unwrap_or_default() != body {
        std::fs::File::create(target).unwrap().write_all(body.as_bytes()).unwrap();
    }
    println!("cargo:rerun-if-changed=../value.txt");
}
"#,
    );

    // The patched copy depends on the guard (normal dep) → cargo builds the guard
    // (runs its build script) before compiling the copy.
    write(
        &ws.join("c/Cargo.toml"),
        "[package]\nname = \"c\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ng = { path = \"../g\" }\n",
    );
    // Deliberately STALE on disk: if cargo compiled this verbatim, the consumer
    // would print 0. The heal rewrites it before compilation.
    let copy_src = ws.join("c/src/lib.rs");
    write(&copy_src, "pub fn v() -> u32 { 0 }\n");
    // Baseline guard: the discriminator only works if the source genuinely
    // starts stale (== 0) and DIFFERS from the value the heal will write.
    // Otherwise build #1 could print 111 with no heal at all.
    assert_eq!(
        read(&copy_src),
        "pub fn v() -> u32 { 0 }\n",
        "precondition: copy source must start STALE (0)"
    );
    assert_ne!(
        read(&copy_src),
        healed_body("111"),
        "precondition: stale source must differ from the healed body"
    );

    write(
        &ws.join("consumer/Cargo.toml"),
        "[package]\nname = \"consumer\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nc = { path = \"../c\" }\n",
    );
    write(
        &ws.join("consumer/src/main.rs"),
        "fn main() { println!(\"{}\", c::v()); }\n",
    );

    // Build #1: on-disk copy says 0; the heal writes 111. Same-tick ⇒ prints 111.
    let (out, stderr) = build_and_run(ws);
    assert_eq!(out, "111", "same-tick heal failed: copy compiled the STALE source");
    // The "111" must come from compiling the healed source IN THIS BUILD — a fresh
    // workspace has no prior artifacts, so both the guard and the copy must compile
    // from scratch here. If either is silently cached, the same-tick claim is unproven.
    assert!(
        stderr.contains("Compiling g "),
        "fresh build #1 must compile the guard:\n{stderr}"
    );
    assert!(
        stderr.contains("Compiling c "),
        "fresh build #1 must compile the copy (not a cached artifact):\n{stderr}"
    );
    // The heal must have physically rewritten the stale source to the healed body.
    assert_eq!(
        read(&copy_src),
        healed_body("111"),
        "heal did not rewrite the copy source on disk"
    );

    // Steady state: nothing changed ⇒ the copy must NOT recompile (zero overhead).
    let (out, stderr) = build_and_run(ws);
    assert_eq!(out, "111");
    assert!(
        !stderr.contains("Compiling c "),
        "unchanged build should be cached, but recompiled the copy:\n{stderr}"
    );
    // The cached no-op must leave the healed source intact (not revert to stale).
    assert_eq!(
        read(&copy_src),
        healed_body("111"),
        "steady-state build must leave the healed source intact"
    );

    // Change the "manifest"; ONE build must flip the value same-tick.
    write(&ws.join("value.txt"), "222\n");
    // Sanity: at this point the on-disk copy still reflects the OLD value, so a
    // "222" result can only come from this single build re-healing + recompiling.
    assert_eq!(read(&copy_src), healed_body("111"), "copy should still hold old value pre-build");
    let (out, stderr) = build_and_run(ws);
    assert_eq!(out, "222", "manifest change did not take effect in a single build");
    assert!(
        stderr.contains("Compiling c "),
        "a manifest change must recompile the copy:\n{stderr}"
    );
    assert_eq!(
        read(&copy_src),
        healed_body("222"),
        "manifest change must re-heal the copy source on disk"
    );
}
