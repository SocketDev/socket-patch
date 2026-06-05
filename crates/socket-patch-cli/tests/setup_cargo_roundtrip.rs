#![cfg(feature = "cargo")]
//! `socket-patch setup` round-trip for the cargo guard, driven through the CLI
//! binary (no Docker, no network, no real `cargo`).
//!
//! Covers, across a 2-member workspace:
//!   * `setup` adds `socket-patch-guard` to every member's `[dependencies]` and
//!     writes `[env] SOCKET_PATCH_ROOT` into `.cargo/config.toml`;
//!   * a member's pre-existing user `build.rs` is left **byte-for-byte
//!     unchanged** (the regression the dedicated guard crate buys us);
//!   * `setup --check` exits 0 when configured;
//!   * `setup --remove` reverts the dep + `[env]`;
//!   * `setup --check` then exits non-zero.

use std::path::Path;
use std::process::Command;

#[path = "common/mod.rs"]
mod common;

const USER_BUILD_RS: &str = "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n";

/// Run the CLI binary with `args` in `cwd`, scrubbing **all** ambient
/// `SOCKET_*` env vars from the child. The shared `common::run` only strips
/// `SOCKET_API_TOKEN`; setup/check resolve discovery roots and offline gates
/// from the environment, so an ambient `SOCKET_*` could otherwise satisfy a
/// flag-driven assertion via the environment and mask a regression. This keeps
/// the round-trip flag-driven and parallel-safe.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(common::binary());
    cmd.args(args).current_dir(cwd);
    for (k, _) in std::env::vars() {
        if k.starts_with("SOCKET_") {
            cmd.env_remove(k);
        }
    }
    let out = cmd.output().expect("failed to execute socket-patch binary");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

/// Run `setup --check --json` and return `(exit_code, parsed_envelope)`.
/// Asserting on the JSON (not just the exit code) closes two holes in an
/// exit-code-only check:
///   * exit 0 is ALSO returned by `report_no_files` when discovery finds
///     nothing — so a broken cargo discovery would make "--check passes after
///     setup" pass vacuously;
///   * exit 1 conflates `needs_configuration` with `error` (a parse failure),
///     so a check that errored instead of reporting "needs setup" would still
///     look like the expected before/after-remove state.
fn check_json(cwd: &Path, root_s: &str) -> (i32, serde_json::Value) {
    let (code, stdout, stderr) = run(cwd, &["setup", "--check", "--json", "--cwd", root_s]);
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("setup --check --json did not emit parseable JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env)
}

/// Extract the per-member cargo check states and the `[env]` state from a
/// `setup --check --json` envelope, asserting the workspace shape we staged
/// (exactly two `cargo` member entries + one `cargo_env` entry, and NOTHING
/// else — no stray npm/pth entries leaking in). Returns
/// `(member_statuses, env_status)`.
fn cargo_check_states(env: &serde_json::Value) -> (Vec<String>, String) {
    let files = env
        .get("files")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| panic!("check envelope has no `files` array:\n{env}"));
    let mut members = Vec::new();
    let mut env_status: Option<String> = None;
    for f in files {
        let kind = f
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or_else(|| panic!("check entry missing string `kind`:\n{f}"));
        let status = f
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("check entry missing string `status`:\n{f}"))
            .to_string();
        match kind {
            "cargo" => members.push(status),
            "cargo_env" => {
                assert!(
                    env_status.replace(status).is_none(),
                    "more than one cargo_env entry in check envelope:\n{env}"
                );
            }
            other => panic!(
                "unexpected check entry kind {other:?} (only cargo/cargo_env expected for a \
                 pure-cargo workspace):\n{env}"
            ),
        }
    }
    assert_eq!(
        members.len(),
        2,
        "expected exactly two cargo member check entries (crates/a, crates/b):\n{env}"
    );
    let env_status =
        env_status.unwrap_or_else(|| panic!("no cargo_env check entry:\n{env}"));
    (members, env_status)
}

fn stage_workspace(root: &Path) {
    std::fs::create_dir_all(root.join("crates/a/src")).unwrap();
    std::fs::create_dir_all(root.join("crates/b/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("crates/a/Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("crates/b/Cargo.toml"),
        "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.join("crates/a/src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(root.join("crates/b/src/lib.rs"), "\n").unwrap();
    // A user-authored build.rs that setup must NOT touch.
    std::fs::write(root.join("crates/a/build.rs"), USER_BUILD_RS).unwrap();
}

// ── independent (dependency-free) TOML probes ─────────────────────────────
//
// These deliberately do NOT use the production `toml_edit`/`cargo_config`
// parsers — those are the very code paths under test, so reusing them would
// make the oracle circular. A minimal hand-rolled scan keeps the test honest:
// it can disagree with a broken writer.

/// Return the trimmed right-hand side of `key = <rhs>` inside the `[section]`
/// table of `doc`, scanning only until the next table header. `None` if the
/// section or key is absent. Top-level keys use `section = ""`.
fn toml_value_in_section(doc: &str, section: &str, key: &str) -> Option<String> {
    let header = format!("[{section}]");
    // `section == ""` means top-level (before any header).
    let mut in_section = section.is_empty();
    for line in doc.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.is_empty() {
            continue;
        }
        if t.starts_with('[') {
            in_section = t == header;
            continue;
        }
        if in_section {
            if let Some((k, v)) = t.split_once('=') {
                if k.trim() == key {
                    return Some(v.trim().to_string());
                }
            }
        }
    }
    None
}

/// Assert the guard dep is a real `[dependencies].socket-patch-guard` entry
/// carrying a plausible `"<major>.<minor>"` version string — not merely a
/// substring lurking in a comment or the wrong table.
fn assert_guard_dep_versioned(toml: &str, who: &str) {
    let rhs = toml_value_in_section(toml, "dependencies", "socket-patch-guard")
        .unwrap_or_else(|| panic!("no [dependencies].socket-patch-guard in {who}:\n{toml}"));
    // A bare version string is double-quoted; reject table/path forms that
    // would mean setup wrote something other than a published version pin.
    let inner = rhs
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or_else(|| {
            panic!("guard dep in {who} is not a quoted version string: {rhs}\n{toml}")
        });
    let parts: Vec<&str> = inner.split('.').collect();
    assert!(
        parts.len() >= 2 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        "guard dep version in {who} is not a numeric major.minor: {inner:?}\n{toml}"
    );
}

#[test]
fn setup_check_remove_check_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    stage_workspace(root);
    let root_s = root.to_str().unwrap();

    // ── check (before setup) ────────────────────────────────────────
    // A pristine workspace is unconfigured: `--check` must report that,
    // proving the check reads real state rather than hardcoding 0. We assert
    // on the JSON so exit 1 can't be satisfied by an *error* (parse failure)
    // or by "no files found" instead of the genuine "needs configuration".
    let (code, env) = check_json(root, root_s);
    assert_eq!(code, 1, "setup --check should fail before setup");
    assert_eq!(
        env.get("status").and_then(|s| s.as_str()),
        Some("needs_configuration"),
        "pristine workspace must report needs_configuration, not error/no_files:\n{env}"
    );
    assert_eq!(
        env.get("errors").and_then(|e| e.as_u64()),
        Some(0),
        "pristine check must have zero parse errors:\n{env}"
    );
    let (members, env_state) = cargo_check_states(&env);
    assert!(
        members.iter().all(|s| s == "needs_configuration"),
        "both members must report needs_configuration before setup, got {members:?}\n{env}"
    );
    assert_eq!(
        env_state, "needs_configuration",
        "[env] must report needs_configuration before setup:\n{env}"
    );

    // ── setup ───────────────────────────────────────────────────────
    let (code, stdout, stderr) = run(root, &["setup", "--cwd", root_s, "--yes"]);
    assert_eq!(
        code, 0,
        "setup failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let a_toml = std::fs::read_to_string(root.join("crates/a/Cargo.toml")).unwrap();
    let b_toml = std::fs::read_to_string(root.join("crates/b/Cargo.toml")).unwrap();
    // Guard must be a real, version-pinned [dependencies] entry in BOTH
    // members (b started with no [dependencies] table at all, so this also
    // proves setup created the table correctly).
    assert_guard_dep_versioned(&a_toml, "crates/a/Cargo.toml");
    assert_guard_dep_versioned(&b_toml, "crates/b/Cargo.toml");

    let config = std::fs::read_to_string(root.join(".cargo/config.toml")).unwrap();
    // The [env] entry must carry the exact relative-root spec the build-time
    // guard relies on (`{ value = ".", relative = true }`) — not just the key
    // name with an arbitrary/empty/absolute value.
    let env_rhs = toml_value_in_section(&config, "env", "SOCKET_PATCH_ROOT")
        .unwrap_or_else(|| panic!("[env] SOCKET_PATCH_ROOT missing:\n{config}"));
    let normalized: String = env_rhs.split_whitespace().collect::<Vec<_>>().join(" ");
    assert_eq!(
        normalized, r#"{ value = ".", relative = true }"#,
        "[env] SOCKET_PATCH_ROOT must be the relative project-root spec, got: {env_rhs}\n{config}"
    );

    // The user's build.rs is untouched, byte-for-byte.
    assert_eq!(
        std::fs::read_to_string(root.join("crates/a/build.rs")).unwrap(),
        USER_BUILD_RS,
        "setup must never modify a user's build.rs"
    );

    // ── check (configured) ──────────────────────────────────────────
    // Exit 0 alone is ambiguous (`report_no_files` also returns 0); assert the
    // envelope proves every cargo entry — both members AND the [env] — is
    // independently reported `configured`, with no errors.
    let (code, env) = check_json(root, root_s);
    assert_eq!(code, 0, "setup --check should pass after setup");
    assert_eq!(
        env.get("status").and_then(|s| s.as_str()),
        Some("configured"),
        "configured workspace must report status=configured (not no_files):\n{env}"
    );
    assert_eq!(
        env.get("needsConfiguration").and_then(|n| n.as_u64()),
        Some(0),
        "no entry should still need configuration after setup:\n{env}"
    );
    assert_eq!(
        env.get("errors").and_then(|e| e.as_u64()),
        Some(0),
        "configured check must have zero errors:\n{env}"
    );
    assert_eq!(
        env.get("configured").and_then(|c| c.as_u64()),
        Some(3),
        "all three cargo entries (2 members + [env]) must be configured:\n{env}"
    );
    let (members, env_state) = cargo_check_states(&env);
    assert!(
        members.iter().all(|s| s == "configured"),
        "both members must report configured after setup, got {members:?}\n{env}"
    );
    assert_eq!(
        env_state, "configured",
        "[env] must report configured after setup:\n{env}"
    );

    // ── remove ──────────────────────────────────────────────────────
    let (code, stdout, stderr) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes"]);
    assert_eq!(
        code, 0,
        "setup --remove failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let a_toml = std::fs::read_to_string(root.join("crates/a/Cargo.toml")).unwrap();
    let b_toml = std::fs::read_to_string(root.join("crates/b/Cargo.toml")).unwrap();
    assert!(
        toml_value_in_section(&a_toml, "dependencies", "socket-patch-guard").is_none()
            && !a_toml.contains("socket-patch-guard"),
        "guard dep should be removed from a:\n{a_toml}"
    );
    assert!(
        toml_value_in_section(&b_toml, "dependencies", "socket-patch-guard").is_none()
            && !b_toml.contains("socket-patch-guard"),
        "guard dep should be removed from b:\n{b_toml}"
    );
    let config = std::fs::read_to_string(root.join(".cargo/config.toml")).unwrap_or_default();
    assert!(
        toml_value_in_section(&config, "env", "SOCKET_PATCH_ROOT").is_none()
            && !config.contains("SOCKET_PATCH_ROOT"),
        "[env] root should be removed:\n{config}"
    );

    // build.rs still untouched after remove.
    assert_eq!(
        std::fs::read_to_string(root.join("crates/a/build.rs")).unwrap(),
        USER_BUILD_RS,
        "setup --remove must never modify a user's build.rs"
    );

    // ── check (needs configuration) ─────────────────────────────────
    // After remove we must be back to the genuine needs_configuration state —
    // not an error, and not no_files (which would also exit non-1 / 0).
    let (code, env) = check_json(root, root_s);
    assert_eq!(code, 1, "setup --check should fail after remove");
    assert_eq!(
        env.get("status").and_then(|s| s.as_str()),
        Some("needs_configuration"),
        "after remove the workspace must report needs_configuration again:\n{env}"
    );
    assert_eq!(
        env.get("errors").and_then(|e| e.as_u64()),
        Some(0),
        "post-remove check must have zero parse errors:\n{env}"
    );
    let (members, env_state) = cargo_check_states(&env);
    assert!(
        members.iter().all(|s| s == "needs_configuration"),
        "both members must report needs_configuration after remove, got {members:?}\n{env}"
    );
    assert_eq!(
        env_state, "needs_configuration",
        "[env] must report needs_configuration after remove:\n{env}"
    );
}
