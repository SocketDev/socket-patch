//! Store-class semantics for the gem multi-copy fan-out.
//!
//! `get_gem_paths` appends the `gem env` fallback homes (rvm `@global`,
//! `--user-install`, system gem dirs) after the project's bundle-path
//! stores, and the multi-copy fan-out patches EVERY copy. Patching a
//! shared home's copy is fine (vulnerable bytes are vulnerable bytes) —
//! but its FAILURE semantics must not cross store classes:
//!
//!   * copies in bundle-path stores are PRIMARY — loud-fail (unchanged);
//!   * copies in gem-env fallback homes are BEST-EFFORT once at least one
//!     bundle-store copy applied: a variant mismatch or write failure
//!     there becomes a per-copy non-fatal `Skipped` event
//!     (`gem_fallback_home_skipped`, with the path and reason), never a
//!     run failure — the copy bundler actually loads was patched;
//!   * with NO bundle-store copy (the historic fallback-only layout) the
//!     home copy IS primary: loud-fail exactly as plain apply always
//!     behaved.
//!
//! Unix-only: the fallback homes come from a fake `gem` binary on PATH.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const BASE_PURL: &str = "pkg:gem/rack@3.1.0";
const QUALIFIED_PURL: &str = "pkg:gem/rack@3.1.0?platform=ruby";
const SKIP_CODE: &str = "gem_fallback_home_skipped";

const ORIGINAL: &[u8] = b"module Rack\n  VERSION = 'VULNERABLE'\nend\n";
const MARKER: &[u8] = b"# SOCKET-PATCHED-FALLBACK\n";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn patched_bytes() -> Vec<u8> {
    let mut v = ORIGINAL.to_vec();
    v.extend_from_slice(MARKER);
    v
}

/// Fake `gem` answering `env gemdir` with `home` (and an empty `gempath`
/// failure), so the crawler's fallback resolves to exactly one home.
fn install_fake_gem(bin_dir: &Path, home: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let script = format!(
        "#!/bin/sh\nif [ \"$1\" = env ] && [ \"$2\" = gemdir ]; then\n  printf '%s\\n' \"{}\"\n  exit 0\nfi\nexit 1\n",
        home.display()
    );
    let bin = bin_dir.join("gem");
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Stage a gem copy (`<root>/gems/rack-3.1.0/lib/rack.rb` = `bytes`) plus
/// the `specifications/` marker; returns the staged file path.
fn stage_copy(root: &Path, bytes: &[u8]) -> PathBuf {
    let file = root
        .join("gems")
        .join("rack-3.1.0")
        .join("lib")
        .join("rack.rb");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, bytes).unwrap();
    std::fs::create_dir_all(root.join("specifications")).unwrap();
    file
}

fn stage_manifest(root: &Path, purl: &str) {
    let before_hash = git_sha256(ORIGINAL);
    let after_hash = git_sha256(&patched_bytes());
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "{purl}": {{
                    "uuid": "66616c6c-6261-4b63-8368-6f6d65000000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "lib/rack.rb": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "fallback-home fixture",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), patched_bytes()).unwrap();
}

struct Fixture {
    project: tempfile::TempDir,
    store_file: Option<PathBuf>,
    home_file: PathBuf,
    bin_dir: PathBuf,
    store_root: Option<PathBuf>,
}

/// Project with a Gemfile; optionally an env-`BUNDLE_PATH` store copy
/// (pristine); a gem-env fallback home copy with `home_bytes`; manifest
/// keyed by `purl`.
fn build_fixture(with_store: bool, home_bytes: &[u8], purl: &str) -> Fixture {
    let project = tempfile::tempdir().unwrap();
    let root = project.path();
    std::fs::write(root.join("Gemfile"), b"source 'https://rubygems.org'\n").unwrap();

    let store_root = with_store.then(|| root.join("bundle-store"));
    let store_file = store_root.as_ref().map(|s| stage_copy(s, ORIGINAL));

    let home = root.join("gem-home");
    let home_file = stage_copy(&home, home_bytes);

    let bin_dir = root.join("fake-bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    install_fake_gem(&bin_dir, &home);

    stage_manifest(root, purl);
    Fixture {
        project,
        store_file,
        home_file,
        bin_dir,
        store_root,
    }
}

/// Run apply with SOCKET_*/BUNDLE_* scrubbed, PATH = the fake-gem bin dir
/// only, and BUNDLE_PATH set to the store root when present.
fn run_apply(fx: &Fixture, extra: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["apply", "--offline", "--ecosystems", "gem", "--cwd"])
        .arg(fx.project.path())
        .args(extra);
    for (key, _) in std::env::vars_os() {
        let k = key.to_string_lossy();
        if (k.starts_with("SOCKET_") && k != "SOCKET_NO_CONFIG") || k.starts_with("BUNDLE_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd.env("PATH", &fx.bin_dir);
    if let Some(store_root) = &fx.store_root {
        cmd.env("BUNDLE_PATH", store_root);
    }
    let out = cmd.output().expect("run socket-patch apply");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn parse_env(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("apply must emit JSON: {e}; stdout={stdout}"))
}

fn find_skip_event<'a>(env: &'a serde_json::Value) -> Option<&'a serde_json::Value> {
    env["events"].as_array().and_then(|events| {
        events.iter().find(|e| {
            e["action"] == "skipped"
                // `with_reason` serializes its stable tag as `errorCode`.
                && e.get("errorCode").and_then(|c| c.as_str()) == Some(SKIP_CODE)
        })
    })
}

/// (a) Store copy patched + home copy that matches NO variant (foreign
/// bytes, qualified record): the home copy becomes a per-copy non-fatal
/// `Skipped` event naming its path — exit 0, `applied` counts the store
/// copy. Before the fix this failed the WHOLE run ("no matching variant
/// found", exit 1) even though the copy bundler loads patched fine.
#[test]
fn mismatched_fallback_home_copy_is_nonfatal_when_store_patched() {
    let foreign = b"totally different bytes\n";
    let fx = build_fixture(true, foreign, QUALIFIED_PURL);

    let (code, stdout, stderr) = run_apply(&fx, &["--json"]);
    let env = parse_env(&stdout);
    assert_eq!(
        code, 0,
        "a mismatched fallback-home copy must not fail the run.\nenvelope: {env}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["summary"]["applied"], 1,
        "the bundle-store copy counts as applied.\nenvelope: {env}"
    );
    assert_eq!(
        std::fs::read(fx.store_file.as_ref().unwrap()).unwrap(),
        patched_bytes(),
        "store copy must be patched"
    );
    assert_eq!(
        std::fs::read(&fx.home_file).unwrap(),
        foreign,
        "the mismatched home copy must be left untouched"
    );

    let skip = find_skip_event(&env).unwrap_or_else(|| {
        panic!("envelope must carry a skipped event with reasonCode={SKIP_CODE}.\nenvelope: {env}")
    });
    assert_eq!(skip["purl"], BASE_PURL, "envelope: {env}");
    let reason = skip["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains(
            &fx.home_file
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .display()
                .to_string()
        ) || reason.contains(&fx.home_file.display().to_string()),
        "skip reason must name the fallback-home copy path; got: {reason}"
    );
}

/// (b) Parity pin: with NO bundle-store copy, the fallback-home copy IS
/// the primary install — a mismatch there keeps the historic loud
/// failure (exit 1), exactly as plain apply behaved before #218.
#[test]
fn fallback_only_mismatch_keeps_loud_failure_parity() {
    let fx = build_fixture(false, b"totally different bytes\n", QUALIFIED_PURL);

    let (code, stdout, _stderr) = run_apply(&fx, &["--json"]);
    let env = parse_env(&stdout);
    assert_ne!(
        code, 0,
        "fallback-only mismatch must still fail the run (parity).\nenvelope: {env}"
    );
    assert!(
        find_skip_event(&env).is_none(),
        "no best-effort skip without a patched store copy.\nenvelope: {env}"
    );
}

/// (c) Both copies healthy: both patched (the multi-copy guarantee is
/// unchanged by the class split), exit 0, applied counts both.
#[test]
fn writable_fallback_home_copy_still_patched() {
    let fx = build_fixture(true, ORIGINAL, QUALIFIED_PURL);

    let (code, stdout, stderr) = run_apply(&fx, &["--json"]);
    let env = parse_env(&stdout);
    assert_eq!(code, 0, "envelope: {env}\nstderr:\n{stderr}");
    assert_eq!(
        env["summary"]["applied"], 2,
        "both copies count.\nenvelope: {env}"
    );
    assert_eq!(
        std::fs::read(fx.store_file.as_ref().unwrap()).unwrap(),
        patched_bytes()
    );
    assert_eq!(std::fs::read(&fx.home_file).unwrap(), patched_bytes());
    assert!(
        find_skip_event(&env).is_none(),
        "healthy home copies are patched, never best-effort-skipped.\nenvelope: {env}"
    );
}

/// An ATTEMPTED apply that FAILS on the fallback-home copy converts to
/// the same non-fatal per-copy skip when the store copy applied. The
/// deterministic non-root failure: an UNQUALIFIED record's home copy with
/// locally-diverged bytes under `--strict` — the singleton exemption
/// drives it past the variant gate into `apply_package_patch`, whose
/// strict mismatch policy then refuses the write. (A root-owned rvm
/// `@global` EACCES is the production shape; owner-run tests can't
/// produce it — `DirWriteGuard` defeats read-only-dir setups by design.)
/// Before the fix: a `Failed` event + exit 1 even though the copy bundler
/// loads patched fine.
#[test]
fn failing_fallback_home_copy_write_is_nonfatal_when_store_patched() {
    let mut diverged = ORIGINAL.to_vec();
    diverged.extend_from_slice(b"# local tweak\n");
    let fx = build_fixture(true, &diverged, BASE_PURL);

    let (code, stdout, stderr) = run_apply(&fx, &["--json", "--strict"]);
    let env = parse_env(&stdout);
    assert_eq!(
        code, 0,
        "a failing fallback-home write must not fail the run once the store copy applied.\nenvelope: {env}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        std::fs::read(fx.store_file.as_ref().unwrap()).unwrap(),
        patched_bytes(),
        "store copy must be patched"
    );
    assert_eq!(
        std::fs::read(&fx.home_file).unwrap(),
        diverged,
        "strict refusal leaves the diverged home copy untouched"
    );
    let skip = find_skip_event(&env).unwrap_or_else(|| {
        panic!("write failure must surface as a {SKIP_CODE} skipped event.\nenvelope: {env}")
    });
    assert_eq!(skip["purl"], BASE_PURL, "envelope: {env}");
    let failed_events = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "failed")
        .count();
    assert_eq!(
        failed_events, 0,
        "no Failed event for a best-effort home copy.\nenvelope: {env}"
    );
}
