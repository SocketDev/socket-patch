//! Coverage-gap suite for the DENO branch of `ecosystem_dispatch`.
//!
//! `tests/ecosystem_dispatch_e2e.rs` charters itself as exercising "every
//! ecosystem dispatch branch", but deno is absent from both its apply and
//! rollback halves — lcov shows the deno `scan_ecosystem!` invocation has
//! never executed with a `pkg:jsr/` PURL in any test. These two tests close
//! that charter gap using the sibling suite's own oracles (adapted copies —
//! that file is owned by another suite and must not be edited):
//!
//! * **Apply branch** — a manifest holding one `pkg:jsr/` PURL, run under
//!   `apply --offline --json --ecosystems deno` with nothing installed. The
//!   `skipped` / `package_not_installed` event for that exact PURL is the
//!   load-bearing proof of dispatch: it appears only when `partition_purls`
//!   classified the `pkg:jsr/` type to `Ecosystem::Deno` AND the
//!   `--ecosystems deno` token kept it in scope (deno is the one ecosystem
//!   whose PURL type, `jsr`, differs from its cli_name).
//!
//! * **Rollback branch** — a real, crawler-discoverable JSR cache layout
//!   (`<root>/@<scope>/<name>/<version>/`) staged with PATCHED bytes and
//!   reached via `--global-prefix` (exactly how real users point the deno
//!   crawler at a materialized JSR tree — `DenoCrawler::get_jsr_cache_paths`
//!   returns the prefix verbatim). The rollback must discover the package
//!   through `find_packages_for_rollback`'s deno branch, restore the file's
//!   ORIGINAL bytes on disk, and report `rolledBack == 1` for the exact PURL.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

const ORIGINAL: &[u8] = b"original\n";
const PATCHED: &[u8] = b"patched\n";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Compute the git-style blob SHA-256 (`sha256("blob <len>\0" + bytes)`)
/// the same way the production hashing code does.
fn git_blob_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", bytes.len()).as_bytes());
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "covgap-ecosystem-dispatch", "version": "0.0.0" }"#,
    )
    .unwrap();
}

/// Hermeticity scrub (same seed-then-scrub contract as the sibling suite):
/// hostile values for the vars that would silently change the branch under
/// test are set first, then the whole `SOCKET_*` prefix is removed — if the
/// scrub ever stops running, the seeds turn these tests red immediately.
fn scrub_socket_env(cmd: &mut Command) {
    const HOSTILE_SEEDS: &[(&str, &str)] = &[
        ("SOCKET_DRY_RUN", "true"),
        ("SOCKET_GLOBAL", "true"),
        ("SOCKET_GLOBAL_PREFIX", "/nonexistent"),
        ("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json"),
    ];
    for (k, v) in HOSTILE_SEEDS {
        cmd.env(k, v);
    }
    for (k, _) in HOSTILE_SEEDS {
        cmd.env_remove(k);
    }
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") && name != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
}

/// Write a minimal manifest with one (file-less) patch for the given PURL.
fn write_manifest(root: &Path, purl: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let body = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "dispatch test",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), body).unwrap();
}

/// Write a rollback manifest whose single file's `afterHash` matches the
/// on-disk (patched) bytes and whose `beforeHash` matches the staged
/// ORIGINAL blob. After rollback the file must hold ORIGINAL again.
fn write_rollback_manifest(root: &Path, purl: &str, file_key: &str) {
    let before_hash = git_blob_sha256(ORIGINAL);
    let after_hash = git_blob_sha256(PATCHED);
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let body = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "44444444-4444-4444-8444-444444444444",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "{file_key}": {{
          "beforeHash": "{before_hash}",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "x",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), body).unwrap();
    // Stage the BEFORE blob so rollback can restore it.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), ORIGINAL).unwrap();
}

/// Run `socket-patch apply --offline --json --ecosystems deno` in `cwd` and
/// return the exit code + parsed envelope. `DENO_DIR` is pinned to an empty
/// dir under `cwd` so the local-mode cache probe can never reach the real
/// user cache (`~/Library/Caches/deno` on macOS).
fn run_apply_deno(cwd: &Path) -> (i32, Value) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "apply",
        "--offline",
        "--json",
        "--ecosystems",
        "deno",
        "--silent",
    ])
    .current_dir(cwd);
    scrub_socket_env(&mut cmd);
    let deno_dir = cwd.join("deno-cache");
    std::fs::create_dir_all(&deno_dir).unwrap();
    cmd.env("DENO_DIR", &deno_dir);
    let out = cmd.output().expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let env: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("apply envelope must parse ({e}); stdout={stdout}"));
    (out.status.code().unwrap_or(-1), env)
}

/// Apply dispatch branch for deno: the `pkg:jsr/` PURL is classified to
/// `Ecosystem::Deno` and kept in scope by `--ecosystems deno`, so with
/// nothing installed apply must emit exactly one `skipped` /
/// `package_not_installed` event for the exact PURL (a removed or
/// mis-routed deno branch partitions the PURL away → empty events).
#[test]
fn apply_dispatch_branch_deno() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    // Deno project marker so the local-mode gate in `get_jsr_cache_paths`
    // passes and the branch actually probes cache paths (the pinned empty
    // DENO_DIR keeps that probe hermetic).
    std::fs::write(tmp.path().join("deno.json"), "{}").unwrap();
    let purl = "pkg:jsr/@__dispatch_test__/pkg@1.0.0";
    write_manifest(tmp.path(), purl);

    let (code, env) = run_apply_deno(tmp.path());

    // No package on disk for an in-scope patch => partial failure, exit 1.
    assert_eq!(
        code, 1,
        "apply --ecosystems=deno: expected exit 1 (in-scope patch, nothing installed); env={env}"
    );
    assert_eq!(env["command"], "apply", "env={env}");
    assert_eq!(env["status"], "partialFailure", "env={env}");
    assert_eq!(
        env["summary"]["skipped"].as_u64(),
        Some(1),
        "apply --ecosystems=deno: the jsr PURL must be dispatched and skipped; env={env}"
    );
    assert_eq!(env["summary"]["failed"].as_u64(), Some(0), "env={env}");
    let events = env["events"]
        .as_array()
        .unwrap_or_else(|| panic!("apply --ecosystems=deno: events missing; env={env}"));
    assert_eq!(
        events.len(),
        1,
        "apply --ecosystems=deno: expected exactly one dispatch event; env={env}"
    );
    assert!(
        events.iter().any(|e| {
            e["purl"] == purl
                && e["action"] == "skipped"
                && e["errorCode"] == "package_not_installed"
        }),
        "apply --ecosystems=deno: missing skipped/package_not_installed event for {purl}; env={env}"
    );
}

/// Rollback dispatch branch for deno: a staged JSR cache reached via
/// `--global-prefix` must be discovered by `find_packages_for_rollback`'s
/// deno branch and the patched file restored to its ORIGINAL bytes.
#[test]
fn rollback_dispatch_branch_deno() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_root_package_json(root);

    // JSR cache layout: <prefix>/@<scope>/<name>/<version>/ — the deno
    // crawler resolves `pkg:jsr/@scope/name@version` to that dir (the scope
    // keeps its leading `@` on disk).
    let jsr_root = root.join("jsr-root");
    let pkg_dir = jsr_root
        .join("@__rollback_dispatch__")
        .join("pkg")
        .join("1.0.0");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    let verify_file = pkg_dir.join("mod.ts");
    std::fs::write(&verify_file, PATCHED).unwrap();

    let purl = "pkg:jsr/@__rollback_dispatch__/pkg@1.0.0";
    write_rollback_manifest(root, purl, "mod.ts");

    let mut cmd = Command::new(binary());
    cmd.args([
        "rollback",
        "--offline",
        "--json",
        "--ecosystems",
        "deno",
        "--silent",
        "--global-prefix",
        jsr_root.to_str().unwrap(),
    ])
    .current_dir(root);
    scrub_socket_env(&mut cmd);
    let out = cmd.output().expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let env: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("rollback envelope must parse ({e}); stdout={stdout}"));
    let code = out.status.code().unwrap_or(-1);

    assert_eq!(code, 0, "rollback --ecosystems=deno: expected exit 0; env={env}");
    assert_eq!(
        env["status"], "success",
        "rollback --ecosystems=deno: expected success; env={env}"
    );
    assert_eq!(
        env["rolledBack"].as_u64(),
        Some(1),
        "rollback --ecosystems=deno: must roll back exactly the one staged jsr package; env={env}"
    );
    assert_eq!(env["failed"].as_u64(), Some(0), "env={env}");
    assert_eq!(
        env["alreadyOriginal"].as_u64(),
        Some(0),
        "rollback --ecosystems=deno: package was patched, not already-original; env={env}"
    );
    let results = env["results"]
        .as_array()
        .unwrap_or_else(|| panic!("rollback --ecosystems=deno: results missing; env={env}"));
    assert_eq!(
        results.len(),
        1,
        "rollback --ecosystems=deno: exactly one rolled-back package (proves the deno crawler \
         discovered it); env={env}"
    );
    assert_eq!(
        results[0]["purl"],
        Value::from(purl),
        "rollback --ecosystems=deno: rolled-back PURL mismatch; env={env}"
    );
    assert_eq!(results[0]["success"], true, "env={env}");
    assert!(
        results[0]["filesRolledBack"]
            .as_array()
            .is_some_and(|a| !a.is_empty()),
        "rollback --ecosystems=deno: must list at least one rolled-back file; env={env}"
    );

    // The decisive check: the on-disk bytes are restored to ORIGINAL.
    let restored = std::fs::read(&verify_file).unwrap();
    assert_eq!(
        restored, ORIGINAL,
        "rollback --ecosystems=deno: {} was not restored to its original bytes",
        verify_file.display()
    );
}
