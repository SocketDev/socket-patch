//! Helpers shared across the e2e-safety test suites.
//!
//! The original e2e files (`e2e_npm.rs`, `e2e_pypi.rs`, `e2e_gem.rs`)
//! each carry their own copy of the same `binary` / `run` /
//! `assert_run_ok` / `git_sha256` helpers. Rather than refactor those
//! files in this PR, this module is an additive landing place for the
//! same surface plus the new helpers the safety suites need
//! (synthetic manifest writers, pnpm runners, cargo runners). Existing
//! suites can migrate in a follow-up.
//!
//! Each test file pulls this in with `#[path = "common/mod.rs"] mod common;`.
//!
//! `#![allow(dead_code)]` because each test file uses a different
//! subset of these helpers; the unused ones would otherwise produce
//! warnings under `-D warnings`.

#![allow(dead_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

// ── Binary discovery + invocation ─────────────────────────────────────

/// Absolute path to the built `socket-patch` binary that cargo
/// provides via the `CARGO_BIN_EXE_*` env var. Available because
/// these tests live in the same crate that produces the binary.
pub fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Quick check whether `cmd` is on PATH. Used to soft-skip
/// toolchain-dependent tests when the toolchain isn't installed
/// (CI gates the toolchain at the workflow level; this is a
/// belt-and-braces guard for local runs).
pub fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Run the CLI binary with `args`, working dir `cwd`. Returns
/// `(exit_code, stdout, stderr)`. Strips `SOCKET_API_TOKEN` from the
/// environment so apply paths default to the public proxy and tests
/// don't accidentally exercise authed endpoints.
pub fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    run_with_env(cwd, args, &[])
}

/// `run` + child-only env-var injection. Useful for tests that need
/// to flip the per-ecosystem runtime gates (`SOCKET_EXPERIMENTAL_NUGET`)
/// or override discovery roots (`NUGET_PACKAGES`, `GOMODCACHE`) without
/// touching the parent process's environment — keeps tests parallel-safe.
pub fn run_with_env(
    cwd: &Path,
    args: &[&str],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd).env_remove("SOCKET_API_TOKEN");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out: Output = cmd.output().expect("failed to execute socket-patch binary");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

/// `run` + assertion that exit code is 0. Returns `(stdout, stderr)`
/// on success; panics with a context message + both streams on
/// failure (so test logs show exactly what the binary printed).
pub fn assert_run_ok(cwd: &Path, args: &[&str], context: &str) -> (String, String) {
    let (code, stdout, stderr) = run(cwd, args);
    assert_eq!(
        code, 0,
        "{context} failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (stdout, stderr)
}

// ── Hashing ───────────────────────────────────────────────────────────

/// Compute Git-flavored SHA-256: `SHA256("blob <len>\0" ++ content)`.
/// This is the hash socket-patch records in manifests under
/// `before_hash` / `after_hash`.
pub fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Git-SHA-256 of the file at `path`. Panics if the file can't be
/// read — tests use this on paths they know exist.
pub fn git_sha256_file(path: &Path) -> String {
    let content =
        std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    git_sha256(&content)
}

/// Raw lowercase-hex SHA-256 (no Git blob framing). Used by the
/// Cargo sidecar which embeds plain digests in
/// `.cargo-checksum.json`.
pub fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

// ── Toolchain runners ─────────────────────────────────────────────────

/// Run `npm` in `cwd`, panic on non-zero exit with full output.
pub fn npm_run(cwd: &Path, args: &[&str]) {
    run_toolchain(cwd, "npm", args, &[]);
}

/// Run `pnpm` in `cwd`. Same shape as `npm_run`; `extra_env` lets
/// the caller force store-dir overrides etc.
pub fn pnpm_run(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) {
    run_toolchain(cwd, "pnpm", args, extra_env);
}

/// Run `cargo` in `cwd`. Returns the raw Output so callers can
/// inspect stdout/stderr/exit on either pass or fail — the cargo
/// e2e test wants both passing and failing cases (negative control).
pub fn cargo_run(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new("cargo");
    cmd.args(args).current_dir(cwd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run cargo")
}

fn run_toolchain(cwd: &Path, exe: &str, args: &[&str], extra_env: &[(&str, &str)]) {
    let mut cmd = Command::new(exe);
    cmd.args(args).current_dir(cwd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("failed to run {exe}: {e}"));
    assert!(
        out.status.success(),
        "{exe} {args:?} failed (exit {:?}).\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ── Project scaffolding ───────────────────────────────────────────────

/// Write a minimal package.json. Avoids `npm init -y` which rejects
/// temp dir names that start with `.` or contain invalid chars.
pub fn write_package_json(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"e2e-test","version":"0.0.0","private":true}"#,
    )
    .expect("write package.json");
}

// ── Synthetic manifest + blob construction ────────────────────────────

/// Describe a single patched-file row in a synthetic manifest.
pub struct PatchEntry<'a> {
    /// File path as recorded by the manifest (may include the
    /// `package/` prefix used by the API; apply strips it before
    /// resolving against pkg_path).
    pub file_name: &'a str,
    pub before_hash: &'a str,
    pub after_hash: &'a str,
}

/// Write a minimal `.socket/manifest.json` at `socket_dir/manifest.json`
/// describing one patch for `purl` with the given `uuid` and `files`.
///
/// Returns the path to the manifest file.
///
/// Does NOT write the `after_hash` blobs — that's `write_blob`'s
/// job, and the test gets to decide which blobs to omit (e.g. to
/// force an offline-apply failure).
pub fn write_minimal_manifest(
    socket_dir: &Path,
    purl: &str,
    uuid: &str,
    files: &[PatchEntry<'_>],
) -> PathBuf {
    std::fs::create_dir_all(socket_dir).expect("create .socket dir");
    let mut files_map = serde_json::Map::new();
    for f in files {
        files_map.insert(
            f.file_name.to_string(),
            serde_json::json!({
                "beforeHash": f.before_hash,
                "afterHash": f.after_hash,
            }),
        );
    }
    let manifest = serde_json::json!({
        "patches": {
            purl: {
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": files_map,
                "vulnerabilities": {},
                "description": "synthetic test patch",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    let path = socket_dir.join("manifest.json");
    std::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap())
        .expect("write manifest.json");
    path
}

/// Drop `content` at `<socket_dir>/blobs/<hash>`. Used to stage the
/// `after_hash` blob a synthetic manifest references so apply can
/// run fully offline.
pub fn write_blob(socket_dir: &Path, hash: &str, content: &[u8]) {
    let blobs = socket_dir.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create .socket/blobs");
    std::fs::write(blobs.join(hash), content).expect("write blob");
}

/// Parse `--json` apply output, returning the top-level JSON object
/// or panicking with the raw text on parse failure. Most safety tests
/// want to assert on specific fields (`errorCode`, `status`, etc.).
pub fn parse_json_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("failed to parse JSON envelope: {e}\nstdout:\n{stdout}"))
}

/// Extract a stringified field from a parsed JSON envelope, or None
/// if the field is missing / not a string. Convenience for the
/// `status` checks the safety tests do repeatedly.
pub fn json_string<'a>(env: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    env.get(key).and_then(|v| v.as_str())
}

/// Extract `env.error.code` from a parsed envelope. The v3.0
/// envelope shape nests the error under a top-level `error` object
/// (`{"error": {"code": "lock_held", "message": "..."}}`), not at
/// the top level. This helper centralises that lookup so individual
/// tests can stay terse.
pub fn envelope_error_code(env: &serde_json::Value) -> Option<&str> {
    env.get("error")?.get("code")?.as_str()
}

/// Extract `env.error.message` from a parsed envelope. Companion to
/// [`envelope_error_code`].
pub fn envelope_error_message(env: &serde_json::Value) -> Option<&str> {
    env.get("error")?.get("message")?.as_str()
}

/// Map a slice of `(env-var-name, env-var-value)` tuples into a
/// HashMap for callers that want a stable container.
pub fn env_map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}
