//! `rollback --silent` error-output contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only" — never "nothing":
//! an exit-1 run with zero output is undiagnosable. Regression guards for
//! the rollback error paths that gated their ONLY error print on `!silent`:
//!
//! 1. `rollback --silent` with no manifest exited 1 with zero output.
//! 2. `rollback --silent <unknown-id>` (the `rollback_patches_inner` error
//!    path) exited 1 with zero output.
//! 3. `rollback --silent --offline` with a missing before-blob (the offline
//!    bail) exited 1 with zero output.
//! 4. `rollback --silent` whose blob download fails (unreachable server)
//!    exited 1 with zero output.
//! 5. `rollback --silent` with a per-package failure (installed file
//!    modified after patching — hash mismatch) exited 1 with zero output.
//!
//! Same bug class previously fixed in `scan` (`embed_vex_human`), `setup`
//! (all three modes), `apply` (`--silent`/`--check` mutes), and `remove`.
//!
//! Stderr assertions ignore the "No SOCKET_API_TOKEN set" client warning:
//! it's printed unconditionally by `get_api_client_with_overrides` in core
//! for every command and is out of scope for `rollback`'s `--silent` gating.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Run `socket-patch rollback` in `cwd` with the entire `SOCKET_*` ambient
/// environment scrubbed (prefix scrub — ambient tokens, silent toggles, or
/// manifest redirects must not change the branch under test) and telemetry
/// disabled.
fn run_rollback(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("rollback").args(args).current_dir(cwd);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch rollback");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Non-error stderr lines: drop the unconditional core API-token warning
/// (both its lead line and its "Got: ... Continuing anyway" continuation)
/// and blank lines, keep everything else.
fn stderr_chatter(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| {
            !l.contains("SOCKET_API_TOKEN")
                && !l.contains("Continuing anyway")
                && !l.trim().is_empty()
        })
        .map(|l| l.to_string())
        .collect()
}

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Manifest with one npm patch whose before-blob is NOT staged.
fn write_missing_blob_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/__rb_silent__@1.0.0": {
                "uuid": "44444444-4444-4444-8444-444444444444",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
                }},
                "vulnerabilities": {}, "description": "x",
                "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();
}

/// `rollback --silent` with no manifest must still print the error.
#[test]
fn rollback_silent_no_manifest_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_rollback(tmp.path(), &["--silent", "--offline"]);
    assert_eq!(code, 1, "no manifest must fail; stderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.iter().any(|l| l.contains("Manifest not found")),
        "--silent must keep the manifest-not-found error (errors only, \
         never nothing); stderr was: {stderr:?}"
    );
}

/// `rollback --silent <unknown-identifier>` (the inner error path) must
/// still print why it failed.
#[test]
fn rollback_silent_unknown_identifier_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_missing_blob_manifest(tmp.path());

    let (code, stdout, stderr) = run_rollback(
        tmp.path(),
        &["--silent", "--offline", "pkg:npm/does-not-exist@9.9.9"],
    );
    assert_eq!(code, 1, "unknown identifier must fail; stderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains("No patch found matching identifier")),
        "--silent must keep the unknown-identifier error; stderr was: {stderr:?}"
    );
}

/// `rollback --silent --offline` with a missing before-blob (the offline
/// bail) must still print the error. This path returns a contentless
/// partial_failure — the eprintln IS the only diagnostic.
#[test]
fn rollback_silent_offline_missing_blob_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_missing_blob_manifest(tmp.path());

    let (code, stdout, stderr) = run_rollback(tmp.path(), &["--silent", "--offline"]);
    assert_eq!(code, 1, "offline missing blob must fail; stderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains("missing") && l.contains("--offline")),
        "--silent must keep the offline missing-blob error; stderr was: {stderr:?}"
    );
}

/// `rollback --silent` whose blob download fails (both API and proxy pinned
/// to an unroutable localhost port — nothing leaves the machine, and the
/// connection-refused failure is instant) must still print the error.
#[test]
fn rollback_silent_undownloadable_blob_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_missing_blob_manifest(tmp.path());

    let (code, stdout, stderr) = run_rollback(
        tmp.path(),
        &[
            "--silent",
            "--api-url",
            "http://127.0.0.1:1/",
            "--proxy-url",
            "http://127.0.0.1:1/",
        ],
    );
    assert_eq!(code, 1, "failed blob download must fail; stderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains("could not be downloaded")),
        "--silent must keep the undownloadable-blob error; stderr was: {stderr:?}"
    );
}

/// `rollback --silent` with a per-package failure (installed file modified
/// after patching, so neither beforeHash nor afterHash matches) must still
/// print the per-package failure line.
#[test]
fn rollback_silent_per_package_failure_keeps_error_output() {
    let before = b"original-content\n";
    let after = b"patched-content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "rb-silent", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg_dir = tmp.path().join("node_modules/mismatch-target");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "mismatch-target", "version": "1.0.0" }"#,
    )
    .unwrap();
    // Locally modified: matches NEITHER hash — rollback must fail this
    // package (HashMismatch, "modified after patching").
    std::fs::write(pkg_dir.join("index.js"), b"user-edited-content\n").unwrap();

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "pkg:npm/mismatch-target@1.0.0": {{
                    "uuid": "55555555-5555-4555-8555-555555555555",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}",
                        "afterHash":  "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "x",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), before).unwrap();

    let (code, stdout, stderr) = run_rollback(tmp.path(), &["--silent", "--offline"]);
    assert_eq!(code, 1, "per-package failure must fail; stderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains("Failed to rollback") && l.contains("mismatch-target")),
        "--silent must keep the per-package failure line; stderr was: {stderr:?}"
    );
    // The mismatched file must be left untouched (fail-safe).
    assert_eq!(
        std::fs::read(pkg_dir.join("index.js")).unwrap(),
        b"user-edited-content\n",
        "a hash-mismatched file must never be overwritten"
    );
}
