//! Integration tests for `apply`'s state invariants.
//!
//! These lock down two contracts that make `apply` safe to run from
//! deploy hooks and CI pipelines:
//!
//! 1. `apply` is read-only against `.socket/`. Even when fetching missing
//!    sources over the network, downloaded bytes go to an OS tempdir and
//!    `.socket/` itself is byte-identical before and after the run.
//! 2. `apply --offline` against a manifest with no usable local source
//!    surfaces a `partial_failure` JSON envelope and exits non-zero —
//!    the documented airgap behavior.
//!
//! Both tests run fully offline: no network calls, no real package
//! installs. The manifest references a synthetic PURL that the npm
//! crawler won't match, which trips the "no packages found / offline"
//! branches and exercises the invariants without needing a real fixture.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Minimal manifest with one synthetic patch entry. The PURL points at a
/// package that won't be found on disk; the `afterHash` blob is missing
/// from `.socket/blobs/`. This forces every branch we want to test —
/// `--offline` bails out, and the no-mutation invariant holds because
/// nothing actually runs.
const MANIFEST_JSON: &str = r#"{
  "patches": {
    "pkg:npm/__invariant_test_pkg__@9.9.9": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/index.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic invariant test patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn write_project(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), MANIFEST_JSON).expect("write manifest");
    // Pre-create the blobs dir with a sentinel file so the recursive
    // hash has something stable to chew on. Apply must not delete or
    // alter this file.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(
        blobs.join("sentinel"),
        b"do not modify me",
    )
    .expect("write sentinel");
    // Empty node_modules so the npm crawler returns nothing.
    std::fs::create_dir_all(root.join("node_modules")).expect("create node_modules");
    // A package.json so the crawler considers this a project root.
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"invariant-test","version":"0.0.0"}"#,
    )
    .expect("write package.json");
}

/// Recursive, stable hash of every regular file under `dir`. Combines
/// each file's relative path and bytes into a single SHA-256 so any
/// change — adding, removing, or rewriting a file — flips the digest.
///
/// Excludes `apply.lock` (advisory lock file created by `apply` /
/// `rollback` / `repair` / `remove`). That file is deliberate
/// ephemeral session state — not patch content — and persists by
/// design so subsequent runs can re-flock the same inode without a
/// create race. The "apply is read-only against .socket/" invariant
/// is about the patch payload (manifest, blobs, diffs, packages),
/// not session metadata.
fn dir_hash(dir: &Path) -> String {
    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    collect_files(dir, dir, &mut files);
    files.retain(|(rel, _)| rel.file_name().and_then(|n| n.to_str()) != Some("apply.lock"));
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (rel, bytes) in files {
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update(b"\0");
        hasher.update(&bytes);
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

fn collect_files(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            collect_files(root, &path, out);
        } else if file_type.is_file() {
            let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
            if let Ok(bytes) = std::fs::read(&path) {
                out.push((rel, bytes));
            }
        }
    }
}

fn run_apply(cwd: &Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["apply", "--json"];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn offline_with_missing_source_emits_partial_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let (code, stdout) = run_apply(tmp.path(), &["--offline", "--silent"]);

    // Exit code 1 is contract: any patch without a usable source under
    // `--offline` flips the run to partialFailure.
    assert_eq!(code, 1, "unexpected exit code; stdout=\n{stdout}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["status"], "partialFailure",
        "expected status=partialFailure, got {v}"
    );
    // No patches applied; the failed count comes from the summary block.
    assert_eq!(v["summary"]["applied"], 0);
    assert_eq!(v["summary"]["failed"], 0);
}

#[test]
fn apply_does_not_mutate_socket_dir_offline() {
    // Even on the failure path (offline + missing source), apply must
    // not touch `.socket/`. The directory hash should match exactly.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let before = dir_hash(&tmp.path().join(".socket"));
    let (code, _stdout) = run_apply(tmp.path(), &["--offline", "--silent"]);
    let after = dir_hash(&tmp.path().join(".socket"));

    assert_eq!(code, 1, "offline+missing should exit 1");
    assert_eq!(
        before, after,
        "apply --offline must not mutate .socket/; hash changed"
    );
}

#[test]
fn apply_does_not_mutate_socket_dir_when_no_packages_match() {
    // Same hash invariant when not offline. With no packages installed
    // and a synthetic PURL, apply's "no packages found" branch fires
    // before any fetch is attempted. `.socket/` must remain pristine.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let before = dir_hash(&tmp.path().join(".socket"));
    let _ = run_apply(tmp.path(), &["--silent"]);
    let after = dir_hash(&tmp.path().join(".socket"));

    assert_eq!(
        before, after,
        "apply must not mutate .socket/ on the no-match path; hash changed"
    );
}
