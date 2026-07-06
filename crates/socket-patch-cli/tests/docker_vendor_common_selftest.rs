//! Host-side self-tests for the shared docker vendor harness
//! (`docker_vendor_common/mod.rs`): the bash snippets are exercised with
//! plain local bash — no docker image or `docker-e2e` feature required — so
//! the guards inside `stage_patch` stay honest.
//!
//! Why this matters: `vendor` warn-and-overwrites beforeHash mismatches
//! (`commands/vendor.rs` — `vendor_content_mismatch_overwritten`), so if
//! `stage_patch` silently records a garbage hash for a typo'd fixture path,
//! the capstone suites still green while exercising the wrong code path.
//! The `|| fail "hashing ..."` guards are the only thing standing in the
//! way, and they only work if `git_blob_sha` actually reports failure.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use sha2::{Digest, Sha256};

#[path = "docker_vendor_common/mod.rs"]
mod docker_vendor_common;

use docker_vendor_common::{bash_prelude, stage_patch_fn};

/// The docker images always have coreutils `sha256sum`; macOS dev hosts may
/// only have perl `shasum`, so shim it for these local runs.
const SHA256SUM_SHIM: &str =
    "command -v sha256sum >/dev/null 2>&1 || sha256sum() { shasum -a 256 \"$@\"; }\n";

fn has_bash() -> bool {
    Command::new("bash")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

/// Run `body` under the same prelude + stage_patch definitions the docker
/// stage scripts get, with `dir` as the project root.
fn run_stage_script(dir: &Path, body: &str) -> Output {
    let script = format!(
        "{}{}{}{}",
        bash_prelude(),
        SHA256SUM_SHIM,
        stage_patch_fn(),
        body
    );
    Command::new("bash")
        .args(["-c", &script])
        .current_dir(dir)
        .output()
        .expect("failed to run bash")
}

/// Git-blob SHA-256 (`sha256("blob <len>\0" ++ bytes)`) — the hash format
/// socket-patch records in manifests.
fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// A missing before-file must abort staging at the hashing guard — not
/// silently record the hash of the bare `blob \0` header (a plausible
/// 64-hex value) in the manifest and return success.
#[test]
fn stage_patch_missing_before_file_fails_at_hashing() {
    if !has_bash() {
        eprintln!("skipping: bash not on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("after.txt"), b"patched\n").unwrap();
    let out = run_stage_script(
        dir.path(),
        "stage_patch 'pkg:npm/x@1.0.0' uuid-1 index.js ./missing-before.txt ./after.txt\n",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "stage_patch must fail when the before-file is missing\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("FAIL: hashing ./missing-before.txt"),
        "stage_patch must fail at the hashing guard\nstderr=\n{stderr}"
    );
    assert!(
        !dir.path().join(".socket/manifest.json").exists(),
        "no manifest may be written after a hashing failure"
    );
}

/// Same guard for the after-file: it must trip at hashing, not limp on to
/// the `cp` with a garbage blob name.
#[test]
fn stage_patch_missing_after_file_fails_at_hashing() {
    if !has_bash() {
        eprintln!("skipping: bash not on PATH");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("before.txt"), b"original\n").unwrap();
    let out = run_stage_script(
        dir.path(),
        "stage_patch 'pkg:npm/x@1.0.0' uuid-1 index.js ./before.txt ./missing-after.txt\n",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "stage_patch must fail when the after-file is missing\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("FAIL: hashing ./missing-after.txt"),
        "stage_patch must fail at the hashing guard\nstderr=\n{stderr}"
    );
}

/// Happy path: the manifest must carry the exact git-blob SHA-256s the
/// socket-patch binary computes (NUL byte in the `blob <len>\0` header
/// included), the after-blob must be staged under its hash, and the
/// optional ghsa/cve pair must land in `vulnerabilities`.
#[test]
fn stage_patch_records_git_blob_sha256_and_stages_blob() {
    if !has_bash() {
        eprintln!("skipping: bash not on PATH");
        return;
    }
    let before: &[u8] = b"original content\n";
    let after: &[u8] = b"patched content\n";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("before.txt"), before).unwrap();
    std::fs::write(dir.path().join("after.txt"), after).unwrap();
    let out = run_stage_script(
        dir.path(),
        "stage_patch 'pkg:npm/x@1.0.0' uuid-1 package/index.js ./before.txt ./after.txt \
         GHSA-xxxx-yyyy-zzzz CVE-2024-99999\n",
    );
    assert!(
        out.status.success(),
        "stage_patch failed\nstdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join(".socket/manifest.json")).unwrap(),
    )
    .expect("stage_patch wrote invalid JSON");
    let patch = &manifest["patches"]["pkg:npm/x@1.0.0"];
    let files = &patch["files"]["package/index.js"];
    assert_eq!(files["beforeHash"], git_sha256(before).as_str());
    assert_eq!(files["afterHash"], git_sha256(after).as_str());
    assert_eq!(
        patch["vulnerabilities"]["GHSA-xxxx-yyyy-zzzz"]["cves"],
        serde_json::json!(["CVE-2024-99999"])
    );

    let blob = dir.path().join(".socket/blobs").join(git_sha256(after));
    assert_eq!(std::fs::read(&blob).unwrap(), after, "staged blob bytes");
}
