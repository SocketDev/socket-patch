//! Multi-copy apply/rollback regression (P0 silent partial).
//!
//! When two REAL on-disk copies of the SAME `name@version` exist in a
//! `node_modules` tree (an npm nested duplicate, a diamond dependency, a
//! `file:` dup), agent-mode `apply` used to patch only ONE copy and report
//! `success` with no signal the other copy was left with pristine
//! (vulnerable) bytes — a false success for a security tool.
//!
//! These tests build such a tree by hand (no package manager needed, so
//! they are hermetic and offline), hand-stage a `.socket/` manifest + blob,
//! run the REAL `apply` / `rollback` flow through the built binary, and
//! assert EVERY physical copy is patched (and later restored) AND that the
//! JSON summary counts every copy.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

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

/// Write `node_modules/.../<name>/{package.json,index.js}` at the given
/// `pkg_dir` (which already encodes the nesting), returning the index.js path.
fn write_copy(pkg_dir: &Path, name: &str, version: &str, index_bytes: &[u8]) -> PathBuf {
    std::fs::create_dir_all(pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    let index = pkg_dir.join("index.js");
    std::fs::write(&index, index_bytes).unwrap();
    index
}

fn stage_manifest_and_blob(
    root: &Path,
    purl: &str,
    before_hash: &str,
    after_hash: &str,
    patched: &[u8],
) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "{purl}": {{
                    "uuid": "multicopy-uuid-0000",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "multi-copy fixture",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(after_hash), patched).unwrap();
}

/// Lay down a root project with TWO real copies of `dupvuln@1.0.0`:
/// a hoisted root copy and a nested copy under `parent`. Returns
/// `(root, index_a, index_b, before_hash, after_hash, patched_bytes)`.
fn build_two_copy_tree(tmp: &Path) -> (PathBuf, PathBuf, PathBuf, String, String, Vec<u8>) {
    let name = "dupvuln";
    let version = "1.0.0";
    let purl = "pkg:npm/dupvuln@1.0.0";
    let original = b"module.exports = function(){ return 'VULNERABLE'; };\n";
    let mut patched = original.to_vec();
    patched.extend_from_slice(b"// SOCKET-PATCHED-MULTICOPY\n");
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(&patched);
    assert_ne!(before_hash, after_hash, "fixture must be non-degenerate");

    std::fs::write(
        tmp.join("package.json"),
        r#"{ "name": "multicopy-root", "version": "0.0.0" }"#,
    )
    .unwrap();

    // Copy A — hoisted at the root node_modules.
    let index_a = write_copy(
        &tmp.join("node_modules").join(name),
        name,
        version,
        original,
    );
    // Copy B — a genuine second physical copy nested under `parent`.
    let index_b = write_copy(
        &tmp.join("node_modules")
            .join("parent")
            .join("node_modules")
            .join(name),
        name,
        version,
        original,
    );
    // `parent` itself so the nested copy has a plausible owner.
    write_copy(
        &tmp.join("node_modules").join("parent"),
        "parent",
        "1.0.0",
        b"module.exports = require('dupvuln');\n",
    );

    stage_manifest_and_blob(tmp, purl, &before_hash, &after_hash, &patched);

    (
        tmp.to_path_buf(),
        index_a,
        index_b,
        before_hash,
        after_hash,
        patched,
    )
}

fn run_apply(root: &Path) -> (i32, serde_json::Value) {
    let out = Command::new(binary())
        .args([
            "apply",
            "--json",
            "--offline",
            "--ecosystems",
            "npm",
            "--cwd",
            root.to_str().unwrap(),
        ])
        .output()
        .expect("run apply");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("apply must emit JSON: {e}; stdout={stdout}"));
    (code, v)
}

#[test]
fn apply_patches_every_on_disk_copy_of_a_duplicated_package() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, index_a, index_b, before_hash, after_hash, patched) =
        build_two_copy_tree(tmp.path());

    // Pristine pre-check: neither copy carries the marker yet.
    for f in [&index_a, &index_b] {
        let bytes = std::fs::read(f).unwrap();
        assert_eq!(git_sha256(&bytes), before_hash, "pre-apply copy at {f:?}");
    }

    let (code, v) = run_apply(&root);
    assert_eq!(code, 0, "apply must succeed; envelope={v}");
    assert_eq!(v["status"], "success", "envelope={v}");

    // THE security guarantee: BOTH physical copies must now be patched
    // byte-for-byte. Before the fix, only copy A was written and copy B
    // stayed VULNERABLE while the run still reported success.
    for (label, f) in [("A(root)", &index_a), ("B(nested)", &index_b)] {
        let bytes = std::fs::read(f).unwrap();
        assert_eq!(
            bytes, patched,
            "copy {label} at {f:?} was NOT patched (silent partial)"
        );
        assert_eq!(
            git_sha256(&bytes),
            after_hash,
            "copy {label} at {f:?} does not hash to afterHash"
        );
    }

    // The summary must COUNT both copies — one Applied event per physical
    // copy — so the envelope carries a signal that a second copy existed.
    assert_eq!(
        v["summary"]["applied"], 2,
        "summary must count both patched copies; envelope={v}"
    );
    let applied_events = v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["action"] == "applied" && e["purl"] == "pkg:npm/dupvuln@1.0.0")
        .count();
    assert_eq!(
        applied_events, 2,
        "one applied event per physical copy; envelope={v}"
    );
}

#[test]
fn rollback_restores_every_on_disk_copy_of_a_duplicated_package() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, index_a, index_b, before_hash, after_hash, patched) =
        build_two_copy_tree(tmp.path());

    // Stage the before-blob so rollback can restore in place (the scan
    // pipeline only caches after-blobs; rollback needs the before-blob).
    let original: Vec<u8> = {
        let mut o = patched.clone();
        // recover the original by stripping the marker suffix
        let marker = b"// SOCKET-PATCHED-MULTICOPY\n";
        o.truncate(o.len() - marker.len());
        o
    };
    assert_eq!(git_sha256(&original), before_hash);
    std::fs::write(
        root.join(".socket").join("blobs").join(&before_hash),
        &original,
    )
    .unwrap();

    // Apply first so both copies are patched.
    let (code, _v) = run_apply(&root);
    assert_eq!(code, 0);
    for f in [&index_a, &index_b] {
        assert_eq!(std::fs::read(f).unwrap(), patched, "precondition: patched {f:?}");
    }

    // Now roll back and assert EVERY copy is restored to pristine bytes.
    let out = Command::new(binary())
        .args([
            "rollback",
            "--json",
            "--offline",
            "--yes",
            "--ecosystems",
            "npm",
            "--cwd",
            root.to_str().unwrap(),
        ])
        .output()
        .expect("run rollback");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("rollback must emit JSON: {e}; stdout={stdout}"));
    assert_eq!(code, 0, "rollback must succeed; envelope={v}");

    for (label, f) in [("A(root)", &index_a), ("B(nested)", &index_b)] {
        let bytes = std::fs::read(f).unwrap();
        assert_eq!(
            bytes, original,
            "copy {label} at {f:?} was NOT restored (rollback left a patched copy)"
        );
        assert_eq!(git_sha256(&bytes), before_hash, "copy {label} restore hash");
    }
    // Guard against the fixture asserting nothing.
    assert_ne!(before_hash, after_hash);
}
