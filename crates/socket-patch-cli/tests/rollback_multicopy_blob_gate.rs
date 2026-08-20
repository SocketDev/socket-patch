//! Regression: the before-blob gate's download decision must probe EVERY
//! physical copy of a duplicated package, not just the first-discovered
//! (root) copy.
//!
//! Copies drift independently: `npm install` can restore the hoisted root
//! copy to original bytes while a nested duplicate stays patched. Before-
//! blobs are downloaded on demand (the cleanup sweep retains only afterHash
//! blobs), so the gate is the ONLY place an online rollback fetches them.
//! When the gate verified only the representative first copy — which was
//! already original — it concluded no blob was needed, skipped the download,
//! and the rollback loop then failed the still-patched nested copy with
//! `MissingBlob` ("Re-download the patch to enable rollback") on a run that
//! was online and could have fetched the blob. Every retry failed the same
//! way. Twin of apply's `mismatch_blob_gaps`, which probes every copy for
//! exactly this reason.
//!
//! The stub server plays the authenticated API so the test is hermetic.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Minimal HTTP stub playing the authenticated API: serves `blob` bytes at
/// any path ending in `/patches/blob/<hash>`, 404 otherwise, and records
/// every request path. The accept thread is detached; it dies with the test
/// process. Same shape as `remove_rollback_api_overrides.rs`.
fn spawn_blob_server(hash: String, blob: Vec<u8>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
    let port = listener.local_addr().unwrap().port();
    let paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&paths);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        head.extend_from_slice(&buf[..n]);
                        if head.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            let head = String::from_utf8_lossy(&head).to_string();
            let path = head
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("")
                .to_string();
            seen.lock().unwrap().push(path.clone());
            let response = if path.ends_with(&format!("/patches/blob/{hash}")) {
                let mut r = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    blob.len()
                )
                .into_bytes();
                r.extend_from_slice(&blob);
                r
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
            };
            let _ = stream.write_all(&response);
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    });
    (port, paths)
}

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

/// Lay down a root project with TWO real copies of `gatedup@1.0.0` whose
/// bytes DIVERGE: the hoisted root copy (discovered first — root-copy-first
/// is pinned at the dispatch layer) is already at its ORIGINAL bytes, while
/// the nested copy under `parent` is still PATCHED. The before-blob is
/// deliberately absent (before-blobs are on-demand and never retained), so
/// only the gate's download can make the nested copy's restore possible.
/// Returns `(index_a, index_b, before_hash, original, patched)`.
fn build_diverged_two_copy_tree(root: &Path) -> (PathBuf, PathBuf, String, Vec<u8>, Vec<u8>) {
    let name = "gatedup";
    let version = "1.0.0";
    let purl = "pkg:npm/gatedup@1.0.0";
    let original = b"module.exports = function(){ return 'VULNERABLE'; };\n".to_vec();
    let mut patched = original.clone();
    patched.extend_from_slice(b"// SOCKET-PATCHED-GATE\n");
    let before_hash = git_sha256(&original);
    let after_hash = git_sha256(&patched);
    assert_ne!(before_hash, after_hash, "fixture must be non-degenerate");

    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "gate-root", "version": "0.0.0" }"#,
    )
    .unwrap();

    // Copy A — hoisted at the root node_modules, ALREADY ORIGINAL.
    let index_a = write_copy(
        &root.join("node_modules").join(name),
        name,
        version,
        &original,
    );
    // Copy B — a genuine second physical copy nested under `parent`,
    // STILL PATCHED.
    let index_b = write_copy(
        &root
            .join("node_modules")
            .join("parent")
            .join("node_modules")
            .join(name),
        name,
        version,
        &patched,
    );
    write_copy(
        &root.join("node_modules").join("parent"),
        "parent",
        "1.0.0",
        b"module.exports = require('gatedup');\n",
    );

    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    // The before-blob is deliberately ABSENT from .socket/blobs.
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "{purl}": {{
                    "uuid": "55555555-5555-4555-8555-555555555555",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "package/index.js": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "gate multi-copy fixture",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();

    (index_a, index_b, before_hash, original, patched)
}

/// A `rollback` command with the full `SOCKET_*` environment scrubbed and
/// hermeticity vars pinned, so behavior is driven only by the flags under
/// test (prefix scrub — an explicit list rots as flags are added).
fn rollback_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.arg("rollback").current_dir(cwd);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

/// THE regression: an online rollback must download a before-blob that only
/// a NESTED duplicate copy needs. The gate used to verify the root copy
/// alone — already original, so "no blob needed" — skip the download, and
/// the loop then failed the nested copy with `MissingBlob` while it stayed
/// patched. Retrying could never succeed.
#[test]
fn rollback_downloads_blob_needed_only_by_nested_duplicate_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (index_a, index_b, before_hash, original, patched) = build_diverged_two_copy_tree(root);

    // Pre-check the divergence the gate must see through.
    assert_eq!(std::fs::read(&index_a).unwrap(), original);
    assert_eq!(std::fs::read(&index_b).unwrap(), patched);

    let (port, seen_paths) = spawn_blob_server(before_hash.clone(), original.clone());

    let out = rollback_cmd(root)
        .args([
            "--json",
            "--ecosystems",
            "npm",
            "--api-url",
            &format!("http://127.0.0.1:{port}"),
            "--api-token",
            "test-token",
            "--org",
            "testorg",
        ])
        .output()
        .expect("run socket-patch rollback");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // The gate must have fetched the blob the nested copy needs.
    let blob_requests: Vec<String> = seen_paths
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.contains("/patches/blob/"))
        .cloned()
        .collect();
    assert_eq!(
        blob_requests,
        vec![format!("/v0/orgs/testorg/patches/blob/{before_hash}")],
        "the gate must download the before-blob the still-patched nested \
         copy needs, even though the root copy is already original.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "online rollback must succeed once the blob is fetched.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    // Both copies end at original bytes: A untouched, B restored.
    assert_eq!(
        std::fs::read(&index_a).unwrap(),
        original,
        "root copy must stay at its original bytes"
    );
    assert_eq!(
        std::fs::read(&index_b).unwrap(),
        original,
        "nested copy must be RESTORED (it was left patched when the gate \
         only probed the root copy)"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("rollback must emit JSON: {e}; stdout={stdout}"));
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(v["failed"], 0, "envelope={v}");
}

/// Anti-overshoot guard: when EVERY copy is already original, the absent
/// before-blob is needed by nothing — the gate must not fetch it or abort,
/// even offline. Pins that probing every copy doesn't turn a fully
/// rolled-back tree into a gate failure.
#[test]
fn rollback_offline_succeeds_when_every_copy_already_original() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (index_a, index_b, _before_hash, original, _patched) = build_diverged_two_copy_tree(root);
    // Rewrite the nested copy to original: no copy needs the blob now.
    std::fs::write(&index_b, &original).unwrap();

    let out = rollback_cmd(root)
        .args(["--json", "--offline", "--ecosystems", "npm"])
        .output()
        .expect("run socket-patch rollback");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "an all-already-original offline rollback must succeed.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("rollback must emit JSON: {e}; stdout={stdout}"));
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(v["failed"], 0, "envelope={v}");
    assert_eq!(std::fs::read(&index_a).unwrap(), original);
    assert_eq!(std::fs::read(&index_b).unwrap(), original);
}
