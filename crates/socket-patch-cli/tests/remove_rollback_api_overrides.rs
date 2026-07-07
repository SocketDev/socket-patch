//! Regression test: flag-passed API overrides must reach the blob download
//! inside `remove`'s pre-removal rollback.
//!
//! `remove` builds its own API client from `GlobalArgs::api_client_overrides()`
//! (so `--api-url` / `--api-token` / `--org` / `--proxy-url` work for its
//! telemetry client), but `rollback_patches` reconstructed a from-scratch
//! `GlobalArgs::default()` whose override fields are all empty. The
//! missing-before-blob download inside the nested rollback therefore fell
//! back to env vars / hardcoded defaults: with credentials passed as flags
//! the nested client was UNAUTHENTICATED and pointed at the public proxy,
//! so the download failed (the configured `--api-url` was never contacted —
//! and in proxied environments the request leaked outside it) and the whole
//! `remove` aborted with `rollback_failed`.
//!
//! The stub server below plays the authenticated API; `SOCKET_PROXY_URL` is
//! pointed at a dead localhost port so the buggy fallback path fails fast
//! and hermetically instead of touching the real network.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Every `SOCKET_*` env var `GlobalArgs` reads as a flag fallback — scrubbed
/// so behavior is driven only by the explicit flags under test (an ambient
/// `SOCKET_API_TOKEN` would let the buggy env-fallback path pass).
const SOCKET_ENV_VARS: &[&str] = &[
    "SOCKET_API_TOKEN",
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_URL",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_DOWNLOAD_MODE",
    "SOCKET_VENDOR_SOURCE",
    "SOCKET_VENDOR_URL",
    "SOCKET_PATCH_SERVER_URL",
    "SOCKET_OFFLINE",
    "SOCKET_STRICT",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_BREAK_LOCK",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_ONE_OFF",
    "SOCKET_SKIP_ROLLBACK",
];

/// Drift guard: the scrub must cover every env var `GlobalArgs` binds — the
/// production `GLOBAL_ARG_ENV_VARS` list is the source of truth. A var
/// missing here escapes the scrub, so an ambient value in the developer's
/// shell or CI (e.g. `SOCKET_STRICT=garbage`) aborts every invocation in
/// this file. Mirrors `cli_parse_vendor.rs`.
#[test]
fn env_scrub_covers_every_global_arg_env_var() {
    for var in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS {
        assert!(
            SOCKET_ENV_VARS.contains(var),
            "{var} is bound by GlobalArgs but missing from SOCKET_ENV_VARS — the scrub won't strip it",
        );
    }
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
/// process.
fn spawn_blob_server(hash: String, blob: Vec<u8>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
    let port = listener.local_addr().unwrap().port();
    let paths: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&paths);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            // Read until the end of the request head (GET has no body).
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

/// A localhost port with nothing listening (bind-then-drop): a connect
/// attempt is refused immediately, keeping the buggy env-fallback path fast
/// and off the real network.
fn dead_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind dead port");
    l.local_addr().unwrap().port()
}

#[test]
fn remove_rollback_downloads_missing_blob_via_flag_overrides() {
    let before = b"original-content\n";
    let before_hash = git_sha256(before);

    let (port, seen_paths) = spawn_blob_server(before_hash.clone(), before.to_vec());
    let dead = dead_port();

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    // The before-blob is deliberately ABSENT from .socket/blobs: the
    // rollback gate must download it through the flag-configured client.
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/__ovr_test__@1.0.0": {{
      "uuid": "44444444-4444-4444-8444-444444444444",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash": "1111111111111111111111111111111111111111111111111111111111111111"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic override-plumbing test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();

    let mut cmd = Command::new(binary());
    cmd.args([
        "remove",
        "pkg:npm/__ovr_test__@1.0.0",
        "--yes",
        "--api-url",
        &format!("http://127.0.0.1:{port}"),
        "--api-token",
        "test-token",
        "--org",
        "testorg",
    ])
    .current_dir(tmp.path());
    for var in SOCKET_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_PROXY_URL", format!("http://127.0.0.1:{dead}"));
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");

    let out = cmd.output().expect("run socket-patch remove");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

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
        "the missing-blob download inside remove's rollback must use the \
         flag-passed --api-url/--api-token/--org (authenticated endpoint), \
         not fall back to env/default settings.\nstdout: {stdout}\nstderr: {stderr}"
    );
    // The blob's on-disk lifecycle: it must have LANDED in .socket/blobs for
    // remove to proceed (the post-download `still_missing` re-check reads the
    // dir; exit 0 below is unreachable otherwise), and then remove's
    // unused-blob sweep deletes it again — beforeHash blobs are by design
    // downloaded on-demand and never retained (`cleanup_unused_blobs` keeps
    // only afterHash blobs, and this patch was just removed anyway).
    assert!(
        !socket.join("blobs").join(&before_hash).exists(),
        "remove's unused-blob sweep must not retain the on-demand before-blob.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "remove must succeed once the blob download works.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    let manifest_after = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    assert!(
        !manifest_after.contains("__ovr_test__"),
        "the manifest entry must be removed; manifest now: {manifest_after}"
    );
}
