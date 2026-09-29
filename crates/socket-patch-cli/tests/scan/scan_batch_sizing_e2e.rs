//! How `scan` sizes its batch requests: unset, `--batch-size` follows the
//! endpoint (500 purls per POST on the authenticated API — the server's own
//! per-request maximum — and 100 on the public proxy); a given size
//! (`--batch-size` or `SOCKET_BATCH_SIZE`) wins on either; a chunk whose
//! body would exceed 256 KiB is split into consecutive smaller chunks; and a
//! mid-run downgrade to the proxy keeps the chunk boundaries the run started
//! with.
//!
//! Subprocess runs scrub the `SOCKET_*` environment (the
//! `scan_ordered_concurrency_e2e.rs::scrubbed_cli` pattern) so ambient
//! configuration cannot reroute the branch under test.

use std::path::Path;
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const AUTH_BATCH_ROUTE: &str = "/v0/orgs/test-org/patches/batch";
const PROXY_BATCH_ROUTE: &str = "/patch/batch";
/// The body cap `scan` splits at (the public proxy's own limit).
const BODY_CAP: usize = 256 * 1024;

fn scrubbed_cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && name != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&key);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

/// `scan --json` in `cwd`: authenticated against `server` when `token`,
/// else token-less against `server` as the public proxy (the authenticated
/// base is unroutable, so a stray authenticated request fails the run).
fn run_scan(
    cwd: &Path,
    server: &str,
    token: bool,
    args: &[&str],
    env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = scrubbed_cli();
    cmd.arg("scan")
        .args(["--json", "--cwd", cwd.to_str().unwrap()])
        .args(args)
        .env("SOCKET_NO_CONFIG", "1");
    if token {
        cmd.args([
            "--api-url",
            server,
            "--api-token",
            "fake-token-for-test",
            "--org",
            ORG,
        ]);
    } else {
        cmd.args(["--api-url", "http://127.0.0.1:1", "--proxy-url", server])
            .env("SOCKET_NO_API_TOKEN", "1");
    }
    for (key, value) in env {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An npm project with `n` installed packages whose names are padded to
/// `name_len` characters.
fn write_project(root: &Path, n: usize, name_len: usize) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "consumer", "version": "0.0.0" }"#,
    )
    .unwrap();
    for i in 0..n {
        let head = format!("pkg{i:05}-");
        let name = format!("{head}{}", "x".repeat(name_len.saturating_sub(head.len())));
        let dir = root.join("node_modules").join(&name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("package.json"),
            format!(r#"{{ "name": "{name}", "version": "1.0.0" }}"#),
        )
        .unwrap();
    }
}

async fn empty_batch_server(route: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    server
}

/// Each batch POST's body, in arrival order.
async fn batch_bodies(server: &MockServer, route: &str) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .into_iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == route)
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

fn components(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).expect("batch body");
    v["components"]
        .as_array()
        .expect("components")
        .iter()
        .map(|c| c["purl"].as_str().unwrap().to_string())
        .collect()
}

/// The chunk sizes of a run's batch POSTs, largest first (the chunks run
/// concurrently, so arrival order is not chunk order).
fn sizes(bodies: &[String]) -> Vec<usize> {
    let mut sizes: Vec<usize> = bodies.iter().map(|b| components(b).len()).collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    sizes
}

/// One run of `scan` with `args`, returning its batch bodies.
async fn bodies_of(root: &Path, token: bool, args: &[&str], env: &[(&str, &str)]) -> Vec<String> {
    let route = if token {
        AUTH_BATCH_ROUTE
    } else {
        PROXY_BATCH_ROUTE
    };
    let server = empty_batch_server(route).await;
    let (code, stdout, stderr) = run_scan(root, &server.uri(), token, args, env);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("scan --json envelope");
    assert_eq!(v["status"], "success", "{stdout}");
    batch_bodies(&server, route).await
}

/// Unset on the authenticated API: 500 purls per POST, cut at the same
/// place a one-chunk run lists them (chunk 0 is the first 500 of the crawl
/// order, chunk 1 the rest).
#[tokio::test]
async fn authenticated_default_is_500_per_batch() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), 501, 12);

    let bodies = bodies_of(tmp.path(), true, &[], &[]).await;
    assert_eq!(sizes(&bodies), vec![500, 1]);

    let whole = bodies_of(tmp.path(), true, &["--batch-size", "1000"], &[]).await;
    assert_eq!(whole.len(), 1);
    let order = components(&whole[0]);
    let mut chunks: Vec<Vec<String>> = bodies.iter().map(|b| components(b)).collect();
    chunks.sort_by_key(|c| std::cmp::Reverse(c.len()));
    assert_eq!(chunks.concat(), order, "same purls, same order, cut at 500");
}

/// Unset on the public proxy: 100 purls per POST, as before.
#[tokio::test]
async fn proxy_default_stays_100_per_batch() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), 101, 12);

    let bodies = bodies_of(tmp.path(), false, &[], &[]).await;
    assert_eq!(sizes(&bodies), vec![100, 1]);
}

/// A given size wins on both endpoints, from the flag or from
/// `SOCKET_BATCH_SIZE` (which the parser honors like the flag).
#[tokio::test]
async fn an_explicit_batch_size_wins_on_either_endpoint() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), 20, 12);

    for token in [true, false] {
        let flag = bodies_of(tmp.path(), token, &["--batch-size", "7"], &[]).await;
        assert_eq!(sizes(&flag), vec![7, 7, 6], "flag, token={token}");
        let env = bodies_of(tmp.path(), token, &[], &[("SOCKET_BATCH_SIZE", "7")]).await;
        assert_eq!(sizes(&env), vec![7, 7, 6], "env, token={token}");
    }
}

/// A chunk whose body would pass 256 KiB is split: every POST fits, and
/// together they carry every purl exactly once.
#[tokio::test]
async fn an_oversize_chunk_is_split_at_the_body_cap() {
    let tmp = tempfile::tempdir().unwrap();
    // 1,300 purls of ~226 body bytes each: ~290 KiB in one 5,000-purl chunk.
    write_project(tmp.path(), 1300, 200);

    let bodies = bodies_of(tmp.path(), true, &["--batch-size", "5000"], &[]).await;
    assert_eq!(bodies.len(), 2, "{:?}", sizes(&bodies));
    for body in &bodies {
        assert!(body.len() <= BODY_CAP, "{} bytes", body.len());
    }
    let mut all: Vec<String> = bodies.iter().flat_map(|b| components(b)).collect();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 1300);
}

/// A 401 from the authenticated batch endpoint downgrades the run to the
/// public proxy, which then gets the SAME 500-purl chunks: the failed chunk
/// retried as-is, the rest as cut. The downgrade does not re-chunk at the
/// proxy's own 100-purl default (every chunk is within the proxy's body cap
/// by construction), it warns once, and the run still succeeds.
#[tokio::test]
async fn a_mid_run_downgrade_keeps_the_500_purl_chunks() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), 1001, 12);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(AUTH_BATCH_ROUTE))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(PROXY_BATCH_ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let mut cmd = scrubbed_cli();
    cmd.arg("scan")
        .args(["--json", "--cwd", tmp.path().to_str().unwrap()])
        .args(["--api-url", &server.uri(), "--proxy-url", &server.uri()])
        .args(["--api-token", "fake-token-for-test", "--org", ORG])
        .env("SOCKET_NO_CONFIG", "1");
    let out = cmd.output().expect("run socket-patch scan");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={stdout} stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("scan --json envelope");
    assert_eq!(v["status"], "success", "{stdout}");

    let auth = batch_bodies(&server, AUTH_BATCH_ROUTE).await;
    assert_eq!(
        sizes(&auth),
        vec![500],
        "the first chunk goes alone, then downgrades"
    );
    let proxy = batch_bodies(&server, PROXY_BATCH_ROUTE).await;
    assert_eq!(
        sizes(&proxy),
        vec![500, 500, 1],
        "the proxy gets the run's own chunks, not a 100-purl re-chunk"
    );
    assert_eq!(
        components(&auth[0]),
        components(&proxy[0]),
        "the failed chunk is retried as-is, first"
    );
    assert_eq!(
        stderr
            .matches("falling back to public patch API proxy")
            .count(),
        1,
        "{stderr}"
    );
}
