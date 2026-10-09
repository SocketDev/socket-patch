//! `scan` against a patch API that throttles (HTTP 429 / 503).
//!
//! The client retries a 429 / 503 a bounded number of times
//! (`socket_patch_core::api::retry`); a request still throttled after that
//! is a real failure in the channel its siblings already use — the
//! per-batch / per-package warning (stderr for a human run, run-level
//! `warnings[]` for `--json`), or the all-failed error when nothing
//! succeeded — never a package silently missing from the envelope.
//!
//! Every throttled answer carries `Retry-After: 0`, so the subprocess
//! retries without sleeping (the backoff arithmetic itself is pinned on a
//! virtual clock in the core crate's `api_retry_e2e.rs`).

use std::path::Path;
use std::process::Command;

use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAMES: [&str; 6] = [
    "retry-alpha",
    "retry-bravo",
    "retry-charlie",
    "retry-delta",
    "retry-echo",
    "retry-foxtrot",
];
const VERSION: &str = "1.0.0";

fn purl(name: &str) -> String {
    format!("pkg:npm/{name}@{VERSION}")
}

fn uuid(idx: usize) -> String {
    format!("0000000a-0000-4000-8000-{idx:012x}")
}

fn encode_purl(purl: &str) -> String {
    purl.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
}

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

fn run_scan(cwd: &Path, api: &str, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let out = scrubbed_cli()
        .arg("scan")
        .args([
            "--cwd",
            cwd.to_str().unwrap(),
            "--api-url",
            api,
            "--api-token",
            "fake-token-for-test",
            "--org",
            ORG,
        ])
        .args(args)
        // Never reach for the real proxy.
        .env("SOCKET_PROXY_URL", api)
        .envs(env.iter().copied())
        .output()
        .expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An npm project with every name in `NAMES` installed and locked.
fn write_project(root: &Path) {
    let deps: Vec<String> = NAMES
        .iter()
        .map(|n| format!(r#""{n}": "{VERSION}""#))
        .collect();
    let deps = deps.join(", ");
    std::fs::write(
        root.join("package.json"),
        format!(r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ {deps} }} }}"#),
    )
    .unwrap();
    let mut entries = vec![format!(
        r#"    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ {deps} }} }}"#
    )];
    for name in NAMES {
        let pkg = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{ "name": "{name}", "version": "{VERSION}" }}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), b"module.exports = 1;\n").unwrap();
        entries.push(format!(
            r#"    "node_modules/{name}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{name}/-/{name}-{VERSION}.tgz",
      "integrity": "sha512-UPSTREAM{name}=="
    }}"#
        ));
    }
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            "{{\n  \"name\": \"consumer\",\n  \"version\": \"0.0.0\",\n  \"lockfileVersion\": 3,\n  \
             \"requires\": true,\n  \"packages\": {{\n{}\n  }}\n}}\n",
            entries.join(",\n")
        ),
    )
    .unwrap();
}

fn auth_batch_route() -> String {
    format!("/v0/orgs/{ORG}/patches/batch")
}

fn batch_entry(idx: usize) -> serde_json::Value {
    let p = purl(NAMES[idx]);
    serde_json::json!({
        "purl": p,
        "patches": [{
            "uuid": uuid(idx), "purl": p, "tier": "free",
            "cveIds": [], "ghsaIds": [], "severity": "high",
            "title": format!("patch for {}", NAMES[idx]),
        }]
    })
}

fn batch_body(entries: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({ "packages": entries, "canAccessPaidPatches": false })
}

fn throttled(status: u16, idx: usize) -> ResponseTemplate {
    ResponseTemplate::new(status)
        .insert_header("Retry-After", "0")
        .set_body_string(format!("busy-{}", NAMES[idx]))
}

/// Per-package batch mocks (`--batch-size 1`): package `idx` answers
/// `throttle(idx)` = `Some((status, times))` that many times first (`None`
/// times = forever), then its 200.
async fn mount_batches(
    server: &MockServer,
    throttle: impl Fn(usize) -> Option<(u16, Option<u64>)>,
) {
    for (idx, name) in NAMES.iter().enumerate() {
        let needle = format!("\"{}\"", purl(name));
        let body = || body_string_contains(needle.clone());
        if let Some((status, times)) = throttle(idx) {
            let mock = Mock::given(method("POST"))
                .and(path(auth_batch_route()))
                .and(body())
                .respond_with(throttled(status, idx))
                .with_priority(1);
            let mock = match times {
                Some(n) => mock.up_to_n_times(n),
                None => mock,
            };
            mock.mount(server).await;
        }
        Mock::given(method("POST"))
            .and(path(auth_batch_route()))
            .and(body())
            .respond_with(
                ResponseTemplate::new(200).set_body_json(batch_body(vec![batch_entry(idx)])),
            )
            .mount(server)
            .await;
    }
}

/// Per-package detail GETs for every package; `stuck` answers 429 forever.
async fn mount_details(server: &MockServer, stuck: Option<usize>) {
    for (idx, name) in NAMES.iter().enumerate() {
        let p = purl(name);
        let route = format!("/v0/orgs/{ORG}/patches/by-package/{}", encode_purl(&p));
        let template = if Some(idx) == stuck {
            throttled(429, idx)
        } else {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": uuid(idx), "purl": p,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": format!("details for {name}"),
                    "license": "MIT", "tier": "free", "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            }))
        };
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(template)
            .mount(server)
            .await;
    }
}

async fn posts_for(server: &MockServer, idx: usize) -> usize {
    let needle = format!("\"{}\"", purl(NAMES[idx]));
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| {
            r.url.path() == auth_batch_route() && String::from_utf8_lossy(&r.body).contains(&needle)
        })
        .count()
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

fn warnings(v: &serde_json::Value, code: &str) -> Vec<String> {
    v["warnings"]
        .as_array()
        .map(|w| {
            w.iter()
                .filter(|w| w["code"] == code)
                .map(|w| w["detail"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// 429 (and 503) answers that clear within the retries leave the `--json`
/// envelope byte-identical to a clean run's.
#[tokio::test]
async fn transient_throttling_is_invisible_in_the_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let clean = MockServer::start().await;
    mount_batches(&clean, |_| None).await;
    let (code0, stdout0, stderr0) = run_scan(
        tmp.path(),
        &clean.uri(),
        &["--json", "--batch-size", "1"],
        &[],
    );
    assert_eq!(code0, 0, "{stdout0}\n{stderr0}");
    assert_eq!(json(&stdout0)["packages"].as_array().unwrap().len(), 6);

    let busy = MockServer::start().await;
    mount_batches(&busy, |idx| match idx % 3 {
        0 => Some((429, Some(1))),
        1 => Some((503, Some(3))),
        _ => None,
    })
    .await;
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &busy.uri(),
        &["--json", "--batch-size", "1"],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        stdout, stdout0,
        "retried answers fold exactly like clean ones"
    );
    assert_eq!(posts_for(&busy, 0).await, 2);
    assert_eq!(posts_for(&busy, 1).await, 4, "3 retries is the default");
    assert_eq!(posts_for(&busy, 2).await, 1);
}

/// Batches still throttled after 3 retries: the run succeeds with the rest,
/// and each failed batch is a `warnings[]` entry in chunk order — the same
/// text a human run prints on stderr — instead of its packages silently
/// vanishing from `packages`.
#[tokio::test]
async fn exhausted_batches_surface_as_json_warnings() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    // Throttle two packages forever: one 429, one 503.
    let stuck = |idx: usize| match idx {
        1 => Some((429, None)),
        4 => Some((503, None)),
        _ => None,
    };
    mount_batches(&server, stuck).await;
    mount_details(&server, None).await;

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &["--json", "--batch-size", "1"],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["status"], "success");
    assert_eq!(v["packagesWithPatches"], 4, "{v:#}");
    let w = warnings(&v, "api_batch_failed");
    assert_eq!(w.len(), 2, "{v:#}");
    // Chunk order is crawl order (readdir), so match either batch number.
    let rate =
        "failed: Rate limit exceeded (HTTP 429, gave up after 3 retries). Please try again later.";
    let down = format!(
        "failed: API request failed with status 503: busy-{} (gave up after 3 retries)",
        NAMES[4]
    );
    assert!(
        w.iter()
            .any(|d| d.starts_with("API batch ") && d.ends_with(rate)),
        "{w:?}"
    );
    assert!(w.iter().any(|d| d.ends_with(&down)), "{w:?}");
    assert!(w.iter().all(|d| d.contains(" of 6 failed: ")), "{w:?}");
    let first_batch = |d: &String| -> usize {
        d["API batch ".len()..]
            .split(' ')
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    assert!(
        first_batch(&w[0]) < first_batch(&w[1]),
        "chunk order: {w:?}"
    );
    assert_eq!(posts_for(&server, 1).await, 4);
    assert_eq!(posts_for(&server, 4).await, 4);

    // The human run prints the same lines as warnings on stderr.
    let (code_h, _, stderr_h) = run_scan(
        tmp.path(),
        &server.uri(),
        &["--batch-size", "1", "--dry-run"],
        &[],
    );
    assert_eq!(code_h, 0, "{stderr_h}");
    for d in &w {
        assert!(
            stderr_h.contains(&format!("Warning: {d}")),
            "{d}\n{stderr_h}"
        );
    }
}

/// Every batch still throttled: the existing all-batches-failed error
/// envelope and exit 1, carrying the last chunk's error.
#[tokio::test]
async fn every_batch_exhausted_is_the_all_failed_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    mount_batches(&server, |_| Some((503, None))).await;
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &["--json", "--batch-size", "1"],
        &[],
    );
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["status"], "error");
    let err = v["error"]["message"].as_str().unwrap();
    assert!(
        err.starts_with("API request failed with status 503: busy-")
            && err.ends_with(" (gave up after 3 retries)"),
        "{err}"
    );
    assert!(v.get("warnings").is_none(), "{v:#}");
}

/// `SOCKET_API_MAX_RETRIES=0` turns the retry off: one request per batch,
/// and the pre-retry error text.
#[tokio::test]
async fn max_retries_env_zero_disables_retry() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    mount_batches(&server, |idx| (idx == 2).then_some((429, Some(1)))).await;
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &["--json", "--batch-size", "1"],
        &[("SOCKET_API_MAX_RETRIES", "0")],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["packagesWithPatches"], 5);
    let w = warnings(&v, "api_batch_failed");
    assert_eq!(w.len(), 1, "{v:#}");
    assert!(
        w[0].ends_with("failed: Rate limit exceeded. Please try again later."),
        "{w:?}"
    );
    assert_eq!(posts_for(&server, 2).await, 1);
}

/// The agent flow's per-package detail fetch: a package still throttled
/// after its retries is a `patch_details_failed` warning in the `--json`
/// envelope (the human run's `could not fetch details` line), and the
/// other packages proceed.
#[tokio::test]
async fn exhausted_detail_fetch_is_a_json_warning() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(auth_batch_route()))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(batch_body((0..NAMES.len()).map(batch_entry).collect())),
        )
        .mount(&server)
        .await;
    let stuck = 3usize;
    mount_details(&server, Some(stuck)).await;
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &["--json", "--mode", "agent", "--dry-run"],
        &[],
    );
    let v = json(&stdout);
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    let w = warnings(&v, "patch_details_failed");
    assert_eq!(
        w,
        vec![format!(
            "could not fetch details for {}: Rate limit exceeded (HTTP 429, gave up after 3 \
             retries). Please try again later.",
            purl(NAMES[stuck])
        )],
        "{v:#}"
    );
    let stuck_route = format!(
        "/v0/orgs/{ORG}/patches/by-package/{}",
        encode_purl(&purl(NAMES[stuck]))
    );
    let gets = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == stuck_route)
        .count();
    assert_eq!(gets, 4);
}
