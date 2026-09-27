//! `scan`'s patch-API loops run their requests concurrently (batch POSTs,
//! per-package detail GETs, hosted record views) but must stay
//! indistinguishable from the old serial loops: results fold in input
//! order, warnings print in input order, and the authenticated-to-proxy
//! fallback replays from the exact chunk that triggered it.
//!
//! Every test here makes the server answer LATER requests FIRST (reversed
//! latencies), so an implementation that folded in completion order — or
//! that let a discarded response leak in — produces visibly different
//! output. Where a pure oracle exists, the output is also compared with a
//! zero-latency run of the same fixture.
//!
//! Subprocess runs scrub the `SOCKET_*` environment (the
//! `in_process_redirect.rs::scrubbed_cli` pattern) so ambient
//! configuration cannot reroute the branch under test.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

/// Package names: no name is a prefix of another, so a body/path match on
/// `"{name}@"` is unambiguous.
const NAMES: [&str; 6] = [
    "conc-alpha",
    "conc-bravo",
    "conc-charlie",
    "conc-delta",
    "conc-echo",
    "conc-foxtrot",
];
const VERSION: &str = "1.0.0";

fn purl(name: &str) -> String {
    format!("pkg:npm/{name}@{VERSION}")
}

/// Distinct uuid per (package index, source) so the output reveals which
/// server response was folded for each package.
fn uuid(idx: usize, source: u8) -> String {
    format!("{source:08x}-0000-4000-8000-{idx:012x}")
}

const AUTH: u8 = 0xa;
const PROXY: u8 = 0xb;

fn encode_purl(purl: &str) -> String {
    purl.replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
}

fn scrubbed_cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_ECOSYSTEMS", "cargo")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_ECOSYSTEMS")
        .env_remove("SOCKET_MANIFEST_PATH");
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

/// `socket-patch scan <args>` in `cwd` against `api` (authenticated) with
/// the public proxy pointed at `proxy`.
fn run_scan(cwd: &Path, api: &str, proxy: &str, args: &[&str]) -> (i32, String, String) {
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
        .env("SOCKET_PROXY_URL", proxy)
        .output()
        .expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An npm project with every name in `names` installed and locked.
fn write_project(root: &Path, names: &[&str]) {
    let deps: Vec<String> = names
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
    for name in names {
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

fn batch_entry(idx: usize, source: u8) -> serde_json::Value {
    let p = purl(NAMES[idx]);
    serde_json::json!({
        "purl": p,
        "patches": [{
            "uuid": uuid(idx, source),
            "purl": p,
            "tier": "free",
            "cveIds": [],
            "ghsaIds": [],
            "severity": "high",
            "title": format!("patch for {}", NAMES[idx]),
        }]
    })
}

fn batch_body(entries: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({ "packages": entries, "canAccessPaidPatches": false })
}

/// One batch mock per package on `route`, matched by the package in the
/// request body: answers `status` (a 200 carries that package's patch from
/// `source`) after `delay`.
async fn mount_batch_for(
    server: &MockServer,
    route: &str,
    idx: usize,
    source: u8,
    status: u16,
    delay: Duration,
) {
    let template = if status == 200 {
        ResponseTemplate::new(200).set_body_json(batch_body(vec![batch_entry(idx, source)]))
    } else {
        ResponseTemplate::new(status).set_body_string(format!("boom-{}", NAMES[idx]))
    };
    Mock::given(method("POST"))
        .and(path(route))
        .and(body_string_contains(format!("\"{}\"", purl(NAMES[idx]))))
        .respond_with(template.set_delay(delay))
        .mount(server)
        .await;
}

fn auth_batch_route() -> String {
    format!("/v0/orgs/{ORG}/patches/batch")
}

const PROXY_BATCH_ROUTE: &str = "/patch/batch";

async fn batch_requests(server: &MockServer, route: &str) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("wiremock records requests")
        .into_iter()
        .filter(|r| r.method.as_str() == "POST" && r.url.path() == route)
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

/// The crawl order of the fixture's packages — the order `scan` chunks
/// them in. Learned from one default-batch-size run: its single batch body
/// lists every purl in that order. (Crawl order is readdir order, which the
/// test must not assume.)
async fn crawl_order(root: &Path) -> Vec<usize> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(auth_batch_route()))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_body(vec![])))
        .mount(&server)
        .await;
    let (code, stdout, stderr) = run_scan(root, &server.uri(), &server.uri(), &["--json"]);
    assert_eq!(code, 0, "order probe: stdout={stdout} stderr={stderr}");
    let bodies = batch_requests(&server, &auth_batch_route()).await;
    assert_eq!(bodies.len(), 1, "one batch expected: {bodies:?}");
    let body: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    let order: Vec<usize> = body["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let p = c["purl"].as_str().unwrap();
            NAMES.iter().position(|n| purl(n) == p).unwrap()
        })
        .collect();
    assert_eq!(order.len(), NAMES.len(), "every package crawled: {order:?}");
    order
}

/// `package idx → folded patch uuids` from a `scan --json` envelope.
fn folded_uuids(stdout: &str) -> Vec<(String, Vec<String>)> {
    let v: serde_json::Value = serde_json::from_str(stdout).expect("scan --json envelope");
    v["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .map(|pkg| {
            let uuids = pkg["patches"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p["uuid"].as_str().unwrap().to_string())
                .collect();
            (pkg["purl"].as_str().unwrap().to_string(), uuids)
        })
        .collect()
}

/// Delay for the `pos`-th chunk (crawl position): later chunks answer
/// first.
fn reversed(pos: usize) -> Duration {
    Duration::from_millis(60 * (NAMES.len() - pos) as u64)
}

// ---------------------------------------------------------------------------
// Batch POSTs (A2)
// ---------------------------------------------------------------------------

/// A 401 on the very first chunk: that chunk and every later one go to the
/// proxy, the authenticated API sees exactly the one request it saw
/// before, and the downgrade warning prints once.
#[tokio::test]
async fn batch_fallback_on_first_chunk_sends_everything_after_to_proxy() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES[..5]);

    let auth = MockServer::start().await;
    let proxy = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(auth_batch_route()))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid token"))
        .expect(1)
        .mount(&auth)
        .await;
    for idx in 0..5 {
        mount_batch_for(&proxy, PROXY_BATCH_ROUTE, idx, PROXY, 200, reversed(idx)).await;
    }

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &auth.uri(),
        &proxy.uri(),
        &["--json", "--batch-size", "1"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert_eq!(
        stderr
            .matches("falling back to public patch API proxy")
            .count(),
        1,
        "exactly one downgrade warning: {stderr}"
    );
    assert_eq!(batch_requests(&auth, &auth_batch_route()).await.len(), 1);
    assert_eq!(batch_requests(&proxy, PROXY_BATCH_ROUTE).await.len(), 5);
    let folded = folded_uuids(&stdout);
    assert_eq!(folded.len(), 5, "{stdout}");
    for (p, uuids) in folded {
        let idx = NAMES.iter().position(|n| purl(n) == p).unwrap();
        assert_eq!(uuids, vec![uuid(idx, PROXY)], "{p}");
    }
}

/// A 401 on chunk 3 of 6 (crawl order): chunks 0-2 fold the authenticated
/// answers, chunk 3 is retried on the proxy and 4-5 are proxy-only. The
/// authenticated answers for 4-5 arrive BEFORE chunk 3's 401 (reversed
/// latencies) and must be discarded, exactly as if they had never been
/// sent.
#[tokio::test]
async fn batch_fallback_mid_run_replays_from_the_failing_chunk() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES);
    let order = crawl_order(tmp.path()).await;

    let auth = MockServer::start().await;
    let proxy = MockServer::start().await;
    for (pos, &idx) in order.iter().enumerate() {
        let status = if pos == 3 { 401 } else { 200 };
        mount_batch_for(&auth, &auth_batch_route(), idx, AUTH, status, reversed(pos)).await;
        mount_batch_for(&proxy, PROXY_BATCH_ROUTE, idx, PROXY, 200, reversed(pos)).await;
    }

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &auth.uri(),
        &proxy.uri(),
        &["--json", "--batch-size", "1"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert_eq!(
        stderr
            .matches("falling back to public patch API proxy")
            .count(),
        1,
        "exactly one downgrade warning: {stderr}"
    );

    let mut expected: Vec<(String, Vec<String>)> = order
        .iter()
        .enumerate()
        .map(|(pos, &idx)| {
            let source = if pos < 3 { AUTH } else { PROXY };
            (purl(NAMES[idx]), vec![uuid(idx, source)])
        })
        .collect();
    expected.sort();
    assert_eq!(folded_uuids(&stdout), expected);

    // The proxy saw exactly the replayed tail, chunk 3 onward.
    let mut proxied: Vec<String> = batch_requests(&proxy, PROXY_BATCH_ROUTE)
        .await
        .iter()
        .map(|b| {
            let v: serde_json::Value = serde_json::from_str(b).unwrap();
            v["components"][0]["purl"].as_str().unwrap().to_string()
        })
        .collect();
    proxied.sort();
    let mut tail: Vec<String> = order[3..].iter().map(|&i| purl(NAMES[i])).collect();
    tail.sort();
    assert_eq!(proxied, tail);

    // The authenticated API saw every chunk: chunk 0 alone, then the
    // whole 1..6 window in flight at once. So the answers for chunks 4-5
    // really existed (they arrived before chunk 3's 401) and were
    // dropped — the uuids above prove it — rather than never requested.
    assert_eq!(batch_requests(&auth, &auth_batch_route()).await.len(), 6);
}

/// The same mid-run downgrade under `--debug`: the window really does
/// dispatch chunks past the failing one to the authenticated endpoint, but
/// the chunks it then drops announce nothing. Each chunk's debug lines are
/// held back until it is folded, so the stream reads exactly as the
/// one-at-a-time loop's did — four authenticated POSTs (chunks 0-3, the
/// last being the 401) and three proxy POSTs (the replayed 3-5) — while
/// the authenticated server saw six requests.
#[tokio::test]
async fn a_dropped_batch_window_holds_back_its_debug_lines() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES);
    let order = crawl_order(tmp.path()).await;

    let auth = MockServer::start().await;
    let proxy = MockServer::start().await;
    for (pos, &idx) in order.iter().enumerate() {
        let status = if pos == 3 { 401 } else { 200 };
        mount_batch_for(&auth, &auth_batch_route(), idx, AUTH, status, reversed(pos)).await;
        mount_batch_for(&proxy, PROXY_BATCH_ROUTE, idx, PROXY, 200, reversed(pos)).await;
    }

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &auth.uri(),
        &proxy.uri(),
        &["--json", "--batch-size", "1", "--debug"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");

    let posted = |host: &str, route: &str| {
        let needle = format!("[socket-patch debug] POST {host}{route}");
        stderr.matches(needle.as_str()).count()
    };
    assert_eq!(
        posted(&auth.uri(), &auth_batch_route()),
        4,
        "chunks 0-3 announce themselves, the dropped 4-5 do not: {stderr}"
    );
    assert_eq!(
        posted(&proxy.uri(), PROXY_BATCH_ROUTE),
        3,
        "the replayed tail announces itself once per chunk: {stderr}"
    );
    assert_eq!(
        batch_requests(&auth, &auth_batch_route()).await.len(),
        6,
        "the window did dispatch the chunks whose lines were held back"
    );
}

/// Mixed 500s in chunks 2 and 4 with reversed latencies: the per-batch
/// warnings print in chunk order, and the run still succeeds with the
/// other chunks' patches.
#[tokio::test]
async fn batch_failure_warnings_print_in_chunk_order() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES);
    let order = crawl_order(tmp.path()).await;

    let auth = MockServer::start().await;
    for (pos, &idx) in order.iter().enumerate() {
        let status = if pos == 2 || pos == 4 { 500 } else { 200 };
        mount_batch_for(&auth, &auth_batch_route(), idx, AUTH, status, reversed(pos)).await;
    }
    let all: Vec<usize> = (0..NAMES.len()).collect();
    mount_details(&auth, &all, &[], |_| Duration::ZERO).await;

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &auth.uri(),
        &auth.uri(),
        &["--batch-size", "1", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let warn2 = format!(
        "Warning: API batch 3 of 6 failed: API request failed with status 500: boom-{}",
        NAMES[order[2]]
    );
    let warn4 = format!(
        "Warning: API batch 5 of 6 failed: API request failed with status 500: boom-{}",
        NAMES[order[4]]
    );
    let at2 = stderr
        .find(&warn2)
        .unwrap_or_else(|| panic!("{warn2}\n{stderr}"));
    let at4 = stderr
        .find(&warn4)
        .unwrap_or_else(|| panic!("{warn4}\n{stderr}"));
    assert!(at2 < at4, "chunk-order warnings: {stderr}");
    assert_eq!(stderr.matches("Warning: API batch").count(), 2, "{stderr}");
}

/// Every chunk fails, the FIRST chunk slowest: the all-failed error still
/// carries the LAST chunk's error, as the serial loop's `last_batch_error`
/// did.
#[tokio::test]
async fn all_batches_failed_reports_the_last_chunks_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES);
    let order = crawl_order(tmp.path()).await;

    let auth = MockServer::start().await;
    for (pos, &idx) in order.iter().enumerate() {
        mount_batch_for(&auth, &auth_batch_route(), idx, AUTH, 500, reversed(pos)).await;
    }

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &auth.uri(),
        &auth.uri(),
        &["--json", "--batch-size", "1"],
    );
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["status"], "error");
    assert_eq!(
        v["error"].as_str().unwrap(),
        format!(
            "API request failed with status 500: boom-{}",
            NAMES[order[5]]
        )
    );
}

/// `scan` against `proxy` with NO API token — the common unauthenticated
/// path. `extra` env is applied on top of the scrubbed environment. The
/// authenticated base URL is unroutable, so any request that reached for it
/// fails the run loudly instead of escaping to the real API.
fn run_scan_anonymous(
    cwd: &Path,
    proxy: &str,
    args: &[&str],
    extra: &[(&str, &str)],
) -> (i32, String, String) {
    let mut cmd = scrubbed_cli();
    cmd.arg("scan")
        .args([
            "--cwd",
            cwd.to_str().unwrap(),
            "--api-url",
            "http://127.0.0.1:1",
            "--proxy-url",
            proxy,
        ])
        .args(args)
        .env("SOCKET_NO_API_TOKEN", "1")
        .env("SOCKET_NO_CONFIG", "1");
    for (key, value) in extra {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Every proxy batch POST takes this long, so the chunks in flight at an
/// arrival are exactly those that arrived less than this before it.
const PROXY_CHUNK_DELAY: Duration = Duration::from_millis(400);

/// Records each proxy batch POST's arrival, then answers its chunk's
/// packages after [`PROXY_CHUNK_DELAY`].
struct ProxyArrivals(std::sync::Arc<std::sync::Mutex<Vec<std::time::Instant>>>);

impl wiremock::Respond for ProxyArrivals {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        self.0.lock().unwrap().push(std::time::Instant::now());
        let body: serde_json::Value = serde_json::from_slice(&req.body).expect("batch body");
        let entries: Vec<serde_json::Value> = body["components"]
            .as_array()
            .expect("components")
            .iter()
            .map(|c| {
                let p = c["purl"].as_str().unwrap();
                let idx = NAMES.iter().position(|n| purl(n) == p).unwrap();
                batch_entry(idx, PROXY)
            })
            .collect();
        ResponseTemplate::new(200)
            .set_body_json(batch_body(entries))
            .set_delay(PROXY_CHUNK_DELAY)
    }
}

/// A request is "in flight" at an arrival when it arrived less than this
/// before: its slot frees only once its answer, one delay later, is back.
fn in_flight_window() -> Duration {
    PROXY_CHUNK_DELAY.mul_f32(0.8)
}

/// Most arrivals inside one [`in_flight_window`] — a lower bound on the
/// chunks that were in flight together.
fn peak_in_flight(arrivals: &[Duration]) -> usize {
    (0..arrivals.len())
        .map(|i| {
            arrivals[i..]
                .iter()
                .take_while(|t| **t - arrivals[i] < in_flight_window())
                .count()
        })
        .max()
        .unwrap_or(0)
}

/// One anonymous `scan --json --batch-size 1` over every package against a
/// proxy that records arrivals; returns `(stdout, each chunk POST's
/// arrival as an offset from the first, sorted)`.
async fn anonymous_batch_run(root: &Path, extra: &[(&str, &str)]) -> (String, Vec<Duration>) {
    let proxy = MockServer::start().await;
    let arrivals = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("POST"))
        .and(path(PROXY_BATCH_ROUTE))
        .respond_with(ProxyArrivals(std::sync::Arc::clone(&arrivals)))
        .mount(&proxy)
        .await;

    let (code, stdout, stderr) =
        run_scan_anonymous(root, &proxy.uri(), &["--json", "--batch-size", "1"], extra);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert_eq!(
        batch_requests(&proxy, PROXY_BATCH_ROUTE).await.len(),
        NAMES.len(),
        "one POST per chunk"
    );
    let mut arrivals = arrivals.lock().unwrap().clone();
    arrivals.sort();
    let first = arrivals[0];
    (
        stdout,
        arrivals.into_iter().map(|t| t - first).collect::<Vec<_>>(),
    )
}

/// A token-less run is already on the proxy, so it has no authenticated
/// downgrade left to cap: its batch window opens at chunk 0 instead of
/// waiting out a round trip for a fallback that cannot fire. The second
/// chunk therefore arrives while the first is still unanswered — and
/// `SOCKET_API_CONCURRENCY=1`, the escape hatch for an endpoint that caps
/// in-flight requests, puts the very same run back on one request at a
/// time, with identical output.
#[tokio::test]
async fn proxy_batch_window_opens_at_the_first_chunk_unless_capped() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES);

    let (concurrent_stdout, concurrent) = anonymous_batch_run(tmp.path(), &[]).await;
    assert!(
        concurrent[1] < in_flight_window(),
        "chunk 0 must not go alone on the proxy: arrivals {concurrent:?}"
    );
    assert!(
        peak_in_flight(&concurrent) > 1,
        "chunks must overlap: arrivals {concurrent:?}"
    );

    let (serial_stdout, serial) =
        anonymous_batch_run(tmp.path(), &[("SOCKET_API_CONCURRENCY", "1")]).await;
    assert_eq!(
        peak_in_flight(&serial),
        1,
        "a cap of 1 is the old serial loop: arrivals {serial:?}"
    );
    assert_eq!(
        concurrent_stdout, serial_stdout,
        "the cap changes pacing, never output"
    );
    let folded = folded_uuids(&concurrent_stdout);
    assert_eq!(folded.len(), NAMES.len(), "{concurrent_stdout}");
    for (p, uuids) in folded {
        let idx = NAMES.iter().position(|n| purl(n) == p).unwrap();
        assert_eq!(uuids, vec![uuid(idx, PROXY)], "{p}");
    }
}

// ---------------------------------------------------------------------------
// Per-package detail GETs (A1)
// ---------------------------------------------------------------------------

/// One batch answering every package in `idxs`, then per-package detail
/// GETs ([`mount_details`]).
async fn mount_discovery_with_details(
    server: &MockServer,
    idxs: &[usize],
    failing: &[usize],
    delay: impl Fn(usize) -> Duration,
) {
    Mock::given(method("POST"))
        .and(path(auth_batch_route()))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_body(
            idxs.iter().map(|&i| batch_entry(i, AUTH)).collect(),
        )))
        .mount(server)
        .await;
    mount_details(server, idxs, failing, delay).await;
}

/// Per-package detail GETs for `idxs`: `failing` ones answer 500, the rest
/// their patch; every answer is delayed by `delay(idx)`.
async fn mount_details(
    server: &MockServer,
    idxs: &[usize],
    failing: &[usize],
    delay: impl Fn(usize) -> Duration,
) {
    for &idx in idxs {
        let p = purl(NAMES[idx]);
        let template = if failing.contains(&idx) {
            ResponseTemplate::new(500).set_body_string(format!("detail-boom-{}", NAMES[idx]))
        } else {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": uuid(idx, AUTH), "purl": p,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": format!("details for {}", NAMES[idx]),
                    "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            }))
        };
        Mock::given(method("GET"))
            .and(path(format!(
                "/v0/orgs/{ORG}/patches/by-package/{}",
                encode_purl(&p)
            )))
            .respond_with(template.set_delay(delay(idx)))
            .mount(server)
            .await;
    }
}

/// Partial detail-fetch failures with reversed latencies: the per-package
/// warnings print in package (purl-sorted) order, and the whole human
/// preview is byte-identical to a zero-latency run.
#[tokio::test]
async fn detail_fetch_warnings_and_preview_keep_package_order() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES);
    let all: Vec<usize> = (0..NAMES.len()).collect();
    let failing = [1usize, 4];

    let run_with = |delay: fn(usize) -> Duration| {
        let all = all.clone();
        let root = tmp.path().to_path_buf();
        async move {
            let server = MockServer::start().await;
            mount_discovery_with_details(&server, &all, &failing, delay).await;
            run_scan(&root, &server.uri(), &server.uri(), &["--dry-run"])
        }
    };
    // NAMES is already purl-sorted, so index order is the fold order.
    let (code, stdout, stderr) = run_with(|i| Duration::from_millis(50 * (6 - i as u64))).await;
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let w1 = format!("Warning: could not fetch details for {}: ", purl(NAMES[1]));
    let w4 = format!("Warning: could not fetch details for {}: ", purl(NAMES[4]));
    let at1 = stderr.find(&w1).unwrap_or_else(|| panic!("{w1}\n{stderr}"));
    let at4 = stderr.find(&w4).unwrap_or_else(|| panic!("{w4}\n{stderr}"));
    assert!(at1 < at4, "package-order warnings: {stderr}");

    let (code0, stdout0, stderr0) = run_with(|_| Duration::ZERO).await;
    assert_eq!(code0, code);
    assert_eq!(stdout0, stdout, "latency must not change the preview");
    assert_eq!(stderr0, stderr, "latency must not change stderr");
}

/// Every detail fetch fails (reversed latencies): the one terminal error
/// names the LAST package's failure, as the serial loop's `failures.last()`
/// did.
#[tokio::test]
async fn all_detail_fetches_failed_reports_the_last_packages_error() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), &NAMES);
    let all: Vec<usize> = (0..NAMES.len()).collect();

    let server = MockServer::start().await;
    mount_discovery_with_details(&server, &all, &all, |i| {
        Duration::from_millis(50 * (6 - i as u64))
    })
    .await;
    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &server.uri(),
        &["--json", "--mode", "hosted", "--dry-run"],
    );
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let err = v["error"].as_str().unwrap();
    assert!(
        err.starts_with("all 6 patch-detail queries failed: ")
            && err.ends_with(&format!("detail-boom-{}", NAMES[5])),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Hosted record views (A3)
// ---------------------------------------------------------------------------

fn hosted_url(idx: usize) -> String {
    let name = NAMES[idx];
    format!(
        "http://patch.test/patch/npm/{name}/{VERSION}/22222222-2222-4222-8222-222222222222/{}/{name}-{VERSION}.tgz",
        uuid(idx, AUTH)
    )
}

/// Discovery + references + views for a hosted wet run over every package;
/// the `failing` views answer 500. Every by-package / view answer is delayed
/// by `delay(idx)`.
async fn mount_hosted(server: &MockServer, failing: &[usize], delay: fn(usize) -> Duration) {
    let all: Vec<usize> = (0..NAMES.len()).collect();
    mount_discovery_with_details(server, &all, &[], delay).await;
    let mut results = serde_json::Map::new();
    for (idx, name) in NAMES.iter().enumerate() {
        results.insert(
            uuid(idx, AUTH),
            serde_json::json!({
                "status": "granted",
                "url": hosted_url(idx),
                "purl": purl(name),
                "artifacts": [{
                    "kind": "tarball",
                    "url": hosted_url(idx),
                    "integrity": { "sha512": format!("sha512-PATCHED{idx}==") }
                }],
                "registryOverride": null
            }),
        );
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results })),
        )
        .mount(server)
        .await;
    for (idx, name) in NAMES.iter().enumerate() {
        let u = uuid(idx, AUTH);
        let template = if failing.contains(&idx) {
            ResponseTemplate::new(500)
        } else {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": u,
                "purl": purl(name),
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": format!("{idx:064x}"),
                        "afterHash": format!("{:064x}", idx + 100),
                    }
                },
                "vulnerabilities": {
                    format!("GHSA-conc-{idx:04}-aaaa"): {
                        "cves": [format!("CVE-2024-{idx:04}")],
                        "summary": "s", "severity": "high", "description": "d"
                    }
                },
                "description": "x", "license": "MIT", "tier": "free"
            }))
        };
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{u}")))
            .respond_with(template.set_delay(delay(idx)))
            .mount(server)
            .await;
    }
}

/// The ledger with its run timestamps blanked, for a byte comparison.
fn ledger_without_timestamps(root: &Path) -> String {
    let raw = std::fs::read_to_string(root.join(".socket/vendor/redirect-state.json")).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    fn blank(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    let key = k.to_ascii_lowercase();
                    if key.ends_with("at") && val.is_string() {
                        *val = serde_json::Value::String("<ts>".into());
                    } else {
                        blank(val);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(blank),
            _ => {}
        }
    }
    blank(&mut v);
    serde_json::to_string_pretty(&v).unwrap()
}

/// A wet hosted run where 2 of 6 record views fail, with reversed
/// latencies: the `record_fetch_failed` warnings keep `confirmed` order,
/// and stdout, the rewritten lockfile and the ledger all equal a
/// zero-latency run's.
#[tokio::test]
async fn hosted_record_fetch_failures_keep_order_and_ledger_bytes() {
    let failing = [1usize, 3];
    let slow: fn(usize) -> Duration = |i| Duration::from_millis(50 * (6 - i as u64));
    let fast: fn(usize) -> Duration = |_| Duration::ZERO;

    let mut outcomes = Vec::new();
    for delay in [slow, fast] {
        let tmp = tempfile::tempdir().unwrap();
        write_project(tmp.path(), &NAMES);
        let server = MockServer::start().await;
        mount_hosted(&server, &failing, delay).await;
        let (code, stdout, stderr) = run_scan(
            tmp.path(),
            &server.uri(),
            &server.uri(),
            &["--json", "--mode", "hosted", "--yes"],
        );
        assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
        let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
        outcomes.push((stdout, lock, ledger_without_timestamps(tmp.path())));
    }

    let (stdout, lock, ledger) = &outcomes[0];
    let v: serde_json::Value = serde_json::from_str(stdout).unwrap();
    let warnings: Vec<&str> = v["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["code"] == "record_fetch_failed")
        .map(|w| w["detail"].as_str().unwrap())
        .collect();
    assert_eq!(warnings.len(), 2, "{stdout}");
    assert!(warnings[0].starts_with(&format!("{} redirected", purl(NAMES[1]))));
    assert!(warnings[1].starts_with(&format!("{} redirected", purl(NAMES[3]))));
    for idx in 0..NAMES.len() {
        assert!(lock.contains(&hosted_url(idx)), "{lock}");
        let has_record = ledger.contains(&format!("GHSA-conc-{idx:04}-aaaa"));
        assert_eq!(has_record, !failing.contains(&idx), "{ledger}");
    }

    assert_eq!(outcomes[0], outcomes[1], "latency must not change the run");
}
