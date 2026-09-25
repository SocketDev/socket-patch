//! `scan --mode hosted` over a uv project with SEVERAL pypi wheel patches:
//! the hosted wheel metadata each native uv rewrite embeds is fetched
//! concurrently, but every outcome must fold in dep order — the
//! `python_metadata_unavailable` skips come out in the same order the old
//! one-at-a-time loop produced, whatever order the downloads finish in.
//!
//! The first failing wheel is served SLOWLY and the second fails at once,
//! so a fold in completion order would swap them. Request arrivals are
//! recorded too, so a regression to one-at-a-time fetching (which keeps the
//! order but loses the overlap) fails as well.
//!
//! Runs the built binary as a subprocess (`common::run_with_env`) against a
//! wiremock patch API. Unix-only: the fabricated `.venv` uses the POSIX
//! site-packages layout.

#![cfg(unix)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";

/// (name, version, patch uuid) — purl order is name order.
const PKGS: [(&str, &str, &str); 4] = [
    ("aaa-pkg", "1.0.0", "11111111-1111-4111-8111-111111111111"),
    ("bbb-pkg", "2.0.0", "22222222-2222-4222-8222-222222222222"),
    ("ccc-pkg", "3.0.0", "33333333-3333-4333-8333-333333333333"),
    ("ddd-pkg", "4.0.0", "44444444-4444-4444-8444-444444444444"),
];

fn purl(name: &str, version: &str) -> String {
    format!("pkg:pypi/{name}@{version}")
}

fn wheel_file(name: &str, version: &str) -> String {
    format!("{}-{version}-py3-none-any.whl", name.replace('-', "_"))
}

/// A minimal but valid wheel: `<name>-<version>.dist-info/METADATA` with the
/// three required core-metadata headers. Returns the bytes and their sha256.
fn build_wheel(name: &str, version: &str) -> (Vec<u8>, String) {
    use std::io::Write as _;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        let dist = name.replace('-', "_");
        writer
            .start_file(format!("{dist}-{version}.dist-info/METADATA"), opts)
            .unwrap();
        writer
            .write_all(
                format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n").as_bytes(),
            )
            .unwrap();
        writer.finish().unwrap();
    }
    let bytes = buf.into_inner();
    let sha = common::sha256_hex(&bytes);
    (bytes, sha)
}

fn write_uv_project(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    let deps: Vec<String> = PKGS
        .iter()
        .map(|(name, version, _)| format!("\"{name}=={version}\""))
        .collect();
    std::fs::write(
        root.join("pyproject.toml"),
        format!(
            "[project]\nname = \"socket-uv-order-fixture\"\nversion = \"0.1.0\"\nrequires-python = \">=3.9\"\ndependencies = [{}]\n",
            deps.join(", ")
        ),
    )
    .unwrap();
    let mut lock = String::from(
        "version = 1\nrevision = 3\nrequires-python = \">=3.9\"\n\n[[package]]\nname = \"socket-uv-order-fixture\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\ndependencies = [\n",
    );
    for (name, _, _) in PKGS {
        lock.push_str(&format!("    {{ name = \"{name}\" }},\n"));
    }
    lock.push_str("]\n\n[package.metadata]\nrequires-dist = [");
    lock.push_str(
        &PKGS
            .iter()
            .map(|(name, version, _)| {
                format!("{{ name = \"{name}\", specifier = \"=={version}\" }}")
            })
            .collect::<Vec<_>>()
            .join(", "),
    );
    lock.push_str("]\n");
    for (name, version, _) in PKGS {
        let file = wheel_file(name, version);
        lock.push_str(&format!(
            "\n[[package]]\nname = \"{name}\"\nversion = \"{version}\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\nwheels = [\n    {{ url = \"https://files.pythonhosted.org/packages/xx/{file}\", hash = \"sha256:{}\" }},\n]\n",
            "0".repeat(64)
        ));
    }
    std::fs::write(root.join("uv.lock"), lock).unwrap();
    let site = root
        .join(".venv")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    for (name, version, _) in PKGS {
        let dist = site.join(format!("{}-{version}.dist-info", name.replace('-', "_")));
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
        )
        .unwrap();
    }
}

/// When each wheel request ARRIVED at the mock (before its response delay).
type Arrivals = Arc<Mutex<Vec<(&'static str, Instant)>>>;

/// Serves `template` and records the request's arrival under `name`.
struct RecordArrival {
    name: &'static str,
    template: ResponseTemplate,
    arrivals: Arrivals,
}

impl Respond for RecordArrival {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        self.arrivals
            .lock()
            .unwrap()
            .push((self.name, Instant::now()));
        self.template.clone()
    }
}

/// A serve host that handles ONE download at a time: a wheel request that
/// arrives while another is still being answered gets `429 Retry-After: 1`
/// (a per-token rate limiter / CDN cap). Records every arrival and status.
struct OneAtATime {
    name: &'static str,
    body: Vec<u8>,
    busy_until: Arc<Mutex<Instant>>,
    log: Arc<Mutex<Vec<(&'static str, u16)>>>,
}

impl Respond for OneAtATime {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let now = Instant::now();
        let mut busy_until = self.busy_until.lock().unwrap();
        let (status, template) = if now < *busy_until {
            (
                429,
                ResponseTemplate::new(429).insert_header("Retry-After", "1"),
            )
        } else {
            let delay = Duration::from_millis(200);
            *busy_until = now + delay;
            (
                200,
                ResponseTemplate::new(200)
                    .set_body_bytes(self.body.clone())
                    .set_delay(delay),
            )
        };
        self.log.lock().unwrap().push((self.name, status));
        template
    }
}

/// A serve host that 503s a wheel's first `fail_first` requests and serves
/// it from then on — the shape that catches a retry budget being spent
/// twice: one `attempts`-deep budget never reaches request `fail_first + 1`.
struct Flapping {
    name: &'static str,
    body: Vec<u8>,
    fail_first: usize,
    log: Arc<Mutex<Vec<(&'static str, u16)>>>,
}

impl Respond for Flapping {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let mut log = self.log.lock().unwrap();
        let seen = log.iter().filter(|(n, _)| *n == self.name).count();
        let (status, template) = if seen < self.fail_first {
            (503, ResponseTemplate::new(503))
        } else {
            (
                200,
                ResponseTemplate::new(200).set_body_bytes(self.body.clone()),
            )
        };
        log.push((self.name, status));
        template
    }
}

/// Which wheel host [`mock_api`] mounts.
enum WheelHost {
    /// `aaa` and `ccc` serve valid bytes (reversed delays), `bbb` is a SLOW
    /// 404 and `ddd` serves bytes that do not match the granted sha256.
    Mixed(Arrivals),
    /// Every wheel is valid, behind a [`OneAtATime`] host.
    OneAtATime(Arc<Mutex<Vec<(&'static str, u16)>>>),
    /// Every wheel is valid, but `bbb` is behind a [`Flapping`] host that
    /// 503s its first `VENDOR_ATTEMPTS` requests.
    Flapping(Arc<Mutex<Vec<(&'static str, u16)>>>),
}

/// `VendorRetryPolicy::default().attempts` — the requests one wheel
/// download may cost the host, however the fan-out splits it up.
const VENDOR_ATTEMPTS: usize = 3;

/// Discovery, per-package search and the reference grants for all of PKGS,
/// with the wheels served per [`WheelHost::Mixed`]. Returns the
/// wheel-request arrival log.
async fn mock_api(server: &MockServer) -> Arrivals {
    let arrivals: Arrivals = Arc::default();
    mock_api_with(server, WheelHost::Mixed(arrivals.clone())).await;
    arrivals
}

async fn mock_api_with(server: &MockServer, host: WheelHost) {
    let busy_until = Arc::new(Mutex::new(Instant::now()));
    let patch = |name: &str, version: &str, uuid: &str| {
        json!({
            "uuid": uuid, "purl": purl(name, version), "tier": "free",
            "cveIds": [], "ghsaIds": [], "severity": "high",
            "title": format!("{name} fixture")
        })
    };
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": PKGS.iter().map(|(name, version, uuid)| json!({
                "purl": purl(name, version),
                "patches": [patch(name, version, uuid)],
            })).collect::<Vec<_>>(),
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    for (name, version, uuid) in PKGS {
        Mock::given(method("GET"))
            .and(path_regex(format!(
                "^/v0/orgs/{ORG}/patches/by-package/.*{name}.*$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [{
                    "uuid": uuid, "purl": purl(name, version),
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "x", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(server)
            .await;
    }
    let mut results = serde_json::Map::new();
    for (i, (name, version, uuid)) in PKGS.into_iter().enumerate() {
        let file = wheel_file(name, version);
        let url = format!("{}/wheels/{file}", server.uri());
        let (bytes, sha256) = build_wheel(name, version);
        let wheel = Mock::given(method("GET")).and(path(format!("/wheels/{file}")));
        match &host {
            WheelHost::Mixed(arrivals) => {
                let delay = Duration::from_millis([600, 900, 0, 0][i]);
                let response = match name {
                    "bbb-pkg" => ResponseTemplate::new(404),
                    "ddd-pkg" => {
                        ResponseTemplate::new(200).set_body_bytes(b"not the granted wheel".to_vec())
                    }
                    _ => ResponseTemplate::new(200).set_body_bytes(bytes),
                };
                wheel
                    .respond_with(RecordArrival {
                        name,
                        template: response.set_delay(delay),
                        arrivals: arrivals.clone(),
                    })
                    .mount(server)
                    .await;
            }
            WheelHost::OneAtATime(log) => {
                wheel
                    .respond_with(OneAtATime {
                        name,
                        body: bytes,
                        busy_until: busy_until.clone(),
                        log: log.clone(),
                    })
                    .mount(server)
                    .await;
            }
            WheelHost::Flapping(log) => {
                wheel
                    .respond_with(Flapping {
                        name,
                        body: bytes,
                        fail_first: if name == "bbb-pkg" {
                            VENDOR_ATTEMPTS
                        } else {
                            0
                        },
                        log: log.clone(),
                    })
                    .mount(server)
                    .await;
            }
        }
        results.insert(
            uuid.to_string(),
            json!({
                "status": "granted",
                "url": url,
                "purl": purl(name, version),
                "artifacts": [{ "kind": "tarball", "url": url, "integrity": { "sha256": sha256 } }],
                "registryOverride": null
            }),
        );
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn wheel_metadata_failures_fold_in_dep_order() {
    let server = MockServer::start().await;
    let arrivals = mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_uv_project(&root);
    let lock_before = std::fs::read(root.join("uv.lock")).unwrap();

    let cwd = root.to_str().unwrap().to_string();
    let api = server.uri();
    let (code, stdout, stderr) = common::run_with_env(
        &root,
        &[
            "scan",
            "--mode",
            "hosted",
            "--dry-run",
            "--json",
            "--cwd",
            &cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &[],
    );
    let doc: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON envelope ({e}):\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{doc:#}\n{stderr}");

    let skipped: Vec<(String, String)> = doc["redirect"]["skipped"]
        .as_array()
        .unwrap_or_else(|| panic!("redirect.skipped: {doc:#}"))
        .iter()
        .filter(|s| s["reason"] == "python_metadata_unavailable")
        .map(|s| {
            (
                s["purl"].as_str().unwrap().to_string(),
                s["uuid"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(
        skipped,
        vec![
            (purl("bbb-pkg", "2.0.0"), PKGS[1].2.to_string()),
            (purl("ddd-pkg", "4.0.0"), PKGS[3].2.to_string()),
        ],
        "metadata failures must be reported in dep order: {doc:#}"
    );
    for s in doc["redirect"]["skipped"].as_array().unwrap() {
        if s["reason"] == "python_metadata_unavailable" {
            let detail = s["detail"].as_str().unwrap();
            assert!(
                !detail.contains(&server.uri()),
                "the hosted URL is redacted from the detail: {detail}"
            );
        }
    }
    // The two good wheels still redirect; the refused two stay upstream.
    assert_eq!(doc["redirect"]["redirected"], 2, "{doc:#}");
    assert_eq!(
        std::fs::read(root.join("uv.lock")).unwrap(),
        lock_before,
        "--dry-run writes nothing"
    );

    // The fetches overlap: `bbb` is requested while `aaa`'s 600 ms response
    // is still pending. A one-at-a-time loop cannot request `bbb` until
    // `aaa` has been answered. (No wall-clock budget: arrival order only.)
    let arrivals = arrivals.lock().unwrap().clone();
    let first = |name: &str| {
        arrivals
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, at)| *at)
            .unwrap_or_else(|| panic!("no request for {name}: {arrivals:?}"))
    };
    let (aaa, bbb) = (first("aaa-pkg"), first("bbb-pkg"));
    assert!(
        bbb < aaa + Duration::from_millis(600),
        "bbb must be requested before aaa's delayed response is due \
         (arrived {:?} after aaa): {arrivals:?}",
        bbb.saturating_duration_since(aaa)
    );
}

/// The debug stream's wheel GET lines, as `(dep name, whole line)`.
fn wheel_debug_gets(stderr: &str, api: &str) -> Vec<(String, String)> {
    stderr
        .lines()
        .filter(|line| line.starts_with("[socket-patch debug]") && line.contains("/wheels/"))
        .map(|line| {
            let dep = PKGS
                .iter()
                .find(|(name, version, _)| line.ends_with(&wheel_file(name, version)))
                .unwrap_or_else(|| panic!("unknown wheel in {line}"));
            assert!(line.contains(api), "the wheel host is {api}: {line}");
            (dep.0.to_string(), line.to_string())
        })
        .collect()
}

/// A host that serves one download at a time and 429s the rest must end up
/// with the one-at-a-time loop's outcome: every wheel's metadata fetched,
/// nothing skipped. Concurrent attempts that share a `Retry-After` wake up
/// together and collide again, so letting each one retry on its own drains
/// the budgets and drops a redirect the serial loop makes; a retryable
/// failure must hand the rest of the fan-out back to the serial loop.
///
/// The collisions themselves are the fan-out's own doing, so this asserts on
/// the HOST's log, not only on stdout: no wheel may cost more requests than
/// the one-at-a-time loop's budget (a deferred attempt is resumed, never
/// replayed on a fresh one), and every wheel must end on a 200. The opt-in
/// debug stream must account for every one of those requests — a speculative
/// GET the host really served is reported, not censored — and must still
/// fold in dep order.
#[tokio::test]
async fn rate_limited_wheel_host_matches_the_serial_outcome() {
    let server = MockServer::start().await;
    let log: Arc<Mutex<Vec<(&'static str, u16)>>> = Arc::default();
    mock_api_with(&server, WheelHost::OneAtATime(log.clone())).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_uv_project(&root);

    let cwd = root.to_str().unwrap().to_string();
    let api = server.uri();
    let (code, stdout, stderr) = common::run_with_env(
        &root,
        &[
            "scan",
            "--mode",
            "hosted",
            "--dry-run",
            "--json",
            "--cwd",
            &cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &[("SOCKET_DEBUG", "1")],
    );
    let doc: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON envelope ({e}):\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{doc:#}\n{stderr}");
    let log = log.lock().unwrap().clone();
    assert_eq!(
        doc["redirect"]["redirected"],
        PKGS.len(),
        "every wheel redirects, as in the serial loop: {doc:#}\nwheel requests: {log:?}"
    );
    let metadata_skips: Vec<&Value> = doc["redirect"]["skipped"]
        .as_array()
        .map(|skipped| {
            skipped
                .iter()
                .filter(|s| s["reason"] == "python_metadata_unavailable")
                .collect()
        })
        .unwrap_or_default();
    assert!(
        metadata_skips.is_empty(),
        "no wheel may be skipped: {metadata_skips:?}\nwheel requests: {log:?}"
    );

    // No wheel may cost more than one retry budget, and each must end on a
    // 200 — a deferred first attempt is resumed, not replayed on a fresh
    // budget, which would let a wheel outlive the serial loop's failures.
    for (name, _, _) in PKGS {
        let statuses: Vec<u16> = log
            .iter()
            .filter(|(n, _)| *n == name)
            .map(|(_, status)| *status)
            .collect();
        assert!(
            !statuses.is_empty() && statuses.len() <= VENDOR_ATTEMPTS,
            "{name} may cost at most {VENDOR_ATTEMPTS} requests, got {statuses:?}: {log:?}"
        );
        assert_eq!(
            statuses.last(),
            Some(&200),
            "{name} must end on the metadata the serial loop got: {log:?}"
        );
    }

    // Every request the host really served is in the debug stream, and the
    // stream still folds in dep order (each dep's lines in one run).
    let wheel_debug = wheel_debug_gets(&stderr, &server.uri());
    assert_eq!(
        wheel_debug.len(),
        log.len(),
        "the debug stream must account for every wheel request the host \
         served ({log:?}):\n{stderr}"
    );
    let mut folded: Vec<&str> = wheel_debug.iter().map(|(dep, _)| dep.as_str()).collect();
    folded.dedup();
    assert_eq!(
        folded,
        PKGS.iter().map(|(name, _, _)| *name).collect::<Vec<_>>(),
        "each dep's GETs must fold together, in dep order:\n{stderr}"
    );
    // Each reported retry is a real 429, and each real 429 is reported.
    let failed = stderr
        .lines()
        .filter(|line| line.contains("vendor package download attempt"))
        .count();
    assert_eq!(
        failed,
        log.iter().filter(|(_, status)| *status == 429).count(),
        "every collision the host answered must be reported once:\n{stderr}"
    );
    assert_eq!(
        failed,
        stderr
            .lines()
            .filter(|line| line.contains("vendor service retry"))
            .count(),
        "every reported failure must also report its Retry-After pause:\n{stderr}"
    );
}

/// The fan-out may not hand a wheel a second retry budget. A host that 503s
/// a wheel's first `VENDOR_ATTEMPTS` requests exhausts the one-at-a-time
/// loop's budget, so that wheel is skipped and the other three redirect.
/// Spending the speculative attempt and then starting a FULL retry budget
/// would reach the host's first 200 instead — a different stdout, and in a
/// wet run a lockfile the serial loop never writes.
#[tokio::test]
async fn a_deferred_wheel_attempt_does_not_buy_a_second_retry_budget() {
    let server = MockServer::start().await;
    let log: Arc<Mutex<Vec<(&'static str, u16)>>> = Arc::default();
    mock_api_with(&server, WheelHost::Flapping(log.clone())).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_uv_project(&root);

    let cwd = root.to_str().unwrap().to_string();
    let api = server.uri();
    let (code, stdout, stderr) = common::run_with_env(
        &root,
        &[
            "scan",
            "--mode",
            "hosted",
            "--dry-run",
            "--json",
            "--cwd",
            &cwd,
            "--api-url",
            &api,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ],
        &[],
    );
    let doc: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON envelope ({e}):\n{stdout}\n{stderr}"));
    assert_eq!(code, 0, "{doc:#}\n{stderr}");
    let log = log.lock().unwrap().clone();
    let bbb: Vec<u16> = log
        .iter()
        .filter(|(n, _)| *n == "bbb-pkg")
        .map(|(_, status)| *status)
        .collect();
    assert_eq!(
        bbb,
        vec![503; VENDOR_ATTEMPTS],
        "the flapping wheel gets exactly the serial loop's budget, all of \
         it spent before the host's first 200: {log:?}"
    );
    let skipped: Vec<String> = doc["redirect"]["skipped"]
        .as_array()
        .unwrap_or_else(|| panic!("redirect.skipped: {doc:#}"))
        .iter()
        .filter(|s| s["reason"] == "python_metadata_unavailable")
        .map(|s| s["purl"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        skipped,
        vec![purl("bbb-pkg", "2.0.0")],
        "the exhausted wheel is skipped, as in the serial loop: {doc:#}"
    );
    assert_eq!(
        doc["redirect"]["redirected"],
        PKGS.len() - 1,
        "the other three still redirect: {doc:#}"
    );
}
