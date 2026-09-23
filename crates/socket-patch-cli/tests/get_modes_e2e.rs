//! Subprocess end-to-end tests for `get --mode hosted|vendored` (v3.6):
//! the JSON envelope shapes, the `--silent` stdout discipline, and the
//! `--save-only` conflict — the output surfaces the in-process suite
//! (`in_process_get_modes.rs`) cannot capture because `get::run` prints
//! to the real stdout. Disk-state parity with scan's engines is pinned
//! there; here every assertion is about what the spawned binary PRINTS
//! (plus just enough disk/request oracles to keep the envelopes honest).
//!
//! The API is wiremock-mocked with the same recipes as the in-process
//! suite, adapted to subprocess flags (`--api-url` / `--api-token` /
//! `--org` / `--json` / `--yes`). Every `--json` test asserts stdout is
//! exactly ONE JSON document (`serde_json::from_str` over the full
//! stream — it rejects trailing data, so a second document or stray
//! human line fails loudly).
//!
//! No `#[serial]`: the child gets a scrubbed env copy (`run_bin_with_env`
//! via `run_with_env`); the parent process env is never mutated.

use std::path::Path;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const NAME: &str = "getmodes-pkg";
const GHSA: &str = "GHSA-aaaa-bbbb-cccc";

/// The INSTALLED version's patch.
const UUID1: &str = "11111111-1111-4111-8111-111111111111";
const PURL1: &str = "pkg:npm/getmodes-pkg@1.0.0";
/// A patch for a version this project does NOT have.
const UUID2: &str = "22222222-2222-4222-8222-222222222222";
const PURL2: &str = "pkg:npm/getmodes-pkg@2.0.0";

const HOSTED_URL1: &str = "http://patch.test/patch/npm/getmodes-pkg/1.0.0/33333333-3333-4333-8333-333333333333/11111111-1111-4111-8111-111111111111/getmodes-pkg-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";

const BEFORE_BYTES: &[u8] = b"vulnerable\n";
const AFTER_BYTES: &[u8] = b"patched\n";

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `view/{uuid}` with REAL git-blob hashes and inline blob content, so the
/// vendored flow's staging hash-gates pass (the hosted flow only needs the
/// record fields). Same recipe as the in-process suite.
async fn mock_view(server: &MockServer, uuid: &str, purl: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": common::git_sha256(BEFORE_BYTES),
                    "afterHash": common::git_sha256(AFTER_BYTES),
                    "blobContent": b64(AFTER_BYTES),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2024-1234"],
                    "summary": "get-modes fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "get-modes fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// `by-ghsa/{GHSA}`: the two-version fan-out — 1.0.0 (installable in the
/// project fixture) and 2.0.0 (never present), both free.
async fn mock_ghsa_fanout(server: &MockServer) {
    let patch = |uuid: &str, purl: &str, published: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl,
            "publishedAt": published,
            "description": "x", "license": "MIT", "tier": "free",
            "vulnerabilities": {}
        })
    };
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                patch(UUID2, PURL2, "2024-02-01T00:00:00Z"),
                patch(UUID1, PURL1, "2024-01-01T00:00:00Z"),
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// The hosted reference grant for the installed version's patch only.
async fn mock_reference(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID1: {
                    "status": "granted",
                    "url": HOSTED_URL1,
                    "purl": PURL1,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": HOSTED_URL1,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// An npm project with `getmodes-pkg@1.0.0` INSTALLED (crawler-visible)
/// and lockfile-resolved; version 2.0.0 exists nowhere in the project.
fn write_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "1.0.0" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "1.0.0", "main": "index.js" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE_BYTES).unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "1.0.0" }} }},
    "node_modules/{NAME}": {{
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-1.0.0.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
}

/// Spawn `socket-patch get <extra...>` against the mock server via the
/// shared scrub-and-run helper (`common::run_with_env` →
/// `run_bin_with_env`), with telemetry disabled in the child so no test
/// ever POSTs to the real telemetry endpoint.
fn run_get(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["get"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&[
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-tests",
        "--org",
        ORG,
        "--yes",
    ]);
    common::run_with_env(cwd, &args, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

/// Parse stdout as exactly ONE JSON document. `serde_json::from_str`
/// errors on trailing content, so a passing parse proves nothing else
/// (a second envelope, a stray human println) shares the stream.
fn parse_single_json_doc(stdout: &str) -> serde_json::Value {
    let trimmed = stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "expected a JSON envelope on stdout, got nothing"
    );
    serde_json::from_str(trimmed).unwrap_or_else(|e| {
        panic!("stdout must be exactly one JSON document: {e}\nstdout:\n{stdout}")
    })
}

/// Requests the mock server saw for a given path fragment.
async fn requests_containing(server: &MockServer, fragment: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().contains(fragment))
        .count()
}

// ---------------------------------------------------------------------------
// (1) hosted envelope
// ---------------------------------------------------------------------------

/// `get <uuid> --mode hosted --json` emits ONE JSON object: get's base
/// envelope (`status`/`found`/`patches`, NO `downloaded`/`applied` — nothing
/// lands in `.socket/`) with scan's `redirect` sub-object nested in. Exact
/// whole-envelope equality so an additive key can't sneak in unnoticed.
#[tokio::test]
async fn get_uuid_hosted_json_envelope_nests_redirect() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[UUID1, "--mode", "hosted", "--json"],
    );
    assert_eq!(
        code, 0,
        "get --mode hosted --json should succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let v = parse_single_json_doc(&stdout);
    let expected = serde_json::json!({
        "status": "success",
        "found": 1,
        "patches": [],
        "redirect": {
            "mode": "hosted",
            "redirected": 1,
            "rewrittenFiles": ["package-lock.json"],
            "skipped": [],
            "warnings": [],
            "dryRun": false,
        },
    });
    assert_eq!(
        v,
        expected,
        "hosted get JSON envelope drifted.\nexpected:\n{}\ngot:\n{}",
        serde_json::to_string_pretty(&expected).unwrap(),
        serde_json::to_string_pretty(&v).unwrap(),
    );
    // Belt-and-suspenders on the keys the contract calls out by name, in
    // case the exact-equality pin above is ever loosened in maintenance.
    assert!(
        v.get("downloaded").is_none() && v.get("applied").is_none(),
        "hosted mode downloads/applies nothing into .socket — neither key \
         may appear at top level; got {v}"
    );

    // The envelope must describe a rewrite that actually happened: the
    // lock points at the hosted artifact, and no manifest/blobs exist.
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(HOSTED_URL1) && lock.contains(PATCHED_SHA512),
        "redirected:1 must reflect a real lock rewrite; got:\n{lock}"
    );
    assert!(!tmp.path().join(".socket/manifest.json").exists());
    assert!(!tmp.path().join(".socket/blobs").exists());
}

// ---------------------------------------------------------------------------
// (2) vendored envelope
// ---------------------------------------------------------------------------

/// `get <uuid> --mode vendored --json` (local `--vendor-source build`, so no
/// vendoring-service mocks): the detached download envelope — the same
/// vocabulary scan's `download` block uses (`downloaded`, `patches[].action:
/// "downloaded"`, `detached: true`), no `applied` (nothing is applied in
/// place) — with scan's full vendor `Envelope` nested under `vendor`
/// (camelCase keys/statuses).
#[tokio::test]
async fn get_uuid_vendored_json_envelope_nests_vendor() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[
            UUID1,
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--json",
        ],
    );
    assert_eq!(
        code, 0,
        "get --mode vendored --json should succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(v["found"], 1, "envelope={v}");
    assert_eq!(v["downloaded"], 1, "envelope={v}");
    assert_eq!(v["skipped"], 0, "envelope={v}");
    assert_eq!(v["failed"], 0, "envelope={v}");
    assert_eq!(
        v["detached"], true,
        "vendored get is the detached download phase; got {v}"
    );
    assert_eq!(v["patches"][0]["purl"], PURL1, "envelope={v}");
    assert_eq!(v["patches"][0]["uuid"], UUID1, "envelope={v}");
    assert_eq!(
        v["patches"][0]["action"], "downloaded",
        "the detached vocabulary: the record was fetched into memory, not added to a manifest; got {v}"
    );
    assert!(
        v.get("applied").is_none(),
        "vendored mode has no top-level `applied` key (nothing is applied in place); got {v}"
    );

    // The nested vendor Envelope: the unified `--json` shape the standalone
    // `vendor` command emits — command tag, camelCase status + dryRun,
    // events[], pre-aggregated camelCase summary.
    let venv = v["vendor"]
        .as_object()
        .unwrap_or_else(|| panic!("vendored envelope must nest a vendor Envelope; got {v}"));
    assert_eq!(venv["command"], "vendor", "vendor={venv:?}");
    assert_eq!(venv["status"], "success", "vendor={venv:?}");
    assert_eq!(venv["dryRun"], false, "vendor={venv:?}");
    assert_eq!(
        venv["summary"]["applied"], 1,
        "summary must count the fresh vendoring (camelCase keys); vendor={venv:?}"
    );
    let events = venv["events"]
        .as_array()
        .unwrap_or_else(|| panic!("vendor Envelope must carry events[]; got {venv:?}"));
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == PURL1 && e["action"] == "applied"),
        "events must record the vendored purl with a camelCase action; got {events:?}"
    );

    // Anti-vacuity: the envelope reflects the real vendored result —
    // committed artifact + rewired lock, NO blobs and NO manifest (vendored
    // mode is manifest-free: the ledger's detached entry is the record).
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID1)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "missing {}", artifact.display());
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(".socket/vendor/npm/"), "lock:\n{lock}");
    assert!(!tmp.path().join(".socket/blobs").exists());
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "get --mode vendored must not write .socket/manifest.json"
    );
}

// ---------------------------------------------------------------------------
// (3) all-narrowed-out → not_installed
// ---------------------------------------------------------------------------

/// A GHSA fan-out whose every found version is uninstalled: exit 0 with the
/// additive `not_installed` status and the calm per-version skip records
/// (`errorCode: "package_not_installed"`). Exact whole-envelope equality —
/// this shape is the machine-readable "patches exist, none apply here"
/// signal bots route on. The skip is decided BEFORE download: zero
/// `view/` fetches is the request-level oracle.
#[tokio::test]
async fn get_ghsa_all_uninstalled_emits_not_installed_envelope() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;

    // Empty project: neither found version is installed anywhere.
    let tmp = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_get(tmp.path(), &server.uri(), &[GHSA, "--json"]);
    assert_eq!(
        code, 0,
        "all-narrowed-out is a calm exit-0 state.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let v = parse_single_json_doc(&stdout);
    let expected = serde_json::json!({
        "status": "not_installed",
        "found": 2,
        "downloaded": 0,
        "applied": 0,
        "patches": [
            {
                "purl": PURL1, "uuid": UUID1,
                "action": "skipped", "errorCode": "package_not_installed",
            },
            {
                "purl": PURL2, "uuid": UUID2,
                "action": "skipped", "errorCode": "package_not_installed",
            },
        ],
    });
    assert_eq!(
        v,
        expected,
        "not_installed envelope drifted.\nexpected:\n{}\ngot:\n{}",
        serde_json::to_string_pretty(&expected).unwrap(),
        serde_json::to_string_pretty(&v).unwrap(),
    );

    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "narrowed-out patches must never be view-fetched"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "nothing may be written when every version was narrowed out"
    );
}

// ---------------------------------------------------------------------------
// (4) --save-only + --mode conflict
// ---------------------------------------------------------------------------

/// `--save-only --mode hosted|vendored` is a usage conflict: exit 1 before
/// any network contact. Human mode names the conflict on stderr; `--json`
/// mode emits get's `{status:"error", error:<string>}` envelope on stdout.
#[tokio::test]
async fn save_only_with_mode_conflicts_exit_one() {
    // No mocks mounted: the zero-received-requests assertion below is the
    // "before any network contact" oracle.
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();

    for mode in ["hosted", "vendored"] {
        // Human path: stderr names both flags; stdout stays empty.
        let (code, stdout, stderr) = run_get(
            tmp.path(),
            &server.uri(),
            &[UUID1, "--mode", mode, "--save-only"],
        );
        assert_eq!(code, 1, "--save-only + --mode {mode} must exit 1");
        assert!(
            stdout.is_empty(),
            "conflict error is stderr-only in human mode; stdout: {stdout:?}"
        );
        assert!(
            stderr.contains("--save-only") && stderr.contains(&format!("--mode {mode}")),
            "stderr must name the conflicting flags; got:\n{stderr}"
        );

        // JSON path: ONE {status:"error"} envelope on stdout, exit 1.
        let (code, stdout, stderr) = run_get(
            tmp.path(),
            &server.uri(),
            &[UUID1, "--mode", mode, "--save-only", "--json"],
        );
        assert_eq!(
            code, 1,
            "--save-only + --mode {mode} --json must exit 1; stderr:\n{stderr}"
        );
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "error", "envelope={v}");
        let msg = v["error"]
            .as_str()
            .unwrap_or_else(|| panic!("get's conflict envelope carries a string error; got {v}"));
        assert!(
            msg.contains("--save-only") && msg.contains(&format!("--mode {mode}")),
            "the JSON error must name the conflicting flags; got: {msg}"
        );
    }

    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the conflict must be rejected before any network contact"
    );
    assert!(!tmp.path().join(".socket").exists());
}

// ---------------------------------------------------------------------------
// (5) --silent discipline
// ---------------------------------------------------------------------------

/// `get <uuid> --mode hosted --silent` (no `--json`) prints NOTHING to
/// stdout — `--silent` is "errors only" and the hosted engine's human
/// chatter is stdout-side. A loud control run proves the assertion isn't
/// vacuous (same scenario without `--silent` DOES print).
#[tokio::test]
async fn get_hosted_silent_prints_nothing_to_stdout() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[UUID1, "--mode", "hosted", "--silent"],
    );
    assert_eq!(
        code, 0,
        "silent hosted get should succeed.\nstderr:\n{stderr}"
    );
    assert!(
        stdout.is_empty(),
        "--silent must print NOTHING to stdout; got {stdout:?}"
    );
    // ...while still doing the work (the silence must not be a no-op's).
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(HOSTED_URL1),
        "silent run must still redirect; lock:\n{lock}"
    );
    assert!(tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .is_file());

    // Loud control: without --silent the human path prints the redirect
    // summary — otherwise the empty-stdout assertion above proves nothing.
    let tmp2 = tempfile::tempdir().unwrap();
    write_project(tmp2.path());
    let (loud_code, loud_stdout, loud_stderr) =
        run_get(tmp2.path(), &server.uri(), &[UUID1, "--mode", "hosted"]);
    assert_eq!(loud_code, 0, "stderr:\n{loud_stderr}");
    assert!(
        loud_stdout.contains("Redirected 1 package(s)"),
        "non-silent hosted run must print the redirect summary; got {loud_stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// (6) --dry-run envelopes
// ---------------------------------------------------------------------------

/// Hosted `--dry-run --json`: the same nested `redirect` object with
/// `dryRun: true` — and the envelope must describe a rewrite that did NOT
/// happen (lock byte-identical, no ledger).
#[tokio::test]
async fn get_hosted_dry_run_json_envelope() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let (code, stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[UUID1, "--mode", "hosted", "--dry-run", "--json"],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let v = parse_single_json_doc(&stdout);
    let expected = serde_json::json!({
        "status": "success",
        "found": 1,
        "patches": [],
        "redirect": {
            "mode": "hosted",
            "redirected": 1,
            "rewrittenFiles": ["package-lock.json"],
            "skipped": [],
            "warnings": [],
            "dryRun": true,
        },
    });
    assert_eq!(
        v,
        expected,
        "hosted dry-run envelope drifted.\nexpected:\n{}\ngot:\n{}",
        serde_json::to_string_pretty(&expected).unwrap(),
        serde_json::to_string_pretty(&v).unwrap(),
    );

    assert_eq!(
        lock_before,
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        "dry-run must not touch the lock"
    );
    assert!(!tmp.path().join(".socket").exists(), "no .socket writes");
}

/// Vendored `--dry-run --json`: scan's ledger-classification preview nested
/// under `vendor` (`dryRun: true` + per-patch `would_vendor`), before any
/// download or disk write — and no top-level `applied`/`downloaded` (the
/// download phase never ran).
#[tokio::test]
async fn get_vendored_dry_run_json_envelope() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let (code, stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[
            UUID1,
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--dry-run",
            "--json",
        ],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let v = parse_single_json_doc(&stdout);
    let expected = serde_json::json!({
        "status": "success",
        "found": 1,
        "patches": [],
        "vendor": {
            "dryRun": true,
            "patches": [
                { "purl": PURL1, "uuid": UUID1, "action": "would_vendor" },
            ],
        },
    });
    assert_eq!(
        v,
        expected,
        "vendored dry-run envelope drifted.\nexpected:\n{}\ngot:\n{}",
        serde_json::to_string_pretty(&expected).unwrap(),
        serde_json::to_string_pretty(&v).unwrap(),
    );

    assert_eq!(
        lock_before,
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        "dry-run must not touch the lock"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "vendored dry-run is a preview: no manifest, no artifacts, no ledger"
    );
}

// ── Cross-mode takeover: vendored → hosted, driven entirely by get ─────────

/// A purl vendored by `get --mode vendored` is then redirected by
/// `get --mode hosted`: the hosted engine's takeover pre-revert must unwind
/// the vendored wiring FIRST (restore the lock original, drop the ledger
/// entry, remove the committed artifact) and only then redirect — the
/// project ends fully hosted, never half-migrated (mode_migration_npm.rs's
/// invariants, exercised through get alone).
#[tokio::test]
async fn get_vendored_then_hosted_takes_over_cleanly() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    // Step 1: vendor via get.
    let (code, _stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[
            UUID1,
            "--mode",
            "vendored",
            "--json",
            "--vendor-source",
            "build",
        ],
    );
    assert_eq!(code, 0, "vendored step failed: {stderr}");
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID1)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "precondition: artifact committed");
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(".socket/vendor/npm/"),
        "precondition: lock vendored-wired; got:\n{lock}"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "precondition: vendored get wrote no manifest — the takeover unwinds a detached entry"
    );

    // Step 2: hosted via get — the takeover.
    let (code, stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[UUID1, "--mode", "hosted", "--json"],
    );
    assert_eq!(code, 0, "hosted takeover failed: {stderr}\n{stdout}");
    let envelope = parse_single_json_doc(&stdout);
    assert_eq!(envelope["redirect"]["redirected"], 1, "got: {envelope}");

    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(HOSTED_URL1) && lock.contains(PATCHED_SHA512),
        "lock must point at the hosted patch after takeover; got:\n{lock}"
    );
    assert!(
        !lock.contains(".socket/vendor/npm/"),
        "the vendored file: wiring must be fully unwound; got:\n{lock}"
    );
    assert!(
        !artifact.exists(),
        "the committed vendored artifact must be removed by the pre-revert"
    );
    // Vendor ledger entry gone (the file may be deleted outright when it
    // empties — both shapes mean "no longer vendor-owned").
    let vendor_state = tmp.path().join(".socket/vendor/state.json");
    if vendor_state.is_file() {
        let state = std::fs::read_to_string(&vendor_state).unwrap();
        assert!(
            !state.contains(UUID1),
            "the vendored ledger must no longer claim the purl; got:\n{state}"
        );
    }
    // Hosted ledger present with the record.
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger["records"][PURL1]["uuid"], UUID1);
    // The takeover is announced, not silent.
    assert!(
        stdout.contains("redirect_takeover_reverted_vendored"),
        "the takeover warning must ride the envelope; got:\n{stdout}"
    );
}

// ── bugbot follow-ups: variant-filter wiring (hosted) + PnP-only message ────

/// Hosted mode runs the per-release VARIANT filter (agent/vendored get it
/// inside the download engines; hosted has no download). The uninstalled-base
/// fallback keeps all variants WITH its distinctive warning — the warning's
/// presence in the envelope is the wiring pin.
#[tokio::test]
async fn get_hosted_runs_release_variant_filter() {
    const V_UUID_A: &str = "55555555-5555-4555-8555-555555555555";
    const V_UUID_B: &str = "66666666-6666-4666-8666-666666666666";
    const V_PURL_A: &str = "pkg:pypi/varpkg@1.0.0?artifact_id=wheel";
    const V_PURL_B: &str = "pkg:pypi/varpkg@1.0.0?artifact_id=sdist";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                { "uuid": V_UUID_A, "purl": V_PURL_A,
                  "publishedAt": "2024-01-01T00:00:00Z",
                  "description": "x", "license": "MIT", "tier": "free",
                  "vulnerabilities": {} },
                { "uuid": V_UUID_B, "purl": V_PURL_B,
                  "publishedAt": "2024-01-01T00:00:00Z",
                  "description": "x", "license": "MIT", "tier": "free",
                  "vulnerabilities": {} }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    // Grants for both (the uninstalled-base fallback keeps all variants).
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {}
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    // Coarse presence via manifest membership (nothing installed on disk):
    // the run must fall through to the VARIANT filter, whose not-installed
    // fallback emits the pinned warning.
    let socket_dir = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    std::fs::write(
        socket_dir.join("manifest.json"),
        serde_json::json!({
            "patches": {
                "pkg:pypi/varpkg@1.0.0": {
                    "uuid": "99999999-9999-4999-8999-999999999999",
                    "exportedAt": "2023-01-01T00:00:00Z",
                    "files": {}, "vulnerabilities": {},
                    "description": "old", "license": "MIT", "tier": "free"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_get(
        tmp.path(),
        &server.uri(),
        &[GHSA, "--mode", "hosted", "--json"],
    );
    assert_eq!(code, 0, "stderr: {stderr}\nstdout: {stdout}");
    let envelope = parse_single_json_doc(&stdout);
    let warnings = envelope["warnings"].to_string();
    assert!(
        warnings.contains("release_narrowing") && warnings.contains("keeping all"),
        "the variant filter's not-installed fallback warning must ride the \
         hosted envelope (proves the filter runs on the hosted path); got: {envelope}"
    );
}

/// When EVERY narrowed-out result is a PnP layout refusal, the human
/// terminal must point at the layout warning — never claim "not installed"
/// or advise --all-releases (which cannot make PnP patchable).
#[tokio::test]
async fn get_pnp_only_narrowing_message_names_the_layout() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        format!(r#"{{ "name": "consumer", "dependencies": {{ "{NAME}": "1.0.0" }} }}"#),
    )
    .unwrap();
    std::fs::write(tmp.path().join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    std::fs::write(tmp.path().join(".pnp.cjs"), "/* yarn berry PnP loader */").unwrap();

    let (code, stdout, stderr) = run_get(tmp.path(), &server.uri(), &[GHSA]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("Plug'n'Play"),
        "the PnP-only terminal must name the layout; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("--all-releases"),
        "--all-releases cannot make PnP patchable and must not be advised; \
         stdout:\n{stdout}"
    );
    assert!(
        stderr.contains("yarn_pnp_unsupported"),
        "the layout refusal warning must be on stderr; stderr:\n{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Bun vendored-mode preflight through `get`: --silent, --dry-run, --save-only
// ---------------------------------------------------------------------------

const ENCODED1: &str = "pkg%3Anpm%2Fgetmodes-pkg%401.0.0";
const BUN_WS_CODE: &str = "vendor_bun_workspace_unsupported";

/// The per-package search for the exact PURL identifier path.
async fn mock_by_package(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/by-package/{ENCODED1}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID1, "purl": PURL1,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "get-modes fixture", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// `write_project` re-locked by bun 1.3.14 as a workspace: the real
/// lockfileVersion-1 grammar (1-tuple `workspace:` entry, blank line
/// between entries, trailing commas), `getmodes-pkg` declared by the
/// member — the shape the vendored gate refuses.
fn write_bun_workspace_project(root: &Path) {
    write_project(root);
    std::fs::remove_file(root.join("package-lock.json")).unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "consumer", "version": "0.0.0", "private": true, "workspaces": ["packages/*"], "dependencies": { "app": "workspace:*" } }"#,
    )
    .unwrap();
    let app = root.join("packages/app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("package.json"),
        format!(
            r#"{{ "name": "app", "version": "1.0.0", "dependencies": {{ "{NAME}": "1.0.0" }} }}"#
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("bun.lock"),
        format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"configVersion\": 1,\n  \"workspaces\": {{\n    \"\": {{\n      \"name\": \"consumer\",\n      \"dependencies\": {{\n        \"app\": \"workspace:*\",\n      }},\n    }},\n    \"packages/app\": {{\n      \"name\": \"app\",\n      \"version\": \"1.0.0\",\n      \"dependencies\": {{\n        \"{NAME}\": \"1.0.0\",\n      }},\n    }},\n  }},\n  \"packages\": {{\n    \"app\": [\"app@workspace:packages/app\"],\n\n    \"{NAME}\": [\"{NAME}@1.0.0\", \"\", {{}}, \"sha512-UPSTREAMupstream==\"],\n  }}\n}}\n"
        ),
    )
    .unwrap();
}

/// `--silent` is "errors only": the Bun refusal is an error, so BOTH
/// identifier kinds keep it on stderr — code-tagged — with an empty
/// stdout and exit 1. Regression guard: the refusal lines were gated on
/// `!silent`, so a `--silent` run exited 1 with no text anywhere.
#[tokio::test]
async fn get_vendored_refusal_visible_under_silent() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_by_package(&server).await;

    for (label, ident) in [("purl", PURL1), ("uuid", UUID1)] {
        let tmp = tempfile::tempdir().unwrap();
        write_bun_workspace_project(tmp.path());
        let lock_before = std::fs::read(tmp.path().join("bun.lock")).unwrap();
        let (code, stdout, stderr) = run_get(
            tmp.path(),
            &server.uri(),
            &[
                ident,
                "--mode",
                "vendored",
                "--vendor-source",
                "build",
                "--silent",
            ],
        );
        assert_eq!(code, 1, "{label}: stdout={stdout}\nstderr={stderr}");
        assert!(
            stdout.trim().is_empty(),
            "{label}: --silent must print nothing on stdout:\n{stdout}"
        );
        assert!(
            stderr.contains(BUN_WS_CODE),
            "{label}: --silent must keep the refusal code on stderr:\n{stderr}"
        );
        if label == "purl" {
            assert!(
                stderr.contains(&format!("[error] {PURL1} ({BUN_WS_CODE}):")),
                "purl path prints the code-tagged per-patch line:\n{stderr}"
            );
        } else {
            assert!(
                stderr.contains(&format!("Error ({BUN_WS_CODE}):")),
                "uuid path prints the code-tagged Error line:\n{stderr}"
            );
        }
        assert_eq!(
            std::fs::read(tmp.path().join("bun.lock")).unwrap(),
            lock_before,
            "{label}: refused runs never touch the lock"
        );
        assert!(!tmp.path().join(".socket/vendor").exists(), "{label}");
    }
}

/// The vendored dry-run preview names what the wet run would refuse:
/// `would_refuse` + `errorCode` + `error` (additive) instead of
/// `would_vendor`, on both identifier kinds — exit 0, `status:"success"`,
/// nothing written, exactly like every other vendored preview.
#[tokio::test]
async fn get_vendored_dry_run_reports_bun_refusal() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_by_package(&server).await;

    for (label, ident) in [("purl", PURL1), ("uuid", UUID1)] {
        let tmp = tempfile::tempdir().unwrap();
        write_bun_workspace_project(tmp.path());
        let lock_before = std::fs::read(tmp.path().join("bun.lock")).unwrap();
        let (code, stdout, stderr) = run_get(
            tmp.path(),
            &server.uri(),
            &[
                ident,
                "--mode",
                "vendored",
                "--vendor-source",
                "build",
                "--dry-run",
                "--json",
            ],
        );
        assert_eq!(code, 0, "{label}: stdout={stdout}\nstderr={stderr}");
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "success", "{label}: {v}");
        assert_eq!(v["found"], 1, "{label}: {v}");
        assert_eq!(v["vendor"]["dryRun"], true, "{label}: {v}");
        let rec = &v["vendor"]["patches"][0];
        assert_eq!(rec["purl"], PURL1, "{label}: {v}");
        assert_eq!(rec["uuid"], UUID1, "{label}: {v}");
        assert_eq!(rec["action"], "would_refuse", "{label}: {v}");
        assert_eq!(rec["errorCode"], BUN_WS_CODE, "{label}: {v}");
        assert!(
            rec["error"].as_str().is_some_and(|d| !d.is_empty()),
            "{label}: {v}"
        );
        assert_eq!(
            std::fs::read(tmp.path().join("bun.lock")).unwrap(),
            lock_before,
            "{label}: dry-run must not touch the lock"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "{label}: vendored dry-run is a preview: no manifest, no artifacts, no ledger"
        );
    }
}

/// The preflight is scoped to the vendored posture: an agent-mode
/// `get --save-only` on the same refused workspace project records the
/// patch and persists the blob like on any other project (record-only
/// intent has no Bun precondition; the fresh-clone record→vendor flow
/// keeps working).
#[tokio::test]
async fn get_save_only_agent_ignores_bun_preflight() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_by_package(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_workspace_project(tmp.path());

    let (code, stdout, stderr) =
        run_get(tmp.path(), &server.uri(), &[PURL1, "--save-only", "--json"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["patches"][0]["action"], "added", "{v}");
    assert!(v["patches"][0].get("errorCode").is_none(), "{v}");
    assert_eq!(requests_containing(&server, "/patches/view/").await, 1);
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["patches"][PURL1]["uuid"], UUID1, "{manifest}");
    assert!(
        tmp.path()
            .join(".socket/blobs")
            .join(common::git_sha256(AFTER_BYTES))
            .is_file(),
        "the agent download persists the after-blob"
    );
}
