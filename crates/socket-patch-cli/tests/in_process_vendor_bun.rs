//! Hermetic subprocess tests for the Bun VENDORED-mode refusals and their
//! positive twins: `scan --mode vendored` (with and without the no-op
//! `--detached`), `get <uuid> --mode vendored`, `get <purl> --mode
//! vendored`, their `--dry-run` previews, `--silent`, and the agent
//! `--save-only` exemption — driven through the built binary against a
//! wiremock patch API, on lockfiles written in the grammar REAL bun
//! releases emit (captured in the PR #245 compatibility matrix and from a
//! bun 1.1.45 `--save-text-lockfile` run):
//!
//! * lockfileVersion 1 (bun 1.2.x–1.3.x) / 2 (bun 1.4.x) workspace locks:
//!   1-tuple `"consumer": ["consumer@workspace:packages/consumer"]`, a
//!   blank line between entries, trailing commas;
//! * lockfileVersion 0 (bun 1.1.39–1.1.45 `--save-text-lockfile`): no
//!   `configVersion`, the root's workspace dep spelled as a bare path, and
//!   the 2-tuple `["consumer@workspace:packages/consumer", { "dependencies":
//!   { … } }]`;
//! * a malformed `bun.lockb` with no text lock;
//! * a malformed lock (`lockfileVersion` 3, non-canonical `"packages" : {`
//!   header, unterminated entry) and — on Unix — a FIFO squatting
//!   `bun.lock`.
//!
//! Every refusal test pins the whole observable contract: exit code; the
//! exact envelope shape (uuid path: `status:"error"` with `error{code,
//! message}` and a `failed` record carrying `errorCode` AND `error`; scan
//! and purl paths: `partial_failure` with the same record); ZERO
//! `/patches/view/` fetches for the refused patch (request-log oracle); a
//! byte-identical `bun.lock`; no `.socket/vendor/`; and — where a legacy
//! manifest existed — that manifest surviving byte-for-byte (vendored mode
//! never touches it).
//!
//! No `#[serial]`: the child gets a scrubbed env copy (`common::run_with_env`).

use std::path::Path;
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
/// A second, unrelated manifest record (never installed here) used to prove
/// a pre-existing manifest survives a refused run.
const OTHER_UUID: &str = "22222222-2222-4222-8222-222222222222";
const OTHER_PURL: &str = "pkg:npm/other-pkg@2.0.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
/// The real registry integrity of left-pad@1.3.0 (spike BN3 fixture).
const LEFT_PAD_SHA512: &str =
    "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
const WS_CODE: &str = "vendor_bun_workspace_unsupported";
const LOCKB_CODE: &str = "vendor_bun_lockb_invalid";
const VERSION_CODE: &str = "vendor_lockfile_version_unsupported";
const MISSING_CODE: &str = "vendor_lockfile_missing";

// ---------------------------------------------------------------------------
// Fixtures: real bun grammar
// ---------------------------------------------------------------------------

/// The registry 4-tuple bun writes for left-pad@1.3.0 (identical across
/// lockfileVersion 0/1/2).
fn registry_line() -> String {
    format!("    \"left-pad\": [\"left-pad@1.3.0\", \"\", {{}}, \"{LEFT_PAD_SHA512}\"],\n")
}

/// bun 1.3.14 (lockfileVersion 1) / bun 1.4.2 (lockfileVersion 2) workspace
/// lock, byte-for-byte the matrix capture grammar (the two versions differ
/// only in the version integer).
const WS_V1V2_TEMPLATE: &str = r#"{
  "lockfileVersion": {VERSION},
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bun-fixture",
      "dependencies": {
        "consumer": "workspace:*",
      },
    },
    "packages/consumer": {
      "name": "consumer",
      "version": "1.0.0",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
    "consumer": ["consumer@workspace:packages/consumer"],

{REGISTRY}  }
}
"#;

/// bun 1.1.45 `--save-text-lockfile` workspace lock: lockfileVersion 0, no
/// `configVersion`, root workspace dep as a bare path, 2-tuple workspace
/// entry carrying the member's deps object.
const WS_V0_TEMPLATE: &str = r#"{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "name": "bun-fixture",
      "dependencies": {
        "consumer": "packages/consumer",
      },
    },
    "packages/consumer": {
      "name": "consumer",
      "version": "1.0.0",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
    "consumer": ["consumer@workspace:packages/consumer", { "dependencies": { "left-pad": "1.3.0" } }],

{REGISTRY}  }
}
"#;

/// bun 1.1.45 `--save-text-lockfile` single-package lock (matrix
/// `1.1.45-text-*` captures): lockfileVersion 0, no `configVersion`.
const DIRECT_V0_TEMPLATE: &str = r#"{
  "lockfileVersion": 0,
  "workspaces": {
    "": {
      "name": "bun-fixture",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
{REGISTRY}  }
}
"#;

/// bun 1.3.x single-package lock (spike BN3 grammar).
const DIRECT_V1_TEMPLATE: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bun-fixture",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
{REGISTRY}  }
}
"#;

/// A future/hand-edited lock the version gate refuses: lockfileVersion 3,
/// a non-canonical `"packages" : {` header and an unterminated entry.
const MALFORMED_V3_LOCK: &str = "{\n  \"lockfileVersion\": 3,\n  \"packages\" : {\n    \"left-pad\": [\"left-pad@1.3.0\", \"\",\n  }\n}\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockShape {
    V0Workspace,
    V1Workspace,
    V2Workspace,
    V0Direct,
    V1Direct,
    MalformedLockb,
    MalformedV3,
}

impl LockShape {
    fn is_workspace(self) -> bool {
        matches!(
            self,
            LockShape::V0Workspace | LockShape::V1Workspace | LockShape::V2Workspace
        )
    }

    /// The text lock for this shape (`None` = binary `bun.lockb` only).
    fn lock_text(self) -> Option<String> {
        let registry = registry_line();
        let text = match self {
            LockShape::V1Workspace => WS_V1V2_TEMPLATE.replace("{VERSION}", "1"),
            LockShape::V2Workspace => WS_V1V2_TEMPLATE.replace("{VERSION}", "2"),
            LockShape::V0Workspace => WS_V0_TEMPLATE.to_string(),
            LockShape::V0Direct => DIRECT_V0_TEMPLATE.to_string(),
            LockShape::V1Direct => DIRECT_V1_TEMPLATE.to_string(),
            LockShape::MalformedV3 => return Some(MALFORMED_V3_LOCK.to_string()),
            LockShape::MalformedLockb => return None,
        };
        Some(text.replace("{REGISTRY}", &registry))
    }
}

/// A bun project with left-pad@1.3.0 INSTALLED (hoisted `node_modules/`,
/// which every bun release through 1.2.x lays out and the crawler
/// resolves) and lock-resolved in the requested grammar. Workspace shapes
/// declare left-pad from `packages/consumer` (the member-declared case the
/// vendored gate exists for).
fn write_bun_project(root: &Path, shape: LockShape) {
    let root_pkg = if shape.is_workspace() {
        r#"{"name":"bun-fixture","version":"1.0.0","private":true,"workspaces":["packages/*"],"dependencies":{"consumer":"workspace:*"}}"#
    } else {
        r#"{"name":"bun-fixture","version":"1.0.0","private":true,"dependencies":{"left-pad":"1.3.0"}}"#
    };
    std::fs::write(root.join("package.json"), root_pkg).unwrap();
    if shape.is_workspace() {
        let consumer = root.join("packages/consumer");
        std::fs::create_dir_all(&consumer).unwrap();
        std::fs::write(
            consumer.join("package.json"),
            r#"{"name":"consumer","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
        )
        .unwrap();
    }
    write_installed_left_pad(root);
    match shape.lock_text() {
        Some(text) => std::fs::write(root.join("bun.lock"), text).unwrap(),
        None => std::fs::write(root.join("bun.lockb"), b"\x00bun-lockb\x00").unwrap(),
    }
}

fn write_installed_left_pad(dir: &Path) {
    let pkg = dir.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// A schema-valid manifest holding ONE record for [`OTHER_PURL`], written
/// COMPACT (single line) so any rewrite — even a semantically identical
/// re-serialization — is detectable byte-for-byte. Returns the bytes.
fn seed_other_manifest_record(root: &Path) -> Vec<u8> {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let record = serde_json::json!({
        "uuid": OTHER_UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": common::git_sha256(BEFORE),
                "afterHash": common::git_sha256(AFTER),
            }
        },
        "vulnerabilities": {},
        "description": "seeded record",
        "license": "MIT",
        "tier": "free",
    });
    let manifest = serde_json::json!({ "patches": { OTHER_PURL: record } });
    let bytes = serde_json::to_vec(&manifest).unwrap();
    std::fs::write(socket.join("manifest.json"), &bytes).unwrap();
    bytes
}

// ---------------------------------------------------------------------------
// Mock API
// ---------------------------------------------------------------------------

fn view_body(uuid: &str, purl: &str) -> serde_json::Value {
    use base64::Engine as _;
    let blob_content = base64::engine::general_purpose::STANDARD.encode(AFTER);
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": common::git_sha256(BEFORE),
                "afterHash": common::git_sha256(AFTER),
                "blobContent": blob_content,
            }
        },
        "vulnerabilities": {
            "GHSA-aaaa-bbbb-cccc": {
                "cves": ["CVE-2026-0001"],
                "summary": "bun fixture",
                "severity": "high",
                "description": "d"
            }
        },
        "description": "bun fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// Discovery (batch), per-package search and the full view for [`UUID`] /
/// [`PURL`] — the same recipe as `scan_vendor_e2e.rs`.
async fn mount_patch_api(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID,
                    "purl": PURL,
                    "tier": "free",
                    "cveIds": ["CVE-2026-0001"],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "bun fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-package/{ENCODED}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "bun fixture",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    mount_view(mock, UUID, PURL).await;
}

async fn mount_view(mock: &MockServer, uuid: &str, purl: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view_body(uuid, purl)))
        .mount(mock)
        .await;
}

/// `/patches/view/{uuid}` fetches the mock saw.
async fn view_requests_for(mock: &MockServer, uuid: &str) -> usize {
    mock.received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with(&format!("/patches/view/{uuid}")))
        .count()
}

// ---------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------

fn run(root: &Path, argv: &[&str]) -> (i32, String, String) {
    common::run_with_env(root, argv, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

fn with_api<'a>(argv: &[&'a str], uri: &'a str) -> Vec<&'a str> {
    let mut v = argv.to_vec();
    v.extend_from_slice(&[
        "--api-url",
        uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG,
        "--yes",
    ]);
    v
}

fn scan_vendored(root: &Path, uri: &str, extra: &[&str]) -> (i32, String, String) {
    let mut argv = vec!["scan", "--mode", "vendored", "--vendor-source", "build"];
    argv.extend_from_slice(extra);
    run(root, &with_api(&argv, uri))
}

fn get_vendored(root: &Path, uri: &str, ident: &str, extra: &[&str]) -> (i32, String, String) {
    let mut argv = vec![
        "get",
        ident,
        "--mode",
        "vendored",
        "--vendor-source",
        "build",
    ];
    argv.extend_from_slice(extra);
    run(root, &with_api(&argv, uri))
}

/// Parse stdout as exactly ONE JSON document (`from_str` rejects trailing
/// data, so a second envelope or a stray human line fails loudly).
fn parse_single_json_doc(stdout: &str) -> serde_json::Value {
    let trimmed = stdout.trim();
    assert!(!trimmed.is_empty(), "expected a JSON envelope on stdout");
    serde_json::from_str(trimmed).unwrap_or_else(|e| {
        panic!("stdout must be exactly one JSON document: {e}\nstdout:\n{stdout}")
    })
}

fn lock_bytes(root: &Path) -> Vec<u8> {
    std::fs::read(root.join("bun.lock")).unwrap()
}

fn manifest_value(root: &Path) -> Option<serde_json::Value> {
    let body = std::fs::read_to_string(root.join(".socket/manifest.json")).ok()?;
    Some(serde_json::from_str(&body).unwrap_or_else(|e| panic!("manifest not JSON: {e}\n{body}")))
}

/// The refused `failed` record every entry point must emit for [`PURL`].
fn assert_refused_record(record: &serde_json::Value, code: &str, ctx: &serde_json::Value) {
    assert_eq!(record["purl"], PURL, "{ctx}");
    assert_eq!(record["uuid"], UUID, "{ctx}");
    assert_eq!(record["action"], "failed", "{ctx}");
    assert_eq!(record["errorCode"], code, "{ctx}");
    assert!(
        record["error"].as_str().is_some_and(|d| !d.is_empty()),
        "a refused record must carry the engine's detail text: {ctx}"
    );
}

/// The on-disk invariants of EVERY refusal: lock bytes untouched, nothing
/// vendored, no record for [`PURL`] in the manifest (if one exists).
fn assert_refusal_left_tree_alone(root: &Path, lock_before: &[u8]) {
    if root.join("bun.lock").exists() {
        assert_eq!(
            lock_bytes(root),
            lock_before,
            "bun.lock must be byte-identical"
        );
    }
    assert!(
        !root.join(".socket/vendor").exists(),
        "a refused run must not create .socket/vendor/"
    );
    if let Some(m) = manifest_value(root) {
        assert!(
            m["patches"].get(PURL).is_none(),
            "the refused purl must not be recorded: {m}"
        );
    }
}

// ---------------------------------------------------------------------------
// scan --mode vendored: the download-phase refusal, per lock shape
// ---------------------------------------------------------------------------

/// Drive `scan --mode vendored --json` on `shape` and pin the refusal
/// contract for `code`: exit 1, `partial_failure`, the download-phase
/// record, zero downloads, zero view fetches, engine untouched.
async fn assert_scan_refuses(shape: LockShape, code: &str) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), shape);
    let lock_before = if tmp.path().join("bun.lock").exists() {
        lock_bytes(tmp.path())
    } else {
        Vec::new()
    };

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--json"]);
    assert_eq!(exit, 1, "{shape:?}: stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "partial_failure", "{shape:?}: {v}");
    let dl = &v["download"];
    assert_eq!(dl["found"], 1, "{v}");
    assert_eq!(dl["downloaded"], 0, "{v}");
    assert_eq!(dl["skipped"], 0, "{v}");
    assert_eq!(dl["failed"], 1, "{v}");
    assert_refused_record(&dl["patches"][0], code, &v);
    assert_eq!(
        v["vendor"]["summary"]["applied"], 0,
        "nothing may be vendored: {v}"
    );
    assert_eq!(
        view_requests_for(&mock, UUID).await,
        0,
        "{shape:?}: a refused patch must never be fetched"
    );
    assert_refusal_left_tree_alone(tmp.path(), &lock_before);
    // Vendored mode is manifest-free, and a fully refused run has nothing
    // to vendor: nothing at all is created under `.socket/`.
    assert!(
        !tmp.path().join(".socket").exists(),
        "{shape:?}: a refused run must create nothing under .socket/"
    );
}

#[tokio::test]
async fn scan_vendored_refuses_v1_workspace_lock_before_download() {
    assert_scan_refuses(LockShape::V1Workspace, WS_CODE).await;
}

#[tokio::test]
async fn scan_vendored_refuses_v0_workspace_two_tuple_lock_before_download() {
    assert_scan_refuses(LockShape::V0Workspace, WS_CODE).await;
}

#[tokio::test]
async fn scan_vendored_refuses_malformed_bun_lockb_before_download() {
    assert_scan_refuses(LockShape::MalformedLockb, LOCKB_CODE).await;
}

#[tokio::test]
async fn scan_vendored_refuses_malformed_v3_lock_before_download() {
    assert_scan_refuses(LockShape::MalformedV3, VERSION_CODE).await;
}

/// A refused scan on a project with a legacy (agent-mode) manifest: the
/// manifest is not vendored mode's business — it survives byte-for-byte
/// (never re-serialized, never fetched for), and the refused purl is still
/// not recorded anywhere.
#[tokio::test]
async fn scan_vendored_refusal_preserves_seeded_manifest_record() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Workspace);
    let seeded = seed_other_manifest_record(tmp.path());
    let lock_before = lock_bytes(tmp.path());

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--json"]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_refused_record(&v["download"]["patches"][0], WS_CODE, &v);
    assert_eq!(view_requests_for(&mock, UUID).await, 0);
    assert_eq!(
        view_requests_for(&mock, OTHER_UUID).await,
        0,
        "a legacy manifest record is never staged by a vendored scan"
    );
    assert_refusal_left_tree_alone(tmp.path(), &lock_before);
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        seeded,
        "the legacy manifest must survive byte-for-byte"
    );
}

// ---------------------------------------------------------------------------
// scan --mode vendored --detached: the same refusal, BEFORE any fetch
// ---------------------------------------------------------------------------

/// The detached download phase used to skip the preflight: the patch view
/// was fetched (`download.downloaded: 1`) and the refusal only surfaced
/// from the vendor engine afterwards (degrading to `package_not_installed`
/// for alias installs). Now it refuses exactly like the manifest-tracked
/// phase — pre-fetch, with the vendor code — and, being detached, writes
/// no manifest at all.
#[tokio::test]
async fn scan_vendored_detached_refuses_v1_workspace_before_fetch() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Workspace);
    let lock_before = lock_bytes(tmp.path());

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--detached", "--json"]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "partial_failure", "{v}");
    let dl = &v["download"];
    assert_eq!(dl["detached"], true, "{v}");
    assert_eq!(
        dl["downloaded"], 0,
        "detached must refuse BEFORE fetching: {v}"
    );
    assert_eq!(dl["failed"], 1, "{v}");
    assert_refused_record(&dl["patches"][0], WS_CODE, &v);
    assert_eq!(view_requests_for(&mock, UUID).await, 0);
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "detached mode never writes a manifest"
    );
    assert_refusal_left_tree_alone(tmp.path(), &lock_before);
}

/// The lockb twin of the detached refusal: the shape that used to
/// misreport `package_not_installed` after a needless fetch.
#[tokio::test]
async fn scan_vendored_detached_refuses_bun_lockb_before_fetch() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::MalformedLockb);

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--detached", "--json"]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["download"]["downloaded"], 0, "{v}");
    assert_refused_record(&v["download"]["patches"][0], LOCKB_CODE, &v);
    assert!(
        !v["vendor"]["events"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .any(|e| e["errorCode"] == "package_not_installed"),
        "the refusal must not degrade to package_not_installed: {v}"
    );
    assert_eq!(view_requests_for(&mock, UUID).await, 0);
    assert!(!tmp.path().join(".socket/manifest.json").exists());
    assert!(!tmp.path().join(".socket/vendor").exists());
}

// ---------------------------------------------------------------------------
// get <uuid> --mode vendored: the pre-record refusal envelope
// ---------------------------------------------------------------------------

/// `get <uuid> --mode vendored --json` on a refused Bun project exits 1
/// with EXACTLY this envelope (contract: uuid-path pre-record refusal):
/// `status:"error"`, `error{code,message}`, counts, and a `failed` record
/// carrying both `errorCode` and `error`. The uuid lookup itself is the
/// only network traffic (one view fetch — that IS the identifier
/// resolution), and NOTHING is written: no `.socket/` at all.
#[tokio::test]
async fn get_uuid_vendored_refusal_envelope_is_exact_and_writes_nothing() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Workspace);
    let lock_before = lock_bytes(tmp.path());

    let (exit, stdout, stderr) = get_vendored(tmp.path(), &mock.uri(), UUID, &["--json"]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    let detail = v["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("error.message must be a string: {v}"))
        .to_string();
    assert!(!detail.is_empty(), "{v}");
    let expected = serde_json::json!({
        "status": "error",
        "found": 1,
        "downloaded": 0,
        "skipped": 0,
        "failed": 1,
        "error": { "code": WS_CODE, "message": detail },
        "patches": [{
            "purl": PURL,
            "uuid": UUID,
            "action": "failed",
            "errorCode": WS_CODE,
            "error": detail,
        }],
    });
    assert_eq!(
        v,
        expected,
        "uuid-path refusal envelope drifted.\nexpected:\n{}\ngot:\n{}",
        serde_json::to_string_pretty(&expected).unwrap(),
        serde_json::to_string_pretty(&v).unwrap(),
    );
    assert_eq!(
        view_requests_for(&mock, UUID).await,
        1,
        "the uuid lookup is the only fetch"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "the uuid path refuses before creating .socket/"
    );
    assert_eq!(lock_bytes(tmp.path()), lock_before);
}

/// Human mode prints the code-tagged `Error (…)` line to stderr, nothing
/// on stdout, exit 1 — and writes nothing.
#[tokio::test]
async fn get_uuid_vendored_refusal_human_names_code_on_stderr() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::MalformedLockb);

    let (exit, stdout, stderr) = get_vendored(tmp.path(), &mock.uri(), UUID, &[]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("Error ({LOCKB_CODE}):")),
        "stderr must carry the code-tagged error line:\n{stderr}"
    );
    assert!(
        !stdout.contains(LOCKB_CODE) && !stdout.contains("Patch record saved"),
        "the refusal must not be reported as a save on stdout:\n{stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

// ---------------------------------------------------------------------------
// get <purl> --mode vendored: the search-path refusal
// ---------------------------------------------------------------------------

/// The search path shares `scan`'s download phase: `partial_failure`, the
/// same `failed` record (with `errorCode` + `error`), zero fetches, an
/// empty vendor envelope, `applied` dropped — and, vendored mode being
/// manifest-free, no manifest.
#[tokio::test]
async fn get_purl_vendored_refuses_v1_workspace_before_fetch() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Workspace);
    let lock_before = lock_bytes(tmp.path());

    let (exit, stdout, stderr) = get_vendored(tmp.path(), &mock.uri(), PURL, &["--json"]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "partial_failure", "{v}");
    assert_eq!(v["found"], 1, "{v}");
    assert_eq!(v["downloaded"], 0, "{v}");
    assert_eq!(v["skipped"], 0, "{v}");
    assert_eq!(v["failed"], 1, "{v}");
    assert!(
        v.get("applied").is_none(),
        "vendored mode drops `applied`: {v}"
    );
    assert_refused_record(&v["patches"][0], WS_CODE, &v);
    assert_eq!(v["vendor"]["summary"]["applied"], 0, "{v}");
    assert_eq!(view_requests_for(&mock, UUID).await, 0);
    assert_refusal_left_tree_alone(tmp.path(), &lock_before);
    assert_eq!(
        manifest_value(tmp.path()),
        None,
        "vendored mode never writes a manifest"
    );
}

// ---------------------------------------------------------------------------
// --silent: errors only, so the refusal stays visible (code-tagged)
// ---------------------------------------------------------------------------

/// `--silent` mutes informational chatter, never errors: each refusing
/// entry point exits 1 with an EMPTY stdout and the stable code (plus the
/// purl on the per-patch paths) on stderr. Regression guard: the refusal
/// lines were gated on `!silent` and a `--silent` run exited 1 mutely.
#[tokio::test]
async fn silent_refusals_stay_visible_on_stderr_with_empty_stdout() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;

    for (label, argv) in [
        (
            "get <purl>",
            vec!["get", PURL, "--mode", "vendored", "--silent"],
        ),
        (
            "get <uuid>",
            vec!["get", UUID, "--mode", "vendored", "--silent"],
        ),
        ("scan", vec!["scan", "--mode", "vendored", "--silent"]),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_bun_project(tmp.path(), LockShape::V1Workspace);
        let mut argv = argv;
        argv.extend_from_slice(&["--vendor-source", "build"]);
        let (exit, stdout, stderr) = run(tmp.path(), &with_api(&argv, &mock.uri()));
        assert_eq!(exit, 1, "{label}: stdout={stdout}\nstderr={stderr}");
        assert!(
            stdout.trim().is_empty(),
            "{label}: --silent must print nothing to stdout:\n{stdout}"
        );
        assert!(
            stderr.contains(WS_CODE),
            "{label}: --silent must still name the refusal code on stderr:\n{stderr}"
        );
        if label != "get <uuid>" {
            assert!(
                stderr.contains(PURL),
                "{label}: the per-patch error line must name the purl:\n{stderr}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// --dry-run: the preview names the refusal (additive `would_refuse`)
// ---------------------------------------------------------------------------

/// The vendored dry-run preview is a ledger classification by contract
/// (exit 0, `status:"success"`, nothing written); on a Bun project the
/// wet run is known to refuse, its npm records become the additive
/// `would_refuse` (+`errorCode`/`error`) instead of advertising
/// `would_vendor`. All three entry points; nothing touched on disk.
#[tokio::test]
async fn dry_run_previews_report_would_refuse_on_refused_bun_project() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;

    for (label, argv) in [
        (
            "scan",
            vec!["scan", "--mode", "vendored", "--dry-run", "--json"],
        ),
        (
            "scan --detached",
            vec![
                "scan",
                "--mode",
                "vendored",
                "--detached",
                "--dry-run",
                "--json",
            ],
        ),
        (
            "get <uuid>",
            vec!["get", UUID, "--mode", "vendored", "--dry-run", "--json"],
        ),
        (
            "get <purl>",
            vec!["get", PURL, "--mode", "vendored", "--dry-run", "--json"],
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_bun_project(tmp.path(), LockShape::V1Workspace);
        let lock_before = lock_bytes(tmp.path());
        let (exit, stdout, stderr) = run(tmp.path(), &with_api(&argv, &mock.uri()));
        assert_eq!(
            exit, 0,
            "{label}: a preview never flips the exit: {stdout}\n{stderr}"
        );
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "success", "{label}: {v}");
        let preview = &v["vendor"];
        assert_eq!(preview["dryRun"], true, "{label}: {v}");
        let rec = &preview["patches"][0];
        assert_eq!(rec["purl"], PURL, "{label}: {v}");
        assert_eq!(rec["uuid"], UUID, "{label}: {v}");
        assert_eq!(rec["action"], "would_refuse", "{label}: {v}");
        assert_eq!(rec["errorCode"], WS_CODE, "{label}: {v}");
        assert!(
            rec["error"].as_str().is_some_and(|d| !d.is_empty()),
            "{label}: {v}"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "{label}: a dry run writes nothing"
        );
        assert_eq!(lock_bytes(tmp.path()), lock_before, "{label}");
    }
}

/// The human dry-run keeps its count line and additionally names what the
/// wet run would refuse — under `--silent` it prints nothing at all.
#[tokio::test]
async fn dry_run_human_names_would_refuse_records() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::MalformedLockb);

    let (exit, stdout, stderr) = get_vendored(tmp.path(), &mock.uri(), PURL, &["--dry-run"]);
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("[dry-run] Would download and vendor 1 patch(es)."),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("[would-refuse] {PURL} ({LOCKB_CODE}):")),
        "the human preview must name the refusal:\n{stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());

    let (exit, stdout, _) = get_vendored(tmp.path(), &mock.uri(), PURL, &["--dry-run", "--silent"]);
    assert_eq!(exit, 0);
    assert!(
        stdout.trim().is_empty(),
        "silent dry run prints nothing:\n{stdout}"
    );
}

// ---------------------------------------------------------------------------
// Agent --save-only: record-only intent is NOT preflighted
// ---------------------------------------------------------------------------

/// The preflight is scoped to the vendored posture; an agent-mode
/// `get --save-only` on the same refused workspace project records the
/// patch and persists its blob exactly as on any other project (the
/// fresh-clone record→vendor workflow must keep working).
#[tokio::test]
async fn get_save_only_agent_bypasses_bun_preflight() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Workspace);

    let argv = vec!["get", PURL, "--save-only", "--json"];
    let (exit, stdout, stderr) = run(tmp.path(), &with_api(&argv, &mock.uri()));
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["patches"][0]["action"], "added", "{v}");
    assert!(v["patches"][0].get("errorCode").is_none(), "{v}");
    assert_eq!(view_requests_for(&mock, UUID).await, 1);
    let manifest = manifest_value(tmp.path()).expect("manifest written");
    assert_eq!(manifest["patches"][PURL]["uuid"], UUID, "{manifest}");
    assert!(
        tmp.path()
            .join(".socket/blobs")
            .join(common::git_sha256(AFTER))
            .is_file(),
        "the agent download persists the after-blob"
    );
}

// ---------------------------------------------------------------------------
// Positive controls: supported Bun shapes still vendor (and revert)
// ---------------------------------------------------------------------------

/// A lockfileVersion-2 workspace lock (bun ≥ 1.4) is the supported
/// workspace shape: `scan --mode vendored` vendors left-pad — the registry
/// 4-tuple becomes the local-tarball 3-tuple, the workspace entry survives
/// byte-identically, the ledger records the bun flavor, the artifact is
/// committed — and the run exits 0.
#[tokio::test]
async fn scan_vendored_v2_workspace_lock_vendors() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V2Workspace);

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--json"]);
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["download"]["downloaded"], 1, "{v}");
    assert_eq!(v["download"]["detached"], true, "{v}");
    assert_eq!(v["download"]["patches"][0]["action"], "downloaded", "{v}");
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "{v}");
    assert_eq!(
        manifest_value(tmp.path()),
        None,
        "vendored mode never writes a manifest"
    );

    let lock = String::from_utf8(lock_bytes(tmp.path())).unwrap();
    let tgz_rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
    assert!(
        lock.contains(&format!(
            "    \"left-pad\": [\"left-pad@{tgz_rel}\", {{}}, \"sha512-"
        )),
        "the registry tuple must become the local-tarball 3-tuple:\n{lock}"
    );
    assert!(
        lock.contains("    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n"),
        "the workspace entry must survive untouched:\n{lock}"
    );
    assert!(lock.starts_with("{\n  \"lockfileVersion\": 2,\n"), "{lock}");
    assert!(tmp.path().join(&tgz_rel).is_file(), "missing {tgz_rel}");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["entries"][PURL]["uuid"], UUID, "{state}");
    assert_eq!(state["entries"][PURL]["flavor"], "bun", "{state}");
    assert_eq!(state["entries"][PURL]["detached"], true, "{state}");
    assert_eq!(state["entries"][PURL]["record"]["uuid"], UUID, "{state}");
}

/// A lockfileVersion-0 single-package lock (bun 1.1.39–1.1.45 opt-in text
/// lock) is supported: `get <uuid> --mode vendored --vendor-source build`
/// vendors it, and `rollback` restores the lock byte-for-byte and removes
/// the vendored tree.
#[tokio::test]
async fn get_uuid_vendored_v0_direct_lock_vendors_and_rollback_restores_bytes() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V0Direct);
    let lock_before = lock_bytes(tmp.path());

    let (exit, stdout, stderr) = get_vendored(tmp.path(), &mock.uri(), UUID, &["--json"]);
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    // Vendored mode is manifest-free for `get` too: the record is fetched
    // in memory (`downloaded`), never recorded in a manifest.
    assert_eq!(v["patches"][0]["action"], "downloaded", "{v}");
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "{v}");
    assert_eq!(manifest_value(tmp.path()), None, "{v}");
    let tgz_rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz");
    let lock = String::from_utf8(lock_bytes(tmp.path())).unwrap();
    assert!(lock.contains(&format!("\"left-pad@{tgz_rel}\"")), "{lock}");
    assert!(lock.starts_with("{\n  \"lockfileVersion\": 0,\n"), "{lock}");
    assert!(tmp.path().join(&tgz_rel).is_file());

    let (exit, stdout, stderr) = run(tmp.path(), &with_api(&["rollback", "--json"], &mock.uri()));
    assert_eq!(exit, 0, "rollback: stdout={stdout}\nstderr={stderr}");
    assert_eq!(
        lock_bytes(tmp.path()),
        lock_before,
        "rollback must restore the v0 lock byte-for-byte"
    );
    assert!(
        !tmp.path().join(".socket/vendor/npm").exists(),
        "rollback removes the vendored artifact tree"
    );
}

// ---------------------------------------------------------------------------
// Already-vendored exemption (upgrade path of pre-gate projects)
// ---------------------------------------------------------------------------

/// Vendor a supported v1 single-package project, then turn it into a
/// workspace the way a real repo evolves (add `packages/consumer`, the
/// `workspaces` field and — as `bun install` would — the 1-tuple workspace
/// entry, keeping the vendored tuple intact and the version at 1).
fn vendor_then_add_workspace(root: &Path, mock_uri: &str) -> Vec<u8> {
    write_bun_project(root, LockShape::V1Direct);
    let (exit, stdout, stderr) = scan_vendored(root, mock_uri, &["--json"]);
    assert_eq!(exit, 0, "setup vendoring: stdout={stdout}\nstderr={stderr}");
    let lock = String::from_utf8(lock_bytes(root)).unwrap();
    assert!(lock.contains(".socket/vendor/npm/"), "setup: {lock}");
    let with_workspace = lock.replace(
        "  \"packages\": {\n",
        "  \"packages\": {\n    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n\n",
    );
    assert_ne!(with_workspace, lock, "the workspace splice must land");
    std::fs::write(root.join("bun.lock"), &with_workspace).unwrap();
    let consumer = root.join("packages/consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("package.json"),
        r#"{"name":"consumer","version":"1.0.0","dependencies":{"other-pkg":"2.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"bun-fixture","version":"1.0.0","private":true,"workspaces":["packages/*"],"dependencies":{"left-pad":"1.3.0","consumer":"workspace:*"}}"#,
    )
    .unwrap();
    with_workspace.into_bytes()
}

#[tokio::test]
async fn preserved_ledger_does_not_bypass_bun_refusal_after_rollback() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_bun_project(root, LockShape::V1Direct);
    let (exit, stdout, stderr) = scan_vendored(root, &mock.uri(), &["--json", "--detached"]);
    assert_eq!(exit, 0, "{stdout}\n{stderr}");
    assert!(!root.join(".socket/manifest.json").exists());
    let (exit, stdout, stderr) = run(root, &["rollback", "--preserve-state", "--yes", "--json"]);
    assert_eq!(exit, 0, "{stdout}\n{stderr}");
    let registry = String::from_utf8(lock_bytes(root)).unwrap();
    assert!(!registry.contains(".socket/vendor/npm/"));
    let lock = registry.replace(
        "  \"packages\": {\n",
        "  \"packages\": {\n    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n\n",
    );
    std::fs::write(root.join("bun.lock"), &lock).unwrap();
    let state = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
    let artifact_path = root.join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    let artifact = std::fs::read(&artifact_path).unwrap();

    let (exit, stdout, stderr) = scan_vendored(root, &mock.uri(), &["--json", "--dry-run"]);
    assert_eq!(exit, 0, "{stdout}\n{stderr}");
    let preview = parse_single_json_doc(&stdout);
    assert_eq!(
        preview["vendor"]["patches"][0]["action"], "would_refuse",
        "{preview}"
    );
    assert_eq!(
        preview["vendor"]["patches"][0]["errorCode"], WS_CODE,
        "{preview}"
    );

    let views_before = view_requests_for(&mock, UUID).await;
    let (exit, stdout, stderr) = get_vendored(root, &mock.uri(), UUID, &["--json"]);
    assert_eq!(exit, 1, "{stdout}\n{stderr}");
    let env = parse_single_json_doc(&stdout);
    assert_eq!(env["status"], "error", "{env}");
    assert_eq!(env["downloaded"], 0, "{env}");
    assert_eq!(env["error"]["code"], WS_CODE, "{env}");
    assert_eq!(
        view_requests_for(&mock, UUID).await,
        views_before + 1,
        "only the UUID lookup may fetch"
    );
    assert!(!root.join(".socket/manifest.json").exists());
    assert_eq!(String::from_utf8(lock_bytes(root)).unwrap(), lock);
    assert_eq!(
        std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
        state
    );
    assert_eq!(std::fs::read(artifact_path).unwrap(), artifact);
}

/// The download phase must NOT refuse a purl the ledger already wires at
/// the selected uuid: the re-run classifies it `skipped` (the ledger's
/// embedded record is reused) exactly as on a non-Bun project, instead of
/// `failed`. Pinned
/// independently of the vendor step below so the CLI half of the
/// exemption is guarded even while the engine half lands separately.
#[tokio::test]
async fn already_vendored_v1_workspace_rerun_download_phase_is_skipped_not_refused() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    let lock_before = vendor_then_add_workspace(tmp.path(), &mock.uri());

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--json"]);
    let v = parse_single_json_doc(&stdout);
    let rec = &v["download"]["patches"][0];
    assert_eq!(
        rec["action"], "skipped",
        "an in-sync vendored purl must not be refused by the preflight (exit {exit}): {v}\n{stderr}"
    );
    assert!(rec.get("errorCode").is_none(), "{v}");
    assert_eq!(v["download"]["failed"], 0, "{v}");
    assert_eq!(
        lock_bytes(tmp.path()),
        lock_before,
        "an in-sync re-run leaves the lock alone"
    );
}

/// The full in-sync re-run on the upgraded workspace project: exit 0, the
/// download phase `skipped` (the CLI exempts already-vendored purls from the
/// Bun preflight), the vendor step a `skipped`/`already_vendored` event —
/// `vendor_bun` classifies the in-sync tuple BEFORE applying the workspace
/// gate, so a pre-1.4 workspace project vendored earlier keeps working.
#[tokio::test]
async fn already_vendored_v1_workspace_rerun_is_already_vendored_exit_zero() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    let lock_before = vendor_then_add_workspace(tmp.path(), &mock.uri());

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--json"]);
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["download"]["patches"][0]["action"], "skipped", "{v}");
    let events = v["vendor"]["events"].as_array().unwrap();
    assert!(
        events.iter().any(|e| e["purl"] == PURL
            && e["action"] == "skipped"
            && e["errorCode"] == "already_vendored"),
        "{v}"
    );
    assert_eq!(lock_bytes(tmp.path()), lock_before);
}

/// A SUPERSEDING patch uuid on the upgraded workspace project: the ledger
/// holds the OLD uuid, so a ledger-only exemption refused the update at
/// download (`vendor_bun_workspace_unsupported`, exit 1) with a re-lock
/// remedy a Bun 1.2/1.3 team cannot follow — while the engine would have
/// re-vendored the already-local tuple in place. The lock-derived
/// exemption sees every instance is ours and lets the run through: the
/// record is fetched (`downloaded` — vendored mode is manifest-free, so
/// the download vocabulary is the detached one for `get` too), the engine
/// re-pins the tuple at the new uuid, the lock stays at lockfileVersion 1
/// with its workspace entry intact.
#[tokio::test]
async fn superseding_uuid_on_already_vendored_v1_workspace_is_revendored_not_refused() {
    const SUPERSEDING_UUID: &str = "33333333-3333-4333-8333-333333333333";
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    vendor_then_add_workspace(tmp.path(), &mock.uri());
    mount_view(&mock, SUPERSEDING_UUID, PURL).await;

    let (exit, stdout, stderr) =
        get_vendored(tmp.path(), &mock.uri(), SUPERSEDING_UUID, &["--json"]);
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["patches"][0]["action"], "downloaded", "{v}");
    assert!(v["patches"][0].get("errorCode").is_none(), "{v}");
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "vendored mode never writes a manifest"
    );
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "{v}");
    assert_eq!(v["vendor"]["summary"]["failed"], 0, "{v}");
    assert!(
        !stdout.contains(WS_CODE),
        "no arm may raise the workspace refusal for an already-vendored purl: {v}"
    );
    let lock = String::from_utf8(lock_bytes(tmp.path())).unwrap();
    assert!(
        lock.contains(&format!(
            "\"left-pad@.socket/vendor/npm/{SUPERSEDING_UUID}/left-pad-1.3.0.tgz\""
        )),
        "the tuple must point at the superseding uuid:\n{lock}"
    );
    assert!(
        !lock.contains(UUID),
        "the old uuid path must be gone:\n{lock}"
    );
    assert!(
        lock.contains("    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n"),
        "the workspace entry survives:\n{lock}"
    );
    assert!(lock.starts_with("{\n  \"lockfileVersion\": 1,\n"), "{lock}");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["entries"][PURL]["uuid"], SUPERSEDING_UUID, "{state}");
    assert!(tmp
        .path()
        .join(format!(
            ".socket/vendor/npm/{SUPERSEDING_UUID}/left-pad-1.3.0.tgz"
        ))
        .is_file());
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists(),
        "the stale uuid dir is swept"
    );
}

/// The same upgraded project with its vendor ledger LOST (`state.json`
/// deleted — the shape `repair` reconstructs from): the ledger exemption
/// has nothing to match, but the lock still says every instance is ours,
/// so the download phase must NOT refuse the in-sync re-run — with no
/// embedded record left to reuse it fetches the record (`downloaded`) and
/// hands the ledgerless wiring to the engine, whose verdict (not the
/// preflight's) decides the run. Nothing here may raise the workspace code.
#[tokio::test]
async fn wiped_ledger_on_already_vendored_v1_workspace_is_not_refused_at_preflight() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    let lock_before = vendor_then_add_workspace(tmp.path(), &mock.uri());
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--json"]);
    let v = parse_single_json_doc(&stdout);
    let rec = &v["download"]["patches"][0];
    assert_eq!(
        rec["action"], "downloaded",
        "an in-sync purl must not be refused for a lost ledger (exit {exit}): {v}\n{stderr}"
    );
    assert!(rec.get("errorCode").is_none(), "{v}");
    assert_eq!(v["download"]["failed"], 0, "{v}");
    assert!(
        !stdout.contains(WS_CODE),
        "no arm may raise the workspace refusal: {v}"
    );
    assert_eq!(
        lock_bytes(tmp.path()),
        lock_before,
        "the wired lock is left alone"
    );
}

// ---------------------------------------------------------------------------
// Corrupt vendor ledger beside a refused Bun lock: name the ledger
// ---------------------------------------------------------------------------

/// `get <uuid> --mode vendored` returns before the vendor step, so the
/// preflight's refusal is the ONLY diagnosis the run emits; the dry-run
/// preview and the detached download phase share the same ledger-blind
/// spot. All three must report `vendor_state_unreadable` (the code every
/// other vendor-adjacent command uses for this file) with the io/parse
/// detail, not the Bun re-lock remedy — fail-closed still: nothing exempt,
/// nothing written, the corrupt ledger left in place for the operator.
#[tokio::test]
async fn corrupt_vendor_ledger_on_refused_bun_lock_reports_vendor_state_unreadable() {
    const LEDGER_CODE: &str = "vendor_state_unreadable";
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Workspace);
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("state.json"), b"{ not json").unwrap();
    let lock_before = lock_bytes(tmp.path());

    // uuid path, JSON: the pre-record refusal envelope carries the ledger code.
    let (exit, stdout, stderr) = get_vendored(tmp.path(), &mock.uri(), UUID, &["--json"]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["error"]["code"], LEDGER_CODE, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("state.json")),
        "the detail names the ledger file: {v}"
    );
    assert_eq!(v["patches"][0]["errorCode"], LEDGER_CODE, "{v}");
    assert!(
        !stdout.contains(WS_CODE),
        "the Bun lock remedy must not shadow the ledger corruption: {v}"
    );
    assert!(!tmp.path().join(".socket/manifest.json").exists());

    // uuid path, human: the code-tagged Error line.
    let (exit, stdout, stderr) = get_vendored(tmp.path(), &mock.uri(), UUID, &[]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("Error ({LEDGER_CODE}):")),
        "stderr must carry the ledger code:\n{stderr}"
    );

    // Dry-run preview: `would_refuse` with the ledger code.
    let (exit, stdout, stderr) =
        get_vendored(tmp.path(), &mock.uri(), UUID, &["--dry-run", "--json"]);
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    let rec = &v["vendor"]["patches"][0];
    assert_eq!(rec["action"], "would_refuse", "{v}");
    assert_eq!(rec["errorCode"], LEDGER_CODE, "{v}");

    // Detached download phase: the same code before any fetch.
    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--detached", "--json"]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    let rec = &v["download"]["patches"][0];
    assert_eq!(rec["action"], "failed", "{v}");
    assert_eq!(rec["errorCode"], LEDGER_CODE, "{v}");
    assert_eq!(v["download"]["downloaded"], 0, "{v}");

    assert_eq!(
        lock_bytes(tmp.path()),
        lock_before,
        "refused runs never touch the lock"
    );
    assert_eq!(
        std::fs::read(vendor_dir.join("state.json")).unwrap(),
        b"{ not json",
        "the corrupt ledger is left for the operator, never overwritten"
    );
    assert!(!vendor_dir.join("npm").exists());
}

// ---------------------------------------------------------------------------
// Digest-less re-saves (Bun 1.1.39–1.3.9)
// ---------------------------------------------------------------------------
// Every text-lock release below 1.3.10 re-saves our local-tarball 3-tuple
// WITHOUT its sha512 on any later lock re-save (`bun add`, `bun install`
// after a manifest change) — measured on real 1.1.45, 1.2.23 and 1.3.9. The
// 2-tuple `["left-pad@.socket/vendor/npm/<uuid>/left-pad-1.3.0.tgz", {}]`
// is still our wiring: the re-run must stay `already_vendored` (and heal
// the digest), `repair` must rebuild through it, and `rollback` must
// restore the registry line — not `vendor_lock_entry_not_found` /
// `vendor_lock_entry_drifted` + `vendor_artifact_kept`.

/// The packages-entry line keyed `key` (verbatim, no line terminator).
fn bun_packages_line(lock: &str, key: &str) -> String {
    let prefix = format!("    \"{key}\": [");
    lock.split('\n')
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no `{key}` packages entry in:\n{lock}"))
        .trim_end_matches('\r')
        .to_string()
}

/// The line as Bun < 1.3.10 re-saves it: trailing `"sha512-…"` dropped.
fn drop_bun_digest(line: &str) -> String {
    let cut = line
        .rfind(", \"sha512-")
        .unwrap_or_else(|| panic!("no sha512 element in {line}"));
    let tail = if line.ends_with("],") { "]," } else { "]" };
    format!("{}{tail}", &line[..cut])
}

/// Vendor the V1 direct project, then re-spell its wired line digest-less.
/// Returns (pristine lock, wired lock, wired line).
fn vendor_then_drop_digest(root: &Path, mock_uri: &str) -> (Vec<u8>, String, String) {
    write_bun_project(root, LockShape::V1Direct);
    let pristine = lock_bytes(root);
    let (exit, stdout, stderr) = scan_vendored(root, mock_uri, &["--json"]);
    assert_eq!(exit, 0, "setup vendoring: stdout={stdout}\nstderr={stderr}");
    let wired = String::from_utf8(lock_bytes(root)).unwrap();
    let wired_line = bun_packages_line(&wired, "left-pad");
    assert!(
        wired_line.contains(&format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
            && wired_line.contains("\"sha512-"),
        "setup: {wired_line}"
    );
    let digestless = drop_bun_digest(&wired_line);
    std::fs::write(
        root.join("bun.lock"),
        wired.replace(&wired_line, &digestless),
    )
    .unwrap();
    (pristine, wired, wired_line)
}

#[tokio::test]
async fn digestless_vendored_tuple_rerun_is_already_vendored_and_heals_the_digest() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    let (_, wired, _) = vendor_then_drop_digest(tmp.path(), &mock.uri());

    let (exit, stdout, stderr) = scan_vendored(tmp.path(), &mock.uri(), &["--json"]);
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(
        v["download"]["patches"][0]["action"], "skipped",
        "the ledger still wires the purl: {v}"
    );
    assert_eq!(v["download"]["failed"], 0, "{v}");
    let vendor = &v["vendor"];
    assert_eq!(vendor["summary"]["applied"], 0, "{v}");
    assert_eq!(vendor["summary"]["skipped"], 1, "{v}");
    assert_eq!(vendor["summary"]["failed"], 0, "{v}");
    let events = vendor["events"].as_array().unwrap();
    assert!(
        events.iter().any(|e| e["purl"] == PURL
            && e["action"] == "skipped"
            && e["errorCode"] == "already_vendored"),
        "{v}"
    );
    assert!(
        events
            .iter()
            .all(|e| e["errorCode"] != "vendor_lock_entry_not_found" && e["action"] != "failed"),
        "{v}"
    );
    assert_eq!(
        String::from_utf8(lock_bytes(tmp.path())).unwrap(),
        wired,
        "the in-sync re-run heals the digest back to the 3-tuple, byte-identical"
    );
}

#[tokio::test]
async fn digestless_vendored_tuple_rollback_restores_the_registry_line() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    let (pristine, _, _) = vendor_then_drop_digest(tmp.path(), &mock.uri());

    let (exit, stdout, stderr) = run(tmp.path(), &with_api(&["rollback", "--json"], &mock.uri()));
    assert_eq!(exit, 0, "rollback: stdout={stdout}\nstderr={stderr}");
    assert!(
        !stdout.contains("vendor_lock_entry_drifted") && !stdout.contains("vendor_artifact_kept"),
        "the digest-less spelling of our own tuple is not drift: {stdout}"
    );
    assert_eq!(
        lock_bytes(tmp.path()),
        pristine,
        "rollback must restore the registry lock byte-for-byte"
    );
    assert!(
        !tmp.path().join(".socket/vendor/npm").exists(),
        "rollback removes the vendored artifact tree"
    );
}

#[tokio::test]
async fn repair_rebuilds_a_deleted_artifact_through_a_digestless_lock() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    let (_, wired, _) = vendor_then_drop_digest(tmp.path(), &mock.uri());
    let tgz = tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    std::fs::remove_file(&tgz).unwrap();

    // `scan --mode vendored` keeps no local blob in this harness, so the
    // rebuild fetches the patch content from the mock API (no `--offline`).
    let (exit, stdout, stderr) = run(tmp.path(), &with_api(&["repair", "--json"], &mock.uri()));
    assert_eq!(exit, 0, "repair: stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["summary"]["rebuilt"], 1, "{v}");
    assert!(
        v["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "{v}"
    );
    assert!(tgz.is_file(), "the artifact must be rebuilt");
    assert_eq!(
        String::from_utf8(lock_bytes(tmp.path())).unwrap(),
        wired,
        "the rebuild re-pins the digest into the healed 3-tuple"
    );
}

// ---------------------------------------------------------------------------
// Workspace-member --cwd: today's behaviour, pinned
// ---------------------------------------------------------------------------

/// `scan --mode vendored --cwd <workspace member>`: the member directory
/// holds no bun.lock, so the Bun preflight passes (it cannot see a Bun
/// project), the download phase fetches the record in memory, and the
/// vendor engine then refuses `vendor_lockfile_missing` (the flavor router
/// finds no lockfile at cwd) — so nothing is written under the member
/// either. Pre-existing, flavor-agnostic behaviour (`--cwd` is the
/// lockfile root by contract) — pinned here so any change to it is
/// deliberate. The root tree is never touched.
#[tokio::test]
async fn scan_vendored_from_workspace_member_cwd_fetches_then_engine_refuses_lockfile_missing() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V2Workspace);
    // The member must have an installed copy for the crawler to find.
    let member = tmp.path().join("packages/consumer");
    write_installed_left_pad(&member);
    let lock_before = lock_bytes(tmp.path());

    let member_str = member.to_str().unwrap().to_string();
    let (exit, stdout, stderr) =
        scan_vendored(tmp.path(), &mock.uri(), &["--json", "--cwd", &member_str]);
    assert_eq!(exit, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "partial_failure", "{v}");
    assert_eq!(v["download"]["downloaded"], 1, "{v}");
    assert_eq!(v["download"]["patches"][0]["action"], "downloaded", "{v}");
    let events = v["vendor"]["events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == PURL && e["errorCode"] == MISSING_CODE),
        "the engine refuses from the member dir: {v}"
    );
    assert_eq!(
        manifest_value(&member),
        None,
        "vendored mode never writes a manifest"
    );
    assert!(
        !member.join(".socket").exists(),
        "a refused vendoring leaves nothing under the member's .socket/"
    );
    assert_eq!(lock_bytes(tmp.path()), lock_before, "root lock untouched");
    assert!(!tmp.path().join(".socket").exists(), "no root .socket/");
}

// ---------------------------------------------------------------------------
// FIFO bun.lock (Unix): refused fast, never wedged
// ---------------------------------------------------------------------------

/// Spawn the binary with the same env scrub as `common::run_with_env`, but
/// kill it if it outlives `deadline` — a wedged child must fail the test,
/// not hang the suite.
#[cfg(unix)]
fn run_with_deadline(root: &Path, argv: &[&str], deadline: Duration) -> (i32, String, String) {
    let out_path = root.join("child.stdout");
    let err_path = root.join("child.stderr");
    let mut cmd = Command::new(common::binary());
    cmd.args(argv).current_dir(root);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_")
            && !name.contains("TELEMETRY")
            && name != "SOCKET_NO_CONFIG"
            && name != "SOCKET_NO_UPDATE_CHECK"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_NO_UPDATE_CHECK", "1")
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&out_path).unwrap())
        .stderr(std::fs::File::create(&err_path).unwrap());
    let mut child = cmd.spawn().expect("spawn socket-patch");
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if started.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "socket-patch {argv:?} did not finish within {deadline:?} — wedged on the FIFO?\nstderr:\n{}",
                std::fs::read_to_string(&err_path).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    (
        status.code().unwrap_or(-1),
        std::fs::read_to_string(&out_path).unwrap_or_default(),
        std::fs::read_to_string(&err_path).unwrap_or_default(),
    )
}

#[cfg(unix)]
fn mkfifo(path: &Path) {
    assert!(
        Command::new("mkfifo").arg(path).status().unwrap().success(),
        "mkfifo {}",
        path.display()
    );
}

/// A FIFO squatting `bun.lock` (a planted special file): the preflight's
/// guarded open refuses `vendor_lockfile_missing` immediately on both the
/// scan and the uuid path — no `open(2)` waiting forever for a writer.
#[cfg(unix)]
#[tokio::test]
async fn fifo_bun_lock_is_refused_without_blocking() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let uri = mock.uri();

    // scan: discovery's lock inventory and the preflight both open the FIFO
    // through the guarded path.
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Direct);
    std::fs::remove_file(tmp.path().join("bun.lock")).unwrap();
    mkfifo(&tmp.path().join("bun.lock"));
    let argv = with_api(
        &[
            "scan",
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--json",
        ],
        &uri,
    );
    let (exit, stdout, stderr) = run_with_deadline(tmp.path(), &argv, Duration::from_secs(20));
    assert_eq!(exit, 1, "scan: stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_refused_record(&v["download"]["patches"][0], MISSING_CODE, &v);
    assert_eq!(view_requests_for(&mock, UUID).await, 0);

    // get <uuid>: the FIFO is the only Bun artefact the preflight reads.
    let tmp = tempfile::tempdir().unwrap();
    write_bun_project(tmp.path(), LockShape::V1Direct);
    std::fs::remove_file(tmp.path().join("bun.lock")).unwrap();
    mkfifo(&tmp.path().join("bun.lock"));
    let argv = with_api(
        &[
            "get",
            UUID,
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--json",
        ],
        &uri,
    );
    let (exit, stdout, stderr) = run_with_deadline(tmp.path(), &argv, Duration::from_secs(20));
    assert_eq!(exit, 1, "get: stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "error", "{v}");
    assert_eq!(v["error"]["code"], MISSING_CODE, "{v}");
    assert!(!tmp.path().join(".socket").exists());
}
