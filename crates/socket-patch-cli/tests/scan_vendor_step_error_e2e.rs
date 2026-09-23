//! Regression: the vendor step's ERROR returns must still hand the JSON
//! consumer the step's `vendor` envelope — demoted — instead of dropping it.
//!
//! `scan --vendor`'s vendor step (`run_scan_vendor_step`) takes the apply
//! lock, stages the fetched records' patch content in memory, then drives
//! the vendor engine. Vendored mode is manifest-free: the step never reads
//! the manifest and never reconciles ledger entries against it, so a
//! staging failure (`no_local_source`: the API serves the patch view
//! without blob content) aborts a run that has mutated nothing. The run
//! DID enter the step, though, and the contract's `vendor` sub-object
//! rides the error fold: `status` demoted to `partialFailure` (a consumer
//! reading `.vendor.status` inside a `"status":"error"` result must not
//! see the fresh-envelope default of `success`) and `events[]` present —
//! empty, and in particular holding no revert of a ledger entry the run
//! did not select. The `vendor` command prints its envelope on the same
//! failure (`vendor::run` emits `env` whatever `run_vendor` returned);
//! scan's JSON arm must not be the one place it vanishes. `get --mode
//! vendored` shares the fold
//! (`covgap_commands_get::get_uuid_vendored_vendor_step_error_leaves_legacy_state_alone`).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
/// The patch discovery selects; its view carries hashes but no content.
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
/// A legacy (non-detached) ledger entry the run never selects: the
/// manifest-free step must leave it alone, event-less and byte-identical.
const UNSELECTED_PURL: &str = "pkg:npm/gone@9.9.9";
const UNSELECTED_UUID: &str = "33333333-3333-4333-8333-333333333333";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// A vendorable npm project: root package.json, a v3 package-lock with a
/// registry-resolved left-pad entry, and the installed package.
fn write_fixture(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-vendor-step-error", "version": "0.0.0" }"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "scan-vendor-step-error",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "scan-vendor-step-error",
                "version": "0.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), lock_bytes).unwrap();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// Discovery (batch) plus the per-package search that selects `UUID` for
/// `PURL` — the endpoints `scan --vendor` hits before the download phase.
async fn mount_discovery(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
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
                    "title": "vendor target"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Vendor patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

/// The patch view WITHOUT `blobContent`: the download phase records the
/// patch (it needs only the hashes), but the vendor step cannot obtain the
/// patched bytes and staging fails `no_local_source` — however many times
/// the view is fetched along the way.
async fn mount_contentless_view(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": git_sha256(BEFORE),
                    "afterHash": git_sha256(AFTER),
                }
            },
            "vulnerabilities": {},
            "description": "Vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// Seed the vendor ledger with one legacy entry for a purl the run never
/// selects. Returns the exact bytes for the byte-identical check after
/// the run.
fn seed_unselected_ledger_entry(root: &Path) -> String {
    let vendor = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(
        vendor.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { UNSELECTED_PURL: {
                "ecosystem": "npm",
                "basePurl": UNSELECTED_PURL,
                "uuid": UNSELECTED_UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{UNSELECTED_UUID}/gone-9.9.9.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::read_to_string(vendor.join("state.json")).unwrap()
}

fn run_cli(root: &Path, argv: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(argv).current_dir(root);
    // Scrub the ambient `SOCKET_*` surface (prefix scrub — fixed lists rot)
    // so a developer's shell can't steer the child, then force the telemetry
    // kill-switch: telemetry resolves its endpoint from env only, so an
    // ambient value would ship this run's events to the LIVE API.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn scan_vendor_staging_error_still_carries_the_demoted_vendor_envelope() {
    let mock = MockServer::start().await;
    mount_discovery(&mock).await;
    mount_contentless_view(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let ledger_before = seed_unselected_ledger_entry(tmp.path());

    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &[
            "scan",
            "--json",
            "--vendor",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
    );

    assert_eq!(
        code, 1,
        "an unstageable record must fail the run; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object ({e}); stdout={stdout}"));
    assert_eq!(v["status"], "error", "envelope={v}");
    assert_eq!(
        v["error"]["code"], "no_local_source",
        "precondition: the run must abort at staging; envelope={v}"
    );

    // Non-vacuous: the run got PAST the download phase (the record was
    // fetched — hashes only — into memory, detached) and INTO the step.
    assert_eq!(v["download"]["downloaded"], 1, "envelope={v}");
    assert_eq!(v["download"]["detached"], true, "envelope={v}");

    // The carried envelope must not claim the vendor step succeeded: the
    // run aborted at staging, so a consumer reading `.vendor.status` inside
    // a `"status":"error"` result must see the demoted status, not the
    // fresh-envelope default of "success".
    assert_eq!(
        v["vendor"]["status"], "partialFailure",
        "the carried envelope's own status must be demoted; envelope={v}"
    );

    // The point: the envelope survives the error fold — `events[]` is where
    // any pre-failure work would be reported — and the manifest-free step
    // reconciles nothing: no event names the unselected legacy entry, whose
    // ledger bytes are untouched.
    let events = v["vendor"]["events"].as_array().unwrap_or_else(|| {
        panic!("the vendor envelope must survive the staging error; envelope={v}")
    });
    assert!(
        events.is_empty(),
        "nothing mutates before staging — in particular the unselected {UNSELECTED_PURL} \
         is never reconciled; envelope={v}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
        ledger_before,
        "the detached vendor step never reconciles unselected ledger entries"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "vendored mode never writes a manifest"
    );
    assert!(
        !tmp.path().join(".socket/apply.lock").exists(),
        "the lock file is removed when the aborted step releases the lock"
    );
}
