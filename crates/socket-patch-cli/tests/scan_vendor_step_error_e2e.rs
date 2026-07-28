//! Regression: the vendor step's ERROR returns must still report the work
//! the step already committed to disk.
//!
//! `scan --vendor`'s vendor step (`run_scan_vendor_step`) runs the manifest
//! reconcile — reverting vendored entries whose patch left the manifest,
//! which rewrites lockfiles, deletes `.socket/vendor/<uuid>/` artifacts and
//! rewrites the ledger — BEFORE it stages patch sources. A staging failure
//! (`no_local_source`: a patch view the API would not serve) therefore
//! aborts a run that has already mutated the project, and the `vendor`
//! Envelope holding those `Removed`/`Failed` events is the only record of
//! it. The `vendor` command prints that envelope on the same failure
//! (`vendor::run` emits `env` whatever `run_vendor` returned); scan's JSON
//! arm must not be the one place the events vanish.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
/// The manifest patch whose content the mock API refuses to serve.
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
/// A ledger entry with NO manifest patch — the reconcile reverts it.
const DROPPED_PURL: &str = "pkg:npm/gone@9.9.9";
const DROPPED_UUID: &str = "33333333-3333-4333-8333-333333333333";
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

/// A committed manifest whose afterHash blob is NOT on disk: the vendor
/// step must fetch the patch view to stage it, and the mock refuses.
fn seed_unstageable_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
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
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// A ledger holding one entry the manifest does not mention: the vendor
/// step's `reconcile_dropped` reverts it (and rewrites `state.json`)
/// before staging is even attempted.
fn seed_dropped_ledger_entry(root: &Path) {
    let vendor = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(
        vendor.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { DROPPED_PURL: {
                "ecosystem": "npm",
                "basePurl": DROPPED_PURL,
                "uuid": DROPPED_UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{DROPPED_UUID}/gone-9.9.9.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();
}

/// Discovery reports no available patches (so nothing downloads and the
/// run goes straight to the vendor step), and the patch-view endpoint is
/// deliberately unmounted so staging the committed manifest fails.
async fn mount_empty_discovery(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
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
async fn scan_vendor_staging_error_still_reports_the_reconcile() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    seed_unstageable_manifest(tmp.path());
    seed_dropped_ledger_entry(tmp.path());

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
        "an unstageable manifest must fail the run; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object ({e}); stdout={stdout}"));
    assert_eq!(
        v["error"]["code"], "no_local_source",
        "precondition: the run must abort at staging; envelope={v}"
    );

    // Non-vacuous: the reconcile really did run and really did persist —
    // the ledger's only entry is gone, so `save_state` deleted state.json.
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "precondition: the reconcile must have reverted the dropped entry \
         and rewritten the ledger; envelope={v}"
    );

    // The point: that on-disk mutation must be visible to the JSON consumer.
    let events = v["vendor"]["events"].as_array().unwrap_or_else(|| {
        panic!(
            "the vendor envelope must survive the staging error — the \
             reconcile already reverted {DROPPED_PURL} on disk; envelope={v}"
        )
    });
    assert!(
        events.iter().any(|e| e["purl"] == DROPPED_PURL),
        "the reconcile's event for {DROPPED_PURL} must be reported; envelope={v}"
    );
}
