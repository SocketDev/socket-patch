//! Coverage-gap tests for `commands/scan/vendor_flow.rs` (2026-09 audit).
//!
//! Pins the audited-but-untested surfaces of `scan --vendor`:
//!
//! * the `already_vendored` dry-run preview arm (the sibling
//!   `would_vendor` / `would_revendor` arms are pinned by
//!   `scan_vendor_e2e.rs`);
//! * the legal-but-never-executed `--dry-run --prune` combination in the
//!   vendor JSON path (GC preview field names, nothing mutated);
//! * every None-envelope error constructor of `run_scan_vendor_step` —
//!   `lock_held`, `lock_io`, `invalid_manifest`, `socket_dir_unwritable` —
//!   through the JSON error fold (which must NOT emit a `vendor` key when
//!   no reconcile envelope rides the error);
//! * the interactive (non-JSON) vendor-step error arm — the only error
//!   output a terminal user sees when `scan --vendor` aborts at
//!   lock/stage/manifest (the JSON twin is `scan_vendor_step_error_e2e.rs`).
//!
//! Fixtures are clones of `scan_vendor_e2e.rs` /
//! `scan_vendor_step_error_e2e.rs` (each e2e file carries its own copy —
//! the established pattern), plus `e2e_safety_lock.rs`'s external-flock
//! trick for lock contention. Mock API only; no real hosts.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process::Command;

use fs2::FileExt;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
/// A manifest patch for a package that is NOT installed — prunable.
const STALE_PURL: &str = "pkg:npm/uninstalled@1.0.0";
/// A ledger entry with NO manifest patch — the reconcile reverts it.
const DROPPED_PURL: &str = "pkg:npm/gone@9.9.9";
const DROPPED_UUID: &str = "33333333-3333-4333-8333-333333333333";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
/// base64 of AFTER, inlined as the view response's blobContent.
const AFTER_B64: &str = "YWZ0ZXIK";

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
        r#"{ "name": "covgap-scan-vendor-flow", "version": "0.0.0" }"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "covgap-scan-vendor-flow",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "covgap-scan-vendor-flow",
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

/// Mount discovery (batch), per-package search, and the full view for
/// `uuid` on the mock server.
async fn mount_patch_api(mock: &MockServer, uuid: &str) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": uuid,
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
                "uuid": uuid,
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
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": AFTER_B64,
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

/// A batch endpoint that reports NO available patches. The by-package /
/// view endpoints are deliberately unmounted: nothing may reach them.
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

/// Spawn the built binary in `root`, hermetically (the
/// `scan_vendor_e2e.rs` pattern): scrub the ambient `SOCKET_*` surface so
/// a developer's shell can't steer the child, then force the telemetry
/// kill-switch so no run ever phones the live API.
fn run_cli(root: &Path, argv: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(argv).current_dir(root);
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

fn run_scan_vendor(root: &Path, mock_uri: &str, extra: &[&str]) -> (i32, String, String) {
    let mut argv = vec![
        "scan",
        "--json",
        "--vendor",
        "--yes",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ];
    argv.extend_from_slice(extra);
    run_cli(root, &argv)
}

/// Take the apply lock EXTERNALLY, exactly as `e2e_safety_lock.rs` does:
/// fs2 (the same crate the binary uses) on the same `.socket/apply.lock`
/// path, so the spawned binary observes real OS-level contention.
fn take_external_lock(socket_dir: &Path) -> std::fs::File {
    std::fs::create_dir_all(socket_dir).unwrap();
    let path = socket_dir.join("apply.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("open lock file");
    file.try_lock_exclusive()
        .expect("test could not take initial lock");
    file
}

/// Seed the vendor ledger with the PURL entry at `uuid` — the state the
/// dry-run preview classifies against.
fn seed_vendor_state(root: &Path, uuid: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("vendor")).unwrap();
    std::fs::write(
        socket.join("vendor/state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { PURL: {
                "ecosystem": "npm",
                "basePurl": PURL,
                "uuid": uuid,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();
}

/// A committed manifest whose only patch targets a package that is NOT
/// installed (and not vendored) — the GC's prunable case.
fn seed_stale_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            STALE_PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {},
                "vulnerabilities": {},
                "description": "stranded entry",
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

/// A committed manifest whose afterHash blob is NOT on disk: the vendor
/// step must fetch the patch view to stage it, and the mock refuses
/// (`mount_empty_discovery` mounts no view route).
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

/// Shared assertions for the None-envelope error fold: exit 1, a JSON
/// envelope with `status: "error"`, the given `error.code`, a `download`
/// sub-object (proof the run got PAST the download phase and died inside
/// the vendor step) and NO `vendor` key (no reconcile envelope rode the
/// error — `run_vendor_json_path`'s `if let Some(venv)` fall-through).
fn assert_vendor_step_error(
    code: i32,
    stdout: &str,
    stderr: &str,
    expect_code: &str,
) -> serde_json::Value {
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON object ({e}); stdout={stdout}"));
    assert_eq!(v["status"], "error", "envelope={v}");
    assert_eq!(v["error"]["code"], expect_code, "envelope={v}");
    assert!(
        v["download"].is_object(),
        "the run must reach the vendor step (download phase completed); envelope={v}"
    );
    assert!(
        !v.as_object().unwrap().contains_key("vendor"),
        "a None-envelope error must not fabricate a vendor sub-object; envelope={v}"
    );
    v
}

/// Dry-run preview, same-uuid case: an entry already vendored at the
/// discovered uuid is classified `already_vendored` — with no `oldUuid`
/// key (that key marks `would_revendor` only) — and nothing on disk or
/// beyond discovery is touched. Companion to
/// `scan_vendor_dry_run_previews_without_touching_disk`
/// (`scan_vendor_e2e.rs`), which pins the mismatched-uuid arm.
#[tokio::test]
async fn scan_vendor_dry_run_reports_already_vendored() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    seed_vendor_state(tmp.path(), UUID);
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["vendor"]["dryRun"], true, "envelope={v}");
    let patches = v["vendor"]["patches"].as_array().expect("vendor preview");
    assert_eq!(patches.len(), 1, "envelope={v}");
    assert_eq!(patches[0]["purl"], PURL, "envelope={v}");
    assert_eq!(patches[0]["action"], "already_vendored", "envelope={v}");
    assert_eq!(patches[0]["uuid"], UUID, "envelope={v}");
    assert!(
        !patches[0].as_object().unwrap().contains_key("oldUuid"),
        "oldUuid marks would_revendor only; envelope={v}"
    );

    // Non-mutation: no manifest written, lock untouched, no view fetch.
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "dry run must not write a manifest"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "dry run must not edit the lock"
    );
    let reqs = mock.received_requests().await.unwrap();
    assert!(
        !reqs.iter().any(|r| r.url.path().contains("/patches/view/")),
        "dry run must not download patch views"
    );
}

/// `scan --json --vendor --dry-run --prune` (a legal combination —
/// `--vendor` conflicts only with `--apply`/`--sync`): the vendor JSON
/// path's dry-run arm must emit the GC PREVIEW (`prunable*`/`orphan*`
/// field names, per `to_preview_json`) and mutate nothing on disk.
#[tokio::test]
async fn scan_vendor_dry_run_prune_previews_gc_without_mutating() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    seed_stale_manifest(tmp.path());
    let manifest_before = std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap();

    let (code, stdout, stderr) =
        run_scan_vendor(tmp.path(), &mock.uri(), &["--dry-run", "--prune"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");

    // The vendor dry-run preview ran (empty discovery ⇒ empty preview).
    assert_eq!(v["vendor"]["dryRun"], true, "envelope={v}");
    assert_eq!(v["vendor"]["patches"], serde_json::json!([]), "envelope={v}");

    // The GC preview: the stale entry is PRUNABLE (preview vocabulary),
    // not "pruned" (the mutating pass's vocabulary).
    let gc = v["gc"]
        .as_object()
        .unwrap_or_else(|| panic!("--prune must emit a gc sub-object; envelope={v}"));
    assert_eq!(
        gc["prunableManifestEntries"],
        serde_json::json!([STALE_PURL]),
        "envelope={v}"
    );
    assert!(
        gc.contains_key("bytesReclaimable") && gc.contains_key("orphanBlobs"),
        "dry+prune must use the preview field names; gc={gc:?}"
    );
    assert!(
        !gc.contains_key("prunedManifestEntries") && !gc.contains_key("bytesFreed"),
        "dry+prune must not use the mutating pass's field names; gc={gc:?}"
    );

    // Nothing mutated: the stale entry survives byte-for-byte.
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        manifest_before,
        "a dry-run prune must not GC the manifest"
    );
}

/// An externally-held `.socket/apply.lock` fails the vendor step with the
/// contract `lock_held` code + the stable contention message, folded into
/// scan's own JSON error shape (not an `acquire_or_emit` Envelope).
#[tokio::test]
async fn scan_vendor_lock_held_reports_json_error() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    seed_unstageable_manifest(tmp.path());
    let _external = take_external_lock(&tmp.path().join(".socket"));

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    let v = assert_vendor_step_error(code, &stdout, &stderr, "lock_held");
    assert_eq!(
        v["error"]["message"],
        "another socket-patch process is operating in this directory",
        "the contention message is contract; envelope={v}"
    );
}

/// A DIRECTORY squatting on `.socket/apply.lock` makes the lock file
/// unopenable — `apply_lock::acquire` surfaces it as `LockError::Io`, and
/// the vendor step maps that to the distinct `lock_io` code (never
/// mislabeled as contention).
#[tokio::test]
async fn scan_vendor_lock_io_reports_json_error() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    seed_unstageable_manifest(tmp.path());
    std::fs::create_dir_all(tmp.path().join(".socket/apply.lock")).unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_vendor_step_error(code, &stdout, &stderr, "lock_io");
}

/// A corrupt committed manifest: scan's EARLY tolerant read swallows the
/// parse error (`.ok().flatten()`), so the run proceeds all the way to
/// the vendor step, whose own `read_manifest` surfaces the corruption as
/// `invalid_manifest` — the same code the `vendor` command uses.
#[tokio::test]
async fn scan_vendor_corrupt_manifest_reports_invalid_manifest() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), b"{not json").unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_vendor_step_error(code, &stdout, &stderr, "invalid_manifest");
}

/// A regular FILE squatting on `.socket` itself: scan's earlier phases
/// tolerate it (the manifest read degrades to None, the ledger load to an
/// empty set), so the run reaches the vendor step and dies exactly at its
/// `create_dir_all(socket_dir)` guard — `socket_dir_unwritable`.
#[tokio::test]
async fn scan_vendor_socket_dir_file_reports_unwritable() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_vendor_step_error(code, &stdout, &stderr, "socket_dir_unwritable");
}

/// The interactive (non-JSON) vendor-step error arm: same unstageable
/// fixture as `scan_vendor_step_error_e2e.rs`, `--json` dropped. The
/// human arm must exit 1 with the `Error (code): message` line on stderr
/// — and the reconcile that ran BEFORE the staging failure must still
/// have persisted its ledger rewrite (human mode reports less, it must
/// not DO less).
#[tokio::test]
async fn scan_vendor_staging_error_interactive_prints_error_line() {
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
    assert!(
        stderr.contains(
            "Error (no_local_source): patch artifacts unavailable (offline or download failure)"
        ),
        "the human arm must name the code and message on stderr; \
         stdout={stdout}; stderr={stderr}"
    );
    // Human mode: no JSON envelope on stdout.
    assert!(
        serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err(),
        "the interactive arm must not print a JSON envelope; stdout={stdout}"
    );
    // The pre-failure reconcile still persisted: the ledger's only entry
    // was reverted, so `save_state` deleted state.json (disk truth is the
    // human arm's only record of the mutation).
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "the reconcile must persist even when the run aborts at staging; \
         stdout={stdout}; stderr={stderr}"
    );
}
