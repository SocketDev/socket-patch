//! Coverage-gap tests for `commands/scan/vendor_flow.rs` (2026-09 audit).
//!
//! Pins the audited-but-untested surfaces of `scan --vendor`:
//!
//! * the `already_vendored` dry-run preview arm (the sibling
//!   `would_vendor` / `would_revendor` arms are pinned by
//!   `scan_vendor_e2e.rs`);
//! * the legal-but-never-executed `--dry-run --prune` combination in the
//!   vendor JSON path (GC preview field names, nothing mutated);
//! * every error constructor of `run_scan_vendor_step` — `lock_held`,
//!   `lock_io` (a directory squatting on `apply.lock`; a file squatting on
//!   `.socket` itself) and `no_local_source` — through the JSON error fold
//!   (a lock failure precedes the step and carries NO `vendor` key; a
//!   staging failure carries the step's envelope demoted to
//!   `partialFailure`, events-less because nothing mutates before staging)
//!   and the interactive `Error (code): message` line;
//! * a corrupt legacy manifest, which vendored mode reports and steps
//!   around (the manifest is not its record source).
//!
//! Fixtures are clones of `scan_vendor_e2e.rs` (each e2e file carries its
//! own copy — the established pattern), plus `e2e_safety_lock.rs`'s
//! external-flock trick for lock contention. Mock API only; no real hosts.

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
    mount_discovery(mock, uuid).await;
    mount_view(mock, uuid, /*with_blob_content=*/ true).await;
}

/// Mount discovery (batch) and the per-package search for `uuid`.
async fn mount_discovery(mock: &MockServer, uuid: &str) {
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
}

/// Mount the full patch view for `uuid`. Without `with_blob_content` the
/// view carries the file hashes but no `blobContent`: the download phase
/// still records the patch (it needs only the hashes), but the vendor
/// step cannot obtain the patched bytes and staging fails
/// (`no_local_source`) — independent of how many times the view is
/// fetched along the way.
async fn mount_view(mock: &MockServer, uuid: &str, with_blob_content: bool) {
    let mut file = serde_json::json!({
        "beforeHash": git_sha256(BEFORE),
        "afterHash": git_sha256(AFTER),
    });
    if with_blob_content {
        file["blobContent"] = serde_json::json!(AFTER_B64);
    }
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": file },
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

/// Shared assertions for the vendor-step error fold: exit 1, a JSON
/// envelope with `status: "error"`, the given `error.code` and a `download`
/// sub-object (proof the run got PAST the download phase and died inside
/// the vendor step). Whether a `vendor` sub-object rides along depends on
/// WHERE the step died — see [`assert_no_vendor_envelope`] (lock failures)
/// and [`assert_demoted_empty_vendor_envelope`] (staging failures).
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
    v
}

/// A lock failure happens BEFORE the step builds its envelope: no `vendor`
/// sub-object may be fabricated for it (get's fold pins the same in
/// `covgap_commands_get::vendored_lock_held_vendor_step_errors_without_vendor_envelope`).
fn assert_no_vendor_envelope(v: &serde_json::Value) {
    assert!(
        !v.as_object().unwrap().contains_key("vendor"),
        "a pre-lock failure has no vendor envelope to carry; envelope={v}"
    );
}

/// A staging failure happens AFTER the lock, inside the step: the fold
/// carries the step's envelope demoted to `partialFailure` (a consumer
/// reading `.vendor.status` inside a `"status":"error"` result must not
/// see the fresh-envelope default `success`) and events-less — nothing
/// mutates before staging, so there is no work to report.
fn assert_demoted_empty_vendor_envelope(v: &serde_json::Value) {
    assert_eq!(
        v["vendor"]["status"], "partialFailure",
        "the carried envelope's status must be demoted; envelope={v}"
    );
    assert_eq!(
        v["vendor"]["events"],
        serde_json::json!([]),
        "nothing mutates before staging, so the aborted step reports no events; envelope={v}"
    );
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
    assert_eq!(
        v["vendor"]["patches"],
        serde_json::json!([]),
        "envelope={v}"
    );

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

/// An externally-held `.socket/apply.lock` fails the vendor step (after
/// the manifest-free download phase fetched the record) with the contract
/// `lock_held` code + the stable contention message — no `--lock-timeout`,
/// so no "(waited …)" clause — folded into scan's own JSON error shape
/// (not an `acquire_or_emit` Envelope). Nothing is vendored.
#[tokio::test]
async fn scan_vendor_lock_held_reports_json_error() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let _external = take_external_lock(&tmp.path().join(".socket"));

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    let v = assert_vendor_step_error(code, &stdout, &stderr, "lock_held");
    assert_no_vendor_envelope(&v);
    assert_eq!(
        v["error"]["message"], "another socket-patch process is operating in this directory",
        "the contention message is contract; envelope={v}"
    );
    assert_eq!(v["download"]["downloaded"], 1, "envelope={v}");
    assert!(!tmp.path().join(".socket/vendor").exists());
}

/// A DIRECTORY squatting on `.socket/apply.lock` makes the lock file
/// unopenable — `apply_lock::acquire` surfaces it as `LockError::Io`, and
/// the vendor step maps that to the distinct `lock_io` code (never
/// mislabeled as contention).
#[tokio::test]
async fn scan_vendor_lock_io_reports_json_error() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    std::fs::create_dir_all(tmp.path().join(".socket/apply.lock")).unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    let v = assert_vendor_step_error(code, &stdout, &stderr, "lock_io");
    assert_no_vendor_envelope(&v);
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("apply.lock")),
        "the I/O reason names the lock file; envelope={v}"
    );
}

/// A corrupt committed manifest is not vendored mode's record source:
/// scan's early tolerant read swallows the parse error, the run vendors
/// normally (exit 0), and only the post-vendor legacy-record migration
/// notices — reporting `vendor_manifest_migration_failed` on the vendor
/// envelope's `warnings[]` and leaving the file byte-identical for the
/// operator (the `vendor` command, whose work list it is, still fails
/// closed on it).
#[tokio::test]
async fn scan_vendor_corrupt_manifest_is_reported_and_stepped_around() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), b"{not json").unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "envelope={v}");
    assert!(
        v["vendor"]["warnings"]
            .as_array()
            .is_some_and(|ws| ws.iter().any(|w| {
                w["code"] == "vendor_manifest_migration_failed"
                    && w["detail"].as_str().unwrap_or("").contains("manifest.json")
            })),
        "the unreadable manifest must be reported; envelope={v}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        b"{not json",
        "the corrupt manifest is left for the operator"
    );
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
}

/// A regular FILE squatting on `.socket` itself: scan's earlier phases
/// tolerate it (the ledger load degrades to an empty set on a non-Bun
/// project), so the run reaches the vendor step, whose `acquire` cannot
/// create the lock directory — `lock_io`, the file left untouched.
#[tokio::test]
async fn scan_vendor_socket_dir_file_reports_lock_io() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    let v = assert_vendor_step_error(code, &stdout, &stderr, "lock_io");
    assert_no_vendor_envelope(&v);
    assert_eq!(
        std::fs::read(tmp.path().join(".socket")).unwrap(),
        b"not a dir",
        "the squatting file survives"
    );
}

/// The JSON vendor-step error fold for a staging failure: the download
/// phase recorded the patch (hashes only), but the view serves no blob
/// content, so the vendor step cannot stage it and the run aborts
/// `no_local_source` with a `download` object and the step's own `vendor`
/// envelope carried through the fold — demoted to `partialFailure`, with
/// no events (nothing mutated before staging) — and creates nothing under
/// `.socket/`. Contract: the `vendor` sub-object is present whenever the
/// step ran; `get --mode vendored` shares the fold
/// (`covgap_commands_get::get_uuid_vendored_vendor_step_error_leaves_legacy_state_alone`).
#[tokio::test]
async fn scan_vendor_staging_error_reports_json_error() {
    let mock = MockServer::start().await;
    mount_discovery(&mock, UUID).await;
    mount_view(&mock, UUID, /*with_blob_content=*/ false).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    let v = assert_vendor_step_error(code, &stdout, &stderr, "no_local_source");
    assert_demoted_empty_vendor_envelope(&v);
    assert_eq!(
        v["error"]["message"], "patch artifacts unavailable (offline or download failure)",
        "envelope={v}"
    );
    assert_eq!(v["download"]["downloaded"], 1, "envelope={v}");
    assert!(
        !tmp.path().join(".socket").exists(),
        "an aborted step leaves no .socket/ behind (lock file and empty dir removed)"
    );
}

/// The interactive (non-JSON) twin of the staging failure: exit 1 with
/// the `Error (code): message` line on stderr, no JSON envelope on
/// stdout, nothing vendored.
#[tokio::test]
async fn scan_vendor_staging_error_interactive_prints_error_line() {
    let mock = MockServer::start().await;
    mount_discovery(&mock, UUID).await;
    mount_view(&mock, UUID, /*with_blob_content=*/ false).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

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
        "an unstageable record must fail the run; stdout={stdout}; stderr={stderr}"
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
    assert!(
        !tmp.path().join(".socket").exists(),
        "an aborted step leaves no .socket/ behind; stdout={stdout}; stderr={stderr}"
    );
}
