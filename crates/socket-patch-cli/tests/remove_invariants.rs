//! Integration tests for `remove` against pre-populated manifests.
//!
//! `remove` runs rollback internally before deleting from the manifest.
//! These tests pass `--skip-rollback` so they don't try to walk
//! node_modules — every code path here is testable without network or
//! installed packages.

use std::path::{Path, PathBuf};

#[path = "common/mod.rs"]
mod common;

const TWO_PATCH_MANIFEST: &str = r#"{
  "patches": {
    "pkg:npm/__remove_test_a__@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/a.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic remove test patch A",
      "license": "MIT",
      "tier": "free"
    },
    "pkg:npm/__remove_test_b__@2.0.0": {
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-02T00:00:00Z",
      "files": {
        "package/b.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "2222222222222222222222222222222222222222222222222222222222222222"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic remove test patch B",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn make_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), TWO_PATCH_MANIFEST).expect("write manifest");
    socket
}

/// Install `__remove_test_a__` under `node_modules/` with `a.js` matching
/// neither the (unsatisfiable all-zeros) beforeHash nor the afterHash: the
/// file genuinely needs its original bytes back, so an absent before-blob
/// blocks the internal rollback.
///
/// The rollback-failure tests need this because the before-blob gate covers
/// only INSTALLED packages whose files need restoring: a manifest entry with
/// no installed package is a benign `package_not_installed` skip (nothing on
/// disk to restore), which `remove` correctly proceeds past — it would never
/// reach the `rollback_failed` paths those tests pin.
fn install_remove_test_a(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "remove-invariants-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
    let pkg_dir = root.join("node_modules/__remove_test_a__");
    std::fs::create_dir_all(&pkg_dir).expect("create package dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "__remove_test_a__", "version": "1.0.0" }"#,
    )
    .expect("write package.json");
    std::fs::write(pkg_dir.join("a.js"), b"patched-ish content\n").expect("write a.js");
}

/// All spawns go through `common::run_with_env`, which scrubs the ambient
/// `SOCKET_*` environment: an inherited SOCKET_DRY_RUN=true silently turns
/// every wet remove below into a no-op preview, and an inherited
/// SOCKET_MANIFEST_PATH / SOCKET_PROXY_URL aims the mutation (or the
/// rollback blob fetch) outside the tempdir.
fn run_remove(cwd: &Path, identifier: &str, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["remove", identifier, "--json", "--yes", "--skip-rollback"];
    args.extend_from_slice(extra);
    let (code, stdout, _stderr) = common::run_with_env(cwd, &args, &[]);
    (code, stdout)
}

fn read_manifest(socket: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(socket.join("manifest.json")).expect("read manifest");
    serde_json::from_str(&body).expect("parse manifest")
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn remove_with_no_manifest_emits_manifest_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/foo@1.0.0", &[]);
    assert_eq!(code, 1, "no manifest must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "manifest_not_found");
    // A "not found" error must not silently materialize a default manifest
    // directory as a side effect.
    assert!(
        !tmp.path().join(".socket").exists(),
        "a missing-manifest error must not create a .socket directory"
    );
}

#[test]
fn remove_with_unknown_identifier_emits_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    let before = std::fs::read(socket.join("manifest.json")).expect("read before");

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/does-not-exist@1.0.0", &[]);
    assert_eq!(code, 1, "unknown identifier must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "notFound");
    assert_eq!(v["error"]["code"], "not_found");
    if let Some(summary) = v.get("summary") {
        assert_eq!(
            summary["removed"], 0,
            "a not-found remove must report 0 removed"
        );
    }

    // A no-match remove must leave BOTH existing entries in place and must
    // not rewrite the file at all — otherwise a broken matcher that deletes
    // the wrong entry (or churns the manifest) could still report notFound.
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 2, "no entries should be removed");
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
    let after = std::fs::read(socket.join("manifest.json")).expect("read after");
    assert_eq!(
        before, after,
        "a no-op remove must not rewrite the manifest file"
    );
}

#[test]
fn remove_with_invalid_manifest_emits_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), "{not json").unwrap();

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/foo@1.0.0", &[]);
    assert_eq!(code, 1, "invalid manifest must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    // A parse failure must be distinguished from a missing manifest, otherwise
    // a broken loader could silently treat corrupt JSON as "not found".
    assert_eq!(v["error"]["code"], "manifest_unreadable");
    let msg = v["error"]["message"]
        .as_str()
        .expect("error message string");
    assert!(
        msg.contains("parse") || msg.contains("JSON"),
        "error message should explain the parse failure; got: {msg}"
    );
    // Nothing was removed on the error path.
    assert_eq!(v["summary"]["removed"], 0);
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn remove_by_purl_drops_matching_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/__remove_test_a__@1.0.0", &[]);
    assert_eq!(code, 0, "remove must succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1, "exactly one entry removed");
    let events = v["events"].as_array().expect("events array");
    let removed_purls: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "removed" && e["purl"].is_string())
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(removed_purls, vec!["pkg:npm/__remove_test_a__@1.0.0"]);

    // Manifest should still contain the other entry.
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 1);
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
    assert!(!patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
}

#[test]
fn remove_by_uuid_drops_matching_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout) = run_remove(tmp.path(), "22222222-2222-4222-8222-222222222222", &[]);
    assert_eq!(code, 0, "remove by uuid must succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1, "exactly one entry removed");
    // Resolving a UUID must drop B's PURL (not just "some" entry): the event
    // stream must name B, proving the uuid→purl resolution is correct rather
    // than incidentally deleting the right count of entries.
    let events = v["events"].as_array().expect("events array");
    let removed_purls: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "removed" && e["purl"].is_string())
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(removed_purls, vec!["pkg:npm/__remove_test_b__@2.0.0"]);

    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(patches.len(), 1);
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(!patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
}

#[test]
fn remove_event_has_required_envelope_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/__remove_test_a__@1.0.0", &[]);
    assert_eq!(code, 0, "remove must succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1);
    // This is a real removal (no --dry-run), so dryRun must be exactly false —
    // not merely "a boolean". A run that secretly short-circuits to dry-run
    // would report removed:1 while never touching the manifest.
    assert_eq!(v["dryRun"], serde_json::Value::Bool(false));

    // The event stream must name the actually-removed patch.
    let events = v["events"].as_array().expect("events array");
    let removed_purls: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "removed" && e["purl"].is_string())
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(removed_purls, vec!["pkg:npm/__remove_test_a__@1.0.0"]);

    // The reported removal must be durable: the manifest on disk must reflect it.
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 1);
    assert!(!patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
}

// ---------------------------------------------------------------------------
// Real rollback path (no --skip-rollback)
// ---------------------------------------------------------------------------

/// Every other test passes `--skip-rollback`, which bypasses the
/// rollback-before-remove step that `remove` runs by default. That makes the
/// suite blind to the actual contract: if the internal rollback fails, the
/// manifest entry must NOT be deleted (fail-closed — never drop a patch from
/// the manifest while leaving patched files un-restored on disk).
///
/// Here we drive the real path. The synthetic patch's beforeHash blob does
/// not exist in `.socket/blobs`, and `--offline` forbids fetching it, so
/// rollback cannot complete and `remove` must abort with `rollback_failed`,
/// leaving the manifest fully intact. A regression that swallowed the
/// rollback failure and deleted the entry anyway would flip this test red.
///
/// `--offline` is what keeps this hermetic: without it, rollback fetches the
/// missing before-blob from the live proxy (`GET /patch/blob/<beforeHash>`)
/// and the test only passes because that request 404s.
///
/// The package must be INSTALLED (with its file off the original bytes) for
/// the missing before-blob to fail the rollback: since the before-blob gate
/// reorder, a manifest entry with no installed package is a benign
/// `package_not_installed` skip — nothing on disk to restore — and `remove`
/// correctly proceeds to drop it (its "No packages found to rollback (not
/// installed)" path). Only an installed, patched package with an absent
/// before-blob still fails closed.
#[test]
fn remove_without_skip_rollback_fails_closed_and_keeps_manifest() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    let before = std::fs::read(socket.join("manifest.json")).expect("read before");
    install_remove_test_a(tmp.path());

    let (code, stdout, _stderr) = common::run_with_env(
        tmp.path(),
        &[
            "remove",
            "pkg:npm/__remove_test_a__@1.0.0",
            "--json",
            "--yes",
            "--offline",
        ],
        &[],
    );
    assert_eq!(
        code, 1,
        "a failed rollback must abort remove; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    assert_eq!(
        v["error"]["code"], "rollback_failed",
        "remove must surface the rollback failure, not a generic error"
    );
    assert_eq!(
        v["summary"]["removed"], 0,
        "nothing removed when rollback fails"
    );

    // The crucial invariant: the manifest is byte-for-byte unchanged. The
    // entry the user asked to remove is still present because its files could
    // not be restored.
    let after = std::fs::read(socket.join("manifest.json")).expect("read after");
    assert_eq!(
        before, after,
        "a failed rollback must leave the manifest entirely untouched"
    );
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 2);
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
}

// ---------------------------------------------------------------------------
// Blob-sweep artifact event must not inflate the removed count
// ---------------------------------------------------------------------------

/// When `remove` sweeps an orphaned blob (or rolls files back) it appends a
/// purl-less, artifact-level `Removed` event carrying `details.blobsRemoved` /
/// `details.rolledBack`. That carrier is metadata — NOT a removed manifest
/// entry — so it must never bump `summary.removed`.
///
/// Every other test passes `--skip-rollback` against a manifest whose afterHash
/// blobs aren't present on disk, so the cleanup phase sweeps nothing and the
/// carrier never fires — leaving this path completely uncovered. Here we stage
/// both patches' afterHash blobs in `.socket/blobs`, remove A, and force a
/// real one-blob sweep (A's afterHash blob becomes unreferenced; B's stays).
///
/// The contract: exactly ONE manifest entry was deleted, so `summary.removed`
/// must be 1 — matching the single per-purl `removed` event — even though the
/// event stream also carries the artifact carrier reporting `blobsRemoved: 1`.
/// A regression that routes the carrier through the summary-bumping `record`
/// path would report `removed: 2` and flip this test red.
#[test]
fn remove_blob_sweep_does_not_inflate_removed_count() {
    // afterHash values from TWO_PATCH_MANIFEST.
    const AFTER_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const AFTER_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(AFTER_A), b"blob-a").expect("stage blob A");
    std::fs::write(blobs.join(AFTER_B), b"blob-b").expect("stage blob B");

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/__remove_test_a__@1.0.0", &[]);
    assert_eq!(code, 0, "remove must succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");

    // The crux: one entry removed → summary.removed == 1, NOT 2.
    assert_eq!(
        v["summary"]["removed"], 1,
        "the blob-sweep carrier event must not inflate summary.removed; envelope={v}"
    );

    let events = v["events"].as_array().expect("events array");
    // Exactly one per-purl Removed event, naming A.
    let removed_purls: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "removed" && e["purl"].is_string())
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(removed_purls, vec!["pkg:npm/__remove_test_a__@1.0.0"]);

    // The artifact carrier is still present (purl-less) and reports the sweep.
    let carrier = events
        .iter()
        .find(|e| e["action"] == "removed" && e["purl"].is_null())
        .expect("artifact-level Removed carrier event must be present");
    assert_eq!(
        carrier["details"]["blobsRemoved"], 1,
        "exactly A's orphaned afterHash blob should be swept; carrier={carrier}"
    );

    // B's afterHash blob is still referenced, so it must survive on disk;
    // A's must be gone.
    assert!(
        !blobs.join(AFTER_A).exists(),
        "A's orphaned blob must be swept"
    );
    assert!(
        blobs.join(AFTER_B).exists(),
        "B's referenced blob must remain"
    );
}

// ---------------------------------------------------------------------------
// Vendored patches: the wiring must never outlive the manifest entry
// ---------------------------------------------------------------------------

const VENDORED_PURL: &str = "pkg:npm/__remove_vendored__@1.0.0";
/// The manifest's current patch generation.
const MANIFEST_UUID: &str = "55555555-5555-4555-8555-555555555555";
/// The generation that was actually vendored — one behind the manifest.
/// This is the documented `vendor_uuid_mismatch` state: `get` / `scan
/// --apply` refreshed the manifest record while the re-vendor is still
/// pending (repair reports it and declines to cross patch generations).
const LEDGER_UUID: &str = "66666666-6666-4666-8666-666666666666";

/// Manifest with a single vendored npm patch. `files: {}` keeps the run
/// offline — the internal rollback needs no before-blobs.
fn write_vendored_manifest(root: &Path, patch_uuid: &str) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "{VENDORED_PURL}": {{
      "uuid": "{patch_uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "synthetic vendored remove test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// Vendor ledger with one npm entry for [`VENDORED_PURL`] at `ledger_uuid`
/// (empty wiring, so the revert is a pure offline artifact-dir delete),
/// plus the artifact dir it names.
fn write_vendored_ledger(root: &Path, ledger_uuid: &str) -> PathBuf {
    let vendor = root.join(".socket/vendor");
    let artifact_dir = vendor.join("npm").join(ledger_uuid);
    std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").expect("write artifact");
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{VENDORED_PURL}": {{
      "ecosystem": "npm",
      "basePurl": "{VENDORED_PURL}",
      "uuid": "{ledger_uuid}",
      "artifact": {{ "path": ".socket/vendor/npm/{ledger_uuid}/package.tgz" }},
      "wiring": []
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).expect("write vendor state");
    artifact_dir
}

/// `remove` must revert the vendoring of every patch it deletes from the
/// manifest: otherwise the lockfile keeps resolving to the committed
/// `.socket/vendor/` artifact after the manifest forgot the patch, so the
/// dependency stays silently patched with no record of it — and the
/// internal rollback can't compensate, because it deliberately skips
/// vendor-owned purls (nothing was patched in the installed tree).
///
/// The regression: the ledger lookup matched the raw remove identifier
/// only, never the manifest purls actually being deleted. A patch uuid is
/// exactly the identifier that resolves through the manifest but not
/// through the ledger whenever the vendored generation is older than the
/// manifest's — `remove <uuid>` matched the manifest entry by its NEW
/// uuid and would have had to match the ledger entry by its OLD one. The
/// revert was skipped in silence and the run still reported success.
///
/// Fully offline: no files in the record, vendor-owned purl (so the
/// rollback returns before the before-blob gate), empty wiring.
#[test]
#[ignore = "RED: pins a ledger-generation matching fix in remove.rs that was not \
            part of this change."]
fn remove_by_uuid_reverts_vendoring_when_ledger_generation_is_older() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_vendored_manifest(tmp.path(), MANIFEST_UUID);
    let artifact_dir = write_vendored_ledger(tmp.path(), LEDGER_UUID);

    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &["remove", MANIFEST_UUID, "--json", "--yes"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["summary"]["removed"], 1, "the manifest entry is deleted");
    assert!(
        read_manifest(&socket)["patches"]
            .as_object()
            .expect("patches object")
            .is_empty(),
        "precondition: the manifest entry really was removed"
    );

    // The crux: the vendoring must be gone too. An emptied ledger is
    // deleted outright, so a surviving state.json means a surviving entry.
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "remove must revert the vendoring of the entry it deleted; envelope={v}"
    );
    assert!(
        !artifact_dir.exists(),
        "the vendored artifact must be deleted with the patch; envelope={v}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["errorCode"] == "vendor_reverted"
            && e["purl"] == VENDORED_PURL
            && e["action"] == "removed"),
        "expected a vendor_reverted Removed event for the vendored purl: {events:?}"
    );
}

/// Control for the test above: removing the SAME fixture by PURL already
/// reverted the vendoring, so the by-uuid failure was a matching hole
/// rather than a broken fixture (no artifact, unrevertable wiring, ...).
/// Also pins the in-sync generation case end to end.
#[test]
fn remove_by_purl_reverts_vendoring() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_vendored_manifest(tmp.path(), MANIFEST_UUID);
    let artifact_dir = write_vendored_ledger(tmp.path(), LEDGER_UUID);

    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &["remove", VENDORED_PURL, "--json", "--yes"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "removing by purl must revert the vendoring; stdout=\n{stdout}"
    );
    assert!(!artifact_dir.exists(), "artifact must be deleted");
}

// ---------------------------------------------------------------------------
// Manifest-path override
// ---------------------------------------------------------------------------

#[test]
fn remove_honors_manifest_path_override() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let custom_dir = tmp.path().join("custom");
    std::fs::create_dir_all(&custom_dir).unwrap();
    std::fs::write(custom_dir.join("patches.json"), TWO_PATCH_MANIFEST).unwrap();

    let (code, stdout, _stderr) = common::run_with_env(
        tmp.path(),
        &[
            "remove",
            "pkg:npm/__remove_test_a__@1.0.0",
            "--json",
            "--yes",
            "--skip-rollback",
            "--manifest-path",
            "custom/patches.json",
        ],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1);

    // The override file — not the default location — must be the one mutated,
    // and it must drop exactly the requested entry (A), keeping B.
    let body = std::fs::read_to_string(custom_dir.join("patches.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(patches.len(), 1);
    assert!(!patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));

    // The override must be honored, not silently ignored in favor of a
    // freshly-created default manifest.
    assert!(
        !tmp.path().join(".socket").exists(),
        "remove must not create a default .socket manifest when --manifest-path is given"
    );
}

// ---------------------------------------------------------------------------
// --dry-run (global contract row: "Preview, no mutations")
// ---------------------------------------------------------------------------

/// `remove --dry-run` must mutate NOTHING — the manifest keeps every entry —
/// while the envelope reports the preview: `dryRun: true`, per-purl
/// `Verified` events (the apply/vendor/repair dry-run convention), and
/// `summary.removed` stays 0 because no entry was actually deleted.
#[test]
fn remove_dry_run_keeps_manifest_and_emits_verified_previews() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = make_socket_dir(tmp.path());

    let (code, stdout) = run_remove(
        tmp.path(),
        "pkg:npm/__remove_test_a__@1.0.0",
        &["--dry-run"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["dryRun"], true);
    assert_eq!(
        v["summary"]["removed"], 0,
        "a preview must not count as a removal"
    );

    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "verified" && e["purl"] == "pkg:npm/__remove_test_a__@1.0.0"),
        "expected a Verified preview event for the matched purl: {events:?}"
    );
    assert!(
        events.iter().all(|e| e["action"] != "removed"),
        "dry-run must not emit Removed events: {events:?}"
    );

    // The on-disk manifest is untouched: both entries survive.
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(patches.len(), 2, "dry-run must not delete manifest entries");
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
}

/// The blob sweep runs in preview mode on `--dry-run`: the artifact-level
/// carrier event reports how many blobs WOULD be swept (as `Verified`,
/// with `details.blobsRemoved`), but the blob files stay on disk.
#[test]
fn remove_dry_run_previews_blob_sweep_without_deleting() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = make_socket_dir(tmp.path());

    // A's afterHash blob: referenced only by entry A, so removing A
    // makes it sweepable.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    let blob_a = blobs.join("1111111111111111111111111111111111111111111111111111111111111111");
    std::fs::write(&blob_a, b"patched contents").unwrap();

    let (code, stdout) = run_remove(
        tmp.path(),
        "pkg:npm/__remove_test_a__@1.0.0",
        &["--dry-run"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["dryRun"], true);

    let events = v["events"].as_array().expect("events array");
    let carrier = events
        .iter()
        .find(|e| e["action"] == "verified" && e["details"]["blobsRemoved"].is_number())
        .unwrap_or_else(|| panic!("expected a Verified blob-sweep carrier event: {events:?}"));
    assert_eq!(
        carrier["details"]["blobsRemoved"], 1,
        "the preview must count A's now-unreferenced blob"
    );

    assert!(blob_a.exists(), "dry-run must not delete blobs from disk");
    let manifest = read_manifest(&socket);
    assert_eq!(manifest["patches"].as_object().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// Crawler-miss safety: a dropped entry whose rollback was skipped as
// not-installed must keep its beforeHash blobs (the only local revert data)
// ---------------------------------------------------------------------------

/// beforeHash values distinct per entry (unlike TWO_PATCH_MANIFEST's shared
/// all-zeros), so the sweep assertions can attribute each blob to one entry.
const NI_BEFORE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NI_AFTER_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const NI_BEFORE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NI_AFTER_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn make_distinct_blob_socket_dir(root: &Path) -> PathBuf {
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/__remove_test_a__@1.0.0": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/a.js": {{ "beforeHash": "{NI_BEFORE_A}", "afterHash": "{NI_AFTER_A}" }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic remove test patch A",
      "license": "MIT",
      "tier": "free"
    }},
    "pkg:npm/__remove_test_b__@2.0.0": {{
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-02T00:00:00Z",
      "files": {{
        "package/b.js": {{ "beforeHash": "{NI_BEFORE_B}", "afterHash": "{NI_AFTER_B}" }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic remove test patch B",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// The purls of events carrying `errorCode: rollback_not_installed`.
fn not_installed_event_purls(v: &serde_json::Value) -> Vec<String> {
    v["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|e| e["errorCode"] == "rollback_not_installed")
                .filter_map(|e| e["purl"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// THE crawler-miss guard: entry A is in the manifest but NOT installed
/// (nothing under `node_modules/`), so the nested rollback skips it as
/// `not_installed` — nothing was actually reverted. A crawler layout gap
/// looks exactly the same, with the patched bytes still on disk. `remove`
/// still drops the manifest entry (the documented long-uninstalled
/// contract), but it must (a) surface a machine-visible warning event and
/// (b) keep A's beforeHash blob out of the sweep — destroying it would
/// permanently lose the only local revert data.
///
/// `--offline` keeps this hermetic AND proves no download is needed: a
/// not-installed entry never enters the before-blob plan.
#[test]
fn remove_not_installed_keeps_before_blob_and_warns() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_distinct_blob_socket_dir(tmp.path());
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(NI_BEFORE_A), b"a-before").expect("stage A before blob");
    std::fs::write(blobs.join(NI_AFTER_A), b"a-after").expect("stage A after blob");
    std::fs::write(blobs.join(NI_AFTER_B), b"b-after").expect("stage B after blob");

    let (code, stdout, _stderr) = common::run_with_env(
        tmp.path(),
        &[
            "remove",
            "pkg:npm/__remove_test_a__@1.0.0",
            "--json",
            "--yes",
            "--offline",
        ],
        &[],
    );
    assert_eq!(
        code, 0,
        "removing a not-installed entry still succeeds; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");

    // The entry is dropped (long-uninstalled contract unchanged)...
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert!(!patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));

    // (a) ...with a machine-visible warning naming the purl whose rollback
    // was skipped as not-installed...
    assert_eq!(
        not_installed_event_purls(&v),
        vec!["pkg:npm/__remove_test_a__@1.0.0"],
        "expected a rollback_not_installed warning event; envelope={v}"
    );

    // (b) ...and A's beforeHash blob SURVIVES the sweep: it is the only
    // local revert data for bytes that may still be patched on disk.
    assert!(
        blobs.join(NI_BEFORE_A).exists(),
        "the not-installed entry's beforeHash blob must be excluded from \
         the cleanup sweep; envelope={v}"
    );
    // The keep-set addition is scoped to REVERT data: A's afterHash blob is
    // unreferenced patched bytes and is swept as before, and B's referenced
    // afterHash blob survives as before.
    assert!(
        !blobs.join(NI_AFTER_A).exists(),
        "A's orphaned afterHash blob is still swept"
    );
    assert!(
        blobs.join(NI_AFTER_B).exists(),
        "B's referenced afterHash blob must remain"
    );
}

/// Control for the guard above: an entry whose files are INSTALLED and
/// already at their original bytes really is reverted state — rollback
/// reports it `already_original`, so its beforeHash blob is swept exactly
/// as before and no `rollback_not_installed` warning fires. Guards the
/// fail-closed keep-set from degrading into keep-everything.
#[test]
fn remove_already_original_sweeps_before_blob_without_warning() {
    let original = b"original bytes\n";
    let before_hash = common::git_sha256(original);

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/__remove_test_a__@1.0.0": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/a.js": {{ "beforeHash": "{before_hash}", "afterHash": "{NI_AFTER_A}" }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic remove test patch A",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(&before_hash), original).expect("stage before blob");

    // Installed at the BEFORE bytes: rollback verifies already-original.
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "remove-invariants-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
    let pkg_dir = tmp.path().join("node_modules/__remove_test_a__");
    std::fs::create_dir_all(&pkg_dir).expect("create package dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "__remove_test_a__", "version": "1.0.0" }"#,
    )
    .expect("write package.json");
    std::fs::write(pkg_dir.join("a.js"), original).expect("write a.js");

    let (code, stdout, _stderr) = common::run_with_env(
        tmp.path(),
        &[
            "remove",
            "pkg:npm/__remove_test_a__@1.0.0",
            "--json",
            "--yes",
            "--offline",
        ],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        not_installed_event_purls(&v).is_empty(),
        "an already-original entry is not a crawler miss — no warning; envelope={v}"
    );
    assert!(
        !blobs.join(&before_hash).exists(),
        "an already-original entry's beforeHash blob is swept as before"
    );
    assert!(
        !read_manifest(&socket)["patches"]
            .as_object()
            .expect("patches object")
            .contains_key("pkg:npm/__remove_test_a__@1.0.0"),
        "the entry is removed"
    );
}

/// `--skip-rollback` semantics unchanged: no rollback runs, so there is no
/// not-installed outcome to react to — the sweep and the (absent) warning
/// behave exactly as before the crawler-miss guard.
#[test]
fn remove_skip_rollback_sweep_semantics_unchanged() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_distinct_blob_socket_dir(tmp.path());
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(NI_BEFORE_A), b"a-before").expect("stage A before blob");

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/__remove_test_a__@1.0.0", &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        not_installed_event_purls(&v).is_empty(),
        "--skip-rollback runs no rollback, so no not-installed warning; envelope={v}"
    );
    assert!(
        !blobs.join(NI_BEFORE_A).exists(),
        "--skip-rollback ('don't touch my tree') keeps the pre-guard sweep \
         behavior: the dropped entry's beforeHash blob is swept"
    );
}

/// The full-path preview (no --skip-rollback) must not create `.socket/blobs`
/// either: rollback's preview previously `create_dir_all`'d it (and, online,
/// downloaded before-blobs into it) — leaving new files a wet remove's sweep
/// would have deleted. Offline keeps this hermetic: the preview reports the
/// missing-blob failure (accurate — a wet offline run fails the same way)
/// without inventing directories.
///
/// The package is installed (see `install_remove_test_a`) so the missing
/// before-blob genuinely fails the rollback preview — and the preview walks
/// its full path, including the throwaway dry-run blob stage the litter
/// check below covers.
#[test]
fn remove_dry_run_with_rollback_does_not_create_blobs_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = make_socket_dir(tmp.path());
    install_remove_test_a(tmp.path());
    assert!(!socket.join("blobs").exists(), "precondition: no blobs dir");

    let (code, stdout, _stderr) = common::run_with_env(
        tmp.path(),
        &[
            "remove",
            "pkg:npm/__remove_test_a__@1.0.0",
            "--json",
            "--yes",
            "--dry-run",
            "--offline",
        ],
        &[],
    );
    // Offline + missing before-blobs: the preview accurately reports the
    // rollback failure a wet run would hit (exit 1, rollback_failed)...
    assert_eq!(code, 1, "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["error"]["code"], "rollback_failed");
    assert_eq!(
        v["dryRun"], true,
        "preview failures must still report dryRun:true"
    );
    // ...but mutates nothing: no blobs dir, manifest intact, no stage litter.
    assert!(
        !socket.join("blobs").exists(),
        "dry-run must not create .socket/blobs"
    );
    assert_eq!(
        read_manifest(&socket)["patches"].as_object().unwrap().len(),
        2
    );
    let litter: Vec<_> = std::fs::read_dir(&socket)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".socket-stage-"))
        .collect();
    assert!(litter.is_empty(), "no stage litter: {litter:?}");
}
