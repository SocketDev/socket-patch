//! Integration tests for the v5.0 remove↔rollback duality surface of
//! `remove`: `--preserve-state` (restore the tree, keep the local patch
//! state), its `--skip-rollback` conflict, the archive-sweep extension of
//! the default GC, the hosted-redirect leg, and the drift-keep
//! partial-failure contract.
//!
//! Binary-driven (spawns `CARGO_BIN_EXE_socket-patch` through
//! `common::run_with_env`, which scrubs the ambient `SOCKET_*` env), fully
//! offline: every fixture is hand-written camelCase JSON plus blobs staged
//! under `.socket/blobs`, and every wet run passes `--offline`.
//!
//! DISCREPANCY PINS (implementation is the source of truth):
//! CLI_CONTRACT.md ("remove unwinds hosted redirects (v5.0)") promises "a
//! hosted-only match works with no manifest at all (mirroring the
//! detached-vendored escape)". The implementation does NOT deliver that:
//! `remove.rs`'s manifest-missing gate recognizes the hosted-only match and
//! proceeds, but the `matching.is_empty()` branch afterwards knows only the
//! detached-vendored escape and falls through to `not_found` (exit 1)
//! without ever reaching the hosted leg. The two `*_pins_not_found` tests
//! below pin that ACTUAL behavior; the hosted leg itself is reachable (and
//! covered here) only when the identifier also matches a manifest entry.

use std::path::{Path, PathBuf};

#[path = "common/mod.rs"]
mod common;

/// Spawn `socket-patch remove` with the scrubbed env (`common::run_with_env`)
/// plus telemetry disabled; `env` entries land last so per-test injections
/// (e.g. `SOCKET_PRESERVE_STATE`) survive the scrub.
fn run_remove(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut full = vec!["remove"];
    full.extend_from_slice(args);
    let mut env_full = vec![("SOCKET_TELEMETRY_DISABLED", "1")];
    env_full.extend_from_slice(env);
    common::run_with_env(cwd, &full, &env_full)
}

fn read_json_file(path: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn read_manifest(socket: &Path) -> serde_json::Value {
    read_json_file(&socket.join("manifest.json"))
}

/// Events carrying `action == "removed"` and a string purl.
fn removed_event_purls(v: &serde_json::Value) -> Vec<String> {
    v["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|e| e["action"] == "removed" && e["purl"].is_string())
                .filter_map(|e| e["purl"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 1. --preserve-state on an installed, genuinely patched agent-mode package
// ---------------------------------------------------------------------------

const PRESERVE_PURL: &str = "pkg:npm/__preserve_dual_test__@1.0.0";
const PRESERVE_UUID: &str = "77777777-7777-4777-8777-777777777777";
const ORIGINAL_BYTES: &[u8] = b"original contents\n";
const PATCHED_BYTES: &[u8] = b"patched contents\n";

/// Manifest + blobs + installed-at-PATCHED-bytes package for
/// [`PRESERVE_PURL`]. Returns (socket_dir, before_hash, after_hash).
fn make_preserve_fixture(root: &Path) -> (PathBuf, String, String) {
    let before_hash = common::git_sha256(ORIGINAL_BYTES);
    let after_hash = common::git_sha256(PATCHED_BYTES);
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "{PRESERVE_PURL}": {{
      "uuid": "{PRESERVE_UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/a.js": {{ "beforeHash": "{before_hash}", "afterHash": "{after_hash}" }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic preserve test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(&before_hash), ORIGINAL_BYTES).expect("stage before blob");
    std::fs::write(blobs.join(&after_hash), PATCHED_BYTES).expect("stage after blob");

    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "preserve-fixture", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
    let pkg_dir = root.join("node_modules/__preserve_dual_test__");
    std::fs::create_dir_all(&pkg_dir).expect("create package dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "__preserve_dual_test__", "version": "1.0.0" }"#,
    )
    .expect("write package.json");
    std::fs::write(pkg_dir.join("a.js"), PATCHED_BYTES).expect("write patched a.js");
    (socket, before_hash, after_hash)
}

/// `remove --preserve-state` on an installed, patched package must restore
/// the file to its ORIGINAL bytes (the rollback half still runs) while
/// keeping ALL local state: the manifest entry survives byte-for-byte, both
/// blobs survive (GC is skipped entirely), `summary.removed` stays 0, and
/// no per-purl `removed` event fires.
///
/// ACTUAL event shape pinned here: for a pure agent-mode patch the wet run
/// emits ONLY the purl-less artifact carrier (`details.rolledBack: 1`) — the
/// `vendor_state_preserved` Skipped reason exists only for vendored entries
/// (pinned by the next test). `--offline` proves the restore came from the
/// staged before-blob, not the network.
#[test]
fn preserve_state_restores_but_keeps_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (socket, before_hash, after_hash) = make_preserve_fixture(tmp.path());
    let manifest_before = std::fs::read(socket.join("manifest.json")).expect("read before");

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[PRESERVE_PURL, "--json", "--yes", "--offline", "--preserve-state"],
        &[],
    );
    assert_eq!(
        code, 0,
        "preserve-state remove must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "success");
    assert_eq!(v["dryRun"], serde_json::Value::Bool(false));
    assert_eq!(
        v["summary"]["removed"], 0,
        "no manifest entry is deleted under --preserve-state; envelope={v}"
    );

    // The system half really happened: the installed file is back at its
    // ORIGINAL bytes.
    let restored =
        std::fs::read(tmp.path().join("node_modules/__preserve_dual_test__/a.js")).unwrap();
    assert_eq!(
        restored, ORIGINAL_BYTES,
        "the patched file must be restored to its original bytes"
    );

    // The state half was preserved: manifest byte-identical (entry kept)...
    let manifest_after = std::fs::read(socket.join("manifest.json")).expect("read after");
    assert_eq!(
        manifest_before, manifest_after,
        "--preserve-state must not touch the manifest"
    );
    // ...and BOTH blobs survive — GC is skipped, so even the afterHash blob
    // (an orphan a default remove would sweep) stays for the re-apply.
    assert!(
        socket.join("blobs").join(&before_hash).exists(),
        "beforeHash blob must be kept"
    );
    assert!(
        socket.join("blobs").join(&after_hash).exists(),
        "afterHash blob must be kept (GC skipped under --preserve-state)"
    );

    // Envelope events: no per-purl removal, and the artifact carrier reports
    // the rollback that DID happen.
    assert!(
        removed_event_purls(&v).is_empty(),
        "no per-purl removed event may fire under --preserve-state; envelope={v}"
    );
    let events = v["events"].as_array().expect("events array");
    let carrier = events
        .iter()
        .find(|e| e["action"] == "removed" && e["purl"].is_null())
        .unwrap_or_else(|| panic!("expected the artifact carrier event: {events:?}"));
    assert_eq!(
        carrier["details"]["rolledBack"], 1,
        "the carrier must report the one rolled-back package; carrier={carrier}"
    );
    assert_eq!(
        carrier["details"]["blobsRemoved"], 0,
        "no blobs may be swept under --preserve-state; carrier={carrier}"
    );
}

// ---------------------------------------------------------------------------
// 1b. --preserve-state on a vendored entry: the actual state-preserved reason
// ---------------------------------------------------------------------------

const PV_PURL: &str = "pkg:npm/__preserve_vendored__@1.0.0";
const PV_UUID: &str = "55555555-5555-4555-8555-555555555555";

fn write_manifest_files_empty(root: &Path, purl: &str, uuid: &str) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "synthetic remove-duality test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// Vendor ledger with one npm entry (fixture copied from
/// cli_remove_silent.rs / remove_invariants.rs — do not edit those files).
fn write_vendor_state_wired(root: &Path, purl: &str, uuid: &str, wiring: &str) -> PathBuf {
    let vendor = root.join(".socket/vendor");
    let artifact_dir = vendor.join("npm").join(uuid);
    std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").expect("write artifact");
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{purl}": {{
      "ecosystem": "npm",
      "basePurl": "{purl}",
      "uuid": "{uuid}",
      "artifact": {{ "path": ".socket/vendor/npm/{uuid}/package.tgz" }},
      "wiring": {wiring}
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).expect("write vendor state");
    artifact_dir
}

/// The vendored flavor of `--preserve-state` pins the ACTUAL state-preserved
/// reason code remove.rs emits: `skipped`/`vendor_state_preserved`. The
/// ledger entry is kept byte-identical, the artifact dir survives, the
/// manifest entry survives, and `summary.removed` stays 0.
#[test]
fn preserve_state_keeps_vendored_ledger_and_artifact() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_manifest_files_empty(tmp.path(), PV_PURL, PV_UUID);
    let artifact_dir = write_vendor_state_wired(tmp.path(), PV_PURL, PV_UUID, "[]");
    let manifest_before = std::fs::read(socket.join("manifest.json")).expect("read before");
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = std::fs::read(&ledger_path).expect("read ledger before");

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[PV_PURL, "--json", "--yes", "--offline", "--preserve-state"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 0);

    // The ACTUAL preserved-state reason code from remove.rs.
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "skipped"
            && e["errorCode"] == "vendor_state_preserved"
            && e["purl"] == PV_PURL),
        "expected a skipped/vendor_state_preserved event: {events:?}"
    );

    // Ledger entry kept BYTE-IDENTICAL (the liveness contract: its wiring
    // records replay as no-ops on a later revert), artifact + manifest kept.
    assert_eq!(
        std::fs::read(&ledger_path).expect("read ledger after"),
        ledger_before,
        "--preserve-state must keep the vendor ledger entry byte-identical"
    );
    assert!(
        artifact_dir.join("package.tgz").exists(),
        "the vendored artifact must be kept"
    );
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).expect("read after"),
        manifest_before,
        "the manifest entry must be kept"
    );
}

// ---------------------------------------------------------------------------
// 2. --preserve-state conflicts with --skip-rollback (exit 2), flag- or
//    env-sourced
// ---------------------------------------------------------------------------

/// The two flags select the do-nothing quadrant: `--skip-rollback` keeps the
/// tree and drops the state, `--preserve-state` restores the tree and keeps
/// the state. Together → self-enforced usage error, exit 2, before anything
/// is read or created. Fires identically when either side comes from its
/// env var (`SOCKET_PRESERVE_STATE=true`).
#[test]
fn preserve_conflicts_with_skip_rollback() {
    // Flag-sourced.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[
            "pkg:npm/x@1.0.0",
            "--json",
            "--yes",
            "--preserve-state",
            "--skip-rollback",
        ],
        &[],
    );
    assert_eq!(
        code, 2,
        "the conflict is a usage error; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("no-op"),
        "the error must explain the no-op quadrant; got {stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "usage errors print to stderr, not a JSON envelope; got {stdout:?}"
    );
    // The conflict fires before any store is read or created.
    assert!(
        !tmp.path().join(".socket").exists(),
        "a usage error must not create a .socket directory"
    );

    // Env-sourced: SOCKET_PRESERVE_STATE=true + --skip-rollback conflicts
    // exactly the same way (the contract row says flag- or env-sourced alike).
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let (code2, _stdout2, stderr2) = run_remove(
        tmp2.path(),
        &["pkg:npm/x@1.0.0", "--json", "--yes", "--skip-rollback"],
        &[("SOCKET_PRESERVE_STATE", "true")],
    );
    assert_eq!(
        code2, 2,
        "env-sourced preserve-state must conflict too; stderr=\n{stderr2}"
    );
    assert!(
        stderr2.contains("no-op"),
        "same self-enforced usage error text; got {stderr2:?}"
    );
    assert!(!tmp2.path().join(".socket").exists());
}

// ---------------------------------------------------------------------------
// 3. Default remove sweeps diff/package archives too (v5.0 GC extension)
// ---------------------------------------------------------------------------

const ARCH_UUID_A: &str = "11111111-1111-4111-8111-111111111111";
const ARCH_UUID_B: &str = "22222222-2222-4222-8222-222222222222";

/// Two-entry manifest whose uuids anchor the archive keep-rule.
fn make_two_entry_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/__archive_a__@1.0.0": {{
      "uuid": "{ARCH_UUID_A}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "synthetic archive test patch A",
      "license": "MIT",
      "tier": "free"
    }},
    "pkg:npm/__archive_b__@2.0.0": {{
      "uuid": "{ARCH_UUID_B}",
      "exportedAt": "2024-01-02T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "synthetic archive test patch B",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// The default cleanup now covers `.socket/diffs` and `.socket/packages`
/// (`<uuid>.tar.gz`, kept iff the uuid is still referenced by the
/// post-removal manifest) in addition to blobs. Removing A must sweep A's
/// archives from BOTH dirs while B's — still referenced by the second
/// manifest entry — survive; the artifact carrier reports the count.
#[test]
fn default_remove_sweeps_archives_too() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_two_entry_socket_dir(tmp.path());
    for dir in ["diffs", "packages"] {
        let d = socket.join(dir);
        std::fs::create_dir_all(&d).expect("create archive dir");
        std::fs::write(d.join(format!("{ARCH_UUID_A}.tar.gz")), b"a-archive").unwrap();
        std::fs::write(d.join(format!("{ARCH_UUID_B}.tar.gz")), b"b-archive").unwrap();
    }

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &["pkg:npm/__archive_a__@1.0.0", "--json", "--yes", "--skip-rollback"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1);
    assert_eq!(
        removed_event_purls(&v),
        vec!["pkg:npm/__archive_a__@1.0.0"],
        "exactly A's manifest entry is removed"
    );

    // A's archives are gone from BOTH archive dirs; B's survive in both.
    for dir in ["diffs", "packages"] {
        assert!(
            !socket.join(dir).join(format!("{ARCH_UUID_A}.tar.gz")).exists(),
            "the removed entry's {dir} archive must be swept"
        );
        assert!(
            socket.join(dir).join(format!("{ARCH_UUID_B}.tar.gz")).exists(),
            "the kept entry's {dir} archive must survive"
        );
    }

    // The purl-less artifact carrier reports the two swept archives.
    let events = v["events"].as_array().expect("events array");
    let carrier = events
        .iter()
        .find(|e| e["action"] == "removed" && e["purl"].is_null())
        .unwrap_or_else(|| panic!("expected the artifact carrier event: {events:?}"));
    assert_eq!(
        carrier["details"]["archivesRemoved"], 2,
        "one diff + one package archive swept; carrier={carrier}"
    );

    // The keep-rule really is manifest-anchored: B's entry survives.
    let manifest = read_manifest(&socket);
    assert!(manifest["patches"]["pkg:npm/__archive_b__@2.0.0"].is_object());
}

// ---------------------------------------------------------------------------
// 4. Hosted-redirect leg
// ---------------------------------------------------------------------------

const NPM_PURL: &str = "pkg:npm/left-pad@1.3.0";
const NPM_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const ORIG_RESOLVED: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
const ORIG_INTEGRITY: &str = "sha512-UPSTREAM==";
const HOSTED_RESOLVED: &str = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
const HOSTED_INTEGRITY: &str = "sha512-PATCHED==";

/// A lockfileVersion-3 package-lock.json whose left-pad entry currently
/// holds the HOSTED (redirected) resolved/integrity pair.
fn redirected_lock_text() -> String {
    format!(
        r#"{{
  "name": "hosted-fixture",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "packages": {{
    "": {{ "name": "hosted-fixture", "version": "0.0.0" }},
    "node_modules/left-pad": {{
      "name": "left-pad",
      "version": "1.3.0",
      "resolved": "{HOSTED_RESOLVED}",
      "integrity": "{HOSTED_INTEGRITY}"
    }}
  }}
}}
"#
    )
}

/// One hand-written camelCase PatchRecord body (the shared record shape of
/// the manifest and the redirect ledger).
fn record_json(uuid: &str, description: &str) -> String {
    format!(
        r#"{{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "{description}",
      "license": "MIT",
      "tier": "free"
    }}"#
    )
}

/// Redirect ledger (real `RedirectState` schema: version/mode/edits/records)
/// with ONE npm record and its recorded `redirect_npm_lock_entry` edit
/// matching [`redirected_lock_text`].
fn npm_redirect_ledger_text() -> String {
    let record = record_json(NPM_UUID, "synthetic hosted npm patch");
    format!(
        r#"{{
  "version": 1,
  "mode": "hosted",
  "edits": [
    {{
      "path": "package-lock.json",
      "kind": "redirect_npm_lock_entry",
      "action": "rewritten",
      "key": "node_modules/left-pad",
      "original": {{ "resolved": "{ORIG_RESOLVED}", "integrity": "{ORIG_INTEGRITY}" }},
      "new": {{ "resolved": "{HOSTED_RESOLVED}", "integrity": "{HOSTED_INTEGRITY}" }}
    }}
  ],
  "records": {{
    "{NPM_PURL}": {record}
  }}
}}"#
    )
}

fn write_redirect_ledger_text(root: &Path, text: &str) -> PathBuf {
    let vendor = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor).expect("create .socket/vendor");
    let path = vendor.join("redirect-state.json");
    std::fs::write(&path, text).expect("write redirect ledger");
    path
}

/// Hosted-only remove with no manifest at all (a hosted-only project's
/// per-purl exit path): the redirect is unwound — lock restored to the
/// pre-redirect entry, emptied ledger deleted — and the unwind IS the
/// removal, so the `hosted_reverted` event counts toward
/// `summary.removed` (the detached-vendored convention).
#[test]
fn hosted_only_remove_without_manifest_unwinds_redirect() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_text = redirected_lock_text();
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, &lock_text).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(
        v["summary"]["removed"], 1,
        "the hosted unwind IS the removal on this path; envelope={v}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "removed"
            && e["purl"] == NPM_PURL
            && e["errorCode"] == "hosted_reverted"),
        "removed/hosted_reverted event expected; envelope={v}"
    );

    // The lock holds exactly the pre-redirect entry again (same whole-file
    // derivation as the manifest-path twin below).
    let mut expected: serde_json::Value = serde_json::from_str(&lock_text).unwrap();
    let entry = expected["packages"]["node_modules/left-pad"]
        .as_object_mut()
        .expect("lock entry object");
    entry.insert("resolved".into(), serde_json::json!(ORIG_RESOLVED));
    entry.insert("integrity".into(), serde_json::json!(ORIG_INTEGRITY));
    let expected_text = format!("{}\n", serde_json::to_string_pretty(&expected).unwrap());
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_text,
        "the lock must hold exactly the pre-redirect entry"
    );
    assert!(
        !ledger_path.exists(),
        "the emptied redirect ledger must be deleted"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "no manifest may be materialized as a side effect"
    );
}

/// The hosted leg where it IS reachable: the identifier matches a manifest
/// entry AND the redirect ledger's record for the same purl. The remove
/// unwinds the redirect (per-purl npm revert): the lock entry gets its
/// original resolved/integrity back byte-exactly, the emptied ledger is
/// deleted, and the envelope carries the `hosted_reverted` event alongside
/// the per-purl manifest removal.
#[test]
fn hosted_remove_with_manifest_entry_unwinds_redirect() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_text = redirected_lock_text();
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, &lock_text).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(
        v["summary"]["removed"], 1,
        "the hosted_reverted event must not inflate the manifest-entry count"
    );

    // The lock is restored byte-exactly: derive the expected bytes the same
    // way the revert writes them (parse the fixture, put the originals back,
    // serialize with the workspace's preserve_order serde_json + trailing
    // newline). This pins the WHOLE file, not just the two fields.
    let mut expected: serde_json::Value = serde_json::from_str(&lock_text).unwrap();
    let entry = expected["packages"]["node_modules/left-pad"]
        .as_object_mut()
        .expect("lock entry object");
    entry.insert("resolved".into(), serde_json::json!(ORIG_RESOLVED));
    entry.insert("integrity".into(), serde_json::json!(ORIG_INTEGRITY));
    let expected_text = format!("{}\n", serde_json::to_string_pretty(&expected).unwrap());
    let reverted_text = std::fs::read_to_string(&lock_path).unwrap();
    assert_eq!(
        reverted_text, expected_text,
        "the lock must hold exactly the pre-redirect entry"
    );
    assert!(
        !reverted_text.contains(NPM_UUID),
        "no hosted artifact URL (patch uuid) may survive in the lock"
    );

    // Record + edit dropped → empty ledger deleted outright.
    assert!(
        !ledger_path.exists(),
        "the emptied redirect ledger must be deleted; envelope={v}"
    );

    // Envelope: the hosted unwind event plus the plain per-purl removal.
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "removed"
            && e["errorCode"] == "hosted_reverted"
            && e["purl"] == NPM_PURL),
        "expected a removed/hosted_reverted event: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "removed" && e["purl"] == NPM_PURL && e["errorCode"].is_null()),
        "expected the per-purl manifest-removal event: {events:?}"
    );

    // The manifest entry itself is gone.
    let manifest = read_manifest(&socket);
    assert!(
        manifest["patches"].as_object().expect("patches").is_empty(),
        "the manifest entry must be removed"
    );
}

// ---------------------------------------------------------------------------
// 5. Unsupported-ecosystem hosted purl fails closed
// ---------------------------------------------------------------------------

const GEM_PURL: &str = "pkg:gem/rexml@3.2.5";
const GEM_UUID: &str = "aaaa1111-2222-4333-8444-555566667777";

/// Ledger with a gem record (no per-purl revert exists) AND a second npm
/// record, so a `remove pkg:gem/…` identifier does NOT cover the full
/// record set and the whole-ledger replay cannot serve it.
fn gem_plus_npm_ledger_text() -> String {
    let gem_record = record_json(GEM_UUID, "synthetic hosted gem patch");
    let npm_record = record_json(NPM_UUID, "synthetic hosted npm patch");
    format!(
        r#"{{
  "version": 1,
  "mode": "hosted",
  "edits": [
    {{
      "path": "Gemfile",
      "kind": "redirect_gem_source_block",
      "action": "added",
      "key": "rexml",
      "new": "source \"https://patch.socket.dev/gem/t0k3n\" do\n  gem \"rexml\"\nend\n"
    }}
  ],
  "records": {{
    "{GEM_PURL}": {gem_record},
    "{NPM_PURL}": {npm_record}
  }}
}}"#
    )
}

/// With a manifest entry for the gem purl (the only way the hosted leg is
/// reachable — see the module docs), the unsupported-ecosystem hosted
/// target fails closed BEFORE the manifest mutation: exit 1, top-level
/// `hosted_revert_unsupported`, and BOTH stores byte-identical.
#[test]
fn hosted_unsupported_ecosystem_remove_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ledger_path = write_redirect_ledger_text(tmp.path(), &gem_plus_npm_ledger_text());
    let ledger_before = std::fs::read(&ledger_path).unwrap();
    let socket = write_manifest_files_empty(tmp.path(), GEM_PURL, GEM_UUID);
    let manifest_before = std::fs::read(socket.join("manifest.json")).unwrap();

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[GEM_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "unsupported hosted revert must fail; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    assert_eq!(
        v["error"]["code"], "hosted_revert_unsupported",
        "envelope={v}"
    );
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains(GEM_PURL) && msg.contains("scan --mode hosted"),
        "the error must name the purl and the remedy; got {msg}"
    );
    assert_eq!(v["summary"]["removed"], 0);

    // Fail-closed: ledger AND manifest byte-identical.
    assert_eq!(
        std::fs::read(&ledger_path).unwrap(),
        ledger_before,
        "the redirect ledger must be unchanged"
    );
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).unwrap(),
        manifest_before,
        "the manifest was not modified (the error message promises it)"
    );
}

/// Manifest-less twin of the unsupported-ecosystem refusal: the gem+npm
/// ledger's gem identifier reaches the hosted-only removal path (the
/// manifest-missing escape), where the gem record has no per-purl revert
/// and the identifier does NOT cover the full record set (so the
/// whole-ledger replay cannot serve it) — fail closed with
/// `hosted_revert_unsupported`, ledger untouched.
#[test]
fn hosted_only_unsupported_remove_without_manifest_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ledger_path = write_redirect_ledger_text(tmp.path(), &gem_plus_npm_ledger_text());
    let ledger_before = std::fs::read(&ledger_path).unwrap();

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[GEM_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "error", "envelope={v}");
    assert_eq!(v["error"]["code"], "hosted_revert_unsupported", "envelope={v}");
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains(GEM_PURL) && msg.contains("socket-patch rollback"),
        "the refusal names the purl and the unscoped-rollback remedy; envelope={v}"
    );
    assert_eq!(
        std::fs::read(&ledger_path).unwrap(),
        ledger_before,
        "the redirect ledger must be unchanged"
    );
}

// ---------------------------------------------------------------------------
// 6. Drift-kept vendored revert = partial failure (v5.0 drift-keep fix)
// ---------------------------------------------------------------------------

const DK_PURL: &str = "pkg:npm/__remove_dual_test__@1.0.0";
const DK_UUID: &str = "33333333-3333-4333-8333-333333333333";

/// A wiring record naming a file the npm revert backend does not edit: the
/// revert drift-keeps (`kept_artifact`) — fixture copied from
/// cli_remove_silent.rs (do not edit that file).
const DRIFTED_WIRING: &str = r#"[{ "file": "weird.txt", "kind": "npm_lock_entry", "action": "added", "key": "node_modules/x" }]"#;

/// When EVERY matching entry's vendored revert drift-keeps, the remove did
/// not happen: exit 1, `status: partialFailure`, top-level
/// `vendor_revert_kept` (NOT `not_found` — the identifier DID match),
/// `summary.removed` honest at 0, and BOTH the manifest entry and the
/// ledger entry survive byte-for-byte (plus the artifact) so a later
/// normalize + retry can finish the job.
#[test]
fn drift_kept_vendored_remove_is_partial_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_manifest_files_empty(tmp.path(), DK_PURL, DK_UUID);
    let artifact_dir = write_vendor_state_wired(tmp.path(), DK_PURL, DK_UUID, DRIFTED_WIRING);
    let manifest_before = std::fs::read(socket.join("manifest.json")).unwrap();
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = std::fs::read(&ledger_path).unwrap();

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[DK_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "an all-kept remove is a partial failure; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "partialFailure", "envelope={v}");
    assert_eq!(v["error"]["code"], "vendor_revert_kept", "envelope={v}");
    assert_eq!(
        v["summary"]["removed"], 0,
        "nothing was removed, the count must say so"
    );

    // The per-purl Skipped event carries the same reason code.
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "skipped"
            && e["errorCode"] == "vendor_revert_kept"
            && e["purl"] == DK_PURL),
        "expected a skipped/vendor_revert_kept event: {events:?}"
    );

    // Fail-closed: manifest entry, ledger entry, and artifact all survive.
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).unwrap(),
        manifest_before,
        "the drift-kept purl's manifest entry must survive byte-for-byte"
    );
    assert_eq!(
        std::fs::read(&ledger_path).unwrap(),
        ledger_before,
        "the drift-kept ledger entry must survive byte-for-byte"
    );
    assert!(
        artifact_dir.join("package.tgz").exists(),
        "the vendored artifact must survive a drift-keep"
    );
}
