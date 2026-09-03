//! Coverage-gap tests for `commands/remove.rs` (audit of 2026-09, commit
//! d5e1815): the lock-contention return, the vendor-ledger hard-failure
//! aborts, the hosted-redirect leg's dry-run / preserve-state / refusal /
//! failure branches, the drift-keep exclusion arms, the mixed drift-keep
//! partial failure, and the human-mode output surfaces that were only ever
//! exercised in JSON mode.
//!
//! Binary-driven (spawns `CARGO_BIN_EXE_socket-patch` through
//! `common::run_with_env`, which scrubs the ambient `SOCKET_*` env), fully
//! offline: every fixture is hand-written camelCase JSON, and every wet run
//! passes `--offline`. Fixture shapes are copied from
//! remove_invariants.rs / remove_duality_invariants.rs /
//! interactive_prompts_e2e.rs (do not edit those files).

use std::path::{Path, PathBuf};

#[path = "common/mod.rs"]
mod common;

/// Spawn `socket-patch remove` with the scrubbed env plus telemetry
/// disabled; `env` entries land last so per-test injections survive.
fn run_remove(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut full = vec!["remove"];
    full.extend_from_slice(args);
    let mut env_full = vec![("SOCKET_TELEMETRY_DISABLED", "1")];
    env_full.extend_from_slice(env);
    common::run_with_env(cwd, &full, &env_full)
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("stdout must be a JSON envelope: {e}\nstdout:\n{stdout}"))
}

/// Events carrying the given action and a string purl.
fn event_purls(v: &serde_json::Value, action: &str) -> Vec<String> {
    v["events"]
        .as_array()
        .map(|events| {
            events
                .iter()
                .filter(|e| e["action"] == action && e["purl"].is_string())
                .filter_map(|e| e["purl"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// One hand-written camelCase manifest with a single `files: {}` patch —
/// the internal rollback needs no before-blobs, keeping wet runs offline.
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
      "description": "covgap remove test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// Two-entry `files: {}` manifest (purl1/uuid1, purl2/uuid2).
fn write_two_entry_manifest(
    root: &Path,
    purl1: &str,
    uuid1: &str,
    purl2: &str,
    uuid2: &str,
) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let manifest = format!(
        r#"{{
  "patches": {{
    "{purl1}": {{
      "uuid": "{uuid1}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "covgap remove test patch 1",
      "license": "MIT",
      "tier": "free"
    }},
    "{purl2}": {{
      "uuid": "{uuid2}",
      "exportedAt": "2024-01-02T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "covgap remove test patch 2",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).expect("write manifest");
    socket
}

/// Vendor ledger with one npm entry keyed `key` (extra: raw JSON fields
/// appended to the entry — e.g. `"flavor": "...",` or `"detached": true,`),
/// plus the artifact dir it names. Fixture shape copied from
/// remove_invariants.rs::write_vendored_ledger (do not edit that file).
fn write_vendor_ledger_entry(
    root: &Path,
    key: &str,
    base_purl: &str,
    uuid: &str,
    wiring: &str,
    extra: &str,
) -> PathBuf {
    let vendor = root.join(".socket/vendor");
    let artifact_dir = vendor.join("npm").join(uuid);
    std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").expect("write artifact");
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{key}": {{
      "ecosystem": "npm",
      "basePurl": "{base_purl}",
      "uuid": "{uuid}",
      {extra}"artifact": {{ "path": ".socket/vendor/npm/{uuid}/package.tgz" }},
      "wiring": {wiring}
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).expect("write vendor state");
    artifact_dir
}

/// A wiring record naming a file the npm revert backend does not edit: the
/// revert drift-keeps (`kept_artifact`) — fixture copied from
/// remove_duality_invariants.rs (do not edit that file).
const DRIFTED_WIRING: &str = r#"[{ "file": "weird.txt", "kind": "npm_lock_entry", "action": "added", "key": "node_modules/x" }]"#;

// ---------------------------------------------------------------------------
// Hosted-redirect fixtures (copied from remove_duality_invariants.rs —
// do not edit that file).
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

/// Redirect ledger (real `RedirectState` schema) with ONE npm record and
/// its recorded `redirect_npm_lock_entry` edit matching
/// [`redirected_lock_text`].
fn npm_redirect_ledger_text() -> String {
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
    "{NPM_PURL}": {{
      "uuid": "{NPM_UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "covgap hosted npm patch",
      "license": "MIT",
      "tier": "free"
    }}
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

/// The exact bytes the npm redirect revert writes when it restores
/// [`redirected_lock_text`] to the pre-redirect entry (same whole-file
/// derivation the remove_duality_invariants.rs twins use).
fn expected_reverted_lock_text() -> String {
    let mut expected: serde_json::Value =
        serde_json::from_str(&redirected_lock_text()).expect("parse fixture lock");
    let entry = expected["packages"]["node_modules/left-pad"]
        .as_object_mut()
        .expect("lock entry object");
    entry.insert("resolved".into(), serde_json::json!(ORIG_RESOLVED));
    entry.insert("integrity".into(), serde_json::json!(ORIG_INTEGRITY));
    format!("{}\n", serde_json::to_string_pretty(&expected).unwrap())
}

// ---------------------------------------------------------------------------
// 1. Lock contention (remove.rs:207)
// ---------------------------------------------------------------------------

/// `remove` against an externally-held `.socket/apply.lock` must refuse
/// with the same `lock_held` envelope contract apply pins in
/// e2e_safety_lock.rs — remove had never been run against a held lock.
/// After the lock is released the same removal must proceed.
#[test]
fn remove_lock_held_returned_then_proceeds_after_release() {
    use fs2::FileExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_lock__@1.0.0";
    let socket = write_manifest_files_empty(tmp.path(), purl, "11111111-1111-4111-8111-111111111111");
    let manifest_before = read_bytes(&socket.join("manifest.json"));

    // Take an exclusive flock on the binary's lock path (the
    // e2e_safety_lock.rs helper shape: same fs2 crate, same file).
    let lock_path = socket.join("apply.lock");
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open lock file");
    lock_file
        .try_lock_exclusive()
        .expect("test could not take initial lock");

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--skip-rollback"], &[]);
    assert_eq!(
        code, 1,
        "remove under contention must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "lock_held", "envelope={v}");
    assert_eq!(
        v["error"]["message"],
        "another socket-patch process is operating in this directory",
        "lock_held message must be the stable contention string; envelope={v}"
    );
    assert_eq!(
        v["summary"]["removed"], 0,
        "nothing may be removed while the lock is held; envelope={v}"
    );
    // Fail-closed: the manifest is byte-identical under contention.
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "a lock_held remove must not touch the manifest"
    );

    // Release and re-run: the removal must now proceed.
    drop(lock_file);
    let (code2, stdout2, stderr2) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--skip-rollback"], &[]);
    assert_eq!(code2, 0, "stdout=\n{stdout2}\nstderr=\n{stderr2}");
    let v2 = parse_envelope(&stdout2);
    assert_eq!(v2["status"], "success");
    assert_eq!(
        event_purls(&v2, "removed"),
        vec![purl],
        "the released lock must let the removal proceed; envelope={v2}"
    );
}

// ---------------------------------------------------------------------------
// 2. Corrupt vendor ledger fails the remove closed (remove.rs:457-464; the
//    human branch also covers emit_error_envelope's stderr arm at 87-88)
// ---------------------------------------------------------------------------

/// Garbage `.socket/vendor/state.json` must abort the remove BEFORE any
/// mutation (`vendor_state_unreadable`): we are about to mutate and cannot
/// know what we would leave wired.
#[test]
fn remove_corrupt_vendor_ledger_fails_closed_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_vsl__@1.0.0";
    let socket = write_manifest_files_empty(tmp.path(), purl, "22222222-2222-4222-8222-222222222222");
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let vendor = socket.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join("state.json"), "{{{").unwrap();

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "a corrupt vendor ledger must fail the remove; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "vendor_state_unreadable", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains("cannot read .socket/vendor/state.json"),
        "the error must name the unreadable ledger; got: {msg}"
    );
    assert_eq!(v["summary"]["removed"], 0);
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "the mutation must be aborted: manifest byte-identical"
    );
}

/// Human-mode twin: the same failure must reach stderr as an `Error:` line
/// (emit_error_envelope's non-JSON arm), with no JSON envelope on stdout.
#[test]
fn remove_corrupt_vendor_ledger_fails_closed_human() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_vsl__@1.0.0";
    let socket = write_manifest_files_empty(tmp.path(), purl, "22222222-2222-4222-8222-222222222222");
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let vendor = socket.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join("state.json"), "{{{").unwrap();

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Error: cannot read .socket/vendor/state.json"),
        "human mode must put the error line on stderr; got:\n{stderr}"
    );
    assert!(
        !stdout.contains("\"command\""),
        "human mode must not print a JSON envelope; got:\n{stdout}"
    );
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "the mutation must be aborted: manifest byte-identical"
    );
}

// ---------------------------------------------------------------------------
// 3. Vendor revert hard failure aborts before the manifest mutation
//    (remove.rs:517-533 main flow; 1240-1255 detached twin)
// ---------------------------------------------------------------------------

/// An unknown wiring flavor fails the revert closed (the VendorEntry
/// contract: reverts route on `flavor` and fail closed on flavors this
/// build has no backend for), and the remove must abort with
/// `vendor_revert_failed` BEFORE touching the manifest.
#[test]
fn remove_unknown_vendor_flavor_fails_closed_before_manifest_mutation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_flavor__@1.0.0";
    let uuid = "33333333-3333-4333-8333-333333333333";
    let socket = write_manifest_files_empty(tmp.path(), purl, uuid);
    let artifact_dir = write_vendor_ledger_entry(
        tmp.path(),
        purl,
        purl,
        uuid,
        "[]",
        "\"flavor\": \"no-such-flavor\",\n      ",
    );
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "an unrevertable flavor must fail the remove; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "vendor_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains("no-such-flavor") && msg.contains("The manifest was not modified."),
        "the error must name the flavor and promise the manifest is intact; got: {msg}"
    );
    assert_eq!(v["summary"]["removed"], 0);

    // Fail-closed: manifest, ledger entry, and artifact all survive.
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "the manifest was not modified (the error message promises it)"
    );
    assert_eq!(
        read_bytes(&ledger_path),
        ledger_before,
        "the ledger entry must survive a failed revert"
    );
    assert!(
        artifact_dir.join("package.tgz").exists(),
        "the vendored artifact must survive a failed revert"
    );
}

/// Detached twin (no manifest at all): the failure surfaces through
/// `remove_detached_only`'s own `vendor_revert_failed` branch, and the
/// ledger entry survives.
#[test]
fn remove_detached_unknown_vendor_flavor_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_detflavor__@1.0.0";
    let uuid = "44444444-4444-4444-8444-444444444444";
    let artifact_dir = write_vendor_ledger_entry(
        tmp.path(),
        purl,
        purl,
        uuid,
        "[]",
        "\"detached\": true,\n      \"flavor\": \"no-such-flavor\",\n      ",
    );
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "vendor_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains("no-such-flavor") && msg.contains(purl),
        "the error must name the flavor and the key; got: {msg}"
    );
    assert_eq!(
        read_bytes(&ledger_path),
        ledger_before,
        "the detached ledger entry must survive a failed revert"
    );
    assert!(
        artifact_dir.join("package.tgz").exists(),
        "the detached artifact must survive a failed revert"
    );
}

// ---------------------------------------------------------------------------
// 4. save_state failure after a successful revert (remove.rs:592-598 main
//    flow; 1273-1279 detached twin). Unix-only chmod choreography:
//    `.socket/vendor` goes read-only while `.socket/vendor/npm/` stays
//    writable, so the artifact delete succeeds but the ledger write fails.
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod {}: {e}", path.display()));
}

/// Restore the dir's mode even on assertion panic (or a panic inside the
/// binary runner), so the tempdir can clean up.
#[cfg(unix)]
struct ModeGuard(PathBuf);

#[cfg(unix)]
impl Drop for ModeGuard {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// Probe whether permission bits are enforced for this process; root (or
/// CAP_DAC_OVERRIDE containers) bypasses them, making read-only-dir tests
/// fail spuriously. Returns false (and logs a skip) when they are not.
#[cfg(unix)]
fn readonly_dir_enforced(dir: &Path) -> bool {
    let probe = dir.join(".covgap-write-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return false;
    }
    true
}

/// A vendor revert that succeeds but whose ledger persist fails must abort
/// with `vendor_state_write_failed` — and the manifest mutation (which
/// runs after) must never have happened.
#[cfg(unix)]
#[test]
fn remove_vendor_state_write_failure_aborts_before_manifest_mutation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_vsw__@1.0.0";
    let uuid = "55555555-5555-4555-8555-555555555555";
    let socket = write_manifest_files_empty(tmp.path(), purl, uuid);
    write_vendor_ledger_entry(tmp.path(), purl, purl, uuid, "[]", "");
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let vendor = tmp.path().join(".socket/vendor");

    // Read-only ledger dir; the per-eco artifact dir stays writable so the
    // revert's artifact delete succeeds and only save_state fails.
    chmod(&vendor, 0o555);
    let _mode = ModeGuard(vendor.clone());
    if !readonly_dir_enforced(&vendor) {
        return;
    }
    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--offline"], &[]);

    assert_eq!(
        code, 1,
        "a failed ledger write must abort the remove; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "vendor_state_write_failed", "envelope={v}");
    assert_eq!(v["summary"]["removed"], 0);
    // The manifest mutation runs after the vendor leg: it must not have
    // happened.
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "the manifest must be untouched when the ledger write fails"
    );
}

/// Detached twin: same choreography through `remove_detached_only`.
#[cfg(unix)]
#[test]
fn remove_detached_vendor_state_write_failure_fails_with_code() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_detvsw__@1.0.0";
    let uuid = "66666666-6666-4666-8666-666666666666";
    write_vendor_ledger_entry(tmp.path(), purl, purl, uuid, "[]", "\"detached\": true,\n      ");
    let vendor = tmp.path().join(".socket/vendor");

    chmod(&vendor, 0o555);
    let _mode = ModeGuard(vendor.clone());
    if !readonly_dir_enforced(&vendor) {
        return;
    }
    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--offline"], &[]);

    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "vendor_state_write_failed", "envelope={v}");
    // The ledger file could not be rewritten, so it must still exist.
    assert!(
        vendor.join("state.json").exists(),
        "the unwritable ledger must still be on disk"
    );
}

// ---------------------------------------------------------------------------
// 5. Hosted leg: dry-run previews (remove.rs:716 main flow; 1164
//    hosted-only)
// ---------------------------------------------------------------------------

/// A dry-run remove touching hosted records had NEVER run. The preview
/// must leave BOTH the lockfile and the redirect ledger byte-identical
/// while reporting the would-be unwind as a Verified/hosted_reverted
/// event.
#[test]
fn remove_hosted_dry_run_leaves_lock_and_ledger_untouched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let ledger_before = read_bytes(&ledger_path);
    let lock_before = read_bytes(&lock_path);
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
    let manifest_before = read_bytes(&socket.join("manifest.json"));

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[NPM_PURL, "--json", "--yes", "--offline", "--dry-run"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["dryRun"], true);
    assert_eq!(
        v["summary"]["removed"], 0,
        "a preview must not count as a removal; envelope={v}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "verified"
            && e["purl"] == NPM_PURL
            && e["errorCode"] == "hosted_reverted"),
        "the hosted unwind preview must be a verified/hosted_reverted event: {events:?}"
    );
    assert!(
        events.iter().all(|e| e["action"] != "removed"),
        "dry-run must not emit Removed events: {events:?}"
    );

    // Nothing on disk moved.
    assert_eq!(read_bytes(&lock_path), lock_before, "lock byte-identical");
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger byte-identical");
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "manifest byte-identical"
    );
}

/// Hosted-only twin (no manifest): the dry-run routes through
/// `remove_hosted_only`'s Verified arm and previews without mutating.
#[test]
fn remove_hosted_only_dry_run_previews_without_mutation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let ledger_before = read_bytes(&ledger_path);
    let lock_before = read_bytes(&lock_path);

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[NPM_PURL, "--json", "--offline", "--dry-run"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["dryRun"], true);
    assert_eq!(
        v["summary"]["verified"], 1,
        "the preview must count the would-be unwind; envelope={v}"
    );
    assert_eq!(v["summary"]["removed"], 0);
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "verified"
            && e["purl"] == NPM_PURL
            && e["errorCode"] == "hosted_reverted"),
        "expected a verified/hosted_reverted preview event: {events:?}"
    );
    assert_eq!(read_bytes(&lock_path), lock_before, "lock byte-identical");
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger byte-identical");
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "no manifest may be materialized as a side effect"
    );
}

// ---------------------------------------------------------------------------
// 6. Hosted leg: --preserve-state note + preserve-state human summary
//    (remove.rs:706-713, 809-813)
// ---------------------------------------------------------------------------

/// `--preserve-state` still unwinds hosted redirects (hosted has no
/// preservable local state) and the human run must say so on stderr —
/// while the manifest entry survives and the final preserve summary
/// prints.
#[test]
fn remove_hosted_preserve_state_notes_no_preservable_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
    let manifest_before = read_bytes(&socket.join("manifest.json"));

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[NPM_PURL, "--yes", "--offline", "--preserve-state"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("hosted redirects have no preservable local state"),
        "the preserve-state hosted note must reach stderr; got:\n{stderr}"
    );
    assert!(
        stdout.contains("Manifest entries and vendored artifacts preserved"),
        "the preserve-state summary must print; got:\n{stdout}"
    );

    // The unwind really happened: lock restored, emptied ledger deleted.
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_reverted_lock_text(),
        "the lock must hold exactly the pre-redirect entry"
    );
    assert!(!ledger_path.exists(), "the emptied redirect ledger must be deleted");
    // The state half was preserved: manifest byte-identical.
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "--preserve-state must keep the manifest entry"
    );
}

// ---------------------------------------------------------------------------
// 7. Corrupt hosted-redirect ledger: warn-and-continue (remove.rs:623-629)
// ---------------------------------------------------------------------------

/// A corrupt redirect ledger must not block a manifest removal: the main
/// flow warns on stderr ("hosted redirects were not examined") and the
/// removal still succeeds. The corrupt ledger is left alone (it may hold
/// revert data a human can repair).
#[test]
fn remove_corrupt_hosted_ledger_warns_and_continues_human() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_hcorrupt__@1.0.0";
    let socket = write_manifest_files_empty(tmp.path(), purl, "77777777-7777-4777-8777-777777777777");
    let ledger_path = write_redirect_ledger_text(tmp.path(), "{nope");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--yes", "--offline"], &[]);
    assert_eq!(
        code, 0,
        "a corrupt hosted ledger must not block the removal; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("hosted redirects were not examined"),
        "the warning must reach stderr; got:\n{stderr}"
    );
    assert!(
        stdout.contains("Removed 1 patch(es) from manifest:"),
        "the removal must still report; got:\n{stdout}"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "the manifest entry must be removed"
    );
    assert_eq!(
        read_bytes(&ledger_path),
        ledger_before,
        "the corrupt ledger must be left alone (it may hold repairable revert data)"
    );
}

/// JSON twin: the removal still succeeds and the corrupt ledger is left
/// alone. (Known gap, deliberately NOT pinned here: JSON mode currently
/// carries no machine-visible signal for the skipped hosted leg.)
#[test]
fn remove_corrupt_hosted_ledger_json_still_removes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_hcorrupt__@1.0.0";
    write_manifest_files_empty(tmp.path(), purl, "77777777-7777-4777-8777-777777777777");
    let ledger_path = write_redirect_ledger_text(tmp.path(), "{nope");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1, "envelope={v}");
    assert_eq!(event_purls(&v, "removed"), vec![purl]);
    assert_eq!(
        read_bytes(&ledger_path),
        ledger_before,
        "the corrupt ledger must be left alone"
    );
}

// ---------------------------------------------------------------------------
// 8. Hosted-only refusal + human listing (remove.rs:1066-1076, 1080-1084)
// ---------------------------------------------------------------------------

/// With no manifest entry to delete, removing a hosted patch can only mean
/// unwinding its redirect — `--skip-rollback` is refused with
/// `hosted_state_retained` and nothing moves.
#[test]
fn remove_hosted_only_skip_rollback_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let ledger_before = read_bytes(&ledger_path);
    let lock_before = read_bytes(&lock_path);

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[NPM_PURL, "--json", "--yes", "--offline", "--skip-rollback"],
        &[],
    );
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "hosted_state_retained", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains(NPM_PURL) && msg.contains("--skip-rollback"),
        "the refusal must name the purl and the flag; got: {msg}"
    );
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger untouched");
    assert_eq!(read_bytes(&lock_path), lock_before, "lock untouched");
}

/// Hosted-only human mode: the pre-confirm listing ("The following hosted
/// redirect(s) will be unwound and removed:") must print to stderr, and
/// the wet run must complete the unwind.
#[test]
fn remove_hosted_only_human_lists_redirects_and_unwinds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--yes", "--offline"], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("The following hosted redirect(s) will be unwound and removed:"),
        "the hosted-only listing must reach stderr; got:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("  - {NPM_PURL}")),
        "the listing must name the purl; got:\n{stderr}"
    );
    // The unwind really ran: lock restored byte-exactly, ledger deleted.
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_reverted_lock_text(),
        "the lock must hold exactly the pre-redirect entry"
    );
    assert!(!ledger_path.exists(), "the emptied redirect ledger must be deleted");
}

// ---------------------------------------------------------------------------
// 9. Hosted per-purl revert failure fails closed (remove.rs:694-703 main
//    flow; 1152-1159 hosted-only twin)
// ---------------------------------------------------------------------------

/// A package-lock.json that is no longer valid JSON makes the recorded
/// `redirect_npm_lock_entry` revert fail — the remove must abort with
/// `hosted_revert_failed` BEFORE the manifest mutation, leaving every
/// store byte-identical.
#[test]
fn remove_hosted_revert_failure_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, "{corrupt lock").unwrap();
    let lock_before = read_bytes(&lock_path);
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let ledger_before = read_bytes(&ledger_path);
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
    let manifest_before = read_bytes(&socket.join("manifest.json"));

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "a failed hosted revert must abort the remove; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "hosted_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains("could not unwind hosted redirect for pkg:npm/left-pad@1.3.0")
            && msg.contains("The manifest was not modified."),
        "the error must name the purl and promise the manifest is intact; got: {msg}"
    );
    assert_eq!(v["summary"]["removed"], 0);

    // Fail-closed: manifest, ledger, and (corrupt) lock all byte-identical.
    assert_eq!(read_bytes(&socket.join("manifest.json")), manifest_before);
    assert_eq!(read_bytes(&ledger_path), ledger_before);
    assert_eq!(read_bytes(&lock_path), lock_before);
}

/// Hosted-only twin: the same corrupt-lock failure surfaces through
/// `remove_hosted_only`'s failed-revert branch.
#[test]
fn remove_hosted_only_revert_failure_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, "{corrupt lock").unwrap();
    let lock_before = read_bytes(&lock_path);
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "hosted_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains("could not unwind hosted redirect for pkg:npm/left-pad@1.3.0"),
        "the error must name the purl; got: {msg}"
    );
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger untouched");
    assert_eq!(read_bytes(&lock_path), lock_before, "corrupt lock untouched");
}

// ---------------------------------------------------------------------------
// 10. Hosted ledger persist failure after successful lockfile reverts
//     (remove.rs:669-675 main flow; 1122-1128 hosted-only). Unix-only.
// ---------------------------------------------------------------------------

/// The per-purl reverts flush lockfile writes as they go; when the ledger
/// persist then fails, the remove must abort with `hosted_revert_failed`
/// naming the persist — the manifest untouched, the (stale) ledger still
/// on disk, and the lock already restored (the documented desync posture).
#[cfg(unix)]
#[test]
fn remove_hosted_ledger_persist_failure_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let ledger_before = read_bytes(&ledger_path);
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let vendor = tmp.path().join(".socket/vendor");

    chmod(&vendor, 0o555);
    let _mode = ModeGuard(vendor.clone());
    if !readonly_dir_enforced(&vendor) {
        return;
    }
    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--json", "--yes", "--offline"], &[]);

    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "hosted_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains("failed to persist the hosted redirect ledger"),
        "the error must name the persist failure; got: {msg}"
    );
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "the manifest mutation must not have happened"
    );
    assert_eq!(
        read_bytes(&ledger_path),
        ledger_before,
        "the unwritable ledger keeps its old bytes"
    );
    // The lockfile edits flushed BEFORE the persist (the documented
    // desync-avoidance ordering): the lock is already restored.
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_reverted_lock_text(),
        "the per-purl revert flushed the lock before the persist failed"
    );
}

/// Hosted-only twin of the persist failure.
#[cfg(unix)]
#[test]
fn remove_hosted_only_ledger_persist_failure_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
    let ledger_before = read_bytes(&ledger_path);
    let vendor = tmp.path().join(".socket/vendor");

    chmod(&vendor, 0o555);
    let _mode = ModeGuard(vendor.clone());
    if !readonly_dir_enforced(&vendor) {
        return;
    }
    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--json", "--yes", "--offline"], &[]);

    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "hosted_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains("failed to persist the hosted redirect ledger"),
        "the error must name the persist failure; got: {msg}"
    );
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger keeps its old bytes");
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_reverted_lock_text(),
        "the per-purl revert flushed the lock before the persist failed"
    );
}

// ---------------------------------------------------------------------------
// 11. Drift-keep exclusion arms (remove.rs:741-745) + mixed partial
//     failure (remove.rs:1009, 1022-1031)
// ---------------------------------------------------------------------------

const MIXED_UUID: &str = "88888888-8888-4888-8888-888888888888";
const MIXED_KEPT_PURL: &str = "pkg:npm/__covgap_dk_kept__@1.0.0";
const MIXED_REMOVED_PURL: &str = "pkg:npm/__covgap_dk_removed__@2.0.0";

/// Two manifest entries sharing one patch uuid — the only identifier shape
/// that matches BOTH while the drift-keep exclusion set covers only one —
/// plus a drift-keeping vendored ledger entry for the first.
fn make_mixed_drift_fixture(root: &Path) -> PathBuf {
    let socket = write_two_entry_manifest(
        root,
        MIXED_KEPT_PURL,
        MIXED_UUID,
        MIXED_REMOVED_PURL,
        MIXED_UUID,
    );
    write_vendor_ledger_entry(
        root,
        MIXED_KEPT_PURL,
        MIXED_KEPT_PURL,
        MIXED_UUID,
        DRIFTED_WIRING,
        "",
    );
    socket
}

/// The MIXED drift-keep outcome — some entries kept, some removed — had
/// never run in any mode. JSON contract: `status: partialFailure` with NO
/// top-level error (the removal partially happened), `summary.removed`
/// honest at 1, exit 1; the kept purl's manifest entry and ledger entry
/// survive while the sibling is deleted.
#[test]
fn remove_mixed_drift_keep_is_partial_failure_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_mixed_drift_fixture(tmp.path());
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[MIXED_UUID, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "a partially drift-kept remove must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "envelope={v}");
    assert!(
        v["error"].is_null(),
        "the mixed outcome carries no top-level error (part of the removal \
         DID happen); envelope={v}"
    );
    assert_eq!(
        v["summary"]["removed"], 1,
        "exactly the non-kept sibling was removed; envelope={v}"
    );
    assert_eq!(
        event_purls(&v, "removed"),
        vec![MIXED_REMOVED_PURL],
        "the removed event must name the sibling; envelope={v}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "skipped"
            && e["errorCode"] == "vendor_revert_kept"
            && e["purl"] == MIXED_KEPT_PURL),
        "expected a skipped/vendor_revert_kept event for the kept purl: {events:?}"
    );

    // The kept purl's manifest entry and ledger entry survive; the sibling
    // is gone from the manifest.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    let patches = manifest["patches"].as_object().expect("patches object");
    assert!(
        patches.contains_key(MIXED_KEPT_PURL),
        "the drift-kept purl's manifest entry must survive; got: {patches:?}"
    );
    assert!(
        !patches.contains_key(MIXED_REMOVED_PURL),
        "the sibling's manifest entry must be removed; got: {patches:?}"
    );
    assert_eq!(
        read_bytes(&ledger_path),
        ledger_before,
        "the drift-kept ledger entry must survive byte-for-byte"
    );
}

/// Human twin: exit 1 plus the singular drift-keep error line on stderr
/// (the count + pluralization surface at remove.rs:1022-1030).
#[test]
fn remove_mixed_drift_keep_is_partial_failure_human() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_mixed_drift_fixture(tmp.path());

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[MIXED_UUID, "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("1 matching entry was drift-kept"),
        "the singular drift-keep error line must reach stderr; got:\n{stderr}"
    );
    assert!(
        stderr.contains("re-run `scan --mode vendored`"),
        "the error must carry the normalize remedy; got:\n{stderr}"
    );
    assert!(
        stdout.contains("Removed 1 patch(es) from manifest:"),
        "the partial removal must still report; got:\n{stdout}"
    );
}

/// Qualifier-stripped exclusion arm (remove.rs:741): a drift-kept ledger
/// key for ONE release variant keeps the manifest entries of ALL sibling
/// variants of that package@version (vendored state is per-package, so
/// dropping a sibling's record would strand the surviving vendored state).
#[test]
fn remove_drift_keep_excludes_sibling_variants_by_stripped_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sdist = "pkg:pypi/__covgap_six__@1.16.0?artifact_id=sdist";
    let wheel = "pkg:pypi/__covgap_six__@1.16.0?artifact_id=wheel";
    let base = "pkg:pypi/__covgap_six__@1.16.0";
    let socket = write_two_entry_manifest(
        tmp.path(),
        sdist,
        "99999999-9999-4999-8999-999999999999",
        wheel,
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    );
    // The ledger key is the sdist purl (the qualified manifest key); its
    // strip matches BOTH variants' strips.
    write_vendor_ledger_entry(
        tmp.path(),
        sdist,
        base,
        "99999999-9999-4999-8999-999999999999",
        DRIFTED_WIRING,
        "",
    );
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[base, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "an all-kept remove is a partial failure; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "envelope={v}");
    assert_eq!(v["error"]["code"], "vendor_revert_kept", "envelope={v}");
    assert_eq!(v["summary"]["removed"], 0);

    // THE point: the wheel variant — whose own ledger entry doesn't exist —
    // is excluded via the qualifier-stripped arm, so the manifest survives
    // byte-for-byte (fail-closed sibling keep), as does the ledger.
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "BOTH variants' manifest entries must survive the drift-keep"
    );
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger byte-identical");
}

/// Base-purl exclusion arm (remove.rs:742-745, and the base_purl match arm
/// of vendor_entries_matching at remove.rs:44): a drift-kept ledger entry
/// whose KEY differs from the manifest purl but whose `basePurl` resolves
/// to it still keeps the manifest entry.
#[test]
fn remove_drift_keep_excludes_manifest_entry_by_base_purl() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = "pkg:npm/__covgap_dk_target__@1.0.0";
    let alias_key = "pkg:npm/__covgap_dk_alias__@1.0.0";
    let uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let socket = write_manifest_files_empty(tmp.path(), target, uuid);
    // Ledger entry keyed by a DIFFERENT purl, resolving to the manifest
    // purl through basePurl (the golang case-encoded shape, npm-flavored
    // here so the drift-keep wiring trick applies).
    write_vendor_ledger_entry(tmp.path(), alias_key, target, uuid, DRIFTED_WIRING, "");
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[target, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "envelope={v}");
    assert_eq!(v["error"]["code"], "vendor_revert_kept", "envelope={v}");
    assert_eq!(v["summary"]["removed"], 0);
    // The kept event names the LEDGER key (the base_purl arm matched it).
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "skipped"
            && e["errorCode"] == "vendor_revert_kept"
            && e["purl"] == alias_key),
        "expected the kept event to carry the ledger key: {events:?}"
    );
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "the base-purl-matched manifest entry must survive"
    );
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger byte-identical");
}

// ---------------------------------------------------------------------------
// 12. Detached entry matched by base_purl only (remove.rs:44): the golang
//     case-encoded ledger key, whose decoded basePurl is what users type.
// ---------------------------------------------------------------------------

/// A golang ledger key carries the module path case-ENCODED
/// (`!burnt!sushi`) while `basePurl` holds the decoded form users type;
/// `purl_eq` does not decode `!x` escaping, so only the base_purl arm can
/// match. The dry-run preview proves the match end-to-end without needing
/// a working golang revert.
#[test]
fn remove_matches_detached_entry_by_base_purl() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let encoded_key = "pkg:golang/github.com/!burnt!sushi/toml@v1.2.1";
    let decoded = "pkg:golang/github.com/BurntSushi/toml@v1.2.1";
    let uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    // Minimal valid go.mod: the golang revert's go.mod edit (a dry-run
    // no-op here — no replace directive to drop) requires the file.
    std::fs::write(
        tmp.path().join("go.mod"),
        "module example.com/covgap-fixture\n\ngo 1.21\n",
    )
    .unwrap();
    let go_mod_before = read_bytes(&tmp.path().join("go.mod"));

    let vendor = tmp.path().join(".socket/vendor");
    let artifact_dir = vendor.join("golang").join(uuid);
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("module.zip"), b"zip").unwrap();
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{encoded_key}": {{
      "ecosystem": "golang",
      "basePurl": "{decoded}",
      "uuid": "{uuid}",
      "detached": true,
      "artifact": {{ "path": ".socket/vendor/golang/{uuid}/module.zip" }},
      "wiring": []
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).unwrap();
    let ledger_before = read_bytes(&vendor.join("state.json"));

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[decoded, "--json", "--offline", "--dry-run"],
        &[],
    );
    assert_eq!(
        code, 0,
        "the decoded identifier must match through basePurl; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["dryRun"], true);
    assert_eq!(
        v["summary"]["verified"], 1,
        "the preview must count the matched detached entry; envelope={v}"
    );
    // The event carries the LEDGER key (the encoded spelling).
    assert_eq!(
        event_purls(&v, "verified"),
        vec![encoded_key],
        "the preview event must name the encoded ledger key; envelope={v}"
    );
    // Nothing moved.
    assert_eq!(read_bytes(&vendor.join("state.json")), ledger_before);
    assert_eq!(read_bytes(&tmp.path().join("go.mod")), go_mod_before);
    assert!(artifact_dir.join("module.zip").exists());
}

// ---------------------------------------------------------------------------
// 13. Detached-only --skip-rollback refusal (remove.rs:1194-1204)
// ---------------------------------------------------------------------------

/// With no manifest entry to delete, removing a detached vendored patch
/// can only mean reverting its vendoring — `--skip-rollback` is refused
/// with `vendor_state_retained` and the ledger is untouched.
#[test]
fn remove_detached_skip_rollback_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_detskip__@1.0.0";
    let uuid = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    let artifact_dir =
        write_vendor_ledger_entry(tmp.path(), purl, purl, uuid, "[]", "\"detached\": true,\n      ");
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[purl, "--json", "--yes", "--offline", "--skip-rollback"],
        &[],
    );
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "vendor_state_retained", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains(purl) && msg.contains("--skip-rollback"),
        "the refusal must name the purl and the flag; got: {msg}"
    );
    assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger untouched");
    assert!(artifact_dir.join("package.tgz").exists(), "artifact untouched");
}

// ---------------------------------------------------------------------------
// 14. Human-mode output surfaces (remove.rs:319-324, 421, 559, 579,
//     809-813)
// ---------------------------------------------------------------------------

/// A base PURL expanding to multiple manifest entries must make the blast
/// radius explicit on stderr before removing all of them.
#[test]
fn remove_multi_variant_blast_radius_prints_expansion() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sdist = "pkg:pypi/__covgap_blast__@1.0.0?artifact_id=sdist";
    let wheel = "pkg:pypi/__covgap_blast__@1.0.0?artifact_id=wheel";
    let base = "pkg:pypi/__covgap_blast__@1.0.0";
    let socket = write_two_entry_manifest(
        tmp.path(),
        sdist,
        "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        wheel,
        "ffffffff-ffff-4fff-8fff-ffffffffffff",
    );

    let (code, stdout, stderr) = run_remove(tmp.path(), &[base, "--yes", "--offline"], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains(&format!("{base} matches 2 release variant(s) — all will be removed:")),
        "the blast-radius line must reach stderr; got:\n{stderr}"
    );
    assert!(
        stdout.contains("Removed 2 patch(es) from manifest:"),
        "both variants must be removed; got:\n{stdout}"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "both variants must be gone from the manifest"
    );
}

/// The "already in original state" count line (remove.rs:421): an entry
/// whose installed file is already at its original bytes rolls back as
/// already-original, and the human run must say so. (JSON twin lives in
/// remove_invariants.rs; the human surface was never exercised.)
#[test]
fn remove_already_original_human_prints_count_line() {
    let original = b"covgap original bytes\n";
    let before_hash = common::git_sha256(original);
    let after_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let purl = "pkg:npm/__covgap_already__@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/a.js": {{ "beforeHash": "{before_hash}", "afterHash": "{after_hash}" }}
      }},
      "vulnerabilities": {{}},
      "description": "covgap already-original patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    common::write_blob(&socket, &before_hash, original);

    // Installed at the BEFORE bytes: rollback verifies already-original.
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "covgap-already-root", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg_dir = tmp.path().join("node_modules/__covgap_already__");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "__covgap_already__", "version": "1.0.0" }"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("a.js"), original).unwrap();

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--yes", "--offline"], &[]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("1 package(s) already in original state"),
        "the already-original count line must print; got:\n{stdout}"
    );
    assert!(
        stdout.contains("Removed 1 patch(es) from manifest:"),
        "the removal must still report; got:\n{stdout}"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "the entry must be removed"
    );
}

/// Wet `--preserve-state` on a vendored entry, human mode: the per-key
/// "Unwired vendoring … (artifact preserved)" line (remove.rs:579) plus
/// the final preserve summary (809-813), with all state kept.
#[test]
fn remove_preserve_state_vendored_human_wet_surfaces() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_pv__@1.0.0";
    let uuid = "12121212-1212-4121-8121-121212121212";
    let socket = write_manifest_files_empty(tmp.path(), purl, uuid);
    let artifact_dir = write_vendor_ledger_entry(tmp.path(), purl, purl, uuid, "[]", "");
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[purl, "--yes", "--offline", "--preserve-state"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!("Unwired vendoring for {purl} (artifact preserved)")),
        "the per-key preserve line must print; got:\n{stdout}"
    );
    assert!(
        stdout.contains("Manifest entries and vendored artifacts preserved"),
        "the preserve summary must print; got:\n{stdout}"
    );
    // All state kept: manifest, ledger, artifact.
    assert_eq!(read_bytes(&socket.join("manifest.json")), manifest_before);
    assert_eq!(read_bytes(&ledger_path), ledger_before);
    assert!(artifact_dir.join("package.tgz").exists());
}

/// Dry-run `--preserve-state` twin: the "Would unwire vendoring …
/// (artifact preserved)" preview line (remove.rs:559), nothing mutated.
#[test]
fn remove_preserve_state_vendored_human_dry_run_previews() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_pv__@1.0.0";
    let uuid = "12121212-1212-4121-8121-121212121212";
    let socket = write_manifest_files_empty(tmp.path(), purl, uuid);
    let artifact_dir = write_vendor_ledger_entry(tmp.path(), purl, purl, uuid, "[]", "");
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[purl, "--yes", "--offline", "--preserve-state", "--dry-run"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!("Would unwire vendoring for {purl} (artifact preserved)")),
        "the dry-run preserve preview must print; got:\n{stdout}"
    );
    assert_eq!(read_bytes(&socket.join("manifest.json")), manifest_before);
    assert_eq!(read_bytes(&ledger_path), ledger_before);
    assert!(artifact_dir.join("package.tgz").exists());
}

// ---------------------------------------------------------------------------
// 15. Blob/archive cleanup failures warn, never fatal (remove.rs:887-891,
//     905-908)
// ---------------------------------------------------------------------------

/// Plant `.socket/blobs`, `.socket/diffs`, `.socket/packages` as regular
/// FILES so every cleanup read_dir errors: the remove must still succeed
/// (repair's posture: warn and continue, never fatal), with one stderr
/// warning per store.
#[test]
fn remove_cleanup_failures_warn_not_fatal() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_cleanup__@1.0.0";
    let socket = write_manifest_files_empty(tmp.path(), purl, "13131313-1313-4131-8131-131313131313");
    for name in ["blobs", "diffs", "packages"] {
        std::fs::write(socket.join(name), b"not a directory").unwrap();
    }

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--yes", "--skip-rollback"], &[]);
    assert_eq!(
        code, 0,
        "cleanup failures must never fail the remove; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Removed 1 patch(es) from manifest:"),
        "the removal must succeed; got:\n{stdout}"
    );
    assert!(
        stderr.contains("Warning: blob cleanup failed"),
        "the blob-sweep failure must warn; got:\n{stderr}"
    );
    assert!(
        stderr.contains("Warning: diffs cleanup failed"),
        "the diffs-sweep failure must warn; got:\n{stderr}"
    );
    assert!(
        stderr.contains("Warning: packages cleanup failed"),
        "the packages-sweep failure must warn; got:\n{stderr}"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "the entry must be removed despite the cleanup failures"
    );
}

// ---------------------------------------------------------------------------
// 16. rollback_patches Err(String) plumbing (remove.rs:429-437) — distinct
//     from the covered Ok(success=false) gate abort.
// ---------------------------------------------------------------------------

/// `.socket/blobs` planted as a regular FILE makes the wet rollback's
/// `create_dir_all(blobs_path)` fail (an infrastructure `Err`, not the
/// before-blob gate's Ok(success=false)): remove must surface it as
/// `rollback_failed` with the "Error during rollback:" prefix and leave
/// the manifest untouched. The package must be installed off its original
/// bytes so the rollback has in-place work (the dir is created lazily).
#[test]
fn remove_rollback_infrastructure_error_surfaces_rollback_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_rberr__@1.0.0";
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "14141414-1414-4141-8141-141414141414",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/a.js": {{
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "covgap rollback-err patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    // blobs as a regular FILE: create_dir_all errors on a wet rollback.
    std::fs::write(socket.join("blobs"), b"not a directory").unwrap();

    // Installed with a.js off both hashes: genuine in-place restore work.
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "covgap-rberr-root", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg_dir = tmp.path().join("node_modules/__covgap_rberr__");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "__covgap_rberr__", "version": "1.0.0" }"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("a.js"), b"patched-ish content\n").unwrap();

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--json", "--yes", "--offline"], &[]);
    assert_eq!(
        code, 1,
        "a rollback infrastructure error must abort remove; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "rollback_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.starts_with("Error during rollback:"),
        "the Err branch's message prefix must surface (distinct from the \
         gate's 'Rollback failed during patch removal'); got: {msg}"
    );
    assert!(
        msg.contains("--skip-rollback"),
        "the message must suggest the escape hatch; got: {msg}"
    );
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "a failed rollback must leave the manifest untouched"
    );
}

// ---------------------------------------------------------------------------
// 17. Hosted-only interactive decline (remove.rs:1092-1095) — PTY-driven
//     (the non-TTY confirm auto-proceeds, so only a real terminal reaches
//     the cancel branch). Runner copied from interactive_prompts_e2e.rs
//     (do not edit that file).
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod pty {
    use super::*;
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};
    use std::time::Duration;

    fn binary() -> PathBuf {
        env!("CARGO_BIN_EXE_socket-patch").into()
    }

    /// Spawn the binary inside a PTY, send `input`, collect all output
    /// until exit (watchdog-killed after `timeout`).
    fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");

        let mut cmd = CommandBuilder::new(binary());
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);
        // Scrub the ambient SOCKET_* surface (SOCKET_YES would skip the
        // very prompt this test drives); keep telemetry opt-outs.
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
        cmd.env("SOCKET_NO_CONFIG", "1");
        cmd.env("SOCKET_NO_UPDATE_CHECK", "1");
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1");

        let mut child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("clone reader");
        let reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = reader.read_to_end(&mut buf);
            buf
        });

        let mut killer = child.clone_killer();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = killer.kill();
        });

        let mut writer = pair.master.take_writer().expect("take writer");
        let _ = writer.write_all(input.as_bytes());
        let _ = writer.flush();
        drop(writer);

        let status = child.wait().expect("child.wait");
        drop(pair.master);
        let output = reader_handle.join().expect("reader thread join");
        (status.exit_code() as i32, String::from_utf8_lossy(&output).to_string())
    }

    /// Declining the hosted-only confirm prompt must cancel cleanly (exit
    /// 0, "Removal cancelled.") with the lock and ledger byte-identical.
    #[test]
    fn remove_hosted_only_interactive_n_cancels() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lock_path = tmp.path().join("package-lock.json");
        std::fs::write(&lock_path, redirected_lock_text()).unwrap();
        let ledger_path = write_redirect_ledger_text(tmp.path(), &npm_redirect_ledger_text());
        let ledger_before = read_bytes(&ledger_path);
        let lock_before = read_bytes(&lock_path);

        let (code, output) = run_in_pty(
            &["remove", NPM_PURL],
            tmp.path(),
            "n\n",
            Duration::from_secs(15),
        );
        assert_eq!(code, 0, "declined hosted remove must exit cleanly; got: {output}");
        // Vacuity guard: the hosted-only confirm prompt MUST have run.
        assert!(
            output.contains("Remove 1 hosted redirect(s) and unwind their lockfile wiring?"),
            "the hosted-only confirm prompt must have shown; got: {output}"
        );
        assert!(
            !output.contains("Non-interactive mode"),
            "must NOT have taken the non-interactive branch in a PTY; got: {output}"
        );
        assert!(
            output.contains("Removal cancelled"),
            "'n' must report cancellation; got: {output}"
        );
        // Declined: nothing moved.
        assert_eq!(read_bytes(&ledger_path), ledger_before, "ledger untouched");
        assert_eq!(read_bytes(&lock_path), lock_before, "lock untouched");
    }
}
