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
//! The hosted leg is covered on both paths: through a manifest entry, and
//! manifest-less via `remove_hosted_only` (CLI_CONTRACT.md: "a hosted-only
//! match works with no manifest at all").

use std::path::{Path, PathBuf};

use crate::common;

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
    let body =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
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

/// Removing one patch must not collect another active patch's only local
/// rollback data (#559). Exercise both commands against the same lifecycle.
#[test]
fn scoped_removal_preserves_other_patches_for_offline_rollback() {
    for (command, skip_rollback) in [("remove", false), ("remove", true), ("rollback", false)] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let (socket, before_hash, after_hash) = make_preserve_fixture(root);
        let other_purl = "pkg:npm/other-patch@1.0.0";
        let original = b"other original\n";
        let patched = b"other patched\n";
        let other_before = common::git_sha256(original);
        let other_after = common::git_sha256(patched);
        let mut manifest = read_manifest(&socket);
        let mut record = manifest["patches"][PRESERVE_PURL].clone();
        record["uuid"] = serde_json::json!("88888888-8888-4888-8888-888888888888");
        record["files"]["package/a.js"] = serde_json::json!({
            "beforeHash": other_before, "afterHash": other_after,
        });
        manifest["patches"][other_purl] = record.clone();
        std::fs::write(
            socket.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let package = root.join("node_modules/other-patch");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join("package.json"),
            r#"{"name":"other-patch","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(package.join("a.js"), patched).unwrap();
        std::fs::write(socket.join("blobs").join(&other_before), original).unwrap();
        std::fs::write(socket.join("blobs").join(&other_after), patched).unwrap();

        let mut args = vec![command, PRESERVE_PURL, "--json", "--yes", "--offline"];
        if skip_rollback {
            args.push("--skip-rollback");
        }
        let (code, stdout, stderr) = common::run_with_env(root, &args, &[]);
        assert_eq!(code, 0, "{command}: {stdout}\n{stderr}");
        let remaining = read_manifest(&socket);
        assert_eq!(remaining["patches"].as_object().unwrap().len(), 1);
        assert_eq!(remaining["patches"][other_purl], record);
        assert_eq!(std::fs::read(package.join("a.js")).unwrap(), patched);
        assert!(!socket.join("blobs").join(&before_hash).exists());
        assert!(!socket.join("blobs").join(&after_hash).exists());
        assert!(socket.join("blobs").join(&other_after).exists());
        assert!(
            socket.join("blobs").join(&other_before).exists(),
            "{command} swept the remaining patch's rollback data"
        );

        let (code, stdout, stderr) =
            common::run_with_env(root, &["rollback", other_purl, "--json", "--offline"], &[]);
        assert_eq!(
            code, 0,
            "offline rollback after {command}: {stdout}\n{stderr}"
        );
        assert_eq!(std::fs::read(package.join("a.js")).unwrap(), original);
        assert!(read_manifest(&socket)["patches"]
            .as_object()
            .unwrap()
            .is_empty());
        assert!(!socket.join("blobs").exists());
    }
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
        &[
            PRESERVE_PURL,
            "--json",
            "--yes",
            "--offline",
            "--preserve-state",
        ],
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

/// The default cleanup now covers `.socket/diffs` (`<uuid>.tar.gz`, kept iff
/// the uuid is still referenced by the post-removal manifest) and the legacy
/// `.socket/packages` (swept whole: v5.0 reads no package archives) in
/// addition to blobs. Removing A must sweep A's diff archive while B's —
/// still referenced by the second manifest entry — survives, and both
/// package archives go; the artifact carrier reports the count.
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
        &[
            "pkg:npm/__archive_a__@1.0.0",
            "--json",
            "--yes",
            "--skip-rollback",
        ],
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

    // A's archives are gone from BOTH archive dirs; B's diff archive
    // survives, its legacy package archive does not.
    for dir in ["diffs", "packages"] {
        assert!(
            !socket
                .join(dir)
                .join(format!("{ARCH_UUID_A}.tar.gz"))
                .exists(),
            "the removed entry's {dir} archive must be swept"
        );
    }
    assert!(
        socket
            .join("diffs")
            .join(format!("{ARCH_UUID_B}.tar.gz"))
            .exists(),
        "the kept entry's diff archive must survive"
    );
    assert!(
        !socket
            .join("packages")
            .join(format!("{ARCH_UUID_B}.tar.gz"))
            .exists(),
        "a legacy package archive is swept even for a kept entry"
    );

    // The purl-less artifact carrier reports the three swept archives.
    let events = v["events"].as_array().expect("events array");
    let carrier = events
        .iter()
        .find(|e| e["action"] == "removed" && e["purl"].is_null())
        .unwrap_or_else(|| panic!("expected the artifact carrier event: {events:?}"));
    assert_eq!(
        carrier["details"]["archivesRemoved"], 3,
        "one diff + two package archives swept; carrier={carrier}"
    );

    // The keep-rule really is manifest-anchored: B's entry survives.
    let manifest = read_manifest(&socket);
    assert!(manifest["patches"]["pkg:npm/__archive_b__@2.0.0"].is_object());
}

// ---------------------------------------------------------------------------
// 4. Hosted-redirect leg
//
// v5 hosted state is the lockfile pin itself (no ledger): removing a hosted
// patch restores the pin's DEFAULT UPSTREAM registry entry, re-resolved
// from a mock npm registry (`SOCKET_NPM_REGISTRY`).
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

/// The exact bytes the upstream restore writes for [`redirected_lock_text`]:
/// parse the fixture, put the registry's resolved/integrity back, serialize
/// with the workspace's preserve_order serde_json + trailing newline. This
/// pins the WHOLE file, not just the two fields.
fn upstream_lock_text() -> String {
    let mut expected: serde_json::Value = serde_json::from_str(&redirected_lock_text()).unwrap();
    let entry = expected["packages"]["node_modules/left-pad"]
        .as_object_mut()
        .expect("lock entry object");
    entry.insert("resolved".into(), serde_json::json!(ORIG_RESOLVED));
    entry.insert("integrity".into(), serde_json::json!(ORIG_INTEGRITY));
    format!("{}\n", serde_json::to_string_pretty(&expected).unwrap())
}

/// A mock npm registry serving left-pad@1.3.0's version document `dist`.
/// wiremock serves from its own thread; the runtime only owns the server.
struct NpmRegistry {
    server: wiremock::MockServer,
    _rt: tokio::runtime::Runtime,
}

impl NpmRegistry {
    fn start(dist: serde_json::Value) -> Self {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let server = rt.block_on(async {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/npm/left-pad/1.3.0"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "name": "left-pad",
                    "version": "1.3.0",
                    "dist": dist,
                })))
                .mount(&server)
                .await;
            server
        });
        Self { server, _rt: rt }
    }

    /// The registry's real entry for the fixture package.
    fn upstream() -> Self {
        Self::start(serde_json::json!({ "tarball": ORIG_RESOLVED, "integrity": ORIG_INTEGRITY }))
    }

    fn env(&self) -> String {
        format!("{}/npm", self.server.uri())
    }
}

/// A PRE-V5 redirect ledger (v5 never writes one): one npm record and its
/// recorded `redirect_npm_lock_entry` edit matching
/// [`redirected_lock_text`], its recorded original deliberately DIFFERENT
/// from the registry's entry (a replay would write it; the restore must
/// not).
fn legacy_npm_redirect_ledger_text() -> String {
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
      "original": {{ "resolved": "{ORIG_RESOLVED}", "integrity": "sha512-LEDGERledger==" }},
      "new": {{ "resolved": "{HOSTED_RESOLVED}", "integrity": "{HOSTED_INTEGRITY}" }}
    }}
  ],
  "records": {{
    "{NPM_PURL}": {{
      "uuid": "{NPM_UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "synthetic hosted npm patch",
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

/// Hosted-only remove with no manifest at all (a hosted-only project's
/// per-purl exit path): the lockfile pin is restored to the upstream
/// registry entry, and the restore IS the removal, so the
/// `hosted_reverted` event counts toward `summary.removed` (the
/// detached-vendored convention). No ledger is involved, and no `.socket/`
/// state is left behind.
#[test]
fn hosted_only_remove_without_manifest_restores_upstream() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let registry = NpmRegistry::upstream();

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[NPM_PURL, "--json", "--yes"],
        &[("SOCKET_NPM_REGISTRY", &registry.env())],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(
        v["summary"]["removed"], 1,
        "the hosted restore IS the removal on this path; envelope={v}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "removed"
            && e["purl"] == NPM_PURL
            && e["errorCode"] == "hosted_reverted"),
        "removed/hosted_reverted event expected; envelope={v}"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        upstream_lock_text(),
        "the lock must hold exactly the upstream registry entry"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "no manifest (or ledger) may be materialized as a side effect"
    );
}

/// The hosted leg on the manifest path: the identifier matches a manifest
/// entry AND the lockfile's hosted pin for the same purl. The remove
/// restores the pin's upstream entry byte-exactly — from the REGISTRY, not
/// from a pre-v5 ledger left beside it (whose recorded original differs),
/// which is retired once no hosted pin remains — and the envelope carries
/// the `hosted_reverted` event alongside the per-purl manifest removal.
#[test]
fn hosted_remove_with_manifest_entry_restores_upstream() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(tmp.path(), &legacy_npm_redirect_ledger_text());
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
    let registry = NpmRegistry::upstream();

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[NPM_PURL, "--json", "--yes"],
        &[("SOCKET_NPM_REGISTRY", &registry.env())],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(
        v["summary"]["removed"], 1,
        "the hosted_reverted event must not inflate the manifest-entry count"
    );

    let restored = std::fs::read_to_string(&lock_path).unwrap();
    assert_eq!(
        restored,
        upstream_lock_text(),
        "the lock must hold exactly the upstream registry entry"
    );
    assert!(
        !restored.contains(NPM_UUID) && !restored.contains("LEDGER"),
        "no hosted URL survives, and the ledger's recorded original was never replayed"
    );
    assert!(
        !ledger_path.exists(),
        "the pre-v5 ledger is retired once no hosted pin remains; envelope={v}"
    );

    // Envelope: the hosted restore event plus the plain per-purl removal.
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
// 5. A hosted pin the upstream restore refuses fails closed
// ---------------------------------------------------------------------------

/// With a manifest entry for the purl (the manifest path; the
/// manifest-less twin is below), a pin whose upstream entry cannot be
/// re-derived (the registry records no integrity for it) fails closed
/// BEFORE the manifest mutation: exit 1, top-level `hosted_revert_failed`
/// naming the `git checkout` remedy, and the lock + manifest
/// byte-identical.
#[test]
fn hosted_refused_restore_remove_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let lock_before = std::fs::read(&lock_path).unwrap();
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
    let manifest_before = std::fs::read(socket.join("manifest.json")).unwrap();
    let registry = NpmRegistry::start(serde_json::json!({ "tarball": ORIG_RESOLVED }));

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[NPM_PURL, "--json", "--yes"],
        &[("SOCKET_NPM_REGISTRY", &registry.env())],
    );
    assert_eq!(
        code, 1,
        "a refused hosted restore must fail; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "hosted_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().expect("message string");
    assert!(
        msg.contains(&format!(
            "cannot restore {NPM_PURL} to its upstream registry entry"
        )) && msg.contains("the registry records no integrity")
            && msg.contains("git checkout -- package-lock.json")
            && msg.contains("The manifest was not modified."),
        "the error must name the purl, the cause and the remedy; got {msg}"
    );
    assert_eq!(v["summary"]["removed"], 0);

    // Fail-closed: lock AND manifest byte-identical.
    assert_eq!(std::fs::read(&lock_path).unwrap(), lock_before);
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).unwrap(),
        manifest_before,
        "the manifest was not modified (the error message promises it)"
    );
}

/// Manifest-less twin of the refusal: the identifier reaches the
/// hosted-only removal path, where an `--offline` run cannot re-resolve the
/// upstream entry — fail closed with `hosted_revert_failed`, the lock
/// untouched and no `.socket/` state written.
#[test]
fn hosted_only_refused_restore_remove_without_manifest_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let lock_before = std::fs::read(&lock_path).unwrap();

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[NPM_PURL, "--json", "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "error", "envelope={v}");
    assert_eq!(v["error"]["code"], "hosted_revert_failed", "envelope={v}");
    let msg = v["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains(NPM_PURL)
            && msg.contains("this run is offline")
            && msg.contains("git checkout -- package-lock.json"),
        "the refusal names the purl, the cause and the remedy; envelope={v}"
    );
    assert_eq!(
        std::fs::read(&lock_path).unwrap(),
        lock_before,
        "the lock must be unchanged"
    );
    assert!(!tmp.path().join(".socket").exists(), "nothing written");
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

use crate::vlt_hosted_common;
use crate::vlt_vendored;

/// `remove --preserve-state` of a vlt-vendored purl restores the registry
/// lock and package.json but keeps the directory artifact and the ledger
/// entry (byte-identical).
#[test]
fn remove_preserve_state_unwires_a_vlt_entry_and_keeps_the_artifact() {
    use vlt_hosted_common as hosted;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vlt_vendored::vendored_project(root, true);
    let state = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
    let cwd = root.to_str().unwrap().to_string();
    let (code, v, stderr) = hosted::run_json(
        root,
        &[
            "remove",
            hosted::PURL,
            "--preserve-state",
            "--offline",
            "--cwd",
            &cwd,
        ],
        &[],
    );
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    assert_eq!(
        hosted::read(root, "vlt-lock.json"),
        vlt_vendored::registry_lock()
    );
    assert_eq!(
        hosted::read(root, "package.json"),
        vlt_vendored::PACKAGE_JSON
    );
    assert!(root.join(vlt_vendored::rel()).join("index.js").is_file());
    assert_eq!(
        std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
        state
    );
}
