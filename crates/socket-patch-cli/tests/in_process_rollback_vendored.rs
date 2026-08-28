//! In-process rollback tests over a VENDORED npm fixture — the vendored leg
//! of the v5.0 scan↔rollback duality (CLI_CONTRACT.md "Rollback command
//! contract (v5.0)"):
//!
//!   * `--preserve-state` unwires the lockfile but keeps the artifact, the
//!     ledger entry (byte-identical — R6: wiring records intact), and the
//!     manifest entry, and skips GC;
//!   * a re-vendor after a preserve-rollback re-wires from the LIVE lock
//!     (the in-sync probe regression);
//!   * a drift-keep (wiring fragments matching nothing in the lock) exits
//!     partial_failure and holds BOTH the ledger entry and the manifest
//!     entry;
//!   * detached ledger entries are reverted by the unscoped default run.
//!
//! Fixture and conventions are copied from `in_process_vendor.rs`: the
//! lifecycle steps call `commands::vendor::run` / `commands::rollback::run`
//! in-process and assert exit codes + on-disk post-state; every assertion
//! that needs the JSON envelope goes through the built binary
//! (`CARGO_BIN_EXE_socket-patch`) with a scrubbed `SOCKET_*` child env.
//!
//! Hermeticity: each fixture stages its patch blob under `.socket/blobs/`
//! and runs with `--offline`, so nothing touches the network. No test
//! mutates this process's environment (the in-process runs only mirror
//! `--offline` INTO the env, which every test here wants anyway), so none
//! need `#[serial]` — each runs in its own tempdir.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};
use socket_patch_cli::commands::vendor::{run as vendor_run, VendorArgs};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

/// Canonical-grammar patch UUID — the vendor path layer validates the uuid
/// path level fail-closed, so fixtures must use the real shape.
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
const REG_RESOLVED: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
const REG_INTEGRITY: &str = "sha512-orig==";

/// Project-relative tarball path the npm backend produces:
/// `.socket/vendor/<eco>/<patch-uuid>/<name>-<version>.tgz`.
fn rel_tgz() -> String {
    format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
}

// ───────────────────────────── fixture ─────────────────────────────

/// One self-contained npm project: root package.json, a v3 package-lock with
/// a registry-resolved `left-pad` entry, the installed package under
/// node_modules/, and a `.socket/` manifest + after-hash blob so vendor runs
/// fully offline. Copied from `in_process_vendor.rs`.
struct NpmFixture {
    tmp: tempfile::TempDir,
    /// The lockfile bytes exactly as the fixture wrote them — the
    /// byte-identity oracle for the rollback round-trips.
    original_lock: Vec<u8>,
    /// Manifest bytes as written (preserve/drift rollbacks must not
    /// rewrite the manifest).
    original_manifest: Vec<u8>,
    after_hash: String,
}

impl NpmFixture {
    fn root(&self) -> &Path {
        self.tmp.path()
    }
    fn lock_path(&self) -> PathBuf {
        self.root().join("package-lock.json")
    }
    fn lock_bytes(&self) -> Vec<u8> {
        std::fs::read(self.lock_path()).expect("read package-lock.json")
    }
    fn manifest_path(&self) -> PathBuf {
        self.root().join(".socket/manifest.json")
    }
    fn tgz_path(&self) -> PathBuf {
        self.root().join(rel_tgz())
    }
    fn state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/state.json")
    }
    fn state_value(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.state_path()).expect("read state.json"))
            .expect("state.json is JSON")
    }
    fn blob_path(&self) -> PathBuf {
        self.root().join(".socket/blobs").join(&self.after_hash)
    }
    fn installed_index(&self) -> PathBuf {
        self.root().join("node_modules/left-pad/index.js")
    }
}

/// The manifest patch record the fixture purl uses.
fn patch_record(before_hash: &str, after_hash: &str) -> Value {
    json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": { "beforeHash": before_hash, "afterHash": after_hash }
        },
        "vulnerabilities": {},
        "description": "synthetic vendored-rollback test patch",
        "license": "MIT",
        "tier": "free"
    })
}

fn npm_fixture() -> NpmFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // Installed package (original, unpatched bytes).
    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();

    // Root project files. The lock is written pretty + 2-space indent +
    // trailing newline — the exact shape the production serializer emits —
    // so byte-identity assertions across vendor/rollback are meaningful.
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": REG_RESOLVED,
                "integrity": REG_INTEGRITY,
                "license": "WTFPL"
            }
        }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).unwrap();
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).unwrap();

    // Manifest + staged after-hash blob (offline source for vendor).
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    let manifest = json!({ "patches": { PURL: patch_record(&before_hash, &after_hash) } });
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut original_manifest = serde_json::to_vec_pretty(&manifest).unwrap();
    original_manifest.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &original_manifest).unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), PATCHED_INDEX).unwrap();

    NpmFixture {
        tmp,
        original_lock,
        original_manifest,
        after_hash,
    }
}

/// In-process `VendorArgs` for the fixture — `in_process_vendor.rs`'s
/// helper verbatim: `json`+`silent` suppress prompts/output, `offline`
/// keeps the patch pipeline on the staged local blobs.
fn vendor_args(cwd: &Path) -> VendorArgs {
    VendorArgs {
        common: GlobalArgs {
            cwd: cwd.to_path_buf(),
            json: true,
            silent: true,
            offline: true,
            // Absorb the fork→exec OFD-lock window (see in_process_vendor.rs).
            lock_timeout: Some(5),
            ..GlobalArgs::default()
        },
        force: false,
        revert: false,
        vex: Default::default(),
    }
}

/// In-process `RollbackArgs`: unscoped (no targets), json auto-accepts the
/// confirmation prompt, offline keeps every leg local.
fn rollback_args(cwd: &Path, preserve_state: bool) -> RollbackArgs {
    RollbackArgs {
        targets: Vec::new(),
        common: GlobalArgs {
            cwd: cwd.to_path_buf(),
            json: true,
            silent: true,
            offline: true,
            lock_timeout: Some(5),
            ..GlobalArgs::default()
        },
        one_off: false,
        preserve_state,
    }
}

// ───────────────────────── subprocess runner ─────────────────────────

/// Run the built `socket-patch` binary with every ambient `SOCKET_*` env var
/// scrubbed from the child (env-robustness: the assertions must reflect the
/// argv, not the developer's shell) and telemetry hard-disabled.
fn run_cli(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args(args).current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("spawn socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `rollback --json --offline --cwd <cwd> <extra...>` through the binary,
/// returning `(exit_code, parsed envelope)`. `--json` auto-accepts the
/// confirmation prompt (the shared `confirm` semantics).
fn rollback_cli(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args = vec![
        "rollback",
        "--json",
        "--offline",
        "--cwd",
        cwd.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_cli(cwd, &args);
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("rollback --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env)
}

// ─────────────────────────────────────────────────────────────────────
// 1. --preserve-state: unwire but keep artifact + ledger + manifest
// ─────────────────────────────────────────────────────────────────────

/// `rollback --preserve-state` on a vendored purl restores the lockfile
/// byte-for-byte but PRESERVES all local patch state: the vendored artifact
/// stays, the ledger entry stays byte-identical (R6 — wiring records
/// intact, never cleared), the manifest entry stays, and no GC runs (the
/// staged blob survives). The envelope surfaces the purl in
/// `vendoredPreserved` with `manifest.preserved: true` and `gc.skipped`.
#[tokio::test]
async fn preserve_state_unwires_but_keeps_artifact_and_ledger() {
    // ── in-process lifecycle: vendor, then rollback --preserve-state ──
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "vendor");
    assert_ne!(
        fx.lock_bytes(),
        fx.original_lock,
        "sanity: vendor actually rewired the lock"
    );
    let state_before = std::fs::read(fx.state_path()).expect("state.json after vendor");
    let entry_before = fx.state_value()["entries"][PURL].clone();
    assert!(entry_before.is_object(), "sanity: ledger entry written");
    let manifest_before = std::fs::read(fx.manifest_path()).unwrap();
    assert_eq!(
        manifest_before, fx.original_manifest,
        "sanity: vendor never touches the manifest"
    );

    let code = rollback_run(rollback_args(fx.root(), true)).await;
    assert_eq!(code, 0, "rollback --preserve-state must exit 0");

    // The system is unpatched: the lock is byte-for-byte the pre-vendor
    // registry spelling again.
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "--preserve-state must restore the lock byte-for-byte"
    );
    // …but the LOCAL STATE is all still there.
    assert!(
        fx.tgz_path().is_file(),
        "the vendored artifact must be kept under --preserve-state"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).expect("state.json survives"),
        state_before,
        "the vendor ledger must be byte-identical (entry kept INTACT, \
         wiring records included — R6)"
    );
    assert_eq!(
        fx.state_value()["entries"][PURL],
        entry_before,
        "the ledger entry must be unchanged"
    );
    assert_eq!(
        std::fs::read(fx.manifest_path()).unwrap(),
        fx.original_manifest,
        "the manifest entry must be kept (no rewrite at all)"
    );
    assert!(
        fx.blob_path().is_file(),
        "GC is skipped under --preserve-state: the staged blob survives"
    );
    assert_eq!(
        std::fs::read(fx.installed_index()).unwrap(),
        ORIG_INDEX,
        "the installed tree of a vendored purl is never touched"
    );

    // ── envelope contract, on a fresh identical fixture ──
    let fx2 = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx2.root())).await, 0, "vendor #2");
    let (code, env) = rollback_cli(fx2.root(), &["--preserve-state"]);
    assert_eq!(code, 0, "preserve rollback exits 0: {env:#}");
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(
        env["vendoredPreserved"],
        json!([PURL]),
        "the unwired-but-kept purl rides vendoredPreserved: {env:#}"
    );
    assert_eq!(env["vendoredReverted"], json!([]), "{env:#}");
    assert_eq!(env["vendoredKept"], json!([]), "{env:#}");
    assert_eq!(env["manifest"]["preserved"], json!(true), "{env:#}");
    assert_eq!(env["manifest"]["removedEntries"], json!([]), "{env:#}");
    assert_eq!(env["gc"], json!({ "skipped": true }), "{env:#}");
    assert_eq!(fx2.lock_bytes(), fx2.original_lock, "lock restored");
    assert!(fx2.tgz_path().is_file(), "artifact kept");
    assert!(
        fx2.state_value()["entries"][PURL].is_object(),
        "ledger entry kept"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 2. re-vendor after --preserve-state re-wires the lock
// ─────────────────────────────────────────────────────────────────────

/// The preserved ledger entry's wiring records now describe already-reverted
/// fragments; a later `vendor` run must read the LIVE lock (registry
/// spelling), see the entry is out of sync, and re-wire — not trust the
/// ledger and skip as "already vendored", which would strand the lock
/// unwired forever (the in-sync probe regression).
#[tokio::test]
async fn revendor_after_preserve_rewires() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "first vendor");
    let wired_lock = fx.lock_bytes();

    assert_eq!(
        rollback_run(rollback_args(fx.root(), true)).await,
        0,
        "rollback --preserve-state"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "sanity: the lock is back at the registry spelling"
    );

    // Re-vendor: exit 0 and the lock is re-wired to the .socket/vendor path
    // (byte-identical to the first wiring — deterministic pack, same uuid).
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "re-vendor");
    assert_eq!(
        fx.lock_bytes(),
        wired_lock,
        "re-vendor must re-wire the lock to the .socket/vendor artifact"
    );
    let lock_text = String::from_utf8(fx.lock_bytes()).unwrap();
    assert!(
        lock_text.contains(&format!("file:{}", rel_tgz())),
        "the lock must point at the vendored tarball again: {lock_text}"
    );
    assert!(fx.tgz_path().is_file(), "artifact present after re-vendor");

    // The ledger entry survived the round-trip and still records the
    // pre-vendor registry fragment, so a LATER revert can still restore it.
    let state = fx.state_value();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["uuid"], UUID, "{state:#}");
    let wiring = entry["wiring"].as_array().expect("wiring array");
    assert_eq!(
        wiring[0]["original"]["resolved"], REG_RESOLVED,
        "the registry original must survive the preserve→re-vendor \
         round-trip: {state:#}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. drift-keep: exit 1, ledger AND manifest entries survive
// ─────────────────────────────────────────────────────────────────────

/// A vendored entry whose wiring records match NOTHING in the live lock is
/// a drift-keep: the backend refuses to touch the drifted lock, the run
/// exits 1 (`partial_failure` — the system is still patched, R5), the
/// envelope carries the purl + reason in `vendoredKept`, and BOTH the
/// ledger entry and the manifest entry survive for a later normalize +
/// retry (fail-closed manifest cleanup).
#[tokio::test]
async fn drift_keep_exits_partial_failure_and_holds_manifest() {
    const DRIFT_PURL: &str = "pkg:npm/__rollback_drift_kept__@1.0.0";
    const DRIFT_UUID: &str = "33333333-3333-4333-8333-333333333333";

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    // A real lock that contains NO fragment the wiring below names.
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": { "": { "name": "fixture", "version": "1.0.0" } }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).unwrap();
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).unwrap();

    // Manifest entry for the same purl (files empty: the drift-keep must
    // hold the entry regardless of any agent-leg work).
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let original_manifest = format!(
        r#"{{
  "patches": {{
    "{DRIFT_PURL}": {{
      "uuid": "{DRIFT_UUID}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "synthetic drift-keep fixture",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), &original_manifest).unwrap();

    // Vendor ledger entry wired with a fragment the lock does not contain —
    // cli_remove_silent.rs's DRIFTED_WIRING shape (the npm revert backend
    // classifies the vanished `node_modules/x` entry as third-party drift
    // and keeps the artifact + wiring untouched).
    let artifact_dir = socket.join("vendor/npm").join(DRIFT_UUID);
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").unwrap();
    let original_state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{DRIFT_PURL}": {{
      "ecosystem": "npm",
      "basePurl": "{DRIFT_PURL}",
      "uuid": "{DRIFT_UUID}",
      "artifact": {{ "path": ".socket/vendor/npm/{DRIFT_UUID}/package.tgz" }},
      "wiring": [{{ "file": "weird.txt", "kind": "npm_lock_entry", "action": "added", "key": "node_modules/x" }}]
    }}
  }}
}}"#
    );
    let state_path = socket.join("vendor/state.json");
    std::fs::write(&state_path, &original_state).unwrap();

    // ── in-process bare rollback: exit 1, nothing on disk moves ──
    let code = rollback_run(rollback_args(root, false)).await;
    assert_eq!(code, 1, "a drift-keep must exit partial_failure (R5)");
    assert_eq!(
        std::fs::read(&state_path).expect("ledger survives"),
        original_state.as_bytes(),
        "the drift-kept ledger entry must survive byte-identical"
    );
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).expect("manifest survives"),
        original_manifest.as_bytes(),
        "the manifest entry must survive a drift-keep (fail-closed cleanup)"
    );
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        original_lock,
        "the drifted lock must be left alone"
    );
    assert!(
        artifact_dir.join("package.tgz").is_file(),
        "the kept artifact must survive"
    );

    // ── envelope: the drift-keep leaves everything untouched, so the same
    //    fixture replays identically through the binary ──
    let (code, env) = rollback_cli(root, &[]);
    assert_eq!(code, 1, "drift-keep exits 1: {env:#}");
    assert_eq!(env["status"], "partial_failure", "{env:#}");
    let kept = env["vendoredKept"].as_array().expect("vendoredKept array");
    assert_eq!(kept.len(), 1, "{env:#}");
    assert_eq!(kept[0]["purl"], DRIFT_PURL, "{env:#}");
    assert!(
        kept[0]["reason"]
            .as_str()
            .is_some_and(|r| r.contains("drifted")),
        "the kept reason must name the drift: {env:#}"
    );
    assert_eq!(env["vendoredReverted"], json!([]), "{env:#}");
    assert_eq!(
        env["manifest"]["removedEntries"],
        json!([]),
        "a drift-kept purl's manifest entry is never removed: {env:#}"
    );

    // Still nothing moved.
    assert_eq!(
        std::fs::read(&state_path).unwrap(),
        original_state.as_bytes(),
        "ledger byte-identical after the second (binary) run"
    );
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(socket.join("manifest.json")).unwrap()).unwrap();
    assert!(
        manifest["patches"].get(DRIFT_PURL).is_some(),
        "manifest entry survives: {manifest:#}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 4. detached entries are reverted by the unscoped default
// ─────────────────────────────────────────────────────────────────────

/// A detached ledger entry (`scan --vendor --detached` — never
/// manifest-tracked) is IN SCOPE for the unscoped default rollback: the
/// lock is restored byte-for-byte, the artifact is deleted, the emptied
/// ledger is deleted, and the purl rides `vendoredReverted` (exit 0).
/// The fixture detaches a REAL vendor run's entry (the
/// `in_process_vendor.rs` idiom), so the wiring genuinely points into the
/// lock.
#[tokio::test]
async fn detached_entries_reverted_by_unscoped_default() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "vendor");

    // Mark the entry detached (the shape `scan --vendor --detached` writes)
    // and drop the patch from the manifest — detached entries are never
    // manifest-tracked.
    let mut state = fx.state_value();
    state["entries"][PURL]["detached"] = json!(true);
    std::fs::write(fx.state_path(), serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    std::fs::write(fx.manifest_path(), b"{\"patches\": {}}\n").unwrap();
    assert_ne!(
        fx.lock_bytes(),
        fx.original_lock,
        "sanity: the detached entry is wired into the lock"
    );

    let (code, env) = rollback_cli(fx.root(), &[]);
    assert_eq!(code, 0, "detached revert exits 0: {env:#}");
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(
        env["vendoredReverted"],
        json!([PURL]),
        "the detached entry must ride vendoredReverted: {env:#}"
    );
    assert_eq!(env["vendoredPreserved"], json!([]), "{env:#}");
    assert_eq!(env["vendoredKept"], json!([]), "{env:#}");
    assert_eq!(
        env["manifest"]["removedEntries"],
        json!([]),
        "detached entries have no manifest record to remove: {env:#}"
    );

    // On-disk post-state: fully reverted.
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock must be restored byte-for-byte"
    );
    assert!(!fx.tgz_path().exists(), "artifact deleted");
    assert!(
        !fx.root()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists(),
        "the artifact uuid dir must be gone"
    );
    assert!(
        !fx.state_path().exists(),
        "the emptied ledger must be deleted"
    );
    assert_eq!(
        std::fs::read(fx.installed_index()).unwrap(),
        ORIG_INDEX,
        "the installed tree is never touched by a vendored revert"
    );
}
