//! Coverage-gap tests for `commands/vendor.rs` (2026-09 coverage audit):
//! the fail-closed ledger/manifest exit contracts, the fresh-clone
//! committed-artifact staging error ladder, the redirect-ledger takeover
//! guard, the human-mode (no `--json`) output surface, and the unix
//! fault-injection paths for the two state-write failure events.
//!
//! Fixture + runner shapes mirror `in_process_vendor.rs` (which this suite
//! deliberately does not touch): an offline, self-contained npm project with
//! a staged patch blob, driven either in-process (`vendor_run`) or through
//! the built binary with a scrubbed child environment (`run_cli` /
//! `vendor_cli`). No test mutates this process's environment.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::vendor::{run as vendor_run, VendorArgs};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::vendor::state::VendorArtifact;
use socket_patch_core::vendor::{save_state, VendorEntry, VendorState};

/// Canonical-grammar patch UUID (the vendor path layer validates it).
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
const REG_RESOLVED: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
const REG_INTEGRITY: &str = "sha512-orig==";

fn rel_tgz() -> String {
    format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
}

// ───────────────────────────── fixture ─────────────────────────────

struct NpmFixture {
    tmp: tempfile::TempDir,
    original_lock: Vec<u8>,
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
    fn vendor_dir(&self) -> PathBuf {
        self.root().join(".socket/vendor")
    }
    fn tgz_path(&self) -> PathBuf {
        self.root().join(rel_tgz())
    }
    fn state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/state.json")
    }
    fn redirect_state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/redirect-state.json")
    }
}

/// One manifest patch record (camelCase, the TS-compatible manifest shape).
fn patch_record(before_hash: &str, after_hash: &str) -> Value {
    json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": { "beforeHash": before_hash, "afterHash": after_hash }
        },
        "vulnerabilities": {},
        "description": "synthetic covgap vendor test patch",
        "license": "MIT",
        "tier": "free"
    })
}

fn npm_fixture_with_purls(manifest_purls: &[&str]) -> NpmFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();

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

    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    let mut patches = serde_json::Map::new();
    for purl in manifest_purls {
        patches.insert(purl.to_string(), patch_record(&before_hash, &after_hash));
    }
    let manifest = json!({ "patches": patches });
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    manifest_bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &manifest_bytes).unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), PATCHED_INDEX).unwrap();

    NpmFixture { tmp, original_lock }
}

fn npm_fixture() -> NpmFixture {
    npm_fixture_with_purls(&[PURL])
}

/// In-process `VendorArgs` (json+silent+offline), for staging a vendored
/// state a subsequent subprocess run asserts against.
fn vendor_args(cwd: &Path) -> VendorArgs {
    VendorArgs {
        common: GlobalArgs {
            cwd: cwd.to_path_buf(),
            json: true,
            silent: true,
            offline: true,
            // See in_process_vendor.rs: absorbs the fork→exec fd window of
            // concurrent tests in this binary.
            lock_timeout: Some(5),
            ..GlobalArgs::default()
        },
        force: false,
        revert: false,
        vex: Default::default(),
    }
}

// ───────────────────────── subprocess runner ─────────────────────────

/// Run the built `socket-patch` binary with every ambient `SOCKET_*` env var
/// scrubbed from the child and telemetry hard-disabled.
fn run_cli(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args(args).current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `vendor --json --offline --cwd <cwd> <extra...>` through the binary.
fn vendor_cli(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let mut args = vec![
        "vendor",
        "--json",
        "--offline",
        "--cwd",
        cwd.to_str().unwrap(),
    ];
    args.extend_from_slice(extra);
    let (code, stdout, stderr) = run_cli(cwd, &args, &[]);
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("vendor --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env)
}

fn events(envelope: &Value) -> &Vec<Value> {
    envelope["events"].as_array().expect("events array")
}

fn find_event<'a>(envelope: &'a Value, action: &str, error_code: Option<&str>) -> &'a Value {
    events(envelope)
        .iter()
        .find(|e| e["action"] == action && error_code.is_none_or(|c| e["errorCode"] == c))
        .unwrap_or_else(|| {
            panic!("expected a `{action}` event (errorCode={error_code:?}) in:\n{envelope:#}")
        })
}

/// A synthetic ledger with one entry of `eco` for [`PURL`], written via the
/// real `save_state` serializer (what a tampered-but-parseable state.json
/// deserializes into).
async fn write_ledger_entry(root: &Path, eco: &str) {
    let mut state = VendorState::default();
    state.entries.insert(
        PURL.to_string(),
        VendorEntry {
            ecosystem: eco.into(),
            base_purl: PURL.into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/{eco}/{UUID}/left-pad-1.3.0.tgz"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        },
    );
    save_state(root, &state).await.unwrap();
}

// ─────────────────────────────────────────────────────────────────────
// 1. corrupt-ledger / corrupt-manifest fail-closed exit contracts
// ─────────────────────────────────────────────────────────────────────

/// A corrupt `.socket/vendor/state.json` fails the vendor run CLOSED:
/// exit 1, a single top-level `vendor_state_unreadable` envelope error —
/// `reconcile_dropped`'s unreadable-state early return must NOT duplicate
/// the report — and the lockfile untouched.
#[test]
fn corrupt_vendor_state_fails_vendor_closed_once() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    std::fs::write(fx.state_path(), b"not json{").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "corrupt ledger must fail the run: {env:#}");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "vendor_state_unreadable");
    assert!(
        events(&env)
            .iter()
            .all(|e| e["errorCode"] != "vendor_state_unreadable"),
        "exactly ONE report — the reconcile pass must not add a duplicate \
         event for the same corruption: {env:#}"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "nothing may be vendored over an unreadable ledger"
    );
}

/// The same corruption fails `--revert` closed with the same code (the
/// revert must not guess what to restore).
#[test]
fn corrupt_vendor_state_fails_revert_closed() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    std::fs::write(fx.state_path(), b"not json{").unwrap();

    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 1, "corrupt ledger must fail the revert: {env:#}");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "vendor_state_unreadable");
    assert!(
        events(&env).is_empty(),
        "a pre-event failure carries no events: {env:#}"
    );
}

/// A present-but-corrupt manifest is `invalid_manifest`, exit 1 (the
/// documented vendor exit contract; distinct from the missing-manifest
/// clean no-op).
#[test]
fn corrupt_manifest_fails_closed() {
    let fx = npm_fixture();
    std::fs::write(fx.manifest_path(), b"{broken").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "corrupt manifest must fail the run: {env:#}");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "invalid_manifest");
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

// ─────────────────────────────────────────────────────────────────────
// 2. fresh-clone committed-artifact staging error ladder
// ─────────────────────────────────────────────────────────────────────

/// Fresh-clone re-vendor over a PRESENT-but-corrupt committed artifact
/// (ledger sha mismatch): a loud `vendor_fetch_failed` failure carrying the
/// `socket-patch repair` hint — silently re-vendoring over it would mask
/// the corruption.
#[tokio::test]
async fn corrupt_committed_artifact_fails_with_repair_hint() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    // Fresh-clone shape: no installed tree, only the committed artifacts.
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    std::fs::write(fx.tgz_path(), b"corrupt bytes").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "a corrupt committed artifact must fail: {env:#}");
    let failed = find_event(&env, "failed", Some("vendor_fetch_failed"));
    assert_eq!(failed["purl"], PURL);
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("socket-patch repair")),
        "the failure must advise `socket-patch repair`: {env:#}"
    );
}

/// A legacy ledger with NO recorded artifact sha cannot verify the
/// committed artifact (`Unverifiable`) and must fall through to the
/// registry ladder — under `--offline` that lands in the calm
/// `package_not_installed` skip, never a loud `vendor_fetch_failed`.
#[tokio::test]
async fn legacy_ledger_without_sha_falls_through_to_calm_offline_skip() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    // Legacy shape: blank the recorded sha (parseable, just unverifiable).
    let mut state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap())
        .expect("state.json parses");
    state["entries"][PURL]["artifact"]["sha256"] = Value::String(String::new());
    std::fs::write(fx.state_path(), serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    let skipped = find_event(&env, "skipped", Some("package_not_installed"));
    assert_eq!(skipped["purl"], PURL);
    assert!(
        events(&env)
            .iter()
            .all(|e| e["errorCode"] != "vendor_fetch_failed"),
        "an unverifiable legacy artifact is not a fetch FAILURE: {env:#}"
    );
    assert!(
        fx.tgz_path().is_file(),
        "the committed artifact is left alone"
    );
}

/// `PristineFetch::NoSource` in the auto-fetch loop: manifest purl, nothing
/// installed, no lockfile, no ledger — a NON-offline run still skips calmly
/// with the plain not-installed detail (the ladder returns before any
/// network I/O; `SOCKET_NO_API_TOKEN` keeps the run anonymous so no other
/// network path opens either).
#[test]
fn missing_package_with_no_lock_and_no_ledger_is_calm_skip() {
    let fx = npm_fixture();
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    std::fs::remove_file(fx.lock_path()).unwrap();

    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &["vendor", "--json", "--cwd", fx.root().to_str().unwrap()],
        &[("SOCKET_NO_API_TOKEN", "1")],
    );
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("vendor --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(
        code, 1,
        "an unvendorable manifest purl fails the run: {env:#}"
    );
    let skipped = find_event(&env, "skipped", Some("package_not_installed"));
    assert_eq!(skipped["purl"], PURL);
    assert_eq!(
        skipped["reason"], "no installed package found on disk",
        "the plain (non-offline) detail: {env:#}"
    );
    assert!(
        events(&env)
            .iter()
            .all(|e| e["errorCode"] != "vendor_fetch_failed"),
        "NoSource is a calm skip, not a fetch failure: {env:#}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. redirect-ledger takeover guard
// ─────────────────────────────────────────────────────────────────────

/// A malformed redirect ledger makes a claimed purl indistinguishable from
/// an unclaimed one, so every purl of a takeover-capable ecosystem (npm,
/// cargo) fails CLOSED with the corruption surfaced — and nothing is
/// vendored over the possibly-live hosted redirect.
#[test]
fn corrupt_redirect_ledger_fails_takeover_capable_purl_closed() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    std::fs::write(fx.redirect_state_path(), b"garbage").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    let failed = find_event(&env, "failed", Some("redirect_ledger_corrupt"));
    assert_eq!(failed["purl"], PURL);
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("cannot vendor over a possibly-live hosted redirect")),
        "{env:#}"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock must not be rewired while the redirect ledger is unreadable"
    );
    assert!(
        !fx.tgz_path().exists(),
        "no artifact may be produced for the refused purl"
    );
}

/// Dry-run over a purl the redirect ledger still claims: the run must warn
/// `vendor_would_revert_redirect` (an UNCOUNTED advisory — dry/wet takeover
/// parity) and leave both the redirect ledger and the lockfile untouched.
#[test]
fn dry_run_over_claimed_redirect_warns_and_writes_nothing() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    let ledger = json!({
        "version": 1,
        "mode": "hosted",
        "records": { PURL: patch_record(&before_hash, &after_hash) }
    });
    let ledger_bytes = serde_json::to_vec_pretty(&ledger).unwrap();
    std::fs::write(fx.redirect_state_path(), &ledger_bytes).unwrap();

    let (code, env) = vendor_cli(fx.root(), &["--dry-run"]);
    assert_eq!(code, 0, "the dry run itself succeeds: {env:#}");
    let warned = find_event(&env, "skipped", Some("vendor_would_revert_redirect"));
    assert_eq!(warned["purl"], PURL);
    assert_eq!(
        env["summary"]["skipped"], 0,
        "the takeover advisory is uncounted: {env:#}"
    );
    assert_eq!(
        std::fs::read(fx.redirect_state_path()).unwrap(),
        ledger_bytes,
        "a dry run must not touch the redirect ledger"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "a dry run must not touch the lock"
    );
}

/// A claimed redirect whose recorded edit cannot be reverted (no recorded
/// original fragment) fails the purl CLOSED with `redirect_revert_failed`
/// — vendoring over an unrevertable live redirect would strand the hosted
/// edits forever.
#[test]
fn unrevertable_redirect_claim_fails_closed() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    // A yarn-classic hosted edit claiming this purl, with NO original
    // fragment recorded: the revert must refuse rather than guess.
    let ledger = json!({
        "version": 1,
        "mode": "hosted",
        "edits": [{
            "path": "yarn.lock",
            "kind": "redirect_yarn_classic_entry",
            "action": "rewritten",
            "key": "left-pad@1.3.0"
        }],
        "records": { PURL: patch_record(&before_hash, &after_hash) }
    });
    let ledger_bytes = serde_json::to_vec_pretty(&ledger).unwrap();
    std::fs::write(fx.redirect_state_path(), &ledger_bytes).unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    let failed = find_event(&env, "failed", Some("redirect_revert_failed"));
    assert_eq!(failed["purl"], PURL);
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("cannot vendor over the live hosted redirect")),
        "{env:#}"
    );
    assert_eq!(
        std::fs::read(fx.redirect_state_path()).unwrap(),
        ledger_bytes,
        "a refused takeover must leave the redirect ledger as it was"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
    assert!(!fx.tgz_path().exists(), "no artifact for the refused purl");
}

// ─────────────────────────────────────────────────────────────────────
// 4. revert-failure accounting on tampered ledger entries
// ─────────────────────────────────────────────────────────────────────

/// `vendor --revert` over a ledger entry whose ecosystem has no revert
/// backend (tampered state.json): a `revert_failed` event with the
/// fail-closed diagnostic, exit 1, and the entry KEPT.
#[tokio::test]
async fn revert_unknown_ecosystem_entry_fails_closed_and_keeps_entry() {
    let fx = npm_fixture();
    write_ledger_entry(fx.root(), "frobnicate").await;

    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 1, "{env:#}");
    assert_eq!(env["status"], "partialFailure", "{env:#}");
    let failed = find_event(&env, "failed", Some("revert_failed"));
    assert_eq!(failed["purl"], PURL);
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("no vendor backend for ecosystem `frobnicate`")),
        "{env:#}"
    );
    let state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    assert!(
        state["entries"][PURL].is_object(),
        "a failed revert must keep the ledger entry: {state:#}"
    );
}

/// The reconcile pass (patch dropped from the manifest) hits the same
/// fail-closed refusal: `revert_failed`, exit 1, entry kept.
#[tokio::test]
async fn reconcile_unknown_ecosystem_entry_fails_closed_and_keeps_entry() {
    let fx = npm_fixture_with_purls(&[]);
    write_ledger_entry(fx.root(), "frobnicate").await;

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    let failed = find_event(&env, "failed", Some("revert_failed"));
    assert_eq!(failed["purl"], PURL);
    let state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    assert!(
        state["entries"][PURL].is_object(),
        "a failed reconcile revert must keep the ledger entry: {state:#}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 5. human-mode output surface (no --json, no --silent)
// ─────────────────────────────────────────────────────────────────────

fn human_vendor(fx: &NpmFixture, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["vendor", "--offline", "--cwd", fx.root().to_str().unwrap()];
    args.extend_from_slice(extra);
    run_cli(fx.root(), &args, &[])
}

/// Human happy path: the summary line, the committables hint, and the
/// npm reinstall hint (package-lock flavor).
#[test]
fn human_vendor_prints_summary_committables_and_reinstall_hint() {
    let fx = npm_fixture();
    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Vendored 1 package(s); 0 skipped; 0 failed."),
        "summary line: {stdout}"
    );
    assert!(
        stdout.contains("Commit .socket/vendor/ and the updated lockfiles"),
        "committables hint: {stdout}"
    );
    assert!(
        stdout.contains("Run `npm install`"),
        "package-lock reinstall hint: {stdout}"
    );
}

/// Human `--dry-run`: the `Would vendor` verb and NO commit/reinstall
/// hints (nothing was written). NOTE the pinned count: a dry-run success
/// is translated to a `Verified` event (counted under `summary.verified`,
/// not `applied`), while the human line prints `summary.applied` — so a
/// would-vendor package prints as `Would vendor 0`; the JSON cross-check
/// below anchors where the package actually lands. A future fix that
/// prints the verified count must consciously update this pin.
#[test]
fn human_dry_run_prints_would_vendor_and_no_commit_hints() {
    let fx = npm_fixture();
    let (code, stdout, stderr) = human_vendor(&fx, &["--dry-run"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Would vendor 0 package(s); 0 skipped; 0 failed."),
        "dry-run verb (applied stays 0 — the success is a Verified event): {stdout}"
    );
    let (json_code, env) = vendor_cli(fx.root(), &["--dry-run"]);
    assert_eq!(json_code, 0, "{env:#}");
    assert_eq!(
        env["summary"]["verified"], 1,
        "the dry-run success is counted as verified: {env:#}"
    );
    assert!(
        !stdout.contains("Commit .socket/vendor/"),
        "a dry run has nothing to commit: {stdout}"
    );
    assert!(
        !stdout.contains("Run `"),
        "a dry run needs no reinstall: {stdout}"
    );
    assert!(!fx.vendor_dir().exists(), "dry run writes nothing");
}

/// Human not-installed skip: the `Cannot vendor …` stderr line with the
/// on-disk cause, while the installed package still vendors (and the
/// summary counts both honestly).
#[test]
fn human_not_installed_prints_cannot_vendor_to_stderr() {
    let fx = npm_fixture_with_purls(&[PURL, "pkg:npm/right-pad@9.9.9"]);
    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor"),
        "stderr names the skip: {stderr}"
    );
    assert!(
        stderr.contains("no installed package found on disk"),
        "stderr carries the on-disk cause: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 1 package(s); 1 skipped; 0 failed."),
        "summary counts the skip: {stdout}"
    );
}

/// Human `--revert` summary after a completed revert.
#[tokio::test]
async fn human_revert_prints_reverted_summary() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Reverted 1 vendored package(s); 0 failed."),
        "revert summary: {stdout}"
    );
    assert!(
        !stdout.contains("Kept"),
        "nothing drifted, so no drift explainer: {stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

/// Human `--revert` over a drifted lock: `Reverted 0 …` plus the
/// `Kept N drifted package(s)` explainer (counts come from the drift-skip
/// keep, not advisory warnings).
#[tokio::test]
async fn human_revert_drift_keep_prints_kept_explainer() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    // Third-party drift: neither ours nor the recorded pre-vendor original.
    let mut drifted: Value = serde_json::from_slice(&fx.lock_bytes()).unwrap();
    drifted["packages"]["node_modules/left-pad"]["resolved"] =
        Value::String("https://example.com/their-fork.tgz".to_string());
    let mut drifted_lock = serde_json::to_vec_pretty(&drifted).unwrap();
    drifted_lock.push(b'\n');
    std::fs::write(fx.lock_path(), &drifted_lock).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "a drift keep is not an error:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("Reverted 0 vendored package(s); 0 failed."),
        "nothing reverted: {stdout}"
    );
    assert!(
        stdout.contains("Kept 1 drifted package(s)"),
        "the drift-keep explainer: {stdout}"
    );
    assert!(fx.tgz_path().is_file(), "kept artifacts survive");
    assert_eq!(fx.lock_bytes(), drifted_lock, "drifted lock left alone");
}

/// Human `--revert` with a `.socket/` present but an empty ledger: the
/// calm no-op line (complements the no-`.socket`-dir no-op pinned in
/// in_process_vendor.rs).
#[test]
fn human_revert_empty_ledger_prints_nothing_to_revert() {
    let fx = npm_fixture();
    assert!(!fx.state_path().exists(), "fixture starts unvendored");

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Nothing vendored to revert."),
        "the empty-ledger no-op line: {stdout}"
    );
}

/// Human plain vendor with no manifest at all: the clean no-op message,
/// exit 0 (same contract as apply).
#[test]
fn human_missing_manifest_prints_nothing_to_vendor() {
    let fx = npm_fixture();
    std::fs::remove_file(fx.manifest_path()).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("No .socket folder found, nothing to vendor."),
        "the no-manifest no-op line: {stdout}"
    );
    assert!(!fx.vendor_dir().exists(), "nothing written");
}

// ─────────────────────────────────────────────────────────────────────
// 6. pnpm committables hint (pnpm >=11 workspace-file portability)
// ─────────────────────────────────────────────────────────────────────

/// A pnpm project (lockfileVersion 9.0): package.json + pnpm-lock.yaml +
/// installed node_modules/left-pad + the same staged `.socket` blob as the
/// npm fixture. The lock grammar mirrors core's pnpm_lock spike fixtures.
fn pnpm_fixture() -> NpmFixture {
    let fx = npm_fixture();
    std::fs::remove_file(fx.lock_path()).unwrap();
    let lock = "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==}

snapshots:

  left-pad@1.3.0: {}
";
    std::fs::write(fx.root().join("pnpm-lock.yaml"), lock).unwrap();
    fx
}

/// pnpm-wired human run: the committables line must name
/// pnpm-workspace.yaml (pnpm >=11 reads overrides only from there — losing
/// it silently unvendors on the next install) and the reinstall hint must
/// say `pnpm install`.
#[test]
fn human_pnpm_vendor_names_workspace_committable_and_pnpm_install() {
    let fx = pnpm_fixture();
    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("pnpm-workspace.yaml"),
        "the pnpm committables line names the workspace file: {stdout}"
    );
    assert!(
        stdout.contains("pnpm >=11"),
        "…and says why (pnpm >=11 override source): {stdout}"
    );
    assert!(
        stdout.contains("Run `pnpm install`"),
        "the pnpm reinstall hint: {stdout}"
    );
    assert!(
        !stdout.contains("Run `npm install`"),
        "only the wired flavor's install is suggested: {stdout}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 7. unix fault injection: state-write failures
// ─────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Restores the directory mode on drop so the tempdir can clean up even if
/// an assertion panics first.
#[cfg(unix)]
struct RestorePerms(PathBuf);
#[cfg(unix)]
impl Drop for RestorePerms {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
    }
}

/// `--revert` whose per-entry `save_state` fails AFTER the entry's revert
/// succeeded (`.socket/vendor` read-only, artifacts still deletable): the
/// purl carries BOTH its `Removed` event and a `vendor_state_write_failed`
/// failure, and the run exits 1 — the ledger on disk no longer matches
/// what was unwired, which must never pass silently.
#[cfg(unix)]
#[tokio::test]
async fn revert_state_write_failure_reports_failed_after_removal() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    chmod(&fx.vendor_dir(), 0o555);
    let _restore = RestorePerms(fx.vendor_dir());

    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 1, "{env:#}");
    let removed = find_event(&env, "removed", None);
    assert_eq!(
        removed["purl"], PURL,
        "the revert itself succeeded: {env:#}"
    );
    let failed = find_event(&env, "failed", Some("vendor_state_write_failed"));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock restore itself succeeded"
    );
}

/// A vendor run whose per-package `save_state` fails after the backend
/// already wrote the artifact and rewired the lock: the package's
/// `Applied` event stands, a `vendor_state_write_failed` failure rides
/// beside it, and the run exits 1 (the crash-consistency contract of the
/// per-package save).
#[cfg(unix)]
#[tokio::test]
async fn vendor_state_write_failure_reports_failed_event() {
    let fx = npm_fixture();
    // The backend's artifact home stays writable; only the ledger's own
    // directory refuses writes.
    std::fs::create_dir_all(fx.vendor_dir().join("npm")).unwrap();
    chmod(&fx.vendor_dir(), 0o555);
    let _restore = RestorePerms(fx.vendor_dir());

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL, "the backend vendored: {env:#}");
    let failed = find_event(&env, "failed", Some("vendor_state_write_failed"));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert!(
        fx.tgz_path().is_file(),
        "the artifact the backend wrote is on disk"
    );
    assert!(!fx.state_path().exists(), "the ledger write failed");
}

/// A hosted redirect record whose revert succeeds but whose ledger update
/// cannot be persisted (`.socket/vendor` read-only): the purl fails CLOSED
/// with `redirect_ledger_write_failed` and is NOT vendored — a ledger
/// still claiming reverted wiring must stop the takeover.
#[cfg(unix)]
#[test]
fn redirect_ledger_write_failure_fails_takeover_purl_closed() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    // A record claiming the purl with no edits left to unwind: the revert
    // trivially succeeds, so the ledger persist is the step that fails.
    let ledger = json!({
        "version": 1,
        "mode": "hosted",
        "records": { PURL: patch_record(&before_hash, &after_hash) }
    });
    let ledger_bytes = serde_json::to_vec_pretty(&ledger).unwrap();
    std::fs::write(fx.redirect_state_path(), &ledger_bytes).unwrap();
    chmod(&fx.vendor_dir(), 0o555);
    let _restore = RestorePerms(fx.vendor_dir());

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    let failed = find_event(&env, "failed", Some("redirect_ledger_write_failed"));
    assert_eq!(failed["purl"], PURL);
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("could not") && d.contains("redirect-state.json")),
        "{env:#}"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "no vendor rewire happened"
    );
    assert!(!fx.tgz_path().exists(), "the purl must not be vendored");
    assert_eq!(
        std::fs::read(fx.redirect_state_path()).unwrap(),
        ledger_bytes,
        "the unpersistable ledger is left exactly as found"
    );
}
