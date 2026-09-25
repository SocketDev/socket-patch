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
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

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
    // In-process tests in this binary `std::env::set_var` these via
    // `apply_env_toggles`; one set by a parallel test between the scan
    // above and the spawn would be inherited, so remove them
    // unconditionally (see in_process_vendor.rs `run_cli`).
    for key in [
        "SOCKET_OFFLINE",
        "SOCKET_DEBUG",
        "SOCKET_API_URL",
        "SOCKET_PROXY_URL",
    ] {
        cmd.env_remove(key);
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
        stdout.contains("Vendored 1 package."),
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
/// hints (nothing was written). A dry-run success is translated to a
/// `Verified` event (counted under `summary.verified`, not `applied`); the
/// human line counts it as a would-vendor package, and the JSON
/// cross-check below anchors where the package actually lands.
#[test]
fn human_dry_run_prints_would_vendor_and_no_commit_hints() {
    let fx = npm_fixture();
    let (code, stdout, stderr) = human_vendor(&fx, &["--dry-run"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Would vendor 1 package."),
        "dry-run verb, counting the Verified preview event: {stdout}"
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
        stdout.contains("Vendored 1 package; 1 not installed."),
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
        stdout.contains("Reverted 1 vendored package."),
        "revert summary: {stdout}"
    );
    assert!(
        !stdout.contains("Kept"),
        "nothing drifted, so no drift explainer: {stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

/// Human `--revert` over a drifted lock: no `Reverted …` line, only the
/// `Kept 1 drifted package` explainer (counts come from the drift-skip
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
        !stdout.contains("Reverted"),
        "nothing reverted, so no package line: {stdout}"
    );
    assert!(
        stdout.contains("Kept 1 drifted package:"),
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
/// exit 0 (same contract as apply). The line names the MANIFEST — the
/// fixture's `.socket/` (blobs) very much exists, so the old "No .socket
/// folder found" text was false here and on every hosted-only or
/// vendored-mode project.
#[test]
fn human_missing_manifest_prints_nothing_to_vendor() {
    let fx = npm_fixture();
    std::fs::remove_file(fx.manifest_path()).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("No manifest found, nothing to vendor."),
        "the no-manifest no-op line: {stdout}"
    );
    assert!(
        !stdout.contains(".socket folder"),
        "never claims .socket/ is missing: {stdout}"
    );
    assert!(!fx.vendor_dir().exists(), "nothing written");
    assert!(
        !fx.root().join(".socket/apply.lock").exists(),
        "the no-op path takes no lock"
    );
}

/// Human plain vendor on a LEDGER-tracked project with no manifest — the
/// shape every `scan`/`get --mode vendored` project has (`.socket/vendor/`
/// exists, `.socket/manifest.json` does not): still the clean exit-0
/// no-op (nothing locked, reverted or written), but the line says what IS
/// vendored and points at `repair` instead of implying nothing is set up.
#[tokio::test]
async fn human_missing_manifest_with_ledger_names_the_tracked_entries() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    std::fs::remove_file(fx.manifest_path()).unwrap();
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("No manifest to vendor from; 1 vendored entry is tracked in the ledger"),
        "the ledger-aware no-op line: {stdout}"
    );
    assert!(
        stdout.contains("`socket-patch repair`"),
        "points at repair as the verification path: {stdout}"
    );
    assert!(!stdout.contains(".socket folder"), "{stdout}");
    assert!(fx.tgz_path().is_file(), "no-op: the artifact survives");
    assert_eq!(
        fx.lock_bytes(),
        wired_lock,
        "no-op: the wiring is untouched"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_before,
        "no-op: the ledger is untouched"
    );
    assert!(
        !fx.root().join(".socket/apply.lock").exists(),
        "the no-op path takes no lock"
    );
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

/// The reconcile twin of the pin above: a patch dropped from the manifest
/// whose ledger save fails AFTER the entry's revert succeeded
/// (`.socket/vendor` read-only, the artifact dir under `npm/` still
/// deletable). The purl carries BOTH its `vendor_reconciled` removal and a
/// `vendor_state_write_failed` failure, and the run exits 1 — pre-fix
/// `reconcile_dropped` swallowed the error (`let _ = save_state`) and
/// exited 0 with a ledger still listing the reverted purl.
#[cfg(unix)]
#[tokio::test]
async fn reconcile_state_write_failure_reports_failed_after_removal() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    std::fs::write(fx.manifest_path(), b"{\"patches\": {}}\n").unwrap();
    chmod(&fx.vendor_dir(), 0o555);
    let _restore = RestorePerms(fx.vendor_dir());

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    let removed = find_event(&env, "removed", Some("vendor_reconciled"));
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
    assert!(
        fx.state_path().is_file(),
        "the stale ledger is left in place — the write is what failed"
    );
}

/// A vendor run whose ledger cannot be written (`.socket/vendor` refuses
/// writes) after the backend already wrote the artifact: the run's ONE
/// commit of the lock rewire and the ledger fails as a whole, so neither is
/// written — the lock keeps its pre-run bytes, no ledger appears — and the
/// run exits 1 with the top-level `vendor_commit_failed` error. The
/// package's `Applied` event still reports what the backend did; the
/// artifact is an orphan the next run re-vendors over. (Before the group
/// commit this was a per-package `vendor_state_write_failed` next to an
/// already-rewired lock.)
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
    assert_eq!(env["error"]["code"], "vendor_commit_failed", "{env:#}");
    assert!(
        fx.tgz_path().is_file(),
        "the artifact the backend wrote is on disk"
    );
    assert!(!fx.state_path().exists(), "the ledger write failed");
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock rewire is committed with the ledger or not at all"
    );
}

/// A hosted redirect record whose revert succeeds but whose ledger update
/// cannot be persisted (`.socket/vendor` read-only). The takeover's revert,
/// its redirect-ledger drop, the vendor rewire and the vendor ledger are
/// committed together, so the failed commit leaves ALL of them as found:
/// the lock untouched, the redirect ledger byte-identical (still claiming
/// only wiring that is still there), no vendor ledger — never a redirect
/// ledger claiming reverted wiring. The run exits 1 with
/// `vendor_commit_failed`. (Before the group commit the takeover persisted
/// the redirect ledger on its own and failed the purl closed with
/// `redirect_ledger_write_failed` before vendoring it.)
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
    assert_eq!(env["error"]["code"], "vendor_commit_failed", "{env:#}");
    assert!(
        env["error"]["message"]
            .as_str()
            .is_some_and(|d| d.contains("could not commit")),
        "{env:#}"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "no vendor rewire is committed"
    );
    assert!(!fx.state_path().exists(), "no vendor ledger is committed");
    assert_eq!(
        std::fs::read(fx.redirect_state_path()).unwrap(),
        ledger_bytes,
        "the unpersistable ledger is left exactly as found"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 8. human-mode error/refusal stderr surfaces (no --json, no --silent)
//
// Section 5 covered the human happy paths; every test here pins one of
// the human-only eprintln lines that ride beside an already-pinned JSON
// contract (same fixture shapes as sections 1–4, human runner).
// ─────────────────────────────────────────────────────────────────────

/// `sha512-…` SRI of `bytes` (same helper shape as the sibling repair and
/// scan-vendor suites): a syntactically VALID integrity so the pristine
/// ladder proceeds past the no-integrity `Unverifiable` refusal and
/// actually attempts the fetch.
fn sri_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest as _, Sha512};
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// Human corrupt-manifest surface: the `Error: could not read manifest`
/// stderr line beside the `invalid_manifest` exit contract section 1 pins
/// under --json.
#[test]
fn human_corrupt_manifest_prints_could_not_read() {
    let fx = npm_fixture();
    std::fs::write(fx.manifest_path(), b"{broken").unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Error: Could not read manifest:"),
        "the human explanation for the flipped exit code: {stderr}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

/// Human corrupt-committed-artifact surface (fresh clone, ledger sha
/// mismatch): the `Cannot vendor …` stderr line still carries the
/// `socket-patch repair` remedy.
#[tokio::test]
async fn human_corrupt_committed_artifact_prints_repair_hint() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    std::fs::write(fx.tgz_path(), b"corrupt bytes").unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor pkg:npm/left-pad@1.3.0:"),
        "stderr names the purl: {stderr}"
    );
    assert!(
        stderr.contains("socket-patch repair"),
        "the human line must carry the repair remedy: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "the summary counts the failure: {stdout}"
    );
}

/// Human registry-fetch-failure surface: a lockfile-resolved missing
/// package whose registry serves a 500 prints the
/// `Cannot vendor …: fetch failed: …` stderr line (the human twin of the
/// `vendor_fetch_failed` event scan_vendor_e2e pins under --json).
#[tokio::test]
async fn human_fetch_failure_prints_fetch_failed() {
    let fx = npm_fixture();
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;
    // Re-point the lock at the mock registry with a VALID SRI: the ladder
    // reaches the download (an SRI-less entry would stop at Unverifiable)
    // and the 500 lands in `PristineFetch::Failed`.
    let mut lock: Value = serde_json::from_slice(&fx.lock_bytes()).unwrap();
    lock["packages"]["node_modules/left-pad"]["resolved"] =
        Value::String(format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()));
    lock["packages"]["node_modules/left-pad"]["integrity"] =
        Value::String(sri_of(b"pristine bytes the mock never serves"));
    std::fs::write(fx.lock_path(), serde_json::to_vec_pretty(&lock).unwrap()).unwrap();

    // Non-offline (the fetch must actually run), anonymous (no other
    // network path opens), human mode (no --json).
    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &["vendor", "--cwd", fx.root().to_str().unwrap()],
        &[("SOCKET_NO_API_TOKEN", "1")],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor pkg:npm/left-pad@1.3.0: fetch failed:"),
        "the human fetch-failure line: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "a fetch failure is counted as failed, not skipped: {stdout}"
    );
    assert!(
        !fx.vendor_dir().exists(),
        "nothing may be vendored from a failed fetch"
    );
}

/// Human corrupt-redirect-ledger surface: the takeover-capable purl's
/// fail-closed refusal prints `Cannot vendor …` with the corruption.
#[test]
fn human_corrupt_redirect_ledger_prints_cannot_vendor() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    std::fs::write(fx.redirect_state_path(), b"garbage").unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor pkg:npm/left-pad@1.3.0:"),
        "stderr names the refused purl: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "the fail-closed refusal is counted: {stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

/// Human unrevertable-redirect surface: a claimed purl whose hosted edits
/// cannot be reverted prints the `cannot revert the hosted redirect` line.
#[test]
fn human_unrevertable_redirect_prints_cannot_revert() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    // Same unrevertable shape as section 3: a rewritten hosted edit with
    // NO recorded original fragment.
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
    std::fs::write(
        fx.redirect_state_path(),
        serde_json::to_vec_pretty(&ledger).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor pkg:npm/left-pad@1.3.0:")
            && stderr.contains("cannot revert the hosted redirect"),
        "the human takeover-refusal line: {stderr}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

/// Human backend-refusal surface: an installed package with NO lockfile of
/// any flavor is a non-benign `vendor_lockfile_missing` refusal — the
/// `Cannot vendor …` stderr line carries the backend's remedy.
#[test]
fn human_lockfile_missing_refusal_prints_cannot_vendor() {
    let fx = npm_fixture();
    std::fs::remove_file(fx.lock_path()).unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Cannot vendor pkg:npm/left-pad@1.3.0:")
            && stderr.contains("vendoring rewires the lockfile"),
        "the refusal detail surfaces verbatim: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "a non-benign refusal is counted as failed: {stdout}"
    );
}

/// Human patch-failure surface: a manifest record with a patch-target file
/// ABSENT from the installed copy (non-empty beforeHash, no --force) fails
/// the staged apply closed; the `Failed to vendor …` stderr line carries
/// the apply diagnostic.
#[test]
fn human_patch_failure_prints_failed_to_vendor() {
    let fx = npm_fixture();
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    let elsewhere = compute_git_sha256_from_bytes(b"bytes the fixture never installed\n");
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(fx.manifest_path()).unwrap()).unwrap();
    manifest["patches"][PURL]["files"]["package/absent.js"] =
        json!({ "beforeHash": elsewhere, "afterHash": after_hash });
    std::fs::write(
        fx.manifest_path(),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Failed to vendor pkg:npm/left-pad@1.3.0:")
            && stderr.contains("File not found"),
        "the human line carries the apply failure: {stderr}"
    );
    assert!(
        stdout.contains("Vendored 0 packages; 1 failed."),
        "the failed patch is counted: {stdout}"
    );
    assert!(
        !fx.tgz_path().exists(),
        "a failed patch must not pack an artifact"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

/// Human corrupt-ledger `--revert` surface: the
/// `Error: Could not read the vendor ledger` stderr line beside
/// the `vendor_state_unreadable` exit contract section 1 pins under --json.
#[test]
fn human_corrupt_state_revert_prints_could_not_read() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    std::fs::write(fx.state_path(), b"not json{").unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Error: Could not read the vendor ledger"),
        "the human explanation for the flipped exit code: {stderr}"
    );
}

/// Human `--revert` failure surface: a ledger entry with no revert backend
/// prints the `Failed to revert <purl>` stderr line, and the summary
/// counts it.
#[tokio::test]
async fn human_revert_failure_prints_failed_to_revert() {
    let fx = npm_fixture();
    write_ledger_entry(fx.root(), "frobnicate").await;

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Failed to revert pkg:npm/left-pad@1.3.0"),
        "stderr names the failed purl: {stderr}"
    );
    assert!(
        stdout.contains("Reverted 0 vendored packages; 1 failed."),
        "the summary counts the failure: {stdout}"
    );
}

/// Human `--revert --dry-run`: the `Would revert` verb, and NOTHING is
/// mutated — the ledger keeps its entry, the wired lock and the artifact
/// stay exactly as vendored.
#[tokio::test]
async fn human_revert_dry_run_prints_would_revert_and_mutates_nothing() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    let state_before = std::fs::read(fx.state_path()).unwrap();
    let wired_lock = fx.lock_bytes();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert", "--dry-run"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Would revert 1 vendored package."),
        "the dry-run verb and count: {stdout}"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_before,
        "a dry revert must not touch the ledger"
    );
    assert_eq!(
        fx.lock_bytes(),
        wired_lock,
        "a dry revert must not touch the wired lock"
    );
    assert!(fx.tgz_path().is_file(), "a dry revert keeps the artifact");
}

/// Human `--dry-run --vex`: the VEX skip line — a dry run vendors nothing,
/// so generating (and verifying the untouched tree) would spuriously fail;
/// the file must NOT be written.
#[test]
fn human_dry_run_with_vex_prints_skip_and_writes_no_vex() {
    let fx = npm_fixture();
    let vex_path = fx.root().join("attestation.vex.json");

    let (code, stdout, stderr) =
        human_vendor(&fx, &["--dry-run", "--vex", vex_path.to_str().unwrap()]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Skipping VEX generation (--dry-run: nothing was vendored)."),
        "the human VEX-skip explanation: {stdout}"
    );
    assert!(
        !vex_path.exists(),
        "no attestation may be written during --dry-run"
    );
}

/// Human run-level classic→berry migration advisory: a classic `yarn.lock`
/// carrying vendored wiring (and no yarn@1 corepack pin) warns on stderr at
/// envelope-finalize time — pinned through the `--revert` no-op path, which
/// exercises the state-based probe without any vendoring in the run itself.
#[test]
fn human_classic_migration_risk_prints_stderr_warning() {
    let fx = npm_fixture();
    std::fs::write(
        fx.root().join("yarn.lock"),
        "# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n  \
         resolved \"file:.socket/vendor/npm/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz\"\n",
    )
    .unwrap();

    let (code, stdout, stderr) = human_vendor(&fx, &["--revert"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Nothing vendored to revert."),
        "the revert itself is the calm no-op: {stdout}"
    );
    assert!(
        stderr.contains("Warning (yarn_classic_berry_migration_risk)"),
        "the run-level advisory prints for humans: {stderr}"
    );
}

// ─────────────── service outage / source-flip idempotence ───────────────
//
// A re-run whose committed artifact the ledger vouches for is
// `already_vendored` whichever source built it and whatever the service
// answers now: exit 0, the lock byte-identical, no service request.

const PACKAGE_PATH: &str = "/v0/orgs/acme/patches/package";

/// `vendor --json` against the mock service at `uri` (authenticated, org
/// `acme`, `--vendor-url` pointed at the mock too).
fn vendor_via_service(root: &Path, uri: &str) -> (i32, Value, String) {
    let args = [
        "vendor",
        "--json",
        "--cwd",
        root.to_str().unwrap(),
        "--api-url",
        uri,
        "--vendor-url",
        uri,
        "--api-token",
        "sktsec_placeholder_value_for_tests_api",
        "--org",
        "acme",
        "--lock-timeout",
        "5",
    ];
    let (code, stdout, stderr) = run_cli(root, &args, &[]);
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("vendor --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (code, env, stderr)
}

fn regzip(tgz: &[u8]) -> Vec<u8> {
    use std::io::{Read as _, Write as _};
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(tgz)
        .read_to_end(&mut raw)
        .unwrap();
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(&raw).unwrap();
    let out = enc.finish().unwrap();
    assert_ne!(out, tgz);
    out
}

async fn mount_granted_artifact(server: &MockServer, leaf: &str, bytes: &[u8]) {
    let serve = format!("/serve/{UUID}/{leaf}");
    let url = format!("{}{serve}", server.uri());
    Mock::given(method("POST"))
        .and(path(PACKAGE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { UUID: { "status": "granted", "url": url,
                "artifacts": [{ "kind": "tarball", "url": url,
                                "integrity": { "sha512": sri_of(bytes) } }] } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(serve))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
        .mount(server)
        .await;
}

async fn mount_outage(server: &MockServer) {
    server.reset().await;
    Mock::given(method("POST"))
        .and(path(PACKAGE_PATH))
        .respond_with(ResponseTemplate::new(503).set_body_string("upstream unavailable"))
        .mount(server)
        .await;
}

async fn package_posts(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == PACKAGE_PATH)
        .count()
}

/// The run-2 contract: exit 0, applied 0, skipped 1, exactly one
/// `already_vendored` event, no outage advisory.
fn assert_already_vendored(code: i32, env: &Value, stderr: &str) {
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    assert_eq!(env["summary"]["skipped"], 1, "{env:#}");
    let in_sync = events(env)
        .iter()
        .filter(|e| e["errorCode"] == "already_vendored")
        .count();
    assert_eq!(in_sync, 1, "{env:#}");
    assert!(
        events(env)
            .iter()
            .all(|e| e["errorCode"] != "vendor_prebuilt_unavailable"),
        "{env:#}"
    );
}

/// Swap an npm fixture's package-lock for a bun.lock project.
fn to_bun(fx: &NpmFixture) {
    std::fs::remove_file(fx.lock_path()).unwrap();
    std::fs::write(
        fx.root().join("package.json"),
        "{\n  \"name\": \"bn3-lockonly\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n",
    )
    .unwrap();
    std::fs::write(
        fx.root().join("bun.lock"),
        r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "bn3-lockonly",
      "dependencies": {
        "left-pad": "1.3.0",
      },
    },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="],
  }
}
"#,
    )
    .unwrap();
}

/// `(fixture, lock file name)` for a flavor.
fn flavor_fixture(bun: bool) -> (NpmFixture, &'static str) {
    let fx = npm_fixture();
    if bun {
        to_bun(&fx);
        (fx, "bun.lock")
    } else {
        (fx, "package-lock.json")
    }
}

/// The service's prebuilt artifact: the local build's members, re-encoded.
fn prebuilt_for(bun: bool) -> Vec<u8> {
    let (probe, _) = flavor_fixture(bun);
    let (code, stdout, stderr) = run_cli(
        probe.root(),
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            probe.root().to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    regzip(&std::fs::read(probe.tgz_path()).unwrap())
}

async fn service_then_outage(bun: bool) {
    let alt = prebuilt_for(bun);
    let (fx, lock) = flavor_fixture(bun);
    let server = MockServer::start().await;
    mount_granted_artifact(&server, "left-pad-1.3.0.tgz", &alt).await;
    let (code, env, stderr) = vendor_via_service(fx.root(), &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    assert_eq!(
        std::fs::read(fx.tgz_path()).unwrap(),
        alt,
        "run 1 used the service"
    );
    let lock1 = std::fs::read(fx.root().join(lock)).unwrap();

    mount_outage(&server).await;
    let (code, env, stderr) = vendor_via_service(fx.root(), &server.uri());
    assert_already_vendored(code, &env, &stderr);
    assert_eq!(
        std::fs::read(fx.root().join(lock)).unwrap(),
        lock1,
        "{lock} unchanged"
    );
    assert_eq!(std::fs::read(fx.tgz_path()).unwrap(), alt);
    assert_eq!(
        package_posts(&server).await,
        0,
        "no service request on the re-run"
    );
}

async fn outage_then_service(bun: bool) {
    let alt = prebuilt_for(bun);
    let (fx, lock) = flavor_fixture(bun);
    let server = MockServer::start().await;
    mount_outage(&server).await;
    let (code, env, stderr) = vendor_via_service(fx.root(), &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    assert!(
        events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_prebuilt_unavailable"),
        "run 1 fell back to a local build: {env:#}"
    );
    let lock1 = std::fs::read(fx.root().join(lock)).unwrap();
    let tgz1 = std::fs::read(fx.tgz_path()).unwrap();

    server.reset().await;
    mount_granted_artifact(&server, "left-pad-1.3.0.tgz", &alt).await;
    let (code, env, stderr) = vendor_via_service(fx.root(), &server.uri());
    assert_already_vendored(code, &env, &stderr);
    assert_eq!(
        std::fs::read(fx.root().join(lock)).unwrap(),
        lock1,
        "{lock} unchanged"
    );
    assert_eq!(std::fs::read(fx.tgz_path()).unwrap(), tgz1);
    assert_eq!(package_posts(&server).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn npm_service_then_outage_rerun_is_already_vendored() {
    service_then_outage(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn npm_outage_then_service_rerun_is_already_vendored() {
    outage_then_service(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_lock_service_then_outage_rerun_is_already_vendored() {
    service_then_outage(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_lock_outage_then_service_rerun_is_already_vendored() {
    outage_then_service(true).await;
}

const PDM_REGISTRY_LOCK: &str = r#"# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default"]
strategy = ["inherit_metadata"]
lock_version = "4.5.0"
content_hash = "sha256:d49d286986c5de41ec9879b6d710389b0be11cd096d883c069123b489ac6e6ea"

[[metadata.targets]]
requires_python = "==3.14.*"

[[package]]
name = "six"
version = "1.16.0"
requires_python = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
summary = "Python 2 and 3 compatibility utilities"
groups = ["default"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"},
    {file = "six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},
]
"#;
const SIX_WHEEL: &str = "six-1.16.0-py2.py3-none-any.whl";

/// A PDM project: pdm.lock pinning registry six, six installed in a
/// project `.venv`, and the manifest + blob for a patch to `six.py`.
fn pdm_fixture() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    const ORIG: &[u8] = b"# six, original\n";
    const PATCHED: &[u8] = b"# six, patched\n";
    std::fs::write(root.join("pdm.lock"), PDM_REGISTRY_LOCK).unwrap();
    let sp = if cfg!(windows) {
        root.join(".venv/Lib/site-packages")
    } else {
        root.join(".venv/lib/python3.12/site-packages")
    };
    let di = sp.join("six-1.16.0.dist-info");
    std::fs::create_dir_all(&di).unwrap();
    std::fs::write(sp.join("six.py"), ORIG).unwrap();
    std::fs::write(
        di.join("METADATA"),
        "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\nbody\n",
    )
    .unwrap();
    std::fs::write(
        di.join("WHEEL"),
        "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n",
    )
    .unwrap();
    std::fs::write(
        di.join("RECORD"),
        "six.py,sha256=AAAA,20\nsix-1.16.0.dist-info/METADATA,,\nsix-1.16.0.dist-info/WHEEL,,\nsix-1.16.0.dist-info/RECORD,,\n",
    )
    .unwrap();
    let before = compute_git_sha256_from_bytes(ORIG);
    let after = compute_git_sha256_from_bytes(PATCHED);
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(&after), PATCHED).unwrap();
    let manifest = json!({ "patches": { "pkg:pypi/six@1.16.0": {
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "six.py": { "beforeHash": before, "afterHash": after } },
        "vulnerabilities": {},
        "description": "synthetic pdm outage test patch",
        "license": "MIT",
        "tier": "free"
    } } });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    tmp
}

fn wheel_path(root: &Path) -> PathBuf {
    root.join(format!(".socket/vendor/pypi/{UUID}/{SIX_WHEEL}"))
}

/// The same wheel members, re-encoded (stored): the service's prebuilt.
fn rezip(whl: &[u8]) -> Vec<u8> {
    use std::io::{Read as _, Write as _};
    let mut src = zip::ZipArchive::new(std::io::Cursor::new(whl)).unwrap();
    let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for i in 0..src.len() {
        let mut entry = src.by_index(i).unwrap();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        out.start_file(entry.name().to_string(), opts).unwrap();
        out.write_all(&bytes).unwrap();
    }
    let alt = out.finish().unwrap().into_inner();
    assert_ne!(alt, whl);
    alt
}

/// PDM relock twin (P1 end to end): vendor from the service, `pdm lock`
/// restores the registry unit, re-vendor during an outage — the committed
/// wheel is re-wired (the service sha, no request), and `rollback` then
/// restores the relocked bytes exactly.
#[tokio::test(flavor = "multi_thread")]
async fn pdm_relock_rescan_under_outage_rewires_the_committed_wheel() {
    use sha2::{Digest as _, Sha256};
    let probe = pdm_fixture();
    let (code, stdout, stderr) = run_cli(
        probe.path(),
        &[
            "vendor",
            "--json",
            "--offline",
            "--cwd",
            probe.path().to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let alt = rezip(&std::fs::read(wheel_path(probe.path())).unwrap());
    let alt_sha = hex::encode(Sha256::digest(&alt));

    let tmp = pdm_fixture();
    let root = tmp.path();
    let server = MockServer::start().await;
    mount_granted_artifact(&server, SIX_WHEEL, &alt).await;
    let (code, env, stderr) = vendor_via_service(root, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "{env:#}");
    let wired = std::fs::read_to_string(root.join("pdm.lock")).unwrap();
    assert!(
        wired.contains(&alt_sha),
        "run 1 pins the service wheel: {wired}"
    );

    // `pdm lock` re-resolves the registry unit.
    std::fs::write(root.join("pdm.lock"), PDM_REGISTRY_LOCK).unwrap();
    mount_outage(&server).await;
    let (code, env, stderr) = vendor_via_service(root, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(
        env["summary"]["applied"], 1,
        "the relock is re-wired: {env:#}"
    );
    assert!(
        events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_artifact_reused"),
        "{env:#}"
    );
    assert!(
        events(&env)
            .iter()
            .all(|e| e["errorCode"] != "vendor_prebuilt_unavailable"),
        "{env:#}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("pdm.lock")).unwrap(),
        wired,
        "the same service sha is pinned again"
    );
    assert_eq!(std::fs::read(wheel_path(root)).unwrap(), alt);
    assert_eq!(package_posts(&server).await, 0);

    let (code, stdout, stderr) = run_cli(
        root,
        &[
            "rollback",
            "--json",
            "--offline",
            "--yes",
            "--cwd",
            root.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert_eq!(
        std::fs::read_to_string(root.join("pdm.lock")).unwrap(),
        PDM_REGISTRY_LOCK,
        "rollback restores the relocked bytes"
    );
}
