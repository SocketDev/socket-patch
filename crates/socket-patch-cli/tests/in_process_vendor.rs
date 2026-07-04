//! In-process + envelope contract tests for `socket-patch vendor` (npm
//! backend, plus the golang apply-yields-to-vendor handshake).
//!
//! The lifecycle tests call `socket_patch_cli::commands::vendor::run(args)`
//! directly (the in-process convention of `in_process_cargo_apply.rs` /
//! `in_process_edge_cases.rs`) and assert exit codes + disk state. The
//! in-process `run()` prints its JSON envelope to the process stdout, which
//! a test cannot capture — so every assertion that needs the envelope JSON
//! itself goes through the built binary (`CARGO_BIN_EXE_socket-patch`) with
//! a fully scrubbed child environment, exactly like the `e2e_*` suites.
//!
//! Hermeticity: every fixture stages its patch blob under `.socket/blobs/`
//! and runs with `--offline`/`offline: true`, so the patch pipeline never
//! touches the network. Subprocess children additionally get every ambient
//! `SOCKET_*` var removed (env-robustness) and `SOCKET_TELEMETRY_DISABLED=1`.
//! No test mutates this process's environment, so none of them need
//! `#[serial]` — each runs in its own tempdir.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socket_patch_cli::args::GlobalArgs;
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

/// Project-relative tarball path the npm backend must produce:
/// `.socket/vendor/<eco>/<patch-uuid>/<name>-<version>.tgz`.
fn rel_tgz() -> String {
    format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
}

// ───────────────────────────── fixture ─────────────────────────────

/// One self-contained npm project: root package.json, a v3 package-lock with
/// a registry-resolved `left-pad` entry, the installed package under
/// node_modules/, and a `.socket/` manifest + after-hash blob so vendor runs
/// fully offline.
struct NpmFixture {
    tmp: tempfile::TempDir,
    /// The lockfile bytes exactly as the fixture wrote them — the
    /// byte-identity oracle for dry-run / revert round-trips.
    original_lock: Vec<u8>,
    /// Manifest bytes as written (vendor must never touch the manifest).
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
    fn lock_value(&self) -> Value {
        serde_json::from_slice(&self.lock_bytes()).expect("lock parses")
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
    fn marker_path(&self) -> PathBuf {
        self.root().join(format!(
            ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
        ))
    }
    fn state_path(&self) -> PathBuf {
        self.root().join(".socket/vendor/state.json")
    }
    fn installed_index(&self) -> PathBuf {
        self.root().join("node_modules/left-pad/index.js")
    }
}

/// The manifest patch record every fixture purl shares (same files map ⇒ one
/// staged blob satisfies the offline source check for all of them).
fn patch_record(before_hash: &str, after_hash: &str) -> Value {
    json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": { "beforeHash": before_hash, "afterHash": after_hash }
        },
        "vulnerabilities": {},
        "description": "synthetic vendor test patch",
        "license": "MIT",
        "tier": "free"
    })
}

/// Build the fixture with a manifest covering `manifest_purls` (each gets an
/// identical record). The installed package + lock entry always describe
/// `left-pad@1.3.0`.
fn npm_fixture_with_purls(manifest_purls: &[&str]) -> NpmFixture {
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
    // so byte-identity assertions across vendor/revert are meaningful.
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

    // Manifest + staged after-hash blob (offline source).
    let before_hash = compute_git_sha256_from_bytes(ORIG_INDEX);
    let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
    let mut patches = serde_json::Map::new();
    for purl in manifest_purls {
        patches.insert(purl.to_string(), patch_record(&before_hash, &after_hash));
    }
    let manifest = json!({ "patches": patches });
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

fn npm_fixture() -> NpmFixture {
    npm_fixture_with_purls(&[PURL])
}

/// In-process `VendorArgs` for the fixture: `json` suppresses interactive
/// prompts/human output, `offline` keeps the patch pipeline on the staged
/// local blobs (no network).
fn vendor_args(cwd: &Path) -> VendorArgs {
    VendorArgs {
        common: GlobalArgs {
            cwd: cwd.to_path_buf(),
            json: true,
            silent: true,
            offline: true,
            // flock guards are OFD-based: when a CONCURRENT test in this
            // binary forks a subprocess, the pre-exec child briefly holds
            // copies of every parent fd — including this test's just-dropped
            // lock fd — so back-to-back in-process runs can see their own
            // lock as "held" for the fork→exec window (observed as rare
            // release-only `lock_held` CI failures in the revert tests). A
            // short wait absorbs the window via the acquire loop's 100 ms
            // retry; a real deadlock still fails after the budget.
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
/// scrubbed from the child (env-robustness: the assertions must reflect the
/// argv, not the developer's shell) and telemetry hard-disabled. Returns
/// `(exit_code, stdout, stderr)`.
fn run_cli(cwd: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args(args).current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") {
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

/// `vendor --json --offline --cwd <cwd> <extra...>` through the binary,
/// returning `(exit_code, parsed envelope)`.
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

/// The single event matching `action` (+ optional `errorCode`), or panic
/// with the envelope.
fn find_event<'a>(envelope: &'a Value, action: &str, error_code: Option<&str>) -> &'a Value {
    events(envelope)
        .iter()
        .find(|e| e["action"] == action && error_code.is_none_or(|c| e["errorCode"] == c))
        .unwrap_or_else(|| {
            panic!("expected a `{action}` event (errorCode={error_code:?}) in:\n{envelope:#}")
        })
}

// ─────────────────────────────────────────────────────────────────────
// 1. end-to-end: vendor an installed npm package
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vendor_npm_end_to_end() {
    let fx = npm_fixture();
    let code = vendor_run(vendor_args(fx.root())).await;
    assert_eq!(code, 0, "vendor must succeed");

    // Artifact: deterministic tarball at the contract path, plus the
    // informational marker beside it.
    assert!(fx.tgz_path().is_file(), "tarball at {}", rel_tgz());
    let marker: Value =
        serde_json::from_slice(&std::fs::read(fx.marker_path()).expect("marker written"))
            .expect("marker is JSON");
    assert_eq!(marker["purl"], PURL);
    assert_eq!(marker["patchUuid"], UUID);
    assert_eq!(marker["ecosystem"], "npm");

    // Ledger: the state entry carries the artifact facts and the VERBATIM
    // pre-vendor lock fragment (revert's only offline source of truth).
    let state: Value =
        serde_json::from_slice(&std::fs::read(fx.state_path()).expect("state.json written"))
            .expect("state.json is JSON");
    let entry = &state["entries"][PURL];
    assert_eq!(entry["ecosystem"], "npm");
    assert_eq!(entry["uuid"], UUID);
    assert_eq!(entry["artifact"]["path"], rel_tgz());
    let tgz = std::fs::read(fx.tgz_path()).unwrap();
    assert_eq!(
        entry["artifact"]["sha256"],
        hex::encode(Sha256::digest(&tgz)),
        "ledger sha256 must describe the tarball actually on disk"
    );
    let wiring = entry["wiring"].as_array().expect("wiring array");
    assert_eq!(wiring.len(), 1, "one rewritten lock instance");
    assert_eq!(wiring[0]["file"], "package-lock.json");
    assert_eq!(wiring[0]["action"], "rewritten");
    assert_eq!(
        wiring[0]["original"]["resolved"], REG_RESOLVED,
        "wiring must record the verbatim pre-vendor resolved URL"
    );
    assert_eq!(wiring[0]["original"]["integrity"], REG_INTEGRITY);

    // Lock rewrite: resolved → relative file: spec carrying the uuid path,
    // integrity → the RECOMPUTED tarball hash (a reused registry integrity
    // would let a warm npm cache install the unpatched bytes); the entry's
    // other fields are byte-preserved.
    let lock = fx.lock_value();
    let live = &lock["packages"]["node_modules/left-pad"];
    assert_eq!(live["resolved"], format!("file:{}", rel_tgz()));
    let integrity = live["integrity"].as_str().expect("integrity string");
    assert!(integrity.starts_with("sha512-"), "sri sha512: {integrity}");
    assert_ne!(integrity, REG_INTEGRITY, "integrity must be recomputed");
    assert_eq!(live["version"], "1.3.0", "version field preserved");
    assert_eq!(live["license"], "WTFPL", "license field preserved");
    // Untouched lock regions stay identical (root project entry).
    let original: Value = serde_json::from_slice(&fx.original_lock).unwrap();
    assert_eq!(lock["packages"][""], original["packages"][""]);

    // The manifest is read-only input; node_modules is NOT patched in place
    // (vendor patches a staged copy and packs it — the installed tree keeps
    // the original bytes until/unless `apply` runs).
    assert_eq!(
        std::fs::read(fx.manifest_path()).unwrap(),
        fx.original_manifest,
        "vendor must not touch the manifest"
    );
    assert_eq!(
        std::fs::read(fx.installed_index()).unwrap(),
        ORIG_INDEX,
        "vendor must not patch node_modules in place"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 2. idempotent re-run
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rerun_is_idempotent() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "first vendor");
    let lock_after_first = fx.lock_bytes();
    let tgz_first = std::fs::read(fx.tgz_path()).unwrap();
    let state_first = std::fs::read(fx.state_path()).unwrap();

    // Second run through the binary so the envelope is observable.
    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "re-run must exit 0: {env:#}");
    assert_eq!(env["status"], "success");
    assert_eq!(
        env["summary"]["applied"], 0,
        "nothing newly applied: {env:#}"
    );
    assert_eq!(env["summary"]["failed"], 0);
    assert_eq!(env["summary"]["skipped"], 1);
    // The in-sync re-run synthesizes its result against the vendored
    // artifact path, which routes to the `vendored` skip reason (the same
    // tag `apply` uses for vendor-owned packages) — pin the actual contract.
    let skipped = find_event(&env, "skipped", Some("already_vendored"));
    assert_eq!(skipped["purl"], PURL);

    // NOTHING on disk churned.
    assert_eq!(fx.lock_bytes(), lock_after_first, "lock byte-stable");
    assert_eq!(
        std::fs::read(fx.tgz_path()).unwrap(),
        tgz_first,
        "tarball byte-stable (deterministic pack)"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_first,
        "ledger byte-stable (no re-recorded originals)"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. --dry-run writes nothing
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dry_run_writes_nothing() {
    let fx = npm_fixture();
    let mut args = vendor_args(fx.root());
    args.common.dry_run = true;
    assert_eq!(vendor_run(args).await, 0, "dry-run must exit 0");

    assert!(
        !fx.vendor_dir().exists(),
        "--dry-run must not create .socket/vendor (no tarball, no state.json)"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock byte-identical");
    assert_eq!(
        std::fs::read(fx.manifest_path()).unwrap(),
        fx.original_manifest
    );
    assert_eq!(std::fs::read(fx.installed_index()).unwrap(), ORIG_INDEX);
}

// ─────────────────────────────────────────────────────────────────────
// 4. vendor → revert round-trip
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn revert_round_trip() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    assert_ne!(
        fx.lock_bytes(),
        fx.original_lock,
        "sanity: vendor actually rewired the lock"
    );

    let mut revert = vendor_args(fx.root());
    revert.revert = true;
    assert_eq!(vendor_run(revert).await, 0, "revert must exit 0");

    // The lock is restored to the EXACT original fixture bytes — revert
    // restores the recorded verbatim fragments, not a re-serialization
    // guess.
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "revert must restore the original lock byte-for-byte"
    );
    // The whole vendor tree is gone — artifacts, marker, state.json, the
    // eco level, and .socket/vendor itself (no empty-dir residue).
    assert!(
        !fx.vendor_dir().exists(),
        ".socket/vendor must be fully pruned after a complete revert"
    );

    // Second revert is a clean no-op: exit 0, ZERO events.
    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 0, "second revert must exit 0: {env:#}");
    assert_eq!(env["status"], "success");
    assert!(
        events(&env).is_empty(),
        "nothing left to revert ⇒ no events: {env:#}"
    );
    assert_eq!(env["summary"]["removed"], 0);
}

// ─────────────────────────────────────────────────────────────────────
// 5. revert works without a manifest
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn revert_works_without_manifest() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);

    // Simulate `remove`/manual deletion: the manifest is gone but the
    // committed ledger + artifacts remain. `--revert` derives everything
    // from state.json and must still restore.
    std::fs::remove_file(fx.manifest_path()).unwrap();

    let mut revert = vendor_args(fx.root());
    revert.revert = true;
    assert_eq!(
        vendor_run(revert).await,
        0,
        "revert must work without a manifest"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
    assert!(!fx.vendor_dir().exists(), "vendor tree removed");
}

// ─────────────────────────────────────────────────────────────────────
// 6. unsupported-ecosystem purls
// ─────────────────────────────────────────────────────────────────────

/// Contract behavior (CLI_CONTRACT.md "Vendor command contract"): a PURL of an
/// ecosystem `vendor` cannot vendor is a benign skip — it never fails the run,
/// and the supported npm patch still vendors. The exemplar is `pkg:jsr/...`
/// (Deno's JSR registry) — the one compiled-in ecosystem with no vendor
/// backend now that nuget and maven vendor (`vendor/path.rs` pins jsr as
/// having no vendor dir by design). The purl is recognized but not
/// vendorable → a `skipped` event carrying `vendor_unsupported_ecosystem`.
///
/// The jsr purl is never `applied`, the npm patch vendors, and the run
/// exits 0.
#[tokio::test]
async fn unsupported_ecosystem_purl_is_a_benign_skip() {
    let fx = npm_fixture_with_purls(&[PURL, "pkg:jsr/@std/path@1.0.0"]);
    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "benign skip must not fail the run: {env:#}");
    assert_eq!(env["status"], "success");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL);
    assert_eq!(env["summary"]["applied"], 1);

    let jsr_event = events(&env)
        .iter()
        .find(|e| e["purl"].as_str().is_some_and(|p| p.contains("jsr")))
        .cloned();
    // The jsr purl is never vendored.
    assert!(
        jsr_event.as_ref().is_none_or(|e| e["action"] != "applied"),
        "jsr purl must never be applied: {env:#}"
    );

    // Recognized but not vendorable ⇒ an explicit, informative skip.
    let ev = jsr_event.expect("jsr purl must produce an explicit skip event");
    assert_eq!(ev["action"], "skipped", "{env:#}");
    assert_eq!(ev["errorCode"], "vendor_unsupported_ecosystem", "{env:#}");

    assert!(fx.tgz_path().is_file(), "the npm patch still vendors");
}

// ─────────────────────────────────────────────────────────────────────
// 7. package not installed
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn package_not_installed_fails() {
    // The manifest names a package that is nowhere in node_modules. The
    // user asked for it to be vendored and it wasn't — that is a partial
    // failure (exit 1), surfaced as a skipped event with the stable code.
    let fx = npm_fixture_with_purls(&["pkg:npm/ghost-pkg@9.9.9"]);
    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(
        code, 1,
        "an unsatisfiable manifest entry must exit 1: {env:#}"
    );
    assert_eq!(env["status"], "partialFailure");
    let skipped = find_event(&env, "skipped", Some("package_not_installed"));
    assert_eq!(skipped["purl"], "pkg:npm/ghost-pkg@9.9.9");
    assert!(
        !fx.vendor_dir().exists(),
        "nothing may be written for a package that isn't installed"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

// ─────────────────────────────────────────────────────────────────────
// 8. reconcile: entries dropped from the manifest are auto-reverted
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reconcile_drops_stale_entries() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    assert!(fx.tgz_path().is_file());

    // The patch is dropped from the manifest (e.g. `remove --skip-rollback`
    // ran, which deliberately leaves the vendoring in place, or the manifest
    // was hand-edited). The next vendor run must revert the now-stale entry
    // even though zero in-scope patches remain.
    std::fs::write(fx.manifest_path(), b"{\"patches\": {}}\n").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "reconcile-only run must exit 0: {env:#}");
    let removed = find_event(&env, "removed", Some("vendor_reconciled"));
    assert_eq!(removed["purl"], PURL);

    assert!(
        !fx.vendor_dir().exists(),
        "the stale artifact (and the emptied vendor tree) must be gone"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock must be restored to the pre-vendor registry fragment"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 8b. reconcile: detached entries are exempt
// ─────────────────────────────────────────────────────────────────────

/// A detached entry (`scan --vendor --detached`) is never manifest-tracked,
/// so "absent from the manifest" is its normal state — reconcile must leave
/// it alone. Only `vendor --revert` or `remove` may undo it.
#[tokio::test]
async fn reconcile_leaves_detached_entries_alone() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    let wired_lock = fx.lock_bytes();

    // Mark the entry detached (the shape `scan --vendor --detached` writes)
    // and drop the patch from the manifest.
    let mut state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap())
        .expect("state.json is JSON");
    state["entries"][PURL]["detached"] = json!(true);
    std::fs::write(fx.state_path(), serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    std::fs::write(fx.manifest_path(), b"{\"patches\": {}}\n").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "detached-only run must exit 0: {env:#}");
    assert!(
        !events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_reconciled"),
        "a detached entry must never be reconcile-reverted: {env:#}"
    );
    assert!(fx.tgz_path().is_file(), "artifact must survive");
    assert_eq!(fx.lock_bytes(), wired_lock, "wiring must survive");
    let state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    assert!(
        state["entries"][PURL].is_object(),
        "ledger entry must survive: {state:#}"
    );

    // `--revert` is still the detached entry's exit path.
    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 0, "revert must undo detached entries: {env:#}");
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
    assert!(!fx.vendor_dir().exists(), "vendor tree removed");
}

// ─────────────────────────────────────────────────────────────────────
// 8c. re-vendor under a new patch uuid
// ─────────────────────────────────────────────────────────────────────

/// Re-vendoring after the manifest moved to a newer patch uuid (the
/// `scan --vendor` auto-update path) must (a) rewire the lock at the new
/// uuid, (b) remove the old uuid's now-orphaned artifact dir, and (c) carry
/// the pre-vendor lock fragment forward so a later `--revert` still
/// restores the registry spelling byte-for-byte.
#[tokio::test]
async fn revendor_new_uuid_cleans_stale_artifact_and_still_reverts() {
    const UUID2: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    let old_uuid_dir = fx.root().join(format!(".socket/vendor/npm/{UUID}"));
    assert!(old_uuid_dir.is_dir());

    // The manifest record moves to a newer patch uuid (same files/hashes —
    // the staged blob is keyed by content hash, not uuid).
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(fx.manifest_path()).unwrap()).unwrap();
    manifest["patches"][PURL]["uuid"] = json!(UUID2);
    std::fs::write(
        fx.manifest_path(),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "re-vendor must succeed: {env:#}");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL);
    let stale = find_event(&env, "removed", Some("vendor_stale_artifact_removed"));
    assert_eq!(stale["purl"], PURL);

    assert!(
        !old_uuid_dir.exists(),
        "the old uuid's artifact dir is an orphan and must be removed"
    );
    let new_tgz = fx
        .root()
        .join(format!(".socket/vendor/npm/{UUID2}/left-pad-1.3.0.tgz"));
    assert!(new_tgz.is_file(), "artifact re-vendored under the new uuid");
    let state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    assert_eq!(state["entries"][PURL]["uuid"], UUID2);
    let lock_text = String::from_utf8(fx.lock_bytes()).unwrap();
    assert!(
        lock_text.contains(UUID2) && !lock_text.contains(UUID),
        "lock must point at the new uuid only"
    );

    // The pre-vendor registry fragment was recorded by the FIRST vendor run;
    // the re-vendor rewrote our own wiring (original: None from the backend)
    // and must have carried the true original forward.
    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 0, "revert after re-vendor must succeed: {env:#}");
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "revert must restore the pre-vendor registry fragment byte-for-byte"
    );
    assert!(!fx.vendor_dir().exists(), "vendor tree fully pruned");
}

// ─────────────────────────────────────────────────────────────────────
// 9. offline with no local source
// ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn offline_missing_source_fails() {
    let fx = npm_fixture();
    // Remove the staged blob: offline + no blob/diff/package ⇒ the patch has
    // no usable local source and vendor must fail loudly, not guess.
    std::fs::remove_file(fx.root().join(".socket/blobs").join(&fx.after_hash)).unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "offline with no local source must exit 1: {env:#}");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "no_local_source");
    assert!(
        !fx.vendor_dir().exists(),
        "a failed staging must write nothing"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

// ─────────────────────────────────────────────────────────────────────
// 10a. apply after vendor — npm yields with skipped/vendored
// ─────────────────────────────────────────────────────────────────────

/// Apply yields to vendor for EVERY ecosystem (CLI_CONTRACT.md): a purl
/// recorded in `.socket/vendor/state.json` is skipped with reason
/// `vendored` — the committed artifact + lock wiring are the patch, so an
/// in-place re-patch of node_modules is redundant at best and fights the
/// vendor lifecycle at worst. Installed tree, lock, and artifact must all
/// be byte-untouched.
#[tokio::test]
async fn vendored_npm_purl_skipped_by_apply() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    let lock_after_vendor = fx.lock_bytes();
    let tgz_after_vendor = std::fs::read(fx.tgz_path()).unwrap();
    assert_eq!(std::fs::read(fx.installed_index()).unwrap(), ORIG_INDEX);

    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &[
            "apply",
            "--json",
            "--offline",
            "--cwd",
            fx.root().to_str().unwrap(),
        ],
        &[],
    );
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("apply --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "apply after vendor exits 0: {env:#}");
    assert_eq!(env["status"], "success");
    let skipped = find_event(&env, "skipped", Some("vendored"));
    assert_eq!(skipped["purl"], PURL);
    assert_eq!(env["summary"]["applied"], 0);

    assert_eq!(
        std::fs::read(fx.installed_index()).unwrap(),
        ORIG_INDEX,
        "apply must not re-patch a vendor-owned installed tree"
    );
    assert_eq!(
        fx.lock_bytes(),
        lock_after_vendor,
        "apply must not disturb the vendored lock wiring"
    );
    assert_eq!(
        std::fs::read(fx.tgz_path()).unwrap(),
        tgz_after_vendor,
        "apply must not touch the vendored artifact"
    );
}

/// The wiped-tree variant: with node_modules gone entirely, a vendored
/// purl must STILL surface as `skipped`/`vendored` (exit 0) — never as
/// `package_not_installed` — because the committed artifact is the source
/// of truth, not the installed tree.
#[tokio::test]
async fn vendored_npm_purl_skipped_even_without_installed_tree() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();

    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &[
            "apply",
            "--json",
            "--offline",
            "--cwd",
            fx.root().to_str().unwrap(),
        ],
        &[],
    );
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("apply --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(
        code, 0,
        "vendored purl with no installed tree must exit 0: {env:#}"
    );
    assert_eq!(env["status"], "success");
    let skipped = find_event(&env, "skipped", Some("vendored"));
    assert_eq!(skipped["purl"], PURL);
    assert!(
        !events(&env)
            .iter()
            .any(|e| e["errorCode"] == "package_not_installed"),
        "vendored must win over package_not_installed: {env:#}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 10a′. rollback after vendor — vendored purls are excluded
// ─────────────────────────────────────────────────────────────────────

/// `rollback` excludes vendor-owned purls from in-place restoration: the
/// patch lives in the committed artifact + lock wiring, so before-blob
/// restoration has nothing to restore (and would only hash-mismatch).
/// The skip is benign (exit 0) and surfaced in the JSON `vendored` array;
/// an identifier that targets ONLY a vendored purl is still exit 0, not
/// `not_found`.
#[tokio::test]
async fn vendored_purl_excluded_from_rollback() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    let lock_after_vendor = fx.lock_bytes();

    for extra in [&[][..], &[PURL][..]] {
        let mut argv = vec![
            "rollback",
            "--json",
            "--offline",
            "--cwd",
            fx.root().to_str().unwrap(),
        ];
        argv.extend_from_slice(extra);
        let (code, stdout, stderr) = run_cli(fx.root(), &argv, &[]);
        let out: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("rollback --json must emit JSON: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        });
        assert_eq!(code, 0, "vendored-only rollback exits 0: {out:#}");
        assert_eq!(out["status"], "success", "{out:#}");
        assert_eq!(
            out["vendored"],
            json!([PURL]),
            "vendored skip must be surfaced: {out:#}"
        );
        assert_eq!(out["rolledBack"], 0, "{out:#}");
        assert_eq!(out["failed"], 0, "{out:#}");
    }

    assert_eq!(
        std::fs::read(fx.installed_index()).unwrap(),
        ORIG_INDEX,
        "rollback must not touch the installed tree of a vendored purl"
    );
    assert_eq!(
        fx.lock_bytes(),
        lock_after_vendor,
        "rollback must not disturb the vendored lock wiring"
    );
    assert!(fx.tgz_path().is_file(), "artifact untouched");
}

// ─────────────────────────────────────────────────────────────────────
// 10a″. remove after vendor — vendoring is reverted
// ─────────────────────────────────────────────────────────────────────

/// `remove` on a vendored purl reverts the vendoring (lock restored
/// byte-for-byte, artifact + ledger entry gone) in addition to deleting
/// the manifest entry — one command, patch fully gone. The reverted purl
/// rides the envelope as `removed`/`vendor_reverted` WITHOUT bumping
/// `summary.removed` (that count stays "manifest entries deleted").
#[tokio::test]
async fn remove_reverts_vendoring() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);

    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &[
            "remove",
            PURL,
            "--json",
            "--offline",
            "--yes",
            "--cwd",
            fx.root().to_str().unwrap(),
        ],
        &[],
    );
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("remove --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "remove of a vendored purl exits 0: {env:#}");
    assert_eq!(env["status"], "success");
    let reverted = find_event(&env, "removed", Some("vendor_reverted"));
    assert_eq!(reverted["purl"], PURL);
    assert_eq!(
        env["summary"]["removed"], 1,
        "summary.removed counts manifest entries only: {env:#}"
    );

    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "remove must restore the pre-vendor lock byte-for-byte"
    );
    assert!(!fx.vendor_dir().exists(), "vendor tree fully removed");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(fx.manifest_path()).unwrap()).unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "manifest entry removed: {manifest:#}"
    );
}

/// `--skip-rollback` promises "don't touch my tree": the vendor wiring and
/// artifact stay in place (surfaced as `skipped`/`vendor_state_retained`),
/// only the manifest entry goes. The next plain `vendor` run then
/// reconcile-reverts the dropped entry.
#[tokio::test]
async fn remove_skip_rollback_retains_vendoring() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);
    let wired_lock = fx.lock_bytes();

    let (code, stdout, _stderr) = run_cli(
        fx.root(),
        &[
            "remove",
            PURL,
            "--json",
            "--offline",
            "--yes",
            "--skip-rollback",
            "--cwd",
            fx.root().to_str().unwrap(),
        ],
        &[],
    );
    let env: Value = serde_json::from_str(&stdout).expect("envelope");
    assert_eq!(code, 0, "{env:#}");
    let retained = find_event(&env, "skipped", Some("vendor_state_retained"));
    assert_eq!(retained["purl"], PURL);
    assert!(
        !events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_reverted"),
        "--skip-rollback must not revert: {env:#}"
    );

    assert_eq!(fx.lock_bytes(), wired_lock, "wiring untouched");
    assert!(fx.tgz_path().is_file(), "artifact untouched");
    let state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    assert!(state["entries"][PURL].is_object(), "ledger entry retained");

    // The dropped-from-manifest entry is now reconcile-reverted by the
    // next plain vendor run (completing the two-step lifecycle).
    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    find_event(&env, "removed", Some("vendor_reconciled"));
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

/// A detached vendored patch has no manifest entry; `remove <purl>` must
/// still find it in the ledger, revert it, and exit 0 — not `not_found`.
/// Here the revert IS the removal, so it bumps `summary.removed`.
#[tokio::test]
async fn remove_detached_only_purl_reverts() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0);

    // Detach the entry and drop the manifest record (the state a
    // `scan --vendor --detached` run leaves behind).
    let mut state: Value =
        serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    state["entries"][PURL]["detached"] = json!(true);
    std::fs::write(fx.state_path(), serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    std::fs::write(fx.manifest_path(), b"{\"patches\": {}}\n").unwrap();

    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &[
            "remove",
            PURL,
            "--json",
            "--offline",
            "--yes",
            "--cwd",
            fx.root().to_str().unwrap(),
        ],
        &[],
    );
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("remove --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "detached purl must be removable: {env:#}");
    assert_eq!(env["status"], "success");
    let reverted = find_event(&env, "removed", Some("vendor_reverted"));
    assert_eq!(reverted["purl"], PURL);
    assert_eq!(env["summary"]["removed"], 1, "{env:#}");

    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
    assert!(!fx.vendor_dir().exists(), "vendor tree removed");
}

// ─────────────────────────────────────────────────────────────────────
// 10b. apply after vendor — golang yields with skipped/vendored
// ─────────────────────────────────────────────────────────────────────

/// The golang half of "apply yields to vendor" (CLI_CONTRACT.md): a module
/// recorded in `.socket/vendor/state.json` must be skipped by `apply` with
/// reason `vendored` — apply must never repoint the vendor-owned `replace`
/// back at `.socket/go-patches/`. The ledger entry is seeded by hand (the
/// exact state `vendor` persists) so the test needs no full go vendor run.
#[tokio::test]
async fn vendored_golang_purl_skipped_by_apply() {
    use socket_patch_core::patch::vendor::state::{VendorArtifact, VendorEntry, VendorState};

    const MODULE: &str = "github.com/foo/bar";
    const VERSION: &str = "v1.4.2";
    let purl = format!("pkg:golang/{MODULE}@{VERSION}");
    const PRISTINE: &[u8] = b"package bar\n\nfunc Hello() string { return \"hi\" }\n";
    const GO_PATCHED: &[u8] = b"package bar\n\nfunc Hello() string { return \"PATCHED\" }\n";

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();

    // Fake extracted module cache (the crawler's discovery source).
    let cache_dir = root.join("modcache").join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(cache_dir.join("bar.go"), PRISTINE).unwrap();
    std::fs::write(
        cache_dir.join("go.mod"),
        "module github.com/foo/bar\n\ngo 1.21\n",
    )
    .unwrap();

    // Consumer go.mod carrying the vendor-owned replace, exactly as the
    // vendor backend wires it.
    let replace_target = format!("./.socket/vendor/golang/{UUID}/{MODULE}@{VERSION}");
    let gomod = format!(
        "module example.com/app\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n\n\
         replace {MODULE} {VERSION} => {replace_target}\n"
    );
    std::fs::write(root.join("go.mod"), &gomod).unwrap();

    // Manifest + offline blob for the golang patch.
    let before_hash = compute_git_sha256_from_bytes(PRISTINE);
    let after_hash = compute_git_sha256_from_bytes(GO_PATCHED);
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = json!({
        "patches": {
            purl.clone(): {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { "bar.go": { "beforeHash": before_hash, "afterHash": after_hash } },
                "vulnerabilities": {},
                "description": "synthetic", "license": "MIT", "tier": "free"
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(&after_hash), GO_PATCHED).unwrap();

    // Seed the ledger with the golang entry (what a `vendor` run records).
    let mut state = VendorState::new();
    state.entries.insert(
        purl.clone(),
        VendorEntry {
            ecosystem: "golang".to_string(),
            base_purl: purl.clone(),
            uuid: UUID.to_string(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/golang/{UUID}/{MODULE}@{VERSION}"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
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
    socket_patch_core::patch::vendor::save_state(root, &state)
        .await
        .expect("seed state.json");

    // apply (through the binary: scrubbed env + child-only GOMODCACHE).
    let (code, stdout, stderr) = run_cli(
        root,
        &[
            "apply",
            "--json",
            "--offline",
            "--ecosystems",
            "golang",
            "--cwd",
            root.to_str().unwrap(),
        ],
        &[("GOMODCACHE", root.join("modcache").to_str().unwrap())],
    );
    let env: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("apply --json envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(code, 0, "apply must succeed while yielding: {env:#}");
    assert_eq!(env["status"], "success");
    let skipped = find_event(&env, "skipped", Some("vendored"));
    assert_eq!(skipped["purl"], purl);

    // Apply must not have re-pointed the replace or materialised a
    // go-patches redirect.
    assert_eq!(
        std::fs::read_to_string(root.join("go.mod")).unwrap(),
        gomod,
        "go.mod must be byte-unchanged (the vendor-owned replace stays)"
    );
    assert!(
        !root.join(".socket/go-patches").exists(),
        "apply must not materialise a go-patches redirect for a vendored module"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 11. lock contention
// ─────────────────────────────────────────────────────────────────────

#[test]
fn lock_contention_exits_lock_held() {
    let fx = npm_fixture();
    // Hold the same advisory lock `vendor` takes (`<.socket>/apply.lock`);
    // vendor shares it with apply/rollback so an apply↔vendor race is
    // impossible. flock contention is cross-process, so the child binary
    // genuinely contends with this test's guard.
    let _guard = socket_patch_core::patch::apply_lock::acquire(
        &fx.root().join(".socket"),
        std::time::Duration::ZERO,
    )
    .expect("test holds the lock first");

    let (code, env) = vendor_cli(fx.root(), &["--lock-timeout", "1"]);
    assert_eq!(code, 1, "contended vendor must exit 1: {env:#}");
    assert_eq!(
        env["command"], "vendor",
        "the failure envelope is vendor's own"
    );
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "lock_held");
    assert!(
        events(&env).is_empty(),
        "a pre-event failure carries no events: {env:#}"
    );

    // Nothing happened while contended.
    assert!(
        !fx.vendor_dir().exists(),
        "no vendor writes under contention"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

// ─────────────────────────────────────────────────────────────────────
// 12. JSON envelope shape
// ─────────────────────────────────────────────────────────────────────

#[test]
fn json_envelope_shape() {
    // Wet run.
    let fx = npm_fixture();
    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["command"], "vendor");
    assert_eq!(env["status"], "success");
    assert_eq!(env["dryRun"], false, "dryRun mirrors the (absent) flag");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL);
    assert_eq!(
        applied["files"][0]["path"], "package/index.js",
        "applied event enumerates the patched files"
    );
    // The pre-aggregated summary carries every counter field.
    let summary = env["summary"].as_object().expect("summary object");
    for field in [
        "discovered",
        "downloaded",
        "applied",
        "updated",
        "skipped",
        "failed",
        "removed",
        "verified",
    ] {
        assert!(
            summary.contains_key(field),
            "summary.{field} present: {env:#}"
        );
    }
    assert_eq!(env["summary"]["applied"], 1);
    assert_eq!(env["summary"]["failed"], 0);

    // Dry run on a fresh fixture: dryRun flips, the patch is Verified (not
    // Applied), and the envelope is still command=vendor.
    let fx2 = npm_fixture();
    let (code, env) = vendor_cli(fx2.root(), &["--dry-run"]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["command"], "vendor");
    assert_eq!(env["dryRun"], true, "dryRun mirrors --dry-run");
    assert_eq!(env["status"], "success");
    find_event(&env, "verified", None);
    assert_eq!(env["summary"]["verified"], 1);
    assert_eq!(env["summary"]["applied"], 0);

    // No manifest at all: same contract as apply — clean no-op, exit 0,
    // status noManifest (the envelope still identifies the command).
    let empty = tempfile::tempdir().unwrap();
    let (code, env) = vendor_cli(empty.path(), &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(env["command"], "vendor");
    assert_eq!(env["status"], "noManifest");
    assert!(events(&env).is_empty());
}

// ──────────────── vendor auto-force + already-applied lifecycle ────────────────

/// A package already patched IN PLACE by `apply` must vendor cleanly on the
/// first run — and the envelope must report it as `applied` (this run packed
/// the artifact and rewired the lock), NOT `skipped/already_vendored`. The
/// second run is the true in-sync rerun and reports `already_vendored`.
#[test]
fn vendor_after_in_place_apply_emits_applied_event() {
    let fx = npm_fixture();
    // Simulate a prior in-place `socket-patch apply`.
    std::fs::write(fx.installed_index(), PATCHED_INDEX).unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL);
    assert_eq!(
        env["summary"]["applied"], 1,
        "first vendor of an applied package counts as applied: {env:#}"
    );
    assert!(fx.tgz_path().exists(), "artifact packed");
    assert!(fx.state_path().exists(), "ledger entry recorded");
    // No mismatch warning: afterHash content is AlreadyPatched, not divergent.
    assert!(
        !events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_content_mismatch_overwritten"),
        "{env:#}"
    );

    // Second run: artifact + wiring already in sync.
    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    find_event(&env, "skipped", Some("already_vendored"));
    assert_eq!(env["summary"]["applied"], 0);
}

/// Installed content matching NEITHER hash (a patch built against different
/// bytes than the installed artifact — the flatted@3.3.1 case) still vendors:
/// the stage is overwritten with the verified patched content, the run exits
/// 0 with an `applied` event, and the overwrite surfaces as a
/// `vendor_content_mismatch_overwritten` warning event.
#[test]
fn mismatched_baseline_vendors_with_warning_event() {
    let fx = npm_fixture();
    std::fs::write(
        fx.installed_index(),
        b"module.exports = () => 'divergent';\n",
    )
    .unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL);
    let warning = find_event(&env, "skipped", Some("vendor_content_mismatch_overwritten"));
    assert!(
        warning["reason"]
            .as_str()
            .unwrap_or("")
            .contains("left-pad@1.3.0"),
        "warning names the package: {env:#}"
    );
    assert!(
        fx.tgz_path().exists(),
        "artifact packed despite the mismatch"
    );
    // The installed tree keeps its divergent bytes (only the stage changed).
    assert_eq!(
        std::fs::read(fx.installed_index()).unwrap(),
        b"module.exports = () => 'divergent';\n"
    );
}

/// A patch-target file MISSING from the installed package still fails closed
/// (auto-force must not inherit `--force`'s silent NotFound skip — the
/// tarball would ship without the fix); `--force` keeps that tolerance.
#[test]
fn vendor_missing_file_fails_closed_without_force() {
    let fx = npm_fixture();
    std::fs::remove_file(fx.installed_index()).unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_ne!(code, 0, "missing patch target must fail: {env:#}");
    let failed = find_event(&env, "failed", None);
    assert!(
        failed["error"]
            .as_str()
            .unwrap_or("")
            .contains("File not found"),
        "{env:#}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock byte-untouched");
    assert!(!fx.vendor_dir().exists(), "no artifacts on failure");

    // --force: the missing file is tolerated (skipped) and the vendor lands.
    let fx2 = npm_fixture();
    std::fs::remove_file(fx2.installed_index()).unwrap();
    let (code, env) = vendor_cli(fx2.root(), &["--force"]);
    assert_eq!(code, 0, "{env:#}");
}

// ──────────────── percent-encoded scoped purls (Fix A integration) ────────────────

/// Build a fixture whose installed package is the SCOPED `@scope/left-pad`
/// while the manifest keys the patch by the API's percent-encoded purl
/// (`pkg:npm/%40scope/left-pad@1.3.0`) — exactly what `scan` writes.
fn npm_scoped_fixture() -> NpmFixture {
    let fx = npm_fixture_with_purls(&["pkg:npm/%40scope/left-pad@1.3.0"]);
    let root = fx.root();

    // Re-home the installed package under the scope dir.
    let scoped = root.join("node_modules/@scope/left-pad");
    std::fs::create_dir_all(scoped.parent().unwrap()).unwrap();
    std::fs::rename(root.join("node_modules/left-pad"), &scoped).unwrap();
    std::fs::write(
        scoped.join("package.json"),
        br#"{"name":"@scope/left-pad","version":"1.3.0"}"#,
    )
    .unwrap();

    // Re-key the lock entry to the scoped install path.
    let mut lock: Value = serde_json::from_slice(&fx.original_lock).unwrap();
    let packages = lock["packages"].as_object_mut().unwrap();
    let entry = packages.remove("node_modules/left-pad").unwrap();
    packages.insert("node_modules/@scope/left-pad".to_string(), entry);
    lock["packages"][""]["dependencies"] = json!({ "@scope/left-pad": "^1.3.0" });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &lock_bytes).unwrap();

    fx
}

/// The API serves scoped purls percent-encoded and `scan` stores them
/// verbatim as manifest keys; vendor must decode them to find the installed
/// `node_modules/@scope/...` package and wire the lock — while the ledger
/// stays keyed by the verbatim encoded purl (manifest parity).
#[test]
fn vendor_resolves_percent_encoded_scope_purl() {
    let fx = npm_scoped_fixture();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], "pkg:npm/%40scope/left-pad@1.3.0");

    // Artifact lands under the DECODED scope dir.
    let tgz = fx.root().join(format!(
        ".socket/vendor/npm/{UUID}/@scope/left-pad-1.3.0.tgz"
    ));
    assert!(tgz.exists(), "tarball at the decoded scoped path");

    // Lock rewired to the vendored artifact.
    let lock = fx.lock_value();
    assert_eq!(
        lock["packages"]["node_modules/@scope/left-pad"]["resolved"],
        json!(format!(
            "file:.socket/vendor/npm/{UUID}/@scope/left-pad-1.3.0.tgz"
        ))
    );

    // Ledger keyed by the VERBATIM encoded purl (manifest key parity).
    let state: Value = serde_json::from_slice(&std::fs::read(fx.state_path()).unwrap()).unwrap();
    assert!(
        state["entries"]["pkg:npm/%40scope/left-pad@1.3.0"].is_object(),
        "state keyed by the encoded manifest purl: {state:#}"
    );

    // Round-trip: revert restores the original (scoped) lock bytes.
    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 0, "{env:#}");
    let lock = fx.lock_value();
    assert_eq!(
        lock["packages"]["node_modules/@scope/left-pad"]["resolved"],
        json!(REG_RESOLVED)
    );
    assert!(!fx.vendor_dir().join("npm").exists(), "artifacts removed");
}

// ─────────────────────────────────────────────────────────────────────
// 11. --dry-run --vex: skipped, not generated
// ─────────────────────────────────────────────────────────────────────

/// A dry run vendors nothing, so there is no vendored state to attest:
/// generating VEX here verified the deliberately untouched tree, spuriously
/// failed the whole command with `no_applicable_patches`, and would write an
/// attestation file during --dry-run (the same contract `apply --dry-run
/// --vex` already honors by skipping generation).
#[tokio::test]
async fn dry_run_vex_is_skipped_not_generated() {
    let fx = npm_fixture();
    let vex_path = fx.root().join("vendor-dry.vex.json");
    let mut args = vendor_args(fx.root());
    args.common.dry_run = true;
    args.vex.vex = Some(vex_path.clone());

    let code = vendor_run(args).await;
    assert_eq!(code, 0, "vendor --dry-run --vex must not fail");
    assert!(
        !vex_path.exists(),
        "--dry-run must never write an attestation file"
    );
    // The dry run itself stayed read-only.
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
    assert!(!fx.vendor_dir().exists(), "no artifacts staged");
}

// ─────────────────────────────────────────────────────────────────────
// 12. fail-closed --vendor-source=service refuses --offline
// ─────────────────────────────────────────────────────────────────────

/// `--vendor-source=service` promises "prebuilt service artifacts only",
/// and `--offline` forbids the network the service needs — the combination
/// can never be satisfied. It must refuse up front; silently falling back
/// to a local build (what `service_enabled() == false` otherwise causes in
/// every backend) violates the fail-closed contract.
#[tokio::test]
async fn offline_service_mode_refuses_instead_of_building() {
    let fx = npm_fixture();
    let mut args = vendor_args(fx.root());
    args.common.vendor_source = "service".to_string();

    let code = vendor_run(args).await;
    assert_ne!(
        code, 0,
        "--offline --vendor-source=service cannot be satisfied and must refuse"
    );
    assert!(
        !fx.tgz_path().exists(),
        "service mode must not silently build a local artifact"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}
