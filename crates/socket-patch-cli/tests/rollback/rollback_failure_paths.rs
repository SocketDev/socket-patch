//! `rollback`'s `--json` contracts for the paths the rest of the suite
//! never drove (#1089): exit code, `status`, `error.code`, `events[]`,
//! `warnings[]` codes and the bytes on disk. A message is read only for
//! what it must name (an ecosystem, a path, a remedy). The human output of
//! the same paths is pinned in `rollback_render.rs`.
//!
//!   1. boundary errors: a corrupt manifest, `.socket/blobs` as a file, a
//!      ledger-less but wired lock, lock contention and the manifest
//!      vanishing under a held lock;
//!   2. agent-leg scope: the out-of-scope multi-copy warning, a directory
//!      squatting a blob hash, a Bun store entry the project moved off, a
//!      PyPI variant group with no installed match and a discovered
//!      local-go redirect;
//!   3. the vendored leg: an unknown backend, a corrupt ledger, a ledger
//!      save failure, `--ecosystems` and path scoping, qualifier bridging
//!      and identifier isolation;
//!   4. the hosted leg: per-pin refusals, pre-v5 ledger retirement,
//!      `--ecosystems` and path scoping, a lockfile write failure and the
//!      Bun hoisted-copy warning;
//!   5. GC failures (unix) and a manifest write failure (macOS) warn.

use serde_json::{json, Value};

use crate::common;
use crate::common::envelope::{
    envelope_error_code, envelope_error_message, json_string, parse_json_envelope, warning_codes,
};
use crate::common::git_sha256;
use crate::rollback_fixture::*;
use crate::rollback_json;

/// A syntactically invalid manifest is the top-level `manifest_invalid`
/// error, exit 1. Its human `Error:` line is in `rollback_render.rs`.
#[test]
fn corrupt_manifest_is_manifest_invalid() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), b"{ not json").expect("write corrupt manifest");

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline"]);
    assert_eq!(
        code, 1,
        "a corrupt manifest must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&v, "status"),
        Some("error"),
        "stdout=\n{stdout}"
    );
    assert_eq!(
        envelope_error_code(&v),
        Some("manifest_invalid"),
        "stdout=\n{stdout}"
    );
}

/// `.socket/blobs` existing as a regular FILE is corrupt state the inner
/// pipeline refuses up front (its wet-run shape probe; the directory itself
/// is only ever created by the blob download) — the boundary maps that to
/// the legacy `{status: "error", rolledBack: 0, vendored: [], results: []}`
/// envelope, exit 1. The human `Error:` line is in `rollback_render.rs`.
#[test]
fn blobs_path_as_file_yields_legacy_error_envelope() {
    let tmp = blobs_path_as_file_fixture();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "the inner Err must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|e| !e.is_empty()),
        "the envelope carries the io error; stdout=\n{stdout}"
    );
    assert_eq!(v["summary"]["rolledBack"], 0, "stdout=\n{stdout}");
    assert_eq!(v["summary"]["failed"], 0, "stdout=\n{stdout}");
    assert_eq!(v["command"], "rollback", "stdout=\n{stdout}");
    assert_eq!(
        v["events"],
        json!([]),
        "a full error envelope; stdout=\n{stdout}"
    );
}

/// Multi-copy contract meets path scoping: rollback restores EVERY
/// installed copy of a selected patch, and when some restored copy lives
/// outside the given paths the run says so via the
/// `out_of_scope_copies_restored` warning (singular grammar pinned).
#[test]
fn path_scope_warns_about_out_of_scope_restored_copies() {
    let before: &[u8] = b"dup-original\n";
    let after: &[u8] = b"dup-patched\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/covgap-dup@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // The SAME name@version installed twice: root + nested workspace copy.
    let root_copy = install_npm_pkg(tmp.path(), "node_modules", "covgap-dup", "1.0.0", after);
    let nested_copy = install_npm_pkg(
        tmp.path(),
        "packages/app/node_modules",
        "covgap-dup",
        "1.0.0",
        after,
    );
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            &before_hash,
            &after_hash,
        )],
    );
    stage_blob(&socket, &before_hash, before);
    stage_blob(&socket, &after_hash, after);

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--json", "--offline", "--yes", "packages/app"],
    );
    assert_eq!(
        code, 0,
        "the path-scoped multi-copy rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");

    // BOTH copies are restored (patches are per-package, not per-path)...
    assert_eq!(
        std::fs::read(nested_copy.join("index.js")).expect("read nested copy"),
        before,
        "the in-scope copy must be restored"
    );
    assert_eq!(
        std::fs::read(root_copy.join("index.js")).expect("read root copy"),
        before,
        "the out-of-scope copy must be restored too (multi-copy contract)"
    );

    // ...and the out-of-scope restore is surfaced, singular grammar intact.
    let warning = v["warnings"]
        .as_array()
        .and_then(|arr| {
            arr.iter()
                .find(|w| w["code"] == "out_of_scope_copies_restored")
        })
        .unwrap_or_else(|| panic!("out_of_scope_copies_restored must be warned; stdout=\n{stdout}"))
        .clone();
    assert!(
        warning["detail"]
            .as_str()
            .is_some_and(|d| d.contains("1 restored copy")),
        "the singular grammar must hold; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::manifest_removed(&v),
        json!([purl]),
        "the fully-restored patch leaves the manifest; stdout=\n{stdout}"
    );
}

/// Ledger-less but still WIRED: a lockfile that consumes `.socket/vendor/`
/// artifacts with NO ledger and NO manifest — rollback must refuse with the
/// restore-`state.json` guidance (exit 1),
/// never fall through to the bare "Manifest not found" error, and must not
/// touch the wired lock.
#[test]
fn ledgerless_wired_lock_errors_with_state_json_guidance() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // A v3 package-lock whose resolution points into `.socket/vendor/` —
    // exactly what a deleted/uncommitted state.json leaves behind.
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "fixture", "version": "1.0.0" },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": format!("file:.socket/vendor/npm/{V_UUID}/left-pad-1.3.0.tgz")
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(tmp.path().join("package-lock.json"), &lock_bytes).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "the recovery state must refuse; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert_eq!(
        envelope_error_code(&v),
        Some("vendor_ledger_missing"),
        "the recovery state is its own error, not `manifest_not_found`; stdout=\n{stdout}"
    );
    assert!(
        envelope_error_message(&v).is_some_and(|e| e.contains(".socket/vendor/state.json")),
        "the error must name the ledger to restore; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_bytes,
        "the wired lock must be untouched"
    );
}

/// Lock contention: rollback against an externally-held `.socket/apply.lock`
/// exits 1 with the shared `lock_held` error envelope (command `rollback`).
#[test]
fn lock_contention_exits_with_lock_held_envelope() {
    use fs2::FileExt;

    let before_hash = git_sha256(b"lock-original\n");
    let after_hash = git_sha256(b"lock-patched\n");
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            "pkg:npm/covgap-locked@1.0.0",
            "11111111-1111-4111-8111-111111111111",
            &before_hash,
            &after_hash,
        )],
    );

    // Hold the binary's lock for the duration of the test (the
    // e2e_safety_lock.rs pattern: same crate, same path, real flock).
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
        .expect("test could not take the initial lock");

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "lock contention must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        envelope_error_code(&v),
        Some("lock_held"),
        "expected error.code=lock_held; stdout=\n{stdout}"
    );
    assert_eq!(
        json_string(&v, "status"),
        Some("error"),
        "stdout=\n{stdout}"
    );
    assert_eq!(
        json_string(&v, "command"),
        Some("rollback"),
        "the envelope must name the rollback command; stdout=\n{stdout}"
    );
    drop(lock_file);
}

/// The manifest vanishing while another process holds the apply lock: the
/// pre-lock existence probe saw the file, but the under-lock read finds
/// it gone — rollback fails closed with `manifest_not_found` naming the
/// path (exit 1) rather than silently treating the run as empty.
///
/// Choreography: hold the lock, let the CLI pass its probe and block,
/// delete the manifest, release. If the CLI was slow enough to probe
/// AFTER the delete it takes the pre-lock "Manifest not found" path
/// instead — that alternative is detected and retried with a longer
/// pre-delete grace (bounded; the first attempt lands in practice).
#[test]
fn manifest_deleted_under_held_lock_fails_with_manifest_not_found() {
    use fs2::FileExt;

    for attempt in 1..=8u64 {
        let tmp = tempfile::tempdir().expect("tempdir");
        let socket = write_socket_manifest(
            tmp.path(),
            &[manifest_entry(
                "pkg:npm/covgap-toctou@1.0.0",
                "33333333-3333-4333-8333-333333333333",
                &git_sha256(b"toctou-original\n"),
                &git_sha256(b"toctou-patched\n"),
            )],
        );
        let lock_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(socket.join("apply.lock"))
            .expect("open lock file");
        lock_file
            .try_lock_exclusive()
            .expect("test could not take the initial lock");

        let child = spawn_scrubbed(
            tmp.path(),
            &[
                "rollback",
                "--json",
                "--offline",
                "--yes",
                "--lock-timeout",
                "30",
            ],
        );
        // Grace for the child to pass its (fast) pre-lock probe and block
        // on the lock; escalates across retries.
        std::thread::sleep(std::time::Duration::from_millis(200 * attempt));
        std::fs::remove_file(socket.join("manifest.json")).expect("delete manifest");
        FileExt::unlock(&lock_file).expect("release the lock");

        let out = child.wait_with_output().expect("wait for socket-patch");
        let code = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert_eq!(
            code, 1,
            "both interleavings exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
        );
        let v = parse_json_envelope(&stdout);
        assert_eq!(v["status"], "error", "stdout=\n{stdout}");
        // Both interleavings are `manifest_not_found` (v5.0); the read
        // under the lock names the path, the pre-lock probe does not.
        assert_eq!(
            v["error"]["code"], "manifest_not_found",
            "stdout=\n{stdout}"
        );
        match v["error"]["message"].as_str() {
            Some(m) if m.starts_with("Manifest not found at ") => return, // target interleaving reached
            Some("Manifest not found") => continue, // probed after the delete — retry
            other => panic!(
                "unexpected error for the vanished manifest: {other:?}\nstdout=\n{stdout}\nstderr=\n{stderr}"
            ),
        }
    }
    panic!("the probe-then-delete interleaving never landed in 8 attempts");
}

/// A DIRECTORY squatting a before-blob's path in `.socket/blobs`: the
/// dry-run stage's hard-link fails and the copy fallback is attempted
/// (and swallowed) — the preview still completes because the
/// already-original file never reads the blob, and the squatter itself is
/// untouched.
#[test]
fn dry_run_blob_stage_survives_directory_squatting_blob_hash() {
    let before: &[u8] = b"squat-original\n";
    let before_hash = git_sha256(before);
    let purl = "pkg:npm/covgap-squat@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    install_npm_pkg(tmp.path(), "node_modules", "covgap-squat", "1.0.0", before);
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            &before_hash,
            &git_sha256(b"squat-patched\n"),
        )],
    );
    let squatter = socket.join("blobs").join(&before_hash);
    std::fs::create_dir_all(&squatter).unwrap();
    std::fs::write(squatter.join("marker"), b"keep").unwrap();

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["rollback", "--dry-run", "--json", "--offline"],
    );
    assert_eq!(
        code, 0,
        "the already-original preview must survive the squatter; \
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::already_original(&v),
        1,
        "the entry must still verify as already original; stdout=\n{stdout}"
    );
    assert!(
        squatter.is_dir() && squatter.join("marker").exists(),
        "the squatting directory must be untouched by the dry run"
    );
}

/// #599: Bun never prunes `node_modules/.bun`. A patched `is-number@6.0.0`
/// entry the project has since moved off (an in-place `bun install` of
/// 7.0.0 re-linked the importer and hoist dir to the new entry) is an
/// orphan nothing loads now, but a later install that resolves back to
/// 6.0.0 re-links it as it is ("no changes"). Rollback must still restore
/// it, or the rolled-back patch silently returns: the orphan filter that
/// keeps `vex` from judging the install by such an entry is for checks of
/// the live install only.
#[cfg(unix)]
#[test]
fn bun_orphaned_store_entry_is_still_rolled_back() {
    let before: &[u8] = b"module.exports = 'original'\n";
    let after: &[u8] = b"module.exports = 'original' // PATCHED-599\n";
    let (before_hash, after_hash) = (git_sha256(before), git_sha256(after));
    let purl = "pkg:npm/is-number@6.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "app", "version": "0.0.0", "dependencies": { "is-number": "7.0.0" } }"#,
    )
    .expect("write root package.json");
    let orphan = install_npm_pkg(
        root,
        "node_modules/.bun/is-number@6.0.0/node_modules",
        "is-number",
        "6.0.0",
        after,
    );
    install_npm_pkg(
        root,
        "node_modules/.bun/is-number@7.0.0/node_modules",
        "is-number",
        "7.0.0",
        b"module.exports = 7\n",
    );
    std::fs::create_dir_all(root.join("node_modules/.bun/node_modules")).expect("hoist dir");
    std::os::unix::fs::symlink(
        "../is-number@7.0.0/node_modules/is-number",
        root.join("node_modules/.bun/node_modules/is-number"),
    )
    .expect("hoist link");
    std::os::unix::fs::symlink(
        ".bun/is-number@7.0.0/node_modules/is-number",
        root.join("node_modules/is-number"),
    )
    .expect("importer link");
    let socket = write_socket_manifest(
        root,
        &[manifest_entry(
            purl,
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            &before_hash,
            &after_hash,
        )],
    );
    stage_blob(&socket, &before_hash, before);
    stage_blob(&socket, &after_hash, after);

    let (code, stdout, stderr) = run(root, &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::not_installed(&v),
        json!([]),
        "the orphaned entry must be found; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::agent_rolled_back(&v),
        json!([purl]),
        "stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(orphan.join("index.js")).expect("read orphan index.js"),
        before,
        "the orphaned entry keeps its patched bytes; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
}

/// A ledger entry whose ecosystem has no vendor backend in this build
/// fails the vendored leg: exit 1, the purl + error in `vendoredFailed`
/// with `vendor_revert_failed`, and the manifest entry retained
/// (fail-closed cleanup). The human line is in `rollback_render.rs`.
#[test]
fn vendored_unknown_ecosystem_fails_the_leg() {
    let fx = vendor_fixture();
    vendor(&fx);
    rewrite_vendored_ecosystem(&fx, "brew");
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "an unknown-backend entry must fail the run; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    // The vendored failure is the run's only outcome: a total failure
    // (#1066), counted in the top-level `failed`.
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert_eq!(v["error"]["code"], "rollback_failed", "stdout=\n{stdout}");
    assert_eq!(v["summary"]["failed"], 1, "stdout=\n{stdout}");
    let failed_view = rollback_json::vendored_failed(&v);
    let failed = failed_view.as_array().expect("vendoredFailed array");
    assert_eq!(failed.len(), 1, "stdout=\n{stdout}");
    assert_eq!(failed[0]["purl"], V_PURL, "stdout=\n{stdout}");
    assert_eq!(
        failed[0]["errorCode"], "vendor_revert_failed",
        "stdout=\n{stdout}"
    );
    assert!(
        failed[0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("`brew`")),
        "the error must name the ecosystem; stdout=\n{stdout}"
    );
    assert!(
        fx.manifest_json()["patches"].get(V_PURL).is_some(),
        "a failed vendored purl's manifest entry must be retained"
    );
}

/// JSON dry-run of the vendored leg: the human preview print is skipped
/// (the mode gate's false branch) while the envelope still previews the
/// revert — `dryRun: true`, `vendoredReverted` names the key — and lock,
/// ledger, and artifact are all untouched.
#[test]
fn vendored_dry_run_json_previews_without_human_print() {
    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).unwrap();

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--dry-run"]);
    assert_eq!(
        code, 0,
        "the JSON dry run must exit 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["dryRun"], json!(true), "stdout=\n{stdout}");
    assert_eq!(
        rollback_json::vendored_reverted(&v),
        json!([V_PURL]),
        "the envelope must preview the revert; stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains("Would revert vendoring"),
        "--json must mute the human preview line; stdout=\n{stdout}"
    );
    assert_eq!(
        fx.lock_bytes(),
        wired_lock,
        "dry run must not touch the lock"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        state_before,
        "dry run must not touch the ledger"
    );
    assert!(fx.tgz_path().is_file(), "dry run must keep the artifact");
}

/// `--ecosystems` narrows the vendored leg: a pypi-scoped run leaves the
/// npm entry (wiring, ledger, artifact all intact), an npm-scoped run
/// reverts it.
#[test]
fn ecosystems_filter_narrows_vendored_scope() {
    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();

    let (code, stdout, stderr) = run(
        fx.root(),
        &[
            "rollback",
            "--json",
            "--offline",
            "--yes",
            "--ecosystems",
            "pypi",
        ],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::vendored_reverted(&v),
        json!([]),
        "a pypi-scoped run must not revert the npm entry; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), wired_lock, "the wiring must survive");
    assert!(fx.tgz_path().is_file(), "the artifact must survive");
    assert!(fx.state_path().is_file(), "the ledger must survive");

    let (code, stdout, stderr) = run(
        fx.root(),
        &[
            "rollback",
            "--json",
            "--offline",
            "--yes",
            "--ecosystems",
            "npm",
        ],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::vendored_reverted(&v),
        json!([V_PURL]),
        "the npm-scoped run must revert it; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

/// A corrupt vendor ledger fails ONLY the legs that need it: the run exits
/// 1 with the `vendor_state_unreadable` warning, manifest cleanup and GC
/// are skipped fail-closed, and the garbage ledger is left in place. The
/// human notice is in `rollback_render.rs`.
#[test]
fn corrupt_vendor_ledger_warns_and_fails_closed() {
    // NOT vendored: the installed tree is already original,
    // so the agent leg is a clean no-op and the exit-1 is the corrupt
    // ledger alone.)
    let fx = vendor_fixture();
    corrupt_vendor_ledger(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "a corrupt vendor ledger must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "stdout=\n{stdout}");
    assert!(
        warning_codes(&v).contains(&"vendor_state_unreadable".to_string()),
        "the warning must be surfaced; stdout=\n{stdout}"
    );
    assert!(
        v.get("gc").is_none(),
        "GC must be skipped fail-closed; stdout=\n{stdout}"
    );
    assert!(
        warning_codes(&v).contains(&"gc_skipped".to_string()),
        "the skipped GC is warned; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::manifest_removed(&v),
        json!([]),
        "manifest cleanup must be skipped fail-closed; stdout=\n{stdout}"
    );
    assert!(
        fx.manifest_json()["patches"].get(V_PURL).is_some(),
        "the manifest entry must survive"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).unwrap(),
        b"garbage not json",
        "the corrupt ledger must be left in place for quarantine"
    );
}

/// A path-shaped target selects a VENDORED entry through its installed
/// copy: `rollback node_modules/left-pad` reverts the vendored state.
#[test]
fn path_glob_selects_vendored_entry() {
    let fx = vendor_fixture();
    vendor(&fx);

    let (code, stdout, stderr) = run(
        fx.root(),
        &[
            "rollback",
            "--json",
            "--offline",
            "--yes",
            "node_modules/left-pad",
        ],
    );
    assert_eq!(
        code, 0,
        "the path-scoped vendored rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::vendored_reverted(&v),
        json!([V_PURL]),
        "the path target must select the vendored entry; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
    assert!(!fx.tgz_path().exists(), "artifact deleted");
}

/// A vendor-ledger SAVE failure after a successful revert (the artifact is
/// already gone, the entry already removed in memory): the purl lands in
/// `vendoredFailed` as `vendor_state_write_failed`, the run
/// exits 1, and the manifest entry is retained.
#[cfg(unix)]
#[test]
fn vendored_ledger_save_failure_fails_closed() {
    let fx = vendor_fixture();
    vendor(&fx);

    // Read-only `.socket/vendor`: the revert itself succeeds (the lock is
    // at the project root and the artifact lives in a writable uuid dir),
    // but `save_state`'s emptied-ledger unlink of state.json fails.
    let vendor_dir = fx.root().join(".socket/vendor");
    let guard = DirModeGuard::chmod(&vendor_dir, 0o555, 0o755);
    if !readonly_dir_enforced(&vendor_dir) {
        return;
    }

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    guard.restore();

    assert_eq!(
        code, 1,
        "a ledger save failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    // The vendored failure is the run's only outcome: a total failure
    // (#1066), counted in the top-level `failed`.
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert_eq!(v["error"]["code"], "rollback_failed", "stdout=\n{stdout}");
    assert_eq!(v["summary"]["failed"], 1, "stdout=\n{stdout}");
    let failed_view = rollback_json::vendored_failed(&v);
    let failed = failed_view.as_array().expect("vendoredFailed array");
    assert_eq!(failed.len(), 1, "stdout=\n{stdout}");
    assert_eq!(failed[0]["purl"], V_PURL, "stdout=\n{stdout}");
    assert_eq!(
        failed[0]["errorCode"], "vendor_state_write_failed",
        "the failure must be the ledger write; stdout=\n{stdout}"
    );
    assert!(
        fx.manifest_json()["patches"].get(V_PURL).is_some(),
        "the manifest entry must be retained when the ledger save failed"
    );
}

/// Manifest-cleanup qualifier bridging: a manifest purl spelled WITH a
/// qualifier still leaves the manifest after its (bare-keyed) ledger entry
/// is cleanly reverted — the qualifier-stripped match arm.
#[test]
fn qualified_manifest_purl_removed_after_vendored_revert() {
    const QUALIFIED: &str = "pkg:npm/left-pad@1.3.0?foo=bar";

    let fx = vendor_fixture();
    vendor(&fx);

    // Re-key the manifest entry with a qualifier the ledger key lacks.
    let mut manifest = fx.manifest_json();
    let record = manifest["patches"][V_PURL].take();
    manifest["patches"].as_object_mut().unwrap().remove(V_PURL);
    manifest["patches"][QUALIFIED] = record;
    std::fs::write(
        fx.root().join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::vendored_reverted(&v),
        json!([V_PURL]),
        "the ledger revert reports the LEDGER key; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::manifest_removed(&v),
        json!([QUALIFIED]),
        "the qualified manifest spelling must still be removed; stdout=\n{stdout}"
    );
    assert_eq!(
        fx.manifest_json()["patches"],
        json!({}),
        "the qualified entry must be gone from disk"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
}

/// An identifier that matches only a MANIFEST entry is still probed
/// against every vendor-ledger entry — by ledger key AND by the entry's
/// `base_purl` — and must match neither: the unrelated vendored package
/// keeps its ledger record, lock wiring, and artifact while the named
/// in-place patch rolls back and leaves the manifest.
#[test]
fn identifier_scope_leaves_unrelated_vendored_entry_untouched() {
    const IO_PURL: &str = "pkg:npm/is-odd@1.0.0";
    const IO_UUID: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    let io_before: &[u8] = b"module.exports = n => n % 2 === 1; // orig\n";
    let io_patched: &[u8] = b"module.exports = n => Math.abs(n) % 2 === 1; // patched\n";

    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).expect("read vendor ledger");

    // The in-place patch arrives AFTER vendoring so `vendor` never saw it:
    // installed at the PATCHED bytes, before-blob staged for the restore.
    install_npm_pkg(fx.root(), "node_modules", "is-odd", "1.0.0", io_patched);
    let socket = fx.root().join(".socket");
    stage_blob(&socket, &git_sha256(io_before), io_before);
    let mut manifest = fx.manifest_json();
    manifest["patches"][IO_PURL] = patch_entry_value(
        IO_UUID,
        "package/index.js",
        &git_sha256(io_before),
        &git_sha256(io_patched),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");

    let (code, stdout, stderr) = run(
        fx.root(),
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--lock-timeout",
            "5",
            IO_PURL,
        ],
    );
    assert_eq!(
        code, 0,
        "the identifier-scoped rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["summary"]["rolledBack"], json!(1), "stdout=\n{stdout}");
    assert_eq!(
        rollback_json::agent_rolled_back(&v),
        json!([IO_PURL]),
        "only the named patch may be acted on; stdout=\n{stdout}"
    );
    assert!(
        rollback_json::events_with_mode(&v, "vendored").is_empty(),
        "the identifier must not leak into the vendored leg; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::manifest_removed(&v),
        json!([IO_PURL]),
        "only the named entry leaves the manifest; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(fx.root().join("node_modules/is-odd/index.js")).expect("read restored file"),
        io_before,
        "the named patch must be restored in place"
    );
    // Every vendored surface survives byte-identically.
    assert_eq!(
        fx.lock_bytes(),
        wired_lock,
        "the vendored lock wiring must survive"
    );
    assert_eq!(
        std::fs::read(fx.state_path()).expect("vendor ledger still present"),
        state_before,
        "the vendor ledger must be byte-identical"
    );
    assert!(
        fx.tgz_path().is_file(),
        "the vendored artifact must survive"
    );
    let m = fx.manifest_json();
    assert!(
        m["patches"].get(V_PURL).is_some(),
        "the vendored manifest entry must be retained; manifest={m}"
    );
    assert!(
        m["patches"].get(IO_PURL).is_none(),
        "the rolled-back entry must be removed; manifest={m}"
    );
}

/// TWO vendored entries reverted in one run: the manifest-cleanup matcher
/// walks EVERY reverted ledger key for each vendor-owned purl — the
/// non-matching sibling key falls through key equality, qualifier
/// stripping, and the ledger `base_purl` probe — and each entry is still
/// keyed to ITS OWN revert: both manifest records drop, both artifacts
/// and ledger entries go, and the lock returns to its pre-vendor bytes.
#[test]
fn two_vendored_entries_each_cleanup_via_their_own_revert() {
    const RP_PURL: &str = "pkg:npm/right-pad@1.0.1";
    const RP_UUID: &str = "5b8c0d2e-3f4a-4b5c-8d6e-9f0a1b2c3d4e";
    let rp_orig: &[u8] = b"module.exports = (s, n) => s + ' '.repeat(n); // orig\n";
    let rp_patched: &[u8] =
        b"module.exports = (s, n) => s + ' '.repeat(n < 0 ? 0 : n); // patched\n";

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    install_npm_pkg(root, "node_modules", "left-pad", "1.3.0", ORIG_INDEX);
    install_npm_pkg(root, "node_modules", "right-pad", "1.0.1", rp_orig);
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .expect("write root package.json");
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0", "right-pad": "^1.0.1" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            },
            "node_modules/right-pad": {
                "version": "1.0.1",
                "resolved": "https://registry.npmjs.org/right-pad/-/right-pad-1.0.1.tgz",
                "integrity": "sha512-origrp==",
                "license": "MIT"
            }
        }
    });
    let mut original_lock = serde_json::to_vec_pretty(&lock).expect("serialize lock");
    original_lock.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &original_lock).expect("write lock");

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let mut patches = serde_json::Map::new();
    patches.insert(
        V_PURL.to_string(),
        patch_entry_value(
            V_UUID,
            "package/index.js",
            &git_sha256(ORIG_INDEX),
            &git_sha256(PATCHED_INDEX),
        ),
    );
    patches.insert(
        RP_PURL.to_string(),
        patch_entry_value(
            RP_UUID,
            "package/index.js",
            &git_sha256(rp_orig),
            &git_sha256(rp_patched),
        ),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).expect("serialize manifest"),
    )
    .expect("write manifest");
    // After-hash blobs are the offline vendor source for both packages.
    stage_blob(&socket, &git_sha256(PATCHED_INDEX), PATCHED_INDEX);
    stage_blob(&socket, &git_sha256(rp_patched), rp_patched);

    let (code, stdout, stderr) = run(
        root,
        &[
            "vendor",
            "--json",
            "--silent",
            "--offline",
            "--lock-timeout",
            "5",
        ],
    );
    assert_eq!(
        code, 0,
        "fixture vendor of both packages must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let lp_tgz = root.join(format!(".socket/vendor/npm/{V_UUID}/left-pad-1.3.0.tgz"));
    let rp_tgz = root.join(format!(".socket/vendor/npm/{RP_UUID}/right-pad-1.0.1.tgz"));
    assert!(
        lp_tgz.is_file() && rp_tgz.is_file(),
        "sanity: both artifacts written"
    );

    let (code, stdout, stderr) = run(
        root,
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--lock-timeout",
            "5",
        ],
    );
    assert_eq!(
        code, 0,
        "the two-entry revert must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    let reverted_view = rollback_json::vendored_reverted(&v);
    let mut reverted: Vec<String> = reverted_view
        .as_array()
        .expect("vendoredReverted array")
        .iter()
        .map(|p| p.as_str().expect("purl string").to_string())
        .collect();
    reverted.sort();
    assert_eq!(
        reverted,
        vec![V_PURL.to_string(), RP_PURL.to_string()],
        "both entries must revert; stdout=\n{stdout}"
    );
    let removed_view = rollback_json::manifest_removed(&v);
    let mut removed: Vec<String> = removed_view
        .as_array()
        .expect("removedEntries array")
        .iter()
        .map(|p| p.as_str().expect("purl string").to_string())
        .collect();
    removed.sort();
    assert_eq!(
        removed,
        vec![V_PURL.to_string(), RP_PURL.to_string()],
        "each manifest entry must be keyed to its own revert; stdout=\n{stdout}"
    );
    let m: Value = serde_json::from_slice(
        &std::fs::read(socket.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest is JSON");
    assert_eq!(
        m["patches"],
        json!({}),
        "no manifest entry may survive its own clean revert; manifest={m}"
    );
    assert!(
        !lp_tgz.exists() && !rp_tgz.exists(),
        "both artifacts must be deleted"
    );
    let state_path = root.join(".socket/vendor/state.json");
    if state_path.exists() {
        let state: Value =
            serde_json::from_slice(&std::fs::read(&state_path).expect("read vendor ledger"))
                .expect("ledger is JSON");
        assert_eq!(
            state["entries"],
            json!({}),
            "no ledger entry may survive; state={state}"
        );
    }
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).expect("read lock"),
        original_lock,
        "the lock must return to its pre-vendor bytes"
    );
}

/// Two pins in one yarn.lock, one of which the registry does not answer
/// for: each pin restores or refuses on its own. The refused purl + error
/// land in `hosted.failed` (exit 1, `partial_failure`), the other pin is
/// restored, and the refused block stays hosted byte-for-byte.
#[test]
fn per_purl_revert_failure_lands_in_hosted_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let io_redirected = yarn_block_for("is-odd", "3.0.1", IO_HOSTED_URL, "sha512-PATCHEDio==");
    std::fs::write(
        tmp.path().join("yarn.lock"),
        yarn_lock_content(&format!("{io_redirected}\n\n{}", yarn_redirected_block())),
    )
    .unwrap();
    // left-pad is NOT served: its lookup 404s.
    let registry = NpmRegistry::start(&[("is-odd", "3.0.1")]);

    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--yes"],
        Some(&registry),
    );
    assert_eq!(
        code, 1,
        "a refused pin must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "stdout=\n{stdout}");
    let failed_view = rollback_json::hosted_failed(&v);
    let failed = failed_view.as_array().expect("failed array");
    assert_eq!(failed.len(), 1, "stdout=\n{stdout}");
    assert_eq!(failed[0]["purl"], LP_PURL, "stdout=\n{stdout}");
    assert_eq!(
        failed[0]["errorCode"], "hosted_restore_refused",
        "stdout=\n{stdout}"
    );
    let error = failed[0]["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("404") && error.contains("git checkout") && error.contains("yarn.lock"),
        "the error must name the registry failure and the remedy; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::hosted_reverted(&v),
        json!([IO_PURL]),
        "the other pin restores on its own; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&format!(
            "{}\n\n{}",
            yarn_upstream_block_for("is-odd", "3.0.1"),
            yarn_redirected_block()
        )),
        "only the resolvable pin is restored; the refused one stays hosted"
    );
}

/// A pre-v5 ledger's edits are NEVER replayed: a ledger whose only content
/// is an edit naming an unsafe path (the old replay refused such a group)
/// is simply retired — no lockfile pins a hosted patch, so rollback removes
/// the stale file and exits 0 (`legacyRedirectLedgerRemoved`), and the
/// edit's target is never touched. The human retire line is in
/// `rollback_render.rs`.
#[test]
fn legacy_ledger_edits_are_never_replayed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let evil = tmp.path().join("evil.lock");
    std::fs::write(&evil, yarn_lock_content(&yarn_redirected_block())).unwrap();
    write_legacy_ledger(&project, unsafe_legacy_edits());

    let (code, stdout, stderr) = run_hosted(&project, &["rollback", "--json", "--yes"], None);
    assert_eq!(
        code, 0,
        "a stale pre-v5 ledger is retired, not replayed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(v["legacyRedirectLedgerRemoved"], true, "stdout=\n{stdout}");
    assert!(
        !ledger_path(&project).exists(),
        "the stale ledger is deleted"
    );
    assert_eq!(
        std::fs::read_to_string(&evil).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "a legacy ledger's edit is never replayed"
    );
}

/// A pre-v5 ledger beside a live hosted pin: the pin is restored from the
/// registry (never from the ledger's recorded original), and the ledger is
/// retired once no pin remains. Offline, the ledger's recorded original is
/// NOT a fallback: the pin is refused, and the ledger stays while the pin
/// is still wired.
#[test]
fn legacy_ledger_beside_a_live_pin_is_never_the_revert_source() {
    let legacy_edits = || {
        json!([{
            "path": "yarn.lock",
            "kind": "redirect_yarn_classic_entry",
            "action": "rewritten",
            "key": "left-pad@1.2.3",
            // A recorded "original" the registry disagrees with: a replay
            // would write it; the restore must not.
            "original": yarn_block_for(
                "left-pad", "1.2.3",
                "https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.3.tgz#bbbb",
                "sha512-LEDGERledger==",
            ),
            "new": yarn_redirected_block(),
        }])
    };

    // Offline: refused, nothing written, ledger kept.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    write_legacy_ledger(tmp.path(), legacy_edits());
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();
    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--offline", "--yes"],
        None,
    );
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    // Nothing was rolled back: a total failure (#1066), and the refused
    // hosted pin counts in the top-level `failed`.
    assert_eq!(v["status"], "error", "stdout=\n{stdout}");
    assert_eq!(v["error"]["code"], "rollback_failed", "stdout=\n{stdout}");
    assert_eq!(v["summary"]["failed"], 1, "stdout=\n{stdout}");
    assert_eq!(
        rollback_json::hosted_failed(&v)[0]["purl"],
        LP_PURL,
        "stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::hosted_reverted(&v),
        json!([]),
        "stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "the ledger's recorded original is never replayed"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "the ledger stays while a pin is still wired"
    );

    // Online: restored from the registry, ledger retired.
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);
    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--yes"],
        Some(&registry),
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(
        rollback_json::hosted_reverted(&v),
        json!([LP_PURL]),
        "stdout=\n{stdout}"
    );
    assert!(
        v["hosted"]["editedFiles"].as_u64().unwrap_or(0) >= 1,
        "the restore rewrote the lock; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the entry comes back from the registry, not the ledger"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "with no hosted pin left the pre-v5 ledger is retired"
    );
}

/// A corrupt pre-v5 ledger is inert: a project whose only state is that
/// garbage file retires it and exits 0 (it is never parsed, so it can
/// never fail the run). The dry-run preview is in `rollback_render.rs`.
#[test]
fn corrupt_legacy_ledger_is_retired() {
    let tmp = corrupt_legacy_ledger_project();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "a corrupt pre-v5 ledger never fails the run; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    assert_eq!(v["legacyRedirectLedgerRemoved"], true, "stdout=\n{stdout}");
    assert!(!ledger_path(tmp.path()).exists());
}

/// `--ecosystems` narrows the hosted leg: a pypi-scoped run leaves the npm
/// pin; an npm-scoped run restores it.
#[test]
fn ecosystems_filter_narrows_hosted_scope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--yes", "--ecosystems", "pypi"],
        Some(&registry),
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::hosted_reverted(&v),
        json!([]),
        "a pypi-scoped run must not restore the npm pin; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "the wiring must survive the eco-narrowed run"
    );

    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--yes", "--ecosystems", "npm"],
        Some(&registry),
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::hosted_reverted(&v),
        json!([LP_PURL]),
        "the npm-scoped run must restore it; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the entry must be restored"
    );
    assert!(!tmp.path().join(".socket").exists(), "no .socket/ residue");
}

/// A path-shaped target selects a HOSTED pin through its installed copy:
/// `rollback node_modules/left-pad` restores the upstream entry.
#[test]
fn path_glob_selects_hosted_record() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    // An installed copy for the path-scope crawler to discover.
    write_root_package_json(tmp.path());
    install_npm_pkg(
        tmp.path(),
        "node_modules",
        "left-pad",
        "1.2.3",
        b"installed bytes\n",
    );
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--json", "--yes", "node_modules/left-pad"],
        Some(&registry),
    );
    assert_eq!(
        code, 0,
        "the path-scoped hosted rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(
        rollback_json::hosted_reverted(&v),
        json!([LP_PURL]),
        "the path target must select the hosted pin; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the entry must be restored"
    );
    assert!(!tmp.path().join(".socket").exists(), "no .socket/ residue");
}

/// The restored lockfile cannot be written (a read-only project root; the
/// write is an atomic temp-file + rename beside it): the failure lands in
/// `hosted.failed` under the `files` key and the run exits 1, the lock
/// untouched. (Skipped where the sandbox ignores directory modes, e.g. as
/// root.)
#[cfg(unix)]
#[test]
fn hosted_restore_write_failure_lands_in_hosted_failed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    write_single_npm_fixture(&project);
    // `.socket/` exists and stays writable so the apply lock is taken.
    std::fs::create_dir(project.join(".socket")).unwrap();
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let guard = DirModeGuard::chmod(&project, 0o555, 0o755);
    if !readonly_dir_enforced(&project) {
        return;
    }
    let (code, stdout, stderr) =
        run_hosted(&project, &["rollback", "--json", "--yes"], Some(&registry));
    guard.restore();

    assert_eq!(
        code, 1,
        "a lockfile write failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "stdout=\n{stdout}");
    let failed_view = rollback_json::hosted_failed(&v);
    let failed = failed_view.as_array().expect("failed array");
    assert!(
        failed
            .iter()
            .any(|f| f["purl"].is_null() && f["errorCode"] == "hosted_write_failed"),
        "the write failure must be an artifact-level hosted_write_failed event; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(project.join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "the lock was never written"
    );
}

/// #764: Bun's hoisted linker keeps an installed copy whose lock entry
/// returns to the registry record (a plain `bun install` reports "no
/// changes"), so a rollback over a hoisted `node_modules/left-pad` warns
/// `redirect_bun_reinstall_required` and names `bun install --force` in
/// `warnings[]` (the stderr line is in `rollback_render.rs`). An isolated install (the copy a
/// link into `node_modules/.bun/`) relinks, so it stays silent.
#[test]
fn bun_lock_rollback_warns_that_a_hoisted_copy_is_kept() {
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);
    let has_code = |v: &serde_json::Value| {
        v["warnings"].as_array().is_some_and(|ws| {
            ws.iter().any(|w| {
                w["code"] == "redirect_bun_reinstall_required"
                    && w["detail"].as_str().is_some_and(|d| {
                        d.contains("left-pad@1.2.3") && d.contains("`bun install --force`")
                    })
            })
        })
    };

    let hoisted = bun_hosted_project(true);
    let (code, stdout, stderr) = run_hosted(
        hoisted.path(),
        &["rollback", "--json", "--yes"],
        Some(&registry),
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(has_code(&parse_json_envelope(&stdout)), "stdout=\n{stdout}");

    // The preview warns the same way: its run-level `reinstall_required`
    // note would otherwise promise that the next plain install refreshes
    // the tree, which is the #764 failure.
    let hoisted = bun_hosted_project(true);
    let (code, stdout, stderr) = run_hosted(
        hoisted.path(),
        &["rollback", "--dry-run", "--json", "--yes"],
        Some(&registry),
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    let env = parse_json_envelope(&stdout);
    assert!(has_code(&env), "stdout=\n{stdout}");
    assert!(
        env["warnings"]
            .as_array()
            .is_some_and(|ws| ws.iter().any(|w| {
                w["code"] == "reinstall_required"
                    && w["detail"]
                        .as_str()
                        .is_some_and(|d| d.contains("`bun install --force`"))
            })),
        "the preview's reinstall note names the forcing install; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(hoisted.path().join("bun.lock")).unwrap(),
        bun_lock(&bun_redirected_line()),
        "a dry run writes nothing"
    );

    let fresh = bun_hosted_project(false);
    let (code, stdout, stderr) = run_hosted(
        fresh.path(),
        &["rollback", "--json", "--yes"],
        Some(&registry),
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        !has_code(&parse_json_envelope(&stdout)),
        "nothing installed, nothing kept; stdout=\n{stdout}"
    );
}

/// GC failures WARN, never fail the rollback: with the blob and diff
/// stores unreadable (mode 000) on an already-original fixture, the run
/// still exits 0 carrying `cleanup_failed` warnings for both sweeps.
#[cfg(unix)]
#[test]
fn gc_failure_warns_but_run_still_succeeds() {
    let before: &[u8] = b"gc-original\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"gc-patched\n");
    let purl = "pkg:npm/covgap-gc@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Installed at BEFORE bytes: the engine never reads a blob.
    install_npm_pkg(tmp.path(), "node_modules", "covgap-gc", "1.0.0", before);
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "22222222-2222-4222-8222-222222222222",
            &before_hash,
            &after_hash,
        )],
    );
    let blobs = socket.join("blobs");
    let diffs = socket.join("diffs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::create_dir_all(&diffs).unwrap();
    let blob_guard = DirModeGuard::chmod(&blobs, 0o000, 0o755);
    let diff_guard = DirModeGuard::chmod(&diffs, 0o000, 0o755);
    // The sweeps READ these dirs, so probe the denial with a read: root (or
    // CAP_DAC_OVERRIDE) opens a mode-000 dir fine and the GC would succeed.
    if std::fs::read_dir(&blobs).is_ok() {
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return;
    }

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--json", "--offline", "--yes"]);
    blob_guard.restore();
    diff_guard.restore();

    assert_eq!(
        code, 0,
        "GC failures must not fail the rollback; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "stdout=\n{stdout}");
    let warnings = v["warnings"].as_array().expect("warnings array");
    assert!(
        warnings.iter().any(|w| w["code"] == "cleanup_failed"
            && w["detail"]
                .as_str()
                .is_some_and(|d| d.contains("blob cleanup failed"))),
        "the blob sweep failure must be warned; stdout=\n{stdout}"
    );
    assert!(
        warnings.iter().any(|w| w["code"] == "cleanup_failed"
            && w["detail"]
                .as_str()
                .is_some_and(|d| d.contains("diffs cleanup failed"))),
        "the diffs sweep failure must be warned; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::manifest_removed(&v),
        json!([purl]),
        "the already-original entry still leaves the manifest; stdout=\n{stdout}"
    );
}

/// `write_manifest` failure AFTER a successful restore: the files are
/// rolled back, but the entry removal cannot land — `removedEntries` comes
/// back empty, the `manifest_write_failed` warning is carried, the run
/// exits 1, and the on-disk manifest is byte-identical.
#[cfg(target_os = "macos")]
#[test]
fn manifest_write_failure_warns_and_exits_one() {
    let fx = patched_fixture();
    let manifest_path = fx.socket.join("manifest.json");
    let manifest_before = std::fs::read(&manifest_path).expect("read manifest bytes");
    let guard = ChflagsGuard::set(&manifest_path);

    let (code, stdout, stderr) = run(
        fx.root.path(),
        &["rollback", "--json", "--offline", "--yes"],
    );
    guard.release();

    assert_eq!(
        code, 1,
        "a manifest write failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["status"], "partialFailure", "stdout=\n{stdout}");
    assert!(
        warning_codes(&v).contains(&"manifest_write_failed".to_string()),
        "the write failure must be warned; stdout=\n{stdout}"
    );
    assert_eq!(
        rollback_json::manifest_removed(&v),
        json!([]),
        "nothing may be reported removed when the write failed; stdout=\n{stdout}"
    );
    // The restore itself DID land...
    assert_eq!(
        std::fs::read(fx.pkg_dir.join("index.js")).expect("read restored file"),
        fx.before,
        "the file restore happens before the manifest write"
    );
    // ...but the manifest is untouched.
    assert_eq!(
        std::fs::read(&manifest_path).expect("manifest exists"),
        manifest_before,
        "a failed manifest write must leave the file byte-identical"
    );
    // And the entry's blobs must survive for a retry (the failed-write
    // fallback restores the in-memory reference before the GC).
    assert!(
        fx.socket.join("blobs").join(git_sha256(fx.before)).exists()
            && fx.socket.join("blobs").join(git_sha256(fx.after)).exists(),
        "the failed-cleanup entry's blobs must be pinned"
    );
}

/// PyPI release-variant fallback when NO variant matches the installed
/// distribution (a locally-modified file): rollback attempts EVERY
/// variant instead of silently skipping the package, so the per-file
/// verification surfaces the drift — both qualified purls land in
/// `results` as hash-mismatch failures, exit 1, the file keeps its
/// drifted bytes, and the manifest keeps both entries.
#[test]
fn pypi_variant_group_with_no_installed_match_attempts_every_variant() {
    const WHEEL: &str = "pkg:pypi/covgapkit@1.0.0?artifact_id=covgapkit-1.0.0-py3-none-any.whl";
    const SDIST: &str = "pkg:pypi/covgapkit@1.0.0?artifact_id=covgapkit-1.0.0.tar.gz";
    let drifted: &[u8] = b"VERSION = 'locally-drifted'\n";
    let wheel_before: &[u8] = b"VERSION = 'wheel-original'\n";
    let wheel_after: &[u8] = b"VERSION = 'wheel-patched'\n";
    let sdist_before: &[u8] = b"VERSION = 'sdist-original'\n";
    let sdist_after: &[u8] = b"VERSION = 'sdist-patched'\n";

    // Hand-built venv layout (the shape the python crawler probes);
    // `VIRTUAL_ENV` is injected child-only, so discovery is deterministic
    // and parallel-safe regardless of the ambient shell.
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    let venv = root.join(".venv");
    #[cfg(windows)]
    let site_packages = venv.join("Lib").join("site-packages");
    #[cfg(not(windows))]
    let site_packages = venv.join("lib").join("python3.12").join("site-packages");
    let dist_info = site_packages.join("covgapkit-1.0.0.dist-info");
    std::fs::create_dir_all(&dist_info).expect("create dist-info");
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: covgapkit\nVersion: 1.0.0\n",
    )
    .expect("write METADATA");
    let pkg = site_packages.join("covgapkit");
    std::fs::create_dir_all(&pkg).expect("create package dir");
    std::fs::write(pkg.join("__init__.py"), drifted).expect("write module");

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let mut patches = serde_json::Map::new();
    patches.insert(
        WHEEL.to_string(),
        patch_entry_value(
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "covgapkit/__init__.py",
            &git_sha256(wheel_before),
            &git_sha256(wheel_after),
        ),
    );
    patches.insert(
        SDIST.to_string(),
        patch_entry_value(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "covgapkit/__init__.py",
            &git_sha256(sdist_before),
            &git_sha256(sdist_after),
        ),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).expect("serialize manifest"),
    )
    .expect("write manifest");
    // Both before-blobs staged: verification must reach the drift
    // comparison (hash_mismatch), not stop at a missing-blob gate.
    stage_blob(&socket, &git_sha256(wheel_before), wheel_before);
    stage_blob(&socket, &git_sha256(sdist_before), sdist_before);

    let (code, stdout, stderr) = common::run_with_env(
        root,
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--lock-timeout",
            "5",
        ],
        &[("VIRTUAL_ENV", venv.to_str().expect("utf8 venv path"))],
    );
    assert_eq!(
        code, 1,
        "a drifted install cannot roll back; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    // Both variants failed and nothing was rolled back: a total failure.
    assert_eq!(v["status"], json!("error"), "stdout=\n{stdout}");
    assert_eq!(v["error"]["code"], "rollback_failed", "stdout=\n{stdout}");
    assert_eq!(v["summary"]["failed"], json!(2), "stdout=\n{stdout}");
    let results: Vec<&Value> = v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["action"] == "failed")
        .collect();
    let mut result_purls: Vec<&str> = results
        .iter()
        .map(|r| r["purl"].as_str().expect("purl string"))
        .collect();
    result_purls.sort_unstable();
    assert_eq!(
        result_purls,
        vec![WHEEL, SDIST],
        "EVERY variant must be attempted when none matches the installed \
         distribution — silent skipping is the bug this guards; stdout=\n{stdout}"
    );
    for r in results {
        assert_eq!(r["errorCode"], json!("hash_mismatch"), "stdout=\n{stdout}");
        assert_eq!(
            r["details"]["filesVerified"][0]["status"],
            json!("hashMismatch"),
            "the per-file verification must surface the drift; stdout=\n{stdout}"
        );
    }
    assert_eq!(
        std::fs::read(pkg.join("__init__.py")).expect("read module"),
        drifted,
        "a failed verification must leave the drifted bytes alone"
    );
    let m: Value = serde_json::from_slice(
        &std::fs::read(socket.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest is JSON");
    assert!(
        m["patches"].get(WHEEL).is_some() && m["patches"].get(SDIST).is_some(),
        "failed variants must both stay in the manifest; manifest={m}"
    );
}

/// A DISCOVERED local-go redirect target: the module lives in the module
/// cache (child-only `GOMODCACHE` injection), so the crawler resolves it
/// and the rollback loop routes the discovered target through the
/// local-go redirect teardown — dropping the socket-owned `replace` and
/// the `.socket/go-patches/` copy while the CACHE copy stays
/// byte-identical (a redirect never patches the cache in place).
#[test]
fn discovered_local_go_redirect_drops_wiring_not_cache_copy() {
    use socket_patch_core::vendor::go_mod_edit::{
        ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
    };

    const MODULE: &str = "github.com/covgap/discovered";
    const VERSION: &str = "v1.2.3";
    const PURL: &str = "pkg:golang/github.com/covgap/discovered@v1.2.3";
    let original: &[u8] = b"package discovered\n\nfunc V() string { return \"orig\" }\n";
    let patched: &[u8] = b"package discovered\n\nfunc V() string { return \"patched\" }\n";

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(
        root.join("go.mod"),
        format!("module covgapproj\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n"),
    )
    .expect("write go.mod");
    assert!(
        rt.block_on(ensure_replace_entry(
            root,
            MODULE,
            VERSION,
            GO_PATCHES_DIR,
            false
        ))
        .expect("install replace directive"),
        "fixture must install the socket-owned replace"
    );
    let copy_dir = root
        .join(GO_PATCHES_DIR)
        .join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&copy_dir).expect("create go-patches copy");
    std::fs::write(copy_dir.join("discovered.go"), patched).expect("write patched copy");

    // The module cache the crawler discovers. All-lowercase coordinates:
    // no case-escaping in the on-disk directory name.
    let cache = tempfile::tempdir().expect("cache tempdir");
    let cache_mod_dir = cache.path().join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&cache_mod_dir).expect("create cache module dir");
    std::fs::write(cache_mod_dir.join("discovered.go"), original).expect("write cache copy");

    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    let mut patches = serde_json::Map::new();
    patches.insert(
        PURL.to_string(),
        patch_entry_value(
            "abababab-abab-4bab-8bab-abababababab",
            "package/discovered.go",
            &git_sha256(original),
            &git_sha256(patched),
        ),
    );
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": patches })).expect("serialize manifest"),
    )
    .expect("write manifest");

    let (code, stdout, stderr) = common::run_with_env(
        root,
        &[
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--lock-timeout",
            "5",
        ],
        &[(
            "GOMODCACHE",
            cache.path().to_str().expect("utf8 cache path"),
        )],
    );
    assert_eq!(
        code, 0,
        "the discovered redirect rollback must succeed; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    let v = parse_json_envelope(&stdout);
    assert_eq!(v["summary"]["rolledBack"], json!(1), "stdout=\n{stdout}");
    let result = rollback_json::agent_event(&v, "rolledBack", PURL);
    // The DISCOVERED route: the result names the module-cache copy — the
    // undiscovered fallback reports the project root instead, so this
    // pins which path ran.
    let path = result["details"]["path"].as_str().expect("path string");
    assert!(
        path.ends_with("discovered@v1.2.3") && path != root.display().to_string(),
        "the target must be the discovered cache dir; path={path}"
    );
    assert!(
        result["files"]
            .as_array()
            .expect("files array")
            .iter()
            .any(|f| f["path"] == "package/discovered.go"),
        "the redirect teardown reports the patch's files; stdout=\n{stdout}"
    );
    assert!(
        rt.block_on(read_replace_entries(root))
            .iter()
            .all(|e| !(e.module == MODULE && e.socket_owned())),
        "the socket-owned replace directive must be dropped"
    );
    let go_mod = std::fs::read_to_string(root.join("go.mod")).expect("read go.mod");
    assert!(
        go_mod.contains(&format!("require {MODULE} {VERSION}")),
        "the require directive must survive; go.mod=\n{go_mod}"
    );
    assert!(!copy_dir.exists(), "the go-patches copy must be removed");
    assert_eq!(
        std::fs::read(cache_mod_dir.join("discovered.go")).expect("read cache copy"),
        original,
        "the module-cache copy must stay byte-identical"
    );
    let m: Value = serde_json::from_slice(
        &std::fs::read(socket.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest is JSON");
    assert!(
        m["patches"].get(PURL).is_none(),
        "the rolled-back entry must leave the manifest; manifest={m}"
    );
}
