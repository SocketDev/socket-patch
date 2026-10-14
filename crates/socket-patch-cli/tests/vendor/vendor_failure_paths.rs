//! `vendor`'s failure paths, asserted through `--json` codes, events and
//! the bytes on disk (#1089): the fail-closed ledger/manifest exit
//! contracts, the fresh-clone committed-artifact staging error ladder, the
//! hosted-pin takeover guard (v5: hosted state is the lockfile pins), the
//! unix fault-injection paths for the state-write failure events, and the
//! service-outage re-runs. A message is read only for what it must name
//! (a lockfile, a remedy command, an ecosystem). The human output lives in
//! `vendor_render.rs`; the refusal tests here also run the human mode once,
//! to check it claims no vendored package.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::common::envelope::{events, find_event};
use crate::npm_fixture::*;

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

/// A present-but-corrupt manifest is `manifest_invalid` (the shared
/// manifest-load mapping, #931), exit 1 (the documented vendor exit
/// contract; distinct from the missing-manifest clean no-op).
#[test]
fn corrupt_manifest_fails_closed() {
    let fx = npm_fixture();
    std::fs::write(fx.manifest_path(), b"{broken").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "corrupt manifest must fail the run: {env:#}");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "manifest_invalid");
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock untouched");
}

// ─────────────────────────────────────────────────────────────────────
// 2. fresh-clone committed-artifact staging error ladder
// ─────────────────────────────────────────────────────────────────────

/// Fresh-clone re-vendor over a PRESENT-but-corrupt committed artifact
/// (ledger sha mismatch) under `--offline`: a loud `vendor_redownload_failed`
/// failure naming the `--offline` conflict (the redownload needs the patch
/// service) — silently re-vendoring over it would mask the corruption.
#[tokio::test]
async fn corrupt_committed_artifact_offline_fails_the_redownload() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    // Fresh-clone shape: no installed tree, only the committed artifacts.
    std::fs::remove_dir_all(fx.root().join("node_modules")).unwrap();
    std::fs::write(fx.tgz_path(), b"corrupt bytes").unwrap();

    let (code, env) = vendor_cli(fx.root(), &["--offline"]);
    assert_eq!(code, 1, "a corrupt committed artifact must fail: {env:#}");
    let failed = find_event(&env, "failed", Some("vendor_redownload_failed"));
    assert_eq!(failed["purl"], PURL);
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("--offline")),
        "the failure names the --offline conflict: {env:#}"
    );
}

/// A legacy ledger with NO recorded artifact sha cannot verify the
/// committed artifact (`Unverifiable`), so the run redownloads it: with no
/// installed copy that is a `vendor_redownload_failed` failure (exit 1),
/// never a `vendor_fetch_failed`, and the committed artifact is left alone.
#[tokio::test]
async fn legacy_ledger_without_sha_fails_the_redownload_not_a_fetch() {
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
    let failed = find_event(&env, "failed", Some("vendor_redownload_failed"));
    assert_eq!(failed["purl"], PURL);
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
/// installed, no lockfile, no ledger — a NON-offline run fails the purl
/// with `vendor_lockfile_missing` before any network I/O, never a
/// `vendor_fetch_failed` (`SOCKET_NO_API_TOKEN` keeps the run anonymous so
/// no other network path opens either).
#[test]
fn missing_package_with_no_lock_and_no_ledger_fails_before_any_fetch() {
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
    let failed = find_event(&env, "failed", Some("vendor_lockfile_missing"));
    assert_eq!(failed["purl"], PURL);

    assert!(
        events(&env)
            .iter()
            .all(|e| e["errorCode"] != "vendor_fetch_failed"),
        "NoSource is not a fetch failure: {env:#}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// 3. hosted-pin takeover guard (v5: lockfile pins, no redirect ledger)
// ─────────────────────────────────────────────────────────────────────
/// A pre-v5 redirect ledger on disk (even a malformed one) is IGNORED:
/// the vendor run neither reads nor rewrites it, vendors the purl as
/// usual, and leaves the stale file byte-identical.
#[test]
fn corrupt_pre_v5_redirect_ledger_is_ignored_by_vendor() {
    let fx = npm_fixture();
    std::fs::create_dir_all(fx.vendor_dir()).unwrap();
    std::fs::write(fx.redirect_state_path(), b"garbage").unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "a stale ledger must not block vendoring: {env:#}");
    let applied = find_event(&env, "applied", None);
    assert_eq!(applied["purl"], PURL);
    assert!(
        events(&env)
            .iter()
            .all(|e| e["errorCode"] != "redirect_ledger_corrupt"),
        "the pre-v5 ledger is never read: {env:#}"
    );
    assert!(fx.tgz_path().is_file(), "the purl is vendored");
    assert_ne!(fx.lock_bytes(), fx.original_lock, "the lock is rewired");
    assert_eq!(
        std::fs::read(fx.redirect_state_path()).unwrap(),
        b"garbage",
        "the pre-v5 ledger is left untouched"
    );
}

/// Dry run over a purl the lockfile pins hosted: the run warns
/// `vendor_would_revert_redirect` (an UNCOUNTED advisory — dry/wet takeover
/// parity) after resolving the upstream entry exactly like a wet run
/// would, and writes nothing — no lock edit, no artifact, no ledger.
#[tokio::test]
async fn dry_run_over_hosted_pin_warns_and_writes_nothing() {
    let fx = npm_fixture();
    let hosted_lock = pin_hosted(&fx);
    let registry = mock_npm_registry().await;

    let (code, env) = vendor_online(&fx, &registry.uri(), &["--dry-run"]);
    assert_eq!(code, 0, "the dry run itself succeeds: {env:#}");
    let warned = find_event(&env, "skipped", Some("vendor_would_revert_redirect"));
    assert_eq!(warned["purl"], PURL);
    assert_eq!(
        env["summary"]["skipped"], 0,
        "the takeover advisory is uncounted: {env:#}"
    );
    assert_eq!(
        fx.lock_bytes(),
        hosted_lock,
        "a dry run must not touch the lock"
    );
    assert!(!fx.tgz_path().exists(), "a dry run vendors nothing");
    assert!(
        !fx.state_path().exists(),
        "a dry run writes no vendor ledger"
    );
    assert!(
        !fx.redirect_state_path().exists(),
        "no hosted ledger is ever written"
    );
}

/// The wet twin: vendoring over the hosted pin first restores the upstream
/// registry entry (`vendor_takeover_reverted_redirect`), then vendors; the
/// vendor ledger records the UPSTREAM entry as the original, so `vendor
/// --revert` lands on the registry entry — never back on the hosted URL.
#[tokio::test]
async fn vendor_over_hosted_pin_restores_upstream_then_revert_returns_to_registry() {
    let fx = npm_fixture();
    pin_hosted(&fx);
    let registry = mock_npm_registry().await;

    let (code, env) = vendor_online(&fx, &registry.uri(), &[]);
    assert_eq!(code, 0, "{env:#}");
    find_event(&env, "applied", None);
    let warned = find_event(&env, "skipped", Some("vendor_takeover_reverted_redirect"));
    assert!(
        warned["reason"]
            .as_str()
            .is_some_and(|m| m.contains("package-lock.json")),
        "the advisory names the restored lockfile: {warned:#}"
    );
    let lock: Value = serde_json::from_slice(&fx.lock_bytes()).unwrap();
    let entry = &lock["packages"]["node_modules/left-pad"];
    assert!(
        entry["resolved"]
            .as_str()
            .unwrap_or_default()
            .contains(".socket/vendor/"),
        "the lock is vendored: {lock:#}"
    );
    assert!(!fx
        .lock_bytes()
        .windows(HOSTED_ORIGIN.len())
        .any(|w| w == HOSTED_ORIGIN.as_bytes()));
    assert!(!fx.redirect_state_path().exists(), "no hosted ledger");

    let (code, env) = vendor_cli(fx.root(), &["--revert"]);
    assert_eq!(code, 0, "{env:#}");
    let lock: Value = serde_json::from_slice(&fx.lock_bytes()).unwrap();
    let entry = &lock["packages"]["node_modules/left-pad"];
    assert_eq!(
        entry["resolved"],
        format!("{}/left-pad/-/left-pad-1.3.0.tgz", registry.uri()),
        "revert lands on the upstream registry tarball: {lock:#}"
    );
    assert_eq!(entry["integrity"], UPSTREAM_INTEGRITY, "{lock:#}");
}

/// A hosted pin whose upstream entry cannot be restored (here: `--offline`,
/// so the registry lookup is impossible) fails the purl CLOSED with
/// `redirect_revert_failed` naming the checkout remedy — vendoring over a
/// live hosted pin would record the hosted fragment as the "original".
#[test]
fn unrestorable_hosted_pin_fails_closed() {
    let fx = npm_fixture();
    let hosted_lock = pin_hosted(&fx);

    let (code, env) = vendor_cli(
        fx.root(),
        &["--offline", "--patch-server-url", HOSTED_ORIGIN],
    );
    assert_eq!(code, 1, "{env:#}");
    let failed = find_event(&env, "failed", Some("redirect_revert_failed"));
    assert_eq!(failed["purl"], PURL);
    let detail = failed["error"].as_str().unwrap_or_default();
    assert!(
        detail.contains("git checkout") && detail.contains("package-lock.json"),
        "the refusal names the checkout remedy for the lockfile: {env:#}"
    );
    assert_eq!(
        fx.lock_bytes(),
        hosted_lock,
        "the hosted pin stays as found"
    );
    assert!(!fx.tgz_path().exists(), "no artifact for the refused purl");
    assert!(!fx.state_path().exists(), "no vendor ledger entry");
    assert!(!fx.redirect_state_path().exists());
}

/// Without `--patch-server-url` a URL on a non-Socket origin is NOT a
/// hosted pin, so no takeover is attempted and no `redirect_revert_failed`
/// can fire.
#[test]
fn hosted_url_on_unconfigured_origin_is_not_a_takeover() {
    let fx = npm_fixture();
    let lock = String::from_utf8(pin_hosted(&fx))
        .unwrap()
        .replace(HOSTED_ORIGIN, "https://unconfigured.example");
    std::fs::write(fx.root().join("package-lock.json"), lock).unwrap();

    let (_code, env) = vendor_cli(fx.root(), &[]);
    assert!(
        events(&env).iter().all(|e| {
            e["errorCode"] != "redirect_revert_failed"
                && e["errorCode"] != "vendor_takeover_reverted_redirect"
        }),
        "an unrecognized origin is not hosted state: {env:#}"
    );
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
            .is_some_and(|d| d.contains("`frobnicate`")),
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

/// A manifest record with a patch-target file ABSENT from the installed
/// copy (non-empty beforeHash, no --force) still vendors the package: the
/// artifact is the patch service's build, which carries the patched file,
/// and the installed tree is never written to.
#[test]
fn patch_target_absent_from_the_install_still_vendors() {
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

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(find_event(&env, "applied", None)["purl"], PURL, "{env:#}");
    let tgz = std::fs::read(fx.tgz_path()).unwrap();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(&tgz[..]));
    let absent = archive
        .entries()
        .unwrap()
        .map(Result::unwrap)
        .find(|e| e.path().unwrap().as_os_str() == "package/absent.js")
        .map(|mut e| {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut e, &mut bytes).unwrap();
            bytes
        });
    assert_eq!(
        absent.as_deref(),
        Some(PATCHED_INDEX),
        "the artifact carries the patched file"
    );
    assert!(!fx.root().join("node_modules/left-pad/absent.js").exists());
}

// ─────────────────────────────────────────────────────────────────────
// 5. unix fault injection: state-write failures
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
/// Is the test process running as root? Read-only directories are inert
/// under euid 0, so the fault-injection tests skip themselves.
#[cfg(unix)]
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

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
    if is_root() {
        eprintln!("skipped: chmod cannot make a directory read-only for root");
        return;
    }
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
/// `vendor_state_write_failed` failure, and the run exits 1 —
/// `reconcile_dropped` must not swallow the save error and exit 0 with a
/// ledger still listing the reverted purl.
#[cfg(unix)]
#[tokio::test]
async fn reconcile_state_write_failure_reports_failed_after_removal() {
    if is_root() {
        eprintln!("skipped: chmod cannot make a directory read-only for root");
        return;
    }
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
/// run exits 1 with the top-level `vendor_commit_failed` error. Like the
/// symlink refusal (#898), nothing of the package stands: it is a `failed`
/// event with that code, not `applied`, the artifact the backend wrote is
/// removed, and the human run claims no vendored package. (Before the
/// group commit this was a per-package `vendor_state_write_failed` next to
/// an already-rewired lock.)
#[cfg(unix)]
#[tokio::test]
async fn vendor_state_write_failure_reports_failed_event() {
    if is_root() {
        eprintln!("skipped: chmod cannot make a directory read-only for root");
        return;
    }
    let fx = npm_fixture();
    // The backend's artifact home stays writable; only the ledger's own
    // directory refuses writes.
    std::fs::create_dir_all(fx.vendor_dir().join("npm")).unwrap();
    chmod(&fx.vendor_dir(), 0o555);
    let _restore = RestorePerms(fx.vendor_dir());

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    assert_eq!(env["error"]["code"], "vendor_commit_failed", "{env:#}");
    assert_eq!(env["summary"]["applied"], 0, "{env:#}");
    let failed = find_event(&env, "failed", Some("vendor_commit_failed"));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert!(
        !events(&env)
            .iter()
            .any(|e| e["action"] == "applied" || e["errorCode"] == "vendor_prebuilt_downloaded"),
        "nothing reports the uncommitted vendoring as done: {env:#}"
    );
    assert!(
        !fx.tgz_path().exists(),
        "the uncommitted run leaves no orphan artifact"
    );
    assert!(!fx.state_path().exists(), "the ledger write failed");
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock rewire is committed with the ledger or not at all"
    );

    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &["vendor", "--cwd", fx.root().to_str().unwrap()],
        &[],
    );
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        !stdout.contains("Vendored 1 package") && !stdout.contains("Next steps"),
        "{stdout}\n{stderr}"
    );
}

/// #691: yarn 1 resolves the vendored `file:./.socket/vendor/…` tarball
/// against the directory it runs in, so in a workspaces project every
/// cold-cache install run from a member directory fails once vendoring
/// wires one. The vendor run must say so (and say nothing for a project
/// without workspaces).
#[test]
fn yarn_classic_workspaces_vendor_warns_about_member_dir_installs() {
    const CODE: &str = "yarn_classic_workspace_member_install_risk";
    let yarn_lock = format!(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n\
         left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"{REG_RESOLVED}\"\n  \
         integrity {REG_INTEGRITY}\n"
    );
    for workspaces in [true, false] {
        let fx = npm_fixture();
        std::fs::remove_file(fx.lock_path()).unwrap();
        let manifest = if workspaces {
            std::fs::create_dir_all(fx.root().join("a")).unwrap();
            std::fs::write(
                fx.root().join("a/package.json"),
                br#"{"name":"a","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}}"#,
            )
            .unwrap();
            r#"{"name":"fixture","version":"1.0.0","private":true,"workspaces":["a"]}"#
        } else {
            r#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"left-pad":"^1.3.0"}}"#
        };
        std::fs::write(fx.root().join("package.json"), manifest).unwrap();
        std::fs::write(fx.root().join("yarn.lock"), &yarn_lock).unwrap();

        let (code, env) = vendor_cli(fx.root(), &[]);
        assert_eq!(code, 0, "{env:#}");
        assert!(
            std::fs::read_to_string(fx.root().join("yarn.lock"))
                .unwrap()
                .contains("resolved \"file:./.socket/vendor/"),
            "{env:#}"
        );
        let warned = env["warnings"]
            .as_array()
            .is_some_and(|ws| ws.iter().any(|w| w["code"] == CODE));
        assert_eq!(warned, workspaces, "workspaces={workspaces}: {env:#}");
    }
}

/// #1379: a yarn classic lock a pre-v5 release vendored with the
/// patched manifest's new dependency in the block's sub-map but no lock
/// block for it. Releases since #591 refuse to write that, but on such a
/// lock `vendor --check` reported `vendor_check_ok` and `repair` left it
/// alone, while yarn 1 installs the dependency unpinned. Both now fail the
/// entry and name the descriptor; locking it turns the check green.
#[test]
fn yarn_classic_check_and_repair_flag_a_dangling_dependency_descriptor() {
    let fx = npm_fixture();
    std::fs::remove_file(fx.lock_path()).unwrap();
    std::fs::write(
        fx.root().join("package.json"),
        r#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"left-pad":"^1.3.0"}}"#,
    )
    .unwrap();
    let yarn_lock = fx.root().join("yarn.lock");
    std::fs::write(
        &yarn_lock,
        format!(
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
             # yarn lockfile v1\n\n\n\
             left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"{REG_RESOLVED}\"\n  \
             integrity {REG_INTEGRITY}\n"
        ),
    )
    .unwrap();
    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "{env:#}");
    let (code, env) = vendor_cli(fx.root(), &["--check"]);
    assert_eq!(code, 0, "the fresh vendor is healthy: {env:#}");

    // What a pre-v5 vendor of a patch adding `is-number` left behind.
    let wired = std::fs::read_to_string(&yarn_lock).unwrap();
    assert!(
        wired.contains("resolved \"file:./.socket/vendor/"),
        "{wired}"
    );
    assert!(
        wired.ends_with("==\n"),
        "left-pad is the last block: {wired}"
    );
    let dangling = format!("{wired}  dependencies:\n    is-number \"^7.0.0\"\n");
    std::fs::write(&yarn_lock, &dangling).unwrap();

    let (code, env) = vendor_cli(fx.root(), &["--check"]);
    assert_eq!(code, 1, "{env:#}");
    let failed = find_event(&env, "failed", Some("vendor_check_failed"));
    assert!(
        failed["reason"]
            .as_str()
            .is_some_and(|m| m.contains("is-number@^7.0.0")),
        "the check names the dangling descriptor: {env:#}"
    );

    let cwd = fx.root().to_str().unwrap();
    let (code, stdout, stderr) = run_cli(
        fx.root(),
        &["repair", "--json", "--offline", "--cwd", cwd],
        &[],
    );
    assert_ne!(code, 0, "{stdout}\n{stderr}");
    let env: Value = serde_json::from_str(&stdout).unwrap();
    let failed = find_event(&env, "failed", Some("vendor_dep_manifest_unlocked"));
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|m| m.contains("is-number@^7.0.0")),
        "{env:#}"
    );
    assert_eq!(
        std::fs::read_to_string(&yarn_lock).unwrap(),
        dangling,
        "repair leaves the lock as it was"
    );

    // Once the descriptor is locked, the check is green again.
    std::fs::write(
        &yarn_lock,
        format!("{dangling}\nis-number@^7.0.0:\n  version \"7.0.0\"\n"),
    )
    .unwrap();
    let (code, env) = vendor_cli(fx.root(), &["--check"]);
    assert_eq!(code, 0, "{env:#}");
}

/// #627: a symlinked lockfile (a lock shared with another checkout) is
/// refused like hosted mode refuses it — `redirect_symlinked_file_unsupported`,
/// exit 1 — instead of being renamed over: the link survives, its target
/// keeps the pre-run bytes, and no ledger names wiring that was never
/// written. A dry run predicts it with a `vendor_would_refuse_symlinked_file`
/// advisory. Covers npm's `package-lock.json` and yarn classic's `yarn.lock`
/// (the issue's report), both written through the shared group commit.
#[cfg(unix)]
#[tokio::test]
async fn vendor_refuses_a_symlinked_lock_instead_of_replacing_it() {
    let yarn_lock = format!(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n\
         left-pad@^1.3.0:\n  version \"1.3.0\"\n  resolved \"{REG_RESOLVED}\"\n  \
         integrity {REG_INTEGRITY}\n"
    );
    for linked in ["package-lock.json", "yarn.lock"] {
        let fx = npm_fixture();
        if linked == "yarn.lock" {
            std::fs::remove_file(fx.lock_path()).unwrap();
            std::fs::write(
                fx.root().join("package.json"),
                br#"{"name":"fixture","version":"1.0.0","private":true,"dependencies":{"left-pad":"^1.3.0"}}"#,
            )
            .unwrap();
            std::fs::write(fx.root().join(linked), &yarn_lock).unwrap();
        }
        let link = fx.root().join(linked);
        let original = std::fs::read(&link).unwrap();
        let shared = tempfile::tempdir().unwrap();
        let target = shared.path().join(linked);
        std::fs::rename(&link, &target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // The dry run, which captures nothing, predicts the refusal.
        let (code, env) = vendor_cli(fx.root(), &["--dry-run"]);
        assert_eq!(code, 0, "{linked}: {env:#}");
        let warning = find_event(&env, "skipped", Some("vendor_would_refuse_symlinked_file"));
        assert!(
            warning["reason"]
                .as_str()
                .is_some_and(|m| m.contains(linked)),
            "{linked}: the advisory names the link: {env:#}"
        );

        let (code, env) = vendor_cli(fx.root(), &[]);
        assert_eq!(code, 1, "{linked}: {env:#}");
        assert_eq!(
            env["error"]["code"], "redirect_symlinked_file_unsupported",
            "{linked}: {env:#}"
        );
        assert!(
            env["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains(linked)),
            "{linked}: the refusal names the link: {env:#}"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "{linked}: the link is kept"
        );
        assert_eq!(std::fs::read(&target).unwrap(), original, "{linked}");
        assert!(
            !fx.state_path().exists(),
            "{linked}: no ledger entry was committed"
        );
        // #898: "nothing was written" holds — the artifact the loop
        // downloaded before the commit was refused is removed — and the
        // package is reported refused, not applied.
        assert!(
            !fx.tgz_path().exists(),
            "{linked}: the refused run leaves no orphan artifact"
        );
        assert_eq!(env["summary"]["applied"], 0, "{linked}: {env:#}");
        let refused = find_event(&env, "failed", Some("redirect_symlinked_file_unsupported"));
        assert_eq!(refused["purl"], PURL, "{linked}: {env:#}");

        // The human run neither claims a vendored package nor advises
        // committing `.socket/vendor/`.
        let (code, stdout, stderr) = run_cli(
            fx.root(),
            &["vendor", "--cwd", fx.root().to_str().unwrap()],
            &[],
        );
        assert_eq!(code, 1, "{linked}: {stdout}\n{stderr}");
        assert!(stderr.contains(linked), "{linked}: {stdout}\n{stderr}");
        assert!(
            !stdout.contains("Vendored 1 package") && !stdout.contains("Next steps"),
            "{linked}: {stdout}\n{stderr}"
        );
        assert!(!fx.tgz_path().exists(), "{linked}");
    }
}

/// #898: a refused commit removes only the artifact dirs the run ADDED.
/// An artifact the pre-run ledger already names, deleted and redownloaded
/// in place by this run, is referenced without any commit, so the refusal
/// keeps it (the ledger still points there).
#[cfg(unix)]
#[tokio::test]
async fn refused_commit_keeps_an_artifact_the_ledger_already_names() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    let state_before = std::fs::read(fx.state_path()).unwrap();
    // The artifact is lost and the lock re-resolved from the registry
    // (e.g. a fresh `npm install`), and the lock is now a shared symlink.
    std::fs::remove_dir_all(fx.tgz_path().parent().unwrap()).unwrap();
    let shared = tempfile::tempdir().unwrap();
    let target = shared.path().join("package-lock.json");
    std::fs::write(&target, &fx.original_lock).unwrap();
    std::fs::remove_file(fx.lock_path()).unwrap();
    std::os::unix::fs::symlink(&target, fx.lock_path()).unwrap();

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 1, "{env:#}");
    assert_eq!(
        env["error"]["code"], "redirect_symlinked_file_unsupported",
        "{env:#}"
    );
    assert!(
        fx.tgz_path().is_file(),
        "the artifact the pre-run ledger names is kept: {env:#}"
    );
    assert_eq!(std::fs::read(fx.state_path()).unwrap(), state_before);
    assert_eq!(std::fs::read(&target).unwrap(), fx.original_lock);
}

/// #627 follow-up: an already-vendored package whose lock is LATER made a
/// symlink writes nothing on a re-run, so neither the dry run nor the wet
/// run may predict or raise the symlink refusal: the dry run previews it as
/// in sync with no `vendor_would_refuse_symlinked_file` advisory, and the
/// wet run is a no-op that keeps the link.
#[cfg(unix)]
#[tokio::test]
async fn in_sync_vendor_over_a_symlinked_lock_neither_warns_nor_refuses() {
    let fx = npm_fixture();
    assert_eq!(vendor_run(vendor_args(fx.root())).await, 0, "stage vendor");
    let shared = tempfile::tempdir().unwrap();
    let target = shared.path().join("package-lock.json");
    std::fs::rename(fx.lock_path(), &target).unwrap();
    std::os::unix::fs::symlink(&target, fx.lock_path()).unwrap();
    let wired = std::fs::read(&target).unwrap();

    let (code, env) = vendor_cli(fx.root(), &["--dry-run"]);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        !events(&env)
            .iter()
            .any(|e| e["errorCode"] == "vendor_would_refuse_symlinked_file"),
        "an in-sync package gets no symlink advisory: {env:#}"
    );

    let (code, env) = vendor_cli(fx.root(), &[]);
    assert_eq!(code, 0, "an in-sync re-run writes nothing: {env:#}");
    assert!(
        std::fs::symlink_metadata(fx.lock_path())
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link is kept"
    );
    assert_eq!(std::fs::read(&target).unwrap(), wired);
}

// ───────────── 6. service outage / source-flip idempotence ─────────────
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
        &["vendor", "--json", "--cwd", probe.root().to_str().unwrap()],
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
    let original = std::fs::read(fx.root().join(lock)).unwrap();
    let server = MockServer::start().await;
    mount_outage(&server).await;
    let (code, env, stderr) = vendor_via_service(fx.root(), &server.uri());
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert!(!fx.tgz_path().exists());
    assert_eq!(std::fs::read(fx.root().join(lock)).unwrap(), original);
    server.reset().await;
    mount_granted_artifact(&server, "left-pad-1.3.0.tgz", &alt).await;
    let (code, env, stderr) = vendor_via_service(fx.root(), &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(std::fs::read(fx.tgz_path()).unwrap(), alt);
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
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
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
        &["vendor", "--json", "--cwd", probe.path().to_str().unwrap()],
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
