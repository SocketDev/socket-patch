//! Integration tests for `apply`'s state invariants.
//!
//! These lock down two contracts that make `apply` safe to run from
//! deploy hooks and CI pipelines:
//!
//! 1. `apply` is read-only against `.socket/`. Even when fetching missing
//!    sources over the network, downloaded bytes go to an OS tempdir and
//!    `.socket/` itself is byte-identical before and after the run.
//! 2. `apply --offline` against a manifest with no usable local source
//!    surfaces a `partial_failure` JSON envelope and exits non-zero —
//!    the documented airgap behavior.
//!
//! Both tests run fully offline: no network calls, no real package
//! installs. The manifest references a synthetic PURL that the npm
//! crawler won't match, which trips the "no packages found / offline"
//! branches and exercises the invariants without needing a real fixture.

use std::path::Path;

use serde_json::json;

use super::apply_fixture::{
    hashed_file, install_npm_pkg, one_file, patch_record, run_apply, stage_blob, write_manifest,
    write_root_package_json,
};
use crate::common::{binary, git_sha256, hermetic_command};

/// One synthetic npm patch whose package is not installed and whose
/// `afterHash` blob is missing from `.socket/blobs/`, so `--offline` bails
/// and nothing else runs. `.socket/blobs/` holds a sentinel apply must not
/// touch.
fn write_project(root: &Path) {
    write_root_package_json(root);
    std::fs::create_dir_all(root.join("node_modules")).expect("create node_modules");
    write_manifest(
        root,
        json!({
            "pkg:npm/__invariant_test_pkg__@9.9.9": patch_record(
                "11111111-1111-4111-8111-111111111111",
                hashed_file("package/index.js", &"0".repeat(64), &"1".repeat(64)),
            )
        }),
    );
    stage_blob(root, "sentinel", b"do not modify me");
}

/// Every counter in the envelope's `summary` block must be exactly 0.
/// We enumerate the keys explicitly (rather than "applied == 0") so a
/// regression that started reporting work on these no-op paths — e.g. a
/// phantom `downloaded`, `verified`, or `skipped` — trips the test
/// instead of slipping through an unchecked field.
fn assert_summary_all_zero(summary: &serde_json::Value) {
    let obj = summary
        .as_object()
        .unwrap_or_else(|| panic!("summary must be a JSON object, got {summary}"));
    assert!(!obj.is_empty(), "summary object must not be empty");
    for (key, val) in obj {
        assert_eq!(
            val.as_u64(),
            Some(0),
            "summary.{key} must be 0 on this no-op path, got {val}"
        );
    }
}

const SCOPED_NPM_PURL: &str = "pkg:npm/scopedpkg@1.0.0";
const SCOPED_ORIGINAL: &[u8] = b"module.exports = function vulnerable() { return 'pwn'; };\n";
const SCOPED_PATCHED: &[u8] = b"module.exports = function safe() { return 'ok'; };\n";

/// Lay down a project with TWO manifest patches:
///   - an npm patch that is fully applicable offline (package installed,
///     patched blob present in `.socket/blobs/`), and
///   - a pypi patch whose blob is missing from `.socket/` entirely.
///
/// Used to prove the offline no-local-source guard is scoped to the
/// patches the run can actually apply (`--ecosystems` filter).
fn write_mixed_scope_project(root: &Path) {
    write_root_package_json(root);
    install_npm_pkg(root, "scopedpkg", "1.0.0", Some(SCOPED_ORIGINAL));
    write_manifest(
        root,
        json!({
            SCOPED_NPM_PURL: patch_record(
                "33333333-3333-4333-8333-333333333333",
                one_file("package/index.js", SCOPED_ORIGINAL, SCOPED_PATCHED),
            ),
            "pkg:pypi/__ghost_pkg__@9.9.9": patch_record(
                "44444444-4444-4444-8444-444444444444",
                hashed_file("ghost.py", &"2".repeat(64), &"3".repeat(64)),
            ),
        }),
    );
    stage_blob(root, &git_sha256(SCOPED_PATCHED), SCOPED_PATCHED);
}

/// Regression: the `--offline` no-local-source guard (and the download
/// planner feeding it) must only consider patches that are in scope for
/// THIS run. A patch filtered out by `--ecosystems` — or belonging to an
/// ecosystem this build can't apply at all — will never be applied, so
/// its missing `.socket/` sources must not fail a run whose in-scope
/// patches are all locally applicable: here the out-of-scope pypi patch
/// (no blob on disk) must not trip the offline bail for the npm patch.
#[test]
fn offline_ecosystems_filter_ignores_out_of_scope_missing_source() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_mixed_scope_project(tmp.path());

    let (code, stdout, _) = run_apply(
        tmp.path(),
        &["--json", "--offline", "--silent", "--ecosystems", "npm"],
        &[],
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(
        code, 0,
        "all in-scope (npm) patches have local sources; the out-of-scope pypi \
         patch must not trip the offline bail. envelope:\n{v}"
    );
    assert_eq!(v["status"], "success", "expected a clean apply, got {v}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == SCOPED_NPM_PURL),
        "the in-scope npm patch must actually be applied; got {events:?}"
    );
    // The patched bytes really landed on disk.
    assert_eq!(
        std::fs::read(
            tmp.path()
                .join("node_modules")
                .join("scopedpkg")
                .join("index.js")
        )
        .expect("read patched file"),
        SCOPED_PATCHED,
        "in-scope npm patch must be written to disk"
    );

    // CONTROL: the same fixture WITHOUT the `--ecosystems` filter puts the
    // sourceless pypi patch in scope, so the documented offline bail must
    // still fire — the guard is scoped, not disabled.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    write_mixed_scope_project(tmp2.path());
    let (code2, stdout2, _) = run_apply(tmp2.path(), &["--json", "--offline", "--silent"], &[]);
    assert_eq!(
        code2, 1,
        "with no ecosystem filter the sourceless pypi patch is in scope and \
         must still trip the offline bail; stdout=\n{stdout2}"
    );
    let v2: serde_json::Value =
        serde_json::from_str(&stdout2).expect("apply --json must emit valid JSON");
    assert_eq!(v2["status"], "partialFailure", "{v2}");
}

#[test]
fn offline_with_missing_source_emits_partial_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let (code, stdout, _) = run_apply(tmp.path(), &["--json", "--offline", "--silent"], &[]);

    // Exit code 1 is contract: any patch without a usable source under
    // `--offline` flips the run to partialFailure.
    assert_eq!(code, 1, "unexpected exit code; stdout=\n{stdout}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["status"], "partialFailure",
        "expected status=partialFailure, got {v}"
    );
    // `partialFailure` is distinct from a hard `error` envelope: the
    // command ran to completion and decided nothing was applicable. A
    // top-level `error` payload here would mean a different failure mode
    // slipped through wearing the partialFailure label.
    assert!(
        v.get("error").is_none(),
        "partialFailure must not carry a top-level error payload; got {v}"
    );
    // Nothing was applied, downloaded, skipped, or otherwise touched —
    // the offline guard bails before any work. Every summary counter
    // must be 0 (not just `applied`/`failed`), and no per-patch events
    // should be emitted on this short-circuit path.
    assert_summary_all_zero(&v["summary"]);
    let events = v["events"]
        .as_array()
        .expect("envelope must carry an events array");
    assert!(
        events.is_empty(),
        "offline bail emits no per-patch events; got {events:?}"
    );
}

#[test]
fn apply_does_not_mutate_socket_dir_offline() {
    // Even on the failure path (offline + missing source), apply must
    // not touch `.socket/`: every file's bytes must match exactly.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let socket = tmp.path().join(".socket");
    let before = snapshot_dir(&socket);
    let (code, stdout, _) = run_apply(tmp.path(), &["--json", "--offline", "--silent"], &[]);
    let after = snapshot_dir(&socket);

    // The run must have actually taken the failure path we care about —
    // otherwise an apply that errored out *before* reaching any write
    // would also leave `.socket/` pristine and the hash check would pass
    // vacuously. Pin the exit code AND the envelope status so the
    // no-mutation guarantee is anchored to the documented offline bail.
    assert_eq!(code, 1, "offline+missing should exit 1; stdout=\n{stdout}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(
        v["status"], "partialFailure",
        "expected the offline partialFailure path, got {v}"
    );
    assert_eq!(before, after, "apply --offline must not mutate .socket/");
}

#[test]
fn apply_does_not_mutate_socket_dir_when_no_packages_match() {
    // Same hash invariant when not offline. With no packages installed
    // and a synthetic PURL, apply's "no packages found" branch fires
    // before any fetch is attempted. `.socket/` must remain pristine.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());

    let socket = tmp.path().join(".socket");
    let before = snapshot_dir(&socket);
    let (code, stdout, _) = run_apply(tmp.path(), &["--json", "--silent"], &[]);
    let after = snapshot_dir(&socket);

    // Pin the bail itself, or a run that died early would leave
    // `.socket/` untouched and pass vacuously.
    assert_eq!(
        code, 1,
        "no-match / unfetchable run must exit 1; stdout=\n{stdout}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["status"], "partialFailure",
        "expected partialFailure on the no-match path, got {v}"
    );
    assert!(
        v.get("error").is_none(),
        "no-match path is a partialFailure, not a hard error; got {v}"
    );
    // Parity with the offline test: this bail path does no work either, so
    // every summary counter must be 0 and no per-patch events should be
    // emitted. Without these a regression that started reporting phantom
    // work (a spurious `failed`/`discovered`/`downloaded`, or fabricated
    // events) on the no-match branch would pass unnoticed.
    assert_summary_all_zero(&v["summary"]);
    let events = v["events"]
        .as_array()
        .expect("envelope must carry an events array");
    assert!(
        events.is_empty(),
        "no-match bail emits no per-patch events; got {events:?}"
    );
    assert_eq!(
        before, after,
        "apply must not mutate .socket/ on the no-match path"
    );
}

/// Apply against a directory with NO `.socket/` folder at all
/// emits a `status: "noManifest"` envelope in JSON mode and exits
/// 0 (not an error — there's just nothing to do). Covers the
/// early-return branch at the top of `commands::apply::run`.
#[test]
fn apply_with_no_socket_dir_emits_no_manifest_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Note: NO .socket/ directory at all — completely fresh tree.
    let (code, stdout, _) = run_apply(tmp.path(), &["--json"], &[]);
    assert_eq!(code, 0, "no-manifest is not an error; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope must be valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(v["status"], "noManifest");
    // noManifest is a clean no-op, not a partial failure dressed up: no
    // error payload, no events, and every summary counter at 0.
    assert!(
        v.get("error").is_none(),
        "noManifest must not carry an error payload; got {v}"
    );
    assert!(
        v["events"]
            .as_array()
            .expect("envelope must carry an events array")
            .is_empty(),
        "noManifest emits no events; got {}",
        v["events"]
    );
    assert_summary_all_zero(&v["summary"]);
}

/// Non-JSON / silent flag: same no-manifest case but in human
/// (non-JSON) mode with `--silent` suppresses the friendly
/// message. Exit still 0. Locks the silent-mode short-circuit.
#[test]
fn apply_with_no_socket_dir_silent_emits_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = hermetic_command(&binary())
        .args(["apply", "--silent"])
        .current_dir(tmp.path())
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "silent must produce no stdout; got {stdout:?}"
    );

    // Control run: the same no-manifest scenario WITHOUT `--silent` must
    // print the friendly skip message to stdout. Without this control the
    // test above would pass vacuously even if `--silent` did nothing and
    // the message simply never existed — i.e. it would not actually prove
    // the silent-mode short-circuit suppresses anything.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let loud = hermetic_command(&binary())
        .args(["apply"])
        .current_dir(tmp2.path())
        .output()
        .expect("run socket-patch");
    assert_eq!(loud.status.code(), Some(0));
    let loud_stdout = String::from_utf8_lossy(&loud.stdout);
    assert!(
        loud_stdout.contains("No patch manifest found; nothing to apply."),
        "non-silent no-manifest run must print the skip message; got {loud_stdout:?}"
    );
}

/// Regression: only a genuine NotFound means "no `.socket/` set up". Any
/// other stat error — an unreadable `.socket/` (root-owned directory,
/// restrictive ACL), a plain file where `.socket/` should be, a symlink
/// loop — must NOT take the `status: noManifest` / exit-0 path: a project
/// whose patches were never even read would report "nothing to apply",
/// which the install hook and CI both read as success. Fail closed.
#[cfg(unix)]
#[test]
fn apply_with_unreadable_socket_dir_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_project(tmp.path());
    let socket = tmp.path().join(".socket");
    let manifest = socket.join("manifest.json");
    let restore = || {
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755));
    };

    // Drop the search bit: the manifest is still there, apply just cannot
    // stat it.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000))
        .expect("chmod .socket");
    // In-test control: as root (or on a filesystem that ignores mode bits)
    // the stat still succeeds and there is no fail-open case to exercise.
    if std::fs::metadata(&manifest).is_ok() {
        restore();
        eprintln!("SKIP: .socket/ still readable after chmod 000 (running as root?)");
        return;
    }

    let (code, stdout, _) = run_apply(tmp.path(), &["--json"], &[]);
    restore();

    assert_ne!(
        code, 0,
        "an unreadable manifest must not report success; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope must be valid JSON");
    assert_ne!(
        v["status"], "noManifest",
        "\"cannot read\" is not \"no manifest\"; envelope: {v}"
    );
    assert_eq!(
        v["error"]["code"], "manifest_unreadable",
        "expected the manifest_unreadable envelope error; envelope: {v}"
    );
}

/// Lay down a project with TWO npm manifest patches, BOTH with their
/// patched blobs staged (so the offline no-local-source guard never
/// fires and the only difference between them is matchability):
///   - `scopedpkg@1.0.0` is installed on disk and fully applicable;
///   - `__ghost_pkg__@9.9.9` matches nothing on disk.
fn write_partial_match_project(root: &Path) {
    write_root_package_json(root);
    install_npm_pkg(root, "scopedpkg", "1.0.0", Some(SCOPED_ORIGINAL));
    write_manifest(
        root,
        json!({
            SCOPED_NPM_PURL: patch_record(
                "33333333-3333-4333-8333-333333333333",
                one_file("package/index.js", SCOPED_ORIGINAL, SCOPED_PATCHED),
            ),
            "pkg:npm/__ghost_pkg__@9.9.9": patch_record(
                "44444444-4444-4444-8444-444444444444",
                one_file("package/index.js", b"ghost original\n", b"ghost patched\n"),
            ),
        }),
    );
    stage_blob(root, &git_sha256(SCOPED_PATCHED), SCOPED_PATCHED);
    stage_blob(root, &git_sha256(b"ghost patched\n"), b"ghost patched\n");
}

/// PINS the current (asymmetric) unmatched-purl exit semantics so any
/// change to them is deliberate. Today:
///
///   - a manifest whose patches ALL miss (no installed package matches)
///     exits 1 with `status: partialFailure`, while
///   - a MIXED manifest (one patch applied, one unmatched) exits 0 with
///     `status: success` and only a per-purl `skipped` event
///     (`errorCode: package_not_installed`) recording the miss.
///
/// The asymmetry is a known open decision, not an endorsement: CI that
/// gates on the exit code reads the mixed run as fully patched even when
/// a manifest-listed CVE patch was silently not applied (2026-08-18 pnpm
/// matrix, apply-pnpm8 leg), while install hooks want the all-miss case
/// to STOP exiting 1 (it fails `npm install` from the postinstall hook).
/// Resolving either direction changes a documented contract for the
/// other consumer — whoever does it must update BOTH halves of this test
/// and the hook/CI guidance together.
///
/// Narrowed by #403: an unmatched purl the project's lockfiles resolve
/// (deliberately not installed here) never fails the all-miss run — see
/// `lockfile_only_skip.rs`. The ghost purl below has no lock evidence, so
/// both halves still hold for it.
#[test]
fn unmatched_purl_exit_semantics_are_pinned() {
    // Mixed manifest: applied + unmatched → exit 0, status success,
    // with the miss visible only as a skipped event.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_partial_match_project(tmp.path());
    let (code, stdout, _) = run_apply(tmp.path(), &["--json", "--offline", "--silent"], &[]);
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("apply --json must emit valid JSON");
    assert_eq!(code, 0, "mixed manifest pins exit 0 today; envelope:\n{v}");
    assert_eq!(
        v["status"], "success",
        "mixed manifest pins status=success; {v}"
    );
    assert_eq!(v["summary"]["applied"], 1, "{v}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == SCOPED_NPM_PURL),
        "installed patch must be applied; {events:?}"
    );
    let ghost = events
        .iter()
        .find(|e| e["purl"] == "pkg:npm/__ghost_pkg__@9.9.9")
        .unwrap_or_else(|| panic!("unmatched purl must surface as an event; {events:?}"));
    assert_eq!(ghost["action"], "skipped", "{ghost}");
    assert_eq!(
        ghost["errorCode"], "package_not_installed",
        "the miss must be machine-identifiable; {ghost}"
    );

    // All-miss manifest (same ghost patch alone, blob still staged so the
    // offline source guard is not what fires) → exit 1, partialFailure.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    write_partial_match_project(tmp2.path());
    std::fs::remove_dir_all(tmp2.path().join("node_modules")).expect("uninstall scopedpkg");
    let (code2, stdout2, _) = run_apply(tmp2.path(), &["--json", "--offline", "--silent"], &[]);
    let v2: serde_json::Value =
        serde_json::from_str(&stdout2).expect("apply --json must emit valid JSON");
    assert_eq!(
        code2, 1,
        "all-miss manifest pins exit 1 today; envelope:\n{v2}"
    );
    assert_eq!(v2["status"], "partialFailure", "{v2}");
}

use crate::vlt_hosted_common;
use crate::vlt_vendored;

/// A vlt-vendored purl: `apply` yields it to the vendor ledger (the
/// committed dir artifact is what vlt installs), leaves `.socket/`
/// byte-identical and patches nothing in place.
#[test]
fn apply_yields_a_vlt_vendored_purl_and_leaves_socket_untouched() {
    use vlt_hosted_common as hosted;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vlt_vendored::vendored_project(root, true);
    let before = snapshot_dir(&root.join(".socket"));
    let cwd = root.to_str().unwrap().to_string();
    let (code, v, stderr) = hosted::run_json(root, &["apply", "--offline", "--cwd", &cwd], &[]);
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    assert!(v.to_string().contains("vendored"), "{v:#}");
    assert_eq!(snapshot_dir(&root.join(".socket")), before);
    assert_eq!(
        std::fs::read(root.join("node_modules/left-pad/index.js")).unwrap(),
        hosted::PRISTINE
    );
}

fn snapshot_dir(dir: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                let rel = e
                    .path()
                    .strip_prefix(dir)
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                out.insert(rel, std::fs::read(e.path()).unwrap());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Manifest keys no crawler of this CLI can look for
// ---------------------------------------------------------------------------

/// A purl of an ecosystem this CLI has no crawler for (what a newer
/// socket-patch would record) and a known type in another case.
const UNSUPPORTED_SWIFT: &str = "pkg:swift/github.com/apple/swift-nio@2.60.0";
const UNSUPPORTED_CASE: &str = "pkg:NPM/left-pad@1.3.0";

/// The installed, applicable `scopedpkg` patch (blob staged) beside
/// `extra` records, which share one staged blob of their own.
fn write_project_with_extra_keys(root: &Path, extra: &[&str]) {
    write_root_package_json(root);
    install_npm_pkg(root, "scopedpkg", "1.0.0", Some(SCOPED_ORIGINAL));
    let mut patches = serde_json::Map::new();
    patches.insert(
        SCOPED_NPM_PURL.to_string(),
        patch_record(
            "33333333-3333-4333-8333-333333333333",
            one_file("package/index.js", SCOPED_ORIGINAL, SCOPED_PATCHED),
        ),
    );
    for (i, key) in extra.iter().enumerate() {
        patches.insert(
            key.to_string(),
            patch_record(
                &format!("55555555-5555-4555-8555-{i:012}"),
                one_file("package/index.js", b"other original\n", b"other patched\n"),
            ),
        );
    }
    write_manifest(root, serde_json::Value::Object(patches));
    stage_blob(root, &git_sha256(SCOPED_PATCHED), SCOPED_PATCHED);
    stage_blob(root, &git_sha256(b"other patched\n"), b"other patched\n");
}

/// Drop the `scopedpkg` record, leaving only the extra keys.
fn drop_scoped_record(root: &Path) {
    let manifest_path = root.join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    manifest["patches"]
        .as_object_mut()
        .unwrap()
        .remove(SCOPED_NPM_PURL);
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn skipped_with(v: &serde_json::Value, code: &str) -> Vec<String> {
    let mut purls: Vec<String> = v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["action"] == "skipped" && e["errorCode"] == code)
        .filter_map(|e| e["purl"].as_str().map(str::to_string))
        .collect();
    purls.sort();
    purls
}

/// `partition_purls` drops a record whose purl type has no crawler, so
/// `apply` used to pass over it unseen: "No patches to apply.", exit 0,
/// `success` with no event. It now names each one (a `skipped` /
/// `unsupported_ecosystem` event, a `warnings[]` entry, a stderr warning)
/// and still exits 0: a newer CLI's ecosystem in a committed manifest must
/// not break an older CLI's CI run.
#[test]
fn apply_names_records_of_an_unsupported_ecosystem() {
    // Alone: nothing this CLI can apply, but not a silent "nothing to do".
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project_with_extra_keys(tmp.path(), &[UNSUPPORTED_SWIFT, UNSUPPORTED_CASE]);
    drop_scoped_record(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(
        code, 0,
        "an unsupported ecosystem never fails apply; {v}\n{stderr}"
    );
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(
        skipped_with(&v, "unsupported_ecosystem"),
        vec![UNSUPPORTED_CASE, UNSUPPORTED_SWIFT],
        "{v}"
    );
    let warning = v["warnings"]
        .as_array()
        .and_then(|w| w.iter().find(|w| w["code"] == "unsupported_ecosystem"))
        .unwrap_or_else(|| panic!("no unsupported_ecosystem warning: {v}"));
    let detail = warning["detail"].as_str().unwrap();
    assert!(
        detail.contains(UNSUPPORTED_SWIFT) && detail.contains(UNSUPPORTED_CASE),
        "the warning names the records: {detail}"
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains("Warning:")
            && stderr.contains(UNSUPPORTED_SWIFT)
            && stderr.contains(UNSUPPORTED_CASE),
        "the human run names them on stderr: {stderr}"
    );
    // The case variant gets the fix, not just the fact.
    assert!(stderr.contains("`pkg:npm/`"), "{stderr}");

    // Beside an applicable patch: that one applies, the other is named.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project_with_extra_keys(tmp.path(), &[UNSUPPORTED_SWIFT]);
    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(code, 0, "{v}\n{stderr}");
    assert_eq!(v["summary"]["applied"], 1, "{v}");
    assert_eq!(
        skipped_with(&v, "unsupported_ecosystem"),
        vec![UNSUPPORTED_SWIFT],
        "{v}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/scopedpkg/index.js")).unwrap(),
        SCOPED_PATCHED
    );
}

/// A key that is not a purl at all (a hand-edited manifest) can never be
/// matched to a package, by this CLI or a newer one: its patch fails by
/// name (exit 1) while every other patch still applies.
#[test]
fn apply_fails_a_manifest_key_that_is_not_a_purl() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project_with_extra_keys(tmp.path(), &["left-pad@1.3.0"]);

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(code, 1, "{v}\n{stderr}");
    assert_eq!(v["status"], "partialFailure", "{v}");
    let failed = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "failed")
        .unwrap_or_else(|| panic!("no failed event: {v}"));
    assert_eq!(failed["purl"], "left-pad@1.3.0", "{v}");
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|e| e.contains("not a package URL")),
        "{failed}"
    );
    assert_eq!(
        v["summary"]["applied"], 1,
        "the valid patch still applies: {v}"
    );

    // Alone, it is still a failure, not "No patches to apply." exit 0.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_project_with_extra_keys(tmp.path(), &["left-pad@1.3.0"]);
    drop_scoped_record(tmp.path());
    let (code, stdout, stderr) = run_apply(tmp.path(), &["--offline", "--silent"], &[]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains("left-pad@1.3.0") && stderr.contains("not a package URL"),
        "the error prints even under --silent: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// An unreadable vendor ledger
// ---------------------------------------------------------------------------

/// `apply` and `apply --check` decide which purls `socket-patch vendor`
/// owns from `.socket/vendor/state.json`. A ledger they cannot read used
/// to degrade to "nothing vendored" without a word, where rollback and
/// remove report `vendor_state_unreadable`. The agent patches still apply
/// (and the check still passes: an agent-only run must not fail over it),
/// but the run says that vendor ownership was not consulted.
#[test]
fn apply_warns_when_the_vendor_ledger_is_unreadable() {
    let project = || {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_project_with_extra_keys(tmp.path(), &[]);
        let vendor_dir = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor_dir).unwrap();
        std::fs::write(vendor_dir.join("state.json"), "{ torn ledger").unwrap();
        tmp
    };
    let ledger_warning = |v: &serde_json::Value| -> String {
        v["warnings"]
            .as_array()
            .and_then(|w| w.iter().find(|w| w["code"] == "vendor_state_unreadable"))
            .and_then(|w| w["detail"].as_str())
            .unwrap_or_else(|| panic!("no vendor_state_unreadable warning: {v}"))
            .to_string()
    };

    let tmp = project();
    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(code, 0, "the agent patch still applies; {v}\n{stderr}");
    assert_eq!(v["summary"]["applied"], 1, "{v}");
    assert!(ledger_warning(&v).contains("state.json"), "{v}");

    // Now patched: the read-only check passes, with the same warning.
    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json", "--offline"], &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(code, 0, "{v}\n{stderr}");
    assert!(ledger_warning(&v).contains("state.json"), "{v}");

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--check", "--offline"], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("Warning:") && stderr.contains("state.json"),
        "the human check names the ledger: {stderr}"
    );

    let tmp = project();
    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--offline"], &[]);
    assert_eq!(code, 0, "{stderr}");
    assert!(
        stderr.contains("Warning:") && stderr.contains("state.json"),
        "the human apply names the ledger: {stderr}"
    );
}
