//! `rollback`'s render suite (#1089): the human-mode (no `--json`, no
//! `--silent`) output of `commands/rollback.rs`. Behavior is asserted
//! through `--json` codes, events and disk state in
//! `rollback_failure_paths.rs`; the sentence checks here are the render
//! checks, one per message family.
//!
//! Lines pinned: the dry-run verification summary and its conditional
//! counts, the wet "Rolled back packages:" / "(already original)" report,
//! the not-installed warning block, `--verbose` per-file details, the
//! `--preserve-state` closing message, the empty-manifest announce, the
//! boundary `Error:` lines, the vendored revert / unwire / preview lines,
//! the drift-keep notice, the hosted restore / preview / refusal lines,
//! the pre-v5 ledger retire lines, the Bun and vlt reinstall advisories,
//! the manifest-write failure line (macOS) and the interactive confirm
//! decline (PTY).

use serde_json::{json, Value};

use crate::common;
use crate::common::git_sha256;
use crate::rollback_fixture::*;

/// The HUMAN dry-run summary (`--dry-run` with no `--json`): the
/// verification header, the can-rollback count, the would-be manifest
/// removal block, and the "Would free" GC preview — none of which any
/// `--json` dry-run test renders. Nothing may be mutated.
#[test]
fn human_dry_run_summary_lists_counts_and_would_free() {
    let fx = patched_fixture();
    let manifest_before =
        std::fs::read(fx.socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(fx.root.path(), &["rollback", "--dry-run", "--offline"]);
    assert_eq!(
        code, 0,
        "human dry run must exit 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Rollback verification complete:"),
        "the dry-run header must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 package can be rolled back"),
        "the can-rollback count must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Would remove 1 patch from manifest:")
            && stdout.contains(&format!("  - {}", fx.purl)),
        "the would-be manifest removal must be previewed; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Would free") && stdout.contains("of unused blobs and archives"),
        "the GC preview must print its would-free line; stdout=\n{stdout}"
    );

    // Disk untouched.
    assert_eq!(
        std::fs::read(fx.pkg_dir.join("index.js")).expect("read installed file"),
        fx.after,
        "dry run must not restore the file"
    );
    assert_eq!(
        std::fs::read(fx.socket.join("manifest.json")).expect("manifest exists"),
        manifest_before,
        "dry run must leave the manifest byte-identical"
    );
}

/// Wet human run over one already-original entry plus one not-installed
/// entry: the "(already original)" line prints on stdout and the
/// not-installed warning block prints on stderr — and the run still
/// exits 0 (per-package semantics).
#[test]
fn human_wet_reports_already_original_and_not_installed() {
    let before: &[u8] = b"already-orig-original\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(b"already-orig-patched\n");
    let purl = "pkg:npm/already-orig@1.0.0";
    let ghost_purl = "pkg:npm/covgap-ghost@2.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Installed at the BEFORE bytes: rollback is a no-op for it.
    install_npm_pkg(tmp.path(), "node_modules", "already-orig", "1.0.0", before);
    write_socket_manifest(
        tmp.path(),
        &[
            manifest_entry(
                purl,
                "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                &before_hash,
                &after_hash,
            ),
            manifest_entry(
                ghost_purl,
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                &git_sha256(b"ghost-original\n"),
                &git_sha256(b"ghost-patched\n"),
            ),
        ],
    );

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(
        code, 0,
        "already-original + not-installed exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Rolled back packages:")
            && stdout.contains(&format!("  {purl} (already original)")),
        "the no-op must print its '(already original)' line; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("Warning: 1 manifest patch had no matching installed package:")
            && stderr.contains(&format!("  - {ghost_purl}")),
        "the not-installed warning block must print on stderr; stderr=\n{stderr}"
    );
}

/// `--verbose` per-file details on a hash-mismatch failure: the humanized
/// `[hash mismatch]` label plus the `message:` and `expected:` lines
/// (populated exactly on this status) — and the wet "Failed to roll back:"
/// section with exit 1.
#[test]
fn human_verbose_hash_mismatch_details() {
    let before: &[u8] = b"mismatch-original\n";
    let after: &[u8] = b"mismatch-patched\n";
    let drifted: &[u8] = b"locally drifted content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);
    let purl = "pkg:npm/covgap-drifted@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let pkg_dir = install_npm_pkg(
        tmp.path(),
        "node_modules",
        "covgap-drifted",
        "1.0.0",
        drifted,
    );
    let socket = write_socket_manifest(
        tmp.path(),
        &[manifest_entry(
            purl,
            "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            &before_hash,
            &after_hash,
        )],
    );
    // Before-blob staged so the missing-blob gate never trips: the failure
    // under test is the engine's hash-mismatch verification.
    common::write_blob(&socket, &before_hash, before);

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes", "--verbose"]);
    assert_eq!(
        code, 1,
        "a hash mismatch must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Failed to roll back:") && stdout.contains(purl),
        "the wet failure section must name the package; stdout=\n{stdout}"
    );
    // Exit 1: the error stream says so too, not only the stdout report.
    assert!(
        stderr.ends_with("Error: Some patches could not be rolled back.\n"),
        "stderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Detailed verification:"),
        "--verbose must print the details header; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("[hash mismatch]"),
        "the humanized status label must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("message: File has been modified after patching"),
        "the verbose message line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("expected: {after_hash}")),
        "the verbose expected-hash line must print; stdout=\n{stdout}"
    );

    // Fail-closed: file untouched, manifest entry retained.
    assert_eq!(
        std::fs::read(pkg_dir.join("index.js")).expect("read file"),
        drifted,
        "a mismatched file must never be overwritten"
    );
    let m: Value = serde_json::from_str(
        &std::fs::read_to_string(socket.join("manifest.json")).expect("manifest exists"),
    )
    .expect("valid manifest JSON");
    assert!(
        m["patches"].get(purl).is_some(),
        "a failed entry must stay in the manifest; manifest={m}"
    );
}

/// The human `--preserve-state` closing message — every prior
/// preserve-state test runs `--json`.
#[test]
fn human_preserve_state_closing_message() {
    let fx = patched_fixture();
    let manifest_before =
        std::fs::read(fx.socket.join("manifest.json")).expect("read manifest bytes");

    let (code, stdout, stderr) = run(
        fx.root.path(),
        &["rollback", "--offline", "--preserve-state"],
    );
    assert_eq!(
        code, 0,
        "preserve-state rollback exits 0; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Manifest entry preserved (--preserve-state)"),
        "the preserve-state closing message must print; stdout=\n{stdout}"
    );
    // The system IS restored, the state is NOT.
    assert_eq!(
        std::fs::read(fx.pkg_dir.join("index.js")).expect("read restored file"),
        fx.before,
        "the file restore still happens under --preserve-state"
    );
    assert_eq!(
        std::fs::read(fx.socket.join("manifest.json")).expect("manifest exists"),
        manifest_before,
        "--preserve-state must not rewrite the manifest"
    );
}

/// The dry-run human summary's two conditional lines: "N package(s)
/// already in original state" and "N package(s) cannot be rolled back" —
/// one no-op entry plus one drifted entry render both, the can-rollback
/// count excludes them, and nothing is mutated.
#[test]
fn human_dry_run_summary_reports_already_original_and_failed() {
    let noop_before: &[u8] = b"dryboth-noop-original\n";
    let noop_purl = "pkg:npm/covgap-dry-noop@1.0.0";
    let drift_before: &[u8] = b"dryboth-drift-original\n";
    let drifted: &[u8] = b"dryboth-locally-drifted\n";
    let drift_purl = "pkg:npm/covgap-dry-drift@1.0.0";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Installed at the BEFORE bytes: verification says already-original.
    install_npm_pkg(
        tmp.path(),
        "node_modules",
        "covgap-dry-noop",
        "1.0.0",
        noop_before,
    );
    // Installed at DRIFTED bytes: verification says hash-mismatch.
    let drift_dir = install_npm_pkg(
        tmp.path(),
        "node_modules",
        "covgap-dry-drift",
        "1.0.0",
        drifted,
    );
    let socket = write_socket_manifest(
        tmp.path(),
        &[
            manifest_entry(
                noop_purl,
                "88888888-8888-4888-8888-888888888888",
                &git_sha256(noop_before),
                &git_sha256(b"dryboth-noop-patched\n"),
            ),
            manifest_entry(
                drift_purl,
                "99999999-9999-4999-8999-999999999999",
                &git_sha256(drift_before),
                &git_sha256(b"dryboth-drift-patched\n"),
            ),
        ],
    );
    // Both before-blobs staged so the missing-blob gate never downloads:
    // the statuses under test are already_original and hash_mismatch.
    common::write_blob(&socket, &git_sha256(noop_before), noop_before);
    common::write_blob(&socket, &git_sha256(drift_before), drift_before);
    let manifest_bytes = std::fs::read(socket.join("manifest.json")).unwrap();

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--dry-run", "--offline"]);
    assert_eq!(
        code, 1,
        "the drifted entry cannot roll back, so the preview exits 1; \
         stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("Rollback verification complete:"),
        "the dry-run header must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("0 packages can be rolled back"),
        "a no-op and a failure leave nothing rollback-able; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 package already in original state"),
        "the already-original summary line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 package cannot be rolled back"),
        "the cannot-rollback summary line must print; stdout=\n{stdout}"
    );
    // Preview, no mutations.
    assert_eq!(
        std::fs::read(drift_dir.join("index.js")).unwrap(),
        drifted,
        "dry run must not touch the drifted file"
    );
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).unwrap(),
        manifest_bytes,
        "dry run must leave the manifest byte-identical"
    );
}

/// A dry run over a locally modified file exits 1 AND says why: the
/// reason appears exactly once, under the verification counts (a dry run
/// has no other failure report).
#[test]
fn dry_run_failure_prints_reason_once() {
    let fx = patched_fixture();
    std::fs::write(fx.pkg_dir.join("index.js"), b"locally-edited\n").expect("drift file");

    let (code, stdout, stderr) = run(fx.root.path(), &["rollback", "--offline", "--dry-run"]);
    assert_eq!(
        code, 1,
        "a dry run that cannot roll back exits 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("1 package cannot be rolled back"),
        "the count line must print; stdout=\n{stdout}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        stdout.contains("Failed to roll back:"),
        "the dry run must carry the failure section; stdout=\n{stdout}"
    );
    assert_eq!(
        combined.matches("modified after patching").count(),
        1,
        "the reason must appear exactly once; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert_eq!(
        combined.matches(fx.purl).count(),
        1,
        "the package must be named exactly once; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
}

/// The unscoped empty-manifest announce still prints when it should: a
/// manifest exists, lists no patches, and no vendored or hosted leg has
/// work.
#[test]
fn empty_manifest_announces_no_patches() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_socket_manifest(tmp.path(), &[]);

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "-y"]);
    assert_eq!(
        code, 0,
        "an empty manifest is a clean no-op; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("No patches found in manifest"),
        "the empty-manifest announce must print; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
}

/// A syntactically invalid manifest prints the parse failure as an
/// `Error:` stderr line, exit 1. The `--json` twin pins
/// `manifest_invalid` in `rollback_failure_paths.rs`.
#[test]
fn corrupt_manifest_prints_human_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), b"{ not json").expect("write corrupt manifest");

    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline"]);
    assert_eq!(
        code, 1,
        "human mode exits 1 too; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Error:") && stderr.contains("Failed to parse manifest JSON"),
        "the human error must print on stderr; stderr=\n{stderr}"
    );
}

/// `.socket/blobs` existing as a regular FILE: the boundary error prints a
/// bare `Error:` stderr line, exit 1. The `--json` envelope shape is pinned
/// in `rollback_failure_paths.rs`.
#[test]
fn blobs_path_as_file_prints_human_error() {
    let tmp = blobs_path_as_file_fixture();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Error:"),
        "the human boundary error must print on stderr; stderr=\n{stderr}"
    );
}

/// A ledger entry with no vendor backend prints the "Failed to revert
/// vendoring" stderr line, exit 1. The `--json` twin pins
/// `vendor_revert_failed` in `rollback_failure_paths.rs`.
#[test]
fn vendored_unknown_ecosystem_prints_human_failure() {
    let fx = vendor_fixture();
    vendor(&fx);
    rewrite_vendored_ecosystem(&fx, "brew");
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains(&format!("Failed to revert vendoring for {V_PURL}")),
        "the human failure line must print on stderr; stderr=\n{stderr}"
    );
}

/// Human dry-run previews of the vendored leg: "Would revert vendoring"
/// (default) and "Would unwire … (artifact preserved)" (--preserve-state),
/// with lock, ledger, and artifact all untouched.
#[test]
fn vendored_dry_run_previews_in_human_mode() {
    let fx = vendor_fixture();
    vendor(&fx);
    let wired_lock = fx.lock_bytes();
    let state_before = std::fs::read(fx.state_path()).unwrap();

    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!("Would revert vendoring for {V_PURL}")),
        "the default preview line must print; stdout=\n{stdout}"
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

    let (code, stdout, stderr) = run(
        fx.root(),
        &["rollback", "--offline", "--dry-run", "--preserve-state"],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Would unwire vendoring for {V_PURL} (artifact preserved)"
        )),
        "the preserve-state preview line must print; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), wired_lock, "still untouched");
    assert!(fx.tgz_path().is_file(), "still kept");
}

/// Wet human-mode vendored messages: "Reverted vendoring for {key}" plus
/// the reinstall note on the default run, and "Unwired vendoring for {key}
/// (artifact preserved)" under --preserve-state.
#[test]
fn vendored_wet_human_messages() {
    // ── default: revert ──
    let fx = vendor_fixture();
    vendor(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!("Reverted vendoring for {V_PURL}")),
        "the wet revert line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 unwired package keeps its patched bytes"),
        "the reinstall note must print; stdout=\n{stdout}"
    );
    assert_eq!(
        fx.lock_bytes(),
        fx.original_lock,
        "the lock must be restored byte-for-byte"
    );
    assert!(!fx.tgz_path().exists(), "the artifact must be deleted");

    // ── --preserve-state: unwire ──
    let fx = vendor_fixture();
    vendor(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--preserve-state"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Unwired vendoring for {V_PURL} (artifact preserved)"
        )),
        "the preserve-state wet line must print; stdout=\n{stdout}"
    );
    assert_eq!(fx.lock_bytes(), fx.original_lock, "lock restored");
    assert!(fx.tgz_path().is_file(), "artifact kept");
    assert!(fx.state_path().is_file(), "ledger entry kept");
}

/// A corrupt vendor ledger prints the error-class `Error
/// (vendor_state_unreadable):` notice on stderr, exit 1. The `--json` twin
/// pins the warning and the fail-closed cleanup in
/// `rollback_failure_paths.rs`.
#[test]
fn corrupt_vendor_ledger_prints_human_notice() {
    let fx = vendor_fixture();
    corrupt_vendor_ledger(&fx);
    let (code, stdout, stderr) = run(fx.root(), &["rollback", "--offline", "--yes"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Error (vendor_state_unreadable):"),
        "the error-class notice must print on stderr; stderr=\n{stderr}"
    );
}

/// The human drift-keep notice: a vendored entry whose wiring matches
/// nothing in the live lock is kept, and the error-class "Kept vendored
/// state for …" line prints on stderr with exit 1.
#[test]
fn drift_keep_prints_human_notice() {
    const DRIFT_PURL: &str = "pkg:npm/__covgap_drift_kept__@1.0.0";
    const DRIFT_UUID: &str = "33333333-3333-4333-8333-333333333333";

    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
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

    // Ledger wired with a fragment the lock does not contain (the
    // in_process_rollback_vendored.rs drift shape).
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

    let (code, stdout, stderr) = run(root, &["rollback", "--offline", "--yes"]);
    assert_eq!(
        code, 1,
        "a drift-keep exits partial_failure; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("Kept vendored state for {DRIFT_PURL}"))
            && stderr.contains("drifted"),
        "the drift-keep notice must print on stderr; stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read(&state_path).unwrap(),
        original_state.as_bytes(),
        "the drift-kept ledger must survive byte-identical"
    );
    assert_eq!(
        std::fs::read(socket.join("manifest.json")).unwrap(),
        original_manifest.as_bytes(),
        "the manifest entry must survive a drift-keep"
    );
}

/// Human wet run over a hosted-only (manifest-less, ledger-less) project:
/// the "Restored {purl} to its upstream registry entry" line and the
/// reinstall note — with the lock entry actually restored and no
/// `.socket/` residue. The unscoped "No patches found in manifest" line is
/// reserved for a run with no work in ANY leg: a project whose patches are
/// all hosted has work, so the line must NOT print alongside the restore.
#[test]
fn hosted_human_wet_announces_and_unwinds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let (code, stdout, stderr) = run_hosted(tmp.path(), &["rollback", "--yes"], Some(&registry));
    assert_eq!(
        code, 0,
        "the hosted-only rollback succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        !stdout.contains("No patches found in manifest"),
        "the empty-manifest announce must not print when the hosted leg has work; \
         stdout=\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "Restored {LP_PURL} to its upstream registry entry"
        )),
        "the wet restore line must print; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("1 unwired package keeps its patched bytes"),
        "the reinstall note must print; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the lock entry must be restored to the upstream registry entry"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "no ledger is ever written"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "a fully restored hosted project keeps no .socket/ residue (apply.lock \
         removed by the lock guard)"
    );
}

/// Human dry-run twin: "Would restore {purl} …", nothing mutated. A dry
/// run resolves exactly like a wet run (the registry IS asked) and skips
/// only the write.
#[test]
fn hosted_human_dry_run_previews() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let (code, stdout, stderr) =
        run_hosted(tmp.path(), &["rollback", "--dry-run"], Some(&registry));
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Would restore {LP_PURL} to its upstream registry entry"
        )),
        "the dry-run restore preview must print; stdout=\n{stdout}"
    );
    assert!(
        registry.request_count() >= 1,
        "a dry run resolves the upstream entry like a wet run"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "dry run must not touch the wired lock"
    );
    assert!(!tmp.path().join(".socket").exists(), "no .socket/ residue");
}

/// `--offline` cannot re-resolve the upstream entry: the pin is REFUSED
/// with the `git checkout` remedy on stderr (human), exit 1, nothing
/// written — the registry is never asked.
#[test]
fn offline_refusal_prints_human_notice() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let (code, stdout, stderr) = run_hosted(
        tmp.path(),
        &["rollback", "--offline", "--yes", LP_PURL],
        Some(&registry),
    );
    assert_eq!(
        code, 1,
        "an offline hosted restore is refused; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "Error: Cannot restore {LP_PURL} to its upstream registry entry"
        )) && stderr.contains("this run is offline")
            && stderr.contains("`git checkout -- yarn.lock`"),
        "the human refusal must print on stderr with the remedy; stderr=\n{stderr}"
    );
    assert_eq!(registry.request_count(), 0, "offline asks no registry");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "the refused pin's wiring must be untouched"
    );
}

/// Human twin of `per_purl_revert_failure_lands_in_hosted_failed`: the
/// refused pin prints the "Error: Cannot restore {purl} …" stderr line
/// (errors print even without `--json`), exit 1, the lock untouched.
#[test]
fn per_purl_revert_failure_prints_human_stderr_line() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_single_npm_fixture(tmp.path());
    let registry = NpmRegistry::start(&[]);

    let (code, stdout, stderr) =
        run_hosted(tmp.path(), &["rollback", "--yes", LP_PURL], Some(&registry));
    assert_eq!(
        code, 1,
        "a refused pin must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "Error: Cannot restore {LP_PURL} to its upstream registry entry:"
        )),
        "the human failure line must print on stderr; stderr=\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_redirected_block()),
        "a refused pin leaves the lock byte-identical"
    );
}

/// Retiring a stale pre-v5 hosted ledger prints its one-line notice on
/// stdout. The `--json` twin (`legacyRedirectLedgerRemoved`, the edit never
/// replayed) is in `rollback_failure_paths.rs`.
#[test]
fn legacy_ledger_retire_prints_human_line() {
    // A `project/` subdirectory keeps the edit's `../evil.lock` target
    // inside this test's own tempdir.
    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    write_legacy_ledger(&project, unsafe_legacy_edits());
    let (code, stdout, stderr) = run_hosted(&project, &["rollback", "--yes"], None);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(
            "Removed the pre-v5 hosted ledger .socket/vendor/redirect-state.json: no \
             lockfile pins a hosted patch."
        ),
        "the human retire line must print; stdout=\n{stdout}"
    );
    assert!(!ledger_path(&project).exists());
    assert!(
        !tmp.path().join("evil.lock").exists(),
        "a legacy ledger's edit is never replayed"
    );
}

/// A dry run over a corrupt pre-v5 ledger previews its removal and deletes
/// nothing. The wet `--json` retire is in `rollback_failure_paths.rs`.
#[test]
fn corrupt_legacy_ledger_dry_run_previews_retire() {
    let tmp = corrupt_legacy_ledger_project();
    let (code, stdout, stderr) = run(tmp.path(), &["rollback", "--offline", "--dry-run"]);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("Would remove the pre-v5 hosted ledger"),
        "stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        b"garbage not json",
        "a dry run deletes nothing"
    );
}

/// Human twin of `hosted_restore_write_failure_lands_in_hosted_failed`:
/// the "Error: Writing the restored lockfiles failed" stderr line, exit 1.
#[cfg(unix)]
#[test]
fn hosted_restore_write_failure_prints_human_error_line() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("project");
    std::fs::create_dir(&project).unwrap();
    write_single_npm_fixture(&project);
    std::fs::create_dir(project.join(".socket")).unwrap();
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let guard = DirModeGuard::chmod(&project, 0o555, 0o755);
    if !readonly_dir_enforced(&project) {
        return;
    }
    let (code, stdout, stderr) = run_hosted(&project, &["rollback", "--yes"], Some(&registry));
    guard.restore();

    assert_eq!(
        code, 1,
        "a lockfile write failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Error: Writing the restored lockfiles failed"),
        "the human write-failure line must print on stderr; stderr=\n{stderr}"
    );
}

/// A hosted bun.lock pin restores to the registry 4-tuple
/// `["name@version", "", {deps}, "<registry integrity>"]`, with the human
/// restore line.
#[test]
fn bun_lock_pin_restores_to_the_registry_tuple() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("bun.lock"),
        bun_lock(&bun_redirected_line()),
    )
    .unwrap();
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let (code, stdout, stderr) = run_hosted(tmp.path(), &["rollback", "--yes"], Some(&registry));
    assert_eq!(
        code, 0,
        "the bun.lock restore succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains(&format!(
            "Restored {LP_PURL} to its upstream registry entry"
        )),
        "the wet restore line must print; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap(),
        bun_lock(&bun_original_line()),
        "the bun.lock entry must be the registry tuple again"
    );
    assert!(!tmp.path().join(".socket").exists(), "no .socket/ residue");
}

/// Dry-run twin of `bun_lock_pin_restores_to_the_registry_tuple`: "Would
/// restore …", bun.lock byte-identical afterwards.
#[test]
fn bun_lock_pin_dry_run_previews() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("bun.lock"),
        bun_lock(&bun_redirected_line()),
    )
    .unwrap();
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);

    let (code, stdout, stderr) =
        run_hosted(tmp.path(), &["rollback", "--dry-run"], Some(&registry));
    assert_eq!(
        code, 0,
        "the bun.lock dry run succeeds; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains(&format!(
            "Would restore {LP_PURL} to its upstream registry entry"
        )),
        "the dry-run preview line must print; stdout=\n{stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap(),
        bun_lock(&bun_redirected_line()),
        "dry run must not touch the wired bun.lock"
    );
}

/// #764: a human rollback over a hoisted Bun copy names `bun install
/// --force` on stderr. The `redirect_bun_reinstall_required` warning itself
/// is pinned in `rollback_failure_paths.rs`.
#[test]
fn bun_hoisted_copy_prints_force_install_hint() {
    let registry = NpmRegistry::start(&[("left-pad", "1.2.3")]);
    let hoisted = bun_hosted_project(true);
    let (code, stdout, stderr) =
        run_hosted(hoisted.path(), &["rollback", "--yes"], Some(&registry));
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("`bun install --force`"),
        "the human run names the forcing install; stderr=\n{stderr}"
    );
}

/// A dry-run rollback previews the vlt restore but deletes nothing and
/// says nothing about installed copies; the wet human run restores the
/// registry pin (integrity from the registry's version document),
/// invalidates the patched store entry and prints the advisory as a
/// warning line.
#[test]
fn vlt_hosted_rollback_dry_run_keeps_the_store_and_wet_human_run_heals() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let store = write_vlt_hosted_fixture(root);
    let hosted_lock = std::fs::read_to_string(root.join("vlt-lock.json")).unwrap();
    let registry = NpmRegistry::start(&[("left-pad", "1.3.0")]);

    let (code, stdout, stderr) =
        run_hosted(root, &["rollback", "--dry-run", "--yes"], Some(&registry));
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("Would restore pkg:npm/left-pad@1.3.0 to its upstream registry entry"),
        "{stdout}"
    );
    assert!(
        !stderr.contains("redirect_vlt_reinstall_required"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("vlt-lock.json")).unwrap(),
        hosted_lock
    );
    assert!(store.join("index.js").exists());

    let (code, stdout, stderr) = run_hosted(root, &["rollback", "--yes"], Some(&registry));
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let restored = std::fs::read_to_string(root.join("vlt-lock.json")).unwrap();
    assert!(
        restored.contains(&format!(
            "\"{VLT_ID}\": [0,\"left-pad\",\"{UPSTREAM_INTEGRITY}\""
        )) && !restored.contains("patch.socket.dev"),
        "the node must carry the registry integrity again, no hosted URL:\n{restored}"
    );
    assert!(
        stderr.contains(
            "Warning: restored registry pins for 1 packages; \
             removed the patched installed copies"
        ),
        "{stderr}"
    );
    assert!(!store.exists());
    assert!(!root.join("node_modules/.vlt-lock.json").exists());
}

/// Human twin of `manifest_write_failure_warns_and_exits_one`: the failed
/// manifest update prints the "Error: Failed to update the manifest:"
/// stderr line, exit 1, manifest byte-identical — after the file restore
/// already landed.
#[cfg(target_os = "macos")]
#[test]
fn manifest_write_failure_prints_human_error_line() {
    let fx = patched_fixture();
    let manifest_path = fx.socket.join("manifest.json");
    let manifest_before = std::fs::read(&manifest_path).expect("read manifest bytes");
    let guard = ChflagsGuard::set(&manifest_path);

    let (code, stdout, stderr) = run(fx.root.path(), &["rollback", "--offline", "--yes"]);
    guard.release();

    assert_eq!(
        code, 1,
        "a manifest write failure must exit 1; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("Error: Failed to update the manifest:"),
        "the human write-failure line must print on stderr; stderr=\n{stderr}"
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
}

// ═══════════════ interactive confirm decline (PTY) ═══════════════

#[cfg(unix)]
mod interactive {
    use std::path::Path;

    use crate::common;
    use crate::common::git_sha256;
    use crate::rollback_fixture::*;
    use portable_pty::{native_pty_system, PtySize};
    use std::time::Duration;

    /// Spawn the binary inside a PTY, send `input`, collect all output —
    /// the `interactive_prompts_e2e.rs` harness (same env scrubbing).
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

        // The hermetic environment: SOCKET_YES would skip the very prompt
        // under test.
        let mut cmd = common::hermetic::pty_binary_command();
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .expect("spawn socket-patch in PTY");
        drop(pair.slave);

        let reader_handle =
            crate::pty_io::PtyOutput::spawn(pair.master.try_clone_reader().expect("clone reader"));

        let mut killer = child.clone_killer();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = killer.kill();
        });

        let mut writer = pair.master.take_writer().expect("take writer");
        crate::pty_io::send_when_prompted(&reader_handle, &mut writer, input.as_bytes());
        drop(writer);

        let status = child.wait().expect("child.wait");
        drop(pair.master);

        let output = reader_handle.finish();
        (
            status.exit_code() as i32,
            String::from_utf8_lossy(&output).to_string(),
        )
    }

    /// Declining the rollback confirm prompt cancels cleanly: the composed
    /// manifest clause renders with the `[Y/n]` hint, "Cancelled; no changes made."
    /// prints, the run exits 0, and nothing is mutated.
    #[test]
    fn rollback_interactive_decline_cancels() {
        let before_hash = git_sha256(b"pty-original\n");
        let after_hash = git_sha256(b"pty-patched\n");
        let tmp = tempfile::tempdir().expect("tempdir");
        let socket = write_socket_manifest(
            tmp.path(),
            &[manifest_entry(
                "pkg:npm/covgap-pty@1.0.0",
                "44444444-4444-4444-8444-444444444444",
                &before_hash,
                &after_hash,
            )],
        );
        let manifest_before =
            std::fs::read(socket.join("manifest.json")).expect("read manifest bytes");

        let (code, output) = run_in_pty(
            &["rollback", "--offline"],
            tmp.path(),
            "n\n",
            Duration::from_secs(15),
        );
        assert_eq!(code, 0, "declining must exit 0; got: {output}");
        assert!(
            output.contains("Roll back 1 patch and remove it from the local manifest? [Y/n]"),
            "the composed confirm prompt must render verbatim; got: {output}"
        );
        assert!(
            !output.contains("Non-interactive mode"),
            "the PTY run must take the interactive branch; got: {output}"
        );
        assert!(
            output.contains("Cancelled; no changes made."),
            "the decline must be acknowledged; got: {output}"
        );
        assert_eq!(
            std::fs::read(socket.join("manifest.json")).expect("manifest exists"),
            manifest_before,
            "a declined rollback must leave the manifest byte-identical"
        );
    }
}
