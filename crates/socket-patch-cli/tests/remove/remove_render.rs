//! `remove`'s render suite (#1089): the human-mode (no `--json`) output
//! of `commands/remove.rs`. Behavior is asserted through `--json` codes,
//! events and disk state in `remove_failure_paths.rs`; the sentence checks
//! here are the render checks, one per message family.

use crate::common;
use crate::remove_fixture::*;

/// Human-mode twin: the same failure must reach stderr as an `Error:` line
/// (emit_error_envelope's non-JSON arm), with no JSON envelope on stdout.
#[test]
fn remove_corrupt_vendor_ledger_fails_closed_human() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_vsl__@1.0.0";
    let socket =
        write_manifest_files_empty(tmp.path(), purl, "22222222-2222-4222-8222-222222222222");
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let vendor = socket.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(vendor.join("state.json"), "{{{").unwrap();

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with("Error:") && l.contains(".socket/vendor/state.json")),
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

/// `--preserve-state` still restores hosted pins (hosted has no
/// preservable local state) and the human run must say so on stderr —
/// while the manifest entry survives and the final preserve summary
/// prints.
#[test]
fn remove_hosted_preserve_state_notes_no_preservable_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let socket = write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
    let manifest_before = read_bytes(&socket.join("manifest.json"));
    let registry = NpmRegistry::start(true);

    let (code, stdout, stderr) = run_remove_online(
        tmp.path(),
        &[NPM_PURL, "--yes", "--preserve-state"],
        &registry,
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("hosted wiring has no preservable local state"),
        "the preserve-state hosted note must reach stderr; got:\n{stderr}"
    );
    assert!(
        stdout.contains("Manifest entry preserved (--preserve-state)"),
        "the preserve-state summary must print; got:\n{stdout}"
    );

    // The restore really happened: the lock holds the upstream entry.
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_reverted_lock_text(),
        "the lock must hold exactly the upstream registry entry"
    );
    // The state half was preserved: manifest byte-identical.
    assert_eq!(
        read_bytes(&socket.join("manifest.json")),
        manifest_before,
        "--preserve-state must keep the manifest entry"
    );
}

/// A corrupt pre-v5 redirect ledger is inert: hosted state comes from the
/// lockfiles, so a manifest removal neither reads nor warns about it, the
/// removal succeeds, and the file is left alone.
#[test]
fn remove_corrupt_legacy_hosted_ledger_is_ignored_human() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let purl = "pkg:npm/__covgap_hcorrupt__@1.0.0";
    let socket =
        write_manifest_files_empty(tmp.path(), purl, "77777777-7777-4777-8777-777777777777");
    let ledger_path = write_redirect_ledger_text(tmp.path(), "{nope");
    let ledger_before = read_bytes(&ledger_path);

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--yes", "--offline"], &[]);
    assert_eq!(
        code, 0,
        "a corrupt pre-v5 ledger must not block the removal; stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        !stderr.contains("redirect") && !stderr.contains("ledger"),
        "the pre-v5 ledger is never read, so nothing warns about it; got:\n{stderr}"
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
        "the corrupt ledger must be left alone"
    );
}

/// Hosted-only human mode: the pre-confirm listing ("The following hosted
/// redirect(s) will be unwound and removed:") must print to stderr, the
/// wet run must restore the upstream entry, and a pre-v5 ledger left
/// beside the pin is retired once no hosted pin remains (it is never the
/// revert source: its recorded original disagrees with the registry).
#[test]
fn remove_hosted_only_human_lists_redirects_and_unwinds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let ledger_path = write_redirect_ledger_text(
        tmp.path(),
        &npm_redirect_ledger_text().replace(ORIG_INTEGRITY, "sha512-LEDGERledger=="),
    );
    let registry = NpmRegistry::start(true);

    let (code, stdout, stderr) = run_remove_online(tmp.path(), &[NPM_PURL, "--yes"], &registry);
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("The following hosted patch will be unwound and removed:"),
        "the hosted-only listing must reach stderr; got:\n{stderr}"
    );
    assert!(
        stderr.contains(&format!("  - {NPM_PURL}")),
        "the listing must name the purl; got:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!(
            "Restored {NPM_PURL} to its upstream registry entry"
        )),
        "the restore line must print; got:\n{stdout}"
    );
    // The restore really ran: lock holds the registry's entry byte-exactly.
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_reverted_lock_text(),
        "the lock must hold exactly the upstream registry entry"
    );
    assert!(
        !ledger_path.exists(),
        "the pre-v5 ledger is retired once no hosted pin remains"
    );
}

/// B77: a human (non-JSON) hosted remove whose restore is refused prints
/// the refusal ONCE. The hosted leg prints each refusal as it happens;
/// remove used to print the same `Error:` line again on its way out.
/// Covers the manifest-backed path (which adds that the manifest was not
/// modified) and the hosted-only path.
#[test]
fn remove_hosted_revert_failure_prints_the_error_once() {
    let needle = "annot restore pkg:npm/left-pad@1.3.0 to its upstream registry entry";
    for manifest_backed in [true, false] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lock_path = tmp.path().join("package-lock.json");
        std::fs::write(&lock_path, redirected_lock_text()).unwrap();
        if manifest_backed {
            write_manifest_files_empty(tmp.path(), NPM_PURL, NPM_UUID);
        }
        let (code, stdout, stderr) = run_remove(tmp.path(), &[NPM_PURL, "--yes", "--offline"], &[]);
        assert_eq!(
            code, 1,
            "manifest_backed={manifest_backed}: stdout=\n{stdout}\nstderr=\n{stderr}"
        );
        assert_eq!(
            stderr.matches(needle).count(),
            1,
            "manifest_backed={manifest_backed}: the refusal must print exactly once; \
             stderr=\n{stderr}"
        );
        assert_eq!(
            stderr.contains("The manifest was not modified."),
            manifest_backed,
            "manifest_backed={manifest_backed}: stderr=\n{stderr}"
        );
    }
}

/// Human twin: exit 1 plus the singular drift-keep error line on stderr
/// (the count + pluralization surface).
#[test]
fn remove_mixed_drift_keep_is_partial_failure_human() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_mixed_drift_fixture(tmp.path());

    let (code, stdout, stderr) = run_remove(tmp.path(), &[MIXED_UUID, "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("1 matching entry was drift-kept"),
        "the singular drift-keep error line must reach stderr; got:\n{stderr}"
    );
    assert!(
        stderr.contains("re-run `scan --mode vendored`"),
        "the error must carry the normalize remedy; got:\n{stderr}"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(socket.join("manifest.json")).unwrap())
            .unwrap();
    let patches = manifest["patches"].as_object().expect("patches object");
    assert!(
        patches.contains_key(MIXED_KEPT_PURL) && !patches.contains_key(MIXED_REMOVED_PURL),
        "the kept entry must survive and the sibling must be removed; got: {patches:?}"
    );
}

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
        stderr.contains(&format!(
            "{base} matches 2 release variants — all will be removed:"
        )),
        "the blast-radius line must reach stderr; got:\n{stderr}"
    );
    assert!(
        stdout.contains("Removed 2 patches from manifest:"),
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

/// The "already in original state" count line: an entry
/// whose installed file is already at its original bytes rolls back as
/// already-original, and the human run must say so. (JSON twin lives in
/// remove_invariants.rs.)
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
        stdout.contains("1 package already in original state"),
        "the already-original count line must print; got:\n{stdout}"
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
/// "Unwired vendoring … (artifact preserved)" line plus
/// the final preserve summary, with all state kept.
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
        stdout.contains(&format!(
            "Unwired vendoring for {purl} (artifact preserved)"
        )),
        "the per-key preserve line must print; got:\n{stdout}"
    );
    assert!(
        stdout.contains("Manifest entry and vendored artifact preserved"),
        "the preserve summary must print; got:\n{stdout}"
    );
    // All state kept: manifest, ledger, artifact.
    assert_eq!(read_bytes(&socket.join("manifest.json")), manifest_before);
    assert_eq!(read_bytes(&ledger_path), ledger_before);
    assert!(artifact_dir.join("package.tgz").exists());
}

/// Dry-run `--preserve-state` twin: the "Would unwire vendoring …
/// (artifact preserved)" preview line, nothing mutated.
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
        stdout.contains(&format!(
            "Would unwire vendoring for {purl} (artifact preserved)"
        )),
        "the dry-run preserve preview must print; got:\n{stdout}"
    );
    assert_eq!(read_bytes(&socket.join("manifest.json")), manifest_before);
    assert_eq!(read_bytes(&ledger_path), ledger_before);
    assert!(artifact_dir.join("package.tgz").exists());
}

/// Hosted-only twin (#433) of the preserve-state note: with no manifest,
/// `remove --preserve-state` still restores the pin and must say so on
/// stderr.
#[test]
fn remove_hosted_only_preserve_state_notes_no_preservable_state() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let lock_path = tmp.path().join("package-lock.json");
    std::fs::write(&lock_path, redirected_lock_text()).unwrap();
    let registry = NpmRegistry::start(true);

    let (code, stdout, stderr) = run_remove_online(
        tmp.path(),
        &[NPM_PURL, "--yes", "--preserve-state"],
        &registry,
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains("Note: hosted wiring has no preservable local state"),
        "the preserve-state hosted note must reach stderr; got:\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        expected_reverted_lock_text(),
        "the lock must hold exactly the upstream registry entry"
    );
}

/// Dry-run `remove --preserve-state` on a ledger-only (detached) entry: the
/// listing and the preview line say what `--preserve-state` will do, and
/// nothing moves.
#[test]
fn remove_detached_preserve_state_dry_run_previews() {
    let purl = "pkg:npm/__covgap_detpreserve__@1.0.0";
    let uuid = "77777777-7777-4777-8777-777777777777";
    let tmp = tempfile::tempdir().expect("tempdir");
    let artifact_dir = write_vendor_ledger_entry(
        tmp.path(),
        purl,
        purl,
        uuid,
        "[]",
        "\"detached\": true,\n      ",
    );
    let ledger_path = tmp.path().join(".socket/vendor/state.json");
    let ledger_before = read_bytes(&ledger_path);
    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[purl, "--offline", "--preserve-state", "--dry-run"],
        &[],
    );
    assert_eq!(code, 0, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Would unwire vendoring for {purl} (artifact preserved)"
        )),
        "the preserve preview line must print; stdout=\n{stdout}"
    );
    assert!(
        stderr.contains("would be unwired (artifacts and ledger entries preserved)"),
        "the listing must be honest about --preserve-state; stderr=\n{stderr}"
    );
    assert_eq!(
        read_bytes(&ledger_path),
        ledger_before,
        "dry run: ledger untouched"
    );
    assert!(
        artifact_dir.join("package.tgz").exists(),
        "dry run: artifact untouched"
    );
}

/// Human twin of the ledger-only drift-keep: the per-key keep line and the
/// errors-only summary line, exit 1, and no "Reverted" line.
#[test]
fn remove_detached_drift_keep_human_prints_keep_lines() {
    let purl = "pkg:npm/__covgap_detdrift__@1.0.0";
    let uuid = "88888888-8888-4888-8888-888888888888";
    let tmp = tempfile::tempdir().expect("tempdir");
    write_vendor_ledger_entry(
        tmp.path(),
        purl,
        purl,
        uuid,
        DRIFTED_WIRING,
        "\"detached\": true,\n      ",
    );
    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--yes", "--offline"], &[]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stderr.contains(&format!(
            "Kept vendored state for {purl}: lockfile wiring drifted"
        )),
        "the per-key keep line must print; stderr=\n{stderr}"
    );
    assert!(
        stderr.contains(
            "1 matching entry was drift-kept (vendored state and ledger record retained)"
        ),
        "the summary error line must print; stderr=\n{stderr}"
    );
    assert!(
        !stdout.contains("Reverted vendoring for"),
        "nothing was reverted; stdout=\n{stdout}"
    );
}

/// Hosted-only interactive decline, PTY-driven: the non-TTY confirm
/// auto-proceeds, so only a real terminal reaches the cancel branch.
/// Runner copied from interactive_prompts_e2e.rs.
#[cfg(unix)]
mod pty {
    use super::*;
    use portable_pty::{native_pty_system, PtySize};
    use std::path::Path;
    use std::time::Duration;

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

        // The hermetic environment: SOCKET_YES would skip the very prompt
        // this test drives.
        let mut cmd = common::hermetic::pty_binary_command();
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);

        let mut child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
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

    /// Declining the hosted-only confirm prompt must cancel cleanly (exit
    /// 0, "Cancelled; no changes made.") with the lock byte-identical and no
    /// `.socket/` state written.
    #[test]
    fn remove_hosted_only_interactive_n_cancels() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lock_path = tmp.path().join("package-lock.json");
        std::fs::write(&lock_path, redirected_lock_text()).unwrap();
        let lock_before = read_bytes(&lock_path);

        let (code, output) = run_in_pty(
            &["remove", NPM_PURL],
            tmp.path(),
            "n\n",
            Duration::from_secs(15),
        );
        assert_eq!(
            code, 0,
            "declined hosted remove must exit cleanly; got: {output}"
        );
        // Vacuity guard: the hosted-only confirm prompt MUST have run.
        assert!(
            output.contains("Remove 1 hosted patch and unwind its lockfile wiring?"),
            "the hosted-only confirm prompt must have shown; got: {output}"
        );
        assert!(
            !output.contains("Non-interactive mode"),
            "must NOT have taken the non-interactive branch in a PTY; got: {output}"
        );
        assert!(
            output.contains("Cancelled; no changes made."),
            "'n' must report cancellation; got: {output}"
        );
        // Declined: nothing moved.
        assert_eq!(read_bytes(&lock_path), lock_before, "lock untouched");
        assert!(
            !tmp.path().join(".socket").exists(),
            "a declined remove leaves no .socket/ state"
        );
    }
}
