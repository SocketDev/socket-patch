//! End-to-end tests that drive interactive prompts (`ui::confirm`) via a
//! pseudo-terminal. These exercise the stdin-is-a-terminal-gated
//! confirmation paths in `remove` (plus `apply`'s no-manifest message)
//! that subprocess-with-piped-stdin tests can't reach.
//!
//! PTY support: macOS + Linux. Skipped on Windows.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use crate::pty_io;

// ---------------------------------------------------------------------------
// `remove` interactive confirmation
// ---------------------------------------------------------------------------

const REMOVE_MANIFEST: &str = r#"{
  "patches": {
    "pkg:npm/__interactive_remove__@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "interactive remove test",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn write_remove_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), REMOVE_MANIFEST).unwrap();
}

#[test]
fn remove_interactive_y_proceeds() {
    let tmp = tempfile::tempdir().unwrap();
    write_remove_manifest(tmp.path());

    let (code, output) = pty_io::run(
        &[
            "remove",
            "pkg:npm/__interactive_remove__@1.0.0",
            "--skip-rollback",
        ],
        tmp.path(),
        "y\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0);
    // The interactive confirm MUST have run (printed to the tty via stderr),
    // not the non-interactive auto-default branch. Match the DISTINCTIVE
    // prompt text ("...without rolling back its files?") rather than the loose pair
    // `contains("Remove") && contains("patch(es)")` — the latter is also
    // satisfied by the SUCCESS line "Removed 1 patch(es) from manifest:",
    // so it would stay green even if the confirm prompt were dropped and the
    // command auto-removed. The exact count ("1") pins single-entry preview.
    assert!(
        output.contains("Remove 1 patch from the manifest without rolling back its files?"),
        "remove must have shown the interactive confirm prompt verbatim; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode"),
        "remove must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Removed"),
        "remove 'y' must report what it removed; got: {output}"
    );
    // Manifest should be empty now: the `patches` object must exist and be
    // empty (not merely "missing", which a corrupt rewrite could produce).
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = manifest["patches"]
        .as_object()
        .unwrap_or_else(|| panic!("manifest must keep a 'patches' object; got: {body}"));
    assert!(
        patches.is_empty(),
        "remove 'y' must drop the entry; got: {body}"
    );
}

#[test]
fn remove_interactive_n_cancels() {
    let tmp = tempfile::tempdir().unwrap();
    write_remove_manifest(tmp.path());

    let (code, output) = pty_io::run(
        &[
            "remove",
            "pkg:npm/__interactive_remove__@1.0.0",
            "--skip-rollback",
        ],
        tmp.path(),
        "n\n",
        Duration::from_secs(15),
    );
    assert_eq!(code, 0, "remove 'n' must exit cleanly");
    // The interactive confirm MUST have run and the cancellation path taken.
    // Match the verbatim prompt (see remove_interactive_y_proceeds): the loose
    // `contains("Remove") && contains("patch(es)")` pair could also be matched
    // by the preview banner, masking a dropped confirm prompt.
    assert!(
        output.contains("Remove 1 patch from the manifest without rolling back its files?"),
        "remove must have shown the interactive confirm prompt verbatim; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode"),
        "remove must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Cancelled; no changes made."),
        "remove 'n' must report cancellation; got: {output}"
    );
    assert!(
        !output.contains("Removed"),
        "remove 'n' must not report any removal; got: {output}"
    );
    // Manifest must still have the SPECIFIC entry intact. The previous
    // `.unwrap_or(true)` silently passed even if `patches` was wiped/missing,
    // which is exactly the regression this test must catch.
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = manifest["patches"]
        .as_object()
        .unwrap_or_else(|| panic!("remove 'n' must keep the 'patches' object; got: {body}"));
    assert!(
        patches.contains_key("pkg:npm/__interactive_remove__@1.0.0"),
        "remove 'n' must leave the exact entry intact; got: {body}"
    );
    // And the entry's contents must be preserved byte-for-byte.
    let original: serde_json::Value = serde_json::from_str(REMOVE_MANIFEST).unwrap();
    assert_eq!(
        manifest, original,
        "remove 'n' must not mutate the manifest at all"
    );
}

#[test]
fn remove_interactive_non_utf8_answer_declines_without_panic() {
    let tmp = tempfile::tempdir().unwrap();
    write_remove_manifest(tmp.path());

    // A terminal can deliver non-UTF-8 bytes at the prompt (e.g. a
    // Latin-1 paste: `é` = 0xE9); `read_line` reports them as an
    // InvalidData error. Regression: `confirm()` unwrapped that error
    // and panicked (exit 101) instead of treating the garbage like any
    // other unrecognized answer (decline).
    let pty_io::PtyRun { code, output, .. } = pty_io::run_command(
        crate::common::hermetic::pty_binary_command(),
        &[
            "remove",
            "pkg:npm/__interactive_remove__@1.0.0",
            "--skip-rollback",
        ],
        tmp.path(),
        &[],
        &[b"\xE9\n"],
        Duration::from_secs(15),
    );
    assert!(
        !output.contains("panicked"),
        "non-UTF-8 answer must not panic the CLI; got: {output}"
    );
    assert_eq!(
        code, 0,
        "non-UTF-8 answer must decline cleanly, not crash; got: {output}"
    );
    // The interactive confirm MUST have run (same vacuity guard as the
    // y/n tests above), and the unreadable answer must land on "no".
    assert!(
        output.contains("Remove 1 patch from the manifest without rolling back its files?"),
        "remove must have shown the interactive confirm prompt; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode"),
        "remove must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Cancelled; no changes made."),
        "non-UTF-8 answer must be treated as 'no'; got: {output}"
    );
    // Declined: the manifest entry must be intact.
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    let original: serde_json::Value = serde_json::from_str(REMOVE_MANIFEST).unwrap();
    assert_eq!(
        manifest, original,
        "declined remove must not mutate the manifest"
    );
}

/// Write a vendor ledger with one DETACHED npm entry (no manifest at all —
/// the ledger-only layout every `scan --mode vendored` run writes), so
/// `remove <purl>` routes to the ledger-only path and its own confirm prompt.
fn write_detached_vendor_state(root: &Path, purl: &str, uuid: &str) {
    let vendor = root.join(".socket/vendor");
    let artifact_dir = vendor.join("npm").join(uuid);
    std::fs::create_dir_all(&artifact_dir).unwrap();
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").unwrap();
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{purl}": {{
      "ecosystem": "npm",
      "basePurl": "{purl}",
      "uuid": "{uuid}",
      "artifact": {{ "path": ".socket/vendor/npm/{uuid}/package.tgz" }},
      "detached": true,
      "wiring": []
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).unwrap();
}

#[test]
fn remove_detached_interactive_n_cancel_message_respects_silent() {
    // `--silent` is "errors only" (CLI_CONTRACT.md), and "Removal
    // cancelled." is chatter: the manifest path gates it on
    // `!json && !silent`, but the detached-only path gated it on `!json`
    // alone. The cancel branch is only reachable by an interactive decline
    // (non-TTY confirm auto-proceeds with the default), which is why the
    // earlier detached `--silent` sweep in cli_remove_silent.rs missed it.
    let purl = "pkg:npm/__interactive_detached__@1.0.0";
    let uuid = "55555555-5555-4555-8555-555555555555";

    let tmp = tempfile::tempdir().unwrap();
    write_detached_vendor_state(tmp.path(), purl, uuid);

    let (code, output) = pty_io::run(
        &["remove", purl, "--silent"],
        tmp.path(),
        "n\n",
        Duration::from_secs(15),
    );
    assert_eq!(
        code, 0,
        "declined detached remove must exit cleanly; got: {output}"
    );
    // Vacuity guard: the detached confirm prompt MUST have run — otherwise
    // an early error (e.g. a broken ledger fixture) would pass the absence
    // assertion below without ever reaching the cancel branch.
    assert!(
        output.contains("Remove 1 vendored patch and revert its vendoring?"),
        "detached remove must have shown its confirm prompt; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode"),
        "remove must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        !output.contains("Cancelled; no changes made."),
        "--silent must suppress the cancellation chatter; got: {output}"
    );
    // Declined: the detached ledger entry must be intact.
    assert!(
        tmp.path().join(".socket/vendor/state.json").exists(),
        "declined detached remove must not touch the vendor ledger"
    );

    // Control run: without --silent the cancel message must print —
    // otherwise the absence assertion above passes vacuously against a
    // fix that deleted the message instead of gating it.
    let tmp2 = tempfile::tempdir().unwrap();
    write_detached_vendor_state(tmp2.path(), purl, uuid);
    let (loud_code, loud_output) = pty_io::run(
        &["remove", purl],
        tmp2.path(),
        "n\n",
        Duration::from_secs(15),
    );
    assert_eq!(
        loud_code, 0,
        "declined detached remove must exit cleanly; got: {loud_output}"
    );
    assert!(
        loud_output.contains("Cancelled; no changes made."),
        "non-silent declined detached remove must report cancellation; got: {loud_output}"
    );
    assert!(
        tmp2.path().join(".socket/vendor/state.json").exists(),
        "declined detached remove must not touch the vendor ledger"
    );
}

// ---------------------------------------------------------------------------
// `apply` has no prompt; in a real TTY the no-manifest path must still
// print its friendly message.
// ---------------------------------------------------------------------------

#[test]
fn apply_in_pty_with_no_manifest_prints_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, output) = pty_io::run(&["apply"], tmp.path(), "", Duration::from_secs(15));
    assert_eq!(code, 0);
    // Assert the full message, not either half of it. The wording names the
    // missing manifest, not the `.socket/` folder (hosted/vendored projects
    // have one with nothing for `apply` to do).
    assert!(
        output.contains("No patch manifest found; nothing to apply."),
        "PTY apply no-manifest must print the friendly message; got: {output}"
    );
}
