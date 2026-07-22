//! End-to-end tests that drive interactive `dialoguer` prompts via a
//! pseudo-terminal. These exercise the `stdin_is_tty()`-gated
//! confirmation paths in `setup`, `remove`, and `get` that
//! subprocess-with-piped-stdin tests can't reach.
//!
//! PTY support: macOS + Linux. Skipped on Windows.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Spawn the socket-patch binary inside a PTY, send `input`, and
/// collect all output until the child exits. Returns `(exit_code,
/// output)`. The timeout is enforced via a watchdog thread that
/// kills the child if it doesn't exit in time.
///
/// Three pieces compose:
///   * **Reader thread**: `read_to_end` on the master side.
///     Blocks until EOF, which the kernel sends once both the
///     slave fd (dropped here) and the child's last open fd are
///     closed.
///   * **Watchdog thread**: sleeps `timeout` then sends SIGKILL
///     via a cloned ChildKiller. Detaches; no join needed since
///     the killer is idempotent and the child either exits
///     normally first (kill is a no-op) or is killed (we proceed).
///   * **Main thread**: writes input, closes the writer (sends
///     EOF on the child's stdin), blocks on `child.wait()`, then
///     joins the reader.
///
/// No polling loops, no mpsc channels, no fixed-duration sleeps
/// before sending input — the PTY buffers the input until the
/// child reads it, so timing-coupling isn't needed.
fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
    run_in_pty_bytes(args, cwd, input.as_bytes(), timeout)
}

/// Byte-level variant of [`run_in_pty`] for input that is not valid
/// UTF-8 (e.g. a Latin-1 paste at an interactive prompt).
fn run_in_pty_bytes(args: &[&str], cwd: &Path, input: &[u8], timeout: Duration) -> (i32, String) {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = CommandBuilder::new(binary());
    for a in args {
        cmd.arg(a);
    }
    cmd.cwd(cwd);
    // The binary binds a wide `SOCKET_*` env surface (SOCKET_YES,
    // SOCKET_JSON, SOCKET_DRY_RUN, SOCKET_SILENT, SOCKET_MANIFEST_PATH,
    // ...). An ambient value silently reroutes what these tests exercise —
    // SOCKET_YES=true skips the very confirm prompts this file exists to
    // drive, and SOCKET_SILENT=true suppresses the output the oracles
    // match. The highest-risk vars are seeded with hostile values and then
    // scrubbed — `env_remove` clears the seed too, so the child never sees
    // it, but if a scrub line is ever dropped the seed (rather than a
    // developer's ambient shell, which this suite can't rely on) turns the
    // tests red immediately.
    cmd.env("SOCKET_YES", "true");
    cmd.env("SOCKET_JSON", "true");
    cmd.env("SOCKET_DRY_RUN", "true");
    cmd.env("SOCKET_SILENT", "true");
    cmd.env_remove("SOCKET_YES");
    cmd.env_remove("SOCKET_JSON");
    cmd.env_remove("SOCKET_DRY_RUN");
    cmd.env_remove("SOCKET_SILENT");
    // Prefix-scrub whatever else the ambient shell carries (SOCKET_CWD,
    // SOCKET_MANIFEST_PATH, SOCKET_API_TOKEN — removing the token also
    // forces the public proxy). Telemetry opt-outs are deliberately kept
    // so an opted-out dev stays opted out.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") && name != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }

    let mut child = pair
        .slave
        .spawn_command(cmd)
        .expect("spawn socket-patch in PTY");
    // Drop the slave so the master sees EOF once the child closes its
    // own copy of the slave fd on exit.
    drop(pair.slave);

    // Reader: a single `read_to_end` is sufficient — it blocks until
    // EOF, which arrives when (a) the master is dropped (we do that
    // below) or (b) the child has exited and its end of the slave is
    // closed. The previous design used a chunked read+mpsc loop
    // because it interleaved with a try_wait poll; the simplified
    // design serializes wait → drop master → read_to_end joins.
    let mut reader = pair.master.try_clone_reader().expect("clone reader");
    let reader_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        buf
    });

    // Watchdog: detach a thread that kills the child after `timeout`.
    // The cloned ChildKiller is independent of the main `child`
    // handle, so the watchdog can fire without coordinating with the
    // main thread. If the child exits naturally first, the kill is a
    // no-op against a dead pid.
    let mut killer = child.clone_killer();
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        let _ = killer.kill();
    });

    // Writer: send input then close. PTY buffers absorb the write so
    // no pre-sleep is needed — dialoguer/rustyline will read it when
    // their prompt loop polls stdin.
    let mut writer = pair.master.take_writer().expect("take writer");
    let _ = writer.write_all(input);
    let _ = writer.flush();
    drop(writer);

    // Block until the child exits (watchdog enforces the timeout).
    let status = child.wait().expect("child.wait");
    // Drop the master so the reader's `read_to_end` sees EOF and
    // returns.
    drop(pair.master);

    let output = reader_handle.join().expect("reader thread join");
    let code = status.exit_code() as i32;
    (code, String::from_utf8_lossy(&output).to_string())
}

// ---------------------------------------------------------------------------
// `setup` interactive confirmation
// ---------------------------------------------------------------------------

#[test]
fn setup_interactive_y_proceeds_with_update() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "p", "version": "1.0.0" }"#,
    )
    .unwrap();

    // Without --yes, setup prompts "Proceed with these changes? (y/N): ".
    // Sending "y\n" should make it proceed with the update.
    let (code, output) = run_in_pty(&["setup"], tmp.path(), "y\n", Duration::from_secs(15));
    assert_eq!(code, 0, "setup with 'y' must succeed");

    // The interactive prompt MUST have actually run — otherwise this test
    // would pass against a regression that drops the TTY gate and
    // auto-proceeds, never exercising the path this file is named for.
    assert!(
        output.contains("Proceed with these changes?"),
        "setup must have shown the interactive confirm prompt; got: {output}"
    );
    // A regression that took the non-interactive auto-proceed branch would
    // print this banner instead of prompting; it must NOT appear.
    assert!(
        !output.contains("Non-interactive mode detected"),
        "setup must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );

    // package.json should have been updated with a real postinstall hook
    // that invokes socket-patch (not merely mention the string somewhere).
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&pkg)
        .unwrap_or_else(|e| panic!("setup must leave valid JSON; err={e}; got: {pkg}"));
    let postinstall = parsed["scripts"]["postinstall"]
        .as_str()
        .unwrap_or_else(|| panic!("setup must write scripts.postinstall; got: {pkg}"));
    assert!(
        postinstall.contains("socket-patch"),
        "postinstall must invoke socket-patch; got: {postinstall}"
    );
}

#[test]
fn setup_interactive_n_aborts_without_update() {
    let tmp = tempfile::tempdir().unwrap();
    let original = r#"{ "name": "p", "version": "1.0.0" }
"#;
    std::fs::write(tmp.path().join("package.json"), original).unwrap();

    let (code, output) = run_in_pty(&["setup"], tmp.path(), "n\n", Duration::from_secs(15));
    assert_eq!(code, 0, "setup with 'n' must exit cleanly");
    // The interactive prompt MUST have run, then aborted.
    assert!(
        output.contains("Proceed with these changes?"),
        "setup must have shown the interactive confirm prompt; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode detected"),
        "setup must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Aborted"),
        "setup must print abort message; got: {output}"
    );
    // It must NOT have started applying changes.
    assert!(
        !output.contains("Applying changes..."),
        "setup 'n' must abort before applying; got: {output}"
    );

    // package.json must be unchanged.
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert_eq!(pkg, original, "setup 'n' must not modify package.json");
}

#[test]
fn setup_interactive_default_no_aborts() {
    // Pressing just Enter at the prompt defaults to N (abort).
    let tmp = tempfile::tempdir().unwrap();
    let original = r#"{ "name": "p", "version": "1.0.0" }
"#;
    std::fs::write(tmp.path().join("package.json"), original).unwrap();

    let (code, output) = run_in_pty(&["setup"], tmp.path(), "\n", Duration::from_secs(15));
    assert_eq!(code, 0);
    // The prompt MUST have run; bare Enter must hit the default-N abort.
    // Without these, the test passes vacuously if setup never prompts and
    // simply no-ops, never proving the default is "No".
    assert!(
        output.contains("Proceed with these changes?"),
        "setup must have shown the interactive confirm prompt; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode detected"),
        "setup must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Aborted"),
        "bare-Enter must default to N and print abort; got: {output}"
    );
    assert!(
        !output.contains("Applying changes..."),
        "default-N must abort before applying; got: {output}"
    );
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert_eq!(pkg, original, "default-N must not modify package.json");
}

#[test]
fn setup_interactive_non_utf8_answer_aborts_without_panic() {
    // Same regression class as remove_interactive_non_utf8_answer_
    // declines_without_panic below, but for setup's own prompt reader
    // (`confirm_proceed`), a separate implementation from
    // `output::confirm`: a Latin-1 paste (`é` = 0xE9) at
    // "Proceed with these changes? (y/N): " makes `read_line` return
    // InvalidData, and unwrapping it panics the CLI (exit 101) instead
    // of treating the unreadable answer as "not yes" (abort).
    let tmp = tempfile::tempdir().unwrap();
    let original = r#"{ "name": "p", "version": "1.0.0" }
"#;
    std::fs::write(tmp.path().join("package.json"), original).unwrap();

    let (code, output) =
        run_in_pty_bytes(&["setup"], tmp.path(), b"\xE9\n", Duration::from_secs(15));
    assert!(
        !output.contains("panicked"),
        "non-UTF-8 answer must not panic the CLI; got: {output}"
    );
    assert_eq!(
        code, 0,
        "non-UTF-8 answer must abort cleanly, not crash; got: {output}"
    );
    // The interactive prompt MUST have run (vacuity guard as above), and
    // the unreadable answer must land on the default-N abort path.
    assert!(
        output.contains("Proceed with these changes?"),
        "setup must have shown the interactive confirm prompt; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode detected"),
        "setup must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Aborted"),
        "non-UTF-8 answer must be treated as 'no' and abort; got: {output}"
    );
    assert!(
        !output.contains("Applying changes..."),
        "non-UTF-8 answer must abort before applying; got: {output}"
    );
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert_eq!(pkg, original, "aborted setup must not modify package.json");
}

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

    let (code, output) = run_in_pty(
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
    // prompt text ("...and rollback files?") rather than the loose pair
    // `contains("Remove") && contains("patch(es)")` — the latter is also
    // satisfied by the SUCCESS line "Removed 1 patch(es) from manifest:",
    // so it would stay green even if the confirm prompt were dropped and the
    // command auto-removed. The exact count ("1") pins single-entry preview.
    assert!(
        output.contains("Remove 1 patch(es) and rollback files?"),
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

    let (code, output) = run_in_pty(
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
        output.contains("Remove 1 patch(es) and rollback files?"),
        "remove must have shown the interactive confirm prompt verbatim; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode"),
        "remove must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Removal cancelled"),
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
    let (code, output) = run_in_pty_bytes(
        &[
            "remove",
            "pkg:npm/__interactive_remove__@1.0.0",
            "--skip-rollback",
        ],
        tmp.path(),
        b"\xE9\n",
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
        output.contains("Remove 1 patch(es) and rollback files?"),
        "remove must have shown the interactive confirm prompt; got: {output}"
    );
    assert!(
        !output.contains("Non-interactive mode"),
        "remove must NOT have taken the non-interactive branch in a PTY; got: {output}"
    );
    assert!(
        output.contains("Removal cancelled"),
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

// ---------------------------------------------------------------------------
// Apply non-JSON without --yes also exercises confirm() flow,
// even though apply auto-proceeds in non-interactive contexts.
// ---------------------------------------------------------------------------

#[test]
fn apply_in_pty_with_no_manifest_prints_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, output) = run_in_pty(&["apply"], tmp.path(), "", Duration::from_secs(15));
    assert_eq!(code, 0);
    // Assert the full message, not either half of it. The `||` previously
    // let a truncated/garbled message ("...skipping...") pass.
    assert!(
        output.contains("No .socket folder found, skipping patch application."),
        "PTY apply no-manifest must print the friendly message; got: {output}"
    );
}
