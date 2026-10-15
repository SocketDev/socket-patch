//! `scan` on a real terminal (#1089): it never prompts, never opens the
//! select menu under `--json`, and renders the live status line cleanly.
//! Unix only (`portable_pty`); the built binary runs in the hermetic
//! environment.

use std::path::Path;
use std::time::Duration;

use portable_pty::{native_pty_system, PtySize};
use wiremock::MockServer;

use crate::common;
use crate::scan_fixture::*;

/// Spawn the binary in a PTY, send `input`, and collect all output
/// until exit (the `interactive_prompts_e2e.rs` harness pattern:
/// reader thread + kill-after-timeout watchdog, no polling).
fn run_in_pty(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
    run_in_pty_with(args, cwd, &[], "", input, timeout)
}

/// [`run_in_pty`] with extra child `env`, first writing `typeahead`
/// straight after spawn — keystrokes a user types while the scan is
/// still running, before any prompt is on screen.
fn run_in_pty_with(
    args: &[&str],
    cwd: &Path,
    env: &[(&str, &str)],
    typeahead: &str,
    input: &str,
    timeout: Duration,
) -> (i32, String) {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    // The hermetic environment (`tests/common/hermetic.rs`), which also
    // forces the update notifier off: this child gets a REAL terminal,
    // so the stderr-TTY guard does not protect it.
    let mut cmd = common::hermetic::pty_binary_command();
    for a in args {
        cmd.arg(a);
    }
    cmd.cwd(cwd);
    // These tests assert VT rendering, even when the parent has TERM=dumb.
    cmd.env("TERM", "xterm-256color");
    for (k, v) in env {
        cmd.env(k, v);
    }

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
    if !typeahead.is_empty() {
        use std::io::Write as _;
        let _ = writer.write_all(typeahead.as_bytes());
        let _ = writer.flush();
    }
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

/// v5 scan never prompts, even on a TTY: agent mode applies with no
/// input at all.
#[tokio::test(flavor = "multi_thread")]
async fn scan_on_a_tty_applies_without_prompting() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/silent-target@1.0.0";
    let before = b"before\n";
    mount_one_patch_api(&mock, purl, before).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);

    let uri = mock.uri();
    let cwd = tmp.path().to_path_buf();
    let (code, output) = tokio::task::spawn_blocking(move || {
        run_in_pty(
            &[
                "scan",
                "--mode",
                "agent",
                "--api-url",
                &uri,
                "--api-token",
                "fake-token-for-test",
                "--org",
                ORG_SLUG,
            ],
            &cwd,
            "",
            Duration::from_secs(60),
        )
    })
    .await
    .expect("spawn_blocking join");

    assert_eq!(code, 0, "output:\n{output}");
    assert!(
        !output.contains("[Y/n]") && !output.contains("Download and apply"),
        "scan must not prompt; got:\n{output}"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/silent-target/index.js")).unwrap(),
        b"after\n",
        "the apply must proceed unattended"
    );
}

/// `scan --json` on a real terminal must never open the interactive
/// "Select one" menu over its machine-read output: with several free
/// patches for one package it picks the top-ranked one, like a non-TTY
/// run, and finishes on its own.
#[tokio::test(flavor = "multi_thread")]
async fn scan_json_on_a_tty_never_opens_the_select_menu() {
    let mock = MockServer::start().await;
    let purl = MINIMIST;
    let second = UUID_B;
    let offer = |uuid: &str, cve: &str, title: &str| {
        serde_json::json!({ "uuid": uuid, "purl": purl, "tier": "free", "cveIds": [cve],
                            "ghsaIds": [], "severity": "high", "title": title })
    };
    let packages = serde_json::json!([{
        "purl": purl,
        "patches": [offer(UUID, "CVE-2024-1", "a"), offer(second, "CVE-2024-2", "b")],
    }]);
    mount_batch(&mock, packages, false).await;
    let patch = |uuid: &str, published: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl, "publishedAt": published,
            "description": "d", "license": "MIT", "tier": "free",
            "vulnerabilities": {},
        })
    };
    let details = serde_json::json!({
        "patches": [patch(UUID, "2024-01-01T00:00:00Z"), patch(second, "2025-01-01T00:00:00Z")],
        "canAccessPaidPatches": false,
    });
    mount_by_package_body(&mock, purl, details).await;

    let tmp = minimist_project(b"x\n");

    let uri = mock.uri();
    let cwd = tmp.path().to_path_buf();
    let (code, output) = tokio::task::spawn_blocking(move || {
        run_in_pty(
            &[
                "scan",
                "--json",
                "--mode",
                "agent",
                "--dry-run",
                "--api-url",
                &uri,
                "--api-token",
                "fake-token-for-test",
                "--org",
                ORG_SLUG,
            ],
            &cwd,
            "",
            Duration::from_secs(30),
        )
    })
    .await
    .expect("spawn_blocking join");

    assert!(
        !output.contains("Select one") && !output.contains("Multiple patches available"),
        "no interactive menu under --json; got:\n{output}"
    );
    assert_eq!(code, 0, "the run must finish on its own; output:\n{output}");
    // The pty merges stdout and stderr; the envelope is the only `{…}`.
    let text = output.replace("\r\n", "\n");
    let json_text =
        &text[text.find('{').expect("JSON envelope")..=text.rfind('}').expect("JSON envelope end")];
    let json: serde_json::Value = serde_json::from_str(json_text)
        .unwrap_or_else(|e| panic!("envelope must parse ({e}); got:\n{output}"));
    assert_eq!(json["status"], "success", "{json}");
    let planned = json["events"]
        .as_array()
        .unwrap_or_else(|| panic!("events must be an array: {json}"));
    assert_eq!(planned.len(), 1, "exactly one patch selected: {json}");
    assert_eq!(
        planned[0]["uuid"], second,
        "the top-ranked (newer) patch is picked, not the first listed: {json}"
    );
}

/// The live status line on a real terminal: every progress message is
/// replaced (never overwritten in place), so what the user sees is the
/// result lines only — no "Found 1 patch for 1 packagesatch 1/1)"
/// residue from the longer "Querying API ... (batch 1/1)" line.
#[tokio::test(flavor = "multi_thread")]
async fn scan_progress_on_a_tty_renders_without_stale_tail() {
    let mock = MockServer::start().await;
    let purl = MINIMIST;
    mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
    mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;

    let tmp = minimist_project(b"x\n");

    let uri = mock.uri();
    let cwd = tmp.path().to_path_buf();
    let (code, output) = tokio::task::spawn_blocking(move || {
        run_in_pty(
            &[
                "scan",
                "--api-url",
                &uri,
                "--api-token",
                "fake-token-for-test",
                "--org",
                ORG_SLUG,
            ],
            &cwd,
            "n\n",
            Duration::from_secs(60),
        )
    })
    .await
    .expect("spawn_blocking join");
    assert_eq!(code, 0, "output:\n{output}");

    // The raw stream really used the live line (so this test would
    // catch a regression to bare `\r` rewrites)...
    assert!(
        output.contains("\r\x1b[2KQuerying API for patches... (batch 1/1)"),
        "expected a live status update; raw={output:?}"
    );
    // ...and the screen shows only clean result lines.
    let screen = crate::pty_io::render(output.as_bytes());
    assert!(
        screen.iter().any(|l| l == "Found 1 package (1 npm)"),
        "screen:\n{}",
        screen.join("\n")
    );
    assert!(
        screen.iter().any(|l| l == "Found 1 patch for 1 package"),
        "screen:\n{}",
        screen.join("\n")
    );
    for transient in [
        "Scanning packages",
        "Querying API",
        "Fetching patch details",
    ] {
        assert!(
            !screen.iter().any(|l| l.contains(transient)),
            "transient status {transient:?} must not stay on screen:\n{}",
            screen.join("\n")
        );
    }
}

/// Under `SOCKET_DEBUG` core prints `[socket-patch debug] ...` lines
/// straight to stderr. The live status line is off then, so those
/// lines never land glued onto the end of a progress message.
#[tokio::test(flavor = "multi_thread")]
async fn scan_debug_mode_on_a_tty_keeps_debug_lines_off_the_status() {
    let mock = MockServer::start().await;
    let purl = MINIMIST;
    mount_batch_one(&mock, purl, UUID, "free", &[], false).await;
    mount_by_package(&mock, purl, UUID, serde_json::json!({})).await;

    let tmp = minimist_project(b"x\n");

    let uri = mock.uri();
    let cwd = tmp.path().to_path_buf();
    let (code, output) = tokio::task::spawn_blocking(move || {
        run_in_pty_with(
            &[
                "scan",
                "--api-url",
                &uri,
                "--api-token",
                "fake-token-for-test",
                "--org",
                ORG_SLUG,
            ],
            &cwd,
            &[("SOCKET_DEBUG", "1")],
            "",
            "n\n",
            Duration::from_secs(60),
        )
    })
    .await
    .expect("spawn_blocking join");
    assert_eq!(code, 0, "output:\n{output}");

    let screen = crate::pty_io::render(output.as_bytes());
    let debug: Vec<&String> = screen
        .iter()
        .filter(|l| l.contains("[socket-patch debug]"))
        .collect();
    assert!(
        !debug.is_empty(),
        "SOCKET_DEBUG must produce debug lines; screen:\n{}",
        screen.join("\n")
    );
    for line in debug {
        assert!(
            line.starts_with("[socket-patch debug]"),
            "a debug line was glued onto other output: {line:?}"
        );
    }
    assert!(
        !output.contains("Querying API for patches..."),
        "no transient status is drawn in debug mode; raw={output:?}"
    );
    assert!(
        screen.iter().any(|l| l == "Found 1 patch for 1 package"),
        "the result lines still print; screen:\n{}",
        screen.join("\n")
    );
}
