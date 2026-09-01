//! Coverage-gap tests for `commands/update.rs` (audit of 2026-09, commit
//! d5e1815): the pinned already-there message (a zero-network path), the
//! already-latest `--json` envelope shape, the human-mode dry-run prints
//! (both the `--force` "Would reinstall" wording and the plain
//! "Update available" wording), and the PTY-driven interactive decline.
//!
//! Every wet run drives a COPY of the built binary staged into a tempdir
//! (`update_fixture::staged_install`) — `CARGO_BIN_EXE_socket-patch`
//! itself must never be a swap target. Fixture shapes are copied from
//! self_update_e2e.rs / interactive_prompts_e2e.rs (do not edit those
//! files).

#[path = "common/mod.rs"]
mod common;
#[path = "common/update_fixture.rs"]
mod update_fixture;

use update_fixture::{make_served_binary, run_installed, staged_install, FakeReleaseBuilder};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// A TCP endpoint nothing listens on (port 9 = discard, never bound on a
/// dev host): any request the child makes fails fast and loudly, so a
/// "zero network" contract regressing into a fetch flips the exit code.
const DEAD_ENDPOINT: &str = "http://127.0.0.1:9";

/// `--update <CURRENT>`: an explicit pin equal to the compiled version is
/// an informational no-op that never creates a network client — no
/// latest-resolution, no sums, no download (update.rs:225). It must use
/// the PINNED wording ("already version X", not "already the latest": the
/// pin path cannot know what the latest is), and it must NOT refresh the
/// passive notifier cache (update.rs:170 gates the state write on
/// `!pinned` — a pin says nothing about the latest release, so caching it
/// as `latestSeen` would poison the nag).
#[test]
fn update_pin_to_current_is_noop_zero_network() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();

    // No fake release is mounted at all: the dead endpoint proves the
    // pinned already-there path is decided entirely offline.
    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", CURRENT],
        &[("SOCKET_UPDATE_BASE_URL", DEAD_ENDPOINT)],
    );
    assert_eq!(
        code, 0,
        "pin-to-current must be a clean no-op.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!("socket-patch is already version {CURRENT}.")),
        "must print the pinned already-there message: {stdout}"
    );
    assert!(
        !stdout.contains("already the latest"),
        "the pin path must not claim latest-knowledge it doesn't have: {stdout}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    install.assert_workdir_untouched();
    // Pinned runs skip the notifier state refresh entirely.
    assert!(
        !install.state_dir.join("update-check.json").exists(),
        "a pinned run must not write the passive notifier cache"
    );
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// The already-latest `--json` envelope (update.rs:229-241) is a machine
/// contract scripts branch on, and it has only ever been exercised in
/// human mode: exit 0, `status: success`, `dryRun: false`, exactly one
/// skipped/already_latest event carrying `details.current`/`details.latest`,
/// summary agreeing, and the empty `warnings` omitted (additive-only
/// envelope contract). One resolve, zero sums, zero downloads.
#[tokio::test]
async fn update_already_latest_json_envelope_shape() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .expect_resolves(1)
        .expect_sums_fetches(0)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::json_string(&env, "command"), Some("update"));
    assert_eq!(common::json_string(&env, "status"), Some("success"));
    assert_eq!(
        env["dryRun"], false,
        "a wet already-latest run must not read as a dry run: {stdout}"
    );

    let events = env["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1, "exactly one skip event: {stdout}");
    let event = &events[0];
    assert_eq!(event["action"], "skipped");
    assert_eq!(
        event["errorCode"], "already_latest",
        "the routing tag scripts branch on: {stdout}"
    );
    let reason = event["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("already the latest"),
        "the human message rides the event as its reason: {reason}"
    );
    assert_eq!(event["details"]["current"], CURRENT);
    assert_eq!(event["details"]["latest"], CURRENT);
    assert_eq!(env["summary"]["skipped"], 1);

    // No advisories were raised, so `warnings` must be omitted (the
    // skip_serializing_if contract keeps existing consumers byte-stable).
    assert!(
        env.get("warnings").is_none(),
        "empty warnings must be omitted from the envelope: {stdout}"
    );

    install.assert_binary_intact();
    release.verify_request_hygiene().await;
}

/// `--dry-run --force` when already up to date: the probe still reports
/// first (one resolve, zero downloads, zero mutation), and the human
/// message is the documented "Would reinstall … (dry run; --force)"
/// wording (update.rs:193) via the human-mode dry-run print
/// (update.rs:215) — both existing dry-run tests pass `--json`, so this
/// interactive-facing surface never executed.
#[tokio::test]
async fn update_dry_run_force_up_to_date_human_says_would_reinstall() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .expect_resolves(1)
        .expect_sums_fetches(0)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--dry-run", "--force"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Would reinstall socket-patch {CURRENT} (dry run; --force)"
        )),
        "human dry-run --force must print the reinstall probe message: {stdout}"
    );

    // Dry-run mutates nothing, even with --force.
    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// The plain human dry-run with an update available (update.rs:190-191 via
/// the 215 print): "Update available: socket-patch X → Y (dry run; not
/// installed)", exit 0, nothing downloaded, nothing swapped.
#[tokio::test]
async fn update_dry_run_human_reports_update_available() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .expect_resolves(1)
        .expect_sums_fetches(0)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--dry-run"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "Update available: socket-patch {CURRENT} \u{2192} 9.9.9 (dry run; not installed)"
        )),
        "human dry-run must report the available update: {stdout}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

// ---------------------------------------------------------------------------
// Interactive decline (update.rs:251-255) — PTY-driven: output::confirm
// auto-proceeds with default-yes on non-TTY stdin (and under --yes/--json),
// so only a real terminal reaches the cancel branch. Runner copied from
// interactive_prompts_e2e.rs (do not edit that file), adapted to spawn the
// STAGED binary with injected env — so even a decline-regression that
// proceeds to a swap can only ever touch the tempdir copy, and the dead
// SOCKET_UPDATE_BASE_URL kills such a run at download.
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod pty {
    use super::*;
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};
    use std::path::Path;
    use std::time::Duration;

    /// Spawn `bin` inside a PTY under the standard SOCKET_* scrub, apply
    /// `env` last (so injections survive), send `input`, and collect all
    /// output until exit (watchdog-killed after `timeout`).
    fn run_in_pty_env(
        bin: &Path,
        args: &[&str],
        cwd: &Path,
        env: &[(&str, &str)],
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

        let mut cmd = CommandBuilder::new(bin);
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);
        // Scrub the ambient SOCKET_* surface (SOCKET_YES would skip the
        // very prompt this test drives); keep telemetry opt-outs.
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("SOCKET_")
                && !name.contains("TELEMETRY")
                && name != "SOCKET_NO_CONFIG"
                && name != "SOCKET_NO_UPDATE_CHECK"
            {
                cmd.env_remove(&key);
            }
        }
        cmd.env("SOCKET_NO_CONFIG", "1");
        // This suite hands the child a REAL terminal, so the update
        // notifier's stderr-TTY guard does not protect it — force the
        // kill-switch so no PTY child fetches release metadata mid-prompt.
        cmd.env("SOCKET_NO_UPDATE_CHECK", "1");
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
        // Caller env lands last so explicit injections survive the scrub.
        for (k, v) in env {
            cmd.env(k, v);
        }

        let mut child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("clone reader");
        let reader_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = reader.read_to_end(&mut buf);
            buf
        });

        let mut killer = child.clone_killer();
        std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = killer.kill();
        });

        let mut writer = pair.master.take_writer().expect("take writer");
        let _ = writer.write_all(input.as_bytes());
        let _ = writer.flush();
        drop(writer);

        let status = child.wait().expect("child.wait");
        drop(pair.master);
        let output = reader_handle.join().expect("reader thread join");
        (
            status.exit_code() as i32,
            String::from_utf8_lossy(&output).to_string(),
        )
    }

    /// Declining the update confirm must cancel with exit 1 and "Update
    /// cancelled.", leaving the installed binary byte-identical. The
    /// pin-to-current + `--force` combination reaches the confirm with
    /// ZERO network before the prompt (pinned skips latest-resolution,
    /// --force skips the already-there return), and the dead endpoint
    /// guarantees that even a decline-regression dies at download instead
    /// of swapping anything.
    #[test]
    fn update_interactive_n_cancels() {
        let real_hash = update_fixture::real_binary_hash();
        let install = staged_install();
        let state_dir = install.state_dir.display().to_string();

        let (code, output) = run_in_pty_env(
            &install.bin,
            &["--update", CURRENT, "--force"],
            &install.workdir,
            &[
                ("SOCKET_UPDATE_BASE_URL", DEAD_ENDPOINT),
                ("SOCKET_UPDATE_STATE_DIR", state_dir.as_str()),
            ],
            "n\n",
            Duration::from_secs(15),
        );

        // Vacuity guard: the interactive confirm MUST have run — otherwise
        // this passes against a regression that drops the TTY gate and
        // auto-proceeds (which the intact-binary check below would catch
        // only by accident of the dead endpoint).
        assert!(
            output.contains(&format!("Update socket-patch {CURRENT} \u{2192} {CURRENT}?")),
            "update must have shown the interactive confirm prompt; got: {output}"
        );
        assert!(
            !output.contains("Non-interactive mode detected"),
            "update must NOT have taken the non-TTY auto-proceed branch in a PTY; got: {output}"
        );
        assert!(
            output.contains("Update cancelled."),
            "'n' must report cancellation; got: {output}"
        );
        assert_eq!(
            code, 1,
            "a declined update exits 1 (codebase convention); got: {output}"
        );
        assert!(
            !output.contains("Updated socket-patch"),
            "a declined update must not report a swap; got: {output}"
        );

        // Declined: the staged binary is untouched and nothing was staged
        // next to it, and the real build artifact was never in play.
        install.assert_binary_intact();
        install.assert_only_binary_present();
        install.assert_workdir_untouched();
        update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
    }
}
