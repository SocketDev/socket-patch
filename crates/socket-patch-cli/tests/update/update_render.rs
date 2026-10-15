//! Human output of `socket-patch --update`, one check per message
//! family: the pinned already-there wording, the two dry-run reports and
//! the interactive reinstall confirm (PTY). The behavior behind each is
//! asserted through `--json` in `update_json_contracts.rs`; these tests
//! only pin what a person reads.
//!
//! Every run drives a COPY of the built binary staged into a tempdir
//! (`update_fixture::staged_install`): `CARGO_BIN_EXE_socket-patch`
//! itself must never be a swap target.

use crate::update_fixture;
use crate::update_json_contracts::DEAD_ENDPOINT;

use update_fixture::{make_served_binary, run_installed, staged_install, FakeReleaseBuilder};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// The pinned already-there message names the pin, not "the latest": the
/// pin path never resolves the latest release, so it can't claim it.
#[test]
fn update_pin_to_current_human_says_already_version() {
    let install = staged_install();

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", CURRENT],
        &[("SOCKET_UPDATE_BASE_URL", DEAD_ENDPOINT)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(&format!("socket-patch is already version {CURRENT}.")),
        "must print the pinned already-there message: {stdout}"
    );
    assert!(
        !stdout.contains("already the latest"),
        "the pin path must not claim latest-knowledge it doesn't have: {stdout}"
    );
    install.assert_binary_intact();
}

/// `--dry-run --force` when already up to date: the probe still reports
/// first (one resolve, zero downloads, zero mutation), and the human
/// message is the documented "Would reinstall … (dry run; --force)"
/// wording via the human-mode dry-run print (the other dry-run tests pass
/// `--json`).
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

/// The plain human dry-run with an update available: "Update available:
/// socket-patch X → Y (dry run; not installed)", exit 0, nothing
/// downloaded, nothing swapped.
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
// Interactive decline — PTY-driven: ui::confirm
// auto-proceeds with default-yes on non-TTY stdin (and under --yes/--json),
// so only a real terminal reaches the cancel branch. Runner copied from
// interactive_prompts_e2e.rs, adapted to spawn the
// STAGED binary with injected env — so even a decline-regression that
// proceeds to a swap can only ever touch the tempdir copy, and the dead
// SOCKET_UPDATE_BASE_URL kills such a run at download.
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod pty {
    use super::*;
    use portable_pty::{native_pty_system, PtySize};
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

        // The hermetic environment: SOCKET_YES would skip the very prompt
        // this test drives, and the update notifier is forced off (this
        // suite hands the child a REAL terminal, so the stderr-TTY guard
        // does not protect it).
        let mut cmd = crate::common::hermetic::pty_command(bin);
        for a in args {
            cmd.arg(a);
        }
        cmd.cwd(cwd);
        // Caller env lands last so explicit injections survive the scrub.
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

    /// Declining the reinstall confirm must cancel with exit 1 and
    /// "Cancelled; no changes made.", leaving the installed binary byte-identical.
    /// The pin-to-current + `--force` combination reaches the confirm with
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
            // Pinned to the running version + --force: a reinstall.
            output.contains(&format!("Reinstall socket-patch {CURRENT}?")),
            "update must have shown the interactive confirm prompt; got: {output}"
        );
        assert!(
            !output.contains("Non-interactive mode detected"),
            "update must NOT have taken the non-TTY auto-proceed branch in a PTY; got: {output}"
        );
        assert!(
            output.contains("Cancelled; no changes made."),
            "'n' must report cancellation, naming the reinstall; got: {output}"
        );
        assert_eq!(
            code, 1,
            "a declined update exits 1 (codebase convention); got: {output}"
        );
        assert!(
            !output.contains("Updated socket-patch")
                && !output.contains("Reinstalled socket-patch"),
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
