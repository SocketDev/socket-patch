//! e2e for the passive update notifier: guard precedence observed through
//! a real spawned binary, the once-a-day cadence driven purely through the
//! on-disk state file (no clock mocking — "a day passed" is a
//! `lastCheckAt` written 25h in the past), and the two invariants that
//! only an e2e can prove: a silenced run performs ZERO network I/O, and
//! the notifier can never fail, slow, or pollute the carrier command.
//!
//! Carrier command: `apply` in an empty workdir — it flows through normal
//! dispatch (so the notifier hook runs), prints its friendly no-manifest
//! skip, exits 0, and touches nothing. `list`/`rollback`/`repair` exit 1
//! without a manifest, and `--version`/`--help` never dispatch (clap
//! handles them before the hook), so none of those can carry the notifier.

#[path = "common/mod.rs"]
mod common;
#[path = "common/update_fixture.rs"]
mod update_fixture;

use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use update_fixture::{run_installed, staged_install, FakeReleaseBuilder, StagedInstall};

const CURRENT: &str = env!("CARGO_PKG_VERSION");
const HOUR: i64 = 60 * 60;
/// 25h vs the 24h TTL: slack against wall-clock drift between the write
/// and the child's own `unix_now()`.
const STALE: i64 = 25 * HOUR;
const FRESH: i64 = HOUR;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("post-1970 clock")
        .as_secs() as i64
}

/// Write `update-check.json` the way the binary would have after a check
/// `last_check_ago_secs` in the past (negative = a future timestamp, for
/// the clock-skew row).
fn write_state(
    state_dir: &Path,
    last_check_ago_secs: i64,
    latest_seen: Option<&str>,
    last_notified_ago_secs: Option<i64>,
) {
    let now = now_secs();
    let mut obj = serde_json::json!({
        "schemaVersion": 1,
        "lastCheckAt": now - last_check_ago_secs,
    });
    if let Some(v) = latest_seen {
        obj["latestSeen"] = serde_json::Value::from(v);
    }
    if let Some(ago) = last_notified_ago_secs {
        obj["lastNotifiedAt"] = serde_json::Value::from(now - ago);
    }
    std::fs::write(
        state_dir.join("update-check.json"),
        serde_json::to_vec_pretty(&obj).unwrap(),
    )
    .expect("write update-check.json");
}

fn read_state(state_dir: &Path) -> serde_json::Value {
    let raw = std::fs::read(state_dir.join("update-check.json"))
        .expect("update-check.json must exist");
    serde_json::from_slice(&raw).unwrap_or_else(|e| {
        panic!(
            "update-check.json must be valid JSON: {e}\nraw:\n{}",
            String::from_utf8_lossy(&raw)
        )
    })
}

/// Env for a run that SHOULD check: opt-out off, the test-only force knob
/// bypassing the stderr-TTY guard (children write to pipes), CI vars
/// neutralized (the test runner itself may be in CI), release endpoint
/// pointed at the fake. `run_installed` already injects the state dir.
fn eligible_kit(base_url: &str) -> Vec<(&str, &str)> {
    vec![
        ("SOCKET_NO_UPDATE_CHECK", "0"),
        ("SOCKET_UPDATE_NOTIFIER_FORCE", "1"),
        ("CI", ""),
        ("GITHUB_ACTIONS", ""),
        ("SOCKET_UPDATE_BASE_URL", base_url),
    ]
}

/// The notifier must never mutate the install or the project dir, on any
/// path — every row re-proves it.
fn assert_install_pristine(install: &StagedInstall) {
    install.assert_binary_intact();
    install.assert_only_binary_present();
    install.assert_workdir_untouched();
}

// ── The notice lifecycle ───────────────────────────────────────────────

/// Virgin install, newer release available: the first eligible run checks,
/// notices on stderr (never stdout — stdout belongs to the command), and
/// seeds the state file.
#[tokio::test]
async fn first_eligible_run_checks_and_notices() {
    let install = staged_install();
    // No assets: the notifier only resolves the latest version.
    let release = FakeReleaseBuilder::new("9.9.9")
        .expect_resolves(1)
        .mount()
        .await;

    let (code, stdout, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("Update available") && stderr.contains("9.9.9"),
        "first eligible run must print the notice on stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Update available"),
        "the notice must never contaminate stdout: {stdout}"
    );

    let state = read_state(&install.state_dir);
    assert_eq!(state["latestSeen"], "9.9.9", "check must persist what it saw");
    assert!(
        state["lastCheckAt"].as_i64().is_some(),
        "check must record when it ran: {state}"
    );
    assert!(
        state["lastNotifiedAt"].as_i64().is_some(),
        "printing the notice must start the daily rate limit: {state}"
    );

    release.verify_request_hygiene().await;
    assert_install_pristine(&install);
}

/// A check ran an hour ago and saw a newer version: the notice comes from
/// the CACHE with zero network — the fetch cadence and the nag cadence are
/// independent.
#[tokio::test]
async fn fresh_state_notices_from_cache_with_zero_network() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, FRESH, Some("9.9.9"), None);

    let (code, _, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0);
    assert!(
        stderr.contains("Update available") && stderr.contains("9.9.9"),
        "cached knowledge must still produce the notice: {stderr}"
    );
    assert_eq!(
        release.received_request_count().await,
        0,
        "a fresh state file must suppress the fetch entirely"
    );
    assert_install_pristine(&install);
}

/// 25h-old state: the cadence has lapsed, so the run re-fetches and
/// rewrites the state with what it found.
#[tokio::test]
async fn stale_state_rechecks() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9")
        .expect_resolves(1)
        .mount()
        .await;
    write_state(&install.state_dir, STALE, Some(CURRENT), None);

    let (code, stdout, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let state = read_state(&install.state_dir);
    assert_eq!(
        state["latestSeen"], "9.9.9",
        "the re-check must overwrite the stale latestSeen: {state}"
    );
    let last = state["lastCheckAt"].as_i64().expect("lastCheckAt set");
    assert!(
        (now_secs() - last).abs() <= 60,
        "lastCheckAt must advance to the new check time, got {last}"
    );
    release.verify_request_hygiene().await;
    assert_install_pristine(&install);
}

/// Already on the latest release: the check still runs (cadence lapsed)
/// but no notice appears — the notifier only speaks when there is news.
#[tokio::test]
async fn up_to_date_prints_nothing() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new(CURRENT)
        .expect_resolves(1)
        .mount()
        .await;
    write_state(&install.state_dir, STALE, Some(CURRENT), None);

    let (code, _, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0);
    assert!(
        !stderr.contains("Update available"),
        "no notice when current == latest: {stderr}"
    );
    assert_install_pristine(&install);
}

/// The nag itself is rate-limited: an update is KNOWN (cached) but the
/// notice was already shown an hour ago, so this run stays quiet.
#[tokio::test]
async fn notice_rate_limited_to_daily() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, FRESH, Some("9.9.9"), Some(FRESH));

    let (code, _, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0);
    assert!(
        !stderr.contains("Update available"),
        "a notice shown within the last day must not repeat: {stderr}"
    );
    assert_eq!(release.received_request_count().await, 0);
    assert_install_pristine(&install);
}

/// …and once a day has passed since the last notice, the nag returns
/// (still from cache — the check cadence is untouched).
#[tokio::test]
async fn notice_returns_after_a_day() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, FRESH, Some("9.9.9"), Some(STALE));

    let (code, _, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0);
    assert!(
        stderr.contains("Update available"),
        "a day after the last notice the nag must return: {stderr}"
    );
    assert_eq!(release.received_request_count().await, 0);
    assert_install_pristine(&install);
}

// ── State-file resilience ──────────────────────────────────────────────

/// Corrupt cache bytes must read as "never checked" — never crash, and the
/// next successful check heals the file back into valid JSON.
#[tokio::test]
async fn corrupt_state_recovers() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9")
        .expect_resolves(1)
        .mount()
        .await;
    std::fs::write(
        install.state_dir.join("update-check.json"),
        b"\x00garbage{{{",
    )
    .unwrap();

    let (code, stdout, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        !stderr.contains("panicked"),
        "corrupt state must never panic the CLI: {stderr}"
    );
    // read_state panics on invalid JSON — this IS the heal assertion.
    let state = read_state(&install.state_dir);
    assert_eq!(
        state["latestSeen"], "9.9.9",
        "the recovery check must rewrite a valid state file: {state}"
    );
    assert_install_pristine(&install);
}

/// A `lastCheckAt` 48h in the FUTURE is clock skew, not a valid
/// suppression: it must count as due, so a wrong clock can never wedge the
/// notifier until the bogus timestamp passes.
#[tokio::test]
async fn future_timestamp_tolerated() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9")
        .expect_resolves(1)
        .mount()
        .await;
    write_state(&install.state_dir, -48 * HOUR, Some("9.9.9"), None);

    let (code, stdout, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_install_pristine(&install);
}

/// State dir the child cannot write: the check runs, the persist fails,
/// and the carrier neither fails nor complains — cache trouble is never
/// the user's problem.
#[cfg(unix)]
#[tokio::test]
async fn unwritable_state_dir_is_harmless() {
    use std::os::unix::fs::PermissionsExt;

    let install = staged_install();
    std::fs::set_permissions(&install.state_dir, std::fs::Permissions::from_mode(0o555))
        .expect("chmod state dir read-only");
    // Root ignores mode bits; probe and skip rather than assert a
    // restriction that isn't in force.
    if std::fs::write(install.state_dir.join("probe"), b"x").is_ok() {
        let _ = std::fs::remove_file(install.state_dir.join("probe"));
        eprintln!("running as root: read-only dir not enforceable, skipping");
        return;
    }

    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    let (code, stdout, stderr) =
        run_installed(&install, &["apply"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        !stderr.contains("Error"),
        "an unwritable cache dir must be silently absorbed: {stderr}"
    );

    std::fs::set_permissions(&install.state_dir, std::fs::Permissions::from_mode(0o755))
        .expect("restore state dir perms");
    assert_install_pristine(&install);
}

// ── Guards: silence means ZERO network, not just zero output ──────────
//
// Every guard row writes STALE state first — a check is genuinely due, so
// zero requests proves the guard suppressed the fetch itself, not that the
// cadence happened to be fresh.

/// Piped stderr (no force knob): the TTY guard silences the fetch too. A
/// regression that only muted the print would still leak network I/O into
/// every scripted invocation.
#[tokio::test]
async fn guard_non_tty_silences_fetch_too() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, STALE, Some("9.9.9"), None);

    let mut kit = eligible_kit(&release.base_url);
    kit.retain(|(k, _)| *k != "SOCKET_UPDATE_NOTIFIER_FORCE");
    let (code, _, stderr) = run_installed(&install, &["apply"], &kit);
    assert_eq!(code, 0);
    assert_eq!(
        release.received_request_count().await,
        0,
        "the TTY guard must suppress the FETCH, not just the print"
    );
    assert!(!stderr.contains("Update available"), "{stderr}");
    assert_install_pristine(&install);
}

/// CI always silences — the force knob bypasses ONLY the TTY guard, so a
/// forced test env inside CI still stays quiet and offline.
#[tokio::test]
async fn guard_ci_silences_even_forced() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, STALE, Some("9.9.9"), None);

    let mut kit = eligible_kit(&release.base_url);
    kit.push(("CI", "true")); // lands after the kit's CI="" and wins
    let (code, _, stderr) = run_installed(&install, &["apply"], &kit);
    assert_eq!(code, 0);
    assert_eq!(release.received_request_count().await, 0);
    assert!(!stderr.contains("Update available"), "{stderr}");
    assert_install_pristine(&install);
}

/// Offline mode is a promise of zero network — the notifier is bound by it
/// like everything else.
#[tokio::test]
async fn guard_offline_silences() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, STALE, Some("9.9.9"), None);

    let mut kit = eligible_kit(&release.base_url);
    kit.push(("SOCKET_OFFLINE", "1"));
    let (code, _, stderr) = run_installed(&install, &["apply"], &kit);
    assert_eq!(code, 0);
    assert_eq!(release.received_request_count().await, 0);
    assert!(!stderr.contains("Update available"), "{stderr}");
    assert_install_pristine(&install);
}

/// `--silent` asked for nothing but the essentials — the notifier is not
/// essential, and its background fetch isn't either.
#[tokio::test]
async fn guard_silent_flag_silences() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, STALE, Some("9.9.9"), None);

    let (code, _, stderr) = run_installed(
        &install,
        &["apply", "--silent"],
        &eligible_kit(&release.base_url),
    );
    assert_eq!(code, 0);
    assert_eq!(release.received_request_count().await, 0);
    assert!(
        !stderr.contains("Update available") && !stderr.contains("[socket-patch]"),
        "--silent must leave stderr free of notices: {stderr}"
    );
    assert_install_pristine(&install);
}

/// `--json` output is consumed by machines: the envelope must stay pure
/// and the run must stay network-clean.
#[tokio::test]
async fn guard_json_flag_silences() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, STALE, Some("9.9.9"), None);

    let (code, stdout, stderr) = run_installed(
        &install,
        &["apply", "--json"],
        &eligible_kit(&release.base_url),
    );
    assert_eq!(code, 0);
    // parse_json_envelope panics on trailing/leading garbage — this IS the
    // purity assertion for stdout.
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::json_string(&env, "command").as_deref(), Some("apply"));
    assert_eq!(release.received_request_count().await, 0);
    assert!(
        !stderr.contains("Update available"),
        "no notice may ride alongside a JSON run: {stderr}"
    );
    assert_install_pristine(&install);
}

/// The kill switch wins over everything, including the force knob — the
/// documented "make it stop" works unconditionally.
#[tokio::test]
async fn guard_opt_out_beats_force() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9").mount().await;
    write_state(&install.state_dir, STALE, Some("9.9.9"), None);

    let mut kit = eligible_kit(&release.base_url);
    kit.push(("SOCKET_NO_UPDATE_CHECK", "1")); // overrides the kit's "0"
    let (code, _, stderr) = run_installed(&install, &["apply"], &kit);
    assert_eq!(code, 0);
    assert_eq!(release.received_request_count().await, 0);
    assert!(!stderr.contains("Update available"), "{stderr}");
    assert_install_pristine(&install);
}

// ── The notifier can never hurt the carrier ────────────────────────────

/// Unreachable release host: the carrier is untouched, and the FAILED
/// check still advances `lastCheckAt` — a broken network is retried at
/// most once a day, not on every command.
#[tokio::test]
async fn dead_endpoint_never_fails_the_command() {
    let install = staged_install();
    write_state(&install.state_dir, STALE, Some(CURRENT), None);

    let (code, stdout, stderr) = run_installed(
        &install,
        &["apply"],
        &eligible_kit("http://127.0.0.1:1"),
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!stderr.contains("Update available"), "{stderr}");

    let state = read_state(&install.state_dir);
    let last = state["lastCheckAt"].as_i64().expect("lastCheckAt set");
    assert!(
        (now_secs() - last).abs() <= 60,
        "a failed check must still rate-limit itself to once a day; \
         lastCheckAt={last} now={}",
        now_secs()
    );
    assert_install_pristine(&install);
}

/// A slow release host must cost the user at most the 500ms grace budget.
/// The fetch budget is deliberately raised to 30s so only the join grace
/// can explain a fast exit.
#[tokio::test]
async fn grace_budget_bounds_command_latency() {
    let install = staged_install();
    let release = FakeReleaseBuilder::new("9.9.9")
        .delay_metadata(Duration::from_secs(30))
        .mount()
        .await;
    write_state(&install.state_dir, STALE, Some(CURRENT), None);

    let mut kit = eligible_kit(&release.base_url);
    kit.push(("SOCKET_UPDATE_TIMEOUT_MS", "30000"));
    let start = Instant::now();
    let (code, stdout, stderr) = run_installed(&install, &["apply"], &kit);
    let wall = start.elapsed();
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    // 10s = 500ms grace + generous debug-binary startup slack; the 30s
    // response delay proves the join gave up rather than the fetch winning.
    assert!(
        wall < Duration::from_secs(10),
        "the notifier must never hold a command hostage: took {wall:?}"
    );
    assert!(!stderr.contains("Update available"), "{stderr}");
    assert_install_pristine(&install);
}

/// `--update` IS the check — the hook is skipped structurally for it. The
/// stale cache screams "9.9.9 available", the env is fully eligible, yet
/// no notice may ride on the update command's own output.
#[tokio::test]
async fn update_command_never_notifies() {
    let install = staged_install();
    let (served, _) = update_fixture::make_served_binary();
    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .mount()
        .await;
    write_state(&install.state_dir, STALE, Some("9.9.9"), None);

    let (code, stdout, stderr) =
        run_installed(&install, &["--update"], &eligible_kit(&release.base_url));
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("already the latest"),
        "no --force: this must be the already-latest no-op: {stdout}"
    );
    assert!(
        !stderr.contains("Update available"),
        "--update must never carry the passive notice: {stderr}"
    );
    release.verify_request_hygiene().await;
    assert_install_pristine(&install);
}

// ── The one genuine-TTY row ────────────────────────────────────────────

/// Every other row bypasses the TTY guard with the force knob; this is the
/// proof the REAL guard passes on a real terminal — a regression inverting
/// the isatty check (notices everywhere except terminals) would slip past
/// the whole piped suite.
#[cfg(unix)]
mod pty {
    use super::*;
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::Read;

    /// Minimal PTY runner (same shape as `interactive_prompts_e2e.rs`):
    /// reader thread to EOF, detached SIGKILL watchdog, no input. This
    /// bypasses `run_installed`, so the hermetic scrub and the update kit
    /// are reproduced by hand.
    fn run_in_pty(
        bin: &Path,
        cwd: &Path,
        env: &[(&str, &str)],
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
        cmd.arg("apply");
        cmd.cwd(cwd);
        // Prefix-scrub the ambient SOCKET_* surface (keep telemetry
        // opt-outs and the no-config hermeticity default), then land the
        // caller's kit — mirrors run_bin_with_env for a PTY child.
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy().into_owned();
            if name.starts_with("SOCKET_")
                && !name.contains("TELEMETRY")
                && name != "SOCKET_NO_CONFIG"
            {
                cmd.env_remove(name);
            }
        }
        cmd.env("SOCKET_NO_CONFIG", "1");
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

        // No prompt to answer: close the writer immediately so the child's
        // stdin sees EOF if anything ever reads it.
        drop(pair.master.take_writer().expect("take writer"));

        let status = child.wait().expect("child.wait");
        drop(pair.master);
        let output = reader_handle.join().expect("reader join");
        (status.exit_code() as i32, String::from_utf8_lossy(&output).to_string())
    }

    #[tokio::test]
    async fn real_tty_shows_notice_pty() {
        let install = staged_install();
        let release = FakeReleaseBuilder::new("9.9.9").mount().await;
        write_state(&install.state_dir, STALE, Some(CURRENT), None);

        let state_dir = install.state_dir.display().to_string();
        // The eligible kit WITHOUT the force knob — the PTY itself must
        // satisfy the stderr-TTY guard.
        let kit: Vec<(&str, &str)> = vec![
            ("SOCKET_UPDATE_STATE_DIR", state_dir.as_str()),
            ("SOCKET_NO_UPDATE_CHECK", "0"),
            ("CI", ""),
            ("GITHUB_ACTIONS", ""),
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
        ];
        let (code, output) = run_in_pty(
            &install.bin,
            &install.workdir,
            &kit,
            Duration::from_secs(30),
        );
        assert_eq!(code, 0, "carrier must succeed in a PTY; got: {output}");
        assert!(
            output.contains("Update available") && output.contains("9.9.9"),
            "a real terminal must receive the notice without the force knob: {output}"
        );
        assert_install_pristine(&install);
    }
}
