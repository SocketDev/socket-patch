//! Passive update-check notifier: at most once a day, on interactive
//! human-facing runs only, mention on stderr that a newer release exists.
//!
//! Model: after clap parses (and never for `--update` itself — `main`
//! skips the hook structurally), a guard stack decides whether a check may
//! run at all. If one is due, a spawned tokio task first records the
//! attempt (so "once a day" holds even if the process exits mid-fetch),
//! then fetches while the real command does its work; at the end of the
//! run the task is joined with a 500 ms grace budget. A fetch that misses
//! the budget is abandoned — a completed result surfaces as a zero-latency
//! cached notice on the NEXT run, a killed one waits for tomorrow's
//! attempt.
//!
//! Invariants (enforced by `update_notifier_e2e.rs`):
//! - a silenced run performs **zero network I/O**, not just zero output;
//! - the notifier can never change a command's exit code or stdout;
//! - it can never delay a command beyond the grace budget;
//! - state corruption/unwritability is silently absorbed.

use std::time::Duration;

use socket_patch_core::update::{
    self as core_update, detect_channel, is_newer, upgrade_hint, ChannelEnv, InstallChannel,
    UpdateEndpoints, UpdateTimeouts,
};

use crate::args::GlobalArgs;
use crate::output;

/// Everything the guard stack looks at, captured up front so the decision
/// logic is a pure, table-testable function.
#[derive(Debug, Clone)]
pub struct GuardCtx {
    /// `SOCKET_NO_UPDATE_CHECK` truthy — the kill switch. Wins over
    /// everything, including the force knob.
    pub opted_out: bool,
    pub offline: bool,
    pub silent: bool,
    pub json: bool,
    /// `CI`/`GITHUB_ACTIONS` say a robot is watching. Always silences —
    /// the force knob does NOT bypass it (tests neutralize with `CI=""`).
    pub ci: bool,
    pub stderr_tty: bool,
    /// `SOCKET_UPDATE_NOTIFIER_FORCE` truthy — undocumented test hook that
    /// bypasses ONLY the stderr-TTY guard (e2e children write to pipes).
    pub forced: bool,
    pub state_dir_resolvable: bool,
}

/// Why the notifier stayed quiet (debug-logged under `--debug`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    OptedOut,
    Offline,
    Silent,
    Json,
    Ci,
    NotATty,
    NoStateDir,
}

impl SkipReason {
    fn as_str(self) -> &'static str {
        match self {
            SkipReason::OptedOut => "SOCKET_NO_UPDATE_CHECK is set",
            SkipReason::Offline => "offline mode",
            SkipReason::Silent => "--silent",
            SkipReason::Json => "--json",
            SkipReason::Ci => "CI environment",
            SkipReason::NotATty => "stderr is not a terminal",
            SkipReason::NoStateDir => "no resolvable state directory",
        }
    }
}

/// The single place notifier-guard precedence is defined:
/// opt-out, offline, `--silent`, `--json`, and CI always silence;
/// the force knob bypasses the TTY guard alone.
pub fn should_check(ctx: &GuardCtx) -> Result<(), SkipReason> {
    if ctx.opted_out {
        return Err(SkipReason::OptedOut);
    }
    if ctx.offline {
        return Err(SkipReason::Offline);
    }
    if ctx.silent {
        return Err(SkipReason::Silent);
    }
    if ctx.json {
        return Err(SkipReason::Json);
    }
    if ctx.ci {
        return Err(SkipReason::Ci);
    }
    if !ctx.stderr_tty && !ctx.forced {
        return Err(SkipReason::NotATty);
    }
    if !ctx.state_dir_resolvable {
        return Err(SkipReason::NoStateDir);
    }
    Ok(())
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on" | "y" | "t"
    )
}

/// `CI` set to anything non-empty except an explicit falsy counts;
/// `GITHUB_ACTIONS` counts whenever non-empty. Deliberately short list —
/// the TTY guard covers other vendors' runners anyway.
fn in_ci() -> bool {
    let ci = std::env::var("CI").unwrap_or_default();
    if !ci.is_empty() && !matches!(ci.trim().to_ascii_lowercase().as_str(), "0" | "false") {
        return true;
    }
    !std::env::var("GITHUB_ACTIONS").unwrap_or_default().is_empty()
}

impl GuardCtx {
    /// Capture the real environment + the parsed global flags.
    pub fn capture(common: &GlobalArgs) -> Self {
        GuardCtx {
            opted_out: env_flag("SOCKET_NO_UPDATE_CHECK"),
            offline: common.offline,
            silent: common.silent,
            json: common.json,
            ci: in_ci(),
            stderr_tty: output::stderr_is_tty(),
            forced: env_flag("SOCKET_UPDATE_NOTIFIER_FORCE"),
            state_dir_resolvable: core_update::state::state_dir().is_some(),
        }
    }
}

/// Handle carried across the command run.
pub struct Notifier {
    /// Running fetch, present only when a check was due this run.
    task: Option<tokio::task::JoinHandle<Option<semver::Version>>>,
    /// `latestSeen` loaded at spawn time — the cached fallback the notice
    /// uses when the in-run fetch misses the grace budget (or none ran).
    cached_latest: Option<semver::Version>,
    last_notified_at: Option<u64>,
    debug: bool,
}

fn debug_log(debug: bool, message: &str) {
    if debug {
        eprintln!("[socket-patch update] {message}");
    }
}

/// Evaluate the guards and, when a check is due, start the background
/// fetch. Cheap on every path: env reads plus one tiny state-file read.
/// Returns `None` when the notifier is fully silenced for this run.
pub fn spawn_if_due(common: &GlobalArgs) -> Option<Notifier> {
    let ctx = GuardCtx::capture(common);
    let debug = common.debug;
    if let Err(reason) = should_check(&ctx) {
        debug_log(debug, &format!("skipped: {}", reason.as_str()));
        return None;
    }

    let state = core_update::load_state();
    let cached_latest = state
        .latest_seen
        .as_deref()
        .and_then(|v| semver::Version::parse(v).ok());
    let now = core_update::unix_now();

    let task = if core_update::check_is_due(state.last_check_at, now) {
        debug_log(debug, "checking for updates in the background");
        Some(tokio::spawn(refresh_latest(debug)))
    } else {
        debug_log(debug, "check not due; using cached state");
        None
    };

    Some(Notifier {
        task,
        cached_latest,
        last_notified_at: state.last_notified_at,
        debug,
    })
}

/// The background fetch, bounded hard at 2 s (or the test override).
///
/// The ATTEMPT is persisted before the fetch, not after: the process may
/// exit (and kill this task) as soon as the carrier command finishes, and
/// on some platforms even a dead endpoint takes seconds to fail (Windows
/// retries SYNs to a closed port) — recording afterwards would let every
/// sub-grace command on a broken network burn a fresh fetch attempt.
/// Writing first makes "at most one attempt per day" hold unconditionally;
/// the cost is that a killed fetch's result waits for tomorrow's retry.
/// All errors are swallowed into debug logs.
async fn refresh_latest(debug: bool) -> Option<semver::Version> {
    let mut state = core_update::load_state();
    state.last_check_at = Some(core_update::unix_now());
    if let Err(e) = core_update::save_state(&state).await {
        debug_log(debug, &format!("could not persist update state: {e}"));
    }

    let endpoints = UpdateEndpoints::from_env();
    let override_ms = std::env::var("SOCKET_UPDATE_TIMEOUT_MS")
        .ok()
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<u64>().ok());
    let budget = Duration::from_millis(override_ms.unwrap_or(2000));
    let timeouts = UpdateTimeouts {
        connect: budget,
        metadata: budget,
        download: budget,
    };

    let fetched = match core_update::fetch_latest_version(&endpoints, &timeouts).await {
        Ok(v) => Some(v),
        Err(e) => {
            debug_log(debug, &format!("check failed: {e}"));
            None
        }
    };

    if let Some(v) = &fetched {
        let mut state = core_update::load_state();
        state.last_check_at = Some(core_update::unix_now());
        state.latest_seen = Some(v.to_string());
        if let Err(e) = core_update::save_state(&state).await {
            debug_log(debug, &format!("could not persist update state: {e}"));
        }
    }
    fetched
}

/// The channel-aware upgrade command for the notice's second line —
/// pointing an npm-installed user at `--update` would only route them into
/// its managed-install refusal.
fn upgrade_command() -> &'static str {
    let channel = core_update::resolve_install_path()
        .map(|p| detect_channel(&p, &ChannelEnv::from_env()))
        .unwrap_or(InstallChannel::Standalone);
    upgrade_hint(channel)
}

/// Render the two-line notice. Pure for unit tests.
fn format_notice(
    current: &semver::Version,
    latest: &semver::Version,
    hint: &str,
    use_color: bool,
) -> String {
    let new_version = output::color(&latest.to_string(), "32", use_color);
    format!(
        "[socket-patch] Update available: {current} \u{2192} {new_version}\n\
         [socket-patch] Run `{hint}` to upgrade (set SOCKET_NO_UPDATE_CHECK=1 to hide)"
    )
}

/// Join the background fetch within the grace budget and print the notice
/// if one is warranted. Runs after all command output; never touches
/// stdout or the exit code.
pub async fn finish(notifier: Option<Notifier>) {
    let Some(notifier) = notifier else {
        return;
    };
    let fetched = match notifier.task {
        Some(handle) => {
            match tokio::time::timeout(Duration::from_millis(500), handle).await {
                Ok(Ok(result)) => result,
                // Timed out (the task keeps running until process exit —
                // its own state write may still land) or panicked; either
                // way fall back to the cached value.
                Ok(Err(_)) | Err(_) => {
                    debug_log(notifier.debug, "check missed the grace budget; will retry");
                    None
                }
            }
        }
        None => None,
    };

    let latest_known = fetched.or(notifier.cached_latest);
    let Some(latest) = latest_known else {
        return;
    };
    let current = core_update::current_version();
    if !is_newer(&latest, &current) {
        return;
    }
    let now = core_update::unix_now();
    if !core_update::notice_is_due(notifier.last_notified_at, now) {
        debug_log(notifier.debug, "update pending but notice already shown today");
        return;
    }

    eprintln!(
        "{}",
        format_notice(&current, &latest, upgrade_command(), output::stderr_is_tty())
    );

    let mut state = core_update::load_state();
    state.last_notified_at = Some(now);
    if let Err(e) = core_update::save_state(&state).await {
        debug_log(notifier.debug, &format!("could not persist notice time: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_ctx() -> GuardCtx {
        GuardCtx {
            opted_out: false,
            offline: false,
            silent: false,
            json: false,
            ci: false,
            stderr_tty: true,
            forced: false,
            state_dir_resolvable: true,
        }
    }

    #[test]
    fn guard_precedence_table() {
        // (mutation, expected outcome) — the full precedence contract in
        // one table. e2e spot-checks a subset of rows end-to-end.
        let cases: &[(&str, fn(&mut GuardCtx), Result<(), SkipReason>)] = &[
            ("all open", |_| {}, Ok(())),
            ("opt-out", |c| c.opted_out = true, Err(SkipReason::OptedOut)),
            (
                "opt-out beats force",
                |c| {
                    c.opted_out = true;
                    c.forced = true;
                },
                Err(SkipReason::OptedOut),
            ),
            ("offline", |c| c.offline = true, Err(SkipReason::Offline)),
            (
                "offline beats force",
                |c| {
                    c.offline = true;
                    c.forced = true;
                },
                Err(SkipReason::Offline),
            ),
            ("silent", |c| c.silent = true, Err(SkipReason::Silent)),
            ("json", |c| c.json = true, Err(SkipReason::Json)),
            (
                "json beats force",
                |c| {
                    c.json = true;
                    c.forced = true;
                },
                Err(SkipReason::Json),
            ),
            ("ci", |c| c.ci = true, Err(SkipReason::Ci)),
            (
                "ci beats force — force bypasses ONLY the TTY guard",
                |c| {
                    c.ci = true;
                    c.forced = true;
                },
                Err(SkipReason::Ci),
            ),
            ("no tty", |c| c.stderr_tty = false, Err(SkipReason::NotATty)),
            (
                "force bypasses the tty guard",
                |c| {
                    c.stderr_tty = false;
                    c.forced = true;
                },
                Ok(()),
            ),
            (
                "no state dir",
                |c| c.state_dir_resolvable = false,
                Err(SkipReason::NoStateDir),
            ),
        ];
        for (name, mutate, expected) in cases {
            let mut ctx = open_ctx();
            mutate(&mut ctx);
            assert_eq!(&should_check(&ctx), expected, "case: {name}");
        }
    }

    #[test]
    fn notice_names_versions_hint_and_optout() {
        let current = semver::Version::new(3, 3, 0);
        let latest = semver::Version::new(3, 4, 0);
        let plain = format_notice(&current, &latest, "socket-patch --update", false);
        assert!(plain.contains("3.3.0"), "{plain}");
        assert!(plain.contains("3.4.0"), "{plain}");
        assert!(plain.contains("socket-patch --update"), "{plain}");
        assert!(plain.contains("SOCKET_NO_UPDATE_CHECK=1"), "{plain}");
        assert!(
            !plain.contains("\u{1b}["),
            "no ANSI codes without a terminal: {plain}"
        );
        let colored = format_notice(&current, &latest, "socket-patch --update", true);
        assert!(colored.contains("\u{1b}["), "{colored}");
        // Two lines, both stderr-prefixed for grep-ability.
        for line in plain.lines() {
            assert!(line.starts_with("[socket-patch]"), "{line}");
        }
        assert_eq!(plain.lines().count(), 2);
    }
}
