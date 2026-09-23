//! Process-wide switch for core's own stderr advisories.
//!
//! Core has no view of the CLI's `--silent`/`--json` flags, so the CLI
//! sets them once after parsing via [`set_output_mode`]. Each advisory
//! prints at most once per process even when a command builds several API
//! clients, and is muted according to its [`Notice`] level:
//!
//! - [`Notice::Info`] (the public-proxy notice, the multiple-orgs note):
//!   muted by `--silent` or `--json`.
//! - [`Notice::Warning`] (token-shape and org auto-detect warnings): muted
//!   only by `--silent`. `--json` keeps stdout machine-readable but still
//!   shows warnings on stderr (CLI_CONTRACT: `--silent` is errors only),
//!   so a CI run with a misconfigured token still says why.

use std::sync::atomic::{AtomicBool, Ordering};

static SILENT: AtomicBool = AtomicBool::new(false);
static JSON: AtomicBool = AtomicBool::new(false);

/// How loud an advisory is; decides which output modes mute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Notice {
    /// Informational; muted by `--silent` or `--json`.
    Info,
    /// Something is likely misconfigured; muted only by `--silent`.
    Warning,
}

/// Record the process's `--silent`/`--json` mode for the rest of the run.
pub fn set_output_mode(silent: bool, json: bool) {
    SILENT.store(silent, Ordering::Relaxed);
    JSON.store(json, Ordering::Relaxed);
}

/// Whether informational output is suppressed (`--silent` or `--json`).
pub fn is_quiet() -> bool {
    SILENT.load(Ordering::Relaxed) || JSON.load(Ordering::Relaxed)
}

/// Whether an advisory of `level` is suppressed in the current mode.
pub(crate) fn is_muted(level: Notice) -> bool {
    match level {
        Notice::Info => is_quiet(),
        Notice::Warning => SILENT.load(Ordering::Relaxed),
    }
}

/// Print `msg()` to stderr unless `level` is muted or `shown` already
/// fired. The message is built lazily so a suppressed advisory costs
/// nothing, and a muted call does not consume the once.
pub(crate) fn notice_once(level: Notice, shown: &AtomicBool, msg: impl FnOnce() -> String) {
    if is_muted(level) {
        return;
    }
    if !shown.swap(true, Ordering::Relaxed) {
        eprintln!("{}", msg());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether `notice_once` built (and so printed) its message.
    fn fires(level: Notice, shown: &AtomicBool) -> bool {
        let mut fired = false;
        notice_once(level, shown, || {
            fired = true;
            String::new()
        });
        fired
    }

    #[test]
    fn notice_once_fires_once_and_respects_mode() {
        // Only this test touches the mode switches in core's unit tests.
        let info = AtomicBool::new(false);
        let warn = AtomicBool::new(false);

        // --silent mutes both levels without consuming the once.
        set_output_mode(true, false);
        assert!(!fires(Notice::Info, &info), "silent mutes info");
        assert!(!fires(Notice::Warning, &warn), "silent mutes warnings");
        assert!(!info.load(Ordering::Relaxed) && !warn.load(Ordering::Relaxed));

        // --json mutes info but still shows warnings, once.
        set_output_mode(false, true);
        assert!(is_quiet());
        assert!(!fires(Notice::Info, &info), "json mutes info");
        assert!(fires(Notice::Warning, &warn), "json keeps warnings");
        assert!(!fires(Notice::Warning, &warn), "warning fires once");

        // Neither: info fires, once.
        set_output_mode(false, false);
        assert!(!is_quiet());
        assert!(fires(Notice::Info, &info));
        assert!(!fires(Notice::Info, &info));
    }
}
