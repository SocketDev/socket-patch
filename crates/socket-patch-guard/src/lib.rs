//! `socket-patch-guard` — a tiny build-time guard crate.
//!
//! Add it under your crate's `[dependencies]` (via `socket-patch setup`) and
//! cargo will compile it and run its [`build script`](../build.rs) on every
//! `build` / `test` / `check` / `install`. The build script is a cached no-op
//! until the dependency set (`Cargo.lock`) or patch set
//! (`.socket/manifest.json`) changes, at which point it re-runs
//! `socket-patch apply --offline --ecosystems cargo` to regenerate the
//! project-local patched-crate copies under `.socket/cargo-patches/`.
//!
//! The library itself is intentionally empty — it exists only so the build
//! script runs in the consumer's graph. The decision logic lives in
//! [`logic`] (shared with `build.rs` via `include!`) so it can be unit-tested.

mod logic;
pub use logic::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_skips_when_root_unset_or_empty() {
        assert_eq!(plan(None, None), Plan::SkipRootUnset);
        assert_eq!(plan(Some(""), Some("x")), Plan::SkipRootUnset);
    }

    #[test]
    fn plan_runs_with_default_bin() {
        assert_eq!(
            plan(Some("/proj"), None),
            Plan::Run {
                root: "/proj".to_string(),
                bin: "socket-patch".to_string()
            }
        );
        // Empty bin falls back to the default too.
        assert_eq!(
            plan(Some("/proj"), Some("")),
            Plan::Run {
                root: "/proj".to_string(),
                bin: "socket-patch".to_string()
            }
        );
    }

    #[test]
    fn plan_honours_explicit_bin() {
        assert_eq!(
            plan(Some("/proj"), Some("/usr/local/bin/socket-patch")),
            Plan::Run {
                root: "/proj".to_string(),
                bin: "/usr/local/bin/socket-patch".to_string()
            }
        );
    }

    #[test]
    fn rerun_keys_name_lockfile_and_manifest() {
        let keys = rerun_keys("/proj");
        assert!(keys
            .iter()
            .any(|k| k == "cargo:rerun-if-env-changed=SOCKET_PATCH_ROOT"));
        assert!(keys
            .iter()
            .any(|k| k == "cargo:rerun-if-changed=/proj/Cargo.lock"));
        assert!(keys
            .iter()
            .any(|k| k == "cargo:rerun-if-changed=/proj/.socket/manifest.json"));
    }

    #[test]
    fn apply_args_are_offline_cargo_scoped() {
        assert_eq!(
            apply_args("/proj"),
            vec![
                "apply",
                "--offline",
                "--ecosystems",
                "cargo",
                "--cwd",
                "/proj"
            ]
        );
    }

    #[test]
    fn check_args_are_readonly_offline_cargo_scoped() {
        assert_eq!(
            check_args("/proj"),
            vec![
                "apply",
                "--check",
                "--offline",
                "--ecosystems",
                "cargo",
                "--cwd",
                "/proj"
            ]
        );
    }

    #[test]
    fn guard_mode_defaults_to_error() {
        assert_eq!(guard_mode(None), GuardMode::Error);
        assert_eq!(guard_mode(Some("1")), GuardMode::Error);
        assert_eq!(guard_mode(Some("error")), GuardMode::Error);
        assert_eq!(guard_mode(Some("warn")), GuardMode::Warn);
        assert_eq!(guard_mode(Some("off")), GuardMode::Off);
    }

    #[test]
    fn decide_in_sync_always_proceeds() {
        for mode in [GuardMode::Error, GuardMode::Warn, GuardMode::Off] {
            assert_eq!(decide(&CheckOutcome::InSync, mode), Action::Proceed);
        }
    }

    #[test]
    fn decide_drift_fails_closed_by_default() {
        // The core fix: drift in the default (Error) mode FAILS the build.
        assert!(matches!(
            decide(&CheckOutcome::Drift, GuardMode::Error),
            Action::Fail(_)
        ));
    }

    #[test]
    fn decide_drift_in_warn_heals_and_continues_not_panics() {
        // Pins the bug the old `interpret` had (Failed always panicked):
        // warn mode must NOT fail on drift — it heals and continues.
        assert!(matches!(
            decide(&CheckOutcome::Drift, GuardMode::Warn),
            Action::HealAndWarn(_)
        ));
    }

    #[test]
    fn decide_probe_failure_respects_mode() {
        let pf = CheckOutcome::ProbeFailed("no such file".to_string());
        assert!(matches!(decide(&pf, GuardMode::Error), Action::Fail(_)));
        assert!(matches!(decide(&pf, GuardMode::Warn), Action::Warn(_)));
    }
}
