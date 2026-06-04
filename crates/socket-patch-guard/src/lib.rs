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

    // ── single fail-closed mode: decide_initial ──────────────────────
    #[test]
    fn decide_initial_in_sync_proceeds() {
        assert_eq!(decide_initial(&Probe::InSync), Action::Proceed);
    }

    #[test]
    fn decide_initial_drift_heals() {
        assert_eq!(decide_initial(&Probe::Drift), Action::Heal);
    }

    #[test]
    fn decide_initial_probe_error_fails_closed() {
        // A missing/unspawnable CLI fails the build — no escape hatch.
        assert!(matches!(
            decide_initial(&Probe::ProbeError("no such file".to_string())),
            Action::Fail(_)
        ));
    }

    // ── after-heal messaging (the build always fails here) ────────────
    #[test]
    fn after_heal_in_sync_says_regenerated_and_rerun() {
        let m = fail_message_after_heal(&Probe::InSync, "");
        assert!(m.contains("regenerated") && m.to_lowercase().contains("re-run"), "{m}");
    }

    #[test]
    fn after_heal_still_drift_is_unrecoverable_and_includes_detail() {
        let m = fail_message_after_heal(&Probe::Drift, "resolved version 1.0.1");
        assert!(m.contains("could NOT be reconciled"), "{m}");
        assert!(m.contains("resolved version 1.0.1"), "detail must be surfaced: {m}");
    }

    #[test]
    fn after_heal_probe_error_reports_cli() {
        let m = fail_message_after_heal(&Probe::ProbeError("boom".to_string()), "");
        assert!(m.contains("could not run") && m.contains("boom"), "{m}");
    }
}
