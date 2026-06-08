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

    /// The heal rewrites `cargo-patches/`, so the guard must NOT watch its own
    /// output (that would re-run on every build); and it watches the resolved
    /// `Cargo.lock`, not `Cargo.toml`. Pins these against an over-eager edit.
    #[test]
    fn rerun_keys_watch_inputs_not_outputs() {
        let keys = rerun_keys("/proj");
        assert!(
            !keys.iter().any(|k| k.contains("cargo-patches")),
            "must not watch the heal's own output dir (would loop): {keys:?}"
        );
        assert!(
            !keys.iter().any(|k| k.ends_with("/Cargo.toml")),
            "watches the resolved lockfile, not the manifest: {keys:?}"
        );
    }

    #[test]
    fn rerun_keys_also_watches_bin_env_and_has_no_extras() {
        // The guard reads SOCKET_PATCH_BIN too, so a change to it must re-run the
        // probe. The original test only `any`-checked 3 of the 4 keys, so dropping
        // this one would have slipped through — pin it explicitly + pin the count.
        let keys = rerun_keys("/proj");
        assert!(
            keys.iter()
                .any(|k| k == "cargo:rerun-if-env-changed=SOCKET_PATCH_BIN"),
            "{keys:?}"
        );
        assert_eq!(keys.len(), 4, "unexpected rerun key set: {keys:?}");
    }

    #[test]
    fn check_is_read_only_and_apply_heals() {
        // The single safety-critical difference between the probe and the heal is
        // `--check` (read-only audit) vs no `--check` (mutating regenerate). Pin
        // that the probe carries it and the heal does NOT — swapping them would
        // either never heal or mutate during the read-only verify.
        assert!(check_args("/proj").iter().any(|a| a == "--check"));
        assert!(!apply_args("/proj").iter().any(|a| a == "--check"));
        // Both must stay cargo-scoped and offline regardless.
        for args in [check_args("/proj"), apply_args("/proj")] {
            assert!(args.iter().any(|a| a == "--offline"), "{args:?}");
            assert!(args.windows(2).any(|w| w == ["--ecosystems", "cargo"]), "{args:?}");
            assert!(args.windows(2).any(|w| w == ["--cwd", "/proj"]), "{args:?}");
        }
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

    /// The probe and heal must differ by EXACTLY `--check` — same ecosystem
    /// scope, offline flag, and cwd. Complements `check_is_read_only_and_apply_heals`
    /// (which checks presence) by pinning that nothing else diverges.
    #[test]
    fn probe_and_heal_differ_only_by_check() {
        let probe_without_check: Vec<String> = check_args("/proj")
            .into_iter()
            .filter(|a| a != "--check")
            .collect();
        assert_eq!(probe_without_check, apply_args("/proj"));
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

    #[test]
    fn probe_error_message_is_consistent_initial_and_after_heal() {
        // A CLI that can't run must produce the SAME diagnostic whether it fails
        // the initial probe or the re-probe after a heal — both route through the
        // one helper. Guards against the two messages drifting apart.
        let initial = match decide_initial(&Probe::ProbeError("zap".to_string())) {
            Action::Fail(m) => m,
            other => panic!("probe error must fail-closed, got {other:?}"),
        };
        let after_heal = fail_message_after_heal(&Probe::ProbeError("zap".to_string()), "");
        assert_eq!(initial, after_heal);
    }

    #[test]
    fn after_heal_drift_omits_detail_when_blank() {
        // A blank / whitespace-only detail must not produce a dangling "detail:"
        // line with nothing after it.
        let m = fail_message_after_heal(&Probe::Drift, "   \n  ");
        assert!(m.contains("could NOT be reconciled"), "{m}");
        assert!(!m.contains("detail:"), "blank detail must be dropped: {m}");
    }

    #[test]
    fn after_heal_in_sync_ignores_detail() {
        // The "regenerated, re-run" path describes a successful heal; probe output
        // (relevant only to the unrecoverable Drift case) must not leak into it.
        let m = fail_message_after_heal(&Probe::InSync, "stale copy of foo@1.2.3");
        assert!(!m.contains("stale copy of foo@1.2.3"), "{m}");
    }

    #[test]
    fn after_heal_drift_trims_surrounding_whitespace_from_detail() {
        // Non-blank detail is surfaced on its own line, trimmed — no trailing
        // blank after "detail:" and no leading indentation from the CLI output.
        let m = fail_message_after_heal(&Probe::Drift, "  cargo: drift on serde \n");
        assert!(m.contains("\n  detail: cargo: drift on serde"), "{m}");
        assert!(!m.contains("detail:  "), "leading whitespace must be trimmed: {m}");
        assert!(!m.ends_with(' ') && !m.ends_with('\n'), "trailing whitespace: {m:?}");
    }
}
