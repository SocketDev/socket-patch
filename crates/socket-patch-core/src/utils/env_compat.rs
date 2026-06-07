//! Legacy → new env-var compatibility shim.
//!
//! The v3.0 CLI surface migrated three env vars from the `SOCKET_PATCH_*`
//! prefix to the unified `SOCKET_*` prefix:
//!
//! | New                          | Legacy                              |
//! |------------------------------|-------------------------------------|
//! | `SOCKET_PROXY_URL`           | `SOCKET_PATCH_PROXY_URL`            |
//! | `SOCKET_DEBUG`               | `SOCKET_PATCH_DEBUG`                |
//! | `SOCKET_TELEMETRY_DISABLED`  | `SOCKET_PATCH_TELEMETRY_DISABLED`   |
//!
//! `read_env_with_legacy` reads the new name; if absent, it falls back to the
//! legacy name and prints a one-shot deprecation warning to stderr. The
//! warning fires **unconditionally** — even under `--silent` / `--json` — so
//! users see the transition signal in scripts and CI logs. The legacy names
//! will be removed in the next major release.

use std::collections::HashSet;
use std::sync::Mutex;

use once_cell::sync::Lazy;

/// Names of legacy env vars that have already warned in this process. Used
/// so each legacy var warns at most once per invocation, even when read
/// from multiple call sites.
static WARNED: Lazy<Mutex<HashSet<&'static str>>> = Lazy::new(|| Mutex::new(HashSet::new()));

/// Read the new-style env var `new_name`. If absent, fall back to
/// `legacy_name` and print a one-shot deprecation warning to stderr (the
/// warning fires regardless of CLI verbosity flags so users notice the
/// transition).
///
/// Returns `None` when neither name is set (or both are set to an empty
/// string, matching the prior call sites' filtering).
pub fn read_env_with_legacy(new_name: &'static str, legacy_name: &'static str) -> Option<String> {
    if let Ok(v) = std::env::var(new_name) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    match std::env::var(legacy_name) {
        Ok(v) if !v.is_empty() => {
            warn_legacy_once(legacy_name, new_name);
            Some(v)
        }
        _ => None,
    }
}

/// Print a one-shot deprecation warning. Public so callers that read the
/// legacy name through other code paths (e.g. clap's `env =` attribute,
/// which reads only the new name) can still surface the deprecation when
/// they detect the legacy name was set.
pub fn warn_legacy_once(legacy_name: &'static str, new_name: &'static str) {
    let mut warned = match WARNED.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    if warned.insert(legacy_name) {
        eprintln!(
            "[socket-patch] warning: env var `{legacy_name}` is deprecated; \
             use `{new_name}` instead. The legacy name will be removed in a \
             future major release."
        );
    }
}

/// Renamed env vars whose legacy `SOCKET_PATCH_*` names are still honored.
///
/// First entry of each tuple is the new name (what clap and current code
/// read); second is the legacy name that gets a deprecation warning.
pub const LEGACY_ENV_RENAMES: &[(&str, &str)] = &[
    ("SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"),
    ("SOCKET_DEBUG", "SOCKET_PATCH_DEBUG"),
    (
        "SOCKET_TELEMETRY_DISABLED",
        "SOCKET_PATCH_TELEMETRY_DISABLED",
    ),
];

/// Promote legacy `SOCKET_PATCH_*` env vars to their new `SOCKET_*` names
/// in-process. When the new name is unset and the legacy name is set, copy
/// the value over and emit a one-shot deprecation warning to stderr.
///
/// Call this *once*, very early in `main`, before clap parses. After
/// promotion every downstream reader (clap `env =`, core code) only needs
/// to know the new name.
///
/// The warning fires unconditionally — even under `--silent` / `--json`
/// — so the transition signal isn't swallowed in CI logs.
pub fn promote_legacy_env_vars() {
    promote_renames(LEGACY_ENV_RENAMES);
}

/// Core of [`promote_legacy_env_vars`], parameterized over the rename table so
/// it can be exercised in tests with isolated env-var names (the real names are
/// read concurrently by other tests in this binary).
fn promote_renames(renames: &[(&'static str, &'static str)]) {
    for &(new_name, legacy_name) in renames {
        let new_already_set = std::env::var(new_name)
            .ok()
            .filter(|v| !v.is_empty())
            .is_some();
        if new_already_set {
            continue;
        }
        if let Ok(value) = std::env::var(legacy_name) {
            if !value.is_empty() {
                warn_legacy_once(legacy_name, new_name);
                std::env::set_var(new_name, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The warning bookkeeping is process-global, so tests must use env-var
    /// names that no other test touches. `std::env` serializes access behind
    /// an internal lock, so distinct names never race for memory safety; the
    /// only hazard is two tests fighting over the *same* name, which unique
    /// names avoid.
    #[test]
    fn warn_legacy_once_fires_only_once_per_name() {
        let name = "SOCKET_TEST_LEGACY_ONCE_PATCH";
        let new = "SOCKET_TEST_LEGACY_ONCE";
        warn_legacy_once(name, new);
        warn_legacy_once(name, new);
        // The dedup is driven by `HashSet::insert` returning `false` once the
        // name has been recorded. Prove that directly: after `warn_legacy_once`
        // ran, re-inserting the same name must report "already present", which
        // is exactly what suppresses any second eprintln.
        let mut warned = WARNED.lock().unwrap();
        assert!(warned.contains(name));
        assert!(
            !warned.insert(name),
            "name should already be recorded, so a second warning is suppressed"
        );
    }

    #[test]
    fn read_env_prefers_new_var_over_legacy() {
        const NEW: &str = "SOCKET_TEST_READ_PREFERS_NEW";
        const LEGACY: &str = "SOCKET_TEST_READ_PREFERS_NEW_PATCH";
        std::env::set_var(NEW, "new-value");
        std::env::set_var(LEGACY, "legacy-value");
        assert_eq!(
            read_env_with_legacy(NEW, LEGACY),
            Some("new-value".to_string())
        );
        std::env::remove_var(NEW);
        std::env::remove_var(LEGACY);
    }

    #[test]
    fn read_env_falls_back_to_legacy_when_new_unset() {
        const NEW: &str = "SOCKET_TEST_READ_FALLBACK_NEW";
        const LEGACY: &str = "SOCKET_TEST_READ_FALLBACK_NEW_PATCH";
        std::env::remove_var(NEW);
        std::env::set_var(LEGACY, "legacy-value");
        assert_eq!(
            read_env_with_legacy(NEW, LEGACY),
            Some("legacy-value".to_string())
        );
        std::env::remove_var(LEGACY);
    }

    /// Regression: an empty new var must be treated as "unset" and fall back to
    /// the legacy name, matching the prior call sites' `!is_empty()` filtering.
    #[test]
    fn read_env_empty_new_falls_back_to_legacy() {
        const NEW: &str = "SOCKET_TEST_READ_EMPTY_NEW";
        const LEGACY: &str = "SOCKET_TEST_READ_EMPTY_NEW_PATCH";
        std::env::set_var(NEW, "");
        std::env::set_var(LEGACY, "legacy-value");
        assert_eq!(
            read_env_with_legacy(NEW, LEGACY),
            Some("legacy-value".to_string())
        );
        std::env::remove_var(NEW);
        std::env::remove_var(LEGACY);
    }

    #[test]
    fn read_env_none_when_neither_set() {
        const NEW: &str = "SOCKET_TEST_READ_NONE_NEW";
        const LEGACY: &str = "SOCKET_TEST_READ_NONE_NEW_PATCH";
        std::env::remove_var(NEW);
        std::env::remove_var(LEGACY);
        assert_eq!(read_env_with_legacy(NEW, LEGACY), None);
    }

    /// Regression: both names set but empty → `None` (empty == unset on both
    /// sides), per the documented contract.
    #[test]
    fn read_env_none_when_both_empty() {
        const NEW: &str = "SOCKET_TEST_READ_BOTH_EMPTY_NEW";
        const LEGACY: &str = "SOCKET_TEST_READ_BOTH_EMPTY_NEW_PATCH";
        std::env::set_var(NEW, "");
        std::env::set_var(LEGACY, "");
        assert_eq!(read_env_with_legacy(NEW, LEGACY), None);
        std::env::remove_var(NEW);
        std::env::remove_var(LEGACY);
    }

    /// `promote_renames` copies a set legacy value over to the unset new name,
    /// so downstream readers (clap `env =`, core code) only need the new name.
    #[test]
    fn promote_copies_legacy_to_new_when_new_unset() {
        const NEW: &str = "SOCKET_TEST_PROMOTE_COPY_NEW";
        const LEGACY: &str = "SOCKET_TEST_PROMOTE_COPY_NEW_PATCH";
        std::env::remove_var(NEW);
        std::env::set_var(LEGACY, "legacy-value");
        promote_renames(&[(NEW, LEGACY)]);
        assert_eq!(std::env::var(NEW).ok().as_deref(), Some("legacy-value"));
        std::env::remove_var(NEW);
        std::env::remove_var(LEGACY);
    }

    /// A non-empty new value must win: promote must not clobber it with the
    /// legacy value.
    #[test]
    fn promote_does_not_clobber_existing_new() {
        const NEW: &str = "SOCKET_TEST_PROMOTE_KEEP_NEW";
        const LEGACY: &str = "SOCKET_TEST_PROMOTE_KEEP_NEW_PATCH";
        std::env::set_var(NEW, "new-value");
        std::env::set_var(LEGACY, "legacy-value");
        promote_renames(&[(NEW, LEGACY)]);
        assert_eq!(std::env::var(NEW).ok().as_deref(), Some("new-value"));
        std::env::remove_var(NEW);
        std::env::remove_var(LEGACY);
    }

    /// An empty new value counts as unset, so the legacy value is promoted in
    /// over it — mirroring `read_env_with_legacy`'s empty-is-unset rule.
    #[test]
    fn promote_treats_empty_new_as_unset() {
        const NEW: &str = "SOCKET_TEST_PROMOTE_EMPTY_NEW";
        const LEGACY: &str = "SOCKET_TEST_PROMOTE_EMPTY_NEW_PATCH";
        std::env::set_var(NEW, "");
        std::env::set_var(LEGACY, "legacy-value");
        promote_renames(&[(NEW, LEGACY)]);
        assert_eq!(std::env::var(NEW).ok().as_deref(), Some("legacy-value"));
        std::env::remove_var(NEW);
        std::env::remove_var(LEGACY);
    }

    /// An empty legacy value is not promoted (empty == unset on the legacy
    /// side too), leaving the new name untouched.
    #[test]
    fn promote_ignores_empty_legacy() {
        const NEW: &str = "SOCKET_TEST_PROMOTE_EMPTY_LEGACY_NEW";
        const LEGACY: &str = "SOCKET_TEST_PROMOTE_EMPTY_LEGACY_NEW_PATCH";
        std::env::remove_var(NEW);
        std::env::set_var(LEGACY, "");
        promote_renames(&[(NEW, LEGACY)]);
        assert_eq!(std::env::var(NEW).ok(), None);
        std::env::remove_var(LEGACY);
    }
}
