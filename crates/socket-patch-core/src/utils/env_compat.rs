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

/// Read the new env var; if it isn't set, also probe the legacy name and
/// surface a deprecation warning when the legacy name is set. Returns the
/// Renamed env vars whose legacy `SOCKET_PATCH_*` names are still honored.
///
/// First entry of each tuple is the new name (what clap and current code
/// read); second is the legacy name that gets a deprecation warning.
pub const LEGACY_ENV_RENAMES: &[(&str, &str)] = &[
    ("SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"),
    ("SOCKET_DEBUG", "SOCKET_PATCH_DEBUG"),
    ("SOCKET_TELEMETRY_DISABLED", "SOCKET_PATCH_TELEMETRY_DISABLED"),
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
    for (new_name, legacy_name) in LEGACY_ENV_RENAMES {
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

    /// The warning bookkeeping is process-global, so any test that flips a
    /// real env var would race with parallel tests. Exercise the dedup
    /// path directly instead.
    #[test]
    fn warn_legacy_once_fires_only_once_per_name() {
        let name = "SOCKET_TEST_LEGACY_ONCE_PATCH";
        let new = "SOCKET_TEST_LEGACY_ONCE";
        warn_legacy_once(name, new);
        warn_legacy_once(name, new);
        let warned = WARNED.lock().unwrap();
        assert!(warned.contains(name));
    }
}
