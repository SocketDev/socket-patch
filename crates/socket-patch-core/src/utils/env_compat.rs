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
pub(crate) fn read_env_with_legacy(
    new_name: &'static str,
    legacy_name: &'static str,
) -> Option<String> {
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

/// Print a one-shot deprecation warning for a legacy name.
fn warn_legacy_once(legacy_name: &'static str, new_name: &'static str) {
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

/// Check if debug mode is enabled via `SOCKET_DEBUG` (with the legacy
/// `SOCKET_PATCH_DEBUG` shim).
pub(crate) fn is_debug_enabled() -> bool {
    matches!(
        read_env_with_legacy("SOCKET_DEBUG", "SOCKET_PATCH_DEBUG").as_deref(),
        Some("1" | "true")
    )
}

/// The public patch-API proxy base URL: `SOCKET_PROXY_URL` (with the legacy
/// `SOCKET_PATCH_PROXY_URL` shim), defaulting to
/// [`DEFAULT_PATCH_API_PROXY_URL`](crate::constants::DEFAULT_PATCH_API_PROXY_URL).
pub(crate) fn proxy_url_from_env() -> String {
    read_env_with_legacy("SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL")
        .unwrap_or_else(|| crate::constants::DEFAULT_PATCH_API_PROXY_URL.to_string())
}

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
    promote_renames(&[
        ("SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"),
        ("SOCKET_DEBUG", "SOCKET_PATCH_DEBUG"),
        (
            "SOCKET_TELEMETRY_DISABLED",
            "SOCKET_PATCH_TELEMETRY_DISABLED",
        ),
    ]);
}

/// Peer env-var aliases accepted from the sibling JS Socket CLI, so an
/// environment configured for `socket` (e.g. a CI job exporting
/// `SOCKET_CLI_API_TOKEN`) works for `socket-patch` unchanged.
///
/// First entry is the canonical `SOCKET_*` name (what clap and core read);
/// second is the accepted `SOCKET_CLI_*` peer name. Unlike
/// [`promote_legacy_env_vars`] these are **not** deprecated — promotion is
/// silent and the canonical name simply wins when both are set. The list is
/// deliberately tight: `SOCKET_CLI_CONFIG` (ephemeral JSON override),
/// `SOCKET_CLI_API_PROXY` (an HTTP forward proxy — reqwest already honors
/// `HTTP_PROXY`/`HTTPS_PROXY`), and `SOCKET_CLI_DEBUG` are intentionally
/// not mirrored.
pub const PEER_ENV_ALIASES: &[(&str, &str)] = &[
    ("SOCKET_API_TOKEN", "SOCKET_CLI_API_TOKEN"),
    ("SOCKET_ORG_SLUG", "SOCKET_CLI_ORG_SLUG"),
    ("SOCKET_API_URL", "SOCKET_CLI_API_BASE_URL"),
    ("SOCKET_NO_API_TOKEN", "SOCKET_CLI_NO_API_TOKEN"),
];

/// Silently copy each set-and-non-empty [`PEER_ENV_ALIASES`] value onto its
/// canonical `SOCKET_*` name when the canonical name is unset or empty.
/// Call once, early in `main`, right after [`promote_legacy_env_vars`] and
/// before the empty-var scrub / clap parse.
pub fn promote_peer_env_vars() {
    promote_aliases(PEER_ENV_ALIASES);
}

/// Core of [`promote_peer_env_vars`], parameterized over the alias table so
/// tests can use isolated env-var names.
fn promote_aliases(aliases: &[(&str, &str)]) {
    for &(canonical, alias) in aliases {
        let canonical_set = matches!(std::env::var(canonical).as_deref(), Ok(v) if !v.is_empty());
        if canonical_set {
            continue;
        }
        if let Ok(value) = std::env::var(alias) {
            if !value.is_empty() {
                std::env::set_var(canonical, value);
            }
        }
    }
}

/// Core of [`promote_legacy_env_vars`], parameterized over the rename table so
/// it can be exercised in tests with isolated env-var names (the real names are
/// read concurrently by other tests in this binary).
fn promote_renames(renames: &[(&'static str, &'static str)]) {
    for &(new_name, legacy_name) in renames {
        let new_already_set = matches!(std::env::var(new_name).as_deref(), Ok(v) if !v.is_empty());
        if new_already_set {
            continue;
        }
        // New name is unset/empty, so any value returned here came from the
        // legacy name (with the one-shot warning already emitted).
        if let Some(value) = read_env_with_legacy(new_name, legacy_name) {
            std::env::set_var(new_name, value);
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

    /// Peer-alias promotion copies a set alias onto the unset canonical
    /// name — and, unlike the legacy shim, records **no** deprecation
    /// warning (peer names are supported, not deprecated).
    #[test]
    fn peer_alias_promotes_silently_when_canonical_unset() {
        const CANONICAL: &str = "SOCKET_TEST_PEER_PROMOTE";
        const ALIAS: &str = "SOCKET_TEST_PEER_PROMOTE_CLI";
        std::env::remove_var(CANONICAL);
        std::env::set_var(ALIAS, "from-alias");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(std::env::var(CANONICAL).ok().as_deref(), Some("from-alias"));
        assert!(
            !WARNED.lock().unwrap().contains(ALIAS),
            "peer promotion must not register a deprecation warning"
        );
        std::env::remove_var(CANONICAL);
        std::env::remove_var(ALIAS);
    }

    /// The canonical name wins when both are set — the alias never clobbers.
    #[test]
    fn peer_alias_does_not_clobber_canonical() {
        const CANONICAL: &str = "SOCKET_TEST_PEER_KEEP";
        const ALIAS: &str = "SOCKET_TEST_PEER_KEEP_CLI";
        std::env::set_var(CANONICAL, "canonical-value");
        std::env::set_var(ALIAS, "alias-value");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(
            std::env::var(CANONICAL).ok().as_deref(),
            Some("canonical-value")
        );
        std::env::remove_var(CANONICAL);
        std::env::remove_var(ALIAS);
    }

    /// Empty == unset on both sides: an empty canonical is filled from the
    /// alias, and an empty alias is never promoted.
    #[test]
    fn peer_alias_treats_empty_as_unset() {
        const CANONICAL: &str = "SOCKET_TEST_PEER_EMPTY";
        const ALIAS: &str = "SOCKET_TEST_PEER_EMPTY_CLI";
        std::env::set_var(CANONICAL, "");
        std::env::set_var(ALIAS, "alias-value");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(std::env::var(CANONICAL).ok().as_deref(), Some("alias-value"));
        std::env::remove_var(CANONICAL);

        std::env::set_var(ALIAS, "");
        promote_aliases(&[(CANONICAL, ALIAS)]);
        assert_eq!(std::env::var(CANONICAL).ok(), None);
        std::env::remove_var(ALIAS);
    }
}
