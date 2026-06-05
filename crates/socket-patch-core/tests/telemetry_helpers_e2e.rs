//! Integration coverage for `utils::telemetry`'s pub helpers
//! (`is_telemetry_disabled`, `sanitize_error_message`). These are
//! exposed for tests + future external callers; the apply/scan
//! suites never invoke them directly, so the env-var-branch logic
//! and the home-dir redaction were uncovered.
//!
//! Hardening notes: every disable-gate test runs inside `with_clean_env`,
//! which scrubs ALL four disabling vars first. Each test then proves
//! *causation*, not mere correlation:
//!   1. clean env => NOT disabled  (kills an always-`true` impl + ambient
//!      `SOCKET_OFFLINE=1` masking the result),
//!   2. set the one var under test => disabled,
//!   3. remove it => NOT disabled again (proves THAT var was the cause and
//!      that no other ambient var was secretly carrying the assertion).

use serial_test::serial;
use socket_patch_core::utils::telemetry::{is_telemetry_disabled, sanitize_error_message};

/// Every environment variable that can independently disable telemetry.
/// Scrubbing the full set is what makes the per-var causation asserts honest.
const DISABLE_VARS: &[&str] = &[
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_PATCH_TELEMETRY_DISABLED",
    "VITEST",
    "SOCKET_OFFLINE",
];

/// Run `f` with all telemetry-disabling vars removed, restoring the prior
/// values afterward even if `f` panics (so one failing assert can't poison
/// sibling tests). The closure starts from a known-clean slate.
fn with_clean_env<T>(f: impl FnOnce() -> T) -> T {
    let saved: Vec<(&str, Option<String>)> = DISABLE_VARS
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
    for k in DISABLE_VARS {
        std::env::remove_var(k);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    match result {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e),
    }
}

/// Baseline: with nothing set, telemetry is enabled. This alone kills an
/// impl that hardcodes `true`, which would otherwise satisfy every
/// "must disable" assertion below.
#[test]
#[serial]
fn telemetry_enabled_by_default_when_no_vars_set() {
    with_clean_env(|| {
        assert!(
            !is_telemetry_disabled(),
            "clean env (no disable vars) must NOT disable telemetry"
        );
    });
}

#[test]
#[serial]
fn telemetry_disabled_when_socket_telemetry_disabled_eq_1() {
    with_clean_env(|| {
        assert!(!is_telemetry_disabled(), "baseline must be enabled");
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", "1");
        assert!(is_telemetry_disabled(), "1 must disable telemetry");
        std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
        assert!(
            !is_telemetry_disabled(),
            "removing SOCKET_TELEMETRY_DISABLED must re-enable telemetry (proves it was the cause)"
        );
    });
}

#[test]
#[serial]
fn telemetry_disabled_when_socket_telemetry_disabled_eq_true() {
    with_clean_env(|| {
        assert!(!is_telemetry_disabled(), "baseline must be enabled");
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", "true");
        assert!(is_telemetry_disabled(), "'true' must disable telemetry");
        std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
        assert!(
            !is_telemetry_disabled(),
            "removing SOCKET_TELEMETRY_DISABLED must re-enable telemetry"
        );
    });
}

/// Falsy / non-canonical values must NOT engage the gate — pins the exact
/// `"1" | "true"` match so a broadened `unwrap_or_default() != ""`-style
/// regression is caught.
#[test]
#[serial]
fn telemetry_not_disabled_when_socket_telemetry_disabled_falsy() {
    with_clean_env(|| {
        for v in ["0", "", "false", "no", "yes", "TRUE", "True"] {
            std::env::set_var("SOCKET_TELEMETRY_DISABLED", v);
            assert!(
                !is_telemetry_disabled(),
                "SOCKET_TELEMETRY_DISABLED={v:?} must NOT disable telemetry"
            );
        }
    });
}

#[test]
#[serial]
fn telemetry_disabled_when_vitest_env_is_true() {
    with_clean_env(|| {
        assert!(!is_telemetry_disabled(), "baseline must be enabled");
        std::env::set_var("VITEST", "true");
        assert!(is_telemetry_disabled(), "VITEST=true must disable telemetry");
        std::env::remove_var("VITEST");
        assert!(
            !is_telemetry_disabled(),
            "removing VITEST must re-enable telemetry"
        );
    });
}

/// VITEST is matched strictly against `"true"` (not "1"/truthy). Pin it so a
/// regression that loosens the comparison is caught.
#[test]
#[serial]
fn telemetry_not_disabled_when_vitest_is_not_literal_true() {
    with_clean_env(|| {
        for v in ["1", "", "false", "True", "TRUE", "yes"] {
            std::env::set_var("VITEST", v);
            assert!(
                !is_telemetry_disabled(),
                "VITEST={v:?} must NOT disable telemetry (only literal 'true' does)"
            );
        }
    });
}

#[test]
#[serial]
fn telemetry_disabled_legacy_socket_patch_var_honored() {
    with_clean_env(|| {
        assert!(!is_telemetry_disabled(), "baseline must be enabled");
        // Both accepted spellings of the legacy var must work on their own,
        // with the new var name absent.
        for v in ["1", "true"] {
            std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", v);
            assert!(
                std::env::var("SOCKET_TELEMETRY_DISABLED").is_err(),
                "precondition: new var must be unset so legacy is the only cause"
            );
            assert!(
                is_telemetry_disabled(),
                "legacy SOCKET_PATCH_TELEMETRY_DISABLED={v:?} must still disable"
            );
            std::env::remove_var("SOCKET_PATCH_TELEMETRY_DISABLED");
            assert!(
                !is_telemetry_disabled(),
                "removing legacy var must re-enable telemetry"
            );
        }
    });
}

#[test]
#[serial]
fn telemetry_disabled_when_socket_offline_eq_1() {
    // Airgap mode: SOCKET_OFFLINE=1 means "never contact the network",
    // so the telemetry endpoint (a network call) must be suppressed.
    with_clean_env(|| {
        assert!(!is_telemetry_disabled(), "baseline must be enabled");
        std::env::set_var("SOCKET_OFFLINE", "1");
        assert!(
            is_telemetry_disabled(),
            "SOCKET_OFFLINE=1 must disable telemetry (airgap)"
        );
        std::env::remove_var("SOCKET_OFFLINE");
        assert!(
            !is_telemetry_disabled(),
            "removing SOCKET_OFFLINE must re-enable telemetry"
        );
    });
}

#[test]
#[serial]
fn telemetry_disabled_when_socket_offline_eq_true() {
    with_clean_env(|| {
        assert!(!is_telemetry_disabled(), "baseline must be enabled");
        std::env::set_var("SOCKET_OFFLINE", "true");
        assert!(
            is_telemetry_disabled(),
            "SOCKET_OFFLINE=true must disable telemetry (airgap)"
        );
        std::env::remove_var("SOCKET_OFFLINE");
        assert!(
            !is_telemetry_disabled(),
            "removing SOCKET_OFFLINE must re-enable telemetry"
        );
    });
}

#[test]
#[serial]
fn telemetry_not_disabled_when_socket_offline_unset_or_falsy() {
    // Defensive: confirm falsy values don't accidentally engage the gate.
    with_clean_env(|| {
        for v in ["0", "", "false", "no", "TRUE", "True"] {
            std::env::set_var("SOCKET_OFFLINE", v);
            assert!(
                !is_telemetry_disabled(),
                "SOCKET_OFFLINE={v:?} must NOT engage gate"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// sanitize_error_message — home-dir redaction
//
// These set HOME to a deterministic sentinel so the test is hermetic and can
// never silently no-op on a host where HOME is unset/empty (the original
// loophole: the entire assertion body sat behind `if let Ok(home)`).
// ---------------------------------------------------------------------------

const HOME_VARS: &[&str] = &["HOME", "USERPROFILE"];

fn with_home<T>(home: &str, f: impl FnOnce() -> T) -> T {
    let saved: Vec<(&str, Option<String>)> = HOME_VARS
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
    // home_dir_string() reads HOME first, then USERPROFILE. Clear USERPROFILE
    // so HOME is unambiguously the source on every platform.
    std::env::remove_var("USERPROFILE");
    std::env::set_var("HOME", home);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    match result {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e),
    }
}

#[test]
#[serial]
fn sanitize_error_message_without_home_returns_unchanged() {
    // A message that does NOT contain the (deterministic) home prefix must be
    // returned byte-for-byte unchanged.
    with_home("/home/socket-sentinel", || {
        let msg = "some error message with no home directory in it";
        assert_eq!(sanitize_error_message(msg), msg);
    });
}

#[test]
#[serial]
fn sanitize_error_message_replaces_home_with_tilde() {
    let home = "/home/socket-sentinel";
    with_home(home, || {
        // Exact-output check (not just contains/!contains): the home prefix is
        // collapsed to `~`, the rest of the path is preserved verbatim.
        let msg = format!("error at {home}/.cache/socket/blob.tar.gz");
        assert_eq!(
            sanitize_error_message(&msg),
            "error at ~/.cache/socket/blob.tar.gz"
        );

        // Every occurrence is redacted, not just the first.
        let multi = format!("read {home}/a failed; wrote {home}/b ok");
        assert_eq!(sanitize_error_message(&multi), "read ~/a failed; wrote ~/b ok");

        // The bare home path with nothing after it is also redacted.
        assert_eq!(sanitize_error_message(home), "~");

        // Belt-and-suspenders: the raw home string must not survive anywhere.
        assert!(
            !sanitize_error_message(&msg).contains(home),
            "sanitized output must not leak the raw home path"
        );
    });
}

#[test]
#[serial]
fn sanitize_error_message_falls_back_to_userprofile() {
    // On Windows-style hosts HOME may be absent and USERPROFILE is the source.
    let saved: Vec<(&str, Option<String>)> = HOME_VARS
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
    let profile = "/Users/socket-sentinel";
    std::env::remove_var("HOME");
    std::env::set_var("USERPROFILE", profile);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let msg = format!("{profile}/AppData/blob.bin");
        assert_eq!(sanitize_error_message(&msg), "~/AppData/blob.bin");
    }));
    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}
