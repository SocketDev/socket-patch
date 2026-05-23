//! Integration coverage for `utils::telemetry`'s pub helpers
//! (`is_telemetry_disabled`, `sanitize_error_message`). These are
//! exposed for tests + future external callers; the apply/scan
//! suites never invoke them directly, so the env-var-branch logic
//! and the home-dir redaction were uncovered.

use serial_test::serial;
use socket_patch_core::utils::telemetry::{is_telemetry_disabled, sanitize_error_message};

#[test]
#[serial]
fn telemetry_disabled_when_socket_telemetry_disabled_eq_1() {
    let prev = std::env::var("SOCKET_TELEMETRY_DISABLED").ok();
    let prev_vitest = std::env::var("VITEST").ok();
    std::env::remove_var("VITEST");
    std::env::set_var("SOCKET_TELEMETRY_DISABLED", "1");
    assert!(is_telemetry_disabled(), "1 must disable telemetry");
    std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
    if let Some(v) = prev {
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", v);
    }
    if let Some(v) = prev_vitest {
        std::env::set_var("VITEST", v);
    }
}

#[test]
#[serial]
fn telemetry_disabled_when_socket_telemetry_disabled_eq_true() {
    let prev = std::env::var("SOCKET_TELEMETRY_DISABLED").ok();
    let prev_vitest = std::env::var("VITEST").ok();
    std::env::remove_var("VITEST");
    std::env::set_var("SOCKET_TELEMETRY_DISABLED", "true");
    assert!(is_telemetry_disabled(), "'true' must disable telemetry");
    std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
    if let Some(v) = prev {
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", v);
    }
    if let Some(v) = prev_vitest {
        std::env::set_var("VITEST", v);
    }
}

#[test]
#[serial]
fn telemetry_disabled_when_vitest_env_is_true() {
    let prev = std::env::var("SOCKET_TELEMETRY_DISABLED").ok();
    let prev_vitest = std::env::var("VITEST").ok();
    std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
    std::env::set_var("VITEST", "true");
    assert!(is_telemetry_disabled(), "VITEST=true must disable telemetry");
    std::env::remove_var("VITEST");
    if let Some(v) = prev {
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", v);
    }
    if let Some(v) = prev_vitest {
        std::env::set_var("VITEST", v);
    }
}

#[test]
#[serial]
fn telemetry_disabled_legacy_socket_patch_var_honored() {
    let prev = std::env::var("SOCKET_TELEMETRY_DISABLED").ok();
    let prev_legacy = std::env::var("SOCKET_PATCH_TELEMETRY_DISABLED").ok();
    let prev_vitest = std::env::var("VITEST").ok();
    std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
    std::env::remove_var("VITEST");
    std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", "1");
    assert!(is_telemetry_disabled(), "legacy var must still work");
    std::env::remove_var("SOCKET_PATCH_TELEMETRY_DISABLED");
    if let Some(v) = prev {
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", v);
    }
    if let Some(v) = prev_legacy {
        std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", v);
    }
    if let Some(v) = prev_vitest {
        std::env::set_var("VITEST", v);
    }
}

#[test]
fn sanitize_error_message_without_home_returns_unchanged() {
    // No home substring means no replacement happens.
    let msg = "some error message with no home directory in it";
    let out = sanitize_error_message(msg);
    assert_eq!(out, msg);
}

#[test]
fn sanitize_error_message_replaces_home_with_tilde() {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"));
    if let Ok(home) = home {
        if !home.is_empty() {
            let msg = format!("error at {}/.cache/socket/blob.tar.gz", home);
            let out = sanitize_error_message(&msg);
            assert!(
                !out.contains(&home),
                "sanitize must remove home dir; got {out}"
            );
            assert!(out.contains("~/"), "sanitize must use ~/ prefix; got {out}");
        }
    }
}
