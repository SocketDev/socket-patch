//! Self-tests for `test_env`. They live apart from it because the
//! integration tests compile `test_env.rs` in with `#[path]`, and these
//! should run once, in the lib's unit tests.

use std::ffi::OsStr;

use crate::test_env::{with_env, EnvGuard};

const KEY: &str = "SOCKET_PATCH_TEST_ENV_GUARD_PROBE";

#[test]
#[serial_test::serial]
fn restores_set_unset_and_repeated_keys_on_drop() {
    std::env::set_var(KEY, "orig");
    {
        let _a = EnvGuard::set(KEY, "a");
        assert_eq!(std::env::var(KEY).as_deref(), Ok("a"));
        let _b = EnvGuard::many([(KEY, None::<&str>), (KEY, Some("c"))]);
        assert_eq!(std::env::var(KEY).as_deref(), Ok("c"));
    }
    assert_eq!(std::env::var(KEY).as_deref(), Ok("orig"));

    std::env::remove_var(KEY);
    drop(EnvGuard::set(KEY, "x"));
    assert_eq!(std::env::var_os(KEY), None);
}

#[test]
#[serial_test::serial]
fn with_env_restores_after_a_panic() {
    std::env::remove_var(KEY);
    let caught = std::panic::catch_unwind(|| {
        with_env(&[(KEY, Some("leak"))], || panic!("intentional panic"))
    });
    assert!(caught.is_err());
    assert_eq!(std::env::var_os(KEY), None);
}

#[cfg(unix)]
#[test]
#[serial_test::serial]
fn keeps_a_non_utf8_previous_value() {
    use std::os::unix::ffi::OsStrExt;
    let raw = OsStr::from_bytes(b"\xff\xfe");
    std::env::set_var(KEY, raw);
    drop(EnvGuard::unset(KEY));
    assert_eq!(std::env::var_os(KEY).as_deref(), Some(raw));
    std::env::remove_var(KEY);
}

#[test]
#[serial_test::serial]
fn guarded_var_sees_only_vars_a_live_guard_holds() {
    std::env::set_var(KEY, "host");
    assert_eq!(crate::test_env::guarded_var(KEY), None, "host value hidden");
    {
        let _outer = EnvGuard::set(KEY, "a");
        assert_eq!(crate::test_env::guarded_var(KEY).as_deref(), Some("a"));
        {
            let _inner = EnvGuard::unset(KEY);
            assert_eq!(crate::test_env::guarded_var(KEY), None);
        }
        // The outer guard still holds it once the inner one drops.
        assert_eq!(crate::test_env::guarded_var(KEY).as_deref(), Some("a"));
    }
    assert_eq!(crate::test_env::guarded_var(KEY), None, "released on drop");
    std::env::remove_var(KEY);
}
