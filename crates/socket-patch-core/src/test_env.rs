//! The one restore-on-drop guard the tests use to change process env. The
//! integration tests that need it compile this same file in with
//! `#[path = "../src/test_env.rs"]`. Env is process-global, so every user
//! must also be `#[serial_test::serial]`.

use std::ffi::{OsStr, OsString};

/// Sets or removes env vars and puts the previous values back on drop, a
/// panicking assertion included. Previous values are kept as `OsString`,
/// so a non-UTF-8 value survives the round trip.
#[must_use = "the variables are restored when the guard drops"]
pub(crate) struct EnvGuard {
    saved: Vec<(OsString, Option<OsString>)>,
}

impl EnvGuard {
    pub(crate) fn set(key: &str, value: impl AsRef<OsStr>) -> Self {
        Self::many([(key, Some(value))])
    }

    pub(crate) fn unset(key: &str) -> Self {
        Self::many([(key, None::<&str>)])
    }

    /// Applies each pair in order: `Some` sets the var, `None` removes it.
    pub(crate) fn many<K, V>(pairs: impl IntoIterator<Item = (K, Option<V>)>) -> Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        // Saved before each change, so a panic partway through (a key with
        // `=` in it) still restores the vars already changed.
        let mut guard = Self { saved: Vec::new() };
        for (key, value) in pairs {
            let key = key.as_ref();
            guard
                .saved
                .push((key.to_os_string(), std::env::var_os(key)));
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        guard
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // Newest first, so a key listed twice ends at its original value.
        while let Some((key, prev)) = self.saved.pop() {
            match prev {
                Some(v) => std::env::set_var(&key, v),
                None => std::env::remove_var(&key),
            }
        }
    }
}

/// Runs `f` with `pairs` applied (`None` removes the var), then restores
/// them, even if `f` panics.
pub(crate) fn with_env<T>(pairs: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
    let _env = EnvGuard::many(pairs.iter().copied());
    f()
}
