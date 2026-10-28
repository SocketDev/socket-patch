//! The cargo home cargo itself would use: `$CARGO_HOME`, else
//! `<home>/.cargo` with `<home>` resolved the way cargo's `home` crate
//! resolves it.
//!
//! [`super::fs::home_dir`] reads only `HOME` / `USERPROFILE`, but cargo
//! falls back to the account's passwd entry on Unix when `HOME` is unset
//! (`env -i`, systemd units, stripped CI and container entrypoints). A
//! crawler that stopped at `home_dir` probed no registry cache there and
//! reported the crate lockfile-only while cargo built the unpatched copy
//! from the passwd home's `~/.cargo` (#1135). Every cargo-home reader (the
//! crawler, the `[patch]` config chain, the build-cache cleaner) goes
//! through [`cargo_home`] so they agree with cargo and with each other.

use std::ffi::OsString;
use std::path::PathBuf;

/// The process's cargo home: `$CARGO_HOME` when set and non-blank, else
/// `<home>/.cargo`, where `<home>` is `HOME` / `USERPROFILE` and then, on
/// Unix, the passwd entry. `None` when none of them names a directory.
pub fn cargo_home() -> Option<PathBuf> {
    resolve(
        std::env::var_os("CARGO_HOME"),
        super::fs::home_dir(),
        crate::crawlers::gradle_cache::passwd_home,
    )
}

/// [`cargo_home`] over an injected `CARGO_HOME`, env home and passwd home
/// (only consulted when the first two give nothing).
fn resolve(
    cargo_home_var: Option<OsString>,
    env_home: Option<PathBuf>,
    passwd_home: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    // An empty value means unset (the env_non_empty convention):
    // `PathBuf::from("")` would resolve `registry/src` against the CWD.
    if let Some(v) = cargo_home_var.filter(|v| !v.to_string_lossy().trim().is_empty()) {
        return Some(PathBuf::from(v));
    }
    env_home
        .or_else(|| passwd_home().filter(|h| super::fs::is_usable_home(h)))
        .map(|home| home.join(".cargo"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_passwd() -> Option<PathBuf> {
        None
    }

    #[test]
    fn cargo_home_var_wins() {
        let got = resolve(Some("/opt/cargo".into()), Some("/home/u".into()), || {
            panic!("passwd consulted with CARGO_HOME set")
        });
        assert_eq!(got, Some(PathBuf::from("/opt/cargo")));
    }

    #[test]
    fn blank_cargo_home_var_is_unset() {
        let got = resolve(Some("  ".into()), Some("/home/u".into()), no_passwd);
        assert_eq!(got, Some(PathBuf::from("/home/u/.cargo")));
    }

    #[test]
    fn env_home_wins_over_passwd() {
        let got = resolve(None, Some("/home/u".into()), || {
            Some("/var/lib/other".into())
        });
        assert_eq!(got, Some(PathBuf::from("/home/u/.cargo")));
    }

    /// #1135: with `HOME` and `CARGO_HOME` unset cargo builds from the
    /// passwd home's `~/.cargo`, so the crawler must probe it too.
    #[test]
    fn no_env_home_falls_back_to_passwd_home() {
        let got = resolve(None, None, || Some("/root".into()));
        assert_eq!(got, Some(PathBuf::from("/root/.cargo")));
    }

    #[test]
    fn relative_or_missing_passwd_home_is_no_home() {
        assert_eq!(resolve(None, None, || Some("rel".into())), None);
        assert_eq!(resolve(None, None, || Some(PathBuf::new())), None);
        assert_eq!(resolve(None, None, no_passwd), None);
    }

    /// #1135 through the process environment: `HOME`, `USERPROFILE` and
    /// `CARGO_HOME` all unset still finds the passwd home's `.cargo`.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn process_cargo_home_without_home_uses_passwd_entry() {
        let Some(passwd) = crate::crawlers::gradle_cache::passwd_home() else {
            return; // no passwd entry for this uid: nothing cargo could use either
        };
        let keys = ["HOME", "USERPROFILE", "CARGO_HOME"];
        let saved: Vec<_> = keys.iter().map(|k| std::env::var_os(k)).collect();
        for k in keys {
            std::env::remove_var(k);
        }
        let got = cargo_home();
        for (k, v) in keys.iter().zip(saved) {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        assert_eq!(got, Some(passwd.join(".cargo")));
    }
}
