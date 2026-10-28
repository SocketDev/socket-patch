//! The cargo home cargo itself would use: `$CARGO_HOME`, else
//! `<home>/.cargo` with `<home>` resolved the way cargo's `home` crate
//! resolves it.
//!
//! [`super::fs::home_dir`] reads only `HOME` / `USERPROFILE`, but cargo
//! falls back to the account's passwd entry on Unix when `HOME` is unset
//! (`env -i`, systemd units, stripped CI and container entrypoints). A
//! crawler that stopped at `home_dir` probed no registry cache there and
//! reported the crate lockfile-only while cargo built the unpatched copy
//! from the passwd home's `~/.cargo` (#1135). The cargo-home readers (the
//! crawler, the `[patch]` config chain, the build-cache cleaner and the
//! self-update channel check) go through [`cargo_home`] so they agree with
//! cargo and with each other.

use std::ffi::OsString;
use std::path::PathBuf;

/// The variable cargo's `home` crate reads the user home from: `HOME` on
/// Unix, `USERPROFILE` on Windows (cargo ignores the other one).
const HOME_VAR: &str = if cfg!(windows) { "USERPROFILE" } else { "HOME" };

/// The process's cargo home: `$CARGO_HOME` when set and non-blank, else
/// `<home>/.cargo`, where `<home>` is `HOME` (`USERPROFILE` on Windows) or,
/// with that variable unset on Unix, the passwd entry. `None` when none of
/// them names an absolute directory.
pub fn cargo_home() -> Option<PathBuf> {
    resolve(
        std::env::var_os("CARGO_HOME"),
        std::env::var_os(HOME_VAR),
        super::fs::passwd_home,
    )
}

/// [`cargo_home`] over an injected `CARGO_HOME`, home variable and passwd
/// home (consulted only when the home variable is unset).
fn resolve(
    cargo_home_var: Option<OsString>,
    home_var: Option<OsString>,
    passwd_home: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    // An empty value means unset (the env_non_empty convention):
    // `PathBuf::from("")` would resolve `registry/src` against the CWD.
    if let Some(v) = cargo_home_var.filter(|v| !v.to_string_lossy().trim().is_empty()) {
        return Some(PathBuf::from(v));
    }
    // A set-but-empty or relative home stays no home (see
    // `fs::home_dir`): probing it would read directories inside the
    // project, and the passwd home is not where cargo looks then either.
    let home = match home_var {
        Some(v) => Some(PathBuf::from(v)),
        None => passwd_home(),
    };
    home.filter(|h| super::fs::is_usable_home(h))
        .map(|home| home.join(".cargo"))
}

/// Removes `HOME`, `USERPROFILE` and `CARGO_HOME` from the process
/// environment until dropped, restoring them even if the test panics.
/// Users are `#[serial_test::serial]`.
#[cfg(test)]
pub(crate) struct NoHomeEnv(Vec<(&'static str, Option<OsString>)>);

#[cfg(test)]
impl NoHomeEnv {
    const KEYS: [&'static str; 3] = ["HOME", "USERPROFILE", "CARGO_HOME"];

    pub(crate) fn set() -> Self {
        let saved = Self::KEYS
            .into_iter()
            .map(|k| (k, std::env::var_os(k)))
            .collect();
        for k in Self::KEYS {
            std::env::remove_var(k);
        }
        NoHomeEnv(saved)
    }
}

#[cfg(test)]
impl Drop for NoHomeEnv {
    fn drop(&mut self) {
        for (k, v) in self.0.drain(..) {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_passwd() -> Option<PathBuf> {
        None
    }

    fn passwd_unused() -> Option<PathBuf> {
        panic!("passwd home consulted with the home variable set")
    }

    #[test]
    fn cargo_home_var_wins() {
        let got = resolve(
            Some("/opt/cargo".into()),
            Some("/home/u".into()),
            passwd_unused,
        );
        assert_eq!(got, Some(PathBuf::from("/opt/cargo")));
    }

    #[test]
    fn blank_cargo_home_var_is_unset() {
        let got = resolve(Some("  ".into()), Some("/home/u".into()), passwd_unused);
        assert_eq!(got, Some(PathBuf::from("/home/u/.cargo")));
    }

    #[test]
    fn home_var_wins_over_passwd() {
        let got = resolve(None, Some("/home/u".into()), passwd_unused);
        assert_eq!(got, Some(PathBuf::from("/home/u/.cargo")));
    }

    /// #1135: with `HOME` and `CARGO_HOME` unset cargo builds from the
    /// passwd home's `~/.cargo`, so the crawler must probe it too.
    #[test]
    fn unset_home_var_falls_back_to_passwd_home() {
        let got = resolve(None, None, || Some("/root".into()));
        assert_eq!(got, Some(PathBuf::from("/root/.cargo")));
    }

    /// A set-but-unusable home is no home, not a cue to patch the shared
    /// passwd-home cache cargo isn't using.
    #[test]
    fn empty_or_relative_home_var_is_no_home() {
        assert_eq!(resolve(None, Some("".into()), passwd_unused), None);
        assert_eq!(resolve(None, Some("rel/home".into()), passwd_unused), None);
    }

    #[test]
    fn relative_or_missing_passwd_home_is_no_home() {
        assert_eq!(resolve(None, None, || Some("rel".into())), None);
        assert_eq!(resolve(None, None, || Some(PathBuf::new())), None);
        assert_eq!(resolve(None, None, no_passwd), None);
    }

    /// The process wrapper reads `HOME` only on Unix: a `USERPROFILE`
    /// left over from a Windows-forwarding shell is not cargo's home.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn process_cargo_home_ignores_userprofile_on_unix() {
        let want = super::super::fs::passwd_home().map(|h| h.join(".cargo"));
        let got = {
            let _env = NoHomeEnv::set();
            std::env::set_var("USERPROFILE", "/mnt/c/Users/x");
            cargo_home()
        };
        assert_eq!(got, want);
    }

    /// #1135 through the process environment: `HOME`, `USERPROFILE` and
    /// `CARGO_HOME` all unset still finds the passwd home's `.cargo`.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn process_cargo_home_without_home_uses_passwd_entry() {
        let Some(passwd) = super::super::fs::passwd_home() else {
            return; // no passwd entry for this uid: nothing cargo could use either
        };
        let got = {
            let _env = NoHomeEnv::set();
            cargo_home()
        };
        assert_eq!(got, Some(passwd.join(".cargo")));
    }
}
