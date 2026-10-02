//! JVM build-tool isolation for the `socket-patch` children the tests spawn.
//!
//! The JVM crawlers resolve their caches from the environment: Gradle's user
//! home from `-Dgradle.user.home` in `GRADLE_OPTS` / `JAVA_OPTS`, then
//! `GRADLE_USER_HOME`, then `~/.gradle`; the read-only cache from
//! `GRADLE_RO_DEP_CACHE`; Maven's local repository from `~/.m2`. Inherited
//! as-is, a developer's real caches leak into every test that does not pin
//! them, and a machine with a warm `~/.gradle` sees packages a CI runner
//! does not.
//!
//! [`isolate_cli`] scrubs [`AMBIENT`] and points `HOME` / `USERPROFILE` at
//! [`stand_in_home`], an empty directory nothing writes to. On Unix Gradle
//! (and so the CLI) takes the user home from the passwd entry, not `$HOME`,
//! so `GRADLE_USER_HOME` is pinned to the stand-in's `.gradle` as well. A
//! test that wants a cache passes it as explicit env AFTER this call (the
//! caller's env lands last; see [`EXPLICIT`]).
//!
//! Shared by `common/mod.rs` and `prebuilt_common/mod.rs` (the latter pulls
//! it in with `#[path]`), so the two harnesses cannot drift.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::Command;

/// Scrubbed from every CLI child by default.
pub const AMBIENT: &[&str] = &[
    "GRADLE_OPTS",
    "JAVA_OPTS",
    "GRADLE_USER_HOME",
    "GRADLE_RO_DEP_CACHE",
    "GRADLE_HOME",
];

/// The cache roots a test may hand the CLI explicitly (they survive
/// `prebuilt_common::prepare_command`'s scrub and are served by its fixture
/// server).
pub const EXPLICIT: &[&str] = &[
    "GRADLE_USER_HOME",
    "GRADLE_RO_DEP_CACHE",
    // sbt (Coursier / Ivy) registers COURSIER_CACHE here.
];

/// Toolchain locations that default to a path under the real home (the
/// list `cache_env::TOOLCHAIN_ROOTS` carries for package-manager children).
/// A CLI child that spawns `node` / `git` through a version-manager shim
/// still needs them once `HOME` moves.
const TOOLCHAIN_ROOTS: &[(&str, &str)] = &[
    ("RUSTUP_HOME", ".rustup"),
    ("RBENV_ROOT", ".rbenv"),
    ("PYENV_ROOT", ".pyenv"),
    ("NVM_DIR", ".nvm"),
    ("FNM_DIR", ".fnm"),
    ("VOLTA_HOME", ".volta"),
    ("ASDF_DIR", ".asdf"),
    ("ASDF_DATA_DIR", ".asdf"),
    ("SDKMAN_DIR", ".sdkman"),
    ("MISE_DATA_DIR", ".local/share/mise"),
    ("MISE_CONFIG_DIR", ".config/mise"),
];

/// The empty stand-in home every isolated CLI child gets. Per account
/// (`/tmp` is shared on Linux) and outside every test's scratch tree, so
/// the policy lookup's stop-at-home rule never fires inside a fixture.
pub fn stand_in_home() -> PathBuf {
    let account: String = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let home = std::env::temp_dir().join(format!("socket-patch-cli-home-{account}"));
    let _ = std::fs::create_dir_all(&home);
    home
}

/// Scrub [`AMBIENT`] from `cmd` and pin `HOME` / `USERPROFILE` to
/// [`stand_in_home`] (and `GRADLE_USER_HOME` to its `.gradle`, which nothing
/// creates), carrying the version-manager roots over. Call it before
/// applying a test's own env.
pub fn isolate_cli(cmd: &mut Command) -> &mut Command {
    for key in AMBIENT {
        cmd.env_remove(key);
    }
    let real = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty());
    if let Some(real) = real {
        for (var, relative) in TOOLCHAIN_ROOTS {
            if std::env::var_os(var).is_some() {
                continue;
            }
            let path = real.join(relative);
            if path.is_dir() {
                cmd.env(var, path);
            }
        }
    }
    let home = stand_in_home();
    cmd.env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("GRADLE_USER_HOME", home.join(".gradle"))
}

mod jvm_env_selftests {
    use super::*;

    /// A stray GRADLE_OPTS (and every other ambient JVM knob) never reaches
    /// the child, the home is the stand-in, and an explicit cache applied
    /// afterwards wins.
    #[test]
    fn isolate_cli_scrubs_ambient_jvm_env_and_pins_home() {
        let mut cmd = Command::new("socket-patch");
        cmd.env("GRADLE_OPTS", "-Dgradle.user.home=/real/.gradle")
            .env("JAVA_OPTS", "-Dgradle.user.home=/real/.gradle")
            .env("GRADLE_RO_DEP_CACHE", "/real/ro");
        isolate_cli(&mut cmd);
        cmd.env("GRADLE_USER_HOME", "/explicit/gradle-home");
        let envs: std::collections::HashMap<String, Option<String>> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        for key in [
            "GRADLE_OPTS",
            "JAVA_OPTS",
            "GRADLE_RO_DEP_CACHE",
            "GRADLE_HOME",
        ] {
            assert_eq!(envs.get(key), Some(&None), "{key} must be scrubbed");
        }
        let home = stand_in_home().to_string_lossy().into_owned();
        assert_eq!(envs["HOME"].as_deref(), Some(home.as_str()));
        assert_eq!(envs["USERPROFILE"].as_deref(), Some(home.as_str()));
        assert_eq!(
            envs["GRADLE_USER_HOME"].as_deref(),
            Some("/explicit/gradle-home")
        );
        assert!(std::path::Path::new(&home).is_dir());
    }

    /// Without an explicit cache the Gradle user home is the stand-in's
    /// `.gradle`: the CLI resolves Gradle's home from the passwd entry on
    /// Unix, so pinning `HOME` alone would leak the real `~/.gradle`.
    #[test]
    fn isolate_cli_pins_the_gradle_user_home() {
        let mut cmd = Command::new("socket-patch");
        cmd.env("GRADLE_USER_HOME", "/real/.gradle");
        isolate_cli(&mut cmd);
        let home = cmd
            .get_envs()
            .find(|(k, _)| *k == "GRADLE_USER_HOME")
            .and_then(|(_, v)| v)
            .map(PathBuf::from);
        assert_eq!(home, Some(stand_in_home().join(".gradle")));
    }
}
