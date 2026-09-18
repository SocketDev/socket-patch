//! Which Pipenv release installs this project. The hosted rewriter writes
//! `path` references for Pipenv 7–11 and `file` references from 2018 on, and
//! the vendored backend refuses installers older than 2018, so both ask
//! [`installed_major`] once per command.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

// Only the Windows PATHEXT test below asserts shim detection.
#[cfg(all(test, windows))]
use crate::utils::process::is_batch_shim;

/// Pins the answer without spawning anything: CI images without pipenv on
/// PATH, or a project installed with a different release than the machine's
/// default pipenv.
pub const MAJOR_OVERRIDE_ENV: &str = "SOCKET_PIPENV_MAJOR";

/// `SOCKET_PIPENV_MAJOR` accepts the bare major (`11`, `2026`) or the full
/// release as `pipenv --version` prints it (`11.10.4`, `2026.8.0`); anything
/// else is ignored (the probe then runs as if the variable were unset).
fn parse_override(value: &str) -> Option<u32> {
    let value = value.trim().trim_start_matches('v');
    value.split('.').next()?.parse::<u32>().ok()
}

/// `pipenv, version 2026.8.0` — every release from 0.2.8 through 2026.8.0
/// prints exactly this shape on stdout (measured). Only the token after
/// `version` counts: a bare dotted number elsewhere (a `Python 3.12` banner
/// from a wrapper, a "Courtesy Notice" line) must never be mistaken for the
/// major, because a wrong major silently picks the wrong lock reference
/// shape or refuses vendoring.
fn parse_major(output: &str) -> Option<u32> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    let index = tokens
        .iter()
        .position(|token| token.trim_end_matches(':').eq_ignore_ascii_case("version"))?;
    let token = tokens
        .get(index + 1)?
        .trim_start_matches('v')
        .trim_matches(|c: char| matches!(c, ',' | '(' | ')' | ';'));
    let (major, rest) = token.split_once('.')?;
    rest.chars().next().filter(char::is_ascii_digit)?;
    major.parse().ok()
}

/// The `pipenv` executable, searched on ABSOLUTE `PATH` entries only: the
/// probe runs with the project as its working directory, so a relative entry
/// (`.`, an empty component) would execute a `pipenv` planted in the
/// repository being scanned. On Windows every `PATHEXT` extension is tried,
/// so `pipenv.exe` and the `pipenv.bat` / `pipenv.cmd` shims (pyenv-win,
/// hand-written wrappers) are both found. The rule lives in
/// [`crate::utils::process::resolve_tool_with`], shared with every other
/// tool the CLI spawns inside a project (`bun`).
fn resolve_on_path(var: &impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    crate::utils::process::resolve_tool_with("pipenv", var)
}

/// The major of the `pipenv` on PATH (`11`, `2018`, `2026`, …), or `None`
/// when none is found, it does not answer within 10 s, exits non-zero or
/// prints something unrecognizable. [`MAJOR_OVERRIDE_ENV`] short-circuits
/// the probe.
pub async fn installed_major(root: &Path) -> Option<u32> {
    if let Some(forced) = std::env::var(MAJOR_OVERRIDE_ENV)
        .ok()
        .and_then(|value| parse_override(&value))
    {
        return Some(forced);
    }
    let program = resolve_on_path(&|name| std::env::var_os(name))?;
    // `.bat` / `.cmd` shims launch through `cmd.exe /C`, real executables
    // directly — the shared launcher decides.
    let mut command = tokio::process::Command::from(crate::utils::process::command_for(&program));
    // The version banner does not depend on a project, so the probe runs in a
    // NEUTRAL directory: with the scanned repository as cwd, Pipenv would read
    // its `.env`, `Pipfile` and `.venv` pointer — committed, attacker-shaped
    // inputs that must not influence (or slow down) a version check.
    let _ = root;
    command
        .arg("--version")
        .current_dir(std::env::temp_dir())
        .env("PIPENV_DONT_LOAD_ENV", "1")
        .env("PIPENV_NOSPIN", "1")
        .env("PIPENV_IGNORE_VIRTUALENVS", "1")
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_major(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installer_version_output() {
        assert_eq!(parse_major("pipenv, version 11.10.4\n"), Some(11));
        assert_eq!(parse_major("pipenv, version 2026.8.0\n"), Some(2026));
        assert_eq!(parse_major("pipenv, version 0.2.8\n"), Some(0));
        assert_eq!(parse_major("unavailable"), None);
        // Extra lines before the banner (a courtesy notice, a `.env` load
        // message routed to stdout by a wrapper) do not confuse it…
        assert_eq!(
            parse_major(
                "Courtesy Notice: Pipenv found itself running within a virtual environment 3.12\npipenv, version 2023.12.1\n"
            ),
            Some(2023)
        );
        assert_eq!(parse_major("Loading .env environment variables...\npipenv, version 2022.12.19"), Some(2022));
        // …and a dotted number that is NOT the pipenv version is never taken.
        assert_eq!(parse_major("Python 3.12.0"), None);
        assert_eq!(parse_major("version"), None);
        assert_eq!(parse_major("version x.1"), None);
        assert_eq!(parse_major("pipenv version 2024\n"), None, "no minor: not a version banner");
    }

    #[test]
    fn resolve_on_path_skips_relative_entries_and_finds_absolute_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let leaf = if cfg!(windows) { "pipenv.exe" } else { "pipenv" };
        std::fs::write(bin.join(leaf), b"").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(bin.join(leaf), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // A repo-planted `pipenv` under a RELATIVE entry must never win.
        let planted = tmp.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        std::fs::write(planted.join(leaf), b"").unwrap();
        let joined = std::env::join_paths([
            std::path::PathBuf::from("."),
            std::path::PathBuf::from(""),
            std::path::PathBuf::from("planted"),
            bin.clone(),
        ])
        .unwrap();
        let var = |name: &str| (name == "PATH").then(|| joined.clone());
        assert_eq!(resolve_on_path(&var), Some(bin.join(leaf)));

        let only_relative = std::env::join_paths([std::path::PathBuf::from("."), std::path::PathBuf::from("planted")]).unwrap();
        let var = |name: &str| (name == "PATH").then(|| only_relative.clone());
        assert_eq!(resolve_on_path(&var), None);
        let none = |_: &str| None::<OsString>;
        assert_eq!(resolve_on_path(&none), None);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_on_path_skips_non_executable_files() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(data.join("pipenv"), b"not a program").unwrap();
        std::fs::set_permissions(data.join("pipenv"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(bin.join("pipenv"), b"").unwrap();
        std::fs::set_permissions(bin.join("pipenv"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let joined = std::env::join_paths([data.clone(), bin.clone()]).unwrap();
        let var = |name: &str| (name == "PATH").then(|| joined.clone());
        assert_eq!(resolve_on_path(&var), Some(bin.join("pipenv")));
    }

    #[test]
    fn override_accepts_a_major_or_a_full_release() {
        assert_eq!(parse_override("11"), Some(11));
        assert_eq!(parse_override(" 2026 "), Some(2026));
        assert_eq!(parse_override("11.10.4"), Some(11));
        assert_eq!(parse_override("v2018.11.26"), Some(2018));
        assert_eq!(parse_override("eleven"), None);
        assert_eq!(parse_override(""), None);
        assert_eq!(parse_override("-11"), None);
    }

    #[cfg(windows)]
    #[test]
    fn resolve_on_path_honours_pathext_shims() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("pipenv.bat"), b"@echo pipenv, version 2024.4.1").unwrap();
        let joined = std::env::join_paths([bin.clone()]).unwrap();
        let var = |name: &str| match name {
            "PATH" => Some(joined.clone()),
            "PATHEXT" => Some(OsString::from(".COM;.EXE;.BAT;.CMD")),
            _ => None,
        };
        let found = resolve_on_path(&var).unwrap();
        assert_eq!(found, bin.join("pipenv.bat"));
        assert!(is_batch_shim(&found));
    }
}
