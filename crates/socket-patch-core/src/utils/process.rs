//! Subprocess invocation seam shared by the ecosystem crawlers.
//!
//! Several crawlers ask an external CLI for a path that's hard to
//! infer otherwise — `npm root -g`, `gem env gemdir`, `python3 -c
//! "import site; ..."`, etc. The historical pattern was to embed
//! `std::process::Command::new(bin).args([...]).output()` directly
//! inside each helper, which leaves two arms untestable without
//! installing the binary: the success arm (binary present, stdout
//! parsed) and the spawn-Err arm (binary missing or unspawnable).
//!
//! This module provides a `CommandRunner` trait whose default impl,
//! `SystemCommandRunner`, performs the real spawn, and whose test
//! double (`MockCommandRunner` in `tests/common/mod.rs`) maps
//! `(bin, args)` to canned stdout. Each shell-out helper accepts a
//! `&dyn CommandRunner` argument so tests can inject the mock;
//! production callers either build the helper with the default
//! runner or thread a singleton.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The executable `name` on ABSOLUTE `PATH` entries only, or `None` when
/// no entry holds one.
///
/// Shared by every tool the CLI spawns with the scanned project as its
/// working directory (`bun`, `pipenv`): a relative `PATH` component (`.`,
/// an empty string) resolves against the child's cwd, so a bare
/// `Command::new("bun")` would execute a `bun` planted in the repository
/// being scanned — and on macOS `posix_spawnp` can run BOTH the planted
/// file and the next absolute entry's binary for one spawn. Skipping
/// non-absolute entries closes that; callers must then spawn the RESOLVED
/// path, never the bare name.
///
/// On Windows every `PATHEXT` extension is tried (falling back to
/// `.exe`/`.bat`/`.cmd` when the variable is unset or empty), so an npm-global
/// `bun.cmd` / pyenv-win `pipenv.bat` shim is found where Rust's own
/// `Command` resolution — which appends only `.exe` — would report NotFound.
/// A plain file without execute permission is skipped like execvp does.
pub fn resolve_tool(name: &str) -> Option<PathBuf> {
    resolve_tool_with(name, &|var| std::env::var_os(var))
}

/// [`resolve_tool`] over an injected environment reader (tests).
pub(crate) fn resolve_tool_with(
    name: &str,
    var: &impl Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    let path = var("PATH")?;
    let extensions: Vec<String> = if cfg!(windows) {
        var("PATHEXT")
            .map(|value| {
                value
                    .to_string_lossy()
                    .split(';')
                    .filter(|ext| !ext.is_empty())
                    .map(|ext| ext.to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .filter(|list| !list.is_empty())
            .unwrap_or_else(|| vec![".exe".into(), ".bat".into(), ".cmd".into()])
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path) {
        if !dir.is_absolute() {
            continue;
        }
        for ext in &extensions {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() && is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// A plain file that cannot be executed (a stray `bun` data file on PATH)
/// is skipped in favour of the next entry, like execvp does; Windows has no
/// mode bits, PATHEXT is the executability rule there.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

/// A [`Command`] that launches the RESOLVED `program` — the absolute path
/// [`resolve_tool`] found, never the bare name. Callers add their own args /
/// cwd / env; `tokio::process::Command::from` lifts it into the async
/// runtime unchanged.
///
/// A Windows `.bat` / `.cmd` shim (npm-global `bun.cmd`, pyenv-win
/// `pipenv.bat`) is spawned through this same path: since Rust 1.77.2 (the
/// BatBadBut fix) `std` detects the batch extension on the resolved program
/// and runs `%SystemRoot%\System32\cmd.exe /e:ON /v:OFF /d /c ""<script>"
/// <args>"` itself — an OUTER quote pair around the whole line plus per-
/// argument escaping — so a shim path with a space AND a cmd metacharacter
/// (`C:\Program Files (x86)\…\bun.cmd`, `C:\Users\Jane (Work)\…`) survives
/// cmd's `/c` quote-stripping rule. A hand-rolled `cmd.exe /C <shim>`
/// wrapper here (the shape this replaced) quoted the path as an ordinary
/// argument, which that rule strips down to `C:\Program` → "is not
/// recognized". Nothing to add on top of `std`; a wrapper can only be
/// less correct.
pub fn command_for(program: &Path) -> Command {
    Command::new(program)
}

/// [`resolve_tool`] + [`command_for`]: the command for the tool `name` found
/// on an absolute PATH entry, or `None` when there is none — the caller
/// decides how "not installed" degrades (a warning, a refusal).
pub fn tool_command(name: &str) -> Option<Command> {
    resolve_tool(name).map(|program| command_for(&program))
}

/// Run an external binary with the given args and return its
/// stdout, trimmed, when the spawn succeeded AND the process exited
/// with a success status AND stdout is non-empty after trimming.
///
/// Returns `None` for any of: spawn failure (binary not on PATH),
/// non-zero exit status, empty stdout after trim. Stderr is
/// captured and discarded — the crawlers treat all failures as
/// "no information", not as errors to surface.
pub trait CommandRunner {
    fn run(&self, bin: &str, args: &[&str]) -> Option<String>;
}

/// Default runner: spawns the real binary via `std::process::Command`.
///
/// `output()` nulls stdin so the child can't block waiting for
/// input. stdout is captured; stderr is captured and dropped (we
/// don't surface CLI diagnostics — the helpers fall back to other
/// discovery paths on any failure).
pub(crate) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, bin: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(bin).args(args).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            None
        } else {
            Some(stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm the real runner returns Some for a tiny command we
    /// know is on every Unix PATH — `echo`. Skipped on Windows where
    /// `echo` isn't a real binary.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_stdout_for_real_binary() {
        let runner = SystemCommandRunner;
        let out = runner.run("echo", &["hello"]).expect("echo should succeed");
        assert_eq!(out, "hello");
    }

    /// Spawn failure → None. The binary name is intentionally one
    /// that should never be on PATH.
    #[test]
    fn system_runner_returns_none_on_spawn_failure() {
        let runner = SystemCommandRunner;
        let out = runner.run("definitely-not-a-real-binary-1234567", &[]);
        assert_eq!(out, None);
    }

    /// Non-zero exit → None. `false`(1) is in coreutils everywhere.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_none_on_non_zero_exit() {
        let runner = SystemCommandRunner;
        let out = runner.run("false", &[]);
        assert_eq!(out, None);
    }

    /// Exit 0 but stdout is empty → None. This is the fourth arm of
    /// the contract and was previously untested. A successful command
    /// that prints nothing carries no information for the crawlers.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_none_on_empty_stdout_despite_success() {
        let runner = SystemCommandRunner;
        let out = runner.run("true", &[]);
        assert_eq!(out, None);
    }

    /// Exit 0 with whitespace-only stdout → None: the empty check
    /// happens *after* trimming, so a command that prints only spaces
    /// and newlines is treated as "no output".
    #[cfg(unix)]
    #[test]
    fn system_runner_treats_whitespace_only_stdout_as_empty() {
        let runner = SystemCommandRunner;
        let out = runner.run("sh", &["-c", "printf '  \\t\\n  '"]);
        assert_eq!(out, None);
    }

    /// Surrounding whitespace is trimmed from a non-empty result, so
    /// callers that join the value into a path don't get stray
    /// newlines (e.g. `npm root -g` emits a trailing `\n`).
    #[cfg(unix)]
    #[test]
    fn system_runner_trims_surrounding_whitespace() {
        let runner = SystemCommandRunner;
        let out = runner.run("sh", &["-c", "printf '  /some/path  \\n'"]);
        assert_eq!(out.as_deref(), Some("/some/path"));
    }

    /// stderr never leaks into the result. When stdout is empty but
    /// the process wrote to stderr and still exited 0, the result is
    /// None — stderr is captured and dropped, not returned.
    #[cfg(unix)]
    #[test]
    fn system_runner_ignores_stderr_when_stdout_empty() {
        let runner = SystemCommandRunner;
        let out = runner.run("sh", &["-c", "printf 'diagnostic' >&2"]);
        assert_eq!(out, None);
    }

    /// When a command writes to both streams, only stdout comes back —
    /// the stderr line must not be appended or interleaved.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_only_stdout_when_both_streams_used() {
        let runner = SystemCommandRunner;
        let out = runner.run("sh", &["-c", "printf 'good\\n'; printf 'bad\\n' >&2"]);
        assert_eq!(out.as_deref(), Some("good"));
    }

    /// Every element of `args` is forwarded to the child in order.
    /// Here `$0` is `sh` and `$1` is `forwarded`; printing `$1` proves
    /// positional args survive the hop into `Command::args`.
    #[cfg(unix)]
    #[test]
    fn system_runner_forwards_all_args_in_order() {
        let runner = SystemCommandRunner;
        let out = runner.run("sh", &["-c", "printf '%s' \"$1\"", "sh", "forwarded"]);
        assert_eq!(out.as_deref(), Some("forwarded"));
    }

    // ───────────────────────── resolve_tool / tool_command ─────────────────────────

    /// Mark an existing file executable (no-op off Unix: PATHEXT rules there).
    fn set_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    /// An empty executable file — enough for the resolver, which only
    /// stats candidates.
    fn make_executable(path: &Path) {
        std::fs::write(path, b"").unwrap();
        set_executable(path);
    }

    /// The load-bearing rule: `.`, the empty component and a bare relative
    /// dir name never resolve — only the absolute entry wins, even when it
    /// comes LAST. A repo-planted `bun` under a relative entry is ignored.
    #[test]
    fn resolve_tool_skips_relative_entries_and_finds_absolute_ones() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let leaf = if cfg!(windows) { "bun.exe" } else { "bun" };
        make_executable(&bin.join(leaf));
        let planted = tmp.path().join("planted");
        std::fs::create_dir_all(&planted).unwrap();
        make_executable(&planted.join(leaf));
        let joined = std::env::join_paths([
            PathBuf::from("."),
            PathBuf::from(""),
            PathBuf::from("planted"),
            bin.clone(),
        ])
        .unwrap();
        let var = |name: &str| (name == "PATH").then(|| joined.clone());
        assert_eq!(resolve_tool_with("bun", &var), Some(bin.join(leaf)));

        let only_relative =
            std::env::join_paths([PathBuf::from("."), PathBuf::from("planted")]).unwrap();
        let var = |name: &str| (name == "PATH").then(|| only_relative.clone());
        assert_eq!(resolve_tool_with("bun", &var), None);
        let none = |_: &str| None::<OsString>;
        assert_eq!(resolve_tool_with("bun", &none), None);
    }

    /// The name is honoured exactly: a `bunx` beside no `bun` is not `bun`,
    /// and a directory named `bun` is not a program.
    #[test]
    fn resolve_tool_matches_the_exact_leaf_only() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(bin.join("bun")).unwrap();
        let leaf = if cfg!(windows) { "bunx.exe" } else { "bunx" };
        make_executable(&bin.join(leaf));
        let joined = std::env::join_paths([bin.clone()]).unwrap();
        let var = |name: &str| (name == "PATH").then(|| joined.clone());
        assert_eq!(resolve_tool_with("bun", &var), None);
        assert_eq!(resolve_tool_with("bunx", &var), Some(bin.join(leaf)));
    }

    /// A non-executable data file squatting the name is skipped in favour of
    /// the next entry's real program (execvp semantics).
    #[cfg(unix)]
    #[test]
    fn resolve_tool_skips_non_executable_files() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(data.join("bun"), b"not a program").unwrap();
        std::fs::set_permissions(data.join("bun"), std::fs::Permissions::from_mode(0o644)).unwrap();
        make_executable(&bin.join("bun"));
        let joined = std::env::join_paths([data.clone(), bin.clone()]).unwrap();
        let var = |name: &str| (name == "PATH").then(|| joined.clone());
        assert_eq!(resolve_tool_with("bun", &var), Some(bin.join("bun")));
    }

    /// The command spawns the RESOLVED path directly — the program is the
    /// absolute path, not the bare name, with no wrapper and no args of its
    /// own (a `bun.cmd` file on a Unix PATH is just a file).
    #[cfg(unix)]
    #[test]
    fn command_for_spawns_the_resolved_path_directly_on_unix() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let shim = bin.join("bun");
        std::fs::write(&shim, "#!/bin/sh\nprintf 'resolved:%s' \"$0\"\n").unwrap();
        set_executable(&shim);
        let joined = std::env::join_paths([bin.clone()]).unwrap();
        let var = |name: &str| (name == "PATH").then(|| joined.clone());
        let program = resolve_tool_with("bun", &var).expect("the shim resolves");
        let command = command_for(&program);
        assert_eq!(command.get_program(), shim.as_os_str());
        assert_eq!(
            command.get_args().count(),
            0,
            "no wrapper, no args of its own"
        );
        let out = command_for(&program).output().expect("spawn the shim");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("resolved:{}", shim.display()),
            "the child sees its own absolute path as argv[0]"
        );
    }

    /// Windows: every PATHEXT extension is tried (case-insensitively), so a
    /// `.cmd`/`.bat` shim is found; an unset PATHEXT falls back to the
    /// exe/bat/cmd triple. The shim is spawned DIRECTLY — `std` runs it
    /// through cmd.exe with an outer quote pair — and that spawn is proven
    /// to work from a directory whose name carries a space AND a cmd
    /// metacharacter (`Program Files (x86)`), the exact shape the replaced
    /// `cmd.exe /C <shim>` wrapper misquoted ("'C:\Program' is not
    /// recognized").
    #[cfg(windows)]
    #[test]
    fn resolve_tool_honours_pathext_and_spawns_batch_shims_directly() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("bun.cmd"), b"@echo off\r\necho 1.2.3\r\n").unwrap();
        let joined = std::env::join_paths([bin.clone()]).unwrap();
        let with_pathext = |name: &str| match name {
            "PATH" => Some(joined.clone()),
            "PATHEXT" => Some(OsString::from(".COM;.EXE;.BAT;.CMD")),
            _ => None,
        };
        let found = resolve_tool_with("bun", &with_pathext).expect("bun.cmd resolves via PATHEXT");
        assert_eq!(found, bin.join("bun.cmd"));
        let command = command_for(&found);
        assert_eq!(
            command.get_program(),
            found.as_os_str(),
            "the shim itself is the program: no cmd.exe wrapper"
        );
        assert_eq!(command.get_args().count(), 0, "no wrapper args");
        let out = command_for(&found)
            .arg("--version")
            .output()
            .expect("std spawns a .cmd through cmd.exe");
        assert!(out.status.success(), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1.2.3");

        // The misquoting shape: a shim under a directory with a space AND a
        // cmd metacharacter. std's outer quote pair keeps the path whole.
        let awkward = tmp.path().join("Program Files (x86)").join("npm");
        std::fs::create_dir_all(&awkward).unwrap();
        std::fs::write(awkward.join("bun.cmd"), b"@echo off\r\necho 1.2.3\r\n").unwrap();
        let awkward_path = std::env::join_paths([awkward.clone()]).unwrap();
        let awkward_env = |name: &str| match name {
            "PATH" => Some(awkward_path.clone()),
            "PATHEXT" => Some(OsString::from(".COM;.EXE;.BAT;.CMD")),
            _ => None,
        };
        let found = resolve_tool_with("bun", &awkward_env).expect("the awkward shim resolves");
        assert_eq!(found, awkward.join("bun.cmd"));
        let out = command_for(&found)
            .arg("--version")
            .output()
            .expect("std spawns a .cmd under `Program Files (x86)`");
        assert!(
            out.status.success(),
            "a shim path with a space and parentheses must run: {out:?}"
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1.2.3");

        // PATHEXT unset → the default triple still finds the shim.
        let no_pathext = |name: &str| (name == "PATH").then(|| joined.clone());
        assert_eq!(
            resolve_tool_with("bun", &no_pathext),
            Some(bin.join("bun.cmd"))
        );

        // A PATHEXT that does NOT list .cmd hides the shim (Windows semantics).
        let exe_only = |name: &str| match name {
            "PATH" => Some(joined.clone()),
            "PATHEXT" => Some(OsString::from(".EXE")),
            _ => None,
        };
        assert_eq!(resolve_tool_with("bun", &exe_only), None);

        // A real .exe is the program too — the same path for both shapes.
        std::fs::write(bin.join("bun.exe"), b"").unwrap();
        let exe = resolve_tool_with("bun", &exe_only).expect("bun.exe resolves");
        assert_eq!(command_for(&exe).get_program(), exe.as_os_str());
    }

    /// `tool_command` reads the REAL environment: a name that cannot be on
    /// any PATH yields None (the caller's "not installed" arm).
    #[test]
    fn tool_command_is_none_for_an_absent_tool() {
        assert!(tool_command("definitely-not-a-real-binary-1234567").is_none());
    }
}
