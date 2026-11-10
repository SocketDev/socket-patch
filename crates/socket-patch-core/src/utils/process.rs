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
//! This module provides a `CommandRunner` trait whose real impl,
//! `ProbeRunner`, performs the spawn from a directory chosen by the
//! probe's scope (the project, or a neutral one for a global question),
//! and whose test double (`MockCommandRunner` in `tests/common/mod.rs`)
//! maps `(bin, args)` to canned stdout. Each shell-out helper accepts a
//! `&dyn CommandRunner` argument so tests can inject the mock;
//! production callers build the helper with a `ProbeRunner`.

use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
#[cfg(unix)]
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How long a crawler probe (`gem env gemdir`, `npm root -g`, `python3
/// --version`, ...) may run before it is killed and answers "no
/// information". The same budget the Pipenv and Hatch version probes and the
/// self-update `--version` check use.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The environment variables no child process inherits
/// ([`scrub_child_env`]).
///
/// Everything this CLI spawns is someone else's program: a package
/// manager or its version-manager shim, an interpreter, a gem's
/// `extconf.rb` and the compiler it starts. Some of it is chosen by the
/// repository being scanned, and CI usually exports the Socket API token
/// for the run. None of those programs needs a Socket credential, nor
/// this CLI's own settings (the URL ones can carry credentials in their
/// userinfo, and name the hosts the token is sent to).
///
/// Names are exact. A package manager's own settings (`HTTP_PROXY`,
/// `HTTPS_PROXY`, `NO_PROXY`, `NPM_TOKEN` and other registry auth) reach
/// the child untouched, and so does any other variable, `SOCKET_`-prefixed
/// or not: an `.npmrc` or `.yarnrc.yml` may expand one.
///
/// The CLI's flag bindings are listed here because core runs the
/// children; `socket-patch-cli`'s `args` tests fail when a binding is
/// missing.
pub const CHILD_ENV_SCRUB: &[&str] = &[
    // The Socket API token, under each name a Socket tool reads it from
    // (this CLI, socket-cli and its legacy spellings, the Python CLI, the
    // SDKs).
    "SOCKET_API_TOKEN",
    "SOCKET_CLI_API_TOKEN",
    "SOCKET_SECURITY_API_TOKEN",
    "SOCKET_API_KEY",
    "SOCKET_CLI_API_KEY",
    "SOCKET_SECURITY_API_KEY",
    // socket-cli's inline config (it can hold `apiToken`) and its forward
    // proxy URL.
    "SOCKET_CLI_CONFIG",
    "SOCKET_CLI_API_PROXY",
    // The other accepted socket-cli aliases (`env_compat::PEER_ENV_ALIASES`)
    // and the canonical name of the one that is not a flag.
    "SOCKET_CLI_ORG_SLUG",
    "SOCKET_CLI_API_BASE_URL",
    "SOCKET_CLI_NO_API_TOKEN",
    "SOCKET_NO_API_TOKEN",
    // Every flag binding of the CLI.
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_URL",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_VENDOR_SOURCE",
    "SOCKET_VENDOR_URL",
    "SOCKET_PATCH_SERVER_URL",
    "SOCKET_OFFLINE",
    "SOCKET_STRICT",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_NO_TRUST_LOCKFILE_CONFIG",
    "SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG",
    "SOCKET_NO_VLT_INSTALL_CLEANUP",
    "SOCKET_NO_GEM_NATIVE_REBUILD",
    "SOCKET_PATCH_VERSION",
    "SOCKET_SAVE_ONLY",
    "SOCKET_ALL_RELEASES",
    "SOCKET_SKIP_ROLLBACK",
    "SOCKET_PRESERVE_STATE",
    "SOCKET_DOWNLOAD_ONLY",
    "SOCKET_VENDOR_REVERT",
    "SOCKET_BATCH_SIZE",
    "SOCKET_SCAN_PACKAGES",
    "SOCKET_NO_SOCKET_YML",
    "SOCKET_VEX",
    "SOCKET_VEX_OUTPUT",
    "SOCKET_VEX_PRODUCT",
    "SOCKET_VEX_NO_VERIFY",
    "SOCKET_VEX_DOC_ID",
    "SOCKET_VEX_COMPACT",
    // Socket-specific service URLs read from the environment alone.
    "SOCKET_NPM_REGISTRY",
    "SOCKET_PYPI_JSON_API",
    "SOCKET_RUBYGEMS_URL",
    "SOCKET_PACKAGIST_URL",
    "SOCKET_CRATES_INDEX",
    "SOCKET_GOPROXY",
    "SOCKET_GOSUMDB_URL",
    "SOCKET_MAVEN_REGISTRY",
    "SOCKET_NUGET_URL",
    "SOCKET_UPDATE_BASE_URL",
];

/// Take every [`CHILD_ENV_SCRUB`] variable out of `command`'s environment,
/// inherited or set on it.
pub fn scrub_child_env(command: &mut Command) {
    for name in CHILD_ENV_SCRUB {
        command.env_remove(name);
    }
}

/// Why [`output_within`] produced no [`Output`].
#[derive(Debug)]
pub enum BoundedError {
    /// The child could not be spawned (missing program, ETXTBSY, ...).
    Spawn(std::io::Error),
    /// The child did not exit and close stdout within the budget; it was
    /// killed.
    TimedOut,
}

/// Run `command` to completion within `budget`: the one bounded spawn every
/// probe goes through.
///
/// stdin is null (the child can't wait for input), stdout is captured and
/// stderr is discarded. When the child has not exited and closed stdout by
/// the deadline it is killed and reaped, and the call returns
/// [`BoundedError::TimedOut`] without waiting for a grandchild that still
/// holds the pipe (a `#!/bin/sh` shim's `sleep`). A wedged toolchain shim (a
/// version manager prompting for an install, a Ruby waiting on a network
/// gem home) therefore costs at most `budget`, never the whole run.
///
/// The child never sees a [`CHILD_ENV_SCRUB`] variable, whatever the
/// caller did to the command's environment after [`command_for`] made it
/// (an `env_clear().envs(..)` copy of the ambient one puts them back).
///
/// Blocking: async callers run it through `utils::fs::run_blocking`.
pub fn output_within(mut command: Command, budget: Duration) -> Result<Output, BoundedError> {
    scrub_child_env(&mut command);
    let deadline = Instant::now() + budget;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(BoundedError::Spawn)?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let timed_out = |child: &mut std::process::Child| {
        let _ = child.kill();
        let _ = child.wait();
        Err(BoundedError::TimedOut)
    };
    let Ok(stdout) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
    else {
        return timed_out(&mut child);
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(Output {
                    status,
                    stdout,
                    stderr: Vec::new(),
                })
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => return timed_out(&mut child),
            Err(error) => {
                let _ = child.kill();
                return Err(BoundedError::Spawn(error));
            }
        }
    }
}

/// [`output_within`] for a build whose diagnostics matter (a gem's native
/// extension, #1996): stderr is captured too, and on Unix the child leads
/// its own process group, which is killed whole at the deadline, so the
/// `make` / `cc` / `cargo` it started never outlives the budget. (Elsewhere
/// only the child itself is killed.)
///
/// Once the child exits, its pipes are drained for whatever budget is left;
/// a grandchild still holding one past that is killed with the group and its
/// stream is returned as read so far.
///
/// A group of its own is also one the terminal's Ctrl-C never reaches, so
/// while the build runs its group is on record for the host's interrupt
/// handler ([`kill_builds_on_interrupt`]), which ends it before the process
/// goes. From then on this function does not return: its caller would act
/// on the result (put files back, start the next build) in a process that
/// is releasing its lock and dying.
///
/// Blocking: async callers run it through `utils::fs::run_blocking`.
pub fn build_output_within(command: Command, budget: Duration) -> Result<Output, BoundedError> {
    park_if_interrupted();
    let result = run_build(command, budget);
    park_if_interrupted();
    result
}

/// [`build_output_within`], between its interrupt checks.
fn run_build(mut command: Command, budget: Duration) -> Result<Output, BoundedError> {
    scrub_child_env(&mut command);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let deadline = Instant::now() + budget;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(BoundedError::Spawn)?;
    let pid = child.id();
    #[cfg(unix)]
    let _running = RunningBuild::enter(pid);
    let drain = |mut pipe: Box<dyn Read + Send>| {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            let _ = sender.send(bytes);
        });
        receiver
    };
    let stdout = drain(Box::new(child.stdout.take().expect("stdout is piped")));
    let stderr = drain(Box::new(child.stderr.take().expect("stderr is piped")));
    // An interrupt takes the child over: it kills the group and reaps the
    // child itself, so past that point this thread must not signal or
    // wait on a pid that may no longer be the build's.
    let kill_all = |child: &mut std::process::Child| {
        park_if_interrupted();
        kill_process_group(pid);
        let _ = child.kill();
        let _ = child.wait();
    };
    if INTERRUPTED.load(Ordering::SeqCst) {
        // The interrupt may have read the table before this build was on
        // it, and then it is not coming back for it: end the build here.
        kill_process_group(pid);
        let _ = child.kill();
        park_if_interrupted();
    }
    let status = loop {
        park_if_interrupted();
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                kill_all(&mut child);
                return Err(BoundedError::TimedOut);
            }
            Err(error) => {
                kill_all(&mut child);
                return Err(BoundedError::Spawn(error));
            }
        }
    };
    let collect = |receiver: std::sync::mpsc::Receiver<Vec<u8>>| {
        let left = deadline.saturating_duration_since(Instant::now());
        receiver.recv_timeout(left).unwrap_or_else(|_| {
            kill_process_group(pid);
            Vec::new()
        })
    };
    Ok(Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

/// SIGKILL the process group `pid` leads (Unix; a no-op elsewhere).
fn kill_process_group(pid: u32) {
    #[cfg(unix)]
    if let Ok(pid) = i32::try_from(pid) {
        if pid > 0 {
            // SAFETY: a plain syscall on a process group this process
            // created; no memory is shared with the callee.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    #[cfg(not(unix))]
    let _ = pid;
}

/// How many builds [`kill_builds_on_interrupt`] can end at once. A gem
/// rebuild runs one at a time; the rest is headroom for a host that runs
/// several. A build that finds no free slot runs unrecorded.
#[cfg(unix)]
const RUNNING_BUILD_SLOTS: usize = 8;

/// The process groups of the builds [`build_output_within`] is running: a
/// group id per slot, 0 when free. An atomic table, because the reader is
/// a signal handler.
#[cfg(unix)]
static RUNNING_BUILDS: [AtomicI32; RUNNING_BUILD_SLOTS] =
    [const { AtomicI32::new(0) }; RUNNING_BUILD_SLOTS];

/// Set by [`kill_builds_on_interrupt`]: an interrupt is ending the process.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// A build's entry in [`RUNNING_BUILDS`], freed on drop.
#[cfg(unix)]
struct RunningBuild(Option<&'static AtomicI32>);

#[cfg(unix)]
impl RunningBuild {
    /// Record the process group the child `pid` leads.
    fn enter(pid: u32) -> Self {
        let slot = i32::try_from(pid)
            .ok()
            .filter(|pgid| *pgid > 0)
            .and_then(|pgid| {
                RUNNING_BUILDS.iter().find(|slot| {
                    slot.compare_exchange(0, pgid, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                })
            });
        RunningBuild(slot)
    }
}

#[cfg(unix)]
impl Drop for RunningBuild {
    fn drop(&mut self) {
        if let Some(slot) = self.0 {
            slot.store(0, Ordering::SeqCst);
        }
    }
}

/// Never return once an interrupt is ending the process
/// ([`kill_builds_on_interrupt`]).
fn park_if_interrupted() {
    while INTERRUPTED.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// End every build [`build_output_within`] is running and let it start no
/// other: for the host's interrupt handler (SIGINT, SIGTERM, SIGHUP), to
/// call BEFORE it releases the apply lock and lets the signal end the
/// process.
///
/// A build leads its own process group, so the signal that ends the CLI
/// does not reach it. Left alone it would go on compiling into a gem the
/// next run is free to lock and patch, with nothing bounding it any more.
/// Each recorded group is sent SIGKILL and waited for until no process of
/// it is left, for about two seconds at most (SIGKILL cannot be caught, so
/// a group lasts only as long as the kernel takes to tear it down and its
/// parents to reap it). The build's own child is reaped here.
///
/// Async-signal-safe: atomics, `kill`, `waitpid` and `poll` only. Off
/// Unix there is no group to signal (a console Ctrl-C reaches the build
/// itself); only the flag is set.
pub fn kill_builds_on_interrupt() {
    INTERRUPTED.store(true, Ordering::SeqCst);
    #[cfg(unix)]
    {
        let mut killed = [0; RUNNING_BUILD_SLOTS];
        for _ in 0..400 {
            let mut running = false;
            for (slot, sent_to) in RUNNING_BUILDS.iter().zip(&mut killed) {
                let pgid = slot.load(Ordering::SeqCst);
                if pgid > 0 && !end_build_group(pgid, sent_to) {
                    running = true;
                }
            }
            if !running {
                return;
            }
            // SAFETY: `poll` over no descriptors only waits, here 5 ms.
            unsafe {
                libc::poll(std::ptr::null_mut(), 0, 5);
            }
        }
    }
}

/// One pass of [`kill_builds_on_interrupt`] over the process group `pgid`:
/// SIGKILL it (once: `killed` remembers the group), reap its leader when
/// it has exited, and say whether no process of the group is left.
/// Async-signal-safe.
#[cfg(unix)]
fn end_build_group(pgid: i32, killed: &mut i32) -> bool {
    // SAFETY: plain syscalls on a process group this process created and
    // on its own child; no memory is shared with the callee but `status`.
    unsafe {
        if *killed != pgid {
            libc::kill(-pgid, libc::SIGKILL);
            *killed = pgid;
        }
        let mut status = 0;
        libc::waitpid(pgid, &mut status, libc::WNOHANG);
        let gone = libc::kill(-pgid, 0) != 0;
        if gone {
            // Where a zombie no longer counts as a member of its group
            // (macOS), the leader may have died since the wait above.
            libc::waitpid(pgid, &mut status, libc::WNOHANG);
        }
        gone
    }
}

/// The executable `name` on ABSOLUTE `PATH` entries only, or `None` when
/// no entry holds one.
///
/// Shared by every tool the CLI spawns from inside a scanned project
/// (`git`, `vlt`, `node`, `pipenv`, `hatch`): a relative `PATH`
/// component (`.`, an empty string) resolves against the child's cwd, so a
/// bare `Command::new("git")` would execute a `git` planted in the repository
/// being scanned — and on macOS `posix_spawnp` can run BOTH the planted
/// file and the next absolute entry's binary for one spawn. Skipping
/// non-absolute entries closes that; callers must then spawn the RESOLVED
/// path, never the bare name.
///
/// On Windows every `PATHEXT` extension is tried (falling back to
/// `.exe`/`.bat`/`.cmd` when the variable is unset or empty), so an npm-global
/// `vlt.cmd` / pyenv-win `pipenv.bat` shim is found where Rust's own
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

/// `name.exe` as a directory entry of any kind (an App Execution Alias is a
/// reparse point `is_file` can't follow) on an ABSOLUTE `PATH` entry, or
/// `None`. The Windows fallback when [`resolve_tool`] finds nothing; same
/// relative-entry rule, so a project-local executable is never chosen.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn resolve_app_alias_with(
    name: &str,
    var: &impl Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    let path = var("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(format!("{name}.exe")))
        .find(|candidate| std::fs::symlink_metadata(candidate).is_ok_and(|meta| !meta.is_dir()))
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
/// Every child process is made here, and none inherits a
/// [`CHILD_ENV_SCRUB`] variable: the Socket token in the CLI's own
/// environment is not for the programs it runs.
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
    let mut command = Command::new(program);
    scrub_child_env(&mut command);
    command
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

/// The real runner: spawns the binary, from a directory chosen by what the
/// probe asks about. Never from wherever the CLI happens to have been
/// started: a version manager's shim (rbenv, pyenv, asdf, mise) picks the
/// interpreter from the `.ruby-version` / `.python-version` /
/// `.tool-versions` of the directory it runs in.
///
/// * [`ProbeRunner::project`]: a question about one project (`gem env`
///   for its Gemfile, the Python whose site-packages hold its packages)
///   runs from that project's directory (`--cwd`).
/// * [`ProbeRunner::global`]: a question about the machine-wide install
///   (`npm root -g`, `gem env` and the system Python under `--global`)
///   runs from [`neutral_probe_dir`], so no project's files steer it.
///
/// The program is looked up with [`resolve_tool`] and the RESOLVED path is
/// spawned, never the bare name: on Windows `std` appends only `.exe`, so a
/// bare `Command::new("npm")` never finds the `npm.cmd` / `yarn.cmd` /
/// `gem.cmd` / `composer.bat` shim those tools install as, and every probe
/// silently answered "not installed". The lookup also skips relative `PATH`
/// entries, so a tool planted in the scanned project is never run.
///
/// stdin is null so the child can't block waiting for input. stdout is
/// captured; stderr is dropped (we don't surface CLI diagnostics — the
/// helpers fall back to other discovery paths on any failure).
#[derive(Debug, Clone)]
pub(crate) struct ProbeRunner {
    /// Where the child runs. `None`: no neutral directory could be
    /// determined, and the probe is not run at all.
    dir: Option<PathBuf>,
}

impl ProbeRunner {
    /// A probe about the project at `cwd`. Made absolute now, so the memo
    /// key built from [`Self::dir`] names one directory whatever the
    /// process's own working directory is later.
    pub(crate) fn project(cwd: &Path) -> Self {
        let dir = std::path::absolute(cwd).unwrap_or_else(|_| cwd.to_path_buf());
        Self { dir: Some(dir) }
    }

    /// A probe about the machine-wide install.
    pub(crate) fn global() -> Self {
        Self {
            dir: neutral_probe_dir(),
        }
    }

    /// The directory the child runs in.
    pub(crate) fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }
}

impl CommandRunner for ProbeRunner {
    fn run(&self, bin: &str, args: &[&str]) -> Option<String> {
        run_resolved(bin, args, self.dir.as_deref()?)
    }
}

/// [`ProbeRunner::global`] for a question about a package manager's GLOBAL
/// install (`npm root -g`, `yarn global dir`, ...): the child runs from
/// [`neutral_probe_dir`], never from the scanned project. From inside a
/// project the tool reads that project's configuration — Yarn Berry has no
/// `global` command and runs the project's `"global"` package.json script
/// instead, whose stdout then picked the directory scanned (and patched) as
/// the global install; a `.yarnrc.yml` `yarnPath` runs a project-supplied
/// JS file for any `yarn` call.
pub(crate) struct GlobalProbeRunner;

impl CommandRunner for GlobalProbeRunner {
    fn run(&self, bin: &str, args: &[&str]) -> Option<String> {
        ProbeRunner::global().run(bin, args)
    }
}

/// Where global probes run: the user's home directory (theirs, not a
/// checkout's, and never world-writable like the temp dir), else the root
/// of the current drive. `None` only when neither can be determined, and
/// then the probe is not run at all rather than run from the project.
pub(crate) fn neutral_probe_dir() -> Option<PathBuf> {
    neutral_probe_dir_with(&|var| std::env::var_os(var))
}

/// [`neutral_probe_dir`] over an injected environment reader (tests).
pub(crate) fn neutral_probe_dir_with(var: &impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let home = ["HOME", "USERPROFILE"]
        .into_iter()
        .filter_map(var)
        .map(PathBuf::from)
        .find(|path| path.is_absolute() && path.is_dir());
    home.or_else(|| {
        std::env::current_dir()
            .ok()?
            .ancestors()
            .last()
            .map(Path::to_path_buf)
    })
}

/// Spawn `bin` (looked up with [`resolve_tool`]; a value that already
/// names a path is spawned as given) with `args` from `cwd`, and return
/// its trimmed stdout under the [`CommandRunner`] contract.
fn run_resolved(bin: &str, args: &[&str], cwd: &Path) -> Option<String> {
    run_resolved_within(bin, args, cwd, PROBE_TIMEOUT)
}

/// [`run_resolved`] under an explicit budget (tests).
fn run_resolved_within(bin: &str, args: &[&str], cwd: &Path, budget: Duration) -> Option<String> {
    let program = if Path::new(bin).components().count() > 1 {
        PathBuf::from(bin)
    } else {
        match resolve_tool(bin) {
            Some(path) => path,
            // A Windows App Execution Alias (the Store `python3.exe` in
            // WindowsApps) is a reparse point the file probe can't stat;
            // look for it on absolute PATH entries only. Never hand the bare
            // name back to `std`: its Windows search also walks relative
            // PATH entries such as `.` (against the PARENT's cwd, before the
            // child's `current_dir` applies), so a `yarn.exe` planted in the
            // scanned project would run.
            None if cfg!(windows) => resolve_app_alias_with(bin, &|var| std::env::var_os(var))?,
            None => return None,
        }
    };
    let mut command = command_for(&program);
    command.args(args).current_dir(cwd);
    let output = match output_within(command, budget) {
        Ok(output) => output,
        Err(BoundedError::TimedOut) => {
            crate::utils::env_compat::debug_log(
                "debug",
                &format!(
                    "probe `{bin} {}` did not answer within {budget:?}; treating it as absent",
                    args.join(" ")
                ),
            );
            return None;
        }
        Err(BoundedError::Spawn(_)) => return None,
    };
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

/// What a probe subprocess inherits: the (sorted) environment and the
/// directory it runs in. Sorted so a `remove_var`/`set_var` round-trip that
/// restores an identical environment still matches (`vars_os` yields
/// `environ`'s order, which such a round-trip permutes).
pub(crate) type EnvKey = (Vec<(OsString, OsString)>, Option<PathBuf>);

/// The [`EnvKey`] of a probe run from `dir` right now.
pub(crate) fn env_key_in(dir: Option<&Path>) -> EnvKey {
    let mut vars: Vec<_> = std::env::vars_os().collect();
    vars.sort();
    (vars, dir.map(Path::to_path_buf))
}

/// A process-wide memo of one subprocess answer, reused only while the
/// whole environment (every variable, and the directory the subprocess
/// runs in) is exactly what it was when the answer was produced: the
/// subprocess's only inputs the CLI controls. A different environment
/// re-runs it and replaces the entry; concurrent first callers may each
/// run it.
///
/// Only an answer is kept. A failed probe (spawn error under fd pressure,
/// a non-zero exit, empty stdout) is asked again by the next caller, so a
/// transient first failure doesn't stick. Neither is an answer whose
/// environment differs, when the subprocess returns, from the one it was
/// keyed on: the key would misfile it.
pub(crate) struct EnvKeyedMemo<V> {
    slot: std::sync::Mutex<Option<(EnvKey, V)>>,
}

impl<V: Clone> EnvKeyedMemo<V> {
    pub(crate) const fn new() -> Self {
        Self {
            slot: std::sync::Mutex::new(None),
        }
    }

    /// The answer of `run`, a subprocess run from `dir`.
    pub(crate) fn get_or_run(
        &self,
        dir: Option<&Path>,
        run: impl FnOnce() -> Option<V>,
    ) -> Option<V> {
        self.get_or_run_keyed(env_key_in(dir), |ran_under| {
            let answer = run();
            // Keepable only if the environment is, once the subprocess
            // returns, still the one we keyed on.
            (answer, env_key_in(dir) == *ran_under)
        })
    }

    /// The memoized ask. On a miss, `run` gets the key it runs under and
    /// hands back its answer and whether that answer is keepable; a `None`
    /// answer is never kept. Split from [`Self::get_or_run`] so tests can
    /// drive it against a key of their own.
    fn get_or_run_keyed(
        &self,
        key: EnvKey,
        run: impl FnOnce(&EnvKey) -> (Option<V>, bool),
    ) -> Option<V> {
        let lock = || {
            self.slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        if let Some((cached_key, answer)) = lock().as_ref() {
            if *cached_key == key {
                return Some(answer.clone());
            }
        }
        let (answer, keepable) = run(&key);
        if let (Some(answer), true) = (&answer, keepable) {
            *lock() = Some((key, answer.clone()));
        }
        answer
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The memo re-runs only when the environment changed.
    #[test]
    fn env_keyed_memo_reuses_only_an_identical_environment() {
        let env = |path: &str| -> EnvKey {
            (
                vec![(OsString::from("PATH"), OsString::from(path))],
                Some(PathBuf::from("/cwd")),
            )
        };
        let memo = EnvKeyedMemo::new();
        let mut runs = 0;
        let mut run = |answer: Option<&str>| {
            runs += 1;
            (answer.map(str::to_string), true)
        };
        assert_eq!(
            memo.get_or_run_keyed(env("/a"), |_| run(Some("home"))),
            Some("home".into())
        );
        assert_eq!(
            memo.get_or_run_keyed(env("/a"), |_| run(Some("x"))),
            Some("home".into())
        );
        // A different environment misses and replaces the entry.
        assert_eq!(
            memo.get_or_run_keyed(env("/b"), |_| run(Some("other"))),
            Some("other".into())
        );
        assert_eq!(
            memo.get_or_run_keyed(env("/b"), |_| run(Some("x"))),
            Some("other".into())
        );
        assert_eq!(
            memo.get_or_run_keyed(env("/a"), |_| run(Some("again"))),
            Some("again".into())
        );
        assert_eq!(runs, 3);
    }

    /// A failed probe is not kept: the asker gets its own `None` and the
    /// next caller asks again. Neither is an answer the environment
    /// changed under.
    #[test]
    fn env_keyed_memo_asks_again_after_a_failed_probe() {
        let key: EnvKey = (
            vec![(OsString::from("PATH"), OsString::from("/a"))],
            Some(PathBuf::from("/cwd")),
        );
        let memo = EnvKeyedMemo::new();
        let runs = std::cell::Cell::new(0);
        let run = |answer: Option<&str>, keepable: bool| {
            runs.set(runs.get() + 1);
            (answer.map(str::to_string), keepable)
        };

        // A failure, then an answer whose environment moved: both are
        // handed back, neither is kept.
        assert_eq!(
            memo.get_or_run_keyed(key.clone(), |_| run(None, true)),
            None
        );
        assert_eq!(
            memo.get_or_run_keyed(key.clone(), |_| run(Some("moved"), false)),
            Some("moved".into())
        );
        assert_eq!(runs.get(), 2);

        // The next caller still asks, and a complete answer is kept.
        assert_eq!(
            memo.get_or_run_keyed(key.clone(), |_| run(Some("home"), true)),
            Some("home".into())
        );
        assert_eq!(
            memo.get_or_run_keyed(key.clone(), |_| run(None, true)),
            Some("home".into())
        );
        assert_eq!(runs.get(), 3);
    }

    /// The keep rule end to end: an answer computed while the real process
    /// environment changed is handed back but not kept, so the next ask
    /// in the original environment runs again.
    #[test]
    #[serial_test::serial]
    fn env_keyed_memo_drops_an_answer_the_environment_changed_under() {
        const VAR: &str = "SOCKET_PATCH_TEST_ENV_KEYED_MEMO_KEEP_RULE";
        std::env::remove_var(VAR);
        let memo = EnvKeyedMemo::new();
        let runs = std::cell::Cell::new(0);
        let answer = memo.get_or_run(None, || {
            runs.set(runs.get() + 1);
            std::env::set_var(VAR, "moved");
            Some("moved".to_string())
        });
        std::env::remove_var(VAR);
        assert_eq!(answer.as_deref(), Some("moved"));
        let fresh = || {
            runs.set(runs.get() + 1);
            Some("fresh".to_string())
        };
        assert_eq!(memo.get_or_run(None, fresh).as_deref(), Some("fresh"));
        assert_eq!(runs.get(), 2);
    }

    /// The memo key is order-insensitive: an environment restored to the
    /// same variables still hits, whatever order `vars_os` yields.
    #[test]
    fn env_key_is_sorted() {
        let (vars, _) = env_key_in(None);
        assert!(vars.windows(2).all(|w| w[0] <= w[1]), "sorted env snapshot");
    }

    /// An answer asked from one directory is not reused for another: a
    /// version manager's shim answers per directory.
    #[test]
    #[serial_test::serial]
    fn env_keyed_memo_asks_again_from_another_directory() {
        let memo = EnvKeyedMemo::new();
        let runs = std::cell::Cell::new(0);
        let ask = |dir: &str| {
            memo.get_or_run(Some(Path::new(dir)), || {
                runs.set(runs.get() + 1);
                Some(dir.to_string())
            })
        };
        assert_eq!(ask("/proj-a").as_deref(), Some("/proj-a"));
        assert_eq!(ask("/proj-a").as_deref(), Some("/proj-a"));
        assert_eq!(ask("/proj-b").as_deref(), Some("/proj-b"));
        assert_eq!(runs.get(), 2);
    }

    /// A project probe runs from the project directory, whatever the
    /// process's own working directory is, and a relative `--cwd` names
    /// that same directory in the memo key.
    #[cfg(unix)]
    #[test]
    fn a_project_probe_runs_from_the_project_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let project = std::fs::canonicalize(tmp.path()).unwrap();
        assert_ne!(std::env::current_dir().unwrap(), project);
        let runner = ProbeRunner::project(&project);
        assert_eq!(runner.dir(), Some(project.as_path()));
        let ran_from = runner.run("sh", &["-c", "pwd -P"]).expect("sh runs");
        assert_eq!(Path::new(&ran_from), project);

        let relative = ProbeRunner::project(Path::new("."));
        assert!(
            relative.dir().is_some_and(Path::is_absolute),
            "{relative:?}"
        );
    }

    /// A global probe runs from the neutral directory, never from the
    /// process's working directory. `#[serial]`: it reads `HOME`, which
    /// other env tests in this binary swap.
    #[cfg(unix)]
    #[test]
    #[serial_test::serial]
    fn a_global_probe_runs_from_the_neutral_dir() {
        let runner = ProbeRunner::global();
        let neutral = neutral_probe_dir().expect("a home dir or the drive root");
        assert_eq!(runner.dir(), Some(neutral.as_path()));
        let ran_from = runner.run("sh", &["-c", "pwd -P"]).expect("sh runs");
        assert_eq!(
            Path::new(&ran_from),
            std::fs::canonicalize(&neutral).unwrap()
        );
        assert_eq!(
            GlobalProbeRunner.run("sh", &["-c", "pwd -P"]).as_deref(),
            Some(ran_from.as_str())
        );
    }

    /// Confirm the real runner returns Some for a tiny command we
    /// know is on every Unix PATH — `echo`. Skipped on Windows where
    /// `echo` isn't a real binary.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_stdout_for_real_binary() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("echo", &["hello"]).expect("echo should succeed");
        assert_eq!(out, "hello");
    }

    /// A probe that never answers (a wedged `gem` shim) is killed at the
    /// budget and answers "no information" instead of hanging the crawl.
    /// On `main` `run_resolved` waited on `output()` with no deadline.
    #[cfg(unix)]
    #[test]
    fn a_hung_probe_answers_none_within_its_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let shim = tmp.path().join("gem");
        std::fs::write(&shim, "#!/bin/sh\nexec sleep 30\n").unwrap();
        set_executable(&shim);
        let start = Instant::now();
        let out = run_resolved_within(
            shim.to_str().unwrap(),
            &["env", "gemdir"],
            tmp.path(),
            Duration::from_millis(300),
        );
        assert_eq!(out, None);
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the budget must bound the probe, took {:?}",
            start.elapsed()
        );
    }

    /// A shim that forks its child (no `exec`) leaves a grandchild holding
    /// stdout after the shim is killed: the deadline still returns.
    #[cfg(unix)]
    #[test]
    fn output_within_does_not_wait_for_a_grandchild_holding_stdout() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30; echo late"]);
        let start = Instant::now();
        let result = output_within(command, Duration::from_millis(300));
        assert!(matches!(result, Err(BoundedError::TimedOut)), "{result:?}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
    }

    /// The bounded spawn keeps the `output()` contract the former callers
    /// relied on: stdout captured, stderr dropped, exit status reported,
    /// stdin null, a missing program surfaced as a spawn error.
    #[cfg(unix)]
    #[test]
    fn output_within_reports_status_stdout_and_spawn_errors() {
        let mut ok = Command::new("sh");
        ok.args(["-c", "printf out; printf err >&2"]);
        let output = output_within(ok, PROBE_TIMEOUT).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"out");
        assert!(output.stderr.is_empty());

        let mut failing = Command::new("sh");
        failing.args(["-c", "printf partial; exit 3"]);
        let output = output_within(failing, PROBE_TIMEOUT).unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, b"partial");

        let mut reads_stdin = Command::new("sh");
        reads_stdin.args(["-c", "cat; printf done"]);
        let output = output_within(reads_stdin, PROBE_TIMEOUT).unwrap();
        assert_eq!(output.stdout, b"done", "stdin is null, so `cat` sees EOF");

        let missing = Command::new("/definitely/not/a/real/binary-1234567");
        assert!(matches!(
            output_within(missing, PROBE_TIMEOUT),
            Err(BoundedError::Spawn(_))
        ));
    }

    /// The build spawn keeps stderr (the compiler's diagnostic) as well as
    /// stdout and the exit status, with stdin null.
    #[cfg(unix)]
    #[test]
    fn build_output_within_keeps_stderr_and_status() {
        let mut failing = Command::new("sh");
        failing.args(["-c", "cat; printf out; printf err >&2; exit 2"]);
        let output = build_output_within(failing, PROBE_TIMEOUT).unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
        let missing = Command::new("/definitely/not/a/real/binary-1234567");
        assert!(matches!(
            build_output_within(missing, PROBE_TIMEOUT),
            Err(BoundedError::Spawn(_))
        ));
    }

    /// At the deadline the whole process group goes: a grandchild the
    /// build started (a `make` / `cc`) does not outlive it.
    #[cfg(unix)]
    #[test]
    fn build_output_within_kills_the_process_group_at_the_deadline() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("grandchild.pid");
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "sleep 30 & echo $! > '{}'; wait",
            pid_file.display()
        ));
        let start = Instant::now();
        let result = build_output_within(command, Duration::from_millis(500));
        assert!(matches!(result, Err(BoundedError::TimedOut)), "{result:?}");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // The killed grandchild is reaped by init shortly after; signal 0
        // probes whether it still exists.
        let gone = (0..100).any(|_| {
            // SAFETY: signal 0 only checks the pid; nothing is delivered.
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if alive {
                std::thread::sleep(Duration::from_millis(20));
            }
            !alive
        });
        assert!(gone, "the grandchild {pid} outlived the deadline");
    }

    /// Wait until `file` holds a pid, and read it.
    #[cfg(unix)]
    fn pid_written_to(file: &Path) -> i32 {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let pid = std::fs::read_to_string(file)
                .ok()
                .and_then(|text| text.trim().parse::<i32>().ok());
            if let Some(pid) = pid {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "{} was never written",
                file.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// While a build runs, its process group is on record for the
    /// interrupt handler, and off it again once the build is over.
    #[cfg(unix)]
    #[test]
    fn a_running_build_is_on_record_for_the_interrupt_handler() {
        let on_record = |pgid: i32| {
            RUNNING_BUILDS
                .iter()
                .any(|slot| slot.load(Ordering::SeqCst) == pgid)
        };
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("build.pid");
        let done_file = tmp.path().join("done");
        // The build runs until told to finish, so the checks below never
        // race its end.
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "echo $$ > '{}'; until [ -e '{}' ]; do sleep 0.05; done",
            pid_file.display(),
            done_file.display()
        ));
        let build =
            std::thread::spawn(move || build_output_within(command, Duration::from_secs(120)));
        let pgid = pid_written_to(&pid_file);
        // The child can write its pid before the spawning thread has put
        // the group on record.
        let deadline = Instant::now() + Duration::from_secs(30);
        while !on_record(pgid) {
            assert!(
                Instant::now() < deadline,
                "the running build {pgid} is not on record"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::write(&done_file, b"").unwrap();
        assert!(build.join().unwrap().unwrap().status.success());
        assert!(
            !on_record(pgid),
            "the finished build {pgid} is still on record"
        );
    }

    /// What the interrupt handler does to a build on record: the whole
    /// process group is killed, the build's own child reaped, and the pass
    /// reports the group gone only once no process of it is left, so the
    /// lock is not released over a compiler that is still running. (The
    /// handler itself is not run here: it marks the process as ending.)
    #[cfg(unix)]
    #[test]
    fn an_interrupt_pass_ends_the_whole_build_group() {
        use std::os::unix::process::CommandExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("compiler.pid");
        let mut build = Command::new("sh");
        build
            .arg("-c")
            .arg(format!(
                "sleep 30 & echo $! > '{}'; wait",
                pid_file.display()
            ))
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = build.spawn().unwrap();
        let pgid = i32::try_from(child.id()).unwrap();
        let compiler = pid_written_to(&pid_file);

        let mut killed = 0;
        let start = Instant::now();
        while !end_build_group(pgid, &mut killed) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the build group {pgid} outlived SIGKILL"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(killed, pgid);
        // Dead already; as a zombie it still answers signal 0 until init
        // reaps it (macOS does not count zombies in the group).
        let gone = (0..100).any(|_| {
            // SAFETY: signal 0 only checks the pid; nothing is delivered.
            let alive = unsafe { libc::kill(compiler, 0) } == 0;
            if alive {
                std::thread::sleep(Duration::from_millis(20));
            }
            !alive
        });
        assert!(gone, "the build's compiler {compiler} is still there");
        assert!(
            child.try_wait().is_err(),
            "the pass reaped the build's child itself"
        );
    }

    /// Spawn failure → None. The binary name is intentionally one
    /// that should never be on PATH.
    #[test]
    fn system_runner_returns_none_on_spawn_failure() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("definitely-not-a-real-binary-1234567", &[]);
        assert_eq!(out, None);
    }

    /// Non-zero exit → None. `false`(1) is in coreutils everywhere.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_none_on_non_zero_exit() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("false", &[]);
        assert_eq!(out, None);
    }

    /// Exit 0 but stdout is empty → None. This is the fourth arm of
    /// the contract. A successful command
    /// that prints nothing carries no information for the crawlers.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_none_on_empty_stdout_despite_success() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("true", &[]);
        assert_eq!(out, None);
    }

    /// Exit 0 with whitespace-only stdout → None: the empty check
    /// happens *after* trimming, so a command that prints only spaces
    /// and newlines is treated as "no output".
    #[cfg(unix)]
    #[test]
    fn system_runner_treats_whitespace_only_stdout_as_empty() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("sh", &["-c", "printf '  \\t\\n  '"]);
        assert_eq!(out, None);
    }

    /// Surrounding whitespace is trimmed from a non-empty result, so
    /// callers that join the value into a path don't get stray
    /// newlines (e.g. `npm root -g` emits a trailing `\n`).
    #[cfg(unix)]
    #[test]
    fn system_runner_trims_surrounding_whitespace() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("sh", &["-c", "printf '  /some/path  \\n'"]);
        assert_eq!(out.as_deref(), Some("/some/path"));
    }

    /// stderr never leaks into the result. When stdout is empty but
    /// the process wrote to stderr and still exited 0, the result is
    /// None — stderr is captured and dropped, not returned.
    #[cfg(unix)]
    #[test]
    fn system_runner_ignores_stderr_when_stdout_empty() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("sh", &["-c", "printf 'diagnostic' >&2"]);
        assert_eq!(out, None);
    }

    /// When a command writes to both streams, only stdout comes back —
    /// the stderr line must not be appended or interleaved.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_only_stdout_when_both_streams_used() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("sh", &["-c", "printf 'good\\n'; printf 'bad\\n' >&2"]);
        assert_eq!(out.as_deref(), Some("good"));
    }

    /// Every element of `args` is forwarded to the child in order.
    /// Here `$0` is `sh` and `$1` is `forwarded`; printing `$1` proves
    /// positional args survive the hop into `Command::args`.
    #[cfg(unix)]
    #[test]
    fn system_runner_forwards_all_args_in_order() {
        let runner = ProbeRunner::project(Path::new("."));
        let out = runner.run("sh", &["-c", "printf '%s' \"$1\"", "sh", "forwarded"]);
        assert_eq!(out.as_deref(), Some("forwarded"));
    }

    /// Global probes run from the home dir; a relative or missing HOME is
    /// never used (it would resolve against the project), and with no
    /// usable home the probe falls back to the drive root, not the cwd.
    #[test]
    fn neutral_probe_dir_prefers_an_absolute_home_and_never_the_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        let env = |name: &str| (name == "HOME").then(|| home.clone().into_os_string());
        assert_eq!(neutral_probe_dir_with(&env), Some(home.clone()));

        let profile = |name: &str| match name {
            "HOME" => Some(OsString::from("relative/home")),
            "USERPROFILE" => Some(home.clone().into_os_string()),
            _ => None,
        };
        assert_eq!(neutral_probe_dir_with(&profile), Some(home.clone()));

        let none = |_: &str| None::<OsString>;
        let root = neutral_probe_dir_with(&none).expect("the drive root");
        assert!(root.is_absolute() && root.parent().is_none(), "{root:?}");
    }

    // ───────────────────────── child environment ─────────────────────────

    /// A Socket token under the names CI exports it, and the package
    /// managers' own settings beside it.
    #[cfg(unix)]
    const SECRET: &str = "sktsec_child_env_marker";
    #[cfg(unix)]
    const SOCKET_SECRETS: &[&str] = &[
        "SOCKET_API_TOKEN",
        "SOCKET_CLI_API_TOKEN",
        "SOCKET_SECURITY_API_TOKEN",
    ];
    #[cfg(unix)]
    const TOOL_SETTINGS: &[(&str, &str)] = &[
        ("NPM_TOKEN", "registry-auth"),
        ("HTTPS_PROXY", "http://proxy.example:3128"),
        ("NO_PROXY", "localhost"),
    ];

    /// `env`, with the token and the tool settings set on the command the
    /// way a caller that rebuilds the child's environment from the ambient
    /// one hands them over (the PDM site probe: `env_clear().envs(..)`).
    #[cfg(unix)]
    fn env_with_a_socket_token() -> Command {
        let env_bin = resolve_tool("env").expect("`env` is on PATH");
        let mut command = command_for(&env_bin);
        command.env_clear();
        for name in SOCKET_SECRETS {
            command.env(name, SECRET);
        }
        command.envs(TOOL_SETTINGS.iter().copied());
        command
    }

    #[cfg(unix)]
    fn assert_no_socket_token(what: &str, output: &Output) {
        let seen = String::from_utf8_lossy(&output.stdout);
        assert!(
            !seen.contains(SECRET) && !SOCKET_SECRETS.iter().any(|name| seen.contains(name)),
            "{what}: the child saw a Socket credential:\n{seen}"
        );
        for (name, value) in TOOL_SETTINGS {
            assert!(
                seen.lines().any(|line| line == format!("{name}={value}")),
                "{what}: the child lost {name}, which its package manager needs:\n{seen}"
            );
        }
    }

    /// No spawned child sees the Socket token, whichever spawn runs it and
    /// however its environment was put together; a package manager's own
    /// proxy and registry settings still reach it.
    #[cfg(unix)]
    #[test]
    fn spawned_children_do_not_see_socket_credentials() {
        let probe = output_within(env_with_a_socket_token(), PROBE_TIMEOUT).unwrap();
        assert_no_socket_token("output_within", &probe);
        let build = build_output_within(env_with_a_socket_token(), PROBE_TIMEOUT).unwrap();
        assert_no_socket_token("build_output_within", &build);
    }

    /// A command no bounded spawn runs (the `git` pipe) drops the ambient
    /// token too: `command_for` removes it when the command is made.
    #[test]
    fn command_for_drops_the_inherited_socket_credentials() {
        let command = command_for(Path::new("/x/git"));
        let removed: Vec<_> = command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect();
        for name in [
            "SOCKET_API_TOKEN",
            "SOCKET_CLI_API_TOKEN",
            "SOCKET_SECURITY_API_TOKEN",
        ] {
            assert!(
                removed.iter().any(|r| r == name),
                "{name} is inherited: {removed:?}"
            );
        }
        assert_eq!(removed.len(), CHILD_ENV_SCRUB.len(), "the whole list goes");
        assert!(
            command.get_envs().all(|(_, value)| value.is_none()),
            "nothing is set"
        );
    }

    /// The scrub list names every accepted socket-cli alias and its
    /// canonical name, each once, and nothing but `SOCKET_*` names: a proxy
    /// or registry credential of the package manager's is never on it.
    #[test]
    fn the_scrub_list_covers_the_peer_aliases_and_only_socket_names() {
        for (canonical, alias) in crate::utils::env_compat::PEER_ENV_ALIASES {
            for name in [canonical, alias] {
                assert!(
                    CHILD_ENV_SCRUB.contains(name),
                    "{name} is read as Socket configuration but reaches child processes"
                );
            }
        }
        let mut sorted = CHILD_ENV_SCRUB.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            CHILD_ENV_SCRUB.len(),
            "a name is listed twice"
        );
        for name in CHILD_ENV_SCRUB {
            assert!(
                name.starts_with("SOCKET_")
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "{name} is not a Socket variable"
            );
        }
    }

    // ───────────────────────── resolve_tool / command_for ─────────────────────────

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

    /// Run a command whose program this test just wrote, tolerating
    /// `ETXTBSY`. `fs::write` closed our handle, but tests run on parallel
    /// threads: a sibling that forks between our `open` and its own `exec`
    /// inherits the still-open write fd, and exec'ing the shim in that window
    /// fails with "Text file busy" (os error 26). That is a fork/exec race,
    /// not a property of the shim, so retry only that error, briefly — the
    /// same pattern as `sanity_exec` and the CLI's `exec_freshly_written`.
    #[cfg(unix)]
    pub(crate) fn output_of_fresh_shim(make: impl Fn() -> Command) -> Output {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match make().output() {
                Ok(out) => return out,
                Err(e)
                    if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("spawn the shim: {e:?}"),
            }
        }
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
    /// The Windows App Execution Alias fallback takes the same absolute-only
    /// rule as `resolve_tool`: a `yarn.exe` reached only through a relative
    /// entry (`.`, the empty component, a bare dir name) is never chosen;
    /// one on an absolute entry is.
    #[test]
    fn resolve_app_alias_skips_relative_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let safe = tmp.path().join("bin");
        std::fs::create_dir_all(&safe).unwrap();
        let relative = [
            PathBuf::from("."),
            PathBuf::from(""),
            PathBuf::from("planted"),
        ];

        let only_relative = std::env::join_paths(&relative).unwrap();
        let var = |name: &str| (name == "PATH").then(|| only_relative.clone());
        assert_eq!(resolve_app_alias_with("yarn", &var), None);

        std::fs::write(safe.join("yarn.exe"), b"").unwrap();
        let with_safe =
            std::env::join_paths(relative.iter().cloned().chain([safe.clone()])).unwrap();
        let var = |name: &str| (name == "PATH").then(|| with_safe.clone());
        assert_eq!(
            resolve_app_alias_with("yarn", &var),
            Some(safe.join("yarn.exe"))
        );
    }

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
        let out = output_of_fresh_shim(|| command_for(&program));
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
}
