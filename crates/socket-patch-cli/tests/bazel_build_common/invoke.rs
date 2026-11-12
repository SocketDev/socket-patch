//! Finding the Bazel to drive and building every invocation of it: the
//! startup options that keep a run inside its [`Scratch`], the scrubbed
//! environment, and the command options that differ per Bazel line.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use super::env::{self, System, Version};
use super::isolation::Scratch;
use crate::common::hermetic;

/// The Bazel a cell drives.
pub struct Bazel {
    /// The program spawned: a Bazel release binary, or a launcher.
    pub program: OsString,
    pub version: Version,
    /// The program is known to be bazelisk: the launcher cell, or a file
    /// whose name says so. Bazelisk creates its home directory on every
    /// run, `--version` included, so it then gets a scratch
    /// `BAZELISK_HOME`. A launcher that is not known to be bazelisk (a
    /// wrapper script with its own contained home) gets every `BAZELISK_*`
    /// removed instead; `bazel_core_launch_isolated` fails if such a
    /// launcher writes bazelisk's default home.
    pub bazelisk: bool,
    /// What the child's `USE_BAZEL_VERSION` is set to: the pinned version,
    /// or for the launcher cell the absolute path of the release binary.
    pub use_version: Option<OsString>,
}

impl Bazel {
    /// Probe [`env::BAZEL`] (`bazel --version`, answered by the client: no
    /// server starts). `Err` = this machine cannot run the test, and why.
    pub fn detect(scratch: &Scratch) -> Result<Bazel, String> {
        // Unset: `bazel` on PATH, resolved the way the CLI resolves a tool
        // (every PATHEXT extension on Windows) and to a full path, so a
        // `bazel` that is a link to bazelisk is seen for what it is.
        let on_path = || {
            let found = socket_patch_core::utils::process::resolve_tool("bazel");
            found.map_or_else(|| "bazel".into(), PathBuf::into_os_string)
        };
        let program = env::var(env::BAZEL).map_or_else(on_path, absolute_program);
        let bazelisk = named_bazelisk(Path::new(&program));
        Self::probe(scratch, program, bazelisk, env::var(env::VERSION))
    }

    /// The launcher cell: the pinned bazelisk of [`env::BAZELISK`] running
    /// the release binary of [`env::BINARY`], which it uses directly with
    /// no download and no version lookup.
    pub fn detect_launcher(scratch: &Scratch) -> Result<Bazel, String> {
        let (Some(program), Some(binary)) = (env::var(env::BAZELISK), env::var(env::BINARY)) else {
            return Err(format!(
                "{} and {} are not both set",
                env::BAZELISK,
                env::BINARY
            ));
        };
        assert!(
            Path::new(&binary).is_absolute(),
            "{} must be an absolute path: bazelisk treats anything else as a version to download",
            env::BINARY
        );
        Self::probe(scratch, absolute_program(program), true, Some(binary))
    }

    fn probe(
        scratch: &Scratch,
        program: OsString,
        bazelisk: bool,
        use_version: Option<OsString>,
    ) -> Result<Bazel, String> {
        let shown = program.to_string_lossy().into_owned();
        let out = environment(&program, bazelisk, use_version.as_deref(), scratch)
            .arg("--version")
            .output()
            .map_err(|e| format!("`{shown}` did not run: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let Some(text) = stdout.lines().find_map(|l| l.trim().strip_prefix("bazel ")) else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "`{shown} --version` printed no `bazel <v>` line:\n{stdout}{stderr}"
            ));
        };
        if let Some(pin) = env::var(env::VERSION) {
            assert_eq!(
                text,
                pin.to_string_lossy(),
                "{} pins Bazel {} but `{shown}` is Bazel {text}",
                env::VERSION,
                pin.to_string_lossy()
            );
        }
        let version = Version::parse(text)
            .unwrap_or_else(|| panic!("`{shown} --version` printed an unreadable version: {text}"));
        scratch.assert_path_supported(&version);
        Ok(Bazel {
            program,
            version,
            bazelisk,
            use_version,
        })
    }

    /// The startup options of every invocation. They never vary within a
    /// test: a different `--host_jvm_args` restarts the server. Without the
    /// two JVM options the server writes `hsperfdata_<user>`, `bazel-jni.<N>`
    /// and a netty library into the shared temp directory, and 10.0.0rc3
    /// exits 37 when that directory is not writable.
    pub fn startup_args(&self, scratch: &Scratch) -> Vec<OsString> {
        let path = |flag: &str, path: &Path| {
            let mut arg = OsString::from(flag);
            arg.push(path);
            arg
        };
        vec![
            "--nohome_rc".into(),
            "--nosystem_rc".into(),
            path("--output_user_root=", &scratch.output_user_root),
            "--max_idle_secs=15".into(),
            path("--host_jvm_args=-Djava.io.tmpdir=", &scratch.tmp),
            "--host_jvm_args=-XX:-UsePerfData".into(),
        ]
    }

    /// `bazel <startup options> <command>` in the workspace copy, ready
    /// for the command's own options. The workspace `.bazelrc` stays
    /// active: socket-patch's model reads it.
    pub fn command(&self, scratch: &Scratch, command: &str) -> Command {
        let mut cmd = environment(
            &self.program,
            self.bazelisk,
            self.use_version.as_deref(),
            scratch,
        );
        cmd.current_dir(&scratch.workspace)
            .args(self.startup_args(scratch))
            .arg(command);
        cmd
    }
}

/// A program named by a path (anything with a separator) made absolute
/// against this process's working directory; a bare name is left for
/// `PATH`. The `--version` probe runs from the test's directory and every
/// later command from the workspace copy, so a relative path would answer
/// the probe and then fail to spawn.
pub fn absolute_program(program: OsString) -> OsString {
    let path = Path::new(&program);
    if path.is_absolute() || path.components().count() < 2 {
        return program;
    }
    let absolute = std::path::absolute(path);
    absolute.map_or(program, PathBuf::into_os_string)
}

/// The program with the isolated environment and no arguments. Built
/// on `hermetic::command`, the one way this crate's tests spawn a
/// child; everything set here lands after its scrub.
fn environment(
    program: &std::ffi::OsStr,
    bazelisk: bool,
    use_version: Option<&std::ffi::OsStr>,
    scratch: &Scratch,
) -> Command {
    let mut cmd = hermetic::command(Path::new(program));
    for name in env::REMOVED {
        cmd.env_remove(name);
    }
    for name in env::PROXY {
        cmd.env_remove(name);
        cmd.env_remove(name.to_ascii_lowercase());
    }
    // A scratch HOME does not move bazelisk's home (it is under
    // ~/Library/Caches or %LocalAppData%), and its other variables
    // change which Bazel runs.
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("BAZELISK_") {
            cmd.env_remove(name);
        }
    }
    cmd.env_remove("BAZELISK_HOME");
    if bazelisk {
        cmd.env("BAZELISK_HOME", &scratch.bazelisk_home);
    }
    if let Some(version) = use_version {
        cmd.env("USE_BAZEL_VERSION", version);
    }
    cmd.env("HOME", &scratch.home)
        .env("USERPROFILE", &scratch.home)
        .env("TMPDIR", &scratch.tmp)
        .env("TMP", &scratch.tmp)
        .env("TEMP", &scratch.tmp)
        // A ruleset tool that pins (Coursier) otherwise writes the
        // user's own cache.
        .env("COURSIER_CACHE", scratch.home.join("coursier"))
        // rules_js 2.9.3 and aspect_rules_py pull in a telemetry module
        // that otherwise uploads the Bazel and module versions.
        .env("DO_NOT_TRACK", "1")
        // A launcher may export TEST_TMPDIR itself (to contain a nested
        // Bazel). The server then runs in test mode; these two keep a
        // failing extension an error there instead of a crash.
        .env("ENABLE_BUG_REPORT_LOGGING_IN_TEST", "1")
        .env("NO_CRASH_ON_LOGGING_IN_TEST", "1");
    if cfg!(windows) && std::env::var_os("BAZEL_SH").is_none() {
        // Otherwise Bazel takes the first bash.exe on PATH, which on a
        // hosted runner is WSL's.
        let bash = [
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\msys64\usr\bin\bash.exe",
        ];
        if let Some(bash) = bash.iter().find(|p| Path::new(p).is_file()) {
            cmd.env("BAZEL_SH", bash);
        }
    }
    cmd
}

/// Whether `program` is a file named like bazelisk, links followed
/// (Homebrew installs `bazel` as a link to `bazelisk`).
pub fn named_bazelisk(program: &Path) -> bool {
    let resolved = program
        .canonicalize()
        .unwrap_or_else(|_| program.to_path_buf());
    [program, resolved.as_path()].iter().any(|path| {
        path.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .to_ascii_lowercase()
                .contains("bazelisk")
        })
    })
}

/// The command options of a cell, beyond the startup set.
#[derive(Clone, Debug)]
pub struct Options {
    /// The dependency system the fixture is written for; `None` = the
    /// line's default flags (a launch or rc test that has no fixture).
    pub system: Option<System>,
    /// Always stated on 6.2 and later, so a test never depends on a
    /// line's default (`off` on 6.x, `update` from 7).
    pub lockfile_mode: &'static str,
    /// The downloader config of the fixture server, when the cell has one.
    pub downloader_config: Option<PathBuf>,
    /// Extra `--repo_env=NAME=VALUE` pairs (`GOPROXY` for gazelle, ...).
    pub repo_env: Vec<(String, String)>,
    /// Leave the repository contents cache (8.3+) at the line's default.
    /// Only the canary that tests the cache itself sets this: with the
    /// cache on, fetched repositories are shared between workspaces.
    pub contents_cache: bool,
    /// `--experimental_repository_downloader_retries=0`, for a cell that
    /// expects a fetch to fail.
    pub no_retries: bool,
    /// The proxies of every child point at a closed port (the offline
    /// phase): only a loopback fixture server stays reachable.
    pub closed_proxies: bool,
    /// `--registry=`: where Bzlmod resolves modules, in place of the Bazel
    /// Central Registry. The `file://` URL of the committed subset
    /// (`fixtures/bazel/registry`) makes resolution read no network.
    pub registry: Option<String>,
    /// `--distdir=`: a directory Bazel takes an archive from, by file name
    /// and checksum, before it downloads one. Bazel consults it only for a
    /// download the downloader config leaves a URL for, which the rewrite
    /// does and `block *` does not.
    pub distdir: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            system: None,
            lockfile_mode: "update",
            downloader_config: None,
            repo_env: Vec::new(),
            contents_cache: false,
            no_retries: false,
            closed_proxies: false,
            registry: None,
            distdir: None,
        }
    }
}

impl Options {
    /// The command options for `bazel` in `scratch`, or why this line
    /// cannot run the cell.
    pub fn args(&self, bazel: &Bazel, scratch: &Scratch) -> Result<Vec<OsString>, String> {
        let version = &bazel.version;
        let mut args: Vec<OsString> = vec!["--color=no".into(), "--curses=no".into()];
        let mut joined = |flag: &str, value: &std::ffi::OsStr| {
            let mut arg = OsString::from(flag);
            arg.push(value);
            args.push(arg);
        };
        joined("--repository_cache=", scratch.repository_cache.as_os_str());
        let mut home = OsString::from("HOME=");
        home.push(&scratch.home);
        joined("--repo_env=", &home);
        for (name, value) in &self.repo_env {
            joined("--repo_env=", format!("{name}={value}").as_ref());
        }
        if let Some(config) = &self.downloader_config {
            let flag = format!("{}=", version.downloader_config_flag());
            joined(&flag, config.as_os_str());
        }
        if let Some(registry) = &self.registry {
            joined("--registry=", registry.as_ref());
        }
        if let Some(distdir) = &self.distdir {
            joined("--distdir=", distdir.as_os_str());
        }
        if let Some(system) = self.system {
            let flags = version.system_flags(system).ok_or_else(|| {
                format!(
                    "Bazel {} has no {} dependency system",
                    version.text,
                    system.name()
                )
            })?;
            args.extend(flags.iter().map(OsString::from));
        }
        if version.has_lockfile_mode() {
            args.push(format!("--lockfile_mode={}", self.lockfile_mode).into());
        }
        if version.has_contents_cache() && !self.contents_cache {
            args.push("--repo_contents_cache=".into());
        }
        if self.no_retries {
            args.push("--experimental_repository_downloader_retries=0".into());
        }
        args.extend(env::extra_args().into_iter().map(OsString::from));
        Ok(args)
    }

    /// The proxy environment of the offline phase, applied after the scrub.
    pub fn apply_env(&self, cmd: &mut Command) {
        if self.closed_proxies {
            for name in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
                cmd.env(name, "http://127.0.0.1:9");
                cmd.env(name.to_ascii_lowercase(), "http://127.0.0.1:9");
            }
            cmd.env("NO_PROXY", "127.0.0.1,localhost");
            cmd.env("no_proxy", "127.0.0.1,localhost");
        }
    }
}

/// One finished Bazel command.
pub struct Run {
    /// The command line, for failure messages.
    pub line: String,
    pub output: Output,
    pub wall: Duration,
}

impl Run {
    /// Spawn `cmd` and wait. A spawn failure is a harness failure: the
    /// program already answered `--version`.
    pub fn of(cmd: Command) -> Run {
        Self::try_of(cmd).unwrap_or_else(|why| panic!("{why}"))
    }

    /// [`Run::of`] for a caller that must not panic (a `Drop` guard).
    pub fn try_of(mut cmd: Command) -> Result<Run, String> {
        let line = format!("{cmd:?}");
        let started = Instant::now();
        let output = cmd.output().map_err(|e| format!("spawn {line}: {e}"))?;
        Ok(Run {
            line,
            output,
            wall: started.elapsed(),
        })
    }

    pub fn ok(&self) -> bool {
        self.output.status.success()
    }

    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }

    pub fn dump(&self) -> String {
        format!(
            "{}\nexit {:?} after {:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.line,
            self.output.status.code(),
            self.wall,
            self.stdout(),
            self.stderr()
        )
    }

    /// The command failed because a host it needed did not answer, as
    /// opposed to failing on what the host served. Such a failure is a
    /// SKIP on a developer's machine and a failure on a required cell.
    pub fn origin_unreachable(&self) -> bool {
        !self.ok() && names_an_unreachable_origin(&self.stderr())
    }
}

/// Whether a failed command's stderr says a host did not answer. Bazel's
/// own downloader words it the Java way; a tool a repository rule runs
/// (cargo under the crate_universe splice, anything on libcurl) words it
/// as curl does: `[6] Couldn't resolve host name (Could not resolve
/// host: index.crates.io)`.
pub fn names_an_unreachable_origin(stderr: &str) -> bool {
    const SIGNS: &[&str] = &[
        "Unknown host",
        "UnknownHostException",
        "connect timed out",
        "Connection timed out",
        "Connection refused",
        "Network is unreachable",
        "Temporary failure in name resolution",
        "Could not resolve host",
        "Couldn't resolve host",
    ];
    SIGNS.iter().any(|sign| stderr.contains(sign))
}
