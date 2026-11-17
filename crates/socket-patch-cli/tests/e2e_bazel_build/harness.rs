//! What every real-Bazel test shares: the variables that configure a run,
//! the scratch root that holds everything one Bazel writes, the Bazel
//! command line, and the `socket-patch` child that runs in the workspace
//! copy.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

use crate::fs_tree;
use crate::hosted_memory_common::{hermetic, read_tree, ORG};

/// The Bazel binary or launcher to run, by absolute path: every child runs
/// in the workspace copy. Unset: `bazel` on `PATH`.
pub const BAZEL: &str = "SOCKET_PATCH_BAZEL_E2E_BAZEL";
/// Non-empty: a test that cannot run here (no Bazel, or another release)
/// fails. Unset: it prints `SKIP <why>` and passes.
pub const REQUIRED: &str = "SOCKET_PATCH_BAZEL_E2E_REQUIRED";
/// A repository cache shared by the tests of a run, so that only the first
/// downloads the rulesets and the toolchain. Unset: an empty one per test.
pub const REPO_CACHE: &str = "SOCKET_PATCH_BAZEL_E2E_REPO_CACHE";
/// Another `socket-patch` binary to hold the same tests against (a
/// release), by absolute path. Unset: the binary cargo built for this run.
pub const SOCKET_BIN: &str = "SOCKET_PATCH_BAZEL_E2E_SOCKET_BIN";

/// Removed from every Bazel child. `TEST_TMPDIR` puts a Bazel server in
/// test mode, where a failing module extension on 7.x is a crash (exit 37)
/// instead of an error. `USE_BAZEL_VERSION` is set again from the test's
/// release. `XDG_CACHE_HOME` would move a tool's cache out of the scratch
/// home. The CI markers change what some rulesets do, and a test must do
/// the same on a runner and on a developer's machine.
const REMOVED: &[&str] = &[
    "TEST_TMPDIR",
    "USE_BAZEL_VERSION",
    "XDG_CACHE_HOME",
    "CI",
    "GITHUB_ACTIONS",
];

/// The label every fixture builds: a binary that prints one `OUT: ...` line
/// from the package under test.
pub const CONSUMER: &str = "//:consumer";

/// Nothing listens there: a request the `socket-patch` child sends anywhere
/// but loopback fails at once.
const CLOSED_PORT: &str = "http://127.0.0.1:9";

/// The files of a workspace copy: `/`-separated relative path to bytes.
pub type Tree = BTreeMap<String, Vec<u8>>;

/// `name`'s value when it is set and non-empty.
fn var(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|value| !value.is_empty())
}

/// `9.3.2` as three numbers; `None` for anything else.
fn numbers(release: &str) -> Option<(u32, u32, u32)> {
    let parts: Option<Vec<u32>> = release.split('.').map(|part| part.parse().ok()).collect();
    match parts?[..] {
        [major, minor, patch] => Some((major, minor, patch)),
        _ => None,
    }
}

/// The path `rel` under `tests/fixtures/bazel/`.
pub fn fixture_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/bazel")
        .join(rel)
}

/// The names under which `before` and `after` differ.
pub fn changed(before: &Tree, after: &Tree) -> Vec<String> {
    let names = before.keys().chain(after.keys());
    let mut differing: Vec<String> = names
        .filter(|name| before.get(*name) != after.get(*name))
        .cloned()
        .collect();
    differing.sort();
    differing.dedup();
    differing
}

/// This machine cannot run `test`: a failure under [`REQUIRED`], else a
/// `SKIP` line.
fn unavailable(test: &str, why: &str) {
    assert!(
        var(REQUIRED).is_none(),
        "{test}: {REQUIRED} is set and {why}"
    );
    println!("SKIP {test}: {why}");
}

/// The temp root of one workspace copy, with a fixed place for everything a
/// Bazel run writes. Nothing lands in the developer's `~/.cache/bazel`, the
/// shared temp directory or the real home.
struct Scratch {
    /// The workspace copy Bazel and `socket-patch` run in.
    workspace: PathBuf,
    /// `--output_user_root`: one output base, so one Bazel server.
    output_user_root: PathBuf,
    /// `java.io.tmpdir` of the server and `TMPDIR` of every child.
    tmp: PathBuf,
    /// `HOME` of every child.
    home: PathBuf,
    /// `--repository_cache`.
    repository_cache: PathBuf,
    /// `--repo_contents_cache` on Bazel 9, where that cache is on by
    /// default.
    contents_cache: PathBuf,
    /// Removed on drop, after [`Scratch::drop`] made it removable.
    dir: tempfile::TempDir,
}

impl Scratch {
    /// A new temp root. `repository_cache` is one that outlives it; `None`
    /// gives it an empty one of its own.
    fn new(repository_cache: Option<PathBuf>) -> Scratch {
        let dir = tempfile::Builder::new()
            .prefix("sp-bazel-")
            .tempdir()
            .expect("create the scratch root");
        // Canonical: macOS temp directories sit behind a symlink, and a
        // directory named by the environment may be relative, which Bazel
        // would resolve against the workspace copy.
        let made = |dir: PathBuf| {
            std::fs::create_dir_all(&dir)
                .unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
            dir.canonicalize().expect("a canonical directory")
        };
        let root = made(dir.path().to_path_buf());
        Scratch {
            workspace: made(root.join("ws")),
            output_user_root: made(root.join("root")),
            tmp: made(root.join("tmp")),
            home: made(root.join("home")),
            repository_cache: made(repository_cache.unwrap_or_else(|| root.join("cache"))),
            contents_cache: made(root.join("contents")),
            dir,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Bazel marks its install base and the repositories it fetched
        // read-only, which would leave the temp root behind. Silent: this
        // also runs while a failed test unwinds.
        fn make_writable(path: &Path) {
            use std::os::unix::fs::PermissionsExt;
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                return;
            };
            if meta.file_type().is_symlink() {
                return;
            }
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o700);
            let _ = std::fs::set_permissions(path, perms);
            if meta.is_dir() {
                for entry in std::fs::read_dir(path).into_iter().flatten().flatten() {
                    make_writable(&entry.path());
                }
            }
        }
        make_writable(self.dir.path());
    }
}

/// The Bazel a test runs.
#[derive(Clone)]
struct Bazel {
    /// A release binary, or a launcher that reads `USE_BAZEL_VERSION`.
    program: OsString,
    release: String,
}

impl Bazel {
    /// The Bazel of [`BAZEL`], if it is `release`. `bazel --version` is
    /// answered by the client: no server starts. `Err` says why this
    /// machine cannot run the test.
    fn detect(scratch: &Scratch, release: &str) -> Result<Bazel, String> {
        let program = var(BAZEL).unwrap_or_else(|| "bazel".into());
        let bazel = Bazel {
            program,
            release: release.to_string(),
        };
        let shown = bazel.program.to_string_lossy().into_owned();
        let out = bazel
            .child(scratch)
            .arg("--version")
            .output()
            .map_err(|e| format!("`{shown}` did not run: {e}"))?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let found = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix("bazel "));
        match found {
            Some(found) if found == release => Ok(bazel),
            Some(found) => Err(format!("`{shown}` is Bazel {found}, not {release}")),
            None => Err(format!(
                "`{shown} --version` printed no `bazel <release>` line:\n{stdout}{}",
                String::from_utf8_lossy(&out.stderr)
            )),
        }
    }

    /// The program with the environment of every Bazel child and no
    /// arguments. Built on `hermetic::command`, the one way this crate's
    /// tests spawn a child; what is set here lands after its scrub.
    fn child(&self, scratch: &Scratch) -> Command {
        let mut cmd = hermetic::command(Path::new(&self.program));
        for name in REMOVED {
            cmd.env_remove(name);
        }
        // A bazelisk's other variables change which Bazel it runs.
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("BAZELISK_") {
                cmd.env_remove(name);
            }
        }
        // The `go` a ruleset runs must not read the developer's module
        // cache, flags or `go env -w` file.
        hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Go]);
        cmd.env("USE_BAZEL_VERSION", &self.release)
            .env("HOME", &scratch.home)
            .env("TMPDIR", &scratch.tmp);
        cmd
    }

    /// `bazel <startup options> <command>` in the workspace copy. The
    /// startup options never vary within a test: another set restarts the
    /// server. They keep the rc files of the machine out and every write
    /// inside the scratch root; without the two JVM options the server
    /// writes `hsperfdata_<user>` and its native libraries into the shared
    /// temp directory.
    fn command(&self, scratch: &Scratch, command: &str) -> Command {
        let joined = |flag: &str, path: &Path| {
            let mut arg = OsString::from(flag);
            arg.push(path);
            arg
        };
        let mut cmd = self.child(scratch);
        cmd.current_dir(&scratch.workspace)
            .arg("--nohome_rc")
            .arg("--nosystem_rc")
            .arg(joined("--output_user_root=", &scratch.output_user_root))
            .arg("--max_idle_secs=15")
            .arg(joined("--host_jvm_args=-Djava.io.tmpdir=", &scratch.tmp))
            .arg("--host_jvm_args=-XX:-UsePerfData")
            .arg(command);
        cmd
    }
}

/// One finished Bazel command.
pub struct Run {
    /// The command line, for failure messages.
    line: String,
    output: Output,
}

impl Run {
    fn of(mut cmd: Command) -> Result<Run, String> {
        let line = format!("{cmd:?}");
        let output = cmd.output().map_err(|e| format!("spawn {line}: {e}"))?;
        Ok(Run { line, output })
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
            "{}\nexit {:?}\n--- stdout\n{}\n--- stderr\n{}",
            self.line,
            self.output.status.code(),
            self.stdout(),
            self.stderr()
        )
    }
}

/// One run of `socket-patch` in a workspace copy.
pub struct Ran {
    pub code: i32,
    /// stdout, parsed: the `--json` envelope.
    pub envelope: Value,
    /// The command line, the exit code and both streams, for failure
    /// messages.
    pub dump: String,
}

/// One test's checkout of a fixture workspace, with a Bazel server and an
/// output base of its own.
pub struct Cell {
    pub test: String,
    /// `--repo_env=NAME=VALUE` pairs for every Bazel command (`GOPROXY`).
    pub repo_env: Vec<(String, String)>,
    bazel: Bazel,
    // Dropped after `Cell::drop` has stopped the server.
    scratch: Scratch,
}

impl Cell {
    /// The checkout of the fixture workspace `fixture` for `test`, which
    /// runs on Bazel `release`. `None` after a `SKIP` line when this machine
    /// has no such Bazel; a panic instead under [`REQUIRED`].
    pub fn open(test: &str, release: &str, fixture: &str) -> Option<Cell> {
        let (major, _, _) =
            numbers(release).unwrap_or_else(|| panic!("{test}: {release} is no Bazel release"));
        // A workflow leg selects the tests of its Bazel by this prefix.
        assert!(
            test.starts_with(&format!("b{major}_")),
            "{test} runs on Bazel {release}: its name must start with b{major}_"
        );
        let shared = var(REPO_CACHE).map(PathBuf::from);
        let scratch = Scratch::new(shared);
        let bazel = match Bazel::detect(&scratch, release) {
            Ok(bazel) => bazel,
            Err(why) => {
                unavailable(test, &why);
                return None;
            }
        };
        let source = fixture_path(fixture);
        assert!(source.is_dir(), "{test}: no fixture {}", source.display());
        fs_tree::copy_tree(&source, &scratch.workspace);
        // The checkout is its own repository: `socket-patch` looks no
        // higher for a `socket.yml` or a project root.
        std::fs::create_dir(scratch.workspace.join(".git")).expect("create .git");
        println!(
            "{test}: Bazel {release} ({})",
            bazel.program.to_string_lossy()
        );
        Some(Cell {
            test: test.to_string(),
            repo_env: Vec::new(),
            bazel,
            scratch,
        })
    }

    /// A second machine with the same checkout: the files of this one, in
    /// a workspace copy with an output base and a contents cache of its
    /// own, so nothing a build here fetched or built is there. Only the
    /// repository cache is shared. This cell's server is stopped first, so
    /// one runs at a time.
    pub fn twin(&self) -> Cell {
        if let Err(why) = self.shutdown() {
            panic!("{}: {why}", self.test);
        }
        let twin = Cell {
            test: self.test.clone(),
            repo_env: self.repo_env.clone(),
            bazel: self.bazel.clone(),
            scratch: Scratch::new(Some(self.scratch.repository_cache.clone())),
        };
        for (rel, bytes) in self.tree() {
            twin.write(&rel, bytes);
        }
        std::fs::create_dir(twin.scratch.workspace.join(".git")).expect("create .git");
        twin
    }

    /// Write a file of the workspace copy.
    pub fn write(&self, rel: &str, bytes: impl AsRef<[u8]>) {
        let path = self.scratch.workspace.join(rel);
        std::fs::create_dir_all(path.parent().expect("a file path")).expect("create the parent");
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }

    /// Every regular file of the workspace copy. Bazel's `bazel-*` links
    /// into the output base are links, so they are not followed.
    pub fn tree(&self) -> Tree {
        read_tree(&self.scratch.workspace)
    }

    /// `bazel <command> <options> <args>` in the workspace copy.
    pub fn bazel(&self, command: &str, args: &[&str]) -> Run {
        self.bazel_with("update", command, args)
    }

    /// `bazel build --lockfile_mode=error <targets>`: passes only when
    /// `MODULE.bazel.lock` already holds what the build resolves.
    pub fn frozen_build(&self, targets: &[&str]) -> Run {
        self.bazel_with("error", "build", targets)
    }

    fn bazel_with(&self, lockfile_mode: &str, command: &str, args: &[&str]) -> Run {
        let scratch = &self.scratch;
        let mut cmd = self.bazel.command(scratch, command);
        let mut joined = |flag: &str, value: &std::ffi::OsStr| {
            let mut arg = OsString::from(flag);
            arg.push(value);
            cmd.arg(arg);
        };
        joined("--repository_cache=", scratch.repository_cache.as_os_str());
        let mut home = OsString::from("HOME=");
        home.push(&scratch.home);
        joined("--repo_env=", &home);
        for (name, value) in &self.repo_env {
            joined("--repo_env=", format!("{name}={value}").as_ref());
        }
        // Stated, so no test depends on a release's default.
        joined("--lockfile_mode=", lockfile_mode.as_ref());
        let release = numbers(&self.bazel.release).expect("checked by Cell::open");
        if release >= (9, 0, 0) {
            // Bazel 9 keeps the repositories it fetched in a contents cache,
            // by default under the repository cache, and hands them to the
            // next workspace copy without a fetch. The cache stays on, as a
            // user has it, in a place of this copy's own: a twin starts
            // with an empty one and has to fetch. Bazel 8 has the cache
            // off by default, Bazel 7 has none.
            joined("--repo_contents_cache=", scratch.contents_cache.as_os_str());
        }
        cmd.args(["--color=no", "--curses=no"]);
        cmd.args(args);
        Run::of(cmd).unwrap_or_else(|why| panic!("{}: {why}", self.test))
    }

    /// The build a user runs, and what it built: `bazel build //:consumer`
    /// passes, and `bazel run //:consumer` prints the line `marker`.
    pub fn builds(&self, marker: &str) {
        let built = self.bazel("build", &[CONSUMER]);
        assert!(built.ok(), "{}: {}", self.test, built.dump());
        let ran = self.bazel("run", &[CONSUMER]);
        assert!(
            ran.ok() && ran.stdout().lines().any(|line| line == marker),
            "{}: {CONSUMER} did not print {marker:?}:\n{}",
            self.test,
            ran.dump()
        );
    }

    /// `socket-patch <args> --json` in the workspace copy, as a user in
    /// that directory runs it, against the Socket API at `api`. Its home
    /// and temp directory are the cell's, and every proxy is a closed port,
    /// so it reaches no host but loopback.
    pub fn socket_patch(&self, api: &str, args: &[&str], env: &[(&str, &str)]) -> Ran {
        let mut cmd = match var(SOCKET_BIN) {
            Some(bin) => hermetic::command(Path::new(&bin)),
            None => hermetic::binary_command(),
        };
        cmd.current_dir(&self.scratch.workspace)
            .args(args)
            .args(["--json", "--api-url", api, "--org", ORG])
            .args(["--api-token", "fake-token"]);
        hermetic::scrub_crawler_inputs(&mut cmd);
        cmd.env("HOME", &self.scratch.home)
            .env("TMPDIR", &self.scratch.tmp);
        for proxy in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
            cmd.env(proxy, CLOSED_PORT);
            cmd.env(proxy.to_ascii_lowercase(), CLOSED_PORT);
        }
        cmd.env("NO_PROXY", "127.0.0.1,localhost");
        cmd.env("no_proxy", "127.0.0.1,localhost");
        cmd.envs(env.iter().copied());
        let line = format!("{cmd:?}");
        let out = cmd.output().unwrap_or_else(|e| panic!("spawn {line}: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        let code = out.status.code().unwrap_or(-1);
        let dump = format!("{line}\nexit {code}\n--- stdout\n{stdout}\n--- stderr\n{stderr}");
        let envelope = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("{}: stdout is no JSON envelope ({e}):\n{dump}", self.test));
        Ran {
            code,
            envelope,
            dump,
        }
    }

    /// `bazel shutdown`, when the pid file of a server is there. No command
    /// options: the startup options are what address the server.
    fn shutdown(&self) -> Result<(), String> {
        let bases = std::fs::read_dir(&self.scratch.output_user_root);
        let mut bases = bases.into_iter().flatten().flatten();
        if !bases.any(|base| base.path().join("server/server.pid.txt").exists()) {
            return Ok(());
        }
        let run = Run::of(self.bazel.command(&self.scratch, "shutdown"))?;
        if run.ok() {
            Ok(())
        } else {
            Err(format!("`bazel shutdown` failed:\n{}", run.dump()))
        }
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        // Never panic here: this also runs while a failed test unwinds. If
        // the shutdown fails, the idle timeout ends the server.
        if let Err(why) = self.shutdown() {
            eprintln!("{}: leaving a Bazel server behind: {why}", self.test);
        }
    }
}

#[test]
fn a_release_is_read_as_three_numbers() {
    assert_eq!(numbers("9.3.2"), Some((9, 3, 2)));
    assert_eq!(numbers("7.7.2"), Some((7, 7, 2)));
    for unreadable in ["9.3", "9.3.2.1", "10.0.0rc3", ""] {
        assert_eq!(numbers(unreadable), None, "{unreadable:?}");
    }
}
