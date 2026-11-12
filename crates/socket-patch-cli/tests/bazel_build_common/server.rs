//! One cell of a test: a scratch root, the Bazel that runs in it and the
//! server that Bazel starts, with a guard that takes all three down.
//!
//! A Bazel server outlives the command that started it. Left alone it
//! holds 200 to 500 MB until its idle timeout, and on Windows it keeps
//! the output base open so the temp root cannot be removed. [`Cell`]
//! therefore shuts the server down and removes the scratch root on drop,
//! also when the test panics, and at most [`MAX_SERVERS`] cells exist at
//! once in the process. A test holds one cell at a time: it closes its
//! cell before it opens a twin.

use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, PoisonError};
use std::thread::ThreadId;

use super::env::{self, Group, System};
use super::invoke::{Bazel, Options, Run};
use super::isolation::Scratch;
use super::probe_report::{self, Report};

/// How many servers may run at once: two fit a 4-vCPU runner (about
/// 300 MB each, and a concurrent cold pair costs a quarter more wall time
/// than one).
pub const MAX_SERVERS: usize = 2;

static SERVERS: Limiter = Limiter::new(MAX_SERVERS);

/// A counting permit pool: [`Limiter::take`] blocks while `max` slots are
/// held.
pub struct Limiter {
    /// The thread that took each held slot.
    held: Mutex<Vec<ThreadId>>,
    freed: Condvar,
    max: usize,
}

impl Limiter {
    pub const fn new(max: usize) -> Limiter {
        Limiter {
            held: Mutex::new(Vec::new()),
            freed: Condvar::new(),
            max,
        }
    }

    /// Take a slot, waiting for one if all are held. A thread holds one
    /// slot at a time: asking for a second panics, always, instead of
    /// working when a slot happens to be free and hanging the suite when
    /// two tests each wait for the other's.
    pub fn take(&self) -> Slot<'_> {
        let me = std::thread::current().id();
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.contains(&me) {
            drop(held);
            panic!(
                "this test already holds a cell: close it (keep what you need from its tree) \
                 before opening another, e.g. a twin"
            );
        }
        while held.len() >= self.max {
            held = self
                .freed
                .wait(held)
                .unwrap_or_else(PoisonError::into_inner);
        }
        held.push(me);
        Slot {
            limiter: self,
            holder: me,
        }
    }
}

/// One permit of a [`Limiter`], returned on drop.
pub struct Slot<'a> {
    limiter: &'a Limiter,
    holder: ThreadId,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut held = self
            .limiter
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        held.retain(|holder| *holder != self.holder);
        self.limiter.freed.notify_one();
    }
}

/// A test's workspace copy, output base and Bazel, for one run of one
/// test. Fields drop in order after the guard has stopped the server: the
/// scratch root is removed, then the server permit is returned.
pub struct Cell {
    pub test: String,
    pub bazel: Bazel,
    /// The command options of [`Cell::bazel`].
    pub options: Options,
    /// Filled in by the test; written with [`Report::ran`] as its last step.
    pub report: Report,
    pub scratch: Scratch,
    _slot: Slot<'static>,
}

impl Cell {
    /// Open a cell for `test`, which belongs to `group` and needs
    /// `system` (`None`: it runs under any, with the line's default
    /// flags). `None` = the test does not run in this cell or cannot run
    /// here; the reason is printed and a `skipped` report written.
    pub fn open(test: &str, group: Group, system: Option<System>) -> Option<Cell> {
        Self::open_in(test, group, system, Scratch::new, Bazel::detect)
    }

    /// [`Cell::open`] on an empty repository cache: for a tamper or
    /// withdrawal twin and for every assertion about what a host received.
    pub fn open_cold(test: &str, group: Group, system: Option<System>) -> Option<Cell> {
        Self::open_in(test, group, system, Scratch::cold, Bazel::detect)
    }

    /// [`Cell::open`] for the launcher cell: Bazel is run through the
    /// pinned bazelisk instead of directly.
    pub fn open_launcher(test: &str, group: Group, system: Option<System>) -> Option<Cell> {
        Self::open_in(test, group, system, Scratch::new, Bazel::detect_launcher)
    }

    fn open_in(
        test: &str,
        group: Group,
        system: Option<System>,
        scratch: fn() -> Scratch,
        detect: fn(&Scratch) -> Result<Bazel, String>,
    ) -> Option<Cell> {
        let mut report = Report::new(test);
        report.group = Some(group);
        report.system = system;
        if let Some(selected) = env::selected_group().filter(|selected| *selected != group) {
            let why = format!(
                "a {} test; this cell runs {}",
                group.name(),
                selected.name()
            );
            probe_report::skip_na(&report, &why);
            return None;
        }
        let other =
            env::selected_system().filter(|selected| system.is_some_and(|s| s != *selected));
        if let Some(selected) = other {
            let why = format!("not a {} test", selected.name());
            probe_report::skip_na(&report, &why);
            return None;
        }
        let slot = SERVERS.take();
        let scratch = scratch();
        let bazel = match detect(&scratch) {
            Ok(bazel) => bazel,
            Err(why) => {
                probe_report::skip(&report, &why);
                return None;
            }
        };
        report.bazel = Some(bazel.version.text.clone());
        if let Some(system) = system.filter(|s| bazel.version.system_flags(*s).is_none()) {
            let why = format!(
                "Bazel {} has no {} system",
                bazel.version.text,
                system.name()
            );
            probe_report::skip_na(&report, &why);
            return None;
        }
        let program = bazel.program.to_string_lossy();
        println!("{test}: driving Bazel {} ({program})", bazel.version.text);
        Some(Cell {
            test: test.to_string(),
            bazel,
            options: Options {
                system,
                ..Options::default()
            },
            report,
            scratch,
            _slot: slot,
        })
    }

    /// `bazel <command> <the cell's options> <args>` in the workspace copy.
    pub fn bazel(&self, command: &str, args: &[&str]) -> Run {
        self.bazel_with(&self.options, command, args)
    }

    /// [`Cell::bazel`] with other command options for this one command.
    /// The startup options are the cell's and cannot be changed.
    pub fn bazel_with(&self, options: &Options, command: &str, args: &[&str]) -> Run {
        let mut cmd = self.bazel.command(&self.scratch, command);
        let flags = options
            .args(&self.bazel, &self.scratch)
            .unwrap_or_else(|why| panic!("{}: {why}", self.test));
        cmd.args(flags).args(args);
        options.apply_env(&mut cmd);
        Run::of(cmd)
    }

    /// [`Cell::bazel`], asserting success.
    pub fn bazel_ok(&self, command: &str, args: &[&str]) -> Run {
        let run = self.bazel(command, args);
        assert!(run.ok(), "{}: {}", self.test, run.dump());
        run
    }

    /// `bazel info <key>`.
    pub fn info(&self, key: &str) -> String {
        self.bazel_ok("info", &[key]).stdout().trim().to_string()
    }

    /// The pid of the cell's running server, from its pid file: asking
    /// costs no Bazel command and cannot start a server.
    pub fn server_pid(&self) -> Option<u32> {
        server_pids(&self.scratch.output_user_root)
            .into_iter()
            .next()
    }

    /// `bazel shutdown`, when a server runs. Tests call this before they
    /// write `MODULE.bazel.lock` and before a cold-server proof.
    pub fn shutdown(&self) {
        if let Err(why) = self.stop() {
            panic!("{}: {why}", self.test);
        }
    }

    fn stop(&self) -> Result<(), String> {
        if self.server_pid().is_none() {
            return Ok(());
        }
        // No command options: `shutdown` needs none, and the startup
        // options are what address the server.
        let run = Run::try_of(self.bazel.command(&self.scratch, "shutdown"))?;
        if !run.ok() {
            return Err(format!("`bazel shutdown` failed:\n{}", run.dump()));
        }
        match self.server_pid() {
            Some(pid) => Err(format!(
                "server {pid} still has its pid file after `bazel shutdown`"
            )),
            None => Ok(()),
        }
    }

    /// End the cell: stop the server, remove the scratch root and check
    /// that both happened. Returns the report, which the test writes with
    /// [`Report::ran`].
    pub fn close(self) -> Report {
        self.shutdown();
        let report = self.report.clone();
        let test = self.test.clone();
        let roots = [
            self.scratch.root.clone(),
            self.scratch.output_user_root.clone(),
        ];
        drop(self);
        for root in roots {
            assert!(!root.exists(), "{test}: {} was not removed", root.display());
        }
        report
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        // Never panic here: this also runs while a failed test unwinds.
        // If the shutdown fails, removing the output root still ends the
        // server within seconds on Unix, and its idle timeout bounds the
        // leak elsewhere.
        if let Err(why) = self.stop() {
            eprintln!("{}: leaving a Bazel server behind: {why}", self.test);
        }
    }
}

/// The pid of every live server under `output_user_root`. A server
/// removes its pid file when it exits.
fn server_pids(output_user_root: &Path) -> Vec<u32> {
    let bases = std::fs::read_dir(output_user_root)
        .into_iter()
        .flatten()
        .flatten();
    let pid_file = |base: PathBuf| base.join("server").join("server.pid.txt");
    bases
        .filter_map(|base| std::fs::read_to_string(pid_file(base.path())).ok())
        .filter_map(|text| text.trim().parse().ok())
        .collect()
}
