//! The PTY runner shared by the interactive suites: [`run`] and
//! [`run_command`] spawn a hermetic child on a real terminal, answer its
//! prompts and collect what it printed.
//!
//! `confirm()` discards terminal typeahead right before it shows a y/n
//! prompt (so an Enter pressed during a long scan cannot answer it). Input
//! written into the PTY before the prompt appears is therefore thrown
//! away, exactly as a real user's early keystrokes are. These helpers send
//! the scripted answer only once a prompt is on screen.
//!
//! Pull in with `#[path = "common/pty_io.rs"] mod pty_io;` next to the
//! crate's `mod common` (the runner spawns through `common::hermetic`), and
//! use it via `crate::pty_io::...`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Text that marks "a prompt is waiting for input": the y/n hints and
/// dialoguer's `ColorfulTheme` prompt suffix.
pub const PROMPT_MARKERS: &[&str] = &["[Y/n] ", "[y/N] ", "\u{203a}"];

/// Everything the child writes to the PTY, collected on a thread.
pub struct PtyOutput {
    buf: Arc<Mutex<Vec<u8>>>,
    handle: JoinHandle<()>,
}

impl PtyOutput {
    /// Start draining `reader` (the PTY master) until EOF.
    pub fn spawn(mut reader: Box<dyn Read + Send>) -> Self {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&buf);
        let handle = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => sink.lock().unwrap().extend_from_slice(&chunk[..n]),
                }
            }
        });
        PtyOutput { buf, handle }
    }

    fn saw_prompt(&self) -> bool {
        let text = String::from_utf8_lossy(&self.buf.lock().unwrap()).into_owned();
        PROMPT_MARKERS.iter().any(|m| text.contains(m))
    }

    /// Block until a prompt is visible, the child's output ended, or
    /// `timeout` passed (then the caller proceeds anyway).
    pub fn wait_for_prompt(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline && !self.handle.is_finished() && !self.saw_prompt() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Block until `needle` has appeared at least `n` times, the child's
    /// output ended, or `timeout` passed (then the caller proceeds anyway).
    /// For a second prompt in one run, where [`Self::wait_for_prompt`]
    /// would already be satisfied by the first.
    pub fn wait_for_count(&self, needle: &str, n: usize, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let count = || {
            String::from_utf8_lossy(&self.buf.lock().unwrap())
                .matches(needle)
                .count()
        };
        while Instant::now() < deadline && !self.handle.is_finished() && count() < n {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Join the reader and return all output (call after the child exited
    /// and the master was dropped).
    pub fn finish(self) -> Vec<u8> {
        let _ = self.handle.join();
        Arc::try_unwrap(self.buf)
            .map(|m| m.into_inner().unwrap())
            .unwrap_or_else(|arc| arc.lock().unwrap().clone())
    }
}

/// Write `input` once a prompt is on screen (immediately when empty).
pub fn send_when_prompted(out: &PtyOutput, writer: &mut dyn Write, input: &[u8]) {
    if !input.is_empty() {
        out.wait_for_prompt(Duration::from_secs(10));
    }
    let _ = writer.write_all(input);
    let _ = writer.flush();
}

/// How a [`run_command`] child ended, and everything it printed.
pub struct PtyRun {
    pub code: i32,
    /// The signal that ended the child; `None` for a normal exit.
    pub signal: Option<String>,
    pub output: String,
}

/// Run the built binary with `args` in `cwd` on a PTY, answer the first
/// prompt with `input`, and return `(exit_code, output)`.
pub fn run(args: &[&str], cwd: &Path, input: &str, timeout: Duration) -> (i32, String) {
    let run = run_command(
        crate::common::hermetic::pty_binary_command(),
        args,
        cwd,
        &[],
        &[input.as_bytes()],
        timeout,
    );
    (run.code, run.output)
}

/// Run `cmd` (a `hermetic::pty_command`) with `args` in `cwd` on a
/// 24x80 PTY, `env` applied last so it survives the scrub. `answers[0]`
/// is written once any prompt is on screen; `answers[i]` once the `[Y/n] `
/// confirm hint has appeared `i` times (so only `answers[0]` may answer a
/// menu, and the rest answer `[Y/n]` confirms in order). Then the writer is
/// dropped, which portable_pty does by sending a newline and EOF. A child
/// still running after `timeout` gets SIGHUP (`ChildKiller::kill`).
///
/// `TERM` is pinned: `console`/`dialoguer` derive key handling and
/// rendering from it, and bare CI shells leave it unset or `dumb`.
pub fn run_command(
    mut cmd: portable_pty::CommandBuilder,
    args: &[&str],
    cwd: &Path,
    env: &[(&str, &str)],
    answers: &[&[u8]],
    timeout: Duration,
) -> PtyRun {
    let pair = portable_pty::native_pty_system()
        .openpty(portable_pty::PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    for a in args {
        cmd.arg(a);
    }
    cmd.cwd(cwd);
    cmd.env("TERM", "xterm-256color");
    for (k, v) in env {
        cmd.env(k, v);
    }

    let mut child = pair.slave.spawn_command(cmd).expect("spawn in PTY");
    // The master sees EOF only once every slave fd is closed: ours now,
    // the child's when it exits.
    drop(pair.slave);

    let output = PtyOutput::spawn(pair.master.try_clone_reader().expect("clone reader"));

    // Cancelled once the child is reaped, so it never signals a reused pid.
    let (reaped, watchdog) = std::sync::mpsc::channel::<()>();
    let mut killer = child.clone_killer();
    std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = watchdog.recv_timeout(timeout) {
            let _ = killer.kill();
        }
    });

    let mut writer = pair.master.take_writer().expect("take writer");
    for (i, answer) in answers.iter().enumerate() {
        if i == 0 {
            send_when_prompted(&output, &mut writer, answer);
        } else {
            output.wait_for_count("[Y/n] ", i, Duration::from_secs(10));
            let _ = writer.write_all(answer);
            let _ = writer.flush();
        }
    }
    drop(writer);

    let status = child.wait().expect("child.wait");
    drop(reaped);
    drop(pair.master);
    let output = output.finish();
    PtyRun {
        code: status.exit_code() as i32,
        signal: status.signal().map(str::to_string),
        output: String::from_utf8_lossy(&output).into_owned(),
    }
}

/// The lib's terminal emulator (`ui::test_support::render`), included
/// from the same source file so the two can't drift.
#[path = "../../src/ui/test_support.rs"]
mod test_support;
#[allow(unused_imports)]
pub use test_support::render;
