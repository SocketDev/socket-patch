//! PTY I/O shared by the interactive suites.
//!
//! `confirm()` discards terminal typeahead right before it shows a y/n
//! prompt (so an Enter pressed during a long scan cannot answer it). Input
//! written into the PTY before the prompt appears is therefore thrown
//! away, exactly as a real user's early keystrokes are. These helpers send
//! the scripted answer only once a prompt is on screen.
//!
//! Pull in with `#[path = "common/pty_io.rs"] mod pty_io;` and use it via
//! `crate::pty_io::...`.

#![allow(dead_code)]

use std::io::{Read, Write};
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

/// The lib's terminal emulator (`ui::test_support::render`), included
/// from the same source file so the two can't drift.
#[path = "../../src/ui/test_support.rs"]
mod test_support;
#[allow(unused_imports)]
pub use test_support::render;
