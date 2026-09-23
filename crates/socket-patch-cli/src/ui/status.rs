//! A single self-rewriting status line ("Scanning packages...",
//! "Querying API... (batch 3/7)").
//!
//! Deterministic by construction: no timer, no background thread, and
//! every byte is written synchronously by a method call, so a `Vec<u8>`
//! sink captures exactly what a terminal would receive.

use std::fmt::Display;
use std::io::{self, IsTerminal, Write};

/// Return to column 0 and erase the whole line.
const CLEAR: &str = "\r\x1b[2K";

/// A transient progress line on a terminal, or nothing at all elsewhere.
///
/// - **live** (stderr is a terminal that understands escape sequences,
///   `TERM` is not `dumb`, not `--json`/`--silent`, not `SOCKET_DEBUG`):
///   [`set`](Self::set) redraws the line in place, always clearing first,
///   so a shorter message never leaves the tail of a longer one behind.
///   Messages are cut to `width - 1` characters: a line that wraps can't
///   be rewritten by `\r`.
/// - **not live**: `set` is a no-op and no `\r` or escape sequence is
///   ever written. [`finish_with`](Self::finish_with) still writes its
///   plain final line when `report` is on, so logs and pipes keep the
///   result lines.
///
/// Anything else printed while a line is showing must go through
/// [`println`](Self::println), which clears the line, prints, and redraws.
/// Dropping the value clears a still-visible line.
pub(crate) struct StatusLine<W: Write> {
    out: W,
    live: bool,
    report: bool,
    width: usize,
    current: Option<String>,
}

impl StatusLine<io::Stderr> {
    /// The status line for a command's stderr. It reports (writes
    /// [`finish_with`](Self::finish_with) lines) unless `json` or
    /// `silent`, and is live only when it reports on a terminal that
    /// understands escape sequences.
    ///
    /// Under `SOCKET_DEBUG` the line is never live: core's debug logging
    /// writes straight to stderr and would land on the end of the status.
    pub(crate) fn stderr(json: bool, silent: bool) -> Self {
        let human = !json && !silent;
        let live = human
            && io::stderr().is_terminal()
            && super::stderr_vt()
            && !term_is_dumb()
            && !socket_patch_core::utils::env_compat::is_debug_enabled();
        StatusLine::new(io::stderr(), live, human, super::stderr_width())
    }
}

fn term_is_dumb() -> bool {
    std::env::var("TERM").is_ok_and(|t| t == "dumb")
}

impl<W: Write> StatusLine<W> {
    /// `live`: draw transient lines. `report`: write `finish_with` lines.
    /// `width`: terminal columns.
    pub fn new(out: W, live: bool, report: bool, width: usize) -> Self {
        StatusLine {
            out,
            live,
            report,
            width,
            current: None,
        }
    }

    /// Show `msg` as the current status (replacing any previous one).
    pub fn set(&mut self, msg: impl Display) {
        if !self.live {
            return;
        }
        let msg: String = msg.to_string();
        let fitted: String = msg
            .chars()
            .filter(|c| !c.is_control())
            .take(self.width.saturating_sub(1).max(1))
            .collect();
        let _ = write!(self.out, "{CLEAR}{fitted}");
        let _ = self.out.flush();
        self.current = Some(fitted);
    }

    /// Print a permanent line (a warning or error) without garbling the
    /// status: clear it, write `line`, then redraw it. The line is always
    /// written — callers decide whether it should print at all.
    ///
    /// `line` often carries a server error body, so trailing whitespace
    /// (a body's `\r\n`, which would add a blank line) is trimmed and
    /// control characters other than `\n` and `\t` (a stray `\r` or
    /// escape sequence would rewrite the terminal) are dropped.
    pub fn println(&mut self, line: impl Display) {
        let line = line.to_string();
        let line: String = line
            .trim_end()
            .chars()
            .filter(|&c| c == '\n' || c == '\t' || !c.is_control())
            .collect();
        self.clear();
        let _ = writeln!(self.out, "{line}");
        if let Some(cur) = &self.current {
            let _ = write!(self.out, "{CLEAR}{cur}");
        }
        let _ = self.out.flush();
    }

    /// Replace the status with a permanent result line (written when
    /// `report` is on, live or not).
    pub fn finish_with(&mut self, line: impl Display) {
        self.clear();
        self.current = None;
        if self.report {
            let _ = writeln!(self.out, "{line}");
        }
        let _ = self.out.flush();
    }

    /// Erase the status, leaving nothing behind.
    pub fn finish(&mut self) {
        self.clear();
        self.current = None;
        let _ = self.out.flush();
    }

    /// Erase the visible line (keeps `current` for a redraw).
    fn clear(&mut self) {
        if self.live && self.current.is_some() {
            let _ = write!(self.out, "{CLEAR}");
        }
    }

    /// The sink, for tests.
    #[cfg(test)]
    pub(crate) fn into_inner(mut self) -> W
    where
        W: Default,
    {
        self.finish();
        std::mem::take(&mut self.out)
    }
}

impl<W: Write> Drop for StatusLine<W> {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::render;
    use super::*;

    fn live() -> StatusLine<Vec<u8>> {
        StatusLine::new(Vec::new(), true, true, 80)
    }

    fn bytes(s: &StatusLine<Vec<u8>>) -> String {
        String::from_utf8(s.out.clone()).unwrap()
    }

    #[test]
    fn set_writes_clear_then_message() {
        let mut s = live();
        s.set("abc");
        assert_eq!(bytes(&s), "\r\x1b[2Kabc");
    }

    #[test]
    fn user_report_regression_final_line_has_no_stale_tail() {
        // The reported garble: "Found 7 patches for 1 packagesatch 7/7)".
        let mut s = live();
        s.set("Querying API for patches... (batch 7/7)");
        s.finish_with("Found 7 patches for 1 package");
        let out = bytes(&s);
        assert_eq!(
            render(out.as_bytes()),
            vec!["Found 7 patches for 1 package"]
        );
    }

    #[test]
    fn shorter_after_longer_leaves_no_residue() {
        let mut s = live();
        s.set("Scanning global packages...");
        s.finish_with("Found 2 packages");
        assert_eq!(render(bytes(&s).as_bytes()), vec!["Found 2 packages"]);

        let mut s = live();
        s.set("Querying API for patches... (batch 10/10)");
        s.set("Short");
        assert_eq!(render(bytes(&s).as_bytes()), vec!["Short"]);
    }

    #[test]
    fn println_while_active_clears_prints_and_redraws() {
        let mut s = live();
        s.set("Querying API for patches... (batch 1/3)");
        s.println("Warning: falling back");
        assert_eq!(
            bytes(&s),
            "\r\x1b[2KQuerying API for patches... (batch 1/3)\
             \r\x1b[2KWarning: falling back\n\
             \r\x1b[2KQuerying API for patches... (batch 1/3)"
        );
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec![
                "Warning: falling back",
                "Querying API for patches... (batch 1/3)"
            ]
        );
        s.set("Querying API for patches... (batch 2/3)");
        s.finish_with("Found 1 patch for 1 package");
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec!["Warning: falling back", "Found 1 patch for 1 package"]
        );
    }

    #[test]
    fn println_trims_and_strips_control_chars_from_server_text() {
        let mut s = live();
        s.println("Error querying batch 1: 502 Bad\r\nGateway\x1b[2J\x07\r\n\r\n");
        assert_eq!(bytes(&s), "Error querying batch 1: 502 Bad\nGateway[2J\n");
        let mut s = live();
        s.println("a\tb  \n");
        assert_eq!(bytes(&s), "a\tb\n");
    }

    #[test]
    fn println_with_nothing_active_is_just_the_line() {
        let mut s = live();
        s.println("Error querying batch 1: boom");
        assert_eq!(bytes(&s), "Error querying batch 1: boom\n");
    }

    #[test]
    fn drop_clears_an_active_line() {
        let mut buf = Vec::new();
        {
            let mut s = StatusLine::new(&mut buf, true, true, 80);
            s.set("Fetching patch details... (1/3)");
        }
        let out = String::from_utf8(buf).unwrap();
        assert!(out.ends_with("\r\x1b[2K"), "{out:?}");
        assert_eq!(render(out.as_bytes()), Vec::<String>::new());
    }

    #[test]
    fn drop_with_nothing_active_writes_nothing() {
        let mut buf = Vec::new();
        {
            let _s = StatusLine::new(&mut buf, true, true, 80);
        }
        assert!(buf.is_empty());
        {
            let mut s = StatusLine::new(&mut buf, true, true, 80);
            s.set("x");
            s.finish();
        }
        assert_eq!(String::from_utf8(buf).unwrap(), "\r\x1b[2Kx\r\x1b[2K");
    }

    #[test]
    fn non_live_writes_no_escapes_but_keeps_final_lines() {
        let mut s = StatusLine::new(Vec::new(), false, true, 80);
        s.set("Scanning packages...");
        s.println("Warning: w");
        s.set("Querying API for patches... (batch 1/1)");
        s.finish_with("Found 2 packages");
        s.set("Fetching patch details... (1/1)");
        s.finish();
        let out = s.into_inner();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Warning: w\nFound 2 packages\n"
        );
    }

    #[test]
    fn not_reporting_suppresses_final_lines_but_not_println() {
        // --silent: result lines vanish, errors routed via println stay.
        let mut s = StatusLine::new(Vec::new(), false, false, 80);
        s.set("x");
        s.println("Error querying batch 2: boom");
        s.finish_with("Found 2 packages");
        let out = s.into_inner();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "Error querying batch 2: boom\n"
        );
    }

    #[test]
    fn live_output_has_newlines_only_from_println_and_finish_with() {
        let mut s = live();
        for i in 1..=5 {
            s.set(format!("Querying API for patches... (batch {i}/5)"));
        }
        assert!(!bytes(&s).contains('\n'));
    }

    #[test]
    fn long_message_is_cut_to_width_minus_one_on_char_boundaries() {
        let mut s = StatusLine::new(Vec::new(), true, true, 10);
        s.set("Scanning ééééééééé packages");
        let out = bytes(&s);
        let shown = out.strip_prefix("\r\x1b[2K").unwrap();
        assert_eq!(shown, "Scanning ");
        let mut s = StatusLine::new(Vec::new(), true, true, 6);
        s.set("ééééééééé");
        assert_eq!(bytes(&s), "\r\x1b[2Kééééé");
        // A degenerate width still shows something and never panics.
        let mut s = StatusLine::new(Vec::new(), true, true, 0);
        s.set("abc");
        assert_eq!(bytes(&s), "\r\x1b[2Ka");
    }

    #[test]
    fn control_chars_in_a_message_cannot_break_the_line() {
        let mut s = live();
        s.set("a\nb\rc");
        assert_eq!(bytes(&s), "\r\x1b[2Kabc");
    }
}
