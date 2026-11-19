//! A single self-rewriting status line ("Scanning packages",
//! "Reading patches [####----] 8/24").
//!
//! Every byte a method writes is written synchronously by that call, so a
//! `Vec<u8>` sink captures exactly what a terminal would receive. The one
//! thing that moves by itself is the activity mark of a command's stderr
//! line: on a live terminal a ticker thread turns it, so a long step reads
//! as work whether the command is waiting on the network or busy on the
//! CPU. The ticker and the line's own methods write under one lock, and
//! the ticker only ever redraws the line the last method call left, so it
//! cannot interleave with them or outlive a cleared line.

use std::fmt::Display;
use std::io::{self, IsTerminal, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Return to column 0 and erase the whole line.
const CLEAR: &str = "\r\x1b[2K";

/// Width of the bar in a [`StatusLine::progress`] line.
const PROGRESS_CELLS: usize = 20;

/// The activity mark's frames where glyphs are shown, and elsewhere. Each
/// is one column wide.
const TURNS: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const TURNS_ASCII: [&str; 4] = ["|", "/", "-", "\\"];

/// How often the ticker turns the mark.
const TURN_EVERY: Duration = Duration::from_millis(80);

/// A transient progress line on a terminal, or nothing at all elsewhere.
///
/// - **live** (stderr is a terminal that understands escape sequences,
///   `TERM` is not `dumb`, not `--json`/`--silent`, not `SOCKET_DEBUG`):
///   [`set`](Self::set) redraws the line in place, always clearing first,
///   so a shorter message never leaves the tail of a longer one behind.
///   Messages are cut to fit: a line that wraps can't be rewritten by
///   `\r`.
/// - **not live**: `set` is a no-op and no `\r` or escape sequence is
///   ever written. [`finish_with`](Self::finish_with) still writes its
///   plain final line when `report` is on, so logs and pipes keep the
///   result lines.
///
/// Anything else printed while a line is showing must go through
/// [`println`](Self::println), which clears the line, prints, and redraws.
/// Dropping the value clears a still-visible line.
///
/// A command's line ([`stderr`](Self::stderr)) opens with an activity
/// mark that keeps turning for as long as the line shows.
pub(crate) struct StatusLine<W: Write> {
    out: W,
    live: bool,
    report: bool,
    width: usize,
    /// What the terminal's line holds, shared with the ticker.
    shown: Arc<Mutex<Shown>>,
    /// Turns the mark of a live stderr line; stopped on drop.
    ticker: Option<Ticker>,
}

/// The state both writers of a line draw from.
struct Shown {
    /// The visible status, without its mark; `None` once cleared.
    line: Option<String>,
    /// The line opens with the activity mark.
    activity: bool,
    /// Which frame of the mark shows.
    turn: usize,
    /// How a progress bar and the mark are drawn.
    style: super::Style,
}

/// The activity mark at `turn`, painted: the same mark wherever a wait
/// is shown (the status line, the full-screen browser).
pub(crate) fn activity_mark(turn: usize, style: super::Style) -> String {
    let frame = if style.glyphs {
        TURNS[turn % TURNS.len()]
    } else {
        TURNS_ASCII[turn % TURNS_ASCII.len()]
    };
    super::paint(frame, "36", style.color)
}

impl Shown {
    /// The activity mark and its space, or nothing on a line without one.
    fn mark(&self) -> String {
        if !self.activity {
            return String::new();
        }
        format!("{} ", activity_mark(self.turn, self.style))
    }

    /// The bytes that put the current line on the terminal's line, in one
    /// write; `None` when nothing shows.
    fn frame(&self) -> Option<String> {
        self.line
            .as_ref()
            .map(|line| format!("{CLEAR}{}{line}", self.mark()))
    }
}

/// A lock no panic elsewhere can take away: the state is a line of text.
fn locked(shown: &Mutex<Shown>) -> MutexGuard<'_, Shown> {
    shown
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The thread that turns a live stderr line's mark. It holds the line's
/// lock for each redraw and draws only what a method call left showing.
struct Ticker {
    /// Dropped to wake the thread and end it.
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Ticker {
    /// Turn the mark of `shown`, writing each redraw with `write`. `None`
    /// if the thread cannot start: the mark then stands still, which costs
    /// nothing but the motion.
    fn start(
        shown: Arc<Mutex<Shown>>,
        mut write: impl FnMut(&[u8]) + Send + 'static,
    ) -> Option<Ticker> {
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("status-line".to_string())
            .spawn(move || {
                // A timeout is a turn; a dropped sender is the end.
                while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(TURN_EVERY) {
                    let mut shown = locked(&shown);
                    if shown.line.is_none() {
                        continue;
                    }
                    shown.turn = shown.turn.wrapping_add(1);
                    if let Some(frame) = shown.frame() {
                        write(frame.as_bytes());
                    }
                }
            })
            .ok()?;
        Some(Ticker {
            stop: Some(stop),
            thread: Some(thread),
        })
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl StatusLine<io::Stderr> {
    /// The status line for a command's stderr. It reports (writes
    /// [`finish_with`](Self::finish_with) lines) unless `json` or
    /// `silent`, and is live only when it reports on a terminal that
    /// understands escape sequences. A live line opens with the activity
    /// mark, and a ticker keeps it turning.
    ///
    /// Under `SOCKET_DEBUG` the line is never live: core's debug logging
    /// writes straight to stderr and would land on the end of the status.
    pub(crate) fn stderr(json: bool, silent: bool) -> Self {
        let human = !json && !silent;
        let live = human
            && io::stderr().is_terminal()
            && super::vt().1
            && !std::env::var("TERM").is_ok_and(|t| t == "dumb")
            && !socket_patch_core::utils::env_compat::is_debug_enabled();
        let mut line = StatusLine::new(io::stderr(), live, human, super::stderr_width())
            .with_style(super::Style::stderr())
            .with_activity();
        if live {
            line.ticker = Ticker::start(Arc::clone(&line.shown), |frame| {
                let mut err = io::stderr().lock();
                let _ = err.write_all(frame);
                let _ = err.flush();
            });
        }
        line
    }
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
            shown: Arc::new(Mutex::new(Shown {
                line: None,
                activity: false,
                turn: 0,
                style: super::Style::PLAIN,
            })),
            ticker: None,
        }
    }

    /// Draw progress bars and the mark in `style` (plain unless told).
    pub fn with_style(self, style: super::Style) -> Self {
        locked(&self.shown).style = style;
        self
    }

    /// Open the line with the activity mark.
    pub fn with_activity(self) -> Self {
        locked(&self.shown).activity = true;
        self
    }

    /// Show `msg` as the current status (replacing any previous one). On
    /// a line with the activity mark a trailing `...` is dropped: the
    /// turning mark already says the work is going on.
    pub fn set(&mut self, msg: impl Display) {
        if !self.live {
            return;
        }
        let msg = msg.to_string();
        let msg = if locked(&self.shown).activity {
            msg.trim_end().trim_end_matches("...").trim_end()
        } else {
            msg.as_str()
        };
        let fitted: String = msg
            .chars()
            .filter(|c| !c.is_control())
            .take(self.room())
            .collect();
        self.draw(fitted);
    }

    /// Characters a status may hold: one short of the width, since a line
    /// that wraps can't be rewritten by `\r`, less the activity mark and
    /// its space.
    fn room(&self) -> usize {
        let mark = if locked(&self.shown).activity { 2 } else { 0 };
        self.width.saturating_sub(1 + mark).max(1)
    }

    /// Redraw the line as `line`, which already fits.
    fn draw(&mut self, line: String) {
        let mut shown = locked(&self.shown);
        shown.line = Some(line);
        if let Some(frame) = shown.frame() {
            let _ = self.out.write_all(frame.as_bytes());
        }
        let _ = self.out.flush();
    }

    /// Show counted work as the current status: `label`, a bar and
    /// `done/total`, e.g. `Reading patches [####--------] 8/24`. A `total`
    /// of one has nothing to count, so it shows `label` alone (`label...`
    /// on a line without the activity mark), and a terminal too narrow for
    /// the bar shows the count without it.
    pub fn progress(&mut self, label: impl Display, done: usize, total: usize) {
        if !self.live {
            return;
        }
        let (activity, style) = {
            let shown = locked(&self.shown);
            (shown.activity, shown.style)
        };
        if total <= 1 {
            // The turning mark says "working"; without one the dots do.
            return if activity {
                self.set(label)
            } else {
                self.set(format!("{label}..."))
            };
        }
        let label: String = label
            .to_string()
            .chars()
            .filter(|c| !c.is_control())
            .collect();
        let count = format!("{done}/{total}");
        let with_bar =
            label.chars().count() + 1 + style.bar_width(PROGRESS_CELLS) + 1 + count.chars().count();
        if with_bar > self.room() {
            return self.set(format!("{label} {count}"));
        }
        let bar = style.bar(done, total, PROGRESS_CELLS);
        self.draw(format!("{label} {bar} {count}"));
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
        let shown = locked(&self.shown);
        if self.live && shown.line.is_some() {
            let _ = write!(self.out, "{CLEAR}");
        }
        let _ = writeln!(self.out, "{line}");
        if let Some(frame) = shown.frame() {
            let _ = self.out.write_all(frame.as_bytes());
        }
        let _ = self.out.flush();
    }

    /// Replace the status with a permanent result line (written when
    /// `report` is on, live or not).
    pub fn finish_with(&mut self, line: impl Display) {
        let mut shown = locked(&self.shown);
        if self.live && shown.line.is_some() {
            let _ = write!(self.out, "{CLEAR}");
        }
        shown.line = None;
        if self.report {
            let _ = writeln!(self.out, "{line}");
        }
        let _ = self.out.flush();
    }

    /// Erase the status, leaving nothing behind.
    pub fn finish(&mut self) {
        let mut shown = locked(&self.shown);
        if self.live && shown.line.is_some() {
            let _ = write!(self.out, "{CLEAR}");
        }
        shown.line = None;
        let _ = self.out.flush();
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
    fn finish_with_after_a_longer_status_leaves_no_tail() {
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
    fn shorter_set_after_longer_leaves_no_tail() {
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
    fn progress_draws_a_bar_and_a_count() {
        let mut s = live();
        s.progress("Reading patches", 5, 20);
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec!["Reading patches [#####---------------] 5/20"]
        );
        s.progress("Reading patches", 20, 20);
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec!["Reading patches [####################] 20/20"]
        );
        // One step has nothing to count.
        s.progress("Checking 3 packages for patches", 0, 1);
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec!["Checking 3 packages for patches..."]
        );
        // A terminal too narrow for the bar keeps the count; it never
        // wraps.
        let mut s = StatusLine::new(Vec::new(), true, true, 24);
        s.progress("Reading patches", 5, 20);
        assert_eq!(render(bytes(&s).as_bytes()), vec!["Reading patches 5/20"]);
        let mut s = StatusLine::new(Vec::new(), true, true, 12);
        s.progress("Reading patches", 5, 20);
        assert_eq!(render(bytes(&s).as_bytes()), vec!["Reading pat"]);
        // On a terminal that shows them, the bar is drawn in glyphs, and a
        // line printed over it redraws it whole.
        let fancy = crate::ui::Style {
            color: true,
            glyphs: true,
        };
        let mut s = StatusLine::new(Vec::new(), true, true, 80).with_style(fancy);
        s.progress("Reading patches", 5, 20);
        s.println("Warning: w");
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec![
                "Warning: w".to_string(),
                format!("Reading patches {}{} 5/20", "━".repeat(5), "─".repeat(15)),
            ]
        );
        // Not live: nothing at all.
        let mut s = StatusLine::new(Vec::new(), false, true, 80);
        s.progress("Reading patches", 5, 20);
        assert!(s.into_inner().is_empty());
    }

    fn working() -> StatusLine<Vec<u8>> {
        StatusLine::new(Vec::new(), true, true, 80).with_activity()
    }

    #[test]
    fn an_activity_line_opens_with_the_mark_and_keeps_its_room() {
        let mut s = working();
        s.set("Scanning packages");
        assert_eq!(bytes(&s), "\r\x1b[2K| Scanning packages");
        s.println("Warning: w");
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec!["Warning: w", "| Scanning packages"]
        );
        s.finish_with("Found 2 packages");
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec!["Warning: w", "Found 2 packages"]
        );
        // The mark says the work is going on, so a message's own dots go.
        let mut s = working();
        s.set("Fetching patch 5435d265...");
        assert_eq!(
            render(bytes(&s).as_bytes()),
            vec!["| Fetching patch 5435d265"]
        );
        // The mark and its space come out of the line's room: it never
        // wraps.
        let mut s = StatusLine::new(Vec::new(), true, true, 10).with_activity();
        s.set("Scanning packages");
        assert_eq!(render(bytes(&s).as_bytes()), vec!["| Scannin"]);
        // Glyph terminals get the dots.
        let fancy = crate::ui::Style {
            color: false,
            glyphs: true,
        };
        let mut s = working().with_style(fancy);
        s.set("Scanning packages");
        assert_eq!(render(bytes(&s).as_bytes()), vec!["⠋ Scanning packages"]);
    }

    /// What a ticker drew, and the sink it draws into.
    fn ticking(s: &mut StatusLine<Vec<u8>>) -> Arc<Mutex<Vec<u8>>> {
        let drawn = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&drawn);
        s.ticker = Ticker::start(Arc::clone(&s.shown), move |frame| {
            sink.lock().unwrap().extend_from_slice(frame)
        });
        assert!(s.ticker.is_some());
        drawn
    }

    fn frames(drawn: &Mutex<Vec<u8>>) -> Vec<String> {
        String::from_utf8(drawn.lock().unwrap().clone())
            .unwrap()
            .split(CLEAR)
            .filter(|f| !f.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Wait (up to a few seconds: the suite may be busy) for `enough`.
    fn wait_for(enough: impl Fn() -> bool) {
        for _ in 0..500 {
            if enough() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the ticker never drew");
    }

    /// The mark keeps turning while a line shows, whatever the command is
    /// doing: nothing here awaits or calls the line between the turns.
    #[test]
    fn the_ticker_turns_the_mark_of_a_showing_line() {
        let mut s = working();
        let drawn = ticking(&mut s);
        s.set("Scanning packages");
        wait_for(|| frames(&drawn).len() >= 3);
        let seen = frames(&drawn);
        // Every redraw is the whole line, cleared first, and the mark
        // walks its frames in order.
        assert!(
            seen.iter().all(|f| f.ends_with(" Scanning packages")),
            "{seen:?}"
        );
        assert_eq!(
            seen[..3],
            [
                "/ Scanning packages",
                "- Scanning packages",
                "\\ Scanning packages"
            ]
        );
        assert!(!String::from_utf8(drawn.lock().unwrap().clone())
            .unwrap()
            .contains('\n'));
        // A new status opens on the frame the mark has reached: it does
        // not jump back.
        let before = frames(&drawn).len();
        s.set("Reading lockfiles");
        wait_for(|| frames(&drawn).len() > before);
        assert!(
            frames(&drawn)
                .last()
                .unwrap()
                .ends_with(" Reading lockfiles"),
            "{:?}",
            frames(&drawn)
        );
    }

    /// The ticker draws only a line a method call left showing: nothing
    /// before the first status, nothing after it is cleared, so a result
    /// printed after `finish` can never be overwritten.
    #[test]
    fn the_ticker_draws_nothing_without_a_showing_line() {
        let mut s = working();
        let drawn = ticking(&mut s);
        std::thread::sleep(TURN_EVERY * 3);
        assert!(drawn.lock().unwrap().is_empty());
        s.set("Scanning packages");
        wait_for(|| !frames(&drawn).is_empty());
        s.finish_with("Found 2 packages");
        let after = drawn.lock().unwrap().len();
        std::thread::sleep(TURN_EVERY * 3);
        assert_eq!(drawn.lock().unwrap().len(), after);
        // Dropping the line stops the thread.
        drop(s);
        assert_eq!(Arc::strong_count(&drawn), 1);
    }

    /// Off a terminal a command's line has no ticker at all (the test
    /// process's stderr is not a terminal, or it is and the line is
    /// cleared at once).
    #[test]
    fn a_line_that_is_not_live_starts_no_ticker() {
        let s = StatusLine::stderr(true, false);
        assert!(s.ticker.is_none());
        let s = StatusLine::stderr(false, true);
        assert!(s.ticker.is_none());
    }

    #[test]
    fn control_chars_in_a_message_cannot_break_the_line() {
        let mut s = live();
        s.set("a\nb\rc");
        assert_eq!(bytes(&s), "\r\x1b[2Kabc");
    }
}
