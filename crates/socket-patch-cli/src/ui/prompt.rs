//! Yes/no confirmation and single-choice selection. Prompts always go to
//! stderr so stdout stays clean for data.

use std::io::{self, BufRead, IsTerminal, Write};

use crate::args::GlobalArgs;

/// Printed (unless `--silent`) when a prompt is answered automatically
/// because stdin is not a terminal.
const NON_INTERACTIVE_PROCEED: &str = "Non-interactive mode detected, proceeding automatically.";
/// Same, for a prompt whose default is "no".
const NON_INTERACTIVE_DECLINE: &str = "Non-interactive mode detected, declining by default.";
/// Same, for [`select_one`], which takes the first option.
const NON_INTERACTIVE_SELECT_FIRST: &str =
    "Non-interactive mode detected, selecting the first option.";

/// Ask a yes/no question on stderr. Returns the answer.
///
/// - `--yes` or `--json`: `default_yes`, without asking.
/// - stdin not a terminal (CI): `default_yes`, with a one-line note
///   unless `--silent`.
/// - Otherwise: pending typeahead is discarded first (so an Enter pressed
///   during a long scan cannot answer), then `prompt [Y/n] ` is shown.
///   An empty line takes the default; `y`/`yes` accept; anything else,
///   end of input (Ctrl-D) and unreadable input decline.
pub(crate) fn confirm(prompt: &str, default_yes: bool, common: &GlobalArgs) -> bool {
    if common.yes || common.json {
        return default_yes;
    }
    let ask = Ask {
        default_yes,
        interactive: io::stdin().is_terminal(),
        silent: common.silent,
    };
    if ask.interactive {
        discard_typeahead();
    }
    confirm_with(&mut io::stdin().lock(), &mut io::stderr(), prompt, ask)
}

/// How a yes/no question is answered (see [`confirm_with`]).
#[derive(Clone, Copy, Debug)]
struct Ask {
    /// The answer to an empty line or when nobody can be asked; also
    /// picks the `[Y/n]`/`[y/N]` hint.
    default_yes: bool,
    /// Whether stdin is a terminal a person is typing into.
    interactive: bool,
    /// `--silent`: suppress the non-interactive note.
    silent: bool,
}

/// Drop keystrokes typed before the prompt appeared, so an Enter pressed
/// during a long scan cannot answer a default-yes prompt.
fn discard_typeahead() {
    #[cfg(unix)]
    // SAFETY: tcflush only discards the terminal's pending input queue;
    // STDIN_FILENO is a valid descriptor (the caller checked it is a tty).
    unsafe {
        libc::tcflush(libc::STDIN_FILENO, libc::TCIFLUSH);
    }
    #[cfg(windows)]
    // SAFETY: GetStdHandle has no preconditions; FlushConsoleInputBuffer
    // only discards pending console input and fails harmlessly on a
    // non-console handle. Errors are ignored: the flush is best-effort.
    unsafe {
        use windows_sys::Win32::System::Console::{
            FlushConsoleInputBuffer, GetStdHandle, STD_INPUT_HANDLE,
        };
        FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
    }
}

/// The testable core of [`confirm`]: reads one line from `input`, writes
/// the prompt (and any note) to `out`.
fn confirm_with(input: &mut impl BufRead, out: &mut impl Write, prompt: &str, ask: Ask) -> bool {
    if !ask.interactive {
        if !ask.silent {
            let note = if ask.default_yes {
                NON_INTERACTIVE_PROCEED
            } else {
                NON_INTERACTIVE_DECLINE
            };
            let _ = writeln!(out, "{note}");
        }
        return ask.default_yes;
    }
    let hint = if ask.default_yes { "[Y/n]" } else { "[y/N]" };
    let _ = write!(out, "{prompt} {hint} ");
    let _ = out.flush();
    // Read raw bytes: `read_line` rolls its buffer back on invalid UTF-8,
    // which would hide the newline the terminal already echoed.
    let mut buf = Vec::new();
    let read = input.read_until(b'\n', &mut buf);
    // Keep the next output off the prompt line when the terminal did not
    // echo a newline (Ctrl-D, a mid-line read error).
    if !buf.ends_with(b"\n") {
        let _ = writeln!(out);
    }
    // End of input (Ctrl-D), an I/O error and non-UTF-8 bytes (a Latin-1
    // paste) all decline, even when the default is yes.
    let Ok(1..) = read else { return false };
    let Ok(line) = String::from_utf8(buf) else {
        return false;
    };
    let answer = line.trim().to_lowercase();
    if answer.is_empty() {
        return ask.default_yes;
    }
    answer == "y" || answer == "yes"
}

/// Error type for interactive selection.
pub enum SelectError {
    /// User cancelled the selection.
    Cancelled,
    /// JSON mode requires explicit selection (re-running with the chosen
    /// UUID as the identifier — `--id` is a boolean type-tag, not a
    /// value-taking selector).
    JsonModeNeedsExplicit,
}

/// Prompt the user to select one option from a list (arrow-key menu on
/// stderr). Takes the same `common` flags as [`confirm`].
///
/// - `--json`: `Err(JsonModeNeedsExplicit)`.
/// - Empty `options`: `Err(Cancelled)` — there is nothing to select, and
///   `Ok(0)` would hand callers an out-of-bounds index.
/// - stdin not a terminal: the first option, with
///   [`NON_INTERACTIVE_SELECT_FIRST`] unless `--silent`.
/// - Interactive: Esc/q/Ctrl-C cancel; the cursor is always restored.
pub fn select_one(
    prompt: &str,
    options: &[String],
    common: &GlobalArgs,
) -> Result<usize, SelectError> {
    if common.json {
        return Err(SelectError::JsonModeNeedsExplicit);
    }
    if options.is_empty() {
        return Err(SelectError::Cancelled);
    }
    if !io::stdin().is_terminal() {
        if !common.silent {
            eprintln!("{NON_INTERACTIVE_SELECT_FIRST}");
        }
        return Ok(0);
    }
    let (prompt, options) = fit_menu(prompt, options, super::stderr_width());
    let _guard = CursorGuard::install();
    let picked = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(prompt)
        .items(&options)
        .default(0)
        .interact_opt();
    match picked {
        Ok(Some(idx)) => Ok(idx),
        _ => Err(SelectError::Cancelled),
    }
}

/// Fit a [`select_one`] menu to a `width`-column terminal. dialoguer
/// erases its menu by counting logical lines, so a prompt or option that
/// wraps leaves rows of the old menu on screen. The prompt renders as
/// `? <prompt> › ` (5 extra columns, one spare so the cursor never sits
/// in the last column); each option renders as `❯ <option>` (2 extra, one
/// spare).
fn fit_menu(prompt: &str, options: &[String], width: usize) -> (String, Vec<String>) {
    const MIN: usize = 10;
    let prompt = super::truncate(prompt, width.saturating_sub(6).max(MIN));
    let options = options
        .iter()
        .map(|o| super::truncate(o, width.saturating_sub(3).max(MIN)))
        .collect();
    (prompt, options)
}

/// dialoguer hides the cursor while its menu is up. Its own error paths
/// don't show it again, and Ctrl-C (which console turns into a real
/// SIGINT) kills the process mid-menu. This guard shows the cursor on
/// drop and, for its lifetime, on SIGINT before handing the signal to
/// whatever disposition was there before. In the CLI that is the
/// `interrupt` handler, so a Ctrl-C at a menu restores the cursor first
/// and then removes a held `.socket/apply.lock` before the process dies.
struct CursorGuard {
    /// The SIGINT disposition to put back on drop; `None` when the guard
    /// left SIGINT alone (it was ignored).
    #[cfg(unix)]
    previous: Option<libc::sighandler_t>,
}

/// The disposition [`show_cursor_then_reraise`] hands SIGINT back to
/// (`SIG_DFL` is 0).
#[cfg(unix)]
static PREVIOUS_SIGINT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(unix)]
const SHOW_CURSOR: &[u8] = b"\x1b[?25h";

/// Whether stderr was a terminal when the guard was installed: the
/// handler writes [`SHOW_CURSOR`] only then, so a redirected stderr never
/// gets a stray escape. (Checked at install; `isatty` in a handler is
/// not async-signal-safe on every platform.)
#[cfg(unix)]
static STDERR_IS_TTY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn show_cursor_then_reraise(sig: libc::c_int) {
    let previous = PREVIOUS_SIGINT.load(std::sync::atomic::Ordering::SeqCst) as libc::sighandler_t;
    // SAFETY: write, signal and raise are async-signal-safe. SIGINT is
    // blocked while this handler runs, so the re-raised signal is
    // delivered to `previous` once it returns.
    unsafe {
        if STDERR_IS_TTY.load(std::sync::atomic::Ordering::SeqCst) {
            libc::write(
                libc::STDERR_FILENO,
                SHOW_CURSOR.as_ptr().cast(),
                SHOW_CURSOR.len(),
            );
        }
        libc::signal(sig, previous);
        libc::raise(sig);
    }
}

impl CursorGuard {
    fn install() -> Self {
        #[cfg(unix)]
        {
            STDERR_IS_TTY.store(
                io::stderr().is_terminal(),
                std::sync::atomic::Ordering::SeqCst,
            );
            let handler = show_cursor_then_reraise as extern "C" fn(libc::c_int);
            // SAFETY: installs a handler that only calls async-signal-safe
            // functions; the previous disposition is restored on drop.
            let previous = unsafe { libc::signal(libc::SIGINT, handler as libc::sighandler_t) };
            if previous == libc::SIG_IGN || previous == libc::SIG_ERR {
                // Started with Ctrl-C ignored (nohup, some launchers): keep
                // it ignored so the menu just returns Cancelled; the Drop
                // still restores the cursor.
                if previous == libc::SIG_IGN {
                    // SAFETY: puts back the disposition we just replaced.
                    unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
                }
                return CursorGuard { previous: None };
            }
            PREVIOUS_SIGINT.store(previous as usize, std::sync::atomic::Ordering::SeqCst);
            CursorGuard {
                previous: Some(previous),
            }
        }
        #[cfg(not(unix))]
        CursorGuard {}
    }
}

impl Drop for CursorGuard {
    fn drop(&mut self) {
        if io::stderr().is_terminal() {
            let _ = console::Term::stderr().show_cursor();
        }
        #[cfg(unix)]
        if let Some(previous) = self.previous {
            // SAFETY: restores the disposition captured in `install`.
            unsafe {
                libc::signal(libc::SIGINT, previous);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_menu_keeps_every_row_on_one_terminal_line() {
        let prompt = "Multiple patches available for pkg:npm/ws@7.4.5. Select one:";
        let options = vec![
            "77b662dd-cdb4-43d5-8e37-18dd0c605ab8 [FREE] (fixes: CVE-2026-48779)".to_string(),
            "short".to_string(),
        ];
        let (p, o) = fit_menu(prompt, &options, 40);
        assert_eq!(p, "Multiple patches available for...");
        assert_eq!(
            o,
            vec![
                "77b662dd-cdb4-43d5-8e37-18dd0c605a...".to_string(),
                "short".to_string()
            ]
        );
        assert!(p.chars().count() + 5 < 40);
        assert!(o.iter().all(|o| o.chars().count() + 2 < 40));
        // Wide enough: untouched.
        let (p, o) = fit_menu(prompt, &options, 120);
        assert_eq!(p, prompt);
        assert_eq!(o, options);
    }

    /// A person at a terminal answering `Apply 1 patch?`.
    fn at_tty(default_yes: bool) -> Ask {
        Ask {
            default_yes,
            interactive: true,
            silent: false,
        }
    }

    /// Run `confirm_with` over `input`; returns (answer, what was written).
    fn run(input: &[u8], ask: Ask) -> (bool, String) {
        let mut out = Vec::new();
        let answer = confirm_with(&mut &input[..], &mut out, "Apply 1 patch?", ask);
        (answer, String::from_utf8(out).unwrap())
    }

    #[test]
    fn empty_line_takes_the_default() {
        assert_eq!(
            run(b"\n", at_tty(true)),
            (true, "Apply 1 patch? [Y/n] ".into())
        );
        assert_eq!(
            run(b"\n", at_tty(false)),
            (false, "Apply 1 patch? [y/N] ".into())
        );
        assert!(run(b"   \n", at_tty(true)).0);
    }

    #[test]
    fn yes_answers_accept() {
        for input in [&b"y\n"[..], b"Y\n", b"yes\n", b"YES\n", b" y \n"] {
            assert!(run(input, at_tty(false)).0, "{input:?}");
        }
    }

    #[test]
    fn no_and_garbage_decline() {
        for input in [&b"n\n"[..], b"N\n", b"no\n", b"garbage\n", b"yess\n"] {
            assert!(!run(input, at_tty(true)).0, "{input:?}");
        }
    }

    #[test]
    fn eof_declines_even_when_default_is_yes() {
        // Ctrl-D at "[Y/n]" must not mean yes and mutate the project.
        let (answer, out) = run(b"", at_tty(true));
        assert!(!answer);
        assert_eq!(
            out, "Apply 1 patch? [Y/n] \n",
            "a newline must follow the prompt"
        );
    }

    #[test]
    fn answer_without_trailing_newline_still_counts_and_ends_the_line() {
        let (answer, out) = run(b"y", at_tty(false));
        assert!(answer);
        assert_eq!(out, "Apply 1 patch? [y/N] \n");
    }

    #[test]
    fn invalid_utf8_declines_without_an_extra_newline() {
        // The terminal already echoed the Enter; a second newline would
        // leave a stray blank line.
        let (answer, out) = run(b"\xE9\n", at_tty(true));
        assert!(!answer);
        assert_eq!(out, "Apply 1 patch? [Y/n] ");
    }

    #[test]
    fn non_interactive_answers_the_default_with_note() {
        let ask = Ask {
            interactive: false,
            ..at_tty(true)
        };
        let (answer, out) = run(b"n\n", ask);
        assert!(answer, "non-interactive must not read stdin");
        assert_eq!(out, format!("{NON_INTERACTIVE_PROCEED}\n"));

        let ask = Ask {
            interactive: false,
            ..at_tty(false)
        };
        let (answer, out) = run(b"", ask);
        assert!(!answer);
        assert_eq!(out, format!("{NON_INTERACTIVE_DECLINE}\n"));
    }

    #[test]
    fn non_interactive_silent_writes_nothing() {
        let ask = Ask {
            interactive: false,
            silent: true,
            ..at_tty(true)
        };
        assert_eq!(run(b"", ask), (true, String::new()));
    }

    #[test]
    fn select_one_json_mode_requires_explicit_selection() {
        let json = GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        };
        let opts = vec!["first".to_string(), "second".to_string()];
        assert!(matches!(
            select_one("pick one", &opts, &json),
            Err(SelectError::JsonModeNeedsExplicit)
        ));
        // JSON mode is decided before the empty-options guard.
        assert!(matches!(
            select_one("pick", &[], &json),
            Err(SelectError::JsonModeNeedsExplicit)
        ));
    }

    #[test]
    fn select_one_empty_options_is_cancelled_not_index_zero() {
        assert!(matches!(
            select_one("pick", &[], &GlobalArgs::default()),
            Err(SelectError::Cancelled)
        ));
    }

    #[test]
    fn yes_or_json_answers_the_default() {
        for (yes, json) in [(true, false), (false, true), (true, true)] {
            let common = GlobalArgs {
                yes,
                json,
                ..GlobalArgs::default()
            };
            for default_yes in [true, false] {
                assert_eq!(
                    confirm("go?", default_yes, &common),
                    default_yes,
                    "yes={yes} json={json} default={default_yes}"
                );
            }
        }
    }
}
