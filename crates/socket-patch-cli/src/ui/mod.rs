//! Terminal UI: everything that decides *how* human output looks.
//!
//! - [`StatusLine`]: the one self-rewriting progress line.
//! - [`confirm`], [`confirm_or_proceed`], [`select_one`]:
//!   prompts.
//! - [`print_json`]: the one `--json` document writer.
//! - [`plural`], [`truncate`]: text shaping.
//! - [`color_enabled`], [`paint`], [`severity`], [`pad`]: color policy and
//!   ANSI-aware column alignment.
//! - [`init`] / [`quiet`]: the process-wide `--silent`/`--json` switch,
//!   shared with core's own advisories.
//!
//! Every piece that writes takes (or wraps) a plain `Write` sink so it can
//! be unit-tested against a `Vec<u8>`.

mod prompt;
mod status;
mod text;

use std::io::IsTerminal;

use crate::args::GlobalArgs;

pub(crate) use prompt::{confirm, confirm_or_proceed};
pub use prompt::{select_one, SelectError};
pub(crate) use status::StatusLine;
pub(crate) use text::{plural, truncate};

/// Call once after argument parsing. Core's informational advisories (and
/// the prompts' non-interactive notes) go quiet under `--silent`/`--json`;
/// core's warnings (token shape, org auto-detect) go quiet only under
/// `--silent`, since `--json` still reports warnings on stderr. Also
/// points console's (and so dialoguer's) color switches at our policy,
/// so a `NO_COLOR` menu is as plain as everything else.
pub fn init(common: &GlobalArgs) {
    socket_patch_core::utils::notice::set_output_mode(common.silent, common.json);
    console::set_colors_enabled(stdout_color());
    console::set_colors_enabled_stderr(stderr_color());
}

/// Print one JSON document, pretty-printed, to stdout — the one writer
/// behind every `--json` envelope, so each consumer parses stdout as
/// exactly one document.
pub(crate) fn print_json(v: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).expect("serializing an in-memory JSON value cannot fail")
    );
}

/// Whether stdin is a terminal a person can answer prompts on.
pub(crate) fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

/// Whether `--silent`/`--json` is in effect for this process (see [`init`]).
pub(crate) fn quiet() -> bool {
    socket_patch_core::utils::notice::is_quiet()
}

/// Whether the Windows console behind stdout and stderr accepted VT
/// (escape-sequence) processing, probed once. console's color probe is
/// what switches VT on, so its answer is exactly "escapes will render".
/// `false` for a stream that is not a console (it is then not a terminal
/// either, and escapes in a pipe are the reader's business).
#[cfg(windows)]
fn vt_probe() -> (bool, bool) {
    static VT: std::sync::OnceLock<(bool, bool)> = std::sync::OnceLock::new();
    *VT.get_or_init(|| {
        (
            console::Term::stdout().features().colors_supported(),
            console::Term::stderr().features().colors_supported(),
        )
    })
}

/// Whether escape sequences written to a terminal on stdout render: on
/// Windows, whether VT processing could be enabled ([`vt_probe`]).
#[cfg(windows)]
fn stdout_vt() -> bool {
    vt_probe().0
}

/// [`stdout_vt`] for stderr (also gates the live [`StatusLine`]).
#[cfg(windows)]
pub(crate) fn stderr_vt() -> bool {
    vt_probe().1
}

/// Unix terminals always render escape sequences.
#[cfg(not(windows))]
fn stdout_vt() -> bool {
    true
}

/// Unix terminals always render escape sequences.
#[cfg(not(windows))]
pub(crate) fn stderr_vt() -> bool {
    true
}

/// The color policy, pure over its inputs:
/// `NO_COLOR` (non-empty) → off; `CLICOLOR_FORCE` (non-empty, not `0`) →
/// on; not a terminal → off; `CLICOLOR=0` → off; `TERM=dumb` → off;
/// otherwise on.
pub(crate) fn color_enabled(is_tty: bool, env: impl Fn(&str) -> Option<String>) -> bool {
    let set = |k: &str| env(k).filter(|v| !v.is_empty());
    if set("NO_COLOR").is_some() {
        return false;
    }
    if set("CLICOLOR_FORCE").is_some_and(|v| v != "0") {
        return true;
    }
    if !is_tty {
        return false;
    }
    if set("CLICOLOR").is_some_and(|v| v == "0") {
        return false;
    }
    set("TERM").is_none_or(|v| v != "dumb")
}

fn env_var(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// [`color_enabled`] for stdout; a terminal must also render escapes
/// ([`stdout_vt`]).
pub(crate) fn stdout_color() -> bool {
    let tty = std::io::stdout().is_terminal();
    color_enabled(tty, env_var) && (!tty || stdout_vt())
}

/// [`color_enabled`] for stderr; a terminal must also render escapes
/// ([`stderr_vt`]).
pub(crate) fn stderr_color() -> bool {
    let tty = std::io::stderr().is_terminal();
    color_enabled(tty, env_var) && (!tty || stderr_vt())
}

/// Columns of the terminal on stderr (status lines, prompts): its size,
/// else `$COLUMNS`, else 80.
pub(crate) fn stderr_width() -> usize {
    width_of(&console::Term::stderr())
}

/// Columns of the terminal on stdout (tables): its size, else `$COLUMNS`,
/// else 80. Measured separately from stderr, which may be redirected
/// while stdout is still a wide terminal.
pub(crate) fn stdout_width() -> usize {
    width_of(&console::Term::stdout())
}

fn width_of(term: &console::Term) -> usize {
    term.size_checked()
        .map(|(_, cols)| cols as usize)
        .filter(|&c| c > 0)
        .or_else(|| env_var("COLUMNS")?.parse().ok().filter(|&c| c > 0))
        .unwrap_or(80)
}

/// Wrap `text` in an SGR color `code` (e.g. `"33"`) when `on`.
pub fn paint(text: &str, code: &str, on: bool) -> String {
    if on {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Color a severity label by tier (`critical` bright red, `high` red,
/// `medium`/`moderate` yellow, `low` cyan; anything else plain). The
/// text itself is kept verbatim.
pub fn severity(s: &str, on: bool) -> String {
    let code = match s.to_lowercase().as_str() {
        "critical" => "91",
        "high" => "31",
        // GHSA emits `moderate`; same tier as medium (see get.rs severity_rank).
        "medium" | "moderate" => "33",
        "low" => "36",
        _ => return s.to_string(),
    };
    paint(s, code, on)
}

/// Column alignment for [`pad`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Align {
    Left,
    Right,
}

/// Pad `s` to `width` *visible* characters. SGR color sequences don't
/// count, so a colored cell lines up exactly like the plain one (`{:<16}`
/// counts the invisible bytes and misaligns). Never truncates.
pub(crate) fn pad(s: &str, width: usize, align: Align) -> String {
    let fill = " ".repeat(width.saturating_sub(visible_width(s)));
    match align {
        Align::Left => format!("{s}{fill}"),
        Align::Right => format!("{fill}{s}"),
    }
}

/// Characters a terminal would display for `s` (SGR sequences excluded).
pub(crate) fn visible_width(s: &str) -> usize {
    strip_ansi(s).chars().count()
}

/// Remove `ESC [ ... <final>` sequences.
pub(crate) fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.clone().next() == Some('[') {
                chars.next();
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// A tiny terminal emulator for asserting on what a user would *see*
/// (shared with the integration tests' `pty_io`).
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod test_support_tests {
    use super::test_support::render;

    #[test]
    fn render_emulates_cr_and_clears() {
        assert_eq!(render(b"abc\rX"), vec!["Xbc"]);
        assert_eq!(render(b"abcdef\r\x1b[2Kxy"), vec!["xy"]);
        assert_eq!(render(b"abcdef\rxy\x1b[K"), vec!["xy"]);
        assert_eq!(render(b"a\x1b[31mb\x1b[0m\nc\n"), vec!["ab", "c"]);
        assert_eq!(render(b""), Vec::<String>::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: HashMap<&str, &str> = pairs.iter().copied().collect();
        move |k| map.get(k).map(|v| v.to_string())
    }

    #[test]
    fn color_enabled_truth_table() {
        type Case<'a> = (bool, &'a [(&'a str, &'a str)], bool);
        let cases: &[Case] = &[
            (true, &[], true),
            (false, &[], false),
            (true, &[("NO_COLOR", "1")], false),
            (true, &[("NO_COLOR", "")], true), // no-color.org: empty = unset
            (true, &[("TERM", "dumb")], false),
            (true, &[("TERM", "xterm-256color")], true),
            (true, &[("CLICOLOR", "0")], false),
            (true, &[("CLICOLOR", "1")], true),
            (false, &[("CLICOLOR_FORCE", "1")], true),
            (true, &[("CLICOLOR_FORCE", "1"), ("TERM", "dumb")], true),
            (false, &[("CLICOLOR_FORCE", "0")], false),
            (false, &[("CLICOLOR_FORCE", "")], false),
            (true, &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")], false),
        ];
        for (tty, vars, want) in cases {
            assert_eq!(
                color_enabled(*tty, env(vars)),
                *want,
                "tty={tty} env={vars:?}"
            );
        }
    }

    #[test]
    fn paint_off_has_no_escapes() {
        assert_eq!(paint("hi", "31", false), "hi");
        assert_eq!(paint("hi", "31", true), "\x1b[31mhi\x1b[0m");
        assert_eq!(paint("", "1;32", true), "\x1b[1;32m\x1b[0m");
        assert_eq!(severity("", true), "");
        for s in ["critical", "high", "medium", "moderate", "low", "unknown"] {
            assert!(!severity(s, false).contains('\x1b'));
        }
    }

    #[test]
    fn severity_ramp_is_exact() {
        assert_eq!(severity("critical", true), "\x1b[91mcritical\x1b[0m");
        assert_eq!(severity("HIGH", true), "\x1b[31mHIGH\x1b[0m");
        assert_eq!(severity("moderate", true), "\x1b[33mmoderate\x1b[0m");
        assert_eq!(severity("low", true), "\x1b[36mlow\x1b[0m");
        assert_eq!(severity("unknown", true), "unknown");
    }

    #[test]
    fn strip_ansi_removes_sgr_only() {
        assert_eq!(strip_ansi("\x1b[91mCRITICAL\x1b[0m x"), "CRITICAL x");
        assert_eq!(strip_ansi("plain é"), "plain é");
    }

    #[test]
    fn pad_counts_visible_chars_only() {
        let colored = pad(&severity("HIGH", true), 16, Align::Left);
        let plain = pad(&severity("HIGH", false), 16, Align::Left);
        assert_eq!(strip_ansi(&colored), plain);
        assert_eq!(visible_width(&colored), 16);
        assert_eq!(pad("0+1", 8, Align::Right), "     0+1");
        let paid = format!("0+{}", paint("1", "33", true));
        assert_eq!(strip_ansi(&pad(&paid, 8, Align::Right)), "     0+1");
        assert_eq!(pad("toolongvalue", 4, Align::Left), "toolongvalue");
    }
}
