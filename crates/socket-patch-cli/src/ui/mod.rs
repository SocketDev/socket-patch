//! Terminal UI: everything that decides *how* human output looks.
//!
//! - [`StatusLine`]: the self-rewriting progress line.
//! - [`confirm`], [`select_one`]: prompts.
//! - [`print_json`]: the `--json` document writer.
//! - `text`: wording and shaping shared by several commands.
//! - [`color_enabled`], [`paint`], [`severity`], [`pad`]: color policy and
//!   ANSI-aware column alignment.
//! - [`diff`]: a line diff and its unified rendering.
//! - [`Style`]: how one stream is drawn (color, and the Unicode marks and
//!   bars of a terminal known to show them), with [`bar`] as its ASCII
//!   fallback.
//! - [`init`] / [`quiet`]: the process-wide `--silent`/`--json` switch,
//!   shared with core's own advisories.
//!
//! Every piece that writes takes (or wraps) a plain `Write` sink so it can
//! be unit-tested against a `Vec<u8>`.

pub(crate) mod browser;
pub(crate) mod diff;
mod prompt;
mod status;
mod text;

use std::io::IsTerminal;

use crate::args::GlobalArgs;

pub(crate) use prompt::confirm;
pub use prompt::{select_from, select_one, SelectError};
pub(crate) use status::StatusLine;
pub(crate) use text::{
    agent_next_steps, folded, manifest_error_message, next_steps, next_steps_installed,
    package_names, plural, printable, sentence_case, shell_word, short_uuid, sweep_failure,
    truncate, worst_and_ids,
};

/// [`text::no_patches_message`] for this run: the manifest path is named
/// only when `--manifest-path` moved it.
pub(crate) fn no_patches_message(nothing_to: &str, common: &GlobalArgs) -> String {
    let moved = (common.manifest_path != socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH)
        .then(|| common.resolved_manifest_path());
    text::no_patches_message(nothing_to, moved.as_deref())
}

/// A global run's scope as one pasteable argument: `--global-prefix <dir>`
/// (shell-quoted when needed) or `-g`; `None` for a project run.
pub(crate) fn global_scope_arg(common: &GlobalArgs) -> Option<String> {
    match &common.global_prefix {
        Some(prefix) => Some(format!(
            "--global-prefix {}",
            shell_word(&prefix.to_string_lossy())
        )),
        None if common.global => Some("-g".to_string()),
        None => None,
    }
}

/// How to get the original files of the package `purl` back, as the start
/// of a sentence. `bundle install` keeps an installed gem as it is, edits
/// included, so a gem names the commands that reinstall it.
pub(crate) fn reinstall_remedy(purl: &str) -> String {
    match socket_patch_core::utils::purl::strip_purl_qualifiers(purl)
        .strip_prefix("pkg:gem/")
        .and_then(|rest| rest.split('@').next())
    {
        Some(gem) => format!("Run `bundle pristine {gem}` (or `gem pristine {gem}`)"),
        None => "Reinstall the package".to_string(),
    }
}

/// The flags that pick WHICH tree a run acts on, as a pasteable suffix
/// (leading space, empty for a default run): `--cwd`, `--manifest-path`,
/// `-g` / `--global-prefix` and `--ecosystems`, each only when it differs
/// from its default. A remedy a command prints repeats them, so running it
/// verbatim acts on the tree the command just reported on.
pub(crate) fn scope_args(common: &GlobalArgs) -> String {
    let mut out = String::new();
    if common.cwd != std::path::Path::new(".") {
        out.push_str(" --cwd ");
        out.push_str(&shell_word(&common.cwd.to_string_lossy()));
    }
    if common.manifest_path != socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH {
        out.push_str(" --manifest-path ");
        out.push_str(&shell_word(&common.manifest_path));
    }
    if let Some(global) = global_scope_arg(common) {
        out.push(' ');
        out.push_str(&global);
    }
    if let Some(ecosystems) = common.ecosystems.as_deref().filter(|e| !e.is_empty()) {
        out.push_str(" --ecosystems ");
        out.push_str(&shell_word(&ecosystems.join(",")));
    }
    out
}

/// Where a physical copy lives, relative to `cwd` when it is inside it.
pub(crate) fn display_copy_path(package_path: &str, cwd: &std::path::Path) -> String {
    let path = std::path::Path::new(package_path);
    let canonical = std::fs::canonicalize(path).ok();
    let rel = path
        .strip_prefix(cwd)
        .ok()
        .or_else(|| canonical.as_deref().and_then(|c| c.strip_prefix(cwd).ok()));
    match rel {
        Some(r) if !r.as_os_str().is_empty() => r.display().to_string(),
        _ => package_path.to_string(),
    }
}

/// The one line every declined prompt prints (get, rollback, remove,
/// `--update`).
pub(crate) const CANCELLED: &str = "Cancelled; no changes made.";

/// The one paid-plan upsell line (scan and get).
pub(crate) const PAID_UPGRADE: &str =
    "Upgrade to a paid Socket plan to access all patches: https://socket.dev/pricing";

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
    // Hot patch mode: stdout belongs to the command about to start, so the
    // document goes into the run's one stderr line instead.
    if crate::hot_patch::active() {
        crate::hot_patch::report(v);
        return;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(v).expect("serializing an in-memory JSON value cannot fail")
    );
}

/// Whether `--silent`/`--json` is in effect for this process (see [`init`]).
pub(crate) fn quiet() -> bool {
    socket_patch_core::utils::notice::is_quiet()
}

/// Whether escape sequences written to a terminal render, as
/// `(stdout, stderr)`: whether the Windows console accepted VT processing,
/// probed once. console's color probe is what switches VT on, so its
/// answer is exactly "escapes will render". `false` for a stream that is
/// not a console (it is then not a terminal either, and escapes in a pipe
/// are the reader's business).
#[cfg(windows)]
pub(crate) fn vt() -> (bool, bool) {
    static VT: std::sync::OnceLock<(bool, bool)> = std::sync::OnceLock::new();
    *VT.get_or_init(|| {
        (
            console::Term::stdout().features().colors_supported(),
            console::Term::stderr().features().colors_supported(),
        )
    })
}

/// Unix terminals always render escape sequences.
#[cfg(not(windows))]
pub(crate) fn vt() -> (bool, bool) {
    (true, true)
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

/// One of the process's standard streams, for [`attended`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdin,
    Stdout,
    Stderr,
}

/// Whether `stream` is a terminal with a person at it: a terminal, and
/// not one an AI coding agent runs the command in ([`plain_output`]).
///
/// Every choice of how to draw for a person asks this, never
/// `is_terminal()` itself: the animated status line, color, marks and
/// bars, the full-screen browser, the arrow-key menus, text fitted to
/// the terminal's width. So an agent gets what a pipe gets, however its
/// harness wires the streams. Some run commands on a pseudo-terminal,
/// where the status line's redraws alone would be most of what the agent
/// reads back, and the browser would wait for keys nobody presses.
///
/// A typed yes/no question ([`confirm`]) does not ask this: it is a
/// safeguard, not decoration, and the environment is not what waives it
/// (`--yes` is).
pub(crate) fn attended(stream: Stream) -> bool {
    let terminal = match stream {
        Stream::Stdin => std::io::stdin().is_terminal(),
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    };
    terminal && plain() == Plain::No
}

/// [`plain_output`] of this process's environment, read once: it does
/// not change during a run.
fn plain() -> Plain {
    static PLAIN: std::sync::OnceLock<Plain> = std::sync::OnceLock::new();
    *PLAIN.get_or_init(|| plain_output(env_var))
}

/// Say once, on stderr, why this terminal is not getting the interactive
/// output it would: an agent's variable is set. Called where a command
/// prints instead of opening the full-screen browser or a menu, for
/// someone working in a terminal an agent started, who would otherwise
/// look for the reason in vain. Nothing when stdin or stderr is not a
/// terminal, when `SOCKET_PLAIN` decided, or under `--json` / `--silent`.
pub(crate) fn note_agent_terminal(common: &GlobalArgs) {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let Plain::Agent(variable) = plain() else {
        return;
    };
    if common.json
        || common.silent
        || !std::io::stdin().is_terminal()
        || !std::io::stderr().is_terminal()
        || SAID.swap(true, std::sync::atomic::Ordering::Relaxed)
    {
        return;
    }
    eprintln!("{}", agent_terminal_note(variable));
}

/// The line [`note_agent_terminal`] prints.
fn agent_terminal_note(variable: &str) -> String {
    format!(
        "Note: {variable} is set, so this terminal gets the plain output of an AI coding \
         agent's. A person at it can set SOCKET_PLAIN=0 for the interactive output."
    )
}

/// The variables AI coding agents put in the environment of the commands
/// they run: `AI_AGENT` first (any agent may set it, to its name), then
/// each tool's own. Only variables an agent injects into its commands
/// are here. One an editor sets in every terminal, a person's included
/// (`CURSOR_TRACE_ID`, `REPL_ID`), is not, and neither is the bare
/// `AGENT`, which is set for too many other reasons.
pub const AGENT_ENV_VARS: &[&str] = &[
    "AI_AGENT",
    // Claude Code
    "CLAUDECODE",
    "CLAUDE_CODE",
    // Cursor
    "CURSOR_AGENT",
    // OpenAI Codex
    "CODEX_SANDBOX",
    "CODEX_THREAD_ID",
    "CODEX_CI",
    // Gemini CLI, Antigravity
    "GEMINI_CLI",
    "ANTIGRAVITY_AGENT",
    // VS Code and GitHub Copilot
    "VSCODE_AGENT",
    "COPILOT_AGENT",
    "COPILOT_CLI",
    // OpenCode
    "OPENCODE",
    "OPENCODE_CLIENT",
    // Amp, Goose, Augment, Cline, Roo Code, Qwen Code, Pi
    "AMP_CURRENT_THREAD_ID",
    "GOOSE_TERMINAL",
    "AUGMENT_AGENT",
    "CLINE_ACTIVE",
    "ROO_ACTIVE",
    "ROO_CODE_TASK_ID",
    "QWEN_CODE",
    "PI_CODING_AGENT",
];

/// Why output is kept plain on a terminal too (see [`attended`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Plain {
    /// It is not: a terminal has a person at it.
    No,
    /// `SOCKET_PLAIN` asks for it.
    Asked,
    /// An agent runs the command: this one of [`AGENT_ENV_VARS`] is set.
    Agent(&'static str),
}

/// Whether, and why, output is kept plain on a terminal, pure over the
/// environment:
///
/// - `SOCKET_PLAIN` decides when it is set to anything: a truthy value
///   (`1`, `true`, `yes`, `on`, `y`, `t`: the vocabulary of every other
///   `SOCKET_*` toggle) asks for plain output; any other value keeps the
///   terminal output whatever else is set (someone at a terminal an
///   agent started).
/// - Otherwise an agent's variable decides: the first of
///   [`AGENT_ENV_VARS`] set to something other than `0`, `false`, `no`,
///   `off`, `n` or `f`.
pub(crate) fn plain_output(env: impl Fn(&str) -> Option<String>) -> Plain {
    let set = |k: &str| {
        env(k)
            .map(|v| v.trim().to_ascii_lowercase())
            .filter(|v| !v.is_empty())
    };
    if let Some(asked) = set("SOCKET_PLAIN") {
        return match asked.as_str() {
            "1" | "true" | "yes" | "on" | "y" | "t" => Plain::Asked,
            _ => Plain::No,
        };
    }
    let off = |v: &str| matches!(v, "0" | "false" | "no" | "off" | "n" | "f");
    AGENT_ENV_VARS
        .iter()
        .find(|name| set(name).is_some_and(|v| !off(&v)))
        .map_or(Plain::No, |name| Plain::Agent(name))
}

/// Whether the Unicode marks and bars may be drawn, pure over its inputs:
/// only with `color` on (so `NO_COLOR` turns both off) and only on a
/// terminal (a pipe or log gets ASCII, whatever forced its colors), and
/// then only where the terminal is known to show UTF-8:
///
/// - `TERM=linux` (the kernel console's font holds few glyphs) → off;
/// - Windows → on in Windows Terminal (`WT_SESSION`), in an editor's
///   terminal (`TERM_PROGRAM`) and in an xterm-like one (`TERM=xterm...`:
///   Git Bash, MSYS2); the legacy console → off;
/// - elsewhere → on when the locale is UTF-8 (the first set of `LC_ALL`,
///   `LC_CTYPE`, `LANG`).
///
/// Everything drawn with them has an ASCII form of the same width, so a
/// wrong guess costs polish, never alignment.
pub(crate) fn glyphs_enabled(
    color: bool,
    is_tty: bool,
    windows: bool,
    env: impl Fn(&str) -> Option<String>,
) -> bool {
    let set = |k: &str| env(k).filter(|v| !v.is_empty());
    if !color || !is_tty || set("TERM").is_some_and(|t| t == "linux") {
        return false;
    }
    if windows {
        return set("WT_SESSION").is_some()
            || set("TERM_PROGRAM").is_some()
            || set("TERM").is_some_and(|t| t.starts_with("xterm"));
    }
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .find_map(set)
        .is_some_and(|locale| {
            let locale = locale.to_ascii_lowercase();
            locale.contains("utf-8") || locale.contains("utf8")
        })
}

/// Whether someone is at a terminal that can show the full-screen browser
/// ([`browser`]): stdin, stdout and stderr (where it is drawn) are all
/// terminals with a person at them ([`attended`]), and the terminal
/// renders escape sequences (not `TERM=dumb`, not a console without VT
/// processing). The browser is drawn with nothing else, so anywhere this
/// is false a command prints instead.
///
/// Never under `SOCKET_DEBUG`, as the status line is never live then:
/// core's debug logging writes straight to stderr, where it would land
/// in the middle of a frame and be gone with the screen.
pub(crate) fn full_screen() -> bool {
    attended(Stream::Stdin)
        && attended(Stream::Stdout)
        && attended(Stream::Stderr)
        && !socket_patch_core::utils::env_compat::is_debug_enabled()
        && vt() == (true, true)
        && env_var("TERM").is_none_or(|term| term != "dumb")
}

/// Await `work` with `label` on a status line of its own, so a step
/// that takes a moment shows as work in progress ([`StatusLine::stderr`]
/// says when a line shows at all). The line is up only while `work` is
/// awaited, and `work` must not print: its result is what the caller
/// reports, once this returns.
pub(crate) async fn busy<T>(
    common: &GlobalArgs,
    label: impl std::fmt::Display,
    work: impl std::future::Future<Output = T>,
) -> T {
    let mut status = StatusLine::stderr(common.json, common.silent);
    status.set(label);
    let done = work.await;
    status.finish();
    done
}

/// How human output is drawn on one stream: with color, and with the
/// Unicode marks and bars ([`glyphs_enabled`]). Every piece has a plain
/// form, which is what a pipe, a log and a test see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Style {
    pub(crate) color: bool,
    pub(crate) glyphs: bool,
}

impl Style {
    /// No color and no glyphs: logs, pipes, `NO_COLOR`.
    pub(crate) const PLAIN: Style = Style {
        color: false,
        glyphs: false,
    };

    /// The style of stdout (results).
    pub(crate) fn stdout() -> Style {
        Style::of(attended(Stream::Stdout), stdout_color())
    }

    /// The style of stderr (status lines, warnings).
    pub(crate) fn stderr() -> Style {
        Style::of(attended(Stream::Stderr), stderr_color())
    }

    fn of(is_tty: bool, color: bool) -> Style {
        Style {
            color,
            glyphs: glyphs_enabled(color, is_tty, cfg!(windows), env_var),
        }
    }

    /// The mark that opens the line of something done, one column wide:
    /// a green `✔`, or a space where glyphs are off (so the line keeps its
    /// indent).
    pub(crate) fn check(&self) -> String {
        if self.glyphs {
            paint("✔", "32", self.color)
        } else {
            " ".to_string()
        }
    }

    /// A progress bar `cells` columns wide (plus the brackets of the ASCII
    /// form): `done` of `total` filled.
    pub(crate) fn bar(&self, done: usize, total: usize, cells: usize) -> String {
        if !self.glyphs {
            return bar(done, total, cells);
        }
        let filled = filled_cells(done, total, cells);
        format!(
            "{}{}",
            paint(&"━".repeat(filled), "32", self.color),
            paint(&"─".repeat(cells - filled), "2", self.color)
        )
    }

    /// The width of [`Self::bar`] at `cells`.
    pub(crate) fn bar_width(&self, cells: usize) -> usize {
        cells + if self.glyphs { 0 } else { 2 }
    }
}

/// How many of `cells` are filled at `done` of `total`: rounded down, so a
/// bar is full only when the work is done.
fn filled_cells(done: usize, total: usize, cells: usize) -> usize {
    if total == 0 {
        0
    } else {
        (done.min(total) * cells) / total
    }
}

/// [`color_enabled`] for stdout, where a terminal counts when a person
/// is at it ([`attended`]); any terminal, attended or not, must also
/// render escapes ([`vt`]).
pub(crate) fn stdout_color() -> bool {
    let terminal = std::io::stdout().is_terminal();
    color_enabled(attended(Stream::Stdout), env_var) && (!terminal || vt().0)
}

/// [`color_enabled`] for stderr, where a terminal counts when a person
/// is at it ([`attended`]); any terminal, attended or not, must also
/// render escapes ([`vt`]).
pub(crate) fn stderr_color() -> bool {
    let terminal = std::io::stderr().is_terminal();
    color_enabled(attended(Stream::Stderr), env_var) && (!terminal || vt().1)
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

/// `text` in bold when `on`: the numbers a result line is read for.
pub(crate) fn bold(text: &str, on: bool) -> String {
    paint(text, "1", on)
}

/// `text` dimmed when `on`: detail that supports a line without leading it.
pub(crate) fn dim(text: &str, on: bool) -> String {
    paint(text, "2", on)
}

/// A progress bar of `cells` ASCII characters between brackets,
/// `[######----]`: `done` of `total` filled, never more than all of them.
/// ASCII on purpose: every terminal and every log renders it at one column
/// per character, so a status line holding it can always be rewritten.
pub(crate) fn bar(done: usize, total: usize, cells: usize) -> String {
    let filled = filled_cells(done, total, cells);
    format!("[{}{}]", "#".repeat(filled), "-".repeat(cells - filled))
}

/// Color a severity label by tier (`critical` bright red, `high` red,
/// `medium`/`moderate` yellow, `low` cyan; anything else plain). The
/// text itself is kept verbatim.
pub fn severity(s: &str, on: bool) -> String {
    match severity_code(s) {
        Some(code) => paint(s, code, on),
        None => s.to_string(),
    }
}

/// The SGR color of a severity tier, for output that paints its cells
/// itself; `None` for a label that is not a tier.
pub(crate) fn severity_code(s: &str) -> Option<&'static str> {
    Some(match s.to_lowercase().as_str() {
        "critical" => "91",
        "high" => "31",
        // GHSA emits `moderate`; same tier as medium (core `ranking::severity_order`).
        "medium" | "moderate" => "33",
        "low" => "36",
        _ => return None,
    })
}

/// Pad `s` on the right to `width` *visible* characters. SGR color
/// sequences don't count, so a colored cell lines up exactly like the
/// plain one (`{:<16}` counts the invisible bytes and misaligns). Never
/// truncates.
pub(crate) fn pad(s: &str, width: usize) -> String {
    format!("{s}{}", " ".repeat(width.saturating_sub(visible_width(s))))
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
    fn copy_path_outside_cwd_stays_absolute() {
        assert_eq!(
            display_copy_path("/elsewhere/node_modules/x", std::path::Path::new("/p")),
            "/elsewhere/node_modules/x"
        );
        assert_eq!(display_copy_path("/p", std::path::Path::new("/p")), "/p");
        assert_eq!(
            display_copy_path("/p/node_modules/é", std::path::Path::new("/p")),
            "node_modules/é"
        );
    }

    /// An agent's terminal is not a terminal with a person at it: any one
    /// of the variables agents set for their commands makes the output
    /// plain, and `SOCKET_PLAIN` has the last word either way.
    #[test]
    fn plain_output_follows_the_agent_variables_and_the_override() {
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                vars.iter()
                    .find(|(name, _)| *name == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(plain_output(env(&[])), Plain::No);
        // Each agent's own variable, by name.
        for name in AGENT_ENV_VARS {
            let named = move |k: &str| (k == *name).then(|| "1".to_string());
            assert_eq!(plain_output(named), Plain::Agent(name), "{name}");
        }
        assert_eq!(
            plain_output(env(&[("AI_AGENT", "claude-code_2-1-327_agent")])),
            Plain::Agent("AI_AGENT")
        );
        // Set to nothing, or to "off", is not set.
        for value in ["", "  ", "0", "false", "FALSE", "no", "off", "n", "f"] {
            let unset = move |k: &str| (k == "CLAUDECODE").then(|| value.to_string());
            assert_eq!(plain_output(unset), Plain::No, "{value:?}");
        }
        // A variable set for other reasons, or by an editor in every
        // terminal, says nothing.
        assert_eq!(
            plain_output(env(&[
                ("AGENT", "build-agent-7"),
                ("CURSOR_TRACE_ID", "abc"),
                ("REPL_ID", "abc"),
                ("TERM_PROGRAM", "vscode"),
            ])),
            Plain::No
        );
        // The override. Anything but a truthy value keeps the terminal
        // output, an agent or not: a typo never turns the UI off.
        for value in ["0", "false", "no", "off", "n", "flase"] {
            let kept = move |k: &str| match k {
                "SOCKET_PLAIN" => Some(value.to_string()),
                "CLAUDECODE" => Some("1".to_string()),
                _ => None,
            };
            assert_eq!(plain_output(kept), Plain::No, "{value:?}");
        }
        for value in ["1", "true", "YES", "on", "y", "t"] {
            let asked = move |k: &str| (k == "SOCKET_PLAIN").then(|| value.to_string());
            assert_eq!(plain_output(asked), Plain::Asked, "{value:?}");
        }
        // Set to nothing, it decides nothing.
        assert_eq!(
            plain_output(env(&[("SOCKET_PLAIN", ""), ("CLAUDECODE", "1")])),
            Plain::Agent("CLAUDECODE")
        );
        // The note names the variable and the way back.
        assert_eq!(
            agent_terminal_note("CLAUDECODE"),
            "Note: CLAUDECODE is set, so this terminal gets the plain output of an AI coding \
             agent's. A person at it can set SOCKET_PLAIN=0 for the interactive output."
        );
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
    fn glyphs_need_color_a_terminal_and_a_utf8_locale() {
        type Case<'a> = (bool, bool, bool, &'a [(&'a str, &'a str)], bool);
        let utf8: &[(&str, &str)] = &[("LANG", "en_US.UTF-8")];
        let cases: &[Case] = &[
            // (color, tty, windows, env, glyphs)
            (true, true, false, utf8, true),
            (false, true, false, utf8, false),
            (true, false, false, utf8, false),
            (true, true, false, &[], false),
            (true, true, false, &[("LANG", "C")], false),
            (true, true, false, &[("LANG", "C.utf8")], true),
            // The first locale variable that is set decides.
            (
                true,
                true,
                false,
                &[("LC_ALL", "C"), ("LANG", "en_US.UTF-8")],
                false,
            ),
            (
                true,
                true,
                false,
                &[("LC_ALL", ""), ("LC_CTYPE", "ja_JP.UTF-8")],
                true,
            ),
            (
                true,
                true,
                false,
                &[("LANG", "en_US.UTF-8"), ("TERM", "linux")],
                false,
            ),
            // Windows: by terminal, never by locale.
            (true, true, true, utf8, false),
            (true, true, true, &[("WT_SESSION", "1")], true),
            (true, true, true, &[("TERM_PROGRAM", "vscode")], true),
            (true, true, true, &[("TERM", "xterm-256color")], true),
            (true, true, true, &[("TERM", "cygwin")], false),
        ];
        for (color, tty, windows, vars, want) in cases {
            assert_eq!(
                glyphs_enabled(*color, *tty, *windows, env(vars)),
                *want,
                "color={color} tty={tty} windows={windows} env={vars:?}"
            );
        }
    }

    #[test]
    fn style_marks_and_bars_have_a_plain_form_of_the_same_width() {
        let fancy = Style {
            color: true,
            glyphs: true,
        };
        assert_eq!(Style::PLAIN.check(), " ");
        assert_eq!(fancy.check(), "\x1b[32m✔\x1b[0m");
        assert_eq!(visible_width(&fancy.check()), 1);
        assert_eq!(Style::PLAIN.bar(1, 4, 8), "[##------]");
        assert_eq!(fancy.bar(1, 4, 8), "\x1b[32m━━\x1b[0m\x1b[2m──────\x1b[0m");
        assert_eq!(visible_width(&fancy.bar(1, 4, 8)), fancy.bar_width(8));
        assert_eq!(
            visible_width(&Style::PLAIN.bar(1, 4, 8)),
            Style::PLAIN.bar_width(8)
        );
    }

    #[test]
    fn bar_fills_in_proportion_and_never_overflows() {
        assert_eq!(bar(0, 4, 8), "[--------]");
        assert_eq!(bar(1, 4, 8), "[##------]");
        assert_eq!(bar(4, 4, 8), "[########]");
        assert_eq!(bar(9, 4, 8), "[########]");
        // Rounds down: the bar is full only when the work is done.
        assert_eq!(bar(7, 8, 4), "[###-]");
        assert_eq!(bar(0, 0, 4), "[----]");
        assert_eq!(bar(3, 3, 0), "[]");
        assert_eq!(bold("7", true), "\x1b[1m7\x1b[0m");
        assert_eq!(dim("x", false), "x");
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
        let colored = pad(&severity("HIGH", true), 16);
        let plain = pad(&severity("HIGH", false), 16);
        assert_eq!(strip_ansi(&colored), plain);
        assert_eq!(visible_width(&colored), 16);
        assert_eq!(pad("toolongvalue", 4), "toolongvalue");
    }
}
