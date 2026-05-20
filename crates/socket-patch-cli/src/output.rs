use std::io::{self, IsTerminal, Write};

/// Check if stdout is a terminal (for ANSI color output).
pub fn stdout_is_tty() -> bool {
    std::io::stdout().is_terminal()
}

/// Check if stderr is a terminal (for progress output).
pub fn stderr_is_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Check if stdin is a terminal (for interactive prompts).
pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

/// Format a severity string with optional ANSI colors.
pub fn format_severity(s: &str, use_color: bool) -> String {
    if !use_color {
        return s.to_string();
    }
    match s.to_lowercase().as_str() {
        "critical" => format!("\x1b[31m{s}\x1b[0m"),
        "high" => format!("\x1b[91m{s}\x1b[0m"),
        "medium" => format!("\x1b[33m{s}\x1b[0m"),
        "low" => format!("\x1b[36m{s}\x1b[0m"),
        _ => s.to_string(),
    }
}

/// Wrap text in ANSI color codes if use_color is true.
pub fn color(text: &str, code: &str, use_color: bool) -> String {
    if use_color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Error type for interactive selection.
pub enum SelectError {
    /// User cancelled the selection.
    Cancelled,
    /// JSON mode requires explicit selection (e.g. via --id).
    JsonModeNeedsExplicit,
}

/// Prompt the user for a yes/no confirmation.
///
/// - `skip_prompt` (from `-y` flag) or `is_json`: return `default_yes` immediately.
/// - Non-TTY stdin: return `default_yes` with a stderr warning.
/// - Interactive: print prompt to stderr, read line; empty = `default_yes`.
pub fn confirm(prompt: &str, default_yes: bool, skip_prompt: bool, is_json: bool) -> bool {
    if skip_prompt || is_json {
        return default_yes;
    }
    if !stdin_is_tty() {
        eprintln!("Non-interactive mode detected, proceeding with default.");
        return default_yes;
    }
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    eprint!("{prompt} {hint} ");
    io::stderr().flush().unwrap();
    let mut answer = String::new();
    io::stdin().read_line(&mut answer).unwrap();
    let answer = answer.trim().to_lowercase();
    if answer.is_empty() {
        return default_yes;
    }
    answer == "y" || answer == "yes"
}

/// Prompt the user to select one option from a list using dialoguer.
///
/// - `is_json`: return `Err(SelectError::JsonModeNeedsExplicit)`.
/// - Non-TTY: auto-select first option with stderr warning.
/// - Interactive: use `dialoguer::Select` on stderr.
pub fn select_one(prompt: &str, options: &[String], is_json: bool) -> Result<usize, SelectError> {
    if is_json {
        return Err(SelectError::JsonModeNeedsExplicit);
    }
    if !stdin_is_tty() {
        eprintln!("Non-interactive mode: auto-selecting first option.");
        return Ok(0);
    }
    let selection = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(prompt)
        .items(options)
        .default(0)
        .interact_opt()
        .map_err(|_| SelectError::Cancelled)?;
    match selection {
        Some(idx) => Ok(idx),
        None => Err(SelectError::Cancelled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format_severity ----

    #[test]
    fn format_severity_critical_with_color() {
        let out = format_severity("critical", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("critical"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("31"), "expected red code 31: {out:?}");
    }

    #[test]
    fn format_severity_high_with_color() {
        let out = format_severity("high", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("high"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("91"), "expected bright-red code 91: {out:?}");
    }

    #[test]
    fn format_severity_medium_with_color() {
        let out = format_severity("medium", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("medium"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("33"), "expected yellow code 33: {out:?}");
    }

    #[test]
    fn format_severity_low_with_color() {
        let out = format_severity("low", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("low"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("36"), "expected cyan code 36: {out:?}");
    }

    #[test]
    fn format_severity_case_insensitive_critical_uppercase() {
        let out = format_severity("CRITICAL", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("CRITICAL"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("31"), "expected red code 31: {out:?}");
    }

    #[test]
    fn format_severity_case_insensitive_critical_titlecase() {
        let out = format_severity("Critical", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("Critical"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("31"), "expected red code 31: {out:?}");
    }

    #[test]
    fn format_severity_case_insensitive_high_lowercase() {
        let out = format_severity("high", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("high"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
    }

    #[test]
    fn format_severity_case_insensitive_high_uppercase() {
        let out = format_severity("HIGH", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("HIGH"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("91"), "expected bright-red code 91: {out:?}");
    }

    #[test]
    fn format_severity_unknown_passes_through_with_color() {
        let out = format_severity("unknown", true);
        assert_eq!(out, "unknown");
    }

    #[test]
    fn format_severity_critical_no_color() {
        assert_eq!(format_severity("critical", false), "critical");
    }

    #[test]
    fn format_severity_high_no_color() {
        assert_eq!(format_severity("high", false), "high");
    }

    #[test]
    fn format_severity_medium_no_color() {
        assert_eq!(format_severity("medium", false), "medium");
    }

    #[test]
    fn format_severity_low_no_color() {
        assert_eq!(format_severity("low", false), "low");
    }

    #[test]
    fn format_severity_unknown_no_color() {
        assert_eq!(format_severity("unknown", false), "unknown");
    }

    #[test]
    fn format_severity_empty_with_color_passes_through() {
        let out = format_severity("", true);
        assert_eq!(out, "");
    }

    // ---- color ----

    #[test]
    fn color_with_color_on() {
        assert_eq!(color("hi", "31", true), "\x1b[31mhi\x1b[0m");
    }

    #[test]
    fn color_with_color_off() {
        assert_eq!(color("hi", "31", false), "hi");
    }

    #[test]
    fn color_with_empty_text_and_color_on() {
        assert_eq!(color("", "1;32", true), "\x1b[1;32m\x1b[0m");
    }

    // ---- confirm ----

    #[test]
    fn confirm_skip_prompt_returns_default_yes_true() {
        assert!(confirm("?", true, true, false));
    }

    #[test]
    fn confirm_skip_prompt_returns_default_yes_false() {
        assert!(!confirm("?", false, true, false));
    }

    #[test]
    fn confirm_is_json_returns_default_yes_true() {
        assert!(confirm("?", true, false, true));
    }

    #[test]
    fn confirm_is_json_returns_default_yes_false() {
        assert!(!confirm("?", false, false, true));
    }

    #[test]
    fn confirm_skip_prompt_and_is_json_both_set_returns_default_yes() {
        assert!(confirm("?", true, true, true));
    }
}
