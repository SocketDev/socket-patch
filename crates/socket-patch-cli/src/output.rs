use std::io::{self, IsTerminal, Write};

/// Check if stdin is a terminal (for interactive prompts).
pub(crate) fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal()
}

/// Format a severity string with optional ANSI colors.
pub fn format_severity(s: &str, use_color: bool) -> String {
    if !use_color {
        return s.to_string();
    }
    match s.to_lowercase().as_str() {
        "critical" => format!("\x1b[91m{s}\x1b[0m"),
        "high" => format!("\x1b[31m{s}\x1b[0m"),
        // GHSA emits `moderate`; same tier as medium (see get.rs severity_rank).
        "medium" | "moderate" => format!("\x1b[33m{s}\x1b[0m"),
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
    /// JSON mode requires explicit selection (re-running with the chosen
    /// UUID as the identifier — `--id` is a boolean type-tag, not a
    /// value-taking selector).
    JsonModeNeedsExplicit,
}

/// Prompt the user for a yes/no confirmation.
///
/// - `skip_prompt` (from `-y` flag) or `is_json`: return `default_yes` immediately.
/// - Non-TTY stdin: return `default_yes` with a stderr warning.
/// - Interactive: print prompt to stderr, read line; empty = `default_yes`;
///   unreadable input (e.g. non-UTF-8 bytes) = no.
pub(crate) fn confirm(prompt: &str, default_yes: bool, skip_prompt: bool, is_json: bool) -> bool {
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
    if io::stdin().read_line(&mut answer).is_err() {
        // Terminals can deliver non-UTF-8 bytes (e.g. a Latin-1 paste);
        // `read_line` reports those as InvalidData. Treat any read
        // failure like an unrecognized answer (decline), not a panic.
        return false;
    }
    let answer = answer.trim().to_lowercase();
    if answer.is_empty() {
        return default_yes;
    }
    answer == "y" || answer == "yes"
}

/// Prompt the user to select one option from a list using dialoguer.
///
/// - `is_json`: return `Err(SelectError::JsonModeNeedsExplicit)`.
/// - Empty `options`: return `Err(SelectError::Cancelled)` — there is no
///   option to select, so neither auto-select nor an interactive menu is
///   meaningful (returning `Ok(0)` would hand callers an out-of-bounds index).
/// - Non-TTY: auto-select first option with stderr warning.
/// - Interactive: use `dialoguer::Select` on stderr.
pub fn select_one(prompt: &str, options: &[String], is_json: bool) -> Result<usize, SelectError> {
    if is_json {
        return Err(SelectError::JsonModeNeedsExplicit);
    }
    if options.is_empty() {
        return Err(SelectError::Cancelled);
    }
    if !stdin_is_tty() {
        eprintln!("Non-interactive mode: auto-selecting first option.");
        return Ok(0);
    }
    dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt(prompt)
        .items(options)
        .default(0)
        .interact_opt()
        .map_err(|_| SelectError::Cancelled)?
        .ok_or(SelectError::Cancelled)
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
        assert!(out.contains("91"), "expected bright-red code 91: {out:?}");
    }

    #[test]
    fn format_severity_high_with_color() {
        let out = format_severity("high", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("high"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("31"), "expected red code 31: {out:?}");
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
        assert!(out.contains("91"), "expected bright-red code 91: {out:?}");
    }

    #[test]
    fn format_severity_case_insensitive_critical_titlecase() {
        let out = format_severity("Critical", true);
        assert!(out.starts_with("\x1b["), "expected ANSI prefix: {out:?}");
        assert!(out.contains("Critical"), "expected input verbatim: {out:?}");
        assert!(out.ends_with("\x1b[0m"), "expected ANSI reset: {out:?}");
        assert!(out.contains("91"), "expected bright-red code 91: {out:?}");
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
        assert!(out.contains("31"), "expected red code 31: {out:?}");
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

    #[test]
    fn format_severity_full_color_ramp_is_exact() {
        // Pin every known arm to its exact wrapper so an accidental palette
        // edit is caught, not just "contains a digit".
        assert_eq!(format_severity("critical", true), "\x1b[91mcritical\x1b[0m");
        assert_eq!(format_severity("high", true), "\x1b[31mhigh\x1b[0m");
        assert_eq!(format_severity("medium", true), "\x1b[33mmedium\x1b[0m");
        assert_eq!(format_severity("low", true), "\x1b[36mlow\x1b[0m");
    }

    #[test]
    fn format_severity_moderate_is_medium_tier_yellow() {
        // Regression: GHSA emits `moderate` for the medium tier (see
        // get.rs `severity_rank`), and both scan.rs call sites pass raw
        // API severities straight through. Dropping `moderate` into the
        // unknown arm rendered a medium-tier vuln with no color at all —
        // less prominent than `low` (cyan).
        assert_eq!(format_severity("moderate", true), "\x1b[33mmoderate\x1b[0m");
        assert_eq!(format_severity("MODERATE", true), "\x1b[33mMODERATE\x1b[0m");
        assert_eq!(format_severity("moderate", false), "moderate");
    }

    #[test]
    fn format_severity_critical_is_more_prominent_than_high() {
        // Regression: `critical` is the worst severity and must render at
        // least as loud as `high`. The ramp uses the high-intensity (9x) red
        // for critical and the standard (3x) red for high; swapping them (the
        // original bug) made `high` brighter than `critical`.
        let crit = format_severity("critical", true);
        let high = format_severity("high", true);
        assert_ne!(crit, high, "critical and high must use distinct colors");
        assert!(
            crit.contains("\x1b[91m"),
            "critical must use high-intensity red 91: {crit:?}"
        );
        assert!(
            high.contains("\x1b[31m"),
            "high must use standard red 31: {high:?}"
        );
        // Guard the inversion directly: critical must not be wrapped in the
        // duller standard-red code that belongs to `high`.
        assert!(
            !crit.contains("\x1b[31m"),
            "critical must not use the duller standard red reserved for high: {crit:?}"
        );
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

    // ---- select_one ----
    //
    // Only the `is_json` branch is exercised here: it returns before reading
    // stdin, so it is deterministic regardless of whether the test runs under
    // a TTY. The non-TTY auto-select (`Ok(0)`) and the interactive
    // `dialoguer` branches both depend on / consume the real stdin and would
    // hang or vary by environment, so they are intentionally left to the e2e
    // suite (see get.rs `select_patches` coverage).

    #[test]
    fn select_one_json_mode_requires_explicit_selection() {
        let opts = vec!["first".to_string(), "second".to_string()];
        match select_one("pick one", &opts, true) {
            Err(SelectError::JsonModeNeedsExplicit) => {}
            Err(SelectError::Cancelled) => panic!("json mode must not report Cancelled"),
            Ok(idx) => panic!("json mode must not auto-select (got index {idx})"),
        }
    }

    #[test]
    fn select_one_json_mode_ignores_options_contents() {
        // Even with a single option, JSON mode must defer to an explicit
        // UUID re-run rather than silently picking it.
        let opts = vec!["only".to_string()];
        assert!(matches!(
            select_one("pick", &opts, true),
            Err(SelectError::JsonModeNeedsExplicit)
        ));
    }

    #[test]
    fn select_one_empty_options_is_cancelled_not_index_zero() {
        // Regression: with no options there is no "first" to auto-select.
        // Returning `Ok(0)` here would hand the caller an out-of-bounds index
        // (every caller does `group[idx]`). This guard runs before any stdin
        // read, so it is deterministic under TTY and non-TTY alike.
        let opts: Vec<String> = Vec::new();
        match select_one("pick", &opts, false) {
            Err(SelectError::Cancelled) => {}
            Ok(idx) => panic!("empty options must not yield an index (got {idx})"),
            Err(SelectError::JsonModeNeedsExplicit) => {
                panic!("non-JSON empty options must report Cancelled, not JSON mode")
            }
        }
    }

    #[test]
    fn select_one_json_mode_takes_precedence_over_empty_options() {
        // JSON mode is decided first: even an empty list must surface the
        // explicit-selection contract so the caller can emit `selection_required`.
        let opts: Vec<String> = Vec::new();
        assert!(matches!(
            select_one("pick", &opts, true),
            Err(SelectError::JsonModeNeedsExplicit)
        ));
    }
}
