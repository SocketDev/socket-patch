use std::io::IsTerminal;

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
