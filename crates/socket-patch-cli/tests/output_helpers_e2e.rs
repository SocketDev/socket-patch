//! Integration coverage for `socket_patch_cli::output` helpers.
//! The pub `format_severity` and `color` functions are widely used
//! by `commands/scan.rs` + `commands/list.rs` for human-mode display,
//! but the integration test suite runs all its scan/list tests in
//! `--json` mode (which suppresses the colour wrappers entirely), so
//! every ANSI branch was uncovered. These tests drive each branch
//! directly via the lib's pub API.

use socket_patch_cli::output::{color, format_severity};

#[test]
fn format_severity_no_color_returns_input_verbatim() {
    assert_eq!(format_severity("critical", false), "critical");
    assert_eq!(format_severity("high", false), "high");
    assert_eq!(format_severity("medium", false), "medium");
    assert_eq!(format_severity("low", false), "low");
    assert_eq!(format_severity("unknown", false), "unknown");
}

#[test]
fn format_severity_critical_wraps_in_red() {
    // Exact envelope: red open + verbatim text + reset, nothing else.
    assert_eq!(format_severity("critical", true), "\x1b[31mcritical\x1b[0m");
}

#[test]
fn format_severity_high_wraps_in_bright_red() {
    assert_eq!(format_severity("high", true), "\x1b[91mhigh\x1b[0m");
}

#[test]
fn format_severity_medium_wraps_in_yellow() {
    assert_eq!(format_severity("medium", true), "\x1b[33mmedium\x1b[0m");
}

#[test]
fn format_severity_low_wraps_in_cyan() {
    assert_eq!(format_severity("low", true), "\x1b[36mlow\x1b[0m");
}

#[test]
fn format_severity_unknown_passes_through_unwrapped() {
    // The `_` arm returns the input verbatim — no ANSI wrapper.
    let out = format_severity("nonsense", true);
    assert!(!out.contains("\x1b["), "unknown severity must not wrap: {out:?}");
    assert_eq!(out, "nonsense");
}

#[test]
fn format_severity_case_insensitive() {
    // The lowercase match must apply to mixed-case input — AND the displayed
    // text must be the caller's verbatim, original-case string (production
    // wraps `{s}`, not the lowercased key). Exact-equality catches both a
    // miscoloured branch and any impl that lowercases the rendered text.
    assert_eq!(format_severity("CRITICAL", true), "\x1b[31mCRITICAL\x1b[0m");
    assert_eq!(format_severity("High", true), "\x1b[91mHigh\x1b[0m");
    assert_eq!(format_severity("MEDIUM", true), "\x1b[33mMEDIUM\x1b[0m");
    assert_eq!(format_severity("Low", true), "\x1b[36mLow\x1b[0m");
}

#[test]
fn color_with_use_color_false_returns_input() {
    assert_eq!(color("text", "31", false), "text");
}

#[test]
fn color_with_use_color_true_wraps_with_code() {
    let out = color("text", "31", true);
    assert_eq!(out, "\x1b[31mtext\x1b[0m");
}

#[test]
fn color_with_empty_text_still_wraps() {
    // Edge case: empty input still gets the ANSI envelope when
    // colour is enabled.
    let out = color("", "31", true);
    assert_eq!(out, "\x1b[31m\x1b[0m");
}
