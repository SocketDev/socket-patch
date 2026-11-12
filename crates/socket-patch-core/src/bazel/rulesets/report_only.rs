//! Recognizer: shapes that are reported and never patched
//! (rules_req_compile, rules_poetry, bazel-deps, hand-written JVM pins,
//! cargo-raze, hubs of a non-root module), with the out-of-scope counts.
//!
//! Stub until `wp-recog-rust-misc` (wave 3) replaces this file. It
//! recognizes no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum ReportOnlyDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
