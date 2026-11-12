//! Recognizer: paket hubs, resolved from the extension file through its
//! `load` to the generated data file.
//!
//! Stub until `wp-recog-jvm-dotnet` (wave 3) replaces this file. It
//! recognizes no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesDotnetDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
