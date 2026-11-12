//! Recognizer: `crate.from_cargo`, `crates_repository`, `crate.from_specs`
//! and `crates_vendor`.
//!
//! Stub until `wp-recog-rust-misc` (wave 3) replaces this file. It
//! recognizes no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesRustDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
