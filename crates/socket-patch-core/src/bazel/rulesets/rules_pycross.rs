//! Recognizer: lock-import tags by lock kind, `lock_file.instantiate` and
//! `pycross_lock_repo`.
//!
//! Stub until `wp-recog-python` (wave 3) replaces this file. It recognizes
//! no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesPycrossDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
