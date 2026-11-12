//! Recognizer: `uv.project` and `uv.lockfile` hubs with their override
//! tags.
//!
//! Stub until `wp-recog-python` (wave 3) replaces this file. It recognizes
//! no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum AspectRulesPyDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
