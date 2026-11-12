//! Recognizer: `maven.install` and `maven_install` hubs, pinned or
//! unpinned, with their overrides.
//!
//! Stub until `wp-recog-jvm-dotnet` (wave 3) replaces this file. It
//! recognizes no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesJvmExternalDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
