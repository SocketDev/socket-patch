//! Recognizer: `go_deps` tags and literal `go_repository` rules, with the
//! inputs of the Go selection and provision proofs.
//!
//! Stub until `wp-recog-go` (wave 3) replaces this file. It recognizes no
//! hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum GazelleDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
