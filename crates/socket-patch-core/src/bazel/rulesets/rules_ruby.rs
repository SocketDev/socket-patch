//! Recognizer: `bundle_fetch`, `rb_bundle_fetch`, `rb_bundle` and
//! `ruby_bundle` with `gem_checksums`.
//!
//! Stub until `wp-recog-js-ruby` (wave 3) replaces this file. It recognizes
//! no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesRubyDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
