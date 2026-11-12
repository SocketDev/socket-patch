//! Recognizer: `npm_translate_lock` hubs: the lock label,
//! `update_pnpm_lock`, import mode, `data` labels, the managed pnpm version
//! and every npmrc rules_js will load.
//!
//! Stub until `wp-recog-js-ruby` (wave 3) replaces this file. It recognizes
//! no hub.

use super::{RecognizeInput, Recognized};

/// What this recognizer records about one hub. No value exists until the
/// recognizer does.
#[derive(Debug, Clone, PartialEq)]
pub enum RulesJsDetail {}

/// The hubs, signals and gaps of this ruleset in `input`.
pub fn recognize(_input: &RecognizeInput<'_>) -> Recognized {
    Recognized::default()
}
