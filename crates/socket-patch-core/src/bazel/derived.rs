//! Derived state and the lock-refresh policy (design 2.10): every piece of
//! state Bazel or a ruleset derives from the bytes an edit changes, and
//! whether socket-patch can repair it. It runs on forward and on restoring
//! edits alike.
//!
//! Stub until `wp-derived-remedy` (wave 2) replaces this file.

use super::remedy::Remedy;

/// One piece of state an edit makes stale. No value exists until the table
/// does.
#[derive(Debug, Clone, PartialEq)]
pub enum DerivedState {}

/// The one rule behind the three outcomes.
#[derive(Debug, Clone, PartialEq)]
pub enum InterimState {
    /// Nothing stale, or repaired in the same transaction: works.
    Green,
    /// Build and tests keep passing and one command refreshes committed
    /// state: works after.
    SelfHealing { command: Remedy },
    /// The next build would fail: refused.
    Red { what: DerivedState, remedy: Remedy },
}
