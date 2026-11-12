//! The resolved ruleset version as a range (design 2.8). A lower-bound gate
//! rests on the declaration, never on a lock that cannot be proven fresh.
//!
//! Stub until `wp-module-lock` (wave 1) replaces this file.

/// `{lo, hi}` with the source of each side. No value exists until the
/// reader does.
#[derive(Debug, Clone, PartialEq)]
pub enum VersionVerdict {}
