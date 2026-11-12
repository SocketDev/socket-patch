//! `MODULE.bazel.lock`, read-only (design 2.10): both lock families,
//! selected module versions, recorded inputs, extension entries and facts.
//! socket-patch never writes this file; it reads it to predict what an edit
//! makes stale.
//!
//! Stub until `wp-module-lock` (wave 1) replaces this file.

/// The lock as found: absent, a known family, unreadable or an unknown
/// shape. No value exists until the reader does.
#[derive(Debug, Clone, PartialEq)]
pub enum ModuleLock {}
