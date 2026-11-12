//! `.bazelrc` reader (design 2.6): the grammar, imports, command chains and
//! `--config` expansion, giving one [`FlagState`] per flag. Only tracked,
//! in-repository rc files steer what socket-patch commits, and rc evidence
//! only escalates: it can add a hazard and never remove one.
//!
//! Stub until `wp-rc-version` (wave 1) replaces this file.

use std::collections::BTreeMap;

/// What the tracked rc files say about one flag on one command chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagState<T> {
    Set(T),
    /// Set only under a named config, by config name.
    Possible(BTreeMap<String, T>),
    /// A plain `import` could not be read: hosted writes are refused.
    UnknowableHard(String),
    /// An absent or git-ignored `try-import` target: an advisory.
    UnknowableSoft(String),
    NotSeen,
}

/// One [`FlagState`] per flag of design 2.6, per command chain. No value
/// exists until the reader does.
#[derive(Debug, Clone, PartialEq)]
pub enum EffectiveFlags {}
