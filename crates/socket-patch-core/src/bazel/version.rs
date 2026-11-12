//! Bazel line ladder, tier table, the dependency-system table (its one
//! owner), the `lockFileVersion` table and version ordering (design 2.4,
//! 2.5, 8). A prerelease of a threshold is below it.
//!
//! Stub until `wp-rc-version` (wave 1) replaces this file.

/// The Bazel release range a workspace runs, with the evidence for each
/// bound. No value exists until the reader does.
#[derive(Debug, Clone, PartialEq)]
pub enum BazelLine {}

/// Supported, Beta, Legacy or Refused. No value exists until the reader
/// does.
#[derive(Debug, Clone, PartialEq)]
pub enum Tier {}

/// Bzlmod, WORKSPACE, hybrid, dual-mode or unknown. No value exists until
/// the reader does.
#[derive(Debug, Clone, PartialEq)]
pub enum DepSystem {}
