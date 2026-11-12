//! Every code the Bazel layer emits (design 6): `enum Code` with its
//! string, level and the `Reason` to code mapping.
//!
//! Stub until `wp-codes` (wave 0) replaces this file. The empty enum keeps
//! `model::Advisory` uninhabited, so no code string exists outside the
//! file the contract test reads.

/// A code of the CLI contract's Bazel section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {}
