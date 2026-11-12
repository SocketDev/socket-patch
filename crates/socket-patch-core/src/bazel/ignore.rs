//! `.bazelignore` model (design 5.3): a reader that copies Bazel, the
//! coverage test, the canonical line insert and exact-line removal. The
//! lines keep upstream BUILD files under `.socket` trees out of `//...`.
//!
//! Stub until `wp-ignore-index` (wave 1) replaces this file.

/// The lines of one root's `.bazelignore`. No value exists until the reader
/// does.
#[derive(Debug, Clone, PartialEq)]
pub enum IgnoreModel {}
