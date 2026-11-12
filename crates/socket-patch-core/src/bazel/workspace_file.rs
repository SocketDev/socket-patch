//! The `WORKSPACE` family with one level of main-repository `.bzl` macros
//! (design 2.7): literal top-level calls in definition order, because Bazel
//! builds the first definition of a name.
//!
//! Stub until `wp-module-files` (wave 2) replaces this file.

/// The calls of one WORKSPACE-family file. No value exists until the reader
/// does.
#[derive(Debug, Clone, PartialEq)]
pub enum WorkspaceModel {}
