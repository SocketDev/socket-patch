//! Root `MODULE.bazel` with its literal `include()` closure (design 2.7):
//! `bazel_dep`, extension proxies, tags, `use_repo`, overrides.
//!
//! Stub until `wp-module-files` (wave 2) replaces this file.

/// The statements of the root module file and its includes. No value exists
/// until the reader does.
#[derive(Debug, Clone, PartialEq)]
pub enum ModuleModel {}
