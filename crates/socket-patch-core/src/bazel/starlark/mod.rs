//! The Starlark reader (design 2.1): hand-written and bounded like the
//! Gradle script graph (depth 8, 512 files, 1 MiB per file). It reads
//! committed files only; nothing evaluates Starlark.
//!
//! Stub until `wp-starlark` (wave 1) replaces this file.

pub mod edit;
pub mod lexer;
pub mod stmt;
