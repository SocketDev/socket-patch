//! Starlark lexer over bytes, with byte spans (design 2.2). What it
//! refuses follows what Bazel accepts: a file that starts with a BOM, uses
//! CR-only line ends or a tab as indentation is refused, as Bazel refuses
//! it. Bytes that are not UTF-8 are legal inside comments and string
//! literals and are read, and so are mixed line endings; only an edit
//! refuses a mixed file.
//!
//! Stub until `wp-starlark` (wave 1) replaces this file.
