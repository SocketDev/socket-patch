//! The one writer anchored at the Bazel root (design 5.4): `.bazelignore`
//! lines and their index rows. Every other write seam is project-relative,
//! and the project can sit below the root, so ignore lines cannot go
//! through them.
//!
//! Stub until `wp-hz-ignore-line` (wave 2) replaces this file.
