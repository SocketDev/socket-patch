//! The Bazel rewriter group. It owns every file a hub consumes and calls
//! the native pure rewriter as a library on that file set only, so no
//! native side effect reaches a Bazel build unreviewed.
//!
//! Stub until `wp-int-hosted-rewrite` (wave 5) replaces this file.
