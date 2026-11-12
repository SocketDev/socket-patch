//! The Go selection and provision proofs (design 4.4). Bazel selects module
//! versions over every module that calls `go_deps.from_file`, so the root
//! `go.mod` alone does not say which version is built; a Go lane writes
//! only with both proofs.
//!
//! Stub until `wp-lane-go-hosted` (wave 7) replaces this file.
