//! CLI glue for Bazel builds: the one place the commands ask the pure layer
//! (`socket_patch_core::bazel`). It loads the workspace model once per run
//! and Bazel root and emits the run-level warnings once. It is not under
//! `commands/`, so the command layering allowlist does not grow.
//!
//! Stub until `wp-seam-prep` (wave 4) replaces this file. No command calls
//! into it yet. The `mod` lines stay: the files they name belong to the
//! integration packages.

pub mod agent;
pub mod agent_go;
pub mod commands;
pub mod hosted;
pub mod vendored;
pub mod vex;
