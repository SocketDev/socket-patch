//! Hosted mode: rewrite ONLY the patched dependencies' lockfile /
//! registry-config entries to point at Socket's hosted patched artifacts.
//!
//! - [`engine`] — the one plan → rewrite → edits engine, over a
//!   [`ProjectView`](crate::vendor::lock_inventory::ProjectView), shared by
//!   the disk flow (`scan`/`get --mode hosted` in the CLI) and the
//!   in-memory engine.
//! - [`governing_root`] — the workspace-member pre-check (a lock in an
//!   ancestor directory governs the project).
//! - [`guidance`] — the pnpm `trustLockfile` / npm `allow-remote`
//!   auto-config planners and their warning texts.
//! - [`vlt`] — the vlt artifact preflight.
//! - [`memory`] — the engine over an in-memory repository (no filesystem,
//!   subprocesses, environment or telemetry), embedded by the Node addon
//!   (`socket-patch-node`) and the CLI's hidden `hosted-bundle` harness.

pub mod engine;
pub mod governing_root;
pub mod guidance;
pub mod memory;
pub mod render;
pub mod vlt;
