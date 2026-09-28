//! Hosted mode: rewrite ONLY the patched dependencies' lockfile /
//! registry-config entries to point at Socket's hosted patched artifacts.
//!
//! - [`engine`] — the one plan → rewrite → edits engine, over a
//!   [`ProjectView`](crate::vendor::lock_inventory::ProjectView), shared by
//!   the disk flow (`scan`/`get --mode hosted` in the CLI) and the
//!   in-memory engine.
//! - [`guidance`] — the pnpm `trustLockfile` / npm `allow-remote`
//!   auto-config planners and their warning texts.
//! - [`vlt`] — the vlt artifact preflight.
//! - [`ledger`] — the redirect-ledger delta (merge, in-memory load,
//!   serialization), kept apart so the engine never depends on it.
//! - [`memory`] — the engine over an in-memory repository (no filesystem,
//!   subprocesses, environment or telemetry), embedded by the Node addon
//!   (`socket-patch-node`) and the CLI's hidden `hosted-bundle` harness.

pub mod engine;
pub mod guidance;
pub mod ledger;
pub mod memory;
pub mod render;
pub mod vlt;
