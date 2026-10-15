//! Self-update channels, downloads, swaps and the update notifier.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/pty_io.rs"]
mod pty_io;
#[path = "../common/update_fixture.rs"]
mod update_fixture;

mod self_update_channels_e2e;
mod self_update_telemetry_e2e;
mod update_json_contracts;
mod update_notifier_e2e;
mod update_render;
