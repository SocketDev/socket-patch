//! Self-update channels, downloads, swaps and the update notifier.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/pty_io.rs"]
mod pty_io;
#[path = "../common/update_fixture.rs"]
mod update_fixture;

mod covgap_commands_update;
mod covgap_update_download;
mod covgap_update_swap;
mod self_update_channels_e2e;
mod update_notifier_e2e;
