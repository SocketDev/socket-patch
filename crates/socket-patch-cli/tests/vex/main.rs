//! `vex`: its `--json` failure contracts, the go-patches synthesis guards
//! and the human output (#1089).
//!
//! One test binary per command: `covgap_commands_vex.rs` and
//! `vex_terminal_output.rs` were each their own binary.
//! `cli_parse_vex.rs` stays separate because it mutates the process
//! environment under `serial_test`.

#[path = "../common/mod.rs"]
mod common;

mod vex_failure_paths;
mod vex_fixture;
mod vex_go_patches;
mod vex_render;
