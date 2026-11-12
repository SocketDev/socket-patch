//! Real-Bazel plumbing for `e2e_bazel_build`, the one suite that runs
//! Bazel. Pulled in with
//! `#[path = "../bazel_build_common/mod.rs"] mod bazel_build_common;` by a
//! crate root that also declares `mod common`.
//!
//! - [`env`]: the `SOCKET_PATCH_BAZEL_E2E_*` variables, the Bazel version
//!   and the flags that differ per line.
//! - [`isolation`]: the scratch root every write stays inside, and the
//!   checks that it did.
//! - [`invoke`]: the Bazel to drive, its startup options, environment and
//!   command options.
//! - [`server`]: [`server::Cell`], one test's workspace copy, output base
//!   and server, shut down and removed on drop.
//! - [`workspace`]: fixture copy-in, the downloader config, the rules for
//!   `MODULE.bazel.lock`.
//! - [`fixture_server`] and [`registry`]: the loopback server that plays
//!   every upstream host.
//! - [`proof`]: the proof ladder, tiers 0 to 2.
//! - [`toy`]: the core fixture (`fixtures/bazel/core`) and the committed
//!   registry subset that lets a cell on it run with no network.
//! - [`probe_report`]: the per-cell JSON a claim rests on.
//!
//! Socket-patch itself never runs Bazel; only this harness does. Every
//! child is spawned through `common::hermetic::command`.
//!
//! No `#[cfg(test)]` here: integration crates do not set it. `selftests`
//! needs no Bazel and runs on every `cargo test` of the including binary.

#![allow(dead_code)]

pub mod env;
pub mod fixture_server;
pub mod invoke;
pub mod isolation;
pub mod probe_report;
pub mod proof;
pub mod registry;
pub mod server;
pub mod toy;
pub mod workspace;

mod selftests;
