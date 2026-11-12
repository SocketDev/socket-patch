//! Helpers shared by the two Bazel CLI suites, `e2e_bazel` (hermetic) and
//! `e2e_bazel_build` (real Bazel): tree snapshots and the write-policy
//! oracle. Each pulls this in with
//! `#[path = "../bazel_common/mod.rs"] mod bazel_common;`.
//!
//! The oracle exists because "do no harm" is a claim about every file in
//! the repository, not only the ones a test thought to look at: a test
//! snapshots the tree, runs socket-patch, and the oracle classifies every
//! path that changed. A path outside the allowed classes fails the test,
//! whatever the lane meant to do. Which check a test runs depends on the
//! command:
//!
//! - a run that wires, repairs or takes over: [`assert_write_policy`], on
//!   the snapshot taken right after socket-patch exits and before any
//!   Bazel command (Bazel rewrites `MODULE.bazel.lock` itself);
//! - a run that restores (`rollback`, `remove`): [`assert_restore_policy`],
//!   which requires the inverse of an allowed write, and for a round trip
//!   also [`assert_same_tree`] against the snapshot taken before the
//!   wiring;
//! - a comparison made after Bazel ran: [`assert_same_tree_but_bazel_owned`],
//!   which leaves out the files Bazel writes.
//!
//! No `#[cfg(test)]` here: integration crates do not set it, and a module
//! gated on it would compile to nothing. `selftests` runs in each binary
//! that includes this module.

#![allow(dead_code)]

pub mod snapshot;
pub mod write_policy;

mod selftests;

#[allow(unused_imports)]
pub use snapshot::{
    assert_same_tree, assert_same_tree_but_bazel_owned, changes, snapshot, without_bazel_owned,
    Change, Entry, Snapshot,
};
#[allow(unused_imports)]
pub use write_policy::{
    assert_restore_policy, assert_restore_policy_with, assert_write_policy,
    assert_write_policy_with, classify, classify_restore, Layout, WriteClass,
};
