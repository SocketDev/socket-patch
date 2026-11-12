//! Helpers shared by the two Bazel CLI suites, `e2e_bazel` (hermetic) and
//! `e2e_bazel_build` (real Bazel): tree snapshots and the write-policy
//! oracle. Each pulls this in with
//! `#[path = "../bazel_common/mod.rs"] mod bazel_common;`.
//!
//! The oracle exists because "do no harm" is a claim about every file in
//! the repository, not only the ones a test thought to look at: a test
//! snapshots the tree, runs socket-patch, and [`assert_write_policy`]
//! classifies every path that changed. A path outside the allowed classes
//! fails the test, whatever the lane meant to do.
//!
//! No `#[cfg(test)]` here: integration crates do not set it, and a module
//! gated on it would compile to nothing. `selftests` runs in each binary
//! that includes this module.

#![allow(dead_code)]

pub mod snapshot;
pub mod write_policy;

mod selftests;

#[allow(unused_imports)]
pub use snapshot::{assert_same_tree, changes, snapshot, Change, Entry, Snapshot};
#[allow(unused_imports)]
pub use write_policy::{assert_write_policy, assert_write_policy_with, classify, WriteClass};
