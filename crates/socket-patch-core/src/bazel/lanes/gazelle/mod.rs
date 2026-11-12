//! gazelle lanes: `H-GO1` (hosted fork replace), `A-GO1` and `V-GO1`
//! (directory replace) and `H-GO2` (WORKSPACE `go_repository`). Each spec
//! lives in the file of the package that enables it.
//!
//! Stub until `wp-lane-go-hosted` (wave 7) replaces this file. Every lane
//! here is disabled and refuses. The `mod` lines stay: the files they name
//! belong to other packages.

pub mod directory;
pub mod hosted;
pub mod proofs;
pub mod workspace;

use crate::bazel::model::{LaneOps, LaneSpec};

pub const LANES: &[LaneSpec] = &[
    hosted::H_GO1,
    directory::A_GO1,
    directory::V_GO1,
    workspace::H_GO2,
];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
