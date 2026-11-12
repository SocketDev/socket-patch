//! rules_rs lanes: `V-RSR1` (vendored `[patch]` path) and `H-RSR1` (hosted,
//! which stays disabled until the owner signs off the token in the
//! repository name).
//!
//! Stub until `wp-lane-rust` (wave 7) replaces this file. Every lane here
//! is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec, Mode};

pub const LANES: &[LaneSpec] = &[
    LaneSpec::stub("V-RSR1", Mode::Vendored, &["R6", "B3"]),
    LaneSpec::stub("H-RSR1", Mode::Hosted, &["R6"]),
];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
