//! rules_rust lane `H-RS2`: the three-file cargo redirect for
//! crate_universe under Bzlmod without a `lockfile`. Every other
//! crate_universe shape is refused.
//!
//! Stub until `wp-lane-rust` (wave 7) replaces this file. Every lane here
//! is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec, Mode};

pub const LANES: &[LaneSpec] = &[LaneSpec::stub("H-RS2", Mode::Hosted, &["R1", "R2", "B2"])];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
