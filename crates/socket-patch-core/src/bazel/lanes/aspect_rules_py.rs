//! aspect_rules_py lane `H-APY1`: the uv pair rewrite under `uv.project`.
//!
//! Stub until `wp-lane-py-locks` (wave 7) replaces this file. Every lane
//! here is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec, Mode};

pub const LANES: &[LaneSpec] = &[LaneSpec::stub("H-APY1", Mode::Hosted, &["Y4"])];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
