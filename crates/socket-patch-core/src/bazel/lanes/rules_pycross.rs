//! rules_pycross lane `H-PYX1`: the uv pair rewrite, or a poetry URL
//! source.
//!
//! Stub until `wp-lane-py-locks` (wave 7) replaces this file. Every lane
//! here is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec, Mode};

pub const LANES: &[LaneSpec] = &[LaneSpec::stub("H-PYX1", Mode::Hosted, &["Y4"])];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
