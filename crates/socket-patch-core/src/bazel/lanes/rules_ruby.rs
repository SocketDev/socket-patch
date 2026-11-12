//! rules_ruby lane `H-RB1`: the gem pair rewrite, with the existing
//! `gem_checksums` value replaced in the same transaction.
//!
//! Stub until `wp-lane-ruby` (wave 7) replaces this file. Every lane here
//! is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec, Mode};

pub const LANES: &[LaneSpec] = &[LaneSpec::stub("H-RB1", Mode::Hosted, &["U1", "B2"])];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
