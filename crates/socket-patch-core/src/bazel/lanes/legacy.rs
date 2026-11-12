//! Legacy rules, for the extensions `H-NJ1`, `A-NJ1` (rules_nodejs) and
//! `H-RB2` (`rb_bundle`, `ruby_bundle`). Empty in the default set: these
//! shapes are refused.
//!
//! Stub until `wp-ext-legacy` (wave 9) replaces this file. Every lane here
//! is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec};

pub const LANES: &[LaneSpec] = &[];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
