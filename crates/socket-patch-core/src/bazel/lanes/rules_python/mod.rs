//! rules_python lanes: `H-PY1` and `H-PY2` (requirements files) and `H-PY3`
//! (`uv_lock`). Each spec lives in the file of the package that enables it.
//!
//! Stub until `wp-lane-py-requirements` (wave 7) replaces this file. Every
//! lane here is disabled and refuses. The `mod` lines stay: `uv_lock`
//! belongs to another package.

pub mod requirements;
pub mod uv_lock;

use crate::bazel::model::{LaneOps, LaneSpec};

pub const LANES: &[LaneSpec] = &[requirements::H_PY1, requirements::H_PY2, uv_lock::H_PY3];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
