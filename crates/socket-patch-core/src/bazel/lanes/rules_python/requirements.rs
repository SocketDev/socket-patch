//! `H-PY1` (Bzlmod `pip.parse`) and `H-PY2` (WORKSPACE `pip_parse`): the
//! direct reference line written to every requirements file the hub names,
//! all or none.
//!
//! Stub until `wp-lane-py-requirements` (wave 7) replaces this file.

use crate::bazel::model::{LaneSpec, Mode};

pub const H_PY1: LaneSpec = LaneSpec::stub("H-PY1", Mode::Hosted, &["Y1", "Y6", "L3", "B2"]);
pub const H_PY2: LaneSpec = LaneSpec::stub("H-PY2", Mode::Hosted, &["Y2", "C13"]);
