//! `A-GO1` and `V-GO1`: the directory `replace` over a committed module
//! tree. The absolute path `go_deps` derives from it must never reach a
//! committed file.
//!
//! Stub until `wp-lane-go-directory` (wave 7) replaces this file.

use crate::bazel::model::{LaneSpec, Mode};

pub const A_GO1: LaneSpec = LaneSpec::stub("A-GO1", Mode::Agent, &["G1", "G2", "B3", "S9", "T7"]);
pub const V_GO1: LaneSpec =
    LaneSpec::stub("V-GO1", Mode::Vendored, &["G1", "G2", "B3", "S9", "T7"]);
