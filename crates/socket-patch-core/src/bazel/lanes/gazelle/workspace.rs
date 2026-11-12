//! `H-GO2`: WORKSPACE `go_repository`. The write leaves the build passing
//! on upstream until the user runs their own `update-repos`; no Starlark is
//! written.
//!
//! Stub until `wp-lane-go-workspace` (wave 7) replaces this file.

use crate::bazel::model::{LaneSpec, Mode};

pub const H_GO2: LaneSpec = LaneSpec::stub("H-GO2", Mode::Hosted, &["G3", "G4"]);
