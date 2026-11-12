//! `H-MVN1`, discovery, attestation and inventory. The spec lives here
//! because this is the package that lands the lane's real-Bazel cells and
//! enables it.
//!
//! Stub until `wp-lane-rje-discover` (wave 7) replaces this file.

use crate::bazel::model::{LaneSpec, Mode};

pub const H_MVN1: LaneSpec = LaneSpec::stub("H-MVN1", Mode::Hosted, &["M1", "M2", "M4", "H2"]);
