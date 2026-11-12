//! `H-GO1`: the fork `replace` plus `go.sum`, fetched by `go mod download`
//! through `GOPROXY`.
//!
//! Stub until `wp-lane-go-hosted` (wave 7) replaces this file.

use crate::bazel::model::{LaneSpec, Mode};

pub const H_GO1: LaneSpec = LaneSpec::stub("H-GO1", Mode::Hosted, &["G1", "G2", "G4", "H4"]);
