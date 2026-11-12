//! NuGet lanes: `H-NET1` (rules_dotnet: the package's line in the generated
//! `paket.<group>.bzl`) and `H-NET2` (rules_csharp: the native NuGet
//! rewrite on the files the tag names).
//!
//! Stub until `wp-lane-dotnet` (wave 7) replaces this file. Every lane here
//! is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec, Mode};

pub const LANES: &[LaneSpec] = &[LaneSpec::stub("H-NET1", Mode::Hosted, &["U3", "H4"])];
pub const OPS: LaneOps = LaneOps::disabled(LANES);

/// rules_csharp is its own ruleset, so its lane has its own record.
pub const CSHARP_LANES: &[LaneSpec] = &[LaneSpec::stub("H-NET2", Mode::Hosted, &["U3", "B2"])];
pub const CSHARP_OPS: LaneOps = LaneOps::disabled(CSHARP_LANES);
