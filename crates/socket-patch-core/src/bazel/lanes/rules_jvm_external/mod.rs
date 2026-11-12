//! rules_jvm_external lane `H-MVN1`: a new rewriter for
//! `maven_install.json` (lock v2 and v3) that pins the Socket version and
//! digest and recomputes the resolved hash in the file's own format.
//!
//! Stub until `wp-lane-rje-rewrite` (wave 7) replaces this file. The lane
//! is disabled and refuses. The `mod` lines stay: the files they name
//! belong to other packages.

pub mod discover;
pub mod restore;
pub mod rewrite;

use crate::bazel::model::{LaneOps, LaneSpec};

pub const LANES: &[LaneSpec] = &[discover::H_MVN1];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
