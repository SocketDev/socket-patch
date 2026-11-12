//! OS claims: where a real-Bazel cell of a lane has run. Empty until
//! `wp-promote` (wave 8) sets them from the first nightly audit. Only the
//! path-shaped lanes are gated on the host OS; for the others the claim is
//! published and not enforced.

use crate::bazel::model::{ClaimOs, LaneId};

pub const CLAIMS: &[(LaneId, ClaimOs)] = &[];
