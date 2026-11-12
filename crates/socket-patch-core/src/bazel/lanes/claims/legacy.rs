//! Legacy-line claims: Bazel 5.x WORKSPACE and 6.x. Empty until
//! `wp-lines-legacy` (wave 8) proves a cell; until then the gate refuses
//! those lines as unproven.

use crate::bazel::model::{CellClaim, LaneId};

pub const CLAIMS: &[(LaneId, CellClaim)] = &[];
