//! rules_js lanes: `H-JS1` (the hosted pnpm rewrite on the lock the hub
//! names), `H-JS2` (the same with the `update_pnpm_lock` hash line
//! recomputed) and `V-JS1` (a vendored `file:` entry).
//!
//! Stub until `wp-pilot-rules-js` (wave 6) replaces this file. Every lane
//! here is disabled and refuses.

use crate::bazel::model::{LaneOps, LaneSpec, Mode};

pub const LANES: &[LaneSpec] = &[
    LaneSpec::stub(
        "H-JS1",
        Mode::Hosted,
        &["J1", "J4", "B2", "H1", "H2", "H3", "S12"],
    ),
    LaneSpec::stub("H-JS2", Mode::Hosted, &["J3"]),
    LaneSpec::stub("V-JS1", Mode::Vendored, &["J2", "T7"]),
];
pub const OPS: LaneOps = LaneOps::disabled(LANES);
