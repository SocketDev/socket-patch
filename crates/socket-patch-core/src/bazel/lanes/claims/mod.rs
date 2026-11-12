//! Line and OS claims made after a lane first lands (design 8). They live
//! here, one file per owner, so the closing-wave packages that prove the
//! Beta and Legacy lines and record the nightly's OS cells never edit a
//! lane file. A row is added only with the report of an executed cell.

pub mod beta;
pub mod legacy;
pub mod os;

use crate::bazel::model::{CellClaim, ClaimOs, LaneId};

/// The line claims of `lane` beyond the ones its `LaneSpec` carries, each
/// with the tier file that makes it.
pub fn line_claims(lane: LaneId) -> impl Iterator<Item = (&'static str, &'static CellClaim)> {
    let of = move |tier: &'static str, rows: &'static [(LaneId, CellClaim)]| {
        rows.iter()
            .filter(move |(id, _)| *id == lane)
            .map(move |(_, claim)| (tier, claim))
    };
    of("beta", beta::CLAIMS).chain(of("legacy", legacy::CLAIMS))
}

/// The operating systems a real-Bazel cell of `lane` has run on.
pub fn os_claims(lane: LaneId) -> impl Iterator<Item = ClaimOs> {
    os::CLAIMS
        .iter()
        .filter(move |(id, _)| *id == lane)
        .map(|(_, os)| *os)
}
