//! The single decision entry (design 2.12). `scan`, `get`, `apply`,
//! `vendor`, `rollback`, `remove`, `repair`, `list`, `vex`, `--prune` and
//! the in-memory engine all ask here before they act on a lock Bazel
//! reads, so no path can write or attest around the checks.
//!
//! Stub: `wp-gate` (wave 4) lands the obligations and the dispatch through
//! the lane table. Until then every question is refused, so nothing is
//! written or attested on this module's authority. [`LaneCx`] and
//! [`PatchRequest`] are placeholders the same package completes (the
//! workspace, the hub, the grant's digests). The facade re-exports `gate`
//! and `governed` and `model` re-exports the two types, so the four names
//! stay.

use super::govern::governance;
use super::model::{
    BazelWorkspace, FileView, GateOutcome, Governance, LaneTable, Mode, Refusal, Ruleset,
};
use crate::crawlers::types::Ecosystem;

/// What a lane function is handed about the run.
pub struct LaneCx<'a> {
    pub mode: Mode,
    pub files: &'a dyn FileView,
}

/// One patch a caller wants wired, and the project that resolves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchRequest<'a> {
    pub ecosystem: Ecosystem,
    pub name: &'a str,
    pub version: &'a str,
    pub uuid: &'a str,
    /// The project relative to the Bazel root, `""` at the root.
    pub project_rel: &'a str,
}

/// Decides one patch in one mode. The first failed obligation refuses.
pub fn gate(
    _ws: &BazelWorkspace,
    _lanes: &LaneTable,
    _mode: Mode,
    _req: &PatchRequest<'_>,
    _files: &dyn FileView,
) -> GateOutcome {
    GateOutcome::Refuse(Refusal::lane_not_enabled())
}

/// The governance of every ecosystem a Bazel ruleset can build, for the
/// project at `project_rel`. An ecosystem that is absent is one Bazel
/// cannot govern, never one that was not looked at.
pub fn governed(ws: &BazelWorkspace, project_rel: &str) -> Vec<(Ecosystem, Governance)> {
    let mut out: Vec<(Ecosystem, Governance)> = Vec::new();
    for ecosystem in Ruleset::ALL.iter().filter_map(|r| r.ecosystem()) {
        if !out.iter().any(|(seen, _)| *seen == ecosystem) {
            out.push((ecosystem, governance(ws, ecosystem, project_rel)));
        }
    }
    out
}
