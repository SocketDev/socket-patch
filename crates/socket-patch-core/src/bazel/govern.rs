//! Governance (design 2.9): which lock Bazel reads for one ecosystem in
//! one project, from the dependency system, per-name hybrid resolution and
//! each hub's liveness.
//!
//! Stub until `wp-detect-govern` (wave 3). It answers `Undetermined` for
//! every question: an unread workspace is not an ungoverned one, and
//! `NotGoverned` would let the native writers run on a lock Bazel reads.

use super::model::{BazelWorkspace, Governance};
use crate::crawlers::types::Ecosystem;

/// Governance of `ecosystem` for the project at `project_rel`.
pub fn governance(_ws: &BazelWorkspace, _ecosystem: Ecosystem, _project_rel: &str) -> Governance {
    Governance::Undetermined(Vec::new())
}
