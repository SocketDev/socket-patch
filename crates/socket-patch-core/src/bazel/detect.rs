//! The fixpoint reader (design 2.2): boundary files, the `include()`
//! closure, rc files and the recognizers of `rulesets`, read lazily into
//! one [`BazelWorkspace`] per root or the union of nested roots.
//!
//! Stub until `wp-detect-govern` (wave 3): it reads nothing and says so
//! with an error, because "no model" must never be taken for "no Bazel".
//! The facade re-exports this function, so the name stays.

use super::model::{BazelWorkspace, FileView, Gap, RootRef, LANE_NOT_ENABLED};

/// Reads the workspace at `root` through `files`.
pub fn detect(_root: &RootRef, _files: &dyn FileView) -> Result<BazelWorkspace, Gap> {
    Err(Gap {
        token: LANE_NOT_ENABLED,
        file: String::new(),
        detail: "this build cannot read a Bazel workspace yet".to_string(),
    })
}
