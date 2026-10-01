//! The hosted engine's results as the JSON the CLI envelope and the
//! in-memory engine return. The engine itself produces typed values
//! ([`RewriteWarning`], [`SkippedPatch`]); only this adapter spells them as
//! JSON, so the disk and memory paths cannot drift in key names.

use super::engine::SkippedPatch;
use crate::patch::redirect::RewriteWarning;

/// A `skipped[]` entry (`{purl, uuid, reason[, detail]}`).
pub fn skipped_json(skipped: &SkippedPatch) -> serde_json::Value {
    serde_json::to_value(skipped).expect("SkippedPatch is plain strings: serialization cannot fail")
}

/// Warnings as `{code, detail}` JSON.
pub fn rewrite_warnings_json(warnings: &[RewriteWarning]) -> Vec<serde_json::Value> {
    warnings
        .iter()
        .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail }))
        .collect()
}

/// The nested `redirect` block of every hosted `--json` envelope — the ONE
/// spelling of its key set (`mode`, `redirected`, `rewrittenFiles`,
/// `skipped`, `warnings`, `dryRun`), shared by every hosted path (disk
/// scan, its zero-discovery arm, and the in-memory engine), so the two cannot drift by convention.
/// `mode` is `"hosted"`: an additive key so consumers dispatch on the mode without inferring it from which
/// sub-object is present.
pub fn redirect_json_block(
    redirected: usize,
    rewritten: Vec<String>,
    skipped: Vec<serde_json::Value>,
    warnings: Vec<serde_json::Value>,
    dry_run: bool,
) -> serde_json::Value {
    serde_json::json!({
        "mode": "hosted",
        "redirected": redirected,
        "rewrittenFiles": rewritten,
        "skipped": skipped,
        "warnings": warnings,
        "dryRun": dry_run,
    })
}
