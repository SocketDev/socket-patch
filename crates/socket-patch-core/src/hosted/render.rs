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
/// `skipped`, `patches`, `warnings`, `dryRun`), shared by every hosted path
/// (disk scan, its zero-discovery arm, and the in-memory engine), so the
/// two cannot drift by convention.
/// `mode` is `"hosted"`: an additive key so consumers dispatch on the mode without inferring it from which
/// sub-object is present.
///
/// `patches` is the per-purl outcome of every selected patch, sorted by
/// purl then uuid: `pinned` (`would_pin` under `--dry-run`) for each
/// `confirmed` pin, `skipped` with the skip's reason as `errorCode` (the
/// same rows as `skipped[]`), and `unpinned` (`errorCode:
/// redirect_unconfirmed`) for each granted patch no lockfile entry pins.
/// `redirected` is the `confirmed` count.
pub fn redirect_json_block(
    confirmed: &[(String, String)],
    unconfirmed: &[(String, String)],
    rewritten: Vec<String>,
    skipped: &[SkippedPatch],
    warnings: Vec<serde_json::Value>,
    dry_run: bool,
) -> serde_json::Value {
    let pinned = if dry_run { "would_pin" } else { "pinned" };
    let mut patches: Vec<serde_json::Value> = confirmed
        .iter()
        .map(|(purl, uuid)| serde_json::json!({ "purl": purl, "uuid": uuid, "action": pinned }))
        .chain(skipped.iter().map(|s| {
            let mut row = serde_json::json!({
                "purl": s.purl, "uuid": s.uuid, "action": "skipped", "errorCode": s.reason,
            });
            if let Some(detail) = &s.detail {
                row["error"] = serde_json::json!(detail);
            }
            row
        }))
        .chain(unconfirmed.iter().map(|(purl, uuid)| {
            serde_json::json!({
                "purl": purl, "uuid": uuid, "action": "unpinned",
                "errorCode": REDIRECT_UNCONFIRMED,
                "error": "no lockfile entry pinning it could be rewritten",
            })
        }))
        .collect();
    patches.sort_by(|a, b| {
        (a["purl"].as_str(), a["uuid"].as_str()).cmp(&(b["purl"].as_str(), b["uuid"].as_str()))
    });
    serde_json::json!({
        "mode": "hosted",
        "redirected": confirmed.len(),
        "rewrittenFiles": rewritten,
        "skipped": skipped.iter().map(skipped_json).collect::<Vec<_>>(),
        "patches": patches,
        "warnings": warnings,
        "dryRun": dry_run,
    })
}

/// The `errorCode` of an `unpinned` `redirect.patches[]` row: the patch was
/// granted, but no lockfile entry pinning it could be rewritten.
pub const REDIRECT_UNCONFIRMED: &str = "redirect_unconfirmed";
