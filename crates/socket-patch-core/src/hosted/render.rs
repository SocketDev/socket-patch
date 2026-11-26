//! The hosted engine's results as the JSON the CLI envelope and the
//! in-memory engine return. The engine itself produces typed values
//! ([`RewriteWarning`], [`SkippedPatch`]); only this adapter spells them as
//! JSON, so the disk and memory paths cannot drift in key names.

use super::engine::{
    gem_upstream_build_kept_detail, PinReport, SkippedPatch, GEM_UPSTREAM_BUILD_KEPT,
};
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
/// confirmed pin, `skipped` with the skip's reason as `errorCode` (the
/// same rows as `skipped[]`), and `unpinned` (`errorCode:
/// redirect_unconfirmed`) for each granted patch no lockfile entry pins.
///
/// `reports` are the confirmed pins as a run reports them
/// ([`pin_reports`](super::engine::pin_reports)). A gem the lock names as
/// platform builds has one row per locked build, each with `gemFix` (the
/// gem patch's uuid, the one pin its builds go by) and its `platform` (none
/// on the ruby-platform gem's row): `pinned` under the build's own patch,
/// with `newlyPatched: true` when this run put that build in place, or
/// `upstream_kept` with no `uuid` (`errorCode: gem_upstream_build_kept`)
/// for a build the patch registry serves as upstream's own gem.
/// `redirected` counts the `pinned` rows.
pub fn redirect_json_block(
    reports: &[PinReport],
    unconfirmed: &[(String, String)],
    rewritten: Vec<String>,
    skipped: &[SkippedPatch],
    warnings: Vec<serde_json::Value>,
    dry_run: bool,
) -> serde_json::Value {
    let pinned = if dry_run { "would_pin" } else { "pinned" };
    let mut patches: Vec<serde_json::Value> = reports
        .iter()
        .map(|report| {
            let mut row = match &report.uuid {
                Some(uuid) => {
                    serde_json::json!({ "purl": report.purl, "uuid": uuid, "action": pinned })
                }
                None => serde_json::json!({
                    "purl": report.purl,
                    "action": UPSTREAM_KEPT,
                    "errorCode": GEM_UPSTREAM_BUILD_KEPT,
                    "error": gem_upstream_build_kept_detail(
                        report.platform.as_deref().unwrap_or_default(),
                    ),
                }),
            };
            if let Some(gem_fix) = &report.gem_fix {
                row["gemFix"] = serde_json::json!(gem_fix);
            }
            if let Some(platform) = &report.platform {
                row["platform"] = serde_json::json!(platform);
            }
            if report.newly_patched {
                row["newlyPatched"] = serde_json::json!(true);
            }
            row
        })
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
        "redirected": reports.iter().filter(|report| report.uuid.is_some()).count(),
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

/// The `action` of the `redirect.patches[]` row of a locked platform build
/// of a hosted gem that the patch registry serves as upstream's own gem:
/// that build is as it was, and is neither pinned to a patch nor skipped.
pub const UPSTREAM_KEPT: &str = "upstream_kept";

#[cfg(test)]
mod tests {
    use super::*;

    /// A pin of any package is one `pinned` row with `purl` and `uuid`
    /// alone. A gem the lock names as platform builds is one row per
    /// locked build: `pinned` under the build's own patch, or
    /// `upstream_kept` with no `uuid` for a build that stays upstream's
    /// gem, which `redirected` does not count and `skipped[]` does not
    /// list. A dry run previews a pin as `would_pin`.
    #[test]
    fn the_redirect_block_reports_a_platform_locked_gem_per_build() {
        const FIX: &str = "77777777-7777-4777-8777-777777777777";
        let build = |platform: Option<&str>, uuid: Option<&str>, newly: bool| PinReport {
            purl: match platform {
                Some(platform) => format!("pkg:gem/nokogiri@1.19.3?platform={platform}"),
                None => "pkg:gem/nokogiri@1.19.3".to_string(),
            },
            uuid: uuid.map(str::to_string),
            gem_fix: Some(FIX.to_string()),
            platform: platform.map(str::to_string),
            newly_patched: newly,
        };
        let reports = [
            PinReport {
                purl: "pkg:npm/a@1.0.0".into(),
                uuid: Some("ua".into()),
                gem_fix: None,
                platform: None,
                newly_patched: false,
            },
            build(None, Some(FIX), false),
            build(Some("arm64-darwin"), None, false),
            build(Some("x86_64-linux-gnu"), Some("ul"), true),
        ];
        let block = redirect_json_block(&reports, &[], Vec::new(), &[], Vec::new(), false);
        assert_eq!(block["redirected"], 3);
        assert_eq!(block["skipped"], serde_json::json!([]));
        assert_eq!(
            block["patches"],
            serde_json::json!([
                {
                    "purl": "pkg:gem/nokogiri@1.19.3", "uuid": FIX, "action": "pinned",
                    "gemFix": FIX,
                },
                {
                    "purl": "pkg:gem/nokogiri@1.19.3?platform=arm64-darwin",
                    "action": "upstream_kept",
                    "errorCode": "gem_upstream_build_kept",
                    "error": "the patch registry serves upstream's own gem for arm64-darwin: no \
                              patched build yet",
                    "gemFix": FIX,
                    "platform": "arm64-darwin",
                },
                {
                    "purl": "pkg:gem/nokogiri@1.19.3?platform=x86_64-linux-gnu", "uuid": "ul",
                    "action": "pinned", "gemFix": FIX, "platform": "x86_64-linux-gnu",
                    "newlyPatched": true,
                },
                { "purl": "pkg:npm/a@1.0.0", "uuid": "ua", "action": "pinned" },
            ])
        );
        let dry = redirect_json_block(&reports, &[], Vec::new(), &[], Vec::new(), true);
        let actions: Vec<&str> = dry["patches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["action"].as_str().unwrap())
            .collect();
        assert_eq!(
            actions,
            ["would_pin", "upstream_kept", "would_pin", "would_pin"]
        );
        assert_eq!(dry["redirected"], 3);
    }
}
