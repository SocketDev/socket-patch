//! Canonical ordering for patches available on a single package.
//!
//! When a package has more than one available patch, exactly one gets
//! applied (the manifest holds one patch record per PURL). This module is
//! the single place that decides which, and the single place that decides
//! how patch lists are presented. Every listing the CLI prints, every JSON
//! array it emits, and the actual apply-time selection all derive from the
//! comparators here, so the user can never be shown one ordering and handed
//! a different patch.
//!
//! **The order, best first:**
//!
//! 1. **Merged patches** — the fix has landed upstream, so it is the one
//!    the ecosystem is converging on.
//! 2. **Severity** — critical > high > medium/moderate > low > unknown,
//!    taken as the worst severity across everything the patch fixes.
//! 3. **Patch publish date**, most recent first. This is the date *the
//!    patch* was published, never the date the upstream package version
//!    was released — a 2020 package routinely carries a patch published
//!    last week, and two patches for one package have two different dates.
//!    See [`crate::api::types::PatchResponse::published_at`].
//! 4. Paid tier, then UUID — pure tiebreaks, present only so the order is
//!    total and therefore reproducible run to run.
//!
//! Note what is *not* in the list: `tier` is an access filter, not a
//! ranking signal. A free critical patch outranks a paid low one.

use std::cmp::{Ordering, Reverse};

use crate::api::types::{BatchPatchInfo, PatchSearchResult};
use crate::utils::date::parse_timestamp_secs;

/// Severity ordering for sorting: **most severe = lowest number**.
///
/// The single severity ladder for the whole workspace. GHSA emits
/// `moderate` where the Socket API emits `medium`; they are the same tier.
/// Live payloads are uppercase (`"CRITICAL"`), so matching is
/// case-insensitive. Anything unrecognized — including `None` — ranks below
/// `low`, so a patch with no severity information never outranks one that
/// has some.
pub fn severity_order(severity: Option<&str>) -> u8 {
    match severity.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("critical") => 0,
        Some("high") => 1,
        Some("medium") | Some("moderate") => 2,
        Some("low") => 3,
        _ => 4,
    }
}

/// Worst (lowest-numbered) severity across an iterator of severity labels.
/// An empty iterator yields the unknown rank, matching `severity_order(None)`.
pub fn max_severity_order<'a>(severities: impl Iterator<Item = &'a str>) -> u8 {
    severities
        .map(|s| severity_order(Some(s)))
        .min()
        .unwrap_or_else(|| severity_order(None))
}

/// The comparable ranking key. Sorting ascending puts the best patch first.
///
/// Kept as an explicit tuple-shaped struct rather than an ad-hoc tuple so
/// the two entry points below cannot drift in field order, and so the
/// meaning of each position is documented in one place.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RankKey<'a> {
    /// `false` sorts first, so this is negated: merged patches lead.
    not_merged: bool,
    /// 0 = critical … 4 = unknown.
    severity: u8,
    /// Newest **patch** first — the patch's own publication date, not the
    /// package's release date. Unparseable or absent timestamps collapse
    /// to 0 and therefore sort last: the right treatment for a date we
    /// cannot trust, and the reason this is epoch seconds rather than the
    /// raw string (see [`crate::utils::date`]).
    patch_published: Reverse<u64>,
    /// `false` sorts first, so paid leads. A tiebreak only: it can never
    /// override severity or recency.
    not_paid: bool,
    /// Total-order backstop. Without it, two patches identical in every
    /// ranked dimension would keep their incoming (server / HashMap) order
    /// and the CLI's output would not be reproducible.
    uuid: &'a str,
}

fn rank_search_result(p: &PatchSearchResult) -> RankKey<'_> {
    RankKey {
        not_merged: !p.merged,
        severity: max_severity_order(p.vulnerabilities.values().map(|v| v.severity.as_str())),
        patch_published: Reverse(parse_timestamp_secs(&p.published_at).unwrap_or(0)),
        not_paid: p.tier != "paid",
        uuid: &p.uuid,
    }
}

fn rank_batch_info(p: &BatchPatchInfo) -> RankKey<'_> {
    RankKey {
        not_merged: !p.merged,
        severity: severity_order(p.severity.as_deref()),
        patch_published: Reverse(
            p.published_at
                .as_deref()
                .and_then(parse_timestamp_secs)
                .unwrap_or(0),
        ),
        not_paid: p.tier != "paid",
        uuid: &p.uuid,
    }
}

/// Compare two search results best-first. Pass straight to `sort_by`.
pub fn cmp_search_results(a: &PatchSearchResult, b: &PatchSearchResult) -> Ordering {
    rank_search_result(a).cmp(&rank_search_result(b))
}

/// Compare two batch-shaped patches best-first. Pass straight to `sort_by`.
///
/// Ranks on the same key as [`cmp_search_results`], but the batch shape
/// carries a server-computed max `severity` instead of a vulnerability map,
/// and may omit `publishedAt` entirely.
pub fn cmp_batch_infos(a: &BatchPatchInfo, b: &BatchPatchInfo) -> Ordering {
    rank_batch_info(a).cmp(&rank_batch_info(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::VulnerabilityResponse;
    use std::collections::HashMap;

    fn vulns(entries: &[(&str, &str)]) -> HashMap<String, VulnerabilityResponse> {
        entries
            .iter()
            .map(|(id, sev)| {
                (
                    (*id).to_string(),
                    VulnerabilityResponse {
                        cves: Vec::new(),
                        summary: String::new(),
                        severity: (*sev).to_string(),
                        description: String::new(),
                    },
                )
            })
            .collect()
    }

    fn search(
        uuid: &str,
        tier: &str,
        published: &str,
        severity: &str,
        merged: bool,
    ) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.to_string(),
            purl: "pkg:npm/foo@1.0.0".to_string(),
            published_at: published.to_string(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: tier.to_string(),
            vulnerabilities: vulns(&[("GHSA-aaaa-aaaa-aaaa", severity)]),
            merged,
        }
    }

    fn batch(
        uuid: &str,
        tier: &str,
        published: Option<&str>,
        severity: Option<&str>,
        merged: bool,
    ) -> BatchPatchInfo {
        BatchPatchInfo {
            uuid: uuid.to_string(),
            purl: "pkg:npm/foo@1.0.0".to_string(),
            tier: tier.to_string(),
            cve_ids: Vec::new(),
            ghsa_ids: Vec::new(),
            severity: severity.map(str::to_string),
            title: String::new(),
            published_at: published.map(str::to_string),
            merged,
        }
    }

    /// Sort and return the winning uuid.
    fn best_search(mut patches: Vec<PatchSearchResult>) -> String {
        patches.sort_by(cmp_search_results);
        patches[0].uuid.clone()
    }

    fn best_batch(mut patches: Vec<BatchPatchInfo>) -> String {
        patches.sort_by(cmp_batch_infos);
        patches[0].uuid.clone()
    }

    // ── severity_order ────────────────────────────────────────────────

    #[test]
    fn severity_ladder_is_ordered_worst_first() {
        assert!(severity_order(Some("critical")) < severity_order(Some("high")));
        assert!(severity_order(Some("high")) < severity_order(Some("medium")));
        assert!(severity_order(Some("medium")) < severity_order(Some("low")));
        assert!(severity_order(Some("low")) < severity_order(None));
        assert_eq!(severity_order(Some("unknown")), severity_order(None));
    }

    #[test]
    fn severity_ladder_is_case_insensitive() {
        // Live API payloads are uppercase: `"severity": "HIGH"`.
        for s in ["CRITICAL", "Critical", "critical"] {
            assert_eq!(severity_order(Some(s)), 0, "input={s}");
        }
        assert_eq!(severity_order(Some("HIGH")), severity_order(Some("high")));
    }

    #[test]
    fn moderate_is_the_medium_tier() {
        assert_eq!(
            severity_order(Some("moderate")),
            severity_order(Some("medium"))
        );
        assert!(severity_order(Some("MODERATE")) < severity_order(Some("low")));
    }

    #[test]
    fn max_severity_order_takes_the_worst() {
        assert_eq!(
            max_severity_order(["low", "critical", "high"].into_iter()),
            0
        );
        assert_eq!(max_severity_order(["low", "medium"].into_iter()), 2);
        assert_eq!(max_severity_order([].into_iter()), severity_order(None));
    }

    // ── Rank key precedence ───────────────────────────────────────────

    #[test]
    fn merged_outranks_a_more_severe_unmerged_patch() {
        // Rule 1 beats rule 2: a merged low patch leads a critical one.
        assert_eq!(
            best_search(vec![
                search("crit", "free", "2026-01-01T00:00:00Z", "critical", false),
                search("merged", "free", "2020-01-01T00:00:00Z", "low", true),
            ]),
            "merged"
        );
    }

    #[test]
    fn severity_outranks_recency() {
        // The reported bug: the newest patch fixes a `low`, an older one
        // fixes a `critical`. Critical must win.
        assert_eq!(
            best_search(vec![
                search("newest_low", "free", "2026-08-01T00:00:00Z", "low", false),
                search(
                    "older_crit",
                    "free",
                    "2020-01-01T00:00:00Z",
                    "critical",
                    false
                ),
            ]),
            "older_crit"
        );
    }

    #[test]
    fn severity_outranks_tier() {
        // A free critical must beat a paid low. `tier` gates access, it
        // does not rank.
        assert_eq!(
            best_search(vec![
                search("paid_low", "paid", "2026-08-01T00:00:00Z", "low", false),
                search(
                    "free_crit",
                    "free",
                    "2020-01-01T00:00:00Z",
                    "critical",
                    false
                ),
            ]),
            "free_crit"
        );
    }

    #[test]
    fn recency_breaks_severity_ties() {
        // UUIDs are deliberately adversarial: `a_old` sorts first, so the
        // final uuid tiebreak would pick the WRONG patch. Only a working
        // date rung yields `z_new`. (Mutation-checked: stubbing the date
        // out fails this test.)
        assert_eq!(
            best_search(vec![
                search("a_old", "free", "2024-01-01T00:00:00Z", "high", false),
                search("z_new", "free", "2026-01-01T00:00:00Z", "high", false),
            ]),
            "z_new"
        );
    }

    #[test]
    fn recency_uses_the_patch_date_not_the_package_release_date() {
        // Both patches are for the SAME package version (one `purl`, one
        // upstream release date), yet they must still be ordered — which is
        // only possible because each carries its OWN publication date.
        //
        // Verbatim live data: `pkg:npm/axios@1.6.0` shipped to npm on
        // 2023-10-26, and has two patches published 2026-03-27 and
        // 2026-08-03. If the ranking ever keyed off a package-level date,
        // both keys would be equal here and the ordering would collapse to
        // the UUID tiebreak — which would pick `0bc312a6` (the OLDER
        // patch), not `83f5a654`.
        let older = search(
            "0bc312a6",
            "free",
            "Fri, 27 Mar 2026 19:12:42 GMT",
            "high",
            false,
        );
        let newer = search(
            "83f5a654",
            "free",
            "Mon, 03 Aug 2026 20:23:06 GMT",
            "high",
            false,
        );
        assert_eq!(older.purl, newer.purl, "same package version");
        assert!(
            older.uuid < newer.uuid,
            "uuid tiebreak would favor the older patch, so this test is \
             non-vacuous: only a real per-patch date can produce `83f5a654`"
        );
        assert_eq!(best_search(vec![older, newer]), "83f5a654");
    }

    #[test]
    fn recency_is_chronological_not_lexicographic() {
        // Regression: `publishedAt` is RFC 2822 on the wire, so a raw
        // string compare orders by weekday name. `Wed` sorts after `Fri`
        // lexicographically, so the OLDER patch used to win here.
        let older = "Wed, 01 Jan 2025 00:00:00 GMT";
        let newer = "Fri, 01 Aug 2026 00:00:00 GMT";
        assert!(older > newer, "precondition: raw strings sort backwards");
        // Adversarial UUIDs so the uuid tiebreak cannot supply the right
        // answer by accident.
        assert_eq!(
            best_search(vec![
                search("a_older", "free", older, "high", false),
                search("z_newer", "free", newer, "high", false),
            ]),
            "z_newer"
        );
    }

    #[test]
    fn unparseable_dates_sort_last_without_disturbing_severity() {
        // A garbage timestamp must not promote a patch, but it also must
        // not demote it below a less severe one.
        assert_eq!(
            best_search(vec![
                search("dated_high", "free", "2026-01-01T00:00:00Z", "high", false),
                search("undated_crit", "free", "not a date", "critical", false),
            ]),
            "undated_crit"
        );
        assert_eq!(
            best_search(vec![
                search("undated", "free", "", "high", false),
                search("dated", "free", "2020-01-01T00:00:00Z", "high", false),
            ]),
            "dated"
        );
    }

    #[test]
    fn date_outranks_the_tier_and_uuid_tiebreaks() {
        // Pins the RUNG ORDER below severity: a newer FREE patch with a
        // late-sorting uuid must still beat an older PAID one with an
        // early-sorting uuid. Both lower tiebreaks point the wrong way, so
        // this fails the moment the date rung stops working or is demoted.
        assert_eq!(
            best_search(vec![
                search("a_old_paid", "paid", "2024-01-01T00:00:00Z", "high", false),
                search("z_new_free", "free", "2026-01-01T00:00:00Z", "high", false),
            ]),
            "z_new_free"
        );
    }

    #[test]
    fn tier_breaks_ties_after_date() {
        assert_eq!(
            best_search(vec![
                search("free", "free", "2026-01-01T00:00:00Z", "high", false),
                search("paid", "paid", "2026-01-01T00:00:00Z", "high", false),
            ]),
            "paid"
        );
    }

    #[test]
    fn uuid_is_a_deterministic_final_tiebreak() {
        // Two patches identical in every ranked dimension must still land
        // in a fixed order — otherwise `scan --json` is not reproducible.
        let a = search("aaaa", "free", "2026-01-01T00:00:00Z", "high", false);
        let z = search("zzzz", "free", "2026-01-01T00:00:00Z", "high", false);
        assert_eq!(best_search(vec![z.clone(), a.clone()]), "aaaa");
        assert_eq!(best_search(vec![a, z]), "aaaa");
    }

    #[test]
    fn full_precedence_chain_in_one_sort() {
        let mut patches = [
            search("d_low_new", "paid", "2026-08-01T00:00:00Z", "low", false),
            search(
                "b_crit_old",
                "free",
                "2020-01-01T00:00:00Z",
                "critical",
                false,
            ),
            search("a_merged", "free", "2019-01-01T00:00:00Z", "low", true),
            search("c_high_new", "free", "2026-01-01T00:00:00Z", "high", false),
        ];
        patches.sort_by(cmp_search_results);
        let order: Vec<&str> = patches.iter().map(|p| p.uuid.as_str()).collect();
        assert_eq!(order, ["a_merged", "b_crit_old", "c_high_new", "d_low_new"]);
    }

    #[test]
    fn worst_vulnerability_in_the_map_drives_severity() {
        let mixed = PatchSearchResult {
            vulnerabilities: vulns(&[("GHSA-a", "low"), ("GHSA-b", "critical")]),
            ..search("mixed", "free", "2020-01-01T00:00:00Z", "low", false)
        };
        let high = search("high_only", "free", "2026-01-01T00:00:00Z", "high", false);
        // `mixed` is older but carries a critical — it must win.
        assert_eq!(best_search(vec![high, mixed]), "mixed");
    }

    #[test]
    fn patch_with_no_vulnerabilities_ranks_below_one_with_a_low() {
        let none = PatchSearchResult {
            vulnerabilities: HashMap::new(),
            ..search("no_vulns", "free", "2026-08-01T00:00:00Z", "low", false)
        };
        let low = search("has_low", "free", "2020-01-01T00:00:00Z", "low", false);
        assert_eq!(best_search(vec![none, low]), "has_low");
    }

    // ── Batch shape parity ────────────────────────────────────────────

    #[test]
    fn batch_ranking_matches_search_ranking() {
        assert_eq!(
            best_batch(vec![
                batch(
                    "newest_low",
                    "free",
                    Some("2026-08-01T00:00:00Z"),
                    Some("low"),
                    false
                ),
                batch(
                    "older_crit",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("critical"),
                    false
                ),
            ]),
            "older_crit"
        );
        assert_eq!(
            best_batch(vec![
                batch(
                    "crit",
                    "free",
                    Some("2026-01-01T00:00:00Z"),
                    Some("critical"),
                    false
                ),
                batch(
                    "merged",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("low"),
                    true
                ),
            ]),
            "merged"
        );
    }

    #[test]
    fn batch_recency_uses_the_patch_date_not_the_package_release_date() {
        // Batch-shape twin of
        // `recency_uses_the_patch_date_not_the_package_release_date`: one
        // package version, two patches, ordered by their own publish
        // dates. `u_aaa` sorts first by UUID, so only a real per-patch
        // date can produce `u_zzz`.
        assert_eq!(
            best_batch(vec![
                batch(
                    "u_aaa",
                    "free",
                    Some("Fri, 27 Mar 2026 19:12:42 GMT"),
                    Some("HIGH"),
                    false
                ),
                batch(
                    "u_zzz",
                    "free",
                    Some("Mon, 03 Aug 2026 20:23:06 GMT"),
                    Some("HIGH"),
                    false
                ),
            ]),
            "u_zzz"
        );
    }

    #[test]
    fn same_patch_dates_across_different_packages_do_not_interact() {
        // Ranking is computed per patch and is blind to the package: two
        // patches sharing a publish date rank identically regardless of
        // which purl they belong to. Guards against anyone "optimizing"
        // the key to be derived from package-level state.
        let mut a = search("u1", "free", "2026-01-01T00:00:00Z", "high", false);
        let mut b = search("u2", "free", "2026-01-01T00:00:00Z", "high", false);
        let same_purl = cmp_search_results(&a, &b);
        a.purl = "pkg:npm/alpha@1.0.0".to_string();
        b.purl = "pkg:npm/omega@9.9.9".to_string();
        assert_eq!(
            same_purl,
            cmp_search_results(&a, &b),
            "changing the package must not change the relative rank"
        );
    }

    #[test]
    fn batch_without_published_at_still_ranks_by_severity() {
        // The batch endpoint historically omits `publishedAt`; losing the
        // recency tiebreak must not cost us the severity ordering.
        assert_eq!(
            best_batch(vec![
                batch("low", "free", None, Some("low"), false),
                batch("crit", "free", None, Some("critical"), false),
            ]),
            "crit"
        );
    }

    #[test]
    fn batch_missing_severity_ranks_last() {
        assert_eq!(
            best_batch(vec![
                batch("unknown", "free", Some("2026-08-01T00:00:00Z"), None, false),
                batch(
                    "low",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("low"),
                    false
                ),
            ]),
            "low"
        );
    }

    #[test]
    fn batch_ordering_is_total_and_deterministic() {
        let all = || {
            vec![
                batch("u3", "free", None, None, false),
                batch(
                    "u1",
                    "paid",
                    Some("2026-01-01T00:00:00Z"),
                    Some("high"),
                    false,
                ),
                batch(
                    "u2",
                    "free",
                    Some("2026-01-01T00:00:00Z"),
                    Some("high"),
                    false,
                ),
                batch(
                    "u0",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("critical"),
                    true,
                ),
            ]
        };
        let mut first = all();
        first.sort_by(cmp_batch_infos);
        let mut second = all();
        second.reverse();
        second.sort_by(cmp_batch_infos);
        let ids =
            |v: &[BatchPatchInfo]| -> Vec<String> { v.iter().map(|p| p.uuid.clone()).collect() };
        assert_eq!(ids(&first), ids(&second));
        assert_eq!(ids(&first), ["u0", "u1", "u2", "u3"]);
    }
}
