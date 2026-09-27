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
//! 1. **Merged patches** — a patch that folds several advisories into one
//!    blob (see [`merged_coverage`]), newest first. A merged patch is the
//!    cumulative fix for its package, so the most recent one wins outright.
//! 2. **Everything else** — by severity (critical > high > medium/moderate >
//!    low > unknown, the worst severity across everything the patch fixes),
//!    then newest first.
//! 3. Paid tier, then UUID — pure tiebreaks, present only so the order is
//!    total and therefore reproducible run to run.
//!
//! "Newest" is the date *the patch* was published, never the date the
//! upstream package version was released (see
//! [`crate::api::types::PatchResponse::published_at`]).
//!
//! `tier` is an access filter, not a ranking signal: callers drop the paid
//! patches a free user cannot download before ranking.

use std::cmp::{Ordering, Reverse};

use crate::api::date::parse_timestamp_secs;
use crate::api::types::{BatchPatchInfo, PatchSearchResult};

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

/// How many distinct advisories a patch remediates — the **inferred merge
/// state**, derived entirely from data the API already returns.
///
/// There is no `merged` flag on the wire, and none is needed: a merged
/// patch is by definition one that folds several fixes into a single blob,
/// so it names several advisories. `1` is an ordinary single-advisory
/// patch; `>= 2` is a merged one; `0` means the patch names no advisory at
/// all and cannot be preferred on this axis.
///
/// Counting **advisories** (GHSA ids) rather than CVE ids is deliberate:
/// one advisory routinely carries several CVE aliases, and counting those
/// would inflate a single-fix patch into a phantom merged one.
///
/// Production published its first merged patch on 2026-09-04
/// (activestorage 6.0.3, three advisories).
pub fn merged_coverage(advisory_count: usize) -> usize {
    advisory_count
}

/// The comparable ranking key. Sorting ascending puts the best patch first.
///
/// Kept as an explicit tuple-shaped struct rather than an ad-hoc tuple so
/// the two entry points below cannot drift in field order, and so the
/// meaning of each position is documented in one place.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RankKey<'a> {
    /// `false` sorts first: merged patches lead.
    not_merged: bool,
    /// 0 = critical … 4 = unknown. Always 0 for a merged patch, so merged
    /// patches rank by recency alone.
    severity: u8,
    /// Newest patch first. Unparseable or absent timestamps collapse to 0
    /// and sort last (see [`crate::api::date`]).
    patch_published: Reverse<u64>,
    /// `false` sorts first, so paid leads on an otherwise exact tie.
    not_paid: bool,
    /// Total-order backstop, so the output is reproducible.
    uuid: &'a str,
}

fn rank_key<'a>(
    severity: u8,
    advisories: usize,
    published: u64,
    tier: &str,
    uuid: &'a str,
) -> RankKey<'a> {
    let merged = merged_coverage(advisories) >= 2;
    RankKey {
        not_merged: !merged,
        severity: if merged { 0 } else { severity },
        patch_published: Reverse(published),
        not_paid: tier != "paid",
        uuid,
    }
}

fn rank_search_result(p: &PatchSearchResult) -> RankKey<'_> {
    // The map is keyed by advisory id, so its length is the advisory count
    // (no CVE-alias inflation).
    rank_key(
        max_severity_order(p.vulnerabilities.values().map(|v| v.severity.as_str())),
        p.vulnerabilities.len(),
        parse_timestamp_secs(&p.published_at).unwrap_or(0),
        &p.tier,
        &p.uuid,
    )
}

fn rank_batch_info(p: &BatchPatchInfo) -> RankKey<'_> {
    // `ghsa_ids` mirrors the `vulnerabilities` map keys. Fall back to
    // `cve_ids` only when the server named no GHSA at all, otherwise one
    // advisory with two CVE aliases would read as a merged patch.
    let advisories = if p.ghsa_ids.is_empty() {
        p.cve_ids.len()
    } else {
        p.ghsa_ids.len()
    };
    rank_key(
        severity_order(p.severity.as_deref()),
        advisories,
        p.published_at
            .as_deref()
            .and_then(parse_timestamp_secs)
            .unwrap_or(0),
        &p.tier,
        &p.uuid,
    )
}

/// Compare two search results best-first. Pass straight to `sort_by`.
pub fn cmp_search_results(a: &PatchSearchResult, b: &PatchSearchResult) -> Ordering {
    rank_search_result(a).cmp(&rank_search_result(b))
}

/// Compare two batch-shaped patches best-first. Pass straight to `sort_by`.
///
/// Same key as [`cmp_search_results`], but the batch shape carries a
/// server-computed max `severity` instead of a vulnerability map, and may
/// omit `publishedAt` entirely.
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

    /// A single-advisory patch — the only shape production publishes today.
    fn search(uuid: &str, tier: &str, published: &str, severity: &str) -> PatchSearchResult {
        search_multi(uuid, tier, published, &[severity])
    }

    /// A patch fixing one advisory per entry in `severities`. Two or more
    /// makes it a *merged* patch under [`merged_coverage`].
    fn search_multi(
        uuid: &str,
        tier: &str,
        published: &str,
        severities: &[&str],
    ) -> PatchSearchResult {
        let entries: Vec<(String, &str)> = severities
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("GHSA-{uuid}-{i}"), *s))
            .collect();
        let refs: Vec<(&str, &str)> = entries.iter().map(|(k, v)| (k.as_str(), *v)).collect();
        PatchSearchResult {
            uuid: uuid.to_string(),
            purl: "pkg:npm/foo@1.0.0".to_string(),
            published_at: published.to_string(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: tier.to_string(),
            vulnerabilities: vulns(&refs),
        }
    }

    fn batch(
        uuid: &str,
        tier: &str,
        published: Option<&str>,
        severity: Option<&str>,
    ) -> BatchPatchInfo {
        batch_multi(uuid, tier, published, severity, 1)
    }

    /// Batch-shaped patch naming `advisories` GHSA ids — the batch mirror
    /// of `search_multi`.
    fn batch_multi(
        uuid: &str,
        tier: &str,
        published: Option<&str>,
        severity: Option<&str>,
        advisories: usize,
    ) -> BatchPatchInfo {
        BatchPatchInfo {
            uuid: uuid.to_string(),
            purl: "pkg:npm/foo@1.0.0".to_string(),
            tier: tier.to_string(),
            cve_ids: Vec::new(),
            ghsa_ids: (0..advisories)
                .map(|i| format!("GHSA-{uuid}-{i}"))
                .collect(),
            severity: severity.map(str::to_string),
            title: String::new(),
            published_at: published.map(str::to_string),
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
    fn merged_patch_wins_when_severities_tie() {
        // The general preference. `z_merged` fixes two HIGH advisories,
        // `a_single` fixes one; severities tie, so breadth decides. The
        // uuid tiebreak points at `a_single`, and `a_single` is also the
        // more recent patch — so only the coverage rung can produce this.
        assert_eq!(
            best_search(vec![
                search("a_single", "free", "2026-08-01T00:00:00Z", "high"),
                search_multi(
                    "z_merged",
                    "free",
                    "2020-01-01T00:00:00Z",
                    &["high", "high"]
                ),
            ]),
            "z_merged"
        );
    }

    #[test]
    fn a_merged_patch_beats_a_higher_severity_single_one() {
        // A merged patch is the package's cumulative fix, so it wins even
        // against a single-advisory CRITICAL that is its only rival.
        assert_eq!(
            best_search(vec![
                search("a_critical", "free", "2026-08-01T00:00:00Z", "critical"),
                search_multi(
                    "z_merged",
                    "free",
                    "2020-01-01T00:00:00Z",
                    &["high", "high"]
                ),
            ]),
            "z_merged"
        );
    }

    #[test]
    fn the_newest_merged_patch_wins_whatever_its_severity() {
        assert_eq!(
            best_search(vec![
                search_multi(
                    "a_old_critical",
                    "free",
                    "2020-01-01T00:00:00Z",
                    &["critical", "high"]
                ),
                search_multi(
                    "z_new_low",
                    "free",
                    "2026-08-01T00:00:00Z",
                    &["low", "low"]
                ),
            ]),
            "z_new_low"
        );
    }

    #[test]
    fn merged_patch_wins_when_it_already_covers_the_worst_advisory() {
        // Third row of the table in the module docs: the merged patch's max
        // severity already matches the rival's, so there is no
        // higher-severity fix being shadowed and breadth decides again.
        assert_eq!(
            best_search(vec![
                search(
                    "a_critical_only",
                    "free",
                    "2026-08-01T00:00:00Z",
                    "critical"
                ),
                search_multi(
                    "z_merged_crit",
                    "free",
                    "2020-01-01T00:00:00Z",
                    &["critical", "low"],
                ),
            ]),
            "z_merged_crit"
        );
    }

    #[test]
    fn coverage_counts_advisories_not_cve_aliases() {
        // One advisory carrying several CVE aliases is NOT a merged patch.
        // The search shape counts `vulnerabilities` map keys, so aliases in
        // `cves` cannot inflate it; pin that a single-advisory patch stays
        // at coverage 1 no matter how many CVEs hang off it.
        let mut aliased = search("a_aliased", "free", "2026-08-01T00:00:00Z", "high");
        aliased
            .vulnerabilities
            .values_mut()
            .next()
            .unwrap()
            .cves
            .extend(["CVE-1".into(), "CVE-2".into(), "CVE-3".into()]);
        assert_eq!(aliased.vulnerabilities.len(), 1, "still one advisory");
        // A genuine 2-advisory patch must still outrank it despite being
        // older and later-sorting by uuid.
        assert_eq!(
            best_search(vec![
                aliased,
                search_multi(
                    "z_merged",
                    "free",
                    "2020-01-01T00:00:00Z",
                    &["high", "high"]
                ),
            ]),
            "z_merged"
        );
    }

    #[test]
    fn merged_coverage_is_the_advisory_count() {
        assert_eq!(merged_coverage(0), 0);
        assert_eq!(merged_coverage(1), 1, "ordinary single-advisory patch");
        assert!(merged_coverage(2) > merged_coverage(1), "merged leads");
        assert!(merged_coverage(5) > merged_coverage(2));
    }

    #[test]
    fn a_patch_naming_no_advisory_is_not_merged() {
        // Coverage 0 and 1 are both unmerged, so with severities tied the
        // newer patch wins.
        let none = PatchSearchResult {
            vulnerabilities: HashMap::new(),
            ..search("z_none", "free", "2026-08-01T00:00:00Z", "high")
        };
        let one = PatchSearchResult {
            vulnerabilities: vulns(&[("GHSA-x", "not-a-severity")]),
            ..search("a_one", "free", "2020-01-01T00:00:00Z", "high")
        };
        assert_eq!(best_search(vec![none, one]), "z_none");
    }

    #[test]
    fn severity_outranks_recency() {
        // The reported bug: the newest patch fixes a `low`, an older one
        // fixes a `critical`. Critical must win.
        assert_eq!(
            best_search(vec![
                search("newest_low", "free", "2026-08-01T00:00:00Z", "low"),
                search("older_crit", "free", "2020-01-01T00:00:00Z", "critical"),
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
                search("paid_low", "paid", "2026-08-01T00:00:00Z", "low"),
                search("free_crit", "free", "2020-01-01T00:00:00Z", "critical"),
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
                search("a_old", "free", "2024-01-01T00:00:00Z", "high"),
                search("z_new", "free", "2026-01-01T00:00:00Z", "high"),
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
        let older = search("0bc312a6", "free", "Fri, 27 Mar 2026 19:12:42 GMT", "high");
        let newer = search("83f5a654", "free", "Mon, 03 Aug 2026 20:23:06 GMT", "high");
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
                search("a_older", "free", older, "high"),
                search("z_newer", "free", newer, "high"),
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
                search("dated_high", "free", "2026-01-01T00:00:00Z", "high"),
                search("undated_crit", "free", "not a date", "critical"),
            ]),
            "undated_crit"
        );
        assert_eq!(
            best_search(vec![
                search("undated", "free", "", "high"),
                search("dated", "free", "2020-01-01T00:00:00Z", "high"),
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
                search("a_old_paid", "paid", "2024-01-01T00:00:00Z", "high"),
                search("z_new_free", "free", "2026-01-01T00:00:00Z", "high"),
            ]),
            "z_new_free"
        );
    }

    #[test]
    fn tier_breaks_ties_after_date() {
        assert_eq!(
            best_search(vec![
                search("free", "free", "2026-01-01T00:00:00Z", "high"),
                search("paid", "paid", "2026-01-01T00:00:00Z", "high"),
            ]),
            "paid"
        );
    }

    #[test]
    fn uuid_is_a_deterministic_final_tiebreak() {
        // Two patches identical in every ranked dimension must still land
        // in a fixed order — otherwise `scan --json` is not reproducible.
        let a = search("aaaa", "free", "2026-01-01T00:00:00Z", "high");
        let z = search("zzzz", "free", "2026-01-01T00:00:00Z", "high");
        assert_eq!(best_search(vec![z.clone(), a.clone()]), "aaaa");
        assert_eq!(best_search(vec![a, z]), "aaaa");
    }

    #[test]
    fn full_precedence_chain_in_one_sort() {
        // Exercises all four rungs at once. UUIDs are lettered in reverse
        // of the expected order so the uuid tiebreak cannot reproduce the
        // answer on its own.
        let mut patches = [
            // rung 3: loses to `d` on recency (same severity, same coverage)
            search("e_high_old", "free", "2019-01-01T00:00:00Z", "high"),
            // rung 1: worst severity of the lot
            search("d_high_new", "free", "2026-01-01T00:00:00Z", "high"),
            // rung 1: critical, but single-advisory
            search("c_crit_single", "paid", "2026-08-01T00:00:00Z", "critical"),
            // rung 2: critical AND merged -> the winner
            search_multi(
                "b_crit_merged",
                "free",
                "2020-01-01T00:00:00Z",
                &["critical", "low"],
            ),
            // rung 1: lowest severity, so last despite being newest
            search("a_low_newest", "paid", "2026-12-01T00:00:00Z", "low"),
        ];
        patches.sort_by(cmp_search_results);
        let order: Vec<&str> = patches.iter().map(|p| p.uuid.as_str()).collect();
        assert_eq!(
            order,
            [
                "b_crit_merged",
                "c_crit_single",
                "d_high_new",
                "e_high_old",
                "a_low_newest"
            ]
        );
    }

    #[test]
    fn worst_vulnerability_in_the_map_drives_severity() {
        let mixed = PatchSearchResult {
            vulnerabilities: vulns(&[("GHSA-a", "low"), ("GHSA-b", "critical")]),
            ..search("mixed", "free", "2020-01-01T00:00:00Z", "low")
        };
        let high = search("high_only", "free", "2026-01-01T00:00:00Z", "high");
        // `mixed` is older but carries a critical — it must win.
        assert_eq!(best_search(vec![high, mixed]), "mixed");
    }

    #[test]
    fn patch_with_no_vulnerabilities_ranks_below_one_with_a_low() {
        let none = PatchSearchResult {
            vulnerabilities: HashMap::new(),
            ..search("no_vulns", "free", "2026-08-01T00:00:00Z", "low")
        };
        let low = search("has_low", "free", "2020-01-01T00:00:00Z", "low");
        assert_eq!(best_search(vec![none, low]), "has_low");
    }

    // ── Batch shape parity ────────────────────────────────────────────

    #[test]
    fn batch_ranking_matches_search_ranking() {
        // Severity outranks recency, same as the search shape.
        assert_eq!(
            best_batch(vec![
                batch(
                    "newest_low",
                    "free",
                    Some("2026-08-01T00:00:00Z"),
                    Some("low")
                ),
                batch(
                    "older_crit",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("critical")
                ),
            ]),
            "older_crit"
        );
        // Coverage decides once severities tie — the batch shape infers it
        // from `ghsaIds` rather than a vulnerabilities map.
        assert_eq!(
            best_batch(vec![
                batch(
                    "a_single",
                    "free",
                    Some("2026-08-01T00:00:00Z"),
                    Some("high")
                ),
                batch_multi(
                    "z_merged",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("high"),
                    2
                ),
            ]),
            "z_merged"
        );
        // ...and beats a higher-severity single-advisory rival too.
        assert_eq!(
            best_batch(vec![
                batch_multi(
                    "a_merged",
                    "free",
                    Some("2026-08-01T00:00:00Z"),
                    Some("high"),
                    2
                ),
                batch(
                    "z_crit",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("critical")
                ),
            ]),
            "a_merged"
        );
    }

    #[test]
    fn batch_coverage_counts_ghsa_ids_not_cve_aliases() {
        // A single advisory with three CVE aliases must stay coverage 1.
        // `ghsa_ids` is non-empty, so `cve_ids` is ignored entirely.
        let mut aliased = batch(
            "a_aliased",
            "free",
            Some("2026-08-01T00:00:00Z"),
            Some("high"),
        );
        aliased.cve_ids = vec!["CVE-1".into(), "CVE-2".into(), "CVE-3".into()];
        assert_eq!(aliased.ghsa_ids.len(), 1, "still one advisory");
        assert_eq!(
            best_batch(vec![
                aliased,
                batch_multi(
                    "z_merged",
                    "free",
                    Some("2020-01-01T00:00:00Z"),
                    Some("high"),
                    2
                ),
            ]),
            "z_merged"
        );
    }

    #[test]
    fn batch_falls_back_to_cve_ids_when_no_ghsa_is_named() {
        // Some patches may name only CVEs. With `ghsa_ids` empty the
        // advisory count comes from `cve_ids` instead, so a
        // two-CVE-no-GHSA patch still reads as merged.
        let mut single = batch(
            "a_single",
            "free",
            Some("2026-08-01T00:00:00Z"),
            Some("high"),
        );
        single.ghsa_ids.clear();
        single.cve_ids = vec!["CVE-1".into()];
        let mut merged = batch(
            "z_merged",
            "free",
            Some("2020-01-01T00:00:00Z"),
            Some("high"),
        );
        merged.ghsa_ids.clear();
        merged.cve_ids = vec!["CVE-2".into(), "CVE-3".into()];
        assert_eq!(best_batch(vec![single, merged]), "z_merged");
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
                    Some("HIGH")
                ),
                batch(
                    "u_zzz",
                    "free",
                    Some("Mon, 03 Aug 2026 20:23:06 GMT"),
                    Some("HIGH")
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
        let mut a = search("u1", "free", "2026-01-01T00:00:00Z", "high");
        let mut b = search("u2", "free", "2026-01-01T00:00:00Z", "high");
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
                batch("low", "free", None, Some("low")),
                batch("crit", "free", None, Some("critical")),
            ]),
            "crit"
        );
    }

    #[test]
    fn batch_missing_severity_ranks_last() {
        assert_eq!(
            best_batch(vec![
                batch("unknown", "free", Some("2026-08-01T00:00:00Z"), None),
                batch("low", "free", Some("2020-01-01T00:00:00Z"), Some("low")),
            ]),
            "low"
        );
    }

    #[test]
    fn batch_ordering_is_total_and_deterministic() {
        let all = || {
            vec![
                batch("u3", "free", None, None),
                batch("u1", "paid", Some("2026-01-01T00:00:00Z"), Some("high")),
                batch("u2", "free", Some("2026-01-01T00:00:00Z"), Some("high")),
                batch("u0", "free", Some("2020-01-01T00:00:00Z"), Some("critical")),
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
