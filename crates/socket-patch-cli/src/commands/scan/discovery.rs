//! Discovery-side helpers for `scan`: lockfile / vendored-ledger crawl
//! supplements, update detection against the existing manifest, vendor
//! baseline pre-verification, and the table's vuln-ID / severity helpers.

use socket_patch_core::api::ranking::cmp_batch_infos;
use socket_patch_core::api::types::{BatchPackagePatches, BatchPatchInfo, PatchSearchResult};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use std::collections::HashSet;

use crate::args::GlobalArgs;

/// Surfaced in `scan --json` output. Tells a bot which PURLs in the discovery
/// would replace an existing manifest entry with a newer UUID. Stable schema —
/// see CLI_CONTRACT.md (`scan` JSON output / `updates` field).
#[derive(Debug, PartialEq, Eq, Clone)]
pub(super) struct UpdateInfo {
    pub(super) purl: String,
    pub(super) old_uuid: String,
    pub(super) new_uuid: String,
}

/// Lockfile-only packages: dependencies the project's lockfile resolves
/// that have no crawled (installed) counterpart.
#[derive(Default)]
pub(super) struct LockfileSupplement {
    pub(super) packages: Vec<socket_patch_core::crawlers::types::CrawledPackage>,
    /// Literal crawler-form purls, for fast membership tests.
    pub(super) purls: HashSet<String>,
}

/// Inventory the project's lockfile(s) and fabricate crawl entries for
/// dependencies that are not installed. The fabricated `path` is the
/// WOULD-BE install dir — every consumer degrades safely on a nonexistent
/// path (hash verify → NotFound, apply → partitioned skip, vendor →
/// auto-fetch). Global scans target the machine's global tree, not this
/// project's lockfile, so they get no supplement.
pub(super) async fn lockfile_supplement(
    common: &GlobalArgs,
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
) -> LockfileSupplement {
    use socket_patch_core::vendor::lock_inventory;

    let mut out = LockfileSupplement::default();
    if common.global || common.global_prefix.is_some() {
        return out;
    }
    let entries = lock_inventory::inventory_project(&common.cwd).await;
    if entries.is_empty() {
        return out;
    }
    let crawled_purls: HashSet<&str> = crawled.iter().map(|p| p.purl.as_str()).collect();
    for entry in entries {
        if crawled_purls.contains(entry.purl.as_str()) {
            continue;
        }
        let Some(pkg) = crawled_from_purl(&entry.purl, &common.cwd) else {
            continue;
        };
        out.purls.insert(entry.purl.clone());
        out.packages.push(pkg);
    }
    out
}

/// A displayable crawl entry fabricated from a purl (decoded form). The
/// path is a placeholder consumers degrade safely on.
fn crawled_from_purl(
    purl: &str,
    cwd: &std::path::Path,
) -> Option<socket_patch_core::crawlers::types::CrawledPackage> {
    let decoded = normalize_purl(strip_purl_qualifiers(purl)).into_owned();
    let rest = decoded.strip_prefix("pkg:")?;
    let (_eco, rest) = rest.split_once('/')?;
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name_part, version) = (&rest[..at], &rest[at + 1..]);
    let (namespace, name) = match name_part.rsplit_once('/') {
        Some((ns, n)) => (Some(ns.to_string()), n.to_string()),
        None => (None, name_part.to_string()),
    };
    Some(socket_patch_core::crawlers::types::CrawledPackage {
        name,
        version: version.to_string(),
        namespace,
        purl: decoded.clone(),
        path: cwd.join("node_modules").join(name_part),
    })
}

/// Vendored-ledger packages with no crawled counterpart: on a fresh clone
/// the committed artifact IS the dependency, so these stay discoverable
/// (updates[] detection, the table, and `scan --vendor` re-vendor/in-sync
/// runs all keep working before any install). They are NOT "lockfile-only"
/// — nothing needs installing; the artifact satisfies the lock.
pub(super) async fn vendored_ledger_supplement(
    common: &GlobalArgs,
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
) -> Vec<socket_patch_core::crawlers::types::CrawledPackage> {
    if common.global || common.global_prefix.is_some() {
        return Vec::new();
    }
    let Ok(state) = socket_patch_core::vendor::load_state(&common.cwd).await else {
        return Vec::new();
    };
    let crawled_norm: HashSet<String> = crawled
        .iter()
        .map(|p| normalize_purl(&p.purl).into_owned())
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for entry in state.entries.values() {
        let base = strip_purl_qualifiers(&entry.base_purl);
        let norm = normalize_purl(base).into_owned();
        if crawled_norm.contains(&norm) || !seen.insert(norm) {
            continue;
        }
        if let Some(pkg) = crawled_from_purl(base, &common.cwd) {
            out.push(pkg);
        }
    }
    out.sort_by(|a, b| a.purl.cmp(&b.purl));
    out
}

/// Vendor-mode pre-prompt check: uuids of selected patches whose installed
/// files match NEITHER beforeHash nor afterHash — the patch was built
/// against different bytes than the installed artifact. Vendoring still
/// succeeds for these (the vendor stage force-applies the verified patched
/// content; see `force_apply_staged`), but the user should learn it BEFORE
/// the confirm prompt, not from a post-hoc warning event.
///
/// Best-effort and read-only: a detail-fetch failure or an unresolvable
/// installed path just skips the annotation — it never blocks the flow and
/// writes nothing (unlike `download_patch_records`, which stages blobs).
pub(super) async fn preverify_vendor_baselines(
    api_client: &socket_patch_core::api::client::ApiClient,
    org_slug: Option<&str>,
    selected: &[PatchSearchResult],
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
    lockfile_only: &HashSet<String>,
) -> HashSet<String> {
    use socket_patch_core::manifest::schema::PatchFileInfo;
    use socket_patch_core::patch::apply::{verify_file_patch, VerifyStatus};
    use socket_patch_core::utils::purl::purl_eq;

    let mut mismatched: HashSet<String> = HashSet::new();
    for patch in selected {
        // API purls come percent-encoded, crawler purls literal — purl_eq
        // bridges the two spellings.
        let base = strip_purl_qualifiers(&patch.purl);
        // Lockfile-only packages have no installed bytes to compare — the
        // vendor engine fetches them pristine (nothing to annotate).
        if lockfile_only.contains(normalize_purl(base).as_ref()) {
            continue;
        }
        let Some(pkg) = crawled.iter().find(|c| purl_eq(&c.purl, base)) else {
            continue;
        };
        let Ok(Some(detail)) = api_client.fetch_patch(org_slug, &patch.uuid).await else {
            continue;
        };
        for (file, info) in &detail.files {
            let info = PatchFileInfo {
                before_hash: info.before_hash.clone().unwrap_or_default(),
                after_hash: info.after_hash.clone().unwrap_or_default(),
            };
            if info.before_hash.is_empty() {
                continue; // a new file has no baseline to compare
            }
            if verify_file_patch(&pkg.path, file, &info).await.status == VerifyStatus::HashMismatch
            {
                mismatched.insert(patch.uuid.clone());
                break;
            }
        }
    }
    mismatched
}

/// Fold the hosted redirect ledger's patch records into the manifest view
/// update detection consults. Hosted mode persists its purl→uuid records ONLY
/// in `.socket/vendor/redirect-state.json` — it never writes
/// `.socket/manifest.json` — so without this fold a pure hosted project's
/// `updates[]` (the documented CI signal, see CLI_CONTRACT.md) is structurally
/// empty and a superseding patch is never reported. An existing manifest entry
/// wins a collision (that PURL is manifest-owned), matching VEX's
/// `augment_with_redirect`. Pure / no I/O so it's unit-testable.
pub(super) fn merge_redirect_records_for_updates(
    manifest: Option<PatchManifest>,
    redirect: Option<&socket_patch_core::patch::redirect::RedirectState>,
) -> Option<PatchManifest> {
    let records = redirect.map(|s| &s.records).filter(|r| !r.is_empty());
    let Some(records) = records else {
        return manifest;
    };
    let mut merged = manifest.unwrap_or_default();
    for (purl, record) in records {
        merged
            .patches
            .entry(purl.clone())
            .or_insert_with(|| record.clone());
    }
    Some(merged)
}

/// Cross-reference an existing manifest against discovery results to find
/// PURLs whose newest available patch UUID differs from the locally-recorded
/// one. Used by both the discovery JSON path and the table-print path.
/// Pure / no I/O so it's unit-testable.
pub(super) fn detect_updates(
    existing_manifest: Option<&PatchManifest>,
    packages: &[BatchPackagePatches],
) -> Vec<UpdateInfo> {
    let Some(manifest) = existing_manifest else {
        return Vec::new();
    };
    let mut updates = Vec::new();
    for pkg in packages {
        // The candidate is the top-ranked patch — the one the apply path
        // resolves to. Both sides rank with `api::ranking`, so the
        // `[UPDATE]` marker and the JSON `updates` array track what
        // `--apply` installs.
        //
        // Caveat, and the one place the two can still disagree: we rank
        // BATCH-shaped patches here, while apply ranks the richer
        // by-package shape. The batch response currently omits
        // `publishedAt`, so when a package's top candidates tie on merge
        // status AND severity, this falls through to the UUID tiebreak
        // while apply correctly uses the date. `BatchPatchInfo` already
        // deserializes `publishedAt` when present, so the divergence
        // disappears the moment the endpoint emits it — no client change.
        // (Verified live on pkg:npm/axios@1.6.0, two free HIGH patches.)
        //
        // `ApiClient` already returns each package's patches best-first, so
        // `min_by` here is a cheap guard rather than a correction — but it
        // is load-bearing for callers that build a `BatchPackagePatches`
        // themselves rather than getting one from the client.
        let Some(candidate) = pkg.patches.iter().min_by(|a, b| cmp_batch_infos(a, b)) else {
            continue;
        };
        // Manifest keys are written verbatim from the *patch* purl, which
        // the API serves percent-encoded (`pkg:npm/%40scope/...`) and, for
        // artifact-pinned ecosystems, qualified (`?artifact_id=...`); the
        // batch *package* purl is the crawler's literal spelling. Bridge
        // both divergences like the lockfile-only partition does: exact hit
        // first, then a normalized qualifier-stripped comparison.
        //
        // Qualifier TWINS (one package recorded under two artifact-pinned
        // keys, e.g. a pypi wheel + sdist pair) both match the stripped
        // comparison. `manifest.patches` is a HashMap, so a bare `find`
        // would pick a per-process-random twin; instead: any stale twin
        // means an update is available, so prefer the first twin (in
        // sorted-key order, for run-to-run stability) whose uuid differs
        // from the candidate, and fall back to the first twin when all
        // agree.
        let existing = manifest.patches.get(&pkg.purl).or_else(|| {
            let want = normalize_purl(strip_purl_qualifiers(&pkg.purl));
            let mut twins: Vec<(&String, &socket_patch_core::manifest::schema::PatchRecord)> =
                manifest
                    .patches
                    .iter()
                    .filter(|(k, _)| normalize_purl(strip_purl_qualifiers(k)) == want)
                    .collect();
            twins.sort_by(|a, b| a.0.cmp(b.0));
            twins
                .iter()
                .find(|(_, v)| v.uuid != candidate.uuid)
                .or_else(|| twins.first())
                .map(|(_, v)| *v)
        });
        let Some(existing) = existing else {
            continue;
        };
        // (a) Same patch already recorded — never an update.
        if candidate.uuid == existing.uuid {
            continue;
        }
        // (b) The candidate out*ranks* the recorded patch, but "outranks"
        // includes the pure tier/uuid tiebreaks and — because the batch
        // endpoint routinely omits `publishedAt` — an epoch-0 date that is
        // NOT real evidence of recency. When the recorded patch is still
        // among the offered patches, `cmp_batch_infos` can crown an
        // equal-or-older sibling as the "top" candidate purely on the uuid
        // tiebreak, which used to nag a vendored project forever with a patch
        // no newer than the one already committed. Only surface an update
        // when the candidate GENUINELY supersedes the applied patch on a
        // meaningful axis (severity, merge coverage, or a real,
        // strictly-greater publish date).
        //
        // If the recorded patch is no longer offered at all, we cannot
        // compare ages; a different, currently-available candidate is the
        // best signal we have, so flag it (this is also the only behavior a
        // manifest-only, no-batch record can produce).
        if let Some(applied) = pkg.patches.iter().find(|p| p.uuid == existing.uuid) {
            if !candidate_supersedes(candidate, applied) {
                continue;
            }
        }
        updates.push(UpdateInfo {
            purl: pkg.purl.clone(),
            old_uuid: existing.uuid.clone(),
            new_uuid: candidate.uuid.clone(),
        });
    }
    updates
}

/// Whether `candidate` genuinely supersedes the already-applied `applied`
/// patch — strictly better on a MEANINGFUL ranking axis (severity, merge
/// coverage, or a real, strictly-greater publish date), never on the pure
/// tier/uuid tiebreaks or an absent-date (epoch-0) artifact.
///
/// This is the guard that kills the false `[UPDATE]` nag. Batch responses
/// omit `publishedAt`, so [`cmp_batch_infos`] falls through to the uuid
/// tiebreak and can rank an equal-or-older sibling above the applied patch;
/// flagging that as an update perpetually nags a vendored project. Both
/// patches are batch-shaped and drawn from the SAME package response, so this
/// compares like with like, mirroring `api::ranking::rank_batch_info`.
fn candidate_supersedes(candidate: &BatchPatchInfo, applied: &BatchPatchInfo) -> bool {
    use socket_patch_core::api::date::parse_timestamp_secs;
    use socket_patch_core::api::ranking::{merged_coverage, severity_order};

    // Advisory count = inferred merge state: prefer GHSA ids, fall back to
    // CVE ids only when no GHSA is named (so CVE aliases can't inflate it).
    let advisories = |p: &BatchPatchInfo| {
        if p.ghsa_ids.is_empty() {
            p.cve_ids.len()
        } else {
            p.ghsa_ids.len()
        }
    };

    // Severity: lower rank number = worse vulnerability. A candidate fixing a
    // strictly worse advisory supersedes; a less-severe one never does.
    let cand_sev = severity_order(candidate.severity.as_deref());
    let applied_sev = severity_order(applied.severity.as_deref());
    if cand_sev != applied_sev {
        return cand_sev < applied_sev;
    }

    // Merge coverage: a patch folding in more advisories is broader.
    let cand_cov = merged_coverage(advisories(candidate));
    let applied_cov = merged_coverage(advisories(applied));
    if cand_cov != applied_cov {
        return cand_cov > applied_cov;
    }

    // Recency: only a REAL, strictly-greater publishedAt counts. A missing
    // date (the batch norm) parses to `None` and is NOT treated as newer, so
    // an equal-or-older sibling is never surfaced as an update. Parsing stays
    // on the RFC-2822-aware `api::date` helper.
    let cand_date = candidate
        .published_at
        .as_deref()
        .and_then(parse_timestamp_secs);
    let applied_date = applied
        .published_at
        .as_deref()
        .and_then(parse_timestamp_secs);
    matches!((cand_date, applied_date), (Some(c), Some(a)) if c > a)
}

/// Collect the deduplicated CVE and GHSA identifiers across every patch of
/// a package, for the scan table's VULNERABILITIES column. CVEs are listed
/// before GHSAs and each group is sorted, so the rendered output is stable —
/// the per-patch ID lists and set-based dedup are otherwise nondeterministic
/// in order. Pure / no I/O so it's unit-testable.
pub(super) fn collect_vuln_ids(pkg: &BatchPackagePatches) -> Vec<String> {
    let mut cves: HashSet<String> = HashSet::new();
    let mut ghsas: HashSet<String> = HashSet::new();
    for patch in &pkg.patches {
        for cve in &patch.cve_ids {
            cves.insert(cve.clone());
        }
        for ghsa in &patch.ghsa_ids {
            ghsas.insert(ghsa.clone());
        }
    }
    let mut cves: Vec<String> = cves.into_iter().collect();
    cves.sort();
    let mut ghsas: Vec<String> = ghsas.into_iter().collect();
    ghsas.sort();
    cves.into_iter().chain(ghsas).collect()
}

/// Severity ordering for the scan table's SEVERITY column: lower = worse.
/// Delegates to the workspace-wide ladder so the table, the selector and
/// the API client can never disagree about what `moderate` means.
pub(super) fn severity_order(s: &str) -> u8 {
    socket_patch_core::api::ranking::severity_order(Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::api::types::BatchPatchInfo;

    use crate::commands::scan::tests::manifest_with;

    // ---- severity_order ----------------------------------------------------

    #[test]
    fn severity_order_critical_is_zero() {
        assert_eq!(severity_order("critical"), 0);
    }

    #[test]
    fn severity_order_is_case_insensitive() {
        assert_eq!(severity_order("Critical"), 0);
        assert_eq!(severity_order("CRITICAL"), 0);
        assert_eq!(severity_order("High"), 1);
    }

    #[test]
    fn severity_order_known_levels() {
        assert_eq!(severity_order("high"), 1);
        assert_eq!(severity_order("medium"), 2);
        assert_eq!(severity_order("low"), 3);
    }

    #[test]
    fn severity_order_moderate_is_medium_tier() {
        // Regression: GHSA emits `moderate` for the medium tier, and scan
        // passes raw API severities straight through. get.rs
        // `severity_rank`, output.rs `format_severity`, and core's
        // `get_severity_order` all map it to medium; ranking it 4 here
        // (= unknown, below `low`) made the table's max-severity column
        // show `low` for a package whose worst vuln is moderate.
        assert_eq!(severity_order("moderate"), severity_order("medium"));
        assert!(severity_order("moderate") < severity_order("low"));
        assert_eq!(severity_order("Moderate"), severity_order("medium"));
    }

    #[test]
    fn severity_order_unknown_is_four() {
        assert_eq!(severity_order("unknown"), 4);
        assert_eq!(severity_order(""), 4);
        assert_eq!(severity_order("informational"), 4);
    }

    // ---- detect_updates -----------------------------------------------------

    fn batch_with(purl: &str, uuids: &[&str]) -> BatchPackagePatches {
        BatchPackagePatches {
            purl: purl.to_string(),
            patches: uuids
                .iter()
                .map(|u| BatchPatchInfo {
                    uuid: (*u).to_string(),
                    purl: purl.to_string(),
                    tier: "free".to_string(),
                    cve_ids: Vec::new(),
                    ghsa_ids: Vec::new(),
                    severity: None,
                    title: String::new(),
                    published_at: None,
                })
                .collect(),
        }
    }

    /// `batch_with`, but each patch carries an explicit severity and
    /// publish date so the ranking rungs above the uuid tiebreak are
    /// actually exercised.
    fn batch_ranked(purl: &str, patches: &[(&str, &str, &str)]) -> BatchPackagePatches {
        BatchPackagePatches {
            purl: purl.to_string(),
            patches: patches
                .iter()
                .map(|(uuid, severity, published)| BatchPatchInfo {
                    uuid: (*uuid).to_string(),
                    purl: purl.to_string(),
                    tier: "free".to_string(),
                    cve_ids: Vec::new(),
                    ghsa_ids: Vec::new(),
                    severity: Some((*severity).to_string()),
                    title: String::new(),
                    published_at: Some((*published).to_string()),
                })
                .collect(),
        }
    }

    #[test]
    fn detect_updates_returns_empty_when_no_manifest() {
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a"])];
        assert!(detect_updates(None, &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_returns_empty_for_empty_packages() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        assert!(detect_updates(Some(&m), &[]).is_empty());
    }

    #[test]
    fn detect_updates_returns_empty_when_no_overlap() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/bar@2.0", &["uuid-z"])];
        assert!(detect_updates(Some(&m), &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_skips_same_uuid() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a"])];
        assert!(detect_updates(Some(&m), &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_flags_different_uuid() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-b"])];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].purl, "pkg:npm/foo@1.0");
        assert_eq!(updates[0].old_uuid, "uuid-a");
        assert_eq!(updates[0].new_uuid, "uuid-b");
    }

    #[test]
    fn detect_updates_bridges_qualified_manifest_keys() {
        // Manifest keys for artifact-pinned ecosystems carry qualifiers
        // (`?artifact_id=...`); the batch purl is bare. The stripped-purl
        // bridge must match them — decode-only would silently drop these
        // packages from `updates[]` again.
        let m = manifest_with(&[("pkg:pypi/foo@1.0?artifact_id=foo-1.0.tar.gz", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:pypi/foo@1.0", &["uuid-b"])];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_uuid, "uuid-a");
        assert_eq!(updates[0].new_uuid, "uuid-b");
    }

    #[test]
    fn detect_updates_qualifier_twins_are_deterministic_any_stale_wins() {
        // One package recorded under two artifact-pinned keys (wheel +
        // sdist). `manifest.patches` is a HashMap, so an unordered `find`
        // would flip between the twins per process; the contract is: any
        // stale twin means an update, `old_uuid` names the stale one, and
        // repeated calls agree.
        let m = manifest_with(&[
            (
                "pkg:pypi/foo@1.0?artifact_id=foo-1.0-py3-none-any.whl",
                "uuid-new",
            ),
            ("pkg:pypi/foo@1.0?artifact_id=foo-1.0.tar.gz", "uuid-old"),
        ]);
        let pkgs = vec![batch_with("pkg:pypi/foo@1.0", &["uuid-new"])];
        for _ in 0..16 {
            let updates = detect_updates(Some(&m), &pkgs);
            assert_eq!(updates.len(), 1, "a stale twin means an update");
            assert_eq!(updates[0].old_uuid, "uuid-old");
            assert_eq!(updates[0].new_uuid, "uuid-new");
        }

        // Both twins current -> no update, regardless of iteration order.
        let m = manifest_with(&[
            (
                "pkg:pypi/foo@1.0?artifact_id=foo-1.0-py3-none-any.whl",
                "uuid-new",
            ),
            ("pkg:pypi/foo@1.0?artifact_id=foo-1.0.tar.gz", "uuid-new"),
        ]);
        assert!(detect_updates(Some(&m), &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_reports_multiple_updates() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a"), ("pkg:npm/bar@2.0", "uuid-c")]);
        let pkgs = vec![
            batch_with("pkg:npm/foo@1.0", &["uuid-b"]),
            batch_with("pkg:npm/bar@2.0", &["uuid-d"]),
        ];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 2);
    }

    #[test]
    fn detect_updates_skips_packages_with_empty_patch_list() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        // No candidate patches means we can't tell what the new UUID would
        // be, so there's nothing to compare against. Correct behavior is to
        // skip these silently.
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &[])];
        assert!(detect_updates(Some(&m), &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_uses_the_highest_ranked_patch_as_candidate() {
        // `detect_updates` must name the UUID the apply path will actually
        // install, which is the top-ranked patch (`api::ranking`), NOT
        // whatever the server happened to list first. Here the critical
        // patch is listed last and is the older of the two.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_ranked(
            "pkg:npm/foo@1.0",
            &[
                ("uuid-low-new", "low", "2026-06-01T00:00:00Z"),
                ("uuid-crit-old", "critical", "2024-01-01T00:00:00Z"),
            ],
        )];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].new_uuid, "uuid-crit-old");
    }

    #[test]
    fn detect_updates_candidate_ordering_ignores_incoming_list_order() {
        // Same input, reversed. A positional `.first()` would flip its
        // answer; a ranked candidate must not.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let forward = batch_ranked(
            "pkg:npm/foo@1.0",
            &[
                ("uuid-crit", "critical", "2024-01-01T00:00:00Z"),
                ("uuid-high", "high", "2026-06-01T00:00:00Z"),
            ],
        );
        let mut reversed = forward.clone();
        reversed.patches.reverse();
        assert_eq!(
            detect_updates(Some(&m), &[forward])[0].new_uuid,
            detect_updates(Some(&m), &[reversed])[0].new_uuid,
        );
    }

    #[test]
    fn detect_updates_no_update_when_manifest_holds_candidate_despite_other_patches() {
        // Regression: the human-readable table once flagged `[UPDATE]` (and
        // bumped `updates_available`) whenever *any* batch patch differed from
        // the manifest UUID. But the apply path resolves to the top-ranked
        // patch, so a manifest already holding that candidate is up to date
        // even when the batch also lists lesser patches. The table and the
        // JSON `updates` array must agree; both derive from this function,
        // which compares the ranked candidate only.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-critical")]);
        let pkgs = vec![batch_ranked(
            "pkg:npm/foo@1.0",
            &[
                ("uuid-low", "low", "2026-08-01T00:00:00Z"),
                ("uuid-critical", "critical", "2024-01-01T00:00:00Z"),
                ("uuid-medium", "medium", "2026-07-01T00:00:00Z"),
            ],
        )];
        assert!(
            detect_updates(Some(&m), &pkgs).is_empty(),
            "manifest already holds the ranked candidate — no update"
        );
    }

    #[test]
    fn detect_updates_no_nag_when_applied_patch_still_offered_and_batch_omits_dates() {
        // Regression (false-update-nag-batch-ranking / -older-uuid): after
        // vendoring, the batch endpoint re-lists BOTH the applied patch and a
        // sibling and OMITS `publishedAt`. With no real date, `cmp_batch_infos`
        // collapses to the uuid tiebreak and crowns whichever sibling sorts
        // first. `uuid-a` sorts before the applied `uuid-b`, so it becomes the
        // ranked candidate — but it is no genuine improvement (same severity,
        // same coverage, no newer date), so it must NOT be surfaced as an
        // update. Before the fix this flagged a perpetual `[UPDATE]` pointing
        // at an equal-or-older patch.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-b")]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a", "uuid-b"])];
        assert!(
            detect_updates(Some(&m), &pkgs).is_empty(),
            "an equal-or-older sibling with no real date must not be an update"
        );
    }

    #[test]
    fn detect_updates_still_flags_a_higher_severity_candidate_offered_alongside_applied() {
        // Guard against over-suppression: the applied `uuid-low` is still
        // offered, but a CRITICAL sibling supersedes it on severity. That is a
        // genuine update and must still be surfaced.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-low")]);
        let pkgs = vec![batch_ranked(
            "pkg:npm/foo@1.0",
            &[
                ("uuid-low", "low", "2026-06-01T00:00:00Z"),
                ("uuid-crit", "critical", "2024-01-01T00:00:00Z"),
            ],
        )];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_uuid, "uuid-low");
        assert_eq!(updates[0].new_uuid, "uuid-crit");
    }

    #[test]
    fn detect_updates_flags_a_genuinely_newer_candidate_when_batch_supplies_dates() {
        // The date rung is real evidence when the batch supplies it: a
        // strictly-newer sibling the apply path would install IS an update,
        // even though it sits alongside the applied patch. `uuid-new` sorts
        // LAST by uuid, so only its real 2026 date can make it the winner —
        // and the recency guard must accept that as a genuine supersede.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-aold")]);
        let pkgs = vec![batch_ranked(
            "pkg:npm/foo@1.0",
            &[
                ("uuid-aold", "high", "2024-01-01T00:00:00Z"),
                ("uuid-new", "high", "2026-06-01T00:00:00Z"),
            ],
        )];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_uuid, "uuid-aold");
        assert_eq!(updates[0].new_uuid, "uuid-new");
    }

    // ---- merge_redirect_records_for_updates ---------------------------------
    // Hosted mode records patches ONLY in the redirect ledger — these pin that
    // ledger-only projects still surface `updates[]` (the documented CI
    // signal) through the merged manifest view.

    fn ledger_with(entries: &[(&str, &str)]) -> socket_patch_core::patch::redirect::RedirectState {
        let mut state = socket_patch_core::patch::redirect::RedirectState::new();
        let manifest = crate::commands::scan::tests::manifest_with(entries);
        state.records.extend(manifest.patches);
        state
    }

    #[test]
    fn ledger_only_project_reports_superseding_patch_in_updates() {
        // Pure hosted project: NO .socket/manifest.json, one redirected patch
        // recorded in the ledger; discovery now offers a different (newer)
        // uuid. The merged view must make detect_updates flag it — this was
        // structurally impossible before the fold (manifest-only detection).
        let ledger = ledger_with(&[("pkg:npm/foo@1.0", "uuid-old")]);
        let merged = merge_redirect_records_for_updates(None, Some(&ledger));
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-new"])];
        let updates = detect_updates(merged.as_ref(), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].purl, "pkg:npm/foo@1.0");
        assert_eq!(updates[0].old_uuid, "uuid-old");
        assert_eq!(updates[0].new_uuid, "uuid-new");
    }

    #[test]
    fn ledger_record_matching_the_candidate_is_not_an_update() {
        // The redirected patch is still the top offer — no nag.
        let ledger = ledger_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let merged = merge_redirect_records_for_updates(None, Some(&ledger));
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a"])];
        assert!(detect_updates(merged.as_ref(), &pkgs).is_empty());
    }

    #[test]
    fn manifest_entry_wins_a_collision_with_a_ledger_record() {
        // A PURL present in both stores is manifest-owned (same precedence as
        // VEX's augment_with_redirect): the manifest's uuid is the "old" side.
        let manifest =
            crate::commands::scan::tests::manifest_with(&[("pkg:npm/foo@1.0", "uuid-manifest")]);
        let ledger = ledger_with(&[("pkg:npm/foo@1.0", "uuid-ledger")]);
        let merged = merge_redirect_records_for_updates(Some(manifest), Some(&ledger));
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-new"])];
        let updates = detect_updates(merged.as_ref(), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_uuid, "uuid-manifest");
    }

    #[test]
    fn ledger_and_manifest_cover_disjoint_purls() {
        // A mixed project (some deps applied via manifest, some hosted via
        // ledger) gets update detection across BOTH stores.
        let manifest =
            crate::commands::scan::tests::manifest_with(&[("pkg:npm/foo@1.0", "uuid-f1")]);
        let ledger = ledger_with(&[("pkg:npm/bar@2.0", "uuid-b1")]);
        let merged = merge_redirect_records_for_updates(Some(manifest), Some(&ledger));
        let pkgs = vec![
            batch_with("pkg:npm/foo@1.0", &["uuid-f2"]),
            batch_with("pkg:npm/bar@2.0", &["uuid-b2"]),
        ];
        let mut updates = detect_updates(merged.as_ref(), &pkgs);
        updates.sort_by(|a, b| a.purl.cmp(&b.purl));
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].old_uuid, "uuid-b1");
        assert_eq!(updates[1].old_uuid, "uuid-f1");
    }

    #[test]
    fn absent_or_empty_ledger_leaves_the_manifest_view_untouched() {
        assert!(merge_redirect_records_for_updates(None, None).is_none());
        let empty = socket_patch_core::patch::redirect::RedirectState::new();
        assert!(merge_redirect_records_for_updates(None, Some(&empty)).is_none());
        let manifest =
            crate::commands::scan::tests::manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let merged = merge_redirect_records_for_updates(Some(manifest.clone()), Some(&empty));
        assert_eq!(
            merged.unwrap().patches.len(),
            manifest.patches.len(),
            "an empty ledger adds nothing"
        );
    }

    // ---- collect_vuln_ids --------------------------------------------------

    /// Build a single-patch package whose patch carries the given CVE and
    /// GHSA identifier lists.
    fn batch_with_vulns(purl: &str, cves: &[&str], ghsas: &[&str]) -> BatchPackagePatches {
        BatchPackagePatches {
            purl: purl.to_string(),
            patches: vec![BatchPatchInfo {
                uuid: "uuid".to_string(),
                purl: purl.to_string(),
                tier: "free".to_string(),
                cve_ids: cves.iter().map(|s| (*s).to_string()).collect(),
                ghsa_ids: ghsas.iter().map(|s| (*s).to_string()).collect(),
                severity: None,
                title: String::new(),
                published_at: None,
            }],
        }
    }

    #[test]
    fn collect_vuln_ids_empty_when_no_vulns() {
        let pkg = batch_with_vulns("pkg:npm/foo@1.0", &[], &[]);
        assert!(collect_vuln_ids(&pkg).is_empty());
    }

    #[test]
    fn collect_vuln_ids_lists_cves_before_ghsas_each_sorted() {
        // Deliberately unsorted input; output must be CVEs (sorted) then
        // GHSAs (sorted) so the rendered table column is deterministic.
        let pkg = batch_with_vulns(
            "pkg:npm/foo@1.0",
            &["CVE-2024-2", "CVE-2024-1"],
            &["GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-aaaa-aaaa"],
        );
        assert_eq!(
            collect_vuln_ids(&pkg),
            vec![
                "CVE-2024-1".to_string(),
                "CVE-2024-2".to_string(),
                "GHSA-aaaa-aaaa-aaaa".to_string(),
                "GHSA-zzzz-zzzz-zzzz".to_string(),
            ],
        );
    }

    #[test]
    fn collect_vuln_ids_dedups_across_patches() {
        // The same CVE appears on two patches of one package; it must be
        // reported once.
        let pkg = BatchPackagePatches {
            purl: "pkg:npm/foo@1.0".to_string(),
            patches: vec![
                BatchPatchInfo {
                    uuid: "u1".to_string(),
                    purl: "pkg:npm/foo@1.0".to_string(),
                    tier: "free".to_string(),
                    cve_ids: vec!["CVE-2024-1".to_string()],
                    ghsa_ids: vec![],
                    severity: None,
                    title: String::new(),
                    published_at: None,
                },
                BatchPatchInfo {
                    uuid: "u2".to_string(),
                    purl: "pkg:npm/foo@1.0".to_string(),
                    tier: "free".to_string(),
                    cve_ids: vec!["CVE-2024-1".to_string()],
                    ghsa_ids: vec!["GHSA-aaaa-aaaa-aaaa".to_string()],
                    severity: None,
                    title: String::new(),
                    published_at: None,
                },
            ],
        };
        assert_eq!(
            collect_vuln_ids(&pkg),
            vec!["CVE-2024-1".to_string(), "GHSA-aaaa-aaaa-aaaa".to_string(),],
        );
    }
}
