//! Discovery-side helpers for `scan`: lockfile / vendored-ledger crawl
//! supplements, update detection against the existing manifest, vendor
//! baseline pre-verification, and the table's vuln-ID / severity helpers.

use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
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
    use socket_patch_core::patch::vendor::lock_inventory;

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
    let Ok(state) = socket_patch_core::patch::vendor::load_state(&common.cwd).await else {
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
        let Some(existing) = manifest.patches.get(&pkg.purl) else {
            continue;
        };
        // Treat the first patch in the batch as the candidate the apply path
        // would resolve to (mirrors `select_patches` ordering — newest-first
        // for paid users, single-patch auto-select for free).
        let Some(candidate) = pkg.patches.first() else {
            continue;
        };
        if candidate.uuid != existing.uuid {
            updates.push(UpdateInfo {
                purl: pkg.purl.clone(),
                old_uuid: existing.uuid.clone(),
                new_uuid: candidate.uuid.clone(),
            });
        }
    }
    updates
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

pub(super) fn severity_order(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
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
    fn detect_updates_uses_first_patch_as_candidate() {
        // `detect_updates` mirrors `select_patches` by picking the first
        // patch in the batch as the candidate UUID. Locking this in so a
        // future select_patches refactor doesn't silently drift the two.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-b", "uuid-c"])];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].new_uuid, "uuid-b");
    }

    #[test]
    fn detect_updates_no_update_when_manifest_holds_candidate_despite_other_patches() {
        // Regression: the human-readable table once flagged `[UPDATE]` (and
        // bumped `updates_available`) whenever *any* batch patch differed from
        // the manifest UUID. But the apply path resolves to the FIRST patch,
        // so a manifest already holding that candidate is up to date even when
        // the batch also lists older patches. The table and the JSON `updates`
        // array must agree; both derive from this function, which compares the
        // candidate (first) patch only.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-newest")]);
        let pkgs = vec![batch_with(
            "pkg:npm/foo@1.0",
            &["uuid-newest", "uuid-older", "uuid-oldest"],
        )];
        assert!(
            detect_updates(Some(&m), &pkgs).is_empty(),
            "manifest already holds the candidate (first) patch — no update"
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
                },
                BatchPatchInfo {
                    uuid: "u2".to_string(),
                    purl: "pkg:npm/foo@1.0".to_string(),
                    tier: "free".to_string(),
                    cve_ids: vec!["CVE-2024-1".to_string()],
                    ghsa_ids: vec!["GHSA-aaaa-aaaa-aaaa".to_string()],
                    severity: None,
                    title: String::new(),
                },
            ],
        };
        assert_eq!(
            collect_vuln_ids(&pkg),
            vec!["CVE-2024-1".to_string(), "GHSA-aaaa-aaaa-aaaa".to_string(),],
        );
    }
}
