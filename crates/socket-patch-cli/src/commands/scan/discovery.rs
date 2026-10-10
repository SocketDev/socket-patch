//! Discovery-side helpers for `scan`: lockfile / vendored-ledger crawl
//! supplements, update detection against the existing manifest, vendor
//! baseline pre-verification, and the table's vuln-ID / severity helpers.

use futures_util::StreamExt;
use socket_patch_core::api::client::hold_back_debug;
use socket_patch_core::api::ranking::cmp_batch_infos;
use socket_patch_core::api::types::{
    BatchPackagePatches, BatchPatchInfo, PatchResponse, PatchSearchResult,
};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::utils::concurrent::{api_concurrency_for, ordered_concurrent};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::lock_inventory::LockfileEntry;
use socket_patch_core::vendor::VendorState;
use std::collections::{HashMap, HashSet};

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
pub(crate) struct LockfileSupplement {
    pub(crate) packages: Vec<socket_patch_core::crawlers::types::CrawledPackage>,
    /// The lockfile-only packages' identities ([`PurlKey`]), keyed once so
    /// [`lockfile_only_contains`] is a single hash lookup.
    pub(crate) purls: HashSet<PurlKey>,
    /// The FULL lockfile inventory the supplement was derived from (installed
    /// packages included), kept so the hosted-wiring probes reuse it instead
    /// of re-parsing every project lockfile. Empty for global scans.
    pub(crate) entries: Vec<LockfileEntry>,
    /// npm layouts the lockfile inventory REFUSED (Plug'n'Play loaders).
    /// Scan surfaces these as refusal warnings: under PnP the installed-tree
    /// crawl is empty too, so otherwise the project scans as a silent no-op.
    pub(crate) unsupported: Vec<socket_patch_core::vendor::lock_inventory::UnsupportedNpmLayout>,
}

pub(crate) use socket_patch_core::vendor::lock_inventory::unsupported_layout_warnings;

/// Inventory the project's lockfile(s) and fabricate crawl entries for
/// dependencies that are not installed. The fabricated `path` is the
/// WOULD-BE install dir — every consumer degrades safely on a nonexistent
/// path (hash verify → NotFound, apply → partitioned skip, vendor →
/// auto-fetch). Global scans target the machine's global tree, not this
/// project's lockfile, so they get no supplement.
///
/// `only` is the crawl's ecosystem scope (`None`: every ecosystem was
/// crawled): an entry of an ecosystem the crawl skipped is never counted
/// lockfile-only, since there is no crawl to tell whether it is installed.
/// `entries` still holds the full inventory.
pub(crate) async fn lockfile_supplement(
    ctx: &crate::commands::context::ProjectContext<'_>,
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
    only: Option<&[String]>,
) -> LockfileSupplement {
    let common = ctx.common;
    let mut out = LockfileSupplement::default();
    if common.is_global() {
        return out;
    }
    let locks = ctx.locks().await;
    out.unsupported = locks.unsupported.clone();
    let entries = &locks.entries;
    if entries.is_empty() {
        return out;
    }
    (out.packages, out.purls) = lockfile_only_packages(entries, crawled, only, &common.cwd);
    out.entries = entries.clone();
    out
}

/// The lockfile entries with no crawled counterpart, fabricated as crawl
/// entries, plus their [`PurlKey`]s. "Crawled" is by [`PurlKey`], the same
/// relation [`lockfile_only_contains`] answers by: a lock spelling that
/// differs from the installed crawl's only in encoding, NuGet case, PEP 503
/// form or composer padding is the installed package, not a lockfile-only
/// one — keyed in, its every spelling would read as not installed.
fn lockfile_only_packages(
    entries: &[LockfileEntry],
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
    only: Option<&[String]>,
    cwd: &std::path::Path,
) -> (
    Vec<socket_patch_core::crawlers::types::CrawledPackage>,
    HashSet<PurlKey>,
) {
    let mut packages = Vec::new();
    let mut purls = HashSet::new();
    let crawled_keys: HashSet<PurlKey> = crawled.iter().map(|p| PurlKey::new(&p.purl)).collect();
    let in_scope = |purl: &str| {
        only.is_none_or(|list| {
            socket_patch_core::crawlers::Ecosystem::from_purl(purl)
                .is_some_and(|eco| list.iter().any(|name| name == eco.cli_name()))
        })
    };
    for entry in entries {
        let key = PurlKey::new(&entry.purl);
        if crawled_keys.contains(&key) || !in_scope(&entry.purl) {
            continue;
        }
        let Some(pkg) = crawled_from_purl(&entry.purl, cwd) else {
            continue;
        };
        purls.insert(key);
        packages.push(pkg);
    }
    (packages, purls)
}

/// Whether an API-spelled purl (percent-encoded, possibly qualified) names
/// a lockfile-only package: `purls` holds the crawler spellings' keys, so
/// the comparison bridges the two by [`PurlKey`] (encoding, qualifiers,
/// PyPI/NuGet name folding, composer release identity: the API may serve
/// the padded `@3.0.2.0` for a lock's `3.0.2`). The ONE predicate behind the
/// `notInstalled` flag, the `[NOT INSTALLED]` marker, the
/// `package_not_installed` skip partition and the vendor baseline pre-check.
pub(super) fn lockfile_only_contains(purls: &HashSet<PurlKey>, api_purl: &str) -> bool {
    purls.contains(&PurlKey::new(api_purl))
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

/// What [`vendored_ledger_supplement`] adds to discovery, and what it
/// deliberately left out.
#[derive(Debug, Default)]
pub(crate) struct LedgerSupplement {
    /// Ledger packages to discover (decoded purls, sorted).
    pub(crate) packages: Vec<socket_patch_core::crawlers::types::CrawledPackage>,
    /// Ledger keys whose lock provably no longer resolves through their
    /// committed artifact (the dependency was upgraded or removed), so they
    /// are not discoverable packages. `scan --prune` reverts them. Sorted.
    pub(crate) unwired: Vec<String>,
}

/// Vendored-ledger packages with no crawled counterpart: on a fresh clone
/// the committed artifact IS the dependency, so these stay discoverable
/// (updates[] detection, the table, and `scan --mode vendored` re-vendor/in-sync
/// runs all keep working before any install). They are NOT "lockfile-only"
/// — nothing needs installing; the artifact satisfies the lock. `state` is
/// the ledger `run` already loaded (`vendor::load_state`).
///
/// That holds only while the lock still wires the artifact. An entry the
/// project no longer consumes ([`Discovery::vendor_entry_in_use`] is
/// `Some(false)` — the verdict the prune GC reverts by, read from `ctx`'s
/// discovery) is the dependency having left the lock — bumped or
/// uninstalled — and is reported in [`LedgerSupplement::unwired`] instead:
/// re-vendoring it would fail against a lock that no longer has it. `None`
/// (no readable lock for the ecosystem) keeps the entry.
///
/// [`Discovery::vendor_entry_in_use`]: socket_patch_core::vex::discover::Discovery::vendor_entry_in_use
pub(crate) async fn vendored_ledger_supplement(
    ctx: &crate::commands::context::ProjectContext<'_>,
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
    state: &std::io::Result<VendorState>,
) -> LedgerSupplement {
    let common = ctx.common;
    let mut out = LedgerSupplement::default();
    if common.is_global() {
        return out;
    }
    // `(ledger key, base purl, entry)`; the artifact fallback has no
    // entries to probe, so it never reports unwired keys.
    let candidates: Vec<(
        String,
        String,
        Option<&socket_patch_core::vendor::VendorEntry>,
    )> = match state {
        Ok(state) => state
            .entries
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    strip_purl_qualifiers(&entry.base_purl).to_string(),
                    Some(entry),
                )
            })
            .collect(),
        // Corrupt/unreadable ledger (a MISSING file is Ok(empty) above):
        // recover the vendored set from the committed artifacts, or
        // `scan --prune` (whose ledger exemption also degrades to empty)
        // would delete still-vendored packages' manifest entries and blobs.
        Err(_) => vendored_purls_from_artifacts(common)
            .await
            .into_iter()
            .map(|base| (base.clone(), base, None))
            .collect(),
    };
    // By release identity: a ledger `@3.0.2.0` is the crawled composer
    // `@3.0.2`, a ledger `Newtonsoft.Json` the crawled `newtonsoft.json` —
    // not a second package to supplement.
    let crawled_norm: HashSet<PurlKey> = crawled.iter().map(|p| PurlKey::new(&p.purl)).collect();
    let mut seen: HashSet<PurlKey> = HashSet::new();
    for (ledger_key, base, entry) in &candidates {
        let norm = PurlKey::new(base);
        if crawled_norm.contains(&norm) || seen.contains(&norm) {
            continue;
        }
        if let Some(entry) = entry {
            if ctx
                .discovery()
                .await
                .vendor_entry_in_use(&common.cwd, entry)
                .await
                == Some(false)
            {
                out.unwired.push(ledger_key.clone());
                continue;
            }
        }
        seen.insert(norm);
        if let Some(pkg) = crawled_from_purl(base, &common.cwd) {
            out.packages.push(pkg);
        }
    }
    out.packages.sort_by(|a, b| a.purl.cmp(&b.purl));
    out.unwired.sort();
    out
}

/// Fallback source for [`vendored_ledger_supplement`] when the vendor ledger
/// is unreadable — the committed ground truth, read two ways:
///
/// 1. base purls of manifest entries whose patch uuid owns a live
///    `.socket/vendor/<eco>/<uuid>` artifact dir (legacy manifest-mode
///    vendored projects; `vendor_uuid_dir_rel` validates the committed,
///    tamper-able uuid grammar fail-closed before any disk probe — entries
///    without a live artifact dir are NOT recovered: nothing committed
///    consumes them, so they stay prunable);
/// 2. base purls reconstructed from the artifact leaves under every
///    canonical `.socket/vendor/<eco>/<uuid>/` dir (`sweep_vendor_dirs`,
///    the documented external-tool recovery rule) — the only source for a
///    manifest-free vendored project, whose records live in the ledger
///    alone.
///
/// Duplicates between the two are collapsed by the caller.
async fn vendored_purls_from_artifacts(common: &GlobalArgs) -> Vec<String> {
    use socket_patch_core::manifest::operations::read_manifest;
    use socket_patch_core::vendor::ecosystem_dir_for_purl;
    use socket_patch_core::vendor::path::{sweep_vendor_dirs, vendor_uuid_dir_rel};

    let mut out = Vec::new();
    if let Ok(Some(manifest)) = read_manifest(common.resolved_manifest_path()).await {
        for (purl, record) in &manifest.patches {
            let base = strip_purl_qualifiers(purl);
            let Some(eco) = ecosystem_dir_for_purl(base) else {
                continue;
            };
            let Some(rel) = vendor_uuid_dir_rel(eco, &record.uuid) else {
                continue;
            };
            match tokio::fs::metadata(common.cwd.join(&rel)).await {
                Ok(md) if md.is_dir() => out.push(base.to_string()),
                _ => {}
            }
        }
    }
    for unit in sweep_vendor_dirs(&common.cwd).await {
        out.extend(unit.purls);
    }
    out
}

pub(super) async fn preverify_vendor_baselines<W: std::io::Write>(
    api_client: &socket_patch_core::api::client::ApiClient,
    selected: &[PatchSearchResult],
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
    lockfile_only: &HashSet<PurlKey>,
    vendor: Option<&HashMap<String, socket_patch_core::vendor::VendorEntry>>,
    status: &mut crate::ui::StatusLine<W>,
) -> (HashSet<String>, HashMap<String, PatchResponse>) {
    use socket_patch_core::crawlers::gradle_cache;
    use socket_patch_core::manifest::schema::PatchFileInfo;
    use socket_patch_core::patch::apply::{verify_file_patch, VerifyStatus};
    use socket_patch_core::vendor::lookup_entry;

    let mut mismatched: HashSet<String> = HashSet::new();
    let mut views: HashMap<String, PatchResponse> = HashMap::new();
    // Per patch, what the loop below compares: `None` to skip it, else the
    // installed copy plus the ledger's embedded record (`None` = fetch the
    // view). Local and read-only, so it is computed up front.
    let plan: Vec<
        Option<(
            &socket_patch_core::crawlers::types::CrawledPackage,
            Option<&PatchRecord>,
        )>,
    > = selected
        .iter()
        .map(|patch| {
            // API purls come percent-encoded, crawler purls literal —
            // PurlKey bridges the two spellings.
            let base = strip_purl_qualifiers(&patch.purl);
            // Lockfile-only packages have no installed bytes to compare
            // — the vendor engine fetches them pristine (nothing to
            // annotate).
            if lockfile_only_contains(lockfile_only, base) {
                return None;
            }
            let pkg = crawled.iter().find(|c| PurlKey::same(&c.purl, base))?;
            // The same predicate as the download phase's ledger
            // idempotency skip: its no-fetch set and this one must be
            // the same set.
            let embedded = vendor
                .and_then(|entries| lookup_entry(entries, &patch.purl))
                .filter(|e| e.detached && e.uuid == patch.uuid)
                .and_then(|e| e.record.as_ref());
            Some((pkg, embedded))
        })
        .collect();
    // The views the loop needs, fetched concurrently (at most
    // `api_concurrency` in flight) and consumed in `selected` order, each
    // request's `--debug` lines released at its turn.
    let to_fetch: Vec<&str> = selected
        .iter()
        .zip(&plan)
        .filter(|(_, step)| matches!(step, Some((_, None))))
        .map(|(patch, _)| patch.uuid.as_str())
        .collect();
    let window_len = to_fetch.len();
    let mut details = std::pin::pin!(ordered_concurrent(
        to_fetch,
        api_concurrency_for(api_client.uses_public_proxy(), window_len),
        |uuid| async move { (uuid, hold_back_debug(api_client.fetch_patch(uuid)).await) },
    ));
    for (i, (patch, step)) in selected.iter().zip(&plan).enumerate() {
        status.set(format!(
            "Checking installed files against patch baselines... ({}/{})",
            i + 1,
            selected.len()
        ));
        let Some((pkg, embedded)) = *step else {
            continue;
        };
        let files: Vec<(String, PatchFileInfo)> = match embedded {
            Some(record) => record
                .files
                .iter()
                .map(|(file, info)| (file.clone(), info.clone()))
                .collect(),
            None => {
                // The plan names exactly the patches this arm reaches, so
                // the next view is this patch's. Checking says so out
                // loud: a plan out of step would otherwise annotate this
                // package against ANOTHER patch's hashes and store that
                // response under this uuid for the download phase.
                let detail = match details.next().await {
                    Some((planned, detail)) if planned == patch.uuid => detail.release(),
                    _ => {
                        debug_assert!(
                            false,
                            "baseline view prefetch plan out of step with the patches"
                        );
                        api_client.fetch_patch(&patch.uuid).await
                    }
                };
                let Ok(Some(detail)) = detail else {
                    continue;
                };
                let files = detail
                    .files
                    .iter()
                    .map(|(file, info)| {
                        (
                            file.clone(),
                            PatchFileInfo {
                                before_hash: info.before_hash.clone().unwrap_or_default(),
                                after_hash: info.after_hash.clone().unwrap_or_default(),
                            },
                        )
                    })
                    .collect();
                views.insert(patch.uuid.clone(), detail);
                files
            }
        };
        // A new file has no baseline to compare.
        let files: HashMap<String, PatchFileInfo> = files
            .into_iter()
            .filter(|(_, info)| !info.before_hash.is_empty())
            .collect();
        // A Gradle version dir stands for every hash-dir copy of its files;
        // any copy off the baseline is a mismatch.
        'copies: for (dir, files) in gradle_cache::installed_copies(&pkg.path, &files) {
            for (file, info) in &files {
                if verify_file_patch(&dir, file, info).await.status == VerifyStatus::HashMismatch {
                    mismatched.insert(patch.uuid.clone());
                    break 'copies;
                }
            }
        }
    }
    status.finish();
    (mismatched, views)
}

pub(super) use socket_patch_core::ledgers::merge_ledger_records_for_updates;

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
        // resolves to, so `[UPDATE]` and `updates[]` track what scan
        // installs. One divergence: the batch response omits `publishedAt`,
        // so on a merge-status + severity tie this falls to the tier/uuid
        // tiebreaks where apply (by-package shape) uses the date.
        //
        // `min_by` is load-bearing for callers that build a
        // `BatchPackagePatches` themselves (the client already sorts).
        let Some(candidate) = pkg.patches.iter().min_by(|a, b| cmp_batch_infos(a, b)) else {
            continue;
        };
        // Manifest keys are written verbatim from the *patch* purl, which
        // the API serves percent-encoded (`pkg:npm/%40scope/...`) and, for
        // artifact-pinned ecosystems, qualified (`?artifact_id=...`); the
        // batch *package* purl is the crawler's literal spelling. Bridge
        // both divergences like the lockfile-only partition does: exact hit
        // first, then by [`PurlKey`] (a composer `@3.0.2.0` key is the
        // crawler's `@3.0.2`, a NuGet `Newtonsoft.Json` key its lowercase
        // global-cache spelling).
        //
        // Qualifier TWINS (e.g. a pypi wheel + sdist pair) all match the
        // stripped form: any stale twin means an update, so prefer the
        // first (sorted-key order, for stability) whose uuid differs.
        let existing = manifest.patches.get(&pkg.purl).or_else(|| {
            let want = PurlKey::new(&pkg.purl);
            let mut twins: Vec<(&String, &socket_patch_core::manifest::schema::PatchRecord)> =
                manifest
                    .patches
                    .iter()
                    .filter(|(k, _)| PurlKey::new(k) == want)
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
        // (b) "Outranks" includes the tier/uuid tiebreaks and the batch
        // endpoint's missing (epoch-0) dates, so when the recorded patch is
        // still offered, only report a candidate that genuinely supersedes
        // it. If it is no longer offered, any different candidate is flagged.
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

/// Whether `candidate` genuinely supersedes the applied patch (see
/// [`socket_patch_core::api::ranking::batch_supersedes`]): the guard that
/// keeps an equal sibling from showing as a perpetual `[UPDATE]`.
fn candidate_supersedes(candidate: &BatchPatchInfo, applied: &BatchPatchInfo) -> bool {
    socket_patch_core::api::ranking::batch_supersedes(candidate, applied)
}

/// The scan table's VULNERABILITIES data for one package, built from the
/// batch results (see [`collect_vuln_ids`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct VulnIds {
    /// Ids to show first: every CVE, then the GHSAs that only ever appear
    /// on patches listing no CVE (those cannot be aliases). Each group is
    /// sorted.
    pub primary: Vec<String>,
    /// Every CVE and GHSA id (CVEs first, each group sorted), for `--verbose`.
    pub all: Vec<String>,
    /// How many distinct vulnerabilities the ids stand for, for `(+N)`.
    pub count: usize,
}

/// Collect a package's vulnerability ids across all its patches, for the
/// scan table's VULNERABILITIES column. The output is sorted and deduped,
/// so the rendered table is stable (the per-patch lists and set-based
/// dedup are otherwise nondeterministic in order). Pure / no I/O so it's
/// unit-testable.
///
/// A GHSA id is usually an alias of a CVE listed beside it, but the batch
/// endpoint gives the two lists without their pairing, so listing both made
/// `(+N)` count most vulnerabilities twice. Each vulnerability has at least
/// one of the two ids, so the count is the larger of the distinct CVEs and
/// the distinct GHSAs. That is exact when every GHSA has at most one CVE,
/// and never counts an alias twice.
pub(super) fn collect_vuln_ids(pkg: &BatchPackagePatches) -> VulnIds {
    let mut cves: HashSet<&str> = HashSet::new();
    let mut ghsas: HashSet<&str> = HashSet::new();
    let mut ghsa_only: HashSet<&str> = HashSet::new();
    let mut ghsa_beside_cve: HashSet<&str> = HashSet::new();
    for patch in &pkg.patches {
        cves.extend(patch.cve_ids.iter().map(String::as_str));
        ghsas.extend(patch.ghsa_ids.iter().map(String::as_str));
        let bucket = if patch.cve_ids.is_empty() {
            &mut ghsa_only
        } else {
            &mut ghsa_beside_cve
        };
        bucket.extend(patch.ghsa_ids.iter().map(String::as_str));
    }
    // A GHSA listed beside a CVE on any patch may be its alias.
    ghsa_only.retain(|g| !ghsa_beside_cve.contains(g));
    let sorted = |set: &HashSet<&str>| {
        let mut v: Vec<String> = set.iter().map(|s| (*s).to_string()).collect();
        v.sort();
        v
    };
    let cves = sorted(&cves);
    let ghsas = sorted(&ghsas);
    let primary: Vec<String> = cves.iter().cloned().chain(sorted(&ghsa_only)).collect();
    let count = cves.len().max(ghsas.len()).max(primary.len());
    VulnIds {
        primary,
        all: cves.into_iter().chain(ghsas).collect(),
        count,
    }
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
    use std::borrow::Cow;

    use crate::commands::scan::tests::manifest_with;

    // ---- lockfile_only_packages --------------------------------------------

    fn lock_entry(ecosystem: &'static str, purl: &str) -> LockfileEntry {
        use socket_patch_core::vendor::lock_inventory::{LockIntegrity, SourceKind};
        LockfileEntry {
            ecosystem,
            name: String::new(),
            version: String::new(),
            purl: purl.to_string(),
            resolved: None,
            integrity: LockIntegrity::None,
            source_kind: SourceKind::Unspecified,
        }
    }

    fn crawled_from(purl: &str) -> socket_patch_core::crawlers::types::CrawledPackage {
        crawled_from_purl(purl, std::path::Path::new("/p")).unwrap()
    }

    /// An installed package whose lock spelling differs from the crawl's
    /// (NuGet case, PEP 503 form, composer padding) is NOT lockfile-only:
    /// keyed in, [`lockfile_only_contains`] would mark every spelling of the
    /// live install `package_not_installed`. A truly absent one still is.
    #[test]
    fn lockfile_only_packages_excludes_crawled_spelling_variants() {
        let entries = vec![
            lock_entry("nuget", "pkg:nuget/Newtonsoft.Json@13.0.1"),
            lock_entry("pypi", "pkg:pypi/typing_extensions@4.12.2"),
            lock_entry("composer", "pkg:composer/psr/log@3.0.2"),
            lock_entry("npm", "pkg:npm/lockonly@1.0.0"),
        ];
        let crawled = vec![
            crawled_from("pkg:nuget/newtonsoft.json@13.0.1"),
            crawled_from("pkg:pypi/typing-extensions@4.12.2"),
            crawled_from("pkg:composer/psr/log@3.0.2.0"),
        ];
        let (packages, purls) =
            lockfile_only_packages(&entries, &crawled, None, std::path::Path::new("/p"));
        let got: Vec<&str> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(got, vec!["pkg:npm/lockonly@1.0.0"]);
        assert!(lockfile_only_contains(&purls, "pkg:npm/lockonly@1.0.0"));
        for api in [
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            "pkg:pypi/typing-extensions@4.12.2",
            "pkg:composer/psr/log@3.0.2.0",
        ] {
            assert!(!lockfile_only_contains(&purls, api), "{api}");
        }
    }

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
        // GHSA emits `moderate` for the medium tier and scan passes raw API
        // severities through, so it must rank as medium, not unknown.
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
        // bridge must match them, or these packages drop out of `updates[]`.
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
        // A manifest already holding the top-ranked candidate is up to date
        // even when the batch also lists lesser patches.
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
        // The batch re-lists the applied patch and a sibling with no
        // `publishedAt`, so `uuid-a` wins only on the uuid tiebreak. That is
        // no genuine improvement, so it must NOT be surfaced as an update.
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

    // ---- merge_ledger_records_for_updates -----------------------------------
    // Hosted mode records patches ONLY in the lockfiles (the hosted pins) and
    // vendored mode ONLY in the vendor ledger — these pin that manifest-less
    // projects still surface `updates[]` (the documented CI signal) through
    // the merged manifest view.

    fn pins(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(purl, uuid)| (purl.to_string(), uuid.to_string()))
            .collect()
    }

    /// A vendor ledger with one entry per `(key, uuid, detached)`: detached
    /// entries embed their record, legacy ones carry only the uuid.
    fn vendor_ledger_with(entries: &[(&str, &str, bool)]) -> VendorState {
        let entries: serde_json::Map<String, serde_json::Value> = entries
            .iter()
            .map(|(key, uuid, detached)| {
                let record = crate::commands::scan::tests::manifest_with(&[(key, uuid)])
                    .patches
                    .remove(*key)
                    .expect("manifest_with inserted the key");
                let mut entry = serde_json::json!({
                    "ecosystem": "npm",
                    "basePurl": strip_purl_qualifiers(key),
                    "uuid": uuid,
                    "artifact": { "path": format!(".socket/vendor/npm/{uuid}/pkg.tgz") },
                    "wiring": [],
                    "detached": detached,
                });
                if *detached {
                    entry["record"] = serde_json::to_value(record).unwrap();
                }
                ((*key).to_string(), entry)
            })
            .collect();
        serde_json::from_value(serde_json::json!({ "version": 1, "entries": entries }))
            .expect("the camelCase wire shape deserializes")
    }

    #[test]
    fn hosted_only_project_reports_superseding_patch_in_updates() {
        // Pure hosted project: NO .socket/manifest.json, one hosted pin in
        // the lockfile; discovery now offers a different (newer) uuid. The
        // merged view must make detect_updates flag it.
        let hosted = pins(&[("pkg:npm/foo@1.0", "uuid-old")]);
        let merged = merge_ledger_records_for_updates(None, None, &hosted);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-new"])];
        let updates = detect_updates(merged.as_deref(), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].purl, "pkg:npm/foo@1.0");
        assert_eq!(updates[0].old_uuid, "uuid-old");
        assert_eq!(updates[0].new_uuid, "uuid-new");
    }

    #[test]
    fn vendored_only_project_reports_superseding_patch_in_updates() {
        // Pure vendored project (manifest-free): the ledger entry's
        // embedded record is the "old" side. A legacy entry with no embedded
        // record still contributes its uuid — all detection reads.
        for detached in [true, false] {
            let vendor = vendor_ledger_with(&[("pkg:npm/foo@1.0", "uuid-old", detached)]);
            let merged = merge_ledger_records_for_updates(None, Some(&vendor), &[]);
            let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-new"])];
            let updates = detect_updates(merged.as_deref(), &pkgs);
            assert_eq!(updates.len(), 1, "detached={detached}");
            assert_eq!(updates[0].old_uuid, "uuid-old");
            assert_eq!(updates[0].new_uuid, "uuid-new");
        }
        // Still the top offer — no nag.
        let vendor = vendor_ledger_with(&[("pkg:npm/foo@1.0", "uuid-a", true)]);
        let merged = merge_ledger_records_for_updates(None, Some(&vendor), &[]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a"])];
        assert!(detect_updates(merged.as_deref(), &pkgs).is_empty());
    }

    #[test]
    fn hosted_pin_matching_the_candidate_is_not_an_update() {
        // The hosted patch is still the top offer — no nag.
        let hosted = pins(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let merged = merge_ledger_records_for_updates(None, None, &hosted);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a"])];
        assert!(detect_updates(merged.as_deref(), &pkgs).is_empty());
    }

    #[test]
    fn manifest_entry_wins_a_collision_with_a_ledger_record() {
        // A PURL present in every store is manifest-owned (same precedence as
        // VEX's candidate merge): the manifest's uuid is the "old" side;
        // between the other two, the live hosted pin wins over the vendor
        // ledger's (possibly superseded) entry.
        let manifest =
            crate::commands::scan::tests::manifest_with(&[("pkg:npm/foo@1.0", "uuid-manifest")]);
        let hosted = pins(&[("pkg:npm/foo@1.0", "uuid-pin")]);
        let vendor = vendor_ledger_with(&[("pkg:npm/foo@1.0", "uuid-vendor", true)]);
        let merged = merge_ledger_records_for_updates(Some(&manifest), Some(&vendor), &hosted);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-new"])];
        let updates = detect_updates(merged.as_deref(), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_uuid, "uuid-manifest");
        let merged = merge_ledger_records_for_updates(None, Some(&vendor), &hosted);
        let updates = detect_updates(merged.as_deref(), &pkgs);
        assert_eq!(updates[0].old_uuid, "uuid-pin");
    }

    #[test]
    fn hosted_pins_and_manifest_cover_disjoint_purls() {
        // A mixed project (some deps applied via manifest, some hosted in
        // the lockfile, some vendored) gets update detection across every
        // store.
        let manifest =
            crate::commands::scan::tests::manifest_with(&[("pkg:npm/foo@1.0", "uuid-f1")]);
        let hosted = pins(&[("pkg:npm/bar@2.0", "uuid-b1")]);
        let vendor = vendor_ledger_with(&[("pkg:npm/baz@3.0", "uuid-z1", true)]);
        let merged = merge_ledger_records_for_updates(Some(&manifest), Some(&vendor), &hosted);
        let pkgs = vec![
            batch_with("pkg:npm/foo@1.0", &["uuid-f2"]),
            batch_with("pkg:npm/bar@2.0", &["uuid-b2"]),
            batch_with("pkg:npm/baz@3.0", &["uuid-z2"]),
        ];
        let mut updates = detect_updates(merged.as_deref(), &pkgs);
        updates.sort_by(|a, b| a.purl.cmp(&b.purl));
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0].old_uuid, "uuid-b1");
        assert_eq!(updates[1].old_uuid, "uuid-z1");
        assert_eq!(updates[2].old_uuid, "uuid-f1");
    }

    #[test]
    fn absent_or_empty_stores_leave_the_manifest_view_untouched() {
        assert!(merge_ledger_records_for_updates(None, None, &[]).is_none());
        let hosted = pins(&[("pkg:npm/foo@1.0.0", "uuid-pin")]);
        let merged = merge_ledger_records_for_updates(None, None, &hosted).expect("pinned");
        assert_eq!(merged.patches["pkg:npm/foo@1.0.0"].uuid, "uuid-pin");
        let empty_vendor = VendorState::new();
        assert!(merge_ledger_records_for_updates(None, Some(&empty_vendor), &[]).is_none());
        let manifest =
            crate::commands::scan::tests::manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let merged = merge_ledger_records_for_updates(Some(&manifest), Some(&empty_vendor), &[])
            .expect("manifest present");
        assert!(
            matches!(merged, Cow::Borrowed(_)),
            "empty stores must not clone the manifest"
        );
        assert_eq!(
            merged.patches.len(),
            manifest.patches.len(),
            "an empty vendor ledger adds nothing"
        );
    }

    // ---- vendored_ledger_supplement (corrupt-ledger fallback) ---------------
    // Vendored purls enter `scanned_purls` via this supplement, which shields
    // their manifest entries from `scan --prune`. A corrupt ledger must fall
    // back to the committed artifact dirs rather than return empty.

    const VENDORED_UUID: &str = "11111111-1111-4111-8111-111111111111";

    fn seed_manifest_entry(root: &std::path::Path, purl: &str, uuid: &str) {
        let socket = root.join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        let manifest = serde_json::json!({
            "patches": {
                purl: {
                    "uuid": uuid,
                    "exportedAt": "2026-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        });
        std::fs::write(
            socket.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }

    /// A truncated merge-resolution artifact: not valid JSON at all, so
    /// `load_state` errs (fail-closed) rather than reading an empty ledger.
    fn seed_corrupt_ledger(root: &std::path::Path) {
        let vendor = root.join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(vendor.join("state.json"), b"{\"entries\": {").unwrap();
    }

    async fn supplement_in(
        root: &std::path::Path,
        crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
    ) -> Vec<socket_patch_core::crawlers::types::CrawledPackage> {
        let args = GlobalArgs {
            cwd: root.to_path_buf(),
            ..GlobalArgs::default()
        };
        let state = socket_patch_core::vendor::load_state(root).await;
        vendored_ledger_supplement(
            &crate::commands::context::ProjectContext::new(&args),
            crawled,
            &state,
        )
        .await
        .packages
    }

    /// A ledger entry vendored as `@3.0.2.0` is the crawled composer
    /// `@3.0.2`, not a second package to add to the scan.
    #[tokio::test]
    async fn ledger_supplement_matches_composer_by_release_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let mut state = VendorState::new();
        let entry: socket_patch_core::vendor::VendorEntry =
            serde_json::from_value(serde_json::json!({
                "ecosystem": "composer",
                "basePurl": "pkg:composer/psr/log@3.0.2.0",
                "uuid": VENDORED_UUID,
                "artifact": {"path": format!(".socket/vendor/composer/{VENDORED_UUID}/psr/log@3.0.2.0"), "sha256": ""},
                "wiring": [],
            }))
            .unwrap();
        state
            .entries
            .insert("pkg:composer/psr/log@3.0.2.0".to_string(), entry);
        let crawled = crawled_from_purl("pkg:composer/psr/log@3.0.2", tmp.path()).unwrap();
        let args = GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            ..GlobalArgs::default()
        };
        let out = vendored_ledger_supplement(
            &crate::commands::context::ProjectContext::new(&args),
            &[crawled],
            &Ok(state.clone()),
        )
        .await
        .packages;
        assert!(
            out.is_empty(),
            "{:?}",
            out.iter().map(|p| &p.purl).collect::<Vec<_>>()
        );

        let out = vendored_ledger_supplement(
            &crate::commands::context::ProjectContext::new(&args),
            &[],
            &Ok(state),
        )
        .await
        .packages;
        assert_eq!(
            out.iter().map(|p| p.purl.as_str()).collect::<Vec<_>>(),
            vec!["pkg:composer/psr/log@3.0.2.0"]
        );
    }

    /// An npm (package-lock flavor) ledger entry for `left-pad@1.3.0`
    /// vendored under [`VENDORED_UUID`], with `lock` as the project's
    /// package-lock.json (`None`: no lock at all).
    async fn npm_ledger_with_lock(
        root: &std::path::Path,
        lock: Option<&str>,
    ) -> std::io::Result<VendorState> {
        let mut state = VendorState::new();
        let entry: socket_patch_core::vendor::VendorEntry =
            serde_json::from_value(serde_json::json!({
                "ecosystem": "npm",
                "basePurl": "pkg:npm/left-pad@1.3.0",
                "uuid": VENDORED_UUID,
                "artifact": {"path": format!(".socket/vendor/npm/{VENDORED_UUID}/left-pad-1.3.0/node_modules/left-pad"), "sha256": ""},
                "wiring": [],
            }))
            .unwrap();
        state
            .entries
            .insert("pkg:npm/left-pad@1.3.0".to_string(), entry);
        if let Some(lock) = lock {
            std::fs::write(root.join("package-lock.json"), lock).unwrap();
        }
        Ok(state)
    }

    fn npm_lock_resolving(left_pad: &str) -> String {
        serde_json::json!({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "dependencies": {"left-pad": "*"}},
                "node_modules/left-pad": {"version": "1.3.0", "resolved": left_pad},
            }
        })
        .to_string()
    }

    /// #541: once the dependency left the lock (bumped to another release,
    /// or uninstalled), the ledger entry is no longer a discoverable
    /// package: supplementing it made the vendor step re-vendor a package
    /// the lock no longer has and fail the whole scan.
    #[tokio::test]
    async fn ledger_supplement_skips_entries_the_lock_no_longer_wires() {
        let args = |root: &std::path::Path| GlobalArgs {
            cwd: root.to_path_buf(),
            ..GlobalArgs::default()
        };
        // Bumped: the lock resolves left-pad from the registry again.
        let tmp = tempfile::tempdir().unwrap();
        let bumped = serde_json::json!({
            "name": "app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "app", "dependencies": {"left-pad": "1.2.0"}},
                "node_modules/left-pad": {
                    "version": "1.2.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz",
                },
            }
        })
        .to_string();
        let state = npm_ledger_with_lock(tmp.path(), Some(&bumped)).await;
        let out = vendored_ledger_supplement(
            &crate::commands::context::ProjectContext::new(&args(tmp.path())),
            &[],
            &state,
        )
        .await;
        assert!(out.packages.is_empty(), "{:?}", out.packages);
        assert_eq!(out.unwired, vec!["pkg:npm/left-pad@1.3.0".to_string()]);

        // Uninstalled: the lock has no left-pad at all.
        let tmp = tempfile::tempdir().unwrap();
        let removed = r#"{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"}}}"#;
        let state = npm_ledger_with_lock(tmp.path(), Some(removed)).await;
        let out = vendored_ledger_supplement(
            &crate::commands::context::ProjectContext::new(&args(tmp.path())),
            &[],
            &state,
        )
        .await;
        assert!(out.packages.is_empty(), "{:?}", out.packages);
        assert_eq!(out.unwired, vec!["pkg:npm/left-pad@1.3.0".to_string()]);
    }

    /// B19: the supplement and the prune GC share one in-use verdict for
    /// every ecosystem, not only npm/cargo/pypi-requirements. A COMPOSER
    /// entry whose dependency composer.lock bumped to a registry release is
    /// unwired — before, it was resurrected as a discovered package forever.
    #[tokio::test]
    async fn ledger_supplement_reports_a_bumped_composer_entry_unwired() {
        const COMPOSER_PURL: &str = "pkg:composer/monolog/monolog@3.0.0";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let leaf = format!(".socket/vendor/composer/{VENDORED_UUID}/monolog/monolog@3.0.0");
        let entry: socket_patch_core::vendor::VendorEntry =
            serde_json::from_value(serde_json::json!({
                "ecosystem": "composer",
                "basePurl": COMPOSER_PURL,
                "uuid": VENDORED_UUID,
                "artifact": {"path": leaf, "sha256": ""},
                "wiring": [],
                "detached": true,
            }))
            .unwrap();
        let mut state = VendorState::default();
        state.entries.insert(COMPOSER_PURL.to_string(), entry);
        std::fs::write(
            root.join("composer.lock"),
            serde_json::json!({
                "packages": [{
                    "name": "monolog/monolog",
                    "version": "3.1.0",
                    "dist": {
                        "type": "zip",
                        "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
                        "reference": "abc",
                    },
                }],
                "packages-dev": [],
            })
            .to_string(),
        )
        .unwrap();
        let args = GlobalArgs {
            cwd: root.to_path_buf(),
            ..GlobalArgs::default()
        };
        let out = vendored_ledger_supplement(
            &crate::commands::context::ProjectContext::new(&args),
            &[],
            &Ok(state),
        )
        .await;
        assert!(out.packages.is_empty(), "{:?}", out.packages);
        assert_eq!(out.unwired, vec![COMPOSER_PURL.to_string()]);
    }

    /// The fresh-clone case the supplement exists for: the lock still
    /// resolves through the committed artifact, so the entry stays
    /// discoverable. With no lock at all, nothing proves the entry unused,
    /// so it is kept (fail-safe, like the prune GC).
    #[tokio::test]
    async fn ledger_supplement_keeps_wired_and_undecidable_entries() {
        for lock in [
            Some(npm_lock_resolving(&format!(
                "file:.socket/vendor/npm/{VENDORED_UUID}/left-pad-1.3.0/node_modules/left-pad"
            ))),
            None,
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let args = GlobalArgs {
                cwd: tmp.path().to_path_buf(),
                ..GlobalArgs::default()
            };
            let state = npm_ledger_with_lock(tmp.path(), lock.as_deref()).await;
            let out = vendored_ledger_supplement(
                &crate::commands::context::ProjectContext::new(&args),
                &[],
                &state,
            )
            .await;
            assert_eq!(
                out.packages
                    .iter()
                    .map(|p| p.purl.as_str())
                    .collect::<Vec<_>>(),
                vec!["pkg:npm/left-pad@1.3.0"],
                "lock={lock:?}"
            );
            assert!(out.unwired.is_empty(), "lock={lock:?}: {:?}", out.unwired);
        }
    }

    #[tokio::test]
    async fn corrupt_ledger_recovers_vendored_purls_from_committed_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        seed_manifest_entry(tmp.path(), "pkg:cargo/foo@1.0.0", VENDORED_UUID);
        seed_corrupt_ledger(tmp.path());
        std::fs::create_dir_all(
            tmp.path()
                .join(format!(".socket/vendor/cargo/{VENDORED_UUID}/foo-1.0.0")),
        )
        .unwrap();

        let out = supplement_in(tmp.path(), &[]).await;
        assert_eq!(
            out.iter().map(|p| p.purl.as_str()).collect::<Vec<_>>(),
            vec!["pkg:cargo/foo@1.0.0"],
            "a corrupt ledger must fall back to the committed artifact dirs, \
             not silently drop the vendored purls from the scan"
        );
    }

    #[tokio::test]
    async fn corrupt_ledger_fallback_decodes_qualified_manifest_keys() {
        // Manifest keys come API-encoded and possibly qualified; the
        // fabricated purl must be the decoded base form (what the crawler
        // and `scanned_purls` speak).
        let tmp = tempfile::tempdir().unwrap();
        seed_manifest_entry(
            tmp.path(),
            "pkg:npm/%40scope/pkg@1.0.0?artifact_id=x",
            VENDORED_UUID,
        );
        seed_corrupt_ledger(tmp.path());
        std::fs::create_dir_all(
            tmp.path()
                .join(format!(".socket/vendor/npm/{VENDORED_UUID}")),
        )
        .unwrap();

        let out = supplement_in(tmp.path(), &[]).await;
        assert_eq!(
            out.iter().map(|p| p.purl.as_str()).collect::<Vec<_>>(),
            vec!["pkg:npm/@scope/pkg@1.0.0"],
        );
    }

    #[tokio::test]
    async fn corrupt_ledger_fallback_skips_entries_without_artifact_dirs() {
        // A manifest entry with no live uuid dir has nothing committed
        // consuming it — it is NOT resurrected, so a genuinely-stale entry
        // stays prunable even while the ledger is corrupt.
        let tmp = tempfile::tempdir().unwrap();
        seed_manifest_entry(tmp.path(), "pkg:cargo/foo@1.0.0", VENDORED_UUID);
        seed_corrupt_ledger(tmp.path());

        assert!(supplement_in(tmp.path(), &[]).await.is_empty());
    }

    #[tokio::test]
    async fn corrupt_ledger_fallback_rejects_non_canonical_uuids() {
        // The manifest is a committed, tamper-able file: a uuid that is not
        // the exact canonical grammar must not drive any disk probe or
        // fabrication (same fail-closed rule as `vendor_uuid_dir_rel`).
        let tmp = tempfile::tempdir().unwrap();
        seed_manifest_entry(tmp.path(), "pkg:cargo/foo@1.0.0", "../../escape");
        seed_corrupt_ledger(tmp.path());
        // Seed the dir the traversal uuid actually resolves to if a bypassed
        // guard builds `.socket/vendor/cargo/../../escape` (-> `.socket/
        // escape`), so the probe finds an EXISTING dir and fabricates the
        // purl — plus the literal spelling for a bypass that keeps the uuid
        // as a lone path component.
        std::fs::create_dir_all(tmp.path().join(".socket/escape")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".socket/vendor/cargo/escape")).unwrap();

        assert!(supplement_in(tmp.path(), &[]).await.is_empty());
    }

    #[tokio::test]
    async fn missing_ledger_still_yields_no_supplement() {
        // A MISSING state.json is a deliberately-empty ledger (Ok path), not
        // corruption — the fallback must not fire and invent vendored
        // packages for a project that never vendored.
        let tmp = tempfile::tempdir().unwrap();
        seed_manifest_entry(tmp.path(), "pkg:cargo/foo@1.0.0", VENDORED_UUID);
        std::fs::create_dir_all(
            tmp.path()
                .join(format!(".socket/vendor/cargo/{VENDORED_UUID}")),
        )
        .unwrap();

        assert!(supplement_in(tmp.path(), &[]).await.is_empty());
    }

    #[tokio::test]
    async fn corrupt_ledger_fallback_excludes_crawled_packages() {
        // Same exclusion the healthy-ledger path applies: an installed
        // (crawled) copy needs no fabricated supplement entry.
        let tmp = tempfile::tempdir().unwrap();
        seed_manifest_entry(tmp.path(), "pkg:cargo/foo@1.0.0", VENDORED_UUID);
        seed_corrupt_ledger(tmp.path());
        std::fs::create_dir_all(
            tmp.path()
                .join(format!(".socket/vendor/cargo/{VENDORED_UUID}")),
        )
        .unwrap();
        let crawled = vec![socket_patch_core::crawlers::types::CrawledPackage {
            name: "foo".to_string(),
            version: "1.0.0".to_string(),
            namespace: None,
            purl: "pkg:cargo/foo@1.0.0".to_string(),
            path: tmp.path().join("foo"),
        }];

        assert!(supplement_in(tmp.path(), &crawled).await.is_empty());
    }

    #[tokio::test]
    async fn corrupt_ledger_fallback_recovers_manifest_free_vendored_purls_from_leaves() {
        // Manifest-free vendored project (the `scan --mode vendored` posture:
        // records live in the ledger alone) with a corrupt ledger: the
        // committed artifact leaves are the only ground truth left, and the
        // documented leaf grammar recovers the purl. Non-uuid dirs and
        // unparsable leaves stay out.
        let tmp = tempfile::tempdir().unwrap();
        seed_corrupt_ledger(tmp.path());
        let uuid_dir = tmp
            .path()
            .join(format!(".socket/vendor/npm/{VENDORED_UUID}"));
        std::fs::create_dir_all(&uuid_dir).unwrap();
        std::fs::write(uuid_dir.join("left-pad-1.3.0.tgz"), b"tgz").unwrap();
        std::fs::create_dir_all(tmp.path().join(".socket/vendor/npm/not-a-uuid")).unwrap();
        std::fs::write(
            tmp.path()
                .join(".socket/vendor/npm/not-a-uuid/ghost-9.9.9.tgz"),
            b"tgz",
        )
        .unwrap();

        let out = supplement_in(tmp.path(), &[]).await;
        assert_eq!(
            out.iter().map(|p| p.purl.as_str()).collect::<Vec<_>>(),
            vec!["pkg:npm/left-pad@1.3.0"],
            "a manifest-free vendored project must recover its purls from the \
             committed leaves when the ledger is unreadable"
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

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    fn patch_with(uuid: &str, cves: &[&str], ghsas: &[&str]) -> BatchPatchInfo {
        BatchPatchInfo {
            uuid: uuid.to_string(),
            purl: "pkg:npm/foo@1.0".to_string(),
            tier: "free".to_string(),
            cve_ids: strs(cves),
            ghsa_ids: strs(ghsas),
            severity: None,
            title: String::new(),
            published_at: None,
        }
    }

    #[test]
    fn collect_vuln_ids_empty_when_no_vulns() {
        let pkg = batch_with_vulns("pkg:npm/foo@1.0", &[], &[]);
        assert_eq!(collect_vuln_ids(&pkg), VulnIds::default());
    }

    #[test]
    fn collect_vuln_ids_lists_cves_before_ghsas_each_sorted() {
        // Deliberately unsorted input; output must be CVEs (sorted) then
        // GHSAs (sorted) so the rendered table column is deterministic.
        let pkg = batch_with_vulns(
            "pkg:npm/foo@1.0",
            &["CVE-2024-2", "CVE-2024-1"],
            &[
                "GHSA-zzzz-zzzz-zzzz",
                "GHSA-aaaa-aaaa-aaaa",
                "GHSA-mmmm-mmmm-mmmm",
            ],
        );
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(
            ids.all,
            strs(&[
                "CVE-2024-1",
                "CVE-2024-2",
                "GHSA-aaaa-aaaa-aaaa",
                "GHSA-mmmm-mmmm-mmmm",
                "GHSA-zzzz-zzzz-zzzz",
            ]),
        );
        // The GHSAs sit beside CVEs, so none is shown first; there are at
        // least three vulnerabilities (one GHSA has no CVE of its own).
        assert_eq!(ids.primary, strs(&["CVE-2024-1", "CVE-2024-2"]));
        assert_eq!(ids.count, 3);
    }

    #[test]
    fn collect_vuln_ids_drops_ghsa_aliases_of_listed_cves() {
        // minimist: one CVE and its GHSA alias are one vulnerability.
        let pkg = batch_with_vulns(
            "pkg:npm/minimist@1.2.5",
            &["CVE-2021-44906"],
            &["GHSA-xvch-5gv4-984h"],
        );
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(ids.primary, strs(&["CVE-2021-44906"]));
        assert_eq!(ids.all, strs(&["CVE-2021-44906", "GHSA-xvch-5gv4-984h"]));
        assert_eq!(ids.count, 1);
        // A GHSA-only advisory has no CVE to alias: it stays.
        let pkg = batch_with_vulns("pkg:npm/x@1", &[], &["GHSA-r4q5-vmmm-2653"]);
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(ids.primary, strs(&["GHSA-r4q5-vmmm-2653"]));
        assert_eq!(ids.count, 1);
    }

    #[test]
    fn collect_vuln_ids_one_cve_plus_alias_plus_ghsa_only() {
        // CVE-1 (alias GHSA-a) and a GHSA-only GHSA-b on one patch: two
        // vulnerabilities, not three.
        let pkg = batch_with_vulns("pkg:npm/foo@1.0", &["CVE-1"], &["GHSA-a", "GHSA-b"]);
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(ids.count, 2);
        assert_eq!(ids.primary, strs(&["CVE-1"]));
    }

    #[test]
    fn collect_vuln_ids_two_cves_one_ghsa_alias_plus_ghsa_only() {
        // GHSA-a aliases both CVEs, GHSA-b has none. The batch data cannot
        // tell this from two CVE/GHSA pairs, so the count is the lower
        // bound (2) and every id is still listed under --verbose.
        let pkg = batch_with_vulns(
            "pkg:npm/foo@1.0",
            &["CVE-1", "CVE-2"],
            &["GHSA-a", "GHSA-b"],
        );
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(ids.count, 2);
        assert_eq!(ids.all, strs(&["CVE-1", "CVE-2", "GHSA-a", "GHSA-b"]));
        // On its own patch, the GHSA-only advisory is known and shown.
        let pkg = BatchPackagePatches {
            purl: "pkg:npm/foo@1.0".to_string(),
            patches: vec![
                patch_with("u1", &["CVE-1", "CVE-2"], &["GHSA-a"]),
                patch_with("u2", &[], &["GHSA-b"]),
            ],
        };
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(ids.primary, strs(&["CVE-1", "CVE-2", "GHSA-b"]));
        assert_eq!(ids.count, 3);
    }

    #[test]
    fn collect_vuln_ids_ghsa_beside_a_cve_elsewhere_is_not_ghsa_only() {
        let pkg = BatchPackagePatches {
            purl: "pkg:npm/foo@1.0".to_string(),
            patches: vec![
                patch_with("u1", &["CVE-1"], &["GHSA-a"]),
                patch_with("u2", &[], &["GHSA-a"]),
            ],
        };
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(ids.primary, strs(&["CVE-1"]));
        assert_eq!(ids.count, 1);
    }

    // ---- unsupported_layout_warnings -----------------------------------

    #[test]
    fn unsupported_layout_warnings_forwards_unknown_codes_verbatim() {
        use socket_patch_core::vendor::lock_inventory::UnsupportedNpmLayout;

        // Forward-compat contract: a refusal code this match doesn't know
        // yet must surface verbatim — code AND the probe's own detail —
        // rather than being swallowed back into silence.
        let unknown = UnsupportedNpmLayout {
            code: "vendor_future_layout_unsupported",
            detail: "probe detail text".to_string(),
        };
        assert_eq!(
            unsupported_layout_warnings(std::slice::from_ref(&unknown)),
            vec![(
                "vendor_future_layout_unsupported".to_string(),
                "probe detail text".to_string(),
            )],
        );

        // Contrast: a KNOWN code is rewritten — renamed to apply's refusal
        // errorCode and scan-phrased, not the probe's vendor-phrased text.
        let known = UnsupportedNpmLayout {
            code: "vendor_yarn_berry_unsupported",
            detail: "probe detail text".to_string(),
        };
        let rewritten = unsupported_layout_warnings(std::slice::from_ref(&known));
        assert_eq!(rewritten.len(), 1);
        assert_eq!(rewritten[0].0, "yarn_pnp_unsupported");
        assert_ne!(rewritten[0].1, "probe detail text");
    }

    // ---- candidate_supersedes (advisory-count rung) -------------------------

    /// A batch-shaped patch with explicit advisory lists and NO publish
    /// date, so only the severity and advisory-count rungs can decide.
    fn info_with_advisories(
        uuid: &str,
        severity: Option<&str>,
        ghsas: &[&str],
        cves: &[&str],
    ) -> BatchPatchInfo {
        BatchPatchInfo {
            uuid: uuid.to_string(),
            purl: "pkg:npm/foo@1.0".to_string(),
            tier: "free".to_string(),
            cve_ids: cves.iter().map(|s| (*s).to_string()).collect(),
            ghsa_ids: ghsas.iter().map(|s| (*s).to_string()).collect(),
            severity: severity.map(str::to_string),
            title: String::new(),
            published_at: None,
        }
    }

    #[test]
    fn candidate_supersedes_on_broader_ghsa_merge_coverage() {
        // Same severity, no dates: only the advisory count separates them.
        // A merged patch (>= 2 GHSAs) genuinely supersedes a single one.
        let merged = info_with_advisories(
            "uuid-merged",
            Some("high"),
            &["GHSA-1111-1111-1111", "GHSA-2222-2222-2222"],
            &[],
        );
        let single =
            info_with_advisories("uuid-single", Some("high"), &["GHSA-3333-3333-3333"], &[]);
        assert!(
            candidate_supersedes(&merged, &single),
            "broader merge coverage is a genuine supersede"
        );
        // Swapped: fewer advisories at equal severity cannot supersede.
        assert!(
            !candidate_supersedes(&single, &merged),
            "narrower coverage must never supersede"
        );
    }

    #[test]
    fn a_more_severe_single_candidate_supersedes_a_lower_severity_merge() {
        // Same rule as selection: severity beats advisory count, so the
        // [UPDATE] marker names the patch scan would install.
        let merged = info_with_advisories(
            "uuid-merged",
            Some("low"),
            &["GHSA-1111-1111-1111", "GHSA-2222-2222-2222"],
            &[],
        );
        let critical =
            info_with_advisories("uuid-crit", Some("critical"), &["GHSA-3333-3333-3333"], &[]);
        assert!(!candidate_supersedes(&merged, &critical));
        assert!(candidate_supersedes(&critical, &merged));
    }

    #[test]
    fn a_larger_merge_supersedes_a_smaller_merge_at_equal_severity() {
        let smaller = info_with_advisories("small", Some("high"), &["GHSA-a", "GHSA-b"], &[]);
        let larger =
            info_with_advisories("large", Some("high"), &["GHSA-a", "GHSA-b", "GHSA-c"], &[]);
        assert!(candidate_supersedes(&larger, &smaller));
        assert!(!candidate_supersedes(&smaller, &larger));
    }

    #[test]
    fn candidate_supersedes_cve_aliases_do_not_inflate_ghsa_coverage() {
        // Both sides name a GHSA, so the CVE lists are aliases and must not
        // count: both unmerged, same severity, no dates -> not a supersede
        // in either direction (the date rung requires two REAL dates).
        let candidate = info_with_advisories(
            "uuid-cand",
            Some("high"),
            &["GHSA-xxxx-xxxx-xxxx"],
            &["CVE-2026-1", "CVE-2026-2"],
        );
        let applied = info_with_advisories(
            "uuid-appl",
            Some("high"),
            &["GHSA-yyyy-yyyy-yyyy"],
            &["CVE-2026-3"],
        );
        assert!(!candidate_supersedes(&candidate, &applied));
        assert!(!candidate_supersedes(&applied, &candidate));
    }

    #[test]
    fn detect_updates_flags_merged_patch_superseding_applied_single() {
        // End-to-end through detect_updates: the manifest holds the
        // single-advisory patch; the batch offers it alongside a merged
        // sibling (2 GHSAs, same severity, no dates). The merged patch wins
        // the ranking AND genuinely supersedes.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-single")]);
        let pkgs = vec![BatchPackagePatches {
            purl: "pkg:npm/foo@1.0".to_string(),
            patches: vec![
                info_with_advisories("uuid-single", Some("high"), &["GHSA-3333-3333-3333"], &[]),
                info_with_advisories(
                    "uuid-merged",
                    Some("high"),
                    &["GHSA-1111-1111-1111", "GHSA-2222-2222-2222"],
                    &[],
                ),
            ],
        }];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].old_uuid, "uuid-single");
        assert_eq!(updates[0].new_uuid, "uuid-merged");
    }

    // ---- preverify_vendor_baselines --------------------------------------
    // The HashMismatch positive path is covered end-to-end by
    // tests/scan_vendor_e2e.rs; these pin the three SKIP shapes: the two
    // pre-fetch skips (lockfile-only, no crawled counterpart) and the
    // per-file new-file skip after the fetch.

    fn search_result(uuid: &str, purl: &str) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.to_string(),
            purl: purl.to_string(),
            published_at: String::new(),
            description: String::new(),
            license: String::new(),
            tier: "free".to_string(),
            vulnerabilities: std::collections::HashMap::new(),
        }
    }

    fn crawled_pkg(
        name: &str,
        purl: &str,
        path: std::path::PathBuf,
    ) -> socket_patch_core::crawlers::types::CrawledPackage {
        socket_patch_core::crawlers::types::CrawledPackage {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            namespace: None,
            purl: purl.to_string(),
            path,
        }
    }

    fn api_client_for(uri: &str) -> socket_patch_core::api::client::ApiClient {
        socket_patch_core::api::client::ApiClient::new(
            socket_patch_core::api::client::ApiClientOptions {
                api_url: uri.to_string(),
                api_token: None,
                route: socket_patch_core::api::client::ApiRoute::Proxy,
            },
        )
    }

    #[tokio::test]
    async fn preverify_skips_lockfile_only_and_uncrawled_patches_without_fetching() {
        // A server with NO mounted mocks: any fetch would still degrade to
        // "skip" (404 -> Ok(None)), so the real assertion is the request
        // log — both skips fire BEFORE the detail fetch.
        let mock = wiremock::MockServer::start().await;
        let client = api_client_for(&mock.uri());

        let selected = vec![
            // (a) lockfile-only: no installed bytes to compare. The patch
            // purl is API-encoded; the lockfile-only set holds the
            // crawler's literal spelling — the normalize bridge must match
            // them.
            search_result("uuid-lockonly", "pkg:npm/%40scope/lockonly@1.0.0"),
            // (b) no crawled counterpart at all.
            search_result("uuid-ghost", "pkg:npm/ghost@1.0.0"),
        ];
        let crawled = vec![
            // The lockonly purl HAS a crawled counterpart (production's crawl
            // includes the fabricated lockfile-only entries), so the
            // lockfile-only guard is the deciding branch.
            crawled_pkg(
                "lockonly",
                "pkg:npm/@scope/lockonly@1.0.0",
                std::path::PathBuf::from("/nonexistent"),
            ),
            crawled_pkg(
                "other",
                "pkg:npm/other@1.0.0",
                std::path::PathBuf::from("/nonexistent"),
            ),
        ];
        let lockfile_only: HashSet<PurlKey> =
            std::iter::once(PurlKey::new("pkg:npm/@scope/lockonly@1.0.0")).collect();

        // A live status line: every step is shown, and the line is gone
        // once the check returns (nothing left over for the preview).
        let mut status = crate::ui::StatusLine::new(Vec::new(), true, true, 80);
        let (mismatched, views) = preverify_vendor_baselines(
            &client,
            &selected,
            &crawled,
            &lockfile_only,
            None,
            &mut status,
        )
        .await;
        let out = status.into_inner();
        let raw = String::from_utf8_lossy(&out);
        assert!(
            raw.contains("Checking installed files against patch baselines... (2/2)"),
            "{raw:?}"
        );
        assert!(
            crate::ui::test_support::render(&out).is_empty(),
            "the status line must be cleared: {raw:?}"
        );
        assert!(mismatched.is_empty());
        assert!(
            mock.received_requests().await.unwrap().is_empty(),
            "both skip shapes must decide before any detail fetch"
        );
        assert!(views.is_empty(), "nothing fetched, nothing cached");
    }

    /// Mount `GET /patch/view/<uuid>` (the public-proxy detail route) with
    /// the given `files` map; every other `PatchResponse` field is filler.
    async fn mount_patch_view(mock: &wiremock::MockServer, uuid: &str, files: serde_json::Value) {
        use wiremock::matchers::{method, path as wm_path};
        wiremock::Mock::given(method("GET"))
            .and(wm_path(format!("/patch/view/{uuid}")))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "uuid": uuid,
                    "purl": "pkg:npm/newfile@1.0.0",
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "files": files,
                    "vulnerabilities": {},
                    "description": "",
                    "license": "MIT",
                    "tier": "free",
                })),
            )
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn preverify_ignores_new_file_entries_with_no_baseline() {
        // A fetched detail file with NO beforeHash is a new file: there is
        // no baseline to compare, so it must not flag a mismatch — even
        // though nothing exists at its would-be path. (This is the live
        // wire shape: new-file patch entries omit beforeHash entirely.)
        let mock = wiremock::MockServer::start().await;
        mount_patch_view(
            &mock,
            "u3",
            serde_json::json!({
                "package/added.js": { "afterHash": "a".repeat(64) }
            }),
        )
        .await;
        let client = api_client_for(&mock.uri());

        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules/newfile");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let crawled = vec![crawled_pkg("newfile", "pkg:npm/newfile@1.0.0", pkg_dir)];
        let selected = vec![search_result("u3", "pkg:npm/newfile@1.0.0")];

        let (mismatched, views) = preverify_vendor_baselines(
            &client,
            &selected,
            &crawled,
            &HashSet::new(),
            None,
            &mut crate::ui::StatusLine::new(Vec::new(), false, false, 80),
        )
        .await;
        assert!(
            mismatched.is_empty(),
            "a new-file-only patch never annotates a baseline mismatch"
        );
        // Unlike the pre-fetch skips, this one DID fetch the detail — and
        // hands the view on so the download phase never fetches it again.
        assert_eq!(mock.received_requests().await.unwrap().len(), 1);
        assert_eq!(
            views.keys().collect::<Vec<_>>(),
            vec!["u3"],
            "the fetched view is cached by uuid"
        );
        assert_eq!(views["u3"].purl, "pkg:npm/newfile@1.0.0");
    }

    /// A view the server does not serve (404 → `Ok(None)`) is NOT cached:
    /// the download phase retries it and reports the miss per patch.
    #[tokio::test]
    async fn preverify_does_not_cache_a_missing_view() {
        let mock = wiremock::MockServer::start().await;
        let client = api_client_for(&mock.uri());
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules/newfile");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let crawled = vec![crawled_pkg("newfile", "pkg:npm/newfile@1.0.0", pkg_dir)];
        let selected = vec![search_result("u404", "pkg:npm/newfile@1.0.0")];

        let (mismatched, views) = preverify_vendor_baselines(
            &client,
            &selected,
            &crawled,
            &HashSet::new(),
            None,
            &mut crate::ui::StatusLine::new(Vec::new(), false, false, 80),
        )
        .await;
        assert!(mismatched.is_empty());
        assert_eq!(
            mock.received_requests().await.unwrap().len(),
            1,
            "it did try"
        );
        assert!(views.is_empty(), "a 404'd view must not be cached");
    }

    /// A Gradle version dir is checked through every hash-dir copy of the
    /// patched file: one copy off the baseline flags the patch, where the
    /// version dir itself (no files of its own) would only be NotFound.
    #[tokio::test]
    async fn preverify_checks_every_gradle_hash_dir_copy() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let leaf = "commons-text-1.10.0.jar";
        let before = compute_git_sha256_from_bytes(b"pristine jar");
        let mock = wiremock::MockServer::start().await;
        mount_patch_view(
            &mock,
            "u-gradle",
            serde_json::json!({
                leaf: { "beforeHash": before, "afterHash": "c".repeat(64) },
            }),
        )
        .await;
        let client = api_client_for(&mock.uri());

        let tmp = tempfile::tempdir().unwrap();
        let version_dir = tmp
            .path()
            .join("caches/modules-2/files-2.1/org.apache.commons/commons-text/1.10.0");
        for (hash, bytes) in [("0a1b", &b"pristine jar"[..]), ("ffee", b"other bytes")] {
            std::fs::create_dir_all(version_dir.join(hash)).unwrap();
            std::fs::write(version_dir.join(hash).join(leaf), bytes).unwrap();
        }
        let purl = "pkg:maven/org.apache.commons/commons-text@1.10.0";
        let crawled = vec![crawled_pkg("commons-text", purl, version_dir.clone())];
        let selected = vec![search_result("u-gradle", purl)];
        let run = |crawled: Vec<socket_patch_core::crawlers::types::CrawledPackage>| {
            let (client, selected) = (&client, &selected);
            async move {
                preverify_vendor_baselines(
                    client,
                    selected,
                    &crawled,
                    &HashSet::new(),
                    None,
                    &mut crate::ui::StatusLine::new(Vec::new(), false, false, 80),
                )
                .await
                .0
            }
        };
        assert_eq!(
            run(crawled).await,
            HashSet::from(["u-gradle".to_string()]),
            "the off-baseline hash-dir copy flags the patch"
        );

        std::fs::write(version_dir.join("ffee").join(leaf), b"pristine jar").unwrap();
        let crawled = vec![crawled_pkg("commons-text", purl, version_dir)];
        assert!(run(crawled).await.is_empty(), "every copy on the baseline");
    }

    #[tokio::test]
    async fn preverify_new_file_skip_is_per_file_not_per_patch() {
        // One patch, two files: a baseline-less new file AND a real
        // beforeHash entry whose installed bytes differ. The new-file skip
        // is a per-file `continue`, so the sibling mismatch must still
        // flag the patch uuid.
        let mock = wiremock::MockServer::start().await;
        mount_patch_view(
            &mock,
            "u4",
            serde_json::json!({
                "package/added.js": { "afterHash": "a".repeat(64) },
                "package/index.js": {
                    "beforeHash": "b".repeat(64),
                    "afterHash": "c".repeat(64),
                },
            }),
        )
        .await;
        let client = api_client_for(&mock.uri());

        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules/newfile");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        // Installed bytes hash to neither beforeHash nor afterHash.
        std::fs::write(pkg_dir.join("index.js"), b"installed bytes\n").unwrap();
        let crawled = vec![crawled_pkg("newfile", "pkg:npm/newfile@1.0.0", pkg_dir)];
        let selected = vec![search_result("u4", "pkg:npm/newfile@1.0.0")];

        let (mismatched, views) = preverify_vendor_baselines(
            &client,
            &selected,
            &crawled,
            &HashSet::new(),
            None,
            &mut crate::ui::StatusLine::new(Vec::new(), false, false, 80),
        )
        .await;
        assert_eq!(
            mismatched,
            std::iter::once("u4".to_string()).collect::<HashSet<_>>(),
            "the new-file skip must not swallow a sibling file's mismatch"
        );
        assert!(views.contains_key("u4"), "a mismatched view is cached too");
    }

    /// A purl the ledger already holds DETACHED at the selected uuid with an
    /// embedded record is judged from that record — no view fetch, nothing
    /// cached (the download phase reuses the record itself) — while a
    /// stale-uuid or legacy non-detached entry still fetches like an unknown
    /// purl. The no-fetch set is exactly the download phase's
    /// `already vendored` skip set.
    #[tokio::test]
    async fn preverify_reads_an_in_sync_detached_entrys_embedded_record_without_fetching() {
        use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};
        use socket_patch_core::vendor::state::VendorArtifact;
        use socket_patch_core::vendor::VendorEntry;

        let mock = wiremock::MockServer::start().await; // trap: no mounts
        let client = api_client_for(&mock.uri());
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("node_modules/insync");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        // Installed bytes hash to neither hash the record carries.
        std::fs::write(pkg_dir.join("index.js"), b"installed bytes\n").unwrap();
        let crawled = vec![crawled_pkg("insync", "pkg:npm/insync@1.0.0", pkg_dir)];
        let selected = vec![search_result("u5", "pkg:npm/insync@1.0.0")];

        let record = PatchRecord {
            uuid: "u5".into(),
            exported_at: "2026-01-01T00:00:00Z".into(),
            files: HashMap::from([(
                "index.js".to_string(),
                PatchFileInfo {
                    before_hash: "b".repeat(64),
                    after_hash: "c".repeat(64),
                },
            )]),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let entry = |uuid: &str, detached: bool| VendorEntry {
            detached,
            record: Some(record.clone()),
            ..VendorEntry::new(
                "npm".into(),
                "pkg:npm/insync@1.0.0".into(),
                uuid.into(),
                VendorArtifact {
                    yarn_berry10c0: None,
                    path: format!(".socket/vendor/npm/{uuid}/insync-1.0.0.tgz"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                Vec::new(),
            )
        };

        // In sync: judged from the record, zero fetches, nothing cached.
        let ledger = HashMap::from([("pkg:npm/insync@1.0.0".to_string(), entry("u5", true))]);
        let (mismatched, views) = preverify_vendor_baselines(
            &client,
            &selected,
            &crawled,
            &HashSet::new(),
            Some(&ledger),
            &mut crate::ui::StatusLine::new(Vec::new(), false, false, 80),
        )
        .await;
        assert_eq!(
            mismatched,
            std::iter::once("u5".to_string()).collect::<HashSet<_>>(),
            "the embedded record still drives the mismatch annotation"
        );
        assert!(
            mock.received_requests().await.unwrap().is_empty(),
            "an in-sync detached entry never fetches its view"
        );
        assert!(
            views.is_empty(),
            "the download phase reuses the record, not a view"
        );

        // Stale uuid, or a legacy non-detached entry: fetch like an unknown
        // purl — here against a trap server, so the patch is skipped and the
        // attempt is visible in the request log.
        for stale in [entry("u-old", true), entry("u5", false)] {
            let ledger = HashMap::from([("pkg:npm/insync@1.0.0".to_string(), stale)]);
            let before = mock.received_requests().await.unwrap().len();
            let (mismatched, _) = preverify_vendor_baselines(
                &client,
                &selected,
                &crawled,
                &HashSet::new(),
                Some(&ledger),
                &mut crate::ui::StatusLine::new(Vec::new(), false, false, 80),
            )
            .await;
            assert!(mismatched.is_empty());
            assert_eq!(
                mock.received_requests().await.unwrap().len(),
                before + 1,
                "a stale or legacy entry still fetches"
            );
        }
    }

    /// The baseline views are fetched concurrently, so every one must land
    /// on the patch that planned it. Over a `selected` list mixing all four
    /// plan outcomes — lockfile-only, uncrawled, an embedded ledger record
    /// and two fetched views — with the EARLIER view answering LAST, each
    /// package is compared against its own patch's files (a view that
    /// slipped by one would name a file that package does not have, and
    /// annotate nothing), the `views` map pairs each uuid with its own
    /// response, and only the two planned views are ever requested.
    #[tokio::test]
    async fn preverify_pairs_each_concurrent_view_with_its_own_patch() {
        use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};
        use socket_patch_core::vendor::state::VendorArtifact;
        use socket_patch_core::vendor::VendorEntry;
        use wiremock::matchers::{method, path as wm_path};

        let mock = wiremock::MockServer::start().await;
        // Each patch names a file only ITS OWN package has installed, so a
        // view taken by the wrong patch verifies a path that is not there.
        let view = |uuid: &str, file: &str, delay_ms: u64| {
            wiremock::Mock::given(method("GET"))
                .and(wm_path(format!("/patch/view/{uuid}")))
                .respond_with(
                    wiremock::ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({
                            "uuid": uuid,
                            "purl": "pkg:npm/ignored@1.0.0",
                            "publishedAt": "2026-01-01T00:00:00Z",
                            "files": { file: {
                                "beforeHash": "0".repeat(64),
                                "afterHash": "1".repeat(64),
                            }},
                            "vulnerabilities": {},
                            "description": "",
                            "license": "MIT",
                            "tier": "free",
                        }))
                        .set_delay(std::time::Duration::from_millis(delay_ms)),
                )
                .expect(1)
        };
        view("u-alpha", "alpha.js", 300).mount(&mock).await;
        view("u-beta", "beta.js", 0).mount(&mock).await;

        let tmp = tempfile::tempdir().unwrap();
        let installed = |name: &str, file: &str| {
            let dir = tmp.path().join("node_modules").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(file), b"installed bytes\n").unwrap();
            dir
        };
        let crawled = vec![
            crawled_pkg(
                "lockonly",
                "pkg:npm/lockonly@1.0.0",
                std::path::PathBuf::from("/nonexistent"),
            ),
            crawled_pkg(
                "alpha",
                "pkg:npm/alpha@1.0.0",
                installed("alpha", "alpha.js"),
            ),
            crawled_pkg(
                "embedded",
                "pkg:npm/embedded@1.0.0",
                installed("embedded", "embedded.js"),
            ),
            // `beta` is installed but WITHOUT the file its own patch names,
            // so only a view that slipped onto it could annotate it.
            crawled_pkg("beta", "pkg:npm/beta@1.0.0", installed("beta", "other.js")),
        ];
        let selected = vec![
            search_result("u-lockonly", "pkg:npm/lockonly@1.0.0"),
            search_result("u-alpha", "pkg:npm/alpha@1.0.0"),
            search_result("u-embedded", "pkg:npm/embedded@1.0.0"),
            search_result("u-ghost", "pkg:npm/ghost@1.0.0"),
            search_result("u-beta", "pkg:npm/beta@1.0.0"),
        ];
        let ledger = HashMap::from([(
            "pkg:npm/embedded@1.0.0".to_string(),
            VendorEntry {
                detached: true,
                record: Some(PatchRecord {
                    uuid: "u-embedded".into(),
                    exported_at: "2026-01-01T00:00:00Z".into(),
                    files: HashMap::from([(
                        "embedded.js".to_string(),
                        PatchFileInfo {
                            before_hash: "0".repeat(64),
                            after_hash: "1".repeat(64),
                        },
                    )]),
                    vulnerabilities: HashMap::new(),
                    description: String::new(),
                    license: "MIT".into(),
                    tier: "free".into(),
                }),
                ..VendorEntry::new(
                    "npm".into(),
                    "pkg:npm/embedded@1.0.0".into(),
                    "u-embedded".into(),
                    VendorArtifact {
                        yarn_berry10c0: None,
                        path: ".socket/vendor/npm/u-embedded/embedded-1.0.0.tgz".into(),
                        sha256: String::new(),
                        size: None,
                        platform_locked: None,
                        file_inventory: None,
                    },
                    Vec::new(),
                )
            },
        )]);

        let (mismatched, views) = preverify_vendor_baselines(
            &api_client_for(&mock.uri()),
            &selected,
            &crawled,
            &std::iter::once(PurlKey::new("pkg:npm/lockonly@1.0.0")).collect(),
            Some(&ledger),
            &mut crate::ui::StatusLine::new(Vec::new(), false, false, 80),
        )
        .await;

        let mut flagged: Vec<&String> = mismatched.iter().collect();
        flagged.sort();
        assert_eq!(flagged, vec!["u-alpha", "u-embedded"], "{mismatched:?}");
        let mut cached: Vec<(&String, &String)> =
            views.iter().map(|(uuid, v)| (uuid, &v.uuid)).collect();
        cached.sort();
        assert_eq!(
            cached,
            vec![
                (&"u-alpha".to_string(), &"u-alpha".to_string()),
                (&"u-beta".to_string(), &"u-beta".to_string()),
            ],
            "each cached view must be its own patch's"
        );
        // `.expect(1)` on both views is verified on drop: the skipped and
        // embedded patches never reached the network.
        assert_eq!(mock.received_requests().await.unwrap().len(), 2);
        drop(mock);
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
        // (u2's GHSA is the alias of its one CVE, so it is not counted.)
        let ids = collect_vuln_ids(&pkg);
        assert_eq!(ids.primary, vec!["CVE-2024-1".to_string()]);
        assert_eq!(ids.count, 1);
    }
}
