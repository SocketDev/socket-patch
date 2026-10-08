//! The per-run rollout stage (`docs/configuration.md#gradual-rollout`)
//! the disk scan and the in-memory engine share: classify the selected
//! offers against the recorded state, spend the budget on NEW packages
//! most critical first once each mode's eligibility checks ran, and
//! render the `rollout` block.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::api::ranking::{cmp_search_results, max_severity_order, search_result_supersedes};
use crate::api::types::PatchSearchResult;
use crate::crawlers::Ecosystem;
use crate::manifest::schema::PatchManifest;
pub use crate::policy::Offers;
use crate::utils::purl_key::PurlKey;

use super::{plan_rollout, severity_label, Candidate, MaxNew, MaxNewSource, Recorded, RolloutPlan};

/// The env binding of `scan --max-new-patches`.
pub const MAX_NEW_PATCHES_ENV: &str = "SOCKET_MAX_NEW_PATCHES";

/// What one invocation's project directories share: the cap as configured,
/// the budget left, and the base purls already admitted (admitted free in
/// later directories).
#[derive(Debug)]
pub struct Carry {
    pub configured: MaxNew,
    pub remaining: Option<u32>,
    pub admitted: BTreeSet<String>,
    /// The directory the project paths are relative to.
    pub root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RolloutCarry(pub Arc<Mutex<Carry>>);

impl RolloutCarry {
    pub fn new(configured: MaxNew, root: PathBuf) -> Self {
        RolloutCarry(Arc::new(Mutex::new(Carry {
            configured,
            remaining: configured.value,
            admitted: BTreeSet::new(),
            root,
        })))
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Carry> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Warning: a lookup failed for a package that could have been NEW, so a
/// capped run admitted no NEW patch.
pub const ROLLOUT_INCOMPLETE_LOOKUP: &str = "rollout_incomplete_lookup";
/// Warning: the reference lookup failed, but only for rows that were
/// deferred anyway, so the run went on.
pub const ROLLOUT_REFERENCE_FAILED: &str = "rollout_reference_failed";
/// `skipped[].reason` of a deferred row.
pub const ROLLOUT_DEFERRED: &str = "rollout_deferred";

/// Group the by-package records per purl into the step 5 → 7 seam (work
/// item A's [`Offers`]), dropping paid patches the org cannot download, and
/// take the top-ranked offer per purl.
pub fn offers_from_results(results: &[PatchSearchResult], can_access_paid: bool) -> Offers {
    let mut unfiltered: BTreeMap<String, Vec<PatchSearchResult>> = BTreeMap::new();
    for p in results {
        if can_access_paid || p.tier == "free" {
            unfiltered
                .entry(p.purl.clone())
                .or_default()
                .push(p.clone());
        }
    }
    for group in unfiltered.values_mut() {
        group.sort_by(cmp_search_results);
        group.dedup_by(|a, b| a.uuid == b.uuid);
    }
    let selected = unfiltered
        .iter()
        .filter_map(|(purl, group)| group.first().map(|p| (purl.clone(), p.clone())))
        .collect();
    Offers {
        unfiltered,
        selected,
    }
}

/// One classified row plus the offer its writer receives: the selection,
/// or the recorded patch when the selection does not supersede it.
#[derive(Debug, Clone)]
pub struct Row {
    pub candidate: Candidate,
    pub writer: PatchSearchResult,
}

/// The recorded view (§5.1), indexed once so every row is an O(1) lookup:
/// the merged manifest (manifest > hosted pins > vendor ledger) plus every
/// hosted pin (the merge keeps one per key; a project can pin each
/// qualifier twin of a package to its own patch).
#[derive(Debug, Default)]
pub struct RecordedIndex {
    exact: HashMap<String, Vec<String>>,
    /// [`PurlKey::qualified`]: one release variant in any spelling.
    qualified: HashMap<PurlKey, Vec<String>>,
    by_base: HashMap<PurlKey, Vec<String>>,
}

/// The recorded view one project root classifies against: the merged
/// manifest (`updates[]`'s batch fallback reads it) and its index.
pub struct RecordedState<'a> {
    pub manifest: Option<&'a PatchManifest>,
    pub index: RecordedIndex,
}

impl RecordedIndex {
    pub fn new(manifest: Option<&PatchManifest>, pins: &[(String, String)]) -> Self {
        let mut index = RecordedIndex::default();
        let entries = manifest
            .into_iter()
            .flat_map(|m| m.patches.iter().map(|(k, r)| (k.as_str(), r.uuid.as_str())))
            .chain(pins.iter().map(|(p, u)| (p.as_str(), u.as_str())));
        for (key, uuid) in entries {
            index
                .exact
                .entry(key.to_string())
                .or_default()
                .push(uuid.to_string());
            index
                .qualified
                .entry(PurlKey::qualified(key))
                .or_default()
                .push(uuid.to_string());
            index
                .by_base
                .entry(PurlKey::new(key))
                .or_default()
                .push(uuid.to_string());
        }
        for list in index
            .exact
            .values_mut()
            .chain(index.qualified.values_mut())
            .chain(index.by_base.values_mut())
        {
            list.sort();
            list.dedup();
        }
        index
    }

    /// The uuids recorded for `purl`, sorted: the exact key, else the same
    /// purl in another spelling, else any qualifier twin.
    pub fn uuids(&self, purl: &str) -> &[String] {
        self.exact
            .get(purl)
            .or_else(|| self.qualified.get(&PurlKey::qualified(purl)))
            .or_else(|| self.by_base.get(&PurlKey::new(purl)))
            .map_or(&[], Vec::as_slice)
    }

    /// Whether any patch is recorded for `purl`'s base purl.
    pub fn records_package(&self, purl: &str) -> bool {
        self.by_base.contains_key(&PurlKey::new(purl))
    }
}

/// Classify every selected purl of one project root (§5.1). `recorded` is
/// the merged view (manifest > hosted pins > vendor ledger).
pub fn classify(offers: &Offers, recorded: &RecordedIndex, project: &str) -> Vec<Row> {
    offers
        .selected
        .iter()
        .map(|(purl, selected)| {
            let uuids = recorded.uuids(purl);
            let offered = offers
                .unfiltered
                .get(purl)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let (class, writer) = if uuids.is_empty() {
                (Recorded::None, selected.clone())
            } else if uuids.contains(&selected.uuid) {
                (Recorded::Same, selected.clone())
            } else {
                let old = uuids[0].clone();
                match offered.iter().find(|p| p.uuid == old) {
                    Some(prior) if !search_result_supersedes(selected, prior) => {
                        (Recorded::Kept { uuid: old }, prior.clone())
                    }
                    _ => (Recorded::Superseded { old_uuid: old }, selected.clone()),
                }
            };
            Row {
                candidate: Candidate {
                    project: project.to_string(),
                    purl: purl.clone(),
                    base_purl: PurlKey::new(purl).into_string(),
                    uuid: selected.uuid.clone(),
                    ecosystem: Ecosystem::from_purl(purl).map_or("", |e| e.cli_name()),
                    severity_order: max_severity_order(
                        selected
                            .vulnerabilities
                            .values()
                            .map(|v| v.severity.as_str()),
                    ),
                    advisory_count: selected.vulnerabilities.len(),
                    recorded: class,
                    eligible: true,
                    in_flight: false,
                },
                writer,
            }
        })
        .collect()
}

/// Whether a failed detail lookup hit a package that could have been NEW
/// (nothing recorded for it), or a whole batch failed (its packages are
/// unknown).
pub fn lookup_incomplete(
    recorded: &RecordedIndex,
    failed_details: &[String],
    batch_failed: bool,
) -> bool {
    batch_failed
        || failed_details
            .iter()
            .any(|purl| !recorded.records_package(purl))
}

/// Re-classify NEW rows against the pins discovery finds
/// ([`HostedPin::discover`]): the selected uuid pinned is ALREADY, another
/// uuid pinned for the same package is an UPGRADE
/// ([`Recorded::Superseded`]). The recorded view is discovery over the
/// configured patch servers; a pin on the server THIS run's references name
/// (an origin missing from `--patch-server-url`) is only recognized once
/// those references are known, so the caller re-runs discovery with their
/// origins ([`dep_origins`]) and hands the pins here. Without it such a pin
/// would read as NEW on every run and hold its slot forever, and an upgrade
/// on that server would spend a NEW slot. Only discovery's attributable pins
/// count: a uuid a stale or inactive file merely mentions (an unused
/// `pdm.lock`, a `package.json` `resolutions` leftover, a comment) pins
/// nothing and stays NEW.
///
/// The writers were already chosen from the selection, so a pinned uuid
/// that the selection does not supersede is reported as an UPGRADE rather
/// than kept ([`Recorded::Kept`]): what is written does not change, only
/// that it spends no NEW slot.
///
/// [`HostedPin::discover`]: crate::patch::redirect::upstream::HostedPin::discover
/// [`dep_origins`]: crate::patch::redirect::upstream::dep_origins
pub fn mark_pinned(rows: &mut [Row], pins: &[crate::patch::redirect::upstream::HostedPin]) {
    let pairs: Vec<(String, String)> = pins
        .iter()
        .map(|p| (p.purl.clone(), p.uuid.to_ascii_lowercase()))
        .collect();
    let index = RecordedIndex::new(None, &pairs);
    for row in rows.iter_mut().filter(|r| r.candidate.recorded.is_new()) {
        let uuids = index.uuids(&row.candidate.purl);
        let selected = row.candidate.uuid.to_ascii_lowercase();
        if uuids.contains(&selected) {
            row.candidate.recorded = Recorded::Same;
        } else if let Some(old) = uuids.first() {
            row.candidate.recorded = Recorded::Superseded {
                old_uuid: old.clone(),
            };
        }
    }
}

/// Whether any row is NEW (only then can [`mark_pinned`] change anything).
pub fn any_new(rows: &[Row]) -> bool {
    rows.iter().any(|r| r.candidate.recorded.is_new())
}

/// One directory's budget and the outcome of its plan.
#[derive(Debug, Clone)]
pub struct Stage {
    /// The cap as configured (reported).
    pub configured: MaxNew,
    /// The budget this directory may spend (the carried remainder).
    pub budget: MaxNew,
    pub already_admitted: BTreeSet<String>,
    /// A lookup failed for a package that could have been NEW.
    pub incomplete: bool,
    pub project: String,
    pub carry: Option<RolloutCarry>,
    /// Set by [`Self::plan`].
    pub plan: Option<RolloutPlan>,
    /// The reference lookup failed and only deferred rows were affected.
    pub reference_failed: Option<String>,
}

impl Stage {
    /// The stage for one scan of `cwd`: a fresh budget, or the invocation's
    /// shared one.
    pub fn new(configured: MaxNew, carry: Option<RolloutCarry>, cwd: &Path) -> Self {
        let (budget, already_admitted, project) = match &carry {
            Some(c) => {
                let c = c.lock();
                (
                    MaxNew {
                        value: c.remaining,
                        source: c.configured.source,
                    },
                    c.admitted.clone(),
                    crate::policy::repo_relative(
                        &c.root,
                        &std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf()),
                    ),
                )
            }
            None => (configured, BTreeSet::new(), String::new()),
        };
        Stage {
            configured,
            budget,
            already_admitted,
            incomplete: false,
            project,
            carry,
            plan: None,
            reference_failed: None,
        }
    }

    pub fn capped(&self) -> bool {
        self.configured.value.is_some()
    }

    /// Whether any NEW row can be admitted at all.
    pub fn may_admit_new(&self) -> bool {
        !(self.capped() && self.incomplete) && self.budget.value != Some(0)
    }

    /// Plan `rows` with `eligible` deciding each NEW row, record the plan
    /// and hand the remaining budget to the next directory.
    pub fn plan(&mut self, rows: &[Row], eligible: impl Fn(&Row) -> bool) -> &RolloutPlan {
        let candidates: Vec<Candidate> = rows
            .iter()
            .map(|row| Candidate {
                eligible: !row.candidate.recorded.is_new() || eligible(row),
                ..row.candidate.clone()
            })
            .collect();
        let plan = plan_rollout(
            candidates,
            &self.budget,
            self.incomplete,
            &self.already_admitted,
        );
        if let Some(carry) = &self.carry {
            let mut c = carry.lock();
            c.remaining = plan.remaining;
            c.admitted = plan.admitted_base_purls.clone();
        }
        self.plan.insert(plan)
    }

    /// `(purl, uuid)` of every deferred row.
    pub fn deferred_keys(&self) -> HashSet<(String, String)> {
        self.plan
            .iter()
            .flat_map(|p| &p.deferred)
            .map(|(c, _)| (c.purl.clone(), c.uuid.clone()))
            .collect()
    }

    /// Run-level warnings the plan earned.
    pub fn warnings(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        if let Some(detail) = &self.reference_failed {
            out.push((
                ROLLOUT_REFERENCE_FAILED,
                format!(
                    "the hosted reference lookup failed ({detail}); only new patches were \
                     affected and they were deferred to the next scan"
                ),
            ));
        }
        let deferred = self.plan.as_ref().map_or(0, |p| p.counts.deferred);
        if self.capped() && self.incomplete && deferred > 0 {
            out.push((
                ROLLOUT_INCOMPLETE_LOOKUP,
                format!(
                    "a patch lookup failed for a package that could get its first patch, so \
                     no new patches were added this run ({} deferred) and none can take the \
                     missing package's place; re-run once the API answers",
                    if deferred == 1 {
                        "1 package".to_string()
                    } else {
                        format!("{deferred} packages")
                    }
                ),
            ));
        }
        out
    }

    /// The top-level `rollout` block (§5.5).
    pub fn json(&self) -> serde_json::Value {
        rollout_json(&self.configured, self.plan.as_ref())
    }

    /// `redirect.skipped[]` entries mirroring the deferred rows.
    pub fn deferred_skips(&self) -> Vec<crate::hosted::engine::SkippedPatch> {
        self.plan
            .iter()
            .flat_map(|p| &p.deferred)
            .map(|(c, rank)| crate::hosted::engine::SkippedPatch {
                purl: c.purl.clone(),
                uuid: c.uuid.clone(),
                reason: ROLLOUT_DEFERRED.to_string(),
                detail: Some(format!(
                    "rank {rank} in the rollout queue; a later scan adds it"
                )),
            })
            .collect()
    }
}

pub fn source_label(max: &MaxNew) -> &'static str {
    match max.source {
        MaxNewSource::Flag => "--max-new-patches",
        MaxNewSource::Env => MAX_NEW_PATCHES_ENV,
        MaxNewSource::File => "socket.yml",
        MaxNewSource::Cap => "the server cap",
        MaxNewSource::Default => "default",
    }
}

/// One deferred package, grouped over its rows.
pub struct DeferredGroup {
    pub base_purl: String,
    pub uuids: BTreeSet<String>,
    pub severity_order: u8,
    pub advisory_count: usize,
    pub projects: BTreeSet<String>,
    pub rank: u32,
}

pub fn deferred_groups(plan: &RolloutPlan) -> Vec<DeferredGroup> {
    let mut groups: Vec<DeferredGroup> = Vec::new();
    let mut at: HashMap<&str, usize> = HashMap::new();
    for (c, rank) in &plan.deferred {
        match at.get(c.base_purl.as_str()).map(|&i| &mut groups[i]) {
            Some(g) => {
                g.uuids.insert(c.uuid.clone());
                g.projects.insert(c.project.clone());
                g.severity_order = g.severity_order.min(c.severity_order);
                g.advisory_count = g.advisory_count.max(c.advisory_count);
            }
            None => {
                at.insert(c.base_purl.as_str(), groups.len());
                groups.push(DeferredGroup {
                    base_purl: c.base_purl.clone(),
                    uuids: BTreeSet::from([c.uuid.clone()]),
                    severity_order: c.severity_order,
                    advisory_count: c.advisory_count,
                    projects: BTreeSet::from([c.project.clone()]),
                    rank: *rank,
                })
            }
        }
    }
    groups.sort_by_key(|g| g.rank);
    groups
}

/// The `rollout` block. `plan: None` (a run that planned nothing) reports
/// zero counts.
pub fn rollout_json(configured: &MaxNew, plan: Option<&RolloutPlan>) -> serde_json::Value {
    let counts = plan.map(|p| p.counts).unwrap_or_default();
    let deferred: Vec<serde_json::Value> = plan
        .map(deferred_groups)
        .unwrap_or_default()
        .into_iter()
        .map(|g| {
            serde_json::json!({
                "purl": g.base_purl,
                "uuids": g.uuids,
                "severity": severity_label(g.severity_order),
                "advisoryCount": g.advisory_count,
                "projects": g.projects,
                "rank": g.rank,
            })
        })
        .collect();
    serde_json::json!({
        "maxNewPatches": {
            "value": configured.value,
            "source": configured.source.as_str(),
        },
        "counts": {
            "new": counts.new,
            "deferred": counts.deferred,
            "upgrade": counts.upgrade,
            "already": counts.already,
        },
        "deferred": deferred,
    })
}
