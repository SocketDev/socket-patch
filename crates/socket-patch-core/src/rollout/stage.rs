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
use crate::vex::UnlockedPin;

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
    /// Lockless hosted pins ([`UnlockedPin`]), each with its uuid as a
    /// one-element list: they route every satisfying version of a package,
    /// so they are matched per purl rather than indexed by key.
    unlocked: Vec<(UnlockedPin, Vec<String>)>,
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

    /// Also count discovery's lockless pins (a cargo `registry =` or nuget
    /// source-mapping pin with no lockfile) as recorded. They are the
    /// hosted rewriter's own output for a lockless project but never refs,
    /// so without them a re-scan would read the pin it wrote as NEW and
    /// spend a `--max-new-patches` slot on it every run.
    pub fn with_unlocked_pins(mut self, pins: impl IntoIterator<Item = UnlockedPin>) -> Self {
        self.unlocked.extend(pins.into_iter().map(|pin| {
            let uuid = vec![pin.uuid.clone()];
            (pin, uuid)
        }));
        self
    }

    /// The uuids recorded for `purl`, sorted: the exact key, else the same
    /// purl in another spelling, else any qualifier twin, else the uuid of a
    /// lockless pin that routes it.
    pub fn uuids(&self, purl: &str) -> &[String] {
        self.exact
            .get(purl)
            .or_else(|| self.qualified.get(&PurlKey::qualified(purl)))
            .or_else(|| self.by_base.get(&PurlKey::new(purl)))
            .or_else(|| self.unlocked_uuid(purl))
            .map_or(&[], Vec::as_slice)
    }

    fn unlocked_uuid(&self, purl: &str) -> Option<&Vec<String>> {
        self.unlocked
            .iter()
            .find(|(pin, _)| pin.routes(purl))
            .map(|(_, uuid)| uuid)
    }

    /// Whether any patch is recorded for `purl`'s base purl.
    pub fn records_package(&self, purl: &str) -> bool {
        self.by_base.contains_key(&PurlKey::new(purl)) || self.unlocked_uuid(purl).is_some()
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

    /// Whether a NEW row of `purl` could be admitted: budget left, or its
    /// package already admitted by an earlier directory.
    pub fn may_admit(&self, purl: &str) -> bool {
        self.may_admit_new()
            || (!(self.capped() && self.incomplete)
                && self
                    .already_admitted
                    .contains(&PurlKey::new(purl).into_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::VulnerabilityResponse;
    use crate::manifest::schema::PatchRecord;
    use crate::patch::redirect::upstream::HostedPin;

    fn offer(purl: &str, uuid: &str, published: &str, severities: &[&str]) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.to_string(),
            purl: purl.to_string(),
            published_at: published.to_string(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
            vulnerabilities: severities
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    (
                        format!("GHSA-{uuid}-{i}"),
                        VulnerabilityResponse {
                            cves: Vec::new(),
                            summary: String::new(),
                            severity: (*s).to_string(),
                            description: String::new(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn manifest(entries: &[(&str, &str)]) -> PatchManifest {
        let mut m = PatchManifest::new();
        for (purl, uuid) in entries {
            m.patches.insert(
                (*purl).to_string(),
                PatchRecord {
                    uuid: (*uuid).to_string(),
                    exported_at: String::new(),
                    files: HashMap::new(),
                    vulnerabilities: HashMap::new(),
                    description: String::new(),
                    license: String::new(),
                    tier: String::new(),
                },
            );
        }
        m
    }

    #[test]
    fn offers_drop_inaccessible_paid_patches_and_pick_the_top_one() {
        let mut paid = offer("pkg:npm/a@1", "p", "2026-01-01T00:00:00Z", &["critical"]);
        paid.tier = "paid".into();
        let results = vec![
            offer("pkg:npm/a@1", "old", "2020-01-01T00:00:00Z", &["high"]),
            paid,
            offer("pkg:npm/a@1", "new", "2026-01-01T00:00:00Z", &["high"]),
        ];
        let free = offers_from_results(&results, false);
        assert_eq!(free.selected["pkg:npm/a@1"].uuid, "new");
        assert_eq!(free.unfiltered["pkg:npm/a@1"].len(), 2);
        let all = offers_from_results(&results, true);
        assert_eq!(all.selected["pkg:npm/a@1"].uuid, "p");
    }

    #[test]
    fn composer_version_spellings_upgrade_without_spending_the_new_patch_budget() {
        let stored = manifest(&[("pkg:composer/psr/log@3.0.2.0", "old")]);
        let recorded = RecordedIndex::new(Some(&stored), &[]);
        let offers = offers_from_results(
            &[offer(
                "pkg:composer/psr/log@v3.0.2",
                "new",
                "2026-02-01T00:00:00Z",
                &["high"],
            )],
            false,
        );
        let rows = classify(&offers, &recorded, "");
        let plan = crate::rollout::plan_rollout(
            rows.into_iter().map(|row| row.candidate).collect(),
            &MaxNew {
                value: Some(0),
                source: MaxNewSource::Flag,
            },
            false,
            &BTreeSet::new(),
        );
        assert_eq!(plan.counts.upgrade, 1);
        assert_eq!(plan.counts.new, 0);
        assert!(plan.deferred.is_empty());
        assert_eq!(plan.admitted.len(), 1);
    }

    #[test]
    fn recorded_matches_percent_encoding_and_qualifier_twins() {
        let results = vec![
            offer("pkg:npm/%40s/x@1", "e1", "", &["high"]),
            offer("pkg:pypi/w@1?artifact_id=b", "w2", "", &["high"]),
        ];
        let offers = offers_from_results(&results, true);
        let recorded = manifest(&[
            ("pkg:npm/@s/x@1", "e1"),
            ("pkg:pypi/w@1?artifact_id=a", "w1"),
        ]);
        let rows = classify(&offers, &RecordedIndex::new(Some(&recorded), &[]), "");
        assert_eq!(rows[0].candidate.recorded, Recorded::Same);
        // The twin's recorded uuid is not offered for this twin: the late
        // twin lands uncapped as an UPGRADE.
        assert_eq!(
            rows[1].candidate.recorded,
            Recorded::Superseded {
                old_uuid: "w1".into()
            }
        );
    }

    #[test]
    fn several_recorded_uuids_prefer_the_selected_one_else_the_smallest() {
        let results = vec![offer("pkg:pypi/w@1", "b", "", &["high"])];
        let offers = offers_from_results(&results, true);
        let recorded = manifest(&[
            ("pkg:pypi/w@1?artifact_id=1", "c"),
            ("pkg:pypi/w@1?artifact_id=2", "b"),
        ]);
        let rows = classify(&offers, &RecordedIndex::new(Some(&recorded), &[]), "");
        assert_eq!(rows[0].candidate.recorded, Recorded::Same);
        let recorded = manifest(&[
            ("pkg:pypi/w@1?artifact_id=1", "d"),
            ("pkg:pypi/w@1?artifact_id=2", "c"),
        ]);
        let rows = classify(&offers, &RecordedIndex::new(Some(&recorded), &[]), "");
        assert_eq!(
            rows[0].candidate.recorded,
            Recorded::Superseded {
                old_uuid: "c".into()
            }
        );
    }

    #[test]
    fn a_discovered_pin_of_the_selected_uuid_marks_the_row_already() {
        let results = vec![
            offer(
                "pkg:npm/a@1",
                "aaaaaaaa-1111-4111-8111-00000000000a",
                "",
                &["high"],
            ),
            offer(
                "pkg:npm/b@1",
                "bbbbbbbb-1111-4111-8111-00000000000b",
                "",
                &["high"],
            ),
        ];
        let offers = offers_from_results(&results, true);
        let mut rows = classify(&offers, &RecordedIndex::default(), "");
        mark_pinned(
            &mut rows,
            &[HostedPin {
                purl: "pkg:npm/a@1".into(),
                uuid: "aaaaaaaa-1111-4111-8111-00000000000a".into(),
                files: vec!["package-lock.json".into()],
            }],
        );
        assert_eq!(rows[0].candidate.recorded, Recorded::Same);
        assert_eq!(rows[1].candidate.recorded, Recorded::None);
    }

    #[test]
    fn a_discovered_pin_of_another_uuid_marks_the_row_an_upgrade() {
        // A pin on a patch server only this run's references name is found
        // by the second discovery pass: an older patch pinned there is an
        // UPGRADE, not a NEW row spending a cap slot.
        let results = vec![offer(
            "pkg:npm/a@1",
            "aaaaaaaa-1111-4111-8111-00000000000a",
            "",
            &["high"],
        )];
        let offers = offers_from_results(&results, true);
        let mut rows = classify(&offers, &RecordedIndex::default(), "");
        mark_pinned(
            &mut rows,
            &[HostedPin {
                purl: "pkg:npm/a@1".into(),
                uuid: "AAAAAAAA-2222-4222-8222-00000000000A".into(),
                files: vec!["package-lock.json".into()],
            }],
        );
        assert_eq!(
            rows[0].candidate.recorded,
            Recorded::Superseded {
                old_uuid: "aaaaaaaa-2222-4222-8222-00000000000a".into()
            }
        );
    }

    #[test]
    fn case_folded_pins_match_the_selection_spelling() {
        // Discovery keys a nuget pin by the lowercased name; the API and
        // the lockfile keep the original case.
        let results = vec![
            offer("pkg:nuget/Newtonsoft.Json@13.0.3", "a-sel", "", &["high"]),
            offer("pkg:nuget/Newtonsoft.Json@13.0.3", "z-pin", "", &["high"]),
        ];
        let offers = offers_from_results(&results, true);
        let index = RecordedIndex::new(
            None,
            &[("pkg:nuget/newtonsoft.json@13.0.3".into(), "z-pin".into())],
        );
        let rows = classify(&offers, &index, "");
        assert_eq!(
            rows[0].candidate.recorded,
            Recorded::Kept {
                uuid: "z-pin".into()
            },
            "an equal sibling never replaces the pinned patch"
        );
        assert_eq!(rows[0].writer.uuid, "z-pin");
    }

    #[test]
    fn both_pinned_qualifier_twins_are_already() {
        // Hosted pins are keyed by base purl; each twin carries its own
        // patch. Neither may read as an UPGRADE on a converged repo.
        let results = vec![
            offer(
                "pkg:pypi/foo@1.0?artifact_id=sdist",
                "u-sdist",
                "",
                &["high"],
            ),
            offer("pkg:pypi/foo@1.0?artifact_id=whl", "u-whl", "", &["high"]),
        ];
        let offers = offers_from_results(&results, true);
        let pins = vec![
            ("pkg:pypi/foo@1.0".to_string(), "u-sdist".to_string()),
            ("pkg:pypi/foo@1.0".to_string(), "u-whl".to_string()),
        ];
        let mut merged = PatchManifest::new();
        merged.patches.insert(
            "pkg:pypi/foo@1.0".into(),
            manifest(&[("x", "u-sdist")]).patches.remove("x").unwrap(),
        );
        let rows = classify(&offers, &RecordedIndex::new(Some(&merged), &pins), "");
        assert!(
            rows.iter().all(|r| r.candidate.recorded == Recorded::Same),
            "{rows:?}"
        );
    }

    #[test]
    fn lookup_incomplete_only_when_a_new_package_could_be_missing() {
        let index = RecordedIndex::new(Some(&manifest(&[("pkg:npm/rec@1", "u")])), &[]);
        assert!(!lookup_incomplete(&index, &[], false));
        assert!(
            lookup_incomplete(&index, &[], true),
            "a failed batch hides unknown packages"
        );
        assert!(
            !lookup_incomplete(&index, &["pkg:npm/rec@1".into()], false),
            "a recorded package's failed lookup cannot hide a NEW row"
        );
        assert!(lookup_incomplete(
            &index,
            &["pkg:npm/other@1".into()],
            false
        ));
    }

    #[test]
    fn incomplete_lookups_warn_only_when_they_deferred_something() {
        let results = vec![offer("pkg:npm/a@1", "ua", "", &["critical"])];
        let offers = offers_from_results(&results, true);
        let capped = MaxNew {
            value: Some(3),
            source: MaxNewSource::Flag,
        };
        let mut stage = Stage::new(capped, None, Path::new("/repo"));
        stage.incomplete = true;
        assert!(!stage.may_admit_new());
        stage.plan(&classify(&offers, &RecordedIndex::default(), ""), |_| true);
        let codes: Vec<&str> = stage.warnings().iter().map(|(c, _)| *c).collect();
        assert_eq!(codes, [ROLLOUT_INCOMPLETE_LOOKUP]);
        let mut unlimited = Stage::new(MaxNew::UNLIMITED, None, Path::new("/repo"));
        unlimited.incomplete = true;
        assert!(unlimited.may_admit_new());
        unlimited.plan(&classify(&offers, &RecordedIndex::default(), ""), |_| true);
        assert!(unlimited.warnings().is_empty());
    }

    /// A lockless NuGet / Cargo pin (the hosted rewriter's own
    /// output when the project has no lockfile) is never a discovery ref,
    /// so `HostedPin::all` drops it. Re-scanned under `--max-new-patches 1`
    /// it must read as ALREADY through the recorded view (as `scan` builds
    /// it), not as NEW: otherwise every re-scan spends the one slot on the
    /// pin it already wrote and the genuinely new patch is deferred forever.
    #[tokio::test]
    async fn a_rescanned_lockless_pin_is_already_not_new_under_a_cap() {
        const NUGET: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        const CARGO: &str = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
        const GRANT: &str = "cccccccc-3333-4333-8333-cccccccccccc";
        let tmp = tempfile::tempdir().unwrap();
        let nuget_key = format!("socket-patch-{NUGET}");
        std::fs::write(
            tmp.path().join("nuget.config"),
            format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
                 <add key=\"{nuget_key}\" value=\"https://patch.socket.dev/patch-registry/nuget/{GRANT}/{NUGET}/index.json\" />\n  \
                 </packageSources>\n  <packageSourceMapping>\n    <packageSource key=\"{nuget_key}\">\n      \
                 <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n  \
                 </packageSourceMapping>\n</configuration>\n"
            ),
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("Cargo.toml"),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                 serde = {{ version = \"1\", registry = \"socket-patch-{CARGO}\" }}\n"
            ),
        )
        .unwrap();
        std::fs::create_dir(tmp.path().join(".cargo")).unwrap();
        std::fs::write(
            tmp.path().join(".cargo/config.toml"),
            format!(
                "[registries.socket-patch-{CARGO}]\nindex = \
                 \"sparse+https://patch.socket.dev/patch-registry/cargo/{GRANT}/{CARGO}/index/\"\n"
            ),
        )
        .unwrap();
        let discovery = crate::vex::discover::discover_patched_refs(tmp.path()).await;
        assert_eq!(discovery.unlocked_pins.len(), 2, "{discovery:#?}");
        let pins: Vec<(String, String)> = HostedPin::all(&discovery)
            .into_iter()
            .map(|p| (p.purl, p.uuid))
            .collect();
        assert!(pins.is_empty(), "lockless pins are never refs: {pins:?}");

        let results = vec![
            offer("pkg:nuget/Newtonsoft.Json@13.0.3", NUGET, "", &["critical"]),
            offer("pkg:cargo/serde@1.0.200", CARGO, "", &["critical"]),
            offer("pkg:npm/fresh@1.0.0", "fresh", "", &["low"]),
        ];
        let offers = offers_from_results(&results, true);
        let index = RecordedIndex::new(None, &pins).with_unlocked_pins(discovery.unlocked_pins);
        let one = MaxNew {
            value: Some(1),
            source: MaxNewSource::Flag,
        };
        let mut stage = Stage::new(one, None, Path::new("/repo"));
        stage.plan(&classify(&offers, &index, ""), |_| true);
        let counts = &stage.json()["counts"];
        assert_eq!(counts["already"], 2, "{counts}");
        assert_eq!(counts["new"], 1, "{counts}");
        assert_eq!(counts["deferred"], 0, "{counts}");

        // A version outside the cargo pin's requirement is not routed by it.
        assert!(index.uuids("pkg:cargo/serde@2.0.0").is_empty());
        assert!(!index.records_package("pkg:cargo/serde@2.0.0"));
    }
}
