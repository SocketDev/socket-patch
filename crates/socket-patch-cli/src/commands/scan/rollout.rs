//! Scan's step-7 stage (`docs/design/staged-rollout.md` §5, §9.2):
//! classify the selected offers against the recorded state, let the
//! mode's planning pass decide eligibility, spend the per-run budget on
//! NEW packages most critical first, and report what was deferred.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use socket_patch_core::api::ranking::{
    cmp_search_results, max_severity_order, search_result_supersedes,
};
use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::rollout::{
    canonical_base_purl, plan_rollout, severity_label, Candidate, MaxNew, MaxNewSource, Recorded,
    RolloutPlan,
};
use socket_patch_core::utils::purl::normalize_purl;

use super::discovery::UpdateInfo;
use super::rollout_args::RolloutCarry;

/// Warning: a lookup failed for a package that could have been NEW, so a
/// capped run admitted no NEW patch.
pub(crate) const ROLLOUT_INCOMPLETE_LOOKUP: &str = "rollout_incomplete_lookup";
/// Warning: the reference lookup failed, but only for rows that were
/// deferred anyway, so the run went on.
pub(crate) const ROLLOUT_REFERENCE_FAILED: &str = "rollout_reference_failed";
/// `skipped[].reason` of a deferred row.
pub(crate) const ROLLOUT_DEFERRED: &str = "rollout_deferred";

/// The step 5 → 7 seam: every offer per purl, and the winner per purl.
///
/// Work item A owns the shared `policy::Offers`; until it lands the
/// severity floor does not exist, so `selected` is the top of `unfiltered`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Offers {
    /// purl → every accessible offer, best first.
    pub(crate) unfiltered: BTreeMap<String, Vec<PatchSearchResult>>,
    /// purl → the offer per-package ranking selects.
    pub(crate) selected: BTreeMap<String, PatchSearchResult>,
}

impl Offers {
    /// Group the by-package records per purl, dropping paid patches the
    /// org cannot download, and take the top-ranked one per purl.
    pub(crate) fn from_results(results: &[PatchSearchResult], can_access_paid: bool) -> Self {
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
}

/// One classified row plus the offer its writer receives: the selection,
/// or the recorded patch when the selection does not supersede it.
#[derive(Debug, Clone)]
pub(crate) struct Row {
    pub(crate) candidate: Candidate,
    pub(crate) writer: PatchSearchResult,
}

/// The uuids the recorded view holds for `purl`: exact key, else the same
/// purl up to percent-encoding, else any qualifier twin.
pub(crate) fn recorded_uuids(recorded: &PatchManifest, purl: &str) -> Vec<String> {
    if let Some(r) = recorded.patches.get(purl) {
        return vec![r.uuid.clone()];
    }
    let want = normalize_purl(purl);
    let mut same: Vec<String> = recorded
        .patches
        .iter()
        .filter(|(k, _)| normalize_purl(k) == want)
        .map(|(_, r)| r.uuid.clone())
        .collect();
    if same.is_empty() {
        let base = canonical_base_purl(purl);
        same = recorded
            .patches
            .iter()
            .filter(|(k, _)| canonical_base_purl(k) == base)
            .map(|(_, r)| r.uuid.clone())
            .collect();
    }
    same.sort();
    same.dedup();
    same
}

/// Classify every selected purl of one project root (§5.1). `recorded` is
/// the merged view (manifest > hosted pins > vendor ledger).
pub(crate) fn classify(
    offers: &Offers,
    recorded: Option<&PatchManifest>,
    project: &str,
) -> Vec<Row> {
    offers
        .selected
        .iter()
        .map(|(purl, selected)| {
            let uuids = recorded
                .map(|m| recorded_uuids(m, purl))
                .unwrap_or_default();
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
                    base_purl: canonical_base_purl(purl),
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

/// `updates[]`: the UPGRADE rows, reported under the batch package's purl
/// spelling when one names the same base purl (one entry per package).
pub(super) fn upgrades(rows: &[Row], package_purls: &[String]) -> Vec<UpdateInfo> {
    let by_base: BTreeMap<String, &String> = package_purls
        .iter()
        .map(|p| (canonical_base_purl(p), p))
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for row in rows {
        let Recorded::Superseded { old_uuid } = &row.candidate.recorded else {
            continue;
        };
        let purl = by_base
            .get(&row.candidate.base_purl)
            .map_or_else(|| row.candidate.purl.clone(), |p| (*p).clone());
        if seen.insert(purl.clone()) {
            out.push(UpdateInfo {
                purl,
                old_uuid: old_uuid.clone(),
                new_uuid: row.candidate.uuid.clone(),
            });
        }
    }
    out.sort_by(|a, b| a.purl.cmp(&b.purl));
    out
}

/// Whether a failed detail lookup hit a package that could have been NEW
/// (nothing recorded for it), or a whole batch failed (its packages are
/// unknown).
pub(crate) fn lookup_incomplete(
    recorded: Option<&PatchManifest>,
    failed_details: &[String],
    batch_failed: bool,
) -> bool {
    batch_failed
        || failed_details
            .iter()
            .any(|purl| recorded.is_none_or(|m| recorded_uuids(m, purl).is_empty()))
}

/// Mark NEW rows whose selected uuid the project's lockfile texts already
/// mention as ALREADY. A hosted pin on a patch server discovery does not
/// recognize (an origin missing from `--patch-server-url`) would otherwise
/// read as NEW on every run and hold its slot forever; patch uuids are
/// unique, so a mention is a pin.
pub(crate) fn mark_pinned(rows: &mut [Row], texts: &[&str]) {
    for row in rows.iter_mut().filter(|r| r.candidate.recorded.is_new()) {
        if texts
            .iter()
            .any(|t| t.contains(row.candidate.uuid.as_str()))
        {
            row.candidate.recorded = Recorded::Same;
        }
    }
}

/// The rows the hosted engine plans (§9.0 step 7 inside the engine, after
/// its eligibility checks) and the stage that records the plan.
pub(crate) struct Gate<'a> {
    pub(crate) stage: &'a mut Stage,
    pub(crate) rows: Vec<Row>,
}

impl Gate<'_> {
    /// Whether `(purl, uuid)` is a NEW row.
    pub(crate) fn is_new(&self, purl: &str, uuid: &str) -> bool {
        self.rows.iter().any(|r| {
            r.candidate.recorded.is_new() && r.writer.purl == purl && r.writer.uuid == uuid
        })
    }
}

/// `updates[]` for a run that fetched by-package records: the UPGRADE rows,
/// plus the batch-derived entries for packages the by-package lookup
/// returned no offer for (nothing was selected there to disagree with).
pub(super) fn merge_updates(
    rows: &[Row],
    offers: &Offers,
    package_purls: &[String],
    batch: Vec<UpdateInfo>,
) -> Vec<UpdateInfo> {
    let offered: BTreeSet<String> = offers
        .unfiltered
        .keys()
        .map(|p| canonical_base_purl(p))
        .collect();
    let mut out = upgrades(rows, package_purls);
    out.extend(
        batch
            .into_iter()
            .filter(|u| !offered.contains(&canonical_base_purl(&u.purl))),
    );
    out.sort_by(|a, b| a.purl.cmp(&b.purl));
    out.dedup_by(|a, b| a.purl == b.purl);
    out
}

/// Repo-relative `/`-separated path of `dir` under `root`; `""` for the
/// root itself.
pub(crate) fn project_rel(root: &Path, dir: &Path) -> String {
    let rel = dir.strip_prefix(root).unwrap_or(dir);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .filter(|s| s != ".")
        .collect::<Vec<_>>()
        .join("/")
}

/// One directory's budget and the outcome of its plan.
#[derive(Debug, Clone)]
pub(crate) struct Stage {
    /// The cap as configured (reported).
    pub(crate) configured: MaxNew,
    /// The budget this directory may spend (the carried remainder).
    pub(crate) budget: MaxNew,
    pub(crate) already_admitted: BTreeSet<String>,
    /// A lookup failed for a package that could have been NEW.
    pub(crate) incomplete: bool,
    pub(crate) project: String,
    pub(crate) carry: Option<RolloutCarry>,
    /// Set by [`Self::plan`].
    pub(crate) plan: Option<RolloutPlan>,
    /// The reference lookup failed and only deferred rows were affected.
    pub(crate) reference_failed: Option<String>,
}

impl Stage {
    /// The stage for one scan of `cwd`: a fresh budget, or the invocation's
    /// shared one.
    pub(crate) fn new(configured: MaxNew, carry: Option<RolloutCarry>, cwd: &Path) -> Self {
        let (budget, already_admitted, project) = match &carry {
            Some(c) => {
                let c = c.lock();
                (
                    MaxNew {
                        value: c.remaining,
                        source: c.configured.source,
                    },
                    c.admitted.clone(),
                    project_rel(
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

    pub(crate) fn capped(&self) -> bool {
        self.configured.value.is_some()
    }

    /// Whether any NEW row can be admitted at all.
    pub(crate) fn may_admit_new(&self) -> bool {
        !(self.capped() && self.incomplete) && self.budget.value != Some(0)
    }

    /// Plan `rows` with `eligible` deciding each NEW row, record the plan
    /// and hand the remaining budget to the next directory.
    pub(crate) fn plan(&mut self, rows: &[Row], eligible: impl Fn(&Row) -> bool) -> &RolloutPlan {
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
    pub(crate) fn deferred_keys(&self) -> HashSet<(String, String)> {
        self.plan
            .iter()
            .flat_map(|p| &p.deferred)
            .map(|(c, _)| (c.purl.clone(), c.uuid.clone()))
            .collect()
    }

    /// Run-level warnings the plan earned.
    pub(crate) fn warnings(&self) -> Vec<(&'static str, String)> {
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
                    crate::ui::plural(deferred as usize, "package", "packages")
                ),
            ));
        }
        out
    }

    /// The top-level `rollout` block (§5.5).
    pub(crate) fn json(&self) -> serde_json::Value {
        rollout_json(&self.configured, self.plan.as_ref())
    }

    /// `redirect.skipped[]` entries mirroring the deferred rows.
    pub(crate) fn deferred_skips(&self) -> Vec<serde_json::Value> {
        self.plan
            .iter()
            .flat_map(|p| &p.deferred)
            .map(|(c, rank)| {
                serde_json::json!({
                    "purl": c.purl,
                    "uuid": c.uuid,
                    "reason": ROLLOUT_DEFERRED,
                    "detail": format!("rank {rank} in the rollout queue; a later scan adds it"),
                })
            })
            .collect()
    }

    /// The human `Rollout:` line (only when a cap is set) and the
    /// Next-steps lines about deferred patches.
    pub(crate) fn human(&self, dry_run: bool) -> (Option<String>, Vec<String>) {
        let Some(plan) = self.plan.as_ref() else {
            return (None, Vec::new());
        };
        human_lines(&self.configured, plan, dry_run)
    }
}

fn source_label(max: &MaxNew) -> &'static str {
    match max.source {
        MaxNewSource::Flag => "--max-new-patches",
        MaxNewSource::Env => super::rollout_args::MAX_NEW_PATCHES_ENV,
        MaxNewSource::File => "socket.yml",
        MaxNewSource::Cap => "the server cap",
        MaxNewSource::Default => "default",
    }
}

/// One deferred package, grouped over its rows.
struct DeferredGroup {
    base_purl: String,
    uuids: BTreeSet<String>,
    severity_order: u8,
    advisory_count: usize,
    projects: BTreeSet<String>,
    rank: u32,
}

fn deferred_groups(plan: &RolloutPlan) -> Vec<DeferredGroup> {
    let mut groups: Vec<DeferredGroup> = Vec::new();
    for (c, rank) in &plan.deferred {
        match groups.iter_mut().find(|g| g.base_purl == c.base_purl) {
            Some(g) => {
                g.uuids.insert(c.uuid.clone());
                g.projects.insert(c.project.clone());
                g.severity_order = g.severity_order.min(c.severity_order);
                g.advisory_count = g.advisory_count.max(c.advisory_count);
            }
            None => groups.push(DeferredGroup {
                base_purl: c.base_purl.clone(),
                uuids: BTreeSet::from([c.uuid.clone()]),
                severity_order: c.severity_order,
                advisory_count: c.advisory_count,
                projects: BTreeSet::from([c.project.clone()]),
                rank: *rank,
            }),
        }
    }
    groups.sort_by_key(|g| g.rank);
    groups
}

/// The `rollout` block. `plan: None` (a run that planned nothing) reports
/// zero counts.
pub(crate) fn rollout_json(configured: &MaxNew, plan: Option<&RolloutPlan>) -> serde_json::Value {
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

/// `pkg:npm/@scope/x@1.0.0` → `@scope/x@1.0.0`.
fn short_name(base_purl: &str) -> &str {
    base_purl
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split_once('/'))
        .map_or(base_purl, |(_, name)| name)
}

pub(crate) fn human_lines(
    configured: &MaxNew,
    plan: &RolloutPlan,
    dry_run: bool,
) -> (Option<String>, Vec<String>) {
    let c = plan.counts;
    let line = configured.value.map(|cap| {
        let verb = if dry_run {
            "would be applied"
        } else {
            "applied"
        };
        format!(
            "Rollout: {} of {} {verb} (maxNewPatches={cap} from {}); {}, {} already applied.",
            c.new,
            crate::ui::plural((c.new + c.deferred) as usize, "new patch", "new patches"),
            source_label(configured),
            crate::ui::plural(c.upgrade as usize, "upgrade", "upgrades"),
            c.already,
        )
    });
    let groups = deferred_groups(plan);
    if groups.is_empty() {
        return (line, Vec::new());
    }
    let deferred = crate::ui::plural(groups.len(), "new patch", "new patches");
    let first = match configured.value {
        Some(0) => format!(
            "{deferred} deferred: maxNewPatches=0 adds no new patches; raise it (or pass \
             --max-new-patches) to add them."
        ),
        Some(cap) => format!(
            "{deferred} deferred; commit these changes and run scan again to apply the next {}.",
            (cap as usize).min(groups.len())
        ),
        None => format!("{deferred} deferred; run scan again once the patch API answers."),
    };
    let shown: Vec<String> = groups
        .iter()
        .take(3)
        .map(|g| {
            format!(
                "{} ({})",
                short_name(&g.base_purl),
                severity_label(g.severity_order)
            )
        })
        .collect();
    let more = if groups.len() > 3 { ", …" } else { "" };
    (
        line,
        vec![first, format!("Next up: {}{more}", shown.join(", "))],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::api::types::VulnerabilityResponse;
    use socket_patch_core::manifest::schema::PatchRecord;
    use std::collections::HashMap;

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

    fn classes(rows: &[Row]) -> Vec<(String, Recorded, String)> {
        rows.iter()
            .map(|r| {
                (
                    r.candidate.purl.clone(),
                    r.candidate.recorded.clone(),
                    r.writer.uuid.clone(),
                )
            })
            .collect()
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
        let free = Offers::from_results(&results, false);
        assert_eq!(free.selected["pkg:npm/a@1"].uuid, "new");
        assert_eq!(free.unfiltered["pkg:npm/a@1"].len(), 2);
        let all = Offers::from_results(&results, true);
        assert_eq!(all.selected["pkg:npm/a@1"].uuid, "p");
    }

    #[test]
    fn classification_rows() {
        let results = vec![
            // NEW
            offer("pkg:npm/new@1", "n1", "2026-01-01T00:00:00Z", &["high"]),
            // ALREADY: recorded == selected
            offer("pkg:npm/same@1", "s1", "2026-01-01T00:00:00Z", &["high"]),
            // UPGRADE: the selection is newer than the recorded patch
            offer("pkg:npm/up@1", "u-new", "2026-06-01T00:00:00Z", &["high"]),
            offer("pkg:npm/up@1", "u-old", "2026-01-01T00:00:00Z", &["high"]),
            // ALREADY (kept): the selection only wins on the uuid tiebreak
            offer("pkg:npm/tie@1", "a-sel", "", &["high"]),
            offer("pkg:npm/tie@1", "z-rec", "", &["high"]),
            // UPGRADE: the recorded uuid is no longer offered
            offer("pkg:npm/gone@1", "g2", "2026-01-01T00:00:00Z", &["low"]),
        ];
        let offers = Offers::from_results(&results, true);
        let recorded = manifest(&[
            ("pkg:npm/same@1", "s1"),
            ("pkg:npm/up@1", "u-old"),
            ("pkg:npm/tie@1", "z-rec"),
            ("pkg:npm/gone@1", "g1"),
        ]);
        let rows = classify(&offers, Some(&recorded), "");
        assert_eq!(
            classes(&rows),
            vec![
                (
                    "pkg:npm/gone@1".into(),
                    Recorded::Superseded {
                        old_uuid: "g1".into()
                    },
                    "g2".into()
                ),
                ("pkg:npm/new@1".into(), Recorded::None, "n1".into()),
                ("pkg:npm/same@1".into(), Recorded::Same, "s1".into()),
                (
                    "pkg:npm/tie@1".into(),
                    Recorded::Kept {
                        uuid: "z-rec".into()
                    },
                    "z-rec".into()
                ),
                (
                    "pkg:npm/up@1".into(),
                    Recorded::Superseded {
                        old_uuid: "u-old".into()
                    },
                    "u-new".into()
                ),
            ]
        );
        let updates = upgrades(&rows, &["pkg:npm/up@1".to_string()]);
        assert_eq!(
            updates
                .iter()
                .map(|u| (u.purl.as_str(), u.old_uuid.as_str(), u.new_uuid.as_str()))
                .collect::<Vec<_>>(),
            [
                ("pkg:npm/gone@1", "g1", "g2"),
                ("pkg:npm/up@1", "u-old", "u-new")
            ]
        );
    }

    #[test]
    fn recorded_matches_percent_encoding_and_qualifier_twins() {
        let results = vec![
            offer("pkg:npm/%40s/x@1", "e1", "", &["high"]),
            offer("pkg:pypi/w@1?artifact_id=b", "w2", "", &["high"]),
        ];
        let offers = Offers::from_results(&results, true);
        let recorded = manifest(&[
            ("pkg:npm/@s/x@1", "e1"),
            ("pkg:pypi/w@1?artifact_id=a", "w1"),
        ]);
        let rows = classify(&offers, Some(&recorded), "");
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
        let offers = Offers::from_results(&results, true);
        let recorded = manifest(&[
            ("pkg:pypi/w@1?artifact_id=1", "c"),
            ("pkg:pypi/w@1?artifact_id=2", "b"),
        ]);
        let rows = classify(&offers, Some(&recorded), "");
        assert_eq!(rows[0].candidate.recorded, Recorded::Same);
        let recorded = manifest(&[
            ("pkg:pypi/w@1?artifact_id=1", "d"),
            ("pkg:pypi/w@1?artifact_id=2", "c"),
        ]);
        let rows = classify(&offers, Some(&recorded), "");
        assert_eq!(
            rows[0].candidate.recorded,
            Recorded::Superseded {
                old_uuid: "c".into()
            }
        );
    }

    #[test]
    fn stage_carries_the_budget_and_renders_the_block() {
        let configured = MaxNew {
            value: Some(2),
            source: MaxNewSource::Flag,
        };
        let carry = RolloutCarry::new(configured, "/repo".into());
        let results = vec![
            offer("pkg:npm/a@1", "ua", "", &["critical"]),
            offer("pkg:npm/b@1", "ub", "", &["low"]),
        ];
        let offers = Offers::from_results(&results, true);
        let mut first = Stage::new(configured, Some(carry.clone()), Path::new("/repo/x"));
        assert_eq!(first.project, "x");
        let rows = classify(&offers, None, &first.project);
        first.plan(&rows, |_| true);
        assert_eq!(carry.lock().remaining, Some(0));
        let results = vec![
            offer("pkg:npm/a@1", "ua", "", &["critical"]),
            offer("pkg:npm/c@1", "uc", "", &["high"]),
        ];
        let offers = Offers::from_results(&results, true);
        let mut second = Stage::new(configured, Some(carry.clone()), Path::new("/repo/y"));
        let rows = classify(&offers, None, &second.project);
        second.plan(&rows, |_| true);
        let json = second.json();
        assert_eq!(
            json["maxNewPatches"],
            serde_json::json!({"value": 2, "source": "flag"})
        );
        assert_eq!(
            json["counts"],
            serde_json::json!({"new": 1, "deferred": 1, "upgrade": 0, "already": 0})
        );
        assert_eq!(
            json["deferred"],
            serde_json::json!([{
                "purl": "pkg:npm/c@1", "uuids": ["uc"], "severity": "high",
                "advisoryCount": 1, "projects": ["y"], "rank": 2
            }])
        );
        assert_eq!(
            second.deferred_skips(),
            vec![serde_json::json!({
                "purl": "pkg:npm/c@1", "uuid": "uc", "reason": "rollout_deferred",
                "detail": "rank 2 in the rollout queue; a later scan adds it"
            })]
        );
        let (line, next) = second.human(false);
        assert_eq!(
            line.as_deref(),
            Some(
                "Rollout: 1 of 2 new patches applied (maxNewPatches=2 from --max-new-patches); \
                 0 upgrades, 0 already applied."
            )
        );
        assert_eq!(
            next,
            [
                "1 new patch deferred; commit these changes and run scan again to apply the next 1.",
                "Next up: c@1 (high)"
            ]
        );
    }

    #[test]
    fn unlimited_runs_print_no_rollout_line() {
        let results = vec![offer("pkg:npm/a@1", "ua", "", &["critical"])];
        let offers = Offers::from_results(&results, true);
        let mut stage = Stage::new(MaxNew::UNLIMITED, None, Path::new("/repo"));
        let rows = classify(&offers, None, "");
        stage.plan(&rows, |_| true);
        assert_eq!(stage.human(false), (None, Vec::new()));
        assert_eq!(
            stage.json()["maxNewPatches"]["value"],
            serde_json::Value::Null
        );
        assert_eq!(stage.json()["counts"]["new"], 1);
    }

    #[test]
    fn a_zero_cap_says_how_to_add_the_deferred_patches() {
        let results: Vec<PatchSearchResult> = ["a", "b", "c", "d"]
            .iter()
            .map(|n| offer(&format!("pkg:npm/{n}@1"), n, "", &["high"]))
            .collect();
        let offers = Offers::from_results(&results, true);
        let zero = MaxNew {
            value: Some(0),
            source: MaxNewSource::File,
        };
        let mut stage = Stage::new(zero, None, Path::new("/repo"));
        let rows = classify(&offers, None, "");
        stage.plan(&rows, |_| true);
        let (line, next) = stage.human(true);
        assert_eq!(
            line.as_deref(),
            Some(
                "Rollout: 0 of 4 new patches would be applied (maxNewPatches=0 from socket.yml); \
                 0 upgrades, 0 already applied."
            )
        );
        assert!(
            next[0].starts_with("4 new patches deferred: maxNewPatches=0"),
            "{next:?}"
        );
        assert_eq!(next[1], "Next up: a@1 (high), b@1 (high), c@1 (high), …");
    }

    #[test]
    fn incomplete_lookups_warn_only_when_they_deferred_something() {
        let results = vec![offer("pkg:npm/a@1", "ua", "", &["critical"])];
        let offers = Offers::from_results(&results, true);
        let capped = MaxNew {
            value: Some(3),
            source: MaxNewSource::Flag,
        };
        let mut stage = Stage::new(capped, None, Path::new("/repo"));
        stage.incomplete = true;
        assert!(!stage.may_admit_new());
        stage.plan(&classify(&offers, None, ""), |_| true);
        let codes: Vec<&str> = stage.warnings().iter().map(|(c, _)| *c).collect();
        assert_eq!(codes, [ROLLOUT_INCOMPLETE_LOOKUP]);
        let mut unlimited = Stage::new(MaxNew::UNLIMITED, None, Path::new("/repo"));
        unlimited.incomplete = true;
        assert!(unlimited.may_admit_new());
        unlimited.plan(&classify(&offers, None, ""), |_| true);
        assert!(unlimited.warnings().is_empty());
    }

    #[test]
    fn project_paths_are_repo_relative() {
        assert_eq!(project_rel(Path::new("/r"), Path::new("/r")), "");
        assert_eq!(project_rel(Path::new("/r"), Path::new("/r/a/b")), "a/b");
    }
}
