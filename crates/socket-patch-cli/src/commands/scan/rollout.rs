//! Scan's step-7 stage (`docs/design/staged-rollout.md` §5, §9.2):
//! classify the selected offers against the recorded state, let the
//! mode's planning pass decide eligibility, spend the per-run budget on
//! NEW packages most critical first, and report what was deferred.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use socket_patch_core::api::ranking::{
    cmp_search_results, max_severity_order, search_result_supersedes,
};
use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::manifest::schema::PatchManifest;
pub(crate) use socket_patch_core::policy::Offers;
use socket_patch_core::rollout::{
    canonical_base_purl, plan_rollout, severity_label, Candidate, MaxNew, MaxNewSource, Recorded,
    RolloutPlan,
};

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

/// Group the by-package records per purl into the step 5 → 7 seam (work
/// item A's [`Offers`]), dropping paid patches the org cannot download, and
/// take the top-ranked offer per purl.
pub(crate) fn offers_from_results(results: &[PatchSearchResult], can_access_paid: bool) -> Offers {
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
pub(crate) struct Row {
    pub(crate) candidate: Candidate,
    pub(crate) writer: PatchSearchResult,
}

/// The recorded view (§5.1), indexed once so every row is an O(1) lookup:
/// the merged manifest (manifest > hosted pins > vendor ledger) plus every
/// hosted pin (the merge keeps one per key; a project can pin each
/// qualifier twin of a package to its own patch).
#[derive(Debug, Default)]
pub(crate) struct RecordedIndex {
    exact: HashMap<String, Vec<String>>,
    /// Discovery's folded base purl plus the raw qualifier suffix.
    qualified: HashMap<String, Vec<String>>,
    by_base: HashMap<String, Vec<String>>,
}

/// The recorded view one project root classifies against: the merged
/// manifest (`updates[]`'s batch fallback reads it) and its index.
pub(crate) struct RecordedState<'a> {
    pub(crate) manifest: Option<&'a PatchManifest>,
    pub(crate) index: RecordedIndex,
}

/// `purl`'s folded base plus its qualifiers: equal for two spellings of the
/// same qualified purl (percent-encoding, case where it does not matter).
fn qualified_key(purl: &str) -> String {
    let suffix = purl.find(['?', '#']).map_or("", |i| &purl[i..]);
    format!("{}{suffix}", canonical_base_purl(purl))
}

impl RecordedIndex {
    pub(crate) fn new(manifest: Option<&PatchManifest>, pins: &[(String, String)]) -> Self {
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
                .entry(qualified_key(key))
                .or_default()
                .push(uuid.to_string());
            index
                .by_base
                .entry(canonical_base_purl(key))
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
    pub(crate) fn uuids(&self, purl: &str) -> &[String] {
        self.exact
            .get(purl)
            .or_else(|| self.qualified.get(&qualified_key(purl)))
            .or_else(|| self.by_base.get(&canonical_base_purl(purl)))
            .map_or(&[], Vec::as_slice)
    }

    /// Whether any patch is recorded for `purl`'s base purl.
    fn records_package(&self, purl: &str) -> bool {
        self.by_base.contains_key(&canonical_base_purl(purl))
    }
}

/// Classify every selected purl of one project root (§5.1). `recorded` is
/// the merged view (manifest > hosted pins > vendor ledger).
pub(crate) fn classify(offers: &Offers, recorded: &RecordedIndex, project: &str) -> Vec<Row> {
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
    recorded: &RecordedIndex,
    failed_details: &[String],
    batch_failed: bool,
) -> bool {
    batch_failed
        || failed_details
            .iter()
            .any(|purl| !recorded.records_package(purl))
}

/// Every canonical-shaped uuid (`8-4-4-4-12` hex) `text` mentions,
/// lowercased, in one linear pass.
pub(crate) fn mentioned_uuids(text: &str, out: &mut HashSet<String>) {
    let bytes = text.as_bytes();
    if bytes.len() < 36 {
        return;
    }
    let mut i = 0;
    while i + 36 <= bytes.len() {
        let window = &bytes[i..i + 36];
        let shaped = window.iter().enumerate().all(|(k, b)| match k {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
        if shaped {
            out.insert(String::from_utf8_lossy(window).to_ascii_lowercase());
            i += 36;
        } else {
            i += 1;
        }
    }
}

/// Mark NEW rows whose selected uuid the project's lockfile texts already
/// mention as ALREADY. A hosted pin on a patch server discovery does not
/// recognize (an origin missing from `--patch-server-url`) would otherwise
/// read as NEW on every run and hold its slot forever; patch uuids are
/// unique, so a mention is a pin.
pub(crate) fn mark_pinned(rows: &mut [Row], texts: &[&str]) {
    if !rows.iter().any(|r| r.candidate.recorded.is_new()) {
        return;
    }
    let mut mentioned = HashSet::new();
    for text in texts {
        mentioned_uuids(text, &mut mentioned);
    }
    for row in rows.iter_mut().filter(|r| r.candidate.recorded.is_new()) {
        if mentioned.contains(&row.candidate.uuid.to_ascii_lowercase()) {
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

impl<'a> Gate<'a> {
    pub(crate) fn new(stage: &'a mut Stage, rows: Vec<Row>) -> Self {
        Gate { stage, rows }
    }

    /// `(purl, uuid)` of every NEW row, for O(1) [`Self::is_new`] checks.
    pub(crate) fn new_keys(&self) -> HashSet<(String, String)> {
        self.rows
            .iter()
            .filter(|r| r.candidate.recorded.is_new())
            .map(|r| (r.writer.purl.clone(), r.writer.uuid.clone()))
            .collect()
    }

    /// Whether a NEW `(purl, uuid)` row could be admitted: budget left, or
    /// its package already admitted by an earlier directory.
    pub(crate) fn may_admit(&self, purl: &str) -> bool {
        self.stage.may_admit_new()
            || (!(self.stage.capped() && self.stage.incomplete)
                && self
                    .stage
                    .already_admitted
                    .contains(&canonical_base_purl(purl)))
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
                    socket_patch_core::policy::repo_relative(
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
        let ctx = HumanContext {
            dry_run,
            incomplete: self.incomplete && self.capped(),
            shared: self.carry.is_some(),
        };
        human_lines(&self.configured, plan, ctx)
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

/// How [`human_lines`] words a run.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HumanContext {
    pub(crate) dry_run: bool,
    /// A lookup failed, so no new patch could be admitted.
    pub(crate) incomplete: bool,
    /// The budget is shared with other project directories of this run.
    pub(crate) shared: bool,
}

pub(crate) fn human_lines(
    configured: &MaxNew,
    plan: &RolloutPlan,
    ctx: HumanContext,
) -> (Option<String>, Vec<String>) {
    let c = plan.counts;
    let line = configured.value.map(|cap| {
        let verb = if ctx.dry_run {
            "would be applied"
        } else {
            "applied"
        };
        let shared = match (ctx.shared, plan.remaining) {
            (true, Some(left)) => format!(", shared by this run's directories, {left} left"),
            _ => String::new(),
        };
        format!(
            "Rollout: {} of {} {verb} (maxNewPatches={cap} from {}{shared}); {}, {} already applied.",
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
    let deferred = if ctx.dry_run {
        format!("{deferred} would be deferred")
    } else {
        format!("{deferred} deferred")
    };
    let first = match configured.value {
        _ if ctx.incomplete => format!(
            "{deferred}: a patch lookup failed, so no new patch was added this run; run scan \
             again once the patch API answers."
        ),
        Some(0) => format!(
            "{deferred}: maxNewPatches=0 adds no new patches; {} to add them.",
            match configured.source {
                MaxNewSource::Flag => "pass a larger --max-new-patches",
                MaxNewSource::Env => "raise SOCKET_MAX_NEW_PATCHES",
                MaxNewSource::File => "raise patches.maxNewPatches in socket.yml",
                MaxNewSource::Cap | MaxNewSource::Default => "raise the cap",
            }
        ),
        Some(cap) if ctx.dry_run => format!(
            "{deferred}; the wet run adds the top {}, and each later committed scan the next ones.",
            (cap as usize).min(c.new as usize + groups.len())
        ),
        Some(cap) => format!(
            "{deferred}; commit these changes and run scan again to apply the next {}.",
            (cap as usize).min(groups.len())
        ),
        None => format!("{deferred}; run scan again to add them."),
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
        let free = offers_from_results(&results, false);
        assert_eq!(free.selected["pkg:npm/a@1"].uuid, "new");
        assert_eq!(free.unfiltered["pkg:npm/a@1"].len(), 2);
        let all = offers_from_results(&results, true);
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
        let offers = offers_from_results(&results, true);
        let recorded = manifest(&[
            ("pkg:npm/same@1", "s1"),
            ("pkg:npm/up@1", "u-old"),
            ("pkg:npm/tie@1", "z-rec"),
            ("pkg:npm/gone@1", "g1"),
        ]);
        let rows = classify(&offers, &RecordedIndex::new(Some(&recorded), &[]), "");
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
    fn mentioned_uuids_finds_every_canonical_shape_once() {
        let mut out = HashSet::new();
        mentioned_uuids(
            "https://h/p/22222222-2222-4222-8222-222222222222/AAAAAAAA-1111-4111-8111-00000000000A/x.tgz \
             not-a-uuid 1234 socket-patch-bbbbbbbb-1111-4111-8111-00000000000b",
            &mut out,
        );
        let mut got: Vec<&str> = out.iter().map(String::as_str).collect();
        got.sort();
        assert_eq!(
            got,
            [
                "22222222-2222-4222-8222-222222222222",
                "aaaaaaaa-1111-4111-8111-00000000000a",
                "bbbbbbbb-1111-4111-8111-00000000000b",
            ]
        );
    }

    #[test]
    fn a_lock_naming_the_selected_uuid_marks_the_row_already() {
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
            &["resolved: https://x/AAAAAAAA-1111-4111-8111-00000000000A/a.tgz"],
        );
        assert_eq!(rows[0].candidate.recorded, Recorded::Same);
        assert_eq!(rows[1].candidate.recorded, Recorded::None);
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
        let offers = offers_from_results(&results, true);
        let mut first = Stage::new(configured, Some(carry.clone()), Path::new("/repo/x"));
        assert_eq!(first.project, "x");
        let rows = classify(&offers, &RecordedIndex::default(), &first.project);
        first.plan(&rows, |_| true);
        assert_eq!(carry.lock().remaining, Some(0));
        let results = vec![
            offer("pkg:npm/a@1", "ua", "", &["critical"]),
            offer("pkg:npm/c@1", "uc", "", &["high"]),
        ];
        let offers = offers_from_results(&results, true);
        let mut second = Stage::new(configured, Some(carry.clone()), Path::new("/repo/y"));
        let rows = classify(&offers, &RecordedIndex::default(), &second.project);
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
                "Rollout: 1 of 2 new patches applied (maxNewPatches=2 from --max-new-patches, \
                 shared by this run's directories, 0 left); 0 upgrades, 0 already applied."
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
        let offers = offers_from_results(&results, true);
        let mut stage = Stage::new(MaxNew::UNLIMITED, None, Path::new("/repo"));
        let rows = classify(&offers, &RecordedIndex::default(), "");
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
        let offers = offers_from_results(&results, true);
        let zero = MaxNew {
            value: Some(0),
            source: MaxNewSource::File,
        };
        let mut stage = Stage::new(zero, None, Path::new("/repo"));
        let rows = classify(&offers, &RecordedIndex::default(), "");
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
            next[0].starts_with("4 new patches would be deferred: maxNewPatches=0"),
            "{next:?}"
        );
        assert_eq!(next[1], "Next up: a@1 (high), b@1 (high), c@1 (high), …");
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
}
