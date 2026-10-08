//! Scan's side of the rollout stage (`docs/configuration.md#gradual-rollout`):
//! `updates[]`, the hosted gate and the human lines. The stage
//! itself is [`socket_patch_core::rollout::stage`].

use std::collections::{BTreeMap, BTreeSet, HashSet};

pub(crate) use socket_patch_core::rollout::stage::*;
use socket_patch_core::rollout::{
    canonical_base_purl, severity_label, MaxNew, MaxNewSource, Recorded, RolloutPlan,
};

use super::discovery::UpdateInfo;

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

/// The rows the hosted engine plans (§9.0 step 7 inside the engine, after
/// its eligibility checks) and the stage that records the plan.
pub(crate) struct Gate<'a> {
    pub(crate) stage: &'a mut Stage,
    pub(crate) rows: Vec<Row>,
    /// Scan's lockfile discovery of `--cwd`, made before the redirect
    /// (with the configured patch-server origins): the rewrite's
    /// attribution gate reuses it when nothing changed the project since.
    pub(crate) prior: Option<Prior<'a>>,
}

/// Scan's discovery, made BEFORE the apply lock, with the paths it read.
#[derive(Clone, Copy)]
pub(crate) struct Prior<'a> {
    pub(crate) discovery: &'a socket_patch_core::vex::discover::Discovery,
    /// `None` when the read set cannot cover what discovery read (it read
    /// the disk around the snapshot): never reusable.
    pub(crate) read_set: Option<&'a socket_patch_core::vendor::lock_inventory::ReadSet>,
}

impl<'a> Prior<'a> {
    /// The discovery, when every path it read still has the fingerprint it
    /// had then (stats only). Called under the apply lock, so nothing that
    /// takes it can change the project between this check and the gate; a
    /// change since the unlocked read sends the gate to a fresh discovery.
    pub(crate) fn still_current(&self) -> Option<&'a socket_patch_core::vex::discover::Discovery> {
        self.read_set
            .filter(|read| read.unchanged())
            .map(|_| self.discovery)
    }
}

impl<'a> Gate<'a> {
    pub(crate) fn new(stage: &'a mut Stage, rows: Vec<Row>) -> Self {
        Gate {
            stage,
            rows,
            prior: None,
        }
    }

    /// This gate carrying scan's pre-redirect discovery (see [`Self::prior`]).
    pub(crate) fn with_prior(mut self, prior: Option<Prior<'a>>) -> Self {
        self.prior = prior;
        self
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

/// The human `Rollout:` line (only when a cap is set) and the
/// Next-steps lines about deferred patches.
pub(crate) fn human(stage: &Stage, dry_run: bool) -> (Option<String>, Vec<String>) {
    let Some(plan) = stage.plan.as_ref() else {
        return (None, Vec::new());
    };
    let ctx = HumanContext {
        dry_run,
        incomplete: stage.incomplete && stage.capped(),
        shared: stage.carry.is_some(),
    };
    human_lines(&stage.configured, plan, ctx)
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
    /// Scan's discovery is taken before the apply lock: the gate reuses it
    /// only while every path it read is unchanged, so a lockfile written
    /// between scan's discovery and the gate (a concurrent run that held the
    /// lock first) sends the gate to a fresh discovery.
    #[tokio::test]
    async fn the_prior_discovery_is_reused_only_while_the_project_is_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let lock = r#"{"name":"app","lockfileVersion":3,"requires":true,"packages":{"":{"name":"app","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-UPSTREAM=="}}}"#;
        std::fs::write(root.join("package-lock.json"), lock).unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"app"}"#).unwrap();
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            ..crate::args::GlobalArgs::default()
        };
        let ctx = crate::commands::context::ProjectContext::new(&common);
        let (discovery, read_set) = ctx.recorded_discovery().await;
        let prior = super::Prior {
            discovery,
            read_set: read_set.as_ref(),
        };
        let read = read_set
            .as_ref()
            .expect("an npm project's discovery is recorded");
        assert!(!read.is_empty());
        // Unchanged (taking the apply lock creates `.socket/`): reused.
        std::fs::create_dir_all(root.join(".socket")).unwrap();
        std::fs::write(root.join(".socket/apply.lock"), "").unwrap();
        assert!(std::ptr::eq(prior.still_current().unwrap(), discovery));
        // A concurrent writer rewrote the lockfile: never reused.
        std::fs::write(
            root.join("package-lock.json"),
            lock.replace("1.3.0.tgz", "1.3.0.tgz?x"),
        )
        .unwrap();
        assert!(prior.still_current().is_none());
        // Without a read set (discovery read the disk around the snapshot):
        // never reused either.
        let unrecorded = super::Prior {
            discovery,
            read_set: None,
        };
        assert!(unrecorded.still_current().is_none());
    }

    use super::*;
    use socket_patch_core::api::types::PatchSearchResult;
    use socket_patch_core::api::types::VulnerabilityResponse;
    use socket_patch_core::manifest::schema::PatchManifest;
    use socket_patch_core::manifest::schema::PatchRecord;
    use std::collections::HashMap;
    use std::path::Path;

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
        let plan = socket_patch_core::rollout::plan_rollout(
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
            &[socket_patch_core::patch::redirect::upstream::HostedPin {
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
            &[socket_patch_core::patch::redirect::upstream::HostedPin {
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
            serde_json::to_value(second.deferred_skips()).unwrap(),
            serde_json::json!([{
                "purl": "pkg:npm/c@1", "uuid": "uc", "reason": "rollout_deferred",
                "detail": "rank 2 in the rollout queue; a later scan adds it"
            }])
        );
        let (line, next) = human(&second, false);
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
        assert_eq!(human(&stage, false), (None, Vec::new()));
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
        let (line, next) = human(&stage, true);
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
