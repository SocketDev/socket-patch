//! Scan's side of the rollout stage (`docs/configuration.md#gradual-rollout`):
//! `updates[]`, the hosted gate and the human lines. The stage
//! itself is [`socket_patch_core::rollout::stage`].

use std::collections::{BTreeMap, BTreeSet, HashSet};

pub(crate) use socket_patch_core::rollout::stage::*;
use socket_patch_core::rollout::{severity_label, MaxNewSource, Recorded};
use socket_patch_core::utils::purl_key::PurlKey;

use super::discovery::UpdateInfo;

/// `updates[]`: the UPGRADE rows, reported under the batch package's purl
/// spelling when one names the same base purl (one entry per package).
pub(super) fn upgrades(rows: &[Row], package_purls: &[String]) -> Vec<UpdateInfo> {
    let by_base: BTreeMap<String, &String> = package_purls
        .iter()
        .map(|p| (PurlKey::new(p).into_string(), p))
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
    /// The withdrawn-pin sweep's reference answers: the redirect asks the
    /// endpoint only about the selected uuids these do not cover.
    pub(crate) references: Option<super::withdrawn::KnownReferences>,
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

impl Gate<'_> {
    /// `(purl, uuid)` of every NEW row, for O(1) [`Self::is_new`] checks.
    pub(crate) fn new_keys(&self) -> HashSet<(String, String)> {
        self.rows
            .iter()
            .filter(|r| r.candidate.recorded.is_new())
            .map(|r| (r.writer.purl.clone(), r.writer.uuid.clone()))
            .collect()
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
        .map(|p| PurlKey::new(p).into_string())
        .collect();
    let mut out = upgrades(rows, package_purls);
    out.extend(
        batch
            .into_iter()
            .filter(|u| !offered.contains(&PurlKey::new(&u.purl).into_string())),
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
    let configured = &stage.configured;
    let c = plan.counts;
    let line = configured.value.map(|cap| {
        let verb = if dry_run {
            "would be applied"
        } else {
            "applied"
        };
        let shared = match (stage.carry.is_some(), plan.remaining) {
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
    let deferred = if dry_run {
        format!("{deferred} would be deferred")
    } else {
        format!("{deferred} deferred")
    };
    let first = match configured.value {
        _ if stage.incomplete && stage.capped() => format!(
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
        Some(cap) if dry_run => format!(
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
                g.base_purl
                    .strip_prefix("pkg:")
                    .and_then(|rest| rest.split_once('/'))
                    .map_or(g.base_purl.as_str(), |(_, name)| name),
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
    use socket_patch_core::rollout::MaxNew;
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
}
