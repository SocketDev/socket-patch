//! Staged rollout: the per-run cap on NEW patches (`scan
//! --max-new-patches`, `patches.maxNewPatches` in socket.yml).
//!
//! Pure planning only. Callers classify each selected `(project, purl)` row
//! against the recorded state ([`Recorded`]), decide eligibility with their
//! planning pass, and hand the rows to [`plan_rollout`], which admits the
//! most critical NEW packages up to the budget and defers the rest. Rows
//! that already carry a patch (ALREADY, UPGRADE) never count toward the cap.
//!
//! The order ([`rollout_cmp`]) is total and time-independent, so the same
//! inputs always give the same plan and repeated runs converge: run k lands
//! the top N, run k+1 sees them as recorded and lands the next N.

use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BTreeSet};

use crate::utils::purl::canonical_purl;

/// What the recorded state (manifest > hosted pins > vendor ledger) says
/// about one selected row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    /// No patch recorded for this base purl in this project: NEW.
    None,
    /// The recorded uuid is the selected one: ALREADY.
    Same,
    /// A different uuid is recorded and the selection does not supersede
    /// it: ALREADY, and the writer keeps `uuid`.
    Kept { uuid: String },
    /// The selection supersedes the recorded uuid, or the recorded uuid is
    /// no longer offered: UPGRADE.
    Superseded { old_uuid: String },
}

impl Recorded {
    pub fn is_new(&self) -> bool {
        matches!(self, Recorded::None)
    }
}

/// One selected `(project, purl)` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Repo-relative project root; `""` is the repo root.
    pub project: String,
    pub purl: String,
    /// [`canonical_base_purl`] of `purl`: the budget unit.
    pub base_purl: String,
    /// The selected uuid.
    pub uuid: String,
    /// `Ecosystem::cli_name`.
    pub ecosystem: &'static str,
    /// `ranking::max_severity_order` of the selected patch (0 = critical).
    pub severity_order: u8,
    pub advisory_count: usize,
    pub recorded: Recorded,
    /// Every check the planning pass can decide without writing passed.
    /// Only read for NEW rows.
    pub eligible: bool,
    /// Already proposed in an open rollout PR (in-memory engine option).
    pub in_flight: bool,
}

/// Where the effective cap came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaxNewSource {
    Flag,
    Env,
    File,
    Default,
    /// A server ceiling (`maxNewPatchesCap`) tightened the value.
    Cap,
}

impl MaxNewSource {
    pub fn as_str(self) -> &'static str {
        match self {
            MaxNewSource::Flag => "flag",
            MaxNewSource::Env => "env",
            MaxNewSource::File => "file",
            MaxNewSource::Default => "default",
            MaxNewSource::Cap => "cap",
        }
    }
}

/// The effective cap. `value: None` is unlimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxNew {
    pub value: Option<u32>,
    pub source: MaxNewSource,
}

impl MaxNew {
    pub const UNLIMITED: MaxNew = MaxNew {
        value: None,
        source: MaxNewSource::Default,
    };
}

/// Resolve the cap: flag > env > file > unlimited, then a server `cap`
/// tightens it (never loosens; it applies to `none` too). For `flag` and
/// `env`, `Some(None)` is an explicit `none`.
pub fn resolve_max_new(
    flag: Option<Option<u32>>,
    env: Option<Option<u32>>,
    file: Option<u32>,
    cap: Option<u32>,
) -> MaxNew {
    let chosen = if let Some(value) = flag {
        MaxNew {
            value,
            source: MaxNewSource::Flag,
        }
    } else if let Some(value) = env {
        MaxNew {
            value,
            source: MaxNewSource::Env,
        }
    } else if let Some(value) = file {
        MaxNew {
            value: Some(value),
            source: MaxNewSource::File,
        }
    } else {
        MaxNew::UNLIMITED
    };
    match cap {
        Some(cap) if chosen.value.is_none_or(|v| v > cap) => MaxNew {
            value: Some(cap),
            source: MaxNewSource::Cap,
        },
        _ => chosen,
    }
}

/// The budget unit: ecosystem + name + version, qualifiers stripped and
/// percent-decoded, so qualifier twins (a wheel and its sdist, gem
/// platforms) and the API's encoded spelling are one package.
pub fn canonical_base_purl(purl: &str) -> String {
    canonical_purl(purl)
}

/// Rollout order, most urgent first: in-flight, severity, advisory count
/// (descending), ecosystem, base purl, uuid. Total, and free of
/// time-dependent keys.
pub fn rollout_cmp(a: &Candidate, b: &Candidate) -> Ordering {
    rollout_key(a).cmp(&rollout_key(b))
}

type RolloutKey<'a> = (bool, u8, Reverse<usize>, &'a str, &'a str, &'a str);

fn rollout_key(c: &Candidate) -> RolloutKey<'_> {
    (
        !c.in_flight,
        c.severity_order,
        Reverse(c.advisory_count),
        c.ecosystem,
        c.base_purl.as_str(),
        c.uuid.as_str(),
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RolloutCounts {
    /// Distinct base purls admitted as NEW.
    pub new: u32,
    /// Distinct base purls deferred.
    pub deferred: u32,
    /// UPGRADE rows.
    pub upgrade: u32,
    /// ALREADY rows (same or kept).
    pub already: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RolloutPlan {
    /// Rows the writers receive: admitted NEW rows plus every ALREADY and
    /// UPGRADE row, in input order. Ineligible NEW rows are in neither
    /// list; they keep their own skip reasons.
    pub admitted: Vec<Candidate>,
    /// Eligible NEW rows over the budget, in rank order, each with the
    /// 1-based rank of its base purl among eligible NEW base purls.
    pub deferred: Vec<(Candidate, u32)>,
    pub counts: RolloutCounts,
    /// Budget left for the next project directory; `None` is unlimited.
    pub remaining: Option<u32>,
    /// Base purls admitted so far in this invocation (input set included).
    pub admitted_base_purls: BTreeSet<String>,
}

/// Admit eligible NEW base purls in [`rollout_cmp`] order until the budget
/// is spent. A base purl already in `already_admitted` (an earlier
/// directory of the same invocation) is admitted without spending budget.
/// With a finite cap and `incomplete` set (a lookup failed for a package
/// that could have been NEW), no NEW row is admitted: a missing package
/// must not let lower-ranked ones take its slot.
pub fn plan_rollout(
    candidates: Vec<Candidate>,
    max_new: &MaxNew,
    incomplete: bool,
    already_admitted: &BTreeSet<String>,
) -> RolloutPlan {
    let mut counts = RolloutCounts::default();
    let mut remaining = max_new.value;
    let mut admitted_base_purls = already_admitted.clone();

    let mut new_rows: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| c.recorded.is_new() && c.eligible)
        .collect();
    new_rows.sort_by(|a, b| rollout_cmp(a, b));
    // Base purl → (rank, admitted), in rank order.
    let mut decisions: BTreeMap<&str, (u32, bool)> = BTreeMap::new();
    let mut rank = 0u32;
    for row in &new_rows {
        if decisions.contains_key(row.base_purl.as_str()) {
            continue;
        }
        rank += 1;
        let admit = if incomplete && max_new.value.is_some() {
            false
        } else if already_admitted.contains(&row.base_purl) {
            true
        } else {
            match remaining.as_mut() {
                None => true,
                Some(0) => false,
                Some(left) => {
                    *left -= 1;
                    true
                }
            }
        };
        if admit {
            counts.new += 1;
            admitted_base_purls.insert(row.base_purl.clone());
        } else {
            counts.deferred += 1;
        }
        decisions.insert(row.base_purl.as_str(), (rank, admit));
    }

    let deferred: Vec<(Candidate, u32)> = new_rows
        .iter()
        .filter_map(|row| match decisions[row.base_purl.as_str()] {
            (rank, false) => Some(((*row).clone(), rank)),
            _ => None,
        })
        .collect();
    let mut admitted = Vec::new();
    for row in &candidates {
        match &row.recorded {
            Recorded::None => {
                if row.eligible && decisions[row.base_purl.as_str()].1 {
                    admitted.push(row.clone());
                }
            }
            Recorded::Superseded { .. } => {
                counts.upgrade += 1;
                admitted.push(row.clone());
            }
            Recorded::Same | Recorded::Kept { .. } => {
                counts.already += 1;
                admitted.push(row.clone());
            }
        }
    }
    RolloutPlan {
        admitted,
        deferred,
        counts,
        remaining,
        admitted_base_purls,
    }
}

/// The severity label for a `ranking::severity_order` value.
pub fn severity_label(order: u8) -> &'static str {
    match order {
        0 => "critical",
        1 => "high",
        2 => "medium",
        3 => "low",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(project: &str, purl: &str, uuid: &str, severity: u8, advisories: usize) -> Candidate {
        Candidate {
            project: project.to_string(),
            purl: purl.to_string(),
            base_purl: canonical_base_purl(purl),
            uuid: uuid.to_string(),
            ecosystem: purl
                .strip_prefix("pkg:")
                .and_then(|r| r.split('/').next())
                .map(|e| match e {
                    "npm" => "npm",
                    "pypi" => "pypi",
                    "cargo" => "cargo",
                    "gem" => "gem",
                    _ => "golang",
                })
                .unwrap_or("npm"),
            severity_order: severity,
            advisory_count: advisories,
            recorded: Recorded::None,
            eligible: true,
            in_flight: false,
        }
    }

    fn cap(n: u32) -> MaxNew {
        MaxNew {
            value: Some(n),
            source: MaxNewSource::Flag,
        }
    }

    fn admitted_purls(plan: &RolloutPlan) -> Vec<&str> {
        plan.admitted.iter().map(|c| c.purl.as_str()).collect()
    }

    fn deferred_purls(plan: &RolloutPlan) -> Vec<(&str, u32)> {
        plan.deferred
            .iter()
            .map(|(c, r)| (c.purl.as_str(), *r))
            .collect()
    }

    fn nine() -> Vec<Candidate> {
        vec![
            row("", "pkg:npm/a@1", "u1", 3, 1),
            row("", "pkg:npm/b@1", "u2", 0, 1),
            row("", "pkg:npm/c@1", "u3", 1, 1),
            row("", "pkg:npm/d@1", "u4", 2, 1),
            row("", "pkg:npm/e@1", "u5", 0, 2),
            row("", "pkg:npm/f@1", "u6", 4, 1),
            row("", "pkg:npm/g@1", "u7", 1, 3),
            row("", "pkg:npm/h@1", "u8", 2, 1),
            row("", "pkg:npm/i@1", "u9", 3, 1),
        ]
    }

    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut out = Vec::new();
        for i in 0..items.len() {
            let mut rest = items.to_vec();
            let head = rest.remove(i);
            for mut tail in permutations(&rest) {
                tail.insert(0, head.clone());
                out.push(tail);
            }
        }
        out
    }

    #[test]
    fn rollout_cmp_is_a_total_order_every_permutation_sorts_the_same() {
        let mut in_flight = row("", "pkg:pypi/z@1", "u9", 4, 0);
        in_flight.in_flight = true;
        let items = vec![
            row("", "pkg:npm/b@1", "u2", 1, 1),
            row("", "pkg:npm/a@1", "u3", 1, 1),
            row("", "pkg:cargo/a@1", "u1", 1, 1),
            row("", "pkg:npm/m@1", "u0", 1, 2),
            row("", "pkg:npm/a@1", "u1", 1, 1),
            in_flight,
        ];
        let expected: Vec<(String, String)> = vec![
            ("pkg:pypi/z@1".into(), "u9".into()),
            ("pkg:npm/m@1".into(), "u0".into()),
            ("pkg:cargo/a@1".into(), "u1".into()),
            ("pkg:npm/a@1".into(), "u1".into()),
            ("pkg:npm/a@1".into(), "u3".into()),
            ("pkg:npm/b@1".into(), "u2".into()),
        ];
        for mut perm in permutations(&items) {
            perm.sort_by(rollout_cmp);
            let got: Vec<(String, String)> = perm
                .iter()
                .map(|c| (c.purl.clone(), c.uuid.clone()))
                .collect();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn severity_then_advisory_count_decide_before_names() {
        let mut rows = [
            row("", "pkg:npm/a@1", "u", 2, 5),
            row("", "pkg:npm/b@1", "u", 0, 1),
            row("", "pkg:npm/c@1", "u", 0, 3),
            row("", "pkg:npm/d@1", "u", 4, 9),
        ];
        rows.sort_by(rollout_cmp);
        let order: Vec<&str> = rows.iter().map(|c| c.purl.as_str()).collect();
        assert_eq!(
            order,
            ["pkg:npm/c@1", "pkg:npm/b@1", "pkg:npm/a@1", "pkg:npm/d@1"]
        );
    }

    #[test]
    fn a_cap_admits_the_most_critical_and_defers_the_rest_with_ranks() {
        let plan = plan_rollout(nine(), &cap(3), false, &BTreeSet::new());
        assert_eq!(
            admitted_purls(&plan),
            ["pkg:npm/b@1", "pkg:npm/e@1", "pkg:npm/g@1"]
        );
        assert_eq!(
            deferred_purls(&plan),
            [
                ("pkg:npm/c@1", 4),
                ("pkg:npm/d@1", 5),
                ("pkg:npm/h@1", 6),
                ("pkg:npm/a@1", 7),
                ("pkg:npm/i@1", 8),
                ("pkg:npm/f@1", 9),
            ]
        );
        assert_eq!(
            plan.counts,
            RolloutCounts {
                new: 3,
                deferred: 6,
                upgrade: 0,
                already: 0
            }
        );
        assert_eq!(plan.remaining, Some(0));
    }

    #[test]
    fn three_runs_roll_nine_packages_forward_and_a_fourth_changes_nothing() {
        let mut state = nine();
        let mut landed: Vec<Vec<String>> = Vec::new();
        for _ in 0..4 {
            let plan = plan_rollout(state.clone(), &cap(3), false, &BTreeSet::new());
            let new: Vec<String> = plan
                .admitted
                .iter()
                .filter(|c| c.recorded.is_new())
                .map(|c| c.purl.clone())
                .collect();
            for c in &mut state {
                if new.contains(&c.purl) {
                    c.recorded = Recorded::Same;
                }
            }
            landed.push(new);
        }
        assert_eq!(landed[0], ["pkg:npm/b@1", "pkg:npm/e@1", "pkg:npm/g@1"]);
        assert_eq!(landed[1], ["pkg:npm/c@1", "pkg:npm/d@1", "pkg:npm/h@1"]);
        assert_eq!(landed[2], ["pkg:npm/a@1", "pkg:npm/f@1", "pkg:npm/i@1"]);
        assert!(landed[3].is_empty());
    }

    #[test]
    fn zero_admits_no_new_rows_but_keeps_upgrades_and_already() {
        let mut rows = nine();
        rows[0].recorded = Recorded::Superseded {
            old_uuid: "old".into(),
        };
        rows[1].recorded = Recorded::Same;
        rows[2].recorded = Recorded::Kept { uuid: "k".into() };
        let plan = plan_rollout(rows, &cap(0), false, &BTreeSet::new());
        assert_eq!(
            admitted_purls(&plan),
            ["pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1"]
        );
        assert_eq!(plan.counts.new, 0);
        assert_eq!(plan.counts.deferred, 6);
        assert_eq!(plan.counts.upgrade, 1);
        assert_eq!(plan.counts.already, 2);
        assert_eq!(plan.deferred[0].1, 1, "ranks start at 1 among NEW rows");
    }

    #[test]
    fn a_cap_of_one_admits_exactly_the_top_package() {
        let plan = plan_rollout(nine(), &cap(1), false, &BTreeSet::new());
        assert_eq!(admitted_purls(&plan), ["pkg:npm/e@1"]);
        assert_eq!(plan.counts.deferred, 8);
    }

    #[test]
    fn unlimited_and_a_cap_above_the_supply_admit_everything() {
        for max in [MaxNew::UNLIMITED, cap(50)] {
            let plan = plan_rollout(nine(), &max, false, &BTreeSet::new());
            assert_eq!(plan.admitted.len(), 9);
            assert!(plan.deferred.is_empty());
            assert_eq!(plan.counts.new, 9);
        }
        let plan = plan_rollout(nine(), &cap(50), false, &BTreeSet::new());
        assert_eq!(plan.remaining, Some(41));
        let plan = plan_rollout(nine(), &MaxNew::UNLIMITED, false, &BTreeSet::new());
        assert_eq!(plan.remaining, None);
    }

    #[test]
    fn ineligible_rows_hold_no_slot_and_are_not_reported_as_deferred() {
        let mut rows = nine();
        // The top two by rank cannot land.
        rows[4].eligible = false; // e
        rows[1].eligible = false; // b
        let plan = plan_rollout(rows, &cap(2), false, &BTreeSet::new());
        assert_eq!(admitted_purls(&plan), ["pkg:npm/c@1", "pkg:npm/g@1"]);
        assert!(plan
            .deferred
            .iter()
            .all(|(c, _)| c.purl != "pkg:npm/b@1" && c.purl != "pkg:npm/e@1"));
        assert_eq!(plan.counts.deferred, 5);
        assert_eq!(plan.deferred[0].1, 3);
    }

    #[test]
    fn incomplete_lookups_admit_nothing_new_under_a_cap() {
        let mut rows = nine();
        rows[0].recorded = Recorded::Superseded {
            old_uuid: "old".into(),
        };
        let plan = plan_rollout(rows.clone(), &cap(3), true, &BTreeSet::new());
        assert_eq!(admitted_purls(&plan), ["pkg:npm/a@1"]);
        assert_eq!(plan.counts.deferred, 8);
        assert_eq!(plan.remaining, Some(3), "nothing was spent");
        // Without a cap there is no slot to steal.
        let plan = plan_rollout(rows, &MaxNew::UNLIMITED, true, &BTreeSet::new());
        assert_eq!(plan.admitted.len(), 9);
    }

    #[test]
    fn one_package_across_roots_costs_one_slot() {
        let rows = vec![
            row("services/api", "pkg:npm/qs@6.5.2", "u1", 1, 1),
            row("services/web", "pkg:npm/qs@6.5.2", "u1", 1, 1),
            row("", "pkg:npm/minimist@1.2.5", "u2", 0, 1),
            row("", "pkg:npm/zzz@1.0.0", "u3", 3, 1),
        ];
        let plan = plan_rollout(rows, &cap(2), false, &BTreeSet::new());
        assert_eq!(
            admitted_purls(&plan),
            [
                "pkg:npm/qs@6.5.2",
                "pkg:npm/qs@6.5.2",
                "pkg:npm/minimist@1.2.5"
            ]
        );
        assert_eq!(plan.counts.new, 2);
        assert_eq!(deferred_purls(&plan), [("pkg:npm/zzz@1.0.0", 3)]);
    }

    #[test]
    fn qualifier_twins_share_a_base_purl_and_a_rank() {
        assert_eq!(
            canonical_base_purl("pkg:pypi/foo@1.0?artifact_id=abc"),
            canonical_base_purl("pkg:pypi/foo@1.0?artifact_id=def")
        );
        assert_eq!(
            canonical_base_purl("pkg:npm/%40scope/x@1.0.0"),
            "pkg:npm/@scope/x@1.0.0"
        );
        let rows = vec![
            row("", "pkg:pypi/foo@1.0?artifact_id=whl", "u2", 1, 1),
            row("", "pkg:pypi/foo@1.0?artifact_id=sdist", "u1", 1, 1),
            row("", "pkg:pypi/bar@1.0", "u3", 0, 1),
        ];
        let plan = plan_rollout(rows, &cap(1), false, &BTreeSet::new());
        assert_eq!(admitted_purls(&plan), ["pkg:pypi/bar@1.0"]);
        assert_eq!(
            deferred_purls(&plan),
            [
                ("pkg:pypi/foo@1.0?artifact_id=sdist", 2),
                ("pkg:pypi/foo@1.0?artifact_id=whl", 2)
            ]
        );
        assert_eq!(plan.counts.deferred, 1);
    }

    #[test]
    fn ties_across_ecosystems_break_by_ecosystem_name() {
        let rows = vec![
            row("", "pkg:npm/x@1", "u1", 1, 1),
            row("", "pkg:cargo/x@1", "u2", 1, 1),
            row("", "pkg:pypi/x@1", "u3", 1, 1),
            row("", "pkg:gem/x@1", "u4", 1, 1),
        ];
        let plan = plan_rollout(rows, &cap(2), false, &BTreeSet::new());
        assert_eq!(admitted_purls(&plan), ["pkg:cargo/x@1", "pkg:gem/x@1"]);
        assert_eq!(
            deferred_purls(&plan),
            [("pkg:npm/x@1", 3), ("pkg:pypi/x@1", 4)]
        );
    }

    #[test]
    fn in_flight_rows_go_first_whatever_their_severity() {
        let mut rows = nine();
        rows[5].in_flight = true; // f, unknown severity
        let plan = plan_rollout(rows, &cap(1), false, &BTreeSet::new());
        assert_eq!(admitted_purls(&plan), ["pkg:npm/f@1"]);
    }

    #[test]
    fn remaining_budget_carries_across_directories() {
        let first = vec![
            row("a", "pkg:npm/x@1", "u1", 0, 1),
            row("a", "pkg:npm/y@1", "u2", 1, 1),
        ];
        let plan_a = plan_rollout(first, &cap(3), false, &BTreeSet::new());
        assert_eq!(plan_a.remaining, Some(1));
        let carried = MaxNew {
            value: plan_a.remaining,
            source: MaxNewSource::Flag,
        };
        let second = vec![
            row("b", "pkg:npm/x@1", "u1", 0, 1),
            row("b", "pkg:npm/z@1", "u3", 2, 1),
            row("b", "pkg:npm/w@1", "u4", 3, 1),
        ];
        let plan_b = plan_rollout(second, &carried, false, &plan_a.admitted_base_purls);
        assert_eq!(admitted_purls(&plan_b), ["pkg:npm/x@1", "pkg:npm/z@1"]);
        assert_eq!(plan_b.remaining, Some(0));
        assert_eq!(deferred_purls(&plan_b), [("pkg:npm/w@1", 3)]);
        assert_eq!(plan_b.admitted_base_purls.len(), 3);
    }

    #[test]
    fn an_empty_plan_is_empty() {
        let plan = plan_rollout(Vec::new(), &cap(3), true, &BTreeSet::new());
        assert!(plan.admitted.is_empty() && plan.deferred.is_empty());
        assert_eq!(plan.counts, RolloutCounts::default());
        assert_eq!(plan.remaining, Some(3));
    }

    #[test]
    fn resolve_max_new_precedence_table() {
        use MaxNewSource::*;
        type Case = (
            Option<Option<u32>>,
            Option<Option<u32>>,
            Option<u32>,
            Option<u32>,
            Option<u32>,
            MaxNewSource,
        );
        let cases: [Case; 10] = [
            (None, None, None, None, None, Default),
            (None, None, Some(5), None, Some(5), File),
            (None, Some(Some(2)), Some(5), None, Some(2), Env),
            (Some(Some(1)), Some(Some(2)), Some(5), None, Some(1), Flag),
            (Some(None), None, Some(5), None, None, Flag),
            (None, Some(None), Some(5), None, None, Env),
            (Some(None), None, None, Some(4), Some(4), Cap),
            (None, None, None, Some(4), Some(4), Cap),
            (Some(Some(9)), None, None, Some(4), Some(4), Cap),
            (Some(Some(2)), None, None, Some(4), Some(2), Flag),
        ];
        for (flag, env, file, cap, value, source) in cases {
            assert_eq!(
                resolve_max_new(flag, env, file, cap),
                MaxNew { value, source },
                "flag={flag:?} env={env:?} file={file:?} cap={cap:?}"
            );
        }
        assert_eq!(resolve_max_new(None, None, Some(4), Some(4)).source, File);
    }

    #[test]
    fn severity_labels_follow_the_ladder() {
        assert_eq!(
            (0..=5).map(severity_label).collect::<Vec<_>>(),
            ["critical", "high", "medium", "low", "unknown", "unknown"]
        );
    }
}
