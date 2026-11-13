//! The lane table (design 2.12, 4.3): one file or directory per ruleset
//! family, each exporting a `LaneOps` record. The gate, the hosted engine,
//! discovery, inventory and restore dispatch through [`PRODUCTION`].
//!
//! A lane is enabled only by the change that lands its executed real-Bazel
//! cells, and it names a Bazel line, a dependency system or an OS only
//! with a cell report for it. [`claims_json`] renders those claims so
//! `scripts/bazel-matrix-audit.py` can check each against the reports.
//!
//! Skeleton state: every lane is a disabled stub. `wp-gate` (wave 4)
//! replaces this file with the dispatch helpers and the token-surface
//! policy; the table and the claims format below are its starting point.
//! The `mod` lines stay: the lane files belong to the lane packages.

pub mod aspect_rules_py;
pub mod claims;
pub mod gazelle;
pub mod legacy;
pub mod rules_dotnet;
pub mod rules_js;
pub mod rules_jvm_external;
pub mod rules_pycross;
pub mod rules_python;
pub mod rules_rs;
pub mod rules_ruby;
pub mod rules_rust;

use serde_json::{json, Value};

use super::model::{LaneTable, Mode, Ruleset};

/// The table every production caller passes. Report-only shapes have no
/// row: nothing will ever write for them.
pub const PRODUCTION: LaneTable = LaneTable(&[
    (Ruleset::RulesJs, &rules_js::OPS),
    (Ruleset::RulesNodejs, &legacy::OPS),
    (Ruleset::RulesPython, &rules_python::OPS),
    (Ruleset::AspectRulesPy, &aspect_rules_py::OPS),
    (Ruleset::RulesPycross, &rules_pycross::OPS),
    (Ruleset::RulesJvmExternal, &rules_jvm_external::OPS),
    (Ruleset::Gazelle, &gazelle::OPS),
    (Ruleset::RulesRust, &rules_rust::OPS),
    (Ruleset::RulesRs, &rules_rs::OPS),
    (Ruleset::RulesRuby, &rules_ruby::OPS),
    (Ruleset::RulesDotnet, &rules_dotnet::OPS),
    (Ruleset::RulesCsharp, &rules_dotnet::CSHARP_OPS),
]);

/// The claims of [`PRODUCTION`], for `target/bazel-claims.json`.
pub fn claims_json() -> String {
    claims_of(&PRODUCTION)
}

/// Every claim of `lanes` as pretty JSON with a final newline:
/// `{"version": 1, "claims": [{lane, mode, ruleset, tier, lo, hi, system,
/// os}]}`, one row per claimed line range. `tier` is `supported` for a
/// claim the lane carries, else the `claims` file that makes it. A
/// disabled lane contributes no row, whatever its claim lists say.
pub fn claims_of(lanes: &LaneTable) -> String {
    let mut rows: Vec<Value> = Vec::new();
    for (ruleset, spec) in lanes.specs().filter(|(_, spec)| spec.enabled) {
        let os: Vec<&str> = claims::os_claims(spec.id).map(|os| os.as_str()).collect();
        let own = spec.supported.iter().map(|claim| ("supported", claim));
        for (tier, claim) in own.chain(claims::line_claims(spec.id)) {
            rows.push(json!({
                "lane": spec.id.0,
                "mode": mode_name(spec.mode),
                "ruleset": ruleset.name(),
                "tier": tier,
                "lo": claim.lo,
                "hi": claim.hi,
                "system": claim.system.as_str(),
                "os": os,
            }));
        }
    }
    let mut text =
        serde_json::to_string_pretty(&json!({ "version": 1, "claims": rows })).unwrap_or_default();
    text.push('\n');
    text
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Agent => "agent",
        Mode::Vendored => "vendored",
        Mode::Hosted => "hosted",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::bazel::govern::tests::{read as read_workspace, JS_MODULE, PNPM_LOCK};
    use crate::bazel::model::{
        Anchor, AttestBasis, BazelRef, CellClaim, ClaimSystem, FileText, FileView, Files,
        GateOutcome, HubId, Index, LaneCx, LaneId, LaneOps, LaneSpec, PatchRequest, Plan, Reason,
        RunPolicy, WithholdKind, LANE_NOT_ENABLED,
    };
    use crate::crawlers::types::Ecosystem;
    use crate::patch::redirect::RewriteResult;

    struct NoFiles;
    impl FileView for NoFiles {
        fn read(&self, _: &str) -> FileText {
            FileText::Absent
        }
        fn list(&self, _: &str) -> Option<Vec<String>> {
            Some(Vec::new())
        }
    }

    #[test]
    fn every_ruleset_but_report_only_has_exactly_one_family() {
        let served: Vec<Ruleset> = PRODUCTION.0.iter().map(|(ruleset, _)| *ruleset).collect();
        let expected: Vec<Ruleset> = Ruleset::ALL
            .iter()
            .copied()
            .filter(|r| *r != Ruleset::ReportOnly)
            .collect();
        assert_eq!(served, expected);
    }

    /// The default set of design 4.3. A lane missing here would have no
    /// stub to refuse for it and no spec for its package to enable.
    #[test]
    fn the_table_holds_the_lanes_of_the_design_once_each() {
        let ids: Vec<&str> = PRODUCTION.specs().map(|(_, spec)| spec.id.0).collect();
        let unique: BTreeSet<&str> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "a lane is listed twice: {ids:?}");
        let designed: BTreeSet<&str> = [
            "H-JS1", "H-JS2", "V-JS1", "H-PY1", "H-PY2", "H-PY3", "H-APY1", "H-PYX1", "H-MVN1",
            "A-GO1", "V-GO1", "H-GO1", "H-GO2", "H-RS2", "V-RSR1", "H-RSR1", "H-RB1", "H-NET1",
            "H-NET2",
        ]
        .into();
        assert_eq!(unique, designed);
    }

    #[test]
    fn a_lane_id_names_its_mode() {
        for (_, spec) in PRODUCTION.specs() {
            let letter = match spec.mode {
                Mode::Hosted => "H-",
                Mode::Vendored => "V-",
                Mode::Agent => "A-",
            };
            assert!(
                spec.id.0.starts_with(letter),
                "{:?} is {:?}",
                spec.id,
                spec.mode
            );
            assert!(
                !spec.probes.is_empty(),
                "{:?} names no gating probe",
                spec.id
            );
        }
    }

    #[test]
    fn no_production_lane_is_enabled_or_claims_anything() {
        for (_, spec) in PRODUCTION.specs() {
            assert!(
                !spec.enabled,
                "{:?} is enabled without a real-Bazel proof",
                spec.id
            );
            assert!(spec.supported.is_empty() && spec.token_surfaces.is_empty());
        }
        assert_eq!(claims_json(), "{\n  \"version\": 1,\n  \"claims\": []\n}\n");
    }

    /// Every family, in every mode: the gate refuses with the contract's
    /// reason and token, the writers change nothing, discovery and
    /// inventory say "cannot tell" (never "nothing"), and `vex` withholds.
    /// `restore` takes an index row, which has no value until the owned
    /// index lands; the toy lane exercises it from wave 4.
    #[test]
    fn every_stub_family_refuses_and_writes_nothing() {
        let request = PatchRequest {
            ecosystem: Ecosystem::Npm,
            name: "left-pad",
            version: "1.3.0",
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
            project_rel: "",
        };
        let pin = BazelRef {
            lane: LaneId("H-JS1"),
            purl: "pkg:npm/left-pad@1.3.0".to_string(),
            uuid: request.uuid.to_string(),
            file: "pnpm-lock.yaml".to_string(),
            basis: AttestBasis::LockUrl,
        };
        let plan = Plan {
            lane: pin.lane,
            writes: Vec::new(),
            advisories: Vec::new(),
            attest: AttestBasis::Withheld,
            anchor: Anchor::Digest,
        };
        let read = |_: &str| -> Option<String> { Some("lockfileVersion: '9.0'\n".to_string()) };
        let ws = read_workspace(&[("MODULE.bazel", JS_MODULE), PNPM_LOCK]);
        let index = Index::default();
        for (ruleset, ops) in PRODUCTION.0 {
            for mode in Mode::ALL {
                let cx = LaneCx {
                    mode: *mode,
                    files: &NoFiles,
                    ws: &ws,
                    hub: HubId(0),
                    index: &index,
                    run: RunPolicy::Never,
                };
                let GateOutcome::Refuse(refusal) = (ops.gate)(&cx, &request) else {
                    panic!("{ruleset:?} {mode:?}: a stub lane did not refuse");
                };
                assert_eq!(refusal.reason, Reason::RulesetUnsupported);
                assert_eq!(refusal.token, LANE_NOT_ENABLED);
                assert!(
                    !refusal.lift.is_final(),
                    "{ruleset:?}: a stub refused for good"
                );

                let before: Files = [("pnpm-lock.yaml".to_string(), "x\n".to_string())].into();
                let (mut files, mut result) = (before.clone(), RewriteResult::default());
                (ops.rewrite_owned)(&cx, &mut files, &[], &mut result);
                (ops.fixups)(&cx, &mut files, &plan, &mut result);
                assert_eq!(files, before);
                assert!(
                    result == RewriteResult::default(),
                    "{ruleset:?} reported a write"
                );

                assert_eq!((ops.discover)(&cx, &read), None);
                assert!((ops.inventory)(&cx, &read).is_none());
                let withheld = (ops.attest)(&cx, &pin).expect_err("a stub lane attested");
                assert_eq!(withheld.kind, WithholdKind::ConsumerUndetermined);
            }
        }
    }

    #[test]
    fn claims_render_enabled_lanes_only() {
        const CLAIMS: &[CellClaim] = &[
            CellClaim {
                lo: "7.2.0",
                hi: "9.3.2",
                system: ClaimSystem::Bzlmod,
            },
            CellClaim {
                lo: "7.7.2",
                hi: "7.7.2",
                system: ClaimSystem::Workspace,
            },
        ];
        const PROVEN: LaneSpec = LaneSpec {
            enabled: true,
            supported: CLAIMS,
            ..LaneSpec::stub("H-TOY1", Mode::Hosted, &[])
        };
        const UNPROVEN: LaneSpec = LaneSpec {
            supported: CLAIMS,
            ..LaneSpec::stub("V-TOY1", Mode::Vendored, &[])
        };
        const TOY: LaneOps = LaneOps::disabled(&[PROVEN, UNPROVEN]);
        const TABLE: LaneTable = LaneTable(&[(Ruleset::RulesJs, &TOY)]);
        let doc: Value = serde_json::from_str(&claims_of(&TABLE)).unwrap();
        assert_eq!(
            doc,
            json!({ "version": 1, "claims": [
                { "lane": "H-TOY1", "mode": "hosted", "ruleset": "rules_js", "tier": "supported",
                  "lo": "7.2.0", "hi": "9.3.2", "system": "bzlmod", "os": [] },
                { "lane": "H-TOY1", "mode": "hosted", "ruleset": "rules_js", "tier": "supported",
                  "lo": "7.7.2", "hi": "7.7.2", "system": "workspace", "os": [] },
            ]})
        );
    }
}
