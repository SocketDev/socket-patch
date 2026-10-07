//! The vendored sbt gate: `formats::sbt::gate` over the build's local
//! evidence (`crawlers::sbt_evidence::distill`), before planning.
//!
//! - A NEW pin ([`gate::check_new`]): the run-level conditions (no
//!   evidence, incomplete, stale) skip the patch with one `vendor_sbt_*`
//!   warning and exit 0; a GA no library configuration resolves is skipped
//!   silently (a debug line; `vendor_sbt_meta_build_only` when only the
//!   meta-build resolves it); the per-candidate conditions refuse it.
//! - A pin already in `socket-patch-vendor.sbt` for this GA and base
//!   ([`gate::check_existing`], re-planned idempotently): advisories only,
//!   unless the build now declares the GA newer than the pin's base
//!   (`vendor_sbt_pin_declared_newer`, refused: the override would force it
//!   back down). A dependency digest that moved is re-verified against
//!   evidence resolved since (fresh, newer than the generated file) and
//!   then recorded anew ([`GatePass::deps_digest`]); without such evidence
//!   it is `vendor_sbt_pin_unverifiable`. A base version still resolved is
//!   `vendor_sbt_override_shadowed`, the suffixed version served from
//!   outside the vendored tree is `vendor_sbt_resolved_elsewhere`. Evidence
//!   older than the generated file proves nothing about the pin (sbt has
//!   not resolved since it was written) and is not checked.
//!
//! The digest a pin records is always the distilled document's
//! ([`ResolutionDoc::deps_digest`], every build source the walk read), the
//! same definition the hosted rewriter uses.
//!
//! The owned-file states (modified, foreign) are the planner's refusals
//! (`vendor::jvm::sbt`); the gate reads the file only to find an existing
//! pin.

use std::path::Path;

use super::{JvmRefusal, JvmWarning, Shape};
use crate::crawlers::jvm_cache::debug_log;
use crate::formats::sbt::build::declared_newer;
use crate::formats::sbt::evidence::ResolutionDoc;
use crate::formats::sbt::gate::{self, GateRefusal, GateWarning};
use crate::formats::sbt::owned_file::{
    self, SbtFileMode, SbtPin, VENDORED_FILE, VENDORED_REPO_REL,
};
use crate::vendor::common::refused;
use crate::vendor::{VendorOutcome, VendorWarning};

/// Every code a [`GateStop::Skip`] / [`GateStop::Silent`] carries into its
/// [`VendorOutcome::Refused`]: an expected skip (exit 0, a `skipped` event
/// naming why), never a failure, and never counted as applied.
pub const SKIP_CODES: &[&str] = &[
    "vendor_sbt_no_resolution_evidence",
    "vendor_sbt_resolution_incomplete",
    "vendor_sbt_resolution_stale",
    "vendor_sbt_meta_build_only",
    NOT_RESOLVED,
    "vendor_scala_cli_resolution_missing",
    "vendor_scala_cli_resolution_stale",
    "vendor_scala_cli_not_resolved",
];

/// The code of a [`GateStop::Silent`] outcome.
pub const NOT_RESOLVED: &str = "vendor_jvm_not_resolved";

/// The remedy every run-level skip names.
const UPDATE_REMEDY: &str =
    "run `sbt update` (or `sbt Test/compile`) for the whole build, then re-run socket-patch";

/// Why the gate stopped a patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateStop {
    /// A run-level condition: nothing is vendored, the run still succeeds.
    Skip(JvmWarning),
    /// A per-patch refusal.
    Refuse(JvmRefusal),
    /// The build does not resolve the GA: nothing to vendor, no warning.
    Silent,
}

impl GateStop {
    /// The vendor outcome for a stopped patch: a refusal. A run-level skip
    /// (and the silent not-resolved one) refuses with a [`SKIP_CODES`]
    /// code, which the CLI records as an expected skip: nothing was
    /// vendored, so it is never reported applied.
    pub(crate) fn into_outcome(self, purl: &str) -> VendorOutcome {
        match self {
            GateStop::Refuse(r) => refused(r.code, r.detail),
            GateStop::Skip(w) => refused(w.code, w.detail),
            GateStop::Silent => refused(
                NOT_RESOLVED,
                format!("no project of the build resolves {purl}; nothing to vendor"),
            ),
        }
    }

    /// The `(code, detail)` this stop reports.
    pub fn code_and_detail(&self, purl: &str) -> (&'static str, String) {
        match self {
            GateStop::Refuse(r) => (r.code, r.detail.clone()),
            GateStop::Skip(w) => (w.code, w.detail.clone()),
            GateStop::Silent => (
                NOT_RESOLVED,
                format!("no project of the build resolves {purl}; nothing to vendor"),
            ),
        }
    }
}

/// A patch the gate let through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatePass {
    /// The advisories to carry.
    pub warnings: Vec<JvmWarning>,
    /// The dependency digest the sbt pin records (`None`: not an sbt build,
    /// or the walk read no build source; the planner then computes its
    /// own).
    pub deps_digest: Option<String>,
}

/// [`GatePass`] as vendor warnings.
#[derive(Debug, Clone, Default)]
pub(crate) struct ShapePass {
    pub warnings: Vec<VendorWarning>,
    pub deps_digest: Option<String>,
}

/// The gate of a project of `shape` ([`check`] for sbt,
/// [`super::coursier_gate::check`] for scala-cli, none otherwise).
pub(crate) fn for_shape(
    shape: Shape,
    project_root: &Path,
    g: &str,
    a: &str,
    base: &str,
) -> Result<ShapePass, GateStop> {
    let pass = match shape {
        Shape::Sbt => check(project_root, g, a, base)?,
        Shape::ScalaCli => GatePass {
            warnings: super::coursier_gate::check(project_root, g, a, base)?,
            deps_digest: None,
        },
        _ => GatePass::default(),
    };
    Ok(ShapePass {
        warnings: pass
            .warnings
            .into_iter()
            .map(|w| VendorWarning::new(w.code, w.detail))
            .collect(),
        deps_digest: pass.deps_digest,
    })
}

/// Gate vendoring `g:a` at upstream `base` into the sbt build at
/// `project_root`.
pub fn check(project_root: &Path, g: &str, a: &str, base: &str) -> Result<GatePass, GateStop> {
    let doc = crate::crawlers::sbt_evidence::distill(project_root);
    let existing = existing_pin(project_root, g, a);
    decide(&doc, existing.as_ref(), g, a, base)
}

/// The pin `socket-patch-vendor.sbt` holds for `g:a`, when the file parses
/// as socket-patch's own (FIFO-safe read).
fn existing_pin(project_root: &Path, g: &str, a: &str) -> Option<SbtPin> {
    let bytes =
        crate::utils::fs::read_regular_to_bytes_sync(&project_root.join(VENDORED_FILE)).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let file = owned_file::parse(SbtFileMode::Vendored, &text).ok()?;
    file.pins
        .into_values()
        .find(|p| p.group == g && p.artifact == a)
}

fn warning(code: &'static str, detail: impl Into<String>) -> JvmWarning {
    JvmWarning {
        code,
        detail: detail.into(),
    }
}

/// [`check`] over a distilled `doc` and the `existing` pin for `g:a`.
pub(crate) fn decide(
    doc: &ResolutionDoc,
    existing: Option<&SbtPin>,
    g: &str,
    a: &str,
    base: &str,
) -> Result<GatePass, GateStop> {
    let ga = format!("{g}:{a}");
    let newer = declared_newer(&doc.declared_deps, g, a, base);
    if let Some(pin) = existing.filter(|p| p.base == base) {
        if !newer.is_empty() {
            return Err(GateStop::Refuse(JvmRefusal {
                code: "vendor_sbt_pin_declared_newer",
                detail: format!(
                    "the build now declares {ga} {}, but {VENDORED_FILE} forces the patched {} \
                     (base {base}), a downgrade sbt's load-time check refuses; revert the patch \
                     (`socket-patch vendor --revert`), or declare {base} again",
                    newer.join(", "),
                    pin.sv
                ),
            }));
        }
        return Ok(existing_advisories(doc, pin, g, a));
    }
    // Evidence resolved under an earlier pin (a patch update) shows the
    // suffixed version whatever the build declares now.
    if !newer.is_empty() {
        return Err(GateStop::Refuse(JvmRefusal {
            code: "vendor_sbt_version_conflict",
            detail: format!(
                "the build declares {ga} {} but the patch is for {base}; a build-wide pin would \
                 downgrade it",
                newer.join(", ")
            ),
        }));
    }
    let res = doc.resolution.as_ref();
    match gate::check_new(res, doc.declared.as_ref(), doc.stale, g, a, base) {
        Ok(warnings) => Ok(GatePass {
            warnings: warnings.into_iter().map(|w| advisory(w, &ga)).collect(),
            deps_digest: (!doc.deps_digest.is_empty()).then(|| doc.deps_digest.clone()),
        }),
        Err(GateRefusal::Missing) => {
            let why = doc
                .read_error
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default();
            Err(GateStop::Skip(warning(
                "vendor_sbt_no_resolution_evidence",
                format!(
                    "no readable sbt resolution evidence under target/{why}; {ga} not vendored: {UPDATE_REMEDY}"
                ),
            )))
        }
        Err(GateRefusal::Incomplete { missing }) => {
            let which = if missing.is_empty() {
                "the build's project definitions cannot be read statically (a computed \
                 `Project(...)`, `projectMatrix` or `crossProject`), so not every project's \
                 resolution can be checked"
                    .to_string()
            } else {
                format!(
                    "these projects have no sbt resolution evidence: {}",
                    missing.join(", ")
                )
            };
            Err(GateStop::Skip(warning(
                "vendor_sbt_resolution_incomplete",
                format!("{which}; {ga} not vendored: {UPDATE_REMEDY}"),
            )))
        }
        Err(GateRefusal::Stale) => Err(GateStop::Skip(warning(
            "vendor_sbt_resolution_stale",
            format!(
                "a build source is newer than sbt's resolution evidence; {ga} not vendored: \
                 {UPDATE_REMEDY} (`sbt clean update` if this persists)"
            ),
        ))),
        Err(GateRefusal::NotResolved { meta_build_only }) => {
            if meta_build_only {
                return Err(GateStop::Skip(warning(
                    "vendor_sbt_meta_build_only",
                    format!(
                        "{ga} is resolved only by the meta-build (sbt plugins under project/), \
                         which a library pin does not reach; not vendored"
                    ),
                )));
            }
            debug_log(&format!(
                "vendor_sbt_not_resolved: no project of the sbt build resolves {ga}; skipped"
            ));
            Err(GateStop::Silent)
        }
        Err(GateRefusal::VersionConflict { found }) => Err(GateStop::Refuse(JvmRefusal {
            code: "vendor_sbt_version_conflict",
            detail: format!(
                "the build resolves {ga} at {} but the patch is for {base}; a build-wide pin \
                 would change the version some project resolves",
                found.join(", ")
            ),
        })),
        Err(GateRefusal::ScalaRuntime) => Err(GateStop::Refuse(JvmRefusal {
            code: "vendor_sbt_scala_runtime_unsupported",
            detail: format!(
                "{ga} is the Scala runtime / compiler, which sbt pins through scalaVersion; \
                 not vendored"
            ),
        })),
        Err(GateRefusal::Classifier { found }) => Err(GateStop::Refuse(JvmRefusal {
            code: "vendor_sbt_classifier_unsupported",
            detail: format!(
                "the build resolves {ga} with the classifier(s) {}, which the patched jar \
                 does not replace",
                found.join(", ")
            ),
        })),
        // Only `check_existing` refuses with this.
        Err(GateRefusal::ResolvedElsewhere { paths }) => Err(GateStop::Refuse(JvmRefusal {
            code: "vendor_sbt_resolved_elsewhere",
            detail: format!("{ga} resolves from {}", display_paths(&paths)),
        })),
    }
}

/// The advisories on a pin already written for `g:a` at its base, and the
/// digest it keeps recording.
fn existing_advisories(doc: &ResolutionDoc, pin: &SbtPin, g: &str, a: &str) -> GatePass {
    let ga = format!("{g}:{a}");
    let mut out = Vec::new();
    // The digest comes from the build sources alone: only a walk that read
    // none (a cap) leaves it empty, a malformed record does not.
    let moved = !doc.deps_digest.is_empty() && pin.deps_digest != doc.deps_digest;
    // Only evidence sbt resolved after the change (fresh, and newer than
    // the generated file) re-verifies a pin whose dependencies moved.
    let fresh = doc.resolution.is_some() && !doc.stale && !doc.wiring_newer;
    if moved && !fresh {
        out.push(warning(
            "vendor_sbt_pin_unverifiable",
            format!(
                "the build's dependencies changed since {ga} was pinned (digest {} → {}); \
                 run `sbt update`, then re-run socket-patch to re-check the pin still resolves \
                 {}",
                pin.deps_digest, doc.deps_digest, pin.sv
            ),
        ));
    }
    let mut verified = true;
    if !doc.wiring_newer {
        let repo = doc.root.join(VENDORED_REPO_REL);
        let pinned_bytes = |path: &Path| doc.holds_pinned_bytes(path, &pin.jar_sha256);
        match gate::check_existing(doc.resolution.as_ref(), g, a, &pin.sv, &repo, &pinned_bytes) {
            Ok(warnings) => {
                verified = warnings.is_empty();
                out.extend(warnings.into_iter().map(|w| advisory(w, &ga)));
            }
            Err(GateRefusal::ResolvedElsewhere { paths }) => {
                verified = false;
                out.push(warning(
                    "vendor_sbt_resolved_elsewhere",
                    format!(
                        "{ga} {} resolves from outside {VENDORED_REPO_REL}: {}; another \
                         repository serves the pinned version",
                        pin.sv,
                        display_paths(&paths)
                    ),
                ))
            }
            Err(_) => verified = false,
        }
    }
    let deps_digest = if moved && fresh && verified {
        doc.deps_digest.clone()
    } else {
        pin.deps_digest.clone()
    };
    GatePass {
        warnings: out,
        deps_digest: Some(deps_digest),
    }
}

fn advisory(w: GateWarning, ga: &str) -> JvmWarning {
    match w {
        GateWarning::OverrideShadowed { evidence } => warning(
            "vendor_sbt_override_shadowed",
            format!(
                "sbt still resolves the unpatched {ga} in {} (a project-level \
                 `dependencyOverrides :=` shadows the generated one)",
                evidence.join(", ")
            ),
        ),
        GateWarning::MetaBuildOnly => warning(
            "vendor_sbt_meta_build_only",
            format!("{ga} is also resolved by the meta-build, which the pin does not reach"),
        ),
    }
}

fn display_paths(paths: &[std::path::PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    use super::*;
    use crate::formats::sbt::JvmResolution;

    const G: &str = "org.apache.commons";
    const A: &str = "commons-lang3";
    const SV: &str = "3.11-socket.abcdef12";

    fn ga(g: &str, a: &str) -> (String, String) {
        (g.to_string(), a.to_string())
    }

    fn res(versions: &[&str]) -> JvmResolution {
        let mut r = JvmResolution {
            projects_seen: BTreeSet::from([".".to_string()]),
            ..Default::default()
        };
        for v in versions {
            r.modules
                .entry(ga(G, A))
                .or_default()
                .entry(v.to_string())
                .or_default()
                .insert(format!("target/x:compile@{v}"));
            r.in_scope.insert(ga(G, A));
        }
        r
    }

    fn doc(r: Option<JvmResolution>) -> ResolutionDoc {
        ResolutionDoc {
            root: PathBuf::from("/w"),
            resolution: r,
            declared: Some(BTreeSet::from([".".to_string()])),
            deps_digest: "0123abcd".into(),
            ..Default::default()
        }
    }

    fn pin() -> SbtPin {
        SbtPin {
            uuid: "abcdef12-0000-4000-8000-000000000001".into(),
            group: G.into(),
            artifact: A.into(),
            base: "3.11".into(),
            sv: SV.into(),
            pom_sha256: "0".repeat(64),
            jar_sha256: "1".repeat(64),
            deps_digest: "0123abcd".into(),
            index_url: None,
        }
    }

    fn code(r: Result<GatePass, GateStop>) -> Vec<&'static str> {
        match r {
            Ok(p) => p.warnings.iter().map(|w| w.code).collect(),
            Err(GateStop::Skip(w)) => vec!["skip", w.code],
            Err(GateStop::Refuse(r)) => vec!["refuse", r.code],
            Err(GateStop::Silent) => vec!["silent"],
        }
    }

    #[test]
    fn new_pins_split_run_level_skips_from_refusals() {
        let ok = doc(Some(res(&["3.11"])));
        assert!(code(decide(&ok, None, G, A, "3.11")).is_empty());
        let cases: Vec<(ResolutionDoc, &str, &str, Vec<&str>)> = vec![
            (
                doc(None),
                G,
                A,
                vec!["skip", "vendor_sbt_no_resolution_evidence"],
            ),
            (
                ResolutionDoc {
                    declared: None,
                    ..ok.clone()
                },
                G,
                A,
                vec!["skip", "vendor_sbt_resolution_incomplete"],
            ),
            (
                ResolutionDoc {
                    declared: Some(BTreeSet::from([".".into(), "b".into()])),
                    ..ok.clone()
                },
                G,
                A,
                vec!["skip", "vendor_sbt_resolution_incomplete"],
            ),
            (
                ResolutionDoc {
                    stale: true,
                    ..ok.clone()
                },
                G,
                A,
                vec!["skip", "vendor_sbt_resolution_stale"],
            ),
            (ok.clone(), "com.x", "y", vec!["silent"]),
            (
                ok.clone(),
                "org.scala-lang",
                "scala-library",
                vec!["refuse", "vendor_sbt_scala_runtime_unsupported"],
            ),
            (
                doc(Some(res(&["3.11", "3.12.0"]))),
                G,
                A,
                vec!["refuse", "vendor_sbt_version_conflict"],
            ),
        ];
        for (d, g, a, want) in cases {
            assert_eq!(code(decide(&d, None, g, a, "3.11")), want, "{g}:{a}");
        }
        let mut meta = res(&[]);
        meta.meta_build.insert(ga(G, A));
        assert_eq!(
            code(decide(&doc(Some(meta)), None, G, A, "3.11")),
            ["skip", "vendor_sbt_meta_build_only"]
        );
        let mut cl = res(&["3.11"]);
        cl.classifiers
            .insert(ga(G, A), BTreeSet::from(["tests".to_string()]));
        assert_eq!(
            code(decide(&doc(Some(cl)), None, G, A, "3.11")),
            ["refuse", "vendor_sbt_classifier_unsupported"]
        );
        // The read error names why there is no evidence.
        let unreadable = ResolutionDoc {
            read_error: Some("over the cap".into()),
            ..doc(None)
        };
        let Err(GateStop::Skip(w)) = decide(&unreadable, None, G, A, "3.11") else {
            panic!()
        };
        assert!(w.detail.contains("over the cap"), "{}", w.detail);
    }

    #[test]
    fn existing_pins_carry_advisories_only() {
        let p = pin();
        let repo_jar = PathBuf::from("/w/.socket/vendor/maven2/org/apache/commons/x.jar");
        let mut verified = res(&[SV]);
        verified
            .artifacts
            .entry((G.into(), A.into(), SV.into()))
            .or_default()
            .insert(repo_jar);
        assert!(code(decide(&doc(Some(verified.clone())), Some(&p), G, A, "3.11")).is_empty());
        // No evidence, stale or a conflict: the existing pin is re-planned.
        assert!(code(decide(&doc(None), Some(&p), G, A, "3.11")).is_empty());
        let stale = ResolutionDoc {
            stale: true,
            ..doc(Some(res(&["3.12.0"])))
        };
        assert!(code(decide(&stale, Some(&p), G, A, "3.11")).is_empty());
        // Shadowed: the base still resolves.
        assert_eq!(
            code(decide(
                &doc(Some(res(&["3.11", SV]))),
                Some(&p),
                G,
                A,
                "3.11"
            )),
            ["vendor_sbt_override_shadowed"]
        );
        // ...unless the evidence predates the wiring.
        let before = ResolutionDoc {
            wiring_newer: true,
            ..doc(Some(res(&["3.11"])))
        };
        assert!(code(decide(&before, Some(&p), G, A, "3.11")).is_empty());
        // Served from elsewhere.
        let mut elsewhere = verified.clone();
        elsewhere
            .artifacts
            .get_mut(&(G.into(), A.into(), SV.into()))
            .unwrap()
            .insert(PathBuf::from("/root/.ivy2/local/x.jar"));
        assert_eq!(
            code(decide(
                &doc(Some(elsewhere.clone())),
                Some(&p),
                G,
                A,
                "3.11"
            )),
            ["vendor_sbt_resolved_elsewhere"]
        );
        // ...unless that copy holds the pinned bytes (content, not place).
        let same_bytes = ResolutionDoc {
            artifact_sha256: [(
                PathBuf::from("/root/.ivy2/local/x.jar"),
                p.jar_sha256.clone(),
            )]
            .into(),
            ..doc(Some(elsewhere))
        };
        assert!(code(decide(&same_bytes, Some(&p), G, A, "3.11")).is_empty());
        // The build's dependencies moved since the pin: re-verified by
        // fresh evidence, the new digest is recorded...
        let moved = ResolutionDoc {
            deps_digest: "ffffffff".into(),
            ..doc(Some(verified.clone()))
        };
        let pass = decide(&moved, Some(&p), G, A, "3.11").unwrap();
        assert!(pass.warnings.is_empty(), "{:?}", pass.warnings);
        assert_eq!(pass.deps_digest.as_deref(), Some("ffffffff"));
        // ...stale evidence (or none) cannot, and the old digest is kept.
        let moved = ResolutionDoc {
            stale: true,
            ..moved
        };
        assert_eq!(
            code(decide(&moved, Some(&p), G, A, "3.11")),
            ["vendor_sbt_pin_unverifiable"]
        );
        assert_eq!(
            decide(&moved, Some(&p), G, A, "3.11")
                .unwrap()
                .deps_digest
                .as_deref(),
            Some("0123abcd")
        );
        // An unchanged pin keeps its digest; a new one records the doc's.
        assert_eq!(
            decide(&doc(Some(verified)), Some(&p), G, A, "3.11")
                .unwrap()
                .deps_digest
                .as_deref(),
            Some("0123abcd")
        );
        assert_eq!(
            decide(&doc(Some(res(&["3.11"]))), None, G, A, "3.11")
                .unwrap()
                .deps_digest
                .as_deref(),
            Some("0123abcd")
        );
        // ...still checked when a record is malformed (the digest reads only
        // the build sources), never when the walk read nothing.
        let malformed = ResolutionDoc {
            resolution: None,
            read_error: Some("malformed".into()),
            ..moved.clone()
        };
        assert_eq!(
            code(decide(&malformed, Some(&p), G, A, "3.11")),
            ["vendor_sbt_pin_unverifiable"]
        );
        let capped = ResolutionDoc {
            read_error: Some("over the cap".into()),
            deps_digest: String::new(),
            ..doc(None)
        };
        assert!(code(decide(&capped, Some(&p), G, A, "3.11")).is_empty());
        // A pin for another base is no existing pin: the new-pin gate runs.
        assert_eq!(
            code(decide(&doc(Some(res(&["3.11"]))), Some(&p), G, A, "3.12.0")),
            ["refuse", "vendor_sbt_version_conflict"]
        );
    }

    #[test]
    fn a_declared_bump_refuses_the_existing_pin() {
        let p = pin();
        let bumped = ResolutionDoc {
            declared_deps: [crate::formats::sbt::build::DepLiteral {
                group: G.into(),
                op: "%".into(),
                artifact: A.into(),
                version: "3.12.0".into(),
            }]
            .into(),
            ..doc(Some(res(&[SV])))
        };
        assert_eq!(
            code(decide(&bumped, Some(&p), G, A, "3.11")),
            ["refuse", "vendor_sbt_pin_declared_newer"]
        );
        // A patch update over evidence resolved under the old pin.
        let other = SbtPin {
            base: "3.10".into(),
            ..p
        };
        assert_eq!(
            code(decide(&bumped, Some(&other), G, A, "3.11")),
            ["refuse", "vendor_sbt_version_conflict"]
        );
        // Declaring the base (or older) again is fine.
        let same = ResolutionDoc {
            declared_deps: [crate::formats::sbt::build::DepLiteral {
                group: G.into(),
                op: "%".into(),
                artifact: A.into(),
                version: "3.11".into(),
            }]
            .into(),
            ..doc(Some(res(&[SV])))
        };
        assert!(code(decide(&same, Some(&pin()), G, A, "3.11")).is_empty());
    }

    #[test]
    fn into_outcome_maps_every_stop() {
        // Skips refuse with a skip code: never a successful (applied) no-op.
        assert!(matches!(
            GateStop::Silent.into_outcome("pkg:maven/g/a@1"),
            VendorOutcome::Refused {
                code: NOT_RESOLVED,
                ..
            }
        ));
        assert!(matches!(
            GateStop::Skip(warning("vendor_sbt_resolution_stale", "x"))
                .into_outcome("pkg:maven/g/a@1"),
            VendorOutcome::Refused {
                code: "vendor_sbt_resolution_stale",
                ..
            }
        ));
        assert!(matches!(
            GateStop::Refuse(JvmRefusal {
                code: "vendor_sbt_version_conflict",
                detail: String::new()
            })
            .into_outcome("pkg:maven/g/a@1"),
            VendorOutcome::Refused {
                code: "vendor_sbt_version_conflict",
                ..
            }
        ));
        for code in [
            "vendor_sbt_no_resolution_evidence",
            "vendor_sbt_meta_build_only",
            "vendor_scala_cli_not_resolved",
        ] {
            assert!(SKIP_CODES.contains(&code), "{code}");
        }
        assert!(!SKIP_CODES.contains(&"vendor_sbt_version_conflict"));
    }

    #[test]
    fn check_reads_the_disk_build() {
        // An sbt build with no evidence: one run-level skip.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("project")).unwrap();
        std::fs::write(
            tmp.path().join("project/build.properties"),
            "sbt.version=1.9.9\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("build.sbt"), "").unwrap();
        assert_eq!(
            code(check(tmp.path(), G, A, "3.11")),
            ["skip", "vendor_sbt_no_resolution_evidence"]
        );
        // The probe matrix: lang3 3.11 has a `tests` classifier, gson is
        // clean.
        let root = tmp.path().join("x");
        crate::crawlers::sbt_evidence::stage_fixture(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sbt/evidence/1.9.9/matrix"),
            &root,
        );
        assert_eq!(
            code(check(&root, G, A, "3.11")),
            ["refuse", "vendor_sbt_classifier_unsupported"]
        );
        assert!(code(check(&root, "com.google.code.gson", "gson", "2.8.9")).is_empty());
        assert_eq!(
            code(check(&root, "com.google.code.gson", "gson", "2.10.1")),
            ["refuse", "vendor_sbt_version_conflict"]
        );
    }
}
