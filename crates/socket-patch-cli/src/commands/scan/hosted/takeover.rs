//! The staged vendored → hosted mode takeover.
//!
//! A purl this run is about to redirect may still be VENDORED: for cargo a
//! committed `[patch.crates-io]` path entry, a detached Cargo.lock entry and
//! a committed copy; for the npm family a `file:./.socket/vendor/…` lock
//! resolution (plus a berry `resolutions` pin) and its committed tarball;
//! for golang the vendor-owned go.mod `replace` and its module copy; for
//! pypi the vendored lock / requirements source; for a Gradle build the
//! vendored JVM wiring — each with its vendored ledger entry. The hosted
//! rewriters cannot pin over that wiring, so the takeover reverts it first
//! (the per-purl machinery `vendor --revert` runs), which also hands the
//! rewriter the PRISTINE registry lock fragment to pin.
//!
//! Every step is staged in the run's [`GroupCommit`], never on disk:
//!
//! 1. [`Takeover::plan`] picks the purls in reach
//!    ([`socket_patch_core::hosted::takeover::in_reach`]) and refuses the
//!    ones that cannot be reverted at all (linked wiring, cargo wiring with
//!    no ledger entry).
//! 2. [`Takeover::stage`] reverts each purl into the overlay, under a
//!    savepoint: a revert that fails or keeps drifted wiring is rolled back
//!    and refused. A yarn-berry entry is first checked against the berry
//!    project gates on the pre-revert project (its revert re-renders
//!    `package.json`). The artifact deletions wait for the commit
//!    ([`GroupCommit::defer_removals`]).
//! 3. The hosted rewrite reads the overlay, so it plans against the
//!    reverted project. A staged purl it does not pin is RETRACTED
//!    ([`Takeover::retract`]): the whole overlay goes back to its pre-revert
//!    state, the purl is refused (it stays vendored, byte for byte) and the
//!    others are staged and rewritten again.
//! 4. The caller writes the hosted pins into the same overlay, saves the
//!    vendored ledger without the migrated entries, and commits once: the
//!    revert and the hosted pins reach the disk together or not at all.
//!
//! A dry run runs the same steps and drops the overlay instead of
//! committing, so it reports exactly what the wet run would do.

use std::collections::BTreeSet;

use socket_patch_core::hosted::engine::{Candidate, Refusal, SkippedPatch};
use socket_patch_core::patch::redirect::RewriteWarning;
use socket_patch_core::utils::group_commit::{GroupCommit, Savepoint};
use socket_patch_core::utils::purl::{canonical_purl, purl_parts, strip_purl_qualifiers};
use socket_patch_core::vendor::{RevertOutcome, VendorEntry, VendorState};

/// The warning that announces a staged takeover the run did not complete:
/// the purl stays vendored.
pub(super) const KEPT_VENDORED: &str = "redirect_takeover_kept_vendored";

/// The skip reason of a staged takeover whose purl the hosted rewrite did
/// not pin, when no rewriter warning names the cause.
const NOT_PINNED: &str = "redirect_takeover_not_pinned";

/// One purl whose vendored state the overlay holds reverted.
struct Staged {
    purl: String,
    uuid: String,
    entry: VendorEntry,
    /// The revert's own advisories that outlive the takeover (vlt's
    /// reinstall notice).
    advisories: Vec<serde_json::Value>,
}

/// A vendored → hosted takeover in progress (see the module docs).
pub(super) struct Takeover {
    /// The overlay as it was before any revert: what [`Self::retract`]
    /// rolls back to.
    base: Option<Savepoint>,
    /// The purls to revert, with their ledger entries, in candidate order.
    attempts: Vec<(String, String, VendorEntry)>,
    staged: Vec<Staged>,
    /// Refusals, in order.
    warnings: Vec<serde_json::Value>,
    /// Rewriter warnings that explained a retracted purl (the final rewrite
    /// no longer reports them once the purl left the rewrite set).
    explained: Vec<RewriteWarning>,
}

/// What a finished takeover did (or, on `--dry-run`, would do).
pub(super) struct Finished {
    /// Refusals and the per-purl takeover announcements, reported after the
    /// rewriters' own warnings.
    pub warnings: Vec<serde_json::Value>,
    /// The purls migrated (or to be migrated) from vendored to hosted.
    pub migrated: Vec<String>,
    /// The files their revert touches. Human output counts `rewritten ∪
    /// files`: a revert can touch a wiring file the hosted rewriter does not
    /// also rewrite (a Gemfile line, a uv source).
    pub files: BTreeSet<String>,
}

fn key(purl: &str) -> String {
    canonical_purl(strip_purl_qualifiers(purl))
}

impl Takeover {
    /// Pick the candidates in a takeover's reach (step 1). Refused purls
    /// move from `candidates` into `skipped`. `Err` is the linked-wiring
    /// refusal: nothing was written.
    pub(super) async fn plan(
        common: &crate::args::GlobalArgs,
        group: &GroupCommit,
        candidates: &mut Vec<Candidate>,
        vendor_state: &std::io::Result<VendorState>,
        skipped: &mut Vec<SkippedPatch>,
    ) -> Result<Self, Refusal> {
        use socket_patch_core::hosted::takeover;
        let mut out = Takeover {
            base: Some(group.savepoint()),
            attempts: Vec::new(),
            staged: Vec::new(),
            warnings: Vec::new(),
            explained: Vec::new(),
        };
        if !takeover::any_takeover_ecosystem(candidates.iter().map(|c| c.purl.as_str())) {
            return Ok(out);
        }
        let mut refused: Vec<String> = Vec::new();
        for candidate in candidates.iter() {
            let purl = &candidate.purl;
            let entry = vendor_state.as_ref().ok().and_then(|s| {
                socket_patch_core::vendor::lookup_entry(&s.entries, strip_purl_qualifiers(purl))
            });
            if !takeover::in_reach(purl, entry) {
                continue;
            }
            match entry {
                Some(entry) => out.attempts.push((
                    purl.clone(),
                    candidate.dep.patch_uuid.clone(),
                    entry.clone(),
                )),
                // No usable ledger entry. If socket-owned vendored wiring
                // for this crate is nevertheless present, the ledger is
                // missing or corrupt — the originals needed to revert are
                // unrecoverable, so redirecting on top would wedge the
                // project. Refuse. (Cargo-only probe: Socket-owned
                // `[patch.crates-io]` entries for exactly this name@version
                // in the root Cargo.toml or a legacy `.cargo/config*`. An
                // npm purl in this state falls through to the rewriters' own
                // per-flavor diagnostics.)
                None => {
                    let Some((_, name, version)) = purl
                        .starts_with("pkg:cargo/")
                        .then(|| purl_parts(purl))
                        .flatten()
                    else {
                        continue;
                    };
                    if socket_patch_core::vendor::cargo::socket_wiring_present(
                        &common.cwd,
                        &name,
                        &version,
                    )
                    .await
                    {
                        refused.push(purl.clone());
                        skipped.push(SkippedPatch::new(
                            purl,
                            &candidate.dep.patch_uuid,
                            "vendored_revert_failed",
                        ));
                        out.warnings.push(serde_json::json!({
                            "code": "redirect_vendored_revert_failed",
                            "detail": format!(
                                "{purl} has socket-owned vendored `[patch.crates-io]` \
                                 wiring but no usable vendored ledger entry \
                                 (.socket/vendor/state.json is missing or corrupt); NOT \
                                 redirected — restore the ledger or remove the vendored \
                                 wiring manually, then re-run"
                            ),
                        }));
                    }
                }
            }
        }
        // SYMLINK PRE-CHECK — the same rule as the hosted SYMLINK GUARD,
        // applied to each ledger entry's recorded wiring (the revert
        // backends also stage and rename over the file), dry runs included.
        let wiring = out
            .attempts
            .iter()
            .flat_map(|(_, _, entry)| entry.wiring.iter().map(|w| w.file.as_str()));
        if let Some(linked) = socket_patch_core::utils::fs::first_symlink(&common.cwd, wiring).await
        {
            return Err(socket_patch_core::hosted::engine::symlink_refusal(linked));
        }
        candidates.retain(|c| !refused.contains(&c.purl));
        Ok(out)
    }

    /// Whether any purl is (still) staged.
    pub(super) fn is_staged(&self) -> bool {
        !self.staged.is_empty()
    }

    /// Revert every pending attempt into `group`'s overlay (step 2). A
    /// revert that fails, or that leaves drifted wiring in place, is rolled
    /// back and refused.
    pub(super) async fn stage(
        &mut self,
        common: &crate::args::GlobalArgs,
        group: &GroupCommit,
        candidates: &mut Vec<Candidate>,
        skipped: &mut Vec<SkippedPatch>,
    ) {
        // Judged once, before any revert of this pass (`stage` runs on the
        // pre-takeover overlay, a retraction having rolled back to it).
        let berry_gate = if self.attempts.iter().any(|(_, _, e)| is_berry_entry(e)) {
            berry_project_gate(common).await
        } else {
            None
        };
        for (purl, uuid, entry) in std::mem::take(&mut self.attempts) {
            if let Some(gate) = berry_gate.as_ref().filter(|_| is_berry_entry(&entry)) {
                self.warnings
                    .push(serde_json::json!({ "code": &gate.code, "detail": &gate.detail }));
                self.warnings.push(kept_vendored(&purl, &gate.code));
                skipped.push(SkippedPatch::new(&purl, &uuid, &gate.code));
                candidates.retain(|c| c.purl != purl);
                continue;
            }
            let savepoint = group.savepoint();
            let outcome =
                crate::commands::vendor::dispatch_revert_one(&entry, &common.cwd, false).await;
            let refusal = if !outcome.success {
                Some(serde_json::json!({
                    "code": "redirect_vendored_revert_failed",
                    "detail": format!(
                        "{purl} is vendored and its vendored state could not be \
                         reverted ({}); NOT switched to hosted — run `socket-patch vendor \
                         --revert` to clean up, then re-run `scan --mode hosted`",
                        outcome.error.as_deref().unwrap_or("unknown error")
                    ),
                }))
            } else if revert_keeps_wiring(&outcome) {
                // A wiring record drifted and was left in place, so the
                // project may still resolve through the vendored artifact
                // and the ledger entry holds the only recorded originals
                // (the RevertOutcome contract): keep both and refuse,
                // exactly as `vendor --revert` reports it skipped.
                Some(drifted_takeover_warning(&purl))
            } else {
                None
            };
            if let Some(warning) = refusal {
                group.rollback_to(savepoint);
                self.warnings.push(warning);
                skipped.push(SkippedPatch::new(&purl, &uuid, "vendored_revert_failed"));
                candidates.retain(|c| c.purl != purl);
                continue;
            }
            let advisories = outcome
                .warnings
                .iter()
                .filter(|w| w.code == socket_patch_core::vendor::vlt_lock::REINSTALL_REQUIRED)
                .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail }))
                .collect();
            self.staged.push(Staged {
                purl,
                uuid,
                entry,
                advisories,
            });
        }
    }

    /// The staged purls the rewrite did not pin (`confirmed` is the
    /// rewrite's `(purl, uuid)` list).
    pub(super) fn unpinned(&self, confirmed: &[(String, String)]) -> Vec<String> {
        self.staged
            .iter()
            .filter(|s| !confirmed.iter().any(|(_, uuid)| *uuid == s.uuid))
            .map(|s| s.uuid.clone())
            .collect()
    }

    /// Undo every staged revert and refuse the purls of `unpinned` (uuids):
    /// they stay vendored. The rest are staged again from the pristine
    /// overlay (step 3); the caller then rewrites again. `warnings` are the
    /// rewrite's own warnings, which explain why a purl was not pinned.
    pub(super) async fn retract(
        &mut self,
        common: &crate::args::GlobalArgs,
        group: &GroupCommit,
        unpinned: &[String],
        warnings: &[RewriteWarning],
        candidates: &mut Vec<Candidate>,
        skipped: &mut Vec<SkippedPatch>,
    ) {
        if let Some(base) = self.base.take() {
            group.rollback_to(base);
        }
        self.base = Some(group.savepoint());
        for staged in std::mem::take(&mut self.staged) {
            if !unpinned.contains(&staged.uuid) {
                self.attempts.push((staged.purl, staged.uuid, staged.entry));
                continue;
            }
            let dep = candidates
                .iter()
                .find(|c| c.dep.patch_uuid == staged.uuid)
                .map(|c| &c.dep);
            let code = match skipped.iter().find(|s| s.uuid == staged.uuid) {
                // Already skipped with its own reason (unavailable wheel
                // metadata, a withheld artifact, ...).
                Some(skip) => skip.reason.clone(),
                None => {
                    let (code, explained) = explain(&staged.entry, dep, warnings);
                    skipped.push(SkippedPatch::new(&staged.purl, &staged.uuid, &code));
                    for w in explained {
                        if !self.explained.contains(&w) {
                            self.explained.push(w);
                        }
                    }
                    code
                }
            };
            self.warnings.push(kept_vendored(&staged.purl, &code));
            candidates.retain(|c| c.dep.patch_uuid != staged.uuid);
        }
        self.stage(common, group, candidates, skipped).await;
    }

    /// Settle the takeover once the rewrite pins every staged purl (step 4's
    /// bookkeeping): announce each one, and on a wet run drop its entry
    /// from the in-memory vendored ledger, which the caller saves into the
    /// overlay before the commit. `final_warnings` are the last rewrite's
    /// warnings: the explanations it no longer reports are carried here.
    pub(super) fn finish(
        self,
        dry_run: bool,
        vendor_state: &mut std::io::Result<VendorState>,
        final_warnings: &[RewriteWarning],
    ) -> Finished {
        let mut warnings: Vec<serde_json::Value> = self
            .explained
            .iter()
            .filter(|w| !final_warnings.contains(w))
            .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail }))
            .collect();
        warnings.extend(self.warnings);
        let mut migrated = Vec::new();
        let mut files = BTreeSet::new();
        for staged in self.staged {
            let purl = &staged.purl;
            warnings.push(if dry_run {
                serde_json::json!({
                    "code": "redirect_would_revert_vendored",
                    "detail": format!(
                        "{purl} is currently vendored; the hosted wiring will \
                         revert its vendored wiring, ledger entry, and committed \
                         artifact first, then switch to hosted (mode takeover)"
                    ),
                })
            } else {
                serde_json::json!({
                    "code": "redirect_takeover_reverted_vendored",
                    "detail": format!(
                        "{purl} was vendored; reverted its vendored wiring, ledger \
                         entry, and committed artifact before switching to hosted (mode \
                         takeover: the project is now fully hosted for this package)"
                    ),
                })
            });
            warnings.extend(staged.advisories);
            if !dry_run {
                if let Ok(state) = vendor_state.as_mut() {
                    state
                        .entries
                        .retain(|k, e| key(k) != key(purl) && key(&e.base_purl) != key(purl));
                }
            }
            files.extend(staged.entry.wiring.iter().map(|w| w.file.clone()));
            migrated.push(staged.purl);
        }
        Finished {
            warnings,
            migrated,
            files,
        }
    }
}

/// Why the rewrite did not pin a staged purl: the skip reason, and the
/// rewriter warnings that say so. In order: for a requirements entry wired
/// outside the root file, the reach the hosted rewriter lacks (#699); a
/// rewriter warning naming the package; the rewrite's first warning (a
/// lock-level refusal names no package); else [`NOT_PINNED`].
fn explain(
    entry: &VendorEntry,
    dep: Option<&socket_patch_core::patch::redirect::DepOverride>,
    warnings: &[RewriteWarning],
) -> (String, Vec<RewriteWarning>) {
    if let Err(w) = socket_patch_core::patch::redirect::preflight_requirements_takeover(entry) {
        return (w.code.clone(), vec![w]);
    }
    if let Some(w) = dep.and_then(|dep| {
        warnings
            .iter()
            .find(|w| names_package(&w.detail, &dep.name))
    }) {
        return (w.code.clone(), vec![w.clone()]);
    }
    match warnings.first() {
        Some(w) => (w.code.clone(), vec![w.clone()]),
        None => (NOT_PINNED.to_string(), Vec::new()),
    }
}

/// The [`KEPT_VENDORED`] warning for `purl`, naming the `code` that kept it.
fn kept_vendored(purl: &str, code: &str) -> serde_json::Value {
    serde_json::json!({
        "code": KEPT_VENDORED,
        "detail": format!(
            "{purl} is vendored, but hosted mode would not pin it ({code}); it stays \
             vendored — its vendored wiring, ledger entry and artifact are untouched"
        ),
    })
}

/// A vendored entry wired through the yarn-berry backend.
fn is_berry_entry(entry: &VendorEntry) -> bool {
    entry.ecosystem == "npm" && entry.flavor.as_deref() == Some("yarn-berry")
}

/// The yarn berry project gates (lock and root `package.json` line endings,
/// `cacheKey`, `.yarnrc.yml` `compressionLevel`), judged on the project as
/// it is BEFORE any yarn-berry entry's revert. The revert re-renders
/// `package.json` in its majority line ending, so a mixed manifest would
/// pass the hosted rewriter's own check afterwards, while both modes refuse
/// to rewrite a mixed one (#628): the takeover keeps such a package
/// vendored. The gate itself is the rewriter's
/// (`preflight_yarn_berry_hosted`, over the shared `berry_gates`).
async fn berry_project_gate(common: &crate::args::GlobalArgs) -> Option<RewriteWarning> {
    use socket_patch_core::utils::fs::read_regular_to_string;
    // An unreadable lock is left to the revert's own diagnostics.
    let lock = read_regular_to_string(&common.cwd.join("yarn.lock"))
        .await
        .ok()?;
    let manifest = read_regular_to_string(&common.cwd.join("package.json"))
        .await
        .ok();
    let yarnrc = read_regular_to_string(&common.cwd.join(".yarnrc.yml"))
        .await
        .ok();
    socket_patch_core::patch::redirect::preflight_yarn_berry_hosted(
        &lock,
        manifest.as_deref(),
        yarnrc.as_deref(),
    )
    .err()
}

/// Whether `detail` names the package `name` as a whole word.
fn names_package(detail: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let is_word = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | '@');
    detail.match_indices(name).any(|(at, _)| {
        let before = detail[..at].chars().next_back();
        let after = detail[at + name.len()..].chars().next();
        !before.is_some_and(|c| is_word(c) && c != '@' && c != '/')
            && !after.is_some_and(|c| is_word(c) && c != '@' && c != '.')
    })
}

/// Whether a takeover revert left vendored wiring in place: a drift-skipped
/// record, or a reverted file that still references the artifact dir.
fn revert_keeps_wiring(outcome: &RevertOutcome) -> bool {
    outcome.kept_artifact
        || outcome.drift_skipped()
        || outcome
            .warnings
            .iter()
            .any(|w| w.code == "vendor_revert_residual_reference")
}

/// The refusal for a takeover whose vendored wiring drifted since vendoring.
fn drifted_takeover_warning(purl: &str) -> serde_json::Value {
    serde_json::json!({
        "code": "redirect_vendored_revert_failed",
        "detail": format!(
            "{purl} is vendored and part of its vendored wiring was edited since \
             vendoring, so it is left in place; NOT switched to hosted — restore or \
             remove that wiring (`socket-patch vendor --revert` lists it), then re-run \
             `scan --mode hosted`"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_package_matches_whole_names_only() {
        assert!(names_package("the patched wheel for six==1.16.0 is", "six"));
        assert!(names_package("left-pad@1.3.0 has no checksum", "left-pad"));
        assert!(names_package("`six` is missing", "six"));
        assert!(!names_package("sixteen entries", "six"));
        assert!(!names_package("left-pad-extra@1", "left-pad"));
        assert!(!names_package("anything", ""));
    }
}
