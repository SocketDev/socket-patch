//! The one vendored-mode backend: [`VendoredBackend`] with its three
//! operations, shared by every command that vendors, un-vendors or repairs.
//!
//! * [`VendoredBackend::apply`] downloads verified server artifacts and
//!   persists their wiring and ledger entries through `vendor_records_reusing`.
//! * [`VendoredBackend::revert`] restores the recorded project wiring.
//! * [`VendoredBackend::repair`] redownloads missing or corrupt artifacts,
//!   preserving their recorded identities, lockfiles and ledger.
//!
//! The backends themselves (`dispatch_vendor_one`, `dispatch_revert_one*`)
//! stay in `vendor.rs`; this module is the policy layer over them.

pub(crate) mod repair;

use std::collections::HashMap;
use std::path::Path;

use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::vendor::{
    save_state, RevertOpts, RevertOutcome, VendorServiceConfig, VendorState, VendorWarning,
};

use crate::args::GlobalArgs;
use crate::commands::vendor::{dispatch_revert_one_opts, vendor_records_reusing, EjectCapture};
use crate::ecosystem_dispatch::NpmCrawlSnapshot;
use crate::json_envelope::Envelope;

/// Stamp `details.mode` (`"vendored"` / `"hosted"`) on `events`: the
/// convention every envelope uses to tell a vendored- or hosted-leg event
/// from an agent-mode (manifest) one, which carries no mode. Existing
/// `details` keys are kept; an event with no `details` gets
/// `{"mode": ...}`.
pub(crate) fn tag_event_mode(events: &mut [crate::json_envelope::PatchEvent], mode: &str) {
    for event in events {
        match event.details.as_mut() {
            Some(serde_json::Value::Object(map)) => {
                map.insert("mode".to_string(), serde_json::json!(mode));
            }
            Some(_) => {}
            None => event.details = Some(serde_json::json!({ "mode": mode })),
        }
    }
}

/// The vendored-mode backend for one run: the run's global args and its
/// patch-service config (`--revert` does not need one).
pub(crate) struct VendoredBackend<'a> {
    /// The run's args re-rooted at the manifest's project
    /// ([`GlobalArgs::at_project_root`]): the ledger, its artifacts and the
    /// lockfile wiring they record always belong to one project.
    pub(crate) common: std::borrow::Cow<'a, GlobalArgs>,
    pub(crate) service: Option<&'a VendorServiceConfig>,
    /// See [`VendoredBackend::with_closing_lines`].
    pub(crate) closing_lines: Option<&'a ClosingLines<'a>>,
}

/// Lines for the human close of a vendor run to print under its summary
/// line, given the purls the run vendored or found already vendored.
pub(crate) type ClosingLines<'a> = dyn Fn(&[&str]) -> Vec<String> + Sync + 'a;

/// What [`VendoredBackend::apply`] vendors.
pub(crate) struct ApplyRequest<'a> {
    /// Patch records keyed by manifest purl.
    pub(crate) manifest: &'a PatchManifest,
    pub(crate) socket_dir: &'a Path,
    /// Loaded once by the caller under the apply lock.
    pub(crate) ledger: std::io::Result<VendorState>,
    /// `true` for manifest-free vendoring (`scan`/`get --mode vendored`,
    /// and repair of an entry with no manifest owner).
    pub(crate) detached: bool,
    /// `vendor --force`.
    pub(crate) force: bool,
    /// The npm half of a crawl this process already made over an untouched
    /// tree (see [`vendor_records_reusing`]).
    pub(crate) prior: Option<&'a NpmCrawlSnapshot>,
    /// The hosted→vendored eject's hand-back: every project file the run's
    /// group commit wrote, with the bytes it held before (the eject's
    /// rollback undoes exactly these), and the wired flavors. With it, the
    /// run's human summary and "Next steps:" are left to the eject, which
    /// prints them only once it knows the eject stands.
    /// The records are exact lockfile-selected patches with their hosted
    /// wiring already restored upstream; skip installed-package discovery
    /// and per-package hosted takeover.
    pub(crate) eject: Option<&'a mut EjectCapture>,
}

impl<'a> VendoredBackend<'a> {
    pub(crate) fn new(common: &'a GlobalArgs, service: Option<&'a VendorServiceConfig>) -> Self {
        Self {
            common: common.at_project_root(),
            service,
            closing_lines: None,
        }
    }

    /// Have [`VendoredBackend::apply`]'s human close print what `lines`
    /// returns under its summary line. `scan --mode vendored` uses it to
    /// say which advisories each vendored patch fixes.
    pub(crate) fn with_closing_lines(mut self, lines: Option<&'a ClosingLines<'a>>) -> Self {
        self.closing_lines = lines;
        self
    }

    /// Vendor `req.manifest`'s records. The caller holds the apply lock.
    ///
    /// Each package fails closed if its server artifact is unavailable.
    /// Returns whether any package failed.
    ///
    /// The engine future is boxed here — this is its transient frame, so no
    /// caller's poll frame embeds it (Windows' 1 MiB main-thread stack; see
    /// `scan_run_fits_windows_main_thread_stack`).
    pub(crate) async fn apply(&self, req: ApplyRequest<'_>, env: &mut Envelope) -> bool {
        let common: &GlobalArgs = &self.common;
        if !common.allow_patch_conflicts {
            if let Err(error) =
                super::user_patches::check(common, req.manifest.patches.keys()).await
            {
                if !common.json {
                    eprintln!("Error: {}", error.message);
                }
                env.mark_error(error);
                return true;
            }
        }
        let blobs = req.socket_dir.join("blobs");
        let sources = socket_patch_core::patch::apply::PatchSources {
            blobs_path: &blobs,
            mem_blobs: None,
        };
        let records = &req.manifest.patches;
        Box::pin(vendor_records_reusing(
            common,
            records,
            &sources,
            req.detached,
            req.force,
            env,
            self.service,
            req.ledger,
            req.prior,
            req.eject,
            self.closing_lines,
        ))
        .await
    }

    /// Revert the ledger entries `keys` (in order) with `opts`, mutating
    /// `state` and saving the ledger per reverted entry (crash-consistent).
    /// Silent: callers own the human lines and the event vocabulary. With
    /// `stop_on_failure` the loop ends after the first hard failure (a
    /// backend refusal or a ledger write failure), which is the last
    /// element returned — `remove` aborts there without touching the rest.
    pub(crate) async fn revert(
        &self,
        keys: &[String],
        state: &mut VendorState,
        opts: RevertOpts,
        stop_on_failure: bool,
    ) -> Vec<RevertedEntry> {
        let mut out = Vec::with_capacity(keys.len());
        // The gems a wet revert put back on their upstream entries: the
        // index of each one's element in `out`, and its purl. With the
        // patch record of each one the ledger alone owned (a detached
        // entry), which the entry takes with it.
        let mut unwound_gems: Vec<(usize, String)> = Vec::new();
        let mut gem_records = std::collections::BTreeMap::new();
        // The ledger's record of every unwound gem that has one, detached
        // or not: what proves an installed copy unpatched (#2214).
        let mut gem_ledger_records = std::collections::BTreeMap::new();
        for key in keys {
            let Some(entry) = state.entries.get(key).cloned() else {
                out.push(RevertedEntry {
                    key: key.clone(),
                    flavor: None,
                    warnings: Vec::new(),
                    progress: Vec::new(),
                    gem_install_upstream: false,
                    step: VendorRevertStep::Missing,
                });
                continue;
            };
            let flavor = entry.flavor.clone();
            let wiring_files: Vec<String> = entry.wiring.iter().map(|w| w.file.clone()).collect();
            let root = &self.common.cwd;
            let outcome = dispatch_revert_one_opts(&entry, root, opts).await;
            let step = if !outcome.success {
                VendorRevertStep::Failed(outcome.error.unwrap_or_else(|| "unknown error".into()))
            } else if outcome.kept_artifact {
                VendorRevertStep::Kept(KeepCause::of(&outcome))
            } else if opts.dry_run {
                VendorRevertStep::WouldRevert
            } else if opts.keep_artifact {
                VendorRevertStep::Preserved
            } else {
                state.entries.remove(key);
                match save_state(root, state).await {
                    Ok(()) => VendorRevertStep::Reverted,
                    Err(e) => VendorRevertStep::LedgerWriteFailed(e.to_string()),
                }
            };
            let mut warnings = outcome.warnings;
            let hard_failure = matches!(
                step,
                VendorRevertStep::Failed(_) | VendorRevertStep::LedgerWriteFailed(_)
            );
            let dry = matches!(step, VendorRevertStep::WouldRevert);
            // The wiring is back on the registry while the installed tree
            // may still hold the vendored build, which pip, PDM, uv and
            // Pipenv keep through a plain sync: name the reinstall.
            if dry || step.unwired() {
                crate::commands::pypi_reinstall::push_vendor_advisory(
                    root,
                    key,
                    flavor.as_deref(),
                    &wiring_files,
                    &mut warnings,
                )
                .await;
                // A dry run reads the still-vendored lock, whose bare
                // CHECKSUMS entry can't judge the archive: the wet run
                // names it.
                if !dry {
                    push_gem_stale_cache(
                        root,
                        &entry.ecosystem,
                        &entry.base_purl,
                        self.common.offline,
                        &mut warnings,
                    )
                    .await;
                    if is_gem(&entry.ecosystem) {
                        unwound_gems.push((out.len(), entry.base_purl.clone()));
                        if let Some(record) = &entry.record {
                            gem_ledger_records.insert(entry.base_purl.clone(), record.clone());
                            if entry.detached {
                                gem_records.insert(entry.base_purl.clone(), record.clone());
                            }
                        }
                    }
                }
            }
            out.push(RevertedEntry {
                key: key.clone(),
                flavor,
                warnings,
                progress: Vec::new(),
                gem_install_upstream: false,
                step,
            });
            if stop_on_failure && hard_failure {
                break;
            }
        }
        self.refresh_unwound_gems(&unwound_gems, &gem_records, &gem_ledger_records, &mut out)
            .await;
        out
    }

    /// Bundler loads the installed copies of the unwound gems again. One
    /// that a hosted scan replaced with the patched build before the gem
    /// was vendored still is that build, so the app would keep running the
    /// patch under an upstream lock, and `bundle pristine` would fail on
    /// the upstream checksum (#2083). One that agent mode patched in place
    /// before the gem was vendored still holds the patched files, and
    /// `records` (the record of each unwound gem that the ledger alone
    /// owned) is the last thing that can tell (#2093). Bring those copies back to the
    /// upstream gem as the hosted unwind does, and name what is left (the
    /// "Gem stale-install guard" section of CLI_CONTRACT.md). `ledger` is
    /// the ledger's record of every unwound gem that has one: it proves a
    /// copy that was never patched to be the upstream build.
    ///
    /// `--json` gets a note per refreshed copy and a warning per stale
    /// one, on the entry of its gem. A human run gets the progress lines on
    /// the last unwound gem's entry, so they print once every revert is
    /// reported, and ONE warning for the gems still on their patched build.
    async fn refresh_unwound_gems(
        &self,
        unwound: &[(usize, String)],
        records: &std::collections::BTreeMap<String, PatchRecord>,
        ledger: &std::collections::BTreeMap<String, PatchRecord>,
        out: &mut [RevertedEntry],
    ) {
        let Some((first, _)) = unwound.first() else {
            return;
        };
        let (first, last) = (*first, unwound[unwound.len() - 1].0);
        let purls: Vec<String> = unwound.iter().map(|(_, purl)| purl.clone()).collect();
        let records = self.ended_records(records).await;
        let records = &records;
        let refresh = crate::commands::gem_refresh::after_vendored_unwind(
            &self.common,
            &purls,
            records,
            ledger,
        )
        .await;
        for (index, purl) in unwound {
            if refresh.refreshed_installs.contains(purl) || refresh.upstream_installs.contains(purl)
            {
                out[*index].gem_install_upstream = true;
            }
        }
        let report = refresh.report;
        if self.common.json {
            for (code, detail) in report.warnings {
                // Each detail starts with the purl it is about.
                let index = unwound
                    .iter()
                    .find(|(_, purl)| {
                        detail
                            .strip_prefix(purl.as_str())
                            .is_some_and(|rest| rest.starts_with([' ', ':']))
                    })
                    .map_or(first, |(index, _)| *index);
                out[index].warnings.push(VendorWarning::new(code, detail));
            }
            return;
        }
        out[last].progress = report.progress;
        if let Some(summary) = &report.summary {
            out[first].warnings.push(VendorWarning::new(
                crate::commands::gem_refresh::Direction::Upstream.stale_code(),
                summary.paragraph(),
            ));
        }
    }

    /// The patch record each unwound gem's installed copies are judged by:
    /// `ledger` (the records of detached entries, which the ledger alone
    /// owned) without the gems `.socket/manifest.json` has a record for.
    /// The in-place patch of such a gem is agent mode's and on record
    /// there, so this unwind does not end it. A manifest that cannot be
    /// read proves nothing, so no gem is judged then.
    async fn ended_records(
        &self,
        ledger: &std::collections::BTreeMap<String, PatchRecord>,
    ) -> std::collections::BTreeMap<String, PatchRecord> {
        use socket_patch_core::utils::purl_key::PurlKey;
        if ledger.is_empty() {
            return Default::default();
        }
        let manifest = socket_patch_core::manifest::operations::read_manifest(
            &self.common.resolved_manifest_path(),
        )
        .await;
        let in_manifest: std::collections::HashSet<PurlKey> = match manifest {
            Ok(Some(manifest)) => manifest.patches.keys().map(|k| PurlKey::new(k)).collect(),
            Ok(None) => Default::default(),
            Err(_) => return Default::default(),
        };
        ledger
            .iter()
            .filter(|(purl, _)| !in_manifest.contains(&PurlKey::new(purl)))
            .map(|(purl, record)| (purl.clone(), record.clone()))
            .collect()
    }

    /// Dropping a vendored Go `replace` leaves a committed
    /// vendor/modules.txt still recording it, which breaks every default
    /// build until `go mod vendor` runs. The undo commands
    /// call this after [`Self::revert`]: it audits the Go consumer state
    /// once and returns the issues of the Go modules `reverted` unwired,
    /// each keyed by the ledger key of its entry. Not part of `revert`
    /// itself, whose forward-run caller (the manifest reconcile) audits
    /// once at the end of the run instead.
    pub(crate) async fn go_undo_warnings(
        &self,
        reverted: &[RevertedEntry],
    ) -> Vec<(String, VendorWarning)> {
        let unwired: Vec<(&str, String)> = reverted
            .iter()
            .filter(|e| e.step.unwired())
            .filter_map(|e| {
                socket_patch_core::utils::purl::parse_golang_purl(&e.key)
                    .map(|(module, _)| (e.key.as_str(), module.into_owned()))
            })
            .collect();
        if unwired.is_empty() {
            return Vec::new();
        }
        socket_patch_core::vendor::go_consumer_sync::audit(&self.common.cwd, &HashMap::new())
            .await
            .into_iter()
            .filter_map(|issue| {
                let (key, _) = unwired.iter().find(|(_, m)| m == issue.module())?;
                Some((
                    key.to_string(),
                    VendorWarning::new(issue.code(), issue.to_string()),
                ))
            })
            .collect()
    }
}

/// Whether a ledger entry's `ecosystem` is RubyGems.
fn is_gem(ecosystem: &str) -> bool {
    socket_patch_core::vendor::jvm::layout::ledger_ecosystem(ecosystem) == "gem"
}

/// Name each patched `<name>-<version>[-<platform>].gem` left in Bundler's
/// cache dir once the vendored ledger entry of `ecosystem` for `base_purl`
/// is unwired: a
/// `bundle cache` taken while a hosted pin was live keeps it there through
/// the takeover, and bundler installs from it again once the lock is back
/// on upstream. The hosted unwind raises the same warning.
pub(crate) async fn push_gem_stale_cache(
    root: &Path,
    ecosystem: &str,
    base_purl: &str,
    offline: bool,
    warnings: &mut Vec<VendorWarning>,
) {
    if !is_gem(ecosystem) {
        return;
    }
    for (code, detail) in
        socket_patch_core::patch::redirect::upstream::gem_stale_cache_after_unwind(
            root, base_purl, offline,
        )
        .await
    {
        warnings.push(VendorWarning::new(code, detail));
    }
}

/// One entry [`VendoredBackend::revert`] handled.
pub(crate) struct RevertedEntry {
    /// The ledger key.
    pub(crate) key: String,
    /// The entry's npm-family lockfile flavor, read before the revert (for
    /// the reinstall hints).
    pub(crate) flavor: Option<String>,
    /// The backend's advisories.
    pub(crate) warnings: Vec<VendorWarning>,
    /// Lines a human run prints to stdout after its own line for the
    /// entry: what the gem refresh replaced in the installed tree.
    pub(crate) progress: Vec<String>,
    /// No installed copy of the gem is left on the patched build: the
    /// unwind brought them back to the upstream one, or found them to be
    /// it already (a gem that was only ever vendored, #2214). Nothing of
    /// it is left for a reinstall.
    pub(crate) gem_install_upstream: bool,
    pub(crate) step: VendorRevertStep,
}

/// What one vendored ledger entry's revert did. The drift-keep and
/// `--preserve-state` rules are identical for every caller by construction.
pub(crate) enum VendorRevertStep {
    /// `key` has no ledger entry (a divergent ledger, or an earlier leg
    /// already reverted it): a silent no-op.
    Missing,
    /// The backend refused; nothing changed for this entry.
    Failed(String),
    /// The backend kept the artifact (see [`KeepCause`]). Per
    /// `RevertOutcome`'s contract the ledger entry — and any manifest
    /// record — must survive.
    Kept(KeepCause),
    /// Dry run: the revert (or, with `keep_artifact`, the unwire) would
    /// succeed. Nothing changed.
    WouldRevert,
    /// `keep_artifact`: wiring restored; artifact and ledger entry kept
    /// byte-identical. Its wiring records now describe already-reverted
    /// fragments, which later reverts replay as silent no-ops (the
    /// liveness contract), and a re-vendor re-wires from the live lock.
    Preserved,
    /// Reverted on disk, dropped from the ledger, ledger saved (per entry,
    /// so the run is crash-consistent like `vendor --revert`).
    Reverted,
    /// Reverted on disk and dropped from the in-memory ledger, but the
    /// ledger write failed.
    LedgerWriteFailed(String),
}

impl VendorRevertStep {
    /// The wiring is back on the registry (a dry run's `WouldRevert` is not).
    fn unwired(&self) -> bool {
        matches!(
            self,
            VendorRevertStep::Reverted
                | VendorRevertStep::Preserved
                | VendorRevertStep::LedgerWriteFailed(_)
        )
    }
}

/// Why a vendored revert kept the artifact and ledger entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum KeepCause {
    /// Drift-keep: the lock changed under us and the backend left both
    /// the wiring and the artifact alone.
    Drift,
    /// The recorded wiring was restored, but another project file (an
    /// exported requirements file) still installs from the artifact
    /// (`vendor_revert_residual_reference`). Nothing drifted: the
    /// way out is to point that file back at the registry release.
    Reference,
}

impl KeepCause {
    /// Why `outcome`, a revert that kept its artifact, kept it.
    pub(crate) fn of(outcome: &RevertOutcome) -> Self {
        if outcome.kept_for_residual_reference() {
            KeepCause::Reference
        } else {
            KeepCause::Drift
        }
    }

    /// The per-entry reason, after "`<what>` kept".
    pub(crate) fn reason(self) -> &'static str {
        match self {
            KeepCause::Drift => "lockfile wiring drifted",
            KeepCause::Reference => {
                "a project file still installs from the vendored artifact (see \
                 vendor_revert_residual_reference); the recorded wiring was restored"
            }
        }
    }

    /// The remedy that finishes the unwind, for `then` (the command to
    /// re-run).
    pub(crate) fn remedy(self, then: &str) -> String {
        match self {
            KeepCause::Drift => {
                format!("re-run `scan --mode vendored` to normalize, then {then}")
            }
            KeepCause::Reference => format!(
                "point the file named by vendor_revert_residual_reference back at the \
                 registry release (or re-export it from the restored lock), then {then}"
            ),
        }
    }
}

/// A patch-record map as the manifest view [`ApplyRequest::manifest`]
/// takes (no `setup` block — vendoring never reads it).
pub(crate) fn records_manifest(patches: HashMap<String, PatchRecord>) -> PatchManifest {
    PatchManifest {
        patches,
        setup: None,
    }
}
