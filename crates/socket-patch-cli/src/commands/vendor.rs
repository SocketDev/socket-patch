//! `socket-patch vendor` — committable vendoring of patched dependencies.
//!
//! Works like `apply`, but instead of patching installed packages in place it
//! ejects each patched package into `.socket/vendor/<eco>/<patch-uuid>/…` and
//! rewires the ecosystem's lockfile/config so the project consumes the
//! vendored copy. After committing `.socket/vendor/` + the lockfile edits, a
//! fresh checkout builds with the patched dependency on machines with no
//! socket-patch and no Socket API access. `--revert` restores the recorded
//! original lockfile fragments and removes the artifacts.
//!
//! The rest of the CLI is vendor-aware: `apply` yields ownership of
//! ledger-recorded purls, `rollback` skips them in its in-place leg and then
//! reverts them through its vendored leg, `remove` reverts vendoring as part
//! of removing a patch, `scan --prune` exempts vendored entries, and `scan`/`get --mode
//! vendored` drive this module's [`vendor_records`] engine directly in
//! DETACHED mode: every entry they write carries its patch record embedded
//! in the ledger and no `.socket/manifest.json` is ever written — this
//! command is the one manifest-driven writer (`detached: false`). See
//! CLI_CONTRACT.md "Ownership, state, and reversal".

use clap::Args;
use futures_util::StreamExt;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::constants::SOCKET_DIR;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::{verify_file_patch, PatchSources};
use socket_patch_core::patch::redirect::upstream::HostedPin;
use socket_patch_core::telemetry::{
    track_patch_vendor_failed, track_patch_vendored, TelemetryAuth,
};
use socket_patch_core::utils::concurrent::ordered_concurrent;
use socket_patch_core::utils::group_commit::{CommittedFile, GroupCommit};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::utils::socket_dir::remove_tree_and_prune;
use socket_patch_core::vendor::{
    self, ecosystem_dir_for_purl, load_state, lock_inventory, lookup_entry, lookup_entry_kv,
    save_state, save_state_shared, PackageSource, RevertOpts, RevertOutcome, VendorEntry,
    VendorOutcome, VendorServiceConfig, VendorState, VendorWarning,
};
use socket_patch_core::vex::time::now_rfc3339;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::apply::{representative_file, result_to_event, variant_matches_installed};
use crate::commands::bun_preflight::bun_vendor_preflight_pairs;
use crate::commands::lock_cli::acquire_or_emit;
use crate::commands::vendored_backend::{
    ApplyRequest, RevertedEntry, VendorRevertStep, VendoredBackend,
};
use crate::commands::vex::{
    generate_vex_from_manifest_path, generate_vex_without_manifest, ManifestlessVex, VexEmbedArgs,
};
use crate::commands::vlt_preflight::{vlt_refusal_for, vlt_vendor_preflight_pairs};
use crate::ecosystem_dispatch::{
    find_packages_for_rollback_reusing, npm_paths_by_identity, npm_paths_by_identity_in,
    partition_purls, NpmCrawlSnapshot,
};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, RunWarning, Status, VexSummary,
};
use crate::ui::{plural, StatusLine};

#[derive(Args)]
pub struct VendorArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Bypass the installed-variant probe for multi-release ecosystems
    /// (vendor every recorded release variant, not just the one whose
    /// bytes match the installed copy). Vendoring never reads the
    /// installed files' content: it commits the patch server's verified
    /// artifact, so a missing or locally edited file needs no flag.
    #[arg(
        short = 'f',
        long,
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub force: bool,

    /// Undo vendoring: restore the recorded original lockfile fragments and
    /// remove the `.socket/vendor/` artifacts. Works without a manifest.
    #[arg(
        long = "revert",
        env = "SOCKET_VENDOR_REVERT",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub revert: bool,

    /// Verify committed artifacts and JVM wiring offline without changing files.
    #[arg(long, conflicts_with = "revert")]
    pub check: bool,

    /// Also check suffixed Maven jars in this local repository for conflicting bytes.
    #[arg(long, requires = "check", hide_short_help = true)]
    pub local_repo: Option<std::path::PathBuf>,

    /// On a successful vendor, also generate an OpenVEX 0.2.0 document
    /// (same contract as `apply --vex`).
    #[command(flatten)]
    pub vex: VexEmbedArgs,
}

/// Refusal codes that are expected skips, not command failures: the user's
/// request is still fully satisfied when these are the only non-successes.
fn refusal_is_benign(code: &str) -> bool {
    matches!(code, "vendor_unsupported_ecosystem" | "already_vendored")
        // An older vendored patch kept in force (see [`keep_older_vendored_patch`]).
        || matches!(code, vendor::VENDOR_PREBUILT_PENDING | vendor::VENDOR_PREBUILT_UNAVAILABLE)
        || socket_patch_core::vendor::jvm::sbt_gate::SKIP_CODES.contains(&code)
}

/// #954: the patch service has no artifact for `uuid` yet (still building)
/// or at all (`build_failed`, `not_found`, …) — the backend's failed `Done`
/// carries [`vendor::VENDOR_PREBUILT_PENDING`] /
/// [`vendor::VENDOR_PREBUILT_UNAVAILABLE`] — while the ledger already holds
/// `purl` vendored at another patch. The backend touched nothing, so that
/// older vendoring is still in force: like hosted mode, which keeps its pin
/// and skips the upgrade, the package is a benign skip under the unserved
/// code instead of a failure that would fail every re-run until the server
/// builds the artifact. Only an older vendoring whose wiring is still live
/// (the [`Discovery::vendor_entry_live`] verdict `vendor --check` and `vex`
/// use) is in force: once a relock dropped its `.socket/vendor/` reference
/// the package is patched in neither mode, so the unserved upgrade stays a
/// failure. Any other outcome passes through, a failure minus the unserved
/// marker (its error already says it).
///
/// [`Discovery::vendor_entry_live`]: socket_patch_core::vex::discover::Discovery::vendor_entry_live
async fn keep_older_vendored_patch(
    outcome: Option<VendorOutcome>,
    state: &VendorState,
    purl: &str,
    uuid: &str,
    common: &GlobalArgs,
) -> Option<VendorOutcome> {
    let Some(VendorOutcome::Done {
        result,
        entry,
        mut warnings,
    }) = outcome
    else {
        return outcome;
    };
    if !result.success {
        if let Some(i) = warnings.iter().position(|w| {
            matches!(
                w.code,
                vendor::VENDOR_PREBUILT_PENDING | vendor::VENDOR_PREBUILT_UNAVAILABLE
            )
        }) {
            let unserved = warnings.remove(i);
            if let Some(kept) = lookup_entry(&state.entries, purl).filter(|e| e.uuid != uuid) {
                let root = common.project_root();
                if !crate::commands::discover_wiring(common, &root)
                    .await
                    .vendor_entry_live(&root, kept)
                    .await
                {
                    return Some(VendorOutcome::Done {
                        result,
                        entry,
                        warnings,
                    });
                }
                return Some(VendorOutcome::Refused {
                    code: unserved.code,
                    detail: format!(
                        "kept the vendored patch {}: {} for patch {uuid}",
                        kept.uuid, unserved.detail
                    ),
                });
            }
        }
    }
    Some(VendorOutcome::Done {
        result,
        entry,
        warnings,
    })
}

/// The `vendor_dir_symlink_unsupported` detail when `purl`'s vendor dir
/// (`.socket/vendor`, its ecosystem dir, or the `uuid` unit) is a link.
fn linked_vendor_dir_refusal(project_root: &Path, purl: &str, uuid: &str) -> Option<String> {
    let eco = ecosystem_dir_for_purl(purl)?;
    vendor::path::vendor_dir_symlink(project_root, eco, Some(uuid))
        .map(|link| vendor::path::vendor_dir_symlink_detail(&link))
}

/// A wet hosted → vendored takeover held open until the backend's outcome
/// is known: the group-commit savepoint taken before the upstream restore,
/// and what the restore reported, recorded only once the restore stands.
struct TakeoverUndo {
    savepoint: Option<socket_patch_core::utils::group_commit::Savepoint>,
    advisories: Vec<VendorWarning>,
    vlt_targets: Vec<socket_patch_core::patch::redirect::vlt_heal::LedgerTarget>,
}

impl TakeoverUndo {
    /// The purl is not vendored: roll the restore back in `group`'s
    /// overlay, so the hosted pin stays and nothing of the restore is
    /// reported.
    fn abandon(self, group: Option<&GroupCommit>) {
        if let (Some(savepoint), Some(group)) = (self.savepoint, group) {
            group.rollback_to(savepoint);
        }
    }

    /// The restore stands: record its advisories and queue the vlt heal.
    fn settle(
        self,
        env: &mut Envelope,
        common: &GlobalArgs,
        candidate: &str,
        vlt_takeover_targets: &mut HashMap<
            String,
            Vec<socket_patch_core::patch::redirect::vlt_heal::LedgerTarget>,
        >,
    ) {
        if !self.vlt_targets.is_empty() {
            vlt_takeover_targets.insert(candidate.to_string(), self.vlt_targets);
        }
        for advisory in &self.advisories {
            record_warning(env, candidate, advisory, common);
        }
    }
}

/// The dry-run twin of the wet takeover's rollback: the vendored backend's
/// refusal over the project as `restore` would leave it, or `None` when it
/// would vendor (or the restored project cannot be previewed). The
/// restored text is staged in a throwaway group commit that is never
/// committed, so nothing reaches the disk: a restore touching a file the
/// overlay does not capture, or a binary lock (no staged text), is not
/// previewed.
#[allow(clippy::too_many_arguments)]
async fn takeover_dry_refusal(
    restore: &socket_patch_core::patch::redirect::upstream::RestoreOutcome,
    purl: &str,
    pkg_path: PackageSource<'_>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    force: bool,
    service: Option<&VendorServiceConfig>,
    pipenv_version: &tokio::sync::OnceCell<Option<u32>>,
    installed_sites: &vendor::pypi::InstalledSiteListings,
) -> Option<(&'static str, String)> {
    if restore.reverted_files.is_empty()
        || !restore.reverted_files.iter().all(|f| {
            socket_patch_core::utils::group_commit::captures(f)
                && restore.staged_text.contains_key(f)
        })
    {
        return None;
    }
    let probe = GroupCommit::begin(project_root);
    for (rel, text) in &restore.staged_text {
        let path = project_root.join(rel);
        let staged = match text {
            Some(text) => {
                socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(
                    &path,
                    text.as_bytes(),
                )
                .await
            }
            None => socket_patch_core::utils::fs::remove_file(&path).await,
        };
        if staged.is_err() {
            return None;
        }
    }
    let outcome = Box::pin(dispatch_vendor_one(
        purl,
        pkg_path,
        project_root,
        record,
        sources,
        vendored_at,
        true,
        force,
        service,
        pipenv_version,
        installed_sites,
    ))
    .await;
    drop(probe);
    match outcome {
        Some(VendorOutcome::Refused { code, detail }) if !refusal_is_benign(code) => {
            Some((code, detail))
        }
        _ => None,
    }
}

/// Dispatch one purl to its ecosystem backend. `pkg_path` is the crawler's
/// installed location (site-packages root for pypi, the package dir
/// otherwise), when available. Returns `None` for purls with no vendor
/// backend in this build.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_vendor_one(
    purl: &str,
    pkg_path: PackageSource<'_>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
    pipenv_version: &tokio::sync::OnceCell<Option<u32>>,
    installed_sites: &vendor::pypi::InstalledSiteListings,
) -> Option<VendorOutcome> {
    let eco = ecosystem_dir_for_purl(purl)?;
    // Before any backend write: a linked vendor dir is never ours, and the
    // unit would land in (and a later revert delete from) its target. The
    // vendor loop refuses it earlier still, before a hosted takeover; this
    // is the backstop for every other caller.
    if let Some(detail) = linked_vendor_dir_refusal(project_root, purl, &record.uuid) {
        return Some(VendorOutcome::Refused {
            code: "vendor_dir_symlink_unsupported",
            detail,
        });
    }

    const SERVICE_ECOSYSTEMS: &[&str] = &[
        "npm", "pypi", "cargo", "golang", "composer", "gem", "nuget", "maven",
    ];
    if service.is_some() && !SERVICE_ECOSYSTEMS.contains(&eco) {
        return Some(VendorOutcome::Refused {
            code: "vendor_service_unsupported_ecosystem",
            detail: format!(
                "--vendor-source=service is not supported for `{eco}` \
                     (prebuilt downloads cover npm, pypi, cargo, golang, composer, \
                     gem, nuget, and maven)"
            ),
        });
    }
    // Every backend takes the identical 9-argument tuple.
    macro_rules! vend {
        ($backend:path, $source:expr) => {
            $backend(
                purl,
                $source,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
            )
            .await
        };
    }
    Some(match eco {
        // The flavor router probes the project's lockfile (package-lock /
        // yarn / pnpm / bun) and dispatches or refuses per flavor.
        "npm" => vend!(vendor::npm_flavor::vendor_npm_any, pkg_path),
        "pypi" => {
            vendor::pypi::vendor_pypi_with_pipenv_version(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
                pipenv_version,
                installed_sites,
            )
            .await
        }
        "gem" => vend!(vendor::gem::vendor_gem, pkg_path),
        "cargo" => vend!(vendor::cargo::vendor_cargo_crate, pkg_path),
        "golang" => vend!(vendor::golang::vendor_go_module, pkg_path),
        "composer" => vend!(vendor::composer_lock::vendor_composer, pkg_path),
        "nuget" => vend!(vendor::nuget_feed::vendor_nuget, pkg_path.path()),
        "maven" => vend!(vendor::maven_repo::vendor_maven, pkg_path.path()),
        _ => return None,
    })
}

/// Dispatch one recorded entry to its ecosystem's revert.
pub(crate) async fn dispatch_revert_one(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    dispatch_revert_one_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`dispatch_revert_one`] with full [`RevertOpts`]: `keep_artifact` is the
/// `rollback/remove --preserve-state` shape — restore the lockfile wiring
/// but keep the artifact dir (the caller keeps the ledger entry).
pub(crate) async fn dispatch_revert_one_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    // Before any lock edit or delete: the unit removal would reach through
    // a linked vendor dir into another project's artifacts (#664).
    if let Some(link) =
        vendor::path::vendor_dir_symlink(project_root, &entry.ecosystem, Some(&entry.uuid))
    {
        return RevertOutcome::failed(vendor::path::vendor_dir_symlink_detail(&link));
    }
    match vendor::jvm::layout::ledger_ecosystem(&entry.ecosystem) {
        "npm" => vendor::npm_flavor::revert_npm_any_opts(entry, project_root, opts).await,
        "pypi" => vendor::pypi::revert_pypi_opts(entry, project_root, opts).await,
        "gem" => vendor::gem::revert_gem_opts(entry, project_root, opts).await,
        "cargo" => vendor::cargo::revert_cargo_vendor_opts(entry, project_root, opts).await,
        "golang" => vendor::golang::revert_go_vendor_opts(entry, project_root, opts).await,
        "composer" => vendor::composer_lock::revert_composer_opts(entry, project_root, opts).await,
        "nuget" => vendor::nuget_feed::revert_nuget_opts(entry, project_root, opts).await,
        "maven" => vendor::maven_repo::revert_maven_opts(entry, project_root, opts).await,
        other => RevertOutcome::failed(format!(
            "this build has no vendor backend for ecosystem `{other}`"
        )),
    }
}

/// The `vendor --check` failure for a ledger entry the liveness rule
/// ([`Discovery::vendor_entry_live`]) calls dead, naming WHY so the remedy
/// works:
///
/// * another lock contests the wiring (`package-lock.json` resolving the
///   same version from the registry beside a wired `yarn.lock`): name both
///   locks; re-vendoring changes nothing;
/// * the dependency left the lock (upgraded or uninstalled): the in-use
///   verdict the prune GC reverts by ([`Discovery::vendor_entry_in_use`])
///   says so and no lock resolves the package any more, so `scan --prune`
///   is the fix, as `scan`'s own `vendor_ledger_entry_unwired` hint says;
/// * otherwise a relock dropped the reference while the package stayed.
async fn unwired_check_failure(
    discovery: &socket_patch_core::vex::discover::Discovery,
    root: &Path,
    key: &str,
    entry: &VendorEntry,
) -> String {
    let dir = format!(".socket/vendor/{}/{}", entry.ecosystem, entry.uuid);
    if let Some(c) = discovery.vendored_contest(&entry.base_purl, &entry.uuid) {
        return format!(
            "wiring contested: {} wires {dir}, but {} resolves the same version from \
             elsewhere (not a Socket patch), so an install driven by {} gets the unpatched \
             package; delete whichever of the two locks the project does not install from \
             (re-vendoring changes nothing while both resolve it)",
            c.file.display(),
            c.other.display(),
            c.other.display(),
        );
    }
    // Only the npm-family and Python extractors record every lock entry
    // (`resolved_elsewhere`), so only there does "no lock resolves it"
    // prove the dependency is gone rather than unreadable.
    if matches!(entry.ecosystem.as_str(), "npm" | "pypi")
        && !discovery.resolves_package(&entry.base_purl)
        && discovery.vendor_entry_in_use(root, entry).await == Some(false)
    {
        return format!(
            "dependency removed: no lockfile resolves {} any more (it was upgraded or \
             uninstalled), so nothing installs {dir}; run `socket-patch scan --mode vendored \
             --prune` to revert the vendored entry",
            strip_purl_qualifiers(key)
        );
    }
    format!(
        "wiring missing: no lockfile or config references {dir} any more, so a fresh install \
         gets the unpatched package; re-run `socket-patch vendor` to rewire it"
    )
}

/// What the orphan sweep did with the uuid dirs no ledger entry owns.
#[derive(Default)]
struct OrphanSweep {
    /// Un-ledgered AND unreferenced — deleted (unless `dry_run`).
    removed: Vec<vendor::path::SweptVendorDir>,
    /// Un-ledgered but a project lockfile still points into them — kept.
    still_wired: Vec<vendor::path::SweptVendorDir>,
}

/// Uuid dirs under `.socket/vendor/<eco>/` with no owning `(eco, uuid)`
/// ledger entry (a hand-edited state file, or artifacts left by an
/// interrupted run). Unparseable dirs are never returned (and never
/// deleted). Returns the orphans so callers can emit events / counts.
///
/// A missing ledger entry does NOT prove missing wiring: lockfiles can
/// still point into `.socket/vendor/` after a deleted state.json or a
/// partial commit. Deleting such a dir would break the next install, so
/// every candidate is checked against the wiring-bearing files first — the
/// same lockfile scan `repair` reports `vendor_ledger_missing` from — and a
/// referenced dir is kept for the caller to warn about.
async fn sweep_orphan_vendor_dirs(cwd: &Path, state: &VendorState, dry_run: bool) -> OrphanSweep {
    let recorded_units: HashSet<(&str, &str)> = state
        .entries
        .values()
        .map(|e| (e.ecosystem.as_str(), e.uuid.as_str()))
        .collect();
    let candidates: Vec<vendor::path::SweptVendorDir> = vendor::path::sweep_vendor_dirs(cwd)
        .await
        .into_iter()
        .filter(|unit| !recorded_units.contains(&(unit.eco.as_str(), unit.uuid.as_str())))
        .collect();
    let mut out = OrphanSweep::default();
    if candidates.is_empty() {
        return out;
    }
    let wired: HashSet<(String, String)> =
        crate::commands::vendored_backend::repair::scan_vendor_references(cwd)
            .await
            .into_iter()
            .map(|(eco, uuid, _path)| (eco, uuid))
            .collect();
    // Each removal also prunes the `<eco>/` and `vendor/` levels it
    // emptied (never `.socket/` — the lock guard owns that level): the
    // sweep runs AFTER the per-entry reverts and their ledger saves, so it
    // is the last thing that can leave a fully reverted project with empty
    // `.socket/vendor/<eco>/` husks.
    let stop_dir = cwd.join(SOCKET_DIR);
    for unit in candidates {
        if wired.contains(&(unit.eco.clone(), unit.uuid.clone())) {
            out.still_wired.push(unit);
            continue;
        }
        if !dry_run {
            let _ = remove_tree_and_prune(&unit.dir, &stop_dir).await;
        }
        out.removed.push(unit);
    }
    out
}

/// How an orphan uuid dir is named in events: the PURL recovered from its
/// leaf when the layout is recognizable, else `<eco>/<uuid>`.
fn orphan_label(unit: &vendor::path::SweptVendorDir) -> String {
    unit.purls
        .first()
        .cloned()
        .unwrap_or_else(|| format!("{}/{}", unit.eco, unit.uuid))
}

/// Does `eco` fall inside this run's `--ecosystems` scope? A vendor-ledger
/// name counts as the package ecosystem it stands for (a `jvm` entry is
/// `maven`, [`vendor::jvm::layout::ledger_ecosystem`]).
pub(crate) fn ecosystem_in_scope(common: &GlobalArgs, eco: &str) -> bool {
    let eco = vendor::jvm::layout::ledger_ecosystem(eco);
    match socket_patch_core::crawlers::Ecosystem::all()
        .iter()
        .find(|e| e.cli_name() == eco)
    {
        Some(eco) => common.ecosystem_selected(*eco),
        None => common.ecosystems.as_ref().is_none_or(Vec::is_empty),
    }
}

/// Surface a backend vendor ADVISORY: a stderr line for humans, and a
/// `Skipped` event carrying the stable code/detail for JSON consumers.
///
/// A vendor warning is a per-package advisory ABOUT how the package was
/// vendored — a successful `vendor_prebuilt_downloaded` service fetch, an
/// artifact rebuild, a content-mismatch overwrite — NOT a package that was
/// skipped. The package's genuine `Applied`/`Skipped`/`Failed` outcome is
/// recorded separately (via [`Envelope::record`]) alongside this advisory.
///
/// The event is therefore pushed DIRECTLY onto `events` rather than through
/// [`Envelope::record`], so it stays visible to JSON consumers but does NOT
/// bump `summary.skipped`, which counts genuinely skipped packages.
/// `Skipped` never flips the run status, so no status signal is lost.
/// A dry run captures nothing, so it cannot see which files the wet run
/// would rewrite: one `vendor_would_refuse_symlinked_file` advisory per
/// symlinked wiring file of `purl`'s ecosystem, which the wet run's group
/// commit refuses to rename over (`redirect_symlinked_file_unsupported`).
/// Shared by `vendor --dry-run` and the `scan` / `get --mode vendored`
/// dry-run preview.
pub(crate) fn symlinked_wiring_warnings(cwd: &Path, purl: &str) -> Vec<VendorWarning> {
    let Some(eco) = Ecosystem::from_purl(purl) else {
        return Vec::new();
    };
    socket_patch_core::utils::group_commit::symlinked_paths(
        cwd,
        socket_patch_core::formats::registry::wiring_paths(eco.cli_name()),
    )
    .into_iter()
    .map(|linked| {
        VendorWarning::new(
            "vendor_would_refuse_symlinked_file",
            format!(
                "{linked} is a symbolic link; a non-dry-run vendor refuses with \
                 redirect_symlinked_file_unsupported if it must rewrite it (an atomic \
                 rename would replace the link) — replace the link with a regular file, \
                 or run socket-patch in the directory it points to"
            ),
        )
    })
    .collect()
}

pub(crate) fn record_warning(
    env: &mut Envelope,
    purl: &str,
    warning: &VendorWarning,
    common: &GlobalArgs,
) {
    if !common.silent && !common.json {
        if let Some(line) = format_advisory(warning.code, &warning.detail, common.verbose) {
            eprintln!("{line}");
        }
    }
    push_advisory_event(env, purl, warning);
}

/// The JSON half of [`record_warning`]: the uncounted advisory event,
/// with no human line (for an advisory that would mislead in context).
fn push_advisory_event(env: &mut Envelope, purl: &str, warning: &VendorWarning) {
    env.events.push(
        PatchEvent::new(PatchAction::Skipped, purl.to_string())
            .with_reason(warning.code, warning.detail.clone()),
    );
}

/// How loudly a vendor advisory prints for humans.
#[derive(Debug, PartialEq, Eq)]
enum AdvisoryTier {
    /// Routine success detail: shown only under `--verbose`.
    Verbose,
    /// Worth knowing, but nothing is wrong: `Note: ...`.
    Note,
    /// Something the user may need to act on: `Warning (<code>): ...`.
    Warning,
}

fn advisory_tier(code: &str) -> AdvisoryTier {
    match code {
        // Every successful service vendor emits this, one per package; a
        // relock re-scan that re-wires the committed wheel emits the other.
        "vendor_prebuilt_downloaded" | "vendor_artifact_reused" => AdvisoryTier::Verbose,
        // The run did what was asked; these explain how.
        "vendor_fetched_missing"
        | "vendor_would_revert_redirect"
        | "vendor_takeover_reverted_redirect"
        | "cargo_wiring_migrated"
        | "cargo_version_tagged" => AdvisoryTier::Note,
        _ => AdvisoryTier::Warning,
    }
}

/// The human line for a vendor advisory, or `None` when it is hidden at
/// this verbosity. The stable code is JSON-only (`warnings[].code`).
pub(crate) fn format_advisory(code: &str, detail: &str, verbose: bool) -> Option<String> {
    match advisory_tier(code) {
        AdvisoryTier::Verbose if !verbose => None,
        AdvisoryTier::Verbose | AdvisoryTier::Note => Some(format!("Note: {detail}")),
        AdvisoryTier::Warning => Some(format!("Warning: {detail}")),
    }
}

/// `Error: Cannot vendor <purl>: <detail>`.
fn format_vendor_failure(purl: &str, detail: &str) -> String {
    format!("Error: Cannot vendor {}: {detail}", normalize_purl(purl))
}

/// The status line while one package's vendor engine call runs.
fn format_vendor_progress(dry_run: bool, purl: &str, n: usize, total: usize) -> String {
    let verb = if dry_run { "Checking" } else { "Vendoring" };
    if total > 1 {
        format!("{verb} {purl}... ({n}/{total})")
    } else {
        format!("{verb} {purl}...")
    }
}

/// Report one package that failed to vendor. An error, so it prints even
/// under `--silent` ("errors only", never nothing); `--json` carries it
/// in the envelope instead.
fn report_vendor_failure(common: &GlobalArgs, purl: &str, detail: &str) {
    if !common.json {
        eprintln!("{}", format_vendor_failure(purl, detail));
    }
}

/// The unreadable-ledger error, shared by the vendor and revert paths.
fn report_state_unreadable(common: &GlobalArgs, err: &dyn std::fmt::Display) {
    if !common.json {
        eprintln!("{}", format_state_unreadable(&err.to_string()));
    }
}

/// `Error: Could not read the vendor ledger: <err>`, naming the ledger
/// file only when `err` doesn't already (a parse error carries the path,
/// a bare I/O error doesn't).
pub(crate) fn format_state_unreadable(err: &str) -> String {
    if err.contains("state.json") {
        format!("Error: Could not read the vendor ledger: {err}")
    } else {
        format!("Error: Could not read the vendor ledger (.socket/vendor/state.json): {err}")
    }
}

/// Per-outcome counts behind the human vendor summary line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct VendorTally {
    /// Vendored this run (or, on a dry run, would be).
    vendored: u32,
    /// Already in sync with the manifest's patch.
    already: u32,
    /// Not installed and not fetchable (these fail the run).
    not_installed: u32,
    /// Every other skip.
    skipped: u32,
    failed: u32,
}

impl VendorTally {
    /// Derive the tally from the envelope. `dry_in_sync` is the number of
    /// dry-run previews whose ledger entry already records the patch (the
    /// backends preview those as `verified`, like a fresh vendor).
    fn from_envelope(env: &Envelope, dry_run: bool, dry_in_sync: u32) -> Self {
        let code_count = |code: &str| {
            env.events
                .iter()
                .filter(|e| {
                    e.action == PatchAction::Skipped && e.error_code.as_deref() == Some(code)
                })
                .count() as u32
        };
        let already_wet = code_count("already_vendored");
        let not_installed = code_count("package_not_installed");
        let vendored = if dry_run {
            (env.summary.applied + env.summary.verified).saturating_sub(dry_in_sync)
        } else {
            env.summary.applied
        };
        VendorTally {
            vendored,
            already: already_wet + dry_in_sync,
            not_installed,
            skipped: env
                .summary
                .skipped
                .saturating_sub(already_wet + not_installed),
            failed: env.summary.failed,
        }
    }
}

/// `Vendored 2 packages.` / `Would vendor 1 package; 1 already vendored;
/// 1 failed.` Zero clauses are left out; the headline count never is.
fn format_vendor_summary(dry_run: bool, t: &VendorTally) -> String {
    // Everything already in sync: say so, instead of "Vendored 0 packages".
    if t.vendored == 0 && t.already > 0 && t.not_installed == 0 && t.skipped == 0 && t.failed == 0 {
        let all = if t.already == 1 {
            "1 package is".to_string()
        } else {
            format!("All {} packages are", t.already)
        };
        return format!("{all} already vendored; nothing to do.");
    }
    let verb = if dry_run { "Would vendor" } else { "Vendored" };
    let mut line = format!(
        "{verb} {}",
        plural(t.vendored as usize, "package", "packages")
    );
    for (n, what) in [
        (t.already, "already vendored"),
        (t.not_installed, "not installed"),
        (t.skipped, "skipped"),
        (t.failed, "failed"),
    ] {
        if n > 0 {
            line.push_str(&format!("; {n} {what}"));
        }
    }
    line.push('.');
    line
}

/// Report an entry that could not be reverted (an error: prints even
/// under `--silent`).
fn report_revert_failure(common: &GlobalArgs, purl: &str, detail: &str) {
    if !common.json {
        eprintln!("Error: Failed to revert {}: {detail}", normalize_purl(purl));
    }
}

/// The line for a vendored entry reverted because its patch left the
/// manifest.
fn format_reconciled(purl: &str, dry_run: bool) -> String {
    let verb = if dry_run { "Would revert" } else { "Reverted" };
    format!(
        "{verb} vendoring of {} (patch no longer in manifest).",
        normalize_purl(purl)
    )
}

/// Counts behind the `vendor --revert` summary.
#[derive(Debug, Default)]
struct RevertSummary {
    /// Ledger entries reverted (orphan dirs excluded).
    reverted: u32,
    failed: u32,
    /// Drift-kept entries.
    kept: u32,
    /// Orphaned uuid dirs (no ledger entry) removed, as display paths.
    orphans: Vec<String>,
}

/// The `vendor --revert` summary lines. Orphaned dirs are reported on
/// their own line (they are not packages); the package line is left out
/// when only orphans were swept.
fn format_revert_summary(dry_run: bool, s: &RevertSummary) -> Vec<String> {
    let mut lines = Vec::new();
    if s.reverted > 0 || s.failed > 0 || (s.orphans.is_empty() && s.kept == 0) {
        let verb = if dry_run { "Would revert" } else { "Reverted" };
        let mut line = format!(
            "{verb} {}",
            plural(s.reverted as usize, "vendored package", "vendored packages")
        );
        if s.failed > 0 {
            line.push_str(&format!("; {} failed", s.failed));
        }
        line.push('.');
        lines.push(line);
    }
    if !s.orphans.is_empty() {
        let verb = if dry_run { "Would remove" } else { "Removed" };
        lines.push(format!(
            "{verb} {} with no ledger entry: {}.",
            plural(
                s.orphans.len(),
                "orphaned vendor directory",
                "orphaned vendor directories"
            ),
            s.orphans.join(", ")
        ));
    }
    if s.kept > 0 {
        lines.push(format!(
            "Kept {}: lock entries were re-resolved since vendoring, so their artifacts \
             and ledger entries were retained — undo the drift and re-run `vendor --revert` \
             to finish.",
            plural(s.kept as usize, "drifted package", "drifted packages")
        ));
    }
    lines
}

/// After a revert the lockfile points at the registry again. The installed
/// tree holds the vendored bytes only if it was reinstalled after vendoring
/// (vendoring itself rewires the lockfile only), so the hint is conditional.
fn format_revert_install_hint(cmd: &str) -> String {
    format!(
        "Run `{cmd}` to resync the installed tree with the restored lockfile (it may \
         still hold the vendored bytes if you reinstalled after vendoring)."
    )
}

/// Run-level advisory shared by the `vendor` command and the scan-driven
/// vendor step: warn (once, at the envelope level — not per package) when
/// the project's classic `yarn.lock` carries vendored wiring that a stray
/// yarn 2+ install would silently drop. The probe is state-based (it reads
/// the on-disk lockfile), so callers invoke it unconditionally at
/// envelope-finalize time — unwired projects and fully-reverted runs stay
/// silent, and dry runs report the risk that already exists on disk.
pub(crate) fn note_classic_migration_risk(
    env: &mut Envelope,
    project_root: &Path,
    common: &GlobalArgs,
) {
    let Some(w) = vendor::yarn_classic_berry_migration_risk(project_root) else {
        return;
    };
    if !common.silent && !common.json {
        eprintln!("Warning: {}", w.detail);
    }
    env.warnings.push(RunWarning {
        code: w.code.to_string(),
        detail: w.detail,
    });
}

/// The usage error for `vendor` under global scope, or `None` for a
/// project run. Every form of the command acts on the `--cwd` project's
/// lockfiles and vendor ledger, which a global run never targets (#498):
/// plain `vendor` would vendor into the project, `--revert` would unwind
/// the project's vendoring, and `--check` would report on it.
fn global_scope_conflict(args: &VendorArgs) -> Option<String> {
    if crate::commands::project_state_in_scope(&args.common) {
        return None;
    }
    let (form, why) = if args.check {
        (" --check", "check vendored artifacts in")
    } else if args.revert {
        (" --revert", "revert vendored artifacts from")
    } else {
        ("", "wire vendored artifacts into")
    };
    Some(format!(
        "{} cannot be used with vendor{form}: global installs have no project lockfile to {why}",
        crate::commands::global_scope_flag(&args.common),
    ))
}

pub async fn run(args: VendorArgs) -> i32 {
    // Usage errors exit 2, like scan's and get's global mode guard. Checked
    // before anything reads or locks the project.
    if let Some(message) = global_scope_conflict(&args) {
        return crate::json_envelope::usage_error(
            Command::Vendor,
            args.common.json,
            args.common.dry_run,
            "global_scope_unsupported",
            &message,
        );
    }
    if args.check {
        return run_check(&args).await;
    }
    apply_env_toggles(&args.common);

    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = crate::args::socket_dir_of(&manifest_path, &args.common.cwd);

    // `--revert` derives everything from state.json + the vendor tree; it
    // must work after the manifest was deleted. Plain vendor needs the
    // manifest and exits clean without one (same contract as apply). This
    // is a MANIFEST check, not a `.socket/` check: `scan`/`get --mode
    // vendored` projects have `.socket/` but never a manifest. Nothing is
    // locked or written on this path.
    if !args.revert && tokio::fs::metadata(&manifest_path).await.is_err() {
        // A hosted project (no manifest, hosted pins in its lockfiles)
        // ejects: its patch set is the lockfiles' hosted pins.
        let inventory = crate::commands::hosted_inventory(&args.common, &args.common.cwd).await;
        // Contested hosted wiring: the patch set cannot be read off the
        // lockfiles, and a "nothing to vendor" answer would hide it.
        if let Some(refusal) = inventory.contested_refusal() {
            return emit_eject_refusal(&args.common, "hosted_wiring_contested", &refusal);
        }
        let pins = hosted_pins_in_scope(&args.common, inventory.pins);
        if !pins.is_empty() {
            // Eject needs every patch record from the API: an offline
            // run (or dry run) refuses before any request.
            if args.common.offline {
                return emit_eject_refusal(
                    &args.common,
                    "offline_eject_unavailable",
                    &format!(
                        "ejecting {} needs {} patch record(s) from the Socket API, and this \
                         run is offline; re-run without --offline",
                        plural(pins.len(), "hosted package", "hosted packages"),
                        pins.len()
                    ),
                );
            }
            return run_eject(&args, pins).await;
        }
        // A requested `--vex` still attests what the `.socket/vendor`
        // ledgers and lockfiles already wire. Same contract as `apply --vex`
        // with no manifest: nothing referenced anywhere keeps exit 0; any
        // other VEX failure flips the exit; a dry run skips generation.
        if !args.common.json && !args.common.silent {
            // An unreadable ledger is not "no entries": say so (stderr)
            // instead of the calm nothing-to-vendor line.
            match load_state(&args.common.cwd).await {
                Ok(state) => println!("{}", no_manifest_message(state.entries.len())),
                Err(e) => eprintln!("{}", no_manifest_ledger_unreadable(&e.to_string())),
            }
        }
        let vex_result = match args.vex.vex.as_ref() {
            Some(_) if !args.common.dry_run => {
                let params = args.vex.to_build_params(None);
                Some(generate_vex_without_manifest(&args.common, &params, &manifest_path).await)
            }
            _ => None,
        };
        if args.common.json {
            let mut env = Envelope::new(Command::Vendor);
            env.status = Status::NoManifest;
            env.dry_run = args.common.dry_run;
            match vex_result.as_ref() {
                Some(ManifestlessVex::Written(summary)) => {
                    env.vex = Some(VexSummary {
                        path: args
                            .vex
                            .vex
                            .as_ref()
                            .expect("vex_result is Some only when --vex was given")
                            .display()
                            .to_string(),
                        statements: summary.statements,
                        format: "openvex-0.2.0".to_string(),
                        warnings: summary.warnings.clone(),
                    });
                }
                Some(ManifestlessVex::Failed(e)) => {
                    env.warnings.extend(e.embedded_warnings());
                    env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                }
                Some(ManifestlessVex::NothingToAttest(warnings)) => {
                    env.warnings.extend(warnings.iter().cloned());
                }
                None => {}
            }
            println!("{}", env.to_pretty_json());
        } else {
            match vex_result.as_ref() {
                Some(ManifestlessVex::Written(summary)) if !args.common.silent => println!(
                    "{}",
                    crate::commands::vex::format_vex_written(
                        summary.statements,
                        args.vex
                            .vex
                            .as_ref()
                            .expect("vex_result is Some only when --vex was given"),
                    )
                ),
                // Errors print even under --silent ("errors only").
                Some(ManifestlessVex::Failed(e)) => e.print_embedded(&args.common),
                Some(ManifestlessVex::NothingToAttest(_)) if !args.common.silent => {
                    println!("{}", crate::commands::vex::format_vex_nothing_to_attest())
                }
                None if !args.common.silent && args.common.dry_run && args.vex.vex.is_some() => {
                    println!(
                        "{}",
                        crate::commands::vex::format_vex_dry_run_skip("vendored")
                    );
                }
                _ => {}
            }
        }
        return i32::from(matches!(vex_result, Some(ManifestlessVex::Failed(_))));
    }

    // The API client and vendoring-service config exist for the vendoring
    // arm alone (`--revert` never talks to the API). Built BEFORE the lock,
    // like apply/rollback: the client's org-resolve round-trip must not run
    // while other commands wait on `apply.lock`.
    let vendor_service = if args.revert {
        None
    } else {
        let (client, use_public_proxy) =
            get_api_client_with_overrides(args.common.api_client_overrides()).await;
        let telemetry = TelemetryAuth::for_client(&client);
        Some((
            args.common
                .vendor_service_config(Some(client), use_public_proxy),
            telemetry,
        ))
    };

    // Same lock as apply/rollback: vendor mutates the same lockfiles and
    // `.socket/` tree, so a separate lock would allow an apply↔vendor race.
    //
    // `--revert` with no `.socket/` dir is a clean no-op ("a missing ledger
    // is an empty ledger") and must never create `.socket/`, even
    // transiently for the lock file — so skip the lock.
    let lock = if args.revert && tokio::fs::metadata(&socket_dir).await.is_err() {
        None
    } else {
        match acquire_or_emit(
            &socket_dir,
            Command::Vendor,
            args.common.json,
            args.common.dry_run,
            Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
        ) {
            Ok(guard) => Some(guard),
            Err(code) => return code,
        }
    };

    let mut env = Envelope::new(Command::Vendor);
    env.dry_run = args.common.dry_run;
    // A token whose org could not be resolved put the run on the proxy
    // (stderr already said so); the embedded `--vex` reuses this client and
    // leaves reporting it to the host's `warnings[]`.
    if args.common.json {
        if let Some(client) = vendor_service.as_ref().and_then(|(s, _)| s.client.as_ref()) {
            env.warnings
                .extend(crate::commands::vex_sources::api_auth_fallback_warning(
                    client,
                ));
        }
    }

    let mut exit = match &vendor_service {
        None => run_revert(&args, &mut env).await,
        Some((service, _)) => run_vendor(&args, &manifest_path, &mut env, service).await,
    };

    // Embedded VEX: same contract as `apply --vex` — only on success, and a
    // requested-but-failed VEX flips the exit code. A dry run vendors
    // nothing, so there is nothing to attest: skip.
    if exit == 0 && !args.revert {
        if let Some(vex_path) = args.vex.vex.as_ref() {
            if args.common.dry_run {
                if !args.common.json && !args.common.silent {
                    println!(
                        "{}",
                        crate::commands::vex::format_vex_dry_run_skip("vendored")
                    );
                }
            } else {
                let params = args.vex.to_build_params(
                    vendor_service
                        .as_ref()
                        .and_then(|(svc, _)| svc.client.as_ref()),
                );
                match generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await {
                    Ok(summary) => {
                        env.vex = Some(VexSummary {
                            path: vex_path.display().to_string(),
                            statements: summary.statements,
                            format: "openvex-0.2.0".to_string(),
                            // note_warning suppressed these on stderr under
                            // --json; the envelope copy is their only
                            // surviving channel.
                            warnings: summary.warnings,
                        });
                    }
                    Err(e) => {
                        env.warnings.extend(e.embedded_warnings());
                        env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                        // The envelope only prints under --json; in human mode
                        // this error is the sole explanation for the flipped
                        // exit code, so it prints even under --silent ("errors
                        // only", never "nothing").
                        if !args.common.json {
                            e.print_embedded(&args.common);
                        }
                        exit = 1;
                    }
                }
            }
        }
    }

    note_classic_migration_risk(&mut env, &args.common.cwd, &args.common);

    // Everything below is output and telemetry, so release the lock before
    // the telemetry round-trip.
    drop(lock);

    if args.common.json {
        println!("{}", env.to_pretty_json());
    }

    if let Some((_, telemetry)) = &vendor_service {
        track_outcomes_for_vendor(exit != 0, &env, args.common.dry_run, telemetry).await;
    }

    exit
}

/// Read-only audit: no API client, lock recovery, staging, or telemetry is started.
async fn run_check(args: &VendorArgs) -> i32 {
    let root = &args.common.project_root();
    let local_repo = args.local_repo.as_ref().map(|p| args.common.cwd.join(p));
    let mut env = Envelope::new(Command::Vendor);
    let state = match load_state(root).await {
        Ok(state) => state,
        Err(e) => {
            return emit_eject_refusal(&args.common, "vendor_state_unreadable", &e.to_string())
        }
    };
    // JVM trees are not `.socket/vendor/<eco>/<uuid>` dirs the reference
    // scan below can name, so their layout is checked against the ledger's
    // JVM entries directly: present with none of them is an orphan, whatever
    // other ecosystems the ledger records.
    let jvm_orphan = (!state.entries.values().any(vendor::jvm::apply::is_jvm_entry))
        .then(|| {
            vendor::jvm::layout::LEDGER_OWNED_PATHS
                .iter()
                .copied()
                .find(|rel| root.join(rel).exists())
        })
        .flatten();
    const JVM_ORPHAN_DETAIL: &str = "JVM artifacts exist without a vendor ledger entry; restore \
                                     .socket/vendor/state.json from version control";
    if state.entries.is_empty() && jvm_orphan.is_some() {
        return emit_eject_refusal(&args.common, "vendor_ledger_missing", JVM_ORPHAN_DETAIL);
    }
    let manifest_path = args.common.resolved_manifest_path();
    let manifest = match read_manifest(&manifest_path).await {
        Ok(m) => m.unwrap_or_default(),
        Err(e) => return emit_eject_refusal(&args.common, "manifest_unreadable", &e.to_string()),
    };
    let mut entries: Vec<_> = state.entries.iter().collect();
    entries.sort_by_key(|(key, _)| *key);
    // The lockfile view `vex` and `scan` judge vendor-ledger liveness from;
    // JVM entries are checked against their own layout instead.
    let discovery = if state
        .entries
        .values()
        .any(|e| !vendor::jvm::apply::is_jvm_entry(e))
    {
        Some(crate::commands::discover_wiring(&args.common, root).await)
    } else {
        None
    };
    for (key, entry) in entries {
        let record = entry.record.as_ref().or_else(|| manifest.patches.get(key));
        let mut failure = match record {
            Some(record) => match vendor::check_vendored_artifact(root, entry, record).await {
                vendor::ArtifactHealth::Healthy => None,
                health => Some(format!("artifact verification failed: {health:?}")),
            },
            None => Some("patch record missing; restore the manifest or vendor ledger".to_string()),
        };
        if failure.is_none() && vendor::jvm::apply::is_jvm_entry(entry) {
            failure = vendor::jvm::apply::check_entry(root, entry, local_repo.as_deref()).err();
        }
        // The npm check names the exact unwired lock entry, so it runs
        // before the generic liveness rule below.
        if failure.is_none() && entry.ecosystem == "npm" {
            failure = vendor::npm_flavor::check_npm_wiring(entry, root)
                .await
                .err();
        }
        if let (None, Some(discovery), false) = (
            &failure,
            &discovery,
            vendor::jvm::apply::is_jvm_entry(entry),
        ) {
            // A relock (`pipenv lock`, `npm install`, `uv lock`, …) can
            // drop the `.socket/vendor/` reference while the artifact stays
            // intact; a fresh install is then unpatched. Same rule as
            // `vex`'s `vendor_unwired`.
            if !discovery.vendor_entry_live(root, entry).await {
                failure = Some(unwired_check_failure(discovery, root, key, entry).await);
            }
        }
        if vendor::jvm::apply::upstream_unverified(entry) {
            env.warnings.push(RunWarning {code: "vendor_jvm_upstream_unverified".into(), detail: format!("{key}: upstream metadata was accepted offline; run vendor online to verify registry checksums")});
        }
        let event = match failure {
            Some(reason) => {
                PatchEvent::new(PatchAction::Failed, key).with_reason("vendor_check_failed", reason)
            }
            None => PatchEvent::new(PatchAction::Verified, key)
                .with_reason("vendor_check_ok", "committed artifact and wiring verified"),
        };
        if !args.common.json && (!args.common.silent || event.action == PatchAction::Failed) {
            println!("{}: {}", key, event.reason.as_deref().unwrap_or("verified"));
        }
        env.record(event);
    }
    let mut unledgered_uuids: HashSet<&str> = HashSet::new();
    for (key, record) in manifest
        .patches
        .iter()
        .filter(|(k, _)| !state.entries.contains_key(*k))
    {
        unledgered_uuids.insert(record.uuid.as_str());
        if !args.common.json {
            eprintln!("{key}: patch has no vendored ledger entry");
        }
        env.record(PatchEvent::new(PatchAction::Failed, key).with_reason(
            "vendor_ledger_missing",
            "patch has no vendored ledger entry",
        ));
    }
    if let Some(rel) = jvm_orphan {
        if !args.common.json {
            eprintln!("vendor_ledger_missing: {JVM_ORPHAN_DETAIL}");
        }
        env.record(
            PatchEvent::artifact(PatchAction::Failed)
                .with_error("vendor_ledger_missing", JVM_ORPHAN_DETAIL)
                .with_details(serde_json::json!({ "ecosystem": "maven", "path": rel })),
        );
    }
    // A project file still wired to a vendored artifact the ledger does not
    // know (the ledger was ignored or dropped from the commit along with the
    // manifest) leaves every fresh install failing; the manifest keys above
    // cannot see it, so the references are read from the wiring itself.
    let references = crate::commands::vendored_backend::repair::scan_vendor_references(root).await;
    for (eco, uuid, rel) in references {
        let ledgered = state
            .entries
            .values()
            .any(|entry| entry.uuid == uuid && entry.ecosystem == eco);
        if ledgered || unledgered_uuids.contains(uuid.as_str()) {
            continue;
        }
        // No ledger entry means no purl to name: like repair, the event
        // carries the uuid and the referenced path instead. The message
        // names only the ecosystem, keeping patch identifiers out of logs.
        let detail = format!(
            "a lockfile references a vendored {eco} artifact under .socket/vendor/{eco}/ but \
             the vendor ledger (.socket/vendor/state.json) has no entry for it; restore \
             state.json from version control"
        );
        if !args.common.json {
            eprintln!("vendor_ledger_missing: {detail}");
        }
        env.record(
            PatchEvent::artifact(PatchAction::Failed)
                .with_uuid(uuid)
                .with_error("vendor_ledger_missing", detail)
                .with_details(serde_json::json!({ "ecosystem": eco, "path": rel })),
        );
    }
    if args.common.json {
        println!("{}", env.to_pretty_json());
    }
    i32::from(env.summary.failed != 0)
}

/// A refused eject: the JSON error envelope (`status: error`) or an
/// `Error:` line (printed even under `--silent`). Exit 1; nothing touched.
fn emit_eject_refusal(common: &GlobalArgs, code: &'static str, message: &str) -> i32 {
    if common.json {
        let mut env = Envelope::new(Command::Vendor);
        env.dry_run = common.dry_run;
        env.mark_error(EnvelopeError::new(code, message.to_string()));
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error ({code}): {message}");
    }
    1
}

/// The gem vendored backend's refusals a hosted→vendored takeover raises
/// BEFORE it restores `pin` upstream, so a gem vendored mode cannot wire
/// keeps its hosted wiring instead of ending up unpatched in both modes:
/// the manifest gate (a `gems.rb` twin, `BUNDLE_GEMFILE`) and the Gemfile
/// declaration gate on the restored Gemfile (a declaration inside a
/// `group` block, #775).
async fn gem_takeover_refusal(
    cwd: &Path,
    candidate: &str,
    pin: &HostedPin,
    restore_opts: &socket_patch_core::patch::redirect::upstream::RestoreOptions,
) -> Option<(&'static str, String)> {
    match socket_patch_core::vendor::gem::gem_manifest_refusal(cwd).await {
        Some(refusal) => Some(refusal),
        None => {
            socket_patch_core::vendor::gem::gem_vendor_target_preflight(
                cwd,
                candidate,
                pin,
                restore_opts,
            )
            .await
        }
    }
}

/// [`gem_takeover_refusal`] for the dry-run preview of `scan` / `get
/// --mode vendored`: each selected gem purl the lockfiles still pin hosted
/// whose takeover the wet run would refuse, keyed by the selected purl.
/// Nothing is written (the restore is resolved as a dry run).
pub(crate) async fn gem_takeover_preview_refusals<'a>(
    common: &GlobalArgs,
    purls: impl Iterator<Item = &'a str>,
) -> HashMap<String, (&'static str, String)> {
    let gems: Vec<&str> = purls.filter(|p| p.starts_with("pkg:gem/")).collect();
    if gems.is_empty() {
        return HashMap::new();
    }
    let pins = HostedPin::all(&crate::commands::discover_wiring(common, &common.cwd).await);
    gem_takeover_refusals_for(
        &common.cwd,
        gems.into_iter(),
        &pins,
        common.offline,
        crate::commands::hosted_unwind::patch_server_origins(common),
    )
    .await
}

/// [`gem_takeover_preview_refusals`] over already-discovered hosted `pins`:
/// the vendored download phase reads the pins itself, so it refuses these
/// gems before fetching their views instead of after.
pub(crate) async fn gem_takeover_refusals_for<'a>(
    cwd: &Path,
    purls: impl Iterator<Item = &'a str>,
    pins: &[HostedPin],
    offline: bool,
    patch_server_origins: Vec<String>,
) -> HashMap<String, (&'static str, String)> {
    let mut refusals = HashMap::new();
    let restore_opts = socket_patch_core::patch::redirect::upstream::RestoreOptions {
        dry_run: true,
        offline,
        patch_server_origins,
        bun_lockb: true,
    };
    for purl in purls.filter(|p| p.starts_with("pkg:gem/")) {
        let Some(pin) = pins.iter().find(|pin| PurlKey::same(&pin.purl, purl)) else {
            continue;
        };
        if let Some(refusal) = gem_takeover_refusal(cwd, purl, pin, &restore_opts).await {
            refusals.insert(purl.to_string(), refusal);
        }
    }
    refusals
}

/// The hosted pins whose ecosystem `--ecosystems` selects.
fn hosted_pins_in_scope(common: &GlobalArgs, pins: Vec<HostedPin>) -> Vec<HostedPin> {
    pins.into_iter()
        .filter(|pin| {
            socket_patch_core::utils::purl::purl_parts(&pin.purl)
                .is_some_and(|(eco, _, _)| ecosystem_in_scope(common, &eco))
        })
        .collect()
}

/// What a wet eject can touch, captured before it touches anything: every
/// regular file directly in the project root, the hosted pins' files and
/// the restore's files (nested locks included), the project's cargo,
/// maven and Gradle config and owned files (every Gradle build's settings
/// and lock files when the project has a hosted Gradle index), the vendor
/// ledger, and the set of vendored uuid directories.
///
/// [`EjectSnapshot::restore`] puts back only what the eject WROTE: the
/// files above that the upstream restore planned or wrote, and every file
/// the vendored group commit wrote (from its own before-image when no
/// snapshot holds it), each only when its bytes actually changed. Every
/// other root file is left alone, so a redirect target (`vendor --json >
/// report.json`), a log another process appends to, or an untouched
/// README keeps its inode and its bytes (#687).
struct EjectSnapshot {
    root: std::path::PathBuf,
    /// Pre-eject bytes (`None`: absent) by project-relative path.
    files: std::collections::BTreeMap<String, Option<Vec<u8>>>,
    /// The pins' files, the planned restore files and [`Self::EXTRA`]:
    /// always in the rollback's scope.
    planned: std::collections::BTreeSet<String>,
    root_files: std::collections::BTreeSet<String>,
    vendor_dirs: std::collections::BTreeSet<std::path::PathBuf>,
}

impl EjectSnapshot {
    const EXTRA: [&'static str; 12] = [
        ".cargo/config",
        ".cargo/config.toml",
        ".mvn/maven.config",
        ".mvn/checksums/checksums.sha256",
        socket_patch_core::vendor::VENDOR_STATE_REL,
        // The Gradle owned files: the hosted ones the restore removes and
        // the vendored ones the vendor step writes.
        socket_patch_core::patch::redirect::gradle::HOSTED_INDEX_REL,
        socket_patch_core::patch::redirect::gradle::HOSTED_SCRIPT_REL,
        socket_patch_core::patch::redirect::gradle::GITATTRIBUTES_REL,
        socket_patch_core::vendor::jvm::gradle::SCRIPT_REL,
        socket_patch_core::vendor::jvm::gradle::INDEX_REL,
        socket_patch_core::vendor::jvm::gradle::VENDOR_GITATTRIBUTES_REL,
        socket_patch_core::vendor::jvm::gradle::VERIFICATION_REL,
    ];

    async fn root_file_names(root: &Path) -> std::io::Result<std::collections::BTreeSet<String>> {
        let mut out = std::collections::BTreeSet::new();
        let mut dir = tokio::fs::read_dir(root).await?;
        while let Some(entry) = dir.next_entry().await? {
            if entry.file_type().await?.is_file() {
                out.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
        Ok(out)
    }

    fn vendor_dir_set(root: &Path) -> std::collections::BTreeSet<std::path::PathBuf> {
        let base = root.join(".socket/vendor");
        let mut out = std::collections::BTreeSet::new();
        for eco in std::fs::read_dir(&base).into_iter().flatten().flatten() {
            if eco.file_type().is_ok_and(|t| t.is_dir()) {
                for unit in std::fs::read_dir(eco.path())
                    .into_iter()
                    .flatten()
                    .flatten()
                {
                    out.insert(unit.path());
                }
            }
        }
        out
    }

    async fn take(root: &Path, touched: &[String]) -> std::io::Result<Self> {
        let root_files = Self::root_file_names(root).await?;
        let mut planned: std::collections::BTreeSet<String> = touched.iter().cloned().collect();
        planned.extend(Self::EXTRA.iter().map(|s| s.to_string()));
        // A Gradle pin's restore also rewrites (or deletes) files below
        // the root: every build's settings file and every build's lock
        // files. The same files are where the vendored wiring goes.
        if tokio::fs::symlink_metadata(
            root.join(socket_patch_core::patch::redirect::gradle::HOSTED_INDEX_REL),
        )
        .await
        .is_ok()
        {
            let build =
                socket_patch_core::patch::redirect::gradle::read_build_from_disk(root).await;
            planned.extend(socket_patch_core::patch::redirect::gradle::wiring_files(
                &build.files,
            ));
        }
        planned.extend(
            socket_patch_core::vendor::jvm::layout::CAPTURED_FILES
                .iter()
                .map(|s| s.to_string()),
        );
        let mut files = std::collections::BTreeMap::new();
        for rel in root_files.iter().chain(planned.iter()) {
            if files.contains_key(rel) {
                continue;
            }
            // FIFO-safe: a FIFO or device planted at a captured name
            // (scala-cli / Coursier owned files included) fails the
            // snapshot, and with it the eject, instead of blocking open(2).
            let bytes =
                match socket_patch_core::utils::fs::read_regular_to_bytes(&root.join(rel)).await {
                    Ok(bytes) => Some(bytes),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => return Err(e),
                };
            files.insert(rel.clone(), bytes);
        }
        Ok(EjectSnapshot {
            root: root.to_path_buf(),
            files,
            planned,
            root_files,
            vendor_dirs: Self::vendor_dir_set(root),
        })
    }

    /// A file's bytes, `None` when it does not exist. Read through the
    /// FIFO-safe opener: a FIFO or device at a snapshotted workspace path
    /// fails the snapshot (and the eject refuses) instead of wedging open(2).
    async fn read(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
        match socket_patch_core::utils::fs::read_regular_to_bytes(path).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The files the rollback restores: the planned ones, the ones the
    /// upstream restore `written`, and the ones the vendored commit wrote.
    fn scope(
        &self,
        written: &[String],
        committed: &[CommittedFile],
    ) -> std::collections::BTreeSet<String> {
        let mut scope = self.planned.clone();
        scope.extend(written.iter().cloned());
        scope.extend(committed.iter().map(|c| c.rel.clone()));
        scope
    }

    /// What the rollback puts `rel` back to: `Some(Some(bytes))` to rewrite,
    /// `Some(None)` to remove, `None` to leave it as it is. The pre-eject
    /// snapshot wins; without one, the bytes the vendored commit replaced.
    fn wanted<'s>(&'s self, rel: &str, committed: &'s [CommittedFile]) -> Option<Option<&'s [u8]>> {
        if let Some(bytes) = self.files.get(rel) {
            return Some(bytes.as_deref());
        }
        match committed.iter().find(|c| c.rel == rel) {
            Some(c) => Some(c.before.as_deref()),
            // A root file the restore created; anything deeper that no
            // snapshot holds is left as it is.
            None if !rel.contains('/') && !self.root_files.contains(rel) => Some(None),
            None => None,
        }
    }

    /// Put `rel` back to `want` (`None`: absent) unless it already is, so a
    /// file the eject left unchanged is never replaced.
    async fn put_back(&self, rel: &str, want: Option<&[u8]>) -> std::io::Result<()> {
        let path = self.root.join(rel);
        if Self::read(&path).await.ok().as_ref().map(|b| b.as_deref()) == Some(want) {
            return Ok(());
        }
        match want {
            Some(bytes) => {
                // The upstream restore may have removed the file's
                // directory with it (the hosted Gradle files under
                // `.socket/gradle/`).
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(&path, bytes).await
            }
            None => match tokio::fs::remove_file(&path).await {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                other => other,
            },
        }
    }

    /// Undo the eject: `written` is the upstream restore's file list and
    /// `committed` what the vendored group commit wrote (see the type doc).
    async fn restore(&self, written: &[String], committed: &[CommittedFile]) -> Result<(), String> {
        let mut errors: Vec<String> = Vec::new();
        for rel in self.scope(written, committed) {
            let Some(want) = self.wanted(&rel, committed) else {
                continue;
            };
            if let Err(e) = self.put_back(&rel, want).await {
                errors.push(format!("{rel}: {e}"));
            }
        }
        // Vendored uuid dirs the eject created.
        for dir in Self::vendor_dir_set(&self.root).difference(&self.vendor_dirs) {
            if let Err(e) = remove_tree_and_prune(dir, &self.root.join(SOCKET_DIR)).await {
                errors.push(format!("{}: {e}", dir.display()));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    /// The project files for the manual remedy: every file in the
    /// rollback's scope that it would put back to earlier bytes (a nested
    /// file only the vendored commit's before-image holds included).
    fn files_hint(&self, written: &[String], committed: &[CommittedFile]) -> String {
        self.scope(written, committed)
            .into_iter()
            .filter(|rel| matches!(self.wanted(rel, committed), Some(Some(_))))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Standalone `vendor` in a hosted project — no manifest, hosted pins in the
/// lockfiles: EJECT. The patch set is the pins themselves (purl + the uuid
/// in each hosted URL); each record is fetched from the API, vendored into
/// `.socket/vendor/` exactly like `scan --mode vendored`, and the lock is
/// rewired from hosted to vendored (the engine's takeover restores each
/// pin's upstream registry entry first, so `vendor --revert` later returns
/// the project to upstream, not to hosted).
async fn run_eject(args: &VendorArgs, pins: Vec<HostedPin>) -> i32 {
    let common = &args.common;
    let (client, use_public_proxy) =
        get_api_client_with_overrides(common.api_client_overrides()).await;
    let telemetry = TelemetryAuth::for_client(&client);
    if !common.json && !common.silent {
        println!(
            "{} {} into .socket/vendor/...",
            if common.dry_run {
                "Would eject"
            } else {
                "Ejecting"
            },
            plural(pins.len(), "hosted package", "hosted packages")
        );
    }

    // One view per distinct uuid, fetched concurrently and consumed in pin
    // order; only their records are needed to verify the artifacts.
    let mut records: HashMap<String, PatchRecord> = HashMap::new();
    let mut fetch_failures: Vec<(String, String)> = Vec::new();
    let mut views = std::pin::pin!(ordered_concurrent(
        pins.iter(),
        socket_patch_core::utils::concurrent::api_concurrency_for(
            client.uses_public_proxy(),
            pins.len(),
        ),
        |pin| {
            let client = &client;
            async move { client.fetch_patch(&pin.uuid).await }
        },
    ));
    for pin in &pins {
        let Some(view) = views.next().await else {
            break;
        };
        match view {
            Ok(Some(patch)) => {
                let (_, record) =
                    socket_patch_core::manifest::records::record_from_patch_response(&patch);
                records.insert(pin.purl.clone(), record);
            }
            Ok(None) => fetch_failures.push((
                pin.purl.clone(),
                format!("patch {} was not found on the API", pin.uuid),
            )),
            Err(e) => fetch_failures.push((
                pin.purl.clone(),
                format!("could not fetch patch {}: {e}", pin.uuid),
            )),
        }
    }

    // All or nothing: a record the API cannot serve refuses the whole eject
    // before anything is touched, so every package stays hosted.
    if !fetch_failures.is_empty() {
        let mut env = Envelope::new(Command::Vendor);
        env.dry_run = common.dry_run;
        if common.json {
            env.warnings
                .extend(crate::commands::vex_sources::api_auth_fallback_warning(
                    &client,
                ));
        }
        for (purl, detail) in &fetch_failures {
            report_vendor_failure(common, purl, detail);
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone())
                    .with_error("patch_fetch_failed", detail.clone()),
            );
        }
        env.mark_error(EnvelopeError::new(
            "eject_refused",
            "not every hosted patch record could be fetched; nothing was changed",
        ));
        if common.json {
            println!("{}", env.to_pretty_json());
        }
        track_outcomes_for_vendor(true, &env, common.dry_run, &telemetry).await;
        return 1;
    }

    // Plan the upstream restore before touching anything: every pin must
    // re-resolve to its registry entry (a dry resolve), or the eject is
    // refused whole with each pin's remedy.
    let origins = crate::commands::hosted_unwind::patch_server_origins(common);
    let plan = socket_patch_core::patch::redirect::upstream::restore_upstream(
        &common.cwd,
        &pins,
        &socket_patch_core::patch::redirect::upstream::RestoreOptions {
            dry_run: true,
            offline: common.offline,
            patch_server_origins: origins.clone(),
            bun_lockb: true,
        },
    )
    .await;
    let mut refused: Vec<(String, &'static str, String)> = plan
        .refused()
        .map(|(pin, why)| (pin.purl.clone(), "redirect_revert_failed", why.to_string()))
        .collect();
    // An sbt / scala-cli pin is vendored only past the build-evidence gate
    // (no `target/` evidence in a fresh clone, stale evidence, …). Run it
    // now, while the hosted pin still serves the patch: a pin the gate
    // would stop after the restore would end neither hosted nor vendored.
    for pin in &pins {
        if let Err((code, detail)) =
            socket_patch_core::vendor::maven_repo::jvm_gate_preflight(&common.cwd, &pin.purl).await
        {
            refused.push((
                pin.purl.clone(),
                code,
                format!("kept hosted: the vendored gate would not vendor it ({detail})"),
            ));
        }
    }
    if !refused.is_empty() {
        let mut env = Envelope::new(Command::Vendor);
        env.dry_run = common.dry_run;
        if common.json {
            env.warnings
                .extend(crate::commands::vex_sources::api_auth_fallback_warning(
                    &client,
                ));
        }
        for (purl, code, why) in &refused {
            report_vendor_failure(common, purl, why);
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone()).with_error(*code, why.clone()),
            );
        }
        env.mark_error(EnvelopeError::new(
            "eject_refused",
            "not every hosted pin can be restored to its upstream registry entry and vendored; \
             nothing was changed",
        ));
        if common.json {
            println!("{}", env.to_pretty_json());
        }
        track_outcomes_for_vendor(true, &env, common.dry_run, &telemetry).await;
        return 1;
    }

    // A dry run stops at the verified plan: restoring the live lock to
    // preview the vendor step would be a write.
    if common.dry_run {
        let mut env = Envelope::new(Command::Vendor);
        env.dry_run = true;
        if common.json {
            env.warnings
                .extend(crate::commands::vex_sources::api_auth_fallback_warning(
                    &client,
                ));
        }
        for pin in &pins {
            env.record(
                PatchEvent::new(PatchAction::Applied, pin.purl.clone()).with_reason(
                    "eject_planned",
                    format!(
                        "would restore the upstream registry entry ({}) and vendor the patch",
                        pin.files.join(", ")
                    ),
                ),
            );
            if !common.json && !common.silent {
                println!(
                    "Would eject {} (restore {}, then vendor into .socket/vendor/)",
                    pin.purl,
                    pin.files.join(", ")
                );
            }
        }
        if args.vex.vex.is_some() && !common.json && !common.silent {
            println!(
                "{}",
                crate::commands::vex::format_vex_dry_run_skip("vendored")
            );
        }
        if common.json {
            println!("{}", env.to_pretty_json());
        }
        track_outcomes_for_vendor(false, &env, true, &telemetry).await;
        return 0;
    }

    // One transaction under one apply lock: snapshot what the eject can
    // touch, restore every pin upstream (so the vendor engine resolves the
    // pristine registry package even in a fresh checkout with nothing
    // installed), vendor, and on ANY failure put back what the eject wrote
    // — a failed eject leaves the project hosted, exactly as it was, and
    // every file it never wrote untouched.
    let socket_dir = common.socket_dir();
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    let guard = match crate::commands::lock_cli::acquire_with_status(&socket_dir, timeout) {
        Ok(guard) => guard,
        Err(e) => {
            let (code, message) = crate::commands::lock_cli::lock_failure(&e, timeout);
            return emit_eject_refusal(common, code, &message);
        }
    };
    let touched: Vec<String> = pins
        .iter()
        .flat_map(|p| p.files.iter().cloned())
        .chain(plan.reverted_files.iter().cloned())
        .collect();
    let snapshot = match EjectSnapshot::take(&common.cwd, &touched).await {
        Ok(snapshot) => snapshot,
        Err(e) => {
            drop(guard);
            return emit_eject_refusal(
                common,
                "eject_refused",
                &format!("could not snapshot the project before ejecting: {e}"),
            );
        }
    };
    let mut env = Envelope::new(Command::Vendor);
    if common.json {
        env.warnings
            .extend(crate::commands::vex_sources::api_auth_fallback_warning(
                &client,
            ));
    }
    let restore = socket_patch_core::patch::redirect::upstream::restore_upstream(
        &common.cwd,
        &pins,
        &socket_patch_core::patch::redirect::upstream::RestoreOptions {
            dry_run: false,
            offline: common.offline,
            patch_server_origins: origins,
            bun_lockb: true,
        },
    )
    .await;
    let restore_failure = restore
        .refused()
        .map(|(_, why)| why.to_string())
        .next()
        .or_else(|| restore.flush_error.clone());
    // Every file the vendored apply's group commit wrote, with its bytes
    // from before (the rollback's scope beyond the restore's own files),
    // and the flavors it wired for the close printed below.
    let mut capture = EjectCapture::default();
    // The vendored apply's events start here: a rollback retracts them.
    let events_start = env.events.len();
    let mut exit: i32;
    if let Some(why) = restore_failure {
        env.mark_error(EnvelopeError::new("redirect_revert_failed", why.clone()));
        if !common.json {
            eprintln!("Error: {}", crate::ui::sentence_case(&why));
        }
        exit = 1;
    } else {
        for (code, detail) in &restore.warnings {
            env.warnings.push(RunWarning {
                code: code.to_string(),
                detail: detail.clone(),
            });
        }
        let manifest = crate::commands::vendored_backend::records_manifest(records);
        // The same vendored apply as `scan --mode vendored`: detached (the
        // eject is manifest-free) over this run's client and the shared
        // service-config assembler.
        let service = common.vendor_service_config(Some(client.clone()), use_public_proxy);
        let applied = VendoredBackend::new(common, Some(&service))
            .apply(
                ApplyRequest {
                    manifest: &manifest,
                    socket_dir: &socket_dir,
                    ledger: load_state(&common.cwd).await,
                    detached: true,
                    force: false,
                    prior: None,
                    eject: Some(&mut capture),
                },
                &mut env,
            )
            .await;
        exit = i32::from(applied);
        // Backstop: every ejected pin must now be vendored. A package the
        // backend skipped (a vendored gate condition the pre-pass did not
        // see) would otherwise leave the project neither hosted nor
        // vendored while the run succeeds.
        if exit == 0 {
            let ledger = load_state(&common.cwd).await.ok();
            let missing: Vec<&str> = pins
                .iter()
                .map(|p| p.purl.as_str())
                .filter(|purl| {
                    ledger
                        .as_ref()
                        .is_none_or(|l| lookup_entry(&l.entries, purl).is_none())
                })
                .collect();
            if !missing.is_empty() {
                let detail = format!(
                    "{} {} not vendored, so the eject is undone",
                    missing.join(", "),
                    if missing.len() == 1 { "was" } else { "were" }
                );
                if !common.json {
                    eprintln!("Error: {detail}");
                }
                env.mark_error(EnvelopeError::new("eject_incomplete", detail));
                exit = 1;
            }
        }
    }
    let committed = &capture.committed;
    if exit != 0 {
        match snapshot.restore(&restore.reverted_files, committed).await {
            Ok(()) => {
                let detail = "the eject did not complete, so every file it touched was \
                              restored: the project is still hosted, exactly as before";
                // Nothing the vendored apply did survives the rollback: a
                // package it vendored is still hosted, not applied (#1005).
                env.retract_applied(
                    events_start,
                    PatchAction::Skipped,
                    "eject_rolled_back",
                    "vendored, then rolled back with the rest of the eject: still hosted",
                );
                if !common.json && !common.silent {
                    eprintln!("Warning: {detail}");
                }
                env.warnings.push(RunWarning {
                    code: "eject_rolled_back".to_string(),
                    detail: detail.to_string(),
                });
            }
            Err(e) => {
                let detail = format!(
                    "the eject did not complete and restoring the pre-eject files failed ({e}); \
                     restore them from version control (`git checkout -- {}`)",
                    snapshot.files_hint(&restore.reverted_files, committed)
                );
                if !common.json {
                    eprintln!("Error: {detail}");
                }
                env.mark_error(EnvelopeError::new("eject_rollback_failed", detail));
            }
        }
        if env.error.is_none() {
            env.mark_partial_failure();
        }
    } else {
        // The vendored summary and its "Next steps:", deferred until the
        // eject is known to stand: a failed one is rolled back (or needs
        // the manual restore its error names), so neither applies.
        print_vendor_closing(common, &env, 0, &capture.wired_flavors, true);
    }
    note_classic_migration_risk(&mut env, &common.cwd, common);
    drop(guard);

    // Embedded VEX: same contract as the manifest-driven arm — only on
    // success, never on a dry run, and a requested-but-failed VEX flips the
    // exit code. The ejected project has no manifest.
    if exit == 0 {
        if let Some(vex_path) = args.vex.vex.as_ref() {
            if common.dry_run {
                if !common.json && !common.silent {
                    println!(
                        "{}",
                        crate::commands::vex::format_vex_dry_run_skip("vendored")
                    );
                }
            } else {
                let params = args.vex.to_build_params(Some(&client));
                let manifest_path = common.resolved_manifest_path();
                match generate_vex_without_manifest(common, &params, &manifest_path).await {
                    ManifestlessVex::Written(summary) => {
                        env.vex = Some(VexSummary {
                            path: vex_path.display().to_string(),
                            statements: summary.statements,
                            format: "openvex-0.2.0".to_string(),
                            warnings: summary.warnings,
                        });
                    }
                    ManifestlessVex::NothingToAttest(warnings) => {
                        env.warnings.extend(warnings);
                        if !common.json && !common.silent {
                            println!("{}", crate::commands::vex::format_vex_nothing_to_attest());
                        }
                    }
                    ManifestlessVex::Failed(e) => {
                        env.warnings.extend(e.embedded_warnings());
                        env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                        if !common.json {
                            e.print_embedded(common);
                        }
                        exit = 1;
                    }
                }
            }
        }
    }

    if common.json {
        println!("{}", env.to_pretty_json());
    }
    track_outcomes_for_vendor(exit != 0, &env, common.dry_run, &telemetry).await;
    exit
}

/// The no-manifest warning when the vendor ledger cannot be read either.
fn no_manifest_ledger_unreadable(err: &str) -> String {
    format!(
        "Warning: No manifest to vendor from, and the vendor ledger could not be read: \
         {err}\n  Run `socket-patch repair` to check the vendored artifacts."
    )
}

/// The human no-op line for a plain `vendor` with no manifest. Names the
/// MANIFEST (the thing actually missing), and — when the vendor ledger
/// tracks entries, i.e. a `scan`/`get --mode vendored` project — says so
/// instead of implying nothing is vendored: their refresh path is `scan
/// --mode vendored`, and `repair` is what re-verifies the ledger.
fn no_manifest_message(tracked_entries: usize) -> String {
    match tracked_entries {
        0 => "No manifest found, nothing to vendor.".to_string(),
        1 => "No manifest to vendor from; 1 vendored entry is tracked in the ledger — \
              `socket-patch repair` verifies it."
            .to_string(),
        n => format!(
            "No manifest to vendor from; {n} vendored entries are tracked in the ledger — \
             `socket-patch repair` verifies them."
        ),
    }
}

/// Telemetry for a vendor run's success/failure split, shared by
/// [`run`] and the scan-driven vendor step (`scan --mode vendored`).
pub(crate) async fn track_outcomes_for_vendor(
    has_errors: bool,
    env: &Envelope,
    dry_run: bool,
    telemetry: &TelemetryAuth,
) {
    if has_errors {
        track_patch_vendor_failed("vendor completed with failures", dry_run, telemetry).await;
    } else {
        track_patch_vendored(env.summary.applied, dry_run, telemetry).await;
    }
}

async fn run_vendor(
    args: &VendorArgs,
    manifest_path: &Path,
    env: &mut Envelope,
    service: &VendorServiceConfig,
) -> i32 {
    let common = &args.common;
    let manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => return 0, // vanished since the existence check (TOCTOU)
        Err(e) => {
            env.mark_error(EnvelopeError::new("invalid_manifest", e.to_string()));
            if !common.json {
                eprintln!("Error: Could not read manifest: {e}");
            }
            return 1;
        }
    };

    // Reconcile first (mirrors apply's placement): entries vendored by a
    // previous run whose patches were dropped from the manifest are reverted
    // even when zero in-scope patches remain. Its post-reconcile ledger
    // feeds the staging harvest below and then the engine.
    let (mut has_errors, ledger) = reconcile_dropped(&manifest, common, env).await;

    let socket_dir = crate::args::socket_dir_of(manifest_path, &common.cwd);
    if manifest.patches.is_empty() && !common.json && !common.silent {
        println!("The manifest has no patches; nothing to vendor.");
    }
    // Download the server artifacts through the shared vendored backend.
    let applied = VendoredBackend::new(common, Some(service))
        .apply(
            ApplyRequest {
                manifest: &manifest,
                socket_dir: &socket_dir,
                ledger,
                detached: false,
                force: args.force,
                prior: None,
                eject: None,
            },
            env,
        )
        .await;
    has_errors |= applied;

    if has_errors {
        // A run where EVERY event failed still reads as "partialFailure":
        // status=error is reserved for pre-event failures (a top-level error
        // payload and empty events[] — see json_envelope.rs), matching
        // `scan --mode vendored` and `vendor --revert`.
        env.mark_partial_failure();
        1
    } else {
        0
    }
}

/// Persist one backend-returned ledger entry: detached flagging, the
/// embedded patch record, wiring `original` carry-forward from the entry
/// being replaced, per-package save (crash-consistent with what is already
/// wired), and the stale-uuid-dir sweep on re-vendors. Returns `true` when
/// the save failed (has_errors).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn persist_vendor_entry(
    common: &GlobalArgs,
    env: &mut Envelope,
    state: &mut VendorState,
    candidate: &str,
    entry: VendorEntry,
    detached: bool,
    record: &PatchRecord,
) -> bool {
    let mut shared = std::sync::Arc::new(std::mem::take(state));
    let (has_errors, stale) =
        record_vendor_entry(common, env, &mut shared, candidate, entry, detached, record).await;
    // A group commit keeps its own reference to the ledger it captured, so
    // this may copy once per save.
    *state = std::sync::Arc::try_unwrap(shared).unwrap_or_else(|held| (*held).clone());
    if let Some(stale) = stale {
        sweep_stale_artifact(common, env, state, stale).await;
    }
    has_errors
}

/// The entry a re-vendor under a newer patch uuid replaced, whose uuid dir
/// is an orphan once the new wiring and ledger are committed.
pub(crate) struct StaleArtifact {
    candidate: String,
    prev: VendorEntry,
}

/// [`persist_vendor_entry`]'s bookkeeping half: everything but the sweep of
/// the replaced uuid's dir, which is handed back so a group-committed run
/// can hold it until its commit (deleting it earlier would leave the
/// committed, pre-run wiring pointing at a dir that is gone if the run
/// never commits).
#[allow(clippy::too_many_arguments)]
async fn record_vendor_entry(
    common: &GlobalArgs,
    env: &mut Envelope,
    state: &mut std::sync::Arc<VendorState>,
    candidate: &str,
    mut entry: VendorEntry,
    detached: bool,
    record: &PatchRecord,
) -> (bool, Option<StaleArtifact>) {
    let candidate = candidate.to_string();
    entry.detached = detached;
    // EVERY entry embeds its patch record, not only detached ones, so a
    // checkout whose manifest is gone or was never committed can still
    // verify and attest the vendored patch offline. For a non-detached
    // entry the manifest record stays authoritative wherever both exist;
    // the embedded copy is the fallback.
    entry.record = Some(record.clone());
    // A re-vendor re-derives the entry from disk state where the earlier
    // wiring already happened, so carry forward the true pre-vendor
    // originals and wiring records from the entry it replaces — `--revert`
    // must still undo every surface any earlier vendoring touched. See
    // [`vendor::carry_forward_wiring`].
    let prev = state.entries.get(&candidate).cloned();
    if let Some(prev) = &prev {
        vendor::carry_forward_wiring(prev, &mut entry);
    }
    let new_uuid = entry.uuid.clone();
    // Persist per-package so a crash mid-run leaves a ledger that matches
    // what's already wired (under a group commit this lands in the run's
    // captured state, committed with the wiring it describes).
    let key = candidate.clone();
    if let Err(e) = save_state_shared(&common.cwd, state, move |s| {
        s.entries.insert(key, entry);
    })
    .await
    {
        env.record(
            PatchEvent::new(PatchAction::Failed, candidate.clone())
                .with_error("vendor_state_write_failed", e.to_string()),
        );
        return (true, None);
    }
    let stale = prev
        .filter(|p| p.uuid != new_uuid)
        .map(|prev| StaleArtifact { candidate, prev });
    (false, stale)
}

/// Re-vendor under a newer patch uuid: the old uuid's dir is an orphan now —
/// the wiring and ledger both point at the new uuid — unless another entry
/// still shares it (the same `(eco, uuid)` ownership test as `--revert`'s
/// orphan sweep). Only the live entry would otherwise reclaim it, and that
/// never happens.
async fn sweep_stale_artifact(
    common: &GlobalArgs,
    env: &mut Envelope,
    state: &VendorState,
    stale: StaleArtifact,
) {
    let StaleArtifact { candidate, prev } = stale;
    // A JVM tree is not a uuid dir: the replaced entry's own tree files go,
    // minus any path a live entry records (a Gradle update rewrites them).
    if vendor::jvm::apply::is_jvm_entry(&prev) {
        let removed = if common.dry_run {
            Ok(false)
        } else {
            vendor::jvm::apply::sweep_replaced_tree(&common.cwd, &prev, state.entries.values())
                .await
        };
        match removed {
            Ok(true) => env.record(
                PatchEvent::new(PatchAction::Removed, candidate).with_reason(
                    "vendor_stale_artifact_removed",
                    "previous patch uuid's vendored artifact removed",
                ),
            ),
            Ok(false) => {}
            Err(detail) => record_warning(
                env,
                &candidate,
                &VendorWarning::new("vendor_stale_artifact_kept", detail),
                common,
            ),
        }
        return;
    }
    let still_referenced = state
        .entries
        .values()
        .any(|e| e.ecosystem == prev.ecosystem && e.uuid == prev.uuid);
    let stale_rel = vendor::path::vendor_uuid_dir_rel(&prev.ecosystem, &prev.uuid);
    let Some(rel) = stale_rel.filter(|_| !still_referenced) else {
        return;
    };
    if let Err(detail) =
        vendor::bun_lock::cleanup_binary_workspace_artifacts(&common.cwd, &prev, common.dry_run)
            .await
    {
        record_warning(
            env,
            &candidate,
            &VendorWarning::new("vendor_stale_artifact_kept", detail),
            common,
        );
        return;
    }
    if !common.dry_run {
        // Prunes the emptied `<eco>/` level too (a uuid change
        // within one ecosystem never empties it, but a re-vendor
        // that moved ecosystems would otherwise leave a husk).
        let _ = remove_tree_and_prune(&common.cwd.join(rel), &common.cwd.join(SOCKET_DIR)).await;
    }
    env.record(
        PatchEvent::new(PatchAction::Removed, candidate).with_reason(
            "vendor_stale_artifact_removed",
            "previous patch uuid's vendored artifact removed",
        ),
    );
}

pub(crate) async fn pristine_fetch_is_verifiable(
    project_root: &Path,
    inventory: &[lock_inventory::LockfileEntry],
    purl: &str,
    ledger_entry: Option<&VendorEntry>,
) -> bool {
    let verifiable =
        |e: &lock_inventory::LockfileEntry| e.integrity != lock_inventory::LockIntegrity::None;
    if lock_inventory::lookup(inventory, purl).is_some_and(verifiable) {
        return true;
    }
    match ledger_entry {
        Some(le) => lock_inventory::recover_lock_entry(project_root, le)
            .await
            .is_ok_and(|e| verifiable(&e)),
        None => false,
    }
}

pub(crate) async fn installed_purls(
    options: &CrawlerOptions,
    purls: &[String],
    prior: Option<&NpmCrawlSnapshot>,
) -> HashSet<String> {
    if purls.is_empty() {
        return HashSet::new();
    }
    let partition = partition_purls(purls, None);
    let mut installed: HashSet<String> =
        find_packages_for_rollback_reusing(&partition, options, true, prior)
            .await
            .into_keys()
            .collect();
    let missing_npm: Vec<&String> = partition
        .get(&Ecosystem::Npm)
        .into_iter()
        .flatten()
        .filter(|p| !installed.contains(*p))
        .collect();
    let by_identity = match prior.and_then(|p| p.packages_for(options)) {
        Some(crawled) => npm_paths_by_identity_in(crawled, &missing_npm),
        None => npm_paths_by_identity(options, &missing_npm).await,
    };
    installed.extend(by_identity.into_keys());
    installed
}

pub(crate) async fn lock_refusals_reaching_backend<F, Fut>(
    cwd: &Path,
    mut refused: HashMap<String, (&'static str, String)>,
    ledger: &HashMap<String, VendorEntry>,
    installed: F,
) -> HashMap<String, (&'static str, String)>
where
    F: FnOnce(Vec<String>) -> Fut,
    Fut: std::future::Future<Output = HashSet<String>>,
{
    if refused.is_empty() {
        return refused;
    }
    let inventory = lock_inventory::inventory_project(cwd).await;
    let mut unresolved: Vec<String> = Vec::new();
    for purl in refused.keys() {
        if !pristine_fetch_is_verifiable(cwd, &inventory, purl, lookup_entry(ledger, purl)).await {
            unresolved.push(purl.clone());
        }
    }
    if unresolved.is_empty() {
        return refused;
    }
    unresolved.sort();
    let installed = installed(unresolved.clone()).await;
    for purl in unresolved {
        if !installed.contains(&purl) {
            refused.remove(&purl);
        }
    }
    refused
}

enum StagedSource {
    Installed(std::path::PathBuf),
    Missing(std::path::PathBuf),
}

impl StagedSource {
    fn as_source(&self) -> PackageSource<'_> {
        match self {
            Self::Installed(dir) | Self::Missing(dir) => PackageSource::Installed(dir),
        }
    }
}

/// Whether an installed copy that fails `candidate`'s variant probe is
/// still `candidate` itself, superseded: the ledger vendored exactly this
/// package at an OLDER patch uuid (#769), so the venv most likely holds
/// that patch's bytes (`pipenv sync` from the vendored wheel), which are
/// neither the pristine release nor this patch's output. The re-vendor
/// then takes the pristine artifact from the lock / registry / service, as
/// a lock-only checkout does, instead of reporting it not installed.
fn superseded_install(
    ledger: &VendorState,
    candidate: &str,
    record: &PatchRecord,
    sole_candidate: bool,
) -> bool {
    lookup_entry_kv(&ledger.entries, candidate).is_some_and(|(key, entry)| {
        entry.uuid != record.uuid && (sole_candidate || key == candidate)
    })
}

#[allow(clippy::too_many_arguments)]
async fn plan_service_downloads(
    cwd: &Path,
    force: bool,
    all_packages: &[(String, StagedSource)],
    variant_groups: &HashMap<String, Vec<String>>,
    records: &HashMap<String, PatchRecord>,
    ledger: &VendorState,
    refused: &HashSet<String>,
    bun_refusal: Option<&crate::commands::bun_preflight::BunVendorRefusal>,
    takeover_blocked: &dyn Fn(&str) -> bool,
    (pipenv_version, installed_sites): (
        &tokio::sync::OnceCell<Option<u32>>,
        &vendor::pypi::InstalledSiteListings,
    ),
) -> Vec<socket_patch_core::api::client::PlannedDownload> {
    // The loop's stand-in for a superseded install (see there).
    let uninstalled = cwd.join(".socket/vendor/.uninstalled");
    // Each loop candidate that reaches its backend, in loop order.
    let mut reaching: Vec<(&str, &PatchRecord, &Path)> = Vec::new();
    let mut handled_bases: HashSet<String> = HashSet::new();
    for (purl, staged) in all_packages {
        let source = staged.as_source();
        let is_variant_eco =
            Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants());
        let candidates: Vec<String> = if is_variant_eco {
            let base = strip_purl_qualifiers(purl).to_string();
            if !handled_bases.insert(base.clone()) {
                continue;
            }
            variant_groups
                .get(&base)
                .cloned()
                .unwrap_or_else(|| vec![base])
        } else {
            vec![purl.clone()]
        };
        for candidate in &candidates {
            let Some((candidate, record)) = records.get_key_value(candidate) else {
                continue;
            };
            if refused.contains(candidate) {
                continue;
            }
            // The loop's installed-variant probe (see there).
            let probe_applicable = is_variant_eco
                && !matches!(Ecosystem::from_purl(candidate), Some(Ecosystem::Maven));
            let ledger_answers_probe =
                lookup_entry(&ledger.entries, candidate).is_some_and(|e| e.uuid == record.uuid);
            let mut source_path = source.path();
            if probe_applicable && !force && !ledger_answers_probe {
                if matches!(staged, StagedSource::Installed(_)) {
                    if let Some((file, info)) = representative_file(&record.files) {
                        let dir = source.path();
                        if !variant_matches_installed(Some(
                            &verify_file_patch(dir, file, info).await.status,
                        )) {
                            if !superseded_install(ledger, candidate, record, candidates.len() == 1)
                            {
                                continue;
                            }
                            source_path = &uninstalled;
                        }
                    }
                } else if candidates.len() > 1 && lookup_entry(&ledger.entries, candidate).is_none()
                {
                    // The loop leaves this variant to a sibling the ledger
                    // records, or refuses it as ambiguous (see there).
                    continue;
                }
            }
            if bun_refusal.is_some_and(|r| r.applies_to(candidate)) {
                continue;
            }
            // The loop refuses a linked vendor dir; no grant on its behalf.
            if linked_vendor_dir_refusal(cwd, candidate, &record.uuid).is_some() {
                continue;
            }
            if takeover_blocked(candidate) {
                continue;
            }
            // The npm backends re-wire a committed artifact the ledger
            // anchors at this uuid without asking the service.
            if candidate.starts_with("pkg:npm/")
                && ledger.entries.values().any(|e| {
                    e.ecosystem == "npm" && e.uuid == record.uuid && !e.artifact.sha256.is_empty()
                })
            {
                continue;
            }
            // A purl the ledger already records at this record's uuid is a
            // re-run, which every backend's in-sync hot path answers without
            // the service; proving it costs the verification of the whole
            // committed artifact, which the loop's own call repeats. Left
            // out of the plan: should the artifact need rebuilding after all,
            // the loop fetches it live.
            if lookup_entry(&ledger.entries, candidate).is_some_and(|e| e.uuid == record.uuid) {
                continue;
            }
            reaching.push((candidate.as_str(), record, source_path));
        }
    }

    let npm: Vec<(&str, &PatchRecord)> = reaching
        .iter()
        .filter(|(purl, _, _)| purl.starts_with("pkg:npm/"))
        .map(|(purl, record, _)| (*purl, *record))
        .collect();
    let mut npm_verdicts = if npm.is_empty() {
        Vec::new()
    } else {
        vendor::npm_flavor::preflight_packages(cwd, &npm).await
    }
    .into_iter();
    // One gate at a time: several at once would each hold their own parse
    // of the project's lockfiles (a cargo gate clones the whole Cargo.lock
    // document), which a monorepo pays for in peak memory.
    let mut planned = Vec::new();
    for (purl, record, source_path) in &reaching {
        let download = if purl.starts_with("pkg:npm/") {
            npm_verdicts
                .next()
                .filter(|verdict| verdict.is_ok())
                .map(|_| {
                    socket_patch_core::api::client::PlannedDownload::archive(record.uuid.clone())
                })
        } else {
            vendor::service_preflight(
                purl,
                source_path,
                cwd,
                record,
                pipenv_version,
                installed_sites,
            )
            .await
        };
        planned.extend(download);
    }
    planned
}

/// The vendoring engine, decoupled from the manifest file. `records` is the
/// purl → [`PatchRecord`] view to vendor: `manifest.patches` for the
/// manifest-driven `vendor` command, or the in-memory record map
/// `scan`/`get --mode vendored` fetched (`detached`). Entries written in
/// `detached` mode carry [`VendorEntry::detached`] plus an embedded copy of
/// their record, so revert/verify/VEX work without a manifest entry — the
/// vendored modes never write one; only this command's `detached: false`
/// entries are manifest-tracked.
///
/// Does NOT lock, read the manifest, load the ledger or print the envelope —
/// callers own all four. `ledger` is the vendor ledger the caller loaded
/// once under its apply lock (the same load that fed its staging harvest),
/// handed over for this run's persists; an unreadable one is reported here
/// as `vendor_state_unreadable`. Returns whether any non-benign failure
/// occurred.
// Tests drive the engine without a prior crawl through this shim.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor_records(
    common: &GlobalArgs,
    records: &HashMap<String, PatchRecord>,
    sources: &PatchSources<'_>,
    detached: bool,
    force: bool,
    env: &mut Envelope,
    service: Option<&VendorServiceConfig>,
    ledger: std::io::Result<VendorState>,
) -> bool {
    vendor_records_reusing(
        common, records, sources, detached, force, env, service, ledger, None, None,
    )
    .await
}

/// [`vendor_records`], resolving npm packages from `prior` — the npm half
/// of a crawl this process made earlier with the same options, over a tree
/// nothing has touched since (`scan`'s own crawl) — instead of walking
/// `node_modules` again: its roots feed the targeted lookup and its
/// packages the alias identity fallback. `None` (or a snapshot taken with
/// other options) crawls afresh.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vendor_records_reusing(
    common: &GlobalArgs,
    records: &HashMap<String, PatchRecord>,
    sources: &PatchSources<'_>,
    detached: bool,
    force: bool,
    env: &mut Envelope,
    service: Option<&VendorServiceConfig>,
    ledger: std::io::Result<VendorState>,
    prior: Option<&NpmCrawlSnapshot>,
    mut eject: Option<&mut EjectCapture>,
) -> bool {
    let mut has_errors = false;
    // This run's events start here (`scan --mode vendored` hands over an
    // envelope that already holds its own): the ones a refused commit
    // retracts.
    let events_start = env.events.len();
    // Lockfile flavors the backends wired THIS run (from the returned ledger
    // entries, not the whole ledger — an old pnpm entry must not re-flavor
    // the hints of a run that vendored only cargo). Drives the human
    // committable-files + reinstall hints below.
    let mut wired_flavors: HashSet<String> = HashSet::new();
    let manifest_purls: Vec<String> = records.keys().cloned().collect();
    let partitioned = partition_purls(&manifest_purls, common.ecosystems.as_deref());

    // Purls with no vendor backend (jsr) are expected skips, not failures.
    let (vendorable, unsupported): (Vec<String>, Vec<String>) = partitioned
        .values()
        .flatten()
        .cloned()
        .partition(|p| vendor::is_vendorable(p));
    for purl in &unsupported {
        env.record(
            PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                "vendor_unsupported_ecosystem",
                "vendoring is not supported for this ecosystem",
            ),
        );
    }

    // An empty record set says nothing about scope: the caller knows why
    // it is empty (an empty manifest, or a download phase that refused or
    // failed every patch and already said so) and reports it.
    if vendorable.is_empty() {
        if !records.is_empty() && !common.json && !common.silent {
            println!("No vendorable patches in scope.");
        }
        return has_errors;
    }

    let vendorable_partition: HashMap<Ecosystem, Vec<String>> = partitioned
        .into_iter()
        .map(|(eco, purls)| {
            (
                eco,
                purls
                    .into_iter()
                    .filter(|p| vendor::is_vendorable(p))
                    .collect(),
            )
        })
        .collect();

    // The vendor ledger, loaded ONCE per run by the caller (under its lock)
    // and handed over here; every read and per-package persist below uses
    // this copy. An unreadable ledger fails here, before the crawler walk
    // and any registry traffic.
    let mut state = match ledger {
        Ok(s) => std::sync::Arc::new(s),
        Err(e) => {
            env.mark_error(EnvelopeError::new("vendor_state_unreadable", e.to_string()));
            report_state_unreadable(common, &e);
            return true;
        }
    };
    // Pre-stage trees a previous run left behind (it crashed or was
    // interrupted between staging an archive and settling): nothing of
    // this run is staged yet, and the caller holds the apply lock, so every
    // one on disk is stale scratch. A dry run deletes nothing.
    if !common.dry_run {
        vendor::prestage::sweep_stale(&common.cwd).await;
    }

    let crawler_options = common.crawler_options();
    // Resolve installed packages with the qualified-purl-aware resolver, never
    // a base-keyed one: the manifest keys release-variant ecosystems (gem
    // `?platform=`, pypi `?artifact_id=`, maven `?classifier=&ext=`) by
    // *qualified* purls, but the crawler only knows the *base* purl, so a
    // base-keyed map would misclassify every installed qualified purl as
    // "not installed". The rollback variant fans each base path back out to
    // every qualified manifest purl.
    let mut all_packages: HashMap<String, StagedSource> = find_packages_for_rollback_reusing(
        &vendorable_partition,
        &crawler_options,
        common.silent || common.json,
        prior,
    )
    .await
    .into_iter()
    .map(|(purl, dir)| (purl, StagedSource::Installed(dir)))
    .collect();

    // An npm alias is installed under its dependency key, not its actual
    // package name. The targeted resolver probes canonical paths; before
    // fetching a supposedly missing source, resolve aliases by the installed
    // package.json identity. This also permits offline binary Bun vendoring.
    let missing_npm: Vec<&String> = vendorable_partition
        .get(&Ecosystem::Npm)
        .into_iter()
        .flatten()
        .filter(|p| !all_packages.contains_key(*p))
        .collect();
    let by_identity = match prior.and_then(|p| p.packages_for(&crawler_options)) {
        Some(installed) => npm_paths_by_identity_in(installed, &missing_npm),
        None => npm_paths_by_identity(&crawler_options, &missing_npm).await,
    };
    for (purl, paths) in by_identity {
        all_packages.insert(purl, StagedSource::Installed(paths[0].clone()));
    }
    let vendored_installs =
        drop_vendored_installs_by(&common.cwd, &mut all_packages, |source| match source {
            StagedSource::Installed(path) => Some(path.as_path()),
            StagedSource::Missing(_) => None,
        });

    let inventory: Arc<tokio::sync::OnceCell<Vec<lock_inventory::LockfileEntry>>> =
        Arc::new(tokio::sync::OnceCell::new());
    let mut fetch_failed: HashSet<String> = HashSet::new();
    let references =
        crate::commands::vendored_backend::repair::scan_vendor_references(&common.cwd).await;
    for purl in &vendorable {
        let record = &records[purl];
        if lookup_entry(&state.entries, purl).is_none_or(|entry| entry.uuid != record.uuid)
            && references.iter().any(|(eco, uuid, _)| {
                uuid == &record.uuid
                    && (vendor::ecosystem_dir_for_purl(purl) == Some(eco.as_str())
                        || (eco == "maven2" && purl.starts_with("pkg:maven/")))
            })
        {
            let detail = match vendored_installs.get(purl) {
                Some(dir) => format!("installed from the vendored artifact {dir}, but the vendor ledger has no entry for it; restore .socket/vendor/state.json from version control"),
                None => "the lockfile references this patch without its vendor ledger entry; restore .socket/vendor/state.json from version control".to_string(),
            };
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone())
                    .with_error("vendor_ledger_entry_missing", detail.clone()),
            );
            report_vendor_failure(common, purl, &detail);
            fetch_failed.insert(purl.clone());
            all_packages.remove(purl);
            continue;
        }
        all_packages.entry(purl.clone()).or_insert_with(|| {
            StagedSource::Missing(common.cwd.join(".socket/vendor/.uninstalled"))
        });
    }

    let vendored_at = now_rfc3339();

    // Bun vendored preflight (see `crate::commands::bun_preflight`), run
    // ONCE per run over the in-scope records and consulted per candidate
    // BEFORE the hosted→vendored takeover: the takeover reverts a hosted
    // purl's lockfile edits first, so a bun refusal the engine would raise
    // afterwards (pre-v2 text `workspace:` lock, unsupported project) must
    // be raised before it, or the purl ends up unpatched in both modes.
    // A purl the ledger wires at the record's uuid is exempt.
    let bun_pairs: Vec<(&str, &str)> = vendorable
        .iter()
        .filter_map(|p| records.get(p).map(|r| (p.as_str(), r.uuid.as_str())))
        .collect();
    let bun_refusal = bun_vendor_preflight_pairs(&common.cwd, &bun_pairs, Ok(&state.entries)).await;
    // The vlt twin (see `crate::commands::vlt_preflight`): every refusal
    // the vlt backend can decide from the lock, the package.json files,
    // the ledger and the installed copy, consulted per candidate before
    // the takeover below reverts a live hosted redirect.
    let vlt_refusals =
        vlt_vendor_preflight_pairs(&common.cwd, &bun_pairs, Ok(&state.entries)).await;

    // Release-variant grouping (pypi `?artifact_id=`, gem `?platform=`):
    // the crawler emits base purls; match the manifest's qualified variants
    // against the installed distribution via the first-file probe.
    let mut variant_groups: HashMap<String, Vec<String>> = HashMap::new();
    for purl in &vendorable {
        if Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants()) {
            variant_groups
                .entry(strip_purl_qualifiers(purl).to_string())
                .or_default()
                .push(purl.clone());
        }
    }

    let mut matched: HashSet<String> = HashSet::new();
    let mut handled_bases: HashSet<String> = HashSet::new();

    // The lockfiles' hosted pins, for cross-mode takeovers: vendoring a purl
    // the lockfiles still pin hosted must restore its upstream registry
    // entry FIRST (see the dispatch loop below). Discovered once, before any
    // write of this run.
    let hosted_pins: Vec<socket_patch_core::patch::redirect::upstream::HostedPin> =
        socket_patch_core::patch::redirect::upstream::HostedPin::all(
            &crate::commands::discover_wiring(common, &common.cwd).await,
        );
    let hosted_pin_of = |purl: &str| {
        hosted_pins
            .iter()
            .find(|pin| PurlKey::same(&pin.purl, purl))
    };

    // Yarn berry / npm package-lock takeover preflight (see
    // `socket_patch_core::vendor::yarn_berry_vendor_preflight` and
    // `npm_lock_vendor_preflight`): the backend's project-level refusals
    // (berry: mixed line endings in yarn.lock or package.json, cacheKey,
    // `.yarnrc.yml` compressionLevel; package-lock: a lock that is not
    // v2/v3, #659), computed at
    // most once per run and only when a hosted-claimed npm purl reaches the
    // takeover below, which must refuse such a purl BEFORE reverting its
    // hosted edits.
    let npm_takeover_refusal: tokio::sync::OnceCell<Option<(&'static str, String)>> =
        tokio::sync::OnceCell::new();
    let pipenv_version = tokio::sync::OnceCell::new();
    // The vlt store entries each hosted→vendored takeover unpinned, healed
    // once the purl is vendored.
    let mut vlt_takeover_targets: HashMap<
        String,
        Vec<socket_patch_core::patch::redirect::vlt_heal::LedgerTarget>,
    > = HashMap::new();
    let installed_sites = vendor::pypi::InstalledSiteListings::default();
    let mut dry_in_sync: u32 = 0;
    // Sorted, so per-package lines print in the same order every run.
    let mut all_packages: Vec<(String, StagedSource)> = all_packages.into_iter().collect();
    all_packages.sort_by(|a, b| a.0.cmp(&b.0));
    // Progress over the per-package engine calls (download, pack, lockfile
    // rewrite): shown only while an engine call runs, so every per-package
    // line prints on a clean line.
    let mut status = StatusLine::stderr(common.json, common.silent);
    let total = all_packages.len();
    // The vendored artifact dirs before this run wrote any: a commit the
    // symlink check refuses (or that fails with nothing written) removes
    // the ones the loop added, so it leaves no orphan artifact behind
    // (#898). A dir the pre-run ledger
    // already names (an artifact redownloaded in place) is kept: it needs
    // no commit to be referenced.
    let vendor_dirs_before = (!common.dry_run).then(|| VendorDirsBefore {
        dirs: EjectSnapshot::vendor_dir_set(&common.cwd),
        referenced: state
            .entries
            .values()
            .map(|e| common.cwd.join(&e.artifact.path))
            .collect(),
    });

    // Service downloads, fetched ahead of this serial loop (the wiring and
    // every write stay here, in order). The plan is EXACT — only the
    // records the loop will ask the service for (see
    // `plan_service_downloads`): a download grant can start a server-side
    // build and counts against quota, so a package the loop refuses is
    // never granted on its behalf. The plan stays advisory — every outcome
    // is still decided at the loop's own call (see `VendorPrefetch`).
    let service_prefetch = match service.filter(|cfg| !common.dry_run && cfg.wants_prefetch()) {
        Some(cfg) => {
            let takeover_blocked = |purl: &str| hosted_pin_of(purl).is_some();
            let planned = plan_service_downloads(
                &common.cwd,
                force,
                &all_packages,
                &variant_groups,
                records,
                &state,
                &fetch_failed,
                bun_refusal.as_ref(),
                &takeover_blocked,
                (&pipenv_version, &installed_sites),
            )
            .await;
            cfg.prefetch_archives(planned)
        }
        None => None,
    };
    // Group commit: from here until the loop ends, every backend's
    // lockfile / manifest / config edits, the takeover's hosted reverts and
    // the per-package ledger saves are captured in memory — every read in
    // the loop sees them — and written to disk ONCE, after the loop (see
    // `socket_patch_core::utils::group_commit`). A run that never reaches
    // the commit (a crash, a panic) leaves the pre-run lockfiles and ledgers
    // on disk; the artifacts it wrote are orphans the next run re-vendors
    // over. The replaced uuid dirs of re-vendored packages are swept only
    // after the commit, since until then the committed wiring still names
    // them. Dry runs write nothing and capture nothing.
    let group = (!common.dry_run
        && !socket_patch_core::utils::failpoint::switched_off("group_commit"))
    .then(|| GroupCommit::begin(&common.cwd));
    let mut stale_artifacts: Vec<StaleArtifact> = Vec::new();
    // The source of a superseded install (see [`superseded_install`]).
    let uninstalled = common.cwd.join(".socket/vendor/.uninstalled");
    for (index, (purl, staged)) in all_packages.iter().enumerate() {
        let pkg_source = staged.as_source();
        let is_variant_eco =
            Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants());
        let candidates: Vec<String> = if is_variant_eco {
            let base = strip_purl_qualifiers(purl).to_string();
            if !handled_bases.insert(base.clone()) {
                continue;
            }
            variant_groups
                .get(&base)
                .cloned()
                .unwrap_or_else(|| vec![base])
        } else {
            vec![purl.clone()]
        };

        for candidate in &candidates {
            let Some(record) = records.get(candidate) else {
                continue;
            };
            // Refused above (`vendor_ledger_entry_missing`); a sibling
            // variant's group must not bring it back.
            if fetch_failed.contains(candidate) {
                continue;
            }

            // Variant probe: only the installed distribution's variant is
            // vendored (mirrors apply / select_installed_variants). It hashes a
            // representative patch-target file against the installed package
            // dir, so it only works when those files are EXTRACTED on disk.
            // Maven's patch targets live INSIDE the un-extracted jar and its
            // vendor takes the single main jar regardless, so it is skipped.
            let probe_applicable = is_variant_eco
                && !matches!(Ecosystem::from_purl(candidate), Some(Ecosystem::Maven));
            // A deferred source was deferred because the ledger covers the
            // purl at this record's uuid: the variant the ledger vendored is
            // the installed one's by construction, so it answers the probe
            // without downloading the pristine tree just to read one file.
            let ledger_answers_probe =
                lookup_entry(&state.entries, candidate).is_some_and(|e| e.uuid == record.uuid);
            let mut candidate_source = pkg_source;
            if probe_applicable && !force && !ledger_answers_probe {
                if matches!(staged, StagedSource::Installed(_)) {
                    if let Some((file, info)) = representative_file(&record.files) {
                        if !variant_matches_installed(Some(
                            &verify_file_patch(pkg_source.path(), file, info)
                                .await
                                .status,
                        )) {
                            if !superseded_install(&state, candidate, record, candidates.len() == 1)
                            {
                                continue;
                            }
                            candidate_source = PackageSource::Installed(&uninstalled);
                        }
                    }
                } else if candidates.len() > 1 && lookup_entry(&state.entries, candidate).is_none()
                {
                    // Nothing installed to probe: a variant the ledger
                    // records (at any uuid) is the wired distribution, so
                    // its siblings are left out and accounted for by it.
                    if candidates
                        .iter()
                        .any(|c| lookup_entry(&state.entries, c).is_some())
                    {
                        continue;
                    }
                    let detail = "multiple patch variants match an uninstalled package; select one release variant";
                    env.record(
                        PatchEvent::new(PatchAction::Failed, candidate.clone())
                            .with_error("vendor_variant_ambiguous", detail),
                    );
                    report_vendor_failure(common, candidate, detail);
                    fetch_failed.insert(candidate.clone());
                    continue;
                }
            }
            matched.insert(candidate.clone());

            // The Bun/vlt preflight verdicts (computed once above): refuse
            // HERE, with the engine's own code and detail, before the
            // takeover block below can revert a live hosted redirect.
            if let Some(refusal) = bun_refusal.as_ref().filter(|r| r.applies_to(candidate)) {
                has_errors = true;
                env.record(
                    PatchEvent::new(PatchAction::Failed, candidate.clone())
                        .with_error(refusal.code, refusal.detail.clone()),
                );
                report_vendor_failure(common, candidate, &refusal.detail);
                continue;
            }
            if let Some(refusal) = vlt_refusal_for(&vlt_refusals, candidate) {
                has_errors = true;
                env.record(
                    PatchEvent::new(PatchAction::Failed, candidate.clone())
                        .with_error(refusal.code, refusal.detail.clone()),
                );
                report_vendor_failure(common, candidate, &refusal.detail);
                continue;
            }
            // A linked vendor dir (#664) is refused before the takeover
            // below can restore a live hosted pin's upstream entry: the
            // refusal must leave the hosted patch wired.
            if let Some(detail) = linked_vendor_dir_refusal(&common.cwd, candidate, &record.uuid) {
                has_errors = true;
                env.record(
                    PatchEvent::new(PatchAction::Failed, candidate.clone())
                        .with_error("vendor_dir_symlink_unsupported", detail.clone()),
                );
                report_vendor_failure(common, candidate, &detail);
                continue;
            }

            // Cross-mode takeover: vendoring over a LIVE hosted pin must
            // first restore the upstream registry entry (v5 keeps no hosted
            // ledger: the entry is re-resolved from the registry). Cargo:
            // `[patch.crates-io]` only patches crates-io-sourced deps, so
            // vendoring on top of the hosted registry pin leaves the project
            // unbuildable. npm family: without the restore the vendor ledger
            // records the grant-tokenized HOSTED lock fragment as its
            // pre-vendor original. In every ecosystem the restore hands the
            // vendor detach the PRISTINE registry entry to record. A purl
            // whose upstream entry cannot be restored is REFUSED; the cargo
            // backend's `hosted_redirect_live` guard backstops the rest.
            // A wet takeover whose restore stayed in the group commit's
            // overlay: the point to roll back to when the backend below
            // does not vendor the purl, and the advisories that only hold
            // once it does (see `TakeoverUndo`).
            let mut takeover_undo: Option<TakeoverUndo> = None;
            if let Some(pin) = hosted_pin_of(candidate) {
                let origins = crate::commands::hosted_unwind::patch_server_origins(common);
                let restore_opts = socket_patch_core::patch::redirect::upstream::RestoreOptions {
                    dry_run: common.dry_run,
                    offline: common.offline,
                    patch_server_origins: origins.clone(),
                    bun_lockb: true,
                };
                // The refusal the berry backend would raise after the
                // restore, raised HERE instead — the same `failed` event,
                // code and detail, in the dry run and the wet run alike —
                // so the hosted wiring stays untouched.
                // The gem backend's manifest refusal, likewise raised before
                // the restore (a hosted `gems.rb` project cannot vendor), and
                // its Gemfile declaration refusal, evaluated on the restored
                // Gemfile (a gem declared inside a `group` block stays hosted).
                if candidate.starts_with("pkg:gem/") {
                    let refusal =
                        gem_takeover_refusal(&common.cwd, candidate, pin, &restore_opts).await;
                    if let Some((code, detail)) = refusal {
                        has_errors = true;
                        env.record(
                            PatchEvent::new(PatchAction::Failed, candidate.clone())
                                .with_error(code, detail.clone()),
                        );
                        report_vendor_failure(common, candidate, &detail);
                        continue;
                    }
                }
                if candidate.starts_with("pkg:npm/") {
                    let project = npm_takeover_refusal
                        .get_or_init(|| async {
                            match socket_patch_core::vendor::yarn_berry_vendor_preflight(
                                &common.cwd,
                            )
                            .await
                            {
                                Some(refusal) => Some(refusal),
                                None => {
                                    socket_patch_core::vendor::npm_lock_vendor_preflight(
                                        &common.cwd,
                                    )
                                    .await
                                }
                            }
                        })
                        .await
                        .clone();
                    let refusal = match project {
                        Some(refusal) => Some(refusal),
                        None => match socket_patch_core::vendor::npm_tarball_gitignore_preflight(
                            &common.cwd,
                            &record.uuid,
                        )
                        .await
                        {
                            Some(refusal) => Some(refusal),
                            None => {
                                socket_patch_core::vendor::yarn_berry_vendor_target_preflight(
                                    &common.cwd,
                                    candidate,
                                    pin,
                                    &restore_opts,
                                )
                                .await
                            }
                        },
                    };
                    if let Some((code, detail)) = &refusal {
                        has_errors = true;
                        env.record(
                            PatchEvent::new(PatchAction::Failed, candidate.clone())
                                .with_error(*code, detail.clone()),
                        );
                        report_vendor_failure(common, candidate, detail);
                        continue;
                    }
                }
                // The vendored sbt / scala-cli gate, before the restore: a
                // pin it would stop stays hosted (never neither).
                if let Err((code, detail)) =
                    socket_patch_core::vendor::maven_repo::jvm_gate_preflight(
                        &common.cwd,
                        candidate,
                    )
                    .await
                {
                    has_errors = true;
                    let detail = format!(
                        "kept the hosted pin: the vendored gate would not vendor it ({detail})"
                    );
                    env.record(
                        PatchEvent::new(PatchAction::Failed, candidate.clone())
                            .with_error(code, detail.clone()),
                    );
                    report_vendor_failure(common, candidate, &detail);
                    continue;
                }
                let vlt_lock = socket_patch_core::utils::fs::read_regular_to_string(
                    &common
                        .cwd
                        .join(socket_patch_core::constants::npm_family::VLT_LOCK),
                )
                .await
                .ok();
                let targets = vlt_lock
                    .as_deref()
                    .map(|lock| {
                        socket_patch_core::patch::redirect::vlt_heal::lock_targets(
                            lock,
                            &origins,
                            std::slice::from_ref(candidate),
                        )
                    })
                    .unwrap_or_default();
                let savepoint = group.as_ref().map(GroupCommit::savepoint);
                let restore = socket_patch_core::patch::redirect::upstream::restore_upstream(
                    &common.cwd,
                    std::slice::from_ref(pin),
                    &restore_opts,
                )
                .await;
                // Undoable only when every file the restore wrote is still
                // in the overlay (a `.socket/gradle/hosted-index.tsv` is
                // written straight to disk).
                let savepoint = savepoint.filter(|_| {
                    restore
                        .reverted_files
                        .iter()
                        .all(|f| socket_patch_core::utils::group_commit::captures(f))
                });
                let refusal = restore
                    .refused()
                    .map(|(_, why)| why.to_string())
                    .next()
                    .or_else(|| restore.flush_error.clone());
                if let Some(detail) = refusal {
                    // A flush that failed partway may have staged some of
                    // the restore: put the hosted wiring back.
                    if let (Some(savepoint), Some(group)) = (savepoint, group.as_ref()) {
                        group.rollback_to(savepoint);
                    }
                    has_errors = true;
                    env.record(
                        PatchEvent::new(PatchAction::Failed, candidate.clone()).with_error(
                            "redirect_revert_failed",
                            format!("cannot vendor over the live hosted pin: {detail}"),
                        ),
                    );
                    report_vendor_failure(
                        common,
                        candidate,
                        &format!("cannot restore the upstream entry: {detail}"),
                    );
                    continue;
                }
                let mut advisories: Vec<VendorWarning> = restore
                    .warnings
                    .iter()
                    .map(|(code, detail)| VendorWarning::new(code, detail.clone()))
                    .collect();
                if common.dry_run {
                    // The refusal the backend would raise over the restored
                    // project, previewed here with the wet run's code (the
                    // wet run rolls the restore back on it, below).
                    if let Some((code, detail)) = takeover_dry_refusal(
                        &restore,
                        candidate,
                        pkg_source,
                        &common.cwd,
                        record,
                        sources,
                        &vendored_at,
                        force,
                        service,
                        &pipenv_version,
                        &installed_sites,
                    )
                    .await
                    {
                        has_errors = true;
                        env.record(
                            PatchEvent::new(PatchAction::Failed, candidate.clone())
                                .with_error(code, detail.clone()),
                        );
                        report_vendor_failure(common, candidate, &detail);
                        continue;
                    }
                    for advisory in &advisories {
                        record_warning(env, candidate, advisory, common);
                    }
                    record_warning(
                        env,
                        candidate,
                        &VendorWarning::new(
                            "vendor_would_revert_redirect",
                            format!(
                                "{} is hosted; a non-dry-run vendor will restore its upstream \
                                 registry entry first, then vendor (mode takeover)",
                                normalize_purl(candidate)
                            ),
                        ),
                        common,
                    );
                    // The backend preview below reads the lock from disk,
                    // where the hosted wiring is still live. Bun's hosted
                    // rewrite REPLACES the entry's `name@version` spec, so the
                    // backend would refuse a `vendor_lock_entry_not_found`
                    // the wet run never sees: the advisory already states the
                    // plan, so the preview stops here.
                    //
                    // Likewise `socket-patch.sbt`: it still pins the GA on
                    // disk, so the sbt planner would refuse the
                    // `vendor_sbt_hosted_conflict` the wet run (which
                    // restores first) never sees.
                    if restore.reverted_files.iter().any(|f| {
                        f == "bun.lock"
                            || f == "bun.lockb"
                            || f == socket_patch_core::formats::sbt::owned_file::HOSTED_FILE
                    }) {
                        continue;
                    }
                } else {
                    advisories.push(VendorWarning::new(
                        "vendor_takeover_reverted_redirect",
                        format!(
                            "{} was hosted; restored its upstream registry entry ({}) \
                             before vendoring (mode takeover)",
                            normalize_purl(candidate),
                            restore.reverted_files.join(", ")
                        ),
                    ));
                    let undo = TakeoverUndo {
                        savepoint,
                        advisories,
                        vlt_targets: targets,
                    };
                    if undo.savepoint.is_some() {
                        takeover_undo = Some(undo);
                    } else {
                        undo.settle(env, common, candidate, &mut vlt_takeover_targets);
                    }
                }
            }

            // A dir-shaped entry with no file inventory (vendored before
            // inventories were recorded, or past the inventory cap) gives an
            // exact restore nothing to check a download against: the backend
            // below rebuilds its copy from a fresh verified download instead.
            if let Some(entry) = lookup_entry(&state.entries, candidate).filter(|entry| {
                entry.uuid == record.uuid
                    && (entry.artifact.file_inventory.is_some()
                        || vendor::artifact_is_file_shaped(&entry.artifact.path))
            }) {
                let redownload =
                    match vendor::check_vendored_artifact(&common.cwd, entry, record).await {
                        vendor::ArtifactHealth::Healthy => {
                            entry.artifact.sha256.is_empty()
                                && entry.artifact.file_inventory.is_none()
                                && vendor::artifact_is_file_shaped(&entry.artifact.path)
                        }
                        // Only a Bun member-relative mirror of the verified
                        // canonical tarball is off: the backend rewrites it from
                        // the committed tarball, offline too.
                        vendor::ArtifactHealth::Corrupt { reason }
                            if reason.starts_with("vendor_workspace_artifact_")
                                && !entry.artifact.sha256.is_empty() =>
                        {
                            false
                        }
                        _ => true,
                    };
                if redownload {
                    if common.dry_run {
                        env.record(PatchEvent::new(PatchAction::Verified, candidate.clone()).with_details(serde_json::json!({"wouldRedownload": true, "path": entry.artifact.path})));
                        continue;
                    }
                    let restored = match service {
                        Some(service) => {
                            vendor::redownload::restore(&common.cwd, entry, record, service).await
                        }
                        None => Err(
                            "vendoring requires a prebuilt artifact from the patch service"
                                .to_string(),
                        ),
                    };
                    match restored {
                        Ok(warnings) => {
                            for warning in &warnings {
                                record_warning(env, candidate, warning, common);
                            }
                            env.record(PatchEvent::new(PatchAction::Rebuilt, candidate.clone()).with_details(serde_json::json!({"redownloaded": true, "path": entry.artifact.path})));
                        }
                        Err(detail) => {
                            has_errors = true;
                            env.record(
                                PatchEvent::new(PatchAction::Failed, candidate.clone())
                                    .with_error("vendor_redownload_failed", detail.clone()),
                            );
                            report_vendor_failure(common, candidate, &detail);
                            if let Some(undo) = takeover_undo.take() {
                                undo.abandon(group.as_ref());
                            }
                            continue;
                        }
                    }
                }
            }

            status.set(format_vendor_progress(
                common.dry_run,
                &normalize_purl(candidate),
                index + 1,
                total,
            ));
            let outcome = dispatch_vendor_one(
                candidate,
                candidate_source,
                &common.cwd,
                record,
                sources,
                &vendored_at,
                common.dry_run,
                force,
                service,
                &pipenv_version,
                &installed_sites,
            )
            .await;
            status.finish();
            let vendored =
                matches!(&outcome, Some(VendorOutcome::Done { result, .. }) if result.success);
            if let Some(undo) = takeover_undo.take() {
                // A takeover the backend did not carry through keeps the
                // hosted pin: its restore is rolled back in the overlay, so
                // the purl is never left un-hosted AND unvendored (#853,
                // #944). One the backend recorded keeps the restore.
                let recorded =
                    matches!(&outcome, Some(VendorOutcome::Done { entry, .. }) if entry.is_some());
                if vendored || recorded || undo.savepoint.is_none() || group.is_none() {
                    undo.settle(env, common, candidate, &mut vlt_takeover_targets);
                } else {
                    undo.abandon(group.as_ref());
                }
            }

            let outcome =
                keep_older_vendored_patch(outcome, &state, candidate, &record.uuid, common).await;
            match outcome {
                None => {
                    env.record(
                        PatchEvent::new(PatchAction::Skipped, candidate.clone()).with_reason(
                            "vendor_unsupported_ecosystem",
                            "vendoring is not supported for this ecosystem",
                        ),
                    );
                }
                Some(VendorOutcome::Refused { code, detail }) => {
                    if refusal_is_benign(code) {
                        // An expected skip, not an error: informational.
                        if !common.silent && !common.json {
                            eprintln!("Skipping {}: {detail}", normalize_purl(candidate));
                        }
                        env.record(
                            PatchEvent::new(PatchAction::Skipped, candidate.clone())
                                .with_reason(code, detail.clone()),
                        );
                    } else {
                        has_errors = true;
                        report_vendor_failure(common, candidate, &detail);
                        env.record(
                            PatchEvent::new(PatchAction::Failed, candidate.clone())
                                .with_error(code, detail.clone()),
                        );
                    }
                }
                Some(VendorOutcome::Done {
                    result,
                    entry,
                    warnings,
                }) => {
                    if !result.success {
                        has_errors = true;
                        // The patch itself failed to apply to the staged copy.
                        if !common.json {
                            eprintln!(
                                "Error: Failed to vendor {}: {}",
                                normalize_purl(candidate),
                                result.error.as_deref().unwrap_or("unknown error")
                            );
                        }
                    }
                    let mut event = result_to_event(&result, common.dry_run);
                    // The shared translator's in-sync classification reads
                    // `already_patched`. Two distinct cases land there:
                    //
                    // * `entry` is None — the TRUE in-sync rerun (the backend
                    //   synthesized AlreadyPatched and recorded nothing);
                    //   under `vendor` the contract tag is `already_vendored`.
                    // * `entry` is Some — the FIRST vendor of a package
                    //   already patched in place by `apply`: every file
                    //   verified AlreadyPatched, but THIS run packed the
                    //   artifact and rewired the lock. That is an Applied
                    //   (`summary.applied` must count it), not a skip.
                    if event.action == PatchAction::Skipped
                        && event.error_code.as_deref() == Some("already_patched")
                    {
                        if entry.is_none() {
                            event = PatchEvent::new(PatchAction::Skipped, candidate.clone())
                                .with_reason(
                                    "already_vendored",
                                    "artifact and lockfile wiring already in sync",
                                );
                        } else {
                            let files = result
                                .files_verified
                                .iter()
                                .map(|f| crate::json_envelope::PatchEventFile {
                                    path: f.file.clone(),
                                    verified: true,
                                    applied_via: None,
                                })
                                .collect();
                            event = PatchEvent::new(PatchAction::Applied, candidate.clone())
                                .with_files(files);
                        }
                    }
                    // A dry run previews an in-sync package as `verified`
                    // (the backends cannot tell without writing); the
                    // ledger recording this exact patch is the tell.
                    let dry_previewed_in_sync = common.dry_run
                        && event.action == PatchAction::Verified
                        && lookup_entry(&state.entries, candidate)
                            .is_some_and(|e| e.uuid == record.uuid);
                    if dry_previewed_in_sync {
                        dry_in_sync += 1;
                    }
                    let in_sync = event.error_code.as_deref() == Some("already_vendored");
                    // An in-sync package's wet run writes nothing, so it
                    // cannot hit the commit's symlink refusal.
                    let symlinked =
                        if common.dry_run && result.success && !in_sync && !dry_previewed_in_sync {
                            symlinked_wiring_warnings(&common.cwd, candidate)
                        } else {
                            Vec::new()
                        };
                    env.record(event);
                    for w in &symlinked {
                        record_warning(env, candidate, w, common);
                    }
                    for w in &warnings {
                        // "vendored X from the patch service" on a package
                        // this run left untouched would contradict the
                        // "already vendored" count: JSON only.
                        if in_sync && w.code == "vendor_prebuilt_downloaded" {
                            push_advisory_event(env, candidate, w);
                        } else {
                            record_warning(env, candidate, w, common);
                        }
                    }
                    // An artifact-only rebuild hands back a refreshed
                    // fingerprint with no wiring of its own: it relies on
                    // the ledger entry it replaces for the pre-vendor
                    // originals, and `carry_forward_wiring` re-attaches them
                    // only from a SAME-uuid predecessor. With no such entry
                    // (none at all, or one from another patch generation),
                    // recording it would give `--revert` an entry that
                    // deletes the artifact yet cannot unwire the project —
                    // leave the ledger as is.
                    let rebuilt = warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt");
                    let entry = entry.filter(|e| {
                        !rebuilt
                            || state
                                .entries
                                .get(candidate.as_str())
                                .is_some_and(|prev| prev.uuid == e.uuid)
                    });
                    if let Some(entry) = entry {
                        if let Some(flavor) = entry.flavor.as_deref() {
                            wired_flavors.insert(flavor.to_string());
                        } else if entry.ecosystem == "composer" {
                            wired_flavors.insert("composer".to_string());
                        } else if let Some(tool) = jvm_wiring_tool(&entry.wiring) {
                            wired_flavors.insert(tool.to_string());
                        }
                        let (save_failed, stale) = record_vendor_entry(
                            common, env, &mut state, candidate, entry, detached, record,
                        )
                        .await;
                        has_errors |= save_failed;
                        socket_patch_core::utils::failpoint::hit("vendor_package_recorded");
                        if let Some(stale) = stale {
                            if group.is_some() {
                                stale_artifacts.push(stale);
                            } else {
                                sweep_stale_artifact(common, env, &state, stale).await;
                            }
                        }
                    }
                }
            }
            // The reverted hosted pin is gone either way: a vendored purl
            // is healed against its new wiring, a failed one against the
            // restored registry pin.
            if let Some(targets) = vlt_takeover_targets.remove(candidate) {
                let detail = if vendored {
                    crate::commands::vlt_heal::takeover_heal(common, &targets).await
                } else {
                    crate::commands::vlt_heal::rollback_heal(common, &targets)
                        .await
                        .into_iter()
                        .map(|(_, detail)| detail)
                        .next()
                };
                if let Some(detail) = detail {
                    record_warning(
                        env,
                        candidate,
                        &VendorWarning::new("redirect_vlt_reinstall_required", detail),
                        common,
                    );
                }
            }
        }
    }

    // The loop is done with the service: detach the download plan (and stop
    // what is still in flight), then remove whatever it staged that no
    // backend claimed — a download the breaker skipped or the loop passed
    // over. Never earlier: the loop's own unwinds prune empty vendor levels,
    // and a concurrent removal could race them.
    drop(service_prefetch);
    vendor::prestage::settle().await;

    // The run's one commit of every lockfile, manifest, config and ledger
    // the loop changed. The packages that succeeded are committed even when
    // others failed — a failed package's backend already put back what it
    // had touched, in the captured state — so a completed run ends exactly
    // where committing after every package would have left it.
    let mut commit_failed = false;
    if let Some(group) = group {
        socket_patch_core::utils::failpoint::hit("vendor_group_commit");
        match group.commit_changes().await {
            Ok(changes) => {
                if let Some(capture) = eject.as_deref_mut() {
                    capture.committed.extend(changes);
                }
                for stale in stale_artifacts {
                    sweep_stale_artifact(common, env, &state, stale).await;
                }
            }
            Err(e) if socket_patch_core::utils::group_commit::symlinked_target(&e).is_some() => {
                // Refused before any lockfile, manifest or ledger was
                // written: the hosted refusal, same code and wording. The
                // artifacts the loop already downloaded are removed, and
                // the packages it vendored are reported as refused, not
                // applied — nothing of them was committed (#898).
                has_errors = true;
                commit_failed = true;
                let linked = socket_patch_core::utils::group_commit::symlinked_target(&e)
                    .unwrap_or_default();
                let refusal = socket_patch_core::hosted::engine::symlink_refusal(linked);
                let mut message = refusal.message;
                let leftovers = remove_new_vendor_dirs(common, vendor_dirs_before.as_ref()).await;
                if !leftovers.is_empty() {
                    message = format!(
                        "{} (except the downloaded artifacts that could not be removed: {}; \
                         `socket-patch vendor --revert` removes them)",
                        message,
                        leftovers.join("; ")
                    );
                }
                env.retract_applied(events_start, PatchAction::Failed, &refusal.code, &message);
                if !common.json {
                    eprintln!("Error: {message}");
                }
                env.mark_error(EnvelopeError::new(refusal.code, message));
            }
            Err(e) => {
                has_errors = true;
                commit_failed = true;
                let detail = if socket_patch_core::utils::group_commit::is_pending(&e) {
                    // Some files were replaced and could not be put back:
                    // the journal left behind makes the next locked command
                    // finish the commit.
                    format!(
                        "could not commit the vendored lockfile, manifest and ledger edits: \
                         {e}; the commit is journaled and the next socket-patch command in \
                         this project finishes it"
                    )
                } else {
                    // Nothing was committed: like the symlink refusal
                    // (#898), the artifacts the loop downloaded are removed
                    // and its packages are reported failed, not applied.
                    let mut detail = format!(
                        "could not commit the vendored lockfile, manifest and ledger edits: \
                         {e}; the project's lockfiles and .socket/vendor/state.json are \
                         unchanged"
                    );
                    let leftovers =
                        remove_new_vendor_dirs(common, vendor_dirs_before.as_ref()).await;
                    if !leftovers.is_empty() {
                        detail = format!(
                            "{detail} (except the downloaded artifacts that could not be \
                             removed: {}; `socket-patch vendor --revert` removes them)",
                            leftovers.join("; ")
                        );
                    }
                    env.retract_applied(
                        events_start,
                        PatchAction::Failed,
                        "vendor_commit_failed",
                        &detail,
                    );
                    detail
                };
                if !common.json {
                    eprintln!("Error: {detail}");
                }
                env.mark_error(EnvelopeError::new("vendor_commit_failed", detail));
            }
        }
    }

    // Manifest entries that targeted in-scope ecosystems but had no
    // installed package on disk (and could not be auto-fetched).
    let mut unmatched: Vec<String> = vendorable
        .iter()
        .filter(|p| !matched.contains(*p) && !fetch_failed.contains(*p))
        .cloned()
        .collect();
    unmatched.sort();
    // A base that vendored one variant accounts for its qualified siblings.
    let vendored_bases: HashSet<PurlKey> = matched.iter().map(|p| PurlKey::new(p)).collect();
    unmatched.retain(|p| !vendored_bases.contains(&PurlKey::new(p)));
    has_errors |= !fetch_failed.is_empty();
    if !unmatched.is_empty() {
        has_errors = true;
        // Offline runs name the packages the lockfile COULD have fetched —
        // the inventory is a local file read, allowed offline (and reused
        // when the fetch rung above already built it).
        let lock_resolvable: HashSet<String> = if common.offline {
            let entries = inventory
                .get_or_init(|| lock_inventory::inventory_project(&common.cwd))
                .await;
            unmatched
                .iter()
                .filter(|p| lock_inventory::lookup(entries, p).is_some())
                .cloned()
                .collect()
        } else {
            HashSet::new()
        };
        for purl in &unmatched {
            if let Some(dir) = vendored_installs.get(purl) {
                // The only installed copy is this tool's own artifact, which
                // is never a pristine source: say so, not "not installed".
                match lookup_entry(&state.entries, purl) {
                    None => {
                        let detail = format!(
                            "installed from the vendored artifact {dir}, but the vendor ledger \
                             has no entry for it; restore .socket/vendor/state.json from version control"
                        );
                        report_vendor_failure(common, purl, &detail);
                        env.record(
                            PatchEvent::new(PatchAction::Failed, purl.clone())
                                .with_error("vendor_ledger_entry_missing", detail),
                        );
                        continue;
                    }
                    Some(entry) if records.get(purl).is_some_and(|r| r.uuid != entry.uuid) => {
                        let blocked = if common.offline {
                            "--offline prevents fetching the pristine artifact from the registry"
                        } else {
                            "no pristine artifact could be fetched"
                        };
                        let detail = format!(
                            "the only installed copy is the vendored artifact {dir} of patch \
                             {}, which is not a pristine source for this patch; {blocked}",
                            entry.uuid
                        );
                        report_vendor_failure(common, purl, &detail);
                        env.record(
                            PatchEvent::new(PatchAction::Skipped, purl.clone())
                                .with_reason("package_not_installed", detail),
                        );
                        continue;
                    }
                    Some(_) => {
                        let detail = format!(
                            "the only installed copy is the vendored artifact {dir}, which is \
                             not a pristine source, and its ledger entry records no file \
                             inventory to stage the committed artifact against"
                        );
                        report_vendor_failure(common, purl, &detail);
                        env.record(
                            PatchEvent::new(PatchAction::Skipped, purl.clone())
                                .with_reason("package_not_installed", detail),
                        );
                        continue;
                    }
                }
            }
            // Honesty order: every purl here is first and foremost a crawler
            // miss — nothing on disk matched — so the on-disk cause leads.
            // The --offline note is strictly secondary and only stated when
            // it is actually what blocked the fallback (the lockfile resolves
            // the package, so a non-offline run would have auto-fetched it).
            let detail = if lock_resolvable.contains(purl) {
                "no installed package found on disk; the lockfile resolves it, but \
                 --offline prevents fetching the pristine artifact from the registry"
            } else {
                "no installed package found on disk"
            };
            // Fails the run (exit 1), so it is an error line.
            report_vendor_failure(common, purl, detail);
            env.record(
                PatchEvent::new(PatchAction::Skipped, purl.clone())
                    .with_reason("package_not_installed", detail),
            );
        }
    }

    // A rolled-back eject's summary would describe a vendoring that was
    // undone: the eject prints it itself once it knows the outcome (#1005).
    match eject {
        Some(capture) => capture.wired_flavors = wired_flavors,
        None => print_vendor_closing(common, env, dry_in_sync, &wired_flavors, !commit_failed),
    }

    has_errors
}

/// The human close of a vendor run: the summary line, then — when
/// something was vendored and `next_steps` (the run's commit landed) — the
/// commit and reinstall "Next steps:" for the lockfile flavors the run
/// wired.
fn print_vendor_closing(
    common: &GlobalArgs,
    env: &Envelope,
    dry_in_sync: u32,
    wired_flavors: &HashSet<String>,
    next_steps: bool,
) {
    if common.json || common.silent {
        return;
    }
    let tally = VendorTally::from_envelope(env, common.dry_run, dry_in_sync);
    println!("{}", format_vendor_summary(common.dry_run, &tally));
    if env.summary.applied > 0 && !common.dry_run && next_steps {
        // pnpm >=11 reads `overrides` ONLY from pnpm-workspace.yaml (the
        // package.json `pnpm.overrides` mirror is ignored), so pnpm-wired
        // runs must name that file among the committables: a checkout
        // that loses it silently unvendors on the next install.
        // A project pinned to pnpm 9.0–10.4 gets no pnpm-workspace.yaml
        // (#734), so the file is named only when it is there.
        let commit = commit_hint(
            wired_flavors,
            common.cwd.join("pnpm-workspace.yaml").exists(),
        );
        let mut installs: Vec<&str> = wired_flavors
            .iter()
            .filter_map(|f| flavor_install_command(f))
            .collect();
        installs.sort_unstable();
        installs.dedup();
        let jvm_only = !installs.is_empty()
            && wired_flavors
                .iter()
                .filter(|f| flavor_install_command(f).is_some())
                .all(|f| JVM_TOOLS.contains(&f.as_str()));
        let reinstall = if jvm_only {
            let cmds: Vec<String> = installs.iter().map(|c| format!("`{c}`")).collect();
            format!(
                "Run {} so the build resolves the vendored artifacts (the generated root \
                 file points it at .socket/vendor/)",
                cmds.join(" and ")
            )
        } else if installs.is_empty() {
            "Reinstall from the updated lockfile so the installed packages pick up the \
             vendored artifacts"
                .to_string()
        } else {
            let cmds: Vec<String> = installs.iter().map(|c| format!("`{c}`")).collect();
            format!(
                "Run {} to update the installed tree (vendoring rewires the lockfile \
                 only; the current install keeps the unpatched bytes until reinstalled)",
                cmds.join(" and ")
            )
        };
        let mut extra = Vec::new();
        if wired_flavors.contains("bun") && common.cwd.join("bun.lockb").exists() {
            extra.push(
                "For binary Bun workspaces, also commit the workspace members' \
                 .socket/vendor/ tarballs recorded in the vendor ledger."
                    .to_string(),
            );
        }
        if wired_flavors.contains("composer") {
            if let Ok(lock) = socket_patch_core::utils::fs::read_regular_to_string_sync(
                &common.cwd.join("composer.lock"),
            ) {
                let packages = super::composer_hints::vendored_composer_packages(&lock);
                let vendor_dir = super::composer_hints::vendor_dir_label(&common.cwd);
                extra.extend(super::composer_hints::vendored_reinstall_hints(
                    &packages,
                    &vendor_dir,
                ));
            }
        }
        for line in crate::ui::next_steps(&commit, &reinstall, &extra) {
            println!("{line}");
        }
    }
}

/// The vendored artifact dirs a run started with (see
/// [`EjectSnapshot::vendor_dir_set`]), and the artifact paths its ledger
/// named then.
struct VendorDirsBefore {
    dirs: std::collections::BTreeSet<std::path::PathBuf>,
    referenced: Vec<std::path::PathBuf>,
}

/// Remove the vendored artifact dirs that appeared since `before`, except
/// one holding an artifact the pre-run ledger names (redownloaded in place,
/// referenced without any commit), returning what could not be removed.
async fn remove_new_vendor_dirs(
    common: &GlobalArgs,
    before: Option<&VendorDirsBefore>,
) -> Vec<String> {
    let Some(before) = before else {
        return Vec::new();
    };
    let mut leftovers = Vec::new();
    for dir in EjectSnapshot::vendor_dir_set(&common.cwd).difference(&before.dirs) {
        if before.referenced.iter().any(|p| p.starts_with(dir)) {
            continue;
        }
        if let Err(e) = remove_tree_and_prune(dir, &common.cwd.join(SOCKET_DIR)).await {
            leftovers.push(format!("{}: {e}", dir.display()));
        }
    }
    leftovers
}

/// What a hosted→vendored eject's vendored apply hands back instead of
/// printing its own close: every project file its group commit wrote (with
/// the bytes from before, for the rollback) and the lockfile flavors it
/// wired (for the "Next steps:" the eject prints only when it completes).
#[derive(Default)]
pub(crate) struct EjectCapture {
    pub(crate) committed: Vec<CommittedFile>,
    pub(crate) wired_flavors: HashSet<String>,
}

/// The pseudo-flavors of vendored JVM builds whose wiring is a generated
/// root file rather than a lockfile.
const JVM_TOOLS: &[&str] = &["sbt", "scala-cli"];

/// `sbt` / `scala-cli` when `wiring` is that vendored backend's (a ledger
/// entry of either records ecosystem `maven` and no flavor).
fn jvm_wiring_tool(wiring: &[vendor::state::WiringRecord]) -> Option<&'static str> {
    use socket_patch_core::vendor::jvm::{COURSIER_INDEX_KIND, SBT_FRAGMENT_KIND};
    if wiring.iter().any(|w| w.kind == SBT_FRAGMENT_KIND) {
        Some("sbt")
    } else if wiring.iter().any(|w| w.kind == COURSIER_INDEX_KIND) {
        Some("scala-cli")
    } else {
        None
    }
}

/// The "Commit …" next step for the flavors a run wired. sbt and scala-cli
/// wire through a generated root file, never a lockfile: committing only
/// `.socket/` would leave CI resolving the unpatched upstream silently.
fn commit_hint(wired: &HashSet<String>, pnpm_workspace: bool) -> String {
    if wired.contains("pnpm") && pnpm_workspace {
        return ".socket/vendor/, package.json, pnpm-lock.yaml, and pnpm-workspace.yaml to make \
                the patches portable (pnpm >=11 reads the vendored override only from \
                pnpm-workspace.yaml)"
            .to_string();
    }
    if wired.contains("pnpm") {
        return ".socket/vendor/, package.json, and pnpm-lock.yaml to make the patches \
                portable (the project's pnpm 9.0–10.4 reads the override from package.json; \
                after upgrading to pnpm >=11, re-run vendor so it also writes \
                pnpm-workspace.yaml)"
            .to_string();
    }
    if wired.contains("vlt") {
        return VLT_COMMIT_HINT.to_string();
    }
    let mut roots: Vec<&str> = Vec::new();
    if wired.contains("sbt") {
        roots.push(socket_patch_core::vendor::jvm::sbt::BUILD_FILE);
    }
    if wired.contains("scala-cli") {
        roots.push(socket_patch_core::vendor::jvm::scala_cli::ROOT_FILE);
    }
    let lockfiles = wired.iter().any(|f| !JVM_TOOLS.contains(&f.as_str())) || roots.is_empty();
    match (roots.is_empty(), lockfiles) {
        (true, _) => {
            ".socket/vendor/ and the updated lockfiles to make the patches portable".into()
        }
        (false, false) => format!(
            "{} and .socket/vendor/ to make the patches portable (without the root file the \
             build resolves the unpatched upstream)",
            roots.join(", ")
        ),
        (false, true) => format!(
            "{}, .socket/vendor/ and the updated lockfiles to make the patches portable",
            roots.join(", ")
        ),
    }
}

/// What a vlt-wired run commits (the "Commit …" next step).
const VLT_COMMIT_HINT: &str = "package.json (and workspace package.json files), \
     vlt-lock.json and .socket/vendor/ (the .gitignore there re-includes the payload and keeps \
     vlt's node_modules links out of git); CI: `vlt ci`";

/// The install command that re-materializes the project tree from the wired
/// lockfile, per npm-family flavor. Vendoring edits ONLY the lockfile/config
/// wiring — the already-installed node_modules keeps its pre-vendor bytes
/// until the package manager reinstalls from the rewired lock — so a
/// successful vendor must say how to update it. `None` for flavors whose
/// consuming step is not an install.
fn flavor_install_command(flavor: &str) -> Option<&'static str> {
    match flavor {
        "package-lock" => Some("npm install"),
        "yarn-classic" | "yarn-berry" => Some("yarn install"),
        // pnpm-legacy (lockfileVersion 5.4/6.0): plain `pnpm install` is also
        // the moved-checkout recovery — pnpm <= 8 absolutizes file: override
        // specifiers, so `--frozen-lockfile` only passes at the vendoring path.
        "pnpm" | "pnpm-legacy" => Some("pnpm install"),
        "bun" => Some("bun install"),
        "vlt" => Some("vlt install"),
        // Not an install: the JVM build re-resolves from the vendored tree.
        "sbt" => Some("sbt update"),
        "scala-cli" => Some("scala-cli compile --test ."),
        _ => None,
    }
}

/// The install that resyncs an installed tree after a revert: Bun's
/// hoisted linker keeps the vendored copy through a plain `bun install`
/// (#764), so Bun's needs `--force`.
fn flavor_revert_install_command(flavor: &str) -> Option<&'static str> {
    match flavor {
        "bun" => Some("bun install --force"),
        other => flavor_install_command(other),
    }
}

/// Drop installed npm copies that resolve into `.socket/vendor/` (or no
/// longer resolve at all): vlt links a vendored `file:` dependency straight
/// to its committed dir, which is this tool's own artifact and never a
/// pristine source. The committed-artifact rung stages it
/// inventory-verified instead. Returns the dropped purls whose copy
/// resolved into a vendored uuid dir, with that dir
/// (`.socket/vendor/<eco>/<uuid>/`). Works over any source map: `path_of`
/// names an entry's installed location, and entries without one are kept.
fn drop_vendored_installs_by<V>(
    cwd: &Path,
    packages: &mut HashMap<String, V>,
    path_of: impl Fn(&V) -> Option<&Path>,
) -> HashMap<String, String> {
    let mut dropped = HashMap::new();
    let Ok(vendor_root) = std::fs::canonicalize(cwd.join(SOCKET_DIR).join("vendor")) else {
        return dropped;
    };
    packages.retain(|purl, source| {
        if !purl.starts_with("pkg:npm/") {
            return true;
        }
        let Some(path) = path_of(source) else {
            return true;
        };
        let Ok(real) = std::fs::canonicalize(path) else {
            return false;
        };
        let Ok(rest) = real.strip_prefix(&vendor_root) else {
            return true;
        };
        let mut parts = rest.components().map(|c| c.as_os_str().to_string_lossy());
        if let (Some(eco), Some(uuid)) = (parts.next(), parts.next()) {
            dropped.insert(purl.clone(), format!(".socket/vendor/{eco}/{uuid}/"));
        }
        false
    });
    dropped
}

/// Ledger entries whose patch is gone from the manifest — the stale test
/// shared by [`reconcile_dropped`] and [`run_vendor_gc`]. Respects this
/// run's --ecosystems scope: a `vendor --ecosystems npm` invocation must
/// not silently revert a cargo/go entry (restoring its lockfile and
/// deleting its artifact) as a cross-ecosystem side effect. Detached
/// entries — every `scan`/`get --mode vendored` entry — are never
/// manifest-tracked, so "absent from the manifest" is their normal state,
/// not a drop — only `vendor --revert`, `remove`, `rollback` (its vendored
/// leg), or the lockfile-driven half of [`run_vendor_gc`] may undo them.
fn manifest_dropped_purls(
    state: &VendorState,
    manifest: &PatchManifest,
    common: &GlobalArgs,
) -> Vec<String> {
    state
        .entries
        .iter()
        .filter(|(purl, entry)| {
            !entry.detached
                && ecosystem_in_scope(common, &entry.ecosystem)
                && !manifest.patches.contains_key(*purl)
                && !manifest.patches.contains_key(&entry.base_purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect()
}

/// Revert vendored entries whose patches were dropped from the manifest.
/// Returns `(had_error, ledger)`: the post-reconcile ledger load, for the
/// caller's staging harvest (an unreadable ledger is `Err` — reported by
/// the engine, not here).
pub(crate) async fn reconcile_dropped(
    manifest: &PatchManifest,
    common: &GlobalArgs,
    env: &mut Envelope,
) -> (bool, std::io::Result<VendorState>) {
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => return (false, Err(e)),
    };
    let stale = manifest_dropped_purls(&state, manifest, common);
    let mut had_error = false;
    let reverted = VendoredBackend::new(common, None)
        .revert(&stale, &mut state, RevertOpts::new(common.dry_run), false)
        .await;
    for RevertedEntry {
        key: purl,
        warnings,
        step,
        ..
    } in reverted
    {
        for w in &warnings {
            record_warning(env, &purl, w, common);
        }
        match step {
            VendorRevertStep::Missing | VendorRevertStep::Preserved => {}
            // Drift-skip keep: the backend left the drifted lock alone and
            // kept the artifacts, so the ledger entry must survive too — and
            // the genuine outcome is a COUNTED skip, not a removal.
            VendorRevertStep::Kept => env.record(
                PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                    "vendor_revert_kept",
                    "patch no longer in manifest, but its lock entries drifted since \
                     vendoring; artifacts and ledger entry kept",
                ),
            ),
            VendorRevertStep::WouldRevert | VendorRevertStep::Reverted => {
                if !common.json && !common.silent {
                    println!("{}", format_reconciled(&purl, common.dry_run));
                }
                env.record(
                    PatchEvent::new(PatchAction::Removed, purl.clone())
                        .with_reason("vendor_reconciled", "patch no longer in manifest"),
                );
            }
            // Reverted on disk, and saved per purl exactly like `--revert`:
            // a failed write fails the purl rather than leaving it in the
            // ledger silently.
            VendorRevertStep::LedgerWriteFailed(e) => {
                if !common.json && !common.silent {
                    println!("{}", format_reconciled(&purl, common.dry_run));
                }
                env.record(
                    PatchEvent::new(PatchAction::Removed, purl.clone())
                        .with_reason("vendor_reconciled", "patch no longer in manifest"),
                );
                had_error = true;
                env.record(
                    PatchEvent::new(PatchAction::Failed, purl.clone())
                        .with_error("vendor_state_write_failed", e),
                );
            }
            VendorRevertStep::Failed(detail) => {
                had_error = true;
                report_revert_failure(common, &purl, &detail);
                env.record(
                    PatchEvent::new(PatchAction::Failed, purl.clone())
                        .with_error("revert_failed", detail),
                );
            }
        }
    }
    (had_error, Ok(state))
}

async fn run_revert(args: &VendorArgs, env: &mut Envelope) -> i32 {
    let common = &args.common;
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            env.mark_error(EnvelopeError::new("vendor_state_unreadable", e.to_string()));
            report_state_unreadable(common, &e);
            return 1;
        }
    };

    let mut has_errors = false;
    let mut recorded: Vec<String> = state.entries.keys().cloned().collect();
    recorded.sort();
    // Lockfile flavors of the entries this run reverted: the installed
    // tree still holds the vendored bytes until a reinstall.
    let mut reverted_flavors: HashSet<String> = HashSet::new();

    // The one vendored-revert primitive every reverting command shares
    // (rollback's vendored leg, both of remove's paths, the manifest
    // reconcile): dispatch → drift-keep → per-entry ledger save. Only the
    // event vocabulary and the human lines are this command's.
    let reverted = VendoredBackend::new(common, None)
        .revert(
            &recorded,
            &mut state,
            RevertOpts::new(common.dry_run),
            false,
        )
        .await;
    for RevertedEntry {
        key: purl,
        flavor,
        warnings,
        step,
    } in reverted
    {
        let purl = &purl;
        for w in &warnings {
            record_warning(env, purl, w, common);
        }
        match step {
            // Every key came from this ledger; `--revert` never preserves.
            VendorRevertStep::Missing | VendorRevertStep::Preserved => {}
            VendorRevertStep::Failed(why) => {
                has_errors = true;
                report_revert_failure(common, purl, &why);
                env.record(
                    PatchEvent::new(PatchAction::Failed, purl.clone())
                        .with_error("revert_failed", why),
                );
            }
            // Drift-skip keep: the backend left the drifted lock alone and
            // kept the artifacts, so the ledger entry must survive too — and
            // the genuine outcome is a COUNTED skip, not a removal.
            // (`record_warning` above already surfaced the per-record
            // details as uncounted advisory events.)
            VendorRevertStep::Kept => env.record(
                PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                    "vendor_revert_kept",
                    "lock entries drifted since vendoring; artifacts and ledger entry kept \
                     — undo the drift and re-run `vendor --revert` to finish",
                ),
            ),
            VendorRevertStep::WouldRevert | VendorRevertStep::Reverted => {
                env.record(PatchEvent::new(PatchAction::Removed, purl.clone()));
                reverted_flavors.extend(flavor);
            }
            // Reverted on disk; the record of it could not be persisted.
            VendorRevertStep::LedgerWriteFailed(e) => {
                env.record(PatchEvent::new(PatchAction::Removed, purl.clone()));
                reverted_flavors.extend(flavor);
                has_errors = true;
                env.record(
                    PatchEvent::new(PatchAction::Failed, purl.clone())
                        .with_error("vendor_state_write_failed", e),
                );
            }
        }
    }

    // `--revert` returns to UPSTREAM: a package vendored over hosted wiring
    // before v5 recorded the hosted fragment as its pre-vendor original, so
    // its revert just wired it back to the patch server. Restore those pins
    // to their upstream registry entries too (a wet run only — a dry revert
    // wrote nothing to inspect).
    if !common.dry_run {
        let reverted: HashSet<PurlKey> = env
            .events
            .iter()
            .filter(|e| e.action == PatchAction::Removed)
            .filter_map(|e| e.purl.as_deref().map(PurlKey::new))
            .collect();
        let rehosted: Vec<HostedPin> =
            HostedPin::all(&crate::commands::discover_wiring(common, &common.cwd).await)
                .into_iter()
                .filter(|pin| reverted.contains(&PurlKey::new(&pin.purl)))
                .collect();
        if !rehosted.is_empty() {
            let leg = crate::commands::hosted_unwind::run_hosted_leg(common, &rehosted).await;
            for purl in &leg.reverted {
                record_warning(
                    env,
                    purl,
                    &VendorWarning::new(
                        "vendor_revert_restored_upstream",
                        format!(
                            "{purl} was vendored over a hosted pin before v5, so its revert \
                             re-wired it to the hosted patch server; restored its upstream \
                             registry entry"
                        ),
                    ),
                    common,
                );
            }
            for (purl, why) in &leg.failed {
                has_errors = true;
                env.record(
                    PatchEvent::new(PatchAction::Failed, purl.clone())
                        .with_error("hosted_restore_failed", why.clone()),
                );
            }
            // The vendored revert above already advised a Bun reinstall
            // per package (#764); the hosted unwind's run-level twin for
            // the same packages would only repeat it.
            let bun_advised: HashSet<PurlKey> = env
                .events
                .iter()
                .filter(|e| {
                    e.error_code.as_deref()
                        == Some(socket_patch_core::vendor::bun_lock::REINSTALL_REQUIRED)
                })
                .filter_map(|e| e.purl.as_deref().map(PurlKey::new))
                .collect();
            let bun_repeat = rehosted
                .iter()
                .all(|pin| bun_advised.contains(&PurlKey::new(&pin.purl)));
            for (code, detail) in &leg.warnings {
                if bun_repeat && code == "redirect_bun_reinstall_required" {
                    continue;
                }
                env.warnings.push(RunWarning {
                    code: code.clone(),
                    detail: detail.clone(),
                });
            }
        }
    }

    // Orphan sweep: uuid dirs on disk with no ledger entry (a hand-edited
    // state file, or artifacts left by an interrupted run). Unparseable dirs
    // are reported, never deleted — and neither are dirs a lockfile still
    // points at (their wiring outlived the ledger).
    let sweep = sweep_orphan_vendor_dirs(&common.cwd, &state, common.dry_run).await;
    for unit in &sweep.still_wired {
        let label = orphan_label(unit);
        record_warning(
            env,
            &label,
            &VendorWarning::new(
                "vendor_orphan_still_wired",
                format!(
                    "a project lockfile still points at .socket/vendor/{}/{}, which no ledger \
                     entry owns; the artifacts were kept (run `socket-patch repair` to re-adopt \
                     them into the ledger, then revert again)",
                    unit.eco, unit.uuid
                ),
            ),
            common,
        );
    }
    for unit in &sweep.removed {
        env.record(
            PatchEvent::new(PatchAction::Removed, orphan_label(unit))
                .with_reason("vendor_orphan_removed", "vendored dir had no ledger entry"),
        );
    }

    if env.events.is_empty() {
        if !common.json && !common.silent {
            println!("Nothing vendored to revert.");
        }
        return 0;
    }

    if !common.json && !common.silent {
        let orphans: Vec<String> = sweep
            .removed
            .iter()
            .map(|u| format!(".socket/vendor/{}/{}", u.eco, u.uuid))
            .collect();
        // In this command summary.skipped counts only genuine drift-skip
        // keeps (advisory warnings are pushed uncounted by record_warning).
        let summary = RevertSummary {
            reverted: env.summary.removed.saturating_sub(orphans.len() as u32),
            failed: env.summary.failed,
            kept: env.summary.skipped,
            orphans,
        };
        for line in format_revert_summary(common.dry_run, &summary) {
            println!("{line}");
        }
        if summary.reverted > 0 && !common.dry_run {
            let mut installs: Vec<&str> = reverted_flavors
                .iter()
                .filter_map(|f| flavor_revert_install_command(f))
                .collect();
            installs.sort_unstable();
            installs.dedup();
            for cmd in installs {
                println!("{}", format_revert_install_hint(cmd));
            }
        }
    }

    if has_errors {
        env.mark_partial_failure();
        1
    } else {
        0
    }
}

// ───────────────────────── prune-time vendored GC ─────────────────────────

/// Summary of the vendored-state GC pass `scan --prune` runs (wet or
/// preview). Purls are the state-ledger keys (manifest spelling).
#[derive(Debug, Default)]
pub(crate) struct VendorGcSummary {
    /// (a) entries whose patch is gone from the manifest — reverted.
    pub dropped_reverted: Vec<String>,
    /// (b) entries whose package left the lockfile dependency graph —
    /// reverted, and their manifest entries dropped.
    pub unused_reverted: Vec<String>,
    /// Entries a wet revert drift-kept ([`RevertOutcome::kept_artifact`]):
    /// the backend left the drifted lock alone, so artifacts, ledger entry
    /// and (in (b)) manifest records were all retained — nothing reclaimed.
    /// Always empty on dry runs: backends detect drift only during a wet
    /// wiring replay, so the preview still lists such entries as revertable.
    pub kept: Vec<String>,
    /// (c) orphan uuid dirs (no owning ledger entry) swept.
    pub orphan_dirs: usize,
    /// Entries (ledger keys) that could not be reverted — kept in the
    /// ledger, nothing reclaimed. Only purls; the pass-level outcomes below
    /// have their own fields.
    pub failed: Vec<String>,
    /// Post-revert rewrites that failed: `("vendor_state_write_failed" |
    /// "manifest_write_failed", <detail>)`. The reverts themselves already
    /// happened on disk; the stale record is what the caller must report.
    pub write_failures: Vec<(&'static str, String)>,
    /// The wet reverts' reinstall advisories (`code`, `detail`): Bun's
    /// `vendor_bun_reinstall_required` (#764) and vlt's
    /// `vendor_vlt_reinstall_required`. Every other reverting command
    /// surfaces these, and the GC must not drop them.
    pub advisories: Vec<(&'static str, String)>,
}

/// The revert warnings `scan --prune` forwards into `gc.warnings[]`: only
/// the "the installed tree still holds the vendored copy" advisories. The
/// revert's other warnings are routine for a prune and stay out:
/// `vendor_lock_entry_removed` is the normal leg-(b) case (the dependency
/// was uninstalled), and a drift keep is already reported through
/// `keptVendoredEntries` and its own `GC: kept …` line.
const GC_FORWARDED_ADVISORIES: &[&str] = &[
    socket_patch_core::vendor::bun_lock::REINSTALL_REQUIRED,
    socket_patch_core::vendor::vlt_lock::REINSTALL_REQUIRED,
];

impl VendorGcSummary {
    /// Keep a revert's reinstall advisories. Only a revert that actually
    /// restored the lock (succeeded, not drift-kept) can leave a stale
    /// installed copy behind.
    fn take_advisories(&mut self, outcome: &RevertOutcome) {
        if !outcome.success || outcome.kept_artifact {
            return;
        }
        self.advisories.extend(
            outcome
                .warnings
                .iter()
                .filter(|w| GC_FORWARDED_ADVISORIES.contains(&w.code))
                .map(|w| (w.code, w.detail.clone())),
        );
    }
}
/// The manifest keys an unused vendored `entry`, stored under ledger key
/// `purl`, owns: every key with the same [`PurlKey`] as the ledger key OR
/// the entry's base purl ([`VendorEntry::covers_purl`]: any qualifier set,
/// encoding, NuGet case, PEP 503 spelling or composer release padding). The
/// base purl matters for golang, whose ledger key may keep the module
/// proxy's `!x` case encoding (`!burnt!sushi`) while the manifest holds the
/// decoded `BurntSushi` spelling. The ONE relation behind the wet vendor
/// GC's manifest drop and `scan --prune --dry-run`'s preview of it, so the
/// two never report different prune sets.
pub(crate) fn unused_vendored_manifest_keys<V>(
    patches: &std::collections::HashMap<String, V>,
    purl: &str,
    entry: &VendorEntry,
) -> Vec<String> {
    patches
        .keys()
        .filter(|k| k.as_str() == purl || entry.covers_purl(purl, k))
        .cloned()
        .collect()
}

/// The vendored-state GC behind `scan --prune`:
///
/// (a) revert entries whose patch was dropped from the manifest (same
///     stale test as [`reconcile_dropped`], shared with the vendor flows);
/// (b) revert entries the project no longer consumes
///     ([`Discovery::vendor_entry_in_use`] == `Some(false)`, the liveness
///     discovery `vendor --check` and `vex` judge by; `None` keeps,
///     fail-safe) and drop their manifest entries so the caller's manifest
///     prune + blob sweep reclaims the rest in the same pass;
/// (c) sweep orphan uuid dirs.
///
/// A drift-skipped revert ([`RevertOutcome::kept_artifact`]) keeps the
/// ledger entry — and, in (b), the purl's manifest records — exactly like
/// every other `dispatch_revert_one` caller; the kept purl is reported in
/// [`VendorGcSummary::kept`] so `scan --prune` can explain it. Wet-only: a
/// dry [`dispatch_revert_one`] returns before the wiring replay that
/// detects drift.
///
/// Detached entries — every `scan`/`get --mode vendored` entry — are exempt
/// from (a) alone: they are never manifest-tracked, so "absent from the
/// manifest" is their normal state, not a drop. (b) applies to every entry:
/// it asks the lockfile, not the manifest, and a detached entry is wired
/// into the lock exactly like a manifest-tracked one, so a dependency that
/// left the lock graph is reclaimed either way. A missing/unreadable
/// manifest skips (a) only (a prune must not mass-revert on a deleted
/// manifest — that is `vendor --revert`'s explicit contract).
///
/// Lock-free: the caller holds the apply lock for a wet pass (flock is per
/// open file description, so a nested acquire here would read as a live
/// holder and skip every revert); a dry run needs none. Re-reads the ledger
/// itself — under the caller's lock it is the authoritative copy. The
/// ledger and manifest are rewritten only when a pass removed something; a
/// failed rewrite is recorded in [`VendorGcSummary::write_failures`].
pub(crate) async fn run_vendor_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    dry_run: bool,
) -> VendorGcSummary {
    let mut out = VendorGcSummary::default();
    let mut state = match load_state(&common.cwd).await {
        Ok(s) if !s.entries.is_empty() => s,
        // No ledger (or unreadable): only the orphan sweep could apply, and
        // without a trustworthy ledger it must not delete anything.
        _ => return out,
    };

    // (a) manifest-dropped entries. Everything (a) touches is excluded from
    // (b), which would otherwise list/fail the same purl a second time on a
    // dry run or after a wet revert failure.
    let mut handled_by_a: HashSet<String> = HashSet::new();
    // Set at the two `state.entries.remove` sites: the ledger is rewritten
    // only when a pass reclaimed something (the common `scan --prune` with
    // nothing reclaimable must not churn a committed file).
    let mut ledger_dirty = false;
    let mut manifest = read_manifest(manifest_path).await.ok().flatten();
    if let Some(m) = &manifest {
        for purl in manifest_dropped_purls(&state, m, common) {
            handled_by_a.insert(purl.clone());
            if dry_run {
                out.dropped_reverted.push(purl);
                continue;
            }
            let entry = state.entries.get(&purl).cloned().expect("listed above");
            let outcome = dispatch_revert_one(&entry, &common.cwd, false).await;
            out.take_advisories(&outcome);
            if !outcome.success {
                out.failed.push(purl);
            } else if outcome.kept_artifact {
                // Drift-skip keep: the ledger entry must survive too (which
                // also shields the uuid dir from the (c) orphan sweep), and
                // the purl is reported as kept, never as reverted.
                out.kept.push(purl);
            } else {
                state.entries.remove(&purl);
                ledger_dirty = true;
                out.dropped_reverted.push(purl);
            }
        }
    }

    // (b) lockfile-unused entries — detached ones included: the verdict
    // reads the live lockfile wiring, which a detached entry has like any
    // other. Every verdict is taken from ONE discovery of the project as
    // (a) left it, before (b) reverts anything: a revert rewrites locks,
    // and the entries still to judge must not see a half-pruned state.
    let mut manifest_dirty = false;
    let candidates: Vec<String> = state
        .entries
        .iter()
        .filter(|(purl, entry)| {
            ecosystem_in_scope(common, &entry.ecosystem) && !handled_by_a.contains(*purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect();
    let mut unused: Vec<String> = Vec::new();
    if !candidates.is_empty() {
        let discovery = crate::commands::discover_wiring(common, &common.cwd).await;
        for purl in candidates {
            let entry = state.entries.get(&purl).expect("listed above");
            // In use, or cannot determine — keep.
            if discovery.vendor_entry_in_use(&common.cwd, entry).await == Some(false) {
                unused.push(purl);
            }
        }
    }
    for purl in unused {
        let entry = state.entries.get(&purl).cloned().expect("listed above");
        if dry_run {
            out.unused_reverted.push(purl);
            continue;
        }
        let outcome = dispatch_revert_one(&entry, &common.cwd, false).await;
        out.take_advisories(&outcome);
        if !outcome.success {
            out.failed.push(purl);
            continue;
        }
        if outcome.kept_artifact {
            // Drift-skip keep, same gate as (a) — and the purl's manifest
            // records must survive too: pruning them would make the next
            // `vendor` reconcile re-revert an entry whose backing record is
            // gone.
            out.kept.push(purl);
            continue;
        }
        state.entries.remove(&purl);
        ledger_dirty = true;
        if let Some(m) = manifest.as_mut() {
            for k in unused_vendored_manifest_keys(&m.patches, &purl, &entry) {
                m.patches.remove(&k);
                manifest_dirty = true;
            }
        }
        out.unused_reverted.push(purl);
    }

    if !dry_run {
        // The reverts above already restored the wiring and removed the
        // artifacts; a failed ledger/manifest rewrite leaves records for
        // state that is gone, which must not pass silently.
        if ledger_dirty {
            if let Err(e) = save_state(&common.cwd, &state).await {
                let detail = format!(
                    "reverted vendored entries but could not update \
                     .socket/vendor/state.json: {e}"
                );
                gc_note(common, "vendor_state_write_failed", &detail);
                out.write_failures
                    .push(("vendor_state_write_failed", detail));
            }
        }
        if manifest_dirty {
            if let Some(m) = &manifest {
                if let Err(e) = write_manifest(manifest_path, m).await {
                    let detail = format!(
                        "reverted vendored entries but could not update {}: {e}",
                        manifest_path.display()
                    );
                    gc_note(common, "manifest_write_failed", &detail);
                    out.write_failures.push(("manifest_write_failed", detail));
                }
            }
        }
    }

    // (c) orphan uuid dirs, against the post-removal ledger. Dirs a lockfile
    // still points at are kept, so they are not counted as reclaimed.
    out.orphan_dirs = sweep_orphan_vendor_dirs(&common.cwd, &state, dry_run)
        .await
        .removed
        .len();
    out
}

/// Human-mode stderr line for a pass-level GC problem (the GC has no
/// envelope of its own; JSON consumers see it as `scan --prune --json`'s
/// `gc.skipped` / `gc.warnings`). Muted under `--json` and `--silent`.
fn gc_note(common: &GlobalArgs, _code: &str, detail: &str) {
    if !common.json && !common.silent {
        eprintln!("Warning: {detail}");
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use socket_patch_core::vendor::VendorSource;

    /// Fail-closed `--vendor-source=service` must not refuse maven at the
    /// dispatch gate: the maven backend has a full service path (prebuilt
    /// jar download + registry pom), and its own errors advise exactly
    /// that flag.
    #[tokio::test]
    async fn service_mode_gate_admits_maven() {
        let tmp = tempfile::tempdir().unwrap();
        let record = PatchRecord {
            uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f".to_string(),
            exported_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        let sources = PatchSources {
            blobs_path: tmp.path(),
            mem_blobs: None,
        };
        let service = GlobalArgs {
            vendor_source: "service".to_string(),
            ..Default::default()
        }
        .vendor_service_config(None, false);
        assert_eq!(service.source, VendorSource::Service);
        let outcome = dispatch_vendor_one(
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
            tmp.path().into(),
            tmp.path(),
            &record,
            &sources,
            "2026-01-01T00:00:00Z",
            false,
            false,
            Some(&service),
            &tokio::sync::OnceCell::new(),
            &Default::default(),
        )
        .await;
        // The backend itself may refuse (nothing is installed in the
        // fixture) — the gate just must not be what stops it.
        if let Some(VendorOutcome::Refused { code, .. }) = outcome {
            assert_ne!(
                code, "vendor_service_unsupported_ecosystem",
                "maven has a service backend; the dispatch gate must admit it"
            );
        }
    }
}

#[cfg(test)]
mod plan_gate_tests {
    use super::*;
    use socket_patch_core::manifest::schema::PatchFileInfo;

    const UUID_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const UUID_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const UUID_C: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    fn record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files: HashMap::from([(
                "index.php".to_string(),
                PatchFileInfo {
                    before_hash: "1".repeat(64),
                    after_hash: "2".repeat(64),
                },
            )]),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    /// The download plan runs every record through its backend's own gate:
    /// a package the backend refuses before its first service call is
    /// never planned, wherever it sits in the loop order. Here the refused
    /// composer package (`psr/http-message`, absent from composer.lock)
    /// sorts BETWEEN the two locked ones, so a plan that skipped the gate
    /// would name it at a position the prefetch reaches ahead of the loop.
    #[tokio::test]
    async fn the_plan_leaves_out_a_package_its_backend_refuses_first() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("composer.json"), r#"{"require":{}}"#).unwrap();
        let locked: Vec<serde_json::Value> = [("psr/cache", "1.0.0"), ("psr/log", "3.0.2")]
            .iter()
            .map(|(name, version)| {
                serde_json::json!({
                    "name": name, "version": version,
                    "dist": {"type": "zip", "url": format!("https://example.invalid/{name}.zip"),
                             "reference": "abc", "shasum": ""},
                    "type": "library"
                })
            })
            .collect();
        std::fs::write(
            root.join("composer.lock"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "content-hash": "x", "packages": locked, "packages-dev": []
            }))
            .unwrap(),
        )
        .unwrap();
        let packages = [
            ("pkg:composer/psr/cache@1.0.0", "psr/cache", UUID_A),
            (
                "pkg:composer/psr/http-message@1.1.0",
                "psr/http-message",
                UUID_B,
            ),
            ("pkg:composer/psr/log@3.0.2", "psr/log", UUID_C),
        ];
        let mut all_packages: Vec<(String, StagedSource)> = Vec::new();
        let mut records: HashMap<String, PatchRecord> = HashMap::new();
        for (purl, name, uuid) in packages {
            let dir = root.join("vendor").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            all_packages.push((purl.to_string(), StagedSource::Installed(dir)));
            records.insert(purl.to_string(), record(uuid));
        }
        let planned = plan_service_downloads(
            root,
            false,
            &all_packages,
            &HashMap::new(),
            &records,
            &VendorState::default(),
            &HashSet::new(),
            None,
            &|_| false,
            (
                &tokio::sync::OnceCell::new(),
                &vendor::pypi::InstalledSiteListings::default(),
            ),
        )
        .await;
        let uuids: Vec<&str> = planned.iter().map(|d| d.uuid.as_str()).collect();
        assert_eq!(
            uuids,
            vec![UUID_A, UUID_C],
            "one planned download per package the loop asks the service for, in loop \
             order, and none for the package its backend refuses first"
        );
    }

    /// A record whose patch dir is a link (#664) is refused by the loop
    /// before dispatch, so the plan leaves it out: a prefetch running ahead
    /// of the loop must never stage or extract an archive through the link.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_plan_leaves_out_a_package_whose_vendor_dir_is_linked() {
        let tmp = tempfile::tempdir().unwrap();
        let root = &tmp.path().join("project");
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join("composer.json"), r#"{"require":{}}"#).unwrap();
        let names = ["psr/cache", "psr/container", "psr/log"];
        let locked: Vec<serde_json::Value> = names
            .iter()
            .map(|name| {
                serde_json::json!({
                    "name": name, "version": "1.0.0",
                    "dist": {"type": "zip", "url": format!("https://example.invalid/{name}.zip"),
                             "reference": "abc", "shasum": ""},
                    "type": "library"
                })
            })
            .collect();
        std::fs::write(
            root.join("composer.lock"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "content-hash": "x", "packages": locked, "packages-dev": []
            }))
            .unwrap(),
        )
        .unwrap();
        let mut all_packages: Vec<(String, StagedSource)> = Vec::new();
        let mut records: HashMap<String, PatchRecord> = HashMap::new();
        for (name, uuid) in names.iter().zip([UUID_A, UUID_B, UUID_C]) {
            let purl = format!("pkg:composer/{name}@1.0.0");
            let dir = root.join("vendor").join(name);
            std::fs::create_dir_all(&dir).unwrap();
            all_packages.push((purl.clone(), StagedSource::Installed(dir)));
            records.insert(purl, record(uuid));
        }
        let other = tmp.path().join("other-project-unit");
        std::fs::create_dir_all(&other).unwrap();
        let eco_dir = root.join(".socket/vendor/composer");
        std::fs::create_dir_all(&eco_dir).unwrap();
        std::os::unix::fs::symlink(&other, eco_dir.join(UUID_B)).unwrap();

        let planned = plan_service_downloads(
            root,
            false,
            &all_packages,
            &HashMap::new(),
            &records,
            &VendorState::default(),
            &HashSet::new(),
            None,
            &|_| false,
            (
                &tokio::sync::OnceCell::new(),
                &vendor::pypi::InstalledSiteListings::default(),
            ),
        )
        .await;
        let uuids: Vec<&str> = planned.iter().map(|d| d.uuid.as_str()).collect();
        assert_eq!(
            uuids,
            vec![UUID_A, UUID_C],
            "the linked package is never planned"
        );
    }
}

#[cfg(test)]
mod warning_counting_tests {
    use super::*;

    /// `record_warning` must not print (so the test captures no stderr) —
    /// `json = true` suppresses the human line; every other field defaults.
    fn quiet_common() -> GlobalArgs {
        GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        }
    }

    /// A vendor advisory (e.g. a SUCCESSFUL `vendor_prebuilt_downloaded`
    /// service fetch) must NOT inflate `summary.skipped`: that counter counts
    /// packages that were genuinely skipped, not the number of advisory
    /// events. The advisory must still remain visible in `events[]`.
    #[test]
    fn advisory_warning_does_not_bump_skipped_summary() {
        let common = quiet_common();
        let purl = "pkg:cargo/cfg-if@1.0.4";
        let mut env = Envelope::new(Command::Vendor);
        // The package's real outcome: it WAS vendored (applied).
        env.record(PatchEvent::new(PatchAction::Applied, purl));
        // The service-download advisory rides alongside that outcome.
        record_warning(
            &mut env,
            purl,
            &VendorWarning::new(
                "vendor_prebuilt_downloaded",
                "vendored cfg-if from the patch service",
            ),
            &common,
        );

        assert_eq!(
            env.summary.applied, 1,
            "the vendored package is counted as applied"
        );
        assert_eq!(
            env.summary.skipped, 0,
            "a per-package advisory is not a skipped package: {:?}",
            env.summary
        );
        // The advisory is still emitted for JSON consumers.
        assert!(
            env.events
                .iter()
                .any(|e| e.error_code.as_deref() == Some("vendor_prebuilt_downloaded")),
            "advisory stays visible in events[]"
        );
    }

    /// Two advisories on a single 1-package vendor must still leave
    /// `summary.skipped` at zero.
    #[test]
    fn multiple_advisories_do_not_accumulate_skips() {
        let common = quiet_common();
        let purl = "pkg:npm/minimist@1.2.2";
        let mut env = Envelope::new(Command::Vendor);
        env.record(PatchEvent::new(PatchAction::Applied, purl));
        record_warning(
            &mut env,
            purl,
            &VendorWarning::new("vendor_prebuilt_downloaded", "from the service"),
            &common,
        );
        record_warning(
            &mut env,
            purl,
            &VendorWarning::new("vendor_fetched_missing", "fetched the pristine artifact"),
            &common,
        );
        assert_eq!(
            env.summary.skipped, 0,
            "advisories never count as skipped packages: {:?}",
            env.summary
        );
    }

    /// A genuinely-skipped PACKAGE (recorded via `Envelope::record`, e.g.
    /// `already_vendored` or `package_not_installed`) must still bump
    /// `summary.skipped`.
    #[test]
    fn genuine_package_skip_still_counts() {
        let mut env = Envelope::new(Command::Vendor);
        env.record(
            PatchEvent::new(PatchAction::Skipped, "pkg:cargo/cfg-if@1.0.4").with_reason(
                "already_vendored",
                "artifact and lockfile wiring already in sync",
            ),
        );
        assert_eq!(
            env.summary.skipped, 1,
            "an already_vendored package is a genuine skip"
        );
    }
}

#[cfg(test)]
mod variant_probe_tests {
    use super::*;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
    use socket_patch_core::manifest::schema::PatchFileInfo;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const WHEEL: &str = "pkg:pypi/foo@1.0.0?artifact_id=foo-1.0.0-py3-none-any.whl";
    const SDIST: &str = "pkg:pypi/foo@1.0.0?artifact_id=foo-1.0.0.tar.gz";

    fn record(files: &[(&str, &str, &str)]) -> PatchRecord {
        PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files: files
                .iter()
                .map(|(name, before, after)| {
                    (
                        (*name).to_string(),
                        PatchFileInfo {
                            before_hash: (*before).to_string(),
                            after_hash: (*after).to_string(),
                        },
                    )
                })
                .collect(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    /// The release-variant probe must never pick a NEW file (empty
    /// `beforeHash`) as the representative that decides whether a variant
    /// describes the installed distribution: a new file verifies `Ready`
    /// against *any* environment, so it can neither identify nor
    /// disqualify a variant.
    ///
    /// Fixture: an installed wheel of `foo@1.0.0` (its `foo/__init__.py`
    /// matches the wheel variant's `beforeHash`) plus a manifest sdist
    /// variant that is NOT installed — it patches `setup.py` (absent from
    /// the wheel install → `NotFound`) and adds one new file. A
    /// representative taken from `HashMap::iter().next()` would pick the
    /// sdist's new file roughly half the time and admit the not-installed
    /// variant.
    #[tokio::test]
    async fn variant_probe_never_picks_a_new_file_as_representative() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        tokio::fs::create_dir_all(site.join("foo-1.0.0.dist-info"))
            .await
            .unwrap();
        tokio::fs::write(
            site.join("foo-1.0.0.dist-info").join("METADATA"),
            "Name: foo\nVersion: 1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(site.join("foo")).await.unwrap();
        let installed = b"print('hi')\n";
        tokio::fs::write(site.join("foo").join("__init__.py"), installed)
            .await
            .unwrap();
        let before = compute_git_sha256_from_bytes(installed);
        let elsewhere = compute_git_sha256_from_bytes(b"setup(name='foo')\n");
        let after = compute_git_sha256_from_bytes(b"patched\n");

        let common = GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            // Aim the pypi crawler at the fixture site-packages: hermetic,
            // and no real interpreter needed.
            global_prefix: Some(site.clone()),
            ecosystems: Some(vec!["pypi".to_string()]),
            dry_run: true,
            offline: true,
            json: true,
            silent: true,
            ..GlobalArgs::default()
        };
        let sources = PatchSources {
            blobs_path: tmp.path(),
            mem_blobs: None,
        };

        // `HashMap` iteration order is randomized per instance, so build a
        // fresh `records` map (and hence fresh per-record `files` maps)
        // every round.
        for round in 0..32 {
            let mut records: HashMap<String, PatchRecord> = HashMap::new();
            records.insert(
                WHEEL.to_string(),
                record(&[("foo/__init__.py", &before, &after)]),
            );
            records.insert(
                SDIST.to_string(),
                record(&[
                    // Sorts before `setup.py`, so a lex-only representative
                    // pick would still be caught.
                    ("aaa_added_by_the_sdist.py", "", &after),
                    ("setup.py", &elsewhere, &after),
                ]),
            );

            let mut env = Envelope::new(Command::Vendor);
            vendor_records(
                &common,
                &records,
                &sources,
                false,
                false,
                &mut env,
                None,
                load_state(&common.cwd).await,
            )
            .await;

            assert!(
                !env.events.iter().any(|e| e.purl.as_deref() == Some(SDIST)),
                "round {round}: the sdist variant is not the installed distribution \
                 (its only discriminating file, setup.py, is absent) — vendor must not \
                 act on it; events: {:?}",
                env.events
            );
        }
    }

    /// A variant record consisting ONLY of new files (every `beforeHash`
    /// empty) has no representative to probe: `representative_file` returns
    /// `None`, and `variant_matches_installed(None)` must ADMIT the variant
    /// (the same pinned contract as apply's variant loop) — a new file can
    /// neither identify nor disqualify a variant, so the record proceeds to
    /// the backend instead of being silently dropped as not-installed.
    #[tokio::test]
    async fn all_new_file_variant_record_is_admitted() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        tokio::fs::create_dir_all(site.join("foo-1.0.0.dist-info"))
            .await
            .unwrap();
        tokio::fs::write(
            site.join("foo-1.0.0.dist-info").join("METADATA"),
            "Name: foo\nVersion: 1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(site.join("foo")).await.unwrap();
        tokio::fs::write(site.join("foo").join("__init__.py"), b"print('hi')\n")
            .await
            .unwrap();
        let after = compute_git_sha256_from_bytes(b"patched\n");

        let common = GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(site.clone()),
            ecosystems: Some(vec!["pypi".to_string()]),
            dry_run: true,
            offline: true,
            json: true,
            silent: true,
            ..GlobalArgs::default()
        };
        let sources = PatchSources {
            blobs_path: tmp.path(),
            mem_blobs: None,
        };

        let mut records: HashMap<String, PatchRecord> = HashMap::new();
        records.insert(
            WHEEL.to_string(),
            record(&[("brand_new_file.py", "", &after)]),
        );
        let mut env = Envelope::new(Command::Vendor);
        vendor_records(
            &common,
            &records,
            &sources,
            false,
            false,
            &mut env,
            None,
            load_state(&common.cwd).await,
        )
        .await;

        assert!(
            env.events.iter().any(|e| e.purl.as_deref() == Some(WHEEL)),
            "an all-new-files variant must pass the probe (representative None \
             admits) and reach the backend; events: {:?}",
            env.events
        );
        assert!(
            !env.events
                .iter()
                .any(|e| e.error_code.as_deref() == Some("package_not_installed")),
            "the admitted variant must not be misclassified as not installed: {:?}",
            env.events
        );
    }

    const UUID_SDIST: &str = "3c8e1a5f-7b2d-4e9a-9c1f-5d7b3a9e1c2f";
    const UUID_OLD: &str = "0a4d8f2b-6c1e-4b3a-8d5f-9e2c7a1b4d6e";
    const BASE: &str = "pkg:pypi/foo@1.0.0";

    /// The wheel (at `UUID`) and sdist (at `UUID_SDIST`) variants of
    /// `foo@1.0.0`, each patching a file only its own distribution ships.
    fn wheel_and_sdist() -> HashMap<String, PatchRecord> {
        let before = compute_git_sha256_from_bytes(b"print('hi')\n");
        let after = compute_git_sha256_from_bytes(b"patched\n");
        let mut sdist = record(&[("setup.py", &before, &after)]);
        sdist.uuid = UUID_SDIST.to_string();
        HashMap::from([
            (
                WHEEL.to_string(),
                record(&[("foo/__init__.py", &before, &after)]),
            ),
            (SDIST.to_string(), sdist),
        ])
    }

    /// A ledger entry recording the wheel variant as vendored at `uuid`.
    fn wheel_entry(uuid: &str) -> VendorEntry {
        VendorEntry {
            flavor: Some("requirements".into()),
            ..VendorEntry::new(
                "pypi".into(),
                BASE.into(),
                uuid.into(),
                socket_patch_core::vendor::state::VendorArtifact {
                    yarn_berry10c0: None,
                    path: format!(".socket/vendor/pypi/{uuid}/foo-1.0.0-py3-none-any.whl"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                Vec::new(),
            )
        }
    }

    /// A dry run over `site` as the only site-packages.
    fn dry_run_over(root: &Path, site: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            global_prefix: Some(site.to_path_buf()),
            ecosystems: Some(vec!["pypi".to_string()]),
            dry_run: true,
            offline: true,
            json: true,
            silent: true,
            ..GlobalArgs::default()
        }
    }

    /// Nothing installed to probe (a fresh clone): the variant the ledger
    /// records — at the record's uuid, or at an older one after a patch
    /// update — is the wired distribution, so it goes on to its backend and
    /// its sibling is left out without an event instead of failing the
    /// re-run as `vendor_variant_ambiguous`.
    #[tokio::test]
    async fn the_ledger_picks_the_variant_of_an_uninstalled_package() {
        for ledger_uuid in [UUID, UUID_OLD] {
            let tmp = tempfile::tempdir().unwrap();
            let site = tmp.path().join("site-packages");
            tokio::fs::create_dir_all(&site).await.unwrap();
            let common = dry_run_over(tmp.path(), &site);
            let sources = PatchSources {
                blobs_path: tmp.path(),
                mem_blobs: None,
            };
            let mut state = VendorState::default();
            state
                .entries
                .insert(WHEEL.to_string(), wheel_entry(ledger_uuid));

            let mut env = Envelope::new(Command::Vendor);
            vendor_records(
                &common,
                &wheel_and_sdist(),
                &sources,
                false,
                false,
                &mut env,
                None,
                Ok(state),
            )
            .await;

            assert!(
                !env.events
                    .iter()
                    .any(|e| e.error_code.as_deref() == Some("vendor_variant_ambiguous")),
                "ledger at {ledger_uuid}: the ledger names the variant; events: {:?}",
                env.events
            );
            assert!(
                !env.events.iter().any(|e| e.purl.as_deref() == Some(SDIST)),
                "ledger at {ledger_uuid}: the sibling of the ledger's variant is left out \
                 silently; events: {:?}",
                env.events
            );
            assert!(
                env.events.iter().any(|e| e.purl.as_deref() == Some(WHEEL)),
                "ledger at {ledger_uuid}: the ledger's variant reaches its backend; events: {:?}",
                env.events
            );
        }
    }

    /// The control: with no ledger record either, nothing identifies the
    /// distribution, and every variant fails `vendor_variant_ambiguous`.
    #[tokio::test]
    async fn an_uninstalled_variant_group_without_a_ledger_record_is_ambiguous() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        tokio::fs::create_dir_all(&site).await.unwrap();
        let common = dry_run_over(tmp.path(), &site);
        let sources = PatchSources {
            blobs_path: tmp.path(),
            mem_blobs: None,
        };

        let mut env = Envelope::new(Command::Vendor);
        let has_errors = vendor_records(
            &common,
            &wheel_and_sdist(),
            &sources,
            false,
            false,
            &mut env,
            None,
            Ok(VendorState::default()),
        )
        .await;

        assert!(has_errors, "an ambiguous variant fails the run");
        for purl in [WHEEL, SDIST] {
            assert!(
                env.events.iter().any(|e| e.purl.as_deref() == Some(purl)
                    && e.action == PatchAction::Failed
                    && e.error_code.as_deref() == Some("vendor_variant_ambiguous")),
                "{purl} fails as ambiguous; events: {:?}",
                env.events
            );
        }
    }

    /// A variant refused for a lockfile reference with no ledger entry
    /// (`vendor_ledger_entry_missing`) stays refused: its installed
    /// sibling's variant group must not probe and dispatch it again.
    #[tokio::test]
    async fn a_variant_refused_for_a_missing_ledger_entry_is_not_revisited() {
        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        tokio::fs::create_dir_all(site.join("foo-1.0.0.dist-info"))
            .await
            .unwrap();
        tokio::fs::write(
            site.join("foo-1.0.0.dist-info").join("METADATA"),
            "Name: foo\nVersion: 1.0.0\n",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(site.join("foo")).await.unwrap();
        // The wheel variant's `beforeHash`: its probe would admit it.
        tokio::fs::write(site.join("foo").join("__init__.py"), b"print('hi')\n")
            .await
            .unwrap();
        tokio::fs::write(
            tmp.path().join("requirements.txt"),
            format!("foo @ file:./.socket/vendor/pypi/{UUID}/foo-1.0.0-py3-none-any.whl\n"),
        )
        .await
        .unwrap();
        let common = dry_run_over(tmp.path(), &site);
        let sources = PatchSources {
            blobs_path: tmp.path(),
            mem_blobs: None,
        };

        let mut env = Envelope::new(Command::Vendor);
        vendor_records(
            &common,
            &wheel_and_sdist(),
            &sources,
            false,
            false,
            &mut env,
            None,
            Ok(VendorState::default()),
        )
        .await;

        let wheel: Vec<&PatchEvent> = env
            .events
            .iter()
            .filter(|e| e.purl.as_deref() == Some(WHEEL))
            .collect();
        assert_eq!(
            wheel.len(),
            1,
            "the refused variant gets its refusal and nothing else; events: {:?}",
            env.events
        );
        assert_eq!(
            wheel[0].error_code.as_deref(),
            Some("vendor_ledger_entry_missing")
        );
    }

    /// The download plan follows the loop: an uninstalled variant group
    /// plans only the variant the ledger records (here at an older uuid, so
    /// the loop does ask the service), nothing when the ledger records none
    /// (the loop refuses them as ambiguous), and never a variant refused
    /// before the loop.
    #[tokio::test]
    async fn the_plan_follows_the_ledger_pick_of_an_uninstalled_variant_group() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("requirements.txt"), "foo==1.0.0\n").unwrap();
        let missing = || StagedSource::Missing(root.join(".socket/vendor/.uninstalled"));
        let both = vec![
            (WHEEL.to_string(), missing()),
            (SDIST.to_string(), missing()),
        ];
        let sdist_only = vec![(SDIST.to_string(), missing())];
        let variant_groups =
            HashMap::from([(BASE.to_string(), vec![WHEEL.to_string(), SDIST.to_string()])]);
        let records = wheel_and_sdist();
        let mut picked = VendorState::default();
        picked
            .entries
            .insert(WHEEL.to_string(), wheel_entry(UUID_OLD));
        let refused = HashSet::from([WHEEL.to_string()]);

        let cases = [
            (&both, VendorState::default(), HashSet::new(), vec![]),
            (&both, picked.clone(), HashSet::new(), vec![UUID]),
            (&sdist_only, picked, refused, vec![]),
        ];
        for (all_packages, ledger, refused, expected) in cases {
            let planned = plan_service_downloads(
                root,
                false,
                all_packages,
                &variant_groups,
                &records,
                &ledger,
                &refused,
                None,
                &|_| false,
                (
                    &tokio::sync::OnceCell::new(),
                    &vendor::pypi::InstalledSiteListings::default(),
                ),
            )
            .await;
            let uuids: Vec<&str> = planned.iter().map(|d| d.uuid.as_str()).collect();
            assert_eq!(uuids, expected, "refused: {refused:?}");
        }
    }
}

#[cfg(test)]
mod gc_tests {
    use super::*;
    use socket_patch_core::vendor::state::VendorArtifact;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:npm/left-pad@1.3.0";

    fn entry(detached: bool) -> VendorEntry {
        VendorEntry {
            detached,
            flavor: Some("package-lock".into()),
            ..VendorEntry::new(
                "npm".into(),
                PURL.into(),
                UUID.into(),
                VendorArtifact {
                    yarn_berry10c0: None,
                    path: format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                Vec::new(),
            )
        }
    }

    /// Tempdir with: a manifest carrying PURL, a ledger with one entry,
    /// the artifact on disk, and a package-lock that resolves to it.
    async fn gc_fixture(detached: bool) -> (tempfile::TempDir, GlobalArgs, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        tokio::fs::create_dir_all(socket.join(format!("vendor/npm/{UUID}")))
            .await
            .unwrap();
        tokio::fs::write(
            socket.join(format!("vendor/npm/{UUID}/left-pad-1.3.0.tgz")),
            b"tgz",
        )
        .await
        .unwrap();

        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            PURL.to_string(),
            socket_patch_core::manifest::schema::PatchRecord {
                uuid: UUID.to_string(),
                exported_at: String::new(),
                files: HashMap::new(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );
        let manifest_path = socket.join("manifest.json");
        write_manifest(&manifest_path, &manifest).await.unwrap();

        let mut state = VendorState::default();
        state.entries.insert(PURL.to_string(), entry(detached));
        save_state(root, &state).await.unwrap();

        tokio::fs::write(
            root.join("package-lock.json"),
            format!(
                "{{\"packages\":{{\"node_modules/left-pad\":{{\"version\":\"1.3.0\",\"resolved\":\"file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz\"}}}}}}"
            ),
        )
        .await
        .unwrap();

        let common = GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            silent: true,
            ..GlobalArgs::default()
        };
        (tmp, common, manifest_path)
    }

    /// In-manifest + in-lock: the GC keeps everything.
    #[tokio::test]
    async fn vendor_gc_keeps_in_use_entries() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(out.dropped_reverted.is_empty(), "{out:?}");
        assert!(out.unused_reverted.is_empty(), "{out:?}");
        assert!(
            out.failed.is_empty(),
            "an in-use entry is never reverted: {out:?}"
        );
        assert_eq!(out.orphan_dirs, 0);
        assert!(load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));
    }

    /// An attestation drop is not a liveness verdict: a lockfileVersion 2
    /// lock still installs `node_modules/left-pad` from the vendored tarball
    /// (npm 7+) while its legacy `dependencies` mirror (npm <= 6) resolves
    /// the registry. Discovery refuses to attest that wiring, but the GC
    /// must not unwire a patch npm 7+ still installs.
    #[tokio::test]
    async fn vendor_gc_keeps_an_entry_whose_wiring_is_only_unattributable() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        tokio::fs::write(
            tmp.path().join("package-lock.json"),
            serde_json::json!({
                "lockfileVersion": 2,
                "packages": {
                    "": {"dependencies": {"left-pad": "1.3.0"}},
                    "node_modules/left-pad": {
                        "version": "1.3.0",
                        "resolved": format!("file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                    },
                },
                "dependencies": {
                    "left-pad": {
                        "version": "1.3.0",
                        "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    },
                },
            })
            .to_string(),
        )
        .await
        .unwrap();
        for dry_run in [true, false] {
            let out = run_vendor_gc(&common, &manifest_path, dry_run).await;
            assert!(out.unused_reverted.is_empty(), "dry_run={dry_run}: {out:?}");
            assert!(out.failed.is_empty(), "dry_run={dry_run}: {out:?}");
        }
        assert!(load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));
    }

    /// (a) the patch is gone from the manifest: revert + drop the entry.
    ///
    /// The fixture entry carries EMPTY wiring (a synthetic ledger, not a
    /// vendor-produced one), so the lock must no longer resolve through
    /// the artifact for the revert to proceed: the unwired-revert guard
    /// refuses to delete an artifact a live lock still points at (the
    /// pre-v5 repair-reconstruction brick). Re-lock the
    /// fixture to the registry — the realistic reclaim shape.
    #[tokio::test]
    async fn vendor_gc_reverts_manifest_dropped_entry() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        tokio::fs::write(
            tmp.path().join("package-lock.json"),
            "{\"packages\":{\"node_modules/left-pad\":{\"resolved\":\
             \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\"}}}",
        )
        .await
        .unwrap();

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(out.dropped_reverted, vec![PURL.to_string()], "{out:?}");
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(load_state(tmp.path()).await.unwrap().entries.is_empty());
        assert!(
            !tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "artifact dir removed by the revert"
        );
    }

    /// (b) the dependency left the lockfile graph: revert + drop BOTH the
    /// ledger entry and the manifest entry.
    #[tokio::test]
    async fn vendor_gc_reverts_unused_entry_and_drops_manifest_entry() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        // Re-lock without the dependency (no reference to the artifact).
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
            .await
            .unwrap();

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(out.unused_reverted, vec![PURL.to_string()], "{out:?}");
        assert!(load_state(tmp.path()).await.unwrap().entries.is_empty());
        let manifest = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(
            !manifest.patches.contains_key(PURL),
            "the unused entry's manifest record is dropped too"
        );
    }

    /// A MISSING manifest skips pass (a) entirely — a prune must not
    /// mass-revert every ledger entry as "dropped" just because the
    /// manifest file is gone (that is `vendor --revert`'s explicit
    /// contract) — while pass (b) still runs: a lockfile-unused entry is
    /// reclaimed, its manifest half is skipped (nothing to edit), and no
    /// manifest file is invented; a still-wired entry is kept untouched.
    #[tokio::test]
    async fn vendor_gc_missing_manifest_skips_pass_a_but_b_still_runs() {
        // Still wired: with no manifest, NOTHING may be reclaimed — a
        // regression that treats a missing manifest as an empty one would
        // land the entry in dropped_reverted.
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        tokio::fs::remove_file(&manifest_path).await.unwrap();
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(
            out.dropped_reverted.is_empty(),
            "no manifest must not read as every-patch-dropped: {out:?}"
        );
        assert!(out.unused_reverted.is_empty(), "{out:?}");
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));

        // Dependency gone from the lock graph: (b) reclaims the entry even
        // with no manifest, and invents no manifest file for its manifest
        // half.
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        tokio::fs::remove_file(&manifest_path).await.unwrap();
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
            .await
            .unwrap();
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(out.dropped_reverted.is_empty(), "{out:?}");
        assert_eq!(out.unused_reverted, vec![PURL.to_string()], "{out:?}");
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(load_state(tmp.path()).await.unwrap().entries.is_empty());
        assert!(
            !tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "the unused entry's artifacts are reclaimed"
        );
        assert!(
            !manifest_path.exists(),
            "the GC must not invent a manifest file"
        );
    }

    /// Dry run lists without mutating anything.
    #[tokio::test]
    async fn vendor_gc_dry_run_is_read_only() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
            .await
            .unwrap();
        let state_before = tokio::fs::read(tmp.path().join(".socket/vendor/state.json"))
            .await
            .unwrap();
        let manifest_before = tokio::fs::read(&manifest_path).await.unwrap();

        let out = run_vendor_gc(&common, &manifest_path, true).await;
        assert_eq!(out.unused_reverted, vec![PURL.to_string()], "{out:?}");
        assert_eq!(
            tokio::fs::read(tmp.path().join(".socket/vendor/state.json"))
                .await
                .unwrap(),
            state_before,
            "dry run must not touch the ledger"
        );
        assert_eq!(
            tokio::fs::read(&manifest_path).await.unwrap(),
            manifest_before,
            "dry run must not touch the manifest"
        );
        assert!(
            tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "dry run must not remove artifacts"
        );
    }

    /// A missing/undeterminable lockfile keeps the entry (fail-safe). A
    /// DETACHED entry — the shape every `scan`/`get --mode vendored` run
    /// writes — is exempt from (a) alone (never manifest-tracked, so its
    /// absence from the manifest is not a drop) but NOT from (b): it is
    /// wired into the lock like any other entry, so once the dependency
    /// leaves the lock graph the GC reclaims it.
    #[tokio::test]
    async fn vendor_gc_keeps_undeterminable_entries_and_reclaims_unused_detached() {
        // Lock removed entirely: probe says None → keep.
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        tokio::fs::remove_file(tmp.path().join("package-lock.json"))
            .await
            .unwrap();
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(out.unused_reverted.is_empty(), "{out:?}");
        assert!(load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));

        // Detached entry, still wired: (a) exempts it and (b) sees it in
        // use — kept.
        let (tmp, common, manifest_path) = gc_fixture(true).await;
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(out.dropped_reverted.is_empty(), "{out:?}");
        assert!(out.unused_reverted.is_empty(), "{out:?}");
        assert!(load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));

        // Detached entry whose dependency left the lock graph: (a) still
        // exempts it (no manifest drop to detect), (b) reclaims it.
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
            .await
            .unwrap();
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(
            out.dropped_reverted.is_empty(),
            "(a) never touches a detached entry: {out:?}"
        );
        assert_eq!(
            out.unused_reverted,
            vec![PURL.to_string()],
            "(b) reclaims a lockfile-unused detached entry: {out:?}"
        );
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(
            load_state(tmp.path()).await.unwrap().entries.is_empty(),
            "the reclaimed detached entry leaves the ledger"
        );
        assert!(
            !tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "the reclaimed detached entry's artifacts are removed"
        );
    }

    /// An entry that is BOTH manifest-dropped and lockfile-unused must be
    /// listed exactly once. The wet pass removes it from the ledger in (a)
    /// before (b) runs; the dry-run preview leaves the ledger untouched, so
    /// without excluding (a)-handled purls from (b) the same purl lands in
    /// both lists and `scan --prune`'s `revertableVendoredEntries` preview
    /// duplicates it (breaking preview/wet parity).
    #[tokio::test]
    async fn vendor_gc_dry_run_lists_dropped_and_unused_entry_once() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        // Patch gone from the manifest AND dependency gone from the lock.
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
            .await
            .unwrap();

        let dry = run_vendor_gc(&common, &manifest_path, true).await;
        assert_eq!(dry.dropped_reverted, vec![PURL.to_string()], "{dry:?}");
        assert!(
            dry.unused_reverted.is_empty(),
            "an (a)-handled entry must not also be previewed as (b)-unused: {dry:?}"
        );

        // Wet parity: the same single listing.
        let wet = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(wet.dropped_reverted, vec![PURL.to_string()], "{wet:?}");
        assert!(wet.unused_reverted.is_empty(), "{wet:?}");
    }

    /// B19: a vendored COMPOSER entry whose dependency was bumped to a
    /// registry release in composer.lock is reclaimed by the GC — composer
    /// (like gem, golang, nuget, maven and most pypi flavors) used to have
    /// no in-use probe, so the GC kept it forever — while the same entry is
    /// kept as long as the lock installs from its vendored path dist.
    #[tokio::test]
    async fn vendor_gc_reclaims_unused_composer_entry_and_keeps_a_wired_one() {
        const COMPOSER_PURL: &str = "pkg:composer/monolog/monolog@3.0.0";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let leaf = format!(".socket/vendor/composer/{UUID}/monolog/monolog@3.0.0");
        tokio::fs::create_dir_all(root.join(&leaf)).await.unwrap();
        tokio::fs::write(root.join(&leaf).join("composer.json"), b"{}")
            .await
            .unwrap();
        let mut state = VendorState::default();
        let mut entry = entry(true);
        entry.ecosystem = "composer".into();
        entry.base_purl = COMPOSER_PURL.into();
        entry.flavor = None;
        entry.artifact.path = leaf.clone();
        state.entries.insert(COMPOSER_PURL.to_string(), entry);
        save_state(root, &state).await.unwrap();
        let common = GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            silent: true,
            ..GlobalArgs::default()
        };
        let manifest_path = root.join(".socket/manifest.json");

        // The lock installs from the vendored path dist: in use, kept.
        tokio::fs::write(
            root.join("composer.lock"),
            serde_json::json!({
                "packages": [{
                    "name": "monolog/monolog",
                    "version": "3.0.0",
                    "dist": {"type": "path", "url": leaf, "reference": UUID},
                    "transport-options": {"symlink": false},
                }],
                "packages-dev": [],
            })
            .to_string(),
        )
        .await
        .unwrap();
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(out.unused_reverted.is_empty(), "{out:?}");
        assert!(load_state(root)
            .await
            .unwrap()
            .entries
            .contains_key(COMPOSER_PURL));

        // Bumped to a registry release: nothing installs the vendored copy.
        tokio::fs::write(
            root.join("composer.lock"),
            serde_json::json!({
                "packages": [{
                    "name": "monolog/monolog",
                    "version": "3.1.0",
                    "dist": {
                        "type": "zip",
                        "url": "https://api.github.com/repos/Seldaek/monolog/zipball/abc",
                        "reference": "abc",
                    },
                }],
                "packages-dev": [],
            })
            .to_string(),
        )
        .await
        .unwrap();
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(
            out.unused_reverted,
            vec![COMPOSER_PURL.to_string()],
            "{out:?}"
        );
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(load_state(root).await.unwrap().entries.is_empty());
        assert!(
            !root
                .join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "the reclaimed entry's artifact is removed"
        );
    }

    /// A vendored CARGO entry displaced by a hosted takeover (its lock entry
    /// re-sourced to a socket-patch sparse index) is reclaimable by the GC
    /// through the discovery in-use verdict (the cargo extractor's lock
    /// shape rule), which drops the
    /// build-breaking `[patch.crates-io]` entry.
    #[tokio::test]
    async fn vendor_gc_reclaims_cargo_entry_displaced_by_hosted_takeover() {
        const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.4";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        tokio::fs::create_dir_all(socket.join(format!("vendor/cargo/{UUID}/cfg-if-1.0.4")))
            .await
            .unwrap();
        tokio::fs::write(
            socket.join(format!("vendor/cargo/{UUID}/cfg-if-1.0.4/lib.rs")),
            b"// patched",
        )
        .await
        .unwrap();

        // Manifest still carries the patch (so pass (a) keeps it; the
        // lock-shape probe (b) is what must reclaim it).
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            CARGO_PURL.to_string(),
            socket_patch_core::manifest::schema::PatchRecord {
                uuid: UUID.to_string(),
                exported_at: String::new(),
                files: HashMap::new(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: String::new(),
            },
        );
        let manifest_path = socket.join("manifest.json");
        write_manifest(&manifest_path, &manifest).await.unwrap();

        let mut state = VendorState::default();
        let mut entry = entry(false);
        entry.ecosystem = "cargo".into();
        entry.base_purl = CARGO_PURL.into();
        entry.artifact.path = format!(".socket/vendor/cargo/{UUID}/cfg-if-1.0.4");
        state.entries.insert(CARGO_PURL.to_string(), entry);
        save_state(root, &state).await.unwrap();

        // The mixed hosted-takeover state: [patch] entry survives, lock
        // re-sourced to the socket-patch sparse index.
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".cargo/config.toml"),
            format!(
                "[patch.crates-io]\ncfg-if = {{ path = \".socket/vendor/cargo/{UUID}/cfg-if-1.0.4\" }}\n"
            ),
        )
        .await
        .unwrap();
        tokio::fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"sparse+http://127.0.0.1:5555/index/\"\nchecksum = \"{}\"\n",
                "a".repeat(64)
            ),
        )
        .await
        .unwrap();

        let common = GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            silent: true,
            ..GlobalArgs::default()
        };
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(out.unused_reverted, vec![CARGO_PURL.to_string()], "{out:?}");
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(load_state(root).await.unwrap().entries.is_empty());
        assert!(
            !root.join(format!(".socket/vendor/cargo/{UUID}")).exists(),
            "committed tree reclaimed"
        );
        // The build-breaking leftover [patch.crates-io] entry is gone; the
        // hosted lock wiring is left exactly as it was (still hosted-live).
        let cfg = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap_or_default();
        assert!(!cfg.contains("patch.crates-io"), "{cfg}");
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(
            lock.contains("sparse+http://127.0.0.1:5555/index/"),
            "{lock}"
        );
    }

    /// The registry fragment recorded as the wiring `original` (pre-vendor).
    fn registry_fragment() -> serde_json::Value {
        serde_json::json!({
            "version": "1.3.0",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "integrity": "sha512-orig==",
            "license": "WTFPL"
        })
    }

    /// `entry(false)` plus the wiring record a real vendor run records for
    /// the package-lock entry — what lets the revert classify third-party
    /// drift (live fragment neither ours nor the recorded original).
    fn wired_entry() -> VendorEntry {
        use socket_patch_core::vendor::state::{WiringAction, WiringRecord};
        let mut e = entry(false);
        e.wiring.push(WiringRecord {
            file: "package-lock.json".into(),
            kind: "npm_lock_entry".into(),
            action: WiringAction::Rewritten,
            key: Some("node_modules/left-pad".into()),
            original: Some(registry_fragment()),
            new: Some(serde_json::json!({
                "version": "1.3.0",
                "resolved": format!("file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
            })),
        });
        e
    }

    /// [`gc_fixture`] with the ledger entry re-written as [`wired_entry`]
    /// and the package-lock's `node_modules/left-pad` set to
    /// `lock_fragment`.
    async fn wired_gc_fixture(
        lock_fragment: serde_json::Value,
    ) -> (tempfile::TempDir, GlobalArgs, PathBuf) {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        let mut state = VendorState::default();
        state.entries.insert(PURL.to_string(), wired_entry());
        save_state(tmp.path(), &state).await.unwrap();
        tokio::fs::write(
            tmp.path().join("package-lock.json"),
            serde_json::to_vec(&serde_json::json!({
                "packages": { "node_modules/left-pad": lock_fragment }
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        (tmp, common, manifest_path)
    }

    /// The drifted lock fragment: a third party re-resolved the entry since
    /// vendoring — neither ours nor the recorded pre-vendor original.
    fn fork_fragment() -> serde_json::Value {
        serde_json::json!({
            "version": "1.3.0",
            "resolved": "https://example.com/their-fork.tgz"
        })
    }

    /// (a) + drift-keep: the patch left the manifest, but
    /// the lock entry drifted since vendoring, so the revert leaves the
    /// lock alone and returns success with `kept_artifact`. Per the
    /// [`RevertOutcome::kept_artifact`] contract the GC must keep the
    /// ledger entry — which also shields the uuid dir from the (c) orphan
    /// sweep — and must NOT report the purl as cleanly reverted.
    #[tokio::test]
    async fn vendor_gc_keeps_drift_skipped_manifest_dropped_entry() {
        let (tmp, common, manifest_path) = wired_gc_fixture(fork_fragment()).await;
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        let lock_before = tokio::fs::read(tmp.path().join("package-lock.json"))
            .await
            .unwrap();

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(
            out.dropped_reverted.is_empty(),
            "a drift-kept entry must not be reported reverted: {out:?}"
        );
        assert!(out.failed.is_empty(), "a keep is not a failure: {out:?}");
        assert_eq!(
            out.kept,
            vec![PURL.to_string()],
            "the drift-keep must be COUNTED — scan --prune's only signal \
             that the entry its preview listed was deliberately not \
             reclaimed: {out:?}"
        );
        assert!(
            load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "ledger entry must be kept"
        );
        assert!(
            tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "kept artifacts must survive the orphan sweep"
        );
        assert_eq!(
            tokio::fs::read(tmp.path().join("package-lock.json"))
                .await
                .unwrap(),
            lock_before,
            "drifted lock left alone"
        );
    }

    /// (b) + drift-keep: the patch is still in the manifest, and the
    /// in-use probe says the dependency no longer resolves through the
    /// artifact — because the lock entry drifted to a third-party fork.
    /// Same keep contract as (a), plus the purl's manifest records must
    /// survive (pruning them would make the next `vendor` reconcile
    /// re-revert an entry whose backing record is gone).
    #[tokio::test]
    async fn vendor_gc_keeps_drift_skipped_unused_entry_and_manifest_record() {
        let (tmp, common, manifest_path) = wired_gc_fixture(fork_fragment()).await;

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(
            out.unused_reverted.is_empty(),
            "a drift-kept entry must not be reported reverted: {out:?}"
        );
        assert!(out.failed.is_empty(), "a keep is not a failure: {out:?}");
        assert_eq!(
            out.kept,
            vec![PURL.to_string()],
            "the drift-keep must be COUNTED — scan --prune's only signal \
             that the entry its preview listed was deliberately not \
             reclaimed: {out:?}"
        );
        assert!(
            load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "ledger entry must be kept"
        );
        assert!(
            tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "kept artifacts must survive the orphan sweep"
        );
        let manifest = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(
            manifest.patches.contains_key(PURL),
            "the kept entry's manifest record must survive"
        );
    }

    /// The preview half of the drift-keep contract: backends detect drift
    /// only during a wet wiring replay (a dry [`dispatch_revert_one`]
    /// returns before it), so the read-only preview still lists a drifted
    /// entry as revertable and `kept` stays empty. The wet run's `kept`
    /// report — and the `keptVendoredEntries` / hint `scan --prune` builds
    /// on it — is what explains the difference when the wet run then
    /// reclaims nothing.
    #[tokio::test]
    async fn vendor_gc_dry_run_cannot_see_drift_and_reports_nothing_kept() {
        let (tmp, common, manifest_path) = wired_gc_fixture(fork_fragment()).await;
        let dry = run_vendor_gc(&common, &manifest_path, true).await;
        assert_eq!(dry.unused_reverted, vec![PURL.to_string()], "{dry:?}");
        assert!(dry.kept.is_empty(), "{dry:?}");
        // Read-only: the ledger entry is untouched.
        assert!(load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));
    }

    /// KEEP-GATE LIVENESS (mirrors in_process_vendor.rs's
    /// `revert_completes_when_lock_already_matches_the_original`): a wired
    /// entry whose lock fragment already equals the recorded pre-vendor
    /// original is CONVERGED, not drifted — the keep gate must not block
    /// the full reclaim.
    #[tokio::test]
    async fn vendor_gc_reclaims_converged_wired_unused_entry() {
        let (tmp, common, manifest_path) = wired_gc_fixture(registry_fragment()).await;

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(out.unused_reverted, vec![PURL.to_string()], "{out:?}");
        assert!(out.failed.is_empty(), "{out:?}");
        assert!(
            out.kept.is_empty(),
            "a converged entry reverts cleanly — it must not be reported \
             as a drift-keep: {out:?}"
        );
        assert!(load_state(tmp.path()).await.unwrap().entries.is_empty());
        assert!(
            !tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "converged revert completes: artifacts reclaimed"
        );
        let manifest = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(!manifest.patches.contains_key(PURL), "{manifest:?}");
    }

    /// The orphan sweep keeps every un-ledgered dir a project file still
    /// points at. A vendored requirements pin may live ONLY in a `-r`
    /// include (the planner writes it where the original pin was), so the
    /// sweep must follow includes, not just the root requirements.txt —
    /// deleting the include-referenced wheel would brick the next
    /// `pip install`.
    #[tokio::test]
    async fn orphan_sweep_keeps_include_referenced_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let uuid = "1a2b3c4d-5e6f-4a1b-8c2d-9e0f1a2b3c4d";
        let rel_wheel = format!(".socket/vendor/pypi/{uuid}/six-1.16.0-py2.py3-none-any.whl");
        let wheel = root.join(&rel_wheel);
        tokio::fs::create_dir_all(wheel.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        tokio::fs::write(root.join("requirements.txt"), "-r requirements/base.txt\n")
            .await
            .unwrap();
        tokio::fs::create_dir(root.join("requirements"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("requirements/base.txt"),
            format!(
                "./{rel_wheel} --hash=sha256:{}  # socket-patch vendor: six==1.16.0\n",
                "0".repeat(64)
            ),
        )
        .await
        .unwrap();

        let sweep = sweep_orphan_vendor_dirs(root, &VendorState::default(), false).await;
        assert_eq!(sweep.still_wired.len(), 1, "{:?}", sweep.still_wired);
        assert_eq!(sweep.still_wired[0].uuid, uuid);
        assert!(sweep.removed.is_empty(), "{:?}", sweep.removed);
        assert!(wheel.is_file(), "the include-referenced wheel must survive");

        // Drop the include reference: the dir is a true orphan now.
        tokio::fs::write(root.join("requirements/base.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let sweep = sweep_orphan_vendor_dirs(root, &VendorState::default(), false).await;
        assert_eq!(sweep.removed.len(), 1, "{:?}", sweep.removed);
        assert!(sweep.still_wired.is_empty());
        assert!(!wheel.exists(), "the unreferenced orphan is reclaimed");
        // The sweep was the last unit under `.socket/vendor/`: the emptied
        // `<eco>/` and `vendor/` husks go with it, `.socket/` itself stays
        // (the lock guard's level).
        assert!(
            !root.join(".socket/vendor").exists(),
            "the orphan sweep prunes the emptied vendor tree"
        );
        assert!(
            root.join(".socket").is_dir(),
            ".socket/ is never the sweep's to remove"
        );
    }

    /// (c) uuid dirs with no owning ledger entry are swept (wet) / counted
    /// (dry).
    #[tokio::test]
    async fn vendor_gc_sweeps_orphan_uuid_dirs() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        let orphan_uuid = "1a2b3c4d-5e6f-4a1b-8c2d-9e0f1a2b3c4d";
        let orphan_dir = tmp.path().join(format!(".socket/vendor/npm/{orphan_uuid}"));
        tokio::fs::create_dir_all(&orphan_dir).await.unwrap();
        tokio::fs::write(orphan_dir.join("left-pad-1.3.0.tgz"), b"tgz")
            .await
            .unwrap();

        let out = run_vendor_gc(&common, &manifest_path, true).await;
        assert_eq!(out.orphan_dirs, 1, "{out:?}");
        assert!(orphan_dir.exists(), "dry run keeps the orphan");

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(out.orphan_dirs, 1, "{out:?}");
        assert!(!orphan_dir.exists(), "wet run sweeps the orphan");
        // The recorded entry's dir survives the sweep.
        assert!(tmp
            .path()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists());
    }

    /// The GC body is lock-free and runs under the CALLER's guard: with the
    /// apply lock held by the caller (as `scan --prune`'s `run_apply_gc`
    /// holds it), a dry pass lists and a wet pass reclaims — the held lock
    /// is no obstacle because nothing here acquires (flock is per open file
    /// description, so a nested acquire would have read as a live holder).
    #[tokio::test]
    async fn vendor_gc_body_runs_under_callers_held_lock() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        // Both passes WOULD reclaim: patch dropped + dependency gone.
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
            .await
            .unwrap();

        let _held = socket_patch_core::patch::apply_lock::acquire(
            &tmp.path().join(".socket"),
            Duration::ZERO,
        )
        .expect("test holds the apply lock first");

        let dry = run_vendor_gc(&common, &manifest_path, true).await;
        assert_eq!(
            dry.dropped_reverted,
            vec![PURL.to_string()],
            "the lock-free dry preview lists under the held lock: {dry:?}"
        );
        assert!(dry.failed.is_empty(), "{dry:?}");
        assert!(
            load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "a dry pass reverts nothing"
        );

        let wet = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(wet.dropped_reverted, vec![PURL.to_string()], "{wet:?}");
        assert!(wet.failed.is_empty(), "{wet:?}");
        assert!(
            !load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "the wet body reverts under the caller's guard"
        );
    }

    /// (a) revert FAILURE accounting: a ledger entry whose ecosystem has no
    /// revert backend (a tampered/hand-edited state.json) lands in
    /// `out.failed`, is KEPT in the ledger, and is excluded from pass (b)
    /// (no double count).
    #[tokio::test]
    async fn vendor_gc_failed_dropped_revert_keeps_entry() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        let mut state = load_state(tmp.path()).await.unwrap();
        state.entries.get_mut(PURL).unwrap().ecosystem = "frobnicate".into();
        save_state(tmp.path(), &state).await.unwrap();

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(out.failed, vec![PURL.to_string()], "{out:?}");
        assert!(out.dropped_reverted.is_empty(), "{out:?}");
        assert!(
            out.unused_reverted.is_empty(),
            "an (a)-handled purl must not also be tried by (b): {out:?}"
        );
        assert!(
            load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "a failed revert must keep the ledger entry"
        );
        assert!(
            tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "the still-wired artifact dir survives the orphan sweep"
        );
    }

    /// (b) revert FAILURE accounting: the in-use probe says the dependency
    /// left the lock graph (the lock never mentions the tampered uuid's
    /// dir), the revert refuses fail-closed on the non-canonical uuid, and
    /// BOTH the ledger entry and the purl's manifest record are kept.
    #[tokio::test]
    async fn vendor_gc_failed_unused_revert_keeps_entry_and_manifest() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        let mut state = load_state(tmp.path()).await.unwrap();
        state.entries.get_mut(PURL).unwrap().uuid = "deadbeef".into();
        save_state(tmp.path(), &state).await.unwrap();

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(out.failed, vec![PURL.to_string()], "{out:?}");
        assert!(out.unused_reverted.is_empty(), "{out:?}");
        assert!(out.dropped_reverted.is_empty(), "{out:?}");
        assert!(
            load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "a failed (b) revert must keep the ledger entry"
        );
        let manifest = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(
            manifest.patches.contains_key(PURL),
            "a failed (b) revert must not drop the manifest record"
        );
    }

    /// `--ecosystems` scoping gates BOTH GC passes ([`ecosystem_in_scope`]'s
    /// `Some(list)` branch): a cargo-scoped run must not revert an npm entry
    /// as a cross-ecosystem side effect, while the matching scope reclaims
    /// it normally.
    #[tokio::test]
    async fn vendor_gc_respects_ecosystems_scope() {
        let (tmp, mut common, manifest_path) = gc_fixture(false).await;
        // Both passes WOULD reclaim the npm entry were it in scope.
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
            .await
            .unwrap();

        common.ecosystems = Some(vec!["cargo".to_string()]);
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert!(
            out.dropped_reverted.is_empty()
                && out.unused_reverted.is_empty()
                && out.failed.is_empty(),
            "an out-of-scope entry is untouchable: {out:?}"
        );
        assert!(
            load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "cargo scope must keep the npm ledger entry"
        );
        assert!(
            tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "cargo scope must keep the npm artifacts"
        );

        common.ecosystems = Some(vec!["npm".to_string()]);
        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(
            out.dropped_reverted,
            vec![PURL.to_string()],
            "the matching scope reclaims: {out:?}"
        );
        assert!(load_state(tmp.path()).await.unwrap().entries.is_empty());
    }
}

#[cfg(test)]
mod scope_and_hint_tests {
    use super::*;

    /// [`flavor_install_command`] drives the human reinstall hints: every
    /// npm-family flavor must name its own package manager's install, and
    /// flavors with no consuming install step stay silent.
    #[test]
    fn flavor_install_command_maps_every_flavor() {
        assert_eq!(flavor_install_command("package-lock"), Some("npm install"));
        assert_eq!(flavor_install_command("yarn-classic"), Some("yarn install"));
        assert_eq!(flavor_install_command("yarn-berry"), Some("yarn install"));
        assert_eq!(flavor_install_command("pnpm"), Some("pnpm install"));
        assert_eq!(flavor_install_command("pnpm-legacy"), Some("pnpm install"));
        assert_eq!(flavor_install_command("bun"), Some("bun install"));
        assert_eq!(flavor_install_command("vlt"), Some("vlt install"));
        assert_eq!(flavor_install_command("cargo"), None);
        assert_eq!(flavor_install_command(""), None);
        assert_eq!(flavor_install_command("sbt"), Some("sbt update"));
        assert_eq!(
            flavor_install_command("scala-cli"),
            Some("scala-cli compile --test .")
        );
    }

    #[test]
    fn jvm_commit_hint_names_the_generated_root_file() {
        let set = |fs: &[&str]| fs.iter().map(|f| f.to_string()).collect::<HashSet<_>>();
        let sbt = commit_hint(&set(&["sbt"]), false);
        assert!(
            sbt.starts_with("socket-patch-vendor.sbt and .socket/vendor/"),
            "{sbt}"
        );
        assert!(!sbt.contains("lockfiles"), "{sbt}");
        let cli = commit_hint(&set(&["scala-cli"]), false);
        assert!(
            cli.starts_with("socket-patch.scala and .socket/vendor/"),
            "{cli}"
        );
        let both = commit_hint(&set(&["sbt", "package-lock"]), false);
        assert!(
            both.contains("socket-patch-vendor.sbt") && both.contains("lockfiles"),
            "{both}"
        );
        assert_eq!(
            commit_hint(&set(&[]), false),
            ".socket/vendor/ and the updated lockfiles to make the patches portable"
        );
        // pnpm names pnpm-workspace.yaml only when the run left one (#734).
        let pnpm = commit_hint(&set(&["pnpm"]), true);
        assert!(pnpm.contains("and pnpm-workspace.yaml"), "{pnpm}");
        let pnpm = commit_hint(&set(&["pnpm"]), false);
        assert!(
            pnpm.starts_with(".socket/vendor/, package.json, and pnpm-lock.yaml")
                && pnpm.contains("re-run vendor"),
            "{pnpm}"
        );
        let wiring = |kind: &str| {
            vec![vendor::state::WiringRecord {
                file: "x".into(),
                kind: kind.into(),
                action: vendor::state::WiringAction::Added,
                key: None,
                original: None,
                new: None,
            }]
        };
        assert_eq!(
            jvm_wiring_tool(&wiring(socket_patch_core::vendor::jvm::SBT_FRAGMENT_KIND)),
            Some("sbt")
        );
        assert_eq!(
            jvm_wiring_tool(&wiring(socket_patch_core::vendor::jvm::COURSIER_INDEX_KIND)),
            Some("scala-cli")
        );
        assert_eq!(jvm_wiring_tool(&wiring("pom_fragment")), None);
    }

    #[test]
    fn no_manifest_with_unreadable_ledger_warns() {
        assert_eq!(
            no_manifest_ledger_unreadable("corrupt .socket/vendor/state.json: expected value"),
            "Warning: No manifest to vendor from, and the vendor ledger could not be read: \
             corrupt .socket/vendor/state.json: expected value\n  Run `socket-patch repair` \
             to check the vendored artifacts."
        );
    }

    /// The no-manifest no-op names the MANIFEST (the thing missing) and,
    /// on a ledger-tracked project (`scan`/`get --mode vendored` never
    /// write a manifest), says what IS vendored instead of "nothing".
    #[test]
    fn no_manifest_message_names_the_manifest_and_tracked_entries() {
        assert_eq!(
            no_manifest_message(0),
            "No manifest found, nothing to vendor."
        );
        let one = no_manifest_message(1);
        assert!(
            one.starts_with("No manifest to vendor from; 1 vendored entry is tracked"),
            "{one}"
        );
        assert!(one.contains("`socket-patch repair`"), "{one}");
        let many = no_manifest_message(3);
        assert!(
            many.contains("3 vendored entries are tracked in the ledger"),
            "{many}"
        );
        for msg in [&one, &many] {
            assert!(
                !msg.contains(".socket folder"),
                "never claims .socket/ is missing: {msg}"
            );
        }
    }

    fn with_scope(list: Option<&[&str]>) -> GlobalArgs {
        GlobalArgs {
            ecosystems: list.map(|l| l.iter().map(|s| s.to_string()).collect()),
            ..GlobalArgs::default()
        }
    }

    /// [`ecosystem_in_scope`] is `--ecosystems`' exact-name match (clap
    /// validates the names, so no case or alias variant reaches it); `None`
    /// means everything is in scope.
    #[test]
    fn ecosystem_in_scope_is_an_exact_name_match() {
        let unscoped = with_scope(None);
        assert!(ecosystem_in_scope(&unscoped, "npm"));
        assert!(ecosystem_in_scope(&unscoped, "cargo"));

        let npm_only = with_scope(Some(&["npm"]));
        assert!(ecosystem_in_scope(&npm_only, "npm"));
        assert!(!ecosystem_in_scope(&npm_only, "cargo"));
        assert!(!ecosystem_in_scope(&npm_only, "golang"));

        let golang = with_scope(Some(&["golang"]));
        assert!(ecosystem_in_scope(&golang, "golang"));
    }

    /// A v5 JVM-backend ledger entry is recorded as `jvm`, which is no
    /// `--ecosystems` name: `--ecosystems maven` must still scope it in
    /// (the GC passes, rollback's vendored leg and repair all filter ledger
    /// entries by this), and another ecosystem's scope must leave it out.
    #[test]
    fn jvm_ledger_entries_are_in_the_maven_scope() {
        let maven = with_scope(Some(&["maven"]));
        assert!(ecosystem_in_scope(&maven, "jvm"));
        assert!(ecosystem_in_scope(&maven, "maven"));
        let npm_only = with_scope(Some(&["npm"]));
        assert!(!ecosystem_in_scope(&npm_only, "jvm"));
        assert!(ecosystem_in_scope(&with_scope(None), "jvm"));
    }
}

#[cfg(test)]
mod revert_dispatch_tests {
    use super::*;
    use socket_patch_core::vendor::state::VendorArtifact;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn entry_for(eco: &str, base_purl: &str) -> VendorEntry {
        VendorEntry::new(
            eco.into(),
            base_purl.into(),
            UUID.into(),
            VendorArtifact {
                yarn_berry10c0: None,
                path: format!(".socket/vendor/{eco}/{UUID}/artifact"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            Vec::new(),
        )
    }

    /// The nuget and maven revert arms must route to their real backends —
    /// whatever those backends decide about an empty project, the outcome
    /// must never be the unknown-ecosystem fall-through refusal.
    #[tokio::test]
    async fn nuget_and_maven_reverts_route_to_real_backends() {
        for (eco, purl) in [
            ("nuget", "pkg:nuget/Newtonsoft.Json@13.0.1"),
            (
                "maven",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let outcome = dispatch_revert_one(&entry_for(eco, purl), tmp.path(), true).await;
            if let Some(error) = &outcome.error {
                assert!(
                    !error.contains("no vendor backend for ecosystem"),
                    "`{eco}` must route to its backend, not the unknown-ecosystem arm: {error}"
                );
            }
        }
    }

    /// An unknown ecosystem string (a tampered/hand-edited state.json entry)
    /// fails CLOSED with a diagnostic naming the ecosystem — never guessed
    /// into some other backend, never a silent success.
    #[tokio::test]
    async fn unknown_ecosystem_revert_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome = dispatch_revert_one(
            &entry_for("frobnicate", "pkg:frobnicate/x@1.0.0"),
            tmp.path(),
            false,
        )
        .await;
        assert!(!outcome.success, "unknown ecosystem must fail the revert");
        let error = outcome.error.expect("failure carries a diagnostic");
        assert!(
            error.contains("no vendor backend for ecosystem `frobnicate`"),
            "{error}"
        );
    }

    /// [`Discovery::vendor_entry_in_use`]'s fail-safe arm: with no file of
    /// the entry's ecosystem to read (no lock), every ecosystem — and an
    /// unknown one — reports `None`, "cannot determine", which all callers
    /// must treat as KEEP.
    #[tokio::test]
    async fn in_use_is_none_without_a_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let discovery = socket_patch_core::vex::discover_patched_refs(tmp.path()).await;
        for (eco, purl) in [
            ("npm", "pkg:npm/left-pad@1.3.0"),
            ("cargo", "pkg:cargo/cfg-if@1.0.4"),
            ("gem", "pkg:gem/rails@6.0.3"),
            ("pypi", "pkg:pypi/foo@1.0.0"),
            ("composer", "pkg:composer/monolog/monolog@3.0.0"),
            ("golang", "pkg:golang/github.com/pkg/errors@v0.9.1"),
            ("nuget", "pkg:nuget/Newtonsoft.Json@13.0.1"),
            ("frobnicate", "pkg:frobnicate/x@1.0.0"),
        ] {
            assert_eq!(
                discovery
                    .vendor_entry_in_use(tmp.path(), &entry_for(eco, purl))
                    .await,
                None,
                "`{eco}` with no lock must report undeterminable (keep)"
            );
        }
    }
}

#[cfg(test)]
mod persist_tests {
    use super::*;
    use socket_patch_core::vendor::state::VendorArtifact;

    const UUID_A: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const UUID_B: &str = "1a2b3c4d-5e6f-4a1b-8c2d-9e0f1a2b3c4d";
    const UUID_C: &str = "2b3c4d5e-6f7a-4b2c-9d3e-0f1a2b3c4d5e";
    const PURL_ONE: &str = "pkg:npm/left-pad@1.3.0";
    const PURL_TWO: &str = "pkg:npm/right-pad@1.0.0";

    fn npm_entry(base_purl: &str, uuid: &str) -> VendorEntry {
        VendorEntry {
            flavor: Some("package-lock".into()),
            ..VendorEntry::new(
                "npm".into(),
                base_purl.into(),
                uuid.into(),
                VendorArtifact {
                    yarn_berry10c0: None,
                    path: format!(".socket/vendor/npm/{uuid}/pkg.tgz"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                Vec::new(),
            )
        }
    }

    fn empty_record() -> PatchRecord {
        PatchRecord {
            uuid: UUID_A.to_string(),
            exported_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    async fn mk_uuid_dir(root: &Path, uuid: &str) {
        let dir = root.join(format!(".socket/vendor/npm/{uuid}"));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("pkg.tgz"), b"tgz").await.unwrap();
    }

    /// The stale-uuid sweep's filter-false KEEP: on a re-vendor under a new
    /// patch uuid, the previous uuid's dir must be kept when another ledger
    /// entry (a variant sibling) still shares the same `(eco, uuid)` —
    /// deleting it would destroy the sibling's live artifact. Once nothing
    /// shares the uuid, the same sweep removes the stale dir and records
    /// the `vendor_stale_artifact_removed` event.
    #[tokio::test]
    async fn stale_uuid_sweep_keeps_dir_still_shared_with_a_sibling() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        mk_uuid_dir(root, UUID_A).await;
        let common = GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            silent: true,
            ..GlobalArgs::default()
        };
        let record = empty_record();

        let mut state = VendorState::default();
        state
            .entries
            .insert(PURL_ONE.to_string(), npm_entry(PURL_ONE, UUID_A));
        state
            .entries
            .insert(PURL_TWO.to_string(), npm_entry(PURL_TWO, UUID_A));

        // Re-vendor PURL_ONE under UUID_B: UUID_A is still owned by the
        // sibling entry, so its dir must survive and no removal is recorded.
        let mut env = Envelope::new(Command::Vendor);
        let has_errors = persist_vendor_entry(
            &common,
            &mut env,
            &mut state,
            PURL_ONE,
            npm_entry(PURL_ONE, UUID_B),
            false,
            &record,
        )
        .await;
        assert!(!has_errors, "save must succeed: {:?}", env.events);
        assert!(
            root.join(format!(".socket/vendor/npm/{UUID_A}")).exists(),
            "a uuid dir still shared with a sibling entry must be KEPT"
        );
        assert!(
            !env.events
                .iter()
                .any(|e| e.error_code.as_deref() == Some("vendor_stale_artifact_removed")),
            "no removal may be recorded for a kept dir: {:?}",
            env.events
        );

        // Drop the sibling; re-vendor PURL_ONE again under UUID_C. UUID_B is
        // now unshared — the sweep removes it and records the event.
        state.entries.remove(PURL_TWO);
        mk_uuid_dir(root, UUID_B).await;
        let mut env = Envelope::new(Command::Vendor);
        let has_errors = persist_vendor_entry(
            &common,
            &mut env,
            &mut state,
            PURL_ONE,
            npm_entry(PURL_ONE, UUID_C),
            false,
            &record,
        )
        .await;
        assert!(!has_errors, "save must succeed: {:?}", env.events);
        assert!(
            !root.join(format!(".socket/vendor/npm/{UUID_B}")).exists(),
            "an unshared stale uuid dir is removed on re-vendor"
        );
        assert!(
            env.events
                .iter()
                .any(|e| e.error_code.as_deref() == Some("vendor_stale_artifact_removed")),
            "the removal is recorded: {:?}",
            env.events
        );
        assert!(
            root.join(format!(".socket/vendor/npm/{UUID_A}")).exists(),
            "the sweep only reclaims the REPLACED entry's dir, never unrelated ones"
        );
    }

    /// The stale-uuid sweep's dry-run guard: a dry-run caller must NEVER
    /// delete the replaced uuid's dir, while the `Removed` event still
    /// records (as the preview of what a wet run would reclaim). Today's
    /// backends return no entry on dry runs, so this pins the helper's own
    /// contract against a future caller that does.
    #[tokio::test]
    async fn stale_uuid_sweep_dry_run_keeps_the_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        mk_uuid_dir(root, UUID_A).await;
        let common = GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            silent: true,
            dry_run: true,
            ..GlobalArgs::default()
        };
        let record = empty_record();
        let mut state = VendorState::default();
        state
            .entries
            .insert(PURL_ONE.to_string(), npm_entry(PURL_ONE, UUID_A));

        let mut env = Envelope::new(Command::Vendor);
        let has_errors = persist_vendor_entry(
            &common,
            &mut env,
            &mut state,
            PURL_ONE,
            npm_entry(PURL_ONE, UUID_B),
            false,
            &record,
        )
        .await;
        assert!(!has_errors, "save must succeed: {:?}", env.events);
        assert!(
            root.join(format!(".socket/vendor/npm/{UUID_A}")).exists(),
            "a dry run must not delete the replaced uuid's dir"
        );
        assert!(
            env.events
                .iter()
                .any(|e| e.error_code.as_deref() == Some("vendor_stale_artifact_removed")),
            "the would-be removal is still previewed as an event: {:?}",
            env.events
        );
    }
}

/// Exact-string tests for the human output of `vendor` / `vendor --revert`.
#[cfg(test)]
mod ui_format_tests {
    use super::*;

    #[test]
    fn vendor_progress_line() {
        assert_eq!(
            format_vendor_progress(false, "pkg:npm/lodash@4.17.20", 1, 2),
            "Vendoring pkg:npm/lodash@4.17.20... (1/2)"
        );
        assert_eq!(
            format_vendor_progress(true, "pkg:npm/lodash@4.17.20", 1, 1),
            "Checking pkg:npm/lodash@4.17.20..."
        );
    }

    fn tally(
        vendored: u32,
        already: u32,
        not_installed: u32,
        skipped: u32,
        failed: u32,
    ) -> VendorTally {
        VendorTally {
            vendored,
            already,
            not_installed,
            skipped,
            failed,
        }
    }

    #[test]
    fn vendor_summary_singular_plural_and_zero() {
        assert_eq!(
            format_vendor_summary(false, &tally(0, 0, 0, 0, 0)),
            "Vendored 0 packages."
        );
        assert_eq!(
            format_vendor_summary(false, &tally(1, 0, 0, 0, 0)),
            "Vendored 1 package."
        );
        assert_eq!(
            format_vendor_summary(false, &tally(2, 0, 0, 0, 0)),
            "Vendored 2 packages."
        );
        assert_eq!(
            format_vendor_summary(true, &tally(1, 0, 0, 0, 0)),
            "Would vendor 1 package."
        );
        assert_eq!(
            format_vendor_summary(true, &tally(0, 0, 0, 0, 2)),
            "Would vendor 0 packages; 2 failed."
        );
    }

    #[test]
    fn vendor_summary_lists_only_nonzero_clauses_in_order() {
        assert_eq!(
            format_vendor_summary(false, &tally(1, 2, 1, 3, 1)),
            "Vendored 1 package; 2 already vendored; 1 not installed; 3 skipped; 1 failed."
        );
        // Nothing but in-sync packages: no "Vendored 0 packages" headline.
        assert_eq!(
            format_vendor_summary(false, &tally(0, 2, 0, 0, 0)),
            "All 2 packages are already vendored; nothing to do."
        );
        assert_eq!(
            format_vendor_summary(true, &tally(0, 2, 0, 0, 0)),
            "All 2 packages are already vendored; nothing to do."
        );
        assert_eq!(
            format_vendor_summary(false, &tally(0, 1, 0, 0, 0)),
            "1 package is already vendored; nothing to do."
        );
        assert_eq!(
            format_vendor_summary(false, &tally(0, 2, 0, 0, 1)),
            "Vendored 0 packages; 2 already vendored; 1 failed."
        );
        assert_eq!(
            format_vendor_summary(false, &tally(1, 0, 1, 0, 0)),
            "Vendored 1 package; 1 not installed."
        );
    }

    #[test]
    fn tally_splits_skips_and_counts_dry_run_previews() {
        let mut env = Envelope::new(Command::Vendor);
        env.record(
            PatchEvent::new(PatchAction::Skipped, "pkg:npm/a@1")
                .with_reason("already_vendored", "in sync"),
        );
        env.record(
            PatchEvent::new(PatchAction::Skipped, "pkg:npm/b@1")
                .with_reason("package_not_installed", "not on disk"),
        );
        env.record(
            PatchEvent::new(PatchAction::Skipped, "pkg:jsr/c@1")
                .with_reason("vendor_unsupported_ecosystem", "no backend"),
        );
        env.record(PatchEvent::new(PatchAction::Applied, "pkg:npm/d@1"));
        env.record(PatchEvent::new(PatchAction::Failed, "pkg:npm/e@1").with_error("x", "y"));
        // An uncounted advisory event must not count as anything.
        push_advisory_event(
            &mut env,
            "pkg:npm/d@1",
            &VendorWarning::new("vendor_prebuilt_downloaded", "detail"),
        );
        assert_eq!(
            VendorTally::from_envelope(&env, false, 0),
            tally(1, 1, 1, 1, 1)
        );

        let mut dry = Envelope::new(Command::Vendor);
        dry.record(PatchEvent::new(PatchAction::Verified, "pkg:npm/a@1"));
        dry.record(PatchEvent::new(PatchAction::Verified, "pkg:npm/b@1"));
        dry.record(PatchEvent::new(PatchAction::Verified, "pkg:npm/c@1"));
        assert_eq!(
            VendorTally::from_envelope(&dry, true, 0),
            tally(3, 0, 0, 0, 0)
        );
        assert_eq!(
            VendorTally::from_envelope(&dry, true, 2),
            tally(1, 2, 0, 0, 0)
        );
        assert_eq!(
            format_vendor_summary(true, &VendorTally::from_envelope(&dry, true, 3)),
            "All 3 packages are already vendored; nothing to do."
        );
    }

    #[test]
    fn advisories_are_tiered() {
        assert_eq!(
            format_advisory("vendor_prebuilt_downloaded", "d", false),
            None
        );
        assert_eq!(
            format_advisory(
                "vendor_prebuilt_downloaded",
                "vendored x from the service",
                true
            ),
            Some("Note: vendored x from the service".to_string())
        );
        assert_eq!(format_advisory("vendor_artifact_reused", "r", false), None);
        assert_eq!(
            format_advisory("vendor_artifact_reused", "re-wired x", true),
            Some("Note: re-wired x".to_string())
        );
        assert_eq!(
            format_advisory("vendor_fetched_missing", "fetched", false),
            Some("Note: fetched".to_string())
        );
        assert_eq!(
            format_advisory("vendor_lock_entry_drifted", "drifted", false),
            Some("Warning: drifted".to_string())
        );
    }

    #[test]
    fn failure_lines_normalize_the_purl() {
        assert_eq!(
            format_vendor_failure(
                "pkg:npm/%40scope/pkg@1.0.0",
                "no installed package found on disk"
            ),
            "Error: Cannot vendor pkg:npm/@scope/pkg@1.0.0: no installed package found on disk"
        );
        assert_eq!(
            format_reconciled("pkg:npm/left-pad@1.3.0", false),
            "Reverted vendoring of pkg:npm/left-pad@1.3.0 (patch no longer in manifest)."
        );
        assert_eq!(
            format_reconciled("pkg:npm/left-pad@1.3.0", true),
            "Would revert vendoring of pkg:npm/left-pad@1.3.0 (patch no longer in manifest)."
        );
    }

    fn revert(reverted: u32, failed: u32, kept: u32, orphans: &[&str]) -> RevertSummary {
        RevertSummary {
            reverted,
            failed,
            kept,
            orphans: orphans.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn revert_summary_package_line() {
        assert_eq!(
            format_revert_summary(false, &revert(1, 0, 0, &[])),
            vec!["Reverted 1 vendored package."]
        );
        assert_eq!(
            format_revert_summary(false, &revert(2, 1, 0, &[])),
            vec!["Reverted 2 vendored packages; 1 failed."]
        );
        assert_eq!(
            format_revert_summary(true, &revert(2, 0, 0, &[])),
            vec!["Would revert 2 vendored packages."]
        );
        // Every entry failed: the line still explains the exit code.
        assert_eq!(
            format_revert_summary(false, &revert(0, 1, 0, &[])),
            vec!["Reverted 0 vendored packages; 1 failed."]
        );
    }

    #[test]
    fn revert_summary_reports_orphans_separately() {
        let one = ".socket/vendor/npm/4444";
        assert_eq!(
            format_revert_summary(false, &revert(0, 0, 0, &[one])),
            vec!["Removed 1 orphaned vendor directory with no ledger entry: .socket/vendor/npm/4444."]
        );
        assert_eq!(
            format_revert_summary(true, &revert(1, 0, 0, &["a", "b"])),
            vec![
                "Would revert 1 vendored package.",
                "Would remove 2 orphaned vendor directories with no ledger entry: a, b.",
            ]
        );
    }

    #[test]
    fn revert_summary_kept_line() {
        let lines = format_revert_summary(false, &revert(0, 0, 1, &[]));
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with("Kept 1 drifted package: lock entries were re-resolved"),
            "{lines:?}"
        );
        let lines = format_revert_summary(false, &revert(1, 0, 2, &[]));
        assert_eq!(lines[0], "Reverted 1 vendored package.");
        assert!(
            lines[1].starts_with("Kept 2 drifted packages: "),
            "{lines:?}"
        );
    }

    #[test]
    fn state_unreadable_names_the_file_once() {
        assert_eq!(
            format_state_unreadable("corrupt ./.socket/vendor/state.json: key must be a string"),
            "Error: Could not read the vendor ledger: corrupt ./.socket/vendor/state.json: \
             key must be a string"
        );
        assert_eq!(
            format_state_unreadable("Permission denied (os error 13)"),
            "Error: Could not read the vendor ledger (.socket/vendor/state.json): \
             Permission denied (os error 13)"
        );
    }

    #[test]
    fn revert_install_hint_forces_bun() {
        assert_eq!(
            flavor_revert_install_command("bun"),
            Some("bun install --force")
        );
        assert_eq!(flavor_revert_install_command("pnpm"), Some("pnpm install"));
        assert_eq!(flavor_revert_install_command("cargo"), None);
    }

    #[test]
    fn revert_install_hint_names_the_command() {
        assert_eq!(
            format_revert_install_hint("npm install"),
            "Run `npm install` to resync the installed tree with the restored lockfile (it \
             may still hold the vendored bytes if you reinstalled after vendoring)."
        );
    }
}

#[cfg(test)]
mod eject_snapshot_tests {
    use super::*;

    fn write(root: &Path, rel: &str, bytes: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn read(root: &Path, rel: &str) -> Option<String> {
        std::fs::read_to_string(root.join(rel)).ok()
    }

    /// #687: the rollback puts back exactly what the eject wrote — the
    /// planned restore files, the files the restore reported, and the
    /// vendored commit's files (from the commit's before-image when no
    /// snapshot holds them; deleted when the commit created them) — and
    /// leaves every other root file as it is now, even one whose bytes
    /// changed during the run (another process's log).
    /// A FIFO at a snapshotted path fails the snapshot promptly (the eject
    /// then refuses) instead of blocking in open(2).
    #[cfg(unix)]
    #[tokio::test]
    async fn snapshot_refuses_a_fifo_instead_of_wedging() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let c = std::ffi::CString::new(root.join("package-lock.json").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            EjectSnapshot::take(root, &["package-lock.json".to_string()]),
        )
        .await
        .expect("the snapshot must not block on a FIFO");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn restore_undoes_only_what_the_eject_wrote() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "package-lock.json", "hosted lock");
        write(root, "package.json", "manifest v1");
        write(root, "build.log", "line 1\n");
        write(root, "packages/a/package.json", "member v1");
        let snapshot = EjectSnapshot::take(root, &["package-lock.json".to_string()])
            .await
            .unwrap();

        // The upstream restore: rewrites the planned lock and creates a root
        // file it reports.
        write(root, "package-lock.json", "upstream lock");
        write(root, ".npmrc-created", "x");
        let written = vec![
            "package-lock.json".to_string(),
            ".npmrc-created".to_string(),
        ];
        // The vendored commit: a root manifest edit, a nested member edit
        // no snapshot holds, and a root file it creates.
        write(root, "package.json", "manifest vendored");
        write(root, "packages/a/package.json", "member vendored");
        write(root, "vendored-new.yaml", "new");
        let committed = vec![
            CommittedFile {
                rel: "package.json".into(),
                before: Some(b"manifest v1".to_vec()),
            },
            CommittedFile {
                rel: "packages/a/package.json".into(),
                before: Some(b"member v1".to_vec()),
            },
            CommittedFile {
                rel: "vendored-new.yaml".into(),
                before: None,
            },
        ];
        // Another process appends to its log meanwhile.
        write(root, "build.log", "line 1\nline 2\n");

        snapshot.restore(&written, &committed).await.unwrap();

        assert_eq!(
            read(root, "package-lock.json").as_deref(),
            Some("hosted lock")
        );
        assert_eq!(read(root, "package.json").as_deref(), Some("manifest v1"));
        assert_eq!(
            read(root, "packages/a/package.json").as_deref(),
            Some("member v1")
        );
        assert_eq!(read(root, "vendored-new.yaml"), None);
        assert_eq!(read(root, ".npmrc-created"), None);
        assert_eq!(
            read(root, "build.log").as_deref(),
            Some("line 1\nline 2\n"),
            "a root file the eject never wrote keeps its new bytes"
        );
        let hint = snapshot.files_hint(&written, &committed);
        let hinted: Vec<&str> = hint.split(' ').collect();
        assert_eq!(
            hinted,
            vec![
                "package-lock.json",
                "package.json",
                "packages/a/package.json"
            ],
            "the remedy names every file the rollback restores, nested commit \
             files included, and nothing it leaves alone or removes"
        );
    }

    /// #687: a file in scope whose bytes are already the snapshot's is not
    /// rewritten, so it keeps its inode.
    #[cfg(unix)]
    #[tokio::test]
    async fn restore_skips_files_already_at_their_snapshot_bytes() {
        use std::os::unix::fs::MetadataExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "package-lock.json", "hosted lock");
        let snapshot = EjectSnapshot::take(root, &["package-lock.json".to_string()])
            .await
            .unwrap();
        let ino = std::fs::metadata(root.join("package-lock.json"))
            .unwrap()
            .ino();
        snapshot
            .restore(&["package-lock.json".to_string()], &[])
            .await
            .unwrap();
        assert_eq!(
            std::fs::metadata(root.join("package-lock.json"))
                .unwrap()
                .ino(),
            ino
        );
    }

    /// A FIFO at a captured path fails the snapshot fast instead of
    /// wedging the eject in a blocking open(2).
    #[cfg(unix)]
    #[tokio::test]
    async fn snapshot_fails_closed_on_a_fifo() {
        let tmp = tempfile::tempdir().unwrap();
        let rel = socket_patch_core::vendor::jvm::layout::CAPTURED_FILES[0];
        let path = tmp.path().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        let taken = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            EjectSnapshot::take(tmp.path(), &[]),
        )
        .await
        .expect("a FIFO must not wedge the eject snapshot");
        let err = taken.err().expect("a FIFO must fail the snapshot");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}

#[cfg(test)]
mod unused_vendored_manifest_keys_tests {
    use super::unused_vendored_manifest_keys;
    use socket_patch_core::vendor::state::{VendorArtifact, VendorEntry};
    use std::collections::HashMap;

    /// A ledger entry whose base purl is `base_purl`; only the purl
    /// matters to the manifest-key relation.
    fn entry(ecosystem: &str, base_purl: &str) -> VendorEntry {
        VendorEntry::new(
            ecosystem.into(),
            base_purl.into(),
            "11111111-1111-4111-8111-111111111111".into(),
            VendorArtifact {
                yarn_berry10c0: None,
                path: String::new(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            Vec::new(),
        )
    }

    /// The keys an unused ledger entry `key` (base purl = the key) owns.
    fn keys_for(patches: &HashMap<String, ()>, eco: &str, key: &str) -> Vec<String> {
        let mut out = unused_vendored_manifest_keys(patches, key, &entry(eco, key));
        out.sort();
        out
    }

    /// A golang ledger key may keep the module proxy's `!x` case encoding
    /// while the entry's base purl and the manifest key are the decoded
    /// spelling; [`PurlKey`](socket_patch_core::utils::purl_key::PurlKey)
    /// does not decode `!x`, so the base purl must be matched too or the
    /// manifest entry (and its blobs) survive the revert.
    #[test]
    fn covers_the_decoded_golang_base_purl_of_a_bang_encoded_key() {
        let patches: HashMap<String, ()> = [
            "pkg:golang/github.com/BurntSushi/toml@v1.0.0",
            "pkg:golang/github.com/BurntSushi/toml@v1.1.0",
        ]
        .into_iter()
        .map(|k| (k.to_string(), ()))
        .collect();
        let key = "pkg:golang/github.com/!burnt!sushi/toml@v1.0.0";
        let e = entry("golang", "pkg:golang/github.com/BurntSushi/toml@v1.0.0");
        assert_eq!(
            unused_vendored_manifest_keys(&patches, key, &e),
            vec!["pkg:golang/github.com/BurntSushi/toml@v1.0.0".to_string()]
        );
    }

    /// The wet vendor GC and `scan --prune --dry-run`'s preview both drop
    /// these keys, so they must cover every spelling of the release and
    /// nothing else.
    #[test]
    fn covers_every_spelling_of_the_release() {
        let patches: HashMap<String, ()> = [
            "pkg:nuget/Newtonsoft.Json@13.0.1",
            "pkg:nuget/newtonsoft.json@13.0.1?x=1",
            "pkg:nuget/newtonsoft.json@13.0.2",
            "pkg:pypi/typing-extensions@4.12.2",
            "pkg:composer/psr/log@3.0.2",
        ]
        .into_iter()
        .map(|k| (k.to_string(), ()))
        .collect();
        assert_eq!(
            keys_for(&patches, "nuget", "pkg:nuget/newtonsoft.json@13.0.1"),
            vec![
                "pkg:nuget/Newtonsoft.Json@13.0.1".to_string(),
                "pkg:nuget/newtonsoft.json@13.0.1?x=1".to_string(),
            ]
        );
        assert_eq!(
            keys_for(&patches, "pypi", "pkg:pypi/typing_extensions@4.12.2"),
            vec!["pkg:pypi/typing-extensions@4.12.2".to_string()]
        );
        assert_eq!(
            keys_for(&patches, "composer", "pkg:composer/psr/log@3.0.2.0"),
            vec!["pkg:composer/psr/log@3.0.2".to_string()]
        );
    }
}
