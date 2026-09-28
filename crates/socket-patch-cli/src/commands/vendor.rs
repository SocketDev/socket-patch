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
use socket_patch_core::telemetry::{track_patch_vendor_failed, track_patch_vendored};
use socket_patch_core::utils::concurrent::{ordered_concurrent, registry_concurrency};
use socket_patch_core::utils::group_commit::GroupCommit;
use socket_patch_core::utils::purl::{canonical_purl, normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::socket_dir::remove_tree_and_prune;
use socket_patch_core::vendor::{
    self, ecosystem_dir_for_purl, load_state, lock_inventory, lookup_entry, registry_fetch,
    save_state, save_state_shared, DeferredMiss, DeferredPackage, PackageSource, RevertOpts,
    RevertOutcome, VendorEntry, VendorOutcome, VendorServiceConfig, VendorState, VendorWarning,
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
    ApplyRequest, RevertedEntry, VendorRevertStep, VendoredBackend, NO_LOCAL_SOURCE_MESSAGE,
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

    /// Tolerate missing patch-target files in the staged copy (skip them
    /// instead of failing) and bypass the variant probe for multi-release
    /// ecosystems. Not needed for a beforeHash mismatch: vendoring always
    /// overwrites mismatched content with the verified patched bytes and
    /// warns (`vendor_content_mismatch_overwritten`).
    #[arg(
        short = 'f',
        long,
        env = "SOCKET_FORCE",
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

    /// On a successful vendor, also generate an OpenVEX 0.2.0 document
    /// (same contract as `apply --vex`).
    #[command(flatten)]
    pub vex: VexEmbedArgs,
}

/// Refusal codes that are expected skips, not command failures: the user's
/// request is still fully satisfied when these are the only non-successes.
fn refusal_is_benign(code: &str) -> bool {
    matches!(code, "vendor_unsupported_ecosystem" | "already_vendored")
}

/// Dispatch one purl to its ecosystem backend. `pkg_path` is the crawler's
/// installed location (site-packages root for pypi, the package dir
/// otherwise), or a fetched artifact the backend materialises only if it
/// reaches a branch that reads it. Returns `None` for purls with no vendor
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
    // The patch.socket.dev vendoring-service config. `None` = build-only;
    // `vendor` and `scan`/`get --mode vendored` pass `Some(_)` (honoring
    // `--vendor-source`); repair passes `None` — it rebuilds locally from
    // the recorded patch.
    service: Option<&VendorServiceConfig>,
    pipenv_version: &tokio::sync::OnceCell<Option<u32>>,
    installed_sites: &vendor::pypi::InstalledSiteListings,
) -> Option<VendorOutcome> {
    let eco = ecosystem_dir_for_purl(purl)?;

    // Ecosystems with prebuilt service downloads. Under fail-closed `service`
    // mode any other ecosystem is refused rather than silently built; under
    // `auto`/`build` it falls through to the local build.
    const SERVICE_ECOSYSTEMS: &[&str] = &[
        "npm", "pypi", "cargo", "golang", "composer", "gem", "nuget", "maven",
    ];
    if let Some(cfg) = service {
        if cfg.source.requires_service() && !SERVICE_ECOSYSTEMS.contains(&eco) {
            return Some(VendorOutcome::Refused {
                code: "vendor_service_unsupported_ecosystem",
                detail: format!(
                    "--vendor-source=service is not supported for `{eco}` \
                     (prebuilt downloads cover npm, pypi, cargo, golang, composer, \
                     gem, nuget, and maven); \
                     use --vendor-source=auto or --vendor-source=build"
                ),
            });
        }
    }
    // Every backend takes the identical 9-argument tuple.
    macro_rules! vend {
        ($backend:path) => {
            $backend(
                purl,
                pkg_path,
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
    // Maven and NuGet have no registry-fetch rung — `fetch_and_stage` serves
    // no fetcher for either and `stage_local_artifact` is npm-only — so their
    // source is always the crawler's own directory.
    macro_rules! vend_installed {
        ($backend:path) => {{
            debug_assert!(
                matches!(pkg_path, PackageSource::Installed(_)),
                "{eco} has no fetch rung; a pending source would need materialising"
            );
            $backend(
                purl,
                pkg_path.path(),
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
                service,
            )
            .await
        }};
    }
    Some(match eco {
        // The flavor router probes the project's lockfile (package-lock /
        // yarn / pnpm / bun) and dispatches or refuses per flavor.
        "npm" => vend!(vendor::npm_flavor::vendor_npm_any),
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
        "gem" => vend!(vendor::gem::vendor_gem),
        "cargo" => vend!(vendor::cargo::vendor_cargo_crate),
        "golang" => vend!(vendor::golang::vendor_go_module),
        "composer" => vend!(vendor::composer_lock::vendor_composer),
        "nuget" => vend_installed!(vendor::nuget_feed::vendor_nuget),
        "maven" => vend_installed!(vendor::maven_repo::vendor_maven),
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
    match entry.ecosystem.as_str() {
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

/// Is this vendored entry still consumed by its project's lockfile
/// dependency graph? `None` = cannot determine — callers must keep the
/// entry (fail-safe): ecosystems other than npm and cargo have no in-use
/// probe yet, and a missing/unreadable lockfile proves nothing.
async fn dispatch_in_use_one(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    match entry.ecosystem.as_str() {
        "npm" => vendor::npm_flavor::vendored_entry_in_use(entry, project_root).await,
        // Cargo probes the lock entry's shape: detached + `[patch]` pointing
        // at this entry's copy = in use; a registry source (crates.io
        // re-resolve or a hosted takeover) or a missing entry = reclaimable.
        "cargo" => vendor::cargo::vendored_entry_in_use(entry, project_root).await,
        _ => None,
    }
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

/// Does `eco` fall inside this run's `--ecosystems` scope?
pub(crate) fn ecosystem_in_scope(common: &GlobalArgs, eco: &str) -> bool {
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

pub async fn run(args: VendorArgs) -> i32 {
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
        if !args.common.is_global() {
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
                let params = args.vex.to_build_params();
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
        let telemetry_ids = (client.api_token().cloned(), client.org_slug().cloned());
        Some((
            args.common
                .vendor_service_config(Some(client), use_public_proxy),
            telemetry_ids,
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
                let params = args.vex.to_build_params();
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

    if let Some((_, (api_token, org_slug))) = &vendor_service {
        track_outcomes_for_vendor(
            exit != 0,
            &env,
            args.common.dry_run,
            api_token.as_deref(),
            org_slug.as_deref(),
        )
        .await;
    }

    exit
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
/// the restore's files (nested locks included), the project's cargo and
/// maven config files, the vendor ledger, and the set of vendored uuid
/// directories. [`EjectSnapshot::restore`] puts all of it back and removes
/// what the eject created.
struct EjectSnapshot {
    root: std::path::PathBuf,
    files: Vec<(String, Option<Vec<u8>>)>,
    root_files: std::collections::BTreeSet<String>,
    vendor_dirs: std::collections::BTreeSet<std::path::PathBuf>,
}

impl EjectSnapshot {
    const EXTRA: [&'static str; 5] = [
        ".cargo/config",
        ".cargo/config.toml",
        ".mvn/maven.config",
        ".mvn/checksums/checksums.sha256",
        socket_patch_core::vendor::VENDOR_STATE_REL,
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
                for unit in std::fs::read_dir(eco.path()).into_iter().flatten().flatten() {
                    out.insert(unit.path());
                }
            }
        }
        out
    }

    async fn take(root: &Path, touched: &[String]) -> std::io::Result<Self> {
        let root_files = Self::root_file_names(root).await?;
        let mut rels: std::collections::BTreeSet<String> = root_files.clone();
        rels.extend(touched.iter().cloned());
        rels.extend(Self::EXTRA.iter().map(|s| s.to_string()));
        let mut files = Vec::with_capacity(rels.len());
        for rel in rels {
            let bytes = match tokio::fs::read(root.join(&rel)).await {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            };
            files.push((rel, bytes));
        }
        Ok(EjectSnapshot {
            root: root.to_path_buf(),
            files,
            root_files,
            vendor_dirs: Self::vendor_dir_set(root),
        })
    }

    async fn restore(&self) -> Result<(), String> {
        let mut errors: Vec<String> = Vec::new();
        for (rel, bytes) in &self.files {
            let path = self.root.join(rel);
            let result = match bytes {
                Some(bytes) => {
                    socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(&path, bytes).await
                }
                None => match tokio::fs::remove_file(&path).await {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    other => other,
                },
            };
            if let Err(e) = result {
                errors.push(format!("{rel}: {e}"));
            }
        }
        // Root files the eject created.
        if let Ok(now) = Self::root_file_names(&self.root).await {
            for name in now.difference(&self.root_files) {
                if self.files.iter().any(|(rel, _)| rel == name) {
                    continue;
                }
                if let Err(e) = tokio::fs::remove_file(self.root.join(name)).await {
                    errors.push(format!("{name}: {e}"));
                }
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

    /// The project files for the manual remedy.
    fn files_hint(&self) -> String {
        self.files
            .iter()
            .filter(|(_, bytes)| bytes.is_some())
            .map(|(rel, _)| rel.as_str())
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
    let (api_token, org_slug) = (client.api_token().cloned(), client.org_slug().cloned());
    if !common.json && !common.silent {
        println!(
            "{} {} into .socket/vendor/...",
            if common.dry_run { "Would eject" } else { "Ejecting" },
            plural(pins.len(), "hosted package", "hosted packages")
        );
    }

    // One view per distinct uuid, fetched concurrently and consumed in pin
    // order; the views' blobs seed the in-memory staging.
    let mut records: HashMap<String, PatchRecord> = HashMap::new();
    let mut blobs: HashMap<String, Vec<u8>> = HashMap::new();
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
                for info in patch.files.values() {
                    let (Some(b64), Some(hash)) = (&info.blob_content, &info.after_hash) else {
                        continue;
                    };
                    if !socket_patch_core::patch::apply::is_valid_blob_hash(hash)
                        || blobs.contains_key(hash)
                    {
                        continue;
                    }
                    if let Ok(bytes) = crate::commands::get::base64_decode(b64) {
                        blobs.insert(hash.clone(), bytes);
                    }
                }
                let (_, record) = crate::commands::get::record_from_patch_response(&patch);
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
        track_outcomes_for_vendor(true, &env, common.dry_run, api_token.as_deref(), org_slug.as_deref())
            .await;
        return 1;
    }

    // Plan the upstream restore before touching anything: every pin must
    // re-resolve to its registry entry (a dry resolve), or the eject is
    // refused whole with each pin's remedy.
    let origins = crate::commands::rollback::patch_server_origins(common);
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
    let refused: Vec<(String, String)> = plan
        .refused()
        .map(|(pin, why)| (pin.purl.clone(), why.to_string()))
        .collect();
    if !refused.is_empty() {
        let mut env = Envelope::new(Command::Vendor);
        env.dry_run = common.dry_run;
        for (purl, why) in &refused {
            report_vendor_failure(common, purl, why);
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone())
                    .with_error("redirect_revert_failed", why.clone()),
            );
        }
        env.mark_error(EnvelopeError::new(
            "eject_refused",
            "not every hosted pin can be restored to its upstream registry entry; nothing was \
             changed",
        ));
        if common.json {
            println!("{}", env.to_pretty_json());
        }
        track_outcomes_for_vendor(true, &env, common.dry_run, api_token.as_deref(), org_slug.as_deref())
            .await;
        return 1;
    }

    // A dry run stops at the verified plan: restoring the live lock to
    // preview the vendor step would be a write.
    if common.dry_run {
        let mut env = Envelope::new(Command::Vendor);
        env.dry_run = true;
        for pin in &pins {
            env.record(PatchEvent::new(PatchAction::Applied, pin.purl.clone()).with_reason(
                "eject_planned",
                format!(
                    "would restore the upstream registry entry ({}) and vendor the patch",
                    pin.files.join(", ")
                ),
            ));
            if !common.json && !common.silent {
                println!(
                    "Would eject {} (restore {}, then vendor into .socket/vendor/)",
                    pin.purl,
                    pin.files.join(", ")
                );
            }
        }
        if args.vex.vex.is_some() && !common.json && !common.silent {
            println!("{}", crate::commands::vex::format_vex_dry_run_skip("vendored"));
        }
        if common.json {
            println!("{}", env.to_pretty_json());
        }
        track_outcomes_for_vendor(false, &env, true, api_token.as_deref(), org_slug.as_deref()).await;
        return 0;
    }

    // One transaction under one apply lock: snapshot what the eject can
    // touch, restore every pin upstream (so the vendor engine resolves the
    // pristine registry package even in a fresh checkout with nothing
    // installed), vendor, and on ANY failure put the snapshot back — a
    // failed eject leaves the project hosted, exactly as it was.
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
    let mut exit: i32;
    if let Some(why) = restore_failure {
        env.mark_error(EnvelopeError::new("redirect_revert_failed", why.clone()));
        if !common.json {
            eprintln!("Error: {}", crate::commands::rollback::capitalize_first(&why));
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
                    seed: blobs,
                    detached: true,
                    force: false,
                    prior: None,
                },
                &mut env,
            )
            .await;
        match applied {
            Ok(has_errors) => exit = i32::from(has_errors),
            Err(_) => {
                let code = "no_local_source";
                env.mark_error(EnvelopeError::new(code, NO_LOCAL_SOURCE_MESSAGE));
                if !common.json {
                    eprintln!(
                        "{}",
                        crate::commands::scan::vendor_flow::format_vendor_step_error(
                            code,
                            NO_LOCAL_SOURCE_MESSAGE
                        )
                    );
                }
                exit = 1;
            }
        }
    }
    if exit != 0 {
        match snapshot.restore().await {
            Ok(()) => env.warnings.push(RunWarning {
                code: "eject_rolled_back".to_string(),
                detail: "the eject did not complete, so every file it touched was restored: the \
                         project is still hosted, exactly as before"
                    .to_string(),
            }),
            Err(e) => {
                let detail = format!(
                    "the eject did not complete and restoring the pre-eject files failed ({e}); \
                     restore them from version control (`git checkout -- {}`)",
                    snapshot.files_hint()
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
                    println!("{}", crate::commands::vex::format_vex_dry_run_skip("vendored"));
                }
            } else {
                let params = args.vex.to_build_params();
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
    track_outcomes_for_vendor(
        exit != 0,
        &env,
        common.dry_run,
        api_token.as_deref(),
        org_slug.as_deref(),
    )
    .await;
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
    token: Option<&str>,
    org: Option<&str>,
) {
    if has_errors {
        track_patch_vendor_failed("vendor completed with failures", dry_run, token, org).await;
    } else {
        track_patch_vendored(env.summary.applied, dry_run, token, org).await;
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
    // The shared vendored apply: in-memory staging (committed .socket
    // artifacts read in place, missing content fetched per patch — no seed:
    // this manifest-driven command has no download phase) → the engine.
    let applied = VendoredBackend::new(common, Some(service))
        .apply(
            ApplyRequest {
                manifest: &manifest,
                socket_dir: &socket_dir,
                ledger,
                seed: HashMap::new(),
                detached: false,
                force: args.force,
                prior: None,
            },
            env,
        )
        .await;
    match applied {
        Ok(errors) => has_errors |= errors,
        Err(_) => {
            env.mark_error(EnvelopeError::new(
                "no_local_source",
                NO_LOCAL_SOURCE_MESSAGE,
            ));
            return 1;
        }
    }

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

/// One registry-fetch attempt through the pristine-source ladder's network
/// half: the lockfile inventory first, then the ledger-recovered pre-vendor
/// registry fragment (the live lockfile is rewired to `.socket/vendor/...`
/// for vendored packages, so only `--revert`'s restore data still knows the
/// registry resolution). Always integrity-verified fail-closed.
pub(crate) enum PristineFetch {
    Fetched(registry_fetch::FetchedPackage),
    /// Neither the lockfile nor the ledger can name a verifiable source.
    NoSource,
    Unverifiable(String),
    Failed(String),
}

pub(crate) async fn fetch_pristine_package(
    project_root: &Path,
    inventory: &[lock_inventory::LockfileEntry],
    client: &registry_fetch::RegistryClient,
    purl: &str,
    ledger_entry: Option<&VendorEntry>,
) -> PristineFetch {
    // A lock entry that carries an integrity is the registry resolution to
    // fetch. A DISCOVERY-ONLY entry (the lock is rewired to OUR reference,
    // whose recorded hashes are the patched wheel's — nothing PyPI serves)
    // cannot be fetched by itself: the ledger's pre-vendor fragment can, so
    // an already-vendored lock-only checkout re-scans green.
    let inventory_entry = lock_inventory::lookup(inventory, purl).cloned();
    let fetchable = inventory_entry
        .as_ref()
        .filter(|e| e.integrity != lock_inventory::LockIntegrity::None)
        .cloned();
    let entry = match (fetchable, ledger_entry) {
        (Some(e), _) => e,
        (None, Some(le)) => match lock_inventory::recover_lock_entry(project_root, le).await {
            Ok(rec) => rec,
            Err(e) => {
                return PristineFetch::Unverifiable(format!(
                    "the lockfile no longer records a registry resolution for {purl} \
                     (rewired to the vendored artifact) and the ledger cannot recover \
                     one: {e}"
                ))
            }
        },
        (None, None) => match inventory_entry {
            Some(e) => e,
            None => return PristineFetch::NoSource,
        },
    };
    match registry_fetch::fetch_and_stage(&entry, client).await {
        Ok(fetched) => PristineFetch::Fetched(fetched),
        Err(registry_fetch::FetchError::Unverifiable(d)) => PristineFetch::Unverifiable(d),
        Err(registry_fetch::FetchError::Failed(d)) => PristineFetch::Failed(d),
    }
}

/// Whether [`fetch_pristine_package`] would pick a VERIFIABLE registry
/// resolution for this purl — the same entry choice, made without the
/// download: the lock's own entry when it carries an integrity, else the
/// pre-vendor resolution the ledger recovers. A cargo crate from a git,
/// path or custom-registry source has neither, so its fetch refuses
/// `vendor_fetch_unverifiable`; deferring that fetch behind the patch
/// service would instead vendor the crates.io patch over it.
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

/// The purls among `purls` with an installed copy, found exactly as the
/// vendor loop finds them: the qualified-aware resolver
/// ([`find_packages_for_rollback_reusing`]), then the npm `package.json`
/// identity lookup for an npm purl it missed (an alias install). `prior`
/// is the loop's own reusable npm crawl, when the caller has it.
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

/// Narrows `refused` (the lock-text refusals of
/// [`vendor::lock_text_refusals`]) to the packages the vendor loop would
/// actually hand to their backend — and so see refused, in these very
/// words — once it has a source for them: an installed copy (`installed`
/// answers, for the purls with no verifiable registry resolution), or a
/// verifiable registry resolution the pristine-source ladder fetches
/// ([`pristine_fetch_is_verifiable`]). A package with neither never
/// reaches its backend: the loop reports it `package_not_installed` (a
/// calm skip), with no pristine fetch, so it is left to the loop and keeps
/// that outcome. The check reads only local files.
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

/// One purl's pristine source while the vendor loop is being assembled.
///
/// A fetched artifact is held by index into the run's `fetched_holders`
/// rather than by path: the tree is not on disk yet (see
/// [`registry_fetch::FetchedPackage`]), and only a backend branch that
/// actually reads it makes it so.
enum StagedSource {
    /// The crawler's installed location.
    Installed(std::path::PathBuf),
    /// `fetched_holders[i]`.
    Fetched(usize),
    /// `deferred_holders[i]`: not downloaded unless a backend reads it.
    Deferred(usize),
}

impl StagedSource {
    fn as_source<'a>(
        &'a self,
        holders: &'a [registry_fetch::FetchedPackage],
        deferred: &'a [DeferredPackage],
    ) -> PackageSource<'a> {
        match self {
            Self::Installed(dir) => PackageSource::Installed(dir),
            Self::Fetched(at) => PackageSource::Pending(&holders[*at]),
            Self::Deferred(at) => PackageSource::Deferred(&deferred[*at]),
        }
    }
}

/// Where a vendorable purl with no installed copy stands after the local
/// rungs of the pristine-source ladder (see [`missing_local_rung`]).
enum MissingRung {
    /// Staged from its own committed artifact (sha256-verified).
    Staged(registry_fetch::FetchedPackage),
    /// Its committed artifact is present but corrupt (the detail).
    StageFailed(String),
    /// `--offline`: no registry rung.
    Offline,
    /// Left for the registry fetch ([`fetch_pristine_package`]).
    Fetch,
    /// The registry fetch, run only if the backend reads the pristine tree
    /// ([`deferred_pristine_package`]).
    Deferred,
    /// A gem a local build cannot vendor from a download: refused before
    /// the fetch.
    GemBuildRefused,
}

impl MissingRung {
    /// Whether this purl still needs [`fetch_pristine_package`] — the one
    /// predicate behind both the fetch plan and the lazy lock inventory,
    /// so they cannot name different purls.
    fn needs_registry(&self) -> bool {
        matches!(self, MissingRung::Fetch)
    }
}

/// The local rungs for one missing purl, deciding without emitting
/// anything: an already-vendored npm purl with no installed copy (fresh
/// clone) stages from its own committed artifact, sha256-verified against
/// the ledger (a vlt directory artifact against its file inventory) —
/// offline-safe, no registry traffic — and `--offline` stops before the
/// registry. Only at the record's own uuid: an older patch's artifact holds
/// that patch's bytes, never a pristine source for a superseding one. Also
/// returns the committed artifact's path when it is missing (the caller's
/// `vendor_artifact_missing` warning; the purl then falls through to the
/// registry ladder).
async fn missing_local_rung(
    common: &GlobalArgs,
    ledger_entry: Option<&VendorEntry>,
    record: Option<&PatchRecord>,
) -> (Option<String>, MissingRung) {
    let mut artifact_missing = None;
    if let Some(entry) = ledger_entry.filter(|e| {
        e.ecosystem == "npm"
            && record.is_some_and(|r| r.uuid == e.uuid)
            && (e.artifact.path.ends_with(".tgz")
                || !vendor::artifact_is_file_shaped(&e.artifact.path))
    }) {
        let committed = common.cwd.join(&entry.artifact.path);
        if tokio::fs::metadata(&committed).await.is_err() {
            artifact_missing = Some(entry.artifact.path.clone());
        } else {
            let staged = if entry.artifact.path.ends_with(".tgz") {
                registry_fetch::stage_local_artifact(&committed, &entry.artifact.sha256).await
            } else {
                registry_fetch::stage_local_dir_artifact(
                    &committed,
                    entry.artifact.file_inventory.as_ref(),
                )
                .await
            };
            match staged {
                Ok(staged) => return (None, MissingRung::Staged(staged)),
                Err(registry_fetch::FetchError::Failed(detail)) => {
                    return (None, MissingRung::StageFailed(detail))
                }
                // No recorded hash (legacy ledger) — fall through to the
                // lockfile/registry path.
                Err(registry_fetch::FetchError::Unverifiable(_)) => {}
            }
        }
    }
    let rung = if common.offline {
        MissingRung::Offline
    } else {
        MissingRung::Fetch
    };
    (artifact_missing, rung)
}

/// Whether the ledger already covers `record` for `entry`'s purl: the entry
/// records this very patch uuid and its committed artifact is on disk — a
/// FILE artifact (wheel, tarball) hashing to the ledger's `sha256`.
/// Read-only, no network. The backend's in-sync hot path answers such a
/// purl from the committed artifact without reading the pristine tree,
/// which is what lets its download be deferred. Some in-sync checks look
/// only for the artifact's presence (pypi's), so a file artifact that no
/// longer hashes to its ledger pin is not covered: it keeps the eager
/// ladder. A copy DIR's integrity stays the backend's own question.
async fn ledger_covers(cwd: &Path, entry: Option<&VendorEntry>, record: &PatchRecord) -> bool {
    match entry {
        Some(entry) if entry.uuid == record.uuid => entry.committed_artifact_intact(cwd).await,
        _ => false,
    }
}

/// The pristine source for a purl whose download is deferred: the same
/// [`fetch_pristine_package`] ladder, run on the first backend call that
/// reads the tree. `--offline` never reaches the registry, so there the
/// deferred fetch reports the offline stop instead. The outcome's `code`
/// tells [`deferred_miss`] which eager-fetch report to reproduce.
fn deferred_pristine_package(
    common: &GlobalArgs,
    inventory: &Arc<tokio::sync::OnceCell<Vec<lock_inventory::LockfileEntry>>>,
    client: &registry_fetch::RegistryClient,
    purl: &str,
    ledger_entry: Option<&VendorEntry>,
) -> DeferredPackage {
    let cwd = common.cwd.clone();
    let offline = common.offline;
    let inventory = Arc::clone(inventory);
    let client = client.clone();
    let owned_purl = purl.to_string();
    let ledger_entry = ledger_entry.cloned();
    DeferredPackage::new(
        &registry_fetch::staged_leaf_for_purl(purl),
        Box::new(move || {
            Box::pin(async move {
                if offline {
                    return Err(DeferredMiss {
                        code: "offline",
                        detail: "--offline prevents fetching the pristine artifact from \
                                 the registry"
                            .to_string(),
                    });
                }
                let inv = inventory
                    .get_or_init(|| lock_inventory::inventory_project(&cwd))
                    .await;
                match fetch_pristine_package(&cwd, inv, &client, &owned_purl, ledger_entry.as_ref())
                    .await
                {
                    PristineFetch::Fetched(fetched) => Ok(fetched),
                    PristineFetch::NoSource => Err(DeferredMiss {
                        code: "no_source",
                        detail: "no installed package found on disk".to_string(),
                    }),
                    PristineFetch::Unverifiable(detail) => Err(DeferredMiss {
                        code: "unverifiable",
                        detail,
                    }),
                    PristineFetch::Failed(detail) => Err(DeferredMiss {
                        code: "failed",
                        detail,
                    }),
                }
            })
        }),
    )
}

/// The `vendor_fetched_missing` advisory for a pristine artifact fetched
/// because the package is not installed.
fn record_fetched_missing(env: &mut Envelope, common: &GlobalArgs, purl: &str, url: &str) {
    record_warning(
        env,
        purl,
        &VendorWarning::new(
            "vendor_fetched_missing",
            format!(
                "{} is not installed; fetched the pristine artifact from {url} (integrity \
                 verified) and vendored from that copy — the project tree was not touched",
                normalize_purl(purl)
            ),
        ),
        common,
    );
}

/// Report a deferred fetch that produced no package exactly as the eager
/// fetch would have reported it for `purl`: a failed download is the same
/// `vendor_fetch_failed` failure (and suppresses the later
/// `package_not_installed` skip for the whole variant group), an
/// unverifiable lock entry the same `vendor_fetch_unverifiable` warning;
/// no source, and the `--offline` stop, say nothing here and leave the
/// candidates to the unmatched pass's `package_not_installed` skip. The
/// caller drops the backend's own outcome — the backend only failed
/// because the tree it asked for never arrived — and un-matches
/// `candidates`.
fn deferred_miss(
    env: &mut Envelope,
    common: &GlobalArgs,
    purl: &str,
    miss: &DeferredMiss,
    candidates: &[String],
    fetch_failed: &mut HashSet<String>,
) {
    match miss.code {
        "unverifiable" => record_warning(
            env,
            purl,
            &VendorWarning::new("vendor_fetch_unverifiable", miss.detail.clone()),
            common,
        ),
        "no_source" | "offline" => {}
        _ => {
            fetch_failed.insert(purl.to_string());
            fetch_failed.extend(candidates.iter().cloned());
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.to_string())
                    .with_error("vendor_fetch_failed", miss.detail.clone()),
            );
            report_vendor_failure(common, purl, &format!("fetch failed: {}", miss.detail));
        }
    }
}

/// The patch-service downloads the vendor loop will make, in the loop's
/// order: `all_packages` walked as the loop walks it — release-variant
/// bases fanned out once to their manifest variants, each variant through
/// the same installed-variant probe — past the Bun refusal and the hosted
/// takeover gate, then through the record's backend gate (see
/// [`vendor::service_preflight`], and npm's one-read
/// [`vendor::npm_flavor::preflight_packages`] with the committed-artifact
/// reuse the npm backends answer from the ledger). Only reads: the probe
/// extracts a fetched artifact the loop's own probe would, and a variant
/// whose probe needs a download not made yet is left out — unplanned, the
/// loop simply fetches it live. Every doubt resolves to "not planned",
/// never to a grant the loop does not ask for.
#[allow(clippy::too_many_arguments)]
async fn plan_service_downloads(
    cwd: &Path,
    force: bool,
    all_packages: &[(String, StagedSource)],
    (fetched_holders, deferred_holders): (&[registry_fetch::FetchedPackage], &[DeferredPackage]),
    variant_groups: &HashMap<String, Vec<String>>,
    records: &HashMap<String, PatchRecord>,
    ledger: &VendorState,
    bun_refusal: Option<&crate::commands::bun_preflight::BunVendorRefusal>,
    takeover_blocked: &dyn Fn(&str) -> bool,
    (pipenv_version, installed_sites): (
        &tokio::sync::OnceCell<Option<u32>>,
        &vendor::pypi::InstalledSiteListings,
    ),
) -> Vec<socket_patch_core::api::client::PlannedDownload> {
    // Each loop candidate that reaches its backend, in loop order.
    let mut reaching: Vec<(&str, &PatchRecord, &Path)> = Vec::new();
    let mut handled_bases: HashSet<String> = HashSet::new();
    for (purl, staged) in all_packages {
        let source = staged.as_source(fetched_holders, deferred_holders);
        let deferred = match staged {
            StagedSource::Deferred(at) => Some(&deferred_holders[*at]),
            _ => None,
        };
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
            // The loop's installed-variant probe (see there).
            let probe_applicable = is_variant_eco
                && !matches!(Ecosystem::from_purl(candidate), Some(Ecosystem::Maven));
            let ledger_answers_probe = deferred.is_some_and(|d| d.outcome().is_none())
                && lookup_entry(&ledger.entries, candidate).is_some_and(|e| e.uuid == record.uuid);
            if probe_applicable && !force && !ledger_answers_probe {
                if let Some((file, info)) = representative_file(&record.files) {
                    if matches!(source, PackageSource::Deferred(_)) {
                        continue;
                    }
                    let Ok(dir) = source.materialize().await else {
                        continue;
                    };
                    let status = verify_file_patch(dir, file, info).await.status;
                    if !variant_matches_installed(Some(&status)) {
                        continue;
                    }
                }
            }
            if bun_refusal.is_some_and(|r| r.applies_to(candidate)) {
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
            reaching.push((candidate.as_str(), record, source.path()));
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
    // Vendoring-service config (`None` = build-only). Both the `vendor`
    // command and `scan --mode vendored` pass `Some(_)`, honoring
    // `--vendor-source`.
    service: Option<&VendorServiceConfig>,
    ledger: std::io::Result<VendorState>,
) -> bool {
    vendor_records_reusing(
        common, records, sources, detached, force, env, service, ledger, None,
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
) -> bool {
    let mut has_errors = false;
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
            StagedSource::Fetched(_) | StagedSource::Deferred(_) => None,
        });

    // ── Auto-fetch: lockfile-resolved packages with no installed copy ────
    // A manifest patch whose package is not on disk but IS resolvable from
    // the project's lockfile is fetched pristine from its registry (lock-
    // recorded URL else the conventional one), verified against the lock's
    // integrity FAIL-CLOSED, and staged from a private tempdir — the
    // project tree is never touched, and the lock wiring works without an
    // installed copy (it keys off lock entries). The holders keep the
    // tempdirs alive until the dispatch loop below has staged from them.
    let mut fetched_holders: Vec<registry_fetch::FetchedPackage> = Vec::new();
    // Sources whose download is deferred to the backend branch that reads
    // them (see the plan below), held by index like `fetched_holders`.
    let mut deferred_holders: Vec<DeferredPackage> = Vec::new();
    // Fetch failures must keep their distinct Failed event; this set
    // suppresses the later duplicate `package_not_installed` skip.
    let mut fetch_failed: HashSet<String> = HashSet::new();
    // The lockfile inventory (every recognized lockfile parsed) — a local
    // read, fine offline — built lazily at the first site that consumes it
    // and shared by the registry-fetch rung below, the deferred fetches and
    // the `--offline` "the lockfile resolves it" detail at the end, so a run
    // parses the lockfiles at most once (and not at all when every missing
    // purl stages from its committed artifact, every deferred source is
    // answered by its backend's hot path, or nothing is missing).
    let inventory: Arc<tokio::sync::OnceCell<Vec<lock_inventory::LockfileEntry>>> =
        Arc::new(tokio::sync::OnceCell::new());
    {
        let missing: Vec<String> = vendorable
            .iter()
            .filter(|p| !all_packages.contains_key(*p))
            .cloned()
            .collect();
        if !missing.is_empty() {
            let client = registry_fetch::build_registry_client();
            // Two passes over `missing`, so the registry fetches can run
            // concurrently while every event, warning and stderr line still
            // lands in `missing` order. Pass 1 decides each purl's local
            // rungs (local and read-only) without emitting anything; the
            // purls left for the registry are then fetched at most
            // `registry_concurrency` at a time, in order, and pass 2 emits
            // every purl's outcome in turn.
            let mut rungs: Vec<(Option<String>, MissingRung)> = {
                let mut rungs = Vec::with_capacity(missing.len());
                for purl in &missing {
                    rungs.push(
                        missing_local_rung(
                            common,
                            lookup_entry(&state.entries, purl),
                            records.get(purl),
                        )
                        .await,
                    );
                }
                rungs
            };
            // Downloads nothing may need, deferred to the backend branch
            // that reads the pristine tree (see `DeferredPackage`):
            //
            //  * a purl the ledger already covers (see `ledger_covers`): the
            //    backend's in-sync hot path answers it from the committed
            //    bytes alone, so a re-run needs no network. `--force` may
            //    rebuild anyway, so it keeps the eager fetch.
            //  * a cargo crate the patch service can serve: the backend reads
            //    the pristine tree only if it falls back to the local build.
            //    Only a crate the registry ladder COULD fetch (see
            //    `pristine_fetch_is_verifiable`) — a git, path or
            //    custom-registry crate keeps the eager rung, whose
            //    `vendor_fetch_unverifiable` refusal keeps a crates.io patch
            //    off it.
            //
            // A backend that does reach its pristine tree fetches it then,
            // through the same ladder, and the loop reports the fetch as the
            // eager one would have (see `deferred_miss`).
            let service_enabled = service.is_some_and(VendorServiceConfig::service_enabled);
            for (purl, (_, rung)) in missing.iter().zip(rungs.iter_mut()) {
                if !matches!(rung, MissingRung::Fetch | MissingRung::Offline) {
                    continue;
                }
                let covered = !force
                    && match records.get(purl) {
                        Some(record) => {
                            ledger_covers(&common.cwd, lookup_entry(&state.entries, purl), record)
                                .await
                        }
                        None => false,
                    };
                let cargo_via_service = service_enabled
                    && matches!(rung, MissingRung::Fetch)
                    && Ecosystem::from_purl(purl) == Some(Ecosystem::Cargo)
                    && pristine_fetch_is_verifiable(
                        &common.cwd,
                        inventory
                            .get_or_init(|| lock_inventory::inventory_project(&common.cwd))
                            .await,
                        purl,
                        lookup_entry(&state.entries, purl),
                    )
                    .await;
                if covered || cargo_via_service {
                    *rung = MissingRung::Deferred;
                }
            }
            // A missing npm or cargo purl its backend refuses on the
            // project's lock text alone (see `vendor::lock_text_refusals`:
            // the pnpm / yarn classic / yarn berry gates, cargo's locked
            // version) is deferred rather than fetched: the backend refuses
            // it — at its turn, in its own words — before anything reads
            // the source, so the refusal costs no registry request. A purl
            // the lockfiles pin hosted keeps the eager fetch: its takeover
            // restores the upstream lock entry first, which rewrites the
            // text the gates read.
            let lock_candidates: Vec<(&str, &str)> = missing
                .iter()
                .zip(&rungs)
                .filter(|(_, (_, rung))| matches!(rung, MissingRung::Fetch))
                .filter_map(|(purl, _)| {
                    records
                        .get(purl)
                        .map(|record| (purl.as_str(), record.uuid.as_str()))
                })
                .filter(|(purl, _)| {
                    matches!(
                        vendor::ecosystem_dir_for_purl(purl),
                        Some("npm") | Some("cargo")
                    )
                })
                .collect();
            if !lock_candidates.is_empty() {
                let claimed: Option<Vec<String>> = Some(
                    socket_patch_core::patch::redirect::upstream::HostedPin::all(
                        &crate::commands::discover_wiring(common, &common.cwd).await,
                    )
                    .into_iter()
                    .map(|pin| canonical_purl(&pin.purl))
                    .collect(),
                );
                if let Some(claimed) = claimed {
                    let unclaimed: Vec<(&str, &str)> = lock_candidates
                        .into_iter()
                        .filter(|(purl, _)| !claimed.contains(&canonical_purl(purl)))
                        .collect();
                    // Only a purl the ladder would really fetch (a
                    // verifiable registry resolution): one with no source
                    // at all keeps the loop's `package_not_installed` skip.
                    // These purls have no installed copy, so none is
                    // looked for.
                    let refused = lock_refusals_reaching_backend(
                        &common.cwd,
                        vendor::lock_text_refusals(&common.cwd, &unclaimed).await,
                        &state.entries,
                        |_| async { HashSet::new() },
                    )
                    .await;
                    for (purl, (_, rung)) in missing.iter().zip(rungs.iter_mut()) {
                        if matches!(rung, MissingRung::Fetch) && refused.contains_key(purl) {
                            *rung = MissingRung::Deferred;
                        }
                    }
                }
            }
            // A NOT-INSTALLED gem can only be vendored through the patch
            // service: the bundler path source needs the eval-able stub
            // gemspec rubygems writes at INSTALL time, which a fetched `.gem`
            // lacks (the service serves a converted `gem-stub-gemspec`).
            // With the service off, refuse `gem_spec_missing` before the
            // download rather than after it; the backend keeps its own
            // refusal as the backstop.
            //
            // Scoped to the purls a DOWNLOAD would actually happen for,
            // mirroring `fetch_pristine_package`'s `fetchable` filter: a gem
            // the lock cannot VERIFY, one the ledger already holds, or one
            // that resolves from nowhere keeps its existing outcome. A dry
            // run keeps the eager fetch: its verify-only preview runs on the
            // fetched copy.
            if !service_enabled
                && !common.dry_run
                && missing
                    .iter()
                    .zip(&rungs)
                    .any(|(p, (_, r))| p.starts_with("pkg:gem/") && r.needs_registry())
            {
                let inv = inventory
                    .get_or_init(|| lock_inventory::inventory_project(&common.cwd))
                    .await;
                for (purl, (_, rung)) in missing.iter().zip(rungs.iter_mut()) {
                    if purl.starts_with("pkg:gem/")
                        && rung.needs_registry()
                        && lookup_entry(&state.entries, purl).is_none()
                        && lock_inventory::lookup(inv, purl)
                            .is_some_and(|e| e.integrity != lock_inventory::LockIntegrity::None)
                    {
                        *rung = MissingRung::GemBuildRefused;
                    }
                }
            }
            // Parsed only when some purl reaches the registry rung.
            let inv: &[lock_inventory::LockfileEntry] =
                if rungs.iter().any(|(_, r)| r.needs_registry()) {
                    inventory
                        .get_or_init(|| lock_inventory::inventory_project(&common.cwd))
                        .await
                } else {
                    &[]
                };
            let (cwd, client_ref, ledger) = (&common.cwd, &client, &state.entries);
            let to_fetch: Vec<&String> = missing
                .iter()
                .zip(&rungs)
                .filter(|(_, (_, rung))| rung.needs_registry())
                .map(|(purl, _)| purl)
                .collect();
            let mut pristine = std::pin::pin!(ordered_concurrent(
                to_fetch,
                registry_concurrency(),
                |purl| fetch_pristine_package(
                    cwd,
                    inv,
                    client_ref,
                    purl,
                    lookup_entry(ledger, purl)
                ),
            ));
            for (purl, (artifact_missing, rung)) in missing.iter().zip(rungs) {
                if let Some(artifact) = artifact_missing {
                    // The committed artifact is GONE (gitignored or
                    // deleted): not corruption — fall through to the
                    // registry ladder, which recovers the pre-vendor
                    // resolution from the ledger and rebuilds.
                    record_warning(
                        env,
                        purl,
                        &VendorWarning::new(
                            "vendor_artifact_missing",
                            format!(
                                "the committed vendored artifact {artifact} is missing; \
                                 recovering the registry resolution to rebuild it"
                            ),
                        ),
                        common,
                    );
                }
                let fetched = match rung {
                    MissingRung::Staged(staged) => {
                        all_packages
                            .insert(purl.clone(), StagedSource::Fetched(fetched_holders.len()));
                        fetched_holders.push(staged);
                        continue;
                    }
                    MissingRung::StageFailed(detail) => {
                        // A PRESENT-but-corrupt committed artifact is
                        // worth a loud failure — silently re-vendoring
                        // over it would mask the corruption.
                        fetch_failed.insert(purl.clone());
                        let detail = format!(
                            "{detail}; run `socket-patch repair` to rebuild the \
                             vendored artifact"
                        );
                        env.record(
                            PatchEvent::new(PatchAction::Failed, purl.clone())
                                .with_error("vendor_fetch_failed", detail.clone()),
                        );
                        report_vendor_failure(common, purl, &detail);
                        continue;
                    }
                    MissingRung::Deferred => {
                        all_packages
                            .insert(purl.clone(), StagedSource::Deferred(deferred_holders.len()));
                        deferred_holders.push(deferred_pristine_package(
                            common,
                            &inventory,
                            &client,
                            purl,
                            lookup_entry(&state.entries, purl),
                        ));
                        continue;
                    }
                    MissingRung::GemBuildRefused => {
                        fetch_failed.insert(purl.clone());
                        // The backend's own refusal text, word for word.
                        let detail = format!(
                            "no local stub gemspec for {} (a path source cannot be wired \
                             without one); install the gem or use --vendor-source=service",
                            strip_purl_qualifiers(purl).trim_start_matches("pkg:gem/")
                        );
                        env.record(
                            PatchEvent::new(PatchAction::Failed, purl.clone())
                                .with_error("gem_spec_missing", detail.clone()),
                        );
                        report_vendor_failure(common, purl, &detail);
                        continue;
                    }
                    // The enriched skip detail lands below in the unmatched
                    // pass (the purl stays unmatched).
                    MissingRung::Offline => continue,
                    MissingRung::Fetch => match pristine.next().await {
                        Some(fetched) => fetched,
                        // Unreachable: `to_fetch` holds one fetch per
                        // `needs_registry` rung, and this is the only arm
                        // that consumes one. A live fetch keeps the outcome
                        // right if the two ever fall out of step.
                        None => {
                            debug_assert!(false, "pristine prefetch plan out of step at {purl}");
                            fetch_pristine_package(
                                cwd,
                                inv,
                                client_ref,
                                purl,
                                lookup_entry(ledger, purl),
                            )
                            .await
                        }
                    },
                };
                match fetched {
                    PristineFetch::Fetched(fetched) => {
                        record_fetched_missing(env, common, purl, &fetched.url);
                        all_packages
                            .insert(purl.clone(), StagedSource::Fetched(fetched_holders.len()));
                        fetched_holders.push(fetched);
                    }
                    PristineFetch::NoSource => {
                        // Plain not-installed package → the calm
                        // package_not_installed skip below.
                    }
                    PristineFetch::Unverifiable(detail) => {
                        record_warning(
                            env,
                            purl,
                            &VendorWarning::new("vendor_fetch_unverifiable", detail),
                            common,
                        );
                        // Falls through to package_not_installed below.
                    }
                    PristineFetch::Failed(detail) => {
                        fetch_failed.insert(purl.clone());
                        env.record(
                            PatchEvent::new(PatchAction::Failed, purl.clone())
                                .with_error("vendor_fetch_failed", detail.clone()),
                        );
                        report_vendor_failure(common, purl, &format!("fetch failed: {detail}"));
                    }
                }
            }
        }
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
            .find(|pin| canonical_purl(&pin.purl) == canonical_purl(purl))
    };

    // Yarn berry takeover preflight (see
    // `socket_patch_core::vendor::yarn_berry_vendor_preflight`): the berry
    // backend's project-level refusals (mixed line endings in yarn.lock or
    // package.json, cacheKey, `.yarnrc.yml` compressionLevel), computed at
    // most once per run and only when a hosted-claimed npm purl reaches the
    // takeover below, which must refuse such a purl BEFORE reverting its
    // hosted edits.
    let berry_takeover_refusal: tokio::sync::OnceCell<Option<(&'static str, String)>> =
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
                (&fetched_holders, &deferred_holders),
                &variant_groups,
                records,
                &state,
                bun_refusal.as_ref(),
                &takeover_blocked,
                (&pipenv_version, &installed_sites),
            )
            .await;
            cfg.prefetch_archives(planned)
        }
        None => None,
    };
    // The source of the purl the loop has just left. Its archive is what a
    // fetched source holds to be able to write its tree, and `all_packages`
    // gives each holder to exactly one purl — so once the loop moves on,
    // nothing reads it again, and a run that fetched 110 artifacts need not
    // carry all 110 to the end of the loop.
    let mut spent: Option<PackageSource<'_>> = None;
    // Deferred sources whose fetch the loop has already reported.
    let mut deferred_fetch_reported: HashSet<String> = HashSet::new();
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
    for (index, (purl, staged)) in all_packages.iter().enumerate() {
        if let Some(done) = spent.take() {
            done.release();
        }
        let pkg_source = staged.as_source(&fetched_holders, &deferred_holders);
        let deferred = match staged {
            StagedSource::Deferred(at) => Some(&deferred_holders[*at]),
            _ => None,
        };
        spent = Some(pkg_source);
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
            let ledger_answers_probe = deferred.is_some_and(|d| d.outcome().is_none())
                && lookup_entry(&state.entries, candidate).is_some_and(|e| e.uuid == record.uuid);
            if probe_applicable && !force && !ledger_answers_probe {
                // The representative must be a file that MODIFIES existing
                // content: a new file (empty beforeHash) verifies `Ready`
                // against any environment, so it can neither identify nor
                // disqualify a variant. Same deterministic pick as apply /
                // core's `select_installed_variants`.
                let first = match representative_file(&record.files) {
                    Some((f, info)) => match pkg_source.materialize().await {
                        Ok(dir) => Some(verify_file_patch(dir, f, info).await.status),
                        // A deferred download that produced nothing is
                        // reported as the eager fetch would have reported it.
                        Err(_) if deferred.is_some_and(|d| matches!(d.outcome(), Some(Err(_)))) => {
                            if let Some(Some(Err(miss))) = deferred.map(DeferredPackage::outcome) {
                                deferred_miss(
                                    env,
                                    common,
                                    purl,
                                    miss,
                                    &candidates,
                                    &mut fetch_failed,
                                );
                            }
                            break;
                        }
                        // Not a variant verdict: the tree could not be
                        // WRITTEN at all (full `$TMPDIR`, no fds). Report one
                        // failure for the SOURCE purl rather than filing it
                        // under `package_not_installed` and losing the cause.
                        Err(detail) => {
                            env.record(
                                PatchEvent::new(PatchAction::Failed, purl.clone())
                                    .with_error("vendor_fetch_failed", detail.clone()),
                            );
                            report_vendor_failure(common, purl, &format!("fetch failed: {detail}"));
                            fetch_failed.insert(purl.clone());
                            fetch_failed.extend(candidates.iter().cloned());
                            break;
                        }
                    },
                    None => None,
                };
                if !variant_matches_installed(first.as_ref()) {
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
            if let Some(pin) = hosted_pin_of(candidate) {
                // The refusal the berry backend would raise after the
                // restore, raised HERE instead — the same `failed` event,
                // code and detail, in the dry run and the wet run alike —
                // so the hosted wiring stays untouched.
                if candidate.starts_with("pkg:npm/") {
                    let refusal = berry_takeover_refusal
                        .get_or_init(|| {
                            socket_patch_core::vendor::yarn_berry_vendor_preflight(&common.cwd)
                        })
                        .await;
                    if let Some((code, detail)) = refusal {
                        has_errors = true;
                        env.record(
                            PatchEvent::new(PatchAction::Failed, candidate.clone())
                                .with_error(*code, detail.clone()),
                        );
                        report_vendor_failure(common, candidate, detail);
                        continue;
                    }
                }
                let origins = crate::commands::rollback::patch_server_origins(common);
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
                let restore = socket_patch_core::patch::redirect::upstream::restore_upstream(
                    &common.cwd,
                    std::slice::from_ref(pin),
                    &socket_patch_core::patch::redirect::upstream::RestoreOptions {
                        dry_run: common.dry_run,
                        offline: common.offline,
                        patch_server_origins: origins,
                        bun_lockb: true,
                    },
                )
                .await;
                let refusal = restore
                    .refused()
                    .map(|(_, why)| why.to_string())
                    .next()
                    .or_else(|| restore.flush_error.clone());
                if let Some(detail) = refusal {
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
                for (code, detail) in &restore.warnings {
                    record_warning(env, candidate, &VendorWarning::new(code, detail.clone()), common);
                }
                if common.dry_run {
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
                    if restore
                        .reverted_files
                        .iter()
                        .any(|f| f == "bun.lock" || f == "bun.lockb")
                    {
                        continue;
                    }
                } else {
                    if !targets.is_empty() {
                        vlt_takeover_targets.insert(candidate.clone(), targets);
                    }
                    record_warning(
                        env,
                        candidate,
                        &VendorWarning::new(
                            "vendor_takeover_reverted_redirect",
                            format!(
                                "{} was hosted; restored its upstream registry entry ({}) \
                                 before vendoring (mode takeover)",
                                normalize_purl(candidate),
                                restore.reverted_files.join(", ")
                            ),
                        ),
                        common,
                    );
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
                pkg_source,
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

            // A deferred source whose backend needed the pristine tree after
            // all fetched it inside the call. Report that fetch as the eager
            // ladder did — ahead of this package's own outcome — once per
            // source; a fetch that produced nothing replaces the outcome.
            if let Some(fetch) = deferred.and_then(DeferredPackage::outcome) {
                match fetch {
                    Ok(fetched) => {
                        if deferred_fetch_reported.insert(purl.clone()) {
                            record_fetched_missing(env, common, purl, &fetched.url);
                        }
                    }
                    Err(miss) => {
                        deferred_miss(env, common, purl, miss, &candidates, &mut fetch_failed);
                        for c in &candidates {
                            matched.remove(c);
                        }
                        break;
                    }
                }
            }

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
                    if common.dry_run
                        && event.action == PatchAction::Verified
                        && lookup_entry(&state.entries, candidate)
                            .is_some_and(|e| e.uuid == record.uuid)
                    {
                        dry_in_sync += 1;
                    }
                    let in_sync = event.error_code.as_deref() == Some("already_vendored");
                    env.record(event);
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
                    crate::commands::scan::vlt_takeover_heal(common, &targets).await
                } else {
                    crate::commands::scan::vlt_rollback_heal(common, &targets)
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

    // Every backend has staged what it needed, so the fetch tempdirs can
    // go. Dropping them removes whatever was extracted into them — a
    // recursive delete that belongs off the runtime thread.
    if !fetched_holders.is_empty() || !deferred_holders.is_empty() {
        let _ =
            tokio::task::spawn_blocking(move || drop((fetched_holders, deferred_holders))).await;
    }

    // The run's one commit of every lockfile, manifest, config and ledger
    // the loop changed. The packages that succeeded are committed even when
    // others failed — a failed package's backend already put back what it
    // had touched, in the captured state — so a completed run ends exactly
    // where committing after every package would have left it.
    if let Some(group) = group {
        socket_patch_core::utils::failpoint::hit("vendor_group_commit");
        match group.commit().await {
            Ok(_) => {
                for stale in stale_artifacts {
                    sweep_stale_artifact(common, env, &state, stale).await;
                }
            }
            Err(e) => {
                has_errors = true;
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
                    format!(
                        "could not commit the vendored lockfile, manifest and ledger edits: \
                         {e}; the project's lockfiles and .socket/vendor/state.json are \
                         unchanged"
                    )
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
    let vendored_bases: HashSet<String> = matched
        .iter()
        .map(|p| strip_purl_qualifiers(p).to_string())
        .collect();
    unmatched.retain(|p| !vendored_bases.contains(strip_purl_qualifiers(p)));
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

    if !common.json && !common.silent {
        let tally = VendorTally::from_envelope(env, common.dry_run, dry_in_sync);
        println!("{}", format_vendor_summary(common.dry_run, &tally));
        if env.summary.applied > 0 && !common.dry_run {
            // pnpm >=11 reads `overrides` ONLY from pnpm-workspace.yaml (the
            // package.json `pnpm.overrides` mirror is ignored), so pnpm-wired
            // runs must name that file among the committables: a checkout
            // that loses it silently unvendors on the next install.
            let commit = if wired_flavors.contains("pnpm") {
                ".socket/vendor/, package.json, pnpm-lock.yaml, and pnpm-workspace.yaml to \
                 make the patches portable (pnpm >=11 reads the vendored override only from \
                 pnpm-workspace.yaml)"
            } else if wired_flavors.contains("vlt") {
                VLT_COMMIT_HINT
            } else {
                ".socket/vendor/ and the updated lockfiles to make the patches portable"
            };
            let mut installs: Vec<&str> = wired_flavors
                .iter()
                .filter_map(|f| flavor_install_command(f))
                .collect();
            installs.sort_unstable();
            installs.dedup();
            let reinstall = if installs.is_empty() {
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
            for line in crate::ui::next_steps(commit, &reinstall, &extra) {
                println!("{line}");
            }
        }
    }

    has_errors
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
        _ => None,
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
        .revert(&recorded, &mut state, RevertOpts::new(common.dry_run), false)
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
        let reverted: HashSet<String> = env
            .events
            .iter()
            .filter(|e| e.action == PatchAction::Removed)
            .filter_map(|e| e.purl.as_deref().map(canonical_purl))
            .collect();
        let rehosted: Vec<HostedPin> =
            HostedPin::all(&crate::commands::discover_wiring(common, &common.cwd).await)
                .into_iter()
                .filter(|pin| reverted.contains(&canonical_purl(&pin.purl)))
                .collect();
        if !rehosted.is_empty() {
            let leg = crate::commands::rollback::run_hosted_leg(common, &rehosted).await;
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
            for (code, detail) in &leg.warnings {
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
                .filter_map(|f| flavor_install_command(f))
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
}

/// The vendored-state GC behind `scan --prune`:
///
/// (a) revert entries whose patch was dropped from the manifest (same
///     stale test as [`reconcile_dropped`], shared with the vendor flows);
/// (b) revert entries whose dependency is no longer in the lockfile graph
///     ([`dispatch_in_use_one`] == `Some(false)`; `None` keeps, fail-safe)
///     and drop their manifest entries so the caller's manifest prune +
///     blob sweep reclaims the rest in the same pass;
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

    // (b) lockfile-unused entries — detached ones included: the probe asks
    // the live lockfile wiring, which a detached entry has like any other.
    let mut manifest_dirty = false;
    let candidates: Vec<String> = state
        .entries
        .iter()
        .filter(|(purl, entry)| {
            ecosystem_in_scope(common, &entry.ecosystem) && !handled_by_a.contains(*purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect();
    for purl in candidates {
        let entry = state.entries.get(&purl).cloned().expect("listed above");
        if dispatch_in_use_one(&entry, &common.cwd).await != Some(false) {
            continue; // in use, or cannot determine — keep
        }
        if dry_run {
            out.unused_reverted.push(purl);
            continue;
        }
        let outcome = dispatch_revert_one(&entry, &common.cwd, false).await;
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
            let base = strip_purl_qualifiers(&entry.base_purl).to_string();
            let dropped: Vec<String> = m
                .patches
                .keys()
                .filter(|k| *k == &purl || strip_purl_qualifiers(k) == base)
                .cloned()
                .collect();
            for k in dropped {
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
            diffs_path: None,
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
            ("pkg:composer/psr/http-message@1.1.0", "psr/http-message", UUID_B),
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
            (&[], &[]),
            &HashMap::new(),
            &records,
            &VendorState::default(),
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
            diffs_path: None,
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
            diffs_path: None,
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
            ecosystem: "npm".into(),
            base_purl: PURL.into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached,
            record: None,
            flavor: Some("package-lock".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
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
                "{{\"packages\":{{\"node_modules/left-pad\":{{\"resolved\":\"file:.socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz\"}}}}}}"
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
        assert_eq!(out.orphan_dirs, 0);
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

    /// A vendored CARGO entry displaced by a hosted takeover (its lock entry
    /// re-sourced to a socket-patch sparse index) is reclaimable by the GC
    /// through `dispatch_in_use_one`'s cargo probe, which drops the
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
}

#[cfg(test)]
mod revert_dispatch_tests {
    use super::*;
    use socket_patch_core::vendor::state::VendorArtifact;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn entry_for(eco: &str, base_purl: &str) -> VendorEntry {
        VendorEntry {
            ecosystem: eco.into(),
            base_purl: base_purl.into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/{eco}/{UUID}/artifact"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: None,
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
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

    /// [`dispatch_in_use_one`]'s fail-safe arm: every ecosystem without an
    /// in-use probe (everything but npm/cargo) reports `None` — "cannot
    /// determine" — which all callers must treat as KEEP.
    #[tokio::test]
    async fn in_use_probe_is_none_for_unprobed_ecosystems() {
        let tmp = tempfile::tempdir().unwrap();
        for (eco, purl) in [
            ("gem", "pkg:gem/rails@6.0.3"),
            ("pypi", "pkg:pypi/foo@1.0.0"),
            ("frobnicate", "pkg:frobnicate/x@1.0.0"),
        ] {
            assert_eq!(
                dispatch_in_use_one(&entry_for(eco, purl), tmp.path()).await,
                None,
                "`{eco}` has no in-use probe — must report undeterminable (keep)"
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
            ecosystem: "npm".into(),
            base_purl: base_purl.into(),
            uuid: uuid.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/npm/{uuid}/pkg.tgz"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("package-lock".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
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

#[cfg(test)]
mod pristine_fetch_tests {
    use super::*;

    /// No lockfile entry AND no ledger entry: the pristine-source ladder
    /// reports `NoSource` (the calm `package_not_installed` path) BEFORE any
    /// network I/O — nothing else can name a verifiable source.
    #[tokio::test]
    async fn no_lock_and_no_ledger_is_no_source() {
        let tmp = tempfile::tempdir().unwrap();
        let client = registry_fetch::build_registry_client();
        let out =
            fetch_pristine_package(tmp.path(), &[], &client, "pkg:npm/left-pad@1.3.0", None).await;
        assert!(
            matches!(out, PristineFetch::NoSource),
            "expected NoSource for a purl with no lock and no ledger entry"
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
    fn revert_install_hint_names_the_command() {
        assert_eq!(
            format_revert_install_hint("npm install"),
            "Run `npm install` to resync the installed tree with the restored lockfile (it \
             may still hold the vendored bytes if you reinstalled after vendoring)."
        );
    }
}
