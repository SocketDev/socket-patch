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
//! The rest of the CLI is vendor-aware: `apply`/`rollback` yield ownership of
//! ledger-recorded purls, `remove` reverts vendoring as part of removing a
//! patch, `scan --prune` exempts vendored entries, and `scan --vendor`
//! drives this module's [`vendor_records`] engine directly (optionally
//! `--detached`, writing ledger entries with embedded patch records instead
//! of manifest entries). See CLI_CONTRACT.md "Ownership, state, and
//! reversal".

use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::{verify_file_patch, PatchSources};
use socket_patch_core::patch::copy_tree::remove_tree;
use socket_patch_core::telemetry::{track_patch_vendor_failed, track_patch_vendored};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::vendor::{
    self, ecosystem_dir_for_purl, load_state, lock_inventory, lookup_entry, registry_fetch,
    save_state, RevertOpts, RevertOutcome, VendorEntry, VendorOutcome, VendorServiceConfig,
    VendorSource, VendorState, VendorWarning,
};
use socket_patch_core::vex::time::now_rfc3339;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::apply::{representative_file, result_to_event, variant_matches_installed};
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::lock_cli::acquire_or_emit;
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::{find_packages_for_rollback, partition_purls};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, RunWarning, Status, VexSummary,
};

#[derive(Args)]
pub struct VendorArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Tolerate MISSING patch-target files in the staged copy (they are
    /// skipped instead of failing the vendor) and bypass the variant
    /// probe for multi-release ecosystems. A plain beforeHash mismatch
    /// no longer needs this: vendor staging always overwrites mismatched
    /// content with the verified patched bytes (surfaced as a
    /// `vendor_content_mismatch_overwritten` warning).
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
/// otherwise). Returns `None` for purls with no vendor backend in this build.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn dispatch_vendor_one(
    purl: &str,
    pkg_path: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    // The patch.socket.dev vendoring-service config. `None` = build-only (the
    // pre-service behavior); used by the `vendor` command, `None` from `scan
    // --vendor` / repair. Per-ecosystem backends consume it as they gain a
    // service path.
    service: Option<&VendorServiceConfig>,
) -> Option<VendorOutcome> {
    let eco = ecosystem_dir_for_purl(purl)?;

    // Prebuilt service downloads now cover every vendorable ecosystem: npm,
    // pypi, cargo, golang, composer, gem, nuget, and maven. Gem's `.gem`
    // archive doesn't carry the eval-able stub gemspec a bundler path source
    // wants, so the converter generates it and serves it as a
    // `gem-stub-gemspec` second artifact alongside the `.gem` (the gem backend
    // downloads + verifies both).
    // Under fail-closed `service` mode, refuse any not-covered ecosystem with a
    // clear message rather than silently building (which would violate the
    // contract). Under `auto`/`build` they fall through to the local build.
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
    // Every backend takes the identical 9-argument tuple; the macro keeps
    // the per-arm #[cfg] while collapsing the eight-way repetition.
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
    Some(match eco {
        // The flavor router probes the project's lockfile (package-lock /
        // yarn / pnpm / bun) and dispatches or refuses per flavor.
        "npm" => vend!(vendor::npm_flavor::vendor_npm_any),
        "pypi" => vend!(vendor::pypi::vendor_pypi),
        "gem" => vend!(vendor::gem::vendor_gem),
        "cargo" => vend!(vendor::cargo::vendor_cargo_crate),
        "golang" => vend!(vendor::golang::vendor_go_module),
        "composer" => vend!(vendor::composer_lock::vendor_composer),
        "nuget" => vend!(vendor::nuget_feed::vendor_nuget),
        "maven" => vend!(vendor::maven_repo::vendor_maven),
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
/// entry (fail-safe): non-npm ecosystems have no in-use probe yet, and a
/// missing/unreadable lockfile proves nothing.
async fn dispatch_in_use_one(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    match entry.ecosystem.as_str() {
        "npm" => vendor::npm_flavor::vendored_entry_in_use(entry, project_root).await,
        // Cargo probes the lock entry's shape: detached + `[patch]` pointing
        // at this entry's copy = in use; a registry source (crates.io
        // re-resolve or a hosted takeover) or a missing entry = reclaimable
        // (the revert restores / keeps the registry resolution and drops the
        // dead wiring). Without this, a vendored entry displaced by a hosted
        // takeover survives every `scan --prune` forever.
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
/// A missing ledger entry does NOT prove missing wiring: `repair`
/// reconstructs entries from lockfiles that still point into
/// `.socket/vendor/` precisely because that state occurs (a deleted
/// state.json, a partial commit). Deleting such a dir would break the next
/// install, so every candidate is checked against the wiring-bearing files
/// first — the same lockfile scan `repair` reconstructs from — and a
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
        crate::commands::repair_vendor::scan_vendor_references(cwd)
            .await
            .into_iter()
            .map(|(eco, uuid, _path)| (eco, uuid))
            .collect();
    for unit in candidates {
        if wired.contains(&(unit.eco.clone(), unit.uuid.clone())) {
            out.still_wired.push(unit);
            continue;
        }
        if !dry_run {
            let _ = remove_tree(&unit.dir).await;
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
    match common.ecosystems.as_deref() {
        None => true,
        Some(list) => list.iter().any(|e| {
            e.eq_ignore_ascii_case(eco) || (eco == "golang" && e.eq_ignore_ascii_case("go"))
        }),
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
/// bump `summary.skipped`. That counter must report packages that were
/// genuinely skipped, not the number of advisory events — routing every
/// warning through `record` made a single SUCCESSFUL service vendor report
/// `applied:1 skipped:1`, let a 1-package project print "2 skipped", and
/// counted "1 skipped" on a refresh that skipped nothing. `Skipped` never
/// flips the run status, so pushing it directly loses no status signal.
pub(crate) fn record_warning(
    env: &mut Envelope,
    purl: &str,
    warning: &VendorWarning,
    common: &GlobalArgs,
) {
    if !common.silent && !common.json {
        eprintln!("Warning ({}): {}", warning.code, warning.detail);
    }
    env.events.push(
        PatchEvent::new(PatchAction::Skipped, purl.to_string())
            .with_reason(warning.code, warning.detail.clone()),
    );
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
        eprintln!("Warning ({}): {}", w.code, w.detail);
    }
    env.warnings.push(RunWarning {
        code: w.code.to_string(),
        detail: w.detail,
    });
}

pub async fn run(args: VendorArgs) -> i32 {
    apply_env_toggles(&args.common);
    let (telemetry_client, use_public_proxy) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    // Vendoring-service config, built once from the run-level client + flags.
    // `vendor_source` was validated by clap, so the parse cannot fail; fall
    // back to the `auto` default defensively. The same client is reused for
    // the package-reference request (no second auth round-trip).
    let vendor_service = VendorServiceConfig {
        source: VendorSource::parse(&args.common.vendor_source).unwrap_or_default(),
        client: Some(telemetry_client.clone()),
        use_public_proxy,
        vendor_url: args.common.vendor_url.clone(),
        patch_server_url: args.common.patch_server_url.clone(),
        offline: args.common.offline,
    };

    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // `--revert` derives everything from state.json + the vendor tree; it
    // must work after the manifest was deleted. Plain vendor needs the
    // manifest and exits clean without one (same contract as apply).
    if !args.revert && tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.common.json {
            let mut env = Envelope::new(Command::Vendor);
            env.status = Status::NoManifest;
            env.dry_run = args.common.dry_run;
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("No .socket folder found, nothing to vendor.");
        }
        return 0;
    }

    // Same lock as apply/rollback: vendor mutates the same lockfiles and
    // `.socket/` tree, so a separate lock would allow an apply↔vendor race.
    //
    // The lock file lives INSIDE `.socket/`, and `acquire` creates the file
    // but never its parent. `--revert` skipped the manifest check above, so
    // it is the one path that can reach here with no `.socket/` dir at all —
    // the documented clean no-op ("a missing ledger is an empty ledger").
    // Locking first would turn that into a `lock_io` failure, so skip it:
    // with no `.socket/` there is no ledger to read and nothing to write,
    // hence nothing to serialize against.
    let _lock = if args.revert && tokio::fs::metadata(&socket_dir).await.is_err() {
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

    let mut exit = if args.revert {
        run_revert(&args, &mut env).await
    } else {
        run_vendor(&args, &manifest_path, &mut env, &vendor_service).await
    };

    // Embedded VEX: same contract as `apply --vex` — only on success, and a
    // requested-but-failed VEX flips the exit code. A dry run vendors
    // nothing, so there is no vendored state to attest: generating here
    // would verify the deliberately untouched tree, spuriously fail the
    // whole command with `no_applicable_patches`, and write an attestation
    // file during --dry-run. Skip instead.
    if exit == 0 && !args.revert {
        if let Some(vex_path) = args.vex.vex.as_ref() {
            if args.common.dry_run {
                if !args.common.json && !args.common.silent {
                    println!("Skipping VEX generation (--dry-run: nothing was vendored).");
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
                        env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                        // The envelope only prints under --json; in human mode
                        // this error is the sole explanation for the flipped
                        // exit code, so it prints even under --silent ("errors
                        // only", never "nothing").
                        if !args.common.json {
                            eprintln!("Error: VEX generation failed: {}", e.message);
                        }
                        exit = 1;
                    }
                }
            }
        }
    }

    note_classic_migration_risk(&mut env, &args.common.cwd, &args.common);
    // Same cross-mode takeover advisory the scan-driven vendored flow emits:
    // the standalone `vendor` command is the PRIMARY hosted→vendored
    // migration entry point, so it must surface a redirect ledger that this
    // run (or an earlier one) superseded — silence here left the stale
    // ledger feeding VEX indefinitely.
    super::scan::note_vendor_supersedes_redirect(&mut env, &args.common.cwd, &args.common).await;

    if args.common.json {
        println!("{}", env.to_pretty_json());
    }

    if !args.revert {
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

/// Telemetry for a vendor run's success/failure split, shared by
/// [`run`] and the scan-driven vendor step (`scan --vendor`).
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
            if !common.json && !common.silent {
                eprintln!("Error: could not read manifest: {e}");
            }
            return 1;
        }
    };

    // Reconcile first (mirrors apply's placement): entries vendored by a
    // previous run whose patches were dropped from the manifest are reverted
    // even when zero in-scope patches remain.
    let mut has_errors = reconcile_dropped(&manifest, common, env).await;

    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    // Vendor stages patch content IN MEMORY: existing .socket artifacts are
    // read in place, missing content is fetched per patch — vendoring never
    // writes blobs or temp files (the committed artifact is the patch).
    let staged =
        match stage_vendor_sources_in_memory(common, &manifest, socket_dir, &common.cwd).await {
            MemStageOutcome::Ready(s) => s,
            MemStageOutcome::Unavailable => {
                env.mark_error(EnvelopeError::new(
                    "no_local_source",
                    "patch artifacts unavailable (offline or download failure)",
                ));
                return 1;
            }
        };
    let sources = staged.as_patch_sources();

    has_errors |= vendor_records(
        common,
        &manifest.patches,
        &sources,
        false,
        args.force,
        env,
        Some(service),
    )
    .await;

    if has_errors {
        // A run where EVERY event failed still reads as "partialFailure":
        // the envelope has no "completed with zero successes" status, and
        // status=error is reserved for pre-event failures (it implies a
        // top-level error payload and empty events[] — see json_envelope.rs).
        // Escalating here without an envelope-level API broke that contract,
        // and scan --vendor / vendor --revert report the same outcome as
        // partialFailure, so this stays aligned with them.
        env.mark_partial_failure();
        1
    } else {
        0
    }
}

/// Persist one backend-returned ledger entry: detached flagging, wiring
/// `original` carry-forward from the entry being replaced, per-package save
/// (crash-consistent with what is already wired), and the stale-uuid-dir
/// sweep on re-vendors. Returns `true` when the save failed (has_errors).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn persist_vendor_entry(
    common: &GlobalArgs,
    env: &mut Envelope,
    state: &mut VendorState,
    candidate: &str,
    mut entry: VendorEntry,
    detached: bool,
    record: &PatchRecord,
) -> bool {
    let mut has_errors = false;
    let candidate = candidate.to_string();
    entry.detached = detached;
    entry.record = detached.then(|| record.clone());
    // A re-vendor run re-derives the entry from current disk state, where
    // the takeover / earlier wiring already happened. Reconcile the fresh
    // entry with the one it replaces so `--revert` still knows how to undo
    // every surface any earlier vendoring touched: carry forward the true
    // pre-vendor originals (a re-vendor records `original: None` for its own
    // stale `.socket/vendor/` pointer), the wiring records for surfaces this
    // run left in sync (e.g. package.json + pnpm-lock.yaml when only the new
    // pnpm-workspace.yaml override was added on a pnpm >= 11 upgrade), the
    // pnpm created-surface bookkeeping, the cargo lock originals, and the
    // takeover flag. See [`vendor::carry_forward_wiring`].
    let prev = state.entries.get(&candidate).cloned();
    if let Some(prev) = &prev {
        vendor::carry_forward_wiring(prev, &mut entry);
    }
    let new_uuid = entry.uuid.clone();
    state.entries.insert(candidate.clone(), entry);
    // Persist per-package so a crash mid-run leaves a
    // ledger that matches what's already wired.
    if let Err(e) = save_state(&common.cwd, state).await {
        has_errors = true;
        env.record(
            PatchEvent::new(PatchAction::Failed, candidate.clone())
                .with_error("vendor_state_write_failed", e.to_string()),
        );
    } else if let Some(prev) = prev.filter(|p| p.uuid != new_uuid) {
        // Re-vendor under a newer patch uuid: the old
        // uuid's dir is an orphan now — the wiring and
        // ledger both point at the new uuid — unless
        // another entry still shares it (the same
        // `(eco, uuid)` ownership test as `--revert`'s
        // orphan sweep). Only the live entry would
        // otherwise reclaim it, and that never happens.
        let still_referenced = state
            .entries
            .values()
            .any(|e| e.ecosystem == prev.ecosystem && e.uuid == prev.uuid);
        let stale_rel = vendor::path::vendor_uuid_dir_rel(&prev.ecosystem, &prev.uuid);
        if let Some(rel) = stale_rel.filter(|_| !still_referenced) {
            if !common.dry_run {
                let _ = remove_tree(&common.cwd.join(rel)).await;
            }
            env.record(
                PatchEvent::new(PatchAction::Removed, candidate.clone()).with_reason(
                    "vendor_stale_artifact_removed",
                    "previous patch uuid's vendored artifact removed",
                ),
            );
        }
    }
    has_errors
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
    let entry = match lock_inventory::lookup(inventory, purl) {
        Some(e) => e.clone(),
        None => {
            let Some(le) = ledger_entry else {
                return PristineFetch::NoSource;
            };
            match lock_inventory::recover_lock_entry(project_root, le).await {
                Ok(rec) => rec,
                Err(e) => {
                    return PristineFetch::Unverifiable(format!(
                        "the lockfile no longer records a registry resolution for {purl} \
                         (rewired to the vendored artifact) and the ledger cannot recover \
                         one: {e}"
                    ))
                }
            }
        }
    };
    match registry_fetch::fetch_and_stage(&entry, client).await {
        Ok(fetched) => PristineFetch::Fetched(fetched),
        Err(registry_fetch::FetchError::Unverifiable(d)) => PristineFetch::Unverifiable(d),
        Err(registry_fetch::FetchError::Failed(d)) => PristineFetch::Failed(d),
    }
}

/// The vendoring engine, decoupled from the manifest file. `records` is the
/// purl → [`PatchRecord`] view to vendor: `manifest.patches` for the
/// manifest-driven `vendor` command (and `scan --vendor`), or the
/// freshly-fetched record map for `scan --vendor --detached`. Entries written
/// in `detached` mode carry [`VendorEntry::detached`] plus an embedded copy
/// of their record, so revert/verify/VEX work without a manifest entry.
///
/// Does NOT lock, read the manifest, or print the envelope — callers own all
/// three. Returns whether any non-benign failure occurred.
pub(crate) async fn vendor_records(
    common: &GlobalArgs,
    records: &HashMap<String, PatchRecord>,
    sources: &PatchSources<'_>,
    detached: bool,
    force: bool,
    env: &mut Envelope,
    // Vendoring-service config (`None` = build-only). Both the `vendor`
    // command and `scan --vendor` pass `Some(_)`, honoring `--vendor-source`.
    service: Option<&VendorServiceConfig>,
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

    if vendorable.is_empty() {
        if !common.json && !common.silent {
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

    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    };
    // Resolve installed packages with the qualified-purl-aware resolver, NOT
    // `find_packages_for_purls`: the manifest keys release-variant ecosystems
    // (gem `?platform=`, pypi `?artifact_id=`, maven `?classifier=&ext=`) by
    // *qualified* purls, but the crawler only knows the *base* purl.
    // `find_packages_for_purls` keys the result map by the base purl, so the
    // `missing`/`contains_key` check below would miss every installed
    // qualified-purl package and falsely classify it "not installed" —
    // triggering a spurious `vendor_fetched_missing`, a redundant per-run
    // registry download, and (for gem) a HashMap-order platform coin-flip.
    // The rollback variant fans each base path back out to every qualified
    // manifest purl (same invariant as `find_manifest_package_paths`).
    let mut all_packages = find_packages_for_rollback(
        &vendorable_partition,
        &crawler_options,
        common.silent || common.json,
    )
    .await;

    // ── Auto-fetch: lockfile-resolved packages with no installed copy ────
    // A manifest patch whose package is not on disk but IS resolvable from
    // the project's lockfile is fetched pristine from its registry (lock-
    // recorded URL else the conventional one), verified against the lock's
    // integrity FAIL-CLOSED, and staged from a private tempdir — the
    // project tree is never touched, and the lock wiring works without an
    // installed copy (it keys off lock entries). The holders keep the
    // tempdirs alive until the dispatch loop below has staged from them.
    let mut fetched_holders: Vec<registry_fetch::FetchedPackage> = Vec::new();
    // Fetch failures must keep their distinct Failed event; this set
    // suppresses the later duplicate `package_not_installed` skip.
    let mut fetch_failed: HashSet<String> = HashSet::new();
    {
        let missing: Vec<String> = vendorable
            .iter()
            .filter(|p| !all_packages.contains_key(*p))
            .cloned()
            .collect();
        if !missing.is_empty() {
            // The inventory is a local file read — fine offline; only the
            // fetch itself needs the network.
            let inventory = lock_inventory::inventory_project(&common.cwd).await;
            let client = registry_fetch::build_registry_client();
            // Pre-loaded vendor ledger for the artifact-staging path: an
            // already-vendored purl with no installed copy (fresh clone)
            // stages from its own committed artifact, sha256-verified
            // against the ledger — offline-safe, no registry traffic.
            let ledger = load_state(&common.cwd).await.unwrap_or_default();
            for purl in &missing {
                let ledger_entry = lookup_entry(&ledger.entries, purl);
                if let Some(entry) = ledger_entry
                    .filter(|e| e.ecosystem == "npm" && e.artifact.path.ends_with(".tgz"))
                {
                    let tgz = common.cwd.join(&entry.artifact.path);
                    if tokio::fs::metadata(&tgz).await.is_err() {
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
                                    "the committed vendored artifact {} is missing; \
                                     recovering the registry resolution to rebuild it",
                                    entry.artifact.path
                                ),
                            ),
                            common,
                        );
                    } else {
                        match registry_fetch::stage_local_artifact(&tgz, &entry.artifact.sha256)
                            .await
                        {
                            Ok(staged) => {
                                all_packages.insert(purl.clone(), staged.dir().to_path_buf());
                                fetched_holders.push(staged);
                                continue;
                            }
                            Err(registry_fetch::FetchError::Failed(detail)) => {
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
                                if !common.silent && !common.json {
                                    eprintln!("Cannot vendor {}: {detail}", normalize_purl(purl));
                                }
                                continue;
                            }
                            Err(registry_fetch::FetchError::Unverifiable(_)) => {
                                // No recorded hash (legacy ledger) — fall
                                // through to the lockfile/registry path.
                            }
                        }
                    }
                }
                if common.offline {
                    // The enriched skip detail lands below in the unmatched
                    // pass (the purl stays unmatched).
                    continue;
                }
                match fetch_pristine_package(&common.cwd, &inventory, &client, purl, ledger_entry)
                    .await
                {
                    PristineFetch::Fetched(fetched) => {
                        record_warning(
                            env,
                            purl,
                            &VendorWarning::new(
                                "vendor_fetched_missing",
                                format!(
                                    "{} is not installed; fetched the pristine artifact \
                                     from {} (integrity verified) and vendored from that \
                                     copy — the project tree was not touched",
                                    normalize_purl(purl),
                                    fetched.url
                                ),
                            ),
                            common,
                        );
                        all_packages.insert(purl.clone(), fetched.dir().to_path_buf());
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
                        if !common.silent && !common.json {
                            eprintln!(
                                "Cannot vendor {}: fetch failed: {detail}",
                                normalize_purl(purl)
                            );
                        }
                    }
                }
            }
        }
    }

    let vendored_at = now_rfc3339();
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            env.mark_error(EnvelopeError::new("vendor_state_unreadable", e.to_string()));
            return true;
        }
    };

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

    // The hosted redirect ledger, for cross-mode takeovers: vendoring a purl
    // it still claims must revert the hosted edits FIRST (see the hook in the
    // dispatch loop below). Loaded once; mutated + persisted per reverted
    // purl. A MALFORMED ledger is held as the hard error it is: this loop
    // WRITES the ledger for takeovers, and with its records unreadable a
    // claimed purl is indistinguishable from an unclaimed one — so every
    // purl of a takeover-capable ecosystem (cargo, npm) fails closed with
    // the corruption surfaced (other purls never touch the redirect ledger
    // here and proceed).
    let (mut redirect_ledger, redirect_ledger_corrupt) =
        match socket_patch_core::patch::redirect::load_redirect_state(&common.cwd).await {
            Ok(state) => (state, None),
            Err(corrupt) => (None, Some(corrupt)),
        };

    for (purl, pkg_path) in &all_packages {
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
            // dir, so it only works when those files are EXTRACTED on disk
            // (pypi wheels / gem gems). Maven is a release-variant ecosystem
            // too, but its patch targets live INSIDE the un-extracted
            // `<a>-<v>.jar` — the version dir holds only the jar/pom, so the
            // probe would always read NotFound and drop the package. Maven
            // vendor takes the single main jar regardless (no on-disk variant
            // to select), so the probe is inapplicable and is skipped for it.
            let probe_applicable = is_variant_eco
                && !matches!(Ecosystem::from_purl(candidate), Some(Ecosystem::Maven));
            if probe_applicable && !force {
                // The representative must be a file that MODIFIES existing
                // content: a new file (empty beforeHash) verifies `Ready`
                // against any environment, so it can neither identify nor
                // disqualify a variant. Same deterministic pick as apply /
                // core's `select_installed_variants`.
                let first = match representative_file(&record.files) {
                    Some((f, info)) => Some(verify_file_patch(pkg_path, f, info).await.status),
                    None => None,
                };
                if !variant_matches_installed(first.as_ref()) {
                    continue;
                }
            }
            matched.insert(candidate.clone());

            // Cross-mode takeover: vendoring over a LIVE hosted redirect
            // must first revert the hosted edits from the redirect ledger.
            // Cargo: `[patch.crates-io]` only patches crates-io-sourced
            // deps, so vendoring on top of the `registry = "socket-patch-…"`
            // pin leaves the project unbuildable in BOTH modes while this
            // run reports success. npm family: the vendor rewire happens to
            // succeed either way, but without the pre-revert the vendor
            // ledger records the grant-tokenized HOSTED lock fragment as its
            // unrecoverable pre-vendor original (so `vendor --revert` lands
            // back on an expiring hosted URL with no CLI path to registry
            // state) and the superseded redirect records/edits survive
            // forever as a stale-ledger replay hazard. In every ecosystem
            // the pre-revert hands the vendor detach the PRISTINE registry
            // lock fragment to record as the ledger's originals. A purl
            // whose hosted edits cannot be cleanly reverted is REFUSED; the
            // cargo backend's own fail-closed guard (`hosted_redirect_live`)
            // backstops states with no usable ledger at all.
            if socket_patch_core::patch::redirect::redirect_revert_supported(candidate) {
                if let Some(corrupt) = &redirect_ledger_corrupt {
                    has_errors = true;
                    env.record(
                        PatchEvent::new(PatchAction::Failed, candidate.clone()).with_error(
                            "redirect_ledger_corrupt",
                            format!(
                                "cannot vendor over a possibly-live hosted redirect: \
                                 {corrupt}"
                            ),
                        ),
                    );
                    if !common.silent && !common.json {
                        eprintln!("Cannot vendor {}: {corrupt}", normalize_purl(candidate));
                    }
                    continue;
                }
                let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
                let claimed = redirect_ledger
                    .as_ref()
                    .is_some_and(|l| l.records.keys().any(|k| canon(k) == canon(candidate)));
                if claimed && common.dry_run {
                    record_warning(
                        env,
                        candidate,
                        &VendorWarning::new(
                            "vendor_would_revert_redirect",
                            format!(
                                "{} is hosted-redirected; a non-dry-run vendor will \
                                 revert the hosted redirect edits first, then vendor \
                                 (mode takeover)",
                                normalize_purl(candidate)
                            ),
                        ),
                        common,
                    );
                } else if claimed {
                    let ledger = redirect_ledger.as_mut().expect("claimed implies Some");
                    match socket_patch_core::patch::redirect::revert_redirect_purl(
                        &common.cwd,
                        ledger,
                        candidate,
                        false,
                    )
                    .await
                    {
                        Ok(_) => {
                            if let Err(e) =
                                socket_patch_core::patch::redirect::persist_redirect_state(
                                    &common.cwd,
                                    ledger,
                                )
                                .await
                            {
                                // The hosted edits are reverted but the ledger
                                // still claims them; vendoring now would leave
                                // a ledger asserting wiring that is gone. Fail
                                // closed for this purl.
                                has_errors = true;
                                env.record(
                                    PatchEvent::new(PatchAction::Failed, candidate.clone())
                                        .with_error(
                                            "redirect_ledger_write_failed",
                                            format!(
                                                "reverted the hosted redirect but could not \
                                                 update .socket/vendor/redirect-state.json: {e}"
                                            ),
                                        ),
                                );
                                continue;
                            }
                            let reverted_what = if candidate.starts_with("pkg:cargo/") {
                                "the hosted edits (Cargo.toml registry pin, Cargo.lock \
                                 source/checksum, registries block)"
                            } else {
                                "the hosted lockfile edits back to their pre-redirect \
                                 registry values"
                            };
                            record_warning(
                                env,
                                candidate,
                                &VendorWarning::new(
                                    "vendor_takeover_reverted_redirect",
                                    format!(
                                        "{} was hosted-redirected; reverted {reverted_what} \
                                         and dropped the redirect-ledger record before \
                                         vendoring (mode takeover)",
                                        normalize_purl(candidate)
                                    ),
                                ),
                                common,
                            );
                        }
                        Err(detail) => {
                            has_errors = true;
                            env.record(
                                PatchEvent::new(PatchAction::Failed, candidate.clone()).with_error(
                                    "redirect_revert_failed",
                                    format!(
                                        "cannot vendor over the live hosted redirect: \
                                             {detail}"
                                    ),
                                ),
                            );
                            if !common.silent && !common.json {
                                eprintln!(
                                    "Cannot vendor {}: cannot revert the hosted redirect: \
                                     {detail}",
                                    normalize_purl(candidate)
                                );
                            }
                            continue;
                        }
                    }
                }
            }

            let outcome = dispatch_vendor_one(
                candidate,
                pkg_path,
                &common.cwd,
                record,
                sources,
                &vendored_at,
                common.dry_run,
                force,
                service,
            )
            .await;

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
                        env.record(
                            PatchEvent::new(PatchAction::Skipped, candidate.clone())
                                .with_reason(code, detail.clone()),
                        );
                    } else {
                        has_errors = true;
                        env.record(
                            PatchEvent::new(PatchAction::Failed, candidate.clone())
                                .with_error(code, detail.clone()),
                        );
                    }
                    if !common.silent && !common.json {
                        eprintln!("Cannot vendor {}: {detail}", normalize_purl(candidate));
                    }
                }
                Some(VendorOutcome::Done {
                    result,
                    entry,
                    warnings,
                }) => {
                    if !result.success {
                        has_errors = true;
                        if !common.silent && !common.json {
                            eprintln!(
                                "Failed to vendor {}: {}",
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
                    env.record(event);
                    for w in &warnings {
                        record_warning(env, candidate, w, common);
                    }
                    if let Some(entry) = entry {
                        if let Some(flavor) = entry.flavor.as_deref() {
                            wired_flavors.insert(flavor.to_string());
                        }
                        has_errors |= persist_vendor_entry(
                            common, env, &mut state, candidate, entry, detached, record,
                        )
                        .await;
                    }
                }
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
        // the inventory is a local file read, allowed offline.
        let lock_resolvable: HashSet<String> = if common.offline {
            let entries = lock_inventory::inventory_project(&common.cwd).await;
            unmatched
                .iter()
                .filter(|p| lock_inventory::lookup(&entries, p).is_some())
                .cloned()
                .collect()
        } else {
            HashSet::new()
        };
        for purl in &unmatched {
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
            env.record(
                PatchEvent::new(PatchAction::Skipped, purl.clone())
                    .with_reason("package_not_installed", detail),
            );
            if !common.silent && !common.json {
                eprintln!("Cannot vendor {}: {detail}", normalize_purl(purl));
            }
        }
    }

    if !common.json && !common.silent {
        let verb = if common.dry_run {
            "Would vendor"
        } else {
            "Vendored"
        };
        println!(
            "{verb} {} package(s); {} skipped; {} failed.",
            env.summary.applied, env.summary.skipped, env.summary.failed
        );
        if env.summary.applied > 0 && !common.dry_run {
            // pnpm >=11 reads `overrides` ONLY from pnpm-workspace.yaml (the
            // package.json `pnpm.overrides` mirror is ignored), so pnpm-wired
            // runs must name that file among the committables: a checkout
            // that loses it silently unvendors on the next install.
            if wired_flavors.contains("pnpm") {
                println!(
                    "Commit .socket/vendor/, package.json, pnpm-lock.yaml, and \
                     pnpm-workspace.yaml to make the patches portable (pnpm >=11 reads \
                     the vendored override only from pnpm-workspace.yaml)."
                );
            } else {
                println!(
                    "Commit .socket/vendor/ and the updated lockfiles to make the patches \
                     portable."
                );
            }
            let mut installs: Vec<&str> = wired_flavors
                .iter()
                .filter_map(|f| flavor_install_command(f))
                .collect();
            installs.sort_unstable();
            for cmd in installs {
                println!(
                    "Run `{cmd}` to update the installed tree — vendoring rewires the \
                     lockfile only, so the current node_modules keeps the unpatched bytes \
                     until reinstalled."
                );
            }
        }
    }

    has_errors
}

/// The install command that re-materializes the project tree from the wired
/// lockfile, per npm-family flavor. Vendoring edits ONLY the lockfile/config
/// wiring — the already-installed node_modules keeps its pre-vendor bytes
/// until the package manager reinstalls from the rewired lock (verified
/// against real pnpm installs) — so a successful vendor must say how to
/// update it. `None` for flavors whose consuming step is not an install.
fn flavor_install_command(flavor: &str) -> Option<&'static str> {
    match flavor {
        "package-lock" => Some("npm install"),
        "yarn-classic" | "yarn-berry" => Some("yarn install"),
        // pnpm-legacy (lockfileVersion 5.4/6.0): plain `pnpm install` is also
        // the moved-checkout recovery — pnpm <= 8 absolutizes file: override
        // specifiers, so `--frozen-lockfile` only passes at the vendoring path.
        "pnpm" | "pnpm-legacy" => Some("pnpm install"),
        "bun" => Some("bun install"),
        _ => None,
    }
}

/// Ledger entries whose patch is gone from the manifest — the stale test
/// shared by [`reconcile_dropped`] and [`run_vendor_gc`]. Respects this
/// run's --ecosystems scope: a `vendor --ecosystems npm` invocation must
/// not silently revert a cargo/go entry (restoring its lockfile and
/// deleting its artifact) as a cross-ecosystem side effect. Detached
/// entries (`scan --vendor --detached`) are never manifest-tracked, so
/// "absent from the manifest" is their normal state, not a drop — only
/// `vendor --revert` or `remove` may undo them.
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
/// Shared with `scan --vendor` (which runs the same engine in-process).
pub(crate) async fn reconcile_dropped(
    manifest: &PatchManifest,
    common: &GlobalArgs,
    env: &mut Envelope,
) -> bool {
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(_) => return false, // unreadable state is reported by the main path
    };
    let stale = manifest_dropped_purls(&state, manifest, common);
    let mut had_error = false;
    for purl in stale {
        let entry = state.entries.get(&purl).cloned().expect("listed above");
        let outcome = dispatch_revert_one(&entry, &common.cwd, common.dry_run).await;
        for w in &outcome.warnings {
            record_warning(env, &purl, w, common);
        }
        if outcome.success {
            if outcome.kept_artifact {
                // Drift-skip keep (residual #131): the backend left the
                // drifted lock alone and kept the artifacts, so the ledger
                // entry must survive too — and the genuine outcome is a
                // COUNTED skip, not a removal.
                env.record(
                    PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                        "vendor_revert_kept",
                        "patch no longer in manifest, but its lock entries drifted since \
                         vendoring; artifacts and ledger entry kept",
                    ),
                );
                continue;
            }
            env.record(
                PatchEvent::new(PatchAction::Removed, purl.clone())
                    .with_reason("vendor_reconciled", "patch no longer in manifest"),
            );
            if !common.dry_run {
                state.entries.remove(&purl);
            }
        } else {
            had_error = true;
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone()).with_error(
                    "revert_failed",
                    outcome.error.unwrap_or_else(|| "unknown error".into()),
                ),
            );
        }
    }
    if !common.dry_run {
        let _ = save_state(&common.cwd, &state).await;
    }
    had_error
}

async fn run_revert(args: &VendorArgs, env: &mut Envelope) -> i32 {
    let common = &args.common;
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            env.mark_error(EnvelopeError::new("vendor_state_unreadable", e.to_string()));
            if !common.json && !common.silent {
                eprintln!("Error: could not read .socket/vendor/state.json: {e}");
            }
            return 1;
        }
    };

    let mut has_errors = false;
    let mut recorded: Vec<String> = state.entries.keys().cloned().collect();
    recorded.sort();

    for purl in &recorded {
        let entry = state.entries.get(purl).cloned().expect("key listed above");
        let outcome = dispatch_revert_one(&entry, &common.cwd, common.dry_run).await;
        for w in &outcome.warnings {
            record_warning(env, purl, w, common);
        }
        if outcome.success {
            if outcome.kept_artifact {
                // Drift-skip keep (residual #131): the backend left the
                // drifted lock alone and kept the artifacts, so the ledger
                // entry must survive too — and the genuine outcome is a
                // COUNTED skip, not a removal. (`record_warning` above
                // already surfaced the per-record details as uncounted
                // advisory events.)
                env.record(
                    PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                        "vendor_revert_kept",
                        "lock entries drifted since vendoring; artifacts and ledger entry kept \
                         — undo the drift and re-run `vendor --revert` to finish",
                    ),
                );
                continue;
            }
            env.record(PatchEvent::new(PatchAction::Removed, purl.clone()));
            if !common.dry_run {
                state.entries.remove(purl);
                if let Err(e) = save_state(&common.cwd, &state).await {
                    has_errors = true;
                    env.record(
                        PatchEvent::new(PatchAction::Failed, purl.clone())
                            .with_error("vendor_state_write_failed", e.to_string()),
                    );
                }
            }
        } else {
            has_errors = true;
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone()).with_error(
                    "revert_failed",
                    outcome.error.unwrap_or_else(|| "unknown error".into()),
                ),
            );
            if !common.silent && !common.json {
                eprintln!("Failed to revert {purl}");
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
        let verb = if common.dry_run {
            "Would revert"
        } else {
            "Reverted"
        };
        println!(
            "{verb} {} vendored package(s); {} failed.",
            env.summary.removed, env.summary.failed
        );
        // In this command summary.skipped counts only genuine drift-skip
        // keeps (advisory warnings are pushed uncounted by record_warning).
        if env.summary.skipped > 0 {
            println!(
                "Kept {} drifted package(s): lock entries were re-resolved since vendoring, so \
                 their artifacts and ledger entries were retained — undo the drift and re-run \
                 `vendor --revert` to finish.",
                env.summary.skipped
            );
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
    /// Entries that could not be reverted (kept in the ledger), plus any
    /// pass-level skip marker (e.g. lock contention).
    pub failed: Vec<String>,
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
/// [`VendorGcSummary::kept`] so `scan --prune` can explain the entry it
/// did not reclaim instead of silently no-oping on what its own preview
/// listed as revertable. Wet-only: a dry [`dispatch_revert_one`] returns
/// before the wiring replay that detects drift, so the dry lists still
/// carry such an entry as revertable.
///
/// Detached entries are exempt from BOTH (a) (never manifest-tracked) and
/// (b) (lockfile-invisible by design — the probe would always call them
/// unused). A missing/unreadable manifest skips (a) only (a prune must
/// not mass-revert on a deleted manifest — that is `vendor --revert`'s
/// explicit contract).
///
/// Wet runs take the apply lock (lockfiles + the manifest are rewritten);
/// contention records a skip marker and returns — it never fails the
/// scan. Dry runs are read-only, lock-free, and list-only.
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

    let socket_dir = manifest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| common.cwd.clone());
    let _guard = if dry_run {
        None
    } else {
        match socket_patch_core::patch::apply_lock::acquire(&socket_dir, Duration::from_secs(0)) {
            Ok(g) => Some(g),
            Err(_) => {
                out.failed.push(
                    "vendor GC skipped: another socket-patch run holds the apply lock".to_string(),
                );
                return out;
            }
        }
    };

    // (a) manifest-dropped entries. Everything (a) touches is excluded from
    // (b): in a dry run the ledger keeps the entry, and after a wet revert
    // failure it does too — either way (b) would list/fail the same purl a
    // second time, which the wet success path (entry removed before (b)'s
    // candidate scan) never does.
    let mut handled_by_a: HashSet<String> = HashSet::new();
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
                // Drift-skip keep (residual #131): the backend left the
                // drifted lock alone and kept the artifacts, so the ledger
                // entry must survive too (the RevertOutcome contract every
                // other caller honors) — which also shields the uuid dir
                // from the (c) orphan sweep. Nothing was reclaimed, so the
                // purl is reported as kept, never as reverted.
                out.kept.push(purl);
            } else {
                state.entries.remove(&purl);
                out.dropped_reverted.push(purl);
            }
        }
    }

    // (b) lockfile-unused entries.
    let mut manifest_dirty = false;
    let candidates: Vec<String> = state
        .entries
        .iter()
        .filter(|(purl, entry)| {
            !entry.detached
                && ecosystem_in_scope(common, &entry.ecosystem)
                && !handled_by_a.contains(*purl)
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
            // Drift-skip keep (residual #131), same gate as (a) — and the
            // purl's manifest records must survive too: pruning them would
            // make the next `vendor` reconcile re-revert an entry whose
            // backing record is gone (the `remove` caller's rationale).
            out.kept.push(purl);
            continue;
        }
        state.entries.remove(&purl);
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
        let _ = save_state(&common.cwd, &state).await;
        if manifest_dirty {
            if let Some(m) = &manifest {
                let _ = write_manifest(manifest_path, m).await;
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

#[cfg(test)]
mod dispatch_tests {
    use super::*;
    use socket_patch_core::vendor::VendorSource;

    /// Fail-closed `--vendor-source=service` must not refuse maven at the
    /// dispatch gate: the maven backend has a full service path (prebuilt
    /// jar download + registry pom), and its own errors advise exactly
    /// that flag. Regression: PR #117 shipped the backend and added nuget
    /// to `SERVICE_ECOSYSTEMS` but left maven off the list, so the gate
    /// dead-ended the flag the backend recommends.
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
            packages_path: None,
            diffs_path: None,
            mem_blobs: None,
        };
        let service = VendorServiceConfig {
            source: VendorSource::Service,
            client: None,
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
        };
        let outcome = dispatch_vendor_one(
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
            tmp.path(),
            tmp.path(),
            &record,
            &sources,
            "2026-01-01T00:00:00Z",
            false,
            false,
            Some(&service),
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
    /// events. Regression: every warning was routed through
    /// `Envelope::record` as a `Skipped` event, so a single service vendor
    /// reported `applied:1 skipped:1` and a 1-package project could print
    /// "2 skipped". The advisory must still remain visible in `events[]`.
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
    /// `summary.skipped` at zero — directly reproduces the "2 skipped" report
    /// the sweep observed for a one-package project.
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
    /// `summary.skipped` — the fix narrows the counter to real skips, it does
    /// not zero it out.
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
    /// the wheel install → `NotFound`) and adds one new file. With the
    /// representative taken from `HashMap::iter().next()` the sdist's new
    /// file comes up first roughly half the time, `Ready` admits the
    /// not-installed variant, and `vendor` attempts to vendor it — the
    /// same nondeterminism that was fixed in core's
    /// `select_installed_variants` and in `apply`'s variant loop.
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
            packages_path: None,
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
            vendor_records(&common, &records, &sources, false, false, &mut env, None).await;

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
            packages_path: None,
            diffs_path: None,
            mem_blobs: None,
        };

        let mut records: HashMap<String, PatchRecord> = HashMap::new();
        records.insert(
            WHEEL.to_string(),
            record(&[("brand_new_file.py", "", &after)]),
        );
        let mut env = Envelope::new(Command::Vendor);
        vendor_records(&common, &records, &sources, false, false, &mut env, None).await;

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
    /// repair-reconstruction brick; pinned end-to-end in
    /// repair_vendor_e2e / repair_vendor_flavors_e2e). Re-lock the
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

    /// A missing/undeterminable lockfile keeps the entry (fail-safe), and a
    /// DETACHED entry is exempt from both (a) and (b).
    #[tokio::test]
    async fn vendor_gc_keeps_undeterminable_and_detached_entries() {
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

        // Detached entry: absent from the manifest AND lockfile-invisible —
        // exactly its normal state. Never reverted by the GC.
        let (tmp, common, manifest_path) = gc_fixture(true).await;
        write_manifest(&manifest_path, &PatchManifest::new())
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("package-lock.json"), "{\"packages\":{}}")
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
    /// re-sourced to a socket-patch sparse index) is reclaimable by the GC:
    /// pre-fix, `dispatch_in_use_one` had no cargo probe (`None` = keep), so
    /// the stale ledger entry, the committed tree, and the build-breaking
    /// `[patch.crates-io]` entry survived every `scan --prune` forever.
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

    /// (a) + drift-keep (residual #131): the patch left the manifest, but
    /// the lock entry drifted since vendoring, so the revert leaves the
    /// lock alone and returns success with `kept_artifact`. Per the
    /// [`RevertOutcome::kept_artifact`] contract the GC must keep the
    /// ledger entry — which also shields the uuid dir from the (c) orphan
    /// sweep — and must NOT report the purl as cleanly reverted. Pre-fix
    /// it pruned the entry, counted it `dropped_reverted`, and the sweep
    /// then destroyed the kept artifacts.
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
    /// re-revert an entry whose backing record is gone — the `remove`
    /// caller's rationale).
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

    /// Wet GC under apply-lock contention: the run records the single skip
    /// marker and reclaims NOTHING (the scan-must-not-fail contract), while
    /// a dry-run preview with the same lock held still lists (dry runs are
    /// read-only and lock-free).
    #[tokio::test]
    async fn vendor_gc_lock_contention_skips_without_reverting() {
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

        let out = run_vendor_gc(&common, &manifest_path, false).await;
        assert_eq!(
            out.failed,
            vec!["vendor GC skipped: another socket-patch run holds the apply lock".to_string()],
            "{out:?}"
        );
        assert!(out.dropped_reverted.is_empty(), "{out:?}");
        assert!(out.unused_reverted.is_empty(), "{out:?}");
        assert_eq!(out.orphan_dirs, 0, "{out:?}");
        assert!(
            load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "a contended GC must not touch the ledger"
        );
        assert!(
            tmp.path()
                .join(format!(".socket/vendor/npm/{UUID}"))
                .exists(),
            "a contended GC must not touch artifacts"
        );

        let dry = run_vendor_gc(&common, &manifest_path, true).await;
        assert_eq!(
            dry.dropped_reverted,
            vec![PURL.to_string()],
            "the lock-free dry preview still lists: {dry:?}"
        );
        assert!(dry.failed.is_empty(), "{dry:?}");
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
        assert_eq!(flavor_install_command("cargo"), None);
        assert_eq!(flavor_install_command(""), None);
    }

    fn with_scope(list: Option<&[&str]>) -> GlobalArgs {
        GlobalArgs {
            ecosystems: list.map(|l| l.iter().map(|s| s.to_string()).collect()),
            ..GlobalArgs::default()
        }
    }

    /// The `Some(list)` branch of [`ecosystem_in_scope`]: exact match,
    /// case-insensitivity, and the `go` → `golang` alias; `None` means
    /// everything is in scope.
    #[test]
    fn ecosystem_in_scope_honors_list_alias_and_case() {
        let unscoped = with_scope(None);
        assert!(ecosystem_in_scope(&unscoped, "npm"));
        assert!(ecosystem_in_scope(&unscoped, "cargo"));

        let npm_only = with_scope(Some(&["npm"]));
        assert!(ecosystem_in_scope(&npm_only, "npm"));
        assert!(!ecosystem_in_scope(&npm_only, "cargo"));
        assert!(!ecosystem_in_scope(&npm_only, "golang"));

        let upper = with_scope(Some(&["NPM"]));
        assert!(
            ecosystem_in_scope(&upper, "npm"),
            "scope matching is case-insensitive"
        );

        let go_alias = with_scope(Some(&["go"]));
        assert!(
            ecosystem_in_scope(&go_alias, "golang"),
            "`go` must alias the golang ecosystem"
        );
        assert!(!ecosystem_in_scope(&go_alias, "npm"));
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
