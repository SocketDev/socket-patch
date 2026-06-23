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
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::{verify_file_patch, PatchSources};
use socket_patch_core::patch::copy_tree::remove_tree;
use socket_patch_core::patch::vendor::{
    self, ecosystem_dir_for_purl, load_state, save_state, RevertOutcome, VendorEntry,
    VendorOutcome, VendorServiceConfig, VendorSource, VendorWarning,
};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::telemetry::{track_patch_vendor_failed, track_patch_vendored};
use socket_patch_core::vex::time::now_rfc3339;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::apply::{result_to_event, variant_matches_installed};
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::lock_cli::{acquire_or_emit, lock_broken_event};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, Status, VexSummary,
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
pub(crate) fn refusal_is_benign(code: &str) -> bool {
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
    // service path; today npm does.
    service: Option<&VendorServiceConfig>,
) -> Option<VendorOutcome> {
    let eco = ecosystem_dir_for_purl(purl)?;
    Some(match eco {
        "npm" => {
            // The flavor router probes the project's lockfile (package-lock /
            // yarn / pnpm / bun) and dispatches or refuses per flavor.
            socket_patch_core::patch::vendor::npm_flavor::vendor_npm_any(
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
        }
        "pypi" => {
            socket_patch_core::patch::vendor::pypi::vendor_pypi(
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
        }
        "gem" => {
            socket_patch_core::patch::vendor::gem::vendor_gem(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        #[cfg(feature = "cargo")]
        "cargo" => {
            socket_patch_core::patch::vendor::cargo::vendor_cargo_crate(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        #[cfg(feature = "golang")]
        "golang" => {
            socket_patch_core::patch::vendor::golang::vendor_go_module(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        #[cfg(feature = "composer")]
        "composer" => {
            socket_patch_core::patch::vendor::composer_lock::vendor_composer(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        _ => return None,
    })
}

/// Dispatch one recorded entry to its ecosystem's revert.
pub(crate) async fn dispatch_revert_one(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    match entry.ecosystem.as_str() {
        "npm" => {
            socket_patch_core::patch::vendor::npm_flavor::revert_npm_any(
                entry,
                project_root,
                dry_run,
            )
            .await
        }
        "pypi" => {
            socket_patch_core::patch::vendor::pypi::revert_pypi(entry, project_root, dry_run).await
        }
        "gem" => {
            socket_patch_core::patch::vendor::gem::revert_gem(entry, project_root, dry_run).await
        }
        #[cfg(feature = "cargo")]
        "cargo" => {
            socket_patch_core::patch::vendor::cargo::revert_cargo_vendor(
                entry,
                project_root,
                dry_run,
            )
            .await
        }
        #[cfg(feature = "golang")]
        "golang" => {
            socket_patch_core::patch::vendor::golang::revert_go_vendor(entry, project_root, dry_run)
                .await
        }
        #[cfg(feature = "composer")]
        "composer" => {
            socket_patch_core::patch::vendor::composer_lock::revert_composer(
                entry,
                project_root,
                dry_run,
            )
            .await
        }
        other => RevertOutcome::failed(format!(
            "this build has no vendor backend for ecosystem `{other}`"
        )),
    }
}

/// Is this vendored entry still consumed by its project's lockfile
/// dependency graph? `None` = cannot determine — callers must keep the
/// entry (fail-safe): non-npm ecosystems have no in-use probe yet, and a
/// missing/unreadable lockfile proves nothing.
pub(crate) async fn dispatch_in_use_one(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    match entry.ecosystem.as_str() {
        "npm" => {
            socket_patch_core::patch::vendor::npm_flavor::vendored_entry_in_use(entry, project_root)
                .await
        }
        _ => None,
    }
}

/// Uuid dirs under `.socket/vendor/<eco>/` with no owning `(eco, uuid)`
/// ledger entry (a hand-edited state file, or artifacts left by an
/// interrupted run). The lockfile wiring for these is already gone or
/// owned by a recorded entry, so removal is safe; removed unless
/// `dry_run`. Unparseable dirs are never returned (and never deleted).
/// Returns the orphans so callers can emit events / counts.
pub(crate) async fn sweep_orphan_vendor_dirs(
    cwd: &Path,
    state: &socket_patch_core::patch::vendor::VendorState,
    dry_run: bool,
) -> Vec<socket_patch_core::patch::vendor::path::SweptVendorDir> {
    let recorded_units: HashSet<(&str, &str)> = state
        .entries
        .values()
        .map(|e| (e.ecosystem.as_str(), e.uuid.as_str()))
        .collect();
    let mut orphans = Vec::new();
    for unit in vendor::path::sweep_vendor_dirs(cwd).await {
        if recorded_units.contains(&(unit.eco.as_str(), unit.uuid.as_str())) {
            continue;
        }
        if !dry_run {
            let _ = remove_tree(&unit.dir).await;
        }
        orphans.push(unit);
    }
    orphans
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

/// Surface a backend warning: stderr line for humans, a Skipped event with
/// the stable code for JSON consumers (Skipped never flips the status).
pub(crate) fn record_warning(
    env: &mut Envelope,
    purl: &str,
    warning: &VendorWarning,
    common: &GlobalArgs,
) {
    if !common.silent && !common.json {
        eprintln!("Warning ({}): {}", warning.code, warning.detail);
    }
    env.record(
        PatchEvent::new(PatchAction::Skipped, purl.to_string())
            .with_reason(warning.code, warning.detail.clone()),
    );
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
    let acquired = match acquire_or_emit(
        &socket_dir,
        Command::Vendor,
        args.common.json,
        args.common.silent,
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
        args.common.break_lock,
    ) {
        Ok(acquired) => acquired,
        Err(code) => return code,
    };
    let _lock = acquired.guard;
    let lock_was_broken = acquired.broke_lock;

    let mut env = Envelope::new(Command::Vendor);
    env.dry_run = args.common.dry_run;
    if lock_was_broken {
        env.record(lock_broken_event(&socket_dir));
    }

    let exit = if args.revert {
        run_revert(&args, &mut env).await
    } else {
        run_vendor(&args, &manifest_path, &mut env, &vendor_service).await
    };

    // Embedded VEX: same contract as `apply --vex` — only on success, and a
    // requested-but-failed VEX flips the exit code.
    let mut exit = exit;
    if exit == 0 && !args.revert {
        if let Some(vex_path) = args.vex.vex.as_ref() {
            let params = args.vex.to_build_params();
            match generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await {
                Ok(summary) => {
                    env.vex = Some(VexSummary {
                        path: vex_path.display().to_string(),
                        statements: summary.statements,
                        format: "openvex-0.2.0".to_string(),
                    });
                }
                Err(e) => {
                    env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                    exit = 1;
                }
            }
        }
    }

    if args.common.json {
        println!("{}", env.to_pretty_json());
    }

    if !args.revert {
        if exit == 0 {
            track_patch_vendored(
                env.summary.applied,
                args.common.dry_run,
                api_token.as_deref(),
                org_slug.as_deref(),
            )
            .await;
        } else {
            track_patch_vendor_failed(
                "vendor completed with failures",
                args.common.dry_run,
                api_token.as_deref(),
                org_slug.as_deref(),
            )
            .await;
        }
    }

    exit
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
            Ok(MemStageOutcome::Ready(s)) => s,
            Ok(MemStageOutcome::Unavailable) => {
                env.mark_error(EnvelopeError::new(
                    "no_local_source",
                    "patch artifacts unavailable (offline or download failure)",
                ));
                return 1;
            }
            Err(e) => {
                env.mark_error(EnvelopeError::new("stage_failed", e));
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
        env.mark_partial_failure();
        1
    } else {
        0
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
/// Persist one backend-returned ledger entry: detached flagging, wiring
/// `original` carry-forward from the entry being replaced, per-package save
/// (crash-consistent with what is already wired), and the stale-uuid-dir
/// sweep on re-vendors. Returns `true` when the save failed (has_errors).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn persist_vendor_entry(
    common: &GlobalArgs,
    env: &mut Envelope,
    state: &mut socket_patch_core::patch::vendor::VendorState,
    candidate: &str,
    mut entry: socket_patch_core::patch::vendor::VendorEntry,
    detached: bool,
    record: &PatchRecord,
) -> bool {
    let mut has_errors = false;
    let candidate = candidate.to_string();
    entry.detached = detached;
    entry.record = detached.then(|| record.clone());
    // A re-vendor run re-derives the entry from current
    // disk state, where the takeover already happened —
    // preserve the prior flag or the revert-time
    // "takeover_not_restored" hint is lost.
    let prev = state.entries.get(&candidate).cloned();
    if let Some(prev) = &prev {
        entry.took_over_go_patches = entry.took_over_go_patches || prev.took_over_go_patches;
        // A re-vendor (new patch uuid) rewrites our own
        // stale wiring, so the backend records
        // `original: None` (it must never record a
        // dangling `.socket/vendor/` pointer as the
        // pre-vendor fragment). The TRUE pre-vendor
        // original lives in the entry being replaced —
        // carry it forward by wiring identity, or a
        // later `--revert` can only shrug
        // (`vendor_lock_entry_drifted`) instead of
        // restoring the registry fragment.
        for rec in &mut entry.wiring {
            if rec.action == socket_patch_core::patch::vendor::state::WiringAction::Rewritten
                && rec.original.is_none()
            {
                if let Some(prev_rec) = prev
                    .wiring
                    .iter()
                    .find(|p| p.file == rec.file && p.kind == rec.kind && p.key == rec.key)
                {
                    rec.original = prev_rec.original.clone();
                }
            }
        }
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
    Fetched(socket_patch_core::patch::vendor::registry_fetch::FetchedPackage),
    /// Neither the lockfile nor the ledger can name a verifiable source.
    NoSource,
    Unverifiable(String),
    Failed(String),
}

pub(crate) async fn fetch_pristine_package(
    project_root: &Path,
    inventory: &[socket_patch_core::patch::vendor::lock_inventory::LockfileEntry],
    client: &socket_patch_core::patch::vendor::registry_fetch::RegistryClient,
    purl: &str,
    ledger_entry: Option<&socket_patch_core::patch::vendor::VendorEntry>,
) -> PristineFetch {
    use socket_patch_core::patch::vendor::{lock_inventory, registry_fetch};

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

pub(crate) async fn vendor_records(
    common: &GlobalArgs,
    records: &HashMap<String, PatchRecord>,
    sources: &PatchSources<'_>,
    detached: bool,
    force: bool,
    env: &mut Envelope,
    // Vendoring-service config (`None` = build-only). The `vendor` command
    // passes `Some(_)`; `scan --vendor` passes `None` today.
    service: Option<&VendorServiceConfig>,
) -> bool {
    let mut has_errors = false;
    let manifest_purls: Vec<String> = records.keys().cloned().collect();
    let partitioned = partition_purls(&manifest_purls, common.ecosystems.as_deref());
    let target_manifest_purls: HashSet<String> = partitioned
        .values()
        .flat_map(|p| p.iter().cloned())
        .collect();

    // Purls with no vendor backend (maven/nuget/jsr, or compiled-out
    // ecosystems) are expected skips, not failures.
    let (vendorable, unsupported): (Vec<String>, Vec<String>) = target_manifest_purls
        .iter()
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
        batch_size: 100,
    };
    let mut all_packages = find_packages_for_purls(
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
    let mut fetched_holders: Vec<socket_patch_core::patch::vendor::registry_fetch::FetchedPackage> =
        Vec::new();
    // Fetch failures must keep their distinct Failed event; this set
    // suppresses the later duplicate `package_not_installed` skip.
    let mut fetch_failed: HashSet<String> = HashSet::new();
    {
        use socket_patch_core::patch::vendor::{lock_inventory, registry_fetch};
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
                let ledger_entry = ledger
                    .entries
                    .get(purl)
                    .or_else(|| ledger.entries.values().find(|e| &e.base_purl == purl));
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
            // vendored (mirrors apply / select_installed_variants).
            if is_variant_eco && !force {
                let first = match record.files.iter().next() {
                    Some((f, info)) => Some(verify_file_patch(pkg_path, f, info).await.status),
                    None => None,
                };
                if !variant_matches_installed(first.as_ref()) {
                    continue;
                }
            }
            matched.insert(candidate.clone());

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
            let entries =
                socket_patch_core::patch::vendor::lock_inventory::inventory_project(&common.cwd)
                    .await;
            unmatched
                .iter()
                .filter(|p| {
                    socket_patch_core::patch::vendor::lock_inventory::lookup(&entries, p).is_some()
                })
                .cloned()
                .collect()
        } else {
            HashSet::new()
        };
        for purl in &unmatched {
            let detail = if lock_resolvable.contains(purl) {
                "no installed package found; --offline prevents fetching it from the \
                 registry (the lockfile resolves it)"
            } else {
                "no installed package found"
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
            println!(
                "Commit .socket/vendor/ and the updated lockfiles to make the patches portable."
            );
        }
    }

    has_errors
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
    // Respect this run's --ecosystems scope: a `vendor --ecosystems npm`
    // invocation must not silently revert a cargo/go entry (restoring its
    // lockfile and deleting its artifact) as a cross-ecosystem side effect.
    let stale: Vec<String> = state
        .entries
        .iter()
        .filter(|(purl, entry)| {
            // Detached entries (`scan --vendor --detached`) are never
            // manifest-tracked, so "absent from the manifest" is their
            // normal state, not a drop — only `vendor --revert` or
            // `remove` may undo them.
            !entry.detached
                && ecosystem_in_scope(common, &entry.ecosystem)
                && !manifest.patches.contains_key(*purl)
                && !manifest.patches.contains_key(&entry.base_purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect();
    let mut had_error = false;
    for purl in stale {
        let entry = state.entries.get(&purl).cloned().expect("listed above");
        let outcome = dispatch_revert_one(&entry, &common.cwd, common.dry_run).await;
        for w in &outcome.warnings {
            record_warning(env, &purl, w, common);
        }
        if outcome.success {
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
    let recorded: Vec<String> = {
        let mut keys: Vec<String> = state.entries.keys().cloned().collect();
        keys.sort();
        keys
    };

    for purl in &recorded {
        let entry = state.entries.get(purl).cloned().expect("key listed above");
        let outcome = dispatch_revert_one(&entry, &common.cwd, common.dry_run).await;
        for w in &outcome.warnings {
            record_warning(env, purl, w, common);
        }
        if outcome.success {
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
    // state file, or artifacts left by an interrupted run). The lockfile
    // wiring for these is already gone or owned by a recorded entry, so
    // removal is safe; unparseable dirs are reported, never deleted.
    for unit in sweep_orphan_vendor_dirs(&common.cwd, &state, common.dry_run).await {
        let label = unit
            .purls
            .first()
            .cloned()
            .unwrap_or_else(|| format!("{}/{}", unit.eco, unit.uuid));
        env.record(
            PatchEvent::new(PatchAction::Removed, label)
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

    // (a) manifest-dropped entries.
    let mut manifest = socket_patch_core::manifest::operations::read_manifest(manifest_path)
        .await
        .ok()
        .flatten();
    if let Some(m) = &manifest {
        let stale: Vec<String> = state
            .entries
            .iter()
            .filter(|(purl, entry)| {
                !entry.detached
                    && ecosystem_in_scope(common, &entry.ecosystem)
                    && !m.patches.contains_key(*purl)
                    && !m.patches.contains_key(&entry.base_purl)
            })
            .map(|(purl, _)| purl.clone())
            .collect();
        for purl in stale {
            if dry_run {
                out.dropped_reverted.push(purl);
                continue;
            }
            let entry = state.entries.get(&purl).cloned().expect("listed above");
            if dispatch_revert_one(&entry, &common.cwd, false)
                .await
                .success
            {
                state.entries.remove(&purl);
                out.dropped_reverted.push(purl);
            } else {
                out.failed.push(purl);
            }
        }
    }

    // (b) lockfile-unused entries.
    let mut manifest_dirty = false;
    let candidates: Vec<String> = state
        .entries
        .iter()
        .filter(|(_, entry)| !entry.detached && ecosystem_in_scope(common, &entry.ecosystem))
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
        if !dispatch_revert_one(&entry, &common.cwd, false)
            .await
            .success
        {
            out.failed.push(purl);
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
                let _ =
                    socket_patch_core::manifest::operations::write_manifest(manifest_path, m).await;
            }
        }
    }

    // (c) orphan uuid dirs, against the post-removal ledger.
    out.orphan_dirs = sweep_orphan_vendor_dirs(&common.cwd, &state, dry_run)
        .await
        .len();
    out
}

#[cfg(test)]
mod gc_tests {
    use super::*;
    use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
    use socket_patch_core::patch::vendor::state::VendorArtifact;
    use socket_patch_core::patch::vendor::VendorState;
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
    #[tokio::test]
    async fn vendor_gc_reverts_manifest_dropped_entry() {
        let (tmp, common, manifest_path) = gc_fixture(false).await;
        write_manifest(&manifest_path, &PatchManifest::new())
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
}
