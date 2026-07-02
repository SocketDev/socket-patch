use clap::Args;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply_lock;
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::telemetry::{
    track_patch_scan_failed, track_patch_scanned, track_patch_vendor_failed, track_patch_vendored,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::crawl_all_ecosystems;
use crate::json_envelope::{Command as EnvelopeCommand, Envelope};
use crate::output::{color, confirm, format_severity, stderr_is_tty, stdout_is_tty};

use super::get::{
    download_and_apply_patches, download_patch_records, select_patches, truncate_with_ellipsis,
    DownloadParams,
};
use super::vendor::{reconcile_dropped, vendor_records};

mod discovery;
mod gc;
mod hosted;

use self::discovery::{
    collect_vuln_ids, detect_updates, lockfile_supplement, preverify_vendor_baselines,
    severity_order, vendored_ledger_supplement,
};
use self::gc::{gc_json, print_gc_vendored_line, run_apply_gc};
use self::hosted::run_redirect;

const DEFAULT_BATCH_SIZE: usize = 100;


/// The three patch-application modes `scan` can drive, selectable via
/// `--mode` (the documented spelling). Each variant is equivalent to one
/// legacy boolean flag, which remains supported as an alias.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// Rewrite lockfiles so ONLY patched dependencies resolve to Socket's
    /// hosted patch server (== `--redirect`): no artifact bytes land in the
    /// repo, but installs must reach the patch server.
    Hosted,
    /// Commit patched artifacts to `.socket/vendor/` (== `--vendor`):
    /// hermetic, offline-safe installs at the cost of repo size.
    Vendored,
    /// Record patches in `.socket/manifest.json` + blobs and re-apply them
    /// in place, e.g. from CI (== `--apply`): smallest repo footprint, but
    /// every install environment must run the agent.
    Agent,
}

impl ScanMode {
    /// The CLI spelling of the variant (`--mode <name>`), for error messages.
    fn cli_name(self) -> &'static str {
        match self {
            ScanMode::Hosted => "hosted",
            ScanMode::Vendored => "vendored",
            ScanMode::Agent => "agent",
        }
    }
}

/// Fold the legacy boolean spellings (`--redirect` / `--vendor` /
/// `--apply` / `--sync`) into `args.mode`, so `ScanMode` is the single
/// source of truth everything downstream reads (the booleans are input
/// spellings only, never consulted after this returns), and enforce the
/// cross-flag rules clap cannot express:
///
/// * `--mode X` combined with a boolean belonging to a DIFFERENT mode is a
///   contradiction → `Err`. Clap's `conflicts_with` is value-independent —
///   it could not allow `--mode vendored --vendor` while rejecting
///   `--mode hosted --vendor` — so the check lives here.
/// * The same mode spelled both ways (`--mode vendored --vendor`) is
///   redundant but accepted: both spellings mean one thing.
/// * `--sync` implies `--apply`, so it counts as an agent-mode spelling;
///   `--prune` is an orthogonal GC knob and never conflicts. (`--sync`'s
///   prune half is orthogonal too, and stays a separate read in `run`.)
/// * `--detached` requires vendored mode in either spelling. The former
///   clap-level `requires = "vendor"` couldn't see `--mode vendored`, so
///   the requirement moved here too.
///
/// Public (not `pub(crate)`) so the CLI-contract tests can exercise the
/// fold without driving a full `run()`.
pub fn resolve_mode_flags(args: &mut ScanArgs) -> Result<(), String> {
    if let Some(mode) = args.mode {
        // First boolean that selects a mode OTHER than the requested one.
        let mut conflicting: Option<&'static str> = None;
        if args.redirect && mode != ScanMode::Hosted {
            conflicting = Some("--redirect");
        }
        if args.vendor && mode != ScanMode::Vendored {
            conflicting = Some("--vendor");
        }
        if args.apply && mode != ScanMode::Agent {
            conflicting = Some("--apply");
        }
        if args.sync && mode != ScanMode::Agent {
            conflicting = Some("--sync");
        }
        if let Some(flag) = conflicting {
            // "cannot be used with" phrasing matches clap's conflict errors —
            // the scan_vendor_e2e contract test accepts exactly that shape.
            return Err(format!(
                "--mode {} cannot be used with {flag}: the flags select different \
                 modes (hosted == --redirect, vendored == --vendor, agent == --apply/--sync)",
                mode.cli_name(),
            ));
        }
    } else if args.redirect {
        args.mode = Some(ScanMode::Hosted);
    } else if args.vendor {
        args.mode = Some(ScanMode::Vendored);
    } else if args.apply || args.sync {
        args.mode = Some(ScanMode::Agent);
    }
    if args.detached && args.mode != Some(ScanMode::Vendored) {
        // "required" phrasing matches clap's requires errors — the
        // scan_vendor_e2e contract test accepts exactly that shape.
        return Err(
            "--detached requires vendored mode: --mode vendored or --vendor is required"
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Args)]
pub struct ScanArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Number of packages to query per API request.
    #[arg(long = "batch-size", env = "SOCKET_BATCH_SIZE", default_value_t = DEFAULT_BATCH_SIZE)]
    pub batch_size: usize,

    /// Deprecated spelling of `--mode agent` (kept for compatibility;
    /// prefer `--mode`). Download and apply selected patches in JSON mode
    /// (non-interactive). Without a mode, `scan --json` is read-only — it
    /// lists available patches plus an `updates` array but does not mutate
    /// the manifest. Designed for unattended workflows (cron jobs, bots
    /// that open PRs); pair with `--yes` for clarity though `--json`
    /// already implies non-interactive confirmation. No effect outside
    /// `--json` mode (the non-JSON path always prompts the user).
    #[arg(long, default_value_t = false)]
    pub apply: bool,

    /// Garbage-collect after the scan: prune manifest entries for
    /// packages no longer present in the crawl, then delete orphan
    /// blob, diff, and package-archive files from `.socket/`. Off by
    /// default to preserve manifest state across temporary uninstalls;
    /// pair with `--apply` (or use `--sync`) for the auto-update
    /// workflow.
    #[arg(long, default_value_t = false)]
    pub prune: bool,

    /// Convenience flag for the auto-update workflow: implies both
    /// `--apply` and `--prune`. Designed so a cron job or CI workflow
    /// can run `socket-patch scan --json --sync --yes` and end up in a
    /// fully-reconciled state in one invocation.
    #[arg(long, default_value_t = false)]
    pub sync: bool,

    /// Deprecated spelling of `--mode vendored` (kept for compatibility;
    /// prefer `--mode`). Vendor every patched dependency into the
    /// committable `.socket/vendor/` tree instead of applying patches in
    /// place: download the selected patches, record them in the manifest,
    /// then build + wire the vendored artifacts (the whole manifest is
    /// vendored, so a package vendored at an older patch uuid is
    /// re-vendored automatically). Conflicts with `--apply`/`--sync`
    /// (vendoring replaces the in-place apply); combine with `--prune`
    /// to drop uninstalled entries before they fail vendoring. JSON mode
    /// is non-interactive like `--apply`; the interactive path prompts
    /// before downloading.
    #[arg(long, default_value_t = false, conflicts_with_all = ["apply", "sync"])]
    pub vendor: bool,

    /// With vendored mode (`--mode vendored` / `--vendor`): do not write
    /// `.socket/manifest.json` entries — the vendor ledger
    /// (`.socket/vendor/state.json`) carries an embedded copy of each
    /// patch record instead. Detached patches are invisible to
    /// apply/rollback/repair (nothing is in the manifest); they are
    /// undone per-purl via `remove <purl>` or wholesale via
    /// `vendor --revert`, and are exempt from `vendor`'s manifest
    /// reconcile. The vendored-mode requirement is enforced in
    /// `resolve_mode_flags` (not clap `requires`) so `--mode vendored`
    /// satisfies it too.
    #[arg(long, default_value_t = false)]
    pub detached: bool,

    /// Redirect every patched dependency to Socket's HOSTED vendored patches
    /// by rewriting lockfiles/registry configs so ONLY the patched dependency
    /// points at the patch-server (`--patch-server-url`), instead of applying
    /// patches in place or ejecting local artifacts. This is the remote
    /// counterpart of `--vendor`: no artifact bytes land in the repo — the
    /// lockfile pins the hosted URL + integrity (npm/pypi/composer) or a
    /// per-dependency registry override (cargo/nuget/gem/…). Conflicts with
    /// `--apply`/`--sync`/`--vendor`. Hidden from help: the flag is
    /// unreleased and `--mode hosted` is the documented spelling.
    #[arg(long, default_value_t = false, hide = true, conflicts_with_all = ["apply", "sync", "vendor"])]
    pub redirect: bool,

    /// How discovered patches are consumed — the documented selector for
    /// the three modes (each is equivalent to one boolean flag, kept as an
    /// alias):
    ///
    /// * `hosted` (== `--redirect`): rewrite lockfiles so only patched
    ///   dependencies resolve to Socket's hosted patch server — no
    ///   artifact bytes in the repo, but installs must reach the server.
    /// * `vendored` (== `--vendor`): commit patched artifacts under
    ///   `.socket/vendor/` — hermetic, offline-safe installs at the cost
    ///   of repo size.
    /// * `agent` (== `--apply`): record patches in `.socket/manifest.json`
    ///   plus blobs and re-apply in place — smallest repo footprint, but
    ///   every environment must run the agent.
    ///
    /// Combining `--mode` with a boolean flag from a DIFFERENT mode is
    /// rejected (see `resolve_mode_flags`); the same mode spelled both
    /// ways is accepted.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<ScanMode>,

    /// Download patches for every release/distribution variant of a
    /// matched package, not just the one(s) matching the locally-
    /// installed distribution. Affects ecosystems with per-release
    /// variants — PyPI (wheel/sdist via `artifact_id`), RubyGems
    /// (`platform`), and Maven (`classifier`). Off by default: narrow
    /// scans store only the patch(es) for the installed dist, keeping
    /// `.socket/` small; `--all-releases` makes the manifest portable
    /// across environments (e.g. cross-platform CI caches).
    #[arg(
        long = "all-releases",
        env = "SOCKET_ALL_RELEASES",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub all_releases: bool,

    /// On a successful scan, also generate an OpenVEX 0.2.0 document.
    /// `--vex <path>` is the trigger; the `--vex-*` knobs mirror the
    /// standalone `vex` command. The document is built from the manifest
    /// as it stands after the scan (including any `--apply`/`--sync`
    /// writes) and verified against on-disk state. A requested-but-failed
    /// VEX makes the command exit non-zero.
    #[command(flatten)]
    pub vex: VexEmbedArgs,
}

/// Embedded-VEX side-effect for `scan`'s JSON terminal returns. When
/// `--vex` was requested and `base_code` is 0, generate the OpenVEX
/// document from the post-scan manifest and fold the outcome into
/// `result` — a `vex` object on success, or `status: "error"` + `error`
/// on failure (per the fail-the-command contract). Returns the final exit
/// code: `base_code` when not requested / skipped / on VEX success, `1`
/// when VEX generation failed. Caller prints `result` after this returns.
async fn embed_vex_into_json(
    common: &GlobalArgs,
    vex_args: &VexEmbedArgs,
    manifest_path: &Path,
    base_code: i32,
    result: &mut serde_json::Value,
) -> i32 {
    if vex_args.vex.is_none() || base_code != 0 {
        return base_code;
    }
    let params = vex_args.to_build_params();
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            result["vex"] = serde_json::json!({
                "path": vex_args.vex.as_ref().unwrap().display().to_string(),
                "statements": summary.statements,
                "format": "openvex-0.2.0",
            });
            0
        }
        Err(e) => {
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({
                "code": e.code,
                "message": e.message,
            });
            1
        }
    }
}

/// Embedded-VEX side-effect for `scan`'s human-readable terminal returns.
/// Prints a one-line note (or error) and returns the final exit code:
/// `base_code` when not requested / skipped / on VEX success, `1` on VEX
/// failure. No-op unless `--vex` was set and `base_code` is 0.
async fn embed_vex_human(
    common: &GlobalArgs,
    vex_args: &VexEmbedArgs,
    manifest_path: &Path,
    base_code: i32,
) -> i32 {
    if vex_args.vex.is_none() || base_code != 0 {
        return base_code;
    }
    let params = vex_args.to_build_params();
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            if !common.silent {
                println!(
                    "Wrote OpenVEX document with {} statement(s) to {}",
                    summary.statements,
                    vex_args.vex.as_ref().unwrap().display(),
                );
            }
            0
        }
        Err(e) => {
            if !common.silent {
                eprintln!("Error: VEX generation failed: {}", e.message);
            }
            1
        }
    }
}

/// Dry-run preview for `scan --vendor`: classify each selected patch
/// against the vendor ledger without touching disk or the network beyond
/// discovery. Action values are part of the CLI contract:
/// `would_vendor` (no ledger entry), `already_vendored` (entry at this
/// uuid), `would_revendor` + `oldUuid` (entry at an older uuid).
async fn preview_vendor_json(cwd: &Path, selected: &[PatchSearchResult]) -> serde_json::Value {
    let state = socket_patch_core::patch::vendor::load_state(cwd)
        .await
        .unwrap_or_default();
    let mut patches: Vec<serde_json::Value> = selected
        .iter()
        .map(|p| {
            let entry = state
                .entries
                .get(&p.purl)
                .or_else(|| state.entries.values().find(|e| e.base_purl == p.purl));
            match entry {
                Some(e) if e.uuid == p.uuid => serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "already_vendored",
                }),
                Some(e) => serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid,
                    "action": "would_revendor", "oldUuid": e.uuid,
                }),
                None => serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_vendor",
                }),
            }
        })
        .collect();
    patches.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    serde_json::json!({ "dryRun": true, "patches": patches })
}

/// The per-package discovery + selection step shared by the apply, vendor,
/// and redirect flows: search each patched package's full patch list, then
/// resolve the newest accessible patch per PURL. Per-package search errors
/// are skipped. Passes `is_json = false` to `select_patches`: scan-driven
/// workflows have no "specify --id" option, so non-TTY runs auto-select
/// the newest patch rather than erroring with `selection_required`. `Err`
/// carries `select_patches`' exit code.
pub(super) async fn discover_selected(
    api_client: &socket_patch_core::api::client::ApiClient,
    org_slug: Option<&str>,
    packages: &[BatchPackagePatches],
    can_access_paid_patches: bool,
) -> Result<Vec<PatchSearchResult>, i32> {
    let mut all_search_results: Vec<PatchSearchResult> = Vec::new();
    for pkg in packages {
        if let Ok(response) = api_client
            .search_patches_by_package(org_slug, &pkg.purl)
            .await
        {
            all_search_results.extend(response.patches);
        }
    }
    if all_search_results.is_empty() {
        return Ok(Vec::new());
    }
    select_patches(&all_search_results, can_access_paid_patches, false)
}

/// The `DownloadParams` every scan-driven download shares. Only the output
/// shape (`json`/`silent`) and `save_only` differ per flow; vendor mode
/// never persists blobs (the vendor step consumes the staged sources).
fn download_params(args: &ScanArgs, save_only: bool, json: bool, silent: bool) -> DownloadParams {
    DownloadParams {
        cwd: args.common.cwd.clone(),
        org: args.common.org.clone(),
        save_only,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json,
        silent,
        download_mode: args.common.download_mode.clone(),
        api_overrides: args.common.api_client_overrides(),
        all_releases: args.all_releases,
        strict: args.common.strict,
        persist_blobs: args.mode != Some(ScanMode::Vendored),
    }
}

/// The vendor step shared by `scan --vendor`'s JSON and interactive
/// paths: acquire the apply lock, stage patch sources, and drive
/// [`vendor_records`] — manifest mode (`detached_records: None`, records
/// come from re-reading the manifest, preceded by the same reconcile as
/// the `vendor` command) or detached mode (`Some(records)` from
/// [`download_patch_records`]; no manifest involvement at all).
///
/// `Ok((has_errors, envelope))` on a run that reached the engine;
/// `Err((code, message))` for the lock/stage/manifest failures the
/// caller folds into its own output shape (scan's ad-hoc JSON can't use
/// `acquire_or_emit`, which prints an Envelope).
async fn run_scan_vendor_step(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    detached_records: Option<&HashMap<String, PatchRecord>>,
) -> Result<(bool, Envelope), (&'static str, String)> {
    // The download phase created `.socket/` already in every flow that
    // reaches here, but `acquire` deliberately refuses to mkdir.
    if let Err(e) = tokio::fs::create_dir_all(socket_dir).await {
        return Err(("socket_dir_unwritable", e.to_string()));
    }
    let guard = apply_lock::acquire(
        socket_dir,
        Duration::from_secs(common.lock_timeout.unwrap_or(0)),
    )
    .map_err(|e| match e {
        apply_lock::LockError::Held => (
            "lock_held",
            "another socket-patch process is operating in this directory".to_string(),
        ),
        apply_lock::LockError::Io { .. } => ("lock_io", e.to_string()),
    })?;

    let mut env = Envelope::new(EnvelopeCommand::Vendor);
    env.dry_run = common.dry_run;
    let (manifest, detached, mut has_errors) = match detached_records {
        Some(records) => {
            // Staging probes blobs by the records' hashes; a synthetic
            // manifest view is all it needs.
            let synth = PatchManifest {
                patches: records.clone(),
                setup: None,
            };
            (synth, true, false)
        }
        None => {
            let manifest = match read_manifest(manifest_path).await {
                Ok(Some(m)) => m,
                Ok(None) => {
                    // No manifest ⇒ nothing downloaded and nothing
                    // pre-existing to vendor: a clean no-op.
                    drop(guard);
                    return Ok((false, env));
                }
                Err(e) => return Err(("invalid_manifest", e.to_string())),
            };
            // Same placement as the `vendor` command: dropped entries
            // are reverted even when zero in-scope patches remain.
            let has_errors = reconcile_dropped(&manifest, common, &mut env).await;
            (manifest, false, has_errors)
        }
    };
    let staged =
        match stage_vendor_sources_in_memory(common, &manifest, socket_dir, &common.cwd).await {
            Ok(MemStageOutcome::Ready(s)) => s,
            Ok(MemStageOutcome::Unavailable) => {
                return Err((
                    "no_local_source",
                    "patch artifacts unavailable (offline or download failure)".to_string(),
                ))
            }
            Err(e) => return Err(("stage_failed", e)),
        };
    let sources = staged.as_patch_sources();
    has_errors |=
        boxed_vendor_records(common, &manifest.patches, &sources, detached, &mut env).await;
    drop(guard);
    if has_errors {
        env.mark_partial_failure();
    }
    Ok((has_errors, env))
}

/// The `scan --vendor` JSON path: discovery → (dry-run preview | download
/// → GC → vendor engine) → embedded VEX → print `result` → exit code.
///
/// Extracted from `run` (and called through `Box::pin`) so its sizeable
/// temporaries get their own poll frame, entered only when `--vendor` is
/// actually requested — in debug builds the enclosing frame retains stack
/// slots for never-taken branches, and `run`'s frame must fit Windows'
/// 1 MiB main-thread stack.
#[allow(clippy::too_many_arguments)]
async fn run_vendor_json_path(
    args: &ScanArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&str>,
    all_packages_with_patches: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    result: &mut serde_json::Value,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored_purls: &HashSet<String>,
    prune: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    // Same discovery as `--apply`. Vendored purls are NOT filtered here —
    // re-vendoring a stale uuid is the point of the flag (same-uuid re-runs
    // land on the backend's `already_vendored` skip).
    let selected = match discover_selected(
        api_client,
        effective_org_slug,
        all_packages_with_patches,
        can_access_paid_patches,
    )
    .await
    {
        Ok(s) => s,
        Err(code) => return code,
    };

    if args.common.dry_run {
        // No downloads, no backends: classify against the ledger
        // and preview the GC, exactly like `--apply`'s dry run.
        result["vendor"] = preview_vendor_json(&args.common.cwd, &selected).await;
        if prune {
            result["gc"] = gc_json(
                &args.common,
                manifest_path,
                socket_dir,
                scanned_purls,
                vendored_purls,
                true,
            )
            .await;
        }
        let final_code =
            embed_vex_into_json(&args.common, &args.vex, manifest_path, 0, result).await;
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return final_code;
    }

    // 1) Download phase. Manifest mode reuses the `--apply`
    //    download (with `save_only` — the nested apply::run never
    //    fires); detached mode fetches records without touching
    //    the manifest. Either way the vendor step still runs when
    //    zero patches were downloaded (re-vendor after a wipe).
    let params = download_params(
        args, /*save_only=*/ true, /*json=*/ true, /*silent=*/ true,
    );
    let mut has_errors = false;
    let detached_records: Option<HashMap<String, PatchRecord>> = if args.detached {
        let (code, mut dl_json, records) = boxed_download_patch_records(&selected, &params).await;
        has_errors |= code != 0;
        if let Some(obj) = dl_json.as_object_mut() {
            obj.remove("status");
        }
        result["download"] = dl_json;
        Some(records)
    } else if selected.is_empty() {
        result["download"] = serde_json::json!({
            "found": 0, "downloaded": 0, "skipped": 0,
            "failed": 0, "patches": [],
        });
        None
    } else {
        let (code, mut dl_json) = boxed_download_and_apply(&selected, &params).await;
        has_errors |= code != 0;
        if let Some(obj) = dl_json.as_object_mut() {
            obj.remove("status");
            // save_only: the nested apply never ran, so the
            // `applied` count is structurally zero — drop it
            // rather than report a misleading 0-applied.
            obj.remove("applied");
        }
        result["download"] = dl_json;
        None
    };

    // 2) GC BEFORE the vendor step (when --prune): stale manifest
    //    entries would otherwise fail vendoring with
    //    package_not_installed; vendored entries are exempt from
    //    the prune itself.
    if prune {
        result["gc"] = gc_json(
            &args.common,
            manifest_path,
            socket_dir,
            scanned_purls,
            vendored_purls,
            false,
        )
        .await;
    }

    // 3) The vendor engine, under the same lock as apply/vendor.
    let vendor_code = match boxed_scan_vendor_step(
        &args.common,
        manifest_path,
        socket_dir,
        detached_records.as_ref(),
    )
    .await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            track_outcomes_for_vendor(
                vendor_errors,
                &venv,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            result["vendor"] =
                serde_json::to_value(&venv).unwrap_or_else(|_| serde_json::json!({}));
            i32::from(has_errors)
        }
        Err((code, message)) => {
            track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({
                "code": code,
                "message": message,
            });
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            return 1;
        }
    };
    if vendor_code != 0 {
        result["status"] = serde_json::json!("partial_failure");
    }

    let final_code =
        embed_vex_into_json(&args.common, &args.vex, manifest_path, vendor_code, result).await;
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    final_code
}

/// The `scan --vendor` interactive arm: download (manifest or detached
/// mode) → pre-vendor GC → vendor engine, with human-readable output.
/// Extracted + boxed for the same Windows-1-MiB-poll-frame reason as
/// [`run_vendor_json_path`].
#[allow(clippy::too_many_arguments)]
async fn run_vendor_interactive_path(
    args: &ScanArgs,
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored_purls: &HashSet<String>,
    prune: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    let mut has_errors = false;
    let detached_records: Option<HashMap<String, PatchRecord>> = if args.detached {
        let (dl_code, _, records) = boxed_download_patch_records(selected, params).await;
        has_errors |= dl_code != 0;
        Some(records)
    } else {
        if !selected.is_empty() {
            let (dl_code, _) = boxed_download_and_apply(selected, params).await;
            has_errors |= dl_code != 0;
        }
        None
    };
    // GC before the vendor step (see the JSON path): stale manifest
    // entries would fail vendoring with package_not_installed.
    if prune {
        let gc = run_apply_gc(
            &args.common,
            manifest_path,
            socket_dir,
            scanned_purls,
            vendored_purls,
        )
        .await;
        if !gc.pruned.is_empty() {
            println!("GC: pruned {} manifest entr{}.", gc.pruned.len(), {
                if gc.pruned.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            });
        }
        print_gc_vendored_line(&gc);
    }
    match boxed_scan_vendor_step(
        &args.common,
        manifest_path,
        socket_dir,
        detached_records.as_ref(),
    )
    .await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            track_outcomes_for_vendor(
                vendor_errors,
                &venv,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            i32::from(has_errors)
        }
        Err((code, message)) => {
            track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            eprintln!("Error ({code}): {message}");
            1
        }
    }
}

/// Partition purls matching `skip` out of the selected set and pre-render
/// their skip records (sorted by purl) with the contract `error_code`.
/// Two skip classes ride this, both removed BEFORE download:
///
/// * `"vendored"` — the patch is consumed from the committed artifact, and
///   moving the manifest past the vendored uuid would break VEX
///   verification (`vendor_uuid_mismatch`) until a vendor run.
/// * `"package_not_installed"` — the package is not on disk to patch in
///   place, and downloading its patch into the manifest would create a
///   not-yet-appliable entry (and flip the apply path's exit code).
///   `scan --vendor` is the route that handles these (the vendor engine
///   auto-fetches lockfile-resolved packages); matching bridges API purl
///   encoding via `normalize_purl`.
///
/// A plain fn (not inlined into `run`) so the json! temporaries don't ride
/// `run`'s async poll frame — see [`run_vendor_json_path`]'s Windows-stack
/// note.
fn partition_skipped_selected(
    selected: Vec<PatchSearchResult>,
    skip: impl Fn(&str) -> bool,
    error_code: &str,
) -> (Vec<PatchSearchResult>, Vec<serde_json::Value>) {
    let (skipped, kept): (Vec<_>, Vec<_>) = selected.into_iter().partition(|p| skip(&p.purl));
    let mut records: Vec<serde_json::Value> = skipped
        .iter()
        .map(|p| {
            serde_json::json!({
                "purl": p.purl, "uuid": p.uuid,
                "action": "skipped", "errorCode": error_code,
            })
        })
        .collect();
    records.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    (kept, records)
}

/// Fold the pre-download vendored skips into the apply report returned by
/// `download_and_apply_patches`: they were "found" by discovery and
/// skipped here, never downloaded. Also strips the inner `status` (scan
/// recomputes its own). Plain fn for the same poll-frame reason as
/// [`partition_vendored_selected`].
fn fold_vendored_skips_into_apply(
    apply_obj: &mut serde_json::Value,
    vendored_records: &[serde_json::Value],
) {
    let Some(obj) = apply_obj.as_object_mut() else {
        return;
    };
    obj.remove("status");
    if vendored_records.is_empty() {
        return;
    }
    let n = vendored_records.len() as u64;
    for key in ["found", "skipped"] {
        let bumped = obj.get(key).and_then(|v| v.as_u64()).unwrap_or(0) + n;
        obj.insert(key.to_string(), serde_json::json!(bumped));
    }
    if let Some(patches) = obj.get_mut("patches").and_then(|p| p.as_array_mut()) {
        patches.extend(vendored_records.iter().cloned());
    }
}

/// Construct the (large) vendor-JSON-path future on THIS transient frame
/// and hand `run` only the heap pointer. Writing
/// `Box::pin(run_vendor_json_path(..))` inline in `run` materializes the
/// future — which embeds the whole vendor engine — as a stack temporary in
/// `run`'s poll frame: debug builds allocate slots even for never-taken
/// branches, and that frame has to fit Windows' 1 MiB main-thread stack
/// (every plain `scan` was overflowing there).
#[allow(clippy::too_many_arguments)]
fn boxed_vendor_json_path<'a>(
    args: &'a ScanArgs,
    api_client: &'a socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&'a str>,
    all_packages_with_patches: &'a [BatchPackagePatches],
    can_access_paid_patches: bool,
    result: &'a mut serde_json::Value,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    scanned_purls: &'a HashSet<String>,
    vendored_purls: &'a HashSet<String>,
    prune: bool,
    telemetry_token: Option<&'a str>,
    telemetry_org: Option<&'a str>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_vendor_json_path(
        args,
        api_client,
        effective_org_slug,
        all_packages_with_patches,
        can_access_paid_patches,
        result,
        manifest_path,
        socket_dir,
        scanned_purls,
        vendored_purls,
        prune,
        telemetry_token,
        telemetry_org,
    ))
}

/// The interactive twin of [`boxed_vendor_json_path`] — same transient-
/// frame indirection, same Windows-stack rationale.
#[allow(clippy::too_many_arguments)]
fn boxed_vendor_interactive_path<'a>(
    args: &'a ScanArgs,
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    scanned_purls: &'a HashSet<String>,
    vendored_purls: &'a HashSet<String>,
    prune: bool,
    telemetry_token: Option<&'a str>,
    telemetry_org: Option<&'a str>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_vendor_interactive_path(
        args,
        selected,
        params,
        manifest_path,
        socket_dir,
        scanned_purls,
        vendored_purls,
        prune,
        telemetry_token,
        telemetry_org,
    ))
}

/// Transient-frame boxed constructor for [`run_scan_vendor_step`] — the
/// future embeds the entire vendor engine, and the vendor-path frames it
/// would otherwise ride must themselves fit Windows' 1 MiB main-thread
/// stack (same rationale as [`boxed_vendor_json_path`], one level down).
#[allow(clippy::type_complexity)]
fn boxed_scan_vendor_step<'a>(
    common: &'a GlobalArgs,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    detached_records: Option<&'a HashMap<String, PatchRecord>>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(bool, Envelope), (&'static str, String)>> + 'a>,
> {
    Box::pin(run_scan_vendor_step(
        common,
        manifest_path,
        socket_dir,
        detached_records,
    ))
}

/// Transient-frame boxed constructors for the download-phase futures used
/// inside the vendor paths — `download_and_apply_patches`'s future embeds
/// the in-process `apply::run`, and these frames must fit Windows' 1 MiB
/// main-thread stack (same rationale as [`boxed_vendor_json_path`]).
fn boxed_download_and_apply<'a>(
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = (i32, serde_json::Value)> + 'a>> {
    Box::pin(download_and_apply_patches(selected, params))
}

/// See [`boxed_download_and_apply`].
#[allow(clippy::type_complexity)]
fn boxed_download_patch_records<'a>(
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (i32, serde_json::Value, HashMap<String, PatchRecord>)>
            + 'a,
    >,
> {
    Box::pin(download_patch_records(selected, params))
}

/// Transient-frame boxed constructor for the vendor engine itself
/// ([`vendor_records`]) — the deepest, largest future on the scan-vendor
/// chain. See [`boxed_vendor_json_path`] for the Windows-stack rationale.
fn boxed_vendor_records<'a>(
    common: &'a GlobalArgs,
    records: &'a HashMap<String, PatchRecord>,
    sources: &'a socket_patch_core::patch::apply::PatchSources<'a>,
    detached: bool,
    env: &'a mut Envelope,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + 'a>> {
    // `scan --vendor` builds locally (no vendoring-service config); the
    // `vendor` command is the service-download entry point.
    Box::pin(vendor_records(
        common, records, sources, detached, false, env, None,
    ))
}

/// Telemetry for the scan-driven vendor step (mirrors `vendor::run`'s
/// success/failure split).
async fn track_outcomes_for_vendor(
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

pub async fn run(mut args: ScanArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Fold the legacy mode booleans into `args.mode` before anything reads
    // it, so every branch below keeps a single source of truth (the enum;
    // the booleans are never consulted past this point). Cross-mode
    // combinations get a usage-style error (exit 2, matching clap's
    // conflict exit code) — see `resolve_mode_flags` for why clap itself
    // can't express them.
    if let Err(message) = resolve_mode_flags(&mut args) {
        eprintln!("error: {message}");
        return 2;
    }

    // `--sync` is sugar for `--mode agent --prune`. Derive locals once and
    // use them everywhere downstream so the flag interactions are
    // expressed in one place. `--apply --prune --sync` is redundant
    // but legal.
    let apply = args.mode == Some(ScanMode::Agent);
    let vendor = args.mode == Some(ScanMode::Vendored);
    let hosted = args.mode == Some(ScanMode::Hosted);
    let prune = args.prune || args.sync;

    // A zero batch size would panic the API-query loop below: both
    // `all_purls.len().div_ceil(batch_size)` and `all_purls.chunks(batch_size)`
    // abort the process on a divisor/chunk-size of 0. `--batch-size 0`
    // (or `SOCKET_BATCH_SIZE=0`) is otherwise unvalidated, so clamp to a
    // floor of 1 — degrade to one-package batches rather than crash.
    let batch_size = args.batch_size.max(1);

    // Resolved up-front (rather than at the GC site) because the embedded
    // `--vex` side-effect reads the manifest at several terminal returns,
    // including the early "no packages" exit before the GC block.
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path.parent().unwrap().to_path_buf();

    let overrides = args.common.api_client_overrides();
    let (mut api_client, mut use_public_proxy) =
        get_api_client_with_overrides(overrides.clone()).await;
    let telemetry_token = api_client.api_token().cloned();
    let telemetry_org = api_client.org_slug().cloned();
    // Tracks whether scan was downgraded from the authenticated
    // endpoint to the public proxy mid-run after a 401/403. Surfaces
    // in the final `patch_scanned` telemetry event so we can measure
    // how often stale-token fallbacks fire in the wild.
    let mut fallback_to_proxy = false;

    // org slug is already stored in the client
    let effective_org_slug: Option<&str> = None;

    let crawler_options = CrawlerOptions {
        cwd: args.common.cwd.clone(),
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        batch_size,
    };

    let scan_target = if args.common.global || args.common.global_prefix.is_some() {
        "global packages"
    } else {
        "packages"
    };

    // `--silent` is "errors only" (CLI_CONTRACT.md): progress, the crawl
    // summary, the results table, and the per-patch listing are all
    // suppressed below, mirroring `list`/`get`/`repair`/`remove`. Errors
    // and the JSON envelope are unaffected.
    let show_progress = !args.common.json && !args.common.silent && stderr_is_tty();

    if show_progress {
        eprint!("Scanning {scan_target}...");
    }

    // Crawl packages
    let (mut all_crawled, mut eco_counts) = crawl_all_ecosystems(&crawler_options).await;

    // Lockfile supplement: dependencies the project's lockfile resolves
    // that have NO installed copy (fresh clone, partial install). They join
    // discovery — counts, API lookup, table, the prune "scanned" set — and
    // are flagged "not yet installed" everywhere a user could act on them.
    let lockfile_only = lockfile_supplement(&args.common, &all_crawled).await;
    if !lockfile_only.packages.is_empty() {
        for pkg in &lockfile_only.packages {
            if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
                *eco_counts.entry(eco).or_insert(0) += 1;
            }
        }
        all_crawled.extend(lockfile_only.packages.iter().cloned());
    }
    let ledger_supplement = vendored_ledger_supplement(&args.common, &all_crawled).await;
    for pkg in &ledger_supplement {
        if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
            *eco_counts.entry(eco).or_insert(0) += 1;
        }
    }
    all_crawled.extend(ledger_supplement);

    // Every PURL the crawl found, captured BEFORE the `--ecosystems`
    // display/query filter is applied. Prunable detection (manifest
    // entries whose PURL is not installed) must reference the full
    // installed set: `--ecosystems npm` narrows what we *query and
    // show*, but packages of other ecosystems are still installed. If
    // prune used the filtered set instead, `scan --ecosystems npm --prune`
    // would treat every cargo/go/pypi/gem manifest entry as "uninstalled"
    // and delete it (plus its blobs) — silent cross-ecosystem data loss.
    // Lockfile-only purls are deliberately included: a dependency the
    // lockfile still resolves must not be pruned just because node_modules
    // is wiped or partially installed.
    let scanned_purls: HashSet<String> = all_crawled.iter().map(|p| p.purl.clone()).collect();

    // Vendor-ledger purl keys, loaded once and shared by the prune
    // exemption (a vendored package is consumed from the committed
    // artifact, so "absent from the crawl" is its normal state, not
    // grounds for pruning) and the vendored-skip in the apply path.
    let vendored_purls =
        socket_patch_core::patch::vendor::vendored_purl_keys(&args.common.cwd).await;

    // Filter by --ecosystems if provided
    let filtered_crawled: Vec<_> = if let Some(ref allowed) = args.common.ecosystems {
        all_crawled
            .into_iter()
            .filter(|pkg| {
                if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
                    allowed.iter().any(|a| a == eco.cli_name())
                } else {
                    false
                }
            })
            .collect()
    } else {
        all_crawled
    };

    let all_purls: Vec<String> = filtered_crawled.iter().map(|p| p.purl.clone()).collect();
    let package_count = all_purls.len();

    if package_count == 0 {
        if show_progress {
            eprintln!();
        }
        // Telemetry: empty-scan still counts as a successful scan.
        track_patch_scanned(
            0,
            0,
            0,
            false,
            args.common
                .ecosystems
                .clone()
                .unwrap_or_default()
                .as_slice(),
            false,
            telemetry_token.as_deref(),
            telemetry_org.as_deref(),
        )
        .await;
        if args.common.json {
            // When the crawler finds nothing, GC is intentionally skipped
            // — pruning every manifest entry on the assumption that the
            // user "uninstalled everything" is too destructive. Bots
            // that need full cleanup can call `repair` explicitly. No
            // `gc` field emitted because the user didn't request one.
            let mut result = serde_json::json!({
                "status": "success",
                "scannedPackages": 0,
                "lockfileOnlyPackages": 0,
                "packagesWithPatches": 0,
                "totalPatches": 0,
                "freePatches": 0,
                "paidPatches": 0,
                "canAccessPaidPatches": false,
                "packages": [],
                "updates": [],
            });
            let code =
                embed_vex_into_json(&args.common, &args.vex, &manifest_path, 0, &mut result).await;
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            return code;
        } else if args.common.silent {
            // Errors only: the empty-scan hint is informational.
        } else if args.common.global || args.common.global_prefix.is_some() {
            println!("No global packages found.");
        } else {
            #[allow(unused_mut)]
            let mut install_cmds = String::from("npm/yarn/pnpm/pip");
            #[cfg(feature = "cargo")]
            install_cmds.push_str("/cargo");
            #[cfg(feature = "golang")]
            install_cmds.push_str("/go");
            #[cfg(feature = "maven")]
            install_cmds.push_str("/mvn");
            #[cfg(feature = "composer")]
            install_cmds.push_str("/composer");
            println!("No packages found. Run {install_cmds} install first.");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Build ecosystem summary
    let mut eco_parts = Vec::new();
    for eco in Ecosystem::all() {
        let count = if args.common.ecosystems.is_some() {
            // When filtering, count the filtered packages
            filtered_crawled
                .iter()
                .filter(|p| Ecosystem::from_purl(&p.purl) == Some(*eco))
                .count()
        } else {
            eco_counts.get(eco).copied().unwrap_or(0)
        };
        if count > 0 {
            eco_parts.push(format!("{count} {}", eco.display_name()));
        }
    }
    let eco_summary = if eco_parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", eco_parts.join(", "))
    };

    if !args.common.json && !args.common.silent {
        if show_progress {
            eprintln!("\rFound {package_count} packages{eco_summary}");
        } else {
            eprintln!("Found {package_count} packages{eco_summary}");
        }
        if !lockfile_only.purls.is_empty() {
            eprintln!(
                "Note: {} package(s) from project lockfiles are not yet installed (lockfile-only).",
                lockfile_only.purls.len(),
            );
        }
    }

    // Query API in batches
    let mut all_packages_with_patches: Vec<BatchPackagePatches> = Vec::new();
    let mut can_access_paid_patches = false;
    let total_batches = all_purls.len().div_ceil(batch_size);
    let mut batch_error_count = 0usize;
    let mut last_batch_error: Option<String> = None;

    if show_progress {
        eprint!("Querying API for patches... (batch 1/{total_batches})");
    }

    for (batch_idx, chunk) in all_purls.chunks(batch_size).enumerate() {
        if show_progress {
            eprint!(
                "\rQuerying API for patches... (batch {}/{})",
                batch_idx + 1,
                total_batches
            );
        }

        let purls: Vec<String> = chunk.to_vec();
        let mut result = api_client
            .search_patches_batch(effective_org_slug, &purls)
            .await;

        // Fallback: a 401/403 against the authenticated endpoint can
        // mean a stale/revoked token. Retry against the public proxy
        // (free patches only) once, then continue the rest of the
        // loop with the downgraded client. Only triggers on the
        // first authenticated batch; subsequent iterations are
        // already on the proxy.
        if !use_public_proxy {
            if let Err(ref e) = result {
                if is_fallback_candidate(e) {
                    eprintln!(
                        "Warning: authenticated API returned {e}; \
                         falling back to public patch API proxy (free patches only)."
                    );
                    api_client = build_proxy_fallback_client(&overrides);
                    use_public_proxy = true;
                    fallback_to_proxy = true;
                    result = api_client
                        .search_patches_batch(effective_org_slug, &purls)
                        .await;
                }
            }
        }

        match result {
            Ok(response) => {
                if response.can_access_paid_patches {
                    can_access_paid_patches = true;
                }
                for pkg in response.packages {
                    if !pkg.patches.is_empty() {
                        all_packages_with_patches.push(pkg);
                    }
                }
            }
            Err(e) => {
                batch_error_count += 1;
                last_batch_error = Some(e.to_string());
                if !args.common.json {
                    eprintln!("\nError querying batch {}: {e}", batch_idx + 1);
                }
            }
        }
    }

    // If every batch errored, surface this as a full scan failure rather
    // than silently reporting zero patches (which historically looked
    // identical to "no patches for these packages").
    if total_batches > 0 && batch_error_count == total_batches {
        let err = last_batch_error.unwrap_or_else(|| "all batches failed".to_string());
        track_patch_scan_failed(
            &err,
            fallback_to_proxy,
            telemetry_token.as_deref(),
            telemetry_org.as_deref(),
        )
        .await;

        // A scan in which *every* batch failed produced no trustworthy
        // patch data. Surfacing `status: "success"` / exit 0 here would be
        // indistinguishable from a genuine "no patches" result and would
        // mask a total API outage. Report the failure explicitly and bail
        // before writing any manifest or attempting apply/prune.
        if args.common.json {
            let result = serde_json::json!({
                "status": "error",
                "error": err,
                "scannedPackages": package_count,
                "packagesWithPatches": 0,
                "totalPatches": 0,
                "freePatches": 0,
                "paidPatches": 0,
                "canAccessPaidPatches": false,
                "packages": [],
                "updates": [],
            });
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        } else {
            eprintln!("Error: all {total_batches} API batch queries failed: {err}");
        }
        return 1;
    }

    let total_patches_found: usize = all_packages_with_patches
        .iter()
        .map(|p| p.patches.len())
        .sum();

    if !args.common.json && !args.common.silent {
        if total_patches_found > 0 {
            if show_progress {
                eprintln!(
                    "\rFound {total_patches_found} patches for {} packages",
                    all_packages_with_patches.len()
                );
            } else {
                eprintln!(
                    "Found {total_patches_found} patches for {} packages",
                    all_packages_with_patches.len()
                );
            }
        } else if show_progress {
            eprintln!("\rAPI query complete");
        } else {
            eprintln!("API query complete");
        }
    }

    // Calculate patch counts
    let mut free_patches = 0usize;
    let mut paid_patches = 0usize;
    for pkg in &all_packages_with_patches {
        for patch in &pkg.patches {
            if patch.tier == "free" {
                free_patches += 1;
            } else {
                paid_patches += 1;
            }
        }
    }
    let total_patches = free_patches + paid_patches;

    // Telemetry: record the scan outcome once we have the canonical
    // per-tier counts. `fallback_to_proxy` is `true` iff the batch
    // loop downgraded from the authenticated endpoint to the public
    // proxy after a 401/403.
    track_patch_scanned(
        package_count,
        free_patches,
        paid_patches,
        can_access_paid_patches,
        args.common
            .ecosystems
            .clone()
            .unwrap_or_default()
            .as_slice(),
        fallback_to_proxy,
        telemetry_token.as_deref(),
        telemetry_org.as_deref(),
    )
    .await;

    // Registry-redirect mode is a distinct, self-contained flow (rewrite
    // lockfiles → hosted vendored patches). It reuses discovery above, then
    // returns — it must NOT fall through to the apply/vendor branches.
    if hosted {
        return run_redirect(
            &args,
            &api_client,
            effective_org_slug,
            &all_packages_with_patches,
            can_access_paid_patches,
        )
        .await;
    }

    // Read existing manifest once for update detection. Used by both the
    // JSON-mode emission (always includes an `updates` array) and the
    // non-JSON table-print path (counts `updates_available`).
    // (`manifest_path`/`socket_dir` are resolved at the top of `run`.)
    let existing_manifest = read_manifest(&manifest_path).await.ok().flatten();
    let updates = detect_updates(existing_manifest.as_ref(), &all_packages_with_patches);

    if args.common.json {
        let mut result = serde_json::json!({
            "status": "success",
            "scannedPackages": package_count,
            "lockfileOnlyPackages": lockfile_only.purls.len(),
            "packagesWithPatches": all_packages_with_patches.len(),
            "totalPatches": total_patches,
            "freePatches": free_patches,
            "paidPatches": paid_patches,
            "canAccessPaidPatches": can_access_paid_patches,
            "packages": all_packages_with_patches,
            "updates": updates.iter().map(|u| serde_json::json!({
                "purl": u.purl,
                "oldUuid": u.old_uuid,
                "newUuid": u.new_uuid,
            })).collect::<Vec<_>>(),
        });
        // Flag lockfile-only packages so JSON consumers can tell "patch
        // available but not installed" from the installed case. Additive
        // field; absent means installed.
        if let Some(packages) = result["packages"].as_array_mut() {
            for pkg in packages {
                let is_lockfile_only = pkg["purl"]
                    .as_str()
                    .is_some_and(|p| lockfile_only.purls.contains(p));
                if is_lockfile_only {
                    pkg["notInstalled"] = serde_json::json!(true);
                }
            }
        }

        // `apply` and `prune` are computed once at the top of run()
        // (factoring in --sync, which implies both). They're independent
        // here: a bot can `--apply` without `--prune`, or `--prune`
        // without `--apply` (just GC-sweep), or both (full sync).
        let dry = args.common.dry_run;
        let mut apply_code = 0i32;

        // --- Apply path (if requested) -----------------------------------
        if apply {
            let selected = match discover_selected(
                &api_client,
                effective_org_slug,
                &all_packages_with_patches,
                can_access_paid_patches,
            )
            .await
            {
                Ok(s) => s,
                Err(code) => return code,
            };

            // Vendor-owned purls are skipped BEFORE download (any uuid);
            // a newer patch still surfaces in `updates[]` — the
            // operator's signal to run `scan --vendor` (or `vendor`).
            let (selected, vendored_records) = partition_skipped_selected(
                selected,
                |p| vendored_purls.contains(p) || vendored_purls.contains(strip_purl_qualifiers(p)),
                "vendored",
            );
            // Lockfile-only purls leave the apply selection here (calm
            // skip records, never an error); the union rides the same
            // bookkeeping as the vendored skips.
            let (selected, vendored_records) = {
                let (kept, not_installed) = partition_skipped_selected(
                    selected,
                    |p| {
                        lockfile_only
                            .purls
                            .contains(normalize_purl(strip_purl_qualifiers(p)).as_ref())
                    },
                    "package_not_installed",
                );
                let mut all = vendored_records;
                all.extend(not_installed);
                all.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
                (kept, all)
            };

            if dry {
                // Synthesize the per-patch outcome without touching disk.
                // `decide_patch_action` consults the existing manifest,
                // so it accurately reports what `--apply` *would* do.
                let manifest_for_preview =
                    existing_manifest.clone().unwrap_or_else(PatchManifest::new);
                let mut patches: Vec<serde_json::Value> = selected
                    .iter()
                    .map(|p| {
                        match super::get::decide_patch_action(
                            &manifest_for_preview,
                            &p.purl,
                            &p.uuid,
                        ) {
                            super::get::PatchAction::Added => serde_json::json!({
                                "purl": p.purl, "uuid": p.uuid, "action": "added",
                            }),
                            super::get::PatchAction::Updated { old_uuid } => serde_json::json!({
                                "purl": p.purl, "uuid": p.uuid,
                                "action": "updated", "oldUuid": old_uuid,
                            }),
                            super::get::PatchAction::Skipped => serde_json::json!({
                                "purl": p.purl, "uuid": p.uuid, "action": "skipped",
                            }),
                        }
                    })
                    .collect();
                patches.extend(vendored_records.iter().cloned());
                let added = patches.iter().filter(|p| p["action"] == "added").count();
                let updated = patches.iter().filter(|p| p["action"] == "updated").count();
                let skipped = patches.iter().filter(|p| p["action"] == "skipped").count();
                result["apply"] = serde_json::json!({
                    "found": selected.len() + vendored_records.len(),
                    "downloaded": 0,
                    "skipped": skipped,
                    "failed": 0,
                    "applied": 0,
                    "updated": updated,
                    "added": added,
                    "patches": patches,
                    "dryRun": true,
                });
            } else if selected.is_empty() {
                // No patches left to download (e.g. all paid for a free
                // user, no packages had patches, or everything selected is
                // vendor-owned). Emit a stable-shape `apply` carrying any
                // vendored skips, then fall through to GC if requested.
                result["apply"] = serde_json::json!({
                    "found": vendored_records.len(),
                    "downloaded": 0,
                    "skipped": vendored_records.len(),
                    "failed": 0, "applied": 0, "updated": 0,
                    "patches": vendored_records,
                });
            } else {
                let params = download_params(
                    &args, /*save_only=*/ false, /*json=*/ true, /*silent=*/ true,
                );
                let (code, apply_json) = download_and_apply_patches(&selected, &params).await;
                apply_code = code;
                let mut apply_obj = apply_json;
                fold_vendored_skips_into_apply(&mut apply_obj, &vendored_records);
                result["apply"] = apply_obj;
                if apply_code != 0 {
                    result["status"] = serde_json::json!("partial_failure");
                }
            }
        // --- Vendor path (if requested; conflicts with --apply/--sync) ---
        } else if vendor {
            // Extracted into its own boxed fn — and it must STAY extracted:
            // this branch's temporaries (json! trees, DownloadParams, the
            // engine dispatch) live in the enclosing poll frame in debug
            // builds even when the branch is never taken, and that frame
            // has to fit Windows' 1 MiB main-thread stack (regression-
            // pinned by `scan_run_fits_windows_main_thread_stack`).
            return boxed_vendor_json_path(
                &args,
                &api_client,
                effective_org_slug,
                &all_packages_with_patches,
                can_access_paid_patches,
                &mut result,
                &manifest_path,
                &socket_dir,
                &scanned_purls,
                &vendored_purls,
                prune,
                telemetry_token.as_deref(),
                telemetry_org.as_deref(),
            )
            .await;
        }

        // --- GC (post-apply, or standalone --prune GC-sweep) -------------
        if prune {
            result["gc"] = gc_json(
                &args.common,
                &manifest_path,
                &socket_dir,
                &scanned_purls,
                &vendored_purls,
                dry,
            )
            .await;
        }

        let final_code = embed_vex_into_json(
            &args.common,
            &args.vex,
            &manifest_path,
            apply_code,
            &mut result,
        )
        .await;
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return final_code;
    }

    let use_color = stdout_is_tty();

    if all_packages_with_patches.is_empty() {
        if !args.common.silent {
            println!("\nNo patches available for installed packages.");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // The whole table + summary section is presentational only (nothing
    // computed inside is consumed downstream), so `--silent` skips it
    // wholesale.
    if !args.common.silent {
        let mut updates_available = 0usize;

        // Canonical set of PURLs with a newer patch available, computed once via
        // `detect_updates` (the same source the JSON `updates` array uses). The
        // table path MUST agree with the JSON path, so reuse that result rather
        // than re-deriving it: comparing against *any* batch patch (instead of the
        // first/candidate one `select_patches` would resolve to) over-reports
        // updates whenever the manifest already holds the newest patch but older
        // patches also appear in the batch.
        let update_purls: HashSet<&str> = updates.iter().map(|u| u.purl.as_str()).collect();

        // Print table
        println!("\n{}", "=".repeat(100));
        println!(
            "{}  {}  {}  VULNERABILITIES",
            "PACKAGE".to_string() + &" ".repeat(33),
            "PATCHES".to_string() + " ",
            "SEVERITY".to_string() + &" ".repeat(8),
        );
        println!("{}", "=".repeat(100));

        for pkg in &all_packages_with_patches {
            // Char-safe truncation: a byte slice (`&pkg.purl[..37]`) panics
            // when the cut lands mid-codepoint. PURLs can carry non-ASCII
            // names/qualifiers, so route through the shared helper.
            let display_purl = truncate_with_ellipsis(&pkg.purl, 40);

            let pkg_free = pkg.patches.iter().filter(|p| p.tier == "free").count();
            let pkg_paid = pkg.patches.iter().filter(|p| p.tier == "paid").count();

            let count_str = if pkg_paid > 0 {
                if can_access_paid_patches {
                    format!("{}+{}", pkg_free, pkg_paid)
                } else {
                    format!(
                        "{}+{}",
                        pkg_free,
                        color(&pkg_paid.to_string(), "33", use_color)
                    )
                }
            } else {
                format!("{}", pkg_free)
            };

            // Get highest severity
            let severity = pkg
                .patches
                .iter()
                .filter_map(|p| p.severity.as_deref())
                .min_by_key(|s| severity_order(s))
                .unwrap_or("unknown");

            // Collect vuln IDs (deterministic: deduped, CVEs then GHSAs,
            // each group sorted — see collect_vuln_ids).
            let vuln_ids = collect_vuln_ids(pkg);
            let vuln_str = if vuln_ids.len() > 2 {
                format!("{} (+{})", vuln_ids[..2].join(", "), vuln_ids.len() - 2)
            } else if vuln_ids.is_empty() {
                "-".to_string()
            } else {
                vuln_ids.join(", ")
            };

            // Check for updates — consult the canonical `detect_updates` result
            // (mirrored into `update_purls`) so the human table and JSON `updates`
            // array never disagree.
            let has_update = update_purls.contains(pkg.purl.as_str());
            if has_update {
                updates_available += 1;
            }

            let update_marker = if has_update {
                color(" [UPDATE]", "33", use_color)
            } else {
                String::new()
            };
            // Lockfile-only packages can be patched by `scan --vendor`
            // (which fetches them pristine) but not applied in place.
            let not_installed_marker = if lockfile_only.purls.contains(pkg.purl.as_str()) {
                color(" [NOT INSTALLED]", "33", use_color)
            } else {
                String::new()
            };

            println!(
                "{:<40}  {:>8}  {:<16}  {}{}{}",
                display_purl,
                count_str,
                format_severity(severity, use_color),
                vuln_str,
                update_marker,
                not_installed_marker,
            );
        }

        println!("{}", "=".repeat(100));

        // Summary
        if can_access_paid_patches {
            println!(
                "\nSummary: {} package(s) with {} available patch(es)",
                all_packages_with_patches.len(),
                total_patches,
            );
        } else {
            println!(
                "\nSummary: {} package(s) with {} free patch(es)",
                all_packages_with_patches.len(),
                free_patches,
            );
            if paid_patches > 0 {
                println!(
                    "{}",
                    color(
                        &format!(
                            "         + {} additional patch(es) available with paid subscription",
                            paid_patches
                        ),
                        "33",
                        use_color,
                    ),
                );
                println!(
                    "\nUpgrade to Socket's paid plan to access all patches: https://socket.dev/pricing"
                );
            }
        }

        if updates_available > 0 {
            println!(
                "\n{}",
                color(
                    &format!("{updates_available} package(s) have newer patches available."),
                    "33",
                    use_color,
                ),
            );
        }
    }

    // Count downloadable patches
    let downloadable_count = if can_access_paid_patches {
        all_packages_with_patches.len()
    } else {
        all_packages_with_patches
            .iter()
            .filter(|pkg| pkg.patches.iter().any(|p| p.tier == "free"))
            .count()
    };

    if downloadable_count == 0 {
        if !args.common.silent {
            println!("\nNo downloadable patches (paid subscription required).");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Fetch full PatchSearchResult for each package that has patches
    if show_progress {
        eprint!("\nFetching patch details...");
    }

    let mut all_search_results: Vec<PatchSearchResult> = Vec::new();
    for (i, pkg) in all_packages_with_patches.iter().enumerate() {
        if show_progress {
            eprint!(
                "\rFetching patch details... ({}/{})",
                i + 1,
                all_packages_with_patches.len()
            );
        }
        match api_client
            .search_patches_by_package(effective_org_slug, &pkg.purl)
            .await
        {
            Ok(response) => {
                all_search_results.extend(response.patches);
            }
            Err(e) => {
                if !args.common.silent {
                    eprintln!("\n  Warning: could not fetch details for {}: {e}", pkg.purl);
                }
            }
        }
    }

    if show_progress {
        eprintln!();
    }

    if all_search_results.is_empty() {
        eprintln!("Could not fetch patch details.");
        return 1;
    }

    // Smart selection
    let selected: Vec<PatchSearchResult> =
        match select_patches(&all_search_results, can_access_paid_patches, false) {
            Ok(s) => s,
            Err(code) => return code,
        };

    // Vendor-owned purls never download/apply here (mirrors the JSON
    // path): the committed artifact is the patch, and a manifest moved
    // past the vendored uuid would break VEX verification until a vendor
    // run refreshes the artifact. In `--vendor` mode the partition is a
    // no-op — re-vendoring a stale uuid is exactly what the flag is for.
    let is_vendored =
        |p: &str| vendored_purls.contains(p) || vendored_purls.contains(strip_purl_qualifiers(p));
    let (vendored_selected, selected): (Vec<_>, Vec<_>) = if vendor {
        (Vec::new(), selected)
    } else {
        selected.into_iter().partition(|p| is_vendored(&p.purl))
    };
    if !args.common.silent {
        for p in &vendored_selected {
            println!(
                "  [skip] {} (vendored — run scan --vendor to update)",
                normalize_purl(&p.purl)
            );
        }
    }

    // Lockfile-only purls leave the in-place apply selection (calm skip,
    // mirrors the JSON path). In `--vendor` mode they stay: the vendor
    // engine fetches lockfile-resolved packages pristine.
    let (selected, not_installed_selected): (Vec<_>, Vec<String>) = if vendor {
        (selected, Vec::new())
    } else {
        let (kept, skipped) = partition_skipped_selected(
            selected,
            |p| {
                lockfile_only
                    .purls
                    .contains(normalize_purl(strip_purl_qualifiers(p)).as_ref())
            },
            "package_not_installed",
        );
        let printed: Vec<String> = skipped
            .iter()
            .filter_map(|r| r["purl"].as_str().map(str::to_string))
            .collect();
        (kept, printed)
    };
    if !args.common.silent {
        for purl in &not_installed_selected {
            println!(
                "  [skip] {} (not installed — run your package manager's install first, \
                 or `scan --vendor` to vendor it from the lockfile)",
                normalize_purl(purl)
            );
        }
    }

    if selected.is_empty() && !vendor {
        if !args.common.silent {
            println!("No patches selected.");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Vendor mode: pre-verify baselines so a content mismatch surfaces
    // BEFORE the confirm prompt (vendoring still proceeds for these —
    // the stage force-applies the verified patched content).
    let mismatched_baselines: HashSet<String> = if vendor && !args.common.silent {
        preverify_vendor_baselines(
            &api_client,
            effective_org_slug,
            &selected,
            &filtered_crawled,
            &lockfile_only.purls,
        )
        .await
    } else {
        HashSet::new()
    };

    // Display detailed summary of selected patches before confirming
    // (presentational only — skipped wholesale under --silent).
    if !args.common.silent {
        if vendor {
            println!("\nPatches to vendor:\n");
        } else {
            println!("\nPatches to apply:\n");
        }
        for patch in &selected {
            // Collect CVE/GHSA IDs and highest severity from vulnerabilities
            let mut vuln_ids: Vec<String> = Vec::new();
            let mut highest_severity: Option<&str> = None;
            for (id, vuln) in &patch.vulnerabilities {
                if vuln.cves.is_empty() {
                    vuln_ids.push(id.clone());
                } else {
                    for cve in &vuln.cves {
                        vuln_ids.push(cve.clone());
                    }
                }
                let sev = vuln.severity.as_str();
                if highest_severity.is_none_or(|cur| severity_order(sev) < severity_order(cur)) {
                    highest_severity = Some(sev);
                }
            }

            let sev_display = highest_severity.unwrap_or("unknown");
            let sev_colored = format_severity(sev_display, use_color);

            // Char-safe: descriptions come straight from the API and routinely
            // contain non-ASCII text; a `&desc[..69]` byte slice would panic.
            let desc = truncate_with_ellipsis(&patch.description, 72);

            println!(
                "  {} [{}] {}",
                // Human display only: show the decoded form of an
                // API-encoded purl (`%40scope` → `@scope`). JSON output
                // keeps the verbatim key.
                normalize_purl(&patch.purl),
                patch.tier.to_uppercase(),
                sev_colored,
            );
            if mismatched_baselines.contains(&patch.uuid) {
                println!(
                    "    (installed content differs from patch baseline — will vendor patched content)"
                );
            }
            if !vuln_ids.is_empty() {
                println!("    Fixes: {}", vuln_ids.join(", "));
            }
            // Show per-vulnerability summaries
            for vuln in patch.vulnerabilities.values() {
                if !vuln.summary.is_empty() {
                    // Char-safe: vulnerability summaries are API-sourced free
                    // text; a `&summary[..73]` byte slice would panic mid-codepoint.
                    let summary = truncate_with_ellipsis(&vuln.summary, 76);
                    let cve_label = if vuln.cves.is_empty() {
                        String::new()
                    } else {
                        format!("{}: ", vuln.cves.join(", "))
                    };
                    println!("    - {cve_label}{summary}");
                }
            }
            if !desc.is_empty() {
                println!("    {desc}");
            }
            println!();
        }
    }

    // `--dry-run` is a non-mutating preview (see the global flag's doc and
    // the JSON path's `dryRun` envelope). The interactive path must honor it
    // too: stop here, having printed the table and the per-patch plan above,
    // before the confirm prompt, the download/apply, and the prune GC — all
    // of which mutate the manifest and `.socket/` on disk.
    if args.common.dry_run {
        if !args.common.silent {
            let action = if vendor {
                "download and vendor"
            } else {
                "download and apply"
            };
            println!(
                "\n[dry-run] Would {action} {} patch(es). No changes made.",
                selected.len()
            );
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Prompt to download
    let verb = if vendor { "vendor" } else { "apply" };
    let prompt = format!("Download and {verb} {} patch(es)?", selected.len());
    if !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.silent {
            println!("\nTo apply a patch, run:");
            println!("  socket-patch get <package-name-or-purl>");
            println!("  socket-patch get <CVE-ID>");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Download, then apply in place — or vendor (`--vendor`, where the
    // download only saves and the vendor step below does the rest).
    let params = download_params(
        &args,
        /*save_only=*/ vendor,
        /*json=*/ false,
        args.common.silent,
    );

    let code = if vendor {
        // Extracted + boxed for the same Windows-1-MiB-frame reason as the
        // JSON path (see `run_vendor_json_path`).
        boxed_vendor_interactive_path(
            &args,
            &selected,
            &params,
            &manifest_path,
            &socket_dir,
            &scanned_purls,
            &vendored_purls,
            prune,
            telemetry_token.as_deref(),
            telemetry_org.as_deref(),
        )
        .await
    } else {
        let (code, _) = download_and_apply_patches(&selected, &params).await;
        code
    };

    // Post-apply GC: only runs when the user opted in via `--prune` or
    // `--sync`. Default `scan --yes` no longer touches the manifest
    // beyond what `--apply` added — users wanting to clean up should
    // run `socket-patch gc` (or `repair`) explicitly. (Vendor mode
    // already ran its GC before the vendor step.)
    if prune && !vendor {
        let gc = run_apply_gc(
            &args.common,
            &manifest_path,
            &socket_dir,
            &scanned_purls,
            &vendored_purls,
        )
        .await;
        let total = gc.blobs.blobs_removed + gc.diffs.blobs_removed + gc.packages.blobs_removed;
        if !args.common.silent && (!gc.pruned.is_empty() || total > 0) {
            println!(
                "\nGC: pruned {} manifest entr{} and removed {} orphan file{} ({}).",
                gc.pruned.len(),
                if gc.pruned.len() == 1 { "y" } else { "ies" },
                total,
                if total == 1 { "" } else { "s" },
                socket_patch_core::utils::cleanup_blobs::format_bytes(gc.total_bytes()),
            );
        }
        if !args.common.silent {
            print_gc_vendored_line(&gc);
        }
    }

    embed_vex_human(&args.common, &args.vex, &manifest_path, code).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use std::collections::HashMap;

    pub(super) fn manifest_with(entries: &[(&str, &str)]) -> PatchManifest {
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
                    tier: "free".to_string(),
                },
            );
        }
        m
    }

    // ---- truncate_with_ellipsis (scan's display columns) -------------------
    // scan.rs renders PURLs, descriptions, and vulnerability summaries — all
    // API-sourced and potentially non-ASCII — into fixed-width columns. These
    // pin scan's use of the char-safe helper; a raw `&s[..n]` byte slice
    // would panic when the cut lands mid-codepoint.

    #[test]
    fn truncate_multibyte_purl_does_not_panic() {
        // 30 three-byte chars (90 bytes, 30 chars). The old purl path sliced
        // `&purl[..37]` once `len() > 40`; byte 37 splits a codepoint here.
        let purl = format!("pkg:npm/{}", "日".repeat(30));
        let out = truncate_with_ellipsis(&purl, 40);
        assert!(out.chars().count() <= 40);
    }

    #[test]
    fn truncate_multibyte_description_truncates_on_char_boundary() {
        // 100 two-byte chars; description column truncates at 72.
        let desc = "é".repeat(100);
        let out = truncate_with_ellipsis(&desc, 72);
        assert_eq!(out.chars().count(), 72);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn truncate_multibyte_summary_truncates_on_char_boundary() {
        // Summary column truncates at 76.
        let summary = "—".repeat(100); // em dash, 3 bytes each
        let out = truncate_with_ellipsis(&summary, 76);
        assert_eq!(out.chars().count(), 76);
        assert!(out.ends_with("..."));
    }
}
