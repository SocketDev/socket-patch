//! The vendored-mode (`--mode vendored` / `--vendor`) flow driven by
//! `scan`: the shared download → vendor-engine → GC step, its JSON and
//! interactive arms, the pre-download skip partitions, and the `boxed_*`
//! transient-frame constructors that keep the never-taken vendor branches
//! out of `run`'s poll frame (Windows 1 MiB main-thread stack).
//!
//! Vendored mode is manifest-free: the download phase fetches the patch
//! records in memory ([`download_patch_records_with`]), the vendor engine
//! embeds each record in its ledger entry (`detached: true`), and
//! `.socket/manifest.json` is never written — a project vendored by an
//! older, manifest-mode CLI is migrated on its next vendored run (see
//! [`migrate_legacy_manifest_records`]). `--detached` is accepted as a
//! no-op for compatibility.
//!
//! One API client per run: `scan`/`get` build it once (proxy fallback
//! included) and thread it through the download phase and into the vendor
//! engine's service config; the views the download phase fetched seed the
//! in-memory stager, so no view is fetched twice.

use socket_patch_core::api::client::ApiClient;
use socket_patch_core::api::types::{BatchPackagePatches, PatchResponse, PatchSearchResult};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply_lock;
use socket_patch_core::telemetry::track_patch_vendor_failed;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vendor::{load_state, lookup_entry, save_state, VendorState};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::GlobalArgs;
use crate::commands::bun_preflight::bun_vendor_preflight_with_ledger;
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::get::{download_patch_records_with, DetachedDownload, DownloadParams};
use crate::commands::lock_cli::lock_failure;
use crate::commands::vendor::{
    note_classic_migration_risk, track_outcomes_for_vendor, vendor_records,
};
use crate::json_envelope::{Command as EnvelopeCommand, Envelope, RunWarning};
use crate::output::print_json;

use super::gc::{gc_json, print_gc_vendored_line, run_apply_gc};
use super::{
    discover_selected, download_params, embed_vex_into_json, emit_discovery_error_json,
    note_vendor_supersedes_redirect, ScanArgs,
};

/// Run-level warning: a `.socket/manifest.json` record for a purl the
/// vendor ledger now owns (detached entry with an embedded record) was
/// dropped — the ledger is the single owner of vendored state.
const VENDOR_MANIFEST_RECORD_MIGRATED: &str = "vendor_manifest_record_migrated";
/// Run-level warning: the migration above could not read or rewrite the
/// manifest (or the ledger); the legacy records were left in place.
const VENDOR_MANIFEST_MIGRATION_FAILED: &str = "vendor_manifest_migration_failed";

/// The vendor step's error: the contract code, its message and — when the
/// step had already taken the lock and died at staging — the vendor
/// Envelope it was building, demoted to `partialFailure`, for the caller's
/// JSON fold. Lock failures precede the step and carry `None`.
type VendorStepError = (&'static str, String, Option<Box<Envelope>>);
/// `(has_errors, envelope)` from a step that reached the engine, else a
/// [`VendorStepError`].
type VendorStepResult = Result<(bool, Envelope), VendorStepError>;

/// Dry-run preview for `scan --vendor` (and `get … --mode vendored
/// --dry-run`): classify each selected patch against the vendor ledger
/// without writing anything or touching the network beyond discovery.
/// Action values are part of the CLI contract: `would_vendor` (no ledger
/// entry), `already_vendored` (entry at this uuid), `would_revendor` +
/// `oldUuid` (entry at an older uuid), and — additive — `would_refuse` +
/// `errorCode` + `error` for npm purls the wet run's Bun preflight
/// ([`crate::commands::bun_preflight::BunVendorRefusal`]) would refuse
/// before any download. The preview stays a ledger classification otherwise
/// (engine refusals outside the preflight are not predicted), and it never
/// flips the run's status or exit code: `would_refuse` is best-effort
/// advice so a preview never advertises vendoring the wet run is known to
/// refuse. The preflight reads `bun.lock`/`bun.lockb` (plus, on a refused
/// workspace lock, the lock once more per npm purl for the exemption) —
/// the only disk access here — and runs only when the selection holds an
/// npm purl.
pub(crate) async fn preview_vendor_json(
    cwd: &Path,
    selected: &[PatchSearchResult],
) -> serde_json::Value {
    // The ledger load outcome reaches the preflight AS a result, so an
    // unreadable ledger previews as `vendor_state_unreadable` (nothing
    // exempt) instead of being flattened into an empty ledger that then
    // predicts a Bun lock refusal; the classification below degrades it to
    // empty (every npm record then reads `would_refuse` with that code).
    let state = load_state(cwd).await;
    let refusal =
        bun_vendor_preflight_with_ledger(cwd, selected, state.as_ref().map(|s| &s.entries)).await;
    let state = state.unwrap_or_default();
    let mut patches: Vec<serde_json::Value> = selected
        .iter()
        .map(|p| match lookup_entry(&state.entries, &p.purl) {
            // Refusal takes priority: a preserved ledger can name this
            // UUID even after rollback has removed its live wiring.
            _ if refusal.as_ref().is_some_and(|r| r.applies_to(&p.purl)) => {
                let r = refusal.as_ref().expect("checked by the guard");
                serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_refuse",
                    "errorCode": r.code, "error": r.detail,
                })
            }
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
        })
        .collect();
    patches.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    serde_json::json!({ "dryRun": true, "patches": patches })
}

/// Human rendering of the vendored dry-run preview's `would_refuse` records
/// (see [`preview_vendor_json`]): the count line above it still says
/// "would download and vendor", so name what the wet run would refuse and
/// why. Shared by `scan --mode vendored --dry-run`'s interactive arm and
/// both `get … --mode vendored --dry-run` arms so the two commands' human
/// previews cannot drift (the contract promises the line for both).
/// Informational (the preview exits 0), hence behind the caller's
/// `--silent` gate.
pub(crate) fn print_dry_run_refusals(preview: &serde_json::Value) {
    let Some(patches) = preview["patches"].as_array() else {
        return;
    };
    for p in patches.iter().filter(|p| p["action"] == "would_refuse") {
        println!(
            "  [would-refuse] {} ({}): {}",
            p["purl"].as_str().unwrap_or_default(),
            p["errorCode"].as_str().unwrap_or_default(),
            p["error"].as_str().unwrap_or_default()
        );
    }
}

/// The vendor step shared by `scan --vendor`'s JSON and interactive arms
/// (and, through [`boxed_scan_vendor_step`], `get --mode vendored`):
/// acquire the apply lock, stage the in-memory `records` (from
/// [`download_patch_records_with`], whose blob `seed` spares the stager a
/// second view fetch), drive [`vendor_records`] detached — every ledger
/// entry embeds its record; `.socket/manifest.json` is never a record
/// source — over the run's `client`, then migrate any legacy manifest
/// records the ledger now owns and run the run-level advisories, all under
/// the lock.
///
/// An empty `records` map (nothing selected, or everything refused/failed
/// in the download phase) is a no-op BEFORE the lock: nothing is staged,
/// the engine does not run, and no `.socket/` is created for a run with
/// nothing to vendor.
///
/// `Ok((has_errors, envelope))` on a run that reached the engine;
/// `Err((code, message, envelope))` for the lock/stage failures the caller
/// folds into its own output shape (scan's ad-hoc JSON can't use
/// `acquire_or_emit`, which prints an Envelope). A lock failure precedes
/// the step, so it carries no envelope (`None`); a staging failure
/// (`no_local_source`) hands back the step's envelope demoted to
/// `partialFailure` — the contract's `vendor` sub-object is present
/// whenever the step ran, and a consumer reading `.vendor.status` inside a
/// `"status":"error"` result must never see the fresh-envelope default of
/// `success`. Nothing mutates the project before staging, so that
/// envelope carries no events.
async fn run_scan_vendor_step(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    records: HashMap<String, PatchRecord>,
    seed: HashMap<String, Vec<u8>>,
    client: ApiClient,
    use_public_proxy: bool,
) -> VendorStepResult {
    let mut env = Envelope::new(EnvelopeCommand::Vendor);
    env.dry_run = common.dry_run;
    if records.is_empty() {
        return Ok((false, env));
    }
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    // `acquire` creates `.socket/` itself and reports a file squatting on
    // it as `LockError::Io` (→ `lock_io`). The guard lives to the end of
    // the step so the ledger migration and the redirect-ledger reconcile
    // inside `note_vendor_supersedes_redirect` run under the lock too.
    let _guard = apply_lock::acquire(socket_dir, timeout).map_err(|e| {
        let (code, message) = lock_failure(&e, timeout);
        (code, message, None)
    })?;

    // Staging probes blobs by the records' hashes; a manifest VIEW over the
    // in-memory records (a move, not a clone) is all it needs.
    let manifest = PatchManifest {
        patches: records,
        setup: None,
    };
    let has_errors = match stage_and_vendor(
        common,
        socket_dir,
        &manifest,
        seed,
        client,
        use_public_proxy,
        &mut env,
    )
    .await
    {
        Ok(has_errors) => has_errors,
        Err((code, message)) => {
            // The step ran and is aborting: hand its envelope (demoted) to
            // the caller's fold instead of letting the `vendor` sub-object
            // vanish from a run that entered the step.
            env.mark_partial_failure();
            return Err((code, message, Some(Box::new(env))));
        }
    };
    migrate_legacy_manifest_records(common, manifest_path, &manifest.patches, &mut env).await;
    if has_errors {
        env.mark_partial_failure();
    }
    note_classic_migration_risk(&mut env, &common.cwd, common);
    note_vendor_supersedes_redirect(&mut env, &common.cwd, common).await;
    Ok((has_errors, env))
}

/// Stage `manifest`'s patch sources in memory (seeded with the download
/// phase's blobs, harvesting the committed artifacts the ledger names for
/// the rest) and drive the vendor engine over them (detached: every entry
/// embeds its record). The caller holds the apply lock. `Err` is the
/// `no_local_source` fold (staging could not obtain the patch content —
/// offline, or the view fetch failed).
async fn stage_and_vendor(
    common: &GlobalArgs,
    socket_dir: &Path,
    manifest: &PatchManifest,
    seed: HashMap<String, Vec<u8>>,
    client: ApiClient,
    use_public_proxy: bool,
    env: &mut Envelope,
) -> Result<bool, (&'static str, String)> {
    // Loaded under the lock for the staging harvest; an unreadable ledger
    // harvests nothing and is the engine's report.
    let ledger = load_state(&common.cwd).await;
    let staged = match stage_vendor_sources_in_memory(
        common,
        manifest,
        socket_dir,
        &common.cwd,
        ledger.as_ref().map(|s| &s.entries),
        seed,
    )
    .await
    {
        MemStageOutcome::Ready(s) => s,
        MemStageOutcome::Unavailable => {
            return Err((
                "no_local_source",
                "patch artifacts unavailable (offline or download failure)".to_string(),
            ));
        }
    };
    let sources = staged.as_patch_sources();
    // Honor `--vendor-source` (and `--vendor-url` / `--patch-server-url`)
    // exactly as the `vendor` command does: the SAME service-config
    // assembler, over the run's one client, so `scan --mode vendored` and a
    // plain `vendor` commit byte-identical artifacts by default (both
    // service-download under `auto`) instead of scan silently building
    // locally.
    let service = common.vendor_service_config(Some(client), use_public_proxy);
    Ok(boxed_vendor_records(common, &manifest.patches, &sources, Some(&service), env).await)
}

/// Record a run-level advisory: stderr `Warning (code): detail` in human
/// mode (informational, so muted by `--silent`) and `warnings[]` on the
/// envelope for JSON consumers.
fn push_run_warning(env: &mut Envelope, common: &GlobalArgs, code: &str, detail: String) {
    if !common.silent && !common.json {
        eprintln!("Warning ({code}): {detail}");
    }
    env.warnings.push(RunWarning {
        code: code.to_string(),
        detail,
    });
}

/// The ledger key addressable as `purl`: the exact key, else the entry
/// whose resolved `base_purl` equals it (see [`lookup_entry`]).
fn ledger_key_for(state: &VendorState, purl: &str) -> Option<String> {
    if state.entries.contains_key(purl) {
        return Some(purl.to_string());
    }
    state
        .entries
        .iter()
        .find(|(_, e)| e.base_purl == purl)
        .map(|(k, _)| k.clone())
}

/// Migrate a project vendored by an older, manifest-mode CLI: the ledger
/// is now the single owner of vendored state, so (1) a legacy entry the
/// engine just found in sync at a record's uuid (an `already_vendored`
/// skip persists nothing) is upgraded in place — `detached: true` plus the
/// embedded record, the verification source every manifest-free reader
/// needs — and (2) every `.socket/manifest.json` record keyed by (or
/// sharing a qualifier-stripped base with) a ledger-owned entry is
/// dropped. An emptied manifest is left as `{"patches":{}}` (never
/// deleted: `list`/`apply`/`repair` distinguish empty from missing).
/// Idempotent, so it also heals records stranded by earlier detached
/// runs; a project with no manifest is untouched (no file is created).
/// Best-effort: failures are reported as run-level warnings, never as
/// run errors — the vendoring itself already committed.
///
/// Caller holds the apply lock (both files are rewritten).
async fn migrate_legacy_manifest_records(
    common: &GlobalArgs,
    manifest_path: &Path,
    records: &HashMap<String, PatchRecord>,
    env: &mut Envelope,
) {
    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => return,
        Err(e) => {
            push_run_warning(
                env,
                common,
                VENDOR_MANIFEST_MIGRATION_FAILED,
                format!(
                    "could not read {}: {e}; any records it holds for vendored packages \
                     were left in place",
                    manifest_path.display()
                ),
            );
            return;
        }
    };
    if manifest.patches.is_empty() {
        return;
    }
    // An unreadable ledger is the engine's report; nothing to migrate to.
    let Ok(mut state) = load_state(&common.cwd).await else {
        return;
    };

    // (1) Legacy same-uuid entries: upgrade in place.
    let mut upgraded = false;
    for (purl, record) in records {
        let Some(key) = ledger_key_for(&state, purl) else {
            continue;
        };
        let entry = state.entries.get_mut(&key).expect("key listed above");
        if entry.uuid == record.uuid && !(entry.detached && entry.record.is_some()) {
            entry.detached = true;
            entry.record = Some(record.clone());
            upgraded = true;
        }
    }
    if upgraded {
        if let Err(e) = save_state(&common.cwd, &state).await {
            push_run_warning(
                env,
                common,
                VENDOR_MANIFEST_MIGRATION_FAILED,
                format!("could not rewrite the vendor ledger: {e}; manifest records left in place"),
            );
            return;
        }
    }

    // (2) Drop the manifest records the ledger now owns.
    let mut dropped: Vec<String> = Vec::new();
    for (purl, entry) in state
        .entries
        .iter()
        .filter(|(_, e)| e.detached && e.record.is_some())
    {
        let base = strip_purl_qualifiers(&entry.base_purl);
        let keys: Vec<String> = manifest
            .patches
            .keys()
            .filter(|k| *k == purl || strip_purl_qualifiers(k) == base)
            .cloned()
            .collect();
        for k in keys {
            manifest.patches.remove(&k);
            dropped.push(k);
        }
    }
    if dropped.is_empty() {
        return;
    }
    dropped.sort();
    match write_manifest(manifest_path, &manifest).await {
        Ok(()) => push_run_warning(
            env,
            common,
            VENDOR_MANIFEST_RECORD_MIGRATED,
            format!(
                "{} manifest record{} moved to the vendor ledger (vendored mode is \
                 manifest-free): {}",
                dropped.len(),
                if dropped.len() == 1 { "" } else { "s" },
                dropped.join(", ")
            ),
        ),
        Err(e) => push_run_warning(
            env,
            common,
            VENDOR_MANIFEST_MIGRATION_FAILED,
            format!(
                "could not rewrite {} after moving {} to the vendor ledger: {e}",
                manifest_path.display(),
                dropped.join(", ")
            ),
        ),
    }
}

/// The `scan --vendor` JSON path: discovery → (dry-run preview | download
/// → vendor engine → GC → embedded VEX) → print `result` → exit code.
/// The dry-run arm skips the VEX embed (emitting a `vex.skipped` marker
/// instead): a dry run vendors nothing, so there is no state to attest.
///
/// Extracted from `run` (and called through `Box::pin`) so its sizeable
/// temporaries get their own poll frame, entered only when `--vendor` is
/// actually requested — in debug builds the enclosing frame retains stack
/// slots for never-taken branches, and `run`'s frame must fit Windows'
/// 1 MiB main-thread stack.
#[allow(clippy::too_many_arguments)]
async fn run_vendor_json_path(
    args: &ScanArgs,
    api_client: &ApiClient,
    use_public_proxy: bool,
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
        all_packages_with_patches,
        can_access_paid_patches,
    )
    .await
    {
        Ok(s) => s,
        Err((code, message)) => {
            emit_discovery_error_json(result, &message);
            return code;
        }
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
        // Embedded VEX is skipped on a dry run (apply.rs's precedent):
        // nothing was vendored, so there is no just-vendored state to
        // attest — generating here would verify the deliberately untouched
        // tree (failing outright on a not-yet-vendored project) and write
        // an attestation file during --dry-run. The marker keeps the
        // request visible to JSON consumers instead of silently dropping it.
        if args.vex.vex.is_some() {
            result["vex"] = serde_json::json!({ "skipped": true, "reason": "dry_run" });
        }
        print_json(result);
        return 0;
    }

    // 1) Download phase: fetch the selected records in memory. The
    //    manifest is never written; `download.detached: true` stays on
    //    the sub-object for consumers that keyed on it.
    let params = download_params(
        args, /*save_only=*/ true, /*json=*/ true, /*silent=*/ true,
    );
    let (dl_code, dl_json, records, blobs) =
        boxed_download_patch_records(&selected, &params, api_client, HashMap::new()).await;
    let mut has_errors = dl_code != 0;
    result["download"] = dl_json;

    // 2) The vendor engine, under the same lock as apply/vendor (a no-op
    //    that creates nothing when there is nothing to vendor).
    let vendor_code = match boxed_scan_vendor_step(
        &args.common,
        manifest_path,
        socket_dir,
        records,
        blobs,
        api_client.clone(),
        use_public_proxy,
    )
    .await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            // Telemetry follows the RUN outcome: a download-phase failure
            // (a Bun refusal, a failed view fetch) exits 1 and must not
            // report a successful vendoring of zero patches.
            track_outcomes_for_vendor(
                has_errors,
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
        Err((code, message, venv)) => {
            track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            // A step that ran (and died at staging) hands back its demoted
            // envelope; it must reach the JSON consumer even though the run
            // aborts here. A lock failure carries none — no `vendor` key.
            if let Some(venv) = venv {
                result["vendor"] =
                    serde_json::to_value(&*venv).unwrap_or_else(|_| serde_json::json!({}));
            }
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({
                "code": code,
                "message": message,
            });
            print_json(result);
            return 1;
        }
    };
    if vendor_code != 0 {
        result["status"] = serde_json::json!("partial_failure");
    }

    // 3) GC AFTER the vendor step (when --prune), like the apply arm: the
    //    step never reads the manifest, so nothing there depends on the
    //    prune, and running it last lets the sweep reclaim what this run
    //    orphaned (a migrated legacy record's blobs, a superseded uuid dir).
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

    let final_code =
        embed_vex_into_json(&args.common, &args.vex, manifest_path, vendor_code, result).await;
    print_json(result);
    final_code
}

/// The `scan --vendor` interactive arm: download → vendor engine → GC,
/// with human-readable output. `prefetched` holds the views the pre-prompt
/// baseline check already fetched (uuid-keyed), so the download phase
/// serves those records from memory. Extracted + boxed for the same
/// Windows-1-MiB-poll-frame reason as [`run_vendor_json_path`].
#[allow(clippy::too_many_arguments)]
async fn run_vendor_interactive_path(
    args: &ScanArgs,
    api_client: &ApiClient,
    use_public_proxy: bool,
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    prefetched: HashMap<String, PatchResponse>,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored_purls: &HashSet<String>,
    prune: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    let (dl_code, _, records, blobs) =
        boxed_download_patch_records(selected, params, api_client, prefetched).await;
    let mut has_errors = dl_code != 0;
    let code = match boxed_scan_vendor_step(
        &args.common,
        manifest_path,
        socket_dir,
        records,
        blobs,
        api_client.clone(),
        use_public_proxy,
    )
    .await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            // Run-outcome telemetry, same as the JSON arm above.
            track_outcomes_for_vendor(
                has_errors,
                &venv,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            i32::from(has_errors)
        }
        Err((code, message, _envelope)) => {
            track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            eprintln!("Error ({code}): {message}");
            return 1;
        }
    };
    // GC after the vendor step (see the JSON arm).
    if prune {
        let gc = run_apply_gc(
            &args.common,
            manifest_path,
            socket_dir,
            scanned_purls,
            vendored_purls,
        )
        .await;
        if !args.common.silent && !gc.pruned.is_empty() {
            println!(
                "GC: pruned {} manifest entr{}.",
                gc.pruned.len(),
                if gc.pruned.len() == 1 { "y" } else { "ies" },
            );
        }
        if !args.common.silent {
            print_gc_vendored_line(&gc);
        }
    }
    code
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
pub(super) fn partition_skipped_selected(
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
/// [`partition_skipped_selected`].
pub(super) fn fold_vendored_skips_into_apply(
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
pub(super) fn boxed_vendor_json_path<'a>(
    args: &'a ScanArgs,
    api_client: &'a ApiClient,
    use_public_proxy: bool,
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
        use_public_proxy,
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
pub(super) fn boxed_vendor_interactive_path<'a>(
    args: &'a ScanArgs,
    api_client: &'a ApiClient,
    use_public_proxy: bool,
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
    prefetched: HashMap<String, PatchResponse>,
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
        api_client,
        use_public_proxy,
        selected,
        params,
        prefetched,
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
/// one entry for scan's two arms and for `get --mode vendored`. The future
/// embeds the entire vendor engine, and the vendor-path frames it would
/// otherwise ride must themselves fit Windows' 1 MiB main-thread stack
/// (same rationale as [`boxed_vendor_json_path`], one level down). Moving
/// the records and seed maps and the client into the future is
/// stack-neutral (a few words each).
#[allow(clippy::too_many_arguments)]
pub(crate) fn boxed_scan_vendor_step<'a>(
    common: &'a GlobalArgs,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    records: HashMap<String, PatchRecord>,
    seed: HashMap<String, Vec<u8>>,
    client: ApiClient,
    use_public_proxy: bool,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = VendorStepResult> + 'a>> {
    Box::pin(run_scan_vendor_step(
        common,
        manifest_path,
        socket_dir,
        records,
        seed,
        client,
        use_public_proxy,
    ))
}

/// Transient-frame boxed constructor for the download-phase future used
/// inside the vendor paths, so the frame fits Windows' 1 MiB main-thread
/// stack (same rationale as [`boxed_vendor_json_path`]).
fn boxed_download_patch_records<'a>(
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
    api_client: &'a ApiClient,
    prefetched: HashMap<String, PatchResponse>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = DetachedDownload> + 'a>> {
    Box::pin(download_patch_records_with(
        selected, params, api_client, prefetched,
    ))
}

/// Transient-frame boxed constructor for the vendor engine itself
/// ([`vendor_records`]) — the deepest, largest future on the scan-vendor
/// chain. See [`boxed_vendor_json_path`] for the Windows-stack rationale.
fn boxed_vendor_records<'a>(
    common: &'a GlobalArgs,
    records: &'a HashMap<String, PatchRecord>,
    sources: &'a socket_patch_core::patch::apply::PatchSources<'a>,
    service: Option<&'a socket_patch_core::vendor::VendorServiceConfig>,
    env: &'a mut Envelope,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + 'a>> {
    // `scan --vendor` threads the SAME service config the `vendor` command
    // builds (honoring `--vendor-source`), so both entry points vendor the
    // same bytes by default. See `run_scan_vendor_step`. Always detached:
    // vendored mode is manifest-free.
    Box::pin(vendor_records(
        common, records, sources, /*detached=*/ true, false, env, service,
    ))
}

#[cfg(test)]
mod migration_tests {
    use super::{
        migrate_legacy_manifest_records, VENDOR_MANIFEST_MIGRATION_FAILED,
        VENDOR_MANIFEST_RECORD_MIGRATED,
    };
    use crate::args::GlobalArgs;
    use crate::json_envelope::{Command as EnvelopeCommand, Envelope};
    use socket_patch_core::manifest::operations::read_manifest;
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::vendor::state::VendorArtifact;
    use socket_patch_core::vendor::{load_state, save_state, VendorEntry, VendorState};
    use std::collections::HashMap;
    use std::path::Path;

    const PURL: &str = "pkg:npm/left-pad@1.3.0";
    const QUALIFIED: &str = "pkg:npm/left-pad@1.3.0?artifact_id=x";
    const OTHER: &str = "pkg:npm/other@2.0.0";
    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER_UUID: &str = "22222222-2222-4222-8222-222222222222";

    fn record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.into(),
            exported_at: "2026-01-01T00:00:00Z".into(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "fixture".into(),
            license: "MIT".into(),
            tier: "free".into(),
        }
    }

    fn entry(uuid: &str, detached: bool, record: Option<PatchRecord>) -> VendorEntry {
        VendorEntry {
            ecosystem: "npm".into(),
            base_purl: PURL.into(),
            uuid: uuid.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            detached,
            record,
            flavor: Some("package-lock".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    async fn seed_ledger(root: &Path, e: VendorEntry) {
        let mut state = VendorState::default();
        state.entries.insert(PURL.to_string(), e);
        save_state(root, &state).await.unwrap();
    }

    fn seed_manifest(root: &Path, purls: &[(&str, &str)]) {
        let socket = root.join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        let patches: serde_json::Map<String, serde_json::Value> = purls
            .iter()
            .map(|(p, u)| (p.to_string(), serde_json::to_value(record(u)).unwrap()))
            .collect();
        std::fs::write(
            socket.join("manifest.json"),
            serde_json::to_string_pretty(&serde_json::json!({ "patches": patches })).unwrap(),
        )
        .unwrap();
    }

    fn common(root: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            silent: true,
            ..Default::default()
        }
    }

    fn warning_codes(env: &Envelope) -> Vec<&str> {
        env.warnings.iter().map(|w| w.code.as_str()).collect()
    }

    /// The same-uuid legacy case: the engine skipped `already_vendored`
    /// and persisted nothing, so the entry is upgraded in place (detached
    /// + embedded record) and its manifest record moves out; an unrelated
    /// agent-mode record survives.
    #[tokio::test]
    async fn upgrades_same_uuid_legacy_entry_and_drops_its_manifest_record() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_ledger(root, entry(UUID, false, None)).await;
        seed_manifest(root, &[(PURL, UUID), (OTHER, OTHER_UUID)]);
        let manifest_path = root.join(".socket/manifest.json");
        let records: HashMap<String, PatchRecord> = [(PURL.to_string(), record(UUID))].into();
        let mut env = Envelope::new(EnvelopeCommand::Vendor);

        migrate_legacy_manifest_records(&common(root), &manifest_path, &records, &mut env).await;

        let state = load_state(root).await.unwrap();
        let e = &state.entries[PURL];
        assert!(e.detached, "{state:?}");
        assert_eq!(e.record.as_ref().map(|r| r.uuid.as_str()), Some(UUID));
        let manifest = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert_eq!(
            manifest.patches.keys().collect::<Vec<_>>(),
            vec![OTHER],
            "only the ledger-owned record moves out"
        );
        assert_eq!(warning_codes(&env), vec![VENDOR_MANIFEST_RECORD_MIGRATED]);
        assert!(env.warnings[0].detail.contains(PURL), "{:?}", env.warnings);
    }

    /// Every record the ledger already owns is dropped — exact key and
    /// qualified variants sharing the base purl — whichever run vendored
    /// them, and an emptied manifest stays on disk as `{"patches":{}}`.
    #[tokio::test]
    async fn drops_every_ledger_owned_record_and_leaves_an_emptied_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_ledger(root, entry(OTHER_UUID, true, Some(record(OTHER_UUID)))).await;
        seed_manifest(root, &[(PURL, UUID), (QUALIFIED, UUID)]);
        let manifest_path = root.join(".socket/manifest.json");
        let mut env = Envelope::new(EnvelopeCommand::Vendor);

        migrate_legacy_manifest_records(&common(root), &manifest_path, &HashMap::new(), &mut env)
            .await;

        assert_eq!(
            std::fs::read_to_string(&manifest_path).unwrap().trim(),
            "{\n  \"patches\": {}\n}",
            "an emptied manifest is kept, never deleted"
        );
        assert_eq!(warning_codes(&env), vec![VENDOR_MANIFEST_RECORD_MIGRATED]);
        let detail = &env.warnings[0].detail;
        assert!(detail.contains(PURL) && detail.contains(QUALIFIED), "{detail}");
    }

    /// A record for a purl whose ledger entry is NOT ledger-owned (a
    /// legacy entry at another uuid that this run did not re-vendor) is
    /// left alone: dropping it would hand the entry to the `vendor`
    /// command's reconcile as "dropped from the manifest".
    #[tokio::test]
    async fn leaves_records_of_non_owned_entries_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_ledger(root, entry(UUID, false, None)).await;
        seed_manifest(root, &[(PURL, UUID)]);
        let manifest_path = root.join(".socket/manifest.json");
        let before = std::fs::read(&manifest_path).unwrap();
        let ledger_before = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
        let records: HashMap<String, PatchRecord> =
            [(PURL.to_string(), record(OTHER_UUID))].into();
        let mut env = Envelope::new(EnvelopeCommand::Vendor);

        migrate_legacy_manifest_records(&common(root), &manifest_path, &records, &mut env).await;

        assert_eq!(std::fs::read(&manifest_path).unwrap(), before);
        assert_eq!(
            std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
            ledger_before
        );
        assert!(env.warnings.is_empty(), "{:?}", env.warnings);
    }

    /// No manifest ⇒ nothing to migrate, and nothing is created.
    #[tokio::test]
    async fn is_a_no_op_without_a_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let manifest_path = root.join(".socket/manifest.json");
        let records: HashMap<String, PatchRecord> = [(PURL.to_string(), record(UUID))].into();
        let mut env = Envelope::new(EnvelopeCommand::Vendor);

        migrate_legacy_manifest_records(&common(root), &manifest_path, &records, &mut env).await;

        assert!(!root.join(".socket").exists(), "must not conjure .socket/");
        assert!(env.warnings.is_empty(), "{:?}", env.warnings);
    }

    /// A corrupt manifest is reported, not rewritten and not fatal: the
    /// vendoring already committed and the manifest is not vendored
    /// mode's concern.
    #[tokio::test]
    async fn warns_on_a_corrupt_manifest_and_leaves_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_ledger(root, entry(UUID, true, Some(record(UUID)))).await;
        std::fs::write(root.join(".socket/manifest.json"), b"{not json").unwrap();
        let manifest_path = root.join(".socket/manifest.json");
        let mut env = Envelope::new(EnvelopeCommand::Vendor);

        migrate_legacy_manifest_records(&common(root), &manifest_path, &HashMap::new(), &mut env)
            .await;

        assert_eq!(
            std::fs::read(&manifest_path).unwrap(),
            b"{not json",
            "the corrupt file is left for the operator"
        );
        assert_eq!(warning_codes(&env), vec![VENDOR_MANIFEST_MIGRATION_FAILED]);
        assert!(
            env.warnings[0].detail.contains("manifest.json"),
            "{:?}",
            env.warnings
        );
    }
}

#[cfg(test)]
mod preview_tests {
    use super::preview_vendor_json;
    use socket_patch_core::api::types::PatchSearchResult;
    use std::collections::HashMap;
    use std::path::Path;

    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    const OLD_UUID: &str = "00000000-0000-4000-8000-000000000000";
    const NPM: &str = "pkg:npm/preview-bun@1.0.0";
    const PYPI: &str = "pkg:pypi/preview-other@1.0.0";

    /// Real bun 1.3.14 lockfileVersion-1 workspace grammar (1-tuple
    /// `workspace:` entry) — the shape the wet run refuses.
    const V1_WORKSPACE_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "preview-fixture",
      "dependencies": {
        "consumer": "workspace:*",
      },
    },
    "packages/consumer": {
      "name": "consumer",
      "version": "1.0.0",
      "dependencies": {
        "preview-bun": "1.0.0",
      },
    },
  },
  "packages": {
    "consumer": ["consumer@workspace:packages/consumer"],

    "preview-bun": ["preview-bun@1.0.0", "", {}, "sha512-AAAA=="],
  }
}
"#;

    fn sel(uuid: &str, purl: &str) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.into(),
            purl: purl.into(),
            published_at: "2024-01-01T00:00:00Z".into(),
            description: String::new(),
            license: "MIT".into(),
            tier: "free".into(),
            vulnerabilities: HashMap::new(),
        }
    }

    fn seed_entry(root: &Path, purl: &str, uuid: &str) {
        let vendor = root.join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm", "basePurl": purl, "uuid": uuid,
                    "artifact": { "path": format!(".socket/vendor/npm/{uuid}/x.tgz") },
                    "wiring": [], "flavor": "bun",
                }}
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn action_of<'a>(preview: &'a serde_json::Value, purl: &str) -> &'a serde_json::Value {
        preview["patches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["purl"] == purl)
            .unwrap_or_else(|| panic!("no preview record for {purl}: {preview}"))
    }

    /// Without a Bun lock the preview is the pre-existing ledger
    /// classification, byte for byte: `would_vendor` and nothing else.
    #[tokio::test]
    async fn preview_without_bun_lock_is_plain_would_vendor() {
        let tmp = tempfile::tempdir().unwrap();
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)]).await;
        assert_eq!(
            preview,
            serde_json::json!({
                "dryRun": true,
                "patches": [{ "purl": NPM, "uuid": UUID, "action": "would_vendor" }],
            })
        );
    }

    /// A refused Bun tree flips npm purls to the additive `would_refuse`
    /// (with the vendor code + detail) and leaves other ecosystems alone.
    #[tokio::test]
    async fn preview_marks_would_refuse_for_refused_bun_tree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lock"), V1_WORKSPACE_LOCK).unwrap();
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM), sel(UUID, PYPI)]).await;
        let npm = action_of(&preview, NPM);
        assert_eq!(npm["action"], "would_refuse", "{preview}");
        assert_eq!(
            npm["errorCode"], "vendor_bun_workspace_unsupported",
            "{preview}"
        );
        assert!(
            npm["error"].as_str().is_some_and(|d| !d.is_empty()),
            "{preview}"
        );
        assert_eq!(
            action_of(&preview, PYPI)["action"],
            "would_vendor",
            "{preview}"
        );
        assert_eq!(preview["dryRun"], true);
        // The preflight is read-only.
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap(),
            V1_WORKSPACE_LOCK
        );
    }

    /// A ledger cannot override the live-lock refusal. Already-vendored
    /// classification remains available when the lock is actually wired.
    #[tokio::test]
    async fn preview_bun_refusal_requires_live_wiring_even_at_the_same_uuid() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lock"), V1_WORKSPACE_LOCK).unwrap();

        seed_entry(tmp.path(), NPM, UUID);
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)]).await;
        assert_eq!(
            action_of(&preview, NPM)["action"],
            "would_refuse",
            "{preview}"
        );

        seed_entry(tmp.path(), NPM, OLD_UUID);
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)]).await;
        let rec = action_of(&preview, NPM);
        assert_eq!(rec["action"], "would_refuse", "{preview}");
        assert!(
            rec.get("oldUuid").is_none(),
            "a refused record is not a revendor preview: {preview}"
        );

        let wired = V1_WORKSPACE_LOCK.replace(
            r#"["preview-bun@1.0.0", "", {}, "sha512-AAAA=="]"#,
            &format!(r#"["preview-bun@.socket/vendor/npm/{UUID}/preview-bun-1.0.0.tgz", {{}}, "sha512-AAAA=="]"#),
        );
        std::fs::write(tmp.path().join("bun.lock"), wired).unwrap();
        seed_entry(tmp.path(), NPM, UUID);
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)]).await;
        assert_eq!(
            action_of(&preview, NPM)["action"],
            "already_vendored",
            "{preview}"
        );
    }

    /// Malformed bun.lockb: `would_refuse` with the binary format code.
    #[tokio::test]
    async fn preview_marks_malformed_lockb_would_refuse() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)]).await;
        assert_eq!(
            action_of(&preview, NPM)["errorCode"],
            "vendor_bun_lockb_invalid",
            "{preview}"
        );
    }
}

#[cfg(test)]
mod fold_vendored_skips_tests {
    use super::fold_vendored_skips_into_apply;

    /// A pre-rendered vendored-skip record, shaped exactly like
    /// [`super::partition_skipped_selected`]'s output.
    fn record(purl: &str) -> serde_json::Value {
        serde_json::json!({
            "purl": purl,
            "uuid": "11111111-1111-4111-8111-111111111111",
            "action": "skipped",
            "errorCode": "vendored",
        })
    }

    /// The count-consistency contract: every pre-download vendored skip
    /// was "found" by discovery and "skipped" here, so both counters bump
    /// by the record count, the records land appended after the download
    /// phase's own entries, and every other counter is left alone.
    #[test]
    fn fold_bumps_found_and_skipped_and_appends_records() {
        let mut apply_obj = serde_json::json!({
            "status": "partialFailure",
            "found": 2,
            "downloaded": 1,
            "skipped": 1,
            "failed": 1,
            "applied": 1,
            "patches": [{ "purl": "pkg:npm/a@1.0.0" }],
        });
        let records = [record("pkg:npm/b@1.0.0"), record("pkg:npm/c@1.0.0")];

        fold_vendored_skips_into_apply(&mut apply_obj, &records);

        let obj = apply_obj.as_object().expect("still an object");
        assert!(
            !obj.contains_key("status"),
            "the inner status is scan's to recompute: {apply_obj}"
        );
        assert_eq!(apply_obj["found"], 4, "{apply_obj}");
        assert_eq!(apply_obj["skipped"], 3, "{apply_obj}");
        assert_eq!(apply_obj["downloaded"], 1, "untouched: {apply_obj}");
        assert_eq!(apply_obj["failed"], 1, "untouched: {apply_obj}");
        assert_eq!(apply_obj["applied"], 1, "untouched: {apply_obj}");
        let patches = apply_obj["patches"].as_array().expect("patches array");
        assert_eq!(patches.len(), 3, "{apply_obj}");
        assert_eq!(patches[0]["purl"], "pkg:npm/a@1.0.0", "{apply_obj}");
        assert_eq!(patches[1], records[0], "appended in order: {apply_obj}");
        assert_eq!(patches[2], records[1], "appended in order: {apply_obj}");
    }

    /// Missing counters default to zero before the bump (the
    /// `unwrap_or(0)` fallback) — the keys are CREATED, not skipped, so a
    /// minimal download report still ends up count-consistent.
    #[test]
    fn fold_missing_counts_default_to_zero() {
        let mut apply_obj = serde_json::json!({ "patches": [] });
        let records = [record("pkg:npm/b@1.0.0")];

        fold_vendored_skips_into_apply(&mut apply_obj, &records);

        assert_eq!(apply_obj["found"], 1, "{apply_obj}");
        assert_eq!(apply_obj["skipped"], 1, "{apply_obj}");
        let patches = apply_obj["patches"].as_array().expect("patches array");
        assert_eq!(patches.len(), 1, "{apply_obj}");
        assert_eq!(patches[0], records[0], "{apply_obj}");
    }

    /// A non-object report (defensive arm) is left byte-identical — no
    /// panic, no partial mutation.
    #[test]
    fn fold_non_object_report_is_a_noop() {
        let mut apply_obj = serde_json::json!("nope");
        fold_vendored_skips_into_apply(&mut apply_obj, &[record("pkg:npm/b@1.0.0")]);
        assert_eq!(apply_obj, serde_json::json!("nope"));
    }

    /// With zero records the fold only strips the inner `status`: counts
    /// and patches stay exactly as the download phase reported them.
    #[test]
    fn fold_empty_records_only_strips_status() {
        let mut apply_obj = serde_json::json!({
            "status": "success",
            "found": 2,
            "skipped": 1,
            "patches": [{ "purl": "pkg:npm/a@1.0.0" }],
        });
        fold_vendored_skips_into_apply(&mut apply_obj, &[]);
        assert_eq!(
            apply_obj,
            serde_json::json!({
                "found": 2,
                "skipped": 1,
                "patches": [{ "purl": "pkg:npm/a@1.0.0" }],
            }),
            "only the status may change on the zero-record fold"
        );
    }
}
