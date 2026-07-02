//! The vendored-mode (`--mode vendored` / `--vendor`) flow driven by
//! `scan`: the shared download + GC + vendor-engine step, its JSON and
//! interactive arms, the pre-download skip partitions, and the `boxed_*`
//! transient-frame constructors that keep the never-taken vendor branches
//! out of `run`'s poll frame (Windows 1 MiB main-thread stack).

use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply_lock;
use socket_patch_core::utils::telemetry::{track_patch_vendor_failed, track_patch_vendored};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::GlobalArgs;
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::get::{download_and_apply_patches, download_patch_records, DownloadParams};
use crate::commands::vendor::{reconcile_dropped, vendor_records};
use crate::json_envelope::{Command as EnvelopeCommand, Envelope};

use super::gc::{gc_json, print_gc_vendored_line, run_apply_gc};
use super::{discover_selected, download_params, embed_vex_into_json, ScanArgs};

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
/// [`partition_vendored_selected`].
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
pub(super) fn boxed_vendor_interactive_path<'a>(
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
