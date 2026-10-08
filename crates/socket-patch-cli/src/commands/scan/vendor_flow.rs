//! The vendored-mode (`--mode vendored`) flow driven by
//! `scan`: the shared download → vendor-engine → GC step, its JSON and
//! interactive arms, the pre-download skip partitions, and the `boxed_*`
//! transient-frame constructors that keep the never-taken vendor branches
//! out of `run`'s poll frame (Windows 1 MiB main-thread stack).
//!
//! Vendored mode is manifest-free: the download phase fetches the patch
//! records in memory ([`download_patch_records_reusing`]), the vendor engine
//! embeds each record in its ledger entry (`detached: true`), and
//! `.socket/manifest.json` is never written — a project vendored by an
//! older, manifest-mode CLI is migrated on its next vendored run (see
//! [`migrate_legacy_manifest_records`]).
//!
//! One API client per run: `scan`/`get` build it once (proxy fallback
//! included) and thread it through the download phase and into the vendor
//! engine's service config; the views the download phase fetched seed the
//! in-memory stager, so no view is fetched twice.

use socket_patch_core::api::client::ApiClient;
use socket_patch_core::api::types::{BatchPackagePatches, PatchResponse, PatchSearchResult};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::telemetry::{track_patch_vendor_failed, PendingTelemetry};
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::{load_state, lookup_entry, save_state, VendorState};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::GlobalArgs;
use crate::commands::bun_preflight::bun_vendor_preflight_with_ledger;
use crate::commands::get::{download_patch_records_reusing, DetachedDownload, DownloadParams};
use crate::commands::lock_cli::lock_failure;
use crate::commands::vendor::{
    note_classic_migration_risk, symlinked_wiring_warnings, track_outcomes_for_vendor,
};
use crate::commands::vendored_backend::{records_manifest, ApplyRequest, VendoredBackend};
use crate::commands::vlt_preflight::{vlt_refusal_for, vlt_vendor_preflight_selected};
use crate::ecosystem_dispatch::NpmCrawlSnapshot;
use crate::json_envelope::{Command as EnvelopeCommand, Envelope};
use crate::ui::{plural, print_json};

use super::gc::{gc_json, print_gc_vendored_line, run_apply_gc};
use super::rollout::Stage;
use super::{
    classified_rows, discover_selected, download_params, embed_vex_into_json,
    emit_discovery_error_json, finish_rollout_json, push_run_warning, writers_of, ScanArgs,
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

/// Dry-run preview for `scan --mode vendored` (and `get … --mode vendored
/// --dry-run`): classify each selected patch against the vendor ledger
/// without writing anything or touching the network beyond discovery.
/// Action values are part of the CLI contract: `would_vendor` (no ledger
/// entry), `already_vendored` (entry at this uuid), `would_revendor` +
/// `oldUuid` (entry at an older uuid), and — additive — `would_refuse` +
/// `errorCode` + `error` for npm purls the wet run's Bun, vlt or npm
/// package-lock preflight
/// ([`crate::commands::bun_preflight::BunVendorRefusal`],
/// [`crate::commands::vlt_preflight`], [`npm_lock_refusal`]) would refuse
/// before any download.
/// The preview stays a ledger classification otherwise (engine refusals
/// outside the preflights are not predicted), and `would_refuse` never
/// flips the run's status or exit code. The preflights (the only disk
/// access besides the ledger) run only when the selection holds an npm purl.
/// `takeover_refusals` adds the hosted→vendored takeover refusals the
/// caller resolved (the gem gates of
/// [`crate::commands::vendor::gem_takeover_preview_refusals`]), keyed by
/// the selected purl, as `would_refuse` rows too.
pub(crate) async fn preview_vendor_json(
    cwd: &Path,
    selected: &[PatchSearchResult],
    takeover_refusals: &HashMap<String, (&'static str, String)>,
) -> serde_json::Value {
    // The ledger load outcome reaches the preflight AS a result, so an
    // unreadable ledger previews as `vendor_state_unreadable` rather than
    // as an empty ledger.
    let state = load_state(cwd).await;
    let refusal =
        bun_vendor_preflight_with_ledger(cwd, selected, state.as_ref().map(|s| &s.entries)).await;
    let vlt_refusals =
        vlt_vendor_preflight_selected(cwd, selected, state.as_ref().map(|s| &s.entries)).await;
    let npm_lock_refusal = npm_lock_refusal(cwd, selected).await;
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
            _ if vlt_refusal_for(&vlt_refusals, &p.purl).is_some() => {
                let r = vlt_refusal_for(&vlt_refusals, &p.purl).expect("checked by the guard");
                serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_refuse",
                    "errorCode": r.code, "error": r.detail,
                })
            }
            _ if takeover_refusals.contains_key(&p.purl) => {
                let (code, detail) = &takeover_refusals[&p.purl];
                serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_refuse",
                    "errorCode": code, "error": detail,
                })
            }
            _ if p.purl.starts_with("pkg:npm/") && npm_lock_refusal.is_some() => {
                let (code, detail) = npm_lock_refusal.as_ref().expect("checked by the guard");
                serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_refuse",
                    "errorCode": code, "error": detail,
                })
            }
            Some(e) if e.uuid == p.uuid => serde_json::json!({
                "purl": p.purl, "uuid": p.uuid, "action": "already_vendored",
            }),
            Some(e) => with_symlink_warnings(
                cwd,
                &p.purl,
                serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid,
                    "action": "would_revendor", "oldUuid": e.uuid,
                }),
            ),
            None => with_symlink_warnings(
                cwd,
                &p.purl,
                serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_vendor",
                }),
            ),
        })
        .collect();
    patches.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    serde_json::json!({ "dryRun": true, "patches": patches })
}

/// A `would_vendor` / `would_revendor` preview row, plus a `warnings` list
/// naming each symlinked wiring file the wet run's commit refuses to rename
/// over (see [`symlinked_wiring_warnings`]); no key when there are none.
fn with_symlink_warnings(cwd: &Path, purl: &str, mut row: serde_json::Value) -> serde_json::Value {
    let warnings: Vec<serde_json::Value> = symlinked_wiring_warnings(cwd, purl)
        .into_iter()
        .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail }))
        .collect();
    if !warnings.is_empty() {
        row["warnings"] = serde_json::Value::Array(warnings);
    }
    row
}

/// The purls of `selected` the wet run's Bun, vlt or npm package-lock
/// preflight, or the gem hosted→vendored takeover gate, would refuse before
/// any download (the `would_refuse` rows of [`preview_vendor_json`]): the
/// vendored planning pass, so a refused NEW patch holds no rollout slot.
pub(super) async fn preflight_refused_purls(
    common: &GlobalArgs,
    selected: &[PatchSearchResult],
) -> HashSet<String> {
    let cwd = common.cwd.as_path();
    let state = load_state(cwd).await;
    let refusal =
        bun_vendor_preflight_with_ledger(cwd, selected, state.as_ref().map(|s| &s.entries)).await;
    let vlt_refusals =
        vlt_vendor_preflight_selected(cwd, selected, state.as_ref().map(|s| &s.entries)).await;
    let npm_lock_refusal = npm_lock_refusal(cwd, selected).await;
    let gem_refusals = crate::commands::vendor::gem_takeover_preview_refusals(
        common,
        selected.iter().map(|p| p.purl.as_str()),
    )
    .await;
    selected
        .iter()
        .filter(|p| {
            refusal.as_ref().is_some_and(|r| r.applies_to(&p.purl))
                || vlt_refusal_for(&vlt_refusals, &p.purl).is_some()
                || (p.purl.starts_with("pkg:npm/") && npm_lock_refusal.is_some())
                || gem_refusals.contains_key(&p.purl)
        })
        .map(|p| p.purl.clone())
        .collect()
}

/// The npm package-lock backend's project-level refusal (a lock that is
/// not v2/v3, see [`socket_patch_core::vendor::npm_lock_vendor_preflight`]),
/// which refuses every npm purl of the project before any download or
/// takeover. Read only when the selection holds an npm purl.
async fn npm_lock_refusal(
    cwd: &Path,
    selected: &[PatchSearchResult],
) -> Option<(&'static str, String)> {
    if !selected.iter().any(|p| p.purl.starts_with("pkg:npm/")) {
        return None;
    }
    socket_patch_core::vendor::npm_lock_vendor_preflight(cwd).await
}

/// Human rendering of the vendored dry-run preview's `would_refuse` records
/// (see [`preview_vendor_json`]): the count line above it still says
/// "would download and vendor", so name what the wet run would refuse and
/// why. Shared by `scan --mode vendored --dry-run` and
/// `get … --mode vendored --dry-run` so the two cannot drift. Callers gate
/// it on `--silent`.
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
    for p in patches {
        for w in p["warnings"].as_array().into_iter().flatten() {
            println!(
                "  [warning] {} ({}): {}",
                p["purl"].as_str().unwrap_or_default(),
                w["code"].as_str().unwrap_or_default(),
                w["detail"].as_str().unwrap_or_default()
            );
        }
    }
}

/// Everything the vendor step takes: the in-memory `records` to vendor
/// (from [`download_patch_records_reusing`] or `get`'s download phase), the
/// blob `seed` that phase fetched (so the stager fetches no view twice),
/// the run's API client, and the run outcome so far for telemetry.
pub(crate) struct VendorStep<'a> {
    pub(crate) common: &'a GlobalArgs,
    pub(crate) records: HashMap<String, PatchRecord>,
    pub(crate) client: ApiClient,
    pub(crate) use_public_proxy: bool,
    /// Print "No vendorable patches in scope." when there are no records
    /// at all (the step is a silent no-op then). `get --mode vendored` and
    /// scan's JSON arm want it; scan's interactive arm prints its own
    /// closing line instead (see [`format_nothing_vendored`]).
    pub(crate) report_empty: bool,
    /// The npm half of scan's crawl, for the engine to reuse instead of
    /// walking the untouched tree again (see `vendor_records_reusing`).
    pub(crate) prior: Option<&'a NpmCrawlSnapshot>,
    /// The download phase failed or refused some patch: the run exits 1
    /// and its telemetry must not report a clean vendoring.
    pub(crate) download_errors: bool,
    pub(crate) telemetry_token: Option<&'a str>,
    pub(crate) telemetry_org: Option<&'a str>,
}

/// The one vendored-apply entry of `scan --mode vendored` (JSON and
/// interactive arms) and `get --mode vendored`: acquire the apply lock,
/// drive [`VendoredBackend::apply`] detached (every ledger entry embeds its
/// record) over the run's client, migrate any legacy manifest records the
/// ledger now owns, run the run-level advisories — all under the lock —
/// then report the run's telemetry.
///
/// An empty `records` map is a no-op BEFORE the lock: nothing is staged and
/// no `.socket/` is created.
///
/// `Ok((has_errors, envelope))` — `has_errors` includes
/// [`VendorStep::download_errors`]. `Err((code, message, envelope))` is a
/// lock/stage failure the caller folds into its own output shape. A lock
/// failure carries no envelope; a staging failure (`no_local_source`) hands
/// back the step's envelope demoted to `partialFailure`, so
/// `.vendor.status` inside a `"status":"error"` result never reads
/// `success`.
async fn run_vendor_step(step: VendorStep<'_>) -> VendorStepResult {
    let VendorStep {
        common,
        records,
        client,
        use_public_proxy,
        report_empty,
        prior,
        download_errors,
        telemetry_token,
        telemetry_org,
    } = step;
    let outcome = vendor_under_lock(
        common,
        records,
        client,
        use_public_proxy,
        report_empty,
        prior,
    )
    .await;
    match &outcome {
        // Telemetry follows the RUN outcome: a download-phase failure (a
        // Bun refusal, a failed view fetch) exits 1 and must not report a
        // successful vendoring of zero patches.
        Ok((vendor_errors, venv)) => {
            track_outcomes_for_vendor(
                download_errors || *vendor_errors,
                venv,
                common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await
        }
        Err((_, message, _)) => {
            track_patch_vendor_failed(message, common.dry_run, telemetry_token, telemetry_org).await
        }
    }
    outcome.map(|(vendor_errors, venv)| (download_errors || vendor_errors, venv))
}

/// [`run_vendor_step`]'s locked half (see there).
async fn vendor_under_lock(
    common: &GlobalArgs,
    records: HashMap<String, PatchRecord>,
    client: ApiClient,
    use_public_proxy: bool,
    report_empty: bool,
    prior: Option<&NpmCrawlSnapshot>,
) -> VendorStepResult {
    let mut env = Envelope::new(EnvelopeCommand::Vendor);
    env.dry_run = common.dry_run;
    if records.is_empty() {
        if report_empty && !common.json && !common.silent {
            println!("No vendorable patches in scope.");
        }
        return Ok((false, env));
    }
    // The one socket-dir / manifest-path derivation every caller shares.
    let manifest_path = common.resolved_manifest_path();
    let socket_dir = common.socket_dir();
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    // The guard lives to the end of the step so the ledger migration runs
    // under the lock too.
    let _guard =
        crate::commands::lock_cli::acquire_with_status(&socket_dir, timeout).map_err(|e| {
            let (code, message) = lock_failure(&e, timeout);
            (code, message, None)
        })?;

    // Staging probes blobs by the records' hashes; a manifest VIEW over the
    // in-memory records (a move, not a clone) is all it needs.
    let manifest = records_manifest(records);
    // The SAME service-config assembler the `vendor` command uses
    // (`--vendor-source` / `--vendor-url` / `--patch-server-url`), so
    // `scan --mode vendored` and `vendor` commit byte-identical artifacts.
    let service = common.vendor_service_config(Some(client), use_public_proxy);
    let applied = VendoredBackend::new(common, Some(&service))
        .apply(
            ApplyRequest {
                manifest: &manifest,
                socket_dir: &socket_dir,
                // Loaded ONCE under the lock: the staging harvest reads it,
                // then the engine takes it over for its persists.
                ledger: load_state(&common.cwd).await,
                // Always detached: vendored mode is manifest-free.
                detached: true,
                force: false,
                prior,
                committed: None,
            },
            &mut env,
        )
        .await;
    let has_errors = applied;
    migrate_legacy_manifest_records(common, &manifest_path, &manifest.patches, &mut env).await;
    if has_errors {
        env.mark_partial_failure();
    }
    note_classic_migration_risk(&mut env, &common.cwd, common);
    Ok((has_errors, env))
}

/// The ledger key addressable as `purl`: the exact key, else the entry
/// whose resolved `base_purl` equals it (see [`lookup_entry`]).
fn ledger_key_for(state: &VendorState, purl: &str) -> Option<String> {
    socket_patch_core::vendor::state::lookup_entry_kv(&state.entries, purl).map(|(k, _)| k.clone())
}

/// Migrate a project vendored by an older, manifest-mode CLI. For the purls
/// THIS run vendored (`records`, in-sync `already_vendored` skips included):
/// (1) a legacy entry in sync at a record's uuid is upgraded in place
/// (`detached: true` plus the embedded record), and (2) every
/// `.socket/manifest.json` record keyed by (or sharing a qualifier-stripped
/// base with) the purl's ledger entry is dropped, provided the entry is
/// detached with an embedded record AT the record's uuid. An emptied
/// manifest is left as `{"patches":{}}` (`list`/`apply`/`repair` distinguish
/// empty from missing). Scoped to the selection on purpose: an agent-mode
/// `get X` may record X at a NEWER uuid than the ledger's, a pending signal
/// a vendored run for another purl must not destroy. Idempotent; a project
/// with no manifest is untouched. Best-effort: failures are run-level
/// warnings, never run errors.
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

    // (2) Drop the manifest records the ledger now owns — for this run's
    // purls only, and only when the ledger holds the purl at the record's
    // uuid (a purl whose vendoring FAILED this run keeps its manifest record
    // and the standalone `vendor` remedy it drives).
    let mut dropped: Vec<String> = Vec::new();
    for (purl, record) in records {
        let Some(key) = ledger_key_for(&state, purl) else {
            continue;
        };
        let entry = &state.entries[&key];
        if !(entry.detached && entry.record.is_some() && entry.uuid == record.uuid) {
            continue;
        }
        let base = PurlKey::new(&entry.base_purl);
        let keys: Vec<String> = manifest
            .patches
            .keys()
            .filter(|k| *k == &key || *k == purl || PurlKey::new(k) == base)
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
    dropped.dedup();
    match write_manifest(manifest_path, &manifest).await {
        Ok(()) => push_run_warning(
            env,
            common,
            VENDOR_MANIFEST_RECORD_MIGRATED,
            format!(
                "{} moved to the vendor ledger (vendored mode is manifest-free): {}",
                plural(dropped.len(), "manifest record", "manifest records"),
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

/// The `scan --mode vendored` JSON path: discovery → (dry-run preview | download
/// → vendor engine → GC → embedded VEX) → print `result` → exit code.
/// The dry-run arm skips the VEX embed (emitting a `vex.skipped` marker
/// instead): a dry run vendors nothing, so there is no state to attest.
///
/// Extracted from `run` (and called through `Box::pin`) so its temporaries
/// get their own poll frame: `run`'s frame must fit Windows' 1 MiB
/// main-thread stack, and debug builds reserve slots for never-taken branches.
#[allow(clippy::too_many_arguments)]
async fn run_vendor_json_path(
    args: &ScanArgs,
    api_client: &ApiClient,
    use_public_proxy: bool,
    all_packages_with_patches: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    recorded: &super::rollout::RecordedState<'_>,
    batch_failed: bool,
    stage: &mut Stage,
    policy: &super::policy::ScanPolicy,
    result: &mut serde_json::Value,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored_purls: &HashSet<PurlKey>,
    prune: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
    // Scan's pending telemetry, flushed by `discover_selected` before
    // anything below writes to stdout.
    telemetry: &mut PendingTelemetry,
    // The npm half of scan's crawl, for the vendor engine to reuse.
    prior: Option<&NpmCrawlSnapshot>,
) -> i32 {
    // Same discovery as agent mode. Vendored purls are NOT filtered here —
    // re-vendoring a stale uuid is the point of the flag (same-uuid re-runs
    // land on the backend's `already_vendored` skip).
    let discovered = match discover_selected(
        api_client,
        all_packages_with_patches,
        can_access_paid_patches,
        policy,
        false,
        false,
        false,
        telemetry,
        Some(&mut *result),
    )
    .await
    {
        Ok(d) => d,
        Err((code, message)) => {
            emit_discovery_error_json(result, &message);
            return code;
        }
    };
    let rows = classified_rows(
        stage,
        &discovered,
        recorded,
        batch_failed,
        all_packages_with_patches,
        Some(&mut *result),
    );
    // The planning pass: a patch the preflight refuses holds no slot (it
    // still reaches the engine, which reports the refusal).
    let writers = writers_of(&rows);
    let refused = preflight_refused_purls(&args.common, &writers).await;
    stage.plan(&rows, |r| !refused.contains(&r.writer.purl));
    let deferred = stage.deferred_keys();
    let selected: Vec<PatchSearchResult> = writers
        .into_iter()
        .filter(|p| !deferred.contains(&(p.purl.clone(), p.uuid.clone())))
        .collect();
    finish_rollout_json(stage, result);

    if args.common.dry_run {
        // No downloads, no backends: classify against the ledger
        // and preview the GC, exactly like agent mode's dry run.
        let takeover = crate::commands::vendor::gem_takeover_preview_refusals(
            &args.common,
            selected.iter().map(|p| p.purl.as_str()),
        )
        .await;
        result["vendor"] = preview_vendor_json(&args.common.cwd, &selected, &takeover).await;
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
        // Embedded VEX is skipped on a dry run (nothing was vendored to
        // attest); the marker keeps the request visible to JSON consumers.
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
    let (dl_code, dl_json, records) =
        boxed_download_patch_records(&selected, &params, api_client, HashMap::new(), prior).await;
    result["download"] = dl_json;

    // 2) The vendor engine, under the same lock as apply/vendor (a no-op
    //    that creates nothing when there is nothing to vendor).
    let vendor_code = match boxed_vendor_step(VendorStep {
        common: &args.common,
        records,
        client: api_client.clone(),
        use_public_proxy,
        report_empty: true,
        prior,
        download_errors: dl_code != 0,
        telemetry_token,
        telemetry_org,
    })
    .await
    {
        Ok((has_errors, venv)) => {
            result["vendor"] =
                serde_json::to_value(&venv).unwrap_or_else(|_| serde_json::json!({}));
            i32::from(has_errors)
        }
        Err((code, message, venv)) => {
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
            if let Some(obj) = result.as_object_mut() {
                obj.remove("rollout");
            }
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

    let final_code = embed_vex_into_json(
        &args.common,
        &args.vex,
        manifest_path,
        vendor_code,
        result,
        false,
    )
    .await;
    print_json(result);
    final_code
}

/// The `scan --mode vendored` interactive arm: download → vendor engine → GC,
/// with human-readable output. `prefetched` holds the views the pre-download
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
    vendored_purls: &HashSet<PurlKey>,
    prune: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
    // The npm half of scan's crawl, for the vendor engine to reuse.
    prior: Option<&NpmCrawlSnapshot>,
) -> i32 {
    // The download phase is quiet about its own header in vendored mode
    // (only the manifest-mode download prints it), so this arm does.
    if !args.common.silent && !selected.is_empty() {
        eprintln!(
            "Downloading {}...",
            plural(selected.len(), "patch", "patches")
        );
    }
    let (dl_code, dl_json, records) =
        boxed_download_patch_records(selected, params, api_client, prefetched, prior).await;
    // Patches the download phase could not get (it reported each one).
    let download_failed = dl_json["failed"].as_u64().unwrap_or(0);
    // The vendor step is a silent no-op on an empty record set (it can't
    // know why it is empty); this arm can.
    let nothing_to_vendor = records.is_empty();
    let code = match boxed_vendor_step(VendorStep {
        common: &args.common,
        records,
        client: api_client.clone(),
        use_public_proxy,
        report_empty: false,
        prior,
        download_errors: dl_code != 0,
        telemetry_token,
        telemetry_org,
    })
    .await
    {
        Ok((has_errors, _venv)) => {
            if nothing_to_vendor && !args.common.silent {
                println!("{}", format_nothing_vendored(download_failed));
            }
            i32::from(has_errors)
        }
        // Human mode prints no per-event lines even on success, so the
        // carried envelope has no human rendering to feed — JSON mode is
        // where the reconcile events must survive (see the JSON fold above).
        Err((code, message, _envelope)) => {
            eprintln!("{}", format_vendor_step_error(code, &message));
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
        if !args.common.silent {
            // The agent arm's GC line: pruned entries AND swept files.
            if let Some(line) = super::gc::format_gc_line(&gc, false) {
                println!("{line}");
            }
            print_gc_vendored_line(&gc);
        }
    }
    code
}

/// The closing line when the vendor step had no patch records at all:
/// either the download phase failed or refused every patch (and listed
/// why), or there was nothing to vendor in the first place.
fn format_nothing_vendored(download_failed: u64) -> String {
    if download_failed > 0 {
        format!(
            "Nothing was vendored: {} failed (see above).",
            plural(download_failed as usize, "patch", "patches")
        )
    } else {
        "No vendorable patches in scope.".to_string()
    }
}

/// The human error line (plus any remediation hint) for a failed vendor
/// step: `Error (<code>): <Message>.`. The code and message are the ones
/// the JSON envelope carries.
pub(crate) fn format_vendor_step_error(code: &str, message: &str) -> String {
    let mut chars = message.trim_end_matches('.').chars();
    let message: String = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    };
    let mut out = if message.is_empty() {
        format!("Error ({code}).")
    } else {
        format!("Error ({code}): {message}.")
    };
    if code == "lock_held" {
        // Same advice as the other commands' lock error (lock_cli).
        out.push_str("\n  ");
        out.push_str(crate::commands::lock_cli::HELD_RETRY_HINT);
    }
    out
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
///   not-yet-appliable entry. `scan --mode vendored` handles these (the
///   vendor engine auto-fetches lockfile-resolved packages).
///
/// A plain fn (not inlined into `run`) so the json! temporaries don't ride
/// `run`'s async poll frame — see [`run_vendor_json_path`].
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
/// `download_and_apply_patches_with`: they were "found" by discovery and
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
/// and hand `run` only the heap pointer. `Box::pin(run_vendor_json_path(..))`
/// inline in `run` would materialize the future (which embeds the whole
/// vendor engine) as a stack temporary in `run`'s poll frame, which has to
/// fit Windows' 1 MiB main-thread stack.
#[allow(clippy::too_many_arguments)]
pub(super) fn boxed_vendor_json_path<'a>(
    args: &'a ScanArgs,
    api_client: &'a ApiClient,
    use_public_proxy: bool,
    all_packages_with_patches: &'a [BatchPackagePatches],
    can_access_paid_patches: bool,
    recorded: &'a super::rollout::RecordedState<'a>,
    batch_failed: bool,
    stage: &'a mut Stage,
    policy: &'a super::policy::ScanPolicy,
    result: &'a mut serde_json::Value,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    scanned_purls: &'a HashSet<String>,
    vendored_purls: &'a HashSet<PurlKey>,
    prune: bool,
    telemetry_token: Option<&'a str>,
    telemetry_org: Option<&'a str>,
    telemetry: &'a mut PendingTelemetry,
    prior: Option<&'a NpmCrawlSnapshot>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_vendor_json_path(
        args,
        api_client,
        use_public_proxy,
        all_packages_with_patches,
        can_access_paid_patches,
        recorded,
        batch_failed,
        stage,
        policy,
        result,
        manifest_path,
        socket_dir,
        scanned_purls,
        vendored_purls,
        prune,
        telemetry_token,
        telemetry_org,
        telemetry,
        prior,
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
    vendored_purls: &'a HashSet<PurlKey>,
    prune: bool,
    telemetry_token: Option<&'a str>,
    telemetry_org: Option<&'a str>,
    prior: Option<&'a NpmCrawlSnapshot>,
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
        prior,
    ))
}

/// Transient-frame boxed constructor for [`run_vendor_step`] — the one
/// vendored-apply entry for scan's two arms and for `get --mode vendored`.
/// Same Windows-stack rationale as [`boxed_vendor_json_path`], one level
/// down (the engine itself is boxed inside `VendoredBackend::apply`).
pub(crate) fn boxed_vendor_step<'a>(
    step: VendorStep<'a>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = VendorStepResult> + 'a>> {
    Box::pin(run_vendor_step(step))
}

/// Transient-frame boxed constructor for the download-phase future used
/// inside the vendor paths, so the frame fits Windows' 1 MiB main-thread
/// stack (same rationale as [`boxed_vendor_json_path`]).
fn boxed_download_patch_records<'a>(
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
    api_client: &'a ApiClient,
    prefetched: HashMap<String, PatchResponse>,
    prior: Option<&'a NpmCrawlSnapshot>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = DetachedDownload> + 'a>> {
    Box::pin(download_patch_records_reusing(
        selected, params, api_client, prefetched, prior,
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
                yarn_berry10c0: None,
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

    /// Every record for a purl THIS run vendored that the ledger now owns is
    /// dropped — exact key and qualified variants sharing the base purl —
    /// and an emptied manifest stays on disk as `{"patches":{}}`.
    #[tokio::test]
    async fn drops_this_runs_ledger_owned_records_and_leaves_an_emptied_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_ledger(root, entry(OTHER_UUID, true, Some(record(OTHER_UUID)))).await;
        seed_manifest(root, &[(PURL, UUID), (QUALIFIED, UUID)]);
        let manifest_path = root.join(".socket/manifest.json");
        let records: HashMap<String, PatchRecord> = [(PURL.to_string(), record(OTHER_UUID))].into();
        let mut env = Envelope::new(EnvelopeCommand::Vendor);

        migrate_legacy_manifest_records(&common(root), &manifest_path, &records, &mut env).await;

        assert_eq!(
            std::fs::read_to_string(&manifest_path).unwrap().trim(),
            "{\n  \"patches\": {}\n}",
            "an emptied manifest is kept, never deleted"
        );
        assert_eq!(warning_codes(&env), vec![VENDOR_MANIFEST_RECORD_MIGRATED]);
        let detail = &env.warnings[0].detail;
        assert!(
            detail.contains(PURL) && detail.contains(QUALIFIED),
            "{detail}"
        );
    }

    /// A ledger-owned entry this run did NOT vendor keeps its manifest
    /// record: agent-mode `get X` may have recorded X at a newer uuid than
    /// the ledger's (the user was told a `vendor` run refreshes the
    /// artifact), and a vendored run for some OTHER purl must not destroy
    /// that pending signal. Manifest and ledger stay byte-identical, no
    /// warning claims a migration that did not happen.
    #[tokio::test]
    async fn leaves_records_of_purls_this_run_did_not_vendor_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        seed_ledger(root, entry(UUID, true, Some(record(UUID)))).await;
        seed_manifest(root, &[(PURL, OTHER_UUID)]);
        let manifest_path = root.join(".socket/manifest.json");
        let before = std::fs::read(&manifest_path).unwrap();
        let ledger_before = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();
        let records: HashMap<String, PatchRecord> = [(OTHER.to_string(), record(UUID))].into();
        let mut env = Envelope::new(EnvelopeCommand::Vendor);

        migrate_legacy_manifest_records(&common(root), &manifest_path, &records, &mut env).await;

        assert_eq!(std::fs::read(&manifest_path).unwrap(), before);
        assert_eq!(
            std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
            ledger_before
        );
        assert!(env.warnings.is_empty(), "{:?}", env.warnings);
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
        let records: HashMap<String, PatchRecord> = [(PURL.to_string(), record(OTHER_UUID))].into();
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

    /// Without a Bun lock the preview is the plain ledger classification:
    /// `would_vendor` and nothing else.
    #[tokio::test]
    async fn preview_without_bun_lock_is_plain_would_vendor() {
        let tmp = tempfile::tempdir().unwrap();
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)], &HashMap::new()).await;
        assert_eq!(
            preview,
            serde_json::json!({
                "dryRun": true,
                "patches": [{ "purl": NPM, "uuid": UUID, "action": "would_vendor" }],
            })
        );
    }

    /// #627: `scan` / `get --mode vendored --dry-run` stop at this preview,
    /// so it carries the symlink advisory the wet run's commit would turn
    /// into `redirect_symlinked_file_unsupported` — for the npm purl whose
    /// `yarn.lock` is a link, not the PyPI one.
    #[cfg(unix)]
    #[tokio::test]
    async fn preview_warns_about_a_symlinked_wiring_file() {
        let tmp = tempfile::tempdir().unwrap();
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        std::os::unix::fs::symlink(
            shared.path().join("yarn.lock"),
            tmp.path().join("yarn.lock"),
        )
        .unwrap();
        let preview = preview_vendor_json(
            tmp.path(),
            &[sel(UUID, NPM), sel(UUID, PYPI)],
            &HashMap::new(),
        )
        .await;
        let npm = action_of(&preview, NPM);
        assert_eq!(npm["action"], "would_vendor", "{preview}");
        assert_eq!(
            npm["warnings"][0]["code"], "vendor_would_refuse_symlinked_file",
            "{preview}"
        );
        assert!(
            npm["warnings"][0]["detail"]
                .as_str()
                .is_some_and(|d| d.starts_with("yarn.lock is a symbolic link")),
            "{preview}"
        );
        assert!(
            action_of(&preview, PYPI).get("warnings").is_none(),
            "{preview}"
        );
    }

    /// A refused Bun tree flips npm purls to the additive `would_refuse`
    /// (with the vendor code + detail) and leaves other ecosystems alone.
    #[tokio::test]
    async fn preview_marks_would_refuse_for_refused_bun_tree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lock"), V1_WORKSPACE_LOCK).unwrap();
        let preview = preview_vendor_json(
            tmp.path(),
            &[sel(UUID, NPM), sel(UUID, PYPI)],
            &HashMap::new(),
        )
        .await;
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
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)], &HashMap::new()).await;
        assert_eq!(
            action_of(&preview, NPM)["action"],
            "would_refuse",
            "{preview}"
        );

        seed_entry(tmp.path(), NPM, OLD_UUID);
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)], &HashMap::new()).await;
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
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)], &HashMap::new()).await;
        assert_eq!(
            action_of(&preview, NPM)["action"],
            "already_vendored",
            "{preview}"
        );
    }

    /// Malformed bun.lockb: `would_refuse` with the binary format code.
    #[tokio::test]
    async fn preview_marks_a_refused_takeover_would_refuse() {
        const GEM: &str = "pkg:gem/rails@7.0.0";
        let tmp = tempfile::tempdir().unwrap();
        let refusals = HashMap::from([(
            GEM.to_string(),
            ("gemfile_declaration_not_editable", "indented".to_string()),
        )]);
        let preview =
            preview_vendor_json(tmp.path(), &[sel(UUID, GEM), sel(UUID, NPM)], &refusals).await;
        let gem = action_of(&preview, GEM);
        assert_eq!(gem["action"], "would_refuse", "{preview}");
        assert_eq!(gem["errorCode"], "gemfile_declaration_not_editable");
        assert_eq!(gem["error"], "indented");
        assert_eq!(action_of(&preview, NPM)["action"], "would_vendor");
    }

    #[tokio::test]
    async fn preview_marks_malformed_lockb_would_refuse() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let preview = preview_vendor_json(tmp.path(), &[sel(UUID, NPM)], &HashMap::new()).await;
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

/// Exact-string tests for the scan-driven vendor step's human lines.
#[cfg(test)]
mod ui_format_tests {
    use super::{format_nothing_vendored, format_vendor_step_error};

    #[test]
    fn nothing_vendored_line() {
        assert_eq!(
            format_nothing_vendored(0),
            "No vendorable patches in scope."
        );
        assert_eq!(
            format_nothing_vendored(1),
            "Nothing was vendored: 1 patch failed (see above)."
        );
        assert_eq!(
            format_nothing_vendored(2),
            "Nothing was vendored: 2 patches failed (see above)."
        );
    }

    #[test]
    fn step_error_is_capitalized_with_one_period() {
        assert_eq!(
            format_vendor_step_error(
                "no_local_source",
                "patch artifacts unavailable (offline or download failure)"
            ),
            "Error (no_local_source): Patch artifacts unavailable (offline or download failure)."
        );
        assert_eq!(format_vendor_step_error("x", "done."), "Error (x): Done.");
        assert_eq!(format_vendor_step_error("x", ""), "Error (x).");
        assert_eq!(format_vendor_step_error("x", "état"), "Error (x): État.");
    }

    #[test]
    fn lock_held_carries_the_wait_hint() {
        assert_eq!(
            format_vendor_step_error(
                "lock_held",
                "another socket-patch process is operating in this directory"
            ),
            "Error (lock_held): Another socket-patch process is operating in this directory.\n  \
             Wait for it to finish, or retry with --lock-timeout <secs> to wait for the lock."
        );
    }
}
