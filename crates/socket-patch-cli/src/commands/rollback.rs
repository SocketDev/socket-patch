use clap::Args;
use socket_patch_core::api::blob_fetcher::{fetch_blobs_by_hash, format_fetch_result};
use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::cleanup_blobs::{cleanup_unused_archives, cleanup_unused_blobs};
use socket_patch_core::manifest::operations::{
    get_before_hash_blobs, read_manifest, write_manifest,
};
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::select_installed_variants;
use socket_patch_core::patch::rollback::{
    cannot_rollback_error, rollback_package_patch, verify_file_rollback, RollbackResult,
    VerifyRollbackResult, VerifyRollbackStatus,
};
use socket_patch_core::telemetry::{track_patch_rollback_failed, track_patch_rolled_back};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::apply::is_local_go;
use crate::commands::lock_cli::acquire_or_emit;
use crate::commands::remove::patch_matches;
use crate::ecosystem_dispatch::{find_all_packages_for_rollback, partition_purls};
use crate::json_envelope::Command as EnvelopeCommand;
use crate::looks_like_uuid;

/// Pin the beforeHash blobs of `purls` into `reference` as synthetic keep
/// records: `cleanup_unused_blobs` keeps only afterHash blobs (beforeHash
/// blobs are normally re-downloadable on demand), so each pinned
/// before-hash is listed in an afterHash slot. Scoped to REVERT data only
/// — the pinned entries' real afterHash blobs stay sweepable like any
/// other orphan. Shared by rollback's default GC and `remove`'s
/// crawler-miss guard.
pub(crate) fn pin_before_hash_blobs<'a>(
    reference: &mut PatchManifest,
    source: &PatchManifest,
    purls: impl IntoIterator<Item = &'a String>,
) {
    for purl in purls {
        let Some(record) = source.patches.get(purl) else {
            continue;
        };
        let pinned: HashMap<String, PatchFileInfo> = record
            .files
            .iter()
            .filter(|(_, info)| !info.before_hash.is_empty())
            .map(|(file, info)| {
                (
                    file.clone(),
                    PatchFileInfo {
                        before_hash: String::new(),
                        after_hash: info.before_hash.clone(),
                    },
                )
            })
            .collect();
        if pinned.is_empty() {
            continue; // every file was created-by-patch: no revert blobs
        }
        let mut keep_record = record.clone();
        keep_record.files = pinned;
        reference.patches.insert(purl.clone(), keep_record);
    }
}

#[derive(Args)]
pub struct RollbackArgs {
    /// What to roll back: a package PURL, a patch UUID, or a path glob
    /// (e.g. `packages/foo`, `apps/**`) selecting the patches whose
    /// installed copies live under matching paths. Multiple targets union.
    /// Omit to roll back ALL patch state — in-place patches, vendored
    /// patches, and hosted lockfile redirects.
    ///
    /// A token counts as a path only when it is path-shaped (contains a
    /// separator or a glob metacharacter, or is `./`-prefixed/absolute);
    /// anything else keeps the PURL/UUID identifier semantics, so a
    /// mistyped identifier stays a safe error rather than becoming a path
    /// scope. Path targets select installed copies — manifest entries with
    /// no installed package are reachable only by identifier or unscoped
    /// runs. Rollback restores EVERY installed copy of a selected patch:
    /// patches are tracked per-package, not per-path.
    pub targets: Vec<String>,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Rollback a patch by fetching beforeHash blobs from API (no manifest required).
    ///
    /// `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    /// clap's default bool parser accepts only the literal strings
    /// `true`/`false` from the env binding, so `SOCKET_ONE_OFF=1` (or an
    /// exported-but-empty `SOCKET_ONE_OFF=`) aborted every `rollback`
    /// invocation. This flag is also outside `GLOBAL_ARG_ENV_VARS`, so
    /// `main`'s empty-var scrub never rescues it.
    #[arg(
        long = "one-off",
        env = "SOCKET_ONE_OFF",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub one_off: bool,

    /// Restore the system (files and lockfiles) but PRESERVE the local
    /// patch state for a later re-apply: manifest entries are kept,
    /// vendored artifacts and their ledger entries are kept (only the
    /// lockfile wiring is reverted), and no blob/archive cleanup runs.
    /// Hosted redirects have no preservable local state — their ledger
    /// records describe live wiring and are dropped with it either way.
    #[arg(
        long = "preserve-state",
        env = "SOCKET_PRESERVE_STATE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub preserve_state: bool,
}

/// One classified rollback target token.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RollbackTarget {
    /// PURL or UUID — today's `patch_matches` semantics.
    Identifier(String),
    /// A path glob scoping the run to patches with an installed copy
    /// under a matching path.
    PathGlob(String),
}

/// Shape-classify a target token. Only path-SHAPED tokens become globs
/// (separator, glob metachar, `./` prefix, or absolute); `pkg:` and every
/// other bare word keep identifier semantics, so a truncated UUID or a
/// package name typed without its `pkg:` prefix stays a safe
/// "No patch found matching identifier" error instead of silently
/// selecting a directory subtree.
pub(crate) fn classify_target(token: &str) -> RollbackTarget {
    if token.starts_with("pkg:") {
        return RollbackTarget::Identifier(token.to_string());
    }
    let path_shaped = token.contains('/')
        || token.contains('\\')
        || token.contains(['*', '?', '['])
        || Path::new(token).is_absolute();
    if path_shaped {
        RollbackTarget::PathGlob(token.to_string())
    } else {
        RollbackTarget::Identifier(token.to_string())
    }
}

struct PatchToRollback {
    purl: String,
    patch: PatchRecord,
}

/// Everything one rollback pass learned.
///
/// `success` means "no attempted rollback failed" — per-package semantics
/// only. Entries whose package is not installed are NOT failures and never
/// flip it: apply and rollback are deliberately asymmetric here. Apply's job
/// is "make the tree patched", so an unmatched purl means the job was NOT
/// done (apply's all-unmatched run exits 1 / `partialFailure`); rollback's
/// job is "make the tree unpatched", and a not-installed package already
/// satisfies that end state — so even a run whose in-scope targets ALL turn
/// out not-installed exits 0 / `success`. Do not "fix" this into symmetry:
/// `remove` also rides on it (it drops long-uninstalled entries from the
/// manifest via its "No packages found to rollback" path).
struct RollbackOutcome {
    /// No attempted rollback failed (per-package; see above).
    success: bool,
    results: Vec<RollbackResult>,
    /// Vendor-owned purls excluded from in-place rollback (benign).
    vendored_skipped: Vec<String>,
    /// In-scope manifest entries with no installed package on disk —
    /// apply's `unmatched` twin (`package_not_installed`). Never in the
    /// before-blob plan, never a failed result. Sorted for determinism.
    not_installed: Vec<String>,
    /// The run aborted at the before-blob gate BEFORE any restore ran
    /// (offline with missing blobs, or a failed download). The CLI
    /// boundary's manifest-cleanup default must skip entirely: nothing
    /// was restored, so nothing is removable and the GC must not sweep
    /// the revert data the retry needs.
    aborted: bool,
}

/// How `rollback_patches_inner` selects manifest entries.
enum InnerSelection<'a> {
    /// The legacy single-identifier filter (`remove`'s delegation): a
    /// no-match identifier is an error, a missing manifest is an error,
    /// and `None` selects the whole manifest.
    Identifier(Option<&'a str>),
    /// A pre-resolved purl set from the CLI boundary's target resolver
    /// (identifiers ∪ path globs ∪ everything). No-match and
    /// missing-manifest handling already happened upstream, so an empty
    /// selection is a quiet success; `announce_empty` keeps the unscoped
    /// run's "No patches found in manifest" line.
    Scope {
        purls: &'a HashSet<String>,
        announce_empty: bool,
    },
}

// ── local-redirect rollback helpers (go only) ────────────────────────────────
// Local go rolls back by dropping the project-local redirect (go's `replace`
// directive) + the patched copy — no in-place restore, no before-blob. Cargo
// patches in place (vendored or registry cache), so it rolls back in place from
// before-blobs like npm/pypi. The helper is an inert stub without `golang`.
// `is_local_go` is shared with `apply`, which creates the same redirects.

/// True when `purl` rolls back by dropping a project-local redirect (local-mode
/// go) rather than restoring bytes from a before-blob. The before-blob gate uses
/// this to skip those PURLs — they read no blobs, so a missing before-blob must
/// not block (or trigger a needless download for) an offline redirect rollback.
fn is_local_redirect(purl: &str, common: &GlobalArgs) -> bool {
    if is_local_go(purl, common) {
        return true;
    }
    let _ = (purl, common);
    false
}

/// Copy of `manifest` with local-redirect PURLs (local-mode go) removed — used
/// for the before-blob gate, which those PURLs never need. Avoids blocking an
/// offline redirect rollback on absent blobs.
fn exclude_local_redirects(manifest: &PatchManifest, common: &GlobalArgs) -> PatchManifest {
    PatchManifest {
        patches: manifest
            .patches
            .iter()
            .filter(|(purl, _)| !is_local_redirect(purl, common))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        setup: manifest.setup.clone(),
    }
}

/// Roll back a local-go redirect (drop the `go.mod` `replace` directive + the
/// patched copy under `.socket/go-patches/`), or `None` if `purl` isn't a
/// local-go target (caller falls back to in-place rollback). The module cache
/// is left pristine by the redirect, so there is no before-blob to restore;
/// mirrors apply's `try_local_go_apply`. Go has no `vendor/` fallthrough (apply
/// always redirects local go), so there is no vendored discriminator here.
async fn try_rollback_local_go(
    purl: &str,
    pkg_path: &Path,
    patch: &PatchRecord,
    common: &GlobalArgs,
) -> Option<RollbackResult> {
    use socket_patch_core::patch::redirect::golang_local::remove_go_redirect;
    use socket_patch_core::vendor::go_mod_edit::{ReplaceOwner, GO_PATCHES_DIR};
    if !is_local_go(purl, common) {
        return None;
    }
    let mut result = RollbackResult {
        package_key: purl.to_string(),
        package_path: pkg_path.display().to_string(),
        success: true,
        files_verified: Vec::new(),
        // The engine leaves `files_rolled_back` empty on dry-run (verify
        // only); match it so the JSON `rolledBack` count never claims a dry
        // run mutated anything.
        files_rolled_back: if common.dry_run {
            Vec::new()
        } else {
            patch.files.keys().cloned().collect()
        },
        error: None,
        // The go redirect leaves the module cache pristine — no in-place
        // bytes changed, so there is no sidecar state to resync.
        sidecar: None,
    };
    if let Err(e) = remove_go_redirect(
        purl,
        &common.cwd,
        GO_PATCHES_DIR,
        ReplaceOwner::GoPatches,
        common.dry_run,
    )
    .await
    {
        result.success = false;
        result.files_rolled_back.clear();
        result.error = Some(e.to_string());
    }
    Some(result)
}

fn find_patches_to_rollback(
    manifest: &PatchManifest,
    identifier: Option<&str>,
) -> Vec<PatchToRollback> {
    manifest
        .patches
        .iter()
        .filter(|(purl, patch)| identifier.is_none_or(|id| patch_matches(purl, &patch.uuid, id)))
        .map(|(purl, patch)| PatchToRollback {
            purl: purl.clone(),
            patch: patch.clone(),
        })
        .collect()
}

async fn get_missing_before_blobs(manifest: &PatchManifest, blobs_path: &Path) -> HashSet<String> {
    let before_blobs = get_before_hash_blobs(manifest);
    let mut missing = HashSet::new();
    for hash in before_blobs {
        let blob_path = blobs_path.join(&hash);
        if tokio::fs::metadata(&blob_path).await.is_err() {
            missing.insert(hash);
        }
    }
    missing
}

fn verify_rollback_status_str(status: &VerifyRollbackStatus) -> &'static str {
    match status {
        VerifyRollbackStatus::Ready => "ready",
        VerifyRollbackStatus::AlreadyOriginal => "already_original",
        VerifyRollbackStatus::HashMismatch => "hash_mismatch",
        VerifyRollbackStatus::NotFound => "not_found",
        VerifyRollbackStatus::MissingBlob => "missing_blob",
    }
}

/// True when every file the engine verified for this package is already
/// at its original (`beforeHash`) state — i.e. the rollback is a complete
/// no-op on disk.
///
/// This is the rollback-side mirror of apply's `all_files_already_patched`.
/// The `!is_empty()` guard is essential: `Iterator::all` over an empty
/// slice is vacuously `true`. Without it a result with no verified files
/// — a zero-file patch record, or a result whose `files_verified` came
/// back empty — would be mislabeled "already original" and miscounted as
/// a no-op even though nothing matched `beforeHash`.
pub(crate) fn all_files_already_original(result: &RollbackResult) -> bool {
    !result.files_verified.is_empty()
        && result
            .files_verified
            .iter()
            .all(|f| f.status == VerifyRollbackStatus::AlreadyOriginal)
}

/// Number of packages that have files which actually need restoring,
/// used by the dry-run summary. Successful-but-already-original packages
/// are no-ops reported on their own line, so they are excluded here —
/// mirroring apply's dry-run split — to avoid double-counting them
/// against "can be rolled back".
fn can_rollback_count(results: &[RollbackResult]) -> usize {
    let successful = results.iter().filter(|r| r.success).count();
    let already_original = results
        .iter()
        .filter(|r| r.success && all_files_already_original(r))
        .count();
    successful.saturating_sub(already_original)
}

fn result_to_json(result: &RollbackResult) -> serde_json::Value {
    serde_json::json!({
        "purl": result.package_key,
        "path": result.package_path,
        "success": result.success,
        "error": result.error,
        "filesRolledBack": result.files_rolled_back,
        // Rollback-side sidecar resync record (e.g. cargo's
        // `.cargo-checksum.json` rewritten back to original hashes), or
        // an error-severity advisory when the resync failed. Null when
        // no sidecar applied — same serialization as `error` above.
        "sidecar": result.sidecar,
        "filesVerified": result.files_verified.iter().map(|f| {
            serde_json::json!({
                "file": f.file,
                "status": verify_rollback_status_str(&f.status),
                "message": f.message,
                "currentHash": f.current_hash,
                "expectedHash": f.expected_hash,
                "targetHash": f.target_hash,
            })
        }).collect::<Vec<_>>(),
    })
}

/// Skipped marker appended to `results[]` for an in-scope manifest entry
/// with no installed package — apply's `package_not_installed` Skipped
/// event, rollback-side. Deliberately NOT a result record: no `success`,
/// no `error`, `path` null (there is no installed tree to name), and it
/// never counts toward `rolledBack`/`failed` or flips the status —
/// rollback exits 0 even when ALL in-scope targets land here (see
/// `RollbackOutcome` for the apply/rollback asymmetry).
fn skipped_not_installed_json(purl: &str) -> serde_json::Value {
    serde_json::json!({
        "purl": purl,
        "path": null,
        "skipped": "package_not_installed",
    })
}

/// Per-package failure results for the pre-flight before-blob abort.
///
/// The abort fires before the rollback loop produces any per-package
/// results, so without these the `--json` envelope claimed `failed: 0`
/// with empty `results[]` on an exit-1 run — contentless and
/// self-contradictory, and `--json` mutes the stderr explanation the
/// human path gets. One failed result per affected package keeps the
/// `failed` counter meaning "packages that failed" (the same per-package
/// semantics as a mid-run failure) and names each missing blob hash plus
/// the `socket-patch repair` remedy in machine-readable form, using the
/// engine's own `missing_blob` verify vocabulary. `reason_for` renders
/// the per-hash diagnostic (offline gate vs. download failure).
fn missing_blob_abort_results(
    gate_manifest: &PatchManifest,
    missing_blobs: &HashSet<String>,
    all_packages: &HashMap<String, PathBuf>,
    reason_for: impl Fn(&str) -> String,
) -> Vec<RollbackResult> {
    // The manifest map is a HashMap — sort so the envelope is deterministic.
    let mut purls: Vec<&String> = gate_manifest.patches.keys().collect();
    purls.sort();
    let mut results = Vec::new();
    for purl in purls {
        let patch = &gate_manifest.patches[purl];
        let mut files: Vec<(&String, &PatchFileInfo)> = patch
            .files
            .iter()
            .filter(|(_, info)| {
                // Empty beforeHash is the created-by-patch sentinel: no
                // blob backs it, so it can never be "missing".
                !info.before_hash.is_empty() && missing_blobs.contains(&info.before_hash)
            })
            .collect();
        if files.is_empty() {
            continue;
        }
        files.sort_by(|a, b| a.0.cmp(b.0));
        let files_verified: Vec<VerifyRollbackResult> = files
            .iter()
            .map(|(file, info)| VerifyRollbackResult {
                file: (*file).clone(),
                status: VerifyRollbackStatus::MissingBlob,
                message: Some(reason_for(&info.before_hash)),
                current_hash: None,
                expected_hash: None,
                target_hash: Some(info.before_hash.clone()),
            })
            .collect();
        // The engine's own first-blocking-file error constructor, so this
        // synthesized abort is byte-identical to a mid-run missing-blob
        // failure.
        let first = &files_verified[0];
        let error = cannot_rollback_error(
            &first.file,
            first
                .message
                .as_deref()
                .expect("message is set for every synthesized entry above"),
        );
        results.push(RollbackResult {
            package_key: purl.clone(),
            // The gate feeds only attempted (crawler-discovered) targets
            // here, so a path is always present; the empty-string fallback
            // is defensive against that invariant breaking upstream.
            package_path: all_packages
                .get(purl)
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            success: false,
            files_verified,
            files_rolled_back: Vec::new(),
            error: Some(error),
            sidecar: None,
        });
    }
    results
}

/// Legacy top-level error emission (the pre-envelope rollback shape):
/// `{status: "error", error}` on `--json`, an `Error:` stderr line
/// otherwise. Errors print even under --silent ("errors only", never
/// "nothing").
fn emit_rollback_error(json: bool, msg: &str) {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "error": msg,
            }))
            .expect("serializing an in-memory JSON value cannot fail")
        );
    } else {
        eprintln!("Error: {msg}");
    }
}

/// What the vendored leg did. Keys are LEDGER keys (which may differ from
/// manifest purls in qualifier spelling); each list feeds one envelope
/// array.
#[derive(Default)]
struct VendoredLegOutcome {
    /// Reverted: lockfile unwired, artifact deleted, ledger entry dropped
    /// (previewed on dry-run).
    reverted: Vec<String>,
    /// `--preserve-state`: lockfile unwired, artifact + ledger entry kept.
    preserved: Vec<String>,
    /// Drift-keeps: the backend refused to touch a drifted lock; entry,
    /// artifact, and manifest record all stay (exit 1 — the system is
    /// still patched).
    kept: Vec<(String, String)>,
    failed: Vec<(String, String)>,
    warnings: Vec<(String, String)>,
}

/// What the hosted leg did.
#[derive(Default)]
struct HostedLegOutcome {
    reverted: Vec<String>,
    failed: Vec<(String, String)>,
    /// Scoped targets whose ecosystem has no per-purl hosted revert.
    unsupported: Vec<String>,
    warnings: Vec<(String, String)>,
    edited_files: std::collections::BTreeSet<String>,
}

/// Unwire the in-scope vendored entries. `preserve` keeps artifacts and
/// ledger entries (only the lockfile wiring is restored); otherwise a
/// clean revert drops the entry and saves the ledger per purl
/// (crash-consistent, like `vendor --revert`).
async fn run_vendored_leg(
    common: &GlobalArgs,
    keys: &[String],
    state: &mut socket_patch_core::vendor::VendorState,
    preserve: bool,
) -> VendoredLegOutcome {
    use crate::commands::vendor::dispatch_revert_one_opts;
    use socket_patch_core::vendor::{save_state, RevertOpts};

    let mut out = VendoredLegOutcome::default();
    for key in keys {
        let Some(entry) = state.entries.get(key).cloned() else {
            continue;
        };
        let outcome = dispatch_revert_one_opts(
            &entry,
            &common.cwd,
            RevertOpts {
                dry_run: common.dry_run,
                keep_artifact: preserve,
            },
        )
        .await;
        for w in &outcome.warnings {
            if !common.json && !common.silent {
                eprintln!("Warning ({}): {}", w.code, w.detail);
            }
            out.warnings.push((w.code.to_string(), w.detail.clone()));
        }
        if !outcome.success {
            let why = outcome
                .error
                .as_deref()
                .unwrap_or("unknown error")
                .to_string();
            // Errors print even under --silent.
            if !common.json {
                eprintln!("Failed to revert vendoring for {key}: {why}");
            }
            out.failed.push((key.clone(), why));
            continue;
        }
        if outcome.kept_artifact {
            // Drift-keep: the lock changed under us; the backend left both
            // the wiring and the artifact alone. The entry (and the
            // manifest record) must survive — see RevertOutcome's contract.
            out.kept.push((
                key.clone(),
                "lockfile wiring drifted; vendored state left untouched".to_string(),
            ));
            continue;
        }
        if common.dry_run {
            if !common.json && !common.silent {
                if preserve {
                    println!("Would unwire vendoring for {key} (artifact preserved)");
                } else {
                    println!("Would revert vendoring for {key}");
                }
            }
            if preserve {
                out.preserved.push(key.clone());
            } else {
                out.reverted.push(key.clone());
            }
            continue;
        }
        if preserve {
            // Ledger entry kept byte-identical: its wiring records now
            // describe already-reverted fragments, which later reverts
            // replay as silent no-ops (the liveness contract), and a
            // re-vendor re-wires from the live lock probe.
            if !common.json && !common.silent {
                println!("Unwired vendoring for {key} (artifact preserved)");
            }
            out.preserved.push(key.clone());
        } else {
            state.entries.remove(key);
            if let Err(e) = save_state(&common.cwd, state).await {
                out.failed.push((key.clone(), format!("vendor ledger write failed: {e}")));
                continue;
            }
            if !common.json && !common.silent {
                println!("Reverted vendoring for {key}");
            }
            out.reverted.push(key.clone());
        }
    }
    out
}

/// Unwind the in-scope hosted redirects: per-purl reverts where they
/// exist (cargo + npm-family), and — when the scope covers the ENTIRE
/// record set — the whole-ledger reverse replay for everything else.
/// Mutates `state`; the caller persists on wet runs.
async fn run_hosted_leg(
    common: &GlobalArgs,
    purls: &[String],
    state: &mut socket_patch_core::patch::redirect::RedirectState,
    replay_eligible: bool,
) -> HostedLegOutcome {
    use socket_patch_core::patch::redirect::{
        redirect_revert_supported, revert_redirect_purl, revert_remaining_redirect_edits,
    };

    let mut out = HostedLegOutcome::default();
    // bun.lock edits hard-refuse the per-purl npm revert; when the replay
    // will run it owns them instead, so npm purls on bun projects defer
    // rather than fail.
    let has_bun_edits = state
        .edits
        .iter()
        .any(|e| e.kind == "redirect_bun_lock_package" || e.kind == "redirect_bun_lockb_migrated");
    let mut deferred_to_replay: Vec<String> = Vec::new();
    for purl in purls {
        let defer_bun = has_bun_edits && purl.starts_with("pkg:npm/") && replay_eligible;
        if !defer_bun && redirect_revert_supported(purl) {
            match revert_redirect_purl(&common.cwd, state, purl, common.dry_run).await {
                Ok(revert) => {
                    if !common.json && !common.silent {
                        if common.dry_run {
                            println!("Would unwind hosted redirect for {purl}");
                        } else {
                            println!("Unwound hosted redirect for {purl}");
                        }
                    }
                    out.edited_files
                        .extend(revert.reverted_files.iter().cloned());
                    out.reverted.push(purl.clone());
                }
                Err(e) => {
                    if !common.json {
                        eprintln!("Failed to unwind hosted redirect for {purl}: {e}");
                    }
                    out.failed.push((purl.clone(), e));
                }
            }
        } else if replay_eligible {
            deferred_to_replay.push(purl.clone());
        } else {
            if !common.json {
                eprintln!(
                    "Cannot unwind hosted redirect for {purl}: no per-purl revert exists for \
                     this ecosystem. Run an unscoped `socket-patch rollback` to unwind ALL \
                     hosted redirects, or re-run `scan --mode hosted` to normalize."
                );
            }
            out.unsupported.push(purl.clone());
        }
    }
    // The whole-ledger replay runs when the scope covers every record
    // (however it was spelled), and also as the "last one out turns off
    // the lights" pass — per-purl reverts never claim the non-package
    // rideshare edits (pnpm trustLockfile, the bun.lockb migration
    // marker), so an emptied record map with leftover edits replays them
    // here too.
    if replay_eligible || (state.records.is_empty() && !state.edits.is_empty()) {
        let replay = revert_remaining_redirect_edits(&common.cwd, state, common.dry_run).await;
        for refusal in &replay.refusals {
            let files: Vec<&str> = refusal.files.iter().map(String::as_str).collect();
            let why = format!("{} ({})", refusal.reason, files.join(", "));
            if !common.json {
                eprintln!("Cannot unwind hosted redirect edits ({}): {why}", refusal.group);
            }
            out.failed.push((format!("group:{}", refusal.group), why));
        }
        out.warnings.extend(replay.warnings.iter().cloned());
        out.edited_files.extend(replay.reverted_files.iter().cloned());
        // Deferred purls succeeded iff the replay dropped their records.
        for purl in deferred_to_replay {
            if replay.dropped_records.iter().any(|p| p == &purl) {
                if !common.json && !common.silent {
                    if common.dry_run {
                        println!("Would unwind hosted redirect for {purl}");
                    } else {
                        println!("Unwound hosted redirect for {purl}");
                    }
                }
                out.reverted.push(purl);
            } else if !out.failed.iter().any(|(p, _)| p.starts_with("group:")) {
                out.failed
                    .push((purl, "hosted redirect edits could not be replayed".into()));
            }
        }
    }
    out
}

pub async fn run(args: RollbackArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Classify targets up front: the one-off stub and the glob validation
    // are pre-network usage checks.
    let mut identifiers: Vec<String> = Vec::new();
    let mut path_patterns: Vec<String> = Vec::new();
    for token in &args.targets {
        match classify_target(token) {
            RollbackTarget::Identifier(id) => identifiers.push(id),
            RollbackTarget::PathGlob(p) => path_patterns.push(p),
        }
    }

    // Bail on the unimplemented flag BEFORE constructing the API client:
    // client construction can auto-resolve the org slug over the network,
    // and the contract promises the one-off stub fails before any network
    // or disk activity.
    if args.one_off {
        let msg = if identifiers.is_empty() {
            "--one-off requires an identifier (UUID or PURL)"
        } else {
            "One-off rollback mode is not yet implemented"
        };
        if args.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": msg,
                }))
                .expect("serializing an in-memory JSON value cannot fail")
            );
        } else {
            eprintln!("Error: {msg}");
        }
        return 1;
    }

    // An unparseable glob is a usage error — same exit-2 stderr shape as
    // scan's self-enforced mode conflicts.
    let path_scope = match crate::path_scope::PathScope::parse(&path_patterns) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = args.common.resolved_manifest_path();
    let cwd = args.common.cwd.clone();

    // ── state discovery ─────────────────────────────────────────────────
    // Rollback infers what to undo from the three state stores: the
    // manifest (in-place/agent patches), the vendor ledger (vendored
    // patches), and the redirect ledger (hosted lockfile redirects). A
    // missing manifest is no longer fatal when a ledger holds work.
    let manifest_missing = tokio::fs::metadata(&manifest_path).await.is_err();
    let vendor_state_result = socket_patch_core::vendor::load_state(&cwd).await;
    let redirect_state_result =
        socket_patch_core::patch::redirect::load_redirect_state(&cwd).await;

    let vendor_present = vendor_state_result
        .as_ref()
        .is_ok_and(|s| !s.entries.is_empty());
    let redirect_present = redirect_state_result
        .as_ref()
        .is_ok_and(|s| s.as_ref().is_some_and(|s| !s.records.is_empty() || !s.edits.is_empty()));
    let vendor_corrupt = vendor_state_result.is_err();
    let redirect_corrupt = redirect_state_result.is_err();

    if manifest_missing && !vendor_present && !redirect_present {
        if vendor_corrupt || redirect_corrupt {
            // The only state on disk is unreadable: nothing can be safely
            // undone. Fail closed naming the store.
            let msg = if vendor_corrupt {
                format!(
                    "cannot read .socket/vendor/state.json: {}",
                    vendor_state_result.as_ref().expect_err("checked corrupt above")
                )
            } else {
                format!(
                    "cannot read the hosted redirect ledger: {}",
                    redirect_state_result
                        .as_ref()
                        .expect_err("checked corrupt above")
                )
            };
            emit_rollback_error(args.common.json, &msg);
            return 1;
        }
        // Ledger-less but still wired? (a deleted/uncommitted state.json
        // with lockfiles still consuming `.socket/vendor/` artifacts is a
        // supported recovery state — `repair` reconstructs the ledger.)
        let wired = crate::commands::repair_vendor::scan_vendor_references(&cwd).await;
        if !wired.is_empty() {
            emit_rollback_error(
                args.common.json,
                "lockfiles still reference .socket/vendor/ artifacts but the vendor ledger \
                 is missing — run `socket-patch repair` to reconstruct it, then roll back",
            );
            return 1;
        }
        if args.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": "Manifest not found",
                    "path": manifest_path.display().to_string(),
                }))
                .expect("serializing an in-memory JSON value cannot fail")
            );
        } else {
            // Errors print even under --silent ("errors only", never
            // "nothing"): exit 1 with no message would be undiagnosable.
            eprintln!("Manifest not found at {}", manifest_path.display());
        }
        return 1;
    }

    // Serialize against concurrent socket-patch runs targeting the
    // same `.socket/` directory. See
    // `socket_patch_core::patch::apply_lock`.
    let socket_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let _lock = match acquire_or_emit(
        &socket_dir,
        EnvelopeCommand::Rollback,
        args.common.json,
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
    ) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

    // ── scope resolution ────────────────────────────────────────────────
    let manifest = if manifest_missing {
        PatchManifest::new()
    } else {
        match read_manifest(&manifest_path).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                track_patch_rollback_failed(
                    "Invalid manifest",
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
                emit_rollback_error(args.common.json, "Invalid manifest");
                return 1;
            }
            Err(e) => {
                let msg = e.to_string();
                track_patch_rollback_failed(&msg, api_token.as_deref(), org_slug.as_deref())
                    .await;
                emit_rollback_error(args.common.json, &msg);
                return 1;
            }
        }
    };
    let vendor_entries: Vec<(String, socket_patch_core::vendor::VendorEntry)> =
        match &vendor_state_result {
            Ok(s) => {
                let mut v: Vec<_> = s
                    .entries
                    .iter()
                    .map(|(k, e)| (k.clone(), e.clone()))
                    .collect();
                v.sort_by(|a, b| a.0.cmp(&b.0));
                v
            }
            Err(_) => Vec::new(),
        };
    let redirect_records: Vec<(String, String)> = match &redirect_state_result {
        Ok(Some(s)) => s
            .records
            .iter()
            .map(|(purl, rec)| (purl.clone(), rec.uuid.clone()))
            .collect(),
        _ => Vec::new(),
    };

    let scoped = !identifiers.is_empty() || !path_scope.is_empty();

    // Identifier matching runs across ALL THREE stores; an identifier
    // matching nothing anywhere is the familiar exit-1 error.
    let mut manifest_scope: HashSet<String> = HashSet::new();
    let mut vendor_scope: HashSet<String> = HashSet::new();
    let mut hosted_scope: HashSet<String> = HashSet::new();
    if identifiers.is_empty() && path_scope.is_empty() {
        manifest_scope.extend(manifest.patches.keys().cloned());
        vendor_scope.extend(vendor_entries.iter().map(|(k, _)| k.clone()));
        hosted_scope.extend(redirect_records.iter().map(|(p, _)| p.clone()));
    }
    for id in &identifiers {
        let mut matched = false;
        for (purl, patch) in &manifest.patches {
            if patch_matches(purl, &patch.uuid, id) {
                manifest_scope.insert(purl.clone());
                matched = true;
            }
        }
        for (key, entry) in &vendor_entries {
            if patch_matches(key, &entry.uuid, id)
                || patch_matches(&entry.base_purl, &entry.uuid, id)
            {
                vendor_scope.insert(key.clone());
                matched = true;
            }
        }
        for (purl, uuid) in &redirect_records {
            if patch_matches(purl, uuid, id) {
                hosted_scope.insert(purl.clone());
                matched = true;
            }
        }
        if !matched {
            let hint = if id.starts_with("pkg:") || looks_like_uuid(id) {
                String::new()
            } else {
                format!(" (to target a directory instead, use ./{id} or {id}/**)")
            };
            let msg = format!("No patch found matching identifier: {id}{hint}");
            track_patch_rollback_failed(&msg, api_token.as_deref(), org_slug.as_deref()).await;
            if args.common.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "error",
                        "error": msg,
                        "rolledBack": 0,
                        "alreadyOriginal": 0,
                        "failed": 0,
                        "dryRun": args.common.dry_run,
                        "vendored": [],
                        "results": [],
                    }))
                    .expect("serializing an in-memory JSON value cannot fail")
                );
            } else {
                eprintln!("Error: {msg}");
            }
            return 1;
        }
    }

    // Path scoping: discover installed copies of every candidate purl and
    // select the purls with a copy under a matching path. Each pattern
    // must select something — an empty pattern is an error, protecting a
    // mistyped target from silently becoming an empty (or wrong) scope.
    if !path_scope.is_empty() {
        let mut candidates: Vec<String> = manifest.patches.keys().cloned().collect();
        candidates.extend(vendor_entries.iter().map(|(k, _)| k.clone()));
        candidates.extend(redirect_records.iter().map(|(p, _)| p.clone()));
        candidates.sort();
        candidates.dedup();
        let partitioned = partition_purls(&candidates, args.common.ecosystems.as_deref());
        let crawler_options = CrawlerOptions {
            cwd: cwd.clone(),
            global: args.common.global,
            global_prefix: args.common.global_prefix.clone(),
        };
        let discovered = find_all_packages_for_rollback(
            &partitioned,
            &crawler_options,
            args.common.silent || args.common.json,
        )
        .await;
        let mut matched_patterns: HashSet<usize> = HashSet::new();
        let mut path_selected: HashSet<String> = HashSet::new();
        for (purl, paths) in &discovered {
            for path in paths {
                for (idx, raw) in path_scope.raw().iter().enumerate() {
                    let single = crate::path_scope::PathScope::parse(std::slice::from_ref(raw))
                        .expect("already parsed above");
                    if single.matches(&cwd, path) {
                        matched_patterns.insert(idx);
                        path_selected.insert(purl.clone());
                    }
                }
            }
        }
        if let Some(unmatched) = path_scope
            .raw()
            .iter()
            .enumerate()
            .find(|(idx, _)| !matched_patterns.contains(idx))
        {
            let msg = format!(
                "path pattern matched no patched packages: {} (path targets select \
                 installed copies; patches for uninstalled packages are reachable by \
                 identifier or an unscoped rollback)",
                unmatched.1
            );
            track_patch_rollback_failed(&msg, api_token.as_deref(), org_slug.as_deref()).await;
            emit_rollback_error(args.common.json, &msg);
            return 1;
        }
        for purl in &path_selected {
            if manifest.patches.contains_key(purl) {
                manifest_scope.insert(purl.clone());
            }
            for (key, entry) in &vendor_entries {
                if key == purl || &entry.base_purl == purl {
                    vendor_scope.insert(key.clone());
                }
            }
            if redirect_records.iter().any(|(p, _)| p == purl) {
                hosted_scope.insert(purl.clone());
            }
        }
    }

    // `--ecosystems` narrows every leg (the manifest side is scoped inside
    // the agent engine as before).
    if args.common.ecosystems.is_some() {
        vendor_scope.retain(|key| {
            vendor_entries
                .iter()
                .find(|(k, _)| k == key)
                .is_some_and(|(_, e)| {
                    crate::commands::vendor::ecosystem_in_scope(&args.common, &e.ecosystem)
                })
        });
        hosted_scope.retain(|purl| {
            Ecosystem::from_purl(purl)
                .is_some_and(|e| crate::commands::vendor::ecosystem_in_scope(&args.common, e.cli_name()))
        });
    }

    // The whole-ledger hosted replay (which covers the ecosystems without
    // a per-purl revert) runs only when the scope covers EVERY record —
    // however the scope was spelled.
    let replay_eligible = match &redirect_state_result {
        Ok(Some(s)) => s.records.keys().all(|p| hosted_scope.contains(p)),
        _ => false,
    };

    // Corrupt-ledger containment: a corrupt store fails ONLY the legs that
    // need it; the agent leg still restores files (emergency restores are
    // never blocked by an unrelated corrupt ledger). Cleanup/GC also skip
    // fail-closed — ownership cannot be established.
    let mut run_warnings: Vec<(String, String)> = Vec::new();
    if vendor_corrupt {
        run_warnings.push((
            "vendor_state_unreadable".into(),
            format!(
                "cannot read .socket/vendor/state.json: {} — the vendored leg, manifest \
                 cleanup, and GC were skipped",
                vendor_state_result.as_ref().expect_err("checked corrupt above")
            ),
        ));
    }
    if redirect_corrupt {
        run_warnings.push((
            "redirect_state_unreadable".into(),
            format!(
                "cannot read the hosted redirect ledger: {} — the hosted leg was skipped; \
                 quarantine or restore .socket/vendor/redirect-state.json and re-run",
                redirect_state_result
                    .as_ref()
                    .expect_err("checked corrupt above")
            ),
        ));
    }

    // ── confirmation ────────────────────────────────────────────────────
    // The default run deletes manifest entries, vendored artifacts, ledger
    // records, and unused blobs — prompt once, remove-style. Auto-accepted
    // under --yes/--json/non-TTY; skipped for previews and for
    // --preserve-state runs (which delete no local state).
    let has_work =
        !manifest_scope.is_empty() || !vendor_scope.is_empty() || !hosted_scope.is_empty();
    if has_work && !args.common.dry_run && !args.preserve_state {
        let detached_count = vendor_entries
            .iter()
            .filter(|(k, e)| vendor_scope.contains(k) && e.detached)
            .count();
        let mut prompt = format!(
            "Roll back {} patch(es), remove them from the local manifest",
            manifest_scope.len().max(1)
        );
        if !vendor_scope.is_empty() {
            prompt.push_str(&format!(
                ", and delete {} vendored artifact(s)",
                vendor_scope.len()
            ));
        }
        if detached_count > 0 {
            prompt.push_str(&format!(
                " ({detached_count} detached — their embedded patch records are the only \
                 local copy)"
            ));
        }
        prompt.push('?');
        if !crate::output::confirm(&prompt, true, args.common.yes, args.common.json) {
            if !args.common.json && !args.common.silent {
                println!("Rollback cancelled.");
            }
            return 0;
        }
    }

    // ── agent leg (in-place restore) ────────────────────────────────────
    let selection = InnerSelection::Scope {
        purls: &manifest_scope,
        announce_empty: !scoped,
    };
    match rollback_patches_inner(
        &args.common,
        &manifest_path,
        selection,
        Some(&telemetry_client),
    )
    .await
    {
        Ok(RollbackOutcome {
            success: agent_success,
            results,
            vendored_skipped: vendored_excluded,
            not_installed,
            aborted,
        }) => {
            // ── vendored leg ─────────────────────────────────────────────
            // The in-scope ledger entries: unwire the lockfiles and (by
            // default) delete the artifacts + drop the entries.
            // `--preserve-state` keeps artifacts and entries. Skipped
            // fail-closed when the ledger is unreadable.
            let mut vendored_leg = VendoredLegOutcome::default();
            if !vendor_corrupt && !vendor_scope.is_empty() {
                let mut vs = vendor_state_result
                    .as_ref()
                    .ok()
                    .cloned()
                    .unwrap_or_default();
                let mut keys: Vec<String> = vendor_scope.iter().cloned().collect();
                keys.sort();
                vendored_leg =
                    run_vendored_leg(&args.common, &keys, &mut vs, args.preserve_state).await;
            }
            // `vendored` (the legacy "benign, untouched" array) now lists
            // only vendor-owned purls the run did NOT act on — i.e. the
            // corrupt-ledger skip. Acted-on entries land in the
            // vendoredReverted/vendoredPreserved/vendoredKept arrays.
            let vendored: Vec<String> = if vendor_corrupt {
                vendored_excluded.clone()
            } else {
                Vec::new()
            };

            // ── hosted leg ───────────────────────────────────────────────
            let mut hosted_leg = HostedLegOutcome::default();
            if !redirect_corrupt {
                if let Ok(Some(existing)) = &redirect_state_result {
                    let mut st = existing.clone();
                    let before = (st.edits.len(), st.records.len());
                    let mut purls: Vec<String> = hosted_scope.iter().cloned().collect();
                    purls.sort();
                    if !purls.is_empty() || (replay_eligible && !st.edits.is_empty()) {
                        hosted_leg =
                            run_hosted_leg(&args.common, &purls, &mut st, replay_eligible).await;
                        let changed =
                            (st.edits.len(), st.records.len()) != before;
                        if !args.common.dry_run && changed {
                            if let Err(e) =
                                socket_patch_core::patch::redirect::persist_redirect_state(
                                    &cwd, &st,
                                )
                                .await
                            {
                                let msg =
                                    format!("failed to persist the hosted redirect ledger: {e}");
                                if !args.common.json {
                                    eprintln!("Error: {msg}");
                                }
                                hosted_leg.failed.push(("ledger".to_string(), msg));
                            }
                        }
                    }
                }
            }

            // ── manifest cleanup ─────────────────────────────────────────
            // The new default: entries whose state was fully undone leave
            // the manifest, and the now-unused blobs/archives are swept.
            // Fail-closed skips: --preserve-state, a blob-gate abort
            // (nothing was restored), and an unreadable vendor ledger
            // (ownership unknowable).
            let failed_purls: HashSet<String> = results
                .iter()
                .filter(|r| !r.success)
                .map(|r| r.package_key.clone())
                .collect();
            let cleanup_allowed = !args.preserve_state && !aborted && !vendor_corrupt;
            // A vendor-owned manifest purl is removable only when its
            // ledger entry was cleanly reverted this run (drift-keeps and
            // failures keep the record; the matching mirrors the
            // ledger-key / base-purl / qualifier-stripped triple).
            let vendored_reverted_ok = |purl: &str| {
                vendored_leg.reverted.iter().any(|key| {
                    key == purl
                        || strip_purl_qualifiers(key) == strip_purl_qualifiers(purl)
                        || vendor_entries
                            .iter()
                            .find(|(k, _)| k == key)
                            .is_some_and(|(_, e)| e.base_purl == strip_purl_qualifiers(purl))
                })
            };
            let succeeded_purls: HashSet<String> = results
                .iter()
                .filter(|r| r.success)
                .map(|r| r.package_key.clone())
                .collect();
            let mut removable: Vec<String> = manifest_scope
                .iter()
                .filter(|purl| {
                    if failed_purls.contains(*purl) {
                        return false;
                    }
                    if vendored_excluded.contains(purl) {
                        return vendored_reverted_ok(purl);
                    }
                    succeeded_purls.contains(*purl) || not_installed.contains(purl)
                })
                .cloned()
                .collect();
            removable.sort();

            let mut removed: Vec<String> = Vec::new();
            let mut updated_manifest = manifest.clone();
            let mut manifest_write_failed: Option<String> = None;
            if cleanup_allowed && !removable.is_empty() {
                updated_manifest
                    .patches
                    .retain(|purl, _| !removable.contains(purl));
                removed = removable.clone();
                if !args.common.dry_run {
                    if let Err(e) = write_manifest(&manifest_path, &updated_manifest).await {
                        manifest_write_failed = Some(e.to_string());
                        removed.clear();
                        updated_manifest = manifest.clone();
                    }
                }
            }

            // ── GC ───────────────────────────────────────────────────────
            // Sweep against the post-removal manifest, with beforeHash
            // blobs pinned (synthetic afterHash-slot records — the sweep
            // keeps only afterHash blobs) for (a) removed-but-not-installed
            // entries — a crawler miss must not destroy the only local
            // revert data — and (b) in-scope entries that FAILED this run:
            // their entries stay, and the blobs the gate just downloaded
            // must survive for an offline retry.
            let mut gc_json: serde_json::Value = serde_json::json!({ "skipped": true });
            let mut gc_bytes_freed: u64 = 0;
            if cleanup_allowed {
                let mut cleanup_reference = updated_manifest.clone();
                let pinned_purls: Vec<&String> = removed
                    .iter()
                    .filter(|p| not_installed.contains(p))
                    .chain(manifest_scope.iter().filter(|p| failed_purls.contains(*p)))
                    .collect();
                pin_before_hash_blobs(&mut cleanup_reference, &manifest, pinned_purls);
                let blobs_dir = socket_dir.join("blobs");
                let mut removed_blobs = 0usize;
                let mut removed_diffs = 0usize;
                let mut removed_packages = 0usize;
                match cleanup_unused_blobs(&cleanup_reference, &blobs_dir, args.common.dry_run)
                    .await
                {
                    Ok(r) => {
                        removed_blobs = r.blobs_removed;
                        gc_bytes_freed += r.bytes_freed;
                    }
                    Err(e) => run_warnings.push((
                        "cleanup_failed".into(),
                        format!("blob cleanup failed: {e}"),
                    )),
                }
                for (dir, slot) in [
                    ("diffs", &mut removed_diffs),
                    ("packages", &mut removed_packages),
                ] {
                    match cleanup_unused_archives(
                        &cleanup_reference,
                        &socket_dir.join(dir),
                        args.common.dry_run,
                    )
                    .await
                    {
                        Ok(r) => {
                            *slot = r.blobs_removed;
                            gc_bytes_freed += r.bytes_freed;
                        }
                        Err(e) => run_warnings.push((
                            "cleanup_failed".into(),
                            format!("{dir} cleanup failed: {e}"),
                        )),
                    }
                }
                gc_json = serde_json::json!({
                    "removedBlobs": removed_blobs,
                    "removedDiffArchives": removed_diffs,
                    "removedPackageArchives": removed_packages,
                    "bytesFreed": gc_bytes_freed,
                });
            }

            // ── run-level warnings ───────────────────────────────────────
            let unwired_any = !vendored_leg.reverted.is_empty()
                || !vendored_leg.preserved.is_empty()
                || !hosted_leg.reverted.is_empty();
            if unwired_any {
                run_warnings.push((
                    "reinstall_required".into(),
                    "unwired packages keep their patched bytes in installed trees until \
                     the next package-manager install"
                        .into(),
                ));
            }
            if args.preserve_state && !hosted_leg.reverted.is_empty() {
                run_warnings.push((
                    "hosted_state_not_preservable".into(),
                    "hosted redirects have no preservable local state: their ledger \
                     records were dropped with the unwound wiring; re-run \
                     `scan --mode hosted` to re-wire"
                        .into(),
                ));
            }
            if !path_scope.is_empty() {
                let out_of_scope: Vec<&str> = results
                    .iter()
                    .filter(|r| {
                        r.success
                            && !r.files_rolled_back.is_empty()
                            && !path_scope.matches(&cwd, Path::new(&r.package_path))
                    })
                    .map(|r| r.package_key.as_str())
                    .collect();
                if !out_of_scope.is_empty() {
                    run_warnings.push((
                        "out_of_scope_copies_restored".into(),
                        format!(
                            "rollback restores every installed copy of a selected patch; \
                             {} restored cop{} outside the given paths",
                            out_of_scope.len(),
                            if out_of_scope.len() == 1 { "y lives" } else { "ies live" }
                        ),
                    ));
                }
            }
            vendored_leg
                .warnings
                .iter()
                .chain(hosted_leg.warnings.iter())
                .for_each(|(code, detail)| run_warnings.push((code.clone(), detail.clone())));

            // ── status / exit ────────────────────────────────────────────
            // Not-installed entries never flip the exit code (see
            // `RollbackOutcome`). Everything that leaves the system still
            // patched DOES: agent failures, vendored drift-keeps and
            // failures, hosted refusals/unsupported targets, corrupt
            // ledgers, and a failed manifest write.
            let success = agent_success
                && vendored_leg.kept.is_empty()
                && vendored_leg.failed.is_empty()
                && hosted_leg.failed.is_empty()
                && hosted_leg.unsupported.is_empty()
                && !vendor_corrupt
                && !redirect_corrupt
                && manifest_write_failed.is_none();
            let rolled_back_count = results
                .iter()
                .filter(|r| r.success && !r.files_rolled_back.is_empty())
                .count();
            let already_original_count = results
                .iter()
                .filter(|r| r.success && all_files_already_original(r))
                .count();
            let failed_count = results.iter().filter(|r| !r.success).count();

            if let Some(e) = &manifest_write_failed {
                if !args.common.json {
                    eprintln!("Error: failed to update the manifest: {e}");
                }
                run_warnings.push((
                    "manifest_write_failed".into(),
                    format!("failed to update the manifest: {e}"),
                ));
            }

            if args.common.json {
                // Legacy shape plus the additive duality keys — every key
                // always present so consumers never null-check.
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": if success { "success" } else { "partial_failure" },
                        "rolledBack": rolled_back_count,
                        "alreadyOriginal": already_original_count,
                        "failed": failed_count,
                        "dryRun": args.common.dry_run,
                        "warnings": run_warnings
                            .iter()
                            .map(|(code, detail)| serde_json::json!({
                                "code": code, "detail": detail,
                            }))
                            .collect::<Vec<_>>(),
                        // Vendor-owned purls the run did NOT act on (the
                        // corrupt-ledger skip); acted-on entries are in the
                        // vendored* arrays below.
                        "vendored": vendored,
                        "vendoredReverted": vendored_leg.reverted,
                        "vendoredPreserved": vendored_leg.preserved,
                        "vendoredKept": vendored_leg.kept
                            .iter()
                            .map(|(key, reason)| serde_json::json!({
                                "purl": key, "reason": reason,
                            }))
                            .collect::<Vec<_>>(),
                        "hosted": {
                            "reverted": hosted_leg.reverted,
                            "failed": hosted_leg.failed
                                .iter()
                                .map(|(purl, error)| serde_json::json!({
                                    "purl": purl, "error": error,
                                }))
                                .collect::<Vec<_>>(),
                            "unsupported": hosted_leg.unsupported,
                            "editedFiles": hosted_leg.edited_files.len(),
                        },
                        "manifest": {
                            "removedEntries": removed,
                            "preserved": args.preserve_state,
                        },
                        "gc": gc_json,
                        "paths": path_scope.raw(),
                        // Real result records first, then one skipped marker
                        // per in-scope entry with no installed package —
                        // apply's `package_not_installed` Skipped event,
                        // rollback-side. Markers never count toward
                        // `rolledBack`/`failed` and never flip the status.
                        "results": results
                            .iter()
                            .map(result_to_json)
                            .chain(not_installed.iter().map(|p| skipped_not_installed_json(p)))
                            .collect::<Vec<_>>(),
                    }))
                    .expect("serializing an in-memory JSON value cannot fail")
                );
            } else if !args.common.silent && !results.is_empty() {
                let rolled_back: Vec<_> = results
                    .iter()
                    .filter(|r| r.success && !r.files_rolled_back.is_empty())
                    .collect();
                let already_original: Vec<_> = results
                    .iter()
                    .filter(|r| r.success && all_files_already_original(r))
                    .collect();
                let failed: Vec<_> = results.iter().filter(|r| !r.success).collect();

                if args.common.dry_run {
                    println!("\nRollback verification complete:");
                    // Exclude already-original packages — they are
                    // reported separately just below, so counting them
                    // here too would double-report each no-op.
                    let can_rollback = can_rollback_count(&results);
                    println!("  {can_rollback} package(s) can be rolled back");
                    if !already_original.is_empty() {
                        println!(
                            "  {} package(s) already in original state",
                            already_original.len()
                        );
                    }
                    if !failed.is_empty() {
                        println!("  {} package(s) cannot be rolled back", failed.len());
                    }
                } else {
                    if !rolled_back.is_empty() || !already_original.is_empty() {
                        println!("\nRolled back packages:");
                        for result in &rolled_back {
                            println!("  {}", result.package_key);
                        }
                        for result in &already_original {
                            println!("  {} (already original)", result.package_key);
                        }
                    }
                    if !failed.is_empty() {
                        println!("\nFailed to rollback:");
                        for result in &failed {
                            println!(
                                "  {}: {}",
                                result.package_key,
                                result.error.as_deref().unwrap_or("unknown error")
                            );
                        }
                    }
                }

                if args.common.verbose {
                    println!("\nDetailed verification:");
                    for result in &results {
                        println!("  {}:", result.package_key);
                        for f in &result.files_verified {
                            // Same labels as the JSON status strings, with the
                            // underscores humanized (`already_original` →
                            // `already original`).
                            let status_str =
                                verify_rollback_status_str(&f.status).replace('_', " ");
                            println!("    {} [{}]", f.file, status_str);
                            if let Some(ref msg) = f.message {
                                println!("      message: {msg}");
                            }
                            if let Some(ref h) = f.current_hash {
                                println!("      current:  {h}");
                            }
                            if let Some(ref h) = f.expected_hash {
                                println!("      expected: {h}");
                            }
                            if let Some(ref h) = f.target_hash {
                                println!("      target:   {h}");
                            }
                        }
                    }
                }
            }

            if !args.common.json && !args.common.silent {
                if !vendored.is_empty() {
                    println!(
                        "\n{} vendored package(s) skipped (vendor ledger unreadable; \
                         quarantine or restore .socket/vendor/state.json and re-run):",
                        vendored.len()
                    );
                    for purl in &vendored {
                        println!("  {purl}");
                    }
                }
                for (key, reason) in &vendored_leg.kept {
                    eprintln!("Kept vendored state for {key}: {reason}");
                }
                if args.common.dry_run {
                    if cleanup_allowed && !removed.is_empty() {
                        println!("\nWould remove {} patch(es) from manifest:", removed.len());
                        for purl in &removed {
                            println!("  - {purl}");
                        }
                    }
                } else if !removed.is_empty() {
                    println!("\nRemoved {} patch(es) from manifest:", removed.len());
                    for purl in &removed {
                        println!("  - {purl}");
                    }
                } else if args.preserve_state && has_work {
                    println!(
                        "\nManifest entries and vendored artifacts preserved \
                         (--preserve-state); re-apply with `socket-patch apply` or \
                         `socket-patch vendor`."
                    );
                }
                if gc_bytes_freed > 0 {
                    println!(
                        "{} {} bytes of unused blobs/archives",
                        if args.common.dry_run {
                            "Would free"
                        } else {
                            "Freed"
                        },
                        gc_bytes_freed
                    );
                }
                if unwired_any {
                    println!(
                        "\nNote: unwired packages keep their patched bytes in installed \
                         trees until the next package-manager install."
                    );
                }
            }

            // Apply's unmatched warning, rollback-side — informational only
            // (the run still exits 0; see `RollbackOutcome`), so --silent
            // mutes it like every other non-error notice.
            if !args.common.json && !args.common.silent && !not_installed.is_empty() {
                eprintln!(
                    "\nWarning: {} manifest patch(es) had no matching installed package:",
                    not_installed.len()
                );
                for purl in &not_installed {
                    eprintln!("  - {purl}");
                }
            }

            if success {
                track_patch_rolled_back(
                    rolled_back_count,
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            } else {
                track_patch_rollback_failed(
                    "One or more rollbacks failed",
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            }

            if success {
                0
            } else {
                1
            }
        }
        Err(e) => {
            track_patch_rollback_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
            if args.common.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "error",
                        "error": e,
                        "rolledBack": 0,
                        "alreadyOriginal": 0,
                        "failed": 0,
                        "dryRun": args.common.dry_run,
                        "vendored": [],
                        "results": [],
                    }))
                    .expect("serializing an in-memory JSON value cannot fail")
                );
            } else {
                // Errors print even under --silent ("errors only", never
                // "nothing"): exit 1 with no message would be undiagnosable.
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn rollback_patches_inner(
    common: &GlobalArgs,
    manifest_path: &Path,
    selection: InnerSelection<'_>,
    // The client `run()` already built. Constructing one per phase printed
    // the core client's "No SOCKET_API_TOKEN set" notice once per
    // construction — twice in a single rollback. `None` (the `remove`
    // delegation path) builds one on demand, only when the blob download
    // below actually fires.
    api_client: Option<&ApiClient>,
) -> Result<RollbackOutcome, String> {
    // The Scope selection tolerates a missing manifest (ledger-only
    // projects reach here with hosted/vendored work and no manifest);
    // the Identifier selection keeps the legacy hard requirement.
    let manifest = match read_manifest(manifest_path).await.map_err(|e| e.to_string())? {
        Some(m) => m,
        None => match &selection {
            InnerSelection::Identifier(_) => return Err("Invalid manifest".to_string()),
            InnerSelection::Scope { .. } => PatchManifest::new(),
        },
    };

    let socket_dir = manifest_path
        .parent()
        .expect("manifest path names a file, so it has a parent");
    let mut blobs_path = socket_dir.join("blobs");
    // `--dry-run` must not mutate `.socket/` ("Preview, no mutations"):
    // don't create the blobs dir; a throwaway stage replaces it below.
    if !common.dry_run {
        tokio::fs::create_dir_all(&blobs_path)
            .await
            .map_err(|e| e.to_string())?;
    }

    let patches_to_rollback = match &selection {
        InnerSelection::Identifier(identifier) => {
            find_patches_to_rollback(&manifest, identifier.as_deref())
        }
        InnerSelection::Scope { purls, .. } => manifest
            .patches
            .iter()
            .filter(|(purl, _)| purls.contains(*purl))
            .map(|(purl, patch)| PatchToRollback {
                purl: purl.clone(),
                patch: patch.clone(),
            })
            .collect(),
    };

    if patches_to_rollback.is_empty() {
        match &selection {
            InnerSelection::Identifier(Some(identifier)) => {
                return Err(format!("No patch found matching identifier: {identifier}"));
            }
            InnerSelection::Identifier(None) => {
                if !common.silent && !common.json {
                    println!("No patches found in manifest");
                }
            }
            InnerSelection::Scope { announce_empty, .. } => {
                // No-match errors were the resolver's job; an empty scoped
                // selection here just means the work lives in other legs.
                if *announce_empty && !common.silent && !common.json {
                    println!("No patches found in manifest");
                }
            }
        }
        return Ok(RollbackOutcome {
            success: true,
            results: Vec::new(),
            vendored_skipped: Vec::new(),
            not_installed: Vec::new(),
            aborted: false,
        });
    }

    // Vendor-owned purls are excluded from in-place rollback: their patch
    // lives in the committed `.socket/vendor/` artifact + lock wiring, not
    // in the installed tree, so before-blob restoration is meaningless
    // there (and would only hash-mismatch). `remove` reverts vendoring;
    // `vendor --revert` undoes it wholesale. Matching mirrors apply's
    // ledger-key / base-purl / qualifier-stripped triple; unreadable state
    // degrades to "nothing vendored".
    let vendored_keys = socket_patch_core::vendor::vendored_purl_keys(&common.cwd).await;
    let is_vendored =
        |p: &str| vendored_keys.contains(p) || vendored_keys.contains(strip_purl_qualifiers(p));
    let (vendored_targets, patches_to_rollback): (Vec<_>, Vec<_>) = patches_to_rollback
        .into_iter()
        .partition(|p| is_vendored(&p.purl));
    let mut vendored_skipped: Vec<String> = vendored_targets.into_iter().map(|p| p.purl).collect();
    vendored_skipped.sort();
    if patches_to_rollback.is_empty() {
        // Everything targeted is vendor-owned: a benign skip, not an error
        // (and not `not_found` — the identifier did match).
        return Ok(RollbackOutcome {
            success: true,
            results: Vec::new(),
            vendored_skipped,
            not_installed: Vec::new(),
            aborted: false,
        });
    }

    // Create filtered manifest (a synthetic rollback-target subset, never
    // written to disk, so it carries no persisted setup state).
    let filtered_manifest = PatchManifest {
        patches: patches_to_rollback
            .iter()
            .map(|p| (p.purl.clone(), p.patch.clone()))
            .collect(),
        setup: None,
    };

    // Partition PURLs by ecosystem up front. The before-blob gate and the
    // download below must only consider patches this run can actually roll
    // back — the `--ecosystems` filter. An out-of-scope patch with an
    // absent before-blob must not abort
    // (or trigger fetches for) a run that will never restore it. Mirrors
    // apply's `scoped_manifest`.
    let rollback_purls: Vec<String> = patches_to_rollback.iter().map(|p| p.purl.clone()).collect();
    let partitioned = partition_purls(&rollback_purls, common.ecosystems.as_deref());
    let in_scope: HashSet<String> = partitioned
        .values()
        .flat_map(|purls| purls.iter().cloned())
        .collect();
    let mut scoped_manifest = filtered_manifest.clone();
    scoped_manifest
        .patches
        .retain(|purl, _| in_scope.contains(purl));

    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    };

    // Multi-copy aware: npm nests genuine duplicates of one `name@version`,
    // so the resolver returns EVERY physical copy per PURL. Restoring only
    // one would leave the other copy still patched (silently divergent from
    // the manifest's rolled-back state). The rollback loop below restores
    // every copy.
    let all_packages_multi = find_all_packages_for_rollback(
        &partitioned,
        &crawler_options,
        common.silent || common.json,
    )
    .await;

    // One representative path per PURL for the "is it installed" checks and
    // the abort envelope's path display. The before-blob gate and the
    // per-copy restore use `all_packages_multi`: copies drift independently,
    // so which blobs a rollback needs is NOT identical across copies (an
    // already-original root copy says nothing about a still-patched nested
    // duplicate).
    let all_packages: HashMap<String, PathBuf> = all_packages_multi
        .iter()
        .filter_map(|(purl, paths)| paths.first().map(|p| (purl.clone(), p.clone())))
        .collect();

    // Local-redirect rollback (local-mode go) drops a project-local redirect
    // and reads nothing out of the ecosystem's package store, so — unlike an
    // in-place restore — it must NOT depend on the crawler finding the package
    // there. A directory `replace` makes go skip downloading the replaced
    // module entirely, so a clone of a repo that committed `go.mod` +
    // `.socket/go-patches/` + `.socket/manifest.json` (the documented golang
    // workflow) has no module-cache copy for discovery to find. Without this
    // fallback the redirect silently survived the rollback: `rollback`
    // reported success while the build kept linking the patched copy, and
    // `remove` (which delegates here) then deleted the manifest record,
    // leaving an active patch nothing tracks. Scoped to `scoped_manifest` so
    // `--ecosystems` still applies.
    let undiscovered_redirects: Vec<String> = scoped_manifest
        .patches
        .keys()
        .filter(|purl| is_local_redirect(purl, common) && !all_packages.contains_key(*purl))
        .cloned()
        .collect();

    // Group discovered packages by base PURL. A release-variant
    // `package@version` (PyPI/RubyGems/Maven) may have several variants
    // in the manifest that `merge_qualified` resolves to the same
    // installed package dir. Rolling back a variant that is *not* present
    // on disk would HashMismatch and report a spurious failure, so —
    // mirroring apply — we collapse each group to the variant(s) whose
    // hashes actually match the installed bytes. PyPI/RubyGems yield one
    // such variant; Maven's coexisting classifier jars may yield several.
    //
    // Non-variant ecosystems (npm/cargo/go/…) have no qualifiers, but npm
    // does have genuine MULTIPLE physical copies of one `name@version`
    // (nested dupes, diamonds, `file:` dups). Those must NOT be collapsed
    // into a release-variant group — each copy is restored independently —
    // so they are pushed straight to `rollback_targets`. Only the
    // release-variant ecosystems (whose multiple qualified PURLs share ONE
    // install dir) go through the group + narrow path.
    let mut rollback_targets: Vec<(&String, &PathBuf)> = Vec::new();
    let mut groups: HashMap<String, Vec<(&String, &PathBuf)>> = HashMap::new();
    for (purl, pkg_paths) in &all_packages_multi {
        if Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants()) {
            for pkg_path in pkg_paths {
                groups
                    .entry(strip_purl_qualifiers(purl).to_string())
                    .or_default()
                    .push((purl, pkg_path));
            }
        } else {
            for pkg_path in pkg_paths {
                rollback_targets.push((purl, pkg_path));
            }
        }
    }

    // Resolve which variant(s) each base PURL will actually roll back,
    // BEFORE the before-blob gate below, so the gate covers only them.
    for (_base, entries) in groups {
        let to_rollback: Vec<(&String, &PathBuf)> = if entries.len() == 1 {
            entries
        } else {
            // All variants in a group resolve to the same installed path.
            let pkg_path = entries[0].1;
            let candidates: Vec<(&str, &HashMap<String, PatchFileInfo>)> = entries
                .iter()
                .filter_map(|(purl, _)| {
                    filtered_manifest
                        .patches
                        .get(*purl)
                        .map(|p| (purl.as_str(), &p.files))
                })
                .collect();
            let matched = select_installed_variants(pkg_path, &candidates).await;
            if matched.is_empty() {
                // No variant matches the installed distribution (e.g. a
                // locally-modified file). Fall back to attempting every
                // variant so the per-file verification surfaces the
                // mismatch rather than silently skipping the package.
                entries
            } else {
                let winners: HashSet<String> = matched
                    .iter()
                    .map(|&i| candidates[i].0.to_string())
                    .collect();
                entries
                    .into_iter()
                    .filter(|(p, _)| winners.contains(*p))
                    .collect()
            }
        };
        rollback_targets.extend(to_rollback);
    }

    // Check for missing beforeHash blobs — AFTER discovery and variant
    // narrowing, so the gate covers ONLY the packages this run will
    // actually attempt to restore in place:
    //
    //   * Narrowed-away sibling variants (they describe a distribution
    //     that is not on disk) don't gate: an unfetchable sibling
    //     before-blob used to abort the WHOLE rollback even though that
    //     variant was never going to be attempted.
    //   * In-scope purls the crawler could NOT resolve (package not
    //     installed) don't gate either: there is nothing on disk to
    //     restore, so no before-blob is ever read for them. They used to
    //     be gated "fail-closed", which hard-failed the run (exit 1,
    //     `Cannot rollback: ... Before blob not found`, `path: ""`) over
    //     an entry that had nothing to roll back — the same entry apply
    //     reports as a benign `package_not_installed` skip. They surface
    //     via `not_installed` below instead.
    //   * Local-redirect PURLs (local-mode go) are excluded as before:
    //     their rollback just drops the project-local redirect + copy and
    //     reads no blobs, so a missing before-blob must not block an
    //     offline redirect rollback.
    let attempted_purls: HashSet<&str> = rollback_targets.iter().map(|(p, _)| p.as_str()).collect();
    let gate_manifest = exclude_local_redirects(
        &PatchManifest {
            patches: scoped_manifest
                .patches
                .iter()
                .filter(|(purl, _)| attempted_purls.contains(purl.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            setup: None,
        },
        common,
    );

    // Apply's `unmatched` twin: in-scope manifest entries the crawler found
    // no installed package for. Undiscovered local redirects are NOT
    // not-installed — their rollback runs from the manifest alone (the
    // fallback loop below). Sorted so every consumer sees a deterministic
    // order across the manifest HashMap's iteration order.
    let mut not_installed: Vec<String> = scoped_manifest
        .patches
        .keys()
        .filter(|purl| !all_packages.contains_key(*purl) && !undiscovered_redirects.contains(*purl))
        .cloned()
        .collect();
    not_installed.sort();

    // `--dry-run`: verification needs real blob content for an accurate
    // preview, but the preview must not leave new files in the committable
    // `.socket/blobs` (a wet run's sweep would have removed them) — so stage
    // blob reads in a throwaway sibling dir: hardlink (or copy) the
    // already-cached before-blobs in, and let any download below land there
    // too. `tempdir_in(socket_dir)` keeps it on the same filesystem for
    // hardlinks and is auto-removed on drop, like the `.socket-stage-*`
    // atomic-write siblings.
    let _dry_run_blob_stage: Option<tempfile::TempDir> = if common.dry_run {
        let stage = tempfile::Builder::new()
            .prefix(".socket-stage-dryrun-blobs-")
            .tempdir_in(socket_dir)
            .map_err(|e| e.to_string())?;
        let staged_path = stage.path().to_path_buf();
        for patch in gate_manifest.patches.values() {
            for info in patch.files.values() {
                if info.before_hash.is_empty() {
                    continue; // created-by-patch marker: no blob to read
                }
                let src = blobs_path.join(&info.before_hash);
                let dst = staged_path.join(&info.before_hash);
                if tokio::fs::metadata(&src).await.is_ok()
                    && !dst.exists()
                    && tokio::fs::hard_link(&src, &dst).await.is_err()
                {
                    let _ = tokio::fs::copy(&src, &dst).await;
                }
            }
        }
        blobs_path = staged_path;
        Some(stage)
    } else {
        None
    };

    // Of the absent blobs, keep only those an installed file would actually
    // READ: the engine restores from a before-blob only when the on-disk
    // file exists and is not already at its original bytes —
    // `verify_file_rollback` reports `MissingBlob` exactly then (and checks
    // `AlreadyOriginal` BEFORE probing the blob). An absent blob for an
    // already-original, deleted, or locally-drifted file is never read, so
    // it must not abort the run or trigger a download; the rollback loop's
    // own per-file verification still reports those states honestly
    // (already_original / not_found / hash_mismatch).
    let absent_blobs = get_missing_before_blobs(&gate_manifest, &blobs_path).await;
    let mut missing_blobs: HashSet<String> = HashSet::new();
    let mut blob_gated_purls: HashSet<String> = HashSet::new();
    if !absent_blobs.is_empty() {
        for (purl, patch) in &gate_manifest.patches {
            // EVERY physical copy is probed: the rollback loop restores each
            // copy, and copies drift independently — an already-original (or
            // locally-drifted) root copy says nothing about a still-patched
            // nested duplicate, whose restore still needs the blob. Probing
            // only a representative copy skipped the download and wedged the
            // online rollback with a mid-run `MissingBlob` failure. Mirrors
            // apply's `mismatch_blob_gaps`.
            let pkg_paths = all_packages_multi
                .get(purl)
                .expect("gate manifest holds only attempted targets, which the crawler discovered");
            for (file, info) in &patch.files {
                if info.before_hash.is_empty() || !absent_blobs.contains(&info.before_hash) {
                    continue;
                }
                for pkg_path in pkg_paths {
                    let v = verify_file_rollback(pkg_path, file, info, &blobs_path).await;
                    if v.status == VerifyRollbackStatus::MissingBlob {
                        missing_blobs.insert(info.before_hash.clone());
                        blob_gated_purls.insert(purl.clone());
                        break; // the fetch is per-hash; one needy copy queues it
                    }
                }
            }
        }
    }
    if !missing_blobs.is_empty() {
        // Only the packages that genuinely need a missing blob enter the
        // synthesized abort envelope — a gated sibling file that happens to
        // share a needed hash rides along, but a package none of whose
        // absent blobs are needed never fails here.
        let abort_manifest = PatchManifest {
            patches: gate_manifest
                .patches
                .iter()
                .filter(|(purl, _)| blob_gated_purls.contains(purl.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            setup: None,
        };
        if common.offline {
            // Errors print even under --silent ("errors only", never
            // "nothing"): in human mode this bail is the run's only
            // stderr diagnostic; `--json` mutes it and instead carries
            // the synthesized per-package failures below.
            if !common.json {
                eprintln!(
                    "Error: {} blob(s) are missing and --offline mode is enabled.",
                    missing_blobs.len()
                );
                eprintln!("Run \"socket-patch repair\" to download missing blobs.");
            }
            let results = missing_blob_abort_results(
                &abort_manifest,
                &missing_blobs,
                &all_packages,
                |hash| {
                    format!(
                        "Before blob not found: {hash} and --offline prevents fetching. \
                         Run \"socket-patch repair\" to download missing blobs."
                    )
                },
            );
            return Ok(RollbackOutcome {
                success: false,
                results,
                vendored_skipped,
                not_installed,
                aborted: true,
            });
        }

        if !common.silent && !common.json {
            println!("Downloading {} missing blob(s)...", missing_blobs.len());
        }

        let built_client;
        let client = match api_client {
            Some(c) => c,
            None => {
                built_client = get_api_client_with_overrides(common.api_client_overrides())
                    .await
                    .0;
                &built_client
            }
        };
        let fetch_result = fetch_blobs_by_hash(&missing_blobs, &blobs_path, client, None).await;

        if !common.silent && !common.json {
            println!("{}", format_fetch_result(&fetch_result));
        }

        // Re-check ONLY the needed-missing set the download targeted (built
        // from the local-go-excluded, installed-only gate above) — never the
        // full filtered manifest, which would re-introduce never-needed
        // blobs (local-go, not-installed, already-original) and spuriously
        // abort the run over a blob nothing will read.
        let mut still_missing: HashSet<String> = HashSet::new();
        for hash in &missing_blobs {
            if tokio::fs::metadata(blobs_path.join(hash)).await.is_err() {
                still_missing.insert(hash.clone());
            }
        }
        if !still_missing.is_empty() {
            // Errors print even under --silent — same contract as the
            // offline bail above (and same `--json` carrier).
            if !common.json {
                eprintln!(
                    "{} blob(s) could not be downloaded. Cannot rollback.",
                    still_missing.len()
                );
            }
            // Per-hash download outcomes; a hash the fetch never reported
            // on still fails closed with the generic reason.
            let download_errors: HashMap<&str, &str> = fetch_result
                .results
                .iter()
                .filter(|r| !r.success)
                .map(|r| {
                    (
                        r.hash.as_str(),
                        r.error.as_deref().unwrap_or("unknown error"),
                    )
                })
                .collect();
            let results = missing_blob_abort_results(
                &abort_manifest,
                &still_missing,
                &all_packages,
                |hash| {
                    let why = download_errors
                        .get(hash)
                        .copied()
                        .unwrap_or("download failed");
                    format!(
                        "Before blob could not be downloaded: {hash} - {why}. \
                         Run \"socket-patch repair\" to download missing blobs."
                    )
                },
            );
            return Ok(RollbackOutcome {
                success: false,
                results,
                vendored_skipped,
                not_installed,
                aborted: true,
            });
        }
    }

    if all_packages.is_empty() && undiscovered_redirects.is_empty() {
        if !common.silent && !common.json {
            println!("No packages found that match patches to rollback");
        }
        // `success: true` — per-package semantics for the `remove`
        // delegation. The CLI boundary layers apply's "nothing matched at
        // all" exit-1 on top via `not_installed`.
        return Ok(RollbackOutcome {
            success: true,
            results: Vec::new(),
            vendored_skipped,
            not_installed,
            aborted: false,
        });
    }

    // Rollback patches
    let mut results: Vec<RollbackResult> = Vec::new();
    let mut has_errors = false;

    for (purl, pkg_path) in rollback_targets {
        let patch = match filtered_manifest.patches.get(purl) {
            Some(p) => p,
            None => continue,
        };

        // Local go drops the project-local `replace`-redirect; everything
        // else — npm/pypi/gem and cargo (vendored or registry cache) —
        // restores in place from before-blobs.
        let result = match try_rollback_local_go(purl, pkg_path, patch, common).await {
            Some(r) => r,
            None => {
                rollback_package_patch(
                    purl,
                    pkg_path,
                    &patch.files,
                    &blobs_path,
                    common.dry_run,
                )
                .await
            }
        };

        if !result.success {
            has_errors = true;
            // Errors print even under --silent ("errors only", never
            // "nothing"): with the summary muted, this line is the
            // silent run's only failure diagnostic.
            if !common.json {
                eprintln!(
                    "Failed to rollback {}: {}",
                    purl,
                    result.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
        results.push(result);
    }

    // Redirects the crawler never saw (see `undiscovered_redirects` above):
    // roll the redirect back from the manifest alone. `package_path` is the
    // project root — what gets dropped is the `go.mod` directive + the
    // project-local copy, not anything under a package store.
    for purl in &undiscovered_redirects {
        let Some(patch) = scoped_manifest.patches.get(purl) else {
            continue;
        };
        let Some(result) = try_rollback_local_go(purl, &common.cwd, patch, common).await
        else {
            continue;
        };
        if !result.success {
            has_errors = true;
            // Errors print even under --silent — same contract as the
            // in-place loop above.
            if !common.json {
                eprintln!(
                    "Failed to rollback {}: {}",
                    purl,
                    result.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
        results.push(result);
    }

    Ok(RollbackOutcome {
        success: !has_errors,
        results,
        vendored_skipped,
        not_installed,
        aborted: false,
    })
}

// Export for use by remove command. The third tuple element lists
// vendor-owned purls that were excluded from in-place rollback (benign);
// the fourth is `RollbackOutcome::not_installed` — in-scope manifest
// entries the crawler found no installed package for.
//
// The returned `bool` is `RollbackOutcome::success` — per-package semantics
// only. Manifest entries whose package is not installed are NOT failures
// here (there is nothing on disk to restore), so `remove` proceeds to drop
// them from the manifest; the CLI `rollback` boundary's apply-mirroring
// "none matched → exit 1" rule deliberately does NOT apply to this
// delegation (it would wedge `remove` for packages long uninstalled).
//
// The `not_installed` element exists because that drop is IRREVERSIBLE in a
// way a genuine rollback is not: "not installed" can also mean "installed
// but missed by the crawler" (layout gaps are a documented reality), in
// which case the patched bytes are still on disk. `remove` uses the list to
// warn and to keep those entries' beforeHash blobs out of its cleanup
// sweep, so the revert data survives a crawler miss.
//
// Takes the caller's `GlobalArgs` as the base (only the per-call fields are
// overridden): the nested missing-blob download builds its API client from
// `api_client_overrides()`, so flag-passed `--api-url` / `--api-token` /
// `--org` / `--proxy-url` must flow through. A from-scratch
// `GlobalArgs::default()` here silently dropped them — with credentials
// passed as flags the nested client was unauthenticated and pointed at the
// public proxy, so the download failed and the whole `remove` aborted with
// `rollback_failed` (see tests/remove_rollback_api_overrides.rs).
pub(crate) async fn rollback_patches(
    common: &crate::args::GlobalArgs,
    manifest_path: &Path,
    identifier: Option<&str>,
    dry_run: bool,
    silent: bool,
    ecosystems: Option<Vec<String>>,
) -> Result<(bool, Vec<RollbackResult>, Vec<String>, Vec<String>), String> {
    let delegated_common = crate::args::GlobalArgs {
        manifest_path: manifest_path.display().to_string(),
        ecosystems,
        silent,
        dry_run,
        ..common.clone()
    };
    let outcome = rollback_patches_inner(
        &delegated_common,
        manifest_path,
        InnerSelection::Identifier(identifier),
        None,
    )
    .await?;
    Ok((
        outcome.success,
        outcome.results,
        outcome.vendored_skipped,
        outcome.not_installed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use std::collections::HashMap;

    fn make_record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "test patch".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    fn make_manifest() -> PatchManifest {
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        patches.insert("pkg:npm/bar@2.0".to_string(), make_record("uuid-bar"));
        patches.insert("pkg:pypi/baz@3.0".to_string(), make_record("uuid-baz"));
        PatchManifest {
            patches,
            setup: None,
        }
    }

    #[test]
    fn test_find_patches_to_rollback_none_returns_all() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, None);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_find_patches_to_rollback_purl_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:npm/foo@1.0"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:npm/foo@1.0");
    }

    #[test]
    fn test_find_patches_to_rollback_purl_no_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:npm/nonexistent@1"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_patches_to_rollback_uuid_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("uuid-bar"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].patch.uuid, "uuid-bar");
        assert_eq!(result[0].purl, "pkg:npm/bar@2.0");
    }

    #[test]
    fn test_find_patches_to_rollback_uuid_no_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("uuid-does-not-exist"));
        assert!(result.is_empty());
    }

    /// A manifest holding several PyPI release variants of one
    /// package@version (broad mode).
    fn make_multi_variant_manifest() -> PatchManifest {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=wheel-cp311".to_string(),
            make_record("uuid-wheel-cp311"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=wheel-cp312".to_string(),
            make_record("uuid-wheel-cp312"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=sdist".to_string(),
            make_record("uuid-sdist"),
        );
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        PatchManifest {
            patches,
            setup: None,
        }
    }

    #[test]
    fn test_find_patches_to_rollback_base_purl_matches_all_variants() {
        let manifest = make_multi_variant_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:pypi/six@1.16.0"));
        // Base PURL (no qualifier) expands to every release variant.
        assert_eq!(result.len(), 3);
        for p in &result {
            assert!(p.purl.starts_with("pkg:pypi/six@1.16.0?artifact_id="));
        }
    }

    #[test]
    fn test_find_patches_to_rollback_qualified_purl_matches_one_variant() {
        let manifest = make_multi_variant_manifest();
        let result =
            find_patches_to_rollback(&manifest, Some("pkg:pypi/six@1.16.0?artifact_id=sdist"));
        // A fully-qualified PURL targets exactly one variant.
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:pypi/six@1.16.0?artifact_id=sdist");
    }

    #[test]
    fn test_find_patches_to_rollback_base_purl_does_not_leak_other_packages() {
        let manifest = make_multi_variant_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:pypi/six@1.16.0"));
        assert!(result.iter().all(|p| p.purl.contains("six@1.16.0")));
    }

    // --- Summary-counting regressions -----------------------------------
    //
    // These pin the rollback summary to the same contract apply uses:
    // an "already original" result must have at least one verified file,
    // and the dry-run "can be rolled back" count must not double-report
    // packages that are already in their original state.

    use socket_patch_core::patch::rollback::VerifyRollbackResult;

    fn verified(status: VerifyRollbackStatus) -> VerifyRollbackResult {
        VerifyRollbackResult {
            file: "package/index.js".to_string(),
            status,
            message: None,
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        }
    }

    /// Build a `RollbackResult` from verification statuses and the list of
    /// files reported rolled back. `success` defaults to whether every
    /// verified file is Ready/AlreadyOriginal, matching the engine.
    fn make_result(
        verified_statuses: &[VerifyRollbackStatus],
        rolled_back: &[&str],
    ) -> RollbackResult {
        let files_verified: Vec<_> = verified_statuses.iter().cloned().map(verified).collect();
        let success = files_verified.iter().all(|f| {
            f.status == VerifyRollbackStatus::Ready
                || f.status == VerifyRollbackStatus::AlreadyOriginal
        });
        RollbackResult {
            package_key: "pkg:npm/foo@1.0.0".to_string(),
            package_path: "/tmp/foo".to_string(),
            success,
            files_verified,
            files_rolled_back: rolled_back.iter().map(|s| s.to_string()).collect(),
            error: None,
            sidecar: None,
        }
    }

    #[test]
    fn all_files_already_original_true_when_every_file_matches() {
        let r = make_result(
            &[
                VerifyRollbackStatus::AlreadyOriginal,
                VerifyRollbackStatus::AlreadyOriginal,
            ],
            &[],
        );
        assert!(all_files_already_original(&r));
    }

    #[test]
    fn all_files_already_original_false_when_any_file_differs() {
        let r = make_result(
            &[
                VerifyRollbackStatus::AlreadyOriginal,
                VerifyRollbackStatus::Ready,
            ],
            &[],
        );
        assert!(!all_files_already_original(&r));
    }

    /// Regression: `Iterator::all` over an empty slice is vacuously true.
    /// A successful result with no verified files (a zero-file patch
    /// record) must NOT be reported as "already original" — the
    /// `!is_empty()` guard enforces this, matching apply.
    #[test]
    fn all_files_already_original_false_when_no_verified_files() {
        let r = make_result(&[], &[]);
        assert!(r.files_verified.is_empty());
        assert!(r.success);
        assert!(!all_files_already_original(&r));
    }

    /// Regression: the dry-run "can be rolled back" count must exclude
    /// already-original packages, which are reported on their own line.
    /// Otherwise each no-op is double-counted (once as can-rollback, once
    /// as already-original).
    #[test]
    fn can_rollback_count_excludes_already_original() {
        let results = vec![
            // Genuinely needs restoring.
            make_result(&[VerifyRollbackStatus::Ready], &[]),
            // No-op: already at beforeHash.
            make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
            // Mixed → still needs restoring.
            make_result(
                &[
                    VerifyRollbackStatus::Ready,
                    VerifyRollbackStatus::AlreadyOriginal,
                ],
                &[],
            ),
            // Failed (e.g. HashMismatch) → not counted as rollbackable.
            make_result(&[VerifyRollbackStatus::HashMismatch], &[]),
        ];
        // 2 successful non-no-op packages; the already-original one is
        // excluded and the failed one was never successful.
        assert_eq!(can_rollback_count(&results), 2);
    }

    /// A summary made entirely of no-ops reports zero rollbackable
    /// packages (and `saturating_sub` keeps it from underflowing).
    #[test]
    fn can_rollback_count_all_already_original_is_zero() {
        let results = vec![
            make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
            make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
        ];
        assert_eq!(can_rollback_count(&results), 0);
    }

    // --- Missing-blob gate consistency ----------------------------------
    //
    // The before-blob gate excludes local-go PURLs (redirect rollback
    // reads no blobs). Both the initial missing-blob check AND the
    // post-download re-check (`still_missing`) must run against the SAME
    // local-go-excluded gate manifest. Re-checking the full filtered
    // manifest re-introduces local-go before-hashes that were never
    // downloaded, spuriously aborting a mixed rollback.

    fn record_with_file(uuid: &str, path: &str, before_hash: &str) -> PatchRecord {
        let mut rec = make_record(uuid);
        let mut files = HashMap::new();
        files.insert(
            path.to_string(),
            PatchFileInfo {
                before_hash: before_hash.to_string(),
                after_hash: "after".to_string(),
            },
        );
        rec.files = files;
        rec
    }

    /// Regression: an empty `beforeHash` (the "file created by the patch"
    /// sentinel) is not a blob. The missing-before-blob gate must ignore it:
    /// `blobs_path.join("")` resolves to the blobs directory itself, so when
    /// the blobs dir does not exist yet (fresh checkout of a committed
    /// manifest, or a cache that was cleaned) the phantom "" counted as a
    /// missing blob -- an `--offline` rollback of a new-file-only patch
    /// aborted with "1 blob(s) are missing" even though it needs zero blobs,
    /// and an online rollback fired a pointless download of blob "".
    #[tokio::test]
    async fn missing_before_blobs_ignores_new_file_sentinel() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "created.js", ""),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };

        // Blobs dir does NOT exist (nothing ever downloaded).
        let tmp = tempfile::tempdir().unwrap();
        let blobs = tmp.path().join("blobs");

        let missing = get_missing_before_blobs(&manifest, &blobs).await;
        assert!(
            missing.is_empty(),
            "a new-file-only patch needs no before-blobs, got {missing:?}"
        );
    }

    /// The pre-flight bail must map each missing blob back to its package:
    /// one failed result per affected package (that's what the envelope's
    /// `failed` counter counts), files carrying the engine's `missing_blob`
    /// status + the missing hash, packages whose blobs are all present left
    /// untouched, and created-by-patch sentinels (empty beforeHash) never
    /// counted — they are backed by no blob.
    #[test]
    fn missing_blob_abort_results_map_hashes_to_packages() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-foo", "a.js", "missing_a"),
        );
        patches.insert(
            "pkg:npm/bar@1.0.0".to_string(),
            record_with_file("uuid-bar", "b.js", "present_b"),
        );
        patches.insert(
            "pkg:npm/baz@1.0.0".to_string(),
            record_with_file("uuid-baz", "c.js", ""),
        );
        let gate = PatchManifest {
            patches,
            setup: None,
        };
        let missing: HashSet<String> = ["missing_a".to_string(), "".to_string()]
            .into_iter()
            .collect();
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:npm/foo@1.0.0".to_string(), PathBuf::from("/tmp/foo"));

        let results =
            missing_blob_abort_results(&gate, &missing, &all_packages, |h| format!("gone: {h}"));

        assert_eq!(
            results.len(),
            1,
            "only the package referencing a genuinely missing blob fails, got {results:?}"
        );
        let r = &results[0];
        assert_eq!(r.package_key, "pkg:npm/foo@1.0.0");
        assert_eq!(r.package_path, "/tmp/foo");
        assert!(!r.success);
        assert!(r.files_rolled_back.is_empty());
        assert_eq!(
            r.error.as_deref(),
            Some("Cannot rollback: a.js - gone: missing_a"),
            "error mirrors the engine's first-blocking-file shape"
        );
        assert_eq!(r.files_verified.len(), 1);
        let f = &r.files_verified[0];
        assert_eq!(f.file, "a.js");
        assert_eq!(f.status, VerifyRollbackStatus::MissingBlob);
        assert_eq!(f.target_hash.as_deref(), Some("missing_a"));
        assert_eq!(f.message.as_deref(), Some("gone: missing_a"));
    }

    /// Helper-level determinism + tolerance pin: multiple affected packages
    /// come out purl-sorted (stable envelope across the manifest HashMap's
    /// iteration order), and a purl absent from `all_packages` degrades to
    /// an empty path rather than panicking. Production can no longer feed
    /// an undiscovered purl here — since the gate reorder, only attempted
    /// (crawler-discovered) targets enter the blob plan, so `path` is
    /// always populated in real envelopes; the tolerance is defensive.
    #[test]
    fn missing_blob_abort_results_sorted_and_pathless_when_undiscovered() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/zeta@1.0.0".to_string(),
            record_with_file("uuid-zeta", "z.js", "missing_z"),
        );
        patches.insert(
            "pkg:npm/alpha@1.0.0".to_string(),
            record_with_file("uuid-alpha", "a.js", "missing_a"),
        );
        let gate = PatchManifest {
            patches,
            setup: None,
        };
        let missing: HashSet<String> = ["missing_a".to_string(), "missing_z".to_string()]
            .into_iter()
            .collect();

        let results =
            missing_blob_abort_results(&gate, &missing, &HashMap::new(), |h| h.to_string());

        let keys: Vec<&str> = results.iter().map(|r| r.package_key.as_str()).collect();
        assert_eq!(keys, ["pkg:npm/alpha@1.0.0", "pkg:npm/zeta@1.0.0"]);
        assert!(
            results.iter().all(|r| r.package_path.is_empty()),
            "no discovered install path to report, got {results:?}"
        );
    }

    /// Cargo now patches in place (vendored or registry cache) and rolls back
    /// by restoring from before-blobs — exactly like npm/pypi. So a cargo PURL
    /// must NOT be excluded by the before-blob gate: a missing cargo before-blob
    /// IS a real problem the gate should surface. This guards against cargo
    /// being mistakenly reclassified as a redirect again.
    #[tokio::test]
    async fn gate_manifest_keeps_cargo_before_blobs_in_missing_check() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:cargo/serde@1.0.0".to_string(),
            record_with_file("uuid-cargo", "src/lib.rs", "cargo_before"),
        );
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "index.js", "npm_before"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };

        // Local mode (no --global / --global-prefix).
        let common = crate::args::GlobalArgs::default();
        assert!(!common.global && common.global_prefix.is_none());

        // Blobs dir holds only the npm before-blob; the cargo one is absent.
        let tmp = tempfile::tempdir().unwrap();
        let blobs = tmp.path();
        tokio::fs::write(blobs.join("npm_before"), b"x")
            .await
            .unwrap();

        // The gate must STILL report the cargo before-blob as missing — cargo
        // is an in-place rollback that genuinely needs it.
        let gate = exclude_local_redirects(&manifest, &common);
        let gate_missing = get_missing_before_blobs(&gate, blobs).await;
        assert!(
            gate_missing.contains("cargo_before"),
            "gate must keep cargo before-blobs (in-place rollback), got {gate_missing:?}"
        );
        // And the cargo PURL must not be classified as a redirect.
        assert!(!is_local_redirect("pkg:cargo/serde@1.0.0", &common));
    }

    /// Regression: local-GO redirects must be excluded from the before-blob
    /// gate exactly like local-cargo. A go redirect drops the `go.mod`
    /// `replace` directive + the patched copy and reads no before-blob, so a
    /// missing before-blob must not abort (nor trigger a needless download for)
    /// an offline local-go rollback. Before the fix only cargo was excluded, so
    /// a local-go patch with an absent before-blob aborted the whole rollback
    /// under `--offline`.
    #[tokio::test]
    async fn gate_manifest_excludes_local_go_before_blobs_from_missing_check() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1".to_string(),
            record_with_file("uuid-go", "errors.go", "go_before"),
        );
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "index.js", "npm_before"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };

        // Local mode (no --global / --global-prefix).
        let common = crate::args::GlobalArgs::default();
        assert!(!common.global && common.global_prefix.is_none());

        // Blobs dir holds only the npm before-blob; the go one is absent.
        let tmp = tempfile::tempdir().unwrap();
        let blobs = tmp.path();
        tokio::fs::write(blobs.join("npm_before"), b"x")
            .await
            .unwrap();

        // Full manifest: the go before-blob shows up as missing — exactly what
        // the buggy (cargo-only) gate left in, spuriously aborting rollback.
        let full_missing = get_missing_before_blobs(&manifest, blobs).await;
        assert!(full_missing.contains("go_before"));

        // Gate manifest: the local-go PURL is excluded, so its before-blob is
        // not counted as missing. With the npm blob present, the gate reports
        // nothing missing.
        let gate = exclude_local_redirects(&manifest, &common);
        let gate_missing = get_missing_before_blobs(&gate, blobs).await;
        assert!(
            gate_missing.is_empty(),
            "gate must exclude local-go before-blobs, got {gate_missing:?}"
        );

        // And `is_local_redirect` must classify the go PURL as a redirect in
        // local mode but a global PURL as in-place (gate must keep the latter).
        assert!(is_local_redirect(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1",
            &common
        ));
        let global = crate::args::GlobalArgs {
            global: true,
            ..crate::args::GlobalArgs::default()
        };
        assert!(!is_local_redirect(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1",
            &global
        ));
    }

    /// Regression: rolling back a local-GO patch must DROP the project-local
    /// redirect (the `go.mod` `replace` directive + the patched copy under
    /// `.socket/go-patches/`), not fall through to in-place rollback.
    ///
    /// Before the fix, `rollback` only had a cargo redirect backend; a go PURL
    /// fell through to `rollback_package_patch` against the pristine module
    /// cache, every file verified `AlreadyOriginal`, and the redirect was left
    /// active — a silent no-op that reported "already original" while the build
    /// kept using the patched copy.
    #[tokio::test]
    async fn try_rollback_local_go_drops_redirect_and_copy() {
        use socket_patch_core::vendor::go_mod_edit::{
            ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
        };

        const MODULE: &str = "github.com/foo/bar";
        const VERSION: &str = "v1.4.2";
        const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // A go.mod with a require directive (NOT socket-owned) plus the
        // socket-owned replace directive a prior apply would have written.
        tokio::fs::write(
            root.join("go.mod"),
            "module myproj\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();
        let changed = ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        assert!(changed, "fixture must install a socket-owned replace");

        // The patched copy the redirect points at.
        let copy_dir = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();
        tokio::fs::write(copy_dir.join("errors.go"), b"// patched\n")
            .await
            .unwrap();

        // Sanity: the redirect is in place before rollback.
        assert!(read_replace_entries(root)
            .await
            .iter()
            .any(|e| e.module == MODULE && e.socket_owned()));

        let patch = record_with_file("uuid-go", "errors.go", "go_before");
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            ..crate::args::GlobalArgs::default()
        };

        // `pkg_path` is the (unused for go) pristine module-cache dir.
        let result = try_rollback_local_go(PURL, root, &patch, &common)
            .await
            .expect("go PURL in local mode must be handled by the go backend");

        assert!(result.success, "rollback failed: {:?}", result.error);
        assert!(
            result.files_rolled_back.contains(&"errors.go".to_string()),
            "the patched file must be reported rolled back, got {:?}",
            result.files_rolled_back
        );

        // The socket-owned replace directive is gone...
        assert!(
            read_replace_entries(root)
                .await
                .iter()
                .all(|e| !(e.module == MODULE && e.socket_owned())),
            "socket-owned replace directive must be dropped"
        );
        // ...the require directive (user-authored) survives...
        assert!(tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap()
            .contains("require github.com/foo/bar v1.4.2"));
        // ...and the patched copy is removed.
        assert!(
            !copy_dir.exists(),
            "patched copy under .socket/go-patches must be removed"
        );
    }

    /// Regression: a dry-run local-go rollback must not CLAIM files were
    /// rolled back. The engine leaves `files_rolled_back` empty on dry-run
    /// (verify only — `rollback_package_patch` pushes into it only on the
    /// mutating path), and the JSON envelope counts `rolledBack` from a
    /// non-empty `files_rolled_back`. Before the fix the go backend populated
    /// it unconditionally, so `rollback --dry-run --json` reported
    /// `rolledBack: 1` (with the files listed in `filesRolledBack`) for a run
    /// that mutated nothing.
    #[tokio::test]
    async fn try_rollback_local_go_dry_run_reports_no_files_rolled_back() {
        use socket_patch_core::vendor::go_mod_edit::{
            ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
        };

        const MODULE: &str = "github.com/foo/bar";
        const VERSION: &str = "v1.4.2";
        const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            "module myproj\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();
        assert!(
            ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
                .await
                .unwrap()
        );
        let copy_dir = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();

        let patch = record_with_file("uuid-go", "errors.go", "go_before");
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            dry_run: true,
            ..crate::args::GlobalArgs::default()
        };
        let result = try_rollback_local_go(PURL, root, &patch, &common)
            .await
            .expect("go PURL in local mode must be handled by the go backend");

        assert!(
            result.success,
            "dry-run rollback failed: {:?}",
            result.error
        );
        assert!(
            result.files_rolled_back.is_empty(),
            "dry-run must not claim files were rolled back (the JSON \
             `rolledBack` count is derived from this), got {:?}",
            result.files_rolled_back
        );
        // And dry-run must not have mutated anything: the redirect and the
        // patched copy both survive.
        assert!(
            read_replace_entries(root)
                .await
                .iter()
                .any(|e| e.module == MODULE && e.socket_owned()),
            "dry-run must leave the replace directive in place"
        );
        assert!(copy_dir.exists(), "dry-run must leave the patched copy");
    }

    /// A go PURL under `--global` is an in-place module-cache rollback, NOT a
    /// redirect — `try_rollback_local_go` must decline it so the caller falls
    /// through to `rollback_package_patch`.
    #[tokio::test]
    async fn try_rollback_local_go_declines_global() {
        let patch = record_with_file("uuid-go", "errors.go", "go_before");
        let global = crate::args::GlobalArgs {
            global: true,
            ..crate::args::GlobalArgs::default()
        };
        let result = try_rollback_local_go(
            "pkg:golang/github.com/foo/bar@v1.4.2",
            Path::new("/nonexistent"),
            &patch,
            &global,
        )
        .await;
        assert!(
            result.is_none(),
            "global go must not use the redirect backend"
        );
    }

    /// Regression: a local-GO rollback must NOT depend on the module still
    /// sitting in the Go module cache. A directory `replace` makes go skip the
    /// download of the replaced module entirely, so on a fresh clone of a repo
    /// that committed `go.mod` + `.socket/go-patches/` + `.socket/manifest.json`
    /// (the documented golang workflow) the cache holds no copy of the module —
    /// the crawler finds nothing and the redirect rollback was skipped
    /// altogether. `rollback` (and `remove`, which delegates here) then reported
    /// success while leaving the `replace` directive + patched copy in place, so
    /// the build kept linking patched bytes — for `remove`, with the manifest
    /// record deleted, i.e. an active patch nothing tracks.
    #[tokio::test]
    async fn rollback_drops_local_go_redirect_when_module_cache_has_no_copy() {
        use socket_patch_core::vendor::go_mod_edit::{
            ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
        };

        // A module path no real module cache can hold.
        const MODULE: &str = "github.com/socket-patch-test/never-cached";
        const VERSION: &str = "v1.4.2";
        const PURL: &str = "pkg:golang/github.com/socket-patch-test/never-cached@v1.4.2";

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            format!("module myproj\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n"),
        )
        .await
        .unwrap();
        assert!(
            ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
                .await
                .unwrap(),
            "fixture must install a socket-owned replace"
        );
        let copy_dir = root
            .join(GO_PATCHES_DIR)
            .join(format!("{MODULE}@{VERSION}"));
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();
        tokio::fs::write(copy_dir.join("errors.go"), b"// patched\n")
            .await
            .unwrap();

        let mut patches = HashMap::new();
        patches.insert(
            PURL.to_string(),
            record_with_file("uuid-go", "errors.go", "go_before"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let socket = root.join(".socket");
        tokio::fs::create_dir_all(&socket).await.unwrap();
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();

        // `--offline`: the redirect rollback reads no blobs, so it must not
        // need the network either.
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored, _not_installed) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false, // dry_run
            true,  // silent
            Some(vec!["golang".to_string()]),
        )
        .await
        .expect("rollback must not error");

        assert!(success, "local-go redirect rollback must succeed");
        assert_eq!(
            results.len(),
            1,
            "the local-go redirect must be rolled back even though the module \
             cache holds no copy of the module, got {results:?}"
        );
        assert!(
            results[0]
                .files_rolled_back
                .contains(&"errors.go".to_string()),
            "the patched file must be reported rolled back, got {:?}",
            results[0].files_rolled_back
        );
        assert!(
            read_replace_entries(root)
                .await
                .iter()
                .all(|e| !(e.module == MODULE && e.socket_owned())),
            "socket-owned replace directive must be dropped"
        );
        assert!(
            !copy_dir.exists(),
            "patched copy under .socket/go-patches must be removed"
        );
    }

    /// The undiscovered-redirect fallback must stay scoped: a local-go PURL
    /// filtered out by `--ecosystems` must not be rolled back behind the
    /// filter's back.
    #[tokio::test]
    async fn undiscovered_local_go_redirect_respects_ecosystem_filter() {
        use socket_patch_core::vendor::go_mod_edit::{
            ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
        };

        const MODULE: &str = "github.com/socket-patch-test/never-cached";
        const VERSION: &str = "v1.4.2";
        const PURL: &str = "pkg:golang/github.com/socket-patch-test/never-cached@v1.4.2";

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            format!("module myproj\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n"),
        )
        .await
        .unwrap();
        assert!(
            ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
                .await
                .unwrap()
        );
        let copy_dir = root
            .join(GO_PATCHES_DIR)
            .join(format!("{MODULE}@{VERSION}"));
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();

        let mut patches = HashMap::new();
        patches.insert(
            PURL.to_string(),
            record_with_file("uuid-go", "errors.go", "go_before"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let socket = root.join(".socket");
        tokio::fs::create_dir_all(&socket).await.unwrap();
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();

        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored, _not_installed) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false,
            true,
            Some(vec!["npm".to_string()]), // golang out of scope
        )
        .await
        .expect("rollback must not error");
        assert!(success);
        assert!(
            results.is_empty(),
            "golang is out of scope — nothing may be rolled back, got {results:?}"
        );
        assert!(
            read_replace_entries(root)
                .await
                .iter()
                .any(|e| e.module == MODULE && e.socket_owned()),
            "an out-of-scope redirect must survive"
        );
        assert!(copy_dir.exists(), "an out-of-scope copy must survive");
    }

    // --- Before-blob gate `--ecosystems` scoping --------------------------
    //
    // Twin of apply's (fixed) "offline guard unscoped" bug: the gate must
    // only consider patches this run can actually roll back — the
    // `--ecosystems` filter.

    /// Regression: an out-of-scope patch's missing before-blob must not abort
    /// an `--ecosystems`-scoped rollback. Before the fix the gate ran on the
    /// identifier-filtered manifest BEFORE `partition_purls`, so
    /// `rollback --ecosystems npm --offline` aborted the whole run because a
    /// pypi patch — which this run would never touch — was missing its
    /// before-blob (and online, the gate triggered needless downloads for it).
    #[tokio::test]
    async fn before_blob_gate_ignores_ecosystem_filtered_patches() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        let blobs = socket.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        // npm patch (in scope): before-blob present.
        // pypi patch (filtered out by `--ecosystems npm`): before-blob ABSENT.
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "package/index.js", "npm_before_hash"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0".to_string(),
            record_with_file("uuid-pypi", "six.py", "pypi_before_hash"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();
        tokio::fs::write(blobs.join("npm_before_hash"), b"x")
            .await
            .unwrap();

        // With no npm package installed under the tempdir the run finds
        // nothing to do — but it must get past the gate and report success,
        // not abort over a blob it would never read.
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored_skipped, _not_installed) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false, // dry_run
            true,  // silent
            Some(vec!["npm".to_string()]),
        )
        .await
        .expect("rollback must not error");
        assert!(results.is_empty(), "nothing installed, nothing rolled back");
        assert!(
            success,
            "an out-of-scope patch's missing before-blob must not abort an \
             --ecosystems-scoped offline rollback"
        );
    }

    /// Write a fake installed npm package so the crawler discovers it and
    /// the before-blob gate has an attempted target to protect. `content`
    /// is the installed `index.js` bytes (whose hash decides whether the
    /// engine would actually need the before-blob).
    async fn install_fake_npm_package(root: &Path, name: &str, version: &str, content: &[u8]) {
        tokio::fs::write(
            root.join("package.json"),
            r#"{ "name": "gate-test-root", "version": "0.0.0" }"#,
        )
        .await
        .unwrap();
        let pkg_dir = root.join("node_modules").join(name);
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("package.json"),
            format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
        )
        .await
        .unwrap();
        tokio::fs::write(pkg_dir.join("index.js"), content)
            .await
            .unwrap();
    }

    /// The scoped gate still protects in-scope INSTALLED patches: with no
    /// `--ecosystems` filter, a missing before-blob for an installed npm
    /// package whose file genuinely needs restoring must abort the offline
    /// run exactly as before. (The package is installed here — since the
    /// gate reorder a not-installed entry never enters the blob plan; see
    /// `not_installed_entry_never_enters_blob_plan` below.)
    #[tokio::test]
    async fn before_blob_gate_still_blocks_in_scope_missing_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        let blobs = socket.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        // Installed, with bytes matching NEITHER beforeHash nor afterHash:
        // the file exists and is not already original, so the engine would
        // read the before-blob — the gate must fail closed on its absence.
        install_fake_npm_package(root, "foo", "1.0.0", b"patched-ish content\n").await;

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "package/index.js", "npm_before_hash"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();
        // The npm before-blob is deliberately absent.

        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored_skipped, _not_installed) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false, // dry_run
            true,  // silent
            None,  // no ecosystem filter — the npm patch is in scope
        )
        .await
        .expect("rollback must not error");
        assert!(
            !success,
            "an in-scope missing before-blob must still abort the offline run"
        );
        // The abort synthesizes the per-package failure the JSON envelope
        // reports (`failed` would otherwise claim 0 on this exit-1 path).
        assert_eq!(results.len(), 1, "got {results:?}");
        assert_eq!(results[0].package_key, "pkg:npm/foo@1.0.0");
        assert!(!results[0].success);
        assert!(
            !results[0].package_path.is_empty(),
            "a gated package is installed, so its path must be reported, got {results:?}"
        );
        assert!(
            results[0]
                .files_verified
                .iter()
                .any(|f| f.status == VerifyRollbackStatus::MissingBlob
                    && f.target_hash.as_deref() == Some("npm_before_hash")),
            "the missing blob must be named, got {results:?}"
        );
    }

    /// Regression (rollback ordering): a manifest entry whose package is
    /// NOT installed must never enter the before-blob plan. Before the gate
    /// reorder, its missing before-blob hard-failed the whole offline run
    /// (exit 1, `Cannot rollback: ... Before blob not found`, `path: ""`)
    /// even though there was nothing on disk to roll back. Through the
    /// `remove`-facing delegation this is a benign no-op: success with zero
    /// results, exactly as when the blob IS present — so `remove` can drop
    /// the entry of a long-uninstalled package either way.
    #[tokio::test]
    async fn not_installed_entry_never_enters_blob_plan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        tokio::fs::create_dir_all(&socket).await.unwrap();
        // No node_modules at all — the package is not installed, and the
        // blobs dir does not even exist.

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "package/index.js", "npm_before_hash"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();

        // `--offline` proves no download is attempted for the unneeded blob.
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, vendored_skipped, not_installed) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false, // dry_run
            true,  // silent
            None,
        )
        .await
        .expect("rollback must not error");
        assert!(
            success,
            "a not-installed entry's missing before-blob must not fail the run"
        );
        assert!(
            results.is_empty(),
            "nothing installed, nothing attempted, got {results:?}"
        );
        assert!(vendored_skipped.is_empty());
        // The skip is not silent to the delegation: `remove` needs to know
        // this entry was never actually reverted (a crawler miss looks the
        // same) so it can keep the before-blobs and warn.
        assert_eq!(
            not_installed,
            vec!["pkg:npm/foo@1.0.0".to_string()],
            "the delegation must surface the not-installed entry"
        );
    }

    /// The needed-blob narrowing: an INSTALLED package whose file is already
    /// at its original bytes needs no before-blob (the engine checks
    /// `AlreadyOriginal` before probing the blob), so a missing — e.g.
    /// GC'd — blob must not abort the offline run. The rollback proceeds
    /// and reports the no-op honestly.
    #[tokio::test]
    async fn missing_blob_for_already_original_file_does_not_gate() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let original = b"original content\n";
        let before_hash = compute_git_sha256_from_bytes(original);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        tokio::fs::create_dir_all(&socket).await.unwrap();

        // Installed at the BEFORE bytes — rollback is a no-op for it.
        install_fake_npm_package(root, "foo", "1.0.0", original).await;

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "package/index.js", &before_hash),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();
        // The before-blob is deliberately absent (e.g. garbage-collected).

        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored_skipped, not_installed) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false, // dry_run
            true,  // silent
            None,
        )
        .await
        .expect("rollback must not error");
        assert!(
            success,
            "a blob nothing will read must not gate the run, got {results:?}"
        );
        assert!(
            not_installed.is_empty(),
            "an installed already-original package is not a crawler miss"
        );
        assert_eq!(results.len(), 1, "got {results:?}");
        assert!(results[0].success);
        assert!(
            all_files_already_original(&results[0]),
            "the no-op must be reported as already original, got {results:?}"
        );
    }
}
