use clap::Args;
use socket_patch_core::api::blob_fetcher::{fetch_blobs_by_hash, format_fetch_result};
use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::cleanup_blobs::ArtifactReferences;
use socket_patch_core::manifest::operations::{
    get_before_hash_blobs, read_manifest, write_manifest,
};
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::select_installed_variants;
use socket_patch_core::patch::redirect::upstream::HostedPin;
use socket_patch_core::patch::rollback::{
    cannot_rollback_error, rollback_package_patch, verify_file_rollback, RollbackResult,
    VerifyRollbackResult, VerifyRollbackStatus,
};
use socket_patch_core::telemetry::{
    track_patch_rollback_failed, track_patch_rolled_back, TelemetryAuth,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::utils::target::{is_path_shaped, Target, TargetKind};
use socket_patch_core::vendor::{purl_keys_cover, RevertOpts, VendorState};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{apply_env_toggles, is_local_go, parse_bool_flag, GlobalArgs};
use crate::commands::hosted_unwind::{run_hosted_leg, HostedLegOutcome};
use crate::commands::lock_cli::acquire_or_emit;
use crate::commands::vendored_backend::{RevertedEntry, VendorRevertStep, VendoredBackend};
use crate::ecosystem_dispatch::{
    distinct_npm_copies, find_all_packages_for_rollback, partition_purls, JvmScope,
};
use crate::json_envelope::{
    Command as EnvelopeCommand, Envelope, EnvelopeError, GcReport, PatchAction, PatchEvent,
    PatchEventFile, Status,
};
use crate::ui::{plural, StatusLine};

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

/// Join prompt clauses as an English list: `a`, `a and b`, `a, b, and c`.
pub(crate) fn join_clauses(clauses: &[String]) -> String {
    match clauses {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [init @ .., last] => format!("{}, and {last}", init.join(", ")),
    }
}

/// The `hosted_state_not_preservable` run warning: a `--preserve-state`
/// run (rollback or remove) restored hosted pins to upstream anyway — the
/// lockfile pins are hosted mode's only record, so there is no local
/// state to keep.
pub(crate) fn hosted_state_not_preservable_warning() -> (String, String) {
    (
        "hosted_state_not_preservable".into(),
        "hosted wiring has no preservable local state: the lockfile pins are the only \
         record, and they now resolve upstream; re-run `scan --mode hosted` to re-wire"
            .into(),
    )
}

/// Capitalize the first character and end with `?`.
pub(crate) fn as_question(text: &str) -> String {
    if text.is_empty() {
        return String::new();
    }
    format!("{}?", crate::ui::sentence_case(text))
}

/// The default (destructive) rollback's confirmation prompt, naming only
/// the legs that have work.
fn rollback_prompt(manifest: usize, vendored: usize, hosted: usize) -> String {
    let mut clauses: Vec<String> = Vec::new();
    if manifest > 0 {
        clauses.push(format!(
            "roll back {}",
            plural(manifest, "patch", "patches")
        ));
        clauses.push(format!(
            "remove {} from the local manifest",
            if manifest == 1 { "it" } else { "them" }
        ));
    }
    if vendored > 0 {
        // Vendored-mode entries live only in the ledger (their embedded
        // patch record is the local copy), so name the ledger records as
        // what goes, the way the manifest clause names its entries.
        clauses.push(format!(
            "delete {} and {} ledger {}",
            plural(vendored, "vendored artifact", "vendored artifacts"),
            if vendored == 1 { "its" } else { "their" },
            if vendored == 1 { "record" } else { "records" }
        ));
    }
    if hosted > 0 {
        clauses.push(format!(
            "restore {} to the upstream registry",
            plural(hosted, "hosted package", "hosted packages")
        ));
    }
    as_question(&join_clauses(&clauses))
}

/// `Error: Failed to roll back <purl>: <why>` — the per-package failure
/// line `--silent` runs print inline (their summary is muted).
pub(crate) fn format_rollback_failure(purl: &str, why: &str) -> String {
    format!("Error: Failed to roll back {purl}: {why}")
}

/// The closing stderr error of a human run whose stdout report lists
/// failed packages (under `--silent` the per-package
/// [`format_rollback_failure`] lines print instead).
fn format_rollback_failed(dry_run: bool) -> &'static str {
    if dry_run {
        "Error: Some patches cannot be rolled back."
    } else {
        "Error: Some patches could not be rolled back."
    }
}

/// Per-package counts, keyed by `package_key` so two physical copies of
/// one purl count once (apply's summary counts the same way). A package
/// with any failed copy counts as failed; otherwise it is "already
/// original" only when every copy is.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RollbackTally {
    /// Some copy had files restored (wet run).
    pub(crate) rolled_back: usize,
    /// Some copy is not yet original (dry run: would be rolled back).
    pub(crate) can_roll_back: usize,
    /// Every copy already matches its beforeHash.
    pub(crate) already: usize,
    /// Some copy failed.
    pub(crate) failed: usize,
}

pub(crate) fn tally_rollback_results(results: &[RollbackResult]) -> RollbackTally {
    let mut by_key: std::collections::BTreeMap<&str, Vec<&RollbackResult>> =
        std::collections::BTreeMap::new();
    for r in results {
        by_key.entry(r.package_key.as_str()).or_default().push(r);
    }
    let mut tally = RollbackTally::default();
    for copies in by_key.values() {
        if copies.iter().any(|r| !r.success) {
            tally.failed += 1;
            continue;
        }
        if copies.iter().all(|r| all_files_already_original(r)) {
            tally.already += 1;
            continue;
        }
        tally.can_roll_back += 1;
        if copies.iter().any(|r| !r.files_rolled_back.is_empty()) {
            tally.rolled_back += 1;
        }
    }
    tally
}

/// The dry-run verification block, followed by the reason for each
/// package that cannot be rolled back (a dry run prints no other
/// failure report).
fn format_rollback_dry_run_counts(results: &[RollbackResult], cwd: &Path) -> Vec<String> {
    let tally = tally_rollback_results(results);
    let mut lines = vec![
        String::new(),
        "Rollback verification complete:".to_string(),
        format!(
            "  {} can be rolled back",
            plural(tally.can_roll_back, "package", "packages")
        ),
    ];
    if tally.already > 0 {
        lines.push(format!(
            "  {} already in original state",
            plural(tally.already, "package", "packages")
        ));
    }
    if tally.failed > 0 {
        lines.push(format!(
            "  {} cannot be rolled back",
            plural(tally.failed, "package", "packages")
        ));
    }
    lines.extend(format_rollback_failures(results, cwd));
    lines
}

/// `  <purl> (<copy>)` — the copy path only when the package has several.
fn copy_label(
    results: &[RollbackResult],
    r: &RollbackResult,
    note: Option<&str>,
    cwd: &Path,
) -> String {
    let copies = results
        .iter()
        .filter(|o| o.package_key == r.package_key)
        .count();
    let copy = (copies > 1).then(|| crate::ui::display_copy_path(&r.package_path, cwd));
    match (copy, note) {
        (Some(c), Some(n)) => format!("  {} ({c}, {n})", r.package_key),
        (Some(c), None) => format!("  {} ({c})", r.package_key),
        (None, Some(n)) => format!("  {} ({n})", r.package_key),
        (None, None) => format!("  {}", r.package_key),
    }
}

/// The `Failed to roll back:` section (empty when nothing failed).
fn format_rollback_failures(results: &[RollbackResult], cwd: &Path) -> Vec<String> {
    let failed: Vec<String> = results
        .iter()
        .filter(|r| !r.success)
        .map(|r| {
            format!(
                "{}: {}",
                copy_label(results, r, None, cwd),
                r.error.as_deref().unwrap_or("unknown error")
            )
        })
        .collect();
    let mut lines = Vec::new();
    if !failed.is_empty() {
        lines.push(String::new());
        lines.push("Failed to roll back:".to_string());
        lines.extend(failed);
    }
    lines
}

/// Purls (qualifiers stripped) whose installed tree this run leaves
/// original: restored now, restorable on a dry run, or already original.
/// Any successful in-place result that verified files qualifies — so a
/// dry run's reinstall note matches the wet run's, and a never-patched
/// tree is not reported as still holding patched bytes.
fn handled_in_place(results: &[RollbackResult]) -> HashSet<&str> {
    results
        .iter()
        .filter(|r| r.success && (!r.files_rolled_back.is_empty() || !r.files_verified.is_empty()))
        .map(|r| strip_purl_qualifiers(&r.package_key))
        .collect()
}

/// The wet run's per-package blocks: what was rolled back (naming each
/// physical copy when a package has several) and what failed.
fn format_rollback_results(results: &[RollbackResult], cwd: &Path) -> Vec<String> {
    let rolled_back: Vec<String> = results
        .iter()
        .filter(|r| r.success && !r.files_rolled_back.is_empty())
        .map(|r| copy_label(results, r, None, cwd))
        .chain(
            results
                .iter()
                .filter(|r| r.success && all_files_already_original(r))
                .map(|r| copy_label(results, r, Some("already original"), cwd)),
        )
        .collect();
    let mut lines = Vec::new();
    if !rolled_back.is_empty() {
        lines.push(String::new());
        lines.push("Rolled back packages:".to_string());
        lines.extend(rolled_back);
    }
    lines.extend(format_rollback_failures(results, cwd));
    lines
}

/// `--preserve-state`'s closing line (names vendored artifacts only when
/// some were preserved). Shared with `remove --preserve-state`.
pub(crate) fn format_preserved_note(entries: usize, vendored: usize) -> String {
    let entries_part = if entries == 1 {
        "Manifest entry"
    } else {
        "Manifest entries"
    };
    let (what, reapply) = match vendored {
        0 => (entries_part.to_string(), "`socket-patch apply`"),
        1 => (
            format!("{entries_part} and vendored artifact"),
            "`socket-patch apply` or `socket-patch vendor`",
        ),
        _ => (
            format!("{entries_part} and vendored artifacts"),
            "`socket-patch apply` or `socket-patch vendor`",
        ),
    };
    format!("{what} preserved (--preserve-state); re-apply with {reapply}.")
}

/// The GC line: `Freed 328.28 KB of unused blobs and archives`.
fn format_gc_freed(bytes: u64, dry_run: bool) -> String {
    format!(
        "{} {} of unused blobs and archives",
        if dry_run { "Would free" } else { "Freed" },
        socket_patch_core::manifest::cleanup_blobs::format_bytes(bytes)
    )
}

/// Appended to the generic stale-install advisory when a Bun advisory
/// fired in the same run: Bun's hoisted linker keeps the patched copy
/// through a plain `bun install` (#764), so "the next package-manager
/// install" alone would contradict it.
const BUN_REINSTALL_QUALIFIER: &str =
    " (Bun: a plain `bun install` keeps them; run `bun install --force`)";

/// True when the run's leg warnings carry a Bun reinstall advisory.
fn bun_reinstall_advised<'a>(mut codes: impl Iterator<Item = &'a str>) -> bool {
    codes.any(|c| {
        c == socket_patch_core::vendor::bun_lock::REINSTALL_REQUIRED
            || c == "redirect_bun_reinstall_required"
    })
}

/// The reinstall note for packages whose wiring was undone but whose
/// installed tree still holds patched bytes.
fn format_reinstall_note(still_patched: usize, dry_run: bool, bun: bool) -> String {
    let keep = match (still_patched == 1, dry_run) {
        (true, false) => "keeps its",
        (true, true) => "would keep its",
        (false, false) => "keep their",
        (false, true) => "would keep their",
    };
    format!(
        "Note: {} {keep} patched bytes in installed trees until the next \
         package-manager install{}.",
        plural(still_patched, "unwired package", "unwired packages"),
        if bun { BUN_REINSTALL_QUALIFIER } else { "" }
    )
}

/// One classified rollback target token.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RollbackTarget {
    /// A UUID, purl or package name in the shared target grammar
    /// ([`Target::matches_patch`]).
    Identifier(Target),
    /// A path glob scoping the run to patches with an installed copy
    /// under a matching path.
    PathGlob(String),
}

/// Shape-classify a target token. Only path-SHAPED tokens become globs
/// ([`is_path_shaped`]: separator, glob metachar, `./` prefix, or absolute;
/// an npm `@scope/name` is a name); `pkg:` and every other token keep the
/// shared target grammar, so a truncated UUID or a mistyped name stays a
/// safe "No patch found matching identifier" error instead of silently
/// selecting a directory subtree.
///
/// A path-shaped token without glob metacharacters (composer
/// `vendor/pkg`, a go module path) is promoted back to a name once the
/// stores are loaded, when it selects a recorded or hosted patch.
pub(crate) fn classify_target(token: &str) -> RollbackTarget {
    if is_path_shaped(token) {
        RollbackTarget::PathGlob(token.to_string())
    } else {
        RollbackTarget::Identifier(Target::parse(token))
    }
}

/// A path-shaped token that could also be a slash-containing package
/// name: relative, no glob metacharacter or backslash, no `.` / `..`
/// segment (`./x` and `x/..` are always paths).
fn is_name_shaped_path(token: &str) -> bool {
    !token.contains(['*', '?', '[', '\\'])
        && !std::path::Path::new(token).is_absolute()
        && !token.starts_with('/')
        && token
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
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
/// manifest via `RollbackOutcome::not_installed`).
pub(crate) struct RollbackOutcome {
    /// No attempted rollback failed (per-package; see above).
    pub(crate) success: bool,
    pub(crate) results: Vec<RollbackResult>,
    /// Vendor-owned purls excluded from in-place rollback (benign).
    pub(crate) vendored_skipped: Vec<String>,
    /// In-scope manifest entries with no installed package on disk —
    /// apply's `unmatched` twin (`package_not_installed`). Never in the
    /// before-blob plan, never a failed result. Sorted for determinism.
    pub(crate) not_installed: Vec<String>,
    /// Release-variant manifest entries narrowed away by
    /// `select_installed_variants` (their distribution is not on disk;
    /// an attempted sibling covered the group). The manifest-cleanup
    /// default drops them with their group. Empty on early returns.
    pub(crate) narrowed_out: Vec<String>,
    /// The run aborted at the before-blob gate BEFORE any restore ran
    /// (offline with missing blobs, or a failed download). The CLI
    /// boundary's manifest-cleanup default must skip entirely: nothing
    /// was restored, so nothing is removable and the GC must not sweep
    /// the revert data the retry needs.
    pub(crate) aborted: bool,
    /// Run warnings `(code, detail)` for copies left alone without failing
    /// the run (`gradle_m2_copy_not_restored`, `rollback_record_superseded`).
    pub(crate) warnings: Vec<(String, String)>,
    /// In-scope manifest entries superseded by a live hosted pin whose
    /// installed copies hold neither side of the recorded patch (#933):
    /// left to the hosted leg's lock restore instead of failing, and
    /// removable from the manifest like a rolled-back entry. Sorted.
    pub(crate) superseded: Vec<String>,
}

/// How `rollback_patches_inner` selects manifest entries.
pub(crate) enum InnerSelection<'a> {
    /// The legacy single-identifier filter (`remove`'s delegation): a
    /// no-match identifier is an error, a missing manifest is an error,
    /// and `None` selects the whole manifest.
    Identifier(Option<&'a Target>),
    /// A pre-resolved purl set from the CLI boundary's target resolver
    /// (identifiers ∪ path globs ∪ everything). No-match and
    /// missing-manifest handling already happened upstream, so an empty
    /// selection is a quiet success; `announce_empty` keeps the "No
    /// patches found in manifest" line for an unscoped run with no work
    /// in ANY leg (a hosted-/vendored-only project has work, so it is
    /// not "no patches").
    Scope {
        purls: &'a HashSet<String>,
        announce_empty: bool,
    },
}

// ── local-redirect rollback helpers (go only) ────────────────────────────────
// Local go rolls back by dropping the project-local redirect (go's `replace`
// directive) + the patched copy — no in-place restore, no before-blob. Cargo
// patches in place (vendored or registry cache), so it rolls back in place from
// before-blobs like npm/pypi. `is_local_go` is shared with `apply`, which
// creates the same redirects.

/// The before-blob gate's manifest: the ATTEMPTED (crawler-discovered)
/// entries of `scoped`, minus local-redirect PURLs (local-mode go). Those
/// roll back by dropping a project-local redirect and read no blobs, so a
/// missing before-blob must not block (or trigger a needless download for)
/// an offline redirect rollback.
fn before_blob_gate_manifest(
    scoped: &PatchManifest,
    attempted: &HashSet<&str>,
    common: &GlobalArgs,
) -> PatchManifest {
    PatchManifest {
        patches: scoped
            .patches
            .iter()
            .filter(|(purl, _)| attempted.contains(purl.as_str()) && !is_local_go(purl, common))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        setup: None,
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
    target: Option<&Target>,
) -> Vec<PatchToRollback> {
    manifest
        .patches
        .iter()
        .filter(|(purl, patch)| target.is_none_or(|t| t.matches_patch(purl, &patch.uuid)))
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

/// The camelCase per-file status a failed event's `details.filesVerified`
/// carries (the human `--verbose` block keeps the snake_case labels of
/// [`verify_rollback_status_str`]).
fn verify_rollback_status_camel(status: &VerifyRollbackStatus) -> &'static str {
    match status {
        VerifyRollbackStatus::Ready => "ready",
        VerifyRollbackStatus::AlreadyOriginal => "alreadyOriginal",
        VerifyRollbackStatus::HashMismatch => "hashMismatch",
        VerifyRollbackStatus::NotFound => "notFound",
        VerifyRollbackStatus::MissingBlob => "missingBlob",
    }
}

/// The `errorCode` of a failed agent-leg result: the first blocking file's
/// verify status, else the generic `rollback_failed` (a write error, a
/// local-go redirect that could not be dropped).
fn rollback_failure_code(result: &RollbackResult) -> &'static str {
    result
        .files_verified
        .iter()
        .find_map(|f| match f.status {
            VerifyRollbackStatus::HashMismatch => Some("hash_mismatch"),
            VerifyRollbackStatus::NotFound => Some("file_not_found"),
            VerifyRollbackStatus::MissingBlob => Some("missing_blob"),
            VerifyRollbackStatus::Ready | VerifyRollbackStatus::AlreadyOriginal => None,
        })
        .unwrap_or("rollback_failed")
}

/// The event one agent-leg (in-place) result becomes: `rolledBack` (wet
/// restore; `files` = the restored files), `verified` (dry-run preview;
/// `files` = the files that would be restored), `skipped`
/// `already_original`, or `failed` with the blocking file's code. The
/// installed copy rides in `details.path`; a failure adds
/// `details.filesVerified` (per-file camelCase status + hashes).
fn agent_result_event(result: &RollbackResult, uuid: Option<&str>, dry_run: bool) -> PatchEvent {
    let file = |path: &str| PatchEventFile {
        path: path.to_string(),
        verified: true,
        applied_via: None,
    };
    let mut details = serde_json::json!({ "path": result.package_path });
    let mut event = if !result.success {
        details["filesVerified"] = result
            .files_verified
            .iter()
            .map(|f| {
                serde_json::json!({
                    "file": f.file,
                    "status": verify_rollback_status_camel(&f.status),
                    "message": f.message,
                    "currentHash": f.current_hash,
                    "expectedHash": f.expected_hash,
                    "targetHash": f.target_hash,
                })
            })
            .collect();
        PatchEvent::new(PatchAction::Failed, result.package_key.clone()).with_error(
            rollback_failure_code(result),
            result.error.as_deref().unwrap_or("unknown error"),
        )
    } else if all_files_already_original(result) {
        PatchEvent::new(PatchAction::Skipped, result.package_key.clone()).with_reason(
            "already_original",
            "every file already matches its original (beforeHash) content",
        )
    } else if dry_run {
        PatchEvent::new(PatchAction::Verified, result.package_key.clone()).with_files(
            result
                .files_verified
                .iter()
                .filter(|f| f.status == VerifyRollbackStatus::Ready)
                .map(|f| file(&f.file))
                .collect(),
        )
    } else if !result.files_rolled_back.is_empty() {
        PatchEvent::new(PatchAction::RolledBack, result.package_key.clone())
            .with_files(result.files_rolled_back.iter().map(|f| file(f)).collect())
    } else {
        // A successful wet result that restored nothing and is not
        // "already original": a patch record that lists no files.
        PatchEvent::new(PatchAction::Skipped, result.package_key.clone())
            .with_reason("no_files", "the patch record lists no files to restore")
    };
    if let Some(uuid) = uuid {
        event = event.with_uuid(uuid);
    }
    event.with_details(details)
}

/// An in-scope manifest entry with no installed package: `skipped`
/// `package_not_installed` (apply's event, rollback-side). It never fails
/// the run — rollback exits 0 even when ALL in-scope targets land here
/// (see `RollbackOutcome` for the apply/rollback asymmetry).
fn not_installed_event(purl: &str, uuid: Option<&str>) -> PatchEvent {
    let event = PatchEvent::new(PatchAction::Skipped, purl).with_reason(
        "package_not_installed",
        "no installed package matches this manifest entry",
    );
    match uuid {
        Some(uuid) => event.with_uuid(uuid),
        None => event,
    }
}

/// Per-package failure results for the pre-flight before-blob abort.
///
/// The abort fires before the rollback loop produces any per-package
/// results, so without these the `--json` envelope claimed
/// `summary.failed: 0` with no events on an exit-1 run — contentless and
/// self-contradictory, and `--json` mutes the stderr explanation the
/// human path gets. One failed result (a `failed` `missing_blob` event)
/// per affected package keeps `summary.failed` meaning "packages that failed" (the same per-package
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

/// Rollback's `--json` failure document: a full envelope with
/// `status: "error"`, empty `events`, a zero `summary` and `error: {code,
/// message}`.
fn error_envelope(dry_run: bool, err: EnvelopeError) -> Envelope {
    let mut env = Envelope::new(EnvelopeCommand::Rollback);
    env.dry_run = dry_run;
    env.mark_error(err);
    env
}

/// Report a top-level rollback error: the error envelope on `--json`
/// (message verbatim), an `Error:` stderr line otherwise. Errors print even
/// under --silent ("errors only", never "nothing").
fn emit_rollback_error(json: bool, dry_run: bool, code: &str, msg: &str) {
    if json {
        println!(
            "{}",
            error_envelope(dry_run, EnvelopeError::new(code, msg)).to_pretty_json()
        );
    } else {
        eprintln!("Error: {}", crate::ui::sentence_case(msg));
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
    /// `(key, errorCode, error)`: `vendor_revert_failed`, or
    /// `vendor_state_write_failed` when the revert landed but the ledger
    /// could not be saved.
    failed: Vec<(String, &'static str, String)>,
    warnings: Vec<(String, String)>,
}

/// Unwire the in-scope vendored entries. `preserve` keeps artifacts and
/// ledger entries (only the lockfile wiring is restored); otherwise a
/// clean revert drops the entry and saves the ledger per purl.
async fn run_vendored_leg(
    common: &GlobalArgs,
    keys: &[String],
    state: &mut VendorState,
    preserve: bool,
) -> VendoredLegOutcome {
    let mut out = VendoredLegOutcome::default();
    let opts = RevertOpts {
        dry_run: common.dry_run,
        keep_artifact: preserve,
    };
    let loud = !common.json && !common.silent;
    let reverted = VendoredBackend::new(common, None)
        .revert(keys, state, opts, false)
        .await;
    for RevertedEntry {
        key,
        warnings,
        step,
        ..
    } in reverted
    {
        for w in &warnings {
            if loud {
                eprintln!("Warning: {}", w.detail);
            }
            out.warnings.push((w.code.to_string(), w.detail.clone()));
        }
        match step {
            VendorRevertStep::Missing => {}
            VendorRevertStep::Failed(why) => {
                // Errors print even under --silent.
                if !common.json {
                    eprintln!("Error: Failed to revert vendoring for {key}: {why}");
                }
                out.failed.push((key, "vendor_revert_failed", why));
            }
            VendorRevertStep::Kept => out.kept.push((
                key,
                "lockfile wiring drifted; vendored state left untouched".to_string(),
            )),
            VendorRevertStep::WouldRevert if preserve => {
                if loud {
                    println!("Would unwire vendoring for {key} (artifact preserved)");
                }
                out.preserved.push(key);
            }
            VendorRevertStep::WouldRevert => {
                if loud {
                    println!("Would revert vendoring for {key}");
                }
                out.reverted.push(key);
            }
            VendorRevertStep::Preserved => {
                if loud {
                    println!("Unwired vendoring for {key} (artifact preserved)");
                }
                out.preserved.push(key);
            }
            VendorRevertStep::Reverted => {
                if loud {
                    println!("Reverted vendoring for {key}");
                }
                out.reverted.push(key);
            }
            VendorRevertStep::LedgerWriteFailed(e) => {
                let why = format!("vendor ledger write failed: {e}");
                // Errors print even under --silent: this drives exit 1.
                if !common.json {
                    eprintln!("Error: Failed to revert vendoring for {key}: {why}");
                }
                out.failed.push((key, "vendor_state_write_failed", why));
            }
        }
    }
    out
}

/// Hosted-leg failure keys that are not purls: `run_hosted_leg`'s lockfile
/// write failure (an artifact-level event, `hosted_write_failed`).
const HOSTED_WRITE_FAILURE_KEY: &str = "files";

/// Everything the main rollback run reports, for [`build_rollback_envelope`].
struct RollbackReport<'a> {
    dry_run: bool,
    /// Whether the run leaves the system unpatched: false drives exit 1 and
    /// at least `partialFailure`.
    success: bool,
    manifest: &'a PatchManifest,
    results: &'a [RollbackResult],
    not_installed: &'a [String],
    vendored: &'a VendoredLegOutcome,
    vendor_entries: &'a [(String, socket_patch_core::vendor::VendorEntry)],
    hosted: &'a HostedLegOutcome,
    hosted_pins: &'a [HostedPin],
    /// An unscoped run's contested hosted wiring (`hosted_wiring_contested`).
    contested: Option<&'a str>,
    /// Manifest entries the run dropped (would drop, on a dry run).
    removed: &'a [String],
    gc: Option<GcReport>,
    warnings: &'a [(String, String)],
    paths: &'a [String],
}

/// Rollback's `--json` envelope (v5.0): one event per outcome across the
/// three legs plus the manifest cleanup, `summary` counted from them.
///
/// * agent leg: [`agent_result_event`] per installed copy, then one
///   `skipped` `package_not_installed` per in-scope entry with no copy;
/// * vendored leg (`details.mode: "vendored"`): reverted / preserved
///   entries are `rolledBack` (`verified` on a dry run; preserved adds
///   `details.preserved: true`), drift-keeps `failed` `vendor_revert_kept`,
///   failures `failed` with their code;
/// * hosted leg (`details.mode: "hosted"`): restored pins `rolledBack`
///   (`verified`), refusals `failed` `hosted_restore_refused`, a lockfile
///   write failure an artifact-level `failed` `hosted_write_failed`,
///   contested wiring an artifact-level `failed` `hosted_wiring_contested`;
/// * manifest cleanup: each dropped entry is `removed` (`verified` on a dry
///   run) with `details.manifest: true`.
///
/// Status: `success` iff `report.success`; a failure with nothing restored,
/// restorable, already original or not installed is `error`
/// `rollback_failed` (#1066); anything else is `partialFailure`.
fn build_rollback_envelope(report: &RollbackReport<'_>) -> Envelope {
    let dry_run = report.dry_run;
    let mut env = Envelope::new(EnvelopeCommand::Rollback);
    env.dry_run = dry_run;
    let restored = if dry_run {
        PatchAction::Verified
    } else {
        PatchAction::RolledBack
    };
    let with_uuid = |event: PatchEvent, uuid: Option<&str>| match uuid {
        Some(uuid) => event.with_uuid(uuid),
        None => event,
    };

    // ── agent leg ──
    let manifest_uuid = |purl: &str| report.manifest.patches.get(purl).map(|p| p.uuid.as_str());
    for result in report.results {
        env.record(agent_result_event(
            result,
            manifest_uuid(&result.package_key),
            dry_run,
        ));
        if let Some(sidecar) = &result.sidecar {
            env.sidecars.push(sidecar.clone());
        }
    }
    for purl in report.not_installed {
        env.record(not_installed_event(purl, manifest_uuid(purl)));
    }

    // ── vendored leg ──
    let vendored = |details: serde_json::Value| {
        let mut d = serde_json::json!({ "mode": "vendored" });
        if let (Some(d), Some(extra)) = (d.as_object_mut(), details.as_object()) {
            d.extend(extra.clone());
        }
        d
    };
    let vendor_uuid = |key: &str| {
        report
            .vendor_entries
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, e)| e.uuid.as_str())
    };
    let leg = report.vendored;
    for key in &leg.reverted {
        env.record(with_uuid(
            PatchEvent::new(restored, key.clone()).with_details(vendored(serde_json::json!({}))),
            vendor_uuid(key),
        ));
    }
    for key in &leg.preserved {
        env.record(with_uuid(
            PatchEvent::new(restored, key.clone())
                .with_details(vendored(serde_json::json!({ "preserved": true }))),
            vendor_uuid(key),
        ));
    }
    for (key, reason) in &leg.kept {
        env.record(with_uuid(
            PatchEvent::new(PatchAction::Failed, key.clone())
                .with_error("vendor_revert_kept", reason.clone())
                .with_details(vendored(serde_json::json!({}))),
            vendor_uuid(key),
        ));
    }
    for (key, code, error) in &leg.failed {
        env.record(with_uuid(
            PatchEvent::new(PatchAction::Failed, key.clone())
                .with_error(*code, error.clone())
                .with_details(vendored(serde_json::json!({}))),
            vendor_uuid(key),
        ));
    }

    // ── hosted leg ──
    let hosted = || serde_json::json!({ "mode": crate::commands::HOSTED_MODE_LABEL });
    let pin_uuid = |purl: &str| {
        report
            .hosted_pins
            .iter()
            .find(|pin| pin.purl == purl)
            .map(|pin| pin.uuid.as_str())
    };
    let leg = report.hosted;
    for purl in &leg.reverted {
        env.record(with_uuid(
            PatchEvent::new(restored, purl.clone()).with_details(hosted()),
            pin_uuid(purl),
        ));
    }
    for (purl, error) in &leg.failed {
        let event = if purl == HOSTED_WRITE_FAILURE_KEY {
            PatchEvent::artifact(PatchAction::Failed).with_error("hosted_write_failed", error.clone())
        } else {
            with_uuid(
                PatchEvent::new(PatchAction::Failed, purl.clone())
                    .with_error("hosted_restore_refused", error.clone()),
                pin_uuid(purl),
            )
        };
        env.record(event.with_details(hosted()));
    }
    for purl in &leg.unsupported {
        env.record(
            PatchEvent::new(PatchAction::Failed, purl.clone())
                .with_error(
                    "hosted_unsupported",
                    "this ecosystem has no per-package hosted restore",
                )
                .with_details(hosted()),
        );
    }
    if let Some(refusal) = report.contested {
        env.record(
            PatchEvent::artifact(PatchAction::Failed)
                .with_error("hosted_wiring_contested", refusal)
                .with_details(hosted()),
        );
    }

    // ── manifest cleanup ──
    let removal = if dry_run {
        PatchAction::Verified
    } else {
        PatchAction::Removed
    };
    for purl in report.removed {
        env.record(with_uuid(
            PatchEvent::new(removal, purl.clone())
                .with_details(serde_json::json!({ "manifest": true })),
            manifest_uuid(purl),
        ));
    }

    if let Some(gc) = report.gc {
        env.set_gc(gc);
    }
    for (code, detail) in report.warnings {
        env.warn(code.clone(), detail.clone());
    }
    env.set_extra(
        "hosted",
        serde_json::json!({ "editedFiles": report.hosted.edited_files.len() }),
    );
    env.set_extra("paths", serde_json::json!(report.paths));

    // ── status ──
    if !report.success {
        // Run-level failures (a corrupt vendor ledger, a failed manifest
        // write) carry no event but still leave the system patched.
        env.mark_partial_failure();
        let s = &env.summary;
        let reached_unpatched = s.rolled_back > 0
            || s.verified > 0
            || env.events.iter().any(|e| {
                e.action == PatchAction::Skipped
                    && matches!(
                        e.error_code.as_deref(),
                        Some("already_original" | "package_not_installed")
                    )
            });
        if s.failed > 0 && !reached_unpatched {
            let message = format!(
                "nothing was rolled back: {}",
                plural(s.failed as usize, "patch failed", "patches failed")
            );
            env.mark_error(EnvelopeError::new("rollback_failed", message));
        }
    } else {
        debug_assert_eq!(env.status, Status::Success, "a failed event on a success run");
    }
    env
}

/// Delete a pre-v5 hosted ledger once no hosted pin is left for it to
/// describe (v5 never writes it; it is read only for migration). A wet run
/// only; a failure is a warning (the file is inert).
pub(crate) async fn retire_legacy_redirect_ledger(common: &GlobalArgs) -> Option<(String, String)> {
    let path = common
        .cwd
        .join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL);
    if common.dry_run
        || !crate::commands::project_state_in_scope(common)
        || tokio::fs::symlink_metadata(&path).await.is_err()
    {
        return None;
    }
    let remaining = crate::commands::discover_wiring(common, &common.cwd).await;
    if !HostedPin::all(&remaining).is_empty() {
        return None;
    }
    // The emptied `.socket/vendor/` goes with it; the apply lock's drop
    // prunes an emptied `.socket/` itself.
    let stop = common.cwd.join(socket_patch_core::constants::SOCKET_DIR);
    match socket_patch_core::utils::socket_dir::remove_file_and_prune(&path, &stop).await {
        Ok(()) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some((
            "legacy_redirect_ledger_kept".to_string(),
            format!(
                "could not delete the pre-v5 hosted ledger {}: {e}",
                socket_patch_core::patch::redirect::REDIRECT_STATE_REL
            ),
        )),
    }
}

pub async fn run(args: RollbackArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Classify targets up front: the glob validation is a pre-network
    // usage check.
    let mut identifiers: Vec<Target> = Vec::new();
    let mut path_patterns: Vec<String> = Vec::new();
    for token in &args.targets {
        match classify_target(token) {
            RollbackTarget::Identifier(id) => identifiers.push(id),
            RollbackTarget::PathGlob(p) => path_patterns.push(p),
        }
    }

    // An unparseable glob is a usage error — same exit-2 shape as scan's
    // self-enforced usage errors.
    let path_scope = match crate::path_scope::PathScope::parse(&path_patterns) {
        Ok(s) => s,
        Err(e) => {
            // Like emit_rollback_error: JSON keeps the verbatim message,
            // only the human stderr line is sentence-cased.
            let message = if args.common.json {
                e.to_string()
            } else {
                crate::ui::sentence_case(&e.to_string())
            };
            return crate::json_envelope::usage_error(
                crate::json_envelope::Command::Rollback,
                args.common.json,
                args.common.dry_run,
                "path_glob_invalid",
                &message,
            );
        }
    };

    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let telemetry = TelemetryAuth::for_client(&telemetry_client);

    let manifest_path = args.common.resolved_manifest_path();
    let cwd = args.common.cwd.clone();

    // ── state discovery ─────────────────────────────────────────────────
    // Rollback infers what to undo from three sources: the manifest
    // (in-place/agent patches), the vendor ledger (vendored patches), and
    // the lockfiles themselves (hosted pins — v5 hosted mode keeps no
    // ledger). A missing manifest is not fatal when either holds work.
    //
    // Only cheap EXISTENCE probes happen before the lock (they decide the
    // truly-empty error path, which never locks: acquiring would create
    // `.socket/` only for the guard's drop to prune it again, and a bare
    // project must never see the directory flicker). The stores
    // themselves are LOADED UNDER the apply lock below: this run persists
    // mutated clones of the ledgers, so a pre-lock snapshot could clobber
    // a concurrent run's writes with stale state.
    //
    // Under global scope the project's hosted pins and vendor ledger are
    // not this run's to unwind (see `project_state_in_scope`): a global
    // rollback restores the global copies and their manifest records only.
    let project_state = crate::commands::project_state_in_scope(&args.common);
    let manifest_missing = tokio::fs::metadata(&manifest_path).await.is_err();
    let vendor_ledger_exists = project_state
        && tokio::fs::metadata(cwd.join(".socket/vendor/state.json"))
            .await
            .is_ok();
    // The hosted pins the lockfiles wire (read-only discovery; the restore
    // re-reads every file under the lock before it writes).
    let hosted_inventory = if project_state {
        crate::commands::hosted_inventory(&args.common, &cwd).await
    } else {
        Default::default()
    };
    let hosted_pins: Vec<HostedPin> = hosted_inventory.pins.clone();

    if manifest_missing && !vendor_ledger_exists && hosted_pins.is_empty() {
        // Hosted wiring the lockfiles name but cannot attribute is still
        // hosted state: refuse, naming it, instead of "Manifest not found".
        if let Some(refusal) = hosted_inventory.contested_refusal() {
            emit_rollback_error(
                args.common.json,
                args.common.dry_run,
                "hosted_wiring_contested",
                &refusal,
            );
            return 1;
        }
        // Only a pre-v5 hosted ledger left: no lockfile pins it any more,
        // so there is nothing to restore — retire the stale file (a wet run
        // only) instead of failing on the missing manifest.
        let legacy = cwd.join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL);
        if project_state && tokio::fs::symlink_metadata(&legacy).await.is_ok() {
            let warning = retire_legacy_redirect_ledger(&args.common).await;
            if args.common.json {
                let mut env = Envelope::new(EnvelopeCommand::Rollback);
                env.dry_run = args.common.dry_run;
                if let Some((code, detail)) = &warning {
                    env.warn(code.clone(), detail.clone());
                }
                env.set_extra(
                    "legacyRedirectLedgerRemoved",
                    serde_json::json!(warning.is_none() && !args.common.dry_run),
                );
                println!("{}", env.to_pretty_json());
            } else if let Some((_, detail)) = &warning {
                eprintln!("Warning: {}", crate::ui::sentence_case(detail));
            } else if !args.common.silent {
                println!(
                    "{} the pre-v5 hosted ledger {}: no lockfile pins a hosted patch.",
                    if args.common.dry_run {
                        "Would remove"
                    } else {
                        "Removed"
                    },
                    socket_patch_core::patch::redirect::REDIRECT_STATE_REL
                );
            }
            return 0;
        }
        // Ledger-less but still wired? (a deleted/uncommitted state.json
        // with lockfiles still consuming `.socket/vendor/` artifacts: the
        // ledger holds the pre-vendor originals, so it must come back from
        // version control first.)
        let wired = if project_state {
            crate::commands::vendored_backend::repair::scan_vendor_references(&cwd).await
        } else {
            Default::default()
        };
        if !wired.is_empty() {
            emit_rollback_error(
                args.common.json,
                args.common.dry_run,
                "vendor_ledger_missing",
                "lockfiles still reference .socket/vendor/ artifacts but the vendor ledger \
                 is missing — restore .socket/vendor/state.json from version control, then \
                 roll back (or restore the lockfiles with `git checkout -- <lockfile>`)",
            );
            return 1;
        }
        if args.common.json {
            let mut env = error_envelope(
                args.common.dry_run,
                EnvelopeError::new(
                    "manifest_not_found",
                    format!("Manifest not found at {}", manifest_path.display()),
                ),
            );
            env.set_extra("path", serde_json::json!(manifest_path.display().to_string()));
            println!("{}", env.to_pretty_json());
        } else {
            // Errors print even under --silent ("errors only", never
            // "nothing"): exit 1 with no message would be undiagnosable.
            eprintln!("Error: Manifest not found at {}", manifest_path.display());
        }
        return 1;
    }

    // Serialize against concurrent socket-patch runs targeting the
    // same `.socket/` directory. See
    // `socket_patch_core::patch::apply_lock`.
    let socket_dir = crate::args::socket_dir_of(&manifest_path, &cwd);
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

    // Load the state stores UNDER the lock (see the discovery note above),
    // each exactly once: the agent leg below receives the manifest and the
    // vendor-ownership key set instead of re-reading them.
    //
    // Under global scope the ledger is read only to keep the project's
    // vendored manifest records (see the cleanup below): no vendored leg
    // runs, and the ledger does not own the global copies, so the in-place
    // leg restores them.
    let loaded_vendor_state = socket_patch_core::vendor::load_state(&cwd).await;
    let project_vendored_keys: HashSet<PurlKey> = loaded_vendor_state
        .as_ref()
        .map(VendorState::purl_keys)
        .unwrap_or_default();
    let ledger_unreadable = loaded_vendor_state.is_err();
    let vendor_state_result = if project_state {
        loaded_vendor_state
    } else {
        Ok(VendorState::default())
    };
    let vendor_corrupt = vendor_state_result.is_err();
    // An unreadable ledger degrades to "nothing vendored" for the in-place
    // leg (its own containment is the `vendor_state_unreadable` exit below).
    let vendored_keys: HashSet<PurlKey> = vendor_state_result
        .as_ref()
        .map(VendorState::purl_keys)
        .unwrap_or_default();

    // ── scope resolution ────────────────────────────────────────────────
    let manifest = if manifest_missing {
        PatchManifest::new()
    } else {
        match read_manifest(&manifest_path).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                // Deleted between the existence probe and the read.
                let msg = format!("Manifest not found at {}", manifest_path.display());
                track_patch_rollback_failed(&msg, &telemetry).await;
                emit_rollback_error(
                    args.common.json,
                    args.common.dry_run,
                    "manifest_not_found",
                    &msg,
                );
                return 1;
            }
            Err(e) => {
                let msg = e.to_string();
                track_patch_rollback_failed(&msg, &telemetry).await;
                if args.common.json {
                    let err = crate::json_envelope::manifest_load_error(&manifest_path, &e);
                    println!(
                        "{}",
                        error_envelope(args.common.dry_run, err).to_pretty_json()
                    );
                } else {
                    eprintln!("Error: {}", crate::ui::sentence_case(&msg));
                }
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
    let redirect_records: Vec<(String, String)> = hosted_pins
        .iter()
        .map(|pin| (pin.purl.clone(), pin.uuid.clone()))
        .collect();

    let ledgers = socket_patch_core::ledgers::Ledgers {
        manifest: Some(&manifest),
        vendor: vendor_state_result.as_ref().ok(),
        redirect: None,
    };
    // A slash-containing package name (composer `vendor/pkg`, a go module
    // path) is shaped like a path, but is a target first: one that selects
    // a recorded or hosted patch is an identifier, as in `get` and
    // `remove`; only otherwise is it a path glob.
    let (identifiers, path_scope) = {
        let mut identifiers = identifiers;
        let mut globs: Vec<String> = Vec::new();
        for raw in path_scope.raw() {
            let named = is_name_shaped_path(raw)
                .then(|| Target::parse(raw))
                .filter(|t| {
                    t.kind() == TargetKind::Name
                        && (!ledgers.matching(t).is_empty()
                            || redirect_records
                                .iter()
                                .any(|(purl, uuid)| t.matches_patch(purl, uuid)))
                });
            match named {
                Some(t) => identifiers.push(t),
                None => globs.push(raw.clone()),
            }
        }
        let path_scope =
            crate::path_scope::PathScope::parse(&globs).expect("a subset of the parsed patterns");
        (identifiers, path_scope)
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
        // Hosted pins live in the lockfiles, not in a store: matched by the
        // target, or as another generation of a matched manifest key.
        let select = |id: &Target| {
            let found = ledgers.matching(id);
            let pins =
                socket_patch_core::ledgers::hosted_pins_matching(&hosted_pins, id, &found.manifest);
            (found, pins)
        };
        // A name reaching several packages by last segment (`core` →
        // `@angular/core` and `@babel/core`) is refused across every
        // store: `rollback` acts on one package per name, and only on the
        // one the check settled on (`lodash` beside `@types/lodash` is
        // `lodash` alone).
        let settled = {
            let (found, pins) = select(id);
            id.settle(
                found
                    .manifest
                    .iter()
                    .map(String::as_str)
                    .chain(found.vendor.iter().map(|(k, e)| e.ambiguity_purl(k, id)))
                    .chain(pins.iter().map(|pin| pin.purl.as_str())),
            )
        };
        let id = match settled {
            Ok(settled) => settled,
            Err(msg) => {
                track_patch_rollback_failed(&msg, &telemetry).await;
                emit_rollback_error(
                    args.common.json,
                    args.common.dry_run,
                    "ambiguous_target",
                    &msg,
                );
                return 1;
            }
        };
        let (found, pins) = select(&id);
        let matched = !found.is_empty() || !pins.is_empty();
        manifest_scope.extend(found.manifest);
        vendor_scope.extend(found.vendor.into_iter().map(|(k, _)| k));
        hosted_scope.extend(pins.into_iter().map(|pin| pin.purl));
        if !matched {
            let hint = if matches!(id.kind(), TargetKind::Purl | TargetKind::Uuid) {
                String::new()
            } else {
                format!(" (to target a directory instead, use ./{id} or {id}/**)")
            };
            let msg = format!("No patch found matching identifier: {id}{hint}");
            track_patch_rollback_failed(&msg, &telemetry).await;
            if args.common.json {
                println!(
                    "{}",
                    error_envelope(
                        args.common.dry_run,
                        EnvelopeError::new("patch_not_found", msg)
                    )
                    .to_pretty_json()
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
        // One single-pattern scope per raw pattern, compiled once (not per
        // discovered copy), so each pattern can be checked for a match.
        let singles: Vec<crate::path_scope::PathScope> = path_scope
            .raw()
            .iter()
            .map(|raw| {
                crate::path_scope::PathScope::parse(std::slice::from_ref(raw))
                    .expect("already parsed above")
            })
            .collect();
        let mut matched_patterns: HashSet<usize> = HashSet::new();
        let mut path_selected: HashSet<String> = HashSet::new();
        for (purl, paths) in &discovered {
            for path in paths {
                for (idx, single) in singles.iter().enumerate() {
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
            track_patch_rollback_failed(&msg, &telemetry).await;
            emit_rollback_error(
                args.common.json,
                args.common.dry_run,
                "path_glob_no_match",
                &msg,
            );
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

    // `--ecosystems` narrows every leg. The agent engine scopes the
    // manifest side again internally; narrowing it here too keeps the
    // confirmation prompt's count honest (an npm-only manifest under
    // `-e pypi` has nothing to roll back, so there is nothing to confirm).
    let scope_before_eco_filter = manifest_scope.len() + vendor_scope.len() + hosted_scope.len();
    if let Some(ecosystems) = args.common.ecosystems.as_deref() {
        let manifest_purls: Vec<String> = manifest_scope.iter().cloned().collect();
        let in_eco: HashSet<String> = partition_purls(&manifest_purls, Some(ecosystems))
            .into_values()
            .flatten()
            .collect();
        manifest_scope.retain(|purl| in_eco.contains(purl));
        vendor_scope.retain(|key| {
            vendor_entries
                .iter()
                .find(|(k, _)| k == key)
                .is_some_and(|(_, e)| {
                    crate::commands::vendor::ecosystem_in_scope(&args.common, &e.ecosystem)
                })
        });
        hosted_scope.retain(|purl| {
            Ecosystem::from_purl(purl).is_some_and(|e| {
                crate::commands::vendor::ecosystem_in_scope(&args.common, e.cli_name())
            })
        });
    }

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
                vendor_state_result
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
    // Everything in scope was filtered out by `--ecosystems`: say so,
    // instead of the misleading "No patches found in manifest".
    let eco_filtered_everything = !has_work && scope_before_eco_filter > 0;
    if eco_filtered_everything && !args.common.json && !args.common.silent {
        println!(
            "No patches in scope for --ecosystems {}",
            args.common
                .ecosystems
                .as_deref()
                .unwrap_or_default()
                .join(",")
        );
    }
    if has_work && !args.common.dry_run && !args.preserve_state {
        // Compose only the clauses that apply, so a hosted-only run never
        // claims manifest entries it does not have.
        let prompt = rollback_prompt(manifest_scope.len(), vendor_scope.len(), hosted_scope.len());
        if !crate::ui::confirm(&prompt, true, &args.common) {
            if !args.common.json && !args.common.silent {
                println!("{}", crate::ui::CANCELLED);
            }
            return 0;
        }
    }

    // ── agent leg (in-place restore) ────────────────────────────────────
    // The "No patches found in manifest" line is for an unscoped run with
    // nothing to do anywhere: a hosted-/vendored-only project has work in
    // the other legs and is not "no patches". A manifest-less project, or
    // one whose scope `--ecosystems` filtered out entirely (announced
    // above), is not told its manifest is empty either.
    let selection = InnerSelection::Scope {
        purls: &manifest_scope,
        announce_empty: !scoped && !manifest_missing && !has_work && !eco_filtered_everything,
    };
    match rollback_patches_inner(
        &args.common,
        &socket_dir,
        &manifest,
        &vendored_keys,
        selection,
        &superseded_by_hosted(&manifest, &hosted_pins),
        Some(&telemetry_client),
    )
    .await
    {
        Ok(RollbackOutcome {
            success: agent_success,
            results,
            vendored_skipped: vendored_excluded,
            not_installed,
            narrowed_out,
            aborted,
            warnings: agent_warnings,
            superseded,
        }) => {
            // Copies left alone without failing the run (an unconsumed
            // `~/.m2` copy: `gradle_m2_copy_not_restored`).
            run_warnings.extend(agent_warnings);
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

            // ── hosted leg ───────────────────────────────────────────────
            let in_scope: Vec<HostedPin> = hosted_pins
                .iter()
                .filter(|pin| hosted_scope.contains(&pin.purl))
                .cloned()
                .collect();
            let hosted_leg = run_hosted_leg(&args.common, &in_scope).await;
            // An unscoped rollback promises to unwind EVERY hosted patch:
            // contested wiring it cannot restore fails the leg (a scoped run
            // names its own targets and leaves unrelated wiring alone).
            let contested = if scoped {
                None
            } else {
                hosted_inventory.contested_refusal()
            };
            if let Some(refusal) = &contested {
                if !args.common.json {
                    eprintln!("Error: {}", crate::ui::sentence_case(refusal));
                }
            }
            if hosted_leg.failed.is_empty() && contested.is_none() {
                if let Some(warning) = retire_legacy_redirect_ledger(&args.common).await {
                    run_warnings.push(warning);
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
            // A global run keeps the project's vendored records too: their
            // vendored state is not unwound, so dropping them would hand a
            // later `vendor` reconcile a revert with no backing record. An
            // unreadable ledger leaves that ownership unknowable either way.
            let cleanup_allowed = !args.preserve_state && !aborted && !ledger_unreadable;
            // A vendor-owned manifest purl is removable only when its
            // ledger entry was cleanly reverted this run (drift-keeps and
            // failures keep the record; the matching mirrors the
            // ledger-key / base-purl / qualifier-stripped triple).
            let vendored_reverted_ok = |purl: &str| {
                vendored_leg.reverted.iter().any(|key| {
                    vendor_entries
                        .iter()
                        .find(|(k, _)| k == key)
                        .is_some_and(|(k, e)| e.covers_purl(k, purl))
                })
            };
            let succeeded_purls: HashSet<String> = results
                .iter()
                .filter(|r| r.success)
                .map(|r| r.package_key.clone())
                .collect();
            // Bases whose attempted variant(s) failed hold their whole
            // group in the manifest (narrowed-away siblings included).
            let failed_bases: HashSet<&str> = failed_purls
                .iter()
                .map(|p| strip_purl_qualifiers(p))
                .collect();
            let mut removable: Vec<String> = manifest_scope
                .iter()
                .filter(|purl| {
                    if failed_purls.contains(*purl) {
                        return false;
                    }
                    if !project_state && purl_keys_cover(&project_vendored_keys, purl) {
                        return false;
                    }
                    if vendored_excluded.contains(purl) {
                        return vendored_reverted_ok(purl);
                    }
                    succeeded_purls.contains(*purl)
                        || not_installed.contains(purl)
                        || superseded.contains(purl)
                        || (narrowed_out.contains(purl)
                            && !failed_bases.contains(strip_purl_qualifiers(purl)))
                })
                .cloned()
                .collect();
            removable.sort();

            // The manifest is rewritten only when an entry actually leaves
            // it; an emptied manifest stays on disk as `{"patches": {}}`
            // (it carries any legacy setup block and `list`/`apply`/`repair`'s
            // empty-vs-missing exit codes) — never deleted.
            let mut removed: Vec<String> = Vec::new();
            let mut updated_manifest = manifest.clone();
            let mut manifest_write_failed: Option<String> = None;
            if cleanup_allowed && !removable.is_empty() {
                updated_manifest
                    .patches
                    .retain(|purl, _| !removable.contains(purl));
                removed = removable;
                if !args.common.dry_run {
                    if let Err(e) = write_manifest(&manifest_path, &updated_manifest).await {
                        manifest_write_failed = Some(e.to_string());
                        removed.clear();
                        updated_manifest = manifest.clone();
                    }
                }
            }

            // ── GC ───────────────────────────────────────────────────────
            // Removal retains originals for active patches and crawler misses.
            let mut gc: Option<GcReport> = None;
            if cleanup_allowed {
                let references = ArtifactReferences::after_removal(
                    &manifest,
                    &updated_manifest,
                    removed
                        .iter()
                        .filter(|p| not_installed.contains(p))
                        .map(String::as_str),
                );
                let sweep = references.sweep(&socket_dir, args.common.dry_run).await;
                for (label, result) in [
                    ("blob", &sweep.blobs),
                    ("diffs", &sweep.diffs),
                    ("packages", &sweep.packages),
                ] {
                    if let Some(detail) = crate::ui::sweep_failure(label, result) {
                        run_warnings.push(("cleanup_failed".into(), detail));
                    }
                }
                gc = Some(GcReport::from_passes(
                    sweep.blobs.as_ref().ok(),
                    sweep.diffs.as_ref().ok(),
                    sweep.packages.as_ref().ok(),
                ));
            }
            let gc_bytes_freed = gc.map_or(0, |gc| gc.bytes_freed);

            // ── run-level warnings ───────────────────────────────────────
            let unwired_any = !vendored_leg.reverted.is_empty()
                || !vendored_leg.preserved.is_empty()
                || !hosted_leg.reverted.is_empty();
            let bun_advised = bun_reinstall_advised(
                vendored_leg
                    .warnings
                    .iter()
                    .chain(hosted_leg.warnings.iter())
                    .map(|(code, _)| code.as_str()),
            );
            if unwired_any {
                run_warnings.push((
                    "reinstall_required".into(),
                    format!(
                        "unwired packages keep their patched bytes in installed trees until \
                         the next package-manager install{}",
                        if bun_advised {
                            BUN_REINSTALL_QUALIFIER
                        } else {
                            ""
                        }
                    ),
                ));
            }
            if args.preserve_state && !hosted_leg.reverted.is_empty() {
                run_warnings.push(hosted_state_not_preservable_warning());
            }
            if !path_scope.is_empty() {
                let scope = path_scope.bind(&cwd);
                let out_of_scope: Vec<&str> = results
                    .iter()
                    .filter(|r| {
                        r.success
                            && !r.files_rolled_back.is_empty()
                            && !scope.matches(Path::new(&r.package_path))
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
                            if out_of_scope.len() == 1 {
                                "y lives"
                            } else {
                                "ies live"
                            }
                        ),
                    ));
                }
            }
            // The human path's warning lines: every run warning except the
            // ones already said another way — the corrupt-ledger skips
            // (printed as errors below), `reinstall_required` (the Note
            // below), and the vendored leg's own warnings (printed inline
            // as they happened). Hosted replay warnings are printed here.
            let mut human_warnings: Vec<(String, String)> = run_warnings
                .iter()
                .filter(|(code, _)| {
                    !matches!(
                        code.as_str(),
                        "vendor_state_unreadable" | "reinstall_required"
                    )
                })
                .chain(hosted_leg.warnings.iter())
                .cloned()
                .collect();
            vendored_leg
                .warnings
                .iter()
                .chain(hosted_leg.warnings.iter())
                .for_each(|(code, detail)| run_warnings.push((code.clone(), detail.clone())));
            // A restored package whose ownership could not be put back
            // (the engine reports it on `error` with `success: true`) is
            // restored but worth a note, here and in the envelope.
            for r in results.iter().filter(|r| r.success) {
                if let Some(note) = &r.error {
                    let warning = (
                        "ownership_not_restored".to_string(),
                        format!("{}: {note}", r.package_key),
                    );
                    human_warnings.push(warning.clone());
                    run_warnings.push(warning);
                }
            }

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
                && contested.is_none()
                && !vendor_corrupt
                && manifest_write_failed.is_none();
            // Telemetry's count spans every leg (#1066), like the envelope's
            // `summary.rolledBack`.
            let rolled_back_total = results
                .iter()
                .filter(|r| r.success && !r.files_rolled_back.is_empty())
                .count()
                + vendored_leg.reverted.len()
                + vendored_leg.preserved.len()
                + hosted_leg.reverted.len();

            if let Some(e) = &manifest_write_failed {
                if !args.common.json {
                    eprintln!("Error: Failed to update the manifest: {e}");
                }
                run_warnings.push((
                    "manifest_write_failed".into(),
                    format!("failed to update the manifest: {e}"),
                ));
            }

            if args.common.json {
                // The GC was requested (not `--preserve-state`) but could not
                // run: `gc` stays absent and this warning says why.
                if !args.preserve_state && gc.is_none() {
                    let why = if aborted {
                        "the rollback aborted before restoring anything, so the revert data a \
                         retry needs was kept"
                    } else {
                        "the vendor ledger is unreadable, so artifact ownership cannot be \
                         established"
                    };
                    run_warnings.push(("gc_skipped".into(), format!("artifact GC skipped: {why}")));
                }
                let env = build_rollback_envelope(&RollbackReport {
                    dry_run: args.common.dry_run,
                    success,
                    manifest: &manifest,
                    results: &results,
                    not_installed: &not_installed,
                    vendored: &vendored_leg,
                    vendor_entries: &vendor_entries,
                    hosted: &hosted_leg,
                    hosted_pins: &hosted_pins,
                    contested: contested.as_deref(),
                    removed: &removed,
                    gc,
                    warnings: &run_warnings,
                    paths: path_scope.raw(),
                });
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent && !results.is_empty() {
                let cwd_abs = std::fs::canonicalize(&cwd).unwrap_or_else(|_| cwd.clone());
                let lines = if args.common.dry_run {
                    format_rollback_dry_run_counts(&results, &cwd_abs)
                } else {
                    format_rollback_results(&results, &cwd_abs)
                };
                for line in lines {
                    println!("{line}");
                }
                // The report above is on stdout; the run exits 1, so the
                // error stream says so too.
                if results.iter().any(|r| !r.success) {
                    eprintln!("{}", format_rollback_failed(args.common.dry_run));
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

            // Apply's unmatched warning, rollback-side — informational only
            // (the run still exits 0; see `RollbackOutcome`), so --silent
            // mutes it like every other non-error notice. Printed before
            // the manifest-removal list that names the same purls.
            if !args.common.json && !args.common.silent && !not_installed.is_empty() {
                // Separate it from the per-package report only when one
                // was printed above.
                if !results.is_empty() {
                    eprintln!();
                }
                eprintln!(
                    "Warning: {} had no matching installed package:",
                    plural(not_installed.len(), "manifest patch", "manifest patches")
                );
                for purl in &not_installed {
                    eprintln!("  - {purl}");
                }
            }

            if !args.common.json && !args.common.silent {
                if args.common.dry_run {
                    if cleanup_allowed && !removed.is_empty() {
                        println!(
                            "\nWould remove {} from manifest:",
                            plural(removed.len(), "patch", "patches")
                        );
                        for purl in &removed {
                            println!("  - {purl}");
                        }
                    }
                } else if !removed.is_empty() {
                    println!(
                        "\nRemoved {} from manifest:",
                        plural(removed.len(), "patch", "patches")
                    );
                    for purl in &removed {
                        println!("  - {purl}");
                    }
                } else if args.preserve_state && has_work {
                    println!(
                        "\n{}",
                        format_preserved_note(manifest_scope.len(), vendored_leg.preserved.len())
                    );
                }
                if gc_bytes_freed > 0 {
                    println!("\n{}", format_gc_freed(gc_bytes_freed, args.common.dry_run));
                }
                // Only packages that are NOT also handled in place keep
                // patched bytes. A successful in-place result that verified
                // files leaves the installed tree original: restored now,
                // restorable (dry run), or already original (never
                // patched). None of those has anything left to reinstall.
                let restored = handled_in_place(&results);
                let base_of = |key: &str| {
                    vendor_entries
                        .iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, e)| e.base_purl.clone())
                };
                let still_patched = vendored_leg
                    .reverted
                    .iter()
                    .chain(vendored_leg.preserved.iter())
                    .chain(hosted_leg.reverted.iter())
                    .filter(|key| {
                        !restored.contains(strip_purl_qualifiers(key))
                            && !base_of(key).is_some_and(|b| restored.contains(b.as_str()))
                    })
                    .count();
                if still_patched > 0 {
                    println!(
                        "\n{}",
                        format_reinstall_note(still_patched, args.common.dry_run, bun_advised)
                    );
                }
            }

            // Non-error run warnings (out-of-scope copies restored, cleanup
            // failures, hosted replay notes, ...): the JSON envelope's
            // `warnings[]`, one stderr line each here.
            if !args.common.json && !args.common.silent {
                for (_, detail) in &human_warnings {
                    eprintln!("Warning: {detail}");
                }
            }

            // Error-class notices print even under --silent ("errors only,
            // never nothing"): drift-keeps and corrupt-ledger skips drive
            // exit 1, so a silent run must still say why. Printed after
            // the summary blocks so they are the last thing on screen.
            if !args.common.json {
                for (key, reason) in &vendored_leg.kept {
                    eprintln!("Error: Kept vendored state for {key}: {reason}");
                }
                for (code, detail) in &run_warnings {
                    if code == "vendor_state_unreadable" {
                        eprintln!("Error ({code}): {}", crate::ui::sentence_case(detail));
                    }
                }
            }

            if success {
                track_patch_rolled_back(rolled_back_total, &telemetry).await;
            } else {
                track_patch_rollback_failed("One or more rollbacks failed", &telemetry).await;
            }

            if success {
                0
            } else {
                1
            }
        }
        Err(e) => {
            track_patch_rollback_failed(&e, &telemetry).await;
            if args.common.json {
                println!(
                    "{}",
                    error_envelope(args.common.dry_run, EnvelopeError::new("rollback_failed", e))
                        .to_pretty_json()
                );
            } else {
                // Errors print even under --silent ("errors only", never
                // "nothing"): exit 1 with no message would be undiagnosable.
                eprintln!("Error: {}", crate::ui::sentence_case(&e));
            }
            1
        }
    }
}

/// The in-place (agent) rollback engine over an already-loaded `manifest`.
/// `vendored_keys` is the ledger's ownership set (see
/// [`VendorState::purl_keys`]): vendor-owned purls are excluded from the
/// in-place restore. Both `run()` and `remove`'s delegation load each
/// store once under the lock and thread it in here.
pub(crate) async fn rollback_patches_inner(
    common: &GlobalArgs,
    socket_dir: &Path,
    manifest: &PatchManifest,
    vendored_keys: &HashSet<PurlKey>,
    selection: InnerSelection<'_>,
    // Manifest purl -> the hosted uuid a live lockfile pin superseded its
    // record with ([`superseded_by_hosted`]); empty when no hosted pin
    // replaces a recorded patch.
    superseded: &HashMap<String, String>,
    // The client the caller already built. Constructing one per phase
    // printed the core client's "No SOCKET_API_TOKEN set" notice once per
    // construction — twice in a single rollback. `None` builds one on
    // demand, only when the blob download below actually fires.
    api_client: Option<&ApiClient>,
) -> Result<RollbackOutcome, String> {
    let mut blobs_path = socket_dir.join("blobs");

    let patches_to_rollback = match &selection {
        InnerSelection::Identifier(identifier) => find_patches_to_rollback(manifest, *identifier),
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
            narrowed_out: Vec::new(),
            aborted: false,
            warnings: Vec::new(),
            superseded: Vec::new(),
        });
    }

    // Vendor-owned purls are excluded from in-place rollback: their patch
    // lives in the committed `.socket/vendor/` artifact + lock wiring, not
    // in the installed tree, so before-blob restoration is meaningless
    // there (and would only hash-mismatch). `remove` reverts vendoring;
    // `vendor --revert` undoes it wholesale. Matching mirrors apply's
    // ledger-key / base-purl / qualifier-stripped triple; the caller
    // degrades unreadable state to "nothing vendored".
    let is_vendored = |p: &str| purl_keys_cover(vendored_keys, p);
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
            narrowed_out: Vec::new(),
            aborted: false,
            warnings: Vec::new(),
            superseded: Vec::new(),
        });
    }

    // Nothing here creates `.socket/blobs`: the engine only READS blobs,
    // and the missing-blob download creates the directory itself when (and
    // only when) it has something to write — so a rollback whose blobs are
    // cached or whose files are already original leaves no empty blobs
    // dir behind. A regular FILE squatting on the path is corrupt state,
    // though: refuse up front rather than misreport it as N "Before blob
    // not found" failures.
    if !common.dry_run {
        if let Ok(meta) = tokio::fs::metadata(&blobs_path).await {
            if !meta.is_dir() {
                return Err(format!("{} is not a directory", blobs_path.display()));
            }
        }
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
    // absent before-blob must not abort (or trigger fetches for) a run that
    // will never restore it, so `scoped_manifest` below narrows the
    // reference set to the in-scope purls (apply narrows its manifest the
    // same way, in place, in `apply_patches_inner`).
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

    let crawler_options = common.crawler_options();

    // Multi-copy aware: npm nests genuine duplicates of one `name@version`,
    // so the resolver returns EVERY physical copy per PURL. Restoring only
    // one would leave the other copy still patched (silently divergent from
    // the manifest's rolled-back state). The rollback loop below restores
    // every copy.
    let mut all_packages_multi = find_all_packages_for_rollback(
        &partitioned,
        &crawler_options,
        common.silent || common.json,
    )
    .await;
    // One restore per physical copy, as apply patches them (#633).
    distinct_npm_copies(&mut all_packages_multi).await;

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
        .filter(|purl| is_local_go(purl, common) && !all_packages.contains_key(*purl))
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
    let mut rollback_targets: Vec<CopyTarget> = Vec::new();
    let mut groups: HashMap<String, Vec<(&String, &PathBuf)>> = HashMap::new();
    // Maven: grouped by (base purl, copy) — `~/.m2` and each Gradle cache
    // are distinct installs whose variants and state differ per copy.
    let jvm_scope = if partitioned.contains_key(&Ecosystem::Maven) {
        Some(JvmScope::of(common).await)
    } else {
        None
    };
    let mut maven_groups: Vec<((String, PathBuf), Vec<&String>, bool)> = Vec::new();
    for (purl, pkg_paths) in &all_packages_multi {
        if let Some(scope) = jvm_scope
            .as_ref()
            .filter(|_| Ecosystem::from_purl(purl) == Some(Ecosystem::Maven))
        {
            // Every writable copy: the read-only cache is never written,
            // but a `~/.m2` copy this Gradle-only build no longer reads
            // (`m2_ignored`) is still restored. An earlier apply wrote it
            // (before the gate existed, or while `mavenLocal()` was
            // declared); skipping it would leave the shared jar patched
            // with no record to restore it from once `remove` drops the
            // entry. Only bytes that verify as this record's afterHash
            // are ever put back, and a Maven build that wants the patch
            // re-applies it from its own manifest. Such a copy never
            // decides the run's outcome, though (`CopyTarget::unconsumed_m2`):
            // the build does not read it, so one another build re-patched
            // or rebuilt, or whose backup lives in that other project, is
            // left with a warning instead of failing this rollback/remove.
            let copies = scope.split(pkg_paths);
            let tagged = copies
                .consumed
                .iter()
                .map(|p| (p, false))
                .chain(copies.m2_ignored.iter().map(|p| (p, true)));
            for (pkg_path, unconsumed) in tagged {
                let key = (strip_purl_qualifiers(purl).to_string(), pkg_path.clone());
                match maven_groups.iter_mut().find(|(k, _, _)| *k == key) {
                    Some((_, purls, _)) => purls.push(purl),
                    None => maven_groups.push((key, vec![purl], unconsumed)),
                }
            }
        } else if Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants()) {
            for pkg_path in pkg_paths {
                groups
                    .entry(strip_purl_qualifiers(purl).to_string())
                    .or_default()
                    .push((purl, pkg_path));
            }
        } else {
            for pkg_path in pkg_paths {
                rollback_targets.push(CopyTarget::plain(purl, pkg_path));
            }
        }
    }

    // Resolve which variant(s) each base PURL will actually roll back,
    // BEFORE the before-blob gate below, so the gate covers only them.
    // Narrowed-away sibling variants (same base, distribution NOT on disk)
    // are collected so the CLI boundary's manifest-cleanup default can
    // drop them alongside their attempted siblings — a rolled-back
    // package must not leave half its variant group in the manifest
    // (remove's identifier flow drops the whole group the same way).
    let mut narrowed_out: Vec<String> = Vec::new();
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
                narrowed_out.extend(
                    entries
                        .iter()
                        .filter(|(p, _)| !winners.contains(*p))
                        .map(|(p, _)| (*p).clone()),
                );
                entries
                    .into_iter()
                    .filter(|(p, _)| winners.contains(*p))
                    .collect()
            }
        };
        rollback_targets.extend(
            to_rollback
                .into_iter()
                .map(|(purl, path)| CopyTarget::plain(purl, path)),
        );
    }
    let (maven_targets, maven_narrowed) =
        maven_rollback_targets(&maven_groups, &filtered_manifest).await;
    rollback_targets.extend(maven_targets);
    narrowed_out.extend(maven_narrowed);
    narrowed_out.sort();
    narrowed_out.dedup();

    // Check for missing beforeHash blobs — AFTER discovery and variant
    // narrowing, so the gate covers ONLY the packages this run will
    // actually attempt to restore in place:
    //
    //   * Narrowed-away sibling variants (they describe a distribution
    //     that is not on disk) don't gate: that variant is never attempted.
    //   * In-scope purls the crawler could NOT resolve (package not
    //     installed) don't gate either: there is nothing on disk to
    //     restore, so no before-blob is ever read for them (apply reports
    //     the same entry as a benign `package_not_installed` skip). They
    //     surface via `not_installed` below instead.
    //   * Local-redirect PURLs (local-mode go) are excluded:
    //     their rollback just drops the project-local redirect + copy and
    //     reads no blobs, so a missing before-blob must not block an
    //     offline redirect rollback.
    let attempted_purls: HashSet<&str> = rollback_targets.iter().map(|t| t.purl.as_str()).collect();
    let gate_manifest = before_blob_gate_manifest(&scoped_manifest, &attempted_purls, common);

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
            let mut pkg_paths = all_packages_multi
                .get(purl)
                .expect("gate manifest holds only attempted targets, which the crawler discovered")
                .clone();
            // Maven copies are probed where they are restored: the hash
            // dirs (and `~/.m2` dirs) of the expanded targets.
            if purl.starts_with("pkg:maven/") {
                pkg_paths = rollback_targets
                    .iter()
                    .filter(|t| t.purl == *purl && t.jar_leaf.is_none())
                    .map(|t| t.dir.clone())
                    .collect();
            }
            // The engine also restores every pnpm/vlt store peer variant of
            // an npm copy, so each of those is a copy that may need a blob.
            if purl.starts_with("pkg:npm/") {
                let found = pkg_paths.clone();
                for path in &found {
                    for copy in
                        socket_patch_core::crawlers::npm_crawler::find_store_peer_variant_copies(
                            path,
                        )
                        .await
                    {
                        if !pkg_paths.contains(&copy) {
                            pkg_paths.push(copy);
                        }
                    }
                }
            }
            for (file, info) in &patch.files {
                if info.before_hash.is_empty() || !absent_blobs.contains(&info.before_hash) {
                    continue;
                }
                for pkg_path in &pkg_paths {
                    let file = maven_target_key(purl, pkg_path, file);
                    let v = verify_file_rollback(pkg_path, &file, info, &blobs_path).await;
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
                    "Error: {} missing and --offline is set.",
                    plural(missing_blobs.len(), "blob is", "blobs are")
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
                narrowed_out: Vec::new(),
                aborted: true,
                warnings: Vec::new(),
                superseded: Vec::new(),
            });
        }

        // Transient progress on stderr; the result line replaces it.
        let mut status = StatusLine::stderr(common.json, common.silent);
        status.set(format!(
            "Downloading {}...",
            plural(missing_blobs.len(), "missing blob", "missing blobs")
        ));

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

        status.finish_with(format_fetch_result(&fetch_result));

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
                    "Error: {} not be downloaded; cannot roll back.",
                    plural(still_missing.len(), "blob could", "blobs could")
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
                narrowed_out: Vec::new(),
                aborted: true,
                warnings: Vec::new(),
                superseded: Vec::new(),
            });
        }
    }

    if all_packages.is_empty() && undiscovered_redirects.is_empty() {
        // Nothing printed here: every caller reports `not_installed` itself
        // (rollback's "had no matching installed package" warning,
        // remove's crawler-miss warning).
        //
        // `success: true` — not-installed entries already satisfy
        // rollback's end state (see `RollbackOutcome`); callers report
        // `not_installed` as an informational warning, never an exit 1.
        return Ok(RollbackOutcome {
            success: true,
            results: Vec::new(),
            vendored_skipped,
            not_installed,
            narrowed_out: narrowed_out.clone(),
            aborted: false,
            warnings: Vec::new(),
            superseded: Vec::new(),
        });
    }

    // Rollback patches
    let mut results: Vec<RollbackResult> = Vec::new();
    let mut has_errors = false;
    let mut warnings: Vec<(String, String)> = Vec::new();
    let mut superseded_left: Vec<String> = Vec::new();

    for target in &rollback_targets {
        let (purl, pkg_path) = (&target.purl, &target.dir);
        let patch = match filtered_manifest.patches.get(purl) {
            Some(p) => p,
            None => continue,
        };

        // Local go drops the project-local `replace`-redirect; Maven
        // restores each expanded copy (`rollback_maven_target`);
        // everything else — npm/pypi/gem and cargo (vendored or registry
        // cache) — restores in place from before-blobs.
        let result = if purl.starts_with("pkg:maven/") {
            Box::pin(rollback_maven_target(
                target,
                patch,
                &blobs_path,
                socket_dir,
                common,
            ))
            .await
        } else {
            match try_rollback_local_go(purl, pkg_path, patch, common).await {
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
            }
        };

        if let Some(warning) = unconsumed_m2_skip(target, &result) {
            warnings.push(warning);
            continue;
        }
        let files = target.files.as_ref().unwrap_or(&patch.files);
        let mut result = result;
        if let Some(warning) = superseded_record_skip(target, &result, files, superseded).await {
            // The superseded primary never reached its store copies; one
            // still at this record's patched bytes (Bun's orphaned
            // isolated-store entry, #1084) is restored here, or fails the
            // run and keeps the record, before the record is dropped.
            match socket_patch_core::patch::rollback::rollback_store_copies_holding_patch(
                purl,
                pkg_path,
                files,
                &blobs_path,
                common.dry_run,
            )
            .await
            {
                Some(copies) if !copies.success => result = copies,
                restored => {
                    warnings.push(warning);
                    superseded_left.push(purl.clone());
                    results.extend(restored);
                    continue;
                }
            }
        }
        if !result.success {
            has_errors = true;
            // Under --silent (the summary muted) this line is the run's
            // only failure diagnostic ("errors only", never "nothing").
            // Otherwise the failure is reported once, in the summary's
            // "Failed to roll back:" section plus a closing stderr error
            // (or by `remove`).
            if common.silent && !common.json {
                eprintln!(
                    "{}",
                    format_rollback_failure(
                        purl,
                        result.error.as_deref().unwrap_or("unknown error")
                    )
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
        let Some(result) = try_rollback_local_go(purl, &common.cwd, patch, common).await else {
            continue;
        };
        if !result.success {
            has_errors = true;
            // Same contract as the in-place loop above.
            if common.silent && !common.json {
                eprintln!(
                    "{}",
                    format_rollback_failure(
                        purl,
                        result.error.as_deref().unwrap_or("unknown error")
                    )
                );
            }
        }
        results.push(result);
    }

    superseded_left.sort();
    superseded_left.dedup();
    Ok(RollbackOutcome {
        success: !has_errors,
        results,
        vendored_skipped,
        not_installed,
        narrowed_out,
        aborted: false,
        warnings,
        superseded: superseded_left,
    })
}

/// One copy `rollback_patches_inner` restores.
#[derive(Debug, Clone)]
struct CopyTarget {
    purl: String,
    dir: PathBuf,
    /// Maven: the record's files as joined onto `dir` (a Gradle hash dir's
    /// keys are bare file names). `None`: the manifest record's files.
    files: Option<HashMap<String, PatchFileInfo>>,
    /// Maven member-keyed record: the jar under `dir` to restore whole.
    jar_leaf: Option<String>,
    /// A `~/.m2` copy this Gradle-only build never reads
    /// (`JvmScope::split`'s `m2_ignored`). Restored when it holds this
    /// record's patched bytes, but a copy that verifies as neither side
    /// or has no backup here is left with a `gradle_m2_copy_not_restored`
    /// warning (`unconsumed_m2_skip`), never a failure.
    unconsumed_m2: bool,
}

impl CopyTarget {
    fn plain(purl: &str, dir: &Path) -> Self {
        Self {
            purl: purl.to_string(),
            dir: dir.to_path_buf(),
            files: None,
            jar_leaf: None,
            unconsumed_m2: false,
        }
    }
}

/// The run warning that replaces a failed restore of an unconsumed
/// `~/.m2` copy ([`CopyTarget::unconsumed_m2`]), when it failed before
/// writing anything because the copy holds bytes that are neither side of
/// this record (another build re-patched it, or `mvn install` rebuilt it),
/// lacks a file, or is a swapped jar whose original this project never
/// backed up. `None` for any other result, which is reported as usual —
/// including a file that is there but cannot be read or stat'd, which may
/// still hold this record's patched bytes.
fn unconsumed_m2_skip(target: &CopyTarget, result: &RollbackResult) -> Option<(String, String)> {
    if !target.unconsumed_m2 || result.success || !result.files_rolled_back.is_empty() {
        return None;
    }
    // A file that is there but could not be read or stat'd (EACCES, EISDIR,
    // ELOOP…) may still hold this record's patched bytes: leaving it would
    // let `remove` drop the record and its before-blobs with the shared
    // copy still patched, so it fails the run like any unverifiable copy.
    if result
        .files_verified
        .iter()
        .any(|v| v.status == VerifyRollbackStatus::NotFound && !v.is_absent())
    {
        return None;
    }
    let refused = result
        .files_verified
        .iter()
        .any(|v| v.status == VerifyRollbackStatus::HashMismatch || v.is_absent())
        || result
            .error
            .as_deref()
            .is_some_and(|e| e.starts_with("jvm_jar_backup_missing"));
    refused.then(|| {
        (
            "gradle_m2_copy_not_restored".to_string(),
            format!(
                "{}: left the ~/.m2 copy at {} as it is; this Gradle-only build does not \
                 read it ({})",
                target.purl,
                target.dir.display(),
                result.error.as_deref().unwrap_or("it cannot be restored")
            ),
        )
    })
}

/// Manifest records a live hosted pin has superseded (#933): purl -> the
/// hosted uuid the lockfiles wire for the same package release, when no
/// hosted pin for that release carries the record's own uuid. An agent →
/// hosted migration whose patch was replaced meanwhile leaves exactly this:
/// record A in the manifest, the lock pinning B. `vex` reports the same
/// state as `vex_record_superseded`.
pub(crate) fn superseded_by_hosted(
    manifest: &PatchManifest,
    pins: &[HostedPin],
) -> HashMap<String, String> {
    manifest
        .patches
        .iter()
        .filter_map(|(purl, record)| {
            let pkg = PurlKey::new(purl);
            let same: Vec<&HostedPin> = pins
                .iter()
                .filter(|pin| PurlKey::new(&pin.purl) == pkg)
                .collect();
            if same.iter().any(|pin| pin.uuid == record.uuid) {
                return None;
            }
            same.first().map(|pin| (purl.clone(), pin.uuid.clone()))
        })
        .collect()
}

/// The run warning that replaces a failed in-place restore of a manifest
/// record a live hosted pin superseded ([`superseded_by_hosted`]), when it
/// failed before writing anything because the installed copy holds bytes
/// that are neither side of the record (the superseding patch's, after a
/// reinstall), lacks a file, or is a Gradle hash directory this record
/// never patched (`gradle_rollback_hash_mismatch` with no file at the
/// record's patched bytes). The hosted leg's lock restore and the reinstall
/// it asks for unwind that copy; restoring the record's original bytes over
/// the superseding patch's would only mix the two. `None` for any other
/// result: a copy still holding the record's patched bytes (including a
/// swapped jar with no backup, `jvm_jar_backup_missing`) is restored or
/// fails as usual, and so does a file that cannot be read.
async fn superseded_record_skip(
    target: &CopyTarget,
    result: &RollbackResult,
    files: &HashMap<String, PatchFileInfo>,
    superseded: &HashMap<String, String>,
) -> Option<(String, String)> {
    let wired = superseded.get(&target.purl)?;
    if result.success || !result.files_rolled_back.is_empty() {
        return None;
    }
    if result
        .files_verified
        .iter()
        .any(|v| v.status == VerifyRollbackStatus::NotFound && !v.is_absent())
    {
        return None;
    }
    let mismatched = result
        .files_verified
        .iter()
        .any(|v| v.status == VerifyRollbackStatus::HashMismatch || v.is_absent());
    // A Gradle hash directory is refused before verification when the
    // record's before-blob does not hash to its name: normally the
    // superseding patch's own download, which this record never patched.
    // It is left only if no file there still holds the record's patched
    // bytes (a corrupt blob for the directory the record DID patch fails
    // as usual).
    let foreign_gradle_dir = result
        .error
        .as_deref()
        .is_some_and(|e| e.starts_with("gradle_rollback_hash_mismatch"))
        && !holds_patched_bytes(target, files).await;
    (mismatched || foreign_gradle_dir).then(|| {
        (
            "rollback_record_superseded".to_string(),
            format!(
                "{}: the recorded patch is superseded by the lockfile-wired hosted patch {wired}; \
                 left the installed copy at {} to the lockfile restore (the next \
                 package-manager install puts the original files back)",
                target.purl,
                target.dir.display()
            ),
        )
    })
}

/// Whether any of `files` in `target`'s copy is at the record's patched
/// bytes, or cannot be checked (an unsafe key, a read error other than
/// "not found"), which may hide them.
async fn holds_patched_bytes(target: &CopyTarget, files: &HashMap<String, PatchFileInfo>) -> bool {
    for (file, info) in files {
        let key = maven_target_key(&target.purl, &target.dir, file);
        let rel = Path::new(key.strip_prefix("package/").unwrap_or(&key));
        if rel.as_os_str().is_empty()
            || !rel
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            return true;
        }
        // FIFO-safe: a FIFO or device planted at the leaf is refused, not
        // opened (a bare read would block forever), and counts as possibly
        // patched below.
        match socket_patch_core::utils::fs::read_regular_to_bytes(&target.dir.join(rel)).await {
            Ok(bytes) => {
                if socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(&bytes)
                    == info.after_hash
                {
                    return true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return true,
        }
    }
    false
}

/// The key `file` of a Maven record as it is joined onto `dir`: a Gradle
/// hash dir holds the bare file name (`package/` dropped).
fn maven_target_key(purl: &str, dir: &Path, file: &str) -> String {
    if purl.starts_with("pkg:maven/")
        && socket_patch_core::patch::sidecars::maven::is_gradle_hash_dir(dir)
    {
        file.trim_start_matches("package/").to_string()
    } else {
        file.to_string()
    }
}

/// Maven rollback targets, per `(base purl, copy)` group: the variants the
/// copy holds (`select_installed_variants`, which expands a Gradle version
/// dir through `installed_copies`), each expanded into the hash dirs
/// holding its files — or, for a member-keyed record, into every copy of
/// its jar. A copy holding none of a group's variants' files is not an
/// install of them and is skipped; one that holds files no variant
/// matches attempts every variant, so verification reports the mismatch.
/// Returns the targets and the variants no copy kept (narrowed out).
async fn maven_rollback_targets(
    groups: &[((String, PathBuf), Vec<&String>, bool)],
    manifest: &PatchManifest,
) -> (Vec<CopyTarget>, Vec<String>) {
    use socket_patch_core::crawlers::gradle_cache::{expands, installed_copies_detailed};
    use socket_patch_core::patch::jvm_jar::{self, RecordShape};

    let mut targets = Vec::new();
    let mut considered: HashSet<String> = HashSet::new();
    let mut kept: HashSet<String> = HashSet::new();
    for ((_, copy), purls, unconsumed_m2) in groups {
        let unconsumed_m2 = *unconsumed_m2;
        let candidates: Vec<(&str, &HashMap<String, PatchFileInfo>)> = purls
            .iter()
            .filter_map(|purl| {
                manifest
                    .patches
                    .get(*purl)
                    .map(|p| (purl.as_str(), &p.files))
            })
            .collect();
        considered.extend(candidates.iter().map(|(p, _)| p.to_string()));
        let mut expanded: Vec<(String, Vec<CopyTarget>)> = Vec::new();
        for (purl, files) in &candidates {
            let mut out = Vec::new();
            match jvm_jar::classify(purl, files) {
                RecordShape::Members { jar_leaf } => {
                    for dir in jvm_jar::jar_copies(copy, &jar_leaf) {
                        out.push(CopyTarget {
                            purl: purl.to_string(),
                            dir,
                            files: None,
                            jar_leaf: Some(jar_leaf.clone()),
                            unconsumed_m2,
                        });
                    }
                }
                // A Gradle version dir, or an Ivy artifact dir whose
                // module keeps classifier jars in sibling type dirs.
                RecordShape::Leaf if expands(copy) => {
                    for (dir, files) in installed_copies_detailed(copy, files).targets {
                        out.push(CopyTarget {
                            purl: purl.to_string(),
                            dir,
                            files: Some(files),
                            jar_leaf: None,
                            unconsumed_m2,
                        });
                    }
                }
                RecordShape::Leaf => {
                    let present = files
                        .keys()
                        .any(|k| copy.join(k.trim_start_matches("package/")).exists());
                    if present {
                        out.push(CopyTarget {
                            unconsumed_m2,
                            ..CopyTarget::plain(purl, copy)
                        });
                    }
                }
            }
            if !out.is_empty() {
                expanded.push((purl.to_string(), out));
            }
        }
        if expanded.is_empty() {
            continue;
        }
        let winners: HashSet<String> = if candidates.len() == 1 {
            expanded.iter().map(|(p, _)| p.clone()).collect()
        } else {
            let matched = select_installed_variants(copy, &candidates).await;
            if matched.is_empty() {
                expanded.iter().map(|(p, _)| p.clone()).collect()
            } else {
                matched
                    .iter()
                    .map(|&i| candidates[i].0.to_string())
                    .collect()
            }
        };
        for (purl, out) in expanded {
            if winners.contains(&purl) {
                kept.insert(purl);
                targets.extend(out);
            }
        }
    }
    let mut narrowed: Vec<String> = considered.difference(&kept).cloned().collect();
    narrowed.sort();
    (targets, narrowed)
}

/// Roll back one Maven target: a member-keyed record restores its whole
/// jar (`jvm_jar::rollback_jar_swap`); a leaf record restores its files
/// from before-blobs, `~/.m2` checksum files put back to the restored bytes.
/// A restored Gradle hash-dir file must hash to its directory's name (the
/// sha1 Gradle verified when it downloaded it): a before-blob that does not
/// is refused with `gradle_rollback_hash_mismatch` before anything is
/// written, so the patched file is left as it is.
async fn rollback_maven_target(
    target: &CopyTarget,
    patch: &PatchRecord,
    blobs_path: &Path,
    socket_dir: &Path,
    common: &GlobalArgs,
) -> RollbackResult {
    use socket_patch_core::crawlers::gradle_cache::pristine;
    use socket_patch_core::patch::jvm_jar::{rollback_jar_swap, JarRestore};
    use socket_patch_core::patch::sidecars::{maven as maven_sidecars, SidecarRecord};

    if let Some(jar_leaf) = &target.jar_leaf {
        let restore = JarRestore {
            purl: &target.purl,
            jar_leaf,
            files: &patch.files,
            socket_dir,
            dry_run: common.dry_run,
            offline: common.offline,
        };
        return rollback_jar_swap(&restore, std::slice::from_ref(&target.dir))
            .await
            .into_iter()
            .next()
            .expect("one result per copy");
    }
    let files = target.files.as_ref().unwrap_or(&patch.files);
    let gradle = maven_sidecars::is_gradle_hash_dir(&target.dir);
    let keys: Vec<String> = files.keys().cloned().collect();
    let pre = if gradle || common.dry_run {
        None
    } else {
        Some(maven_sidecars::snapshot(&target.dir, &keys).await)
    };
    let hash = target
        .dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    if gradle {
        // Check the before-blobs before anything is written, so a refusal
        // really leaves the patched file in place (and a re-run refuses
        // again); read-only, so a dry run predicts it too. A blob that is
        // missing, not a regular file or named by an invalid hash is left
        // to `rollback_package_patch`, whose verify step refuses it without
        // reading through it.
        for (file, info) in files {
            if !socket_patch_core::patch::apply::is_valid_blob_hash(&info.before_hash) {
                continue;
            }
            let blob = blobs_path.join(&info.before_hash);
            if !tokio::fs::symlink_metadata(&blob)
                .await
                .is_ok_and(|m| m.is_file())
            {
                continue;
            }
            let Ok(bytes) = socket_patch_core::utils::fs::read_regular_to_bytes(&blob).await else {
                continue;
            };
            if !pristine(hash, &bytes) {
                let path = target.dir.join(file.trim_start_matches("package/"));
                return RollbackResult {
                    package_key: target.purl.clone(),
                    package_path: target.dir.display().to_string(),
                    success: false,
                    files_verified: Vec::new(),
                    files_rolled_back: Vec::new(),
                    error: Some(format!(
                        "gradle_rollback_hash_mismatch: the before-blob for {} does not hash \
                         to its Gradle cache directory (it is not the bytes Gradle \
                         downloaded); left as it is — delete {} and let Gradle download it \
                         again.",
                        path.display(),
                        target.dir.display()
                    )),
                    sidecar: None,
                };
            }
        }
    }
    let mut result =
        rollback_package_patch(&target.purl, &target.dir, files, blobs_path, common.dry_run).await;
    if !result.success || common.dry_run {
        return result;
    }
    if let Some(pre) = pre.filter(|p| !p.is_empty()) {
        result.sidecar = Some(match maven_sidecars::resync(&target.dir, &pre).await {
            Ok(files) => SidecarRecord {
                purl: target.purl.clone(),
                ecosystem: "maven".to_string(),
                files,
                advisory: None,
            },
            Err(e) => SidecarRecord {
                purl: target.purl.clone(),
                ecosystem: "maven".to_string(),
                files: Vec::new(),
                advisory: Some(socket_patch_core::patch::sidecars::SidecarAdvisory {
                    code:
                        socket_patch_core::patch::sidecars::SidecarAdvisoryCode::SidecarFixupFailed,
                    severity: socket_patch_core::patch::sidecars::SidecarSeverity::Error,
                    message: format!("sidecar resync failed (rollback still applied): {e}"),
                }),
            },
        });
    }
    if gradle {
        for file in &result.files_rolled_back {
            let path = target.dir.join(file.trim_start_matches("package/"));
            let Ok(bytes) = socket_patch_core::utils::fs::read_regular_to_bytes(&path).await else {
                continue;
            };
            if !pristine(hash, &bytes) {
                result.success = false;
                result.error = Some(format!(
                    "gradle_rollback_hash_mismatch: {} does not hash to its Gradle cache \
                     directory after the restore (the before-blob is not the bytes Gradle \
                     downloaded) — delete {} and let Gradle download it again.",
                    path.display(),
                    target.dir.display()
                ));
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use std::collections::HashMap;

    // The legacy path-taking delegation shape, kept for the unit tests below
    // (`remove` now threads its already-loaded manifest and ledger straight
    // into `rollback_patches_inner`; this wrapper reads them from disk). The
    // third tuple element lists vendor-owned purls that were excluded from
    // in-place rollback (benign); the fourth is `RollbackOutcome::not_installed`
    // — in-scope manifest entries the crawler found no installed package for.
    //
    // The returned `bool` is `RollbackOutcome::success` — per-package semantics
    // only. Manifest entries whose package is not installed are NOT failures
    // here (there is nothing on disk to restore), so `remove` proceeds to drop
    // them from the manifest. Like the CLI boundary, not-installed entries
    // never fail the run (see `RollbackOutcome`).
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
    async fn rollback_patches(
        common: &crate::args::GlobalArgs,
        manifest_path: &Path,
        identifier: Option<&str>,
        dry_run: bool,
        silent: bool,
        ecosystems: Option<Vec<String>>,
    ) -> Result<(bool, Vec<RollbackResult>, Vec<String>, Vec<String>), String> {
        // The Identifier selection keeps the legacy hard requirement: a
        // missing manifest is the (historical) "Invalid manifest" error.
        let manifest = read_manifest(manifest_path)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Invalid manifest".to_string())?;
        let socket_dir = crate::args::socket_dir_of(manifest_path, &common.cwd);
        let vendored_keys = socket_patch_core::vendor::vendored_purl_keys(&common.cwd).await;
        let delegated_common = crate::args::GlobalArgs {
            ecosystems,
            silent,
            dry_run,
            ..common.clone()
        };
        let target = identifier.map(Target::parse);
        let outcome = rollback_patches_inner(
            &delegated_common,
            &socket_dir,
            &manifest,
            &vendored_keys,
            InnerSelection::Identifier(target.as_ref()),
            &HashMap::new(),
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
        let result = find_patches_to_rollback(&manifest, Some(&Target::parse("pkg:npm/foo@1.0")));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:npm/foo@1.0");
    }

    #[test]
    fn test_find_patches_to_rollback_purl_no_match() {
        let manifest = make_manifest();
        let result =
            find_patches_to_rollback(&manifest, Some(&Target::parse("pkg:npm/nonexistent@1")));
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_patches_to_rollback_uuid_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some(&Target::parse("uuid-bar")));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].patch.uuid, "uuid-bar");
        assert_eq!(result[0].purl, "pkg:npm/bar@2.0");
    }

    #[test]
    fn test_find_patches_to_rollback_uuid_no_match() {
        let manifest = make_manifest();
        let result =
            find_patches_to_rollback(&manifest, Some(&Target::parse("uuid-does-not-exist")));
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
        let result =
            find_patches_to_rollback(&manifest, Some(&Target::parse("pkg:pypi/six@1.16.0")));
        // Base PURL (no qualifier) expands to every release variant.
        assert_eq!(result.len(), 3);
        for p in &result {
            assert!(p.purl.starts_with("pkg:pypi/six@1.16.0?artifact_id="));
        }
    }

    #[test]
    fn test_find_patches_to_rollback_qualified_purl_matches_one_variant() {
        let manifest = make_multi_variant_manifest();
        let result = find_patches_to_rollback(
            &manifest,
            Some(&Target::parse("pkg:pypi/six@1.16.0?artifact_id=sdist")),
        );
        // A fully-qualified PURL targets exactly one variant.
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:pypi/six@1.16.0?artifact_id=sdist");
    }

    /// Rollback shares the target grammar: a bare name (and an npm
    /// `@scope/name`) is a package target, not a uuid-only identifier or a
    /// path glob; only path-shaped tokens are globs.
    #[test]
    fn classify_target_uses_the_shared_grammar() {
        assert!(matches!(
            classify_target("lodash"),
            RollbackTarget::Identifier(_)
        ));
        assert!(matches!(
            classify_target("@babel/core"),
            RollbackTarget::Identifier(_)
        ));
        assert!(matches!(
            classify_target("pkg:npm/@s/x"),
            RollbackTarget::Identifier(_)
        ));
        assert!(matches!(
            classify_target("./node_modules"),
            RollbackTarget::PathGlob(_)
        ));
        assert!(matches!(
            classify_target("node_modules/**"),
            RollbackTarget::PathGlob(_)
        ));
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some(&Target::parse("foo")));
        assert_eq!(result.len(), 1, "a bare name selects its recorded patch");
        assert_eq!(result[0].purl, "pkg:npm/foo@1.0");
        let result = find_patches_to_rollback(&manifest, Some(&Target::parse("pkg:npm/foo")));
        assert_eq!(
            result.len(),
            1,
            "a versionless purl selects its recorded patch"
        );
    }

    #[test]
    fn test_find_patches_to_rollback_base_purl_does_not_leak_other_packages() {
        let manifest = make_multi_variant_manifest();
        let result =
            find_patches_to_rollback(&manifest, Some(&Target::parse("pkg:pypi/six@1.16.0")));
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

    fn superseded_map() -> HashMap<String, String> {
        HashMap::from([(
            "pkg:npm/foo@1.0.0".to_string(),
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".to_string(),
        )])
    }

    /// A record of one file, `package/index.js`, patched from `before` to
    /// `after`, and a copy dir holding `installed` as that file.
    fn superseded_copy(
        installed: &[u8],
    ) -> (
        tempfile::TempDir,
        CopyTarget,
        HashMap<String, PatchFileInfo>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("index.js"), installed).unwrap();
        let files = HashMap::from([(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(
                    b"original",
                ),
                after_hash: socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(
                    b"patched by A",
                ),
            },
        )]);
        let target = CopyTarget::plain("pkg:npm/foo@1.0.0", tmp.path());
        (tmp, target, files)
    }

    fn refused(error: &str) -> RollbackResult {
        let mut result = make_result(&[], &[]);
        result.success = false;
        result.error = Some(error.to_string());
        result
    }

    #[tokio::test]
    async fn superseded_skip_covers_a_copy_holding_neither_side() {
        let (_tmp, target, files) = superseded_copy(b"patched by B");
        let result = make_result(&[VerifyRollbackStatus::HashMismatch], &[]);
        let (code, detail) = superseded_record_skip(&target, &result, &files, &superseded_map())
            .await
            .expect("a superseded record's mismatched copy is left to the hosted leg");
        assert_eq!(code, "rollback_record_superseded");
        assert!(
            detail.contains("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            "{detail}"
        );
    }

    #[tokio::test]
    async fn superseded_skip_covers_a_gradle_dir_the_record_never_patched() {
        let (_tmp, target, files) = superseded_copy(b"patched by B");
        let result = refused("gradle_rollback_hash_mismatch: the before-blob for x does not hash");
        assert!(
            superseded_record_skip(&target, &result, &files, &superseded_map())
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn superseded_skip_keeps_jvm_copies_holding_the_patched_bytes() {
        // The record's own patched bytes are still there: a corrupt blob for
        // the directory it patched, or a swapped jar with no backup, fails.
        let (_tmp, target, files) = superseded_copy(b"patched by A");
        for error in [
            "gradle_rollback_hash_mismatch: the before-blob for x does not hash",
            "jvm_jar_backup_missing: no original of lib-1.0.jar",
        ] {
            let result = refused(error);
            assert!(
                superseded_record_skip(&target, &result, &files, &superseded_map())
                    .await
                    .is_none(),
                "{error}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn superseded_skip_never_blocks_on_a_fifo() {
        // A FIFO where the record's file should be is unverifiable: the
        // check must refuse it, not block in open(2), and must not skip.
        let (tmp, target, files) = superseded_copy(b"patched by B");
        std::fs::remove_file(tmp.path().join("index.js")).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(tmp.path().join("index.js"))
            .status()
            .expect("run mkfifo");
        assert!(made.success());
        let result = refused("gradle_rollback_hash_mismatch: the before-blob for x does not hash");
        let skip = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            superseded_record_skip(&target, &result, &files, &superseded_map()),
        )
        .await
        .expect("the patched-bytes probe must not block on a FIFO");
        assert!(skip.is_none());
    }

    #[tokio::test]
    async fn superseded_skip_leaves_other_failures_and_records_alone() {
        let (_tmp, target, files) = superseded_copy(b"patched by B");
        let mismatch = make_result(&[VerifyRollbackStatus::HashMismatch], &[]);
        // Not superseded: the mismatch fails as before.
        assert!(
            superseded_record_skip(&target, &mismatch, &files, &HashMap::new())
                .await
                .is_none()
        );
        // A missing before-blob is a real failure even when superseded.
        let missing = make_result(&[VerifyRollbackStatus::MissingBlob], &[]);
        assert!(
            superseded_record_skip(&target, &missing, &files, &superseded_map())
                .await
                .is_none()
        );
        // A file that exists but cannot be read may still hold A's bytes.
        let mut unreadable = make_result(&[VerifyRollbackStatus::NotFound], &[]);
        unreadable.files_verified[0].message = Some("Failed to hash file: EACCES".to_string());
        assert!(
            superseded_record_skip(&target, &unreadable, &files, &superseded_map())
                .await
                .is_none()
        );
    }

    #[test]
    fn superseded_by_hosted_needs_a_pin_with_another_uuid() {
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/foo@1.0.0".to_string(), make_record("aaaa"));
        manifest
            .patches
            .insert("pkg:npm/bar@2.0.0".to_string(), make_record("cccc"));
        let pin = |purl: &str, uuid: &str| HostedPin {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            files: vec!["package-lock.json".to_string()],
        };
        let pins = vec![
            pin("pkg:npm/foo@1.0.0", "bbbb"),
            // bar's hosted pin carries the record's own uuid: not superseded.
            pin("pkg:npm/bar@2.0.0", "cccc"),
        ];
        let map = superseded_by_hosted(&manifest, &pins);
        assert_eq!(
            map,
            HashMap::from([("pkg:npm/foo@1.0.0".to_string(), "bbbb".to_string())])
        );
        assert!(superseded_by_hosted(&manifest, &[]).is_empty());
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

    /// `make_result` with a distinct package key (the tally is per package).
    fn keyed(key: &str, r: RollbackResult) -> RollbackResult {
        RollbackResult {
            package_key: key.to_string(),
            ..r
        }
    }

    /// Regression: the dry-run "can be rolled back" count must exclude
    /// already-original packages, which are reported on their own line.
    /// Otherwise each no-op is double-counted (once as can-rollback, once
    /// as already-original).
    #[test]
    fn can_roll_back_tally_excludes_already_original() {
        let results = vec![
            // Genuinely needs restoring.
            keyed(
                "pkg:npm/a@1",
                make_result(&[VerifyRollbackStatus::Ready], &[]),
            ),
            // No-op: already at beforeHash.
            keyed(
                "pkg:npm/b@1",
                make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
            ),
            // Mixed → still needs restoring.
            keyed(
                "pkg:npm/c@1",
                make_result(
                    &[
                        VerifyRollbackStatus::Ready,
                        VerifyRollbackStatus::AlreadyOriginal,
                    ],
                    &[],
                ),
            ),
            // Failed (e.g. HashMismatch) → not counted as rollbackable.
            keyed(
                "pkg:npm/d@1",
                make_result(&[VerifyRollbackStatus::HashMismatch], &[]),
            ),
        ];
        let t = tally_rollback_results(&results);
        assert_eq!(t.can_roll_back, 2);
        assert_eq!(t.already, 1);
        assert_eq!(t.failed, 1);
    }

    /// A summary made entirely of no-ops reports zero rollbackable
    /// packages.
    #[test]
    fn can_roll_back_tally_all_already_original_is_zero() {
        let results = vec![
            keyed(
                "pkg:npm/a@1",
                make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
            ),
            keyed(
                "pkg:npm/b@1",
                make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
            ),
        ];
        let t = tally_rollback_results(&results);
        assert_eq!(t.can_roll_back, 0);
        assert_eq!(t.already, 2);
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
            Some("Cannot roll back: a.js - gone: missing_a"),
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

    /// Cargo patches in place (vendored or registry cache) and rolls back
    /// from before-blobs like npm/pypi, so the before-blob gate must NOT
    /// exclude a cargo PURL: a missing cargo before-blob is a real problem.
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
        let attempted: HashSet<&str> = manifest.patches.keys().map(String::as_str).collect();
        let gate = before_blob_gate_manifest(&manifest, &attempted, &common);
        let gate_missing = get_missing_before_blobs(&gate, blobs).await;
        assert!(
            gate_missing.contains("cargo_before"),
            "gate must keep cargo before-blobs (in-place rollback), got {gate_missing:?}"
        );
        // And the cargo PURL must not be classified as a redirect.
        assert!(!is_local_go("pkg:cargo/serde@1.0.0", &common));
    }

    /// Local-GO redirects must be excluded from the before-blob gate (cargo
    /// is not — it restores in place). A go redirect drops the `go.mod`
    /// `replace` directive + the patched copy and reads no before-blob, so a
    /// missing before-blob must not abort (nor trigger a needless download for)
    /// an offline local-go rollback.
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

        // Full manifest: the go before-blob shows up as missing, which an
        // unfiltered gate would spuriously abort on.
        let full_missing = get_missing_before_blobs(&manifest, blobs).await;
        assert!(full_missing.contains("go_before"));

        // Gate manifest: the local-go PURL is excluded, so its before-blob is
        // not counted as missing. With the npm blob present, the gate reports
        // nothing missing. (Only ATTEMPTED purls enter the gate; every
        // entry is attempted here.)
        let attempted: HashSet<&str> = manifest.patches.keys().map(String::as_str).collect();
        let gate = before_blob_gate_manifest(&manifest, &attempted, &common);
        let gate_missing = get_missing_before_blobs(&gate, blobs).await;
        assert!(
            gate_missing.is_empty(),
            "gate must exclude local-go before-blobs, got {gate_missing:?}"
        );

        // A purl the crawler did not discover is not attempted, so it never
        // gates either — even an in-place npm one.
        let only_go: HashSet<&str> = ["pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1"].into();
        assert!(
            before_blob_gate_manifest(&manifest, &only_go, &common)
                .patches
                .is_empty(),
            "an undiscovered in-place purl and a local-go purl both stay out of the gate"
        );

        // And `is_local_go` must classify the go PURL as a redirect in
        // local mode but a global PURL as in-place (gate must keep the latter).
        assert!(is_local_go(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1",
            &common
        ));
        let global = crate::args::GlobalArgs {
            global: true,
            ..crate::args::GlobalArgs::default()
        };
        assert!(!is_local_go(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1",
            &global
        ));
        let global_attempted: HashSet<&str> = ["pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1"].into();
        assert!(
            before_blob_gate_manifest(&manifest, &global_attempted, &global)
                .patches
                .contains_key("pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1"),
            "a global go purl rolls back in place, so its before-blob gates"
        );
    }

    /// Regression: rolling back a local-GO patch must DROP the project-local
    /// redirect (the `go.mod` `replace` directive + the patched copy under
    /// `.socket/go-patches/`), not fall through to in-place rollback against
    /// the pristine module cache (a silent "already original" no-op that
    /// leaves the build using the patched copy).
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
        // ...and the patched copy is removed, together with the emptied
        // `.socket/go-patches/<host>/<org>/` levels (no husk residue).
        assert!(
            !copy_dir.exists(),
            "patched copy under .socket/go-patches must be removed"
        );
        assert!(
            !root.join(".socket/go-patches").exists(),
            "emptied .socket/go-patches/ husk must be pruned after the last module"
        );
    }

    /// Regression: a dry-run local-go rollback must not CLAIM files were
    /// rolled back. The engine leaves `files_rolled_back` empty on dry-run
    /// (verify only — `rollback_package_patch` pushes into it only on the
    /// mutating path), and the JSON envelope counts `rolledBack` from a
    /// non-empty `files_rolled_back`.
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
    /// Regression: an out-of-scope patch's missing before-blob must not abort
    /// an `--ecosystems`-scoped rollback (`rollback --ecosystems npm --offline`
    /// must not fail on a pypi patch it never touches, nor download for it
    /// online).
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
    /// NOT installed must never enter the before-blob plan: its missing
    /// before-blob must not hard-fail an offline run with nothing on disk to
    /// roll back. Through the
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

    // --- Coverage-gap fills (2026-09 audit) --------------------------------

    /// Exhaustive pin of the status vocabulary the JSON `filesVerified`
    /// entries and the `--verbose` per-file labels are built from: every
    /// `VerifyRollbackStatus` variant maps to its stable snake_case string.
    #[test]
    fn verify_rollback_status_str_covers_every_variant() {
        assert_eq!(
            verify_rollback_status_str(&VerifyRollbackStatus::Ready),
            "ready"
        );
        assert_eq!(
            verify_rollback_status_str(&VerifyRollbackStatus::AlreadyOriginal),
            "already_original"
        );
        assert_eq!(
            verify_rollback_status_str(&VerifyRollbackStatus::HashMismatch),
            "hash_mismatch"
        );
        assert_eq!(
            verify_rollback_status_str(&VerifyRollbackStatus::NotFound),
            "not_found"
        );
        assert_eq!(
            verify_rollback_status_str(&VerifyRollbackStatus::MissingBlob),
            "missing_blob"
        );
    }

    /// The local-go redirect rollback's FAILURE arm: when the `go.mod` edit
    /// fails (here: `go.mod` is a directory, so the read errors), the result
    /// flips to failure, clears the pre-populated `files_rolled_back` (the
    /// JSON `rolledBack` count is derived from it, and nothing was rolled
    /// back), and carries the error.
    #[tokio::test]
    async fn try_rollback_local_go_reports_failure_when_go_mod_unreadable() {
        const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // go.mod as a DIRECTORY: `drop_replace_entry`'s go.mod read fails.
        std::fs::create_dir(root.join("go.mod")).unwrap();

        let patch = record_with_file("uuid-go", "errors.go", "go_before");
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            ..crate::args::GlobalArgs::default()
        };
        let result = try_rollback_local_go(PURL, root, &patch, &common)
            .await
            .expect("go PURL in local mode must be handled by the go backend");
        assert!(
            !result.success,
            "an unreadable go.mod must fail the redirect rollback, got {result:?}"
        );
        assert!(
            result.files_rolled_back.is_empty(),
            "a failed redirect rollback must not claim files were rolled \
             back, got {:?}",
            result.files_rolled_back
        );
        assert!(
            result.error.is_some(),
            "the failure must carry the underlying error"
        );
    }

    /// The undiscovered-redirect fallback's FAILURE leg: a manifest-only
    /// local-go redirect (no module-cache copy for the crawler to find)
    /// whose `go.mod` edit fails must surface as a real failed result —
    /// `success: false` with the error set — not silently vanish.
    #[tokio::test]
    async fn undiscovered_local_go_redirect_failure_reports_error() {
        use socket_patch_core::vendor::go_mod_edit::{ensure_replace_entry, GO_PATCHES_DIR};

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

        // Now break the redirect removal: replace go.mod with a DIRECTORY.
        tokio::fs::remove_file(root.join("go.mod")).await.unwrap();
        tokio::fs::create_dir(root.join("go.mod")).await.unwrap();

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
        .expect("rollback must not error at the boundary");

        assert!(
            !success,
            "a failed undiscovered-redirect rollback must flip success, got {results:?}"
        );
        assert_eq!(results.len(), 1, "got {results:?}");
        assert!(!results[0].success, "got {results:?}");
        assert!(
            results[0].error.is_some(),
            "the failure must carry the go.mod error, got {results:?}"
        );
        assert!(
            results[0].files_rolled_back.is_empty(),
            "nothing was rolled back, got {results:?}"
        );
        assert!(
            copy_dir.exists(),
            "the go.mod edit failed first, so the patched copy must survive"
        );
    }

    /// The `remove`-delegation contract for a MISSING manifest: the
    /// Identifier selection keeps the legacy hard error. Pins the CURRENT
    /// wording — `read_manifest` reports NotFound as `Ok(None)`, which the
    /// Identifier arm maps to the legacy "Invalid manifest" string (the
    /// message predates the missing/corrupt split).
    #[tokio::test]
    async fn rollback_patches_missing_manifest_is_identifier_error() {
        let tmp = tempfile::tempdir().unwrap();
        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let err = rollback_patches(
            &common,
            &tmp.path().join(".socket/manifest.json"),
            Some("pkg:npm/x@1.0.0"),
            false,
            true,
            None,
        )
        .await
        .expect_err("a missing manifest is an error for the Identifier selection");
        assert_eq!(err, "Invalid manifest");
    }

    /// The Identifier selection's no-match error names the identifier.
    #[tokio::test]
    async fn rollback_patches_unmatched_identifier_is_error() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        tokio::fs::create_dir_all(&socket).await.unwrap();
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let err = rollback_patches(
            &common,
            &manifest_path,
            Some("pkg:npm/nope@9.9"),
            false,
            true,
            None,
        )
        .await
        .expect_err("an identifier matching nothing must be an error");
        assert_eq!(err, "No patch found matching identifier: pkg:npm/nope@9.9");
    }

    /// An EMPTY manifest with no identifier is a quiet success for the
    /// delegation (the announce print runs; `remove` then has nothing to
    /// drop): `Ok` with success and every list empty.
    #[tokio::test]
    async fn rollback_patches_empty_manifest_is_quiet_success() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        tokio::fs::create_dir_all(&socket).await.unwrap();
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, b"{\"patches\": {}}\n")
            .await
            .unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        // silent=false so the "No patches found in manifest" announce path
        // actually executes (its output is not capturable here; the
        // contract under test is the quiet Ok).
        let (success, results, vendored_skipped, not_installed) =
            rollback_patches(&common, &manifest_path, None, false, false, None)
                .await
                .expect("an empty manifest is not an error");
        assert!(success);
        assert!(results.is_empty(), "got {results:?}");
        assert!(vendored_skipped.is_empty());
        assert!(not_installed.is_empty());
    }

    /// A package gated by ONE absent before-blob must name ONLY that blob's
    /// file in the synthesized offline abort: a sibling file in the SAME
    /// patch whose blob IS staged never rides into the failure rows (the
    /// per-file gate skip for present blobs).
    #[tokio::test]
    async fn offline_gate_names_only_the_absent_blob_file() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let index_before: &[u8] = b"index original\n";
        let index_after: &[u8] = b"index patched\n";
        let lib_before: &[u8] = b"lib original\n";
        let lib_after: &[u8] = b"lib patched\n";
        let index_before_hash = compute_git_sha256_from_bytes(index_before);
        let index_after_hash = compute_git_sha256_from_bytes(index_after);
        let lib_before_hash = compute_git_sha256_from_bytes(lib_before);
        let lib_after_hash = compute_git_sha256_from_bytes(lib_after);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        let blobs = socket.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        // Installed package with BOTH files at their PATCHED bytes (so
        // both would genuinely read their before-blob on restore).
        tokio::fs::write(
            root.join("package.json"),
            r#"{ "name": "gate-two-file-root", "version": "0.0.0" }"#,
        )
        .await
        .unwrap();
        let pkg_dir = root.join("node_modules").join("gatepkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("package.json"),
            r#"{ "name": "gatepkg", "version": "1.0.0" }"#,
        )
        .await
        .unwrap();
        tokio::fs::write(pkg_dir.join("index.js"), index_after)
            .await
            .unwrap();
        tokio::fs::write(pkg_dir.join("lib.js"), lib_after)
            .await
            .unwrap();

        // One record, two file rows.
        let mut rec = make_record("uuid-gate");
        rec.files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: index_before_hash.clone(),
                after_hash: index_after_hash.clone(),
            },
        );
        rec.files.insert(
            "package/lib.js".to_string(),
            PatchFileInfo {
                before_hash: lib_before_hash.clone(),
                after_hash: lib_after_hash.clone(),
            },
        );
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/gatepkg@1.0.0".to_string(), rec);
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();

        // Stage ONLY index's before-blob; lib's is deliberately absent.
        tokio::fs::write(blobs.join(&index_before_hash), index_before)
            .await
            .unwrap();

        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored, _not_installed) =
            rollback_patches(&common, &manifest_path, None, false, true, None)
                .await
                .expect("rollback must not error");
        assert!(!success, "the absent lib before-blob must abort offline");
        assert_eq!(results.len(), 1, "got {results:?}");
        let r = &results[0];
        assert_eq!(r.package_key, "pkg:npm/gatepkg@1.0.0");
        assert!(!r.success);
        assert_eq!(
            r.files_verified.len(),
            1,
            "the staged index blob must NOT ride into the abort, got {results:?}"
        );
        let f = &r.files_verified[0];
        assert_eq!(f.file, "package/lib.js");
        assert_eq!(f.status, VerifyRollbackStatus::MissingBlob);
        assert_eq!(f.target_hash.as_deref(), Some(lib_before_hash.as_str()));
        assert!(
            r.error
                .as_deref()
                .is_some_and(|e| e.contains("package/lib.js")),
            "the abort error names the blocking file, got {results:?}"
        );
    }

    /// A dry run over a patch that CREATES a file (empty `beforeHash`
    /// sentinel) must succeed: the throwaway blob stage skips the sentinel
    /// (there is no blob "" to stage) and leaves no litter behind.
    #[tokio::test]
    async fn dry_run_tolerates_created_by_patch_sentinel_rows() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let index_before: &[u8] = b"sentinel index original\n";
        let index_after: &[u8] = b"sentinel index patched\n";
        let created: &[u8] = b"file created by the patch\n";
        let index_before_hash = compute_git_sha256_from_bytes(index_before);
        let index_after_hash = compute_git_sha256_from_bytes(index_after);
        let created_hash = compute_git_sha256_from_bytes(created);

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        let blobs = socket.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(
            root.join("package.json"),
            r#"{ "name": "sentinel-root", "version": "0.0.0" }"#,
        )
        .await
        .unwrap();
        let pkg_dir = root.join("node_modules").join("sentinelpkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("package.json"),
            r#"{ "name": "sentinelpkg", "version": "1.0.0" }"#,
        )
        .await
        .unwrap();
        tokio::fs::write(pkg_dir.join("index.js"), index_after)
            .await
            .unwrap();
        tokio::fs::write(pkg_dir.join("created.js"), created)
            .await
            .unwrap();

        let mut rec = make_record("uuid-sentinel");
        rec.files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: index_before_hash.clone(),
                after_hash: index_after_hash,
            },
        );
        rec.files.insert(
            "package/created.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(), // created-by-patch sentinel
                after_hash: created_hash,
            },
        );
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/sentinelpkg@1.0.0".to_string(), rec);
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();
        tokio::fs::write(blobs.join(&index_before_hash), index_before)
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
            true, // dry_run
            true, // silent
            None,
        )
        .await
        .expect("dry run must not error");
        assert!(
            success,
            "a created-by-patch row must not fail the dry run, got {results:?}"
        );
        assert_eq!(results.len(), 1, "got {results:?}");
        assert!(results[0].success, "got {results:?}");

        // No `.socket-stage-*` litter, and the real blobs dir is untouched
        // (exactly the one staged before-blob — no phantom "" blob).
        let mut socket_entries: Vec<String> = std::fs::read_dir(&socket)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        socket_entries.sort();
        assert!(
            socket_entries
                .iter()
                .all(|n| !n.starts_with(".socket-stage")),
            "dry-run must clean up its blob stage, found {socket_entries:?}"
        );
        let blob_entries: Vec<String> = std::fs::read_dir(&blobs)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            blob_entries,
            vec![index_before_hash],
            "the committable blobs dir must be untouched by a dry run"
        );
    }

    /// The vendored leg tolerates a key with no ledger entry: the scope
    /// resolver guarantees keys exist, but a divergent ledger must skip
    /// the key silently (the lookup-miss `continue`) rather than panic or
    /// fail the leg — every outcome array stays empty.
    #[tokio::test]
    async fn run_vendored_leg_skips_keys_missing_from_ledger() {
        let common = crate::args::GlobalArgs::default();
        let mut state = socket_patch_core::vendor::VendorState::new();
        let out = run_vendored_leg(
            &common,
            &["pkg:npm/ghost@1.0.0".to_string()],
            &mut state,
            false,
        )
        .await;
        assert!(
            out.reverted.is_empty()
                && out.preserved.is_empty()
                && out.kept.is_empty()
                && out.failed.is_empty()
                && out.warnings.is_empty(),
            "an unknown ledger key must be a silent no-op: reverted={:?} \
             preserved={:?} kept={:?} failed={:?} warnings={:?}",
            out.reverted,
            out.preserved,
            out.kept,
            out.failed,
            out.warnings
        );
        assert!(
            state.entries.is_empty(),
            "the ledger must be untouched, got {:?}",
            state.entries.keys().collect::<Vec<_>>()
        );
    }

    // ── human output formatters ──────────────────────────────────────────

    fn rb(purl: &str, path: &str, status: VerifyRollbackStatus, rolled: bool) -> RollbackResult {
        RollbackResult {
            package_key: purl.to_string(),
            package_path: path.to_string(),
            success: true,
            files_verified: vec![VerifyRollbackResult {
                file: "index.js".to_string(),
                status,
                message: None,
                current_hash: None,
                expected_hash: None,
                target_hash: None,
            }],
            files_rolled_back: if rolled {
                vec!["index.js".to_string()]
            } else {
                Vec::new()
            },
            error: None,
            sidecar: None,
        }
    }

    #[test]
    fn join_clauses_is_an_english_list() {
        let c = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(join_clauses(&[]), "");
        assert_eq!(join_clauses(&c(&["a"])), "a");
        assert_eq!(join_clauses(&c(&["a", "b"])), "a and b");
        assert_eq!(join_clauses(&c(&["a", "b", "c"])), "a, b, and c");
        assert_eq!(as_question(""), "");
        assert_eq!(as_question("roll back"), "Roll back?");
        assert_eq!(as_question("éclair"), "Éclair?");
    }

    #[test]
    fn rollback_prompt_singular_plural_and_clauses() {
        assert_eq!(
            rollback_prompt(1, 0, 0),
            "Roll back 1 patch and remove it from the local manifest?"
        );
        assert_eq!(
            rollback_prompt(2, 0, 0),
            "Roll back 2 patches and remove them from the local manifest?"
        );
        // Never "..., and restore" after an inner "and".
        assert_eq!(
            rollback_prompt(1, 0, 1),
            "Roll back 1 patch, remove it from the local manifest, and restore 1 hosted \
             package to the upstream registry?"
        );
        assert_eq!(
            rollback_prompt(0, 0, 3),
            "Restore 3 hosted packages to the upstream registry?"
        );
        assert_eq!(
            rollback_prompt(0, 1, 0),
            "Delete 1 vendored artifact and its ledger record?"
        );
        assert_eq!(
            rollback_prompt(0, 2, 0),
            "Delete 2 vendored artifacts and their ledger records?"
        );
    }

    #[test]
    fn rollback_failure_line() {
        assert_eq!(
            format_rollback_failure("pkg:npm/a@1", "boom"),
            "Error: Failed to roll back pkg:npm/a@1: boom"
        );
    }

    #[test]
    fn rollback_failed_closing_line() {
        assert_eq!(
            format_rollback_failed(false),
            "Error: Some patches could not be rolled back."
        );
        assert_eq!(
            format_rollback_failed(true),
            "Error: Some patches cannot be rolled back."
        );
    }

    #[test]
    fn dry_run_counts_block() {
        let p = Path::new("/p");
        let results = vec![
            rb("pkg:npm/a@1", "/p/a", VerifyRollbackStatus::Ready, false),
            rb(
                "pkg:npm/b@1",
                "/p/b",
                VerifyRollbackStatus::AlreadyOriginal,
                false,
            ),
        ];
        assert_eq!(
            format_rollback_dry_run_counts(&results, p),
            vec![
                "",
                "Rollback verification complete:",
                "  1 package can be rolled back",
                "  1 package already in original state",
            ]
        );
        // Failures carry their reason: a dry run has no other report.
        let mut failed = rb(
            "pkg:npm/c@1",
            "/p/c",
            VerifyRollbackStatus::HashMismatch,
            false,
        );
        failed.success = false;
        failed.error = Some("modified after patching".into());
        let mut other = failed.clone();
        other.package_key = "pkg:npm/d@1".into();
        assert_eq!(
            format_rollback_dry_run_counts(&[failed, other], p),
            vec![
                "",
                "Rollback verification complete:",
                "  0 packages can be rolled back",
                "  2 packages cannot be rolled back",
                "",
                "Failed to roll back:",
                "  pkg:npm/c@1: modified after patching",
                "  pkg:npm/d@1: modified after patching",
            ]
        );
        assert_eq!(format_rollback_dry_run_counts(&[], p).len(), 3);
    }

    #[test]
    fn dry_run_counts_each_package_once_across_copies() {
        // Two installed copies of one purl: "1 package", matching apply.
        let results = vec![
            rb(
                "pkg:npm/nuxt@4.5.0",
                "/p/node_modules/nuxt",
                VerifyRollbackStatus::Ready,
                false,
            ),
            rb(
                "pkg:npm/nuxt@4.5.0",
                "/p/node_modules/vite/node_modules/nuxt",
                VerifyRollbackStatus::Ready,
                false,
            ),
        ];
        assert_eq!(
            format_rollback_dry_run_counts(&results, Path::new("/p"))[2],
            "  1 package can be rolled back"
        );
        assert_eq!(
            tally_rollback_results(&results),
            RollbackTally {
                can_roll_back: 1,
                ..RollbackTally::default()
            }
        );
    }

    #[test]
    fn handled_in_place_covers_restored_restorable_and_original() {
        let restored = rb("pkg:npm/a@1", "/p/a", VerifyRollbackStatus::Ready, true);
        let dry = rb("pkg:npm/b@1", "/p/b", VerifyRollbackStatus::Ready, false);
        let orig = rb(
            "pkg:npm/c@1",
            "/p/c",
            VerifyRollbackStatus::AlreadyOriginal,
            false,
        );
        let mut failed = rb(
            "pkg:npm/d@1",
            "/p/d",
            VerifyRollbackStatus::HashMismatch,
            false,
        );
        failed.success = false;
        let mut empty = rb("pkg:npm/e@1", "/p/e", VerifyRollbackStatus::Ready, false);
        empty.files_verified.clear();
        let all = [restored, dry, orig, failed, empty];
        let got = handled_in_place(&all);
        let mut got: Vec<&str> = got.into_iter().collect();
        got.sort();
        assert_eq!(got, vec!["pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1"]);
    }

    #[test]
    fn tally_buckets_per_package() {
        let done = rb("pkg:npm/a@1", "/p/a1", VerifyRollbackStatus::Ready, true);
        let done_twin = rb(
            "pkg:npm/a@1",
            "/p/a2",
            VerifyRollbackStatus::AlreadyOriginal,
            false,
        );
        let orig = rb(
            "pkg:npm/b@1",
            "/p/b",
            VerifyRollbackStatus::AlreadyOriginal,
            false,
        );
        let ok_copy = rb("pkg:npm/c@1", "/p/c1", VerifyRollbackStatus::Ready, true);
        let mut bad_copy = rb(
            "pkg:npm/c@1",
            "/p/c2",
            VerifyRollbackStatus::HashMismatch,
            false,
        );
        bad_copy.success = false;
        assert_eq!(
            tally_rollback_results(&[done, done_twin, orig, ok_copy, bad_copy]),
            RollbackTally {
                rolled_back: 1,
                can_roll_back: 1,
                already: 1,
                failed: 1,
            }
        );
        assert_eq!(tally_rollback_results(&[]), RollbackTally::default());
    }

    #[test]
    fn results_block_names_duplicate_copies_and_failures_once() {
        let results = vec![
            rb(
                "pkg:npm/nuxt@4.5.0",
                "/p/node_modules/nuxt",
                VerifyRollbackStatus::Ready,
                true,
            ),
            rb(
                "pkg:npm/nuxt@4.5.0",
                "/p/node_modules/vite/node_modules/nuxt",
                VerifyRollbackStatus::Ready,
                true,
            ),
            rb(
                "pkg:npm/ok@1",
                "/p/node_modules/ok",
                VerifyRollbackStatus::AlreadyOriginal,
                false,
            ),
        ];
        assert_eq!(
            format_rollback_results(&results, Path::new("/p")),
            vec![
                "",
                "Rolled back packages:",
                "  pkg:npm/nuxt@4.5.0 (node_modules/nuxt)",
                "  pkg:npm/nuxt@4.5.0 (node_modules/vite/node_modules/nuxt)",
                "  pkg:npm/ok@1 (already original)",
            ]
        );
        let mut failed = rb(
            "pkg:npm/x@1",
            "/p/x",
            VerifyRollbackStatus::HashMismatch,
            false,
        );
        failed.success = false;
        failed.error = Some("modified".into());
        assert_eq!(
            format_rollback_results(&[failed], Path::new("/p")),
            vec!["", "Failed to roll back:", "  pkg:npm/x@1: modified"]
        );
        assert!(format_rollback_results(&[], Path::new("/p")).is_empty());
    }

    #[test]
    fn preserved_note_names_only_what_was_kept() {
        assert_eq!(
            format_preserved_note(1, 0),
            "Manifest entry preserved (--preserve-state); re-apply with `socket-patch apply`."
        );
        assert_eq!(
            format_preserved_note(1, 1),
            "Manifest entry and vendored artifact preserved (--preserve-state); re-apply \
             with `socket-patch apply` or `socket-patch vendor`."
        );
        assert_eq!(
            format_preserved_note(2, 2),
            "Manifest entries and vendored artifacts preserved (--preserve-state); re-apply \
             with `socket-patch apply` or `socket-patch vendor`."
        );
    }

    #[test]
    fn gc_freed_uses_human_bytes() {
        assert_eq!(
            format_gc_freed(336161, false),
            "Freed 328.28 KB of unused blobs and archives"
        );
        assert_eq!(
            format_gc_freed(12, true),
            "Would free 12 B of unused blobs and archives"
        );
    }

    #[test]
    fn reinstall_note_tense_and_number() {
        assert_eq!(
            format_reinstall_note(1, false, false),
            "Note: 1 unwired package keeps its patched bytes in installed trees until the \
             next package-manager install."
        );
        assert_eq!(
            format_reinstall_note(2, true, false),
            "Note: 2 unwired packages would keep their patched bytes in installed trees \
             until the next package-manager install."
        );
    }

    /// #764: next to a Bun advisory the generic note must not imply that
    /// any install refreshes the copy.
    #[test]
    fn reinstall_note_defers_to_the_bun_advisory() {
        assert_eq!(
            format_reinstall_note(1, false, true),
            "Note: 1 unwired package keeps its patched bytes in installed trees until the \
             next package-manager install (Bun: a plain `bun install` keeps them; run \
             `bun install --force`)."
        );
        assert!(bun_reinstall_advised(
            ["cleanup_failed", "vendor_bun_reinstall_required"].into_iter()
        ));
        assert!(bun_reinstall_advised(
            ["redirect_bun_reinstall_required"].into_iter()
        ));
        assert!(!bun_reinstall_advised(
            ["redirect_vlt_reinstall_required"].into_iter()
        ));
    }

    // ── v5.0 envelope (build_rollback_envelope) ─────────────────────────

    fn failed_rb(purl: &str) -> RollbackResult {
        RollbackResult {
            package_key: purl.to_string(),
            package_path: "/p/bad".to_string(),
            success: false,
            files_verified: vec![VerifyRollbackResult {
                file: "index.js".to_string(),
                status: VerifyRollbackStatus::HashMismatch,
                message: Some("drifted".to_string()),
                current_hash: Some("c".to_string()),
                expected_hash: Some("e".to_string()),
                target_hash: None,
            }],
            files_rolled_back: Vec::new(),
            error: Some("cannot roll back index.js: drifted".to_string()),
            sidecar: None,
        }
    }

    fn report<'a>(
        dry_run: bool,
        success: bool,
        manifest: &'a PatchManifest,
        results: &'a [RollbackResult],
        vendored: &'a VendoredLegOutcome,
        hosted: &'a HostedLegOutcome,
    ) -> RollbackReport<'a> {
        RollbackReport {
            dry_run,
            success,
            manifest,
            results,
            not_installed: &[],
            vendored,
            vendor_entries: &[],
            hosted,
            hosted_pins: &[],
            contested: None,
            removed: &[],
            gc: None,
            warnings: &[],
            paths: &[],
        }
    }

    /// Every top-level key, status and event action/errorCode is from the
    /// shared vocabulary, and `summary` equals the event counts.
    fn assert_envelope_invariants(v: &serde_json::Value) {
        assert_eq!(v["command"], "rollback", "{v}");
        let allowed = [
            "command", "status", "dryRun", "events", "summary", "error", "sidecars", "warnings",
            "vex", "gc", "hosted", "paths", "path", "legacyRedirectLedgerRemoved",
        ];
        for key in v.as_object().unwrap().keys() {
            assert!(allowed.contains(&key.as_str()), "unexpected key {key}: {v}");
            assert!(!key.contains('_'), "snake_case key {key}");
        }
        assert!(!v["status"].as_str().unwrap().contains('_'), "{v}");
        let events = v["events"].as_array().unwrap();
        for action in [
            "discovered", "downloaded", "applied", "updated", "skipped", "failed", "removed",
            "verified", "rebuilt", "rolledBack",
        ] {
            let n = events.iter().filter(|e| e["action"] == action).count();
            assert_eq!(v["summary"][action], n, "summary.{action}: {v}");
        }
    }

    #[test]
    fn envelope_maps_every_leg_to_events() {
        let mut manifest = PatchManifest::new();
        manifest
            .patches
            .insert("pkg:npm/a@1.0.0".to_string(), make_record("uuid-a"));
        let results = vec![
            rb("pkg:npm/a@1.0.0", "/p/a", VerifyRollbackStatus::Ready, true),
            rb("pkg:npm/o@1.0.0", "/p/o", VerifyRollbackStatus::AlreadyOriginal, false),
            failed_rb("pkg:npm/bad@1.0.0"),
        ];
        let vendored = VendoredLegOutcome {
            reverted: vec!["pkg:npm/v@1.0.0".to_string()],
            preserved: vec!["pkg:npm/vp@1.0.0".to_string()],
            kept: vec![("pkg:npm/vk@1.0.0".to_string(), "drifted".to_string())],
            failed: vec![(
                "pkg:npm/vf@1.0.0".to_string(),
                "vendor_revert_failed",
                "boom".to_string(),
            )],
            warnings: Vec::new(),
        };
        let hosted = HostedLegOutcome {
            reverted: vec!["pkg:npm/h@1.0.0".to_string()],
            failed: vec![
                ("pkg:npm/hf@1.0.0".to_string(), "refused".to_string()),
                (HOSTED_WRITE_FAILURE_KEY.to_string(), "disk full".to_string()),
            ],
            edited_files: ["package-lock.json".to_string()].into(),
            ..Default::default()
        };
        let not_installed = vec!["pkg:npm/gone@1.0.0".to_string()];
        let removed = vec!["pkg:npm/a@1.0.0".to_string()];
        let warnings = vec![("reinstall_required".to_string(), "x".to_string())];
        let gc = GcReport {
            removed_blobs: 1,
            bytes_freed: 42,
            ..Default::default()
        };
        let env = build_rollback_envelope(&RollbackReport {
            not_installed: &not_installed,
            removed: &removed,
            warnings: &warnings,
            gc: Some(gc),
            ..report(false, false, &manifest, &results, &vendored, &hosted)
        });
        let v = env.to_value();
        assert_envelope_invariants(&v);
        assert_eq!(v["status"], "partialFailure");
        assert!(v.get("error").is_none());
        assert_eq!(v["summary"]["rolledBack"], 4, "a, v, vp, h: {v}");
        assert_eq!(v["summary"]["failed"], 5, "bad, vk, vf, hf, files: {v}");
        assert_eq!(v["summary"]["skipped"], 2, "already original + not installed");
        assert_eq!(v["summary"]["removed"], 1);
        assert_eq!(v["summary"]["bytesFreed"], 42);
        assert_eq!(v["gc"]["removedBlobs"], 1);
        assert_eq!(v["hosted"]["editedFiles"], 1);
        assert_eq!(v["paths"], serde_json::json!([]));
        assert_eq!(v["warnings"][0]["code"], "reinstall_required");

        let events = v["events"].as_array().unwrap();
        let find = |action: &str, purl: &str| {
            events
                .iter()
                .find(|e| e["action"] == action && e["purl"] == purl)
                .unwrap_or_else(|| panic!("no {action} {purl}: {v}"))
        };
        let a = find("rolledBack", "pkg:npm/a@1.0.0");
        assert_eq!(a["uuid"], "uuid-a");
        assert_eq!(a["files"][0]["path"], "index.js");
        assert_eq!(a["details"]["path"], "/p/a");
        assert!(a["details"].get("mode").is_none(), "agent events carry no mode");
        assert_eq!(
            find("skipped", "pkg:npm/o@1.0.0")["errorCode"],
            "already_original"
        );
        let bad = find("failed", "pkg:npm/bad@1.0.0");
        assert_eq!(bad["errorCode"], "hash_mismatch");
        assert_eq!(bad["details"]["filesVerified"][0]["status"], "hashMismatch");
        assert_eq!(
            find("skipped", "pkg:npm/gone@1.0.0")["errorCode"],
            "package_not_installed"
        );
        assert_eq!(find("rolledBack", "pkg:npm/v@1.0.0")["details"]["mode"], "vendored");
        let vp = find("rolledBack", "pkg:npm/vp@1.0.0");
        assert_eq!(vp["details"]["mode"], "vendored");
        assert_eq!(vp["details"]["preserved"], true);
        assert_eq!(find("failed", "pkg:npm/vk@1.0.0")["errorCode"], "vendor_revert_kept");
        assert_eq!(find("failed", "pkg:npm/vf@1.0.0")["errorCode"], "vendor_revert_failed");
        assert_eq!(find("rolledBack", "pkg:npm/h@1.0.0")["details"]["mode"], "hosted");
        assert_eq!(
            find("failed", "pkg:npm/hf@1.0.0")["errorCode"],
            "hosted_restore_refused"
        );
        let write = events
            .iter()
            .find(|e| e["errorCode"] == "hosted_write_failed")
            .expect("artifact-level write failure");
        assert!(write.get("purl").is_none());
        let removed = find("removed", "pkg:npm/a@1.0.0");
        assert_eq!(removed["details"]["manifest"], true);
    }

    #[test]
    fn envelope_dry_run_previews_are_verified() {
        let manifest = PatchManifest::new();
        let results = vec![rb("pkg:npm/a@1.0.0", "/p/a", VerifyRollbackStatus::Ready, false)];
        let vendored = VendoredLegOutcome {
            reverted: vec!["pkg:npm/v@1.0.0".to_string()],
            ..Default::default()
        };
        let hosted = HostedLegOutcome {
            reverted: vec!["pkg:npm/h@1.0.0".to_string()],
            ..Default::default()
        };
        let removed = vec!["pkg:npm/a@1.0.0".to_string()];
        let env = build_rollback_envelope(&RollbackReport {
            removed: &removed,
            ..report(true, true, &manifest, &results, &vendored, &hosted)
        });
        let v = env.to_value();
        assert_envelope_invariants(&v);
        assert_eq!(v["status"], "success");
        assert_eq!(v["dryRun"], true);
        assert_eq!(v["summary"]["verified"], 4, "{v}");
        assert_eq!(v["summary"]["rolledBack"], 0);
        assert_eq!(v["summary"]["removed"], 0);
        assert_eq!(v["events"][0]["files"][0]["path"], "index.js");
        assert!(v.get("gc").is_none());
    }

    #[test]
    fn envelope_total_failure_is_rollback_failed_error() {
        let manifest = PatchManifest::new();
        let results = vec![failed_rb("pkg:npm/bad@1.0.0")];
        let vendored = VendoredLegOutcome::default();
        let hosted = HostedLegOutcome::default();
        let v = build_rollback_envelope(&report(
            false, false, &manifest, &results, &vendored, &hosted,
        ))
        .to_value();
        assert_envelope_invariants(&v);
        assert_eq!(v["status"], "error");
        assert_eq!(v["error"]["code"], "rollback_failed");
        assert_eq!(v["summary"]["failed"], 1);
        // The failed event survives beside the top-level error.
        assert_eq!(v["events"][0]["action"], "failed");
    }

    #[test]
    fn envelope_run_level_failure_is_partial_without_events() {
        // A corrupt vendor ledger / failed manifest write: no event, exit 1.
        let manifest = PatchManifest::new();
        let vendored = VendoredLegOutcome::default();
        let hosted = HostedLegOutcome::default();
        let warnings = vec![("vendor_state_unreadable".to_string(), "bad".to_string())];
        let v = build_rollback_envelope(&RollbackReport {
            warnings: &warnings,
            ..report(false, false, &manifest, &[], &vendored, &hosted)
        })
        .to_value();
        assert_envelope_invariants(&v);
        assert_eq!(v["status"], "partialFailure");
        assert!(v.get("error").is_none());
    }

    #[test]
    fn envelope_contested_wiring_is_an_artifact_failure() {
        let manifest = PatchManifest::new();
        let results = vec![rb("pkg:npm/a@1.0.0", "/p/a", VerifyRollbackStatus::Ready, true)];
        let vendored = VendoredLegOutcome::default();
        let hosted = HostedLegOutcome::default();
        let v = build_rollback_envelope(&RollbackReport {
            contested: Some("cannot attribute"),
            ..report(false, false, &manifest, &results, &vendored, &hosted)
        })
        .to_value();
        assert_envelope_invariants(&v);
        assert_eq!(v["status"], "partialFailure");
        let e = &v["events"][1];
        assert_eq!(e["action"], "failed");
        assert_eq!(e["errorCode"], "hosted_wiring_contested");
        assert_eq!(e["details"]["mode"], "hosted");
    }

    #[test]
    fn error_envelope_is_a_full_envelope() {
        let v = error_envelope(true, EnvelopeError::new("patch_not_found", "nope")).to_value();
        assert_envelope_invariants(&v);
        assert_eq!(v["status"], "error");
        assert_eq!(v["dryRun"], true);
        assert_eq!(v["events"], serde_json::json!([]));
        assert_eq!(v["summary"]["failed"], 0);
        assert_eq!(v["error"]["code"], "patch_not_found");
        assert_eq!(v["error"]["message"], "nope");
    }

    #[test]
    fn failure_codes_follow_the_blocking_file() {
        assert_eq!(rollback_failure_code(&failed_rb("pkg:npm/x@1")), "hash_mismatch");
        let mut r = failed_rb("pkg:npm/x@1");
        r.files_verified[0].status = VerifyRollbackStatus::MissingBlob;
        assert_eq!(rollback_failure_code(&r), "missing_blob");
        r.files_verified[0].status = VerifyRollbackStatus::NotFound;
        assert_eq!(rollback_failure_code(&r), "file_not_found");
        r.files_verified.clear();
        assert_eq!(rollback_failure_code(&r), "rollback_failed");
    }
}
