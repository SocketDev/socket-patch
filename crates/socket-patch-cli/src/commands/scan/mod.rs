//! The `scan` command: crawl installed (and lockfile-resolved) packages,
//! query the patch API for available patches, and optionally consume them
//! in one of three modes — hosted (`hosted::run_redirect`), vendored
//! (`vendor_flow`), or agent (in-place apply) — with an optional GC pass
//! (`gc`) and discovery helpers (`discovery`). This module keeps the CLI
//! surface (`ScanArgs`, `ScanMode`, `resolve_mode_flags`, `run`) and the
//! small helpers shared across the submodules.

use clap::Args;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::telemetry::{track_patch_scan_failed, track_patch_scanned};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use std::collections::HashSet;
use std::io::IsTerminal;
use std::path::Path;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::crawl_all_ecosystems;
use crate::output::{color, confirm, format_severity};

use super::get::{
    download_and_apply_patches, select_patches, truncate_with_ellipsis, DownloadParams,
};

mod discovery;
mod gc;
mod hosted;
mod vendor_flow;

use self::discovery::{
    collect_vuln_ids, detect_updates, lockfile_supplement, merge_redirect_records_for_updates,
    preverify_vendor_baselines, severity_order, vendored_ledger_supplement,
};
// Shared with `get --mode hosted|vendored` (commands::get): the advisory-
// pinned entry into the hosted engine, the vendor step + its dry-run
// preview, and the PnP layout-refusal warning mapping. `pub(crate)`
// re-exports because the submodules themselves stay private to scan.
pub(crate) use self::discovery::unsupported_layout_warnings;
pub(crate) use self::hosted::boxed_run_redirect_selected;
pub(crate) use self::vendor_flow::{boxed_scan_vendor_step, preview_vendor_json};
use self::gc::{gc_json, print_gc_vendored_line, run_apply_gc};
use self::hosted::run_redirect;
use self::vendor_flow::{
    boxed_vendor_interactive_path, boxed_vendor_json_path, fold_vendored_skips_into_apply,
    partition_skipped_selected,
};

const DEFAULT_BATCH_SIZE: usize = 100;

/// The three patch-application modes `scan` can drive, selectable via
/// `--mode` (the documented spelling). Each variant is equivalent to one
/// legacy boolean flag, which remains supported as an alias.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// Rewrite lockfiles so ONLY patched dependencies resolve to Socket's
    /// hosted patch server (== `--redirect`): no artifact bytes land in the
    /// repo, but installs must reach the patch server. Hidden value aliases
    /// mirror the legacy flag spellings symmetrically: `host` matches the
    /// old mode name, `redirect` matches the `--redirect` boolean (vendored
    /// accepts `vendor` for the same reason; `apply` is NOT an alias of
    /// agent — applying is not a scan mode name anywhere else).
    #[value(alias = "host", alias = "redirect")]
    Hosted,
    /// Commit patched artifacts to `.socket/vendor/` (== `--vendor`):
    /// hermetic, offline-safe installs at the cost of repo size.
    #[value(alias = "vendor")]
    Vendored,
    /// Record patches in `.socket/manifest.json` + blobs and re-apply them
    /// in place, e.g. from CI (== `--apply`): smallest repo footprint, but
    /// every install environment must run the agent.
    Agent,
}

impl ScanMode {
    /// The CLI spelling of the variant (`--mode <name>`), for error messages.
    /// `pub(crate)`: `get --mode` reuses the enum and its error wording.
    pub(crate) fn cli_name(self) -> &'static str {
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
///   Hosted mode runs no GC, so `--mode hosted --prune` stays accepted but
///   emits an explicit `redirect_prune_ignored` warning in `run` rather
///   than silently dropping the flag.
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
    /// workflow. No effect in hosted mode (which runs no GC): the run
    /// proceeds with an explicit `redirect_prune_ignored` warning.
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
    // A dry run is a non-mutating preview: generating here would verify the
    // deliberately untouched tree (failing outright on a not-yet-vendored
    // project) and write an attestation file to disk. The marker keeps the
    // request visible to JSON consumers instead of silently dropping it
    // (same shape as the vendor JSON arm's early return).
    if common.dry_run {
        result["vex"] = serde_json::json!({ "skipped": true, "reason": "dry_run" });
        return base_code;
    }
    let params = vex_args.to_build_params();
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            result["vex"] = serde_json::json!({
                "path": vex_args.vex.as_ref().expect("--vex is Some: guarded by the early return above").display().to_string(),
                "statements": summary.statements,
                "format": "openvex-0.2.0",
            });
            // Same additive `warnings` key the envelope's `VexSummary`
            // carries (skip-if-empty): note_warning suppressed these on
            // stderr under --json, so this is their only surviving channel.
            if !summary.warnings.is_empty() {
                result["vex"]["warnings"] = serde_json::to_value(&summary.warnings)
                    .expect("RunWarning is a plain string struct: serialization cannot fail");
            }
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
    // Dry-run twin of the JSON guard above: no generation, no file write.
    if common.dry_run {
        if !common.silent {
            println!("[dry-run] VEX generation skipped. No attestation written.");
        }
        return base_code;
    }
    let params = vex_args.to_build_params();
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            if !common.silent {
                println!(
                    "Wrote OpenVEX document with {} statement(s) to {}",
                    summary.statements,
                    vex_args
                        .vex
                        .as_ref()
                        .expect("--vex is Some: guarded by the early return above")
                        .display(),
                );
            }
            0
        }
        Err(e) => {
            // Errors print even under --silent ("errors only", never
            // "nothing"): exit 1 with no message would be undiagnosable.
            eprintln!("Error: VEX generation failed: {}", e.message);
            1
        }
    }
}

/// The per-package discovery + selection step shared by the apply, vendor,
/// and redirect flows: search each patched package's full patch list, then
/// resolve the newest accessible patch per PURL. Per-package search errors
/// are skipped — but when EVERY query errors the step produced no
/// trustworthy patch data at all, and reporting the empty set would be
/// indistinguishable from a genuine "no patches" result (the same masking
/// the batch loop in `run` guards against), so that surfaces as `Err(1)`
/// with the failure on stderr. Passes `is_json = false` to
/// `select_patches`: scan-driven workflows have no "specify --id" option,
/// so non-TTY runs auto-select the newest patch rather than erroring with
/// `selection_required`. `Err` carries the exit code AND the message: the
/// JSON callers must fold it into their envelope (every `--json`
/// invocation emits exactly one JSON object — see CLI_CONTRACT.md), so
/// the stderr line alone is not enough.
async fn discover_selected(
    api_client: &socket_patch_core::api::client::ApiClient,
    org_slug: Option<&str>,
    packages: &[BatchPackagePatches],
    can_access_paid_patches: bool,
) -> Result<Vec<PatchSearchResult>, (i32, String)> {
    let mut all_search_results: Vec<PatchSearchResult> = Vec::new();
    let mut error_count = 0usize;
    let mut last_error: Option<String> = None;
    for pkg in packages {
        match api_client
            .search_patches_by_package(org_slug, &pkg.purl)
            .await
        {
            Ok(response) => all_search_results.extend(response.patches),
            Err(e) => {
                error_count += 1;
                last_error = Some(e.to_string());
            }
        }
    }
    if error_count > 0 && error_count == packages.len() {
        let err = last_error.unwrap_or_else(|| "all patch-detail queries failed".to_string());
        let message = format!("all {error_count} patch-detail queries failed: {err}");
        eprintln!("Error: {message}");
        return Err((1, message));
    }
    if all_search_results.is_empty() {
        return Ok(Vec::new());
    }
    select_patches(&all_search_results, can_access_paid_patches, false)
        .map_err(|code| (code, "patch selection failed".to_string()))
}

/// Fold a [`discover_selected`] failure into a JSON caller's `result` and
/// print it. The discovery counts already in `result` stay — they were
/// computed from the (successful) batch phase — while `status`/`error`
/// mirror the all-batches-failed envelope so JSON consumers see one
/// consistent scan-error schema instead of empty stdout.
fn emit_discovery_error_json(result: &mut serde_json::Value, message: &str) {
    result["status"] = serde_json::json!("error");
    result["error"] = serde_json::json!(message);
    println!(
        "{}",
        serde_json::to_string_pretty(result)
            .expect("serializing an in-memory JSON value cannot fail")
    );
}

/// The `DownloadParams` every scan-driven download shares. Only the output
/// shape (`json`/`silent`) and `save_only` differ per flow; vendor mode
/// never persists blobs (the vendor step consumes the staged sources).
fn download_params(args: &ScanArgs, save_only: bool, json: bool, silent: bool) -> DownloadParams {
    DownloadParams {
        cwd: args.common.cwd.clone(),
        manifest_path: args.common.resolved_manifest_path(),
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
        ecosystems: args.common.ecosystems.clone(),
        persist_blobs: args.mode != Some(ScanMode::Vendored),
    }
}

// ---------------------------------------------------------------------------
// Cross-mode ledger takeover detection (hosted ⇄ vendored)
// ---------------------------------------------------------------------------
//
// Hosted mode writes `.socket/vendor/redirect-state.json`; vendored mode
// writes `.socket/vendor/state.json` (+ committed tarballs). Switching a
// project's mode rewires the lockfile to the NEW mode but leaves the OLD
// mode's ledger on disk asserting wiring that is no longer live (and, for
// vendored→hosted, the orphaned tarball behind). Anything auditing a ledger
// as "what is live" (including `vex`) is then misled. Detect the overlap so
// each flow can warn. Reconciliation is per direction: the VENDORED flows
// clean the superseded redirect-ledger halves themselves (cargo via
// `revert_cargo_redirect_purl` before vendoring, npm-family via
// `note_vendor_supersedes_redirect` after — always announced by the
// takeover warning, never silent); the HOSTED direction stays warn-only
// (removing a vendored ledger entry means deleting committed artifacts —
// `remove <purl>`'s job, on the operator's say-so).
//
// The overlap alone only proves BOTH ledgers name the same package(s) — NOT
// which one won. The takeover DIRECTION is decided by the ACTUAL current
// lockfile wiring for each overlapping package (see `classify_overlap_takeover`),
// never by which command happens to be running: a hosted dry-run/no-op over a
// lock that still points at the vendored files must not tell the user to delete
// the live vendored ledger (and vice-versa). Remediation always points at the
// ledger that does NOT match the live lock; a package the lock proves neither
// way stays silent.

/// Warning code emitted by the HOSTED flow when it just redirected package(s)
/// a committed vendored ledger still claims (its tarballs are now orphaned).
pub(super) const REDIRECT_SUPERSEDES_VENDORED: &str = "redirect_supersedes_vendored";

/// Warning code emitted by the VENDORED flow when it just vendored package(s)
/// a committed hosted redirect ledger still claims.
pub(super) const VENDOR_SUPERSEDES_REDIRECT: &str = "vendor_supersedes_redirect";

/// Warning code + detail emitted when `--prune` is combined with
/// `--mode hosted`: both hosted terminals return before the GC blocks, so
/// the flag would otherwise be silently dropped — a bot migrating its sync
/// job from `--mode agent --prune` to `--mode hosted --prune` would stop
/// pruning forever with exit 0 and no signal. `--prune` stays accepted
/// (CLI_CONTRACT.md: an orthogonal GC knob, never a usage error), but the
/// no-op must be explicit in both the JSON `warnings[]` and stderr.
pub(super) const REDIRECT_PRUNE_IGNORED: &str = "redirect_prune_ignored";
pub(super) const REDIRECT_PRUNE_IGNORED_DETAIL: &str =
    "--prune has no effect with --mode hosted: the hosted flow rewrites lockfiles only and \
     runs no GC sweep of `.socket/` state; run `scan --prune` (agent mode) or \
     `scan --mode vendored --prune` to garbage-collect";

/// The PURLs claimed by BOTH the hosted redirect ledger
/// (`.socket/vendor/redirect-state.json`) and the vendored state ledger
/// (`.socket/vendor/state.json`) in `cwd`, sorted. A non-empty result means
/// one mode has taken the lockfile over from the other for these package(s)
/// while the displaced mode's ledger stayed on disk — exactly one of the two
/// ledgers is stale for each PURL (a package's lockfile entry can point only
/// one way). Empty when either ledger is missing/empty/unreadable, or when the
/// two ledgers describe disjoint packages (a legitimate split: some redirected,
/// others vendored) — so there are no false positives.
pub(super) async fn overlapping_ledger_purls(cwd: &Path) -> Vec<String> {
    // A malformed redirect ledger classifies like a missing one here — this
    // path only feeds takeover WARNINGS, and the corruption itself is already
    // a hard error on every path that would write (`run_redirect`) or attest
    // (`vex`) from the ledger.
    let Ok(Some(redirect)) = socket_patch_core::patch::redirect::load_redirect_state(cwd).await
    else {
        return Vec::new();
    };
    let Ok(vendor) = socket_patch_core::vendor::load_state(cwd).await else {
        return Vec::new();
    };
    if vendor.entries.is_empty() {
        return Vec::new();
    }
    // Canonicalize both sides (drop qualifiers, percent-decode) so the API
    // purl form the redirect records carry matches the vendor entry's base
    // purl — mirrors `vendored_ledger_supplement`.
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let mut vendor_purls: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (key, entry) in &vendor.entries {
        vendor_purls.insert(canon(key));
        vendor_purls.insert(canon(&entry.base_purl));
    }
    if !redirect.records.is_empty() {
        let redirect_purls: std::collections::BTreeSet<String> =
            redirect.records.keys().map(|p| canon(p)).collect();
        return redirect_purls
            .intersection(&vendor_purls)
            .cloned()
            .collect();
    }
    // The records map can be EMPTY while the ledger still asserts stale lock
    // wiring: a run where every per-uuid record fetch failed persists its
    // edits with no records (`record_fetch_failed`). Deriving the redirect
    // side of the overlap from record keys alone would leave the takeover
    // machinery blind to exactly that degraded ledger, so fall back to
    // matching the vendored purls against the recorded edit keys — npm
    // `node_modules/<name>` (possibly nested), pnpm/yarn/cargo/uv
    // `<name>@<version>`, bun `<prefix>/<name>`, gem/composer/pypi bare
    // `<name>`. Name-level matching can over-claim across versions, but the
    // direction gate in `classify_overlap_takeover` still requires the live
    // lock to prove one side before anything is reported.
    if redirect.edits.is_empty() {
        return Vec::new();
    }
    vendor_purls
        .into_iter()
        .filter(|purl| {
            let Some((name, version)) = purl_name_version(purl) else {
                return false;
            };
            redirect
                .edits
                .iter()
                .filter_map(|e| e.key.as_deref())
                .any(|key| {
                    key == name
                        || key == format!("{name}@{version}")
                        || key.ends_with(&format!("/{name}"))
                })
        })
        .collect()
}

/// `pkg:<type>/<name>@<version>` → `(<name>, <version>)`; the name keeps any
/// namespace slashes (`@scope/pkg`, `vendor/pkg`). `None` when either part
/// is missing. Input is already canonicalized by the caller.
fn purl_name_version(purl: &str) -> Option<(&str, &str)> {
    let rest = strip_purl_qualifiers(purl).strip_prefix("pkg:")?;
    let (_, coord) = rest.split_once('/')?;
    let at = coord.rfind('@').filter(|&i| i > 0)?;
    Some((&coord[..at], &coord[at + 1..]))
}

/// The overlapping PURLs split by which mode the LIVE lockfile actually wires
/// them to right now — the truth source for takeover direction.
///
/// `redirect` holds the overlap PURLs the lock currently routes to the hosted
/// patch server (see [`hosted_wiring_live`] — proved by the record's patch
/// uuid on any host, not a hardcoded hostname): hosted genuinely won the
/// lockfile, so the
/// vendored ledger entry (and its now-orphaned tarball) is the stale one and
/// `redirect_supersedes_vendored` is truthful. `vendored` holds the PURLs the
/// lock currently routes to a committed `.socket/vendor/<eco>/<uuid>` artifact:
/// vendored won, the redirect ledger record is stale, and
/// `vendor_supersedes_redirect` is truthful.
///
/// A PURL the lock proves NEITHER way — a dry-run/no-op that did not rewire it,
/// a half-migrated lock naming both, or an ecosystem whose live spec we cannot
/// read — lands in neither bucket, so the caller stays SILENT instead of
/// guessing the direction from which command happened to run (the
/// takeover-direction bug: a hosted no-op pointing cleanup at the live vendored
/// ledger).
#[derive(Debug, Default, PartialEq)]
pub(super) struct OverlapTakeover {
    /// Overlap PURLs whose vendored ledger is stale (lock points hosted).
    pub redirect: Vec<String>,
    /// Overlap PURLs whose redirect ledger is stale (lock points vendored).
    pub vendored: Vec<String>,
}

pub(super) async fn classify_overlap_takeover(cwd: &Path) -> OverlapTakeover {
    let overlap = overlapping_ledger_purls(cwd).await;
    let mut out = OverlapTakeover::default();
    if overlap.is_empty() {
        return out;
    }
    // Re-load the vendored ledger to recover each overlapping entry's uuid +
    // the lockfiles it wired (revert reads the same set); `overlapping_ledger_purls`
    // already proved it loads and is non-empty.
    let Ok(vendor) = socket_patch_core::vendor::load_state(cwd).await else {
        return out;
    };
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let mut vendor_by_purl: std::collections::HashMap<
        String,
        &socket_patch_core::vendor::VendorEntry,
    > = std::collections::HashMap::new();
    for (key, entry) in &vendor.entries {
        vendor_by_purl.entry(canon(key)).or_insert(entry);
        vendor_by_purl
            .entry(canon(&entry.base_purl))
            .or_insert(entry);
    }
    // The hosted proof needs the redirect ledger too: each record's patch
    // uuid (embedded in every hosted artifact URL, whatever the host) and
    // the lockfiles the redirect actually edited. A malformed ledger
    // classifies like a missing one, matching `overlapping_ledger_purls`
    // (this path only feeds takeover warnings; corruption is a hard error
    // on the write/attest paths) — and that guard already returned empty
    // overlap for the corrupt case, so this consult never runs then.
    let redirect_state = socket_patch_core::patch::redirect::load_redirect_state(cwd)
        .await
        .ok()
        .flatten();
    let mut redirect_uuid_by_purl: std::collections::HashMap<String, &str> =
        std::collections::HashMap::new();
    let mut redirect_files: Vec<&str> = Vec::new();
    if let Some(redirect) = &redirect_state {
        for (key, record) in &redirect.records {
            redirect_uuid_by_purl
                .entry(canon(key))
                .or_insert(record.uuid.as_str());
        }
        redirect_files = redirect.edits.iter().map(|e| e.path.as_str()).collect();
        redirect_files.sort();
        redirect_files.dedup();
    }
    let inventory = socket_patch_core::vendor::lock_inventory::inventory_project(cwd).await;
    for purl in overlap {
        // Cargo needs its own probe: the scan inventory records `resolved:
        // None` for every cargo entry (a Cargo.lock `source` is an index URL,
        // not a tarball URL), so `hosted_wiring_live`'s inventory proof can
        // never fire for cargo — and the vendored substring scan alone then
        // INVERTS the direction after a hosted takeover (the
        // takeover-direction bug, cargo edition). The cargo classifier reads
        // the lock entry's actual shape instead — the lock is the truth
        // source both modes rewire, in mutually exclusive ways.
        let (hosted_live, vendored_live) = if purl.starts_with("pkg:cargo/") {
            classify_cargo_overlap(cwd, &purl, vendor_by_purl.get(&purl).copied()).await
        } else {
            let record_uuid = redirect_uuid_by_purl.get(&purl).copied();
            let hosted_live =
                hosted_wiring_live(cwd, &purl, record_uuid, &redirect_files, &inventory).await;
            let vendored_live = match vendor_by_purl.get(&purl) {
                Some(entry) => vendored_wiring_live(cwd, entry).await,
                None => false,
            };
            (hosted_live, vendored_live)
        };
        match (hosted_live, vendored_live) {
            (true, false) => out.redirect.push(purl),
            (false, true) => out.vendored.push(purl),
            // Both (a half-migrated lock naming both) or neither (no rewire /
            // unreadable) does not prove a single direction — stay silent.
            _ => {}
        }
    }
    out.redirect.sort();
    out.vendored.sort();
    out
}

/// Cargo takeover direction, proven from the `Cargo.lock` entry's shape —
/// the one file BOTH modes rewire, in mutually exclusive ways:
///
/// * `source` = a Socket hosted patch registry index (matched against the
///   config-declared `[registries.socket-patch-*]` URLs, plus the
///   `patch.socket.dev` host for configs that were already cleaned up) ⇒
///   hosted is live;
/// * entry DETACHED (no `source` — the vendored shape) with the
///   `[patch.crates-io]` entry pointing into this vendor entry's committed
///   `.socket/vendor/cargo/<uuid>/` copy ⇒ vendored is live;
/// * anything else (crates.io / other registry / entry or lock missing) ⇒
///   neither proven, stay silent.
async fn classify_cargo_overlap(
    cwd: &Path,
    purl: &str,
    entry: Option<&socket_patch_core::vendor::VendorEntry>,
) -> (bool, bool) {
    use socket_patch_core::vendor::{cargo_config, cargo_lock};
    let Some(rest) = purl.strip_prefix("pkg:cargo/") else {
        return (false, false);
    };
    let Some((name, version)) = rest.rsplit_once('@') else {
        return (false, false);
    };
    match cargo_lock::probe_lock_entry(cwd, name, version).await {
        cargo_lock::LockEntryProbe::Source(src) => {
            let hosted = src.contains("patch.socket.dev")
                || cargo_config::socket_registry_indexes(cwd)
                    .await
                    .iter()
                    .any(|(_, index)| *index == src);
            (hosted, false)
        }
        cargo_lock::LockEntryProbe::Detached => {
            let vendored = match entry {
                Some(entry) => {
                    match socket_patch_core::vendor::path::vendor_uuid_dir_rel(
                        &entry.ecosystem,
                        &entry.uuid,
                    ) {
                        Some(marker) => cargo_config::read_patch_entries(cwd)
                            .await
                            .get(name)
                            .and_then(|i| i.path.as_deref())
                            .is_some_and(|p| {
                                p.replace('\\', "/").starts_with(&format!("{marker}/"))
                            }),
                        None => false,
                    }
                }
                None => false,
            };
            (false, vendored)
        }
        _ => (false, false),
    }
}

/// Whether the LIVE lockfile provably wires `purl` to a HOSTED patch
/// artifact. Two proofs, tried in order:
///
/// 1. Inventory: the lock's `resolved` URL for this exact purl carries the
///    redirect record's patch uuid — every hosted artifact URL embeds it,
///    on ANY patch-server host (staging, self-hosted `--patch-server-url`
///    deployments), so this is not pinned to the default `patch.socket.dev`
///    hostname (kept only as a fallback for a ledger with no record).
/// 2. Text: the record's patch uuid appears in a lockfile the redirect
///    ledger recorded editing, OUTSIDE a committed `.socket/vendor/<eco>/`
///    path. This covers the flavors the inventory structurally cannot see —
///    yarn-berry (its inventory `resolved` is always `None`; the hosted URL
///    lives percent-encoded in the `::__archiveUrl=` binding) and bun (the
///    inventory skips the URL 3-tuples hosted mode writes). The vendored
///    wiring embeds the SAME uuid in its `.socket/vendor/<eco>/<uuid>/`
///    path, so a bare containment check would prove the wrong mode — only
///    non-vendored-path occurrences count.
///
/// No record uuid and no default-host inventory match ⇒ `false` (the caller
/// then stays silent rather than guess).
async fn hosted_wiring_live(
    cwd: &Path,
    purl: &str,
    record_uuid: Option<&str>,
    redirect_files: &[&str],
    inventory: &[socket_patch_core::vendor::lock_inventory::LockfileEntry],
) -> bool {
    if let Some(resolved) = socket_patch_core::vendor::lock_inventory::lookup(inventory, purl)
        .and_then(|e| e.resolved.as_deref())
    {
        if resolved.contains("patch.socket.dev")
            || record_uuid.is_some_and(|uuid| resolved.contains(uuid))
        {
            return true;
        }
    }
    let Some(uuid) = record_uuid else {
        return false;
    };
    let Some(eco) = strip_purl_qualifiers(purl)
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split_once('/'))
        .map(|(eco, _)| eco)
    else {
        return false;
    };
    let vendored_prefix = format!("vendor/{eco}/");
    for file in redirect_files {
        if !is_safe_project_rel_file(file) {
            continue;
        }
        let Ok(text) = tokio::fs::read_to_string(cwd.join(file)).await else {
            continue;
        };
        let mut search_from = 0;
        while let Some(pos) = text[search_from..].find(uuid) {
            let idx = search_from + pos;
            if !text[..idx].ends_with(&vendored_prefix) {
                return true;
            }
            search_from = idx + uuid.len();
        }
    }
    false
}

/// The ledgers are tamper-able: only ever READ a plain in-project relative
/// lockfile name recorded in them — never one that could climb out of `cwd`.
fn is_safe_project_rel_file(file: &str) -> bool {
    !(file.is_empty()
        || file.starts_with('/')
        || file.starts_with('\\')
        || file.split(['/', '\\']).any(|c| c == ".."))
}

/// Whether the LIVE lockfile still wires `entry` to its committed
/// `.socket/vendor/<eco>/<uuid>` artifact. Reads the lockfile(s) this entry
/// recorded editing (the same set `--revert` walks) and looks for that exact
/// vendored-path marker — the anchor `parse_vendor_path` recovers and the
/// vendor drift-guards match on. `None`/unreadable/absent ⇒ `false` (the
/// caller then stays silent rather than assume vendored is live).
async fn vendored_wiring_live(cwd: &Path, entry: &socket_patch_core::vendor::VendorEntry) -> bool {
    let Some(marker) =
        socket_patch_core::vendor::path::vendor_uuid_dir_rel(&entry.ecosystem, &entry.uuid)
    else {
        return false;
    };
    let mut files: Vec<&str> = entry.wiring.iter().map(|w| w.file.as_str()).collect();
    files.sort();
    files.dedup();
    for file in files {
        if !is_safe_project_rel_file(file) {
            continue;
        }
        if let Ok(text) = tokio::fs::read_to_string(cwd.join(file)).await {
            if text.contains(&marker) {
                return true;
            }
        }
    }
    false
}

/// Human-readable detail for a mode-takeover warning naming the displaced
/// package(s). `current_is_hosted` selects the direction: `true` when a
/// hosted redirect displaced a vendored ledger, `false` when a vendored run
/// displaced a hosted redirect ledger.
///
/// The warning fires PER PACKAGE (the direction is proved per purl by the
/// live lockfile), so the remediation must be per-package and non-destructive
/// too. It must never tell the user to delete a whole ledger file or a whole
/// `.socket/vendor/<eco>/` tree: both may still carry LIVE data for packages
/// this takeover did not touch — the redirect ledger holds other packages'
/// records (VEX reads them) plus the recorded pre-redirect lockfile originals
/// (the only revert data), and the `<eco>/` tree holds every vendored uuid
/// dir, including packages the hosted run skipped.
///
/// Per package also has to mean COMPLETE per package, or the remediation does
/// not converge:
///
/// * The vendored direction names the package's `edits` entry alongside its
///   `records` entry. `overlapping_ledger_purls` falls back to matching edit
///   KEYS once `records` is empty (the degraded-ledger blind spot), so a
///   records-only cleanup that happened to delete the last record left the
///   package still matching and this warning firing on every later run —
///   repeating advice the operator had already carried out.
/// * The hosted direction describes `socket-patch remove`'s full blast radius.
///   It deletes the package's `.socket/manifest.json` entry too, not just the
///   vendor ledger entry and artifact dir, and a reader who budgeted for a
///   ledger-only edit needs to know that before running it with `--yes`.
pub(super) fn mode_takeover_detail(superseded: &[String], current_is_hosted: bool) -> String {
    let list = superseded.join(", ");
    if current_is_hosted {
        // NEVER offer deleting the `.socket/vendor/<eco>/` tree here: for
        // cargo the leftover `[patch.crates-io]` entry still points at that
        // tree, and deleting it hard-fails every cargo invocation ("failed to
        // load source for dependency"). Nor `vendor --revert`, which unwinds
        // EVERY vendored package including the ones still live in the
        // lockfile — `remove <purl>` is the per-package equivalent.
        format!(
            "hosted redirect superseded the vendored ledger for: {list}. \
             `.socket/vendor/state.json` still claims these package(s) and their \
             committed artifacts under `.socket/vendor/` are now orphaned — the \
             lockfile points at the hosted patch server, not the vendored files. \
             Clean up per package: run `socket-patch remove <purl>` for each \
             package listed above, so audits and VEX do not read superseded \
             wiring. It drops that package's vendored ledger entry and its own \
             `.socket/vendor/<eco>/<uuid>/` artifact directory, AND deletes that \
             package's now-superseded `.socket/manifest.json` entry — that entry \
             describes the vendored delivery, while the live hosted patch is \
             recorded in `.socket/vendor/redirect-state.json`, which `remove` \
             never touches. In-place file rollback is skipped for vendor-owned \
             package(s), so the installed tree is left as the lockfile wires it; \
             preview with `--dry-run` first. Do not delete the whole \
             `.socket/vendor/<eco>/` tree and do not run `vendor --revert`: \
             other vendored package(s) may still be live in the lockfile and \
             would break or be mass-reverted."
        )
    } else {
        // NEVER advise deleting the redirect ledger by hand: it may hold the
        // only revert data (FileEdit originals) and VEX records for OTHER
        // packages that are still hosted-redirected. The vendored flows
        // reconcile per package — reverting the stale hosted edits and
        // dropping exactly the superseded ledger records.
        format!(
            "vendored artifacts superseded the hosted redirect ledger for: {list}. \
             `.socket/vendor/redirect-state.json` still records a hosted redirect for \
             these package(s), but the lockfile now points at the committed \
             `.socket/vendor/` files. The vendored flows (`socket-patch vendor`, \
             `scan --mode vendored`) reconcile npm-family and cargo package(s) \
             automatically on their next non-dry run, dropping both halves of \
             each superseded entry — the `records` entry AND its matching \
             `edits` (cargo additionally reverts the stale hosted edits on disk \
             first). For other package(s), or if the automatic reconciliation \
             could not run, clean up by hand: delete only these package(s)' \
             entries under `records` AND their matching entries under `edits`, \
             so audits and VEX do not read superseded wiring. \
             Both halves matter: the leftover `edits` are that package's stale \
             pre-redirect originals, which a later redirect revert would replay \
             over the live vendored wiring — and an `edits` entry left behind \
             still names the package, so a ledger whose last record you just \
             deleted keeps reading as superseded and this warning keeps firing. \
             Do not delete the ledger file itself: it may still hold live \
             redirect records for other package(s), plus the recorded \
             pre-redirect lockfile originals (`edits`) a future revert needs \
             for them."
        )
    }
}

/// Detail for the vendored-direction takeover warning on the run that
/// RECONCILED the ledger in place (non-dry-run, npm-family): past tense —
/// it states what was dropped and where the revert data now lives, so the
/// operator is told the takeover happened without being handed remediation
/// that is already done. The warning code stays `vendor_supersedes_redirect`
/// (envelope contract: codes are additive and stable; only the free-text
/// detail differs), and it fires exactly once — the reconciled ledger no
/// longer overlaps, so re-runs stay silent.
pub(super) fn mode_takeover_reconciled_detail(reconciled: &[String]) -> String {
    let list = reconciled.join(", ");
    format!(
        "vendored artifacts superseded the hosted redirect ledger for: {list}; \
         reconciled automatically. Both halves of each superseded entry — the \
         package's `records` entry AND its matching `edits` — were dropped \
         from `.socket/vendor/redirect-state.json` (an emptied ledger is \
         deleted). The lockfile points at the committed `.socket/vendor/` \
         files, and the pre-vendor lock values (including the hosted-spliced \
         fragment) are preserved as the vendor ledger's wiring originals, so \
         `vendor --revert` still restores the hosted wiring losslessly. \
         Ledger data for other, still-redirected package(s) was left \
         untouched. No action needed."
    )
}

/// Drop the superseded purls' `records` + `edits` from the redirect ledger
/// and persist it (atomic write; an emptied ledger is deleted — the same
/// delete-when-empty contract every other persist follows). Called ONLY with
/// purls [`classify_overlap_takeover`] proved vendored-live AND hosted-dead
/// against the LIVE lockfile: the gate that makes the warning truthful is
/// the one that makes the drop lossless (the vendor ledger's wiring
/// `original` embeds the hosted-spliced fragment, so `vendor --revert` needs
/// nothing from these records). `Ok(false)` when nothing matched (degenerate
/// — the caller falls back to the manual advisory rather than claiming a
/// reconciliation that did not happen); `Err` when the ledger could not be
/// read back or persisted (fail closed: the atomic writer leaves the on-disk
/// ledger either untouched or fully pre-drop, and the caller surfaces the
/// failure inside the warning).
async fn reconcile_superseded_redirect(cwd: &Path, purls: &[String]) -> Result<bool, String> {
    let mut state = match socket_patch_core::patch::redirect::load_redirect_state(cwd).await {
        Ok(Some(state)) => state,
        Ok(None) => return Ok(false),
        Err(corrupt) => return Err(corrupt.to_string()),
    };
    let mut dropped = false;
    for purl in purls {
        dropped |= socket_patch_core::patch::redirect::drop_superseded_purl(&mut state, purl);
    }
    if !dropped {
        return Ok(false);
    }
    socket_patch_core::patch::redirect::persist_redirect_state(cwd, &state)
        .await
        .map_err(|e| e.to_string())?;
    Ok(true)
}

/// Cross-mode takeover advisory shared by every VENDORED flow (`vendor`,
/// `scan --mode vendored`): when this ledger and a committed hosted redirect
/// ledger both claim package(s) AND the live lockfile proves vendored won,
/// the redirect ledger records for those package(s) are stale. Warn once at
/// the envelope level (JSON `warnings[]` and stderr) — and, for npm-family
/// package(s) on a non-dry run, reconcile the ledger in place at the same
/// time (mirroring the cargo branch in `vendor.rs`, which reverts + drops
/// BEFORE vendoring because `[patch.crates-io]` cannot stack on the hosted
/// registry pin; npm-family needs no on-disk revert — vendoring already
/// overwrote the hosted splice and recorded it as the wiring `original`).
/// Without the drop, the stale records fed VEX/updates forever and this
/// warning re-fired on every subsequent run (`already_vendored` no-ops drop
/// nothing). The reverse direction (`redirect_supersedes_vendored`) is
/// deliberately untouched.
pub(super) async fn note_vendor_supersedes_redirect(
    env: &mut crate::json_envelope::Envelope,
    cwd: &Path,
    common: &GlobalArgs,
) {
    // Only warn for the package(s) the LIVE lockfile actually routes to the
    // committed `.socket/vendor/` files — the direction the lock proves, not
    // the fact that this happens to be a vendored flow. A dry-run / no-op
    // over a lock that still points at the hosted patch server stays silent
    // instead of pointing cleanup at the live redirect ledger.
    let superseded = classify_overlap_takeover(cwd).await.vendored;
    if superseded.is_empty() {
        return;
    }
    fn push_warning(env: &mut crate::json_envelope::Envelope, common: &GlobalArgs, detail: String) {
        if !common.silent && !common.json {
            eprintln!("Warning ({VENDOR_SUPERSEDES_REDIRECT}): {detail}");
        }
        env.warnings.push(crate::json_envelope::RunWarning {
            code: VENDOR_SUPERSEDES_REDIRECT.to_string(),
            detail,
        });
    }
    // Reconciliation is gated three ways, each fail-closed to the manual
    // advisory: never under --dry-run (this advisory runs even on preview
    // flows, and a dry run must not mutate the ledger); only npm-family
    // purls (cargo goes through `revert_cargo_redirect_purl`'s on-disk
    // revert in vendor.rs, and other ecosystems' vendor wiring has not been
    // verified to embed the hosted originals); and only purls the live-lock
    // classification above already proved no longer resolve the hosted URL.
    let (reconcilable, manual): (Vec<String>, Vec<String>) = if common.dry_run {
        (Vec::new(), superseded)
    } else {
        superseded
            .into_iter()
            .partition(|purl| purl.starts_with("pkg:npm/"))
    };
    if !manual.is_empty() {
        push_warning(
            env,
            common,
            mode_takeover_detail(&manual, /*current_is_hosted=*/ false),
        );
    }
    if reconcilable.is_empty() {
        return;
    }
    match reconcile_superseded_redirect(cwd, &reconcilable).await {
        Ok(true) => push_warning(env, common, mode_takeover_reconciled_detail(&reconcilable)),
        // Nothing matched to drop — do not claim a reconciliation that did
        // not happen; hand out the manual remediation instead.
        Ok(false) => push_warning(
            env,
            common,
            mode_takeover_detail(&reconcilable, /*current_is_hosted=*/ false),
        ),
        Err(e) => push_warning(
            env,
            common,
            format!(
                "{} Automatic reconciliation failed ({e}); the ledger was left \
                 as it was, so this warning will fire again until the cleanup \
                 above succeeds.",
                mode_takeover_detail(&reconcilable, /*current_is_hosted=*/ false)
            ),
        ),
    }
}

/// Top-level `warnings[]` JSON for scan's envelope from `(code, detail)`
/// pairs (see [`unsupported_layout_warnings`]). Same `{code, detail}` object
/// shape as the run-level `warnings[]` on the unified envelope.
fn layout_refusal_json(refusals: &[(String, String)]) -> serde_json::Value {
    serde_json::Value::Array(
        refusals
            .iter()
            .map(|(code, detail)| serde_json::json!({ "code": code, "detail": detail }))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Agent-flow cross-mode visibility (hosted / vendored state left in place)
// ---------------------------------------------------------------------------
//
// The takeover machinery above covers hosted ⇄ vendored — the two modes that
// COMPETE for lockfile wiring. The agent flow competes with neither (it
// patches installed trees in place), so running `scan --mode agent` over
// another mode's live state is not a takeover: nothing goes stale, nothing
// is mutated. But it IS a mode conversion that silently did not complete,
// and the envelope said nothing:
//
// * over live HOSTED wiring, the agent apply succeeds against the already-
//   patched bytes while the lockfile keeps resolving to the hosted patch
//   server and the redirect ledger stays live — and no npm/yarn hosted
//   revert exists, so the "conversion" can never complete without another
//   mode run;
// * over VENDORED ownership, the apply partitions the vendor-owned purls
//   into `apply.patches[]` skip records (`skipped`/`vendored`) that a
//   `--json` consumer only finds by digging into the per-patch array.
//
// Both get one additive run-level warning (top-level `warnings[]` on the
// scan `--json` envelope + stderr when not silent). NEVER a status or
// exit-code change — hosted refusals set that precedent (exit 0 + warning).

/// Warning code: agent-mode scan ran over package(s) whose hosted redirect
/// wiring is still LIVE (ledger record present AND the lock provably still
/// routes the purl to the hosted artifact).
pub(super) const HOSTED_WIRING_RETAINED: &str = "hosted_wiring_retained";

/// Warning code: agent-mode apply yielded ownership of vendor-owned
/// package(s) (the per-patch `skipped`/`vendored` records), so those
/// package(s) did NOT convert to agent mode.
pub(super) const VENDORED_OWNERSHIP_RETAINED: &str = "vendored_ownership_retained";

/// The scanned purls whose HOSTED redirect wiring is still live: the
/// redirect ledger records the purl AND [`hosted_wiring_live`] proves the
/// current lockfile still routes it to the hosted artifact.
///
/// Deliberately NOT routed through [`classify_overlap_takeover`]: that
/// classifier keys on purls present in BOTH ledgers (hosted ∩ vendored),
/// so hosted-only wiring — the exact hosted→agent conversion state — can
/// structurally never trigger it (pinned by
/// `hosted_only_wiring_is_invisible_to_the_overlap_classifier`).
///
/// Silent-by-construction cases (each pinned by a test):
/// * ledger absent/malformed or `records` empty — a hosted→vendored
///   pre-revert that retired the records must retire this warning with
///   them, even while the append-only `edits` (revert originals) remain;
/// * purl not scanned this run — the warning only ever names packages the
///   scan actually covered;
/// * the live lock does not prove hosted wiring (registry-clean lock, an
///   ecosystem whose lock we cannot read) — never guess from ledger
///   presence alone.
pub(super) async fn hosted_wiring_retained_purls(
    cwd: &Path,
    redirect_state: Option<&socket_patch_core::patch::redirect::RedirectState>,
    scanned_purls: &HashSet<String>,
) -> Vec<String> {
    let Some(redirect) = redirect_state else {
        return Vec::new();
    };
    if redirect.records.is_empty() {
        return Vec::new();
    }
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let scanned: std::collections::BTreeSet<String> =
        scanned_purls.iter().map(|p| canon(p)).collect();
    // Cheap no-I/O gate: only ledger records naming a scanned purl can ever
    // prove live wiring, so when none do (a zero/filtered discovery, or a
    // ledger about other packages) skip the lockfile inventory below — a
    // full multi-file lock parse — entirely.
    let candidates: Vec<(String, &str)> = redirect
        .records
        .iter()
        .map(|(key, record)| (canon(key), record.uuid.as_str()))
        .filter(|(purl, _)| scanned.contains(purl))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut redirect_files: Vec<&str> = redirect.edits.iter().map(|e| e.path.as_str()).collect();
    redirect_files.sort();
    redirect_files.dedup();
    let inventory = socket_patch_core::vendor::lock_inventory::inventory_project(cwd).await;
    let mut out = Vec::new();
    for (purl, uuid) in candidates {
        if hosted_wiring_live(cwd, &purl, Some(uuid), &redirect_files, &inventory).await {
            out.push(purl);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Detail for [`HOSTED_WIRING_RETAINED`]. Names the package(s) and the two
/// real options — stay hosted, or migrate via the vendored flow (which
/// reconciles the superseded ledger entries per package). It must never
/// advise hand-deleting the redirect ledger (the only store of the
/// pre-redirect originals plus the records VEX reads) and never promise a
/// hosted→agent unwind that does not exist for npm/yarn.
pub(super) fn hosted_wiring_retained_detail(retained: &[String]) -> String {
    let list = retained.join(", ");
    format!(
        "agent-mode scan left the hosted redirect wiring live for: {list}. \
         The lockfile still resolves these package(s) to the hosted patch \
         server and `.socket/vendor/redirect-state.json` still records the \
         redirect — an agent run patches installed files in place but does \
         NOT unwind hosted lockfile wiring (no hosted revert exists for \
         this ecosystem yet), so installs keep fetching these package(s) \
         from the patch server. Either keep the project in hosted mode \
         (`scan --mode hosted`), or migrate to committed artifacts with \
         `scan --mode vendored`, which takes these package(s) over in the \
         lockfile and reconciles the superseded redirect ledger entries. \
         Do not delete `.socket/vendor/redirect-state.json` by hand: it \
         holds the recorded pre-redirect lockfile originals (the only \
         revert data) and the redirect records VEX reads."
    )
}

/// Detail for [`VENDORED_OWNERSHIP_RETAINED`]. Names the vendor-owned
/// package(s) the agent apply skipped and the real migration path —
/// per-package `remove <purl>` first (with `vendor --revert` named but
/// scoped: it unwinds EVERY vendored package), then re-run.
pub(super) fn vendored_ownership_retained_detail(purls: &[String]) -> String {
    let list = purls
        .iter()
        .map(|p| normalize_purl(p).into_owned())
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "agent-mode apply did not take over vendor-owned package(s): {list}. \
         These package(s) are managed by `socket-patch vendor` (committed \
         `.socket/vendor/` artifacts own their lockfile wiring), so they \
         were skipped before download — recorded in `apply.patches[]` as \
         `skipped`/`vendored` — and stay in vendored mode. To keep them \
         vendored, no action is needed. To migrate a package to agent \
         mode, first retire its vendored wiring: run `socket-patch remove \
         <purl>` for that package (or `socket-patch vendor --revert`, \
         which unwinds EVERY vendored package), then re-run `scan --mode \
         agent`."
    )
}

/// Additive top-level `redirectState` block for the scan `--json` envelope:
/// the hosted redirect ledger's records — project STATE, so a descriptive
/// block rather than a warning — plus the scanned purls whose hosted
/// lockfile wiring the live lock still proves.
///
/// Before this block, a hosted-wired project's report-only `scan --json`
/// was byte-identical to a never-touched project's (verified against
/// production on bundler 1.17/2.7/4.0): [`HOSTED_WIRING_RETAINED`] rides
/// only the agent-mode envelope, and the `redirect` sub-object only a
/// hosted-mode run's. `None` (key omitted, additive contract) when the
/// ledger is absent or its `records` are empty — an edits-only ledger
/// (post-takeover / degraded) asserts no patches, mirroring the warning's
/// records gate. This emptiness check is the block's ONE presence
/// decision; the caller precomputes `wiring_live` (see below) whose own
/// probe guards its inputs independently for its other callers.
///
/// Shape: `{ mode, ledger, records: [{purl, ledgerKey, uuid}], wiringLive:
/// [purl] }`. `mode` is the constant [`crate::commands::HOSTED_MODE_LABEL`]
/// — never the ledger's own opaque `mode` string (pre-rename ledgers carry
/// `"redirect"`; consumers dispatching on this key must not need that
/// history). Each record's `purl` is CANONICALIZED (qualifiers stripped,
/// percent-decoded) to the same spelling `wiringLive` carries, so the
/// records↔proof join is a plain string compare; `ledgerKey` is the
/// ledger's verbatim key (percent-encoded scoped names, `?platform=`
/// qualifiers) for consumers that need to address the ledger itself.
/// `wiring_live` is the caller's [`hosted_wiring_retained_purls`] result —
/// computed ONCE per run (it parses the project's lockfiles) and shared
/// with the agent-flow warning. Records are the ledger's word, wiringLive
/// the live lock's proof: a record with no proof means the wiring was
/// unwound, the lock is unreadable, or the purl was not crawled/queried
/// this run — never "still live".
pub(super) fn redirect_state_json(
    redirect_state: Option<&socket_patch_core::patch::redirect::RedirectState>,
    wiring_live: &[String],
) -> Option<serde_json::Value> {
    let redirect = redirect_state?;
    if redirect.records.is_empty() {
        return None;
    }
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let records: Vec<serde_json::Value> = redirect
        .records
        .iter()
        .map(|(key, record)| {
            serde_json::json!({
                "purl": canon(key),
                "ledgerKey": key,
                "uuid": record.uuid,
            })
        })
        .collect();
    Some(serde_json::json!({
        "mode": crate::commands::HOSTED_MODE_LABEL,
        "ledger": socket_patch_core::patch::redirect::REDIRECT_STATE_REL,
        "records": records,
        "wiringLive": wiring_live,
    }))
}

/// Append one `{code, detail}` entry to the scan `--json` result's
/// top-level `warnings` array (created on first use — the key is additive
/// and absent when no run-level warning fired), mirroring the
/// [`crate::json_envelope::RunWarning`] wire shape.
fn push_scan_json_warning(result: &mut serde_json::Value, code: &str, detail: &str) {
    let warnings = result
        .as_object_mut()
        .expect("scan JSON result is an object")
        .entry("warnings")
        .or_insert_with(|| serde_json::json!([]));
    if let Some(arr) = warnings.as_array_mut() {
        arr.push(serde_json::json!({ "code": code, "detail": detail }));
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

    // Strict airgap (CLI_CONTRACT.md `--offline`: never contact the
    // network; operations that need remote data fail loudly). Scan's
    // patch discovery IS remote data — proceeding would POST the crawled
    // package inventory to the batch endpoint — so refuse up front,
    // before the crawl and before the API client is built (org
    // auto-resolve is itself a network call). No telemetry fires here:
    // offline gates `is_telemetry_disabled` too.
    if args.common.offline {
        let err = "scan requires network access to query the patch API and cannot run with \
                   --offline/SOCKET_OFFLINE (strict airgap)";
        if args.common.json {
            // Mirror the all-batches-failed error envelope shape so JSON
            // consumers see one consistent scan-error schema.
            let result = serde_json::json!({
                "status": "error",
                "error": err,
                "scannedPackages": 0,
                "packagesWithPatches": 0,
                "totalPatches": 0,
                "freePatches": 0,
                "paidPatches": 0,
                "canAccessPaidPatches": false,
                "packages": [],
                "updates": [],
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .expect("serializing an in-memory JSON value cannot fail")
            );
        } else {
            eprintln!("Error: {err}");
        }
        return 1;
    }

    // `--sync` is sugar for `--mode agent --prune`. Derive locals once and
    // use them everywhere downstream so the flag interactions are
    // expressed in one place. `--apply --prune --sync` is redundant
    // but legal.
    let apply = args.mode == Some(ScanMode::Agent);
    let vendor = args.mode == Some(ScanMode::Vendored);
    let hosted = args.mode == Some(ScanMode::Hosted);
    let prune = args.prune || args.sync;

    // Hosted mode runs no GC (both hosted terminals return before the GC
    // blocks): say so ONCE up front on the human path instead of silently
    // dropping the flag. The `--json` path carries the same warning in the
    // `redirect.warnings[]` array (see `run_redirect` and the zero-discovery
    // envelope below).
    if hosted && prune && !args.common.json && !args.common.silent {
        eprintln!("Warning ({REDIRECT_PRUNE_IGNORED}): {REDIRECT_PRUNE_IGNORED_DETAIL}");
    }

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
    let socket_dir = manifest_path
        .parent()
        .expect("manifest path names a file, so it has a parent")
        .to_path_buf();

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
    let show_progress = !args.common.json && !args.common.silent && std::io::stderr().is_terminal();

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
    // Explicit refusals for npm layouts whose packages are structurally
    // unreachable (yarn PnP, pnpm node-linker=pnp). Under yarn PnP the
    // crawler leg above is ALSO empty (no `node_modules/`), so without this
    // channel every mode used to print a clean success with
    // `scannedPackages: 0` — a silent no-op the user read as "protected".
    // Surfaced as run-level `warnings[]` in the JSON envelope (omitted when
    // empty) and a stderr line on the human path; exit code and `status`
    // stay deliberately unchanged (same posture as hosted refusals, which
    // exit 0 with `redirected: 0`).
    let layout_refusals = unsupported_layout_warnings(&lockfile_only.unsupported);
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
    let vendored_purls = socket_patch_core::vendor::vendored_purl_keys(&args.common.cwd).await;

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
        if !args.common.json && !args.common.silent {
            for (code, detail) in &layout_refusals {
                eprintln!("Warning ({code}): {detail}");
            }
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
            // PnP layout refusals: additive top-level `warnings` (omitted
            // when empty — run-level warnings precedent) so a JSON consumer
            // can tell "structurally unscannable project" apart from a
            // genuinely-empty one. This is the loud half of the fix for the
            // yarn-PnP silent success-0 no-op.
            if !layout_refusals.is_empty() {
                result["warnings"] = layout_refusal_json(&layout_refusals);
            }
            // Hosted mode: keep the `--json` envelope schema-consistent with
            // the ≥1-package path by including a (no-op) nested `redirect`
            // block — nothing was discovered, so nothing is redirected. The
            // prune-ignored warning still rides along: hosted runs no GC even
            // when the crawl is empty.
            if hosted {
                let mut warnings: Vec<serde_json::Value> = Vec::new();
                if prune {
                    warnings.push(serde_json::json!({
                        "code": REDIRECT_PRUNE_IGNORED,
                        "detail": REDIRECT_PRUNE_IGNORED_DETAIL,
                    }));
                }
                result["redirect"] = serde_json::json!({
                    "mode": "hosted",
                    "redirected": 0,
                    "rewrittenFiles": [],
                    "skipped": [],
                    "warnings": warnings,
                    "dryRun": args.common.dry_run,
                });
            } else if !vendor {
                // The `redirectState` block rides the empty-discovery
                // envelope too (same rule as the ≥1-package path below:
                // every non-hosted-mode, non-vendored-mode `--json` envelope
                // carries it when the ledger holds records) — an
                // `--ecosystems` filter or a wiped tree must not blind a
                // state-probing consumer. The vendored gate mirrors the
                // main path's: vendored runs may reconcile ledger records
                // mid-run, so they never carry a pre-run snapshot. The
                // ledger is loaded here (leniently, --silent-gated) because
                // the main-path load sits after this early return.
                // `wiringLive` is empty by construction: this run counted
                // zero packages, and the block's contract scopes the proof
                // to packages the run actually covered.
                let redirect_state = crate::commands::load_redirect_state_lenient(
                    &args.common.cwd,
                    args.common.silent,
                )
                .await;
                if let Some(state) = redirect_state_json(redirect_state.as_ref(), &[]) {
                    result["redirectState"] = state;
                }
            }
            let code =
                embed_vex_into_json(&args.common, &args.vex, &manifest_path, 0, &mut result).await;
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .expect("serializing an in-memory JSON value cannot fail")
            );
            return code;
        } else if args.common.silent {
            // Errors only: the empty-scan hint is informational.
        } else if args.common.global || args.common.global_prefix.is_some() {
            println!("No global packages found.");
        } else {
            #[allow(unused_mut)]
            let mut install_cmds = String::from("npm/yarn/pnpm/pip");
            install_cmds.push_str("/cargo");
            install_cmds.push_str("/go");
            install_cmds.push_str("/mvn");
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
        // Polyglot PnP repos (e.g. a PnP frontend + a python venv) reach
        // this non-empty path: the refusal still prints so the invisible
        // npm half is never silently blessed by the other ecosystems' scan.
        for (code, detail) in &layout_refusals {
            eprintln!("Warning ({code}): {detail}");
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

    // The client returns each batch's packages PURL-sorted, but the batches
    // themselves are concatenated in chunk order, so the assembled list is
    // only sorted *within* each chunk. Sort globally: this list drives the
    // human table, the `--json` `packages` array, and the apply order, all
    // of which operators diff across runs.
    all_packages_with_patches.sort_by(|a, b| a.purl.cmp(&b.purl));

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
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .expect("serializing an in-memory JSON value cannot fail")
            );
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

    // Registry-redirect (hosted) mode is a distinct, self-contained flow
    // (rewrite lockfiles → hosted vendored patches). It reuses discovery
    // above, then returns — it must NOT fall through to the apply/vendor
    // branches. The HUMAN path returns here; the `--json` path returns from
    // inside the JSON block below (after building the classic scan object)
    // so the redirect result can be NESTED under a `redirect` key — keeping
    // the hosted `--json` envelope schema-consistent with the zero-discovery
    // and non-hosted paths (mirroring vendored mode's nested `vendor` block)
    // rather than replacing the whole envelope with a bare `{status, redirect}`.
    if hosted && !args.common.json {
        return run_redirect(
            &args,
            &api_client,
            effective_org_slug,
            &all_packages_with_patches,
            can_access_paid_patches,
            None,
        )
        .await;
    }

    // Read existing manifest once for update detection. Used by both the
    // JSON-mode emission (always includes an `updates` array) and the
    // non-JSON table-print path (counts `updates_available`).
    // (`manifest_path`/`socket_dir` are resolved at the top of `run`.)
    let existing_manifest = read_manifest(&manifest_path).await.ok().flatten();
    // Hosted mode records its patches ONLY in the redirect ledger (it never
    // writes the manifest), so fold the ledger's purl→uuid records into the
    // view update detection sees — otherwise a pure hosted project's
    // `updates[]` (the documented CI signal) stays structurally empty and a
    // superseding patch is never reported. The envelope schema is unchanged.
    // A malformed ledger is only warned about here (and muted by --silent —
    // the warning is advisory) — this is a read-only consult, and the hosted
    // write path hard-errors on it.
    let redirect_state =
        crate::commands::load_redirect_state_lenient(&args.common.cwd, args.common.silent).await;
    let update_manifest =
        merge_redirect_records_for_updates(existing_manifest.clone(), redirect_state.as_ref());
    let updates = detect_updates(update_manifest.as_ref(), &all_packages_with_patches);

    // Post-filter scanned set for the hosted-wiring probes: `wiringLive` and
    // the agent-flow `hosted_wiring_retained` warning only ever name
    // packages this run actually counted/queried (an `--ecosystems` filter
    // narrows both — a filtered-out purl reads as "not covered this run",
    // never as "wiring unwound"). Distinct from `scanned_purls` above, which
    // deliberately stays PRE-filter for the GC prune (see its comment).
    let wiring_scanned: HashSet<String> = all_purls.iter().cloned().collect();

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
        // PnP layout refusals ride the non-empty envelope too (polyglot
        // repos: the OTHER ecosystems' discovery being non-empty must not
        // silently bless the structurally-invisible npm half). Additive,
        // omitted when empty.
        if !layout_refusals.is_empty() {
            result["warnings"] = layout_refusal_json(&layout_refusals);
        }
        // Flag lockfile-only packages so JSON consumers can tell "patch
        // available but not installed" from the installed case. Additive
        // field; absent means installed. Matching bridges the API's
        // percent-encoded purl spelling to the supplement's literal form
        // via `normalize_purl`, like the apply-path skip partitions.
        if let Some(packages) = result["packages"].as_array_mut() {
            for pkg in packages {
                let is_lockfile_only = pkg["purl"].as_str().is_some_and(|p| {
                    lockfile_only
                        .purls
                        .contains(normalize_purl(strip_purl_qualifiers(p)).as_ref())
                });
                if is_lockfile_only {
                    pkg["notInstalled"] = serde_json::json!(true);
                }
            }
        }

        // Hosted mode: NEST the redirect result under `redirect` in the classic
        // scan object just built above (mirrors vendored mode's nested `vendor`
        // block), so the hosted `--json` envelope carries the same top-level
        // scan keys and `packages` enumeration as every other scan plus the
        // redirect summary. Returns before the apply/vendor/prune branches,
        // which are mutually exclusive with hosted mode.
        if hosted {
            return run_redirect(
                &args,
                &api_client,
                effective_org_slug,
                &all_packages_with_patches,
                can_access_paid_patches,
                Some(result),
            )
            .await;
        }

        // Cross-mode visibility, read-only half (companion to the run-level
        // warnings below): the hosted redirect ledger's records ride every
        // report-only and agent `--json` envelope as the additive
        // `redirectState` block. Hosted mode is excluded above (its nested
        // `redirect` block reports this run's own result, and `run_redirect`
        // re-persists the ledger mid-run, so a pre-run snapshot would go
        // stale); the vendored path below is excluded for the same staleness
        // reason (its takeover reconciliation may retire ledger records
        // mid-run — the `vendor_supersedes_redirect` warning covers it).
        //
        // The live-wiring probe (a full lockfile-inventory parse behind its
        // cheap no-I/O gate) runs ONCE here and is shared with the agent-flow
        // warning in the apply branch below.
        let hosted_retained = if vendor {
            Vec::new()
        } else {
            hosted_wiring_retained_purls(&args.common.cwd, redirect_state.as_ref(), &wiring_scanned)
                .await
        };
        if !vendor {
            if let Some(state) = redirect_state_json(redirect_state.as_ref(), &hosted_retained) {
                result["redirectState"] = state;
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
                Err((code, message)) => {
                    emit_discovery_error_json(&mut result, &message);
                    return code;
                }
            };

            // Vendor-owned purls are skipped BEFORE download (any uuid);
            // a newer patch still surfaces in `updates[]` — the
            // operator's signal to run `scan --vendor` (or `vendor`).
            let (selected, vendored_records) = partition_skipped_selected(
                selected,
                |p| vendored_purls.contains(p) || vendored_purls.contains(strip_purl_qualifiers(p)),
                "vendored",
            );
            // Captured from the vendored partition ONLY (before the
            // not-installed skips merge in below — those are a different,
            // already-calm class): feeds the run-level
            // `vendored_ownership_retained` warning emitted after apply.
            let vendored_skip_purls: Vec<String> = vendored_records
                .iter()
                .filter_map(|r| r["purl"].as_str().map(str::to_string))
                .collect();
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

            // Cross-mode visibility (additive run-level warnings; never a
            // status or exit-code change — see the constants' docs):
            //
            // * vendor-owned purls were partitioned out above — surface
            //   them at the envelope level instead of only deep inside
            //   `apply.patches[]`;
            // * hosted redirect wiring the live lock still proves — the
            //   agent run cannot unwind it, so silence here reads as a
            //   completed conversion that never happened.
            if !vendored_skip_purls.is_empty() {
                let detail = vendored_ownership_retained_detail(&vendored_skip_purls);
                if !args.common.silent {
                    eprintln!("Warning ({VENDORED_OWNERSHIP_RETAINED}): {detail}");
                }
                push_scan_json_warning(&mut result, VENDORED_OWNERSHIP_RETAINED, &detail);
            }
            // `hosted_retained` was computed once above (shared with the
            // `redirectState` block) — same probe, same post-filter scanned
            // set, no second lockfile-inventory parse.
            if !hosted_retained.is_empty() {
                let detail = hosted_wiring_retained_detail(&hosted_retained);
                if !args.common.silent {
                    eprintln!("Warning ({HOSTED_WIRING_RETAINED}): {detail}");
                }
                push_scan_json_warning(&mut result, HOSTED_WIRING_RETAINED, &detail);
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
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .expect("serializing an in-memory JSON value cannot fail")
        );
        return final_code;
    }

    let use_color = std::io::stdout().is_terminal();

    if all_packages_with_patches.is_empty() {
        if !args.common.silent {
            println!("\nNo patches available for installed packages.");
        }
        // Vendored mode still has work to do on an empty discovery: the
        // committed manifest is re-vendored wholesale, which is how a
        // fresh clone (or a wiped `.socket/vendor/`) gets its artifacts
        // back. The JSON arm states this outright — "the vendor step
        // still runs when zero patches were downloaded (re-vendor after a
        // wipe)" — and `selected.is_empty() && !vendor` below encodes the
        // same rule; without this the interactive arm never reaches it.
        if !vendor {
            return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
        }
    }

    // The whole table + summary section is presentational only (nothing
    // computed inside is consumed downstream), so `--silent` skips it
    // wholesale — as does an empty discovery, which vendored mode now
    // falls through with (an all-header, no-row table plus a "0 package(s)"
    // summary is noise, not information).
    if !args.common.silent && !all_packages_with_patches.is_empty() {
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
            // `normalize_purl` bridges the API's percent-encoded spelling
            // to the supplement's literal form, like the JSON flag and the
            // apply-path skip partitions.
            let not_installed_marker = if lockfile_only
                .purls
                .contains(normalize_purl(strip_purl_qualifiers(&pkg.purl)).as_ref())
            {
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
        // The paid-plan nudge only makes sense when the API DID return
        // patches; with an empty discovery (vendored mode falls through
        // the guard above) there is no gated catalog to point at.
        if !args.common.silent && !all_packages_with_patches.is_empty() {
            println!("\nNo downloadable patches (paid subscription required).");
        }
        // Same reason as above: vendored mode re-vendors the committed
        // manifest regardless of what discovery turned up.
        if !vendor {
            return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
        }
    }

    // Fetch full PatchSearchResult for each package that has patches
    if show_progress && !all_packages_with_patches.is_empty() {
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

    if show_progress && !all_packages_with_patches.is_empty() {
        eprintln!();
    }

    // Empty details are a failure only when there WERE packages to fetch
    // details for. Vendored mode now reaches here with nothing discovered
    // (see the two guards above) and must fall through to the vendor step
    // rather than report a fetch failure that never happened.
    if all_search_results.is_empty() && !all_packages_with_patches.is_empty() {
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

    // Cross-mode visibility, mirroring the JSON apply path: after an
    // in-place apply, warn when the hosted redirect wiring is still live
    // for scanned package(s) — the apply cannot unwind it, and silence
    // reads as a completed hosted→agent conversion that never happened.
    // (The vendored-ownership counterpart is already printed per package
    // by the `[skip] … (vendored …)` lines above.)
    if !vendor && !args.common.silent {
        let hosted_retained = hosted_wiring_retained_purls(
            &args.common.cwd,
            redirect_state.as_ref(),
            &wiring_scanned,
        )
        .await;
        if !hosted_retained.is_empty() {
            eprintln!(
                "Warning ({HOSTED_WIRING_RETAINED}): {}",
                hosted_wiring_retained_detail(&hosted_retained)
            );
        }
    }

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
                socket_patch_core::manifest::cleanup_blobs::format_bytes(gc.total_bytes()),
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

    // ---- cross-mode ledger takeover (hosted ⇄ vendored) --------------------
    // Switching a project's patch mode rewires the lockfile to the new mode
    // but leaves the OLD mode's ledger on disk asserting stale wiring. These
    // pin the detection + warning that flags it (the sweep's
    // stale-ledger-on-mode-takeover finding).

    const TAKEOVER_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn takeover_record() -> PatchRecord {
        PatchRecord {
            uuid: TAKEOVER_UUID.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    /// Write a hosted redirect ledger (`.socket/vendor/redirect-state.json`)
    /// recording a redirect for each PURL.
    async fn write_redirect_ledger(root: &Path, purls: &[&str]) {
        use socket_patch_core::patch::redirect::RedirectState;
        let mut state = RedirectState::new();
        for purl in purls {
            state.records.insert((*purl).to_string(), takeover_record());
        }
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();
    }

    /// Write a vendored state ledger (`.socket/vendor/state.json`) with one
    /// entry per PURL, in the committed camelCase wire shape.
    async fn write_vendor_ledger(root: &Path, purls: &[&str]) {
        let entries: serde_json::Map<String, serde_json::Value> = purls
            .iter()
            .map(|purl| {
                (
                    (*purl).to_string(),
                    serde_json::json!({
                        "ecosystem": "npm",
                        "basePurl": purl,
                        "uuid": TAKEOVER_UUID,
                        "artifact": {
                            "path": format!(".socket/vendor/npm/{TAKEOVER_UUID}/pkg.tgz"),
                        },
                        "wiring": [],
                    }),
                )
            })
            .collect();
        let state = serde_json::json!({ "version": 1, "entries": entries });
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn overlapping_ledgers_flag_the_taken_over_package() {
        // Both ledgers claim minimist ⇒ one mode took the lockfile over from
        // the other and the displaced ledger is stale. The detection names
        // exactly the overlapping PURL.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;

        let superseded = overlapping_ledger_purls(root).await;
        assert_eq!(superseded, vec!["pkg:npm/minimist@1.2.2".to_string()]);
    }

    #[tokio::test]
    async fn single_ledger_present_flags_nothing() {
        // A first-time redirect (only the redirect ledger, no vendored ledger)
        // displaces nothing — no warning. Guards against warning on the FIRST
        // scan of a fresh project.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        assert!(overlapping_ledger_purls(root).await.is_empty());

        // And a project with no ledgers at all.
        let tmp2 = tempfile::tempdir().unwrap();
        assert!(overlapping_ledger_purls(tmp2.path()).await.is_empty());
    }

    #[tokio::test]
    async fn disjoint_ledgers_are_not_a_takeover() {
        // A legitimate split — one package redirected, a DIFFERENT one
        // vendored — is not a takeover: neither ledger's wiring is stale.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger(root, &["pkg:npm/lodash@4.17.21"]).await;
        assert!(overlapping_ledger_purls(root).await.is_empty());
    }

    #[test]
    fn takeover_detail_names_direction_package_and_remediation() {
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];

        // Vendored displaced a hosted redirect: name the stale ledger, but
        // NEVER advise deleting it by hand — it may hold the only revert data
        // and VEX records for OTHER still-live redirects. The safe sequence
        // is re-running the vendored flow, which reconciles per package.
        let vendored = mode_takeover_detail(&purls, /*current_is_hosted=*/ false);
        assert!(vendored.contains("pkg:npm/minimist@1.2.2"));
        assert!(vendored.contains("redirect-state.json"));
        assert!(
            !vendored.contains("Remove the stale redirect ledger"),
            "must not advise deleting the redirect ledger: {vendored}"
        );
        assert!(
            vendored.contains("Do not delete"),
            "must warn against hand-deleting the ledger: {vendored}"
        );

        // Hosted displaced a vendored ledger: `vendor --revert` is the ONLY
        // offered remediation. Deleting the `.socket/vendor/<eco>/` tree by
        // hand hard-breaks cargo resolution while `[patch.crates-io]` still
        // references it.
        let hosted = mode_takeover_detail(&purls, /*current_is_hosted=*/ true);
        assert!(hosted.contains("pkg:npm/minimist@1.2.2"));
        assert!(hosted.contains("state.json"));
        assert!(hosted.contains("orphaned"));
        assert!(hosted.contains("vendor --revert"));
        assert!(
            !hosted.contains("or delete the orphaned"),
            "deleting the vendor tree must not be offered as an equal \
             alternative: {hosted}"
        );

        // The two warning codes are distinct routing tags.
        assert_ne!(VENDOR_SUPERSEDES_REDIRECT, REDIRECT_SUPERSEDES_VENDORED);
    }

    // ---- agent-flow hosted-wiring retention (hosted → agent conversion) ----
    // The overlap classifier keys on purls present in BOTH ledgers, so
    // hosted-ONLY wiring (the exact hosted→agent conversion state: redirect
    // ledger live, no vendor state.json) can structurally never trigger it.
    // The agent flow probes the redirect ledger + live lock directly and
    // emits `hosted_wiring_retained`. These pin the trigger, every
    // non-trigger, and the remediation wording.

    /// Redirect ledger with one record per PURL AND a recorded `yarn.lock`
    /// edit — the shape a real hosted run leaves behind (the edit is what
    /// lets `hosted_wiring_live`'s text proof scan the lock).
    async fn write_redirect_ledger_with_edit(root: &Path, purls: &[&str]) {
        use socket_patch_core::patch::redirect::{FileEdit, RedirectState};
        let mut state = RedirectState::new();
        for purl in purls {
            state.records.insert((*purl).to_string(), takeover_record());
        }
        state.edits.push(FileEdit {
            path: "yarn.lock".to_string(),
            kind: "redirect_yarn_entry".to_string(),
            action: "rewritten".to_string(),
            key: Some("minimist@1.2.2".to_string()),
            original: Some(serde_json::Value::String("registry original".to_string())),
            new: None,
        });
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();
    }

    /// yarn classic lock whose resolved URL is the hosted artifact (carries
    /// the record uuid) — the live-hosted-wiring proof.
    async fn write_hosted_yarn_lock(root: &Path, uuid: &str) {
        tokio::fs::write(
            root.join("yarn.lock"),
            format!(
                "# yarn lockfile v1\n\n\nminimist@^1.2.2:\n  version \"1.2.2\"\n  \
                 resolved \"https://patch.socket.dev/patch/npm/minimist/1.2.2/tok/{uuid}/minimist-1.2.2.tgz#aaaa\"\n  \
                 integrity sha512-fake==\n"
            ),
        )
        .await
        .unwrap();
    }

    async fn load_ledger(root: &Path) -> Option<socket_patch_core::patch::redirect::RedirectState> {
        socket_patch_core::patch::redirect::load_redirect_state(root)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn hosted_only_wiring_fires_agent_probe_not_the_overlap_classifier() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let purl = "pkg:npm/minimist@1.2.2";
        write_redirect_ledger_with_edit(root, &[purl]).await;
        write_hosted_yarn_lock(root, TAKEOVER_UUID).await;

        // Hosted-only wiring (no vendor state.json) is structurally
        // invisible to the hosted⇄vendored overlap classifier…
        assert!(overlapping_ledger_purls(root).await.is_empty());
        assert_eq!(
            classify_overlap_takeover(root).await,
            OverlapTakeover::default()
        );

        // …but the agent flow's direct probe sees it for scanned purls.
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();
        let ledger = load_ledger(root).await;
        let retained = hosted_wiring_retained_purls(root, ledger.as_ref(), &scanned).await;
        assert_eq!(retained, vec![purl.to_string()]);
    }

    #[tokio::test]
    async fn hosted_retained_probe_is_silent_without_live_records_or_wiring() {
        let purl = "pkg:npm/minimist@1.2.2";
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();

        // (a) Records retired — the lane-B (hosted→vendored pre-revert)
        // world: the pre-revert drops the ledger RECORDS while the
        // append-only `edits` (revert originals) legitimately remain. The
        // warning keys on records still live at scan time, so it must stay
        // silent even with the uuid still present in the lock text.
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger_with_edit(tmp.path(), &[]).await;
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        let ledger = load_ledger(tmp.path()).await;
        assert!(
            hosted_wiring_retained_purls(tmp.path(), ledger.as_ref(), &scanned)
                .await
                .is_empty(),
            "records gone ⇒ silent (pre-reverted wiring must not re-warn)"
        );

        // (b) Registry-clean lock with a live record: the live lock is the
        // truth source — never guess from ledger presence alone.
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger_with_edit(tmp.path(), &[purl]).await;
        tokio::fs::write(
            tmp.path().join("yarn.lock"),
            "# yarn lockfile v1\n\n\nminimist@^1.2.2:\n  version \"1.2.2\"\n  \
             resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.2.tgz#bbbb\"\n  \
             integrity sha512-orig==\n",
        )
        .await
        .unwrap();
        let ledger = load_ledger(tmp.path()).await;
        assert!(
            hosted_wiring_retained_purls(tmp.path(), ledger.as_ref(), &scanned)
                .await
                .is_empty(),
            "registry-clean lock ⇒ silent"
        );

        // (c) The purl was not scanned this run.
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger_with_edit(tmp.path(), &[purl]).await;
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        let other: HashSet<String> = ["pkg:npm/lodash@4.17.21".to_string()].into_iter().collect();
        let ledger = load_ledger(tmp.path()).await;
        assert!(
            hosted_wiring_retained_purls(tmp.path(), ledger.as_ref(), &other)
                .await
                .is_empty(),
            "unscanned purl ⇒ silent"
        );

        // (d) No ledger at all.
        let tmp = tempfile::tempdir().unwrap();
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        assert!(
            hosted_wiring_retained_purls(tmp.path(), None, &scanned)
                .await
                .is_empty(),
            "no ledger ⇒ silent"
        );
    }

    #[test]
    fn agent_retention_details_name_packages_and_safe_remediation() {
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];

        // hosted_wiring_retained: names the purl and both real options
        // (stay hosted / migrate via vendored), never a hosted→agent
        // unwind (none exists) and never hand-deleting the ledger (the
        // only store of the pre-redirect revert originals).
        let hosted = hosted_wiring_retained_detail(&purls);
        assert!(hosted.contains("pkg:npm/minimist@1.2.2"));
        assert!(hosted.contains("scan --mode hosted"));
        assert!(hosted.contains("scan --mode vendored"));
        assert!(
            hosted.contains("Do not delete"),
            "must warn against hand-deleting the ledger: {hosted}"
        );

        // vendored_ownership_retained: names the purl and the per-package
        // migration path, with the mass-revert alternative scoped.
        let vendored = vendored_ownership_retained_detail(&purls);
        assert!(vendored.contains("pkg:npm/minimist@1.2.2"));
        assert!(vendored.contains("socket-patch remove"));
        assert!(vendored.contains("vendor --revert"));
        assert!(
            vendored.contains("EVERY vendored package"),
            "the mass-revert blast radius must be called out: {vendored}"
        );
        assert!(vendored.contains("scan --mode agent"));

        // Distinct routing tags, also distinct from the takeover family.
        assert_ne!(HOSTED_WIRING_RETAINED, VENDORED_OWNERSHIP_RETAINED);
        assert_ne!(HOSTED_WIRING_RETAINED, REDIRECT_SUPERSEDES_VENDORED);
        assert_ne!(VENDORED_OWNERSHIP_RETAINED, VENDOR_SUPERSEDES_REDIRECT);
    }

    // ---- redirectState envelope block (read-only cross-mode visibility) ----
    // The end-to-end envelope placement (report-only + agent runs carry it,
    // hosted/vendored runs don't) is pinned by `tests/scan_invariants.rs`;
    // these pin the block builder's own gates and shape.

    /// Records present ⇒ the block exists with each record's canonicalized
    /// purl + verbatim ledger key, the constant mode label, and the
    /// caller-supplied wiringLive. Records absent (edits-only ledger, no
    /// ledger) ⇒ `None`, so the envelope key stays additive.
    #[tokio::test]
    async fn redirect_state_block_gates_on_records_and_splits_live_proof() {
        let purl = "pkg:npm/minimist@1.2.2";
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();

        // Records, but no lockfile on disk: listed, with the EMPTY wiringLive
        // the probe computes (the ledger's word is never promoted to a
        // live-lock proof).
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger_with_edit(tmp.path(), &[purl]).await;
        let ledger = load_ledger(tmp.path()).await;
        let wiring = hosted_wiring_retained_purls(tmp.path(), ledger.as_ref(), &scanned).await;
        assert_eq!(wiring, Vec::<String>::new());
        let block =
            redirect_state_json(ledger.as_ref(), &wiring).expect("records present ⇒ block present");
        assert_eq!(block["mode"], "hosted");
        assert_eq!(block["ledger"], ".socket/vendor/redirect-state.json");
        assert_eq!(
            block["records"],
            serde_json::json!([{ "purl": purl, "ledgerKey": purl, "uuid": TAKEOVER_UUID }])
        );
        assert_eq!(block["wiringLive"], serde_json::json!([]));

        // Live lock present too: the same purl graduates into wiringLive.
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        let wiring = hosted_wiring_retained_purls(tmp.path(), ledger.as_ref(), &scanned).await;
        let block =
            redirect_state_json(ledger.as_ref(), &wiring).expect("records present ⇒ block present");
        assert_eq!(block["wiringLive"], serde_json::json!([purl]));

        // Edits-only ledger (records retired) ⇒ no block.
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger_with_edit(tmp.path(), &[]).await;
        let ledger = load_ledger(tmp.path()).await;
        assert!(
            redirect_state_json(ledger.as_ref(), &[]).is_none(),
            "an edits-only ledger asserts no records"
        );

        // No ledger ⇒ no block.
        assert!(redirect_state_json(None, &[]).is_none());
    }

    /// The records↔wiringLive join is a plain string compare: each record's
    /// `purl` is canonicalized to exactly the spelling the probe emits, with
    /// the ledger's raw key preserved as `ledgerKey`. Pinned on the two key
    /// shapes real ledgers carry — a percent-encoded scoped npm name (the
    /// API spelling, the `drop_superseded_purl` fixture shape) and a
    /// `?platform=`-qualified gem purl. Pre-fix, `records[].purl` kept the
    /// verbatim key while `wiringLive` was canonical, so a LIVE redirect
    /// read as "wiring unwound" to any consumer doing the documented join.
    #[tokio::test]
    async fn redirect_state_records_canonicalize_to_the_wiring_live_spelling() {
        use socket_patch_core::patch::redirect::{FileEdit, RedirectState};

        let scoped_key = "pkg:npm/%40scope%2Fpkg@1.0.0";
        let scoped_canon = "pkg:npm/@scope/pkg@1.0.0";
        let gem_key = "pkg:gem/nokogiri@1.13.3?platform=ruby";
        let gem_canon = "pkg:gem/nokogiri@1.13.3";

        let tmp = tempfile::tempdir().unwrap();
        let mut state = RedirectState::new();
        state
            .records
            .insert(scoped_key.to_string(), takeover_record());
        state.records.insert(gem_key.to_string(), takeover_record());
        // A recorded yarn.lock edit + the uuid in the lock text (outside any
        // vendored path) — the text proof of live hosted wiring for the
        // scoped purl.
        state.edits.push(FileEdit {
            path: "yarn.lock".to_string(),
            kind: "redirect_yarn_entry".to_string(),
            action: "rewritten".to_string(),
            key: Some("@scope/pkg@1.0.0".to_string()),
            original: Some(serde_json::Value::String("orig".to_string())),
            new: None,
        });
        let dir = tmp.path().join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;

        let scanned: HashSet<String> = [scoped_canon.to_string()].into_iter().collect();
        let ledger = load_ledger(tmp.path()).await;
        let wiring = hosted_wiring_retained_purls(tmp.path(), ledger.as_ref(), &scanned).await;
        assert_eq!(
            wiring,
            vec![scoped_canon.to_string()],
            "the text proof (uuid in the recorded lock) claims the scoped purl"
        );

        let block =
            redirect_state_json(ledger.as_ref(), &wiring).expect("records present ⇒ block present");
        assert_eq!(
            block["records"],
            serde_json::json!([
                { "purl": gem_canon, "ledgerKey": gem_key, "uuid": TAKEOVER_UUID },
                { "purl": scoped_canon, "ledgerKey": scoped_key, "uuid": TAKEOVER_UUID },
            ]),
            "records carry the canonical purl (wiringLive's spelling) plus \
             the verbatim ledger key; block={block}"
        );
        let live: Vec<&str> = block["wiringLive"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        let record_purls: Vec<&str> = block["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["purl"].as_str().unwrap())
            .collect();
        for purl in live {
            assert!(
                record_purls.contains(&purl),
                "every wiringLive purl must string-match a records[].purl \
                 (the documented join); block={block}"
            );
        }
    }

    /// The block's `mode` is the constant label, not the ledger's opaque
    /// `mode` string: a pre-rename ledger carrying `"redirect"` still labels
    /// as `"hosted"`, so consumers dispatching on the key need no history.
    #[tokio::test]
    async fn redirect_state_mode_is_the_constant_label_for_legacy_ledgers() {
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger_with_edit(tmp.path(), &["pkg:npm/minimist@1.2.2"]).await;
        let mut ledger = load_ledger(tmp.path()).await.unwrap();
        ledger.mode = "redirect".to_string();
        let block =
            redirect_state_json(Some(&ledger), &[]).expect("records present ⇒ block present");
        assert_eq!(block["mode"], "hosted");
    }

    // ---- cargo takeover direction (lock-shape probe) ------------------------
    // The scan inventory records `resolved: None` for every cargo entry, so
    // the generic patch.socket.dev check can never prove hosted for cargo —
    // pre-fix, a genuine vendored→hosted cargo takeover classified as
    // (hosted=false, vendored=true) and the warning INVERTED: the vendored
    // flow told the user to delete the LIVE redirect ledger. These pin the
    // cargo-specific lock-shape classifier.

    const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const CARGO_INDEX: &str = "sparse+http://127.0.0.1:5555/index/";

    /// A vendored state ledger with one CARGO entry wired the way the cargo
    /// backend records it (.cargo/config.toml patch entry + Cargo.lock edit).
    async fn write_cargo_vendor_ledger(root: &Path) {
        let state = serde_json::json!({
            "version": 1,
            "entries": {
                CARGO_PURL: {
                    "ecosystem": "cargo",
                    "basePurl": CARGO_PURL,
                    "uuid": TAKEOVER_UUID,
                    "artifact": {
                        "path": format!(
                            ".socket/vendor/cargo/{TAKEOVER_UUID}/cfg-if-1.0.4"
                        ),
                    },
                    "wiring": [
                        {
                            "file": ".cargo/config.toml",
                            "kind": "cargo_patch_entry",
                            "action": "added",
                        },
                        {
                            "file": "Cargo.lock",
                            "kind": "cargo_lock_entry",
                            "action": "rewritten",
                        },
                    ],
                },
            },
        });
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();
    }

    /// The mixed state a pre-fix vendored→hosted cargo takeover left behind:
    /// the lock rewired to the hosted sparse index (declared as a
    /// socket-patch registry in the config), while the vendored
    /// `[patch.crates-io]` entry ALSO survives in the config.
    async fn write_cargo_hosted_takeover_files(root: &Path) {
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".cargo/config.toml"),
            format!(
                "[patch.crates-io]\ncfg-if = {{ path = \".socket/vendor/cargo/{TAKEOVER_UUID}/cfg-if-1.0.4\" }}\n\n\
                 [registries.socket-patch-{TAKEOVER_UUID}]\nindex = \"{CARGO_INDEX}\"\n"
            ),
        )
        .await
        .unwrap();
        tokio::fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{CARGO_INDEX}\"\nchecksum = \"{}\"\n",
                "a".repeat(64)
            ),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cargo_takeover_classifies_hosted_when_the_lock_points_at_the_socket_registry() {
        // The lock's source is the config-declared socket-patch sparse index
        // (a localhost URL — the probe must not depend on the
        // patch.socket.dev host). Hosted won; the vendored ledger is stale —
        // even though the leftover [patch.crates-io] marker would satisfy the
        // generic wiring scan (the pre-fix inversion).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &[CARGO_PURL]).await;
        write_cargo_vendor_ledger(root).await;
        write_cargo_hosted_takeover_files(root).await;

        let takeover = classify_overlap_takeover(root).await;
        assert_eq!(
            takeover.redirect,
            vec![CARGO_PURL.to_string()],
            "hosted direction must be provable for cargo: {takeover:?}"
        );
        assert!(
            takeover.vendored.is_empty(),
            "the INVERSE warning must not fire (pre-fix bug): {takeover:?}"
        );
    }

    #[tokio::test]
    async fn cargo_takeover_classifies_vendored_when_the_lock_is_detached() {
        // The genuine vendored-live shape: detached lock entry (no source) +
        // [patch.crates-io] pointing at the entry's committed copy. The
        // redirect ledger is the stale one.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &[CARGO_PURL]).await;
        write_cargo_vendor_ledger(root).await;
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".cargo/config.toml"),
            format!(
                "[patch.crates-io]\ncfg-if = {{ path = \".socket/vendor/cargo/{TAKEOVER_UUID}/cfg-if-1.0.4\" }}\n"
            ),
        )
        .await
        .unwrap();
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
        )
        .await
        .unwrap();

        let takeover = classify_overlap_takeover(root).await;
        assert_eq!(
            takeover.vendored,
            vec![CARGO_PURL.to_string()],
            "{takeover:?}"
        );
        assert!(takeover.redirect.is_empty(), "{takeover:?}");
    }

    #[tokio::test]
    async fn cargo_takeover_stays_silent_when_the_lock_points_at_crates_io() {
        // Both ledgers claim the purl but a third party re-resolved the lock
        // back to crates.io: neither mode is live — no directional warning.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &[CARGO_PURL]).await;
        write_cargo_vendor_ledger(root).await;
        tokio::fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n",
                "b".repeat(64)
            ),
        )
        .await
        .unwrap();

        let takeover = classify_overlap_takeover(root).await;
        assert!(
            takeover.redirect.is_empty() && takeover.vendored.is_empty(),
            "{takeover:?}"
        );
    }

    // ---- takeover DIRECTION follows the live lock, not the command ---------
    // The overlap alone only proves both ledgers name the same package; it does
    // NOT prove which mode won. `classify_overlap_takeover` decides direction
    // from the ACTUAL current lockfile wiring, so a dry-run/no-op can never emit
    // the wrong `*_supersedes_*` warning and point cleanup at the LIVE ledger.

    /// Like [`write_vendor_ledger`] but each entry records wiring the
    /// `package-lock.json` — the file the direction check reads to see whether
    /// the lock still points at the committed `.socket/vendor/` artifact.
    async fn write_vendor_ledger_wired(root: &Path, purls: &[&str]) {
        let entries: serde_json::Map<String, serde_json::Value> = purls
            .iter()
            .map(|purl| {
                (
                    (*purl).to_string(),
                    serde_json::json!({
                        "ecosystem": "npm",
                        "basePurl": purl,
                        "uuid": TAKEOVER_UUID,
                        "artifact": {
                            "path": format!(".socket/vendor/npm/{TAKEOVER_UUID}/pkg.tgz"),
                        },
                        "wiring": [{
                            "file": "package-lock.json",
                            "kind": "npm_lock_entry",
                            "action": "rewritten",
                        }],
                    }),
                )
            })
            .collect();
        let state = serde_json::json!({ "version": 1, "entries": entries });
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();
    }

    /// A `package-lock.json` whose single dep resolves to the committed
    /// `.socket/vendor/` artifact — vendored is what the lock actually wires.
    async fn write_lock_pointing_at_vendored(root: &Path, name: &str, version: &str) {
        let lock = serde_json::json!({
            "name": "app",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "0.0.0" },
                format!("node_modules/{name}"): {
                    "version": version,
                    "resolved": format!(
                        "file:.socket/vendor/npm/{TAKEOVER_UUID}/{name}-{version}.tgz"
                    ),
                },
            },
        });
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&lock).unwrap(),
        )
        .await
        .unwrap();
    }

    /// A `package-lock.json` whose single dep resolves to the hosted patch
    /// server — hosted is what the lock actually wires.
    async fn write_lock_pointing_at_hosted(root: &Path, name: &str, version: &str) {
        let lock = serde_json::json!({
            "name": "app",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "0.0.0" },
                format!("node_modules/{name}"): {
                    "version": version,
                    "resolved": format!(
                        "https://patch.socket.dev/npm/{name}/-/{name}-{version}.tgz"
                    ),
                    "integrity": format!("sha512-{}", "a".repeat(86)),
                },
            },
        });
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&lock).unwrap(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn hosted_flow_stays_silent_when_the_lock_still_points_at_vendored() {
        // Both ledgers claim minimist, but the LIVE lockfile still resolves it
        // to the committed `.socket/vendor/` artifact — vendored is live. A
        // hosted dry-run/no-op must NOT emit `redirect_supersedes_vendored`,
        // which would point cleanup at the LIVE vendored ledger (the bug).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;

        let takeover = classify_overlap_takeover(root).await;
        // The hosted flow keys its warning off `.redirect` — empty here, so it
        // stays silent instead of accusing the live vendored ledger.
        assert!(
            takeover.redirect.is_empty(),
            "hosted flow must not warn when the lock is vendored: {takeover:?}"
        );
        // Truthful direction: vendored won ⇒ the redirect ledger is the stale one.
        assert_eq!(
            takeover.vendored,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
        // Pre-fix the hosted flow keyed off the raw overlap, which is non-empty
        // — it WOULD have wrongly told the user to delete the live ledger.
        assert!(!overlapping_ledger_purls(root).await.is_empty());
    }

    #[tokio::test]
    async fn vendored_flow_stays_silent_when_the_lock_still_points_at_hosted() {
        // Mirror: both ledgers claim minimist, but the LIVE lockfile resolves it
        // to the hosted patch server — hosted is live. A vendored dry-run/no-op
        // must NOT emit `vendor_supersedes_redirect` and point cleanup at the
        // live redirect ledger.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_hosted(root, "minimist", "1.2.2").await;

        let takeover = classify_overlap_takeover(root).await;
        assert!(
            takeover.vendored.is_empty(),
            "vendored flow must not warn when the lock is hosted: {takeover:?}"
        );
        // Truthful direction: hosted won ⇒ the vendored ledger is the stale one.
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
    }

    #[tokio::test]
    async fn overlap_without_a_lock_to_prove_direction_stays_silent_both_ways() {
        // Both ledgers overlap, but no lockfile proves which mode is live. Rather
        // than guess the direction from which command is running, both flows stay
        // silent — the raw overlap still fires, only the direction is gated.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;

        let takeover = classify_overlap_takeover(root).await;
        assert!(
            takeover.redirect.is_empty() && takeover.vendored.is_empty(),
            "no lock proof ⇒ no directional warning: {takeover:?}"
        );
        assert_eq!(
            overlapping_ledger_purls(root).await,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
    }

    // ---- remediation is per-package and non-destructive ---------------------

    #[test]
    fn takeover_detail_remediation_is_per_package_and_non_destructive() {
        // Regression: the remediation used to instruct whole-ledger /
        // whole-tree deletion, destroying live data for packages the takeover
        // did not touch — the redirect ledger holds OTHER packages' records
        // (VEX reads them) plus the only recorded pre-redirect originals, and
        // the `.socket/vendor/<eco>/` tree holds EVERY vendored uuid dir.
        // Cleanup must be scoped per named package.
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];

        let hosted = mode_takeover_detail(&purls, /*current_is_hosted=*/ true);
        // The sanctioned per-purl cleanup command…
        assert!(
            hosted.contains("socket-patch remove <purl>"),
            "hosted remediation must be per-package: {hosted}"
        );
        // …never whole-tree deletion, and never a blanket revert (which would
        // mass-revert unrelated still-live vendored packages).
        assert!(
            !hosted.contains("delete the orphaned"),
            "hosted remediation must not advise tree deletion: {hosted}"
        );
        assert!(
            hosted.contains("Do not delete the whole"),
            "hosted remediation must warn against tree deletion: {hosted}"
        );
        assert!(
            !hosted.contains("vendor --revert` before redirecting"),
            "hosted remediation must not advise a blanket revert: {hosted}"
        );

        let vendored = mode_takeover_detail(&purls, /*current_is_hosted=*/ false);
        // Only the named packages' records — never the whole ledger file.
        assert!(
            vendored.contains("only these package(s)"),
            "vendored remediation must be per-package: {vendored}"
        );
        assert!(
            !vendored.contains("Remove the stale redirect ledger"),
            "vendored remediation must not advise deleting the ledger: {vendored}"
        );
        assert!(
            vendored.contains("Do not delete the ledger file"),
            "vendored remediation must warn against file deletion: {vendored}"
        );
    }

    #[test]
    fn hosted_remediation_states_removes_full_blast_radius() {
        // Regression: the hosted text said `socket-patch remove <purl>` "drops
        // only that entry and its own `.socket/vendor/<eco>/<uuid>/` artifact
        // directory". It also deletes the package's `.socket/manifest.json`
        // entry, so a reader budgeting for a ledger-scoped edit — a bot passing
        // `--yes`, especially — was mis-told what the command does.
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];
        let hosted = mode_takeover_detail(&purls, /*current_is_hosted=*/ true);

        assert!(
            !hosted.contains("drops only that entry"),
            "hosted remediation must not understate `remove`: {hosted}"
        );
        assert!(
            hosted.contains("`.socket/manifest.json`"),
            "hosted remediation must name the manifest entry `remove` deletes: {hosted}"
        );
        // …and must place the LIVE hosted patch, so "manifest entry deleted"
        // does not read as "the hosted patch was dropped too".
        assert!(
            hosted.contains("redirect-state.json"),
            "hosted remediation must say where the live hosted patch lives: {hosted}"
        );
    }

    // ---- takeover blind spots: degraded ledgers and hosted-proof gaps ------

    fn redirect_edit(path: &str, key: &str) -> socket_patch_core::patch::redirect::FileEdit {
        socket_patch_core::patch::redirect::FileEdit {
            path: path.to_string(),
            kind: "redirect_npm_lock_entry".to_string(),
            action: "modified".to_string(),
            key: Some(key.to_string()),
            original: None,
            new: None,
        }
    }

    /// Like [`write_redirect_ledger`] but with explicit `edits` (and possibly
    /// NO records — the degraded shape a run with failed record fetches
    /// persists).
    async fn write_redirect_ledger_with_edits(
        root: &Path,
        purls: &[&str],
        edits: Vec<socket_patch_core::patch::redirect::FileEdit>,
    ) {
        use socket_patch_core::patch::redirect::RedirectState;
        let mut state = RedirectState::new();
        for purl in purls {
            state.records.insert((*purl).to_string(), takeover_record());
        }
        state.edits = edits;
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(
            dir.join("redirect-state.json"),
            serde_json::to_string_pretty(&state).unwrap(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn overlap_detected_when_redirect_ledger_has_edits_but_no_records() {
        // A hosted run where every per-uuid record fetch failed persists a
        // ledger with edits but an EMPTY records map (`record_fetch_failed`).
        // That ledger still asserts stale lock wiring, so a vendored takeover
        // of the same package must still be flagged — deriving the overlap
        // from record keys alone was blind to exactly this ledger.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger_with_edits(
            root,
            &[],
            vec![redirect_edit("package-lock.json", "node_modules/minimist")],
        )
        .await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;

        assert_eq!(
            overlapping_ledger_purls(root).await,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "an edits-only redirect ledger must still count as overlapping"
        );
        let takeover = classify_overlap_takeover(root).await;
        assert_eq!(
            takeover.vendored,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "the vendored takeover of a degraded redirect ledger must be flagged"
        );
        assert!(takeover.redirect.is_empty(), "{takeover:?}");
    }

    #[tokio::test]
    async fn following_the_vendored_remediation_clears_the_warning() {
        // Regression (sticky warning): the vendored remediation used to name
        // only the `records` entries. When the takeover cleared the LAST
        // record, the leftover `edits` still matched the package through the
        // degraded-ledger fallback above, so the identical warning fired on
        // every later run — and repeated advice that could no longer be
        // followed, since `records` was already empty. The remediation now
        // names the matching `edits` entries too; carrying it out in full has
        // to leave nothing to warn about.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger_with_edits(
            root,
            &["pkg:npm/minimist@1.2.2"],
            vec![redirect_edit("package-lock.json", "node_modules/minimist")],
        )
        .await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;

        let before = classify_overlap_takeover(root).await;
        assert_eq!(
            before.vendored,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "the vendored takeover must be flagged first: {before:?}"
        );
        let detail = mode_takeover_detail(&before.vendored, /*current_is_hosted=*/ false);
        assert!(
            detail.contains("`edits`"),
            "the remediation must name the edits entries: {detail}"
        );

        // Exactly what the remediation prescribes for this ledger: the
        // package's `records` entry AND its matching `edits` entry gone, the
        // ledger file itself left in place.
        write_redirect_ledger_with_edits(root, &[], Vec::new()).await;

        let after = classify_overlap_takeover(root).await;
        assert_eq!(
            after,
            OverlapTakeover::default(),
            "following the remediation must clear the warning: {after:?}"
        );
        assert!(
            overlapping_ledger_purls(root).await.is_empty(),
            "no residue may keep the ledgers reading as overlapping"
        );
    }

    /// A grant token as it appears between the host and the patch uuid in
    /// hosted artifact URLs.
    const TAKEOVER_TOKEN: &str = "33333333-3333-4333-8333-333333333333";

    #[tokio::test]
    async fn hosted_direction_provable_on_non_default_patch_host() {
        // Hosted artifact URLs embed the record's patch uuid on ANY host
        // (staging / self-hosted `--patch-server-url` deployments), so the
        // liveness proof must not be pinned to the `patch.socket.dev`
        // hostname.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        let lock = serde_json::json!({
            "name": "app",
            "lockfileVersion": 3,
            "requires": true,
            "packages": {
                "": { "name": "app", "version": "0.0.0" },
                "node_modules/minimist": {
                    "version": "1.2.2",
                    "resolved": format!(
                        "https://patches.example.com/patch/npm/{TAKEOVER_TOKEN}/{TAKEOVER_UUID}/minimist-1.2.2.tgz"
                    ),
                    "integrity": format!("sha512-{}", "a".repeat(86)),
                },
            },
        });
        tokio::fs::write(
            root.join("package-lock.json"),
            serde_json::to_string_pretty(&lock).unwrap(),
        )
        .await
        .unwrap();

        let takeover = classify_overlap_takeover(root).await;
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "a non-default patch host must still prove hosted is live"
        );
        assert!(takeover.vendored.is_empty(), "{takeover:?}");
    }

    #[tokio::test]
    async fn hosted_direction_provable_for_bun_url_tuple() {
        // The bun inventory skips the URL 3-tuples hosted mode writes, so
        // hosted liveness must be provable from the redirect-edited lockfile
        // text (the record's uuid outside any vendored path).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger_with_edits(
            root,
            &["pkg:npm/minimist@1.2.2"],
            vec![redirect_edit("bun.lock", "minimist")],
        )
        .await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        tokio::fs::write(
            root.join("bun.lock"),
            format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"packages\": {{\n    \
                 \"minimist\": [\"minimist@https://patch.socket.dev/patch/npm/{TAKEOVER_TOKEN}/{TAKEOVER_UUID}/minimist-1.2.2.tgz\", {{}}, \"sha512-AAA\"],\n  \
                 }}\n}}\n"
            ),
        )
        .await
        .unwrap();

        let takeover = classify_overlap_takeover(root).await;
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "a bun URL 3-tuple must prove hosted is live"
        );
        assert!(takeover.vendored.is_empty(), "{takeover:?}");
    }

    #[tokio::test]
    async fn hosted_direction_provable_for_berry_archive_url() {
        // The berry inventory always emits `resolved: None`; the hosted URL
        // lives percent-encoded in the `::__archiveUrl=` binding. The uuid
        // survives encoding verbatim, so the text proof must see it.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger_with_edits(
            root,
            &["pkg:npm/minimist@1.2.2"],
            vec![redirect_edit("yarn.lock", "minimist@1.2.2")],
        )
        .await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        tokio::fs::write(
            root.join("yarn.lock"),
            format!(
                "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                 \"minimist@npm:1.2.2\":\n  version: 1.2.2\n  \
                 resolution: \"minimist@npm:1.2.2::__archiveUrl=https%3A%2F%2Fpatch.socket.dev%2Fpatch%2Fnpm%2F{TAKEOVER_TOKEN}%2F{TAKEOVER_UUID}%2Fminimist-1.2.2.tgz\"\n"
            ),
        )
        .await
        .unwrap();

        let takeover = classify_overlap_takeover(root).await;
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "a berry __archiveUrl binding must prove hosted is live"
        );
        assert!(takeover.vendored.is_empty(), "{takeover:?}");
    }

    #[tokio::test]
    async fn vendored_path_uuid_does_not_prove_hosted() {
        // The vendored wiring embeds the SAME patch uuid in its
        // `.socket/vendor/<eco>/<uuid>/` path. When the redirect ledger
        // names the same lockfile, those occurrences must NOT read as
        // hosted proof — the lock points at the vendored files.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger_with_edits(
            root,
            &["pkg:npm/minimist@1.2.2"],
            vec![redirect_edit("package-lock.json", "node_modules/minimist")],
        )
        .await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;

        let takeover = classify_overlap_takeover(root).await;
        assert!(
            takeover.redirect.is_empty(),
            "a vendored-path uuid must not prove hosted: {takeover:?}"
        );
        assert_eq!(
            takeover.vendored,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
    }
}
