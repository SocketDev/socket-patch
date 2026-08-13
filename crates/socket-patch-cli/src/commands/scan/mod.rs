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
    collect_vuln_ids, detect_updates, lockfile_supplement, preverify_vendor_baselines,
    severity_order, vendored_ledger_supplement,
};
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
    /// repo, but installs must reach the patch server.
    #[value(alias = "host")]
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
    println!("{}", serde_json::to_string_pretty(result).unwrap());
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
// each flow can warn; reconciliation (removing the stale ledger / orphaned
// artifacts) is deliberately deferred so neither mode silently mutates the
// other's ledger.
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
    let Some(redirect) = socket_patch_core::patch::redirect::load_redirect_state(cwd).await else {
        return Vec::new();
    };
    let Ok(vendor) = socket_patch_core::vendor::load_state(cwd).await else {
        return Vec::new();
    };
    if redirect.records.is_empty() || vendor.entries.is_empty() {
        return Vec::new();
    }
    // Canonicalize both sides (drop qualifiers, percent-decode) so the API
    // purl form the redirect records carry matches the vendor entry's base
    // purl — mirrors `vendored_ledger_supplement`.
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let redirect_purls: std::collections::BTreeSet<String> =
        redirect.records.keys().map(|p| canon(p)).collect();
    let mut vendor_purls: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (key, entry) in &vendor.entries {
        vendor_purls.insert(canon(key));
        vendor_purls.insert(canon(&entry.base_purl));
    }
    redirect_purls
        .intersection(&vendor_purls)
        .cloned()
        .collect()
}

/// The overlapping PURLs split by which mode the LIVE lockfile actually wires
/// them to right now — the truth source for takeover direction.
///
/// `redirect` holds the overlap PURLs the lock currently routes to the hosted
/// patch server (`patch.socket.dev`): hosted genuinely won the lockfile, so the
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
    let mut vendor_by_purl: std::collections::HashMap<String, &socket_patch_core::vendor::VendorEntry> =
        std::collections::HashMap::new();
    for (key, entry) in &vendor.entries {
        vendor_by_purl.entry(canon(key)).or_insert(entry);
        vendor_by_purl.entry(canon(&entry.base_purl)).or_insert(entry);
    }
    // The scan inventory keeps only http(s) `resolved` URLs and DROPS our own
    // `file:.socket/vendor/…` specs (see `lock_inventory`), so a
    // `patch.socket.dev` resolved for a purl is a purl-scoped proof the lock now
    // points at hosted.
    let inventory = socket_patch_core::vendor::lock_inventory::inventory_project(cwd).await;
    for purl in overlap {
        let hosted_live = socket_patch_core::vendor::lock_inventory::lookup(&inventory, &purl)
            .and_then(|e| e.resolved.as_deref())
            .is_some_and(|r| r.contains("patch.socket.dev"));
        let vendored_live = match vendor_by_purl.get(&purl) {
            Some(entry) => vendored_wiring_live(cwd, entry).await,
            None => false,
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
        // state.json is tamper-able: only ever READ a plain in-project relative
        // lockfile name — never one that could climb out of `cwd`.
        if file.is_empty()
            || file.starts_with('/')
            || file.starts_with('\\')
            || file.split(['/', '\\']).any(|c| c == "..")
        {
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
pub(super) fn mode_takeover_detail(superseded: &[String], current_is_hosted: bool) -> String {
    let list = superseded.join(", ");
    if current_is_hosted {
        format!(
            "hosted redirect superseded the vendored ledger for: {list}. \
             `.socket/vendor/state.json` still claims these package(s) and their \
             committed tarball(s) under `.socket/vendor/` are now orphaned — the \
             lockfile points at the hosted patch server, not the vendored files. \
             Remove the stale vendored ledger and orphaned artifacts (run \
             `socket-patch vendor --revert` before redirecting, or delete the \
             orphaned `.socket/vendor/<eco>/` tree) so audits and VEX do not read \
             superseded wiring."
        )
    } else {
        format!(
            "vendored artifacts superseded the hosted redirect ledger for: {list}. \
             `.socket/vendor/redirect-state.json` still records a hosted redirect for \
             these package(s), but the lockfile now points at the committed \
             `.socket/vendor/` files. Remove the stale redirect ledger \
             (`.socket/vendor/redirect-state.json`) so audits and VEX do not read \
             superseded wiring."
        )
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
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
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
            // Hosted mode: keep the `--json` envelope schema-consistent with
            // the ≥1-package path by including a (no-op) nested `redirect`
            // block — nothing was discovered, so nothing is redirected.
            if hosted {
                result["redirect"] = serde_json::json!({
                    "mode": "hosted",
                    "redirected": 0,
                    "rewrittenFiles": [],
                    "skipped": [],
                    "warnings": [],
                    "dryRun": args.common.dry_run,
                });
            }
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

        // Vendored displaced a hosted redirect: point at the redirect ledger.
        let vendored = mode_takeover_detail(&purls, /*current_is_hosted=*/ false);
        assert!(vendored.contains("pkg:npm/minimist@1.2.2"));
        assert!(vendored.contains("redirect-state.json"));

        // Hosted displaced a vendored ledger: point at the vendored ledger +
        // orphaned artifacts.
        let hosted = mode_takeover_detail(&purls, /*current_is_hosted=*/ true);
        assert!(hosted.contains("pkg:npm/minimist@1.2.2"));
        assert!(hosted.contains("state.json"));
        assert!(hosted.contains("orphaned"));

        // The two warning codes are distinct routing tags.
        assert_ne!(VENDOR_SUPERSEDES_REDIRECT, REDIRECT_SUPERSEDES_VENDORED);
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
        assert_eq!(takeover.vendored, vec!["pkg:npm/minimist@1.2.2".to_string()]);
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
        assert_eq!(takeover.redirect, vec!["pkg:npm/minimist@1.2.2".to_string()]);
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
}
