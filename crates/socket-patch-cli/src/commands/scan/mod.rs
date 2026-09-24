//! The `scan` command: crawl installed (and lockfile-resolved) packages,
//! query the patch API for available patches, and optionally consume them
//! in one of three modes — hosted (`hosted::run_redirect`), vendored
//! (`vendor_flow`), or agent (in-place apply) — with an optional GC pass
//! (`gc`) and discovery helpers (`discovery`). This module keeps the CLI
//! surface (`ScanArgs`, `ScanMode`, `resolve_mode_flags`, `run`) and the
//! small helpers shared across the submodules.

use clap::Args;
use futures_util::StreamExt;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate, ApiClient,
};
use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
use socket_patch_core::crawlers::ruby_crawler::config_path_ignored_warning;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::telemetry::{track_patch_scan_failed, track_patch_scanned};
use socket_patch_core::utils::concurrent::{api_concurrency, ordered_concurrent};
use socket_patch_core::utils::purl::{normalize_purl, purl_name_version, strip_purl_qualifiers};
use socket_patch_core::vendor::VendorState;
use socket_patch_core::vex::discover::{LedgerLiveness, WiringMode};
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::Path;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::crawl_all_ecosystems;
use crate::ui::{self, plural, print_json, StatusLine};

use super::get::{download_and_apply_patches_with, select_patches, DownloadParams, DownloadRun};

mod discovery;
mod gc;
mod hosted;
pub(crate) mod render;
pub(crate) mod vendor_flow;

use self::discovery::{
    collect_vuln_ids, detect_updates, lockfile_only_contains, lockfile_supplement,
    merge_ledger_records_for_updates, preverify_vendor_baselines, severity_order,
    vendored_ledger_supplement, LockfileSupplement,
};
// Shared with `get --mode hosted|vendored` (commands::get): the advisory-
// pinned entry into the hosted engine, the vendor step + its dry-run
// preview, and the PnP layout-refusal warning mapping. `pub(crate)`
// re-exports because the submodules themselves stay private to scan.
pub(crate) use self::discovery::unsupported_layout_warnings;
use self::gc::gc_json;
pub(crate) use self::hosted::boxed_run_redirect_selected;
use self::hosted::run_redirect;
pub(crate) use self::vendor_flow::{
    boxed_scan_vendor_step, preview_vendor_json, print_dry_run_refusals,
};
use self::vendor_flow::{
    boxed_vendor_interactive_path, boxed_vendor_json_path, fold_vendored_skips_into_apply,
    partition_skipped_selected,
};

const DEFAULT_BATCH_SIZE: usize = 100;

/// The three patch-application modes `scan` can drive, selectable via
/// `--mode` (the documented spelling). Each variant is equivalent to one
/// legacy boolean flag, which remains supported as an alias.
//
// The `///` docs on the variants are user-facing `--help` text (shared
// with `get --mode`); keep implementation notes in `//` comments.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// Rewrite lockfiles so only patched dependencies resolve to Socket's
    /// hosted patch server: no artifact bytes land in the repo, but
    /// installs must reach the patch server
    // Equivalent to the hidden `--redirect` boolean. Hidden value aliases
    // mirror the legacy flag spellings symmetrically: `host` matches the
    // old mode name, `redirect` matches the `--redirect` boolean (vendored
    // accepts `vendor` for the same reason; `apply` is NOT an alias of
    // agent — applying is not a scan mode name anywhere else).
    #[value(alias = "host", alias = "redirect")]
    Hosted,
    /// Commit patched artifacts to `.socket/vendor/`: hermetic,
    /// offline-safe installs at the cost of repo size
    // Equivalent to `--vendor`.
    #[value(alias = "vendor")]
    Vendored,
    /// Record patches in `.socket/manifest.json` plus blobs and re-apply
    /// them in place (e.g. from CI): smallest repo footprint, but every
    /// install environment must run the agent
    // Equivalent to `--apply`.
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
            // The hidden --redirect is only explained when it was typed.
            let meaning = if flag == "--redirect" {
                "--redirect means --mode hosted"
            } else {
                "--vendor means --mode vendored; --apply and --sync mean --mode agent"
            };
            return Err(format!(
                "--mode {} cannot be used with {flag}: the flags select different \
                 modes ({meaning})",
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
    if !args.paths.is_empty()
        && matches!(args.mode, Some(ScanMode::Hosted) | Some(ScanMode::Vendored))
    {
        // Hosted/vendored rewire the project's root lockfiles — whole-project
        // by construction — so path scoping cannot mean anything coherent
        // there. Same phrasing family as the conflicts above.
        return Err(format!(
            "path targeting cannot be used with --mode {}: it applies to \
             agent-mode and read-only scans",
            args.mode.expect("checked Some above").cli_name(),
        ));
    }
    if args.mode == Some(ScanMode::Hosted)
        && (args.common.global || args.common.global_prefix.is_some())
    {
        // Global installs have no project lockfile to repoint: the hosted
        // flow would "redirect 0 packages" and exit 0, a silent no-op.
        return Err(format!(
            "{} cannot be used with --mode hosted: global installs have no project \
             lockfile to redirect",
            if args.common.global { "--global" } else { "--global-prefix" },
        ));
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
    /// Only scan packages installed under these path globs (e.g.
    /// `packages/foo`, `apps/**`; a bare directory scopes its whole
    /// subtree). `--prune` still considers the whole project, so a scoped
    /// scan never prunes out-of-scope manifest entries. Lockfile-only
    /// packages have no installed path and are left out (with a warning).
    /// Not available with `--mode hosted` or `--mode vendored`, which
    /// rewire the whole project
    pub paths: Vec<String>,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Number of packages to query per API request.
    #[arg(long = "batch-size", env = "SOCKET_BATCH_SIZE", default_value_t = DEFAULT_BATCH_SIZE)]
    pub batch_size: usize,

    /// Deprecated spelling of `--mode agent`. With `--json`, download and
    /// apply the selected patches without prompting (without a mode,
    /// `scan --json` only reports). Without `--json` it asks first on a
    /// terminal and proceeds otherwise, whereas a scan with no mode and no
    /// `--yes` only reports when stdin is not a terminal
    #[arg(long, default_value_t = false)]
    pub apply: bool,

    /// Garbage-collect after the scan: prune manifest entries for
    /// packages that are no longer installed, then delete orphan blob,
    /// diff and package-archive files from `.socket/`. Off by default so
    /// a temporary uninstall does not lose manifest entries; combine with
    /// `--mode agent` (or use `--sync`) for the auto-update workflow.
    /// Ignored, with a warning, in hosted mode
    #[arg(long, default_value_t = false)]
    pub prune: bool,

    /// Shorthand for `--mode agent --prune`: a cron job or CI workflow can
    /// run `socket-patch scan --json --sync --yes` to end up fully
    /// reconciled in one invocation
    #[arg(long, default_value_t = false)]
    pub sync: bool,

    /// Deprecated spelling of `--mode vendored`: vendor every patched
    /// dependency the scan selects into the committable `.socket/vendor/`
    /// tree instead of applying patches in place. The patch records live in
    /// the vendor ledger (`.socket/vendor/state.json`), never in
    /// `.socket/manifest.json`; a package vendored at an older patch is
    /// re-vendored. Combine with `--prune` to garbage-collect stale state
    #[arg(long, default_value_t = false, conflicts_with_all = ["apply", "sync"])]
    pub vendor: bool,

    /// Accepted for compatibility; has no effect
    // Hidden: vendored mode is always manifest-free (the vendor ledger
    // embeds each patch record and `.socket/manifest.json` is never
    // written), so the flag is a no-op. It still requires vendored mode in
    // either spelling (`--mode vendored` / `--vendor`), enforced in
    // `resolve_mode_flags` rather than clap `requires` so `--mode vendored`
    // satisfies it too.
    #[arg(long, default_value_t = false, hide = true)]
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

    /// How discovered patches are consumed. Without a mode, an interactive
    /// scan offers to apply them in place and `scan --json` only reports.
    /// `--vendor` and `--apply` are older spellings of `--mode vendored`
    /// and `--mode agent`
    // Each mode is equivalent to one boolean flag (hosted == the hidden
    // `--redirect`, vendored == `--vendor`, agent == `--apply`/`--sync`).
    // Combining `--mode` with a boolean from a DIFFERENT mode is rejected in
    // `resolve_mode_flags`; the same mode spelled both ways is accepted.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<ScanMode>,

    /// Download patches for every release variant of a matched package,
    /// not just the ones matching the locally installed distribution.
    /// Affects ecosystems with per-release variants: PyPI (wheel/sdist),
    /// RubyGems (`platform`) and Maven (`classifier`). Off by default to
    /// keep `.socket/` small; turn it on to make the manifest portable
    /// across environments (e.g. cross-platform CI caches)
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
            append_vex_error_warnings(result, &e.embedded_warnings());
            1
        }
    }
}

/// Fold a failed embedded VEX's run-level advisories (the lockfile
/// discovery diagnostics — often the only explanation of a
/// `vendor_unwired` / `redirect_unwired` omission) into the scan JSON's
/// top-level `warnings[]`, the channel `--json` has once stderr is
/// silenced. Appends to an existing array (layout refusals) or creates it.
pub(super) fn append_vex_error_warnings(
    result: &mut serde_json::Value,
    warnings: &[crate::json_envelope::RunWarning],
) {
    if warnings.is_empty() {
        return;
    }
    let extra = warnings
        .iter()
        .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail }));
    match result.get_mut("warnings").and_then(|w| w.as_array_mut()) {
        Some(existing) => existing.extend(extra),
        None => result["warnings"] = serde_json::Value::Array(extra.collect()),
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
            println!("{}", crate::commands::vex::format_vex_dry_run_skip("applied"));
        }
        return base_code;
    }
    let params = vex_args.to_build_params();
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            if !common.silent {
                println!(
                    "{}",
                    crate::commands::vex::format_vex_written(
                        summary.statements,
                        vex_args
                            .vex
                            .as_ref()
                            .expect("--vex is Some: guarded by the early return above"),
                    )
                );
            }
            0
        }
        Err(e) => {
            e.print_embedded(common);
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
/// with the failure on stderr. Selects with [`selection_args`]:
/// scan-driven workflows have no "specify --id" option, so non-TTY runs
/// auto-select the newest patch rather than erroring with
/// `selection_required`. `Err` carries the exit code AND the message: the
/// JSON callers must fold it into their envelope (every `--json`
/// invocation emits exactly one JSON object — see CLI_CONTRACT.md), so
/// the stderr line alone is not enough. `show_progress` / `warn` are the
/// human-only output knobs of [`fetch_patch_details`] (the JSON callers pass
/// `false, false`; the hosted human arm passes the same values as the agent
/// human arm, so the two print the same progress counter and per-package
/// warnings).
async fn discover_selected(
    api_client: &socket_patch_core::api::client::ApiClient,
    packages: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    common: &GlobalArgs,
    show_progress: bool,
    warn: bool,
) -> Result<Vec<PatchSearchResult>, (i32, String)> {
    let (all_search_results, failures) =
        fetch_patch_details(api_client, packages, show_progress, warn).await;
    let error_count = failures.len();
    if error_count > 0 && error_count == packages.len() {
        let err = failures
            .into_iter()
            .last()
            .map_or_else(|| "all patch-detail queries failed".to_string(), |(_, e)| e);
        let message = format!("all {error_count} patch-detail queries failed: {err}");
        eprintln!("Error: {message}");
        return Err((1, message));
    }
    if all_search_results.is_empty() {
        return Ok(Vec::new());
    }
    if common.json {
        // A `--json` run must never open the interactive menu (it would
        // pop up over a machine-read stream on a TTY): pick the top-ranked
        // accessible patch per PURL, exactly what a non-TTY run does.
        // `select_patches` takes the top-ranked patch without prompting
        // when every candidate is accessible, so pre-filter to those.
        let accessible: Vec<PatchSearchResult> = all_search_results
            .into_iter()
            .filter(|p| can_access_paid_patches || p.tier == "free")
            .collect();
        return select_patches(&accessible, true, &selection_args(common))
            .map_err(|code| (code, "patch selection failed".to_string()));
    }
    select_patches(
        &all_search_results,
        can_access_paid_patches,
        &selection_args(common),
    )
    .map_err(|code| (code, "patch selection failed".to_string()))
}

/// `common` with `json` off, for `select_patches`: scan has no "re-run
/// with the chosen UUID" path, so it must never get `selection_required`.
/// A `--json` run also counts as `--yes`: it must never stop at the
/// interactive patch menu (on a TTY that menu would block a machine
/// consumer), so it takes the menu's default, the top-ranked patch.
/// (It still keeps the non-interactive note off stderr: the process-wide
/// quiet switch mutes it.)
fn selection_args(common: &GlobalArgs) -> GlobalArgs {
    GlobalArgs {
        json: false,
        yes: common.yes || common.json,
        ..common.clone()
    }
}

/// Print the blank stdout line that opens a paragraph, once: `opened`
/// flips on the first call.
fn open_paragraph(opened: &mut bool) {
    if !std::mem::replace(opened, true) {
        println!();
    }
}

/// One `search_patches_by_package` query per package with patches, merged
/// into one result list — the detail-fetch loop the apply, vendor, redirect
/// and human-preview flows share. Returns the merged results plus every
/// failed query as `(purl, error)`; the CALLERS own the failure rule
/// ([`discover_selected`] bails only when every query errored, the human
/// arm treats an empty merged set as a fetch failure). The two output
/// knobs are human-only: `show_progress` shows the status-line counter on
/// stderr, `warn` prints a warning per failed package once the loop is
/// done — only when some query succeeded (when every one failed, the
/// caller's error line carries the cause instead, so nothing repeats).
async fn fetch_patch_details(
    api_client: &socket_patch_core::api::client::ApiClient,
    packages: &[BatchPackagePatches],
    show_progress: bool,
    warn: bool,
) -> (Vec<PatchSearchResult>, Vec<(String, String)>) {
    let mut results: Vec<PatchSearchResult> = Vec::new();
    let mut failures: Vec<(String, String)> = Vec::new();
    // `show_progress` off reads as `--json` to the status line: never
    // drawn. On, it is live only on a terminal; it never prints a result.
    let mut status = StatusLine::stderr(!show_progress, false);
    // The queries run concurrently but come back in `packages` order, so
    // `results` and `failures` fold exactly as the serial loop's did. The
    // counter names the next result awaited.
    let mut responses = std::pin::pin!(ordered_concurrent(
        packages,
        api_concurrency(api_client.uses_public_proxy()),
        |pkg| async move { (pkg, api_client.search_patches_by_package(&pkg.purl).await) },
    ));
    for i in 0..packages.len() {
        status.set(format!(
            "Fetching patch details... ({}/{})",
            i + 1,
            packages.len()
        ));
        let Some((pkg, response)) = responses.next().await else {
            break;
        };
        match response {
            Ok(response) => results.extend(response.patches),
            Err(e) => failures.push((pkg.purl.clone(), e.to_string())),
        }
    }
    status.finish();
    if warn && !results.is_empty() {
        for (purl, e) in &failures {
            eprintln!("Warning: could not fetch details for {purl}: {e}");
        }
    }
    (results, failures)
}

/// The human hosted arm's stand-in for the lenient loader's advisory: a
/// malformed redirect ledger the engine would report as a hard error, on a
/// run that returned BEFORE the engine (empty discovery, nothing
/// downloadable, a detail-fetch failure, a declined confirm). Read-only —
/// the file is never moved; `--silent` mutes it like every advisory.
fn warn_unreported_corrupt_ledger(common: &crate::args::GlobalArgs, corrupt: Option<&str>) {
    if let Some(corrupt) = corrupt {
        if !common.silent {
            eprintln!("Warning: {corrupt}");
        }
    }
}

/// Fold a [`discover_selected`] failure into a JSON caller's `result` and
/// print it. The discovery counts already in `result` stay — they were
/// computed from the (successful) batch phase — while `status`/`error`
/// mirror the all-batches-failed envelope so JSON consumers see one
/// consistent scan-error schema instead of empty stdout.
fn emit_discovery_error_json(result: &mut serde_json::Value, message: &str) {
    result["status"] = serde_json::json!("error");
    result["error"] = serde_json::json!(message);
    print_json(result);
}

/// The agent-flow selection split both arms (JSON + human) share. Vendor-
/// owned purls leave first (any uuid: the committed artifact IS the patch,
/// and a manifest moved past the vendored uuid would break VEX verification
/// until a vendor run refreshes the artifact — a newer patch still surfaces
/// in `updates[]`, the operator's signal to run `scan --vendor`), then
/// lockfile-only purls (nothing installed to patch in place; `scan --vendor`
/// fetches them pristine). Both classes become calm `skipped` records —
/// never an error.
struct AgentSelection {
    /// What is left to download + apply.
    kept: Vec<PatchSearchResult>,
    /// Every skip record (`vendored` + `package_not_installed`), purl-sorted,
    /// in the `{purl, uuid, action: "skipped", errorCode}` shape the apply
    /// report folds in.
    skip_records: Vec<serde_json::Value>,
    /// The vendored partition's purls alone — feeds the run-level
    /// `vendored_ownership_retained` warning and the human `[skip]` lines.
    vendored_purls: Vec<String>,
    /// The lockfile-only partition's purls alone (human `[skip]` lines).
    not_installed_purls: Vec<String>,
}

fn partition_agent_selection(
    selected: Vec<PatchSearchResult>,
    vendored: &HashSet<String>,
    lockfile_only: &LockfileSupplement,
) -> AgentSelection {
    let (kept, vendored_records) = partition_skipped_selected(
        selected,
        |p| vendored.contains(p) || vendored.contains(strip_purl_qualifiers(p)),
        "vendored",
    );
    let (kept, not_installed_records) = partition_skipped_selected(
        kept,
        |p| lockfile_only_contains(&lockfile_only.purls, p),
        "package_not_installed",
    );
    let purls_of = |records: &[serde_json::Value]| -> Vec<String> {
        records
            .iter()
            .filter_map(|r| r["purl"].as_str().map(str::to_string))
            .collect()
    };
    let vendored_purls = purls_of(&vendored_records);
    let not_installed_purls = purls_of(&not_installed_records);
    let mut skip_records = vendored_records;
    skip_records.extend(not_installed_records);
    skip_records.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    AgentSelection {
        kept,
        skip_records,
        vendored_purls,
        not_installed_purls,
    }
}

/// The `DownloadParams` every scan-driven download shares. Only the output
/// shape (`json`/`silent`) and `save_only` differ per flow; vendored mode
/// never persists blobs (its records stay in memory and the vendor step
/// consumes the staged sources).
fn download_params(args: &ScanArgs, save_only: bool, json: bool, silent: bool) -> DownloadParams {
    DownloadParams {
        cwd: args.common.cwd.clone(),
        manifest_path: args.common.resolved_manifest_path(),
        save_only,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json,
        silent,
        download_mode: args.common.download_mode.clone(),
        all_releases: args.all_releases,
        strict: args.common.strict,
        ecosystems: args.common.ecosystems.clone(),
        persist_blobs: args.mode != Some(ScanMode::Vendored),
    }
}

/// The run-level context the agent engine borrows from scan: the client
/// `run` already built (proxy fallback included) and the flags the nested
/// apply inherits — so `scan --apply` honors `--lock-timeout` and never
/// rebuilds the client.
fn download_run<'a>(args: &ScanArgs, api_client: &'a ApiClient) -> DownloadRun<'a> {
    DownloadRun {
        api_client,
        lock_timeout: args.common.lock_timeout,
        verbose: args.common.verbose,
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
/// (`.socket/vendor/state.json`), sorted, over ALREADY-LOADED ledgers —
/// loads nothing, so a flow holding both in memory (the hosted engine,
/// post-merge) shares its copies instead of re-reading them. A non-empty
/// result means one mode has taken the lockfile over from the other for
/// these package(s) while the displaced mode's ledger stayed on disk —
/// exactly one of the two ledgers is stale for each PURL (a package's
/// lockfile entry can point only one way). `None` / an empty vendor ledger
/// yield the empty overlap; disjoint ledgers (a legitimate split: some
/// redirected, others vendored) too — so there are no false positives.
fn overlap_from_states(
    redirect: Option<&socket_patch_core::patch::redirect::RedirectState>,
    vendor: &VendorState,
) -> Vec<String> {
    let Some(redirect) = redirect else {
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
            let Some((name, version)) = purl_name_version(strip_purl_qualifiers(purl)) else {
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

/// The overlapping PURLs split by which mode the LIVE lockfile actually wires
/// them to right now — the truth source for takeover direction.
///
/// Both directions are proved by lockfile discovery with the same liveness
/// rules `vex` gates attestations on (core `Discovery::redirect_record_live`
/// / `Discovery::vendor_entry_live` — every package manager's lock read
/// through its extractor, cargo's `Cargo.lock` + `[patch]` shapes included,
/// with the ledger's recorded files as the fallback for a uuid no read file
/// mentions). `redirect` holds the overlap PURLs the lock currently routes
/// to the hosted patch server: hosted genuinely won the lockfile, so the
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

pub(super) async fn classify_overlap_takeover(common: &GlobalArgs, cwd: &Path) -> OverlapTakeover {
    // Both ledgers loaded ONCE here. A malformed ledger classifies like a
    // missing one, matching `overlap_from_states` (this path only
    // feeds takeover warnings; corruption is a hard error on the
    // write/attest paths).
    let redirect = socket_patch_core::patch::redirect::load_redirect_state(cwd)
        .await
        .ok()
        .flatten();
    let vendor = socket_patch_core::vendor::load_state(cwd).await.ok();
    classify_overlap_takeover_with(common, cwd, redirect.as_ref(), vendor.as_ref()).await
}

/// [`classify_overlap_takeover`] over ALREADY-LOADED ledgers: loads neither
/// (the hosted engine holds both in memory — its post-merge redirect ledger
/// and the post-takeover vendor ledger — and must classify against those,
/// never a pre-takeover snapshot) but still reads the LIVE lockfiles in
/// `cwd`, the truth source for direction. `None` for either ledger yields
/// no overlap.
pub(super) async fn classify_overlap_takeover_with(
    common: &GlobalArgs,
    cwd: &Path,
    redirect: Option<&socket_patch_core::patch::redirect::RedirectState>,
    vendor: Option<&VendorState>,
) -> OverlapTakeover {
    let mut out = OverlapTakeover::default();
    let Some(vendor) = vendor else {
        return out;
    };
    let overlap = overlap_from_states(redirect, vendor);
    if overlap.is_empty() {
        return out;
    }
    // Each overlapping vendored entry's uuid + the lockfiles it wired
    // (revert reads the same set).
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
    // the lockfiles the redirect actually edited. A non-empty overlap
    // proves the ledger is `Some`.
    let mut redirect_uuid_by_purl: std::collections::HashMap<String, &str> =
        std::collections::HashMap::new();
    for (key, record) in redirect.iter().flat_map(|r| &r.records) {
        redirect_uuid_by_purl
            .entry(canon(key))
            .or_insert(record.uuid.as_str());
    }
    let discovery = crate::commands::discover_wiring(common, cwd).await;
    let mut liveness = LedgerLiveness::new(cwd, &discovery, redirect);
    for purl in overlap {
        let hosted_live = match redirect_uuid_by_purl.get(&purl) {
            Some(uuid) => liveness.redirect_record(&purl, uuid).await,
            // An edits-only ledger (every record fetch failed) names no
            // uuid: the lock's own hosted wiring of the package decides.
            None => discovery.wires_package(&purl, WiringMode::Hosted),
        };
        let vendored_live = match vendor_by_purl.get(&purl) {
            Some(entry) => liveness.vendor_entry(entry).await,
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
///   `records` entry. `overlap_from_states` falls back to matching edit
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
pub(super) fn mode_takeover_reconciled_detail(
    reconciled: &[String],
    npmrc_unwound: bool,
) -> String {
    let list = reconciled.join(", ");
    // The `.npmrc` sentence is conditional: only a run that actually
    // unwound the hosted npm allow-remote auto-config says so, and then the
    // "restores the hosted wiring" claim gains its npm >= 12 caveat.
    let npmrc = if npmrc_unwound {
        " The hosted redirect's `.npmrc` `allow-remote=all` auto-config was \
         unwound too (a redirect-created file deleted, an appended line \
         removed): the vendored `file:` specs do not need it. If you later \
         restore the hosted lock wiring with `vendor --revert`, npm >=12 \
         refuses it (EALLOWREMOTE) until `allow-remote=all` is back — re-run \
         `scan --mode hosted` afterwards to re-establish it and its ledger \
         record."
    } else {
        ""
    };
    format!(
        "vendored artifacts superseded the hosted redirect ledger for: {list}; \
         reconciled automatically. Both halves of each superseded entry — the \
         package's `records` entry AND its matching `edits` — were dropped \
         from `.socket/vendor/redirect-state.json` (an emptied ledger is \
         deleted). The lockfile points at the committed `.socket/vendor/` \
         files, and the pre-vendor lock values (including the hosted-spliced \
         fragment) are preserved as the vendor ledger's wiring originals, so \
         `vendor --revert` still restores the hosted lock wiring \
         byte-for-byte.{npmrc} Ledger data for other, still-redirected \
         package(s) was left untouched. No action needed."
    )
}

/// Drop the superseded purls' `records` + `edits` from the redirect ledger
/// and persist it (atomic write; an emptied ledger is deleted — the same
/// delete-when-empty contract every other persist follows). Called ONLY with
/// purls [`classify_overlap_takeover`] proved vendored-live AND hosted-dead
/// against the LIVE lockfile: the gate that makes the warning truthful is
/// the one that makes the drop lossless (the vendor ledger's wiring
/// `original` embeds the hosted-spliced fragment, so `vendor --revert` needs
/// nothing from these records). `Ok(Some(npmrc))` — reconciled, with the
/// outcome of the `.npmrc` allow-remote unwind (whether the file changed,
/// and its advisories for the caller to surface); `Ok(None)` when nothing
/// matched (degenerate — the caller falls back to the manual advisory
/// rather than claiming a reconciliation that did not happen); `Err` when
/// the ledger could not be read back or persisted (fail closed: the atomic
/// writer leaves the on-disk ledger either untouched or fully pre-drop, and
/// the caller surfaces the failure inside the warning).
async fn reconcile_superseded_redirect(
    cwd: &Path,
    purls: &[String],
) -> Result<Option<socket_patch_core::patch::redirect::npmrc::NpmrcStandaloneUnwind>, String> {
    let mut state = match socket_patch_core::patch::redirect::load_redirect_state(cwd).await {
        Ok(Some(state)) => state,
        Ok(None) => return Ok(None),
        Err(corrupt) => return Err(corrupt.to_string()),
    };
    let mut dropped = false;
    for purl in purls {
        dropped |= socket_patch_core::patch::redirect::drop_superseded_purl(&mut state, purl);
    }
    if !dropped {
        return Ok(None);
    }
    // The dropped npm purls may have been the last package-lock entries the
    // hosted `.npmrc` `allow-remote=all` auto-config served: unwind it
    // (created file deleted / appended line removed) before persisting, so
    // a hosted→vendored migration leaves no loosened install policy behind.
    // Vendored `file:` specs never needed it (npm gates them by
    // `allow-file`, default `all`).
    // Its outcome (and advisories such as
    // `redirect_npmrc_allow_remote_modified`) goes back to the caller.
    let npmrc =
        socket_patch_core::patch::redirect::npmrc::unwind_unneeded_npmrc(cwd, &mut state, false)
            .await?;
    socket_patch_core::patch::redirect::persist_redirect_state(cwd, &state)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(npmrc))
}

/// Record a run-level advisory: stderr `Warning (code): detail` in human
/// mode (informational, so muted by `--silent`) and `warnings[]` on the
/// envelope for JSON consumers. Shared by the vendored flows here and in
/// `vendor_flow.rs`.
pub(super) fn push_run_warning(
    env: &mut crate::json_envelope::Envelope,
    common: &GlobalArgs,
    code: &str,
    detail: String,
) {
    if !common.silent && !common.json {
        eprintln!("Warning ({code}): {detail}");
    }
    env.warnings.push(crate::json_envelope::RunWarning {
        code: code.to_string(),
        detail,
    });
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
    let superseded = classify_overlap_takeover(common, cwd).await.vendored;
    if superseded.is_empty() {
        return;
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
        push_run_warning(
            env,
            common,
            VENDOR_SUPERSEDES_REDIRECT,
            mode_takeover_detail(&manual, /*current_is_hosted=*/ false),
        );
    }
    if reconcilable.is_empty() {
        return;
    }
    match reconcile_superseded_redirect(cwd, &reconcilable).await {
        Ok(Some(npmrc)) => {
            push_run_warning(
                env,
                common,
                VENDOR_SUPERSEDES_REDIRECT,
                mode_takeover_reconciled_detail(&reconcilable, npmrc.file_changed),
            );
            // The `.npmrc` unwind's own advisories (a redirect-created file
            // the user has since added to: kept, only our line removed) —
            // surfaced like rollback / vendor surface them.
            for (code, detail) in npmrc.warnings {
                push_run_warning(env, common, &code, detail);
            }
        }
        // Nothing matched to drop — do not claim a reconciliation that did
        // not happen; hand out the manual remediation instead.
        Ok(None) => push_run_warning(
            env,
            common,
            VENDOR_SUPERSEDES_REDIRECT,
            mode_takeover_detail(&reconcilable, /*current_is_hosted=*/ false),
        ),
        Err(e) => push_run_warning(
            env,
            common,
            VENDOR_SUPERSEDES_REDIRECT,
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
/// redirect ledger records the purl AND lockfile discovery proves the
/// current lockfile still routes it to that hosted patch — core
/// `Discovery::redirect_record_live`, the same liveness rule `vex` gates
/// redirect-ledger attestations on.
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
    common: &GlobalArgs,
    redirect_state: Option<&socket_patch_core::patch::redirect::RedirectState>,
    scanned_purls: impl IntoIterator<Item = impl AsRef<str>>,
) -> Vec<String> {
    let Some(redirect) = redirect_state else {
        return Vec::new();
    };
    if redirect.records.is_empty() {
        return Vec::new();
    }
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let scanned: std::collections::BTreeSet<String> = scanned_purls
        .into_iter()
        .map(|p| canon(p.as_ref()))
        .collect();
    // Cheap no-I/O gate: only ledger records naming a scanned purl can ever
    // prove live wiring, so when none do (a zero/filtered discovery, or a
    // ledger about other packages) skip the lockfile proofs below entirely.
    let candidates: Vec<(String, &str)> = redirect
        .records
        .iter()
        .map(|(key, record)| (canon(key), record.uuid.as_str()))
        .filter(|(purl, _)| scanned.contains(purl))
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    let cwd = &common.cwd;
    let discovery = crate::commands::discover_wiring(common, cwd).await;
    let mut liveness = LedgerLiveness::new(cwd, &discovery, Some(redirect));
    let mut out = Vec::new();
    for (purl, uuid) in candidates {
        if liveness.redirect_record(&purl, uuid).await {
            out.push(purl);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Detail for [`HOSTED_WIRING_RETAINED`]. Names the package(s) and the
/// real options — stay hosted, migrate via the vendored flow (which
/// reconciles the superseded ledger entries per package), or unwind via
/// `rollback`. It must never advise hand-deleting the redirect ledger
/// (the only store of the pre-redirect originals plus the records VEX
/// reads).
pub(super) fn hosted_wiring_retained_detail(retained: &[String]) -> String {
    let list = retained.join(", ");
    format!(
        "agent-mode scan left the hosted redirect wiring live for: {list}. \
         The lockfile still resolves these package(s) to the hosted patch \
         server and `.socket/vendor/redirect-state.json` still records the \
         redirect — an agent run patches installed files in place but does \
         NOT unwind hosted lockfile wiring, so installs keep fetching \
         these package(s) from the patch server. Either keep the project \
         in hosted mode (`scan --mode hosted`), migrate to committed \
         artifacts with `scan --mode vendored` (which takes these \
         package(s) over in the lockfile and reconciles the superseded \
         redirect ledger entries), or unwind the redirects with \
         `socket-patch rollback`. Do not delete \
         `.socket/vendor/redirect-state.json` by hand: it holds the \
         recorded pre-redirect lockfile originals (the only revert data) \
         and the redirect records VEX reads."
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

/// Print the scan error envelope for a refusal before any scanning
/// (`--offline`): the all-batches-failed shape with every count at
/// zero, so JSON consumers see one consistent scan-error schema.
fn print_zero_error_envelope(err: &str, paths: &[String]) {
    let result = serde_json::json!({
        "status": "error",
        "error": err,
        "scannedPackages": 0,
        "lockfileOnlyPackages": 0,
        "packagesWithPatches": 0,
        "totalPatches": 0,
        "freePatches": 0,
        "paidPatches": 0,
        "canAccessPaidPatches": false,
        "packages": [],
        "updates": [],
        "paths": paths,
    });
    print_json(&result);
}

pub async fn run(mut args: ScanArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Fold the legacy mode booleans into `args.mode` before anything reads
    // it, so every branch below keeps a single source of truth (the enum;
    // the booleans are never consulted past this point). Cross-mode
    // combinations get a usage-style error (exit 2, matching clap's
    // conflict exit code) — see `resolve_mode_flags` for why clap itself
    // can't express them.
    // Usage errors (exit 2) print no JSON envelope, even under --json:
    // they behave like clap's own usage errors, which cannot print one
    // either (pinned by scan_paths_e2e::paths_with_hosted_or_vendored_mode_exit_2).
    if let Err(message) = resolve_mode_flags(&mut args) {
        eprintln!("Error: {message}");
        return 2;
    }

    // Positional PATH globs (see `ScanArgs::paths`). An unparseable glob
    // is a usage error, same exit-2 shape as the mode conflicts.
    let path_scope = match crate::path_scope::PathScope::parse(&args.paths) {
        Ok(s) => s,
        Err(message) => {
            eprintln!("Error: {message}");
            return 2;
        }
    };

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
            print_zero_error_envelope(err, path_scope.raw());
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
    let socket_dir = args.common.socket_dir();

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
    // Live only on a terminal; its result lines print whenever `human`.
    let human = !args.common.json && !args.common.silent;
    let mut status = StatusLine::stderr(args.common.json, args.common.silent);
    status.set(format!("Scanning {scan_target}..."));

    // Crawl packages
    let (mut all_crawled, mut eco_counts, skipped_bundle_config_path) =
        crawl_all_ecosystems(&crawler_options).await;

    // Lockfile supplement: dependencies the project's lockfile resolves
    // that have NO installed copy (fresh clone, partial install). They join
    // discovery — counts, API lookup, table, the prune "scanned" set — and
    // are flagged "not yet installed" everywhere a user could act on them.
    let lockfile_only = lockfile_supplement(&args.common, &all_crawled).await;
    // Discovery diagnoses unsupported installation layouts and malformed
    // binary Bun locks. Preserve these on empty scans too: an unreadable
    // graph is not evidence that a fresh checkout has no dependencies.
    // Surface them as run-level JSON warnings and human stderr messages.
    let mut layout_refusals = unsupported_layout_warnings(&lockfile_only.unsupported);
    // Config-sourced gem bundle root refused by the crawler's containment
    // guard (a committed `.bundle/config` whose BUNDLE_PATH resolves
    // outside the project — untrusted input that would otherwise become a
    // scan/apply WRITE-target root). The crawl above consulted and
    // silently skipped it, handing the skip back (local mode only); surface
    // it on the SAME run-level channel as the layout refusals (JSON
    // `warnings[]` on both the zero-package and ≥1-package envelopes; a
    // gated stderr line on the human path) unless `--ecosystems` filtered
    // gem out of this run.
    if let Some(value) = skipped_bundle_config_path {
        if args
            .common
            .ecosystems
            .as_ref()
            .is_none_or(|list| list.iter().any(|e| e == Ecosystem::Gem.cli_name()))
        {
            let (code, detail) = config_path_ignored_warning(&value);
            layout_refusals.push((code.to_string(), detail));
        }
    }
    // Supplement purls, captured for the path-scope filter below: their
    // `path` fields are fabricated placeholders, so a path-scoped scan
    // excludes them (with a counted warning) instead of glob-matching
    // meaningless paths.
    let mut supplement_purls: HashSet<String> = HashSet::new();
    if !lockfile_only.packages.is_empty() {
        for pkg in &lockfile_only.packages {
            if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
                *eco_counts.entry(eco).or_insert(0) += 1;
            }
            supplement_purls.insert(pkg.purl.clone());
        }
        all_crawled.extend(lockfile_only.packages.iter().cloned());
    }
    // The vendor ledger, loaded ONCE and shared by the supplement here, the
    // prune-exemption / vendored-skip key set below, and update detection —
    // three read-only consumers of the same bytes. Their failure policies
    // stay distinct on purpose: the supplement falls back to the committed
    // artifacts (fail-closed for the prune), the key set degrades to empty
    // (fail-open, its documented contract).
    let vendor_state = socket_patch_core::vendor::load_state(&args.common.cwd).await;
    let ledger_supplement =
        vendored_ledger_supplement(&args.common, &all_crawled, &vendor_state).await;
    for pkg in &ledger_supplement {
        if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
            *eco_counts.entry(eco).or_insert(0) += 1;
        }
        supplement_purls.insert(pkg.purl.clone());
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

    // Vendor-ledger purl keys (from the single load above), shared by the
    // prune exemption (a vendored package is consumed from the committed
    // artifact, so "absent from the crawl" is its normal state, not
    // grounds for pruning) and the vendored-skip in the apply path. A
    // corrupt ledger degrades to the EMPTY set — fail-open by the key set's
    // documented contract (the supplement above is the fail-closed half).
    let vendored_purls: HashSet<String> = vendor_state
        .as_ref()
        .map(VendorState::purl_keys)
        .unwrap_or_default();

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

    // PATH scoping — applied strictly AFTER the `scanned_purls` capture
    // above (the prune universe stays full-crawl: `scan PATHS --prune`
    // must never treat out-of-scope packages as uninstalled) and after the
    // `--ecosystems` filter. A purl is in scope when ANY genuinely-crawled
    // copy of it sits under a matching path.
    let filtered_crawled: Vec<_> = if path_scope.is_empty() {
        filtered_crawled
    } else {
        let excluded_supplements = filtered_crawled
            .iter()
            .filter(|pkg| supplement_purls.contains(&pkg.purl))
            .count();
        if excluded_supplements > 0 {
            layout_refusals.push((
                "path_scope_excluded_supplements".to_string(),
                format!(
                    "{} no installed path and {} excluded from the path-scoped scan",
                    if excluded_supplements == 1 {
                        "1 lockfile-only/vendor-ledger package has".to_string()
                    } else {
                        format!("{excluded_supplements} lockfile-only/vendor-ledger packages have")
                    },
                    if excluded_supplements == 1 { "was" } else { "were" },
                ),
            ));
        }
        let scope = path_scope.bind(&args.common.cwd);
        let in_scope: HashSet<String> = filtered_crawled
            .iter()
            .filter(|pkg| !supplement_purls.contains(&pkg.purl))
            .filter(|pkg| scope.matches(&pkg.path))
            .map(|pkg| pkg.purl.clone())
            .collect();
        filtered_crawled
            .into_iter()
            .filter(|pkg| in_scope.contains(&pkg.purl))
            .collect()
    };

    let all_purls: Vec<String> = filtered_crawled.iter().map(|p| p.purl.clone()).collect();
    let package_count = all_purls.len();

    if package_count == 0 {
        status.finish();
        if human {
            for (code, detail) in &layout_refusals {
                eprintln!("Warning ({code}): {detail}");
            }
            // The JSON path skips the GC here too (see below); the human
            // path says so instead of silently dropping `--prune`. Hosted
            // mode already printed its own prune-ignored warning.
            if prune && !hosted {
                eprintln!("{}", render::PRUNE_SKIPPED_EMPTY);
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
                "paths": path_scope.raw(),
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
                    warnings.push(hosted::prune_ignored_warning());
                }
                result["redirect"] = hosted::redirect_json_block(
                    0,
                    Vec::new(),
                    Vec::new(),
                    warnings,
                    args.common.dry_run,
                );
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
            print_json(&result);
            return code;
        } else if !args.common.silent {
            // Errors only under --silent: the empty-scan hint is
            // informational.
            println!(
                "{}",
                render::no_packages_message(
                    args.common.global || args.common.global_prefix.is_some(),
                    args.common.ecosystems.as_deref(),
                    &args.paths,
                )
            );
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Keep discovery format errors on non-empty scans in every mode as
    // well: installed packages do not make an unreadable lockfile safe.

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

    status.finish_with(format!(
        "Found {}{eco_summary}",
        plural(package_count, "package", "packages")
    ));
    if human {
        if !lockfile_only.purls.is_empty() {
            eprintln!("{}", render::lockfile_only_note(lockfile_only.purls.len()));
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

    for (batch_idx, chunk) in all_purls.chunks(batch_size).enumerate() {
        status.set(format!(
            "Querying API for patches... (batch {}/{total_batches})",
            batch_idx + 1
        ));

        let mut result = api_client.search_patches_batch(chunk).await;

        // Fallback: a 401/403 against the authenticated endpoint can
        // mean a stale/revoked token. Retry against the public proxy
        // (free patches only) once, then continue the rest of the
        // loop with the downgraded client. Only triggers on the
        // first authenticated batch; subsequent iterations are
        // already on the proxy.
        if !use_public_proxy {
            if let Err(ref e) = result {
                if is_fallback_candidate(e) {
                    // Errors-only under --silent; --json keeps it on stderr
                    // (the envelope has no slot for a mid-run downgrade).
                    if !args.common.silent {
                        status.println(format!(
                            "Warning: authenticated API returned {e}; \
                             falling back to public patch API proxy (free patches only)."
                        ));
                    }
                    api_client = build_proxy_fallback_client(&overrides);
                    use_public_proxy = true;
                    fallback_to_proxy = true;
                    result = api_client.search_patches_batch(chunk).await;
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
                // Not fatal by itself: the scan goes on with the other
                // batches. A one-batch scan says it once, below.
                if !args.common.json && !args.common.silent && total_batches > 1 {
                    status.println(render::batch_failed_warning(
                        batch_idx + 1,
                        total_batches,
                        &e.to_string(),
                    ));
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
        status.finish();
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
                "lockfileOnlyPackages": lockfile_only.purls.len(),
                "packagesWithPatches": 0,
                "totalPatches": 0,
                "freePatches": 0,
                "paidPatches": 0,
                "canAccessPaidPatches": false,
                "packages": [],
                "updates": [],
                "paths": path_scope.raw(),
            });
            print_json(&result);
        } else {
            eprintln!("{}", render::all_batches_failed(total_batches, &err));
        }
        return 1;
    }

    let total_patches_found: usize = all_packages_with_patches
        .iter()
        .map(|p| p.patches.len())
        .sum();

    if total_patches_found > 0 {
        status.finish_with(format!(
            "Found {} for {}",
            plural(total_patches_found, "patch", "patches"),
            plural(all_packages_with_patches.len(), "package", "packages")
        ));
    } else {
        // The result line ("No patches available for installed packages.")
        // is printed on stdout below; saying it here too would repeat it.
        status.finish();
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

    // Read existing manifest once for update detection. Used by both the
    // JSON-mode emission (always includes an `updates` array) and the
    // non-JSON table-print path (counts `updates_available`).
    // (`manifest_path`/`socket_dir` are resolved at the top of `run`.)
    let existing_manifest = read_manifest(&manifest_path).await.ok().flatten();
    // Hosted and vendored modes record their patches ONLY in their ledgers
    // (neither writes the manifest), so fold both ledgers' purl→uuid records
    // into the view update detection sees — otherwise a pure hosted or
    // vendored project's `updates[]` (the documented CI signal) stays
    // structurally empty and a superseding patch is never reported. The
    // envelope schema is unchanged. A malformed redirect ledger is only
    // warned about here (and muted by --silent — the warning is advisory)
    // — this is a read-only consult; a malformed vendor ledger contributes
    // nothing (the supplement above already recovered its purls from the
    // committed artifacts). A HOSTED run does not warn here: its engine
    // loads the same ledger strictly, under the apply lock when it holds
    // one, and reports the corruption ONCE as the hard error it is, so the
    // advisory here would only duplicate that message. But the human hosted
    // arm has returns BEFORE the engine (empty discovery, nothing
    // downloadable, a detail-fetch failure, a declined confirm) where nobody
    // would report it — so the corruption text is kept and printed at those
    // returns (`warn_unreported_corrupt_ledger`), never quarantined (a
    // read-only consult; quarantine is the engine's under-lock job).
    let (redirect_state, hosted_corrupt_ledger) = if hosted {
        match socket_patch_core::patch::redirect::load_redirect_state(&args.common.cwd).await {
            Ok(state) => (state, None),
            Err(corrupt) => (None, Some(corrupt.to_string())),
        }
    } else {
        (
            crate::commands::load_redirect_state_lenient(&args.common.cwd, args.common.silent)
                .await,
            None,
        )
    };
    let update_manifest = merge_ledger_records_for_updates(
        existing_manifest.as_ref(),
        redirect_state.as_ref(),
        vendor_state.as_ref().ok(),
    );
    let updates = detect_updates(update_manifest.as_deref(), &all_packages_with_patches);

    // The hosted-wiring probes below (`wiringLive`, the agent-flow
    // `hosted_wiring_retained` warning) take `all_purls` — the POST-filter
    // scanned set: they only ever name packages this run actually
    // counted/queried (an `--ecosystems` filter narrows both — a
    // filtered-out purl reads as "not covered this run", never as "wiring
    // unwound"). Distinct from `scanned_purls` above, which deliberately
    // stays PRE-filter for the GC prune (see its comment).

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
            "paths": path_scope.raw(),
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
        // The live-wiring probe (lockfile discovery, behind its cheap
        // no-I/O gate) runs ONCE here and is shared with the agent-flow
        // warning in the apply branch below.
        let hosted_retained = if vendor {
            Vec::new()
        } else {
            hosted_wiring_retained_purls(&args.common, redirect_state.as_ref(), &all_purls).await
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
                &all_packages_with_patches,
                can_access_paid_patches,
                &args.common,
                false,
                false,
            )
            .await
            {
                Ok(s) => s,
                Err((code, message)) => {
                    emit_discovery_error_json(&mut result, &message);
                    return code;
                }
            };

            // Vendor-owned and lockfile-only purls leave the selection as
            // calm skip records BEFORE download (see `partition_agent_
            // selection`); the vendored purls alone feed the run-level
            // `vendored_ownership_retained` warning emitted after apply.
            let AgentSelection {
                kept: selected,
                skip_records: vendored_records,
                vendored_purls: vendored_skip_purls,
                ..
            } = partition_agent_selection(selected, &vendored_purls, &lockfile_only);

            if dry {
                // Synthesize the per-patch outcome without touching disk.
                // `decide_patch_action` consults the existing manifest,
                // so it accurately reports what `--apply` *would* do.
                let empty_manifest = PatchManifest::new();
                let manifest_for_preview = existing_manifest.as_ref().unwrap_or(&empty_manifest);
                let mut patches: Vec<serde_json::Value> = selected
                    .iter()
                    .map(|p| {
                        match super::get::decide_patch_action(
                            manifest_for_preview,
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
                let (code, apply_json) = download_and_apply_patches_with(
                    &selected,
                    &params,
                    &download_run(&args, &api_client),
                )
                .await;
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
                use_public_proxy,
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
        print_json(&result);
        return final_code;
    }

    let use_color = ui::stdout_color();
    let verbose = args.common.verbose;
    let silent = args.common.silent;

    // Every human-path exit that did not fail: the `--prune` GC first
    // (agent mode only: the vendored step runs its own GC and hosted mode
    // runs none), then the embedded VEX. The JSON path runs the GC whether
    // or not anything was applied, and so does this one: an early "nothing
    // to apply" exit must not silently drop `--prune`.
    let (args_ref, manifest_ref, socket_ref) = (&args, &manifest_path, &socket_dir);
    let (scanned_ref, vendored_ref) = (&scanned_purls, &vendored_purls);
    let finish_human = move |code: i32| async move {
        if prune && !vendor && !hosted && code == 0 {
            gc::run_human_gc(
                &args_ref.common,
                manifest_ref,
                socket_ref,
                scanned_ref,
                vendored_ref,
            )
            .await;
        }
        embed_vex_human(&args_ref.common, &args_ref.vex, manifest_ref, code).await
    };

    // Every mode stops on an empty discovery — vendored mode included: scan
    // vendors what THIS discovery selects (a fresh clone or wiped
    // `.socket/vendor/` is `repair`'s job, from the committed ledger), so
    // there is nothing for its vendor step to do and reaching it would only
    // take the apply lock for a no-op.
    if all_packages_with_patches.is_empty() {
        if !silent {
            println!("\nNo patches available for installed packages.");
        }
        warn_unreported_corrupt_ledger(&args.common, hosted_corrupt_ledger.as_deref());
        return finish_human(0).await;
    }

    // The whole table + summary section is presentational only (nothing
    // computed inside is consumed downstream), so `--silent` skips it
    // wholesale.
    if !silent {
        let mut updates_available = 0usize;

        // Canonical set of PURLs with a newer patch available, computed once via
        // `detect_updates` (the same source the JSON `updates` array uses). The
        // table path MUST agree with the JSON path, so reuse that result rather
        // than re-deriving it: comparing against *any* batch patch (instead of the
        // first/candidate one `select_patches` would resolve to) over-reports
        // updates whenever the manifest already holds the newest patch but older
        // patches also appear in the batch.
        let update_purls: HashSet<&str> = updates.iter().map(|u| u.purl.as_str()).collect();

        // Human display only: the decoded PURL (`%40scope` → `@scope`), like
        // the "Patches to apply" preview. The PACKAGE column is as wide as
        // the longest one (capped); longer ones keep their `@version`.
        let shown_purls: Vec<String> = all_packages_with_patches
            .iter()
            .map(|p| normalize_purl(&p.purl).into_owned())
            .collect();
        let purl_w = render::purl_col_width(shown_purls.iter().map(String::as_str));

        let mut rows: Vec<String> = Vec::with_capacity(all_packages_with_patches.len());
        for (pkg, shown) in all_packages_with_patches.iter().zip(&shown_purls) {
            let display_purl = render::elide_purl(shown, purl_w);

            let pkg_free = pkg.patches.iter().filter(|p| p.tier == "free").count();
            let pkg_paid = pkg.patches.iter().filter(|p| p.tier == "paid").count();

            let count_str = if pkg_paid > 0 {
                if can_access_paid_patches {
                    format!("{}+{}", pkg_free, pkg_paid)
                } else {
                    format!(
                        "{}+{}",
                        pkg_free,
                        ui::paint(&pkg_paid.to_string(), "33", use_color)
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
            // each group sorted, aliases not counted — see collect_vuln_ids).
            let vuln_str = render::vuln_cell(&collect_vuln_ids(pkg), verbose);

            // Check for updates — consult the canonical `detect_updates` result
            // (mirrored into `update_purls`) so the human table and JSON `updates`
            // array never disagree.
            let has_update = update_purls.contains(pkg.purl.as_str());
            if has_update {
                updates_available += 1;
            }

            let update_marker = if has_update {
                ui::paint(" [UPDATE]", "33", use_color)
            } else {
                String::new()
            };
            // Lockfile-only packages can be patched by `scan --mode vendored`
            // (which fetches them pristine) but not applied in place.
            // `normalize_purl` bridges the API's percent-encoded spelling
            // to the supplement's literal form, like the JSON flag and the
            // apply-path skip partitions.
            let not_installed_marker = if lockfile_only_contains(&lockfile_only.purls, &pkg.purl) {
                ui::paint(" [NOT INSTALLED]", "33", use_color)
            } else {
                String::new()
            };

            rows.push(render::table_row(
                purl_w,
                &display_purl,
                &count_str,
                &ui::severity(severity, use_color),
                &vuln_str,
                &format!("{update_marker}{not_installed_marker}"),
            ));
        }

        // The rule is as wide as the table, but never wraps a terminal.
        let header = render::table_header(purl_w);
        let cap = std::io::stdout()
            .is_terminal()
            .then(ui::stdout_width);
        let rule = render::ruler(
            std::iter::once(header.as_str()).chain(rows.iter().map(String::as_str)),
            cap,
        );
        println!("\n{rule}");
        println!("{header}");
        println!("{rule}");
        for row in &rows {
            println!("{row}");
        }
        println!("{rule}");

        // Summary
        let with_patches = all_packages_with_patches.len();
        if can_access_paid_patches {
            println!(
                "\n{}",
                render::summary_line(with_patches, total_patches, true)
            );
        } else {
            println!(
                "\n{}",
                render::summary_line(with_patches, free_patches, false)
            );
            if paid_patches > 0 {
                println!(
                    "{}",
                    ui::paint(&render::paid_extra_line(paid_patches), "33", use_color),
                );
                println!(
                    "\nUpgrade to Socket's paid plan to access all patches: https://socket.dev/pricing"
                );
            }
        }

        if updates_available > 0 {
            println!(
                "\n{}",
                ui::paint(&render::updates_line(updates_available), "33", use_color),
            );
        }
    }

    // Registry-redirect (hosted) mode is a distinct, self-contained flow
    // (rewrite lockfiles → hosted vendored patches). It reuses the
    // discovery, table and update detection above, confirms, then hands
    // the selection to the redirect engine — it must NOT fall through to
    // the apply/vendor branches. Same discovery/selection as `run_redirect`
    // (the `--json` arm, which returned above with the redirect result
    // NESTED in its envelope) and the same engine entry as `get --mode
    // hosted`.
    // Count downloadable patches. Shared by the hosted arm below and the
    // agent/vendored arms: a free-tier org whose every offer is paid-tier has
    // nothing any mode could select, so every human arm stops here with the
    // same paid-subscription line instead of entering its engine for a
    // no-op (hosted would otherwise print `Redirected 0 packages`).
    let downloadable_count = if can_access_paid_patches {
        all_packages_with_patches.len()
    } else {
        all_packages_with_patches
            .iter()
            .filter(|pkg| pkg.patches.iter().any(|p| p.tier == "free"))
            .count()
    };

    if downloadable_count == 0 {
        if !silent {
            println!("\nNo downloadable patches (paid subscription required).");
        }
        warn_unreported_corrupt_ledger(&args.common, hosted_corrupt_ledger.as_deref());
        return finish_human(0).await;
    }

    if hosted {
        let selected = match discover_selected(
            &api_client,
            &all_packages_with_patches,
            can_access_paid_patches,
            &args.common,
            human,
            !silent,
        )
        .await
        {
            Ok(s) => s,
            // `discover_selected` already printed the failure to stderr.
            Err((code, _)) => {
                warn_unreported_corrupt_ledger(&args.common, hosted_corrupt_ledger.as_deref());
                return code;
            }
        };
        // The engine honors `--dry-run` itself (a preview mutates nothing),
        // so only a wet run with work confirms. `--mode hosted` is explicit
        // intent, so a non-TTY run auto-proceeds like every other mode —
        // only the mode-less scan below is report-only.
        if !selected.is_empty() && !args.common.dry_run {
            let prompt = render::hosted_confirm_prompt(selected.len());
            // The prompt (or the non-TTY note) opens its own paragraph
            // under the table's Summary, on the prompt's stream.
            if !silent && !args.common.yes {
                eprintln!();
            }
            if !ui::confirm(&prompt, true, &args.common) {
                if !silent {
                    println!();
                    for line in render::hosted_decline_hint() {
                        println!("{line}");
                    }
                }
                warn_unreported_corrupt_ledger(&args.common, hosted_corrupt_ledger.as_deref());
                return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
            }
        }
        let pairs: Vec<(String, String)> = selected
            .iter()
            .map(|s| (s.purl.clone(), s.uuid.clone()))
            .collect();
        return boxed_run_redirect_selected(
            &args.common,
            &args.vex,
            prune,
            &api_client,
            &pairs,
            None,
        )
        .await;
    }

    // Fetch the full per-package patch lists — the same loop the JSON arms
    // run through `discover_selected`, here with progress + per-package
    // warnings. Discovery said these packages HAVE patches, so an empty
    // merged set is a fetch failure.
    let (all_search_results, detail_failures) =
        fetch_patch_details(&api_client, &all_packages_with_patches, human, !silent).await;
    if all_search_results.is_empty() {
        eprintln!("{}", render::fetch_details_failed(&detail_failures));
        return 1;
    }

    // Prompt to download. A MODE-LESS human scan (no `--mode`/`--apply`/
    // `--sync`/`--vendor`/`--redirect` and no `--prune`) with a non-TTY
    // stdin and no `--yes` is report-only: it stops before the prompt with
    // exit 0 and a hint, never downloads, never creates `.socket/`. This is
    // a scan-side pre-check — `confirm()` itself keeps its non-TTY
    // auto-accept, so every explicit-intent flag (and every other command's
    // prompt) still proceeds unattended, and a TTY always prompts.
    let report_only = args.mode.is_none() && !args.prune && !args.common.yes && !ui::stdin_is_tty();

    // Smart selection. A report-only run picks without the non-interactive
    // note: it never downloads, so there is no pick to announce.
    let mut select_common = selection_args(&args.common);
    select_common.silent |= report_only;
    // A menu or the non-interactive note opens its own paragraph under the
    // table's Summary (stderr, like the prompt).
    if !select_common.silent
        && super::get::selection_has_choice(
            &all_search_results,
            can_access_paid_patches,
            &select_common,
        )
    {
        eprintln!();
    }
    let selected: Vec<PatchSearchResult> =
        match select_patches(&all_search_results, can_access_paid_patches, &select_common) {
            Ok(s) => s,
            Err(code) => return code,
        };

    // The skip / already-recorded lines below open their own paragraph
    // under the table's Summary: one blank line before the first of them.
    let mut skip_paragraph = false;

    // Agent flow (mirrors the JSON arm): vendor-owned and lockfile-only
    // purls leave the selection as calm skips. In vendored mode nothing is
    // partitioned — re-vendoring a stale uuid is exactly what the mode is
    // for, and the vendor engine fetches lockfile-resolved packages
    // pristine.
    let selected = if vendor {
        selected
    } else {
        let split = partition_agent_selection(selected, &vendored_purls, &lockfile_only);
        if !silent {
            for purl in &split.vendored_purls {
                open_paragraph(&mut skip_paragraph);
                println!("{}", render::vendored_skip_line(&normalize_purl(purl)));
            }
            for purl in &split.not_installed_purls {
                open_paragraph(&mut skip_paragraph);
                println!("{}", render::not_installed_skip_line(&normalize_purl(purl)));
            }
        }
        split.kept
    };

    // A selection the manifest already records at the same uuid would be
    // downloaded only to be skipped ("already in manifest") — don't offer
    // it. Agent mode only: vendored mode never reads the manifest.
    let recorded = |p: &PatchSearchResult| {
        existing_manifest
            .as_ref()
            .and_then(|m| m.patches.get(&p.purl))
            .is_some_and(|r| r.uuid == p.uuid)
    };
    let (already_recorded, selected): (Vec<_>, Vec<_>) = if vendor {
        (Vec::new(), selected)
    } else {
        selected.into_iter().partition(|p| recorded(p))
    };
    if !silent {
        for p in &already_recorded {
            open_paragraph(&mut skip_paragraph);
            println!(
                "{}",
                render::already_recorded_line(&normalize_purl(&p.purl), &p.uuid)
            );
        }
    }

    if selected.is_empty() {
        if !silent {
            open_paragraph(&mut skip_paragraph);
            if already_recorded.is_empty() {
                println!("No patches selected.");
            } else {
                println!("{}", render::ALL_ALREADY_RECORDED);
            }
        }
        return finish_human(0).await;
    }

    // Display detailed summary of selected patches before confirming
    // (presentational only — skipped wholesale under --silent).
    if !silent {
        if vendor {
            println!("\nPatches to vendor:\n");
        } else {
            println!("\nPatches to apply:\n");
        }
        for patch in &selected {
            let severity =
                ui::severity(render::highest_severity(patch).unwrap_or("unknown"), use_color);
            // The manifest already records a different patch for this
            // package: say so, and warn when the new one fixes less. Agent
            // mode only: vendored mode never writes the manifest.
            let replaces = existing_manifest
                .as_ref()
                .filter(|_| !vendor)
                .and_then(|m| m.patches.get(&patch.purl))
                .filter(|r| r.uuid != patch.uuid)
                .map(|r| render::Replaces {
                    uuid: &r.uuid,
                    vuln_ids: r.vulnerabilities.keys().map(String::as_str).collect(),
                });
            let block = render::PatchBlock {
                patch,
                severity: &severity,
                replaces,
                verbose,
            };
            // The block is a result (stdout); a downgrade warning goes to
            // stderr, right under the block's first line.
            let warning = render::replacement_warning(&block);
            for (i, line) in render::patch_block(&block).iter().enumerate() {
                println!("{line}");
                if i == 0 {
                    if let Some(w) = &warning {
                        eprintln!("{w}");
                    }
                }
            }
        }
    }

    // What the prompt / dry-run line offers.
    let plan = if vendor {
        render::Plan::Vendor(selected.len())
    } else {
        render::Plan::Apply(selected.len())
    };

    // `--dry-run` is a non-mutating preview (see the global flag's doc and
    // the JSON path's `dryRun` envelope). The interactive path must honor it
    // too: stop here, having printed the table and the per-patch plan above,
    // before the confirm prompt, the download/apply, and the prune GC — all
    // of which mutate the manifest and `.socket/` on disk (the GC runs as a
    // read-only preview instead).
    if args.common.dry_run {
        if !silent {
            // Vendored preview: the same ledger classification the JSON arm
            // nests under `vendor`, rendered as `[would-refuse]` lines so a
            // human preview never advertises vendoring the wet run's Bun
            // preflight is known to refuse (the `get --mode vendored
            // --dry-run` arms print the identical lines). The headline
            // counts them too.
            let preview = if vendor {
                Some(preview_vendor_json(&args.common.cwd, &selected).await)
            } else {
                None
            };
            let refused = preview
                .as_ref()
                .and_then(|p| p["patches"].as_array())
                .map_or(0, |a| {
                    a.iter().filter(|p| p["action"] == "would_refuse").count()
                });
            println!("{}", render::dry_run_line(plan, refused));
            if let Some(preview) = &preview {
                print_dry_run_refusals(preview);
            }
        }
        return finish_human(0).await;
    }

    // Report-only (see `report_only` above): stop before the prompt.
    if report_only {
        // The "Patches to apply:" listing already ends with a blank line.
        if !silent {
            for line in render::decline_hint(false) {
                println!("{line}");
            }
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Vendor mode: pre-verify baselines so a content mismatch surfaces
    // BEFORE the confirm prompt (vendoring still proceeds for these — the
    // stage force-applies the verified patched content). Runs after the
    // dry-run return above so a preview fetches no views; the views it
    // does fetch seed the download phase, which never fetches them again.
    let prefetched = if vendor && !silent {
        let (mismatched, views) = preverify_vendor_baselines(
            &api_client,
            &selected,
            &filtered_crawled,
            &lockfile_only.purls,
            vendor_state.as_ref().ok().map(|s| &s.entries),
            &mut status,
        )
        .await;
        let mut any_mismatch = false;
        for patch in selected.iter().filter(|p| mismatched.contains(&p.uuid)) {
            println!(
                "{}",
                render::baseline_mismatch_line(&normalize_purl(&patch.purl))
            );
            any_mismatch = true;
        }
        // Keep the prompt its own paragraph, as in the other flows.
        if any_mismatch {
            println!();
        }
        views
    } else {
        HashMap::new()
    };

    if !ui::confirm(&render::confirm_prompt(plan), true, &args.common) {
        if !silent {
            println!();
            for line in render::decline_hint(vendor) {
                println!("{line}");
            }
            if prune {
                eprintln!("{}", render::PRUNE_SKIPPED_DECLINED);
            }
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Download, then apply in place — or vendor (vendored mode, where the
    // download only saves and the vendor step below does the rest).
    let params = download_params(
        &args,
        /*save_only=*/ vendor,
        /*json=*/ false,
        silent,
    );

    let code = if vendor {
        // Extracted + boxed for the same Windows-1-MiB-frame reason as the
        // JSON path (see `run_vendor_json_path`).
        boxed_vendor_interactive_path(
            &args,
            &api_client,
            use_public_proxy,
            &selected,
            &params,
            prefetched,
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
        let (code, _) =
            download_and_apply_patches_with(&selected, &params, &download_run(&args, &api_client))
                .await;
        code
    };

    // Cross-mode visibility, mirroring the JSON apply path: after an
    // in-place apply, warn when the hosted redirect wiring is still live
    // for scanned package(s) — the apply cannot unwind it, and silence
    // reads as a completed hosted→agent conversion that never happened.
    // (The vendored-ownership counterpart is already printed per package
    // by the `[skip] … (vendored …)` lines above.)
    if !vendor && !silent {
        let hosted_retained =
            hosted_wiring_retained_purls(&args.common, redirect_state.as_ref(), &all_purls).await;
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
    // run `socket-patch gc` (or `repair`) explicitly. (Vendor mode runs
    // its own GC after the vendor step, inside `vendor_flow`.)
    if prune && !vendor {
        gc::run_human_gc(
            &args.common,
            &manifest_path,
            &socket_dir,
            &scanned_purls,
            &vendored_purls,
        )
        .await;
    }

    embed_vex_human(&args.common, &args.vex, &manifest_path, code).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load-then-derive form of [`overlap_from_states`]: the unit
    /// tests' entry point (production classifies over ledgers it already
    /// holds via `classify_overlap_takeover_with`). A malformed redirect
    /// ledger classifies like a missing one — this path only feeds takeover
    /// WARNINGS; the corruption itself is a hard error on every path that
    /// would write or attest from the ledger.
    async fn overlapping_ledger_purls(cwd: &Path) -> Vec<String> {
        let redirect = socket_patch_core::patch::redirect::load_redirect_state(cwd)
            .await
            .ok()
            .flatten();
        let Ok(vendor) = socket_patch_core::vendor::load_state(cwd).await else {
            return Vec::new();
        };
        overlap_from_states(redirect.as_ref(), &vendor)
    }
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
    fn selection_args_never_leaves_json_at_the_patch_menu() {
        let json = selection_args(&GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        });
        assert!(!json.json && json.yes, "--json selects like --yes");
        let human = selection_args(&GlobalArgs::default());
        assert!(!human.json && !human.yes, "a human run keeps its menu");
        let yes = selection_args(&GlobalArgs {
            yes: true,
            ..GlobalArgs::default()
        });
        assert!(yes.yes);
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
    /// lets the ledger-file fallback scan the lock).
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

    /// `GlobalArgs` rooted at `root` (the classifiers read the live
    /// lockfiles there; `json` keeps stderr quiet).
    fn common_at(root: &Path) -> GlobalArgs {
        GlobalArgs {
            cwd: root.to_path_buf(),
            json: true,
            ..GlobalArgs::default()
        }
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
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default()
        );

        // …but the agent flow's direct probe sees it for scanned purls.
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();
        let ledger = load_ledger(root).await;
        let retained =
            hosted_wiring_retained_purls(&common_at(root), ledger.as_ref(), &scanned).await;
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
            hosted_wiring_retained_purls(&common_at(tmp.path()), ledger.as_ref(), &scanned)
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
            hosted_wiring_retained_purls(&common_at(tmp.path()), ledger.as_ref(), &scanned)
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
            hosted_wiring_retained_purls(&common_at(tmp.path()), ledger.as_ref(), &other)
                .await
                .is_empty(),
            "unscanned purl ⇒ silent"
        );

        // (d) No ledger at all.
        let tmp = tempfile::tempdir().unwrap();
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        assert!(
            hosted_wiring_retained_purls(&common_at(tmp.path()), None, &scanned)
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
        let wiring =
            hosted_wiring_retained_purls(&common_at(tmp.path()), ledger.as_ref(), &scanned).await;
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

        // Live lock present too: the same purl graduates into wiringLive
        // (a fresh run re-parses the inventory, so re-take it here).
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        let wiring =
            hosted_wiring_retained_purls(&common_at(tmp.path()), ledger.as_ref(), &scanned).await;
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
        // A recorded yarn.lock edit + a lock entry resolving the scoped
        // package from its hosted artifact — live hosted wiring for the
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
        tokio::fs::write(
            tmp.path().join("yarn.lock"),
            format!(
                "# yarn lockfile v1\n\n\n\"@scope/pkg@^1.0.0\":\n  version \"1.0.0\"\n  \
                 resolved \"https://patch.socket.dev/patch/npm/@scope/pkg/1.0.0/tok/\
                 {TAKEOVER_UUID}/pkg-1.0.0.tgz#aaaa\"\n  integrity sha512-fake==\n"
            ),
        )
        .await
        .unwrap();

        let scanned: HashSet<String> = [scoped_canon.to_string()].into_iter().collect();
        let ledger = load_ledger(tmp.path()).await;
        let wiring =
            hosted_wiring_retained_purls(&common_at(tmp.path()), ledger.as_ref(), &scanned).await;
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
    /// A self-hosted patch server's sparse index (the probe must not depend
    /// on the patch.socket.dev host; discovery counts the operator's
    /// `--patch-server-url` origin, see [`cargo_common_at`]).
    const CARGO_INDEX: &str =
        "sparse+http://127.0.0.1:5555/patch-registry/cargo/tok/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/index/";

    /// [`common_at`] with the self-hosted patch server of [`CARGO_INDEX`].
    fn cargo_common_at(root: &Path) -> GlobalArgs {
        GlobalArgs {
            patch_server_url: Some("http://127.0.0.1:5555".to_string()),
            ..common_at(root)
        }
    }

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

        let takeover = classify_overlap_takeover(&cargo_common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&cargo_common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&cargo_common_at(root), root).await;
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
    /// the lock still points at the committed `.socket/vendor/` artifact —
    /// and names the artifact the npm backend writes for the package
    /// (`<name>-<version>.tgz`, what [`write_lock_pointing_at_vendored`]
    /// wires).
    async fn write_vendor_ledger_wired(root: &Path, purls: &[&str]) {
        let entries: serde_json::Map<String, serde_json::Value> = purls
            .iter()
            .map(|purl| {
                let (name, version) = purl_name_version(purl).expect("pkg:npm/<name>@<version>");
                (
                    (*purl).to_string(),
                    serde_json::json!({
                        "ecosystem": "npm",
                        "basePurl": purl,
                        "uuid": TAKEOVER_UUID,
                        "artifact": {
                            "path": format!(
                                ".socket/vendor/npm/{TAKEOVER_UUID}/{name}-{version}.tgz"
                            ),
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
    /// server — hosted is what the lock actually wires (the artifact url
    /// carries the patch uuid, like every url the hosted rewriter writes).
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
                        "https://patch.socket.dev/patch/npm/{name}/{version}/tok/{TAKEOVER_UUID}/\
                         {name}-{version}.tgz"
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

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
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
        let takeover = classify_overlap_takeover(&common_at(root), root).await;
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

        let before = classify_overlap_takeover(&common_at(root), root).await;
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

        let after = classify_overlap_takeover(&common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
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

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
        assert!(
            takeover.redirect.is_empty(),
            "a vendored-path uuid must not prove hosted: {takeover:?}"
        );
        assert_eq!(
            takeover.vendored,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
    }

    // ---- takeover detection degradation: corrupt / probe-less ledgers ------

    #[tokio::test]
    async fn corrupt_vendor_state_json_degrades_to_no_overlap() {
        // A hand-corrupted (or torn mid-write) `.socket/vendor/state.json`
        // must classify like a missing one: this path only feeds takeover
        // WARNINGS, and the vendored write paths hard-error on corruption
        // themselves. A valid redirect ledger alone must not produce a
        // spurious overlap.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("state.json"), "not-json {{{")
            .await
            .unwrap();

        assert!(
            overlapping_ledger_purls(root).await.is_empty(),
            "a corrupt vendor ledger must degrade to no-overlap"
        );
        assert_eq!(
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default(),
            "no overlap ⇒ no directional classification"
        );
    }

    #[tokio::test]
    async fn cargo_overlap_with_no_lock_to_probe_stays_silent() {
        // Both ledgers claim the cargo purl but there is NO Cargo.lock (a
        // fresh checkout / deleted lock): discovery finds no cargo wiring
        // either way, which proves neither direction — the classifier must
        // stay silent rather than guess.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &[CARGO_PURL]).await;
        write_cargo_vendor_ledger(root).await;

        // The raw overlap fires (both ledgers name the purl)…
        assert_eq!(
            overlapping_ledger_purls(root).await,
            vec![CARGO_PURL.to_string()],
            "the overlap itself must be detected"
        );
        // …but with no lock to prove a direction, both buckets stay empty.
        assert_eq!(
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default(),
            "no Cargo.lock ⇒ neither direction proven ⇒ silent"
        );
    }

    // ---- hostile-ledger tamper guards (path traversal) ----------------------
    // The ledgers are committed files an attacker can edit: a recorded
    // lockfile name must never make the wiring probes READ outside the
    // project root. The probes are core discovery's ledger-liveness rules
    // (the ones `vex` gates on); with nothing discovered they fall back to
    // the ledger's recorded files, which is the path under test.

    #[tokio::test]
    async fn hosted_wiring_text_proof_never_reads_outside_the_project() {
        // The escaping file EXISTS and carries the record uuid — it would
        // prove hosted wiring were it read. The `../` guard must skip it.
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("proj");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(
            outer.path().join("escape.lock"),
            format!("resolved https://patch.socket.dev/x/{TAKEOVER_UUID}/m.tgz\n"),
        )
        .await
        .unwrap();

        let nothing_discovered = socket_patch_core::vex::discover::Discovery::default();
        assert!(
            !nothing_discovered
                .redirect_record_live(
                    &root,
                    "pkg:npm/minimist@1.2.2",
                    TAKEOVER_UUID,
                    &["../escape.lock"],
                    &mut Some(Vec::new()),
                )
                .await,
            "a '../'-escaping ledger path must never be read"
        );

        // Positive control: the SAME content inside the project proves the
        // wiring — so the negative above is the guard, not a missing file.
        tokio::fs::write(
            root.join("inside.lock"),
            format!("resolved https://patch.socket.dev/x/{TAKEOVER_UUID}/m.tgz\n"),
        )
        .await
        .unwrap();
        assert!(
            nothing_discovered
                .redirect_record_live(
                    &root,
                    "pkg:npm/minimist@1.2.2",
                    TAKEOVER_UUID,
                    &["inside.lock"],
                    &mut Some(Vec::new()),
                )
                .await,
            "the identical in-project file must prove hosted wiring"
        );
    }

    #[tokio::test]
    async fn vendored_wiring_probe_never_reads_outside_the_project() {
        let marker = socket_patch_core::vendor::path::vendor_uuid_dir_rel("npm", TAKEOVER_UUID)
            .expect("npm has a vendor dir mapping");
        let entry_json = |wiring_file: &str| {
            serde_json::json!({
                "ecosystem": "npm",
                "basePurl": "pkg:npm/minimist@1.2.2",
                "uuid": TAKEOVER_UUID,
                "artifact": {
                    "path": format!("{marker}/minimist-1.2.2.tgz"),
                },
                "wiring": [{
                    "file": wiring_file,
                    "kind": "npm_lock_entry",
                    "action": "rewritten",
                }],
            })
        };

        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("proj");
        tokio::fs::create_dir_all(&root).await.unwrap();
        // The escaping file EXISTS and contains the vendored marker.
        tokio::fs::write(
            outer.path().join("escape.lock"),
            format!("resolved file:{marker}/minimist-1.2.2.tgz\n"),
        )
        .await
        .unwrap();

        let escaping: socket_patch_core::vendor::VendorEntry =
            serde_json::from_value(entry_json("../escape.lock")).unwrap();
        let nothing_discovered = socket_patch_core::vex::discover::Discovery::default();
        assert!(
            !nothing_discovered.vendor_entry_live(&root, &escaping).await,
            "a '../'-escaping wiring file must never be read"
        );

        // Positive control: same content, in-project name ⇒ proven live.
        tokio::fs::write(
            root.join("inside.lock"),
            format!("resolved file:{marker}/minimist-1.2.2.tgz\n"),
        )
        .await
        .unwrap();
        let in_project: socket_patch_core::vendor::VendorEntry =
            serde_json::from_value(entry_json("inside.lock")).unwrap();
        assert!(
            nothing_discovered
                .vendor_entry_live(&root, &in_project)
                .await,
            "the identical in-project wiring file must prove vendored wiring"
        );
    }

    // ---- note_vendor_supersedes_redirect: warning + npm auto-reconcile ------
    // The vendored flows' takeover advisory. Detection is pinned above;
    // these pin the post-detection body: the reconciled/manual/dry-run
    // partitions, the ledger mutation, and the fires-once contract.

    const NPM_TAKEOVER_PURL: &str = "pkg:npm/minimist@1.2.2";

    fn vendor_env() -> crate::json_envelope::Envelope {
        crate::json_envelope::Envelope::new(crate::json_envelope::Command::Vendor)
    }

    /// `GlobalArgs` for the advisory: `json` keeps the stderr print quiet
    /// (the envelope `warnings[]` is what the tests read).
    fn takeover_common() -> GlobalArgs {
        GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        }
    }

    /// The WET npm takeover: redirect ledger records the purl (with a
    /// version-exact keyed edit `drop_superseded_purl` can claim), the
    /// vendored ledger is wired, and the LIVE lock points at the committed
    /// vendored artifact.
    async fn write_wet_npm_takeover(root: &Path) {
        write_redirect_ledger_with_edits(
            root,
            &[NPM_TAKEOVER_PURL],
            vec![redirect_edit("package-lock.json", "minimist@1.2.2")],
        )
        .await;
        write_vendor_ledger_wired(root, &[NPM_TAKEOVER_PURL]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;
    }

    #[tokio::test]
    async fn vendored_takeover_wet_npm_run_reconciles_the_ledger_once() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_wet_npm_takeover(root).await;

        let mut env = vendor_env();
        note_vendor_supersedes_redirect(&mut env, root, &takeover_common()).await;

        assert_eq!(
            env.warnings.len(),
            1,
            "exactly one warning: {:?}",
            env.warnings
        );
        assert_eq!(env.warnings[0].code, VENDOR_SUPERSEDES_REDIRECT);
        assert!(
            env.warnings[0].detail.contains("reconciled automatically"),
            "a wet npm run must report the past-tense reconciled detail: {}",
            env.warnings[0].detail
        );
        assert!(
            env.warnings[0].detail.contains(NPM_TAKEOVER_PURL),
            "the warning must name the package: {}",
            env.warnings[0].detail
        );

        // Both halves dropped; the emptied ledger is deleted outright.
        assert!(
            load_ledger(root).await.is_none(),
            "an emptied redirect ledger must be deleted"
        );

        // Fires once: the reconciled project no longer overlaps.
        let mut env2 = vendor_env();
        note_vendor_supersedes_redirect(&mut env2, root, &takeover_common()).await;
        assert!(
            env2.warnings.is_empty(),
            "a reconciled takeover must not re-warn: {:?}",
            env2.warnings
        );
    }

    /// Finding: the reconcile unwound the hosted `.npmrc` auto-config but
    /// threw away the unwind's warnings (a user-edited redirect-created
    /// `.npmrc` was rewritten with no `redirect_npmrc_allow_remote_modified`)
    /// and its detail never mentioned `.npmrc` while still promising
    /// `vendor --revert` restores the hosted wiring (npm 12 then refuses it
    /// without the line). Both are now surfaced.
    #[tokio::test]
    async fn vendored_takeover_reconcile_surfaces_the_npmrc_unwind() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger_with_edits(
            root,
            &[NPM_TAKEOVER_PURL],
            vec![
                redirect_edit("package-lock.json", "minimist@1.2.2"),
                socket_patch_core::patch::redirect::FileEdit {
                    path: ".npmrc".into(),
                    kind: "redirect_npmrc_allow_remote".into(),
                    action: "created".into(),
                    key: Some("allow-remote".into()),
                    original: None,
                    new: Some(serde_json::json!("all")),
                },
            ],
        )
        .await;
        write_vendor_ledger_wired(root, &[NPM_TAKEOVER_PURL]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;
        // The user added their own setting to the redirect-created file.
        tokio::fs::write(root.join(".npmrc"), "allow-remote=all\nfund=false\n")
            .await
            .unwrap();

        let mut env = vendor_env();
        note_vendor_supersedes_redirect(&mut env, root, &takeover_common()).await;

        let codes: Vec<&str> = env.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(
            codes,
            [
                VENDOR_SUPERSEDES_REDIRECT,
                "redirect_npmrc_allow_remote_modified"
            ],
            "{:?}",
            env.warnings
        );
        let detail = &env.warnings[0].detail;
        assert!(detail.contains("reconciled automatically"), "{detail}");
        assert!(detail.contains("`.npmrc` `allow-remote=all`"), "{detail}");
        assert!(detail.contains("EALLOWREMOTE"), "{detail}");
        assert_eq!(
            tokio::fs::read_to_string(root.join(".npmrc"))
                .await
                .unwrap(),
            "fund=false\n",
            "only our line removed"
        );
        assert!(load_ledger(root).await.is_none(), "emptied ledger deleted");

        // Without a recorded `.npmrc` edit the detail stays silent on it.
        assert!(!mode_takeover_reconciled_detail(&["p".into()], false).contains(".npmrc"));
    }

    #[tokio::test]
    async fn vendored_takeover_dry_run_warns_manual_and_leaves_the_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_wet_npm_takeover(root).await;
        let ledger_path = root.join(".socket/vendor/redirect-state.json");
        let before = tokio::fs::read(&ledger_path).await.unwrap();

        let mut env = vendor_env();
        let common = GlobalArgs {
            dry_run: true,
            ..takeover_common()
        };
        note_vendor_supersedes_redirect(&mut env, root, &common).await;

        assert_eq!(env.warnings.len(), 1, "{:?}", env.warnings);
        assert_eq!(env.warnings[0].code, VENDOR_SUPERSEDES_REDIRECT);
        // A dry run hands out the MANUAL remediation (never the past-tense
        // reconciled text — nothing was mutated).
        assert!(
            env.warnings[0].detail.contains("clean up by hand"),
            "dry-run must carry the manual advisory: {}",
            env.warnings[0].detail
        );
        assert!(
            !env.warnings[0].detail.contains("reconciled automatically"),
            "dry-run must not claim a reconciliation: {}",
            env.warnings[0].detail
        );
        let after = tokio::fs::read(&ledger_path).await.unwrap();
        assert_eq!(
            before, after,
            "a dry run must leave the ledger byte-identical"
        );
    }

    #[tokio::test]
    async fn degraded_ledger_reconcile_matches_nothing_and_falls_back_to_manual() {
        // The degraded record-fetch-failed ledger: records EMPTY, one
        // version-blind path-keyed edit. The overlap fallback flags it, but
        // `drop_superseded_purl` (fail-closed: no record uuid to anchor on,
        // key not version-exact) drops nothing — the warning must hand out
        // the manual remediation, never claim a reconciliation.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger_with_edits(
            root,
            &[],
            vec![redirect_edit("package-lock.json", "node_modules/minimist")],
        )
        .await;
        write_vendor_ledger_wired(root, &[NPM_TAKEOVER_PURL]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;
        let ledger_path = root.join(".socket/vendor/redirect-state.json");
        let before = tokio::fs::read(&ledger_path).await.unwrap();

        let mut env = vendor_env();
        note_vendor_supersedes_redirect(&mut env, root, &takeover_common()).await;

        assert_eq!(env.warnings.len(), 1, "{:?}", env.warnings);
        assert_eq!(env.warnings[0].code, VENDOR_SUPERSEDES_REDIRECT);
        assert_eq!(
            env.warnings[0].detail,
            mode_takeover_detail(&[NPM_TAKEOVER_PURL.to_string()], false),
            "an Ok(None) reconcile must fall back to the manual detail verbatim"
        );
        let after = tokio::fs::read(&ledger_path).await.unwrap();
        assert_eq!(
            before, after,
            "a no-op reconcile must leave the degraded ledger byte-identical"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reconcile_persist_failure_fails_closed_with_manual_advice() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_wet_npm_takeover(root).await;
        let vendor_dir = root.join(".socket/vendor");
        let ledger_path = vendor_dir.join("redirect-state.json");
        let before = tokio::fs::read(&ledger_path).await.unwrap();

        std::fs::set_permissions(&vendor_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        // Root ignores mode bits; skip there (CI containers sometimes run as root).
        if std::fs::File::create(vendor_dir.join("probe")).is_ok() {
            let _ = std::fs::remove_file(vendor_dir.join("probe"));
            let _ = std::fs::set_permissions(&vendor_dir, std::fs::Permissions::from_mode(0o755));
            eprintln!("skipping: running as root, 0555 does not block writes");
            return;
        }

        let mut env = vendor_env();
        note_vendor_supersedes_redirect(&mut env, root, &takeover_common()).await;

        // Restore BEFORE asserting so a failure never leaks an undeletable
        // tempdir.
        std::fs::set_permissions(&vendor_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(env.warnings.len(), 1, "{:?}", env.warnings);
        assert_eq!(env.warnings[0].code, VENDOR_SUPERSEDES_REDIRECT);
        assert!(
            env.warnings[0]
                .detail
                .contains("Automatic reconciliation failed"),
            "the persist failure must be surfaced inside the warning: {}",
            env.warnings[0].detail
        );
        assert!(
            env.warnings[0].detail.starts_with(&mode_takeover_detail(
                &[NPM_TAKEOVER_PURL.to_string()],
                false
            )),
            "the failure text must ride on the full manual remediation: {}",
            env.warnings[0].detail
        );
        // Fail closed: the atomic writer left the ledger fully pre-drop.
        let after = tokio::fs::read(&ledger_path).await.unwrap();
        assert_eq!(
            before, after,
            "a failed persist must leave the ledger untouched"
        );
    }

    /// A failed embedded VEX's discovery diagnostics reach the scan JSON:
    /// appended after existing `warnings[]` (layout refusals), or creating
    /// the array; an empty list leaves the object untouched.
    #[test]
    fn vex_error_warnings_append_to_scan_json() {
        let w = crate::json_envelope::RunWarning {
            code: "lockfile_unparseable".to_string(),
            detail: "pnpm-lock.yaml: bad".to_string(),
        };
        let mut fresh = serde_json::json!({ "status": "error" });
        append_vex_error_warnings(&mut fresh, &[]);
        assert!(fresh.get("warnings").is_none());
        append_vex_error_warnings(&mut fresh, std::slice::from_ref(&w));
        assert_eq!(fresh["warnings"][0]["code"], "lockfile_unparseable");

        let mut existing = serde_json::json!({ "warnings": [{ "code": "pnp", "detail": "d" }] });
        append_vex_error_warnings(&mut existing, &[w]);
        let codes: Vec<&str> = existing["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["code"].as_str().unwrap())
            .collect();
        assert_eq!(codes, ["pnp", "lockfile_unparseable"]);
    }
}
