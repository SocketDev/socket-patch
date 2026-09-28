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
    build_proxy_fallback_client, get_api_client_with_overrides, hold_back_debug,
    is_fallback_candidate, ApiClient, ApiError,
};
use socket_patch_core::api::types::{BatchPackagePatches, BatchSearchResponse, PatchSearchResult};
use socket_patch_core::crawlers::ruby_crawler::config_path_ignored_warning;
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::telemetry::{
    spawn_patch_scan_failed, spawn_patch_scanned, PendingTelemetry,
};
use socket_patch_core::utils::concurrent::{api_concurrency_for, ordered_concurrent};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::vendor::VendorState;
use socket_patch_core::vex::discover::{LedgerLiveness, WiringMode};
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::{crawl_ecosystems, crawl_ecosystems_with_npm};
use crate::ui::{self, plural, print_json, StatusLine};

use super::get::{download_and_apply_patches_with, select_patches, DownloadParams, DownloadRun};

mod discovery;
mod gc;
pub(crate) mod hosted;
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
pub(crate) use self::hosted::{vlt_rollback_heal, vlt_takeover_heal};
pub(crate) use self::vendor_flow::{
    boxed_scan_vendor_step, preview_vendor_json, print_dry_run_refusals,
};
use self::vendor_flow::{
    boxed_vendor_interactive_path, boxed_vendor_json_path, fold_vendored_skips_into_apply,
    partition_skipped_selected,
};

/// Packages per batch request on the authenticated API when `--batch-size`
/// is not given: the server's own per-request maximum
/// (`MAX_PURLS_PER_BATCH` on `POST /v0/orgs/{org}/patches/batch`).
const DEFAULT_BATCH_SIZE: usize = 500;

/// Packages per batch request on the public proxy when `--batch-size` is
/// not given. The proxy is shared and unauthenticated, so it keeps a
/// smaller size.
const DEFAULT_PROXY_BATCH_SIZE: usize = 100;

/// Upper bound on one batch request's JSON body. A chunk whose purls would
/// serialize past it is split, deterministically, into consecutive smaller
/// chunks. The value is the public proxy's own body cap
/// (`MAX_PATCH_PROXY_BODY_BYTES`, answered with a 413 past it) — the
/// tightest limit any batch route has (the authenticated API accepts
/// 16 MiB). A batch the fallback re-sends to the proxy therefore always
/// fits, whichever endpoint the chunks were sized for.
const BATCH_BODY_BYTE_CAP: usize = 256 * 1024;

/// The chunk size in effect: `--batch-size` / `SOCKET_BATCH_SIZE` when
/// given (on either endpoint), else [`DEFAULT_BATCH_SIZE`] on the
/// authenticated API and [`DEFAULT_PROXY_BATCH_SIZE`] on the public proxy.
/// Floored at 1: `--batch-size 0` is otherwise unvalidated and would make
/// the chunking below panic, so it degrades to one-package batches.
fn effective_batch_size(requested: Option<usize>, use_public_proxy: bool) -> usize {
    requested
        .unwrap_or(if use_public_proxy {
            DEFAULT_PROXY_BATCH_SIZE
        } else {
            DEFAULT_BATCH_SIZE
        })
        .max(1)
}

/// Serialized length of one `{"purl":…}` component of the batch body,
/// exactly as `serde_json` writes it (quotes and escapes included).
fn batch_component_bytes(purl: &str) -> usize {
    // `{"purl":` + the JSON string + `}`.
    8 + serde_json::to_string(purl).map_or(purl.len() + 2, |s| s.len()) + 1
}

/// Split `purls` into consecutive batch chunks of at most `batch_size`
/// purls whose request body (`{"components":[{"purl":…},…]}`) stays within
/// `max_body_bytes`. A chunk closes at `batch_size` purls or when the next
/// purl would push its body past the cap, so the boundaries depend only on
/// the purls, their order and the two limits. A single purl too long for
/// the cap on its own still goes, alone (the server judges it); nothing is
/// ever dropped or reordered. With a cap no chunk reaches, this is exactly
/// `purls.chunks(batch_size)`.
fn batch_chunks(purls: &[String], batch_size: usize, max_body_bytes: usize) -> Vec<&[String]> {
    // `{"components":[` + `]}`.
    const ENVELOPE: usize = 15 + 2;
    let batch_size = batch_size.max(1);
    let mut chunks = Vec::with_capacity(purls.len().div_ceil(batch_size));
    let mut start = 0usize;
    let mut body = ENVELOPE;
    for (i, purl) in purls.iter().enumerate() {
        let count = i - start;
        let item = batch_component_bytes(purl) + usize::from(count > 0);
        if count > 0 && (count == batch_size || body + item > max_body_bytes) {
            chunks.push(&purls[start..i]);
            start = i;
            body = ENVELOPE + batch_component_bytes(purl);
        } else {
            body += item;
        }
    }
    if start < purls.len() {
        chunks.push(&purls[start..]);
    }
    chunks
}

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
    // Equivalent to the hidden `--redirect` boolean. The hidden value
    // aliases mirror legacy spellings (`apply` is deliberately NOT an alias
    // of agent).
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
/// * `--detached` requires vendored mode in either spelling (clap's
///   `requires = "vendor"` cannot see `--mode vendored`).
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
    } else if !args.prune && !args.common.is_global() {
        // v5: hosted is the default. A `--prune` or global scan with no mode
        // stays report-only (neither has a project lockfile to rewire).
        args.mode = Some(ScanMode::Hosted);
    }
    if args.mode == Some(ScanMode::Hosted)
        && args.common.is_global()
    {
        // Global installs have no project lockfile to repoint: the hosted
        // flow would "redirect 0 packages" and exit 0, a silent no-op.
        return Err(format!(
            "{} cannot be used with --mode hosted: global installs have no project \
             lockfile to redirect",
            if args.common.global {
                "--global"
            } else {
                "--global-prefix"
            },
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

#[derive(Args, Clone)]
pub struct ScanArgs {
    /// Only scan these directories. In hosted and vendored mode each PATH
    /// (or glob, e.g. `apps/*`) is a project directory, scanned on its own
    /// as if it were `--cwd`. In agent mode PATHs are globs over installed
    /// package paths (a bare directory scopes its whole subtree; `--prune`
    /// still considers the whole project, and lockfile-only packages are
    /// left out with a warning)
    pub paths: Vec<String>,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Number of packages to query per API request [default: 500 on the
    /// authenticated API, 100 on the public proxy]. A batch whose request
    /// body would exceed 256 KiB is split into smaller consecutive batches
    #[arg(long = "batch-size", env = "SOCKET_BATCH_SIZE")]
    pub batch_size: Option<usize>,

    // Hidden, deprecated spelling of `--mode agent`: download the selected
    // patches and apply them in place.
    #[arg(long, default_value_t = false, hide = true)]
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
    /// run `socket-patch scan --json --sync` to end up fully reconciled in
    /// one invocation
    #[arg(long, default_value_t = false)]
    pub sync: bool,

    // Hidden, deprecated spelling of `--mode vendored`: vendor every
    // patched dependency the scan selects into the committable
    // `.socket/vendor/` tree instead of applying patches in place.
    #[arg(long, default_value_t = false, hide = true, conflicts_with_all = ["apply", "sync"])]
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

    // Hidden legacy spelling of `--mode hosted`.
    #[arg(long, default_value_t = false, hide = true, conflicts_with_all = ["apply", "sync", "vendor"])]
    pub redirect: bool,

    /// How discovered patches are consumed [default: hosted]. A `--prune`
    /// or `--global` scan with no mode only reports
    // The hidden `--vendor` and `--apply` are older spellings of
    // `--mode vendored` and `--mode agent`. Each mode is equivalent to one
    // boolean flag (hosted == the hidden `--redirect`, vendored == `--vendor`, agent == `--apply`/`--sync`).
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

    /// Only scan these packages: a name (`lodash`, `@scope/pkg`,
    /// `requests`), or a purl with or without its version
    /// (`pkg:npm/lodash`, `pkg:pypi/requests@2.31.0`). Repeat the flag or
    /// separate with commas
    #[arg(
        long = "package",
        env = "SOCKET_SCAN_PACKAGES",
        value_delimiter = ','
    )]
    pub packages: Vec<String>,

    /// On a successful scan, also generate an OpenVEX 0.2.0 document.
    /// `--vex <path>` is the trigger; the `--vex-*` knobs mirror the
    /// standalone `vex` command. The document is built from the manifest
    /// as it stands after the scan (including any `--apply`/`--sync`
    /// writes) and verified against on-disk state. A requested-but-failed
    /// VEX makes the command exit non-zero.
    #[command(flatten)]
    pub vex: VexEmbedArgs,
}

/// Whether a `--package` spec names the package at `purl`: a purl spec
/// matches the same purl, or any version of it when it carries none; a
/// bare spec matches the package's full name (`@scope/pkg`, `group/name`)
/// or its last segment. Qualifiers are ignored and names compare
/// case-insensitively (PyPI, NuGet and Composer names are case-insensitive;
/// npm forbids uppercase).
pub(crate) fn package_spec_matches(spec: &str, purl: &str) -> bool {
    let decoded = normalize_purl(strip_purl_qualifiers(purl)).to_lowercase();
    let spec = spec.trim().to_lowercase();
    if spec.is_empty() {
        return false;
    }
    let Some(rest) = decoded.strip_prefix("pkg:") else {
        return false;
    };
    let Some((_eco, name_version)) = rest.split_once('/') else {
        return false;
    };
    let name = match name_version.rfind('@').filter(|&i| i > 0) {
        Some(at) => &name_version[..at],
        None => name_version,
    };
    if let Some(spec_rest) = spec.strip_prefix("pkg:") {
        let spec_purl = normalize_purl(strip_purl_qualifiers(&format!("pkg:{spec_rest}"))).to_lowercase();
        let spec_rest = &spec_purl[4..];
        let has_version = spec_rest
            .split_once('/')
            .is_some_and(|(_, nv)| nv.rfind('@').is_some_and(|i| i > 0));
        return if has_version {
            decoded == spec_purl
        } else {
            decoded.strip_prefix(&spec_purl).is_some_and(|tail| tail.starts_with('@'))
        };
    }
    let spec = spec.replace(':', "/");
    name == spec || name.rsplit('/').next() == Some(spec.as_str())
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
            println!(
                "{}",
                crate::commands::vex::format_vex_dry_run_skip("applied")
            );
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
/// resolve the top-ranked accessible patch per PURL. Per-package search
/// errors are skipped, but when EVERY query errors the empty set would be
/// indistinguishable from a genuine "no patches" result, so that surfaces
/// as `Err(1)` with the failure on stderr. Selects with [`selection_args`]:
/// scan never prompts, so every run auto-selects the top-ranked patch (see
/// `api::ranking`) rather than erroring with `selection_required`. `Err`
/// carries the exit code AND the message, since JSON callers must fold it
/// into their single envelope (CLI_CONTRACT.md). `show_progress` / `warn`
/// are the human-only knobs of [`fetch_patch_details`] (JSON callers pass
/// `false, false`). `json_warnings` is the JSON callers' envelope: a
/// partial failure adds one [`PATCH_DETAILS_FAILED`] warning per failed
/// package to it.
#[allow(clippy::too_many_arguments)]
async fn discover_selected(
    api_client: &socket_patch_core::api::client::ApiClient,
    packages: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    common: &GlobalArgs,
    show_progress: bool,
    warn: bool,
    telemetry: &mut PendingTelemetry,
    json_warnings: Option<&mut serde_json::Value>,
) -> Result<Vec<PatchSearchResult>, (i32, String)> {
    let (all_search_results, failures) =
        fetch_patch_details(api_client, packages, show_progress, warn).await;
    // The scan event's send overlapped the detail fetches; every caller's
    // next output (the error line below, a `--json` envelope) must find it
    // delivered.
    telemetry.flush().await;
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
    // Some queries failed, some succeeded: a `--json` run has no stderr
    // warning (`warn` is human-only), so each failed package becomes a
    // run-level `warnings[]` entry — never a silent drop from the envelope.
    if let Some(result) = json_warnings {
        for (purl, e) in &failures {
            push_scan_json_warning(
                result,
                PATCH_DETAILS_FAILED,
                &format!("could not fetch details for {purl}: {e}"),
            );
        }
    }
    if all_search_results.is_empty() {
        return Ok(Vec::new());
    }
    if common.json {
        // Pre-filter to accessible patches so `select_patches` takes the
        // top-ranked one per PURL.
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

/// `common` for `select_patches`: scan never prompts, so it always takes
/// the top-ranked patch, and with `json` off it never gets
/// `selection_required` (scan has no "re-run with the chosen UUID" path).
pub(crate) fn selection_args(common: &GlobalArgs) -> GlobalArgs {
    GlobalArgs {
        json: false,
        yes: true,
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
    // counter names the next result awaited, and each query's `--debug`
    // lines are held back and printed at its fold, where the serial loop
    // would have made the request.
    let mut responses = std::pin::pin!(ordered_concurrent(
        packages,
        api_concurrency_for(api_client.uses_public_proxy(), packages.len()),
        |pkg| async move {
            (
                pkg,
                hold_back_debug(api_client.search_patches_by_package(&pkg.purl)).await,
            )
        },
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
        match response.release() {
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

/// The ecosystems a scan crawls (`None`: every one). `--ecosystems`
/// narrows everything the run counts, queries and shows to the named
/// ecosystems, so without a GC the other crawlers' output would only be
/// filtered away: they are not run at all. A GC run (`--prune` / `--sync`)
/// still crawls everything — the GC judges every manifest entry against the
/// FULL installed set (see `scanned_purls` in `run_scan`), and a skipped
/// ecosystem would read as uninstalled.
fn crawl_scope(prune: bool, ecosystems: Option<&[String]>) -> Option<&[String]> {
    if prune {
        None
    } else {
        ecosystems
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
        patch_server_url: args.common.patch_server_url.clone(),
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
// Cross-mode takeover detection (hosted over vendored)
// ---------------------------------------------------------------------------
//
// Vendored mode writes `.socket/vendor/state.json` (+ committed tarballs);
// hosted mode keeps no ledger — its lockfile pins are the only record.
// Redirecting a vendored package to the hosted patch server rewires the
// lockfile but leaves the vendored ledger entry on disk asserting wiring that
// is no longer live, which misleads anything auditing the ledger (including
// `vex`). Detect the overlap so the hosted flow can warn (removing a vendored
// entry deletes committed artifacts — `remove <purl>`'s job). The reverse
// direction needs no advisory: once the lock routes a package to
// `.socket/vendor/`, no hosted state is left to go stale.
//
// The overlap only proves the vendored ledger and a hosted pin both name the
// package, not which won. The takeover DIRECTION comes from the current
// lockfile wiring per package (`classify_overlap_takeover`), never from
// which command is running, and a package the lock proves neither way stays
// silent.

/// Warning code emitted by the HOSTED flow when it just redirected package(s)
/// a committed vendored ledger still claims (its tarballs are now orphaned).
pub(super) const REDIRECT_SUPERSEDES_VENDORED: &str = "redirect_supersedes_vendored";

/// Warning code + detail emitted when `--prune` is combined with
/// `--mode hosted`: the hosted flow runs no GC, so the flag would otherwise
/// be silently dropped. `--prune` stays accepted (CLI_CONTRACT.md: an
/// orthogonal GC knob, never a usage error), but the no-op is explicit in
/// both the JSON `warnings[]` and stderr.
pub(super) const REDIRECT_PRUNE_IGNORED: &str = "redirect_prune_ignored";
pub(super) const REDIRECT_PRUNE_IGNORED_DETAIL: &str =
    "--prune has no effect with --mode hosted: the hosted flow rewrites lockfiles only and \
     runs no GC sweep of `.socket/` state; run `scan --mode agent --prune` or \
     `scan --mode vendored --prune` to garbage-collect";

/// The PURLs claimed by BOTH a hosted pin (`redirect`, the lockfiles'
/// hosted state — see [`crate::commands::hosted_state_from_lockfiles`]) and
/// the vendored state ledger (`.socket/vendor/state.json`), sorted. A
/// non-empty result means one of the two is stale for each PURL (a
/// lockfile entry can point only one way). `None`, an empty vendor ledger,
/// or disjoint states (a legitimate split) yield no overlap.
fn overlap_from_states(
    redirect: Option<&socket_patch_core::patch::redirect::RedirectState>,
    vendor: &VendorState,
) -> Vec<String> {
    let Some(redirect) = redirect else {
        return Vec::new();
    };
    if vendor.entries.is_empty() || redirect.records.is_empty() {
        return Vec::new();
    }
    // Canonicalize both sides (drop qualifiers, percent-decode) so the
    // hosted pin's purl matches the vendor entry's base purl — mirrors
    // `vendored_ledger_supplement`.
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let mut vendor_purls: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (key, entry) in &vendor.entries {
        vendor_purls.insert(canon(key));
        vendor_purls.insert(canon(&entry.base_purl));
    }
    let redirect_purls: std::collections::BTreeSet<String> =
        redirect.records.keys().map(|p| canon(p)).collect();
    redirect_purls
        .intersection(&vendor_purls)
        .cloned()
        .collect()
}

/// The overlapping PURLs split by which mode the LIVE lockfile actually wires
/// them to right now — the truth source for takeover direction.
///
/// Both directions are proved by lockfile discovery with the same liveness
/// rules `vex` gates attestations on (core `Discovery::redirect_record_live`
/// / `Discovery::vendor_entry_live`). `redirect` holds the overlap PURLs the
/// lock routes to the hosted patch server (the vendored ledger entry is
/// stale); `vendored` holds those it routes to a committed
/// `.socket/vendor/<eco>/<uuid>` artifact.
///
/// A PURL the lock proves NEITHER way — a dry-run/no-op that did not rewire it,
/// a half-migrated lock naming both, or an ecosystem whose live spec we cannot
/// read — lands in neither bucket, so the caller stays SILENT rather than
/// guessing the direction from which command happened to run.
#[derive(Debug, Default, PartialEq)]
pub(super) struct OverlapTakeover {
    /// Overlap PURLs whose vendored ledger is stale (lock points hosted).
    pub redirect: Vec<String>,
    /// Overlap PURLs the lock routes to the vendored artifact.
    pub vendored: Vec<String>,
}

/// [`classify_overlap_takeover_with`] over the on-disk state: the
/// lockfiles' hosted pins and the committed vendored ledger.
#[cfg(test)]
pub(super) async fn classify_overlap_takeover(common: &GlobalArgs, cwd: &Path) -> OverlapTakeover {
    // A malformed vendor ledger classifies like a missing one (this path
    // only feeds takeover warnings; corruption is a hard error on the
    // write/attest paths).
    let redirect = crate::commands::hosted_state_from_lockfiles(common, cwd).await;
    let vendor = socket_patch_core::vendor::load_state(cwd).await.ok();
    classify_overlap_takeover_with(common, cwd, Some(&redirect), vendor.as_ref()).await
}

/// [`classify_overlap_takeover`] over already-loaded state (the hosted
/// engine classifies against its post-takeover vendor ledger); still reads
/// the LIVE lockfiles in `cwd`. `None` for either yields no overlap.
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
    // Each hosted pin's patch uuid (embedded in every hosted artifact URL,
    // whatever the host). A non-empty overlap proves `redirect` is `Some`.
    let mut redirect_uuid_by_purl: std::collections::HashMap<String, &str> =
        std::collections::HashMap::new();
    for (key, record) in redirect.iter().flat_map(|r| &r.records) {
        redirect_uuid_by_purl
            .entry(canon(key))
            .or_insert(record.uuid.as_str());
    }
    let discovery = crate::commands::discover_wiring(common, cwd).await;
    let mut liveness = LedgerLiveness::new(cwd, &discovery, None);
    for purl in overlap {
        let hosted_live = match redirect_uuid_by_purl.get(&purl) {
            Some(uuid) => liveness.redirect_record(&purl, uuid).await,
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

/// Human-readable detail for the hosted-over-vendored takeover warning
/// ([`REDIRECT_SUPERSEDES_VENDORED`]) naming the displaced package(s).
///
/// The warning fires PER PACKAGE, so the remediation is per-package and
/// non-destructive: never delete a whole `.socket/vendor/<eco>/` tree, which
/// may still carry LIVE data for packages this takeover did not touch. It
/// states `socket-patch remove`'s full blast radius, including the
/// package's `.socket/manifest.json` entry.
pub(super) fn mode_takeover_detail(superseded: &[String]) -> String {
    let list = superseded.join(", ");
    // NEVER offer deleting the `.socket/vendor/<eco>/` tree here: for cargo
    // the leftover `[patch.crates-io]` entry still points at that tree, and
    // deleting it hard-fails every cargo invocation ("failed to load source
    // for dependency"). Nor `vendor --revert`, which unwinds EVERY vendored
    // package including the ones still live in the lockfile — `remove
    // <purl>` is the per-package equivalent.
    format!(
        "hosted wiring superseded the vendored ledger for: {list}. \
         `.socket/vendor/state.json` still claims these package(s) and their \
         committed artifacts under `.socket/vendor/` are now orphaned — the \
         lockfile points at the hosted patch server, not the vendored files. \
         Clean up per package: run `socket-patch remove <purl>` for each \
         package listed above, so audits and VEX do not read superseded \
         wiring. It drops that package's vendored ledger entry and its own \
         `.socket/vendor/<eco>/<uuid>/` artifact directory, AND deletes that \
         package's now-superseded `.socket/manifest.json` entry — that entry \
         describes the vendored delivery, while the live hosted patch is \
         recorded in the lockfile itself. In-place file rollback is skipped \
         for vendor-owned package(s), so the installed tree is left as the \
         lockfile wires it; preview with `--dry-run` first. Do not delete the \
         whole `.socket/vendor/<eco>/` tree and do not run `vendor --revert`: \
         other vendored package(s) may still be live in the lockfile and \
         would break or be mass-reverted."
    )
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
        eprintln!("Warning: {detail}");
    }
    env.warnings.push(crate::json_envelope::RunWarning {
        code: code.to_string(),
        detail,
    });
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
// The agent flow patches installed trees in place, so `scan --mode agent`
// over another mode's live state is not a takeover, but it IS a mode
// conversion that did not complete:
//
// * over live HOSTED wiring, the lockfile keeps resolving to the hosted
//   patch server and the redirect ledger stays live;
// * over VENDORED ownership, the vendor-owned purls become `apply.patches[]`
//   skip records (`skipped`/`vendored`).
//
// Both get one additive run-level warning (top-level `warnings[]` + stderr
// when not silent). NEVER a status or exit-code change.

/// Warning code: agent-mode scan ran over package(s) whose hosted redirect
/// wiring is still LIVE (ledger record present AND the lock provably still
/// routes the purl to the hosted artifact).
pub(super) const HOSTED_WIRING_RETAINED: &str = "hosted_wiring_retained";

/// Warning code: agent-mode apply yielded ownership of vendor-owned
/// package(s) (the per-patch `skipped`/`vendored` records), so those
/// package(s) did NOT convert to agent mode.
pub(super) const VENDORED_OWNERSHIP_RETAINED: &str = "vendored_ownership_retained";

/// Run-level `--json` warning: one API batch query failed (after the
/// client's bounded 429 / 503 retry) while others succeeded, so the
/// packages in that batch were not checked for patches. The detail is the
/// human `Warning: API batch <n> of <total> failed: <error>` line without
/// its prefix. (Every batch failing is the all-batches-failed error
/// envelope instead.)
pub(super) const API_BATCH_FAILED: &str = "api_batch_failed";

/// Run-level `--json` warning: one package's patch-detail query failed
/// (after the client's bounded 429 / 503 retry) while others succeeded, so
/// its patch was left out of the selection. The detail is the human
/// `Warning: could not fetch details for <purl>: <error>` line without its
/// prefix. (Every query failing is the discovery error envelope instead.)
pub(super) const PATCH_DETAILS_FAILED: &str = "patch_details_failed";

/// The scanned purls whose HOSTED redirect wiring is still live: a hosted
/// pin names the purl (`redirect_state`, the lockfiles' hosted state — see
/// [`crate::commands::hosted_state_from_lockfiles`]) AND lockfile discovery
/// proves the current lockfile still routes it to that hosted patch — core
/// `Discovery::redirect_record_live`, the same liveness rule `vex` gates
/// hosted attestations on.
///
/// Deliberately NOT routed through [`classify_overlap_takeover`]: that
/// classifier keys on purls present in BOTH ledgers, so hosted-only wiring
/// can never trigger it (pinned by
/// `hosted_only_wiring_fires_agent_probe_not_the_overlap_classifier`).
///
/// Silent cases (each pinned by a test): no hosted pin (a pre-v5 ledger is
/// not hosted state); purl not scanned this run; the live lock does not
/// prove hosted wiring.
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
    // Cheap no-I/O gate: skip the lockfile proofs when no record names a
    // scanned purl.
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
    let mut liveness = LedgerLiveness::new(cwd, &discovery, None);
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
/// real options — stay hosted, migrate via the vendored flow, or restore
/// the upstream registry entries via `rollback`.
pub(super) fn hosted_wiring_retained_detail(retained: &[String]) -> String {
    let list = retained.join(", ");
    format!(
        "agent-mode scan left the hosted wiring live for: {list}. \
         The lockfile still resolves these package(s) to the hosted patch \
         server — an agent run patches installed files in place but does \
         NOT unwind hosted lockfile wiring, so installs keep fetching \
         these package(s) from the patch server. Either keep the project \
         in hosted mode (`scan --mode hosted`), migrate to committed \
         artifacts with `scan --mode vendored` (which takes these \
         package(s) over in the lockfile), or restore their upstream \
         registry entries with `socket-patch rollback`."
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
/// the hosted pins the lockfiles wire — project STATE, so a descriptive
/// block rather than a warning — plus the scanned purls among them.
///
/// `None` (key omitted, additive contract) when no lockfile pins a hosted
/// patch.
///
/// Shape: `{ mode, records: [{purl, uuid}], wiringLive: [purl] }`. `mode`
/// is the constant [`crate::commands::HOSTED_MODE_LABEL`]. Each record's
/// `purl` is canonicalized (qualifiers stripped, percent-decoded) to the
/// spelling `wiringLive` carries. `wiring_live` is the caller's
/// [`hosted_wiring_retained_purls`] result, computed once per run: the pins
/// this run crawled (a pin whose package was not crawled is still wired,
/// just not covered by this run).
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
                "uuid": record.uuid,
            })
        })
        .collect();
    Some(serde_json::json!({
        "mode": crate::commands::HOSTED_MODE_LABEL,
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

pub async fn run(args: ScanArgs) -> i32 {
    // Scan's telemetry sends run off the critical path: each is spawned
    // where its event fires and flushed before the first stdout write that
    // follows it (so a closed pipe's SIGPIPE or a Ctrl-C still finds it
    // delivered, as with an inline send). The flush here is the
    // backstop that keeps every event ahead of the process exit.
    let mut telemetry = PendingTelemetry::new();
    let code = Box::pin(run_scan(args, &mut telemetry)).await;
    telemetry.flush().await;
    code
}

/// The project directories a hosted or vendored scan's PATHs name: each
/// PATH is a directory, or a glob matching directories, relative to
/// `--cwd`. Sorted and deduplicated.
fn project_dirs(cwd: &Path, paths: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for raw in paths {
        let joined = cwd.join(raw);
        if raw.contains(['*', '?', '[']) {
            let pattern = joined.to_string_lossy().into_owned();
            let matches = glob::glob(&pattern).map_err(|e| format!("invalid path pattern `{raw}`: {e}"))?;
            let before = dirs.len();
            dirs.extend(matches.filter_map(Result::ok).filter(|p| p.is_dir()));
            if dirs.len() == before {
                return Err(format!("`{raw}` matches no directory"));
            }
        } else if joined.is_dir() {
            dirs.push(joined);
        } else {
            return Err(format!("`{raw}` is not a directory"));
        }
    }
    dirs.sort();
    dirs.dedup();
    Ok(dirs)
}

/// Run a hosted or vendored scan once per project directory its PATHs
/// name, as if each were `--cwd`. The exit code is the worst of the runs.
/// `--json` takes one directory, so stdout stays one document.
async fn run_project_dirs(args: ScanArgs, telemetry: &mut PendingTelemetry) -> i32 {
    let dirs = match project_dirs(&args.common.cwd, &args.paths) {
        Ok(dirs) => dirs,
        Err(message) => {
            eprintln!("Error: {message}");
            return 2;
        }
    };
    if args.common.json && dirs.len() > 1 {
        eprintln!(
            "Error: --json takes one project directory ({} given); run one scan per directory",
            dirs.len()
        );
        return 2;
    }
    let mut code = 0;
    for dir in &dirs {
        if dirs.len() > 1 && !args.common.silent {
            let shown = dir.strip_prefix(&args.common.cwd).unwrap_or(dir);
            println!("\n== {} ==", shown.display());
        }
        let mut child = args.clone();
        child.paths.clear();
        child.common.cwd = dir.clone();
        code = code.max(Box::pin(run_scan(child, telemetry)).await);
    }
    code
}

async fn run_scan(mut args: ScanArgs, telemetry: &mut PendingTelemetry) -> i32 {
    apply_env_toggles(&args.common);

    // Fold the legacy mode booleans into `args.mode` (see
    // `resolve_mode_flags`). Cross-mode combinations are usage errors
    // (exit 2), which print no JSON envelope even under --json, like
    // clap's own.
    if let Err(message) = resolve_mode_flags(&mut args) {
        eprintln!("Error: {message}");
        return 2;
    }

    // Hosted and vendored modes rewire a project's lockfiles, so their
    // PATHs name project directories: one scan per directory.
    if matches!(args.mode, Some(ScanMode::Hosted) | Some(ScanMode::Vendored))
        && !args.paths.is_empty()
    {
        return Box::pin(run_project_dirs(args, telemetry)).await;
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

    // Strict airgap (CLI_CONTRACT.md `--offline`): scan's patch discovery
    // is remote data, so refuse before the crawl and before the API client
    // is built (org auto-resolve is itself a network call).
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

    // `--sync` is sugar for `--mode agent --prune`.
    let apply = args.mode == Some(ScanMode::Agent);
    let vendor = args.mode == Some(ScanMode::Vendored);
    let hosted = args.mode == Some(ScanMode::Hosted);
    let prune = args.prune || args.sync;

    // Hosted mode runs no GC: say so once up front on the human path. The
    // `--json` path carries it in `redirect.warnings[]`.
    if hosted && prune && !args.common.json && !args.common.silent {
        eprintln!("Warning: {REDIRECT_PRUNE_IGNORED_DETAIL}");
    }

    // Resolved up-front (rather than at the GC site) because the embedded
    // `--vex` side-effect reads the manifest at several terminal returns,
    // including the early "no packages" exit before the GC block.
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = args.common.socket_dir();

    let overrides = args.common.api_client_overrides();
    let (mut api_client, mut use_public_proxy) =
        get_api_client_with_overrides(overrides.clone()).await;
    // Sized for the endpoint the run starts on. A mid-run downgrade to the
    // proxy keeps these chunk boundaries: every chunk is within the proxy's
    // body cap by construction (`BATCH_BODY_BYTE_CAP`).
    let batch_size = effective_batch_size(args.batch_size, use_public_proxy);
    let telemetry_token = api_client.api_token().cloned();
    let telemetry_org = api_client.org_slug().cloned();
    // Whether scan downgraded to the public proxy mid-run after a 401/403
    // (reported in the `patch_scanned` telemetry event).
    let mut fallback_to_proxy = false;

    let crawler_options = args.common.crawler_options();

    let scan_target = if args.common.is_global() {
        "global packages"
    } else {
        "packages"
    };

    // `--silent` is "errors only" (CLI_CONTRACT.md): progress, summary,
    // table and per-patch listing are suppressed; errors and the JSON
    // envelope are unaffected.
    let human = !args.common.json && !args.common.silent;
    let mut status = StatusLine::stderr(args.common.json, args.common.silent);
    status.set(format!("Scanning {scan_target}..."));

    // Which ecosystems to crawl (see `crawl_scope`).
    let crawl_scope = crawl_scope(prune, args.common.ecosystems.as_deref());

    // Crawl packages. Vendored mode keeps the npm half for its engine to
    // reuse; hosted mode keeps it only for an embedded `--vex` (skipped
    // under `--dry-run`). No other run pays for copying the snapshot.
    let keep_npm = vendor || (hosted && args.vex.vex.is_some() && !args.common.dry_run);
    let (mut all_crawled, mut eco_counts, skipped_bundle_config_path, npm_crawl) = if keep_npm {
        crawl_ecosystems_with_npm(&crawler_options, crawl_scope).await
    } else {
        let (packages, counts, skipped) = crawl_ecosystems(&crawler_options, crawl_scope).await;
        (packages, counts, skipped, None)
    };

    // Lockfile supplement: dependencies the project's lockfile resolves
    // that have NO installed copy (fresh clone, partial install). They join
    // discovery and are flagged "not yet installed". Scoped to the crawled
    // ecosystems.
    let lockfile_only = lockfile_supplement(&args.common, &all_crawled, crawl_scope).await;
    // Unsupported layouts and malformed binary Bun locks, kept on empty
    // scans too: an unreadable graph is not evidence of no dependencies.
    let mut layout_refusals = unsupported_layout_warnings(&lockfile_only.unsupported);
    // A committed `.bundle/config` whose BUNDLE_PATH resolves outside the
    // project, refused by the crawler's containment guard: surface it on
    // the same run-level channel as the layout refusals.
    if let Some(value) = skipped_bundle_config_path {
        if args.common.ecosystem_selected(Ecosystem::Gem) {
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
    // The vendor ledger, loaded ONCE for the supplement, the key set below,
    // and update detection. Failure policies differ on purpose: the
    // supplement falls back to the committed artifacts (fail-closed for the
    // prune), the key set degrades to empty (fail-open).
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

    // Every PURL the crawl found, captured BEFORE the `--ecosystems` /
    // `--package` / PATH filters: prune must judge manifest entries against
    // the full installed set, or `scan --ecosystems npm --prune` would
    // delete every other ecosystem's entries. Lockfile-only purls are
    // included so a wiped node_modules does not prune them.
    let scanned_purls: HashSet<String> = all_crawled.iter().map(|p| p.purl.clone()).collect();

    // Vendor-ledger purl keys, shared by the prune exemption (a vendored
    // package's normal state is absent from the crawl) and the
    // vendored-skip in the apply path. A corrupt ledger yields the empty set.
    let vendored_purls: HashSet<String> = vendor_state
        .as_ref()
        .map(VendorState::purl_keys)
        .unwrap_or_default();

    // Filter by --ecosystems if provided
    let filtered_crawled: Vec<_> = all_crawled
        .into_iter()
        .filter(|pkg| args.common.purl_ecosystem_selected(&pkg.purl))
        .collect();

    let package_specs: Vec<&String> =
        args.packages.iter().filter(|s| !s.trim().is_empty()).collect();
    let filtered_crawled: Vec<_> = if package_specs.is_empty() {
        filtered_crawled
    } else {
        filtered_crawled
            .into_iter()
            .filter(|pkg| {
                package_specs
                    .iter()
                    .any(|spec| package_spec_matches(spec, &pkg.purl))
            })
            .collect()
    };

    // PATH scoping, strictly AFTER the `scanned_purls` capture. A purl is
    // in scope when ANY genuinely-crawled copy of it sits under a matching
    // path.
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
                    if excluded_supplements == 1 {
                        "was"
                    } else {
                        "were"
                    },
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
            for (_, detail) in &layout_refusals {
                eprintln!("Warning: {detail}");
            }
            // Hosted mode already printed its own prune-ignored warning.
            if prune && !hosted {
                eprintln!("{}", render::PRUNE_SKIPPED_EMPTY);
            }
        }
        // Telemetry: empty-scan still counts as a successful scan.
        spawn_patch_scanned(
            telemetry,
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
        );
        // The result prints right away: nothing to overlap the send with.
        telemetry.flush().await;
        if args.common.json {
            // GC is intentionally skipped when the crawl finds nothing:
            // pruning every manifest entry is too destructive (`repair`
            // does full cleanup explicitly).
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
            // Layout refusals: additive top-level `warnings` (omitted when
            // empty) so a consumer can tell an unscannable project from an
            // empty one.
            if !layout_refusals.is_empty() {
                result["warnings"] = layout_refusal_json(&layout_refusals);
            }
            // Hosted mode: a no-op `redirect` block keeps the envelope
            // schema-consistent with the ≥1-package path.
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
                // `redirectState` rides the empty-discovery envelope too
                // (same rule as the ≥1-package path). `wiringLive` is empty
                // by construction: this run covered zero packages.
                let redirect_state = (!args.common.is_global()).then_some(
                    crate::commands::hosted_state_from_lockfiles(
                        &args.common,
                        &args.common.cwd,
                    )
                    .await,
                );
                if let Some(state) = redirect_state_json(redirect_state.as_ref(), &[]) {
                    result["redirectState"] = state;
                }
            }
            let code =
                embed_vex_into_json(&args.common, &args.vex, &manifest_path, 0, &mut result).await;
            print_json(&result);
            return code;
        } else if !args.common.silent {
            println!(
                "{}",
                render::no_packages_message(
                    args.common.is_global(),
                    args.common.ecosystems.as_deref(),
                    &args.paths,
                )
            );
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

    status.finish_with(format!(
        "Found {}{eco_summary}",
        plural(package_count, "package", "packages")
    ));
    if human {
        if !lockfile_only.purls.is_empty() {
            eprintln!("{}", render::lockfile_only_note(lockfile_only.purls.len()));
        }
        for (_, detail) in &layout_refusals {
            eprintln!("Warning: {detail}");
        }
    }

    // Query API in batches
    let mut all_packages_with_patches: Vec<BatchPackagePatches> = Vec::new();
    let mut can_access_paid_patches = false;
    let chunks: Vec<&[String]> = batch_chunks(&all_purls, batch_size, BATCH_BODY_BYTE_CAP);
    let total_batches = chunks.len();
    let mut batch_error_count = 0usize;
    let mut last_batch_error: Option<String> = None;
    // `--json` twin of the per-batch stderr warnings: `(batch, error)` in
    // chunk order, surfaced as run-level `warnings[]` when some batch
    // succeeded (all failing is the error envelope below).
    let mut failed_batches: Vec<(usize, String)> = Vec::new();

    // Fold one batch outcome; callers consume outcomes strictly in chunk
    // order.
    let mut fold = |batch_idx: usize,
                    result: Result<BatchSearchResponse, ApiError>,
                    status: &mut StatusLine<_>| match result {
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
            failed_batches.push((batch_idx + 1, e.to_string()));
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
    };

    // The batches run concurrently (at most `api_concurrency` in flight)
    // but are CONSUMED in chunk order, one window at a time:
    //
    // - On the authenticated client the first chunk goes alone, so a stale
    //   token costs the authenticated API one request before the
    //   downgrade. Already on the proxy, the full window opens at chunk 0.
    // - Fallback: at the first consumed chunk `k` whose error is a 401/403
    //   fallback candidate, the window is dropped (in-flight requests past
    //   `k` cancelled, received responses and their held-back `--debug`
    //   lines discarded), chunk `k` is retried against the public proxy
    //   (free patches only), and the rest continues on the downgraded
    //   client. No further fallback applies on the proxy.
    let mut next = 0usize;
    'windows: while next < total_batches {
        let end = if next == 0 && !use_public_proxy {
            1
        } else {
            total_batches
        };
        let mut fallback_error = None;
        {
            let client = &api_client;
            let mut results = std::pin::pin!(ordered_concurrent(
                &chunks[next..end],
                api_concurrency_for(use_public_proxy, end - next),
                |chunk| hold_back_debug(client.search_patches_batch(chunk)),
            ));
            while next < end {
                status.set(format!(
                    "Querying API for patches... (batch {}/{total_batches})",
                    next + 1
                ));
                // `ordered_concurrent` yields one item per chunk. Should it
                // ever run dry early, stop: re-entering the outer loop with
                // `next` unchanged would re-POST the same window forever.
                let Some(result) = results.next().await else {
                    debug_assert!(false, "batch window yields one result per chunk");
                    break 'windows;
                };
                match result.release() {
                    Err(e) if !use_public_proxy && is_fallback_candidate(&e) => {
                        fallback_error = Some(e);
                        break;
                    }
                    result => fold(next, result, &mut status),
                }
                next += 1;
            }
        }
        if let Some(e) = fallback_error {
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
            let result = api_client.search_patches_batch(chunks[next]).await;
            fold(next, result, &mut status);
            next += 1;
        }
    }

    // Batches are only sorted within each chunk. Sort globally: this list
    // drives the table, the `--json` `packages` array and the apply order,
    // which operators diff across runs.
    all_packages_with_patches.sort_by(|a, b| a.purl.cmp(&b.purl));

    // If every batch errored, surface a full scan failure rather than
    // silently reporting zero patches.
    if total_batches > 0 && batch_error_count == total_batches {
        status.finish();
        let err = last_batch_error.unwrap_or_else(|| "all batches failed".to_string());
        spawn_patch_scan_failed(
            telemetry,
            &err,
            fallback_to_proxy,
            telemetry_token.as_deref(),
            telemetry_org.as_deref(),
        );
        // The failure prints right away: nothing to overlap the send with.
        telemetry.flush().await;
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

    // Telemetry: record the scan outcome with the per-tier counts.
    spawn_patch_scanned(
        telemetry,
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
    );

    // Read existing manifest once for update detection.
    let existing_manifest = read_manifest(&manifest_path).await.ok().flatten();
    // Hosted mode records its patches ONLY in the lockfiles (v5 keeps no
    // hosted ledger) and vendored mode ONLY in its ledger, so the hosted
    // pins and the vendor ledger's purl→uuid records are folded into update
    // detection (otherwise their `updates[]` would stay empty).
    let hosted_pin_list: Vec<socket_patch_core::patch::redirect::upstream::HostedPin> =
        if args.common.is_global() {
            Vec::new()
        } else {
            socket_patch_core::patch::redirect::upstream::HostedPin::all(
                &crate::commands::discover_wiring(&args.common, &args.common.cwd).await,
            )
        };
    let redirect_state = (!args.common.is_global())
        .then(|| crate::commands::hosted_state_from_pins(&hosted_pin_list));
    let hosted_pins: Vec<(String, String)> = hosted_pin_list
        .iter()
        .map(|pin| (pin.purl.clone(), pin.uuid.clone()))
        .collect();
    let update_manifest = merge_ledger_records_for_updates(
        existing_manifest.as_ref(),
        vendor_state.as_ref().ok(),
        &hosted_pins,
    );
    let updates = detect_updates(update_manifest.as_deref(), &all_packages_with_patches);

    // The hosted-wiring probes below take `all_purls` (POST-filter: only
    // packages this run covered), unlike the PRE-filter `scanned_purls`
    // the GC prune uses.

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
        // Layout refusals ride the non-empty envelope too (additive,
        // omitted when empty).
        if !layout_refusals.is_empty() {
            result["warnings"] = layout_refusal_json(&layout_refusals);
        }
        // One warning per failed batch (status and exit unchanged).
        for (batch, err) in &failed_batches {
            let line = render::batch_failed_warning(*batch, total_batches, err);
            let detail = line.strip_prefix("Warning: ").unwrap_or(&line);
            push_scan_json_warning(&mut result, API_BATCH_FAILED, detail);
        }
        // Flag lockfile-only packages (additive; absent means installed).
        // `normalize_purl` bridges the API's percent-encoded spelling to the
        // supplement's literal form.
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

        // Hosted mode: NEST the redirect result under `redirect` in the scan
        // object above (like vendored mode's `vendor` block).
        if hosted {
            return run_redirect(
                &args,
                &api_client,
                &all_packages_with_patches,
                can_access_paid_patches,
                Some(result),
                telemetry,
                npm_crawl.as_ref(),
            )
            .await;
        }

        // The additive `redirectState` block rides every report-only and
        // agent `--json` envelope. Hosted and vendored runs are excluded:
        // both may rewrite the ledger mid-run, so a pre-run snapshot would
        // go stale. The live-wiring probe runs ONCE here and is shared with
        // the agent-flow warning below.
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
                telemetry,
                Some(&mut result),
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
            // skip records BEFORE download (see `partition_agent_selection`).
            let AgentSelection {
                kept: selected,
                skip_records: vendored_records,
                vendored_purls: vendored_skip_purls,
                ..
            } = partition_agent_selection(selected, &vendored_purls, &lockfile_only);

            if dry {
                // Synthesize the per-patch outcome without touching disk.
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
                // Nothing left to download: a stable-shape `apply` carrying
                // any skips, then fall through to GC if requested.
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

            // Cross-mode visibility: additive run-level warnings, never a
            // status or exit-code change.
            if !vendored_skip_purls.is_empty() {
                let detail = vendored_ownership_retained_detail(&vendored_skip_purls);
                if !args.common.silent {
                    eprintln!("Warning: {detail}");
                }
                push_scan_json_warning(&mut result, VENDORED_OWNERSHIP_RETAINED, &detail);
            }
            if !hosted_retained.is_empty() {
                let detail = hosted_wiring_retained_detail(&hosted_retained);
                if !args.common.silent {
                    eprintln!("Warning: {detail}");
                }
                push_scan_json_warning(&mut result, HOSTED_WIRING_RETAINED, &detail);
            }
        // --- Vendor path (if requested; conflicts with --apply/--sync) ---
        } else if vendor {
            // Must STAY a boxed fn: this branch's temporaries would otherwise
            // live in the enclosing poll frame in debug builds, which has to
            // fit Windows' 1 MiB main-thread stack.
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
                telemetry,
                npm_crawl.as_ref(),
            )
            .await;
        }

        // The GC and the VEX build below can write to stderr; the report-
        // only arm has not flushed the scan event yet (the `--apply` arm
        // did, in `discover_selected`).
        telemetry.flush().await;

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

    // Every human exit below prints first; the scan event goes out before.
    telemetry.flush().await;

    let use_color = ui::stdout_color();
    let verbose = args.common.verbose;
    let silent = args.common.silent;

    // Every human-path exit that did not fail: the `--prune` GC first
    // (not vendored, which runs its own, nor hosted, which runs none), then
    // the embedded VEX. An early "nothing to apply" exit still runs the GC.
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

    // Every mode stops on an empty discovery, vendored included (restoring
    // a wiped `.socket/vendor/` is `repair`'s job).
    if all_packages_with_patches.is_empty() {
        if !silent {
            println!("\nNo patches available for installed packages.");
        }
        return finish_human(0).await;
    }

    // Presentational only, so `--silent` skips it wholesale.
    if !silent {
        let mut updates_available = 0usize;

        // PURLs with a newer patch, from the same `detect_updates` result the
        // JSON `updates` array uses, so the table and JSON never disagree.
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

            // Collect vuln IDs (deterministic; see collect_vuln_ids).
            let vuln_str = render::vuln_cell(&collect_vuln_ids(pkg), verbose);

            let has_update = update_purls.contains(pkg.purl.as_str());
            if has_update {
                updates_available += 1;
            }

            let update_marker = if has_update {
                ui::paint(" [UPDATE]", "33", use_color)
            } else {
                String::new()
            };
            // Lockfile-only packages can be vendored (fetched pristine) but
            // not applied in place.
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
        let cap = std::io::stdout().is_terminal().then(ui::stdout_width);
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
                println!("\n{}", ui::PAID_UPGRADE);
            }
        }

        if updates_available > 0 {
            println!(
                "\n{}",
                ui::paint(&render::updates_line(updates_available), "33", use_color),
            );
        }
    }

    // Count downloadable patches: a free-tier org whose every offer is
    // paid-tier has nothing any mode could select, so every human arm stops
    // here with the same paid-subscription line.
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
            println!("\nNo downloadable patches: every patch found requires a paid Socket plan.");
        }
        return finish_human(0).await;
    }

    // Hosted mode is a self-contained flow: it reuses the discovery, table
    // and update detection above, then hands the selection to the redirect
    // engine (the same entry as `get --mode hosted`) — it must NOT fall
    // through to the apply/vendor branches.
    if hosted {
        let selected = match discover_selected(
            &api_client,
            &all_packages_with_patches,
            can_access_paid_patches,
            &args.common,
            human,
            !silent,
            telemetry,
            None,
        )
        .await
        {
            Ok(s) => s,
            // `discover_selected` already printed the failure to stderr.
            Err((code, _)) => {
                return code;
            }
        };
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
            npm_crawl.as_ref(),
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

    // A scan left without a mode (`--prune` or global; see
    // `resolve_mode_flags`) only reports, plus the `--prune` GC.
    let report_only = args.mode.is_none();

    // Scan always takes the top-ranked patch (see `selection_args`).
    let mut select_common = selection_args(&args.common);
    select_common.silent |= report_only;
    let selected: Vec<PatchSearchResult> =
        match select_patches(&all_search_results, can_access_paid_patches, &select_common) {
            Ok(s) => s,
            Err(code) => return code,
        };

    // The skip / already-recorded lines below open their own paragraph
    // under the table's Summary: one blank line before the first of them.
    let mut skip_paragraph = false;

    // Agent flow (mirrors the JSON arm): vendor-owned and lockfile-only
    // purls leave the selection as skips. Vendored mode partitions nothing.
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

    // Drop selections the manifest already records at the same uuid.
    // Agent mode only: vendored mode never reads the manifest.
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

    // Display detailed summary of selected patches (skipped under --silent).
    if !silent {
        if vendor {
            println!("\nPatches to vendor:\n");
        } else {
            println!("\nPatches to apply:\n");
        }
        for patch in &selected {
            let severity = ui::severity(
                render::highest_severity(patch).unwrap_or("unknown"),
                use_color,
            );
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

    // What the dry-run line offers.
    let plan = if vendor {
        render::Plan::Vendor(selected.len())
    } else {
        render::Plan::Apply(selected.len())
    };

    // `--dry-run` is a non-mutating preview: stop here, having printed the
    // table and the per-patch plan above, before the download/apply and the
    // prune GC (which runs as a read-only preview instead).
    if args.common.dry_run {
        if !silent {
            // Vendored preview: the JSON arm's ledger classification,
            // rendered as `[would-refuse]` lines so a preview never
            // advertises vendoring the wet run would refuse.
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

    if report_only {
        // The "Patches to apply:" listing already ends with a blank line.
        if !silent {
            for line in render::report_only_hint() {
                println!("{line}");
            }
        }
        if prune {
            gc::run_human_gc(
                &args.common,
                &manifest_path,
                &socket_dir,
                &scanned_purls,
                &vendored_purls,
            )
            .await;
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Vendor mode: pre-verify baselines so a content mismatch is reported
    // before vendoring starts (vendoring still proceeds — the stage
    // force-applies the verified patched content). The fetched views seed
    // the download phase.
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
        if any_mismatch {
            println!();
        }
        views
    } else {
        HashMap::new()
    };

    // Download, then apply in place — or vendor (vendored mode, where the
    // download only saves and the vendor step below does the rest).
    let params = download_params(
        &args, /*save_only=*/ vendor, /*json=*/ false, silent,
    );

    let code = if vendor {
        // Boxed for the same Windows 1 MiB frame reason as the JSON path.
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
            npm_crawl.as_ref(),
        )
        .await
    } else {
        let (code, _) =
            download_and_apply_patches_with(&selected, &params, &download_run(&args, &api_client))
                .await;
        code
    };

    // Cross-mode visibility, mirroring the JSON apply path: warn when the
    // hosted redirect wiring is still live for scanned package(s). (The
    // vendored-ownership counterpart is the `[skip]` lines above.)
    if !vendor && !silent {
        let hosted_retained =
            hosted_wiring_retained_purls(&args.common, redirect_state.as_ref(), &all_purls).await;
        if !hosted_retained.is_empty() {
            eprintln!(
                "Warning: {}",
                hosted_wiring_retained_detail(&hosted_retained)
            );
        }
    }

    // Post-apply GC: only with `--prune` or `--sync`; otherwise an agent
    // apply leaves every other manifest entry alone (`socket-patch repair`
    // cleans up explicitly). Vendor mode runs its own GC in `vendor_flow`.
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

    #[test]
    fn project_dirs_resolve_directories_and_globs() {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["apps/web", "apps/api", "libs/core"] {
            std::fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        std::fs::write(tmp.path().join("apps/README"), "").unwrap();
        let rel = |dirs: Vec<PathBuf>| -> Vec<String> {
            dirs.iter()
                .map(|d| d.strip_prefix(tmp.path()).unwrap().to_string_lossy().replace('\\', "/"))
                .collect()
        };
        let got = project_dirs(tmp.path(), &["apps/*".into(), "libs/core".into(), "apps/web".into()])
            .unwrap();
        assert_eq!(rel(got), ["apps/api", "apps/web", "libs/core"]);
        assert!(project_dirs(tmp.path(), &["apps/README".into()])
            .unwrap_err()
            .contains("is not a directory"));
        assert!(project_dirs(tmp.path(), &["nope/*".into()])
            .unwrap_err()
            .contains("matches no directory"));
        assert!(project_dirs(tmp.path(), &["x[".into()])
            .unwrap_err()
            .contains("invalid path pattern"));
    }

    #[test]
    fn package_specs_match_names_and_purls() {
        let lodash = "pkg:npm/lodash@4.17.20";
        let scoped = "pkg:npm/%40babel/core@7.0.0";
        let maven = "pkg:maven/org.apache/commons-text@1.9";
        assert!(package_spec_matches("lodash", lodash));
        assert!(package_spec_matches("LoDash", lodash));
        assert!(package_spec_matches("pkg:npm/lodash", lodash));
        assert!(package_spec_matches("pkg:npm/lodash@4.17.20", lodash));
        assert!(!package_spec_matches("pkg:npm/lodash@4.17.21", lodash));
        assert!(!package_spec_matches("pkg:pypi/lodash", lodash));
        assert!(!package_spec_matches("lodash-es", lodash));
        assert!(!package_spec_matches("pkg:npm/lodash-es", lodash));
        assert!(package_spec_matches("@babel/core", scoped));
        assert!(package_spec_matches("core", scoped));
        assert!(package_spec_matches("pkg:npm/@babel/core", scoped));
        assert!(package_spec_matches("pkg:npm/%40babel/core", scoped));
        assert!(package_spec_matches("org.apache:commons-text", maven));
        assert!(package_spec_matches("commons-text", maven));
        assert!(!package_spec_matches("", lodash));
    }

    /// The load-then-derive form of [`overlap_from_states`]: the unit
    /// tests' entry point (production classifies over state it already
    /// holds via `classify_overlap_takeover_with`). The hosted side is the
    /// lockfiles' hosted pins — never a pre-v5 redirect ledger on disk — and
    /// a malformed vendor ledger classifies like a missing one: this path
    /// only feeds takeover WARNINGS; the corruption itself is a hard error on
    /// every path that would write or attest from the ledger.
    async fn overlapping_purls(common: &GlobalArgs, cwd: &Path) -> Vec<String> {
        let redirect = crate::commands::hosted_state_from_lockfiles(common, cwd).await;
        let Ok(vendor) = socket_patch_core::vendor::load_state(cwd).await else {
            return Vec::new();
        };
        overlap_from_states(Some(&redirect), &vendor)
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

    /// The request body `search_patches_batch` sends for `chunk`, as
    /// `serde_json` writes it (the client's `BatchSearchBody`).
    fn batch_body(chunk: &[String]) -> String {
        let components: Vec<serde_json::Value> = chunk
            .iter()
            .map(|p| serde_json::json!({ "purl": p }))
            .collect();
        serde_json::json!({ "components": components }).to_string()
    }

    fn purls(n: usize, len: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let head = format!("pkg:npm/p{i}-");
                let pad = len.saturating_sub(head.len() + 6);
                format!("{head}{}@1.0.0", "x".repeat(pad))
            })
            .collect()
    }

    /// Unset, the batch size follows the endpoint: the server's 500-purl
    /// maximum on the authenticated API, 100 on the public proxy. A given
    /// size wins on both, and 0 is floored to 1.
    #[test]
    fn batch_size_defaults_per_endpoint_and_honors_an_explicit_value() {
        assert_eq!(effective_batch_size(None, false), 500);
        assert_eq!(effective_batch_size(None, true), 100);
        assert_eq!(effective_batch_size(Some(7), false), 7);
        assert_eq!(effective_batch_size(Some(7), true), 7);
        assert_eq!(effective_batch_size(Some(0), false), 1);
        assert_eq!(effective_batch_size(Some(0), true), 1);
    }

    /// The byte arithmetic matches `serde_json`'s output exactly, escapes
    /// and non-ASCII included, so the cap is judged on the real body.
    #[test]
    fn batch_component_bytes_match_the_serialized_body() {
        for purl in [
            "pkg:npm/left-pad@1.3.0",
            "pkg:npm/%40scope/name@1.0.0",
            "pkg:pypi/we\"ird@1.0?x=\\y",
            "pkg:cargo/caf\u{e9}@0.1.0",
            "pkg:npm/ctl\u{1}@1.0.0",
        ] {
            let one = vec![purl.to_string()];
            assert_eq!(
                17 + batch_component_bytes(purl),
                batch_body(&one).len(),
                "{purl}"
            );
        }
        let many = purls(9, 40);
        let sum: usize = many.iter().map(|p| batch_component_bytes(p)).sum();
        assert_eq!(17 + sum + (many.len() - 1), batch_body(&many).len());
    }

    /// With a cap no chunk reaches, the chunks are exactly
    /// `purls.chunks(batch_size)`: same boundaries, same order.
    #[test]
    fn batch_chunks_without_cap_pressure_match_plain_chunking() {
        for n in [0usize, 1, 99, 100, 101, 499, 500, 501, 1000, 1234] {
            let list = purls(n, 30);
            for size in [1usize, 3, 100, 500] {
                let want: Vec<&[String]> = list.chunks(size).collect();
                assert_eq!(
                    batch_chunks(&list, size, BATCH_BODY_BYTE_CAP),
                    want,
                    "n={n} size={size}"
                );
            }
        }
    }

    /// An oversize chunk is split greedily at the byte cap: every body fits,
    /// every chunk is maximal (its successor's first purl would not have
    /// fitted), nothing is dropped or reordered, and the split is the same
    /// on every call.
    #[test]
    fn batch_chunks_split_an_oversize_chunk_at_the_byte_cap() {
        let list = purls(1400, 220);
        let chunks = batch_chunks(&list, 5000, BATCH_BODY_BYTE_CAP);
        assert!(chunks.len() > 1, "1400 x 220-byte purls exceed 256 KiB");
        for (i, chunk) in chunks.iter().enumerate() {
            assert!(batch_body(chunk).len() <= BATCH_BODY_BYTE_CAP, "chunk {i}");
            if let Some(next) = chunks.get(i + 1) {
                let mut grown = chunk.to_vec();
                grown.push(next[0].clone());
                assert!(batch_body(&grown).len() > BATCH_BODY_BYTE_CAP, "chunk {i}");
            }
        }
        assert_eq!(chunks.concat(), list);
        assert_eq!(chunks, batch_chunks(&list, 5000, BATCH_BODY_BYTE_CAP));

        // The count limit still applies inside the byte limit, and a body
        // exactly at the cap is kept whole.
        let small = batch_chunks(&list, 500, BATCH_BODY_BYTE_CAP);
        assert!(small.iter().all(|c| c.len() <= 500));
        let exact = batch_body(&list[..10]).len();
        assert_eq!(batch_chunks(&list[..11], 500, exact)[0].len(), 10);
    }

    /// A purl too long for the cap on its own still goes, alone, between
    /// its neighbours' chunks.
    #[test]
    fn batch_chunks_send_an_oversize_purl_alone() {
        let mut list = purls(4, 30);
        list.insert(2, format!("pkg:npm/{}@1.0.0", "y".repeat(400)));
        let chunks = batch_chunks(&list, 100, 200);
        assert_eq!(chunks.concat(), list);
        let alone: Vec<&[String]> = chunks
            .iter()
            .copied()
            .filter(|c| c.contains(&list[2]))
            .collect();
        assert_eq!(alone, vec![&list[2..3]]);
        assert!(chunks.iter().all(|c| !c.is_empty()));
    }

    /// MVN-4: only a non-GC `--ecosystems` run narrows the crawl. A GC run
    /// crawls every ecosystem whatever `--ecosystems` says (its prune reads
    /// the full installed set), and no `--ecosystems` crawls every one.
    #[test]
    fn crawl_scope_narrows_only_a_non_gc_filtered_run() {
        let npm = vec!["npm".to_string()];
        assert_eq!(crawl_scope(false, Some(&npm)), Some(&npm[..]));
        assert_eq!(crawl_scope(true, Some(&npm)), None);
        assert_eq!(crawl_scope(false, None), None);
        assert_eq!(crawl_scope(true, None), None);
    }

    // ---- cross-mode takeover (hosted over vendored) ------------------------

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

    /// Write a PRE-V5 hosted redirect ledger
    /// (`.socket/vendor/redirect-state.json`) recording a redirect for each
    /// PURL. v5 never writes one and never reads it for hosted state: the
    /// tests plant it only to prove it is ignored.
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

    /// An in-memory hosted state holding one [`takeover_record`] per PURL
    /// under the given (possibly non-canonical) keys — the shape
    /// [`crate::commands::hosted_state_from_pins`] builds, for the block
    /// builder and the probe's own liveness gate.
    fn pinned_state(purls: &[&str]) -> socket_patch_core::patch::redirect::RedirectState {
        let mut state = socket_patch_core::patch::redirect::RedirectState::new();
        for purl in purls {
            state.records.insert((*purl).to_string(), takeover_record());
        }
        state
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
    async fn hosted_pin_over_a_vendored_entry_flags_the_taken_over_package() {
        // The lock pins minimist to the hosted patch server while the vendored
        // ledger still claims it ⇒ one mode took the lockfile over from the
        // other. The detection names exactly the overlapping PURL.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_lock_pointing_at_hosted(root, "minimist", "1.2.2").await;
        write_vendor_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;

        let superseded = overlapping_purls(&common_at(root), root).await;
        assert_eq!(superseded, vec!["pkg:npm/minimist@1.2.2".to_string()]);
    }

    #[tokio::test]
    async fn single_side_present_flags_nothing() {
        // A first-time redirect (a hosted pin, no vendored ledger) displaces
        // nothing — no warning. Guards against warning on the FIRST scan of a
        // fresh project.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_lock_pointing_at_hosted(root, "minimist", "1.2.2").await;
        assert!(overlapping_purls(&common_at(root), root).await.is_empty());

        // And a project with no lockfile and no ledgers at all.
        let tmp2 = tempfile::tempdir().unwrap();
        assert!(overlapping_purls(&common_at(tmp2.path()), tmp2.path())
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn disjoint_states_are_not_a_takeover() {
        // A legitimate split — one package pinned hosted, a DIFFERENT one
        // vendored — is not a takeover: neither side's wiring is stale.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_lock_pointing_at_hosted(root, "minimist", "1.2.2").await;
        write_vendor_ledger(root, &["pkg:npm/lodash@4.17.21"]).await;
        assert!(overlapping_purls(&common_at(root), root).await.is_empty());
    }

    #[tokio::test]
    async fn legacy_redirect_ledger_is_not_hosted_state() {
        // v5 derives hosted state from the lockfiles only: a pre-v5 ledger
        // still claiming minimist, with no lockfile pinning it hosted, makes
        // no overlap with the vendored ledger — and no directional warning.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;

        assert!(overlapping_purls(&common_at(root), root).await.is_empty());
        assert_eq!(
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default(),
            "a legacy ledger must never be read as hosted state"
        );
    }

    /// The overlap keys on hosted RECORDS only: a state carrying edits but no
    /// records (the shape a pre-v5 run with failed record fetches persisted)
    /// names no package, so nothing overlaps.
    #[tokio::test]
    async fn edits_only_hosted_state_names_no_package() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        let vendor = socket_patch_core::vendor::load_state(root).await.unwrap();

        let mut edits_only = socket_patch_core::patch::redirect::RedirectState::new();
        edits_only
            .edits
            .push(socket_patch_core::patch::redirect::FileEdit {
                path: "package-lock.json".to_string(),
                kind: "redirect_npm_lock_entry".to_string(),
                action: "modified".to_string(),
                key: Some("node_modules/minimist".to_string()),
                original: None,
                new: None,
            });
        assert!(overlap_from_states(Some(&edits_only), &vendor).is_empty());
        assert!(overlap_from_states(None, &vendor).is_empty());
        assert_eq!(
            overlap_from_states(Some(&pinned_state(&["pkg:npm/minimist@1.2.2"])), &vendor),
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "positive control: a record names the package"
        );
    }

    #[test]
    fn selection_args_never_prompts() {
        for common in [
            GlobalArgs::default(),
            GlobalArgs {
                json: true,
                ..GlobalArgs::default()
            },
        ] {
            let picked = selection_args(&common);
            assert!(!picked.json && picked.yes, "scan always takes the top patch");
        }
    }

    #[test]
    fn takeover_detail_names_package_and_remediation() {
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];

        // Hosted displaced a vendored ledger: per-package `remove <purl>` is
        // the offered remediation; `vendor --revert` is named only as
        // something NOT to run (it mass-reverts). Deleting the
        // `.socket/vendor/<eco>/` tree by hand hard-breaks cargo resolution
        // while `[patch.crates-io]` still references it.
        let hosted = mode_takeover_detail(&purls);
        assert!(hosted.contains("pkg:npm/minimist@1.2.2"));
        assert!(hosted.contains("state.json"));
        assert!(hosted.contains("orphaned"));
        assert!(hosted.contains("vendor --revert"));
        assert!(
            !hosted.contains("or delete the orphaned"),
            "deleting the vendor tree must not be offered as an equal \
             alternative: {hosted}"
        );
        // v5 keeps no hosted ledger, so the detail must not point at one.
        assert!(
            !hosted.contains("redirect-state.json"),
            "the detail must not name the retired hosted ledger: {hosted}"
        );
    }

    // ---- agent-flow hosted-wiring retention (hosted → agent conversion) ----

    /// yarn classic lock whose resolved URL is the hosted artifact (carries
    /// the patch uuid) — the live-hosted-wiring proof.
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

    /// yarn classic lock resolving minimist from the public registry — no
    /// hosted pin.
    async fn write_registry_yarn_lock(root: &Path) {
        tokio::fs::write(
            root.join("yarn.lock"),
            "# yarn lockfile v1\n\n\nminimist@^1.2.2:\n  version \"1.2.2\"\n  \
             resolved \"https://registry.yarnpkg.com/minimist/-/minimist-1.2.2.tgz#bbbb\"\n  \
             integrity sha512-orig==\n",
        )
        .await
        .unwrap();
    }

    /// The project's hosted state as production derives it: the lockfiles'
    /// hosted pins (`Some`, as a non-global scan passes it).
    async fn hosted_state(
        common: &GlobalArgs,
    ) -> Option<socket_patch_core::patch::redirect::RedirectState> {
        Some(crate::commands::hosted_state_from_lockfiles(common, &common.cwd).await)
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
        write_hosted_yarn_lock(root, TAKEOVER_UUID).await;

        // Hosted-only wiring (no vendor state.json) is structurally
        // invisible to the hosted⇄vendored overlap classifier…
        assert!(overlapping_purls(&common_at(root), root).await.is_empty());
        assert_eq!(
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default()
        );

        // …but the agent flow's direct probe sees it for scanned purls.
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();
        let state = hosted_state(&common_at(root)).await;
        let retained =
            hosted_wiring_retained_purls(&common_at(root), state.as_ref(), &scanned).await;
        assert_eq!(retained, vec![purl.to_string()]);
    }

    #[tokio::test]
    async fn hosted_retained_probe_is_silent_without_live_pins_or_wiring() {
        let purl = "pkg:npm/minimist@1.2.2";
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();

        // (a) Registry-clean lock beside a pre-v5 ledger still recording the
        // redirect: the lockfiles hold no pin, and the legacy ledger is
        // never consulted.
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger(tmp.path(), &[purl]).await;
        write_registry_yarn_lock(tmp.path()).await;
        let common = common_at(tmp.path());
        let state = hosted_state(&common).await;
        assert!(state.as_ref().is_some_and(|s| s.records.is_empty()));
        assert!(
            hosted_wiring_retained_purls(&common, state.as_ref(), &scanned)
                .await
                .is_empty(),
            "no pin ⇒ silent (a legacy ledger must not re-warn)"
        );

        // (b) A state record the live lock does not back (the lock was
        // re-resolved after the state was taken): the live lock is the truth
        // source — never guess from state presence alone.
        let stale = pinned_state(&[purl]);
        assert!(
            hosted_wiring_retained_purls(&common, Some(&stale), &scanned)
                .await
                .is_empty(),
            "registry-clean lock ⇒ silent"
        );

        // (c) The purl was not scanned this run.
        let tmp = tempfile::tempdir().unwrap();
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        let common = common_at(tmp.path());
        let other: HashSet<String> = ["pkg:npm/lodash@4.17.21".to_string()].into_iter().collect();
        let state = hosted_state(&common).await;
        assert!(
            hosted_wiring_retained_purls(&common, state.as_ref(), &other)
                .await
                .is_empty(),
            "unscanned purl ⇒ silent"
        );

        // (d) No hosted state at all (a global scan passes `None`).
        assert!(
            hosted_wiring_retained_purls(&common, None, &scanned)
                .await
                .is_empty(),
            "no state ⇒ silent"
        );
    }

    #[tokio::test]
    async fn hosted_retained_probe_reads_the_vlt_lock() {
        let purl = "pkg:npm/minimist@1.2.2";
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();
        let url = format!(
            "https://patch.socket.dev/patch/npm/minimist/1.2.2/tok/{TAKEOVER_UUID}/minimist-1.2.2.tgz"
        );
        let lock = |slot2: &str, slot3: &str| {
            format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    \
                 \"~npm~minimist@1.2.2\": [0,\"minimist\",\"{slot2}\",\"{slot3}\"]\n  }},\n  \
                 \"edges\": {{}}\n}}\n"
            )
        };
        let hosted = lock("sha512-patched==", &url);
        let registry = lock(
            "sha512-orig==",
            "https://registry.npmjs.org/minimist/-/minimist-1.2.2.tgz",
        );
        for (what, text, live) in [
            ("hosted pin", hosted.clone(), true),
            ("reverted to the registry", registry, false),
            (
                "BOM-prefixed pin vlt cannot read",
                format!("\u{feff}{hosted}"),
                false,
            ),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            tokio::fs::write(tmp.path().join("vlt-lock.json"), text)
                .await
                .unwrap();
            let common = common_at(tmp.path());
            let want = if live {
                vec![purl.to_string()]
            } else {
                Vec::new()
            };
            // The lockfiles' own pins, as production derives them…
            let state = hosted_state(&common).await;
            let pinned: Vec<String> = state
                .iter()
                .flat_map(|s| s.records.keys().cloned())
                .collect();
            assert_eq!(pinned, want, "pins: {what}");
            let retained = hosted_wiring_retained_purls(&common, state.as_ref(), &scanned).await;
            assert_eq!(retained, want, "{what}");
            // …and the probe's own liveness gate over a record the lock may
            // not back.
            let retained =
                hosted_wiring_retained_purls(&common, Some(&pinned_state(&[purl])), &scanned).await;
            assert_eq!(retained, want, "liveness: {what}");
        }
    }

    #[test]
    fn agent_retention_details_name_packages_and_safe_remediation() {
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];

        // hosted_wiring_retained: names the purl and the real options
        // (stay hosted, migrate to vendored, or restore upstream via
        // rollback), and no longer points at a hosted ledger.
        let hosted = hosted_wiring_retained_detail(&purls);
        assert!(hosted.contains("pkg:npm/minimist@1.2.2"));
        assert!(hosted.contains("scan --mode hosted"));
        assert!(hosted.contains("scan --mode vendored"));
        assert!(hosted.contains("socket-patch rollback"));
        assert!(
            !hosted.contains("redirect-state.json"),
            "v5 keeps no hosted ledger to name: {hosted}"
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

        // Distinct routing tags, also distinct from the takeover code.
        assert_ne!(HOSTED_WIRING_RETAINED, VENDORED_OWNERSHIP_RETAINED);
        assert_ne!(HOSTED_WIRING_RETAINED, REDIRECT_SUPERSEDES_VENDORED);
        assert_ne!(VENDORED_OWNERSHIP_RETAINED, REDIRECT_SUPERSEDES_VENDORED);
    }

    // ---- redirectState envelope block (read-only cross-mode visibility) ----
    // The end-to-end envelope placement (report-only + agent runs carry it,
    // hosted/vendored runs don't) is pinned by `tests/scan_invariants.rs`;
    // these pin the block builder's own gates and shape.

    /// Pins present ⇒ the block exists with each pin's canonical purl +
    /// uuid, the constant mode label, and the caller-supplied wiringLive —
    /// and no pre-v5 `ledger` / `ledgerKey` fields. No pin (a
    /// registry-clean lock, even beside a legacy ledger; no state) ⇒ `None`,
    /// so the envelope key stays additive.
    #[tokio::test]
    async fn redirect_state_block_gates_on_pins_and_splits_live_proof() {
        let purl = "pkg:npm/minimist@1.2.2";
        let scanned: HashSet<String> = [purl.to_string()].into_iter().collect();

        // A hosted pin the run did not crawl: listed, with an EMPTY
        // wiringLive (the pin is wired, just not covered by this run).
        let tmp = tempfile::tempdir().unwrap();
        write_hosted_yarn_lock(tmp.path(), TAKEOVER_UUID).await;
        let common = common_at(tmp.path());
        let state = hosted_state(&common).await;
        let unscanned: HashSet<String> = HashSet::new();
        let wiring = hosted_wiring_retained_purls(&common, state.as_ref(), &unscanned).await;
        assert_eq!(wiring, Vec::<String>::new());
        let block =
            redirect_state_json(state.as_ref(), &wiring).expect("pins present ⇒ block present");
        assert_eq!(block["mode"], "hosted");
        assert_eq!(
            block["records"],
            serde_json::json!([{ "purl": purl, "uuid": TAKEOVER_UUID }])
        );
        assert_eq!(block["wiringLive"], serde_json::json!([]));
        let keys: Vec<&str> = block
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["mode", "records", "wiringLive"],
            "v5 block carries no `ledger` key: {block}"
        );

        // Crawled this run: the same purl graduates into wiringLive.
        let wiring = hosted_wiring_retained_purls(&common, state.as_ref(), &scanned).await;
        let block =
            redirect_state_json(state.as_ref(), &wiring).expect("pins present ⇒ block present");
        assert_eq!(block["wiringLive"], serde_json::json!([purl]));

        // Registry-clean lock beside a legacy ledger that still records the
        // redirect ⇒ no pin ⇒ no block.
        let tmp = tempfile::tempdir().unwrap();
        write_redirect_ledger(tmp.path(), &[purl]).await;
        write_registry_yarn_lock(tmp.path()).await;
        let state = hosted_state(&common_at(tmp.path())).await;
        assert!(
            redirect_state_json(state.as_ref(), &[]).is_none(),
            "a legacy ledger alone asserts no hosted pin"
        );

        // No state ⇒ no block.
        assert!(redirect_state_json(None, &[]).is_none());
    }

    /// The records↔wiringLive join is a plain string compare: each record's
    /// `purl` is canonicalized to exactly the spelling the probe emits.
    /// Pinned on a percent-encoded scoped npm name and a
    /// `?platform=`-qualified gem purl.
    #[tokio::test]
    async fn redirect_state_records_canonicalize_to_the_wiring_live_spelling() {
        let scoped_key = "pkg:npm/%40scope%2Fpkg@1.0.0";
        let scoped_canon = "pkg:npm/@scope/pkg@1.0.0";
        let gem_key = "pkg:gem/nokogiri@1.13.3?platform=ruby";
        let gem_canon = "pkg:gem/nokogiri@1.13.3";

        let tmp = tempfile::tempdir().unwrap();
        let state = pinned_state(&[scoped_key, gem_key]);
        // A lock entry resolving the scoped package from its hosted
        // artifact — live hosted wiring for the scoped purl.
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
        let wiring =
            hosted_wiring_retained_purls(&common_at(tmp.path()), Some(&state), &scanned).await;
        assert_eq!(
            wiring,
            vec![scoped_canon.to_string()],
            "the hosted pin in the lock claims the scoped purl"
        );

        let block =
            redirect_state_json(Some(&state), &wiring).expect("records present ⇒ block present");
        assert_eq!(
            block["records"],
            serde_json::json!([
                { "purl": gem_canon, "uuid": TAKEOVER_UUID },
                { "purl": scoped_canon, "uuid": TAKEOVER_UUID },
            ]),
            "records carry the canonical purl (wiringLive's spelling); block={block}"
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

    /// The block's `mode` is the constant label, not the state's opaque
    /// `mode` string: a state carrying the legacy `"redirect"` still labels
    /// as `"hosted"`.
    #[test]
    fn redirect_state_mode_is_the_constant_label_for_legacy_states() {
        let mut state = pinned_state(&["pkg:npm/minimist@1.2.2"]);
        state.mode = "redirect".to_string();
        let block =
            redirect_state_json(Some(&state), &[]).expect("records present ⇒ block present");
        assert_eq!(block["mode"], "hosted");
    }

    // ---- cargo takeover direction (lock-shape probe) ------------------------
    // The scan inventory records `resolved: None` for every cargo entry, so
    // the generic patch.socket.dev check can never prove hosted for cargo;
    // these pin the cargo-specific lock-shape classifier.

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

    /// The mixed state a vendored→hosted cargo takeover can leave behind:
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
        // generic wiring scan.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
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
            "the INVERSE direction must not be reported: {takeover:?}"
        );
    }

    #[tokio::test]
    async fn cargo_lock_routed_to_vendored_yields_no_hosted_pin() {
        // The genuine vendored-live shape: detached lock entry (no source) +
        // [patch.crates-io] pointing at the entry's committed copy. The lock
        // pins nothing hosted, so there is no hosted state to overlap — even
        // with a pre-v5 ledger still claiming the crate.
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

        let common = cargo_common_at(root);
        assert!(overlapping_purls(&common, root).await.is_empty());
        assert_eq!(
            classify_overlap_takeover(&common, root).await,
            OverlapTakeover::default()
        );
    }

    #[tokio::test]
    async fn cargo_takeover_stays_silent_when_the_lock_points_at_crates_io() {
        // A third party re-resolved the lock back to crates.io: no hosted pin
        // is left (a legacy ledger claiming the crate does not count), so
        // no directional warning.
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

    /// Like [`write_vendor_ledger`] but each entry records wiring the
    /// `package-lock.json` — the file the direction check reads to see whether
    /// the lock still points at the committed `.socket/vendor/` artifact —
    /// and names the artifact the npm backend writes for the package
    /// (`<name>-<version>.tgz`, what [`write_lock_pointing_at_vendored`]
    /// wires).
    async fn write_vendor_ledger_wired(root: &Path, purls: &[&str]) {
        use socket_patch_core::utils::purl::purl_name_version;
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
        // The vendored ledger (and a pre-v5 redirect ledger) claim minimist,
        // but the LIVE lockfile resolves it to the committed
        // `.socket/vendor/` artifact — vendored is live and no hosted pin
        // exists. A hosted dry-run/no-op must NOT emit
        // `redirect_supersedes_vendored`, which would point cleanup at the
        // LIVE vendored ledger; nor is there any hosted state to call stale.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;

        assert!(overlapping_purls(&common_at(root), root).await.is_empty());
        assert_eq!(
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default(),
            "a vendored lock leaves no hosted pin to overlap"
        );
    }

    #[tokio::test]
    async fn hosted_lock_classifies_the_vendored_ledger_as_superseded() {
        // The vendored ledger claims minimist, but the LIVE lockfile resolves
        // it to the hosted patch server — hosted is live, so the vendored
        // ledger is the stale one.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_hosted(root, "minimist", "1.2.2").await;

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
        assert!(takeover.vendored.is_empty(), "{takeover:?}");
    }

    #[tokio::test]
    async fn half_migrated_locks_naming_both_stay_silent() {
        // One lockfile pins minimist hosted while another still routes it to
        // the committed vendored artifact: the raw overlap fires, but neither
        // direction is proven, so the classifier stays silent rather than
        // guess from which command is running.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;
        write_hosted_yarn_lock(root, TAKEOVER_UUID).await;

        assert_eq!(
            overlapping_purls(&common_at(root), root).await,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
        assert_eq!(
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default(),
            "both sides live ⇒ no directional warning"
        );
    }

    // ---- remediation is per-package and non-destructive ---------------------

    #[test]
    fn takeover_detail_remediation_is_per_package_and_non_destructive() {
        // Cleanup must be scoped per named package: whole-tree deletion would
        // destroy live data for packages the takeover did not touch.
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];

        let hosted = mode_takeover_detail(&purls);
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
    }

    #[test]
    fn hosted_remediation_states_removes_full_blast_radius() {
        // `socket-patch remove <purl>` also deletes the package's
        // `.socket/manifest.json` entry; the hosted text must say so.
        let purls = vec!["pkg:npm/minimist@1.2.2".to_string()];
        let hosted = mode_takeover_detail(&purls);

        assert!(
            !hosted.contains("drops only that entry"),
            "hosted remediation must not understate `remove`: {hosted}"
        );
        assert!(
            hosted.contains("`.socket/manifest.json`"),
            "hosted remediation must name the manifest entry `remove` deletes: {hosted}"
        );
        // …and must place the LIVE hosted patch (the lockfile pin itself —
        // v5 keeps no hosted ledger), so "manifest entry deleted" does not
        // read as "the hosted patch was dropped too".
        assert!(
            hosted.contains("recorded in the lockfile itself"),
            "hosted remediation must say where the live hosted patch lives: {hosted}"
        );
    }

    // ---- hosted-proof gaps: other hosts and lock formats -------------------

    /// A grant token as it appears between the host and the patch uuid in
    /// hosted artifact URLs.
    const TAKEOVER_TOKEN: &str = "33333333-3333-4333-8333-333333333333";

    #[tokio::test]
    async fn hosted_direction_provable_on_non_default_patch_host() {
        // Hosted artifact URLs embed the pin's patch uuid on ANY host the
        // operator configured (staging / self-hosted `--patch-server-url`
        // deployments), so the proof must not be pinned to the
        // `patch.socket.dev` hostname — but an unconfigured host is a user's
        // own dependency source, never a pin.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
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

        let configured = GlobalArgs {
            patch_server_url: Some("https://patches.example.com".to_string()),
            ..common_at(root)
        };
        let takeover = classify_overlap_takeover(&configured, root).await;
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "a configured non-default patch host must still prove hosted is live"
        );
        assert!(takeover.vendored.is_empty(), "{takeover:?}");

        assert_eq!(
            classify_overlap_takeover(&common_at(root), root).await,
            OverlapTakeover::default(),
            "an unconfigured host is not a hosted pin"
        );
    }

    #[tokio::test]
    async fn hosted_direction_provable_for_bun_url_tuple() {
        // bun records the hosted artifact as a URL 3-tuple; the pin must be
        // found there.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
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
        // The hosted URL lives percent-encoded in berry's `::__archiveUrl=`
        // binding. The uuid survives encoding verbatim, so the pin must be
        // found there.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
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
    async fn vendored_path_uuid_is_not_a_hosted_pin() {
        // The vendored wiring embeds the SAME patch uuid in its
        // `.socket/vendor/<eco>/<uuid>/` path. That occurrence must NOT read
        // as a hosted pin — the lock points at the vendored files.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_lock_pointing_at_vendored(root, "minimist", "1.2.2").await;

        let state = crate::commands::hosted_state_from_lockfiles(&common_at(root), root).await;
        assert!(
            state.records.is_empty(),
            "a vendored-path uuid must not be a hosted pin: {:?}",
            state.records.keys().collect::<Vec<_>>()
        );
    }

    // ---- takeover detection degradation: corrupt / probe-less state --------

    #[tokio::test]
    async fn corrupt_vendor_state_json_degrades_to_no_overlap() {
        // A hand-corrupted (or torn mid-write) `.socket/vendor/state.json`
        // must classify like a missing one: this path only feeds takeover
        // WARNINGS, and the vendored write paths hard-error on corruption
        // themselves. A hosted pin alone must not produce a spurious overlap.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_lock_pointing_at_hosted(root, "minimist", "1.2.2").await;
        let dir = root.join(".socket/vendor");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("state.json"), "not-json {{{")
            .await
            .unwrap();

        assert!(
            overlapping_purls(&common_at(root), root).await.is_empty(),
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
        // The vendored ledger (and a pre-v5 redirect ledger) claim the cargo
        // purl but there is NO Cargo.lock (a fresh checkout / deleted lock):
        // discovery finds no hosted pin, so nothing overlaps and the
        // classifier stays silent rather than guess.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_redirect_ledger(root, &[CARGO_PURL]).await;
        write_cargo_vendor_ledger(root).await;

        let common = cargo_common_at(root);
        assert!(
            overlapping_purls(&common, root).await.is_empty(),
            "no lock ⇒ no hosted pin ⇒ no overlap"
        );
        assert_eq!(
            classify_overlap_takeover(&common, root).await,
            OverlapTakeover::default(),
            "no Cargo.lock ⇒ neither direction proven ⇒ silent"
        );
    }

    // ---- hostile-ledger tamper guards (path traversal) ----------------------
    // The ledgers are committed files an attacker can edit: a recorded
    // lockfile name must never make the wiring probes READ outside the
    // project root. With nothing discovered the probes fall back to the
    // ledger's recorded files, which is the path under test.

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
