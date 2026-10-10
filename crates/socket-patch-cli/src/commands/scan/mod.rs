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
use socket_patch_core::crawlers::ruby_crawler::{
    config_path_ignored_warning, stale_plugin_registration_warning,
};
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::telemetry::{
    spawn_patch_scan_failed, spawn_patch_scanned, PendingTelemetry, TelemetryAuth,
};
use socket_patch_core::utils::concurrent::{api_concurrency_for, ordered_concurrent};
use socket_patch_core::utils::purl::{canonical_purl, normalize_purl};
use socket_patch_core::utils::purl_key::{canonical_base_purl, PurlKey};
use socket_patch_core::vendor::{purl_keys_cover, VendorState};
use socket_patch_core::vex::discover::{LedgerLiveness, WiringMode};
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::{
    crawl_ecosystems, crawl_ecosystems_with_npm, find_all_packages_for_rollback_reusing,
    partition_purls,
};
use crate::json_envelope::{
    usage_error, Command as JsonCommand, Envelope, EnvelopeError, PatchAction, PatchEvent,
    RunWarning, VexSummary,
};
use crate::ui::{self, plural, print_json, StatusLine};

use crate::commands::agent_download::{
    download_and_apply_patches_into, download_and_apply_patches_with, DownloadParams, DownloadRun,
    ALREADY_IN_MANIFEST,
};

use self::policy::{load_invocation_policy, InvocationPolicy, PolicyLoadError, ScanPolicy};
pub use self::socket_yml_args::{SocketYmlArgs, MIN_SEVERITY_ENV};

mod discovery;
mod gc;
pub(crate) mod hosted;
pub(crate) mod policy;
pub(crate) mod render;
pub(crate) mod rollout;
pub mod rollout_args;
mod socket_yml_args;
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
pub(crate) use self::discovery::{
    lockfile_supplement as project_lockfile_supplement, unsupported_layout_warnings,
    vendored_ledger_supplement as project_vendored_supplement,
};
use self::gc::gc_into;
pub(crate) use self::hosted::boxed_run_redirect_selected;
use self::hosted::run_redirect;
use self::vendor_flow::{
    boxed_vendor_interactive_path, boxed_vendor_json_path, partition_skipped_selected,
};
pub(crate) use self::vendor_flow::{boxed_vendor_step, preview_vendor, VendorStep};

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
/// `purls` plus, for each lockfile-only PyPI purl among them, its other
/// PEP 440 spellings of the same release (#604), deduplicated in order.
fn with_pypi_equivalents(purls: &[String], lockfile_only: &HashSet<PurlKey>) -> Vec<String> {
    let mut out = purls.to_vec();
    let mut seen: HashSet<PurlKey> = purls.iter().map(|p| PurlKey::new(p)).collect();
    for purl in purls {
        if !lockfile_only_contains(lockfile_only, purl) {
            continue;
        }
        for spelling in socket_patch_core::utils::purl_key::pypi_equivalent_purls(purl) {
            if seen.insert(PurlKey::new(&spelling)) {
                out.push(spelling);
            }
        }
    }
    out
}

/// Mark each API purl that names a lockfile-only PyPI pin under another
/// PEP 440 spelling (`@1.16.0` for a lock's `@1.16`, #604) as lockfile-only
/// too, so the `notInstalled` flag, the `[NOT INSTALLED]` marker and the
/// vendored baseline pre-check treat it as the package it is. A spelling an
/// installed copy already carries is left alone.
fn adopt_pypi_equivalents(
    packages: &[BatchPackagePatches],
    scanned: &[String],
    lockfile_only: &mut HashSet<PurlKey>,
) {
    let scanned_keys: HashSet<PurlKey> = scanned.iter().map(|p| PurlKey::new(p)).collect();
    let lock_only_pypi: Vec<&String> = scanned
        .iter()
        .filter(|p| p.starts_with("pkg:pypi/") && lockfile_only_contains(lockfile_only, p))
        .collect();
    for pkg in packages {
        let key = PurlKey::new(&pkg.purl);
        if scanned_keys.contains(&key) {
            continue;
        }
        if lock_only_pypi
            .iter()
            .any(|lock| socket_patch_core::utils::purl_key::pypi_same_release(lock, &pkg.purl))
        {
            lockfile_only.insert(key);
        }
    }
}

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
/// `--mode`. `--sync` is shorthand for `--mode agent --prune`.
//
// The `///` docs on the variants are user-facing `--help` text (shared
// with `get --mode`); keep implementation notes in `//` comments.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// Rewrite lockfiles so only patched dependencies resolve to Socket's
    /// hosted patch server: no artifact bytes land in the repo, but
    /// installs must reach the patch server
    Hosted,
    /// Commit patched artifacts to `.socket/vendor/`: hermetic,
    /// offline-safe installs at the cost of repo size
    Vendored,
    /// Record patches in `.socket/manifest.json` plus blobs and re-apply
    /// them in place (e.g. from CI): smallest repo footprint, but every
    /// install environment must run the agent
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

/// Resolve `args.mode` from `--mode` and `--sync`, so `ScanMode` is the
/// single source of truth everything downstream reads, and enforce the
/// cross-flag rules clap cannot express:
///
/// * `--sync` means `--mode agent --prune`, so `--mode X --sync` with any
///   mode other than agent is a contradiction → `Err`. Clap's
///   `conflicts_with` is value-independent — it could not allow
///   `--mode agent --sync` while rejecting `--mode hosted --sync` — so the
///   check lives here. `--mode agent --sync` is redundant but accepted.
/// * `--prune` is an orthogonal GC knob and never conflicts. (`--sync`'s
///   prune half is orthogonal too, and stays a separate read in `run`.)
///   Hosted mode runs no GC, so `--mode hosted --prune` stays accepted but
///   emits an explicit `redirect_prune_ignored` warning in `run` rather
///   than silently dropping the flag.
///
/// Public (not `pub(crate)`) so the CLI-contract tests can exercise the
/// resolution without driving a full `run()`.
pub fn resolve_mode_flags(args: &mut ScanArgs) -> Result<(), String> {
    if let Some(mode) = args.mode {
        if args.sync && mode != ScanMode::Agent {
            // "cannot be used with" phrasing matches clap's conflict errors —
            // the scan_vendor_e2e contract test accepts exactly that shape.
            return Err(format!(
                "--mode {} cannot be used with --sync: --sync means --mode agent --prune",
                mode.cli_name(),
            ));
        }
    } else if args.sync {
        args.mode = Some(ScanMode::Agent);
    } else if !args.prune && !args.common.is_global() {
        // v5: hosted is the default. A `--prune` or global scan with no mode
        // stays report-only (neither has a project lockfile to rewire).
        args.mode = Some(ScanMode::Hosted);
    }
    // Global installs have no project lockfile: hosted and vendored mode
    // would rewire the cwd project instead of the global copy.
    if let Some(conflict) = args
        .mode
        .and_then(|mode| crate::commands::global_mode_conflict(&args.common, mode))
    {
        return Err(conflict);
    }
    // Hosted and vendored mode rewire `--cwd`'s lockfiles and vendor
    // ledger: a manifest in another project would split the run (#745).
    if let Some(conflict) = foreign_mode_conflict(args) {
        return Err(conflict);
    }
    Ok(())
}

/// [`crate::commands::foreign_manifest_conflict`] for a resolved hosted or
/// vendored `args.mode`.
fn foreign_mode_conflict(args: &ScanArgs) -> Option<String> {
    args.mode
        .filter(|mode| *mode != ScanMode::Agent)
        .and_then(|mode| {
            crate::commands::foreign_manifest_conflict(
                &args.common,
                &format!("--mode {}", mode.cli_name()),
            )
        })
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

    /// How discovered patches are consumed [default: the mode the
    /// project's patch state already records, else hosted]. Switching an
    /// existing vendored or agent-mode project to another mode needs this
    /// flag. A `--prune` or `--global` scan with no mode only reports
    // `--sync` also selects agent; combining it with a different `--mode`
    // is rejected in `resolve_mode_flags`.
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
    #[arg(long = "package", env = "SOCKET_SCAN_PACKAGES", value_delimiter = ',')]
    pub packages: Vec<String>,

    /// On a successful scan, also generate an OpenVEX 0.2.0 document.
    /// `--vex <path>` is the trigger; the `--vex-*` knobs mirror the
    /// standalone `vex` command. The document is built from the manifest
    /// as it stands after the scan (including any `--mode agent`/`--sync`
    /// writes) and verified against on-disk state. A requested-but-failed
    /// VEX makes the command exit non-zero.
    #[command(flatten)]
    pub vex: VexEmbedArgs,

    #[command(flatten)]
    pub rollout: rollout_args::RolloutArgs,

    #[command(flatten)]
    pub socket_yml: SocketYmlArgs,
}

pub(crate) use socket_patch_core::policy::package_spec_matches;

/// Warning code: `--vex` was requested on a `--dry-run`, which generates
/// no document (a preview neither verifies nor writes an attestation).
pub(super) const VEX_SKIPPED_DRY_RUN: &str = "vex_skipped_dry_run";

/// The [`VEX_SKIPPED_DRY_RUN`] warning.
pub(super) fn vex_dry_run_warning() -> RunWarning {
    RunWarning::new(
        VEX_SKIPPED_DRY_RUN,
        "--vex was not generated: a dry run changes nothing to attest",
    )
}

/// The one `--json` emitter of `scan`: every document it prints is this
/// [`Envelope`], printed here once per run.
pub(super) fn emit_scan(env: &Envelope) {
    print_json(&env.to_value());
}

/// A fresh `scan` envelope (`dryRun` from the flags).
pub(super) fn scan_envelope(common: &GlobalArgs) -> Envelope {
    let mut env = Envelope::new(JsonCommand::Scan);
    env.dry_run = common.dry_run;
    env
}

/// Embedded-VEX side-effect for `scan`'s JSON terminal returns. When
/// `--vex` was requested and `base_code` is 0, generate the OpenVEX
/// document from the post-scan manifest and fold the outcome into
/// `env` — its `vex` summary on success, or `status: "error"` + `error`
/// on failure (per the fail-the-command contract). Returns the final exit
/// code: `base_code` when not requested / skipped / on VEX success, `1`
/// when VEX generation failed. Caller prints `env` after this returns.
async fn embed_vex_into_json(
    common: &GlobalArgs,
    vex_args: &VexEmbedArgs,
    api_client: &ApiClient,
    manifest_path: &Path,
    base_code: i32,
    env: &mut Envelope,
    hosted: bool,
) -> i32 {
    if vex_args.vex.is_none() || base_code != 0 {
        return base_code;
    }
    // A dry run is a non-mutating preview: generating here would verify the
    // deliberately untouched tree (failing outright on a not-yet-vendored
    // project) and write an attestation file to disk. The warning keeps the
    // request visible to JSON consumers instead of silently dropping it.
    if common.dry_run {
        env.warnings.push(vex_dry_run_warning());
        return base_code;
    }
    let mut params = vex_args.to_build_params(Some(api_client));
    // A hosted scan that redirected nothing (empty catalog / no grants)
    // still attests older hosted gem pins: check them against the mirror.
    params.hosted_gem_mirror_check = hosted;
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            // `vex.warnings`: note_warning suppressed these on stderr under
            // --json, so this is their only surviving channel.
            env.vex = Some(VexSummary {
                path: vex_args
                    .vex
                    .as_ref()
                    .expect("--vex is Some: guarded by the early return above")
                    .display()
                    .to_string(),
                statements: summary.statements,
                format: "openvex-0.2.0".to_string(),
                warnings: summary.warnings,
            });
            0
        }
        Err(e) => {
            env.mark_error(EnvelopeError::new(e.code.to_string(), e.message.clone()));
            append_vex_error_warnings(env, &e.embedded_warnings());
            1
        }
    }
}

/// Fold a failed embedded VEX's run-level advisories (the lockfile
/// discovery diagnostics — often the only explanation of a
/// `vendor_unwired` / `redirect_unwired` omission) into the envelope's
/// top-level `warnings[]`, the channel `--json` has once stderr is
/// silenced.
pub(super) fn append_vex_error_warnings(env: &mut Envelope, warnings: &[RunWarning]) {
    env.warnings.extend(warnings.iter().cloned());
}

/// Embedded-VEX side-effect for `scan`'s human-readable terminal returns.
/// Prints a one-line note (or error) and returns the final exit code:
/// `base_code` when not requested / skipped / on VEX success, `1` on VEX
/// failure. No-op unless `--vex` was set and `base_code` is 0.
async fn embed_vex_human(
    common: &GlobalArgs,
    vex_args: &VexEmbedArgs,
    api_client: &ApiClient,
    manifest_path: &Path,
    base_code: i32,
    hosted: bool,
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
    let mut params = vex_args.to_build_params(Some(api_client));
    // A hosted scan that redirected nothing (empty catalog / no grants)
    // still attests older hosted gem pins: check them against the mirror.
    params.hosted_gem_mirror_check = hosted;
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
/// as `Err(1)` with the failure on stderr. Selects with
/// [`select_accessible`]: scan never prompts, so every run auto-selects the
/// top-ranked patch the policy admits (see `api::ranking`). `Err`
/// carries the exit code AND the message, since JSON callers must fold it
/// into their single envelope (CLI_CONTRACT.md). `show_progress` / `warn`
/// are the human-only knobs of [`fetch_patch_details`] (JSON callers pass
/// `false, false`). `json_warnings` is the JSON callers' envelope: a
/// partial failure adds one [`PATCH_DETAILS_FAILED`] warning per failed
/// package to it, and [`Discovered::failed`] lists each failed purl.
#[allow(clippy::too_many_arguments)]
async fn discover_selected(
    api_client: &socket_patch_core::api::client::ApiClient,
    packages: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    policy: &ScanPolicy,
    show_progress: bool,
    warn: bool,
    detail_error_line: bool,
    telemetry: &mut PendingTelemetry,
    json_warnings: Option<&mut Envelope>,
) -> Result<Discovered, (i32, String)> {
    let (all_search_results, failures) =
        fetch_patch_details(api_client, packages, show_progress, warn).await;
    // The scan event's send overlapped the detail fetches; every caller's
    // next output (the error line below, a `--json` envelope) must find it
    // delivered.
    telemetry.flush().await;
    let error_count = failures.len();
    if error_count > 0 && error_count == packages.len() {
        let err = failures.last().map_or_else(
            || "all patch-detail queries failed".to_string(),
            |(_, e)| e.clone(),
        );
        let message = format!("all {error_count} patch-detail queries failed: {err}");
        if detail_error_line {
            eprintln!("{}", render::fetch_details_failed(&failures));
        } else {
            eprintln!("Error: {message}");
        }
        return Err((1, message));
    }
    // Some queries failed, some succeeded: a `--json` run has no stderr
    // warning (`warn` is human-only), so each failed package becomes a
    // run-level `warnings[]` entry — never a silent drop from the envelope.
    let offers = select_accessible(all_search_results, can_access_paid_patches, policy);
    if let Some(env) = json_warnings {
        for (purl, e) in &failures {
            env.warn(
                PATCH_DETAILS_FAILED,
                format!("could not fetch details for {purl}: {e}"),
            );
        }
        policy.fold_into_envelope(env);
    }
    Ok(Discovered {
        offers,
        failed: failures,
    })
}

/// [`discover_selected`]'s result: the offers and each failed detail
/// query as `(purl, error)` (a failure for a package with no recorded
/// patch makes a capped run's data incomplete).
struct Discovered {
    offers: rollout::Offers,
    failed: Vec<(String, String)>,
}

/// The `updates[]` JSON array.
fn updates_json(updates: &[discovery::UpdateInfo]) -> Vec<serde_json::Value> {
    updates
        .iter()
        .map(|u| {
            serde_json::json!({
                "purl": u.purl,
                "oldUuid": u.old_uuid,
                "newUuid": u.new_uuid,
            })
        })
        .collect()
}

/// Classify the discovered offers against the recorded view (§5.1), note
/// whether a capped run's data is incomplete, and (JSON) replace the
/// batch-derived `updates[]` with the by-package UPGRADE rows.
fn classified_rows(
    stage: &mut rollout::Stage,
    discovered: &Discovered,
    recorded: &rollout::RecordedState<'_>,
    batch_failed: bool,
    packages: &[BatchPackagePatches],
    result: Option<&mut Envelope>,
) -> Vec<rollout::Row> {
    let failed: Vec<String> = discovered
        .failed
        .iter()
        .map(|(purl, _)| purl.clone())
        .collect();
    stage.incomplete = rollout::lookup_incomplete(&recorded.index, &failed, batch_failed);
    let rows = rollout::classify(&discovered.offers, &recorded.index, &stage.project);
    if let Some(env) = result {
        let updates = offer_updates(&rows, discovered, recorded, packages);
        env.set_extra("updates", serde_json::Value::Array(updates_json(&updates)));
    }
    rows
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

/// `updates[]` from the by-package records (see [`rollout::merge_updates`]).
fn offer_updates(
    rows: &[rollout::Row],
    discovered: &Discovered,
    recorded: &rollout::RecordedState<'_>,
    packages: &[BatchPackagePatches],
) -> Vec<discovery::UpdateInfo> {
    let purls: Vec<String> = packages.iter().map(|p| p.purl.clone()).collect();
    rollout::merge_updates(
        rows,
        &discovered.offers,
        &purls,
        detect_updates(recorded.manifest, packages),
    )
}

/// The offers the writers would receive, one per row.
fn writers_of(rows: &[rollout::Row]) -> Vec<PatchSearchResult> {
    rows.iter().map(|r| r.writer.clone()).collect()
}

/// Plan the rows whose writer survived the mode's own partition (`kept`;
/// the rest cannot land and hold no slot), then return `kept` without the
/// deferred rows.
fn plan_kept_rows(
    stage: &mut rollout::Stage,
    rows: Vec<rollout::Row>,
    kept: Vec<PatchSearchResult>,
) -> Vec<PatchSearchResult> {
    let kept_keys: HashSet<(&str, &str)> = kept
        .iter()
        .map(|p| (p.purl.as_str(), p.uuid.as_str()))
        .collect();
    let kept_rows: Vec<rollout::Row> = rows
        .into_iter()
        .filter(|r| kept_keys.contains(&(r.writer.purl.as_str(), r.writer.uuid.as_str())))
        .collect();
    stage.plan(&kept_rows, |_| true);
    let deferred = stage.deferred_keys();
    kept.into_iter()
        .filter(|p| !deferred.contains(&(p.purl.clone(), p.uuid.clone())))
        .collect()
}

/// Fold the stage's `rollout` block and warnings into the envelope.
pub(super) fn finish_rollout_json(stage: &rollout::Stage, env: &mut Envelope) {
    env.set_extra("rollout", stage.json());
    for (code, detail) in stage.warnings() {
        env.warn(code, detail);
    }
}

/// The human `Rollout:` line and the Next-steps lines about deferred
/// patches, for the agent and vendored summaries.
fn print_rollout_human(stage: &rollout::Stage, dry_run: bool, silent: bool) {
    if silent {
        return;
    }
    for (code, detail) in stage.warnings() {
        eprintln!("Warning ({code}): {detail}");
    }
    let (line, next) = rollout::human(stage, dry_run);
    if let Some(line) = line {
        println!("\n{line}");
    }
    if !next.is_empty() {
        println!("Next steps:");
        for step in next {
            println!("  {step}");
        }
    }
}

/// The tier filter, then the policy's per-package selection (see
/// [`ScanPolicy::select`]): scan never prompts, so every package gets its
/// top-ranked admitted patch (see `api::ranking`).
fn select_accessible(
    all_search_results: Vec<PatchSearchResult>,
    can_access_paid_patches: bool,
    policy: &ScanPolicy,
) -> socket_patch_core::policy::Offers {
    let accessible: Vec<PatchSearchResult> = all_search_results
        .into_iter()
        .filter(|p| can_access_paid_patches || p.tier == "free")
        .collect();
    policy.select(accessible)
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
/// done — only when some query succeeded, even with no records (when
/// every one failed, the caller's error line carries the cause instead,
/// so nothing repeats).
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
    // Not when every query failed: the caller's error line names it.
    if warn && failures.len() < packages.len() {
        for (purl, e) in &failures {
            eprintln!("Warning: could not fetch details for {purl}: {e}");
        }
    }
    (results, failures)
}

/// Fold a [`discover_selected`] failure into a JSON caller's envelope and
/// print it. The discovery payload already in it stays — it was computed
/// from the (successful) batch phase — while `status`/`error` carry the
/// failure. The code is [`PATCH_DETAILS_FAILED`]: every patch-detail query
/// failing is the only way discovery fails.
fn emit_discovery_error_json(env: &mut Envelope, message: &str) {
    env.mark_error(EnvelopeError::new(PATCH_DETAILS_FAILED, message));
    // The rollout block describes a successful run only.
    env.extra.remove("rollout");
    emit_scan(env);
}

/// The agent-flow selection split both arms (JSON + human) share. Vendor-
/// owned purls leave first (any uuid: the committed artifact IS the patch,
/// and a manifest moved past the vendored uuid would break VEX verification
/// until a vendor run refreshes the artifact — a newer patch still surfaces
/// in `updates[]`, the operator's signal to run `scan --mode vendored`), then
/// lockfile-only purls (nothing installed to patch in place; `scan --mode vendored`
/// fetches them pristine). Both classes become calm `skipped` records —
/// never an error.
struct AgentSelection {
    /// What is left to download + apply.
    kept: Vec<PatchSearchResult>,
    /// Every skip event (`vendored` + `package_not_installed`), purl-sorted.
    skip_records: Vec<PatchEvent>,
    /// The vendored partition's purls alone — feeds the run-level
    /// `vendored_ownership_retained` warning and the human `[skip]` lines.
    vendored_purls: Vec<String>,
    /// The lockfile-only partition's purls alone (human `[skip]` lines).
    not_installed_purls: Vec<String>,
}

fn partition_agent_selection(
    selected: Vec<PatchSearchResult>,
    vendored: &HashSet<PurlKey>,
    lockfile_only: &LockfileSupplement,
) -> AgentSelection {
    let (kept, vendored_records) =
        partition_skipped_selected(selected, |p| purl_keys_cover(vendored, p), "vendored");
    let (kept, not_installed_records) = partition_skipped_selected(
        kept,
        |p| lockfile_only_contains(&lockfile_only.purls, p),
        "package_not_installed",
    );
    let purls_of = |records: &[PatchEvent]| -> Vec<String> {
        records.iter().filter_map(|r| r.purl.clone()).collect()
    };
    let vendored_purls = purls_of(&vendored_records);
    let not_installed_purls = purls_of(&not_installed_records);
    let mut skip_records = vendored_records;
    skip_records.extend(not_installed_records);
    skip_records.sort_by(|a, b| a.purl.cmp(&b.purl));
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
        all_releases: args.all_releases,
        strict: args.common.strict,
        ecosystems: args.common.ecosystems.clone(),
        persist_blobs: args.mode != Some(ScanMode::Vendored),
        patch_server_url: args.common.patch_server_url.clone(),
    }
}

/// The run-level context the agent engine borrows from scan: the client
/// `run` already built (proxy fallback included) and the flags the nested
/// apply inherits — so `scan --mode agent` honors `--lock-timeout` and never
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
/// hosted state — see [`crate::commands::hosted_state_from_pins`]) and
/// the vendored state ledger (`.socket/vendor/state.json`), sorted. A
/// non-empty result means one of the two is stale for each PURL (a
/// lockfile entry can point only one way). `None`, an empty vendor ledger,
/// or disjoint states (a legitimate split) yield no overlap.
fn overlap_from_states(
    redirect: Option<&socket_patch_core::patch::redirect::RedirectState>,
    vendor: &VendorState,
) -> Vec<String> {
    socket_patch_core::ledgers::Ledgers {
        manifest: None,
        vendor: Some(vendor),
        redirect,
    }
    .hosted_vendored_overlap()
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
pub(super) async fn classify_overlap_takeover(common: &GlobalArgs, root: &Path) -> OverlapTakeover {
    // A malformed vendor ledger classifies like a missing one (this path
    // only feeds takeover warnings; corruption is a hard error on the
    // write/attest paths).
    let vendor = socket_patch_core::vendor::load_state(root).await.ok();
    // Nothing vendored, nothing to overlap: skip the lockfile walk (#993).
    let Some(vendor) = vendor.filter(|v| !v.entries.is_empty()) else {
        return OverlapTakeover::default();
    };
    let discovery = crate::commands::discover_wiring(common, root).await;
    let redirect = crate::commands::hosted_state_from_pins(
        &socket_patch_core::patch::redirect::upstream::HostedPin::all(&discovery),
    );
    classify_overlap_takeover_with(root, Some(&redirect), Some(&vendor), &discovery).await
}

/// [`classify_overlap_takeover`] over already-loaded state (the hosted
/// engine classifies against its post-takeover vendor ledger) and
/// `discovery`, the lockfile discovery of `cwd` as it is now
/// ([`crate::commands::discover_wiring`]). `None` for either state, or an
/// empty vendored ledger, yields no overlap.
///
/// Callers hand in a discovery they already hold and should skip
/// discovering at all when the vendored ledger has no entries: discovery
/// re-walks every lockfile of the project, which is a real share of a
/// hosted scan's time (#993), and a project that never vendored (the
/// hosted common case) has nothing for it to decide.
pub(super) async fn classify_overlap_takeover_with(
    cwd: &Path,
    redirect: Option<&socket_patch_core::patch::redirect::RedirectState>,
    vendor: Option<&VendorState>,
    discovery: &socket_patch_core::vex::discover::Discovery,
) -> OverlapTakeover {
    let mut out = OverlapTakeover::default();
    let Some(vendor) = vendor.filter(|v| !v.entries.is_empty()) else {
        return out;
    };
    let overlap = overlap_from_states(redirect, vendor);
    if overlap.is_empty() {
        return out;
    }
    // Each overlapping vendored entry's uuid + the lockfiles it wired
    // (revert reads the same set).
    let mut vendor_by_purl: std::collections::HashMap<
        PurlKey,
        &socket_patch_core::vendor::VendorEntry,
    > = std::collections::HashMap::new();
    for (key, entry) in &vendor.entries {
        vendor_by_purl.entry(PurlKey::new(key)).or_insert(entry);
        vendor_by_purl
            .entry(PurlKey::new(&entry.base_purl))
            .or_insert(entry);
    }
    // Each hosted pin's patch uuid (embedded in every hosted artifact URL,
    // whatever the host). A non-empty overlap proves `redirect` is `Some`.
    let mut redirect_uuid_by_purl: std::collections::HashMap<PurlKey, &str> =
        std::collections::HashMap::new();
    for (key, record) in redirect.iter().flat_map(|r| &r.records) {
        redirect_uuid_by_purl
            .entry(PurlKey::new(key))
            .or_insert(record.uuid.as_str());
    }
    let mut liveness = LedgerLiveness::new(cwd, discovery, None);
    for purl in overlap {
        let hosted_live = match redirect_uuid_by_purl.get(&PurlKey::new(&purl)) {
            Some(uuid) => liveness.redirect_record(&purl, uuid).await,
            None => discovery.wires_package(&purl, WiringMode::Hosted),
        };
        let vendored_live = match vendor_by_purl.get(&PurlKey::new(&purl)) {
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

/// Top-level `warnings[]` for scan's envelope from `(code, detail)` pairs
/// (see [`unsupported_layout_warnings`]).
fn layout_warnings(refusals: &[(String, String)]) -> Vec<RunWarning> {
    refusals
        .iter()
        .map(|(code, detail)| RunWarning::new(code.as_str(), detail.as_str()))
        .collect()
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

/// Run-level warning: a Gradle-only build that never declares
/// `mavenLocal()` locks (or has patch records for) module(s) that only the
/// Maven local repository holds. The build does not resolve from `~/.m2`,
/// so the scan leaves those copies out (#551).
pub(super) const GRADLE_BUILD_IGNORES_M2: &str = "gradle_build_ignores_m2";

/// Run-level advisory: the Maven local repository stays a scan root of a
/// Gradle build because `mavenLocal()` could not be ruled out (a script or
/// init script that could not be read literally).
pub(super) const GRADLE_MAVEN_LOCAL_UNDETERMINED: &str = "gradle_maven_local_undetermined";

/// Run-level advisory: Gradle takes its user home from the account's passwd
/// entry, which differs from `$HOME`, so its cache is not under
/// `$HOME/.gradle`.
pub(super) const GRADLE_USER_HOME_DIFFERS: &str = "gradle_user_home_differs";

/// What a scan learned about the Gradle side of discovery.
#[derive(Default)]
struct GradleScan {
    /// `(code, detail)` run-level warnings.
    notes: Vec<(String, String)>,
    /// Base purls ([`canonical_base_purl`]) of the packages crawled from a
    /// Gradle cache. Maven coordinates are case-sensitive, so the canonical
    /// spelling is already the identity; these stay strings because the
    /// lock-file GAVs they are checked against are built as strings.
    gradle_purls: HashSet<String>,
    /// Base purls the build's lock files name; `None` when they were not
    /// read (no Gradle build at the cwd, or no Gradle-cached package to
    /// annotate), so no `inLock` is reported.
    locked: Option<HashSet<String>>,
}

/// Whether a run-level warning code is an advisory that needs no action
/// (the Gradle discovery notes), printed as `Note:` for humans.
fn is_info_note(code: &str) -> bool {
    matches!(
        code,
        GRADLE_MAVEN_LOCAL_UNDETERMINED | GRADLE_USER_HOME_DIFFERS
    )
}

/// Print the run-level warnings to stderr: advisories as `Note:` (not
/// under `--silent`), everything else as `Warning:`.
fn print_layout_refusals(refusals: &[(String, String)], silent: bool) {
    for (code, detail) in refusals {
        if is_info_note(code) {
            if !silent {
                eprintln!("Note: {detail}");
            }
        } else {
            eprintln!("Warning: {detail}");
        }
    }
}

/// The Gradle discovery notes and the lock-membership annotation for a
/// scan. `crawled` are the packages this run covers, `scanned` every purl
/// the crawl found, `manifest` the recorded patches. Locks only annotate:
/// they never filter what the scan reports.
async fn gradle_scan(
    common: &GlobalArgs,
    crawled: &[socket_patch_core::crawlers::CrawledPackage],
    scanned: &HashSet<String>,
    manifest: Option<&PatchManifest>,
) -> GradleScan {
    use socket_patch_core::crawlers::gradle_cache;
    use socket_patch_core::crawlers::maven_crawler::{m2_gate, JvmEnv, M2Gate};

    let mut out = GradleScan {
        gradle_purls: crawled
            .iter()
            .filter(|p| gradle_cache::is_gradle_version_dir(&p.path))
            .map(|p| canonical_base_purl(&p.purl))
            .collect(),
        ..GradleScan::default()
    };
    if !common.ecosystem_selected(Ecosystem::Maven) {
        return out;
    }
    let cwd = common.cwd.clone();
    let global = common.is_global();
    // An explicit cache root makes the user home Gradle would pick moot.
    let prefixed = common.global_prefix.is_some();
    let manifest_gavs: Vec<String> = manifest
        .map(|m| {
            m.patches
                .keys()
                .filter(|k| k.starts_with("pkg:maven/"))
                .map(|k| canonical_base_purl(k))
                .collect()
        })
        .unwrap_or_default();
    let want_locks = !out.gradle_purls.is_empty();
    let Ok((gate, locked, mismatch, env)) = tokio::task::spawn_blocking(move || {
        let gradle_build = socket_patch_core::vendor::jvm::layout::has_build(
            &cwd,
            socket_patch_core::vendor::jvm::layout::BuildTool::Gradle,
        );
        let env = JvmEnv::from_process();
        let gate = (!global && gradle_build).then(|| m2_gate(&cwd, &env));
        // The cwd's build locks annotate Gradle-cached packages in a global
        // run too; without a Gradle build at the cwd there is nothing to
        // say, so no annotation at all.
        let locked: Option<HashSet<String>> =
            (gradle_build && (want_locks || gate == Some(M2Gate::Ignored))).then(|| {
                gradle_cache::locked_gavs(&cwd)
                    .into_iter()
                    .map(|(g, a, v)| format!("pkg:maven/{g}/{a}@{v}"))
                    .collect()
            });
        let mismatch = (!prefixed && (global || gradle_build))
            .then(gradle_cache::home_mismatch)
            .flatten();
        (gate, locked, mismatch, env)
    })
    .await
    else {
        return out;
    };

    match gate {
        Some(M2Gate::Undetermined(why)) => out.notes.push((
            GRADLE_MAVEN_LOCAL_UNDETERMINED.to_string(),
            format!(
                "the Maven local repository is scanned for this Gradle build because \
                 mavenLocal() could not be ruled out ({why})"
            ),
        )),
        Some(M2Gate::Ignored) => {
            let mut candidates: Vec<String> = locked
                .iter()
                .flatten()
                .cloned()
                .chain(manifest_gavs)
                .filter(|p| !scanned.contains(p))
                .collect();
            candidates.sort();
            candidates.dedup();
            let m2_repo = env.m2_repo.as_ref().filter(|_| !candidates.is_empty());
            let only_m2: Vec<String> = if let Some(m2_repo) = m2_repo {
                let mut found: Vec<String> = socket_patch_core::crawlers::MavenCrawler
                    .find_by_purls(m2_repo, &candidates)
                    .await
                    .unwrap_or_default()
                    .into_keys()
                    .collect();
                found.sort();
                found
            } else {
                Vec::new()
            };
            if let Some(m2_repo) = m2_repo.filter(|_| !only_m2.is_empty()) {
                const SHOWN: usize = 5;
                let mut list = only_m2[..only_m2.len().min(SHOWN)].join(", ");
                if only_m2.len() > SHOWN {
                    list.push_str(&format!(" and {} more", only_m2.len() - SHOWN));
                }
                out.notes.push((
                    GRADLE_BUILD_IGNORES_M2.to_string(),
                    format!(
                        "this Gradle build declares no mavenLocal(), so it does not resolve \
                         from the Maven local repository ({}); {} found only there {} not \
                         scanned: {list}",
                        m2_repo.display(),
                        plural(only_m2.len(), "module", "modules"),
                        if only_m2.len() == 1 { "is" } else { "are" },
                    ),
                ));
            }
        }
        _ => {}
    }
    if let Some((home, passwd)) = mismatch {
        out.notes.push((
            GRADLE_USER_HOME_DIFFERS.to_string(),
            format!(
                "Gradle's user home follows the account's home directory {} (not $HOME={}); \
                 set GRADLE_USER_HOME to scan another Gradle cache",
                passwd.display(),
                home.display()
            ),
        ));
    }
    out.locked = want_locks.then_some(locked).flatten();
    out
}

/// The scanned purls whose HOSTED redirect wiring is still live: a hosted
/// pin names the purl (`redirect_state`, the lockfiles' hosted state — see
/// [`crate::commands::hosted_state_from_pins`]) AND lockfile discovery
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
    // By release identity: a record keyed `@3.0.2.0` names the scanned
    // composer `@3.0.2`, a `Newtonsoft.Json` record the lowercase NuGet crawl.
    let scanned: std::collections::BTreeSet<PurlKey> = scanned_purls
        .into_iter()
        .map(|p| PurlKey::new(p.as_ref()))
        .collect();
    // Cheap no-I/O gate: skip the lockfile proofs when no record names a
    // scanned purl.
    let candidates: Vec<(String, &str)> = redirect
        .records
        .iter()
        .filter(|(key, _)| scanned.contains(&PurlKey::new(key)))
        .map(|(key, record)| (canonical_purl(key), record.uuid.as_str()))
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

/// Top-level `redirectState` block for the scan `--json` envelope:
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
    let records: Vec<serde_json::Value> = redirect
        .records
        .iter()
        .map(|(key, record)| {
            serde_json::json!({
                "purl": canonical_purl(key),
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

/// Print the scan error envelope for a failure before (or instead of) any
/// discovery: `status: "error"`, empty `events`, zero `summary`, the coded
/// `error`.
fn emit_scan_error(common: &GlobalArgs, error: EnvelopeError) {
    let mut env = scan_envelope(common);
    env.mark_error(error);
    emit_scan(&env);
}

pub async fn run(args: ScanArgs) -> i32 {
    // Scan's telemetry sends run off the critical path: each is spawned
    // where its event fires and flushed before the first stdout write that
    // follows it (so a closed pipe's SIGPIPE or a Ctrl-C still finds it
    // delivered, as with an inline send). The flush here is the
    // backstop that keeps every event ahead of the process exit.
    let mut telemetry = PendingTelemetry::new();
    let code = Box::pin(run_scan(args, &mut telemetry, None, true)).await;
    telemetry.flush().await;
    code
}

/// The project directories a hosted or vendored scan's PATHs name: each
/// PATH is a directory, or a glob matching directories, relative to
/// `--cwd`. Sorted and deduplicated; the flag says whether the user named
/// the directory literally (explicit roots skip the built-in default path
/// ignores; glob matches are discovered roots). `Err` is a usage error:
/// `(code, message)`.
fn project_dirs(
    cwd: &Path,
    paths: &[String],
) -> Result<Vec<(PathBuf, bool)>, (&'static str, String)> {
    let mut dirs: Vec<(PathBuf, bool)> = Vec::new();
    for raw in paths {
        let joined = cwd.join(raw);
        if raw.contains(['*', '?', '[']) {
            let pattern = joined.to_string_lossy().into_owned();
            let matches = glob::glob(&pattern).map_err(|e| {
                (
                    "path_glob_invalid",
                    format!("invalid path pattern `{raw}`: {e}"),
                )
            })?;
            let before = dirs.len();
            dirs.extend(
                matches
                    .filter_map(Result::ok)
                    .filter(|p| p.is_dir())
                    .map(|p| (p, false)),
            );
            if dirs.len() == before {
                return Err((
                    "path_glob_no_match",
                    format!("`{raw}` matches no directory"),
                ));
            }
        } else if joined.is_dir() {
            dirs.push((joined, true));
        } else {
            return Err(("path_not_directory", format!("`{raw}` is not a directory")));
        }
    }
    // A directory both named and matched counts as named.
    dirs.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    dirs.dedup_by(|later, earlier| later.0 == earlier.0);
    Ok(dirs)
}

/// Run a hosted or vendored scan once per project directory its PATHs
/// name, as if each were `--cwd`. The exit code is the worst of the runs.
/// `--json` takes one directory, so stdout stays one document. Every
/// directory must be inside the repository root the policy was read from.
///
/// `mode_inferred`: the mode came from `--cwd`'s state rather than
/// `--mode`, so each directory takes its mode from its own state.
async fn run_project_dirs(
    args: ScanArgs,
    telemetry: &mut PendingTelemetry,
    invocation: &InvocationPolicy,
    mode_inferred: bool,
) -> i32 {
    let usage = |code: &str, message: &str| {
        usage_error(
            JsonCommand::Scan,
            args.common.json,
            args.common.dry_run,
            code,
            message,
        )
    };
    let dirs = match project_dirs(&args.common.cwd, &args.paths) {
        Ok(dirs) => dirs,
        Err((code, message)) => return usage(code, &message),
    };
    if !args.common.is_global() {
        for (dir, _) in &dirs {
            let resolved = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.clone());
            if !resolved.starts_with(&invocation.repo_root) {
                return usage(
                    "path_outside_repo",
                    &format!(
                        "`{}` is outside {} (the repository root socket.yml is read \
                         from; without a trusted .git it is --cwd): run one scan per \
                         repository, or pass --cwd at a common parent",
                        dir.display(),
                        invocation.repo_root.display()
                    ),
                );
            }
        }
    }
    if args.common.json && dirs.len() > 1 {
        return usage(
            "invalid_args",
            &format!(
                "--json takes one project directory ({} given); run one scan per directory",
                dirs.len()
            ),
        );
    }
    // `--vex <path>` names one document: each directory's run would write
    // (or, on a failed generation, remove) the same file, so the last run
    // would silently clobber the others' attestations.
    if args.vex.vex.is_some() && dirs.len() > 1 {
        return usage(
            "invalid_args",
            &format!(
                "--vex takes one project directory ({} given); run one scan per directory",
                dirs.len()
            ),
        );
    }
    // One budget per invocation (§5.2): the directories spend it in sorted
    // order, and a package admitted in one is admitted free in the next.
    let configured = match args
        .rollout
        .resolve_from_env(invocation.policy.max_new_patches())
    {
        Ok(max) => max,
        Err(message) => return usage("invalid_env", &message),
    };
    let root = std::fs::canonicalize(&args.common.cwd).unwrap_or_else(|_| args.common.cwd.clone());
    let carry = rollout_args::RolloutCarry::new(configured, root);
    let mut code = 0;
    for (dir, explicit) in &dirs {
        if dirs.len() > 1 && !args.common.silent {
            let shown = dir.strip_prefix(&args.common.cwd).unwrap_or(dir);
            println!("\n== {} ==", shown.display());
        }
        let mut child = args.clone();
        child.paths.clear();
        child.common.cwd = dir.clone();
        child.rollout.carry = Some(carry.clone());
        if mode_inferred {
            child.mode = None;
        }
        code = code.max(Box::pin(run_scan(child, telemetry, Some(invocation), *explicit)).await);
    }
    code
}

/// Report a usage error `scan` enforces itself (exit 2): the coded error
/// on stdout under `--json`, `Error: ...` on stderr otherwise.
fn scan_usage_error(args: &ScanArgs, code: &str, message: &str) -> i32 {
    usage_error(
        JsonCommand::Scan,
        args.common.json,
        args.common.dry_run,
        code,
        message,
    )
}

/// Print a policy file that cannot be honored (fail closed, exit 1).
fn report_policy_error(err: &socket_patch_core::policy::PolicyError, args: &ScanArgs) -> i32 {
    if args.common.json {
        emit_scan_error(
            &args.common,
            EnvelopeError::new(err.code(), err.to_string()),
        );
    } else {
        eprintln!("Error ({}): {err}", err.code());
    }
    1
}

/// `invocation` is the policy a PATH-list parent already loaded (`None`
/// loads it here); `explicit` says whether the user named this root.
async fn run_scan(
    mut args: ScanArgs,
    telemetry: &mut PendingTelemetry,
    invocation: Option<&InvocationPolicy>,
    explicit: bool,
) -> i32 {
    apply_env_toggles(&args.common);

    // Whether the user chose the mode (`--mode`, or `--sync` = agent).
    // Without it, the mode comes from the project's own state below.
    let mode_explicit = args.mode.is_some() || args.sync;
    // Resolve `--mode`/`--sync` into `args.mode` (see
    // `resolve_mode_flags`). `--sync` with another mode is a usage error
    // (exit 2); under --json it prints the coded error on stdout.
    if let Err(message) = resolve_mode_flags(&mut args) {
        // The global-install refusal is the one with its own code: it is
        // exactly `global_mode_conflict`'s message for the folded mode.
        let global = args
            .mode
            .and_then(|mode| crate::commands::global_mode_conflict(&args.common, mode))
            .is_some_and(|conflict| conflict == message);
        let code = if global {
            "global_scope_unsupported"
        } else if foreign_mode_conflict(&args).is_some_and(|conflict| conflict == message) {
            crate::commands::FOREIGN_MANIFEST_PROJECT
        } else {
            "invalid_args"
        };
        return scan_usage_error(&args, code, &message);
    }
    // A bare scan keeps the mode the project already has (#1088): only an
    // explicit `--mode` converts a vendored or agent-mode project. The
    // hosted default above is the only one this replaces (a `--prune` or
    // global scan with no mode stays report-only).
    let mode_inferred = !mode_explicit && args.mode == Some(ScanMode::Hosted);
    if mode_inferred {
        match crate::commands::mode_from_project_state(&args.common).await {
            Ok(mode) => {
                if !args.common.json && !args.common.silent {
                    if let Some(note) = crate::commands::kept_mode_note(mode) {
                        eprintln!("{note}");
                    }
                }
                args.mode = Some(mode);
            }
            Err(message) => return scan_usage_error(&args, "mode_ambiguous", &message),
        }
    }
    // Hosted and vendored mode refused a foreign manifest above; agent mode
    // (and a report-only scan) still refuses one under `--vex`: it patches
    // `--cwd`'s installed copies, the document attests the manifest's
    // project (#745).
    if let Some(message) =
        crate::commands::foreign_manifest_vex_conflict(&args.common, &args.vex, "scan")
    {
        return scan_usage_error(&args, crate::commands::FOREIGN_MANIFEST_PROJECT, &message);
    }

    // The repo's socket.yml policy, read once per invocation before any
    // write (an invalid file fails the run closed).
    let loaded;
    let invocation = match invocation {
        Some(invocation) => invocation,
        None => match load_invocation_policy(&args) {
            Ok(i) => {
                loaded = i;
                &loaded
            }
            Err(PolicyLoadError::Usage(message)) => {
                return scan_usage_error(&args, "invalid_env", &message);
            }
            Err(PolicyLoadError::Policy(err)) => return report_policy_error(&err, &args),
        },
    };

    // Hosted and vendored modes rewire a project's lockfiles, so their
    // PATHs name project directories: one scan per directory.
    if matches!(args.mode, Some(ScanMode::Hosted) | Some(ScanMode::Vendored))
        && !args.paths.is_empty()
    {
        return Box::pin(run_project_dirs(args, telemetry, invocation, mode_inferred)).await;
    }

    let mut policy = Box::new(ScanPolicy::for_root(
        invocation,
        &args.common.cwd,
        explicit,
        args.common.is_global(),
    ));
    // Agent and report-only scans patch the crawled copies in place, so a
    // copy under a nested project's `node_modules` is judged by that
    // project's root (#554). Hosted and vendored scans only rewire this
    // root's lockfiles.
    if !args.common.is_global()
        && !matches!(args.mode, Some(ScanMode::Hosted) | Some(ScanMode::Vendored))
    {
        policy.judge_nested_roots(invocation, &args.common.cwd);
    }

    // Positional PATH globs (see `ScanArgs::paths`). An unparseable glob
    // is a usage error, same exit-2 shape as the mode conflicts.
    let path_scope = match crate::path_scope::PathScope::parse(&args.paths) {
        Ok(s) => s,
        Err(message) => return scan_usage_error(&args, "path_glob_invalid", &message),
    };

    // The per-run cap on NEW patches (`--max-new-patches` > env > the
    // socket.yml `patches.maxNewPatches`). A malformed env value is a usage
    // error.
    let configured_cap = match args.rollout.carry.as_ref() {
        Some(carry) => carry.lock().configured,
        None => match args
            .rollout
            .resolve_from_env(invocation.policy.max_new_patches())
        {
            Ok(max) => max,
            Err(message) => return scan_usage_error(&args, "invalid_env", &message),
        },
    };
    let mut stage =
        rollout::Stage::new(configured_cap, args.rollout.carry.clone(), &args.common.cwd);

    // Strict airgap (CLI_CONTRACT.md `--offline`): scan's patch discovery
    // is remote data, so refuse before the crawl and before the API client
    // is built (org auto-resolve is itself a network call).
    if args.common.offline {
        let err = "scan requires network access to query the patch API and cannot run with \
                   --offline/SOCKET_OFFLINE (strict airgap)";
        if args.common.json {
            emit_scan_error(&args.common, EnvelopeError::new("offline_unsupported", err));
        } else {
            eprintln!("Error: {err}");
        }
        return 1;
    }

    // `--sync` is sugar for `--mode agent --prune`.
    let apply = args.mode == Some(ScanMode::Agent);
    let vendor = args.mode == Some(ScanMode::Vendored);
    let hosted = args.mode == Some(ScanMode::Hosted);
    // `patches.enabled: false` writes nothing, the GC included.
    let prune = (args.prune || args.sync) && policy.writes_allowed();

    // Hosted mode runs no GC: say so once up front on the human path. The
    // `--json` path carries it in `redirect.warnings[]`.
    if hosted && prune && !args.common.json && !args.common.silent {
        eprintln!("Warning: {REDIRECT_PRUNE_IGNORED_DETAIL}");
    }

    // Resolved up-front (rather than at the GC site) because the embedded
    // `--vex` side-effect reads the manifest at several terminal returns,
    // including the early "no packages" exit before the GC block.
    let manifest_path = args.common.resolved_manifest_path();
    // The stores, lock set and wiring discovery this run reads before it
    // writes anything, each loaded at most once (see `ProjectContext`).
    let ctx = crate::commands::context::ProjectContext::new(&args.common);
    let socket_dir = args.common.socket_dir();

    let overrides = args.common.api_client_overrides();
    let (mut api_client, mut use_public_proxy) =
        get_api_client_with_overrides(overrides.clone()).await;
    // Sized for the endpoint the run starts on. A mid-run downgrade to the
    // proxy keeps these chunk boundaries: every chunk is within the proxy's
    // body cap by construction (`BATCH_BODY_BYTE_CAP`).
    let batch_size = effective_batch_size(args.batch_size, use_public_proxy);
    let telemetry_auth = TelemetryAuth::for_client(&api_client);
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
    // A path-scoped (agent or mode-less) run keeps it to resolve every
    // installed copy for the scope filter below.
    let keep_npm = vendor
        || (hosted && args.vex.vex.is_some() && !args.common.dry_run)
        || !path_scope.is_empty();
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
    let mut lockfile_only = lockfile_supplement(&ctx, &all_crawled, crawl_scope).await;
    // Counted once: #604 adds the API's spellings of lockfile-only PyPI pins
    // to `lockfile_only.purls` after the batch query.
    let lockfile_only_count = lockfile_only.purls.len();
    // Unsupported layouts and malformed binary Bun locks, kept on empty
    // scans too: an unreadable graph is not evidence of no dependencies.
    let mut layout_refusals = unsupported_layout_warnings(&lockfile_only.unsupported);
    // A token whose org could not be resolved put the whole run on the
    // public proxy (the client already warned on stderr): `--json`
    // consumers get it on the same run-level `warnings[]` channel.
    if args.common.json {
        if let Some(reason) = api_client.org_unresolved() {
            layout_refusals.push((
                crate::commands::vex_sources::NOTE_API_AUTH_FALLBACK.to_string(),
                reason.to_string(),
            ));
        }
    }
    // A committed `.bundle/config` whose BUNDLE_PATH resolves outside the
    // project, refused by the crawler's containment guard: surface it on
    // the same run-level channel as the layout refusals.
    if let Some(value) = skipped_bundle_config_path {
        if args.common.ecosystem_selected(Ecosystem::Gem) {
            let (code, detail) = config_path_ignored_warning(&value);
            layout_refusals.push((code.to_string(), detail));
        }
    }
    // A Bundler plugin registration v4's `setup` left in this checkout,
    // pointing at a plugin dir the v5 migration deleted (#1295).
    if args.common.ecosystem_selected(Ecosystem::Gem)
        && !args.common.global
        && args.common.global_prefix.is_none()
    {
        if let Some((code, detail)) = stale_plugin_registration_warning(&args.common.cwd).await {
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
    let vendor_state = &ctx.loaded().await.vendor;
    let ledger_supplement = vendored_ledger_supplement(&ctx, &all_crawled, vendor_state).await;
    for pkg in &ledger_supplement.packages {
        if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
            *eco_counts.entry(eco).or_insert(0) += 1;
        }
        supplement_purls.insert(pkg.purl.clone());
    }
    all_crawled.extend(ledger_supplement.packages);
    // Ledger entries whose dependency left the lock: not discovered (see
    // `vendored_ledger_supplement`). A pruning run reverts them in its GC;
    // every other run says how to.
    let unwired_vendored: Vec<String> = ledger_supplement
        .unwired
        .into_iter()
        .filter(|purl| args.common.purl_ecosystem_selected(purl))
        .collect();
    let prune_reverts_unwired = prune && !hosted;
    if !unwired_vendored.is_empty() && !prune_reverts_unwired {
        layout_refusals.push((
            "vendor_ledger_entry_unwired".to_string(),
            render::unwired_vendored_detail(&unwired_vendored),
        ));
    }

    // Every PURL the crawl found, captured BEFORE the `--ecosystems` /
    // `--package` / PATH filters: prune must judge manifest entries against
    // the full installed set, or `scan --ecosystems npm --prune` would
    // delete every other ecosystem's entries. Lockfile-only purls are
    // included so a wiped node_modules does not prune them.
    let scanned_purls: HashSet<String> = all_crawled.iter().map(|p| p.purl.clone()).collect();

    // Vendor-ledger purl keys, shared by the prune exemption (a vendored
    // package's normal state is absent from the crawl) and the
    // vendored-skip in the apply path. A corrupt ledger yields the empty set.
    let vendored_purls: HashSet<PurlKey> = vendor_state
        .as_ref()
        .map(VendorState::purl_keys)
        .unwrap_or_default();
    // The ledger owns and records the PROJECT's copies only: a global
    // scan's agent leg patches the global copy even when the cwd project
    // vendors the same purl (see `project_state_in_scope`).
    let project_state = crate::commands::project_state_in_scope(&args.common);
    let vendor_owned_purls: HashSet<PurlKey> = if project_state {
        vendored_purls.clone()
    } else {
        HashSet::new()
    };

    // Read existing manifest once for update detection.
    let existing_manifest = ctx.ledgers().await.manifest;
    // A manifest that exists but cannot be loaded (rule shared by every
    // command: `manifest_invalid` / `manifest_unreadable`). Agent mode
    // reads and rewrites it (its dry run previews against it), so it fails
    // closed before any query, in both outputs; every other mode only
    // reads it for update detection and the GC, so it warns and goes on
    // without it (never silently as "no manifest").
    if let Err(e) = &ctx.loaded().await.manifest {
        let err = crate::json_envelope::manifest_load_error(&manifest_path, e);
        if apply {
            status.finish();
            if args.common.json {
                emit_scan_error(&args.common, err);
            } else {
                eprintln!("Error: {}", err.message);
            }
            return 1;
        }
        layout_refusals.push((err.code, err.message));
    }
    // Hosted mode records its patches ONLY in the lockfiles (v5 keeps no
    // hosted ledger) and vendored mode ONLY in its ledger, so the hosted
    // pins and the vendor ledger's purl→uuid records are folded into update
    // detection (otherwise their `updates[]` would stay empty). The same
    // merged view is the policy's recorded state (the retained set).
    let hosted_pin_list: Vec<socket_patch_core::patch::redirect::upstream::HostedPin> =
        if args.common.is_global() {
            Vec::new()
        } else {
            socket_patch_core::patch::redirect::upstream::HostedPin::all(ctx.discovery().await)
        };
    // Lockless cargo/nuget pins are never refs, so `HostedPin::all` drops
    // them; the rollout's recorded view still counts them (otherwise a
    // re-scan reads the pin it wrote as NEW and spends a cap slot).
    let hosted_unlocked_pins = if args.common.is_global() {
        Vec::new()
    } else {
        ctx.discovery().await.unlocked_pins.clone()
    };
    // The same discovery, handed to the hosted redirect's attribution gate
    // (nothing below writes before it; see `rollout::Gate::prior`).
    let prior_discovery = if args.common.is_global() {
        None
    } else {
        let (discovery, read_set) = ctx.recorded_discovery().await;
        Some(rollout::Prior {
            discovery,
            read_set: read_set.as_ref(),
        })
    };
    let hosted_state = (!args.common.is_global())
        .then(|| crate::commands::hosted_state_from_pins(&hosted_pin_list));
    let redirect_state = hosted_state.as_ref();
    // The recorded view also counts the pins discovery withheld over an
    // unpatched copy beside them (`HostedPin::recorded`): still this
    // project's patch, so a capped re-scan reads ALREADY and rewires the
    // copy instead of deferring it as NEW (#1195).
    let mut hosted_pins: Vec<(String, String)> = if args.common.is_global() {
        Vec::new()
    } else {
        socket_patch_core::patch::redirect::upstream::HostedPin::recorded(ctx.discovery().await)
            .into_iter()
            .map(|pin| (pin.purl, pin.uuid))
            .collect()
    };
    // A gem pinned only in the Gemfile (a CHECKSUMS-less lock the hosted
    // rewriter leaves for the next unfrozen `bundle install`) has no lock
    // ref yet; it is recorded all the same, or a capped re-scan reads the
    // pin it wrote as NEW forever (#1224).
    if !args.common.is_global() {
        let view = socket_patch_core::vendor::lock_inventory::ProjectView::Disk(&args.common.cwd);
        for pin in socket_patch_core::vex::discover::gem_manifest_source_pins(&view).await {
            if !hosted_pins.contains(&pin) {
                hosted_pins.push(pin);
            }
        }
    }
    let update_manifest = merge_ledger_records_for_updates(
        existing_manifest,
        vendor_state.as_ref().ok().filter(|_| project_state),
        &hosted_pins,
    );
    policy.set_recorded(update_manifest.as_deref());

    // Filter by --ecosystems if provided
    let filtered_crawled: Vec<_> = all_crawled
        .into_iter()
        .filter(|pkg| args.common.purl_ecosystem_selected(&pkg.purl))
        .collect();

    let package_specs: Vec<&String> = args
        .packages
        .iter()
        .filter(|s| !s.trim().is_empty())
        .collect();
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
    // path. The crawl keeps one record per purl (for npm, the first copy
    // the walk meets: a pnpm workspace's root `.pnpm` store entry, not the
    // member's link to it), so a purl whose record misses is resolved to
    // every installed copy the way `rollback`'s path targets are.
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
        let mut in_scope: HashSet<String> = filtered_crawled
            .iter()
            .filter(|pkg| !supplement_purls.contains(&pkg.purl))
            .filter(|pkg| scope.matches(&pkg.path))
            .map(|pkg| pkg.purl.clone())
            .collect();
        let mut unresolved: Vec<String> = filtered_crawled
            .iter()
            .filter(|pkg| !supplement_purls.contains(&pkg.purl) && !in_scope.contains(&pkg.purl))
            .map(|pkg| pkg.purl.clone())
            .collect();
        unresolved.sort();
        unresolved.dedup();
        if !unresolved.is_empty() {
            let partitioned = partition_purls(&unresolved, args.common.ecosystems.as_deref());
            let copies = find_all_packages_for_rollback_reusing(
                &partitioned,
                &crawler_options,
                true,
                npm_crawl.as_ref(),
            )
            .await;
            in_scope.extend(
                copies
                    .into_iter()
                    .filter(|(_, paths)| paths.iter().any(|p| scope.matches(p)))
                    .map(|(purl, _)| purl),
            );
        }
        filtered_crawled
            .into_iter()
            .filter(|pkg| in_scope.contains(&pkg.purl))
            .collect()
    };

    // The socket.yml root/ecosystem/package filters, after the flags
    // (which only narrow further) and after the prune-universe capture.
    if policy.judges_nested_roots() && args.common.ecosystem_selected(Ecosystem::Npm) {
        let nm_roots = socket_patch_core::crawlers::NpmCrawler::new()
            .get_node_modules_paths(&crawler_options)
            .await
            .unwrap_or_default();
        policy
            .locate_nested_copies(&nm_roots, &filtered_crawled)
            .await;
    }
    let filtered_crawled = policy.admit_crawled_copies(filtered_crawled, &supplement_purls);

    // Gradle discovery notes (m2 gating, the user home) ride the run-level
    // warnings; the lock set only annotates `packages[]` below.
    let gradle = gradle_scan(
        &args.common,
        &filtered_crawled,
        &scanned_purls,
        update_manifest.as_deref(),
    )
    .await;
    layout_refusals.extend(gradle.notes.iter().cloned());

    let all_purls: Vec<String> = filtered_crawled.iter().map(|p| p.purl.clone()).collect();
    let package_count = all_purls.len();

    if package_count == 0 {
        status.finish();
        if human {
            print_layout_refusals(&layout_refusals, args.common.silent);
            policy.print_warnings(args.common.silent);
            // Hosted mode already printed its own prune-ignored warning.
            if prune && !hosted && unwired_vendored.is_empty() {
                eprintln!("{}", render::PRUNE_SKIPPED_EMPTY);
            }
        }
        // The manifest half of the GC is skipped on an empty crawl, but
        // reverting vendored entries the lock no longer wires asks the
        // lockfile, not the crawl: run that half alone, or a project whose
        // last vendored dependency was removed could never reconcile.
        let unwired_gc = if prune_reverts_unwired && !unwired_vendored.is_empty() {
            Some(gc::run_vendor_only_gc(&args.common, &manifest_path, &socket_dir).await)
        } else {
            None
        };
        if human {
            if let Some(gc) = &unwired_gc {
                gc::print_human_gc(gc, args.common.dry_run);
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
            &telemetry_auth,
        );
        // The result prints right away: nothing to overlap the send with.
        telemetry.flush().await;
        if args.common.json {
            // GC is intentionally skipped when the crawl finds nothing:
            // pruning every manifest entry is too destructive (`repair`
            // does full cleanup explicitly).
            let mut env = scan_envelope(&args.common);
            env.set_extra("scannedPackages", serde_json::json!(0));
            env.set_extra("lockfileOnlyPackages", serde_json::json!(0));
            env.set_extra("canAccessPaidPatches", serde_json::json!(false));
            env.set_extra("packages", serde_json::json!([]));
            env.set_extra("updates", serde_json::json!([]));
            env.set_extra("paths", serde_json::json!(path_scope.raw()));
            env.set_extra("rollout", stage.json());
            // Layout refusals ride `warnings` so a consumer can tell an
            // unscannable project from an empty one.
            env.warnings.extend(layout_warnings(&layout_refusals));
            if let Some(gc) = &unwired_gc {
                gc.record_into(&mut env, args.common.dry_run);
            }
            policy.fold_into_envelope(&mut env);
            // Hosted mode: the same `redirect` block as the ≥1-package
            // path (nothing rewritten).
            if hosted {
                if prune {
                    env.warnings.push(hosted::prune_ignored_warning());
                }
                env.set_extra("redirect", hosted::redirect_block(Vec::new()));
            } else if !vendor {
                // `redirectState` rides the empty-discovery envelope too
                // (same rule as the ≥1-package path). `wiringLive` is empty
                // by construction: this run covered zero packages.
                let redirect_state =
                    (!args.common.is_global()).then_some(crate::commands::hosted_state_from_pins(
                        &socket_patch_core::patch::redirect::upstream::HostedPin::all(
                            ctx.discovery().await,
                        ),
                    ));
                if let Some(state) = redirect_state_json(redirect_state.as_ref(), &[]) {
                    env.set_extra("redirectState", state);
                }
            }
            let code = embed_vex_into_json(
                &args.common,
                &args.vex,
                &api_client,
                &manifest_path,
                0,
                &mut env,
                hosted,
            )
            .await;
            emit_scan(&env);
            return code;
        } else if !args.common.silent {
            // A project the policy skipped as a whole is not an empty one.
            if !policy.root_excluded() {
                println!(
                    "{}",
                    render::no_packages_message(
                        args.common.is_global(),
                        args.common.ecosystems.as_deref(),
                        &args.paths,
                    )
                );
            }
            policy.print_human(args.common.silent, args.common.verbose);
        }
        return embed_vex_human(
            &args.common,
            &args.vex,
            &api_client,
            &manifest_path,
            0,
            hosted,
        )
        .await;
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
        if lockfile_only_count > 0 {
            eprintln!("{}", render::lockfile_only_note(lockfile_only_count));
        }
        print_layout_refusals(&layout_refusals, args.common.silent);
        policy.print_warnings(args.common.silent);
    }

    // Query API in batches
    let mut all_packages_with_patches: Vec<BatchPackagePatches> = Vec::new();
    let mut can_access_paid_patches = false;
    // #604: a lockfile-only PyPI pin is spelled as the user wrote it
    // (`six==1.16` → `@1.16`) while the API keys the release as the
    // registry published it (`@1.16.0`); pip treats both as one release
    // (PEP 440). Ask for its equivalent spellings too.
    let query_purls = with_pypi_equivalents(&all_purls, &lockfile_only.purls);
    let chunks: Vec<&[String]> = batch_chunks(&query_purls, batch_size, BATCH_BODY_BYTE_CAP);
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
    // #604: a patch the API returned under an equivalent spelling of a
    // lockfile-only PyPI pin is that lockfile-only package.
    adopt_pypi_equivalents(
        &all_packages_with_patches,
        &all_purls,
        &mut lockfile_only.purls,
    );

    // If every batch errored, surface a full scan failure rather than
    // silently reporting zero patches.
    if total_batches > 0 && batch_error_count == total_batches {
        status.finish();
        let err = last_batch_error.unwrap_or_else(|| "all batches failed".to_string());
        spawn_patch_scan_failed(telemetry, &err, fallback_to_proxy, &telemetry_auth);
        // The failure prints right away: nothing to overlap the send with.
        telemetry.flush().await;
        if args.common.json {
            let mut env = scan_envelope(&args.common);
            env.set_extra("scannedPackages", serde_json::json!(package_count));
            env.set_extra(
                "lockfileOnlyPackages",
                serde_json::json!(lockfile_only_count),
            );
            env.set_extra("paths", serde_json::json!(path_scope.raw()));
            env.mark_error(EnvelopeError::new(API_BATCH_FAILED, err));
            emit_scan(&env);
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
        &telemetry_auth,
    );

    let mut updates = detect_updates(update_manifest.as_deref(), &all_packages_with_patches);
    policy.set_update_purls(updates.iter().map(|u| u.purl.as_str()));
    let recorded = rollout::RecordedState {
        manifest: update_manifest.as_deref(),
        index: rollout::RecordedIndex::new(update_manifest.as_deref(), &hosted_pins)
            .with_unlocked_pins(hosted_unlocked_pins),
    };

    // The hosted-wiring probes below take `all_purls` (POST-filter: only
    // packages this run covered), unlike the PRE-filter `scanned_purls`
    // the GC prune uses.

    // Count downloadable patches: a free-tier org whose every offer is
    // paid-tier has nothing any mode could select. Shared by both outputs.
    let downloadable_count = if can_access_paid_patches {
        all_packages_with_patches.len()
    } else {
        all_packages_with_patches
            .iter()
            .filter(|pkg| pkg.patches.iter().any(|p| p.tier == "free"))
            .count()
    };
    // Whether this run fetches the by-package detail records — ONE decision
    // both outputs read (#1062): every mode that selects needs them, and so
    // does report-only whenever a patch is downloadable (its listing and
    // `updates[]` come from the same records the other modes act on). Only
    // `discover_selected`'s own `Err` (every query failed) fails the run;
    // queries that succeed with no records leave nothing to select.
    let fetch_details = downloadable_count > 0;

    if args.common.json {
        let mut env = scan_envelope(&args.common);
        env.set_extra("scannedPackages", serde_json::json!(package_count));
        env.set_extra(
            "lockfileOnlyPackages",
            serde_json::json!(lockfile_only_count),
        );
        env.set_extra(
            "canAccessPaidPatches",
            serde_json::json!(can_access_paid_patches),
        );
        // Flag lockfile-only packages (absent means installed), with the
        // same predicate as the `[NOT INSTALLED]` marker, and Gradle-cached
        // packages with whether the build's lock files name them (an
        // annotation, never a filter).
        let mut packages =
            serde_json::to_value(&all_packages_with_patches).expect("batch packages serialize");
        if let Some(packages) = packages.as_array_mut() {
            for pkg in packages {
                let is_lockfile_only = pkg["purl"]
                    .as_str()
                    .is_some_and(|p| lockfile_only_contains(&lockfile_only.purls, p));
                if is_lockfile_only {
                    pkg["notInstalled"] = serde_json::json!(true);
                }
                if let Some(base) = pkg["purl"]
                    .as_str()
                    .map(canonical_base_purl)
                    .filter(|base| gradle.gradle_purls.contains(base))
                {
                    if let Some(locked) = &gradle.locked {
                        pkg["inLock"] = serde_json::json!(locked.contains(&base));
                    }
                }
            }
        }
        env.set_extra("packages", packages);
        env.set_extra("paths", serde_json::json!(path_scope.raw()));
        env.set_extra("updates", serde_json::Value::Array(updates_json(&updates)));
        env.set_extra("rollout", stage.json());
        env.warnings.extend(layout_warnings(&layout_refusals));
        // One warning per failed batch (status and exit unchanged).
        for (batch, err) in &failed_batches {
            let line = render::batch_failed_warning(*batch, total_batches, err);
            let detail = line.strip_prefix("Warning: ").unwrap_or(&line);
            env.warn(API_BATCH_FAILED, detail);
        }
        policy.fold_into_envelope(&mut env);

        // Hosted mode: the redirect engine records its events into this
        // envelope and prints it.
        if hosted {
            return run_redirect(
                &args,
                &api_client,
                &all_packages_with_patches,
                can_access_paid_patches,
                &policy,
                Some(env),
                telemetry,
                npm_crawl.as_ref(),
                &recorded,
                batch_error_count > 0,
                &mut stage,
                prior_discovery,
                prune,
            )
            .await;
        }

        // `redirectState` rides every report-only and agent `--json`
        // envelope. Hosted and vendored runs are excluded: both may rewrite
        // the lockfiles mid-run, so a pre-run snapshot would go stale. The
        // live-wiring probe runs ONCE here and is shared with the agent-flow
        // warning below.
        let hosted_retained = if vendor {
            Vec::new()
        } else {
            hosted_wiring_retained_purls(&args.common, redirect_state, &all_purls).await
        };
        if !vendor {
            if let Some(state) = redirect_state_json(redirect_state, &hosted_retained) {
                env.set_extra("redirectState", state);
            }
        }

        let dry = args.common.dry_run;
        let mut apply_code = 0i32;

        // Report-only: select nothing, but fetch the details exactly when
        // the human arm does (`fetch_details`), so a total detail failure
        // fails both outputs alike and `updates[]` comes from the same
        // records; a severity floor or `enabled: false` still reports the
        // candidates it hides.
        if !apply && !vendor && fetch_details {
            match discover_selected(
                &api_client,
                &all_packages_with_patches,
                can_access_paid_patches,
                &policy,
                false,
                false,
                false,
                telemetry,
                Some(&mut env),
            )
            .await
            {
                Ok(discovered) => {
                    classified_rows(
                        &mut stage,
                        &discovered,
                        &recorded,
                        batch_error_count > 0,
                        &all_packages_with_patches,
                        Some(&mut env),
                    );
                }
                Err((code, message)) => {
                    emit_discovery_error_json(&mut env, &message);
                    return code;
                }
            }
        }

        // --- Apply path (if requested) -----------------------------------
        if apply {
            let discovered = match discover_selected(
                &api_client,
                &all_packages_with_patches,
                can_access_paid_patches,
                &policy,
                false,
                false,
                false,
                telemetry,
                Some(&mut env),
            )
            .await
            {
                Ok(d) => d,
                Err((code, message)) => {
                    emit_discovery_error_json(&mut env, &message);
                    return code;
                }
            };
            let rows = classified_rows(
                &mut stage,
                &discovered,
                &recorded,
                batch_error_count > 0,
                &all_packages_with_patches,
                Some(&mut env),
            );

            // Vendor-owned and lockfile-only purls leave the selection as
            // skips BEFORE download (see `partition_agent_selection`); they
            // cannot land, so they hold no rollout slot either.
            let AgentSelection {
                kept,
                skip_records: vendored_records,
                vendored_purls: vendored_skip_purls,
                ..
            } = partition_agent_selection(writers_of(&rows), &vendor_owned_purls, &lockfile_only);
            let selected = plan_kept_rows(&mut stage, rows, kept);
            for event in vendored_records {
                env.record(event);
            }

            if dry {
                // Preview each patch without touching disk: `verified` for
                // what a wet run would record (`oldUuid` on a replacement),
                // `skipped` / `already_in_manifest` for the rest.
                let empty_manifest = PatchManifest::new();
                let manifest_for_preview = existing_manifest.unwrap_or(&empty_manifest);
                for p in &selected {
                    let event = match crate::commands::agent_download::decide_patch_action(
                        manifest_for_preview,
                        &p.purl,
                        &p.uuid,
                    ) {
                        crate::commands::agent_download::PatchAction::Added => {
                            PatchEvent::new(PatchAction::Verified, p.purl.as_str())
                        }
                        crate::commands::agent_download::PatchAction::Updated { old_uuid } => {
                            PatchEvent::new(PatchAction::Verified, p.purl.as_str())
                                .with_old_uuid(old_uuid)
                        }
                        crate::commands::agent_download::PatchAction::Skipped => {
                            PatchEvent::new(PatchAction::Skipped, p.purl.as_str())
                                .with_reason(ALREADY_IN_MANIFEST, "already in manifest")
                        }
                    };
                    env.record(event.with_uuid(p.uuid.as_str()));
                }
            } else if !selected.is_empty() {
                let params = download_params(
                    &args, /*save_only=*/ false, /*json=*/ true, /*silent=*/ true,
                );
                // The engine records into `env` and never prints: one JSON
                // document per run, a hard engine error included.
                apply_code = download_and_apply_patches_into(
                    &selected,
                    &params,
                    &download_run(&args, &api_client),
                    &mut env,
                )
                .await;
                if env.error.is_some() {
                    env.extra.remove("rollout");
                    emit_scan(&env);
                    return apply_code;
                }
            }

            // Cross-mode visibility: run-level warnings, never a status or
            // exit-code change.
            if !vendored_skip_purls.is_empty() {
                let detail = vendored_ownership_retained_detail(&vendored_skip_purls);
                if !args.common.silent {
                    eprintln!("Warning: {detail}");
                }
                env.warn(VENDORED_OWNERSHIP_RETAINED, detail);
            }
            if !hosted_retained.is_empty() {
                let detail = hosted_wiring_retained_detail(&hosted_retained);
                if !args.common.silent {
                    eprintln!("Warning: {detail}");
                }
                env.warn(HOSTED_WIRING_RETAINED, detail);
            }
        // --- Vendor path (if requested; --sync selects agent instead) ---
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
                &recorded,
                batch_error_count > 0,
                &mut stage,
                &policy,
                &mut env,
                &manifest_path,
                &socket_dir,
                &scanned_purls,
                &vendored_purls,
                prune,
                &telemetry_auth,
                telemetry,
                npm_crawl.as_ref(),
            )
            .await;
        }

        // The GC and the VEX build below can write to stderr; the report-
        // only arm may not have flushed the scan event yet.
        telemetry.flush().await;

        // --- GC (post-apply, or standalone --prune GC-sweep) -------------
        if prune {
            gc_into(
                &args.common,
                &manifest_path,
                &socket_dir,
                &scanned_purls,
                &vendored_purls,
                dry,
                &mut env,
            )
            .await;
        }

        finish_rollout_json(&stage, &mut env);
        let final_code = embed_vex_into_json(
            &args.common,
            &args.vex,
            &api_client,
            &manifest_path,
            apply_code,
            &mut env,
            hosted,
        )
        .await;
        emit_scan(&env);
        return final_code;
    }

    // Every human exit below prints first; the scan event goes out before.
    telemetry.flush().await;

    let use_color = ui::stdout_color();
    let verbose = args.common.verbose;
    let silent = args.common.silent;

    // Every human-path exit that did not fail: the `--prune` GC first
    // (not hosted, which runs none), then the embedded VEX. An early
    // "nothing to apply" exit still runs the GC, vendored mode included:
    // its wet vendor step runs its own GC and never reaches this closure,
    // but the early exits (nothing patched, paid-only, nothing selected,
    // `--dry-run`) reconcile and preview like the JSON arm (#1127, #1062).
    let (args_ref, manifest_ref, socket_ref) = (&args, &manifest_path, &socket_dir);
    let client_ref: &ApiClient = &api_client;
    let (scanned_ref, vendored_ref) = (&scanned_purls, &vendored_purls);
    let policy_ref: &ScanPolicy = &policy;
    let finish_human = move |code: i32| async move {
        policy_ref.print_human(silent, verbose);
        if prune && !hosted && code == 0 {
            gc::run_human_gc(
                &args_ref.common,
                manifest_ref,
                socket_ref,
                scanned_ref,
                vendored_ref,
            )
            .await;
        }
        embed_vex_human(
            &args_ref.common,
            &args_ref.vex,
            client_ref,
            manifest_ref,
            code,
            hosted,
        )
        .await
    };

    // Every mode stops on an empty discovery, vendored included (restoring
    // a wiped `.socket/vendor/` is `repair`'s job).
    if all_packages_with_patches.is_empty() {
        if !silent {
            println!("\nNo patches available for installed packages.");
        }
        return finish_human(0).await;
    }

    // `downloadable_count` (above): a free-tier org whose every offer is
    // paid-tier has nothing any mode could select, so every human arm stops
    // below the table with the same paid-subscription line.

    // The by-package records every arm selects from, fetched before the
    // table so its `[UPDATE]` markers are the same UPGRADE rows the
    // selection acts on (§5.1). Only `discover_selected`'s own `Err`
    // (every query failed) is a fetch failure: queries that succeed with
    // no records leave nothing to select, in every arm and in `--json`
    // alike (#1062). A failed discovery still prints the table first; its
    // exit code is returned below it.
    let mut discovery_failure: Option<i32> = None;
    let rows: Vec<rollout::Row> = if !fetch_details {
        Vec::new()
    } else {
        match discover_selected(
            &api_client,
            &all_packages_with_patches,
            can_access_paid_patches,
            &policy,
            human,
            !silent,
            !hosted,
            telemetry,
            None,
        )
        .await
        {
            Ok(discovered) => {
                let rows = classified_rows(
                    &mut stage,
                    &discovered,
                    &recorded,
                    batch_error_count > 0,
                    &all_packages_with_patches,
                    None,
                );
                updates = offer_updates(&rows, &discovered, &recorded, &all_packages_with_patches);
                rows
            }
            // `discover_selected` already printed the failure to stderr.
            Err((code, _)) => {
                discovery_failure = Some(code);
                Vec::new()
            }
        }
    };

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

    if downloadable_count == 0 {
        if !silent {
            println!("\nNo downloadable patches: every patch found requires a paid Socket plan.");
        }
        return finish_human(0).await;
    }
    if let Some(code) = discovery_failure {
        return code;
    }
    policy.print_human(silent, verbose);

    // Hosted mode is a self-contained flow: it reuses the discovery, table
    // and update detection above, then hands the selection to the redirect
    // engine (the same entry as `get --mode hosted`) — it must NOT fall
    // through to the apply/vendor branches.
    if hosted {
        let pairs: Vec<(String, String)> = rows
            .iter()
            .map(|r| (r.writer.purl.clone(), r.writer.uuid.clone()))
            .collect();
        return boxed_run_redirect_selected(
            &args.common,
            &args.vex,
            prune,
            &api_client,
            &pairs,
            None,
            npm_crawl.as_ref(),
            Some(rollout::Gate::new(&mut stage, rows).with_prior(prior_discovery)),
        )
        .await;
    }

    // A scan left without a mode (`--prune` or global; see
    // `resolve_mode_flags`) only reports, plus the `--prune` GC.
    let report_only = args.mode.is_none();
    let selected: Vec<PatchSearchResult> = writers_of(&rows);

    // The skip / already-recorded lines below open their own paragraph
    // under the table's Summary: one blank line before the first of them.
    let mut skip_paragraph = false;

    // Agent flow (mirrors the JSON arm): vendor-owned and lockfile-only
    // purls leave the selection as skips. Vendored mode partitions nothing.
    let selected = if vendor {
        selected
    } else {
        let split = partition_agent_selection(selected, &vendor_owned_purls, &lockfile_only);
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

    // The rollout plan (§5.2): deferred NEW rows leave the selection here.
    // Vendored eligibility is the wet run's Bun / vlt / npm-lock / gem
    // takeover preflight; the agent partition above already removed what
    // cannot land in place.
    let selected = if report_only {
        selected
    } else if vendor {
        let refused = vendor_flow::preflight_refused_purls(&args.common, &selected).await;
        stage.plan(&rows, |r| !refused.contains(&r.writer.purl));
        let deferred = stage.deferred_keys();
        selected
            .into_iter()
            .filter(|p| !deferred.contains(&(p.purl.clone(), p.uuid.clone())))
            .collect()
    } else {
        plan_kept_rows(&mut stage, rows, selected)
    };

    // Set aside selections the manifest already records at the same uuid.
    // A wet agent run still hands them to the download step below, whose
    // nested apply re-applies them after a reinstall (#454, #732); a
    // preview only names them. Agent mode only: vendored mode never reads
    // the manifest.
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
    let reapply = !report_only && !args.common.dry_run;
    if !silent {
        for p in &already_recorded {
            open_paragraph(&mut skip_paragraph);
            println!(
                "{}",
                render::already_recorded_line(&normalize_purl(&p.purl), &p.uuid, reapply)
            );
        }
    }

    if selected.is_empty() && (!reapply || already_recorded.is_empty()) {
        if !silent {
            open_paragraph(&mut skip_paragraph);
            if !stage.deferred_keys().is_empty() {
                if args.common.dry_run {
                    println!("No new patches would be added this run.");
                } else {
                    println!("No new patches added this run.");
                }
            } else if already_recorded.is_empty() {
                println!("No patches selected.");
            } else if args.common.dry_run && !report_only {
                println!("{}", render::ALL_ALREADY_RECORDED_DRY_RUN);
            } else {
                println!("{}", render::ALL_ALREADY_RECORDED);
            }
        }
        print_rollout_human(&stage, args.common.dry_run, silent);
        return finish_human(0).await;
    }

    // Display detailed summary of selected patches (skipped under --silent).
    if !silent && !selected.is_empty() {
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
                let takeover = crate::commands::vendor::gem_takeover_preview_refusals(
                    &args.common,
                    selected.iter().map(|p| p.purl.as_str()),
                )
                .await;
                Some(
                    preview_vendor(
                        &args.common.cwd,
                        &selected,
                        &crate::commands::hosted_unwind::patch_server_origins(&args.common),
                        &takeover,
                    )
                    .await,
                )
            } else {
                None
            };
            let refused = preview.as_ref().map_or(0, |p| p.refused_count());
            println!("{}", render::dry_run_line(plan, refused));
            if let Some(preview) = &preview {
                preview.print_refusals();
            }
        }
        print_rollout_human(&stage, true, silent);
        return finish_human(0).await;
    }

    if report_only {
        // The "Patches to apply:" listing already ends with a blank line.
        if !silent {
            for line in render::report_only_hint(&args.common) {
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
        return embed_vex_human(
            &args.common,
            &args.vex,
            &api_client,
            &manifest_path,
            0,
            hosted,
        )
        .await;
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
            &telemetry_auth,
            npm_crawl.as_ref(),
        )
        .await
    } else {
        // The recorded selections ride along: the fetch loop skips their
        // record and the nested apply re-applies them (a no-op on disk
        // when the installed copy is still patched).
        let to_download: Vec<_> = selected.iter().chain(&already_recorded).cloned().collect();
        let (code, _) = download_and_apply_patches_with(
            &to_download,
            &params,
            &download_run(&args, &api_client),
        )
        .await;
        code
    };

    // Cross-mode visibility, mirroring the JSON apply path: warn when the
    // hosted redirect wiring is still live for scanned package(s). (The
    // vendored-ownership counterpart is the `[skip]` lines above.)
    if !vendor && !silent {
        let hosted_retained =
            hosted_wiring_retained_purls(&args.common, redirect_state, &all_purls).await;
        if !hosted_retained.is_empty() {
            eprintln!(
                "Warning: {}",
                hosted_wiring_retained_detail(&hosted_retained)
            );
        }
    }

    // The deferred next steps assume a run that landed.
    print_rollout_human(&stage, false, silent || code != 0);

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

    embed_vex_human(
        &args.common,
        &args.vex,
        &api_client,
        &manifest_path,
        code,
        hosted,
    )
    .await
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
        let rel = |dirs: Vec<(PathBuf, bool)>| -> Vec<(String, bool)> {
            dirs.iter()
                .map(|(d, explicit)| {
                    (
                        d.strip_prefix(tmp.path())
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                        *explicit,
                    )
                })
                .collect()
        };
        let got = project_dirs(
            tmp.path(),
            &["apps/*".into(), "libs/core".into(), "apps/web".into()],
        )
        .unwrap();
        // Named literally = explicit (also when a glob matches it too).
        assert_eq!(
            rel(got),
            [
                ("apps/api".to_string(), false),
                ("apps/web".to_string(), true),
                ("libs/core".to_string(), true)
            ]
        );
        let err = project_dirs(tmp.path(), &["apps/README".into()]).unwrap_err();
        assert_eq!(err.0, "path_not_directory");
        assert!(err.1.contains("is not a directory"));
        let err = project_dirs(tmp.path(), &["nope/*".into()]).unwrap_err();
        assert_eq!(err.0, "path_glob_no_match");
        assert!(err.1.contains("matches no directory"));
        let err = project_dirs(tmp.path(), &["x[".into()]).unwrap_err();
        assert_eq!(err.0, "path_glob_invalid");
        assert!(err.1.contains("invalid path pattern"));
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

    /// A composer package vendored under the padded `@3.0.2.0` spelling is
    /// still vendor-owned when a later scan's batch echoes `@3.0.2`: it is
    /// skipped as vendored, never applied in place.
    #[test]
    fn agent_selection_partitions_composer_vendored_by_release_identity() {
        let result = |purl: &str| PatchSearchResult {
            uuid: TAKEOVER_UUID.to_string(),
            purl: purl.to_string(),
            published_at: String::new(),
            description: String::new(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
            vulnerabilities: HashMap::new(),
        };
        let mut state = VendorState::new();
        let entry: socket_patch_core::vendor::VendorEntry = serde_json::from_value(
            serde_json::json!({
                "ecosystem": "composer",
                "basePurl": "pkg:composer/psr/log@3.0.2.0",
                "uuid": TAKEOVER_UUID,
                "artifact": {"path": format!(".socket/vendor/composer/{TAKEOVER_UUID}/psr/log@3.0.2.0"), "sha256": ""},
                "wiring": [],
            }),
        )
        .unwrap();
        state
            .entries
            .insert("pkg:composer/psr/log@3.0.2.0".to_string(), entry);
        let split = partition_agent_selection(
            vec![
                result("pkg:composer/psr/log@3.0.2"),
                result("pkg:composer/psr/log@3.0.3"),
            ],
            &state.purl_keys(),
            &LockfileSupplement::default(),
        );
        assert_eq!(split.vendored_purls, vec!["pkg:composer/psr/log@3.0.2"]);
        assert_eq!(
            split
                .kept
                .iter()
                .map(|p| p.purl.as_str())
                .collect::<Vec<_>>(),
            vec!["pkg:composer/psr/log@3.0.3"]
        );
    }

    /// A hosted record keyed by the padded `@3.0.2.0` spelling still names
    /// the scanned composer `@3.0.2` whose live lock the patch server wires.
    #[tokio::test]
    async fn hosted_retained_probe_matches_composer_by_release_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let padded = "pkg:composer/psr/log@3.0.2.0";
        let lock = serde_json::json!({
            "packages": [{
                "name": "psr/log",
                "version": "3.0.2",
                "dist": {
                    "type": "zip",
                    "url": format!("https://patch.socket.dev/patch/composer/psr/log/3.0.2/11111111-1111-1111-1111-111111111111/{TAKEOVER_UUID}/log-3.0.2.zip"),
                    "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                    "shasum": "0123456789abcdef0123456789abcdef01234567"
                }
            }],
            "packages-dev": []
        });
        tokio::fs::write(
            root.join("composer.lock"),
            serde_json::to_string_pretty(&lock).unwrap(),
        )
        .await
        .unwrap();
        let ledger = pinned_state(&[padded]);
        for scanned in ["pkg:composer/psr/log@3.0.2", "pkg:composer/psr/log@v3.0.2"] {
            let scanned: HashSet<String> = [scanned.to_string()].into_iter().collect();
            assert_eq!(
                hosted_wiring_retained_purls(&common_at(root), Some(&ledger), &scanned).await,
                vec![padded.to_string()]
            );
        }
        let other: HashSet<String> = ["pkg:composer/psr/log@3.0.3".to_string()]
            .into_iter()
            .collect();
        assert!(
            hosted_wiring_retained_purls(&common_at(root), Some(&ledger), &other)
                .await
                .is_empty()
        );
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
    // hosted/vendored runs don't) is pinned by `tests/scan/scan_invariants.rs`;
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

    /// The takeover classifier runs after every hosted rewrite, so it must
    /// not re-walk the lockfiles when no vendored ledger entry could
    /// overlap (the hosted common case), and walks them once otherwise
    /// (#993: it used to discover twice — once for the hosted pins, once
    /// for liveness — and even with no vendored ledger at all).
    #[tokio::test]
    async fn takeover_classifier_discovers_at_most_once() {
        let discoveries = || crate::commands::DISCOVERIES.with(|n| n.get());
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_lock_pointing_at_hosted(root, "minimist", "1.2.2").await;

        // No vendored ledger, then an empty one: nothing to overlap.
        for write_empty in [false, true] {
            if write_empty {
                socket_patch_core::vendor::save_state(root, &VendorState::new())
                    .await
                    .unwrap();
            }
            let before = discoveries();
            assert_eq!(
                classify_overlap_takeover(&common_at(root), root).await,
                OverlapTakeover::default()
            );
            assert_eq!(discoveries(), before, "no vendored entry, no discovery");
        }

        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        let before = discoveries();
        let takeover = classify_overlap_takeover(&common_at(root), root).await;
        assert_eq!(discoveries(), before + 1, "one discovery serves both sides");
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()]
        );
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
    async fn hosted_direction_provable_for_berry_tarball_locator() {
        // Today's berry pin is the plain tarball-URL locator (#404).
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_vendor_ledger_wired(root, &["pkg:npm/minimist@1.2.2"]).await;
        tokio::fs::write(
            root.join("yarn.lock"),
            format!(
                "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                 \"minimist@npm:1.2.2\":\n  version: 1.2.2\n  \
                 resolution: \"minimist@https://patch.socket.dev/patch/npm/{TAKEOVER_TOKEN}/{TAKEOVER_UUID}/minimist-1.2.2.tgz\"\n"
            ),
        )
        .await
        .unwrap();

        let takeover = classify_overlap_takeover(&common_at(root), root).await;
        assert_eq!(
            takeover.redirect,
            vec!["pkg:npm/minimist@1.2.2".to_string()],
            "a berry tarball locator must prove hosted is live"
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

    /// A failed embedded VEX's discovery diagnostics reach the scan
    /// envelope's top-level `warnings[]`, after any already there; an empty
    /// list adds nothing.
    #[test]
    fn vex_error_warnings_append_to_scan_json() {
        let w = RunWarning::new("lockfile_unparseable", "pnpm-lock.yaml: bad");
        let mut env = Envelope::new(JsonCommand::Scan);
        append_vex_error_warnings(&mut env, &[]);
        assert!(env.to_value().get("warnings").is_none());
        env.warn("pnp", "d");
        append_vex_error_warnings(&mut env, std::slice::from_ref(&w));
        let codes: Vec<&str> = env.warnings.iter().map(|w| w.code.as_str()).collect();
        assert_eq!(codes, ["pnp", "lockfile_unparseable"]);
    }
}
