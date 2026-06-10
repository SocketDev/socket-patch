use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::crawlers::{
    detect_npm_pkg_manager, CrawlerOptions, Ecosystem, NpmPkgManager,
};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::apply::{
    apply_package_patch, verify_file_patch, ApplyResult, PatchSources, VerifyStatus,
};
#[cfg(feature = "golang")]
use socket_patch_core::patch::go_redirect::{
    apply_go_redirect, reconcile_go_redirects, verify_go_redirect_state,
};
#[cfg(feature = "golang")]
use socket_patch_core::utils::purl::parse_golang_purl;

use crate::commands::lock_cli::{acquire_or_emit, lock_broken_event};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::telemetry::{track_patch_applied, track_patch_apply_failed};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::json_envelope::{
    AppliedVia, Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile, Status,
    VexSummary,
};

use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};

#[derive(Args)]
pub struct ApplyArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Skip pre-application hash verification (apply even if package version differs).
    #[arg(
        short = 'f',
        long,
        env = "SOCKET_FORCE",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub force: bool,

    /// Read-only: verify that the committed Go `replace`-redirects match the
    /// manifest (for CI / GitHub-App auditing), exiting non-zero on drift.
    /// Lock-free and offline-safe — it does not crawl, fetch, or mutate.
    #[arg(
        long = "check",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub check: bool,

    /// On a successful apply, also generate an OpenVEX 0.2.0 document.
    /// `--vex <path>` is the trigger; the `--vex-*` knobs mirror the
    /// standalone `vex` command. A requested-but-failed VEX makes the
    /// whole command exit non-zero even when patches applied cleanly.
    #[command(flatten)]
    pub vex: VexEmbedArgs,
}

// ── local-go redirect helpers ────────────────────────────────────────────────
// The Go analog of the cargo helpers above: in local mode a `pkg:golang/…` PURL
// redirects to a project-local patched copy under `.socket/go-patches/` wired via
// a `go.mod` `replace` directive. Inert stubs without the `golang` feature.

/// True for a golang PURL in local mode (no `--global` / `--global-prefix`).
#[cfg(feature = "golang")]
fn is_local_go(purl: &str, common: &GlobalArgs) -> bool {
    !common.global
        && common.global_prefix.is_none()
        && Ecosystem::from_purl(purl) == Some(Ecosystem::Golang)
}

/// Whether local-go redirects are in scope (local mode + golang not filtered out
/// by `--ecosystems`). Gates reconcile / `--check`.
#[cfg(feature = "golang")]
fn go_in_local_scope(common: &GlobalArgs) -> bool {
    if common.global || common.global_prefix.is_some() {
        return false;
    }
    match &common.ecosystems {
        None => true,
        Some(list) => list
            .iter()
            .any(|e| e.eq_ignore_ascii_case("golang") || e.eq_ignore_ascii_case("go")),
    }
}

/// Materialise a local-go redirect for `purl`, or `None` if `purl` isn't a
/// local-go target (the caller then falls back to in-place apply, i.e. the
/// `--global` module-cache path).
#[cfg(feature = "golang")]
async fn try_local_go_apply(
    purl: &str,
    pkg_path: &Path,
    patch: &PatchRecord,
    sources: &PatchSources<'_>,
    common: &GlobalArgs,
    force: bool,
) -> Option<ApplyResult> {
    if !is_local_go(purl, common) {
        return None;
    }
    // Vendor ownership wins: a module recorded in `.socket/vendor/state.json`
    // is managed by the explicit `socket-patch vendor` action; the implicit
    // apply must not repoint its `replace` back at `.socket/go-patches/`.
    // The synthesized result's vendored package_path routes the event to
    // `Skipped`/`vendored` (see `result_to_event`).
    if socket_patch_core::patch::vendor::is_purl_vendored(&common.cwd, purl).await {
        return Some(ApplyResult {
            package_key: purl.to_string(),
            package_path: VENDOR_OWNED_MARKER.to_string(),
            success: true,
            files_verified: Vec::new(),
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: None,
            sidecar: None,
        });
    }
    // `pkg_path` is the pristine, case-encoded module-cache dir; `module`/
    // `version` are the decoded PURL components keying the copy + `replace`.
    let (module, version) = parse_golang_purl(purl)?;
    Some(
        apply_go_redirect(
            purl,
            module,
            version,
            pkg_path,
            &common.cwd,
            socket_patch_core::patch::go_mod_edit::GO_PATCHES_DIR,
            &patch.files,
            sources,
            Some(&patch.uuid),
            common.dry_run,
            force,
        )
        .await,
    )
}

#[cfg(not(feature = "golang"))]
async fn try_local_go_apply(
    _purl: &str,
    _pkg_path: &Path,
    _patch: &PatchRecord,
    _sources: &PatchSources<'_>,
    _common: &GlobalArgs,
    _force: bool,
) -> Option<ApplyResult> {
    None
}

/// After the apply loop: prune local-go redirects whose patches were dropped
/// from the manifest. No-op unless local go is in scope.
#[cfg(feature = "golang")]
async fn reconcile_local_go(common: &GlobalArgs, target_manifest_purls: &HashSet<String>) {
    if !go_in_local_scope(common) {
        return;
    }
    let desired: HashSet<String> = target_manifest_purls
        .iter()
        .filter(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Golang))
        .cloned()
        .collect();
    let removed = reconcile_go_redirects(&common.cwd, &desired, common.dry_run).await;
    if !removed.is_empty() && !common.silent && !common.json {
        let verb = if common.dry_run {
            "Would remove"
        } else {
            "Removed"
        };
        println!("{verb} {} stale go patch redirect(s):", removed.len());
        for purl in &removed {
            println!("  {purl}");
        }
    }
}

#[cfg(not(feature = "golang"))]
async fn reconcile_local_go(_common: &GlobalArgs, _target_manifest_purls: &HashSet<String>) {}

/// Read-only verification of the committed Go `replace`-redirects for CI /
/// GitHub-App auditing. Lock-free, crawl-free, offline-safe. Exits 0 when in
/// sync, 1 on drift. Cargo patches in place (no redirect to audit), so `--check`
/// covers Go only.
#[cfg(feature = "golang")]
async fn run_check(args: &ApplyArgs, manifest_path: &Path) -> i32 {
    let manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        // The caller already confirmed the manifest file exists. `Ok(None)` means
        // it vanished since (TOCTOU) → nothing to verify. An `Err` means it exists
        // but is unreadable/corrupt: fail-closed (report drift) rather than
        // silently passing — the guard treats exit 0 as "in sync".
        Ok(None) => return 0,
        Err(e) => {
            if !args.common.silent && !args.common.json {
                eprintln!(
                    "Patch redirect check could not read the manifest ({e}); \
                     treating as drift (fail-closed)."
                );
            }
            return 1;
        }
    };

    // (purl_or_name, reason_code, detail) for each drift.
    let mut drifts: Vec<(String, &'static str, String)> = Vec::new();
    let mut checked: usize = 0;

    {
        use socket_patch_core::patch::go_redirect::Drift as GoDrift;
        if go_in_local_scope(&args.common) {
            // Vendored modules are excluded: their replace directives point at
            // `.socket/vendor/golang/` (the verify engine skips Vendor-owned
            // entries) and their state is audited by `vendor`, not `--check`.
            let vendored = socket_patch_core::patch::vendor::load_state(&args.common.cwd)
                .await
                .map(|s| {
                    s.entries
                        .iter()
                        .flat_map(|(k, e)| [k.clone(), e.base_purl.clone()])
                        .collect::<HashSet<String>>()
                })
                .unwrap_or_default();
            let desired: HashSet<String> = manifest
                .patches
                .keys()
                .filter(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Golang))
                .filter(|p| !vendored.contains(*p))
                .cloned()
                .collect();
            checked += desired.len();
            if let Err(ds) = verify_go_redirect_state(&args.common.cwd, &manifest, &desired).await {
                for d in &ds {
                    let id = match d {
                        GoDrift::MissingCopy { purl }
                        | GoDrift::StaleCopy { purl, .. }
                        | GoDrift::MissingReplace { purl }
                        | GoDrift::WrongReplacePath { purl, .. }
                        | GoDrift::ResolvedVersionMismatch { purl, .. } => purl.clone(),
                        GoDrift::OrphanReplace { module } => module.clone(),
                    };
                    drifts.push((id, "go_redirect_drift", d.to_string()));
                }
            }
        }
    }

    if drifts.is_empty() {
        if args.common.json {
            println!("{}", Envelope::new(Command::Apply).to_pretty_json());
        } else if !args.common.silent {
            println!("Patch redirects are in sync ({checked} checked).");
        }
        0
    } else {
        if args.common.json {
            let mut env = Envelope::new(Command::Apply);
            for (id, code, detail) in &drifts {
                env.record(
                    PatchEvent::new(PatchAction::Failed, id.clone())
                        .with_reason(*code, detail.clone()),
                );
            }
            env.mark_partial_failure();
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            eprintln!("Patch redirects are OUT OF SYNC:");
            for (_, _, detail) in &drifts {
                eprintln!("  {detail}");
            }
            eprintln!("Run `socket-patch apply` to regenerate them.");
        }
        1
    }
}

#[cfg(not(feature = "golang"))]
async fn run_check(args: &ApplyArgs, _manifest_path: &Path) -> i32 {
    // Fail-closed: `--check` is the Go `replace`-redirect audit. A socket-patch
    // built WITHOUT the `golang` feature cannot verify those redirects, so it
    // must NOT report "in sync" (exit 0). Exit non-zero with a clear reason.
    if !args.common.silent && !args.common.json {
        eprintln!(
            "socket-patch: this build has no golang support, so it cannot verify \
             Go patch redirects (`--check`). Install a socket-patch built with the \
             `golang` feature, or point SOCKET_PATCH_BIN at one."
        );
    }
    2
}

/// True when every file the engine verified for this package is already
/// at its `afterHash` — i.e. the patch is a complete no-op on disk.
///
/// Sentinel `package_path` for a result synthesized because the purl is
/// owned by `socket-patch vendor` (recorded in `.socket/vendor/state.json`).
/// `result_to_event` routes it to `Skipped`/`vendored` by exact equality.
pub(crate) const VENDOR_OWNED_MARKER: &str = "managed by socket-patch vendor";

/// Single source of truth for the `already_patched` classification, shared
/// by [`result_to_event`] (which feeds the JSON envelope) and the
/// human-readable summaries so both label packages identically.
///
/// The `!is_empty()` guard is essential: `Iterator::all` over an empty
/// slice is vacuously `true`. Without the guard a result with no verified
/// files — a zero-file patch, or a freshly-applied package whose
/// `files_verified` came back empty — would be mislabeled "already
/// patched" and counted as a no-op even though nothing matched `afterHash`.
fn all_files_already_patched(result: &ApplyResult) -> bool {
    !result.files_verified.is_empty()
        && result
            .files_verified
            .iter()
            .all(|f| f.status == VerifyStatus::AlreadyPatched)
}

/// Decide whether a release variant describes the distribution that is
/// actually installed on disk, based on the verification status of its
/// first patched file.
///
/// This is the apply-side mirror of
/// [`select_installed_variants`](socket_patch_core::patch::apply::select_installed_variants),
/// which `rollback` and `get` use: a variant matches only when its first
/// file is [`Ready`](VerifyStatus::Ready) (its `beforeHash` matches the
/// on-disk bytes) or [`AlreadyPatched`](VerifyStatus::AlreadyPatched)
/// (its `afterHash` already matches). A variant with no files (`None`)
/// has nothing to disqualify it and is treated as a match.
///
/// Crucially, both [`HashMismatch`](VerifyStatus::HashMismatch) **and**
/// [`NotFound`](VerifyStatus::NotFound) mean "this variant's
/// distribution is not the one on disk" and must be skipped. A
/// `NotFound` arises when a non-installed variant patches a file that
/// only exists in *its* distribution (e.g. an sdist patching `setup.py`
/// while a wheel is installed). Skipping it avoids attempting — and
/// spuriously reporting a `Failed` event for — a variant that was never
/// installed.
pub(crate) fn variant_matches_installed(first_file_status: Option<&VerifyStatus>) -> bool {
    match first_file_status {
        None => true,
        Some(status) => *status == VerifyStatus::Ready || *status == VerifyStatus::AlreadyPatched,
    }
}

/// Translate the core engine's per-package [`ApplyResult`] into a single
/// patch-level [`PatchEvent`] for the unified envelope.
///
/// Action mapping (in priority order):
///   * `!result.success`                         → `Failed`
///   * `dry_run` and any file was Ready/Patched → `Verified`
///   * all `files_verified` are AlreadyPatched   → `Skipped` (already_patched)
///   * something was actually patched on disk    → `Applied`
///
/// `files` enumerates only the files that participated in the action —
/// for `Applied`, the patched ones with their `applied_via` strategy;
/// for `Verified`, every file the engine confirmed could be patched.
pub(crate) fn result_to_event(result: &ApplyResult, dry_run: bool) -> PatchEvent {
    let purl = result.package_key.clone();
    if !result.success {
        return PatchEvent::new(PatchAction::Failed, purl).with_error(
            "apply_failed",
            result
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string()),
        );
    }

    // A package managed by `socket-patch vendor` is skipped with its own
    // reason: apply runs implicitly (postinstall/CI) and must never flip
    // ownership back from the explicit vendor action. The synthesized result
    // carries the exact sentinel as its package_path — an equality check, NOT
    // a substring match: the vendor command's own successful results carry
    // real `.socket/vendor/…` copy paths and must classify as Applied.
    if result.package_path == VENDOR_OWNED_MARKER {
        return PatchEvent::new(PatchAction::Skipped, purl)
            .with_reason("vendored", "managed by `socket-patch vendor`");
    }

    if all_files_already_patched(result) {
        return PatchEvent::new(PatchAction::Skipped, purl)
            .with_reason("already_patched", "All files already match afterHash");
    }

    if dry_run {
        let files = result
            .files_verified
            .iter()
            .filter(|f| f.status == VerifyStatus::Ready || f.status == VerifyStatus::AlreadyPatched)
            .map(|f| PatchEventFile {
                path: f.file.clone(),
                verified: true,
                applied_via: None,
            })
            .collect();
        return PatchEvent::new(PatchAction::Verified, purl).with_files(files);
    }

    let files = result
        .files_patched
        .iter()
        .map(|f| PatchEventFile {
            path: f.clone(),
            verified: true,
            applied_via: result
                .applied_via
                .get(f)
                .copied()
                .map(AppliedVia::from_core),
        })
        .collect();
    // Sidecar data is NOT attached here — it's surfaced at the
    // envelope level under `Envelope.sidecars[]` by the run loop.
    // See `Envelope::record_sidecar`. Keeping events clean of
    // sidecar info means each event describes only the apply
    // action; sidecar reporting is a separate, JOIN-able list.
    PatchEvent::new(PatchAction::Applied, purl).with_files(files)
}

pub async fn run(args: ApplyArgs) -> i32 {
    apply_env_toggles(&args.common);
    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = args.common.resolved_manifest_path();

    // Check if manifest exists - exit successfully if no .socket folder is set up
    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.common.json {
            let mut env = Envelope::new(Command::Apply);
            env.status = Status::NoManifest;
            env.dry_run = args.common.dry_run;
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("No .socket folder found, skipping patch application.");
        }
        return 0;
    }

    // Read-only Go `replace`-redirect verification for CI / GitHub-App auditing.
    // Branches BEFORE the lock (so concurrent builds don't contend) and
    // before any crawl/fetch; it reads only the manifest + committed copies +
    // `go.mod`, so it is always offline-safe.
    if args.check {
        return run_check(&args, &manifest_path).await;
    }

    // Serialize against concurrent socket-patch runs targeting the same
    // `.socket/` directory. The guard releases on function return; see
    // `socket_patch_core::patch::apply_lock`.
    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let acquired = match acquire_or_emit(
        socket_dir,
        Command::Apply,
        args.common.json,
        args.common.silent,
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
        args.common.break_lock,
    ) {
        Ok(acquired) => acquired,
        Err(code) => return code,
    };
    let _lock = acquired.guard;
    let lock_was_broken = acquired.broke_lock;

    // Package-manager layout detection. yarn-berry PnP keeps packages
    // inside `.yarn/cache/*.zip` and resolves them via `.pnp.cjs` —
    // the npm crawler can't reach them and rewriting zips is a
    // different operation entirely. Refuse with a clear pointer to
    // `yarn patch`. pnpm gets an informational event; the CoW guard
    // in `apply_file_patch` does the substantive safety work.
    let pkg_manager = detect_npm_pkg_manager(&args.common.cwd);
    match pkg_manager {
        NpmPkgManager::YarnBerryPnP => {
            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.dry_run = args.common.dry_run;
                env.mark_error(EnvelopeError::new(
                    "yarn_pnp_unsupported",
                    "yarn-berry Plug'n'Play layout is not supported by socket-patch (packages live inside .yarn/cache zips). Use `yarn patch <pkg>` instead.",
                ));
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent {
                eprintln!("Error: yarn-berry Plug'n'Play layout is not supported.");
                eprintln!(
                    "  Packages live inside .yarn/cache/*.zip — socket-patch cannot rewrite them in place."
                );
                eprintln!("  Use `yarn patch <pkg>` instead.");
            }
            return 1;
        }
        NpmPkgManager::Pnpm => {
            if !args.common.json && !args.common.silent {
                eprintln!(
                    "Note: pnpm layout detected. Copy-on-write will keep the global store untouched."
                );
            }
            // Non-fatal — CoW handles the safety. JSON consumers see
            // the layout-detected info in the apply envelope's
            // existing events (no separate event added here yet).
        }
        NpmPkgManager::Bun => {
            if !args.common.json && !args.common.silent {
                eprintln!(
                    "Note: bun layout detected. Copy-on-write will keep ~/.bun/install/cache/ untouched."
                );
            }
            // Same shape as pnpm: bun hard-links from its global
            // install cache by default. The CoW guard handles the
            // safety; this is informational only.
        }
        _ => {}
    }

    match apply_patches_inner(&args, &manifest_path).await {
        Ok((success, results, unmatched)) => {
            let patched_count = results
                .iter()
                .filter(|r| r.success && !r.files_patched.is_empty())
                .count();

            // Embedded VEX: only on a successful apply and only when
            // `--vex <path>` was passed. Re-read the manifest fresh so
            // verification observes the just-applied on-disk state. The
            // result is folded into the JSON envelope / human output
            // below and flips the exit code on failure (per the
            // fail-the-command contract). `None` => not requested.
            let vex_result = if success && args.vex.vex.is_some() {
                let params = args.vex.to_build_params();
                Some(generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await)
            } else {
                None
            };
            let vex_failed = matches!(vex_result, Some(Err(_)));

            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.dry_run = args.common.dry_run;
                if lock_was_broken {
                    env.record(lock_broken_event(socket_dir));
                }
                for result in &results {
                    env.record(result_to_event(result, args.common.dry_run));
                    // Sidecar records live on the envelope, not on
                    // individual events. Consumers iterate
                    // `envelope.sidecars[]` and JOIN against
                    // `events[]` by `purl` for per-package context.
                    if let Some(ref sidecar) = result.sidecar {
                        env.record_sidecar(sidecar.clone());
                    }
                }
                // Manifest entries that targeted in-scope ecosystems but
                // had no installed package on disk — emit one Skipped
                // event per purl so downstream consumers can surface them.
                for purl in &unmatched {
                    env.record(
                        PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                            "package_not_installed",
                            "No installed package matches this PURL",
                        ),
                    );
                }
                if !success {
                    env.mark_partial_failure();
                }
                match &vex_result {
                    Some(Ok(summary)) => {
                        env.vex = Some(VexSummary {
                            path: args.vex.vex.as_ref().unwrap().display().to_string(),
                            statements: summary.statements,
                            format: "openvex-0.2.0".to_string(),
                        });
                    }
                    Some(Err(e)) => {
                        env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                    }
                    None => {}
                }
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent && !results.is_empty() {
                let patched: Vec<_> = results.iter().filter(|r| r.success).collect();
                let already_patched: Vec<_> = results
                    .iter()
                    .filter(|r| all_files_already_patched(r))
                    .collect();

                if args.common.dry_run {
                    // An already-patched package is `Skipped` in the JSON
                    // envelope, not `Verified`. Mirror that split here so
                    // "can be patched" excludes the no-ops instead of
                    // double-counting them against "already patched".
                    let can_be_patched = patched.len().saturating_sub(already_patched.len());
                    println!("\nPatch verification complete:");
                    println!("  {} package(s) can be patched", can_be_patched);
                    if !already_patched.is_empty() {
                        println!("  {} package(s) already patched", already_patched.len());
                    }
                } else {
                    println!("\nPatched packages:");
                    for result in &patched {
                        if !result.files_patched.is_empty() {
                            // Summarize the per-file strategy used by this
                            // package: if everything came from the same
                            // source, show just that tag; otherwise list
                            // distinct sources.
                            let mut tags: Vec<&'static str> =
                                result.applied_via.values().map(|v| v.as_tag()).collect();
                            tags.sort_unstable();
                            tags.dedup();
                            let suffix = if tags.is_empty() {
                                String::new()
                            } else {
                                format!(" (via {})", tags.join("+"))
                            };
                            println!("  {}{}", result.package_key, suffix);
                        } else if all_files_already_patched(result) {
                            println!("  {} (already patched)", result.package_key);
                        }
                    }
                }

                if args.common.verbose {
                    println!("\nDetailed verification:");
                    for result in &results {
                        println!("  {}:", result.package_key);
                        for f in &result.files_verified {
                            let status_str = match f.status {
                                VerifyStatus::Ready => "ready",
                                VerifyStatus::AlreadyPatched => "already patched",
                                VerifyStatus::HashMismatch => "hash mismatch",
                                VerifyStatus::NotFound => "not found",
                            };
                            println!("    {} [{}]", f.file, status_str);
                            if let Some(ref msg) = f.message {
                                println!("      message: {msg}");
                            }
                            if args.common.verbose {
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
            }

            // Human-readable VEX status (JSON mode already folded the
            // outcome into the envelope above).
            if !args.common.json && !args.common.silent {
                match &vex_result {
                    Some(Ok(summary)) => {
                        println!(
                            "Wrote OpenVEX document with {} statement(s) to {}",
                            summary.statements,
                            args.vex.vex.as_ref().unwrap().display(),
                        );
                    }
                    Some(Err(e)) => {
                        eprintln!("Error: VEX generation failed: {}", e.message);
                    }
                    None => {}
                }
            }

            // Track telemetry
            if success {
                track_patch_applied(
                    patched_count,
                    args.common.dry_run,
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            } else {
                track_patch_apply_failed(
                    "One or more patches failed to apply",
                    args.common.dry_run,
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            }

            // A requested-but-failed VEX flips an otherwise-successful
            // apply to a non-zero exit (fail-the-command contract).
            if success && !vex_failed {
                0
            } else {
                1
            }
        }
        Err(e) => {
            track_patch_apply_failed(
                &e,
                args.common.dry_run,
                api_token.as_deref(),
                org_slug.as_deref(),
            )
            .await;
            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.dry_run = args.common.dry_run;
                env.mark_error(EnvelopeError::new("apply_failed", e.clone()));
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn apply_patches_inner(
    args: &ApplyArgs,
    manifest_path: &Path,
) -> Result<(bool, Vec<ApplyResult>, Vec<String>), String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    // Resolve patch sources (read `.socket/` directly, or stage an overlay
    // tempdir + download the gap). Shared with `vendor` via fetch_stage.
    let socket_dir = manifest_path.parent().unwrap();
    let staged = match crate::commands::fetch_stage::stage_patch_sources(
        &args.common,
        &manifest,
        socket_dir,
    )
    .await?
    {
        crate::commands::fetch_stage::StageOutcome::Ready(s) => s,
        crate::commands::fetch_stage::StageOutcome::Unavailable => {
            return Ok((false, Vec::new(), Vec::new()))
        }
    };
    let blobs_path = staged.blobs.clone();
    let diffs_path = staged.diffs.clone();
    let packages_path = staged.packages.clone();

    // Partition manifest PURLs by ecosystem
    let manifest_purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let partitioned = partition_purls(&manifest_purls, args.common.ecosystems.as_deref());

    let target_manifest_purls: HashSet<String> = partitioned
        .values()
        .flat_map(|purls| purls.iter().cloned())
        .collect();

    // Local go: prune `replace`-redirects whose patches were dropped from the
    // manifest (orphans). Done here — before the crawl + the "no packages
    // found" early returns — so orphans are reconciled even when the manifest
    // now lists zero in-scope go patches (the all-removed case). No-op unless
    // local go is in scope.
    reconcile_local_go(&args.common, &target_manifest_purls).await;

    let crawler_options = CrawlerOptions {
        cwd: args.common.cwd.clone(),
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        batch_size: 100,
    };

    let all_packages = find_packages_for_purls(
        &partitioned,
        &crawler_options,
        args.common.silent || args.common.json,
    )
    .await;

    let has_any_purls = !partitioned.is_empty();

    if all_packages.is_empty() && !has_any_purls {
        // Nothing in scope: the manifest lists no patches (or every patch was
        // filtered out by `--ecosystems`). There is genuinely no work to do,
        // so this is a clean no-op SUCCESS — not a failure. Returning `false`
        // here used to exit 1 / `partialFailure`, which broke the npm
        // `postinstall` hook (it runs `apply` on every install, including
        // fresh projects whose manifest has no matching patches yet).
        if !args.common.silent && !args.common.json {
            println!("No patches to apply.");
        }
        return Ok((true, Vec::new(), Vec::new()));
    }

    if all_packages.is_empty() {
        if !args.common.silent && !args.common.json {
            eprintln!("Warning: No packages found that match available patches");
            eprintln!(
                "  {} targeted manifest patch(es) were in scope, but no matching packages were found on disk.",
                target_manifest_purls.len()
            );
            eprintln!(
                "  Check that packages are installed and --cwd points to the right directory."
            );
        }
        let unmatched: Vec<String> = target_manifest_purls.iter().cloned().collect();
        return Ok((false, Vec::new(), unmatched));
    }

    // Apply patches
    let mut results: Vec<ApplyResult> = Vec::new();
    let mut has_errors = false;

    // Group release-variant PURLs by base. PyPI (`?artifact_id=`),
    // RubyGems (`?platform=`), and Maven (`?classifier=&ext=`) carry
    // qualifiers distinguishing releases of one `package@version`; the
    // crawler emits the base PURL, so we match the manifest's qualified
    // variants against it here.
    let mut variant_qualified_groups: HashMap<String, Vec<String>> = HashMap::new();
    for (eco, purls) in &partitioned {
        if eco.supports_release_variants() {
            for purl in purls {
                variant_qualified_groups
                    .entry(strip_purl_qualifiers(purl).to_string())
                    .or_default()
                    .push(purl.clone());
            }
        }
    }

    let mut applied_base_purls: HashSet<String> = HashSet::new();
    let mut matched_manifest_purls: HashSet<String> = HashSet::new();

    for (purl, pkg_path) in &all_packages {
        if Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants()) {
            let base_purl = strip_purl_qualifiers(purl).to_string();
            if applied_base_purls.contains(&base_purl) {
                continue;
            }

            let variants = variant_qualified_groups
                .get(&base_purl)
                .cloned()
                .unwrap_or_else(|| vec![base_purl.clone()]);
            let mut applied = false;
            // Did at least one variant reach `apply_package_patch`? A
            // variant reaches it only after passing the first-file
            // installed-distribution check (or under `--force`), so an
            // attempted variant *is* the installed distribution — it must
            // not be reported as "package_not_installed" even if the patch
            // itself then fails. Tracks the "matched but failed" case so the
            // failure message is honest and `unmatched` stays accurate.
            let mut attempted = false;

            for variant_purl in &variants {
                let patch = match manifest.patches.get(variant_purl) {
                    Some(p) => p,
                    None => continue,
                };

                // Check the first file's status (skip when --force). A
                // mismatch *or* a missing file means this variant's
                // distribution isn't the one on disk, so skip it —
                // attempting it would only produce a spurious failure.
                // Mirrors `select_installed_variants`, used by rollback/get.
                if !args.force {
                    let first_status = match patch.files.iter().next() {
                        Some((file_name, file_info)) => Some(
                            verify_file_patch(pkg_path, file_name, file_info)
                                .await
                                .status,
                        ),
                        None => None,
                    };
                    if !variant_matches_installed(first_status.as_ref()) {
                        continue;
                    }
                }

                attempted = true;
                let sources = PatchSources {
                    blobs_path: &blobs_path,
                    packages_path: Some(&packages_path),
                    diffs_path: Some(&diffs_path),
                };
                let result = apply_package_patch(
                    variant_purl,
                    pkg_path,
                    &patch.files,
                    &sources,
                    Some(&patch.uuid),
                    args.common.dry_run,
                    args.force,
                )
                .await;

                // A variant that reached apply is the installed distribution
                // (it passed the first-file check, or `--force` bypassed it),
                // so record it as matched whether or not the patch succeeded.
                // Otherwise a variant that matched on disk but failed to patch
                // would land in `unmatched` and be misreported by the run
                // loop as a `package_not_installed` Skipped event — on top of
                // the Failed event it already emits. Mirrors the npm branch
                // below, which always marks an attempted PURL matched.
                matched_manifest_purls.insert(variant_purl.clone());
                if result.success {
                    applied = true;
                    // No `break`: apply *every* matching variant. PyPI/gem
                    // have exactly one installed distribution (the rest
                    // hash-mismatch and were skipped above), so this
                    // applies a single variant for them; Maven's coexisting
                    // classifier jars each get patched.
                } else {
                    // A variant that reached apply IS the installed
                    // distribution, so a failure here is a real apply
                    // failure — flag it even if a *sibling* variant of the
                    // same base succeeds (Maven's coexisting classifier
                    // jars, or any base where `--force` attempts every
                    // variant). Mirrors the npm branch below and the
                    // rollback loop, which mark `has_errors` on every failed
                    // result; without this a partial multi-variant failure
                    // would leave a `failed` event in the envelope while the
                    // command still reported `success` / exit 0.
                    has_errors = true;
                    if !args.common.silent && !args.common.json {
                        eprintln!(
                            "Failed to patch {}: {}",
                            variant_purl,
                            result.error.as_deref().unwrap_or("unknown error")
                        );
                    }
                }
                results.push(result);
            }

            if applied {
                applied_base_purls.insert(base_purl.clone());
            } else {
                // Nothing applied for this base. `has_errors` was already set
                // per-variant above when a variant was attempted-but-failed;
                // set it here too for the no-variant-attempted case so both
                // paths fail the command.
                has_errors = true;
                if !attempted && !args.common.silent && !args.common.json {
                    // No variant matched the installed distribution at all —
                    // the package on disk isn't any known release variant.
                    // (Attempted-but-failed variants already printed their own
                    // per-variant failure line above.)
                    eprintln!("Failed to patch {base_purl}: no matching variant found");
                }
            }
        } else {
            // npm PURLs: direct lookup
            let patch = match manifest.patches.get(purl) {
                Some(p) => p,
                None => continue,
            };

            let sources = PatchSources {
                blobs_path: &blobs_path,
                packages_path: Some(&packages_path),
                diffs_path: Some(&diffs_path),
            };
            // Local go redirects to a project-local patched copy under
            // `.socket/go-patches/` wired via a `go.mod` `replace` (the module
            // cache is `go.sum`-verified, so in-place patching can't build).
            // Everything else — npm/pypi/gem and cargo (vendored or registry
            // cache) — patches in place via `apply_package_patch`. Without the
            // `golang` feature `try_local_go_apply` is an inert `None`.
            let result =
                match try_local_go_apply(purl, pkg_path, patch, &sources, &args.common, args.force)
                    .await
                {
                    Some(r) => r,
                    None => {
                        apply_package_patch(
                            purl,
                            pkg_path,
                            &patch.files,
                            &sources,
                            Some(&patch.uuid),
                            args.common.dry_run,
                            args.force,
                        )
                        .await
                    }
                };

            if !result.success {
                has_errors = true;
                if !args.common.silent && !args.common.json {
                    eprintln!(
                        "Failed to patch {}: {}",
                        purl,
                        result.error.as_deref().unwrap_or("unknown error")
                    );
                }
            }
            results.push(result);
            matched_manifest_purls.insert(purl.clone());
        }
    }

    // Check if targeted manifest entries had no matches
    let unmatched: Vec<String> = target_manifest_purls
        .iter()
        .filter(|p| !matched_manifest_purls.contains(*p))
        .cloned()
        .collect();

    if !unmatched.is_empty() && !args.common.silent && !args.common.json {
        eprintln!(
            "\nWarning: {} manifest patch(es) had no matching installed package:",
            unmatched.len()
        );
        for purl in &unmatched {
            eprintln!("  - {}", purl);
        }
    }

    if !target_manifest_purls.is_empty()
        && matched_manifest_purls.is_empty()
        && !all_packages.is_empty()
    {
        if !args.common.silent && !args.common.json {
            eprintln!("Warning: None of the targeted manifest patches matched installed packages.");
        }
        has_errors = true;
    }

    // Post-apply summary
    if !args.common.silent && !args.common.json {
        let applied_count = results
            .iter()
            .filter(|r| r.success && !r.files_patched.is_empty())
            .count();
        let already_count = results
            .iter()
            .filter(|r| all_files_already_patched(r))
            .count();
        println!(
            "\nSummary: {}/{} targeted patches applied, {} already patched, {} not found on disk",
            applied_count,
            target_manifest_purls.len(),
            already_count,
            unmatched.len()
        );
    }

    // Note: `apply` deliberately does NOT garbage-collect unused blobs in
    // `.socket/`. GC is the responsibility of `socket-patch repair` /
    // `gc` / `scan --prune`. Keeping apply read-only against `.socket/`
    // means it can run repeatedly (CI dry-runs, deploy hooks) without
    // mutating patch state.

    Ok((!has_errors, results, unmatched))
}

#[cfg(test)]
mod tests {
    //! Tests for `result_to_event` — the per-package → per-patch event
    //! translator that feeds apply's unified JSON envelope. Every
    //! contract value here (action tags, `errorCode` reasons, `files[].path`
    //! shape) is documented in `CLI_CONTRACT.md`.
    use super::*;
    use socket_patch_core::patch::apply::{
        AppliedVia as CoreAppliedVia, ApplyResult, VerifyResult, VerifyStatus,
    };

    /// Build a successful `ApplyResult` with one patched file and one
    /// verified file. Used as the base for action-routing tests.
    fn sample_applied(status: VerifyStatus) -> ApplyResult {
        let mut applied_via = HashMap::new();
        applied_via.insert("package/index.js".to_string(), CoreAppliedVia::Diff);
        ApplyResult {
            package_key: "pkg:npm/minimist@1.2.2".to_string(),
            package_path: "/tmp/node_modules/minimist".to_string(),
            success: true,
            files_verified: vec![VerifyResult {
                file: "package/index.js".to_string(),
                status,
                message: None,
                current_hash: None,
                expected_hash: None,
                target_hash: None,
            }],
            files_patched: vec!["package/index.js".to_string()],
            applied_via,
            error: None,
            sidecar: None,
        }
    }

    #[test]
    fn failed_result_maps_to_failed_action() {
        let mut result = sample_applied(VerifyStatus::Ready);
        result.success = false;
        result.error = Some("hash mismatch".into());

        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "failed");
        assert_eq!(v["errorCode"], "apply_failed");
        assert_eq!(v["error"], "hash mismatch");
    }

    #[test]
    fn all_already_patched_maps_to_skipped() {
        let result = sample_applied(VerifyStatus::AlreadyPatched);
        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "skipped");
        assert_eq!(v["errorCode"], "already_patched");
    }

    #[test]
    fn dry_run_maps_to_verified() {
        let result = sample_applied(VerifyStatus::Ready);
        let event = result_to_event(&result, true);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "verified");
        // Dry-run events list verified files but never an `appliedVia`
        // — nothing was actually written.
        assert_eq!(v["files"][0]["path"], "package/index.js");
        assert!(v["files"][0]
            .as_object()
            .unwrap()
            .get("appliedVia")
            .is_none());
    }

    #[test]
    fn successful_apply_maps_to_applied_with_files() {
        let result = sample_applied(VerifyStatus::Ready);
        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "applied");
        assert_eq!(v["purl"], "pkg:npm/minimist@1.2.2");
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["path"], "package/index.js");
        assert_eq!(files[0]["verified"], true);
        // `appliedVia` is camelCase + lowercase tag — contract value.
        assert_eq!(files[0]["appliedVia"], "diff");
    }

    #[test]
    fn applied_event_emits_one_file_entry_per_patched_file() {
        let mut applied_via = HashMap::new();
        applied_via.insert("package/a.js".to_string(), CoreAppliedVia::Diff);
        applied_via.insert("package/b.js".to_string(), CoreAppliedVia::Package);
        applied_via.insert("package/c.js".to_string(), CoreAppliedVia::Blob);
        let result = ApplyResult {
            package_key: "pkg:npm/foo@1.0.0".to_string(),
            package_path: "/tmp/foo".to_string(),
            success: true,
            files_verified: Vec::new(),
            files_patched: vec![
                "package/a.js".to_string(),
                "package/b.js".to_string(),
                "package/c.js".to_string(),
            ],
            applied_via,
            error: None,
            sidecar: None,
        };

        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 3);
        let by_path: std::collections::HashMap<String, &serde_json::Value> = files
            .iter()
            .map(|f| (f["path"].as_str().unwrap().to_string(), f))
            .collect();
        assert_eq!(by_path["package/a.js"]["appliedVia"], "diff");
        assert_eq!(by_path["package/b.js"]["appliedVia"], "package");
        assert_eq!(by_path["package/c.js"]["appliedVia"], "blob");
    }

    /// Build a successful `ApplyResult` whose verified files carry the
    /// given statuses, with no patched files. Used to exercise the
    /// `already_patched` classification directly.
    fn sample_verified(statuses: &[VerifyStatus]) -> ApplyResult {
        let files_verified = statuses
            .iter()
            .enumerate()
            .map(|(i, status)| VerifyResult {
                file: format!("package/f{i}.js"),
                status: status.clone(),
                message: None,
                current_hash: None,
                expected_hash: None,
                target_hash: None,
            })
            .collect();
        ApplyResult {
            package_key: "pkg:npm/foo@1.0.0".to_string(),
            package_path: "/tmp/foo".to_string(),
            success: true,
            files_verified,
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: None,
            sidecar: None,
        }
    }

    #[test]
    fn all_files_already_patched_true_when_every_file_matches() {
        let result = sample_verified(&[VerifyStatus::AlreadyPatched, VerifyStatus::AlreadyPatched]);
        assert!(all_files_already_patched(&result));
    }

    #[test]
    fn all_files_already_patched_false_when_any_file_differs() {
        let result = sample_verified(&[VerifyStatus::AlreadyPatched, VerifyStatus::Ready]);
        assert!(!all_files_already_patched(&result));
    }

    /// Regression: `Iterator::all` over an empty slice is vacuously true.
    /// A result with no verified files must NOT be reported as
    /// "already patched" — the `!is_empty()` guard enforces this so the
    /// human summaries and the JSON envelope agree.
    #[test]
    fn all_files_already_patched_false_when_no_verified_files() {
        let mut result = sample_verified(&[]);
        assert!(result.files_verified.is_empty());
        assert!(!all_files_already_patched(&result));

        // A freshly-applied package (files patched, none left verified)
        // is likewise not a no-op.
        result.files_patched = vec!["package/a.js".to_string()];
        assert!(!all_files_already_patched(&result));
    }

    /// Regression: a non-installed release variant whose first patched
    /// file is `NotFound` (e.g. an sdist patching `setup.py` while only a
    /// wheel is on disk) must be treated as NOT installed and skipped —
    /// exactly like a `HashMismatch`. Before the fix the loop only skipped
    /// `HashMismatch`, so a `NotFound` variant slipped through to
    /// `apply_package_patch` and produced a spurious `Failed` event in the
    /// JSON envelope. This pins the apply-side decision to the same
    /// Ready/AlreadyPatched contract as `select_installed_variants`.
    #[test]
    fn variant_matches_only_when_first_file_ready_or_already_patched() {
        // Installed distribution: first file applies cleanly, or is
        // already at afterHash → this variant is the one on disk.
        assert!(variant_matches_installed(Some(&VerifyStatus::Ready)));
        assert!(variant_matches_installed(Some(
            &VerifyStatus::AlreadyPatched
        )));

        // Not the installed distribution → must be skipped. The NotFound
        // case is the specific regression this guards.
        assert!(!variant_matches_installed(Some(
            &VerifyStatus::HashMismatch
        )));
        assert!(!variant_matches_installed(Some(&VerifyStatus::NotFound)));

        // A variant with no files has nothing to disqualify it — match,
        // mirroring `select_installed_variants`.
        assert!(variant_matches_installed(None));
    }

    /// Regression: a freshly-applied result with an empty `files_verified`
    /// must map to `Applied`, never `Skipped`/`already_patched`. This is
    /// the same classification the human-readable summary relies on via
    /// `all_files_already_patched`.
    #[test]
    fn applied_with_empty_verified_is_not_skipped() {
        let mut applied_via = HashMap::new();
        applied_via.insert("package/a.js".to_string(), CoreAppliedVia::Blob);
        let result = ApplyResult {
            package_key: "pkg:npm/foo@1.0.0".to_string(),
            package_path: "/tmp/foo".to_string(),
            success: true,
            files_verified: Vec::new(),
            files_patched: vec!["package/a.js".to_string()],
            applied_via,
            error: None,
            sidecar: None,
        };
        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "applied");
    }
}
