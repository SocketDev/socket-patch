//! The hosted-mode (`--mode hosted`) flow: rewrite ONLY the
//! patched dependencies' lockfile / registry-config entries to point at
//! Socket's hosted vendored patches. Self-contained — reuses `run`'s
//! discovery, then returns without touching the apply/vendor branches.

use std::path::Path;
use std::time::Duration;

use futures_util::StreamExt;
use socket_patch_core::api::client::hold_back_debug;
use socket_patch_core::api::types::BatchPackagePatches;
use socket_patch_core::patch::apply_lock::LockGuard;
use socket_patch_core::patch::redirect::DepOverride;
use socket_patch_core::utils::concurrent::{
    api_concurrency, api_concurrency_for, ordered_concurrent,
};
use socket_patch_core::utils::purl::purl_parts;

use crate::commands::vex::generate_vex_from_manifest_path;

use super::{discover_selected, ScanArgs};

mod python;
pub(crate) mod vlt;

pub(crate) use vlt::rollback_heal as vlt_rollback_heal;
pub(crate) use vlt::takeover_heal as vlt_takeover_heal;

#[cfg(test)]
pub(crate) use socket_patch_core::hosted::guidance::{
    npm_allow_remote_already_detail, npm_allow_remote_configured_detail,
    npm_allow_remote_env_set_detail, npm_allow_remote_manual_detail,
    npm_allow_remote_outer_set_detail, npm_allow_remote_unreadable_detail,
    npm_allow_remote_user_set_detail, plan_workspace_trust, pnpm_heal_root,
    pnpm_lock_carries_hosted_redirect, pnpm_lock_may_need_store_flag, pnpm_lock_version_major,
    pnpm_trust_configured_detail, pnpm_trust_legacy_detail, pnpm_trust_manual_guidance,
    pnpm_trust_workspace_unreadable_detail, read_npmrc_for_allow_remote, read_workspace_for_trust,
    TrustPlan,
};
pub(crate) use socket_patch_core::hosted::render::redirect_json_block;

/// Most hosted wheel-metadata downloads in flight at once, below the patch
/// API's own in-flight cap: each one buffers a whole wheel (up to
/// `MAX_VENDOR_PACKAGE_BYTES`).
const WHEEL_METADATA_CONCURRENCY: usize = 4;

/// The in-flight cap for the hosted wheel-metadata window.
///
/// These GETs go to the patch server, so they are paced by the same knob as
/// every other patch-API window ([`api_concurrency`], and with it
/// `SOCKET_API_CONCURRENCY`) — an operator who caps in-flight requests per
/// client must be able to cap this one too, or a `uv.lock` project's wheels
/// land in `skipped` as `python_metadata_unavailable`.
fn wheel_metadata_concurrency(use_public_proxy: bool) -> usize {
    api_concurrency(use_public_proxy).min(WHEEL_METADATA_CONCURRENCY)
}

/// The hosted-mode JSON error envelope, for bail-outs that return before the
/// success envelope at the bottom of [`run_redirect`] is built. When the
/// classic scan object (`scan_result`, threaded in from `run`) is present it
/// is reused so the error envelope carries the SAME top-level scan keys as
/// the success path — folding in `status`/`error` and a minimal `redirect`
/// block — instead of a bare shape that flips the schema. When absent (never
/// in JSON mode today) the bare envelope is emitted. A `--json` consumer must
/// always get parseable stdout — never empty output plus an exit code.
fn emit_json_error(scan_result: Option<serde_json::Value>, message: &str) {
    emit_json_error_with_code(scan_result, None, message);
}

/// `emit_json_error` plus an additive top-level `errorCode` (the stable
/// routing tag the CLI contract gives every classified failure) when the
/// refusal has one; `error` stays the human message.
fn emit_json_error_with_code(
    scan_result: Option<serde_json::Value>,
    code: Option<&str>,
    message: &str,
) {
    let mut result = scan_result.unwrap_or_else(|| serde_json::json!({ "status": "error" }));
    result["status"] = serde_json::json!("error");
    result["error"] = serde_json::json!(message);
    // The rollout block describes a successful run only.
    if let Some(obj) = result.as_object_mut() {
        obj.remove("rollout");
    }
    if let Some(code) = code {
        result["errorCode"] = serde_json::json!(code);
    }
    if !result.get("redirect").is_some_and(|r| r.is_object()) {
        result["redirect"] = serde_json::json!({ "mode": "hosted" });
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .expect("serializing an in-memory JSON value cannot fail")
    );
}

/// Build the hosted `--json` success envelope: the classic scan object
/// (`scan_result`, built by `run` — scannedPackages / totalPatches /
/// canAccessPaidPatches plus the `packages` enumeration) with the redirect
/// summary NESTED under `redirect`, mirroring vendored mode's nested `vendor`
/// block. Extracted so the schema (classic scan keys + nested `redirect`) is
/// unit-testable without a live API. When `scan_result` is absent (never in
/// JSON mode today) a minimal `{status:"success"}` base is used so stdout is
/// still parseable.
fn build_redirect_json_envelope(
    scan_result: Option<serde_json::Value>,
    redirect: serde_json::Value,
) -> serde_json::Value {
    let mut result = scan_result.unwrap_or_else(|| serde_json::json!({ "status": "success" }));
    result["status"] = serde_json::json!("success");
    result["redirect"] = redirect;
    result
}

/// The `redirect_prune_ignored` warning object (`--prune` is a no-op in
/// hosted mode; see the constants' doc in `run`'s module).
pub(super) fn prune_ignored_warning() -> serde_json::Value {
    serde_json::json!({
        "code": super::REDIRECT_PRUNE_IGNORED,
        "detail": super::REDIRECT_PRUNE_IGNORED_DETAIL,
    })
}

/// An engine refusal (nothing was written): `Error (<code>): <message>` on
/// stderr plus the `--json` error envelope carrying the code, exit 1.
fn refuse(
    common: &crate::args::GlobalArgs,
    scan_result: Option<serde_json::Value>,
    refusal: &socket_patch_core::hosted::engine::Refusal,
) -> i32 {
    eprintln!("Error ({}): {}", refusal.code, refusal.message);
    if common.json {
        emit_json_error_with_code(scan_result, Some(&refusal.code), &refusal.message);
    }
    1
}

/// The apply lock for a WET hosted run: the same `<manifest dir>/apply.lock`
/// `apply`/`rollback`/`remove`/`vendor` hold, so the takeover pre-reverts,
/// the ledger merge and the lockfile writes never race them. `acquire`
/// creates a missing `.socket/` and the guard's drop unlinks the lock file
/// and prunes an otherwise-empty `.socket/`, so a run that ends up writing
/// nothing leaves no residue. Contention / IO failures render through the
/// shared [`crate::commands::lock_cli::lock_failure`] mapping — the
/// `lock_held` / `lock_io` codes and the "(waited …)" clause match every
/// other mutating command — into the hosted error envelope (NOT
/// `acquire_or_emit`, whose `Envelope` would replace the classic scan / get
/// object) plus the stderr line and, for a live holder, the wait hint.
fn acquire_hosted_lock(
    common: &crate::args::GlobalArgs,
    scan_result: &mut Option<serde_json::Value>,
) -> Result<LockGuard, i32> {
    let socket_dir = common.socket_dir();
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    match crate::commands::lock_cli::acquire_with_status(&socket_dir, timeout) {
        Ok(guard) => Ok(guard),
        Err(err) => {
            let (code, message) = crate::commands::lock_cli::lock_failure(&err, timeout);
            // Errors print even under --silent ("errors only", never
            // "nothing"): exit 1 with no message would be undiagnosable.
            eprint!(
                "{}",
                crate::commands::lock_cli::format_lock_error(&socket_dir, &err, timeout)
            );
            if common.json {
                emit_json_error_with_code(scan_result.take(), Some(code), &message);
            }
            Err(1)
        }
    }
}

/// The installed-tree probes' outcome: warnings for both output channels,
/// plus the stale purls STRUCTURALLY, so the same-run `--vex` can exclude
/// them from `assume_applied` — an envelope must never attest a CVE its own
/// warnings say is live. Python also carries positive evidence through VEX
/// so a different, healthy interpreter cannot mask a stale installation.
#[derive(Default)]
struct StaleInstallOutcome {
    warnings: Vec<serde_json::Value>,
    stale_purls: std::collections::BTreeSet<String>,
}

/// The `redirect_gem_stale_install` warning for one stale installed
/// materialization (defect facts + verified/disproven remedies: the "Gem
/// stale-install guard" section of CLI_CONTRACT.md). Wording splits on
/// blast radius: a PROJECT-LOCAL dir gets the verified delete-list remedy —
/// installed dir + cache `.gem` + `specifications` entry, plus the project's
/// committed `vendor/cache` archive when the caller passes one (bundler
/// installs from it in preference to fetching, so a remedy that leaves it
/// behind silently reinstates the stale bytes) — while a SHARED gem-env
/// home affects every project on the machine, so that flavor prefers moving
/// the project to a local bundle path and only conditionally names the
/// shared files.
fn gem_stale_install_warning(
    purl: &str,
    gem_dir: &Path,
    leaf: &str,
    cwd: &Path,
    project_cache_gem: Option<&Path>,
) -> serde_json::Value {
    let home = gem_dir
        .parent()
        .and_then(Path::parent)
        .expect("crawler-resolved gem dirs always live under <home>/gems/<leaf>");
    let cache = home.join("cache").join(format!("{leaf}.gem"));
    let spec = home.join("specifications").join(format!("{leaf}.gemspec"));
    let mut paths = vec![
        gem_dir.display().to_string(),
        cache.display().to_string(),
        spec.display().to_string(),
    ];
    if let Some(extra) = project_cache_gem {
        paths.push(extra.display().to_string());
    }
    let list = paths.join(", ");
    let detail = if gem_dir.starts_with(cwd) {
        format!(
            "{purl} was switched to its hosted patch, but a stale \
             UNPATCHED install is already materialized at {} — `bundle install` \
             reuses the installed gem (and its cached .gem) without refetching, \
             and `--force`/`--redownload` reinstall from the stale cache, so \
             the vulnerable upstream code stays live. Remove the stale \
             materialization — {list} — then run `bundle install` so bundler \
             fetches the patched gem",
            gem_dir.display()
        )
    } else {
        format!(
            "{purl} was switched to its hosted patch, but a stale \
             UNPATCHED install is materialized in the shared gem home at {} — \
             `bundle install` reuses it without refetching, so the vulnerable \
             upstream code stays live. That gem home is shared by every \
             project on this machine: prefer switching this project to a \
             project-local bundle path (`bundle config set --local path \
             vendor/bundle`, then `bundle install`); remove {list} directly \
             only if no other project relies on the stale gem",
            gem_dir.display()
        )
    };
    serde_json::json!({ "code": "redirect_gem_stale_install", "detail": detail })
}

/// The vendor/cache flavor of `redirect_gem_stale_install`: the project's
/// committed `bundle cache` archive (`vendor/cache/<leaf>.gem`) is not the
/// patched artifact. Bundler installs from vendor/cache in preference to
/// fetching, so every install — a fresh checkout included — re-materializes
/// the unpatched bytes no matter what the redirected Gemfile + lock say.
fn gem_stale_cache_warning(purl: &str, cache_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "code": "redirect_gem_stale_install",
        "detail": format!(
            "{purl} was switched to its hosted patch, but the \
             project's committed bundler cache still holds an UNPATCHED \
             archive at {} — bundler installs from its cache dir in preference \
             to fetching, so installs (fresh checkouts included) keep \
             materializing the vulnerable upstream bytes. Remove that file, \
             run `bundle install` so bundler fetches the patched gem, and \
             re-run `bundle cache` if the project commits its cache",
            cache_path.display()
        ),
    })
}

/// POSITIVE staleness evidence: at least one record file whose on-disk
/// content was actually read and hashed to something other than its
/// `afterHash` (`Ready` = pristine upstream bytes, `HashMismatch` = neither
/// hash). Missing or unreadable files are NEVER evidence — `verify_file_patch`
/// folds IO errors into `NotFound`, and a transiently unreadable file in an
/// already-patched install must not produce a delete prescription.
/// (`current_hash` is `Some` only when the bytes were really hashed, which
/// also excludes the absent-new-file `Ready`.)
///
/// The probes take this from the same one-pass
/// [`socket_patch_core::vex::verify::judge_installed_record`] that decides
/// PATCHED (`stale_evidence`); this view of it is what the unit tests pin.
#[cfg(test)]
async fn installed_stale_positive_evidence(
    package_dir: &Path,
    record: &socket_patch_core::manifest::schema::PatchRecord,
) -> bool {
    socket_patch_core::vex::verify::judge_installed_record(package_dir, record)
        .await
        .stale_evidence
}

/// Post-rewrite stale-materialization probe for gem redirects: `bundle
/// install` never refetches an already-materialized gem (see the "Gem
/// stale-install guard" section of CLI_CONTRACT.md).
///
/// Judgment sources and rules:
/// * Discovery is [`socket_patch_core::crawlers::RubyCrawler`] — the same
///   installed-gem APIs `apply` uses, honoring `--global`/`--global-prefix`
///   exactly like scan's own discovery; layouts the crawler grows into are
///   covered automatically.
/// * Records are found BY UUID (the fetch key, stable across purl
///   spellings): this run's fetched records first, then the redirect
///   ledger's persisted ones — a re-scan whose `/patches/view` fetch failed
///   transiently still re-fires from the ledger instead of silently
///   dropping the warning (`record_fetch_failed` covers the fetch failure
///   itself). Record availability is part of the candidate filter, and the
///   probe returns before any crawler work (or `gem env` subprocess spawn)
///   when no judgment is possible.
/// * PATCHED means [`verify_patch_record`] `Ok` — the one shared oracle
///   (decided, with STALE, by one pass of
///   [`socket_patch_core::vex::verify::judge_installed_record`]).
///   Judgments are grouped BY INSTALLED DIR: platform-variant purls of one
///   gem resolve to the same dir, and if ANY variant's record proves the
///   dir patched, the dir is patched — never warned.
/// * STALE requires positive evidence (the `installed_stale_positive_evidence`
///   rule) — never inferred from missing/unreadable files.
/// * A committed `vendor/cache/<leaf>.gem` whose sha256 differs from the
///   patched artifact's is stale too (bundler installs from it first, fresh
///   checkouts included): folded into a project-local install warning's
///   delete list, or warned standalone.
///
/// Read-only by contract: nothing is ever deleted — the remedy is
/// prescribed to the user.
async fn gem_stale_install_warnings(
    cwd: &Path,
    global: bool,
    global_prefix: Option<std::path::PathBuf>,
    confirmed: &[(String, String)],
    // This run's fetched records MERGED with the ledger's persisted ones
    // (the caller hands the post-merge ledger map).
    records: &std::collections::BTreeMap<String, socket_patch_core::manifest::schema::PatchRecord>,
    gem_artifact_shas: &std::collections::BTreeMap<(String, String), String>,
) -> StaleInstallOutcome {
    use socket_patch_core::crawlers::types::CrawlerOptions;
    use socket_patch_core::crawlers::RubyCrawler;
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::vendor::file_sha256_hex;
    use socket_patch_core::vex::verify::judge_installed_record;

    let mut out = StaleInstallOutcome::default();
    let find_record =
        |uuid: &str| -> Option<&PatchRecord> { records.values().find(|r| r.uuid == uuid) };
    // Record availability folds into the candidate filter (a zero-file map
    // included: nothing to hash means no judgment either way) so the no-op
    // cases return here, before the crawler is built. On `--dry-run` the
    // caller skips the probe entirely — see the call site.
    let candidates: Vec<(&str, &PatchRecord)> = confirmed
        .iter()
        .filter(|(purl, _)| purl.starts_with("pkg:gem/"))
        .filter_map(|(purl, uuid)| find_record(uuid).map(|r| (purl.as_str(), r)))
        .filter(|(_, r)| !r.files.is_empty())
        .collect();
    if candidates.is_empty() {
        return out;
    }

    // Pass 1: resolve every candidate's installed materializations and judge
    // them, grouped by installed dir (see the fn doc's variant rule).
    struct DirJudgment {
        purl: String,
        leaf: String,
        patched: bool,
        positive: bool,
    }
    let crawler = RubyCrawler::new();
    let options = CrawlerOptions {
        cwd: cwd.to_path_buf(),
        global,
        global_prefix,
    };
    let gem_paths = crawler.get_gem_paths(&options).await.unwrap_or_default();
    // Every candidate's installed dir in every gem home, one blocking pass
    // (and at most one listing) per home — the per-candidate lookups the
    // loop below consumes, in the same (candidate, home) order.
    let stripped: Vec<String> = candidates
        .iter()
        .map(|(purl, _)| socket_patch_core::utils::purl::strip_purl_qualifiers(purl).to_string())
        .collect();
    let mut found_per_home = Vec::with_capacity(gem_paths.len());
    for gems_dir in &gem_paths {
        found_per_home.push(crawler.find_each_by_purl(gems_dir, &stripped).await);
    }
    let mut dir_state: std::collections::BTreeMap<std::path::PathBuf, DirJudgment> =
        std::collections::BTreeMap::new();
    // Bundler's configured cache dir (`cache_path`, default vendor/cache):
    // the committed archives `bundle install` installs from (#483).
    let app_cache = socket_patch_core::crawlers::ruby_crawler::bundler_app_cache_dir(cwd).await;
    for (index, (purl, record)) in candidates.iter().enumerate() {
        for found in &found_per_home {
            let Some(pkg) = &found[index] else {
                continue;
            };
            // A dir whose leaf isn't clean UTF-8 cannot be a real crawler
            // coordinate — skip it rather than interpolate a garbled leaf
            // into the remedy paths.
            let Some(leaf) = pkg.path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let entry = dir_state
                .entry(pkg.path.clone())
                .or_insert_with(|| DirJudgment {
                    purl: (*purl).to_string(),
                    leaf: leaf.to_string(),
                    patched: false,
                    positive: false,
                });
            let judged = judge_installed_record(&pkg.path, record).await;
            if judged.patched {
                entry.patched = true;
            } else if !entry.positive && judged.stale_evidence {
                entry.positive = true;
                entry.purl = (*purl).to_string();
            }
        }
    }

    // Pass 2: warn per stale dir. A project-local dir's delete list also
    // carries the committed vendor/cache archive when one is present and not
    // proven to be the patched artifact — bundler installs from it first, so
    // a remedy that leaves it behind silently reinstates the stale bytes.
    let mut cache_covered: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (dir, j) in &dir_state {
        if j.patched || !j.positive {
            continue;
        }
        let mut folded_cache: Option<std::path::PathBuf> = None;
        if dir.starts_with(cwd) {
            let project_cache = app_cache.join(format!("{}.gem", j.leaf));
            if project_cache.is_file() {
                let proven_patched = match (
                    gem_artifact_shas.get(&gem_sha_key(&j.purl)),
                    file_sha256_hex(&project_cache).await,
                ) {
                    (Some(want), Some(got)) => &got == want,
                    // Unknown sha (or unreadable archive): include it —
                    // removal is safe either way, `bundle install` refetches.
                    _ => false,
                };
                if !proven_patched {
                    folded_cache = Some(project_cache);
                }
            }
        }
        if folded_cache.is_some() {
            if let Some((purl, _)) = candidates.iter().find(|(p, _)| *p == j.purl) {
                cache_covered.insert(purl);
            }
        }
        out.warnings.push(gem_stale_install_warning(
            &j.purl,
            dir,
            &j.leaf,
            cwd,
            folded_cache.as_deref(),
        ));
        out.stale_purls.insert(j.purl.clone());
    }

    // Pass 3: standalone vendor/cache staleness — a committed archive whose
    // sha256 is readable and differs from the patched artifact's, for purls
    // whose project-local install warning did not already fold it in (a
    // fresh checkout with a committed stale cache has no installed dir at
    // all, and would otherwise never warn).
    for (purl, _) in &candidates {
        if cache_covered.contains(purl) {
            continue;
        }
        let Some(want_sha) = gem_artifact_shas.get(&gem_sha_key(purl)) else {
            continue;
        };
        let Some((_, name, version)) = purl_parts(purl) else {
            continue;
        };
        let cache_path = app_cache.join(format!("{name}-{version}.gem"));
        if !cache_path.is_file() {
            continue;
        }
        // Unreadable → no positive evidence, never a guess.
        let Some(got) = file_sha256_hex(&cache_path).await else {
            continue;
        };
        if &got == want_sha {
            continue; // the PATCHED archive — healthy commit, nothing stale
        }
        out.warnings
            .push(gem_stale_cache_warning(purl, &cache_path));
        out.stale_purls.insert((*purl).to_string());
    }
    out
}

/// Whether the hosted flow's Pipenv probe is CERTAIN to run: the candidates
/// that no wheel-metadata failure can drop (none shares a fetched wheel's
/// artifact URL) already target an entry of Pipfile.lock, so
/// `pipenv_lock_targets` over the post-fetch overrides — a superset of
/// them — is true whatever the fetch returns.
fn pipenv_probe_certain<'a>(
    files: &std::collections::BTreeMap<String, String>,
    candidates: impl Iterator<Item = &'a DepOverride>,
    fetched_wheel_urls: impl Iterator<Item = &'a str>,
) -> bool {
    // Cheap pre-check: every hosted run reaches this, so skip building the
    // list when there is no Pipfile.lock.
    if !files.contains_key("Pipfile.lock") {
        return false;
    }
    let droppable: std::collections::BTreeSet<&str> = fetched_wheel_urls.collect();
    let kept: Vec<DepOverride> = candidates
        .filter(|dep| !droppable.contains(dep.artifact_url.as_str()))
        .cloned()
        .collect();
    socket_patch_core::patch::redirect::pipenv_lock_targets(files, &kept)
}

/// The `(name, version)` key the gem artifact-sha map uses — derived from
/// the purl so overrides (which carry no purl) and confirmed purls meet on
/// neutral ground.
fn gem_sha_key(purl: &str) -> (String, String) {
    purl_parts(purl)
        .map(|(_, name, version)| (name, version))
        .unwrap_or_default()
}

/// `scan --mode hosted`: resolve hosted-patch references for the selected patches,
/// then rewrite ONLY those dependencies' lockfile/registry-config entries to
/// point at the hosted vendored patches (the byte-identical counterpart of the
/// GitHub-app registry mode). No artifact bytes land in the repo.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_redirect(
    args: &ScanArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    all_packages_with_patches: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    policy: &super::policy::ScanPolicy,
    // The classic scan object `run` builds for the `--json` path (`Some` in
    // JSON mode, `None` for human output). The redirect result is NESTED into
    // it so the hosted `--json` envelope stays schema-consistent with every
    // other scan; `.take()` at each terminal (error or success) folds it in.
    mut scan_result: Option<serde_json::Value>,
    // Scan's pending telemetry, flushed by `discover_selected` before
    // anything below writes to stdout.
    telemetry: &mut socket_patch_core::telemetry::PendingTelemetry,
    // Scan's npm crawl (`Some` only when an embedded `--vex` will run),
    // handed to the VEX step so it does not walk the tree for the npm
    // roots again.
    npm_prior: Option<&crate::ecosystem_dispatch::NpmCrawlSnapshot>,
    // The merged recorded view (manifest > hosted pins > vendor ledger) the
    // rollout classifies against, whether a batch failed, and the stage
    // that holds this directory's budget.
    recorded: &super::rollout::RecordedState<'_>,
    batch_failed: bool,
    stage: &mut super::rollout::Stage,
) -> i32 {
    // Same discovery/selection as `--apply`/`--vendor`.
    let discovered = match discover_selected(
        api_client,
        all_packages_with_patches,
        can_access_paid_patches,
        policy,
        false,
        false,
        false,
        telemetry,
        scan_result.as_mut(),
    )
    .await
    {
        Ok(d) => d,
        // Hosted mode has no discovery envelope to fold the message into at
        // this point (it builds its `redirect` result further down).
        // `discover_selected` already printed the message to stderr; a
        // `--json` run additionally gets the machine-readable envelope so
        // stdout is never empty on failure.
        Err((code, message)) => {
            if args.common.json {
                emit_json_error(scan_result.take(), &message);
            } else if code == 0 && !args.common.silent {
                // Unreachable from scan (it never prompts, so selection
                // cannot be cancelled); kept for a code-0 selection error.
                eprintln!("No changes made.");
            }
            return code;
        }
    };
    let rows = super::classified_rows(
        stage,
        &discovered,
        recorded,
        batch_failed,
        all_packages_with_patches,
        scan_result.as_mut(),
    );

    // The redirect body consumes the selection only as (purl, uuid) pairs —
    // the seam `get --mode hosted` injects its advisory-pinned selection
    // through (see `run_redirect_selected`). ALREADY rows carry the
    // recorded uuid, so a re-scan re-confirms the pin instead of swapping it.
    let pairs: Vec<(String, String)> = rows
        .iter()
        .map(|r| (r.writer.purl.clone(), r.writer.uuid.clone()))
        .collect();
    run_redirect_selected(
        &args.common,
        &args.vex,
        args.prune || args.sync,
        api_client,
        &pairs,
        scan_result,
        npm_prior,
        Some(super::rollout::Gate::new(stage, rows)),
    )
    .await
}

/// The hosted-redirect flow over an ALREADY-SELECTED `(purl, uuid)` set,
/// on disk. The plan → rewrite → edits core is the shared hosted engine
/// ([`socket_patch_core::hosted::engine`], over a
/// [`ProjectView::Disk`](socket_patch_core::vendor::lock_inventory::ProjectView));
/// what stays here is what needs the host: reference grants and the other
/// network fetches, the apply lock (wet runs with a grant), the redirect
/// ledger load, the vendored→hosted takeover pre-revert (symlink-checked
/// first), the `pipenv --version` probe, the symlink guard, the ledger
/// merge-then-persist and the file writes, the gem / Python / vlt
/// stale-install probes, and the optional VEX. Shared VERBATIM by `scan
/// --mode hosted` (its `--json` arm through the `run_redirect` wrapper, its
/// human arm through [`boxed_run_redirect_selected`] in `scan/mod.rs`; both
/// select via `discover_selected`, with no prompt) and by `get --mode
/// hosted` (which pins the advisory-resolved uuid), so all produce
/// identical on-disk results for the same selection. The redirect ledger
/// is loaded HERE, under the apply lock whenever this run holds one (never
/// handed in pre-loaded: a copy read before the lock could merge over a
/// concurrent writer's edits); a dry run or a zero-grant run reads it
/// strictly but writes nothing, quarantine included.
///
/// `scan_result` must be `Some` exactly when `common.json` is set (the
/// human/JSON split keys on `common.json`; a `--json` caller passing `None`
/// would get a minimal envelope that drops its own keys). `prune_requested`
/// only feeds the `redirect_prune_ignored` warning — `get` passes `false`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_redirect_selected(
    common: &crate::args::GlobalArgs,
    vex: &crate::commands::vex::VexEmbedArgs,
    prune_requested: bool,
    api_client: &socket_patch_core::api::client::ApiClient,
    selected: &[(String, String)],
    mut scan_result: Option<serde_json::Value>,
    npm_prior: Option<&crate::ecosystem_dispatch::NpmCrawlSnapshot>,
    // `scan`'s rollout gate: NEW rows past the budget are deferred after
    // every write-free eligibility check below (§5.2). `get` passes `None`.
    mut rollout: Option<super::rollout::Gate<'_>>,
) -> i32 {
    use socket_patch_core::hosted::engine::{
        self, Candidate, CandidateFiles, RewriteOptions, SkippedPatch,
    };
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::vendor::lock_inventory::ProjectView;

    let view = ProjectView::Disk(&common.cwd);
    let mut skipped: Vec<SkippedPatch> = Vec::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    // The network phases below (reference grants, wheel metadata, patch
    // records) would otherwise be silent gaps on a terminal. Inert under
    // --json/--silent and off a terminal.
    let mut status = crate::ui::StatusLine::stderr(common.json, common.silent);

    if !selected.is_empty() {
        let uuids: Vec<String> = selected.iter().map(|(_, uuid)| uuid.clone()).collect();
        status.set(format!(
            "Resolving hosted artifacts for {}...",
            crate::ui::plural(uuids.len(), "patch", "patches")
        ));
        let fetched = api_client.fetch_registry_references(&uuids).await;
        status.finish();
        let references = match fetched {
            Ok(r) => r,
            // A capped run whose every row is NEW: the failure affects only
            // rows the incomplete lookup defers anyway (§5.2), so it becomes
            // a warning instead of failing the run.
            Err(e)
                if rollout.as_ref().is_some_and(|gate| {
                    let new = gate.new_keys();
                    gate.stage.capped()
                        && selected
                            .iter()
                            .all(|(p, u)| new.contains(&(p.clone(), u.clone())))
                }) =>
            {
                if let Some(gate) = rollout.as_mut() {
                    gate.stage.incomplete = true;
                    gate.stage.reference_failed = Some(e.to_string());
                }
                std::collections::HashMap::new()
            }
            Err(e) => {
                let message = format!("failed to resolve patch references: {e}");
                eprintln!(
                    "{} (nothing was changed; re-run to retry)",
                    format_error_line(&message)
                );
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        };
        // Deferred rows need no reference: a failed lookup that only hit
        // them builds nothing (and records no `not_found` for them).
        if rollout
            .as_ref()
            .is_none_or(|gate| gate.stage.reference_failed.is_none())
        {
            candidates = engine::build_candidates(selected, &references, &mut skipped);
        }
    }
    // The rollout rows key on the selection's purl spelling; the server's
    // reference may spell a candidate's `purl` differently. Uuids are unique
    // across the selection.
    let sel_purl_of: std::collections::HashMap<&str, &str> = selected
        .iter()
        .map(|(purl, uuid)| (uuid.as_str(), purl.as_str()))
        .collect();
    let sel_purl = |c: &Candidate| -> String {
        sel_purl_of
            .get(c.dep.patch_uuid.as_str())
            .map_or_else(|| c.purl.clone(), |p| (*p).to_string())
    };

    // Check binary lock symlinks before a mode takeover changes any wiring
    // (the takeover reverts rewrite locks in place, never create or remove
    // one, so the lock-presence probe holds for the rewrite below too).
    if engine::bun_lockb_symlinked(&view, &candidates) {
        return refuse(
            common,
            scan_result.take(),
            &engine::bun_lockb_symlink_refusal(),
        );
    }

    // vlt artifact preflight: before any takeover or rewrite (dry runs
    // included), each in-scope artifact is fetched as vlt fetches it. A
    // failure while vlt drives withholds the dep from every rewriter;
    // otherwise only from the vlt rewrite.
    let vlt_preflight = {
        let deps: Vec<(&str, &DepOverride)> = candidates
            .iter()
            .filter(|c| c.dep.ecosystem == "npm")
            .map(|c| (c.purl.as_str(), &c.dep))
            .collect();
        vlt::artifact_preflight(common, api_client, &deps).await
    };
    engine::withhold_everywhere(
        &mut candidates,
        &vlt_preflight.withheld_everywhere,
        &mut skipped,
    );

    // The apply lock (see `acquire_hosted_lock`), taken only by a WET run
    // that holds at least one granted reference — the only runs that can
    // write anything: the takeover pre-reverts (lockfiles + the vendored
    // ledger) and the lockfile writes. Dry runs
    // and zero-grant runs never touch `.socket/`, so they never lock (a
    // preview must not create `.socket/`, flip to `lock_held` under a
    // concurrent wet run, or fail on a read-only checkout). Held to the end
    // of the function.
    // A capped run whose only candidates are NEW rows it cannot admit
    // (budget 0, or incomplete data) writes nothing: take no lock either.
    let may_write = rollout.as_ref().is_none_or(|gate| {
        let new = gate.new_keys();
        candidates.iter().any(|c| {
            !new.contains(&(sel_purl(c), c.dep.patch_uuid.clone())) || gate.may_admit(&sel_purl(c))
        })
    });
    let mut lock: Option<LockGuard> = if !common.dry_run && !candidates.is_empty() && may_write {
        match acquire_hosted_lock(common, &mut scan_result) {
            Ok(guard) => Some(guard),
            Err(code) => return code,
        }
    } else {
        None
    };

    // v5 hosted mode keeps no ledger: the lockfiles are the only record of
    // a redirect (vex, list, vendor and rollback read the hosted pins from
    // them). This run's patch records (fetched below) feed only the
    // stale-install probes and the in-run VEX attestation. A pre-v5 ledger
    // on disk is left untouched: it is read only for migration.
    // The vendored ledger, loaded ONCE per run (under the same lock, so no
    // other writer can move the on-disk file under it): the takeover below
    // mutates it in place per reverted purl (saving after each), and the
    // post-write overlap classification reads that post-takeover state —
    // never a pre-takeover snapshot, which would flag every migrated purl
    // as still vendored. `Err` (unreadable / malformed) is "no vendored
    // ownership known" for both consumers.
    let mut vendor_state = socket_patch_core::vendor::load_state(&common.cwd).await;

    // Cross-mode takeover of still-vendored purls (see `vendored_takeover`).
    let Takeover {
        pre_warnings: takeover_pre_warnings,
        dry_run: dry_run_takeover,
        migrated: takeover_migrated,
        unrecorded: takeover_unrecorded,
        files: takeover_files,
        previews: dry_run_takeover_urls,
    } = match vendored_takeover(common, &mut candidates, &mut vendor_state, &mut skipped).await {
        Ok(t) => t,
        Err(refusal) => return refuse(common, scan_result.take(), &refusal),
    };

    // Read the project's candidate files. Skipped when no candidate
    // survived and no dry-run takeover preview is pending (the rewriters do
    // nothing without a dep); everything after the rewrite still runs. A
    // dry-run takeover preview still needs the root locks for the
    // install-policy previews below.
    let read = if !candidates.is_empty() || !dry_run_takeover_urls.is_empty() {
        engine::read_candidate_files(&view, &std::collections::BTreeSet::new(), &candidates).await
    } else {
        CandidateFiles::default()
    };

    let mut python_metadata = std::collections::BTreeMap::new();
    let mut unavailable_python_artifacts = std::collections::BTreeSet::new();
    // `pipenv --version` (see `pipenv_major` below), started before the
    // wheel metadata fetch when that probe is certain to be needed.
    let mut pipenv_probe: Option<tokio::task::JoinHandle<Option<u32>>> = None;
    {
        let wheel_deps = engine::wheel_targets(&candidates, &read.files);
        // The only candidates the metadata fetch can still drop are those
        // sharing a fetched wheel's artifact URL. If the rest already
        // target an entry of Pipfile.lock, the Pipenv probe below is certain
        // to run: start it now so it overlaps the fetch.
        if pipenv_probe_certain(
            &read.files,
            candidates.iter().map(|c| &c.dep),
            wheel_deps.iter().map(|(dep, _)| dep.artifact_url.as_str()),
        ) {
            let root = common.cwd.clone();
            pipenv_probe = Some(tokio::spawn(async move {
                socket_patch_core::utils::pipenv::installed_major(&root).await
            }));
        }
        // The wheels' FIRST attempts run concurrently and are folded in dep
        // order, so `python_metadata`, `unavailable_python_artifacts`,
        // `skipped` and the held-back debug lines come out in dep order.
        //
        // An attempt the client would RETRY (a 429 / 5xx / transport
        // failure) is never settled concurrently: at the first one no
        // further attempt starts, the in-flight ones are awaited (host idle
        // again), and that dep plus every later one finish one at a time. A
        // deferred attempt is RESUMED, not restarted (`Retry-After` waited
        // out, only its remaining budget spent), so each wheel costs the
        // host the same requests a serial fetch would.
        let wheel_metadata_concurrency = wheel_metadata_concurrency(api_client.uses_public_proxy());
        use futures_util::StreamExt as _;
        use socket_patch_core::vendor::pypi::{
            finish_hosted_wheel_metadata, try_fetch_hosted_wheel_metadata_once,
        };
        // Lazily built: a dep's attempt starts only once it is pulled here.
        let mut unstarted = wheel_deps.iter().map(|&(dep, sha256)| {
            try_fetch_hosted_wheel_metadata_once(api_client, &dep.artifact_url, sha256)
        });
        let mut in_flight: futures_util::stream::FuturesOrdered<_> = unstarted
            .by_ref()
            .take(wheel_metadata_concurrency)
            .collect();
        // Once serial: the attempts that were in flight when a dep needed a
        // retry, in dep order (the deps after them were never started).
        let mut drained: Option<std::collections::VecDeque<_>> = None;
        for &(dep, sha256) in &wheel_deps {
            status.set(format!(
                "Fetching hosted wheel metadata for {}...",
                dep.name
            ));
            let attempt = match drained.as_mut() {
                Some(drained) => drained.pop_front(),
                None => match in_flight.next().await {
                    Some(attempt) if !attempt.needs_retry() => {
                        in_flight.extend(unstarted.next());
                        Some(attempt)
                    }
                    // A retryable failure (or nothing left in flight): let
                    // the host go idle, then finish one at a time from here.
                    struggling => {
                        let mut rest = std::collections::VecDeque::new();
                        while let Some(later) = in_flight.next().await {
                            rest.push_back(later);
                        }
                        drained = Some(rest);
                        struggling
                    }
                },
            };
            match finish_hosted_wheel_metadata(api_client, &dep.artifact_url, sha256, attempt).await
            {
                Ok(Some(metadata)) => {
                    python_metadata.insert(dep.artifact_url.clone(), metadata);
                }
                Ok(None) => {}
                Err(detail) => {
                    unavailable_python_artifacts.insert(dep.artifact_url.clone());
                    skipped.push(engine::wheel_metadata_unavailable(dep, &detail));
                }
            }
        }
    }
    // A yarn berry pin takes its `bin:` map from the served tarball's own
    // package.json, the way yarn builds a tarball entry (#718). Only the
    // berry entries that carry a `bin:` map need it; a tarball that cannot
    // be fetched or read drops its patch rather than pin an entry yarn
    // would rewrite on the next install.
    for dep in engine::yarn_berry_manifest_targets(&candidates, &read.files) {
        status.set(format!(
            "Fetching hosted package manifest for {}...",
            dep.name
        ));
        match socket_patch_core::hosted::npm_manifest::fetch_hosted_npm_manifest(
            api_client,
            &dep.artifact_url,
            dep.integrity.sha512.as_deref(),
        )
        .await
        {
            Ok(manifest) => {
                python_metadata.insert(dep.artifact_url.clone(), manifest);
            }
            Err(detail) => {
                unavailable_python_artifacts.insert(dep.artifact_url.clone());
                skipped.push(engine::npm_manifest_unavailable(dep, &detail));
            }
        }
    }
    status.finish();
    candidates.retain(|c| !unavailable_python_artifacts.contains(&c.dep.artifact_url));
    // The Pipfile.lock reference shape depends on the installing Pipenv
    // (`path` for 7–11, `file` from 2018 on), so the installed release is
    // probed (`pipenv --version`, up to 10 s) — but only when a pypi patch
    // actually targets an entry of THIS lock: a stray Pipfile.lock in a uv /
    // Poetry project, a re-scan with nothing left to do and any non-Python
    // run must neither spawn Pipenv nor warn about its absence.
    let targets_pipenv_lock = engine::pipenv_lock_targets(&read.files, &candidates);
    let pipenv_major = match (targets_pipenv_lock, pipenv_probe) {
        (true, Some(probe)) => match probe.await {
            Ok(major) => major,
            Err(err) => std::panic::resume_unwind(err.into_panic()),
        },
        (true, None) => socket_patch_core::utils::pipenv::installed_major(&common.cwd).await,
        // Unreachable (the early start implies the target), but never leave
        // a probe running: aborting drops it, which reaps the child.
        (false, Some(probe)) => {
            probe.abort();
            None
        }
        (false, None) => None,
    };
    // The npm config layers OUTSIDE the project file, located the way npm
    // does: an env `npm_config_allow_remote` beats the project file, and an
    // explicit user / global / builtin value is a machine / org policy a
    // committed project line would silently override — both are respected
    // like a project value.
    let npm_outer = || {
        use socket_patch_core::patch::redirect::npmrc::{resolve_outer_allow_remote, NpmConfigEnv};
        resolve_outer_allow_remote(&NpmConfigEnv::from_process(), |path| {
            socket_patch_core::utils::fs::read_regular_to_string_sync(path).ok()
        })
    };
    let rewrite_options = || RewriteOptions {
        dry_run: common.dry_run,
        targets_pipenv_lock,
        pipenv_major,
        pipenv_unknown_detail: format!(
            "Pipenv was not found on PATH, so the Pipfile.lock references use the modern `file` form (Pipenv 2018 and later). A project installed with Pipenv 7–11 needs `path` references instead: put that pipenv on PATH or set {}=<major> and re-run `scan --mode hosted`.",
            socket_patch_core::utils::pipenv::MAJOR_OVERRIDE_ENV
        ),
        trust_lockfile_config: !common.no_trust_lockfile_config,
        npm_allow_remote_config: !common.no_npm_allow_remote_config,
        npm_outer: &npm_outer,
        blocking: true,
    };
    // The rollout gate plans again without its deferred rows: keep what
    // the second pass needs.
    let second_pass = rollout
        .is_some()
        .then(|| (read.clone(), python_metadata.clone()));
    let mut done = engine::rewrite(
        &view,
        read,
        &candidates,
        python_metadata,
        &vlt_preflight.withheld_from_vlt,
        &dry_run_takeover_urls,
        rewrite_options(),
    )
    .await;

    // The rollout gate (§5.2): every write-free check has run — grants,
    // purl/url, vlt preflight, takeover refusals, wheel metadata, and the
    // rewrite above, whose confirmation probe proves a NEW row would be
    // pinned. Only then is the budget spent; deferred rows leave the
    // rewrite set, which is rewritten again without them.
    if let (Some(gate), Some((read, python_metadata))) = (rollout.as_mut(), second_pass) {
        let eligible: std::collections::HashSet<(String, String)> = done
            .confirmed
            .iter()
            .map(|(purl, uuid)| {
                let purl = sel_purl_of.get(uuid.as_str()).map_or(purl.as_str(), |p| p);
                (purl.to_string(), uuid.clone())
            })
            .collect();
        let texts: Vec<&str> = done.files.values().map(String::as_str).collect();
        super::rollout::mark_pinned(&mut gate.rows, &texts);
        let unknown = gate.stage.reference_failed.is_some();
        gate.stage.plan(&gate.rows, |row| {
            unknown || eligible.contains(&(row.writer.purl.clone(), row.writer.uuid.clone()))
        });
        let deferred = gate.stage.deferred_keys();
        skipped.extend(gate.stage.deferred_skips());
        let before = candidates.len();
        candidates.retain(|c| !deferred.contains(&(sel_purl(c), c.dep.patch_uuid.clone())));
        if candidates.len() != before {
            done = engine::rewrite(
                &view,
                read,
                &candidates,
                python_metadata,
                &vlt_preflight.withheld_from_vlt,
                &dry_run_takeover_urls,
                rewrite_options(),
            )
            .await;
        }
        // A row that turned out to be pinned already (`mark_pinned`: a pin
        // discovery did not recognize) still gets written: take the lock
        // skipped above. Only NEW rows ran without it, so no takeover did.
        if lock.is_none() && !common.dry_run && !candidates.is_empty() {
            match acquire_hosted_lock(common, &mut scan_result) {
                Ok(guard) => lock = Some(guard),
                Err(code) => return code,
            }
        }
    }
    // Held to the end of the function.
    let _lock = lock;
    // Dry-run mode-takeover previews were withheld from the rewriters (their
    // lock fragments still carry the vendored wiring the wet run reverts
    // first), so the presence probe cannot see them: the wet run reverts
    // then redirects each one, and the preview's `redirected` count must
    // report that outcome. Populated only under --dry-run.
    let mut confirmed = done.confirmed.clone();
    confirmed.extend(dry_run_takeover);
    // The takeover already reverted these purls' vendored wiring; one the
    // rewrite then did not pin (a refused lock, unavailable wheel
    // metadata) is left on the unpatched registry release in BOTH modes.
    // That must never pass as success.
    let mut stranded = stranded_takeovers(&takeover_migrated, &confirmed, common.dry_run);
    // A takeover whose revert succeeded but whose ledger update failed is
    // refused (never redirected), yet its vendored wiring and artifact are
    // already gone: it is unpatched in both modes all the same.
    stranded.extend(takeover_unrecorded);

    // Fetch the full patch view (file hashes + vulnerabilities) for each
    // CONFIRMED redirect and persist it so a post-install `socket-patch vex`
    // can attest the patch. A fetch failure does not undo the redirect, but
    // it leaves the patch unattestable — surface it as a warning (JSON +
    // stderr) so CI can detect the attestation gap and re-run.
    let mut records: std::collections::BTreeMap<String, PatchRecord> =
        std::collections::BTreeMap::new();
    let mut record_warnings: Vec<socket_patch_core::patch::redirect::RewriteWarning> = Vec::new();

    // SYMLINK GUARD (see `engine::guard`) — before the ledger and before any
    // write, dry runs included, so a dry run predicts the refusal. The
    // revert side (replay.rs) already refuses linked files, so the write
    // side must too.
    if let Some(refusal) = engine::guard(&view, &done, &candidates) {
        return refuse(common, scan_result.take(), &refusal);
    }

    if !common.dry_run {
        let total = confirmed.len();
        // The views are fetched concurrently but consumed in `confirmed`
        // order, so `records` (newest wins), `record_warnings` and the
        // held-back `--debug` lines fold deterministically. Each response is
        // reduced to its record inside the window: a view carries every
        // file's `blobContent`, which would otherwise be buffered for the
        // whole window.
        let mut views = std::pin::pin!(ordered_concurrent(
            confirmed.iter(),
            api_concurrency_for(api_client.uses_public_proxy(), confirmed.len()),
            |(_, uuid)| {
                hold_back_debug(async move {
                    api_client.fetch_patch(uuid).await.map(|resp| {
                        resp.map(|resp| {
                            socket_patch_core::manifest::records::record_from_patch_response(&resp)
                        })
                    })
                })
            },
        ));
        for (i, (purl, _)) in confirmed.iter().enumerate() {
            status.set(format!("Fetching patch records... ({}/{total})", i + 1));
            let Some(view) = views.next().await else {
                break;
            };
            match view.release() {
                Ok(Some((rec_purl, record))) => {
                    records.insert(rec_purl, record);
                }
                Ok(None) | Err(_) => {
                    record_warnings.push(engine::record_fetch_failed_warning(purl));
                }
            }
        }
        status.finish();
    }

    let rewrite = &done.rewrite;
    if !common.dry_run {
        for (rel, content) in rewrite
            .files
            .iter()
            .map(|(p, s)| (p, s.as_bytes()))
            .chain(rewrite.binary_files.iter().map(|(p, b)| (p, b.as_slice())))
        {
            let path = common.cwd.join(rel);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            // Atomic stage+rename, mode-preserving (the vendored backend's
            // writer): a bare `fs::write` truncates first, so a crash
            // mid-write could leave a torn lockfile behind.
            if let Err(e) =
                socket_patch_core::utils::fs::atomic_write_bytes_preserving_mode(&path, content)
                    .await
            {
                let message = format!("failed to write {rel}: {e}");
                eprintln!("{}", format_error_line(&message));
                if common.json {
                    emit_json_error(scan_result.take(), &message);
                }
                return 1;
            }
        }
    }

    // Gem stale-install probe (see `gem_stale_install_warnings`): runs after
    // the writes so the warning describes the project as this run leaves it.
    // Idempotent re-scans re-confirm and re-probe, so the warning keeps
    // firing until the stale materialization is actually gone. Skipped
    // EXPLICITLY on --dry-run: the probe's ledger-record fallback would
    // otherwise judge state the run did not (re)create.
    let gem_stale: StaleInstallOutcome = if common.dry_run {
        StaleInstallOutcome::default()
    } else {
        // purl-coordinate → the PATCHED .gem artifact's sha256 (registry
        // override identifier, tarball integrity fallback) — judges a
        // committed vendor/cache archive.
        let gem_artifact_shas: std::collections::BTreeMap<(String, String), String> = done
            .overrides
            .iter()
            .filter(|o| o.ecosystem == "gem")
            .filter_map(|o| {
                let sha = o
                    .registry_override
                    .as_ref()
                    .and_then(|ro| ro.identifiers.gem_checksum_sha256.clone())
                    .or_else(|| o.integrity.sha256.clone())?;
                Some(((o.name.clone(), o.version.clone()), sha))
            })
            .collect();
        gem_stale_install_warnings(
            &common.cwd,
            common.global,
            common.global_prefix.clone(),
            &confirmed,
            &records,
            &gem_artifact_shas,
        )
        .await
    };
    let python_stale = if common.dry_run {
        StaleInstallOutcome::default()
    } else {
        python::stale_install_warnings(
            common,
            &confirmed,
            &rewrite.confirmed_pipenv_uuids,
            &records,
        )
        .await
    };

    // vlt warm-tree heal: stale installed copies of the Socket-owned nodes
    // are invalidated (classified only on a dry run or
    // with --no-vlt-install-cleanup), and every confirmed vlt purl whose
    // installed or next-installed bytes are not known to be patched is
    // withheld from the in-run VEX attestation.
    let vlt_stale = {
        let rewrite_codes: Vec<&str> = rewrite.warnings.iter().map(|w| w.code.as_str()).collect();
        let lock_key = socket_patch_core::constants::npm_family::VLT_LOCK;
        vlt::heal_after_rewrite(
            common,
            &vlt::HealInputs {
                final_lock: rewrite
                    .files
                    .get(lock_key)
                    .or_else(|| done.files.get(lock_key))
                    .map(String::as_str),
                preflight: &vlt_preflight,
                records: &records,
                confirmed: &confirmed,
                confirmed_vlt: &rewrite.confirmed_vlt_uuids,
                foreign: &rewrite.vlt_foreign_uuids,
                rewrite_warning_codes: &rewrite_codes,
            },
        )
        .await
    };

    // Cross-mode takeover: a committed vendored ledger (`.socket/vendor/state.json`)
    // may still claim package(s) the lockfiles now pin hosted — their
    // tarballs would then be orphaned and that ledger stale. But the overlap
    // alone does NOT prove hosted won: only warn for the package(s) the LIVE
    // lockfile actually routes to the hosted patch server (see
    // `classify_overlap_takeover`), so a dry-run / no-op over a lock that
    // still points at the vendored files stays silent instead of pointing
    // cleanup at the live vendored ledger. The takeover pre-revert above
    // already reconciled what it could; this only warns (JSON `warnings[]`
    // and stderr) about any overlap left, WITHOUT deleting the other ledger.
    // Classified over the lockfiles as this run left them and the vendored
    // ledger as the takeover left it.
    let mut takeover_warnings: Vec<serde_json::Value> = Vec::new();
    let hosted_now = crate::commands::hosted_state_from_lockfiles(common, &common.cwd).await;
    let superseded = super::classify_overlap_takeover_with(
        common,
        &common.cwd,
        Some(&hosted_now),
        vendor_state.as_ref().ok(),
    )
    .await
    .redirect;
    if !superseded.is_empty() {
        takeover_warnings.push(serde_json::json!({
            "code": super::REDIRECT_SUPERSEDES_VENDORED,
            "detail": super::mode_takeover_detail(&superseded),
        }));
    }

    // `--prune` is a no-op in hosted mode (both hosted terminals return
    // before the GC blocks): make that explicit in the JSON `warnings[]`
    // rather than silently dropping the flag. The human path warns once up
    // front in `run`.
    let mut prune_warnings: Vec<serde_json::Value> = Vec::new();
    if prune_requested {
        prune_warnings.push(prune_ignored_warning());
    }

    // Emit an OpenVEX attestation when `--vex` was requested. The redirected
    // bytes are fetched from the hosted patch server at install time, so the
    // PURLs CONFIRMED REDIRECTED BY THIS RUN are attested from this run's
    // records WITHOUT hash verification (`assume_applied` — the integrity
    // pins written into the lockfile are the evidence), while any OTHER
    // manifest patches (previously applied / vendored — and any stale ledger
    // records this run did not confirm) still verify normally (a
    // post-install `socket-patch vex` re-proves them — see
    // `commands::vex_sources`). Requested-but-failed VEX (including "nothing
    // to attest") flips the exit code.
    let mut vex_statements: Option<usize> = None;
    // VEX run-level advisories: `note_warning` keeps them off stderr under
    // --json, so the envelope's `vex.warnings` is their only channel there.
    let mut vex_warnings: Vec<crate::json_envelope::RunWarning> = Vec::new();
    let mut vex_error: Option<crate::commands::vex::VexGenError> = None;
    let mut vex_code = 0;
    if vex.vex.is_some() && !common.dry_run {
        let mut params = vex.to_build_params();
        // Hosted mode wrote only lockfiles and config files since scan's
        // crawl, never a directory the npm root walk descends into, so its
        // roots and packages still describe the tree (the snapshot checks
        // it was taken with these crawler options). `get --mode hosted`
        // passes none.
        params.npm_prior = npm_prior.cloned();
        // v5 keeps no hosted ledger: this run's fetched records are the
        // hosted record source of the in-run attestation.
        params.hosted_records = records.clone();
        // Stale-flagged purls are EXCLUDED from assume_applied: the same-run
        // envelope carries a redirect_gem_stale_install warning proving the
        // installed materialization unpatched, so attesting that purl from
        // the ledger would contradict the run's own warning. Excluded purls
        // fall back to `vex`'s normal installed-tree verification.
        // A confirmed uuid whose bundled instance the rewriter had to skip
        // (#469) leaves that copy unpatched, so it too is verified, never
        // assumed.
        params.assume_applied = confirmed
            .iter()
            .filter(|(_, uuid)| !rewrite.bundled_skipped_uuids.contains(uuid))
            .map(|(purl, _)| purl.clone())
            .filter(|purl| {
                !gem_stale.stale_purls.contains(purl)
                    && !python_stale.stale_purls.contains(purl)
                    && !vlt_stale.stale_purls.contains(purl)
            })
            .collect();
        // A healthy copy in another interpreter must not override a stale
        // Python tree found by the probe, including with --vex-no-verify;
        // likewise a vlt copy the heal could not prove patched.
        params.known_stale = python_stale
            .stale_purls
            .iter()
            .chain(&vlt_stale.stale_purls)
            .cloned()
            .collect();
        let manifest_path = common.resolved_manifest_path();
        match generate_vex_from_manifest_path(common, &params, &manifest_path).await {
            Ok(summary) => {
                vex_statements = Some(summary.statements);
                vex_warnings = summary.warnings;
            }
            Err(e) => {
                vex_code = 1;
                vex_warnings = e.embedded_warnings();
                vex_error = Some(e);
            }
        }
    }

    // One merged warning list, in one order, for both channels: the
    // rewriter's own warnings first (e.g. `no package-lock.json`), then the
    // record, package-manager, stale-install, takeover and prune warnings.
    let mut engine_warnings = rewrite.warnings.clone();
    engine_warnings.extend(vlt_preflight.warnings.iter().cloned());
    engine_warnings.extend(record_warnings);
    engine_warnings.extend(done.rush_warnings.iter().cloned());
    engine_warnings.extend(done.pnpm_warnings.iter().cloned());
    engine_warnings.extend(done.npm_warnings.iter().cloned());
    let mut warnings: Vec<serde_json::Value> =
        socket_patch_core::hosted::render::rewrite_warnings_json(&engine_warnings);
    warnings.extend(gem_stale.warnings.iter().cloned());
    warnings.extend(python_stale.warnings.iter().cloned());
    warnings.extend(vlt_stale.warnings.iter().cloned());
    warnings.extend(takeover_pre_warnings.iter().cloned());
    warnings.extend(stranded.iter().map(|purl| {
        serde_json::json!({
            "code": "redirect_takeover_unpatched",
            "detail": format!(
                "{purl} was vendored and its vendored wiring was reverted, but it \
                 was not pinned to hosted (see the warnings above), so the \
                 project now installs the UNPATCHED registry release — fix the \
                 reported cause and re-run `scan --mode hosted`, or run `scan \
                 --mode vendored` to vendor it again"
            ),
        })
    }));
    warnings.extend(takeover_warnings.iter().cloned());
    warnings.extend(prune_warnings.iter().cloned());

    if common.json {
        // Nest the redirect result under `redirect` inside the classic scan
        // object (built by `run`, threaded in via `scan_result`), mirroring
        // vendored mode's nested `vendor` block, so the hosted `--json`
        // envelope keeps the same top-level scan keys as every other scan.
        let redirect = redirect_json_block(
            confirmed.len(),
            done.rewritten.clone(),
            skipped
                .iter()
                .map(socket_patch_core::hosted::render::skipped_json)
                .collect(),
            warnings,
            common.dry_run,
        );
        let mut result = build_redirect_json_envelope(scan_result.take(), redirect);
        if !stranded.is_empty() {
            result["status"] = serde_json::json!("partial_failure");
        }
        if let Some(gate) = &rollout {
            super::finish_rollout_json(gate.stage, &mut result);
        }
        if let Some(statements) = vex_statements {
            result["vex"] = serde_json::json!({
                "path": vex.vex.as_ref().expect("vex_statements is Some only when --vex was given").display().to_string(),
                "statements": statements,
                "format": "openvex-0.2.0",
                "verified": false,
            });
            // Same skip-if-empty `warnings` key as the agent arm's VEX block.
            if !vex_warnings.is_empty() {
                result["vex"]["warnings"] = serde_json::to_value(&vex_warnings)
                    .expect("RunWarning is a plain string struct: serialization cannot fail");
            }
        } else if let Some(e) = &vex_error {
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({ "code": e.code, "message": e.message });
            super::append_vex_error_warnings(&mut result, &vex_warnings);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .expect("serializing an in-memory JSON value cannot fail")
        );
    } else {
        if !common.silent {
            // Wrap long warnings only on a terminal: logs and pipes keep one
            // line per sentence so CI can grep them.
            let width =
                std::io::IsTerminal::is_terminal(&std::io::stderr()).then(crate::ui::stderr_width);
            // A stranded takeover was NOT migrated to hosted: its
            // `redirect_takeover_unpatched` warning below says so instead.
            for purl in takeover_migrated.iter().filter(|p| !stranded.contains(p)) {
                eprintln!("{}", format_takeover_line(purl, common.dry_run));
            }
            // The files a takeover's revert touched (or, on --dry-run,
            // would touch) count alongside the rewriters' own: a dry-run
            // takeover is withheld from the rewriters, and a wet revert can
            // touch a wiring file the hosted rewriter never rewrites. The
            // same union in both modes keeps preview and wet counts equal.
            let mut human_files = done.rewritten.clone();
            human_files.extend(takeover_files.iter().cloned());
            human_files.sort();
            human_files.dedup();
            // The summary line: scripts read it, so it stays on stdout, as do
            // the rollout line and the next steps; the warnings below are on
            // stderr and name their package themselves.
            println!(
                "{}",
                format_redirect_summary(confirmed.len(), human_files.len(), common.dry_run)
            );
            let human_warnings: Vec<(&str, &str)> = warnings
                .iter()
                .map(|w| {
                    (
                        w["code"].as_str().unwrap_or_default(),
                        w["detail"].as_str().unwrap_or_default(),
                    )
                })
                // The prune notice already printed up front (in `run`);
                // successful takeovers printed above as progress lines.
                .filter(|(code, _)| {
                    *code != super::REDIRECT_PRUNE_IGNORED && !TAKEOVER_INFO_CODES.contains(code)
                })
                .collect();
            // Human output prints the bare strings — `Value`'s `Display`
            // would JSON-quote them.
            // Deferred rows are summed up by the rollout lines instead.
            let skipped_pairs: Vec<(String, String)> = skipped
                .iter()
                .filter(|s| s.reason != super::rollout::ROLLOUT_DEFERRED)
                .map(|s| (s.purl.clone(), s.reason.clone()))
                .collect();
            // Granted, but nothing in the project pins it (no lock entry,
            // unreadable lock, ...): listed so it never vanishes silently.
            // (A skipped uuid — e.g. unavailable wheel metadata — is already
            // listed with its reason.)
            let unconfirmed: Vec<String> = candidates
                .iter()
                .filter(|c| {
                    !confirmed
                        .iter()
                        .any(|(cp, cu)| *cp == c.purl && *cu == c.dep.patch_uuid)
                })
                .filter(|c| !skipped.iter().any(|s| s.uuid == c.dep.patch_uuid))
                .map(|c| c.purl.clone())
                .collect();
            for line in format_unredirected(
                &skipped_pairs,
                &unconfirmed,
                confirmed.is_empty(),
                // Only the lockfile rewriters' own warnings explain a
                // missing lock entry; unrelated guidance (pnpm trust, VEX,
                // stale installs) is not what the hint points at.
                rewrite.warnings.len(),
            ) {
                eprintln!("{line}");
            }
            for (code, detail) in &human_warnings {
                let detail = if *code == "redirect_npm_allow_remote" && !common.verbose {
                    // One line by default; the full policy text (the
                    // tradeoff, every manual recovery) is in `--json` and
                    // `--verbose`.
                    eprintln!("{}", npm_allow_remote_one_line(detail));
                    continue;
                } else if *code == "redirect_pnpm_trust_lockfile" && done.pnpm_rerun_only {
                    pnpm_trust_rerun_reminder()
                } else {
                    detail
                };
                eprintln!("{}", format_warning(code, detail, width));
            }
            if let Some(statements) = vex_statements {
                eprintln!(
                    "Wrote OpenVEX document with {} to {} (hosted patches are attested \
                     from their patch records, not hash-verified — their bytes are fetched at install \
                     time; run `socket-patch vex` after installing to verify against the \
                     installed tree).",
                    crate::ui::plural(statements, "statement", "statements"),
                    vex.vex
                        .as_ref()
                        .expect("vex_statements is Some only when --vex was given")
                        .display(),
                );
            } else if vex.vex.is_some() && common.dry_run {
                eprintln!(
                    "{}",
                    crate::commands::vex::format_vex_dry_run_skip("rewritten")
                );
            }
            let (rollout_line, deferred_steps) = match &rollout {
                Some(gate) => {
                    for (code, detail) in gate.stage.warnings() {
                        eprintln!("{}", format_warning(code, &detail, width));
                    }
                    super::rollout::human(gate.stage, common.dry_run)
                }
                None => (None, Vec::new()),
            };
            if let Some(line) = rollout_line {
                println!("{line}");
            }
            // "Commit … to keep the hosted patches" / "reinstall" would be
            // wrong for a stranded takeover, whose warning names the remedy.
            let mut next_steps = if common.dry_run || !stranded.is_empty() {
                Vec::new()
            } else {
                format_next_steps(&human_files, &rewrite.edits, !takeover_migrated.is_empty())
            };
            next_steps.extend(deferred_steps);
            for line in next_steps {
                println!("{line}");
            }
        }
        // Errors print even under --silent ("errors only", never
        // "nothing"): exit 1 with no message would be undiagnosable.
        if let Some(e) = &vex_error {
            e.print_embedded(common);
        }
        if common.silent {
            for w in warnings
                .iter()
                .filter(|w| w["code"] == "redirect_takeover_unpatched")
            {
                eprintln!(
                    "{}",
                    format_warning(
                        "redirect_takeover_unpatched",
                        w["detail"].as_str().unwrap_or_default(),
                        None
                    )
                );
            }
        }
    }
    if vex_code == 0 && !stranded.is_empty() {
        return 1;
    }
    vex_code
}

/// The purls a WET takeover migrated (vendored wiring reverted) that the
/// rewrite did not confirm as pinned. Empty under `--dry-run`, whose
/// takeover previews are counted as confirmed without a rewrite.
fn stranded_takeovers(
    migrated: &[String],
    confirmed: &[(String, String)],
    dry_run: bool,
) -> Vec<String> {
    use socket_patch_core::utils::purl::{canonical_purl, strip_purl_qualifiers};
    if dry_run {
        return Vec::new();
    }
    let key = |purl: &str| canonical_purl(strip_purl_qualifiers(purl));
    let pinned: std::collections::HashSet<String> =
        confirmed.iter().map(|(purl, _)| key(purl)).collect();
    migrated
        .iter()
        .filter(|purl| !pinned.contains(&key(purl)))
        .cloned()
        .collect()
}

/// Cross-mode takeover: a purl this run is about to redirect may still be
/// VENDORED — for cargo a committed `[patch.crates-io]` path entry, a
/// detached Cargo.lock entry, a committed copy, and a vendored ledger
/// entry; for the npm family a `file:./.socket/vendor/…` lock resolution
/// (plus a berry `resolutions` pin) and its committed tarball; for golang
/// the vendor-owned go.mod `replace`, its committed module copy, and its
/// ledger entry. The hosted rewriters know nothing about that wiring
/// (cargo would refuse `--locked` builds over the unused `[patch]` entry;
/// yarn classic would hijack a resolution the vendored ledger still
/// claims; yarn berry refuses `file:` outright). A takeover must leave the
/// project FULLY hosted: revert each such purl's vendored state first (the
/// per-purl machinery `vendor --revert` runs), and only then redirect —
/// which also hands the redirect the PRISTINE registry lock fragment to
/// record as its own revert original. A purl
/// whose vendored state cannot be cleanly reverted (revert failure, or
/// vendored wiring with a missing/corrupt ledger) is REFUSED — skipped
/// with an actionable error — never half-migrated.
///
/// Refused purls are moved from `candidates` into `skipped`; dry-run
/// takeover previews leave `candidates` too (see [`Takeover::dry_run`]).
/// `Err` is the symlinked-wiring refusal (nothing was written).
async fn vendored_takeover(
    common: &crate::args::GlobalArgs,
    candidates: &mut Vec<socket_patch_core::hosted::engine::Candidate>,
    vendor_state: &mut std::io::Result<socket_patch_core::vendor::VendorState>,
    skipped: &mut Vec<socket_patch_core::hosted::engine::SkippedPatch>,
) -> Result<Takeover, socket_patch_core::hosted::engine::Refusal> {
    use socket_patch_core::hosted::engine::{Candidate, SkippedPatch, TakeoverPreview};
    let mut out = Takeover::default();
    // Which root locks each dry-run takeover purl is vendored into (from
    // its vendor ledger wiring): the wet run reverts that wiring and then
    // splices the hosted URL there, so the install-policy auto-configs
    // (npm `.npmrc` allow-remote, pnpm `trustLockfile`) must be PREVIEWED
    // for those locks even though the rewriters never see these purls.
    let mut dry_run_locks: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    // PyPI: every Python rewriter (requirements.txt, Poetry, Pipenv, uv,
    // Hatch, PDM, pylock) refuses a non-registry source as user-authored,
    // including the vendored one socket-patch wrote itself, so a vendored
    // purl must be reverted to its registry entry first (#328).
    let takeover_capable = |p: &str| {
        p.starts_with("pkg:cargo/")
            || p.starts_with("pkg:npm/")
            || p.starts_with("pkg:golang/")
            || p.starts_with("pkg:pypi/")
    };
    if !candidates.iter().any(|c| takeover_capable(&c.purl)) {
        // No takeover-capable candidates — nothing to reconcile.
        return Ok(out);
    }
    use socket_patch_core::utils::purl::{canonical_purl as canon, strip_purl_qualifiers};
    // Each takeover-capable candidate with its vendored ledger entry, if
    // any (cloned out so the loop can mutate the state).
    let takeover: Vec<(&Candidate, Option<socket_patch_core::vendor::VendorEntry>)> = candidates
        .iter()
        .filter(|c| takeover_capable(&c.purl))
        .map(|c| {
            let entry = vendor_state
                .as_ref()
                .ok()
                .and_then(|s| {
                    socket_patch_core::vendor::lookup_entry(
                        &s.entries,
                        strip_purl_qualifiers(&c.purl),
                    )
                })
                .cloned();
            (c, entry)
        })
        .collect();
    // Compatibility must be known before the takeover removes a live
    // patch. In particular, a v0 workspace can keep an existing local
    // tuple even though hosted mode cannot replace it with a URL. Only
    // an npm purl WITH a vendored entry can be taken over, so the bun
    // locks are read here only when one exists — the candidate-file
    // read below covers every other run.
    let bun_takeover_refusal = if takeover
        .iter()
        .any(|(c, entry)| entry.is_some() && c.purl.starts_with("pkg:npm/"))
    {
        match socket_patch_core::utils::fs::read_regular_to_string(&common.cwd.join("bun.lock"))
            .await
        {
            Ok(content) => socket_patch_core::patch::redirect::preflight_bun_hosted(&content).err(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match socket_patch_core::utils::fs::read_regular_to_bytes_sync(
                    &common.cwd.join("bun.lockb"),
                ) {
                    Ok(bytes) => {
                        socket_patch_core::patch::redirect::preflight_bun_binary(&bytes).err()
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    Err(e) => Some(socket_patch_core::patch::redirect::RewriteWarning {
                        code: "redirect_bun_lockb_invalid".into(),
                        detail: format!("cannot read bun.lockb: {e}"),
                    }),
                }
            }
            Err(e) => Some(socket_patch_core::patch::redirect::RewriteWarning {
                code: "redirect_bun_lock_unsupported".into(),
                detail: format!("cannot read bun.lock before mode takeover: {e}"),
            }),
        }
    } else {
        None
    };
    // Yarn berry twin of the bun gate: the berry rewriter's project-level
    // refusals (mixed line endings, cacheKey, `.yarnrc.yml`
    // compressionLevel) must be known before the takeover reverts a
    // vendored berry purl, or the revert strips the live vendored patch
    // and the rewriter then refuses the lock. Only entries the
    // vendor ledger wired through the yarn-berry backend are gated (the
    // lock is read only when one exists); an unreadable lock is left to
    // the revert's own diagnostics.
    let berry_entry = |entry: &socket_patch_core::vendor::VendorEntry| {
        entry.ecosystem == "npm" && entry.flavor.as_deref() == Some("yarn-berry")
    };
    let berry_takeover_refusal = if takeover
        .iter()
        .any(|(_, entry)| entry.as_ref().is_some_and(berry_entry))
    {
        match socket_patch_core::utils::fs::read_regular_to_string(&common.cwd.join("yarn.lock"))
            .await
        {
            Ok(lock) => {
                let yarnrc = socket_patch_core::utils::fs::read_regular_to_string(
                    &common.cwd.join(".yarnrc.yml"),
                )
                .await
                .ok();
                socket_patch_core::patch::redirect::preflight_yarn_berry_hosted(
                    &lock,
                    yarnrc.as_deref(),
                )
                .err()
            }
            Err(_) => None,
        }
    } else {
        None
    };
    // vlt twin: the hosted rewriter's lock-level refusal must be known
    // before a vendored vlt entry is reverted, or the revert strips the
    // live vendored patch and the rewrite then refuses the lock.
    let vlt_entry = |entry: &socket_patch_core::vendor::VendorEntry| {
        entry.ecosystem == "npm" && entry.flavor.as_deref() == Some("vlt")
    };
    let vlt_takeover_refusal = if takeover
        .iter()
        .any(|(_, entry)| entry.as_ref().is_some_and(vlt_entry))
    {
        match socket_patch_core::utils::fs::read_regular_to_string(
            &common
                .cwd
                .join(socket_patch_core::constants::npm_family::VLT_LOCK),
        )
        .await
        {
            Ok(lock) => {
                let files = std::collections::BTreeMap::from([(
                    socket_patch_core::constants::npm_family::VLT_LOCK.to_string(),
                    lock,
                )]);
                socket_patch_core::patch::redirect::vlt::preflight_vlt_hosted(&files).err()
            }
            Err(_) => None,
        }
    } else {
        None
    };
    // The takeover refusal (if any) for one candidate: bun gates every
    // npm purl, berry and vlt only their own vendored entries, and a
    // requirements.txt entry is gated on the hosted rewriter's reach (it
    // pins only the root file, #699). Berry also runs the rewriter's
    // per-dep grant gate (a grant without the berry cache checksum is
    // skipped by the rewriter, so reverting first would leave the package
    // in neither mode). A refused purl is never
    // dispatched (see the loop), so its wiring is not a write target here.
    let takeover_refusal = |c: &Candidate,
                            entry: Option<&socket_patch_core::vendor::VendorEntry>|
     -> Option<socket_patch_core::patch::redirect::RewriteWarning> {
        if c.purl.starts_with("pkg:pypi/") {
            return entry.and_then(|e| {
                socket_patch_core::patch::redirect::preflight_requirements_takeover(e).err()
            });
        }
        if !c.purl.starts_with("pkg:npm/") {
            return None;
        }
        let berry = entry.is_some_and(berry_entry);
        bun_takeover_refusal
            .clone()
            .or_else(|| berry_takeover_refusal.clone().filter(|_| berry))
            .or_else(|| {
                berry
                    .then(|| {
                        socket_patch_core::patch::redirect::preflight_yarn_berry_hosted_dep(&c.dep)
                            .err()
                    })
                    .flatten()
            })
            .or_else(|| {
                vlt_takeover_refusal
                    .clone()
                    .filter(|_| entry.is_some_and(vlt_entry))
            })
    };
    // SYMLINK PRE-CHECK for the takeover reverts — the same rule as the
    // SYMLINK GUARD below, applied to each ledger entry's recorded wiring
    // (the revert backends also stage and rename over the file). Checked
    // BEFORE any revert dispatches (and under --dry-run too) so "nothing
    // was written" stays true.
    let revert_targets = takeover
        .iter()
        .filter_map(|(c, entry)| {
            entry
                .as_ref()
                .filter(|e| takeover_refusal(c, Some(e)).is_none())
        })
        .flat_map(|entry| entry.wiring.iter().map(|w| w.file.as_str()));
    if let Some(linked) =
        socket_patch_core::utils::fs::first_symlink(&common.cwd, revert_targets).await
    {
        return Err(socket_patch_core::hosted::engine::symlink_refusal(linked));
    }
    let mut refused: Vec<String> = Vec::new();
    for (candidate, ledger_entry) in &takeover {
        let purl = &candidate.purl;
        let uuid = &candidate.dep.patch_uuid;
        if let Some(entry) = ledger_entry {
            if let Some(warning) = takeover_refusal(candidate, Some(entry)) {
                refused.push(purl.clone());
                // Project-level refusals repeat per purl; report each once.
                let warning = serde_json::json!(warning);
                if !out.pre_warnings.contains(&warning) {
                    out.pre_warnings.push(warning);
                }
                continue;
            }
            if common.dry_run {
                // Preview through the same per-purl revert machinery the
                // wet run dispatches (write-free under dry_run): a
                // vendored state the wet run would refuse to revert is
                // refused here too, and one it would revert is announced
                // as a takeover — never handed to the rewriters, which
                // would refuse the still-vendored wiring.
                let outcome =
                    crate::commands::vendor::dispatch_revert_one(entry, &common.cwd, true).await;
                if outcome.success && revert_keeps_wiring(&outcome) {
                    refused.push(purl.clone());
                    out.pre_warnings.push(drifted_takeover_warning(purl));
                    continue;
                }
                if !outcome.success {
                    refused.push(purl.clone());
                    out.pre_warnings.push(serde_json::json!({
                        "code": "redirect_vendored_revert_failed",
                        "detail": format!(
                            "{purl} is vendored and its vendored state could not be \
                             reverted ({}); NOT switched to hosted — run `socket-patch vendor \
                             --revert` to clean up, then re-run `scan --mode hosted`",
                            outcome.error.as_deref().unwrap_or("unknown error")
                        ),
                    }));
                    continue;
                }
                out.pre_warnings.push(serde_json::json!({
                    "code": "redirect_would_revert_vendored",
                    "detail": format!(
                        "{purl} is currently vendored; the hosted wiring will \
                         revert its vendored wiring, ledger entry, and committed \
                         artifact first, then switch to hosted (mode takeover)"
                    ),
                }));
                out.dry_run.push((purl.clone(), uuid.clone()));
                out.migrated.push(purl.clone());
                out.files
                    .extend(entry.wiring.iter().map(|w| w.file.clone()));
                dry_run_locks.insert(
                    purl.clone(),
                    entry.wiring.iter().map(|w| w.file.clone()).collect(),
                );
                continue;
            }
            let outcome =
                crate::commands::vendor::dispatch_revert_one(entry, &common.cwd, false).await;
            if !outcome.success {
                refused.push(purl.clone());
                out.pre_warnings.push(serde_json::json!({
                    "code": "redirect_vendored_revert_failed",
                    "detail": format!(
                        "{purl} is vendored and its vendored state could not be \
                         reverted ({}); NOT switched to hosted — run `socket-patch vendor \
                         --revert` to clean up, then re-run `scan --mode hosted`",
                        outcome.error.as_deref().unwrap_or("unknown error")
                    ),
                }));
                continue;
            }
            if revert_keeps_wiring(&outcome) {
                // A wiring record drifted and was left in place, so the
                // project may still resolve through the vendored artifact
                // and the ledger entry holds the only recorded originals
                // (the RevertOutcome contract): keep both and refuse,
                // exactly as `vendor --revert` reports it skipped.
                refused.push(purl.clone());
                out.pre_warnings.push(drifted_takeover_warning(purl));
                continue;
            }
            // Drop the reverted entry from the in-memory ledger and
            // persist per purl so a crash mid-run leaves a ledger
            // matching the on-disk wiring. The entry stays dropped even
            // when the save fails: its wiring and artifact ARE gone, so
            // a later successful save in this loop writes the truth.
            let state = vendor_state
                .as_mut()
                .expect("a vendored ledger entry was looked up in this state, so it loaded");
            state
                .entries
                .retain(|k, e| canon(k) != canon(purl) && canon(&e.base_purl) != canon(purl));
            if let Err(e) = socket_patch_core::vendor::save_state(&common.cwd, state).await {
                // The wiring is reverted but the ledger still claims it;
                // redirecting now would leave a ledger asserting wiring
                // that is gone. Fail closed for this purl — and since its
                // vendored wiring is already gone, report it as stranded.
                refused.push(purl.clone());
                out.unrecorded.push(purl.clone());
                out.pre_warnings.push(serde_json::json!({
                    "code": "redirect_vendored_revert_failed",
                    "detail": format!(
                        "{purl}: vendored wiring reverted but the vendored ledger \
                         could not be updated ({e}); NOT switched to hosted — fix \
                         .socket/vendor/state.json and re-run"
                    ),
                }));
                continue;
            }
            out.pre_warnings.push(serde_json::json!({
                "code": "redirect_takeover_reverted_vendored",
                "detail": format!(
                    "{purl} was vendored; reverted its vendored wiring, ledger \
                     entry, and committed artifact before switching to hosted (mode \
                     takeover: the project is now fully hosted for this package)"
                ),
            }));
            out.pre_warnings.extend(
                outcome
                    .warnings
                    .iter()
                    .filter(|w| w.code == socket_patch_core::vendor::vlt_lock::REINSTALL_REQUIRED)
                    .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail })),
            );
            out.migrated.push(purl.clone());
            out.files
                .extend(entry.wiring.iter().map(|w| w.file.clone()));
        } else {
            // No usable ledger entry. If socket-owned vendored wiring for
            // this crate is nevertheless present, the ledger is missing or
            // corrupt — the originals needed to revert are unrecoverable,
            // so redirecting on top would wedge the project. Refuse.
            // (Cargo-only probe: Socket-owned `[patch.crates-io]` entries
            // for exactly this name@version in the root Cargo.toml or a
            // legacy `.cargo/config*` — another vendored version of the
            // crate has its own ledger entry. An npm purl in this state
            // falls through to the rewriters' own per-flavor
            // diagnostics.)
            let coords = purl
                .starts_with("pkg:cargo/")
                .then(|| purl_parts(purl).map(|(_, name, version)| (name, version)))
                .flatten();
            let wired = match &coords {
                Some((n, v)) => {
                    socket_patch_core::vendor::cargo::socket_wiring_present(&common.cwd, n, v).await
                }
                None => false,
            };
            if wired {
                refused.push(purl.clone());
                out.pre_warnings.push(serde_json::json!({
                    "code": "redirect_vendored_revert_failed",
                    "detail": format!(
                        "{purl} has socket-owned vendored `[patch.crates-io]` \
                         wiring but no usable vendored ledger entry \
                         (.socket/vendor/state.json is missing or corrupt); NOT \
                         redirected — restore the ledger or remove the vendored \
                         wiring manually, then re-run"
                    ),
                }));
            }
        }
    }
    for purl in &refused {
        if let Some((c, entry)) = takeover.iter().find(|(c, _)| &c.purl == purl) {
            let reason = takeover_refusal(c, entry.as_ref())
                .map_or_else(|| "vendored_revert_failed".to_string(), |w| w.code);
            skipped.push(SkippedPatch::new(purl, &c.dep.patch_uuid, &reason));
        }
    }
    // Purls leaving the rewrite set: refused takeovers, plus the dry-run
    // takeover previews (still vendored on disk — the wet run reverts
    // them before the rewriters ever see their files).
    let withheld: std::collections::HashSet<&str> = refused
        .iter()
        .map(String::as_str)
        .chain(out.dry_run.iter().map(|(p, _)| p.as_str()))
        .collect();
    if !withheld.is_empty() {
        // Keep the dry-run takeover candidates' URLs (and the root locks
        // their purl is vendored into) for the install-policy previews.
        for (purl, _) in &out.dry_run {
            let locks = dry_run_locks.get(purl).cloned().unwrap_or_default();
            for c in candidates.iter().filter(|c| &c.purl == purl) {
                out.previews.push(TakeoverPreview {
                    artifact_url: c.dep.artifact_url.clone(),
                    locks: locks.clone(),
                });
            }
        }
        candidates.retain(|c| !withheld.contains(c.purl.as_str()));
    }
    Ok(out)
}

/// Whether a takeover revert left (or, on `--dry-run`, would leave) vendored
/// wiring in place: a drift-skipped record, or a reverted file that still
/// references the artifact dir. The backends compute both signals on dry
/// runs too, while `kept_artifact` itself is set only on wet runs.
fn revert_keeps_wiring(outcome: &socket_patch_core::vendor::RevertOutcome) -> bool {
    outcome.kept_artifact
        || outcome.drift_skipped()
        || outcome
            .warnings
            .iter()
            .any(|w| w.code == "vendor_revert_residual_reference")
}

/// The refusal for a takeover whose vendored wiring drifted since vendoring.
fn drifted_takeover_warning(purl: &str) -> serde_json::Value {
    serde_json::json!({
        "code": "redirect_vendored_revert_failed",
        "detail": format!(
            "{purl} is vendored and part of its vendored wiring was edited since \
             vendoring, so it is left in place; NOT switched to hosted — restore or \
             remove that wiring (`socket-patch vendor --revert` lists it), then re-run \
             `scan --mode hosted`"
        ),
    })
}

/// What [`vendored_takeover`] did (or, on `--dry-run`, would do).
#[derive(Default)]
struct Takeover {
    /// Its warnings, reported after the rewriters' own.
    pre_warnings: Vec<serde_json::Value>,
    /// Dry-run takeover previews: `(purl, uuid)` pairs whose vendored state
    /// the wet run would revert and then redirect. Withheld from the
    /// rewriters (their lock fragments still carry the vendored wiring the
    /// wet run reverts FIRST) and counted as redirected, so the preview's
    /// envelope matches the wet run's outcome.
    dry_run: Vec<(String, String)>,
    /// Human output: the purls migrated (or, on --dry-run, to be migrated)
    /// from vendored to hosted.
    migrated: Vec<String>,
    /// Wet takeovers whose vendored wiring was reverted but whose ledger
    /// update then failed: refused (never redirected), so unpatched in
    /// both modes.
    unrecorded: Vec<String>,
    /// The files their revert touches (or would touch). Both modes count
    /// `rewritten ∪ files`, so the preview's file count matches the wet
    /// run's even for wiring files the hosted rewriter does not also
    /// rewrite (a Gemfile line, a uv source).
    files: std::collections::BTreeSet<String>,
    /// The withheld dry-run takeover candidates' artifact URLs and wired
    /// root locks, for the install-policy previews.
    previews: Vec<socket_patch_core::hosted::engine::TakeoverPreview>,
}

// ── Human-output formatting ────────────────────────────────────────────────
//
// Pure `String` builders for everything the hosted flow prints in human
// mode, so the exact text is unit-testable (see the tests module). JSON
// output never goes through these: its `detail`/`reason` strings are the
// stable, machine-facing spellings.

/// Warning codes that report a SUCCESSFUL vendored→hosted migration. They
/// stay in the JSON `warnings[]` (additive contract), but a human run
/// prints them as plain progress lines ([`format_takeover_line`]), not as
/// warnings.
const TAKEOVER_INFO_CODES: &[&str] = &[
    "redirect_takeover_reverted_vendored",
    "redirect_would_revert_vendored",
];

/// Lowercase tool names that must keep their spelling at the start of a
/// sentence (`pnpm >=11 rejects…` must not become `Pnpm`).
const LOWERCASE_TOOLS: &[&str] = &[
    "npm", "pnpm", "yarn", "bun", "cargo", "pip", "pipenv", "uv", "poetry", "pdm", "hatch", "go",
    "gem", "bundler", "bundle", "composer", "mvn", "gradle", "dotnet", "deno", "rush", "vlt",
    "vlx", "vlr",
];

/// Capitalize the first letter of a message for an `Error:`/`Warning:`
/// line, leaving it alone when the first word is an identifier rather than
/// an English word: a file name (`pnpm-lock.yaml`), a purl, a flag, a path,
/// or a lowercase tool name.
fn sentence_case(msg: &str) -> String {
    let first_word = msg.split_whitespace().next().unwrap_or("");
    let is_word = !first_word.is_empty()
        && first_word
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == ',' || c == ';')
        && !LOWERCASE_TOOLS.contains(&first_word.trim_end_matches([',', ';']));
    if !is_word {
        return msg.to_string();
    }
    let mut chars = msg.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// `Error: <Message>` for a hosted-flow failure.
fn format_error_line(msg: &str) -> String {
    format!("Error: {}", sentence_case(msg))
}

/// Split `text` into wrap tokens at whitespace, except that a
/// backtick-delimited code span (`` `pnpm install --trust-lockfile` ``)
/// stays one token so a command the user copies is never broken across
/// lines. An unclosed span falls back to plain whitespace splitting.
fn wrap_tokens(text: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut span: Vec<&str> = Vec::new();
    for word in text.split_whitespace() {
        span.push(word);
        let open = span.iter().map(|w| w.matches('`').count()).sum::<usize>() % 2 == 1;
        if !open {
            tokens.push(span.join(" "));
            span.clear();
        }
    }
    tokens.extend(span.into_iter().map(str::to_string));
    tokens
}

/// Greedy word wrap to `width` columns (characters, not bytes). The first
/// line starts with `first_prefix`, later lines with `indent`. A word
/// longer than the line (a URL) gets a line of its own, never split; a
/// backtick code span counts as one word (see [`wrap_tokens`]).
fn wrap_words(text: &str, width: usize, first_prefix: &str, indent: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut line = first_prefix.to_string();
    let mut line_len = first_prefix.chars().count();
    let mut empty = true;
    for word in wrap_tokens(text) {
        let word = word.as_str();
        let wlen = word.chars().count();
        if !empty && line_len + 1 + wlen > width {
            lines.push(std::mem::replace(&mut line, indent.to_string()));
            line_len = indent.chars().count();
            empty = true;
        }
        if !empty {
            line.push(' ');
            line_len += 1;
        }
        line.push_str(word);
        line_len += wlen;
        empty = false;
    }
    lines.push(line);
    lines
}

/// Split a long guidance paragraph into its sentences, at every period
/// followed by a space (host names and versions such as `patch.socket.dev`
/// or `5.4` never contain one). Each sentence keeps its own period; the
/// last one is returned as written.
fn split_sentences(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text.trim();
    while let Some(i) = rest.find(". ") {
        out.push(rest[..=i].to_string());
        rest = rest[i + 2..].trim_start();
    }
    if !rest.is_empty() {
        out.push(rest.to_string());
    }
    out
}

/// One human warning: `Warning: <detail>` (the code is JSON-only). The pnpm
/// trustLockfile guidance is a paragraph of separate instructions, so it renders as a
/// headline plus one `  - ` bullet per sentence. With `width` (stderr is a
/// terminal) every line is word-wrapped; without it (a pipe or a CI log)
/// each sentence stays on one line so the text remains greppable.
fn format_warning(code: &str, detail: &str, width: Option<usize>) -> String {
    let prefix = "Warning: ";
    let detail = sentence_case(detail.trim());
    let (headline, bullets) = if code == "redirect_pnpm_trust_lockfile" {
        let mut sentences = split_sentences(&detail).into_iter();
        let head = sentences.next().unwrap_or_default();
        (head, sentences.collect::<Vec<_>>())
    } else {
        (detail, Vec::new())
    };
    let mut lines: Vec<String> = Vec::new();
    match width {
        Some(w) => {
            lines.extend(wrap_words(&headline, w, prefix, "  "));
            for b in &bullets {
                lines.extend(wrap_words(b, w, "  - ", "    "));
            }
        }
        None => {
            lines.push(format!("{prefix}{headline}"));
            lines.extend(bullets.iter().map(|b| format!("  - {b}")));
        }
    }
    lines.join("\n")
}

/// The one-line re-run reminder that replaces the full pnpm trustLockfile
/// guidance in human mode when this run changed nothing pnpm-related (the
/// lock was redirected and trust configured by an earlier run, whose
/// output carried the full text; `--json` still carries it every time).
fn pnpm_trust_rerun_reminder() -> &'static str {
    "pnpm-lock.yaml already uses hosted patches and pnpm-workspace.yaml already sets \
     `trustLockfile: true`; keep both committed, and never rebuild the lockfile \
     (`pnpm clean --lockfile`), which discards the hosted patches"
}

/// The stdout summary line.
///
/// - wet: `Redirected 1 package; rewrote 1 file.`
/// - dry run: `Would redirect 1 package and rewrite 1 file (--dry-run: nothing was changed).`
/// - every redirected package was already in place (nothing to rewrite):
///   `1 package is already redirected; nothing to rewrite.`
fn format_redirect_summary(redirected: usize, files: usize, dry_run: bool) -> String {
    use crate::ui::plural;
    if redirected > 0 && files == 0 {
        return format!(
            "{} already on hosted patches; nothing to rewrite.",
            plural(redirected, "package is", "packages are")
        );
    }
    let pkgs = plural(redirected, "package", "packages");
    let files = plural(files, "file", "files");
    if dry_run {
        format!("Would switch {pkgs} to hosted patches and rewrite {files} (--dry-run: nothing was changed).")
    } else {
        format!("Switched {pkgs} to hosted patches; rewrote {files}.")
    }
}

/// Readable text for a `skipped[].reason` code (the JSON keeps the code).
/// Unknown server statuses fall through verbatim.
fn describe_skip_reason(reason: &str) -> String {
    match reason {
        "not_found" => "the hosted patch server has no artifact for this patch".into(),
        "forbidden" => "not entitled to this patch (paid plan or no org access)".into(),
        "pending" | "pending_build" => {
            "the hosted artifact is still being built; re-run later".into()
        }
        "build_failed" => "the hosted artifact failed to build".into(),
        "withdrawn" => "the patch was withdrawn".into(),
        "bad_purl" => "the server returned an unparseable package URL".into(),
        "no_url" => "the server returned no artifact URL".into(),
        "vendored_revert_failed" => {
            "its vendored state could not be reverted (see the warning)".into()
        }
        "python_metadata_unavailable" => "the hosted wheel's metadata could not be fetched".into(),
        "npm_manifest_unavailable" => {
            "the hosted tarball's package.json could not be fetched".into()
        }
        "redirect_bun_lock_unsupported" | "redirect_bun_lockb_invalid" => {
            "the Bun lockfile blocks the vendored-to-hosted migration (see the warning)".into()
        }
        "redirect_vlt_lock_unsupported" => {
            "vlt-lock.json blocks the vendored-to-hosted migration (see the warning)".into()
        }
        "redirect_requirements_takeover_unreachable" => {
            "hosted mode cannot pin it where vendored mode wired it, so it stays vendored \
             (see the warning)"
                .into()
        }
        "redirect_vlt_artifact_unverifiable" => {
            "vlt could not verify the hosted artifact (see the warning)".into()
        }
        other => format!("server status `{other}`"),
    }
}

/// The per-package "not redirected" lines, `skipped` (with a reason code)
/// first, then `unconfirmed` (granted, but nothing in the project's files
/// pins it). When nothing at all was redirected they sit under a
/// `No patches could be redirected:` headline; otherwise each line stands
/// alone (it prints on stderr, apart from the stdout summary).
fn format_unredirected(
    skipped: &[(String, String)],
    unconfirmed: &[String],
    nothing_redirected: bool,
    lock_warnings: usize,
) -> Vec<String> {
    if skipped.is_empty() && unconfirmed.is_empty() {
        return Vec::new();
    }
    let see = match lock_warnings {
        0 => "",
        1 => " (see the warning below)",
        _ => " (see the warnings below)",
    };
    // Under the headline every line is a package that was not redirected,
    // so it needs no "Skipped"/"Not redirected" lead of its own.
    let (skip_lead, unpinned_lead) = if nothing_redirected {
        ("  ", "  ")
    } else {
        ("Skipped ", "Not hosted ")
    };
    let mut lines = Vec::new();
    if nothing_redirected {
        lines.push("No patches could be switched to hosted:".to_string());
    }
    for (purl, reason) in skipped {
        lines.push(format!(
            "{skip_lead}{purl}: {}",
            describe_skip_reason(reason)
        ));
    }
    for purl in unconfirmed {
        lines.push(format!(
            "{unpinned_lead}{purl}: no lockfile entry pinning it could be rewritten{see}"
        ));
    }
    lines
}

/// The human line for a successful (or, on `--dry-run`, planned)
/// vendored→hosted migration.
fn format_takeover_line(purl: &str, dry_run: bool) -> String {
    if dry_run {
        format!(
            "Would migrate {purl} from vendored to hosted (its vendored wiring, ledger entry, \
             and committed artifact would be reverted first)."
        )
    } else {
        format!(
            "Migrated {purl} from vendored to hosted (reverted its vendored wiring, ledger \
             entry, and committed artifact)."
        )
    }
}

/// `a`, `a and b`, `a, b, and c`; past `max` names, `a, b, and 3 more`.
fn join_names(names: &[String], max: usize) -> String {
    let shown: Vec<&str> = names.iter().take(max).map(String::as_str).collect();
    let more = names.len().saturating_sub(max);
    let mut parts: Vec<String> = shown.iter().map(|s| s.to_string()).collect();
    if more > 0 {
        parts.push(format!("{more} more"));
    }
    match parts.len() {
        0 => String::new(),
        1 => parts.remove(0),
        2 => format!("{} and {}", parts[0], parts[1]),
        n => format!("{}, and {}", parts[..n - 1].join(", "), parts[n - 1]),
    }
}

/// Next steps after a wet run that rewrote files (stdout, after the
/// summary — the same place vendored mode prints its own): commit the
/// rewritten files, reinstall so the installed tree picks up the patched
/// artifacts, then verify with `vex`. After a vendored→hosted takeover
/// (`vendored_removed`) the commit also has to carry the deleted vendored
/// ledger entries and artifacts.
fn format_next_steps(files: &[String], edits: &[socket_patch_core::patch::redirect::FileEdit], vendored_removed: bool) -> Vec<String> {
    if files.is_empty() && !vendored_removed {
        return Vec::new();
    }
    let mut commit: Vec<String> = Vec::new();
    if vendored_removed {
        commit.push(".socket/vendor/ (the removed vendored ledger entries and artifacts)".to_string());
    }
    commit.extend(files.iter().cloned());
    let npm = files
        .iter()
        .any(|f| f == "package-lock.json" || f == "npm-shrinkwrap.json");
    let hint = if npm {
        " (e.g. `npm ci`)".to_string()
    } else {
        crate::commands::composer_hints::hosted_reinstall_hint(files, edits).unwrap_or_default()
    };
    let mut extra = Vec::new();
    if files
        .iter()
        .any(|f| f == socket_patch_core::constants::npm_family::VLT_LOCK)
    {
        extra.push("vlt: commit vlt-lock.json; CI should run `vlt ci`.".to_string());
    }
    crate::ui::next_steps(
        &format!("{} to keep the hosted patches", join_names(&commit, 6)),
        &format!(
            "Reinstall from the updated lockfile{hint} so the installed packages pick up the \
             patched artifacts"
        ),
        &extra,
    )
}

/// Transient-frame boxed constructor for [`run_redirect_selected`] — the
/// future embeds the whole hosted engine, and callers outside scan (`get
/// --mode hosted`) must not materialize it in their own poll frame (Windows
/// 1 MiB main-thread stack; same rationale as scan's `boxed_*` family).
#[allow(clippy::too_many_arguments)]
pub(crate) fn boxed_run_redirect_selected<'a>(
    common: &'a crate::args::GlobalArgs,
    vex: &'a crate::commands::vex::VexEmbedArgs,
    prune_requested: bool,
    api_client: &'a socket_patch_core::api::client::ApiClient,
    selected: &'a [(String, String)],
    scan_result: Option<serde_json::Value>,
    npm_prior: Option<&'a crate::ecosystem_dispatch::NpmCrawlSnapshot>,
    rollout: Option<super::rollout::Gate<'a>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_redirect_selected(
        common,
        vex,
        prune_requested,
        api_client,
        selected,
        scan_result,
        npm_prior,
        rollout,
    ))
}

/// The default human form of a `redirect_npm_allow_remote` warning: one
/// line saying whether the project `.npmrc` now carries `allow-remote=all`
/// or the user must set it. `detail` is one of the `npm_allow_remote_*`
/// texts below; `--verbose` and `--json` show it in full.
pub(crate) fn npm_allow_remote_one_line(detail: &str) -> String {
    const MORE: &str = "(details: --verbose)";
    if detail.contains("`allow-remote=all` was written to a new")
        || detail.contains("`allow-remote=all` was appended to the existing")
    {
        format!(
            "Note: set `allow-remote=all` in .npmrc so npm >=12 installs the hosted \
             patches; commit it with the lockfile {MORE}."
        )
    } else if detail.contains("`allow-remote=all` would be") {
        format!(
            "Note: would set `allow-remote=all` in .npmrc so npm >=12 installs the \
             hosted patches {MORE}."
        )
    } else if detail.contains("already sets `allow-remote=all`") {
        format!(
            "Note: .npmrc already sets `allow-remote=all`, so npm >=12 installs the \
             hosted patches; keep it committed {MORE}."
        )
    } else {
        format!(
            "Warning: npm >=12 refuses the hosted patches until `allow-remote=all` is \
             set (in .npmrc, or `npm ci --allow-remote=all`); it was not set \
             automatically {MORE}."
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_redirect_json_envelope, gem_stale_cache_warning, gem_stale_install_warning,
        gem_stale_install_warnings, installed_stale_positive_evidence,
        npm_allow_remote_already_detail, npm_allow_remote_configured_detail,
        npm_allow_remote_env_set_detail, npm_allow_remote_manual_detail,
        npm_allow_remote_outer_set_detail, npm_allow_remote_unreadable_detail,
        npm_allow_remote_user_set_detail, plan_workspace_trust, pnpm_heal_root,
        pnpm_lock_carries_hosted_redirect, pnpm_lock_version_major, pnpm_trust_configured_detail,
        pnpm_trust_legacy_detail, pnpm_trust_manual_guidance,
        pnpm_trust_workspace_unreadable_detail, prune_ignored_warning, read_npmrc_for_allow_remote,
        read_workspace_for_trust, redirect_json_block, TrustPlan,
    };
    use super::{
        describe_skip_reason, format_error_line, format_next_steps, format_redirect_summary,
        format_takeover_line, format_unredirected, format_warning, join_names,
        pnpm_lock_may_need_store_flag, pnpm_trust_rerun_reminder, sentence_case, split_sentences,
        wrap_tokens, wrap_words, TAKEOVER_INFO_CODES,
    };
    use super::{wheel_metadata_concurrency, WHEEL_METADATA_CONCURRENCY};
    use socket_patch_core::hosted::engine::REDIRECT_CANDIDATE_FILES;
    use socket_patch_core::patch::redirect::DepOverride;
    use socket_patch_core::utils::concurrent::API_CONCURRENCY_ENV;

    /// The wheel window is a patch-API window, so the documented escape
    /// hatch has to reach it: an operator behind something that caps
    /// in-flight requests per client sets `SOCKET_API_CONCURRENCY=1` and
    /// gets one artifact GET at a time here too — otherwise the capping
    /// endpoint rejects the extras and those deps land in `skipped` as
    /// `python_metadata_unavailable`. Serial: `SOCKET_*` is process-global.
    #[test]
    #[serial_test::serial]
    fn socket_api_concurrency_paces_the_wheel_metadata_window() {
        let orig = std::env::var(API_CONCURRENCY_ENV).ok();
        std::env::remove_var(API_CONCURRENCY_ENV);
        // The window's own ceiling still binds: the authenticated cap is 32,
        // but a whole wheel per in-flight request is what sizes this one.
        assert_eq!(
            wheel_metadata_concurrency(false),
            WHEEL_METADATA_CONCURRENCY
        );
        assert_eq!(wheel_metadata_concurrency(true), WHEEL_METADATA_CONCURRENCY);

        std::env::set_var(API_CONCURRENCY_ENV, "1");
        assert_eq!(wheel_metadata_concurrency(false), 1);
        assert_eq!(wheel_metadata_concurrency(true), 1);

        // A value between 1 and the ceiling lowers the window to it.
        std::env::set_var(API_CONCURRENCY_ENV, "2");
        assert_eq!(wheel_metadata_concurrency(false), 2);

        // Raising the API cap never raises this one past its own ceiling.
        std::env::set_var(API_CONCURRENCY_ENV, "32");
        assert_eq!(
            wheel_metadata_concurrency(false),
            WHEEL_METADATA_CONCURRENCY
        );

        match orig {
            Some(v) => std::env::set_var(API_CONCURRENCY_ENV, v),
            None => std::env::remove_var(API_CONCURRENCY_ENV),
        }
    }

    /// Lock-head version sniff against real pnpm 7/8/9-12 heads: quoted `'9.0'` and `'6.0'`,
    /// unquoted `5.4`; a headless/garbled lock yields `None` (hands-off).
    #[test]
    fn pnpm_lock_version_major_sniffs_real_lock_heads() {
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: '9.0'\n\nsettings:\n"),
            Some(9),
            "pnpm 9-12 emit a quoted '9.0'"
        );
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: '6.0'\n\nsettings:\n"),
            Some(6),
            "pnpm 8 emits a quoted '6.0'"
        );
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: 5.4\n\nspecifiers:\n"),
            Some(5),
            "pnpm 7 emits an unquoted 5.4"
        );
        // Not necessarily the first line (a comment/BOM-damaged head).
        assert_eq!(
            pnpm_lock_version_major("# managed\nlockfileVersion: \"9.0\"\n"),
            Some(9)
        );
        assert_eq!(
            pnpm_lock_version_major("importers:\n  .:\n"),
            None,
            "no version line → None, callers stay hands-off"
        );
        assert_eq!(
            pnpm_lock_version_major("lockfileVersion: banana\n"),
            None,
            "unparseable version → None, never a guess"
        );
    }

    /// No pnpm-workspace.yaml → create the root-only scaffold + trust key
    /// (the exact bytes the vendor backend's scaffold precedent uses, with
    /// `trustLockfile: true` in place of the override).
    #[test]
    fn plan_workspace_trust_creates_the_scaffold() {
        match plan_workspace_trust(None) {
            TrustPlan::Create(text) => {
                assert_eq!(text, "packages:\n  - '.'\ntrustLockfile: true\n");
            }
            _ => panic!("no workspace file must plan a Create"),
        }
    }

    /// An existing workspace file gains exactly one line after its last
    /// non-empty line; every other byte — including a trailing blank line and
    /// comments — is preserved so a revert can remove exactly that line.
    #[test]
    fn plan_workspace_trust_appends_preserving_user_bytes() {
        let user = "# team workspace\npackages:\n  - 'apps/*'\n  - 'libs/*'\n\ncatalog:\n  react: ^18.0.0\n";
        match plan_workspace_trust(Some(user)) {
            TrustPlan::Append(text) => {
                assert_eq!(
                    text,
                    "# team workspace\npackages:\n  - 'apps/*'\n  - 'libs/*'\n\ncatalog:\n  react: ^18.0.0\ntrustLockfile: true\n",
                    "one line appended after the last non-empty line, all user bytes intact"
                );
            }
            _ => panic!("a file without the key must plan an Append"),
        }
        // No trailing newline: the file's (lack of) trailing bytes stays put.
        match plan_workspace_trust(Some("packages:\n  - '.'")) {
            TrustPlan::Append(text) => {
                assert_eq!(text, "packages:\n  - '.'\ntrustLockfile: true");
            }
            _ => panic!("expected Append"),
        }
    }

    /// `trustLockfile: true` already present (any quoting) → nothing to do;
    /// an explicit non-true value is the USER's security call and is
    /// respected, never flipped.
    #[test]
    fn plan_workspace_trust_respects_existing_key() {
        for spelled in [
            "packages:\n  - '.'\ntrustLockfile: true\n",
            "trustLockfile: 'true'\npackages:\n  - '.'\n",
            "trustLockfile: \"true\"\n",
        ] {
            assert!(
                matches!(plan_workspace_trust(Some(spelled)), TrustPlan::AlreadyTrue),
                "already-true must be a no-op for {spelled:?}"
            );
        }
        match plan_workspace_trust(Some("packages:\n  - '.'\ntrustLockfile: false\n")) {
            TrustPlan::UserSet(value) => assert_eq!(value, "false"),
            _ => panic!("an explicit false must be respected as UserSet"),
        }
        // An INDENTED trustLockfile under some other mapping is not the
        // top-level setting pnpm reads — it must not be mistaken for one.
        match plan_workspace_trust(Some(
            "catalogMode:\n  trustLockfile: false\npackages:\n  - '.'\n",
        )) {
            TrustPlan::Append(text) => assert!(text.ends_with("trustLockfile: true\n")),
            _ => panic!("an indented key must not block the top-level append"),
        }
    }

    /// #402: every key spelling pnpm reads as `trustLockfile` is the
    /// setting — an explicit value is respected, never duplicated.
    #[test]
    fn plan_workspace_trust_reads_quoted_and_spaced_keys() {
        for spelled in [
            "packages:\n  - '.'\n\"trustLockfile\": false\n",
            "packages:\n  - '.'\ntrustLockfile : false\n",
            "packages:\n  - '.'\n'trustLockfile':   false   # opt out\n",
        ] {
            match plan_workspace_trust(Some(spelled)) {
                TrustPlan::UserSet(value) => assert_eq!(value, "false", "{spelled:?}"),
                _ => panic!("an explicit false must be respected for {spelled:?}"),
            }
        }
        for spelled in [
            "'trustLockfile': true\npackages:\n  - '.'\n",
            "\"trustLockfile\" : \"true\"\n",
            "trustLockfile: true # set by hand\n",
        ] {
            assert!(
                matches!(plan_workspace_trust(Some(spelled)), TrustPlan::AlreadyTrue),
                "already-true must be a no-op for {spelled:?}"
            );
        }
    }

    /// #400: the key goes inside the document — before a `...` marker —
    /// and shapes a line append would corrupt are never appended to.
    #[test]
    fn plan_workspace_trust_respects_the_document_shape() {
        match plan_workspace_trust(Some("packages:\n  - '.'\n...\n")) {
            TrustPlan::Append(text) => {
                assert_eq!(text, "packages:\n  - '.'\ntrustLockfile: true\n...\n")
            }
            _ => panic!("a `...`-terminated block mapping must plan an Append"),
        }
        // The refusal reason reaches the warning with both manual recoveries.
        let TrustPlan::Unsupported(why) = plan_workspace_trust(Some("{packages: [.]}\n")) else {
            panic!("a flow-style document must be refused");
        };
        let detail = socket_patch_core::hosted::guidance::pnpm_trust_workspace_unsupported_detail(
            "the hosted patch server (patch.test)",
            &why,
        );
        assert!(detail.contains("flow-style"), "{detail}");
        assert!(detail.contains("left untouched"), "{detail}");
        assert!(detail.contains("--trust-lockfile"), "{detail}");
        assert!(detail.contains("trustLockfile: true"), "{detail}");
        assert!(detail.contains("pnpm clean --lockfile"), "{detail}");
        for text in [
            "{packages: [.]}\n",
            "--- {packages: [.]}\n",
            "packages:\n  - '.'\n---\ncatalog: {}\n",
            "packages:\n  - '.'\n...\n---\ncatalog: {}\n",
        ] {
            assert!(
                !matches!(
                    plan_workspace_trust(Some(text)),
                    TrustPlan::Append(_) | TrustPlan::Create(_)
                ),
                "{text:?} must not be appended to"
            );
        }
    }

    /// The warning variants: the configured text says trust is in place and
    /// installs need no flags; the dry-run text says WOULD; both carry the
    /// whole-lock tradeoff disclosure and the don't-rebuild caution; the
    /// manual-guidance text keeps both verified recoveries. None may leak a
    /// URL authority `@` (the userinfo-stripping contract).
    #[test]
    fn pnpm_trust_warning_variants_carry_the_load_bearing_sentences() {
        let server = "the hosted patch server (patch.test)";
        for created in [true, false] {
            let configured = pnpm_trust_configured_detail(server, created, false);
            assert!(configured.contains("trustLockfile: true"), "{configured}");
            assert!(configured.contains("pnpm-workspace.yaml"), "{configured}");
            assert!(
                configured.contains("commit it alongside the lock"),
                "{configured}"
            );
            assert!(configured.contains("no extra flags"), "{configured}");
            assert!(!configured.contains("would be"), "{configured}");
            let dry = pnpm_trust_configured_detail(server, created, true);
            assert!(dry.contains("would be"), "{dry}");
            // The summary line already says it is a dry run; a marker
            // inside the noun phrase ("a new (--dry-run) pnpm-workspace")
            // read as garbled.
            assert!(!dry.contains("--dry-run"), "{dry}");
            let want = if created {
                "so `trustLockfile: true` would be written to a new pnpm-workspace.yaml — commit"
            } else {
                "so `trustLockfile: true` would be merged into the existing pnpm-workspace.yaml — commit"
            };
            assert!(dry.contains(want), "{dry}");
            for text in [&configured, &dry] {
                assert!(text.contains("ALL lockfile entries"), "{text}");
                assert!(text.contains("minimumReleaseAge"), "{text}");
                assert!(text.contains("sha512 integrity pins are"), "{text}");
                assert!(text.contains("pnpm clean --lockfile"), "{text}");
                assert!(text.contains("pnpm <=10"), "{text}");
                assert!(
                    text.contains("ERR_PNPM_TARBALL_URL_MISMATCH")
                        && text.contains("ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION"),
                    "{text}"
                );
                assert!(!text.contains('@'), "no URL authority may leak: {text}");
                assert!(!text.contains(".npmrc"), "{text}");
            }
        }
        let manual = pnpm_trust_manual_guidance(server);
        assert!(manual.contains("--trust-lockfile"), "{manual}");
        assert!(
            manual.contains("trustLockfile: true") && manual.contains("pnpm-workspace.yaml"),
            "{manual}"
        );
        assert!(manual.contains("pnpm clean --lockfile"), "{manual}");
        assert!(manual.contains("pnpm <=10"), "{manual}");
        assert!(!manual.contains('@'), "{manual}");
    }

    /// The legacy-lock (5.x/6.0 — pnpm 7/8) guidance must NEVER mention
    /// `--trust-lockfile` (pnpm 7/8 reject the flag as an unknown option) nor
    /// the `trustLockfile` setting (pnpm 7/8 ignore it); it must say installs
    /// work unchanged with no trust step, keep the don't-regenerate caution,
    /// and leak no URL authority.
    #[test]
    fn pnpm_trust_legacy_detail_never_recommends_the_trust_flag() {
        let server = "the hosted patch server (patch.test)";
        let legacy = pnpm_trust_legacy_detail(server);
        assert!(
            !legacy.contains("trust-lockfile"),
            "pnpm 7/8 reject --trust-lockfile as an unknown option: {legacy}"
        );
        assert!(
            !legacy.contains("trustLockfile"),
            "pnpm 7/8 ignore the setting — recommending it is noise: {legacy}"
        );
        assert!(legacy.contains("pnpm 1–8"), "{legacy}");
        assert!(legacy.contains("no trust step"), "{legacy}");
        // The vulnerable-reinstall caution survives the split: regenerating
        // the lock still silently discards the redirect.
        assert!(legacy.contains("Do NOT regenerate"), "{legacy}");
        assert!(legacy.contains("vulnerable upstream"), "{legacy}");
        assert!(!legacy.contains('@'), "no URL authority may leak: {legacy}");
    }

    /// A PRESENT-but-unreadable pnpm-workspace.yaml must classify as `Err` —
    /// never as `Ok(None)`, which plans a Create that overwrites the user's
    /// file (destroying their `packages:` globs). Absent stays `Ok(None)`
    /// (the only Create-safe state); readable stays `Ok(Some)`.
    #[test]
    fn read_workspace_for_trust_distinguishes_unreadable_from_absent() {
        let tmp = tempfile::tempdir().unwrap();
        // Absent → Ok(None).
        assert!(matches!(
            read_workspace_for_trust(&tmp.path().join("pnpm-workspace.yaml")),
            Ok(None)
        ));
        // Readable → Ok(Some(text)).
        let readable = tmp.path().join("readable.yaml");
        std::fs::write(&readable, "packages:\n  - '.'\n").unwrap();
        assert!(matches!(
            read_workspace_for_trust(&readable),
            Ok(Some(text)) if text.contains("packages")
        ));
        // Invalid UTF-8 → Err(InvalidData), cross-platform.
        let invalid = tmp.path().join("invalid.yaml");
        std::fs::write(&invalid, b"packages:\n  - 'apps/*'\n\xff\xfe\x80").unwrap();
        let err = read_workspace_for_trust(&invalid)
            .expect_err("invalid UTF-8 must classify as Err, never as absent→Create");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // chmod 000 (unix): PermissionDenied → Err. Root ignores mode bits,
        // so only the failing-read outcome is asserted strictly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = tmp.path().join("locked.yaml");
            std::fs::write(&locked, "packages:\n  - '.'\n").unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            match read_workspace_for_trust(&locked) {
                Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied),
                // Running as root: mode bits don't apply; the invalid-UTF-8
                // case above already proved the Err classification.
                Ok(Some(_)) => {}
                Ok(None) => panic!("an unreadable file must never classify as absent"),
            }
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        // The fallback detail names the file, the error, and both manual
        // recoveries — and never plans a write (it returns prose only).
        let server = "the hosted patch server (patch.test)";
        let detail = pnpm_trust_workspace_unreadable_detail(
            server,
            &std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied"),
        );
        assert!(detail.contains("pnpm-workspace.yaml"), "{detail}");
        assert!(detail.contains("could not be read"), "{detail}");
        assert!(detail.contains("permission denied"), "{detail}");
        assert!(detail.contains("left untouched"), "{detail}");
        assert!(
            detail.contains("--trust-lockfile") && detail.contains("trustLockfile: true"),
            "{detail}"
        );
        assert!(detail.contains("pnpm clean --lockfile"), "{detail}");
    }

    /// The early Pipenv probe start is exact: whenever it fires, the
    /// post-fetch gate is true for EVERY outcome of the wheel metadata
    /// fetch (any subset of the fetched wheels' URLs dropped).
    #[test]
    fn pipenv_probe_certain_implies_the_post_fetch_gate() {
        use super::pipenv_probe_certain;
        use socket_patch_core::patch::redirect::pipenv_lock_targets;

        let lock = serde_json::json!({
            "_meta": {"pipfile-spec": 6, "hash": {"sha256": "x"}},
            "default": {"urllib3": {"version": "==1.26.18"}, "six": {"version": "==1.16.0"}},
            "develop": {},
        });
        let files = std::collections::BTreeMap::from([(
            "Pipfile.lock".to_string(),
            serde_json::to_string_pretty(&lock).unwrap(),
        )]);
        let names = ["urllib3", "Six", "requests", "idna"];
        let urls = ["u0", "u1", "u2", "u3"];
        let (mut fired, mut held) = (0, 0);
        for seed in 0..4096u64 {
            // Deterministic spread over names, ecosystems, URLs and the
            // fetched-URL set.
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut next = |n: u64| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                (x.wrapping_mul(0x2545_F491_4F6C_DD1D) % n) as usize
            };
            let candidates: Vec<DepOverride> = (0..next(4))
                .map(|_| {
                    let mut dep = npm_override(urls[next(4)]);
                    dep.name = names[next(4)].to_string();
                    if next(4) != 0 {
                        dep.ecosystem = "pypi".to_string();
                    }
                    dep
                })
                .collect();
            let fetched: Vec<&str> = urls.iter().copied().filter(|_| next(2) == 0).collect();
            if !pipenv_probe_certain(&files, candidates.iter(), fetched.iter().copied()) {
                held += 1;
                continue;
            }
            fired += 1;
            for mask in 0..(1u32 << fetched.len()) {
                let dropped: Vec<&str> = fetched
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, url)| *url)
                    .collect();
                let kept: Vec<DepOverride> = candidates
                    .iter()
                    .filter(|dep| !dropped.contains(&dep.artifact_url.as_str()))
                    .cloned()
                    .collect();
                assert!(
                    pipenv_lock_targets(&files, &kept),
                    "seed {seed} mask {mask}"
                );
            }
        }
        assert!(fired > 100 && held > 100, "{fired}/{held}");
    }

    /// Without a Pipfile.lock the gate is false whatever the candidates
    /// are, exactly as `pipenv_lock_targets` answers it.
    #[test]
    fn pipenv_probe_certain_is_false_without_a_pipfile_lock() {
        use super::pipenv_probe_certain;
        use socket_patch_core::patch::redirect::pipenv_lock_targets;

        let files =
            std::collections::BTreeMap::from([("package-lock.json".to_string(), "{}".to_string())]);
        let mut pypi = npm_override("u1");
        pypi.ecosystem = "pypi".to_string();
        pypi.name = "urllib3".to_string();
        let candidates = [npm_override("u0"), pypi];

        assert!(!pipenv_probe_certain(
            &files,
            candidates.iter(),
            std::iter::empty()
        ));
        assert!(!pipenv_lock_targets(&files, &candidates));
        assert!(!pipenv_probe_certain(
            &std::collections::BTreeMap::new(),
            candidates.iter(),
            std::iter::empty()
        ));
    }

    fn npm_override(artifact_url: &str) -> DepOverride {
        DepOverride {
            ecosystem: "npm".to_string(),
            name: "in-proc-heal".to_string(),
            namespace: None,
            version: "1.0.0".to_string(),
            token: "tok".to_string(),
            patch_uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            artifact_url: artifact_url.to_string(),
            registry_override: None,
            integrity: Default::default(),
        }
    }

    /// Heal-on-rerun probe: a root lock ALREADY
    /// carrying a granted hosted artifact URL from an earlier run — raw,
    /// `\/`-escaped, or percent-encoded — is detected even when this run
    /// spliced nothing, so the trust config can be (re)planned for a project
    /// that missed it (opted-out first run, or a crash between the lock
    /// write and the workspace write). A pristine lock, and a lock whose
    /// only match is a NON-npm override's URL, must stay undetected.
    #[test]
    fn pnpm_lock_carries_hosted_redirect_detects_prior_run_splices() {
        let url = "http://patch.test/patch/npm/in-proc-heal/1.0.0/tok/uuid/in-proc-heal-1.0.0.tgz";
        let mut cargo = npm_override("http://patch.test/crates/heal-1.0.0.crate");
        cargo.ecosystem = "cargo".to_string();
        let overrides = vec![npm_override(url), cargo];

        // The exact splice shape an earlier run wrote.
        let redirected = format!(
            "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}\n"
        );
        assert!(pnpm_lock_carries_hosted_redirect(&redirected, &overrides));

        // The percent-encoded spelling counts too (same predicate set as the
        // confirmation probe).
        let encoded = socket_patch_core::utils::uri::encode_uri_component(url);
        let encoded_lock = format!("lockfileVersion: '9.0'\npackages:\n  x: {encoded}\n");
        assert!(pnpm_lock_carries_hosted_redirect(&encoded_lock, &overrides));

        // Pristine lock: nothing to heal.
        assert!(!pnpm_lock_carries_hosted_redirect(
            "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
             resolution: {integrity: sha512-UPSTREAM==}\n",
            &overrides
        ));

        // A non-npm override's URL in the text is not a pnpm redirect.
        assert!(!pnpm_lock_carries_hosted_redirect(
            "lockfileVersion: '9.0'\n# http://patch.test/crates/heal-1.0.0.crate\n",
            &overrides
        ));

        // No grants at all → never engages.
        assert!(!pnpm_lock_carries_hosted_redirect(&redirected, &[]));
    }

    /// Heal-on-rerun gate (`pnpm_heal_root`): a re-scan that spliced NOTHING
    /// over a pre-redirected root v9 lock with a MISSING pnpm-workspace.yaml
    /// must engage the trust block (heal → plan Create), while a legacy
    /// pre-redirected lock, an unparseable-version lock, a pristine lock,
    /// and a root lock this run DID splice all stay out of the heal path.
    #[test]
    fn pnpm_heal_root_re_engages_trust_planning_for_pre_redirected_v9_locks() {
        let url = "http://patch.test/patch/npm/in-proc-heal/1.0.0/tok/uuid/in-proc-heal-1.0.0.tgz";
        let overrides = vec![npm_override(url)];
        let redirected_v9 = format!(
            "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}\n"
        );

        // The heal scenario: nothing spliced this run, root lock already
        // redirected, workspace file missing → the gate engages and the
        // planning it feeds produces the Create.
        let healed = pnpm_heal_root(false, Some(&redirected_v9), &overrides)
            .expect("a pre-redirected root v9 lock must re-engage the trust block");
        assert_eq!(healed, &redirected_v9);
        assert!(
            matches!(plan_workspace_trust(None), TrustPlan::Create(_)),
            "with the workspace file missing, the healed run must plan the Create"
        );

        // Root lock spliced THIS run: the splice path covers it — no heal.
        assert!(pnpm_heal_root(true, Some(&redirected_v9), &overrides).is_none());

        // Pristine v9 lock (no redirect landed): nothing to heal.
        let pristine = "lockfileVersion: '9.0'\n\npackages:\n  in-proc-heal@1.0.0:\n    \
                        resolution: {integrity: sha512-UPSTREAM==}\n"
            .to_string();
        assert!(pnpm_heal_root(false, Some(&pristine), &overrides).is_none());

        // Legacy pre-redirected lock: pnpm 7/8 need no trust config — the
        // heal gate must not drag a 5.x/6.0 lock into the v9 auto-config.
        let redirected_v6 = format!(
            "lockfileVersion: '6.0'\n\npackages:\n  /in-proc-heal@1.0.0:\n    \
             resolution: {{integrity: sha512-PATCHED==, tarball: {url}}}\n"
        );
        assert!(pnpm_heal_root(false, Some(&redirected_v6), &overrides).is_none());

        // Unparseable version: fail closed, hands off.
        let headless = format!("packages:\n  x:\n    resolution: {{tarball: {url}}}\n");
        assert!(pnpm_heal_root(false, Some(&headless), &overrides).is_none());

        // No root lock at all (e.g. Rush): nothing to heal.
        assert!(pnpm_heal_root(false, None, &overrides).is_none());
    }

    /// The classic scan object `run` builds for the `--json` path with ≥1
    /// discovered package (scannedPackages/totalPatches/… + the `packages`
    /// enumeration). Mirrors the `serde_json::json!` in `scan::run`.
    fn classic_scan_result() -> serde_json::Value {
        serde_json::json!({
            "status": "success",
            "scannedPackages": 3,
            "lockfileOnlyPackages": 0,
            "packagesWithPatches": 1,
            "totalPatches": 2,
            "freePatches": 2,
            "paidPatches": 0,
            "canAccessPaidPatches": false,
            "packages": [
                { "purl": "pkg:npm/minimist@1.2.2", "patches": [ { "uuid": "abc-123" } ] }
            ],
            "updates": [],
        })
    }

    #[test]
    fn hosted_json_envelope_nests_redirect_into_classic_scan_object() {
        // With ≥1 package, the hosted `--json` envelope must carry the SAME
        // top-level scan keys as a zero-discovery / non-hosted scan AND nest
        // the redirect summary under `redirect`. Built through the ONE
        // spelling of the block (`run`'s zero-discovery arm uses the same
        // helper).
        let redirect = redirect_json_block(
            1,
            vec!["package-lock.json".to_string()],
            Vec::new(),
            vec![prune_ignored_warning()],
            false,
        );
        let envelope = build_redirect_json_envelope(Some(classic_scan_result()), redirect);

        // Classic scan keys survive.
        assert_eq!(envelope["status"], "success");
        assert_eq!(envelope["scannedPackages"], 3);
        assert_eq!(envelope["packagesWithPatches"], 1);
        assert_eq!(envelope["totalPatches"], 2);
        assert_eq!(envelope["freePatches"], 2);
        assert_eq!(envelope["paidPatches"], 0);
        assert_eq!(envelope["canAccessPaidPatches"], false);
        assert!(envelope["updates"].is_array());

        // Per-package / patch-uuid enumeration is present.
        assert!(envelope["packages"].is_array());
        assert_eq!(envelope["packages"][0]["purl"], "pkg:npm/minimist@1.2.2");
        assert_eq!(envelope["packages"][0]["patches"][0]["uuid"], "abc-123");

        // Redirect result is NESTED, preserving every sub-field, not replacing
        // the whole envelope.
        let r = &envelope["redirect"];
        assert!(r.is_object());
        assert_eq!(r["mode"], "hosted");
        assert_eq!(r["redirected"], 1);
        assert_eq!(r["rewrittenFiles"][0], "package-lock.json");
        assert!(r["skipped"].is_array());
        assert!(r["warnings"].is_array());
        assert_eq!(r["dryRun"], false);
    }

    // ── gem stale-install probe (redirect_gem_stale_install) ──────────
    //
    // Defect facts + verified/disproven remedies live in CLI_CONTRACT.md's
    // "Gem stale-install guard" section; these tests pin the probe's
    // judgment rules and the warning wording's load-bearing parts.

    use std::path::PathBuf;

    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
    use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};

    const GEM_UUID: &str = "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d";
    const GEM_PURL: &str = "pkg:gem/stale-unit@1.0.0";
    const GEM_LEAF: &str = "stale-unit-1.0.0";
    const GEM_UPSTREAM: &[u8] = b"module StaleUnit; STATUS = :vulnerable; end\n";
    const GEM_PATCHED: &[u8] = b"module StaleUnit; STATUS = :patched; end\n";

    fn gem_record() -> PatchRecord {
        gem_record_with(GEM_UUID, GEM_UPSTREAM, GEM_PATCHED)
    }

    fn gem_record_with(uuid: &str, before: &[u8], after: &[u8]) -> PatchRecord {
        let mut files = std::collections::HashMap::new();
        files.insert(
            "lib/stale_unit.rb".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(before),
                after_hash: compute_git_sha256_from_bytes(after),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2026-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: std::collections::HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: "free".to_string(),
        }
    }

    /// Bundler's deployment gem home under `cwd`, built COMPONENT-WISE —
    /// the same join operations the crawler uses, so `display()` matches
    /// the production paths byte-for-byte on every platform (embedded
    /// `a/b/c` literals diverge from Windows' backslash joins).
    fn gem_home(cwd: &std::path::Path) -> PathBuf {
        cwd.join("vendor").join("bundle").join("ruby").join("3.3.0")
    }

    /// Materialize the gem in the deployment layout (installed dir + cached
    /// .gem + specifications entry — what a real `bundle install` leaves).
    /// Returns the installed gem dir.
    fn materialize_gem(cwd: &std::path::Path, lib: &[u8]) -> PathBuf {
        let home = gem_home(cwd);
        let gem_dir = home.join("gems").join(GEM_LEAF);
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
        std::fs::write(gem_dir.join("lib").join("stale_unit.rb"), lib).unwrap();
        std::fs::create_dir_all(home.join("cache")).unwrap();
        std::fs::write(
            home.join("cache").join(format!("{GEM_LEAF}.gem")),
            b"upstream .gem",
        )
        .unwrap();
        std::fs::create_dir_all(home.join("specifications")).unwrap();
        std::fs::write(
            home.join("specifications")
                .join(format!("{GEM_LEAF}.gemspec")),
            b"#",
        )
        .unwrap();
        gem_dir
    }

    fn one_confirmed() -> Vec<(String, String)> {
        vec![(GEM_PURL.to_string(), GEM_UUID.to_string())]
    }

    fn one_record() -> std::collections::BTreeMap<String, PatchRecord> {
        let mut records = std::collections::BTreeMap::new();
        records.insert(GEM_PURL.to_string(), gem_record());
        records
    }

    /// Probe invocation with the default surface (project-local discovery,
    /// no artifact shas) — tests override the knobs they exercise.
    /// `records` is the merged map production hands over (this run's
    /// fetched records plus the ledger's persisted ones).
    async fn probe(
        cwd: &std::path::Path,
        confirmed: &[(String, String)],
        records: &std::collections::BTreeMap<String, PatchRecord>,
    ) -> super::StaleInstallOutcome {
        gem_stale_install_warnings(
            cwd,
            false,
            None,
            confirmed,
            records,
            &std::collections::BTreeMap::new(),
        )
        .await
    }

    fn detail_of(w: &serde_json::Value) -> &str {
        assert_eq!(w["code"], "redirect_gem_stale_install");
        w["detail"].as_str().expect("detail is a string")
    }

    /// PROJECT-LOCAL flavor: names the purl and all three stale paths —
    /// each built with the same joins production uses, so this holds on
    /// Windows' backslash-joined paths too — steers away from the
    /// empirically disproven `--force`/`--redownload`, and prescribes the
    /// verified removal + `bundle install` remedy.
    #[test]
    fn gem_stale_install_warning_project_local_names_paths_and_remedy() {
        let cwd = PathBuf::from("proj");
        let home = gem_home(&cwd);
        let gem_dir = home.join("gems").join(GEM_LEAF);
        let w = gem_stale_install_warning(GEM_PURL, &gem_dir, GEM_LEAF, &cwd, None);
        let detail = detail_of(&w);
        assert!(detail.contains(GEM_PURL), "{detail}");
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
        let cache = home.join("cache").join(format!("{GEM_LEAF}.gem"));
        let spec = home
            .join("specifications")
            .join(format!("{GEM_LEAF}.gemspec"));
        assert!(detail.contains(&cache.display().to_string()), "{detail}");
        assert!(detail.contains(&spec.display().to_string()), "{detail}");
        assert!(detail.contains("UNPATCHED"), "{detail}");
        assert!(
            detail.contains("--force") && detail.contains("--redownload"),
            "the disproven flags must be steered away from: {detail}"
        );
        assert!(
            detail.contains("Remove the stale materialization")
                && detail.contains("`bundle install`"),
            "the verified remedy must be prescribed: {detail}"
        );
        assert!(
            !detail.contains("shared gem home"),
            "a project-local dir must not get the shared-home caveat: {detail}"
        );
    }

    /// SHARED-HOME flavor: a materialization outside the project must NOT
    /// get an unconditional delete prescription — the home is shared by
    /// every project on the machine — and must prefer the project-local
    /// bundle-path migration instead.
    #[test]
    fn gem_stale_install_warning_shared_home_prefers_local_path_over_deletion() {
        let cwd = PathBuf::from("proj");
        let home = PathBuf::from("shared-gem-home").join("ruby").join("3.3.0");
        let gem_dir = home.join("gems").join(GEM_LEAF);
        let w = gem_stale_install_warning(GEM_PURL, &gem_dir, GEM_LEAF, &cwd, None);
        let detail = detail_of(&w);
        assert!(detail.contains("shared gem home"), "{detail}");
        assert!(
            detail.contains("bundle config set --local path"),
            "the shared flavor must prefer the project-local migration: {detail}"
        );
        assert!(
            detail.contains("only if no other project relies"),
            "shared files must never get an unconditional delete: {detail}"
        );
        assert!(
            !detail.contains("Remove the stale materialization —"),
            "the unconditional delete-list phrasing is project-local only: {detail}"
        );
        // The paths are still named (inside the conditional clause).
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
    }

    /// A committed project `vendor/cache` archive passed by the caller joins
    /// the delete list — bundler installs from it in preference to fetching,
    /// so a remedy that leaves it behind silently reinstates stale bytes.
    #[test]
    fn gem_stale_install_warning_folds_project_cache_into_delete_list() {
        let cwd = PathBuf::from("proj");
        let gem_dir = gem_home(&cwd).join("gems").join(GEM_LEAF);
        let committed = cwd
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        let w = gem_stale_install_warning(GEM_PURL, &gem_dir, GEM_LEAF, &cwd, Some(&committed));
        let detail = detail_of(&w);
        assert!(
            detail.contains(&committed.display().to_string()),
            "the committed cache archive must be in the delete list: {detail}"
        );
    }

    /// Staleness needs POSITIVE evidence — readable bytes hashing to
    /// something other than afterHash. Missing files, unreadable paths
    /// (a directory where a file is expected — the same NotFound that IO
    /// errors fold into), and absent new-files are never evidence: a
    /// transiently unreadable file in a patched install must not produce
    /// a delete prescription.
    #[tokio::test]
    async fn installed_stale_positive_evidence_requires_readable_mismatched_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let record = gem_record();

        // Pristine upstream bytes → evidence.
        let upstream = tmp.path().join("upstream");
        std::fs::create_dir_all(upstream.join("lib")).unwrap();
        std::fs::write(upstream.join("lib").join("stale_unit.rb"), GEM_UPSTREAM).unwrap();
        assert!(installed_stale_positive_evidence(&upstream, &record).await);

        // Tampered bytes (neither hash) → evidence.
        let tampered = tmp.path().join("tampered");
        std::fs::create_dir_all(tampered.join("lib")).unwrap();
        std::fs::write(tampered.join("lib").join("stale_unit.rb"), b"other").unwrap();
        assert!(installed_stale_positive_evidence(&tampered, &record).await);

        // Patched bytes → no evidence.
        let patched = tmp.path().join("patched");
        std::fs::create_dir_all(patched.join("lib")).unwrap();
        std::fs::write(patched.join("lib").join("stale_unit.rb"), GEM_PATCHED).unwrap();
        assert!(!installed_stale_positive_evidence(&patched, &record).await);

        // Missing file → no evidence (never a guess).
        let hollow = tmp.path().join("hollow");
        std::fs::create_dir_all(hollow.join("lib")).unwrap();
        assert!(!installed_stale_positive_evidence(&hollow, &record).await);

        // A DIRECTORY at the file path (the unreadable-NotFound class) →
        // no evidence.
        let blocked = tmp.path().join("blocked");
        std::fs::create_dir_all(blocked.join("lib").join("stale_unit.rb")).unwrap();
        assert!(!installed_stale_positive_evidence(&blocked, &record).await);

        // Absent new-file (empty beforeHash routes to Ready with NO
        // current_hash) → no evidence.
        let mut new_file = gem_record();
        new_file
            .files
            .get_mut("lib/stale_unit.rb")
            .expect("fixture file entry")
            .before_hash = String::new();
        assert!(!installed_stale_positive_evidence(&hollow, &new_file).await);
    }

    /// The probe end to end over a real deployment layout: a STALE
    /// materialization of a confirmed gem redirect produces exactly one
    /// warning naming the on-disk paths and lands the purl in
    /// `stale_purls` (the same-run `--vex` exclusion set); already-patched,
    /// missing-record, zero-file-record, missing-file, and non-gem inputs
    /// all stay silent; and the probe never touches the tree.
    #[tokio::test]
    async fn gem_stale_install_warnings_probe_end_to_end() {
        let confirmed = one_confirmed();
        let records = one_record();

        // STALE: upstream bytes materialized → one warning, real paths named.
        let stale = tempfile::tempdir().unwrap();
        let gem_dir = materialize_gem(stale.path(), GEM_UPSTREAM);
        let out = probe(stale.path(), &confirmed, &records).await;
        assert_eq!(
            out.warnings.len(),
            1,
            "one stale materialization, one warning"
        );
        let detail = detail_of(&out.warnings[0]);
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
        let home = gem_home(stale.path());
        let cache = home.join("cache").join(format!("{GEM_LEAF}.gem"));
        let spec = home
            .join("specifications")
            .join(format!("{GEM_LEAF}.gemspec"));
        assert!(detail.contains(&cache.display().to_string()), "{detail}");
        assert!(detail.contains(&spec.display().to_string()), "{detail}");
        assert_eq!(
            out.stale_purls,
            std::collections::BTreeSet::from([GEM_PURL.to_string()]),
            "the stale purl must be returned structurally for the vex exclusion"
        );
        // Read-only: the stale tree is intact after the probe.
        assert_eq!(
            std::fs::read(gem_dir.join("lib").join("stale_unit.rb")).unwrap(),
            GEM_UPSTREAM
        );
        assert!(cache.is_file() && spec.is_file(), "probe must not delete");

        // PATCHED: every record file at afterHash → silent (the
        // cannot-false-positive contract; agent-mode applies leave exactly
        // this state with an upstream cache .gem beside it).
        let patched = tempfile::tempdir().unwrap();
        materialize_gem(patched.path(), GEM_PATCHED);
        let out = probe(patched.path(), &confirmed, &records).await;
        assert!(out.warnings.is_empty(), "patched install must never warn");
        assert!(out.stale_purls.is_empty());

        // MISSING RECORD (fresh AND ledger): no afterHash map, no judgment.
        let none = std::collections::BTreeMap::new();
        let out = probe(stale.path(), &confirmed, &none).await;
        assert!(out.warnings.is_empty());

        // ZERO-FILE RECORD: nothing to hash → silent, never a guess.
        let mut hollow_records = std::collections::BTreeMap::new();
        let mut hollow = gem_record();
        hollow.files.clear();
        hollow_records.insert(GEM_PURL.to_string(), hollow);
        let out = probe(stale.path(), &confirmed, &hollow_records).await;
        assert!(out.warnings.is_empty());

        // NON-GEM confirmed purls never engage the probe.
        let npm_confirmed = vec![("pkg:npm/x@1.0.0".to_string(), GEM_UUID.to_string())];
        let out = probe(stale.path(), &npm_confirmed, &records).await;
        assert!(out.warnings.is_empty());
    }

    /// FALSE-POSITIVE hardening: an install whose record file is MISSING
    /// (or unreadable — same NotFound class) is not positive evidence, so
    /// the probe stays quiet instead of prescribing deletion on a tree it
    /// could not actually read.
    #[tokio::test]
    async fn gem_stale_probe_never_warns_without_positive_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let gem_dir = materialize_gem(tmp.path(), GEM_UPSTREAM);
        std::fs::remove_file(gem_dir.join("lib").join("stale_unit.rb")).unwrap();
        let out = probe(tmp.path(), &one_confirmed(), &one_record()).await;
        assert!(
            out.warnings.is_empty(),
            "a missing/unreadable file is never staleness evidence: {:?}",
            out.warnings
        );
        assert!(out.stale_purls.is_empty());
    }

    /// Records are found BY UUID — the fetch key, stable across purl
    /// spellings — so a record keyed under a qualified purl still judges
    /// the bare confirmed purl.
    #[tokio::test]
    async fn gem_stale_probe_record_lookup_is_uuid_keyed() {
        let stale = tempfile::tempdir().unwrap();
        materialize_gem(stale.path(), GEM_UPSTREAM);
        let mut records = std::collections::BTreeMap::new();
        records.insert(format!("{GEM_PURL}?platform=ruby"), gem_record());
        let out = probe(stale.path(), &one_confirmed(), &records).await;
        assert_eq!(
            out.warnings.len(),
            1,
            "the uuid lookup must find the record under any purl spelling"
        );
    }

    /// RE-FIRE guarantee: when this run's record fetch failed (no fresh
    /// records), the merged map the caller hands over still carries the
    /// redirect ledger's PERSISTED record under whatever purl key the
    /// ledger used — and the probe's uuid lookup judges from it, so a
    /// transient /patches/view failure cannot silently retire the warning
    /// while the stale materialization is still there.
    #[tokio::test]
    async fn gem_stale_probe_judges_from_persisted_ledger_records() {
        let stale = tempfile::tempdir().unwrap();
        materialize_gem(stale.path(), GEM_UPSTREAM);
        // Persisted under the API's qualified spelling, not the confirmed
        // purl: only the uuid links them.
        let mut ledger_only = std::collections::BTreeMap::new();
        ledger_only.insert(format!("{GEM_PURL}?platform=ruby"), gem_record());
        let out = probe(stale.path(), &one_confirmed(), &ledger_only).await;
        assert_eq!(
            out.warnings.len(),
            1,
            "the ledger records must keep the warning firing across flaky fetches"
        );
    }

    /// `--global-prefix` discovery parity: the probe threads the run's
    /// global surface into the crawler exactly like scan's own discovery,
    /// so a stale materialization in the prefix store is found too.
    #[tokio::test]
    async fn gem_stale_probe_honors_global_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let cwd = tmp.path().join("proj");
        std::fs::create_dir_all(&cwd).unwrap();
        // The prefix IS a gems dir (the crawler's global_prefix contract).
        let store = tmp.path().join("prefix-store").join("gems");
        let gem_dir = store.join(GEM_LEAF);
        std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
        std::fs::write(gem_dir.join("lib").join("stale_unit.rb"), GEM_UPSTREAM).unwrap();
        let out = gem_stale_install_warnings(
            &cwd,
            true,
            Some(store.clone()),
            &one_confirmed(),
            &one_record(),
            &std::collections::BTreeMap::new(),
        )
        .await;
        assert_eq!(
            out.warnings.len(),
            1,
            "the global-prefix store must be probed like scan's own discovery"
        );
        let detail = detail_of(&out.warnings[0]);
        assert!(detail.contains(&gem_dir.display().to_string()), "{detail}");
        assert!(
            detail.contains("shared gem home"),
            "a store outside the project gets the shared-home flavor: {detail}"
        );
    }

    /// PLATFORM-VARIANT guard: multiple confirmed purls of one gem resolve
    /// to the same installed dir; when ANY of their records judges the dir
    /// fully patched, the dir is patched — the sibling record's stale
    /// judgment must not warn.
    #[tokio::test]
    async fn gem_stale_probe_variant_records_stay_quiet_when_any_judges_patched() {
        const UUID_B: &str = "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e";
        let tmp = tempfile::tempdir().unwrap();
        // On disk: content X.
        materialize_gem(tmp.path(), GEM_PATCHED);
        // Record A (uuid GEM_UUID): afterHash == hash(X) → judges PATCHED.
        // Record B (uuid B): beforeHash == hash(X), different afterHash →
        // judges positive-stale.
        let mut records = std::collections::BTreeMap::new();
        records.insert(GEM_PURL.to_string(), gem_record());
        records.insert(
            format!("{GEM_PURL}?platform=java"),
            gem_record_with(UUID_B, GEM_PATCHED, b"some other patched bytes"),
        );
        let confirmed = vec![
            (GEM_PURL.to_string(), GEM_UUID.to_string()),
            (format!("{GEM_PURL}?platform=java"), UUID_B.to_string()),
        ];
        let out = probe(tmp.path(), &confirmed, &records).await;
        assert!(
            out.warnings.is_empty(),
            "any variant judging the dir patched must suppress the warning: {:?}",
            out.warnings
        );
        assert!(out.stale_purls.is_empty());
    }

    /// Committed `vendor/cache` handling, folded flavor: a stale install
    /// whose project also commits `vendor/cache/<leaf>.gem` gets that
    /// archive in the SAME delete list — bundler installs from it first,
    /// so a remedy that leaves it behind silently reinstates stale bytes.
    #[tokio::test]
    async fn gem_stale_probe_folds_committed_vendor_cache_into_the_remedy() {
        let tmp = tempfile::tempdir().unwrap();
        materialize_gem(tmp.path(), GEM_UPSTREAM);
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, b"upstream archive bytes").unwrap();
        let mut shas = std::collections::BTreeMap::new();
        shas.insert(
            ("stale-unit".to_string(), "1.0.0".to_string()),
            "0".repeat(64), // the patched artifact's sha — differs
        );
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        assert_eq!(out.warnings.len(), 1, "one warning, cache folded in");
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&committed.display().to_string()),
            "the committed archive must join the delete list: {detail}"
        );
    }

    /// Committed `vendor/cache` handling, standalone flavor: a fresh
    /// checkout (no installed dir at all) whose committed archive hashes to
    /// something other than the patched artifact still warns — bundler
    /// installs from vendor/cache first, so that checkout materializes
    /// stale bytes forever. The PATCHED archive, an unknown artifact sha,
    /// and an absent archive all stay quiet.
    #[tokio::test]
    async fn gem_stale_probe_warns_on_stale_committed_vendor_cache_without_install() {
        use sha2::{Digest, Sha256};
        let tmp = tempfile::tempdir().unwrap();
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        let stale_bytes: &[u8] = b"upstream archive bytes";
        std::fs::write(&committed, stale_bytes).unwrap();
        let key = ("stale-unit".to_string(), "1.0.0".to_string());
        let mut shas = std::collections::BTreeMap::new();
        shas.insert(key.clone(), "0".repeat(64));

        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        assert_eq!(out.warnings.len(), 1, "stale committed cache must warn");
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&committed.display().to_string()),
            "{detail}"
        );
        assert!(detail.contains("bundle cache"), "{detail}");
        assert_eq!(
            out.stale_purls,
            std::collections::BTreeSet::from([GEM_PURL.to_string()])
        );

        // The PATCHED archive (sha matches) is a healthy commit — quiet.
        let mut patched_shas = std::collections::BTreeMap::new();
        patched_shas.insert(key, hex::encode(Sha256::digest(stale_bytes)));
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &patched_shas,
        )
        .await;
        assert!(out.warnings.is_empty(), "a patched archive must not warn");

        // No artifact sha known → no sound judgment → quiet.
        let out = probe(tmp.path(), &one_confirmed(), &one_record()).await;
        assert!(out.warnings.is_empty(), "unknown sha must never guess");

        // Archive absent → quiet.
        std::fs::remove_file(&committed).unwrap();
        let mut shas = std::collections::BTreeMap::new();
        shas.insert(
            ("stale-unit".to_string(), "1.0.0".to_string()),
            "0".repeat(64),
        );
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        assert!(out.warnings.is_empty());
    }

    /// #483: bundler's cache dir is a setting (`bundle config set --local
    /// cache_path vendor/gems` → `BUNDLE_CACHE_PATH` in `.bundle/config`).
    /// A committed archive at the CONFIGURED path is what `bundle install`
    /// installs from, so it warns standalone (fresh checkout, no installed
    /// dir) and joins a stale install's delete list (folded) — and the
    /// default `vendor/cache`, which bundler no longer reads, is ignored.
    #[tokio::test]
    async fn gem_stale_probe_follows_the_configured_bundle_cache_path() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".bundle")).unwrap();
        std::fs::write(
            tmp.path().join(".bundle/config"),
            "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_CACHE_PATH: \"vendor/gems\"\n",
        )
        .unwrap();
        let configured = tmp
            .path()
            .join("vendor")
            .join("gems")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(configured.parent().unwrap()).unwrap();
        std::fs::write(&configured, b"upstream archive bytes").unwrap();
        let mut shas = std::collections::BTreeMap::new();
        shas.insert(
            ("stale-unit".to_string(), "1.0.0".to_string()),
            "0".repeat(64), // the patched artifact's sha — differs
        );

        // Standalone: a fresh checkout with only the configured cache.
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        assert_eq!(out.warnings.len(), 1, "configured cache must warn");
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&configured.display().to_string()),
            "{detail}"
        );
        assert_eq!(
            out.stale_purls,
            std::collections::BTreeSet::from([GEM_PURL.to_string()]),
            "the in-run VEX must withhold the attestation"
        );

        // Folded: a stale install beside it gets the configured archive in
        // its delete list, in one warning.
        materialize_gem(tmp.path(), GEM_UPSTREAM);
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        assert_eq!(out.warnings.len(), 1, "one warning, cache folded in");
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&configured.display().to_string()),
            "the configured archive must join the delete list: {detail}"
        );

        // A leftover default vendor/cache archive is not what bundler reads
        // once cache_path moves it: it neither warns nor joins the list.
        std::fs::remove_file(&configured).unwrap();
        let default = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(default.parent().unwrap()).unwrap();
        std::fs::write(&default, b"upstream archive bytes").unwrap();
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        assert_eq!(out.warnings.len(), 1, "the stale install still warns");
        let detail = detail_of(&out.warnings[0]);
        assert!(
            !detail.contains(&default.display().to_string()),
            "vendor/cache is not bundler's cache dir here: {detail}"
        );
    }

    /// Committed `vendor/cache` fold, UNKNOWN-sha arm (`_ => false`): when
    /// the run carries NO artifact sha for the gem (empty shas map — e.g. a
    /// reference served without a gem checksum), a committed archive beside
    /// a stale install must STILL be folded into the delete list. Removal is
    /// safe either way (`bundle install` refetches), so "unknown" must never
    /// downgrade to "proven patched" and leave the archive to silently
    /// reinstate the stale bytes.
    #[tokio::test]
    async fn gem_stale_probe_folds_committed_cache_with_unknown_artifact_sha() {
        let tmp = tempfile::tempdir().unwrap();
        materialize_gem(tmp.path(), GEM_UPSTREAM);
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, b"upstream archive bytes").unwrap();

        // `probe()` passes an EMPTY gem_artifact_shas map: the
        // (None, Some(_)) pair must take the fold-anyway arm.
        let out = probe(tmp.path(), &one_confirmed(), &one_record()).await;
        assert_eq!(
            out.warnings.len(),
            1,
            "one stale install, one warning (cache folded, not standalone): {:?}",
            out.warnings
        );
        let detail = detail_of(&out.warnings[0]);
        assert!(
            detail.contains(&committed.display().to_string()),
            "the committed archive must join the delete list even with no \
             known artifact sha: {detail}"
        );
        assert_eq!(
            out.stale_purls,
            std::collections::BTreeSet::from([GEM_PURL.to_string()])
        );
        // Read-only contract: the archive itself is never deleted.
        assert!(committed.is_file(), "the probe prescribes, never deletes");
    }

    /// Standalone cache pass 3, UNREADABLE-archive arm: a committed archive
    /// whose bytes cannot be read (chmod 000) yields NO positive evidence,
    /// so the probe must stay silent instead of guessing staleness from the
    /// differing expected sha — the never-warn-without-positive-evidence
    /// contract, archive flavor.
    #[cfg(unix)]
    #[tokio::test]
    async fn gem_stale_probe_never_judges_unreadable_committed_archive() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        // NO installed gem dir (fresh-checkout shape) so pass 3 is the only
        // judgment path.
        let committed = tmp
            .path()
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        std::fs::create_dir_all(committed.parent().unwrap()).unwrap();
        std::fs::write(&committed, b"upstream archive bytes").unwrap();
        std::fs::set_permissions(&committed, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root ignores mode bits: detect it while the chmod is in force so
        // the assertion below matches what the probe could actually read.
        let readable_despite_chmod = std::fs::File::open(&committed).is_ok();

        let mut shas = std::collections::BTreeMap::new();
        shas.insert(
            ("stale-unit".to_string(), "1.0.0".to_string()),
            "0".repeat(64), // differs from the archive bytes' sha
        );
        let out = gem_stale_install_warnings(
            tmp.path(),
            false,
            None,
            &one_confirmed(),
            &one_record(),
            &shas,
        )
        .await;
        std::fs::set_permissions(&committed, std::fs::Permissions::from_mode(0o644)).unwrap();

        if readable_despite_chmod {
            // Running as root: the archive WAS readable and its sha differs,
            // so the ordinary stale-cache warning is the correct outcome.
            assert_eq!(out.warnings.len(), 1, "root fallback: readable + stale");
        } else {
            assert!(
                out.warnings.is_empty(),
                "an unreadable archive is never staleness evidence: {:?}",
                out.warnings
            );
            assert!(out.stale_purls.is_empty());
        }
    }

    /// The standalone cache-flavor warning's load-bearing wording.
    #[test]
    fn gem_stale_cache_warning_names_archive_and_remedy() {
        let cache = PathBuf::from("proj")
            .join("vendor")
            .join("cache")
            .join(format!("{GEM_LEAF}.gem"));
        let w = gem_stale_cache_warning(GEM_PURL, &cache);
        let detail = detail_of(&w);
        assert!(detail.contains(GEM_PURL), "{detail}");
        assert!(detail.contains(&cache.display().to_string()), "{detail}");
        assert!(detail.contains("UNPATCHED"), "{detail}");
        assert!(detail.contains("fresh checkouts included"), "{detail}");
        assert!(
            detail.contains("`bundle install`") && detail.contains("bundle cache"),
            "{detail}"
        );
    }

    #[test]
    fn redirect_candidates_are_pinned_by_value() {
        // Hardcoded on purpose: the candidate list is derived from the
        // format registry, so a row dropped (or a HOSTED flag lost) there
        // must fail here instead of silently shrinking what hosted reads.
        assert_eq!(
            *REDIRECT_CANDIDATE_FILES,
            [
                "package-lock.json",
                "npm-shrinkwrap.json",
                "pnpm-lock.yaml",
                "shrinkwrap.yaml",
                "node_modules/.modules.yaml",
                "yarn.lock",
                ".yarnrc.yml",
                "bun.lock",
                "bun.lockb",
                "vlt-lock.json",
                "vlt.json",
                "node_modules/.vlt-lock.json",
                "requirements.txt",
                "uv.lock",
                "poetry.lock",
                "pdm.lock",
                "Pipfile.lock",
                "Pipfile",
                "pyproject.toml",
                "hatch.toml",
                "Cargo.toml",
                "Cargo.lock",
                ".cargo/config.toml",
                ".cargo/config",
                "composer.lock",
                "nuget.config",
                "NuGet.config",
                "NuGet.Config",
                "packages.lock.json",
                "Gemfile",
                "Gemfile.lock",
                "gems.rb",
                "gems.locked",
                "go.mod",
                "go.sum",
                "pom.xml",
                ".mvn/maven.config",
                ".mvn/checksums/checksums.sha256",
                ".mvn/wrapper/maven-wrapper.properties",
                "settings.gradle",
                "settings.gradle.kts",
                "build.gradle",
                "build.gradle.kts",
            ]
        );
    }
    // ── Human-output formatting ────────────────────────────────────────────

    #[test]
    fn redirect_summary_singular_plural_and_dry_run() {
        assert_eq!(
            format_redirect_summary(1, 1, false),
            "Switched 1 package to hosted patches; rewrote 1 file."
        );
        assert_eq!(
            format_redirect_summary(2, 3, false),
            "Switched 2 packages to hosted patches; rewrote 3 files."
        );
        assert_eq!(
            format_redirect_summary(0, 0, false),
            "Switched 0 packages to hosted patches; rewrote 0 files."
        );
        assert_eq!(
            format_redirect_summary(1, 1, true),
            "Would switch 1 package to hosted patches and rewrite 1 file (--dry-run: nothing was changed)."
        );
        assert_eq!(
            format_redirect_summary(0, 0, true),
            "Would switch 0 packages to hosted patches and rewrite 0 files (--dry-run: nothing was changed)."
        );
        assert_eq!(
            format_redirect_summary(2, 5, true),
            "Would switch 2 packages to hosted patches and rewrite 5 files (--dry-run: nothing was changed)."
        );
    }

    #[test]
    fn redirect_summary_already_redirected_is_not_redirected_n() {
        // Confirmed but nothing to write: an idempotent re-run, never
        // "Redirected 1 package(s); rewrote 0 file(s)".
        for dry in [false, true] {
            assert_eq!(
                format_redirect_summary(1, 0, dry),
                "1 package is already on hosted patches; nothing to rewrite."
            );
            assert_eq!(
                format_redirect_summary(3, 0, dry),
                "3 packages are already on hosted patches; nothing to rewrite."
            );
        }
    }

    #[test]
    fn skip_reasons_are_readable_and_unknown_codes_pass_through() {
        assert_eq!(
            describe_skip_reason("forbidden"),
            "not entitled to this patch (paid plan or no org access)"
        );
        assert_eq!(
            describe_skip_reason("pending"),
            "the hosted artifact is still being built; re-run later"
        );
        assert_eq!(
            describe_skip_reason("not_found"),
            "the hosted patch server has no artifact for this patch"
        );
        assert_eq!(
            describe_skip_reason("vendored_revert_failed"),
            "its vendored state could not be reverted (see the warning)"
        );
        assert_eq!(
            describe_skip_reason("redirect_bun_lockb_invalid"),
            describe_skip_reason("redirect_bun_lock_unsupported")
        );
        assert_eq!(
            describe_skip_reason("redirect_vlt_artifact_unverifiable"),
            "vlt could not verify the hosted artifact (see the warning)"
        );
        assert_eq!(
            describe_skip_reason("redirect_vlt_lock_unsupported"),
            "vlt-lock.json blocks the vendored-to-hosted migration (see the warning)"
        );
        assert_eq!(
            describe_skip_reason("redirect_requirements_takeover_unreachable"),
            "hosted mode cannot pin it where vendored mode wired it, so it stays vendored \
             (see the warning)"
        );
        assert_eq!(describe_skip_reason("mystery"), "server status `mystery`");
        for code in [
            "not_found",
            "forbidden",
            "pending",
            "pending_build",
            "build_failed",
            "withdrawn",
            "bad_purl",
            "no_url",
            "python_metadata_unavailable",
        ] {
            let text = describe_skip_reason(code);
            assert!(!text.contains('_'), "{code} → {text}");
        }
    }

    #[test]
    fn unredirected_lines_empty_partial_and_nothing_redirected() {
        assert!(format_unredirected(&[], &[], true, 1).is_empty());
        let skipped = vec![(
            "pkg:npm/lodash@4.17.20".to_string(),
            "forbidden".to_string(),
        )];
        let unconfirmed = vec!["pkg:npm/minimist@1.2.5".to_string()];
        assert_eq!(
            format_unredirected(&skipped, &unconfirmed, false, 1),
            vec![
                "Skipped pkg:npm/lodash@4.17.20: not entitled to this patch (paid plan or no \
                 org access)"
                    .to_string(),
                "Not hosted pkg:npm/minimist@1.2.5: no lockfile entry pinning it could be \
                 rewritten (see the warning below)"
                    .to_string(),
            ]
        );
        assert_eq!(
            format_unredirected(&[], &unconfirmed, false, 2),
            vec![
                "Not hosted pkg:npm/minimist@1.2.5: no lockfile entry pinning it could be \
                 rewritten (see the warnings below)"
                    .to_string(),
            ]
        );
        assert_eq!(
            format_unredirected(&[], &unconfirmed, true, 0),
            vec![
                "No patches could be switched to hosted:".to_string(),
                "  pkg:npm/minimist@1.2.5: no lockfile entry pinning it could be rewritten"
                    .to_string(),
            ]
        );
        assert_eq!(
            format_unredirected(&skipped, &[], true, 0),
            vec![
                "No patches could be switched to hosted:".to_string(),
                "  pkg:npm/lodash@4.17.20: not entitled to this patch (paid plan or no org \
                 access)"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn takeover_lines_wet_and_dry() {
        assert_eq!(
            format_takeover_line("pkg:npm/lodash@4.17.20", false),
            "Migrated pkg:npm/lodash@4.17.20 from vendored to hosted (reverted its vendored \
             wiring, ledger entry, and committed artifact)."
        );
        assert_eq!(
            format_takeover_line("pkg:npm/lodash@4.17.20", true),
            "Would migrate pkg:npm/lodash@4.17.20 from vendored to hosted (its vendored \
             wiring, ledger entry, and committed artifact would be reverted first)."
        );
        assert!(TAKEOVER_INFO_CODES.contains(&"redirect_takeover_reverted_vendored"));
        assert!(TAKEOVER_INFO_CODES.contains(&"redirect_would_revert_vendored"));
        assert!(!TAKEOVER_INFO_CODES.contains(&"redirect_vendored_revert_failed"));
    }

    #[test]
    fn sentence_case_skips_identifiers_and_tool_names() {
        assert_eq!(
            sentence_case("failed to write x: y"),
            "Failed to write x: y"
        );
        assert_eq!(
            sentence_case("the hosted ledger ./a is malformed"),
            "The hosted ledger ./a is malformed"
        );
        assert_eq!(sentence_case("pnpm >=11 rejects"), "pnpm >=11 rejects");
        for tool in ["vlt", "vlx", "vlr"] {
            assert_eq!(
                sentence_case(&format!("{tool} ci fails")),
                format!("{tool} ci fails")
            );
        }
        assert_eq!(
            sentence_case("pnpm-lock.yaml was repointed"),
            "pnpm-lock.yaml was repointed"
        );
        assert_eq!(
            sentence_case("pkg:npm/x@1 redirected"),
            "pkg:npm/x@1 redirected"
        );
        assert_eq!(sentence_case("`vendor` refused"), "`vendor` refused");
        assert_eq!(sentence_case("Already upper"), "Already upper");
        assert_eq!(sentence_case(""), "");
        assert_eq!(sentence_case("é accent"), "é accent");
        assert_eq!(
            format_error_line("failed to resolve patch references: boom"),
            "Error: Failed to resolve patch references: boom"
        );
    }

    #[test]
    fn wrap_words_respects_width_prefix_and_long_words() {
        assert_eq!(
            wrap_words("alpha beta gamma delta", 16, "W: ", "  "),
            vec!["W: alpha beta", "  gamma delta"]
        );
        // A word wider than the line sits alone, unsplit.
        let url = "https://patch.socket.dev/very/long/path/that/does/not/fit";
        assert_eq!(
            wrap_words(&format!("see {url} now"), 20, "", "  "),
            vec!["see".to_string(), format!("  {url}"), "  now".to_string()]
        );
        assert_eq!(wrap_words("", 10, "W: ", "  "), vec!["W: "]);
        // Counts characters, not bytes.
        let lines = wrap_words("ééé ééé ééé", 8, "", "");
        assert_eq!(lines, vec!["ééé ééé", "ééé"]);
        for line in wrap_words(&"word ".repeat(50), 30, "Warning: ", "  ") {
            assert!(line.chars().count() <= 30, "{line}");
        }
    }

    #[test]
    fn wrap_words_keeps_code_spans_whole() {
        // The span crosses the wrap column: it moves to the next line whole.
        assert_eq!(
            wrap_words(
                "never rebuild it (`pnpm clean --lockfile`), ever",
                30,
                "",
                "  "
            ),
            vec!["never rebuild it", "  (`pnpm clean --lockfile`),", "  ever"]
        );
        // A span wider than the line gets a line of its own, unsplit.
        assert_eq!(
            wrap_words(
                "use `pnpm install --frozen-lockfile --store-dir <dir>` now",
                20,
                "",
                "  "
            ),
            vec![
                "use",
                "  `pnpm install --frozen-lockfile --store-dir <dir>`",
                "  now"
            ]
        );
        // Two spans in one word, and a word with a closed span, split normally.
        assert_eq!(
            wrap_tokens("a `b` c `d e`f g"),
            vec!["a", "`b`", "c", "`d e`f", "g"]
        );
        // An unclosed span never swallows the rest of the text.
        assert_eq!(wrap_tokens("a `b c d"), vec!["a", "`b", "c", "d"]);
    }

    #[test]
    fn split_sentences_keeps_hosts_and_versions_whole() {
        assert_eq!(
            split_sentences("Repointed at patch.socket.dev. Keep lock 5.4 committed. done"),
            vec![
                "Repointed at patch.socket.dev.",
                "Keep lock 5.4 committed.",
                "done"
            ]
        );
        assert_eq!(split_sentences("one"), vec!["one"]);
        assert!(split_sentences("  ").is_empty());
    }

    #[test]
    fn warning_line_one_line_in_pipes_and_wrapped_on_terminals() {
        assert_eq!(
            format_warning(
                "redirect_npm_no_lockfile",
                "no package-lock.json present",
                None
            ),
            "Warning: No package-lock.json present"
        );
        let long = "word ".repeat(40);
        let wrapped = format_warning("c", &long, Some(40));
        assert!(wrapped.lines().count() > 1, "{wrapped}");
        assert!(
            wrapped.lines().all(|l| l.chars().count() <= 40),
            "{wrapped}"
        );
        assert!(wrapped.starts_with("Warning: Word word"), "{wrapped}");
        assert!(
            wrapped.lines().skip(1).all(|l| l.starts_with("  ")),
            "{wrapped}"
        );
    }

    #[test]
    fn pnpm_warning_renders_headline_plus_bullets() {
        let detail = "pnpm-lock.yaml was repointed at the server; so it goes. Note: a tradeoff. \
                      Do NOT rebuild the lockfile. Run `socket-patch vex` after installation.";
        assert_eq!(
            format_warning("redirect_pnpm_trust_lockfile", detail, None),
            "Warning: pnpm-lock.yaml was repointed at the \
             server; so it goes.\n  - Note: a tradeoff.\n  - Do NOT rebuild the lockfile.\n  \
             - Run `socket-patch vex` after installation."
        );
        let wrapped = format_warning("redirect_pnpm_trust_lockfile", detail, Some(60));
        for line in wrapped.lines() {
            assert!(line.chars().count() <= 60, "{line:?}");
        }
        assert_eq!(
            wrapped,
            "Warning: pnpm-lock.yaml was repointed at the server; so it\n  \
             goes.\n  - Note: a tradeoff.\n  - Do NOT \
             rebuild the lockfile.\n  - Run `socket-patch vex` after installation."
        );
        // Continuation lines of a long bullet are indented under its text.
        let bullet = "Head. Do NOT follow the advice to rebuild the lockfile, which discards it.";
        assert_eq!(
            format_warning("redirect_pnpm_trust_lockfile", bullet, Some(40)),
            "Warning: Head.\n  - Do NOT follow the advice to \
             rebuild\n    the lockfile, which discards it."
        );
    }

    #[test]
    fn pnpm_rerun_reminder_keeps_the_rebuild_caution() {
        let r = pnpm_trust_rerun_reminder();
        assert!(r.contains("trustLockfile: true"), "{r}");
        assert!(r.contains("pnpm clean --lockfile"), "{r}");
        assert!(r.chars().count() < 240, "a reminder, not the wall: {r}");
    }

    #[test]
    fn store_flag_note_only_for_pnpm_one_to_four_locks() {
        assert!(pnpm_lock_may_need_store_flag("shrinkwrapVersion: 3\n"));
        assert!(pnpm_lock_may_need_store_flag("lockfileVersion: 5.1\n"));
        assert!(pnpm_lock_may_need_store_flag("lockfileVersion: '5.2'\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: 5.3\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: 5.4\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: '6.0'\n"));
        assert!(!pnpm_lock_may_need_store_flag("lockfileVersion: '9.0'\n"));
        assert!(!pnpm_lock_may_need_store_flag("packages: {}\n"));
    }

    #[test]
    fn join_names_lists_and_caps() {
        let n = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(join_names(&n(&[]), 6), "");
        assert_eq!(join_names(&n(&["a"]), 6), "a");
        assert_eq!(join_names(&n(&["a", "b"]), 6), "a and b");
        assert_eq!(join_names(&n(&["a", "b", "c"]), 6), "a, b, and c");
        assert_eq!(join_names(&n(&["a", "b", "c", "d"]), 2), "a, b, and 2 more");
    }

    #[test]
    fn next_steps_name_the_rewritten_files_and_reinstall() {
        assert!(format_next_steps(&[], &[], false).is_empty());
        assert_eq!(
            format_next_steps(&["package-lock.json".to_string()], &[], false),
            vec![
                "Next steps:".to_string(),
                "  1. Commit package-lock.json to keep the hosted patches.".to_string(),
                "  2. Reinstall from the updated lockfile (e.g. `npm ci`) so the installed \
                 packages pick up the patched artifacts, then run `socket-patch vex` to verify \
                 the installed patches."
                    .to_string(),
            ]
        );
        let steps = format_next_steps(
            &[
                "pnpm-lock.yaml".to_string(),
                "pnpm-workspace.yaml".to_string(),
            ],
            &[],
            false,
        );
        assert_eq!(
            steps[1],
            "  1. Commit pnpm-lock.yaml and pnpm-workspace.yaml to keep the hosted patches."
        );
        assert!(!steps[2].contains("npm ci"), "{}", steps[2]);
    }

    #[test]
    fn next_steps_add_the_vlt_ci_line_only_for_a_rewritten_vlt_lock() {
        let steps = format_next_steps(&["vlt-lock.json".to_string()], &[], false);
        assert_eq!(
            steps.last().map(String::as_str),
            Some("  3. vlt: commit vlt-lock.json; CI should run `vlt ci`.")
        );
        assert!(
            !format_next_steps(&["package-lock.json".to_string()], &[], false)
                .iter()
                .any(|s| s.contains("vlt:"))
        );
    }

    #[test]
    fn next_steps_after_a_takeover_name_the_removed_vendored_state() {
        assert_eq!(
            format_next_steps(&["pnpm-lock.yaml".to_string()], &[], true)[1],
            "  1. Commit .socket/vendor/ (the removed vendored ledger entries and artifacts) and \
             pnpm-lock.yaml to keep the hosted patches."
        );
    }

    /// Every hosted npm redirect variant tells the user
    /// that npm >= 12 refuses the redirected lock (EALLOWREMOTE) without
    /// `allow-remote=all`, and carries the whole-tree tradeoff disclosure —
    /// the auto-configured, already-set, explicit-other, opted-out and
    /// unreadable variants alike.
    #[test]
    fn npm_allow_remote_warning_variants_carry_the_load_bearing_sentences() {
        let hosts = ["patch.socket.dev"];
        let variants = [
            npm_allow_remote_configured_detail(&hosts, true, false),
            npm_allow_remote_configured_detail(&hosts, false, false),
            npm_allow_remote_configured_detail(&hosts, true, true),
            npm_allow_remote_configured_detail(&hosts, false, true),
            npm_allow_remote_already_detail(&hosts),
            npm_allow_remote_user_set_detail(&hosts, "root"),
            npm_allow_remote_manual_detail(&hosts),
            npm_allow_remote_unreadable_detail(&hosts, "could not be read (denied)"),
            npm_allow_remote_env_set_detail(&hosts, "npm_config_allow_remote", "none"),
            npm_allow_remote_outer_set_detail(
                &hosts,
                "user",
                std::path::Path::new("/home/u/.npmrc"),
                "none",
            ),
        ];
        for d in &variants {
            for needle in [
                "patch.socket.dev",
                "npm >=12",
                "EALLOWREMOTE",
                "lets npm install ANY url-resolved",
                "sha512 integrity pins are still enforced",
                "npm <=11 installs work unchanged",
            ] {
                assert!(d.contains(needle), "{needle:?} missing: {d}");
            }
        }
        let [created, appended, dry_created, dry_appended, already, user_set, manual, unreadable, env_set, outer_set] =
            &variants;
        assert!(
            env_set.contains("npm_config_allow_remote=none")
                && env_set.contains("overrides every .npmrc")
                && env_set.contains("would not take effect")
                && env_set.contains("left untouched"),
            "{env_set}"
        );
        assert!(
            outer_set.contains("The user npm config (/home/u/.npmrc)")
                && outer_set.contains("explicitly sets `allow-remote=none`")
                && outer_set.contains("does not commit a project .npmrc that overrides it"),
            "{outer_set}"
        );
        assert!(
            created.contains("was written to a new project .npmrc"),
            "{created}"
        );
        assert!(
            appended.contains("was appended to the existing project .npmrc"),
            "{appended}"
        );
        // The summary line already says it is a dry run (the pnpm
        // trustLockfile twin's rule): no marker inside the noun phrase.
        assert!(
            dry_created.contains("would be written to a new project .npmrc")
                && !dry_created.contains("(--dry-run)"),
            "{dry_created}"
        );
        assert!(
            dry_appended.contains("would be appended to the existing project .npmrc")
                && !dry_appended.contains("(--dry-run)"),
            "{dry_appended}"
        );
        for d in [created, appended, dry_created, dry_appended] {
            assert!(
                d.contains("--no-npm-allow-remote-config"),
                "opt-out named: {d}"
            );
            assert!(d.contains("SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG"), "{d}");
        }
        assert!(
            already.contains("already sets `allow-remote=all`"),
            "{already}"
        );
        assert!(
            user_set.contains("explicitly sets `allow-remote=root`"),
            "{user_set}"
        );
        assert!(
            user_set.contains("respected and left untouched"),
            "{user_set}"
        );
        assert!(
            user_set.contains("only admits direct dependencies"),
            "{user_set}"
        );
        for d in [user_set, manual, unreadable, env_set, outer_set] {
            assert!(
                d.contains("npm ci --allow-remote=all"),
                "manual remedy: {d}"
            );
        }
        assert!(
            unreadable.contains("could not be read (denied)"),
            "{unreadable}"
        );
    }

    /// The `.npmrc` read classifier: absent → plan a Create; readable →
    /// plan against the text; a symlink or unreadable file → hands off
    /// (never planned — a Create would clobber the user's config, and the
    /// atomic writer would replace a link).
    #[test]
    fn read_npmrc_for_allow_remote_classifies_absent_readable_and_unsafe() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".npmrc");
        assert_eq!(read_npmrc_for_allow_remote(&path), Ok(None));
        std::fs::write(&path, "fund=false\n").unwrap();
        assert_eq!(
            read_npmrc_for_allow_remote(&path),
            Ok(Some("fund=false\n".into()))
        );
        std::fs::write(&path, [0xff_u8, 0xfe]).unwrap();
        assert!(read_npmrc_for_allow_remote(&path)
            .unwrap_err()
            .contains("could not be read"));
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            std::fs::write(tmp.path().join("real"), "fund=false\n").unwrap();
            std::os::unix::fs::symlink(tmp.path().join("real"), &path).unwrap();
            assert!(read_npmrc_for_allow_remote(&path)
                .unwrap_err()
                .contains("symbolic link"));
        }
    }

    #[test]
    fn npm_allow_remote_one_line_covers_every_variant() {
        use super::npm_allow_remote_one_line;
        let hosts = ["patch.socket.dev"];
        let cases = [
            (npm_allow_remote_configured_detail(&hosts, true, false), "Note: set"),
            (npm_allow_remote_configured_detail(&hosts, false, false), "Note: set"),
            (npm_allow_remote_configured_detail(&hosts, true, true), "Note: would set"),
            (npm_allow_remote_already_detail(&hosts), "Note: .npmrc already"),
            (npm_allow_remote_user_set_detail(&hosts, "none"), "Warning: npm >=12"),
            (npm_allow_remote_env_set_detail(&hosts, "npm_config_allow_remote", "none"), "Warning: npm >=12"),
            (npm_allow_remote_manual_detail(&hosts), "Warning: npm >=12"),
            (npm_allow_remote_unreadable_detail(&hosts, "is a symlink"), "Warning: npm >=12"),
        ];
        for (detail, start) in cases {
            let line = npm_allow_remote_one_line(&detail);
            assert!(line.starts_with(start), "{line}");
            assert!(!line.contains('\n') && line.ends_with("(details: --verbose)."), "{line}");
        }
    }
}
