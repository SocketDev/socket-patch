use clap::Args;
use socket_patch_core::api::blob_fetcher::get_missing_blobs;
use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::crawlers::ruby_crawler::config_path_ignored_warning;
use socket_patch_core::crawlers::{
    bun_uses_global_store, detect_npm_pkg_manager, Ecosystem, NpmPkgManager, RubyCrawler,
};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::{
    apply_package_patch, verify_file_patch, ApplyResult, MismatchPolicy, PatchSources, VerifyStatus,
};
use socket_patch_core::patch::apply_lock::LockGuard;
use socket_patch_core::patch::redirect::golang_local::{
    apply_go_redirect, reconcile_go_redirects, verify_go_redirect_state,
};
use socket_patch_core::patch::sidecars::{maven as maven_sidecars, SidecarAdvisoryCode};
use socket_patch_core::telemetry::{track_patch_applied, track_patch_apply_failed, TelemetryAuth};
use socket_patch_core::utils::purl::parse_golang_purl;
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::purl_keys_cover;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{apply_env_toggles, is_local_go, GlobalArgs};
use crate::commands::fetch_stage::{stage_patch_sources, StageOutcome, StagedSources};
use crate::commands::lock_cli::acquire_or_emit;
use crate::commands::vex::{
    generate_vex_from_manifest_path, generate_vex_without_manifest, ManifestlessVex, VexEmbedArgs,
};
use crate::ecosystem_dispatch::{
    distinct_install_dirs, distinct_npm_copies, find_all_packages_for_purls, partition_purls,
    JvmScope,
};
use crate::json_envelope::{
    AppliedVia, Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile,
    RunWarning, Status, VexSummary,
};
use crate::ui::{plural, StatusLine};

/// Files whose pre-apply content matched NEITHER hash and were (or would
/// be) overwritten with the verified patched content — the promoted
/// verify signature `apply_package_patch` leaves behind under the default
/// mismatch policy.
fn mismatch_overwritten_files(result: &ApplyResult) -> Vec<String> {
    result
        .files_verified
        .iter()
        .filter(|v| {
            v.status == VerifyStatus::Ready
                && v.expected_hash.is_some()
                && v.current_hash != v.expected_hash
        })
        .map(|v| v.file.clone())
        .collect()
}

/// Surface one mismatch-overwrite per file on stderr (human mode).
fn warn_mismatch_overwrites(result: &ApplyResult, common: &GlobalArgs) {
    if common.json || common.silent {
        return;
    }
    for file in mismatch_overwritten_files(result) {
        eprintln!(
            "{}",
            format_mismatch_warning(&normalize_purl(&result.package_key), &file, common.dry_run)
        );
    }
}

/// The human stderr line for one mismatch-overwritten file. A dry run
/// wrote nothing, so it says what *would* happen.
fn format_mismatch_warning(purl: &str, file: &str, dry_run: bool) -> String {
    let what = if dry_run { "would apply" } else { "applied" };
    format!(
        "Warning: {purl} {file} did not match the patch's \
         expected original content; {what} the full verified patched content instead \
         (pass --strict to fail on mismatches)"
    )
}

/// The JSON event detail for one mismatch-overwritten file (tense follows
/// `dry_run`, like [`format_mismatch_warning`]).
fn mismatch_event_detail(file: &str, dry_run: bool) -> String {
    let what = if dry_run { "would be" } else { "was" };
    format!(
        "{file} did not match the patch's expected original content; the full verified \
         patched content {what} applied"
    )
}

/// One `content_mismatch_overwritten` run warning per mismatch-overwritten
/// file across `results`, in the event detail's words prefixed with the
/// package purl — what a nested apply hands back to `get` / `scan --mode
/// agent` (#1004).
fn mismatch_overwrite_warnings(results: &[ApplyResult], dry_run: bool) -> Vec<RunWarning> {
    results
        .iter()
        .flat_map(|r| {
            let purl = normalize_purl(&r.package_key);
            mismatch_overwritten_files(r)
                .into_iter()
                .map(move |file| RunWarning {
                    code: "content_mismatch_overwritten".to_string(),
                    detail: format!("{purl}: {}", mismatch_event_detail(&file, dry_run)),
                })
        })
        .collect()
}

/// `1 mismatched file` / `2 mismatched files`, with the verb agreeing.
fn mismatched_files_fail(n: usize) -> String {
    if n == 1 {
        "1 mismatched file will fail to apply".to_string()
    } else {
        format!("{n} mismatched files will fail to apply")
    }
}

/// The default mismatch policy applies the FULL patched content for
/// mismatched files — and the full content lives in the afterHash blob,
/// which the default `--download-mode diff` may not have staged. Probe the
/// in-scope packages for mismatches and fetch the missing afterHash blobs
/// by hash (online only) so the apply below can fall through diff → blob.
async fn ensure_blobs_for_mismatches(
    args: &ApplyArgs,
    manifest: &PatchManifest,
    all_packages: &HashMap<String, Vec<PathBuf>>,
    vendored_purls: &HashSet<PurlKey>,
    staged: &mut StagedSources,
    client: &ApiClient,
) {
    if args.common.strict && !args.force {
        return; // strict fails on mismatch — nothing to fetch
    }
    let needed = mismatch_blob_gaps(
        manifest,
        all_packages,
        vendored_purls,
        &staged.blobs,
        args.force,
    )
    .await;
    if needed.is_empty() {
        return;
    }
    let quiet = args.common.silent || args.common.json;
    if args.common.offline {
        if !quiet {
            eprintln!(
                "Warning: {} {} the full patched blob, but --offline prevents fetching; {}",
                plural(
                    needed.len(),
                    "mismatched file needs",
                    "mismatched files need"
                ),
                if needed.len() == 1 { "its" } else { "their" },
                if needed.len() == 1 {
                    "that file will fail to apply"
                } else {
                    "those files will fail to apply"
                }
            );
        }
        return;
    }
    // Apply is read-only against `.socket/`: when the stage step returned
    // direct `.socket/` paths (everything had a local source), the on-demand
    // blobs must go to a transient overlay, never `.socket/blobs/`.
    let Some(blobs_path) = staged.writable_blobs().await else {
        if !quiet {
            eprintln!(
                "Warning: could not stage a transient blob directory; {}",
                mismatched_files_fail(needed.len())
            );
        }
        return;
    };
    let mut status = StatusLine::stderr(args.common.json, args.common.silent);
    status.set(format!(
        "Downloading {} for mismatched files...",
        plural(needed.len(), "full patched blob", "full patched blobs")
    ));
    let fetched = socket_patch_core::api::blob_fetcher::fetch_blobs_by_hash(
        &needed, blobs_path, client, None,
    )
    .await;
    status.finish_with(format_mismatch_fetch_result(
        fetched.downloaded,
        needed.len(),
    ));
}

/// The result line after fetching full blobs for mismatched files.
fn format_mismatch_fetch_result(downloaded: usize, needed: usize) -> String {
    if downloaded == needed {
        format!(
            "Downloaded {} for mismatched files",
            plural(needed, "full patched blob", "full patched blobs")
        )
    } else {
        format!(
            "Downloaded {downloaded} of {} for mismatched files",
            plural(needed, "full patched blob", "full patched blobs")
        )
    }
}

/// Probe the crawled packages for `beforeHash` mismatches whose
/// `afterHash` blob is not already staged, returning the missing blob
/// hashes [`ensure_blobs_for_mismatches`] should fetch.
///
/// The crawler keys `all_packages` by BASE purl, but release-variant
/// ecosystems (PyPI `?artifact_id=`, RubyGems `?platform=`, Maven
/// `?classifier=&ext=`) key the manifest by QUALIFIED purls — an
/// exact-key lookup misses every one of them. Match records by
/// qualifier-stripped key, and probe only the variants the apply loop
/// will actually attempt (its representative-file installed-distribution
/// gate, bypassed by `--force`) so a skipped sibling variant's files
/// don't trigger spurious fetches or `--offline` warnings. An UNQUALIFIED
/// singleton base is always attempted (the mismatch-policy fall-through),
/// so its mismatched files are probed unconditionally; a QUALIFIED
/// singleton keeps the gate, mirroring the apply loop. Vendor-owned bases
/// are skipped outright: the apply loop never attempts them (their
/// results are synthesized up front), so their drifted files must not
/// queue fetches either.
///
/// EVERY physical copy of a purl is probed: npm materializes genuine
/// duplicates of one `name@version`, the apply loop patches each of them,
/// and copies drift independently — a pristine (or already-patched) root
/// copy says nothing about a locally-modified nested duplicate, whose
/// mismatched files still need their afterHash blobs. The variant gate
/// mirrors the apply loop's representative check PER COPY for gem and
/// PyPI (which patch every copy, and two envs can hold different wheels
/// of one release), and against the FIRST copy otherwise: a variant's
/// files are probed only on the copies it is attempted on. Maven's Gradle
/// copies are version dirs whose files sit in hash dirs, so each one is
/// first expanded into the hash dirs holding the record's files (as
/// `apply_maven_base` does) and gated and probed per hash dir; probing the
/// version dir itself would only ever find nothing, and a drifted Gradle
/// copy would never queue the afterHash blob its write needs.
///
/// Only a mismatched file whose afterHash blob is NOT staged can queue a
/// fetch, so the probe first decides that with metadata probes alone and
/// hashes only the files that can still matter: the common fully-cached
/// run hashes nothing here (the apply loop re-verifies everything anyway).
async fn mismatch_blob_gaps(
    manifest: &PatchManifest,
    all_packages: &HashMap<String, Vec<PathBuf>>,
    vendored_purls: &HashSet<PurlKey>,
    blobs_path: &Path,
    force: bool,
) -> HashSet<String> {
    let mut needed: HashSet<String> = HashSet::new();
    let missing = get_missing_blobs(manifest, blobs_path).await;
    if missing.is_empty() {
        return needed;
    }
    // A record can queue a fetch only through a content-modifying file
    // (non-empty beforeHash) whose afterHash blob is missing.
    let can_queue = |record: &PatchRecord| {
        record
            .files
            .values()
            .any(|f| !f.before_hash.is_empty() && missing.contains(&f.after_hash))
    };
    for (purl, pkg_paths) in all_packages {
        let Some(first_path) = pkg_paths.first() else {
            continue;
        };
        let variant_eco = Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants());
        let stripped = strip_purl_qualifiers(purl);
        let identity = PurlKey::new(purl);
        let records: Vec<(&String, &PatchRecord)> = manifest
            .patches
            .iter()
            .filter(|(key, _)| *key == purl || PurlKey::new(key) == identity)
            .collect();
        if purl_keys_cover(vendored_purls, purl)
            || records
                .iter()
                .any(|(key, _)| purl_keys_cover(vendored_purls, key))
        {
            continue;
        }
        if !records.iter().any(|(_, record)| can_queue(record)) {
            continue;
        }
        let gated = variant_eco
            && !force
            && (records.len() > 1
                || records
                    .first()
                    .is_some_and(|(key, _)| key.as_str() != stripped));
        let maven = Ecosystem::from_purl(purl) == Some(Ecosystem::Maven);
        for (_, record) in records {
            if !can_queue(record) {
                continue;
            }
            // Maven: every Gradle version dir expanded into the hash dirs
            // holding the record's files.
            let expanded: Vec<PathBuf> = if maven {
                pkg_paths
                    .iter()
                    .flat_map(|p| {
                        socket_patch_core::crawlers::gradle_cache::installed_copies(
                            p,
                            &record.files,
                        )
                        .into_iter()
                        .map(|(dir, _)| dir)
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let pkg_paths: &[PathBuf] = if maven { &expanded } else { pkg_paths };
            // The copies the apply loop gates per copy: gem and PyPI patch
            // every copy, each against its own representative check, and
            // Maven each hash dir; the rest gate on the first.
            let gate_copies: &[PathBuf] = if matches!(
                Ecosystem::from_purl(purl),
                Some(Ecosystem::Gem | Ecosystem::Pypi | Ecosystem::Maven)
            ) {
                pkg_paths
            } else {
                std::slice::from_ref(first_path)
            };
            // Copies this variant is attempted on: a copy whose installed
            // distribution is another variant (two envs can hold different
            // wheels of one release) is skipped there by the apply loop.
            let probe_copies: Vec<&PathBuf> = match representative_file(&record.files) {
                Some((file_name, file_info)) if gated => {
                    let mut matched = Vec::new();
                    for copy in gate_copies {
                        let status = verify_file_patch(copy, file_name, file_info).await.status;
                        if variant_matches_installed(Some(&status)) {
                            matched.push(copy);
                        }
                    }
                    matched
                }
                _ => pkg_paths.iter().collect(),
            };
            if probe_copies.is_empty() {
                continue;
            }
            for (file_name, info) in &record.files {
                if info.before_hash.is_empty() || !missing.contains(&info.after_hash) {
                    continue;
                }
                for pkg_path in &probe_copies {
                    let verify = verify_file_patch(pkg_path, file_name, info).await;
                    if verify.status == VerifyStatus::HashMismatch {
                        needed.insert(info.after_hash.clone());
                        break; // the fetch is per-hash; one drifted copy queues it
                    }
                }
            }
        }
    }
    needed
}

/// The mismatch policy this run applies with: `--force` ⊃ default
/// (adds the missing-file skip), `--strict` restores fail-closed.
fn mismatch_policy(force: bool, strict: bool) -> MismatchPolicy {
    if force {
        MismatchPolicy::Force
    } else if strict {
        MismatchPolicy::Strict
    } else {
        MismatchPolicy::Warn
    }
}

#[derive(Args)]
pub struct ApplyArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Skip pre-application hash verification (apply even if package version differs).
    #[arg(
        short = 'f',
        long,
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub force: bool,

    /// Read-only: verify that every manifest patch is in place (each
    /// installed copy hashes to the patched bytes; Go: the committed
    /// `replace`-redirects match the manifest), exiting non-zero on drift.
    /// For CI / GitHub-App auditing. Lock-free and offline-safe: it never
    /// fetches or writes. Vendored patches are `vendor --check`'s job.
    #[arg(
        long = "check",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub check: bool,

    /// On a successful apply, also generate an OpenVEX 0.2.0 document.
    /// `--vex <path>` is the trigger; the `--vex-*` knobs mirror the
    /// standalone `vex` command. A requested-but-failed VEX makes the
    /// whole command exit non-zero even when patches applied cleanly.
    #[command(flatten)]
    pub vex: VexEmbedArgs,

    /// Set when `get` / `scan --mode agent` runs this apply as its last
    /// step (`None` for the `apply` command itself). Not a CLI flag.
    #[arg(skip)]
    pub nested: Option<NestedApply>,
}

/// What a nested apply knows about the command that runs it.
#[derive(Clone, Copy, Debug, Default)]
pub struct NestedApply {
    /// The caller runs under `--json`. The nested run itself is never JSON
    /// (one envelope per command), but the caller's stdout is, so the
    /// nested run's human error lines stay off stderr too.
    pub caller_json: bool,
}

impl ApplyArgs {
    /// Whether human-readable error lines go to stderr: never under
    /// `--json` (the envelope is the channel), always otherwise — errors
    /// are exempt from `--silent`.
    fn prints_errors(&self) -> bool {
        !self.common.json && !self.nested.is_some_and(|n| n.caller_json)
    }
}

// ── local-go redirect helpers ────────────────────────────────────────────────
// In local mode a `pkg:golang/…` PURL redirects to a project-local patched copy under `.socket/go-patches/` wired via
// a `go.mod` `replace` directive.

/// Whether this run can touch `eco`'s LOCAL install tree at all: local mode
/// (a `--global` / `--global-prefix` run crawls a different tree, so the
/// checkout says nothing about what it will patch) with the ecosystem not
/// filtered out by `--ecosystems`. The filter check is the exact `cli_name`
/// match `partition_purls` applies — clap admits no alias or case variant —
/// so a scope decided here can never diverge from the crawl scope. Gates
/// the local-go reconcile / `--check` (golang) and the yarn-PnP refusal
/// (npm: the refusal is about THIS run's packages living inside
/// `.yarn/cache/*.zip`, so a run that never crawls the checkout's
/// `node_modules` must not be refused by its layout).
fn eco_in_local_scope(common: &GlobalArgs, eco: Ecosystem) -> bool {
    !common.is_global() && common.ecosystem_selected(eco)
}

/// Materialise a local-go redirect for `purl`, or `None` if `purl` isn't a
/// local-go target (the caller then falls back to in-place apply, i.e. the
/// `--global` module-cache path).
async fn try_local_go_apply(
    purl: &str,
    pkg_path: &Path,
    patch: &PatchRecord,
    sources: &PatchSources<'_>,
    common: &GlobalArgs,
    policy: MismatchPolicy,
) -> Option<ApplyResult> {
    if !is_local_go(purl, common) {
        return None;
    }
    // NOTE: vendor ownership is enforced upstream for every ecosystem —
    // `apply_patches_inner` synthesizes a `Skipped`/`vendored` result and
    // never routes a vendored purl here, so this function only sees
    // modules the implicit apply actually owns.
    // `pkg_path` is the pristine, case-encoded module-cache dir; `module`/
    // `version` are the decoded PURL components keying the copy + `replace`.
    let (module, version) = parse_golang_purl(purl)?;
    let (module, version) = (&*module, &*version);
    Some(
        apply_go_redirect(
            purl,
            module,
            version,
            pkg_path,
            &common.cwd,
            socket_patch_core::vendor::go_mod_edit::GO_PATCHES_DIR,
            &patch.files,
            sources,
            Some(&patch.uuid),
            common.dry_run,
            policy,
        )
        .await,
    )
}

/// After the apply loop: prune local-go redirects whose patches were dropped
/// from the manifest. No-op unless local go is in scope.
async fn reconcile_local_go(common: &GlobalArgs, target_manifest_purls: &HashSet<String>) {
    if !eco_in_local_scope(common, Ecosystem::Golang) {
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
        println!(
            "{verb} {}:",
            plural(
                removed.len(),
                "stale Go patch redirect",
                "stale Go patch redirects"
            )
        );
        for purl in &removed {
            println!("  {purl}");
        }
    }
}

/// Read-only verification that the manifest's patches are in place, for CI
/// / GitHub-App auditing. Lock-free, fetch-free, offline-safe, and it never
/// writes. Exits 0 when in sync, 1 on drift.
///
/// Two audits, over the in-scope (`--ecosystems`) manifest entries that are
/// not vendor-owned (`vendor --check` audits those):
///
/// * local Go patches: the committed `.socket/go-patches/` copies and
///   `go.mod` `replace` directives ([`verify_go_redirect_state`]);
/// * every other patch: each installed copy must hash to the record's
///   `afterHash` — the same verifier `vex` attests with
///   ([`applied_patches_with_copies`](socket_patch_core::vex::applied_patches_with_copies)),
///   over the same copy lookup. A release variant (a qualified purl) is
///   judged only on the copies holding its distribution, as `apply` patches
///   it. A package with no installed copy is skipped, as `apply` skips it.
async fn run_check(args: &ApplyArgs, manifest_path: &Path) -> i32 {
    let manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        // The caller already confirmed the manifest file exists. `Ok(None)` means
        // it vanished since (TOCTOU) → nothing to verify. An `Err` means it exists
        // but is unreadable/corrupt: fail-closed (report drift) rather than
        // silently passing — the guard treats exit 0 as "in sync".
        Ok(None) => return 0,
        Err(e) => {
            let msg = format!(
                "Patch check could not read the manifest ({e}); \
                 treating it as drift (fail-closed)."
            );
            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.mark_error(EnvelopeError::new("manifest_unreadable", msg));
                println!("{}", env.to_pretty_json());
            } else {
                // Errors print even under --silent ("errors only", never
                // "nothing"): exit 1 with no message would be undiagnosable.
                eprintln!("Error: {msg}");
            }
            return 1;
        }
    };

    // (purl_or_name, reason_code, detail) for each drift.
    let mut drifts: Vec<(String, String, String)> = Vec::new();
    let mut checked: usize = 0;

    // The `apply` scope: `--ecosystems`, minus vendor-owned purls (matched
    // exactly as `apply` matches them; the ledger owns the PROJECT's
    // copies only, so a global check verifies every in-scope copy).
    let manifest_purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let in_scope: HashSet<String> =
        partition_purls(&manifest_purls, args.common.ecosystems.as_deref())
            .into_values()
            .flatten()
            .collect();
    let vendored = if crate::commands::project_state_in_scope(&args.common) {
        socket_patch_core::vendor::vendored_purl_keys(&args.common.cwd).await
    } else {
        Default::default()
    };
    let owned_by_apply = |purl: &str| in_scope.contains(purl) && !purl_keys_cover(&vendored, purl);

    {
        use socket_patch_core::patch::redirect::golang_local::Drift as GoDrift;
        if eco_in_local_scope(&args.common, Ecosystem::Golang) {
            let desired: HashSet<String> = manifest
                .patches
                .keys()
                .filter(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Golang))
                .filter(|p| !purl_keys_cover(&vendored, p))
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
                    drifts.push((id, "go_redirect_drift".to_string(), d.to_string()));
                }
            }
        }
    }

    // Installed-tree patches: everything `apply` patches in place.
    let mut tree = manifest.clone();
    tree.patches
        .retain(|purl, _| owned_by_apply(purl) && !is_local_go(purl, &args.common));
    // The same PnP gate `apply` runs: a PnP tree hides every npm copy, so
    // without it each npm patch would read as not installed and pass calm.
    if matches!(
        detect_npm_pkg_manager(&args.common.cwd),
        NpmPkgManager::YarnBerryPnP
    ) && eco_in_local_scope(&args.common, Ecosystem::Npm)
        && manifest_targets_npm(&tree)
    {
        return refuse_yarn_pnp(args);
    }
    let mut in_sync: Vec<String> = Vec::new();
    let mut not_installed: Vec<String> = Vec::new();
    if !tree.patches.is_empty() {
        let outcome = verify_installed_tree(&args.common, &tree).await;
        in_sync = outcome.applied;
        for failed in outcome.failed {
            match failed.reason.as_str() {
                "package_not_found" => not_installed.push(failed.purl),
                // A zero-file record (`no_files`) is drift, not in sync:
                // nothing was hashed, and `apply` / `get` count such a
                // record as failed, so `--check` must not attest it.
                reason => {
                    let detail = format!("{}: {}", failed.purl, describe_check_failure(reason));
                    drifts.push((failed.purl, reason.to_string(), detail));
                }
            }
        }
        in_sync.sort();
        not_installed.sort();
        checked += in_sync.len();
    }
    drifts.sort();

    if drifts.is_empty() {
        if args.common.json {
            let mut env = Envelope::new(Command::Apply);
            record_check_skips(&mut env, &in_sync, &not_installed);
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("{}", format_check_in_sync(checked, not_installed.len()));
        }
        0
    } else {
        if args.common.json {
            let mut env = Envelope::new(Command::Apply);
            for (id, code, detail) in &drifts {
                env.record(
                    PatchEvent::new(PatchAction::Failed, id.clone())
                        .with_reason(code.clone(), detail.clone()),
                );
            }
            record_check_skips(&mut env, &in_sync, &not_installed);
            env.mark_partial_failure();
            println!("{}", env.to_pretty_json());
        } else {
            // Drift IS the error the exit code signals — it prints even
            // under --silent ("errors only", never "nothing").
            eprintln!("Error: Patches are OUT OF SYNC:");
            for (_, _, detail) in &drifts {
                eprintln!("  {detail}");
            }
            eprintln!("Run `socket-patch apply` to regenerate them.");
        }
        1
    }
}

/// The installed-tree half of `apply --check`: every copy of each purl in
/// `tree`, judged by the `vex` verifier over the `vex` copy lookup (Maven:
/// the copies a build consumes), narrowed by `apply`'s own copy rules:
///
/// * Release variants (a base whose manifest keys are qualified, e.g.
///   `?artifact_id=` / `?platform=`): each copy is matched against EVERY
///   variant of its base, as `apply` matches it, and judged only for the
///   variants it holds. A copy that holds none of them is a
///   `no_matching_variant` drift of the base — `apply` fails that copy
///   ("no matching variant found"), so `--check` must not read it as
///   "not installed". Gradle / Ivy cache dirs are exempt: `apply` treats a
///   cache dir no variant matches as not an install of the record.
/// * Gem: once a bundle-store copy exists, `gem env` fallback-home copies
///   (rvm `@global`, system gem dirs) are dropped — `apply` treats them as
///   best-effort once the store copy is patched, and an unpatched store
///   copy is drift on its own. Copies under a containment-refused
///   `.bundle/config` `BUNDLE_PATH` root are kept: Bundler loads them.
async fn verify_installed_tree(
    common: &GlobalArgs,
    tree: &PatchManifest,
) -> socket_patch_core::vex::VerifyOutcome {
    use socket_patch_core::crawlers::gradle_cache::expands;
    use socket_patch_core::patch::apply::select_installed_variants;
    use socket_patch_core::vex::FailedPatch;
    let purls: Vec<String> = tree.patches.keys().cloned().collect();
    let found =
        crate::ecosystem_dispatch::find_manifest_package_copies_reusing(&purls, common, true, None)
            .await;
    let mut copies = crate::commands::vex::vex_copy_sets(common, tree, &found).await;

    // Gem copy classes, decided exactly as `apply` decides them.
    let (gem_stores, refused_root): (Vec<PathBuf>, Option<PathBuf>) = if !common.global
        && common.global_prefix.is_none()
        && purls
            .iter()
            .any(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Gem))
    {
        let discovery = RubyCrawler::discover_bundle_stores(&common.cwd).await;
        (discovery.stores, discovery.skipped_config_root)
    } else {
        (Vec::new(), None)
    };
    if !gem_stores.is_empty() {
        for (purl, paths) in copies.iter_mut() {
            if Ecosystem::from_purl(purl) != Some(Ecosystem::Gem) {
                continue;
            }
            let in_store = |p: &PathBuf| gem_stores.iter().any(|s| p.starts_with(s));
            // Only `gem env` fallback homes are dropped: a copy under the
            // containment-refused `.bundle/config` root is the one Bundler
            // loads, so it stays verified even when a store copy matches.
            let in_refused_root =
                |p: &PathBuf| refused_root.as_ref().is_some_and(|r| p.starts_with(r));
            if paths.iter().any(in_store) {
                paths.retain(|p| in_store(p) || in_refused_root(p));
            }
        }
    }

    // Release variants, grouped per base purl over all of its keys.
    let mut groups: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for purl in &purls {
        groups
            .entry(strip_purl_qualifiers(purl).to_string())
            .or_default()
            .push(purl.clone());
    }
    let mut unmatched: Vec<FailedPatch> = Vec::new();
    let mut mismatched_keys: std::collections::BTreeSet<String> = Default::default();
    for (base, mut keys) in groups {
        if keys.len() == 1 && keys[0] == base {
            // An unqualified singleton names no distribution: `apply`
            // runs it through the mismatch policy, the verifier judges it.
            continue;
        }
        keys.sort();
        let variants: Vec<(&str, &HashMap<String, PatchFileInfo>)> = keys
            .iter()
            .filter_map(|k| tree.patches.get(k).map(|r| (k.as_str(), &r.files)))
            .collect();
        let mut group_copies: Vec<PathBuf> = keys
            .iter()
            .flat_map(|k| copies.get(k).cloned().unwrap_or_default())
            .collect();
        group_copies.sort();
        group_copies.dedup();
        let mut kept: HashMap<&str, Vec<PathBuf>> = HashMap::new();
        let mut stray: Vec<PathBuf> = Vec::new();
        for path in group_copies {
            let matched = select_installed_variants(&path, &variants).await;
            if matched.is_empty() {
                if !expands(&path) {
                    stray.push(path);
                }
                continue;
            }
            for idx in matched {
                kept.entry(variants[idx].0).or_default().push(path.clone());
            }
        }
        for key in &keys {
            let paths = kept.remove(key.as_str()).unwrap_or_default();
            if !stray.is_empty() && paths.is_empty() {
                mismatched_keys.insert(key.clone());
            }
            copies.insert(key.clone(), paths);
        }
        if !stray.is_empty() {
            unmatched.push(FailedPatch {
                purl: base,
                reason: "no_matching_variant".to_string(),
            });
        }
    }

    let mut outcome =
        socket_patch_core::vex::applied_patches_with_copies(tree, &copies, None).await;
    // A key left copy-less only because its release's installed copy
    // matched no variant is that `no_matching_variant` failure, not a
    // second "not installed" skip.
    outcome
        .failed
        .retain(|f| !(f.reason == "package_not_found" && mismatched_keys.contains(&f.purl)));
    outcome.failed.extend(unmatched);
    outcome
}

/// The `apply --check` drift text for a verifier routing tag.
fn describe_check_failure(reason: &str) -> &'static str {
    match reason {
        "not_applied" => "patch not applied (an installed copy is still unpatched)",
        "hash_mismatch" => "an installed copy matches neither the original nor the patched bytes",
        "file_not_found" => "a patched file is missing from an installed copy",
        "no_files" => "the patch record lists no files to verify",
        "no_matching_variant" => {
            "an installed copy matches none of the manifest's release variants \
             (no matching variant found)"
        }
        _ => "an installed copy does not verify",
    }
}

/// The `skipped` events of an `apply --check --json` envelope: in-sync
/// patches as `already_patched` (apply's own tag for them) and patches with
/// no installed copy as `package_not_installed`.
fn record_check_skips(env: &mut Envelope, in_sync: &[String], not_installed: &[String]) {
    for purl in in_sync {
        env.record(
            PatchEvent::new(PatchAction::Skipped, purl.clone())
                .with_reason("already_patched", "every installed copy is patched"),
        );
    }
    for purl in not_installed {
        env.record(
            PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                "package_not_installed",
                "No installed package matches this PURL",
            ),
        );
    }
}

/// The `apply --check` success line: how many patches were checked, and how
/// many were skipped for having no installed copy, so a check over an
/// uninstalled tree never reads as a vacuous "in sync".
fn format_check_in_sync(checked: usize, not_installed: usize) -> String {
    let skipped = if not_installed == 0 {
        String::new()
    } else {
        format!(
            "; {} not installed, skipped",
            plural(not_installed, "patch", "patches")
        )
    };
    if checked == 0 && not_installed == 0 {
        "No patches to check.".to_string()
    } else {
        format!(
            "Patches are in sync ({} checked{skipped}).",
            plural(checked, "patch", "patches")
        )
    }
}

/// Sentinel `package_path` for a result synthesized because the purl is
/// owned by `socket-patch vendor` (recorded in `.socket/vendor/state.json`).
/// `result_to_event` routes it to `Skipped`/`vendored` by exact equality.
const VENDOR_OWNED_MARKER: &str = "managed by socket-patch vendor";

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
/// representative patched file (see [`representative_file`]).
///
/// This is the apply-side mirror of
/// [`select_installed_variants`](socket_patch_core::patch::apply::select_installed_variants),
/// which `rollback` and `get` use: a variant matches only when its
/// representative file is [`Ready`](VerifyStatus::Ready) (its
/// `beforeHash` matches the on-disk bytes) or
/// [`AlreadyPatched`](VerifyStatus::AlreadyPatched)
/// (its `afterHash` already matches). A variant with no representative
/// (`None`) has nothing to disqualify it and is treated as a match.
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

/// The file whose verify status decides whether a release variant
/// describes the installed distribution (fed to
/// [`variant_matches_installed`]).
///
/// Only a file that modifies existing content (non-empty `beforeHash`)
/// can discriminate between distributions — a NEW file (empty
/// `beforeHash`) verifies `Ready` against any environment, so it can
/// neither identify nor disqualify a variant. Take the lexicographically
/// smallest such key so the choice is deterministic (`HashMap` iteration
/// order is randomized per instance). `None` (no files, or only new
/// files) means nothing can disqualify the variant. Mirrors the
/// representative pick in core's
/// [`select_installed_variants`](socket_patch_core::patch::apply::select_installed_variants).
pub(crate) fn representative_file(
    files: &HashMap<String, PatchFileInfo>,
) -> Option<(&String, &PatchFileInfo)> {
    files
        .iter()
        .filter(|(_, info)| !info.before_hash.is_empty())
        .min_by(|(a, _), (b, _)| a.cmp(b))
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
    // Keeping events clean of sidecar info means each event describes
    // only the apply action; sidecar reporting is a separate,
    // JOIN-able list.
    PatchEvent::new(PatchAction::Applied, purl).with_files(files)
}

/// True when the manifest records at least one npm patch — the only kind a
/// PnP layout can block (a polyglot repo's pypi/gem/go patches live outside
/// `node_modules` and apply fine).
fn manifest_targets_npm(manifest: &PatchManifest) -> bool {
    manifest
        .patches
        .keys()
        .any(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Npm))
}

/// Print the yarn-PnP refusal (JSON envelope or human stderr) and return
/// apply's refusal exit code. Shared by the pre-manifest gate and the
/// package-manager layout gate below: scan cannot discover PnP packages so
/// it never writes a manifest, and the loud `yarn_pnp_unsupported` refusal
/// must still be reachable without one.
/// The yarn-berry PnP refusal's envelope error text.
const YARN_PNP_UNSUPPORTED: &str = "yarn-berry Plug'n'Play layout is not supported by socket-patch (packages live inside .yarn/cache zips). Use `yarn patch <pkg>` instead.";

fn refuse_yarn_pnp(args: &ApplyArgs) -> i32 {
    if args.common.json {
        let mut env = Envelope::new(Command::Apply);
        env.dry_run = args.common.dry_run;
        env.mark_error(EnvelopeError::new(
            "yarn_pnp_unsupported",
            YARN_PNP_UNSUPPORTED,
        ));
        println!("{}", env.to_pretty_json());
    } else {
        // Errors print even under --silent ("errors only", never
        // "nothing"): exit 1 with no message would be undiagnosable.
        eprintln!("Error: yarn-berry Plug'n'Play layout is not supported.");
        eprintln!(
            "  Packages live inside .yarn/cache/*.zip — socket-patch cannot rewrite them in place."
        );
        eprintln!("  Use `yarn patch <pkg>` instead.");
    }
    1
}

pub async fn run(args: ApplyArgs) -> i32 {
    apply_env_toggles(&args.common);
    let manifest_path = args.common.resolved_manifest_path();

    // No manifest → nothing to apply: a clean exit-0 no-op (load-bearing
    // for CI steps and legacy install hooks that run `apply --silent` on
    // every install).
    // Nothing below this gate is touched — no API client (its config read,
    // stderr advisory and org-slug round-trip), no lock, no `.socket/`.
    if tokio::fs::metadata(&manifest_path).await.is_err() {
        // A yarn-PnP layout refuses loudly even with no manifest: scan
        // cannot discover PnP packages (they live inside .yarn/cache zips),
        // so it never writes one — without this hoisted check the layout
        // gate further down never fired and the ONLY signal a PnP project
        // ever produced was this calm exit-0 noManifest, i.e. a silent
        // no-op. Same envelope + exit semantics as the with-manifest gate.
        // Scoped to runs that would actually crawl this checkout's
        // node_modules: a --global/--global-prefix run or an --ecosystems
        // filter excluding npm never touches it.
        if eco_in_local_scope(&args.common, Ecosystem::Npm)
            && matches!(
                detect_npm_pkg_manager(&args.common.cwd),
                NpmPkgManager::YarnBerryPnP
            )
        {
            return refuse_yarn_pnp(&args);
        }
        // Nothing to apply — but `--vex` may still have something to
        // attest: hosted / vendored patches are wired by the lockfiles (and
        // the `.socket/vendor` ledgers), not the manifest, and a
        // `scan --mode hosted|vendored` or depscan checkout (both modes are
        // manifest-free) has none. Before, this branch returned before VEX
        // generation, so `apply --vex` exited 0 having written NO document
        // (and left a previous run's at the path). Nothing referenced
        // anywhere keeps the historical calm exit 0 (a stale document is
        // still removed); any other VEX failure flips the exit like the
        // with-manifest path. A dry run applies nothing, so it skips
        // generation (main-path parity), and so does `--check`: it is
        // read-only, lock-free and offline-safe — it never crawls, fetches
        // or writes — and the with-manifest path returns from it before any
        // VEX work (an ambient `SOCKET_VEX` must not turn an audit job's
        // `apply --check` into a VEX run).
        // The host line first: the VEX run below prints its own warnings to
        // stderr as it goes, and they read as part of the `--vex` side
        // effect only after the command has said what it did.
        if !args.common.json && !args.common.silent {
            // Names the manifest, not the folder: hosted- and vendored-mode
            // projects have a `.socket/` (their ledgers live under
            // `.socket/vendor/`) and still nothing for `apply` to do.
            println!("No patch manifest found; nothing to apply.");
        }
        let vex_result = if !args.common.dry_run && !args.check && args.vex.vex.is_some() {
            let params = args.vex.to_build_params(None);
            Some(generate_vex_without_manifest(&args.common, &params, &manifest_path).await)
        } else {
            None
        };
        let vex_path = || {
            args.vex
                .vex
                .as_ref()
                .expect("vex_result is Some only when --vex was given")
        };
        if args.common.json {
            let mut env = Envelope::new(Command::Apply);
            env.status = Status::NoManifest;
            env.dry_run = args.common.dry_run;
            match &vex_result {
                Some(ManifestlessVex::Written(summary)) => {
                    env.vex = Some(VexSummary {
                        path: vex_path().display().to_string(),
                        statements: summary.statements,
                        format: "openvex-0.2.0".to_string(),
                        warnings: summary.warnings.clone(),
                    });
                }
                Some(ManifestlessVex::Failed(e)) => {
                    // The discovery diagnostics and the omitted patches are
                    // the only explanation of the failure (why a lockfile
                    // mention is not live wiring, which gate refused what):
                    // same channel as the success path's advisories.
                    env.warnings.extend(e.embedded_warnings());
                    env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                }
                Some(ManifestlessVex::NothingToAttest(warnings)) => {
                    env.warnings.extend(warnings.iter().cloned());
                }
                None => {}
            }
            println!("{}", env.to_pretty_json());
        } else {
            match &vex_result {
                Some(ManifestlessVex::Written(summary)) if !args.common.silent => println!(
                    "{}",
                    crate::commands::vex::format_vex_written(summary.statements, vex_path())
                ),
                // Errors print even under --silent (same as the main path).
                Some(ManifestlessVex::Failed(e)) => e.print_embedded(&args.common),
                Some(ManifestlessVex::NothingToAttest(_)) if !args.common.silent => {
                    println!("{}", crate::commands::vex::format_vex_nothing_to_attest())
                }
                None if !args.common.silent && args.common.dry_run && args.vex.vex.is_some() => {
                    println!(
                        "{}",
                        crate::commands::vex::format_vex_dry_run_skip("applied")
                    );
                }
                _ => {}
            }
        }
        return i32::from(matches!(vex_result, Some(ManifestlessVex::Failed(_))));
    }

    // Read-only Go `replace`-redirect verification for CI / GitHub-App auditing.
    // Branches BEFORE the lock (so concurrent builds don't contend) and
    // before any crawl/fetch; it reads only the manifest + committed copies +
    // `go.mod`, so it is always offline-safe.
    if args.check {
        return run_check(&args, &manifest_path).await;
    }

    // The run's ONE API client — built past both read-only exits above (a
    // hook on a manifest-less project or a CI `--check` never pays its
    // config read, stderr advisory or org-slug round-trip) and BEFORE the
    // lock, so none of that lengthens the lock hold. It serves the staging
    // fetch, the mismatch blob top-up and telemetry.
    let (client, _) = get_api_client_with_overrides(args.common.api_client_overrides()).await;

    // Serialize against concurrent socket-patch runs targeting the same
    // `.socket/` directory; see `socket_patch_core::patch::apply_lock`.
    let lock = match acquire_or_emit(
        &args.common.socket_dir(),
        Command::Apply,
        args.common.json,
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
    ) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

    run_locked(args, manifest_path, &client, lock).await.code
}

/// One patch the nested apply failed: the manifest purl, a stable code
/// (`apply_failed`, `package_not_installed`) and the error text — the same
/// `errorCode` / `error` pair the standalone `apply --json` reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ApplyFailure {
    pub purl: String,
    pub code: String,
    pub error: String,
}

/// What a run of [`run_locked`] reports back. `apply` itself only needs
/// `code`; `get` / `scan --mode agent` fold the rest into their own
/// envelope, because the nested apply never prints JSON (#424).
#[derive(Debug, Default)]
pub(crate) struct ApplyRunReport {
    /// The process exit code.
    pub code: i32,
    /// Per-patch failures.
    pub failures: Vec<ApplyFailure>,
    /// A failure not tied to one patch (unreadable manifest, the yarn PnP
    /// refusal, unavailable patch sources, a failed embedded VEX), as
    /// `(errorCode, error)`. Set only when `code != 0` and `failures`
    /// alone would not explain it.
    pub run_error: Option<(String, String)>,
    /// The package keys apply patched or found already patched, so a
    /// failed run's caller can count exactly what applied. Filled only
    /// when `code != 0`.
    pub applied: Vec<String>,
    /// Non-fatal per-file warnings the caller's envelope must carry: one
    /// `content_mismatch_overwritten` per file the default mismatch policy
    /// overwrote (#1004). A nested apply never prints JSON and is silent
    /// for a JSON caller, so this is their only channel. Filled whenever
    /// the apply loop ran, whatever the exit code.
    pub warnings: Vec<RunWarning>,
}

impl ApplyRunReport {
    fn run_failure(code: i32, error_code: &str, error: impl Into<String>) -> Self {
        Self {
            code,
            run_error: Some((error_code.to_string(), error.into())),
            ..Self::default()
        }
    }
}

/// The per-patch failures of a failed apply loop: every failed result (one
/// per package, the first error wins). With none, what failed the run is
/// the in-scope manifest purls with no installed package that the
/// project's lockfiles do not resolve either; beside a failed result those
/// are only the "no matching installed package" warning, never a failure.
fn collect_apply_failures(
    results: &[ApplyResult],
    unmatched: &[String],
    lockfile_only: &HashSet<String>,
) -> Vec<ApplyFailure> {
    let mut failures: Vec<ApplyFailure> = Vec::new();
    for r in results.iter().filter(|r| !r.success) {
        if failures.iter().any(|f| f.purl == r.package_key) {
            continue;
        }
        failures.push(ApplyFailure {
            purl: r.package_key.clone(),
            code: "apply_failed".to_string(),
            error: r
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string()),
        });
    }
    if !failures.is_empty() {
        return failures;
    }
    for purl in unresolved_purls(unmatched, lockfile_only) {
        failures.push(ApplyFailure {
            code: "package_not_installed".to_string(),
            error: not_installed_detail(&purl).to_string(),
            purl,
        });
    }
    failures
}

/// The locked half of `apply`: everything from the manifest read on — the
/// package-manager layout gate, the apply loop, embedded VEX, output and
/// telemetry — over a `lock` the caller already holds and the caller's
/// `client`. [`run`] takes the lock itself; agent-mode `get` and
/// `scan --mode agent` call this straight after their manifest write, so
/// download → manifest write → apply is ONE lock window (a same-process
/// re-acquire would contend) and the nested apply never builds a second
/// client. `lock` is released explicitly once every mutation is done
/// (output and a possibly slow telemetry POST must not keep a sibling
/// waiting), otherwise on return. The returned [`ApplyRunReport`] carries
/// the exit code plus what failed, for a nested caller's envelope.
pub(crate) async fn run_locked(
    args: ApplyArgs,
    manifest_path: PathBuf,
    client: &ApiClient,
    lock: LockGuard,
) -> ApplyRunReport {
    let telemetry = TelemetryAuth::for_client(client);

    // ONE parse of the manifest for the whole run — the PnP gate and the
    // apply loop (embedded VEX re-reads it by design, after the writes).
    // Apply never modifies it, so a read under the lock is final. `Ok(None)`
    // (vanished since the existence probe above) and a read/parse error take
    // the same exit as every other apply failure.
    let manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            lock.release();
            let code = report_apply_failure(&args, "Invalid manifest", &telemetry).await;
            return ApplyRunReport::run_failure(code, "apply_failed", "Invalid manifest");
        }
        Err(e) => {
            lock.release();
            let error = e.to_string();
            let code = report_apply_failure(&args, &error, &telemetry).await;
            return ApplyRunReport::run_failure(code, "apply_failed", error);
        }
    };

    // Package-manager layout detection. yarn-berry PnP keeps packages
    // inside `.yarn/cache/*.zip` and resolves them via `.pnp.cjs` —
    // the npm crawler can't reach them and rewriting zips is a
    // different operation entirely. Refuse with a clear pointer to
    // `yarn patch` — but only when an npm patch is actually in scope:
    // a polyglot repo's pypi/gem/go patches apply fine under PnP, and a
    // global-tree or non-npm `--ecosystems` run never crawls this
    // checkout's node_modules at all. pnpm, bun and vlt get an
    // informational note; the substantive safety is core's rename-over
    // write (`utils::fs::atomic_write_bytes` never touches the store's
    // shared inode).
    match detect_npm_pkg_manager(&args.common.cwd) {
        NpmPkgManager::YarnBerryPnP => {
            if eco_in_local_scope(&args.common, Ecosystem::Npm) && manifest_targets_npm(&manifest) {
                return ApplyRunReport::run_failure(
                    refuse_yarn_pnp(&args),
                    "yarn_pnp_unsupported",
                    YARN_PNP_UNSUPPORTED,
                );
            }
        }
        NpmPkgManager::Pnpm => {
            if !args.common.json && !args.common.silent {
                eprintln!(
                    "Note: pnpm layout detected. Copy-on-write will keep the global store untouched."
                );
            }
            // Non-fatal — the rename-over write handles the safety. JSON
            // consumers see the layout-detected info in the apply
            // envelope's existing events (no separate event added here yet).
        }
        NpmPkgManager::Bun => {
            if !args.common.json && !args.common.silent {
                if bun_uses_global_store(&args.common.cwd) {
                    // #635: the installed package dirs ARE the shared
                    // store (<cache>/links/...), so copy-on-write cannot
                    // isolate them; core refuses each such package.
                    eprintln!(
                        "Note: bun global store detected (install.globalStore). Packages linked \
                         from the shared Bun cache are used by other projects and will not be \
                         patched; set `globalStore = false` under `[install]` in bunfig.toml \
                         (and unset BUN_INSTALL_GLOBAL_STORE), then reinstall."
                    );
                } else {
                    eprintln!(
                        "Note: bun layout detected. Copy-on-write will keep ~/.bun/install/cache/ untouched."
                    );
                }
            }
            // Same shape as pnpm: bun hard-links from its global
            // install cache by default. The rename-over write handles the
            // safety; this is informational only.
        }
        NpmPkgManager::Vlt => {
            if !args.common.json && !args.common.silent {
                eprintln!(
                    "Note: vlt layout detected. Copy-on-write keeps vlt's shared package store \
                     (<vlt cache>/store/v1) untouched."
                );
            }
            // vlt 1.2 hard-links store files from its machine-wide cache
            // (the Linux default); the rename-over write gives every patched
            // file a private inode, so this is informational only.
        }
        // Exhaustive on purpose (no `_`): a new package-manager layout must
        // make an explicit appearance here — silence is a decision, not a
        // default.
        NpmPkgManager::Npm | NpmPkgManager::YarnClassic | NpmPkgManager::Unknown => {}
    }

    match apply_patches_inner(&args, manifest, client).await {
        Ok(ApplyOutcome {
            success,
            results,
            unmatched,
            lockfile_only,
            run_warnings,
            fallback_skips,
            targeted,
            show_summary,
        }) => {
            let patched_count = results
                .iter()
                .filter(|r| r.success && !r.files_patched.is_empty())
                .count();

            // Applied-with-advisory results: the bytes ARE patched, but a
            // post-write ownership restore was not permitted (core carries
            // it as `error` on a SUCCESSFUL result, where the event mapper
            // rightly ignores it). It rides the run-warning channel so it
            // is never silent.
            let mut run_warnings = run_warnings;
            run_warnings.extend(results.iter().filter_map(|r| {
                let note = r.error.as_deref().filter(|_| r.success)?;
                note.contains(socket_patch_core::patch::apply::OWNERSHIP_NOT_RESTORED_MARKER)
                    .then(|| RunWarning {
                        code: "ownership_not_restored".to_string(),
                        detail: format!("{}: {note}", normalize_purl(&r.package_key)),
                    })
            }));

            // Run-level advisories + best-effort fallback-home skips on the
            // human path: one gated stderr line each. `--silent` is
            // errors-only, and under `--json` the envelope copies below are
            // the machine channel — same gating as scan's run warnings.
            if !args.common.json && !args.common.silent {
                for w in &run_warnings {
                    // Sources-unavailable codes restate the staging layer's
                    // own `Error:` diagnostic (already printed, even under
                    // --silent); they exist for the JSON envelope.
                    if !is_stage_failure_code(&w.code) {
                        eprintln!("Warning: {}", w.detail);
                    }
                }
                for skip in &fallback_skips {
                    eprintln!("Warning: {}", skip.detail());
                }
            }

            // Human per-package report BEFORE the embedded VEX runs, so
            // the VEX step's own notes follow the report instead of
            // landing in the middle of it. Only the JSON envelope needs
            // the VEX result first.
            if !args.common.json && !args.common.silent {
                let cwd = std::fs::canonicalize(&args.common.cwd)
                    .unwrap_or_else(|_| args.common.cwd.clone());
                let block = format_results_block(&results, args.common.dry_run, &cwd);
                let mut block = block.iter().peekable();
                // A nested apply's caller already ended its stdout with a
                // blank line (its listing or table), so the block's leading
                // separator goes to stderr: one blank line on a pipe, the
                // same spacing on a terminal.
                if args.nested.is_some() && block.next_if(|l| l.is_empty()).is_some() {
                    eprintln!();
                }
                for line in block {
                    println!("{line}");
                }
                if args.common.verbose && !results.is_empty() {
                    print_verbose_verification(&results);
                }
                if show_summary {
                    let tally = tally_results(&results);
                    println!();
                    if args.common.dry_run {
                        for line in format_dry_run_summary(&tally, unmatched.len()) {
                            println!("{line}");
                        }
                    } else {
                        println!("{}", format_summary_line(&tally, targeted, unmatched.len()));
                    }
                }
            }

            // Embedded VEX: only on a successful apply and only when
            // `--vex <path>` was passed. Re-read the manifest fresh so
            // verification observes the just-applied on-disk state. The
            // result is folded into the JSON envelope / human output
            // below and flips the exit code on failure (per the
            // fail-the-command contract). `None` => not requested.
            //
            // A dry run applies nothing, so there is no just-applied
            // state to attest: generating here verified the deliberately
            // unapplied tree, spuriously failed the whole command with
            // `no_applicable_patches`, and would write an attestation
            // file during --dry-run. Skip instead.
            let vex_result = if success && !args.common.dry_run && args.vex.vex.is_some() {
                let params = args.vex.to_build_params(Some(client));
                Some(generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await)
            } else {
                None
            };
            let vex_failed = matches!(vex_result, Some(Err(_)));
            // Every mutation — the patches and the VEX attestation — is
            // done: release the lock before output and telemetry.
            lock.release();

            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.dry_run = args.common.dry_run;
                for result in &results {
                    env.record(result_to_event(result, args.common.dry_run));
                    // Mismatch overwrites ride as Skipped warning events
                    // (same pattern as the vendor warnings): the package's
                    // Applied event stands, the warning is per-file.
                    for file in mismatch_overwritten_files(result) {
                        env.record(
                            PatchEvent::new(PatchAction::Skipped, result.package_key.clone())
                                .with_reason(
                                    "content_mismatch_overwritten",
                                    mismatch_event_detail(&file, args.common.dry_run),
                                ),
                        );
                    }
                    // Sidecar records live on the envelope, not on
                    // individual events. Consumers iterate
                    // `envelope.sidecars[]` and JOIN against
                    // `events[]` by `purl` for per-package context.
                    if let Some(ref sidecar) = result.sidecar {
                        env.sidecars.push(sidecar.clone());
                        // A Gradle cache copy's other Info advisories
                        // (daemon, shared user home) ride their own
                        // records.
                        if sidecar
                            .advisory
                            .as_ref()
                            .is_some_and(|a| a.code == SidecarAdvisoryCode::GradleRefreshReverts)
                        {
                            env.sidecars.extend(maven_sidecars::gradle_extra_records(
                                &result.package_key,
                                Path::new(&result.package_path),
                            ));
                        }
                    }
                }
                // Manifest entries that targeted in-scope ecosystems but
                // had no installed package on disk — emit one Skipped
                // event per purl so downstream consumers can surface them.
                for purl in &unmatched {
                    let detail = if lockfile_only.contains(purl) {
                        LOCKFILE_ONLY_DETAIL
                    } else {
                        not_installed_detail(purl)
                    };
                    env.record(
                        PatchEvent::new(PatchAction::Skipped, purl.clone())
                            .with_reason("package_not_installed", detail),
                    );
                }
                // Best-effort gem-env fallback-home copies left unpatched:
                // one non-fatal Skipped event each, with the copy's path
                // and reason. Never a Failed event — the bundle-store copy
                // (the one bundler loads) applied, so the run stands.
                for skip in &fallback_skips {
                    env.record(
                        PatchEvent::new(PatchAction::Skipped, skip.purl.clone())
                            .with_reason("gem_fallback_home_skipped", skip.detail()),
                    );
                }
                // Run-level advisories (the gem config-root containment
                // skip, the sources-unavailable reason): the envelope's
                // `warnings[]` is their machine channel — stderr is
                // suppressed under --json.
                env.warnings.extend(run_warnings.iter().cloned());
                // A token whose org could not be resolved put the run on the
                // proxy (stderr already said so); the embedded `--vex` reuses
                // this client and leaves reporting it to the host.
                env.warnings
                    .extend(crate::commands::vex_sources::api_auth_fallback_warning(
                        client,
                    ));
                if !success {
                    env.mark_partial_failure();
                }
                match &vex_result {
                    Some(Ok(summary)) => {
                        env.vex = Some(VexSummary {
                            path: args
                                .vex
                                .vex
                                .as_ref()
                                .expect("vex_result is Some only when --vex was given")
                                .display()
                                .to_string(),
                            statements: summary.statements,
                            format: "openvex-0.2.0".to_string(),
                            // note_warning suppressed these on stderr under
                            // --json; the envelope copy is their only
                            // surviving channel.
                            warnings: summary.warnings.clone(),
                        });
                    }
                    Some(Err(e)) => {
                        env.warnings.extend(e.embedded_warnings());
                        env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                    }
                    None => {}
                }
                println!("{}", env.to_pretty_json());
            }

            // Human-readable VEX status (JSON mode already folded the
            // outcome into the envelope above).
            if !args.common.json {
                match &vex_result {
                    Some(Ok(summary)) => {
                        if !args.common.silent {
                            println!(
                                "{}",
                                crate::commands::vex::format_vex_written(
                                    summary.statements,
                                    args.vex
                                        .vex
                                        .as_ref()
                                        .expect("vex_result is Some only when --vex was given"),
                                )
                            );
                        }
                    }
                    Some(Err(e)) => e.print_embedded(&args.common),
                    None => {
                        // Only a dry run that itself succeeded skips VEX
                        // *because* of --dry-run; a failed one would have
                        // skipped it anyway.
                        if !args.common.silent
                            && success
                            && args.common.dry_run
                            && args.vex.vex.is_some()
                        {
                            println!(
                                "{}",
                                crate::commands::vex::format_vex_dry_run_skip("applied")
                            );
                        }
                    }
                }
            }

            // Track telemetry
            if success {
                track_patch_applied(patched_count, args.common.dry_run, &telemetry).await;
            } else {
                track_patch_apply_failed(
                    "One or more patches failed to apply",
                    args.common.dry_run,
                    &telemetry,
                )
                .await;
            }

            // The mismatch overwrites, for a nested caller's envelope (the
            // JSON events above are the standalone apply's copy).
            let warnings = mismatch_overwrite_warnings(&results, args.common.dry_run);
            // A requested-but-failed VEX flips an otherwise-successful
            // apply to a non-zero exit (fail-the-command contract).
            if success && !vex_failed {
                return ApplyRunReport {
                    warnings,
                    ..ApplyRunReport::default()
                };
            }
            let failures = if success {
                Vec::new()
            } else {
                collect_apply_failures(&results, &unmatched, &lockfile_only)
            };
            let run_error = if let Some(Err(e)) = &vex_result {
                Some((e.code.to_string(), e.message.clone()))
            } else if failures.is_empty() {
                // Nothing per-patch explains the failure: the run-level
                // reason (sources unavailable) or a generic one.
                Some(
                    run_warnings
                        .iter()
                        .find(|w| is_stage_failure_code(&w.code))
                        .map(|w| (w.code.clone(), w.detail.clone()))
                        .unwrap_or_else(|| {
                            (
                                "apply_failed".to_string(),
                                "One or more patches failed to apply".to_string(),
                            )
                        }),
                )
            } else {
                None
            };
            // Vendor-owned results are skips, not applies.
            let applied = results
                .iter()
                .filter(|r| r.success && r.package_path != VENDOR_OWNED_MARKER)
                .map(|r| r.package_key.clone())
                .collect();
            ApplyRunReport {
                code: 1,
                failures,
                run_error,
                applied,
                warnings,
            }
        }
        Err(e) => {
            lock.release();
            let code = report_apply_failure(&args, &e, &telemetry).await;
            ApplyRunReport::run_failure(code, "apply_failed", e)
        }
    }
}

/// The one apply-failure exit: `apply_failed` telemetry, then the error
/// envelope (`--json`) or an `Error:` line that prints even under
/// `--silent` ("errors only", never "nothing" — exit 1 with no message
/// would be undiagnosable), exit 1. Shared by the manifest read in `run`
/// and `apply_patches_inner`'s `Err` arm.
async fn report_apply_failure(args: &ApplyArgs, error: &str, telemetry: &TelemetryAuth) -> i32 {
    track_patch_apply_failed(error, args.common.dry_run, telemetry).await;
    if args.common.json {
        let mut env = Envelope::new(Command::Apply);
        env.dry_run = args.common.dry_run;
        env.mark_error(EnvelopeError::new("apply_failed", error.to_string()));
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {}", crate::ui::sentence_case(error));
    }
    1
}

/// Synthesize one vendor-owned `Skipped`/`vendored` result per in-scope
/// vendored purl, BEFORE the crawl-driven matching (and its empty-crawl
/// early returns): a vendored package must surface as vendored — never as
/// `package_not_installed` — even when its installed tree is absent (e.g.
/// node_modules wiped; the committed artifact is the source of truth).
/// Sorted for deterministic event order. Returns `(results, matched,
/// vendored_bases)` where `vendored_bases` lets a vendored variant account
/// for its qualified siblings (mirrors vendor's own unmatched accounting).
///
/// A plain fn (not inlined into `apply_patches_inner`) so its temporaries
/// don't ride the async poll frame — that frame sits on the
/// scan→download→apply in-process chain and must fit Windows' 1 MiB
/// main-thread stack in debug builds.
fn synthesize_vendor_owned_results(
    target_manifest_purls: &HashSet<String>,
    vendored_purls: &HashSet<PurlKey>,
) -> (Vec<ApplyResult>, HashSet<String>, HashSet<String>) {
    let is_vendored = |p: &str| purl_keys_cover(vendored_purls, p);
    let mut results: Vec<ApplyResult> = Vec::new();
    let mut matched: HashSet<String> = HashSet::new();
    let mut vendored_targets: Vec<String> = target_manifest_purls
        .iter()
        .filter(|p| is_vendored(p))
        .cloned()
        .collect();
    vendored_targets.sort();
    for purl in vendored_targets {
        results.push(ApplyResult {
            package_key: purl.clone(),
            package_path: VENDOR_OWNED_MARKER.to_string(),
            success: true,
            files_verified: Vec::new(),
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: None,
            sidecar: None,
        });
        matched.insert(purl);
    }
    let vendored_bases: HashSet<String> = matched
        .iter()
        .map(|p| strip_purl_qualifiers(p).to_string())
        .collect();
    (results, matched, vendored_bases)
}

/// Targeted manifest purls that matched nothing: not attempted (or
/// vendor-synthesized) and not a qualified sibling of a vendored variant —
/// those are accounted for by the vendored base, not "not installed".
fn unmatched_purls(
    targets: &HashSet<String>,
    matched: &HashSet<String>,
    vendored_bases: &HashSet<String>,
) -> Vec<String> {
    targets
        .iter()
        .filter(|p| !matched.contains(*p) && !vendored_bases.contains(strip_purl_qualifiers(p)))
        .cloned()
        .collect()
}

/// Everything `apply_patches_inner` reports back to `run`'s output
/// builders (JSON envelope + human summary).
struct ApplyOutcome {
    /// Overall success — `false` fails the command (exit 1 /
    /// `partialFailure`).
    success: bool,
    results: Vec<ApplyResult>,
    /// In-scope manifest purls with no installed package on disk.
    unmatched: Vec<String>,
    /// The subset of [`Self::unmatched`] the project's own lockfiles
    /// resolve: deliberately not installed on this host (a platform-gated
    /// optional dependency, a devDependency under `--omit=dev`), so a calm
    /// skip that never fails the run (#403).
    lockfile_only: HashSet<String>,
    /// Run-level advisories: JSON `warnings[]`, and one gated stderr line
    /// each on the human path (`--silent` = errors only) except the
    /// sources-unavailable codes (already printed by the stager): the gem
    /// config-root containment skip and the sources-unavailable reason
    /// (`run` adds `ownership_not_restored`).
    run_warnings: Vec<RunWarning>,
    /// Gem-env fallback-home copies deliberately left unpatched
    /// (best-effort class): one non-fatal `Skipped` event each in the
    /// envelope, one gated stderr line each on the human path.
    fallback_skips: Vec<FallbackHomeSkip>,
    /// In-scope (`--ecosystems`-filtered) manifest patches: the human
    /// summary's denominator.
    targeted: usize,
    /// Whether the run got far enough to print the human summary (not on
    /// the empty-scope no-op or the sources-unavailable bail, which print
    /// their own one-line outcome).
    show_summary: bool,
}

/// Run-warning code for the `--offline` sources-unavailable bail.
const OFFLINE_MISSING_SOURCES: &str = "offline_missing_sources";
/// Run-warning code for the download-failed sources-unavailable bail.
const SOURCES_DOWNLOAD_FAILED: &str = "sources_download_failed";

/// The sources-unavailable codes: the staging layer already printed their
/// `Error:` line on the human path, so `run` keeps them for JSON only.
fn is_stage_failure_code(code: &str) -> bool {
    code == OFFLINE_MISSING_SOURCES || code == SOURCES_DOWNLOAD_FAILED
}

/// Why nothing could be applied when the patch sources are unavailable —
/// the `--json` envelope's only explanation for its empty, failing run
/// (the staging layer's stderr diagnostic is muted under `--json`).
fn stage_failure_warning(offline: bool) -> RunWarning {
    if offline {
        RunWarning {
            code: OFFLINE_MISSING_SOURCES.to_string(),
            detail: "one or more patches have no local source and --offline is set; run \
                     `socket-patch repair` to download the missing artifacts"
                .to_string(),
        }
    } else {
        RunWarning {
            code: SOURCES_DOWNLOAD_FAILED.to_string(),
            detail: "some patch artifacts could not be downloaded, so no patches were applied"
                .to_string(),
        }
    }
}

/// Per-package counts for the human summary, keyed by manifest purl — so
/// two physical copies of one package count once and the "applied"
/// numerator can never exceed the targeted denominator. Vendor-owned
/// synthesized results (not appliable work) are left out.
#[derive(Debug, Default, PartialEq, Eq)]
struct ApplyTally {
    /// Some copy had files patched (wet run).
    applied: usize,
    /// Not applied, and some copy was already fully patched.
    already: usize,
    /// Some copy could be patched (dry run: not already patched).
    can_patch: usize,
    /// Some copy failed.
    failed: usize,
    /// Owned by `socket-patch vendor` (its committed artifact is the
    /// patch; apply does no work for it).
    vendored: usize,
}

fn tally_results(results: &[ApplyResult]) -> ApplyTally {
    let mut by_purl: std::collections::BTreeMap<&str, Vec<&ApplyResult>> =
        std::collections::BTreeMap::new();
    let mut vendored: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for r in results {
        if r.package_path == VENDOR_OWNED_MARKER {
            vendored.insert(r.package_key.as_str());
            continue;
        }
        by_purl.entry(r.package_key.as_str()).or_default().push(r);
    }
    let mut tally = ApplyTally {
        vendored: vendored
            .iter()
            .filter(|k| !by_purl.contains_key(*k))
            .count(),
        ..ApplyTally::default()
    };
    for copies in by_purl.values() {
        let applied = copies
            .iter()
            .any(|r| r.success && !r.files_patched.is_empty());
        let can_patch = copies
            .iter()
            .any(|r| r.success && !all_files_already_patched(r));
        let already = copies.iter().any(|r| all_files_already_patched(r));
        if applied {
            tally.applied += 1;
        } else if already && !can_patch {
            tally.already += 1;
        }
        if can_patch {
            tally.can_patch += 1;
        }
        if copies.iter().any(|r| !r.success) {
            tally.failed += 1;
        }
    }
    tally
}

/// `Summary: 1 of 2 targeted patches applied, ...` (wet runs). The
/// failed and vendored buckets appear only when non-empty, so the counts
/// account for every targeted patch without cluttering the common case.
fn format_summary_line(tally: &ApplyTally, targeted: usize, not_found: usize) -> String {
    let mut parts = vec![
        format!(
            "{} of {} applied",
            tally.applied,
            plural(targeted, "targeted patch", "targeted patches")
        ),
        format!("{} already patched", tally.already),
    ];
    if tally.vendored > 0 {
        parts.push(format!("{} vendored", tally.vendored));
    }
    if tally.failed > 0 {
        parts.push(format!("{} failed", tally.failed));
    }
    parts.push(format!("{not_found} not found on disk"));
    format!("Summary: {}", parts.join(", "))
}

/// The dry-run summary block: what a wet run would do, per package.
fn format_dry_run_summary(tally: &ApplyTally, not_found: usize) -> Vec<String> {
    let mut lines = vec![
        "Patch verification complete:".to_string(),
        format!(
            "  {} can be patched",
            plural(tally.can_patch, "package", "packages")
        ),
    ];
    if tally.already > 0 {
        lines.push(format!(
            "  {} already patched",
            plural(tally.already, "package", "packages")
        ));
    }
    if tally.failed > 0 {
        lines.push(format!(
            "  {} cannot be patched",
            plural(tally.failed, "package", "packages")
        ));
    }
    if not_found > 0 {
        lines.push(format!(
            "  {} not found on disk",
            plural(not_found, "package", "packages")
        ));
    }
    lines
}

/// One `Patched packages:` line. `copy` names the physical copy when a
/// package has more than one (otherwise the lines are indistinguishable).
fn format_patched_line(purl: &str, copy: Option<&str>, detail: &str) -> String {
    match copy {
        Some(copy) => format!("  {purl} ({copy}, {detail})"),
        None => format!("  {purl} ({detail})"),
    }
}

/// The wet run's `Patched packages:` block (empty when nothing would be
/// listed — no header over an empty list). Dry runs report through
/// [`format_dry_run_summary`] instead.
fn format_results_block(results: &[ApplyResult], dry_run: bool, cwd: &Path) -> Vec<String> {
    if dry_run {
        return Vec::new();
    }
    let mut copies: HashMap<&str, usize> = HashMap::new();
    for r in results {
        *copies.entry(r.package_key.as_str()).or_default() += 1;
    }
    let mut lines: Vec<String> = Vec::new();
    for result in results
        .iter()
        .filter(|r| r.success && r.package_path != VENDOR_OWNED_MARKER)
    {
        let detail = if !result.files_patched.is_empty() {
            // Summarize the per-file strategy used by this package: if
            // everything came from the same source, show just that tag;
            // otherwise list distinct sources.
            let mut tags: Vec<&'static str> =
                result.applied_via.values().map(|v| v.as_tag()).collect();
            tags.sort_unstable();
            tags.dedup();
            if tags.is_empty() {
                "patched".to_string()
            } else {
                format!("via {}", tags.join("+"))
            }
        } else if all_files_already_patched(result) {
            "already patched".to_string()
        } else {
            continue;
        };
        let copy = (copies
            .get(result.package_key.as_str())
            .copied()
            .unwrap_or(0)
            > 1)
        .then(|| crate::ui::display_copy_path(&result.package_path, cwd));
        lines.push(format_patched_line(
            &normalize_purl(&result.package_key),
            copy.as_deref(),
            &detail,
        ));
    }
    if lines.is_empty() {
        return lines;
    }
    let mut block = vec![String::new(), "Patched packages:".to_string()];
    block.extend(lines);
    block
}

/// `--verbose`: every verified file with its status and hashes.
fn print_verbose_verification(results: &[ApplyResult]) {
    println!("\nDetailed verification:");
    for result in results {
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
            if let Some(ref h) = f.current_hash {
                println!("      current:  {h}");
            }
            if let Some(ref h) = f.expected_hash {
                println!("      expected: {}", expected_hash_label(h));
            }
            if let Some(ref h) = f.target_hash {
                println!("      target:   {h}");
            }
        }
    }
}

/// The verbose `expected:` value: a new-file collision carries an empty
/// expected hash (the patch adds the file, so there is no beforeHash; see
/// core `mark_new_file_collision`), shown as `(new file)` instead of a
/// blank line.
fn expected_hash_label(hash: &str) -> &str {
    if hash.is_empty() {
        "(new file)"
    } else {
        hash
    }
}

/// One gem-env fallback-home copy the fan-out skipped best-effort (a
/// bundle-store copy applied; this shared-home copy mismatched or failed
/// to write). Carries what the warning must name: the package, the copy's
/// path, and why.
struct FallbackHomeSkip {
    purl: String,
    path: PathBuf,
    why: String,
}

impl FallbackHomeSkip {
    /// The human/detail text shared by the JSON event reason and the
    /// stderr line.
    fn detail(&self) -> String {
        format!(
            "gem-env home copy at {} was not patched ({}); the project's \
             bundle-path copy — the one bundler loads — is patched. Shared \
             gem homes are machine-wide state: patch them explicitly with \
             `--global` if desired",
            self.path.display(),
            self.why
        )
    }
}

async fn apply_patches_inner(
    args: &ApplyArgs,
    mut manifest: PatchManifest,
    client: &ApiClient,
) -> Result<ApplyOutcome, String> {
    // Resolve patch sources (read `.socket/` directly, or stage an overlay
    // tempdir + download the gap). Shared with `vendor` via fetch_stage.
    let socket_dir = args.common.socket_dir();
    // Partition manifest PURLs by ecosystem up front. The source probes,
    // the offline guard, and the download planner in `fetch_stage` must only
    // consider patches this run can actually apply — the `--ecosystems`
    // filter. An out-of-scope
    // patch with no local source must not fail (or trigger fetches for) a
    // run that will never apply it.
    let manifest_purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let partitioned = partition_purls(&manifest_purls, args.common.ecosystems.as_deref());

    let target_manifest_purls: HashSet<String> = partitioned
        .values()
        .flat_map(|purls| purls.iter().cloned())
        .collect();

    // Narrow the manifest to the `--ecosystems` scope IN PLACE: every later
    // lookup key comes from `partitioned` / `all_packages`, which are
    // already in scope, so nothing downstream needs the full map (and the
    // source probes, the offline guard and the download planner must only
    // ever see in-scope patches).
    manifest
        .patches
        .retain(|purl, _| target_manifest_purls.contains(purl));

    let mut staged = match stage_patch_sources(&args.common, &manifest, &socket_dir, client).await?
    {
        StageOutcome::Ready(s) => s,
        StageOutcome::Unavailable => {
            return Ok(ApplyOutcome {
                success: false,
                results: Vec::new(),
                unmatched: Vec::new(),
                lockfile_only: HashSet::new(),
                run_warnings: vec![stage_failure_warning(args.common.offline)],
                fallback_skips: Vec::new(),
                targeted: target_manifest_purls.len(),
                show_summary: false,
            })
        }
    };

    // Local go: prune `replace`-redirects whose patches were dropped from the
    // manifest (orphans). Done here — before the crawl + the "no packages
    // found" early returns — so orphans are reconciled even when the manifest
    // now lists zero in-scope go patches (the all-removed case). No-op unless
    // local go is in scope.
    reconcile_local_go(&args.common, &target_manifest_purls).await;

    if partitioned.is_empty() {
        // Nothing in scope: the manifest lists no patches (or every patch was
        // filtered out by `--ecosystems`). There is genuinely no work to do,
        // so this is a clean no-op SUCCESS — not a failure: the npm
        // `postinstall` hook runs `apply` on every install, including fresh
        // projects whose manifest has no matching patches yet. Decided
        // BEFORE the ledger read, gem discovery and the crawl — none of which
        // can add work to an empty scope — but AFTER the staging above, which
        // is where `--download-mode` is validated at runtime.
        if !args.common.silent && !args.common.json {
            println!("No patches to apply.");
        }
        return Ok(ApplyOutcome {
            success: true,
            results: Vec::new(),
            unmatched: Vec::new(),
            lockfile_only: HashSet::new(),
            run_warnings: Vec::new(),
            fallback_skips: Vec::new(),
            targeted: 0,
            show_summary: false,
        });
    }

    // Vendor ownership wins for EVERY ecosystem: a purl recorded in
    // `.socket/vendor/state.json` is managed by the explicit `vendor`
    // action — apply must not re-patch its installed tree (or repoint a
    // vendor-owned go `replace` back at `.socket/go-patches/`). Matchable
    // by ledger key, resolved base purl, or qualifier-stripped key so
    // release-variant manifest keys (pypi `?artifact_id=`…) hit too;
    // unreadable state degrades to "nothing vendored" (fail-open).
    // The ledger owns the PROJECT's copies only: a global apply restores
    // and patches the global copy even when the cwd project vendors the
    // same purl (see `project_state_in_scope`).
    let vendored_purls = if crate::commands::project_state_in_scope(&args.common) {
        socket_patch_core::vendor::vendored_purl_keys(&args.common.cwd).await
    } else {
        Default::default()
    };
    let is_vendored = |p: &str| purl_keys_cover(&vendored_purls, p);
    let (mut results, mut matched_manifest_purls, vendored_bases) =
        synthesize_vendor_owned_results(&target_manifest_purls, &vendored_purls);

    let crawler_options = args.common.crawler_options();

    // Gem bundle-store discovery, re-run cheaply (filesystem probes only,
    // no `gem env` shell-out) against the same ambient environment the
    // crawler reads, for two consumers:
    //   * the config-skip advisory — a committed `.bundle/config` whose
    //     BUNDLE_PATH the containment guard refused must surface on the
    //     run's warning channels (JSON `warnings[]`; gated stderr), not
    //     vanish silently;
    //   * the store-class boundary for the gem fan-out below — copies
    //     under a bundle-path store are primary, everything else is a
    //     `gem env` fallback-home copy (best-effort once a store copy
    //     applied).
    // Only when this run actually crawls gems locally: a --global run or
    // one whose `--ecosystems`/manifest scope holds no gem purls never
    // consults the config, so it must not warn about it either.
    let gem_discovery = if partitioned.contains_key(&Ecosystem::Gem)
        && !args.common.global
        && args.common.global_prefix.is_none()
    {
        Some(RubyCrawler::discover_bundle_stores(&args.common.cwd).await)
    } else {
        None
    };
    let gem_store_dirs: &[PathBuf] = gem_discovery
        .as_ref()
        .map(|d| d.stores.as_slice())
        .unwrap_or(&[]);
    let mut run_warnings: Vec<RunWarning> = Vec::new();
    if let Some(value) = gem_discovery
        .as_ref()
        .and_then(|d| d.skipped_config_path.as_deref())
    {
        let (code, detail) = config_path_ignored_warning(value);
        run_warnings.push(RunWarning {
            code: code.to_string(),
            detail,
        });
    }
    let mut fallback_skips: Vec<FallbackHomeSkip> = Vec::new();

    // Multi-copy aware: npm nests genuine duplicates of one `name@version`
    // (nested dupes, diamonds, `file:` dups), so the resolver returns EVERY
    // physical copy per PURL. Patching only one would leave a live,
    // vulnerable copy while reporting success (the multi-copy silent
    // partial). The apply loop below iterates every copy.
    let mut all_packages = find_all_packages_for_purls(
        &partitioned,
        &crawler_options,
        args.common.silent || args.common.json,
    )
    .await;
    // One visit per physical copy: a pnpm workspace member's link into
    // the root store is the same copy the root walk found (#633).
    distinct_npm_copies(&mut all_packages).await;

    if all_packages.is_empty() {
        // Vendored purls are already accounted for (synthesized Skipped/
        // vendored results above); only the remainder is genuinely
        // unmatched. An all-vendored manifest with an absent installed
        // tree is a SUCCESS — the committed artifacts are the patch.
        let unmatched = unmatched_purls(
            &target_manifest_purls,
            &matched_manifest_purls,
            &vendored_bases,
        );
        let mut unmatched = unmatched;
        unmatched.sort();
        let lockfile_only = Box::pin(lockfile_resolved(&args.common, &unmatched)).await;
        let unresolved = unresolved_purls(&unmatched, &lockfile_only);
        // This diagnostic flips the exit code, so it is an error — and it
        // prints even under --silent ("errors only", never a mute exit 1);
        // `--json`
        // mutes stderr and the envelope's `package_not_installed` events
        // are the channel. Lockfile-resolved purls never flip it (#403).
        if !unresolved.is_empty() && args.prints_errors() {
            for line in format_none_installed_error(&unresolved) {
                eprintln!("{line}");
            }
        }
        print_lockfile_only_note(args, &unmatched, &lockfile_only);
        return Ok(ApplyOutcome {
            success: unresolved.is_empty(),
            results,
            unmatched,
            lockfile_only,
            run_warnings,
            fallback_skips,
            targeted: target_manifest_purls.len(),
            show_summary: true,
        });
    }

    // Apply patches
    ensure_blobs_for_mismatches(
        args,
        &manifest,
        &all_packages,
        &vendored_purls,
        &mut staged,
        client,
    )
    .await;
    let sources = staged.as_patch_sources();
    let policy = mismatch_policy(args.force, args.common.strict);
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

    // Maven: the run's JVM caches (which copies a build consumes) and the
    // patch service a member-keyed record's whole-jar swap downloads from,
    // resolved once and only when a Maven patch is in scope.
    let jvm_scope = if partitioned.contains_key(&Ecosystem::Maven) {
        Some(JvmScope::of(&args.common).await)
    } else {
        None
    };
    let jvm_service = jvm_scope.as_ref().map(|_| {
        args.common
            .vendor_service_config(Some(client.clone()), client.uses_public_proxy())
    });

    let jvm_derived = socket_patch_core::patch::jvm_jar::DerivedCache::default();

    // PURL order, so the per-package Error/Warning lines, the results and
    // the `Patched packages:` block read the same on every run (the map is
    // a `HashMap`).
    let mut ordered_packages: Vec<_> = all_packages.iter().collect();
    ordered_packages.sort_unstable_by(|a, b| a.0.cmp(b.0));
    for (purl, pkg_paths) in ordered_packages {
        // The paths carry every resolved physical copy. Release-variant
        // ecosystems install one directory per `package@version` (the
        // variants are jars/wheels inside it) — EXCEPT gem, where bundler's
        // coexisting store layouts (the scoped `<engine>/<abi>/gems` store
        // bundler >= 2 loads beside the flat `gems/` store bundler 1 loads)
        // hold genuinely distinct physical copies of one `gem@version`.
        // npm's branch below iterates every physical copy.
        let pkg_path = pkg_paths
            .first()
            .expect("all_packages only holds PURLs with at least one resolved copy");
        if Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants()) {
            let base_purl = strip_purl_qualifiers(purl).to_string();
            if applied_base_purls.contains(&base_purl) {
                continue;
            }

            let variants = variant_qualified_groups
                .get(&base_purl)
                .cloned()
                .unwrap_or_else(|| vec![base_purl.clone()]);

            // Vendor-owned base: the synthesized results above already
            // reported it; re-attempting here would re-patch a vendored
            // tree and mis-flag `has_errors` when every variant skips.
            if vendored_bases.contains(base_purl.as_str())
                || variants.iter().any(|v| is_vendored(v))
            {
                continue;
            }

            // Maven: every copy a build consumes (`~/.m2` and each Gradle
            // cache, version dirs expanded into their hash dirs), with the
            // Gradle guards — see `apply_maven_base`.
            if let Some(scope) = jvm_scope
                .as_ref()
                .filter(|_| Ecosystem::from_purl(purl) == Some(Ecosystem::Maven))
            {
                let maven = MavenBase {
                    args,
                    manifest: &manifest,
                    base_purl: &base_purl,
                    variants: &variants,
                    pkg_paths,
                    scope,
                    sources: &sources,
                    policy,
                    service: jvm_service.as_ref(),
                    socket_dir: &socket_dir,
                    derived: &jvm_derived,
                };
                let out = Box::pin(apply_maven_base(&maven)).await;
                has_errors |= out.failed;
                matched_manifest_purls.extend(out.matched);
                run_warnings.extend(out.warnings);
                if out.applied {
                    applied_base_purls.insert(base_purl.clone());
                }
                results.extend(out.results);
                continue;
            }

            // Patch EVERY coexisting gem store copy and every PyPI
            // site-packages copy (the npm multi-copy precedent): leaving
            // the other copy pristine is a silent false "applied" for
            // whichever bundler / interpreter loads it, and the per-copy
            // results below make the JSON summary count each patched copy
            // — the signal a second copy exists. The Python crawler
            // resolves one release in several candidate envs when it
            // can't tell which one the project's tool runs (a Pipenv
            // WORKON_HOME venv beside `./.venv`, #529) or which one
            // `sys.path` shadows (the user site beside a system dir in
            // global scope, #501), and rollback already restores every
            // copy. A PyPI path that only ALIASES another (a symlinked
            // site-packages) is collapsed by canonical path, so one
            // install is never patched twice. Maven never reaches here:
            // `apply_maven_base` above patches its every consumed copy.
            let pypi_copies: Vec<PathBuf>;
            let copy_paths: &[PathBuf] = match Ecosystem::from_purl(purl) {
                Some(Ecosystem::Gem) => pkg_paths.as_slice(),
                Some(Ecosystem::Pypi) => {
                    pypi_copies = distinct_install_dirs(pkg_paths).await;
                    pypi_copies.as_slice()
                }
                _ => std::slice::from_ref(pkg_path),
            };

            // Copy CLASS decides FAILURE semantics (never write scope —
            // patching a shared home's vulnerable copy is fine when it
            // works): bundle-path store copies are PRIMARY and loud-fail;
            // `gem env` fallback-home copies (rvm `@global`, system gem
            // dirs — often root-owned, shared machine-wide) are
            // BEST-EFFORT once a store copy applied — a mismatch or write
            // failure there becomes a non-fatal per-copy Skipped warning,
            // because the copy bundler actually loads is already patched.
            // With NO store copy the fallback home IS the primary install
            // (the historic pre-bundle-path layout, and every --global
            // run) and keeps loud-fail parity. Store copies run first so
            // best-effort is decidable when the fallback copies come up.
            let (store_copies, home_copies): (Vec<&PathBuf>, Vec<&PathBuf>) = copy_paths
                .iter()
                .partition(|p| gem_store_dirs.iter().any(|s| p.starts_with(s)));
            let mut any_store_copy_applied = false;

            let mut any_copy_applied = false;
            for (pkg_path, is_store_copy) in store_copies
                .into_iter()
                .map(|p| (p, true))
                .chain(home_copies.into_iter().map(|p| (p, false)))
            {
                let best_effort = !is_store_copy && any_store_copy_applied;
                let mut applied = false;
                // Did at least one variant reach `apply_package_patch`? A
                // variant reaches it only after passing the first-file
                // installed-distribution check (or under `--force`), so an
                // attempted variant *is* the installed distribution — it must
                // not be reported as "package_not_installed" even if the patch
                // itself then fails. Tracks the "matched but failed" case so the
                // failure message is honest and `unmatched` stays accurate.
                // Both are PER COPY: a primary copy that matches no variant
                // must fail loudly even when a sibling copy applied cleanly —
                // that copy is a real on-disk gem some bundler loads.
                let mut attempted = false;

                for variant_purl in &variants {
                    let patch = match manifest.patches.get(variant_purl) {
                        Some(p) => p,
                        None => continue,
                    };

                    // Check the representative file's status (skip when
                    // --force). A mismatch *or* a missing file means this
                    // variant's distribution isn't the one on disk, so skip it —
                    // attempting it would only produce a spurious failure.
                    // Mirrors `select_installed_variants`, used by rollback/get.
                    //
                    // Exempt only an UNQUALIFIED singleton (the common bare
                    // `pkg:gem/name@ver` manifest key): it names no
                    // distribution, so a mismatch there is locally-modified
                    // bytes on the only candidate — exactly what the default
                    // mismatch policy covers (warn + apply the full verified
                    // patched content; `--strict` refuses). Gating it made that
                    // documented policy unreachable for gem/pypi/maven, so it
                    // falls through to `apply_package_patch`, whose
                    // `MismatchPolicy` handles it like the npm branch below.
                    // A QUALIFIED singleton (`?platform=`…) stays gated: it
                    // names one specific distribution, and — because the
                    // crawler drops the installed dir's platform suffix (see
                    // ruby_crawler's `parse_dir_name_version`) — this hash
                    // check is the ONLY thing resolving whether that
                    // distribution is the one on disk. Falling through would
                    // let a lone x86_64-linux record silently overwrite a
                    // darwin install in the Bundler plugin's `--silent`
                    // auto-apply, where the warn half of warn-and-apply is
                    // invisible.
                    if !args.force && (variants.len() > 1 || variants[0] != base_purl) {
                        let first_status = match representative_file(&patch.files) {
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
                    let result = apply_package_patch(
                        variant_purl,
                        pkg_path,
                        &patch.files,
                        &sources,
                        Some(&patch.uuid),
                        args.common.dry_run,
                        policy,
                    )
                    .await;

                    warn_mismatch_overwrites(&result, &args.common);
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
                        results.push(result);
                        // No `break`: apply *every* matching variant. PyPI/gem
                        // have exactly one installed distribution (the rest
                        // hash-mismatch and were skipped above), so this
                        // applies a single variant for them; Maven's coexisting
                        // classifier jars each get patched.
                    } else if best_effort {
                        // A write failure on a BEST-EFFORT fallback-home copy
                        // (root-owned rvm `@global`, a system gem dir) is a
                        // per-copy non-fatal skip, never a run failure: the
                        // bundle-store copy — the one bundler loads — already
                        // applied. The failed result is NOT recorded (its
                        // Failed event would flip `partialFailure`); the skip
                        // rides `fallback_skips` into the envelope instead.
                        fallback_skips.push(FallbackHomeSkip {
                            purl: base_purl.clone(),
                            path: pkg_path.clone(),
                            why: result
                                .error
                                .clone()
                                .unwrap_or_else(|| "unknown error".to_string()),
                        });
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
                        // Errors print even under --silent.
                        if args.prints_errors() {
                            eprintln!(
                                "{}",
                                format_patch_failure(
                                    variant_purl,
                                    result.error.as_deref().unwrap_or("unknown error")
                                )
                            );
                        }
                        results.push(result);
                    }
                }

                if applied {
                    any_copy_applied = true;
                    if is_store_copy {
                        any_store_copy_applied = true;
                    }
                } else if best_effort {
                    // Nothing applied on a best-effort fallback-home copy.
                    // Attempted-but-failed variants already recorded their
                    // per-copy skip above; a copy no variant matched gets
                    // one here — the shared home holds a different (or
                    // locally diverged) distribution, and the copy bundler
                    // loads is patched, so this is advisory, not an error.
                    if !attempted {
                        fallback_skips.push(FallbackHomeSkip {
                            purl: base_purl.clone(),
                            path: pkg_path.clone(),
                            why: "no release variant in the manifest matches this copy".to_string(),
                        });
                    }
                } else {
                    // Nothing applied for this PRIMARY copy. `has_errors` was
                    // already set per-variant above when a variant was
                    // attempted-but-failed; set it here too for the
                    // no-variant-attempted case so both paths fail the command
                    // — per copy, so a second store copy that matches no
                    // variant fails loudly instead of silently staying
                    // vulnerable behind a sibling copy's success.
                    has_errors = true;
                    if !attempted && args.prints_errors() {
                        // No variant matched the installed distribution at all —
                        // the package on disk isn't any known release variant.
                        // (Attempted-but-failed variants already printed their own
                        // per-variant failure line above.) Errors print even
                        // under --silent.
                        eprintln!(
                            "{}",
                            format_patch_failure(&base_purl, "no matching variant found")
                        );
                    }
                }
            }

            if any_copy_applied {
                applied_base_purls.insert(base_purl.clone());
            }
        } else {
            // Vendor-owned purl: already reported by the synthesized
            // Skipped/vendored result above.
            if is_vendored(purl) {
                continue;
            }
            // Non-variant PURLs: direct lookup
            let patch = match manifest.patches.get(purl) {
                Some(p) => p,
                None => continue,
            };

            // Patch EVERY physical copy of this PURL. npm materializes more
            // than one on-disk copy of a single `name@version` (nested
            // dupes, diamonds, `file:` dups); the resolver returns them all
            // (root copy first). A per-copy result means the JSON summary
            // counts each copy — the signal a second copy exists — and a
            // failure on any copy fails the run. (Non-npm single-copy
            // ecosystems simply have a one-element list here.)
            for pkg_path in pkg_paths {
                // Local go redirects to a project-local patched copy under
                // `.socket/go-patches/` wired via a `go.mod` `replace` (the
                // module cache is `go.sum`-verified, so in-place patching
                // can't build). Everything else in this branch (npm, cargo,
                // composer, nuget, …) patches in place via
                // `apply_package_patch`.
                let result =
                    match try_local_go_apply(purl, pkg_path, patch, &sources, &args.common, policy)
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
                                policy,
                            )
                            .await
                        }
                    };

                warn_mismatch_overwrites(&result, &args.common);
                if !result.success {
                    has_errors = true;
                    // Errors print even under --silent.
                    if args.prints_errors() {
                        eprintln!(
                            "{}",
                            format_patch_failure(
                                purl,
                                result.error.as_deref().unwrap_or("unknown error")
                            )
                        );
                    }
                }
                results.push(result);
            }
            matched_manifest_purls.insert(purl.clone());
        }
    }

    // Check if targeted manifest entries had no matches.
    let mut unmatched = unmatched_purls(
        &target_manifest_purls,
        &matched_manifest_purls,
        &vendored_bases,
    );
    unmatched.sort();
    let lockfile_only = if unmatched.is_empty() {
        HashSet::new()
    } else {
        Box::pin(lockfile_resolved(&args.common, &unmatched)).await
    };
    let unresolved = unresolved_purls(&unmatched, &lockfile_only);

    // Nothing matched and some purl has no lock evidence either: this
    // fails the run, so it is an error — and errors print even under
    // --silent. Lockfile-resolved purls are deliberately not installed
    // here, so they never fail it (#403).
    let none_matched = !target_manifest_purls.is_empty()
        && matched_manifest_purls.is_empty()
        && !all_packages.is_empty()
        && !unresolved.is_empty();
    if none_matched {
        has_errors = true;
        if args.prints_errors() {
            for line in format_none_installed_error(&unresolved) {
                eprintln!("{line}");
            }
        }
    } else if !unresolved.is_empty() && !args.common.silent && !args.common.json {
        eprintln!(
            "Warning: {} had no matching installed package:",
            plural(unresolved.len(), "manifest patch", "manifest patches")
        );
        for purl in &unresolved {
            eprintln!("  - {}", normalize_purl(purl));
        }
        if let Some(line) = cargo_fetch_hint(&unresolved) {
            eprintln!("{line}");
        }
    }
    print_lockfile_only_note(args, &unmatched, &lockfile_only);

    // The human summary is printed by `run`, after the per-package list.

    // Note: `apply` deliberately does NOT garbage-collect unused blobs in
    // `.socket/`. GC is the responsibility of `socket-patch repair` /
    // `gc` / `scan --prune`. Keeping apply read-only against `.socket/`
    // means it can run repeatedly (CI dry-runs, deploy hooks) without
    // mutating patch state.

    Ok(ApplyOutcome {
        success: !has_errors,
        results,
        unmatched,
        lockfile_only,
        run_warnings,
        fallback_skips,
        targeted: target_manifest_purls.len(),
        show_summary: true,
    })
}

/// One Maven base purl for [`apply_maven_base`].
struct MavenBase<'a> {
    args: &'a ApplyArgs,
    manifest: &'a PatchManifest,
    base_purl: &'a str,
    /// The manifest's (qualified) purls of this base.
    variants: &'a [String],
    /// Every installed copy the resolver found.
    pkg_paths: &'a [PathBuf],
    scope: &'a JvmScope,
    sources: &'a PatchSources<'a>,
    policy: MismatchPolicy,
    service: Option<&'a socket_patch_core::vendor::VendorServiceConfig>,
    socket_dir: &'a Path,
    /// The run's derived-cache walks, one per Gradle user home.
    derived: &'a socket_patch_core::patch::jvm_jar::DerivedCache,
}

/// What [`apply_maven_base`] reports back to the apply loop.
#[derive(Default)]
struct MavenApplied {
    results: Vec<ApplyResult>,
    /// Variants that reached apply (or a refusal naming them).
    matched: Vec<String>,
    warnings: Vec<RunWarning>,
    /// The run fails (exit 1).
    failed: bool,
    /// Some copy ended patched.
    applied: bool,
}

impl MavenApplied {
    /// A refusal of `purl` with nothing written: a Failed event carrying
    /// `code` and a run warning with the same code.
    fn refuse(&mut self, purl: &str, path: &Path, code: &str, detail: String) {
        self.results.push(ApplyResult {
            package_key: purl.to_string(),
            package_path: path.display().to_string(),
            success: false,
            files_verified: Vec::new(),
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: Some(format!("{code}: {detail}")),
            sidecar: None,
        });
        self.warn(code, detail);
        self.failed = true;
    }

    fn warn(&mut self, code: &str, detail: String) {
        self.warnings.push(RunWarning {
            code: code.to_string(),
            detail,
        });
    }

    /// Record one copy's result: printed when it failed, a Windows
    /// daemon lock surfaced as its own code.
    fn record(&mut self, args: &ApplyArgs, result: ApplyResult) {
        warn_mismatch_overwrites(&result, &args.common);
        if let Some(advisory) = result
            .sidecar
            .as_ref()
            .and_then(|s| s.advisory.as_ref())
            .filter(|a| a.code == SidecarAdvisoryCode::GradleJarLockedByDaemon)
        {
            self.warn("gradle_jar_locked_by_daemon", advisory.message.clone());
        }
        if result.success {
            self.applied = true;
        } else {
            self.failed = true;
            if args.prints_errors() {
                eprintln!(
                    "{}",
                    format_patch_failure(
                        &result.package_key,
                        result.error.as_deref().unwrap_or("unknown error")
                    )
                );
            }
        }
        self.results.push(result);
    }
}

/// Apply one Maven base purl's manifest variants to every installed copy a
/// build consumes (#551): each `~/.m2` version dir and each Gradle
/// `files-2.1` version dir, the latter expanded into the hash directories
/// holding the record's files (`gradle_cache::installed_copies`). A
/// member-keyed record swaps the whole jar instead (`jvm_jar`).
///
/// Gradle guards, each with its own run-warning code:
///
/// * `gradle_verification_metadata_present` — the build verifies its
///   dependencies (`gradle/verification-metadata.xml`), which rewritten
///   cache bytes would fail or, with key-only trust, slip past: every
///   variant is refused, nothing written.
/// * `gradle_build_ignores_m2` — the only copy is in `~/.m2`, which this
///   Gradle-only build never reads: nothing applied, exit 1.
/// * `gradle_ro_cache_shadows` — a copy sits in the read-only cache,
///   which is never written and which Gradle may read first: the writable
///   copies are patched, the run still fails.
/// * `gradle_copy_unexpected_bytes` — a hash dir's file is the pristine
///   download (its sha1 names the dir) but not the bytes the record was
///   made for, or a hash dir holds files no release variant matches: that
///   copy is left alone and the run fails (the build still loads it).
/// * `gradle_transform_copy_stale` — after the write, Gradle still holds a
///   copy derived from the pristine jar (`caches/transforms-*`, `jars-*`):
///   that copy's result fails until it is cleared.
async fn apply_maven_base(m: &MavenBase<'_>) -> MavenApplied {
    use socket_patch_core::crawlers::gradle_cache::{self, is_gradle_version_dir};
    use socket_patch_core::patch::jvm_jar::{self, JarSwap, RecordShape};

    let args = m.args;
    let mut out = MavenApplied::default();
    let variants: Vec<&String> = m
        .variants
        .iter()
        .filter(|v| m.manifest.patches.contains_key(*v))
        .collect();
    let copies = m.scope.split(m.pkg_paths);

    if let Some(metadata) = &m.scope.verification_metadata {
        for variant in &variants {
            out.refuse(
                variant,
                metadata,
                "gradle_verification_metadata_present",
                format!(
                    "{}: {} turns on Gradle dependency verification, which checks the bytes \
                     agent mode would rewrite in the Gradle cache; nothing was written. Use \
                     `--mode vendored` or `--mode hosted` for this build.",
                    normalize_purl(variant),
                    metadata.display()
                ),
            );
            out.matched.push((*variant).clone());
        }
        return out;
    }

    if !copies.read_only.is_empty() {
        let list: Vec<String> = copies
            .read_only
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        out.warn(
            "gradle_ro_cache_shadows",
            format!(
                "{}: the read-only Gradle cache holds a copy ({}) that socket-patch never \
                 writes and Gradle may resolve before the patched user-home copy; rebuild \
                 the read-only cache from a patched user home.",
                normalize_purl(m.base_purl),
                list.join(", ")
            ),
        );
        out.failed = true;
    }
    if copies.consumed.is_empty() {
        if copies.read_only.is_empty() {
            if let Some(m2) = copies.m2_ignored.first() {
                out.refuse(
                    m.base_purl,
                    m2,
                    "gradle_build_ignores_m2",
                    format!(
                        "{}: the only installed copy is in the Maven local repository ({}), \
                         which this Gradle build never reads (no mavenLocal()); nothing was \
                         patched. Run the build once so Gradle caches the artifact, then apply \
                         again.",
                        normalize_purl(m.base_purl),
                        m2.display()
                    ),
                );
            }
        }
        out.matched.extend(variants.iter().map(|v| (*v).clone()));
        return out;
    }

    // A Gradle-only build that reads `~/.m2` (mavenLocal() declared or
    // undetermined) but has no Gradle cache copy: the m2 copy is patched,
    // yet Gradle takes a module from the FIRST declared repository that
    // has it, so when another repository comes before mavenLocal() the
    // next build downloads the pristine jar instead. Gradle never caches
    // a mavenLocal() artifact in files-2.1, so this is also exactly what a
    // build reading the module from mavenLocal() looks like: warn, not
    // refuse. `vex` re-hashes the Gradle cache copy that build makes.
    // Only the `~/.m2` copies are named: a Coursier / Ivy copy beside them
    // (an sbt build in the same root) is no Maven local repository.
    let m2_copies: Vec<String> = copies
        .consumed
        .iter()
        .filter(|c| {
            m.scope
                .env
                .m2_repo
                .as_ref()
                .is_some_and(|m2| c.starts_with(m2))
        })
        .map(|p| p.display().to_string())
        .collect();
    if matches!(
        m.scope.gate,
        Some(socket_patch_core::crawlers::maven_crawler::M2Gate::Declared(_))
            | Some(socket_patch_core::crawlers::maven_crawler::M2Gate::Undetermined(_))
    ) && !m2_copies.is_empty()
        && copies.consumed.iter().all(|c| !is_gradle_version_dir(c))
    {
        out.warn(
            "gradle_m2_may_be_unconsumed",
            format!(
                "{}: the only patched copy is in the Maven local repository ({}). This Gradle                  build reads it only when no repository declared before mavenLocal() has the                  module; otherwise its next build downloads the unpatched jar. Run the build                  once and apply again so the Gradle cache copy is patched too.",
                normalize_purl(m.base_purl),
                m2_copies.join(", ")
            ),
        );
    }

    let multi = variants.len() > 1 || variants.first().is_some_and(|v| **v != m.base_purl);
    let gate_variants = !args.force && multi;
    let mut attempted = false;
    // Gradle hash dirs holding some variant's files, with those variants,
    // and the ones some variant was attempted on: a dir held but never
    // attempted holds bytes no variant was made for.
    let mut held: BTreeMap<PathBuf, Vec<String>> = BTreeMap::new();
    let mut hit: HashSet<PathBuf> = HashSet::new();
    for variant in &variants {
        let patch = &m.manifest.patches[*variant];
        if let RecordShape::Members { jar_leaf } = jvm_jar::classify(variant, &patch.files) {
            // Every consumed copy's jar in ONE swap: one download, one
            // backup, and a failed write puts every copy already swapped
            // back — `~/.m2` and the Gradle cache alike.
            let mut dirs = Vec::new();
            for copy in &copies.consumed {
                for dir in jvm_jar::jar_copies(copy, &jar_leaf) {
                    if maven_sidecars::is_gradle_hash_dir(&dir) {
                        held.entry(dir.clone())
                            .or_default()
                            .push((*variant).clone());
                    }
                    if gate_variants
                        && !matches!(
                            jvm_jar::verify_members(&dir, &jar_leaf, &patch.files).await,
                            VerifyStatus::Ready | VerifyStatus::AlreadyPatched
                        )
                    {
                        continue;
                    }
                    hit.insert(dir.clone());
                    dirs.push(dir);
                }
            }
            if dirs.is_empty() {
                continue;
            }
            attempted = true;
            out.matched.push((*variant).clone());
            let swap = JarSwap {
                purl: variant,
                uuid: &patch.uuid,
                jar_leaf: &jar_leaf,
                files: &patch.files,
                socket_dir: m.socket_dir,
                dry_run: args.common.dry_run,
            };
            match Box::pin(jvm_jar::apply_jar_swap(&swap, &dirs, m.service)).await {
                Err(refusal) => out.refuse(variant, &dirs[0], refusal.code, refusal.message),
                Ok(results) => {
                    for mut result in results {
                        check_derived_copies(&mut out, &mut result, &jar_leaf, args, m.derived)
                            .await;
                        out.record(args, result);
                    }
                }
            }
            continue;
        }

        for copy in &copies.consumed {
            // Leaf record: the hash dirs holding its files (the copy itself
            // for `~/.m2`). A Gradle copy holding NONE of the record's
            // files is not an install of it. One holding only some of them
            // is: its held files are patched, and the keys no hash dir
            // holds are applied against the version dir, where they are
            // not found and fail the copy as they would on `~/.m2` (the
            // build still loads the held jar, so a silent skip would leave
            // it unpatched behind a clean exit). An Ivy copy expands the
            // same way over its module's type dirs (`jars/`, `srcs/`, …).
            let (targets, absent) = if gradle_cache::expands(copy) {
                let detailed = gradle_cache::installed_copies_detailed(copy, &patch.files);
                if detailed.targets.is_empty() {
                    continue;
                }
                // Only a Gradle hash dir's name proves its bytes are the
                // pristine download; an Ivy type dir no variant matches is
                // skipped as a `~/.m2` or Coursier copy is.
                for (dir, _) in &detailed.targets {
                    if maven_sidecars::is_gradle_hash_dir(dir) {
                        held.entry(dir.clone())
                            .or_default()
                            .push((*variant).clone());
                    }
                }
                let absent: HashMap<String, PatchFileInfo> = detailed
                    .missing
                    .iter()
                    .filter_map(|k| patch.files.get(k).map(|info| (k.clone(), info.clone())))
                    .collect();
                (detailed.targets, absent)
            } else {
                (vec![(copy.clone(), patch.files.clone())], HashMap::new())
            };
            let mut copy_attempted = false;
            for (dir, files) in targets {
                if gate_variants {
                    let status = match representative_file(&files) {
                        Some((name, info)) => {
                            Some(verify_file_patch(&dir, name, info).await.status)
                        }
                        None => None,
                    };
                    if !variant_matches_installed(status.as_ref()) {
                        continue;
                    }
                }
                hit.insert(dir.clone());
                out.matched.push((*variant).clone());
                copy_attempted = true;
                if let Some(detail) = unexpected_gradle_bytes(&dir, &files).await {
                    out.refuse(variant, &dir, "gradle_copy_unexpected_bytes", detail);
                    continue;
                }
                attempted = true;
                let mut result = apply_package_patch(
                    variant,
                    &dir,
                    &files,
                    m.sources,
                    Some(&patch.uuid),
                    args.common.dry_run,
                    m.policy,
                )
                .await;
                for leaf in files.keys().filter(|k| k.ends_with(".jar")) {
                    check_derived_copies(&mut out, &mut result, leaf, args, m.derived).await;
                }
                out.record(args, result);
            }
            // The record's keys this Gradle copy lacks, once the variant
            // was attempted on its held files: not found there (a failure
            // under the default and strict policies, a skip under
            // `--force`), as on a `~/.m2` copy missing them.
            if copy_attempted && !absent.is_empty() {
                attempted = true;
                let result = apply_package_patch(
                    variant,
                    copy,
                    &absent,
                    m.sources,
                    Some(&patch.uuid),
                    args.common.dry_run,
                    m.policy,
                )
                .await;
                out.record(args, result);
            }
        }
    }
    // A Gradle hash dir that holds a variant's files but whose bytes no
    // variant was made for: the build loads it unpatched.
    for (dir, holders) in held {
        if hit.contains(&dir) {
            continue;
        }
        let mut holders = holders;
        holders.sort();
        holders.dedup();
        out.matched.extend(holders.iter().cloned());
        out.refuse(
            &holders[0],
            &dir,
            "gradle_copy_unexpected_bytes",
            format!(
                "{}: the Gradle cache copy {} holds bytes none of the manifest's variants ({}) \
                 was made for; it was left unpatched.",
                normalize_purl(m.base_purl),
                dir.display(),
                holders
                    .iter()
                    .map(|v| normalize_purl(v))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    out.matched.sort();
    out.matched.dedup();
    // Nothing attempted. Gradle version dirs and Ivy artifact dirs that
    // hold none of a record's files (a pom-only entry, another classifier)
    // are not installs of it: the variants stay unmatched
    // (`package_not_installed`). A `~/.m2` copy no variant matches is a
    // different distribution: an error, as before.
    let gradle_only = copies.consumed.iter().all(|c| gradle_cache::expands(c));
    if !attempted && !out.failed && !gradle_only {
        out.failed = true;
        if args.prints_errors() {
            eprintln!(
                "{}",
                format_patch_failure(m.base_purl, "no matching variant found")
            );
        }
    }
    out
}

/// `gradle_copy_unexpected_bytes`: a hash dir's file IS the pristine
/// download (its sha1 names the dir) but hashes to neither side of the
/// record — the record was made for other bytes. `None` when every file
/// is expected (or the dir is not a Gradle hash dir).
async fn unexpected_gradle_bytes(
    dir: &Path,
    files: &HashMap<String, PatchFileInfo>,
) -> Option<String> {
    use socket_patch_core::crawlers::gradle_cache::pristine;
    use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
    if !maven_sidecars::is_gradle_hash_dir(dir) {
        return None;
    }
    let hash_dir = dir.file_name()?.to_str()?;
    for (leaf, info) in files {
        let Ok(bytes) = socket_patch_core::utils::fs::read_regular_to_bytes(&dir.join(leaf)).await
        else {
            continue;
        };
        let git = compute_git_sha256_from_bytes(&bytes);
        if pristine(hash_dir, &bytes) && git != info.before_hash && git != info.after_hash {
            return Some(format!(
                "{}: the Gradle cache's pristine download is not the file this patch was made \
                 for (its hash matches neither side of the patch); this copy was left \
                 unpatched.",
                dir.join(leaf).display()
            ));
        }
    }
    None
}

/// After a Gradle hash dir's jar `jar_leaf` ends patched: the copies Gradle
/// derived from the PRISTINE jar (`caches/transforms-*`, `jars-*`,
/// instrumented jars) still serve the old bytes. Any proven one fails the
/// copy's result (`gradle_transform_copy_stale`); a same-named copy whose
/// bytes are neither the pristine nor the patched jar, or a walk cut short,
/// is reported unverified (`gradle_transform_copy_unverified`). Skipped on
/// a dry run and for any other directory.
async fn check_derived_copies(
    out: &mut MavenApplied,
    result: &mut ApplyResult,
    jar_leaf: &str,
    args: &ApplyArgs,
    derived: &socket_patch_core::patch::jvm_jar::DerivedCache,
) {
    let dir = PathBuf::from(&result.package_path);
    let leaf = jar_leaf.trim_start_matches("package/").to_string();
    if args.common.dry_run || !result.success || !maven_sidecars::is_gradle_hash_dir(&dir) {
        return;
    }
    let derived = derived.clone();
    let probe = move || socket_patch_core::patch::jvm_jar::derived_copies_in(&derived, &dir, &leaf);
    let Some(verdict) = tokio::task::spawn_blocking(probe).await.ok().flatten() else {
        return;
    };
    let (stale, unknown, incomplete) = (verdict.stale, verdict.unverified, verdict.incomplete);
    let list = |paths: &[PathBuf]| {
        paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if !stale.is_empty() {
        let detail = format!(
            "{}: Gradle keeps copies derived from the unpatched jar that builds may still \
             load ({}); run `gradle --stop`, delete those directories, and apply again.",
            normalize_purl(&result.package_key),
            list(&stale)
        );
        result.success = false;
        result.error = Some(format!("gradle_transform_copy_stale: {detail}"));
        out.warn("gradle_transform_copy_stale", detail);
    }
    if !unknown.is_empty() || incomplete {
        out.warn(
            "gradle_transform_copy_unverified",
            format!(
                "{}: Gradle keeps copies derived from this jar that could not be matched to \
                 the patched bytes{}{}; until they are cleared they may serve the old code.",
                normalize_purl(&result.package_key),
                if unknown.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", list(&unknown))
                },
                if incomplete {
                    " (the cache walk was incomplete)"
                } else {
                    ""
                }
            ),
        );
    }
}

/// The `package_not_installed` detail of a lockfile-resolved purl.
const LOCKFILE_ONLY_DETAIL: &str =
    "Resolved by the project lockfile but not installed on this host (lockfile-only)";

/// The `unmatched` purls the project's own lockfiles resolve (#403): the
/// package manager resolved them but deliberately did not install them on
/// this host — an `os`/`cpu`-gated optional dependency (`fsevents`,
/// `@esbuild/<os>-<cpu>`), a devDependency under `npm ci --omit=dev`. The
/// tree is in its correct end state, so they are calm skips, as `scan
/// --mode agent` treats lockfile-only packages. Global runs have no project
/// lock, so nothing is lockfile-resolved there, and neither is a Cargo
/// crate ([`lock_resolution_is_calm`]).
async fn lockfile_resolved(common: &GlobalArgs, unmatched: &[String]) -> HashSet<String> {
    if unmatched.is_empty() || common.is_global() {
        return HashSet::new();
    }
    let ctx = crate::commands::context::ProjectContext::new(common);
    let entries = &ctx.locks().await.entries;
    let lock_purls: HashSet<PurlKey> = entries.iter().map(|e| PurlKey::new(&e.purl)).collect();
    unmatched
        .iter()
        .filter(|p| lock_resolution_is_calm(p) && lock_purls.contains(&PurlKey::new(p)))
        .cloned()
        .collect()
}

/// Whether a lock-resolved but uninstalled `purl` can be a calm skip.
/// Not for Cargo (#616): cargo leaves no locked crate out on purpose —
/// `cargo fetch` unpacks every `Cargo.lock` entry, target-gated ones
/// included — so a locked crate missing from `$CARGO_HOME/registry/src`
/// was just not fetched yet (a cold CI cache, a pruned `registry/src`),
/// and the next `cargo build` downloads or re-extracts it UNPATCHED.
fn lock_resolution_is_calm(purl: &str) -> bool {
    Ecosystem::from_purl(purl) != Some(Ecosystem::Cargo)
}

/// The `package_not_installed` detail of an unmatched purl the lock does
/// not calmly account for: Cargo's carries the `cargo fetch` remedy.
fn not_installed_detail(purl: &str) -> &'static str {
    if Ecosystem::from_purl(purl) == Some(Ecosystem::Cargo) {
        CARGO_NOT_FETCHED_DETAIL
    } else {
        "No installed package matches this PURL"
    }
}

/// [`not_installed_detail`] for a Cargo crate.
const CARGO_NOT_FETCHED_DETAIL: &str =
    "No unpacked crate source matches this PURL; run `cargo fetch` first so the crate is in \
     the Cargo registry cache, then re-run apply";

/// The `unmatched` purls with no lock evidence (sorted input, sorted
/// output): the ones that can still fail an all-miss run.
fn unresolved_purls(unmatched: &[String], lockfile_only: &HashSet<String>) -> Vec<String> {
    unmatched
        .iter()
        .filter(|p| !lockfile_only.contains(*p))
        .cloned()
        .collect()
}

/// The human note for lockfile-resolved purls (never an error; muted by
/// `--silent` and `--json`).
fn print_lockfile_only_note(
    args: &ApplyArgs,
    unmatched: &[String],
    lockfile_only: &HashSet<String>,
) {
    if lockfile_only.is_empty() || args.common.silent || args.common.json {
        return;
    }
    eprintln!(
        "Note: {} not installed on this host (resolved by the project lockfile; skipped):",
        plural(
            lockfile_only.len(),
            "manifest patch targets a package",
            "manifest patches target packages"
        )
    );
    for purl in unmatched.iter().filter(|p| lockfile_only.contains(*p)) {
        eprintln!("  - {}", normalize_purl(purl));
    }
}

/// `Error: Failed to patch <purl>: <why>` (stderr, even under --silent).
fn format_patch_failure(purl: &str, why: &str) -> String {
    format!("Error: Failed to patch {purl}: {why}")
}

/// The failing "no targeted patch matched an installed package" report:
/// the error line, the unmatched purls, and the usual remedy.
fn format_none_installed_error(unmatched: &[String]) -> Vec<String> {
    let mut lines = vec![if unmatched.is_empty() {
        "Error: None of the targeted manifest patches matched an installed package.".to_string()
    } else if unmatched.len() == 1 {
        "Error: The targeted manifest patch matched no installed package:".to_string()
    } else {
        format!(
            "Error: None of the {} targeted manifest patches matched an installed package:",
            unmatched.len()
        )
    }];
    lines.extend(
        unmatched
            .iter()
            .map(|p| format!("  - {}", normalize_purl(p))),
    );
    lines.push(
        "Check that the packages are installed and --cwd points to the right directory."
            .to_string(),
    );
    if let Some(line) = cargo_fetch_hint(unmatched) {
        lines.push(line.to_string());
    }
    lines
}

/// The `cargo fetch` remedy line when any of `unmatched` is a Cargo crate
/// (#616): cargo unpacks locked crates only when it fetches or builds.
fn cargo_fetch_hint(unmatched: &[String]) -> Option<&'static str> {
    unmatched
        .iter()
        .any(|p| Ecosystem::from_purl(p) == Some(Ecosystem::Cargo))
        .then_some(
            "Cargo crates are patched in the registry cache: run `cargo fetch` first so every \
             locked crate is unpacked there, then re-run apply.",
        )
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

    /// A new-file collision's empty expected hash reads `(new file)` in the
    /// verbose summary; a real hash is shown as is.
    #[test]
    fn expected_hash_label_names_a_new_file_collision() {
        assert_eq!(expected_hash_label(""), "(new file)");
        let h = "a".repeat(64);
        assert_eq!(expected_hash_label(&h), h);
    }

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
        applied_via.insert("package/b.js".to_string(), CoreAppliedVia::Diff);
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
        assert_eq!(by_path["package/b.js"]["appliedVia"], "diff");
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
                status: *status,
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
    /// exactly like a `HashMismatch`, never reaching `apply_package_patch`
    /// as a spurious `Failed` event. This pins the apply-side decision to the same
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

    /// Regression (twin of core's `select_installed_variants` fix): the
    /// representative file that decides "is this variant the installed
    /// distribution?" must never be a NEW file (empty `beforeHash`) — a
    /// new file verifies `Ready` against ANY environment, so a
    /// `HashMap`-iteration-ordered pick let a variant describing a
    /// different, NOT-installed distribution randomly match and get
    /// attempted (nondeterministic spurious failures, or wrong-variant
    /// content overwrites under the default mismatch policy). 64 rounds
    /// with fresh maps so the randomized per-instance iteration order is
    /// actually exercised.
    #[tokio::test]
    async fn representative_never_picks_new_file() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("mod.py"), b"installed wheel content\n")
            .await
            .unwrap();

        for round in 0..64 {
            let mut files: HashMap<String, PatchFileInfo> = HashMap::new();
            // NEW file (empty beforeHash): verifies Ready everywhere; must
            // never drive selection. Name varies per round so hash order
            // varies too.
            files.insert(
                format!("aaa_new_{round}.py"),
                PatchFileInfo {
                    before_hash: String::new(),
                    after_hash: "1".repeat(64),
                },
            );
            // Content-modifying file whose beforeHash does NOT match the
            // on-disk bytes: the discriminating evidence that this variant
            // is NOT the installed distribution.
            files.insert(
                "mod.py".to_string(),
                PatchFileInfo {
                    before_hash: "2".repeat(64),
                    after_hash: "3".repeat(64),
                },
            );

            let status = match representative_file(&files) {
                Some((name, info)) => Some(verify_file_patch(dir.path(), name, info).await.status),
                None => None,
            };
            assert!(
                !variant_matches_installed(status.as_ref()),
                "round {round}: non-installed variant matched — the representative \
                 pick selected the new file instead of the discriminating one"
            );
        }
    }

    /// One-record manifest fixture for the `mismatch_blob_gaps` tests.
    fn manifest_with_record(key: &str, files: HashMap<String, PatchFileInfo>) -> PatchManifest {
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            key.to_string(),
            PatchRecord {
                uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: HashMap::new(),
                description: "fixture".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
        manifest
    }

    /// Regression: release-variant ecosystems key the manifest by
    /// QUALIFIED purl (`?artifact_id=`…) while the crawler keys
    /// `all_packages` by BASE purl, so the exact-key lookup in the
    /// mismatch-blob probe missed every PyPI/Gem/Maven record — the
    /// afterHash blobs that the default (Warn) mismatch policy needs were
    /// never prefetched, and a locally-modified file in a variant package
    /// failed to apply under the default diff download mode instead of
    /// being warn-overwritten.
    #[tokio::test]
    async fn mismatch_blob_gaps_matches_qualified_variant_keys() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        // Representative file (lex-smallest, non-empty beforeHash) matches
        // the installed distribution, so the apply loop WILL attempt this
        // variant...
        tokio::fs::write(pkg.join("aaa.py"), b"pristine\n")
            .await
            .unwrap();
        // ...but a second file was locally modified: under the default
        // Warn policy it is overwritten with the full afterHash blob, so
        // that blob must be prefetched.
        tokio::fs::write(pkg.join("zzz.py"), b"locally modified\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "aaa.py".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"pristine\n"),
                after_hash: "1".repeat(64),
            },
        );
        files.insert(
            "zzz.py".to_string(),
            PatchFileInfo {
                before_hash: "2".repeat(64),
                after_hash: "3".repeat(64),
            },
        );
        let manifest = manifest_with_record(
            "pkg:pypi/foo@1.0.0?artifact_id=foo-1.0.0-py3-none-any.whl",
            files,
        );
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:pypi/foo@1.0.0".to_string(), vec![pkg.clone()]);

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(
            needed,
            HashSet::from(["3".repeat(64)]),
            "the qualified variant's mismatched file must have its afterHash blob queued"
        );
    }

    /// A Maven GAV in two caches: only the second (Coursier) copy holds the
    /// classifier jar, with a locally modified sibling file. The variant
    /// gate runs per copy, as the apply loop attempts it per copy, so the
    /// sibling's afterHash blob is queued although the first copy lacks the
    /// classifier.
    #[tokio::test]
    async fn mismatch_blob_gaps_gates_each_maven_copy() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let dir = tempfile::tempdir().unwrap();
        let m2 = dir.path().join("m2/g/a/1");
        let csr = dir.path().join("csr/https/h/g/a/1");
        for copy in [&m2, &csr] {
            tokio::fs::create_dir_all(copy).await.unwrap();
            tokio::fs::write(copy.join("a-1.jar"), b"jar\n")
                .await
                .unwrap();
        }
        tokio::fs::write(csr.join("a-1-tests.jar"), b"tests\n")
            .await
            .unwrap();
        tokio::fs::write(csr.join("z-tests.txt"), b"locally modified\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let mut base = HashMap::new();
        base.insert(
            "a-1.jar".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"jar\n"),
                after_hash: "1".repeat(64),
            },
        );
        let mut manifest = manifest_with_record("pkg:maven/g/a@1", base);
        let mut tests = HashMap::new();
        tests.insert(
            "a-1-tests.jar".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"tests\n"),
                after_hash: "2".repeat(64),
            },
        );
        tests.insert(
            "z-tests.txt".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"pristine\n"),
                after_hash: "3".repeat(64),
            },
        );
        manifest.patches.insert(
            "pkg:maven/g/a@1?classifier=tests".to_string(),
            PatchRecord {
                uuid: "22222222-2222-4222-8222-222222222222".to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files: tests,
                vulnerabilities: HashMap::new(),
                description: "fixture".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:maven/g/a@1".to_string(), vec![m2.clone(), csr.clone()]);
        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(needed, HashSet::from(["3".repeat(64)]));
    }

    /// The counterpart guard: a sibling variant that does NOT describe the
    /// installed distribution (its representative file mismatches) is
    /// skipped by the apply loop, so its blobs must not be queued — that
    /// would mean spurious downloads and spurious `--offline` "will fail
    /// to apply" warnings on every run. An unqualified singleton is
    /// always attempted (see the singleton test below), so the group
    /// carries an installed wheel sibling alongside the non-installed
    /// sdist. Under `--force` every variant IS attempted, so then its
    /// blob must be queued.
    #[tokio::test]
    async fn mismatch_blob_gaps_skips_non_installed_variant_unless_forced() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        tokio::fs::write(pkg.join("aaa.py"), b"pristine\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        // Installed wheel variant: representative matches the on-disk
        // bytes (Ready — no mismatch, so nothing to queue for it).
        let mut wheel_files = HashMap::new();
        wheel_files.insert(
            "aaa.py".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"pristine\n"),
                after_hash: "1".repeat(64),
            },
        );
        let mut manifest = manifest_with_record(
            "pkg:pypi/foo@1.0.0?artifact_id=foo-1.0.0-py3-none-any.whl",
            wheel_files,
        );
        // The sdist sibling's only file has a different base than the
        // on-disk bytes: representative mismatch → not installed.
        let mut sdist_files = HashMap::new();
        sdist_files.insert(
            "aaa.py".to_string(),
            PatchFileInfo {
                before_hash: "4".repeat(64),
                after_hash: "5".repeat(64),
            },
        );
        manifest.patches.insert(
            "pkg:pypi/foo@1.0.0?artifact_id=foo-1.0.0.tar.gz".to_string(),
            PatchRecord {
                uuid: "22222222-2222-4222-8222-222222222222".to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files: sdist_files,
                vulnerabilities: HashMap::new(),
                description: "fixture".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:pypi/foo@1.0.0".to_string(), vec![pkg.clone()]);

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert!(
            needed.is_empty(),
            "a non-installed sibling variant is never attempted, so its blobs must not be queued: {needed:?}"
        );

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, true).await;
        assert_eq!(
            needed,
            HashSet::from(["5".repeat(64)]),
            "--force attempts every variant, so the mismatch blob is needed"
        );
    }

    /// An UNQUALIFIED singleton release-variant base is always attempted
    /// by the apply loop (the mismatch-policy fall-through: it names no
    /// distribution, so a mismatch means locally-modified bytes), so its
    /// mismatched file's afterHash blob must be queued even though the
    /// representative file mismatches — otherwise the default Warn policy
    /// has no bytes to overwrite with under `--download-mode diff` and
    /// the apply fails instead of warn-overwriting.
    #[tokio::test]
    async fn mismatch_blob_gaps_singleton_mismatch_queued() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        tokio::fs::write(pkg.join("aaa.rb"), b"locally modified\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "aaa.rb".to_string(),
            PatchFileInfo {
                before_hash: "4".repeat(64),
                after_hash: "5".repeat(64),
            },
        );
        let manifest = manifest_with_record("pkg:gem/foo@1.0.0", files);
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:gem/foo@1.0.0".to_string(), vec![pkg.clone()]);

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(
            needed,
            HashSet::from(["5".repeat(64)]),
            "a singleton base falls through to the mismatch policy, so its blob is needed"
        );
    }

    /// #646 review: a Gradle copy is a `files-2.1` version dir whose files
    /// sit one level down in `<sha1>/` hash dirs. A drifted jar there (not
    /// pristine, not the record's beforeHash) must queue its afterHash
    /// blob as a drifted `~/.m2` copy does: the default Warn policy
    /// overwrites it with the full blob.
    #[tokio::test]
    async fn mismatch_blob_gaps_probes_gradle_hash_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let version = dir
            .path()
            .join(".gradle/caches/modules-2/files-2.1/com.example/victim/1.0");
        let hash = version.join("0123456789abcdef0123456789abcdef01234567");
        tokio::fs::create_dir_all(&hash).await.unwrap();
        tokio::fs::write(hash.join("victim-1.0.jar"), b"older patch bytes")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let mut files = HashMap::new();
        files.insert(
            "package/victim-1.0.jar".to_string(),
            PatchFileInfo {
                before_hash: "4".repeat(64),
                after_hash: "5".repeat(64),
            },
        );
        let manifest = manifest_with_record("pkg:maven/com.example/victim@1.0", files);
        let mut all_packages = HashMap::new();
        all_packages.insert(
            "pkg:maven/com.example/victim@1.0".to_string(),
            vec![version.clone()],
        );
        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(needed, HashSet::from(["5".repeat(64)]));
    }

    /// A QUALIFIED singleton (`?platform=`…) keeps the
    /// installed-distribution gate — it names one specific distribution,
    /// and the apply loop skips it when the representative file
    /// mismatches (the crawler drops the gem dir's platform suffix, so
    /// this hash check is the only platform resolution). Its blobs must
    /// not be queued: that would mean spurious downloads and spurious
    /// `--offline` warnings for a variant the loop never attempts. Under
    /// `--force` it IS attempted, so then the blob is needed.
    #[tokio::test]
    async fn mismatch_blob_gaps_qualified_singleton_gated_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        tokio::fs::write(pkg.join("aaa.rb"), b"darwin bytes\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "aaa.rb".to_string(),
            PatchFileInfo {
                before_hash: "4".repeat(64),
                after_hash: "5".repeat(64),
            },
        );
        let manifest = manifest_with_record("pkg:gem/foo@1.0.0?platform=x86_64-linux", files);
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:gem/foo@1.0.0".to_string(), vec![pkg.clone()]);

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert!(
            needed.is_empty(),
            "a qualified singleton whose distribution is not on disk is never attempted, \
             so its blobs must not be queued: {needed:?}"
        );

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, true).await;
        assert_eq!(
            needed,
            HashSet::from(["5".repeat(64)]),
            "--force attempts the qualified singleton, so the mismatch blob is needed"
        );
    }

    /// A vendor-owned base is unconditionally skipped by the apply loop
    /// (its result is synthesized up front), so its drifted installed
    /// files must not queue blobs — that meant a spurious "Downloading N
    /// full patched blob(s)" fetch online and a spurious "will fail to
    /// apply" warning under `--offline` for a package apply never
    /// touches. The same fixture queues without the vendor claim
    /// (anti-vacuity: the mismatch is real).
    #[tokio::test]
    async fn mismatch_blob_gaps_vendored_base_never_queued() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        tokio::fs::write(pkg.join("aaa.rb"), b"drifted\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "aaa.rb".to_string(),
            PatchFileInfo {
                before_hash: "4".repeat(64),
                after_hash: "5".repeat(64),
            },
        );
        let manifest = manifest_with_record("pkg:gem/foo@1.0.0", files);
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:gem/foo@1.0.0".to_string(), vec![pkg.clone()]);

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(
            needed,
            HashSet::from(["5".repeat(64)]),
            "without a vendor claim the drifted singleton must queue (fixture sanity)"
        );

        let vendored = HashSet::from([PurlKey::new("pkg:gem/foo@1.0.0")]);
        let needed = mismatch_blob_gaps(&manifest, &all_packages, &vendored, &blobs, false).await;
        assert!(
            needed.is_empty(),
            "a vendor-owned base is never attempted, so its blobs must not be queued: {needed:?}"
        );

        let needed = mismatch_blob_gaps(&manifest, &all_packages, &vendored, &blobs, true).await;
        assert!(
            needed.is_empty(),
            "--force does not override vendor ownership in the apply loop, so nothing is queued: {needed:?}"
        );
    }

    /// Exact-key (npm-shaped) probing keeps working: unqualified manifest
    /// keys match the crawled purl directly, with no installed-variant
    /// gate (the npm branch always attempts).
    #[tokio::test]
    async fn mismatch_blob_gaps_exact_key_still_probed() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("pkg");
        tokio::fs::create_dir_all(&pkg).await.unwrap();
        tokio::fs::write(pkg.join("index.js"), b"locally modified\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "6".repeat(64),
                after_hash: "7".repeat(64),
            },
        );
        let manifest = manifest_with_record("pkg:npm/foo@1.0.0", files);
        let mut all_packages = HashMap::new();
        all_packages.insert("pkg:npm/foo@1.0.0".to_string(), vec![pkg.clone()]);

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(needed, HashSet::from(["7".repeat(64)]));
    }

    /// Regression (multi-copy): npm materializes genuine duplicates of one
    /// `name@version` and the apply loop patches every copy, so the probe
    /// must scan every copy too — copies drift independently. Before the
    /// fix only the FIRST copy was probed: a clean root copy masked a
    /// locally-modified nested duplicate, its afterHash blob was never
    /// queued, and the nested copy failed to apply under the default
    /// warn-and-overwrite policy in diff download mode.
    #[tokio::test]
    async fn mismatch_blob_gaps_probes_every_copy() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let dir = tempfile::tempdir().unwrap();
        // First copy: pristine (matches beforeHash — no blob needed).
        let root_copy = dir.path().join("root");
        tokio::fs::create_dir_all(&root_copy).await.unwrap();
        tokio::fs::write(root_copy.join("index.js"), b"pristine\n")
            .await
            .unwrap();
        // Second copy: locally modified (matches neither hash).
        let nested_copy = dir.path().join("nested");
        tokio::fs::create_dir_all(&nested_copy).await.unwrap();
        tokio::fs::write(nested_copy.join("index.js"), b"locally modified\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"pristine\n"),
                after_hash: "8".repeat(64),
            },
        );
        let manifest = manifest_with_record("pkg:npm/foo@1.0.0", files);
        let mut all_packages = HashMap::new();
        all_packages.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            vec![root_copy.clone(), nested_copy.clone()],
        );

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(
            needed,
            HashSet::from(["8".repeat(64)]),
            "the drifted second copy must queue the blob even though the first copy is clean"
        );
    }

    /// Regression (#538 review): two PyPI copies of one release holding
    /// DIFFERENT wheels. The apply loop gates each variant per copy, so the
    /// variant installed only in the SECOND copy is attempted there; its
    /// locally-modified non-representative file needs the full afterHash
    /// blob. Gating against the first copy alone skipped that variant and
    /// left the blob unfetched, so warn-and-apply failed on the second copy.
    #[tokio::test]
    async fn mismatch_blob_gaps_gates_pypi_variants_per_copy() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

        let dir = tempfile::tempdir().unwrap();
        // Copy A: the wheel's distribution, pristine.
        let copy_a = dir.path().join("a");
        tokio::fs::create_dir_all(&copy_a).await.unwrap();
        tokio::fs::write(copy_a.join("aaa.py"), b"wheel\n")
            .await
            .unwrap();
        // Copy B: the sdist's distribution, with a locally modified
        // non-representative file.
        let copy_b = dir.path().join("b");
        tokio::fs::create_dir_all(&copy_b).await.unwrap();
        tokio::fs::write(copy_b.join("aaa.py"), b"sdist\n")
            .await
            .unwrap();
        tokio::fs::write(copy_b.join("zzz.py"), b"locally modified\n")
            .await
            .unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut wheel_files = HashMap::new();
        wheel_files.insert(
            "aaa.py".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"wheel\n"),
                after_hash: "1".repeat(64),
            },
        );
        let mut manifest = manifest_with_record(
            "pkg:pypi/foo@1.0.0?artifact_id=foo-1.0.0-py3-none-any.whl",
            wheel_files,
        );
        let mut sdist_files = HashMap::new();
        sdist_files.insert(
            "aaa.py".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"sdist\n"),
                after_hash: "2".repeat(64),
            },
        );
        sdist_files.insert(
            "zzz.py".to_string(),
            PatchFileInfo {
                before_hash: "3".repeat(64),
                after_hash: "4".repeat(64),
            },
        );
        manifest.patches.insert(
            "pkg:pypi/foo@1.0.0?artifact_id=foo-1.0.0.tar.gz".to_string(),
            PatchRecord {
                uuid: "22222222-2222-4222-8222-222222222222".to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files: sdist_files,
                vulnerabilities: HashMap::new(),
                description: "fixture".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
        let mut all_packages = HashMap::new();
        all_packages.insert(
            "pkg:pypi/foo@1.0.0".to_string(),
            vec![copy_a.clone(), copy_b.clone()],
        );

        let needed =
            mismatch_blob_gaps(&manifest, &all_packages, &HashSet::new(), &blobs, false).await;
        assert_eq!(
            needed,
            HashSet::from(["4".repeat(64)]),
            "the second copy's variant must queue its mismatched file's blob"
        );
    }

    /// A variant with no content-modifying files (only new files) has
    /// nothing to disqualify it: no representative, treated as a match —
    /// the same no-files contract as core's `select_installed_variants`.
    #[test]
    fn representative_none_when_only_new_files() {
        let mut files: HashMap<String, PatchFileInfo> = HashMap::new();
        files.insert(
            "new.py".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: "1".repeat(64),
            },
        );
        assert!(representative_file(&files).is_none());
        assert!(representative_file(&HashMap::new()).is_none());
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

    // ── human output formatters ──────────────────────────────────────────

    fn copy_at(path: &str, status: VerifyStatus, patched: bool) -> ApplyResult {
        let mut r = sample_applied(status);
        r.package_key = "pkg:npm/nuxt@4.5.0".to_string();
        r.package_path = path.to_string();
        if !patched {
            r.files_patched.clear();
            r.applied_via.clear();
        }
        r
    }

    #[test]
    fn summary_line_singular_and_plural() {
        let one = ApplyTally {
            applied: 1,
            ..ApplyTally::default()
        };
        assert_eq!(
            format_summary_line(&one, 1, 0),
            "Summary: 1 of 1 targeted patch applied, 0 already patched, 0 not found on disk"
        );
        let mixed = ApplyTally {
            applied: 1,
            already: 2,
            ..ApplyTally::default()
        };
        assert_eq!(
            format_summary_line(&mixed, 4, 1),
            "Summary: 1 of 4 targeted patches applied, 2 already patched, 1 not found on disk"
        );
        assert_eq!(
            format_summary_line(&ApplyTally::default(), 0, 0),
            "Summary: 0 of 0 targeted patches applied, 0 already patched, 0 not found on disk"
        );
        let failed = ApplyTally {
            failed: 1,
            ..ApplyTally::default()
        };
        assert_eq!(
            format_summary_line(&failed, 1, 0),
            "Summary: 0 of 1 targeted patch applied, 0 already patched, 1 failed, 0 not found on disk"
        );
    }

    #[test]
    fn tally_counts_each_manifest_purl_once_across_copies() {
        // Two physical copies of one purl, both patched: 1 applied, never
        // "2/1 targeted patches applied".
        let results = vec![
            copy_at("/p/node_modules/nuxt", VerifyStatus::Ready, true),
            copy_at(
                "/p/node_modules/vite/node_modules/nuxt",
                VerifyStatus::Ready,
                true,
            ),
        ];
        let t = tally_results(&results);
        assert_eq!(t.applied, 1);
        assert_eq!(t.already, 0);
        assert_eq!(t.failed, 0);
        assert!(format_summary_line(&t, 1, 0).starts_with("Summary: 1 of 1 targeted patch "));
    }

    #[test]
    fn tally_already_patched_failed_and_vendored() {
        let already = copy_at("/p/a", VerifyStatus::AlreadyPatched, false);
        let mut failed = sample_applied(VerifyStatus::Ready);
        failed.package_key = "pkg:npm/broken@1.0.0".into();
        failed.success = false;
        failed.files_patched.clear();
        let mut vendored = sample_applied(VerifyStatus::Ready);
        vendored.package_key = "pkg:npm/vend@1.0.0".into();
        vendored.package_path = VENDOR_OWNED_MARKER.into();
        let t = tally_results(&[already, failed, vendored]);
        assert_eq!(
            t,
            ApplyTally {
                applied: 0,
                already: 1,
                can_patch: 0,
                failed: 1,
                vendored: 1,
            }
        );
        assert_eq!(
            format_summary_line(&t, 3, 0),
            "Summary: 0 of 3 targeted patches applied, 1 already patched, 1 vendored, 1 failed, \
             0 not found on disk"
        );
        assert_eq!(tally_results(&[]), ApplyTally::default());
    }

    #[test]
    fn dry_run_summary_lists_every_nonzero_bucket() {
        let t = ApplyTally {
            can_patch: 1,
            already: 2,
            failed: 1,
            applied: 0,
            vendored: 0,
        };
        assert_eq!(
            format_dry_run_summary(&t, 3),
            vec![
                "Patch verification complete:",
                "  1 package can be patched",
                "  2 packages already patched",
                "  1 package cannot be patched",
                "  3 packages not found on disk",
            ]
        );
        // Zero buckets other than "can be patched" are omitted.
        assert_eq!(
            format_dry_run_summary(&ApplyTally::default(), 0),
            vec![
                "Patch verification complete:",
                "  0 packages can be patched"
            ]
        );
    }

    #[test]
    fn results_block_omits_header_when_nothing_to_list() {
        let mut failed = sample_applied(VerifyStatus::Ready);
        failed.success = false;
        failed.files_patched.clear();
        assert!(format_results_block(&[failed], false, Path::new("/p")).is_empty());
        assert!(format_results_block(&[], false, Path::new("/p")).is_empty());
        // Dry runs report through the verification block instead.
        let ok = sample_applied(VerifyStatus::Ready);
        assert!(format_results_block(&[ok], true, Path::new("/p")).is_empty());
    }

    #[test]
    fn results_block_single_copy_has_no_path() {
        let ok = sample_applied(VerifyStatus::Ready);
        let already = {
            let mut r = sample_applied(VerifyStatus::AlreadyPatched);
            r.package_key = "pkg:npm/other@2.0.0".into();
            r.files_patched.clear();
            r.applied_via.clear();
            r
        };
        assert_eq!(
            format_results_block(&[ok, already], false, Path::new("/tmp")),
            vec![
                "",
                "Patched packages:",
                "  pkg:npm/minimist@1.2.2 (via diff)",
                "  pkg:npm/other@2.0.0 (already patched)",
            ]
        );
    }

    #[test]
    fn results_block_names_each_copy_of_a_duplicated_purl() {
        let results = vec![
            copy_at("/p/node_modules/nuxt", VerifyStatus::Ready, true),
            copy_at(
                "/p/node_modules/vite/node_modules/nuxt",
                VerifyStatus::Ready,
                true,
            ),
        ];
        assert_eq!(
            format_results_block(&results, false, Path::new("/p")),
            vec![
                "",
                "Patched packages:",
                "  pkg:npm/nuxt@4.5.0 (node_modules/nuxt, via diff)",
                "  pkg:npm/nuxt@4.5.0 (node_modules/vite/node_modules/nuxt, via diff)",
            ]
        );
    }

    #[test]
    fn patched_line_shapes() {
        assert_eq!(
            format_patched_line("pkg:npm/a@1", None, "via blob+diff"),
            "  pkg:npm/a@1 (via blob+diff)"
        );
        assert_eq!(
            format_patched_line("pkg:npm/a@1", Some("node_modules/a"), "already patched"),
            "  pkg:npm/a@1 (node_modules/a, already patched)"
        );
    }

    #[test]
    fn mismatch_messages_follow_dry_run_tense() {
        assert_eq!(
            format_mismatch_warning("pkg:npm/nuxt@4.5.0", "dist/index.mjs", false),
            "Warning: pkg:npm/nuxt@4.5.0 dist/index.mjs did \
             not match the patch's expected original content; applied the full verified \
             patched content instead (pass --strict to fail on mismatches)"
        );
        assert!(format_mismatch_warning("p", "f", true)
            .contains("; would apply the full verified patched content instead"));
        assert_eq!(
            mismatch_event_detail("f.js", false),
            "f.js did not match the patch's expected original content; the full verified \
             patched content was applied"
        );
        assert!(mismatch_event_detail("f.js", true).ends_with("content would be applied"));
    }

    #[test]
    fn mismatch_fetch_and_fail_counts() {
        assert_eq!(
            format_mismatch_fetch_result(1, 1),
            "Downloaded 1 full patched blob for mismatched files"
        );
        assert_eq!(
            format_mismatch_fetch_result(3, 3),
            "Downloaded 3 full patched blobs for mismatched files"
        );
        assert_eq!(
            format_mismatch_fetch_result(1, 2),
            "Downloaded 1 of 2 full patched blobs for mismatched files"
        );
        assert_eq!(
            mismatched_files_fail(1),
            "1 mismatched file will fail to apply"
        );
        assert_eq!(
            mismatched_files_fail(2),
            "2 mismatched files will fail to apply"
        );
    }

    #[test]
    fn check_in_sync_line() {
        assert_eq!(format_check_in_sync(0, 0), "No patches to check.");
        assert_eq!(
            format_check_in_sync(1, 0),
            "Patches are in sync (1 patch checked)."
        );
        assert_eq!(
            format_check_in_sync(3, 0),
            "Patches are in sync (3 patches checked)."
        );
        // A check that skipped uninstalled packages says so, never a bare
        // vacuous "in sync".
        assert_eq!(
            format_check_in_sync(0, 2),
            "Patches are in sync (0 patches checked; 2 patches not installed, skipped)."
        );
    }

    #[test]
    fn failure_and_none_installed_errors() {
        assert_eq!(
            format_patch_failure("pkg:npm/a@1", "File not found"),
            "Error: Failed to patch pkg:npm/a@1: File not found"
        );
        assert_eq!(
            format_none_installed_error(&["pkg:npm/a@1".to_string()]),
            vec![
                "Error: The targeted manifest patch matched no installed package:",
                "  - pkg:npm/a@1",
                "Check that the packages are installed and --cwd points to the right directory.",
            ]
        );
        let two = format_none_installed_error(&["pkg:npm/a@1".into(), "pkg:npm/b@2".into()]);
        assert_eq!(
            two[0],
            "Error: None of the 2 targeted manifest patches matched an installed package:"
        );
        assert_eq!(two.len(), 4);
        assert_eq!(
            format_none_installed_error(&[])[0],
            "Error: None of the targeted manifest patches matched an installed package."
        );
    }

    #[test]
    fn stage_failure_warning_names_the_cause() {
        let off = stage_failure_warning(true);
        assert_eq!(off.code, "offline_missing_sources");
        assert!(off.detail.contains("--offline"), "{}", off.detail);
        assert!(is_stage_failure_code(&off.code));
        let dl = stage_failure_warning(false);
        assert_eq!(dl.code, "sources_download_failed");
        assert!(is_stage_failure_code(&dl.code));
        assert!(!is_stage_failure_code("gem_config_path_ignored"));
    }

    /// A FIFO squatting a patched leaf in a Gradle hash dir must not wedge
    /// `unexpected_gradle_bytes`: a bare `tokio::fs::read` open(2)s it with
    /// `O_RDONLY` and waits for a writer forever. The FIFO-safe reader
    /// rejects it, so the leaf is skipped and the check returns promptly.
    #[cfg(unix)]
    #[tokio::test]
    async fn unexpected_gradle_bytes_skips_fifo_instead_of_wedging() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp
            .path()
            .join("caches/modules-2/files-2.1/org.example/lib/1.0")
            .join("a".repeat(40));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(maven_sidecars::is_gradle_hash_dir(&dir));
        let leaf = "lib-1.0.jar";
        let c = std::ffi::CString::new(dir.join(leaf).to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let mut files = HashMap::new();
        files.insert(
            leaf.to_string(),
            PatchFileInfo {
                before_hash: "1".repeat(64),
                after_hash: "2".repeat(64),
            },
        );
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            unexpected_gradle_bytes(&dir, &files),
        )
        .await;
        if result.is_err() {
            // Unblock a reader stuck in open(2) so the runtime can exit.
            // O_NONBLOCK: with no reader waiting, a blocking write-open would
            // itself wedge the suite instead of failing it.
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(dir.join(leaf));
            panic!("unexpected_gradle_bytes must not wedge on a FIFO leaf");
        }
        assert_eq!(result.unwrap(), None);
    }

    // --- collect_apply_failures (#424) -------------------------------------

    fn failed_result(purl: &str, error: Option<&str>) -> ApplyResult {
        ApplyResult {
            package_key: purl.to_string(),
            package_path: "/tmp/node_modules/x".to_string(),
            success: false,
            files_verified: Vec::new(),
            files_patched: Vec::new(),
            applied_via: HashMap::new(),
            error: error.map(str::to_string),
            sidecar: None,
        }
    }

    #[test]
    fn collect_apply_failures_reports_each_failed_package_once() {
        let results = vec![
            failed_result("pkg:npm/a@1.0.0", Some("Permission denied (os error 13)")),
            failed_result("pkg:npm/a@1.0.0", Some("second copy")),
            failed_result("pkg:npm/b@1.0.0", None),
            sample_applied(VerifyStatus::Ready),
        ];
        let failures = collect_apply_failures(&results, &[], &HashSet::new());
        assert_eq!(
            failures,
            vec![
                ApplyFailure {
                    purl: "pkg:npm/a@1.0.0".to_string(),
                    code: "apply_failed".to_string(),
                    error: "Permission denied (os error 13)".to_string(),
                },
                ApplyFailure {
                    purl: "pkg:npm/b@1.0.0".to_string(),
                    code: "apply_failed".to_string(),
                    error: "unknown error".to_string(),
                },
            ]
        );
    }

    #[test]
    fn collect_apply_failures_names_unresolved_purls_only_when_nothing_else_failed() {
        let unmatched = vec![
            "pkg:npm/gone@1.0.0".to_string(),
            "pkg:npm/opt@1.0.0".to_string(),
        ];
        let lockfile_only = HashSet::from(["pkg:npm/opt@1.0.0".to_string()]);
        let failures = collect_apply_failures(&[], &unmatched, &lockfile_only);
        assert_eq!(
            failures,
            vec![ApplyFailure {
                purl: "pkg:npm/gone@1.0.0".to_string(),
                code: "package_not_installed".to_string(),
                error: "No installed package matches this PURL".to_string(),
            }],
            "a lockfile-resolved purl never fails the run (#403)"
        );
        // Beside a real failure, an uninstalled patch is only a warning.
        let results = vec![failed_result("pkg:npm/a@1.0.0", Some("boom"))];
        let failures = collect_apply_failures(&results, &unmatched, &lockfile_only);
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].purl, "pkg:npm/a@1.0.0");
    }
}
