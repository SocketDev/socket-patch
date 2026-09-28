//! The hosted-mode redirect engine over an in-memory repository: no
//! filesystem, no subprocesses, no environment reads, no telemetry. Every
//! patch lookup goes through the caller's [`PatchApi`]; the caller hands
//! in the repository's candidate files (chosen by [`select_paths`]) and
//! gets back the changed files, ledger included.
//!
//! Per project root the result matches `scan --mode hosted --json` over a
//! checkout holding the same files (the parity tests hold the two paths to
//! it), with these differences by design: patch lookups are shared across
//! roots (one call per purl / uuid / url), a 401/403 is a project error
//! instead of a public-proxy fallback, the Pipenv major is an option
//! instead of a `pipenv --version` probe, the npm allow-remote planner sees
//! no user/global npm config, and a vendored→hosted takeover is refused
//! (`vendored_takeover_unsupported_in_memory`). Maven and NuGet have no
//! lockfile inventory (disk discovers them only through installed-tree
//! crawlers), so their files raise `ecosystem_unsupported_in_memory`. A dry
//! run still requests reference grants, exactly like the disk dry run.
//!
//! Cargo member manifests are chosen by content on disk (`members`,
//! `exclude`, path dependencies and `[patch]` paths, anywhere but
//! `target/`), which a tree listing cannot evaluate. So [`select_paths`]
//! asks for every `Cargo.toml` under a Cargo root outside `target/`
//! segments (`vendor/`, `node_modules/` and dot-directories included) and
//! the engine repeats the disk walk over them; manifests the walk never
//! reaches are read and ignored. The one exception is `cargo vendor`
//! output: a manifest in or below a directory holding
//! `.cargo-checksum.json` is registry source the walk never reads, so it
//! is not fetched; a path dependency or `[patch]` path into such a crate
//! then fails closed (`redirect_cargo_transitive_dependents`). The cost is
//! over-fetch: a Rust repo with many committed fixture or example crates
//! streams all of them, and each counts toward `maxFiles` /
//! `maxTotalBytes`, so such a repo can fail with a `limit` error where the
//! disk run would succeed. Fetching fewer would instead silently drop
//! manifests the disk run pins.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use socket_patch_core::api::client::PatchApi;
use socket_patch_core::api::types::{PatchResponse, PatchSearchResult};
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::manifest::schema::PatchRecord;
use socket_patch_core::patch::redirect::{RedirectState, REDIRECT_STATE_REL};
use socket_patch_core::utils::cargo_workspace::member_manifests_in;
use socket_patch_core::vendor::lock_inventory::{
    inventory_project_diagnosed_in, MemoryEntry, MemoryProject, ProjectView,
};
use tokio_util::sync::CancellationToken;

pub(crate) mod discover;
pub(crate) mod ledger;
pub mod limits;
pub(crate) mod redirect;
pub(crate) mod roots;
pub mod select;
pub mod types;

pub use limits::SessionBuilder;
pub use select::{candidate_files, safe_repo_path, select_paths};
pub use types::*;

use discover::Provider;
use redirect::{Planned, Refused, Rewritten, StageOptions};

/// `"<crate version>+<git sha or 'unknown'>"`; the sha comes from the
/// `SOCKET_PATCH_GIT_SHA` build-time variable.
pub fn engine_version() -> String {
    format!(
        "{}+{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("SOCKET_PATCH_GIT_SHA").unwrap_or("unknown")
    )
}

/// Run the engine. Resolves with the result, or rejects with an
/// [`EngineError`]: a limit breach, unusable input, cancellation through
/// `cancel` (checked around every await and between roots in the CPU-bound
/// inventory / plan / rewrite phases — one root's running parser is not
/// interrupted), or an engine bug. Provider failures never reject; they
/// become project errors and warnings.
pub async fn run_in_memory(
    input: HostedScanInput,
    provider: Arc<dyn PatchApi>,
    cancel: CancellationToken,
) -> Result<HostedScanOutput, EngineError> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(EngineError::Cancelled),
        result = engine(input, provider, cancel.clone()) => result,
    }
}

/// Yield to the runtime between roots of a CPU-bound phase (memory reads
/// never pend, so without it neither `cancel` nor other tasks on this
/// worker would run until the phase ends).
async fn checkpoint(cancel: &CancellationToken) -> Result<(), EngineError> {
    tokio::task::yield_now().await;
    if cancel.is_cancelled() {
        return Err(EngineError::Cancelled);
    }
    Ok(())
}

/// One root's working state across the phases.
struct RootState {
    root: String,
    project: Option<MemoryProject>,
    /// Root-relative paths that exist but whose content was not provided
    /// (oversize, LFS pointers, presence-only): the disk flow would read
    /// them, so a rewrite that depends on one is refused.
    unreadable: BTreeSet<String>,
    ledger: Option<RedirectState>,
    purls: Vec<String>,
    summary: ProjectSummary,
    packages: Vec<socket_patch_core::api::types::BatchPackagePatches>,
    selected: Vec<(String, String)>,
    skipped: Vec<SkippedPatch>,
    error: Option<ProjectError>,
}

impl RootState {
    fn fail(&mut self, code: &str, message: String) {
        if self.error.is_none() {
            self.error = Some(ProjectError {
                code: code.to_string(),
                message,
            });
        }
    }
}

struct Phases {
    at: Instant,
    ms: BTreeMap<String, u64>,
}

impl Phases {
    fn mark(&mut self, name: &str) {
        let now = Instant::now();
        self.ms.insert(
            name.to_string(),
            now.duration_since(self.at).as_millis() as u64,
        );
        self.at = now;
    }
}

fn validate_input(input: &HostedScanInput, limits: &ResolvedLimits) -> Result<u64, EngineError> {
    if input.files.len() as u64 > limits.max_files {
        return Err(EngineError::limit(
            "max_files",
            format!("more than {} files were provided", limits.max_files),
        ));
    }
    let mut total = 0u64;
    for (path, file) in &input.files {
        if safe_repo_path(path).as_deref() != Some(path.as_str()) {
            return Err(EngineError::invalid(
                "invalid_path",
                format!("`{path}` is not a safe repo-relative path"),
            ));
        }
        let len = match file {
            InputFile::Text(text) => text.len() as u64,
            InputFile::Binary(bytes) => bytes.len() as u64,
            InputFile::Present(_) | InputFile::Symlink => 0,
        };
        if len > limits.max_file_bytes {
            return Err(EngineError::limit(
                "max_file_bytes",
                format!(
                    "`{path}` exceeds the {}-byte per-file limit",
                    limits.max_file_bytes
                ),
            ));
        }
        total += len;
    }
    if total > limits.max_total_bytes {
        return Err(EngineError::limit(
            "max_total_bytes",
            format!(
                "the input exceeds the {}-byte total limit",
                limits.max_total_bytes
            ),
        ));
    }
    Ok(total)
}

/// One input file, stored once: every root's project shares its bytes.
struct SharedFile {
    entry: MemoryEntry,
    /// Exists, but its content (which disk would read) was not provided.
    /// A non-UTF-8 text file is not: disk cannot read it either.
    unreadable: bool,
}

fn share(file: InputFile) -> SharedFile {
    let (entry, unreadable) = match file {
        InputFile::Text(text) => (MemoryEntry::Text(Arc::from(text)), false),
        InputFile::Binary(bytes) => (MemoryEntry::Binary(Arc::from(bytes)), false),
        InputFile::Present(kind) => (MemoryEntry::Present, kind != PresentKind::BinarySkipped),
        InputFile::Symlink => (MemoryEntry::Symlink, false),
    };
    SharedFile { entry, unreadable }
}

/// The root-relative in-memory project for `root` and its unreadable
/// paths.
fn project_for(
    root: &str,
    files: &BTreeMap<String, SharedFile>,
) -> (MemoryProject, BTreeSet<String>) {
    let mut project = MemoryProject::new();
    let mut unreadable = BTreeSet::new();
    for (path, file) in files {
        let Some(rel) = roots::strip_root(root, path) else {
            continue;
        };
        if file.unreadable {
            unreadable.insert(rel.to_string());
        }
        project.insert(rel, file.entry.clone());
    }
    (project, unreadable)
}

/// A root that is a member of an enclosing root's Cargo workspace builds
/// through that workspace's Cargo.lock, which the enclosing root already
/// pins its manifest against; the member's own Cargo.lock (which cargo
/// ignores) is dropped so only the workspace root redirects cargo packages.
fn demote_cargo_members(states: &mut [RootState], warnings: &mut Vec<EngineWarning>) {
    let mut member_of: BTreeMap<String, String> = BTreeMap::new();
    for state in states.iter() {
        let Some(project) = state.project.as_ref() else {
            continue;
        };
        if !project.contains("Cargo.lock") {
            continue;
        }
        for rel in member_manifests_in(&ProjectView::Memory(project)) {
            if let Some(dir) = rel.strip_suffix("/Cargo.toml") {
                member_of
                    .entry(roots::join_root(&state.root, dir))
                    .or_insert_with(|| state.root.clone());
            }
        }
    }
    for state in states.iter_mut() {
        let Some(owner) = member_of.get(&state.root) else {
            continue;
        };
        let Some(project) = state.project.as_mut() else {
            continue;
        };
        if project.remove("Cargo.lock").is_some() {
            state.unreadable.remove("Cargo.lock");
            warnings.push(EngineWarning::new(
                "cargo_member_lock_ignored",
                format!(
                    "{} is a member of the Cargo workspace at `{owner}`, whose Cargo.lock \
                     cargo builds it from; its own Cargo.lock was not scanned",
                    if state.root.is_empty() {
                        "."
                    } else {
                        state.root.as_str()
                    }
                ),
                Some(&state.root),
            ));
        }
    }
}

fn ecosystem_allowed(ecosystems: Option<&[String]>, purl: &str) -> bool {
    match ecosystems {
        None => true,
        Some(list) => {
            Ecosystem::from_purl(purl).is_some_and(|eco| list.iter().any(|a| a == eco.cli_name()))
        }
    }
}

fn unsupported_ecosystem_warnings(
    root: &str,
    project: &MemoryProject,
    ecosystems: Option<&[String]>,
    out: &mut Vec<EngineWarning>,
) {
    let allowed = |eco: &str| ecosystems.is_none_or(|list| list.iter().any(|e| e == eco));
    for (eco, markers) in roots::UNSUPPORTED_MARKERS {
        if !allowed(eco) {
            continue;
        }
        if let Some(found) = markers.iter().find(|m| project.contains(m)) {
            out.push(EngineWarning::new(
                "ecosystem_unsupported_in_memory",
                format!(
                    "{found} is present, but {eco} dependencies are discovered only from an \
                     installed tree, which the in-memory hosted scan does not have; {eco} \
                     dependencies were not scanned"
                ),
                Some(root),
            ));
        }
    }
}

/// Maven / NuGet marker files outside every root (a repo with only those
/// has no root at all): one run-level warning per ecosystem.
fn unrooted_unsupported_warnings<'a>(
    paths: impl Iterator<Item = &'a str>,
    roots: &[String],
    ecosystems: Option<&[String]>,
    out: &mut Vec<EngineWarning>,
) {
    let root_set: BTreeSet<&str> = roots.iter().map(String::as_str).collect();
    let mut found: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for path in paths {
        let (dir, base) = roots::split_path(path);
        let Some(&(eco, _)) = roots::UNSUPPORTED_MARKERS
            .iter()
            .find(|(_, markers)| markers.contains(&base))
        else {
            continue;
        };
        if root_set.contains(dir)
            || !ecosystems.is_none_or(|list| list.iter().any(|e| e == eco))
            || dir
                .split('/')
                .any(|seg| roots::EXCLUDED_ROOT_SEGMENTS.contains(&seg))
        {
            continue;
        }
        found.entry(eco).or_default().push(path);
    }
    for (eco, paths) in found {
        let more = match paths.len() {
            1 => String::new(),
            n => format!(" (and {} more)", n - 1),
        };
        out.push(EngineWarning::new(
            "ecosystem_unsupported_in_memory",
            format!(
                "{}{more} is present, but {eco} dependencies are discovered only from an \
                 installed tree, which the in-memory hosted scan does not have; {eco} \
                 dependencies were not scanned",
                paths[0]
            ),
            None,
        ));
    }
}

async fn engine(
    input: HostedScanInput,
    api: Arc<dyn PatchApi>,
    cancel: CancellationToken,
) -> Result<HostedScanOutput, EngineError> {
    let options = limits::resolve_options(&input.options)?;
    let bytes_input = validate_input(&input, &options.limits)?;
    let files_input = input.files.len() as u64;
    let files: BTreeMap<String, SharedFile> = input
        .files
        .into_iter()
        .map(|(path, file)| (path, share(file)))
        .collect();
    let mut phases = Phases {
        at: Instant::now(),
        ms: BTreeMap::new(),
    };
    let mut warnings: Vec<EngineWarning> = input.warnings;
    let ecosystems = options.ecosystems.as_deref();
    let provider = Provider::new(api, options.request_timeout, options.provider_concurrency);

    let root_list: Vec<String> = match &options.project_roots {
        Some(roots) => roots.clone(),
        None => roots::detect_roots(files.keys().map(String::as_str), ecosystems).0,
    };
    if root_list.len() as u64 > options.limits.max_projects {
        return Err(EngineError::limit(
            "max_projects",
            format!(
                "{} project roots exceed the {}-project limit",
                root_list.len(),
                options.limits.max_projects
            ),
        ));
    }
    unrooted_unsupported_warnings(
        files.keys().map(String::as_str),
        &root_list,
        ecosystems,
        &mut warnings,
    );
    let mut states: Vec<RootState> = root_list
        .iter()
        .map(|root| {
            let (project, unreadable) = project_for(root, &files);
            (root, project, unreadable)
        })
        .map(|(root, project, unreadable)| RootState {
            root: root.clone(),
            project: Some(project),
            unreadable,
            ledger: None,
            purls: Vec::new(),
            summary: ProjectSummary::default(),
            packages: Vec::new(),
            selected: Vec::new(),
            skipped: Vec::new(),
            error: None,
        })
        .collect();
    drop(files);
    demote_cargo_members(&mut states, &mut warnings);
    phases.mark("roots");

    for state in &mut states {
        checkpoint(&cancel).await?;
        let Some(project) = state.project.as_ref() else {
            continue;
        };
        match ledger::load(project, &state.root) {
            Ok(loaded) => state.ledger = loaded,
            Err(message) => {
                state.fail("corrupt_ledger", message);
                continue;
            }
        }
        let (entries, unsupported) =
            inventory_project_diagnosed_in(&ProjectView::Memory(project)).await;
        for (code, detail) in crate::commands::scan::unsupported_layout_warnings(&unsupported) {
            warnings.push(EngineWarning::new(code, detail, Some(&state.root)));
        }
        unsupported_ecosystem_warnings(&state.root, project, ecosystems, &mut warnings);
        let purls: BTreeSet<String> = entries
            .iter()
            .filter_map(|e| discover::supplement_purl(&e.purl))
            .filter(|p| ecosystem_allowed(ecosystems, p))
            .collect();
        state.purls = purls.into_iter().collect();
        state.summary.scanned_packages = state.purls.len() as u64;
    }
    let union_purls: BTreeSet<&str> = states
        .iter()
        .filter(|s| s.error.is_none())
        .flat_map(|s| s.purls.iter().map(String::as_str))
        .collect();
    if union_purls.len() as u64 > options.limits.max_purls {
        return Err(EngineError::limit(
            "max_purls",
            format!(
                "{} distinct packages exceed the {}-package limit",
                union_purls.len(),
                options.limits.max_purls
            ),
        ));
    }
    phases.mark("inventory");

    let root_purls: BTreeMap<String, Vec<String>> = states
        .iter()
        .filter(|s| s.error.is_none() && !s.purls.is_empty())
        .map(|s| (s.root.clone(), s.purls.clone()))
        .collect();
    let batch = discover::batch_search(&provider, &root_purls, options.batch_size).await;
    let can_access_paid = batch.can_access_paid_patches;
    for state in states.iter_mut().filter(|s| s.error.is_none()) {
        state.summary.can_access_paid_patches = can_access_paid;
        let Some(outcome) = batch.roots.get(&state.root) else {
            continue;
        };
        let error = outcome
            .last_error
            .clone()
            .unwrap_or_else(|| "all batches failed".to_string());
        if outcome.failed_purls > 0 && outcome.failed_purls >= state.purls.len() {
            state.fail("patch_lookup_failed", error);
            continue;
        }
        if outcome.failed_purls > 0 {
            warnings.push(EngineWarning::new(
                "batch_failed",
                format!(
                    "{} of {} packages could not be queried for patches: {error}",
                    outcome.failed_purls,
                    state.purls.len()
                ),
                Some(&state.root),
            ));
        }
        state.packages = outcome.packages.clone();
        state.summary.packages_with_patches = state.packages.len() as u64;
        for pkg in &state.packages {
            for patch in &pkg.patches {
                if patch.tier == "free" {
                    state.summary.free_patches += 1;
                } else {
                    state.summary.paid_patches += 1;
                }
            }
        }
        state.summary.total_patches = state.summary.free_patches + state.summary.paid_patches;
    }
    phases.mark("batch");

    let detail_purls: BTreeSet<String> = states
        .iter()
        .filter(|s| s.error.is_none())
        .flat_map(|s| s.packages.iter().map(|p| p.purl.clone()))
        .collect();
    let details = discover::fetch_details(&provider, &detail_purls).await;
    for state in states.iter_mut().filter(|s| s.error.is_none()) {
        if state.packages.is_empty() {
            continue;
        }
        let mut results: Vec<PatchSearchResult> = Vec::new();
        let mut failures: Vec<String> = Vec::new();
        for pkg in &state.packages {
            match details.get(&pkg.purl) {
                Some(Ok(response)) => results.extend(response.patches.iter().cloned()),
                Some(Err(error)) => failures.push(error.clone()),
                None => failures.push("patch details were not fetched".to_string()),
            }
        }
        if !failures.is_empty() && failures.len() == state.packages.len() {
            let last = failures.last().cloned().unwrap_or_default();
            state.fail(
                "patch_lookup_failed",
                format!("all {} patch-detail queries failed: {last}", failures.len()),
            );
            continue;
        }
        if !failures.is_empty() {
            warnings.push(EngineWarning::new(
                "detail_lookup_failed",
                format!(
                    "patch details could not be fetched for {} of {} packages",
                    failures.len(),
                    state.packages.len()
                ),
                Some(&state.root),
            ));
        }
        state.selected = discover::select_top_ranked(&results, can_access_paid);
    }
    phases.mark("details");

    let uuids: BTreeSet<String> = states
        .iter()
        .filter(|s| s.error.is_none())
        .flat_map(|s| s.selected.iter().map(|(_, u)| u.clone()))
        .collect();
    let (references, failed_refs) = if uuids.is_empty() {
        (HashMap::new(), BTreeMap::new())
    } else {
        discover::fetch_references(&provider, &uuids).await
    };
    for state in states.iter_mut().filter(|s| s.error.is_none()) {
        if let Some(error) = state
            .selected
            .iter()
            .find_map(|(_, uuid)| failed_refs.get(uuid))
        {
            state.fail(
                "reference_lookup_failed",
                format!("failed to resolve patch references: {error}"),
            );
        }
    }
    phases.mark("references");

    let mut planned: Vec<(usize, Planned)> = Vec::new();
    for (index, state) in states.iter_mut().enumerate() {
        if state.error.is_some() {
            continue;
        }
        checkpoint(&cancel).await?;
        let Some(project) = state.project.take() else {
            continue;
        };
        let unreadable = std::mem::take(&mut state.unreadable);
        match redirect::plan(project, unreadable, &state.selected, &references) {
            Ok(plan) => planned.push((index, plan)),
            Err(Refused { error }) => state.error = Some(error),
        }
    }
    let wheels: BTreeSet<(String, String)> = planned
        .iter()
        .flat_map(|(_, p)| p.wheels.iter().cloned())
        .collect();
    let wheel_metadata = if wheels.is_empty() {
        BTreeMap::new()
    } else {
        discover::fetch_wheel_metadata(&provider, &wheels, options.limits.max_artifact_bytes).await
    };
    phases.mark("plan");

    let stage = StageOptions {
        dry_run: options.dry_run,
        pipenv_major: options.pipenv_major,
        trust_lockfile_config: options.trust_lockfile_config,
        npm_allow_remote_config: options.npm_allow_remote_config,
    };
    let mut rewritten: Vec<(usize, Rewritten)> = Vec::new();
    for (index, plan) in planned {
        checkpoint(&cancel).await?;
        let skipped_before = plan.skipped.clone();
        match redirect::rewrite(plan, &wheel_metadata, stage) {
            Ok(done) => rewritten.push((index, done)),
            Err(Refused { error }) => {
                states[index].skipped = skipped_before;
                states[index].error = Some(error);
            }
        }
    }
    phases.mark("rewrite");

    let record_uuids: BTreeSet<String> = if options.dry_run {
        BTreeSet::new()
    } else {
        rewritten
            .iter()
            .flat_map(|(_, r)| r.confirmed.iter().map(|(_, u)| u.clone()))
            .collect()
    };
    let records: BTreeMap<String, Option<PatchResponse>> = if record_uuids.is_empty() {
        BTreeMap::new()
    } else {
        discover::fetch_records(&provider, &record_uuids).await
    };
    phases.mark("records");

    let mut changed: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut changed_binary: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    let mut results: BTreeMap<usize, ProjectResult> = BTreeMap::new();
    for (index, done) in rewritten {
        let state = &mut states[index];
        let result = finish_root(
            state,
            done,
            &records,
            options.dry_run,
            &mut changed,
            &mut changed_binary,
            &mut warnings,
        );
        results.insert(index, result);
    }
    let mut projects: Vec<ProjectResult> = Vec::with_capacity(states.len());
    for (index, state) in states.iter().enumerate() {
        if let Some(result) = results.remove(&index) {
            projects.push(result);
            continue;
        }
        let redirect = match &state.error {
            Some(_) => serde_json::json!({ "mode": "hosted" }),
            None => crate::commands::scan::hosted::redirect_json_block(
                0,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                options.dry_run,
            ),
        };
        projects.push(ProjectResult {
            root: state.root.clone(),
            redirect,
            summary: state.summary.clone(),
            redirected: Vec::new(),
            skipped: state.skipped.clone(),
            error: state.error.clone(),
        });
    }
    phases.mark("finish");

    let changed_files: Vec<ChangedFile> = changed
        .into_iter()
        .map(|(path, (_, content))| ChangedFile { path, content })
        .collect();
    let changed_binary_files: Vec<ChangedBinaryFile> = changed_binary
        .into_iter()
        .map(|(path, (_, content))| ChangedBinaryFile { path, content })
        .collect();
    let stats = EngineStats {
        projects: projects.len() as u64,
        files_input,
        bytes_input,
        packages_scanned: projects.iter().map(|p| p.summary.scanned_packages).sum(),
        packages_with_patches: projects
            .iter()
            .map(|p| p.summary.packages_with_patches)
            .sum(),
        patches_selected: states.iter().map(|s| s.selected.len() as u64).sum(),
        patches_redirected: projects.iter().map(|p| p.redirected.len() as u64).sum(),
        files_changed: (changed_files.len() + changed_binary_files.len()) as u64,
        provider_calls: provider.calls(),
        phase_ms: phases.ms,
    };
    Ok(HostedScanOutput {
        projects,
        changed_files,
        changed_binary_files,
        deleted_files: Vec::new(),
        warnings,
        stats,
        engine_version: engine_version(),
    })
}

/// Records → ledger merge → the project's result and changed files.
fn finish_root(
    state: &mut RootState,
    done: Rewritten,
    records: &BTreeMap<String, Option<PatchResponse>>,
    dry_run: bool,
    changed: &mut BTreeMap<String, (String, String)>,
    changed_binary: &mut BTreeMap<String, (String, Vec<u8>)>,
    warnings: &mut Vec<EngineWarning>,
) -> ProjectResult {
    let Rewritten {
        planned,
        rewrite,
        rewritten,
        confirmed,
        rush_warnings,
        pnpm_warnings,
        npm_warnings,
    } = done;
    let root = state.root.clone();
    let mut record_map: BTreeMap<String, PatchRecord> = BTreeMap::new();
    let mut record_warnings: Vec<serde_json::Value> = Vec::new();
    if !dry_run {
        for (purl, uuid) in &confirmed {
            match records.get(uuid) {
                Some(Some(response)) => {
                    let (rec_purl, record) =
                        crate::commands::get::record_from_patch_response(response);
                    record_map.insert(rec_purl, record);
                }
                _ => record_warnings.push(serde_json::json!({
                    "code": "record_fetch_failed",
                    "detail": format!(
                        "{purl} was switched to hosted, but its patch record could not be fetched; \
                         it will be missing from VEX until `socket-patch scan --mode \
                         hosted` is re-run"
                    ),
                })),
            }
        }
    }

    let mut project_changes: Vec<(String, String)> = Vec::new();
    let mut ledger_error: Option<ProjectError> = None;
    if !dry_run && (!rewrite.edits.is_empty() || !record_map.is_empty()) {
        let mut ledger = state.ledger.take().unwrap_or_default();
        ledger::merge(&mut ledger, &rewrite.edits, record_map, &planned.files);
        match ledger::serialize(&ledger) {
            Ok(text) => {
                if planned.project.text(REDIRECT_STATE_REL) != Some(text.as_str()) {
                    project_changes.push((REDIRECT_STATE_REL.to_string(), text));
                }
            }
            Err(message) => {
                ledger_error = Some(ProjectError {
                    code: "ledger_serialize_failed".into(),
                    message,
                })
            }
        }
    }
    if let Some(error) = ledger_error {
        return ProjectResult {
            root,
            redirect: serde_json::json!({ "mode": "hosted" }),
            summary: state.summary.clone(),
            redirected: Vec::new(),
            skipped: planned.skipped,
            error: Some(error),
        };
    }
    for (rel, content) in &rewrite.files {
        if planned.project.text(rel) != Some(content.as_str()) {
            project_changes.push((rel.clone(), content.clone()));
        }
    }
    let text_writes: Vec<(String, String)> = project_changes
        .into_iter()
        .map(|(rel, content)| (roots::join_root(&root, &rel), content))
        .collect();
    let binary_writes: Vec<(String, Vec<u8>)> = rewrite
        .binary_files
        .iter()
        .filter(|(rel, bytes)| {
            !matches!(
                planned.project.get(rel.as_str()),
                Some(MemoryEntry::Binary(existing)) if existing.as_ref() == bytes.as_slice()
            )
        })
        .map(|(rel, bytes)| (roots::join_root(&root, rel), bytes.clone()))
        .collect();
    let conflict = text_writes
        .iter()
        .find_map(|(path, content)| match changed.get(path) {
            Some((owner, existing)) if existing != content => Some((path, owner)),
            _ => None,
        })
        .or_else(|| {
            binary_writes
                .iter()
                .find_map(|(path, bytes)| match changed_binary.get(path) {
                    Some((owner, existing)) if existing != bytes => Some((path, owner)),
                    _ => None,
                })
        });
    if let Some((path, owner)) = conflict {
        let message = format!(
            "{path} is rewritten differently by project `{owner}`; none of this project's \
             changes were written"
        );
        warnings.push(EngineWarning::new(
            "conflicting_write",
            message.clone(),
            Some(&root),
        ));
        return ProjectResult {
            root,
            redirect: serde_json::json!({ "mode": "hosted" }),
            summary: state.summary.clone(),
            redirected: Vec::new(),
            skipped: planned.skipped,
            error: Some(ProjectError {
                code: "conflicting_write".into(),
                message,
            }),
        };
    }
    for (path, content) in text_writes {
        changed
            .entry(path)
            .or_insert_with(|| (root.clone(), content));
    }
    for (path, bytes) in binary_writes {
        changed_binary
            .entry(path)
            .or_insert_with(|| (root.clone(), bytes));
    }

    let mut redirect_warnings: Vec<serde_json::Value> = rewrite
        .warnings
        .iter()
        .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail }))
        .collect();
    redirect_warnings.extend(record_warnings);
    redirect_warnings.extend(rush_warnings);
    redirect_warnings.extend(pnpm_warnings);
    redirect_warnings.extend(npm_warnings);
    redirect_warnings.extend(planned.pre_warnings.iter().cloned());
    let skipped_values: Vec<serde_json::Value> = planned
        .skipped
        .iter()
        .map(|s| serde_json::to_value(s).unwrap_or(serde_json::Value::Null))
        .collect();
    let redirect = crate::commands::scan::hosted::redirect_json_block(
        confirmed.len(),
        rewritten,
        skipped_values,
        redirect_warnings,
        dry_run,
    );
    ProjectResult {
        root,
        redirect,
        summary: state.summary.clone(),
        redirected: confirmed
            .into_iter()
            .map(|(purl, uuid)| RedirectedPatch { purl, uuid })
            .collect(),
        skipped: planned.skipped,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::patch::redirect::{FileEdit, RewriteResult};

    fn state(root: &str, project: MemoryProject) -> RootState {
        RootState {
            root: root.to_string(),
            project: Some(project),
            unreadable: BTreeSet::new(),
            ledger: None,
            purls: Vec::new(),
            summary: ProjectSummary::default(),
            packages: Vec::new(),
            selected: Vec::new(),
            skipped: Vec::new(),
            error: None,
        }
    }

    fn rewritten(files: &[(&str, &str)]) -> Rewritten {
        let planned = redirect::plan(MemoryProject::new(), BTreeSet::new(), &[], &HashMap::new())
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        let mut rewrite = RewriteResult::default();
        for (rel, content) in files {
            rewrite
                .files
                .insert((*rel).to_string(), (*content).to_string());
            rewrite.edits.push(FileEdit {
                path: (*rel).to_string(),
                kind: "cargo_registry_redirect".into(),
                action: "set".into(),
                key: None,
                original: None,
                new: None,
            });
        }
        Rewritten {
            planned,
            rewrite,
            rewritten: files.iter().map(|(rel, _)| (*rel).to_string()).collect(),
            confirmed: vec![("pkg:cargo/serde@1.0.190".into(), "u".into())],
            rush_warnings: Vec::new(),
            pnpm_warnings: Vec::new(),
            npm_warnings: Vec::new(),
        }
    }

    #[test]
    fn a_conflicting_project_writes_nothing() {
        let mut changed = BTreeMap::new();
        let mut changed_binary = BTreeMap::new();
        let mut warnings = Vec::new();
        let records = BTreeMap::new();
        let first = finish_root(
            &mut state("", MemoryProject::new()),
            rewritten(&[("crates/b/Cargo.toml", "A")]),
            &records,
            false,
            &mut changed,
            &mut changed_binary,
            &mut warnings,
        );
        assert!(first.error.is_none());
        let before: Vec<String> = changed.keys().cloned().collect();
        let second = finish_root(
            &mut state("crates/b", MemoryProject::new()),
            rewritten(&[("Cargo.toml", "B"), ("Cargo.lock", "L")]),
            &records,
            false,
            &mut changed,
            &mut changed_binary,
            &mut warnings,
        );
        assert_eq!(second.error.as_ref().unwrap().code, "conflicting_write");
        assert!(second.redirected.is_empty());
        assert_eq!(second.redirect, serde_json::json!({ "mode": "hosted" }));
        assert_eq!(changed.keys().cloned().collect::<Vec<_>>(), before);
        assert_eq!(changed["crates/b/Cargo.toml"].1, "A");
        assert!(warnings.iter().any(
            |w| w.code == "conflicting_write" && w.project_root.as_deref() == Some("crates/b")
        ));

        let same = finish_root(
            &mut state("crates/b", MemoryProject::new()),
            rewritten(&[("Cargo.toml", "A")]),
            &records,
            true,
            &mut changed,
            &mut changed_binary,
            &mut warnings,
        );
        assert!(same.error.is_none());
    }

    #[test]
    fn a_conflicting_binary_write_refuses_the_project() {
        let mut changed = BTreeMap::new();
        let mut changed_binary = BTreeMap::new();
        changed_binary.insert("web/bun.lockb".to_string(), ("".to_string(), vec![1u8]));
        let mut warnings = Vec::new();
        let mut done = rewritten(&[]);
        done.rewrite
            .binary_files
            .insert("bun.lockb".to_string(), vec![2u8]);
        let result = finish_root(
            &mut state("web", MemoryProject::new()),
            done,
            &BTreeMap::new(),
            true,
            &mut changed,
            &mut changed_binary,
            &mut warnings,
        );
        assert_eq!(result.error.unwrap().code, "conflicting_write");
        assert_eq!(changed_binary["web/bun.lockb"].1, vec![1u8]);
        assert!(changed.is_empty());
    }

    #[test]
    fn workspace_member_roots_lose_their_own_cargo_lock() {
        let mut ws = MemoryProject::new();
        ws.insert_text(
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\nexclude = [\"crates/fuzz\"]\n",
        );
        ws.insert_text("Cargo.lock", "version = 3\n");
        ws.insert_text("crates/b/Cargo.toml", "[package]\nname = \"b\"\n");
        ws.insert_text("crates/b/Cargo.lock", "version = 3\n");
        ws.insert_text("crates/b/package-lock.json", "{}");
        ws.insert_text("crates/fuzz/Cargo.toml", "[package]\nname = \"fuzz\"\n");
        ws.insert_text("crates/fuzz/Cargo.lock", "version = 3\n");
        ws.insert_text("crates/fuzz/package-lock.json", "{}");
        let sub = |dir: &str| {
            let mut p = MemoryProject::new();
            for (path, entry) in ws.entries() {
                if let Some(rel) = roots::strip_root(dir, path) {
                    p.insert(rel, entry.clone());
                }
            }
            p
        };
        let mut states = vec![
            state("", ws.clone()),
            state("crates/b", sub("crates/b")),
            state("crates/fuzz", sub("crates/fuzz")),
        ];
        let mut warnings = Vec::new();
        demote_cargo_members(&mut states, &mut warnings);
        let has_lock = |i: usize| states[i].project.as_ref().unwrap().contains("Cargo.lock");
        assert!(has_lock(0));
        assert!(!has_lock(1), "a member's lock is the workspace's");
        assert!(has_lock(2), "an excluded crate is its own workspace");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "cargo_member_lock_ignored");
        assert_eq!(warnings[0].project_root.as_deref(), Some("crates/b"));
    }

    #[test]
    fn nested_roots_share_one_copy_of_each_file() {
        let mut files: BTreeMap<String, SharedFile> = BTreeMap::new();
        files.insert(
            "a/b/package-lock.json".into(),
            share(InputFile::Text("{}".repeat(1024))),
        );
        files.insert(
            "a/big.lock".into(),
            share(InputFile::Present(PresentKind::Oversize)),
        );
        files.insert(
            "a/odd.txt".into(),
            share(InputFile::Present(PresentKind::BinarySkipped)),
        );
        let (outer, outer_unreadable) = project_for("", &files);
        let (inner, _) = project_for("a/b", &files);
        match (
            outer.get("a/b/package-lock.json"),
            inner.get("package-lock.json"),
        ) {
            (Some(MemoryEntry::Text(x)), Some(MemoryEntry::Text(y))) => {
                assert!(Arc::ptr_eq(x, y), "each root must share the input's bytes")
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            outer_unreadable,
            BTreeSet::from(["a/big.lock".to_string()]),
            "a non-UTF-8 file is absent to disk too"
        );
    }

    #[test]
    fn unsupported_markers_outside_roots_warn_once_per_ecosystem() {
        let paths = [
            "java/a/pom.xml",
            "java/b/pom.xml",
            "web/pom.xml",
            "dotnet/nuget.config",
            "tests/pom.xml",
            "src/Main.java",
        ];
        let mut out = Vec::new();
        unrooted_unsupported_warnings(paths.into_iter(), &["web".to_string()], None, &mut out);
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .all(|w| w.code == "ecosystem_unsupported_in_memory" && w.project_root.is_none()));
        assert!(
            out[0].detail.starts_with("java/a/pom.xml (and 1 more)"),
            "{}",
            out[0].detail
        );
        assert!(
            out[1].detail.starts_with("dotnet/nuget.config is"),
            "{}",
            out[1].detail
        );
        let mut filtered = Vec::new();
        unrooted_unsupported_warnings(
            paths.into_iter(),
            &[],
            Some(&["npm".to_string()]),
            &mut filtered,
        );
        assert!(filtered.is_empty());
    }
}
