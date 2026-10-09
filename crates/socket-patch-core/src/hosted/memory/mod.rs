//! The hosted-mode redirect engine over an in-memory repository: no
//! filesystem, no subprocesses, no environment reads, no telemetry. Every
//! patch lookup goes through the caller's [`PatchApi`]; the caller hands
//! in the repository's candidate files (chosen by [`select_paths`]) and
//! gets back the changed files (v5 hosted mode keeps no ledger: the
//! rewritten lockfiles are the whole record).
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
//!
//! A pnpm workspace member's own `pnpm-lock.yaml` (a root the nearest
//! ancestor `pnpm-workspace.yaml` lists) is demoted into that workspace
//! root, which reads it as a disk run from the root does: pinned beside the
//! root lock under `sharedWorkspaceLockfile: false`, ignored beside a
//! shared root lock (#492). Only once the root's files confirm it (the
//! globs read and list the member, which has a package manifest, and the
//! root pins or knowingly ignores its lock) and socket.yml admits the root:
//! otherwise the member keeps its lock as a root of its own. Path selection
//! cannot read the globs, so under a workspace root it fetches every
//! `pnpm-lock.yaml` beside a package manifest outside pnpm's skipped trees,
//! the same over-fetch tradeoff as Cargo member manifests above.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use crate::api::client::PatchApi;
use crate::api::types::{PatchResponse, PatchSearchResult};
use crate::crawlers::Ecosystem;
use crate::utils::cargo_workspace::member_manifests_in;
use crate::vendor::lock_inventory::{
    inventory_project_diagnosed_in, MemoryEntry, MemoryProject, ProjectView,
};
use tokio_util::sync::CancellationToken;

pub(crate) mod discover;
pub mod limits;
pub mod roots;
pub mod select;
pub(crate) mod stages;
pub mod types;

pub use limits::SessionBuilder;
pub use select::{candidate_files, safe_repo_path, select_paths};
pub use types::*;

use crate::policy::{
    patch_severity_order, policy_block, FilterReason, FilteredEntry, MemoryPolicyFs, PolicyError,
    PolicySource, Root, RootFile, SelectionPolicy, PATCHES_DISABLED, POLICY_FILE_NAMES,
};
use crate::rollout::stage::{
    classify, lookup_incomplete, mark_pinned, offers_from_results, Offers, RecordedIndex, Row,
    Stage, ROLLOUT_DEFERRED,
};
use discover::Provider;
use stages::{Planned, RewriteRefused, Rewritten, StageOptions};
use crate::utils::purl_key::PurlKey;

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
    purls: Vec<String>,
    summary: ProjectSummary,
    packages: Vec<crate::api::types::BatchPackagePatches>,
    /// Every accessible offer per purl, and the winner per purl.
    offers: Offers,
    /// Purls whose detail query failed.
    failed_details: Vec<String>,
    /// The classified rows (§5.1) the run-wide rollout plan spends on.
    rows: Vec<Row>,
    selected: Vec<(String, String)>,
    skipped: Vec<SkippedPatch>,
    deferred: Vec<DeferredPatch>,
    /// Candidates the socket.yml policy withheld (`policy_*` reasons).
    policy_skipped: Vec<SkippedPatch>,
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
    // yarn berry merges the rc files above the project as well, so a
    // nested yarn root sees the repository's `.yarnrc.yml` files above it
    // (`select_paths` fetches them for a root holding a PnP loader).
    let ancestor_yarnrcs = roots::strict_ancestors(root)
        .filter_map(
            |dir| match &files.get(&roots::join_root(dir, roots::YARNRC_NAME))?.entry {
                MemoryEntry::Text(text) => Some(Arc::clone(text)),
                _ => None,
            },
        )
        .collect();
    project.set_ancestor_yarnrcs(ancestor_yarnrcs);
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

/// The confirmed pnpm workspace members among `candidates`
/// ([`roots::pnpm_member_candidates`]), each with its workspace root: the
/// root's own files (as a disk run from it reads them) account for the
/// member's lock
/// ([`root_accounts_for_member_lock`](crate::utils::pnpm_workspace::root_accounts_for_member_lock)),
/// and `admitted` (the socket.yml path policy) lets that root be scanned.
/// Any other candidate keeps its lock as a root of its own, as before #492
/// ([`refuse_governed_pnpm_members`] guards its trust auto-config): a lock
/// demoted into a root that leaves it unread, or that is never scanned,
/// would be pinned by no one.
async fn confirm_pnpm_members(
    files: &BTreeMap<String, SharedFile>,
    candidates: Vec<(String, String)>,
    admitted: impl Fn(&str) -> bool,
) -> Vec<(String, String)> {
    let mut views: BTreeMap<String, MemoryProject> = BTreeMap::new();
    let mut out = Vec::new();
    for (member, workspace) in candidates {
        if !admitted(&workspace) {
            continue;
        }
        let Some(rel) = roots::strip_root(&workspace, &member).map(str::to_string) else {
            continue;
        };
        let project = views
            .entry(workspace.clone())
            .or_insert_with(|| project_for(&workspace, files).0);
        let view = ProjectView::Memory(project);
        if crate::utils::pnpm_workspace::root_accounts_for_member_lock(&view, &rel).await {
            out.push((member, workspace));
        }
    }
    out
}

/// A pnpm root with a v9 lock but no `pnpm-workspace.yaml` of its own that
/// the nearest ancestor `pnpm-workspace.yaml` may list as a workspace
/// project, and whose lock was not demoted into that workspace root
/// ([`confirm_pnpm_members`]): pnpm reads `trustLockfile` only from that
/// ancestor file, so the trust auto-config's `pnpm-workspace.yaml` in the
/// member would be ignored and pnpm >= 11 would reject the hosted pins.
/// The disk run refuses a member run the same way
/// (`redirect_pnpm_settings_elsewhere`), so the member is refused rather
/// than given a file pnpm never reads. A governing file the engine cannot
/// read (a symlink, oversize, content not provided) or whose globs it
/// cannot model counts as listing the member, the refusing side.
fn refuse_governed_pnpm_members(files: &BTreeMap<String, SharedFile>, states: &mut [RootState]) {
    use crate::hosted::governing_root::PNPM_SETTINGS_ELSEWHERE;
    use crate::hosted::guidance::PNPM_WORKSPACE_REL;
    for state in states.iter_mut() {
        let Some(project) = state.project.as_ref() else {
            continue;
        };
        if state.root.is_empty() || project.contains(PNPM_WORKSPACE_REL) {
            continue;
        }
        let v9 = matches!(
            project.get("pnpm-lock.yaml"),
            Some(MemoryEntry::Text(lock))
                if crate::formats::pnpm::lock_version_major(lock).is_some_and(|major| major >= 9)
        );
        if !v9 {
            continue;
        }
        let mut dir = state.root.as_str();
        let governing = loop {
            dir = roots::split_path(dir).0;
            let path = roots::join_root(dir, PNPM_WORKSPACE_REL);
            if let Some(file) = files.get(&path) {
                break Some((path, file));
            }
            if dir.is_empty() {
                break None;
            }
        };
        let Some((path, file)) = governing else {
            continue;
        };
        let rel: Vec<String> = roots::strip_root(dir, &state.root)
            .unwrap_or(&state.root)
            .split('/')
            .map(str::to_string)
            .collect();
        let member = match &file.entry {
            MemoryEntry::Text(text) if !file.unreadable => {
                crate::utils::pnpm_workspace::lists_as_member(text, &rel)
            }
            _ => true,
        };
        if member {
            let workspace = if dir.is_empty() { "." } else { dir };
            state.fail(
                PNPM_SETTINGS_ELSEWHERE,
                format!(
                    "{} may be a project of the pnpm workspace whose settings live in {path}: \
                     pnpm reads `trustLockfile` only from that file, so a \
                     pnpm-workspace.yaml created in {} would be ignored and pnpm >= 11 \
                     would reject the hosted pins (ERR_PNPM_TARBALL_URL_MISMATCH); the \
                     in-memory engine pins a member's lock from the workspace root `{workspace}` \
                     only when that root's pnpm-workspace.yaml, lock and the member's \
                     package.json say the root installs or ignores it — scan `{workspace}` \
                     with those files, run hosted mode from the workspace root on a \
                     checkout, or turn the trust auto-config off to pin without it; \
                     nothing was written",
                    state.root, state.root
                ),
            );
        }
    }
}

/// A pnpm workspace member's own `pnpm-lock.yaml` is the workspace root's
/// to read (#492, [`confirm_pnpm_members`]): pinned beside the
/// root's under `sharedWorkspaceLockfile: false`, a stale leftover beside a
/// shared root lock. A member that stays a root (it holds another lock, or
/// the caller named it) drops that lock, as a Cargo member drops its
/// Cargo.lock ([`demote_cargo_members`]); when the workspace root is not
/// among the roots, the lock is not scanned at all and a warning says so.
fn demote_pnpm_members(
    states: &mut [RootState],
    members: &[(String, String)],
    warnings: &mut Vec<EngineWarning>,
) {
    let roots: BTreeSet<String> = states.iter().map(|s| s.root.clone()).collect();
    for (member, workspace) in members {
        let Some(state) = states.iter_mut().find(|s| &s.root == member) else {
            continue;
        };
        let Some(project) = state.project.as_mut() else {
            continue;
        };
        if project.remove("pnpm-lock.yaml").is_none() {
            continue;
        }
        state.unreadable.remove("pnpm-lock.yaml");
        if roots.contains(workspace) {
            continue;
        }
        let workspace = if workspace.is_empty() { "." } else { workspace };
        warnings.push(EngineWarning::new(
            "pnpm_member_lock_ignored",
            format!(
                "{member} is a project of the pnpm workspace at `{workspace}`, whose root \
                 decides which lock pnpm installs it from; its pnpm-lock.yaml was not \
                 scanned — scan `{workspace}` as a project root to pin it"
            ),
            Some(member),
        ));
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
    policy: &SelectionPolicy,
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
            || policy
                .admits_root(&Root {
                    rel_dir: dir,
                    markers: &[base.to_string()],
                    explicit: false,
                })
                .is_err()
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

/// One root's recorded view (§5.1) in memory: its `.socket/manifest.json`,
/// the hosted pins its lockfiles carry, and its vendor ledger — the disk
/// merge's precedence. The pins are discovery's over the root's files
/// ([`HostedPin::discover`], the one "is this pinned" answer the disk scan
/// uses too), so a uuid a stale or inactive file merely mentions pins
/// nothing. Pins on a patch server other than Socket's are recognized once
/// the run's references name it ([`stage::mark_pinned`]).
///
/// Unlike the mention scan this replaced, a pin counts whether or not the
/// API still offers its patch (as on disk): a re-scan re-confirms it as
/// ALREADY instead of spending a NEW slot. A pin wired only by files under
/// a nested root (one discovery reaches through a requirements include or
/// a rush subspace) is that root's own and does not count here.
///
/// [`HostedPin::discover`]: crate::patch::redirect::upstream::HostedPin::discover
/// [`stage::mark_pinned`]: crate::rollout::stage::mark_pinned
async fn memory_recorded(project: &MemoryProject, root: &str, roots: &[String]) -> RecordedIndex {
    let manifest = project
        .text(select::MANIFEST_REL)
        .and_then(|text| serde_json::from_str(text).ok());
    let vendor = stages::vendored_entries(project);
    let nested: Vec<String> = roots
        .iter()
        .filter(|other| other.as_str() != root)
        .filter_map(|other| roots::strip_root(root, other).map(|rel| format!("{rel}/")))
        .filter(|rel| rel != "/")
        .collect();
    let own = |file: &String| !nested.iter().any(|n| file.starts_with(n.as_str()));
    // The same discovery `HostedPin::discover` runs, kept whole so its
    // lockless pins (never refs) count as recorded too.
    let discovery = crate::vex::discover::discover_patched_refs_view(
        ProjectView::Memory(project),
        &crate::vex::DiscoverOptions::default(),
    )
    .await;
    let mut pins: Vec<(String, String)> =
        crate::patch::redirect::upstream::HostedPin::all(&discovery)
            .into_iter()
            .filter(|pin| pin.files.iter().any(own))
            .map(|pin| (pin.purl, pin.uuid))
            .collect();
    // A Gemfile-only gem pin (no lock ref until the next unfrozen `bundle
    // install`) counts as recorded too (#1224).
    for pin in crate::vex::discover::gem_manifest_source_pins(&ProjectView::Memory(project)).await {
        if !pins.contains(&pin) {
            pins.push(pin);
        }
    }
    let unlocked = discovery
        .unlocked_pins
        .into_iter()
        .filter(|pin| own(&pin.file.to_string_lossy().replace('\\', "/")));
    let merged =
        crate::ledgers::merge_ledger_records_for_updates(manifest.as_ref(), vendor.as_ref(), &pins);
    RecordedIndex::new(merged.as_deref(), &pins).with_unlocked_pins(unlocked)
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

    // The repo's socket.yml policy, before any root is processed: a file
    // that cannot be honored fails the whole session closed.
    let (policy, policy_warnings) = match SelectionPolicy::load(
        &memory_policy_fs(&files, &options.policy_paths),
        &options.policy_overrides,
    ) {
        Ok(loaded) => loaded,
        Err(error) => {
            return Ok(policy_error_output(
                &error,
                warnings,
                files_input,
                bytes_input,
            ));
        }
    };
    // Path selection chose which files to send by the policy it read; a
    // different policy here would judge roots it never fetched.
    let read = match policy.source() {
        PolicySource::File { path, sha256 } => Some((path.as_str(), sha256.as_str())),
        PolicySource::None | PolicySource::Bypassed => None,
    };
    // Selection returns no digest when it bypassed the file, so a digest
    // with a bypassed session means the two sides disagree.
    let expected = if options.policy_overrides.bypass {
        None
    } else {
        read.map(|(_, sha)| sha)
    };
    if expected != options.policy_sha256.as_deref() {
        let error = PolicyError::Invalid {
            file: read
                .map_or(POLICY_FILE_NAMES[0], |(path, _)| path)
                .to_string(),
            key: String::new(),
            message: "the policy content differs from the one path selection read: pass \
                      selectHostedScanPaths' policySha256 and stream the same text"
                .to_string(),
        };
        return Ok(policy_error_output(
            &error,
            warnings,
            files_input,
            bytes_input,
        ));
    }
    for w in policy_warnings {
        warnings.push(EngineWarning::new(w.code, w.detail, None));
    }
    if !policy.enabled() {
        warnings.push(EngineWarning::new(
            PATCHES_DISABLED,
            "patches.enabled is false in socket.yml: report only, nothing is written",
            None,
        ));
    }
    let mut policy_filtered: Vec<FilteredEntry> = Vec::new();

    let mut root_list: Vec<String> = match &options.project_roots {
        Some(roots) => roots.clone(),
        None => roots::detect_roots(files.keys().map(String::as_str), ecosystems).0,
    };
    // The full policy (paths from the file too) judges every root before
    // the project limit; roots named in `projectRoots` are explicit.
    let explicit_roots = options.project_roots.is_some();
    // pnpm workspace members' locks belong to the workspace root (#492):
    // a confirmed member with no other lock is no root of its own, and the
    // workspace root is one even with no lock there (pnpm 7 writes none).
    let admitted = |root: &str| {
        let markers = roots::root_markers(root, files.keys().map(String::as_str));
        policy
            .admits_root(&Root {
                rel_dir: root,
                markers: &markers,
                explicit: explicit_roots,
            })
            .is_ok()
    };
    let candidates =
        roots::pnpm_member_candidates(&root_list, |path| files.contains_key(path), ecosystems);
    let pnpm_members = confirm_pnpm_members(&files, candidates.clone(), admitted).await;
    let other_marker =
        |root: &str| roots::has_other_root_marker(root, files.keys().map(String::as_str), ecosystems);
    if !explicit_roots {
        root_list.retain(|root| {
            !pnpm_members.iter().any(|(member, _)| member == root) || other_marker(root)
        });
        root_list.extend(pnpm_members.iter().map(|(_, workspace)| workspace.clone()));
        root_list.sort();
        root_list.dedup();
    } else {
        // Named roots are kept, with two exceptions that make a run over
        // path selection's `roots` match the detected one: a confirmed
        // member named beside its workspace root (and holding no other
        // lock), and a lockless directory selection named only because a
        // pnpm-workspace.yaml sits above candidate members, none of which
        // it turned out to pin.
        let named: BTreeSet<String> = root_list.iter().cloned().collect();
        let speculative: BTreeSet<&str> = candidates
            .iter()
            .map(|(_, workspace)| workspace.as_str())
            .filter(|workspace| {
                !pnpm_members.iter().any(|(_, w)| w == workspace)
                    && roots::root_markers(workspace, files.keys().map(String::as_str)).is_empty()
            })
            .collect();
        root_list.retain(|root| {
            if speculative.contains(root.as_str()) {
                return false;
            }
            !pnpm_members
                .iter()
                .any(|(member, workspace)| member == root && named.contains(workspace))
                || other_marker(root)
        });
    }
    let detected_roots = root_list.clone();
    let root_list: Vec<String> = root_list
        .into_iter()
        .filter(|root| {
            let markers = roots::root_markers(root, files.keys().map(String::as_str));
            match policy.admits_root(&Root {
                rel_dir: root,
                markers: &markers,
                explicit: explicit_roots,
            }) {
                Ok(()) => true,
                Err(reason) => {
                    policy_filtered.push(FilteredEntry {
                        purl: None,
                        uuid: None,
                        project: root.clone(),
                        reason,
                        severity: None,
                    });
                    false
                }
            }
        })
        .collect();
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
        &detected_roots,
        ecosystems,
        &policy,
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
            purls: Vec::new(),
            summary: ProjectSummary::default(),
            packages: Vec::new(),
            offers: Offers::default(),
            failed_details: Vec::new(),
            rows: Vec::new(),
            selected: Vec::new(),
            skipped: Vec::new(),
            deferred: Vec::new(),
            policy_skipped: Vec::new(),
            error: None,
        })
        .collect();
    demote_pnpm_members(&mut states, &pnpm_members, &mut warnings);
    if options.trust_lockfile_config {
        refuse_governed_pnpm_members(&files, &mut states);
    }
    drop(files);
    demote_cargo_members(&mut states, &mut warnings);
    phases.mark("roots");

    for state in &mut states {
        checkpoint(&cancel).await?;
        let Some(project) = state.project.as_ref() else {
            continue;
        };
        let (entries, unsupported) =
            inventory_project_diagnosed_in(&ProjectView::Memory(project)).await;
        for (code, detail) in
            crate::vendor::lock_inventory::unsupported_layout_warnings(&unsupported)
        {
            warnings.push(EngineWarning::new(code, detail, Some(&state.root)));
        }
        unsupported_ecosystem_warnings(&state.root, project, ecosystems, &mut warnings);
        let purls: BTreeSet<String> = entries
            .iter()
            .filter_map(|e| discover::supplement_purl(&e.purl))
            .filter(|p| ecosystem_allowed(ecosystems, p))
            .collect();
        let mut admitted: Vec<String> = Vec::with_capacity(purls.len());
        for purl in purls {
            match policy.admits_purl(&purl) {
                Ok(()) => admitted.push(purl),
                Err(reason) => policy_filtered.push(FilteredEntry {
                    purl: Some(PurlKey::new(&purl).into_string()),
                    uuid: None,
                    project: state.root.clone(),
                    reason,
                    severity: None,
                }),
            }
        }
        state.purls = admitted;
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
    // A package a failed batch hid could have been NEW (§5.2).
    let mut batch_failed = false;
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
            batch_failed = true;
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
                Some(Err(error)) => {
                    failures.push(error.clone());
                    state.failed_details.push(pkg.purl.clone());
                }
                None => {
                    failures.push("patch details were not fetched".to_string());
                    state.failed_details.push(pkg.purl.clone());
                }
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
        state.offers = select_with_policy(
            &policy,
            results,
            can_access_paid,
            &state.root,
            &mut policy_filtered,
            &mut state.policy_skipped,
        );
    }
    phases.mark("details");

    // Classify every root's selection against its recorded view (§5.1):
    // the tree's manifest and vendor ledger, and the hosted pins its
    // lockfiles name. ALREADY rows carry the recorded uuid, so a re-scan
    // re-confirms a pin instead of swapping it.
    let mut stage = Stage::new(
        options.max_new(policy.max_new_patches()),
        None,
        std::path::Path::new(""),
    );
    // A root whose every lookup failed hides packages that could have been
    // NEW: a capped run then admits none anywhere (§5.2).
    stage.incomplete |= states.iter().any(|s| {
        s.error
            .as_ref()
            .is_some_and(|e| e.code == "patch_lookup_failed")
    });
    let roots_by_path: Vec<String> = states.iter().map(|s| s.root.clone()).collect();
    for state in states.iter_mut() {
        if state.error.is_some() {
            continue;
        }
        let Some(project) = state.project.as_ref() else {
            continue;
        };
        let recorded = memory_recorded(project, &state.root, &roots_by_path).await;
        stage.incomplete |= lookup_incomplete(&recorded, &state.failed_details, batch_failed);
        let mut rows = classify(&state.offers, &recorded, &state.root);
        for row in &mut rows {
            row.candidate.in_flight = options.in_flight.contains(&row.candidate.base_purl);
        }
        state.selected = rows
            .iter()
            .map(|r| (r.writer.purl.clone(), r.writer.uuid.clone()))
            .collect();
        state.rows = rows;
    }
    phases.mark("classify");

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
    // Roots whose rows' eligibility is unknown: a reference failure that
    // hit only NEW rows of a capped run defers them instead of failing the
    // root (§5.2).
    let mut unknown_roots: BTreeSet<String> = BTreeSet::new();
    for state in states.iter_mut().filter(|s| s.error.is_none()) {
        if let Some(error) = state
            .selected
            .iter()
            .find_map(|(_, uuid)| failed_refs.get(uuid))
        {
            if stage.capped() && state.rows.iter().all(|r| r.candidate.recorded.is_new()) {
                stage.incomplete = true;
                stage.reference_failed = Some(error.clone());
                unknown_roots.insert(state.root.clone());
                state.selected.clear();
                continue;
            }
            stage.incomplete = true;
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
        match stages::plan(project, unreadable, &state.selected, &references).await {
            Ok(plan) => planned.push((index, plan)),
            Err(refusal) => state.error = Some(ProjectError::from(refusal)),
        }
    }
    // A pin on the patch server these references name, when that is not
    // Socket's own, is recognized only now (see `mark_pinned`).
    for (index, plan) in &planned {
        if !crate::rollout::stage::any_new(&states[*index].rows) {
            continue;
        }
        let origins = crate::patch::redirect::upstream::foreign_dep_origins(
            plan.candidates.iter().map(|c| &c.dep),
            &[],
        );
        if origins.is_empty() {
            continue;
        }
        let pins = crate::patch::redirect::upstream::HostedPin::discover(
            ProjectView::Memory(&plan.project),
            &origins,
        )
        .await;
        mark_pinned(&mut states[*index].rows, &pins);
    }
    let wheels: BTreeSet<(String, String)> = planned
        .iter()
        .flat_map(|(_, p)| p.wheels.iter().cloned())
        .collect();
    let mut artifact_metadata = if wheels.is_empty() {
        BTreeMap::new()
    } else {
        discover::fetch_wheel_metadata(&provider, &wheels, options.limits.max_artifact_bytes).await
    };
    let npm_manifests: BTreeSet<(String, Option<String>)> = planned
        .iter()
        .flat_map(|(_, p)| p.npm_manifests.iter().cloned())
        .collect();
    if !npm_manifests.is_empty() {
        artifact_metadata.extend(
            discover::fetch_npm_manifests(
                &provider,
                &npm_manifests,
                options.limits.max_artifact_bytes,
            )
            .await,
        );
    }
    phases.mark("plan");

    let stage_options = StageOptions {
        dry_run: options.dry_run,
        pipenv_major: options.pipenv_major,
        trust_lockfile_config: options.trust_lockfile_config,
        npm_allow_remote_config: options.npm_allow_remote_config,
    };
    let mut rewritten: Vec<(usize, Rewritten)> = Vec::new();
    let mut first_plans: BTreeMap<usize, Planned> = BTreeMap::new();
    for (index, plan) in planned {
        checkpoint(&cancel).await?;
        if stage.capped() {
            first_plans.insert(index, plan.clone());
        }
        match stages::rewrite(plan, &artifact_metadata, stage_options).await {
            Ok(done) => rewritten.push((index, done)),
            Err(RewriteRefused { refusal, skipped }) => {
                states[index].skipped = skipped;
                states[index].error = Some(ProjectError::from(refusal));
            }
        }
    }
    phases.mark("rewrite");

    // The run-wide rollout plan (§5.2): one budget across every root, spent
    // after each root's write-free checks (grants, takeover refusals, vlt,
    // wheel metadata, the rewrite's confirmation probe). A root with
    // deferred rows is rewritten again without them.
    let confirmed: BTreeSet<(String, String)> = rewritten
        .iter()
        .flat_map(|(index, done)| {
            let root = states[*index].root.clone();
            done.done
                .confirmed
                .iter()
                .map(move |(_, uuid)| (root.clone(), uuid.clone()))
        })
        .collect();
    let all_rows: Vec<Row> = states
        .iter()
        .filter(|s| s.error.is_none())
        .flat_map(|s| s.rows.iter().cloned())
        .collect();
    stage.plan(&all_rows, |row| {
        unknown_roots.contains(&row.candidate.project)
            || confirmed.contains(&(row.candidate.project.clone(), row.writer.uuid.clone()))
    });
    let deferred_rows: Vec<(crate::rollout::Candidate, u32)> = stage
        .plan
        .as_ref()
        .map(|p| p.deferred.clone())
        .unwrap_or_default();
    if !deferred_rows.is_empty() {
        let root_index: BTreeMap<String, usize> = states
            .iter()
            .enumerate()
            .map(|(i, s)| (s.root.clone(), i))
            .collect();
        for (row, rank) in &deferred_rows {
            let Some(&i) = root_index.get(&row.project) else {
                continue;
            };
            states[i].deferred.push(DeferredPatch {
                purl: row.purl.clone(),
                uuid: row.uuid.clone(),
                severity: crate::rollout::severity_label(row.severity_order).into(),
                rank: *rank,
            });
        }
        let deferred_skip = |d: &DeferredPatch| SkippedPatch {
            purl: d.purl.clone(),
            uuid: d.uuid.clone(),
            reason: ROLLOUT_DEFERRED.to_string(),
            detail: Some(format!(
                "rank {} in the rollout queue; a later scan adds it",
                d.rank
            )),
        };
        let mut again: Vec<(usize, Rewritten)> = Vec::with_capacity(rewritten.len());
        for (index, done) in rewritten {
            let root_deferred: BTreeSet<String> = states[index]
                .deferred
                .iter()
                .map(|d| d.uuid.clone())
                .collect();
            if root_deferred.is_empty() {
                again.push((index, done));
                continue;
            }
            checkpoint(&cancel).await?;
            // The first pass's skips stay (wheel metadata the rewrite could
            // not fetch): its candidates are already gone, so the second
            // pass cannot report them again.
            let Some(mut plan) = first_plans.remove(&index) else {
                again.push((index, done));
                continue;
            };
            plan.candidates
                .retain(|c| !root_deferred.contains(&c.dep.patch_uuid));
            plan.skipped
                .extend(states[index].deferred.iter().map(deferred_skip));
            match stages::rewrite(plan, &artifact_metadata, stage_options).await {
                Ok(done) => again.push((index, done)),
                Err(RewriteRefused { refusal, skipped }) => {
                    states[index].skipped = skipped;
                    states[index].error = Some(ProjectError::from(refusal));
                }
            }
        }
        rewritten = again;
        // Roots that never reached the rewrite (unknown eligibility) list
        // their deferred rows as skipped too.
        for state in states.iter_mut() {
            if unknown_roots.contains(&state.root) && state.error.is_none() {
                let extra: Vec<SkippedPatch> = state.deferred.iter().map(deferred_skip).collect();
                state.skipped.extend(extra);
            }
        }
    }
    for (code, detail) in stage.warnings() {
        warnings.push(EngineWarning::new(code, detail, None));
    }
    phases.mark("rollout");

    let record_uuids: BTreeSet<String> = if options.dry_run {
        BTreeSet::new()
    } else {
        rewritten
            .iter()
            .flat_map(|(_, r)| r.done.confirmed.iter().map(|(_, u)| u.clone()))
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
        let mut result = finish_root(
            state,
            done,
            &records,
            options.dry_run,
            &mut changed,
            &mut changed_binary,
            &mut warnings,
        );
        result.skipped.extend(state.policy_skipped.iter().cloned());
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
            None => crate::hosted::render::redirect_json_block(
                &[],
                &[],
                Vec::new(),
                &[],
                Vec::new(),
                options.dry_run,
            ),
        };
        let mut skipped = state.skipped.clone();
        skipped.extend(state.policy_skipped.iter().cloned());
        projects.push(ProjectResult {
            root: state.root.clone(),
            redirect,
            summary: state.summary.clone(),
            redirected: Vec::new(),
            skipped,
            deferred: state.deferred.clone(),
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
        rollout: stage.json(),
        stats,
        engine_version: engine_version(),
        policy: Some(policy_block(&policy, &policy_filtered, &[])),
        policy_error: None,
    })
}

/// The root policy files as the session received them. A path selection
/// listed but the host never sent is present without content (never
/// absent: it may narrow the scan).
fn memory_policy_fs(files: &BTreeMap<String, SharedFile>, listed: &[String]) -> MemoryPolicyFs {
    let mut fs = MemoryPolicyFs::default();
    for name in POLICY_FILE_NAMES {
        let file = match files.get(name).map(|f| &f.entry) {
            Some(MemoryEntry::Text(text)) => RootFile::Present(text.as_bytes().to_vec()),
            Some(MemoryEntry::Binary(bytes)) => RootFile::Present(bytes.to_vec()),
            Some(_) => RootFile::PresentWithoutContent,
            None if listed.iter().any(|l| l == name) => RootFile::PresentWithoutContent,
            None => continue,
        };
        fs.files.insert(name.to_string(), file);
        fs.root_names.push(name.to_string());
    }
    fs
}

/// The session result for a policy file that cannot be honored: no root
/// processed, no file changed.
fn policy_error_output(
    error: &crate::policy::PolicyError,
    warnings: Vec<EngineWarning>,
    files_input: u64,
    bytes_input: u64,
) -> HostedScanOutput {
    HostedScanOutput {
        projects: Vec::new(),
        changed_files: Vec::new(),
        changed_binary_files: Vec::new(),
        deleted_files: Vec::new(),
        warnings,
        rollout: serde_json::Value::Null,
        stats: EngineStats {
            files_input,
            bytes_input,
            ..EngineStats::default()
        },
        engine_version: engine_version(),
        policy: None,
        policy_error: Some(PolicyErrorInfo {
            code: error.code().to_string(),
            detail: error.detail(),
        }),
    }
}

/// The tier filter, the severity floor and the per-package ranking (the
/// disk `ScanPolicy::select` without a recorded view, which the in-memory
/// engine does not read yet). With `patches.enabled: false` nothing is
/// selected and every candidate is reported `policy_disabled`.
fn select_with_policy(
    policy: &SelectionPolicy,
    results: Vec<PatchSearchResult>,
    can_access_paid: bool,
    root: &str,
    filtered: &mut Vec<FilteredEntry>,
    skipped: &mut Vec<SkippedPatch>,
) -> Offers {
    let accessible: Vec<PatchSearchResult> = results
        .into_iter()
        .filter(|p| can_access_paid || p.tier == "free")
        .collect();
    let (admitted, dropped) = if policy.enabled() {
        policy.floor_filter(accessible)
    } else {
        (
            Vec::new(),
            accessible
                .into_iter()
                .map(|p| (p, FilterReason::Disabled))
                .collect(),
        )
    };
    let offers = offers_from_results(&admitted, true);
    let chosen: BTreeSet<&str> = offers.selected.keys().map(String::as_str).collect();
    let mut by_purl: BTreeMap<String, Vec<(PatchSearchResult, FilterReason)>> = BTreeMap::new();
    for (patch, reason) in dropped {
        if !chosen.contains(patch.purl.as_str()) {
            by_purl
                .entry(patch.purl.clone())
                .or_default()
                .push((patch, reason));
        }
    }
    for (purl, mut group) in by_purl {
        group.sort_by(|a, b| crate::api::ranking::cmp_search_results(&a.0, &b.0));
        let (winner, reason) = group.swap_remove(0);
        skipped.push(SkippedPatch {
            purl: purl.clone(),
            uuid: winner.uuid.clone(),
            reason: reason.code().to_string(),
            detail: Some(reason.detail()),
        });
        filtered.push(FilteredEntry {
            purl: Some(PurlKey::new(&purl).into_string()),
            uuid: Some(winner.uuid.clone()),
            project: root.to_string(),
            severity: Some(patch_severity_order(&winner)),
            reason,
        });
    }
    offers
}

/// Records → the project's result and changed files.
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
        project,
        skipped,
        pre_warnings,
        done,
        unconfirmed,
    } = done;
    let crate::hosted::engine::Rewritten {
        rewrite,
        rewritten,
        confirmed,
        rush_warnings,
        pnpm_warnings,
        npm_warnings,
        ..
    } = done;
    let root = state.root.clone();
    // No ledger keeps the records; the fetch mirrors the disk flow's, so a
    // record the API cannot serve warns the same way.
    let mut record_warnings: Vec<crate::patch::redirect::RewriteWarning> = Vec::new();
    if !dry_run {
        for (purl, uuid) in &confirmed {
            match records.get(uuid) {
                Some(Some(_)) => {}
                _ => record_warnings.push(crate::hosted::engine::record_fetch_failed_warning(purl)),
            }
        }
    }

    let mut project_changes: Vec<(String, String)> = Vec::new();
    for (rel, content) in &rewrite.files {
        if project.text(rel) != Some(content.as_str()) {
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
                project.get(rel.as_str()),
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
            skipped,
            deferred: state.deferred.clone(),
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

    // One typed list in the envelope's order; JSON only at the boundary.
    let mut warnings = rewrite.warnings.clone();
    warnings.extend(record_warnings);
    warnings.extend(rush_warnings);
    warnings.extend(pnpm_warnings);
    warnings.extend(npm_warnings);
    warnings.extend(pre_warnings);
    let redirect_warnings = crate::hosted::render::rewrite_warnings_json(&warnings);
    let redirect = crate::hosted::render::redirect_json_block(
        &confirmed,
        &unconfirmed,
        rewritten,
        &skipped,
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
        skipped,
        deferred: state.deferred.clone(),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::redirect::{FileEdit, RewriteResult};

    fn state(root: &str, project: MemoryProject) -> RootState {
        RootState {
            root: root.to_string(),
            project: Some(project),
            unreadable: BTreeSet::new(),
            purls: Vec::new(),
            summary: ProjectSummary::default(),
            packages: Vec::new(),
            offers: Offers::default(),
            failed_details: Vec::new(),
            rows: Vec::new(),
            selected: Vec::new(),
            skipped: Vec::new(),
            deferred: Vec::new(),
            policy_skipped: Vec::new(),
            error: None,
        }
    }

    fn rewritten(files: &[(&str, &str)]) -> Rewritten {
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
            project: MemoryProject::new(),
            skipped: Vec::new(),
            pre_warnings: Vec::new(),
            unconfirmed: Vec::new(),
            done: crate::hosted::engine::Rewritten {
                files: BTreeMap::new(),
                symlinked_reads: Vec::new(),
                unreadable_reads: Vec::new(),
                undecodable_reads: Vec::new(),
                overrides: Vec::new(),
                rewrite,
                rewritten: files.iter().map(|(rel, _)| (*rel).to_string()).collect(),
                confirmed: vec![("pkg:cargo/serde@1.0.190".into(), "u".into())],
                unattributed: Vec::new(),
                binary_bun: false,
                rush_warnings: Vec::new(),
                pnpm_warnings: Vec::new(),
                npm_warnings: Vec::new(),
                pnpm_rerun_only: false,
                workspace_symlinked: false,
                final_discovery: None,
            },
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
        done.done
            .rewrite
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

    /// #975: a nested yarn root's loader follows a `nodeLinker` set only in
    /// a repository `.yarnrc.yml` above it, as the disk walk does.
    #[tokio::test]
    async fn nested_yarn_root_follows_an_ancestor_yarnrc_linker() {
        use crate::vendor::npm_flavor::detect_npm_lock_flavor_in;
        let mut files: BTreeMap<String, SharedFile> = BTreeMap::new();
        files.insert(
            ".yarnrc.yml".into(),
            share(InputFile::Text("nodeLinker: node-modules\n".into())),
        );
        files.insert(
            "apps/.yarnrc.yml".into(),
            share(InputFile::Text("enableGlobalCache: false\n".into())),
        );
        files.insert(
            "apps/web/yarn.lock".into(),
            share(InputFile::Text("__metadata:\n  version: 8\n".into())),
        );
        files.insert(
            "apps/web/.pnp.cjs".into(),
            share(InputFile::Present(PresentKind::Present)),
        );
        let (web, _) = project_for("apps/web", &files);
        assert!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&web))
                .await
                .is_ok(),
            "the repository rc disowns the stale loader"
        );
        files.insert(
            "apps/.yarnrc.yml".into(),
            share(InputFile::Text("nodeLinker: pnp\n".into())),
        );
        let (web, _) = project_for("apps/web", &files);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&web))
                .await
                .unwrap_err()
                .0,
            "vendor_yarn_berry_unsupported",
            "the nearest rc above the project wins"
        );
    }

    /// A multi-project sbt build (no lock, so no root): its root and
    /// subproject `build.sbt` files raise one run-level maven warning. In a
    /// rooted repo the root's own `build.sbt` is the root's (rooted)
    /// warning, and only the subprojects' stay run-level.
    #[test]
    fn sbt_build_files_warn_unsupported_in_memory() {
        let paths = [
            "build.sbt",
            "a/build.sbt",
            "b/build.sbt",
            "project/build.properties",
            "project/plugins.sbt",
            "a/src/main/scala/A.scala",
        ];
        let mut out = Vec::new();
        unrooted_unsupported_warnings(
            paths.into_iter(),
            &[],
            None,
            crate::policy::builtin_defaults(),
            &mut out,
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].code, "ecosystem_unsupported_in_memory");
        assert!(out[0].project_root.is_none());
        assert!(
            out[0]
                .detail
                .starts_with("build.sbt (and 2 more) is present, but maven"),
            "{}",
            out[0].detail
        );
        let mut rooted = Vec::new();
        unrooted_unsupported_warnings(
            paths.into_iter(),
            &[String::new()],
            None,
            crate::policy::builtin_defaults(),
            &mut rooted,
        );
        assert_eq!(rooted.len(), 1, "{rooted:?}");
        assert!(
            rooted[0].detail.starts_with("a/build.sbt (and 1 more)"),
            "{}",
            rooted[0].detail
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
        unrooted_unsupported_warnings(
            paths.into_iter(),
            &["web".to_string()],
            None,
            crate::policy::builtin_defaults(),
            &mut out,
        );
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
            crate::policy::builtin_defaults(),
            &mut filtered,
        );
        assert!(filtered.is_empty());
    }

    /// REGRESSION: the in-memory recorded view counts a lockless NuGet /
    /// Cargo pin (never a discovery ref) as recorded, so a re-scan under a
    /// cap reads the pin it wrote as ALREADY instead of spending a NEW slot.
    #[tokio::test]
    async fn memory_recorded_counts_lockless_nuget_and_cargo_pins() {
        const NUGET: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        const CARGO: &str = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb";
        const GRANT: &str = "cccccccc-3333-4333-8333-cccccccccccc";
        let key = format!("socket-patch-{NUGET}");
        let mut p = MemoryProject::new();
        p.insert_text(
            "nuget.config",
            format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
                 <add key=\"{key}\" value=\"https://patch.socket.dev/patch-registry/nuget/{GRANT}/{NUGET}/index.json\" />\n  \
                 </packageSources>\n  <packageSourceMapping>\n    <packageSource key=\"{key}\">\n      \
                 <package pattern=\"Newtonsoft.Json\" />\n    </packageSource>\n  \
                 </packageSourceMapping>\n</configuration>\n"
            ),
        );
        p.insert_text(
            "Cargo.toml",
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\n\
                 serde = {{ version = \"1\", registry = \"socket-patch-{CARGO}\" }}\n"
            ),
        );
        p.insert_text(
            ".cargo/config.toml",
            format!(
                "[registries.socket-patch-{CARGO}]\nindex = \
                 \"sparse+https://patch.socket.dev/patch-registry/cargo/{GRANT}/{CARGO}/index/\"\n"
            ),
        );
        let index = memory_recorded(&p, "", &[String::new()]).await;
        assert_eq!(index.uuids("pkg:nuget/Newtonsoft.Json@13.0.3"), [NUGET]);
        assert_eq!(index.uuids("pkg:cargo/serde@1.0.200"), [CARGO]);
        assert!(index.records_package("pkg:cargo/serde@1.0.200"));
        assert!(index.uuids("pkg:cargo/serde@2.0.0").is_empty());
        assert!(index.uuids("pkg:nuget/Other@1.0.0").is_empty());
    }
}
