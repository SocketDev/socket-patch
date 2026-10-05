//! The hosted redirect engine: plan → rewrite → edits over a
//! [`ProjectView`], shared verbatim by `scan`/`get --mode hosted` (a
//! [`ProjectView::Disk`] over the checkout) and the in-memory engine
//! ([`super::memory`], a [`ProjectView::Memory`] over the host's file set).
//!
//! The stages, in the order both callers run them:
//!
//! 1. [`build_candidates`] — reference grants → rewriter overrides.
//! 2. [`bun_lockb_symlinked`] — the binary-lock symlink refusal.
//! 3. vlt artifact preflight ([`super::vlt`]) + [`withhold_everywhere`].
//! 4. (caller) the apply lock, the ledger, the vendored→hosted takeover.
//! 5. [`read_candidate_files`] → [`wheel_targets`] → (caller) wheel metadata,
//!    and [`yarn_berry_manifest_targets`] → (caller) served npm manifests.
//! 6. [`rewrite`] — the rewriters, the pnpm `trustLockfile` and npm
//!    `allow-remote` auto-configs, and the per-ecosystem confirmation.
//! 7. [`guard`] — the symlink / unreadable-file refusal before any write.
//!
//! Nothing here writes, spawns, reads the environment or touches the
//! network: every host effect (locking, probes, record fetches, the commit
//! of the rewritten files, the redirect ledger in [`super::ledger`]) stays
//! with the caller.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::api::types::PackageVendorResult;
use crate::constants::npm_family::{
    RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR, VLT_HIDDEN_LOCK_REL, VLT_LOCK,
};
use crate::patch::redirect::npmrc::{
    plan_npmrc_allow_remote_with, NpmrcPlan, OuterAllowRemote, NPMRC_ALLOW_REMOTE_EDIT_KIND,
    NPMRC_REL,
};
use crate::patch::redirect::presence::groups_present;
use crate::patch::redirect::{
    artifact_url_spellings, rewrite_registry_redirect_withholding_vlt, DepOverride, FileEdit,
    RewriteResult, RewriteWarning,
};
use crate::utils::purl::purl_parts;
use crate::vendor::lock_inventory::{MemoryEntry, ProjectView};

use super::guidance::{
    npm_allow_remote_already_detail, npm_allow_remote_configured_detail,
    npm_allow_remote_env_set_detail, npm_allow_remote_manual_detail,
    npm_allow_remote_outer_set_detail, npm_allow_remote_unreadable_detail,
    npm_allow_remote_user_set_detail, npm_lock_url_needles, plan_workspace_trust, pnpm_heal_root,
    pnpm_lock_may_need_store_flag, pnpm_lock_version_major, pnpm_trust_configured_detail,
    pnpm_trust_legacy_detail, pnpm_trust_manual_guidance, pnpm_trust_policy_preamble,
    pnpm_trust_workspace_unreadable_detail, pnpm_trust_workspace_unsupported_detail,
    read_npmrc_for_allow_remote, read_workspace_for_trust, url_host, TrustPlan, NPM_LOCKS,
    PNPM_TRUST_TRADEOFF_AND_CAUTION, PNPM_WORKSPACE_REL, REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND,
};
use super::vlt::bun_lockb_present;

/// Candidate lockfiles / registry configs the redirect rewriters may touch —
/// read from the project when present and handed to
/// `rewrite_registry_redirect`: the [`crate::formats::registry::HOSTED`]
/// rows of the format registry, in its read order.
pub static REDIRECT_CANDIDATE_FILES: std::sync::LazyLock<Vec<&'static str>> =
    std::sync::LazyLock::new(|| {
        crate::formats::registry::paths_with(crate::formats::registry::HOSTED)
    });

/// Refusal code for a rewrite target (or a file the rewrite reads) that is
/// a symbolic link: the writers stage next to the path and rename over it,
/// which would replace the link with a detached copy.
pub const SYMLINK_REFUSAL: &str = "redirect_symlinked_file_unsupported";

/// Refusal code for a candidate file that exists but whose content the
/// in-memory host did not provide (oversize, an LFS pointer,
/// presence-only); disk would read and rewrite it.
pub const UNREADABLE_REFUSAL: &str = "candidate_file_unreadable";

/// Rush's repo-state file, whose `pnpmShrinkwrapHash` a lock edit
/// outside `rush update` desyncs.
pub const RUSH_REPO_STATE_REL: &str = "common/config/rush/repo-state.json";

/// One granted reference: the purl it was granted for plus the rewriter
/// override built from it. The purl is what the takeover, the skip records
/// and the confirmation probe key on; everything the probe needs AFTER the
/// rewrite to decide whether the dep was actually redirected (artifact
/// URL, registry index URL, fail-closed maven's suffixed version) already
/// rides the override. The single vector is filtered in place by every
/// withhold/refusal step, and the rewriters' `overrides` slice is
/// materialized from it once, after the last filter.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub purl: String,
    pub dep: DepOverride,
}

/// A selected patch that was not redirected, and why (the `skipped[]`
/// entries of the `redirect` block).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedPatch {
    pub purl: String,
    pub uuid: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SkippedPatch {
    pub fn new(purl: &str, uuid: &str, reason: &str) -> Self {
        SkippedPatch {
            purl: purl.to_string(),
            uuid: uuid.to_string(),
            reason: reason.to_string(),
            detail: None,
        }
    }
}

/// A whole-project refusal: nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: String,
    pub message: String,
}

/// The refusal for a symlinked rewrite target.
pub fn symlink_refusal(linked: &str) -> Refusal {
    Refusal {
        code: SYMLINK_REFUSAL.to_string(),
        message: format!(
            "{linked} is a symbolic link; socket-patch rewrites files in place with an atomic \
             rename, which would replace the link — replace the link with a regular file (or \
             run socket-patch in the directory it points to) and re-run; nothing was written"
        ),
    }
}

/// The refusal for a symlinked `bun.lockb` (checked before any takeover
/// changes wiring).
pub fn bun_lockb_symlink_refusal() -> Refusal {
    Refusal {
        code: SYMLINK_REFUSAL.to_string(),
        message: "bun.lockb is a symbolic link; replace it with a regular file (or run \
                  socket-patch in the directory it points to) before patching; nothing was \
                  written"
            .to_string(),
    }
}

fn unreadable_refusal(rel: &str) -> Refusal {
    Refusal {
        code: UNREADABLE_REFUSAL.to_string(),
        message: format!(
            "{rel} exists but its content was not provided (too large, an LFS pointer, or \
             not fetched), so it cannot be rewritten alongside the other lockfiles; nothing \
             was written"
        ),
    }
}

/// Reference grants → candidates. A selection without a usable grant is
/// recorded in `skipped` (`not_found`, the reference status, `bad_purl`,
/// `no_url`).
pub fn build_candidates(
    selected: &[(String, String)],
    references: &HashMap<String, PackageVendorResult>,
    skipped: &mut Vec<SkippedPatch>,
) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    for (sel_purl, sel_uuid) in selected {
        let Some(reference) = references.get(sel_uuid) else {
            skipped.push(SkippedPatch::new(sel_purl, sel_uuid, "not_found"));
            continue;
        };
        if reference.status != "granted" && reference.status != "reused" {
            skipped.push(SkippedPatch::new(sel_purl, sel_uuid, &reference.status));
            continue;
        }
        let purl = reference.purl.as_deref().unwrap_or(sel_purl);
        let Some((ecosystem, name, version)) = purl_parts(purl) else {
            skipped.push(SkippedPatch::new(purl, sel_uuid, "bad_purl"));
            continue;
        };
        let Some(url) = reference.url.clone() else {
            skipped.push(SkippedPatch::new(purl, sel_uuid, "no_url"));
            continue;
        };
        let mut integrity = reference
            .artifacts
            .iter()
            .flatten()
            .find(|a| a.kind == "tarball")
            .map(|a| a.integrity.clone())
            .unwrap_or_default();
        // The yarn-berry cache zip carries the `yarnBerry10c0` checksum the
        // berry rewriter pins (berry verifies the zip, not the tarball).
        // Merge it in; the zip URL itself is never read.
        let berry_zip = reference
            .artifacts
            .iter()
            .flatten()
            .find(|a| a.kind == "yarn-berry-zip");
        if let Some(c) = berry_zip.and_then(|a| a.integrity.yarn_berry10c0.clone()) {
            integrity.yarn_berry10c0 = Some(c);
        }
        // goproxy: the hosted-Go hash pair rides the override's
        // identifiers (the tarball's dirhashH1 is the original-path
        // flavor, kept for vendor-mode verification); the golang rewriter
        // reads the normalized integrity, so merge — the gopatch-flavor zip
        // h1 REPLACES dirhashH1 here. Only both together: a half-merged
        // pair would trip the rewriter's fail-closed integrity check by
        // design.
        if let Some(ov) = reference
            .registry_override
            .as_ref()
            .filter(|o| o.kind == "goproxy")
        {
            if let (Some(zip_h1), Some(gomod_h1)) = (
                ov.identifiers.go_zip_dirhash_h1.clone(),
                ov.identifiers.go_mod_h1.clone(),
            ) {
                integrity.dirhash_h1 = Some(zip_h1);
                integrity.go_mod_h1 = Some(gomod_h1);
            }
        }
        // The grant token is never a top-level reference field — it only
        // rides the URLs the reference endpoint hands back, as the path
        // level before the patch uuid. Recover it so the rewriters'
        // rotation-idempotency guards (which wildcard the token path level
        // of a previously-written URL) don't depend on it being derivable
        // from the URL alone (an empty token makes the gem guard nest a new
        // source block on every re-scan).
        let token = reference
            .registry_override
            .as_ref()
            .and_then(|o| crate::patch::redirect::grant_token_path_segment(&o.index_url, sel_uuid))
            .or_else(|| crate::patch::redirect::grant_token_path_segment(&url, sel_uuid))
            .unwrap_or_default();
        candidates.push(Candidate {
            purl: purl.to_string(),
            dep: DepOverride {
                ecosystem,
                name,
                namespace: None,
                version,
                token,
                patch_uuid: sel_uuid.clone(),
                artifact_url: url,
                registry_override: reference.registry_override.clone(),
                integrity,
            },
        });
    }
    candidates
}

/// Whether the text `bun.lock` is present (disk: `exists`). Text retains
/// Bun's precedence when both lock spellings are present.
pub fn bun_lock_present(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(cwd)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot {
            root: cwd, ..
        }) => cwd.join("bun.lock").exists(),
        ProjectView::Memory(project) => project.contains("bun.lock"),
    }
}

/// Whether an npm candidate would rewrite a `bun.lockb` that is a symbolic
/// link (atomic replacement cannot preserve a link; previews refuse too).
pub fn bun_lockb_symlinked(view: &ProjectView<'_>, candidates: &[Candidate]) -> bool {
    candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && !bun_lock_present(view)
        && view.is_symlink("bun.lockb")
}

/// Drop the deps the vlt preflight withheld from every rewriter, recording
/// each as skipped.
pub fn withhold_everywhere(
    candidates: &mut Vec<Candidate>,
    withheld_everywhere: &BTreeMap<String, String>,
    skipped: &mut Vec<SkippedPatch>,
) {
    if withheld_everywhere.is_empty() {
        return;
    }
    for (uuid, purl) in withheld_everywhere {
        skipped.push(SkippedPatch::new(purl, uuid, super::vlt::WITHHELD_REASON));
    }
    candidates.retain(|c| !withheld_everywhere.contains_key(&c.dep.patch_uuid));
}

/// The project's candidate files as the rewriters read them.
#[derive(Debug, Clone, Default)]
pub struct CandidateFiles {
    /// Readable candidate texts, keyed by project-relative path.
    pub files: BTreeMap<String, String>,
    /// The Rush locks among `files` (the repo-state warning keys on them).
    pub rush_lock_keys: Vec<String>,
    /// In memory only: candidate files the disk flow reads through a
    /// symbolic link. Their bytes are unknown here, so a project whose
    /// candidates could rewrite one is refused like the disk symlink guard
    /// refuses the write.
    pub symlinked_reads: Vec<String>,
    /// In memory only: candidate files that exist without content; a
    /// project whose candidates could rewrite (or whose rewrite depends on)
    /// one is refused, since the rewriters would treat it as absent.
    pub unreadable_reads: Vec<String>,
    /// Gradle build files the script graph reached that exist but cannot be
    /// read as text (any view): the hosted Gradle planner refuses the build
    /// instead of taking them for absent (and creating a settings file over
    /// one).
    pub gradle_unreadable: BTreeSet<String>,
    /// Set when bundler is configured (`BUNDLE_GEMFILE`) to load a manifest
    /// the gem rewriter cannot edit: every gem manifest and lock was left
    /// out of `files`, and the rewrite reports this instead of a redirect.
    pub gem_manifest_unsupported: Option<RewriteWarning>,
}

impl CandidateFiles {
    /// Read `rel` into `files`: `true` when it was read.
    async fn read(
        &mut self,
        view: &ProjectView<'_>,
        unreadable: &BTreeSet<String>,
        rel: &str,
    ) -> bool {
        let text = match view {
            // Every disk read goes through the FIFO-safe reader
            // (non-blocking open + fstat regular-file check), so a FIFO
            // under a candidate name is skipped like a missing file instead
            // of wedging the run in open(2).
            ProjectView::Disk(_) | ProjectView::Snapshot(_) => view.read_text(rel).await.ok(),
            ProjectView::Memory(project) => {
                if project.is_symlink(rel) {
                    self.symlinked_reads.push(rel.to_string());
                    return false;
                }
                if unreadable.contains(rel) {
                    self.unreadable_reads.push(rel.to_string());
                    return false;
                }
                // Disk reads any UTF-8 regular file; a non-UTF-8 one is
                // absent to it as well.
                match project.get(rel) {
                    Some(MemoryEntry::Text(text)) => Some(text.to_string()),
                    Some(MemoryEntry::Binary(bytes)) => {
                        std::str::from_utf8(bytes).ok().map(str::to_string)
                    }
                    _ => None,
                }
            }
        };
        match text {
            Some(text) => {
                self.files.insert(rel.to_string(), text);
                true
            }
            None => false,
        }
    }
}

/// The root-level Python lock names (sorted).
async fn python_lock_paths(view: &ProjectView<'_>) -> Vec<String> {
    match view {
        ProjectView::Disk(cwd)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot {
            root: cwd, ..
        }) => crate::utils::python_lock::python_lock_paths(cwd).unwrap_or_default(),
        ProjectView::Memory(project) => project
            .children("")
            .into_iter()
            .filter(|(name, is_dir)| {
                !is_dir && crate::utils::python_lock::is_python_lock_name(name)
            })
            .map(|(name, _)| name)
            .collect(),
    }
}

/// Whether the project is a Rush monorepo (disk: `rush.json` is a file).
fn rush_repo(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(cwd)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot {
            root: cwd, ..
        }) => cwd.join("rush.json").is_file(),
        ProjectView::Memory(project) => project.contains("rush.json"),
    }
}

/// Whether `rel` is a [`PRESENCE_ONLY`](crate::formats::registry::PRESENCE_ONLY)
/// row the in-memory host lists without usable content (a symbolic link,
/// an oversize or presence-only entry). Its planners only ask whether it
/// exists — the Pipenv planner tells a live `Pipfile.lock` from an
/// abandoned one by the `Pipfile` beside it — so it is recorded as present
/// (empty) rather than dropped. Disk reads such a file through any link.
fn presence_only_present(view: &ProjectView<'_>, rel: &str) -> bool {
    let ProjectView::Memory(project) = view else {
        return false;
    };
    project.contains(rel)
        && crate::formats::registry::registry()
            .iter()
            .any(|f| f.path == rel && f.has(crate::formats::registry::PRESENCE_ONLY))
}

/// Read `rel` as advisory rewriter input: a link or an unreadable in-memory
/// entry is left out (the rewriter then keeps its conservative reading)
/// rather than refused like a file the rewrite writes.
async fn read_advisory(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    rel: &str,
) -> Option<String> {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => view.read_text(rel).await.ok(),
        ProjectView::Memory(project) if !project.is_symlink(rel) && !unreadable.contains(rel) => {
            match project.get(rel) {
                Some(MemoryEntry::Text(text)) => Some(text.to_string()),
                Some(MemoryEntry::Binary(bytes)) => {
                    std::str::from_utf8(bytes).ok().map(str::to_string)
                }
                _ => None,
            }
        }
        ProjectView::Memory(_) => None,
    }
}

/// Read the project's candidate files: [`REDIRECT_CANDIDATE_FILES`], the
/// Cargo workspace members (when a cargo candidate meets a root
/// `Cargo.toml`), the Python locks and their scripts, and the Rush locks.
/// `unreadable` are the in-memory paths that exist without content.
pub async fn read_candidate_files(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    candidates: &[Candidate],
) -> CandidateFiles {
    let mut out = CandidateFiles::default();
    for name in REDIRECT_CANDIDATE_FILES.iter() {
        // The binary lock is read and rewritten directly.
        if *name == "bun.lockb" {
            continue;
        }
        // The hidden lock is only the install-state sentinel, never read.
        if *name == VLT_HIDDEN_LOCK_REL {
            if super::vlt::install_state_present(view) {
                out.files.insert((*name).to_string(), String::new());
            }
            continue;
        }
        if !out.read(view, unreadable, name).await && presence_only_present(view, name) {
            out.files.insert((*name).to_string(), String::new());
        }
    }

    // A yarn berry lock is pinned through the root manifest's `resolutions`
    // (see `patch::redirect::rewrite_yarn_berry`), so beside one the
    // manifest is a rewrite target: read strictly, a link or an unreadable
    // in-memory entry refused like any other file the rewrite writes.
    if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && out
            .files
            .get("yarn.lock")
            .is_some_and(|lock| crate::patch::redirect::is_berry_lock(lock))
    {
        out.read(view, unreadable, "package.json").await;
    // Otherwise the root manifest's `overrides` decide which git / url /
    // `file:` dependent specs npm really installs from (#490). Only the npm
    // lock rewriter reads it, as advisory input: no rewriter edits it, so a
    // link or an unreadable in-memory entry is left out (the rewriter then
    // keeps its conservative reading) rather than refused.
    } else if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && NPM_LOCKS.iter().any(|lock| out.files.contains_key(*lock))
    {
        let rel = crate::hosted::memory::select::NPM_MANIFEST_REL;
        if let Some(text) = read_advisory(view, unreadable, rel).await {
            out.files.insert(rel.to_string(), text);
        }
    }

    // A text `bun.lock` names its workspace members; each member's manifest
    // says which `workspace:` literal its inter-workspace dependencies carry,
    // which the bun rewriter restores over a member path a migrated binary
    // lock left behind (#803). Advisory input like the npm manifest above:
    // keyed `<dir>/package.json` (the root as `package.json`), never
    // rewritten, and a member dir that is not a plain relative path is
    // never read.
    if candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        if let Some(lock) = out.files.get("bun.lock") {
            let lines: Vec<String> = lock.split('\n').map(str::to_string).collect();
            for dir in crate::vendor::bun_lock_text::workspace_member_dirs(&lines) {
                if !crate::vendor::bun_lock_text::is_plain_member_dir(&dir) {
                    continue;
                }
                let rel = if dir.is_empty() {
                    "package.json".to_string()
                } else {
                    format!("{dir}/package.json")
                };
                if out.files.contains_key(&rel) {
                    continue;
                }
                if let Some(text) = read_advisory(view, unreadable, &rel).await {
                    out.files.insert(rel, text);
                }
            }
        }
        // The root manifest's `patchedDependencies` names the packages the
        // project patches itself with `bun patch`, which the bun rewriters
        // must leave on their registry tuple (#367). Read beside either bun
        // lock, advisory too: the member walk above reaches the root only
        // through a `workspaces` section in bun's emitted shape.
        if !out.files.contains_key("package.json")
            && (out.files.contains_key("bun.lock") || super::vlt::bun_lockb_present(view))
        {
            if let Some(text) = read_advisory(view, unreadable, "package.json").await {
                out.files.insert("package.json".to_string(), text);
            }
        }
    }

    // Cargo workspace members (and in-root path dependencies) declare
    // dependencies of their own: a member's direct `cfg-if = "1"` must be
    // pinned alongside the root's, or the redirected lock entry is
    // unsatisfiable. Keyed `<dir>/Cargo.toml` for the cargo rewriter.
    if out.files.contains_key("Cargo.toml") && candidates.iter().any(|c| c.dep.ecosystem == "cargo")
    {
        for rel in crate::utils::cargo_workspace::member_manifests_in(view) {
            out.read(view, unreadable, &rel).await;
        }
    }

    for path in python_lock_paths(view).await {
        if let Some(script) = crate::utils::python_lock::script_of_lock(&path) {
            out.read(view, unreadable, script).await;
        }
        out.read(view, unreadable, &path).await;
    }

    // Rush monorepos have no root package.json/lock pair: the single pnpm
    // source-of-truth lock lives at common/config/rush/pnpm-lock.yaml, and
    // (when subspaces are enabled) one lock per subspace under
    // common/config/subspaces/<name>/. Added under their repo-relative
    // keys — the pnpm rewriter is basename-generalized, so nested keys are
    // rewritten in place, and the write-back is path-generic.
    if rush_repo(view) {
        if out.read(view, unreadable, RUSH_COMMON_LOCK_REL).await {
            out.rush_lock_keys.push(RUSH_COMMON_LOCK_REL.to_string());
        }
        // Sorted by name: deterministic output.
        if let Ok(entries) = view.list_dir(RUSH_SUBSPACES_DIR).await {
            for entry in entries.into_iter().filter(|e| e.is_dir) {
                let key = format!("{RUSH_SUBSPACES_DIR}/{}/pnpm-lock.yaml", entry.name);
                if out.read(view, unreadable, &key).await {
                    out.rush_lock_keys.push(key);
                }
            }
        }
    }
    if candidates.iter().any(|c| c.dep.ecosystem == "gem") {
        keep_bundler_loaded_gem_files(view, &mut out).await;
    }
    // A Gradle build: every script, catalog and lock file its script graph
    // reaches, for the hosted Gradle planner.
    if candidates.iter().any(|c| c.dep.ecosystem == "maven")
        && crate::patch::redirect::gradle::gradle_build_present(&out.files)
    {
        read_gradle_files(view, unreadable, &mut out).await;
    }
    out.symlinked_reads.sort();
    out.symlinked_reads.dedup();
    out.unreadable_reads.sort();
    out.unreadable_reads.dedup();
    out
}

/// Read what the hosted Gradle planner needs into `out` (see
/// [`crate::patch::redirect::gradle::GradleFiles`]): the script graph is
/// re-walked over what was read so far until it asks for nothing new
/// (bounded by its own caps and [`MAX_ROUNDS`] rounds). A missing file is
/// absent to the graph, which records it as unresolved; one that exists
/// but cannot be read as text is absent to the graph too, and listed in
/// [`CandidateFiles::gradle_unreadable`] so the planner refuses the build;
/// a directory that cannot be listed lists as empty.
///
/// [`MAX_ROUNDS`]: crate::patch::redirect::gradle::MAX_ROUNDS
async fn read_gradle_files(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    use crate::patch::redirect::gradle::{GradleFiles, MAX_ROUNDS};
    let mut gradle = GradleFiles::default();
    for (rel, text) in &out.files {
        gradle.found(rel, text.clone());
    }
    for _ in 0..MAX_ROUNDS {
        let (reads, lists) = gradle.misses();
        if reads.is_empty() && lists.is_empty() {
            break;
        }
        for rel in reads {
            match read_gradle_file(view, unreadable, out, &rel).await {
                Some(text) => gradle.found(&rel, text),
                None => gradle.absent(&rel),
            }
        }
        for dir in lists {
            let children = view
                .list_dir(&dir)
                .await
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| {
                            if e.is_dir {
                                format!("{}/", e.name)
                            } else {
                                e.name
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            gradle.listed(&dir, children);
        }
    }
}

/// Read one Gradle file into `out` for [`read_gradle_files`]: its text, or
/// `None` when it is missing or cannot be read — in which case a file that
/// exists (permissions, non-UTF-8 bytes, not a regular file, content not
/// provided in memory) is recorded in `gradle_unreadable`.
async fn read_gradle_file(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
    rel: &str,
) -> Option<String> {
    let exists = match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => match view.read_text(rel).await {
            Ok(text) => {
                out.files.insert(rel.to_string(), text.clone());
                return Some(text);
            }
            Err(e) => !crate::patch::redirect::gradle::is_absent_error(&e),
        },
        ProjectView::Memory(project) => {
            if out.read(view, unreadable, rel).await {
                return out.files.get(rel).cloned();
            }
            project.get(rel).is_some()
        }
    };
    if exists {
        out.gradle_unreadable.insert(rel.to_string());
    }
    None
}

/// The Bundler manifest/lock spellings among the candidate files.
const GEM_MANIFEST_FILES: [&str; 4] = ["Gemfile", "Gemfile.lock", "gems.rb", "gems.locked"];

/// Leave only the gem manifest pair bundler loads in the candidate set
/// (see [`crate::formats::gem::manifest`]). The gem rewriter picks between
/// the two default spellings by filename alone; this narrows what it sees
/// to bundler's own choice, so it can never wire a manifest bundler
/// ignores:
///
/// - no `BUNDLE_GEMFILE`: unchanged (the rewriter's `gems.rb`-first choice
///   and its divergence guard are bundler's default discovery);
/// - `BUNDLE_GEMFILE` naming the root `Gemfile` / `gems.rb`: the other
///   spelling is dropped;
/// - `BUNDLE_GEMFILE` naming anything else: every spelling is dropped and
///   [`CandidateFiles::gem_manifest_unsupported`] says why.
///
/// A memory view has no environment: only its own app config is read.
async fn keep_bundler_loaded_gem_files(view: &ProjectView<'_>, out: &mut CandidateFiles) {
    use crate::formats::gem::manifest::LoadedManifest;
    let loaded = crate::crawlers::ruby_crawler::bundler_loaded_manifest_in(view).await;
    let keep: &[&str] = match &loaded {
        LoadedManifest::Default => return,
        LoadedManifest::Configured { .. } => {
            let (gemfile, lock) = loaded
                .pair(out.files.contains_key("gems.rb"))
                .expect("a configured default spelling has a pair");
            &[gemfile, lock]
        }
        LoadedManifest::Unsupported { .. } => &[],
    };
    let dropped = |rel: &str| GEM_MANIFEST_FILES.contains(&rel) && !keep.contains(&rel);
    out.files.retain(|rel, _| !dropped(rel));
    out.symlinked_reads.retain(|rel| !dropped(rel));
    out.unreadable_reads.retain(|rel| !dropped(rel));
    out.gem_manifest_unsupported = loaded.unsupported_detail().map(|detail| RewriteWarning {
        code: "redirect_gem_bundle_gemfile_unsupported".into(),
        detail,
    });
}

/// The pypi wheels whose metadata a native lock rewrite needs, in
/// candidate order: `(override, sha256)` of every `.whl` artifact some
/// `uv.lock` / PEP 723 script lock would rewrite. Each native lock is
/// parsed once, on the first dep that needs the probe.
pub fn wheel_targets<'a>(
    candidates: &'a [Candidate],
    files: &BTreeMap<String, String>,
) -> Vec<(&'a DepOverride, &'a str)> {
    use crate::utils::python_lock::{ArtifactSource, PythonLockProbe};
    let mut probes: Option<Vec<PythonLockProbe>> = None;
    let mut out = Vec::new();
    for dep in candidates
        .iter()
        .map(|c| &c.dep)
        .filter(|dep| dep.ecosystem == "pypi")
    {
        let Some(sha256) = dep.integrity.sha256.as_deref() else {
            continue;
        };
        if !dep
            .artifact_url
            .split(['?', '#'])
            .next()
            .is_some_and(|path| path.ends_with(".whl"))
        {
            continue;
        }
        let native_target = probes
            .get_or_insert_with(|| {
                files
                    .iter()
                    .filter(|(path, _)| {
                        *path == "uv.lock" || crate::utils::python_lock::is_script_lock_name(path)
                    })
                    .map(|(_, text)| PythonLockProbe::new(text))
                    .collect()
            })
            .iter()
            .any(|probe| {
                probe.rewrites(
                    &dep.name,
                    &dep.version,
                    ArtifactSource::Url(&dep.artifact_url),
                )
            });
        if native_target {
            out.push((dep, sha256));
        }
    }
    out
}

/// The skip recorded for a pypi dep whose wheel metadata could not be
/// fetched (the grant token in `detail` is redacted to `<hosted artifact>`).
pub fn wheel_metadata_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!("pkg:pypi/{}@{}", dep.name, dep.version),
        uuid: dep.patch_uuid.clone(),
        reason: "python_metadata_unavailable".to_string(),
        detail: Some(detail.replace(&dep.artifact_url, "<hosted artifact>")),
    }
}

/// The npm candidates whose yarn berry pin needs the served tarball's own
/// `package.json`, in candidate order: yarn builds a tarball entry's `bin:`
/// from that manifest, not from the registry metadata the locked `npm:`
/// entry came from, and the two spell bin paths differently (#718). Only an
/// entry the pin would re-key that carries a `bin:` map needs it (see
/// `berry_pin_needs_manifest`; a fork alias never counts), so a berry
/// project without bins fetches nothing.
pub fn yarn_berry_manifest_targets<'a>(
    candidates: &'a [Candidate],
    files: &BTreeMap<String, String>,
) -> Vec<&'a DepOverride> {
    let Some(lock) = files
        .get("yarn.lock")
        .filter(|lock| crate::patch::redirect::is_berry_lock(lock))
    else {
        return Vec::new();
    };
    let lock = crate::utils::line_endings::to_lf(lock);
    let bin_entries = crate::patch::redirect::berry_bin_entries(&lock);
    if bin_entries.is_empty() {
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    candidates
        .iter()
        .map(|c| &c.dep)
        .filter(|dep| dep.ecosystem == "npm")
        .filter(|dep| crate::patch::redirect::berry_pin_needs_manifest(&bin_entries, dep))
        .filter(|dep| seen.insert(dep.artifact_url.clone()))
        .collect()
}

/// The skip recorded for an npm dep whose served `package.json` could not
/// be fetched (the grant token in `detail` is redacted to `<hosted
/// artifact>`).
pub fn npm_manifest_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!(
            "pkg:npm/{}@{}",
            crate::patch::redirect::full_name(dep),
            dep.version
        ),
        uuid: dep.patch_uuid.clone(),
        reason: "npm_manifest_unavailable".to_string(),
        detail: Some(detail.replace(&dep.artifact_url, "<hosted artifact>")),
    }
}

/// Whether a pypi candidate targets an entry of the project's
/// `Pipfile.lock` (only then does the installing Pipenv's major matter).
pub fn pipenv_lock_targets(files: &BTreeMap<String, String>, candidates: &[Candidate]) -> bool {
    if !files.contains_key("Pipfile.lock") {
        return false;
    }
    let overrides: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();
    crate::patch::redirect::pipenv_lock_targets(files, &overrides)
}

/// A dry-run vendored→hosted takeover the disk caller withheld from the
/// rewriters: its artifact URL and the root locks its vendored wiring
/// lives in (the wet run splices the hosted URL there, so the
/// install-policy auto-configs are previewed for those locks).
#[derive(Debug, Clone)]
pub struct TakeoverPreview {
    pub artifact_url: String,
    pub locks: Vec<String>,
}

/// The host-dependent inputs of [`rewrite`].
pub struct RewriteOptions<'a> {
    pub dry_run: bool,
    /// Whether a pypi candidate targets `Pipfile.lock`
    /// ([`pipenv_lock_targets`]) and the installing Pipenv's major (`None`
    /// when unknown or not targeted).
    pub targets_pipenv_lock: bool,
    pub pipenv_major: Option<u32>,
    /// The `redirect_pipenv_installer_unknown` detail (the remedy names the
    /// host's own knob).
    pub pipenv_unknown_detail: String,
    /// `false` under `--no-trust-lockfile-config`.
    pub trust_lockfile_config: bool,
    /// `false` under `--no-npm-allow-remote-config`.
    pub npm_allow_remote_config: bool,
    /// The npm config layers outside the project `.npmrc`, resolved only
    /// when an npm lock carries a hosted URL.
    pub npm_outer: &'a (dyn Fn() -> OuterAllowRemote + Send + Sync),
    /// Run the rewriters on the blocking pool (the disk flow: pure CPU over
    /// every lock text).
    pub blocking: bool,
}

/// One project's rewrite, ready for the guard, the record fetch and the
/// commit.
#[derive(Debug)]
pub struct Rewritten {
    /// The pre-rewrite candidate texts.
    pub files: BTreeMap<String, String>,
    pub symlinked_reads: Vec<String>,
    pub unreadable_reads: Vec<String>,
    /// The rewriters' override slice (the candidates' deps).
    pub overrides: Vec<DepOverride>,
    pub rewrite: RewriteResult,
    /// Every file this run writes (text and binary), sorted.
    pub rewritten: Vec<String>,
    /// `(purl, uuid)` of each candidate whose redirect is pinned by the
    /// project's final files, in candidate order.
    pub confirmed: Vec<(String, String)>,
    /// A `bun.lockb` without a text `bun.lock` drives npm.
    pub binary_bun: bool,
    pub rush_warnings: Vec<RewriteWarning>,
    pub pnpm_warnings: Vec<RewriteWarning>,
    pub npm_warnings: Vec<RewriteWarning>,
    /// Human mode: this run touched nothing pnpm-related (no lock spliced,
    /// trust already configured), so the full guidance shrinks to a
    /// one-line reminder.
    pub pnpm_rerun_only: bool,
    /// In memory only: the trust auto-config would write through a
    /// symlinked `pnpm-workspace.yaml`.
    pub(crate) workspace_symlinked: bool,
}

/// The pnpm-workspace.yaml read, classified for the trust auto-config
/// (see [`read_workspace_for_trust`]), plus whether it is an in-memory
/// symbolic link (absent to the planner, refused by [`guard`]).
fn read_workspace(view: &ProjectView<'_>) -> (std::io::Result<Option<String>>, bool) {
    match view {
        ProjectView::Disk(cwd)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot {
            root: cwd, ..
        }) => (
            read_workspace_for_trust(&cwd.join(PNPM_WORKSPACE_REL)),
            false,
        ),
        ProjectView::Memory(project) => match project.get(PNPM_WORKSPACE_REL) {
            None => (Ok(None), false),
            Some(MemoryEntry::Text(text)) => (Ok(Some(text.to_string())), false),
            Some(MemoryEntry::Symlink) => (Ok(None), true),
            Some(MemoryEntry::Binary(_)) => (
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stream did not contain valid UTF-8",
                )),
                false,
            ),
            Some(MemoryEntry::Present) => (
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "file content was not provided",
                )),
                false,
            ),
        },
    }
}

/// The project `.npmrc` read, classified for the allow-remote planner (see
/// [`read_npmrc_for_allow_remote`]).
fn read_npmrc(view: &ProjectView<'_>) -> Result<Option<String>, String> {
    match view {
        ProjectView::Disk(cwd)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot {
            root: cwd, ..
        }) => read_npmrc_for_allow_remote(&cwd.join(NPMRC_REL)),
        ProjectView::Memory(project) => match project.get(NPMRC_REL) {
            None => Ok(None),
            Some(MemoryEntry::Symlink) => {
                Err("is a symbolic link (socket-patch never writes through one)".into())
            }
            Some(MemoryEntry::Text(text)) => Ok(Some(text.to_string())),
            Some(MemoryEntry::Binary(_)) => {
                Err("could not be read (stream did not contain valid UTF-8)".into())
            }
            Some(MemoryEntry::Present) => {
                Err("could not be read (file content was not provided)".into())
            }
        },
    }
}

/// Whether Rush's repo-state file is present (disk: a regular file).
fn rush_repo_state_present(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(cwd)
        | ProjectView::Snapshot(crate::vendor::lock_inventory::DiskSnapshot {
            root: cwd, ..
        }) => cwd.join(RUSH_REPO_STATE_REL).is_file(),
        ProjectView::Memory(project) => project.contains(RUSH_REPO_STATE_REL),
    }
}

/// How the confirmation probe settles one candidate: a non-substring rule
/// (a transactional rewriter's own report, a refusal) decides it outright,
/// otherwise it is confirmed iff any of its needles occurs in a final text.
enum ProbeStep {
    Decided(bool),
    Needles(Vec<String>),
    /// [`Self::Needles`], searched in every final text but `vlt-lock.json`
    /// (a dep withheld from the vlt rewrite).
    NeedlesOutsideVlt(Vec<String>),
}

/// The substrings whose presence in a final text confirms `dep`'s redirect —
/// the override's own targets: artifact URL; per-dependency registry index
/// URL; fail-closed maven's globally-unique `-socket.<hex8>` suffixed version
/// (never the `.pom` URL).
///
/// - The artifact URL in the rewriters' own spellings
///   ([`artifact_url_spellings`], raw or the `\/`-escaped slashes an old
///   composer.lock spells them with), so a writer's spelling can never be
///   one this probe misses.
/// - The percent-encoded URL: releases up to 5.0 wrote it into a berry
///   lock's `::__archiveUrl=` binding (today's berry pin is the raw URL), so
///   a lock pinned by them carries no raw form.
/// - The registry index URL and the maven suffixed version, when present.
pub fn candidate_presence_needles(dep: &DepOverride) -> Vec<String> {
    let artifact_url = dep.artifact_url.as_str();
    let registry = dep.registry_override.as_ref();
    let mut needles: Vec<String> = artifact_url_spellings(artifact_url).into();
    needles.push(crate::utils::uri::encode_uri_component(artifact_url));
    if let Some(o) = registry {
        needles.push(o.index_url.clone());
        if let Some(sv) = o.identifiers.maven_suffixed_version.as_deref() {
            needles.push(sv.to_string());
        }
    }
    needles
}

/// Rewrite the candidate files for `candidates`, plan the install-policy
/// auto-configs, and confirm which redirects the final files pin.
///
/// `python_metadata` maps a wheel's artifact URL to its fetched METADATA;
/// `withheld_from_vlt` are the uuids the vlt preflight kept out of the vlt
/// rewrite; `takeover_previews` are the disk dry run's withheld takeovers.
pub async fn rewrite(
    view: &ProjectView<'_>,
    read: CandidateFiles,
    candidates: &[Candidate],
    python_metadata: BTreeMap<String, String>,
    withheld_from_vlt: &BTreeSet<String>,
    takeover_previews: &[TakeoverPreview],
    options: RewriteOptions<'_>,
) -> Rewritten {
    let CandidateFiles {
        files,
        rush_lock_keys,
        symlinked_reads,
        unreadable_reads,
        gradle_unreadable,
        gem_manifest_unsupported,
    } = read;
    // The rewriters' override slice — materialized ONCE, after the last
    // candidate filter, so it can never disagree with `candidates`.
    let overrides: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();
    let bun_lockb = bun_lockb_present(view);
    let binary_bun = !bun_lock_present(view) && bun_lockb;
    let binary_content = if binary_bun && overrides.iter().any(|o| o.ecosystem == "npm") {
        Some(
            view.read_bytes("bun.lockb")
                .await
                .map_err(|e| RewriteWarning {
                    code: "redirect_bun_lockb_invalid".into(),
                    detail: format!("cannot read bun.lockb: {e}"),
                })
                .and_then(|bytes| {
                    crate::patch::redirect::preflight_bun_binary(&bytes)?;
                    Ok(bytes)
                }),
        )
    } else {
        None
    };
    // A malformed primary lock must not cause edits to stale npm siblings.
    let rewrite_overrides: Vec<DepOverride> = overrides
        .iter()
        .filter(|o| !(binary_content.as_ref().is_some_and(Result::is_err) && o.ecosystem == "npm"))
        .cloned()
        .collect();
    let pipenv_major = options.pipenv_major;
    let (files, mut rewrite) = if options.blocking {
        // Pure CPU over every lock text (the independent rewriter groups
        // run concurrently inside), so it runs on the blocking pool rather
        // than on a runtime worker; `files` comes back for the probe below.
        let withheld = withheld_from_vlt.clone();
        tokio::task::spawn_blocking(move || {
            let rewrite = rewrite_registry_redirect_withholding_vlt(
                &files,
                &rewrite_overrides,
                &python_metadata,
                pipenv_major,
                bun_lockb,
                &withheld,
                &gradle_unreadable,
            );
            (files, rewrite)
        })
        .await
        .unwrap_or_else(|e| match e.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(e) => panic!("hosted rewrite task failed: {e}"),
        })
    } else {
        let rewrite = rewrite_registry_redirect_withholding_vlt(
            &files,
            &rewrite_overrides,
            &python_metadata,
            pipenv_major,
            bun_lockb,
            withheld_from_vlt,
            &gradle_unreadable,
        );
        (files, rewrite)
    };
    // The gem files were withheld on purpose: say why, not "no Gemfile".
    if let Some(warning) = gem_manifest_unsupported {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_gem_no_gemfile");
        rewrite.warnings.push(warning);
    }
    if let Some(content) = binary_content {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_npm_no_lockfile");
        match content {
            Ok(bytes) => {
                // A package the project patches itself (`bun patch`) keeps
                // its registry record, loudly (#367).
                let user_patched = crate::vendor::bun_lock_text::patched_dependency_keys(
                    files.get("package.json").map(String::as_str),
                    None,
                );
                let binary_overrides: Vec<DepOverride> = overrides
                    .iter()
                    .filter(|o| {
                        o.ecosystem != "npm"
                            || !crate::patch::redirect::skip_bun_user_patched(
                                &user_patched,
                                &crate::patch::redirect::full_name(o),
                                o,
                                &mut rewrite,
                            )
                    })
                    .cloned()
                    .collect();
                crate::patch::redirect::rewrite_bun_binary(&bytes, &binary_overrides, &mut rewrite)
            }
            Err(warning) => rewrite.warnings.push(warning),
        }
    }

    // Unknown installer → the modern `file` shape was chosen; say so only
    // when the lock was (or, on --dry-run, would be) rewritten.
    if options.targets_pipenv_lock
        && pipenv_major.is_none()
        && rewrite.files.contains_key("Pipfile.lock")
    {
        rewrite.warnings.push(RewriteWarning {
            code: "redirect_pipenv_installer_unknown".into(),
            detail: options.pipenv_unknown_detail.clone(),
        });
    }

    // Editing a Rush lock outside `rush update` desyncs the
    // pnpmShrinkwrapHash recorded in repo-state.json. When
    // preventManualShrinkwrapChanges is enabled, `rush install` then
    // refuses until `rush update` refreshes that hash — but the redirect
    // survives `rush update` (pnpm preserves locked resolutions for
    // unchanged specifiers). Warn only when the rewrite actually landed in
    // a Rush lock and the repo-state file that carries the hash is present.
    let mut rush_warnings: Vec<RewriteWarning> = Vec::new();
    if rush_lock_keys
        .iter()
        .any(|key| rewrite.files.contains_key(key))
        && rush_repo_state_present(view)
    {
        rush_warnings.push(warning(
            "redirect_rush_repo_state_stale",
            "pnpm-lock.yaml was edited outside `rush update`; if \
                 preventManualShrinkwrapChanges is enabled, `rush install` fails until \
                 `rush update` refreshes repo-state.json (the hosted wiring survives `rush \
                 update`)",
        ));
    }

    let (pnpm_warnings, trust_config_write, pnpm_rerun_only, workspace_symlinked) = pnpm_trust(
        view,
        &files,
        &rewrite,
        &overrides,
        takeover_previews,
        &options,
    );
    let (npm_warnings, npmrc_config_write) = npm_allow_remote(
        view,
        &files,
        &rewrite,
        &overrides,
        takeover_previews,
        &options,
    );
    if let Some((text, edit)) = trust_config_write {
        rewrite.files.insert(PNPM_WORKSPACE_REL.to_string(), text);
        // Appended last: `--revert` walks edits in reverse, so the trust key
        // is unwound before the lock originals are restored.
        rewrite.edits.push(edit);
    }
    if let Some((text, edit)) = npmrc_config_write {
        rewrite.files.insert(NPMRC_REL.to_string(), text);
        // Appended after the lock edits for the same reason: a whole-ledger
        // replay unwinds the setting before the lock originals it served.
        rewrite.edits.push(edit);
    }
    let rewritten: Vec<String> = rewrite
        .files
        .keys()
        .chain(rewrite.binary_files.keys())
        .cloned()
        .collect();
    let confirmed = confirm(&files, &rewrite, candidates, binary_bun, withheld_from_vlt);
    Rewritten {
        files,
        symlinked_reads,
        unreadable_reads,
        overrides,
        rewrite,
        rewritten,
        confirmed,
        binary_bun,
        rush_warnings,
        pnpm_warnings,
        npm_warnings,
        pnpm_rerun_only,
        workspace_symlinked,
    }
}

type ConfigWrite = Option<(String, FileEdit)>;

/// pnpm >=11 enforces a lockfile supply-chain policy: it compares each
/// resolution's tarball URL against the registry's published metadata and
/// REFUSES a lock whose URLs differ: pnpm 11 with
/// ERR_PNPM_TARBALL_URL_MISMATCH (ERR_PNPM_META_FETCH_FAIL when the
/// registry is unreachable), pnpm 12 with
/// ERR_PNPM_LOCKFILE_RESOLUTION_VERIFICATION, whose own text tells users
/// to rebuild the lock — which silently discards the redirect, so the
/// warning must pre-empt that advice. The working recoveries are
/// `pnpm install --trust-lockfile` and the pnpm-workspace.yaml
/// `trustLockfile: true` key; the `.npmrc` `trust-lockfile=true` spelling
/// is IGNORED by pnpm and must never be recommended.
///
/// ZERO-TOUCH DEFAULT: when this run rewrote the ROOT pnpm-lock.yaml and
/// its lockfileVersion is >= 9 (5.x/6.0 locks mean pnpm 7/8, which have
/// neither the policy nor the flag and get their own guidance), the run
/// auto-ensures `trustLockfile: true` in pnpm-workspace.yaml. The same
/// auto-config re-engages on a run that spliced NOTHING when the root v9
/// lock already carries a granted hosted artifact URL (HEAL-ON-RERUN).
/// pnpm <=10 ignores the key; the per-entry sha512 pin still fails closed
/// on tampered bytes. An explicit user `trustLockfile: <non-true>` is
/// RESPECTED (never flipped), and `--no-trust-lockfile-config` opts out.
/// Rush nested/subspace locks are excluded: rush runs pnpm in common/temp,
/// which never reads the repo-root pnpm-workspace.yaml. The warning names
/// the host(s) the lock now points at (they follow --api-url).
fn pnpm_trust(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    rewrite: &RewriteResult,
    overrides: &[DepOverride],
    takeover_previews: &[TakeoverPreview],
    options: &RewriteOptions<'_>,
) -> (Vec<RewriteWarning>, ConfigWrite, bool, bool) {
    let mut pnpm_warnings: Vec<RewriteWarning> = Vec::new();
    let mut trust_config_write: ConfigWrite = None;
    let mut pnpm_rerun_only = false;
    let mut workspace_symlinked = false;
    // pnpm locks spliced THIS run (any depth — the rewriter is
    // basename-generalized).
    let mut pnpm_lock_texts: Vec<&String> = rewrite
        .files
        .iter()
        .filter(|(key, _)| {
            std::path::Path::new(key)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| matches!(name, "pnpm-lock.yaml" | "shrinkwrap.yaml"))
        })
        .map(|(_, content)| content)
        .collect();
    // HEAL-ON-RERUN: a root v9 lock that ALREADY carries a granted hosted
    // artifact URL (spliced by an earlier run) still plans the trust config
    // even though this run spliced nothing — so a project that missed the
    // config once (opted-out first run, or a crash between the lock write
    // and the workspace write) is healed by simply re-running the scan. An
    // AlreadyTrue workspace keeps the re-run a byte-stable no-op.
    let heal_root: Option<&String> = pnpm_heal_root(
        rewrite.files.contains_key("pnpm-lock.yaml"),
        files.get("pnpm-lock.yaml"),
        overrides,
    );
    let spliced_pnpm_locks = pnpm_lock_texts.len();
    if let Some(text) = heal_root {
        pnpm_lock_texts.push(text);
    }
    // A dry-run vendored→hosted takeover of a purl vendored into the root
    // pnpm lock: the wet run reverts that wiring and splices the hosted URL
    // into it, so the trust config is previewed against the root lock (the
    // vendored text carries the same lockfileVersion).
    let takeover_pnpm_urls: Vec<&str> = takeover_previews
        .iter()
        .filter(|t| t.locks.iter().any(|l| l == "pnpm-lock.yaml"))
        .map(|t| t.artifact_url.as_str())
        .collect();
    let takeover_root: Option<&String> = if takeover_pnpm_urls.is_empty()
        || heal_root.is_some()
        || rewrite.files.contains_key("pnpm-lock.yaml")
    {
        None
    } else {
        files.get("pnpm-lock.yaml")
    };
    if let Some(text) = takeover_root {
        pnpm_lock_texts.push(text);
    }
    if pnpm_lock_texts.is_empty() {
        return (
            pnpm_warnings,
            trust_config_write,
            pnpm_rerun_only,
            workspace_symlinked,
        );
    }
    // Name only the hosts whose artifact URL actually landed in a touched
    // pnpm lock's final text (spliced this run, or the already-redirected
    // heal root): an npm override may have matched only a sibling lock
    // (e.g. package-lock.json), and naming its host here would point users
    // at a server the pnpm lock never references. Same needles as the
    // confirmation probe.
    let npm_overrides: Vec<_> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
    let groups: Vec<Vec<String>> = npm_overrides
        .iter()
        .map(|o| npm_lock_url_needles(&o.artifact_url))
        .collect();
    let present = groups_present(&pnpm_lock_texts, &groups);
    let mut hosts: Vec<&str> = npm_overrides
        .iter()
        .zip(present)
        .filter(|(_, present)| *present)
        .filter_map(|(o, _)| url_host(&o.artifact_url))
        // Dry-run takeover purls land in the root lock on the wet run.
        .chain(takeover_pnpm_urls.iter().filter_map(|url| url_host(url)))
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    let server = if hosts.is_empty() {
        "the hosted patch server".to_string()
    } else {
        format!("the hosted patch server ({})", hosts.join(", "))
    };
    // Root-lock gate: only the plain project lock at lockfileVersion >= 9
    // gets the auto-config — spliced this run, or detected
    // already-redirected (heal path).
    let root_lock_v9 = heal_root
        .or(takeover_root)
        .and_then(|text| pnpm_lock_version_major(text))
        .is_some_and(|major| major >= 9)
        || rewrite
            .files
            .get("pnpm-lock.yaml")
            .and_then(|text| pnpm_lock_version_major(text))
            .is_some_and(|major| major >= 9);
    // Every touched pnpm lock is a KNOWN legacy (5.x/6.0) format, where
    // `--trust-lockfile` is rejected as an unknown option. An unparseable
    // version stays on the manual guidance: never claim "no trust step
    // needed" for a lock whose era is unknown.
    let all_locks_legacy = pnpm_lock_texts.iter().all(|text| {
        pnpm_lock_version_major(text).is_some_and(|major| major < 9)
            || text
                .lines()
                .any(|line| line.starts_with("shrinkwrapVersion:"))
    });
    let detail = if all_locks_legacy {
        pnpm_trust_legacy_detail(&server)
    } else if !root_lock_v9 || !options.trust_lockfile_config {
        pnpm_trust_manual_guidance(&server)
    } else {
        let (workspace, symlinked) = read_workspace(view);
        workspace_symlinked = symlinked;
        let trust_edit = |action: &str| FileEdit {
            path: PNPM_WORKSPACE_REL.into(),
            kind: REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND.into(),
            action: action.into(),
            key: Some("trustLockfile".into()),
            original: None,
            new: Some(serde_json::json!("true")),
        };
        match workspace {
            // Present but UNREADABLE: never plan a Create (it would
            // overwrite the user's workspace file) — fall back to
            // warning-only guidance naming the file and the error.
            Err(e) => pnpm_trust_workspace_unreadable_detail(&server, &e),
            Ok(ws_existing) => match plan_workspace_trust(ws_existing.as_deref()) {
                TrustPlan::Create(text) => {
                    trust_config_write = Some((text, trust_edit("created")));
                    pnpm_trust_configured_detail(&server, true, options.dry_run)
                }
                TrustPlan::Append(text) => {
                    trust_config_write = Some((text, trust_edit("added")));
                    pnpm_trust_configured_detail(&server, false, options.dry_run)
                }
                TrustPlan::AlreadyTrue => {
                    pnpm_rerun_only = spliced_pnpm_locks == 0;
                    format!(
                        "{}, and {PNPM_WORKSPACE_REL} already carries `trustLockfile: \
                         true` — keep it committed alongside the lock; installs need \
                         no extra flags. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
                        pnpm_trust_policy_preamble(&server),
                    )
                }
                TrustPlan::UserSet(value) => format!(
                    "{}. {PNPM_WORKSPACE_REL} explicitly sets `trustLockfile: \
                 {value}`, which was respected and left untouched — install \
                 with `pnpm install --trust-lockfile`, or set `trustLockfile: \
                 true` yourself so every install accepts the patched \
                 artifacts. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
                    pnpm_trust_policy_preamble(&server),
                ),
                TrustPlan::Unsupported(why) => {
                    pnpm_trust_workspace_unsupported_detail(&server, &why)
                }
            },
        }
    };
    // The `--store` spelling only matters to pnpm 1–4, so it is named only
    // when a touched lock may be that old.
    let store_note = if pnpm_lock_texts
        .iter()
        .any(|text| pnpm_lock_may_need_store_flag(text))
    {
        " (pnpm 1–4 spell the option `--store`)"
    } else {
        ""
    };
    pnpm_warnings.push(warning(
        "redirect_pnpm_trust_lockfile",
        format!(
            "{}. After a lock-only change, existing node_modules or a warm pnpm store \
             can still contain upstream files. For a reliable reinstall, use a clean \
             node_modules tree and an empty store with \
             `pnpm install --frozen-lockfile --store-dir <new-empty-directory>`\
             {store_note}. Do not rely on `--force`: some versions re-resolve the \
             upstream artifact. Run `socket-patch vex` after installation to verify \
             the patched files.",
            detail.trim_end_matches('.')
        ),
    ));
    (
        pnpm_warnings,
        trust_config_write,
        pnpm_rerun_only,
        workspace_symlinked,
    )
}

/// npm >= 12 ships `allow-remote=none`: it refuses (EALLOWREMOTE) every
/// tarball whose `resolved` origin is not the configured registry — which
/// is exactly what a hosted redirect writes. npm <= 11 installs it
/// unchanged; `allow-remote=all` in the project `.npmrc` makes npm 12
/// install the patched bytes with the sha512 pins still enforced (`root`
/// only admits DIRECT dependencies, so it is not enough).
///
/// ZERO-TOUCH DEFAULT (the npm twin of the pnpm trustLockfile
/// auto-config): whenever a root npm lock ends this run carrying a granted
/// hosted artifact URL (spliced now, or already redirected by an earlier
/// run — so a missed config heals on re-run), the run ensures
/// `allow-remote=all` in the project `.npmrc` — created when absent
/// (`action: "created"`), one line appended otherwise (`"added"`), every
/// other byte preserved — and records the edit
/// (`redirect_npmrc_allow_remote`). An explicit user
/// `allow-remote=<other>` is RESPECTED (never flipped), an unreadable /
/// symlinked `.npmrc` is left alone, and `--no-npm-allow-remote-config`
/// opts out entirely; every variant still WARNS
/// (`redirect_npm_allow_remote`) with the whole-tree tradeoff. Vendored
/// mode is unaffected: its `file:.socket/vendor/…` specs are npm `file`
/// specs, gated by `allow-file` (default `all`), not `allow-remote`.
fn npm_allow_remote(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    rewrite: &RewriteResult,
    overrides: &[DepOverride],
    takeover_previews: &[TakeoverPreview],
    options: &RewriteOptions<'_>,
) -> (Vec<RewriteWarning>, ConfigWrite) {
    let mut npm_warnings: Vec<RewriteWarning> = Vec::new();
    let mut npmrc_config_write: ConfigWrite = None;
    let npm_hosts: Vec<&str> = {
        let npm_lock_texts: Vec<&String> = NPM_LOCKS
            .iter()
            .filter_map(|lock| rewrite.files.get(*lock).or_else(|| files.get(*lock)))
            .collect();
        let npm_overrides: Vec<_> = overrides.iter().filter(|o| o.ecosystem == "npm").collect();
        let groups: Vec<[String; 2]> = npm_overrides
            .iter()
            .map(|o| artifact_url_spellings(&o.artifact_url))
            .collect();
        let present = groups_present(&npm_lock_texts, &groups);
        let mut hosts: Vec<&str> = npm_overrides
            .iter()
            .zip(present)
            .filter(|(_, present)| *present)
            .filter_map(|(o, _)| url_host(&o.artifact_url))
            // A dry-run vendored→hosted takeover: the wet run reverts the
            // vendored wiring in a root npm lock and splices the hosted URL
            // there, so preview the `.npmrc` write too.
            .chain(
                takeover_previews
                    .iter()
                    .filter(|t| t.locks.iter().any(|l| NPM_LOCKS.contains(&l.as_str())))
                    .filter_map(|t| url_host(&t.artifact_url)),
            )
            .collect();
        hosts.sort_unstable();
        hosts.dedup();
        hosts
    };
    if npm_hosts.is_empty() {
        return (npm_warnings, npmrc_config_write);
    }
    let edit = |action: &str| FileEdit {
        path: NPMRC_REL.into(),
        kind: NPMRC_ALLOW_REMOTE_EDIT_KIND.into(),
        action: action.into(),
        key: Some("allow-remote".into()),
        original: None,
        new: Some(serde_json::json!("all")),
    };
    let detail = match read_npmrc(view) {
        // Opt-out still reports an explicit / already-set value truthfully;
        // only the WRITE is suppressed.
        Ok(existing) => {
            match plan_npmrc_allow_remote_with(existing.as_deref(), &(options.npm_outer)()) {
                NpmrcPlan::AlreadyAll => npm_allow_remote_already_detail(&npm_hosts),
                NpmrcPlan::UserSet(value) => npm_allow_remote_user_set_detail(&npm_hosts, &value),
                NpmrcPlan::EnvSet { var, value } => {
                    npm_allow_remote_env_set_detail(&npm_hosts, &var, &value)
                }
                NpmrcPlan::OuterSet { layer, path, value } => {
                    npm_allow_remote_outer_set_detail(&npm_hosts, layer, &path, &value)
                }
                NpmrcPlan::Unsupported(why) => npm_allow_remote_unreadable_detail(&npm_hosts, &why),
                _ if !options.npm_allow_remote_config => npm_allow_remote_manual_detail(&npm_hosts),
                NpmrcPlan::Create(text) => {
                    npmrc_config_write = Some((text, edit("created")));
                    npm_allow_remote_configured_detail(&npm_hosts, true, options.dry_run)
                }
                NpmrcPlan::Append(text) => {
                    npmrc_config_write = Some((text, edit("added")));
                    npm_allow_remote_configured_detail(&npm_hosts, false, options.dry_run)
                }
            }
        }
        Err(why) => npm_allow_remote_unreadable_detail(&npm_hosts, &why),
    };
    npm_warnings.push(warning("redirect_npm_allow_remote", detail));
    (npm_warnings, npmrc_config_write)
}

/// A dep counts as REDIRECTED only if its hosted-artifact URL (or its
/// per-dependency registry index URL) actually landed in the project's
/// files — either written by this run or already present from an earlier
/// one. A granted reference whose rewriter found nothing to edit (e.g. no
/// lockfile) must NOT be recorded or attested: nothing pins the patch.
fn confirm(
    files: &BTreeMap<String, String>,
    rewrite: &RewriteResult,
    candidates: &[Candidate],
    binary_bun: bool,
    withheld_from_vlt: &BTreeSet<String>,
) -> Vec<(String, String)> {
    use crate::patch::redirect::pdm_drives;
    // A `pdm.lock` that is NOT the PyPI install driver (a `uv.lock` or
    // `poetry.lock` sits beside it) is never rewritten, yet can still carry
    // a Socket artifact URL from an earlier run. That stale text pins
    // nothing, so it must not feed the substring probe below. When pdm DOES
    // drive, pypi confirmation keys off `confirmed_pdm_uuids`, so dropping
    // the file is always safe.
    let pdm_inactive = files.contains_key("pdm.lock") && !pdm_drives(files);
    // Likewise a `vlt-lock.json` the vlt rewrite was withheld from (its
    // artifact failed the preflight beside another npm-family lock) may
    // still hold an earlier run's pin: only the sibling lock this run
    // rewrote can confirm that dep.
    // The yarn berry pin's `package.json` `resolutions` entry is only half of
    // it — the URL-keyed `yarn.lock` entry is what installs — so a hosted URL
    // left in the manifest (an earlier run, a refused rewrite) proves
    // nothing on its own: the manifest never feeds the probe. Nor do the
    // Bun workspace members' manifests, read only as advisory input.
    fn is_npm_manifest(name: &str) -> bool {
        name == "package.json" || name.ends_with("/package.json")
    }
    let final_texts: Vec<(&str, &String)> = files
        .iter()
        .filter(|(name, _)| !(pdm_inactive && name.as_str() == "pdm.lock"))
        .filter(|(name, _)| !is_npm_manifest(name))
        .map(|(name, content)| (name.as_str(), rewrite.files.get(name).unwrap_or(content)))
        .chain(
            rewrite
                .files
                .iter()
                .filter(|(name, _)| !files.contains_key(*name) && !is_npm_manifest(name))
                .map(|(name, content)| (name.as_str(), content)),
        )
        .collect();
    // Gradle scripts, locks and owned files never confirm by substring: a
    // pasted snippet or a stale lock line pins nothing (the Gradle planner
    // decides its own uuids above the needles).
    let needle_texts: Vec<&String> = final_texts
        .iter()
        .filter(|(name, _)| !is_gradle_file(name))
        .map(|(_, text)| *text)
        .collect();
    // Every non-substring rule decides a candidate outright; the rest are
    // confirmed by substring presence of their needles in the final texts.
    // All needle groups are answered in ONE multi-needle pass per text
    // (`groups_present`), which is the per-candidate `any()` exactly —
    // presence does not depend on search order, and `confirmed` keeps
    // candidate order.
    let steps: Vec<ProbeStep> = candidates
        .iter()
        .map(|c| {
            let purl = c.purl.as_str();
            let uuid = c.dep.patch_uuid.as_str();
            // vlt decides before the binary-bun rule, so `bun.lockb` beside
            // a vlt-driven `vlt-lock.json` never confirms an npm purl.
            if rewrite.refused_vlt_uuids.contains(uuid) || rewrite.refused_bun_uuids.contains(uuid)
            {
                return ProbeStep::Decided(false);
            }
            if rewrite.vlt_drives && purl.starts_with("pkg:npm/") {
                return ProbeStep::Decided(rewrite.confirmed_vlt_uuids.contains(uuid));
            }
            if binary_bun && purl.starts_with("pkg:npm/") {
                return ProbeStep::Decided(rewrite.confirmed_bun_binary_uuids.contains(uuid));
            }
            if rewrite.refused_pipenv_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
            // pdm is transactional like cargo: a refused uuid is never
            // confirmed, and when `pdm.lock` is the PyPI install driver (no
            // `uv.lock` / `poetry.lock`) a pypi dep is confirmed ONLY by the
            // pdm rewriter's own report — the URL landing in a sibling
            // `requirements.txt` the project does not install from pins
            // nothing. When uv/poetry drive, their own lock proof below
            // still confirms them. This check precedes the hatch gate: a
            // PDM project may declare `hatchling` as its build backend,
            // which registers every pypi uuid as hatch-owned while the
            // lock's presence keeps hatch from confirming any of them.
            if rewrite.refused_pdm_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
            if purl.starts_with("pkg:pypi/") && pdm_drives(files) {
                return ProbeStep::Decided(rewrite.confirmed_pdm_uuids.contains(uuid));
            }
            if rewrite.python_lock_uuids.contains(uuid) {
                return ProbeStep::Decided(
                    rewrite.confirmed_python_lock_uuids.contains(uuid)
                        && !rewrite.refused_python_lock_uuids.contains(uuid),
                );
            }
            if rewrite.hatch_uuids.contains(uuid) {
                return ProbeStep::Decided(rewrite.confirmed_hatch_uuids.contains(uuid));
            }
            // A Pipfile.lock rewrite confirms its own uuids (the sibling
            // requirements.txt rewriter may have had nothing to do).
            if purl.starts_with("pkg:pypi/") {
                return ProbeStep::Decided(
                    rewrite.confirmed_pipenv_uuids.contains(uuid)
                        || rewrite.confirmed_requirements_uuids.contains(uuid),
                );
            }
            if rewrite.refused_pnpm_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
            // A yarn berry pin is the URL-keyed lock entry AND the manifest
            // `resolutions` routing to it; the URL in `yarn.lock` alone (the
            // routing removed, a refused re-pin) installs nothing, so the
            // berry rewriter's own report decides every dep its lock holds.
            if rewrite.yarn_berry_uuids.contains(uuid) {
                return ProbeStep::Decided(rewrite.confirmed_yarn_berry_uuids.contains(uuid));
            }
            // Cargo is transactional: the rewriter reports exactly which
            // patch uuids FULLY landed (manifest pin + lock + registry
            // block). Substring presence must never confirm a cargo dep —
            // the `[registries.…]` config block contains the index URL
            // while pinning nothing, so a config-block-only rewrite would be
            // attested with zero enforcement in any build.
            if purl.starts_with("pkg:cargo/") {
                return ProbeStep::Decided(rewrite.confirmed_cargo_uuids.contains(uuid));
            }
            // Golang likewise: the goproxy `indexUrl` is the bare
            // patch-server origin (present in any other hosted lock), and
            // the socket module's go.sum lines outlive a removed replace.
            if purl.starts_with("pkg:golang/") {
                return ProbeStep::Decided(rewrite.confirmed_golang_uuids.contains(uuid));
            }
            // A Gradle build: the hosted Gradle planner decides (a snippet
            // pasted into a build script pins nothing it can check). A
            // pom.xml beside it must pin the patch as well.
            if purl.starts_with("pkg:maven/") && rewrite.gradle_uuids.contains(uuid) {
                let gradle = rewrite.confirmed_gradle_uuids.contains(uuid)
                    && !rewrite.refused_gradle_uuids.contains(uuid);
                if !gradle || !files.contains_key("pom.xml") {
                    return ProbeStep::Decided(gradle);
                }
                let needles = candidate_presence_needles(&c.dep);
                return ProbeStep::Decided(
                    final_texts
                        .iter()
                        .filter(|(name, _)| *name == "pom.xml" || name.starts_with(".mvn/"))
                        .any(|(_, text)| needles.iter().any(|n| text.contains(n.as_str()))),
                );
            }
            let needles = candidate_presence_needles(&c.dep);
            if withheld_from_vlt.contains(uuid) {
                ProbeStep::NeedlesOutsideVlt(needles)
            } else {
                ProbeStep::Needles(needles)
            }
        })
        .collect();
    let groups = |outside_vlt: bool| -> Vec<&[String]> {
        steps
            .iter()
            .filter_map(|step| match step {
                ProbeStep::Needles(needles) if !outside_vlt => Some(needles.as_slice()),
                ProbeStep::NeedlesOutsideVlt(needles) if outside_vlt => Some(needles.as_slice()),
                _ => None,
            })
            .collect()
    };
    let mut present = groups_present(&needle_texts, &groups(false)).into_iter();
    let outside_vlt_groups = groups(true);
    let mut present_outside_vlt = if outside_vlt_groups.is_empty() {
        Vec::new()
    } else {
        let texts: Vec<&String> = final_texts
            .iter()
            .filter(|(name, _)| *name != VLT_LOCK && !is_gradle_file(name))
            .map(|(_, text)| *text)
            .collect();
        groups_present(&texts, &outside_vlt_groups)
    }
    .into_iter();
    candidates
        .iter()
        .zip(&steps)
        .filter(|(_, step)| match step {
            ProbeStep::Decided(keep) => *keep,
            ProbeStep::Needles(_) => present
                .next()
                .expect("one presence answer per needle group"),
            ProbeStep::NeedlesOutsideVlt(_) => present_outside_vlt
                .next()
                .expect("one presence answer per needle group"),
        })
        .map(|(c, _)| (c.purl.clone(), c.dep.patch_uuid.clone()))
        .collect()
}

/// A Gradle script, lock file or hosted-Gradle owned file (the hosted
/// Gradle planner's inputs).
fn is_gradle_file(rel: &str) -> bool {
    crate::gradle::dsl::dsl_of(rel).is_some()
        || rel.ends_with(".lockfile")
        || rel.starts_with(".socket/gradle/")
        || rel == "gradle/verification-metadata.xml"
        || rel.ends_with("gradle-wrapper.properties")
}

/// The ecosystem a candidate file's rewriter belongs to (`None` for files
/// no rewriter edits), for the in-memory symlinked/unreadable-read refusal.
fn file_ecosystem(rel: &str) -> Option<&'static str> {
    if let Some(eco) = crate::formats::registry::hosted_file_ecosystem(rel) {
        return Some(eco);
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    // A legacy Gradle lock (`gradle/dependency-locks/<conf>.lockfile`).
    if base.ends_with(".lockfile") {
        return Some("maven");
    }
    (crate::utils::python_lock::is_python_lock_name(base) || base.ends_with(".py"))
        .then_some("pypi")
}

/// SYMLINK GUARD — fail-closed, whole rewrite, before the ledger and before
/// any write (hosted rewrites are transactional). The writer stages next to
/// the path and renames over it, which REPLACES a symbolic link with a
/// detached regular copy: the link target goes stale and a revert restores
/// bytes but never the link. Applies to every ecosystem's files and to dry
/// runs, so a dry run predicts the refusal.
///
/// In memory, additionally: a candidate file read through a link (its bytes
/// are unknown) or present without content, when a candidate of its
/// ecosystem could rewrite it.
pub fn guard(
    view: &ProjectView<'_>,
    done: &Rewritten,
    candidates: &[Candidate],
) -> Option<Refusal> {
    if done.workspace_symlinked {
        return Some(symlink_refusal(PNPM_WORKSPACE_REL));
    }
    let written = || {
        done.rewrite
            .files
            .keys()
            .chain(done.rewrite.binary_files.keys())
    };
    if let Some(linked) = written().find(|k| view.is_symlink(k)) {
        return Some(symlink_refusal(linked));
    }
    let ProjectView::Memory(project) = view else {
        return None;
    };
    let candidate_ecosystems: BTreeSet<&str> = candidates
        .iter()
        .map(|c| c.dep.ecosystem.as_str())
        .collect();
    if let Some(linked) = done
        .symlinked_reads
        .iter()
        .find(|rel| file_ecosystem(rel).is_some_and(|eco| candidate_ecosystems.contains(eco)))
    {
        return Some(symlink_refusal(linked));
    }
    done.unreadable_reads
        .iter()
        .find(|rel| {
            done.rewrite.files.contains_key(rel.as_str())
                || file_ecosystem(rel).is_some_and(|eco| candidate_ecosystems.contains(eco))
        })
        .or_else(|| {
            done.rewrite
                .files
                .keys()
                .find(|k| matches!(project.get(k), Some(MemoryEntry::Present)))
        })
        .map(|rel| unreadable_refusal(rel))
}

/// The `record_fetch_failed` warning for a confirmed redirect whose patch
/// record could not be fetched.
pub fn record_fetch_failed_warning(purl: &str) -> RewriteWarning {
    warning(
        "record_fetch_failed",
        format!(
            "{purl} was switched to hosted, but its patch record could not be \
             fetched; this run's VEX attestation omits it (`socket-patch vex` \
             fetches it again once the API answers)"
        ),
    )
}

/// A `{code, detail}` warning.
pub fn warning(code: &str, detail: impl Into<String>) -> RewriteWarning {
    RewriteWarning {
        code: code.to_string(),
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::lock_inventory::MemoryProject;

    fn reference(value: serde_json::Value) -> PackageVendorResult {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn candidates_skip_every_unusable_reference() {
        let mut refs: HashMap<String, PackageVendorResult> = HashMap::new();
        refs.insert(
            "u-pending".into(),
            reference(serde_json::json!({"status": "pending_build"})),
        );
        refs.insert(
            "u-nourl".into(),
            reference(serde_json::json!({"status": "granted", "purl": "pkg:npm/b@1"})),
        );
        refs.insert(
            "u-ok".into(),
            reference(serde_json::json!({
                "status": "reused",
                "url": "https://patch.example/patch/npm/c/1/tok/u-ok/c-1.tgz",
                "purl": "pkg:npm/c@1",
                "artifacts": [{"kind": "tarball", "url": null, "integrity": {"sha512": "sha512-x"}}],
                "registryOverride": null
            })),
        );
        let selected = vec![
            ("pkg:npm/a@1".to_string(), "u-missing".to_string()),
            ("pkg:npm/p@1".to_string(), "u-pending".to_string()),
            ("pkg:npm/b@1".to_string(), "u-nourl".to_string()),
            ("pkg:npm/c@1".to_string(), "u-ok".to_string()),
        ];
        let mut skipped = Vec::new();
        let candidates = build_candidates(&selected, &refs, &mut skipped);
        let reasons: Vec<&str> = skipped.iter().map(|s| s.reason.as_str()).collect();
        assert_eq!(reasons, vec!["not_found", "pending_build", "no_url"]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].dep.token, "tok");
        assert_eq!(
            candidates[0].dep.integrity.sha512.as_deref(),
            Some("sha512-x")
        );
    }

    fn cargo_reference(
        uuid: &str,
    ) -> (Vec<(String, String)>, HashMap<String, PackageVendorResult>) {
        let purl = "pkg:cargo/serde@1.0.190";
        let mut refs = HashMap::new();
        refs.insert(
            uuid.to_string(),
            reference(serde_json::json!({
                "status": "granted",
                "url": format!("https://patch.example/patch/cargo/serde/1.0.190/tok/{uuid}/serde-1.0.190.crate"),
                "purl": purl,
                "artifacts": [{"kind": "tarball", "url": null, "integrity": {"sha256": "ab"}}],
                "registryOverride": null
            })),
        );
        (vec![(purl.to_string(), uuid.to_string())], refs)
    }

    #[tokio::test]
    async fn an_unreadable_candidate_file_refuses_its_ecosystem() {
        let (selected, refs) = cargo_reference("u-1");
        let mut p = MemoryProject::new();
        p.insert_text("Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        p.insert_text(
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        );
        p.insert_present(".cargo/config");
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            blocking: false,
        };
        let mut skipped = Vec::new();
        let candidates = build_candidates(&selected, &refs, &mut skipped);
        let view = ProjectView::Memory(&p);
        let unreadable = BTreeSet::from([".cargo/config".to_string()]);
        let read = read_candidate_files(&view, &unreadable, &candidates).await;
        assert_eq!(read.unreadable_reads, vec![".cargo/config"]);
        let done = rewrite(
            &view,
            read,
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
            &[],
            options,
        )
        .await;
        assert_eq!(
            guard(&view, &done, &candidates).unwrap().code,
            UNREADABLE_REFUSAL
        );

        // A non-UTF-8 file is absent to disk too: not a refusal.
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert!(read.unreadable_reads.is_empty());
    }

    /// A hosted URL left in a berry project's `package.json` `resolutions`
    /// while `yarn.lock` still resolves the registry entry confirms nothing:
    /// only the lock pin installs (#404).
    #[test]
    fn a_resolutions_url_alone_does_not_confirm_a_berry_redirect() {
        use crate::patch::redirect::Integrity;
        let url = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz";
        let candidate = Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: url.into(),
                registry_override: None,
                integrity: Integrity::default(),
            },
        };
        let lock = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  \
                    version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n";
        let mut files = BTreeMap::new();
        files.insert("yarn.lock".to_string(), lock.to_string());
        files.insert(
            "package.json".to_string(),
            format!("{{\"resolutions\": {{\"left-pad@npm:^1.3.0\": \"{url}\"}}}}"),
        );
        let none = confirm(
            &files,
            &RewriteResult::default(),
            std::slice::from_ref(&candidate),
            false,
            &BTreeSet::new(),
        );
        assert!(none.is_empty(), "{none:?}");
        // The lock pin itself still confirms.
        files.insert(
            "yarn.lock".to_string(),
            lock.replace(
                "resolution: \"left-pad@npm:1.3.0\"",
                &format!("resolution: \"left-pad@{url}\""),
            ),
        );
        let confirmed = confirm(
            &files,
            &RewriteResult::default(),
            std::slice::from_ref(&candidate),
            false,
            &BTreeSet::new(),
        );
        assert_eq!(confirmed.len(), 1, "{confirmed:?}");
    }

    /// Review of #465: a hosted berry pin whose `resolutions` routing was
    /// removed keeps its URL-keyed lock entry. The rewriter refuses to re-pin
    /// it (the routing is not ours to recreate silently), so nothing
    /// installs the patch — and the URL in `yarn.lock` must not confirm it
    /// (a confirmed dep feeds the in-run VEX `not_affected` exemption).
    #[test]
    fn an_orphaned_berry_lock_pin_is_not_confirmed() {
        use crate::patch::redirect::{rewrite_registry_redirect, Integrity};
        let url = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz";
        let candidate = Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: url.into(),
                registry_override: None,
                integrity: Integrity {
                    yarn_berry10c0: Some(format!("10c0/{}", "7".repeat(128))),
                    ..Default::default()
                },
            },
        };
        let manifest = "{\n  \"name\": \"app\"\n}\n".to_string();
        let mut files = BTreeMap::new();
        files.insert(
            "yarn.lock".to_string(),
            format!(
                "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  \
                 version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  \
                 languageName: node\n  linkType: hard\n",
                "3".repeat(128)
            ),
        );
        files.insert("package.json".to_string(), manifest.clone());
        let run = |files: &BTreeMap<String, String>| {
            let rewrite = rewrite_registry_redirect(files, std::slice::from_ref(&candidate.dep));
            let confirmed = confirm(
                files,
                &rewrite,
                std::slice::from_ref(&candidate),
                false,
                &BTreeSet::new(),
            );
            (rewrite, confirmed)
        };
        let (first, confirmed) = run(&files);
        assert_eq!(confirmed.len(), 1, "{:?}", first.warnings);
        let pinned_lock = first.files["yarn.lock"].clone();
        assert!(
            pinned_lock.contains(&format!("\"left-pad@{url}\":")),
            "{pinned_lock}"
        );

        // Rescan with the pin intact: still confirmed.
        let mut pinned = files.clone();
        pinned.insert("yarn.lock".to_string(), pinned_lock.clone());
        pinned.insert(
            "package.json".to_string(),
            first.files["package.json"].clone(),
        );
        assert_eq!(run(&pinned).1.len(), 1);

        // The routing removed: the URL is still in the lock, nothing installs it.
        let mut orphan = files;
        orphan.insert("yarn.lock".to_string(), pinned_lock);
        orphan.insert("package.json".to_string(), manifest);
        let (rewrite, confirmed) = run(&orphan);
        assert!(
            rewrite
                .warnings
                .iter()
                .any(|w| w.code == "redirect_yarn_berry_resolutions_conflict"),
            "{:?}",
            rewrite.warnings
        );
        assert!(confirmed.is_empty(), "{confirmed:?}");
    }

    fn left_pad_candidate() -> Candidate {
        use crate::patch::redirect::Integrity;
        Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: "https://patch.test/left-pad-1.3.0.tgz".into(),
                registry_override: None,
                integrity: Integrity {
                    sha512: Some("sha512-PATCHED==".into()),
                    ..Default::default()
                },
            },
        }
    }

    /// The #490 lock: `pkga` depends on left-pad from git.
    const OVERRIDDEN_GIT_LOCK: &str = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "dependencies": { "pkga": "file:pkga-1.0.0.tgz" } },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    },
    "node_modules/pkga": {
      "version": "1.0.0",
      "resolved": "file:pkga-1.0.0.tgz",
      "dependencies": { "left-pad": "github:stevemao/left-pad#v1.3.0" }
    }
  }
}
"#;
    const OVERRIDING_MANIFEST: &str = r#"{"name":"app","dependencies":{"pkga":"file:pkga-1.0.0.tgz"},"overrides":{"left-pad":"1.3.0"}}"#;

    async fn npm_rewrite(
        view: &ProjectView<'_>,
        unreadable: &BTreeSet<String>,
    ) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            blocking: false,
        };
        let candidates = vec![left_pad_candidate()];
        let read = read_candidate_files(view, unreadable, &candidates).await;
        let done = rewrite(
            view,
            read.clone(),
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
            &[],
            options,
        )
        .await;
        (read, done)
    }

    #[tokio::test]
    async fn issue_490_the_root_manifest_overrides_reach_the_npm_rewriter() {
        let redirected = |done: &Rewritten| {
            done.rewrite
                .files
                .get("package-lock.json")
                .is_some_and(|lock| lock.contains("https://patch.test/left-pad-1.3.0.tgz"))
        };
        // In memory.
        let mut p = MemoryProject::new();
        p.insert_text("package-lock.json", OVERRIDDEN_GIT_LOCK);
        p.insert_text("package.json", OVERRIDING_MANIFEST);
        let (read, done) = npm_rewrite(&ProjectView::Memory(&p), &BTreeSet::new()).await;
        assert!(read.files.contains_key("package.json"));
        assert!(redirected(&done), "{:?}", done.rewrite.warnings);
        assert!(!done.rewrite.files.contains_key("package.json"));

        // A linked or unreadable manifest is left out, not refused: the
        // rewriter keeps the conservative #326 skip.
        for linked in [true, false] {
            let mut p = MemoryProject::new();
            p.insert_text("package-lock.json", OVERRIDDEN_GIT_LOCK);
            let mut unreadable = BTreeSet::new();
            if linked {
                p.insert("package.json", MemoryEntry::Symlink);
            } else {
                p.insert_present("package.json");
                unreadable.insert("package.json".to_string());
            }
            let (read, done) = npm_rewrite(&ProjectView::Memory(&p), &unreadable).await;
            assert!(!read.files.contains_key("package.json"));
            assert!(read.symlinked_reads.is_empty() && read.unreadable_reads.is_empty());
            assert!(!redirected(&done));
            assert!(done
                .rewrite
                .warnings
                .iter()
                .any(|w| w.code == "redirect_npm_non_registry_entry_skipped"));
        }

        // On disk.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), OVERRIDDEN_GIT_LOCK).unwrap();
        std::fs::write(tmp.path().join("package.json"), OVERRIDING_MANIFEST).unwrap();
        let (_, done) = npm_rewrite(&ProjectView::Disk(tmp.path()), &BTreeSet::new()).await;
        assert!(redirected(&done), "{:?}", done.rewrite.warnings);
    }

    /// REGRESSION (#367), binary lock: a `bun.lockb`-only project's root
    /// manifest is read for its `patchedDependencies`, and a package the
    /// project patches itself with `bun patch` keeps its registry record,
    /// loudly, and is never assumed patched by the in-run VEX.
    #[tokio::test]
    async fn issue_367_bun_lockb_keeps_a_user_patched_package_on_the_registry() {
        use crate::patch::redirect::Integrity;
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bun-lockb-bundled/both");
        let candidates = vec![Candidate {
            purl: "pkg:npm/is-number@7.0.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "is-number".into(),
                namespace: None,
                version: "7.0.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: "https://patch.test/is-number-7.0.0.tgz".into(),
                registry_override: None,
                integrity: Integrity {
                    sha512: Some(format!("sha512-{}==", "A".repeat(86))),
                    ..Default::default()
                },
            },
        }];
        let manifest = r#"{"name":"p","version":"1.0.0","dependencies":{"@bh/bund":"1.0.0","is-number":"7.0.0"}}"#;
        let patched_manifest = manifest.replacen(
            "}}",
            r#"},"patchedDependencies":{"is-number@7.0.0":"patches/is-number@7.0.0.patch"}}"#,
            1,
        );
        for user_patched in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::copy(fixture.join("bun.lockb"), tmp.path().join("bun.lockb")).unwrap();
            std::fs::write(
                tmp.path().join("package.json"),
                if user_patched {
                    &patched_manifest
                } else {
                    manifest
                },
            )
            .unwrap();
            let view = ProjectView::Disk(tmp.path());
            let outer = OuterAllowRemote::default;
            let options = RewriteOptions {
                dry_run: false,
                targets_pipenv_lock: false,
                pipenv_major: None,
                pipenv_unknown_detail: String::new(),
                trust_lockfile_config: true,
                npm_allow_remote_config: true,
                npm_outer: &outer,
                blocking: false,
            };
            let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
            assert!(read.files.contains_key("package.json"));
            let done = rewrite(
                &view,
                read,
                &candidates,
                BTreeMap::new(),
                &BTreeSet::new(),
                &[],
                options,
            )
            .await;
            let skipped = done
                .rewrite
                .warnings
                .iter()
                .find(|w| w.code == "redirect_bun_patched_dependency_skipped");
            if user_patched {
                assert!(
                    !done.rewrite.binary_files.contains_key("bun.lockb"),
                    "the user-patched record is left alone"
                );
                let skipped = skipped.expect("the skip is reported");
                assert!(
                    skipped.detail.contains("is-number@7.0.0"),
                    "{}",
                    skipped.detail
                );
                assert!(done.rewrite.bundled_skipped_uuids.contains("uuid"));
            } else {
                assert!(
                    done.rewrite.binary_files.contains_key("bun.lockb"),
                    "{:?}",
                    done.rewrite.warnings
                );
                assert!(skipped.is_none(), "{:?}", done.rewrite.warnings);
            }
            assert!(!done.rewrite.files.contains_key("package.json"));
        }
    }

    /// REGRESSION (#367), text lock: the root manifest is read beside a
    /// `bun.lock` even when the lock has no `workspaces` section to reach it
    /// through, and a package the project patches itself is never
    /// confirmed, not even when a sibling `package-lock.json` takes the
    /// hosted URL: Bun keeps installing the registry bytes.
    #[tokio::test]
    async fn issue_367_bun_lock_user_patched_package_is_never_confirmed() {
        let bun_lock = "{\n  \"lockfileVersion\": 1,\n  \"packages\": {\n    \"left-pad\": \
                        [\"left-pad@1.3.0\", \"\", {}, \"sha512-UPSTREAM==\"],\n  }\n}\n";
        let npm_lock = r#"{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "dependencies": { "left-pad": "1.3.0" } },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-UPSTREAM=="
    }
  }
}
"#;
        let manifest = r#"{"name":"app","dependencies":{"left-pad":"1.3.0"},"patchedDependencies":{"left-pad@1.3.0":"patches/left-pad@1.3.0.patch"}}"#;
        // Without the sibling npm lock nothing else reads the manifest.
        for with_npm_lock in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join("bun.lock"), bun_lock).unwrap();
            if with_npm_lock {
                std::fs::write(tmp.path().join("package-lock.json"), npm_lock).unwrap();
            }
            std::fs::write(tmp.path().join("package.json"), manifest).unwrap();
            let (read, done) = npm_rewrite(&ProjectView::Disk(tmp.path()), &BTreeSet::new()).await;
            assert!(read.files.contains_key("package.json"));
            assert!(
                !done.rewrite.files.contains_key("bun.lock"),
                "the user-patched entry keeps its registry tuple"
            );
            assert!(
                done.rewrite
                    .warnings
                    .iter()
                    .any(|w| w.code == "redirect_bun_patched_dependency_skipped"),
                "{:?}",
                done.rewrite.warnings
            );
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        }
    }

    fn gem_candidate() -> Candidate {
        use crate::patch::redirect::{Integrity, RegistryOverride, RegistryOverrideIdentifiers};
        Candidate {
            purl: "pkg:gem/rails@7.0.0".into(),
            dep: DepOverride {
                ecosystem: "gem".into(),
                name: "rails".into(),
                namespace: None,
                version: "7.0.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url: "https://patch.test/rails-7.0.0.gem".into(),
                registry_override: Some(RegistryOverride {
                    kind: "rubygems-compact-index".into(),
                    index_url: "https://patch.test/gem/tok/uuid/".into(),
                    identifiers: RegistryOverrideIdentifiers {
                        name: "rails".into(),
                        version: "7.0.0".into(),
                        gem_checksum_sha256: Some("f".repeat(64)),
                        ..Default::default()
                    },
                }),
                integrity: Integrity::default(),
            },
        }
    }

    const GRADLE_UUID: &str = "4d5e6f70-8192-4a3b-9c4d-5e6f708192a3";

    fn gradle_candidate() -> Candidate {
        use crate::patch::redirect::{Integrity, RegistryOverride, RegistryOverrideIdentifiers};
        let token = "22222222-3333-4444-8555-666666666666";
        Candidate {
            purl: "pkg:maven/com.socketfixture/victim@1.10.0".into(),
            dep: DepOverride {
                ecosystem: "maven".into(),
                name: "victim".into(),
                namespace: Some("com.socketfixture".into()),
                version: "1.10.0".into(),
                token: token.into(),
                patch_uuid: GRADLE_UUID.into(),
                artifact_url: format!(
                    "https://patch.socket.dev/patch/maven/com.socketfixture/victim/1.10.0/{token}/{GRADLE_UUID}/victim-1.10.0-socket.4d5e6f70.jar"
                ),
                registry_override: Some(RegistryOverride {
                    kind: "maven2".into(),
                    index_url: format!(
                        "https://patch.socket.dev/patch-registry/maven/{token}/{GRADLE_UUID}/maven2"
                    ),
                    identifiers: RegistryOverrideIdentifiers {
                        name: "com.socketfixture/victim".into(),
                        version: "1.10.0".into(),
                        maven_group_id: Some("com.socketfixture".into()),
                        maven_artifact_id: Some("victim".into()),
                        maven_suffixed_version: Some("1.10.0-socket.4d5e6f70".into()),
                        maven_pom_sha256: Some("b".repeat(64)),
                        ..Default::default()
                    },
                }),
                integrity: Integrity {
                    sha256: Some("a".repeat(64)),
                    ..Default::default()
                },
            },
        }
    }

    async fn gradle_rewrite(p: &MemoryProject) -> (CandidateFiles, Rewritten) {
        gradle_rewrite_in(&ProjectView::Memory(p)).await
    }

    async fn gradle_rewrite_in(view: &ProjectView<'_>) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            blocking: false,
        };
        let candidates = vec![gradle_candidate()];
        let read = read_candidate_files(view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(
            view,
            read.clone(),
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
            &[],
            options,
        )
        .await;
        (read, done)
    }

    /// The Gradle pass reads the script graph's scripts and every build's
    /// lock files (nested ones included), and the planner pins them.
    #[tokio::test]
    async fn the_gradle_pass_reads_the_script_graph_and_its_locks() {
        let mut p = MemoryProject::new();
        p.insert_text(
            "settings.gradle",
            "include 'app'\napply from: 'gradle/more.gradle'\n",
        );
        p.insert_text("gradle/more.gradle", "include 'lib'\n");
        p.insert_text("build.gradle", "");
        p.insert_text(
            "app/build.gradle",
            "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
        );
        p.insert_text("lib/build.gradle", "");
        p.insert_text(
            "lib/gradle.lockfile",
            "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
        );
        p.insert_text(
            "samples/x/gradle.lockfile",
            "com.socketfixture:victim:1.10.0=c\n",
        );
        let (read, done) = gradle_rewrite(&p).await;
        assert!(read.files.contains_key("gradle/more.gradle"));
        assert!(read.files.contains_key("app/build.gradle"));
        assert!(read.files.contains_key("lib/gradle.lockfile"));
        assert!(!read.files.contains_key("samples/x/gradle.lockfile"));
        assert!(done.rewrite.files["lib/gradle.lockfile"].contains("1.10.0-socket.4d5e6f70"));
        assert_eq!(
            done.confirmed,
            vec![(
                "pkg:maven/com.socketfixture/victim@1.10.0".to_string(),
                GRADLE_UUID.to_string()
            )]
        );
    }

    /// #646 review: a settings file that exists but cannot be read as text
    /// (Latin-1 bytes, mode 000) is not absent. The planner refuses the
    /// build instead of "creating" a one-line settings.gradle over it.
    #[tokio::test]
    async fn an_unreadable_settings_file_refuses_the_gradle_build() {
        const BUILD: &str = "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n";
        let refused = |read: &CandidateFiles, done: &Rewritten| {
            assert!(
                read.gradle_unreadable.contains("settings.gradle"),
                "{:?}",
                read.gradle_unreadable
            );
            assert!(done.rewrite.refused_gradle_uuids.contains(GRADLE_UUID));
            assert!(
                !done.rewrite.files.contains_key("settings.gradle"),
                "{:?}",
                done.rewrite.files.keys()
            );
            assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
            assert!(
                done.rewrite.warnings.iter().any(|w| w.code
                    == crate::patch::redirect::gradle::UNREADABLE_REFUSAL_CODE
                    || w.detail
                        .contains(crate::patch::redirect::gradle::UNREADABLE_REFUSAL_CODE)),
                "{:?}",
                done.rewrite.warnings
            );
        };

        let tmp = tempfile::tempdir().unwrap();
        let settings = tmp.path().join("settings.gradle");
        std::fs::write(
            &settings,
            b"rootProject.name = 'app'\n// Auteur: Andr\xe9\ninclude 'core'\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("build.gradle"), BUILD).unwrap();
        let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
        refused(&read, &done);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&settings, "rootProject.name = 'app'\n").unwrap();
            std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&settings).is_err() {
                let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
                refused(&read, &done);
            }
            std::fs::set_permissions(&settings, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        // In memory: non-UTF-8 bytes, and content the host did not provide.
        for entry in [
            MemoryEntry::Binary(b"rootProject.name = 'Andr\xe9'\n".to_vec().into()),
            MemoryEntry::Present,
        ] {
            let mut p = MemoryProject::new();
            p.insert("settings.gradle", entry);
            p.insert_text("build.gradle", BUILD);
            let (read, done) = gradle_rewrite(&p).await;
            refused(&read, &done);
        }

        // Control: a readable settings file is rewritten in place, never
        // created over.
        std::fs::write(&settings, "rootProject.name = 'app'\ninclude 'core'\n").unwrap();
        let (read, done) = gradle_rewrite_in(&ProjectView::Disk(tmp.path())).await;
        assert!(read.gradle_unreadable.is_empty());
        let text = &done.rewrite.files["settings.gradle"];
        assert!(text.contains("include 'core'"), "{text}");
    }

    /// A refused Gradle build is never confirmed by a snippet pasted into a
    /// build script, though it names the suffixed version and the index url.
    #[tokio::test]
    async fn a_pasted_gradle_snippet_is_not_confirmed() {
        let c = gradle_candidate();
        let ov = c.dep.registry_override.as_ref().unwrap();
        let snippet = crate::patch::redirect::gradle::fallback_snippet(
            &[crate::gradle::dsl::Dsl::Groovy],
            &ov.index_url,
            "com.socketfixture",
            "victim",
            "1.10.0",
            Some("1.10.0-socket.4d5e6f70"),
            GRADLE_UUID,
            false,
        );
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text(
            "build.gradle",
            format!("plugins {{ id 'com.android.application' }}\n{snippet}\n").as_str(),
        );
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.refused_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
    }

    /// A pom.xml beside a Gradle build: both must pin the patch.
    #[tokio::test]
    async fn a_mixed_pom_and_gradle_build_needs_both() {
        let pom = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <groupId>x</groupId>\n  <artifactId>y</artifactId>\n  <version>1</version>\n  <dependencies>\n    <dependency>\n      <groupId>com.socketfixture</groupId>\n      <artifactId>victim</artifactId>\n      <version>1.10.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text("pom.xml", pom);
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.rewrite.files["pom.xml"].contains("1.10.0-socket.4d5e6f70"));
        assert_eq!(done.confirmed.len(), 1);

        // The pom names another version: the Gradle half alone is not enough.
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text(
            "pom.xml",
            pom.replace("<version>1.10.0</version>", "<version>2.0</version>")
                .as_str(),
        );
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
    }

    const GEMFILE: &str = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n";
    const GEM_LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
        PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nBUNDLED WITH\n   2.5.22\n";

    async fn gem_rewrite(p: &MemoryProject) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            blocking: false,
        };
        let candidates = vec![gem_candidate()];
        let view = ProjectView::Memory(p);
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(
            &view,
            read.clone(),
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
            &[],
            options,
        )
        .await;
        (read, done)
    }

    /// #390: `bundle config set --local gemfile Gemfile.next` makes bundler
    /// load `Gemfile.next`; the hosted redirect used to rewrite `Gemfile`
    /// (which bundler ignores) and attest the patch. Now no gem file is a
    /// candidate and the run says why.
    #[tokio::test]
    async fn bundle_gemfile_naming_another_manifest_redirects_nothing() {
        let mut p = MemoryProject::new();
        for name in ["Gemfile", "Gemfile.next"] {
            p.insert_text(name, GEMFILE);
        }
        for name in ["Gemfile.lock", "Gemfile.next.lock"] {
            p.insert_text(name, GEM_LOCK);
        }
        p.insert_text(".bundle/config", "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n");
        let (read, done) = gem_rewrite(&p).await;
        assert!(!read.files.contains_key("Gemfile"));
        assert!(!read.files.contains_key("Gemfile.lock"));
        assert!(
            done.rewrite.files.keys().all(|k| !k.starts_with("Gemfile")),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes: Vec<&str> = done
            .rewrite
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect();
        assert!(
            codes.contains(&"redirect_gem_bundle_gemfile_unsupported"),
            "{codes:?}"
        );
        assert!(!codes.contains(&"redirect_gem_no_gemfile"), "{codes:?}");
    }

    /// `BUNDLE_GEMFILE: Gemfile` beside a `gems.rb`: bundler loads the
    /// Gemfile pair, so that is the pair the redirect edits (the rewriter's
    /// own filename rule would have picked gems.rb).
    #[tokio::test]
    async fn bundle_gemfile_naming_the_gemfile_redirects_it_over_gems_rb() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text("gems.rb", GEMFILE);
        p.insert_text("gems.locked", GEM_LOCK);
        p.insert_text(".bundle/config", "---\nBUNDLE_GEMFILE: \"Gemfile\"\n");
        let (_read, done) = gem_rewrite(&p).await;
        assert!(
            done.rewrite.files.contains_key("Gemfile"),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert!(!done.rewrite.files.contains_key("gems.rb"));
        assert!(!done.rewrite.files.contains_key("gems.locked"));
    }

    /// Without `BUNDLE_GEMFILE` nothing changes: `gems.rb` is still the
    /// spelling bundler (and the rewriter) picks.
    #[tokio::test]
    async fn default_discovery_still_prefers_gems_rb() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text("gems.rb", GEMFILE);
        p.insert_text("gems.locked", GEM_LOCK);
        let (read, done) = gem_rewrite(&p).await;
        assert!(read.files.contains_key("Gemfile"));
        assert!(
            done.rewrite.files.contains_key("gems.rb"),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert!(!done.rewrite.files.contains_key("Gemfile"));
    }

    /// #333: the Pipenv planner keys a live lock on the `Pipfile` beside
    /// it, so the candidate reads must carry it — read from disk, and kept
    /// as present in memory even when the host has no content for it.
    #[tokio::test]
    async fn the_pipfile_is_read_for_its_presence() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Pipfile"), "[packages]\n").unwrap();
        std::fs::write(tmp.path().join("Pipfile.lock"), "{}").unwrap();
        let read =
            read_candidate_files(&ProjectView::Disk(tmp.path()), &BTreeSet::new(), &[]).await;
        assert_eq!(
            read.files.get("Pipfile").map(String::as_str),
            Some("[packages]\n")
        );

        for entry in [MemoryEntry::Symlink, MemoryEntry::Present] {
            let mut p = MemoryProject::new();
            p.insert_text("Pipfile.lock", "{}");
            p.insert("Pipfile", entry.clone());
            let unreadable = match entry {
                MemoryEntry::Present => BTreeSet::from(["Pipfile".to_string()]),
                _ => BTreeSet::new(),
            };
            let read = read_candidate_files(&ProjectView::Memory(&p), &unreadable, &[]).await;
            assert_eq!(
                read.files.get("Pipfile").map(String::as_str),
                Some(""),
                "{entry:?}"
            );
        }

        // Absent stays absent: a lone Pipfile.lock is abandoned.
        let mut p = MemoryProject::new();
        p.insert_text("Pipfile.lock", "{}");
        let read = read_candidate_files(&ProjectView::Memory(&p), &BTreeSet::new(), &[]).await;
        assert!(!read.files.contains_key("Pipfile"));
    }

    #[test]
    fn file_ecosystems_cover_the_rewrite_targets() {
        assert_eq!(file_ecosystem("package-lock.json"), Some("npm"));
        assert_eq!(
            file_ecosystem("common/config/rush/pnpm-lock.yaml"),
            Some("npm")
        );
        assert_eq!(file_ecosystem("tool.py.lock"), Some("pypi"));
        assert_eq!(file_ecosystem("crates/a/Cargo.toml"), Some("cargo"));
        assert_eq!(file_ecosystem("build.gradle"), None);
        assert_eq!(file_ecosystem("Pipfile"), None);
    }
}

/// The one-pass multi-needle confirmation probe answers exactly what the
/// per-candidate `any()` oracle answers.
#[cfg(test)]
mod probe_equivalence_tests {
    use super::candidate_presence_needles;
    use crate::hosted::guidance::npm_lock_url_needles;
    use crate::patch::redirect::presence::groups_present;
    use crate::patch::redirect::{
        artifact_url_present, artifact_url_spellings, rewrite_registry_redirect, DepOverride,
    };
    use crate::utils::uri::encode_uri_component;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};

    /// The per-candidate probe [`candidate_presence_needles`] +
    /// `groups_present` replaced, kept as the equivalence oracle.
    fn candidate_present_oracle(final_texts: &[&String], dep: &DepOverride) -> bool {
        let artifact_url = dep.artifact_url.as_str();
        let registry = dep.registry_override.as_ref();
        let index_url = registry.map(|o| o.index_url.as_str());
        let suffixed_version =
            registry.and_then(|o| o.identifiers.maven_suffixed_version.as_deref());
        let encoded = encode_uri_component(artifact_url);
        final_texts.iter().any(|text| {
            artifact_url_present(text, artifact_url)
                || text.contains(encoded.as_str())
                || index_url.is_some_and(|iu| text.contains(iu))
                || suffixed_version.is_some_and(|sv| text.contains(sv))
        })
    }

    fn golden_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redirect")
    }

    fn cases(dir: &Path, out: &mut Vec<PathBuf>) {
        if dir.join("input").is_dir() && dir.join("overrides.json").is_file() {
            out.push(dir.to_path_buf());
            return;
        }
        for entry in std::fs::read_dir(dir).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                cases(&p, out);
            }
        }
    }

    fn read_tree(base: &Path) -> BTreeMap<String, String> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else if let Ok(text) = std::fs::read_to_string(&p) {
                    let rel = p.strip_prefix(base).unwrap().to_string_lossy();
                    out.insert(rel.replace('\\', "/"), text);
                }
            }
        }
        let mut out = BTreeMap::new();
        if base.is_dir() {
            walk(base, base, &mut out);
        }
        out
    }

    /// Every golden fixture (composer `\/`, berry percent-encoded, maven
    /// suffixed version, go module path, cargo index url, …): each case's
    /// final texts — input overlaid with the rewriters' own output, as the probe
    /// sees them — plus its authored `expected/` files, probed with EVERY
    /// fixture's overrides so hits and misses are both well exercised.
    #[test]
    fn multi_needle_probe_matches_per_candidate_any_on_golden_fixtures() {
        let mut dirs = Vec::new();
        cases(&golden_root(), &mut dirs);
        dirs.sort();
        assert!(dirs.len() > 50, "golden fixtures not found: {}", dirs.len());

        let mut all_overrides: Vec<DepOverride> = Vec::new();
        let mut text_sets: Vec<Vec<String>> = Vec::new();
        for case in &dirs {
            let overrides: Vec<DepOverride> = match serde_json::from_str(
                &std::fs::read_to_string(case.join("overrides.json")).unwrap(),
            ) {
                Ok(o) => o,
                Err(_) => continue,
            };
            let input = read_tree(&case.join("input"));
            let rewrite = rewrite_registry_redirect(&input, &overrides);
            let finals: Vec<String> = input
                .iter()
                .map(|(name, text)| rewrite.files.get(name).unwrap_or(text).clone())
                .chain(
                    rewrite
                        .files
                        .iter()
                        .filter(|(name, _)| !input.contains_key(*name))
                        .map(|(_, t)| t.clone()),
                )
                .collect();
            text_sets.push(finals);
            text_sets.push(read_tree(&case.join("expected")).into_values().collect());
            text_sets.push(input.into_values().collect());
            all_overrides.extend(overrides);
        }
        text_sets.push(Vec::new());
        // Texts that carry ONE needle kind and nothing else — no golden
        // fixture has the maven suffixed version or the registry index URL
        // without the artifact URL beside it, so a needle dropped from
        // `candidate_presence_needles` would otherwise go unnoticed.
        let mut lone_suffixed: Vec<usize> = Vec::new();
        for o in all_overrides
            .iter()
            .filter_map(|d| d.registry_override.as_ref())
        {
            text_sets.push(vec![format!("<url>{}</url>\n", o.index_url)]);
            if let Some(sv) = o.identifiers.maven_suffixed_version.as_deref() {
                lone_suffixed.push(text_sets.len());
                text_sets.push(vec![format!("<version>{sv}</version>\n")]);
            }
        }
        assert!(
            !lone_suffixed.is_empty(),
            "no maven suffixed-version override"
        );

        let groups: Vec<Vec<String>> = all_overrides
            .iter()
            .map(candidate_presence_needles)
            .collect();
        let (mut hits, mut misses) = (0usize, 0usize);
        for (set, texts) in text_sets.iter().enumerate() {
            let refs: Vec<&String> = texts.iter().collect();
            let fast = groups_present(&refs, &groups);
            if lone_suffixed.contains(&set) {
                assert!(
                    fast.iter().any(|hit| *hit),
                    "a lone suffixed version confirms its maven override"
                );
            }
            for (dep, got) in all_overrides.iter().zip(&fast) {
                let want = candidate_present_oracle(&refs, dep);
                assert_eq!(
                    *got, want,
                    "{}/{} / {}",
                    dep.ecosystem, dep.name, dep.artifact_url
                );
                if want {
                    hits += 1;
                } else {
                    misses += 1;
                }
            }
        }
        assert!(hits > 100 && misses > 100, "hits={hits} misses={misses}");

        // The pnpm / npm host filters and the heal probe: the npm lock
        // spellings, and the bare `artifact_url_present` pair.
        let npm: Vec<&DepOverride> = all_overrides.iter().collect();
        let lock_groups: Vec<Vec<String>> = npm
            .iter()
            .map(|o| npm_lock_url_needles(&o.artifact_url))
            .collect();
        let pair_groups: Vec<[String; 2]> = npm
            .iter()
            .map(|o| artifact_url_spellings(&o.artifact_url))
            .collect();
        for texts in &text_sets {
            let lock_fast = groups_present(texts, &lock_groups);
            let pair_fast = groups_present(texts, &pair_groups);
            for (i, o) in npm.iter().enumerate() {
                let encoded = encode_uri_component(&o.artifact_url);
                let pair = texts
                    .iter()
                    .any(|t| artifact_url_present(t, &o.artifact_url));
                let lock = texts.iter().any(|t| {
                    artifact_url_present(t, &o.artifact_url) || t.contains(encoded.as_str())
                });
                assert_eq!(pair_fast[i], pair, "{}", o.artifact_url);
                assert_eq!(lock_fast[i], lock, "{}", o.artifact_url);
            }
        }
    }
}
