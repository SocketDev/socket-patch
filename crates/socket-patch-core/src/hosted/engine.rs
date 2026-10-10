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
//! 4. (caller) the apply lock and the vendored→hosted takeover.
//! 5. [`read_candidate_files`] → [`wheel_targets`] → (caller) wheel metadata,
//!    and [`yarn_berry_manifest_targets`] → (caller) served npm manifests.
//! 6. [`rewrite`] — the rewriters, the pnpm `trustLockfile` and npm
//!    `allow-remote` auto-configs, and the per-ecosystem confirmation.
//! 7. [`guard`] — the symlink / unreadable-file refusal before any write.
//!
//! Nothing here writes, spawns, reads the environment or touches the
//! network: every host effect (locking, probes, record fetches, the commit
//! of the rewritten files) stays with the caller.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::api::types::PackageVendorResult;
use crate::constants::npm_family::{
    RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR, VLT_HIDDEN_LOCK_REL, VLT_LOCK,
};
use crate::patch::redirect::npmrc::{
    effective_replace_registry_host, plan_npmrc_allow_remote_with, replace_registry_host_rewrites,
    NpmrcPlan, OuterAllowRemote, NPMRC_ALLOW_REMOTE_EDIT_KIND, NPMRC_REL,
};
use crate::patch::redirect::presence::groups_present;
use crate::patch::redirect::yarnrc::OuterYarnMirror;
use crate::patch::redirect::{
    artifact_url_spellings, rewrite_registry_redirect_withholding_vlt, DepOverride, FileEdit,
    RewriteResult, RewriteWarning,
};
use crate::utils::pnpm_workspace::governing_workspace_file;
use crate::utils::purl::purl_parts;
use crate::utils::redact::url_host;
use crate::vendor::lock_inventory::{bun_text_lock_drives, MemoryEntry, ProjectView};

use super::guidance::{
    npm_allow_remote_already_detail, npm_allow_remote_configured_detail,
    npm_allow_remote_env_set_detail, npm_allow_remote_manual_detail,
    npm_allow_remote_outer_set_detail, npm_allow_remote_unreadable_detail,
    npm_allow_remote_user_set_detail, npm_lock_url_needles, npm_replace_registry_host_detail,
    plan_workspace_trust, pnpm_heal_root, pnpm_is_shrinkwrap_lock, pnpm_lock_may_need_store_flag,
    pnpm_lock_version_major, pnpm_root_only_workspace_breaks_add, pnpm_trust_configured_detail,
    pnpm_trust_legacy_detail, pnpm_trust_manual_guidance, pnpm_trust_not_needed_detail,
    pnpm_trust_policy_preamble, pnpm_trust_rush_detail, pnpm_trust_workspace_unreadable_detail,
    pnpm_trust_workspace_unsupported_detail, read_npmrc_for_allow_remote, read_workspace_for_trust,
    TrustPlan, NPM_LOCKS, NPM_REPLACE_REGISTRY_HOST_CODE, PNPM_TRUST_RUSH_MIXED_NOTE,
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
/// presence-only), and, on disk and in memory alike, for one that is not
/// UTF-8 text (#721): no rewriter can edit it, and reading it as absent
/// would leave its pins unpatched behind an exit-0 run.
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

/// `(purl, uuid)` of each candidate that was granted but that nothing in
/// the project's final files pins: not in `confirmed` (purl and uuid) and
/// not already reported in `skipped` (by uuid — a skip carries its own
/// reason). Candidate order. The disk and memory paths both report these
/// as the `unpinned` rows of the `redirect` block, and the disk path's
/// human output lists them as "Not hosted".
pub fn unconfirmed_candidates(
    candidates: &[Candidate],
    confirmed: &[(String, String)],
    skipped: &[SkippedPatch],
) -> Vec<(String, String)> {
    candidates
        .iter()
        .filter(|c| {
            !confirmed
                .iter()
                .any(|(purl, uuid)| *purl == c.purl && *uuid == c.dep.patch_uuid)
        })
        .filter(|c| !skipped.iter().any(|s| s.uuid == c.dep.patch_uuid))
        .map(|c| (c.purl.clone(), c.dep.patch_uuid.clone()))
        .collect()
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

/// The refusal for an unreadable `socket-patch.sbt`, the file the sbt
/// planner owns and would otherwise create over the user's bytes.
pub const SBT_OWNED_FILE_UNREADABLE: &str = "redirect_sbt_owned_file_unreadable";

fn undecodable_refusal(rel: &str) -> Refusal {
    // Keeps the sbt planner's own refusal code, and still refuses here,
    // before any vendored->hosted takeover revert.
    if rel == crate::formats::sbt::owned_file::HOSTED_FILE {
        return Refusal {
            code: SBT_OWNED_FILE_UNREADABLE.to_string(),
            message: format!(
                "{rel} is not UTF-8 text, so the hosted sbt wiring would replace it; \
                 re-save it as UTF-8 and re-run; nothing was written"
            ),
        };
    }
    Refusal {
        code: UNREADABLE_REFUSAL.to_string(),
        message: format!(
            "{rel} is not UTF-8 text (for example UTF-16, which Windows PowerShell 5.1 \
             writes for `pip freeze > requirements.txt`), so it cannot be rewritten \
             alongside the other lockfiles; re-save it as UTF-8 and re-run; nothing was \
             written"
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

/// Whether an npm candidate would rewrite a `bun.lockb` that is a symbolic
/// link (atomic replacement cannot preserve a link; previews refuse too).
pub fn bun_lockb_symlinked(view: &ProjectView<'_>, candidates: &[Candidate]) -> bool {
    candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && !bun_text_lock_drives(view)
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
    /// The workspace members' own locks among `files`, read beside the
    /// root's when the workspace turned the shared lock off (#492).
    pub pnpm_member_lock_keys: Vec<String>,
    /// In memory only: candidate files the disk flow reads through a
    /// symbolic link. Their bytes are unknown here, so a project whose
    /// candidates could rewrite one is refused like the disk symlink guard
    /// refuses the write.
    pub symlinked_reads: Vec<String>,
    /// In memory only: candidate files that exist without content; a
    /// project whose candidates could rewrite (or whose rewrite depends on)
    /// one is refused, since the rewriters would treat it as absent.
    pub unreadable_reads: Vec<String>,
    /// Candidate files that exist but are not UTF-8 text (a UTF-16
    /// requirements.txt pip reads, #721), on disk and in memory alike. They
    /// are left out of `files`; a project whose candidates could rewrite
    /// one is refused rather than read as if the file were absent.
    pub undecodable_reads: Vec<String>,
    /// Gradle build files the script graph reached that exist but cannot be
    /// read as text (any view): the hosted Gradle planner refuses the build
    /// instead of taking them for absent (and creating a settings file over
    /// one).
    pub gradle_unreadable: BTreeSet<String>,
    /// Set when bundler is configured to load a manifest the gem rewriter
    /// cannot edit (`BUNDLE_GEMFILE`), or to fetch the patch-registry
    /// source through a mirror (`mirror.all`, #681): every gem manifest and
    /// lock was left out of `files`, and the rewrite reports this instead
    /// of a redirect.
    pub gem_refusal: Option<RewriteWarning>,
    /// Set when the root pnpm lock pins nothing pnpm installs: the
    /// workspace keeps one lock per member but the members cannot be
    /// listed (#492), or `gitBranchLockfile` installs the branch from a
    /// `pnpm-lock.<branch>.yaml` (#556). The root lock was left out of
    /// `files`, and the rewrite reports this instead of a redirect or a
    /// "no lockfile" hint.
    pub pnpm_refusal: Option<RewriteWarning>,
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
            ProjectView::Disk(_) | ProjectView::Snapshot(_) => match view.read_text(rel).await {
                Ok(text) => Some(text),
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    self.undecodable_reads.push(rel.to_string());
                    None
                }
                Err(_) => None,
            },
            ProjectView::Memory(project) => {
                if project.is_symlink(rel) {
                    self.symlinked_reads.push(rel.to_string());
                    return false;
                }
                if unreadable.contains(rel) {
                    self.unreadable_reads.push(rel.to_string());
                    return false;
                }
                // Disk reads any UTF-8 regular file and records a non-UTF-8
                // one as undecodable; so does memory.
                match project.get(rel) {
                    Some(MemoryEntry::Text(text)) => Some(text.to_string()),
                    Some(MemoryEntry::Binary(bytes)) => match std::str::from_utf8(bytes) {
                        Ok(text) => Some(text.to_string()),
                        Err(_) => {
                            self.undecodable_reads.push(rel.to_string());
                            None
                        }
                    },
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

/// Whether the project is a Rush monorepo (disk: `rush.json` is a file).
fn rush_repo(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            cwd.join("rush.json").is_file()
        }
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
/// `Cargo.toml`), the Python locks and their scripts, the Rush locks, and
/// the pnpm workspace members' own locks.
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
            .is_some_and(|lock| crate::formats::yarn::is_berry_lock(lock))
    {
        out.read(view, unreadable, "package.json").await;
    // Otherwise the root manifest's `overrides` decide which git / url /
    // `file:` dependent specs npm really installs from (#490), and beside a
    // classic `yarn.lock` its `packageManager` says whether a yarn 2+ install
    // could migrate the lock and drop the hosted pins (#907). The npm lock
    // and yarn classic rewriters read it as advisory input only: no
    // rewriter edits it, so a link or an unreadable in-memory entry is left
    // out (the rewriters then keep their conservative reading) rather than
    // refused.
    } else if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && (NPM_LOCKS.iter().any(|lock| out.files.contains_key(*lock))
            || out.files.contains_key("yarn.lock"))
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

    // Beside a classic yarn.lock, the yarn configs decide whether an
    // offline mirror serves the tarballs (the classic rewriter's refusal).
    // Read strictly: a link or an unreadable in-memory entry could hide a
    // mirror, so it is refused like a rewrite target.
    if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && out
            .files
            .get("yarn.lock")
            .is_some_and(|lock| !crate::formats::yarn::is_berry_lock(lock))
    {
        out.read(view, unreadable, crate::patch::redirect::YARNRC_REL)
            .await;
        out.read(view, unreadable, NPMRC_REL).await;
        // A `file:` directory copy is locked under the DEPENDENCY name, so
        // the classic rewriter reads which package it is from the
        // directory's `package.json` (#1236). Advisory: never rewritten,
        // and an unreadable one only leaves that copy unnamed.
        let dirs: BTreeSet<String> = out
            .files
            .get("yarn.lock")
            .map(|lock| {
                crate::vendor::lock_inventory::yarn::classic_entries(lock)
                    .iter()
                    .filter_map(|e| {
                        crate::formats::yarn::source::classic_file_directory(&e.patterns)
                    })
                    .collect()
            })
            .unwrap_or_default();
        for dir in dirs {
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

    // NuGet merges the user config and every parent directory's config
    // under the project's own: a catch-all mapping the rewriter creates
    // must name their sources too (#354). Disk only (the in-memory engine
    // refuses NuGet, and could not see them).
    if candidates.iter().any(|c| c.dep.ecosystem == "nuget")
        && !matches!(view, ProjectView::Memory(_))
    {
        // The configs live outside the project: read beside the view, then
        // handed to it as such reads (asking for its raw root would end a
        // re-scan read cache's recording).
        if let Some(root) = view.disk_root_reading(std::iter::empty::<&str>()) {
            let (inherited, touched) =
                crate::vendor::nuget_config::inherited_source_keys_traced(root).await;
            view.disk_root_reading(&touched);
            out.files.insert(
                crate::patch::redirect::NUGET_INHERITED_SOURCES_KEY.to_string(),
                inherited.keys.join("\n"),
            );
            if inherited.mapped {
                out.files.insert(
                    crate::patch::redirect::NUGET_INHERITED_MAPPING_KEY.to_string(),
                    String::new(),
                );
            }
        }
    }

    for path in view.python_lock_paths() {
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
    } else if candidates.iter().any(|c| c.dep.ecosystem == "npm") {
        if let Some(branch) = crate::utils::pnpm_workspace::git_branch_locks(view).await {
            refuse_git_branch_locks(&mut out, &branch);
        } else {
            read_pnpm_member_locks(view, unreadable, &mut out).await;
        }
    }
    if candidates.iter().any(|c| c.dep.ecosystem == "gem") {
        keep_bundler_loaded_gem_files(view, candidates, &mut out).await;
    }
    // A Gradle build: every script, catalog and lock file its script graph
    // reaches, for the hosted Gradle planner.
    if candidates.iter().any(|c| c.dep.ecosystem == "maven")
        && crate::patch::redirect::gradle::gradle_build_present(&out.files)
    {
        read_gradle_files(view, unreadable, &mut out).await;
        // The Gradle planner refuses a build over a file it cannot read as
        // text and the scan carries on, so such a file is not a reason to
        // refuse the whole run (#721).
        let gradle_unreadable = &out.gradle_unreadable;
        out.undecodable_reads
            .retain(|rel| !gradle_unreadable.contains(rel));
    } else {
        // No readable Gradle build: the Gradle planner never runs, so a
        // stray Gradle file it would own (a lock, a nested script) is never
        // rewritten and must not refuse the rest of the run. A root build
        // or settings script still refuses: it may be the build itself,
        // unreadable, which the planner would otherwise skip silently.
        out.undecodable_reads.retain(|rel| {
            !is_gradle_owned_file(rel)
                || crate::vendor::jvm::layout::GRADLE_ROOT_FILES.contains(&rel.as_str())
        });
    }
    // An sbt build's resolution evidence rides a synthetic key (see
    // `patch::redirect::sbt::SBT_RESOLUTION_KEY`).
    if candidates.iter().any(|c| c.dep.ecosystem == "maven")
        && crate::formats::sbt::build::sbt_build_present(&crate::formats::sbt::build::files_reader(
            &out.files,
        ))
    {
        if let Some(json) = super::sbt_reads::extra_resolution(view).await {
            let key = crate::patch::redirect::sbt::SBT_RESOLUTION_KEY;
            out.files.insert(key.to_string(), json);
        }
    }
    out.symlinked_reads.sort();
    out.symlinked_reads.dedup();
    out.unreadable_reads.sort();
    out.unreadable_reads.dedup();
    out.undecodable_reads.sort();
    out.undecodable_reads.dedup();
    out
}

/// A pnpm workspace with `sharedWorkspaceLockfile: false` installs each
/// member from the member's own `pnpm-lock.yaml`; the root lock covers the
/// root project alone (pnpm 7 writes none at all). Every member lock is a
/// rewrite target, read strictly under its root-relative key: the pnpm
/// rewriter is basename-generalized and the write-back path-generic, like
/// the Rush locks above. Members whose list cannot be read leave the root
/// lock out too and refuse (see [`CandidateFiles::pnpm_refusal`]).
/// In memory too: the in-memory engine demotes each member lock into its
/// workspace root once that root's files confirm it reads them
/// (`confirm_pnpm_members` in [`super::memory`]),
/// so the root reads them here as a disk run from it does; a member lock
/// whose content was not provided refuses the project like an unreadable
/// root lock.
async fn read_pnpm_member_locks(
    view: &ProjectView<'_>,
    unreadable: &BTreeSet<String>,
    out: &mut CandidateFiles,
) {
    use crate::utils::pnpm_workspace::{member_locks, MemberLocks};
    match member_locks(view).await {
        MemberLocks::Shared => {}
        MemberLocks::PerMember(keys) => {
            for key in keys {
                if out.read(view, unreadable, &key).await {
                    out.pnpm_member_lock_keys.push(key);
                    continue;
                }
                // A member lock that exists but cannot be read (a FIFO, not
                // UTF-8) still drives that member's install: pinning the
                // others would confirm the dep while it stays upstream there.
                for read in std::mem::take(&mut out.pnpm_member_lock_keys) {
                    out.files.remove(&read);
                }
                refuse_pnpm_members(
                    out,
                    format!(
                        "{key} (a workspace member's own lock under \
                         sharedWorkspaceLockfile: false) cannot be read as text"
                    ),
                );
                return;
            }
        }
        MemberLocks::Unresolved(why) => refuse_pnpm_members(out, why),
    }
}

/// Leave the root pnpm lock out and record why (see
/// [`CandidateFiles::pnpm_refusal`]).
fn refuse_pnpm_members(out: &mut CandidateFiles, why: String) {
    out.files.remove("pnpm-lock.yaml");
    out.pnpm_refusal = Some(RewriteWarning {
        code: PNPM_MEMBER_LOCKS_UNRESOLVED.into(),
        detail: format!(
            "{why}; no pnpm lock was rewritten — make every member lock a readable \
             file listed by plain `packages:` globs (or install the members) and re-run"
        ),
    });
}

/// `gitBranchLockfile` with a branch lock present (#556): pnpm installs
/// the branch from that lock, which hosted mode cannot pin, so the root
/// lock (stale on the branch) is left out and the run refuses every pnpm
/// pin (see [`CandidateFiles::pnpm_refusal`]). In memory the root lock is
/// dropped from the link and unreadable lists too: it is not written.
fn refuse_git_branch_locks(
    out: &mut CandidateFiles,
    branch: &crate::utils::pnpm_workspace::GitBranchLocks,
) {
    const ROOT_LOCKS: [&str; 2] = ["pnpm-lock.yaml", "shrinkwrap.yaml"];
    for lock in ROOT_LOCKS {
        out.files.remove(lock);
    }
    out.symlinked_reads
        .retain(|r| !ROOT_LOCKS.contains(&r.as_str()));
    out.unreadable_reads
        .retain(|r| !ROOT_LOCKS.contains(&r.as_str()));
    out.pnpm_refusal = Some(git_branch_lock_refusal(branch));
}

/// The [`PNPM_GIT_BRANCH_LOCKFILE`] warning for `branch`: the hosted
/// rewrite's, and the vendored→hosted takeover's (which keeps the vendored
/// wiring rather than revert it into a lock pnpm does not install from).
pub fn git_branch_lock_refusal(
    branch: &crate::utils::pnpm_workspace::GitBranchLocks,
) -> RewriteWarning {
    RewriteWarning {
        code: PNPM_GIT_BRANCH_LOCKFILE.into(),
        detail: format!(
            "{}; no pnpm lock was rewritten — {}",
            branch.describe(),
            crate::utils::pnpm_workspace::GitBranchLocks::REMEDY
        ),
    }
}

/// Refusal code for a `sharedWorkspaceLockfile: false` workspace whose
/// member locks cannot be listed.
pub const PNPM_MEMBER_LOCKS_UNRESOLVED: &str = "redirect_pnpm_member_locks_unresolved";

/// Refusal code for a project whose `gitBranchLockfile` setting makes pnpm
/// install from a `pnpm-lock.<branch>.yaml` (#556).
pub const PNPM_GIT_BRANCH_LOCKFILE: &str = "redirect_pnpm_git_branch_lockfile";

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
/// - no `BUNDLE_GEMFILE`: unchanged for a lone `Gemfile` or `gems.rb`; a
///   `Gemfile` + `gems.rb` twin is withheld, since bundler 1.x loads the
///   `Gemfile`, >= 2 loads `gems.rb`, and nothing says which runs
///   ([`manifest::twin_manifest_refusal`](crate::formats::gem::manifest::twin_manifest_refusal));
/// - `BUNDLE_GEMFILE` naming the root `Gemfile` / `gems.rb`: the other
///   spelling is dropped;
/// - `BUNDLE_GEMFILE` naming anything else, or bundler 4's
///   `BUNDLE_LOCKFILE` naming a lock other than the pair's own: every
///   spelling is dropped and [`CandidateFiles::gem_refusal`] says why;
/// - a bundler mirror capturing the patch-registry source (`mirror.all`,
///   or `mirror.<source>`; see [`crate::formats::gem::mirror`]): every
///   spelling is dropped the same way (#681).
///
/// A memory view has no environment: only its own app config is read.
async fn keep_bundler_loaded_gem_files(
    view: &ProjectView<'_>,
    candidates: &[Candidate],
    out: &mut CandidateFiles,
) {
    use crate::formats::gem::manifest::{self, LoadedManifest};
    let sources: Vec<&str> = candidates
        .iter()
        .filter_map(|c| c.dep.registry_override.as_ref())
        .filter(|ov| ov.kind == "rubygems-compact-index")
        .map(|ov| ov.index_url.as_str())
        .collect();
    let loaded = crate::crawlers::ruby_crawler::bundler_loaded_manifest_in(view).await;
    let mirror = match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let root = view.disk_root().expect("a disk view has a root");
            crate::crawlers::ruby_crawler::bundler_source_mirror(root, &sources).await
        }
        ProjectView::Memory(_) => {
            let config = view.read_text(".bundle/config").await.ok();
            crate::formats::gem::mirror::capturing_mirror(config.as_deref(), &[], &sources)
        }
    };
    let refusal = if let Some(detail) = loaded.unsupported_detail() {
        let code = match &loaded {
            LoadedManifest::UnsupportedLockfile { .. } => {
                "redirect_gem_bundle_lockfile_unsupported"
            }
            _ => "redirect_gem_bundle_gemfile_unsupported",
        };
        Some(RewriteWarning {
            code: code.into(),
            detail,
        })
    } else {
        // #681: a mirror serves the upstream gem for the redirected source,
        // so bundler would install unpatched bytes while the run (and its
        // VEX) reported the gem redirected. Refuse every gem redirect.
        mirror.map(|capture| RewriteWarning {
            code: "redirect_gem_mirror_overrides_source".into(),
            detail: format!(
                "{} routes the Socket patch-registry source to that mirror, which serves \
                 the unpatched upstream gem; no gem was redirected. To fix, {} and re-run \
                 the scan",
                capture.setting, capture.remedy
            ),
        })
    };
    // A spelling bundler sees (`File.file?`) even when this run couldn't
    // read it: a symlink, an unreadable or a non-UTF-8 file still makes the
    // project a twin, as lock inventory (`view.is_file`) already counts it.
    let present = |rel: &str| {
        out.files.contains_key(rel)
            || view.is_file(rel)
            || out.symlinked_reads.iter().any(|r| r == rel)
            || out.unreadable_reads.iter().any(|r| r == rel)
            || out.undecodable_reads.iter().any(|r| r == rel)
    };
    let is_twin = present("gems.rb") && present("Gemfile");
    let mut twin_ambiguous = None;
    let keep: &[&str] = match (&loaded, &refusal) {
        (_, Some(_))
        | (LoadedManifest::Unsupported { .. } | LoadedManifest::UnsupportedLockfile { .. }, _) => {
            &[]
        }
        // Default discovery of a twin: bundler 1.x loads the `Gemfile`
        // and >= 2 loads `gems.rb`, and nothing here says which runs, so
        // neither pair is wired (#751).
        (LoadedManifest::Default, None) if is_twin => {
            twin_ambiguous = Some(manifest::twin_manifest_refusal());
            &[]
        }
        (LoadedManifest::Default, None) => return,
        (LoadedManifest::Configured { .. }, None) => {
            let (gemfile, lock) = loaded
                .pair(out.files.contains_key("gems.rb"))
                .expect("a configured default spelling has a pair");
            &[gemfile, lock]
        }
    };
    let dropped = |rel: &str| GEM_MANIFEST_FILES.contains(&rel) && !keep.contains(&rel);
    out.files.retain(|rel, _| !dropped(rel));
    out.symlinked_reads.retain(|rel| !dropped(rel));
    out.unreadable_reads.retain(|rel| !dropped(rel));
    out.undecodable_reads.retain(|rel| !dropped(rel));
    out.gem_refusal = refusal.or(twin_ambiguous.map(|detail| RewriteWarning {
        code: "redirect_gem_twin_manifest_ambiguous".into(),
        detail,
    }));
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

/// `text` about one hosted artifact made safe to show: every URL in it
/// through [`crate::utils::redact::redact_urls_in`], and then the grant
/// token of `artifact_url` wherever it is still spelled as a path level.
/// The second pass is what knowing the artifact adds: its token is the
/// level before `patch_uuid`, so a URL served under a root the shape-based
/// redactor does not recognise (a custom `--api-url` server) or with a
/// non-canonical patch id is still covered.
pub fn redact_artifact_text(text: &str, artifact_url: &str, patch_uuid: &str) -> String {
    let text = crate::utils::redact::redact_urls_in(text);
    match crate::patch::redirect::grant_token_path_segment(artifact_url, patch_uuid) {
        Some(token) if token != crate::utils::redact::REDACTED => text.replace(
            &format!("/{token}/"),
            &format!("/{}/", crate::utils::redact::REDACTED),
        ),
        _ => text.into_owned(),
    }
}

/// The skip recorded for a pypi dep whose wheel metadata could not be
/// fetched (`detail` redacted by [`redact_artifact_text`]).
pub fn wheel_metadata_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!("pkg:pypi/{}@{}", dep.name, dep.version),
        uuid: dep.patch_uuid.clone(),
        reason: "python_metadata_unavailable".to_string(),
        detail: Some(redact_artifact_text(
            detail,
            &dep.artifact_url,
            &dep.patch_uuid,
        )),
    }
}

/// The npm candidates whose yarn berry pin needs the served tarball's own
/// `package.json`, in candidate order: yarn builds a tarball entry's `bin:`
/// from that manifest, not from the registry metadata the locked `npm:`
/// entry came from, and the two spell bin paths differently (#718); only the
/// npm resolver adds an implicit `node-gyp` dependency (#737). Only an entry
/// the pin would re-key that carries a `bin:` map or that dependency needs it
/// (see `berry_pin_needs_manifest`; a fork alias never counts), so a berry
/// project with neither fetches nothing.
pub fn yarn_berry_manifest_targets<'a>(
    candidates: &'a [Candidate],
    files: &BTreeMap<String, String>,
) -> Vec<&'a DepOverride> {
    let Some(lock) = files
        .get("yarn.lock")
        .filter(|lock| crate::formats::yarn::is_berry_lock(lock))
    else {
        return Vec::new();
    };
    let bin_entries = crate::formats::yarn::blocks::berry_bin_entries(lock);
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

/// The npm deps whose yarn classic pin reads the served tarball, one per
/// distinct artifact URL: the project's `yarn.lock` is a classic lock that
/// names the package, the grant carries a sha512, and either the grant has
/// no sha1 for the `resolved` fragment yarn 1 keys its cache slot on
/// (#558), or the lock doesn't pin this artifact yet, so the tarball's own
/// dependencies must be checked against the lock (#591).
/// A lock the project's offline mirror refuses outright (`yarn_outer`: the
/// mirror settings outside the project files) needs none.
pub fn yarn_classic_artifact_targets<'a>(
    candidates: &'a [Candidate],
    files: &BTreeMap<String, String>,
    yarn_outer: &OuterYarnMirror,
) -> Vec<&'a DepOverride> {
    let Some(lock) = files
        .get("yarn.lock")
        .filter(|lock| !crate::formats::yarn::is_berry_lock(lock))
    else {
        return Vec::new();
    };
    if crate::patch::redirect::yarn_classic_hosted_refused(files, yarn_outer) {
        return Vec::new();
    }
    let mut seen = BTreeSet::new();
    candidates
        .iter()
        .map(|c| &c.dep)
        .filter(|dep| dep.ecosystem == "npm" && dep.integrity.sha512.is_some())
        .filter(|dep| {
            classic_locks_registry_copy(lock, &crate::patch::redirect::full_name(dep), &dep.version)
        })
        .filter(|dep| {
            dep.integrity.sha1.is_none() || !lock.contains(&format!("\"{}#", dep.artifact_url))
        })
        .filter(|dep| seen.insert(dep.artifact_url.clone()))
        .collect()
}

/// Whether a classic `lock` has a registry block of `name@version`: the
/// only copy a hosted pin rewrites (a git, `file:`, `link:` or remote
/// tarball copy is skipped by name, so it needs no served tarball). Read
/// by the blocks' real names, as the rewriter does, so `lodash` never
/// matches a `lodash.debounce` block.
fn classic_locks_registry_copy(lock: &str, name: &str, version: &str) -> bool {
    use crate::formats::yarn::blocks::{classic_field, scan_blocks};
    use crate::formats::yarn::patterns::{classic_key_real_name, split_key_patterns};
    use crate::formats::yarn::source::{classic_copy_source, CopySource};
    if !lock.contains(name) {
        return false;
    }
    scan_blocks(lock).iter().any(|block| {
        let patterns = split_key_patterns(&block.key);
        classic_key_real_name(&patterns) == Some(name)
            && classic_field(&block.lines, "version") == Some(version)
            && classic_copy_source(&patterns, classic_field(&block.lines, "resolved"))
                == CopySource::Registry
    })
}

/// Record what the served tarball at `url` yielded: its sha1 on every
/// candidate granted that artifact without one, and its manifest (keyed by
/// URL) for the rewriter.
pub fn record_classic_artifact(
    candidates: &mut [Candidate],
    manifests: &mut BTreeMap<String, String>,
    url: &str,
    artifact: &crate::hosted::npm_manifest::HostedClassicArtifact,
) {
    for candidate in candidates
        .iter_mut()
        .filter(|c| c.dep.artifact_url == url && c.dep.integrity.sha1.is_none())
    {
        candidate.dep.integrity.sha1 = Some(artifact.sha1.clone());
    }
    manifests.insert(url.to_string(), artifact.manifest.clone());
}

/// The skip recorded for an npm dep whose served tarball could not be
/// fetched, did not match its grant's sha512 or had no readable
/// package.json, so its yarn classic pin could not be checked (`detail`
/// redacted by [`redact_artifact_text`]).
pub fn npm_tarball_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!(
            "pkg:npm/{}@{}",
            crate::patch::redirect::full_name(dep),
            dep.version
        ),
        uuid: dep.patch_uuid.clone(),
        reason: "npm_tarball_unavailable".to_string(),
        detail: Some(redact_artifact_text(
            detail,
            &dep.artifact_url,
            &dep.patch_uuid,
        )),
    }
}

/// The skip recorded for an npm dep whose served `package.json` could not
/// be fetched (`detail` redacted by [`redact_artifact_text`]).
pub fn npm_manifest_unavailable(dep: &DepOverride, detail: &str) -> SkippedPatch {
    SkippedPatch {
        purl: format!(
            "pkg:npm/{}@{}",
            crate::patch::redirect::full_name(dep),
            dep.version
        ),
        uuid: dep.patch_uuid.clone(),
        reason: "npm_manifest_unavailable".to_string(),
        detail: Some(redact_artifact_text(
            detail,
            &dep.artifact_url,
            &dep.patch_uuid,
        )),
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

/// The host-dependent inputs of [`rewrite`].
#[derive(Clone)]
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
    /// The yarn 1 config layers outside the project's `.yarnrc` / `.npmrc`,
    /// resolved only beside a classic `yarn.lock` (its offline-mirror
    /// refusal).
    pub yarn_classic_outer: &'a (dyn Fn() -> OuterYarnMirror + Send + Sync),
    /// Run the rewriters on the blocking pool (the disk flow: pure CPU over
    /// every lock text).
    pub blocking: bool,
    /// Uuids of the run's staged vendored→hosted takeovers (wet and dry
    /// runs alike): the caller reverted their vendored wiring in the group
    /// overlay before the rewrite, so the attribution gate never drops
    /// them, and their pin keeps the rewriters' verdict (a takeover the
    /// rewriters do not pin is retracted by the caller and stays vendored).
    /// Empty for the in-memory engine, which takes nothing over.
    pub takeover_uuids: BTreeSet<String>,
    /// The operator's extra patch-server origins (`--patch-server-url`):
    /// the allowlist `vex`, `list`, `rollback`, `remove` and `vendor`
    /// discover with, so the attribution gate sees an existing pin on a
    /// configured server even when this run's grants live on another host.
    /// Empty for the in-memory engine, which has no such knob.
    pub patch_server_origins: Vec<String>,
    /// Lockfile discovery of the project exactly as this rewrite reads it,
    /// made with exactly `patch_server_origins` (the caller's pre-rewrite
    /// discovery, `None` when nothing was discovered or the project may
    /// have changed since). The attribution gate reuses it instead of
    /// discovering again when a pass writes nothing and this run's grants
    /// name no origin that `patch_server_origins` does not already count
    /// (see [`reusable_prior`]): the project it would discover is then the
    /// same, read the same way.
    pub prior_discovery: Option<&'a crate::vex::discover::Discovery>,
}

/// One project's rewrite, ready for the guard, the record fetch and the
/// commit.
#[derive(Debug)]
pub struct Rewritten {
    /// The pre-rewrite candidate texts.
    pub files: BTreeMap<String, String>,
    pub symlinked_reads: Vec<String>,
    pub unreadable_reads: Vec<String>,
    pub undecodable_reads: Vec<String>,
    /// The rewriters' override slice (the candidates' deps).
    pub overrides: Vec<DepOverride>,
    pub rewrite: RewriteResult,
    /// Every file this run writes (text and binary), sorted.
    pub rewritten: Vec<String>,
    /// `(purl, uuid)` of each candidate whose redirect is pinned by the
    /// project's final files, in candidate order.
    pub confirmed: Vec<(String, String)>,
    /// Candidates left out of the rewrite because lockfile discovery could
    /// not attribute the pin they would land (see [`rewrite`]): reported as
    /// skipped, written nowhere.
    pub unattributed: Vec<SkippedPatch>,
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
    /// The attribution gate's discovery of the project as this rewrite
    /// leaves it, when it equals a discovery made with exactly
    /// [`RewriteOptions::patch_server_origins`] (this run's grants name no
    /// other origin). `None` when the gate discovered nothing (no
    /// confirmed candidate) or counted another origin. A caller that
    /// writes exactly [`RewriteResult::files`] and
    /// [`RewriteResult::binary_files`] and nothing else may use it in place
    /// of discovering the written project again (see [`FinalDiscovery`]).
    pub final_discovery: Option<FinalDiscovery>,
}

/// Where [`Rewritten::final_discovery`] lives.
#[derive(Debug)]
pub enum FinalDiscovery {
    /// The pass wrote nothing, and the gate reused the caller's
    /// [`RewriteOptions::prior_discovery`]: still the caller's to read.
    Prior,
    /// A discovery of the project with the pass's writes overlaid (the
    /// project read when the gate ran). Every read the view mediates sees
    /// the overlay, created files included (see
    /// [`DiskSnapshot::overlay`](crate::vendor::lock_inventory::DiskSnapshot::overlay)),
    /// so it equals a discovery of the written disk when every written file
    /// already existed, or when discovery read nothing around the view
    /// (`view_only`), or when each created file is one no such read can
    /// see ([`overlay_creation_is_invisible`]).
    Overlaid {
        discovery: Box<crate::vex::discover::Discovery>,
        /// Discovery read the project only through the overlaid view (no
        /// raw disk read: the vlt store, sbt evidence, a vendored feed).
        view_only: bool,
    },
}

/// Whether CREATING `rel` (a write over no existing regular file) leaves a
/// discovery over the overlaid project equal to one over the written disk:
/// the root config files the install-policy auto-configs create
/// ([`NPMRC_REL`], [`PNPM_WORKSPACE_REL`]), which discovery reads, if at
/// all, by path and never finds by listing a directory.
pub fn overlay_creation_is_invisible(rel: &str) -> bool {
    rel == NPMRC_REL || rel == PNPM_WORKSPACE_REL
}

/// The pnpm-workspace.yaml read, classified for the trust auto-config
/// (see [`read_workspace_for_trust`]), plus whether it is an in-memory
/// symbolic link (absent to the planner, refused by [`guard`]).
fn read_workspace(view: &ProjectView<'_>) -> (std::io::Result<Option<String>>, bool) {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            (
                read_workspace_for_trust(&cwd.join(PNPM_WORKSPACE_REL)),
                false,
            )
        }
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
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            read_npmrc_for_allow_remote(&cwd.join(NPMRC_REL))
        }
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

/// The repo-state.json that carries the pnpmShrinkwrapHash of the Rush lock
/// at `lock_key`: the file beside it. The common lock maps to
/// [`RUSH_REPO_STATE_REL`]; with subspaces enabled each subspace keeps its
/// own, at `common/config/subspaces/<name>/repo-state.json`.
fn rush_repo_state_for_lock(lock_key: &str) -> String {
    match lock_key.rsplit_once('/') {
        Some((dir, _)) => format!("{dir}/repo-state.json"),
        None => "repo-state.json".to_string(),
    }
}

/// Whether the Rush repo-state file `rel` is present (disk: a regular file).
fn rush_repo_state_present(view: &ProjectView<'_>, rel: &str) -> bool {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            cwd.join(rel).is_file()
        }
        ProjectView::Memory(project) => project.contains(rel),
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
/// rewrite.
pub async fn rewrite(
    view: &ProjectView<'_>,
    read: CandidateFiles,
    candidates: &[Candidate],
    python_metadata: BTreeMap<String, String>,
    withheld_from_vlt: &BTreeSet<String>,
    options: RewriteOptions<'_>,
) -> Rewritten {
    // The run must never leave wiring that lockfile discovery — what `vex`,
    // `list`, `rollback`, `remove` and `vendor` read — calls contested. A
    // candidate the rewriters confirm but discovery cannot attribute to one
    // package version (another lock resolving the same version elsewhere, a
    // pin Maven never consumes) would be refused by every later command, so
    // it is dropped and the rest rewritten without it. Each pass drops at
    // least one candidate, so this ends. A staged takeover is never dropped
    // (see [`RewriteOptions::takeover_uuids`]): its vendored wiring is
    // reverted in the overlay, and its pin keeps the rewriters' verdict.
    let exempt: BTreeSet<String> = withheld_from_vlt
        .union(&options.takeover_uuids)
        .cloned()
        .collect();
    let mut kept: Vec<Candidate> = candidates.to_vec();
    let mut unattributed: Vec<SkippedPatch> = Vec::new();
    loop {
        let mut done = rewrite_once(
            view,
            read.clone(),
            &kept,
            python_metadata.clone(),
            withheld_from_vlt,
            options.clone(),
        )
        .await;
        let Gated {
            vetoed,
            lockless,
            discovery,
        } = unattributed_pins(
            view,
            &done,
            &kept,
            &exempt,
            &options.patch_server_origins,
            options.prior_discovery,
        )
        .await;
        if vetoed.is_empty() {
            done.unattributed = unattributed;
            done.rewrite.warnings.extend(lockless);
            done.final_discovery = discovery;
            return done;
        }
        kept.retain(|c| !vetoed.iter().any(|skip| skip.uuid == c.dep.patch_uuid));
        unattributed.extend(vetoed);
    }
}

/// Lockfile discovery over the project as `done` would leave it, read as
/// the management commands read it ([`HostedInventory`]): the skips for
/// the confirmed candidates whose pin would be contested wiring, and a
/// [`REDIRECT_PIN_LOCKLESS`] warning per lockless pin. A lockless NuGet /
/// Cargo pin ([`UnlockedPin`]) is written as before — whether such a pin
/// may be written at all is the open hosted-rollback decision (E45) — but
/// the run says that nothing can manage it until a lockfile exists.
///
/// A deliberate partial redirect keeps its behavior too: a dep whose
/// bundled or user-patched copy the rewriters knowingly left on the
/// registry (`bundled_skipped_uuids`, a yarn `npm:` alias entry in
/// `alias_skipped_entries`, or a bundled copy in vlt's store; all are
/// warned and kept out of the in-run VEX), or one withheld from
/// the vlt rewrite while a sibling lock takes it, and a wet vendored→hosted
/// takeover whose vendored wiring the caller already reverted (both in
/// `exempt`). Which unreachable copies should block a redirect is the
/// copy-source policy (audit B16), not decided here.
///
/// [`HostedInventory`]: crate::patch::redirect::upstream::HostedInventory
/// [`UnlockedPin`]: crate::vex::discover::UnlockedPin
async fn unattributed_pins(
    view: &ProjectView<'_>,
    done: &Rewritten,
    candidates: &[Candidate],
    exempt: &BTreeSet<String>,
    configured: &[String],
    prior: Option<&crate::vex::discover::Discovery>,
) -> Gated {
    if done.confirmed.is_empty() {
        return Gated::default();
    }
    // The management commands' allowlist plus the hosts this run's grants
    // name: a pin on either counts, as it will for them. A grant on
    // Socket's own server or a configured one adds nothing discovery does
    // not already count, so the discovery is then the one `configured`
    // alone makes.
    let foreign = crate::patch::redirect::upstream::foreign_dep_origins(
        candidates.iter().map(|c| &c.dep),
        configured,
    );
    let same_origins = foreign.is_empty();
    let mut origins = configured.to_vec();
    for origin in foreign {
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    let opts = crate::vex::DiscoverOptions {
        patch_server_origins: origins,
    };
    let mut written: Vec<(&str, &[u8])> = Vec::new();
    for (rel, text) in &done.rewrite.files {
        if !crate::patch::redirect::sbt::is_synthetic_key(rel) {
            written.push((rel.as_str(), text.as_bytes()));
        }
    }
    for (rel, bytes) in &done.rewrite.binary_files {
        written.push((rel.as_str(), bytes.as_slice()));
    }
    let reused = reusable_prior(prior, written.is_empty(), same_origins);
    let fresh = if reused.is_some() {
        None
    } else {
        Some(match view.disk_root() {
            None => {
                let ProjectView::Memory(project) = *view else {
                    unreachable!("only a memory view has no disk root")
                };
                let mut after = project.clone();
                for (rel, bytes) in written {
                    let entry = match std::str::from_utf8(bytes) {
                        Ok(text) => crate::vendor::lock_inventory::MemoryEntry::Text(text.into()),
                        Err(_) => crate::vendor::lock_inventory::MemoryEntry::Binary(bytes.into()),
                    };
                    after.insert(rel, entry);
                }
                let discovery = crate::vex::discover::discover_patched_refs_view(
                    ProjectView::Memory(&after),
                    &opts,
                )
                .await;
                (discovery, true)
            }
            Some(root) => {
                // Tracked only to learn whether discovery read around the
                // overlay (see `FinalDiscovery::Overlaid::view_only`).
                let after = crate::vendor::lock_inventory::DiskSnapshot::tracked(root);
                for (rel, bytes) in written {
                    after.overlay(rel, bytes);
                }
                after.begin_recording();
                let discovery = crate::vex::discover::discover_patched_refs_view(
                    ProjectView::Snapshot(&after),
                    &opts,
                )
                .await;
                (discovery, after.end_recording().is_some())
            }
        })
    };
    let discovery = match (reused, &fresh) {
        (Some(prior), _) => prior,
        (None, Some((fresh, _))) => fresh,
        (None, None) => unreachable!("a pass reuses the prior discovery or discovers afresh"),
    };
    // The management commands' own view of the result: an attributable
    // pin, or contested wiring they would refuse around.
    let inventory = crate::patch::redirect::upstream::HostedInventory::of(discovery);
    let attributed: BTreeSet<&str> = inventory.pins.iter().map(|p| p.uuid.as_str()).collect();
    let lockless: Vec<RewriteWarning> = discovery
        .unlocked_pins
        .iter()
        .filter(|pin| {
            !attributed.contains(pin.uuid.as_str())
                && done.confirmed.iter().any(|(_, uuid)| *uuid == pin.uuid)
        })
        .map(|pin| {
            let create = match pin.ecosystem.as_str() {
                "nuget" => "create packages.lock.json (`dotnet restore --use-lock-file`)",
                "cargo" => "create Cargo.lock (`cargo generate-lockfile`)",
                _ => "create the lockfile",
            };
            warning(
                REDIRECT_PIN_LOCKLESS,
                format!(
                    "{}: {} is pinned to patch {} without a lockfile that records its version, \
                     so `vex` cannot attest it and `rollback`, `remove` and `vendor` refuse it \
                     as unattributable; {create} and re-run `socket-patch scan --mode hosted` \
                     to make it manageable",
                    pin.file.display(),
                    pin.name,
                    pin.uuid
                ),
            )
        })
        .collect();
    // Contested wiring (not a lockless pin, see above) is what the run must
    // never leave behind. A pin discovery does not see at all (a file it
    // does not read, such as a pre-2.6 bundler Gemfile the next `bundle
    // install` locks) is no such wiring and keeps the rewriters' verdict.
    let contested: BTreeSet<&str> = inventory
        .contested
        .iter()
        .filter(|c| c.lockless.is_empty())
        .map(|c| c.uuid.as_str())
        .collect();
    // vlt's bundled copies live only in its installed store, which the
    // rewriters never read (the scan warns about them after the writes).
    let vlt_bundled: BTreeSet<String> = match view.disk_root() {
        Some(root) if !contested.is_empty() => crate::vendor::vlt_bundled::bundled_copies(root)
            .await
            .into_keys()
            .collect(),
        _ => BTreeSet::new(),
    };
    let vetoed = done
        .confirmed
        .iter()
        .filter(|(purl, uuid)| {
            !attributed.contains(uuid.as_str())
                && contested.contains(uuid.as_str())
                && !done.rewrite.bundled_skipped_uuids.contains(uuid)
                && !done.rewrite.alias_skipped_entries.contains_key(uuid)
                && !exempt.contains(uuid)
                && !vlt_bundled.contains(&crate::utils::purl_key::canonical_base_purl(purl))
        })
        .map(|(purl, uuid)| {
            let findings: Vec<&str> = discovery
                .diagnostics
                .iter()
                .filter(|d| d.detail.contains(uuid.as_str()) || d.detail.contains(purl.as_str()))
                .map(|d| d.detail.as_str())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let why = if findings.is_empty() {
                String::new()
            } else {
                format!(" ({})", findings.join("; "))
            };
            SkippedPatch {
                purl: purl.clone(),
                uuid: uuid.clone(),
                reason: REDIRECT_UNATTRIBUTABLE.to_string(),
                detail: Some(format!(
                    "the rewrite would wire patch {uuid} for {purl}, but lockfile discovery (what \
                     `vex`, `list`, `rollback` and `vendor` read) cannot attribute that pin to \
                     one package version{why}, so nothing was changed for it; reconcile the \
                     project's lockfiles and re-run"
                )),
            }
        })
        .collect();
    let discovery = match (same_origins, fresh) {
        (false, _) => None,
        (true, None) => Some(FinalDiscovery::Prior),
        (true, Some((fresh, view_only))) => Some(FinalDiscovery::Overlaid {
            discovery: Box::new(fresh),
            view_only,
        }),
    };
    Gated {
        vetoed,
        lockless,
        discovery,
    }
}

/// What [`unattributed_pins`] decided for one pass.
#[derive(Default)]
struct Gated {
    /// The confirmed candidates whose pin would be contested wiring.
    vetoed: Vec<SkippedPatch>,
    /// A [`REDIRECT_PIN_LOCKLESS`] warning per lockless pin.
    lockless: Vec<RewriteWarning>,
    /// The discovery the verdict read, for [`Rewritten::final_discovery`].
    discovery: Option<FinalDiscovery>,
}

/// The caller's pre-rewrite discovery, when it is exactly what the gate
/// would discover: the pass writes nothing (so the project is the one the
/// caller discovered) and the gate's origins (`configured` plus the
/// grants' hosts) count exactly the pins the caller's (`configured` alone)
/// did: `same_origins`, no grant on a host outside Socket's own server and
/// `configured` ([`foreign_dep_origins`]).
///
/// [`foreign_dep_origins`]: crate::patch::redirect::upstream::foreign_dep_origins
fn reusable_prior(
    prior: Option<&crate::vex::discover::Discovery>,
    nothing_written: bool,
    same_origins: bool,
) -> Option<&crate::vex::discover::Discovery> {
    prior.filter(|_| nothing_written && same_origins)
}

/// Warning: a confirmed pin no lockfile records a version for (a lockless
/// NuGet / Cargo redirect), which no later command can attribute.
pub const REDIRECT_PIN_LOCKLESS: &str = "redirect_pin_lockless";

/// `skipped[].reason` of a candidate whose pin lockfile discovery would not
/// attribute (see [`rewrite`]).
pub const REDIRECT_UNATTRIBUTABLE: &str = "redirect_unattributable";

async fn rewrite_once(
    view: &ProjectView<'_>,
    read: CandidateFiles,
    candidates: &[Candidate],
    python_metadata: BTreeMap<String, String>,
    withheld_from_vlt: &BTreeSet<String>,
    options: RewriteOptions<'_>,
) -> Rewritten {
    let CandidateFiles {
        files,
        rush_lock_keys,
        pnpm_member_lock_keys,
        symlinked_reads,
        unreadable_reads,
        undecodable_reads,
        gradle_unreadable,
        gem_refusal,
        pnpm_refusal,
    } = read;
    // The rewriters' override slice — materialized ONCE, after the last
    // candidate filter, so it can never disagree with `candidates`.
    let overrides: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();
    let bun_lockb = bun_lockb_present(view);
    let binary_bun = !bun_text_lock_drives(view) && bun_lockb;
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
    // The yarn config outside the project decides the classic rewriter's
    // offline-mirror refusal too: resolved only beside a classic lock.
    let yarn_outer = if rewrite_overrides.iter().any(|o| o.ecosystem == "npm")
        && files
            .get("yarn.lock")
            .is_some_and(|lock| !crate::patch::redirect::is_berry_lock(lock))
    {
        (options.yarn_classic_outer)()
    } else {
        OuterYarnMirror::default()
    };
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
                &yarn_outer,
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
            &yarn_outer,
        );
        (files, rewrite)
    };
    // The gem files were withheld on purpose: say why, not "no Gemfile".
    if let Some(warning) = gem_refusal {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_gem_no_gemfile");
        rewrite.warnings.push(warning);
    }
    // The pnpm locks were withheld on purpose: say why, not "run `pnpm
    // install`" (which never writes a root lock in either layout).
    if let Some(warning) = pnpm_refusal {
        rewrite.warnings.retain(|w| {
            w.code != "redirect_pnpm_no_lockfile" && w.code != "redirect_npm_no_lockfile"
        });
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
                crate::patch::redirect::rewrite_bun_binary(&bytes, &binary_overrides, &mut rewrite);
                // A pinned default-trusted package loses Bun's default trust
                // (#371); the text rewriter warns the same way.
                for o in &binary_overrides {
                    let name = crate::patch::redirect::full_name(o);
                    if rewrite.confirmed_bun_binary_uuids.contains(&o.patch_uuid)
                        && crate::vendor::bun_lock_text::loses_default_trust(
                            files.get("package.json").map(String::as_str),
                            None,
                            &name,
                        )
                    {
                        rewrite
                            .warnings
                            .push(crate::patch::redirect::bun_default_trust_warning(
                                &name, &o.version,
                            ));
                    }
                }
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
    // a Rush lock and the repo-state file that carries THAT lock's hash is
    // present: it sits beside the lock, so with subspaces enabled each
    // subspace lock pairs with its own subspace's repo-state.json (#714).
    let mut rush_warnings: Vec<RewriteWarning> = Vec::new();
    if rush_lock_keys
        .iter()
        .filter(|key| rewrite.files.contains_key(*key))
        .any(|key| rush_repo_state_present(view, &rush_repo_state_for_lock(key)))
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
        &pnpm_member_lock_keys,
        &rewrite,
        &rush_lock_keys,
        &overrides,
        &options,
    );
    let (npm_warnings, npmrc_config_write) =
        npm_allow_remote(view, &files, &rewrite, &overrides, &options);
    if let Some((text, edit)) = trust_config_write {
        rewrite.files.insert(PNPM_WORKSPACE_REL.to_string(), text);
        // Appended last, after the lock edits it serves. v5 keeps no hosted
        // ledger, so nothing replays these edits; the order is write order.
        rewrite.edits.push(edit);
    }
    if let Some((text, edit)) = npmrc_config_write {
        rewrite.files.insert(NPMRC_REL.to_string(), text);
        // Appended after the lock edits, like the pnpm trust key above.
        rewrite.edits.push(edit);
    }
    let rewritten: Vec<String> = rewrite
        .files
        .keys()
        .chain(rewrite.binary_files.keys())
        .filter(|k| !crate::patch::redirect::sbt::is_synthetic_key(k))
        .cloned()
        .collect();
    let confirmed = confirm(&files, &rewrite, candidates, binary_bun, withheld_from_vlt);
    Rewritten {
        files,
        symlinked_reads,
        unreadable_reads,
        undecodable_reads,
        overrides,
        rewrite,
        rewritten,
        confirmed,
        unattributed: Vec::new(),
        binary_bun,
        rush_warnings,
        pnpm_warnings,
        npm_warnings,
        pnpm_rerun_only,
        workspace_symlinked,
        final_discovery: None,
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
/// ZERO-TOUCH DEFAULT: when this run rewrote a GOVERNING pnpm lock (the
/// root pnpm-lock.yaml, or a workspace member's own lock under
/// `sharedWorkspaceLockfile: false`, #492) and its lockfileVersion is >= 9
/// (5.x/6.0 locks mean pnpm 7/8, which have neither the policy nor the
/// flag and get their own guidance), the run
/// auto-ensures `trustLockfile: true` in pnpm-workspace.yaml. The same
/// auto-config re-engages on a run that spliced NOTHING when a governing v9
/// lock already carries a granted hosted artifact URL (HEAL-ON-RERUN). The
/// key always goes to the root pnpm-workspace.yaml, the only one pnpm reads
/// for every member.
/// pnpm <=10 ignores the key; the per-entry sha512 pin still fails closed
/// on tampered bytes. An explicit user `trustLockfile: <non-true>` is
/// RESPECTED (never flipped), and `--no-trust-lockfile-config` opts out.
/// Rush common/subspace locks (`rush_lock_keys`) are excluded from the
/// write: rush runs pnpm in common/temp with a pnpm-workspace.yaml it
/// generates, which never reads the repo-root one. When every spliced lock
/// is a Rush lock the warning carries the Rush remedy instead of the
/// pnpm-only one (#713); a run that also spliced a non-Rush pnpm lock keeps
/// the generic text plus a Rush note. The warning names the host(s) the
/// lock now points at (they follow --api-url).
#[allow(clippy::too_many_arguments)]
fn pnpm_trust(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    member_lock_keys: &[String],
    rewrite: &RewriteResult,
    rush_lock_keys: &[String],
    overrides: &[DepOverride],
    options: &RewriteOptions<'_>,
) -> (Vec<RewriteWarning>, ConfigWrite, bool, bool) {
    let mut pnpm_warnings: Vec<RewriteWarning> = Vec::new();
    let mut trust_config_write: ConfigWrite = None;
    let mut pnpm_rerun_only = false;
    let mut workspace_symlinked = false;
    // pnpm locks spliced THIS run (any depth — the rewriter is
    // basename-generalized).
    let (spliced_keys, mut pnpm_lock_texts): (Vec<&String>, Vec<&String>) = rewrite
        .files
        .iter()
        .filter(|(key, _)| {
            std::path::Path::new(key)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| matches!(name, "pnpm-lock.yaml" | "shrinkwrap.yaml"))
        })
        .unzip();
    // Rush locks spliced this run. The heal and takeover roots below are
    // only ever governing locks, never a Rush one.
    let mut spliced_rush = spliced_keys
        .iter()
        .filter(|key| rush_lock_keys.contains(key))
        .count();
    // The locks pnpm installs the project from: the root lock, plus each
    // member's own under `sharedWorkspaceLockfile: false` (#492). A Rush
    // lock is never one: rush installs it from common/temp.
    let governing: Vec<&str> = std::iter::once("pnpm-lock.yaml")
        .chain(member_lock_keys.iter().map(String::as_str))
        .filter(|key| !rush_lock_keys.iter().any(|rush| rush == key))
        .collect();
    // HEAL-ON-RERUN: a governing v9 lock that ALREADY carries a granted
    // hosted artifact URL (spliced by an earlier run) still plans the trust
    // config even though this run spliced nothing — so a project that
    // missed the config once (opted-out first run, or a crash between the
    // lock write and the workspace write) is healed by simply re-running
    // the scan. An AlreadyTrue workspace keeps the re-run a byte-stable
    // no-op.
    let heal_locks: Vec<&String> = governing
        .iter()
        .filter_map(|key| {
            pnpm_heal_root(rewrite.files.contains_key(*key), files.get(*key), overrides)
        })
        .collect();
    let spliced_pnpm_locks = pnpm_lock_texts.len();
    pnpm_lock_texts.extend(heal_locks.iter().copied());
    // HEAL-ON-RERUN for Rush: a common/subspace v9 lock an earlier run
    // already redirected splices nothing now, but its `rush install` still
    // needs the Rush trust remedy (#713) — nothing persists it, so it is
    // re-issued on every run. Same gate as the governing heal; never
    // configured.
    for key in rush_lock_keys {
        if let Some(text) =
            pnpm_heal_root(rewrite.files.contains_key(key), files.get(key), overrides)
        {
            pnpm_lock_texts.push(text);
            spliced_rush += 1;
        }
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
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    let server = if hosts.is_empty() {
        "the hosted patch server".to_string()
    } else {
        format!("the hosted patch server ({})", hosts.join(", "))
    };
    // Governing-lock gate: only a governing lock (never a Rush one) at
    // lockfileVersion >= 9 gets the auto-config — spliced this run, or
    // detected already-redirected (heal path).
    let is_v9 = |text: &String| pnpm_lock_version_major(text).is_some_and(|major| major >= 9);
    let governing_lock_v9 = heal_locks.iter().copied().any(is_v9)
        || governing
            .iter()
            .filter_map(|key| rewrite.files.get(*key))
            .any(is_v9);
    // Every touched pnpm lock is a KNOWN legacy (5.x/6.0) format, where
    // `--trust-lockfile` is rejected as an unknown option. An unparseable
    // version stays on the manual guidance: never claim "no trust step
    // needed" for a lock whose era is unknown.
    let all_locks_legacy = pnpm_lock_texts.iter().all(|text| {
        pnpm_lock_version_major(text).is_some_and(|major| major < 9)
            || pnpm_is_shrinkwrap_lock(text)
    });
    let rush_only = spliced_rush > 0 && spliced_rush == pnpm_lock_texts.len();
    let detail = if all_locks_legacy {
        pnpm_trust_legacy_detail(&server)
    } else if rush_only {
        pnpm_trust_rush_detail(&server)
    } else if !governing_lock_v9 || !options.trust_lockfile_config {
        pnpm_trust_manual_guidance(&server)
    } else if let Some(root_file) = governing_workspace(view) {
        // A workspace member with its own lock: pnpm reads `trustLockfile`
        // only from the workspace root's file, and a nested one would be
        // ignored (#880). The governing-root pre-check refused every root
        // file but these two, so nothing is written here.
        let root_file = root_file.display().to_string();
        match read_workspace_for_trust(std::path::Path::new(&root_file))
            .ok()
            .flatten()
            .map(|text| plan_workspace_trust(Some(&text)))
        {
            Some(TrustPlan::AlreadyTrue) => {
                pnpm_rerun_only = spliced_pnpm_locks == 0;
                pnpm_trust_already_true_detail(&server, &root_file)
            }
            Some(TrustPlan::UserSet(value)) => {
                pnpm_trust_user_set_detail(&server, &root_file, &value)
            }
            _ => pnpm_trust_manual_guidance(&server),
        }
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
        // No workspace file and a project pinned to pnpm 9.0–10.4: creating
        // one would make it a root-only workspace those releases refuse
        // `pnpm add` in, for a key they never read (#734).
        let pinned_pre_10_5 = match &workspace {
            Ok(None) if !symlinked => root_only_workspace_breaks_add(view),
            _ => None,
        };
        match workspace {
            Ok(None) if pinned_pre_10_5.is_some() => pnpm_trust_not_needed_detail(
                &server,
                pinned_pre_10_5.as_deref().unwrap_or_default(),
                options.dry_run,
            ),
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
                    let detail = pnpm_trust_already_true_detail(&server, PNPM_WORKSPACE_REL);
                    // The root-only scaffold an earlier run created (4.x and
                    // early v5 did so whatever the pnpm), in a project pinned
                    // to a pnpm that refuses `pnpm add` there (#734).
                    match ws_existing
                        .as_deref()
                        .filter(|text| is_trust_scaffold(text))
                        .and_then(|_| root_only_workspace_breaks_add(view))
                    {
                        Some(pins) => format!("{detail} {}", pnpm_scaffold_breaks_add_note(&pins)),
                        None => detail,
                    }
                }
                TrustPlan::UserSet(value) => {
                    pnpm_trust_user_set_detail(&server, PNPM_WORKSPACE_REL, &value)
                }
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
    // Rush keeps its own store under common/temp and the Rush detail
    // carries its own reinstall advice; the legacy text is right for Rush on
    // pnpm 7/8 as well, so it keeps the generic tail.
    let message = if rush_only && !all_locks_legacy {
        format!("{detail}.")
    } else {
        let rush_note = if spliced_rush > 0 && !all_locks_legacy {
            format!(" {PNPM_TRUST_RUSH_MIXED_NOTE}.")
        } else {
            String::new()
        };
        format!(
            "{}. After a lock-only change, existing node_modules or a warm pnpm store \
             can still contain upstream files. For a reliable reinstall, use a clean \
             node_modules tree and an empty store with \
             `pnpm install --frozen-lockfile --store-dir <new-empty-directory>`\
             {store_note}. Do not rely on `--force`: some versions re-resolve the \
             upstream artifact. Run `socket-patch vex` after installation to verify \
             the patched files.{rush_note}",
            detail.trim_end_matches('.')
        )
    };
    pnpm_warnings.push(warning("redirect_pnpm_trust_lockfile", message));
    (
        pnpm_warnings,
        trust_config_write,
        pnpm_rerun_only,
        workspace_symlinked,
    )
}

/// The trust detail for a settings file (`file`) that already carries
/// `trustLockfile: true`.
fn pnpm_trust_already_true_detail(server: &str, file: &str) -> String {
    format!(
        "{}, and {file} already carries `trustLockfile: true` — keep it committed \
         alongside the lock; installs need no extra flags. \
         {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

/// Whether a pnpm-workspace.yaml is exactly the root-only scaffold the
/// trust auto-config creates ([`plan_workspace_trust`] with no file), in
/// either line ending.
fn is_trust_scaffold(text: &str) -> bool {
    let TrustPlan::Create(scaffold) = plan_workspace_trust(None) else {
        return false;
    };
    text == scaffold || text == scaffold.replace('\n', "\r\n")
}

/// The note added when a project pinned to pnpm 9.0–10.4 (`pins`, as
/// prose) still carries the root-only scaffold (#734).
fn pnpm_scaffold_breaks_add_note(pins: &str) -> String {
    format!(
        "Note: {PNPM_WORKSPACE_REL} is the root-only file an earlier socket-patch run \
         created, but the project's pnpm ({pins}) does not read `trustLockfile`, and \
         in a root-only workspace pnpm 9.0–10.4 refuse `pnpm add <pkg>` \
         (ERR_PNPM_ADDING_TO_ROOT). Delete {PNPM_WORKSPACE_REL} (re-run after \
         upgrading to pnpm >= 11 to recreate it), or add dependencies with \
         `pnpm add -w <pkg>`."
    )
}

/// The trust detail for a settings file (`file`) whose explicit
/// `trustLockfile: <value>` was respected.
fn pnpm_trust_user_set_detail(server: &str, file: &str, value: &str) -> String {
    format!(
        "{}. {file} explicitly sets `trustLockfile: {value}`, which was respected \
         and left untouched — install with `pnpm install --trust-lockfile`, or set \
         `trustLockfile: true` yourself so every install accepts the patched \
         artifacts. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
        pnpm_trust_policy_preamble(server),
    )
}

/// The pnpm pins of a project with no pnpm-workspace.yaml, when every one
/// is a release that refuses `pnpm add` in a root-only workspace (see
/// [`pnpm_root_only_workspace_breaks_add`]). Reads the root package.json
/// and the installed `node_modules/.modules.yaml`, both advisory: FIFO-safe
/// on disk, and an in-memory entry that is not text counts as absent.
fn root_only_workspace_breaks_add(view: &ProjectView<'_>) -> Option<String> {
    let read = |rel: &str| match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            crate::utils::fs::read_regular_to_string_sync(&cwd.join(rel)).ok()
        }
        ProjectView::Memory(project) if !project.is_symlink(rel) => match project.get(rel) {
            Some(MemoryEntry::Text(text)) => Some(text.to_string()),
            _ => None,
        },
        ProjectView::Memory(_) => None,
    };
    pnpm_root_only_workspace_breaks_add(
        read(crate::hosted::memory::select::NPM_MANIFEST_REL).as_deref(),
        read("node_modules/.modules.yaml").as_deref(),
    )
}

/// The ancestor `pnpm-workspace.yaml` governing a disk project's pnpm
/// settings (see [`governing_workspace_file`]); an in-memory project has
/// no ancestors.
fn governing_workspace(view: &ProjectView<'_>) -> Option<std::path::PathBuf> {
    match view {
        ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
            let cwd = view.disk_root().expect("a disk view has a root");
            governing_workspace_file(cwd)
        }
        ProjectView::Memory(_) => None,
    }
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
/// specs, gated by `allow-file` (default `all`), not `allow-remote` — an
/// explicit refusing `allow-file` is the vendored flow's own advisory
/// (`vendor_npm_allow_file`, #969).
fn npm_allow_remote(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    rewrite: &RewriteResult,
    overrides: &[DepOverride],
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
    let npmrc = read_npmrc(view);
    let outer = (options.npm_outer)();
    let detail = match &npmrc {
        // Opt-out still reports an explicit / already-set value truthfully;
        // only the WRITE is suppressed.
        Ok(existing) => match plan_npmrc_allow_remote_with(existing.as_deref(), &outer) {
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
        },
        Err(why) => npm_allow_remote_unreadable_detail(&npm_hosts, why),
    };
    npm_warnings.push(warning("redirect_npm_allow_remote", detail));
    // #812: npm >= 8's `replace-registry-host` (`always`, or the pinned
    // host itself) rewrites the hosted pins to the configured registry,
    // so every install 404s. The setting is the user's, so it is reported
    // (from whichever layer sets it), never overridden.
    let project = npmrc.as_ref().ok().and_then(|t| t.as_deref());
    if let Some((value, source)) = effective_replace_registry_host(project, &outer) {
        let blocked: Vec<&str> = npm_hosts
            .iter()
            .copied()
            .filter(|host| replace_registry_host_rewrites(&value, host))
            .collect();
        if !blocked.is_empty() {
            npm_warnings.push(warning(
                NPM_REPLACE_REGISTRY_HOST_CODE,
                npm_replace_registry_host_detail(&blocked, &value, &source),
            ));
        }
    }
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
        .filter(|(name, _)| !crate::patch::redirect::sbt::is_synthetic_key(name))
        .map(|(name, content)| (name.as_str(), rewrite.files.get(name).unwrap_or(content)))
        .chain(
            rewrite
                .files
                .iter()
                .filter(|(name, _)| !files.contains_key(*name) && !is_npm_manifest(name))
                .map(|(name, content)| (name.as_str(), content)),
        )
        .filter(|(name, _)| !crate::patch::redirect::sbt::is_generated_file(name))
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
            if rewrite.refused_vlt_uuids.contains(uuid)
                || rewrite.refused_bun_uuids.contains(uuid)
                || rewrite.refused_npm_uuids.contains(uuid)
            {
                return ProbeStep::Decided(false);
            }
            // An sbt build's Maven pins are confirmed by the sbt rewriter's
            // own report: the generated file names the index URL whether or
            // not the pin was verified against the build's evidence (so it
            // is never a substring proof). Beside a `pom.xml` the Maven
            // rewriter's own landing also confirms. Beside a Gradle build
            // whose planner decided the patch, both builds must pin it
            // (each build pins on its own, as a pom beside Gradle must):
            // the Gradle arm below confirms an sbt-confirmed uuid, and a
            // uuid the sbt rewriter refused is never confirmed by the
            // Gradle planner alone — the sbt build still loads upstream.
            if purl.starts_with("pkg:maven/") {
                if let Some(sbt_only) = crate::patch::redirect::sbt::maven_confirmation(files) {
                    let refused_by_sbt = rewrite.refused_sbt_uuids.contains(uuid);
                    if refused_by_sbt && rewrite.gradle_uuids.contains(uuid) {
                        return ProbeStep::Decided(false);
                    }
                    let by_sbt = rewrite.confirmed_sbt_uuids.contains(uuid) && !refused_by_sbt;
                    let gradle_decides = by_sbt && rewrite.gradle_uuids.contains(uuid);
                    if (by_sbt || sbt_only) && !gradle_decides {
                        return ProbeStep::Decided(by_sbt);
                    }
                }
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
            // A yarn classic lock beside an offline mirror installs the
            // upstream mirror tarball whatever `resolved` says.
            if rewrite.refused_yarn_classic_uuids.contains(uuid) {
                return ProbeStep::Decided(false);
            }
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
    // Read only beside a classic yarn.lock, for its offline-mirror gate.
    if rel == crate::patch::redirect::YARNRC_REL || rel == NPMRC_REL {
        return Some("npm");
    }
    let base = rel.rsplit('/').next().unwrap_or(rel);
    // A legacy Gradle lock (`gradle/dependency-locks/<conf>.lockfile`).
    if base.ends_with(".lockfile") {
        return Some("maven");
    }
    (crate::utils::python_lock::is_python_lock_name(base) || base.ends_with(".py"))
        .then_some("pypi")
}

/// A file only the hosted Gradle planner reads or writes: a settings or
/// build script, a dependency lock, the verification metadata, the wrapper
/// properties, or the planner's own owned files.
fn is_gradle_owned_file(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base.ends_with(".gradle")
        || base.ends_with(".gradle.kts")
        || base.ends_with(".lockfile")
        || rel == "gradle/verification-metadata.xml"
        || rel == "gradle/wrapper/gradle-wrapper.properties"
        || rel.starts_with(".socket/gradle/")
}

/// The [`guard`]'s non-UTF-8 rule on its own (#721): the first of
/// `undecodable` (a [`CandidateFiles::undecodable_reads`]) whose ecosystem
/// has a candidate refuses the run. The vendored→hosted takeover runs it
/// before reverting anything, so a refusal never strands a reverted purl.
pub fn undecodable_guard(undecodable: &[String], candidates: &[Candidate]) -> Option<Refusal> {
    undecodable
        .iter()
        .find(|rel| {
            // The root manifest is read strictly only as a yarn berry
            // rewrite target (its `resolutions`); advisory reads never
            // record it, so here it is always an npm rewrite target. A root
            // Gradle script left here (no readable build beside it) may be
            // the build itself, which only maven candidates could patch.
            let eco = file_ecosystem(rel)
                .or((rel.as_str() == "package.json").then_some("npm"))
                .or(crate::vendor::jvm::layout::GRADLE_ROOT_FILES
                    .contains(&rel.as_str())
                    .then_some("maven"));
            eco.is_some_and(|eco| candidates.iter().any(|c| c.dep.ecosystem == eco))
        })
        .map(|rel| undecodable_refusal(rel))
}

/// SYMLINK GUARD — fail-closed, whole rewrite, before any write (hosted
/// rewrites are transactional). The writer stages next to
/// the path and renames over it, which REPLACES a symbolic link with a
/// detached regular copy: the link target goes stale and a revert restores
/// bytes but never the link. Applies to every ecosystem's files and to dry
/// runs, so a dry run predicts the refusal.
///
/// On disk and in memory: a candidate file that is not UTF-8 text, when a
/// candidate of its ecosystem could rewrite it (#721).
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
            .filter(|k| !crate::patch::redirect::sbt::is_synthetic_key(k))
    };
    if let Some(linked) = written().find(|k| view.is_symlink(k)) {
        return Some(symlink_refusal(linked));
    }
    if let Some(refusal) = undecodable_guard(&done.undecodable_reads, candidates) {
        return Some(refusal);
    }
    let candidate_ecosystems: BTreeSet<&str> = candidates
        .iter()
        .map(|c| c.dep.ecosystem.as_str())
        .collect();
    let ProjectView::Memory(project) = view else {
        return None;
    };
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

    const GRANT: &str = "GRANTTOKEN0123";
    const PATCH_UUID: &str = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";

    fn grant_dep(ecosystem: &str, artifact_url: String) -> DepOverride {
        DepOverride {
            ecosystem: ecosystem.into(),
            name: "left-pad".into(),
            namespace: None,
            version: "1.3.0".into(),
            token: GRANT.into(),
            patch_uuid: PATCH_UUID.into(),
            artifact_url,
            registry_override: None,
            integrity: crate::patch::redirect::Integrity::default(),
        }
    }

    /// The hosted skip details reach `--json`: neither the grant token nor
    /// any userinfo survives, however reqwest re-renders the URL (a
    /// trailing `/`, a different quoting) and under whatever root the
    /// server serves it (a custom `--api-url` with no `/patch/` level).
    #[test]
    fn hosted_skip_details_never_carry_the_grant_token() {
        for (url, uuid) in [
            (
                format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{GRANT}/{PATCH_UUID}/left-pad-1.3.0.tgz"),
                PATCH_UUID,
            ),
            (
                format!("https://u:pw@api.corp.example/serve/{GRANT}/{PATCH_UUID}/left-pad-1.3.0.tgz"),
                PATCH_UUID,
            ),
            // A non-canonical patch id: the shape-based redactor cannot
            // tell its level is a uuid, the dep can.
            (
                format!("https://patch.socket.dev/patch/npm/left-pad/1.3.0/{GRANT}/patch-42/x.tgz"),
                "patch-42",
            ),
        ] {
            let mut dep = grant_dep("npm", url.clone());
            dep.patch_uuid = uuid.into();
            let detail = format!(
                "error sending request for url ({url}?x=1): connection refused (proxy https://p:pw@proxy:3128)"
            );
            for skip in [
                npm_manifest_unavailable(&dep, &detail),
                wheel_metadata_unavailable(&dep, &detail),
            ] {
                let got = skip.detail.unwrap();
                assert!(!got.contains(GRANT), "{url}: {got}");
                assert!(!got.contains("u:pw") && !got.contains("p:pw"), "{got}");
                assert!(got.contains("connection refused"), "{got}");
            }
        }
        let dep = grant_dep("npm", format!("https://h/serve/{GRANT}/{PATCH_UUID}/a.tgz"));
        assert_eq!(
            redact_artifact_text("no url here", &dep.artifact_url, &dep.patch_uuid),
            "no url here"
        );
    }

    fn reference(value: serde_json::Value) -> PackageVendorResult {
        serde_json::from_value(value).unwrap()
    }

    /// #558 review: the served tarball is fetched only for a lock that
    /// really locks a registry copy of the package, read by block names
    /// (`lodash` is not `lodash.debounce`) and copy source (a git or
    /// `file:` copy is never pinned).
    #[test]
    fn classic_registry_copy_is_matched_by_block_name_and_source() {
        let lock = "# yarn lockfile v1\n\n\
                    lodash.debounce@^4.0.8:\n  version \"4.17.21\"\n  \
                    resolved \"https://registry.yarnpkg.com/lodash.debounce/-/x.tgz#aa\"\n\n\
                    left-pad@git+https://github.com/x/left-pad.git:\n  version \"1.3.0\"\n  \
                    resolved \"git+https://github.com/x/left-pad.git#abc\"\n\n\
                    is-odd@^3.0.0:\n  version \"3.0.1\"\n  \
                    resolved \"https://registry.yarnpkg.com/is-odd/-/is-odd-3.0.1.tgz#bb\"\n";
        assert!(!classic_locks_registry_copy(lock, "lodash", "4.17.21"));
        assert!(!classic_locks_registry_copy(lock, "left-pad", "1.3.0"));
        assert!(!classic_locks_registry_copy(lock, "is-odd", "3.0.0"));
        assert!(classic_locks_registry_copy(lock, "is-odd", "3.0.1"));
        assert!(classic_locks_registry_copy(
            lock,
            "lodash.debounce",
            "4.17.21"
        ));
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
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
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

    /// #721: a candidate file that is not UTF-8 (a UTF-16 requirements.txt,
    /// which pip reads) is refused by name, on disk and in memory alike,
    /// when a candidate of its ecosystem could rewrite it, instead of being
    /// treated as absent (exit 0, nothing pinned, no diagnostic).
    #[tokio::test]
    async fn an_undecodable_candidate_file_refuses_its_ecosystem() {
        let purl = "pkg:pypi/six@1.16.0";
        let uuid = "u-721";
        let mut refs = HashMap::new();
        refs.insert(
            uuid.to_string(),
            reference(serde_json::json!({
                "status": "granted",
                "url": format!("https://patch.example/patch/pypi/six/1.16.0/tok/{uuid}/six-1.16.0-py2.py3-none-any.whl"),
                "purl": purl,
                "artifacts": [{"kind": "tarball", "url": null, "integrity": {"sha256": "ab"}}],
                "registryOverride": null
            })),
        );
        let selected = vec![(purl.to_string(), uuid.to_string())];
        let mut skipped = Vec::new();
        let candidates = build_candidates(&selected, &refs, &mut skipped);
        assert_eq!(candidates.len(), 1, "{skipped:?}");
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                "idna==3.7\r\nsix==1.16.0\r\n"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            )
            .collect();
        let outer = OuterAllowRemote::default;
        let options = || RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("requirements.txt"), &utf16).unwrap();
        let mut memory = MemoryProject::new();
        memory.insert(
            "requirements.txt",
            MemoryEntry::Binary(utf16.clone().into()),
        );
        for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
            let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
            assert_eq!(read.undecodable_reads, vec!["requirements.txt"]);
            let done = rewrite(
                &view,
                read,
                &candidates,
                BTreeMap::new(),
                &BTreeSet::new(),
                options(),
            )
            .await;
            let refusal = guard(&view, &done, &candidates).expect("refused");
            assert_eq!(refusal.code, UNREADABLE_REFUSAL);
            assert!(
                refusal.message.contains("requirements.txt") && refusal.message.contains("UTF-8"),
                "{}",
                refusal.message
            );

            // Another ecosystem's run is not blocked by it.
            let (cargo_selected, cargo_refs) = cargo_reference("u-2");
            let cargo = build_candidates(&cargo_selected, &cargo_refs, &mut Vec::new());
            let read = read_candidate_files(&view, &BTreeSet::new(), &cargo).await;
            let done = rewrite(
                &view,
                read,
                &cargo,
                BTreeMap::new(),
                &BTreeSet::new(),
                options(),
            )
            .await;
            assert!(guard(&view, &done, &cargo).is_none());
        }
    }

    /// #721 review: beside a yarn berry lock the root `package.json` is a
    /// rewrite target (its `resolutions`), so a non-UTF-8 one refuses the
    /// run instead of being taken for absent. Beside an npm lock it is
    /// advisory only and never refuses.
    #[tokio::test]
    async fn a_non_utf8_berry_manifest_refuses_the_npm_run() {
        use crate::patch::redirect::Integrity;
        let candidates = vec![Candidate {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: "left-pad".into(),
                namespace: None,
                version: "1.3.0".into(),
                token: "tok".into(),
                patch_uuid: "uuid".into(),
                artifact_url:
                    "https://patch.socket.dev/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz"
                        .into(),
                registry_override: None,
                integrity: Integrity::default(),
            },
        }];
        let berry = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\"left-pad@npm:^1.3.0\":\n  \
                     version: 1.3.0\n  resolution: \"left-pad@npm:1.3.0\"\n";
        let latin1: &[u8] = b"{\"name\": \"Andr\xe9\"}\n";
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("yarn.lock"), berry).unwrap();
        std::fs::write(tmp.path().join("package.json"), latin1).unwrap();
        let view = ProjectView::Disk(tmp.path());
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert_eq!(read.undecodable_reads, vec!["package.json"]);
        let refusal = undecodable_guard(&read.undecodable_reads, &candidates).expect("refused");
        assert_eq!(refusal.code, UNREADABLE_REFUSAL);

        // Beside an npm lock the manifest is advisory: never refused.
        std::fs::remove_file(tmp.path().join("yarn.lock")).unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            "{\"lockfileVersion\": 3, \"packages\": {}}\n",
        )
        .unwrap();
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        assert!(
            read.undecodable_reads.is_empty(),
            "{:?}",
            read.undecodable_reads
        );
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

    /// The grant token and patch uuid of the engine fixtures' hosted urls:
    /// real uuids, so lockfile discovery recognizes the pins the rewrite
    /// lands (the engine keeps only the ones it attributes).
    const FIXTURE_TOKEN: &str = "11111111-1111-4111-8111-111111111111";
    const FIXTURE_UUID: &str = "77777777-7777-4777-8777-777777777777";

    fn left_pad_url() -> String {
        format!("https://patch.test/{FIXTURE_TOKEN}/{FIXTURE_UUID}/left-pad-1.3.0.tgz")
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
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: left_pad_url(),
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
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = vec![left_pad_candidate()];
        let read = read_candidate_files(view, unreadable, &candidates).await;
        let done = rewrite(
            view,
            read.clone(),
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
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
                .is_some_and(|lock| lock.contains(&left_pad_url()))
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

    const LEFT_PAD_V9_LOCK: &str = "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:
  left-pad@1.3.0:
    resolution: {integrity: sha512-UPSTREAM==}

snapshots:
  left-pad@1.3.0: {}
";

    #[test]
    fn rush_repo_state_pairs_with_the_lock_beside_it() {
        assert_eq!(
            rush_repo_state_for_lock(RUSH_COMMON_LOCK_REL),
            RUSH_REPO_STATE_REL
        );
        assert_eq!(
            rush_repo_state_for_lock("common/config/subspaces/tools/pnpm-lock.yaml"),
            "common/config/subspaces/tools/repo-state.json"
        );
    }

    fn pnpm_trust_detail(done: &Rewritten) -> &str {
        done.pnpm_warnings
            .iter()
            .find(|w| w.code == "redirect_pnpm_trust_lockfile")
            .map(|w| w.detail.as_str())
            .expect("redirect_pnpm_trust_lockfile")
    }

    /// #713: a run that spliced only Rush locks gets the Rush remedy (the
    /// env var rush forwards, the pnpm 11 experiment, `rush purge`), never
    /// the pnpm-only one, and writes no workspace file. The same lock at the
    /// repo root still plans the trustLockfile write, and a run that spliced
    /// both keeps the generic text plus the Rush note.
    #[tokio::test]
    async fn issue_713_rush_locks_get_the_rush_trust_remedy() {
        let mut rush = MemoryProject::new();
        rush.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        rush.insert_text(RUSH_COMMON_LOCK_REL, LEFT_PAD_V9_LOCK);
        let (read, done) = npm_rewrite(&ProjectView::Memory(&rush), &BTreeSet::new()).await;
        assert_eq!(read.rush_lock_keys, [RUSH_COMMON_LOCK_REL]);
        assert!(done.rewrite.files.contains_key(RUSH_COMMON_LOCK_REL));
        assert!(!done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("pnpm_config_trust_lockfile=true rush install"),
            "{detail}"
        );
        assert!(
            detail.contains("usePnpmFrozenLockfileForRushInstall"),
            "{detail}"
        );
        assert!(detail.contains("rush purge"), "{detail}");
        assert!(
            !detail.contains("pnpm install --trust-lockfile"),
            "{detail}"
        );
        assert!(!detail.contains("--store-dir"), "{detail}");

        let mut root = MemoryProject::new();
        root.insert_text("pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
        let (_, done) = npm_rewrite(&ProjectView::Memory(&root), &BTreeSet::new()).await;
        assert!(done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
        assert!(!pnpm_trust_detail(&done).contains("rush"));

        let mut mixed = rush.clone();
        mixed.insert_text("pnpm-lock.yaml", LEFT_PAD_V9_LOCK);
        let (_, done) = npm_rewrite(&ProjectView::Memory(&mixed), &BTreeSet::new()).await;
        assert!(done.rewrite.files.contains_key(RUSH_COMMON_LOCK_REL));
        let detail = pnpm_trust_detail(&done);
        assert!(detail.contains("--store-dir"), "{detail}");
        assert!(detail.contains(PNPM_TRUST_RUSH_MIXED_NOTE), "{detail}");
    }

    /// #713 HEAL-ON-RERUN: a Rush lock an earlier run already redirected
    /// splices nothing on a re-run, yet its `rush install` still needs the
    /// Rush remedy — the re-run re-issues it (and still writes nothing).
    #[tokio::test]
    async fn issue_713_rerun_on_a_redirected_rush_lock_keeps_the_rush_remedy() {
        let mut first = MemoryProject::new();
        first.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        first.insert_text(RUSH_COMMON_LOCK_REL, LEFT_PAD_V9_LOCK);
        let (_, done) = npm_rewrite(&ProjectView::Memory(&first), &BTreeSet::new()).await;
        let redirected = done.rewrite.files[RUSH_COMMON_LOCK_REL].clone();

        let mut rerun = MemoryProject::new();
        rerun.insert_text("rush.json", r#"{ "rushVersion": "5.100.0" }"#);
        rerun.insert_text(RUSH_COMMON_LOCK_REL, redirected.as_str());
        let (_, done) = npm_rewrite(&ProjectView::Memory(&rerun), &BTreeSet::new()).await;
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(!done.pnpm_rerun_only);
        let detail = pnpm_trust_detail(&done);
        assert!(
            detail.contains("pnpm_config_trust_lockfile=true rush install"),
            "{detail}"
        );
        assert!(
            !detail.contains("pnpm install --trust-lockfile"),
            "{detail}"
        );
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
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: format!(
                    "https://patch.test/{FIXTURE_TOKEN}/{FIXTURE_UUID}/is-number-7.0.0.tgz"
                ),
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
                yarn_classic_outer: &OuterYarnMirror::default,
                blocking: false,
                takeover_uuids: Default::default(),
                patch_server_origins: Vec::new(),
                prior_discovery: None,
            };
            let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
            assert!(read.files.contains_key("package.json"));
            let done = rewrite(
                &view,
                read,
                &candidates,
                BTreeMap::new(),
                &BTreeSet::new(),
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
                assert!(done.rewrite.bundled_skipped_uuids.contains(FIXTURE_UUID));
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

    /// REGRESSION (#371), binary lock: a default-trusted package pinned to
    /// its hosted URL in a `bun.lockb` loses Bun 1.3.5+'s default trust, so
    /// its install scripts are silently skipped; the run says so unless the
    /// root manifest declares `trustedDependencies`. The fixture is real Bun
    /// 1.4.2 output: `simple-git-hooks` is on the default list, `is-number`
    /// is not.
    #[tokio::test]
    async fn issue_371_bun_lockb_default_trusted_package_warns_that_trust_is_lost() {
        use crate::patch::redirect::Integrity;
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/bun-lockb-trusted");
        let candidate = |name: &str, version: &str, uuid: &str| Candidate {
            purl: format!("pkg:npm/{name}@{version}"),
            dep: DepOverride {
                ecosystem: "npm".into(),
                name: name.into(),
                namespace: None,
                version: version.into(),
                token: "tok".into(),
                patch_uuid: uuid.into(),
                artifact_url: format!("https://patch.test/{name}-{version}.tgz"),
                registry_override: None,
                integrity: Integrity {
                    sha512: Some(format!("sha512-{}==", "A".repeat(86))),
                    ..Default::default()
                },
            },
        };
        let candidates = vec![
            candidate("simple-git-hooks", "2.11.1", "uuid-hooks"),
            candidate("is-number", "7.0.0", "uuid-isn"),
        ];
        let manifest = std::fs::read_to_string(fixture.join("package.json")).unwrap();
        let declared = manifest.replacen(
            "\"private\": true,",
            "\"private\": true,\n  \"trustedDependencies\": [\"simple-git-hooks\"],",
            1,
        );
        assert_ne!(declared, manifest);
        for trusted in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::copy(fixture.join("bun.lockb"), tmp.path().join("bun.lockb")).unwrap();
            std::fs::write(
                tmp.path().join("package.json"),
                if trusted { &declared } else { &manifest },
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
                yarn_classic_outer: &OuterYarnMirror::default,
                blocking: false,
                takeover_uuids: Default::default(),
                patch_server_origins: Vec::new(),
                prior_discovery: None,
            };
            let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
            let done = rewrite(
                &view,
                read,
                &candidates,
                BTreeMap::new(),
                &BTreeSet::new(),
                options,
            )
            .await;
            assert!(
                done.rewrite.binary_files.contains_key("bun.lockb"),
                "{:?}",
                done.rewrite.warnings
            );
            assert_eq!(done.confirmed.len(), 2, "{:?}", done.confirmed);
            let lost: Vec<&RewriteWarning> = done
                .rewrite
                .warnings
                .iter()
                .filter(|w| w.code == "redirect_bun_default_trust_lost")
                .collect();
            if trusted {
                assert!(lost.is_empty(), "{:?}", done.rewrite.warnings);
            } else {
                assert_eq!(lost.len(), 1, "{:?}", done.rewrite.warnings);
                assert!(
                    lost[0].detail.contains("simple-git-hooks@2.11.1"),
                    "{}",
                    lost[0].detail
                );
            }
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
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: format!(
                    "https://patch.test/gem/{FIXTURE_TOKEN}/{FIXTURE_UUID}/gems/rails-7.0.0.gem"
                ),
                registry_override: Some(RegistryOverride {
                    kind: "rubygems-compact-index".into(),
                    index_url: format!("https://patch.test/gem/{FIXTURE_TOKEN}/{FIXTURE_UUID}/"),
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
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = vec![gradle_candidate()];
        let read = read_candidate_files(view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(
            view,
            read.clone(),
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
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
            // Only the Gradle build is refused, not the whole run (#721).
            assert!(
                !read
                    .undecodable_reads
                    .contains(&"settings.gradle".to_string()),
                "{:?}",
                read.undecodable_reads
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

    /// #721 review: with no readable Gradle build the Gradle planner never
    /// runs, so a stray non-UTF-8 Gradle lock does not refuse the rest of a
    /// Maven run. A non-UTF-8 root build or settings script does: it may be
    /// the whole build, unreadable, which would otherwise be skipped
    /// silently (a Gradle-only project exiting 0 unpatched).
    #[tokio::test]
    async fn non_utf8_gradle_files_without_a_readable_build() {
        const POM: &str = "<project><dependencies><dependency><groupId>com.socketfixture</groupId><artifactId>victim</artifactId><version>1.10.0</version></dependency></dependencies></project>\n";
        let latin1: &[u8] = b"rootProject.name = 'Andr\xe9'\n";
        let candidates = vec![gradle_candidate()];

        // A stray lock beside a pom.xml: not refused.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("pom.xml"), POM).unwrap();
        std::fs::write(tmp.path().join("gradle.lockfile"), latin1).unwrap();
        let mut memory = MemoryProject::new();
        memory.insert_text("pom.xml", POM);
        memory.insert(
            "gradle.lockfile",
            MemoryEntry::Binary(latin1.to_vec().into()),
        );
        for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
            let (read, done) = gradle_rewrite_in(&view).await;
            assert!(
                read.undecodable_reads.is_empty(),
                "{:?}",
                read.undecodable_reads
            );
            assert!(guard(&view, &done, &candidates).is_none());
        }

        // A Gradle-only project whose root scripts are all non-UTF-8:
        // refused, never skipped.
        for root in ["settings.gradle", "build.gradle", "build.gradle.kts"] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join(root), latin1).unwrap();
            let mut memory = MemoryProject::new();
            memory.insert(root, MemoryEntry::Binary(latin1.to_vec().into()));
            for view in [ProjectView::Disk(tmp.path()), ProjectView::Memory(&memory)] {
                let (read, done) = gradle_rewrite_in(&view).await;
                assert_eq!(read.undecodable_reads, vec![root.to_string()]);
                let refusal = guard(&view, &done, &candidates).expect("refused");
                assert_eq!(refusal.code, UNREADABLE_REFUSAL);
            }
        }
    }

    /// #721 review: an unreadable `socket-patch.sbt` is refused by the
    /// run-wide check itself, which also runs before any vendored->hosted
    /// takeover revert, and keeps the sbt planner's own refusal code.
    #[tokio::test]
    async fn an_unreadable_sbt_owned_file_refuses_early_with_the_sbt_code() {
        let latin1: &[u8] = b"// Auteur: Andr\xe9\n";
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("socket-patch.sbt"), latin1).unwrap();
        let candidates = vec![gradle_candidate()];
        let read = read_candidate_files(
            &ProjectView::Disk(tmp.path()),
            &BTreeSet::new(),
            &candidates,
        )
        .await;
        assert_eq!(read.undecodable_reads, vec!["socket-patch.sbt"]);
        let refusal = undecodable_guard(&read.undecodable_reads, &candidates).expect("refused");
        assert_eq!(refusal.code, SBT_OWNED_FILE_UNREADABLE);
        assert!(
            refusal.message.contains("socket-patch.sbt"),
            "{}",
            refusal.message
        );
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

    /// An sbt build beside a Gradle build: the Gradle planner pinning a
    /// uuid the sbt rewriter refused (here: no resolution evidence) does
    /// not confirm it — the sbt build still loads the upstream artifact.
    #[tokio::test]
    async fn a_mixed_sbt_and_gradle_build_needs_both() {
        let mut p = MemoryProject::new();
        p.insert_text("settings.gradle", "");
        p.insert_text(
            "build.gradle",
            "dependencies { implementation 'com.socketfixture:victim:1.10.0' }\n",
        );
        p.insert_text(
            "gradle.lockfile",
            "com.socketfixture:victim:1.10.0=runtimeClasspath\nempty=\n",
        );
        // The Gradle half alone pins the patch.
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);

        p.insert_text("project/build.properties", "sbt.version=1.9.9\n");
        p.insert_text(
            "build.sbt",
            "libraryDependencies += \"com.socketfixture\" % \"victim\" % \"1.10.0\"\n",
        );
        let (_, done) = gradle_rewrite(&p).await;
        assert!(done.rewrite.confirmed_gradle_uuids.contains(GRADLE_UUID));
        assert!(done.rewrite.refused_sbt_uuids.contains(GRADLE_UUID));
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
    }

    /// The gate reuses the caller's discovery only for a pass that writes
    /// nothing and counts exactly the origins it was made with.
    #[test]
    fn the_prior_discovery_is_reused_only_unwritten_with_the_same_origins() {
        let prior = crate::vex::discover::Discovery::default();
        assert!(reusable_prior(Some(&prior), true, true).is_some());
        assert!(reusable_prior(Some(&prior), false, true).is_none());
        assert!(reusable_prior(Some(&prior), true, false).is_none());
        assert!(reusable_prior(None, true, true).is_none());
    }

    /// A registry-resolved left-pad: the hosted rewrite redirects it.
    const LEFT_PAD_LOCK: &str = r#"{
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

    /// The left-pad rewrite of the project on disk at `root`, counting
    /// `configured` patch servers and handed `prior` as the caller's
    /// pre-rewrite discovery.
    async fn gated_left_pad_rewrite(
        root: &std::path::Path,
        configured: &[&str],
        prior: Option<&crate::vex::discover::Discovery>,
    ) -> Rewritten {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: configured.iter().map(|o| o.to_string()).collect(),
            prior_discovery: prior,
        };
        let view = ProjectView::Disk(root);
        let candidates = vec![left_pad_candidate()];
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        rewrite(
            &view,
            read,
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
            options,
        )
        .await
    }

    /// Lockfile discovery of `root` as the management commands make it.
    async fn discover_configured(
        root: &std::path::Path,
        configured: &[&str],
    ) -> crate::vex::discover::Discovery {
        crate::vex::discover_patched_refs_with(
            root,
            &crate::vex::DiscoverOptions {
                patch_server_origins: configured.iter().map(|o| o.to_string()).collect(),
            },
        )
        .await
    }

    /// Write `done`'s files under `root`, as the disk flow does.
    fn write_rewrite(root: &std::path::Path, done: &Rewritten) {
        for (rel, text) in &done.rewrite.files {
            std::fs::write(root.join(rel), text).unwrap();
        }
        for (rel, bytes) in &done.rewrite.binary_files {
            std::fs::write(root.join(rel), bytes).unwrap();
        }
    }

    /// A writing pass hands back the gate's discovery over its overlaid
    /// writes, and it is the discovery of the written disk; the caller's
    /// prior discovery is never reused for a pass that writes.
    #[tokio::test]
    async fn a_writing_pass_hands_back_the_discovery_of_its_writes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), LEFT_PAD_LOCK).unwrap();
        let configured = ["https://patch.test"];
        let before = discover_configured(tmp.path(), &configured).await;
        let done = gated_left_pad_rewrite(tmp.path(), &configured, Some(&before)).await;
        assert!(done.rewrite.files.contains_key("package-lock.json"));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
        let Some(FinalDiscovery::Overlaid {
            discovery: overlaid,
            view_only,
        }) = &done.final_discovery
        else {
            panic!(
                "expected the overlaid discovery: {:?}",
                done.final_discovery
            );
        };
        assert!(*view_only, "npm discovery reads only through the view");
        write_rewrite(tmp.path(), &done);
        let after = discover_configured(tmp.path(), &configured).await;
        assert_eq!(format!("{overlaid:?}"), format!("{after:?}"));
        assert_ne!(format!("{before:?}"), format!("{after:?}"));
        assert_eq!(
            crate::patch::redirect::upstream::HostedPin::all(overlaid).len(),
            1
        );
    }

    /// A pass that writes nothing (an already-redirected project) reuses
    /// the caller's discovery and says so.
    #[tokio::test]
    async fn an_unwritten_pass_hands_back_the_prior_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), LEFT_PAD_LOCK).unwrap();
        let configured = ["https://patch.test"];
        let first = gated_left_pad_rewrite(tmp.path(), &configured, None).await;
        write_rewrite(tmp.path(), &first);
        let prior = discover_configured(tmp.path(), &configured).await;
        let done = gated_left_pad_rewrite(tmp.path(), &configured, Some(&prior)).await;
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert_eq!(done.confirmed.len(), 1);
        assert!(matches!(done.final_discovery, Some(FinalDiscovery::Prior)));
        // Without a prior discovery, the gate discovers the (unwritten)
        // project itself and hands that back.
        let done = gated_left_pad_rewrite(tmp.path(), &configured, None).await;
        let Some(FinalDiscovery::Overlaid {
            discovery: fresh, ..
        }) = &done.final_discovery
        else {
            panic!("expected a fresh discovery: {:?}", done.final_discovery);
        };
        assert_eq!(format!("{fresh:?}"), format!("{prior:?}"));
    }

    /// A grant on a server the caller did not configure makes the gate count
    /// another origin: its discovery is not the caller's, so the gate never
    /// reuses the prior one and hands back none.
    #[tokio::test]
    async fn a_foreign_grant_origin_hands_back_no_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("package-lock.json"), LEFT_PAD_LOCK).unwrap();
        let done = gated_left_pad_rewrite(tmp.path(), &[], None).await;
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
        assert!(done.final_discovery.is_none());
        write_rewrite(tmp.path(), &done);
        // Unwritten now, with a prior discovery made without the grant's
        // origin: still not reused.
        let prior = discover_configured(tmp.path(), &[]).await;
        let done = gated_left_pad_rewrite(tmp.path(), &[], Some(&prior)).await;
        assert!(done.rewrite.files.is_empty());
        assert_eq!(done.confirmed.len(), 1);
        assert!(done.final_discovery.is_none());
    }

    /// Nothing confirmed: the gate discovers nothing and hands back none.
    #[tokio::test]
    async fn an_unconfirmed_rewrite_hands_back_no_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("package-lock.json"),
            LEFT_PAD_LOCK.replace("left-pad", "right-pad"),
        )
        .unwrap();
        let prior = discover_configured(tmp.path(), &["https://patch.test"]).await;
        let done = gated_left_pad_rewrite(tmp.path(), &["https://patch.test"], Some(&prior)).await;
        assert!(done.confirmed.is_empty());
        assert!(done.final_discovery.is_none());
    }

    /// Only the install-policy auto-configs' root config files may be
    /// created under an overlaid discovery.
    #[test]
    fn only_root_config_files_are_invisible_overlay_creations() {
        assert!(overlay_creation_is_invisible(".npmrc"));
        assert!(overlay_creation_is_invisible("pnpm-workspace.yaml"));
        for rel in [
            "package-lock.json",
            "pylock.toml",
            "pylock.dev.toml",
            "packages/a/.npmrc",
            "common/config/subspaces/a/pnpm-lock.yaml",
            "settings.gradle",
            "NuGet.Config",
        ] {
            assert!(!overlay_creation_is_invisible(rel), "{rel}");
        }
    }

    /// A lockless NuGet pin (a Socket source mapping, no
    /// `packages.lock.json`) is still written, but the run says no later
    /// command can manage it and names the lockfile that fixes that.
    #[tokio::test]
    async fn a_lockless_nuget_pin_is_written_with_the_lockless_warning() {
        use crate::patch::redirect::{Integrity, RegistryOverride, RegistryOverrideIdentifiers};
        let base =
            format!("https://patch.test/patch-registry/nuget/{FIXTURE_TOKEN}/{FIXTURE_UUID}");
        let candidate = Candidate {
            purl: "pkg:nuget/Newtonsoft.Json@13.0.3".into(),
            dep: DepOverride {
                ecosystem: "nuget".into(),
                name: "Newtonsoft.Json".into(),
                namespace: None,
                version: "13.0.3".into(),
                token: FIXTURE_TOKEN.into(),
                patch_uuid: FIXTURE_UUID.into(),
                artifact_url: format!(
                    "{base}/flat/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg"
                ),
                registry_override: Some(RegistryOverride {
                    kind: "nuget-v3".into(),
                    index_url: format!("{base}/index.json"),
                    identifiers: RegistryOverrideIdentifiers {
                        name: "Newtonsoft.Json".into(),
                        version: "13.0.3".into(),
                        nuget_id_lower: Some("newtonsoft.json".into()),
                        nuget_version_norm: Some("13.0.3".into()),
                        ..Default::default()
                    },
                }),
                integrity: Integrity {
                    sha512: Some("sha512-NUGETPATCHED==".into()),
                    ..Default::default()
                },
            },
        };
        let mut p = MemoryProject::new();
        p.insert_text(
            "nuget.config",
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    \
             <add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n  \
             </packageSources>\n</configuration>\n",
        );
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = vec![candidate];
        let view = ProjectView::Memory(&p);
        let read = read_candidate_files(&view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(
            &view,
            read,
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
            options,
        )
        .await;
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.rewrite.warnings);
        assert!(done.unattributed.is_empty(), "{:?}", done.unattributed);
        let lockless: Vec<&RewriteWarning> = done
            .rewrite
            .warnings
            .iter()
            .filter(|w| w.code == REDIRECT_PIN_LOCKLESS)
            .collect();
        assert_eq!(lockless.len(), 1, "{:?}", done.rewrite.warnings);
        let detail = &lockless[0].detail;
        assert!(detail.contains("Newtonsoft.Json"), "{detail}");
        assert!(
            detail.contains("dotnet restore --use-lock-file"),
            "{detail}"
        );
    }

    const GEMFILE: &str = "source \"https://rubygems.org\"\n\ngem \"rails\", \"7.0.0\"\n";
    const GEM_LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.0)\n\n\
        PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rails (= 7.0.0)\n\nBUNDLED WITH\n   2.5.22\n";

    async fn gem_rewrite(p: &MemoryProject) -> (CandidateFiles, Rewritten) {
        gem_rewrite_in(&ProjectView::Memory(p)).await
    }

    async fn gem_rewrite_in(view: &ProjectView<'_>) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = vec![gem_candidate()];
        let read = read_candidate_files(view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(
            view,
            read.clone(),
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
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

    fn warning_codes(done: &Rewritten) -> Vec<&str> {
        done.rewrite
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect()
    }

    /// #749: bundler 4's `BUNDLE_LOCKFILE` naming another lock leaves every
    /// gem manifest out of the candidates, and the run says why.
    #[tokio::test]
    async fn bundle_lockfile_naming_another_lock_redirects_nothing() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text("custom.lock", GEM_LOCK);
        p.insert_text(".bundle/config", "---\nBUNDLE_LOCKFILE: \"custom.lock\"\n");
        let (read, done) = gem_rewrite(&p).await;
        assert!(!read.files.contains_key("Gemfile"));
        assert!(!read.files.contains_key("Gemfile.lock"));
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes = warning_codes(&done);
        assert!(
            codes.contains(&"redirect_gem_bundle_lockfile_unsupported"),
            "{codes:?}"
        );
    }

    /// #749: a memory view has no real root, so an absolute
    /// `BUNDLE_LOCKFILE` that would land on the pair's lock if the project
    /// sat at `/` still names a file outside the project. Bundler opens
    /// that path, never the in-repo lock, so the pair stays out.
    #[tokio::test]
    async fn absolute_bundle_lockfile_redirects_nothing() {
        for (gems_rb, lock) in [(false, "/Gemfile.lock"), (true, "/gems.locked")] {
            let mut p = MemoryProject::new();
            if gems_rb {
                p.insert_text("gems.rb", GEMFILE);
                p.insert_text("gems.locked", GEM_LOCK);
            } else {
                p.insert_text("Gemfile", GEMFILE);
                p.insert_text("Gemfile.lock", GEM_LOCK);
            }
            p.insert_text(
                ".bundle/config",
                format!("---\nBUNDLE_LOCKFILE: \"{lock}\"\n").as_str(),
            );
            let (_read, done) = gem_rewrite(&p).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{lock}: {:?}",
                done.rewrite.files.keys()
            );
            let codes = warning_codes(&done);
            assert!(
                codes.contains(&"redirect_gem_bundle_lockfile_unsupported"),
                "{lock}: {codes:?}"
            );
        }
    }

    /// #751: a `Gemfile` + `gems.rb` twin is withheld whatever its locks'
    /// `BUNDLED WITH` say (which bundler wrote a lock is not which one
    /// installs it), and the run says why.
    #[tokio::test]
    async fn twin_redirects_nothing_whatever_the_locks_say() {
        let legacy = GEM_LOCK.replace("2.5.22", "1.17.3");
        for (gemfile_lock, gems_locked) in [
            (legacy.as_str(), legacy.as_str()),
            (legacy.as_str(), GEM_LOCK),
            (GEM_LOCK, GEM_LOCK),
        ] {
            let mut p = MemoryProject::new();
            p.insert_text("Gemfile", GEMFILE);
            p.insert_text("Gemfile.lock", gemfile_lock);
            p.insert_text("gems.rb", GEMFILE);
            p.insert_text("gems.locked", gems_locked);
            let (_read, done) = gem_rewrite(&p).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{:?}",
                done.rewrite.files.keys()
            );
            let codes = warning_codes(&done);
            assert!(
                codes.contains(&"redirect_gem_twin_manifest_ambiguous"),
                "{codes:?}"
            );
        }
    }

    /// A twin whose other spelling this run can't read (a symlink, an
    /// unreadable or a non-UTF-8 file) is still a twin: bundler's
    /// `File.file?` sees it, so neither pair is wired (Bugbot on #768).
    #[tokio::test]
    async fn twin_with_an_unreadable_spelling_redirects_nothing() {
        for (other, entry) in [
            ("gems.rb", MemoryEntry::Symlink),
            ("Gemfile", MemoryEntry::Symlink),
            (
                "gems.rb",
                MemoryEntry::Binary(vec![0xff, 0xfe, 0x00].into()),
            ),
        ] {
            let mut p = MemoryProject::new();
            for (rel, text) in [
                ("Gemfile", GEMFILE),
                ("Gemfile.lock", GEM_LOCK),
                ("gems.rb", GEMFILE),
                ("gems.locked", GEM_LOCK),
            ] {
                if rel != other {
                    p.insert_text(rel, text);
                }
            }
            p.insert(other, entry);
            let (_read, done) = gem_rewrite(&p).await;
            assert!(
                done.rewrite.files.is_empty(),
                "{other}: {:?}",
                done.rewrite.files.keys()
            );
            let codes = warning_codes(&done);
            assert!(
                codes.contains(&"redirect_gem_twin_manifest_ambiguous"),
                "{other}: {codes:?}"
            );
        }
    }

    /// On disk, a twin spelling that `stat`s as a regular file but can't
    /// be read (permission denied) is still a twin: bundler's `File.file?`
    /// sees it, so neither pair is wired (Bugbot on #768).
    #[cfg(unix)]
    #[tokio::test]
    async fn twin_with_an_unreadable_disk_spelling_redirects_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for (rel, text) in [
            ("Gemfile", GEMFILE),
            ("Gemfile.lock", GEM_LOCK),
            ("gems.rb", GEMFILE),
            ("gems.locked", GEM_LOCK),
        ] {
            std::fs::write(root.join(rel), text).unwrap();
        }
        let gems_rb = root.join("gems.rb");
        std::fs::set_permissions(&gems_rb, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&gems_rb).is_ok() {
            // Running as root: permissions can't make the read fail.
            return;
        }
        let (_read, done) = gem_rewrite_in(&ProjectView::Disk(root)).await;
        std::fs::set_permissions(&gems_rb, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes = warning_codes(&done);
        assert!(
            codes.contains(&"redirect_gem_twin_manifest_ambiguous"),
            "{codes:?}"
        );
    }

    /// #681: `bundle config set --local mirror.all <url>` sends the
    /// patch-registry `source` block to the mirror, which serves the
    /// upstream gem. The redirect used to be written and attested; now no
    /// gem file is a candidate and the run says why.
    #[tokio::test]
    async fn bundler_mirror_all_redirects_nothing() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text(
            ".bundle/config",
            "---\nBUNDLE_MIRROR__ALL: \"https://artifactory.example/api/gems/rubygems/\"\n",
        );
        let (read, done) = gem_rewrite(&p).await;
        assert!(!read.files.contains_key("Gemfile"));
        assert!(!read.files.contains_key("Gemfile.lock"));
        assert!(
            done.rewrite.files.is_empty(),
            "{:?}",
            done.rewrite.files.keys()
        );
        let codes = warning_codes(&done);
        assert!(
            codes.contains(&"redirect_gem_mirror_overrides_source"),
            "{codes:?}"
        );
        assert!(!codes.contains(&"redirect_gem_no_gemfile"), "{codes:?}");
        let w = done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == "redirect_gem_mirror_overrides_source")
            .unwrap();
        assert!(!w.detail.contains("artifactory.example"), "{}", w.detail);
        assert!(
            w.detail.contains("mirror.https://rubygems.org"),
            "{}",
            w.detail
        );
    }

    /// Exact-source and hostname mirrors both refuse intake and confirmation,
    /// with sensitive mirror values excluded from the rendered warning.
    #[tokio::test]
    async fn bundler_mirror_for_the_patch_source_redirects_nothing() {
        for key in [
            format!("BUNDLE_MIRROR__HTTPS://PATCH__TEST/GEM/{FIXTURE_TOKEN}/{FIXTURE_UUID}/"),
            "BUNDLE_MIRROR__PATCH__TEST".to_string(),
            "BUNDLE_MIRROR__PATCH__TEST/".to_string(),
        ] {
            let mut p = MemoryProject::new();
            p.insert_text("Gemfile", GEMFILE);
            p.insert_text("Gemfile.lock", GEM_LOCK);
            p.insert_text(".bundle/config", format!("---\n{key}: \"https://review-user:review-secret@m.example/?token=review-token\"\n"));
            let (read, done) = gem_rewrite(&p).await;
            assert!(!read.files.contains_key("Gemfile"));
            assert!(!read.files.contains_key("Gemfile.lock"));
            assert!(
                done.rewrite.files.is_empty(),
                "{key}: {:?}",
                done.rewrite.files.keys()
            );
            let warning = done
                .rewrite
                .warnings
                .iter()
                .find(|warning| warning.code == "redirect_gem_mirror_overrides_source")
                .unwrap();
            for secret in ["review-user", "review-secret", "review-token"] {
                assert!(!warning.detail.contains(secret));
            }
        }
    }

    /// A mirror scoped to rubygems.org leaves the patch-registry source
    /// alone: the redirect still lands.
    #[tokio::test]
    async fn bundler_mirror_scoped_to_rubygems_org_still_redirects() {
        let mut p = MemoryProject::new();
        p.insert_text("Gemfile", GEMFILE);
        p.insert_text("Gemfile.lock", GEM_LOCK);
        p.insert_text(
            ".bundle/config",
            "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://m.example/\"\n",
        );
        let (_read, done) = gem_rewrite(&p).await;
        assert!(
            done.rewrite.files.contains_key("Gemfile"),
            "{:?} {:?}",
            done.rewrite.files.keys(),
            warning_codes(&done)
        );
        assert!(!warning_codes(&done).contains(&"redirect_gem_mirror_overrides_source"));
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

    /// Without `BUNDLE_GEMFILE` a lone `gems.rb` pair is still the one
    /// bundler (and the rewriter) picks; a twin is withheld
    /// ([`twin_redirects_nothing_whatever_the_locks_say`]).
    #[tokio::test]
    async fn default_discovery_wires_a_lone_gems_rb() {
        let mut p = MemoryProject::new();
        p.insert_text("gems.rb", GEMFILE);
        p.insert_text("gems.locked", GEM_LOCK);
        let (_read, done) = gem_rewrite(&p).await;
        assert!(
            done.rewrite.files.contains_key("gems.rb"),
            "{:?}",
            done.rewrite.files.keys()
        );
        assert!(warning_codes(&done)
            .iter()
            .all(|c| !c.starts_with("redirect_gem_twin")));
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

    // ── #492: `sharedWorkspaceLockfile: false` member locks ──

    const MEMBER_UUID: &str = "u-member";
    const MEMBER_URL: &str =
        "https://patch.example/patch/npm/is-number/7.0.0/tok/u-member/is-number-7.0.0.tgz";

    fn is_number_candidates() -> Vec<Candidate> {
        let mut refs: HashMap<String, PackageVendorResult> = HashMap::new();
        refs.insert(
            MEMBER_UUID.into(),
            reference(serde_json::json!({
                "status": "granted",
                "url": MEMBER_URL,
                "purl": "pkg:npm/is-number@7.0.0",
                "artifacts": [{"kind": "tarball", "url": MEMBER_URL,
                               "integrity": {"sha512": "sha512-PATCHED=="}}],
                "registryOverride": null
            })),
        );
        let selected = vec![(
            "pkg:npm/is-number@7.0.0".to_string(),
            MEMBER_UUID.to_string(),
        )];
        build_candidates(&selected, &refs, &mut Vec::new())
    }

    fn v9_member_lock(direct: bool) -> String {
        let importer = if direct {
            "      is-number:\n        specifier: 7.0.0\n        version: 7.0.0\n"
        } else {
            "      to-regex-range:\n        specifier: 5.0.1\n        version: 5.0.1\n"
        };
        format!(
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n{importer}\n\
             packages:\n\n  is-number@7.0.0:\n    resolution: {{integrity: sha512-UPSTREAM==}}\n\n\
             snapshots:\n\n  is-number@7.0.0: {{}}\n"
        )
    }

    const V5_MEMBER_LOCK: &str = "lockfileVersion: 5.4\n\nspecifiers:\n  is-number: 7.0.0\n\n\
        dependencies:\n  is-number: 7.0.0\n\npackages:\n\n  /is-number/7.0.0:\n    \
        resolution: {integrity: sha512-UPSTREAM==}\n    dev: false\n";

    const ROOT_ONLY_LOCK: &str = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n";

    fn write_rel(root: &std::path::Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// The issue's layout: a root lock covering only `.` and one lock per
    /// member (`a` direct, `b` transitive).
    fn write_member_workspace(root: &std::path::Path, workspace: &str) {
        write_rel(root, "package.json", r#"{"name":"root","private":true}"#);
        write_rel(root, "pnpm-workspace.yaml", workspace);
        write_rel(root, "pnpm-lock.yaml", ROOT_ONLY_LOCK);
        write_rel(root, "packages/a/package.json", r#"{"name":"a"}"#);
        write_rel(root, "packages/a/pnpm-lock.yaml", &v9_member_lock(true));
        write_rel(root, "packages/b/package.json", r#"{"name":"b"}"#);
        write_rel(root, "packages/b/pnpm-lock.yaml", &v9_member_lock(false));
        // An installed copy's own lock is never a member's.
        write_rel(
            root,
            "packages/a/node_modules/x/pnpm-lock.yaml",
            &v9_member_lock(true),
        );
    }

    async fn member_rewrite(root: &std::path::Path) -> (CandidateFiles, Rewritten) {
        view_rewrite(&ProjectView::Disk(root)).await
    }

    async fn view_rewrite(view: &ProjectView<'_>) -> (CandidateFiles, Rewritten) {
        let outer = OuterAllowRemote::default;
        let options = RewriteOptions {
            dry_run: false,
            targets_pipenv_lock: false,
            pipenv_major: None,
            pipenv_unknown_detail: String::new(),
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
            npm_outer: &outer,
            yarn_classic_outer: &OuterYarnMirror::default,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        };
        let candidates = is_number_candidates();
        let read = read_candidate_files(view, &BTreeSet::new(), &candidates).await;
        let done = rewrite(
            view,
            read.clone(),
            &candidates,
            BTreeMap::new(),
            &BTreeSet::new(),
            options,
        )
        .await;
        (read, done)
    }

    const MEMBER_KEYS: [&str; 2] = ["packages/a/pnpm-lock.yaml", "packages/b/pnpm-lock.yaml"];

    #[tokio::test]
    async fn member_locks_are_pinned_when_the_shared_lock_is_off() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
        write_member_workspace(tmp.path(), ws);
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_eq!(read.pnpm_member_lock_keys, MEMBER_KEYS);
        for key in MEMBER_KEYS {
            let text = done
                .rewrite
                .files
                .get(key)
                .unwrap_or_else(|| panic!("{key} must be pinned: {:?}", done.rewrite.warnings));
            assert!(text.contains(&format!("tarball: {MEMBER_URL}")), "{text}");
        }
        assert!(!done.rewrite.files.contains_key("pnpm-lock.yaml"));
        assert_eq!(done.confirmed.len(), 1, "{:?}", done.confirmed);
        assert!(
            !warning_codes(&done).contains(&"redirect_pnpm_entry_not_found"),
            "{:?}",
            warning_codes(&done)
        );
        // pnpm reads `trustLockfile` from the root file for every member.
        assert_eq!(
            done.rewrite
                .files
                .get(PNPM_WORKSPACE_REL)
                .map(String::as_str),
            Some(format!("{ws}trustLockfile: true\n").as_str())
        );
        assert_eq!(
            done.rewrite.edits.last().map(|e| e.kind.as_str()),
            Some(REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND)
        );

        // HEAL-ON-RERUN: the member locks already pinned, the trust key
        // missing (an opted-out first run): a re-run plans it again.
        for key in MEMBER_KEYS {
            write_rel(tmp.path(), key, &done.rewrite.files[key]);
        }
        let (_, again) = member_rewrite(tmp.path()).await;
        assert!(
            MEMBER_KEYS
                .iter()
                .all(|k| !again.rewrite.files.contains_key(*k)),
            "{:?}",
            again.rewrite.files.keys()
        );
        assert_eq!(again.confirmed.len(), 1);
        assert!(again.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
    }

    #[tokio::test]
    async fn member_locks_are_ignored_while_the_root_lock_is_shared() {
        // The default shared lock: member locks are stale leftovers.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(tmp.path(), "packages:\n  - 'packages/*'\n");
        let (read, done) = member_rewrite(tmp.path()).await;
        assert!(read.pnpm_member_lock_keys.is_empty());
        assert!(MEMBER_KEYS.iter().all(|k| !read.files.contains_key(*k)));
        assert!(done.confirmed.is_empty());

        // The setting says off, but the root lock lists member importers:
        // pnpm installs from it, so the member locks are still stale.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        write_rel(
            tmp.path(),
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/a: {}\n",
        );
        let (read, _) = member_rewrite(tmp.path()).await;
        assert!(read.pnpm_member_lock_keys.is_empty());
    }

    /// pnpm 7 with `shared-workspace-lockfile=false` in `.npmrc` writes no
    /// root lock at all, only the members' (lockfile 5.4).
    #[tokio::test]
    async fn npmrc_member_locks_without_a_root_lock_are_pinned() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_rel(root, "package.json", r#"{"name":"root","private":true}"#);
        write_rel(root, "pnpm-workspace.yaml", "packages:\n  - packages/*\n");
        write_rel(root, ".npmrc", "shared-workspace-lockfile=false\n");
        write_rel(root, "node_modules/.modules.yaml", "layoutVersion: 5\n");
        write_rel(root, "packages/a/package.json", r#"{"name":"a"}"#);
        write_rel(root, "packages/a/pnpm-lock.yaml", V5_MEMBER_LOCK);
        let (read, done) = member_rewrite(root).await;
        assert_eq!(
            read.pnpm_member_lock_keys,
            vec!["packages/a/pnpm-lock.yaml"]
        );
        let text = &done.rewrite.files["packages/a/pnpm-lock.yaml"];
        assert!(text.contains(MEMBER_URL), "{text}");
        assert_eq!(done.confirmed.len(), 1);
        let codes = warning_codes(&done);
        assert!(
            !codes.contains(&"redirect_pnpm_no_lockfile")
                && !codes.contains(&"redirect_npm_no_lockfile"),
            "{codes:?}"
        );
        // A legacy lock gets no trust config.
        assert!(!done.rewrite.files.contains_key(PNPM_WORKSPACE_REL));
    }

    /// Members that cannot be listed refuse instead of pinning the root
    /// lock alone (which no member installs from) and reporting success.
    #[tokio::test]
    async fn unlisted_member_locks_refuse_every_pnpm_pin() {
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages: *members\nsharedWorkspaceLockfile: false\n",
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert!(!read.files.contains_key("pnpm-lock.yaml"));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty());
        let codes = warning_codes(&done);
        assert!(codes.contains(&PNPM_MEMBER_LOCKS_UNRESOLVED), "{codes:?}");
        assert!(!codes.contains(&"redirect_npm_no_lockfile"), "{codes:?}");

        // A member lock that cannot be read refuses the whole set.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        std::fs::write(tmp.path().join("packages/b/pnpm-lock.yaml"), [0xff, 0xfe]).unwrap();
        let (read, done) = member_rewrite(tmp.path()).await;
        assert!(read.pnpm_member_lock_keys.is_empty());
        assert!(MEMBER_KEYS.iter().all(|k| !read.files.contains_key(*k)));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty());
        assert!(warning_codes(&done).contains(&PNPM_MEMBER_LOCKS_UNRESOLVED));

        // No member lock and no root lock: not "run `pnpm install`".
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_rel(root, "pnpm-workspace.yaml", "packages:\n  - packages/*\n");
        write_rel(root, ".npmrc", "shared-workspace-lockfile=false\n");
        write_rel(root, "node_modules/.modules.yaml", "layoutVersion: 5\n");
        write_rel(root, "packages/a/package.json", r#"{"name":"a"}"#);
        let (_, done) = member_rewrite(root).await;
        let codes = warning_codes(&done);
        assert!(codes.contains(&PNPM_MEMBER_LOCKS_UNRESOLVED), "{codes:?}");
        assert!(!codes.contains(&"redirect_pnpm_no_lockfile"), "{codes:?}");
    }

    const BRANCH_LOCK: &str = "pnpm-lock.feature.yaml";
    const BRANCH_WS: &str = "packages:\n  - '.'\ngitBranchLockfile: true\n";

    /// The issue's layout: `pnpm-lock.yaml` as committed on main, and the
    /// lock pnpm writes for the `feature` branch under `gitBranchLockfile`.
    fn write_branch_lock_project(root: &std::path::Path, workspace: &str, root_lock: bool) {
        write_rel(
            root,
            "package.json",
            r#"{"name":"app","dependencies":{"is-number":"7.0.0"}}"#,
        );
        write_rel(root, "pnpm-workspace.yaml", workspace);
        write_rel(root, "node_modules/.modules.yaml", "layoutVersion: 5\n");
        if root_lock {
            write_rel(root, "pnpm-lock.yaml", &v9_member_lock(true));
        }
        write_rel(root, BRANCH_LOCK, &v9_member_lock(true));
    }

    fn assert_branch_lock_refused(read: &CandidateFiles, done: &Rewritten) {
        assert!(!read.files.contains_key("pnpm-lock.yaml"));
        assert!(done.rewrite.files.is_empty(), "{:?}", done.rewrite.files);
        assert!(done.confirmed.is_empty(), "{:?}", done.confirmed);
        let codes = warning_codes(done);
        assert!(codes.contains(&PNPM_GIT_BRANCH_LOCKFILE), "{codes:?}");
        assert!(
            !codes.contains(&"redirect_pnpm_no_lockfile")
                && !codes.contains(&"redirect_npm_no_lockfile"),
            "{codes:?}"
        );
        let detail = &done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == PNPM_GIT_BRANCH_LOCKFILE)
            .unwrap()
            .detail;
        assert!(
            detail.contains(BRANCH_LOCK) && detail.contains("--merge-git-branch-lockfiles"),
            "{detail}"
        );
    }

    /// `gitBranchLockfile` with a branch lock beside `pnpm-lock.yaml`: pnpm
    /// installs the branch from the branch lock, so pinning the stale
    /// `pnpm-lock.yaml` would confirm a pin nothing installs (#556).
    #[tokio::test]
    async fn a_git_branch_lock_refuses_the_stale_root_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), BRANCH_WS, true);
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);

        // pnpm 10 and older read the setting from `.npmrc`.
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), "packages:\n  - '.'\n", true);
        write_rel(tmp.path(), ".npmrc", "git-branch-lockfile=true\n");
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);

        // The in-memory engine refuses the same project.
        let mut project = MemoryProject::new();
        project.insert_text("package.json", r#"{"name":"app"}"#);
        project.insert_text("pnpm-workspace.yaml", BRANCH_WS);
        project.insert_text("pnpm-lock.yaml", v9_member_lock(true));
        project.insert_text(BRANCH_LOCK, v9_member_lock(true));
        let (read, done) = view_rewrite(&ProjectView::Memory(&project)).await;
        assert_branch_lock_refused(&read, &done);
    }

    /// Only the branch lock: not "run `pnpm install`", which just rewrites
    /// the branch lock again (#556).
    #[tokio::test]
    async fn a_lone_git_branch_lock_is_not_a_missing_lock() {
        let tmp = tempfile::tempdir().unwrap();
        write_branch_lock_project(tmp.path(), BRANCH_WS, false);
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);
    }

    /// Under `sharedWorkspaceLockfile: false` pnpm looks for the branch
    /// lock in every member's directory too: a member whose deps changed on
    /// the branch installs from `<member>/pnpm-lock.<branch>.yaml`, so its
    /// `pnpm-lock.yaml` is stale and no member lock is pinned (#492 x #556).
    #[tokio::test]
    async fn a_member_git_branch_lock_refuses_the_stale_member_locks() {
        // pnpm 8+: the settings in the YAML, a root lock covering `.` only,
        // and no branch lock at the root.
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n\
                  gitBranchLockfile: true\n";
        write_member_workspace(tmp.path(), ws);
        write_rel(
            tmp.path(),
            &format!("packages/a/{BRANCH_LOCK}"),
            &v9_member_lock(true),
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);
        assert!(read.pnpm_member_lock_keys.is_empty());
        for key in MEMBER_KEYS {
            assert!(!read.files.contains_key(key), "{key}");
        }

        // pnpm 7: both settings in `.npmrc` and no root lock at all.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(tmp.path(), "packages:\n  - 'packages/*'\n");
        std::fs::remove_file(tmp.path().join("pnpm-lock.yaml")).unwrap();
        write_rel(
            tmp.path(),
            ".npmrc",
            "shared-workspace-lockfile=false\ngit-branch-lockfile=true\n",
        );
        write_rel(
            tmp.path(),
            &format!("packages/a/{BRANCH_LOCK}"),
            &v9_member_lock(true),
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_branch_lock_refused(&read, &done);
        assert!(read.pnpm_member_lock_keys.is_empty());

        // The setting off: the member branch lock is a stray file.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        write_rel(
            tmp.path(),
            &format!("packages/a/{BRANCH_LOCK}"),
            &v9_member_lock(true),
        );
        let (read, done) = member_rewrite(tmp.path()).await;
        assert_eq!(read.pnpm_member_lock_keys, MEMBER_KEYS);
        assert!(!warning_codes(&done).contains(&PNPM_GIT_BRANCH_LOCKFILE));
    }

    /// Run from a member, the setting lives in the ancestor
    /// `pnpm-workspace.yaml` pnpm reads it from, not in the member.
    #[tokio::test]
    async fn a_member_run_reads_the_setting_from_the_governing_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n\
                  gitBranchLockfile: true\n";
        write_member_workspace(tmp.path(), ws);
        let member = tmp.path().join("packages/a");
        write_rel(&member, BRANCH_LOCK, &v9_member_lock(true));
        let (read, done) = member_rewrite(&member).await;
        assert_branch_lock_refused(&read, &done);
        let detail = &done
            .rewrite
            .warnings
            .iter()
            .find(|w| w.code == PNPM_GIT_BRANCH_LOCKFILE)
            .unwrap()
            .detail;
        assert!(detail.contains("gitBranchLockfile: true"), "{detail}");

        // pnpm 10 and older: the `.npmrc` beside the ancestor file.
        let tmp = tempfile::tempdir().unwrap();
        write_member_workspace(
            tmp.path(),
            "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n",
        );
        write_rel(tmp.path(), ".npmrc", "git-branch-lockfile=true\n");
        let member = tmp.path().join("packages/a");
        write_rel(&member, BRANCH_LOCK, &v9_member_lock(true));
        let (read, done) = member_rewrite(&member).await;
        assert_branch_lock_refused(&read, &done);
    }

    /// The setting alone (no branch lock: main, or a branch whose deps never
    /// changed) installs from `pnpm-lock.yaml`, so it is pinned as usual; so
    /// is a stray branch lock while the setting is off.
    #[tokio::test]
    async fn the_root_lock_is_pinned_without_a_live_git_branch_lock() {
        for (workspace, branch_lock) in [
            (BRANCH_WS, false),
            ("packages:\n  - '.'\ngitBranchLockfile: false\n", true),
            ("packages:\n  - '.'\n", true),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            write_branch_lock_project(tmp.path(), workspace, true);
            if !branch_lock {
                std::fs::remove_file(tmp.path().join(BRANCH_LOCK)).unwrap();
            }
            let (_, done) = member_rewrite(tmp.path()).await;
            let text = done
                .rewrite
                .files
                .get("pnpm-lock.yaml")
                .unwrap_or_else(|| panic!("{workspace}: {:?}", done.rewrite.warnings));
            assert!(text.contains(MEMBER_URL), "{text}");
            assert_eq!(done.confirmed.len(), 1, "{workspace}");
            assert!(!warning_codes(&done).contains(&PNPM_GIT_BRANCH_LOCKFILE));
            assert!(!done.rewrite.files.contains_key(BRANCH_LOCK));
        }
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
