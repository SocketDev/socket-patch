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
//! 5. [`read_candidate_files`] → [`wheel_targets`] → (caller) wheel metadata.
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
use crate::constants::npm_family::{RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR, VLT_HIDDEN_LOCK_REL, VLT_LOCK};
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
    pnpm_trust_workspace_unreadable_detail, read_npmrc_for_allow_remote,
    read_workspace_for_trust, url_host, TrustPlan, NPM_LOCKS, PNPM_TRUST_TRADEOFF_AND_CAUTION,
    PNPM_WORKSPACE_REL, REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND,
};
use super::vlt::bun_lockb_present;

/// Candidate lockfiles / registry configs the redirect rewriters may touch —
/// read from the project when present and handed to `rewrite_registry_redirect`.
pub const REDIRECT_CANDIDATE_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    // pnpm <=2 uses the same package identities under the old filename.
    "shrinkwrap.yaml",
    "node_modules/.modules.yaml",
    "yarn.lock",
    // A berry lock's cache-config gate reads `.yarnrc.yml`; bun's text lock is
    // `bun.lock`; binary locks are read separately below.
    ".yarnrc.yml",
    "bun.lock",
    "bun.lockb",
    // vlt: the lock is rewritten, vlt.json is read-only (the old-lockfile
    // advisory), and the hidden lock is only stat'ed as the install-state
    // sentinel.
    "vlt-lock.json",
    "vlt.json",
    "node_modules/.vlt-lock.json",
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "pdm.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "hatch.toml",
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    // The LEGACY extensionless spelling: cargo reads `.cargo/config` in
    // preference to `config.toml` when both exist, so the rewriter must see
    // it (it wires the managed registry into whichever one is present) —
    // otherwise the `[registries.…]` block lands in a file cargo ignores.
    ".cargo/config",
    "composer.lock",
    "nuget.config",
    "packages.lock.json",
    "Gemfile",
    "Gemfile.lock",
    // Bundler's modern manifest spelling — preferred over Gemfile when both
    // exist (the gem rewriter picks the pair bundler reads and fails closed
    // on diverging spellings).
    "gems.rb",
    "gems.locked",
    // The golang rewriter edits the main module's go.mod (fork-style
    // `replace`) and go.sum (the socket module's two h1: lines). go.sum may
    // legitimately be absent — the rewriter creates it in that case.
    "go.mod",
    "go.sum",
    "pom.xml",
    // Maven Trusted Checksums files the fail-closed maven rewriter merges into
    // (read so an existing user config / checksum set is preserved, not
    // clobbered).
    ".mvn/maven.config",
    ".mvn/checksums/checksums.sha256",
    // Gradle build scripts are never edited — their presence only feeds the
    // maven rewriter's paste-able `exclusiveContent` snippet warning.
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
    // deno.lock is deliberately absent: no redirect rewriter edits its
    // integrity entries.
];

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

    /// The `skipped[]` JSON entry (`{purl, uuid, reason[, detail]}`).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("SkippedPatch is plain strings: serialization cannot fail")
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
        // Merge it in and carry the zip URL (None when not stored yet).
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
            .and_then(|o| {
                crate::patch::redirect::grant_token_path_segment(&o.index_url, sel_uuid)
            })
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
                berry_zip_url: berry_zip.and_then(|a| a.url.clone()),
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
        ProjectView::Disk(cwd) => cwd.join("bun.lock").exists(),
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
#[derive(Debug, Default)]
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
            ProjectView::Disk(_) => view.read_text(rel).await.ok(),
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
        ProjectView::Disk(cwd) => crate::utils::python_lock::python_lock_paths(cwd).unwrap_or_default(),
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
        ProjectView::Disk(cwd) => cwd.join("rush.json").is_file(),
        ProjectView::Memory(project) => project.contains("rush.json"),
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
    for name in REDIRECT_CANDIDATE_FILES {
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
        out.read(view, unreadable, name).await;
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
    out.symlinked_reads.sort();
    out.symlinked_reads.dedup();
    out.unreadable_reads.sort();
    out.unreadable_reads.dedup();
    out
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
    pub rush_warnings: Vec<serde_json::Value>,
    pub pnpm_warnings: Vec<serde_json::Value>,
    pub npm_warnings: Vec<serde_json::Value>,
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
        ProjectView::Disk(cwd) => (read_workspace_for_trust(&cwd.join(PNPM_WORKSPACE_REL)), false),
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
        ProjectView::Disk(cwd) => read_npmrc_for_allow_remote(&cwd.join(NPMRC_REL)),
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
        ProjectView::Disk(cwd) => cwd.join(RUSH_REPO_STATE_REL).is_file(),
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
/// - The percent-encoded URL: the berry rewriter writes it into the lock's
///   `::__archiveUrl=` binding, so the raw form is absent.
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
        );
        (files, rewrite)
    };
    if let Some(content) = binary_content {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_npm_no_lockfile");
        match content {
            Ok(bytes) => {
                crate::patch::redirect::rewrite_bun_binary(&bytes, &overrides, &mut rewrite)
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
    let mut rush_warnings: Vec<serde_json::Value> = Vec::new();
    if rush_lock_keys
        .iter()
        .any(|key| rewrite.files.contains_key(key))
        && rush_repo_state_present(view)
    {
        rush_warnings.push(serde_json::json!({
            "code": "redirect_rush_repo_state_stale",
            "detail":
                "pnpm-lock.yaml was edited outside `rush update`; if \
                 preventManualShrinkwrapChanges is enabled, `rush install` fails until \
                 `rush update` refreshes repo-state.json (the redirect survives `rush \
                 update`)",
        }));
    }

    let (pnpm_warnings, trust_config_write, pnpm_rerun_only, workspace_symlinked) =
        pnpm_trust(view, &files, &rewrite, &overrides, takeover_previews, &options);
    let (npm_warnings, npmrc_config_write) =
        npm_allow_remote(view, &files, &rewrite, &overrides, takeover_previews, &options);
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
) -> (Vec<serde_json::Value>, ConfigWrite, bool, bool) {
    let mut pnpm_warnings: Vec<serde_json::Value> = Vec::new();
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
        return (pnpm_warnings, trust_config_write, pnpm_rerun_only, workspace_symlinked);
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
    pnpm_warnings.push(serde_json::json!({
        "code": "redirect_pnpm_trust_lockfile",
        "detail": format!(
            "{}. After a lock-only change, existing node_modules or a warm pnpm store \
             can still contain upstream files. For a reliable reinstall, use a clean \
             node_modules tree and an empty store with \
             `pnpm install --frozen-lockfile --store-dir <new-empty-directory>`\
             {store_note}. Do not rely on `--force`: some versions re-resolve the \
             upstream artifact. Run `socket-patch vex` after installation to verify \
             the patched files.",
            detail.trim_end_matches('.')
        ),
    }));
    (pnpm_warnings, trust_config_write, pnpm_rerun_only, workspace_symlinked)
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
) -> (Vec<serde_json::Value>, ConfigWrite) {
    let mut npm_warnings: Vec<serde_json::Value> = Vec::new();
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
        Ok(existing) => match plan_npmrc_allow_remote_with(existing.as_deref(), &(options.npm_outer)()) {
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
        Err(why) => npm_allow_remote_unreadable_detail(&npm_hosts, &why),
    };
    npm_warnings.push(serde_json::json!({
        "code": "redirect_npm_allow_remote",
        "detail": detail,
    }));
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
    let final_texts: Vec<(&str, &String)> = files
        .iter()
        .filter(|(name, _)| !(pdm_inactive && name.as_str() == "pdm.lock"))
        .map(|(name, content)| (name.as_str(), rewrite.files.get(name).unwrap_or(content)))
        .chain(
            rewrite
                .files
                .iter()
                .filter(|(name, _)| !files.contains_key(*name))
                .map(|(name, content)| (name.as_str(), content)),
        )
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
            if rewrite.refused_vlt_uuids.contains(uuid) {
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
    let all_texts: Vec<&String> = final_texts.iter().map(|(_, text)| *text).collect();
    let mut present = groups_present(&all_texts, &groups(false)).into_iter();
    let outside_vlt_groups = groups(true);
    let mut present_outside_vlt = if outside_vlt_groups.is_empty() {
        Vec::new()
    } else {
        let texts: Vec<&String> = final_texts
            .iter()
            .filter(|(name, _)| *name != VLT_LOCK)
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

/// The ecosystem a candidate file's rewriter belongs to (`None` for files
/// no rewriter edits), for the in-memory symlinked/unreadable-read refusal.
fn file_ecosystem(rel: &str) -> Option<&'static str> {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    Some(match base {
        "package-lock.json"
        | "npm-shrinkwrap.json"
        | "pnpm-lock.yaml"
        | "shrinkwrap.yaml"
        | ".modules.yaml"
        | "yarn.lock"
        | ".yarnrc.yml"
        | "bun.lock"
        | "bun.lockb"
        | "vlt-lock.json"
        | "vlt.json"
        | ".vlt-lock.json" => "npm",
        "requirements.txt" | "uv.lock" | "poetry.lock" | "pdm.lock" | "Pipfile.lock"
        | "pyproject.toml" | "hatch.toml" => "pypi",
        "Cargo.toml" | "Cargo.lock" | "config.toml" | "config" => "cargo",
        "composer.lock" => "composer",
        "nuget.config" | "packages.lock.json" => "nuget",
        "Gemfile" | "Gemfile.lock" | "gems.rb" | "gems.locked" => "gem",
        "go.mod" | "go.sum" => "golang",
        "pom.xml" | "maven.config" | "checksums.sha256" => "maven",
        _ if crate::utils::python_lock::is_python_lock_name(base) || base.ends_with(".py") => {
            "pypi"
        }
        _ => return None,
    })
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
pub fn guard(view: &ProjectView<'_>, done: &Rewritten, candidates: &[Candidate]) -> Option<Refusal> {
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
pub fn record_fetch_failed_warning(purl: &str) -> serde_json::Value {
    serde_json::json!({
        "code": "record_fetch_failed",
        "detail": format!(
            "{purl} redirected, but its patch record could not be fetched; \
             it will be missing from VEX until `socket-patch scan --mode \
             hosted` is re-run"
        ),
    })
}

/// The rewriters' own warnings as `{code, detail}` JSON.
pub fn rewrite_warnings_json(warnings: &[RewriteWarning]) -> Vec<serde_json::Value> {
    warnings
        .iter()
        .map(|w| serde_json::json!({ "code": w.code, "detail": w.detail }))
        .collect()
}

/// The nested `redirect` block of every hosted `--json` envelope — the ONE
/// spelling of its key set (`mode`, `redirected`, `rewrittenFiles`,
/// `skipped`, `warnings`, `dryRun`), shared by every hosted path (disk
/// scan, its zero-discovery arm, and the in-memory engine), so the two cannot drift by convention.
/// `mode` is `"hosted"`: an additive key so consumers dispatch on the mode without inferring it from which
/// sub-object is present.
pub fn redirect_json_block(
    redirected: usize,
    rewritten: Vec<String>,
    skipped: Vec<serde_json::Value>,
    warnings: Vec<serde_json::Value>,
    dry_run: bool,
) -> serde_json::Value {
    serde_json::json!({
        "mode": "hosted",
        "redirected": redirected,
        "rewrittenFiles": rewritten,
        "skipped": skipped,
        "warnings": warnings,
        "dryRun": dry_run,
    })
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
