//! The vlt artifact preflight of the hosted flow, over a [`ProjectView`]:
//! before any takeover or rewrite, each in-scope artifact is judged the way
//! vlt fetches it. The disk flow probes the artifacts over the network (or
//! judges them offline under `--offline`); the in-memory engine has no
//! network and judges every one offline.

use std::collections::{BTreeMap, BTreeSet};

use crate::constants::npm_family::{
    BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK, VLT_HIDDEN_LOCK_REL, VLT_LOCK, VLT_STORE_DIR,
};
use crate::patch::redirect::vlt_preflight::{self, ArtifactProbe, OFFLINE_REASON};
use crate::patch::redirect::{redact_grant_token, vlt, DepOverride};
use crate::vendor::lock_inventory::{MemoryEntry, ProjectView};

/// The warning code (and skip reason) of a dep whose artifact vlt would
/// fail to verify.
pub const ARTIFACT_UNVERIFIABLE: &str = "redirect_vlt_artifact_unverifiable";

/// The skip `reason` of a dep the preflight withheld from every rewriter.
pub const WITHHELD_REASON: &str = ARTIFACT_UNVERIFIABLE;

/// Whether vlt's install state exists: the hidden lock as a regular file,
/// or the store as a real directory. Stat only; the hidden lock can be
/// megabytes and is never read into the rewriter's input.
pub fn install_state_present(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(cwd) => {
            let is = |rel: &str, dir: bool| {
                std::fs::symlink_metadata(cwd.join(rel)).is_ok_and(|m| {
                    if dir {
                        m.file_type().is_dir()
                    } else {
                        m.file_type().is_file()
                    }
                })
            };
            is(VLT_HIDDEN_LOCK_REL, false) || is(VLT_STORE_DIR, true)
        }
        ProjectView::Memory(project) => {
            matches!(
                project.get(VLT_HIDDEN_LOCK_REL),
                Some(MemoryEntry::Text(_) | MemoryEntry::Binary(_) | MemoryEntry::Present)
            ) || project.is_dir(VLT_STORE_DIR)
        }
    }
}

/// Whether `bun.lockb` is present (disk: `exists`, which follows links).
pub(crate) fn bun_lockb_present(view: &ProjectView<'_>) -> bool {
    match view {
        ProjectView::Disk(cwd) => cwd.join(BUN_LOCKB).exists(),
        ProjectView::Memory(project) => project.contains(BUN_LOCKB),
    }
}

/// What the artifact preflight decided for this run's npm candidates.
#[derive(Debug, Default)]
pub struct Preflight {
    /// Failed while vlt drives, or for a vlt-vendored takeover: withheld
    /// from every rewriter.
    pub withheld_everywhere: BTreeMap<String, String>,
    /// Failed while another npm-family lock may drive: kept out of the vlt
    /// rewrite only.
    pub withheld_from_vlt: BTreeSet<String>,
    pub passed: BTreeSet<String>,
    /// Artifact bytes by URL, for the heal's no-record comparison.
    pub artifacts: BTreeMap<String, Vec<u8>>,
    pub warnings: Vec<serde_json::Value>,
}

/// The files `vlt_drives` and the preflight scope read: `vlt-lock.json`
/// itself, and presence-only entries for the sibling locks and vlt's
/// install state. Empty without a readable `vlt-lock.json`.
pub async fn inputs(view: &ProjectView<'_>) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let Ok(lock) = view.read_text(VLT_LOCK).await else {
        return files;
    };
    files.insert(VLT_LOCK.to_string(), lock);
    for sibling in [NPM_LOCKS[0], NPM_LOCKS[1], "yarn.lock", PNPM_LOCK, BUN_LOCK] {
        if view.is_file(sibling) {
            files.insert(sibling.to_string(), String::new());
        }
    }
    if install_state_present(view) {
        files.insert(VLT_HIDDEN_LOCK_REL.to_string(), String::new());
    }
    files
}

/// The deps a preflight must judge, and whether vlt drives the install.
pub struct PreflightPlan {
    pub scope: Vec<vlt_preflight::PreflightDep>,
    pub drives: bool,
}

impl PreflightPlan {
    /// The distinct artifact URLs to probe.
    pub fn urls(&self) -> BTreeSet<String> {
        self.scope.iter().map(|d| d.artifact_url.clone()).collect()
    }
}

/// The preflight's scope over the project's [`inputs`] (`files`, never
/// empty): `None` when no dep is in scope. `vendored` are the uuids whose
/// purl a vlt vendored ledger entry claims.
pub fn plan(
    view: &ProjectView<'_>,
    files: &BTreeMap<String, String>,
    deps: &[(&str, &DepOverride)],
    vendored: &BTreeSet<String>,
) -> Option<PreflightPlan> {
    let overrides: Vec<DepOverride> = deps.iter().map(|(_, dep)| (*dep).clone()).collect();
    let scope = vlt_preflight::preflight_scope(files, &overrides, vendored);
    if scope.is_empty() {
        return None;
    }
    let drives = vlt::vlt_drives(files, bun_lockb_present(view));
    Some(PreflightPlan { scope, drives })
}

fn unverifiable_detail(
    url: &str,
    reason: &str,
    purl: &str,
    already_pinned: bool,
    everywhere: bool,
) -> String {
    if already_pinned {
        format!(
            "vlt would fail to verify {url}: {reason}; {purl} was left pinned by an earlier run \
             and `vlt ci` will fail until the artifact verifies"
        )
    } else if everywhere {
        format!("vlt would fail to verify {url}: {reason}; nothing was written for {purl}")
    } else {
        format!(
            "vlt would fail to verify {url}: {reason}; vlt-lock.json was not changed for {purl}"
        )
    }
}

/// The preflight's verdicts for `plan` given the `probes` fetched for it
/// (none for a URL that was not fetched: judged offline).
pub fn judge(
    plan: &PreflightPlan,
    deps: &[(&str, &DepOverride)],
    probes: BTreeMap<String, ArtifactProbe>,
) -> Preflight {
    let mut out = Preflight::default();
    let mut passed_urls: BTreeSet<&str> = BTreeSet::new();
    for dep in &plan.scope {
        let reason = match probes.get(&dep.artifact_url) {
            None => Some(OFFLINE_REASON.to_string()),
            Some(probe) => probe.failure(&dep.sha512),
        };
        let Some(reason) = reason else {
            out.passed.insert(dep.patch_uuid.clone());
            passed_urls.insert(&dep.artifact_url);
            continue;
        };
        let purl = deps
            .iter()
            .find(|(_, d)| d.patch_uuid == dep.patch_uuid)
            .map_or("", |(purl, _)| *purl);
        let everywhere = plan.drives || dep.vendored;
        let detail = unverifiable_detail(
            &dep.artifact_url,
            &reason,
            purl,
            dep.already_pinned,
            everywhere,
        );
        out.warnings.push(serde_json::json!({
            "code": ARTIFACT_UNVERIFIABLE,
            "detail": redact_grant_token(&detail, &dep.artifact_url, &dep.patch_uuid),
        }));
        if everywhere {
            out.withheld_everywhere
                .insert(dep.patch_uuid.clone(), purl.to_string());
        } else {
            out.withheld_from_vlt.insert(dep.patch_uuid.clone());
        }
    }
    // Moved, not copied: every dep has been judged, and the probes are not
    // read again, so a verified body is held once.
    for (url, probe) in probes {
        if passed_urls.contains(url.as_str()) {
            if let Some(body) = probe.body {
                out.artifacts.insert(url, body);
            }
        }
    }
    out
}

/// The preflight for a host with no network: every in-scope artifact is
/// judged as `--offline` judges it, so the dep is withheld
/// (`redirect_vlt_artifact_unverifiable`, "offline") rather than pinned in
/// a lock vlt may not be able to install.
pub async fn offline(view: &ProjectView<'_>, deps: &[(&str, &DepOverride)]) -> Preflight {
    let files = inputs(view).await;
    if files.is_empty() {
        return Preflight::default();
    }
    match plan(view, &files, deps, &BTreeSet::new()) {
        Some(plan) => judge(&plan, deps, BTreeMap::new()),
        None => Preflight::default(),
    }
}
