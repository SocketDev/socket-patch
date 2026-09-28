//! One project root's hosted redirect over an in-memory file set: the
//! disk flow's `run_redirect_selected` stages as pure functions
//! (reference → `DepOverride` candidates, candidate-file reads, the
//! rewrite, the pnpm `trustLockfile` and npm `allow-remote` auto-configs,
//! per-ecosystem confirmation, the symlink guard). Everything that needs
//! the host machine (the apply lock, vendored takeover reverts, stale
//! install probes, VEX, telemetry, subprocesses) is left out; a vendored
//! takeover is refused instead of performed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use socket_patch_core::api::types::PackageVendorResult;
use socket_patch_core::constants::npm_family::{
    BUN_LOCK, NPM_LOCKS as NPM_LOCK_NAMES, PNPM_LOCK, RUSH_COMMON_LOCK_REL, RUSH_SUBSPACES_DIR,
    VLT_HIDDEN_LOCK_REL, VLT_LOCK, VLT_STORE_DIR,
};
use socket_patch_core::patch::redirect::npmrc::{
    plan_npmrc_allow_remote_with, NpmrcPlan, OuterAllowRemote, NPMRC_ALLOW_REMOTE_EDIT_KIND,
    NPMRC_REL,
};
use socket_patch_core::patch::redirect::{
    rewrite_registry_redirect_withholding_vlt, DepOverride, FileEdit, RewriteResult,
    RewriteWarning,
};
use socket_patch_core::utils::purl::{purl_parts, strip_purl_qualifiers};
use socket_patch_core::vendor::lock_inventory::{MemoryEntry, MemoryProject};
use socket_patch_core::vendor::VendorState;

use super::select::{RUSH_REPO_STATE_REL, VENDOR_STATE_REL};
use super::types::{ProjectError, SkippedPatch};
use crate::commands::scan::hosted::{
    npm_allow_remote_already_detail, npm_allow_remote_configured_detail,
    npm_allow_remote_env_set_detail, npm_allow_remote_manual_detail,
    npm_allow_remote_outer_set_detail, npm_allow_remote_unreadable_detail,
    npm_allow_remote_user_set_detail, plan_workspace_trust, pnpm_heal_root,
    pnpm_lock_may_need_store_flag, pnpm_lock_version_major, pnpm_trust_configured_detail,
    pnpm_trust_legacy_detail, pnpm_trust_manual_guidance, pnpm_trust_policy_preamble,
    pnpm_trust_workspace_unreadable_detail, url_host, TrustPlan, NPM_LOCKS,
    PNPM_TRUST_TRADEOFF_AND_CAUTION, PNPM_WORKSPACE_REL, REDIRECT_CANDIDATE_FILES,
    REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND,
};

/// Skip reason / warning code for a candidate the disk flow would migrate
/// from vendored to hosted (the migration reverts committed wiring, which
/// the in-memory engine does not do).
pub(crate) const VENDORED_TAKEOVER_UNSUPPORTED: &str = "vendored_takeover_unsupported_in_memory";

/// The disk flow's symlink refusal code.
pub(crate) const SYMLINK_REFUSAL: &str = "redirect_symlinked_file_unsupported";

/// A candidate file exists but its content was not provided (oversize, an
/// LFS pointer, presence-only); disk would read and rewrite it.
pub(crate) const UNREADABLE_REFUSAL: &str = "candidate_file_unreadable";

/// One granted reference: the purl it was granted for plus its override.
#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub(crate) purl: String,
    pub(crate) dep: DepOverride,
}

/// The engine-level options the per-root stages read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StageOptions {
    pub(crate) dry_run: bool,
    pub(crate) pipenv_major: Option<u32>,
    pub(crate) trust_lockfile_config: bool,
    pub(crate) npm_allow_remote_config: bool,
}

/// Reference grants → candidates (disk: the loop over `selected` after
/// `fetch_registry_references`).
pub(crate) fn build_candidates(
    selected: &[(String, String)],
    references: &HashMap<String, PackageVendorResult>,
    skipped: &mut Vec<SkippedPatch>,
) -> Vec<Candidate> {
    let skip = |purl: &str, uuid: &str, reason: &str| SkippedPatch {
        purl: purl.to_string(),
        uuid: uuid.to_string(),
        reason: reason.to_string(),
        detail: None,
    };
    let mut candidates = Vec::new();
    for (sel_purl, sel_uuid) in selected {
        let Some(reference) = references.get(sel_uuid) else {
            skipped.push(skip(sel_purl, sel_uuid, "not_found"));
            continue;
        };
        if reference.status != "granted" && reference.status != "reused" {
            skipped.push(skip(sel_purl, sel_uuid, &reference.status));
            continue;
        }
        let purl = reference.purl.as_deref().unwrap_or(sel_purl);
        let Some((ecosystem, name, version)) = purl_parts(purl) else {
            skipped.push(skip(purl, sel_uuid, "bad_purl"));
            continue;
        };
        let Some(url) = reference.url.clone() else {
            skipped.push(skip(purl, sel_uuid, "no_url"));
            continue;
        };
        let mut integrity = reference
            .artifacts
            .iter()
            .flatten()
            .find(|a| a.kind == "tarball")
            .map(|a| a.integrity.clone())
            .unwrap_or_default();
        let berry_zip = reference
            .artifacts
            .iter()
            .flatten()
            .find(|a| a.kind == "yarn-berry-zip");
        if let Some(c) = berry_zip.and_then(|a| a.integrity.yarn_berry10c0.clone()) {
            integrity.yarn_berry10c0 = Some(c);
        }
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
        let token = reference
            .registry_override
            .as_ref()
            .and_then(|o| {
                socket_patch_core::patch::redirect::grant_token_path_segment(&o.index_url, sel_uuid)
            })
            .or_else(|| {
                socket_patch_core::patch::redirect::grant_token_path_segment(&url, sel_uuid)
            })
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

/// The ecosystem a candidate file's rewriter belongs to (`None` for files
/// no rewriter edits), for the symlinked-read refusal.
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
        _ if socket_patch_core::utils::python_lock::is_python_lock_name(base)
            || base.ends_with(".py") =>
        {
            "pypi"
        }
        _ => return None,
    })
}

/// A project's state between the reference grants and the wheel-metadata
/// fetch.
#[derive(Debug)]
pub(crate) struct Planned {
    pub(crate) project: MemoryProject,
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) skipped: Vec<SkippedPatch>,
    pub(crate) pre_warnings: Vec<serde_json::Value>,
    pub(crate) files: BTreeMap<String, String>,
    pub(crate) rush_lock_keys: Vec<String>,
    pub(crate) bun_lock_present: bool,
    /// Candidate files the disk flow reads through a symbolic link: their
    /// bytes are unknown here, so a project whose candidates could rewrite
    /// one is refused like the disk symlink guard refuses the write.
    pub(crate) symlinked_reads: Vec<String>,
    /// Candidate files that exist without content: a project whose
    /// candidates could rewrite (or whose rewrite depends on) one is
    /// refused, since the rewriters would treat it as absent.
    pub(crate) unreadable_reads: Vec<String>,
    /// `(artifact url, sha256)` of every pypi wheel whose metadata a
    /// native lock rewrite needs.
    pub(crate) wheels: Vec<(String, String)>,
    /// The vlt artifact preflight, judged offline (see
    /// [`crate::commands::scan::hosted::vlt::offline_preflight`]).
    pub(crate) vlt_preflight: crate::commands::scan::hosted::vlt::Preflight,
}

/// A refused project: its error and whatever was skipped before it.
#[derive(Debug)]
pub(crate) struct Refused {
    pub(crate) error: ProjectError,
}

fn refusal(code: &str, message: String) -> Refused {
    Refused {
        error: ProjectError {
            code: code.to_string(),
            message,
        },
    }
}

fn unreadable_refusal(rel: &str) -> Refused {
    refusal(
        UNREADABLE_REFUSAL,
        format!(
            "{rel} exists but its content was not provided (too large, an LFS pointer, or \
             not fetched), so it cannot be rewritten alongside the other lockfiles; nothing \
             was written"
        ),
    )
}

fn symlink_refusal(linked: &str) -> Refused {
    refusal(
        SYMLINK_REFUSAL,
        format!(
            "{linked} is a symbolic link; socket-patch rewrites files in place with an atomic \
             rename, which would replace the link — replace the link with a regular file (or \
             run socket-patch in the directory it points to) and re-run; nothing was written"
        ),
    )
}

/// The vendored ledger's entries (the disk `vendor::load_state` parse,
/// including its legacy `{mode}`-only shape); `None` when absent or
/// unreadable.
pub(crate) fn vendored_entries(project: &MemoryProject) -> Option<VendorState> {
    let bytes: Vec<u8> = match project.get(VENDOR_STATE_REL)? {
        MemoryEntry::Text(text) => text.as_bytes().to_vec(),
        MemoryEntry::Binary(bytes) => bytes.to_vec(),
        _ => return None,
    };
    match serde_json::from_slice::<VendorState>(&bytes) {
        Ok(state) => Some(state),
        Err(_) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
            (value.get("mode").is_some() && value.get("entries").is_none()).then(VendorState::new)
        }
    }
}

/// Whether Socket-owned vendored `[patch.crates-io]` wiring for exactly
/// `name@version` is committed in the root manifest or (legacy) the
/// project's cargo config — the disk `socket_wiring_present` probe over
/// the in-memory files. The config cargo reads is `.cargo/config` when it
/// exists, else `.cargo/config.toml`.
fn cargo_vendored_wiring(files: &MemoryProject, name: &str, version: &str) -> bool {
    use socket_patch_core::vendor::cargo_manifest::{
        crates_io_patch_entries, entry_wires, parse_manifest,
    };
    let manifest_wired = files
        .text("Cargo.toml")
        .and_then(|text| parse_manifest(text).ok())
        .is_some_and(|doc| {
            crates_io_patch_entries(&doc)
                .iter()
                .any(|e| entry_wires(e, name, version))
        });
    let config_rel = if files.contains(".cargo/config") {
        ".cargo/config"
    } else {
        ".cargo/config.toml"
    };
    let config_wired = files
        .text(config_rel)
        .and_then(|text| parse_manifest(text).ok())
        .is_some_and(|doc| {
            crates_io_patch_entries(&doc)
                .iter()
                .any(|e| e.source == "crates-io" && entry_wires(e, name, version))
        });
    manifest_wired || config_wired
}

/// Whether vlt's install state is in the file set: the hidden lock as a
/// file, or the store as a directory (the disk `install_state_present`).
fn vlt_install_state_present(project: &MemoryProject) -> bool {
    matches!(
        project.get(VLT_HIDDEN_LOCK_REL),
        Some(MemoryEntry::Text(_) | MemoryEntry::Binary(_) | MemoryEntry::Present)
    ) || project.is_dir(VLT_STORE_DIR)
}

/// The disk `vlt_inputs` over the file set: `vlt-lock.json` itself, and
/// presence-only entries for the sibling locks and vlt's install state.
/// Empty without a readable `vlt-lock.json`.
fn vlt_inputs(project: &MemoryProject) -> BTreeMap<String, String> {
    let mut files = BTreeMap::new();
    let lock = match project.get(VLT_LOCK) {
        Some(MemoryEntry::Text(text)) => text.to_string(),
        Some(MemoryEntry::Binary(bytes)) => match std::str::from_utf8(bytes) {
            Ok(text) => text.to_string(),
            Err(_) => return files,
        },
        _ => return files,
    };
    files.insert(VLT_LOCK.to_string(), lock);
    for sibling in [
        NPM_LOCK_NAMES[0],
        NPM_LOCK_NAMES[1],
        "yarn.lock",
        PNPM_LOCK,
        BUN_LOCK,
    ] {
        if matches!(
            project.get(sibling),
            Some(MemoryEntry::Text(_) | MemoryEntry::Binary(_) | MemoryEntry::Present)
        ) {
            files.insert(sibling.to_string(), String::new());
        }
    }
    if vlt_install_state_present(project) {
        files.insert(VLT_HIDDEN_LOCK_REL.to_string(), String::new());
    }
    files
}

/// Everything up to the wheel-metadata fetch.
pub(crate) fn plan(
    project: MemoryProject,
    unreadable: BTreeSet<String>,
    selected: &[(String, String)],
    references: &HashMap<String, PackageVendorResult>,
) -> Result<Planned, Refused> {
    let mut skipped: Vec<SkippedPatch> = Vec::new();
    let mut candidates = if selected.is_empty() {
        Vec::new()
    } else {
        build_candidates(selected, references, &mut skipped)
    };

    // The disk flow fetches each in-scope artifact the way vlt does before
    // anything else; with no network here every one is judged offline, so
    // the dep is withheld instead of pinned (`--offline` parity).
    let vlt_preflight = {
        let deps: Vec<(&str, &DepOverride)> = candidates
            .iter()
            .filter(|c| c.dep.ecosystem == "npm")
            .map(|c| (c.purl.as_str(), &c.dep))
            .collect();
        crate::commands::scan::hosted::vlt::offline_preflight(
            &vlt_inputs(&project),
            &deps,
            project.contains("bun.lockb"),
        )
    };
    if !vlt_preflight.withheld_everywhere.is_empty() {
        for (uuid, purl) in &vlt_preflight.withheld_everywhere {
            skipped.push(SkippedPatch {
                purl: purl.clone(),
                uuid: uuid.clone(),
                reason: crate::commands::scan::hosted::vlt::WITHHELD_REASON.to_string(),
                detail: None,
            });
        }
        candidates.retain(|c| {
            !vlt_preflight
                .withheld_everywhere
                .contains_key(&c.dep.patch_uuid)
        });
    }

    let bun_lock_present = project.contains("bun.lock");
    if candidates.iter().any(|c| c.dep.ecosystem == "npm")
        && !bun_lock_present
        && project.is_symlink("bun.lockb")
    {
        return Err(refusal(
            SYMLINK_REFUSAL,
            "bun.lockb is a symbolic link; replace it with a regular file (or run \
             socket-patch in the directory it points to) before patching; nothing was written"
                .to_string(),
        ));
    }

    let mut pre_warnings: Vec<serde_json::Value> = vlt_preflight.warnings.clone();
    let takeover_capable = |p: &str| {
        p.starts_with("pkg:cargo/") || p.starts_with("pkg:npm/") || p.starts_with("pkg:golang/")
    };
    if candidates.iter().any(|c| takeover_capable(&c.purl)) {
        let vendored = vendored_entries(&project);
        let mut refused: BTreeSet<String> = BTreeSet::new();
        for candidate in candidates.iter().filter(|c| takeover_capable(&c.purl)) {
            let has_entry = vendored.as_ref().is_some_and(|s| {
                socket_patch_core::vendor::lookup_entry(
                    &s.entries,
                    strip_purl_qualifiers(&candidate.purl),
                )
                .is_some()
            });
            let cargo_wired = !has_entry
                && candidate.purl.starts_with("pkg:cargo/")
                && cargo_vendored_wiring(&project, &candidate.dep.name, &candidate.dep.version);
            if has_entry || cargo_wired {
                refused.insert(candidate.purl.clone());
            }
        }
        if !refused.is_empty() {
            pre_warnings.push(serde_json::json!({
                "code": VENDORED_TAKEOVER_UNSUPPORTED,
                "detail": format!(
                    "{} currently vendored ({}); migrating a vendored package to hosted \
                     reverts its committed vendored wiring, which the in-memory hosted scan \
                     does not do — run `socket-patch scan --mode hosted` in a checkout to \
                     migrate, then re-run",
                    if refused.len() == 1 { "1 package is" } else { "packages are" },
                    refused.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            }));
            for c in candidates.iter().filter(|c| refused.contains(&c.purl)) {
                skipped.push(SkippedPatch {
                    purl: c.purl.clone(),
                    uuid: c.dep.patch_uuid.clone(),
                    reason: VENDORED_TAKEOVER_UNSUPPORTED.to_string(),
                    detail: None,
                });
            }
            candidates.retain(|c| !refused.contains(&c.purl));
        }
    }

    let mut files: BTreeMap<String, String> = BTreeMap::new();
    let mut rush_lock_keys: Vec<String> = Vec::new();
    let mut symlinked_reads: Vec<String> = Vec::new();
    let mut unreadable_reads: Vec<String> = Vec::new();
    if !candidates.is_empty() {
        let mut read = |rel: &str, files: &mut BTreeMap<String, String>| -> bool {
            if project.is_symlink(rel) {
                symlinked_reads.push(rel.to_string());
                return false;
            }
            if unreadable.contains(rel) {
                unreadable_reads.push(rel.to_string());
                return false;
            }
            // Disk reads any UTF-8 regular file; a non-UTF-8 one is absent
            // to it as well.
            let text = match project.get(rel) {
                Some(MemoryEntry::Text(text)) => Some(text.to_string()),
                Some(MemoryEntry::Binary(bytes)) => {
                    std::str::from_utf8(bytes).ok().map(str::to_string)
                }
                _ => None,
            };
            match text {
                Some(text) => {
                    files.insert(rel.to_string(), text);
                    true
                }
                None => false,
            }
        };
        for name in REDIRECT_CANDIDATE_FILES {
            if *name == "bun.lockb" {
                continue;
            }
            // The hidden lock is only the install-state sentinel, never read.
            if *name == VLT_HIDDEN_LOCK_REL {
                if vlt_install_state_present(&project) {
                    files.insert((*name).to_string(), String::new());
                }
                continue;
            }
            read(name, &mut files);
        }
        if files.contains_key("Cargo.toml") && candidates.iter().any(|c| c.dep.ecosystem == "cargo")
        {
            let view = socket_patch_core::vendor::lock_inventory::ProjectView::Memory(&project);
            for rel in socket_patch_core::utils::cargo_workspace::member_manifests_in(&view) {
                read(&rel, &mut files);
            }
        }
        let python_locks: Vec<String> = project
            .children("")
            .into_iter()
            .filter(|(name, is_dir)| {
                !is_dir && socket_patch_core::utils::python_lock::is_python_lock_name(name)
            })
            .map(|(name, _)| name)
            .collect();
        for path in python_locks {
            if let Some(script) = socket_patch_core::utils::python_lock::script_of_lock(&path) {
                read(script, &mut files);
            }
            read(&path, &mut files);
        }
        if project.contains("rush.json") {
            if read(RUSH_COMMON_LOCK_REL, &mut files) {
                rush_lock_keys.push(RUSH_COMMON_LOCK_REL.to_string());
            }
            for (name, is_dir) in project.children(RUSH_SUBSPACES_DIR) {
                if !is_dir {
                    continue;
                }
                let key = format!("{RUSH_SUBSPACES_DIR}/{name}/pnpm-lock.yaml");
                if read(&key, &mut files) {
                    rush_lock_keys.push(key);
                }
            }
        }
    }
    symlinked_reads.sort();
    symlinked_reads.dedup();
    unreadable_reads.sort();
    unreadable_reads.dedup();

    let mut wheels: Vec<(String, String)> = Vec::new();
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
        let native_target = files
            .iter()
            .filter(|(path, _)| {
                *path == "uv.lock"
                    || socket_patch_core::utils::python_lock::is_script_lock_name(path)
            })
            .any(|(_, text)| {
                socket_patch_core::utils::python_lock::rewrite_python_lock(
                    text,
                    &dep.name,
                    &dep.version,
                    socket_patch_core::utils::python_lock::ArtifactSource::Url(&dep.artifact_url),
                    sha256,
                )
                .ok()
                .flatten()
                .is_some()
            });
        if native_target {
            wheels.push((dep.artifact_url.clone(), sha256.to_string()));
        }
    }

    Ok(Planned {
        project,
        candidates,
        skipped,
        pre_warnings,
        files,
        rush_lock_keys,
        bun_lock_present,
        symlinked_reads,
        unreadable_reads,
        wheels,
        vlt_preflight,
    })
}

/// A project's rewrite, ready for the record fetch and the ledger merge.
#[derive(Debug)]
pub(crate) struct Rewritten {
    pub(crate) planned: Planned,
    pub(crate) rewrite: RewriteResult,
    pub(crate) rewritten: Vec<String>,
    pub(crate) confirmed: Vec<(String, String)>,
    pub(crate) rush_warnings: Vec<serde_json::Value>,
    pub(crate) pnpm_warnings: Vec<serde_json::Value>,
    pub(crate) npm_warnings: Vec<serde_json::Value>,
}

/// The `.npmrc` read the allow-remote planner classifies (disk:
/// `read_npmrc_for_allow_remote`).
fn read_npmrc(project: &MemoryProject) -> Result<Option<String>, String> {
    match project.get(NPMRC_REL) {
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
    }
}

/// Wheel metadata → rewrite → install-policy configs → confirmation →
/// symlink guard.
pub(crate) fn rewrite(
    mut planned: Planned,
    wheel_metadata: &BTreeMap<String, Result<Option<String>, String>>,
    options: StageOptions,
) -> Result<Rewritten, Refused> {
    let project = &planned.project;
    let files = &planned.files;

    let mut python_metadata: BTreeMap<String, String> = BTreeMap::new();
    let mut unavailable: BTreeSet<String> = BTreeSet::new();
    for (url, _) in &planned.wheels {
        match wheel_metadata.get(url) {
            Some(Ok(Some(metadata))) => {
                python_metadata.insert(url.clone(), metadata.clone());
            }
            Some(Ok(None)) => {}
            Some(Err(detail)) => {
                if unavailable.insert(url.clone()) {
                    for dep in planned
                        .candidates
                        .iter()
                        .map(|c| &c.dep)
                        .filter(|d| &d.artifact_url == url)
                    {
                        planned.skipped.push(SkippedPatch {
                            purl: format!("pkg:pypi/{}@{}", dep.name, dep.version),
                            uuid: dep.patch_uuid.clone(),
                            reason: "python_metadata_unavailable".to_string(),
                            detail: Some(detail.replace(&dep.artifact_url, "<hosted artifact>")),
                        });
                    }
                }
            }
            None => {
                unavailable.insert(url.clone());
            }
        }
    }
    planned
        .candidates
        .retain(|c| !unavailable.contains(&c.dep.artifact_url));
    let candidates = &planned.candidates;
    let overrides: Vec<DepOverride> = candidates.iter().map(|c| c.dep.clone()).collect();

    let targets_pipenv_lock =
        socket_patch_core::patch::redirect::pipenv_lock_targets(files, &overrides);
    let pipenv_major = if targets_pipenv_lock {
        options.pipenv_major
    } else {
        None
    };
    let binary_bun = !planned.bun_lock_present && project.contains("bun.lockb");
    let binary_content: Option<Result<Vec<u8>, RewriteWarning>> =
        if binary_bun && overrides.iter().any(|o| o.ecosystem == "npm") {
            let read = match project.get("bun.lockb") {
                Some(MemoryEntry::Binary(bytes)) => Ok(bytes.to_vec()),
                Some(MemoryEntry::Text(text)) => Ok(text.as_bytes().to_vec()),
                _ => Err("file content was not provided".to_string()),
            };
            Some(
                read.map_err(|e| RewriteWarning {
                    code: "redirect_bun_lockb_invalid".into(),
                    detail: format!("cannot read bun.lockb: {e}"),
                })
                .and_then(|bytes| {
                    socket_patch_core::patch::redirect::preflight_bun_binary(&bytes)?;
                    Ok(bytes)
                }),
            )
        } else {
            None
        };
    let rewrite_overrides: Vec<DepOverride> = overrides
        .iter()
        .filter(|o| !(binary_content.as_ref().is_some_and(Result::is_err) && o.ecosystem == "npm"))
        .cloned()
        .collect();
    let mut rewrite = rewrite_registry_redirect_withholding_vlt(
        files,
        &rewrite_overrides,
        &python_metadata,
        pipenv_major,
        project.contains("bun.lockb"),
        &planned.vlt_preflight.withheld_from_vlt,
    );
    if let Some(content) = binary_content {
        rewrite
            .warnings
            .retain(|w| w.code != "redirect_npm_no_lockfile");
        match content {
            Ok(bytes) => socket_patch_core::patch::redirect::rewrite_bun_binary(
                &bytes,
                &overrides,
                &mut rewrite,
            ),
            Err(warning) => rewrite.warnings.push(warning),
        }
    }

    if targets_pipenv_lock && pipenv_major.is_none() && rewrite.files.contains_key("Pipfile.lock") {
        rewrite.warnings.push(RewriteWarning {
            code: "redirect_pipenv_installer_unknown".into(),
            detail: "The scan did not set `pipenvMajor`, so the Pipfile.lock references use the modern `file` form (Pipenv 2018 and later). A project installed with Pipenv 7–11 needs `path` references instead: re-run the scan with `pipenvMajor` set to that Pipenv major version.".into(),
        });
    }

    let mut rush_warnings: Vec<serde_json::Value> = Vec::new();
    if planned
        .rush_lock_keys
        .iter()
        .any(|key| rewrite.files.contains_key(key))
        && (project.contains(RUSH_REPO_STATE_REL))
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

    let mut pnpm_warnings: Vec<serde_json::Value> = Vec::new();
    let mut trust_config_write: Option<(String, FileEdit)> = None;
    let mut workspace_symlink_write = false;
    {
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
        let heal_root: Option<&String> = pnpm_heal_root(
            rewrite.files.contains_key("pnpm-lock.yaml"),
            files.get("pnpm-lock.yaml"),
            &overrides,
        );
        if let Some(text) = heal_root {
            pnpm_lock_texts.push(text);
        }
        if !pnpm_lock_texts.is_empty() {
            let mut hosts: Vec<&str> = overrides
                .iter()
                .filter(|o| o.ecosystem == "npm")
                .filter(|o| {
                    let encoded =
                        socket_patch_core::utils::uri::encode_uri_component(&o.artifact_url);
                    pnpm_lock_texts.iter().any(|text| {
                        socket_patch_core::patch::redirect::artifact_url_present(
                            text,
                            &o.artifact_url,
                        ) || text.contains(encoded.as_str())
                    })
                })
                .filter_map(|o| url_host(&o.artifact_url))
                .collect();
            hosts.sort_unstable();
            hosts.dedup();
            let server = if hosts.is_empty() {
                "the hosted patch server".to_string()
            } else {
                format!("the hosted patch server ({})", hosts.join(", "))
            };
            let root_lock_v9 = heal_root
                .and_then(|text| pnpm_lock_version_major(text))
                .is_some_and(|major| major >= 9)
                || rewrite
                    .files
                    .get("pnpm-lock.yaml")
                    .and_then(|text| pnpm_lock_version_major(text))
                    .is_some_and(|major| major >= 9);
            let all_locks_legacy = pnpm_lock_texts.iter().all(|text| {
                pnpm_lock_version_major(text).is_some_and(|major| major < 9)
                    || text
                        .lines()
                        .any(|line| line.starts_with("shrinkwrapVersion:"))
            });
            let workspace: Result<Option<String>, std::io::Error> =
                match project.get(PNPM_WORKSPACE_REL) {
                    None => Ok(None),
                    Some(MemoryEntry::Text(text)) => Ok(Some(text.to_string())),
                    Some(MemoryEntry::Symlink) => {
                        workspace_symlink_write = true;
                        Ok(None)
                    }
                    Some(MemoryEntry::Binary(_)) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "stream did not contain valid UTF-8",
                    )),
                    Some(MemoryEntry::Present) => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "file content was not provided",
                    )),
                };
            let detail = if all_locks_legacy {
                workspace_symlink_write = false;
                pnpm_trust_legacy_detail(&server)
            } else if !root_lock_v9 || !options.trust_lockfile_config {
                workspace_symlink_write = false;
                pnpm_trust_manual_guidance(&server)
            } else {
                match workspace {
                    Err(e) => pnpm_trust_workspace_unreadable_detail(&server, &e),
                    Ok(ws_existing) => match plan_workspace_trust(ws_existing.as_deref()) {
                        TrustPlan::Create(text) => {
                            trust_config_write = Some((
                                text,
                                FileEdit {
                                    path: PNPM_WORKSPACE_REL.into(),
                                    kind: REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND.into(),
                                    action: "created".into(),
                                    key: Some("trustLockfile".into()),
                                    original: None,
                                    new: Some(serde_json::json!("true")),
                                },
                            ));
                            pnpm_trust_configured_detail(&server, true, options.dry_run)
                        }
                        TrustPlan::Append(text) => {
                            trust_config_write = Some((
                                text,
                                FileEdit {
                                    path: PNPM_WORKSPACE_REL.into(),
                                    kind: REDIRECT_PNPM_WORKSPACE_TRUST_EDIT_KIND.into(),
                                    action: "added".into(),
                                    key: Some("trustLockfile".into()),
                                    original: None,
                                    new: Some(serde_json::json!("true")),
                                },
                            ));
                            pnpm_trust_configured_detail(&server, false, options.dry_run)
                        }
                        TrustPlan::AlreadyTrue => format!(
                            "{}, and {PNPM_WORKSPACE_REL} already carries `trustLockfile: \
                             true` — keep it committed alongside the lock; installs need \
                             no extra flags. {PNPM_TRUST_TRADEOFF_AND_CAUTION}",
                            pnpm_trust_policy_preamble(&server),
                        ),
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
        }
    }
    if workspace_symlink_write {
        return Err(symlink_refusal(PNPM_WORKSPACE_REL));
    }

    let mut npm_warnings: Vec<serde_json::Value> = Vec::new();
    let mut npmrc_config_write: Option<(String, FileEdit)> = None;
    {
        let npm_hosts: Vec<&str> = {
            let mut hosts: Vec<&str> = overrides
                .iter()
                .filter(|o| o.ecosystem == "npm")
                .filter(|o| {
                    NPM_LOCKS.iter().any(|lock| {
                        rewrite
                            .files
                            .get(*lock)
                            .or_else(|| files.get(*lock))
                            .is_some_and(|text| {
                                socket_patch_core::patch::redirect::artifact_url_present(
                                    text,
                                    &o.artifact_url,
                                )
                            })
                    })
                })
                .filter_map(|o| url_host(&o.artifact_url))
                .collect();
            hosts.sort_unstable();
            hosts.dedup();
            hosts
        };
        if !npm_hosts.is_empty() {
            let edit = |action: &str| FileEdit {
                path: NPMRC_REL.into(),
                kind: NPMRC_ALLOW_REMOTE_EDIT_KIND.into(),
                action: action.into(),
                key: Some("allow-remote".into()),
                original: None,
                new: Some(serde_json::json!("all")),
            };
            let outer = OuterAllowRemote::default();
            let detail = match read_npmrc(project) {
                Ok(existing) => match plan_npmrc_allow_remote_with(existing.as_deref(), &outer) {
                    NpmrcPlan::AlreadyAll => npm_allow_remote_already_detail(&npm_hosts),
                    NpmrcPlan::UserSet(value) => {
                        npm_allow_remote_user_set_detail(&npm_hosts, &value)
                    }
                    NpmrcPlan::EnvSet { var, value } => {
                        npm_allow_remote_env_set_detail(&npm_hosts, &var, &value)
                    }
                    NpmrcPlan::OuterSet { layer, path, value } => {
                        npm_allow_remote_outer_set_detail(&npm_hosts, layer, &path, &value)
                    }
                    NpmrcPlan::Unsupported(why) => {
                        npm_allow_remote_unreadable_detail(&npm_hosts, &why)
                    }
                    _ if !options.npm_allow_remote_config => {
                        npm_allow_remote_manual_detail(&npm_hosts)
                    }
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
        }
    }
    if let Some((text, edit)) = trust_config_write {
        rewrite.files.insert(PNPM_WORKSPACE_REL.to_string(), text);
        rewrite.edits.push(edit);
    }
    if let Some((text, edit)) = npmrc_config_write {
        rewrite.files.insert(NPMRC_REL.to_string(), text);
        rewrite.edits.push(edit);
    }
    let rewritten: Vec<String> = rewrite
        .files
        .keys()
        .chain(rewrite.binary_files.keys())
        .cloned()
        .collect();

    let pdm_inactive =
        files.contains_key("pdm.lock") && !socket_patch_core::patch::redirect::pdm_drives(files);
    // A `vlt-lock.json` the vlt rewrite was withheld from may still hold an
    // earlier run's pin: only the sibling lock this run rewrote confirms it.
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
    let confirmed: Vec<(String, String)> = candidates
        .iter()
        .filter(|c| {
            let purl = c.purl.as_str();
            let uuid = c.dep.patch_uuid.as_str();
            // vlt decides before the binary-bun rule, as on disk.
            if rewrite.refused_vlt_uuids.contains(uuid) {
                return false;
            }
            if rewrite.vlt_drives && purl.starts_with("pkg:npm/") {
                return rewrite.confirmed_vlt_uuids.contains(uuid);
            }
            if binary_bun && purl.starts_with("pkg:npm/") {
                return rewrite.confirmed_bun_binary_uuids.contains(uuid);
            }
            if rewrite.refused_pipenv_uuids.contains(uuid) {
                return false;
            }
            if rewrite.refused_pdm_uuids.contains(uuid) {
                return false;
            }
            if purl.starts_with("pkg:pypi/")
                && socket_patch_core::patch::redirect::pdm_drives(files)
            {
                return rewrite.confirmed_pdm_uuids.contains(uuid);
            }
            if rewrite.python_lock_uuids.contains(uuid) {
                return rewrite.confirmed_python_lock_uuids.contains(uuid)
                    && !rewrite.refused_python_lock_uuids.contains(uuid);
            }
            if rewrite.hatch_uuids.contains(uuid) {
                return rewrite.confirmed_hatch_uuids.contains(uuid);
            }
            if purl.starts_with("pkg:pypi/") {
                return rewrite.confirmed_pipenv_uuids.contains(uuid)
                    || rewrite.confirmed_requirements_uuids.contains(uuid);
            }
            if rewrite.refused_pnpm_uuids.contains(uuid) {
                return false;
            }
            if purl.starts_with("pkg:cargo/") {
                return rewrite.confirmed_cargo_uuids.contains(uuid);
            }
            if purl.starts_with("pkg:golang/") {
                return rewrite.confirmed_golang_uuids.contains(uuid);
            }
            let artifact_url = c.dep.artifact_url.as_str();
            let registry = c.dep.registry_override.as_ref();
            let index_url = registry.map(|o| o.index_url.as_str());
            let suffixed_version =
                registry.and_then(|o| o.identifiers.maven_suffixed_version.as_deref());
            let encoded = socket_patch_core::utils::uri::encode_uri_component(artifact_url);
            let vlt_withheld = planned.vlt_preflight.withheld_from_vlt.contains(uuid);
            final_texts.iter().any(|(name, text)| {
                if vlt_withheld && *name == VLT_LOCK {
                    return false;
                }
                socket_patch_core::patch::redirect::artifact_url_present(text, artifact_url)
                    || text.contains(encoded.as_str())
                    || index_url.is_some_and(|iu| text.contains(iu))
                    || suffixed_version.is_some_and(|sv| text.contains(sv))
            })
        })
        .map(|c| (c.purl.clone(), c.dep.patch_uuid.clone()))
        .collect();

    if let Some(linked) = rewrite
        .files
        .keys()
        .chain(rewrite.binary_files.keys())
        .find(|k| project.is_symlink(k))
    {
        return Err(symlink_refusal(linked));
    }
    let candidate_ecosystems: BTreeSet<&str> = candidates
        .iter()
        .map(|c| c.dep.ecosystem.as_str())
        .collect();
    if let Some(linked) = planned
        .symlinked_reads
        .iter()
        .find(|rel| file_ecosystem(rel).is_some_and(|eco| candidate_ecosystems.contains(eco)))
    {
        return Err(symlink_refusal(linked));
    }
    if let Some(rel) = planned
        .unreadable_reads
        .iter()
        .find(|rel| {
            rewrite.files.contains_key(rel.as_str())
                || file_ecosystem(rel).is_some_and(|eco| candidate_ecosystems.contains(eco))
        })
        .or_else(|| {
            rewrite
                .files
                .keys()
                .find(|k| matches!(project.get(k), Some(MemoryEntry::Present)))
        })
    {
        return Err(unreadable_refusal(rel));
    }

    Ok(Rewritten {
        planned,
        rewrite,
        rewritten,
        confirmed,
        rush_warnings,
        pnpm_warnings,
        npm_warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn cargo_wiring_probe_is_scoped_to_the_crate_and_version() {
        let mut p = MemoryProject::new();
        p.insert_text(
            "Cargo.toml",
            "[package]\nname = \"app\"\n\n[dependencies]\nlog = \"0.4\"\ncc = \"1\"\n\n\
             [patch.crates-io]\nopenssl-socket-0123abcd = { package = \"openssl\", path = \
             \".socket/vendor/cargo/0123abcd-0000-4000-8000-000000000000/openssl-0.10.66\" }\n",
        );
        assert!(cargo_vendored_wiring(&p, "openssl", "0.10.66"));
        assert!(!cargo_vendored_wiring(&p, "openssl", "0.10.65"));
        assert!(!cargo_vendored_wiring(&p, "log", "0.4.22"));
        assert!(!cargo_vendored_wiring(&p, "cc", "1.1.0"));

        let mut legacy = MemoryProject::new();
        legacy.insert_text("Cargo.toml", "[package]\nname = \"app\"\n");
        let config = "[patch.crates-io]\ncc = { path = \
                      \".socket/vendor/cargo/0123abcd-0000-4000-8000-000000000000/cc-1.1.0\" }\n";
        legacy.insert_text(".cargo/config.toml", config);
        assert!(cargo_vendored_wiring(&legacy, "cc", "1.1.0"));
        // cargo reads the legacy spelling when it exists.
        legacy.insert_text(".cargo/config", "");
        assert!(!cargo_vendored_wiring(&legacy, "cc", "1.1.0"));
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

    #[test]
    fn an_unreadable_candidate_file_refuses_its_ecosystem() {
        let (selected, refs) = cargo_reference("u-1");
        let mut p = MemoryProject::new();
        p.insert_text("Cargo.toml", "[dependencies]\nserde = \"1\"\n");
        p.insert_text(
            "Cargo.lock",
            "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n\
             source = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
        );
        p.insert_present(".cargo/config");
        let options = StageOptions {
            dry_run: false,
            pipenv_major: None,
            trust_lockfile_config: true,
            npm_allow_remote_config: true,
        };
        let unreadable = BTreeSet::from([".cargo/config".to_string()]);
        let planned = plan(p.clone(), unreadable, &selected, &refs)
            .unwrap_or_else(|r| panic!("{:?}", r.error));
        assert_eq!(planned.unreadable_reads, vec![".cargo/config"]);
        let err = rewrite(planned, &BTreeMap::new(), options).unwrap_err();
        assert_eq!(err.error.code, UNREADABLE_REFUSAL);

        // A non-UTF-8 file is absent to disk too: not a refusal.
        let planned =
            plan(p, BTreeSet::new(), &selected, &refs).unwrap_or_else(|r| panic!("{:?}", r.error));
        assert!(planned.unreadable_reads.is_empty());
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
