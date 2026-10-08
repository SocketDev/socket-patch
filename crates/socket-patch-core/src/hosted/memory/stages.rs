//! One project root's hosted redirect over an in-memory file set: the
//! shared engine ([`crate::hosted::engine`]) over a
//! [`ProjectView::Memory`], split at the two provider round-trips the
//! engine batches across roots (wheel metadata, then patch records).
//! Everything that needs the host machine (the apply lock, vendored
//! takeover reverts, stale install probes, VEX, telemetry, subprocesses) is
//! left out; a vendored takeover is refused instead of performed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::api::types::PackageVendorResult;
use crate::hosted::engine::{
    self, Candidate, CandidateFiles, Refusal, RewriteOptions, SkippedPatch,
};
use crate::hosted::vlt::Preflight;
use crate::patch::redirect::npmrc::OuterAllowRemote;
use crate::patch::redirect::yarnrc::OuterYarnMirror;
use crate::patch::redirect::DepOverride;
use crate::utils::purl::strip_purl_qualifiers;
use crate::vendor::lock_inventory::{MemoryEntry, MemoryProject, ProjectView};
use crate::vendor::VendorState;

use super::select::VENDOR_STATE_REL;

/// Skip reason / warning code for a candidate the disk flow would migrate
/// from vendored to hosted (the migration reverts committed wiring, which
/// the in-memory engine does not do).
pub(crate) const VENDORED_TAKEOVER_UNSUPPORTED: &str = "vendored_takeover_unsupported_in_memory";

/// The engine-level options the per-root stages read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StageOptions {
    pub(crate) dry_run: bool,
    pub(crate) pipenv_major: Option<u32>,
    pub(crate) trust_lockfile_config: bool,
    pub(crate) npm_allow_remote_config: bool,
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
    use crate::vendor::cargo_manifest::{crates_io_patch_entries, entry_wires, parse_manifest};
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

/// Refuse (skip, with one warning) every candidate the disk flow would
/// take over from vendored mode.
fn refuse_takeovers(
    project: &MemoryProject,
    candidates: &mut Vec<Candidate>,
    skipped: &mut Vec<SkippedPatch>,
    pre_warnings: &mut Vec<crate::patch::redirect::RewriteWarning>,
) {
    let takeover_capable = |p: &str| {
        p.starts_with("pkg:cargo/") || p.starts_with("pkg:npm/") || p.starts_with("pkg:golang/")
    };
    if !candidates.iter().any(|c| takeover_capable(&c.purl)) {
        return;
    }
    let vendored = vendored_entries(project);
    let mut refused: BTreeSet<String> = BTreeSet::new();
    for candidate in candidates.iter().filter(|c| takeover_capable(&c.purl)) {
        let has_entry = vendored.as_ref().is_some_and(|s| {
            crate::vendor::lookup_entry(&s.entries, strip_purl_qualifiers(&candidate.purl))
                .is_some()
        });
        let cargo_wired = !has_entry
            && candidate.purl.starts_with("pkg:cargo/")
            && cargo_vendored_wiring(project, &candidate.dep.name, &candidate.dep.version);
        if has_entry || cargo_wired {
            refused.insert(candidate.purl.clone());
        }
    }
    if refused.is_empty() {
        return;
    }
    pre_warnings.push(engine::warning(
        VENDORED_TAKEOVER_UNSUPPORTED,
        format!(
            "{} currently vendored ({}); migrating a vendored package to hosted \
             reverts its committed vendored wiring, which the in-memory hosted scan \
             does not do — run `socket-patch scan --mode hosted` in a checkout to \
             migrate, then re-run",
            if refused.len() == 1 {
                "1 package is"
            } else {
                "packages are"
            },
            refused.iter().cloned().collect::<Vec<_>>().join(", ")
        ),
    ));
    for c in candidates.iter().filter(|c| refused.contains(&c.purl)) {
        skipped.push(SkippedPatch::new(
            &c.purl,
            &c.dep.patch_uuid,
            VENDORED_TAKEOVER_UNSUPPORTED,
        ));
    }
    candidates.retain(|c| !refused.contains(&c.purl));
}

/// A project's state between the reference grants and the wheel-metadata
/// fetch.
#[derive(Debug, Clone)]
pub(crate) struct Planned {
    pub(crate) project: MemoryProject,
    pub(crate) candidates: Vec<Candidate>,
    pub(crate) skipped: Vec<SkippedPatch>,
    pub(crate) pre_warnings: Vec<crate::patch::redirect::RewriteWarning>,
    pub(crate) read: CandidateFiles,
    /// `(artifact url, sha256)` of every pypi wheel whose metadata a
    /// native lock rewrite needs.
    pub(crate) wheels: Vec<(String, String)>,
    /// `(artifact url, sha512)` of every npm tarball whose own
    /// package.json a yarn berry pin needs (#718).
    pub(crate) npm_manifests: Vec<(String, Option<String>)>,
    /// The vlt artifact preflight, judged offline (no network here, so
    /// every in-scope dep is withheld instead of pinned: `--offline`
    /// parity).
    pub(crate) vlt_preflight: Preflight,
}

/// Everything up to the wheel-metadata fetch. `unreadable` are the paths
/// that exist without content.
pub(crate) async fn plan(
    project: MemoryProject,
    unreadable: BTreeSet<String>,
    selected: &[(String, String)],
    references: &HashMap<String, PackageVendorResult>,
) -> Result<Planned, Refusal> {
    let mut skipped: Vec<SkippedPatch> = Vec::new();
    let mut candidates = if selected.is_empty() {
        Vec::new()
    } else {
        engine::build_candidates(selected, references, &mut skipped)
    };
    let view = ProjectView::Memory(&project);
    if engine::bun_lockb_symlinked(&view, &candidates) {
        return Err(engine::bun_lockb_symlink_refusal());
    }
    let vlt_preflight = {
        let deps: Vec<(&str, &DepOverride)> = candidates
            .iter()
            .filter(|c| c.dep.ecosystem == "npm")
            .map(|c| (c.purl.as_str(), &c.dep))
            .collect();
        crate::hosted::vlt::offline(&view, &deps).await
    };
    engine::withhold_everywhere(
        &mut candidates,
        &vlt_preflight.withheld_everywhere,
        &mut skipped,
    );
    let mut pre_warnings = vlt_preflight.warnings.clone();
    refuse_takeovers(&project, &mut candidates, &mut skipped, &mut pre_warnings);

    let read = if candidates.is_empty() {
        CandidateFiles::default()
    } else {
        engine::read_candidate_files(&view, &unreadable, &candidates).await
    };
    let wheels = engine::wheel_targets(&candidates, &read.files)
        .into_iter()
        .map(|(dep, sha256)| (dep.artifact_url.clone(), sha256.to_string()))
        .collect();
    let npm_manifests = engine::yarn_berry_manifest_targets(&candidates, &read.files)
        .into_iter()
        .map(|dep| (dep.artifact_url.clone(), dep.integrity.sha512.clone()))
        .collect();
    Ok(Planned {
        project,
        candidates,
        skipped,
        pre_warnings,
        read,
        wheels,
        npm_manifests,
        vlt_preflight,
    })
}

/// A project's rewrite, ready for the record fetch and the ledger merge.
#[derive(Debug)]
pub(crate) struct Rewritten {
    pub(crate) project: MemoryProject,
    pub(crate) skipped: Vec<SkippedPatch>,
    pub(crate) pre_warnings: Vec<crate::patch::redirect::RewriteWarning>,
    pub(crate) done: engine::Rewritten,
    /// Granted candidates nothing pins ([`engine::unconfirmed_candidates`]).
    pub(crate) unconfirmed: Vec<(String, String)>,
}

/// A refused rewrite: its refusal and the skips recorded before the
/// wheel-metadata step.
#[derive(Debug)]
pub(crate) struct RewriteRefused {
    pub(crate) refusal: Refusal,
    pub(crate) skipped: Vec<SkippedPatch>,
}

/// Wheel metadata and served npm manifests (keyed by artifact URL) → the
/// engine's rewrite → the guard.
pub(crate) async fn rewrite(
    planned: Planned,
    artifact_metadata: &BTreeMap<String, Result<Option<String>, String>>,
    options: StageOptions,
) -> Result<Rewritten, RewriteRefused> {
    let Planned {
        project,
        mut candidates,
        mut skipped,
        pre_warnings,
        read,
        wheels,
        npm_manifests,
        vlt_preflight,
    } = planned;
    let skipped_before = skipped.clone();
    let mut python_metadata: BTreeMap<String, String> = BTreeMap::new();
    let mut unavailable: BTreeSet<String> = BTreeSet::new();
    for (url, _) in &wheels {
        match artifact_metadata.get(url) {
            Some(Ok(Some(metadata))) => {
                python_metadata.insert(url.clone(), metadata.clone());
            }
            Some(Ok(None)) => {}
            Some(Err(detail)) => {
                if unavailable.insert(url.clone()) {
                    for dep in candidates
                        .iter()
                        .map(|c| &c.dep)
                        .filter(|d| &d.artifact_url == url)
                    {
                        skipped.push(engine::wheel_metadata_unavailable(dep, detail));
                    }
                }
            }
            None => {
                unavailable.insert(url.clone());
            }
        }
    }
    for (url, _) in &npm_manifests {
        match artifact_metadata.get(url) {
            Some(Ok(Some(manifest))) => {
                python_metadata.insert(url.clone(), manifest.clone());
            }
            Some(Err(detail)) => {
                if unavailable.insert(url.clone()) {
                    for dep in candidates
                        .iter()
                        .map(|c| &c.dep)
                        .filter(|d| &d.artifact_url == url)
                    {
                        skipped.push(engine::npm_manifest_unavailable(dep, detail));
                    }
                }
            }
            Some(Ok(None)) | None => {
                unavailable.insert(url.clone());
            }
        }
    }
    candidates.retain(|c| !unavailable.contains(&c.dep.artifact_url));

    let view = ProjectView::Memory(&project);
    let targets_pipenv_lock = engine::pipenv_lock_targets(&read.files, &candidates);
    // The in-memory host sees no user / global npm or yarn config.
    let npm_outer = OuterAllowRemote::default;
    let yarn_classic_outer = OuterYarnMirror::default;
    let done = engine::rewrite(
        &view,
        read,
        &candidates,
        python_metadata,
        &vlt_preflight.withheld_from_vlt,
        &[],
        RewriteOptions {
            dry_run: options.dry_run,
            targets_pipenv_lock,
            pipenv_major: if targets_pipenv_lock {
                options.pipenv_major
            } else {
                None
            },
            pipenv_unknown_detail: "The scan did not set `pipenvMajor`, so the Pipfile.lock \
                references use the modern `file` form (Pipenv 2018 and later). A project \
                installed with Pipenv 7–11 needs `path` references instead: re-run the scan \
                with `pipenvMajor` set to that Pipenv major version."
                .to_string(),
            trust_lockfile_config: options.trust_lockfile_config,
            npm_allow_remote_config: options.npm_allow_remote_config,
            npm_outer: &npm_outer,
            yarn_classic_outer: &yarn_classic_outer,
            blocking: false,
            takeover_uuids: Default::default(),
            patch_server_origins: Vec::new(),
            prior_discovery: None,
        },
    )
    .await;
    if let Some(refusal) = engine::guard(&view, &done, &candidates) {
        return Err(RewriteRefused {
            refusal,
            skipped: skipped_before,
        });
    }
    skipped.extend(done.unattributed.iter().cloned());
    let unconfirmed = engine::unconfirmed_candidates(&candidates, &done.confirmed, &skipped);
    Ok(Rewritten {
        project,
        skipped,
        pre_warnings,
        done,
        unconfirmed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
