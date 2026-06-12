//! `repair`'s vendored-artifact phase: rebuild committed vendor artifacts
//! that are referenced (ledger entry and/or rewired lockfile) but missing
//! or corrupt on disk.
//!
//! Detection is the core health check ([`check_vendored_artifact`]: per-file
//! afterHashes + the whole-file ledger sha256 for file-shaped artifacts).
//! Rebuilds re-dispatch the normal vendor backends — their wired hot paths
//! rebuild the ARTIFACT only and never touch lockfiles or re-record ledger
//! originals — fed by the same pristine-source ladder as `vendor` (installed
//! copy → lockfile-verified registry fetch → ledger-recovered pre-vendor
//! fragment), with patch content staged in memory.
//!
//! Lockfile references with NO ledger coverage (`.socket/vendor` deleted
//! wholesale, state.json included) are RECONSTRUCTED: the uuid is recovered
//! from the lockfile path itself (the contract's uuid-in-path rule), the
//! record from the manifest (or the patch API, yielding a detached entry),
//! and a fresh ledger entry is re-synthesized so sweep/GC/revert know the
//! artifact again. Reconstructed entries carry no pre-vendor wiring
//! originals — `--revert` degrades to its documented
//! `vendor_lock_entry_drifted` re-resolve guidance.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::copy_tree::remove_tree;
use socket_patch_core::patch::vendor::{
    self, check_vendored_artifact, file_sha256_hex, load_state, lock_inventory, parse_vendor_path,
    registry_fetch, ArtifactHealth, VendorEntry,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::vex::time::now_rfc3339;

use crate::args::GlobalArgs;
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::vendor::{
    dispatch_vendor_one, ecosystem_in_scope, fetch_pristine_package, persist_vendor_entry,
    record_warning, PristineFetch,
};
use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};
use crate::json_envelope::{Envelope, PatchAction, PatchEvent};

/// Counts surfaced to `repair_inner` for telemetry/human output.
#[derive(Default)]
pub(crate) struct RepairVendorCounts {
    pub rebuilt: usize,
    pub failed: usize,
    pub healthy: usize,
}

/// One broken vendored unit queued for rebuild.
struct Candidate {
    purl: String,
    entry: VendorEntry,
    record: PatchRecord,
    detached: bool,
    /// True when the ledger entry was re-synthesized from a lockfile
    /// reference (it must be persisted after a successful rebuild).
    reconstructed: bool,
    reason: &'static str,
}

/// Files the vendor backends rewire — the search space for
/// `.socket/vendor/<eco>/<uuid>/<leaf>` references when the ledger is gone.
const WIRING_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "package.json",
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "go.mod",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "uv.lock",
    "pyproject.toml",
    "poetry.lock",
    "pdm.lock",
    "Pipfile.lock",
    "requirements.txt",
];

/// Scan the wiring-bearing files for vendored-artifact references,
/// returning deduped `(ecosystem, uuid, artifact relpath)` triples. Pure
/// text scan + the canonical path parser — the same recovery rule the CLI
/// contract documents for external tools.
pub(crate) async fn scan_vendor_references(project_root: &Path) -> Vec<(String, String, String)> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for file in WIRING_FILES {
        let Ok(text) = tokio::fs::read_to_string(project_root.join(file)).await else {
            continue;
        };
        let mut rest = text.as_str();
        while let Some(idx) = rest.find(".socket") {
            let slice = &rest[idx..];
            // `:` ends a reference too: pnpm snapshot keys are
            // `name@file:<path>:` and yaml mappings suffix the path with a
            // colon — npm names/versions never contain one.
            let end = slice
                .find([
                    '"', '\'', '`', ' ', '\t', '\n', '\r', ',', ')', ']', '}', ';', ':',
                ])
                .unwrap_or(slice.len());
            let candidate = slice[..end].replace('\\', "/");
            if let Some(parts) = parse_vendor_path(&candidate) {
                if seen.insert((parts.eco.to_string(), parts.uuid.clone())) {
                    out.push((
                        parts.eco.to_string(),
                        parts.uuid.clone(),
                        candidate.trim_start_matches("./").to_string(),
                    ));
                }
            }
            rest = &rest[idx + ".socket".len()..];
        }
    }
    out.sort();
    out
}

fn synth_entry(eco: &str, uuid: &str, artifact_path: &str, base_purl: &str) -> VendorEntry {
    VendorEntry {
        ecosystem: eco.to_string(),
        base_purl: base_purl.to_string(),
        uuid: uuid.to_string(),
        artifact: socket_patch_core::patch::vendor::state::VendorArtifact {
            path: artifact_path.to_string(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
        },
        wiring: Vec::new(),
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: None,
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    }
}

fn fail(
    env: &mut Envelope,
    counts: &mut RepairVendorCounts,
    quiet: bool,
    purl: &str,
    code: &str,
    detail: String,
) {
    if !quiet {
        eprintln!(
            "Cannot repair vendored artifact for {}: {detail}",
            socket_patch_core::utils::purl::normalize_purl(purl)
        );
    }
    env.record(PatchEvent::new(PatchAction::Failed, purl.to_string()).with_error(code, detail));
    env.mark_partial_failure();
    counts.failed += 1;
}

/// The vendored-artifact phase of `repair`. Runs between the download and
/// cleanup phases (and under `--download-only` — restoring artifacts IS
/// repair's job). `manifest` is `None` when the project has no
/// `.socket/manifest.json` (detached/reconstruction-only repairs).
pub(crate) async fn repair_vendored_artifacts(
    common: &GlobalArgs,
    manifest: Option<&PatchManifest>,
    socket_dir: &Path,
    env: &mut Envelope,
) -> RepairVendorCounts {
    let quiet = common.json || common.silent;
    let mut counts = RepairVendorCounts::default();

    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            env.record(
                PatchEvent::artifact(PatchAction::Failed)
                    .with_error("vendor_state_unreadable", e.to_string()),
            );
            env.mark_partial_failure();
            counts.failed += 1;
            return counts;
        }
    };

    // ── Pass 1: ledger-driven health check ───────────────────────────────
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut ledger_purls: Vec<String> = state.entries.keys().cloned().collect();
    ledger_purls.sort();
    for purl in &ledger_purls {
        let entry = state.entries[purl].clone();
        if !ecosystem_in_scope(common, &entry.ecosystem) {
            continue;
        }
        let record = match (&entry.record, manifest) {
            (Some(r), _) => r.clone(),
            (None, Some(m)) => {
                match m
                    .patches
                    .get(purl)
                    .cloned()
                    .or_else(|| m.patches.values().find(|r| r.uuid == entry.uuid).cloned())
                {
                    Some(r) => r,
                    // Dropped from the manifest: the vendor reconcile owns
                    // reverting it — not repair's call.
                    None => continue,
                }
            }
            // Non-detached entry with no manifest at all: recover the
            // record from the API below, like a reconstruction.
            (None, None) => match fetch_record_by_uuid(common, &entry.uuid).await {
                Some((_, r)) => r,
                None => {
                    fail(
                        env,
                        &mut counts,
                        quiet,
                        purl,
                        "vendor_artifact_unrepairable",
                        format!(
                            "no manifest record for patch {} and the patch view could not \
                             be fetched (offline or API failure)",
                            entry.uuid
                        ),
                    );
                    continue;
                }
            },
        };
        if record.uuid != entry.uuid {
            env.record(
                PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                    "vendor_uuid_mismatch",
                    "the manifest's patch uuid moved on; run `socket-patch vendor` (or \
                     `scan --vendor`) to re-vendor",
                ),
            );
            continue;
        }
        match check_vendored_artifact(&common.cwd, &entry, &record).await {
            ArtifactHealth::Healthy => counts.healthy += 1,
            ArtifactHealth::StaleUuid => {
                env.record(
                    PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                        "vendor_uuid_mismatch",
                        "a re-vendor is pending for this package; run `socket-patch vendor`",
                    ),
                );
            }
            ArtifactHealth::Unverifiable { reason } => {
                fail(
                    env,
                    &mut counts,
                    quiet,
                    purl,
                    "vendor_artifact_unrepairable",
                    format!("the ledger entry cannot be verified ({reason}); fix state.json"),
                );
            }
            ArtifactHealth::Missing => {
                let detached = entry.detached;
                candidates.push(Candidate {
                    purl: purl.clone(),
                    entry,
                    record,
                    detached,
                    reconstructed: false,
                    reason: "vendor_artifact_missing",
                });
            }
            ArtifactHealth::Corrupt { .. } => {
                let detached = entry.detached;
                candidates.push(Candidate {
                    purl: purl.clone(),
                    entry,
                    record,
                    detached,
                    reconstructed: false,
                    reason: "vendor_artifact_corrupt",
                });
            }
        }
    }

    // ── Pass 2: lockfile references with no ledger coverage ─────────────
    let covered: HashSet<(String, String)> = state
        .entries
        .values()
        .map(|e| (e.ecosystem.clone(), e.uuid.clone()))
        .collect();
    for (eco, uuid, relpath) in scan_vendor_references(&common.cwd).await {
        if covered.contains(&(eco.clone(), uuid.clone())) || !ecosystem_in_scope(common, &eco) {
            continue;
        }
        // The record: manifest by uuid first, else the patch API (the entry
        // is then detached — exactly the manifest-less vendoring shape).
        let (purl, record, detached) =
            match manifest.and_then(|m| m.patches.iter().find(|(_, r)| r.uuid == uuid)) {
                Some((p, r)) => (p.clone(), r.clone(), false),
                None => match fetch_record_by_uuid(common, &uuid).await {
                    Some((purl, r)) => (purl, r, true),
                    None => {
                        fail(
                            env,
                            &mut counts,
                            quiet,
                            &format!("pkg:{eco}/unknown@{uuid}"),
                            "vendor_artifact_missing",
                            format!(
                                "the lockfile references .socket/vendor/{eco}/{uuid}/ but the \
                             vendor ledger is gone and the patch view could not be fetched \
                             (offline or API failure); restore .socket/vendor/state.json or \
                             re-run online"
                            ),
                        );
                        continue;
                    }
                },
            };
        let mut entry = synth_entry(&eco, &uuid, &relpath, strip_purl_qualifiers(&purl));
        entry.detached = detached;
        if detached {
            entry.record = Some(record.clone());
        }
        match check_vendored_artifact(&common.cwd, &entry, &record).await {
            ArtifactHealth::Healthy => {
                // The artifact survived; only the ledger was lost. Restore
                // the entry (sha/size recomputed) so GC/sweep/revert know
                // the artifact again — without it the next `scan --prune`
                // would sweep the uuid dir as an orphan.
                if common.dry_run {
                    env.record(
                        PatchEvent::new(PatchAction::Verified, purl.clone()).with_details(
                            serde_json::json!({
                                "vendorArtifact": true,
                                "wouldRestoreLedgerEntry": true,
                                "path": relpath,
                            }),
                        ),
                    );
                    continue;
                }
                fill_artifact_fingerprint(&common.cwd, &mut entry).await;
                let save_failed =
                    persist_vendor_entry(common, env, &mut state, &purl, entry, detached, &record)
                        .await;
                if save_failed {
                    counts.failed += 1;
                    continue;
                }
                env.record(
                    PatchEvent::new(PatchAction::Rebuilt, purl.clone()).with_details(
                        serde_json::json!({
                            "path": relpath,
                            "ledgerRestored": true,
                            "artifactRebuilt": false,
                        }),
                    ),
                );
                counts.rebuilt += 1;
            }
            _ => {
                candidates.push(Candidate {
                    purl,
                    entry,
                    record,
                    detached,
                    reconstructed: true,
                    reason: "vendor_artifact_missing",
                });
            }
        }
    }

    if candidates.is_empty() {
        return counts;
    }

    // ── Dry run: preview only ────────────────────────────────────────────
    if common.dry_run {
        for c in &candidates {
            env.record(
                PatchEvent::new(PatchAction::Verified, c.purl.clone()).with_details(
                    serde_json::json!({
                        "vendorArtifact": true,
                        "wouldRebuild": true,
                        "reason": c.reason,
                        "path": c.entry.artifact.path,
                    }),
                ),
            );
        }
        return counts;
    }

    if !quiet {
        println!(
            "\nRebuilding {} broken vendored artifact(s)...",
            candidates.len()
        );
    }

    // ── Corrupt artifacts are deleted first ──────────────────────────────
    // The backends' wired hot paths rebuild on MISSING; turning corrupt
    // into missing gives every ecosystem one uniform rebuild trigger (and
    // never leaves tampered bytes to be blended into a rebuild).
    for c in &candidates {
        if c.reason == "vendor_artifact_corrupt" {
            if let Some(rel) = vendor::path::vendor_uuid_dir_rel(&c.entry.ecosystem, &c.entry.uuid)
            {
                let _ = remove_tree(&common.cwd.join(rel)).await;
            }
        }
    }

    // ── Patch content (in memory, like all vendor flows) ────────────────
    let records_map: HashMap<String, PatchRecord> = candidates
        .iter()
        .map(|c| (c.purl.clone(), c.record.clone()))
        .collect();
    let synth = PatchManifest {
        patches: records_map,
        setup: None,
    };
    let staged = match stage_vendor_sources_in_memory(common, &synth, socket_dir, &common.cwd).await
    {
        Ok(MemStageOutcome::Ready(s)) => s,
        Ok(MemStageOutcome::Unavailable) => {
            for c in &candidates {
                fail(
                    env,
                    &mut counts,
                    quiet,
                    &c.purl,
                    c.reason,
                    format!(
                        "the vendored artifact at {} is broken and its patch content has \
                         no local source ({})",
                        c.entry.artifact.path,
                        if common.offline {
                            "--offline prevents fetching it"
                        } else {
                            "download failed"
                        }
                    ),
                );
            }
            return counts;
        }
        Err(e) => {
            env.record(PatchEvent::artifact(PatchAction::Failed).with_error("stage_failed", e));
            env.mark_partial_failure();
            counts.failed += candidates.len();
            return counts;
        }
    };
    let sources = staged.as_patch_sources();

    // ── Pristine package sources ─────────────────────────────────────────
    let purls: Vec<String> = candidates.iter().map(|c| c.purl.clone()).collect();
    let partitioned = partition_purls(&purls, common.ecosystems.as_deref());
    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
        batch_size: 100,
    };
    let mut all_packages = find_packages_for_purls(&partitioned, &crawler_options, quiet).await;
    let inventory = lock_inventory::inventory_project(&common.cwd).await;
    let client = registry_fetch::build_registry_client();
    let mut holders: Vec<registry_fetch::FetchedPackage> = Vec::new();
    let mut unrebuildable: HashSet<String> = HashSet::new();
    // Reconstructed npm candidates fetched UNVERIFIED from the conventional
    // registry: their rebuilt tarball MUST match the integrity the rewired
    // lockfile records (the trust anchor) before anything is persisted.
    let mut must_verify: HashMap<String, lock_inventory::LockIntegrity> = HashMap::new();
    for c in &candidates {
        if all_packages.contains_key(&c.purl) {
            continue; // installed copy: works offline too
        }
        if common.offline {
            fail(
                env,
                &mut counts,
                quiet,
                &c.purl,
                c.reason,
                format!(
                    "the vendored artifact at {} is broken, the package is not installed, \
                     and --offline prevents fetching a pristine copy",
                    c.entry.artifact.path
                ),
            );
            unrebuildable.insert(c.purl.clone());
            continue;
        }
        match fetch_pristine_package(&common.cwd, &inventory, &client, &c.purl, Some(&c.entry))
            .await
        {
            PristineFetch::Fetched(fetched) => {
                all_packages.insert(c.purl.clone(), fetched.dir().to_path_buf());
                holders.push(fetched);
            }
            PristineFetch::NoSource | PristineFetch::Unverifiable(_) => {
                // Last rung (npm): the REWIRED lockfile still records the
                // integrity of our packed tarball. Fetch the pristine copy
                // unverified, rebuild deterministically, and verify the
                // REBUILT artifact against that wired integrity below —
                // end-to-end fail-closed without ledger or installed copy.
                if c.entry.ecosystem == "npm" {
                    if let Some(wired) =
                        lock_inventory::wired_vendor_integrity(&common.cwd, &c.entry.artifact.path)
                            .await
                    {
                        if let Some((name, version)) = npm_coords(&c.entry.base_purl) {
                            match registry_fetch::fetch_npm_unverified(&name, &version, &client)
                                .await
                            {
                                Ok(fetched) => {
                                    all_packages
                                        .insert(c.purl.clone(), fetched.dir().to_path_buf());
                                    holders.push(fetched);
                                    must_verify.insert(c.purl.clone(), wired);
                                    continue;
                                }
                                Err(registry_fetch::FetchError::Failed(d))
                                | Err(registry_fetch::FetchError::Unverifiable(d)) => {
                                    fail(
                                        env,
                                        &mut counts,
                                        quiet,
                                        &c.purl,
                                        "vendor_fetch_failed",
                                        d,
                                    );
                                    unrebuildable.insert(c.purl.clone());
                                    continue;
                                }
                            }
                        }
                    }
                }
                let detail = fetch_pristine_unrepairable_detail(c).unwrap_or_else(|| {
                    "no verifiable pristine source: the package is not installed, the \
                     lockfile is rewired to the (broken) vendored artifact, and the \
                     ledger records no recoverable registry fragment"
                        .to_string()
                });
                fail(
                    env,
                    &mut counts,
                    quiet,
                    &c.purl,
                    "vendor_artifact_unrepairable",
                    detail,
                );
                unrebuildable.insert(c.purl.clone());
            }
            PristineFetch::Failed(detail) => {
                fail(
                    env,
                    &mut counts,
                    quiet,
                    &c.purl,
                    "vendor_fetch_failed",
                    detail,
                );
                unrebuildable.insert(c.purl.clone());
            }
        }
    }

    // ── Rebuild via the normal backends ──────────────────────────────────
    let vendored_at = now_rfc3339();
    for c in candidates {
        if unrebuildable.contains(&c.purl) {
            continue;
        }
        let Some(pkg_path) = all_packages.get(&c.purl).cloned() else {
            continue; // failed above
        };
        let outcome = dispatch_vendor_one(
            &c.purl,
            &pkg_path,
            &common.cwd,
            &c.record,
            &sources,
            &vendored_at,
            false,
            false,
        )
        .await;
        match outcome {
            None => {
                fail(
                    env,
                    &mut counts,
                    quiet,
                    &c.purl,
                    "vendor_artifact_unrepairable",
                    "no vendor backend for this ecosystem in this build".to_string(),
                );
            }
            Some(socket_patch_core::patch::vendor::VendorOutcome::Refused { code, detail }) => {
                fail(env, &mut counts, quiet, &c.purl, code, detail);
            }
            Some(socket_patch_core::patch::vendor::VendorOutcome::Done {
                result,
                entry,
                warnings,
            }) => {
                if !result.success {
                    fail(
                        env,
                        &mut counts,
                        quiet,
                        &c.purl,
                        "vendor_artifact_rebuild_failed",
                        result.error.unwrap_or_else(|| "rebuild failed".to_string()),
                    );
                    continue;
                }
                for w in &warnings {
                    // The Rebuilt event below carries the rebuild signal.
                    if w.code != "vendor_artifact_rebuilt" {
                        record_warning(env, &c.purl, w, common);
                    }
                }
                // Unverified pristine source: the rebuilt tarball must
                // reproduce the integrity the rewired lockfile records.
                if let Some(wired) = must_verify.get(&c.purl) {
                    let abs = common.cwd.join(&c.entry.artifact.path);
                    let verdict = match tokio::fs::read(&abs).await {
                        Ok(bytes) => {
                            let name = npm_coords(&c.entry.base_purl)
                                .map(|(n, _)| n)
                                .unwrap_or_default();
                            registry_fetch::artifact_matches_integrity(&bytes, &name, wired)
                        }
                        Err(e) => Err(format!("cannot read the rebuilt artifact: {e}")),
                    };
                    if let Err(detail) = verdict {
                        if let Some(rel) =
                            vendor::path::vendor_uuid_dir_rel(&c.entry.ecosystem, &c.entry.uuid)
                        {
                            let _ = remove_tree(&common.cwd.join(rel)).await;
                        }
                        fail(
                            env,
                            &mut counts,
                            quiet,
                            &c.purl,
                            "vendor_artifact_rebuild_failed",
                            format!(
                                "the rebuilt artifact does not match the integrity the \
                                 lockfile records ({detail}); the pristine source may have \
                                 been tampered with — nothing was kept"
                            ),
                        );
                        continue;
                    }
                }
                // The entry whose recorded fingerprint the post-check must
                // match: a backend-returned entry (drift healed / wiring
                // re-recorded) wins; a reconstructed entry gets its
                // fingerprint computed from the rebuilt bytes.
                let mut check_entry = c.entry.clone();
                if let Some(e) = entry {
                    check_entry = e.clone();
                    if persist_vendor_entry(
                        common, env, &mut state, &c.purl, e, c.detached, &c.record,
                    )
                    .await
                    {
                        counts.failed += 1;
                        continue;
                    }
                } else if c.reconstructed {
                    fill_artifact_fingerprint(&common.cwd, &mut check_entry).await;
                    if persist_vendor_entry(
                        common,
                        env,
                        &mut state,
                        &c.purl,
                        check_entry.clone(),
                        c.detached,
                        &c.record,
                    )
                    .await
                    {
                        counts.failed += 1;
                        continue;
                    }
                }
                // ── Fail-closed post-verify ──────────────────────────────
                match check_vendored_artifact(&common.cwd, &check_entry, &c.record).await {
                    ArtifactHealth::Healthy => {
                        if !quiet {
                            println!(
                                "Rebuilt {} ({})",
                                socket_patch_core::utils::purl::normalize_purl(&c.purl),
                                check_entry.artifact.path
                            );
                        }
                        env.record(
                            PatchEvent::new(PatchAction::Rebuilt, c.purl.clone()).with_details(
                                serde_json::json!({
                                    "path": check_entry.artifact.path,
                                    "reason": c.reason,
                                }),
                            ),
                        );
                        counts.rebuilt += 1;
                    }
                    other => {
                        // The deterministic rebuild did not reproduce the
                        // recorded artifact (e.g. a tampered ledger sha):
                        // remove it rather than leave unverifiable bytes.
                        if let Some(rel) = vendor::path::vendor_uuid_dir_rel(
                            &check_entry.ecosystem,
                            &check_entry.uuid,
                        ) {
                            let _ = remove_tree(&common.cwd.join(rel)).await;
                        }
                        fail(
                            env,
                            &mut counts,
                            quiet,
                            &c.purl,
                            "vendor_artifact_rebuild_failed",
                            format!(
                                "the rebuilt artifact does not match the recorded \
                                 fingerprint ({other:?}); if state.json was edited, run \
                                 `socket-patch vendor` to re-vendor from scratch",
                            ),
                        );
                    }
                }
            }
        }
    }
    drop(holders);
    counts
}

/// Compute and record the artifact fingerprint (sha256 + size for
/// file-shaped artifacts) on a re-synthesized ledger entry.
async fn fill_artifact_fingerprint(project_root: &Path, entry: &mut VendorEntry) {
    let norm = entry.artifact.path.replace('\\', "/");
    if !(norm.ends_with(".tgz") || norm.ends_with(".tar.gz") || norm.ends_with(".whl")) {
        return; // dir-shaped: integrity is per-file afterHashes
    }
    let abs = project_root.join(&norm);
    if let Some(hex) = file_sha256_hex(&abs).await {
        entry.artifact.sha256 = hex;
    }
    if let Ok(meta) = tokio::fs::metadata(&abs).await {
        entry.artifact.size = Some(meta.len());
    }
}

/// Fetch one patch view by uuid (proxy-aware) and shape it as a manifest
/// record; `None` offline or on any API failure.
async fn fetch_record_by_uuid(common: &GlobalArgs, uuid: &str) -> Option<(String, PatchRecord)> {
    if common.offline {
        return None;
    }
    let (client, _) = get_api_client_with_overrides(common.api_client_overrides()).await;
    let patch = client
        .fetch_patch(common.org.as_deref(), uuid)
        .await
        .ok()??;
    Some(crate::commands::get::record_from_patch_response(&patch))
}

/// `pkg:npm/<name>@<version>` → (name, version); the name may be scoped.
fn npm_coords(base_purl: &str) -> Option<(String, String)> {
    let rest = strip_purl_qualifiers(base_purl).strip_prefix("pkg:npm/")?;
    let (name, version) = rest.rsplit_once('@')?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// A more specific unrepairable detail when one is knowable from the entry.
fn fetch_pristine_unrepairable_detail(c: &Candidate) -> Option<String> {
    if c.entry.artifact.platform_locked == Some(true) {
        Some(
            "the vendored wheel is platform-locked (compiled); reinstall the package on \
             this platform and re-run repair, or run `socket-patch vendor` to rebuild it"
                .to_string(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// pnpm writes vendored paths in THREE spellings — override values,
    /// `tarball:` fields, and snapshot KEYS with a trailing colon. The
    /// scanner must yield the clean relpath whichever form it meets first.
    #[tokio::test]
    async fn scan_handles_pnpm_snapshot_key_colons() {
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "11111111-1111-4111-8111-111111111111";
        let lock = format!(
            "overrides:\n  left-pad@1.3.0: file:.socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz\n\n\
             snapshots:\n\n  left-pad@file:.socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz:\n    {{}}\n"
        );
        tokio::fs::write(tmp.path().join("pnpm-lock.yaml"), &lock)
            .await
            .unwrap();
        let refs = scan_vendor_references(tmp.path()).await;
        assert_eq!(refs.len(), 1, "{refs:?}");
        assert_eq!(
            refs[0].2,
            format!(".socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz"),
            "no trailing colon: {refs:?}"
        );

        // Snapshot-key-only lock (the key form is the FIRST occurrence).
        let lock = format!(
            "snapshots:\n\n  left-pad@file:.socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz:\n    {{}}\n"
        );
        tokio::fs::write(tmp.path().join("pnpm-lock.yaml"), &lock)
            .await
            .unwrap();
        let refs = scan_vendor_references(tmp.path()).await;
        assert_eq!(refs.len(), 1, "{refs:?}");
        assert!(
            refs[0].2.ends_with("left-pad-1.3.0.tgz"),
            "trailing colon must be cut: {refs:?}"
        );
    }
}
