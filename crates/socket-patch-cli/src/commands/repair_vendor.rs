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
//! artifact again — stamped with the npm lockfile FLAVOR the reference was
//! found in, so a later `vendor --revert` routes to the backend whose
//! unwired-revert guard probes the right lockfile. WIRING reconstruction is
//! per-ecosystem: gem recognizes
//! its own Gemfile/lock wiring and rebuilds full revert-capable records
//! ([`socket_patch_core::vendor::gem::reconstruct_gem_wiring`]); the other
//! ecosystems' pre-vendor originals are registry integrity material no
//! offline source can reproduce, so their entries keep empty wiring and the
//! gap is surfaced loudly (`vendor_wiring_unknown`, riding the envelope's
//! run-level `warnings[]` — the entry itself repaired fine, so it must not
//! ride `events[]` as a `skipped` consumers count) — a gem `--revert` of
//! such an entry refuses instead of stranding the pair edit. Existing gem
//! entries with EMPTY wiring (persisted by pre-reconstruction repairs) are
//! backfilled the same way during the ledger-driven pass while healthy.
//!
//! Dir-shaped rebuilds are always LOCAL (the pristine ladder + the recorded
//! patch), while `vendor` may have used the patch service's prebuilt
//! artifact (a converter-generated stub gemspec the local build cannot
//! reproduce): a rebuild whose patched members verify but whose tree
//! differs from the recorded fileInventory refreshes the inventory from
//! the verified rebuild (`vendor_inventory_refreshed`) instead of failing
//! deterministically on every repair.
//!
//! Reconstruction never fingerprints the LIVE artifact into the restored
//! ledger (trust-on-first-use: a tampered unpatched file would become the
//! canonical tree later repairs enforce and VEX attests). A surviving
//! artifact is only restored as-is when an independent anchor vouches for
//! its exact bytes (the rewired npm-family lockfile integrity); otherwise
//! its fingerprint is derived from a member-verified local rebuild, and
//! when no trustworthy pristine source exists the entry is restored
//! fingerprint-less with `vendor_inventory_unverified` — the legacy
//! member-only state — never from the unverifiable live tree.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::copy_tree::remove_tree;
use socket_patch_core::utils::purl::{
    normalize_purl, percent_decode_purl_component, strip_purl_qualifiers,
};
use socket_patch_core::vendor::state::{VendorArtifact, WiringRecord};
use socket_patch_core::vendor::{
    self, artifact_is_file_shaped, check_vendored_artifact, compute_dir_inventory, file_sha256_hex,
    load_state, lock_inventory, parse_vendor_path, registry_fetch, ArtifactHealth, VendorEntry,
    VendorOutcome, VendorWarning,
};
use socket_patch_core::vex::time::now_rfc3339;

use crate::args::GlobalArgs;
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::vendor::{
    dispatch_vendor_one, ecosystem_in_scope, fetch_pristine_package, persist_vendor_entry,
    record_warning, PristineFetch,
};
use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};
use crate::json_envelope::{Envelope, PatchAction, PatchEvent, RunWarning};

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
    /// True for a healthy-by-members RECONSTRUCTED entry with no
    /// independent integrity anchor (dir-shaped trees; file artifacts no
    /// npm-family lock records an integrity for): the live bytes must never
    /// be fingerprinted into the restored ledger (trust-on-first-use), so
    /// the fingerprint is derived from a member-verified local rebuild —
    /// and every pre-rebuild failure falls back to a fingerprint-less
    /// restore plus a `vendor_inventory_unverified` warning instead of a
    /// hard failure (the artifact itself still verifies member-wise).
    soft: bool,
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
        artifact: VendorArtifact {
            path: artifact_path.to_string(),
            sha256: String::new(),
            size: None,
            platform_locked: None,
            file_inventory: None,
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

/// The npm lockfile FLAVOR whose lock carries the
/// `.socket/vendor/npm/<uuid>/` reference, for stamping onto a
/// re-synthesized ledger entry. The strings are `VendorEntry::flavor`'s
/// stable vocabulary (guarded by npm_flavor's `flavor_strings_are_stable`
/// test). Stamping matters: `revert_npm_any` routes by flavor, and each
/// backend's unwired-revert guard probes ITS OWN lockfile — a
/// pnpm-reconstructed entry left at flavor-None would be guarded against
/// package-lock.json instead of pnpm-lock.yaml. Locks are checked in the
/// vendor router's own precedence order (bun > pnpm > yarn > npm) for the
/// pathological multi-lock case; content sniffs mirror
/// `detect_npm_lock_flavor` (crate-private to core, so re-derived here).
/// `None` when genuinely unknowable — no recognizable lock carries the
/// reference, or the referencing lock's grammar is unrecognized — which
/// routes to the package-lock backend, whose guard also fails closed on
/// unwired entries.
async fn detect_reference_flavor(project_root: &Path, eco: &str, uuid: &str) -> Option<String> {
    if eco != "npm" {
        return None;
    }
    let needle = format!(".socket/vendor/npm/{uuid}/");
    let read = |name: &'static str| async move {
        tokio::fs::read_to_string(project_root.join(name))
            .await
            .ok()
    };
    if read("bun.lock").await.is_some_and(|t| t.contains(&needle)) {
        return Some("bun".to_string());
    }
    if let Some(text) = read("pnpm-lock.yaml").await {
        if text.contains(&needle) {
            // Same version allowlist as core's `sniff_lock_grammar`.
            return match text
                .lines()
                .find_map(|l| l.strip_prefix("lockfileVersion:"))
                .map(|v| v.trim().trim_matches(['\'', '"']))
            {
                Some("9.0") => Some("pnpm".to_string()),
                Some("5.4") | Some("6.0") => Some("pnpm-legacy".to_string()),
                _ => None,
            };
        }
    }
    if let Some(text) = read("yarn.lock").await {
        if text.contains(&needle) {
            // Same head sniff as core's `sniff_yarn_lock`; berry wins.
            let head: Vec<&str> = text.lines().take(30).collect();
            return if head.iter().any(|l| l.starts_with("__metadata:")) {
                Some("yarn-berry".to_string())
            } else if head.iter().any(|l| l.trim() == "# yarn lockfile v1") {
                Some("yarn-classic".to_string())
            } else {
                None
            };
        }
    }
    for name in ["npm-shrinkwrap.json", "package-lock.json"] {
        if read(name).await.is_some_and(|t| t.contains(&needle)) {
            return Some("package-lock".to_string());
        }
    }
    None
}

/// What wiring a re-synthesized ledger entry could recover.
enum WiringReconstruction {
    /// The backend recognized its own wiring in the live project files:
    /// full revert-capable records, plus any degradation notes to surface.
    Wired(Vec<WiringRecord>, Vec<VendorWarning>),
    /// No wiring recoverable — unsupported ecosystem, or files vendor's
    /// grammar does not recognize. The entry keeps empty wiring and the
    /// gap is surfaced loudly.
    Unknown(String),
}

/// Per-ecosystem wiring reconstruction for a no-ledger repair. gem is the
/// one ecosystem whose wiring is fully self-describing (the pair edit's
/// originals are derivable from its own emitted forms); the npm family and
/// the rest record pre-vendor REGISTRY integrity fragments that no offline
/// source can reproduce — never guessed at.
async fn reconstruct_entry_wiring(
    project_root: &Path,
    entry: &VendorEntry,
) -> WiringReconstruction {
    match entry.ecosystem.as_str() {
        "gem" => match vendor::gem::reconstruct_gem_wiring(project_root, entry).await {
            Ok((wiring, notes)) => WiringReconstruction::Wired(wiring, notes),
            Err(detail) => WiringReconstruction::Unknown(detail),
        },
        _ => WiringReconstruction::Unknown(
            "this ecosystem's pre-vendor lock fragments are not offline-recoverable".to_string(),
        ),
    }
}

fn fail(env: &mut Envelope, quiet: bool, purl: &str, code: &str, detail: String) {
    if !quiet {
        eprintln!(
            "Cannot repair vendored artifact for {}: {detail}",
            normalize_purl(purl)
        );
    }
    env.record(PatchEvent::new(PatchAction::Failed, purl.to_string()).with_error(code, detail));
    env.mark_partial_failure();
}

/// A soft (healthy-by-members, unanchored) reconstruction whose trustworthy
/// rebuild cannot proceed: the entry stays restored WITHOUT a whole-file
/// fingerprint — the legacy member-only state pass 1 keeps warning about
/// (`vendor_inventory_missing` for gems) — and the gap is surfaced, instead
/// of either failing the repair or canonizing the unverifiable live tree.
/// The entry itself was already persisted by the pre-rebuild restore.
fn soft_restore_without_fingerprint(
    env: &mut Envelope,
    common: &GlobalArgs,
    purl: &str,
    artifact_path: &str,
    why: &str,
) {
    record_warning(
        env,
        purl,
        &VendorWarning::new(
            "vendor_inventory_unverified",
            format!(
                "the ledger entry was reconstructed but its artifact has no independent \
                 integrity anchor and {why}; the entry was restored without a whole-file \
                 fingerprint (only the patched members were verified) — run `socket-patch \
                 vendor` to re-vendor and record one"
            ),
        ),
        common,
    );
    env.record(
        PatchEvent::new(PatchAction::Rebuilt, purl.to_string()).with_details(serde_json::json!({
            "path": artifact_path,
            "ledgerRestored": true,
            "artifactRebuilt": false,
        })),
    );
}

/// `vendor_wiring_unknown` advises about what a FUTURE `vendor --revert`
/// can restore — the entry itself was restored/verified fine, so the
/// advisory rides the envelope's run-level `warnings[]` (the documented
/// carrier for non-fatal advisories) rather than a per-purl `skipped`
/// event, which consumers count as work not done. The purl is baked into
/// `detail` by the callers so attribution survives the run-level move.
fn warn_wiring_unknown(env: &mut Envelope, common: &GlobalArgs, detail: String) {
    if !common.silent && !common.json {
        eprintln!("Warning (vendor_wiring_unknown): {detail}");
    }
    env.warnings.push(RunWarning {
        code: "vendor_wiring_unknown".to_string(),
        detail,
    });
}

/// Best-effort removal of a vendored uuid dir — ahead of a rebuild (corrupt
/// bytes must never blend into one) or after a failed post-verify (never
/// leave unverifiable bytes behind).
async fn remove_vendor_dir(cwd: &Path, eco: &str, uuid: &str) {
    if let Some(rel) = vendor::path::vendor_uuid_dir_rel(eco, uuid) {
        let _ = remove_tree(&cwd.join(rel)).await;
    }
}

/// Move the live uuid dir aside (same parent, `<uuid>.pre-rebuild`) so the
/// backends' rebuild-on-MISSING trigger fires while the bytes stay
/// recoverable: the dispatch can still refuse or fail — the in-hand
/// installed copy may itself be broken in ways no pre-rebuild rung probes
/// — and a failed dispatch replaced nothing, so the artifact
/// (member-healthy for a soft candidate, corrupt-but-diagnosable for a
/// pass-1 one) must be restorable instead of leaving the wired lockfiles
/// pointing at a bare ENOENT (see the NOTE above the staging step).
/// Returns `(live, kept)` for [`restore_aside_vendor_dir`]; on a rename
/// failure falls back to plain removal (the rebuild trigger must fire)
/// and returns `None`.
async fn set_aside_vendor_dir(cwd: &Path, eco: &str, uuid: &str) -> Option<(PathBuf, PathBuf)> {
    let rel = vendor::path::vendor_uuid_dir_rel(eco, uuid)?;
    let live = cwd.join(&rel);
    let kept = cwd.join(format!("{rel}.pre-rebuild"));
    // A crashed earlier run's leftover must not wedge the rename.
    let _ = remove_tree(&kept).await;
    if tokio::fs::rename(&live, &kept).await.is_ok() {
        Some((live, kept))
    } else {
        let _ = remove_tree(&live).await;
        None
    }
}

/// Put the pre-rebuild bytes back after a dispatch that produced no
/// replacement (clearing any partial husk the failed backend left first).
async fn restore_aside_vendor_dir(live: &Path, kept: &Path) {
    let _ = remove_tree(live).await;
    let _ = tokio::fs::rename(kept, live).await;
}

/// The vendored-artifact phase of `repair`. Runs between the download and
/// cleanup phases (and under `--download-only` — restoring artifacts IS
/// repair's job). `manifest` is `None` when the project has no
/// `.socket/manifest.json` (detached/reconstruction-only repairs).
/// Returns the number of artifacts rebuilt (for the human summary line);
/// failures are carried by `env` (`Failed` events + partial-failure status).
pub(crate) async fn repair_vendored_artifacts(
    common: &GlobalArgs,
    manifest: Option<&PatchManifest>,
    socket_dir: &Path,
    env: &mut Envelope,
) -> usize {
    let quiet = common.json || common.silent;
    let mut rebuilt = 0usize;

    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            env.record(
                PatchEvent::artifact(PatchAction::Failed)
                    .with_error("vendor_state_unreadable", e.to_string()),
            );
            env.mark_partial_failure();
            return rebuilt;
        }
    };

    // ── Pass 1: ledger-driven health check ───────────────────────────────
    // Shared across both passes so the API client (and its one-time
    // token-shape stderr advisory) is constructed at most once per run.
    let mut api_client: Option<ApiClient> = None;
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
            (None, None) => {
                match fetch_record_by_uuid(common, &mut api_client, &entry.uuid).await {
                    Some((_, r)) => r,
                    None => {
                        fail(
                            env,
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
                }
            }
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
            ArtifactHealth::Healthy => {
                // Dir-shaped artifacts from pre-inventory vendors: the
                // health check above could only verify the PATCHED members
                // — unpatched-file drift is invisible until a re-vendor
                // records the whole-tree inventory. Name the gap — for gem
                // only, the one backend that records inventories; the other
                // dir-shaped backends (cargo/golang/composer) don't yet, so
                // a re-vendor there records nothing and the advice would be
                // permanent per-run noise.
                if entry.ecosystem == "gem"
                    && !artifact_is_file_shaped(&entry.artifact.path)
                    && entry.artifact.file_inventory.is_none()
                {
                    record_warning(
                        env,
                        purl,
                        &VendorWarning::new(
                            "vendor_inventory_missing",
                            format!(
                                "the ledger entry for {} records no file inventory \
                                 (pre-inventory vendor); only the patched members were \
                                 verified — re-vendor to make unpatched-file drift \
                                 detectable",
                                normalize_purl(purl)
                            ),
                        ),
                        common,
                    );
                }
                // Empty-wiring gem entries (pre-reconstruction repairs
                // persisted these): backfill full revert-capable wiring
                // from the live pair via the same recognizers the
                // no-ledger reconstruction trusts, so `vendor --revert`
                // stops refusing with manual cleanup steps.
                if entry.ecosystem == "gem" && entry.wiring.is_empty() {
                    match vendor::gem::reconstruct_gem_wiring(&common.cwd, &entry).await {
                        Ok((wiring, notes)) => {
                            if common.dry_run {
                                env.record(
                                    PatchEvent::new(PatchAction::Verified, purl.clone())
                                        .with_details(serde_json::json!({
                                            "vendorArtifact": true,
                                            "wouldRestoreWiring": true,
                                        })),
                                );
                                continue;
                            }
                            for w in &notes {
                                record_warning(env, purl, w, common);
                            }
                            let mut healed = entry.clone();
                            healed.wiring = wiring;
                            let detached = healed.detached;
                            if persist_vendor_entry(
                                common, env, &mut state, purl, healed, detached, &record,
                            )
                            .await
                            {
                                continue;
                            }
                            env.record(
                                PatchEvent::new(PatchAction::Rebuilt, purl.clone()).with_details(
                                    serde_json::json!({
                                        "path": entry.artifact.path,
                                        "wiringRestored": true,
                                        "artifactRebuilt": false,
                                    }),
                                ),
                            );
                            rebuilt += 1;
                        }
                        Err(detail) => {
                            warn_wiring_unknown(
                                env,
                                common,
                                format!(
                                    "the ledger entry for {} records no pre-vendor wiring \
                                     originals and they cannot be reconstructed from the \
                                     live files ({detail}); `vendor --revert` cannot \
                                     restore the project files for this entry",
                                    normalize_purl(purl)
                                ),
                            );
                        }
                    }
                }
            }
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
                    quiet,
                    purl,
                    "vendor_artifact_unrepairable",
                    format!("the ledger entry cannot be verified ({reason}); fix state.json"),
                );
            }
            health @ (ArtifactHealth::Missing | ArtifactHealth::Corrupt { .. }) => {
                let reason = if matches!(health, ArtifactHealth::Missing) {
                    "vendor_artifact_missing"
                } else {
                    "vendor_artifact_corrupt"
                };
                let detached = entry.detached;
                candidates.push(Candidate {
                    purl: purl.clone(),
                    entry,
                    record,
                    detached,
                    reconstructed: false,
                    reason,
                    soft: false,
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
                None => match fetch_record_by_uuid(common, &mut api_client, &uuid).await {
                    Some((purl, r)) => (purl, r, true),
                    None => {
                        fail(
                            env,
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
        // Stamp the flavor the reference was found in (knowable right here:
        // the scan above read specific lockfiles), so `vendor --revert`
        // routes to the backend whose unwired-revert guard probes the RIGHT
        // lockfile. Genuinely unknowable stays None (guarded fallback).
        entry.flavor = detect_reference_flavor(&common.cwd, &eco, &uuid).await;
        entry.detached = detached;
        if detached {
            entry.record = Some(record.clone());
        }
        // Wiring reconstruction (fail-closed): gem rebuilds full
        // revert-capable records from its own recognizable pair edit; the
        // rest keep empty wiring with the gap surfaced loudly — reverting
        // such an entry cannot restore the project files.
        match reconstruct_entry_wiring(&common.cwd, &entry).await {
            WiringReconstruction::Wired(wiring, notes) => {
                entry.wiring = wiring;
                for w in &notes {
                    record_warning(env, &purl, w, common);
                }
            }
            WiringReconstruction::Unknown(detail) => {
                warn_wiring_unknown(
                    env,
                    common,
                    format!(
                        "the ledger entry for {} was reconstructed without pre-vendor \
                         wiring originals ({detail}); `vendor --revert` cannot restore \
                         the project files for this entry",
                        normalize_purl(&purl)
                    ),
                );
            }
        }
        match check_vendored_artifact(&common.cwd, &entry, &record).await {
            ArtifactHealth::Healthy => {
                // The re-synthesized entry records no sha256/fileInventory,
                // so the health check above verified only the patched
                // members — whole-file drift (an altered UNPATCHED member)
                // is invisible to it. The live bytes must therefore NEVER be
                // fingerprinted into the restored ledger: that would be
                // trust-on-first-use, canonizing a tampered tree that later
                // repairs enforce and VEX attests. Only an INDEPENDENT
                // anchor can vouch for the exact bytes — the rewired
                // npm-family lockfile integrity, when one records this
                // artifact. A "surviving" artifact that no longer matches it
                // leaves the package manager broken, so it must be rebuilt,
                // never blessed into the reconstructed ledger.
                let mut anchored = false;
                if let Some(wired) =
                    lock_inventory::wired_vendor_integrity(&common.cwd, &entry.artifact.path).await
                {
                    let name = npm_coords(&entry.base_purl)
                        .map(|(n, _)| n)
                        .unwrap_or_default();
                    let intact = match tokio::fs::read(common.cwd.join(&entry.artifact.path)).await
                    {
                        Ok(bytes) => {
                            registry_fetch::artifact_matches_integrity(&bytes, &name, &wired)
                                .is_ok()
                        }
                        Err(_) => false,
                    };
                    if !intact {
                        candidates.push(Candidate {
                            purl,
                            entry,
                            record,
                            detached,
                            reconstructed: true,
                            reason: "vendor_artifact_corrupt",
                            soft: false,
                        });
                        continue;
                    }
                    anchored = true;
                }
                if common.dry_run {
                    let mut details = serde_json::json!({
                        "vendorArtifact": true,
                        "wouldRestoreLedgerEntry": true,
                        "path": relpath,
                    });
                    if !anchored {
                        // The fingerprint would come from a rebuild, never
                        // the live tree.
                        details["wouldRebuild"] = serde_json::Value::Bool(true);
                    }
                    env.record(
                        PatchEvent::new(PatchAction::Verified, purl.clone()).with_details(details),
                    );
                    continue;
                }
                if anchored {
                    // The artifact bytes are exactly what the rewired
                    // lockfile's integrity records; only the ledger was
                    // lost. Restore the entry (sha/size recomputed from the
                    // VERIFIED bytes) so GC/sweep/revert know the artifact
                    // again — without it the next `scan --prune` would sweep
                    // the uuid dir as an orphan.
                    fill_artifact_fingerprint(&common.cwd, &mut entry).await;
                    let save_failed = persist_vendor_entry(
                        common, env, &mut state, &purl, entry, detached, &record,
                    )
                    .await;
                    if save_failed {
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
                    rebuilt += 1;
                    continue;
                }
                // No anchor (dir-shaped trees — gem, cargo —, file
                // artifacts absent from every npm-family lock): queue a
                // SOFT rebuild. The canonical fingerprint is derived from a
                // member-verified local rebuild (pristine source + the
                // recorded patch, the same dispatch as every other rebuild
                // here); when no trustworthy pristine source exists the
                // entry is restored WITHOUT a fingerprint — the legacy
                // member-only state pass 1 keeps warning about — instead of
                // canonizing the live tree.
                candidates.push(Candidate {
                    purl,
                    entry,
                    record,
                    detached,
                    reconstructed: true,
                    reason: "vendor_inventory_unverified",
                    soft: true,
                });
            }
            _ => {
                candidates.push(Candidate {
                    purl,
                    entry,
                    record,
                    detached,
                    reconstructed: true,
                    reason: "vendor_artifact_missing",
                    soft: false,
                });
            }
        }
    }

    if candidates.is_empty() {
        return rebuilt;
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
        return rebuilt;
    }

    if !quiet {
        println!(
            "\nRebuilding {} broken vendored artifact(s)...",
            candidates.len()
        );
    }

    // ── Soft reconstructions: restore the ledger entry FIRST ─────────────
    // Fingerprint-less: the restore must survive even when no trustworthy
    // rebuild source turns up below, and the fingerprint slot is only ever
    // refilled from a member-verified rebuild — never the live tree. The
    // early persist also lets the rebuild's own persist carry the
    // reconstructed wiring originals forward by identity.
    let mut unrebuildable: HashSet<String> = HashSet::new();
    for c in &candidates {
        if c.soft
            && persist_vendor_entry(
                common,
                env,
                &mut state,
                &c.purl,
                c.entry.clone(),
                c.detached,
                &c.record,
            )
            .await
        {
            // The state write failed (Failed event already recorded):
            // nothing below could persist either.
            unrebuildable.insert(c.purl.clone());
        }
    }

    // NOTE: corrupt artifacts are NOT deleted here. Clearing waits until
    // the rebuild loop below, where the patch sources and a pristine
    // package source are both in hand (and even there it is a MOVE-ASIDE,
    // restored when the dispatch fails) — see the comment there. Destroying
    // the corrupt copy before the rebuild-source ladder runs would, on any
    // no-source outcome (--offline, node_modules gone, fetch failure),
    // convert a corrupt-but-diagnosable integrity-mismatch state into a
    // bare ENOENT on the next install (the lock still points at the
    // artifact) and erase the forensic evidence of the tamper.

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
        MemStageOutcome::Ready(s) => s,
        MemStageOutcome::Unavailable => {
            for c in &candidates {
                if unrebuildable.contains(&c.purl) {
                    continue;
                }
                if c.soft {
                    soft_restore_without_fingerprint(
                        env,
                        common,
                        &c.purl,
                        &c.entry.artifact.path,
                        "its patch content has no local source to rebuild from",
                    );
                    rebuilt += 1;
                    continue;
                }
                fail(
                    env,
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
            return rebuilt;
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
    };
    let mut all_packages = find_packages_for_purls(&partitioned, &crawler_options, quiet).await;
    let inventory = lock_inventory::inventory_project(&common.cwd).await;
    let client = registry_fetch::build_registry_client();
    let mut holders: Vec<registry_fetch::FetchedPackage> = Vec::new();
    // Reconstructed npm candidates fetched UNVERIFIED from the conventional
    // registry: their rebuilt tarball MUST match the integrity the rewired
    // lockfile records (the trust anchor) before anything is persisted.
    let mut must_verify: HashMap<String, lock_inventory::LockIntegrity> = HashMap::new();
    for c in &candidates {
        if unrebuildable.contains(&c.purl) {
            continue;
        }
        if all_packages.contains_key(&c.purl) {
            // Installed copy: works offline too. But for a RECONSTRUCTED
            // entry the copy is an unverified source — the ledger that
            // recorded the artifact sha is gone, so the rewired lockfile's
            // integrity is the ONLY trust anchor. A copy that drifted since
            // vendoring (build-tool artifacts, edited unpatched files) packs
            // into a tarball the package manager would reject on its next
            // install; register the wired integrity so the rebuilt artifact
            // is verified below, exactly like the unverified-registry rung.
            if c.reconstructed {
                if let Some(wired) =
                    lock_inventory::wired_vendor_integrity(&common.cwd, &c.entry.artifact.path)
                        .await
                {
                    must_verify.insert(c.purl.clone(), wired);
                }
            }
            continue;
        }
        if common.offline {
            if c.soft {
                soft_restore_without_fingerprint(
                    env,
                    common,
                    &c.purl,
                    &c.entry.artifact.path,
                    "the package is not installed and --offline prevents fetching a \
                     pristine copy to rebuild from",
                );
                rebuilt += 1;
            } else {
                fail(
                    env,
                    quiet,
                    &c.purl,
                    c.reason,
                    format!(
                        "the vendored artifact at {} is broken, the package is not installed, \
                         and --offline prevents fetching a pristine copy",
                        c.entry.artifact.path
                    ),
                );
            }
            unrebuildable.insert(c.purl.clone());
            continue;
        }
        let pristine =
            fetch_pristine_package(&common.cwd, &inventory, &client, &c.purl, Some(&c.entry)).await;
        // The `Unverifiable` reason carries the precise, fragment-aware cause
        // (e.g. a pdm/poetry/pipenv lock records the wheel hash but no fetchable
        // registry URL) — surface it instead of the blanket "no recoverable
        // registry fragment", which falsely implies the ledger recorded nothing.
        let unverifiable_reason = match &pristine {
            PristineFetch::Unverifiable(d) => Some(d.clone()),
            _ => None,
        };
        match pristine {
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
                                    fail(env, quiet, &c.purl, "vendor_fetch_failed", d);
                                    unrebuildable.insert(c.purl.clone());
                                    continue;
                                }
                            }
                        }
                    }
                }
                if c.soft {
                    soft_restore_without_fingerprint(
                        env,
                        common,
                        &c.purl,
                        &c.entry.artifact.path,
                        "no verifiable pristine source exists to rebuild from (the package \
                         is not installed, the lockfile is rewired to the vendored artifact, \
                         and the reconstructed entry records no recoverable registry \
                         fragment)",
                    );
                    rebuilt += 1;
                    unrebuildable.insert(c.purl.clone());
                    continue;
                }
                let detail = if c.entry.artifact.platform_locked == Some(true) {
                    "the vendored wheel is platform-locked (compiled); reinstall the \
                     package on this platform and re-run repair, or run `socket-patch \
                     vendor` to rebuild it"
                        .to_string()
                } else if let Some(reason) = unverifiable_reason {
                    reason
                } else {
                    "no verifiable pristine source: no installed copy was found, the \
                     lockfile is rewired to the (broken) vendored artifact, and the \
                     ledger records no recoverable registry fragment"
                        .to_string()
                };
                fail(env, quiet, &c.purl, "vendor_artifact_unrepairable", detail);
                unrebuildable.insert(c.purl.clone());
            }
            PristineFetch::Failed(detail) => {
                if c.soft {
                    soft_restore_without_fingerprint(
                        env,
                        common,
                        &c.purl,
                        &c.entry.artifact.path,
                        &format!("the pristine fetch failed ({detail})"),
                    );
                    rebuilt += 1;
                } else {
                    fail(env, quiet, &c.purl, "vendor_fetch_failed", detail);
                }
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
        // Clear the live uuid dir only NOW — the patch sources and the
        // pristine source are both in hand. The backends' wired hot paths
        // rebuild on MISSING (one uniform trigger for every ecosystem),
        // and the live bytes must never blend into the rebuild:
        //  - corrupt: the recorded fingerprint already condemned them;
        //  - soft: the healthy-by-members live tree is exactly what cannot
        //    be trusted — the fingerprint below derives from the
        //    member-verified rebuild, never the live bytes.
        // Cleared by MOVE-ASIDE, not deletion: an in-hand source does not
        // make the dispatch infallible (the installed copy may itself be
        // broken in ways no pre-rebuild rung probes), and a dispatch that
        // refuses or fails replaced nothing — the bytes go back rather
        // than leaving the wired lockfiles pointing at a bare ENOENT and
        // destroying the evidence the NOTE above the staging step keeps.
        let aside = if c.soft || c.reason == "vendor_artifact_corrupt" {
            set_aside_vendor_dir(&common.cwd, &c.entry.ecosystem, &c.entry.uuid).await
        } else {
            None
        };
        // For an unverified-source rebuild the rewired lockfile is the trust
        // anchor: snapshot the wiring files so a failed post-verify can put
        // them back byte-for-byte. The backend's re-wire may refresh the
        // recorded integrity/checksum to the rebuilt tarball's — blessing
        // exactly the drifted bytes the verify below is about to reject.
        let wiring_snapshot: Option<Vec<(std::path::PathBuf, Vec<u8>)>> =
            if must_verify.contains_key(&c.purl) {
                let mut snap = Vec::new();
                for name in [
                    "package-lock.json",
                    "npm-shrinkwrap.json",
                    "pnpm-lock.yaml",
                    "yarn.lock",
                    "bun.lock",
                    "package.json",
                ] {
                    let p = common.cwd.join(name);
                    if let Ok(bytes) = tokio::fs::read(&p).await {
                        snap.push((p, bytes));
                    }
                }
                Some(snap)
            } else {
                None
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
            // Repair rebuilds locally from the recorded patch — no service.
            None,
        )
        .await;
        match outcome {
            None => {
                if let Some((live, kept)) = &aside {
                    restore_aside_vendor_dir(live, kept).await;
                }
                fail(
                    env,
                    quiet,
                    &c.purl,
                    "vendor_artifact_unrepairable",
                    "no vendor backend for this ecosystem in this build".to_string(),
                );
            }
            Some(VendorOutcome::Refused { code, detail }) => {
                if let Some((live, kept)) = &aside {
                    restore_aside_vendor_dir(live, kept).await;
                }
                fail(env, quiet, &c.purl, code, detail);
            }
            Some(VendorOutcome::Done {
                result,
                entry,
                warnings,
            }) => {
                if !result.success {
                    if let Some((live, kept)) = &aside {
                        restore_aside_vendor_dir(live, kept).await;
                    }
                    fail(
                        env,
                        quiet,
                        &c.purl,
                        "vendor_artifact_rebuild_failed",
                        result.error.unwrap_or_else(|| "rebuild failed".to_string()),
                    );
                    continue;
                }
                // The rebuild replaced the artifact: the set-aside copy is
                // condemned bytes now (post-verify failures below keep
                // their existing nothing-kept contract).
                if let Some((_, kept)) = &aside {
                    let _ = remove_tree(kept).await;
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
                        remove_vendor_dir(&common.cwd, &c.entry.ecosystem, &c.entry.uuid).await;
                        // Put the trust anchor back exactly as it was: the
                        // backend's re-wire may have refreshed the recorded
                        // integrity to the rejected rebuild's.
                        if let Some(snap) = &wiring_snapshot {
                            for (path, bytes) in snap {
                                let _ = tokio::fs::write(path, bytes).await;
                            }
                        }
                        fail(
                            env,
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
                let from_backend = entry.is_some();
                let mut check_entry = entry.unwrap_or_else(|| c.entry.clone());
                if !from_backend && c.reconstructed {
                    fill_artifact_fingerprint(&common.cwd, &mut check_entry).await;
                }
                if (from_backend || c.reconstructed)
                    && persist_vendor_entry(
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
                    continue;
                }
                // ── Fail-closed post-verify ──────────────────────────────
                let mut health =
                    check_vendored_artifact(&common.cwd, &check_entry, &c.record).await;
                // A dir-shaped rebuild whose PATCHED members all verify but
                // whose tree differs from the recorded inventory: the entry
                // recorded the OTHER build source's tree (the patch
                // service's prebuilt artifact carries a converter-generated
                // stub gemspec; repair always rebuilds locally). Failing
                // here would delete the rebuild, strand the wired pair on a
                // dead dir, and deterministically re-fail every later
                // repair — so refresh the inventory from the verified
                // rebuild instead, loudly.
                if !from_backend
                    && !c.reconstructed
                    && matches!(&health, ArtifactHealth::Corrupt { reason }
                        if reason == "vendor_inventory_mismatch")
                {
                    let abs = common
                        .cwd
                        .join(check_entry.artifact.path.replace('\\', "/"));
                    if let Ok(inv) = compute_dir_inventory(&abs).await {
                        check_entry.artifact.file_inventory = Some(inv);
                        health =
                            check_vendored_artifact(&common.cwd, &check_entry, &c.record).await;
                        if health == ArtifactHealth::Healthy {
                            record_warning(
                                env,
                                &c.purl,
                                &VendorWarning::new(
                                    "vendor_inventory_refreshed",
                                    "the rebuilt artifact's patched files verify but its \
                                     tree differs from the recorded file inventory (the \
                                     entry was likely vendored from the patch service's \
                                     prebuilt artifact; repair rebuilds locally); the \
                                     inventory was refreshed from the verified rebuild — \
                                     run `socket-patch vendor` to restore the \
                                     service-built tree",
                                ),
                                common,
                            );
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
                                continue;
                            }
                        }
                    }
                }
                match health {
                    ArtifactHealth::Healthy => {
                        if !quiet {
                            println!(
                                "Rebuilt {} ({})",
                                normalize_purl(&c.purl),
                                check_entry.artifact.path
                            );
                        }
                        env.record(
                            PatchEvent::new(PatchAction::Rebuilt, c.purl.clone()).with_details(
                                serde_json::json!({
                                    "path": check_entry.artifact.path,
                                    "reason": c.reason,
                                    "ledgerRestored": c.reconstructed,
                                }),
                            ),
                        );
                        rebuilt += 1;
                    }
                    other => {
                        // The deterministic rebuild did not reproduce the
                        // recorded artifact (e.g. a tampered ledger sha):
                        // remove it rather than leave unverifiable bytes.
                        remove_vendor_dir(&common.cwd, &check_entry.ecosystem, &check_entry.uuid)
                            .await;
                        fail(
                            env,
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
    rebuilt
}

/// Compute and record the artifact fingerprint on a re-synthesized ledger
/// entry: sha256 + size for file-shaped artifacts, the whole-tree file
/// inventory for dir-shaped ones. An uninventoriable dir stays `None` —
/// the entry then behaves as pre-inventory (member-only verification).
async fn fill_artifact_fingerprint(project_root: &Path, entry: &mut VendorEntry) {
    let norm = entry.artifact.path.replace('\\', "/");
    let abs = project_root.join(&norm);
    if !artifact_is_file_shaped(&norm) {
        entry.artifact.file_inventory = compute_dir_inventory(&abs).await.ok();
        return;
    }
    if let Some(hex) = file_sha256_hex(&abs).await {
        entry.artifact.sha256 = hex;
    }
    if let Ok(meta) = tokio::fs::metadata(&abs).await {
        entry.artifact.size = Some(meta.len());
    }
}

/// Fetch one patch view by uuid (proxy-aware) and shape it as a manifest
/// record; `None` offline or on any API failure. `client_cache` holds the
/// one API client the whole vendored-artifact phase shares — construction
/// re-prints the token-shape stderr advisory, so N uuid lookups must not
/// print it N times. Built lazily: a run with nothing to look up never
/// constructs (or warns) at all.
async fn fetch_record_by_uuid(
    common: &GlobalArgs,
    client_cache: &mut Option<ApiClient>,
    uuid: &str,
) -> Option<(String, PatchRecord)> {
    if common.offline {
        return None;
    }
    if client_cache.is_none() {
        *client_cache = Some(
            get_api_client_with_overrides(common.api_client_overrides())
                .await
                .0,
        );
    }
    let client = client_cache
        .as_ref()
        .expect("client_cache was just initialized above");
    let patch = client
        .fetch_patch(common.org.as_deref(), uuid)
        .await
        .ok()??;
    Some(crate::commands::get::record_from_patch_response(&patch))
}

/// `pkg:npm/<name>@<version>` → (name, version); the name may be scoped.
/// `base_purl` is stored verbatim percent-encoded (`pkg:npm/%40scope/…`),
/// so each component is decoded like the npm backend's own coordinate
/// parser — the registry fetch and the berry cache-checksum recipe both
/// need the decoded name.
fn npm_coords(base_purl: &str) -> Option<(String, String)> {
    let rest = strip_purl_qualifiers(base_purl).strip_prefix("pkg:npm/")?;
    let (name_raw, version_raw) = rest.rsplit_once('@')?;
    if name_raw.is_empty() || version_raw.is_empty() {
        return None;
    }
    let name = name_raw
        .split('/')
        .map(percent_decode_purl_component)
        .collect::<Vec<_>>()
        .join("/");
    let version = percent_decode_purl_component(version_raw).into_owned();
    Some((name, version))
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

    /// The scanner's false-positive guard: a `.socket` mention that is NOT
    /// a parseable vendored-artifact path (the committed manifest, a
    /// non-uuid path segment) must never be reported as a vendor reference
    /// — `parse_vendor_path`'s reject branch is what keeps `repair` from
    /// reconstructing ledger entries out of ordinary `.socket/` mentions.
    #[tokio::test]
    async fn scan_ignores_non_vendor_socket_mentions() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(
            tmp.path().join("package.json"),
            r#"{
  "name": "t",
  "socketManifest": ".socket/manifest.json",
  "notAVendorPath": ".socket/vendor/npm/not-a-uuid/x.tgz"
}"#,
        )
        .await
        .unwrap();
        let refs = scan_vendor_references(tmp.path()).await;
        assert!(
            refs.is_empty(),
            "non-vendor .socket mentions must be rejected: {refs:?}"
        );
    }

    /// A lock that is PRESENT but does not reference the uuid must not
    /// claim the entry: the probe falls through past pnpm-lock.yaml and
    /// yarn.lock to the lock that actually carries the reference.
    #[tokio::test]
    async fn detect_reference_flavor_falls_through_present_unreferencing_locks() {
        let uuid = "11111111-1111-4111-8111-111111111111";
        let mention = format!("resolved: file:.socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz\n");
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(
            tmp.path().join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n",
        )
        .await
        .unwrap();
        tokio::fs::write(tmp.path().join("yarn.lock"), "# yarn lockfile v1\n")
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("package-lock.json"), &mention)
            .await
            .unwrap();
        assert_eq!(
            detect_reference_flavor(tmp.path(), "npm", uuid).await,
            Some("package-lock".to_string()),
            "present-but-unreferencing locks must fall through to the referencing one"
        );
    }

    /// [`remove_vendor_dir`] is a best-effort guard that must never GUESS a
    /// path: an eco/uuid pair that cannot map to a canonical vendor dir
    /// (unknown ecosystem dir, non-canonical uuid) removes NOTHING, while
    /// the mappable pair removes exactly its uuid dir.
    #[tokio::test]
    async fn remove_vendor_dir_refuses_unmappable_eco_or_uuid() {
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "11111111-1111-4111-8111-111111111111";
        let dir = tmp.path().join(format!(".socket/vendor/npm/{uuid}"));
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("x.tgz"), b"bytes").await.unwrap();

        remove_vendor_dir(tmp.path(), "jsr", uuid).await;
        assert!(dir.is_dir(), "an unmappable ecosystem must remove nothing");
        remove_vendor_dir(tmp.path(), "npm", "not-a-uuid").await;
        assert!(dir.is_dir(), "a non-canonical uuid must remove nothing");
        remove_vendor_dir(tmp.path(), "npm", uuid).await;
        assert!(!dir.exists(), "the canonical pair removes its uuid dir");
    }

    /// The empty-component rejects: a purl with no name or no version can
    /// never drive a registry fetch — `npm_coords` must return `None`, not
    /// empty coordinates.
    #[test]
    fn npm_coords_rejects_empty_name_or_version() {
        assert_eq!(npm_coords("pkg:npm/@1.2.3"), None, "empty name");
        assert_eq!(npm_coords("pkg:npm/left-pad@"), None, "empty version");
    }

    /// The reconstruction stamps [`VendorEntry::flavor`] from whichever
    /// lockfile carries the vendored reference, so `vendor --revert` routes
    /// to the backend whose unwired-revert guard probes the RIGHT lockfile.
    /// The strings must stay npm_flavor's stable vocabulary; unknowable
    /// shapes stay `None` (the guarded package-lock fallback route).
    #[tokio::test]
    async fn detect_reference_flavor_maps_referencing_lock_to_stable_flavor() {
        let uuid = "11111111-1111-4111-8111-111111111111";
        let mention = format!("resolved: file:.socket/vendor/npm/{uuid}/left-pad-1.3.0.tgz\n");
        let case = |files: Vec<(&'static str, String)>, want: Option<&'static str>| async move {
            let tmp = tempfile::tempdir().unwrap();
            for (name, text) in &files {
                tokio::fs::write(tmp.path().join(name), text).await.unwrap();
            }
            assert_eq!(
                detect_reference_flavor(tmp.path(), "npm", uuid).await,
                want.map(str::to_string),
                "files: {:?}",
                files.iter().map(|(n, _)| n).collect::<Vec<_>>()
            );
        };

        // Each flavor's lock, referenced → its stable string.
        case(
            vec![("package-lock.json", mention.clone())],
            Some("package-lock"),
        )
        .await;
        case(
            vec![("npm-shrinkwrap.json", mention.clone())],
            Some("package-lock"),
        )
        .await;
        case(
            vec![(
                "pnpm-lock.yaml",
                format!("lockfileVersion: '9.0'\n{mention}"),
            )],
            Some("pnpm"),
        )
        .await;
        case(
            vec![("pnpm-lock.yaml", format!("lockfileVersion: 5.4\n{mention}"))],
            Some("pnpm-legacy"),
        )
        .await;
        case(
            vec![(
                "pnpm-lock.yaml",
                format!("lockfileVersion: '6.0'\n{mention}"),
            )],
            Some("pnpm-legacy"),
        )
        .await;
        case(
            vec![("yarn.lock", format!("# yarn lockfile v1\n{mention}"))],
            Some("yarn-classic"),
        )
        .await;
        case(
            vec![("yarn.lock", format!("__metadata:\n  version: 8\n{mention}"))],
            Some("yarn-berry"),
        )
        .await;
        case(vec![("bun.lock", mention.clone())], Some("bun")).await;

        // Unknowable stays None: unrecognized grammars, or no referencing
        // lock at all (an unreferenced lock must not claim the entry).
        case(
            vec![("pnpm-lock.yaml", format!("lockfileVersion: 5.3\n{mention}"))],
            None,
        )
        .await;
        case(vec![("yarn.lock", mention.clone())], None).await;
        case(
            vec![("package-lock.json", "no reference here".to_string())],
            None,
        )
        .await;
        case(vec![], None).await;

        // The referencing lock wins over an unreferenced sibling.
        case(
            vec![
                ("package-lock.json", "no reference here".to_string()),
                ("yarn.lock", format!("# yarn lockfile v1\n{mention}")),
            ],
            Some("yarn-classic"),
        )
        .await;

        // Non-npm ecosystems never carry an npm flavor.
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("package-lock.json"), &mention)
            .await
            .unwrap();
        assert_eq!(detect_reference_flavor(tmp.path(), "gem", uuid).await, None);
    }

    /// `base_purl` is stored VERBATIM percent-encoded (`pkg:npm/%40scope/…`,
    /// manifest/ledger key parity — see npm_common's coordinate tests), but
    /// the registry fetch and the berry cache-checksum recipe both need the
    /// DECODED npm name.
    #[test]
    fn npm_coords_percent_decodes_scoped_names() {
        assert_eq!(
            npm_coords("pkg:npm/%40scope/sdk@1.12.0"),
            Some(("@scope/sdk".to_string(), "1.12.0".to_string()))
        );
        // Already-decoded and unscoped spellings pass through unchanged.
        assert_eq!(
            npm_coords("pkg:npm/@scope/sdk@1.12.0"),
            Some(("@scope/sdk".to_string(), "1.12.0".to_string()))
        );
        assert_eq!(
            npm_coords("pkg:npm/left-pad@1.3.0?foo=bar"),
            Some(("left-pad".to_string(), "1.3.0".to_string()))
        );
        assert_eq!(npm_coords("pkg:npm/left-pad"), None);
    }
}
