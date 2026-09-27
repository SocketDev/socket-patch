//! [`VendoredBackend::repair`] — `repair`'s vendored-artifact phase:
//! re-vendor committed vendor artifacts that the ledger records but that
//! are missing or corrupt on disk.
//!
//! Detection is the core health check ([`check_vendored_artifact`]: per-file
//! afterHashes + the whole-file ledger sha256 for file-shaped artifacts, the
//! whole-tree inventory for dir-shaped ones). A broken artifact is
//! re-vendored through [`VendoredBackend::apply`] — the same engine, the
//! same `--vendor-source` policy and the same pristine-source ladder as
//! `vendor` itself — so under the default `auto` source the patch
//! service's prebuilt artifact is downloaded again (a local build is the
//! fallback when the service has none, and the only source under
//! `--offline`/`--vendor-source build`). The backends' wired hot paths
//! rebuild the ARTIFACT only; lockfiles and the recorded pre-vendor
//! originals are left alone. A rebuild is verified against its ledger entry
//! afterwards, fail-closed.
//!
//! The ledger is the only source of truth: a lockfile that references
//! `.socket/vendor/<eco>/<uuid>/` with NO ledger entry (state.json deleted
//! or never committed) is reported as `vendor_ledger_missing` — repair no
//! longer re-synthesizes ledger entries from lockfile text, because the
//! pre-vendor originals a revert needs cannot be recovered from the
//! rewired lockfile. The remedy is restoring `.socket/vendor/state.json`
//! from version control and re-running repair.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::constants::SOCKET_DIR;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::copy_tree::remove_tree;
use socket_patch_core::utils::fs::read_regular_to_string;
use socket_patch_core::utils::purl::normalize_purl;
use socket_patch_core::vendor::{
    self, artifact_is_file_shaped, check_vendored_artifact, load_state, parse_vendor_path,
    ArtifactHealth, VendorEntry, VendorState, VendorWarning,
};

use super::{records_manifest, ApplyRequest, VendoredBackend, NO_LOCAL_SOURCE_MESSAGE};
use crate::args::GlobalArgs;
use crate::commands::vendor::{
    ecosystem_in_scope, format_advisory, persist_vendor_entry, record_warning,
};
use crate::json_envelope::{Envelope, PatchAction, PatchEvent};
use crate::ui::plural;

/// One broken vendored unit queued for re-vendoring.
struct Candidate {
    purl: String,
    entry: VendorEntry,
    record: PatchRecord,
    detached: bool,
    reason: &'static str,
}

/// Files the vendor backends rewire — the search space for
/// `.socket/vendor/<eco>/<uuid>/<leaf>` references. The Python locks the
/// root LISTS (`pylock*.toml`, `*.py.lock` + script) and the requirements
/// `-r` include tree are appended at scan time.
const WIRING_FILES: &[&str] = &[
    "vlt-lock.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "package.json",
    "Cargo.toml",
    "Cargo.lock",
    // Pre-v5 vendored cargo wiring (migrated into Cargo.toml on re-run).
    ".cargo/config.toml",
    ".cargo/config",
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
/// text scan plus native binary Bun resolution records and the canonical
/// path parser. Used by repair (references the ledger does not cover), by
/// the orphan sweeps (`vendor --revert`, `scan --prune`: a dir a lockfile
/// still points at is never deleted) and by rollback.
pub(crate) async fn scan_vendor_references(project_root: &Path) -> Vec<(String, String, String)> {
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    if !project_root.join("bun.lock").exists() {
        if let Ok(paths) =
            socket_patch_core::vendor::bun_lock::binary_vendor_paths(project_root).await
        {
            for path in paths {
                if let Some(parts) = parse_vendor_path(&path) {
                    if seen.insert((parts.eco.to_string(), parts.uuid.clone())) {
                        let rel =
                            format!(".socket/vendor/{}/{}/{}", parts.eco, parts.uuid, parts.leaf);
                        out.push((parts.eco, parts.uuid, rel));
                    }
                }
            }
        }
    }

    let mut files: Vec<String> = WIRING_FILES
        .iter()
        .map(|file| (*file).to_string())
        .collect();
    files.extend(vendor::vlt_lock::vlt_importer_package_jsons(project_root).await);
    if let Ok(paths) = socket_patch_core::utils::python_lock::python_lock_paths(project_root) {
        for path in paths {
            if let Some(script) =
                socket_patch_core::utils::python_lock::script_of_lock(&path).map(str::to_string)
            {
                files.push(script);
            }
            files.push(path);
        }
    }
    // The requirements planner writes a vendored pin where the original pin
    // was — possibly inside a `-r` include — so the root requirements.txt
    // alone would miss it (and the orphan sweep, which reuses this scan,
    // would delete the include-referenced wheel). An unreadable include
    // tree degrades to the root file, matching the per-file tolerance
    // below.
    if let Ok(includes) = socket_patch_core::vendor::requirements_include_names(project_root).await
    {
        files.extend(includes);
    }
    files.sort();
    files.dedup();
    for file in files {
        // FIFO-safe: a pipe under a wiring-file name must be skipped, not
        // waited on forever in open(2).
        let Ok(text) = read_regular_to_string(&project_root.join(file)).await else {
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

/// Record one artifact that cannot be repaired. An error, so the line
/// prints even under `--silent` (`json` mutes it: the envelope carries it).
fn fail(env: &mut Envelope, json: bool, purl: &str, code: &str, detail: String) {
    if !json {
        eprintln!("{}", format_repair_failure(purl, &detail));
    }
    env.record(PatchEvent::new(PatchAction::Failed, purl.to_string()).with_error(code, detail));
    env.mark_partial_failure();
}

/// `Error: Cannot repair vendored artifact for <purl>: <detail>`.
fn format_repair_failure(purl: &str, detail: &str) -> String {
    format!(
        "Error: Cannot repair vendored artifact for {}: {detail}",
        normalize_purl(purl)
    )
}

/// The `repair --dry-run` preview of vendored rebuilds: a heading, then
/// `  - <purl> (<why>: <path>)` per artifact. `items` are
/// `(purl, reason code, artifact path)`.
fn format_rebuild_preview(items: &[(String, &str, &str)]) -> Vec<String> {
    let mut lines = vec![format!(
        "Would rebuild {}:",
        plural(items.len(), "vendored artifact", "vendored artifacts")
    )];
    lines.extend(items.iter().map(|(purl, reason, path)| {
        format!("  - {purl} ({}: {path})", rebuild_reason_label(reason))
    }));
    lines
}

/// Plain words for a rebuild candidate's reason code.
fn rebuild_reason_label(code: &str) -> &str {
    match code {
        "vendor_artifact_missing" => "missing",
        "vendor_artifact_corrupt" => "corrupt",
        other => other,
    }
}

/// The `vendor_ledger_missing` detail for a lockfile reference no ledger
/// entry owns.
fn format_ledger_missing(eco: &str, uuid: &str) -> String {
    format!(
        "a lockfile references .socket/vendor/{eco}/{uuid}/ but the vendor ledger \
         (.socket/vendor/state.json) has no entry for it, and repair does not rebuild the \
         ledger from lockfiles; restore state.json from version control and re-run \
         `socket-patch repair`, or restore the lockfile (`git checkout -- <lockfile>`) and \
         re-vendor"
    )
}

/// Best-effort removal of a vendored uuid dir after a failed post-verify
/// (never leave unverifiable bytes behind). Prunes the emptied
/// `.socket/vendor/<eco>/` (and `vendor/`) husks like every other artifact
/// removal, stopping at `.socket/`; a sibling unit or the ledger keeps them.
async fn remove_vendor_dir(cwd: &Path, eco: &str, uuid: &str) {
    if let Some(rel) = vendor::path::vendor_uuid_dir_rel(eco, uuid) {
        let _ = socket_patch_core::utils::socket_dir::remove_tree_and_prune(
            &cwd.join(rel),
            &cwd.join(SOCKET_DIR),
        )
        .await;
    }
}

/// Move the live uuid dir aside (same parent, `<uuid>.pre-rebuild`) so the
/// engine's rebuild-on-MISSING trigger fires while the bytes stay
/// recoverable: the re-vendor can still refuse or fail, and a failed one
/// replaced nothing, so the corrupt-but-diagnosable artifact must be
/// restorable instead of leaving the wired lockfiles pointing at a bare
/// ENOENT (and the tamper evidence erased). Returns `(live, kept)` for
/// [`restore_aside_vendor_dir`]; on a rename failure falls back to plain
/// removal (the rebuild trigger must fire) and returns `None`.
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

/// Put the pre-rebuild bytes back after a re-vendor that produced no
/// replacement (clearing any partial husk the failed backend left first).
async fn restore_aside_vendor_dir(live: &Path, kept: &Path) {
    let _ = remove_tree(live).await;
    let _ = tokio::fs::rename(kept, live).await;
}

/// Crash recovery for [`set_aside_vendor_dir`]'s transient: a run killed
/// between the move-aside and the replacement leaves
/// `.socket/vendor/<eco>/<uuid>.pre-rebuild` as the ONLY copy of bytes the
/// rewired lockfiles still point at, with the live path a bare ENOENT. Put
/// every such leftover back where the wiring expects it before the health
/// pass classifies the unit. A leftover whose live sibling EXISTS is left
/// alone: the live dir may be the completed replacement or a partial husk,
/// and only the health pass can tell — a unit it condemns is set aside
/// again, which clears the leftover. Wet runs only; scope-gated like every
/// other unit; best-effort throughout.
async fn restore_orphaned_pre_rebuild_dirs(common: &GlobalArgs) {
    const SUFFIX: &str = ".pre-rebuild";
    let vendor_root = common.cwd.join(".socket/vendor");
    let Ok(mut ecos) = tokio::fs::read_dir(&vendor_root).await else {
        return;
    };
    while let Ok(Some(eco_dir)) = ecos.next_entry().await {
        let eco = eco_dir.file_name().to_string_lossy().into_owned();
        if !ecosystem_in_scope(common, &eco) || !eco_dir.path().is_dir() {
            continue;
        }
        let Ok(mut units) = tokio::fs::read_dir(eco_dir.path()).await else {
            continue;
        };
        while let Ok(Some(unit)) = units.next_entry().await {
            let name = unit.file_name().to_string_lossy().into_owned();
            let Some(uuid) = name.strip_suffix(SUFFIX) else {
                continue;
            };
            let live = eco_dir.path().join(uuid);
            if unit.path().is_dir() && tokio::fs::symlink_metadata(&live).await.is_err() {
                let _ = tokio::fs::rename(unit.path(), &live).await;
            }
        }
    }
}

/// What [`VendoredBackend::repair`] repairs against.
pub(crate) struct RepairRequest<'a> {
    /// `None` when the project has no `.socket/manifest.json` (vendored
    /// mode is manifest-free).
    pub(crate) manifest: Option<&'a PatchManifest>,
    pub(crate) socket_dir: &'a Path,
    /// [`scan_vendor_references`]'s output for `common.cwd`, taken by the
    /// caller under the apply lock this phase runs under.
    pub(crate) references: &'a [(String, String, String)],
    /// The caller's one `load_state` outcome (under the same lock). An
    /// unreadable ledger fails this phase loudly (`vendor_state_unreadable`).
    pub(crate) ledger: std::io::Result<VendorState>,
    /// The run's API client when the caller already built one: the uuid
    /// lookups and the re-vendor reuse it instead of constructing another
    /// (and re-printing its token advisory); `None` builds lazily on first
    /// need.
    pub(crate) client: Option<&'a ApiClient>,
}

impl VendoredBackend<'_> {
    /// The vendored-artifact phase of `repair` (see the module docs). Runs
    /// between the download and cleanup phases, under the caller's apply
    /// lock (and under `--download-only` — restoring artifacts IS repair's
    /// job). Returns the number of artifacts repaired, for the human
    /// summary; failures are carried by `env` (`Failed` events +
    /// partial-failure status).
    ///
    /// `self.service` is ignored: repair assembles its own service config
    /// from `--vendor-source` over the run's client, built only when there
    /// is something to re-vendor.
    pub(crate) async fn repair(&self, req: RepairRequest<'_>, env: &mut Envelope) -> usize {
        let common = self.common;
        let quiet = common.json || common.silent;
        let mut repaired = 0usize;

        if !common.dry_run {
            restore_orphaned_pre_rebuild_dirs(common).await;
        }

        let mut state = match req.ledger {
            Ok(s) => s,
            Err(e) => {
                // Errors print even under --silent; without this line the
                // run exits 1 after a clean-looking repair report.
                if !common.json {
                    eprintln!(
                        "{}",
                        crate::commands::vendor::format_state_unreadable(&e.to_string())
                    );
                }
                env.record(
                    PatchEvent::artifact(PatchAction::Failed)
                        .with_error("vendor_state_unreadable", e.to_string()),
                );
                env.mark_partial_failure();
                return repaired;
            }
        };

        // The one API client of this phase (and its one-time token-shape
        // stderr advisory), seeded from the run's client when there is one.
        let mut api_client: Option<ApiClient> = req.client.cloned();
        let mut candidates: Vec<Candidate> = Vec::new();

        // ── Health check: every in-scope ledger entry ────────────────────
        let mut ledger_purls: Vec<String> = state.entries.keys().cloned().collect();
        ledger_purls.sort();
        for purl in &ledger_purls {
            let entry = state.entries[purl].clone();
            if !ecosystem_in_scope(common, &entry.ecosystem) {
                continue;
            }
            // `detached` is the "no manifest owner" flag. Every entry
            // embeds its record, so an embedded record does not imply
            // detached: a manifest-owned entry keeps taking the manifest's
            // record (a manifest that moved on to a newer patch uuid must
            // still surface as vendor_uuid_mismatch below, never repair the
            // stale artifact from the embedded copy), and the embedded copy
            // stands in only when there is no manifest at all.
            let record = match (entry.detached, &entry.record, req.manifest) {
                (true, Some(r), _) => r.clone(),
                (_, _, Some(m)) => {
                    match m
                        .patches
                        .get(purl)
                        .cloned()
                        .or_else(|| m.patches.values().find(|r| r.uuid == entry.uuid).cloned())
                    {
                        Some(r) => r,
                        // Dropped from the manifest: the vendor reconcile
                        // owns reverting it — not repair's call.
                        None => continue,
                    }
                }
                // No manifest at all: the embedded copy, else (a ledger
                // written before every entry embedded its record) the patch
                // view from the API.
                (_, Some(r), None) => r.clone(),
                (_, None, None) => {
                    match fetch_record_by_uuid(common, &mut api_client, &entry.uuid).await {
                        Some((_, r)) => r,
                        None => {
                            fail(
                                env,
                                common.json,
                                purl,
                                "vendor_artifact_unrepairable",
                                format!(
                                    "no manifest record for patch {} and the patch view \
                                     could not be fetched (offline or API failure)",
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
                         `scan --mode vendored`) to re-vendor",
                    ),
                );
                continue;
            }
            // Pre-v5 cargo wiring in `.cargo/config*`: move it into the
            // root Cargo.toml (the v5 location) and record the move in the
            // ledger — or restore the manifest entry a pre-v5
            // multi-version vendor lost — and tag an untagged copy + lock
            // entry with the patch uuid.
            let entry = if entry.ecosystem == "cargo" {
                match vendor::cargo::migrate_legacy_wiring(&entry, &common.cwd, common.dry_run)
                    .await
                {
                    Ok(Some((migrated, warnings))) => {
                        for warning in &warnings {
                            record_warning(env, purl, warning, common);
                        }
                        if common.dry_run {
                            entry
                        } else if persist_vendor_entry(
                            common,
                            env,
                            &mut state,
                            purl,
                            migrated.clone(),
                            entry.detached,
                            &record,
                        )
                        .await
                        {
                            continue;
                        } else {
                            migrated
                        }
                    }
                    Ok(None) => entry,
                    Err(detail) => {
                        record_warning(
                            env,
                            purl,
                            &VendorWarning::new(
                                "cargo_legacy_wiring_kept",
                                format!(
                                    "the vendored wiring for {} could not be written into \
                                     Cargo.toml ({detail}); any pre-v5 .cargo/config wiring \
                                     was left in place",
                                    normalize_purl(purl)
                                ),
                            ),
                            common,
                        );
                        entry
                    }
                }
            } else {
                entry
            };
            let health = check_vendored_artifact(&common.cwd, &entry, &record).await;
            if health == ArtifactHealth::Healthy || workspace_copy_issue(&health) {
                let mut healed = entry.clone();
                match repair_workspace_copies(&common.cwd, &mut healed, common.dry_run).await {
                    Ok(true) => {
                        if common.dry_run {
                            env.record(
                                PatchEvent::new(PatchAction::Verified, purl.clone())
                                    .with_details(serde_json::json!({
                                        "vendorArtifact": true,
                                        "wouldRestoreWorkspaceArtifacts": true,
                                    })),
                            );
                        } else if !persist_vendor_entry(
                            common,
                            env,
                            &mut state,
                            purl,
                            healed,
                            entry.detached,
                            &record,
                        )
                        .await
                        {
                            env.record(
                                PatchEvent::new(PatchAction::Rebuilt, purl.clone()).with_details(
                                    serde_json::json!({
                                        "path": entry.artifact.path,
                                        "workspaceArtifactsRestored": true,
                                        "artifactRebuilt": false,
                                    }),
                                ),
                            );
                            repaired += 1;
                        }
                        continue;
                    }
                    Ok(false) => {}
                    Err(detail) => {
                        fail(
                            env,
                            common.json,
                            purl,
                            "vendor_artifact_unrepairable",
                            detail,
                        );
                        continue;
                    }
                }
                if workspace_copy_issue(&health) {
                    continue;
                }
            }
            match health {
                ArtifactHealth::Healthy => {
                    // vlt's `<uuid>/.gitignore` and `.gitattributes` are not
                    // part of the artifact: a missing or edited one is
                    // simply rewritten.
                    if entry.ecosystem == "npm"
                        && entry.flavor.as_deref() == Some(vendor::vlt_lock::FLAVOR)
                        && !common.dry_run
                    {
                        if let Err(e) =
                            vendor::vlt_lock::restore_vlt_uuid_metadata(&entry, &common.cwd).await
                        {
                            fail(
                                env,
                                common.json,
                                purl,
                                "vendor_artifact_unrepairable",
                                format!("cannot restore the vendored dir's .gitignore: {e}"),
                            );
                            continue;
                        }
                    }
                    // Dir-shaped gem artifacts from pre-inventory vendors:
                    // the health check could only verify the PATCHED members
                    // — unpatched-file drift is invisible until a re-vendor
                    // records the whole-tree inventory. Named for gem only:
                    // vlt also records inventories but has no pre-inventory
                    // entries, and the other dir-shaped backends
                    // (cargo/golang/composer) record none, so the advice
                    // would be permanent per-run noise there.
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
                        common.json,
                        purl,
                        "vendor_artifact_unrepairable",
                        format!("the ledger entry cannot be verified ({reason}); fix state.json"),
                    );
                }
                ArtifactHealth::UnknownFlavor { flavor } => {
                    record_warning(
                        env,
                        purl,
                        &VendorWarning::new(
                            "vendor_wiring_unknown_revert_blocked",
                            format!(
                                "{} was vendored for the npm flavor `{flavor}`, which this \
                                 socket-patch release does not understand; left untouched — \
                                 upgrade socket-patch",
                                normalize_purl(purl)
                            ),
                        ),
                        common,
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
                        reason,
                    });
                }
            }
        }

        // ── Lockfile references no ledger entry owns ─────────────────────
        // Reported, never re-synthesized: the pre-vendor originals a revert
        // replays are not recoverable from the rewired lockfile.
        let covered: HashSet<(String, String)> = state
            .entries
            .values()
            .map(|e| (e.ecosystem.clone(), e.uuid.clone()))
            .collect();
        for (eco, uuid, _) in req.references {
            if covered.contains(&(eco.clone(), uuid.clone())) || !ecosystem_in_scope(common, eco) {
                continue;
            }
            fail(
                env,
                common.json,
                &format!("pkg:{eco}/unknown@{uuid}"),
                "vendor_ledger_missing",
                format_ledger_missing(eco, uuid),
            );
        }

        if candidates.is_empty() {
            return repaired;
        }

        // ── Dry run: preview only ────────────────────────────────────────
        if common.dry_run {
            if !quiet {
                let items: Vec<(String, &str, &str)> = candidates
                    .iter()
                    .map(|c| {
                        let purl = normalize_purl(&c.purl).into_owned();
                        (purl, c.reason, c.entry.artifact.path.as_str())
                    })
                    .collect();
                println!();
                for line in format_rebuild_preview(&items) {
                    println!("{line}");
                }
            }
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
            return repaired;
        }

        if !quiet {
            println!();
            println!(
                "Rebuilding {}...",
                plural(
                    candidates.len(),
                    "broken vendored artifact",
                    "broken vendored artifacts"
                )
            );
        }

        // ── Re-vendor through the shared apply engine ────────────────────
        // A corrupt artifact is moved aside so the engine's
        // rebuild-on-missing path fires; it goes back if nothing replaced
        // it. A missing one has nothing to keep.
        let mut aside: HashMap<String, (PathBuf, PathBuf)> = HashMap::new();
        for c in &candidates {
            if c.reason == "vendor_artifact_corrupt" {
                if let Some(pair) =
                    set_aside_vendor_dir(&common.cwd, &c.entry.ecosystem, &c.entry.uuid).await
                {
                    aside.insert(c.purl.clone(), pair);
                }
            }
        }
        if api_client.is_none() && !common.offline {
            api_client = Some(
                get_api_client_with_overrides(common.api_client_overrides())
                    .await
                    .0,
            );
        }
        let use_public_proxy = api_client.as_ref().is_some_and(ApiClient::uses_public_proxy);
        let service = common.vendor_service_config(api_client, use_public_proxy);
        // The engine runs quiet into a scratch envelope: repair speaks in
        // its own vocabulary (`rebuilt`, "Cannot repair …") and translates
        // each candidate's outcome below.
        let mut engine_common = common.clone();
        engine_common.json = true;
        engine_common.silent = true;
        let engine = VendoredBackend::new(&engine_common, Some(&service));
        let mut scratch = Envelope::new(crate::json_envelope::Command::Vendor);
        let mut no_source = false;
        for detached in [false, true] {
            let records: HashMap<String, PatchRecord> = candidates
                .iter()
                .filter(|c| c.detached == detached)
                .map(|c| (c.purl.clone(), c.record.clone()))
                .collect();
            if records.is_empty() {
                continue;
            }
            let manifest = records_manifest(records);
            // The ledger as the previous group left it.
            let ledger = load_state(&common.cwd).await;
            let applied = engine
                .apply(
                    ApplyRequest {
                        manifest: &manifest,
                        socket_dir: req.socket_dir,
                        ledger,
                        seed: HashMap::new(),
                        detached,
                        force: false,
                        prior: None,
                    },
                    &mut scratch,
                )
                .await;
            no_source |= applied.is_err();
        }
        // The engine persisted each rebuilt entry; post-verify against the
        // ledger as it is now.
        let state = load_state(&common.cwd).await.unwrap_or(state);

        for c in candidates {
            let kept = aside.remove(&c.purl);
            let outcome = EngineOutcome::of(&scratch, &c.purl);
            forward_advisories(env, common, &scratch, &c.purl);
            let entry = state
                .entries
                .get(&c.purl)
                .cloned()
                .unwrap_or_else(|| c.entry.clone());
            let health = check_vendored_artifact(&common.cwd, &entry, &c.record).await;
            if outcome.rebuilt && health == ArtifactHealth::Healthy {
                if let Some((_, kept)) = &kept {
                    if let Some(w) =
                        vendor::vlt_lock::keep_vlt_links(&c.entry, kept, &common.cwd).await
                    {
                        record_warning(env, &c.purl, &w, common);
                    }
                    let _ = remove_tree(kept).await;
                }
                if !quiet {
                    println!(
                        "Rebuilt {} ({})",
                        normalize_purl(&c.purl),
                        entry.artifact.path
                    );
                }
                env.record(
                    PatchEvent::new(PatchAction::Rebuilt, c.purl.clone()).with_details(
                        serde_json::json!({
                            "path": entry.artifact.path,
                            "reason": c.reason,
                        }),
                    ),
                );
                repaired += 1;
                continue;
            }
            if outcome.rebuilt {
                // The re-vendor did not reproduce the recorded artifact
                // (e.g. a tampered ledger sha): remove it rather than leave
                // unverifiable bytes behind.
                remove_vendor_dir(&common.cwd, &entry.ecosystem, &entry.uuid).await;
                if let Some((_, kept)) = &kept {
                    let _ = remove_tree(kept).await;
                }
                fail(
                    env,
                    common.json,
                    &c.purl,
                    "vendor_artifact_rebuild_failed",
                    format!(
                        "the rebuilt artifact does not match the recorded fingerprint \
                         ({health:?}); if state.json was edited, run `socket-patch vendor` \
                         to re-vendor from scratch",
                    ),
                );
                continue;
            }
            // Nothing replaced the artifact: put the pre-rebuild bytes back.
            if let Some((live, kept)) = &kept {
                restore_aside_vendor_dir(live, kept).await;
            }
            let (code, detail) = match outcome.failure {
                Some((code, detail)) => (code, detail),
                None if no_source || outcome.no_source => (
                    c.reason.to_string(),
                    format!(
                        "the vendored artifact at {} is broken and its patch content could \
                         not be obtained ({})",
                        c.entry.artifact.path,
                        if common.offline {
                            "--offline prevents fetching it"
                        } else {
                            NO_LOCAL_SOURCE_MESSAGE
                        }
                    ),
                ),
                None => (
                    c.reason.to_string(),
                    format!(
                        "the vendored artifact at {} is broken and could not be re-vendored",
                        c.entry.artifact.path
                    ),
                ),
            };
            fail(env, common.json, &c.purl, &code, detail);
        }
        repaired
    }
}

/// One candidate's outcome in the engine's scratch envelope.
struct EngineOutcome {
    /// The engine vendored it (`applied`).
    rebuilt: bool,
    /// Its failure or genuine skip, as `(code, detail)`.
    failure: Option<(String, String)>,
    /// Staging could not obtain its patch content (`no_local_source`).
    no_source: bool,
}

/// Engine skip codes that are a package's OUTCOME (everything else a
/// `Skipped` event carries is an uncounted advisory).
const OUTCOME_SKIPS: &[&str] = &[
    "already_vendored",
    "package_not_installed",
    "vendor_unsupported_ecosystem",
];

/// Engine advisories repair does not forward: its own `rebuilt` event and
/// candidate reason already say it.
const SUPPRESSED_ADVISORIES: &[&str] = &["vendor_artifact_missing", "vendor_artifact_rebuilt"];

impl EngineOutcome {
    fn of(scratch: &Envelope, purl: &str) -> Self {
        let mut out = EngineOutcome {
            rebuilt: false,
            failure: None,
            no_source: false,
        };
        for ev in scratch.events.iter().filter(|e| e.purl.as_deref() == Some(purl)) {
            let code = ev.error_code.clone().unwrap_or_default();
            let detail = ev.error.clone().or_else(|| ev.reason.clone()).unwrap_or_default();
            match ev.action {
                PatchAction::Applied => out.rebuilt = true,
                PatchAction::Failed if out.failure.is_none() => {
                    out.no_source |= code == "no_local_source";
                    out.failure = Some((code, detail));
                }
                PatchAction::Skipped
                    if out.failure.is_none() && OUTCOME_SKIPS.contains(&code.as_str()) =>
                {
                    out.failure = Some(("vendor_artifact_unrepairable".to_string(), detail));
                }
                _ => {}
            }
        }
        if !out.rebuilt && out.failure.is_none() {
            if let Some(e) = &scratch.error {
                out.failure = Some((e.code.clone(), e.message.clone()));
            }
        }
        out
    }
}

/// Carry the engine's advisories for `purl` into repair's envelope (as
/// uncounted events, like every vendor advisory) and onto stderr at the
/// vendor command's own tiers.
fn forward_advisories(env: &mut Envelope, common: &GlobalArgs, scratch: &Envelope, purl: &str) {
    for ev in scratch.events.iter().filter(|e| {
        e.purl.as_deref() == Some(purl) && matches!(e.action, PatchAction::Skipped)
    }) {
        let code = ev.error_code.as_deref().unwrap_or_default();
        if OUTCOME_SKIPS.contains(&code) || SUPPRESSED_ADVISORIES.contains(&code) {
            continue;
        }
        let detail = ev.reason.as_deref().unwrap_or_default();
        if !common.silent && !common.json {
            if let Some(line) = format_advisory(code, detail, common.verbose) {
                eprintln!("{line}");
            }
        }
        env.events.push(ev.clone());
    }
}

fn workspace_copy_issue(health: &ArtifactHealth) -> bool {
    matches!(health, ArtifactHealth::Corrupt { reason }
        if reason == "vendor_workspace_artifact_missing" || reason == "vendor_workspace_artifact_corrupt")
}

/// Preserve package originals while adopting/rebuilding every member-relative
/// copy from a canonical tarball whose whole-file fingerprint is trusted.
async fn repair_workspace_copies(
    root: &Path,
    entry: &mut VendorEntry,
    dry_run: bool,
) -> Result<bool, String> {
    let (wiring, mut changed) =
        vendor::bun_lock::repair_binary_workspace_artifacts(root, entry, dry_run).await?;
    for record in wiring {
        match entry
            .wiring
            .iter_mut()
            .find(|previous| previous.kind == record.kind && previous.file == record.file)
        {
            Some(previous) if *previous != record => {
                *previous = record;
                changed = true;
            }
            Some(_) => {}
            None => {
                entry.wiring.push(record);
                changed = true;
            }
        }
    }
    Ok(changed)
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
    let patch = client.fetch_patch(uuid).await.ok()??;
    Some(crate::commands::get::record_from_patch_response(&patch))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a local native binary resolution through the public binary
    /// rewrite entry point, which shares the codec with vendor's backend.
    fn native_binary_vendor_fixture(uuid: &str) -> Vec<u8> {
        use socket_patch_core::patch::redirect::{
            rewrite_bun_binary, DepOverride, Integrity, RewriteResult,
        };
        let bytes =
            include_bytes!("../../../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/bun.lockb");
        let mut result = RewriteResult::default();
        rewrite_bun_binary(
            bytes,
            &[DepOverride {
                ecosystem: "npm".into(),
                name: "minimist".into(),
                namespace: None,
                version: "1.2.2".into(),
                token: String::new(),
                patch_uuid: uuid.into(),
                artifact_url: format!("./.socket/vendor/npm/{uuid}/minimist-1.2.2.tgz"),
                berry_zip_url: None,
                registry_override: None,
                integrity: Integrity {
                    sha512: Some(format!("sha512-{}", "A".repeat(86) + "==")),
                    ..Default::default()
                },
            }],
            &mut result,
        );
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        result.binary_files.remove("bun.lockb").unwrap()
    }

    #[tokio::test]
    async fn binary_bun_references_are_scanned_without_a_ledger() {
        let root = tempfile::tempdir().unwrap();
        let uuid = "11111111-1111-4111-8111-111111111111";
        tokio::fs::write(
            root.path().join("bun.lockb"),
            native_binary_vendor_fixture(uuid),
        )
        .await
        .unwrap();
        let references = scan_vendor_references(root.path()).await;
        assert_eq!(
            references,
            vec![(
                "npm".into(),
                uuid.into(),
                format!(".socket/vendor/npm/{uuid}/minimist-1.2.2.tgz")
            )]
        );
        assert!(!root.path().join(".socket/vendor/state.json").exists());

        // Text takes precedence even if the older binary still references
        // an artifact: a stale binary must not keep an artifact "wired".
        tokio::fs::write(root.path().join("bun.lock"), "{}\n")
            .await
            .unwrap();
        assert!(scan_vendor_references(root.path()).await.is_empty());
        tokio::fs::remove_file(root.path().join("bun.lock"))
            .await
            .unwrap();
        tokio::fs::write(root.path().join("bun.lockb"), b"malformed")
            .await
            .unwrap();
        assert!(scan_vendor_references(root.path()).await.is_empty());
    }

    /// A FIFO under a wiring-file name (here the paired `<script>.py` of a
    /// `*.py.lock`, which the lister cannot filter because it derives the
    /// script name without stat'ing it) must not wedge `repair`: a
    /// plain `read_to_string` blocks in open(2) waiting for a writer. Every
    /// reference read must go through the FIFO-safe reader and skip it.
    #[cfg(unix)]
    #[tokio::test]
    async fn repair_returns_with_fifo_script() {
        use std::time::Duration;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let uuid = "11111111-1111-4111-8111-111111111111";
        let path = format!(".socket/vendor/pypi/{uuid}/requests-2.28.1-py3-none-any.whl");
        tokio::fs::write(
            root.join("tool.py.lock"),
            format!("archive = {{ path = '{path}' }}"),
        )
        .await
        .unwrap();
        let fifos = ["tool.py", "bun.lock"];
        for name in fifos {
            let c = std::ffi::CString::new(root.join(name).to_str().unwrap()).unwrap();
            assert_eq!(
                unsafe { libc::mkfifo(c.as_ptr(), 0o644) },
                0,
                "mkfifo {name}"
            );
        }
        // Release valve: if a read DID wedge in open(2), connecting a
        // writer lets the blocking thread finish so the runtime can shut
        // down and the test fails on the timeout instead of hanging.
        let release = || {
            use std::os::unix::fs::OpenOptionsExt as _;
            for name in fifos {
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(root.join(name));
            }
        };

        let scanned =
            tokio::time::timeout(Duration::from_secs(5), scan_vendor_references(root)).await;
        release();
        let refs = scanned.expect("scan_vendor_references must not wedge on a FIFO script");
        assert_eq!(
            refs,
            vec![("pypi".to_string(), uuid.to_string(), path.clone())],
            "the lock reference is still recovered around the FIFO"
        );

    }

    /// The requirements planner writes vendored pins into `-r` includes,
    /// so a reference may live ONLY in an include. Reading the root
    /// requirements.txt alone would leave such a wheel unrecoverable by
    /// `repair` and deletable by the orphan sweep.
    #[tokio::test]
    async fn scan_recovers_include_hosted_requirements_reference() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let uuid = "11111111-1111-4111-8111-111111111111";
        let path = format!(".socket/vendor/pypi/{uuid}/six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::write(root.join("requirements.txt"), "-r requirements/base.txt\n")
            .await
            .unwrap();
        tokio::fs::create_dir(root.join("requirements"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("requirements/base.txt"),
            format!(
                "./{path} --hash=sha256:{}  # socket-patch vendor: six==1.16.0\n",
                "0".repeat(64)
            ),
        )
        .await
        .unwrap();
        let refs = scan_vendor_references(root).await;
        assert_eq!(
            refs,
            vec![("pypi".to_string(), uuid.to_string(), path)],
            "{refs:?}"
        );
    }

    #[tokio::test]
    async fn scan_recovers_vlt_lock_and_workspace_package_json_references() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let in_lock = "11111111-1111-4111-8111-111111111111";
        let in_member = "22222222-2222-4222-8222-222222222222";
        let lock_path =
            format!(".socket/vendor/npm/{in_lock}/left-pad-1.3.0/node_modules/left-pad");
        let member_path = format!(".socket/vendor/npm/{in_member}/debug-4.3.4/node_modules/debug");
        let node_id = format!(
            "file~{}",
            lock_path
                .replace('/', "+")
                .replace("node_modules", "node__modules")
        );
        tokio::fs::write(
            root.join("vlt-lock.json"),
            format!(
                "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    \
                 \"{node_id}\": [0,\"left-pad\",null,\"{lock_path}\"],\n    \
                 \"~npm~debug@4.3.4\": [0,\"debug\",\"sha512-D==\"]\n  }},\n  \"edges\": {{\n    \
                 \"file~_d left-pad\": \"prod file:./{lock_path} {node_id}\",\n    \
                 \"workspace~packages+a debug\": \"prod 4.3.4 ~npm~debug@4.3.4\"\n  }}\n}}\n"
            ),
        )
        .await
        .unwrap();
        tokio::fs::write(
            root.join("package.json"),
            "{\"dependencies\":{\"left-pad\":\"1.3.0\"}}",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(root.join("packages/a"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("packages/a/package.json"),
            format!("{{\"dependencies\":{{\"debug\":\"file:../../{member_path}\"}}}}"),
        )
        .await
        .unwrap();
        assert_eq!(
            scan_vendor_references(root).await,
            vec![
                ("npm".to_string(), in_lock.to_string(), lock_path),
                ("npm".to_string(), in_member.to_string(), member_path),
            ]
        );
    }

    #[tokio::test]
    async fn scan_recovers_script_and_pep751_vendor_references() {
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "11111111-1111-4111-8111-111111111111";
        let path = format!(".socket/vendor/pypi/{uuid}/requests-2.28.1-py3-none-any.whl");
        for file in ["example.py.lock", "pylock.dev.toml"] {
            tokio::fs::write(
                tmp.path().join(file),
                format!("archive = {{ path = '{path}' }}"),
            )
            .await
            .unwrap();
        }
        let references = scan_vendor_references(tmp.path()).await;
        assert_eq!(
            references,
            vec![("pypi".to_string(), uuid.to_string(), path.clone())]
        );
    }

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
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "the emptied <eco>/ and vendor/ husks are pruned"
        );
        assert!(
            tmp.path().join(".socket").is_dir(),
            ".socket/ is never removed"
        );
    }

}

/// Exact-string tests for the vendored-repair human lines.
#[cfg(test)]
mod ui_format_tests {
    use super::*;

    #[test]
    fn repair_failure_line_has_error_prefix() {
        assert_eq!(
            format_repair_failure("pkg:npm/%40s/x@1.0.0", "no pristine source"),
            "Error: Cannot repair vendored artifact for pkg:npm/@s/x@1.0.0: no pristine source"
        );
    }

    #[test]
    fn rebuild_preview_singular_and_plural() {
        let one = vec![(
            "pkg:npm/minimist@1.2.5".to_string(),
            "vendor_artifact_missing",
            ".socket/vendor/npm/u/minimist-1.2.5.tgz",
        )];
        assert_eq!(
            format_rebuild_preview(&one),
            vec![
                "Would rebuild 1 vendored artifact:",
                "  - pkg:npm/minimist@1.2.5 (missing: .socket/vendor/npm/u/minimist-1.2.5.tgz)",
            ]
        );
        let two = vec![
            (
                "pkg:npm/a@1".to_string(),
                "vendor_artifact_corrupt",
                "p/a.tgz",
            ),
            (
                "pkg:gem/b@1".to_string(),
                "vendor_artifact_missing",
                "p/b",
            ),
        ];
        assert_eq!(
            format_rebuild_preview(&two),
            vec![
                "Would rebuild 2 vendored artifacts:",
                "  - pkg:npm/a@1 (corrupt: p/a.tgz)",
                "  - pkg:gem/b@1 (missing: p/b)",
            ]
        );
        assert_eq!(rebuild_reason_label("something_else"), "something_else");
    }
}
