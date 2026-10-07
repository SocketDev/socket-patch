//! Repair downloads the recorded server artifact into a temporary location,
//! checks its archive hash or file inventory, and replaces the damaged copy.
//! Wiring and ledger identities remain unchanged. Missing ledger entries
//! must be restored from version control so rollback originals are preserved.

use std::collections::HashSet;
use std::path::Path;

use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::formats::registry;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::utils::fs::read_regular_to_string;
use socket_patch_core::utils::purl::normalize_purl;
use socket_patch_core::vendor::{
    self, artifact_is_file_shaped, check_vendored_artifact, parse_vendor_path,
    path::parse_vendor_reference, ArtifactHealth, VendorEntry, VendorState, VendorWarning,
};

use super::VendoredBackend;
use crate::args::GlobalArgs;
use crate::commands::vendor::{ecosystem_in_scope, persist_vendor_entry, record_warning};
use crate::json_envelope::{Envelope, PatchAction, PatchEvent};
use crate::ui::plural;

/// One broken vendored unit queued for re-vendoring.
#[derive(Clone)]
struct Candidate {
    purl: String,
    entry: VendorEntry,
    record: PatchRecord,
    detached: bool,
    reason: &'static str,
}

/// Scan the wiring-bearing files for vendored-artifact references,
/// returning deduped `(ecosystem, uuid, artifact relpath)` triples (the
/// relpath is the uuid dir itself for a directory-wired unit). Pure
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

    let files = wiring_files(project_root).await;
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
            // colon — npm names/versions never contain one. `<` ends an XML
            // element's text (Maven's `<url>…/<uuid></url>`).
            let end = slice
                .find([
                    '"', '\'', '`', ' ', '\t', '\n', '\r', ',', ')', ']', '}', ';', ':', '<',
                ])
                .unwrap_or(slice.len());
            let candidate = slice[..end].replace('\\', "/");
            // NuGet's feed and Maven's repository name the uuid dir itself.
            if let Some(parts) = parse_vendor_reference(&candidate) {
                if seen.insert((parts.eco.to_string(), parts.uuid.clone())) {
                    out.push((
                        parts.eco.to_string(),
                        parts.uuid.clone(),
                        candidate
                            .trim_start_matches("./")
                            .trim_end_matches('/')
                            .to_string(),
                    ));
                }
            }
            rest = &rest[idx + ".socket".len()..];
        }
    }
    out.sort();
    out
}

/// Every wiring-bearing file name the vendor backends may rewrite, relative
/// to `project_root`: every file the registry says a vendored run writes
/// ([`registry::VENDORED`]: `nuget.config`, `pom.xml` and `hatch.toml`
/// included), vlt importer manifests, the Python
/// locks the root lists (and their scripts) and the requirements `-r`
/// include tree. Sorted and deduplicated; entries need not exist.
async fn wiring_files(project_root: &Path) -> Vec<String> {
    let mut files: Vec<String> = registry::paths_with(registry::VENDORED)
        .into_iter()
        .map(str::to_string)
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
    files
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

/// The `repair --dry-run` preview of vendored redownloads: a heading, then
/// `  - <purl> (<why>: <path>)` per artifact. `items` are
/// `(purl, reason code, artifact path)`.
fn format_redownload_preview(items: &[(String, &str, &str)]) -> Vec<String> {
    let mut lines = vec![format!(
        "Would redownload {}:",
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

/// Recover artifacts left aside by older releases when a repair was interrupted.
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
            if socket_patch_core::utils::purl::canonical_purl(purl)
                != socket_patch_core::utils::purl::canonical_purl(&entry.base_purl)
                || !vendor::is_vendorable(&entry.base_purl)
            {
                fail(
                    env,
                    common.json,
                    purl,
                    "vendor_artifact_unrepairable",
                    "the ledger package identity is invalid or unsupported".into(),
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
                                PatchEvent::new(PatchAction::Verified, purl.clone()).with_details(
                                    serde_json::json!({
                                        "vendorArtifact": true,
                                        "wouldRestoreWorkspaceArtifacts": true,
                                    }),
                                ),
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
                    // Likewise a JVM entry's derived metadata and owned
                    // `.gitattributes`: rewritten when missing, offline.
                    if vendor::jvm::apply::is_jvm_entry(&entry) && !common.dry_run {
                        if let Err(e) =
                            vendor::redownload::restore_jvm_owned_files(&common.cwd, &entry).await
                        {
                            fail(
                                env,
                                common.json,
                                purl,
                                "vendor_artifact_unrepairable",
                                format!("cannot restore the vendored Gradle files: {e}"),
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
        for (eco, uuid, path) in req.references {
            if covered.contains(&(eco.clone(), uuid.clone())) || !ecosystem_in_scope(common, eco) {
                continue;
            }
            // No ledger entry means no purl to name: the event carries the
            // uuid and the referenced path instead.
            let detail = format_ledger_missing(eco, uuid);
            if !common.json {
                eprintln!("Error: Cannot repair vendored artifact {path}: {detail}");
            }
            env.record(
                PatchEvent::artifact(PatchAction::Failed)
                    .with_uuid(uuid.clone())
                    .with_error("vendor_ledger_missing", detail)
                    .with_details(serde_json::json!({ "ecosystem": eco, "path": path })),
            );
            env.mark_partial_failure();
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
                for line in format_redownload_preview(&items) {
                    println!("{line}");
                }
            }
            for c in &candidates {
                env.record(
                    PatchEvent::new(PatchAction::Verified, c.purl.clone()).with_details(
                        serde_json::json!({
                            "vendorArtifact": true,
                            "wouldRedownload": true,
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
                "Redownloading {}...",
                plural(
                    candidates.len(),
                    "broken vendored artifact",
                    "broken vendored artifacts"
                )
            );
        }

        if api_client.is_none() && !common.offline {
            api_client = Some(
                get_api_client_with_overrides(common.api_client_overrides())
                    .await
                    .0,
            );
        }
        let use_public_proxy = api_client
            .as_ref()
            .is_some_and(ApiClient::uses_public_proxy);
        let service = common.vendor_service_config(api_client, use_public_proxy);
        for mut candidate in candidates {
            match vendor::redownload::restore(
                &common.cwd,
                &candidate.entry,
                &candidate.record,
                &service,
            )
            .await
            {
                Ok(warnings) => {
                    for warning in warnings {
                        record_warning(env, &candidate.purl, &warning, common);
                    }
                    match repair_workspace_copies(&common.cwd, &mut candidate.entry, false).await {
                        Ok(true) => {
                            if persist_vendor_entry(
                                common,
                                env,
                                &mut state,
                                &candidate.purl,
                                candidate.entry.clone(),
                                candidate.detached,
                                &candidate.record,
                            )
                            .await
                            {
                                env.mark_partial_failure();
                                continue;
                            }
                        }
                        Ok(false) => {}
                        Err(error) => {
                            fail(
                                env,
                                common.json,
                                &candidate.purl,
                                "vendor_artifact_redownload_failed",
                                error,
                            );
                            continue;
                        }
                    }
                    if !quiet {
                        println!(
                            "Redownloaded {} ({})",
                            normalize_purl(&candidate.purl),
                            candidate.entry.artifact.path
                        );
                    }
                    env.record(PatchEvent::new(PatchAction::Rebuilt, candidate.purl.clone()).with_details(serde_json::json!({
                        "path": candidate.entry.artifact.path, "reason": candidate.reason, "redownloaded": true,
                    })));
                    repaired += 1;
                }
                Err(error) => fail(
                    env,
                    common.json,
                    &candidate.purl,
                    "vendor_artifact_redownload_failed",
                    error,
                ),
            }
        }
        repaired
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
        let bytes = include_bytes!(
            "../../../../socket-patch-core/tests/fixtures/bun-lockb/1.1.45/bun.lockb"
        );
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

    /// #832, #958: every file a vendored run writes is scanned, and a
    /// reference to the uuid dir itself counts. NuGet's feed and Maven's
    /// repository name the dir (Windows backslashes and a trailing slash
    /// included); a Hatch environment in `hatch.toml` names a wheel. Every
    /// caller (repair, the orphan sweeps, the `vendor` stranded-reference
    /// gate, rollback's ledger-less gate) reads this one scan.
    #[tokio::test]
    async fn scan_recovers_unit_dir_and_hatch_toml_references() {
        let tmp = tempfile::tempdir().unwrap();
        let nuget = "22222222-2222-4222-8222-222222222222";
        let nuget_win = "55555555-5555-4555-8555-555555555555";
        let maven = "33333333-3333-4333-8333-333333333333";
        let pypi = "44444444-4444-4444-8444-444444444444";
        let wheel = "six-1.16.0-py2.py3-none-any.whl";
        for (file, text) in [
            (
                "nuget.config",
                format!("<add key=\"socket-patch-vendor\" value=\".socket/vendor/nuget/{nuget}/\" />"),
            ),
            (
                "NuGet.Config",
                format!("<add key=\"socket-patch-vendor\" value=\".socket\\vendor\\nuget\\{nuget_win}\" />"),
            ),
            (
                "pom.xml",
                format!("<url>file://${{project.basedir}}/.socket/vendor/maven/{maven}</url>"),
            ),
            (
                "hatch.toml",
                format!("[envs.default]\ndependencies = [\"six @ {{root:uri}}/.socket/vendor/pypi/{pypi}/{wheel}\"]\n"),
            ),
        ] {
            tokio::fs::write(tmp.path().join(file), text).await.unwrap();
        }
        let refs = scan_vendor_references(tmp.path()).await;
        assert_eq!(
            refs,
            vec![
                (
                    "maven".to_string(),
                    maven.to_string(),
                    format!(".socket/vendor/maven/{maven}")
                ),
                (
                    "nuget".to_string(),
                    nuget.to_string(),
                    format!(".socket/vendor/nuget/{nuget}")
                ),
                (
                    "nuget".to_string(),
                    nuget_win.to_string(),
                    format!(".socket/vendor/nuget/{nuget_win}")
                ),
                (
                    "pypi".to_string(),
                    pypi.to_string(),
                    format!(".socket/vendor/pypi/{pypi}/{wheel}")
                ),
            ]
        );

        // A bare eco dir or a non-uuid dir is still no reference.
        tokio::fs::write(
            tmp.path().join("pom.xml"),
            "<url>file://${project.basedir}/.socket/vendor/maven</url>\n\
             <url>file://${maven.multiModuleProjectDirectory}/.socket/vendor/maven2</url>\n\
             <url>file://${project.basedir}/.socket/vendor/maven/not-a-uuid</url>",
        )
        .await
        .unwrap();
        let refs = scan_vendor_references(tmp.path()).await;
        assert!(refs.iter().all(|(eco, _, _)| eco != "maven"), "{refs:?}");
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
            format_redownload_preview(&one),
            vec![
                "Would redownload 1 vendored artifact:",
                "  - pkg:npm/minimist@1.2.5 (missing: .socket/vendor/npm/u/minimist-1.2.5.tgz)",
            ]
        );
        let two = vec![
            (
                "pkg:npm/a@1".to_string(),
                "vendor_artifact_corrupt",
                "p/a.tgz",
            ),
            ("pkg:gem/b@1".to_string(), "vendor_artifact_missing", "p/b"),
        ];
        assert_eq!(
            format_redownload_preview(&two),
            vec![
                "Would redownload 2 vendored artifacts:",
                "  - pkg:npm/a@1 (corrupt: p/a.tgz)",
                "  - pkg:gem/b@1 (missing: p/b)",
            ]
        );
        assert_eq!(rebuild_reason_label("something_else"), "something_else");
    }
}
