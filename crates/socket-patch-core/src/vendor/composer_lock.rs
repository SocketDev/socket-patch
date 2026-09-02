//! Composer vendor backend: lock-only `dist` surgery pointing at a committed
//! patched copy.
//!
//! Spike-verified mechanism (composer 2.10 — `spikes/PHASE0-FINDINGS.txt`):
//! edit ONLY `composer.lock`. `composer.json` is never touched, and the lock's
//! `content-hash` covers composer.json alone, so the surgery triggers no
//! "lock file out of date" warning. The package's lock entry is rewritten to:
//!
//! * `dist` → `{"type": "path", "url": "<rel copy dir>", "reference": null}`
//!   (replaced IN ITS ORIGINAL SLOT so the entry's key order is stable);
//! * `source` REMOVED entirely — left in place, `--prefer-source` could
//!   git-clone the unpatched upstream; with it removed the spike confirmed
//!   `--prefer-source` falls back to the path dist cleanly;
//! * `"transport-options": {"symlink": false}` inserted right after `dist` —
//!   LOAD-BEARING: composer's default path-repo strategy symlinks, and a
//!   symlink into `.socket/vendor/` would defeat the real-copy guarantee.
//!   `symlink: false` forces the 'Mirroring' (copy) strategy.
//!
//! Lock names are matched CASE-INSENSITIVELY (locks are normally lowercase,
//! but hand-written mixed-case locks exist and install fine) while the dist
//! URL we write always uses the lowercase canonical `<vendor>/<name>` — the
//! casing of the directory this backend creates. Versions are matched through
//! the leading-`v` normalization (locks carry the pretty `v6.4.1`, PURLs the
//! bare `6.4.1`) but the lock's own `version` string is never rewritten.
//!
//! Serialization mirrors composer's own writer: 4-space indent
//! (`JSON_PRETTY_PRINT`) + trailing newline; serde_json does not escape `/`
//! (matching `JSON_UNESCAPED_SLASHES`).

use std::collections::HashSet;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::crawlers::composer_crawler::normalize_version;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::path_safety::{is_safe_multi_segment, is_safe_single_segment};
use crate::utils::fs::atomic_write_bytes_preserving_mode;
use crate::utils::purl::{build_composer_purl, parse_composer_purl};

use super::common::{
    already_patched_result, copy_matches_after_hashes, done, refused, serialize_json,
    service_offline_conflict, synthesized_result,
};
use super::path::{parse_vendor_path, vendor_uuid_dir_rel};
use super::registry_fetch::extract_zip;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::{
    write_marker, VendorArtifact, VendorEntry, VendorMarker, WiringAction, WiringRecord,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// Project-relative lockfile this backend wires.
const COMPOSER_LOCK: &str = "composer.lock";

/// Guarded read shared in shape with the Cargo.lock / .cargo/config.toml
/// twins: `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular
/// files, so a FIFO planted as `composer.lock` fails fast instead of wedging
/// every caller (vendor's presence read, revert's stranded scan and restore)
/// forever in an `open(2)` that waits for a writer.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

/// Wiring-record discriminator. The record's `key` is
/// `"<section>:<vendor>/<name>"` where `<section>` is `packages` or
/// `packages-dev` (the lock array holding the entry) and `<vendor>/<name>` is
/// the lowercase canonical package name — `:` cannot appear in a composer
/// package name, so the encoding is unambiguous.
const WIRING_KIND: &str = "composer_lock_package";

/// Vendor a composer package: materialize a patched copy under
/// `.socket/vendor/composer/<uuid>/<vendor>/<name>@<version>` and rewire the
/// matching `composer.lock` entry at it (see the module doc for the surgery).
///
/// `installed_dir` is the crawler's package dir (`vendor/<v>/<n>` — the same
/// root `apply` patches, so the manifest file keys resolve relative to it).
/// The lock edit runs LAST: any copy/patch failure removes the copy and
/// leaves the lock untouched.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_composer(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    // ── coordinates ──────────────────────────────────────────────────────
    let Some(((vendor, name), version)) = parse_composer_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a composer purl: {purl}"));
    };
    // Canonical (packagist) lowercase form keys the on-disk copy dir and the
    // dist URL; the lock's own pretty casing is preserved untouched.
    let vendor = vendor.to_lowercase();
    let name = name.to_lowercase();
    let pkg = format!("{vendor}/{name}");

    // SECURITY: `uuid`, `vendor/name` and `version` come from committed,
    // tamper-able manifest data and key the copy dir that vendor creates and
    // `--revert` deletes. A `..` segment, separator, or non-canonical uuid
    // would escape `.socket/vendor/composer/` — reject fail-closed before any
    // disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("composer", &record.uuid) else {
        return refused(
            "unsafe_coordinates",
            format!("non-canonical patch uuid {:?}", record.uuid),
        );
    };
    if !is_safe_multi_segment(&pkg) || !is_safe_single_segment(version) {
        return refused(
            "unsafe_coordinates",
            format!("unsafe composer coordinates `{pkg}` @ `{version}`"),
        );
    }

    let copy_rel = format!("{uuid_dir_rel}/{pkg}@{version}");
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let copy_dir = project_root.join(&copy_rel);

    // A patch with no files is meaningless to vendor: no-op success, no edits.
    if record.files.is_empty() {
        let result = synthesized_result(purl, &copy_dir, Vec::new(), true, None);
        return done(result, None, Vec::new());
    }

    // ── lock presence + entry ────────────────────────────────────────────
    let lock_path = project_root.join(COMPOSER_LOCK);
    let lock_text = match read_regular_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return refused(
                "vendor_lockfile_missing",
                format!("no composer.lock at {}", lock_path.display()),
            );
        }
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("unreadable composer.lock: {e}"),
            );
        }
    };
    // An unparseable lock is as unusable as a missing one — same refusal code.
    let mut lock: Value = match serde_json::from_str(&lock_text) {
        Ok(v) => v,
        Err(e) => {
            return refused(
                "vendor_lockfile_missing",
                format!("unparseable composer.lock: {e}"),
            );
        }
    };
    let Some((section, idx)) = find_lock_entry(&lock, &pkg, version) else {
        return refused(
            "vendor_lock_entry_not_found",
            format!("{pkg}@{version} is in neither packages[] nor packages-dev[] of composer.lock"),
        );
    };

    // ── idempotent hot path ──────────────────────────────────────────────
    // Copy already carries every afterHash and the lock entry already points
    // at the uuid path → touch nothing, report AlreadyPatched. `entry` stays
    // `None`: the first run's ledger entry holds the only copy of the
    // verbatim pre-vendor original, and re-recording here would clobber it.
    if entry_is_wired(&lock[section][idx], &copy_rel) {
        if copy_matches_after_hashes(&copy_dir, &record.files).await {
            let result = already_patched_result(purl, &copy_dir, &record.files);
            return done(result, None, Vec::new());
        }
        // Wired but the committed copy is missing/stale: rebuild the
        // ARTIFACT only. The lock is already correct and the first run's
        // ledger entry holds the only pre-vendor original — running the
        // full path here would re-record the live VENDORED fragment as
        // `original`, breaking a later `--revert`. Service-preferred like
        // the full path (a service-vendored package may have no installed
        // copy to rebuild from — only the service can).
        if !dry_run {
            if let Some(refusal) = service_offline_conflict(service) {
                return refusal;
            }
            let mut warnings: Vec<VendorWarning> = Vec::new();
            let result = match composer_service_copy(
                service,
                record,
                &pkg,
                &copy_dir,
                &uuid_dir,
                &mut warnings,
            )
            .await
            {
                ComposerServiceCopy::Used => already_patched_result(purl, &copy_dir, &record.files),
                ComposerServiceCopy::HardFail(outcome) => return *outcome,
                ComposerServiceCopy::FallBack => {
                    match copy_and_patch(
                        purl,
                        installed_dir,
                        &copy_dir,
                        &uuid_dir,
                        record,
                        sources,
                        force,
                        false, // live-wired: never unwind the uuid dir on failure
                        &pkg,
                        version,
                        &mut warnings,
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(result) => return done(result, None, warnings),
                    }
                }
            };
            warnings.push(VendorWarning::new(
                "vendor_artifact_rebuilt",
                format!(
                    "the committed vendored copy for {pkg}@{version} was missing or stale; \
                     rebuilt at {copy_rel} (composer.lock untouched)"
                ),
            ));
            return done(result, None, warnings);
        }
        // Dry runs fall through to the verify-only preview below.
    }

    // ── dry run: verify-only against the installed dir, no writes ────────
    if dry_run {
        let mut dry_warnings: Vec<VendorWarning> = Vec::new();
        let mut result = super::force_apply_staged(
            purl,
            installed_dir,
            record,
            sources,
            true,
            force,
            &pkg,
            version,
            &mut dry_warnings,
        )
        .await;
        result.package_path = copy_dir.display().to_string();
        return done(result, None, dry_warnings);
    }

    // ── copy + patch (wiring last) ───────────────────────────────────────
    // Prefer the prebuilt dist zip from the patch service (download + extract,
    // no installed package needed); else copy the installed package and patch
    // it.
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if let Some(refusal) = service_offline_conflict(service) {
        return refusal;
    }
    let mut result =
        match composer_service_copy(service, record, &pkg, &copy_dir, &uuid_dir, &mut warnings)
            .await
        {
            ComposerServiceCopy::Used => already_patched_result(purl, &copy_dir, &record.files),
            ComposerServiceCopy::HardFail(outcome) => return *outcome,
            ComposerServiceCopy::FallBack => {
                match copy_and_patch(
                    purl,
                    installed_dir,
                    &copy_dir,
                    &uuid_dir,
                    record,
                    sources,
                    force,
                    true, // fresh vendor: nothing pre-existing worth keeping
                    &pkg,
                    version,
                    &mut warnings,
                )
                .await
                {
                    Ok(result) => result,
                    Err(result) => return done(result, None, warnings),
                }
            }
        };

    // ── lock rewrite ─────────────────────────────────────────────────────
    let original_entry = lock[section][idx].clone();
    let Some(original_obj) = original_entry.as_object() else {
        // find_lock_entry only matches objects; defensive.
        let _ = remove_tree(&uuid_dir).await;
        prune_empty_vendor_dirs(&copy_dir).await;
        result.success = false;
        result.error = Some("composer.lock entry is not a JSON object".to_string());
        return done(result, None, warnings);
    };
    // Never record one of our own (stale) edits as the "original" — revert
    // must restore the pre-vendor registry fragment, not a dangling
    // `.socket/vendor/` pointer from an earlier uuid. The persist layer
    // carries the true original forward from the entry being replaced when
    // the record holds `None`.
    let was_vendored = original_obj
        .get("dist")
        .and_then(|d| d.get("url"))
        .and_then(Value::as_str)
        .and_then(parse_vendor_path)
        .is_some_and(|p| p.eco == "composer");
    let rewritten = rewrite_lock_entry(original_obj, &copy_rel, &record.uuid);
    lock[section][idx] = Value::Object(rewritten.clone());
    let write_result = match composer_json_bytes(&lock) {
        Ok(bytes) => atomic_write_bytes_preserving_mode(&lock_path, &bytes).await,
        Err(e) => Err(e),
    };
    if let Err(e) = write_result {
        let _ = remove_tree(&uuid_dir).await;
        prune_empty_vendor_dirs(&copy_dir).await;
        result.success = false;
        result.error = Some(format!("failed to write composer.lock: {e}"));
        return done(result, None, warnings);
    }

    // ── marker + ledger entry ────────────────────────────────────────────
    let base_purl = build_composer_purl(&vendor, &name, version);
    let marker = VendorMarker::new("composer", &base_purl, record, vendored_at);
    if let Err(e) = write_marker(&uuid_dir, &marker).await {
        // The marker is informational only (state.json is the ledger of
        // record), so its failure must not fail an otherwise-wired vendor.
        warnings.push(VendorWarning::new(
            "vendor_marker_write_failed",
            format!("could not write {}: {e}", super::state::VENDOR_MARKER_FILE),
        ));
    }

    let entry = VendorEntry {
        ecosystem: "composer".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: copy_rel,
            sha256: String::new(), // dir-shaped: integrity is per-file afterHashes
            size: None,
            platform_locked: None,
            file_inventory: None,
        },
        wiring: vec![WiringRecord {
            file: COMPOSER_LOCK.to_string(),
            kind: WIRING_KIND.to_string(),
            action: WiringAction::Rewritten,
            key: Some(format!("{section}:{pkg}")),
            original: (!was_vendored).then_some(original_entry),
            new: Some(Value::Object(rewritten)),
        }],
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
    };

    done(result, Some(entry), warnings)
}

/// Revert a composer vendor entry: restore the verbatim original lock entry
/// (when the live entry still points into our uuid dir) and remove the
/// validated uuid dir. A drifted live entry — rewritten by a `composer
/// update`, a hand edit, or a newer vendor run — is left alone with a
/// `vendor_lock_entry_drifted` warning.
///
/// Refused fail-closed when composer.lock still wires a package to our uuid
/// dir that NO wiring record can restore (a `repair`-reconstructed entry
/// carries no pre-vendor fragment): the registry `dist` the surgery replaced
/// exists nowhere else — not in the lock (we overwrote it), not in the
/// artifact — so an un-rewrite is impossible offline, and deleting the
/// artifacts anyway would leave the lock pointing at a gone path (`composer
/// install` then dies with "Source path … is not found"). Nothing is deleted
/// in that case; the error names the re-resolve escape hatch.
///
/// Note: the *installed* `vendor/<v>/<n>` keeps the patched bytes until the
/// next `composer install` re-mirrors from the registry; revert surfaces that
/// as the `vendor_installed_copy_stale` advisory.
pub async fn revert_composer(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    revert_composer_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_composer`] with full [`RevertOpts`]: `keep_artifact` skips the
/// artifact deletion — and the stranded-wiring refusal that exists only to
/// protect it — while the wiring restore runs unchanged.
pub async fn revert_composer_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    // SECURITY: state.json is committed and tamper-able; the uuid keys the
    // directory we are about to delete. Anything but the canonical uuid
    // grammar is rejected fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("composer", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing revert: non-canonical patch uuid {:?}",
            entry.uuid
        ));
    };
    let uuid_dir = project_root.join(&uuid_dir_rel);
    let lock_path = project_root.join(COMPOSER_LOCK);
    let mut warnings = Vec::new();

    // Nothing may be deleted while composer.lock still consumes it. Checked
    // BEFORE the restore loop (and before any write) so the answer is the
    // same for `--dry-run` and a wet run. Skipped under `keep_artifact`:
    // the refusal exists only to protect the deletion, which a
    // preserve-state revert never performs.
    if !keep_artifact {
        let stranded =
            stranded_wired_packages(&lock_path, &entry.uuid, &restorable_keys(entry)).await;
        if !stranded.is_empty() {
            let listed = stranded.join(", ");
            let args = stranded.join(" ");
            return RevertOutcome::failed(format!(
                "refusing revert: composer.lock still points {listed} at {uuid_dir_rel}, but the \
                 ledger entry records no pre-vendor lock fragment to restore (an entry \
                 reconstructed by `socket-patch repair` recovers the artifact, never the \
                 registry dist the surgery replaced). The vendored artifacts were LEFT IN \
                 PLACE so the project still installs. To undo the vendoring, re-resolve the \
                 package from the registry first (`composer update --no-install {args}`), then \
                 re-run `socket-patch vendor --revert`"
            ));
        }
    }

    // Wiring is restored in reverse application order (one record today).
    for w in entry.wiring.iter().rev() {
        if w.kind != WIRING_KIND {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unrecognized wiring kind {:?}; fragment left alone", w.kind),
            ));
            continue;
        }
        match restore_lock_entry(&lock_path, w, &entry.uuid, dry_run).await {
            Ok(true) => {}
            Ok(false) => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "composer.lock entry for {} no longer points into .socket/vendor/composer/; left alone",
                    w.key.as_deref().unwrap_or("<unknown>")
                ),
            )),
            Err(e) => {
                return RevertOutcome {
                    kept_artifact: false,
                    success: false,
                    warnings,
                    error: Some(e),
                };
            }
        }
    }

    // `--preserve-state` (`keep_artifact`): the artifact dir stays behind
    // (and the caller keeps the ledger entry), so only the deletion is
    // skipped.
    if !dry_run && !keep_artifact {
        if let Err(e) = remove_tree(&uuid_dir).await {
            return RevertOutcome {
                kept_artifact: false,
                success: false,
                warnings,
                error: Some(format!("failed to remove {}: {e}", uuid_dir.display())),
            };
        }
    }

    warnings.push(VendorWarning::new(
        "vendor_installed_copy_stale",
        format!(
            "the installed vendor/{} copy keeps the patched bytes until the next `composer install`",
            entry
                .wiring
                .first()
                .and_then(|w| w.key.as_deref())
                .and_then(|k| k.split_once(':').map(|(_, p)| p))
                .unwrap_or("<package>")
        ),
    ));

    RevertOutcome {
        kept_artifact: false,
        success: true,
        warnings,
        error: None,
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn swap_sibling_for(copy_dir: &Path, suffix: &str) -> std::path::PathBuf {
    let name = copy_dir
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "copy".to_string());
    match copy_dir.parent() {
        Some(parent) => parent.join(format!("{name}{suffix}")),
        None => copy_dir.join(suffix),
    }
}

/// The staging sibling for a copy dir:
/// `<uuid>/<vendor>/<name>@<version>.socket-stage`. (Re)builds are
/// materialised here and swapped into place only on success, so a failure can
/// never destroy a pre-existing (possibly live-wired) copy.
fn stage_dir_for(copy_dir: &Path) -> std::path::PathBuf {
    swap_sibling_for(copy_dir, ".socket-stage")
}

/// The backup sibling the old copy is parked at mid-swap:
/// `<uuid>/<vendor>/<name>@<version>.socket-old`.
fn backup_dir_for(copy_dir: &Path) -> std::path::PathBuf {
    swap_sibling_for(copy_dir, ".socket-old")
}

/// Swap a fully-built stage into place without a destructive window: park the
/// old copy (if any) at `<copy>.socket-old` with a same-dir rename, rename the
/// stage over the now-vacant copy path, and only then delete the backup.
/// Every step is a single atomic rename — no step can leave less recoverable
/// state than it started with (see the cargo twin for the full rationale).
async fn swap_stage_into_place(stage: &Path, copy_dir: &Path) -> std::io::Result<()> {
    let backup = backup_dir_for(copy_dir);
    // A stale backup (crash mid-swap on an earlier run) would make the
    // park rename fail; `remove_tree` is a no-op when it is absent.
    remove_tree(&backup).await?;
    let had_old = match tokio::fs::rename(copy_dir, &backup).await {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e),
    };
    match tokio::fs::rename(stage, copy_dir).await {
        Ok(()) => {
            if had_old {
                let _ = remove_tree(&backup).await;
            }
            Ok(())
        }
        Err(e) => {
            if had_old {
                let _ = tokio::fs::rename(&backup, copy_dir).await;
            }
            Err(e)
        }
    }
}

/// Best-effort removal of the EMPTY dir levels a failed run may have created
/// above the copy — `<uuid>/<vendor>/`, `<uuid>/`, `.socket/vendor/composer/`
/// and `.socket/vendor/` — so a hard failure leaves no husk for sweep to
/// enumerate as a vendored unit (or for the user to commit). `remove_dir`
/// refuses non-empty dirs, so live copies, markers, and other patches' vendor
/// dirs always survive. `copy_dir` may be the copy or its stage sibling
/// (same parent); pruning starts at its parent.
async fn prune_empty_vendor_dirs(copy_dir: &Path) {
    let mut level = copy_dir.parent();
    for _ in 0..4 {
        let Some(dir) = level else { return };
        match tokio::fs::remove_dir(dir).await {
            Ok(()) => {}
            // Already unwound wholesale (`remove_tree(uuid_dir)`): keep
            // pruning the parent levels this run created.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Non-empty (a live copy or marker) or otherwise busy: stop.
            Err(_) => return,
        }
        level = dir.parent();
    }
}

/// Failure cleanup for a staged (re)build: always remove the stage, then
/// either unwind the whole `<uuid>/` dir (`unwind_uuid_dir` — a fresh vendor
/// with no pre-existing state worth keeping) or leave existing state (a
/// live-wired copy and its marker) untouched; either way prune any
/// empty-husk dirs left behind.
async fn cleanup_failed_stage(stage: &Path, uuid_dir: &Path, unwind_uuid_dir: bool) {
    let _ = remove_tree(stage).await;
    if unwind_uuid_dir {
        let _ = remove_tree(uuid_dir).await;
    }
    prune_empty_vendor_dirs(stage).await;
}

/// Copy the installed package into a STAGE sibling of `copy_dir`, run the
/// hardened apply pipeline against it (vendor auto-force policy — see
/// [`super::force_apply_staged`]), and swap the stage into `copy_dir` only on
/// success. A failed (re)build therefore never destroys a pre-existing copy:
/// with `unwind_uuid_dir` (a fresh vendor — nothing pre-existing to keep) the
/// whole uuid dir is removed, without it (a live-wired rebuild, where
/// composer.lock keeps pointing at the copy) the previous copy and marker are
/// left exactly as they were; either way no partial copy or empty `<uuid>/`
/// husk — which verify/sweep would misjudge — survives, and the failed
/// [`ApplyResult`] is the `Err` for the caller to bubble (composer.lock is
/// only ever edited after this succeeds).
#[allow(clippy::too_many_arguments)]
async fn copy_and_patch(
    purl: &str,
    installed_dir: &Path,
    copy_dir: &Path,
    uuid_dir: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    unwind_uuid_dir: bool,
    pkg: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<ApplyResult, ApplyResult> {
    let stage = stage_dir_for(copy_dir);
    // `fresh_copy` removes + recreates the stage itself.
    if let Err(e) = fresh_copy(installed_dir, &stage, None).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(synthesized_result(
            purl,
            copy_dir,
            Vec::new(),
            false,
            Some(format!("failed to copy installed package: {e}")),
        ));
    }
    let mut result = super::force_apply_staged(
        purl, &stage, record, sources, false, force, pkg, version, warnings,
    )
    .await;
    result.package_path = copy_dir.display().to_string();
    if !result.success {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(result);
    }
    if let Err(e) = swap_stage_into_place(&stage, copy_dir).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to move the rebuilt copy into place: {e}"));
        return Err(result);
    }
    Ok(result)
}

/// Outcome of attempting to materialise the composer copy from the patch service.
enum ComposerServiceCopy {
    /// The prebuilt dist zip was extracted into `copy_dir`.
    Used,
    /// Bubble this terminal outcome (boxed — `VendorOutcome` is large).
    HardFail(Box<VendorOutcome>),
    /// Fall back to copying + patching the installed package.
    FallBack,
}

/// Download the prebuilt dist zip, integrity-verify it, and extract it into
/// `copy_dir` (dropping the zip's variable top-level dir). Maps each service
/// outcome onto the `auto` / `service` fallback policy. The extracted zip IS
/// the patched package, so it needs no installed copy.
async fn composer_service_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    pkg: &str,
    copy_dir: &Path,
    uuid_dir: &Path,
    warnings: &mut Vec<VendorWarning>,
) -> ComposerServiceCopy {
    let Some(cfg) = service else {
        return ComposerServiceCopy::FallBack;
    };
    if !cfg.service_enabled() {
        return ComposerServiceCopy::FallBack;
    }
    fn hard(code: &'static str, detail: String) -> ComposerServiceCopy {
        ComposerServiceCopy::HardFail(Box::new(refused(code, detail)))
    }
    let miss = |warnings: &mut Vec<VendorWarning>, code: &'static str, reason: String| {
        if cfg.source.requires_service() {
            hard("vendor_prebuilt_required", reason)
        } else {
            warnings.push(VendorWarning::new(
                code,
                format!("{reason}; building locally instead"),
            ));
            ComposerServiceCopy::FallBack
        }
    };
    match fetch_verified_archive(cfg, &record.uuid).await {
        ServiceArtifact::Ready(archive) => {
            // Extract into a STAGE sibling and swap it into the copy dir only
            // once fully verified — a failure then leaves any pre-existing
            // (possibly live-wired) copy and its marker untouched and no husk
            // behind.
            let stage = stage_dir_for(copy_dir);
            let _ = remove_tree(&stage).await;
            if let Err(e) = tokio::fs::create_dir_all(&stage).await {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot create {}: {e}", stage.display()),
                );
            }
            // composer dist zips carry a single variable top-level dir.
            if let Err(e) = extract_zip(&archive.bytes, &stage, /*strip_first=*/ true) {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return hard(
                    "vendor_prebuilt_extract_failed",
                    format!("cannot extract the prebuilt dist zip: {e}"),
                );
            }
            // Verify the EXTRACTED TREE, not just the archive bytes. The
            // archive-bytes SRI (checked in fetch_verified_archive) proves
            // the download is intact, but says nothing about whether the
            // internal layout lands the patched files at the paths the
            // record names: a zip with an unexpected wrapper dir (the
            // single-level `strip_first` leaves an extra `pkg-<sha>/`
            // segment) or a root-level `src/…` (over-stripped) extracts
            // "successfully" with every file at the WRONG path. Without
            // this check the caller synthesized success purely from
            // `record.files` and shipped a copy missing its patched files
            // (exit 0, empty copy_dir on disk). Fail closed here and let
            // the `auto` source fall back to the local build.
            if !copy_matches_after_hashes(&stage, &record.files).await {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return miss(
                    warnings,
                    "vendor_prebuilt_layout_mismatch",
                    format!(
                        "prebuilt dist zip for {pkg} extracted to an \
                         unexpected layout (patched files absent at their \
                         recorded paths)"
                    ),
                );
            }
            if let Err(e) = swap_stage_into_place(&stage, copy_dir).await {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot move the extracted dist into place: {e}"),
                );
            }
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {pkg} from the patch service ({})",
                    archive.source_url
                ),
            ));
            ComposerServiceCopy::Used
        }
        ServiceArtifact::IntegrityMismatch(reason) => miss(
            warnings,
            "vendor_prebuilt_integrity_mismatch",
            format!("prebuilt dist zip failed integrity ({reason})"),
        ),
        ServiceArtifact::Pending => miss(
            warnings,
            "vendor_prebuilt_pending",
            "prebuilt dist zip is still building".to_string(),
        ),
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard(
                    "vendor_prebuilt_required",
                    format!("prebuilt dist zip unavailable: {reason}"),
                )
            } else {
                ComposerServiceCopy::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => miss(
            warnings,
            "vendor_prebuilt_unavailable",
            format!("patch service request failed ({reason})"),
        ),
    }
}

/// Locate the package's entry: `packages[]` first, then `packages-dev[]`.
/// Names are compared case-insensitively, versions through the `v`-prefix
/// normalization (see module doc).
fn find_lock_entry(lock: &Value, pkg_lc: &str, version: &str) -> Option<(&'static str, usize)> {
    for section in ["packages", "packages-dev"] {
        let Some(arr) = lock.get(section).and_then(Value::as_array) else {
            continue;
        };
        for (i, e) in arr.iter().enumerate() {
            let Some(name) = e.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !name.eq_ignore_ascii_case(pkg_lc) {
                continue;
            }
            let Some(v) = e.get("version").and_then(Value::as_str) else {
                continue;
            };
            if normalize_version(v) == normalize_version(version) {
                return Some((section, i));
            }
        }
    }
    None
}

/// True when the live entry already carries our path dist.
fn entry_is_wired(entry: &Value, dist_url: &str) -> bool {
    let dist = entry.get("dist");
    dist.and_then(|d| d.get("type")).and_then(Value::as_str) == Some("path")
        && dist.and_then(|d| d.get("url")).and_then(Value::as_str) == Some(dist_url)
}

/// Rebuild the lock entry for the path dist (see module doc): every original
/// key is preserved in order, `source` is dropped, `dist` is replaced in its
/// original slot with `transport-options` inserted right after it. A
/// pre-existing `transport-options` is superseded by ours (never duplicated).
/// A source-only entry without `dist` gets both appended at the end.
fn rewrite_lock_entry(
    original: &Map<String, Value>,
    dist_url: &str,
    patch_uuid: &str,
) -> Map<String, Value> {
    // `reference` carries the patch uuid: composer preserves it verbatim into
    // vendor/composer/installed.json (spike-proven for arbitrary strings), so
    // SBOM/audit tooling can recover the patch from deployed artifacts even
    // when `.socket/` is stripped from the image. The uuid was already
    // canonical-validated by vendor_uuid_dir_rel before reaching here.
    let dist = json!({ "type": "path", "url": dist_url, "reference": patch_uuid });
    let transport = json!({ "symlink": false });
    let mut out = Map::new();
    let mut replaced_dist = false;
    for (k, v) in original {
        match k.as_str() {
            "source" => {}
            "transport-options" => {}
            "dist" => {
                out.insert("dist".to_string(), dist.clone());
                out.insert("transport-options".to_string(), transport.clone());
                replaced_dist = true;
            }
            _ => {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    if !replaced_dist {
        out.insert("dist".to_string(), dist);
        out.insert("transport-options".to_string(), transport);
    }
    out
}

/// Serialize the lock the way composer writes it: 4-space indent
/// (`JSON_PRETTY_PRINT`) + trailing newline. serde_json never escapes `/`,
/// matching `JSON_UNESCAPED_SLASHES`.
fn composer_json_bytes(value: &Value) -> std::io::Result<Vec<u8>> {
    serialize_json(value, "    ")
}

/// The `<section>:<lowercase pkg>` keys this entry can actually put back:
/// a recognized wiring kind, a well-formed key, and a recorded `original`.
fn restorable_keys(entry: &VendorEntry) -> HashSet<String> {
    entry
        .wiring
        .iter()
        .filter(|w| w.kind == WIRING_KIND && w.original.is_some())
        .filter_map(|w| w.key.as_deref())
        .filter_map(|k| k.split_once(':'))
        .filter(|(section, _)| *section == "packages" || *section == "packages-dev")
        .map(|(section, pkg)| format!("{section}:{}", pkg.to_lowercase()))
        .collect()
}

/// Lock packages still wired to `uuid` that `restorable` cannot un-rewrite —
/// the set that a delete-the-artifacts revert would strand. Names are
/// returned lowercase and deduped (composer package names are canonically
/// lowercase; the lock's own casing is display-only).
///
/// A missing or unparseable composer.lock yields none: no install can be
/// consuming a lock nothing can read, and the restore loop already degrades
/// to `vendor_lock_entry_drifted` for it.
async fn stranded_wired_packages(
    lock_path: &Path,
    uuid: &str,
    restorable: &HashSet<String>,
) -> Vec<String> {
    let Ok(text) = read_regular_to_string(lock_path).await else {
        return Vec::new();
    };
    let Ok(lock) = serde_json::from_str::<Value>(&text) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for section in ["packages", "packages-dev"] {
        let Some(arr) = lock.get(section).and_then(Value::as_array) else {
            continue;
        };
        for e in arr {
            let wired_to_us = e
                .get("dist")
                .and_then(|d| d.get("url"))
                .and_then(Value::as_str)
                .and_then(parse_vendor_path)
                .is_some_and(|p| p.eco == "composer" && p.uuid == uuid);
            if !wired_to_us {
                continue;
            }
            let Some(name) = e.get("name").and_then(Value::as_str) else {
                continue;
            };
            let name = name.to_lowercase();
            // Section-qualified: `restore_lock_entry` only searches the
            // section the wiring recorded, so an entry that moved between
            // packages[] and packages-dev[] is unrestorable too.
            if !restorable.contains(&format!("{section}:{name}")) && !out.contains(&name) {
                out.push(name);
            }
        }
    }
    out
}

/// Restore one `composer_lock_package` wiring record. `Ok(true)` = restored
/// (or would be, on dry run); `Ok(false)` = drifted, left alone; `Err` = a
/// real I/O / serialization failure.
async fn restore_lock_entry(
    lock_path: &Path,
    w: &WiringRecord,
    uuid: &str,
    dry_run: bool,
) -> Result<bool, String> {
    let Some(key) = w.key.as_deref() else {
        return Ok(false);
    };
    let Some((section, pkg)) = key.split_once(':') else {
        return Ok(false);
    };
    if section != "packages" && section != "packages-dev" {
        return Ok(false);
    }
    let Some(original) = w.original.clone() else {
        return Ok(false);
    };

    let lock_text = match read_regular_to_string(lock_path).await {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("unreadable composer.lock: {e}")),
    };
    let mut lock: Value =
        serde_json::from_str(&lock_text).map_err(|e| format!("unparseable composer.lock: {e}"))?;

    let Some(arr) = lock.get(section).and_then(Value::as_array) else {
        return Ok(false);
    };
    let Some(idx) = arr.iter().position(|e| {
        e.get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| n.eq_ignore_ascii_case(pkg))
    }) else {
        return Ok(false);
    };

    // Ownership gate: only restore when the live dist still points into OUR
    // uuid dir. A registry dist (composer update reverted it) or a different
    // uuid (a newer vendor run owns the entry) is third-party state — never
    // clobber it.
    let live = &lock[section][idx];
    let wired_to_us = live
        .get("dist")
        .and_then(|d| d.get("url"))
        .and_then(Value::as_str)
        .and_then(parse_vendor_path)
        .is_some_and(|p| p.eco == "composer" && p.uuid == uuid);
    if !wired_to_us {
        return Ok(false);
    }

    if !dry_run {
        lock[section][idx] = original;
        let bytes = composer_json_bytes(&lock).map_err(|e| e.to_string())?;
        atomic_write_bytes_preserving_mode(lock_path, &bytes)
            .await
            .map_err(|e| format!("failed to write composer.lock: {e}"))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::apply::{ApplyResult, VerifyStatus};
    use crate::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const PURL: &str = "pkg:composer/psr/log@3.0.2";
    const PRISTINE: &[u8] = b"<?php\ninterface LoggerInterface {}\n";
    const PATCHED: &[u8] = b"<?php\n// SOCKET-PATCH-MARKER\ninterface LoggerInterface {}\n";

    fn copy_rel() -> String {
        format!(".socket/vendor/composer/{UUID}/psr/log@3.0.2")
    }

    fn psr_log_entry(name: &str, version: &str) -> Value {
        json!({
            "name": name,
            "version": version,
            "source": {
                "type": "git",
                "url": "https://github.com/php-fig/log.git",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/php-fig/log/zipball/f16e1d5",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "shasum": ""
            },
            "require": { "php": ">=8.0.0" },
            "type": "library"
        })
    }

    fn lock_value(name: &str, version: &str, in_dev: bool) -> Value {
        let dev_entry = json!({
            "name": "phpunit/phpunit",
            "version": "10.0.0",
            "source": {"type": "git", "url": "https://github.com/s/phpunit.git", "reference": "aaa"},
            "dist": {"type": "zip", "url": "https://api.github.com/repos/s/phpunit/zipball/aaa", "reference": "aaa", "shasum": ""},
            "type": "library"
        });
        let (packages, packages_dev) = if in_dev {
            (json!([dev_entry]), json!([psr_log_entry(name, version)]))
        } else {
            (json!([psr_log_entry(name, version)]), json!([dev_entry]))
        };
        json!({
            "_readme": ["This file locks the dependencies of your project to a known state"],
            "content-hash": "7a59d114f58e9b02546b21d7e57430d3",
            "packages": packages,
            "packages-dev": packages_dev,
            "minimum-stability": "stable",
            "plugin-api-version": "2.6.0"
        })
    }

    /// Fixture project: composer.lock (composer-shaped, written with the same
    /// 4-space emitter composer uses), an installed `vendor/psr/log`, and a
    /// blobs dir carrying the patched bytes.
    async fn fixture(lock: &Value) -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        tokio::fs::write(root.join(COMPOSER_LOCK), composer_json_bytes(lock).unwrap())
            .await
            .unwrap();

        let installed = root.join("vendor/psr/log");
        tokio::fs::create_dir_all(installed.join("src"))
            .await
            .unwrap();
        tokio::fs::write(
            installed.join("composer.json"),
            b"{\"name\": \"psr/log\"}\n",
        )
        .await
        .unwrap();
        tokio::fs::write(installed.join("src/LoggerInterface.php"), PRISTINE)
            .await
            .unwrap();

        let before = compute_git_sha256_from_bytes(PRISTINE);
        let after = compute_git_sha256_from_bytes(PATCHED);
        let blobs = root.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "src/LoggerInterface.php".to_string(),
            PatchFileInfo {
                before_hash: before,
                after_hash: after,
            },
        );
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-xxxx-yyyy-zzzz".to_string(),
            crate::manifest::schema::VulnerabilityInfo {
                cves: Vec::new(),
                summary: String::new(),
                severity: String::new(),
                description: String::new(),
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: "2026-06-09T00:00:00Z".to_string(),
            files,
            vulnerabilities,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        (dir, blobs, installed, record)
    }

    fn unwrap_done(o: VendorOutcome) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match o {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => panic!("refused: {code}: {detail}"),
        }
    }

    fn unwrap_refused(o: VendorOutcome) -> (&'static str, String) {
        match o {
            VendorOutcome::Refused { code, detail } => (code, detail),
            VendorOutcome::Done { result, .. } => panic!("not refused: {result:?}"),
        }
    }

    async fn run_vendor(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        purl: &str,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        vendor_composer(
            purl,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            dry_run,
            false,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn test_happy_path_rewrites_lock() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);

        // Copy patched at the uuid path; installed dir untouched.
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
        assert_eq!(
            tokio::fs::read(installed.join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PRISTINE
        );

        // Marker present in the uuid dir.
        let marker = tokio::fs::read_to_string(root.join(format!(
            ".socket/vendor/composer/{UUID}/{VENDOR_MARKER_FILE}"
        )))
        .await
        .unwrap();
        assert!(marker.contains(UUID));
        assert!(marker.contains("GHSA-xxxx-yyyy-zzzz"));

        // Lock surgery: source gone, dist replaced in slot, transport-options
        // right after, all other keys in their original order.
        let text = tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
            .await
            .unwrap();
        let new_lock: Value = serde_json::from_str(&text).unwrap();
        let e = &new_lock["packages"][0];
        let keys: Vec<&str> = e.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "name",
                "version",
                "dist",
                "transport-options",
                "require",
                "type"
            ],
            "dist replaced in its original slot, source dropped, transport-options after dist"
        );
        assert_eq!(e["dist"]["type"], "path");
        assert_eq!(e["dist"]["url"], copy_rel());
        assert_eq!(
            e["dist"]["reference"], UUID,
            "reference carries the patch uuid for in-tree traceability"
        );
        assert_eq!(e["transport-options"]["symlink"], json!(false));
        // content-hash untouched (it covers composer.json only).
        assert_eq!(new_lock["content-hash"], "7a59d114f58e9b02546b21d7e57430d3");
        // 4-space indent + trailing newline + unescaped slashes.
        assert!(text.starts_with("{\n    \""), "4-space indent: {text}");
        assert!(text.ends_with('\n'));
        assert!(
            text.contains(&format!("\"url\": \"{}\"", copy_rel())),
            "slashes must not be escaped"
        );

        // Ledger entry: verbatim original, our rewrite, the artifact path.
        let entry = entry.expect("success must carry a ledger entry");
        assert_eq!(entry.ecosystem, "composer");
        assert_eq!(entry.base_purl, PURL);
        assert_eq!(entry.uuid, UUID);
        assert_eq!(entry.artifact.path, copy_rel());
        assert_eq!(entry.artifact.sha256, "");
        assert_eq!(entry.wiring.len(), 1);
        let w = &entry.wiring[0];
        assert_eq!(w.file, COMPOSER_LOCK);
        assert_eq!(w.kind, WIRING_KIND);
        assert_eq!(w.action, WiringAction::Rewritten);
        assert_eq!(w.key.as_deref(), Some("packages:psr/log"));
        assert_eq!(w.original.as_ref().unwrap(), &lock["packages"][0]);
        assert_eq!(w.new.as_ref().unwrap(), e);
    }

    #[tokio::test]
    async fn test_matches_packages_dev_entry() {
        let lock = lock_value("psr/log", "3.0.2", true);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(entry.wiring[0].key.as_deref(), Some("packages-dev:psr/log"));

        let new_lock: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(new_lock["packages-dev"][0]["dist"]["type"], "path");
        // The packages[] sibling (phpunit) is untouched.
        assert_eq!(new_lock["packages"][0]["dist"]["type"], "zip");
    }

    #[tokio::test]
    async fn test_matches_v_prefixed_lock_version() {
        // Lock carries the pretty `v3.0.2`; the PURL is bare `3.0.2`. The
        // entry must match, and its own version string must NOT be rewritten.
        let lock = lock_value("psr/log", "v3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, _e, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_lock: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(new_lock["packages"][0]["version"], "v3.0.2");
        assert_eq!(new_lock["packages"][0]["dist"]["type"], "path");
    }

    #[tokio::test]
    async fn test_case_insensitive_name_lowercase_dist_url() {
        // Hand-written mixed-case lock name: matched case-insensitively, the
        // lock's pretty casing preserved, the dist URL lowercase canonical.
        let lock = lock_value("Psr/Log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, _e, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_lock: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            new_lock["packages"][0]["name"], "Psr/Log",
            "pretty casing kept"
        );
        assert_eq!(
            new_lock["packages"][0]["dist"]["url"],
            copy_rel(),
            "dist url lowercase"
        );
        assert!(
            dir.path().join(copy_rel()).exists(),
            "copy at the lowercase path"
        );
    }

    #[tokio::test]
    async fn test_refuses_missing_lock() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        tokio::fs::remove_file(root.join(COMPOSER_LOCK))
            .await
            .unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    #[tokio::test]
    async fn test_refuses_entry_not_found() {
        let lock = lock_value("monolog/monolog", "2.9.1", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (code, _d) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert_eq!(code, "vendor_lock_entry_not_found");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched"
        );
        assert!(!root.join(".socket").exists());
    }

    /// SECURITY: traversal coordinates (a tampered manifest) must be refused
    /// before any disk access — no copy outside `.socket/vendor/composer/`,
    /// no lock edit.
    #[tokio::test]
    async fn test_refuses_unsafe_coordinates() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        // (a) non-canonical uuid
        let mut bad_uuid = record.clone();
        bad_uuid.uuid = "../../escape".to_string();
        let (code, _d) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &bad_uuid, PURL, false).await);
        assert_eq!(code, "unsafe_coordinates");

        // (b) traversal in the package name
        let (code, _d) = unwrap_refused(
            run_vendor(
                root,
                &blobs,
                &installed,
                &record,
                "pkg:composer/../evil@1.0.0",
                false,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");

        assert!(!root.join(".socket").exists(), "nothing written");
        assert!(!root.parent().unwrap().join("escape").exists());
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn test_idempotent_rerun_in_sync() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let lock_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        let copy_bytes = tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
            .await
            .unwrap();

        let (r2, e2, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r2.success);
        assert!(r2.files_patched.is_empty(), "in-sync rerun patches nothing");
        assert!(
            r2.files_verified
                .iter()
                .all(|v| v.status == VerifyStatus::AlreadyPatched),
            "synthesized AlreadyPatched: {:?}",
            r2.files_verified
        );
        assert!(
            e2.is_none(),
            "hot path must not re-record (would clobber the original in the ledger)"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            lock_bytes
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            copy_bytes
        );
    }

    /// Wired lock + deleted/corrupt copy: the artifact is rebuilt in place,
    /// the lock stays byte-identical, no ledger entry is re-recorded.
    #[tokio::test]
    async fn test_wired_missing_copy_rebuilds_artifact_only() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success);
        assert!(e1.is_some());
        let lock_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        let patched = root.join(copy_rel()).join("src/LoggerInterface.php");
        let patched_bytes = tokio::fs::read(&patched).await.unwrap();

        // Simulate the fresh-clone hole: the committed copy is gone.
        crate::patch::copy_tree::remove_tree(&root.join(copy_rel()))
            .await
            .unwrap();

        let (r2, e2, w2) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(
            e2.is_none(),
            "artifact-only rebuild must not re-record (the live vendored \
             fragment would clobber the pre-vendor original)"
        );
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {w2:?}"
        );
        assert_eq!(
            tokio::fs::read(&patched).await.unwrap(),
            patched_bytes,
            "rebuilt copy carries the patched bytes"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            lock_bytes,
            "composer.lock untouched by the rebuild"
        );
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run records nothing");
        assert!(!root.join(".socket").exists(), "no copy created");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before
        );
    }

    #[tokio::test]
    async fn test_partial_failure_removes_copy_lock_untouched() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, _blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        // Empty blobs dir → the patch bytes cannot be sourced → apply fails.
        let empty = root.join("empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &empty, &installed, &record, PURL, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            !root
                .join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "half-built copy must be removed"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched on failure (wiring runs last)"
        );
    }

    /// A failed FRESH copy must leave no `.socket/vendor` husk: `fresh_copy`
    /// creates the full `<uuid>/<vendor>/<name>@<version>` destination chain
    /// BEFORE walking the source, so a copy failure (unreadable installed
    /// package, ENOSPC mid-copy) would otherwise strand an empty uuid dir
    /// that sweep enumerates as a vendored unit with no ledger entry — a
    /// phantom orphan the user commits. Same contract as the cargo twin's
    /// `cleanup_failed_stage`.
    #[tokio::test]
    async fn test_failed_fresh_copy_leaves_no_vendor_husk() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, _installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        // A missing installed dir makes the copy's source walk fail after
        // the destination chain was created (unit-level stand-in for the
        // mid-copy ENOSPC / EACCES / concurrent-delete failures).
        let missing = root.join("missing");
        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &missing, &record, PURL, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            !root.join(".socket/vendor").exists(),
            "a failed copy must not strand a uuid-dir husk under .socket/vendor"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched on failure"
        );
    }

    /// Wired lock + drifted copy + a FAILING local rebuild: the
    /// rebuild-artifact-only path keeps composer.lock untouched by design, so
    /// a failure must NOT delete the uuid dir the lock still points at — that
    /// strands the project (`composer install` dies with "Source path … is
    /// not found", precisely the state revert refuses to create). Like the
    /// cargo twin, the rebuild is staged: the previous
    /// (drifted-but-installable) copy and the marker survive exactly as they
    /// were.
    #[tokio::test]
    async fn test_failed_rebuild_keeps_wired_artifact() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let lock_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        // Drift the committed copy so the rerun takes the rebuild path…
        let drifted = root.join(copy_rel()).join("src/LoggerInterface.php");
        tokio::fs::write(&drifted, b"<?php // drifted\n").await.unwrap();
        // …and make the rebuild fail: the patch bytes cannot be sourced.
        let empty = root.join("empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();

        let (r2, e2, _w2) =
            unwrap_done(run_vendor(root, &empty, &installed, &record, PURL, false).await);
        assert!(!r2.success, "the failed rebuild must be reported");
        assert!(e2.is_none());
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            lock_bytes,
            "the rebuild path never touches the lock"
        );
        assert_eq!(
            tokio::fs::read(&drifted).await.unwrap(),
            b"<?php // drifted\n".to_vec(),
            "a failed rebuild must leave the previous live-wired copy as it was"
        );
        assert!(
            root.join(format!(
                ".socket/vendor/composer/{UUID}/{VENDOR_MARKER_FILE}"
            ))
            .exists(),
            "a failed rebuild must not delete the marker while the lock is wired"
        );
    }

    #[tokio::test]
    async fn test_revert_round_trip_byte_identical() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let fixture_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        assert_ne!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            fixture_bytes,
            "vendor must have rewired the lock"
        );

        let outcome = revert_composer(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "clean revert must not report drift: {:?}",
            outcome.warnings
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_installed_copy_stale"),
            "revert advises about the stale installed copy"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            fixture_bytes,
            "lock restored byte-identically"
        );
        assert!(
            !root
                .join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "uuid dir removed"
        );
    }

    #[tokio::test]
    async fn test_revert_drift_warning() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // Third-party drift: `composer update` rewired the entry back to a
        // registry zip dist. Revert must leave it alone and warn.
        let drifted = lock_value("psr/log", "3.0.2", false);
        tokio::fs::write(
            root.join(COMPOSER_LOCK),
            composer_json_bytes(&drifted).unwrap(),
        )
        .await
        .unwrap();
        let drifted_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let outcome = revert_composer(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "drift must be reported: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            drifted_bytes,
            "drifted lock left alone"
        );
        assert!(
            !root
                .join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "uuid dir still removed"
        );
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted as `composer.lock` must fail fast instead of wedging
    /// every lock reader — vendor's presence read, revert's stranded scan and
    /// restore read — forever in an `open(2)` that waits for a writer that
    /// never comes. Same `open_regular_file` guard class as the Cargo.lock /
    /// .cargo/config.toml twins. Vendor refuses loudly; revert fails without
    /// deleting the artifacts (ownership can't be determined).
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_fails_fast_instead_of_wedging() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        // A real vendor run first so revert has a live ledger entry.
        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success, "{:?}", r1.error);
        let entry = e1.unwrap();

        let lock_path = root.join(COMPOSER_LOCK);
        tokio::fs::remove_file(&lock_path).await.unwrap();
        mkfifo(&lock_path);

        // On timeout the open is wedged in a `spawn_blocking` thread that the
        // runtime waits for on shutdown; connect a writer to release it so
        // the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let all = async {
            (
                run_vendor(root, &blobs, &installed, &record, PURL, false).await,
                revert_composer(&entry, root, false).await,
            )
        };
        let Ok((vendor_outcome, revert_outcome)) = tokio::time::timeout(deadline, all).await else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&lock_path);
            panic!("composer.lock reads must fail fast on a FIFO");
        };
        let (code, detail) = unwrap_refused(vendor_outcome);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(
            detail.contains("unreadable"),
            "a squatted lock is unreadable, not missing: {detail}"
        );
        assert!(
            !revert_outcome.success,
            "revert must fail when lock ownership can't be read: {revert_outcome:?}"
        );
        assert!(
            root.join(format!(".socket/vendor/composer/{UUID}"))
                .exists(),
            "failed revert must not delete the artifacts"
        );
    }

    // ─────────────── service-download path (Tier B: composer) ───────────────

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::vendor::{VendorServiceConfig, VendorSource};

    fn sri_sha512(bytes: &[u8]) -> String {
        use base64::Engine as _;
        use sha2::{Digest as _, Sha512};
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
        )
    }

    fn composer_service_cfg(uri: &str, source: VendorSource, offline: bool) -> VendorServiceConfig {
        VendorServiceConfig {
            source,
            client: Some(ApiClient::new(ApiClientOptions {
                api_url: uri.to_string(),
                api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                use_public_proxy: false,
                org_slug: Some("acme".into()),
            })),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline,
        }
    }

    /// Build a composer dist zip with a single variable top-level dir.
    fn make_dist_zip(top: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default();
            for (rel, content) in files {
                zw.start_file(format!("{top}/{rel}"), opts).unwrap();
                zw.write_all(content).unwrap();
            }
            zw.finish().unwrap();
        }
        cursor.into_inner()
    }

    async fn mount_composer_granted(server: &wiremock::MockServer, sha512: &str, zip_bytes: &[u8]) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let serve_path = format!("/patch/composer/psr/log/3.0.2/tok/{UUID}/psr-log-3.0.2.zip");
        let serve_url = format!("{}{serve_path}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "purl": PURL,
                    "artifacts": [{ "kind": "tarball", "url": serve_url,
                                    "integrity": { "sha512": sha512 } }]
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(serve_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes.to_vec()))
            .mount(server)
            .await;
    }

    async fn mount_composer_status(server: &wiremock::MockServer, status: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": { UUID: { "status": status, "url": null, "artifacts": [] } }
            })))
            .mount(server)
            .await;
    }

    async fn vendor_with_service(
        root: &Path,
        blobs: &Path,
        installed: &Path,
        record: &PatchRecord,
        cfg: &VendorServiceConfig,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        vendor_composer(
            PURL,
            installed,
            root,
            record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(cfg),
        )
        .await
    }

    /// Service success: the prebuilt dist zip is extracted into the copy dir
    /// (patched bytes), the lock is rewired, and a `vendor_prebuilt_downloaded`
    /// advisory is emitted — WITHOUT touching the installed package.
    #[tokio::test]
    async fn service_success_extracts_dist_and_rewrites_lock() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, _installed, record) = fixture(&lock).await;
        let root = dir.path();
        let zip = make_dist_zip(
            "php-fig-log-f16e1d5",
            &[
                ("src/LoggerInterface.php", PATCHED),
                ("composer.json", b"{\"name\": \"psr/log\"}\n"),
            ],
        );
        let sri = sri_sha512(&zip);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &zip).await;

        let bogus_installed = root.join("no-such-install");
        let (result, entry, warnings) = unwrap_done(
            vendor_with_service(
                root,
                &blobs,
                &bogus_installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
        let lock_text = tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
            .await
            .unwrap();
        assert!(
            lock_text.contains(&copy_rel()),
            "lock rewired to the copy: {lock_text}"
        );
        assert!(warnings
            .iter()
            .any(|w| w.code == "vendor_prebuilt_downloaded"));
    }

    /// Wrong internal layout (double wrapper → the single-level strip
    /// misplaces the patched file) must NOT be reported as success from
    /// `record.files` alone. Under `service` mode it hard-fails
    /// `vendor_prebuilt_layout_mismatch`; the file is not at the expected
    /// path. Regression for the exit-0-empty-copy incident (run 29040958337).
    #[tokio::test]
    async fn service_wrong_layout_service_mode_hard_fails() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        // A double wrapper: single strip_first leaves `extra/src/...`, so the
        // patched file never lands at `copy_dir/src/LoggerInterface.php`.
        let zip = make_dist_zip(
            "outer-wrapper",
            &[("extra/src/LoggerInterface.php", PATCHED)],
        );
        let sri = sri_sha512(&zip);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &zip).await;

        let outcome = vendor_with_service(
            root,
            &blobs,
            &installed,
            &record,
            &composer_service_cfg(&server.uri(), VendorSource::Service, false),
        )
        .await;
        // Service mode has no fallback, so `miss()` surfaces the uniform
        // `vendor_prebuilt_required` code (same as an integrity mismatch);
        // the layout diagnosis rides in the detail. The point of the
        // regression is that it REFUSES rather than synthesizing success —
        // and the copy dir does not hold the file at its recorded path.
        match outcome {
            VendorOutcome::Refused { code, detail } => {
                assert_eq!(code, "vendor_prebuilt_required");
                assert!(
                    detail.contains("unexpected layout"),
                    "the refusal must diagnose the layout mismatch: {detail}"
                );
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(
            tokio::fs::metadata(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .is_err(),
            "the misplaced service copy must not be left at the recorded path"
        );
    }

    /// Same wrong-layout archive under `auto`: the guard trips and the local
    /// build takes over, producing a correct copy — success WITHOUT the bad
    /// service bytes.
    #[tokio::test]
    async fn service_wrong_layout_auto_falls_back_to_build() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let zip = make_dist_zip(
            "outer-wrapper",
            &[("extra/src/LoggerInterface.php", PATCHED)],
        );
        let sri = sri_sha512(&zip);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &zip).await;

        let (result, entry, warnings) = unwrap_done(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Auto, false),
            )
            .await,
        );
        assert!(
            result.success,
            "auto must fall back to the local build when the service layout \
             is wrong: {:?}",
            result.error
        );
        assert!(entry.is_some());
        // The copy holds the patched bytes at the RIGHT path (from the local
        // build, not the misplaced service extract).
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_layout_mismatch"),
            "the fallback must record why the service copy was rejected: {warnings:?}"
        );
    }

    /// `service` mode + integrity mismatch hard-fails, nothing extracted.
    #[tokio::test]
    async fn service_integrity_mismatch_service_mode_hard_fails() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let zip = make_dist_zip("x", &[("src/LoggerInterface.php", PATCHED)]);
        let wrong = sri_sha512(b"different bytes");
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &wrong, &zip).await;

        let (code, _) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!root
            .join(format!(".socket/vendor/composer/{UUID}"))
            .exists());
    }

    /// `auto` + a not-built service status falls back to the local build.
    #[tokio::test]
    async fn service_unavailable_auto_falls_back_to_build() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_composer_status(&server, "not_found").await;

        let (result, entry, _) = unwrap_done(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Auto, false),
            )
            .await,
        );
        assert!(
            result.success,
            "auto must fall back to the local build: {:?}",
            result.error
        );
        assert!(entry.is_some());
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
    }

    /// The vendor rewrite and the revert restore swap `composer.lock`'s inode;
    /// both must keep the user's permission bits (a 0640 lock silently
    /// becoming umask-default 0644 leaks group/other access the user removed).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_lock_write_preserves_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let lock_path = root.join(COMPOSER_LOCK);
        tokio::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o640))
            .await
            .unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        let mode = tokio::fs::metadata(&lock_path)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "vendor rewrite must keep composer.lock's mode");

        let outcome = revert_composer(&entry.unwrap(), root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let mode = tokio::fs::metadata(&lock_path)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o640, "revert restore must keep composer.lock's mode");
    }

    /// Re-vendor under a NEW patch uuid (a patch update taking over the
    /// entry): the wiring must record `original: None` — never the previous
    /// run's own stale path dist. The persist layer carries the true
    /// pre-vendor original forward from the entry being replaced and sweeps
    /// the old uuid dir, so a recorded stale dist would make a later
    /// `--revert` restore a dangling `.socket/vendor/composer/` pointer.
    #[tokio::test]
    async fn test_takeover_rerun_never_records_own_wiring_as_original() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());

        const UUID_B: &str = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9";
        let mut record_b = record.clone();
        record_b.uuid = UUID_B.to_string();
        let (r2, e2, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record_b, PURL, false).await);
        assert!(r2.success, "{:?}", r2.error);
        let e2 = e2.expect("takeover records a fresh entry");
        let w = &e2.wiring[0];
        assert_eq!(w.key.as_deref(), Some("packages:psr/log"));
        assert!(
            w.original.is_none(),
            "own stale wiring must never be recorded as original: {:?}",
            w.original
        );

        // The lock is rewired at the new uuid's copy.
        let new_lock: Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            new_lock["packages"][0]["dist"]["url"],
            format!(".socket/vendor/composer/{UUID_B}/psr/log@3.0.2")
        );
    }

    /// Wired lock + missing copy + `--vendor-source=service`: the artifact
    /// rebuild must be service-preferred like the full path (a
    /// service-vendored package may have no installed copy to rebuild from),
    /// and `--offline` + `service` must refuse in the rebuild path too.
    #[tokio::test]
    async fn service_rebuild_of_missing_copy_uses_service() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, _installed, record) = fixture(&lock).await;
        let root = dir.path();
        let zip = make_dist_zip(
            "php-fig-log-f16e1d5",
            &[
                ("src/LoggerInterface.php", PATCHED),
                ("composer.json", b"{\"name\": \"psr/log\"}\n"),
            ],
        );
        let sri = sri_sha512(&zip);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &zip).await;
        let cfg = composer_service_cfg(&server.uri(), VendorSource::Service, false);
        let bogus_installed = root.join("no-such-install");

        let (r1, e1, _) =
            unwrap_done(vendor_with_service(root, &blobs, &bogus_installed, &record, &cfg).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let lock_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        // Fresh-clone hole: the committed copy is gone, the lock still wired.
        crate::patch::copy_tree::remove_tree(&root.join(copy_rel()))
            .await
            .unwrap();

        let (r2, e2, w2) =
            unwrap_done(vendor_with_service(root, &blobs, &bogus_installed, &record, &cfg).await);
        assert!(
            r2.success,
            "service-mode rebuild must re-download the prebuilt dist: {:?}",
            r2.error
        );
        assert!(e2.is_none(), "artifact-only rebuild must not re-record");
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{w2:?}"
        );
        assert!(
            w2.iter().any(|w| w.code == "vendor_prebuilt_downloaded"),
            "{w2:?}"
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            lock_bytes,
            "composer.lock untouched by the rebuild"
        );

        // The offline+service conflict is refused in the rebuild path too.
        crate::patch::copy_tree::remove_tree(&root.join(copy_rel()))
            .await
            .unwrap();
        let offline = composer_service_cfg(&server.uri(), VendorSource::Service, true);
        let (code, _) = unwrap_refused(
            vendor_with_service(root, &blobs, &bogus_installed, &record, &offline).await,
        );
        assert_eq!(code, "vendor_service_offline_conflict");
    }

    /// The same strand through the service path: wired lock + drifted copy +
    /// a corrupt prebuilt zip. The extract failure must not delete the
    /// live-wired uuid dir — the marker and the drifted copy composer.lock
    /// still installs from must survive.
    #[tokio::test]
    async fn service_rebuild_extract_failure_keeps_wired_artifact() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());

        let drifted = root.join(copy_rel()).join("src/LoggerInterface.php");
        tokio::fs::write(&drifted, b"<?php // drifted\n").await.unwrap();

        // Integrity-valid garbage: the download verifies, the extract fails.
        let garbage = b"not a zip at all".to_vec();
        let sri = sri_sha512(&garbage);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &garbage).await;

        let (code, _) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        assert_eq!(code, "vendor_prebuilt_extract_failed");
        assert_eq!(
            tokio::fs::read(&drifted).await.unwrap(),
            b"<?php // drifted\n".to_vec(),
            "an extract failure must leave the previous live-wired copy in place"
        );
        assert!(
            root.join(format!(
                ".socket/vendor/composer/{UUID}/{VENDOR_MARKER_FILE}"
            ))
            .exists(),
            "an extract failure must not delete the marker while the lock is wired"
        );
    }

    /// `--offline` + `--vendor-source=service` refuses without any network.
    #[tokio::test]
    async fn offline_service_mode_refuses() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let (code, _) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg("http://127.0.0.1:1", VendorSource::Service, true),
            )
            .await,
        );
        assert_eq!(code, "vendor_service_offline_conflict");
    }

    // ───────────────────── coverage: refusal / no-op input shapes ─────────────

    /// A purl from another ecosystem (a cross-wired manifest) is refused
    /// before any disk access.
    #[tokio::test]
    async fn test_refuses_non_composer_purl() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (code, detail) = unwrap_refused(
            run_vendor(
                root,
                &blobs,
                &installed,
                &record,
                "pkg:npm/left-pad@1.3.0",
                false,
            )
            .await,
        );
        assert_eq!(code, "unsafe_coordinates");
        assert!(detail.contains("not a composer purl"), "{detail}");
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before
        );
    }

    /// A metadata-only record (no files) is meaningless to vendor: no-op
    /// success — no copy, no lock edit, no ledger entry.
    #[tokio::test]
    async fn test_empty_files_record_is_noop_success() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, mut record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        record.files.clear();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "no-op must not record a ledger entry");
        assert!(warnings.is_empty(), "{warnings:?}");
        assert!(!root.join(".socket").exists(), "no copy created");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched"
        );
    }

    /// An unparseable composer.lock is as unusable as a missing one — same
    /// refusal code, distinguishing detail.
    #[tokio::test]
    async fn test_refuses_unparseable_lock() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        tokio::fs::write(root.join(COMPOSER_LOCK), b"{ not json")
            .await
            .unwrap();

        let (code, detail) =
            unwrap_refused(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert_eq!(code, "vendor_lockfile_missing");
        assert!(detail.contains("unparseable"), "{detail}");
        assert!(!root.join(".socket").exists(), "refusal must write nothing");
    }

    /// Wired lock + missing copy under `--dry-run`: the rebuild is a WET
    /// operation, so a dry run must fall through to the verify-only preview —
    /// no copy recreated, no lock write, no rebuild warning.
    #[tokio::test]
    async fn test_wired_stale_copy_dry_run_rebuilds_nothing() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let lock_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        crate::patch::copy_tree::remove_tree(&root.join(copy_rel()))
            .await
            .unwrap();

        let (r2, e2, w2) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, true).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(e2.is_none(), "dry run records nothing");
        assert!(
            w2.iter().all(|w| w.code != "vendor_artifact_rebuilt"),
            "dry run must not rebuild: {w2:?}"
        );
        assert!(
            !root.join(copy_rel()).exists(),
            "dry run must not recreate the copy"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            lock_bytes,
            "lock untouched"
        );
    }

    // ───────────────────── coverage: vendor write-failure edges ───────────────

    /// The marker is informational only: a squatted marker path (a directory
    /// where the file goes) degrades to a `vendor_marker_write_failed`
    /// warning while the vendor itself succeeds and records its entry.
    #[tokio::test]
    async fn test_marker_write_failure_degrades_to_warning() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        // A directory squats the marker path: the atomic rename cannot land.
        tokio::fs::create_dir_all(root.join(format!(
            ".socket/vendor/composer/{UUID}/{VENDOR_MARKER_FILE}"
        )))
        .await
        .unwrap();

        let (result, entry, warnings) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(
            result.success,
            "a marker failure must not fail the vendor: {:?}",
            result.error
        );
        assert!(entry.is_some(), "the wiring is live, the entry is recorded");
        assert!(
            warnings.iter().any(|w| w.code == "vendor_marker_write_failed"),
            "{warnings:?}"
        );
        // The surgery really landed despite the marker failure.
        let text = tokio::fs::read_to_string(root.join(COMPOSER_LOCK))
            .await
            .unwrap();
        assert!(text.contains(&copy_rel()), "lock rewired: {text}");
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
    }

    /// Restores a directory's mode on drop so a failing assertion can never
    /// wedge the TempDir cleanup behind a read-only dir.
    #[cfg(unix)]
    struct ModeGuard {
        path: PathBuf,
        mode: u32,
    }

    #[cfg(unix)]
    impl ModeGuard {
        fn set(path: &Path, mode: u32) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let prev = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
            Self {
                path: path.to_path_buf(),
                mode: prev,
            }
        }
    }

    #[cfg(unix)]
    impl Drop for ModeGuard {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &self.path,
                std::fs::Permissions::from_mode(self.mode),
            );
        }
    }

    /// composer.lock write failure AFTER a successful copy build: the fresh
    /// uuid dir is unwound (wiring runs last — a copy the lock never points
    /// at must not survive) and the failure is reported, lock untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_lock_write_failure_removes_copy_and_reports() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        // Writable vendor chain + read-only project root: the copy build
        // succeeds, the lock's temp-file staging (in the root) fails.
        tokio::fs::create_dir_all(root.join(".socket/vendor/composer"))
            .await
            .unwrap();
        let guard = ModeGuard::set(root, 0o555);

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        drop(guard);
        assert!(!result.success);
        let err = result.error.clone().unwrap_or_default();
        assert!(err.contains("failed to write composer.lock"), "{err}");
        assert!(entry.is_none());
        assert!(
            !root.join(".socket/vendor").exists(),
            "a failed lock write must unwind the never-wired uuid dir"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock unchanged on failure"
        );
    }

    // ───────────────────── coverage: service outcome matrix ───────────────────

    /// `--vendor-source=build` disables the service outright: local build
    /// only, zero network — no `vendor_prebuilt_*` warning may appear even
    /// though a (dead) service endpoint is configured.
    #[tokio::test]
    async fn service_source_build_never_contacts_the_service() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let cfg = composer_service_cfg("http://127.0.0.1:1", VendorSource::Build, false);

        let (result, entry, warnings) =
            unwrap_done(vendor_with_service(root, &blobs, &installed, &record, &cfg).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
        assert!(
            warnings.iter().all(|w| !w.code.starts_with("vendor_prebuilt")),
            "build source must never touch the service: {warnings:?}"
        );
    }

    /// A FRESH vendor whose prebuilt zip fails to extract (integrity-valid
    /// garbage) refuses hard and leaves no `.socket/vendor` husk behind.
    #[tokio::test]
    async fn service_extract_failure_fresh_vendor_leaves_no_husk() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let garbage = b"not a zip at all".to_vec();
        let sri = sri_sha512(&garbage);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &garbage).await;

        let (code, _) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        assert_eq!(code, "vendor_prebuilt_extract_failed");
        assert!(
            !root.join(".socket/vendor").exists(),
            "a failed fresh extract must leave no vendor husk"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched"
        );
    }

    /// `service` mode + a still-building archive hard-fails (no fallback).
    #[tokio::test]
    async fn service_pending_service_mode_hard_fails() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        let server = wiremock::MockServer::start().await;
        mount_composer_status(&server, "pending_build").await;

        let (code, detail) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("still building"), "{detail}");
        assert!(!root.join(".socket").exists(), "nothing written");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before
        );
    }

    /// `auto` + a still-building archive falls back to the local build with a
    /// `vendor_prebuilt_pending` advisory.
    #[tokio::test]
    async fn service_pending_auto_falls_back_to_build() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_composer_status(&server, "pending_build").await;

        let (result, entry, warnings) = unwrap_done(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Auto, false),
            )
            .await,
        );
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert!(
            warnings.iter().any(|w| w.code == "vendor_prebuilt_pending"),
            "{warnings:?}"
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
    }

    /// `service` mode + an unavailable archive (`not_found`) hard-fails; the
    /// auto flavor of the same status is covered by
    /// `service_unavailable_auto_falls_back_to_build`.
    #[tokio::test]
    async fn service_unavailable_service_mode_hard_fails() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_composer_status(&server, "not_found").await;

        let (code, detail) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("unavailable"), "{detail}");
        assert!(!root.join(".socket").exists(), "nothing written");
    }

    /// A failed service REQUEST (HTTP 500 on the grant endpoint) under `auto`
    /// warns `vendor_prebuilt_unavailable` and builds locally.
    #[tokio::test]
    async fn service_request_failure_auto_warns_and_builds_locally() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (result, entry, warnings) = unwrap_done(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Auto, false),
            )
            .await,
        );
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert!(
            warnings.iter().any(|w| w.code == "vendor_prebuilt_unavailable"),
            "the fallback must record why the service was skipped: {warnings:?}"
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED
        );
    }

    /// A granted archive whose copy dir cannot be created (read-only
    /// `.socket/vendor/composer`) hard-fails `vendor_prebuilt_write_failed`.
    #[cfg(unix)]
    #[tokio::test]
    async fn service_copy_dir_create_failure_hard_fails() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        let zip = make_dist_zip(
            "php-fig-log-f16e1d5",
            &[
                ("src/LoggerInterface.php", PATCHED),
                ("composer.json", b"{\"name\": \"psr/log\"}\n"),
            ],
        );
        let sri = sri_sha512(&zip);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &zip).await;

        let composer_dir = root.join(".socket/vendor/composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        let guard = ModeGuard::set(&composer_dir, 0o555);

        let (code, detail) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        drop(guard);
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(detail.contains("cannot create"), "{detail}");
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched"
        );
    }

    // ───────────────────── coverage: helper unit tests ────────────────────────

    /// Malformed lock entries — a bare string, no name, no version, a
    /// same-name/other-version sibling — are skipped leniently until the real
    /// match; a lock without either section (or a non-array one) yields None.
    #[test]
    fn test_find_lock_entry_skips_malformed_entries() {
        let lock = json!({
            "packages": [
                "not-an-object",
                { "version": "1.0" },
                { "name": "psr/log" },
                { "name": "psr/log", "version": "2.0.0" },
                { "name": "psr/log", "version": "3.0.2" }
            ]
        });
        assert_eq!(
            find_lock_entry(&lock, "psr/log", "3.0.2"),
            Some(("packages", 4))
        );
        assert_eq!(
            find_lock_entry(&json!({ "content-hash": "abc" }), "psr/log", "3.0.2"),
            None
        );
        assert_eq!(
            find_lock_entry(&json!({ "packages": "oops" }), "psr/log", "3.0.2"),
            None
        );
    }

    /// A source-only entry (no `dist`) gets `dist` + `transport-options`
    /// appended at the end; a pre-existing `transport-options` (wherever it
    /// sits) is superseded by ours, never duplicated.
    #[test]
    fn test_rewrite_lock_entry_source_only_and_transport_dedup() {
        let original = json!({
            "name": "psr/log",
            "version": "3.0.2",
            "source": {
                "type": "git",
                "url": "https://github.com/php-fig/log.git",
                "reference": "f16e1d5"
            },
            "type": "library"
        });
        let out = rewrite_lock_entry(original.as_object().unwrap(), "rel/copy", "uuid-x");
        let keys: Vec<&str> = out.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec!["name", "version", "type", "dist", "transport-options"],
            "source dropped, dist + transport-options appended at the end"
        );
        assert_eq!(out["dist"]["type"], "path");
        assert_eq!(out["dist"]["url"], "rel/copy");
        assert_eq!(out["dist"]["reference"], "uuid-x");
        assert_eq!(out["transport-options"]["symlink"], json!(false));

        let original = json!({
            "name": "psr/log",
            "transport-options": { "symlink": true },
            "dist": { "type": "zip", "url": "https://example.com/x.zip" },
            "type": "library"
        });
        let out = rewrite_lock_entry(original.as_object().unwrap(), "rel/copy", "uuid-x");
        let keys: Vec<&str> = out.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec!["name", "dist", "transport-options", "type"],
            "exactly one transport-options, right after the replaced dist"
        );
        assert_eq!(
            out["transport-options"]["symlink"],
            json!(false),
            "our transport-options supersedes the pre-existing one"
        );
    }

    /// The stranded scan degrades to empty on a missing/unparseable/odd-shaped
    /// lock, skips a wired entry without a name, reports an unrestorable
    /// wired entry lowercased, and clears once a wiring record can restore it.
    #[tokio::test]
    async fn test_stranded_scan_degrades_on_unreadable_or_odd_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(COMPOSER_LOCK);
        let none: HashSet<String> = HashSet::new();

        // Missing lock: nothing can be consuming it.
        assert!(stranded_wired_packages(&lock_path, UUID, &none)
            .await
            .is_empty());
        // Unparseable lock: same degrade (the restore loop reports drift).
        tokio::fs::write(&lock_path, b"not json").await.unwrap();
        assert!(stranded_wired_packages(&lock_path, UUID, &none)
            .await
            .is_empty());
        // No package sections at all.
        tokio::fs::write(
            &lock_path,
            composer_json_bytes(&json!({ "content-hash": "x" })).unwrap(),
        )
        .await
        .unwrap();
        assert!(stranded_wired_packages(&lock_path, UUID, &none)
            .await
            .is_empty());

        // A wired entry without a name is skipped; the named one (pretty
        // casing) comes back lowercased.
        let lock = json!({
            "packages": [
                { "dist": { "type": "path", "url": copy_rel() } },
                { "name": "Psr/Log", "dist": { "type": "path", "url": copy_rel() } }
            ]
        });
        tokio::fs::write(&lock_path, composer_json_bytes(&lock).unwrap())
            .await
            .unwrap();
        assert_eq!(
            stranded_wired_packages(&lock_path, UUID, &none).await,
            vec!["psr/log".to_string()]
        );
        // The same entry is no longer stranded once a record can restore it.
        let restorable: HashSet<String> =
            std::iter::once("packages:psr/log".to_string()).collect();
        assert!(stranded_wired_packages(&lock_path, UUID, &restorable)
            .await
            .is_empty());
    }

    // ───────────────────── coverage: revert guard rails ───────────────────────

    /// SECURITY: a tampered state.json uuid (the key of the dir revert
    /// deletes) is rejected fail-closed before any disk access.
    #[tokio::test]
    async fn test_revert_refuses_non_canonical_uuid() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let mut tampered = entry.unwrap();
        let wired = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        tampered.uuid = "../../escape".to_string();

        let outcome = revert_composer(&tampered, root, false).await;
        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("non-canonical"),
            "{:?}",
            outcome.error
        );
        assert!(
            root.join(format!(".socket/vendor/composer/{UUID}")).exists(),
            "fail-closed: nothing deleted"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            wired,
            "lock untouched"
        );
    }

    /// `--preserve-state` (`keep_artifact`): the lock restore runs unchanged
    /// while the artifact dir (copy + marker) stays behind; `kept_artifact`
    /// stays false — it is reserved for drift-keeps.
    #[tokio::test]
    async fn test_revert_preserve_state_restores_lock_keeps_artifact() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let fixture_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        let outcome = revert_composer_opts(
            &entry,
            root,
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome.kept_artifact,
            "kept_artifact stays reserved for drift-keeps"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            fixture_bytes,
            "lock restored byte-identically"
        );
        assert!(
            root.join(format!(
                ".socket/vendor/composer/{UUID}/{VENDOR_MARKER_FILE}"
            ))
            .exists(),
            "--preserve-state must keep the marker"
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/LoggerInterface.php"))
                .await
                .unwrap(),
            PATCHED,
            "--preserve-state must keep the patched copy"
        );
    }

    /// A dry-run revert previews cleanly: no lock write, no deletion, no
    /// drift warning.
    #[tokio::test]
    async fn test_revert_dry_run_writes_nothing() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        let wired = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let outcome = revert_composer(&entry, root, true).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "a clean preview must not report drift: {:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            wired,
            "dry run must not rewrite the lock"
        );
        assert!(
            root.join(copy_rel()).exists(),
            "dry run must not delete the artifact"
        );
    }

    /// An unrecognized wiring kind (a forward-version or tampered state.json)
    /// warns `vendor_lock_entry_drifted` and leaves the fragment alone.
    #[tokio::test]
    async fn test_revert_unrecognized_wiring_kind_warns_and_continues() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let mut tampered = entry.unwrap();
        let wired = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        tampered.wiring[0].kind = "composer_json_repo".to_string();

        // keep_artifact skips the stranded refusal that would otherwise trip
        // (an unrecognized kind is unrestorable by definition).
        let outcome = revert_composer_opts(
            &tampered,
            root,
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.iter().any(|w| w.code == "vendor_lock_entry_drifted"
                && w.detail.contains("unrecognized wiring kind")),
            "{:?}",
            outcome.warnings
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            wired,
            "unknown wiring left alone"
        );
        assert!(root.join(copy_rel()).exists(), "artifact kept");
    }

    /// Malformed wiring records — no key, a colon-less key, an unknown
    /// section, no recorded original — each drift-skip with a warning and
    /// never touch the lock.
    #[tokio::test]
    async fn test_revert_malformed_wiring_records_drift_skip() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        let wired = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let mut no_key = entry.clone();
        no_key.wiring[0].key = None;
        let mut no_colon = entry.clone();
        no_colon.wiring[0].key = Some("nocolon".to_string());
        let mut bad_section = entry.clone();
        bad_section.wiring[0].key = Some("plugins:psr/log".to_string());
        let mut no_original = entry.clone();
        no_original.wiring[0].original = None;

        for (label, tampered) in [
            ("no key", no_key),
            ("no colon", no_colon),
            ("bad section", bad_section),
            ("no original", no_original),
        ] {
            // keep_artifact: a malformed record is unrestorable, so a wet
            // delete-the-artifacts revert would hit the stranded refusal.
            let outcome = revert_composer_opts(
                &tampered,
                root,
                RevertOpts {
                    dry_run: false,
                    keep_artifact: true,
                },
            )
            .await;
            assert!(outcome.success, "{label}: {:?}", outcome.error);
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"),
                "{label}: {:?}",
                outcome.warnings
            );
            assert_eq!(
                tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
                wired,
                "{label}: lock untouched"
            );
            assert!(root.join(copy_rel()).exists(), "{label}: artifact kept");
        }
    }

    /// Drift shapes beyond the covered registry-dist rewrite: the whole lock
    /// section vanished, or the package entry was dropped from the lock. Both
    /// warn and still remove the artifact (composer's documented
    /// delete-on-drift behavior — nothing wired consumes it any more).
    #[tokio::test]
    async fn test_revert_drift_section_or_entry_gone_still_removes_artifact() {
        for strip_section in [true, false] {
            let lock = lock_value("psr/log", "3.0.2", false);
            let (dir, blobs, installed, record) = fixture(&lock).await;
            let root = dir.path();

            let (result, entry, _w) =
                unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
            assert!(result.success);
            let entry = entry.unwrap();

            let mut drifted = lock_value("psr/log", "3.0.2", false);
            if strip_section {
                drifted.as_object_mut().unwrap().remove("packages");
            } else {
                drifted["packages"] = json!([]);
            }
            tokio::fs::write(
                root.join(COMPOSER_LOCK),
                composer_json_bytes(&drifted).unwrap(),
            )
            .await
            .unwrap();
            let drifted_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

            let outcome = revert_composer(&entry, root, false).await;
            assert!(
                outcome.success,
                "strip_section={strip_section}: {:?}",
                outcome.error
            );
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"),
                "strip_section={strip_section}: {:?}",
                outcome.warnings
            );
            assert_eq!(
                tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
                drifted_bytes,
                "strip_section={strip_section}: drifted lock left alone"
            );
            assert!(
                !root.join(format!(".socket/vendor/composer/{UUID}")).exists(),
                "strip_section={strip_section}: uuid dir still removed"
            );
        }
    }

    /// Artifact deletion failure AFTER the lock restore landed: the revert
    /// reports the failure (success=false) with the lock already restored —
    /// rerunning revert can finish the job.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_revert_artifact_removal_failure_reported_after_restore() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let fixture_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();

        // The uuid dir's PARENT is read-only: its contents go, the final
        // rmdir fails (removal needs write on the parent, which force
        // deletion never chmods — it only relaxes dirs INSIDE the tree).
        let composer_dir = root.join(".socket/vendor/composer");
        let guard = ModeGuard::set(&composer_dir, 0o555);
        let outcome = revert_composer(&entry, root, false).await;
        drop(guard);

        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("failed to remove"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            fixture_bytes,
            "the lock restore lands BEFORE the failed deletion"
        );
        assert!(
            root.join(format!(".socket/vendor/composer/{UUID}")).exists(),
            "the undeletable uuid dir is still there"
        );
    }

    /// composer.lock write failure during the restore: the revert fails with
    /// the write error and the artifacts are kept (the error return precedes
    /// the deletion) — the wired project still installs.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_revert_lock_write_failure_keeps_artifacts() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(result.success);
        let entry = entry.unwrap();
        let wired = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        // Read-only project root: the lock stays readable (the stranded scan
        // and ownership gate still run) but the atomic write's temp file
        // cannot be staged next to it.
        let guard = ModeGuard::set(root, 0o555);
        let outcome = revert_composer(&entry, root, false).await;
        drop(guard);

        assert!(!outcome.success);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("failed to write composer.lock"),
            "{:?}",
            outcome.error
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            wired,
            "a failed restore leaves the wired lock in place"
        );
        assert!(
            root.join(format!(
                ".socket/vendor/composer/{UUID}/{VENDOR_MARKER_FILE}"
            ))
            .exists(),
            "artifacts must survive a failed restore"
        );
    }

    // ───────────────────── coverage: staged-swap edges ─────────────────────

    /// A rootless copy dir has no parent to stage siblings in; the swap
    /// helpers degrade to suffixing the path itself instead of panicking.
    #[test]
    fn test_swap_sibling_fallback_for_rootless_copy_dir() {
        assert_eq!(
            stage_dir_for(Path::new("/")),
            PathBuf::from("/.socket-stage")
        );
        assert_eq!(backup_dir_for(Path::new("/")), PathBuf::from("/.socket-old"));
    }

    /// A swap whose stage is gone (crash window / concurrent cleanup) must
    /// fail AND put the parked old copy back — no step may leave less
    /// recoverable state than it started with.
    #[tokio::test]
    async fn test_swap_missing_stage_restores_parked_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("log@3.0.2");
        tokio::fs::create_dir_all(&copy).await.unwrap();
        tokio::fs::write(copy.join("keep.php"), b"live copy")
            .await
            .unwrap();
        let stage = stage_dir_for(&copy); // never created

        let err = swap_stage_into_place(&stage, &copy)
            .await
            .expect_err("swapping a missing stage must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            tokio::fs::read(copy.join("keep.php")).await.unwrap(),
            b"live copy".to_vec(),
            "the parked copy must be restored after the failed swap"
        );
        assert!(
            !backup_dir_for(&copy).exists(),
            "no .socket-old husk may remain after the restore"
        );
    }

    /// A park rename that fails for a real reason (EACCES on a read-only
    /// parent — not the benign no-previous-copy NotFound) must bubble the
    /// error with the live copy and the stage still in place.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_swap_park_rename_failure_bubbles() {
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let dir = tempfile::tempdir().unwrap();
        let hold = dir.path().join("hold");
        let copy = hold.join("log@3.0.2");
        tokio::fs::create_dir_all(&copy).await.unwrap();
        tokio::fs::write(copy.join("keep.php"), b"live copy")
            .await
            .unwrap();
        let stage = stage_dir_for(&copy);
        tokio::fs::create_dir_all(&stage).await.unwrap();
        tokio::fs::write(stage.join("new.php"), b"rebuilt").await.unwrap();

        let guard = ModeGuard::set(&hold, 0o555);
        let result = swap_stage_into_place(&stage, &copy).await;
        drop(guard);

        let err = result.expect_err("a read-only parent must fail the park rename");
        assert_ne!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "the failure is a real error, not the benign no-old-copy case"
        );
        assert_eq!(
            tokio::fs::read(copy.join("keep.php")).await.unwrap(),
            b"live copy".to_vec(),
            "the live copy must be untouched"
        );
        assert!(stage.exists(), "the stage is left for the caller's cleanup");
    }

    /// Wired lock + drifted copy + a SUCCEEDING local rebuild: the staged
    /// rebuild swaps over the drifted copy in place — parking it and then
    /// clearing the `.socket-old` backup — while the lock stays
    /// byte-identical and no ledger entry is re-recorded.
    #[tokio::test]
    async fn test_wired_drifted_copy_rebuild_swaps_over_old_copy() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();

        let (r1, e1, _) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r1.success, "{:?}", r1.error);
        assert!(e1.is_some());
        let lock_bytes = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        // Drift the committed copy (a hand edit); the rerun rebuilds it.
        let drifted = root.join(copy_rel()).join("src/LoggerInterface.php");
        tokio::fs::write(&drifted, b"<?php // drifted\n").await.unwrap();

        let (r2, e2, w2) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(e2.is_none(), "artifact-only rebuild must not re-record");
        assert!(
            w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{w2:?}"
        );
        assert_eq!(
            tokio::fs::read(&drifted).await.unwrap(),
            PATCHED,
            "the drifted copy is replaced by the rebuilt one"
        );
        assert!(
            !root.join(format!("{}.socket-old", copy_rel())).exists(),
            "the parked old copy is deleted after a successful swap"
        );
        assert!(
            !root.join(format!("{}.socket-stage", copy_rel())).exists(),
            "no stage sibling survives a successful swap"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            lock_bytes,
            "composer.lock untouched by the rebuild"
        );
    }

    /// A fresh vendor whose final stage→copy swap fails must report the
    /// failure, leave composer.lock untouched, and unwind the never-wired
    /// uuid dir. Trigger: a regular file squatting the `.socket-old` backup
    /// path — `remove_dir_all` on a file fails ENOTDIR on every platform, so
    /// the swap's park step errors deterministically, permission-free.
    #[tokio::test]
    async fn test_fresh_vendor_swap_failure_reports_and_unwinds() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();

        let pkg_parent = root.join(format!(".socket/vendor/composer/{UUID}/psr"));
        tokio::fs::create_dir_all(&pkg_parent).await.unwrap();
        tokio::fs::write(pkg_parent.join("log@3.0.2.socket-old"), b"squatter")
            .await
            .unwrap();

        let (result, entry, _w) =
            unwrap_done(run_vendor(root, &blobs, &installed, &record, PURL, false).await);
        assert!(!result.success);
        let err = result.error.clone().unwrap_or_default();
        assert!(
            err.contains("failed to move the rebuilt copy into place"),
            "{err}"
        );
        assert!(entry.is_none());
        assert!(
            !root.join(".socket/vendor").exists(),
            "a failed fresh vendor must unwind the never-wired uuid dir"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched on failure (wiring runs last)"
        );
    }

    /// The same squatting-backup swap failure through the SERVICE path: the
    /// verified extract cannot be moved into place → hard
    /// `vendor_prebuilt_write_failed`, no copy lands at the wired path, and
    /// composer.lock is untouched.
    #[tokio::test]
    async fn service_swap_failure_hard_fails_write_failed() {
        let lock = lock_value("psr/log", "3.0.2", false);
        let (dir, blobs, installed, record) = fixture(&lock).await;
        let root = dir.path();
        let before = tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap();
        let zip = make_dist_zip(
            "php-fig-log-f16e1d5",
            &[
                ("src/LoggerInterface.php", PATCHED),
                ("composer.json", b"{\"name\": \"psr/log\"}\n"),
            ],
        );
        let sri = sri_sha512(&zip);
        let server = wiremock::MockServer::start().await;
        mount_composer_granted(&server, &sri, &zip).await;

        let pkg_parent = root.join(format!(".socket/vendor/composer/{UUID}/psr"));
        tokio::fs::create_dir_all(&pkg_parent).await.unwrap();
        tokio::fs::write(pkg_parent.join("log@3.0.2.socket-old"), b"squatter")
            .await
            .unwrap();

        let (code, detail) = unwrap_refused(
            vendor_with_service(
                root,
                &blobs,
                &installed,
                &record,
                &composer_service_cfg(&server.uri(), VendorSource::Service, false),
            )
            .await,
        );
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(
            detail.contains("cannot move the extracted dist into place"),
            "{detail}"
        );
        assert!(
            !root.join(copy_rel()).exists(),
            "no copy may land at the wired path after a failed swap"
        );
        assert_eq!(
            tokio::fs::read(root.join(COMPOSER_LOCK)).await.unwrap(),
            before,
            "lock untouched"
        );
    }
}
