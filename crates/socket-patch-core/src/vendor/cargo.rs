//! The cargo vendor backend: committable `[patch.crates-io]` vendoring.
//!
//! Materialises a patched copy of the crate under
//! `.socket/vendor/cargo/<patch-uuid>/<name>-<version>/`, points cargo at it
//! with a `[patch.crates-io]` path entry in `.cargo/config.toml`
//! ([`super::cargo_config`]), and surgically detaches the crate's
//! `Cargo.lock` entry from the registry ([`super::cargo_lock`]) — without the
//! lock edit, `cargo build --locked` fails closed on the un-relocked `[patch]`
//! (spike-verified; the whole wiring is proven offline-from-Socket on a fresh
//! checkout with an empty `CARGO_HOME` — `spikes/PHASE0-FINDINGS.txt`).
//!
//! The copy is produced by **delegating to the hardened
//! [`apply_package_patch`] pipeline** pointed at the fresh copy, so all the
//! verify → package/diff/blob → atomic-write machinery is reused unchanged.

use std::path::Path;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::path_safety::is_safe_single_segment;
use crate::utils::purl::{parse_cargo_purl, strip_purl_qualifiers};

use super::cargo_config::{self, LEGACY_CARGO_PATCHES_DIR};
use super::cargo_lock::{self, LockEditError};
use super::common::{
    already_patched_result, copy_matches_after_hashes, done, refused, service_offline_conflict,
    synthesized_result,
};
use super::path::vendor_uuid_dir_rel;
use super::registry_fetch::extract_tgz;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::{
    write_marker, CargoLockOriginal, VendorArtifact, VendorEntry, VendorMarker, WiringAction,
    WiringRecord, VENDOR_MARKER_FILE,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// True if a crate is vendored under `<project_root>/vendor/` (in either the
/// `<name>-<version>/` or bare `<name>/` layout the cargo crawler probes). A
/// real `cargo vendor` tree already provides committed, project-owned bytes
/// for the crate, so the `[patch]`+lock wiring would conflict with the
/// `[source]` replacement that tree implies — refuse upstream instead.
async fn is_vendored(project_root: &Path, name: &str, version: &str) -> bool {
    let vendor = project_root.join("vendor");
    for candidate in [vendor.join(format!("{name}-{version}")), vendor.join(name)] {
        if tokio::fs::metadata(&candidate)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// True iff a config-entry path points into the retired redirect backend's
/// `.socket/cargo-patches/` tree (vendor takes such entries over and reports
/// the takeover, rather than treating them as a silent refresh).
fn is_legacy_redirect_path(path: &str) -> bool {
    let norm = path.replace('\\', "/");
    let norm = norm.strip_prefix("./").unwrap_or(&norm);
    norm.starts_with(&format!("{LEGACY_CARGO_PATCHES_DIR}/"))
}

/// Is this vendored cargo entry still consumed by the project's `Cargo.lock`
/// dependency graph? The lock is the truth source:
///
/// * entry absent from the lock → `Some(false)` (the dependency left the
///   graph; the `[patch]` would be unused);
/// * entry carries a registry `source` (crates.io re-resolve or a hosted
///   socket-patch takeover) → `Some(false)` — the committed copy is NOT what
///   the lock consumes, so GC may reclaim the entry (its revert restores /
///   keeps the registry resolution and drops the dead `[patch]` wiring);
/// * entry detached AND the `[patch.crates-io]` entry points at THIS entry's
///   committed copy → `Some(true)` (the wired vendored shape);
/// * detached but the `[patch]` points elsewhere / is gone → `Some(false)`
///   (nothing consumes the copy; the revert re-attaches the recorded
///   registry originals, repairing the half-wired lock);
/// * no readable lock → `None` (cannot determine — callers keep, fail-safe).
pub async fn vendored_entry_in_use(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    let (name, version) = parse_cargo_purl(&entry.base_purl)?;
    match cargo_lock::probe_lock_entry(project_root, name, version).await {
        cargo_lock::LockEntryProbe::NoLockfile => None,
        cargo_lock::LockEntryProbe::EntryMissing => Some(false),
        cargo_lock::LockEntryProbe::Source(_) => Some(false),
        cargo_lock::LockEntryProbe::Detached => {
            let marker = vendor_uuid_dir_rel("cargo", &entry.uuid)?;
            let entries = cargo_config::read_patch_entries(project_root).await;
            let wired = entries
                .get(name)
                .and_then(|i| i.path.as_deref())
                .is_some_and(|p| p.replace('\\', "/").starts_with(&format!("{marker}/")));
            Some(wired)
        }
    }
}

/// Guarded read shared in shape with the setup/crawler twins:
/// `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular files,
/// so a FIFO fails fast instead of wedging the caller forever.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

/// A LIVE hosted-redirect wiring for `name`+`version`: the lock resolves it
/// from a Socket hosted patch registry, or Cargo.toml pins it to a
/// `socket-patch-<uuid>` registry (the shapes `scan --mode hosted` writes).
/// Registry indexes are matched against the config-declared
/// `[registries.socket-patch-*]` URLs, not a hardcoded host, so test
/// registries are recognised too. `Some(description)` when residue is found.
async fn hosted_redirect_residue(project_root: &Path, name: &str, version: &str) -> Option<String> {
    let socket_indexes = cargo_config::socket_registry_indexes(project_root).await;
    if let cargo_lock::LockEntryProbe::Source(src) =
        cargo_lock::probe_lock_entry(project_root, name, version).await
    {
        if src.contains("patch.socket.dev") || socket_indexes.iter().any(|(_, index)| *index == src)
        {
            return Some(format!(
                "Cargo.lock resolves {name}@{version} from the Socket hosted patch \
                 registry ({src})"
            ));
        }
    }
    // Guarded read (`open_regular_file`: O_NONBLOCK + regular-file check) —
    // a FIFO planted as `Cargo.toml` would otherwise wedge every wet vendor
    // run in an open(2) that waits for a writer; an unreadable manifest has
    // no readable residue, matching the read_to_string Err arm this guards.
    if let Ok(toml) = read_regular_to_string(&project_root.join("Cargo.toml")).await {
        let c = regex::escape(name);
        let re = regex::Regex::new(&format!(
            r#"(?m)^\s*{c}\s*=\s*\{{[^}}\n]*registry\s*=\s*"socket-patch-[0-9a-fA-F-]{{36}}""#
        ))
        .expect("static regex");
        if re.is_match(&toml) {
            return Some(format!(
                "Cargo.toml pins `{name}` to a socket-patch hosted registry"
            ));
        }
    }
    None
}

/// The config `[patch]` entry points at THIS copy and the lock entry no
/// longer needs detaching: either there is no lockfile (nothing to edit — the
/// first build generates a path-form lock), or the entry exists with no
/// `source` (already detached). The lock half is probed via a dry-run detach:
/// `NotRegistry` *is* the detached shape.
async fn wiring_in_sync(project_root: &Path, name: &str, version: &str, copy_rel: &str) -> bool {
    let entries = cargo_config::read_patch_entries(project_root).await;
    if entries.get(name).and_then(|i| i.path.as_deref()) != Some(copy_rel) {
        return false;
    }
    matches!(
        cargo_lock::detach_lock_entry(project_root, name, version, true).await,
        Err(LockEditError::NotRegistry) | Err(LockEditError::NoLockfile)
    )
}

/// A swap sibling for a copy dir: `<uuid>/<name>-<version><suffix>`. Same
/// directory as the copy → every swap step is a real rename, never a
/// cross-device copy. The suffixes can never collide with a copy dir:
/// `<version>` is a validated single segment and cargo versions never end in
/// `.socket-stage` / `.socket-old`.
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

/// The staging sibling for a copy dir: `<uuid>/<name>-<version>.socket-stage`.
/// Rebuilds are materialised here and swapped into place only on success, so
/// a failure can never destroy a pre-existing (possibly live-wired) copy.
fn stage_dir_for(copy_dir: &Path) -> std::path::PathBuf {
    swap_sibling_for(copy_dir, ".socket-stage")
}

/// The backup sibling the old copy is parked at mid-swap:
/// `<uuid>/<name>-<version>.socket-old`.
fn backup_dir_for(copy_dir: &Path) -> std::path::PathBuf {
    swap_sibling_for(copy_dir, ".socket-old")
}

/// Swap a fully-built stage into place without a destructive window: park the
/// old copy (if any) at `<copy>.socket-old` with a same-dir rename, rename the
/// stage over the now-vacant copy path, and only then delete the backup. Every
/// step is a single atomic rename — unlike a remove-then-rename swap (where a
/// partial `remove_dir_all`, realistic under Windows file locks, strands a
/// half-deleted copy) no step can leave less recoverable state than it started
/// with. If the stage rename fails the backup is renamed straight back; should
/// even that restore fail (an external process racing the uuid dir), the old
/// copy still exists intact at `<copy>.socket-old` instead of being destroyed.
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

/// Best-effort removal of an EMPTY `<uuid>/` dir plus the empty
/// `.socket/vendor/cargo/` and `.socket/vendor/` levels a failed run may have
/// created, so a hard failure leaves no husk for the user to commit.
/// `remove_dir` refuses non-empty dirs, so live copies, markers, and other
/// crates' vendor dirs always survive.
async fn prune_empty_vendor_dirs(uuid_dir: &Path) {
    // The uuid level may already be gone (the unwind paths `remove_tree` it
    // before pruning): NotFound must continue to the parent levels this run
    // created, or they survive as committable husks. Any other error (i.e.
    // non-empty: a live copy or marker) still stops the prune.
    match tokio::fs::remove_dir(uuid_dir).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return,
    }
    let Some(eco_dir) = uuid_dir.parent() else {
        return;
    };
    if tokio::fs::remove_dir(eco_dir).await.is_err() {
        return;
    }
    if let Some(vendor_dir) = eco_dir.parent() {
        let _ = tokio::fs::remove_dir(vendor_dir).await;
    }
}

/// Failure cleanup for a staged (re)build: always remove the stage, then
/// either unwind the whole `<uuid>/` dir (`unwind_uuid_dir` — a fresh vendor
/// with no pre-existing state worth keeping) or leave existing state
/// untouched; either way prune any empty-husk dirs left behind.
async fn cleanup_failed_stage(stage: &Path, uuid_dir: &Path, unwind_uuid_dir: bool) {
    let _ = remove_tree(stage).await;
    if unwind_uuid_dir {
        let _ = remove_tree(uuid_dir).await;
    }
    prune_empty_vendor_dirs(uuid_dir).await;
}

/// Outcome of attempting to materialise the cargo copy from the patch service.
enum CargoServiceCopy {
    /// The prebuilt crate was extracted into `copy_dir`.
    Used,
    /// Bubble this terminal outcome (boxed — `VendorOutcome` is large).
    HardFail(Box<VendorOutcome>),
    /// Fall back to copying + patching the pristine source.
    FallBack,
}

/// Download the prebuilt `.crate`, integrity-verify it, and extract it into
/// `copy_dir` (a path-dep copy must carry no `.cargo-checksum.json`). Maps each
/// service outcome onto the `auto` / `service` fallback policy. The extracted
/// crate IS the patched package the converter built, so it needs no pristine
/// source — which is the point of the service path.
async fn cargo_service_copy(
    service: Option<&VendorServiceConfig>,
    record: &PatchRecord,
    name: &str,
    copy_dir: &Path,
    uuid_dir: &Path,
    warnings: &mut Vec<VendorWarning>,
) -> CargoServiceCopy {
    let Some(cfg) = service else {
        return CargoServiceCopy::FallBack;
    };
    if !cfg.service_enabled() {
        return CargoServiceCopy::FallBack;
    }
    fn hard(code: &'static str, detail: String) -> CargoServiceCopy {
        CargoServiceCopy::HardFail(Box::new(refused(code, detail)))
    }
    let miss = |warnings: &mut Vec<VendorWarning>, code: &'static str, reason: String| {
        if cfg.source.requires_service() {
            hard("vendor_prebuilt_required", reason)
        } else {
            warnings.push(VendorWarning::new(
                code,
                format!("{reason}; building locally instead"),
            ));
            CargoServiceCopy::FallBack
        }
    };
    match fetch_verified_archive(cfg, &record.uuid).await {
        ServiceArtifact::Ready(archive) => {
            // Extract the `.crate` (tar.gz; strip its single
            // `{name}-{version}/` top-level dir) into a STAGE sibling and
            // swap it into the copy dir only once fully verified — a failure
            // then leaves any pre-existing copy untouched and no husk behind.
            let stage = stage_dir_for(copy_dir);
            let _ = remove_tree(&stage).await;
            if let Err(e) = tokio::fs::create_dir_all(&stage).await {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot create {}: {e}", stage.display()),
                );
            }
            if let Err(e) = extract_tgz(&archive.bytes, &stage) {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return hard(
                    "vendor_prebuilt_extract_failed",
                    format!("cannot extract the prebuilt crate: {e}"),
                );
            }
            let _ = tokio::fs::remove_file(stage.join(".cargo-checksum.json")).await;
            // Verify the EXTRACTED TREE, not just the archive bytes: the SRI
            // proves the download is intact, but an unexpected internal
            // layout (the single `{name}-{version}/` strip leaving an extra
            // wrapper, or an over-strip) lands the patched files at the wrong
            // paths and the caller would synthesize success from
            // `record.files` while the copy is wrong. Fail closed → `auto`
            // falls back to the local build. (Mirrors composer_lock.rs.)
            if !copy_matches_after_hashes(&stage, &record.files).await {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return miss(
                    warnings,
                    "vendor_prebuilt_layout_mismatch",
                    format!(
                        "prebuilt crate for {name} extracted to an unexpected \
                         layout (patched files absent at their recorded paths)"
                    ),
                );
            }
            if let Err(e) = swap_stage_into_place(&stage, copy_dir).await {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot move the extracted crate into place: {e}"),
                );
            }
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {name} from the patch service ({})",
                    archive.source_url
                ),
            ));
            CargoServiceCopy::Used
        }
        // Bytes that fail integrity verification are an active tamper signal:
        // ALWAYS a hard error, in `auto` exactly as in `service` — never a
        // quiet local-build fallback (`ServiceArtifact`'s documented
        // contract; nothing was extracted, so there is nothing to clean up).
        ServiceArtifact::IntegrityMismatch(reason) => hard(
            "vendor_prebuilt_integrity_mismatch",
            format!(
                "prebuilt crate for {name} failed integrity verification ({reason}); \
                 refusing to fall back to a local build on tampered bytes"
            ),
        ),
        ServiceArtifact::Pending => miss(
            warnings,
            "vendor_prebuilt_pending",
            "prebuilt crate is still building".to_string(),
        ),
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard(
                    "vendor_prebuilt_required",
                    format!("prebuilt crate unavailable: {reason}"),
                )
            } else {
                CargoServiceCopy::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => miss(
            warnings,
            "vendor_prebuilt_unavailable",
            format!("patch service request failed ({reason})"),
        ),
    }
}

/// Copy the pristine source into a STAGE sibling of `copy_dir`, run the
/// hardened apply pipeline against it (vendor auto-force policy — see
/// [`super::force_apply_staged`]), and swap the stage into `copy_dir` only on
/// success. A failed (re)build therefore never destroys a pre-existing copy:
/// with `unwind_uuid_dir` (a fresh vendor — nothing pre-existing to keep) the
/// whole uuid dir is removed, without it (a live-wired rebuild) the previous
/// copy, marker, and wiring are left exactly as they were; either way no
/// partial copy or empty `<uuid>/` husk — which verify/sweep would misjudge —
/// survives, and the failed [`ApplyResult`] is the `Err` for the caller to
/// bubble. On success the copy carries no `.cargo-checksum.json` (a path-dep
/// copy must never have one; the fresh copy excludes it, and it is re-removed
/// defensively in case the patch recreated it).
#[allow(clippy::too_many_arguments)]
async fn copy_and_patch(
    purl: &str,
    pristine_src: &Path,
    copy_dir: &Path,
    uuid_dir: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    unwind_uuid_dir: bool,
    name: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<ApplyResult, ApplyResult> {
    let stage = stage_dir_for(copy_dir);
    // `fresh_copy` removes + recreates the stage itself.
    if let Err(e) = fresh_copy(pristine_src, &stage, Some(".cargo-checksum.json")).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(synthesized_result(
            purl,
            copy_dir,
            Vec::new(),
            false,
            Some(format!("failed to copy pristine source: {e}")),
        ));
    }
    let mut result = super::force_apply_staged(
        purl, &stage, record, sources, false, force, name, version, warnings,
    )
    .await;
    result.package_path = copy_dir.display().to_string();
    if !result.success {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        return Err(result);
    }
    let _ = tokio::fs::remove_file(stage.join(".cargo-checksum.json")).await;
    if let Err(e) = swap_stage_into_place(&stage, copy_dir).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to move the rebuilt copy into place: {e}"));
        return Err(result);
    }
    debug_assert!(
        result.sidecar.is_none(),
        "vendor copy must not produce a cargo sidecar"
    );
    result.sidecar = None;
    Ok(result)
}

/// Vendor one cargo crate: patched copy + `[patch.crates-io]` entry +
/// `Cargo.lock` surgery + marker, returning the ledger entry to persist.
///
/// * `pristine_src` — the pristine registry/vendor source dir (the crawler's
///   `pkg_path`). It is copied, never mutated.
/// * `vendored_at` — caller-formatted RFC3339 timestamp for the marker.
///
/// `dry_run` writes nothing (it verifies against `pristine_src` for an
/// accurate report). On the in-sync hot path (re-run with everything already
/// wired) `entry` is `None` — the lock originals are only recoverable from
/// the existing ledger entry, so the caller must keep it, not overwrite it.
#[allow(clippy::too_many_arguments)]
pub async fn vendor_cargo_crate(
    purl: &str,
    pristine_src: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    // ── coordinate validation (fail-closed, before any disk access) ──────
    let Some((name, version)) = parse_cargo_purl(purl) else {
        return refused("unsafe_coordinates", format!("not a cargo purl: {purl}"));
    };
    // SECURITY: `name`/`version` key the on-disk copy dir
    // (`.socket/vendor/cargo/<uuid>/<name>-<version>/`) and the `[patch]`
    // path. A `..`/separator from a tampered manifest PURL would let the copy
    // and the apply pipeline escape `.socket/vendor/` — refuse before any
    // disk access.
    if !is_safe_single_segment(name) || !is_safe_single_segment(version) {
        return refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor unsafe cargo coordinates `{name}`/`{version}` \
                 (a path separator or `..` would escape .socket/vendor/cargo/)"
            ),
        );
    }
    // SECURITY: the uuid is a dedicated path level created here and deleted by
    // `--revert`; anything but the canonical UUID grammar is rejected.
    let Some(base_rel) = vendor_uuid_dir_rel("cargo", &record.uuid) else {
        return refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor {purl}: patch uuid `{}` is not a canonical uuid",
                record.uuid
            ),
        );
    };

    // ── pre-flight refusals (read-only) ───────────────────────────────────
    // (a) A real `cargo vendor` tree already provides this crate.
    if is_vendored(project_root, name, version).await {
        return refused(
            "already_vendored_in_tree",
            format!(
                "{name}@{version} is provided by the project's `vendor/` tree \
                 (cargo vendor); patch it in place with `apply` instead"
            ),
        );
    }
    // (b) The lock must resolve this exact version, or the `[patch]` would be
    // unused and an unlocked build would silently re-lock (spike claim 6).
    if let Some(locked) = cargo_lock::read_locked_versions(project_root).await {
        match locked.get(name) {
            Some(versions) if versions.contains(version) => {}
            Some(versions) => {
                let mut sorted: Vec<&str> = versions.iter().map(String::as_str).collect();
                sorted.sort_unstable();
                return refused(
                    "locked_version_mismatch",
                    format!(
                        "Cargo.lock resolves `{name}` to {} but the patch targets {version}",
                        sorted.join(", ")
                    ),
                );
            }
            None => {
                return refused(
                    "locked_version_mismatch",
                    format!("`{name}` is not present in Cargo.lock (patch targets {version})"),
                );
            }
        }
    }
    // (b2) The lock must resolve name+version from a SINGLE entry. A second
    // same-name+version entry (registry + a git fork — a legal,
    // cargo-generated shape) means consumers' `dependencies` arrays
    // disambiguate with full package-id strings, which the detach surgery
    // would dangle: vendor would "succeed" while the committed lock breaks
    // every `cargo build --locked` (real-cargo verified). Refuse up front.
    if cargo_lock::count_lock_entries(project_root, name, version).await > 1 {
        return refused(
            "locked_multi_source_conflict",
            format!(
                "Cargo.lock resolves `{name}@{version}` from multiple sources \
                 (e.g. the registry plus a git fork); detaching the registry \
                 entry would corrupt the full package-id references in the \
                 lock's dependencies arrays, so this crate cannot be vendored \
                 in this project"
            ),
        );
    }
    // (c) A user-authored same-name `[patch.crates-io]` entry is never
    // overwritten. (`ensure_patch_entry` would also refuse, but pre-flighting
    // it keeps the refusal ahead of any write.)
    let prior_entry = cargo_config::read_patch_entries(project_root)
        .await
        .remove(name);
    if let Some(info) = &prior_entry {
        if !info.socket_owned {
            return refused(
                "user_authored_patch_entry",
                format!(
                    "`patch.crates-io.{name}` in .cargo/config.toml is user-authored \
                     ({}); refusing to overwrite",
                    info.path.as_deref().unwrap_or("non-path source")
                ),
            );
        }
    }

    let copy_rel = format!("{base_rel}/{name}-{version}");
    let uuid_dir = project_root.join(&base_rel);
    let copy_dir = project_root.join(&copy_rel);

    // A patch with no files is meaningless: no-op success, nothing wired.
    if record.files.is_empty() {
        return done(
            synthesized_result(purl, &copy_dir, Vec::new(), true, None),
            None,
            Vec::new(),
        );
    }

    if dry_run {
        // Verify (read-only) against the pristine source — the apply
        // pipeline never writes when dry_run — for an accurate "would
        // patch" report (including the auto-force overwrite warnings the
        // real run would emit), without creating the copy or editing
        // config/lock.
        let mut dry_warnings: Vec<VendorWarning> = Vec::new();
        let mut result = super::force_apply_staged(
            purl,
            pristine_src,
            record,
            sources,
            true,
            force,
            name,
            version,
            &mut dry_warnings,
        )
        .await;
        result.package_path = copy_dir.display().to_string();
        result.sidecar = None;
        return done(result, None, dry_warnings);
    }

    // Cross-mode takeover guard (fail-closed): a LIVE hosted-redirect wiring
    // for this crate must be reverted from the redirect ledger BEFORE
    // vendoring — the CLI vendored flows do exactly that. Reaching this point
    // with the residue still present means the redirect ledger is missing or
    // corrupt (no recorded originals to revert with); proceeding would bake
    // the hosted registry values into this entry's lock originals as if they
    // were pristine, leave Cargo.toml pinned to the hosted registry, and
    // report success on an unbuildable half-migrated project. Refuse with the
    // manual remediation instead. Runs after the dry-run branch: a preview
    // must not report the wet run's ledger-driven revert as a failure.
    if let Some(residue) = hosted_redirect_residue(project_root, name, version).await {
        return refused(
            "hosted_redirect_live",
            format!(
                "{residue}, but no redirect ledger record can revert it \
                 (.socket/vendor/redirect-state.json is missing or does not \
                 record this package); restore the ledger, or manually remove \
                 the `registry = \"socket-patch-…\"` key from Cargo.toml, \
                 restore the crates.io source/checksum in Cargo.lock, and drop \
                 the `[registries.socket-patch-…]` block, then re-run"
            ),
        );
    }

    // Hot path: already in sync → touch nothing (entry stays with the caller's
    // existing ledger record, which holds the unrecoverable lock originals).
    if wiring_in_sync(project_root, name, version, &copy_rel).await {
        if copy_matches_after_hashes(&copy_dir, &record.files).await {
            return done(
                already_patched_result(purl, &copy_dir, &record.files),
                None,
                Vec::new(),
            );
        }
        // Wired but the committed copy is missing/stale: rebuild the
        // ARTIFACT only — config + lock are already correct, and the full
        // path's surgery would re-record live vendored state over the
        // first run's unrecoverable lock originals. The rebuild is staged: a
        // failure must leave the previous (drifted-but-buildable) copy and
        // the live wiring exactly as they were, never a deleted copy under a
        // still-pointing `[patch]` entry.
        let mut warnings: Vec<VendorWarning> = Vec::new();
        let result = match copy_and_patch(
            purl,
            pristine_src,
            &copy_dir,
            &uuid_dir,
            record,
            sources,
            force,
            false, // live-wired: never unwind the uuid dir on failure
            name,
            version,
            &mut warnings,
        )
        .await
        {
            Ok(result) => result,
            Err(result) => return done(result, None, warnings),
        };
        warnings.push(VendorWarning::new(
            "vendor_artifact_rebuilt",
            format!(
                "the committed vendored copy for {name}@{version} was missing or stale; \
                 rebuilt at {copy_rel} (config and lock untouched)"
            ),
        ));
        // The rebuild may have recreated the whole uuid dir (deleted
        // wholesale, marker included): restore the committed marker
        // alongside the copy so the re-committed vendor unit is complete.
        // Only when missing — a copy-only rebuild keeps the original marker
        // (and its vendoredAt).
        if tokio::fs::metadata(uuid_dir.join(VENDOR_MARKER_FILE))
            .await
            .is_err()
        {
            let marker =
                VendorMarker::new("cargo", strip_purl_qualifiers(purl), record, vendored_at);
            if let Err(e) = write_marker(&uuid_dir, &marker).await {
                warnings.push(VendorWarning::new(
                    "marker_write_failed",
                    format!("could not write the vendor marker: {e}"),
                ));
            }
        }
        return done(result, None, warnings);
    }

    // ── materialise the patched copy ──────────────────────────────────────
    // Prefer the prebuilt `.crate` from the patch service (download + extract,
    // no pristine source needed); else copy the pristine source and patch it
    // (`copy_and_patch`). Either way a path-dep copy must never carry a
    // `.cargo-checksum.json` (cargo 1.93 src dirs no longer have one, but
    // older layouts do and its presence would re-enable checksum fixups).
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if let Some(refusal) = service_offline_conflict(service) {
        return refusal;
    }
    // When the pre-existing config entry already points at THIS copy (wiring
    // out of sync only because of the lock — e.g. it was re-resolved or went
    // corrupt post-vendor), a failure must not delete the copy that entry
    // points at: the unwind restores the entry, and removing the uuid dir
    // would dangle it and break every build.
    let prior_points_here =
        prior_entry.as_ref().and_then(|i| i.path.as_deref()) == Some(copy_rel.as_str());
    let mut result = match cargo_service_copy(
        service,
        record,
        name,
        &copy_dir,
        &uuid_dir,
        &mut warnings,
    )
    .await
    {
        CargoServiceCopy::Used => {
            // The service crate is the patched package; trust its verified
            // integrity (every file reads as AlreadyPatched).
            already_patched_result(purl, &copy_dir, &record.files)
        }
        CargoServiceCopy::HardFail(outcome) => return *outcome,
        CargoServiceCopy::FallBack => {
            match copy_and_patch(
                purl,
                pristine_src,
                &copy_dir,
                &uuid_dir,
                record,
                sources,
                force,
                !prior_points_here,
                name,
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

    // ── wire the config entry ─────────────────────────────────────────────
    if let Err(e) = cargo_config::ensure_patch_entry(project_root, name, &copy_rel, false).await {
        // The config was left untouched on refusal; unwind the copy so no
        // unwired artifact lingers under .socket/vendor/ — unless the
        // existing config entry points at this very copy, which deleting
        // would dangle.
        if !prior_points_here {
            let _ = remove_tree(&uuid_dir).await;
        }
        prune_empty_vendor_dirs(&uuid_dir).await;
        result.success = false;
        result.error = Some(format!("failed to update .cargo/config.toml: {e}"));
        return done(result, None, warnings);
    }

    let prior_path = prior_entry.as_ref().and_then(|i| i.path.clone());
    if prior_path.as_deref().is_some_and(is_legacy_redirect_path) {
        warnings.push(VendorWarning::new(
            "vendor_takeover",
            format!("took over the legacy `.socket/cargo-patches/` [patch] entry for `{name}`"),
        ));
    }

    // ── detach the lock entry ─────────────────────────────────────────────
    let lock_original: Option<CargoLockOriginal> =
        match cargo_lock::detach_lock_entry(project_root, name, version, false).await {
            Ok(orig) => Some(orig),
            Err(LockEditError::NoLockfile) => {
                // No lock to edit: the first `cargo build`/`generate-lockfile`
                // records the path patch directly (no source/checksum).
                warnings.push(VendorWarning::new(
                    "no_lockfile",
                    "no Cargo.lock found; the first build will generate a path-form lock",
                ));
                None
            }
            Err(LockEditError::NotRegistry) if prior_path.is_some() => {
                // Re-vendor over live wiring (a patch update moved the
                // manifest to a new uuid): the prior socket-owned run already
                // detached this entry — source-less is exactly the shape we
                // produce. The lock is in the desired state; the true
                // pre-vendor originals live only in the ledger entry being
                // replaced, which the caller carries forward. Record nothing.
                None
            }
            Err(e) => {
                // Without the lock edit, `--locked` builds fail closed on the
                // [patch] we just wired — a half-vendored state. UNWIND the
                // config edit so the project is back where it started:
                // restore the prior socket-owned entry when this was a
                // re-vendor (dropping it would destroy the first run's live
                // wiring), else drop the entry we just added. Remove this
                // run's copy — unless the restored entry points at it, in
                // which case deleting it would dangle that entry and break
                // every build.
                match prior_path.as_deref() {
                    Some(p) => {
                        let _ =
                            cargo_config::ensure_patch_entry(project_root, name, p, false).await;
                    }
                    None => {
                        let _ = cargo_config::drop_patch_entry(project_root, name, false).await;
                    }
                }
                if !prior_points_here {
                    let _ = remove_tree(&uuid_dir).await;
                }
                prune_empty_vendor_dirs(&uuid_dir).await;
                result.success = false;
                result.error = Some(format!(
                    "failed to detach the Cargo.lock entry for {name}@{version}: {e} \
                     (the config edit was unwound and nothing new was vendored)"
                ));
                return done(result, None, warnings);
            }
        };

    // ── marker + ledger entry ─────────────────────────────────────────────
    let base_purl = strip_purl_qualifiers(purl).to_string();
    let marker = VendorMarker::new("cargo", &base_purl, record, vendored_at);
    if let Err(e) = write_marker(&uuid_dir, &marker).await {
        // The marker is belt-and-braces metadata (never a trust input); a
        // failed write must not undo a fully-wired vendor — surface it.
        warnings.push(VendorWarning::new(
            "marker_write_failed",
            format!("could not write the vendor marker: {e}"),
        ));
    }

    let mut wiring = vec![WiringRecord {
        file: ".cargo/config.toml".to_string(),
        kind: "cargo_patch_entry".to_string(),
        action: if prior_path.is_some() {
            WiringAction::Rewritten
        } else {
            WiringAction::Added
        },
        key: Some(name.to_string()),
        original: prior_path.map(serde_json::Value::from),
        new: Some(serde_json::Value::from(copy_rel.clone())),
    }];
    if let Some(orig) = &lock_original {
        wiring.push(WiringRecord {
            file: "Cargo.lock".to_string(),
            kind: "cargo_lock_entry".to_string(),
            action: WiringAction::Rewritten,
            key: Some(format!("{name}@{version}")),
            original: Some(serde_json::json!({
                "source": orig.source,
                "checksum": orig.checksum,
            })),
            new: None,
        });
    }

    let entry = VendorEntry {
        ecosystem: "cargo".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: copy_rel,
            sha256: String::new(), // dir-shaped: integrity is per-file afterHashes
            size: None,
            platform_locked: None,
            file_inventory: None,
        },
        wiring,
        lock: lock_original,
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

/// Revert one vendored cargo crate: restore the lock entry's original
/// `source`/`checksum`, drop the `[patch.crates-io]` entry, and remove the
/// uuid dir.
pub async fn revert_cargo_vendor(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    revert_cargo_vendor_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_cargo_vendor`] with full [`RevertOpts`]: `keep_artifact` skips
/// the artifact deletion while the wiring restore runs unchanged.
pub async fn revert_cargo_vendor_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    // SECURITY: the coordinates and uuid come from a committed, tamper-able
    // state.json and key a directory we are about to delete — re-validate
    // fail-closed before any disk access (mirrors the vendor-side guard).
    let Some((name, version)) = parse_cargo_purl(&entry.base_purl) else {
        return RevertOutcome::failed(format!("not a cargo purl: {}", entry.base_purl));
    };
    if !is_safe_single_segment(name) || !is_safe_single_segment(version) {
        return RevertOutcome::failed(format!(
            "refusing to revert unsafe cargo coordinates `{name}`/`{version}`"
        ));
    }
    let Some(base_rel) = vendor_uuid_dir_rel("cargo", &entry.uuid) else {
        return RevertOutcome::failed(format!(
            "refusing to revert: `{}` is not a canonical patch uuid",
            entry.uuid
        ));
    };

    let mut out = RevertOutcome::ok();

    if let Some(lock) = &entry.lock {
        match cargo_lock::restore_lock_entry(project_root, name, version, lock, dry_run).await {
            Ok(true) => {}
            Ok(false) => out.warnings.push(VendorWarning::new(
                "lock_restore_skipped",
                format!(
                    "the Cargo.lock entry for {name}@{version} is no longer in the \
                     detached form (re-resolved or removed); left as-is"
                ),
            )),
            Err(LockEditError::NoLockfile) => out.warnings.push(VendorWarning::new(
                "lock_restore_skipped",
                "Cargo.lock no longer exists; nothing to restore".to_string(),
            )),
            // Fail-closed on a corrupt/unwritable lock BEFORE touching the
            // config entry — a half-revert (entry dropped, lock still
            // path-form) would break every --locked build with no breadcrumb.
            Err(e) => {
                return RevertOutcome {
                    kept_artifact: false,
                    success: false,
                    warnings: out.warnings,
                    error: Some(format!("failed to restore the Cargo.lock entry: {e}")),
                }
            }
        }
    }

    if let Err(e) = cargo_config::drop_patch_entry(project_root, name, dry_run).await {
        return RevertOutcome {
            kept_artifact: false,
            success: false,
            warnings: out.warnings,
            error: Some(format!("failed to update .cargo/config.toml: {e}")),
        };
    }

    // `--preserve-state` (`keep_artifact`): the artifact dir stays behind
    // (and the caller keeps the ledger entry), so only the deletion is
    // skipped.
    if !dry_run && !keep_artifact {
        let uuid_dir = project_root.join(&base_rel);
        let _ = remove_tree(&uuid_dir).await; // ignore NotFound
                                              // Best-effort: prune the now-empty `.socket/vendor/cargo/` level so a
                                              // fully-reverted project carries no vendor residue (`save_state` then
                                              // prunes `.socket/vendor/` itself). `remove_dir` fails on non-empty.
        if let Some(eco_dir) = uuid_dir.parent() {
            let _ = tokio::fs::remove_dir(eco_dir).await;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::{PatchFileInfo, VulnerabilityInfo};
    use crate::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    /// A second canonical uuid, for re-vendor (patch update) scenarios.
    const UUID2: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
    const PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const PRISTINE: &[u8] = b"pub fn cfg() {}\n";
    const PATCHED: &[u8] = b"pub fn cfg() { /* patched */ }\n";
    const SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";
    const CHECKSUM: &str = "9d8f4e3bd2c8f1f5d1a3f5e7c9b1d3f5e7a9b1c3d5f7e9a1b3c5d7e9f1a3b5c7";

    fn git_sha(bytes: &[u8]) -> String {
        compute_git_sha256_from_bytes(bytes)
    }

    fn copy_rel() -> String {
        format!(".socket/vendor/cargo/{UUID}/cfg-if-1.0.4")
    }

    fn lock_body() -> String {
        format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\
             \n\
             [[package]]\n\
             name = \"app\"\n\
             version = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if\",\n]\n\
             \n\
             [[package]]\n\
             name = \"cfg-if\"\n\
             version = \"1.0.4\"\n\
             source = \"{SOURCE}\"\n\
             checksum = \"{CHECKSUM}\"\n"
        )
    }

    fn record_with(files: HashMap<String, PatchFileInfo>) -> PatchRecord {
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-xxxx-yyyy-zzzz".to_string(),
            VulnerabilityInfo {
                cves: vec!["CVE-2026-0001".into()],
                summary: "s".into(),
                severity: "high".into(),
                description: "d".into(),
            },
        );
        PatchRecord {
            uuid: UUID.into(),
            exported_at: "t".into(),
            files,
            vulnerabilities,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    /// Build a pristine registry-style crate dir (with a legacy checksum
    /// sidecar to prove the skip), a blobs dir carrying the patched bytes, and
    /// a consumer project (Cargo.toml + handwritten v4 Cargo.lock). Returns
    /// (project_tmp, blobs, pristine_src, record).
    async fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();

        let pristine = root.join("registry/cfg-if-1.0.4");
        tokio::fs::create_dir_all(pristine.join("src"))
            .await
            .unwrap();
        tokio::fs::write(pristine.join("src/lib.rs"), PRISTINE)
            .await
            .unwrap();
        tokio::fs::write(
            pristine.join("Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
        )
        .await
        .unwrap();
        // Older registry layouts carry this; the copy must skip it.
        tokio::fs::write(pristine.join(".cargo-checksum.json"), "{\"files\":{}}")
            .await
            .unwrap();

        let after = git_sha(PATCHED);
        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(&after), PATCHED).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "package/src/lib.rs".to_string(),
            PatchFileInfo {
                before_hash: git_sha(PRISTINE),
                after_hash: after,
            },
        );

        tokio::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n",
        )
        .await
        .unwrap();
        tokio::fs::write(root.join("Cargo.lock"), lock_body())
            .await
            .unwrap();

        (dir, blobs, pristine, record_with(files))
    }

    async fn run_vendor(
        purl: &str,
        root: &Path,
        blobs: &Path,
        pristine: &Path,
        record: &PatchRecord,
        dry_run: bool,
    ) -> VendorOutcome {
        let sources = PatchSources::blobs_only(blobs);
        vendor_cargo_crate(
            purl,
            pristine,
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

    fn expect_done(
        outcome: VendorOutcome,
    ) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        match outcome {
            VendorOutcome::Done {
                result,
                entry,
                warnings,
            } => (result, entry, warnings),
            VendorOutcome::Refused { code, detail } => {
                panic!("expected Done, got Refused({code}): {detail}")
            }
        }
    }

    fn expect_refused(outcome: VendorOutcome, want_code: &str) -> String {
        match outcome {
            VendorOutcome::Refused { code, detail } => {
                assert_eq!(code, want_code, "refusal code: {detail}");
                detail
            }
            VendorOutcome::Done { result, .. } => {
                panic!(
                    "expected Refused({want_code}), got Done (success={})",
                    result.success
                )
            }
        }
    }

    #[tokio::test]
    async fn test_happy_path_wires_copy_config_lock_and_marker() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // A qualified PURL must collapse to the base in the ledger/marker.
        let qualified = format!("{PURL}?repository_url=https://crates.io");
        let (result, entry, warnings) =
            expect_done(run_vendor(&qualified, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");

        // Copy holds the patched bytes and NO checksum sidecar.
        let copy = root.join(copy_rel());
        assert_eq!(
            tokio::fs::read(copy.join("src/lib.rs")).await.unwrap(),
            PATCHED
        );
        assert!(!copy.join(".cargo-checksum.json").exists());
        // The registry pristine is untouched.
        assert_eq!(
            tokio::fs::read(pristine.join("src/lib.rs")).await.unwrap(),
            PRISTINE
        );

        // Config entry points at the uuid-level copy.
        let entries = cargo_config::read_patch_entries(root).await;
        assert_eq!(entries["cfg-if"].path.as_deref(), Some(copy_rel().as_str()));

        // The lock entry is detached (source+checksum gone), rest preserved.
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(!lock.contains("source ="));
        assert!(!lock.contains("checksum ="));
        assert!(lock.contains("name = \"cfg-if\"\nversion = \"1.0.4\"\n"));

        // Marker sits in the uuid dir, carrying the vuln + uuid + base purl.
        let marker = tokio::fs::read_to_string(
            root.join(format!(".socket/vendor/cargo/{UUID}/{VENDOR_MARKER_FILE}")),
        )
        .await
        .unwrap();
        assert!(marker.contains(UUID));
        assert!(marker.contains("GHSA-xxxx-yyyy-zzzz"));
        assert!(
            marker.contains(&format!("\"purl\": \"{PURL}\"")),
            "{marker}"
        );

        // Ledger entry shape.
        let entry = entry.expect("entry on success");
        assert_eq!(entry.ecosystem, "cargo");
        assert_eq!(entry.base_purl, PURL, "qualifiers stripped");
        assert_eq!(entry.uuid, UUID);
        assert_eq!(entry.artifact.path, copy_rel());
        assert_eq!(entry.artifact.sha256, "", "dir-shaped artifact");
        assert_eq!(
            entry.lock,
            Some(CargoLockOriginal {
                source: SOURCE.into(),
                checksum: Some(CHECKSUM.into()),
            })
        );
        assert!(!entry.took_over_go_patches);
        assert_eq!(entry.wiring.len(), 2);
        let cfg = &entry.wiring[0];
        assert_eq!(
            (cfg.file.as_str(), cfg.kind.as_str()),
            (".cargo/config.toml", "cargo_patch_entry")
        );
        assert_eq!(cfg.action, WiringAction::Added);
        assert_eq!(cfg.key.as_deref(), Some("cfg-if"));
        assert_eq!(cfg.new, Some(serde_json::Value::from(copy_rel())));
        let lockw = &entry.wiring[1];
        assert_eq!(
            (lockw.file.as_str(), lockw.kind.as_str()),
            ("Cargo.lock", "cargo_lock_entry")
        );
        assert_eq!(lockw.action, WiringAction::Rewritten);
        assert_eq!(lockw.key.as_deref(), Some("cfg-if@1.0.4"));
        assert_eq!(
            lockw.original,
            Some(serde_json::json!({ "source": SOURCE, "checksum": CHECKSUM }))
        );
    }

    #[tokio::test]
    async fn test_refuses_locked_version_mismatch() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // Lock resolves a different version → the [patch] would be unused.
        tokio::fs::write(
            root.join("Cargo.lock"),
            format!("version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.5\"\nsource = \"{SOURCE}\"\n"),
        )
        .await
        .unwrap();
        let detail = expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "locked_version_mismatch",
        );
        assert!(
            detail.contains("1.0.5") && detail.contains("1.0.4"),
            "{detail}"
        );
        // Refused before any write.
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
        assert!(!root.join(".cargo").exists());

        // A crate absent from the lock entirely is equally refused. (A lock
        // with no [[package]] array at all reads as "no usable lock" and
        // skips the cross-check, so give it one unrelated package.)
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .await
        .unwrap();
        expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "locked_version_mismatch",
        );
    }

    #[tokio::test]
    async fn test_refuses_user_authored_patch_entry() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        let user_cfg = "[patch.crates-io]\ncfg-if = { path = \"../my-fork\" }\n";
        tokio::fs::write(root.join(".cargo/config.toml"), user_cfg)
            .await
            .unwrap();

        expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "user_authored_patch_entry",
        );
        // Nothing written: config byte-identical, no copy, lock untouched.
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            user_cfg
        );
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    #[tokio::test]
    async fn test_refuses_cargo_vendor_tree() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::create_dir_all(root.join("vendor/cfg-if-1.0.4"))
            .await
            .unwrap();
        expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "already_vendored_in_tree",
        );
        assert!(!root.join(".cargo").exists(), "refused before any write");
    }

    #[tokio::test]
    async fn test_no_lockfile_proceeds_with_warning() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::remove_file(root.join("Cargo.lock"))
            .await
            .unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            warnings.iter().any(|w| w.code == "no_lockfile"),
            "warnings: {warnings:?}"
        );
        let entry = entry.unwrap();
        assert_eq!(entry.lock, None, "nothing was detached");
        assert_eq!(entry.wiring.len(), 1, "only the config wire is recorded");
        // The copy + config still landed.
        assert!(root.join(copy_rel()).join("src/lib.rs").exists());
        assert!(cargo_config::read_patch_entries(root).await["cfg-if"].socket_owned);
    }

    #[tokio::test]
    async fn test_half_build_rolls_back_copy() {
        let (dir, _blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // Empty blobs dir → the blob read fails mid-apply.
        let empty = root.join(".socket/empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &empty, &pristine, &record, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            !root
                .join(format!(".socket/vendor/cargo/{UUID}"))
                .join("cfg-if-1.0.4")
                .exists(),
            "half-built copy must be rolled back"
        );
        // No config entry, lock untouched.
        assert!(cargo_config::read_patch_entries(root).await.is_empty());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// A failed FRESH vendor unwinds the whole `<uuid>/` dir with
    /// `remove_tree`, then prunes — the prune must still remove the empty
    /// `.socket/vendor/cargo/` and `.socket/vendor/` levels this run
    /// created (the module contract: "a hard failure leaves no husk for
    /// the user to commit"), even though the uuid level is already gone.
    #[tokio::test]
    async fn test_failed_fresh_vendor_leaves_no_vendor_husk() {
        let (dir, _blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // Empty blobs dir → the blob read fails mid-apply.
        let empty = root.join(".socket/empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &empty, &pristine, &record, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            !root.join(".socket/vendor").exists(),
            "the empty vendor levels created by the failed run must be pruned"
        );
    }

    /// Uses `mkfifo(2)` directly rather than shelling out to `mkfifo`: the
    /// same helper as the find.rs/detect.rs FIFO tests — fork/exec flakes
    /// under heavy parallel load and the syscall needs no process at all.
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

    /// A FIFO planted as the project `Cargo.toml` must not wedge the wet
    /// vendor run: everything ahead of `hosted_redirect_residue` reads only
    /// Cargo.lock / .cargo/config.toml, so a raw `read_to_string` open(2)
    /// of the manifest waits for a writer that never comes and hangs the
    /// vendor forever with no error and no timeout. Same class as the
    /// `open_regular_file` guards in the setup twins and the crawlers. The
    /// non-regular manifest must instead be skipped (no residue readable)
    /// and the vendor must complete.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_fifo_cargo_toml_does_not_wedge_vendor() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let manifest = root.join("Cargo.toml");
        tokio::fs::remove_file(&manifest).await.unwrap();
        mkfifo(&manifest);

        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(outcome) = tokio::time::timeout(
            deadline,
            run_vendor(PURL, root, &blobs, &pristine, &record, false),
        )
        .await
        else {
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&manifest);
            panic!("vendor must complete promptly with a FIFO Cargo.toml");
        };
        let (result, entry, _warnings) = expect_done(outcome);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/lib.rs"))
                .await
                .unwrap(),
            PATCHED
        );
    }

    #[tokio::test]
    async fn test_lock_detach_failure_unwinds_config_and_copy() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // The lock entry exists at the right version but is NOT registry-shaped
        // (no `source` — e.g. an existing user path-dep): pre-flight passes,
        // detach errs with NotRegistry AFTER the config write → must unwind.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
        )
        .await
        .unwrap();

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            result.error.as_deref().unwrap_or("").contains("Cargo.lock"),
            "error names the lock: {:?}",
            result.error
        );
        // Unwound: config entry gone (file pruned), copy gone, lock unchanged.
        assert!(cargo_config::read_patch_entries(root).await.is_empty());
        assert!(!root.join(copy_rel()).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n"
        );
    }

    /// AUDIT B1: a failed hot-path artifact rebuild must never destroy the
    /// live-wired vendored copy. Drift the committed copy (bad merge /
    /// formatter), then re-run with the patch content unavailable (empty
    /// blobs dir — the offline shape: a drifted file harvests no blob): the
    /// rebuild fails, but the previous — drifted yet buildable — copy, the
    /// marker, the config entry, and the detached lock must all be left
    /// exactly as they were. (Adapted from the audit probe
    /// `audit_failed_rebuild_deletes_wired_artifact`.)
    #[tokio::test]
    async fn test_failed_rebuild_preserves_live_wired_copy() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);

        let lib = root.join(copy_rel()).join("src/lib.rs");
        tokio::fs::write(&lib, b"drifted but buildable\n")
            .await
            .unwrap();
        let cfg1 = tokio::fs::read(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        let lock1 = tokio::fs::read(root.join("Cargo.lock")).await.unwrap();

        let empty = root.join(".socket/empty-blobs");
        tokio::fs::create_dir_all(&empty).await.unwrap();
        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &empty, &pristine, &record, false).await);
        assert!(!result.success, "rebuild must fail without patch content");
        assert!(entry.is_none());

        // The live-wired state is untouched: copy, marker, config, lock.
        assert_eq!(
            tokio::fs::read(&lib).await.unwrap(),
            b"drifted but buildable\n",
            "the previous committed copy must survive a failed rebuild"
        );
        assert!(
            root.join(format!(".socket/vendor/cargo/{UUID}/{VENDOR_MARKER_FILE}"))
                .exists(),
            "marker must survive"
        );
        assert_eq!(
            tokio::fs::read(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            cfg1,
            "config untouched"
        );
        assert_eq!(
            tokio::fs::read(root.join("Cargo.lock")).await.unwrap(),
            lock1,
            "lock untouched"
        );
        // And the failed rebuild's swap siblings never leak into the uuid dir.
        let uuid_dir = root.join(format!(".socket/vendor/cargo/{UUID}"));
        let mut rd = tokio::fs::read_dir(&uuid_dir).await.unwrap();
        while let Some(e) = rd.next_entry().await.unwrap() {
            let n = e.file_name().to_string_lossy().into_owned();
            assert!(!n.contains("socket-stage"), "stage litter: {n}");
            assert!(!n.contains("socket-old"), "backup litter: {n}");
        }
    }

    /// REVIEW must-fix (B1 follow-up): the swap itself must never leave less
    /// recoverable state than it started with. Force the stage rename to fail
    /// (stage absent — the same io::Error surface as a Windows file lock)
    /// with a live copy in place: the old copy must be restored
    /// byte-identical, with no backup parked beside it.
    #[tokio::test]
    async fn test_swap_failure_restores_previous_copy() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("cfg-if-1.0.4");
        tokio::fs::create_dir_all(copy.join("src")).await.unwrap();
        tokio::fs::write(copy.join("src/lib.rs"), b"live\n")
            .await
            .unwrap();

        let stage = stage_dir_for(&copy);
        assert!(
            swap_stage_into_place(&stage, &copy).await.is_err(),
            "swapping a missing stage must fail"
        );
        assert_eq!(
            tokio::fs::read(copy.join("src/lib.rs")).await.unwrap(),
            b"live\n",
            "the previous copy must be restored after a failed swap"
        );
        assert!(!backup_dir_for(&copy).exists(), "no parked backup litter");
    }

    /// A successful swap replaces the old copy with the stage and leaves
    /// neither a stage nor a parked backup behind — including when a stale
    /// backup from an earlier interrupted swap is already parked there.
    #[tokio::test]
    async fn test_swap_success_replaces_copy_without_litter() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("cfg-if-1.0.4");
        tokio::fs::create_dir_all(copy.join("src")).await.unwrap();
        tokio::fs::write(copy.join("src/lib.rs"), b"old\n")
            .await
            .unwrap();
        let stage = stage_dir_for(&copy);
        tokio::fs::create_dir_all(stage.join("src")).await.unwrap();
        tokio::fs::write(stage.join("src/lib.rs"), b"new\n")
            .await
            .unwrap();
        let stale_backup = backup_dir_for(&copy);
        tokio::fs::create_dir_all(&stale_backup).await.unwrap();
        tokio::fs::write(stale_backup.join("husk.rs"), b"stale\n")
            .await
            .unwrap();

        swap_stage_into_place(&stage, &copy).await.unwrap();
        assert_eq!(
            tokio::fs::read(copy.join("src/lib.rs")).await.unwrap(),
            b"new\n"
        );
        assert!(!stage.exists(), "stage consumed by the swap");
        assert!(!stale_backup.exists(), "backup removed after the swap");
    }

    /// First-time swap: no pre-existing copy to park. The stage still lands
    /// at the copy path.
    #[tokio::test]
    async fn test_swap_into_vacant_copy_path() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("cfg-if-1.0.4");
        let stage = stage_dir_for(&copy);
        tokio::fs::create_dir_all(&stage).await.unwrap();
        tokio::fs::write(stage.join("lib.rs"), b"new\n")
            .await
            .unwrap();

        swap_stage_into_place(&stage, &copy).await.unwrap();
        assert_eq!(
            tokio::fs::read(copy.join("lib.rs")).await.unwrap(),
            b"new\n"
        );
        assert!(!backup_dir_for(&copy).exists());
        assert!(!stage.exists());
    }

    /// AUDIT B1 (same destroy class, fresh path): when the pre-existing
    /// config entry already points at THIS copy (wiring out of sync only
    /// because the lock went corrupt post-vendor), a detach failure's unwind
    /// restores that entry — so the uuid dir it points at must survive, or
    /// the restored entry dangles and every build breaks.
    #[tokio::test]
    async fn test_detach_failure_keeps_copy_the_config_points_at() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        // The lock went corrupt post-vendor (the preflight cross-check
        // deliberately skips an unparseable lock).
        tokio::fs::write(root.join("Cargo.lock"), "not = = toml [[[")
            .await
            .unwrap();

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        // The restored prior entry still points at a live copy.
        assert_eq!(
            cargo_config::read_patch_entries(root).await["cfg-if"]
                .path
                .as_deref(),
            Some(copy_rel().as_str())
        );
        assert!(
            root.join(copy_rel()).join("src/lib.rs").exists(),
            "the copy the restored config entry points at must survive the unwind"
        );
    }

    /// AUDIT B2: a lock resolving the SAME name+version from multiple sources
    /// (registry + same-version git fork — a legal, cargo-generated shape)
    /// must be refused: consumers' `dependencies` arrays disambiguate those
    /// entries with full package-id strings, which detaching
    /// `source`/`checksum` dangles (real-cargo verified: the next
    /// `cargo build --locked` fails with "cannot update the lock file").
    #[tokio::test]
    async fn test_refuses_same_version_multi_source_lock() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let lock = format!(
            "version = 4\n\n\
             [[package]]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\n \"cfg-if 1.0.4 (registry+https://github.com/rust-lang/crates.io-index)\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\nchecksum = \"{CHECKSUM}\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"git+https://example.com/fork/cfg-if#abcdef\"\n"
        );
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();

        let detail = expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "locked_multi_source_conflict",
        );
        assert!(detail.contains("cfg-if"), "{detail}");
        // Refused before any write.
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
        assert!(!root.join(".cargo").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock,
            "the multi-source lock must be byte-identical after the refusal"
        );
    }

    /// AUDIT B4 (security_scratch_audit.rs REPRO 3): a user-authored entry
    /// whose path merely TRAVERSES a foreign checkout's
    /// `.socket/vendor/cargo/` is user-authored — vendor must refuse up
    /// front, never silently rewrite (or later delete) it.
    #[tokio::test]
    async fn test_refuses_user_entry_through_foreign_socket_dir() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        let user_cfg = format!(
            "[patch.crates-io]\ncfg-if = {{ path = \"../shared-fork/.socket/vendor/cargo/{UUID2}/cfg-if-1.0.4\" }}\n"
        );
        tokio::fs::write(root.join(".cargo/config.toml"), &user_cfg)
            .await
            .unwrap();

        expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "user_authored_patch_entry",
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join(".cargo/config.toml"))
                .await
                .unwrap(),
            user_cfg,
            "the user's entry must be byte-identical after the refusal"
        );
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    #[tokio::test]
    async fn test_in_sync_rerun_is_byte_stable() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);

        let copy = root.join(copy_rel()).join("src/lib.rs");
        let cfg = root.join(".cargo/config.toml");
        let lock = root.join("Cargo.lock");
        let copy1 = tokio::fs::read(&copy).await.unwrap();
        let cfg1 = tokio::fs::read(&cfg).await.unwrap();
        let lock1 = tokio::fs::read(&lock).await.unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success);
        assert!(
            result.files_patched.is_empty(),
            "in-sync re-run patches nothing"
        );
        assert!(
            entry.is_none(),
            "hot path must not emit a fresh entry (it would clobber the ledger's lock originals)"
        );
        assert!(warnings.is_empty());
        assert_eq!(
            tokio::fs::read(&copy).await.unwrap(),
            copy1,
            "copy unchanged"
        );
        assert_eq!(
            tokio::fs::read(&cfg).await.unwrap(),
            cfg1,
            "config unchanged"
        );
        assert_eq!(
            tokio::fs::read(&lock).await.unwrap(),
            lock1,
            "lock unchanged"
        );
    }

    /// Wired config+lock with a deleted committed copy: the artifact is
    /// rebuilt in place, config and lock stay byte-identical, no fresh entry.
    #[tokio::test]
    async fn test_wired_missing_copy_rebuilds_artifact_only() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);

        let copy = root.join(copy_rel()).join("src/lib.rs");
        let cfg = root.join(".cargo/config.toml");
        let lock = root.join("Cargo.lock");
        let copy1 = tokio::fs::read(&copy).await.unwrap();
        let cfg1 = tokio::fs::read(&cfg).await.unwrap();
        let lock1 = tokio::fs::read(&lock).await.unwrap();

        crate::patch::copy_tree::remove_tree(&root.join(copy_rel()))
            .await
            .unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            entry.is_none(),
            "artifact-only rebuild must not emit a fresh entry"
        );
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {warnings:?}"
        );
        assert_eq!(
            tokio::fs::read(&copy).await.unwrap(),
            copy1,
            "rebuilt copy carries the patched bytes"
        );
        assert!(
            !root.join(copy_rel()).join(".cargo-checksum.json").exists(),
            "no checksum sidecar in the rebuilt path-dep copy"
        );
        assert_eq!(
            tokio::fs::read(&cfg).await.unwrap(),
            cfg1,
            "config untouched"
        );
        assert_eq!(
            tokio::fs::read(&lock).await.unwrap(),
            lock1,
            "lock untouched"
        );
    }

    #[tokio::test]
    async fn test_dry_run_writes_nothing() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, true).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry-run emits no entry");
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
        assert!(!root.join(".cargo").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    #[tokio::test]
    async fn test_revert_round_trip_restores_everything() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(out.success, "{:?}", out.error);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);

        // Lock byte-identical to the pristine fixture.
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
        // Config entry gone — and the socket-created file + .cargo/ pruned.
        assert!(cargo_config::read_patch_entries(root).await.is_empty());
        assert!(!root.join(".cargo").exists());
        // The uuid dir is gone, and the empty eco level pruned with it.
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
        assert!(!root.join(".socket/vendor/cargo").exists());
    }

    #[tokio::test]
    async fn test_revert_warns_when_lock_re_resolved() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        // A third party re-resolved the lock (source back) after vendoring.
        tokio::fs::write(root.join("Cargo.lock"), lock_body())
            .await
            .unwrap();

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(out.success, "{:?}", out.error);
        assert!(
            out.warnings
                .iter()
                .any(|w| w.code == "lock_restore_skipped"),
            "{:?}",
            out.warnings
        );
        // The re-resolved lock is left alone, the rest still reverted.
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
    }

    #[tokio::test]
    async fn test_legacy_redirect_entry_is_taken_over() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // Residue from the retired redirect backend: a legacy-path entry.
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".cargo/config.toml"),
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.4\" }\n",
        )
        .await
        .unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            warnings.iter().any(|w| w.code == "vendor_takeover"),
            "legacy takeover surfaced: {warnings:?}"
        );
        let entry = entry.unwrap();
        let cfg = &entry.wiring[0];
        assert_eq!(cfg.action, WiringAction::Rewritten);
        assert_eq!(
            cfg.original,
            Some(serde_json::Value::from(
                ".socket/cargo-patches/cfg-if-1.0.4"
            ))
        );
        // The live entry now points at the vendor copy.
        assert_eq!(
            cargo_config::read_patch_entries(root).await["cfg-if"]
                .path
                .as_deref(),
            Some(copy_rel().as_str())
        );
    }

    // ── filesystem-safety: coordinate traversal ──────────────────────────

    /// SECURITY regression: a tampered manifest PURL with `..` in the crate
    /// name must NOT let vendor copy + write the patched tree outside
    /// `.socket/vendor/cargo/`.
    #[tokio::test]
    async fn test_refuses_traversal_coordinates() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let escaped = root.parent().unwrap().join("escape-1.0.0");
        let _ = remove_tree(&escaped).await;

        expect_refused(
            run_vendor(
                "pkg:cargo/../../../escape@1.0.0",
                root,
                &blobs,
                &pristine,
                &record,
                false,
            )
            .await,
            "unsafe_coordinates",
        );
        expect_refused(
            run_vendor(
                "pkg:cargo/cfg-if@../../../evil",
                root,
                &blobs,
                &pristine,
                &record,
                false,
            )
            .await,
            "unsafe_coordinates",
        );
        expect_refused(
            run_vendor(
                "pkg:npm/not-cargo@1.0.0",
                root,
                &blobs,
                &pristine,
                &record,
                false,
            )
            .await,
            "unsafe_coordinates",
        );
        assert!(!escaped.exists(), "no copy outside the project");
        assert!(!root.join(".cargo").exists(), "no wiring written");
        let _ = remove_tree(&escaped).await;
    }

    /// SECURITY regression: a poisoned uuid (`..`, uppercase, traversal) must
    /// be refused — it keys the on-disk dir vendor creates and revert deletes.
    #[tokio::test]
    async fn test_refuses_poisoned_uuid() {
        let (dir, blobs, pristine, mut record) = fixture().await;
        let root = dir.path();
        for bad in ["..", "../../../etc", "9F6B2C4E-1D3A-4F6B-8C2D-7E5A9B1C3D5F"] {
            record.uuid = bad.to_string();
            let detail = expect_refused(
                run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
                "unsafe_coordinates",
            );
            assert!(detail.contains("uuid"), "{detail}");
        }
        assert!(!root.join(".cargo").exists());
    }

    /// SECURITY regression: revert re-validates the (tamper-able) ledger entry
    /// fail-closed rather than `remove_tree`-ing a poisoned path.
    #[tokio::test]
    async fn test_revert_refuses_traversal_entry() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let good = entry.unwrap();

        let mut bad_uuid = good.clone();
        bad_uuid.uuid = "../../../precious".to_string();
        assert!(!revert_cargo_vendor(&bad_uuid, root, false).await.success);

        let mut bad_purl = good.clone();
        bad_purl.base_purl = "pkg:cargo/../../../escape@1.0.0".to_string();
        assert!(!revert_cargo_vendor(&bad_purl, root, false).await.success);

        // The refusals deleted nothing: the vendored state is fully intact.
        assert!(root.join(copy_rel()).exists());
        assert!(cargo_config::read_patch_entries(root).await["cfg-if"].socket_owned);
    }

    /// A patch update moves the manifest to a NEW uuid for the same crate.
    /// The CLI re-vendors straight over the first run's live wiring (see
    /// `persist_vendor_entry`: originals are carried forward and the old
    /// uuid dir swept afterwards — there is no revert-first). The lock is
    /// already in the detached shape from the first run, so the re-vendor
    /// must accept it as the desired state and succeed — never fail and
    /// unwind the live config entry (which bricks every build: no `[patch]`
    /// entry left, source-less lock entry).
    #[tokio::test]
    async fn test_revendor_new_uuid_over_live_wiring_succeeds() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let lock_detached = tokio::fs::read(root.join("Cargo.lock")).await.unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.into();
        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record2, false).await);
        assert!(result.success, "re-vendor must succeed: {:?}", result.error);

        // The config entry is repointed at the new uuid's copy.
        let new_rel = format!(".socket/vendor/cargo/{UUID2}/cfg-if-1.0.4");
        assert_eq!(
            cargo_config::read_patch_entries(root).await["cfg-if"]
                .path
                .as_deref(),
            Some(new_rel.as_str())
        );
        // The new copy carries the patched bytes; the old uuid dir is left
        // for the caller's stale-artifact sweep (the caller owns the ledger).
        assert_eq!(
            tokio::fs::read(root.join(&new_rel).join("src/lib.rs"))
                .await
                .unwrap(),
            PATCHED
        );
        assert!(root.join(copy_rel()).exists());
        // The already-detached lock is untouched.
        assert_eq!(
            tokio::fs::read(root.join("Cargo.lock")).await.unwrap(),
            lock_detached
        );
        // A fresh entry is emitted for the ledger. This run edited no lock,
        // so it records no originals — the true pre-vendor source/checksum
        // live only in the entry being replaced (the caller carries them
        // forward).
        let entry = entry.expect("re-vendor emits the new ledger entry");
        assert_eq!(entry.uuid, UUID2);
        assert_eq!(entry.artifact.path, new_rel);
        assert_eq!(entry.lock, None);
    }

    /// When the lock-detach step fails mid-re-vendor (here: the lock went
    /// corrupt, which the pre-flight cross-check deliberately skips), the
    /// unwind must put the PRIOR socket-owned config entry back — dropping
    /// it would destroy the first vendor's live wiring.
    #[tokio::test]
    async fn test_detach_failure_unwind_restores_prior_socket_entry() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);

        tokio::fs::write(root.join("Cargo.lock"), "not = = toml [[[")
            .await
            .unwrap();

        let mut record2 = record.clone();
        record2.uuid = UUID2.into();
        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record2, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        // The prior entry is restored, not dropped; the new uuid dir is gone.
        assert_eq!(
            cargo_config::read_patch_entries(root).await["cfg-if"]
                .path
                .as_deref(),
            Some(copy_rel().as_str()),
            "unwind must restore the pre-existing socket entry"
        );
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID2}")).exists());
        assert!(
            root.join(copy_rel()).exists(),
            "first vendor's copy untouched"
        );
    }

    /// Deleting the WHOLE uuid dir (not just the copy leaf) loses the
    /// committed marker; the artifact-only rebuild must restore it alongside
    /// the copy (as the golang backend does), or the re-committed vendor
    /// unit is incomplete.
    #[tokio::test]
    async fn test_wired_deleted_uuid_dir_rebuild_restores_marker() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        remove_tree(&root.join(format!(".socket/vendor/cargo/{UUID}")))
            .await
            .unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none());
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{warnings:?}"
        );
        assert_eq!(
            tokio::fs::read(root.join(copy_rel()).join("src/lib.rs"))
                .await
                .unwrap(),
            PATCHED
        );
        let marker = root.join(format!(".socket/vendor/cargo/{UUID}/{VENDOR_MARKER_FILE}"));
        assert!(
            marker.exists(),
            "rebuild must restore the committed marker file"
        );
    }

    #[tokio::test]
    async fn test_empty_files_is_noop() {
        let (dir, blobs, pristine, mut record) = fixture().await;
        let root = dir.path();
        record.files = HashMap::new();
        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success);
        assert!(entry.is_none());
        assert!(warnings.is_empty());
        assert!(!root.join(".cargo").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    // ─────────────── service-download path (Tier B: cargo) ───────────────
    //
    // cargo vendors a patched source DIRECTORY, so the service path downloads
    // the prebuilt `.crate`, verifies it, and extracts it into the copy dir.
    // Both the service path AND the local-build fallback are exercised.

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

    fn cargo_service_cfg(uri: &str, source: VendorSource, offline: bool) -> VendorServiceConfig {
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

    /// Build a `.crate` (tar.gz with a single `{prefix}/` top-level dir).
    fn make_crate_tgz(prefix: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut builder = tar::Builder::new(Vec::new());
        for (rel, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("{prefix}/{rel}"), *content)
                .unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap()
    }

    async fn mount_cargo_granted(server: &wiremock::MockServer, sha512: &str, crate_bytes: &[u8]) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let serve_path = format!("/patch/cargo/cfg-if/1.0.4/tok/{UUID}/cfg-if-1.0.4.crate");
        let serve_url = format!("{}{serve_path}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
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
            .respond_with(ResponseTemplate::new(200).set_body_bytes(crate_bytes.to_vec()))
            .mount(server)
            .await;
    }

    async fn mount_cargo_status(server: &wiremock::MockServer, status: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: { "status": status, "url": null, "artifacts": [] } }
            })))
            .mount(server)
            .await;
    }

    fn copy_lib(root: &Path) -> PathBuf {
        root.join(format!(
            ".socket/vendor/cargo/{UUID}/cfg-if-1.0.4/src/lib.rs"
        ))
    }

    /// Service success: the prebuilt crate is extracted into the copy dir (with
    /// the patched content, no checksum sidecar), the config is wired, and a
    /// `vendor_prebuilt_downloaded` advisory is emitted — WITHOUT touching the
    /// pristine source (a deliberately-missing path).
    #[tokio::test]
    async fn service_success_extracts_crate_and_wires_config() {
        let (dir, blobs, _pristine, record) = fixture().await;
        let root = dir.path();
        let crate_tgz = make_crate_tgz(
            "cfg-if-1.0.4",
            &[
                ("src/lib.rs", PATCHED),
                (
                    "Cargo.toml",
                    b"[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
                ),
                (".cargo-checksum.json", b"{\"files\":{}}"),
            ],
        );
        let sri = sri_sha512(&crate_tgz);
        let server = wiremock::MockServer::start().await;
        mount_cargo_granted(&server, &sri, &crate_tgz).await;
        let sources = PatchSources::blobs_only(&blobs);

        // A deliberately-missing pristine source: the service path must not need it.
        let bogus_pristine = root.join("no-such-pristine");
        let outcome = vendor_cargo_crate(
            PURL,
            &bogus_pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let (result, entry, warnings) = expect_done(outcome);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
        assert!(
            !root
                .join(format!(
                    ".socket/vendor/cargo/{UUID}/cfg-if-1.0.4/.cargo-checksum.json"
                ))
                .exists(),
            "path-dep copy must not carry a checksum sidecar"
        );
        let cfg = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        assert!(
            cfg.contains("[patch.crates-io]") && cfg.contains("cfg-if"),
            "{cfg}"
        );
        assert!(warnings
            .iter()
            .any(|w| w.code == "vendor_prebuilt_downloaded"));
    }

    /// `service` mode + integrity mismatch hard-fails, nothing extracted.
    #[tokio::test]
    async fn service_integrity_mismatch_service_mode_hard_fails() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let crate_tgz = make_crate_tgz("cfg-if-1.0.4", &[("src/lib.rs", PATCHED)]);
        let wrong = sri_sha512(b"different bytes");
        let server = wiremock::MockServer::start().await;
        mount_cargo_granted(&server, &wrong, &crate_tgz).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        expect_refused(outcome, "vendor_prebuilt_integrity_mismatch");
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
    }

    /// AUDIT B3: bytes that fail integrity verification are an active tamper
    /// signal — the DEFAULT `auto` mode must hard-fail exactly like `service`
    /// mode, never quietly warn and build locally (the module contract:
    /// "IntegrityMismatch → ALWAYS a hard error regardless of mode").
    #[tokio::test]
    async fn service_integrity_mismatch_auto_mode_hard_fails() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let crate_tgz = make_crate_tgz("cfg-if-1.0.4", &[("src/lib.rs", PATCHED)]);
        let wrong = sri_sha512(b"different bytes");
        let server = wiremock::MockServer::start().await;
        mount_cargo_granted(&server, &wrong, &crate_tgz).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        expect_refused(outcome, "vendor_prebuilt_integrity_mismatch");
        assert!(
            !copy_lib(root).exists(),
            "must not fall back to a local build on tampered bytes"
        );
        assert!(!root.join(".socket/vendor").exists(), "no vendor debris");
        assert!(!root.join(".cargo").exists(), "nothing wired");
    }

    /// AUDIT B5: the service-mode layout-mismatch hard failure must not leave
    /// an empty `.socket/vendor/cargo/<uuid>/` husk (nor the vendor parents
    /// this run created) behind for the user to commit.
    #[tokio::test]
    async fn service_layout_mismatch_service_mode_leaves_no_husk() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // The crate extracts fine but carries the patched file at the wrong
        // path → the extracted-tree afterHash check fails.
        let crate_tgz = make_crate_tgz("cfg-if-1.0.4", &[("src/other.rs", PATCHED)]);
        let sri = sri_sha512(&crate_tgz);
        let server = wiremock::MockServer::start().await;
        mount_cargo_granted(&server, &sri, &crate_tgz).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        expect_refused(outcome, "vendor_prebuilt_required");
        assert!(
            !root.join(format!(".socket/vendor/cargo/{UUID}")).exists(),
            "no empty uuid husk after the hard failure"
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "the vendor levels created by this failed run are pruned"
        );
        assert!(!root.join(".cargo").exists());
    }

    /// `auto` + a not-built service status falls back to the local build (which
    /// copies the pristine source + patches it).
    #[tokio::test]
    async fn service_unavailable_auto_falls_back_to_build() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_cargo_status(&server, "not_found").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let (result, entry, _) = expect_done(outcome);
        assert!(
            result.success,
            "auto must fall back to the local build: {:?}",
            result.error
        );
        assert!(entry.is_some());
        // The locally-built copy has the patched content.
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
    }

    /// `--offline` + `--vendor-source=service` refuses without any network.
    #[tokio::test]
    async fn offline_service_mode_refuses() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                "http://127.0.0.1:1",
                VendorSource::Service,
                true,
            )),
        )
        .await;
        expect_refused(outcome, "vendor_service_offline_conflict");
    }

    // ── cross-mode takeover: in-use probe + fail-closed hosted guard ─────

    fn ledger_entry_for(uuid: &str) -> VendorEntry {
        VendorEntry {
            ecosystem: "cargo".into(),
            base_purl: PURL.into(),
            uuid: uuid.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/cargo/{uuid}/cfg-if-1.0.4"),
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

    /// The lockfile-in-use probe for cargo (GC/prune reclaim): detached lock
    /// + our `[patch]` = in use; a registry source (hosted takeover or a
    /// crates.io re-resolve), a missing entry, or a foreign `[patch]` target
    /// = reclaimable; no lock = undeterminable (keep, fail-safe).
    #[tokio::test]
    async fn test_vendored_entry_in_use_probe() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let entry_probe = ledger_entry_for(UUID);

        // No lockfile: undeterminable.
        tokio::fs::remove_file(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert_eq!(vendored_entry_in_use(&entry_probe, root).await, None);
        tokio::fs::write(root.join("Cargo.lock"), lock_body())
            .await
            .unwrap();

        // Registry-sourced (pre-vendor / re-resolved): not consumed.
        assert_eq!(vendored_entry_in_use(&entry_probe, root).await, Some(false));

        // Fully vendored: detached lock + our [patch] entry ⇒ in use.
        let (result, entry, _w) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(vendored_entry_in_use(&entry, root).await, Some(true));

        // Hosted takeover shape: the lock re-sourced to a socket-patch sparse
        // index (the [patch] entry survives, but nothing consumes the copy).
        tokio::fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"sparse+http://127.0.0.1:5555/index/\"\nchecksum = \"{}\"\n",
                "a".repeat(64)
            ),
        )
        .await
        .unwrap();
        assert_eq!(vendored_entry_in_use(&entry, root).await, Some(false));

        // Dependency left the lock graph entirely: reclaimable.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n",
        )
        .await
        .unwrap();
        assert_eq!(vendored_entry_in_use(&entry, root).await, Some(false));

        // Detached lock but the [patch] points at ANOTHER uuid's copy: this
        // entry's artifact is not what the lock consumes.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
        )
        .await
        .unwrap();
        assert_eq!(
            vendored_entry_in_use(&ledger_entry_for(UUID2), root).await,
            Some(false)
        );
    }

    /// FAIL CLOSED: vendoring over a LIVE hosted redirect with no ledger to
    /// revert it must refuse — proceeding would record the hosted registry
    /// values as the entry's "originals" and leave Cargo.toml pinned to the
    /// hosted registry (unbuildable in both modes) while reporting success.
    #[tokio::test]
    async fn test_refuses_live_hosted_redirect_without_ledger() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let index = "sparse+http://127.0.0.1:5555/index/";
        // The hosted rewriter's output shapes: registry pin in Cargo.toml,
        // socket-patch registries block, lock re-sourced to the index.
        tokio::fs::write(
            root.join("Cargo.toml"),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = {{ version = \"1\", registry = \"socket-patch-{UUID}\" }}\n"
            ),
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".cargo/config.toml"),
            format!("[registries.socket-patch-{UUID}]\nindex = \"{index}\"\n"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{index}\"\nchecksum = \"{}\"\n",
                "a".repeat(64)
            ),
        )
        .await
        .unwrap();

        let detail = expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "hosted_redirect_live",
        );
        assert!(detail.contains("redirect-state.json"), "{detail}");
        // Nothing was half-vendored.
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());

        // The Cargo.toml pin ALONE (lock already detached — the legacy
        // hosted→vendored terminal state) is refused too: the in-sync hot
        // path must not report already_vendored over a broken manifest pin.
        tokio::fs::write(
            root.join("Cargo.lock"),
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
        )
        .await
        .unwrap();
        expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "hosted_redirect_live",
        );
    }

    // ── service status arms: pending / unavailable / failed ──────────────

    /// `auto` + a still-building service artifact falls back to the local
    /// build with a `vendor_prebuilt_pending` advisory explaining why.
    #[tokio::test]
    async fn service_pending_auto_falls_back_with_warning() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_cargo_status(&server, "pending_build").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let (result, entry, warnings) = expect_done(outcome);
        assert!(
            result.success,
            "auto must fall back to the local build: {:?}",
            result.error
        );
        assert!(entry.is_some());
        // The locally-built copy has the patched content.
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
        let w = warnings
            .iter()
            .find(|w| w.code == "vendor_prebuilt_pending")
            .unwrap_or_else(|| panic!("missing pending warning: {warnings:?}"));
        assert!(w.detail.contains("still building"), "{}", w.detail);
        assert!(
            w.detail.ends_with("; building locally instead"),
            "{}",
            w.detail
        );
    }

    /// `service` mode + a still-building artifact hard-fails (no local-build
    /// fallback), writing nothing.
    #[tokio::test]
    async fn service_pending_service_mode_hard_fails() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_cargo_status(&server, "pending_build").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let detail = expect_refused(outcome, "vendor_prebuilt_required");
        assert!(detail.contains("still building"), "{detail}");
        assert!(!root.join(".socket/vendor").exists(), "no vendor debris");
        assert!(!root.join(".cargo").exists(), "nothing wired");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// `service` mode + a not-built artifact (`not_found`) hard-fails with
    /// the unavailable reason — the required-mode twin of the covered `auto`
    /// silent fallback.
    #[tokio::test]
    async fn service_unavailable_service_mode_hard_fails() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_cargo_status(&server, "not_found").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let detail = expect_refused(outcome, "vendor_prebuilt_required");
        assert!(
            detail.contains("prebuilt crate unavailable: not_found"),
            "{detail}"
        );
        assert!(!root.join(".socket/vendor").exists(), "no vendor debris");
        assert!(!root.join(".cargo").exists(), "nothing wired");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// `auto` + a request-level service failure (`forbidden` →
    /// `ServiceArtifact::Failed`) falls back to the local build with a
    /// `vendor_prebuilt_unavailable` advisory.
    #[tokio::test]
    async fn service_failed_auto_falls_back_with_warning() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let server = wiremock::MockServer::start().await;
        mount_cargo_status(&server, "forbidden").await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let (result, entry, warnings) = expect_done(outcome);
        assert!(
            result.success,
            "auto must fall back to the local build: {:?}",
            result.error
        );
        assert!(entry.is_some());
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
        let w = warnings
            .iter()
            .find(|w| w.code == "vendor_prebuilt_unavailable")
            .unwrap_or_else(|| panic!("missing unavailable warning: {warnings:?}"));
        assert!(
            w.detail.contains("patch service request failed"),
            "{}",
            w.detail
        );
        assert!(
            w.detail.ends_with("; building locally instead"),
            "{}",
            w.detail
        );
    }

    /// A downloaded archive that PASSES SRI verification but is not a valid
    /// tar.gz hard-fails (`vendor_prebuilt_extract_failed`) in every mode —
    /// and the failed run leaves no vendor husk, wiring, or lock edit behind.
    #[tokio::test]
    async fn service_corrupt_archive_extract_hard_fails() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let bytes: &[u8] = b"definitely not a tar.gz";
        let server = wiremock::MockServer::start().await;
        mount_cargo_granted(&server, &sri_sha512(bytes), bytes).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let detail = expect_refused(outcome, "vendor_prebuilt_extract_failed");
        assert!(
            detail.contains("cannot extract the prebuilt crate"),
            "{detail}"
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "the vendor levels created by this failed run are pruned"
        );
        assert!(!root.join(".cargo").exists(), "nothing wired");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// A granted service artifact whose stage dir cannot be created (a
    /// regular FILE squatting the `<uuid>` dir path) hard-fails with
    /// `vendor_prebuilt_write_failed` ("cannot create"), touching neither the
    /// config nor the lock.
    #[tokio::test]
    async fn service_stage_create_failure_hard_fails() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // A FILE at the uuid-dir path makes `create_dir_all(&stage)` fail
        // (the preceding remove_tree(&stage) error is discarded).
        tokio::fs::create_dir_all(root.join(".socket/vendor/cargo"))
            .await
            .unwrap();
        tokio::fs::write(root.join(format!(".socket/vendor/cargo/{UUID}")), b"squat")
            .await
            .unwrap();
        // A fully valid granted crate, so the run reaches the stage step.
        let crate_tgz = make_crate_tgz("cfg-if-1.0.4", &[("src/lib.rs", PATCHED)]);
        let sri = sri_sha512(&crate_tgz);
        let server = wiremock::MockServer::start().await;
        mount_cargo_granted(&server, &sri, &crate_tgz).await;
        let sources = PatchSources::blobs_only(&blobs);

        let outcome = vendor_cargo_crate(
            PURL,
            &pristine,
            root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cargo_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let detail = expect_refused(outcome, "vendor_prebuilt_write_failed");
        assert!(detail.contains("cannot create"), "{detail}");
        assert!(!root.join(".cargo").exists(), "nothing wired");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    // ── local-build + wiring error paths ──────────────────────────────────

    /// A missing pristine source (the crawler's pkg_path was deleted between
    /// scan and vendor, no service configured) fails cleanly: a synthesized
    /// "failed to copy pristine source" result and a full unwind — no vendor
    /// husk, no wiring, lock untouched.
    #[tokio::test]
    async fn local_build_missing_pristine_fails_cleanly() {
        let (dir, blobs, _pristine, record) = fixture().await;
        let root = dir.path();
        let bogus_pristine = root.join("no-such-pristine");

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &bogus_pristine, &record, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to copy pristine source"),
            "error names the copy step: {:?}",
            result.error
        );
        assert_eq!(
            result.package_path,
            root.join(copy_rel()).display().to_string(),
            "the synthesized result reports the copy path"
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "the vendor levels created by this failed run are pruned"
        );
        assert!(!root.join(".cargo").exists(), "nothing wired");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// `ensure_patch_entry` failure after a successful local build (a
    /// DIRECTORY squatting `.cargo/config.toml`: the guarded read errs
    /// InvalidInput while the preflight `read_patch_entries` degrades to
    /// empty, so the run proceeds all the way to the config write) unwinds
    /// the copy and prunes the husks; the lock is never touched.
    #[tokio::test]
    async fn config_write_failure_unwinds_copy() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        // NOTE: not `.cargo/config` (extensionless) — config_path would
        // resolve there instead of erroring on the squatted config.toml.
        tokio::fs::create_dir_all(root.join(".cargo/config.toml"))
            .await
            .unwrap();

        let (result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to update .cargo/config.toml"),
            "error names the config: {:?}",
            result.error
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "the copy is unwound and the husks pruned"
        );
        assert!(
            tokio::fs::metadata(root.join(".cargo/config.toml"))
                .await
                .unwrap()
                .is_dir(),
            "the squatting directory is left alone"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body(),
            "the detach never ran"
        );
    }

    /// A failed marker write on a FRESH vendor (a directory squatting the
    /// marker path makes the atomic rename fail) must not undo the
    /// fully-wired vendor: success + a `marker_write_failed` warning, with
    /// copy, config, and lock all wired.
    #[tokio::test]
    async fn marker_write_failure_warns_but_vendor_succeeds() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::create_dir_all(root.join(format!(
            ".socket/vendor/cargo/{UUID}/{VENDOR_MARKER_FILE}"
        )))
        .await
        .unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "the wired vendor still emits its entry");
        assert!(
            warnings.iter().any(|w| w.code == "marker_write_failed"),
            "the failed marker write is surfaced: {warnings:?}"
        );
        // The vendor is otherwise fully wired.
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
        assert_eq!(
            cargo_config::read_patch_entries(root).await["cfg-if"]
                .path
                .as_deref(),
            Some(copy_rel().as_str())
        );
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(!lock.contains("source ="), "lock detached");
    }

    // ── revert failure arms ───────────────────────────────────────────────

    /// Revert re-validates the (tamper-able) ledger entry's purl fail-closed:
    /// a non-cargo purl is refused before any disk access.
    #[tokio::test]
    async fn test_revert_refuses_non_cargo_purl() {
        let (dir, _blobs, _pristine, _record) = fixture().await;
        let root = dir.path();
        let mut entry = ledger_entry_for(UUID);
        entry.base_purl = "pkg:npm/not-cargo@1.0.0".into();

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(!out.success);
        assert!(
            out.error.as_deref().unwrap_or("").contains("not a cargo purl"),
            "{:?}",
            out.error
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body(),
            "the refusal touched nothing"
        );
    }

    /// Revert with recorded lock originals but a DELETED Cargo.lock warns
    /// (`lock_restore_skipped` / "no longer exists" — distinct from the
    /// re-resolved twin) and still completes the config + artifact revert.
    #[tokio::test]
    async fn test_revert_warns_when_lock_deleted() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        tokio::fs::remove_file(root.join("Cargo.lock"))
            .await
            .unwrap();

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(out.success, "{:?}", out.error);
        let w = out
            .warnings
            .iter()
            .find(|w| w.code == "lock_restore_skipped")
            .unwrap_or_else(|| panic!("missing skip warning: {:?}", out.warnings));
        assert!(w.detail.contains("no longer exists"), "{}", w.detail);
        // The rest still reverted: config entry gone, uuid dir gone.
        assert!(cargo_config::read_patch_entries(root).await.is_empty());
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
    }

    /// Revert fails CLOSED on a corrupt lock BEFORE touching the config
    /// entry — a half-revert (entry dropped, lock still path-form) would
    /// break every `--locked` build with no breadcrumb.
    #[tokio::test]
    async fn test_revert_corrupt_lock_fails_closed() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        tokio::fs::write(root.join("Cargo.lock"), "not = = toml [[[")
            .await
            .unwrap();

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(!out.success);
        assert!(
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("failed to restore the Cargo.lock entry"),
            "{:?}",
            out.error
        );
        // Fail-closed: the config entry and the artifact both survive.
        assert_eq!(
            cargo_config::read_patch_entries(root).await["cfg-if"]
                .path
                .as_deref(),
            Some(copy_rel().as_str()),
            "the config entry must not be dropped on a failed lock restore"
        );
        assert!(
            root.join(copy_rel()).exists(),
            "the artifact must survive a failed revert"
        );
    }

    /// Revert `drop_patch_entry` failure (a directory squatting the config
    /// path) reports "failed to update .cargo/config.toml" and leaves the
    /// artifact in place (deletion is last). The lock was already restored
    /// when this fails — documenting the lock-then-config order: a re-run
    /// recovers, with the restore degrading to an Ok(false) skip.
    #[tokio::test]
    async fn test_revert_config_drop_failure_reports_error() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        tokio::fs::remove_file(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join(".cargo/config.toml"))
            .await
            .unwrap();

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(!out.success);
        assert!(
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("failed to update .cargo/config.toml"),
            "{:?}",
            out.error
        );
        // The lock restore ran FIRST and stuck: byte-identical originals.
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body(),
            "the lock is restored before the config edit"
        );
        assert!(
            root.join(copy_rel()).exists(),
            "artifact untouched — its deletion comes after the config edit"
        );
    }

    // ── swap_stage_into_place unit edges ──────────────────────────────────

    /// A failed stage rename with NO pre-existing copy parked (had_old =
    /// false skips the backup restore): the error propagates and no backup
    /// is fabricated.
    #[tokio::test]
    async fn test_swap_missing_stage_and_vacant_copy_errors() {
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("cfg-if-1.0.4");
        let err = swap_stage_into_place(&stage_dir_for(&copy), &copy)
            .await
            .expect_err("swapping a missing stage into a vacant copy must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(
            !backup_dir_for(&copy).exists(),
            "no fabricated backup litter"
        );
        assert!(!copy.exists(), "no fabricated copy");
    }

    /// A park rename (copy → backup) that fails with a non-NotFound error
    /// (EACCES: read-only parent) must propagate WITHOUT touching the old
    /// copy — it is never moved, and no backup appears.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_swap_park_failure_propagates_and_keeps_old_copy() {
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits — the trigger cannot fire
        }
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("uuid");
        let copy = parent.join("cfg-if-1.0.4");
        tokio::fs::create_dir_all(copy.join("src")).await.unwrap();
        tokio::fs::write(copy.join("src/lib.rs"), b"live\n")
            .await
            .unwrap();
        let stage = stage_dir_for(&copy);
        tokio::fs::create_dir_all(&stage).await.unwrap();
        tokio::fs::write(stage.join("lib.rs"), b"new\n")
            .await
            .unwrap();

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555)).unwrap();
        let swapped = swap_stage_into_place(&stage, &copy).await;
        // Restore before any assert so the tempdir can always be cleaned up.
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(swapped.is_err(), "the park rename failure must propagate");
        assert_eq!(
            tokio::fs::read(copy.join("src/lib.rs")).await.unwrap(),
            b"live\n",
            "the old copy is never moved"
        );
        assert!(!backup_dir_for(&copy).exists(), "no parked backup");
        assert!(stage.exists(), "the stage is left for the caller's cleanup");
    }
}
