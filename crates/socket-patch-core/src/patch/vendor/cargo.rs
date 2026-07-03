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
    already_patched_verify, copy_matches_after_hashes, refused, synthesized_result,
};
use super::path::vendor_uuid_dir_rel;
use super::registry_fetch::extract_tgz;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::{
    write_marker, CargoLockOriginal, VendorArtifact, VendorEntry, VendorMarker, WiringAction,
    WiringRecord,
};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

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

fn done(
    result: ApplyResult,
    entry: Option<VendorEntry>,
    warnings: Vec<VendorWarning>,
) -> VendorOutcome {
    VendorOutcome::Done {
        result,
        entry,
        warnings,
    }
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
    match fetch_verified_archive(cfg, &record.uuid, name).await {
        ServiceArtifact::Ready(archive) => {
            // Clean copy dir, then extract the `.crate` (tar.gz; strip its
            // single `{name}-{version}/` top-level dir) into it.
            let _ = remove_tree(copy_dir).await;
            if let Err(e) = tokio::fs::create_dir_all(copy_dir).await {
                return hard(
                    "vendor_prebuilt_write_failed",
                    format!("cannot create {}: {e}", copy_dir.display()),
                );
            }
            if let Err(e) = extract_tgz(&archive.bytes, copy_dir) {
                let _ = remove_tree(uuid_dir).await;
                return hard(
                    "vendor_prebuilt_extract_failed",
                    format!("cannot extract the prebuilt crate: {e}"),
                );
            }
            let _ = tokio::fs::remove_file(copy_dir.join(".cargo-checksum.json")).await;
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {name} from the patch service ({})",
                    archive.source_url
                ),
            ));
            CargoServiceCopy::Used
        }
        ServiceArtifact::IntegrityMismatch(reason) => miss(
            warnings,
            "vendor_prebuilt_integrity_mismatch",
            format!("prebuilt crate failed integrity ({reason})"),
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

/// Copy the pristine source into `copy_dir` and run the hardened apply
/// pipeline against it (vendor auto-force policy — see
/// [`super::force_apply_staged`]). On failure the whole uuid dir is removed —
/// a partial copy (or an empty `<uuid>/` husk) under `.socket/vendor/` would
/// be misjudged by verify/sweep — and the failed [`ApplyResult`] is the `Err`
/// for the caller to bubble. On success the copy carries no
/// `.cargo-checksum.json` (a path-dep copy must never have one; the fresh
/// copy excludes it, and it is re-removed defensively in case the patch
/// recreated it).
#[allow(clippy::too_many_arguments)]
async fn copy_and_patch(
    purl: &str,
    pristine_src: &Path,
    copy_dir: &Path,
    uuid_dir: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    force: bool,
    name: &str,
    version: &str,
    warnings: &mut Vec<VendorWarning>,
) -> Result<ApplyResult, ApplyResult> {
    if let Err(e) = fresh_copy(pristine_src, copy_dir, Some(".cargo-checksum.json")).await {
        let _ = remove_tree(uuid_dir).await;
        return Err(synthesized_result(
            purl,
            copy_dir,
            Vec::new(),
            false,
            Some(format!("failed to copy pristine source: {e}")),
        ));
    }
    let mut result = super::force_apply_staged(
        purl, copy_dir, record, sources, false, force, name, version, warnings,
    )
    .await;
    result.package_path = copy_dir.display().to_string();
    if !result.success {
        let _ = remove_tree(uuid_dir).await;
        return Err(result);
    }
    let _ = tokio::fs::remove_file(copy_dir.join(".cargo-checksum.json")).await;
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

    // Hot path: already in sync → touch nothing (entry stays with the caller's
    // existing ledger record, which holds the unrecoverable lock originals).
    if wiring_in_sync(project_root, name, version, &copy_rel).await {
        if copy_matches_after_hashes(&copy_dir, &record.files).await {
            let verified = record
                .files
                .keys()
                .map(|f| already_patched_verify(f))
                .collect();
            return done(
                synthesized_result(purl, &copy_dir, verified, true, None),
                None,
                Vec::new(),
            );
        }
        // Wired but the committed copy is missing/stale: rebuild the
        // ARTIFACT only — config + lock are already correct, and the full
        // path's surgery would re-record live vendored state over the
        // first run's unrecoverable lock originals.
        let mut warnings: Vec<VendorWarning> = Vec::new();
        let result = match copy_and_patch(
            purl,
            pristine_src,
            &copy_dir,
            &uuid_dir,
            record,
            sources,
            force,
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
        return done(result, None, warnings);
    }

    // ── materialise the patched copy ──────────────────────────────────────
    // Prefer the prebuilt `.crate` from the patch service (download + extract,
    // no pristine source needed); else copy the pristine source and patch it
    // (`copy_and_patch`). Either way a path-dep copy must never carry a
    // `.cargo-checksum.json` (cargo 1.93 src dirs no longer have one, but
    // older layouts do and its presence would re-enable checksum fixups).
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if let Some(cfg) = service {
        if cfg.source.requires_service() && cfg.offline {
            return refused(
                "vendor_service_offline_conflict",
                "--vendor-source=service needs the network but --offline is set",
            );
        }
    }
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
            let verified = record
                .files
                .keys()
                .map(|f| already_patched_verify(f))
                .collect();
            synthesized_result(purl, &copy_dir, verified, true, None)
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
        // unwired artifact lingers under .socket/vendor/.
        let _ = remove_tree(&uuid_dir).await;
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
            Err(e) => {
                // Without the lock edit, `--locked` builds fail closed on the
                // [patch] we just wired — a half-vendored state. UNWIND the
                // config entry + copy so the project is back where it started.
                let _ = cargo_config::drop_patch_entry(project_root, name, false).await;
                let _ = remove_tree(&uuid_dir).await;
                result.success = false;
                result.error = Some(format!(
                    "failed to detach the Cargo.lock entry for {name}@{version}: {e} \
                     (config entry and copy were unwound; nothing was vendored)"
                ));
                return done(result, None, warnings);
            }
        };

    // ── marker + ledger entry ─────────────────────────────────────────────
    let base_purl = strip_purl_qualifiers(purl).to_string();
    let mut vulnerabilities: Vec<String> = record.vulnerabilities.keys().cloned().collect();
    vulnerabilities.sort();
    let marker = VendorMarker {
        schema_version: 1,
        purl: base_purl.clone(),
        patch_uuid: record.uuid.clone(),
        ecosystem: "cargo".to_string(),
        vulnerabilities,
        vendored_at: vendored_at.to_string(),
    };
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
                    success: false,
                    warnings: out.warnings,
                    error: Some(format!("failed to restore the Cargo.lock entry: {e}")),
                }
            }
        }
    }

    if let Err(e) = cargo_config::drop_patch_entry(project_root, name, dry_run).await {
        return RevertOutcome {
            success: false,
            warnings: out.warnings,
            error: Some(format!("failed to update .cargo/config.toml: {e}")),
        };
    }

    if !dry_run {
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
    use crate::patch::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
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
    use crate::patch::vendor::{VendorServiceConfig, VendorSource};

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
        expect_refused(outcome, "vendor_prebuilt_required");
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
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
}
