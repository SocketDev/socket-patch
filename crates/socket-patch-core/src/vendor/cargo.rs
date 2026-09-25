//! The cargo vendor backend: committable `[patch.crates-io]` vendoring.
//!
//! Materialises a patched copy of the crate under
//! `.socket/vendor/cargo/<patch-uuid>/<name>-<version>/`, points cargo at it
//! with a `[patch.crates-io]` path entry in the workspace-root `Cargo.toml`
//! ([`super::cargo_manifest`]), and surgically detaches the crate's
//! `Cargo.lock` entry from the registry ([`super::cargo_lock`]) — without the
//! lock edit, `cargo build --locked` fails closed on the un-relocked `[patch]`
//! (spike-verified; the whole wiring is proven offline-from-Socket on a fresh
//! checkout with an empty `CARGO_HOME` — `spikes/PHASE0-FINDINGS.txt`).
//!
//! The copy's own `Cargo.toml` version is TAGGED `<version>+socket.<uuid>`
//! ([`super::cargo_tag`]) and the detached lock entry carries the same
//! tagged version — the lock cargo itself writes for the tagged copy — so
//! `Cargo.lock` alone names the patch uuid of the copy that builds. Copies
//! and locks vendored before tagged versions (or tagged for a previous
//! uuid) are (re)tagged by the next re-run or `repair`.
//!
//! Pre-v5 releases wrote the same entry to `.cargo/config.toml` (or the
//! legacy `.cargo/config`); a re-run over that wiring moves it into the
//! manifest (`cargo_wiring_migrated`), and every revert removes both
//! spellings ([`super::cargo_config`] owns the legacy reader and cleanup).
//!
//! The copy is produced by **delegating to the hardened
//! [`apply_package_patch`] pipeline** pointed at the fresh copy, so all the
//! verify → package/diff/blob → atomic-write machinery is reused unchanged.

use std::path::{Path, PathBuf};

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::path_safety::is_safe_single_segment;
use crate::utils::fs::{is_symlink, read_regular_to_string};
use crate::utils::purl::{parse_cargo_purl, strip_purl_qualifiers};

use super::cargo_config;
use super::cargo_lock::{self, LockEditError};
use super::cargo_manifest;
use super::cargo_tag;
use super::common::{
    already_patched_result, copy_matches_after_hashes, done, prune_empty_vendor_levels,
    refuse_symlinked, refused, service_offline_conflict, stage_dir_for, swap_stage_into_place,
    synthesized_result,
};
use super::path::vendor_uuid_dir_rel;
use super::registry_fetch::extract_tgz;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::{
    write_marker_or_warn, CargoLockOriginal, VendorArtifact, VendorEntry, VendorMarker,
    WiringAction, WiringRecord, VENDOR_MARKER_FILE,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// The cargo release where a project may vendor TWO versions of one crate.
///
/// Cargo before 1.45 resolves every source-less `Cargo.lock` entry of a
/// crate through a single `[patch.crates-io]` path — the entry whose KEY
/// sorts last — so with two vendored versions one of the two lock entries
/// is pinned to the other version's copy. It fails closed
/// (``patch for `<crate>` … did not resolve to any crates`` under
/// `--locked`, with or without `--offline` and with or without a populated
/// crates.io index), and which of the two orders happens to work is an
/// accident of the patch uuids. Measured on one two-version fixture, both
/// key orders, `cargo check --locked --offline` from an empty CARGO_HOME:
/// 1.41.1, 1.42, 1.43 and 1.44 refuse the adversarial order; 1.45, 1.49,
/// 1.53, 1.56 and current stable resolve either order, each lock entry to
/// its own copy.
const MULTI_VERSION_CARGO_MINOR: u32 = 45;

/// The lowest cargo minor this project TELLS us it must build on, read
/// offline from the project itself: the workspace root's `rust-version`
/// (`[package]`, else `[workspace.package]`), else `rust-toolchain.toml`'s
/// `[toolchain] channel`, else the legacy plain-text `rust-toolchain` file.
///
/// `None` when the project declares nothing, or pins a rolling channel
/// (`stable`, `nightly`, …) — socket-patch never runs `cargo`, so there is
/// no other signal, and "no declaration" is NOT evidence of a modern cargo.
async fn declared_cargo_minor(project_root: &Path) -> Option<u32> {
    fn minor_of(spec: &str) -> Option<u32> {
        let spec = spec.trim().trim_matches('"');
        let rest = spec.strip_prefix("1.")?;
        rest.split(['.', '-', '+']).next()?.parse().ok()
    }
    if let Ok(text) = read_regular_to_string(&project_root.join(cargo_manifest::CARGO_TOML)).await {
        if let Ok(doc) = text.parse::<toml_edit::DocumentMut>() {
            let rust_version = doc
                .get("package")
                .and_then(|p| p.get("rust-version"))
                .or_else(|| {
                    doc.get("workspace")
                        .and_then(|w| w.get("package"))
                        .and_then(|p| p.get("rust-version"))
                })
                .and_then(|v| v.as_str())
                .and_then(minor_of);
            if rust_version.is_some() {
                return rust_version;
            }
        }
    }
    if let Ok(text) = read_regular_to_string(&project_root.join("rust-toolchain.toml")).await {
        if let Ok(doc) = text.parse::<toml_edit::DocumentMut>() {
            if let Some(channel) = doc
                .get("toolchain")
                .and_then(|t| t.get("channel"))
                .and_then(|v| v.as_str())
            {
                return minor_of(channel);
            }
        }
    }
    // The legacy file is a bare channel name, but rustup also accepts the
    // TOML form under this name.
    if let Ok(text) = read_regular_to_string(&project_root.join("rust-toolchain")).await {
        if let Ok(doc) = text.parse::<toml_edit::DocumentMut>() {
            if let Some(channel) = doc
                .get("toolchain")
                .and_then(|t| t.get("channel"))
                .and_then(|v| v.as_str())
            {
                return minor_of(channel);
            }
        }
        return minor_of(&text);
    }
    None
}

/// A warning when THIS vendor puts a SECOND version of `name` behind
/// `[patch.crates-io]` in a project that may be built by a cargo older than
/// [`MULTI_VERSION_CARGO_MINOR`] — `None` when the crate has only this one
/// vendored version, or the project declares a new enough cargo.
///
/// `other` is another vendored version's copy path (for the message).
async fn multi_version_warning(
    project_root: &Path,
    name: &str,
    version: &str,
) -> Option<VendorWarning> {
    let other = socket_patch_paths(project_root, name)
        .await
        .into_iter()
        .find(|p| !cargo_manifest::is_socket_copy_of(p, name, version))?;
    let declared = declared_cargo_minor(project_root).await;
    if declared.is_some_and(|m| m >= MULTI_VERSION_CARGO_MINOR) {
        return None;
    }
    let says = match declared {
        Some(m) => format!("this project pins cargo 1.{m}"),
        None => "this project declares no `rust-version` or toolchain, so the cargo \
                 that builds it is unknown"
            .to_string(),
    };
    Some(VendorWarning::new(
        "cargo_multi_version_old_cargo",
        format!(
            "{name} is now vendored at TWO versions ({version} beside {other}), which needs \
             cargo {MULTI_VERSION_CARGO_MINOR_SPELLED} or newer — {says}. Older cargo resolves \
             every source-less Cargo.lock entry for a crate through ONE `[patch.crates-io]` \
             path (the entry whose key sorts last), so one of the two versions is pinned to the \
             other's copy and `cargo build --locked` fails closed with `patch for `{name}` … \
             did not resolve to any crates` — a populated crates.io index does not help. Build \
             with cargo {MULTI_VERSION_CARGO_MINOR_SPELLED}+, or vendor only one version of \
             {name}.",
            MULTI_VERSION_CARGO_MINOR_SPELLED = format_args!("1.{MULTI_VERSION_CARGO_MINOR}"),
        ),
    ))
}

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

/// Is this vendored cargo entry still consumed by the project's `Cargo.lock`
/// dependency graph? The lock is the truth source:
///
/// * entry absent from the lock → `Some(false)` (the dependency left the
///   graph; the `[patch]` would be unused);
/// * entry carries a registry `source` (crates.io re-resolve or a hosted
///   socket-patch takeover) → `Some(false)` — the committed copy is NOT what
///   the lock consumes, so GC may reclaim the entry (its revert restores /
///   keeps the registry resolution and drops the dead `[patch]` wiring);
/// * entry detached (tagged for any uuid, or untagged — vendored before
///   tagged versions) AND a Socket-owned `[patch.crates-io]` entry (root
///   manifest, or a legacy project-config one) points at THIS entry's
///   committed copy → `Some(true)` (the wired vendored shape). A lock tag
///   for ANOTHER uuid is then only stale (a checkout/merge of the lock from
///   another patch generation): cargo re-locks any unlocked build to this
///   copy, and the vendor hot path retags it — reclaiming the entry would
///   leave the stale tag with no provider and silently build pristine
///   crates.io bytes;
/// * detached but the `[patch]` points elsewhere / is gone → `Some(false)`
///   (nothing consumes the copy — a lock tagged for another uuid builds
///   that generation's copy; the revert re-attaches the recorded registry
///   originals, repairing the half-wired lock);
/// * no readable lock → `None` (cannot determine — callers keep, fail-safe).
pub async fn vendored_entry_in_use(entry: &VendorEntry, project_root: &Path) -> Option<bool> {
    let (name, version) = parse_cargo_purl(&entry.base_purl)?;
    let (name, version) = (name.as_ref(), version.as_ref());
    match cargo_lock::probe_lock_entry_for(project_root, name, version, Some(&entry.uuid)).await {
        cargo_lock::LockEntryProbe::NoLockfile | cargo_lock::LockEntryProbe::Unreadable => None,
        cargo_lock::LockEntryProbe::EntryMissing => Some(false),
        cargo_lock::LockEntryProbe::Source(_) => Some(false),
        cargo_lock::LockEntryProbe::Detached(_) => {
            let marker = vendor_uuid_dir_rel("cargo", &entry.uuid)?;
            let wired = socket_patch_paths(project_root, name)
                .await
                .iter()
                .any(|p| {
                    cargo_manifest::normalize_socket_path(p)
                        .is_some_and(|n| n.starts_with(&format!("{marker}/")))
                });
            Some(wired)
        }
    }
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
        // The rewriter's own reader, not a single-line regex: the hosted pin
        // is just as often a standalone `registry = …` line under a
        // `[dependencies.<crate>]` header, or sits under a renamed key
        // (`legacy = { package = "<crate>", … }`) — shapes a
        // `<name> = { … }` regex reads as "not redirected", which is exactly
        // the half-reverted state this guard exists for.
        if let Some(reg) = crate::patch::redirect::cargo_socket_registry_pin(&toml, name) {
            return Some(format!(
                "Cargo.toml pins `{name}` to the socket-patch hosted registry `{reg}`"
            ));
        }
    }
    None
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
    prune_empty_vendor_levels(uuid_dir).await;
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
    version: &str,
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
            // The copy's version carries the patch uuid tag, written in the
            // stage so a swapped-in copy is never untagged.
            if let Err(e) = cargo_tag::tag_copy_manifest(&stage, version, &record.uuid).await {
                cleanup_failed_stage(&stage, uuid_dir, false).await;
                return miss(
                    warnings,
                    "vendor_prebuilt_layout_mismatch",
                    format!("prebuilt crate for {name}: cannot tag its version ({e})"),
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
/// defensively in case the patch recreated it) and its `Cargo.toml` version
/// is tagged for the patch uuid.
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
    // Tag the copy's version in the stage (after the patch applied, so the
    // patch pipeline verified the untagged bytes).
    if let Err(e) = cargo_tag::tag_copy_manifest(&stage, version, &record.uuid).await {
        cleanup_failed_stage(&stage, uuid_dir, unwind_uuid_dir).await;
        result.success = false;
        result.error = Some(format!("{COPY_UNTAGGABLE}: {e}"));
        return Err(result);
    }
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
    let (name, version) = (name.as_ref(), version.as_ref());
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
    // (c) The wiring lives in the workspace-root Cargo.toml: it must be a
    // readable, parseable regular file — and not a symlink, which the
    // atomic rewrite would replace with a detached copy (leaving the
    // link's target unwired and the revert unable to restore the link).
    if let Err((code, detail)) = refuse_symlinked(
        project_root,
        &[cargo_manifest::CARGO_TOML],
        "cargo_manifest_symlink_unsupported",
    )
    .await
    {
        return refused(code, detail);
    }
    let manifest_doc = match cargo_manifest::read_manifest(project_root).await {
        Ok(text) => match cargo_manifest::parse_manifest(&text) {
            Ok(doc) => doc,
            Err(e) => return refused(e.code(), e.detail().to_string()),
        },
        Err(e) => {
            return refused(
                e.code(),
                format!(
                    "{}; the vendored `[patch.crates-io]` entry is written to the \
                     workspace-root Cargo.toml",
                    e.detail()
                ),
            )
        }
    };
    // (c2) Cargo only honours `[patch]` in the workspace-root manifest, and
    // a `[patch."<crates.io URL>"]` table there replaces `[patch.crates-io]`
    // wholesale: either way the entry would be silently ignored.
    if let Err(e) = cargo_manifest::check_source_alias(&manifest_doc) {
        return refused(e.code(), e.detail().to_string());
    }
    if let Some(detail) = workspace_root_refusal(project_root, &manifest_doc).await {
        return refused(NOT_WORKSPACE_ROOT, detail);
    }
    let manifest_entries = cargo_manifest::crates_io_patch_entries(&manifest_doc);
    // (d) A user-authored crates.io `[patch]` entry — in the manifest or any
    // config file cargo merges (project, ancestor directories,
    // `$CARGO_HOME`) — that overrides, or may override, this crate@version
    // is never shadowed or overwritten.
    let chain = cargo_config::read_config_chain(project_root).await;
    if let Some(detail) =
        user_patch_conflict(project_root, &manifest_entries, &chain, name, version).await
    {
        return refused("user_authored_patch_entry", detail);
    }

    let copy_rel = format!("{base_rel}/{name}-{version}");
    let uuid_dir = project_root.join(&base_rel);
    let copy_dir = project_root.join(&copy_rel);

    // The Socket-owned wiring already in place for THIS crate@version: the
    // manifest entry (v5) and any legacy project-config entries (pre-v5),
    // which this run migrates into the manifest.
    let prior_manifest_entry = manifest_entries
        .iter()
        .find(|e| e.source == "crates-io" && cargo_manifest::entry_wires(e, name, version));
    let prior_manifest_path: Option<String> = prior_manifest_entry
        .and_then(|e| e.path.as_deref())
        .and_then(cargo_manifest::normalize_socket_path);
    let legacy_paths: Vec<String> = cargo_config::legacy_socket_entries(project_root, name)
        .await
        .into_iter()
        .filter(|(_, p)| cargo_manifest::is_socket_copy_of(p, name, version))
        .filter_map(|(_, p)| cargo_manifest::normalize_socket_path(&p))
        .collect();
    let reserved = reserved_config_keys(&chain, name, version);
    // The existing entry's key must still be Socket-owned and unused by any
    // config file (cargo lets a config item with the same key replace it);
    // otherwise even an in-sync re-run moves it to a fresh key.
    let prior_key_ok = prior_manifest_entry
        .is_some_and(|e| cargo_manifest::is_socket_key(&e.key, name) && !reserved.contains(&e.key));
    // A copy of THIS crate@version committed by an earlier Socket run (any
    // uuid) while no wiring points at it: a pre-v5 project whose config
    // `[patch]` key a second vendored version overwrote. Its lock entry is
    // already detached — exactly the shape this run produces.
    let prior_socket_copy = socket_copy_present(project_root, name, version).await;

    // Wiring (manifest or legacy config) already points at THIS copy.
    let points_here = prior_manifest_path.as_deref() == Some(copy_rel.as_str())
        || legacy_paths.contains(&copy_rel);

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
        // manifest/config/lock.
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
        if !legacy_paths.is_empty() {
            dry_warnings.push(migration_warning(project_root, name, version, true).await);
        }
        if let Some(w) = multi_version_warning(project_root, name, version).await {
            dry_warnings.push(w);
        }
        // Preview the wet run's lock edit — unless a live hosted redirect
        // still owns the lock entry: the wet run reverts it from the
        // redirect ledger first, so its lock is not this one.
        if hosted_redirect_residue(project_root, name, version)
            .await
            .is_none()
        {
            let (lock_probe, refusal) =
                lock_tag_preflight(project_root, name, version, &record.uuid).await;
            if let Some(refusal) = refusal {
                return refusal;
            }
            // The hot path (re)tags a copy + detached lock vendored before
            // tagged versions (or for another uuid): say so, and prove the
            // copy takes the tag. A missing / stale copy is rebuilt tagged
            // by the wet run, so only its lock retag is previewed.
            if points_here
                && matches!(
                    lock_probe,
                    cargo_lock::LockEntryProbe::Detached(_)
                        | cargo_lock::LockEntryProbe::NoLockfile
                )
            {
                let would_tag = if cargo_copy_matches(&copy_dir, &record.files).await {
                    tag_vendored_copy(
                        project_root,
                        name,
                        version,
                        &record.uuid,
                        &copy_dir,
                        false,
                        true,
                    )
                    .await
                } else {
                    Ok(matches!(
                        &lock_probe,
                        cargo_lock::LockEntryProbe::Detached(tag)
                            if tag.as_deref() != Some(record.uuid.as_str())
                    ))
                };
                match would_tag {
                    Ok(true) => dry_warnings.push(tag_warning(name, version, &record.uuid, true)),
                    Ok(false) => {}
                    Err(e) => {
                        result.success = false;
                        result.error = Some(e);
                    }
                }
            }
        }
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

    let (lock_probe, lock_refusal) =
        lock_tag_preflight(project_root, name, version, &record.uuid).await;
    if let Some(refusal) = lock_refusal {
        return refusal;
    }

    // Hot path: the wiring points here and the lock entry needs no detach
    // (no lockfile — the first build writes a path-form lock — or already
    // sourceless). Touch nothing but the artifact and the version tag; a
    // legacy-only wiring is migrated, a missing/stale tag re-applied.
    if points_here
        && matches!(
            lock_probe,
            cargo_lock::LockEntryProbe::Detached(_) | cargo_lock::LockEntryProbe::NoLockfile
        )
    {
        let mut warnings: Vec<VendorWarning> = Vec::new();
        let mut rebuilt = false;
        let result = if cargo_copy_matches(&copy_dir, &record.files).await {
            already_patched_result(purl, &copy_dir, &record.files)
        } else {
            // Wired but the committed copy is missing/stale: rebuild the
            // ARTIFACT only — the wiring + lock are already correct, and the
            // full path's surgery would re-record live vendored state over
            // the first run's unrecoverable lock originals. The rebuild is
            // staged: a failure must leave the previous (drifted-but-
            // buildable) copy and the live wiring exactly as they were,
            // never a deleted copy under a still-pointing `[patch]` entry.
            // Service-preferred like the full path, so
            // `--vendor-source=service` never quietly builds locally.
            if let Some(refusal) = service_offline_conflict(service) {
                return refusal;
            }
            rebuilt = true;
            let result = match cargo_service_copy(
                service,
                record,
                name,
                version,
                &copy_dir,
                &uuid_dir,
                &mut warnings,
            )
            .await
            {
                CargoServiceCopy::Used => already_patched_result(purl, &copy_dir, &record.files),
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
                        false, // live-wired: never unwind the uuid dir on failure
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
            warnings.push(VendorWarning::new(
                "vendor_artifact_rebuilt",
                format!(
                    "the committed vendored copy for {name}@{version} was missing or stale; \
                     rebuilt at {copy_rel} (wiring and lock untouched)"
                ),
            ));
            // The rebuild may have recreated the whole uuid dir (deleted
            // wholesale, marker included): restore the committed marker
            // alongside the copy so the re-committed vendor unit is
            // complete. Only when missing — a copy-only rebuild keeps the
            // original marker (and its vendoredAt).
            if tokio::fs::metadata(uuid_dir.join(VENDOR_MARKER_FILE))
                .await
                .is_err()
            {
                let marker =
                    VendorMarker::new("cargo", strip_purl_qualifiers(purl), record, vendored_at);
                write_marker_or_warn(&uuid_dir, &marker, &mut warnings).await;
            }
            result
        };
        let mut result = result;
        let tagged = match tag_vendored_copy(
            project_root,
            name,
            version,
            &record.uuid,
            &copy_dir,
            rebuilt,
            false,
        )
        .await
        {
            Ok(tagged) => tagged,
            Err(e) => {
                result.success = false;
                result.error = Some(e);
                return done(result, None, warnings);
            }
        };
        if tagged {
            warnings.push(tag_warning(name, version, &record.uuid, false));
        }
        if prior_manifest_path.as_deref() == Some(copy_rel.as_str())
            && legacy_paths.is_empty()
            && prior_key_ok
            && !tagged
        {
            // In sync: the entry stays with the caller's existing ledger
            // record, which holds the unrecoverable lock originals.
            return done(result, None, warnings);
        }
        // Migration (legacy config → manifest), a manifest entry moving off
        // a key a config file now shadows, or a (re)tag: a fresh entry
        // naming the manifest wiring; the caller carries the lock originals
        // forward from the entry it replaces (`carry_forward_wiring`).
        let ensured = match cargo_manifest::ensure_patch_entry(
            project_root,
            name,
            version,
            &record.uuid,
            &copy_rel,
            &reserved,
            false,
        )
        .await
        {
            Ok(ensured) => ensured,
            Err(e) => {
                result.success = false;
                result.error = Some(format!(
                    "failed to move the vendored wiring into Cargo.toml: {e} (the legacy \
                     .cargo/config wiring was left in place)"
                ));
                return done(result, None, warnings);
            }
        };
        if let Err(e) =
            retire_legacy_wiring(project_root, name, version, &legacy_paths, &mut warnings).await
        {
            let prior = ensured.prior_path.as_deref();
            unwind_manifest(project_root, name, version, &record.uuid, prior, &reserved).await;
            result.success = false;
            result.error = Some(legacy_kept_error(name, version, &e));
            return done(result, None, warnings);
        }
        let entry = cargo_entry(purl, record, &copy_rel, &ensured, None);
        return done(result, Some(entry), warnings);
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
    // When pre-existing wiring already points at THIS copy (out of sync
    // only because of the lock — e.g. it was re-resolved or went corrupt
    // post-vendor), a failure must not delete the copy that wiring points
    // at: the unwind restores the entry, and removing the uuid dir would
    // dangle it and break every build.
    // Likewise a copy an earlier Socket run committed at this very path (the
    // pre-v5 overwrite shape): the ledger still references it.
    let prior_points_here = points_here
        || tokio::fs::metadata(&copy_dir)
            .await
            .is_ok_and(|m| m.is_dir());
    let mut result = match cargo_service_copy(
        service,
        record,
        name,
        version,
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

    // ── wire the manifest entry ───────────────────────────────────────────
    let ensured = match cargo_manifest::ensure_patch_entry(
        project_root,
        name,
        version,
        &record.uuid,
        &copy_rel,
        &reserved,
        false,
    )
    .await
    {
        Ok(ensured) => ensured,
        Err(e) => {
            // The manifest was left untouched; unwind the copy so no unwired
            // artifact lingers under .socket/vendor/ — unless existing wiring
            // points at this very copy, which deleting would dangle.
            if !prior_points_here {
                let _ = remove_tree(&uuid_dir).await;
            }
            prune_empty_vendor_levels(&uuid_dir).await;
            result.success = false;
            result.error = Some(format!("failed to update Cargo.toml: {e}"));
            return done(result, None, warnings);
        }
    };
    let had_prior_wiring =
        ensured.prior_path.is_some() || !legacy_paths.is_empty() || prior_socket_copy;
    if let Some(w) = multi_version_warning(project_root, name, version).await {
        warnings.push(w);
    }

    // ── detach (and tag) the lock entry ───────────────────────────────────
    // `retagged_from`: the version a retag replaced, for the unwind.
    let mut retagged_from: Option<String> = None;
    let lock_original: Option<CargoLockOriginal> =
        match cargo_lock::detach_lock_entry(project_root, name, version, &record.uuid, false).await
        {
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
            Err(LockEditError::NotRegistry) if had_prior_wiring => {
                // Re-vendor over live wiring (a patch update moved the
                // manifest to a new uuid, or a legacy config wiring is being
                // migrated), or over a committed Socket copy whose wiring a
                // pre-v5 second-version vendor overwrote: the prior
                // socket-owned run already detached this entry — source-less
                // is exactly the shape we produce, once retagged for this
                // uuid. The true pre-vendor originals live only in the
                // ledger entry being replaced, which the caller carries
                // forward.
                match cargo_lock::retag_lock_entry(project_root, name, version, &record.uuid, false)
                    .await
                {
                    Ok(prev) => {
                        retagged_from = prev;
                        None
                    }
                    Err(e) => {
                        let prior = ensured.prior_path.as_deref();
                        unwind_manifest(
                            project_root,
                            name,
                            version,
                            &record.uuid,
                            prior,
                            &reserved,
                        )
                        .await;
                        if !prior_points_here {
                            let _ = remove_tree(&uuid_dir).await;
                        }
                        prune_empty_vendor_levels(&uuid_dir).await;
                        result.success = false;
                        result.error = Some(format!(
                            "failed to retag the Cargo.lock entry for {name}@{version}: {e} \
                             (the Cargo.toml edit was unwound and nothing new was vendored)"
                        ));
                        return done(result, None, warnings);
                    }
                }
            }
            Err(e) => {
                // Without the lock edit, `--locked` builds fail closed on the
                // [patch] we just wired — a half-vendored state. UNWIND the
                // manifest edit: restore the prior socket-owned entry when
                // this was a re-vendor (dropping it would destroy the first
                // run's live wiring), else drop the entry we just added.
                // Remove this run's copy — unless restored wiring points at
                // it, in which case deleting it would dangle that entry.
                let prior = ensured.prior_path.as_deref();
                unwind_manifest(project_root, name, version, &record.uuid, prior, &reserved).await;
                if !prior_points_here {
                    let _ = remove_tree(&uuid_dir).await;
                }
                prune_empty_vendor_levels(&uuid_dir).await;
                result.success = false;
                result.error = Some(format!(
                    "failed to detach the Cargo.lock entry for {name}@{version}: {e} \
                     (the Cargo.toml edit was unwound and nothing new was vendored)"
                ));
                return done(result, None, warnings);
            }
        };

    // ── retire the legacy config wiring (migration) ───────────────────────
    // A legacy entry that cannot be removed would keep pointing at its copy
    // — which the caller's stale sweep deletes on a uuid bump — and would
    // double-wire the crate beside the manifest entry: unwind everything.
    if let Err(e) =
        retire_legacy_wiring(project_root, name, version, &legacy_paths, &mut warnings).await
    {
        if let Some(orig) = &lock_original {
            let _ = cargo_lock::restore_lock_entry(
                project_root,
                name,
                version,
                &record.uuid,
                orig,
                false,
            )
            .await;
        }
        if let Some(prev) = &retagged_from {
            let _ = cargo_lock::retag_lock_entry_to(project_root, name, version, prev, false).await;
        }
        let prior = ensured.prior_path.as_deref();
        unwind_manifest(project_root, name, version, &record.uuid, prior, &reserved).await;
        if !prior_points_here {
            let _ = remove_tree(&uuid_dir).await;
        }
        prune_empty_vendor_levels(&uuid_dir).await;
        result.success = false;
        result.error = Some(legacy_kept_error(name, version, &e));
        return done(result, None, warnings);
    }

    // ── marker + ledger entry ─────────────────────────────────────────────
    let marker = VendorMarker::new("cargo", strip_purl_qualifiers(purl), record, vendored_at);
    write_marker_or_warn(&uuid_dir, &marker, &mut warnings).await;

    let entry = cargo_entry(purl, record, &copy_rel, &ensured, lock_original);
    done(result, Some(entry), warnings)
}

/// The ledger entry for a wired cargo vendor: the manifest `[patch]` record
/// plus, when this run detached the lock, the lock record and originals.
fn cargo_entry(
    purl: &str,
    record: &PatchRecord,
    copy_rel: &str,
    ensured: &cargo_manifest::Ensured,
    lock_original: Option<CargoLockOriginal>,
) -> VendorEntry {
    let base_purl = strip_purl_qualifiers(purl).to_string();
    let mut wiring = vec![manifest_wiring_record(ensured, copy_rel)];
    if let (Some(orig), Some((name, version))) = (&lock_original, parse_cargo_purl(&base_purl)) {
        let (name, version) = (name.as_ref(), version.as_ref());
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
    VendorEntry {
        ecosystem: "cargo".to_string(),
        base_purl,
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: copy_rel.to_string(),
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
    }
}

/// The `Cargo.toml` `cargo_patch_entry` wiring record: `key` is the TOML key
/// the entry lives under, `original` the Socket-owned path a pre-existing
/// manifest entry held (a re-vendor), `new` the copy path.
fn manifest_wiring_record(ensured: &cargo_manifest::Ensured, copy_rel: &str) -> WiringRecord {
    WiringRecord {
        file: cargo_manifest::CARGO_TOML.to_string(),
        kind: "cargo_patch_entry".to_string(),
        action: if ensured.prior_path.is_some() {
            WiringAction::Rewritten
        } else {
            WiringAction::Added
        },
        key: Some(ensured.key.clone()),
        original: ensured.prior_path.clone().map(serde_json::Value::from),
        new: Some(serde_json::Value::from(copy_rel.to_string())),
    }
}

/// The `cargo_wiring_migrated` advisory.
async fn migration_warning(
    project_root: &Path,
    name: &str,
    version: &str,
    dry_run: bool,
) -> VendorWarning {
    let config = cargo_config::effective_config_rel(project_root).await;
    VendorWarning::new(
        "cargo_wiring_migrated",
        format!(
            "{} the vendored `[patch.crates-io]` entry for {name}@{version} from {config} \
             to the workspace-root Cargo.toml",
            if dry_run { "would move" } else { "moved" }
        ),
    )
}

/// Drop the legacy project-config entries for `name@version` once the
/// manifest carries the wiring (warning `cargo_wiring_migrated`). `Err` when
/// they could not be removed — the caller unwinds: a kept legacy entry
/// double-wires the crate beside the manifest entry and, on a uuid bump,
/// points at a copy the stale sweep deletes.
async fn retire_legacy_wiring(
    project_root: &Path,
    name: &str,
    version: &str,
    legacy_paths: &[String],
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), String> {
    if legacy_paths.is_empty() {
        return Ok(());
    }
    cargo_config::drop_legacy_patch_entries(project_root, name, version, false).await?;
    warnings.push(migration_warning(project_root, name, version, false).await);
    Ok(())
}

/// The failure for a legacy config entry [`retire_legacy_wiring`] could not
/// remove.
fn legacy_kept_error(name: &str, version: &str, detail: &str) -> String {
    format!(
        "cargo_legacy_wiring_kept: the pre-v5 .cargo/config wiring for {name}@{version} \
         could not be removed ({detail}); the Cargo.toml edit was unwound and nothing \
         new was vendored — make the config writable and re-run"
    )
}

/// Refusal code: the lock entry cannot carry the copy's tagged version
/// consistently ([`LockEditError::Inconsistent`]).
pub const LOCK_UNTAGGABLE: &str = "cargo_lock_untaggable";

/// Failure tag: the copy's `Cargo.toml` version cannot be tagged
/// ([`cargo_tag::TagError`]).
pub const COPY_UNTAGGABLE: &str = "cargo_copy_untaggable";

/// Advisory code for a copy / lock entry (re)tagged by a re-run or repair.
pub const VERSION_TAGGED: &str = "cargo_version_tagged";

/// Does the committed copy verify against the patch record? The tag-aware
/// twin of [`copy_matches_after_hashes`]: a patched `Cargo.toml` is compared
/// with its Socket tag dropped (the tag is written after the patch).
async fn cargo_copy_matches(
    copy_dir: &Path,
    files: &std::collections::HashMap<String, crate::manifest::schema::PatchFileInfo>,
) -> bool {
    if copy_matches_after_hashes(copy_dir, files).await {
        return true;
    }
    let (manifest, rest): (Vec<_>, Vec<_>) = files
        .iter()
        .partition(|(k, _)| cargo_tag::is_copy_manifest_key(k));
    let Some((_, info)) = manifest.first() else {
        return false;
    };
    let rest: std::collections::HashMap<String, crate::manifest::schema::PatchFileInfo> = rest
        .into_iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if !copy_matches_after_hashes(copy_dir, &rest).await {
        return false;
    }
    let Ok(text) = read_regular_to_string(&copy_dir.join("Cargo.toml")).await else {
        return false;
    };
    cargo_tag::untagged_manifest_bytes(text.as_bytes()).is_some_and(|b| {
        crate::hash::git_sha256::compute_git_sha256_from_bytes(&b) == info.after_hash
    })
}

/// Tag the committed copy at `copy_dir` and its DETACHED lock entry for
/// `uuid` (an untagged copy vendored before tagged versions, or one tagged
/// for a previous uuid). `Ok(true)` when anything changed (or, with
/// `dry_run`, would — the dry run proves both edits, lock and copy
/// manifest, writing nothing). The lock retag is proven first; a failed
/// lock write untags the copy again when this call tagged it (or
/// `untag_on_failure`: the caller just rebuilt it tagged) so copy and lock
/// never disagree. A missing lock needs no edit (the first build locks the
/// tagged copy).
async fn tag_vendored_copy(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
    copy_dir: &Path,
    untag_on_failure: bool,
    dry_run: bool,
) -> Result<bool, String> {
    let lock_retag = matches!(
        cargo_lock::probe_lock_entry_for(project_root, name, version, Some(uuid)).await,
        cargo_lock::LockEntryProbe::Detached(tag) if tag.as_deref() != Some(uuid)
    );
    if lock_retag {
        if let Err(e) = cargo_lock::retag_lock_entry(project_root, name, version, uuid, true).await
        {
            return Err(format!(
                "{LOCK_UNTAGGABLE}: cannot tag the Cargo.lock entry for {name}@{version}: {e}"
            ));
        }
    }
    if dry_run {
        let text = read_regular_to_string(&copy_dir.join("Cargo.toml"))
            .await
            .map_err(|e| format!("{COPY_UNTAGGABLE}: the copy's Cargo.toml: {e}"))?;
        let copy_retag = cargo_tag::tag_manifest_text(&text, version, uuid)
            .map_err(|e| format!("{COPY_UNTAGGABLE}: {e}"))?
            .is_some();
        return Ok(lock_retag || copy_retag);
    }
    let copy_changed = cargo_tag::tag_copy_manifest(copy_dir, version, uuid)
        .await
        .map_err(|e| format!("{COPY_UNTAGGABLE}: {e}"))?;
    if lock_retag {
        if let Err(e) = cargo_lock::retag_lock_entry(project_root, name, version, uuid, false).await
        {
            if copy_changed || untag_on_failure {
                cargo_tag::untag_copy_manifest(copy_dir).await;
            }
            return Err(format!(
                "{LOCK_UNTAGGABLE}: cannot tag the Cargo.lock entry for {name}@{version}: {e}"
            ));
        }
    }
    Ok(copy_changed || lock_retag)
}

/// The lock edit a vendor run makes (a registry entry is detached and
/// tagged; a detached one — an earlier generation, or vendored before
/// tagged versions — is retagged) must be consistent: prove it read-only
/// before anything is written. Returns the probe and, when the edit cannot
/// be made consistently, the [`LOCK_UNTAGGABLE`] refusal.
async fn lock_tag_preflight(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
) -> (cargo_lock::LockEntryProbe, Option<VendorOutcome>) {
    let probe = cargo_lock::probe_lock_entry_for(project_root, name, version, Some(uuid)).await;
    let preflight = match &probe {
        cargo_lock::LockEntryProbe::Source(_) => {
            cargo_lock::detach_lock_entry(project_root, name, version, uuid, true)
                .await
                .err()
        }
        cargo_lock::LockEntryProbe::Detached(tag) if tag.as_deref() != Some(uuid) => {
            cargo_lock::retag_lock_entry(project_root, name, version, uuid, true)
                .await
                .err()
        }
        _ => None,
    };
    let refusal = match preflight {
        Some(e @ LockEditError::Inconsistent(_)) => Some(refused(
            LOCK_UNTAGGABLE,
            format!(
                "cannot tag the Cargo.lock entry for {name}@{version} with the vendored \
                 copy's version: {e}"
            ),
        )),
        _ => None,
    };
    (probe, refusal)
}

/// The [`VERSION_TAGGED`] advisory.
fn tag_warning(name: &str, version: &str, uuid: &str, dry_run: bool) -> VendorWarning {
    VendorWarning::new(
        VERSION_TAGGED,
        format!(
            "{} the vendored copy of {name}@{version} and its Cargo.lock entry with the \
             tagged version {}",
            if dry_run { "would tag" } else { "tagged" },
            cargo_tag::tag_version(version, uuid)
        ),
    )
}

/// Undo this run's manifest edit: restore the prior Socket-owned entry for
/// `name@version` (a re-vendor), else drop the entry this run added.
/// Best-effort — the caller is already failing.
async fn unwind_manifest(
    project_root: &Path,
    name: &str,
    version: &str,
    uuid: &str,
    prior: Option<&str>,
    reserved: &[String],
) {
    match prior {
        Some(p) => {
            let _ = cargo_manifest::ensure_patch_entry(
                project_root,
                name,
                version,
                uuid,
                p,
                reserved,
                false,
            )
            .await;
        }
        None => {
            let _ = cargo_manifest::drop_patch_entries(project_root, name, version, false).await;
        }
    }
}

/// The refusal code for a project directory whose Cargo.toml is not the
/// workspace root (cargo ignores `[patch]` in member manifests).
pub const NOT_WORKSPACE_ROOT: &str = "cargo_manifest_not_workspace_root";

/// `Some(detail)` when `<project_root>/Cargo.toml` is not the workspace
/// root cargo reads `[patch]` from: it names another root
/// (`package.workspace`), or — having no `[workspace]` table of its own —
/// an ancestor directory's `[workspace]` claims it (cargo's own
/// `find_root`: the nearest ancestor workspace that does not `exclude` it;
/// an unparseable ancestor manifest is skipped).
async fn workspace_root_refusal(
    project_root: &Path,
    doc: &toml_edit::DocumentMut,
) -> Option<String> {
    if doc
        .get("workspace")
        .is_some_and(toml_edit::Item::is_table_like)
    {
        return None;
    }
    let hint = "cargo ignores `[patch]` outside the workspace-root manifest; run socket-patch \
                from the workspace root (the directory holding its Cargo.toml and Cargo.lock)";
    if let Some(ws) = doc
        .get("package")
        .and_then(toml_edit::Item::as_table_like)
        .and_then(|p| p.get("workspace"))
        .and_then(toml_edit::Item::as_str)
    {
        return Some(format!(
            "Cargo.toml sets `package.workspace = \"{ws}\"`, so it is a workspace member, not \
             the root; {hint}"
        ));
    }
    let root = tokio::fs::canonicalize(project_root)
        .await
        .unwrap_or_else(|_| project_root.to_path_buf());
    for ancestor in root.ancestors().skip(1) {
        if ancestor.ends_with("target/package") {
            break;
        }
        let manifest = ancestor.join(cargo_manifest::CARGO_TOML);
        let Ok(text) = read_regular_to_string(&manifest).await else {
            continue;
        };
        let Ok(ancestor_doc) = cargo_manifest::parse_manifest(&text) else {
            continue;
        };
        let Some(ws) = ancestor_doc
            .get("workspace")
            .and_then(toml_edit::Item::as_table_like)
        else {
            continue;
        };
        let rel = root.strip_prefix(ancestor).ok()?;
        let listed = |key: &str| {
            ws.get(key)
                .and_then(toml_edit::Item::as_array)
                .is_some_and(|paths| {
                    paths.iter().filter_map(|v| v.as_str()).any(|p| {
                        let p = p.trim_start_matches("./").trim_end_matches('/');
                        !p.is_empty() && rel.starts_with(p)
                    })
                })
        };
        if listed("exclude") && !listed("members") {
            continue;
        }
        return Some(format!(
            "{} is a member of the cargo workspace rooted at {}; {hint}",
            project_root.display(),
            manifest.display()
        ));
    }
    None
}

/// Is a committed copy of `name@version` present under any uuid of this
/// project's `.socket/vendor/cargo/`?
async fn socket_copy_present(project_root: &Path, name: &str, version: &str) -> bool {
    let Ok(mut dir) = tokio::fs::read_dir(project_root.join(".socket/vendor/cargo")).await else {
        return false;
    };
    let leaf = format!("{name}-{version}");
    while let Ok(Some(uuid)) = dir.next_entry().await {
        let canonical = uuid
            .file_name()
            .to_str()
            .is_some_and(|u| vendor_uuid_dir_rel("cargo", u).is_some());
        if canonical
            && tokio::fs::metadata(uuid.path().join(&leaf))
                .await
                .is_ok_and(|m| m.is_dir())
        {
            return true;
        }
    }
    false
}

/// Keys every config file cargo merges already uses in its crates.io
/// `[patch]` — a config item replaces the manifest item with the same key
/// (any version), so a manifest key must avoid them — minus the project
/// config's legacy Socket entries wiring `name@version` (this run retires
/// those).
fn reserved_config_keys(
    chain: &[cargo_config::ChainConfig],
    name: &str,
    version: &str,
) -> Vec<String> {
    chain
        .iter()
        .flat_map(|config| config.entries.iter())
        .filter(|e| !cargo_manifest::entry_wires(e, name, version))
        .map(|e| e.key.clone())
        .collect()
}

/// A USER-authored crates.io `[patch]` entry — in the root manifest or any
/// config file cargo merges ([`cargo_config::read_config_chain`]) — that
/// overrides `name@version`, or may: a git / registry patch, or a path
/// whose `Cargo.toml` version cannot be read, cannot be proven to patch a
/// DIFFERENT version. `Some(detail)` names the blocker.
async fn user_patch_conflict(
    project_root: &Path,
    manifest: &[cargo_manifest::ManifestPatchEntry],
    chain: &[cargo_config::ChainConfig],
    name: &str,
    version: &str,
) -> Option<String> {
    let candidates = manifest
        .iter()
        .map(|e| (cargo_manifest::CARGO_TOML, project_root, e))
        .chain(chain.iter().flat_map(|config| {
            config
                .entries
                .iter()
                .map(move |e| (config.file.as_str(), config.base.as_path(), e))
        }));
    for (file, base, entry) in candidates {
        if entry.socket_owned || entry.name != name {
            continue;
        }
        let proven_other = match entry.path.as_deref() {
            Some(p) => path_crate_version(base, p)
                .await
                .is_some_and(|v| !cargo_tag::denotes(&v, version)),
            None => false,
        };
        if !proven_other {
            return Some(format!(
                "`patch.{}.{}` in {file} is user-authored ({}) and overrides (or may \
                 override) {name}@{version}; refusing to wire a second patch for it",
                entry.source,
                entry.key,
                entry.path.as_deref().unwrap_or("non-path source")
            ));
        }
    }
    None
}

/// The `[package] version` of the crate at a `[patch]` path (relative to
/// `base`: the project root for the manifest and the project config, the
/// config's own root for any other config file).
async fn path_crate_version(base: &Path, rel: &str) -> Option<String> {
    let dir = if Path::new(rel).is_absolute() {
        PathBuf::from(rel)
    } else {
        base.join(rel)
    };
    let text = read_regular_to_string(&dir.join("Cargo.toml")).await.ok()?;
    let doc = text.parse::<toml_edit::DocumentMut>().ok()?;
    doc.get("package")?
        .as_table_like()?
        .get("version")?
        .as_str()
        .map(str::to_string)
}

/// Every Socket-owned `[patch.crates-io]` path wiring crate `name` (any
/// version): the root manifest's (v5) and the legacy project config's.
async fn socket_patch_paths(project_root: &Path, name: &str) -> Vec<String> {
    let mut out: Vec<String> = cargo_manifest::read_patch_entries(project_root)
        .await
        .into_iter()
        .filter(|e| e.socket_owned && e.name == name)
        .filter_map(|e| e.path)
        .collect();
    out.extend(
        cargo_config::legacy_socket_entries(project_root, name)
            .await
            .into_iter()
            .map(|(_, p)| p),
    );
    out
}

/// Is Socket-owned vendored `[patch.crates-io]` wiring for exactly
/// `name@version` present — in the root manifest or (legacy) the project
/// config? Used by the hosted takeover to refuse redirecting over
/// ledger-less vendored wiring; another vendored version of the same crate
/// (with its own ledger entry) does not count.
pub async fn socket_wiring_present(project_root: &Path, name: &str, version: &str) -> bool {
    socket_patch_paths(project_root, name)
        .await
        .iter()
        .any(|p| cargo_manifest::is_socket_copy_of(p, name, version))
}

/// Bring a ledger entry's wiring up to the v5 shape (`repair`'s migration
/// step; `vendor`/`scan`/`get` migrate on their own re-run):
///
/// * a legacy project-config entry pointing at THIS entry's copy is moved
///   into the root manifest (`cargo_wiring_migrated`);
/// * LOST wiring is restored: a detached lock entry that no Socket-owned
///   `[patch]` wires while this entry's committed copy exists (a pre-v5
///   second-version vendor overwrote its crate-named config key) gets its
///   manifest entry back (`cargo_wiring_restored`);
/// * a copy and detached lock entry wired here but not tagged for this
///   entry's uuid (vendored before tagged versions) are tagged
///   ([`VERSION_TAGGED`]; a tag that cannot be written is the
///   `cargo_version_untagged` warning, nothing else undone).
///
/// `Ok(Some((entry, warnings)))` is the updated ledger entry (the
/// `cargo_patch_entry` record names `Cargo.toml`). A recorded file
/// inventory is KEPT as is: it was taken over the untagged copy, and the
/// inventory check accepts the copy's `Cargo.toml` with exactly this
/// entry's tag dropped (`verify::verify_vendored_patch_record`) — so the
/// tag step never re-baselines the inventory over bytes nobody verified,
/// and a copy that drifted before it was tagged still fails verification.
/// `Ok(None)` when there is
/// nothing to do; `Err` when the manifest cannot take the entry (nothing
/// was changed).
pub async fn migrate_legacy_wiring(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> Result<Option<(VendorEntry, Vec<VendorWarning>)>, String> {
    let Some((name, version)) = parse_cargo_purl(&entry.base_purl) else {
        return Ok(None);
    };
    let (name, version) = (name.as_ref(), version.as_ref());
    if !is_safe_single_segment(name) || !is_safe_single_segment(version) {
        return Ok(None);
    }
    let Some(base_rel) = vendor_uuid_dir_rel("cargo", &entry.uuid) else {
        return Ok(None);
    };
    let copy_rel = format!("{base_rel}/{name}-{version}");
    let copy_dir = project_root.join(&copy_rel);
    let copy_present = tokio::fs::metadata(&copy_dir)
        .await
        .is_ok_and(|m| m.is_dir());
    let legacy_here = cargo_config::legacy_socket_entries(project_root, name)
        .await
        .into_iter()
        .any(|(_, p)| cargo_manifest::normalize_socket_path(&p).as_deref() == Some(&copy_rel));
    let unwired_here = !legacy_here
        && matches!(
            cargo_lock::probe_lock_entry_for(project_root, name, version, Some(&entry.uuid)).await,
            cargo_lock::LockEntryProbe::Detached(_)
        )
        && !socket_wiring_present(project_root, name, version).await
        && copy_present;
    let mut migrated = entry.clone();
    let mut warnings: Vec<VendorWarning> = Vec::new();
    if legacy_here || unwired_here {
        let warning = move_wiring_into_manifest(
            entry,
            project_root,
            name,
            version,
            &copy_rel,
            unwired_here,
            dry_run,
            &mut migrated,
        )
        .await?;
        warnings.push(warning);
    }
    // The (now) wired copy carries this entry's tag, and so does the lock.
    let wired_here = socket_patch_paths(project_root, name)
        .await
        .iter()
        .any(|p| cargo_manifest::normalize_socket_path(p).as_deref() == Some(copy_rel.as_str()))
        || (dry_run && unwired_here);
    if copy_present && wired_here {
        match tag_vendored_copy(
            project_root,
            name,
            version,
            &entry.uuid,
            &copy_dir,
            false,
            dry_run,
        )
        .await
        {
            Ok(true) => warnings.push(tag_warning(name, version, &entry.uuid, dry_run)),
            Ok(false) => {}
            Err(e) => warnings.push(VendorWarning::new(
                "cargo_version_untagged",
                format!(
                    "the vendored copy of {name}@{version} could not be tagged with its patch \
                     uuid ({e}); re-run `socket-patch vendor`"
                ),
            )),
        }
    }
    if warnings.is_empty() {
        return Ok(None);
    }
    Ok(Some((migrated, warnings)))
}

/// [`migrate_legacy_wiring`]'s manifest step: write this entry's `[patch]`
/// into the root manifest (retiring the legacy config entry unless the
/// wiring was lost) and point `migrated`'s `cargo_patch_entry` record at it.
#[allow(clippy::too_many_arguments)]
async fn move_wiring_into_manifest(
    entry: &VendorEntry,
    project_root: &Path,
    name: &str,
    version: &str,
    copy_rel: &str,
    unwired_here: bool,
    dry_run: bool,
    migrated: &mut VendorEntry,
) -> Result<VendorWarning, String> {
    if is_symlink(&project_root.join(cargo_manifest::CARGO_TOML)).await {
        return Err("Cargo.toml is a symbolic link; the legacy wiring was left in place".into());
    }
    let text = cargo_manifest::read_manifest(project_root)
        .await
        .map_err(|e| e.to_string())?;
    let doc = cargo_manifest::parse_manifest(&text).map_err(|e| e.to_string())?;
    cargo_manifest::check_source_alias(&doc).map_err(|e| e.to_string())?;
    if let Some(detail) = workspace_root_refusal(project_root, &doc).await {
        return Err(detail);
    }
    let manifest_entries = cargo_manifest::crates_io_patch_entries(&doc);
    let chain = cargo_config::read_config_chain(project_root).await;
    if let Some(detail) =
        user_patch_conflict(project_root, &manifest_entries, &chain, name, version).await
    {
        return Err(detail);
    }
    let reserved = reserved_config_keys(&chain, name, version);
    let ensured = cargo_manifest::ensure_patch_entry(
        project_root,
        name,
        version,
        &entry.uuid,
        copy_rel,
        &reserved,
        dry_run,
    )
    .await
    .map_err(|e| e.to_string())?;
    let warning = if unwired_here {
        VendorWarning::new(
            "cargo_wiring_restored",
            format!(
                "{} the missing Cargo.toml `[patch.crates-io]` entry for {name}@{version}: its \
                 Cargo.lock entry is detached but nothing pointed at the committed copy (a \
                 pre-v5 release overwrote its crate-named .cargo/config key when a second \
                 version was vendored)",
                if dry_run { "would restore" } else { "restored" }
            ),
        )
    } else if dry_run {
        migration_warning(project_root, name, version, true).await
    } else {
        let warning = migration_warning(project_root, name, version, false).await;
        if let Err(e) =
            cargo_config::drop_legacy_patch_entries(project_root, name, version, false).await
        {
            let prior = ensured.prior_path.as_deref();
            unwind_manifest(project_root, name, version, &entry.uuid, prior, &reserved).await;
            return Err(format!(
                "the legacy entry could not be removed ({e}); the Cargo.toml edit was unwound"
            ));
        }
        warning
    };
    migrated.wiring.retain(|w| w.kind != "cargo_patch_entry");
    migrated
        .wiring
        .insert(0, manifest_wiring_record(&ensured, copy_rel));
    Ok(warning)
}

/// Revert one vendored cargo crate: restore the lock entry's original
/// `source`/`checksum` and untagged version (byte-identical to the
/// pre-vendor lock), drop the `[patch.crates-io]` wiring (root manifest
/// and any legacy project-config entry), and remove the uuid dir.
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
    let (name, version) = (name.as_ref(), version.as_ref());
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

    // Pre-flight the manifest removal: an unreadable / unparseable
    // Cargo.toml must fail the revert BEFORE the lock is restored — a
    // restored lock under a still-live `[patch]` entry breaks every
    // `--locked` build.
    match cargo_manifest::drop_patch_entries(project_root, name, version, true).await {
        Err(e) => {
            return RevertOutcome {
                kept_artifact: false,
                success: false,
                warnings: out.warnings,
                error: Some(format!("failed to update Cargo.toml: {e}")),
            };
        }
        // The atomic rewrite would replace a symlinked manifest with a
        // detached regular file, leaving the link's target still wired.
        Ok(true) if is_symlink(&project_root.join(cargo_manifest::CARGO_TOML)).await => {
            return RevertOutcome {
                kept_artifact: false,
                success: false,
                warnings: out.warnings,
                error: Some(
                    "cargo_manifest_symlink_unsupported: Cargo.toml is a symbolic link; \
                     remove the vendored `[patch.crates-io]` entry from the link's target \
                     by hand (nothing was reverted)"
                        .to_string(),
                ),
            };
        }
        Ok(_) => {}
    }

    if let Some(lock) = &entry.lock {
        match cargo_lock::restore_lock_entry(
            project_root,
            name,
            version,
            &entry.uuid,
            lock,
            dry_run,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => out.warnings.push(VendorWarning::new(
                "lock_restore_skipped",
                format!(
                    "the Cargo.lock entry for {name}@{version} is no longer in this \
                     patch's detached form (re-resolved, removed, or tagged for another \
                     patch); left as-is"
                ),
            )),
            Err(LockEditError::NoLockfile) => out.warnings.push(VendorWarning::new(
                "lock_restore_skipped",
                "Cargo.lock no longer exists; nothing to restore".to_string(),
            )),
            // Fail-closed on a corrupt/unwritable lock BEFORE touching the
            // `[patch]` wiring — a half-revert (entry dropped, lock still
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
    } else if matches!(
        cargo_lock::probe_lock_entry_for(project_root, name, version, Some(&entry.uuid)).await,
        cargo_lock::LockEntryProbe::Detached(Some(ref tag)) if *tag == entry.uuid
    ) {
        // Vendored before any Cargo.lock existed (no originals recorded):
        // the first build then locked the tagged copy. Drop the tag, back
        // to the untagged sourceless entry such a vendor always left — an
        // unlocked build re-resolves it, and a hosted takeover finds it by
        // its version; a tag nothing provides would do neither.
        if let Err(e) =
            cargo_lock::retag_lock_entry_to(project_root, name, version, version, dry_run).await
        {
            out.warnings.push(VendorWarning::new(
                "lock_restore_skipped",
                format!(
                    "the Cargo.lock entry for {name}@{version} keeps the tagged version of \
                     the removed copy ({e}); re-lock it with `cargo update -p {name}`"
                ),
            ));
        }
    }

    if let Err(e) = cargo_manifest::drop_patch_entries(project_root, name, version, dry_run).await {
        return RevertOutcome {
            kept_artifact: false,
            success: false,
            warnings: out.warnings,
            error: Some(format!("failed to update Cargo.toml: {e}")),
        };
    }
    // Pre-v5 projects (and half-migrated ones) carry the wiring in the
    // legacy project config: always clean it too.
    if let Err(e) =
        cargo_config::drop_legacy_patch_entries(project_root, name, version, dry_run).await
    {
        let config = cargo_config::effective_config_rel(project_root).await;
        return RevertOutcome {
            kept_artifact: false,
            success: false,
            warnings: out.warnings,
            error: Some(format!("failed to update {config}: {e}")),
        };
    }

    // `--preserve-state` (`keep_artifact`): the artifact dir stays behind
    // (and the caller keeps the ledger entry), so only the deletion is
    // skipped.
    if !dry_run && !keep_artifact {
        let uuid_dir = project_root.join(&base_rel);
        let _ = remove_tree(&uuid_dir).await; // ignore NotFound
                                              // Best-effort: prune the now-empty `.socket/vendor/cargo/` and
                                              // `.socket/vendor/` levels so a fully-reverted project carries no
                                              // vendor residue. `remove_dir` fails on non-empty.
        prune_empty_vendor_levels(&uuid_dir).await;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::{PatchFileInfo, VulnerabilityInfo};
    use crate::vendor::common::backup_dir_for;
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

    /// A project root with `Cargo.toml` and, optionally, a
    /// `[patch.crates-io]` table and toolchain files.
    async fn toolchain_fixture(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in files {
            tokio::fs::write(dir.path().join(name), body).await.unwrap();
        }
        dir
    }

    /// The only signals socket-patch can read offline for "which cargo will
    /// build this project" — it never runs `cargo` itself.
    #[tokio::test]
    async fn declared_cargo_minor_reads_rust_version_and_toolchain_files() {
        /// `(project files, the declared cargo minor)`.
        type Case = (&'static [(&'static str, &'static str)], Option<u32>);
        let cases: [Case; 8] = [
            (
                &[(
                    "Cargo.toml",
                    "[package]\nname = \"a\"\nrust-version = \"1.70\"\n",
                )],
                Some(70),
            ),
            (
                &[(
                    "Cargo.toml",
                    "[package]\nname = \"a\"\nrust-version = \"1.41.1\"\n",
                )],
                Some(41),
            ),
            (
                &[(
                    "Cargo.toml",
                    "[workspace]\nmembers = []\n\n[workspace.package]\nrust-version = \"1.56\"\n",
                )],
                Some(56),
            ),
            (
                &[
                    ("Cargo.toml", "[package]\nname = \"a\"\n"),
                    ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.63.0\"\n"),
                ],
                Some(63),
            ),
            (
                &[
                    ("Cargo.toml", "[package]\nname = \"a\"\n"),
                    ("rust-toolchain", "1.48.0\n"),
                ],
                Some(48),
            ),
            // A rolling channel says nothing about the cargo in use.
            (
                &[
                    ("Cargo.toml", "[package]\nname = \"a\"\n"),
                    ("rust-toolchain.toml", "[toolchain]\nchannel = \"stable\"\n"),
                ],
                None,
            ),
            (&[("Cargo.toml", "[package]\nname = \"a\"\n")], None),
            // `rust-version` wins over a toolchain file: it is the floor the
            // project promises, the toolchain file only what one dev uses.
            (
                &[
                    (
                        "Cargo.toml",
                        "[package]\nname = \"a\"\nrust-version = \"1.41\"\n",
                    ),
                    ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.80.0\"\n"),
                ],
                Some(41),
            ),
        ];
        for (files, want) in cases {
            let dir = toolchain_fixture(files).await;
            assert_eq!(
                declared_cargo_minor(dir.path()).await,
                want,
                "files: {files:?}"
            );
        }
    }

    /// The `[patch.crates-io]` table wiring `versions` of cfg-if, each under
    /// its own Socket-owned key/uuid.
    fn patch_table(versions: &[(&str, &str)]) -> String {
        let mut out =
            String::from("[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[patch.crates-io]\n");
        for (version, uuid) in versions {
            out.push_str(&format!(
                "cfg-if-socket-{} = {{ package = \"cfg-if\", path = \".socket/vendor/cargo/{uuid}/cfg-if-{version}\" }}\n",
                &uuid.replace('-', "")[..8]
            ));
        }
        out
    }

    /// REGRESSION: cargo before 1.45 resolves every source-less lock entry
    /// of a crate through ONE `[patch.crates-io]` path (the entry whose key
    /// sorts last), so a second vendored version of the same crate cannot
    /// build there — verified on the `rust:1.41-slim` image and cargo
    /// 1.42/1.43/1.44, where the adversarial key order fails ``patch for
    /// `cfg-if` … did not resolve to any crates`` even with a populated
    /// index, while 1.45 and later build either order. The vendor says so
    /// when the project does not promise a cargo that can take it.
    #[tokio::test]
    async fn a_second_vendored_version_warns_unless_the_project_pins_cargo_1_45() {
        // One version: nothing to warn about.
        let dir = toolchain_fixture(&[("Cargo.toml", &patch_table(&[("1.0.4", UUID)]))]).await;
        assert!(multi_version_warning(dir.path(), "cfg-if", "1.0.4")
            .await
            .is_none());

        // Two versions, no declared cargo: warn.
        let two = patch_table(&[("1.0.4", UUID), ("0.1.10", UUID2)]);
        let dir = toolchain_fixture(&[("Cargo.toml", &two)]).await;
        let warning = multi_version_warning(dir.path(), "cfg-if", "1.0.4")
            .await
            .expect("a second version warns");
        assert_eq!(warning.code, "cargo_multi_version_old_cargo");
        assert!(warning.detail.contains("cfg-if-0.1.10"), "{warning:?}");
        assert!(warning.detail.contains("1.45"), "{warning:?}");
        // Either version's vendor says it.
        assert!(multi_version_warning(dir.path(), "cfg-if", "0.1.10")
            .await
            .is_some());

        // The project promises a cargo that can take it: silent.
        let dir = toolchain_fixture(&[
            ("Cargo.toml", &two),
            ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.45.0\"\n"),
        ])
        .await;
        assert!(multi_version_warning(dir.path(), "cfg-if", "1.0.4")
            .await
            .is_none());

        // A project that pins an OLDER cargo says so in the warning.
        let dir = toolchain_fixture(&[
            ("Cargo.toml", &two),
            ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.41.0\"\n"),
        ])
        .await;
        let warning = multi_version_warning(dir.path(), "cfg-if", "1.0.4")
            .await
            .expect("an old pinned cargo warns");
        assert!(warning.detail.contains("pins cargo 1.41"), "{warning:?}");
    }

    /// The path of the root manifest's Socket-owned `[patch.crates-io]`
    /// entry for cfg-if (any key), if any.
    async fn manifest_path(root: &Path) -> Option<String> {
        cargo_manifest::read_patch_entries(root)
            .await
            .into_iter()
            .find(|e| e.socket_owned && e.name == "cfg-if")
            .and_then(|e| e.path)
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

        // The ROOT MANIFEST carries the entry (under the Socket-owned key,
        // never the bare crate name); no project config is created.
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            format!(
                "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n\n\
                 [patch.crates-io]\ncfg-if-socket-9f6b2c4e = {{ package = \"cfg-if\", path = \"{}\" }}\n",
                copy_rel()
            )
        );
        assert!(!root.join(".cargo").exists(), "no .cargo/ is created");

        // The lock entry is detached (source+checksum gone) and carries the
        // copy's tagged version; the rest is preserved.
        let lock = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        assert!(!lock.contains("source ="));
        assert!(!lock.contains("checksum ="));
        assert!(lock.contains(&format!(
            "name = \"cfg-if\"\nversion = \"1.0.4+socket.{UUID}\"\n"
        )));
        assert!(lock.contains("dependencies = [\n \"cfg-if\",\n]"));
        // So does the copy's own manifest (the only byte the tag adds).
        assert_eq!(
            tokio::fs::read_to_string(root.join(copy_rel()).join("Cargo.toml"))
                .await
                .unwrap(),
            format!("[package]\nname = \"cfg-if\"\nversion = \"1.0.4+socket.{UUID}\"\n")
        );

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
            ("Cargo.toml", "cargo_patch_entry")
        );
        assert_eq!(cfg.action, WiringAction::Added);
        assert_eq!(cfg.key.as_deref(), Some("cfg-if-socket-9f6b2c4e"));
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
        assert!(manifest_path(root).await.is_some());
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
        assert!(manifest_path(root).await.is_none());
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
    /// vendor run: a raw `read_to_string` open(2) of the manifest waits for
    /// a writer that never comes and hangs the vendor forever with no error
    /// and no timeout. Same class as the `open_regular_file` guards in the
    /// setup twins and the crawlers. The manifest carries the wiring, so the
    /// non-regular file must be refused promptly (`cargo_manifest_unreadable`)
    /// with nothing written.
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
        expect_refused(outcome, "cargo_manifest_unreadable");
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
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
        assert!(manifest_path(root).await.is_none());
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
        let cfg1 = tokio::fs::read(root.join("Cargo.toml")).await.unwrap();
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
            tokio::fs::read(root.join("Cargo.toml")).await.unwrap(),
            cfg1,
            "manifest untouched"
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
            manifest_path(root).await.as_deref(),
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
        let cfg = root.join("Cargo.toml");
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
        let cfg = root.join("Cargo.toml");
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
        // Manifest byte-identical to the pre-vendor fixture; no .cargo/.
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n"
        );
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

    /// `.socket/cargo-patches/` was the retired `[patch]`-redirect backend's
    /// copy root; no tagged release ever wrote it (it lived only between two
    /// main commits), so an entry pointing there is an unknown user path and
    /// refuses like any other user-authored same-name entry.
    #[tokio::test]
    async fn test_retired_redirect_path_entry_is_user_authored() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        let config =
            "[patch.crates-io]\ncfg-if = { path = \".socket/cargo-patches/cfg-if-1.0.4\" }\n";
        tokio::fs::write(root.join(".cargo/config.toml"), config)
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
            config,
            "the user's entry is never rewritten"
        );
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
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
        assert!(manifest_path(root).await.is_some());
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
        assert_eq!(manifest_path(root).await.as_deref(), Some(new_rel.as_str()));
        // The new copy carries the patched bytes; the old uuid dir is left
        // for the caller's stale-artifact sweep (the caller owns the ledger).
        assert_eq!(
            tokio::fs::read(root.join(&new_rel).join("src/lib.rs"))
                .await
                .unwrap(),
            PATCHED
        );
        assert!(root.join(copy_rel()).exists());
        // The already-detached lock is only retagged for the new uuid.
        assert_eq!(
            String::from_utf8(tokio::fs::read(root.join("Cargo.lock")).await.unwrap()).unwrap(),
            String::from_utf8(lock_detached)
                .unwrap()
                .replace(UUID, UUID2)
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
            manifest_path(root).await.as_deref(),
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
            client: Some(
                ApiClient::new(ApiClientOptions {
                    api_url: uri.to_string(),
                    api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                    use_public_proxy: false,
                    org_slug: Some("acme".into()),
                })
                .with_vendor_retry(crate::api::client::VendorRetryPolicy::none()),
            ),
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
        let cfg = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert!(
            cfg.contains("[patch.crates-io]") && cfg.contains(&copy_rel()),
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

    /// FAIL CLOSED in EVERY manifest shape the hosted rewriter writes: a
    /// standalone `registry = …` line under a `[dependencies.<crate>]`
    /// header, a renamed declaration (`legacy = { package = "cfg-if", … }`)
    /// and a quoted key. The lock is the pristine crates.io one — a
    /// re-resolve or a `git checkout Cargo.lock` puts it back while the
    /// manifest pin survives — so the manifest probe is the ONLY thing
    /// standing between `vendor` and a project wired for both modes at once.
    #[tokio::test]
    async fn test_refuses_live_hosted_redirect_in_every_manifest_shape() {
        let index = "sparse+http://127.0.0.1:5555/index/";
        let shapes = [
            (
                "table form",
                format!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                     [dependencies.cfg-if]\nversion = \"1\"\n\
                     registry = \"socket-patch-{UUID}\"\n"
                ),
            ),
            (
                "renamed declaration",
                format!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                     [dependencies]\ncfg-if-legacy = {{ package = \"cfg-if\", \
                     version = \"1\", registry = \"socket-patch-{UUID}\" }}\n"
                ),
            ),
            (
                "quoted key",
                format!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                     [dependencies]\n\"cfg-if\" = {{ version = \"1\", \
                     registry = \"socket-patch-{UUID}\" }}\n"
                ),
            ),
            (
                "dev-dependency table",
                format!(
                    "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
                     [dev-dependencies.cfg-if]\n\
                     registry = \"socket-patch-{UUID}\"\nversion = \"1\"\n"
                ),
            ),
        ];
        for (shape, manifest) in shapes {
            let (dir, blobs, pristine, record) = fixture().await;
            let root = dir.path();
            tokio::fs::write(root.join("Cargo.toml"), &manifest)
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
            let detail = expect_refused(
                run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
                "hosted_redirect_live",
            );
            assert!(
                detail.contains(&format!("socket-patch-{UUID}")),
                "{shape}: the refusal names the live registry: {detail}"
            );
            assert!(
                !root.join(format!(".socket/vendor/cargo/{UUID}")).exists(),
                "{shape}: nothing was half-vendored"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join("Cargo.toml"))
                    .await
                    .unwrap(),
                manifest,
                "{shape}: the manifest is untouched"
            );
        }
    }

    /// A dependency pinned to a registry that is NOT ours, and an unpinned
    /// one, are not hosted residue: vendoring proceeds.
    #[tokio::test]
    async fn test_foreign_registry_pin_is_not_hosted_residue() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n\
             [dependencies.cfg-if]\nversion = \"1\"\nregistry = \"corp-mirror\"\n",
        )
        .await
        .unwrap();
        let (result, _entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "vendor failed: {:?}", result.error);
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

    /// A manifest WRITE failure after a successful local build (the
    /// project root is read-only, so the atomic rewrite cannot stage its
    /// sibling file, while `.socket/` stays writable) unwinds the copy and
    /// prunes the husks; the manifest and the lock are never touched.
    #[cfg(unix)]
    #[tokio::test]
    async fn manifest_write_failure_unwinds_copy() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores directory permission bits
        }
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let manifest_before = tokio::fs::read(root.join("Cargo.toml")).await.unwrap();
        tokio::fs::create_dir_all(root.join(".socket/vendor/cargo"))
            .await
            .unwrap();
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o555)).unwrap();
        let outcome = run_vendor(PURL, root, &blobs, &pristine, &record, false).await;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();

        let (result, entry, _warnings) = expect_done(outcome);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("failed to update Cargo.toml"),
            "error names the manifest: {:?}",
            result.error
        );
        assert!(
            !root.join(format!(".socket/vendor/cargo/{UUID}")).exists(),
            "the copy is unwound"
        );
        assert_eq!(
            tokio::fs::read(root.join("Cargo.toml")).await.unwrap(),
            manifest_before
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body(),
            "the detach never ran"
        );
    }

    /// A missing or unparseable root manifest is refused up front, before
    /// any copy or lock edit (the manifest is where the wiring lives).
    #[tokio::test]
    async fn missing_or_unparseable_manifest_is_refused() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::write(root.join("Cargo.toml"), "[package\nname = 1\n")
            .await
            .unwrap();
        expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "cargo_manifest_unparseable",
        );
        tokio::fs::remove_file(root.join("Cargo.toml"))
            .await
            .unwrap();
        let detail = expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "cargo_manifest_unreadable",
        );
        assert!(detail.contains("Cargo.toml"), "{detail}");
        assert!(!root.join(".socket/vendor").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// A symlinked root manifest is refused: the atomic rewrite would
    /// replace the link with a detached copy.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_manifest_is_refused() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::rename(root.join("Cargo.toml"), root.join("real.toml"))
            .await
            .unwrap();
        std::os::unix::fs::symlink("real.toml", root.join("Cargo.toml")).unwrap();
        expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "cargo_manifest_symlink_unsupported",
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// A failed marker write on a FRESH vendor (a directory squatting the
    /// marker path makes the atomic rename fail) must not undo the
    /// fully-wired vendor: success + a `vendor_marker_write_failed` warning, with
    /// copy, config, and lock all wired.
    #[tokio::test]
    async fn marker_write_failure_warns_but_vendor_succeeds() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::create_dir_all(
            root.join(format!(".socket/vendor/cargo/{UUID}/{VENDOR_MARKER_FILE}")),
        )
        .await
        .unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "the wired vendor still emits its entry");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
            "the failed marker write is surfaced: {warnings:?}"
        );
        // The vendor is otherwise fully wired.
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
        assert_eq!(
            manifest_path(root).await.as_deref(),
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
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("not a cargo purl"),
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
        assert!(manifest_path(root).await.is_none());
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
            manifest_path(root).await.as_deref(),
            Some(copy_rel().as_str()),
            "the config entry must not be dropped on a failed lock restore"
        );
        assert!(
            root.join(copy_rel()).exists(),
            "the artifact must survive a failed revert"
        );
    }

    /// Revert's legacy-config cleanup failing (a directory squatting
    /// `.cargo/config.toml`) reports "failed to update .cargo/config.toml"
    /// and leaves the artifact in place (deletion is last). The lock restore
    /// and the manifest drop ran FIRST — documenting the order: a re-run
    /// recovers, with the restore degrading to an Ok(false) skip.
    #[tokio::test]
    async fn test_revert_config_drop_failure_reports_error() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
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
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body(),
            "the lock is restored before the config edit"
        );
        assert!(
            manifest_path(root).await.is_none(),
            "manifest entry dropped"
        );
        assert!(
            root.join(copy_rel()).exists(),
            "artifact untouched — its deletion comes after the config edit"
        );
    }

    /// An unparseable manifest fails the revert BEFORE the lock is restored
    /// (a restored lock under a still-live `[patch]` breaks `--locked`).
    #[tokio::test]
    async fn test_revert_unparseable_manifest_fails_before_the_lock() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_result, entry, _warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        let lock_wired = tokio::fs::read(root.join("Cargo.lock")).await.unwrap();
        tokio::fs::write(root.join("Cargo.toml"), "[package\n")
            .await
            .unwrap();
        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(!out.success);
        assert!(
            out.error
                .as_deref()
                .unwrap_or("")
                .contains("failed to update Cargo.toml"),
            "{:?}",
            out.error
        );
        assert_eq!(
            tokio::fs::read(root.join("Cargo.lock")).await.unwrap(),
            lock_wired,
            "the lock is untouched"
        );
        assert!(root.join(copy_rel()).exists());
    }

    // ── v5 manifest wiring: legacy migration, multi-version, conflicts ───

    /// The pre-v5 wiring for the fixture: the legacy `.cargo/config.toml`
    /// entry (written by the test-only legacy writer), the copy, and a
    /// detached lock — i.e. what an old release's `vendor` left behind.
    async fn legacy_vendor(root: &Path, blobs: &Path, pristine: &Path, record: &PatchRecord) {
        expect_done(run_vendor(PURL, root, blobs, pristine, record, false).await);
        cargo_manifest::drop_patch_entries(root, "cfg-if", "1.0.4", false)
            .await
            .unwrap();
        cargo_config::ensure_patch_entry(root, "cfg-if", &copy_rel(), false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn legacy_config_wiring_migrates_to_the_manifest_on_rerun() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let manifest_pristine = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        legacy_vendor(root, &blobs, &pristine, &record).await;
        let lock_wired = tokio::fs::read(root.join("Cargo.lock")).await.unwrap();
        assert!(manifest_path(root).await.is_none());

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            warnings.iter().any(|w| w.code == "cargo_wiring_migrated"),
            "{warnings:?}"
        );
        assert_eq!(manifest_path(root).await, Some(copy_rel()));
        assert!(
            !root.join(".cargo").exists(),
            "the emptied socket-created config (and .cargo/) are cleaned"
        );
        assert_eq!(
            tokio::fs::read(root.join("Cargo.lock")).await.unwrap(),
            lock_wired,
            "the lock is already detached — untouched"
        );
        // The fresh entry names the manifest; the lock originals come from
        // the replaced ledger entry (carry_forward_wiring).
        let entry = entry.expect("a migration emits the updated entry");
        assert_eq!(entry.wiring.len(), 1);
        assert_eq!(entry.wiring[0].file, "Cargo.toml");
        assert_eq!(entry.lock, None);
        // A second re-run is the in-sync no-op.
        let (_, entry2, warnings2) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(entry2.is_none() && warnings2.is_empty(), "{warnings2:?}");

        // Revert (with originals carried forward) restores everything.
        let mut full = entry;
        full.lock = Some(CargoLockOriginal {
            source: SOURCE.into(),
            checksum: Some(CHECKSUM.into()),
        });
        let out = revert_cargo_vendor(&full, root, false).await;
        assert!(out.success, "{:?}", out.error);
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            manifest_pristine
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// A user's own config content survives the migration; only the
    /// Socket-owned entry moves.
    #[tokio::test]
    async fn legacy_migration_keeps_user_config_content() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        legacy_vendor(root, &blobs, &pristine, &record).await;
        let cfg = root.join(".cargo/config.toml");
        let body = tokio::fs::read_to_string(&cfg).await.unwrap();
        tokio::fs::write(&cfg, format!("[build]\njobs = 4\n\n{body}"))
            .await
            .unwrap();
        let (result, _, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success);
        assert_eq!(
            tokio::fs::read_to_string(&cfg).await.unwrap(),
            "[build]\njobs = 4\n"
        );
    }

    /// A patch update (new uuid) over legacy wiring: the full path wires the
    /// manifest to the new copy and retires the legacy entry.
    #[tokio::test]
    async fn uuid_bump_over_legacy_wiring_moves_to_the_manifest() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        legacy_vendor(root, &blobs, &pristine, &record).await;
        let mut record2 = record.clone();
        record2.uuid = UUID2.into();
        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record2, false).await);
        assert!(result.success, "{:?}", result.error);
        let new_rel = format!(".socket/vendor/cargo/{UUID2}/cfg-if-1.0.4");
        assert_eq!(manifest_path(root).await, Some(new_rel));
        assert!(cargo_config::legacy_socket_entries(root, "cfg-if")
            .await
            .is_empty());
        assert!(warnings.iter().any(|w| w.code == "cargo_wiring_migrated"));
        assert_eq!(entry.unwrap().lock, None);
    }

    /// Revert drops a legacy config entry too (pre-v5 ledger entry).
    #[tokio::test]
    async fn revert_cleans_legacy_config_wiring() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        cargo_manifest::drop_patch_entries(root, "cfg-if", "1.0.4", false)
            .await
            .unwrap();
        cargo_config::ensure_patch_entry(root, "cfg-if", &copy_rel(), false)
            .await
            .unwrap();
        let mut entry = entry.unwrap();
        entry.wiring[0].file = ".cargo/config.toml".into();
        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(out.success, "{:?}", out.error);
        assert!(!root.join(".cargo").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
    }

    /// `repair`'s migration step: legacy wiring pointing at the entry's copy
    /// moves into the manifest, and the returned entry's patch record names
    /// Cargo.toml; nothing to do → `None`.
    #[tokio::test]
    async fn migrate_legacy_wiring_for_repair() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let mut entry = entry.unwrap();
        assert!(migrate_legacy_wiring(&entry, root, false)
            .await
            .unwrap()
            .is_none());
        cargo_manifest::drop_patch_entries(root, "cfg-if", "1.0.4", false)
            .await
            .unwrap();
        cargo_config::ensure_patch_entry(root, "cfg-if", &copy_rel(), false)
            .await
            .unwrap();
        entry.wiring[0].file = ".cargo/config.toml".into();
        let (dry, _) = migrate_legacy_wiring(&entry, root, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dry.wiring[0].file, "Cargo.toml");
        assert!(
            manifest_path(root).await.is_none(),
            "dry run writes nothing"
        );
        let (migrated, warnings) = migrate_legacy_wiring(&entry, root, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(warnings[0].code, "cargo_wiring_migrated");
        assert_eq!(migrated.wiring.len(), 2);
        assert_eq!(migrated.wiring[0].file, "Cargo.toml");
        assert_eq!(migrated.wiring[1].file, "Cargo.lock");
        assert_eq!(migrated.lock, entry.lock);
        assert_eq!(manifest_path(root).await, Some(copy_rel()));
        assert!(!root.join(".cargo").exists());
    }

    /// A second version of the same crate gets the Socket-owned key with
    /// `package =` — the first version's entry is never clobbered (the pre-v5
    /// config wiring keyed by crate name overwrote it).
    #[tokio::test]
    async fn two_versions_of_one_crate_get_distinct_keys() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let lock = format!(
            "{}\n[[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\nsource = \"{SOURCE}\"\nchecksum = \"{}\"\n",
            lock_body(),
            "e".repeat(64)
        );
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();
        let pristine2 = root.join("registry/cfg-if-0.1.10");
        crate::patch::copy_tree::fresh_copy(&pristine, &pristine2, None)
            .await
            .unwrap();
        tokio::fs::write(
            pristine2.join("Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n",
        )
        .await
        .unwrap();
        let mut record2 = record.clone();
        record2.uuid = UUID2.into();
        let purl2 = "pkg:cargo/cfg-if@0.1.10";

        let (r1, e1, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let (r2, e2, _) =
            expect_done(run_vendor(purl2, root, &blobs, &pristine2, &record2, false).await);
        assert!(r1.success && r2.success, "{:?} {:?}", r1.error, r2.error);
        let (e1, e2) = (e1.unwrap(), e2.unwrap());
        assert_eq!(e1.wiring[0].key.as_deref(), Some("cfg-if-socket-9f6b2c4e"));
        assert_eq!(e2.wiring[0].key.as_deref(), Some("cfg-if-socket-0a1b2c3d"));
        let manifest = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert!(manifest.contains(&format!(
            "cfg-if-socket-9f6b2c4e = {{ package = \"cfg-if\", path = \"{}\" }}",
            copy_rel()
        )));
        assert!(manifest.contains(&format!(
            "cfg-if-socket-0a1b2c3d = {{ package = \"cfg-if\", path = \".socket/vendor/cargo/{UUID2}/cfg-if-0.1.10\" }}"
        )));
        // Both re-runs are in sync; each probe sees its own wiring.
        for (purl, src, rec) in [(PURL, &pristine, &record), (purl2, &pristine2, &record2)] {
            let (_, e, w) = expect_done(run_vendor(purl, root, &blobs, src, rec, false).await);
            assert!(e.is_none() && w.is_empty(), "{purl}: {w:?}");
        }
        assert_eq!(vendored_entry_in_use(&e1, root).await, Some(true));
        assert_eq!(vendored_entry_in_use(&e2, root).await, Some(true));
        // Reverting one version leaves the other wired.
        assert!(revert_cargo_vendor(&e2, root, false).await.success);
        assert_eq!(manifest_path(root).await, Some(copy_rel()));
        assert!(revert_cargo_vendor(&e1, root, false).await.success);
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock
        );
    }

    /// A user-authored manifest entry for the crate refuses unless its path
    /// crate is provably ANOTHER version (then the Socket key is used).
    #[tokio::test]
    async fn user_manifest_entry_refuses_unless_provably_another_version() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let base = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        for user in [
            "cfg-if = { git = \"https://example.com/cfg-if\" }",
            "cfg-if = { path = \"missing-fork\" }",
            "fork = { package = \"cfg-if\", path = \"fork-104\" }",
        ] {
            tokio::fs::create_dir_all(root.join("fork-104"))
                .await
                .unwrap();
            tokio::fs::write(
                root.join("fork-104/Cargo.toml"),
                "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
            )
            .await
            .unwrap();
            let manifest = format!("{base}\n[patch.crates-io]\n{user}\n");
            tokio::fs::write(root.join("Cargo.toml"), &manifest)
                .await
                .unwrap();
            expect_refused(
                run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
                "user_authored_patch_entry",
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join("Cargo.toml"))
                    .await
                    .unwrap(),
                manifest
            );
        }
        tokio::fs::create_dir_all(root.join("fork-09"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("fork-09/Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"0.9.0\"\n",
        )
        .await
        .unwrap();
        let manifest = format!("{base}\n[patch.crates-io]\ncfg-if = {{ path = \"fork-09\" }}\n");
        tokio::fs::write(root.join("Cargo.toml"), &manifest)
            .await
            .unwrap();
        let (result, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            entry.wiring[0].key.as_deref(),
            Some("cfg-if-socket-9f6b2c4e")
        );
        assert!(revert_cargo_vendor(&entry, root, false).await.success);
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            manifest,
            "revert is byte-identical around the user's entry"
        );
    }

    /// CRLF manifests stay CRLF through vendor and revert.
    #[tokio::test]
    async fn crlf_manifest_round_trips() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let crlf = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap()
            .replace('\n', "\r\n");
        tokio::fs::write(root.join("Cargo.toml"), &crlf)
            .await
            .unwrap();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let wired = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        assert!(!wired.replace("\r\n", "").contains('\n'), "{wired:?}");
        assert!(
            revert_cargo_vendor(&entry.unwrap(), root, false)
                .await
                .success
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            crlf
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

    // ── source-flip regression: the hot path decides "in sync" from the
    //    COMMITTED copy before any service call, so a service ↔ local flip
    //    between runs is a byte-identical no-op with no request. ──

    async fn flip_run(
        root: &Path,
        blobs: &Path,
        pristine: &Path,
        record: &PatchRecord,
        uri: &str,
    ) -> (ApplyResult, Option<VendorEntry>, Vec<VendorWarning>) {
        let sources = PatchSources::blobs_only(blobs);
        expect_done(
            vendor_cargo_crate(
                PURL,
                pristine,
                root,
                record,
                &sources,
                "2026-06-09T00:00:00Z",
                false,
                false,
                Some(&cargo_service_cfg(uri, VendorSource::Auto, false)),
            )
            .await,
        )
    }

    /// A service crate that differs from the local build in NON-patched bytes.
    fn flip_service_crate() -> Vec<u8> {
        make_crate_tgz(
            "cfg-if-1.0.4",
            &[
                ("src/lib.rs", PATCHED),
                (
                    "Cargo.toml",
                    b"[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n# service\n",
                ),
                ("README.service.md", b"built by the service\n"),
            ],
        )
    }

    #[tokio::test]
    async fn flip_local_then_service_is_noop() {
        use crate::vendor::test_support as ts;
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let down = wiremock::MockServer::start().await;
        ts::mount_503(&down).await;
        let (r1, e1, _) = flip_run(root, &blobs, &pristine, &record, &down.uri()).await;
        assert!(r1.success && e1.is_some());
        let before = ts::tree_snapshot(root);
        let up = wiremock::MockServer::start().await;
        let tgz = flip_service_crate();
        mount_cargo_granted(&up, &sri_sha512(&tgz), &tgz).await;
        let (r2, e2, w2) = flip_run(root, &blobs, &pristine, &record, &up.uri()).await;
        assert!(r2.success && e2.is_none() && r2.files_patched.is_empty() && w2.is_empty());
        assert_eq!(ts::tree_snapshot(root), before, "tree byte-identical");
        assert_eq!(ts::request_count(&up).await, 0);
    }

    #[tokio::test]
    async fn flip_service_then_local_is_noop() {
        use crate::vendor::test_support as ts;
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let up = wiremock::MockServer::start().await;
        let tgz = flip_service_crate();
        mount_cargo_granted(&up, &sri_sha512(&tgz), &tgz).await;
        let (r1, e1, w1) = flip_run(root, &blobs, &pristine, &record, &up.uri()).await;
        assert!(r1.success && e1.is_some());
        assert!(ts::has_warning(&w1, "vendor_prebuilt_downloaded"));
        let before = ts::tree_snapshot(root);
        let down = wiremock::MockServer::start().await;
        ts::mount_503(&down).await;
        let (r2, e2, w2) = flip_run(root, &blobs, &pristine, &record, &down.uri()).await;
        assert!(r2.success && e2.is_none() && w2.is_empty());
        assert_eq!(ts::tree_snapshot(root), before);
        assert_eq!(ts::request_count(&down).await, 0);
    }

    /// `--vendor-source=service` with no configured client must fail
    /// closed, never quietly build locally.
    #[tokio::test]
    async fn service_mode_without_client_refuses() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let mut cfg = cargo_service_cfg("http://127.0.0.1:1", VendorSource::Service, false);
        cfg.client = None;
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
            Some(&cfg),
        )
        .await;
        expect_refused(outcome, "vendor_prebuilt_required");
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID}")).exists());
    }

    /// Vendor locally, then delete the committed copy so the next run takes
    /// the wired-copy rebuild path.
    async fn wired_with_missing_copy() -> (tempfile::TempDir, PathBuf, PathBuf, PatchRecord) {
        let (dir, blobs, pristine, record) = fixture().await;
        expect_done(run_vendor(PURL, dir.path(), &blobs, &pristine, &record, false).await);
        crate::patch::copy_tree::remove_tree(&dir.path().join(copy_rel()))
            .await
            .unwrap();
        (dir, blobs, pristine, record)
    }

    /// The wired-copy rebuild honours `--vendor-source=service` like the
    /// fresh path: no API client or `--offline` refuses instead of quietly
    /// rebuilding locally, and the copy is not recreated.
    #[tokio::test]
    async fn wired_rebuild_service_mode_unreachable_refuses() {
        for (offline, want) in [
            (false, "vendor_prebuilt_required"),
            (true, "vendor_service_offline_conflict"),
        ] {
            let (dir, blobs, pristine, record) = wired_with_missing_copy().await;
            let root = dir.path();
            let mut cfg = cargo_service_cfg("http://127.0.0.1:1", VendorSource::Service, offline);
            if !offline {
                cfg.client = None;
            }
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
                Some(&cfg),
            )
            .await;
            expect_refused(outcome, want);
            assert!(
                !root.join(copy_rel()).exists(),
                "service mode must not rebuild the copy locally (offline={offline})"
            );
        }
    }

    /// Online `service` mode rebuilds the wired copy from the prebuilt crate,
    /// not from the pristine source (a deliberately-missing path here).
    #[tokio::test]
    async fn wired_rebuild_service_mode_uses_prebuilt_crate() {
        let (dir, blobs, _pristine, record) = wired_with_missing_copy().await;
        let root = dir.path();
        let crate_tgz = make_crate_tgz(
            "cfg-if-1.0.4",
            &[
                ("src/lib.rs", PATCHED),
                (
                    "Cargo.toml",
                    b"[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
                ),
            ],
        );
        let server = wiremock::MockServer::start().await;
        mount_cargo_granted(&server, &sri_sha512(&crate_tgz), &crate_tgz).await;
        let sources = PatchSources::blobs_only(&blobs);
        let outcome = vendor_cargo_crate(
            PURL,
            &root.join("no-such-pristine"),
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
        assert!(entry.is_none(), "artifact-only rebuild records no entry");
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_downloaded"),
            "{warnings:?}"
        );
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
    }

    // ── review follow-ups: shadowing, workspace root, recovery ───────────

    /// A second locked version (cfg-if 0.1.10) plus its pristine source and
    /// a record under [`UUID2`].
    async fn add_second_version(
        root: &Path,
        pristine: &Path,
        record: &PatchRecord,
    ) -> (PathBuf, PatchRecord, &'static str, String) {
        let lock = format!(
            "{}\n[[package]]\nname = \"cfg-if\"\nversion = \"0.1.10\"\nsource = \"{SOURCE}\"\nchecksum = \"{}\"\n",
            lock_body(),
            "e".repeat(64)
        );
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();
        let pristine2 = root.join("registry/cfg-if-0.1.10");
        crate::patch::copy_tree::fresh_copy(pristine, &pristine2, None)
            .await
            .unwrap();
        tokio::fs::write(
            pristine2.join("Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n",
        )
        .await
        .unwrap();
        let mut record2 = record.clone();
        record2.uuid = UUID2.into();
        (pristine2, record2, "pkg:cargo/cfg-if@0.1.10", lock)
    }

    /// Cargo lets a manifest `[patch."<crates.io URL>"]` table replace
    /// `[patch.crates-io]` wholesale: vendoring refuses before any write.
    #[tokio::test]
    async fn url_spelled_crates_io_patch_table_refuses_before_any_write() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let manifest = format!(
            "{}\n[patch.\"https://github.com/rust-lang/crates.io-index\"]\nitoa = {{ path = \"../itoa\" }}\n",
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap()
        );
        tokio::fs::write(root.join("Cargo.toml"), &manifest)
            .await
            .unwrap();
        let detail = expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            "cargo_manifest_patch_source_alias",
        );
        assert!(detail.contains("crates.io-index"), "{detail}");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.toml"))
                .await
                .unwrap(),
            manifest
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_body()
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// Config files in ANCESTOR directories are merged by cargo too (and
    /// replace a manifest item with the same key): a user entry there that
    /// may override this crate@version refuses, and its keys are avoided.
    #[tokio::test]
    async fn ancestor_config_patch_entries_are_checked() {
        let (dir, blobs, pristine, record) = fixture().await;
        let outer = dir.path();
        // Nest the project one level down so `outer` is its ancestor.
        let root = outer.join("rust");
        tokio::fs::create_dir_all(&root).await.unwrap();
        for f in ["Cargo.toml", "Cargo.lock"] {
            tokio::fs::rename(outer.join(f), root.join(f))
                .await
                .unwrap();
        }
        tokio::fs::create_dir_all(outer.join("forks/cfg-if"))
            .await
            .unwrap();
        tokio::fs::write(
            outer.join("forks/cfg-if/Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(outer.join(".cargo"))
            .await
            .unwrap();
        // Same version, relative to the ancestor's root: may override.
        tokio::fs::write(
            outer.join(".cargo/config.toml"),
            "[patch.crates-io]\ncfg-if = { path = \"forks/cfg-if\" }\n",
        )
        .await
        .unwrap();
        let detail = expect_refused(
            run_vendor(PURL, &root, &blobs, &pristine, &record, false).await,
            "user_authored_patch_entry",
        );
        assert!(detail.contains("config.toml"), "{detail}");

        // Another version under the Socket key's spelling: allowed, and the
        // key it occupies is avoided (a config item would replace ours).
        tokio::fs::write(
            outer.join("forks/cfg-if/Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            outer.join(".cargo/config.toml"),
            "[patch.crates-io]\ncfg-if-socket-9f6b2c4e = { package = \"cfg-if\", path = \"forks/cfg-if\" }\n",
        )
        .await
        .unwrap();
        let (result, entry, _) =
            expect_done(run_vendor(PURL, &root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            entry.unwrap().wiring[0].key.as_deref(),
            Some("cfg-if-socket-9f6b2c4e1d3a4f6b8c2d7e5a9b1c3d5f")
        );
    }

    /// The chain reader covers the project, every ancestor, and
    /// `$CARGO_HOME` (whose relative paths resolve against its parent);
    /// only the project's own Socket-shaped paths count as Socket-owned.
    #[tokio::test]
    async fn config_chain_reads_ancestors_and_cargo_home() {
        let dir = tempfile::tempdir().unwrap();
        let outer = tokio::fs::canonicalize(dir.path()).await.unwrap();
        let root = outer.join("a/b");
        let home = outer.join("home/.cargo");
        let socket = |key: &str| {
            format!(
                "[patch.crates-io]\n{key} = {{ path = \".socket/vendor/cargo/{UUID}/cfg-if-1.0.4\" }}\n"
            )
        };
        for (d, body) in [
            (root.join(".cargo"), socket("proj")),
            (outer.join("a/.cargo"), socket("anc")),
            (home.clone(), socket("home")),
        ] {
            tokio::fs::create_dir_all(&d).await.unwrap();
            tokio::fs::write(d.join("config.toml"), body).await.unwrap();
        }
        let chain = cargo_config::read_config_chain_with(&root, &home).await;
        let got: Vec<(String, bool, bool, PathBuf)> = chain
            .iter()
            .map(|c| {
                (
                    c.entries[0].key.clone(),
                    c.project,
                    c.entries[0].socket_owned,
                    c.base.clone(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("proj".to_string(), true, true, root.clone()),
                ("anc".to_string(), false, false, outer.join("a")),
                ("home".to_string(), false, false, outer.join("home")),
            ]
        );
    }

    /// Cargo ignores `[patch]` in a workspace MEMBER's manifest: vendoring
    /// from a member directory refuses instead of writing dead wiring.
    #[tokio::test]
    async fn member_manifest_is_not_the_workspace_root() {
        let (dir, blobs, pristine, record) = fixture().await;
        let outer = dir.path();
        let member = outer.join("m");
        tokio::fs::create_dir_all(&member).await.unwrap();
        tokio::fs::rename(outer.join("Cargo.toml"), member.join("Cargo.toml"))
            .await
            .unwrap();
        tokio::fs::remove_file(outer.join("Cargo.lock"))
            .await
            .unwrap();
        let member_manifest = tokio::fs::read_to_string(member.join("Cargo.toml"))
            .await
            .unwrap();
        for ws in [
            "[workspace]\nmembers = [\"m\"]\n",
            "[workspace]\nmembers = [\"*\"]\n",
            "[workspace]\n",
        ] {
            tokio::fs::write(outer.join("Cargo.toml"), ws)
                .await
                .unwrap();
            let detail = expect_refused(
                run_vendor(PURL, &member, &blobs, &pristine, &record, false).await,
                NOT_WORKSPACE_ROOT,
            );
            assert!(detail.contains("workspace rooted at"), "{detail}");
            assert_eq!(
                tokio::fs::read_to_string(member.join("Cargo.toml"))
                    .await
                    .unwrap(),
                member_manifest
            );
        }
        // An explicitly excluded directory is its own root.
        tokio::fs::write(
            outer.join("Cargo.toml"),
            "[workspace]\nmembers = []\nexclude = [\"m\"]\n",
        )
        .await
        .unwrap();
        let (result, _, _) =
            expect_done(run_vendor(PURL, &member, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);

        // `package.workspace` names another root.
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let manifest = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap()
            .replace(
                "version = \"0.1.0\"\n",
                "version = \"0.1.0\"\nworkspace = \"..\"\n",
            );
        tokio::fs::write(root.join("Cargo.toml"), manifest)
            .await
            .unwrap();
        let detail = expect_refused(
            run_vendor(PURL, root, &blobs, &pristine, &record, false).await,
            NOT_WORKSPACE_ROOT,
        );
        assert!(detail.contains("package.workspace"), "{detail}");
    }

    /// Cargo lets a config `[patch]` item replace the manifest item with the
    /// same key (any version): an in-sync re-run over an entry whose key a
    /// config file now uses moves it to a fresh key instead of reporting
    /// success over wiring cargo ignores.
    #[tokio::test]
    async fn in_sync_rerun_moves_an_entry_off_a_config_shadowed_key() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (r, first, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(r.success);
        assert_eq!(
            first.unwrap().wiring[0].key.as_deref(),
            Some("cfg-if-socket-9f6b2c4e")
        );
        // A user's fork of ANOTHER version under the same key.
        tokio::fs::create_dir_all(root.join("fork-01"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("fork-01/Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"0.1.10\"\n",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(root.join(".cargo"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".cargo/config.toml"),
            "[patch.crates-io]\ncfg-if-socket-9f6b2c4e = { package = \"cfg-if\", path = \"fork-01\" }\n",
        )
        .await
        .unwrap();
        let lock_before = tokio::fs::read(root.join("Cargo.lock")).await.unwrap();
        let (r, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(r.success, "{:?}", r.error);
        let entry = entry.expect("the re-keyed entry is recorded");
        assert_eq!(
            entry.wiring[0].key.as_deref(),
            Some("cfg-if-socket-9f6b2c4e1d3a4f6b8c2d7e5a9b1c3d5f")
        );
        let keys: Vec<String> = cargo_manifest::read_patch_entries(root)
            .await
            .into_iter()
            .map(|e| e.key)
            .collect();
        assert_eq!(keys, vec!["cfg-if-socket-9f6b2c4e1d3a4f6b8c2d7e5a9b1c3d5f"]);
        assert_eq!(manifest_path(root).await, Some(copy_rel()));
        assert_eq!(
            tokio::fs::read(root.join("Cargo.lock")).await.unwrap(),
            lock_before
        );
        // The user's config is untouched.
        assert!(tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap()
            .contains("fork-01"));
    }

    /// The hosted takeover's missing-ledger probe is version-scoped: another
    /// vendored version of the crate does not count.
    #[tokio::test]
    async fn socket_wiring_present_is_version_scoped() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (pristine2, record2, purl2, _) = add_second_version(root, &pristine, &record).await;
        let (r, _, _) =
            expect_done(run_vendor(purl2, root, &blobs, &pristine2, &record2, false).await);
        assert!(r.success, "{:?}", r.error);
        assert!(socket_wiring_present(root, "cfg-if", "0.1.10").await);
        assert!(!socket_wiring_present(root, "cfg-if", "1.0.4").await);
        // Legacy config wiring is version-scoped too.
        cargo_config::ensure_patch_entry(root, "cfg-if", &copy_rel(), false)
            .await
            .unwrap();
        assert!(socket_wiring_present(root, "cfg-if", "1.0.4").await);
    }

    /// A pre-v5 release keyed the config `[patch]` by crate name, so
    /// vendoring a second version repointed the first version's entry: its
    /// lock entry stayed detached with no wiring. A v5 re-run heals it
    /// (the committed copy proves the detach was Socket's) instead of
    /// failing on the already-detached lock entry.
    #[tokio::test]
    async fn pre_v5_multi_version_overwrite_is_healed_by_a_rerun() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (pristine2, record2, purl2, _) = add_second_version(root, &pristine, &record).await;
        let mut first: Option<VendorEntry> = None;
        for (purl, src, rec) in [(PURL, &pristine, &record), (purl2, &pristine2, &record2)] {
            let (r, e, _) = expect_done(run_vendor(purl, root, &blobs, src, rec, false).await);
            assert!(r.success, "{purl}: {:?}", r.error);
            first = first.or(e);
        }
        let first = first.unwrap();
        // Rewrite to the clobbered pre-v5 shape.
        for v in ["1.0.4", "0.1.10"] {
            cargo_manifest::drop_patch_entries(root, "cfg-if", v, false)
                .await
                .unwrap();
        }
        let rel2 = format!(".socket/vendor/cargo/{UUID2}/cfg-if-0.1.10");
        cargo_config::ensure_patch_entry(root, "cfg-if", &rel2, false)
            .await
            .unwrap();
        let lock_before = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();

        // `repair`'s step restores the lost entry (dry run writes nothing)…
        let (_, dry) = migrate_legacy_wiring(&first, root, true)
            .await
            .unwrap()
            .expect("the unwired entry is restorable");
        assert_eq!(dry[0].code, "cargo_wiring_restored");
        assert!(manifest_path(root).await.is_none());
        let (restored, warnings) = migrate_legacy_wiring(&first, root, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(warnings[0].code, "cargo_wiring_restored");
        assert_eq!(restored.wiring[0].file, "Cargo.toml");
        assert_eq!(restored.lock, first.lock, "the lock originals are kept");
        assert_eq!(manifest_path(root).await, Some(copy_rel()));
        cargo_manifest::drop_patch_entries(root, "cfg-if", "1.0.4", false)
            .await
            .unwrap();

        // …and so does a plain vendor re-run.
        let (result, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("rewired");
        assert_eq!(entry.lock, None, "originals carry forward from the ledger");
        assert_eq!(manifest_path(root).await, Some(copy_rel()));
        assert!(root.join(copy_rel()).join("src/lib.rs").exists());
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_before,
            "the lock entry was already detached"
        );
        // The other version migrates on its own re-run; both stay wired.
        let (r2, _, w2) =
            expect_done(run_vendor(purl2, root, &blobs, &pristine2, &record2, false).await);
        assert!(r2.success, "{:?}", r2.error);
        assert!(
            w2.iter().any(|w| w.code == "cargo_wiring_migrated"),
            "{w2:?}"
        );
        let keys: Vec<String> = cargo_manifest::read_patch_entries(root)
            .await
            .into_iter()
            .map(|e| e.key)
            .collect();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(!root.join(".cargo").exists());
    }

    /// A legacy config entry that cannot be removed during a uuid-bump
    /// migration fails the run and unwinds it: nothing may be left pointing
    /// at the old copy the caller's stale sweep deletes.
    #[cfg(unix)]
    #[tokio::test]
    async fn unremovable_legacy_wiring_unwinds_a_uuid_bump() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores mode bits
        }
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        legacy_vendor(root, &blobs, &pristine, &record).await;
        let manifest_before = tokio::fs::read_to_string(root.join("Cargo.toml"))
            .await
            .unwrap();
        let config_before = tokio::fs::read_to_string(root.join(".cargo/config.toml"))
            .await
            .unwrap();
        let lock_before = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        let cargo_dir = root.join(".cargo");
        std::fs::set_permissions(&cargo_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut record2 = record.clone();
        record2.uuid = UUID2.into();
        let outcome = run_vendor(PURL, root, &blobs, &pristine, &record2, false).await;
        std::fs::set_permissions(&cargo_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let (result, entry, _) = expect_done(outcome);
        assert!(!result.success);
        assert!(entry.is_none());
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("cargo_legacy_wiring_kept")),
            "{:?}",
            result.error
        );
        for (file, before) in [
            ("Cargo.toml", &manifest_before),
            (".cargo/config.toml", &config_before),
            ("Cargo.lock", &lock_before),
        ] {
            assert_eq!(
                &tokio::fs::read_to_string(root.join(file)).await.unwrap(),
                before,
                "{file}"
            );
        }
        assert!(root.join(copy_rel()).exists(), "the live copy stays");
        assert!(!root.join(format!(".socket/vendor/cargo/{UUID2}")).exists());
    }

    /// The atomic rewrite would replace a symlinked manifest with a detached
    /// regular file: a revert that must edit it refuses before any write.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_refuses_a_symlinked_manifest() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        let target = root.join("shared-Cargo.toml");
        tokio::fs::rename(root.join("Cargo.toml"), &target)
            .await
            .unwrap();
        std::os::unix::fs::symlink(&target, root.join("Cargo.toml")).unwrap();
        let lock_before = tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap();
        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(!out.success);
        assert!(
            out.error
                .as_deref()
                .is_some_and(|e| e.contains("cargo_manifest_symlink_unsupported")),
            "{:?}",
            out.error
        );
        assert!(crate::utils::fs::is_symlink(&root.join("Cargo.toml")).await);
        assert_eq!(
            tokio::fs::read_to_string(root.join("Cargo.lock"))
                .await
                .unwrap(),
            lock_before,
            "nothing was reverted"
        );
        assert!(root.join(copy_rel()).exists());
    }

    // ── tagged versions ──────────────────────────────────────────────────

    fn tagged(uuid: &str) -> String {
        format!("1.0.4+socket.{uuid}")
    }

    async fn lock_text(root: &Path) -> String {
        tokio::fs::read_to_string(root.join("Cargo.lock"))
            .await
            .unwrap()
    }

    async fn copy_toml(root: &Path) -> String {
        tokio::fs::read_to_string(root.join(copy_rel()).join("Cargo.toml"))
            .await
            .unwrap()
    }

    /// Strip the tag from a vendored project (the untagged shape an earlier
    /// v5 build — manifest wiring, untagged copy + lock — left behind).
    async fn untag_project(root: &Path) {
        let lock = lock_text(root).await.replace(&tagged(UUID), "1.0.4");
        tokio::fs::write(root.join("Cargo.lock"), lock)
            .await
            .unwrap();
        cargo_tag::untag_copy_manifest(&root.join(copy_rel())).await;
    }

    /// An untagged vendored project (copy + lock) is tagged by the next
    /// re-run — a fresh ledger entry (the caller carries the lock originals
    /// forward) with the `cargo_version_tagged` advisory — and the run after
    /// that is in sync. The revert still restores the pre-vendor lock
    /// byte-identically.
    #[tokio::test]
    async fn untagged_vendor_is_tagged_by_a_rerun() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, first, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let first = first.unwrap();
        let wired = lock_text(root).await;
        untag_project(root).await;
        assert!(!lock_text(root).await.contains("+socket."));
        assert_eq!(
            cargo_tag::copy_manifest_tag(&root.join(copy_rel())).await,
            None
        );

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(
            warnings.iter().any(|w| w.code == VERSION_TAGGED),
            "{warnings:?}"
        );
        let entry = entry.expect("a (re)tag records a fresh entry");
        assert_eq!(entry.lock, None, "originals come from the carried entry");
        assert_eq!(lock_text(root).await, wired, "the lock is tagged again");
        assert_eq!(
            cargo_tag::copy_manifest_tag(&root.join(copy_rel()))
                .await
                .as_deref(),
            Some(UUID)
        );

        let (_, again, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(again.is_none() && warnings.is_empty(), "{warnings:?}");

        let out = revert_cargo_vendor(&first, root, false).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(lock_text(root).await, lock_body());
    }

    /// A pre-v5 legacy config wiring over an untagged copy + lock: one
    /// re-run migrates the wiring AND tags.
    #[tokio::test]
    async fn legacy_config_untagged_vendor_is_migrated_and_tagged() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        untag_project(root).await;
        cargo_manifest::drop_patch_entries(root, "cfg-if", "1.0.4", false)
            .await
            .unwrap();
        cargo_config::ensure_patch_entry(root, "cfg-if", &copy_rel(), false)
            .await
            .unwrap();

        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let codes: Vec<&str> = warnings.iter().map(|w| w.code).collect();
        assert!(
            codes.contains(&"cargo_wiring_migrated") && codes.contains(&VERSION_TAGGED),
            "{codes:?}"
        );
        assert!(entry.is_some());
        assert_eq!(manifest_path(root).await, Some(copy_rel()));
        assert!(!root.join(".cargo").exists());
        assert!(lock_text(root).await.contains(&tagged(UUID)));
        assert!(copy_toml(root).await.contains(&tagged(UUID)));
    }

    /// `repair`'s migration step tags an untagged copy + lock (dry run
    /// writes nothing) and KEEPS a recorded file inventory: it still
    /// verifies over the tagged copy (the check drops exactly this uuid's
    /// tag from `Cargo.toml`), so nothing is re-baselined.
    #[tokio::test]
    async fn repair_migration_tags_an_untagged_vendor() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let mut entry = entry.unwrap();
        untag_project(root).await;
        entry.artifact.file_inventory = Some(
            crate::vendor::verify::compute_dir_inventory(&root.join(copy_rel()))
                .await
                .unwrap(),
        );
        let untagged_lock = lock_text(root).await;

        let (_, dry) = migrate_legacy_wiring(&entry, root, true)
            .await
            .unwrap()
            .expect("the untagged vendor needs a tag");
        assert_eq!(dry[0].code, VERSION_TAGGED);
        assert!(dry[0].detail.starts_with("would tag"), "{:?}", dry[0]);
        assert_eq!(
            lock_text(root).await,
            untagged_lock,
            "dry run writes nothing"
        );

        let (migrated, warnings) = migrate_legacy_wiring(&entry, root, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, VERSION_TAGGED);
        assert!(lock_text(root).await.contains(&tagged(UUID)));
        assert!(copy_toml(root).await.contains(&tagged(UUID)));
        assert_eq!(
            migrated.artifact.file_inventory, entry.artifact.file_inventory,
            "the recorded inventory is kept, never re-baselined"
        );
        crate::vendor::verify::verify_vendored_patch_record(root, &migrated, &record)
            .await
            .expect("the kept inventory verifies through this uuid's tag");
        assert!(migrate_legacy_wiring(&migrated, root, false)
            .await
            .unwrap()
            .is_none());
    }

    /// A copy that drifted BEFORE it was tagged (an unpatched file edited,
    /// or one planted) still fails the inventory check after the migration
    /// tags it; so does a copy manifest tagged for another uuid.
    #[tokio::test]
    async fn repair_migration_never_launders_pre_tag_drift() {
        for drift in ["manifest", "planted", "other_tag"] {
            let (dir, blobs, pristine, record) = fixture().await;
            let root = dir.path();
            let (_, entry, _) =
                expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
            let mut entry = entry.unwrap();
            untag_project(root).await;
            let copy = root.join(copy_rel());
            entry.artifact.file_inventory = Some(
                crate::vendor::verify::compute_dir_inventory(&copy)
                    .await
                    .unwrap(),
            );
            match drift {
                "manifest" => {
                    let text = copy_toml(root).await + "build = \"build.rs\"\n";
                    tokio::fs::write(copy.join("Cargo.toml"), text)
                        .await
                        .unwrap();
                }
                "planted" => {
                    tokio::fs::write(copy.join("build.rs"), "fn main() {}\n")
                        .await
                        .unwrap();
                }
                _ => {}
            }
            let (migrated, _) = migrate_legacy_wiring(&entry, root, false)
                .await
                .unwrap()
                .unwrap();
            if drift == "other_tag" {
                let text = copy_toml(root).await.replace(UUID, UUID2);
                tokio::fs::write(copy.join("Cargo.toml"), text)
                    .await
                    .unwrap();
            }
            assert_eq!(
                migrated.artifact.file_inventory,
                entry.artifact.file_inventory
            );
            let err = crate::vendor::verify::verify_vendored_patch_record(root, &migrated, &record)
                .await
                .expect_err(drift);
            assert!(err.contains("vendor_inventory_mismatch"), "{drift}: {err}");
        }
    }

    /// `repair`'s migration over a wired copy whose `Cargo.toml` cannot
    /// take the tag (no literal version) is the `cargo_version_untagged`
    /// warning — dry run and wet run alike — and nothing is written: the
    /// lock keeps its untagged entry, so copy and lock still agree.
    #[tokio::test]
    async fn repair_migration_over_an_untaggable_copy_warns_untagged() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        untag_project(root).await;
        let untaggable = "[package]\nname = \"cfg-if\"\nversion.workspace = true\n";
        tokio::fs::write(root.join(copy_rel()).join("Cargo.toml"), untaggable)
            .await
            .unwrap();
        let lock = lock_text(root).await;
        for dry_run in [true, false] {
            let (_, warnings) = migrate_legacy_wiring(&entry, root, dry_run)
                .await
                .unwrap()
                .expect("the untaggable copy is reported");
            let codes: Vec<&str> = warnings.iter().map(|w| w.code).collect();
            assert_eq!(codes, ["cargo_version_untagged"], "dry_run={dry_run}");
            assert!(
                warnings[0].detail.contains(COPY_UNTAGGABLE),
                "{:?}",
                warnings[0]
            );
            assert_eq!(lock_text(root).await, lock, "dry_run={dry_run}");
            assert_eq!(copy_toml(root).await, untaggable, "dry_run={dry_run}");
        }
    }

    /// A lock retag that passes its read-only proof but whose WRITE fails
    /// (the project root is read-only, so the atomic rewrite cannot stage
    /// its sibling, while the copy under `.socket/` stays writable) untags
    /// the copy again: copy and lock never disagree. Both callers — the
    /// vendor re-run's hot path and `repair`'s migration — report it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_lock_retag_write_untags_the_copy_again() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } == 0 {
            return; // root ignores directory permission bits
        }
        for via_repair in [false, true] {
            let (dir, blobs, pristine, record) = fixture().await;
            let root = dir.path();
            let (_, entry, _) =
                expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
            let entry = entry.unwrap();
            untag_project(root).await;
            let lock = lock_text(root).await;
            let copy = copy_toml(root).await;

            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o555)).unwrap();
            let error = if via_repair {
                let outcome = migrate_legacy_wiring(&entry, root, false).await;
                std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
                let (_, warnings) = outcome.unwrap().expect("the failed tag is reported");
                assert_eq!(warnings.len(), 1, "{warnings:?}");
                assert_eq!(warnings[0].code, "cargo_version_untagged");
                warnings[0].detail.clone()
            } else {
                let outcome = run_vendor(PURL, root, &blobs, &pristine, &record, false).await;
                std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755)).unwrap();
                let (result, again, _) = expect_done(outcome);
                assert!(!result.success && again.is_none());
                result.error.unwrap_or_default()
            };
            assert!(
                error.contains(LOCK_UNTAGGABLE),
                "via_repair={via_repair}: {error}"
            );
            assert_eq!(lock_text(root).await, lock, "via_repair={via_repair}");
            assert_eq!(
                copy_toml(root).await,
                copy,
                "via_repair={via_repair}: the copy is untagged again"
            );
            assert_eq!(
                cargo_tag::copy_manifest_tag(&root.join(copy_rel())).await,
                None
            );
        }
    }

    /// A lock whose detached entry is tagged for ANOTHER uuid while the
    /// wiring points at this copy (a lock checked out from another patch
    /// generation) is only stale: cargo re-locks an unlocked build to the
    /// wired copy, so GC keeps the entry (reclaiming it would leave the
    /// stale tag with no provider and build pristine crates.io bytes), the
    /// other uuid's entry — wired nowhere — is reclaimable, and a re-run
    /// retags the lock.
    #[tokio::test]
    async fn stale_tag_is_retagged_and_gc_keeps_the_wired_entry() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        assert_eq!(vendored_entry_in_use(&entry, root).await, Some(true));
        let stale = lock_text(root).await.replace(UUID, UUID2);
        tokio::fs::write(root.join("Cargo.lock"), &stale)
            .await
            .unwrap();
        assert_eq!(vendored_entry_in_use(&entry, root).await, Some(true));
        assert_eq!(
            vendored_entry_in_use(&ledger_entry_for(UUID2), root).await,
            Some(false),
            "the lock's uuid is wired nowhere"
        );

        let (result, _, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(warnings.iter().any(|w| w.code == VERSION_TAGGED));
        assert!(lock_text(root).await.contains(&tagged(UUID)));
        assert_eq!(vendored_entry_in_use(&entry, root).await, Some(true));
    }

    /// A patch that edits the crate's own `Cargo.toml`: the tag is written
    /// over the patched manifest, the re-run still sees the copy in sync
    /// (the tag is dropped before hashing), and the ledger verification
    /// passes.
    #[tokio::test]
    async fn a_patched_cargo_toml_verifies_through_the_tag() {
        let (dir, blobs, pristine, mut record) = fixture().await;
        let root = dir.path();
        let before = b"[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n".to_vec();
        let after = b"[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n# patched\n".to_vec();
        tokio::fs::write(blobs.join(git_sha(&after)), &after)
            .await
            .unwrap();
        record.files.insert(
            "package/Cargo.toml".to_string(),
            PatchFileInfo {
                before_hash: git_sha(&before),
                after_hash: git_sha(&after),
            },
        );
        let (result, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(
            copy_toml(root).await,
            format!(
                "[package]\nname = \"cfg-if\"\nversion = \"{}\"\n# patched\n",
                tagged(UUID)
            )
        );
        let (_, again, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(
            again.is_none() && warnings.is_empty(),
            "in sync: {warnings:?}"
        );
        crate::vendor::verify::verify_vendored_patch_record(root, &entry, &record)
            .await
            .expect("the tagged manifest verifies against its afterHash");
    }

    /// A lock the tag cannot be written into consistently (a v1 `replace`
    /// naming the crate) refuses before anything is written — the dry run
    /// previews the same refusal.
    #[tokio::test]
    async fn untaggable_lock_refuses_before_writing() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let lock = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({SOURCE})\",\n]\nreplace = \"cfg-if 1.0.4 ({SOURCE})\"\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\n\n\
             [metadata]\n\"checksum cfg-if 1.0.4 ({SOURCE})\" = \"{CHECKSUM}\"\n"
        );
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();
        let manifest = tokio::fs::read(root.join("Cargo.toml")).await.unwrap();
        for dry_run in [true, false] {
            expect_refused(
                run_vendor(PURL, root, &blobs, &pristine, &record, dry_run).await,
                LOCK_UNTAGGABLE,
            );
        }
        assert_eq!(lock_text(root).await, lock);
        assert_eq!(
            tokio::fs::read(root.join("Cargo.toml")).await.unwrap(),
            manifest
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// A v1 lock is detached, tagged and restored byte-identically: the
    /// full-id references follow the tagged version.
    #[tokio::test]
    async fn v1_lock_round_trips_through_the_tag() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let lock = format!(
            "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
             \"cfg-if 1.0.4 ({SOURCE})\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\nsource = \"{SOURCE}\"\n\n\
             [metadata]\n\"checksum cfg-if 1.0.4 ({SOURCE})\" = \"{CHECKSUM}\"\n"
        );
        tokio::fs::write(root.join("Cargo.lock"), &lock)
            .await
            .unwrap();
        let (result, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            lock_text(root).await,
            format!(
                "[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \
                 \"cfg-if {t}\",\n]\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"{t}\"\n\n\
                 [metadata]\n",
                t = tagged(UUID)
            )
        );
        let out = revert_cargo_vendor(&entry.unwrap(), root, false).await;
        assert!(out.success, "{:?}", out.error);
        assert_eq!(lock_text(root).await, lock);
    }

    /// Vendored before any Cargo.lock existed (no originals recorded), then
    /// the first build locked the tagged copy: the revert drops the tag,
    /// back to the untagged sourceless entry such a vendor always left (an
    /// unlocked build re-resolves it; a hosted takeover finds it). A dry run
    /// writes nothing.
    #[tokio::test]
    async fn revert_without_originals_drops_the_first_builds_tag() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::remove_file(root.join("Cargo.lock"))
            .await
            .unwrap();
        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(warnings.iter().any(|w| w.code == "no_lockfile"));
        let entry = entry.unwrap();
        assert_eq!(entry.lock, None);
        let first_build = format!(
            "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\n \"cfg-if\",\n]\n\n[[package]]\nname = \"cfg-if\"\nversion = \"{}\"\n",
            tagged(UUID)
        );
        tokio::fs::write(root.join("Cargo.lock"), &first_build)
            .await
            .unwrap();

        let dry = revert_cargo_vendor(&entry, root, true).await;
        assert!(dry.success && dry.warnings.is_empty(), "{dry:?}");
        assert_eq!(lock_text(root).await, first_build);

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(
            lock_text(root).await,
            first_build.replace(&tagged(UUID), "1.0.4")
        );
        assert!(!root.join(".socket/vendor").exists());
    }

    /// The same, when another uuid's tag is locked (not this entry's
    /// copy): left alone.
    #[tokio::test]
    async fn revert_without_originals_leaves_another_uuids_tag() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::remove_file(root.join("Cargo.lock"))
            .await
            .unwrap();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let other = format!(
            "version = 4\n\n[[package]]\nname = \"cfg-if\"\nversion = \"{}\"\n",
            tagged(UUID2)
        );
        tokio::fs::write(root.join("Cargo.lock"), &other)
            .await
            .unwrap();
        let out = revert_cargo_vendor(&entry.unwrap(), root, false).await;
        assert!(out.success, "{out:?}");
        assert_eq!(lock_text(root).await, other);
    }

    /// The lock real cargo 1.97 writes once a workspace member path-depends
    /// on its own same-version fork of the vendored crate: the fork's
    /// untagged sourceless entry sorts before the tagged copy.
    fn lock_with_fork(copy_version: &str, app_ref: &str) -> String {
        format!(
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n\
             [[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\n \"{app_ref}\",\n]\n\n\
             [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\n\
             [[package]]\nname = \"cfg-if\"\n{copy_version}\n\
             [[package]]\nname = \"m\"\nversion = \"0.1.0\"\ndependencies = [\n \"cfg-if 1.0.4\",\n]\n"
        )
    }

    /// A same-version path fork locked beside the vendored copy after the
    /// vendor: re-runs stay in sync (no `locked_multi_source_conflict`), GC
    /// sees the copy in use, and the revert restores the REGISTRY entry
    /// (spelled by its full id beside the fork) — never the fork — leaving
    /// exactly the lock cargo writes for the fork plus crates.io.
    #[tokio::test]
    async fn a_user_path_fork_beside_the_copy_survives_rerun_and_revert() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let (_, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        let entry = entry.unwrap();
        let t = tagged(UUID);
        let with_fork = lock_with_fork(&format!("version = \"{t}\"\n"), &format!("cfg-if {t}"));
        tokio::fs::write(root.join("Cargo.lock"), &with_fork)
            .await
            .unwrap();
        assert_eq!(vendored_entry_in_use(&entry, root).await, Some(true));

        let (result, again, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(result.success, "{:?}", result.error);
        assert!(again.is_none() && warnings.is_empty(), "{warnings:?}");
        assert_eq!(lock_text(root).await, with_fork);

        let out = revert_cargo_vendor(&entry, root, false).await;
        assert!(out.success && out.warnings.is_empty(), "{out:?}");
        assert_eq!(
            lock_text(root).await,
            lock_with_fork(
                &format!("version = \"1.0.4\"\nsource = \"{SOURCE}\"\nchecksum = \"{CHECKSUM}\"\n"),
                &format!("cfg-if 1.0.4 ({SOURCE})"),
            )
        );
    }

    /// Dry runs preview the wet run's tag work: `would tag` for an
    /// untagged vendor (nothing written), and the wet run's refusals — a
    /// lock the tag cannot be written into, a copy manifest that cannot
    /// take it.
    #[tokio::test]
    async fn dry_runs_preview_the_tag_edit_and_its_refusals() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        untag_project(root).await;
        let lock = lock_text(root).await;
        let copy = copy_toml(root).await;
        let (result, entry, warnings) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, true).await);
        assert!(result.success && entry.is_none(), "{:?}", result.error);
        let tag = warnings
            .iter()
            .find(|w| w.code == VERSION_TAGGED)
            .unwrap_or_else(|| panic!("{warnings:?}"));
        assert!(tag.detail.starts_with("would tag"), "{tag:?}");
        assert_eq!(lock_text(root).await, lock, "dry run writes nothing");
        assert_eq!(copy_toml(root).await, copy);

        // A copy manifest that names another version cannot take the tag.
        tokio::fs::write(
            root.join(copy_rel()).join("Cargo.toml"),
            copy.replace("1.0.4", "1.0.5"),
        )
        .await
        .unwrap();
        let (result, _, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, true).await);
        assert!(!result.success);
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with(COPY_UNTAGGABLE)),
            "{:?}",
            result.error
        );
        let (wet, _, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(!wet.success, "the wet run fails the same way");
        assert_eq!(lock_text(root).await, lock);
    }

    /// A pristine crate whose `Cargo.toml` cannot take the tag
    /// (a workspace-inherited version) fails the local build with
    /// `cargo_copy_untaggable`: nothing is swapped in, no stage or vendor
    /// dir survives, and the manifest and lock are untouched. The same
    /// crate from the patch service is a MISS: auto mode falls back to the
    /// local build.
    #[tokio::test]
    async fn an_untaggable_copy_manifest_swaps_nothing_in() {
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        tokio::fs::write(
            pristine.join("Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion.workspace = true\n",
        )
        .await
        .unwrap();
        let manifest = tokio::fs::read(root.join("Cargo.toml")).await.unwrap();
        let (result, entry, _) =
            expect_done(run_vendor(PURL, root, &blobs, &pristine, &record, false).await);
        assert!(!result.success && entry.is_none());
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.starts_with(COPY_UNTAGGABLE)),
            "{:?}",
            result.error
        );
        assert!(
            !root.join(".socket/vendor").exists(),
            "no copy, stage or husk"
        );
        assert_eq!(lock_text(root).await, lock_body());
        assert_eq!(
            tokio::fs::read(root.join("Cargo.toml")).await.unwrap(),
            manifest
        );

        // Service crate untaggable, pristine fine: auto falls back.
        let (dir, blobs, pristine, record) = fixture().await;
        let root = dir.path();
        let crate_tgz = make_crate_tgz(
            "cfg-if-1.0.4",
            &[
                (
                    "Cargo.toml",
                    b"[package]\nname = \"cfg-if\"\nversion.workspace = true\n",
                ),
                ("src/lib.rs", PATCHED),
            ],
        );
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
            Some(&cargo_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let (result, entry, warnings) = expect_done(outcome);
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_layout_mismatch"
                    && w.detail.contains("cannot tag its version")),
            "{warnings:?}"
        );
        assert!(
            copy_toml(root).await.contains(&tagged(UUID)),
            "the local build"
        );
        assert_eq!(tokio::fs::read(copy_lib(root)).await.unwrap(), PATCHED);
    }
}
