//! Flavor-agnostic npm vendoring pipeline: coordinate guards plus the shared
//! stage→patch→pack steps.
//!
//! Every npm lockfile flavor (package-lock, yarn-classic/berry, pnpm, bun)
//! vendors the same way up to the wiring: validate the
//! coordinates fail-closed, stage a private copy of the installed package in
//! a tempdir OUTSIDE the project, prune nested `node_modules`, refuse
//! bundled-deps packages, run the hardened apply pipeline against the stage,
//! and pack the result into a deterministic tarball under
//! `.socket/vendor/npm/<uuid>/`. Only the lockfile wiring differs per flavor,
//! and it always runs LAST — so a refusal or failure in this pipeline leaves
//! the project byte-untouched (a dry run stops after verification and
//! creates nothing on disk).

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, ApplyResult, PatchSources};
use crate::patch::copy_tree::{fresh_copy, remove_tree};
use crate::patch::package::read_archive_to_map;
use crate::patch::path_safety;
use crate::utils::fs::atomic_write_bytes;
use crate::utils::purl::{percent_decode_purl_component, strip_purl_qualifiers};

use super::common::{
    already_patched_result, done, failed_result, refused, service_offline_conflict,
};
use super::npm_pack::{pack_deterministic, PackedTarball};
use super::path::vendor_uuid_dir_rel;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// Validated npm vendoring coordinates (the output of
/// [`guard_coordinates`]). `name`/`version` are the percent-DECODED purl
/// components (the API serves scoped purls as `%40scope/name`; the
/// lockfile and node_modules carry the literal `@scope/name`).
#[derive(Debug)]
pub(super) struct NpmCoords {
    pub name: String,
    pub version: String,
    /// `.socket/vendor/npm/<uuid>` (validated, forward slashes).
    pub uuid_dir_rel: String,
    /// Qualifier-free base PURL — VERBATIM (still encoded when the API
    /// encoded it): the ledger's `base_purl`/entry keys must keep
    /// matching the manifest keys, which store the purl as-served.
    pub base_purl: String,
}

/// Parse + validate the coordinates every npm flavor keys its artifact path
/// (and lockfile strings) on.
///
/// SECURITY: name/version/uuid come from a committed, tamper-able manifest
/// and key the artifact path under `.socket/vendor/npm/` plus the spec
/// string written into the lockfile. A `..` segment, separator, or
/// non-canonical uuid would escape the vendor dir (arbitrary write on
/// vendor, arbitrary delete on revert) — reject fail-closed before any disk
/// access. `Err` carries a ready [`VendorOutcome::Refused`] to bubble
/// verbatim.
pub(super) fn guard_coordinates(
    purl: &str,
    record: &PatchRecord,
) -> Result<NpmCoords, Box<VendorOutcome>> {
    let Some((name, version)) = parse_npm_purl(purl) else {
        return Err(Box::new(refused(
            "unsafe_coordinates",
            format!("cannot parse an npm name@version out of `{purl}`"),
        )));
    };
    if !is_safe_npm_name(&name) || !path_safety::is_safe_single_segment(&version) {
        return Err(Box::new(refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor `{name}@{version}`: a `..` segment, absolute path, or \
                 separator would escape .socket/vendor/npm/"
            ),
        )));
    }
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("npm", &record.uuid) else {
        return Err(Box::new(refused(
            "unsafe_coordinates",
            format!(
                "refusing to vendor with non-canonical patch uuid `{}`",
                record.uuid
            ),
        )));
    };
    Ok(NpmCoords {
        name,
        version,
        uuid_dir_rel,
        base_purl: strip_purl_qualifiers(purl).to_string(),
    })
}

/// Validate a revert's patch uuid and return the `.socket/vendor/npm/<uuid>`
/// dir it names.
///
/// SECURITY: the uuid comes from the committed, tamper-able state.json and
/// names the directory tree revert is about to DELETE — validate through the
/// same fail-closed grammar vendor used, before any disk access. `Err`
/// carries the ready failure to bubble verbatim.
pub(super) fn guard_revert_uuid_dir(uuid: &str) -> Result<String, RevertOutcome> {
    vendor_uuid_dir_rel("npm", uuid).ok_or_else(|| {
        RevertOutcome::failed(format!(
            "refusing revert: `{uuid}` is not a canonical patch uuid (tampered state.json?)"
        ))
    })
}

/// The shared pipeline's product: a verified, deterministically packed
/// tarball plus the facts the flavor wiring needs.
pub(super) struct NpmStagedPack {
    pub name: String,
    pub version: String,
    /// `.socket/vendor/npm/<uuid>/<leaf>` (forward slashes).
    pub rel_tgz: String,
    pub packed: PackedTarball,
    /// `Some` iff the patch rewrote the package's own `package.json` (the
    /// lockfile's dependency-mirror fields are then stale and the flavor
    /// wiring must recompute them from this parsed manifest).
    pub staged_pkg_json: Option<Value>,
}

/// Stage → patch → pack one installed npm package.
///
/// Runs [`guard_coordinates`] first (pure and cheap — callers that already
/// guarded simply re-validate), stages a fresh copy of `installed_dir` in a
/// tempdir outside the project, prunes nested `node_modules`, refuses
/// bundled-deps packages, applies the patch via the hardened apply pipeline,
/// and packs the deterministic tarball into the uuid dir.
///
/// Result shape (mirrors how `npm_lock::vendor_npm` splits its phases):
///
/// * `Err(outcome)` — a refusal (`Refused`) or a hard pipeline failure
///   (`Done` with a failed synthesized [`ApplyResult`]); bubble verbatim.
///   Nothing inside the project was written.
/// * `Ok((None, result))` — the patch step finished without packing: either
///   `!result.success` (verify/patch failure; the caller wraps it with its
///   accumulated warnings) or a successful dry run (stops after
///   verification — no pack, no dirs created).
/// * `Ok((Some(staged), result))` — full success: the tarball is on disk at
///   `staged.rel_tgz` and the caller proceeds to its lockfile wiring.
#[allow(clippy::too_many_arguments)]
pub(super) async fn stage_patch_pack(
    purl: &str,
    installed_dir: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dry_run: bool,
    force: bool,
    warnings: &mut Vec<VendorWarning>,
    service: Option<&VendorServiceConfig>,
) -> Result<(Option<NpmStagedPack>, ApplyResult), Box<VendorOutcome>> {
    let coords = guard_coordinates(purl, record)?;

    // ── Service-download fast path (Tier A: write the prebuilt tarball) ──
    // When the vendoring service is configured, try to download the already-
    // built, integrity-verified tarball instead of staging+patching+packing
    // locally. A dry run previews the local build (no network). Per the
    // `auto`/`service` policy a non-fatal miss falls back to the local build
    // below; under `service` it fails closed.
    if let Some(refusal) = service_offline_conflict(service) {
        return Err(Box::new(refusal));
    }
    if let Some(cfg) = service {
        if cfg.service_enabled() && !dry_run {
            match try_service_pack(purl, project_root, &coords, record, cfg, warnings).await {
                ServicePackDecision::Used(pair) => return Ok(*pair),
                ServicePackDecision::HardFail(outcome) => return Err(outcome),
                ServicePackDecision::FallBack => { /* fall through to local build */ }
            }
        }
    }

    // ── Stage + patch a private copy ────────────────────────────────────
    // The stage lives in a tempdir OUTSIDE the project: nothing inside the
    // project is written until the patched tarball verifies.
    let stage_tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => {
            return Err(Box::new(done_failure(
                purl,
                format!("cannot create staging tempdir: {e}"),
            )))
        }
    };
    let stage = stage_tmp.path().join("stage");
    if let Err(e) = fresh_copy(installed_dir, &stage, None).await {
        return Err(Box::new(done_failure(
            purl,
            format!("cannot stage a copy of the installed package: {e}"),
        )));
    }
    // The tarball must carry ONLY the package's own files: a nested
    // node_modules (hoisting leftovers, file:-dep installs) would balloon
    // the artifact and shadow the lock's own resolution.
    if let Err(e) = remove_tree(&stage.join("node_modules")).await {
        return Err(Box::new(done_failure(
            purl,
            format!("cannot prune staged node_modules: {e}"),
        )));
    }
    // Bundled dependencies ship INSIDE the package tarball; since we just
    // dropped nested node_modules, repacking would produce a tarball npm
    // cannot satisfy those deps from. Refuse before patching.
    if let Ok(bytes) = tokio::fs::read(stage.join("package.json")).await {
        // npm and Node tolerate a leading UTF-8 BOM in package.json (and the
        // crawler strips one, so a BOM'd install IS vendored), but serde_json
        // rejects it — and a parse failure here fails OPEN, skipping the
        // bundled-deps refusal below.
        let text = String::from_utf8_lossy(&bytes);
        if let Ok(pkg) =
            serde_json::from_str::<Value>(crate::package_json::detect::strip_bom(&text))
        {
            if declares_bundled_deps(&pkg) {
                return Err(Box::new(refused(
                    "vendor_bundled_deps_unsupported",
                    format!(
                        "{}@{} declares bundleDependencies; vendoring would repack \
                         the tarball without its bundled node_modules and break installs",
                        coords.name, coords.version
                    ),
                )));
            }
        }
    }

    // Delegate to the hardened apply pipeline (with the vendor auto-force
    // policy — see `force_apply_staged`), pointed at the stage (which
    // plays the role of the installed package dir — manifest npm keys carry
    // the `package/` prefix and `apply` strips it via `normalize_file_path`,
    // exactly as it does for an in-place npm apply).
    let result = super::force_apply_staged(
        purl,
        &stage,
        record,
        sources,
        dry_run,
        force,
        &coords.name,
        &coords.version,
        warnings,
    )
    .await;
    // A failed patch never packs (wiring is last — the caller returns with
    // the project byte-untouched); a dry run stops after the verify.
    if !result.success || dry_run {
        return Ok((None, result));
    }

    // ── Pack the deterministic tarball ──────────────────────────────────
    // An Err past this point must unwind the uuid dir the pack is about to
    // create inside the project (the `Err` contract above: "Nothing inside
    // the project was written") — but never one that already existed (a
    // same-uuid re-vendor's dir may still be referenced by live wiring).
    let uuid_dir_preexisted = tokio::fs::metadata(project_root.join(&coords.uuid_dir_rel))
        .await
        .is_ok();
    let (rel_tgz, dest) = prepare_tgz_dest(purl, project_root, &coords).await?;
    let packed = match pack_deterministic(&stage, &dest).await {
        Ok(p) => p,
        Err(e) => {
            return Err(Box::new(
                done_failure_unstage(
                    purl,
                    format!("cannot pack the vendored tarball: {e}"),
                    project_root,
                    &coords.uuid_dir_rel,
                    uuid_dir_preexisted,
                )
                .await,
            ))
        }
    };

    // ── Patched package.json ⇒ the lock's dependency mirror is stale ────
    let staged_pkg_json = if record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json")
    {
        match read_staged_package_json(&stage).await {
            Ok(pkg) => Some(pkg),
            Err(e) => {
                return Err(Box::new(
                    done_failure_unstage(
                        purl,
                        e,
                        project_root,
                        &coords.uuid_dir_rel,
                        uuid_dir_preexisted,
                    )
                    .await,
                ))
            }
        }
    } else {
        None
    };

    Ok((
        Some(NpmStagedPack {
            name: coords.name,
            version: coords.version,
            rel_tgz,
            packed,
            staged_pkg_json,
        }),
        result,
    ))
}

// ───────────────────────── service-download path ─────────────────────────

/// Outcome of attempting the service-download fast path in [`stage_patch_pack`].
enum ServicePackDecision {
    /// Use the service artifact — the staged pack + a synthesized success.
    /// Boxed: the pair is large relative to the other (small) variants.
    Used(Box<(Option<NpmStagedPack>, ApplyResult)>),
    /// Abort vendoring this package (a `service`-mode miss, or a downloaded
    /// artifact we could not turn into a staged pack).
    HardFail(Box<VendorOutcome>),
    /// Fall back to the local stage→patch→pack build.
    FallBack,
}

/// Download + verify the prebuilt tarball and turn it into an [`NpmStagedPack`],
/// mapping each service outcome onto the `auto` / `service` fallback policy.
async fn try_service_pack(
    purl: &str,
    project_root: &Path,
    coords: &NpmCoords,
    record: &PatchRecord,
    cfg: &VendorServiceConfig,
    warnings: &mut Vec<VendorWarning>,
) -> ServicePackDecision {
    let hard_fail =
        |detail: String| ServicePackDecision::HardFail(Box::new(done_failure(purl, detail)));
    match fetch_verified_archive(cfg, &record.uuid).await {
        ServiceArtifact::Ready(archive) => {
            match staged_pack_from_service_bytes(
                purl,
                project_root,
                coords,
                record,
                &archive.bytes,
                &archive.integrity_sri,
            )
            .await
            {
                Ok(staged) => {
                    warnings.push(VendorWarning::new(
                        "vendor_prebuilt_downloaded",
                        format!(
                            "vendored {}@{} from the patch service ({})",
                            coords.name, coords.version, archive.source_url
                        ),
                    ));
                    // No local apply to verify — every patched file reads as
                    // `AlreadyPatched` (trust is the service-verified
                    // integrity).
                    let result = already_patched_result(
                        purl,
                        &project_root.join(&staged.rel_tgz),
                        &record.files,
                    );
                    ServicePackDecision::Used(Box::new((Some(staged), result)))
                }
                Err(outcome) => ServicePackDecision::HardFail(outcome),
            }
        }
        // An artifact that downloaded but failed integrity is NEVER silently
        // used; under `auto` we fall back to a fresh local build (loudly).
        ServiceArtifact::IntegrityMismatch(reason) => {
            if cfg.source.requires_service() {
                hard_fail(format!(
                    "prebuilt artifact failed integrity verification: {reason}"
                ))
            } else {
                warnings.push(VendorWarning::new(
                    "vendor_prebuilt_integrity_mismatch",
                    format!(
                        "prebuilt artifact failed integrity ({reason}); building locally instead"
                    ),
                ));
                ServicePackDecision::FallBack
            }
        }
        ServiceArtifact::Pending => {
            if cfg.source.requires_service() {
                hard_fail("prebuilt artifact is still building".to_string())
            } else {
                warnings.push(VendorWarning::new(
                    "vendor_prebuilt_pending",
                    "prebuilt artifact is still building; building locally instead".to_string(),
                ));
                ServicePackDecision::FallBack
            }
        }
        // The common, quiet miss: not built / free-only / not found.
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard_fail(format!("prebuilt artifact unavailable: {reason}"))
            } else {
                ServicePackDecision::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => {
            if cfg.source.requires_service() {
                hard_fail(format!("patch service request failed: {reason}"))
            } else {
                warnings.push(VendorWarning::new(
                    "vendor_prebuilt_unavailable",
                    format!("patch service request failed ({reason}); building locally instead"),
                ));
                ServicePackDecision::FallBack
            }
        }
    }
}

/// Build an [`NpmStagedPack`] from service-downloaded, sha512-verified tarball
/// bytes: write the tarball to the vendor path and (when the patch rewrote
/// `package.json`) extract it for the lockfile's dependency-mirror recompute.
///
/// Re-derives the [`PackedTarball`] facts from the bytes so the lockfile
/// `integrity` is byte-identical to a local build, and asserts they match the
/// integrity the service vouched for (the caller already verified the bytes
/// against it — this guards the value actually written to the lock).
async fn staged_pack_from_service_bytes(
    purl: &str,
    project_root: &Path,
    coords: &NpmCoords,
    record: &PatchRecord,
    bytes: &[u8],
    service_sri: &str,
) -> Result<NpmStagedPack, Box<VendorOutcome>> {
    let packed = PackedTarball::from_bytes(bytes);
    if packed.integrity != service_sri {
        return Err(Box::new(done_failure(
            purl,
            format!(
                "recomputed integrity {} disagrees with the service integrity {service_sri}",
                packed.integrity
            ),
        )));
    }

    // An Err past this point must unwind the uuid dir the write is about to
    // create inside the project (the caller's `Err` contract: "Nothing
    // inside the project was written") — but never one that already existed
    // (a same-uuid re-vendor's dir may still be referenced by live wiring).
    let uuid_dir_preexisted = tokio::fs::metadata(project_root.join(&coords.uuid_dir_rel))
        .await
        .is_ok();
    let (rel_tgz, dest) = prepare_tgz_dest(purl, project_root, coords).await?;
    if let Err(e) = atomic_write_bytes(&dest, bytes).await {
        return Err(Box::new(
            done_failure_unstage(
                purl,
                format!("cannot write the vendored tarball: {e}"),
                project_root,
                &coords.uuid_dir_rel,
                uuid_dir_preexisted,
            )
            .await,
        ));
    }

    let staged_pkg_json = if record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json")
    {
        match read_package_json_from_vendored_tgz(&dest).await {
            Ok(pkg) => Some(pkg),
            Err(e) => {
                return Err(Box::new(
                    done_failure_unstage(
                        purl,
                        e,
                        project_root,
                        &coords.uuid_dir_rel,
                        uuid_dir_preexisted,
                    )
                    .await,
                ))
            }
        }
    } else {
        None
    };

    Ok(NpmStagedPack {
        name: coords.name.clone(),
        version: coords.version.clone(),
        rel_tgz,
        packed,
        staged_pkg_json,
    })
}

/// Read the patched `package.json` out of a written vendored tarball (used
/// only when the patch rewrote it — the lock's dependency mirror is then
/// stale and recomputed from this).
async fn read_package_json_from_vendored_tgz(dest: &Path) -> Result<Value, String> {
    let dest = dest.to_path_buf();
    let map = tokio::task::spawn_blocking(move || read_archive_to_map(&dest))
        .await
        .map_err(|e| format!("join error reading the vendored tarball: {e}"))?
        .map_err(|e| format!("cannot read the vendored tarball: {e}"))?;
    let bytes = map.get("package.json").ok_or_else(|| {
        "the patch rewrites package.json but the prebuilt artifact has none".to_string()
    })?;
    serde_json::from_slice(bytes)
        .map_err(|e| format!("vendored package.json is not parseable JSON: {e}"))
}

// ───────────────────────────── small helpers ─────────────────────────────

/// The artifact's project-relative path (`<uuid_dir>/<leaf>`) and absolute
/// destination, with the destination's parent directories created. Shared by
/// the local pack and the service download so the two paths cannot drift.
async fn prepare_tgz_dest(
    purl: &str,
    project_root: &Path,
    coords: &NpmCoords,
) -> Result<(String, PathBuf), Box<VendorOutcome>> {
    let rel_tgz = format!(
        "{}/{}",
        coords.uuid_dir_rel,
        tgz_rel_leaf(&coords.name, &coords.version)
    );
    let dest = project_root.join(&rel_tgz);
    if let Some(parent) = dest.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return Err(Box::new(done_failure(
                purl,
                format!("cannot create {}: {e}", parent.display()),
            )));
        }
    }
    Ok((rel_tgz, dest))
}

/// `pkg:npm/[@scope/]name@version` → `(name, version)`; scoped names keep
/// the `@scope/` prefix. The LAST `@` separates the version (a leading
/// scope-`@` is at index 0 and never the last `@` of a versioned purl).
///
/// Components are percent-DECODED (the API serves `pkg:npm/%40scope/...`).
/// SECURITY: each segment decodes independently AFTER the `/`/`@` splits,
/// and the post-decode `is_safe_npm_name`/`is_safe_single_segment` gates in
/// [`guard_coordinates`] reject any separator or traversal sequence a
/// decode may have surfaced (`%2e%2e`, `%2f`, ...) — decoding never runs
/// after the guards.
pub(super) fn parse_npm_purl(purl: &str) -> Option<(String, String)> {
    let base = strip_purl_qualifiers(purl);
    let rest = base.strip_prefix("pkg:npm/")?;
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name_raw, version_raw) = (&rest[..at], &rest[at + 1..]);
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

/// npm-name shape on top of the generic traversal guard: at most one `/`,
/// and only with an `@scope` first segment (so a smuggled `a/b/c` can't
/// create surprise directory levels under the uuid dir).
pub(super) fn is_safe_npm_name(name: &str) -> bool {
    if !path_safety::is_safe_multi_segment(name) {
        return false;
    }
    match name.split_once('/') {
        None => !name.starts_with('@'),
        Some((scope, bare)) => scope.starts_with('@') && !bare.contains('/'),
    }
}

/// The artifact path under the uuid dir: `[@scope/]<name>-<version>.tgz`,
/// with the scope kept as a real subdirectory.
pub(super) fn tgz_rel_leaf(name: &str, version: &str) -> String {
    match name.split_once('/') {
        Some((scope, bare)) => format!("{scope}/{bare}-{version}.tgz"),
        None => format!("{name}-{version}.tgz"),
    }
}

/// `bundleDependencies` (npm) / `bundledDependencies` (legacy alias):
/// `true` means "all deps", an array names them, and npm-bundled falls back
/// to `Object.keys(bd)` for any other truthy value — so an OBJECT form
/// bundles its keys too; any of these makes the package unvendorable (see
/// the refusal site).
fn declares_bundled_deps(pkg: &Value) -> bool {
    ["bundleDependencies", "bundledDependencies"]
        .iter()
        .any(|k| match pkg.get(*k) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::Object(o)) => !o.is_empty(),
            _ => false,
        })
}

async fn read_staged_package_json(stage: &Path) -> Result<Value, String> {
    let bytes = tokio::fs::read(stage.join("package.json"))
        .await
        .map_err(|e| format!("patched package.json unreadable in the stage: {e}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("patched package.json is not parseable JSON: {e}"))
}

/// A backend failure after the refusal phase: `Done` with a failed
/// synthesized [`ApplyResult`], mirroring `go_redirect`'s synthesized
/// results.
pub(super) fn done_failure(purl: &str, error: String) -> VendorOutcome {
    done(failed_result(purl, Path::new(""), error), None, Vec::new())
}

/// [`done_failure`] for a wiring failure AFTER the shared pipeline packed
/// the artifact into `<project>/.socket/vendor/<eco>/<uuid>/`: unless the
/// uuid dir already existed before this run (a same-uuid re-vendor may still
/// be referenced by live wiring), best-effort remove it — no ledger entry is
/// ever persisted for a failed wiring, so `--revert` could never clean it up
/// and the module contract ("a failure leaves the project byte-untouched")
/// would be broken by an orphaned, possibly defective artifact dir. Empty
/// parent dirs are pruned non-recursively (a sibling artifact keeps them).
pub(super) async fn done_failure_unstage(
    purl: &str,
    error: String,
    project_root: &Path,
    uuid_dir_rel: &str,
    uuid_dir_preexisted: bool,
) -> VendorOutcome {
    if !uuid_dir_preexisted {
        let uuid_dir = project_root.join(uuid_dir_rel);
        let _ = remove_tree(&uuid_dir).await;
        if let Some(eco_dir) = uuid_dir.parent() {
            let _ = tokio::fs::remove_dir(eco_dir).await;
            if let Some(vendor_dir) = eco_dir.parent() {
                let _ = tokio::fs::remove_dir(vendor_dir).await;
            }
        }
    }
    done_failure(purl, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::PatchFileInfo;
    use std::collections::HashMap;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";

    fn record_with_uuid(uuid: &str) -> PatchRecord {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "a".repeat(64),
                after_hash: "b".repeat(64),
            },
        );
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        }
    }

    fn expect_refusal(err: Box<VendorOutcome>, want_code: &str) {
        match *err {
            VendorOutcome::Refused { code, detail } => {
                assert_eq!(code, want_code, "{detail}");
            }
            other => panic!("expected Refused {want_code}, got {other:?}"),
        }
    }

    #[test]
    fn guard_coordinates_accepts_plain_and_scoped_names() {
        let record = record_with_uuid(UUID);
        let coords = guard_coordinates("pkg:npm/left-pad@1.3.0", &record).unwrap();
        assert_eq!(
            (coords.name.as_str(), coords.version.as_str()),
            ("left-pad", "1.3.0")
        );
        assert_eq!(coords.uuid_dir_rel, format!(".socket/vendor/npm/{UUID}"));
        assert_eq!(coords.base_purl, "pkg:npm/left-pad@1.3.0");

        let coords = guard_coordinates("pkg:npm/@scope/pkg@1.0.0?artifact_id=x", &record).unwrap();
        assert_eq!(
            (coords.name.as_str(), coords.version.as_str()),
            ("@scope/pkg", "1.0.0")
        );
        assert_eq!(
            coords.base_purl, "pkg:npm/@scope/pkg@1.0.0",
            "qualifiers stripped"
        );
    }

    /// The API serves scoped purls percent-encoded; the coordinates must
    /// decode to the literal `@scope/name` (which keys the lockfile and
    /// the artifact path), while `base_purl` stays verbatim — the ledger
    /// must keep matching the manifest key as-served.
    #[test]
    fn guard_coordinates_decodes_percent_encoded_scope() {
        let record = record_with_uuid(UUID);
        let coords =
            guard_coordinates("pkg:npm/%40modelcontextprotocol/sdk@1.12.0", &record).unwrap();
        assert_eq!(
            (coords.name.as_str(), coords.version.as_str()),
            ("@modelcontextprotocol/sdk", "1.12.0")
        );
        assert_eq!(
            coords.base_purl, "pkg:npm/%40modelcontextprotocol/sdk@1.12.0",
            "base_purl stays verbatim-encoded (manifest/ledger key parity)"
        );
        assert_eq!(
            tgz_rel_leaf(&coords.name, &coords.version),
            "@modelcontextprotocol/sdk-1.12.0.tgz",
            "artifact leaf is built from the decoded name"
        );
    }

    #[test]
    fn guard_coordinates_refuses_fail_closed() {
        let record = record_with_uuid(UUID);
        // Unparseable purl.
        expect_refusal(
            guard_coordinates("pkg:pypi/six@1.16.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // Traversal name.
        expect_refusal(
            guard_coordinates("pkg:npm/../escape@1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // Traversal version.
        expect_refusal(
            guard_coordinates("pkg:npm/x@../1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // SECURITY: percent-encoded traversal must be rejected POST-decode —
        // guarding the encoded form would be a bypass (`%2e%2e` → `..`).
        expect_refusal(
            guard_coordinates("pkg:npm/%2e%2e/escape@1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        expect_refusal(
            guard_coordinates("pkg:npm/@scope/%2e%2e%2f%2e%2e@1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        expect_refusal(
            guard_coordinates("pkg:npm/x@%2e%2e%2f1.0.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
        // Tampered uuid.
        let record = record_with_uuid("../../x");
        expect_refusal(
            guard_coordinates("pkg:npm/left-pad@1.3.0", &record).unwrap_err(),
            "unsafe_coordinates",
        );
    }

    /// npm (npm-bundled) derives the bundle list as
    /// `Array.isArray(bd) ? bd : bd === true ? allDeps : Object.keys(bd)` —
    /// the OBJECT form `{"dep": "..."}` is honored (its keys are bundled),
    /// so it must trigger the refusal exactly like the array form instead of
    /// failing open and packing a tarball whose bundled node_modules was
    /// pruned.
    #[test]
    fn declares_bundled_deps_matches_npm_value_shapes() {
        let with = |key: &str, v: serde_json::Value| {
            declares_bundled_deps(&serde_json::json!({ key: v }))
        };
        for key in ["bundleDependencies", "bundledDependencies"] {
            assert!(with(key, serde_json::json!(true)), "{key}: true = all deps");
            assert!(!with(key, serde_json::json!(false)), "{key}: false");
            assert!(with(key, serde_json::json!(["dep"])), "{key}: array names");
            assert!(!with(key, serde_json::json!([])), "{key}: empty array");
            assert!(
                with(key, serde_json::json!({"dep": "^1.0.0"})),
                "{key}: object form bundles its keys (npm-bundled Object.keys)"
            );
            assert!(
                !with(key, serde_json::json!({})),
                "{key}: empty object bundles nothing"
            );
            assert!(!with(key, serde_json::json!(null)), "{key}: null");
        }
        assert!(!declares_bundled_deps(&serde_json::json!({})), "absent");
    }

    /// An Err AFTER `prepare_tgz_dest` must unwind the uuid dir the pack
    /// created inside the project — the module contract ("a refusal or
    /// failure in this pipeline leaves the project byte-untouched", and the
    /// `Err` arm's "Nothing inside the project was written") — instead of
    /// stranding an unledgered, committable husk no `--revert` entry tracks
    /// (the vendor/cargo.rs failed-vendor-husk class). Reachable shape: the
    /// patch rewrites package/package.json to content that is not valid
    /// JSON (apply is afterHash-gated only, never a JSON parse), so
    /// `read_staged_package_json` errs after the tarball fully packed.
    #[tokio::test]
    async fn err_after_pack_unstages_the_uuid_dir() {
        use crate::hash::git_sha256::compute_git_sha256_from_bytes;
        use crate::patch::apply::PatchSources;

        const ORIG_PKG: &[u8] = b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}\n";
        const BAD_PKG: &[u8] = b"module.exports = 'not json';\n";

        async fn build_fixture() -> (tempfile::TempDir, PatchRecord) {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let installed = root.join("node_modules/left-pad");
            tokio::fs::create_dir_all(&installed).await.unwrap();
            tokio::fs::write(installed.join("package.json"), ORIG_PKG)
                .await
                .unwrap();
            let blobs = root.join(".socket/blobs");
            tokio::fs::create_dir_all(&blobs).await.unwrap();
            let after_hash = compute_git_sha256_from_bytes(BAD_PKG);
            tokio::fs::write(blobs.join(&after_hash), BAD_PKG)
                .await
                .unwrap();
            let mut record = record_with_uuid(UUID);
            record.files.clear();
            record.files.insert(
                "package/package.json".to_string(),
                PatchFileInfo {
                    before_hash: compute_git_sha256_from_bytes(ORIG_PKG),
                    after_hash,
                },
            );
            (tmp, record)
        }

        async fn run(root: &Path, record: &PatchRecord) -> Box<VendorOutcome> {
            let blobs = root.join(".socket/blobs");
            let sources = PatchSources::blobs_only(&blobs);
            let mut warnings = Vec::new();
            match stage_patch_pack(
                "pkg:npm/left-pad@1.3.0",
                &root.join("node_modules/left-pad"),
                root,
                record,
                &sources,
                false,
                false,
                &mut warnings,
                None,
            )
            .await
            {
                Err(outcome) => outcome,
                Ok(_) => panic!("expected the post-pack package.json parse to Err"),
            }
        }

        // Fresh vendor: the post-pack failure must leave no husk at all.
        let (tmp, record) = build_fixture().await;
        match *run(tmp.path(), &record).await {
            VendorOutcome::Done { result, entry, .. } => {
                assert!(!result.success);
                assert!(
                    result
                        .error
                        .as_deref()
                        .unwrap_or("")
                        .contains("not parseable JSON"),
                    "fails on the post-pack package.json parse: {:?}",
                    result.error
                );
                assert!(entry.is_none());
            }
            other => panic!("expected Done failure, got {other:?}"),
        }
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "no orphaned uuid-dir husk may remain after a post-pack failure"
        );

        // Same-uuid re-vendor: a PRE-EXISTING uuid dir is never unstaged
        // (live wiring may still reference it).
        let (tmp, record) = build_fixture().await;
        let uuid_dir = tmp.path().join(format!(".socket/vendor/npm/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        match *run(tmp.path(), &record).await {
            VendorOutcome::Done { result, .. } => assert!(!result.success),
            other => panic!("expected Done failure, got {other:?}"),
        }
        assert!(
            uuid_dir.exists(),
            "a pre-existing uuid dir survives the failure"
        );
    }

    #[tokio::test]
    async fn done_failure_shape_matches_contract() {
        let outcome = done_failure("pkg:npm/x@1.0.0", "boom".to_string());
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("done_failure must be Done");
        };
        assert!(!result.success);
        assert_eq!(result.package_key, "pkg:npm/x@1.0.0");
        assert_eq!(result.error.as_deref(), Some("boom"));
        assert!(result.files_verified.is_empty() && result.files_patched.is_empty());
        assert!(entry.is_none());
        assert!(warnings.is_empty());
    }

    // ──────────── shared fixtures for the pipeline-arm tests ────────────

    const LP_PURL: &str = "pkg:npm/left-pad@1.3.0";
    const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
    const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

    /// Unwrap a pipeline `Err` into its `Done` failure, asserting the
    /// synthesized result carries `needle` and no ledger entry; returns the
    /// full error text for further assertions.
    fn expect_done_failure(outcome: Box<VendorOutcome>, needle: &str) -> String {
        match *outcome {
            VendorOutcome::Done { result, entry, .. } => {
                assert!(!result.success, "expected a failed result");
                assert!(entry.is_none(), "a failure must never carry a ledger entry");
                let error = result.error.unwrap_or_default();
                assert!(
                    error.contains(needle),
                    "error `{error}` must contain `{needle}`"
                );
                error
            }
            other => panic!("expected Done failure, got {other:?}"),
        }
    }

    /// `unwrap_err` for pipeline results whose Ok side (`NpmStagedPack`)
    /// deliberately has no `Debug` impl.
    fn expect_err<T>(result: Result<T, Box<VendorOutcome>>) -> Box<VendorOutcome> {
        match result {
            Err(outcome) => outcome,
            Ok(_) => panic!("expected the pipeline to Err"),
        }
    }

    /// Project tempdir with an installed left-pad (the given package.json
    /// plus `ORIG_INDEX`), a patched-index blob, and a record patching only
    /// `package/index.js` — the minimal shape a full local
    /// stage→patch→pack run succeeds on.
    async fn local_fixture(installed_pkg_json: &[u8]) -> (tempfile::TempDir, PatchRecord) {
        use crate::hash::git_sha256::compute_git_sha256_from_bytes;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let installed = root.join("node_modules/left-pad");
        tokio::fs::create_dir_all(&installed).await.unwrap();
        tokio::fs::write(installed.join("package.json"), installed_pkg_json)
            .await
            .unwrap();
        tokio::fs::write(installed.join("index.js"), ORIG_INDEX)
            .await
            .unwrap();
        let blobs = root.join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let after_hash = compute_git_sha256_from_bytes(PATCHED_INDEX);
        tokio::fs::write(blobs.join(&after_hash), PATCHED_INDEX)
            .await
            .unwrap();
        let mut record = record_with_uuid(UUID);
        record.files.clear();
        record.files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(ORIG_INDEX),
                after_hash,
            },
        );
        (tmp, record)
    }

    async fn run_pipeline(
        root: &Path,
        record: &PatchRecord,
        service: Option<&VendorServiceConfig>,
    ) -> Result<(Option<NpmStagedPack>, ApplyResult), Box<VendorOutcome>> {
        let blobs = root.join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let mut warnings = Vec::new();
        stage_patch_pack(
            LP_PURL,
            &root.join("node_modules/left-pad"),
            root,
            record,
            &sources,
            false,
            false,
            &mut warnings,
            service,
        )
        .await
    }

    /// Deterministically pack `files` (rel path → bytes) into real tgz
    /// bytes, exactly as a local build would.
    async fn build_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let tmp = tempfile::tempdir().unwrap();
        let staged = tmp.path().join("staged");
        tokio::fs::create_dir_all(&staged).await.unwrap();
        for &(name, bytes) in files {
            tokio::fs::write(staged.join(name), bytes).await.unwrap();
        }
        let dest = tmp.path().join("built.tgz");
        pack_deterministic(&staged, &dest).await.unwrap();
        tokio::fs::read(&dest).await.unwrap()
    }

    // ───────────────────── local-build failure arms ─────────────────────

    /// A vanished installed dir (removed after the scan resolved it) is a
    /// `Done` failure naming the stage step, with the project left
    /// byte-untouched.
    #[tokio::test]
    async fn missing_installed_dir_fails_without_touching_the_project() {
        let tmp = tempfile::tempdir().unwrap();
        let record = record_with_uuid(UUID);
        let err = expect_err(run_pipeline(tmp.path(), &record, None).await);
        expect_done_failure(err, "cannot stage a copy of the installed package");
        assert!(
            !tmp.path().join(".socket").exists(),
            "a stage failure must write nothing inside the project"
        );
    }

    /// The bundled-deps refusal deliberately fails OPEN on an unparseable
    /// staged package.json (npm itself tolerates manifests serde rejects;
    /// refusing here would make such packages unvendorable — see the comment
    /// at the check site): the pipeline must proceed to a successful pack.
    /// The parseable twin of the same content refuses, proving the skip is
    /// exactly the parse failure and not a dead check.
    #[tokio::test]
    async fn unparseable_package_json_fails_open_past_the_bundled_deps_refusal() {
        // Invalid JSON (trailing comma) that WOULD declare bundled deps if
        // it parsed.
        let (tmp, record) = local_fixture(b"{\"bundleDependencies\": [\"dep\"],}").await;
        let (staged, result) = run_pipeline(tmp.path(), &record, None)
            .await
            .expect("an unparseable package.json must neither refuse nor fail");
        assert!(result.success, "{:?}", result.error);
        let staged = staged.expect("a real (non-dry) run must pack");
        assert!(
            tmp.path().join(&staged.rel_tgz).is_file(),
            "the tarball must be packed despite the unparseable manifest"
        );
        assert!(
            staged.staged_pkg_json.is_none(),
            "the record does not patch package.json"
        );

        // Contrast: the SAME declaration in valid JSON refuses.
        let (tmp, record) = local_fixture(b"{\"bundleDependencies\": [\"dep\"]}").await;
        expect_refusal(
            expect_err(run_pipeline(tmp.path(), &record, None).await),
            "vendor_bundled_deps_unsupported",
        );
    }

    /// A pack failure (something undeletable squatting on the dest path) is
    /// a `Done` failure naming the pack step — and since the uuid dir
    /// pre-existed this run, the unwind must NOT delete it (live wiring may
    /// still reference it).
    #[tokio::test]
    async fn pack_failure_reports_and_preserves_a_preexisting_uuid_dir() {
        let (tmp, record) = local_fixture(b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}").await;
        // A DIRECTORY at the tgz destination: the atomic rename-over fails.
        let squatter = tmp
            .path()
            .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
        tokio::fs::create_dir_all(&squatter).await.unwrap();
        let err = expect_err(run_pipeline(tmp.path(), &record, None).await);
        expect_done_failure(err, "cannot pack the vendored tarball");
        assert!(
            squatter.exists(),
            "a pre-existing uuid dir must survive the failed pack's unwind"
        );
    }

    // ─────────────── service fast path: the hard-fail arms ───────────────

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::vendor::VendorSource;

    const SERVE_PATH: &str = "/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz";

    fn service_cfg(server_uri: &str, source: VendorSource) -> VendorServiceConfig {
        VendorServiceConfig {
            source,
            client: Some(ApiClient::new(ApiClientOptions {
                api_url: server_uri.to_string(),
                api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                use_public_proxy: false,
                org_slug: Some("acme".into()),
            })),
            use_public_proxy: false,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
        }
    }

    async fn mount_status_only(server: &wiremock::MockServer, status: &str) {
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

    async fn mount_granted(server: &wiremock::MockServer, sha512: &str, tgz: &[u8]) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let serve_url = format!("{}{SERVE_PATH}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "artifacts": [{ "kind": "tarball", "url": serve_url,
                                    "integrity": { "sha512": sha512 } }]
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(SERVE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz.to_vec()))
            .mount(server)
            .await;
    }

    /// `--vendor-source=service` + a terminal service miss (not built / not
    /// found) = hard fail carrying the service reason, nothing written. (The
    /// `auto` sibling — a quiet local-build fallback — is pinned in
    /// npm_lock's service tests.)
    #[tokio::test]
    async fn service_mode_hard_fails_when_the_artifact_is_unavailable() {
        let server = wiremock::MockServer::start().await;
        mount_status_only(&server, "not_found").await;
        let tmp = tempfile::tempdir().unwrap();
        let record = record_with_uuid(UUID);
        let cfg = service_cfg(&server.uri(), VendorSource::Service);
        let err = expect_err(run_pipeline(tmp.path(), &record, Some(&cfg)).await);
        let error = expect_done_failure(err, "prebuilt artifact unavailable");
        assert!(
            error.contains("not_found"),
            "carries the service reason: {error}"
        );
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "a service-mode miss writes nothing"
        );
    }

    /// `--vendor-source=service` + a request/transport failure (HTTP 500 on
    /// the package-reference POST) = hard fail naming the request failure.
    #[tokio::test]
    async fn service_mode_hard_fails_when_the_service_request_fails() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        let record = record_with_uuid(UUID);
        let cfg = service_cfg(&server.uri(), VendorSource::Service);
        let err = expect_err(run_pipeline(tmp.path(), &record, Some(&cfg)).await);
        expect_done_failure(err, "patch service request failed");
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "a service-mode request failure writes nothing"
        );
    }

    /// A Ready artifact that VERIFIES (its sha512 token matches the bytes)
    /// but whose service SRI is not byte-identical to the recomputed
    /// canonical SRI (here: a multi-hash string) fails conversion — a hard
    /// fail in EVERY mode, because the value about to be written into the
    /// lockfile is ambiguous and an `auto` fallback would mask the service
    /// defect. The fixture has no node_modules, so a fallback build would
    /// fail with a DIFFERENT error — the assertion proves it never ran.
    #[tokio::test]
    async fn noncanonical_service_sri_hard_fails_with_no_auto_fallback() {
        let tgz = build_tgz(&[("index.js", PATCHED_INDEX)]).await;
        let canonical = PackedTarball::from_bytes(&tgz).integrity;
        let served_sri = format!("{canonical} sha256-AAAA");
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, &served_sri, &tgz).await;

        let record = record_with_uuid(UUID);
        for source in [VendorSource::Service, VendorSource::Auto] {
            let tmp = tempfile::tempdir().unwrap();
            let cfg = service_cfg(&server.uri(), source);
            let err = expect_err(run_pipeline(tmp.path(), &record, Some(&cfg)).await);
            let error = expect_done_failure(err, "disagrees with the service integrity");
            assert!(
                error.contains(&canonical),
                "names the recomputed SRI: {error}"
            );
            assert!(
                !tmp.path().join(".socket/vendor").exists(),
                "the string guard fires before any write"
            );
        }
    }

    // ──────────── staged_pack_from_service_bytes unit matrix ────────────

    fn record_also_patching_package_json() -> PatchRecord {
        let mut record = record_with_uuid(UUID);
        record.files.insert(
            "package/package.json".to_string(),
            PatchFileInfo {
                before_hash: "c".repeat(64),
                after_hash: "d".repeat(64),
            },
        );
        record
    }

    async fn service_bytes(
        root: &Path,
        record: &PatchRecord,
        bytes: &[u8],
        service_sri: &str,
    ) -> Result<NpmStagedPack, Box<VendorOutcome>> {
        let coords = guard_coordinates(LP_PURL, record).unwrap();
        staged_pack_from_service_bytes(LP_PURL, root, &coords, record, bytes, service_sri).await
    }

    /// The recomputed-vs-service SRI guard protects the exact string written
    /// into the lockfile, and fires BEFORE anything touches the project.
    #[tokio::test]
    async fn service_bytes_integrity_string_guard_fires_before_any_write() {
        let tmp = tempfile::tempdir().unwrap();
        let record = record_with_uuid(UUID);
        let err = expect_err(service_bytes(tmp.path(), &record, b"tarball bytes", "sha512-AAAA").await);
        let error = expect_done_failure(err, "disagrees with the service integrity sha512-AAAA");
        assert!(error.contains("recomputed integrity"), "{error}");
        assert!(
            !tmp.path().join(".socket").exists(),
            "the guard must reject before creating anything"
        );
    }

    /// A tarball write failure (something squatting on the dest path) is a
    /// `Done` failure naming the write — with a pre-existing uuid dir kept
    /// by the unwind.
    #[tokio::test]
    async fn service_bytes_write_failure_reports_and_keeps_a_preexisting_uuid_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let squatter = tmp
            .path()
            .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
        tokio::fs::create_dir_all(&squatter).await.unwrap();
        let record = record_with_uuid(UUID);
        let bytes = b"service tarball bytes";
        let sri = PackedTarball::from_bytes(bytes).integrity;
        let err = expect_err(service_bytes(tmp.path(), &record, bytes, &sri).await);
        expect_done_failure(err, "cannot write the vendored tarball");
        assert!(
            squatter.exists(),
            "a pre-existing uuid dir must survive the failed write's unwind"
        );
    }

    /// When the patch rewrites package.json, a prebuilt artifact WITHOUT one
    /// is a service-data defect: fail loudly and unwind the already-written
    /// tarball (nothing inside the project may survive an `Err`).
    #[tokio::test]
    async fn service_bytes_missing_package_json_reports_and_unstages() {
        let tmp = tempfile::tempdir().unwrap();
        let record = record_also_patching_package_json();
        let tgz = build_tgz(&[("index.js", PATCHED_INDEX)]).await;
        let sri = PackedTarball::from_bytes(&tgz).integrity;
        let err = expect_err(service_bytes(tmp.path(), &record, &tgz, &sri).await);
        expect_done_failure(
            err,
            "the patch rewrites package.json but the prebuilt artifact has none",
        );
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "the already-written tarball must be unwound on the Err path"
        );
    }

    /// Same defect class, other arm: the artifact HAS a package.json but it
    /// is not parseable JSON — the dependency-mirror recompute would be
    /// garbage, so fail loudly and unwind.
    #[tokio::test]
    async fn service_bytes_unparseable_package_json_reports_and_unstages() {
        let tmp = tempfile::tempdir().unwrap();
        let record = record_also_patching_package_json();
        let tgz = build_tgz(&[
            ("index.js", PATCHED_INDEX),
            ("package.json", b"not json".as_slice()),
        ])
        .await;
        let sri = PackedTarball::from_bytes(&tgz).integrity;
        let err = expect_err(service_bytes(tmp.path(), &record, &tgz, &sri).await);
        expect_done_failure(err, "vendored package.json is not parseable JSON");
        assert!(!tmp.path().join(".socket/vendor").exists());
    }

    /// Full service-bytes success: the tarball lands verbatim at the same
    /// rel path a local build uses, the `PackedTarball` facts describe the
    /// served bytes, and the patched package.json is extracted through the
    /// archive map's normalized (`package/`-stripped) keys — pinning the
    /// coupling with `read_archive_to_map`'s key format that the lookup
    /// silently depends on.
    #[tokio::test]
    async fn service_bytes_success_writes_verbatim_and_extracts_the_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let record = record_also_patching_package_json();
        let manifest: &[u8] =
            br#"{"name":"left-pad","version":"1.3.0","dependencies":{"pad-core":"^2.0.0"}}"#;
        let tgz = build_tgz(&[("index.js", PATCHED_INDEX), ("package.json", manifest)]).await;
        let sri = PackedTarball::from_bytes(&tgz).integrity;
        let staged = service_bytes(tmp.path(), &record, &tgz, &sri)
            .await
            .unwrap_or_else(|e| panic!("a canonical-SRI artifact must convert: {e:?}"));
        assert_eq!(staged.name, "left-pad");
        assert_eq!(staged.version, "1.3.0");
        assert_eq!(
            staged.rel_tgz,
            format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
        );
        assert_eq!(staged.packed.integrity, sri);
        assert_eq!(staged.packed.size, tgz.len() as u64);
        assert_eq!(
            staged.staged_pkg_json,
            Some(serde_json::json!({
                "name": "left-pad",
                "version": "1.3.0",
                "dependencies": { "pad-core": "^2.0.0" }
            })),
            "the patched manifest is extracted for the lock's dependency-mirror recompute"
        );
        assert_eq!(
            tokio::fs::read(tmp.path().join(&staged.rel_tgz))
                .await
                .unwrap(),
            tgz,
            "the service bytes are written verbatim"
        );
    }

    // ───────────────────────── small helper arms ─────────────────────────

    /// A file squatting where `.socket/vendor` must be a directory makes the
    /// dest-parent creation fail — a `Done` failure naming the parent path.
    #[tokio::test]
    async fn prepare_tgz_dest_reports_an_uncreatable_parent() {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(tmp.path().join(".socket"))
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join(".socket/vendor"), b"squatter")
            .await
            .unwrap();
        let record = record_with_uuid(UUID);
        let coords = guard_coordinates(LP_PURL, &record).unwrap();
        let err = prepare_tgz_dest(LP_PURL, tmp.path(), &coords)
            .await
            .unwrap_err();
        let error = expect_done_failure(err, "cannot create");
        let parent = tmp.path().join(format!(".socket/vendor/npm/{UUID}"));
        assert!(
            error.contains(&parent.display().to_string()),
            "names the parent it could not create: {error}"
        );
    }

    /// An empty version (`pkg:npm/x@`) can never key an artifact path —
    /// parse returns None and `guard_coordinates` refuses fail-closed.
    #[test]
    fn parse_npm_purl_rejects_an_empty_version() {
        assert_eq!(parse_npm_purl("pkg:npm/x@"), None);
        assert_eq!(parse_npm_purl("pkg:npm/@scope/pkg@"), None);
        expect_refusal(
            guard_coordinates("pkg:npm/x@", &record_with_uuid(UUID)).unwrap_err(),
            "unsafe_coordinates",
        );
    }

    // ───────────────────── done_failure_unstage guards ─────────────────────

    fn expect_done_error(outcome: VendorOutcome, want_error: &str) {
        match outcome {
            VendorOutcome::Done { result, entry, .. } => {
                assert!(!result.success);
                assert_eq!(result.error.as_deref(), Some(want_error));
                assert!(entry.is_none());
            }
            other => panic!("expected Done failure, got {other:?}"),
        }
    }

    /// Unstaging one failed artifact must never take out a SIBLING uuid dir:
    /// the parent prune is non-recursive (`remove_dir` on a non-empty dir
    /// fails, deliberately silently).
    #[tokio::test]
    async fn unstage_preserves_sibling_artifacts_and_their_parents() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}");
        let failed_dir = root.join(&rel);
        let sibling = root.join(".socket/vendor/npm/00000000-0000-4000-8000-000000000000");
        tokio::fs::create_dir_all(&failed_dir).await.unwrap();
        tokio::fs::write(failed_dir.join("left-pad-1.3.0.tgz"), b"t")
            .await
            .unwrap();
        tokio::fs::create_dir_all(&sibling).await.unwrap();
        tokio::fs::write(sibling.join("other-1.0.0.tgz"), b"s")
            .await
            .unwrap();

        let outcome =
            done_failure_unstage(LP_PURL, "boom".to_string(), root, &rel, false).await;
        expect_done_error(outcome, "boom");
        assert!(!failed_dir.exists(), "the failed artifact dir is removed");
        assert!(
            sibling.join("other-1.0.0.tgz").exists(),
            "a sibling artifact must survive"
        );
        assert!(root.join(".socket/vendor/npm").exists());
        assert!(root.join(".socket/vendor").exists());
    }

    /// With no siblings the empty `npm/` and `vendor/` parents are pruned —
    /// but never `.socket` itself (blobs, manifest, and state live there).
    #[tokio::test]
    async fn unstage_prunes_empty_parents_but_never_dot_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("left-pad-1.3.0.tgz"), b"t")
            .await
            .unwrap();

        let outcome =
            done_failure_unstage(LP_PURL, "boom".to_string(), root, &rel, false).await;
        expect_done_error(outcome, "boom");
        assert!(
            !root.join(".socket/vendor").exists(),
            "empty parents are pruned"
        );
        assert!(
            root.join(".socket").exists(),
            ".socket itself is never pruned"
        );
    }

    /// `uuid_dir_preexisted` means the dir was there BEFORE this run: it may
    /// be referenced by live wiring, so the unwind must not delete it (or
    /// its contents), only report the failure.
    #[tokio::test]
    async fn unstage_never_deletes_a_preexisting_uuid_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel = format!(".socket/vendor/npm/{UUID}");
        let dir = root.join(&rel);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        tokio::fs::write(dir.join("left-pad-1.3.0.tgz"), b"live artifact")
            .await
            .unwrap();

        let outcome = done_failure_unstage(LP_PURL, "boom".to_string(), root, &rel, true).await;
        expect_done_error(outcome, "boom");
        assert_eq!(
            tokio::fs::read(dir.join("left-pad-1.3.0.tgz")).await.unwrap(),
            b"live artifact",
            "a pre-existing (possibly live) artifact dir survives untouched"
        );
    }
}
