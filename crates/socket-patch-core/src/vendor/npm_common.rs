//! Flavor-agnostic npm vendoring pipeline: coordinate guards plus the shared
//! stage→patch→pack steps.
//!
//! Every tarball-artifact npm flavor (package-lock, yarn classic/berry, pnpm
//! incl. legacy, bun) vendors the same way up to the wiring: validate the
//! coordinates fail-closed, stage a private copy of the installed package in
//! a tempdir OUTSIDE the project, prune nested `node_modules`, refuse
//! bundled-deps packages, run the hardened apply pipeline against the stage,
//! and pack the result into a deterministic tarball under
//! `.socket/vendor/npm/<uuid>/`. Only the lockfile wiring differs per flavor,
//! and it always runs LAST — so a refusal or failure in this pipeline leaves
//! the project byte-untouched (a dry run stops after verification and
//! creates nothing on disk). vlt shares the coordinate guards but vendors a
//! directory artifact instead (see [`super::npm_dir`]).

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{normalize_file_path, ApplyResult, PatchSources};
use crate::patch::copy_tree::remove_tree;
use crate::patch::package::read_archive_to_map;
use crate::patch::path_safety;
use crate::utils::fs::atomic_write_artifact;
use crate::utils::purl::{percent_decode_purl_component, strip_purl_qualifiers};

use super::common::{
    already_patched_result, done, failed_result, refused, service_offline_conflict,
};
use super::npm_dir;
use super::npm_pack::PackedTarball;
use super::path::vendor_uuid_dir_rel;
use super::reuse;
use super::service_fetch::{
    fetch_verified_archive, ServiceArtifact, ServiceAttempt, ServicePolicy, ServiceTerminal,
};
use super::source::PackageSource;
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

/// The code a pre-flight refusal carries. Every pre-flight gate returns
/// `Refused`; a `Done` cannot come out of one, and reads as a failure so a
/// plan built from it still leaves the package to the loop.
pub(super) fn refusal_code(outcome: &VendorOutcome) -> &'static str {
    match outcome {
        VendorOutcome::Refused { code, .. } => code,
        VendorOutcome::Done { .. } => "vendor_preflight_failed",
    }
}

/// Gate `packages` (npm purls with their records) against ONE read of the
/// project, for the vendor loop's download plan, in the order every
/// flavor's `vendor_*` gates them: each package is guarded first
/// ([`guard_coordinates`], the flavors' first gate, ahead of any read),
/// then a project the flavor refuses outright refuses it with that code,
/// and otherwise it is handed to the flavor's own per-package pre-flight.
/// The verdicts come back in `packages` order.
pub(super) fn gate_packages<P>(
    project: Result<P, &'static str>,
    packages: &[(&str, &PatchRecord)],
    gate: impl Fn(&P, &NpmCoords) -> Result<(), &'static str>,
) -> Vec<Result<(), &'static str>> {
    packages
        .iter()
        .map(|(purl, record)| {
            let coords = guard_coordinates(purl, record).map_err(|o| refusal_code(&o))?;
            match &project {
                Ok(project) => gate(project, &coords),
                Err(code) => Err(*code),
            }
        })
        .collect()
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
    /// True iff `<project>/.socket/vendor/npm/<uuid>` existed BEFORE this
    /// run wrote into it. A wiring failure after the pack must unwind the
    /// uuid dir the pipeline created — but never one that already existed
    /// (a same-uuid re-vendor's dir may still be referenced by live wiring);
    /// backends feed this to [`done_failure_unstage`].
    pub uuid_dir_preexisted: bool,
    /// The exact bytes a committed-artifact reuse hashed and verified
    /// (`None` for a fresh pack / download, which this run just wrote).
    /// A consumer that needs the tarball's bytes (yarn berry's checksum)
    /// uses these instead of re-reading the file, so nothing swapped in
    /// after verification can reach the lock.
    pub verified_bytes: Option<Vec<u8>>,
}

/// Reuse a verified committed tarball or download its immutable service artifact.
/// A dry run verifies the download without writing into the project. The
/// backend wires the returned artifact only after acquisition succeeds.
///
/// The artifact must survive the commit the vendored workflow ends with, so
/// git's ignore rules are checked on both sides of the write: a rule that
/// ignores the uuid dir itself (`.socket/`, `vendor/`) refuses
/// `vendor_artifact_gitignored` before anything is written, and once the
/// tarball is in place `<uuid>/.gitignore` re-includes it against file rules
/// such as Node.gitignore's `*.tgz`, then the written paths are probed again.
/// The uuid-dir half of [`stage_patch_pack`]'s gitignore check, for callers
/// that must refuse before an earlier irreversible step: the hosted->vendored
/// takeover restores the registry entry first, so a `.socket/` rule caught
/// only at staging would leave the package patched in neither mode.
pub async fn npm_tarball_gitignore_preflight(
    project_root: &Path,
    uuid: &str,
) -> Option<(&'static str, String)> {
    let uuid_dir_rel = vendor_uuid_dir_rel("npm", uuid)?;
    let rules = npm_dir::gitignored(project_root, &[format!("{uuid_dir_rel}/")]).await?;
    Some((
        npm_dir::GITIGNORED,
        npm_dir::gitignored_detail(&uuid_dir_rel, &rules),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn stage_patch_pack(
    purl: &str,
    installed_dir: PackageSource<'_>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dry_run: bool,
    force: bool,
    warnings: &mut Vec<VendorWarning>,
    service: Option<&VendorServiceConfig>,
) -> Result<(Option<NpmStagedPack>, ApplyResult), Box<VendorOutcome>> {
    let coords = guard_coordinates(purl, record)?;
    if let Some(rules) =
        npm_dir::gitignored(project_root, &[format!("{}/", coords.uuid_dir_rel)]).await
    {
        return Err(Box::new(refused(
            npm_dir::GITIGNORED,
            npm_dir::gitignored_detail(&coords.uuid_dir_rel, &rules),
        )));
    }
    let (staged, result) = acquire_patch_pack(
        purl,
        installed_dir,
        project_root,
        record,
        sources,
        dry_run,
        force,
        warnings,
        service,
    )
    .await?;
    if let Some(staged) = &staged {
        keep_pack_committable(purl, project_root, &coords, staged, warnings).await?;
    }
    Ok((staged, result))
}

/// Write `<uuid>/.gitignore` and `<uuid>/.gitattributes` next to the staged
/// tarball, then ask git whether it would commit them. Still ignored (a rule
/// the nested `.gitignore` cannot override) refuses and unwinds a uuid dir
/// this run created; git failing to answer is only a warning.
async fn keep_pack_committable(
    purl: &str,
    project_root: &Path,
    coords: &NpmCoords,
    staged: &NpmStagedPack,
    warnings: &mut Vec<VendorWarning>,
) -> Result<(), Box<VendorOutcome>> {
    let unstage = |error: String| {
        done_failure_unstage(
            purl,
            error,
            project_root,
            &coords.uuid_dir_rel,
            staged.uuid_dir_preexisted,
        )
    };
    let uuid_dir = project_root.join(&coords.uuid_dir_rel);
    if let Err(e) = npm_dir::restore_uuid_metadata(&uuid_dir).await {
        return Err(Box::new(
            unstage(format!(
                "cannot write {}/.gitignore: {e}",
                coords.uuid_dir_rel
            ))
            .await,
        ));
    }
    let probe = [
        staged.rel_tgz.clone(),
        format!("{}/.gitignore", coords.uuid_dir_rel),
        format!("{}/.gitattributes", coords.uuid_dir_rel),
    ];
    match npm_dir::gitignore_probe(project_root, &probe).await {
        Ok(Some(rules)) => {
            if !staged.uuid_dir_preexisted {
                let _ = remove_tree(&uuid_dir).await;
                super::common::prune_empty_vendor_levels(&uuid_dir).await;
            }
            Err(Box::new(refused(
                npm_dir::GITIGNORED,
                npm_dir::gitignored_detail(&staged.rel_tgz, &rules),
            )))
        }
        Ok(None) => Ok(()),
        Err(why) => {
            warnings.push(VendorWarning::new(
                npm_dir::GITIGNORE_UNCHECKED,
                npm_dir::gitignore_unchecked_detail(&staged.rel_tgz, &why),
            ));
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn acquire_patch_pack(
    purl: &str,
    _installed_dir: PackageSource<'_>,
    project_root: &Path,
    record: &PatchRecord,
    _sources: &PatchSources<'_>,
    dry_run: bool,
    _force: bool,
    warnings: &mut Vec<VendorWarning>,
    service: Option<&VendorServiceConfig>,
) -> Result<(Option<NpmStagedPack>, ApplyResult), Box<VendorOutcome>> {
    let coords = guard_coordinates(purl, record)?;

    if let Some(pair) = reuse_committed_pack(purl, project_root, &coords, record).await {
        return Ok(if dry_run { (None, pair.1) } else { pair });
    }

    // Acquisition is service-only; verified committed artifacts returned above.
    if let Some(refusal) = service_offline_conflict(service) {
        return Err(Box::new(refusal));
    }
    if let Some(cfg) = service {
        if cfg.service_enabled() {
            match try_service_pack(purl, project_root, &coords, record, cfg, dry_run, warnings)
                .await
            {
                ServicePackDecision::Used(pair) => return Ok(*pair),
                ServicePackDecision::HardFail(outcome) => return Err(outcome),
            }
        }
    }

    Err(Box::new(refused(
        "vendor_prebuilt_required",
        "vendoring requires a prebuilt artifact from the patch service".to_string(),
    )))
}

/// The staged pack for a verified committed tarball (see
/// [`super::reuse`]), or `None` to acquire as usual. Nothing is written, so
/// the pack reports `uuid_dir_preexisted: true` — a later wiring failure's
/// [`done_failure_unstage`] must never delete the committed artifact the
/// live ledger entry still names.
async fn reuse_committed_pack(
    purl: &str,
    project_root: &Path,
    coords: &NpmCoords,
    record: &PatchRecord,
) -> Option<(Option<NpmStagedPack>, ApplyResult)> {
    let rel_tgz = format!(
        "{}/{}",
        coords.uuid_dir_rel,
        tgz_rel_leaf(&coords.name, &coords.version)
    );
    let art = match reuse::reusable_committed_artifact(project_root, "npm", record, Some(&rel_tgz))
        .await
    {
        Ok(art) => art,
        Err(miss) => {
            reuse::log_miss(purl, &miss);
            return None;
        }
    };
    // A patched package.json feeds the flavor's dependency-mirror
    // recompute; read it from the SAME verified bytes.
    let staged_pkg_json = if record
        .files
        .keys()
        .any(|k| normalize_file_path(k) == "package.json")
    {
        match art
            .members
            .get("package.json")
            .and_then(|b| serde_json::from_slice::<Value>(b).ok())
        {
            Some(pkg) => Some(pkg),
            None => {
                reuse::log_miss(purl, &reuse::ReuseMiss::Unreadable);
                return None;
            }
        }
    } else {
        None
    };
    let result = already_patched_result(purl, &project_root.join(&rel_tgz), &record.files);
    Some((
        Some(NpmStagedPack {
            name: coords.name.clone(),
            version: coords.version.clone(),
            rel_tgz,
            packed: {
                let mut packed = PackedTarball::from_bytes(&art.bytes);
                packed.yarn_berry10c0 = art.entry.artifact.yarn_berry10c0.clone();
                packed
            },
            staged_pkg_json,
            uuid_dir_preexisted: true,
            verified_bytes: Some(art.bytes),
        }),
        result,
    ))
}

// ───────────────────────── service-download path ─────────────────────────

/// Outcome of attempting the service-download fast path in [`stage_patch_pack`]
/// (`Used`: the staged pack + a synthesized success, boxed — the pair is large).
type ServicePackDecision = ServiceAttempt<Box<(Option<NpmStagedPack>, ApplyResult)>>;

/// Download + verify the prebuilt tarball and turn it into an [`NpmStagedPack`],
/// mapping each service outcome onto the `auto` / `service` fallback policy.
async fn try_service_pack(
    purl: &str,
    project_root: &Path,
    coords: &NpmCoords,
    record: &PatchRecord,
    cfg: &VendorServiceConfig,
    dry_run: bool,
    warnings: &mut Vec<VendorWarning>,
) -> ServicePackDecision {
    let policy = ServicePolicy::new(cfg, ServiceTerminal::Failure(purl));
    let archive = match fetch_verified_archive(cfg, &record.uuid).await {
        // This backend's `service` refusal words a request failure differently.
        ServiceArtifact::Failed(reason) if cfg.source.requires_service() => {
            return policy.hard(
                "vendor_prebuilt_required",
                format!("patch service request failed: {reason}"),
            );
        }
        fetched => match policy.settle(fetched, "artifact", "artifact", warnings) {
            Ok(archive) => archive,
            Err(attempt) => return attempt,
        },
    };
    // The SRI proves only that the transfer is intact: require the tarball to
    // carry every patched file at its afterHash before reporting the package
    // patched and wiring the lock to it.
    if !tgz_bytes_match_after_hashes(&archive.bytes, record) {
        return policy.miss(
            warnings,
            "vendor_prebuilt_layout_mismatch",
            format!(
                "prebuilt tarball for {}@{} does not carry the patched files at their \
                 recorded paths",
                coords.name, coords.version
            ),
        );
    }
    if dry_run {
        return ServicePackDecision::Used(Box::new((
            None,
            super::common::preview_result(
                purl,
                &project_root.join(&coords.uuid_dir_rel),
                &record.files,
            ),
        )));
    }
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
        Ok(mut staged) => {
            staged.packed.yarn_berry10c0 = archive.yarn_berry10c0;
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored {}@{} from the patch service ({})",
                    coords.name, coords.version, archive.source_url
                ),
            ));
            // No local apply to verify — every patched file reads as
            // `AlreadyPatched` (the tarball's members were checked against
            // their afterHashes above).
            let result =
                already_patched_result(purl, &project_root.join(&staged.rel_tgz), &record.files);
            ServicePackDecision::Used(Box::new((Some(staged), result)))
        }
        Err(outcome) => ServicePackDecision::HardFail(outcome),
    }
}

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
    if let Err(e) = atomic_write_artifact(&dest, bytes).await {
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
        uuid_dir_preexisted,
        verified_bytes: None,
    })
}

/// True when the downloaded npm tarball (`package/`-rooted, like the
/// `record.files` keys) has every patched file hashing to its `afterHash`.
fn tgz_bytes_match_after_hashes(bytes: &[u8], record: &PatchRecord) -> bool {
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    let Ok(map) = crate::patch::package::read_archive_bytes_to_map(bytes) else {
        return false;
    };
    record.files.iter().all(|(file_name, info)| {
        map.get(normalize_file_path(file_name))
            .is_some_and(|content| compute_git_sha256_from_bytes(content) == info.after_hash)
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
pub(crate) fn is_safe_npm_name(name: &str) -> bool {
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
    format!("{}.tgz", pkg_rel_leaf(name, version))
}

/// `[@scope/]<name>-<version>`: the tarball leaf without `.tgz`, which the
/// vlt directory artifact uses as its version-bearing level.
pub(crate) fn pkg_rel_leaf(name: &str, version: &str) -> String {
    match name.split_once('/') {
        Some((scope, bare)) => format!("{scope}/{bare}-{version}"),
        None => format!("{name}-{version}"),
    }
}

/// The inverse of [`tgz_rel_leaf`] for a known `name`: the `<version>` of a
/// `[@scope/]<bare>-<version>.tgz` leaf (i.e. `<name>-<version>.tgz`), not
/// validated further. The split is anchored on `name`, never guessed from
/// the leaf alone, so prerelease versions such as `1.0.0-2` survive.
pub(crate) fn tgz_leaf_version<'l>(name: &str, leaf: &'l str) -> Option<&'l str> {
    leaf.strip_prefix(name)?
        .strip_prefix('-')?
        .strip_suffix(".tgz")
}

/// `bundleDependencies` (npm) / `bundledDependencies` (legacy alias):
/// `true` means "all deps", an array names them, and npm-bundled falls back
/// to `Object.keys(bd)` for any other truthy value — so an OBJECT form
/// bundles its keys too; any of these makes the package unvendorable (see
/// the refusal site).
pub(super) fn declares_bundled_deps(pkg: &Value) -> bool {
    ["bundleDependencies", "bundledDependencies"]
        .iter()
        .any(|k| match pkg.get(*k) {
            Some(Value::Bool(b)) => *b,
            Some(Value::Array(a)) => !a.is_empty(),
            Some(Value::Object(o)) => !o.is_empty(),
            _ => false,
        })
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
/// parent dirs are pruned non-recursively (a sibling artifact keeps them) up
/// to and including `.socket/vendor/`; `.socket/` itself is never pruned
/// here — the CLI holds `.socket/apply.lock` for the whole run, and its lock
/// guard removes the emptied directory when it releases.
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
        super::common::prune_empty_vendor_levels(&uuid_dir).await;
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

    /// The download plan gates a package in the loop's order: coordinates
    /// first, ahead of any read — so a malformed record in a project the
    /// flavor refuses carries `unsafe_coordinates`, as `vendor_*` reports
    /// it, and only a well-formed one carries the project's code. A
    /// readable project hands each well-formed package to the flavor's
    /// gate, in input order.
    #[test]
    fn gate_packages_guards_coordinates_before_it_consults_the_project() {
        let good = record_with_uuid(UUID);
        let bad_uuid = record_with_uuid("not-a-uuid");
        let packages: [(&str, &PatchRecord); 3] = [
            ("pkg:npm/left-pad@1.3.0", &bad_uuid),
            ("pkg:npm/left-pad@1.3.0", &good),
            ("pkg:npm/left-pad@1.2.0", &good),
        ];

        let unread: Result<(), &'static str> = Err("vendor_lockfile_missing");
        assert_eq!(
            gate_packages(unread, &packages, |(), _| unreachable!(
                "no project to gate against"
            )),
            vec![
                Err("unsafe_coordinates"),
                Err("vendor_lockfile_missing"),
                Err("vendor_lockfile_missing"),
            ]
        );

        let read: Result<(), &'static str> = Ok(());
        assert_eq!(
            gate_packages(read, &packages, |(), coords| {
                (coords.version == "1.3.0")
                    .then_some(())
                    .ok_or("vendor_lock_entry_not_found")
            }),
            vec![
                Err("unsafe_coordinates"),
                Ok(()),
                Err("vendor_lock_entry_not_found"),
            ]
        );
        assert_eq!(gate_packages(read, &[], |(), _| Ok(())), Vec::new());
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
        let with =
            |key: &str, v: serde_json::Value| declares_bundled_deps(&serde_json::json!({ key: v }));
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
        assert!(warnings
            .iter()
            .all(|w| w.code == "vendor_prebuilt_downloaded"));
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
            (&root.join("node_modules/left-pad")).into(),
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

    async fn build_tgz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let tmp = tempfile::tempdir().unwrap();
        let staged = tmp.path().join("staged");
        tokio::fs::create_dir_all(&staged).await.unwrap();
        for &(name, bytes) in files {
            tokio::fs::write(staged.join(name), bytes).await.unwrap();
        }
        let dest = tmp.path().join("built.tgz");
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        archive.append_dir_all("package", &staged).unwrap();
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        tokio::fs::write(&dest, bytes).await.unwrap();
        tokio::fs::read(&dest).await.unwrap()
    }

    // ─────────────── service fast path: the hard-fail arms ───────────────

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::vendor::VendorSource;

    const SERVE_PATH: &str = "/patch/npm/left-pad/1.3.0/tok/uuid/left-pad-1.3.0.tgz";

    fn service_cfg(server_uri: &str, source: VendorSource) -> VendorServiceConfig {
        VendorServiceConfig {
            maven_config: None,
            source,
            client: Some(
                ApiClient::new(ApiClientOptions {
                    api_url: server_uri.to_string(),
                    api_token: Some("sktsec_placeholder_value_for_tests_api".into()),
                    route: crate::api::client::ApiRoute::org("acme"),
                })
                .with_vendor_retry(crate::api::client::VendorRetryPolicy::none()),
            ),
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

    #[tokio::test]
    async fn noncanonical_service_sri_hard_fails_with_no_auto_fallback() {
        let tgz = build_tgz(&[("index.js", PATCHED_INDEX)]).await;
        let canonical = PackedTarball::from_bytes(&tgz).integrity;
        let served_sri = format!("{canonical} sha256-AAAA");
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, &served_sri, &tgz).await;

        let record = patched_index_record();
        for source in [VendorSource::Service] {
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

    /// A record patching `package/index.js` to `PATCHED_INDEX` (real hashes,
    /// so a served tarball carrying the patch passes the afterHash check).
    fn patched_index_record() -> PatchRecord {
        use crate::hash::git_sha256::compute_git_sha256_from_bytes;
        let mut record = record_with_uuid(UUID);
        record.files.clear();
        record.files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(ORIG_INDEX),
                after_hash: compute_git_sha256_from_bytes(PATCHED_INDEX),
            },
        );
        record
    }

    /// A served tarball with an intact SRI whose `index.js` is still the
    /// ORIGINAL bytes is not the patched package: `service` fails the package
    /// and writes nothing; `auto` warns and builds locally instead.
    #[tokio::test]
    async fn service_tarball_failing_after_hashes_is_rejected() {
        let tgz = build_tgz(&[("index.js", ORIG_INDEX)]).await;
        let sri = PackedTarball::from_bytes(&tgz).integrity;
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, &sri, &tgz).await;

        let tmp = tempfile::tempdir().unwrap();
        let cfg = service_cfg(&server.uri(), VendorSource::Service);
        let err = expect_err(run_pipeline(tmp.path(), &patched_index_record(), Some(&cfg)).await);
        expect_done_failure(err, "does not carry the patched files");
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "an unpatched service tarball is never written"
        );

        let (tmp, record) = local_fixture(b"{\"name\":\"left-pad\",\"version\":\"1.3.0\"}").await;
        let root = tmp.path();
        let blobs = root.join(".socket/blobs");
        let sources = PatchSources::blobs_only(&blobs);
        let mut warnings = Vec::new();
        let cfg = service_cfg(&server.uri(), VendorSource::Service);
        let err = expect_err(
            stage_patch_pack(
                LP_PURL,
                (&root.join("node_modules/left-pad")).into(),
                root,
                &record,
                &sources,
                false,
                false,
                &mut warnings,
                Some(&cfg),
            )
            .await,
        );
        expect_done_failure(err, "does not carry the patched files");
        assert!(!root.join(".socket/vendor").exists());
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
        let err =
            expect_err(service_bytes(tmp.path(), &record, b"tarball bytes", "sha512-AAAA").await);
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

    /// A reuse hands the flavor the EXACT bytes it verified (yarn berry
    /// derives its checksum from them rather than re-reading a file that
    /// may have been swapped since); a fresh download carries none.
    #[tokio::test]
    async fn reused_pack_carries_the_verified_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let mut record = record_with_uuid(UUID);
        record.files.get_mut("package/index.js").unwrap().after_hash =
            crate::hash::git_sha256::compute_git_sha256_from_bytes(PATCHED_INDEX);
        let tgz = build_tgz(&[
            ("index.js", PATCHED_INDEX),
            ("package.json", br#"{"name":"left-pad","version":"1.3.0"}"#),
        ])
        .await;
        let sri = PackedTarball::from_bytes(&tgz).integrity;
        let fresh = service_bytes(tmp.path(), &record, &tgz, &sri)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        assert!(fresh.verified_bytes.is_none());
        let entry = crate::vendor::state::VendorEntry {
            ecosystem: "npm".into(),
            base_purl: LP_PURL.into(),
            uuid: record.uuid.clone(),
            artifact: crate::vendor::state::VendorArtifact {
                yarn_berry10c0: None,
                path: fresh.rel_tgz.clone(),
                sha256: fresh.packed.sha256_hex.clone(),
                size: Some(fresh.packed.size),
                platform_locked: None,
                file_inventory: None,
            },
            wiring: Vec::new(),
            lock: None,
            took_over_go_patches: false,
            flavor: Some("yarn-berry".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
            detached: false,
            record: None,
        };
        crate::vendor::test_support::persist(tmp.path(), LP_PURL, entry).await;
        let coords = guard_coordinates(LP_PURL, &record).unwrap();
        let (staged, _) = reuse_committed_pack(LP_PURL, tmp.path(), &coords, &record)
            .await
            .expect("the committed tarball is reused");
        let staged = staged.unwrap();
        assert_eq!(staged.verified_bytes.as_deref(), Some(tgz.as_slice()));
        assert!(staged.uuid_dir_preexisted);
    }

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

    // ──────────────── git ignore rules over the staged tarball ────────────────

    /// A git work tree at `root` whose `.gitignore` is `rules`, or `None`
    /// when git is not installed.
    fn git_project(root: &Path, rules: &str) -> Option<()> {
        let git = crate::utils::process::resolve_tool("git")?;
        let ok = std::process::Command::new(git)
            .arg("-C")
            .arg(root)
            .args(["init", "-q"])
            .status()
            .ok()?
            .success();
        assert!(ok, "git init");
        std::fs::write(root.join(".gitignore"), rules).unwrap();
        Some(())
    }

    async fn granted_service() -> wiremock::MockServer {
        let tgz = build_tgz(&[("index.js", PATCHED_INDEX)]).await;
        let sri = PackedTarball::from_bytes(&tgz).integrity;
        let server = wiremock::MockServer::start().await;
        mount_granted(&server, &sri, &tgz).await;
        server
    }

    /// #831: GitHub's stock Node.gitignore ignores `*.tgz`. The staged
    /// tarball gets a `<uuid>/.gitignore` that re-includes it, so git
    /// commits it with the rewired lockfile.
    #[tokio::test]
    async fn a_tgz_ignore_rule_is_overridden_by_the_uuid_gitignore() {
        let tmp = tempfile::tempdir().unwrap();
        if git_project(tmp.path(), "node_modules\n*.tgz\n").is_none() {
            return;
        }
        let server = granted_service().await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service);
        let (staged, _) = run_pipeline(tmp.path(), &patched_index_record(), Some(&cfg))
            .await
            .unwrap_or_else(|e| panic!("a re-includable rule must not refuse: {e:?}"));
        let staged = staged.expect("a wet run stages the tarball");
        let uuid_dir = tmp.path().join(format!(".socket/vendor/npm/{UUID}"));
        assert_eq!(
            std::fs::read_to_string(uuid_dir.join(".gitignore")).unwrap(),
            npm_dir::UUID_GITIGNORE
        );
        assert_eq!(
            std::fs::read_to_string(uuid_dir.join(".gitattributes")).unwrap(),
            npm_dir::UUID_GITATTRIBUTES
        );
        assert_eq!(
            npm_dir::gitignored(tmp.path(), std::slice::from_ref(&staged.rel_tgz)).await,
            None,
            "git commits the vendored tarball"
        );
    }

    /// #831: a rule ignoring the uuid dir itself (`vendor/`, `.socket/`)
    /// can't be overridden from inside it, so vendoring refuses before
    /// writing anything, dry run included.
    #[tokio::test]
    async fn a_directory_ignore_rule_refuses_before_any_write() {
        for rule in ["vendor/", ".socket/", ".socket/vendor/"] {
            for dry_run in [false, true] {
                let tmp = tempfile::tempdir().unwrap();
                if git_project(tmp.path(), &format!("node_modules\n{rule}\n")).is_none() {
                    return;
                }
                let server = granted_service().await;
                let cfg = service_cfg(&server.uri(), VendorSource::Service);
                let blobs = tmp.path().join(".socket/blobs");
                let sources = PatchSources::blobs_only(&blobs);
                let mut warnings = Vec::new();
                let err = expect_err(
                    stage_patch_pack(
                        LP_PURL,
                        (&tmp.path().join("node_modules/left-pad")).into(),
                        tmp.path(),
                        &patched_index_record(),
                        &sources,
                        dry_run,
                        false,
                        &mut warnings,
                        Some(&cfg),
                    )
                    .await,
                );
                expect_refusal(err, npm_dir::GITIGNORED);
                assert!(
                    !tmp.path().join(".socket/vendor").exists(),
                    "{rule} (dry run {dry_run}): nothing is written"
                );
            }
        }
    }

    /// Outside a git work tree there is nothing to commit, so no rule
    /// applies and the pack stages as before (metadata included).
    #[tokio::test]
    async fn no_work_tree_stages_without_a_refusal() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".gitignore"), ".socket/\n").unwrap();
        let server = granted_service().await;
        let cfg = service_cfg(&server.uri(), VendorSource::Service);
        let (staged, _) = run_pipeline(tmp.path(), &patched_index_record(), Some(&cfg))
            .await
            .unwrap_or_else(|e| panic!("no work tree, no refusal: {e:?}"));
        assert!(staged.is_some());
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

        let outcome = done_failure_unstage(LP_PURL, "boom".to_string(), root, &rel, false).await;
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

        let outcome = done_failure_unstage(LP_PURL, "boom".to_string(), root, &rel, false).await;
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
            tokio::fs::read(dir.join("left-pad-1.3.0.tgz"))
                .await
                .unwrap(),
            b"live artifact",
            "a pre-existing (possibly live) artifact dir survives untouched"
        );
    }
}
