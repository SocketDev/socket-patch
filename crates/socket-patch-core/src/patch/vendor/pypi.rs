//! pypi vendor backend: flavor routing + orchestration.
//!
//! Order of operations is the safety story: every refusal-capable check
//! (flavor route, uv project guards, requirements pre-flight, dist lookup,
//! tag compression) runs BEFORE the wheel artifact is built, and the
//! lockfile/manifest wiring is written LAST — so a refusal leaves the tree
//! byte-untouched and an artifact failure never leaves half-wired lockfiles.

use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::pth_hook::detect::has_table;
use crate::utils::fs::atomic_write_bytes;
use crate::utils::purl::{parse_pypi_purl, strip_purl_qualifiers};

use super::common::{already_patched_result, done, refused, service_offline_conflict};
use super::path::vendor_uuid_dir_rel;
use super::pypi_pdm::{PdmProject, PdmTarget};
use super::pypi_pipenv::{PipenvProject, PipenvTarget};
use super::pypi_poetry::{PoetryProject, PoetryTarget};
use super::pypi_requirements::{preflight_requirements, revert_requirements, wire_requirements};
use super::pypi_uv::{
    check_target_guards, load_uv_project, revert_uv, wire_uv, UvProject, UvTarget,
};
use super::pypi_wheel::{
    build_patched_wheel, locate_installed_dist, wheel_file_name, WheelArtifact,
};
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::state::{
    write_marker, PdmMeta, PipenvMeta, PoetryMeta, UvMeta, VendorArtifact, VendorEntry,
    VendorMarker,
};
use super::{RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// Which wiring backend serves this project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PypiFlavor {
    /// `uv.lock`-managed project → paired pyproject + lock surgery.
    UvProject,
    /// `poetry.lock`-managed project → lock-only `[[package]]` splice.
    Poetry,
    /// `pdm.lock`-managed project → lock-only `[[package]]` splice.
    Pdm,
    /// `Pipfile.lock`-managed project → lock-only JSON entry rewrite.
    Pipenv,
    /// Plain `requirements.txt` (pip / `uv pip`) → line rewriting.
    Requirements,
}

impl PypiFlavor {
    fn as_str(self) -> &'static str {
        match self {
            PypiFlavor::UvProject => "uv",
            PypiFlavor::Poetry => "poetry",
            PypiFlavor::Pdm => "pdm",
            PypiFlavor::Pipenv => "pipenv",
            PypiFlavor::Requirements => "requirements",
        }
    }
}

const SETUP_ALTERNATIVE: &str =
    "use the `socket-patch setup` .pth install hook instead, which patches installed \
     site-packages without lockfile edits";

/// Route the project to a wiring flavor, first match wins. Lockfiles are the
/// authoritative "this tool manages installs" signal, so locks are compared
/// with locks (precedence follows migration direction / ecosystem currency:
/// uv > poetry > pdm > pipenv), and a lock-less tool MARKER refuses with a
/// "run `<tool> lock`" pointer — falling through to `requirements.txt` when
/// one exists (a marker alone must not block the requirements wiring):
/// 1. `uv.lock` → uv;  2. `poetry.lock` → poetry;  3. `pdm.lock` → pdm;
/// 4. `Pipfile.lock` → pipenv;
/// 5. lock-less `[tool.uv]`/`[tool.poetry]`/`[tool.pdm]`/`Pipfile` →
///    `<tool>_no_lockfile` refusal unless requirements.txt exists;
/// 6. `requirements.txt` → requirements;
/// 7. a lone pyproject → refuse;  8. nothing → refuse.
///
/// When more than one tool lockfile coexists, the winner is wired and a LOUD
/// `pypi_multiple_lockfiles` warning names the ignored locks — they go
/// stale-but-valid, which is otherwise invisible.
async fn detect_pypi_flavor(
    project_root: &Path,
) -> Result<(PypiFlavor, Vec<VendorWarning>), (&'static str, String)> {
    let exists = |name: &str| {
        let p = project_root.join(name);
        async move { tokio::fs::metadata(&p).await.is_ok() }
    };
    let has_uv_lock = exists("uv.lock").await;
    let has_poetry_lock = exists("poetry.lock").await;
    let has_pdm_lock = exists("pdm.lock").await;
    let has_pipfile_lock = exists("Pipfile.lock").await;
    let has_pipfile = exists("Pipfile").await;

    // Coexisting tool locks: wire the precedence winner, warn about the rest.
    let present: Vec<&str> = [
        ("uv.lock", has_uv_lock),
        ("poetry.lock", has_poetry_lock),
        ("pdm.lock", has_pdm_lock),
        ("Pipfile.lock", has_pipfile_lock),
    ]
    .into_iter()
    .filter_map(|(name, present)| present.then_some(name))
    .collect();
    let mut warnings = Vec::new();
    if present.len() > 1 {
        let winner = present[0];
        let losers = present[1..].join(", ");
        warnings.push(VendorWarning::new(
            "pypi_multiple_lockfiles",
            format!(
                "multiple python lockfiles found; wiring `{winner}` — installs driven by \
                 {losers} will still install the UNPATCHED registry bytes"
            ),
        ));
    }

    if has_uv_lock {
        return Ok((PypiFlavor::UvProject, warnings));
    }
    if has_poetry_lock {
        return Ok((PypiFlavor::Poetry, warnings));
    }
    if has_pdm_lock {
        return Ok((PypiFlavor::Pdm, warnings));
    }
    if has_pipfile_lock {
        return Ok((PypiFlavor::Pipenv, warnings));
    }

    let pyproject_text = tokio::fs::read_to_string(project_root.join("pyproject.toml"))
        .await
        .ok();
    let has_requirements = exists("requirements.txt").await;
    let has_pyproject_table = |prefix: &str| {
        pyproject_text
            .as_deref()
            .map(|t| has_table(t, prefix))
            .unwrap_or(false)
    };
    // Lock-less tool markers: a `requirements.txt` fallback wins (the marker
    // alone must not block wiring the file pip/uv-pip actually install from);
    // without one, refuse with the tool-specific "generate your lock" pointer.
    if !has_requirements {
        if has_pyproject_table("tool.uv") {
            return Err((
                "pypi_uv_no_lockfile",
                format!(
                    "pyproject.toml declares [tool.uv] but there is no uv.lock; run `uv lock` and \
                     re-run vendor, or {SETUP_ALTERNATIVE}"
                ),
            ));
        }
        if has_pyproject_table("tool.poetry") {
            return Err((
                "pypi_poetry_no_lockfile",
                format!(
                    "pyproject.toml declares [tool.poetry] but there is no poetry.lock; run \
                     `poetry lock` and re-run vendor, or {SETUP_ALTERNATIVE}"
                ),
            ));
        }
        if has_pyproject_table("tool.pdm") {
            return Err((
                "pypi_pdm_no_lockfile",
                format!(
                    "pyproject.toml declares [tool.pdm] but there is no pdm.lock; run `pdm lock` \
                     and re-run vendor, or {SETUP_ALTERNATIVE}"
                ),
            ));
        }
        if has_pipfile {
            return Err((
                "pypi_pipenv_no_lockfile",
                format!(
                    "a Pipfile exists but there is no Pipfile.lock; run `pipenv lock` and re-run \
                     vendor, or {SETUP_ALTERNATIVE}"
                ),
            ));
        }
    }
    if has_requirements {
        return Ok((PypiFlavor::Requirements, warnings));
    }
    if pyproject_text.is_some() {
        return Err((
            "pypi_pyproject_only",
            format!(
                "the project has a pyproject.toml but no lockfile or requirements.txt to wire; \
                 {SETUP_ALTERNATIVE}"
            ),
        ));
    }
    Err((
        "pypi_no_requirements",
        format!(
            "no uv.lock, pyproject.toml, or requirements.txt found at the project root; \
             {SETUP_ALTERNATIVE}"
        ),
    ))
}

/// Per-flavor pre-flight result carried into the wiring step (the loaded
/// project is reused so the lock is parsed once).
enum WiringPlan {
    Uv(Box<UvProject>),
    Requirements,
    Poetry(Box<PoetryProject>),
    Pdm(Box<PdmProject>),
    Pipenv(Box<PipenvProject>),
    /// The lock already routes this package through THIS patch uuid's
    /// vendored wheel: no wiring — verify (or rebuild) the artifact only.
    InSync,
}

/// Which `VendorEntry` meta slot a flavor's wiring produced.
enum MetaSlot {
    Uv(Option<UvMeta>),
    Poetry(PoetryMeta),
    Pdm(PdmMeta),
    Pipenv(PipenvMeta),
    None,
}

/// The uuid dir holds a wheel artifact — the cheap, flavor-agnostic
/// presence probe for the in-sync hot path (one uuid owns one wheel).
async fn uuid_dir_has_wheel(uuid_dir: &Path) -> bool {
    let Ok(mut rd) = tokio::fs::read_dir(uuid_dir).await else {
        return false;
    };
    while let Ok(Some(e)) = rd.next_entry().await {
        if e.file_name().to_string_lossy().ends_with(".whl") {
            return true;
        }
    }
    false
}

/// Vendor one pypi package: route the flavor, pre-flight every guard, build
/// the patched wheel at `.socket/vendor/pypi/<uuid>/<wheel>`, write the
/// marker, then wire the project files (LAST).
#[allow(clippy::too_many_arguments)]
pub async fn vendor_pypi(
    purl: &str,
    site_packages: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    // The purl may carry `?artifact_id=` variant qualifiers; everything here
    // keys off the qualifier-free base.
    let base = strip_purl_qualifiers(purl);
    let Some((raw_name, version)) = parse_pypi_purl(base) else {
        return refused(
            "pypi_invalid_purl",
            format!("{purl} is not a pkg:pypi PURL with a version"),
        );
    };
    let canon_name = canonicalize_pypi_name(raw_name);

    // SECURITY: the uuid comes from a committed, tamper-able manifest and
    // keys the on-disk artifact directory vendor creates (and --revert
    // deletes). Anything but the canonical UUID grammar is rejected
    // fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("pypi", &record.uuid) else {
        return refused(
            "vendor_unsafe_uuid",
            format!(
                "patch uuid {:?} is not a canonical lowercase uuid; refusing to derive a \
                 vendor path from it",
                record.uuid
            ),
        );
    };

    let (flavor, flavor_warnings) = match detect_pypi_flavor(project_root).await {
        Ok(f) => f,
        Err((code, detail)) => return refused(code, detail),
    };

    // Pre-flight the wiring guards BEFORE building anything, so refusals
    // leave the tree byte-untouched.
    let mut warnings: Vec<VendorWarning> = flavor_warnings;
    let plan = match flavor {
        PypiFlavor::UvProject => {
            let project = match load_uv_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return refused(code, detail),
            };
            match check_target_guards(&project, &canon_name, &record.uuid) {
                Ok(UvTarget::InSync) => WiringPlan::InSync,
                Ok(UvTarget::Fresh) => {
                    warnings.extend(project.warnings.iter().cloned());
                    WiringPlan::Uv(Box::new(project))
                }
                Err((code, detail)) => return refused(code, detail),
            }
        }
        PypiFlavor::Requirements => {
            if let Err((code, detail)) =
                preflight_requirements(project_root, &canon_name, version).await
            {
                return refused(code, detail);
            }
            WiringPlan::Requirements
        }
        PypiFlavor::Poetry => {
            let project = match super::pypi_poetry::load_poetry_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return refused(code, detail),
            };
            match super::pypi_poetry::check_target_guards(
                &project,
                &canon_name,
                version,
                &record.uuid,
            ) {
                Ok(PoetryTarget::InSync) => WiringPlan::InSync,
                Ok(PoetryTarget::Fresh) => {
                    warnings.extend(project.warnings.iter().cloned());
                    WiringPlan::Poetry(Box::new(project))
                }
                Err((code, detail)) => return refused(code, detail),
            }
        }
        PypiFlavor::Pdm => {
            let project = match super::pypi_pdm::load_pdm_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return refused(code, detail),
            };
            match super::pypi_pdm::check_target_guards(&project, &canon_name, version, &record.uuid)
            {
                Ok(PdmTarget::InSync) => WiringPlan::InSync,
                Ok(PdmTarget::Fresh) => {
                    warnings.extend(project.warnings.iter().cloned());
                    WiringPlan::Pdm(Box::new(project))
                }
                Err((code, detail)) => return refused(code, detail),
            }
        }
        PypiFlavor::Pipenv => {
            let project = match super::pypi_pipenv::load_pipenv_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return refused(code, detail),
            };
            match super::pypi_pipenv::check_target_guards(&project, &canon_name, &record.uuid) {
                Ok(PipenvTarget::InSync) => WiringPlan::InSync,
                Ok(PipenvTarget::Fresh) => {
                    warnings.extend(project.warnings.iter().cloned());
                    WiringPlan::Pipenv(Box::new(project))
                }
                Err((code, detail)) => return refused(code, detail),
            }
        }
    };

    let in_sync = matches!(plan, WiringPlan::InSync);
    if in_sync {
        // Wired to this uuid already. Intact artifact → the classic in-sync
        // skip: nothing is built or recorded — the first run's ledger entry
        // holds the only copy of the originals (and no dist lookup, so a
        // not-installed re-run stays green). Missing artifact → rebuild the
        // wheel only; the wiring is correct and re-running it would re-record
        // live vendored fragments as pre-vendor originals.
        if uuid_dir_has_wheel(&project_root.join(&uuid_dir_rel)).await || dry_run {
            return done(
                already_patched_result(base, Path::new(""), &record.files),
                None,
                warnings,
            );
        }
    }

    // Acquire the patched wheel: prefer the prebuilt service artifact (which
    // skips needing the package installed), else build it locally. A refusal /
    // hard fail bubbles as a terminal outcome.
    let AcquiredWheel {
        wheel_name,
        rel_wheel,
        result,
        artifact,
        platform_locked,
        platform_tags_display,
    } = match acquire_patched_wheel(
        base,
        raw_name,
        version,
        site_packages,
        &uuid_dir_rel,
        project_root,
        record,
        sources,
        dry_run,
        force,
        service,
        &mut warnings,
    )
    .await
    {
        Ok(a) => a,
        Err(outcome) => return outcome,
    };
    if dry_run || !result.success {
        return done(result, None, warnings);
    }
    let Some(artifact) = artifact else {
        // Defensive: success without an artifact would be a bug upstream.
        let mut result = result;
        result.success = false;
        result.error = Some("wheel build reported success without an artifact".to_string());
        return done(result, None, warnings);
    };

    // A compiled-extension wheel (cp311/manylinux tags) only installs on this
    // platform, where the registry offered wheels for many — surface it.
    if platform_locked {
        let per_flavor = match flavor {
            PypiFlavor::UvProject => "uv.lock now resolves it from this single-platform wheel only",
            PypiFlavor::Poetry => {
                "poetry.lock now resolves it from this single-platform wheel only"
            }
            PypiFlavor::Pdm => "pdm.lock now resolves it from this single-platform wheel only",
            PypiFlavor::Pipenv => {
                "Pipfile.lock now resolves it from this single-platform wheel only"
            }
            PypiFlavor::Requirements => {
                "the requirements.txt path line installs on this platform only"
            }
        };
        warnings.push(VendorWarning::new(
            "vendor_platform_locked",
            format!(
                "the vendored wheel for {canon_name}=={version} is platform-specific \
                 ({platform_tags_display}); {per_flavor}"
            ),
        ));
    }

    if in_sync {
        // Artifact rebuilt; wiring untouched, ledger entry stays with the
        // first run (the only copy of the pre-vendor originals).
        warnings.push(VendorWarning::new(
            "vendor_artifact_rebuilt",
            format!(
                "the committed vendored wheel for {canon_name}=={version} was missing; \
                 rebuilt at {rel_wheel} (lockfile untouched)"
            ),
        ));
        // Restore the informational marker the deleted uuid dir lost.
        let marker = VendorMarker::new("pypi", base, record, vendored_at);
        if let Err(e) = write_marker(&project_root.join(&uuid_dir_rel), &marker).await {
            warnings.push(VendorWarning::new(
                "marker_write_failed",
                format!("could not write the vendor marker: {e}"),
            ));
        }
        return done(result, None, warnings);
    }

    // Marker: artifact-side breadcrumb in the uuid dir (informational only —
    // sweep/verify key off state.json + the path uuid). Written before the
    // wiring so lockfile edits stay the last mutation.
    let marker = VendorMarker::new("pypi", base, record, vendored_at);
    if let Err(e) = write_marker(&project_root.join(&uuid_dir_rel), &marker).await {
        let _ = tokio::fs::remove_dir_all(project_root.join(&uuid_dir_rel)).await;
        let mut result = result;
        result.success = false;
        result.error = Some(format!("cannot write vendor marker: {e}"));
        return done(result, None, warnings);
    }

    // Wiring LAST. On failure the wheel artifact is swept back out so a
    // failed vendor leaves no committed residue.
    let wired: Result<(Vec<_>, MetaSlot), (&'static str, String)> = match plan {
        WiringPlan::Uv(project) => wire_uv(
            &project,
            project_root,
            &canon_name,
            version,
            &rel_wheel,
            &wheel_name,
            &artifact.sha256_hex,
            &record.uuid,
        )
        .await
        .map(|(wiring, meta)| (wiring, MetaSlot::Uv(Some(meta)))),
        WiringPlan::Requirements => wire_requirements(
            project_root,
            &canon_name,
            version,
            &rel_wheel,
            &artifact.sha256_hex,
        )
        .await
        .map(|wiring| (wiring, MetaSlot::None)),
        WiringPlan::Poetry(project) => super::pypi_poetry::wire_poetry(
            &project,
            project_root,
            &canon_name,
            version,
            &rel_wheel,
            &wheel_name,
            &artifact.sha256_hex,
            &record.uuid,
        )
        .await
        .map(|(wiring, meta)| (wiring, MetaSlot::Poetry(meta))),
        WiringPlan::Pdm(project) => super::pypi_pdm::wire_pdm(
            &project,
            project_root,
            &canon_name,
            version,
            &rel_wheel,
            &wheel_name,
            &artifact.sha256_hex,
            &record.uuid,
        )
        .await
        .map(|(wiring, meta)| (wiring, MetaSlot::Pdm(meta))),
        WiringPlan::Pipenv(project) => super::pypi_pipenv::wire_pipenv(
            &project,
            project_root,
            &canon_name,
            &rel_wheel,
            &artifact.sha256_hex,
            &record.uuid,
        )
        .await
        .map(|(wiring, meta)| (wiring, MetaSlot::Pipenv(meta))),
        // Returned right after the wheel build above.
        WiringPlan::InSync => unreachable!("in-sync rebuilds never reach wiring"),
    };
    let (wiring, meta) = match wired {
        Ok(pair) => pair,
        Err((code, detail)) => {
            let _ = tokio::fs::remove_dir_all(project_root.join(&uuid_dir_rel)).await;
            let mut result = result;
            result.success = false;
            result.error = Some(format!("{code}: {detail}"));
            return done(result, None, warnings);
        }
    };

    let mut entry = VendorEntry {
        ecosystem: "pypi".to_string(),
        base_purl: base.to_string(),
        uuid: record.uuid.clone(),
        artifact: VendorArtifact {
            path: rel_wheel,
            sha256: artifact.sha256_hex,
            size: Some(artifact.size),
            platform_locked: platform_locked.then_some(true),
        },
        wiring,
        lock: None,
        took_over_go_patches: false,
        detached: false,
        record: None,
        flavor: Some(flavor.as_str().to_string()),
        uv: None,
        pnpm: None,
        poetry: None,
        pdm: None,
        pipenv: None,
    };
    match meta {
        MetaSlot::Uv(m) => entry.uv = m,
        MetaSlot::Poetry(m) => entry.poetry = Some(m),
        MetaSlot::Pdm(m) => entry.pdm = Some(m),
        MetaSlot::Pipenv(m) => entry.pipenv = Some(m),
        MetaSlot::None => {}
    }
    done(result, Some(entry), warnings)
}

/// Revert one pypi vendor entry: reverse the wiring per flavor, then remove
/// the artifact uuid dir (validated path only — never a path taken on faith
/// from state.json).
pub async fn revert_pypi(entry: &VendorEntry, project_root: &Path, dry_run: bool) -> RevertOutcome {
    let mut outcome = match entry.flavor.as_deref() {
        Some("uv") => revert_uv(entry, project_root, dry_run).await,
        Some("requirements") => revert_requirements(entry, project_root, dry_run).await,
        Some("poetry") => super::pypi_poetry::revert_poetry(entry, project_root, dry_run).await,
        Some("pdm") => super::pypi_pdm::revert_pdm(entry, project_root, dry_run).await,
        Some("pipenv") => super::pypi_pipenv::revert_pipenv(entry, project_root, dry_run).await,
        other => {
            return RevertOutcome::failed(format!(
                "unknown pypi vendor flavor {other:?}; cannot revert"
            ))
        }
    };
    if !outcome.success || dry_run {
        return outcome;
    }
    // SECURITY: entry.uuid comes from the committed, tamper-able state.json
    // and names a directory for DELETION. Re-validate through the canonical
    // uuid grammar; on failure warn and keep the dir (fail-closed).
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("pypi", &entry.uuid) else {
        outcome.warnings.push(VendorWarning::new(
            "vendor_unsafe_uuid",
            format!(
                "refusing to delete an artifact dir for non-canonical uuid {:?}",
                entry.uuid
            ),
        ));
        return outcome;
    };
    match tokio::fs::remove_dir_all(project_root.join(&uuid_dir_rel)).await {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => outcome.warnings.push(VendorWarning::new(
            "vendor_artifact_remove_failed",
            format!("could not remove {uuid_dir_rel}: {e}"),
        )),
    }
    outcome
}

/// The patched wheel plus the facts the wiring + ledger need, however it was
/// acquired (service download or local build).
struct AcquiredWheel {
    wheel_name: String,
    rel_wheel: String,
    result: ApplyResult,
    /// `None` on a dry run or a failed build (the caller short-circuits).
    artifact: Option<WheelArtifact>,
    platform_locked: bool,
    /// Tag list for the `vendor_platform_locked` advisory.
    platform_tags_display: String,
}

/// Acquire the patched wheel: prefer the prebuilt service artifact (which does
/// not require the package to be installed), else build it locally from the
/// installed dist. Returns `Err(outcome)` with the terminal `VendorOutcome` to
/// bubble (a refusal, or a `service`-mode miss).
#[allow(clippy::too_many_arguments)]
async fn acquire_patched_wheel(
    base: &str,
    raw_name: &str,
    version: &str,
    site_packages: &Path,
    uuid_dir_rel: &str,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
    warnings: &mut Vec<VendorWarning>,
) -> Result<AcquiredWheel, VendorOutcome> {
    if let Some(refusal) = service_offline_conflict(service) {
        return Err(refusal);
    }
    if let Some(cfg) = service {
        // A dry run previews the local build; the service is only consulted for
        // a real vendor.
        if cfg.service_enabled() && !dry_run {
            match try_pypi_service_wheel(
                base,
                raw_name,
                uuid_dir_rel,
                project_root,
                record,
                cfg,
                warnings,
            )
            .await
            {
                PypiServiceWheel::Used(acq) => return Ok(*acq),
                PypiServiceWheel::HardFail(outcome) => return Err(*outcome),
                PypiServiceWheel::FallBack => {}
            }
        }
    }

    // Local build from the installed dist.
    let dist = match locate_installed_dist(site_packages, raw_name, version).await {
        Ok(d) => d,
        Err((code, detail)) => return Err(refused(code, detail)),
    };
    let wheel_name = match wheel_file_name(&dist) {
        Ok(n) => n,
        Err((code, detail)) => return Err(refused(code, detail)),
    };
    let rel_wheel = format!("{uuid_dir_rel}/{wheel_name}");
    let dest = project_root.join(uuid_dir_rel).join(&wheel_name);
    let platform_locked = dist.wheel_tags.iter().any(|t| tag_is_platform_specific(t));
    let platform_tags_display = dist.wheel_tags.join(", ");
    let (result, artifact) = match build_patched_wheel(
        base,
        site_packages,
        &dist,
        record,
        sources,
        &dest,
        dry_run,
        force,
        warnings,
    )
    .await
    {
        Ok(pair) => pair,
        Err((code, detail)) => return Err(refused(code, detail)),
    };
    Ok(AcquiredWheel {
        wheel_name,
        rel_wheel,
        result,
        artifact,
        platform_locked,
        platform_tags_display,
    })
}

/// Outcome of attempting a pypi service download.
enum PypiServiceWheel {
    /// Boxed: the wheel facts are large relative to the other variants.
    Used(Box<AcquiredWheel>),
    /// Bubble this terminal outcome (a `service`-mode miss, or a write failure).
    HardFail(Box<VendorOutcome>),
    /// Fall back to the local build.
    FallBack,
}

/// Download + verify the prebuilt wheel for `record.uuid`, mapping each service
/// outcome onto the `auto` / `service` policy. Only `.whl` artifacts are usable
/// (pypi vendoring is wheel-based); an sdist (or any miss) is a fallback under
/// `auto` and a hard fail under `service`.
async fn try_pypi_service_wheel(
    base: &str,
    name: &str,
    uuid_dir_rel: &str,
    project_root: &Path,
    record: &PatchRecord,
    cfg: &VendorServiceConfig,
    warnings: &mut Vec<VendorWarning>,
) -> PypiServiceWheel {
    // A terminal `service`-mode refusal (boxed — the enum's other variants are
    // small). A nested fn so both `miss` and the write-failure sites can use it.
    fn hard_fail(code: &'static str, detail: String) -> PypiServiceWheel {
        PypiServiceWheel::HardFail(Box::new(refused(code, detail)))
    }
    // service-required → hard fail; `auto` → warn + fall back to the local build.
    let miss = |warnings: &mut Vec<VendorWarning>, code: &'static str, reason: String| {
        if cfg.source.requires_service() {
            hard_fail("vendor_prebuilt_required", reason)
        } else {
            warnings.push(VendorWarning::new(
                code,
                format!("{reason}; building locally instead"),
            ));
            PypiServiceWheel::FallBack
        }
    };

    match fetch_verified_archive(cfg, &record.uuid, name).await {
        ServiceArtifact::Ready(archive) => {
            let Some(wheel_name) = wheel_filename_from_url(&archive.source_url) else {
                return miss(
                    warnings,
                    "vendor_prebuilt_unavailable",
                    "the prebuilt artifact is not a .whl (pypi vendoring is wheel-based)"
                        .to_string(),
                );
            };
            let rel_wheel = format!("{uuid_dir_rel}/{wheel_name}");
            let dest = project_root.join(uuid_dir_rel).join(&wheel_name);
            if let Some(parent) = dest.parent() {
                if let Err(e) = tokio::fs::create_dir_all(parent).await {
                    return hard_fail(
                        "vendor_prebuilt_write_failed",
                        format!("cannot create {}: {e}", parent.display()),
                    );
                }
            }
            if let Err(e) = atomic_write_bytes(&dest, &archive.bytes).await {
                return hard_fail(
                    "vendor_prebuilt_write_failed",
                    format!("cannot write the vendored wheel: {e}"),
                );
            }
            let (platform_locked, platform_tags_display) =
                wheel_platform_from_filename(&wheel_name);
            warnings.push(VendorWarning::new(
                "vendor_prebuilt_downloaded",
                format!(
                    "vendored the wheel for {base} from the patch service ({})",
                    archive.source_url
                ),
            ));
            PypiServiceWheel::Used(Box::new(AcquiredWheel {
                rel_wheel,
                result: already_patched_result(base, &dest, &record.files),
                artifact: Some(WheelArtifact {
                    file_name: wheel_name.clone(),
                    sha256_hex: hex::encode(Sha256::digest(&archive.bytes)),
                    size: archive.bytes.len() as u64,
                }),
                wheel_name,
                platform_locked,
                platform_tags_display,
            }))
        }
        ServiceArtifact::IntegrityMismatch(reason) => miss(
            warnings,
            "vendor_prebuilt_integrity_mismatch",
            format!("prebuilt wheel failed integrity ({reason})"),
        ),
        ServiceArtifact::Pending => miss(
            warnings,
            "vendor_prebuilt_pending",
            "prebuilt wheel is still building".to_string(),
        ),
        // Quiet under `auto` (the common "not built / free-only" case).
        ServiceArtifact::Unavailable(reason) => {
            if cfg.source.requires_service() {
                hard_fail(
                    "vendor_prebuilt_required",
                    format!("prebuilt wheel unavailable: {reason}"),
                )
            } else {
                PypiServiceWheel::FallBack
            }
        }
        ServiceArtifact::Failed(reason) => miss(
            warnings,
            "vendor_prebuilt_unavailable",
            format!("patch service request failed ({reason})"),
        ),
    }
}

/// The last path segment of a serve URL, when it names a `.whl`.
fn wheel_filename_from_url(url: &str) -> Option<String> {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let name = path.rsplit('/').next().unwrap_or("");
    name.ends_with(".whl").then(|| name.to_string())
}

/// Derive `(platform_locked, display)` from a wheel filename's trailing tag
/// triple (`{name}-{ver}(-{build})?-{py}-{abi}-{plat}.whl`). Advisory only —
/// the local-build path reads the same from the dist's WHEEL metadata.
fn wheel_platform_from_filename(wheel_name: &str) -> (bool, String) {
    let stem = wheel_name.strip_suffix(".whl").unwrap_or(wheel_name);
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() >= 3 {
        let triple = parts[parts.len() - 3..].join("-");
        (tag_is_platform_specific(&triple), triple)
    } else {
        // Unparseable → cannot prove portability.
        (true, stem.to_string())
    }
}

/// Platform-specific iff the tag triple binds an ABI or platform — `cp311-
/// none-any` is merely version-bound, `*-cp311-*` / `*-manylinux*` lock the
/// artifact to this machine's platform.
fn tag_is_platform_specific(tag: &str) -> bool {
    let parts: Vec<&str> = tag.split('-').collect();
    match parts.as_slice() {
        [_py, abi, plat] => *abi != "none" || *plat != "any",
        // Malformed tags can't prove portability — claim platform-locked.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;
    use crate::manifest::schema::PatchFileInfo;
    use crate::patch::vendor::state::VENDOR_MARKER_FILE;
    use std::collections::HashMap;
    use std::path::PathBuf;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const ORIG: &[u8] = b"class Six:\n    pass\n";
    const PATCHED: &[u8] = b"class Six:\n    pass\n# SOCKET-PATCH-MARKER\n";

    async fn touch(root: &Path, name: &str, content: &str) {
        tokio::fs::write(root.join(name), content).await.unwrap();
    }

    /// One assert per row of the v2 routing table (locks > lock-less markers
    /// with requirements fallthrough > requirements > pyproject > nothing).
    #[tokio::test]
    async fn flavor_routing_table_v2_precedence() {
        let flavor = |tmp: &Path| {
            let tmp = tmp.to_path_buf();
            async move { detect_pypi_flavor(&tmp).await.map(|(f, _)| f) }
        };

        // 1. uv.lock wins outright (even over requirements + other markers).
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "uv.lock", "version = 1\n").await;
        touch(tmp.path(), "requirements.txt", "six==1.16.0\n").await;
        assert_eq!(flavor(tmp.path()).await.unwrap(), PypiFlavor::UvProject);

        // 2-4. Tool locks route to their flavors.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "poetry.lock", "").await;
        assert_eq!(flavor(tmp.path()).await.unwrap(), PypiFlavor::Poetry);

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "pdm.lock", "").await;
        assert_eq!(flavor(tmp.path()).await.unwrap(), PypiFlavor::Pdm);

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "Pipfile.lock", "{}").await;
        assert_eq!(flavor(tmp.path()).await.unwrap(), PypiFlavor::Pipenv);

        // Lock precedence among coexisting locks + the LOUD warning.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "poetry.lock", "").await;
        touch(tmp.path(), "Pipfile.lock", "{}").await;
        let (f, warnings) = detect_pypi_flavor(tmp.path()).await.unwrap();
        assert_eq!(f, PypiFlavor::Poetry);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "pypi_multiple_lockfiles");
        assert!(
            warnings[0].detail.contains("Pipfile.lock"),
            "{}",
            warnings[0].detail
        );

        // 5. Lock-less tool markers refuse with the per-tool pointer...
        let tmp = tempfile::tempdir().unwrap();
        touch(
            tmp.path(),
            "pyproject.toml",
            "[project]\nname = \"x\"\n\n[tool.uv]\ndev = true\n",
        )
        .await;
        let err = detect_pypi_flavor(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_no_lockfile");
        assert!(err.1.contains("uv lock"));
        assert!(err.1.contains("socket-patch setup"));

        let tmp = tempfile::tempdir().unwrap();
        touch(
            tmp.path(),
            "pyproject.toml",
            "[tool.poetry]\nname = \"x\"\n",
        )
        .await;
        let err = detect_pypi_flavor(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_poetry_no_lockfile");
        assert!(err.1.contains("poetry lock"));

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "pyproject.toml", "[tool.pdm]\n").await;
        assert_eq!(
            detect_pypi_flavor(tmp.path()).await.unwrap_err().0,
            "pypi_pdm_no_lockfile"
        );

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "Pipfile", "").await;
        assert_eq!(
            detect_pypi_flavor(tmp.path()).await.unwrap_err().0,
            "pypi_pipenv_no_lockfile"
        );

        // ...but every lock-less marker falls through to requirements.txt when
        // one exists (the marker alone must not block the pip wiring) — this
        // expands v1, where a bare Pipfile + requirements.txt refused.
        for marker in [
            ("pyproject.toml", "[tool.uv]\n"),
            ("pyproject.toml", "[tool.poetry]\n"),
            ("pyproject.toml", "[tool.pdm]\n"),
            ("Pipfile", ""),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            touch(tmp.path(), marker.0, marker.1).await;
            touch(tmp.path(), "requirements.txt", "six==1.16.0\n").await;
            assert_eq!(
                flavor(tmp.path()).await.unwrap(),
                PypiFlavor::Requirements,
                "marker {marker:?} must fall through to requirements"
            );
        }

        // 6. requirements.txt at the root.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "requirements.txt", "six==1.16.0\n").await;
        assert_eq!(flavor(tmp.path()).await.unwrap(), PypiFlavor::Requirements);

        // 7. a lone pyproject.
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "pyproject.toml", "[project]\nname = \"x\"\n").await;
        assert_eq!(
            detect_pypi_flavor(tmp.path()).await.unwrap_err().0,
            "pypi_pyproject_only"
        );

        // 8. nothing at all.
        let tmp = tempfile::tempdir().unwrap();
        let err = detect_pypi_flavor(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_no_requirements");
        assert!(err.1.contains("socket-patch setup"));
    }

    #[test]
    fn table_probe_is_header_anchored() {
        assert!(has_table("[tool.uv]\n", "tool.uv"));
        assert!(has_table("[tool.uv.sources]\n", "tool.uv"));
        assert!(has_table("[ tool.uv ] # padded\n", "tool.uv"));
        assert!(!has_table("# [tool.uv]\nx = \"[tool.uv]\"\n", "tool.uv"));
        assert!(!has_table("[tool.uvloop]\n", "tool.uv"));
    }

    struct E2eFixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        site_packages: PathBuf,
        blobs: PathBuf,
        record: PatchRecord,
    }

    /// A requirements-flavor project: requirements.txt at the root, a
    /// six-like install in a venv-ish site-packages, and a blob store.
    async fn e2e_fixture() -> E2eFixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        touch(&root, "requirements.txt", "six==1.16.0\n").await;
        let sp = root.join(".venv/lib/python3.12/site-packages");
        let di = sp.join("six-1.16.0.dist-info");
        tokio::fs::create_dir_all(&di).await.unwrap();
        tokio::fs::write(sp.join("six.py"), ORIG).await.unwrap();
        tokio::fs::write(
            di.join("METADATA"),
            "Metadata-Version: 2.1\nName: six\nVersion: 1.16.0\n\nbody\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            di.join("WHEEL"),
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-none-any\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            di.join("RECORD"),
            "six.py,sha256=AAAA,20\nsix-1.16.0.dist-info/METADATA,,\nsix-1.16.0.dist-info/WHEEL,,\nsix-1.16.0.dist-info/RECORD,,\n",
        )
        .await
        .unwrap();
        let blobs = root.join("blob-store");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        tokio::fs::write(blobs.join(compute_git_sha256_from_bytes(PATCHED)), PATCHED)
            .await
            .unwrap();
        let mut files = HashMap::new();
        files.insert(
            "six.py".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(ORIG),
                after_hash: compute_git_sha256_from_bytes(PATCHED),
            },
        );
        let record = PatchRecord {
            uuid: UUID.to_string(),
            exported_at: String::new(),
            files,
            vulnerabilities: HashMap::new(),
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        E2eFixture {
            _tmp: tmp,
            root,
            site_packages: sp,
            blobs,
            record,
        }
    }

    #[tokio::test]
    async fn end_to_end_requirements_vendor_and_revert() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_pypi(
            // Qualified variant purl: the base must be derived internally.
            "pkg:pypi/six@1.16.0?artifact_id=abc123",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry must be present on success");

        // Entry shape.
        assert_eq!(entry.ecosystem, "pypi");
        assert_eq!(entry.base_purl, "pkg:pypi/six@1.16.0");
        assert_eq!(entry.uuid, UUID);
        assert_eq!(entry.flavor.as_deref(), Some("requirements"));
        assert!(entry.uv.is_none());
        let wheel_rel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        assert_eq!(entry.artifact.path, wheel_rel);
        // py2.py3-none-any is portable — no platform lock, no warning.
        assert_eq!(entry.artifact.platform_locked, None);
        assert!(warnings.iter().all(|w| w.code != "vendor_platform_locked"));

        // The wheel exists at the uuid path with the recorded hash + size.
        let wheel_bytes = tokio::fs::read(fx.root.join(&wheel_rel)).await.unwrap();
        assert_eq!(entry.artifact.size, Some(wheel_bytes.len() as u64));
        assert_eq!(
            entry.artifact.sha256,
            hex::encode(sha2::Sha256::digest(&wheel_bytes))
        );

        // The requirements line was rewritten with that exact hash.
        let req = tokio::fs::read_to_string(fx.root.join("requirements.txt"))
            .await
            .unwrap();
        assert_eq!(
            req,
            format!(
                "./{wheel_rel} --hash=sha256:{}  # socket-patch vendor: six==1.16.0\n",
                entry.artifact.sha256
            )
        );
        assert_eq!(entry.wiring.len(), 1);
        assert_eq!(entry.wiring[0].kind, "requirements_line");

        // The marker breadcrumb sits next to the wheel.
        let marker_text = tokio::fs::read_to_string(
            fx.root
                .join(format!(".socket/vendor/pypi/{UUID}"))
                .join(VENDOR_MARKER_FILE),
        )
        .await
        .unwrap();
        assert!(marker_text.contains("pkg:pypi/six@1.16.0"));
        assert!(marker_text.contains(UUID));

        // The installed site-packages tree was never touched.
        assert_eq!(
            tokio::fs::read(fx.site_packages.join("six.py"))
                .await
                .unwrap(),
            ORIG
        );

        // Revert: requirements restored, artifact dir removed.
        let reverted = revert_pypi(&entry, &fx.root, false).await;
        assert!(reverted.success, "{:?}", reverted.error);
        assert!(reverted.warnings.is_empty(), "{:?}", reverted.warnings);
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
        assert!(!fx.root.join(format!(".socket/vendor/pypi/{UUID}")).exists());
    }

    /// uv flavor, wired pair with a deleted committed wheel: the wheel is
    /// rebuilt at the recorded path, pyproject + lock stay byte-identical,
    /// no fresh ledger entry. An INTACT wheel stays the classic in-sync skip.
    #[tokio::test]
    async fn uv_wired_missing_wheel_rebuilds_artifact_only() {
        let fx = e2e_fixture().await;
        // Swap the requirements flavor for a uv project.
        tokio::fs::remove_file(fx.root.join("requirements.txt"))
            .await
            .unwrap();
        touch(
            &fx.root,
            "pyproject.toml",
            r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["six==1.16.0"]
"#,
        )
        .await;
        touch(
            &fx.root,
            "uv.lock",
            r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "six" },
]

[package.metadata]
requires-dist = [{ name = "six", specifier = "==1.16.0" }]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926", size = 34041, upload-time = "2021-05-05T14:18:18.379Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#,
        )
        .await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let vendor_one = |dry_run: bool| {
            vendor_pypi(
                "pkg:pypi/six@1.16.0",
                &fx.site_packages,
                &fx.root,
                &fx.record,
                &sources,
                "2026-06-09T00:00:00Z",
                dry_run,
                false,
                None,
            )
        };

        let VendorOutcome::Done { result, entry, .. } = vendor_one(false).await else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let pyproject1 = tokio::fs::read(fx.root.join("pyproject.toml"))
            .await
            .unwrap();
        let lock1 = tokio::fs::read(fx.root.join("uv.lock")).await.unwrap();
        let uuid_dir = fx.root.join(format!(".socket/vendor/pypi/{UUID}"));
        let wheel = uuid_dir.join("six-1.16.0-py2.py3-none-any.whl");
        assert!(wheel.is_file());

        // Intact wheel: in-sync skip (no rebuild, no entry).
        let VendorOutcome::Done {
            result: r2,
            entry: e2,
            warnings: w2,
        } = vendor_one(false).await
        else {
            panic!("re-run must be Done");
        };
        assert!(r2.success);
        assert!(e2.is_none(), "in-sync re-run records nothing");
        assert!(
            !w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "intact wheel must not claim a rebuild: {w2:?}"
        );

        // Deleted wheel: artifact-only rebuild.
        tokio::fs::remove_dir_all(&uuid_dir).await.unwrap();
        let VendorOutcome::Done {
            result: r3,
            entry: e3,
            warnings: w3,
        } = vendor_one(false).await
        else {
            panic!("rebuild run must be Done");
        };
        assert!(r3.success, "{:?}", r3.error);
        assert!(e3.is_none(), "artifact-only rebuild records no entry");
        assert!(
            w3.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {w3:?}"
        );
        assert!(wheel.is_file(), "wheel rebuilt at the recorded path");
        assert_eq!(
            tokio::fs::read(fx.root.join("pyproject.toml"))
                .await
                .unwrap(),
            pyproject1,
            "pyproject untouched by the rebuild"
        );
        assert_eq!(
            tokio::fs::read(fx.root.join("uv.lock")).await.unwrap(),
            lock1,
            "uv.lock untouched by the rebuild"
        );
    }

    #[tokio::test]
    async fn uuid_traversal_is_refused_before_any_write() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let mut record = fx.record.clone();
        record.uuid = "../../../../tmp/evil".to_string();
        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "vendor_unsafe_uuid");
        assert!(!fx.root.join(".socket").exists(), "nothing may be written");
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            true,
            false,
            None,
        )
        .await;
        let VendorOutcome::Done { result, entry, .. } = outcome else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_none(), "dry run yields no entry to persist");
        assert!(!fx.root.join(".socket").exists());
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
    }

    #[tokio::test]
    async fn requirements_refusal_happens_before_artifact_build() {
        let fx = e2e_fixture().await;
        touch(&fx.root, "requirements.txt", "six>=1.0\n").await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "pypi_requirement_not_pinned");
        assert!(
            !fx.root.join(".socket").exists(),
            "pre-flight refusal must precede the wheel build"
        );
    }

    #[tokio::test]
    async fn platform_specific_tags_set_platform_locked_and_warn() {
        let fx = e2e_fixture().await;
        // Make the installed dist a cp312/manylinux wheel.
        tokio::fs::write(
            fx.site_packages.join("six-1.16.0.dist-info/WHEEL"),
            "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp312-cp312-manylinux_2_17_x86_64\n",
        )
        .await
        .unwrap();
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(entry.artifact.platform_locked, Some(true));
        assert!(entry
            .artifact
            .path
            .ends_with("six-1.16.0-cp312-cp312-manylinux_2_17_x86_64.whl"));
        assert!(
            warnings.iter().any(|w| w.code == "vendor_platform_locked"),
            "{warnings:?}"
        );
    }

    #[test]
    fn platform_specific_tag_detection() {
        assert!(!tag_is_platform_specific("py3-none-any"));
        assert!(!tag_is_platform_specific("cp311-none-any"));
        assert!(tag_is_platform_specific(
            "cp311-cp311-manylinux_2_17_x86_64"
        ));
        assert!(tag_is_platform_specific("py3-none-macosx_11_0_arm64"));
        assert!(tag_is_platform_specific("py3-abi3-any"));
        assert!(tag_is_platform_specific("garbage"));
    }

    #[tokio::test]
    async fn revert_unknown_flavor_fails_closed() {
        let fx = e2e_fixture().await;
        let entry = VendorEntry {
            ecosystem: "pypi".into(),
            base_purl: "pkg:pypi/six@1.16.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: format!(".socket/vendor/pypi/{UUID}/x.whl"),
                sha256: String::new(),
                size: None,
                platform_locked: None,
            },
            wiring: vec![],
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("mystery".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        };
        let outcome = revert_pypi(&entry, &fx.root, false).await;
        assert!(!outcome.success);
        assert!(outcome.error.unwrap().contains("mystery"));
    }

    // ─────────────── service-download path (Tier A: pypi) ───────────────
    //
    // The wheel is opaque bytes to the vendor wiring (it embeds the filename +
    // a recomputed sha256), so these serve arbitrary bytes under a `.whl`
    // filename with a matching sha512. Both the service path AND the
    // local-build fallback are exercised.

    use crate::api::client::{ApiClient, ApiClientOptions};
    use crate::patch::vendor::{VendorServiceConfig, VendorSource};

    const WHEEL_NAME: &str = "six-1.16.0-py2.py3-none-any.whl";

    fn sri_sha512(bytes: &[u8]) -> String {
        use base64::Engine as _;
        format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(bytes))
        )
    }

    fn pypi_service_cfg(
        server_uri: &str,
        source: VendorSource,
        offline: bool,
    ) -> VendorServiceConfig {
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
            offline,
        }
    }

    /// Mount the two-step service for an artifact served at `filename`
    /// (`.whl` → usable, `.tar.gz` → sdist fallback) with the given sha512.
    async fn mount_pypi_granted(
        server: &wiremock::MockServer,
        filename: &str,
        sha512: &str,
        bytes: &[u8],
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let serve_path = format!("/patch/pypi/six/1.16.0/tok/uuid/{filename}");
        let serve_url = format!("{}{serve_path}", server.uri());
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: {
                    "status": "granted",
                    "url": serve_url,
                    "purl": "pkg:pypi/six@1.16.0",
                    "artifacts": [{ "kind": "tarball", "url": serve_url,
                                    "integrity": { "sha512": sha512 } }]
                }}
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(serve_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
            .mount(server)
            .await;
    }

    /// Service success (requirements flavor): the prebuilt wheel is written, the
    /// requirements line is wired to the RECOMPUTED sha256, and a
    /// `vendor_prebuilt_downloaded` advisory is emitted.
    #[tokio::test]
    async fn service_success_requirements_writes_wheel_and_wires_sha256() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"prebuilt wheel bytes from the service";
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &sri, bytes).await;

        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&pypi_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");

        let wheel_rel = format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}");
        assert_eq!(entry.artifact.path, wheel_rel);
        let on_disk = tokio::fs::read(fx.root.join(&wheel_rel)).await.unwrap();
        assert_eq!(on_disk, bytes, "service wheel written byte-for-byte");
        let expected_sha256 = hex::encode(sha2::Sha256::digest(bytes));
        assert_eq!(entry.artifact.sha256, expected_sha256);
        let req = tokio::fs::read_to_string(fx.root.join("requirements.txt"))
            .await
            .unwrap();
        assert!(
            req.contains(&format!("--hash=sha256:{expected_sha256}")),
            "requirements line wired to the recomputed sha256: {req}"
        );
        assert!(warnings
            .iter()
            .any(|w| w.code == "vendor_prebuilt_downloaded"));
        // site-packages untouched (the service path never needs the install).
        assert_eq!(
            tokio::fs::read(fx.site_packages.join("six.py"))
                .await
                .unwrap(),
            ORIG
        );
    }

    /// An sdist service artifact (not a `.whl`) falls back to the local wheel
    /// build under `auto` — pypi vendoring is wheel-based.
    #[tokio::test]
    async fn service_sdist_artifact_auto_falls_back_to_build() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"sdist tarball bytes";
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, "six-1.16.0.tar.gz", &sri, bytes).await;

        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let VendorOutcome::Done { result, entry, .. } = outcome else {
            panic!("expected Done (local build), got {outcome:?}");
        };
        assert!(
            result.success,
            "auto must fall back to the local wheel build: {:?}",
            result.error
        );
        let entry = entry.expect("entry on success");
        // The locally-built wheel landed (not the sdist bytes).
        let wheel_rel = format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}");
        assert_eq!(entry.artifact.path, wheel_rel);
        assert!(fx.root.join(&wheel_rel).exists());
    }

    /// `service` mode + an sdist (non-wheel) artifact hard-fails.
    #[tokio::test]
    async fn service_sdist_artifact_service_mode_hard_fails() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"sdist tarball bytes";
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, "six-1.16.0.tar.gz", &sri, bytes).await;

        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&pypi_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        assert!(
            matches!(outcome, VendorOutcome::Refused { .. }),
            "service mode must refuse a non-wheel artifact, got {outcome:?}"
        );
    }

    /// `service` mode + an integrity mismatch hard-fails (nothing written).
    #[tokio::test]
    async fn service_integrity_mismatch_service_mode_hard_fails() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"the real wheel bytes";
        let wrong = sri_sha512(b"different bytes entirely");
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &wrong, bytes).await;

        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&pypi_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        assert!(
            matches!(outcome, VendorOutcome::Refused { .. }),
            "got {outcome:?}"
        );
        assert!(
            !fx.root
                .join(format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}"))
                .exists(),
            "nothing written on a hard fail"
        );
    }

    /// `--offline` + `--vendor-source=service` refuses, never hitting the network.
    #[tokio::test]
    async fn offline_service_mode_refuses() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            // No server: offline must short-circuit before any request.
            Some(&pypi_service_cfg(
                "http://127.0.0.1:1",
                VendorSource::Service,
                true,
            )),
        )
        .await;
        match outcome {
            VendorOutcome::Refused { code, .. } => {
                assert_eq!(code, "vendor_service_offline_conflict")
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }
}
