//! pypi vendor backend: flavor routing + orchestration.
//!
//! Order of operations is the safety story: every refusal-capable check
//! (flavor route, uv project guards, requirements pre-flight, dist lookup,
//! tag compression) runs BEFORE the wheel artifact is built, and the
//! lockfile/manifest wiring is written LAST — so a refusal leaves the tree
//! byte-untouched and an artifact failure never leaves half-wired lockfiles.

use std::path::Path;

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources, VerifyResult, VerifyStatus};
use crate::utils::purl::{parse_pypi_purl, strip_purl_qualifiers};

use super::path::vendor_uuid_dir_rel;
use super::pypi_pdm::{PdmProject, PdmTarget};
use super::pypi_pipenv::{PipenvProject, PipenvTarget};
use super::pypi_poetry::{PoetryProject, PoetryTarget};
use super::pypi_requirements::{preflight_requirements, revert_requirements, wire_requirements};
use super::pypi_uv::{
    check_target_guards, classify_dependency, load_uv_project, revert_uv, wire_uv, UvDepClass,
    UvProject,
};
use super::pypi_wheel::{build_patched_wheel, locate_installed_dist, wheel_file_name};
use super::state::{
    write_marker, PdmMeta, PipenvMeta, PoetryMeta, UvMeta, VendorArtifact, VendorEntry,
    VendorMarker,
};
use super::{RevertOutcome, VendorOutcome, VendorWarning};

/// Which wiring backend serves this project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PypiFlavor {
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
pub async fn detect_pypi_flavor(
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
    let locks: Vec<(&str, bool)> = vec![
        ("uv.lock", has_uv_lock),
        ("poetry.lock", has_poetry_lock),
        ("pdm.lock", has_pdm_lock),
        ("Pipfile.lock", has_pipfile_lock),
    ];
    let present: Vec<&str> = locks.iter().filter(|(_, p)| *p).map(|(n, _)| *n).collect();
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

/// `[prefix]` / `[prefix.*]` table-header probe. Mirrors the private
/// `has_table` in `pth_hook/detect.rs` (header-anchored so a substring in a
/// value or comment cannot misroute the flavor).
fn has_table(content: &str, prefix: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim();
        let Some(rest) = line.strip_prefix('[') else {
            return false;
        };
        let rest = rest.trim_start_matches('[');
        let Some(end) = rest.find(']') else {
            return false;
        };
        let header = rest[..end].trim();
        header == prefix || header.starts_with(&format!("{prefix}."))
    })
}

/// Per-flavor pre-flight result carried into the wiring step (the loaded
/// project is reused so the lock is parsed once).
enum WiringPlan {
    Uv(Box<UvProject>, UvDepClass),
    Requirements,
    Poetry(Box<PoetryProject>),
    Pdm(Box<PdmProject>),
    Pipenv(Box<PipenvProject>),
}

/// Which `VendorEntry` meta slot a flavor's wiring produced.
enum MetaSlot {
    Uv(Option<UvMeta>),
    Poetry(PoetryMeta),
    Pdm(PdmMeta),
    Pipenv(PipenvMeta),
    None,
}

/// Build the synthesized AlreadyPatched outcome for an in-sync re-run: the
/// artifact + lockfile already point at THIS patch uuid, so nothing is built
/// or recorded (the first run's ledger entry holds the only copy of the
/// originals). Mirrors the npm flavors' in-sync hot path.
fn in_sync_outcome(
    base_purl: &str,
    record: &PatchRecord,
    warnings: Vec<VendorWarning>,
) -> VendorOutcome {
    let files_verified = record
        .files
        .keys()
        .map(|f| VerifyResult {
            file: f.clone(),
            status: VerifyStatus::AlreadyPatched,
            message: None,
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        })
        .collect();
    VendorOutcome::Done {
        result: ApplyResult {
            package_key: base_purl.to_string(),
            package_path: String::new(),
            success: true,
            files_verified,
            files_patched: Vec::new(),
            applied_via: std::collections::HashMap::new(),
            error: None,
            sidecar: None,
        },
        entry: None,
        warnings,
    }
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
) -> VendorOutcome {
    // The purl may carry `?artifact_id=` variant qualifiers; everything here
    // keys off the qualifier-free base.
    let base = strip_purl_qualifiers(purl);
    let Some((raw_name, version)) = parse_pypi_purl(base) else {
        return VendorOutcome::Refused {
            code: "pypi_invalid_purl",
            detail: format!("{purl} is not a pkg:pypi PURL with a version"),
        };
    };
    let canon_name = canonicalize_pypi_name(raw_name);

    // SECURITY: the uuid comes from a committed, tamper-able manifest and
    // keys the on-disk artifact directory vendor creates (and --revert
    // deletes). Anything but the canonical UUID grammar is rejected
    // fail-closed before any disk access.
    let Some(uuid_dir_rel) = vendor_uuid_dir_rel("pypi", &record.uuid) else {
        return VendorOutcome::Refused {
            code: "vendor_unsafe_uuid",
            detail: format!(
                "patch uuid {:?} is not a canonical lowercase uuid; refusing to derive a \
                 vendor path from it",
                record.uuid
            ),
        };
    };

    let (flavor, flavor_warnings) = match detect_pypi_flavor(project_root).await {
        Ok(f) => f,
        Err((code, detail)) => return VendorOutcome::Refused { code, detail },
    };

    // Pre-flight the wiring guards BEFORE building anything, so refusals
    // leave the tree byte-untouched.
    let mut warnings: Vec<VendorWarning> = flavor_warnings;
    let plan = match flavor {
        PypiFlavor::UvProject => {
            let project = match load_uv_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return VendorOutcome::Refused { code, detail },
            };
            if let Err((code, detail)) = check_target_guards(&project, &canon_name) {
                return VendorOutcome::Refused { code, detail };
            }
            warnings.extend(project.warnings.iter().cloned());
            let class = classify_dependency(&project, &canon_name);
            WiringPlan::Uv(Box::new(project), class)
        }
        PypiFlavor::Requirements => {
            if let Err((code, detail)) =
                preflight_requirements(project_root, &canon_name, version).await
            {
                return VendorOutcome::Refused { code, detail };
            }
            WiringPlan::Requirements
        }
        PypiFlavor::Poetry => {
            let project = match super::pypi_poetry::load_poetry_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return VendorOutcome::Refused { code, detail },
            };
            match super::pypi_poetry::check_target_guards(
                &project,
                &canon_name,
                version,
                &record.uuid,
            ) {
                Ok(PoetryTarget::Fresh) => {}
                Ok(PoetryTarget::InSync) => return in_sync_outcome(base, record, warnings),
                Err((code, detail)) => return VendorOutcome::Refused { code, detail },
            }
            warnings.extend(project.warnings.iter().cloned());
            WiringPlan::Poetry(Box::new(project))
        }
        PypiFlavor::Pdm => {
            let project = match super::pypi_pdm::load_pdm_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return VendorOutcome::Refused { code, detail },
            };
            match super::pypi_pdm::check_target_guards(&project, &canon_name, version, &record.uuid)
            {
                Ok(PdmTarget::Fresh) => {}
                Ok(PdmTarget::InSync) => return in_sync_outcome(base, record, warnings),
                Err((code, detail)) => return VendorOutcome::Refused { code, detail },
            }
            warnings.extend(project.warnings.iter().cloned());
            WiringPlan::Pdm(Box::new(project))
        }
        PypiFlavor::Pipenv => {
            let project = match super::pypi_pipenv::load_pipenv_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return VendorOutcome::Refused { code, detail },
            };
            match super::pypi_pipenv::check_target_guards(&project, &canon_name, &record.uuid) {
                Ok(PipenvTarget::Fresh) => {}
                Ok(PipenvTarget::InSync) => return in_sync_outcome(base, record, warnings),
                Err((code, detail)) => return VendorOutcome::Refused { code, detail },
            }
            warnings.extend(project.warnings.iter().cloned());
            WiringPlan::Pipenv(Box::new(project))
        }
    };

    let dist = match locate_installed_dist(site_packages, raw_name, version).await {
        Ok(d) => d,
        Err((code, detail)) => return VendorOutcome::Refused { code, detail },
    };
    let wheel_name = match wheel_file_name(&dist) {
        Ok(n) => n,
        Err((code, detail)) => return VendorOutcome::Refused { code, detail },
    };
    let rel_wheel = format!("{uuid_dir_rel}/{wheel_name}");
    let dest = project_root.join(&uuid_dir_rel).join(&wheel_name);

    let built = build_patched_wheel(
        base,
        site_packages,
        &dist,
        record,
        sources,
        &dest,
        dry_run,
        force,
    )
    .await;
    let (result, artifact) = match built {
        Ok(pair) => pair,
        Err((code, detail)) => return VendorOutcome::Refused { code, detail },
    };
    if dry_run || !result.success {
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    }
    let Some(artifact) = artifact else {
        // Defensive: success without an artifact would be a bug upstream.
        let mut result = result;
        result.success = false;
        result.error = Some("wheel build reported success without an artifact".to_string());
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    };

    // A compiled-extension wheel (cp311/manylinux tags) only installs on this
    // platform, where the registry offered wheels for many — surface it.
    let platform_locked = dist.wheel_tags.iter().any(|t| tag_is_platform_specific(t));
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
                 ({}); {per_flavor}",
                dist.wheel_tags.join(", ")
            ),
        ));
    }

    // Marker: artifact-side breadcrumb in the uuid dir (informational only —
    // sweep/verify key off state.json + the path uuid). Written before the
    // wiring so lockfile edits stay the last mutation.
    let mut vulns: Vec<String> = record.vulnerabilities.keys().cloned().collect();
    vulns.sort();
    let marker = VendorMarker {
        schema_version: 1,
        purl: base.to_string(),
        patch_uuid: record.uuid.clone(),
        ecosystem: "pypi".to_string(),
        vulnerabilities: vulns,
        vendored_at: vendored_at.to_string(),
    };
    if let Err(e) = write_marker(&project_root.join(&uuid_dir_rel), &marker).await {
        let _ = tokio::fs::remove_dir_all(project_root.join(&uuid_dir_rel)).await;
        let mut result = result;
        result.success = false;
        result.error = Some(format!("cannot write vendor marker: {e}"));
        return VendorOutcome::Done {
            result,
            entry: None,
            warnings,
        };
    }

    // Wiring LAST. On failure the wheel artifact is swept back out so a
    // failed vendor leaves no committed residue.
    let wired: Result<(Vec<_>, MetaSlot), (&'static str, String)> = match plan {
        WiringPlan::Uv(project, class) => wire_uv(
            &project,
            project_root,
            &canon_name,
            version,
            &rel_wheel,
            &wheel_name,
            &artifact.sha256_hex,
            class,
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
    };
    let (wiring, meta) = match wired {
        Ok(pair) => pair,
        Err((code, detail)) => {
            let _ = tokio::fs::remove_dir_all(project_root.join(&uuid_dir_rel)).await;
            let mut result = result;
            result.success = false;
            result.error = Some(format!("{code}: {detail}"));
            return VendorOutcome::Done {
                result,
                entry: None,
                warnings,
            };
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
    VendorOutcome::Done {
        result,
        entry: Some(entry),
        warnings,
    }
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
    use sha2::Digest as _;
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
}
