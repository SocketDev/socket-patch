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
use crate::utils::fs::atomic_write_bytes;
use crate::utils::purl::{parse_pypi_purl, strip_purl_qualifiers};
use crate::utils::toml_edit_ext::has_table;

use super::common::{already_patched_result, done, refused, service_offline_conflict};
use super::path::vendor_uuid_dir_rel;
use super::pypi_pdm::{PdmProject, PdmTarget};
use super::pypi_pipenv::{PipenvProject, PipenvTarget};
use super::pypi_poetry::{PoetryProject, PoetryTarget};
use super::pypi_requirements::{
    preflight_requirements, revert_requirements, wire_requirements, RequirementsTarget,
};
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
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

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

/// `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular files,
/// so a FIFO planted as `pyproject.toml` fails fast — read as "no pyproject",
/// falling through to the requirements routing — instead of wedging flavor
/// detection (and every lockless-project vendor run) forever in an `open(2)`
/// that waits for a writer.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

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

    let pyproject_text = read_regular_to_string(&project_root.join("pyproject.toml"))
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

/// The (wheel path, sha256) a WIRED splice-flavor lock (poetry/pdm) still
/// pins: the vendored `[[package]]` unit names the wheel under the uuid dir
/// (`url = "<path>"` / `path = "./<path>"`) and its `files` array carries
/// the one-line `{file = "<wheel>", hash = "sha256:<hex>"}` element vendor
/// wrote. Paths are returned bare (no `./` prefix), matching the ledger's
/// `artifact.path` spelling. `None` on any shape drift — the caller then
/// keeps the unguarded rebuild rather than guessing.
fn splice_lock_wired_pin(lock_text: &str, uuid_dir_rel: &str) -> Option<(String, String)> {
    let prefix = format!("{uuid_dir_rel}/");
    let path = lock_text.lines().find_map(|line| {
        let (_, rest) = line.split_once('"')?;
        let (quoted, _) = rest.split_once('"')?;
        let bare = quoted.strip_prefix("./").unwrap_or(quoted);
        (bare.starts_with(&prefix) && bare.ends_with(".whl")).then(|| bare.to_string())
    })?;
    let wheel_name = path.rsplit('/').next()?;
    let hash_needle = format!("file = \"{wheel_name}\", hash = \"sha256:");
    let at = lock_text.find(&hash_needle)?;
    let hex: String = lock_text[at + hash_needle.len()..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    (hex.len() == 64).then_some((path, hex))
}

/// The (wheel path, sha256) a WIRED Pipfile.lock still pins: the vendored
/// entry's `file` ref names the wheel under the uuid dir and its `hashes`
/// array holds the `sha256:` pin vendor wrote. Scans every category section
/// (`default`, `develop`, and V3 named categories). Paths are returned bare
/// (no `./` prefix), matching the ledger's `artifact.path` spelling.
fn pipenv_wired_pin(lock: &serde_json::Value, uuid_dir_rel: &str) -> Option<(String, String)> {
    let prefix = format!("{uuid_dir_rel}/");
    for (key, section) in lock.as_object()?.iter() {
        if key == "_meta" {
            continue;
        }
        let Some(map) = section.as_object() else {
            continue;
        };
        for entry in map.values() {
            let Some(file) = entry.get("file").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let bare = file.strip_prefix("./").unwrap_or(file);
            if !bare.starts_with(&prefix) || !bare.ends_with(".whl") {
                continue;
            }
            let Some(sha) = entry
                .get("hashes")
                .and_then(serde_json::Value::as_array)
                .and_then(|a| a.iter().find_map(|h| h.as_str()?.strip_prefix("sha256:")))
            else {
                continue;
            };
            if sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some((bare.to_string(), sha.to_string()));
            }
        }
    }
    None
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
    //
    // On an in-sync target the wired lockfiles themselves still carry the
    // first vendor's wheel path + sha256 (that is what the in-sync probes
    // matched on, and what the next hash-checked install verifies against).
    // Captured here, while each flavor's parse is still in scope, so the
    // rebuild pin guard below can fall back to it when the ledger has no
    // entry left (a state.json lost in a merge, clobbered, or never
    // committed — the exact window the state `repair` exists for).
    let mut wired_pin: Option<(String, String)> = None;
    let mut warnings: Vec<VendorWarning> = flavor_warnings;
    let plan = match flavor {
        PypiFlavor::UvProject => {
            let project = match load_uv_project(project_root).await {
                Ok(p) => p,
                Err((code, detail)) => return refused(code, detail),
            };
            match check_target_guards(&project, &canon_name, &record.uuid) {
                Ok(UvTarget::InSync) => {
                    wired_pin = super::pypi_uv::wired_pin(&project, &canon_name, &record.uuid);
                    WiringPlan::InSync
                }
                Ok(UvTarget::Fresh) => {
                    warnings.extend(project.warnings.iter().cloned());
                    WiringPlan::Uv(Box::new(project))
                }
                Err((code, detail)) => return refused(code, detail),
            }
        }
        PypiFlavor::Requirements => {
            match preflight_requirements(project_root, &canon_name, version, &record.uuid).await {
                Ok(RequirementsTarget::InSync { pin }) => {
                    wired_pin = pin;
                    WiringPlan::InSync
                }
                Ok(RequirementsTarget::Fresh) => WiringPlan::Requirements,
                Err((code, detail)) => return refused(code, detail),
            }
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
                Ok(PoetryTarget::InSync) => {
                    wired_pin = splice_lock_wired_pin(&project.lock_text, &uuid_dir_rel);
                    WiringPlan::InSync
                }
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
                Ok(PdmTarget::InSync) => {
                    wired_pin = splice_lock_wired_pin(&project.lock_text, &uuid_dir_rel);
                    WiringPlan::InSync
                }
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
                Ok(PipenvTarget::InSync) => {
                    wired_pin = pipenv_wired_pin(&project.lock, &uuid_dir_rel);
                    WiringPlan::InSync
                }
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

    // The in-sync probes key only on the patch uuid in the wired path, so
    // the lockfile still pins the FIRST vendor's exact wheel path + sha256.
    // An artifact-only rebuild is safe only when it reproduces those exact
    // bytes; the ledger entry recorded at wiring time carries that pin.
    // With no readable ledger entry (a state.json lost in a merge, corrupt,
    // or never committed) the guard must NOT silently drop away — the wired
    // lockfile itself still carries the authoritative pin the next
    // hash-checked install verifies against, so fall back to the pin the
    // flavor pre-flight read out of it. Only when the wired file yields no
    // pin either does the unguarded rebuild remain (the local build is
    // deterministic for locally-vendored projects).
    let expected_pin: Option<(String, String)> = if in_sync {
        match super::state::load_state(project_root).await {
            Ok(state) => state
                .entries
                .into_values()
                .find(|e| e.ecosystem == "pypi" && e.uuid == record.uuid)
                .map(|e| (e.artifact.path, e.artifact.sha256)),
            Err(_) => None,
        }
        .or(wired_pin)
    } else {
        None
    };

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
        expected_pin.as_ref(),
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
        // The wiring still pins the first vendor's wheel path + sha256; a
        // rebuilt artifact that does not reproduce them would break every
        // subsequent hash-checked install (`pip --require-hashes`,
        // `uv sync`, …) the moment vendor reports success. Sweep the
        // mismatched wheel back out and fail loudly instead.
        if let Some((pin_path, pin_sha)) = &expected_pin {
            if *pin_path != rel_wheel || *pin_sha != artifact.sha256_hex {
                let _ = tokio::fs::remove_dir_all(project_root.join(&uuid_dir_rel)).await;
                let mut result = result;
                result.success = false;
                result.error = Some(format!(
                    "the rebuilt wheel ({rel_wheel}, sha256 {}) does not match the wheel the \
                     lockfile still pins ({pin_path}, sha256 {pin_sha}); run `socket-patch \
                     vendor --revert` for {base} and re-vendor to re-wire the lockfile",
                    artifact.sha256_hex
                ));
                return done(result, None, warnings);
            }
        }
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
            file_inventory: None,
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
    revert_pypi_opts(entry, project_root, RevertOpts::new(dry_run)).await
}

/// [`revert_pypi`] with full [`RevertOpts`]: `keep_artifact` skips the
/// artifact deletion while the per-flavor wiring restore runs unchanged.
pub async fn revert_pypi_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
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
    // LOSSINESS GUARD (residual #131 — the RevertOutcome contract every
    // npm-family backend honors): when any wiring record was left alone
    // ("drifted; left untouched"), the lockfile may still resolve through
    // the uuid dir, and the ledger entry holds the only recorded pre-vendor
    // originals. Keep both (the caller keeps the entry when `kept_artifact`
    // is set) instead of deleting evidence out from under a lock the flavor
    // revert just refused to touch. The requirements flavor speaks its own
    // codes: `vendor_revert_residual_reference` is its post-revert proof
    // that a file STILL points into the uuid dir — an even more precise
    // keep signal than the drift code (its `vendor_revert_line_drifted`
    // alone is NOT gated: it also fires for a hand-restored line whose
    // reverted state is already satisfied, and gating on it would keep the
    // artifact forever against the LIVENESS CONTRACT).
    if outcome.drift_skipped()
        || outcome
            .warnings
            .iter()
            .any(|w| w.code == "vendor_revert_residual_reference")
    {
        // Display-only path: with a non-canonical uuid nothing below would
        // have been deleted anyway, but the drift-keep must still be
        // surfaced so the ledger entry survives.
        let uuid_dir_rel = vendor_uuid_dir_rel("pypi", &entry.uuid)
            .unwrap_or_else(|| format!(".socket/vendor/pypi/{:?}", entry.uuid));
        outcome.keep_artifact(&uuid_dir_rel);
        return outcome;
    }
    // `--preserve-state` (`keep_artifact`): the wiring restore above already
    // ran; the artifact dir stays behind (and the caller keeps the ledger
    // entry), so only the deletion is skipped.
    if keep_artifact {
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
    expected_pin: Option<&(String, String)>,
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
                uuid_dir_rel,
                project_root,
                record,
                cfg,
                expected_pin,
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
    uuid_dir_rel: &str,
    project_root: &Path,
    record: &PatchRecord,
    cfg: &VendorServiceConfig,
    expected_pin: Option<&(String, String)>,
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

    match fetch_verified_archive(cfg, &record.uuid).await {
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
            let sha256_hex = hex::encode(Sha256::digest(&archive.bytes));
            // In-sync rebuild: the lockfile still pins the first vendor's
            // wheel path + sha256, and a prebuilt wheel that differs would
            // break every subsequent hash-checked install the moment vendor
            // reports success. Checked BEFORE writing, so a mismatch leaves
            // no poisoned artifact behind (`auto` falls back to the
            // deterministic local build, which reproduces a local pin).
            if let Some((pin_path, pin_sha)) = expected_pin {
                if *pin_path != rel_wheel || *pin_sha != sha256_hex {
                    return miss(
                        warnings,
                        "vendor_prebuilt_pin_mismatch",
                        format!(
                            "the prebuilt wheel ({rel_wheel}, sha256 {sha256_hex}) does not \
                             match the wheel the lockfile still pins ({pin_path}, sha256 \
                             {pin_sha})"
                        ),
                    );
                }
            }
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
                    sha256_hex,
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
    use crate::vendor::state::VENDOR_MARKER_FILE;
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

    /// mkfifo(2) directly rather than shelling out to the `mkfifo` binary —
    /// same helper as the setup/pypi detect.rs FIFO tests: fork/exec flakes
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

    /// A FIFO planted as `pyproject.toml` must not wedge flavor routing: the
    /// lockfile probes ahead of the pyproject read are metadata-only (a FIFO
    /// stats fine), so a plain `read_to_string` open(2) waits for a writer
    /// that never comes, wedging every lockless-project `vendor` run
    /// indefinitely with no error and no timeout. Same class as the
    /// `open_regular_file` guards in the sibling vendor backends and the
    /// setup/pypi detect twin. The non-regular file must instead read as "no
    /// pyproject" and fall through to the requirements routing.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_pyproject_does_not_wedge_flavor_detection() {
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("pyproject.toml");
        mkfifo(&fifo);
        touch(tmp.path(), "requirements.txt", "six==1.16.0\n").await;

        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(routed) = tokio::time::timeout(deadline, detect_pypi_flavor(tmp.path())).await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("detect_pypi_flavor must complete promptly with a FIFO pyproject.toml");
        };
        assert_eq!(routed.unwrap().0, PypiFlavor::Requirements);
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

    /// Re-running vendor on an already-wired requirements project must be
    /// the same in-sync skip the lock flavors report — NOT a second
    /// `(transitive)` line append: the duplicate hands pip two competing
    /// requirements, and re-recording the entry would clobber the original
    /// pin's wiring record (the only copy of the pre-vendor line).
    #[tokio::test]
    async fn requirements_revendor_is_in_sync_skip() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let vendor_one = || {
            vendor_pypi(
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
        };
        let VendorOutcome::Done { result, entry, .. } = vendor_one().await else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some());
        let wired = tokio::fs::read_to_string(fx.root.join("requirements.txt"))
            .await
            .unwrap();

        // Intact wheel: in-sync skip — nothing recorded, file byte-identical.
        let VendorOutcome::Done {
            result: r2,
            entry: e2,
            warnings: w2,
        } = vendor_one().await
        else {
            panic!("re-run must be Done");
        };
        assert!(r2.success, "{:?}", r2.error);
        assert!(e2.is_none(), "in-sync re-run records nothing");
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            wired,
            "re-run must not touch requirements.txt"
        );
        assert!(
            !w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "intact wheel must not claim a rebuild: {w2:?}"
        );

        // Deleted wheel: artifact-only rebuild, wiring untouched.
        let uuid_dir = fx.root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::remove_dir_all(&uuid_dir).await.unwrap();
        let VendorOutcome::Done {
            result: r3,
            entry: e3,
            warnings: w3,
        } = vendor_one().await
        else {
            panic!("rebuild run must be Done");
        };
        assert!(r3.success, "{:?}", r3.error);
        assert!(e3.is_none(), "artifact-only rebuild records no entry");
        assert!(
            w3.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "rebuild is surfaced: {w3:?}"
        );
        assert!(uuid_dir.join("six-1.16.0-py2.py3-none-any.whl").is_file());
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            wired,
            "rebuild must not touch requirements.txt"
        );
    }

    /// A requirements file already wired to an EARLIER patch uuid for the
    /// same package refuses (mirrors uv/poetry): appending a second wheel
    /// line would leave pip two competing requirements, and the new entry
    /// would clobber the old one's ledger record, orphaning its line.
    #[tokio::test]
    async fn requirements_stale_uuid_vendor_line_refuses() {
        const UUID2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let vendor_with = |record: PatchRecord| {
            let sources = &sources;
            let fx = &fx;
            async move {
                vendor_pypi(
                    "pkg:pypi/six@1.16.0",
                    &fx.site_packages,
                    &fx.root,
                    &record,
                    sources,
                    "2026-06-09T00:00:00Z",
                    false,
                    false,
                    None,
                )
                .await
            }
        };
        let VendorOutcome::Done { result, .. } = vendor_with(fx.record.clone()).await else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let wired = tokio::fs::read_to_string(fx.root.join("requirements.txt"))
            .await
            .unwrap();

        // Same package, new patch generation (different uuid).
        let mut record2 = fx.record.clone();
        record2.uuid = UUID2.to_string();
        let outcome = vendor_with(record2).await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "pypi_requirements_already_vendored");
        assert!(detail.contains(UUID), "{detail}");
        // Pre-flight refusal: no second line, no new uuid dir.
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            wired
        );
        assert!(!fx
            .root
            .join(format!(".socket/vendor/pypi/{UUID2}"))
            .exists());
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
                file_inventory: None,
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
    use crate::vendor::{VendorServiceConfig, VendorSource};

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

    /// Write `entry` into the on-disk ledger the CLI would have persisted
    /// after a real vendor run (state.json keyed by base purl).
    async fn save_ledger_entry(root: &Path, entry: &VendorEntry) {
        use crate::vendor::state::{save_state, VendorState};
        let mut state = VendorState::new();
        state.entries.insert(entry.base_purl.clone(), entry.clone());
        save_state(root, &state).await.unwrap();
    }

    /// BUG GUARD (in-sync rebuild × service): the in-sync probes key only on
    /// the patch uuid, so the lockfile still pins the FIRST vendor's exact
    /// wheel sha256. A service-built wheel with different bytes must not
    /// silently replace the missing artifact — under `auto` the rebuild must
    /// fall back to the deterministic local build that reproduces the pin,
    /// or every subsequent `pip install --require-hashes` / `uv sync` fails
    /// hash verification right after vendor reported a successful rebuild.
    #[tokio::test]
    async fn in_sync_service_rebuild_must_not_break_wired_pin() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        // Local vendor: requirements.txt pins the locally-built wheel's hash.
        let VendorOutcome::Done { result, entry, .. } = vendor_pypi(
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
        .await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        let wired = tokio::fs::read_to_string(fx.root.join("requirements.txt"))
            .await
            .unwrap();
        save_ledger_entry(&fx.root, &entry).await;

        // The exact situation the rebuild path exists for: uuid dir deleted.
        tokio::fs::remove_dir_all(fx.root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();

        // The service offers a wheel whose bytes do NOT match the wired pin.
        let bytes = b"service-built wheel bytes that differ from the local build";
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
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let VendorOutcome::Done {
            result,
            entry: e2,
            warnings,
        } = outcome
        else {
            panic!("rebuild run must be Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        assert!(e2.is_none(), "artifact-only rebuild records no entry");
        // The wheel on disk still verifies against the pinned hash.
        let on_disk = tokio::fs::read(fx.root.join(&entry.artifact.path))
            .await
            .expect("the pinned wheel path must exist again");
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&on_disk)),
            entry.artifact.sha256,
            "the rebuilt wheel must reproduce the sha256 the lockfile still pins"
        );
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            wired,
            "rebuild must not touch requirements.txt"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_pin_mismatch"),
            "the service mismatch is surfaced: {warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{warnings:?}"
        );
    }

    /// `service` mode + an in-sync rebuild whose prebuilt bytes do not match
    /// the wired pin hard-fails (nothing written) instead of silently
    /// breaking the lockfile's hash pin.
    #[tokio::test]
    async fn in_sync_service_rebuild_pin_mismatch_service_mode_hard_fails() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_pypi(
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
        .await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        save_ledger_entry(&fx.root, &entry).await;
        tokio::fs::remove_dir_all(fx.root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();

        let bytes = b"service-built wheel bytes that differ from the local build";
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
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("pins"), "{detail}");
        assert!(
            !fx.root.join(&entry.artifact.path).exists(),
            "a pin mismatch must write nothing"
        );
    }

    /// The reverse direction of the same class: a project vendored FROM THE
    /// SERVICE whose wheel goes missing must not "rebuild" locally into
    /// different bytes — the loud failure names the pin so the user can
    /// revert + re-vendor instead of committing a broken lockfile.
    #[tokio::test]
    async fn in_sync_local_rebuild_pin_mismatch_fails_loudly() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"prebuilt wheel bytes from the service";
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &sri, bytes).await;
        let VendorOutcome::Done { result, entry, .. } = vendor_pypi(
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
        .await
        else {
            panic!("service vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        save_ledger_entry(&fx.root, &entry).await;
        let uuid_dir = fx.root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::remove_dir_all(&uuid_dir).await.unwrap();

        // Re-run without the service: the local build cannot reproduce the
        // service bytes the lockfile still pins.
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
            result, entry: e2, ..
        } = outcome
        else {
            panic!("rebuild run must be Done, got {outcome:?}");
        };
        assert!(
            !result.success,
            "a rebuild that breaks the wired pin must not report success"
        );
        assert!(
            result.error.as_deref().unwrap_or("").contains("pins"),
            "{:?}",
            result.error
        );
        assert!(e2.is_none());
        assert!(
            !uuid_dir.exists(),
            "the mismatched wheel must be swept back out"
        );
    }

    /// The LEDGERLESS window of the same class: the state.json entry is gone
    /// (a merge dropped it, or it was never committed) but the wired
    /// requirements line still pins the first vendor's path + sha256 — the
    /// guard must fall back to THAT pin instead of silently switching off.
    /// Service `auto` offering different bytes must fall back to the local
    /// build that reproduces the pin, exactly as with the ledger present.
    #[tokio::test]
    async fn in_sync_ledgerless_service_rebuild_must_not_break_wired_pin() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_pypi(
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
        .await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        let wired = tokio::fs::read_to_string(fx.root.join("requirements.txt"))
            .await
            .unwrap();
        // NO ledger entry is persisted: the clone never got state.json.
        tokio::fs::remove_dir_all(fx.root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();

        let bytes = b"service-built wheel bytes that differ from the local build";
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
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let VendorOutcome::Done {
            result,
            entry: e2,
            warnings,
        } = outcome
        else {
            panic!("rebuild run must be Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        assert!(e2.is_none(), "artifact-only rebuild records no entry");
        let on_disk = tokio::fs::read(fx.root.join(&entry.artifact.path))
            .await
            .expect("the pinned wheel path must exist again");
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&on_disk)),
            entry.artifact.sha256,
            "the rebuilt wheel must reproduce the sha256 the lockfile still pins"
        );
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                .await
                .unwrap(),
            wired,
            "rebuild must not touch requirements.txt"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_pin_mismatch"),
            "the service mismatch is surfaced even without a ledger: {warnings:?}"
        );
    }

    /// The ledgerless twin of the loud local failure: a project vendored
    /// FROM THE SERVICE whose ledger entry AND wheel are gone must not
    /// "rebuild" locally into bytes the wired requirements line does not
    /// pin — the wired file itself carries the pin the guard checks.
    #[tokio::test]
    async fn in_sync_ledgerless_local_rebuild_pin_mismatch_fails_loudly() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"prebuilt wheel bytes from the service";
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &sri, bytes).await;
        let VendorOutcome::Done { result, entry, .. } = vendor_pypi(
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
        .await
        else {
            panic!("service vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        assert!(entry.is_some(), "entry on success");
        // NO ledger entry is persisted; only the uuid dir goes missing.
        let uuid_dir = fx.root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::remove_dir_all(&uuid_dir).await.unwrap();

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
            result, entry: e2, ..
        } = outcome
        else {
            panic!("rebuild run must be Done, got {outcome:?}");
        };
        assert!(
            !result.success,
            "a ledgerless rebuild that breaks the wired pin must not report success"
        );
        assert!(
            result.error.as_deref().unwrap_or("").contains("pins"),
            "{:?}",
            result.error
        );
        assert!(e2.is_none());
        assert!(
            !uuid_dir.exists(),
            "the mismatched wheel must be swept back out"
        );
    }

    /// Positive control: a prebuilt wheel that byte-matches the wired pin
    /// (the normal case for a service-vendored project) rebuilds fine under
    /// `service` mode.
    #[tokio::test]
    async fn in_sync_service_rebuild_matching_pin_succeeds() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_pypi(
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
        .await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        let wheel_bytes = tokio::fs::read(fx.root.join(&entry.artifact.path))
            .await
            .unwrap();
        save_ledger_entry(&fx.root, &entry).await;
        tokio::fs::remove_dir_all(fx.root.join(format!(".socket/vendor/pypi/{UUID}")))
            .await
            .unwrap();

        let sri = sri_sha512(&wheel_bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &sri, &wheel_bytes).await;

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
            result, warnings, ..
        } = outcome
        else {
            panic!("rebuild run must be Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        assert_eq!(
            tokio::fs::read(fx.root.join(&entry.artifact.path))
                .await
                .unwrap(),
            wheel_bytes,
            "the pinned wheel is restored byte-for-byte"
        );
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{warnings:?}"
        );
    }

    // ─────────── revert drift-keep gate (RevertOutcome contract) ───────────

    use crate::vendor::state::{WiringAction, WiringRecord};

    /// A pypi-flavored [`VendorEntry`] carrying just what revert reads.
    fn revert_entry(flavor: &str, rel_wheel: &str, wiring: Vec<WiringRecord>) -> VendorEntry {
        VendorEntry {
            ecosystem: "pypi".into(),
            base_purl: "pkg:pypi/six@1.16.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: rel_wheel.to_string(),
                sha256: String::new(),
                size: None,
                platform_locked: None,
                file_inventory: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some(flavor.into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    const PIPENV_REGISTRY_LOCK: &str = r#"{
    "_meta": {
        "hash": {"sha256": "x"},
        "pipfile-spec": 6,
        "requires": {},
        "sources": []
    },
    "default": {
        "six": {
            "hashes": ["sha256:aaa"],
            "index": "pypi",
            "markers": "python_version >= '2.7'",
            "version": "==1.16.0"
        }
    },
    "develop": {}
}
"#;

    /// BUG GUARD (missing drift-keep gate — the npm-family RevertOutcome
    /// contract, residual #131): a drift-skipped pipenv revert leaves the
    /// vendor-pointing entry in Pipfile.lock, so deleting the uuid dir
    /// bricks every subsequent `pipenv install`/`sync` and pruning the
    /// ledger entry destroys the only recorded pre-vendor original. The
    /// backend must keep both and say so via `kept_artifact`.
    #[tokio::test]
    async fn pipenv_drift_skipped_revert_keeps_artifact() {
        use crate::vendor::pypi_pipenv::{load_pipenv_project, wire_pipenv};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("Pipfile.lock"), PIPENV_REGISTRY_LOCK)
            .await
            .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let p = load_pipenv_project(root).await.unwrap();
        let (wiring, _meta) = wire_pipenv(&p, root, "six", &rel_wheel, &"0".repeat(64), UUID)
            .await
            .unwrap();
        let uuid_dir = root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        let wheel = uuid_dir.join("six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();

        // Hand-edit ONLY the markers string; the "file" ref still points
        // into the uuid dir about to be deleted.
        let text = tokio::fs::read_to_string(root.join("Pipfile.lock"))
            .await
            .unwrap();
        let mut live: serde_json::Value = serde_json::from_str(&text).unwrap();
        live["default"]["six"]["markers"] = serde_json::json!("python_version >= '3.0'");
        tokio::fs::write(
            root.join("Pipfile.lock"),
            serde_json::to_string_pretty(&live).unwrap(),
        )
        .await
        .unwrap();

        let entry = revert_entry("pipenv", &rel_wheel, wiring);
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            outcome.kept_artifact,
            "a drift-skipped revert must flag the keep so the CLI retains the ledger entry"
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            wheel.is_file(),
            "Pipfile.lock still references the wheel; deleting it would brick installs"
        );
    }

    /// The splice flavors (poetry/pdm) share the same missing gate: a
    /// hand-edited-but-still-vendor-pointing `[[package]]` unit is left
    /// alone with a drift warning, so the uuid dir it references must
    /// survive the revert (and the ledger entry with it).
    #[tokio::test]
    async fn poetry_pdm_drift_skipped_revert_keeps_artifact() {
        for (flavor, lock_file, kind) in [
            ("poetry", "poetry.lock", "poetry_lock_package"),
            ("pdm", "pdm.lock", "pdm_lock_package"),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
            let original_unit =
                "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = \"registry\"\n";
            let new_unit = format!(
                "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = \"./{rel_wheel}\"\n"
            );
            // Hand-edited since vendoring (an added comment), but the unit
            // still resolves through the vendored wheel.
            let live = format!(
                "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n# reviewed\nsource = \
                 \"./{rel_wheel}\"\n"
            );
            tokio::fs::write(root.join(lock_file), &live).await.unwrap();
            let uuid_dir = root.join(format!(".socket/vendor/pypi/{UUID}"));
            tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
            let wheel = uuid_dir.join("six-1.16.0-py2.py3-none-any.whl");
            tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();

            let wiring = vec![WiringRecord {
                file: lock_file.to_string(),
                kind: kind.to_string(),
                action: WiringAction::Rewritten,
                key: Some("six".into()),
                original: Some(serde_json::Value::String(original_unit.to_string())),
                new: Some(serde_json::Value::String(new_unit.clone())),
            }];
            let entry = revert_entry(flavor, &rel_wheel, wiring);
            let outcome = revert_pypi(&entry, root, false).await;
            assert!(outcome.success, "{flavor}: {:?}", outcome.error);
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"),
                "{flavor}: {:?}",
                outcome.warnings
            );
            assert!(
                outcome.kept_artifact,
                "{flavor}: a drift-skipped revert must flag the keep"
            );
            assert!(
                wheel.is_file(),
                "{flavor}: {lock_file} still references the wheel; deleting it would brick \
                 installs"
            );
            assert_eq!(
                tokio::fs::read_to_string(root.join(lock_file))
                    .await
                    .unwrap(),
                live,
                "{flavor}: the drifted lock is left alone"
            );
        }
    }

    /// LIVENESS CONTRACT twin of the gate: a lock that already carries the
    /// pre-vendor originals (a relock regenerated them, or an earlier
    /// partial revert restored them) is CONVERGED, not drifted — the revert
    /// must stay silent and still clean up the artifact, or the drift-keep
    /// gate would retain the uuid dir and ledger entry forever.
    #[tokio::test]
    async fn pipenv_converged_revert_deletes_artifact_without_drift() {
        use crate::vendor::pypi_pipenv::{load_pipenv_project, wire_pipenv};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("Pipfile.lock"), PIPENV_REGISTRY_LOCK)
            .await
            .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let p = load_pipenv_project(root).await.unwrap();
        let (wiring, _meta) = wire_pipenv(&p, root, "six", &rel_wheel, &"0".repeat(64), UUID)
            .await
            .unwrap();
        let uuid_dir = root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(uuid_dir.join("six-1.16.0-py2.py3-none-any.whl"), b"wheel")
            .await
            .unwrap();

        // Simulate `pipenv lock` regenerating the registry entry.
        tokio::fs::write(root.join("Pipfile.lock"), PIPENV_REGISTRY_LOCK)
            .await
            .unwrap();

        let entry = revert_entry("pipenv", &rel_wheel, wiring);
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "already-converged records are silent no-ops: {:?}",
            outcome.warnings
        );
        assert!(!outcome.kept_artifact);
        assert!(
            !uuid_dir.exists(),
            "a converged revert must still clean up the artifact"
        );
    }

    /// The requirements twin of the drift-keep gate: a hand-edited vendored
    /// line that no longer trim-matches what vendor wrote — but still points
    /// into the uuid dir — raises `vendor_revert_line_drifted` +
    /// `vendor_revert_residual_reference`, and the gate must key on the
    /// latter: deleting the dir would brick every `pip install -r`, and
    /// pruning the ledger entry would destroy the only recorded pre-vendor
    /// original lines.
    #[tokio::test]
    async fn requirements_residual_reference_revert_keeps_artifact() {
        use crate::vendor::pypi_requirements::wire_requirements;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("requirements.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let wiring = wire_requirements(root, "six", "1.16.0", &rel_wheel, &"0".repeat(64))
            .await
            .unwrap();
        let uuid_dir = root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        let wheel = uuid_dir.join("six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();

        // Hand-edit the vendored line (an env marker) so it no longer
        // trim-matches what vendor wrote, while still referencing the wheel.
        let live = tokio::fs::read_to_string(root.join("requirements.txt"))
            .await
            .unwrap();
        let edited = live.replace(
            "  # socket-patch vendor:",
            " ; python_version >= \"3.8\"  # socket-patch vendor:",
        );
        assert_ne!(edited, live, "the tamper must edit the vendored line");
        tokio::fs::write(root.join("requirements.txt"), &edited)
            .await
            .unwrap();

        let entry = revert_entry("requirements", &rel_wheel, wiring);
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_revert_line_drifted"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_revert_residual_reference"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            outcome.kept_artifact,
            "a residual-reference revert must flag the keep so the CLI retains the ledger entry"
        );
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_artifact_kept"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            wheel.is_file(),
            "requirements.txt still references the wheel; deleting it would brick installs"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("requirements.txt"))
                .await
                .unwrap(),
            edited,
            "the drifted line is left alone"
        );
    }

    /// LIVENESS twin of the requirements gate: a hand-RESTORED line (the
    /// vendored line replaced back with the original pin) still raises
    /// `vendor_revert_line_drifted`, but nothing references the uuid dir any
    /// more — the gate must NOT key on the drift code alone, or the artifact
    /// and ledger entry would be kept forever with an unsatisfiable
    /// remediation. Cleanup proceeds.
    #[tokio::test]
    async fn requirements_hand_restored_revert_still_cleans_up() {
        use crate::vendor::pypi_requirements::wire_requirements;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("requirements.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let wiring = wire_requirements(root, "six", "1.16.0", &rel_wheel, &"0".repeat(64))
            .await
            .unwrap();
        let uuid_dir = root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(uuid_dir.join("six-1.16.0-py2.py3-none-any.whl"), b"wheel")
            .await
            .unwrap();

        // The user hand-restored the original pin.
        tokio::fs::write(root.join("requirements.txt"), "six==1.16.0\n")
            .await
            .unwrap();

        let entry = revert_entry("requirements", &rel_wheel, wiring);
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_revert_residual_reference"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            !outcome.kept_artifact,
            "no surviving reference: the keep gate must not fire: {:?}",
            outcome.warnings
        );
        assert!(
            !uuid_dir.exists(),
            "a hand-restored revert must still clean up the artifact"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("requirements.txt"))
                .await
                .unwrap(),
            "six==1.16.0\n"
        );
    }

    /// The splice-flavor wired-pin reader (the rebuild guard's ledgerless
    /// fallback): poetry's `url = "…"` and pdm's `path = "./…"` unit shapes
    /// both yield (path, sha) from the one-line files element vendor wrote;
    /// a lock missing the hash line yields None.
    #[test]
    fn splice_lock_wired_pin_reads_poetry_and_pdm_shapes() {
        let dir_rel = format!(".socket/vendor/pypi/{UUID}");
        let rel_wheel = format!("{dir_rel}/six-1.16.0-py2.py3-none-any.whl");
        let sha = "a".repeat(64);
        let poetry = format!(
            "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nfiles = [\n    {{file = \
             \"six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{sha}\"}},\n]\n\n\
             [package.source]\ntype = \"file\"\nurl = \"{rel_wheel}\"\n"
        );
        assert_eq!(
            splice_lock_wired_pin(&poetry, &dir_rel),
            Some((rel_wheel.clone(), sha.clone()))
        );
        let pdm = format!(
            "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\npath = \"./{rel_wheel}\"\n\
             summary = \"x\"\nfiles = [\n    {{file = \"six-1.16.0-py2.py3-none-any.whl\", \
             hash = \"sha256:{sha}\"}},\n]\n"
        );
        assert_eq!(
            splice_lock_wired_pin(&pdm, &dir_rel),
            Some((rel_wheel.clone(), sha))
        );
        let no_hash = format!("[[package]]\nname = \"six\"\nurl = \"{rel_wheel}\"\n");
        assert_eq!(
            splice_lock_wired_pin(&no_hash, &dir_rel),
            None,
            "no files hash line ⇒ no pin (the guard stays off rather than guessing)"
        );
        assert_eq!(
            splice_lock_wired_pin(&poetry, ".socket/vendor/pypi/00000000-0000-4000-8000-000000000000"),
            None,
            "a foreign uuid dir pins nothing of ours"
        );
    }

    /// The pipenv wired-pin reader: the vendored entry's `file` ref (with
    /// its `./` prefix stripped) plus the `sha256:` hash, found in ANY
    /// category section — never `_meta`.
    #[test]
    fn pipenv_wired_pin_reads_any_category_section() {
        let dir_rel = format!(".socket/vendor/pypi/{UUID}");
        let rel_wheel = format!("{dir_rel}/six-1.16.0-py2.py3-none-any.whl");
        let sha = "b".repeat(64);
        let lock = serde_json::json!({
            "_meta": {"hash": {"sha256": "c".repeat(64)}},
            "default": {
                "requests": {"hashes": ["sha256:ddd"], "version": "==2.0.0"}
            },
            "packages-custom": {
                "six": {
                    "file": format!("./{rel_wheel}"),
                    "hashes": [format!("sha256:{sha}")]
                }
            }
        });
        assert_eq!(
            pipenv_wired_pin(&lock, &dir_rel),
            Some((rel_wheel, sha))
        );
        let no_ref = serde_json::json!({
            "default": {"six": {"version": "==1.16.0", "hashes": ["sha256:eee"]}}
        });
        assert_eq!(pipenv_wired_pin(&no_ref, &dir_rel), None);
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

    // ──────────────── shared shorthand for the full-cycle tests ────────────────

    /// `vendor_pypi` with the fixture's default arguments (real run, no
    /// force) — the exact call shape every full-cycle test above repeats.
    async fn vendor_six(
        fx: &E2eFixture,
        sources: &PatchSources<'_>,
        service: Option<&VendorServiceConfig>,
    ) -> VendorOutcome {
        vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            service,
        )
        .await
    }

    fn uuid_dir_of(fx: &E2eFixture) -> PathBuf {
        fx.root.join(format!(".socket/vendor/pypi/{UUID}"))
    }

    async fn read_requirements(fx: &E2eFixture) -> String {
        tokio::fs::read_to_string(fx.root.join("requirements.txt"))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn invalid_purl_refuses_before_any_probe() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        // A non-pypi purl and a version-less pypi purl both fail the first
        // guard — before flavor routing, before any disk write.
        for purl in ["pkg:npm/foo@1.0.0", "pkg:pypi/six"] {
            let outcome = vendor_pypi(
                purl,
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
            let VendorOutcome::Refused { code, detail } = outcome else {
                panic!("{purl}: expected Refused, got {outcome:?}");
            };
            assert_eq!(code, "pypi_invalid_purl", "{purl}");
            assert!(detail.contains(purl), "{detail}");
            assert!(
                !fx.root.join(".socket").exists(),
                "{purl}: nothing may be written"
            );
        }
    }

    // ───────── full lock-flavor orchestration (poetry / pdm / pipenv) ─────────
    //
    // Byte-exact copies of the sibling modules' spike-derived six==1.16.0
    // registry lock fixtures (pypi_poetry.rs tests::LOCK21_DIRECT_REGISTRY,
    // pypi_pdm.rs / pypi_pipenv.rs tests::LOCK_DIRECT_REGISTRY — private to
    // their mods, duplicated verbatim; the spike dirs are the source of
    // truth). They pair exactly with e2e_fixture()'s installed six 1.16.0,
    // so one vendor_pypi → revert_pypi cycle runs the flavor's plan arm,
    // wire arm, flavor tag, and MetaSlot arm end to end.

    const POETRY_LOCK_REGISTRY: &str = r#"# This file is automatically @generated by Poetry 2.4.1 and should not be changed by hand.

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
groups = ["main"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"},
    {file = "six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},
]

[metadata]
lock-version = "2.1"
python-versions = ">=3.9"
content-hash = "4b42a89b7ff7b26511b06acdc458dbd85312e5083db8f212b017482bc68cdd01"
"#;

    const PDM_LOCK_REGISTRY: &str = r#"# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default"]
strategy = ["inherit_metadata"]
lock_version = "4.5.0"
content_hash = "sha256:d49d286986c5de41ec9879b6d710389b0be11cd096d883c069123b489ac6e6ea"

[[metadata.targets]]
requires_python = "==3.14.*"

[[package]]
name = "six"
version = "1.16.0"
requires_python = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
summary = "Python 2 and 3 compatibility utilities"
groups = ["default"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"},
    {file = "six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},
]
"#;

    const PIPENV_LOCK_REGISTRY: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "55f44fe4c8bc29094f3076c7eddb912ca00f80c016020ffa2bcbd67ccc7114a1"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.14"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "six": {
            "hashes": [
                "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926",
                "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"
            ],
            "index": "pypi",
            "markers": "python_version >= '2.7' and python_version not in '3.0, 3.1, 3.2'",
            "version": "==1.16.0"
        }
    },
    "develop": {}
}
"#;

    /// The uv pair fixture (same text as the wired-rebuild test above; kept
    /// as consts so the orchestration-refusal tests can reuse it).
    const UV_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["six==1.16.0"]
"#;

    const UV_LOCK_REGISTRY: &str = r#"version = 1
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
"#;

    /// Swap the e2e fixture's requirements flavor for a lockfile flavor.
    async fn swap_to_lock_flavor(fx: &E2eFixture, files: &[(&str, &str)]) {
        tokio::fs::remove_file(fx.root.join("requirements.txt"))
            .await
            .unwrap();
        for (name, text) in files {
            touch(&fx.root, name, text).await;
        }
    }

    /// One full vendor → revert cycle through `vendor_pypi` for a lock-splice
    /// flavor: plan arm, wire arm, `entry.flavor` tag (PypiFlavor::as_str),
    /// the matching MetaSlot, and the byte-identical lock restore.
    async fn full_cycle_lock_flavor(
        flavor: &str,
        lock_file: &str,
        lock_text: &str,
        wiring_kind: &str,
    ) {
        let fx = e2e_fixture().await;
        swap_to_lock_flavor(&fx, &[(lock_file, lock_text)]).await;
        let sources = PatchSources::blobs_only(&fx.blobs);

        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Done { result, entry, .. } = outcome else {
            panic!("{flavor}: expected Done, got {outcome:?}");
        };
        assert!(result.success, "{flavor}: {:?}", result.error);
        let entry = entry.expect("entry on success");

        // Ledger shape: the flavor tag routes revert; exactly the matching
        // meta slot is filled.
        assert_eq!(entry.flavor.as_deref(), Some(flavor));
        assert!(entry.uv.is_none(), "{flavor}: uv slot must stay empty");
        assert_eq!(
            entry.poetry.is_some(),
            flavor == "poetry",
            "{flavor}: poetry meta slot"
        );
        assert_eq!(
            entry.pdm.is_some(),
            flavor == "pdm",
            "{flavor}: pdm meta slot"
        );
        assert_eq!(
            entry.pipenv.is_some(),
            flavor == "pipenv",
            "{flavor}: pipenv meta slot"
        );

        // The wheel landed at the uuid path and the lock was wired to it
        // (path + recomputed sha256 — a positional-arg swap in the wire call
        // would compile silently and break exactly these).
        let wheel_rel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        assert_eq!(entry.artifact.path, wheel_rel);
        assert!(fx.root.join(&wheel_rel).is_file(), "{flavor}");
        let wired = tokio::fs::read_to_string(fx.root.join(lock_file))
            .await
            .unwrap();
        assert_ne!(wired, lock_text, "{flavor}: the lock must be rewritten");
        assert!(
            wired.contains(&wheel_rel),
            "{flavor}: the lock must reference the vendored wheel: {wired}"
        );
        assert!(
            wired.contains(&entry.artifact.sha256),
            "{flavor}: the lock must pin the recomputed wheel sha256: {wired}"
        );
        assert!(!entry.wiring.is_empty(), "{flavor}");
        assert_eq!(entry.wiring[0].kind, wiring_kind, "{flavor}");
        assert_eq!(entry.wiring[0].file, lock_file, "{flavor}");

        // Revert: byte-identical lock restore, artifact dir swept.
        let reverted = revert_pypi(&entry, &fx.root, false).await;
        assert!(reverted.success, "{flavor}: {:?}", reverted.error);
        assert!(
            reverted.warnings.is_empty(),
            "{flavor}: {:?}",
            reverted.warnings
        );
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join(lock_file))
                .await
                .unwrap(),
            lock_text,
            "{flavor}: revert must restore the lock byte-identically"
        );
        assert!(!uuid_dir_of(&fx).exists(), "{flavor}");
    }

    #[tokio::test]
    async fn end_to_end_poetry_vendor_and_revert() {
        full_cycle_lock_flavor(
            "poetry",
            "poetry.lock",
            POETRY_LOCK_REGISTRY,
            "poetry_lock_package",
        )
        .await;
    }

    #[tokio::test]
    async fn end_to_end_pdm_vendor_and_revert() {
        full_cycle_lock_flavor("pdm", "pdm.lock", PDM_LOCK_REGISTRY, "pdm_lock_package").await;
    }

    #[tokio::test]
    async fn end_to_end_pipenv_vendor_and_revert() {
        full_cycle_lock_flavor(
            "pipenv",
            "Pipfile.lock",
            PIPENV_LOCK_REGISTRY,
            "pipenv_lock_entry",
        )
        .await;
    }

    /// The `vendor_platform_locked` advisory names the file the platform
    /// pin now lives in, per flavor (the requirements arm is covered by
    /// `platform_specific_tags_set_platform_locked_and_warn`).
    #[tokio::test]
    async fn platform_locked_warning_names_the_lock_per_flavor() {
        let cases = [
            (
                "uv",
                &[
                    ("pyproject.toml", UV_PYPROJECT),
                    ("uv.lock", UV_LOCK_REGISTRY),
                ][..],
                "uv.lock now resolves",
            ),
            (
                "poetry",
                &[("poetry.lock", POETRY_LOCK_REGISTRY)][..],
                "poetry.lock now resolves",
            ),
            (
                "pdm",
                &[("pdm.lock", PDM_LOCK_REGISTRY)][..],
                "pdm.lock now resolves",
            ),
            (
                "pipenv",
                &[("Pipfile.lock", PIPENV_LOCK_REGISTRY)][..],
                "Pipfile.lock now resolves",
            ),
        ];
        for (flavor, files, needle) in cases {
            let fx = e2e_fixture().await;
            swap_to_lock_flavor(&fx, files).await;
            // The installed dist is a compiled single-platform wheel.
            tokio::fs::write(
                fx.site_packages.join("six-1.16.0.dist-info/WHEEL"),
                "Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: cp312-cp312-manylinux_2_17_x86_64\n",
            )
            .await
            .unwrap();
            let sources = PatchSources::blobs_only(&fx.blobs);
            let outcome = vendor_six(&fx, &sources, None).await;
            let VendorOutcome::Done {
                result,
                entry,
                warnings,
            } = outcome
            else {
                panic!("{flavor}: expected Done, got {outcome:?}");
            };
            assert!(result.success, "{flavor}: {:?}", result.error);
            assert_eq!(
                entry.unwrap().artifact.platform_locked,
                Some(true),
                "{flavor}"
            );
            let w = warnings
                .iter()
                .find(|w| w.code == "vendor_platform_locked")
                .unwrap_or_else(|| panic!("{flavor}: {warnings:?}"));
            assert!(w.detail.contains(needle), "{flavor}: {}", w.detail);
        }
    }

    // ───────────── uv guard failures surfaced through the orchestrator ─────────────

    #[tokio::test]
    async fn uv_lock_parse_failure_refuses_through_orchestrator() {
        let fx = e2e_fixture().await;
        swap_to_lock_flavor(
            &fx,
            &[
                ("pyproject.toml", UV_PYPROJECT),
                ("uv.lock", "version = [broken\n"),
            ],
        )
        .await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "pypi_uv_lock_parse_failed");
        assert!(detail.contains("uv.lock does not parse"), "{detail}");
        assert!(
            !fx.root.join(".socket").exists(),
            "a load refusal must leave the tree byte-untouched"
        );
    }

    /// The uv mirror of `requirements_stale_uuid_vendor_line_refuses`: a pair
    /// already wired to an EARLIER patch uuid refuses through the
    /// orchestrator, before any new uuid dir is created.
    #[tokio::test]
    async fn uv_stale_uuid_vendor_refuses_through_orchestrator() {
        const UUID2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        let fx = e2e_fixture().await;
        swap_to_lock_flavor(
            &fx,
            &[
                ("pyproject.toml", UV_PYPROJECT),
                ("uv.lock", UV_LOCK_REGISTRY),
            ],
        )
        .await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, .. } = vendor_six(&fx, &sources, None).await else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let pyproject_wired = tokio::fs::read(fx.root.join("pyproject.toml"))
            .await
            .unwrap();
        let lock_wired = tokio::fs::read(fx.root.join("uv.lock")).await.unwrap();

        // Same package, new patch generation (different uuid).
        let mut record2 = fx.record.clone();
        record2.uuid = UUID2.to_string();
        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &record2,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            None,
        )
        .await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "pypi_uv_source_already_exists");
        assert!(detail.contains("vendor --revert"), "{detail}");
        // Pre-flight refusal: the wired pair untouched, no second uuid dir.
        assert_eq!(
            tokio::fs::read(fx.root.join("pyproject.toml"))
                .await
                .unwrap(),
            pyproject_wired
        );
        assert_eq!(
            tokio::fs::read(fx.root.join("uv.lock")).await.unwrap(),
            lock_wired
        );
        assert!(!fx
            .root
            .join(format!(".socket/vendor/pypi/{UUID2}"))
            .exists());
    }

    // ───────────── local-build refusals surfaced through the orchestrator ─────────────

    #[tokio::test]
    async fn missing_dist_refuses_with_no_residue() {
        let fx = e2e_fixture().await;
        tokio::fs::remove_dir_all(fx.site_packages.join("six-1.16.0.dist-info"))
            .await
            .unwrap();
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "pypi_dist_not_found");
        assert!(detail.contains("six@1.16.0"), "{detail}");
        assert!(!fx.root.join(".socket").exists());
        assert_eq!(read_requirements(&fx).await, "six==1.16.0\n");
    }

    /// A WHEEL tag set that is not a cross product of its components cannot
    /// be expressed as one wheel filename — `wheel_file_name` refuses through
    /// the orchestrator before anything is built.
    #[tokio::test]
    async fn non_cross_product_wheel_tags_refuse_with_no_residue() {
        let fx = e2e_fixture().await;
        tokio::fs::write(
            fx.site_packages.join("six-1.16.0.dist-info/WHEEL"),
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py2-none-any\nTag: py3-abi3-manylinux1_x86_64\n",
        )
        .await
        .unwrap();
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "pypi_wheel_tags_unrecoverable");
        assert!(detail.contains("cross product"), "{detail}");
        assert!(!fx.root.join(".socket").exists());
    }

    /// An editable install (`pip install -e`) is the user's own working tree
    /// — `build_patched_wheel`'s hard-Err maps to a refusal with no residue.
    #[tokio::test]
    async fn editable_install_refuses_with_no_residue() {
        let fx = e2e_fixture().await;
        tokio::fs::write(
            fx.site_packages
                .join("six-1.16.0.dist-info/direct_url.json"),
            r#"{"url":"file:///src","dir_info":{"editable":true}}"#,
        )
        .await
        .unwrap();
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "pypi_editable_install");
        assert!(detail.contains("editable install"), "{detail}");
        assert!(!fx.root.join(".socket").exists());
        assert_eq!(read_requirements(&fx).await, "six==1.16.0\n");
    }

    /// Deleting ONLY the committed wheel (the marker file survives) must
    /// still take the artifact-only rebuild: `uuid_dir_has_wheel` scans the
    /// surviving entries for a `.whl` rather than keying on dir existence.
    #[tokio::test]
    async fn wheel_deleted_marker_kept_still_rebuilds() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        let wired = read_requirements(&fx).await;
        let wheel = fx.root.join(&entry.artifact.path);
        tokio::fs::remove_file(&wheel).await.unwrap();
        assert!(uuid_dir_of(&fx).join(VENDOR_MARKER_FILE).is_file());

        let VendorOutcome::Done {
            result: r2,
            entry: e2,
            warnings,
        } = vendor_six(&fx, &sources, None).await
        else {
            panic!("rebuild run must be Done");
        };
        assert!(r2.success, "{:?}", r2.error);
        assert!(e2.is_none(), "artifact-only rebuild records no entry");
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{warnings:?}"
        );
        assert!(
            !warnings.iter().any(|w| w.code == "marker_write_failed"),
            "rewriting the surviving marker file must succeed: {warnings:?}"
        );
        assert!(wheel.is_file(), "wheel rebuilt at the recorded path");
        assert_eq!(read_requirements(&fx).await, wired);
    }

    // ───────────── marker write failures (fresh + rebuild paths) ─────────────

    /// A non-empty DIRECTORY squatting at the marker filename makes
    /// `write_marker`'s atomic rename fail deterministically.
    async fn plant_marker_blocker(fx: &E2eFixture) {
        let blocker = uuid_dir_of(fx).join(VENDOR_MARKER_FILE);
        tokio::fs::create_dir_all(&blocker).await.unwrap();
        tokio::fs::write(blocker.join("occupied"), b"x")
            .await
            .unwrap();
    }

    /// Fresh path: a failed marker write flips the run to failure, sweeps
    /// the uuid dir, and leaves the wiring untouched (it was never written —
    /// the marker lands BEFORE the wiring).
    #[tokio::test]
    async fn fresh_marker_write_failure_sweeps_artifact_and_fails() {
        let fx = e2e_fixture().await;
        plant_marker_blocker(&fx).await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Done { result, entry, .. } = outcome else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(!result.success, "the failed marker write must be reported");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write vendor marker"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(
            !uuid_dir_of(&fx).exists(),
            "a failed fresh vendor must leave no committed residue"
        );
        assert_eq!(read_requirements(&fx).await, "six==1.16.0\n");
    }

    /// In-sync rebuild path: the marker restore is advisory — its failure is
    /// a warning riding an otherwise-successful artifact rebuild.
    #[tokio::test]
    async fn rebuild_marker_write_failure_is_warning_only() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        let wired = read_requirements(&fx).await;
        // The wheel rots away; the marker path is then blocked by a dir.
        tokio::fs::remove_file(fx.root.join(&entry.artifact.path))
            .await
            .unwrap();
        tokio::fs::remove_file(uuid_dir_of(&fx).join(VENDOR_MARKER_FILE))
            .await
            .unwrap();
        plant_marker_blocker(&fx).await;

        let VendorOutcome::Done {
            result: r2,
            entry: e2,
            warnings,
        } = vendor_six(&fx, &sources, None).await
        else {
            panic!("rebuild run must be Done");
        };
        assert!(
            r2.success,
            "the rebuild itself succeeded; the marker is advisory: {:?}",
            r2.error
        );
        assert!(e2.is_none());
        assert!(
            warnings.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.code == "marker_write_failed"),
            "{warnings:?}"
        );
        assert!(fx.root.join(&entry.artifact.path).is_file());
        assert_eq!(read_requirements(&fx).await, wired);
    }

    /// Wiring failure LAST-step contract: when the lockfile write fails
    /// after the wheel was built and the marker written, the artifact dir is
    /// swept back out — a failed vendor leaves no committed residue.
    #[cfg(unix)]
    #[tokio::test]
    async fn wiring_failure_sweeps_wheel_artifact() {
        use std::os::unix::fs::PermissionsExt as _;
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        // The artifact area gets its own writable home first; the root is
        // then frozen so the wiring's atomic stage file for requirements.txt
        // cannot be created (flavor routing + preflight only READ the root).
        tokio::fs::create_dir_all(fx.root.join(".socket/vendor/pypi"))
            .await
            .unwrap();
        tokio::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        // Skip when the environment ignores modes (running as root).
        if std::fs::write(fx.root.join(".probe"), b"x").is_ok() {
            let _ = std::fs::remove_file(fx.root.join(".probe"));
            tokio::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o755))
                .await
                .unwrap();
            return;
        }
        let outcome = vendor_six(&fx, &sources, None).await;
        tokio::fs::set_permissions(&fx.root, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        let VendorOutcome::Done { result, entry, .. } = outcome else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(!result.success, "the failed wiring must be reported");
        assert!(
            result
                .error
                .as_deref()
                .unwrap_or("")
                .contains("pypi_requirements_write_failed"),
            "{:?}",
            result.error
        );
        assert!(entry.is_none());
        assert!(
            !uuid_dir_of(&fx).exists(),
            "a failed wiring must sweep the wheel artifact back out"
        );
        assert_eq!(read_requirements(&fx).await, "six==1.16.0\n");
    }

    // ───────────── revert: dry-run / --preserve-state / delete guards ─────────────

    #[tokio::test]
    async fn revert_dry_run_leaves_wiring_and_artifact_intact() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        let wired = read_requirements(&fx).await;

        let outcome = revert_pypi(&entry, &fx.root, true).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            read_requirements(&fx).await,
            wired,
            "a dry-run revert must not touch the wiring"
        );
        assert!(
            fx.root.join(&entry.artifact.path).is_file(),
            "a dry-run revert must not delete the artifact"
        );
        assert!(uuid_dir_of(&fx).join(VENDOR_MARKER_FILE).is_file());
    }

    /// `--preserve-state` (`keep_artifact`): the wiring restore runs, the
    /// artifact dir survives, and the drift-keep flag stays reserved for
    /// actual drift-keeps.
    #[tokio::test]
    async fn revert_keep_artifact_restores_wiring_but_keeps_artifact() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");

        let outcome = revert_pypi_opts(
            &entry,
            &fx.root,
            RevertOpts {
                dry_run: false,
                keep_artifact: true,
            },
        )
        .await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome.kept_artifact,
            "keep_artifact must not claim a drift-keep"
        );
        assert_eq!(
            read_requirements(&fx).await,
            "six==1.16.0\n",
            "the wiring restore still runs under --preserve-state"
        );
        assert!(
            fx.root.join(&entry.artifact.path).is_file(),
            "the artifact dir must survive --preserve-state"
        );
    }

    /// SECURITY fail-closed twin of `uuid_traversal_is_refused_before_any_write`:
    /// a revert with a tampered (non-canonical) uuid from state.json must
    /// warn and refuse the deletion, never derive a delete path from it.
    #[tokio::test]
    async fn revert_with_tampered_uuid_refuses_artifact_deletion() {
        let fx = e2e_fixture().await;
        let mut entry = revert_entry(
            "requirements",
            ".socket/vendor/pypi/x/six-1.16.0-py2.py3-none-any.whl",
            vec![],
        );
        entry.uuid = "../../../etc/passwd".to_string();
        let outcome = revert_pypi(&entry, &fx.root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        let w = outcome
            .warnings
            .iter()
            .find(|w| w.code == "vendor_unsafe_uuid")
            .unwrap_or_else(|| panic!("{:?}", outcome.warnings));
        assert!(w.detail.contains("../../../etc/passwd"), "{}", w.detail);
    }

    /// An artifact dir already gone is the expected post-clean state:
    /// NotFound is tolerated silently.
    #[tokio::test]
    async fn revert_tolerates_already_deleted_artifact_dir() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        tokio::fs::remove_dir_all(uuid_dir_of(&fx)).await.unwrap();

        let outcome = revert_pypi(&entry, &fx.root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome.warnings.is_empty(),
            "an already-deleted dir must stay warning-free: {:?}",
            outcome.warnings
        );
        assert_eq!(read_requirements(&fx).await, "six==1.16.0\n");
    }

    /// A real removal error (not NotFound) is surfaced as a warning naming
    /// the dir, on an otherwise-successful revert.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_artifact_remove_failure_is_warning_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");

        // A read-only PARENT blocks the final rmdir of the uuid dir. Skip
        // when the environment ignores modes (running as root).
        let parent = fx.root.join(".socket/vendor/pypi");
        tokio::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        if std::fs::write(parent.join(".probe"), b"x").is_ok() {
            let _ = std::fs::remove_file(parent.join(".probe"));
            tokio::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
                .await
                .unwrap();
            return;
        }
        let outcome = revert_pypi(&entry, &fx.root, false).await;
        tokio::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(outcome.success, "{:?}", outcome.error);
        let w = outcome
            .warnings
            .iter()
            .find(|w| w.code == "vendor_artifact_remove_failed")
            .unwrap_or_else(|| panic!("{:?}", outcome.warnings));
        assert!(
            w.detail.contains(&format!(".socket/vendor/pypi/{UUID}")),
            "{}",
            w.detail
        );
        assert_eq!(
            read_requirements(&fx).await,
            "six==1.16.0\n",
            "the wiring restore lands before (and despite) the delete failure"
        );
    }

    // ───────────── service status matrix (pending / unavailable / failed) ─────────────

    /// Mount ONLY the package POST, answering `status` for the fixture uuid
    /// (no artifacts — the pre-download build/grant classification arms).
    async fn mount_pypi_status(server: &wiremock::MockServer, status: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "results": { UUID: { "status": status } }
            })))
            .mount(server)
            .await;
    }

    /// `pending_build` under `auto`: warn + fall back to the local build.
    #[tokio::test]
    async fn service_pending_auto_warns_and_builds_locally() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let server = wiremock::MockServer::start().await;
        mount_pypi_status(&server, "pending_build").await;

        let outcome = vendor_six(
            &fx,
            &sources,
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
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
        assert!(entry.is_some(), "the local fallback is a full fresh vendor");
        let w = warnings
            .iter()
            .find(|w| w.code == "vendor_prebuilt_pending")
            .unwrap_or_else(|| panic!("{warnings:?}"));
        assert!(w.detail.contains("still building"), "{}", w.detail);
        assert!(
            w.detail.contains("building locally instead"),
            "{}",
            w.detail
        );
        assert!(
            fx.root
                .join(format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}"))
                .is_file(),
            "the local fallback build must land"
        );
    }

    /// `pending_build` under `service`: hard fail, nothing written.
    #[tokio::test]
    async fn service_pending_service_mode_hard_fails() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let server = wiremock::MockServer::start().await;
        mount_pypi_status(&server, "pending_build").await;

        let outcome = vendor_six(
            &fx,
            &sources,
            Some(&pypi_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("still building"), "{detail}");
        assert!(!fx.root.join(".socket").exists());
        assert_eq!(read_requirements(&fx).await, "six==1.16.0\n");
    }

    /// `not_found` under `auto` is the deliberately-QUIET fallback (the
    /// common "not built / free-only" case): no `vendor_prebuilt_*` warning
    /// at all, just the local build.
    #[tokio::test]
    async fn service_unavailable_auto_falls_back_silently() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let server = wiremock::MockServer::start().await;
        mount_pypi_status(&server, "not_found").await;

        let outcome = vendor_six(
            &fx,
            &sources,
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
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
        assert!(entry.is_some());
        assert!(
            warnings
                .iter()
                .all(|w| !w.code.starts_with("vendor_prebuilt")),
            "the unavailable fallback is documented as silent: {warnings:?}"
        );
        assert!(fx
            .root
            .join(format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}"))
            .is_file());
    }

    /// `not_found` under `service`: hard fail naming the miss reason.
    #[tokio::test]
    async fn service_unavailable_service_mode_hard_fails() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let server = wiremock::MockServer::start().await;
        mount_pypi_status(&server, "not_found").await;

        let outcome = vendor_six(
            &fx,
            &sources,
            Some(&pypi_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(detail.contains("unavailable: not_found"), "{detail}");
        assert!(!fx.root.join(".socket").exists());
    }

    /// A failed service REQUEST (HTTP 500) under `auto`: loud
    /// `vendor_prebuilt_unavailable` warning + local-build fallback.
    #[tokio::test]
    async fn service_request_failure_auto_warns_and_builds_locally() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/patches/package"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let outcome = vendor_six(
            &fx,
            &sources,
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
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
        assert!(entry.is_some());
        let w = warnings
            .iter()
            .find(|w| w.code == "vendor_prebuilt_unavailable")
            .unwrap_or_else(|| panic!("{warnings:?}"));
        assert!(
            w.detail.contains("patch service request failed"),
            "{}",
            w.detail
        );
        assert!(fx
            .root
            .join(format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}"))
            .is_file());
    }

    // ───────────── service write failures (hard fail in EVERY mode) ─────────────

    /// A regular file squatting at the uuid dir path: `create_dir_all`
    /// fails → `vendor_prebuilt_write_failed` hard fail, wiring untouched.
    #[tokio::test]
    async fn service_uuid_dir_create_failure_hard_fails() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"prebuilt wheel bytes from the service";
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &sri, bytes).await;

        tokio::fs::create_dir_all(fx.root.join(".socket/vendor/pypi"))
            .await
            .unwrap();
        tokio::fs::write(
            fx.root.join(format!(".socket/vendor/pypi/{UUID}")),
            b"squatter",
        )
        .await
        .unwrap();

        let outcome = vendor_six(
            &fx,
            &sources,
            Some(&pypi_service_cfg(
                &server.uri(),
                VendorSource::Service,
                false,
            )),
        )
        .await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(detail.contains("cannot create"), "{detail}");
        assert_eq!(read_requirements(&fx).await, "six==1.16.0\n");
    }

    /// A write failure on the wheel itself is a hard fail even under `auto`
    /// (a broken disk is not a "service miss" to silently build around).
    #[tokio::test]
    async fn service_wheel_write_failure_hard_fails_even_under_auto() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let bytes = b"prebuilt wheel bytes from the service";
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &sri, bytes).await;

        // A non-empty directory squatting at the destination wheel filename
        // makes atomic_write_bytes' rename fail deterministically.
        let blocker = fx
            .root
            .join(format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}"));
        tokio::fs::create_dir_all(&blocker).await.unwrap();
        tokio::fs::write(blocker.join("occupied"), b"x")
            .await
            .unwrap();

        let outcome = vendor_six(
            &fx,
            &sources,
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let VendorOutcome::Refused { code, detail } = outcome else {
            panic!("expected Refused, got {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_write_failed");
        assert!(
            detail.contains("cannot write the vendored wheel"),
            "{detail}"
        );
        assert_eq!(
            read_requirements(&fx).await,
            "six==1.16.0\n",
            "the wiring is only ever written after a successful wheel"
        );
        // Pin of CURRENT residue behavior: the refusal does not sweep the
        // (pre-existing) uuid dir — nothing references it, since the wiring
        // was never touched. FIXME(no-residue): candidate cleanup gap if the
        // dir was created by this very run.
        assert!(blocker.is_dir());
    }

    /// The wheel-filename fallback for an unparseable stem (< 3 dash parts)
    /// cannot prove portability → claims platform-locked, fail-closed.
    #[test]
    fn wheel_platform_filename_fallback_is_fail_closed() {
        // Full stems parse the trailing tag triple.
        assert_eq!(
            wheel_platform_from_filename("six-1.16.0-py2.py3-none-any.whl"),
            (false, "py2.py3-none-any".to_string())
        );
        assert_eq!(
            wheel_platform_from_filename("x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl"),
            (true, "cp312-cp312-manylinux_2_17_x86_64".to_string())
        );
        // Short stems fall back closed and surface the stem verbatim.
        assert_eq!(
            wheel_platform_from_filename("six.whl"),
            (true, "six".to_string())
        );
        assert_eq!(
            wheel_platform_from_filename("a-b.whl"),
            (true, "a-b".to_string())
        );
    }
}
