//! pypi vendor backend: flavor routing + orchestration.
//!
//! Order of operations is the safety story: every refusal-capable check
//! (flavor route, uv project guards, requirements pre-flight, dist lookup,
//! tag compression) runs BEFORE the wheel artifact is built, and the
//! lockfile/manifest wiring is written LAST — so a refusal leaves the tree
//! byte-untouched and an artifact failure never leaves half-wired lockfiles.

use std::path::Path;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use crate::api::client::{ApiClient, DeferredAttempt};
use crate::constants::SOCKET_DIR;
use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::manifest::schema::PatchRecord;
use crate::patch::apply::{ApplyResult, PatchSources};
use crate::utils::fs::{atomic_write_artifact, read_regular_to_string};
use crate::utils::purl::{parse_pypi_purl, strip_purl_qualifiers};
use crate::utils::socket_dir::remove_tree_and_prune;
use crate::utils::toml_edit_ext::has_table;

use super::common::{
    already_patched_result, done, prune_empty_vendor_levels, refused, service_offline_conflict,
    zip_bytes_match_after_hashes,
};
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
    build_patched_wheel, escape_wheel_version, locate_installed_dist, wheel_file_name,
    WheelArtifact,
};
use super::reuse;
use super::service_fetch::{fetch_verified_archive, ServiceArtifact};
use super::source::PackageSource;
use super::state::{
    write_marker_or_warn, PdmMeta, PipenvMeta, PoetryMeta, UvMeta, VendorArtifact, VendorEntry,
    VendorMarker,
};
use super::{RevertOpts, RevertOutcome, VendorOutcome, VendorServiceConfig, VendorWarning};

/// Which wiring backend serves this project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PypiFlavor {
    /// `uv.lock`-managed project → paired pyproject + lock surgery.
    UvProject,
    PythonLocks,
    /// `poetry.lock`-managed project → lock-only `[[package]]` splice.
    Poetry,
    /// `pdm.lock`-managed project → lock-only `[[package]]` splice.
    Pdm,
    /// `Pipfile.lock`-managed project → lock-only JSON entry rewrite.
    Pipenv,
    /// Plain `requirements.txt` (pip / `uv pip`) → line rewriting.
    Requirements,
    Hatch,
}

impl PypiFlavor {
    fn as_str(self) -> &'static str {
        match self {
            PypiFlavor::UvProject => "uv",
            PypiFlavor::PythonLocks => "python-lock",
            PypiFlavor::Poetry => "poetry",
            PypiFlavor::Pdm => "pdm",
            PypiFlavor::Pipenv => "pipenv",
            PypiFlavor::Requirements => "requirements",
            PypiFlavor::Hatch => "hatch",
        }
    }
}

fn validate_hosted_wheel_sha256(sha256: &str) -> Result<(), String> {
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("hosted wheel sha256 must be 64 hexadecimal characters".to_string());
    }
    Ok(())
}

fn decode_hosted_wheel_metadata(bytes: &[u8], sha256: &str) -> Result<Option<String>, String> {
    validate_hosted_wheel_sha256(sha256)?;
    if !hex::encode(Sha256::digest(bytes)).eq_ignore_ascii_case(sha256) {
        return Err("hosted wheel sha256 does not match the published artifact".to_string());
    }
    let metadata = super::pypi_uv::wheel_metadata_text(bytes)
        .ok_or_else(|| "hosted wheel has no readable size-bounded core metadata".to_string())?;
    let headers: Vec<_> = metadata
        .lines()
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .collect();
    for required in ["Metadata-Version", "Name", "Version"] {
        if !headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case(required) && !value.trim().is_empty())
        {
            return Err(format!("hosted wheel core metadata is missing {required}"));
        }
    }
    let rendered = super::pypi_uv::render_package_metadata_block(&metadata);
    if rendered.is_none()
        && headers.iter().any(|(name, _)| {
            name.eq_ignore_ascii_case("Requires-Dist")
                || name.eq_ignore_ascii_case("Provides-Extra")
        })
    {
        return Err(
            "hosted wheel dependency metadata cannot be represented in a uv lockfile".to_string(),
        );
    }
    if let Some(rendered) = &rendered {
        rendered
            .parse::<toml_edit::DocumentMut>()
            .map_err(|error| format!("hosted wheel dependency metadata is invalid: {error}"))?;
    }
    Ok(rendered)
}

pub async fn fetch_hosted_wheel_metadata(
    client: &ApiClient,
    url: &str,
    sha256: &str,
) -> Result<Option<String>, String> {
    validate_hosted_wheel_sha256(sha256)?;
    let bytes = client
        .download_artifact(url)
        .await
        .map_err(|error| format!("cannot fetch hosted wheel metadata: {error}"))?;
    decode_hosted_wheel_metadata(&bytes, sha256)
}

/// [`fetch_hosted_wheel_metadata`]'s FIRST attempt, for running several
/// wheels' first attempts concurrently while keeping the one-at-a-time
/// loop's per-wheel request sequence. Opaque; hand it back to
/// [`finish_hosted_wheel_metadata`], which either reports what it settled or
/// spends the rest of its retry budget.
pub struct HostedWheelMetadataAttempt {
    outcome: WheelAttemptOutcome,
    /// The attempt's `debug_log` lines, held back so they print where the
    /// one-at-a-time loop's would have — its GET really happened, so they
    /// are printed, never dropped.
    debug: Vec<String>,
}

enum WheelAttemptOutcome {
    /// Settled on the first attempt: exactly what
    /// `fetch_hosted_wheel_metadata` would have returned.
    Settled(Result<Option<String>, String>),
    /// The first attempt failed in a way `fetch_hosted_wheel_metadata`
    /// retries, with the rest of its budget still unspent.
    Retry(DeferredAttempt),
}

impl HostedWheelMetadataAttempt {
    /// Did the first attempt fail in a way the retry budget covers? Such an
    /// attempt is finished one at a time, so a caller fanning out stops
    /// widening at the first one: the host is struggling.
    pub fn needs_retry(&self) -> bool {
        matches!(self.outcome, WheelAttemptOutcome::Retry(_))
    }
}

/// [`fetch_hosted_wheel_metadata`]'s first attempt only, with its debug
/// lines held back (see [`HostedWheelMetadataAttempt`]).
pub async fn try_fetch_hosted_wheel_metadata_once(
    client: &ApiClient,
    url: &str,
    sha256: &str,
) -> HostedWheelMetadataAttempt {
    if let Err(error) = validate_hosted_wheel_sha256(sha256) {
        return HostedWheelMetadataAttempt {
            outcome: WheelAttemptOutcome::Settled(Err(error)),
            debug: Vec::new(),
        };
    }
    let (attempt, debug) =
        crate::api::client::with_deferred_debug(client.download_artifact_first_attempt(url)).await;
    HostedWheelMetadataAttempt {
        outcome: match attempt {
            Err(deferred) => WheelAttemptOutcome::Retry(deferred),
            Ok(downloaded) => WheelAttemptOutcome::Settled(
                downloaded
                    .map_err(|error| format!("cannot fetch hosted wheel metadata: {error}"))
                    .and_then(|bytes| decode_hosted_wheel_metadata(&bytes, sha256)),
            ),
        },
        debug,
    }
}

/// Finish a wheel's metadata fetch where the one-at-a-time loop would have
/// run it: the first attempt's held-back debug lines print here, and an
/// attempt that earned a retry spends the REST of its budget here, pausing
/// as its `Retry-After` asked. `None` (no attempt was ever started) runs the
/// whole of [`fetch_hosted_wheel_metadata`]. Either way this wheel costs the
/// host the one-at-a-time loop's requests, at most `attempts` of them.
pub async fn finish_hosted_wheel_metadata(
    client: &ApiClient,
    url: &str,
    sha256: &str,
    attempt: Option<HostedWheelMetadataAttempt>,
) -> Result<Option<String>, String> {
    let Some(attempt) = attempt else {
        return fetch_hosted_wheel_metadata(client, url, sha256).await;
    };
    crate::api::client::flush_deferred_debug(attempt.debug);
    match attempt.outcome {
        WheelAttemptOutcome::Settled(result) => result,
        WheelAttemptOutcome::Retry(deferred) => client
            .download_artifact_resuming(url, deferred)
            .await
            .map_err(|error| format!("cannot fetch hosted wheel metadata: {error}"))
            .and_then(|bytes| decode_hosted_wheel_metadata(&bytes, sha256)),
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
    target: Option<(&str, &str)>,
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
    let mut present: Vec<&str> = [
        ("uv.lock", has_uv_lock),
        ("poetry.lock", has_poetry_lock),
        ("pdm.lock", has_pdm_lock),
        ("Pipfile.lock", has_pipfile_lock),
    ]
    .into_iter()
    .filter_map(|(name, present)| present.then_some(name))
    .collect();
    let additional_locks: Vec<String> = crate::utils::python_lock::python_lock_paths(project_root)
        .map_err(|error| ("pypi_lock_read_failed", error.to_string()))?
        .into_iter()
        .filter(|path| path != "uv.lock")
        .collect();
    let mut warnings = Vec::new();
    let matching_additional_lock = if has_uv_lock {
        false
    } else if let Some((name, version)) = target {
        super::pypi_lock::contains_target(project_root, &additional_locks, name, version).await?
    } else {
        !additional_locks.is_empty()
    };
    if !has_uv_lock && matching_additional_lock {
        if exists("requirements.txt").await {
            present.push("requirements.txt");
        }
        if !present.is_empty() {
            warnings.push(VendorWarning::new(
                "pypi_multiple_lockfiles",
                format!(
                    "wiring {}; installs driven by {} retain their existing sources",
                    additional_locks.join(", "),
                    present.join(", ")
                ),
            ));
        }
        return Ok((PypiFlavor::PythonLocks, warnings));
    }
    if has_uv_lock {
        present.extend(additional_locks.iter().map(String::as_str));
    } else if !additional_locks.is_empty() {
        warnings.push(VendorWarning::new(
            "pypi_unmatched_lockfiles",
            format!(
                "{} do not contain this package version; their sources are unchanged",
                additional_locks.join(", ")
            ),
        ));
    }
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
    if exists("hatch.toml").await
        || has_pyproject_table("tool.hatch")
        || pyproject_text.as_ref().is_some_and(|text| {
            let files = [("pyproject.toml".to_owned(), text.clone())]
                .into_iter()
                .collect();
            crate::utils::hatch::is_hatch(&files)
        })
    {
        return Ok((PypiFlavor::Hatch, warnings));
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
    PythonLocks(super::pypi_lock::PythonLocks),
    Requirements,
    Hatch(super::pypi_hatch::HatchProject),
    Poetry(Box<PoetryProject>),
    Pdm(Box<PdmProject>),
    Pipenv(Box<PipenvProject>),
    /// The lock already routes this package through THIS patch uuid's
    /// vendored wheel: no wiring — verify (or rebuild) the artifact only.
    InSync,
}

/// Which `VendorEntry` meta slot a flavor's wiring produced.
enum MetaSlot {
    Uv(UvMeta),
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
            let Some(file) = entry
                .get("file")
                .or_else(|| entry.get("path"))
                .and_then(serde_json::Value::as_str)
            else {
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
pub async fn vendor_pypi<'a>(
    purl: &str,
    site_packages: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
) -> VendorOutcome {
    vendor_pypi_with_pipenv_version(
        purl,
        site_packages,
        project_root,
        record,
        sources,
        vendored_at,
        dry_run,
        force,
        service,
        &tokio::sync::OnceCell::new(),
        &InstalledSiteListings::default(),
    )
    .await
}

/// The run's listings of the project's virtualenv `site-packages`, keyed by
/// site.
///
/// [`pipenv_stale_install_warning`] judges every patched package against the
/// same venvs, and each judgement re-listed the whole directory (a
/// `.dist-info` scan plus a METADATA read per installed package) to answer
/// one question about one purl. A vendor run never writes into a venv, so
/// one listing per site answers for every package that asks.
///
/// The ONE thing this gives up, deliberately (plan §2.1 row 11): an
/// EXTERNAL installer landing mid-run — `pip install -U`, `pipenv sync` in
/// another terminal — is no longer seen by the packages judged after the
/// first ask for that site, where re-listing per package would have seen
/// it. Only the `(canonicalized name, version)` SET is frozen: which files
/// are stale is still read live, per package, through `verify_file_patch`.
#[derive(Default)]
pub struct InstalledSiteListings(tokio::sync::Mutex<SiteListings>);

/// Each listed site's `(canonicalized name, version)` pairs, in listing
/// order — the shape [`crate::crawlers::python_crawler::PythonCrawler::find_by_purls_listed`]
/// matches against.
type SiteListings = std::collections::HashMap<std::path::PathBuf, Arc<Vec<(String, String)>>>;

impl InstalledSiteListings {
    /// `site`'s installed packages, listed on the first ask of the run.
    async fn of(&self, site: &Path) -> Arc<Vec<(String, String)>> {
        if let Some(listed) = self.0.lock().await.get(site) {
            return Arc::clone(listed);
        }
        // Listed outside the lock: two packages racing here simply list
        // twice and agree, and neither blocks the other's judgement.
        let listed = Arc::new(crate::crawlers::python_crawler::list_dist_info_packages(site).await);
        self.0
            .lock()
            .await
            .insert(site.to_path_buf(), Arc::clone(&listed));
        listed
    }
}

/// Pipenv never reinstalls a release that is already present — measured on
/// 11.10.4, 2018.11.26 and 2026.8.0: `pipenv install`, `install --deploy`
/// and `sync` all exit 0 and keep the installed bytes — so wiring the lock
/// while the upstream release sits in the virtualenv leaves that venv
/// vulnerable until it is reinstalled. Positive evidence only (readable
/// bytes hashing to something other than the record's afterHash); an
/// already-patched (agent-mode) install and a lock-only checkout stay silent.
async fn pipenv_stale_install_warning(
    project_root: &Path,
    purl: &str,
    record: &PatchRecord,
    listings: &InstalledSiteListings,
) -> Option<VendorWarning> {
    use crate::crawlers::python_crawler::{find_local_venv_site_packages, PythonCrawler};
    use crate::patch::apply::{verify_file_patch, VerifyStatus};
    if record.files.is_empty() {
        return None;
    }
    // Judged over the PROJECT'S venvs (VIRTUAL_ENV, ./.venv, ./venv, Pipenv's
    // WORKON_HOME venv) — never the staging dir a lock-only vendor fetched
    // the pristine wheel into, and never the global interpreters.
    // The caller refused an unparseable purl long before this probe, so the
    // lookup below is never the empty one `find_by_purls` short-circuits on.
    let base = strip_purl_qualifiers(purl).to_string();
    let crawler = PythonCrawler::new();
    let mut stale_dirs: Vec<std::path::PathBuf> = Vec::new();
    for site in find_local_venv_site_packages(project_root).await {
        let listed = listings.of(&site).await;
        let found = crawler.find_by_purls_listed(&site, &listed, std::slice::from_ref(&base));
        if !found.contains_key(&base) {
            continue;
        }
        if crate::vex::verify::verify_patch_record(&site, record)
            .await
            .is_ok()
        {
            continue;
        }
        for (file, info) in &record.files {
            let result = verify_file_patch(&site, file, info).await;
            if matches!(
                result.status,
                VerifyStatus::Ready | VerifyStatus::HashMismatch
            ) && result.current_hash.is_some()
            {
                stale_dirs.push(site.clone());
                break;
            }
        }
    }
    if stale_dirs.is_empty() {
        return None;
    }
    let name = parse_pypi_purl(strip_purl_qualifiers(purl))
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| purl.to_string());
    let listed = stale_dirs
        .iter()
        .map(|d| d.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Some(VendorWarning::new(
        "pypi_pipenv_stale_install",
        format!(
            "{purl}: the UNPATCHED upstream release is still installed in {listed}. Pipenv does not reinstall a release that is already present (`pipenv install`, `pipenv install --deploy` and `pipenv sync` all keep those bytes), so the wired Pipfile.lock only protects fresh installs. Reinstall it from the lock without touching the Pipfile: `pipenv run pip uninstall -y {name} && pipenv sync` (`pipenv install --deploy` before Pipenv 2018), or `pipenv --rm && pipenv sync` for a clean virtualenv — NOT `pipenv uninstall`, which rewrites the Pipfile and re-locks the patch away; then `socket-patch vex` re-verifies the installed files."
        ),
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn vendor_pypi_with_pipenv_version<'a>(
    purl: &str,
    site_packages: impl Into<PackageSource<'a>>,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
    service: Option<&VendorServiceConfig>,
    pipenv_version: &tokio::sync::OnceCell<Option<u32>>,
    installed_sites: &InstalledSiteListings,
) -> VendorOutcome {
    let site_packages = site_packages.into();
    // The purl may carry `?artifact_id=` variant qualifiers; everything here
    // keys off the qualifier-free base.
    let base = strip_purl_qualifiers(purl);
    let Some((raw_name, version)) = parse_pypi_purl(base) else {
        return refused(
            "pypi_invalid_purl",
            format!("{purl} is not a pkg:pypi PURL with a version"),
        );
    };
    let (raw_name, version) = (raw_name.as_ref(), version.as_ref());
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

    let (flavor, flavor_warnings) =
        match detect_pypi_flavor(project_root, Some((&canon_name, version))).await {
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
        PypiFlavor::PythonLocks => {
            let project = match super::pypi_lock::load_python_locks(
                project_root,
                &canon_name,
                version,
                &record.uuid,
            )
            .await
            {
                Ok(project) => project,
                Err((code, detail)) => return refused(code, detail),
            };
            if project.in_sync {
                wired_pin = project.pin;
                WiringPlan::InSync
            } else {
                WiringPlan::PythonLocks(project)
            }
        }
        PypiFlavor::Hatch => {
            match super::pypi_hatch::load(project_root, &canon_name, version, &record.uuid).await {
                Ok(project) if project.in_sync => {
                    wired_pin = project.pin;
                    WiringPlan::InSync
                }
                Ok(project) => WiringPlan::Hatch(project),
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
            let installer = *pipenv_version
                .get_or_init(|| crate::utils::pipenv::installed_major(project_root))
                .await;
            if installer.is_some_and(|major| major < 2018) {
                return refused("pypi_pipenv_installer_unsupported", "vendored wheel references require Pipenv 2018 or later; upgrade Pipenv or use hosted mode");
            }
            if installer.is_none() {
                // Fail-open like hosted, but say so: the wiring assumes a
                // 2018+ installer, and a Pipenv 7–11 project would not be
                // able to consume it.
                warnings.push(VendorWarning::new(
                    "pypi_pipenv_installer_unknown",
                    format!(
                        "Pipenv was not found on PATH; the vendored references assume Pipenv 2018 or later (Pipenv 7–11 cannot consume them — use hosted mode there). Set {}=<major> to pin the installer release.",
                        crate::utils::pipenv::MAJOR_OVERRIDE_ENV
                    ),
                ));
            }
            let target = match super::pypi_pipenv::check_target_guards(
                &project,
                &canon_name,
                &record.uuid,
                version,
            ) {
                Ok(target) => target,
                // A refusal carries no warnings: probe nothing for it.
                Err((code, detail)) => return refused(code, detail),
            };
            if target == PipenvTarget::Fresh {
                warnings.extend(project.warnings.iter().cloned());
            }
            // Both a fresh vendor and a re-run over an already-wired lock
            // keep warning while the venv still holds the upstream release.
            if let Some(stale) =
                pipenv_stale_install_warning(project_root, purl, record, installed_sites).await
            {
                warnings.push(stale);
            }
            match target {
                PipenvTarget::InSync => {
                    wired_pin = pipenv_wired_pin(&project.lock, &uuid_dir_rel);
                    WiringPlan::InSync
                }
                PipenvTarget::Fresh => WiringPlan::Pipenv(Box::new(project)),
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
        let artifact_present = if flavor == PypiFlavor::Hatch {
            if let Some((wheel, _)) = &wired_pin {
                project_root.join(wheel).is_file()
            } else {
                false
            }
        } else {
            uuid_dir_has_wheel(&project_root.join(&uuid_dir_rel)).await
        };
        if artifact_present || dry_run {
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
    //
    // The ledger entry anchoring this uuid (read once): the rebuild pin, the
    // Fresh-path reuse anchor, and the PDM partial-relock guard's prior sha.
    let prior: Option<VendorEntry> = reuse::prior_entry(project_root, "pypi", record, None)
        .await
        .ok();
    let expected_pin: Option<(String, String)> = if in_sync {
        prior
            .as_ref()
            .map(|e| (e.artifact.path.clone(), e.artifact.sha256.clone()))
            .or(wired_pin)
    } else {
        None
    };

    // Fresh-path reuse: the wiring dropped the vendored reference (a relock
    // restored the registry unit) but the committed wheel the ledger
    // vouches for is intact — re-wire those exact bytes instead of acquiring
    // anew, so the re-scan pins the first run's sha whichever source is
    // reachable now (no service call, no local build).
    //
    // The probe is read-only and offline, so a dry run runs it too: its
    // preview must agree with the real run, which re-wires without the
    // service, the installed dist or the blobs (and so is never refused by
    // `service` + `--offline`).
    let reused_wheel = if !in_sync {
        fresh_reuse_wheel(
            base,
            project_root,
            &uuid_dir_rel,
            record,
            prior.as_ref(),
            &canon_name,
            version,
        )
        .await
    } else {
        None
    };
    if dry_run {
        if let Some(acquired) = &reused_wheel {
            warnings.push(VendorWarning::new(
                "vendor_artifact_reused",
                format!(
                    "would re-wire the committed wheel {} for {base} (no rebuild, no service \
                     download)",
                    acquired.rel_wheel
                ),
            ));
            return done(
                reuse_preview_result(base, &project_root.join(&acquired.rel_wheel), record),
                None,
                warnings,
            );
        }
    }
    let reused = reused_wheel.is_some();
    if let Some(acquired) = &reused_wheel {
        warnings.push(VendorWarning::new(
            "vendor_artifact_reused",
            format!(
                "re-wired the committed wheel {} for {base} (no rebuild, no service download)",
                acquired.rel_wheel
            ),
        ));
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
    } = match reused_wheel {
        Some(acquired) => acquired,
        None => match acquire_patched_wheel(
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
            Err(outcome) => {
                // A refused/hard-failed acquisition may have scaffolded the
                // empty uuid dir (and the ecosystem / vendor levels on a fresh
                // project) before failing: prune them so the failure leaves no
                // committable husk. Dry runs create nothing.
                if !dry_run {
                    prune_empty_vendor_levels(&project_root.join(&uuid_dir_rel)).await;
                }
                return outcome;
            }
        },
    };
    if !result.success {
        prune_empty_vendor_levels(&project_root.join(&uuid_dir_rel)).await;
        return done(result, None, warnings);
    }
    if dry_run {
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
            PypiFlavor::PythonLocks => {
                "Python lockfiles now resolve it from this single-platform wheel only"
            }
            PypiFlavor::Poetry => {
                "poetry.lock now resolves it from this single-platform wheel only"
            }
            PypiFlavor::Pdm => "pdm.lock now resolves it from this single-platform wheel only",
            PypiFlavor::Pipenv => {
                "Pipfile.lock now resolves it from this single-platform wheel only"
            }
            PypiFlavor::Hatch => "Hatch now installs this single-platform wheel only",
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
                prune_empty_vendor_levels(&project_root.join(&uuid_dir_rel)).await;
                let mut result = result;
                result.success = false;
                // A service outage is the likely cause when the pin came from
                // a prebuilt wheel: waiting for the service fixes it, while a
                // revert + re-vendor would needlessly re-wire the lockfile.
                let service_down = warnings.iter().any(|w| {
                    w.code == "vendor_prebuilt_unavailable" || w.code == "vendor_prebuilt_pending"
                });
                result.error = Some(if service_down {
                    format!(
                        "the patch service was unavailable, and the local rebuild ({rel_wheel}, \
                         sha256 {}) cannot reproduce the prebuilt wheel the lockfile pins \
                         ({pin_path}, sha256 {pin_sha}); re-run vendor once the service is \
                         reachable, or run `socket-patch vendor --revert` for {base} and \
                         re-vendor to pin a local build",
                        artifact.sha256_hex
                    )
                } else {
                    format!(
                        "the rebuilt wheel ({rel_wheel}, sha256 {}) does not match the wheel the \
                         lockfile still pins ({pin_path}, sha256 {pin_sha}); run `socket-patch \
                         vendor --revert` for {base} and re-vendor to re-wire the lockfile",
                        artifact.sha256_hex
                    )
                });
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
        write_marker_or_warn(&project_root.join(&uuid_dir_rel), &marker, &mut warnings).await;
        return done(result, None, warnings);
    }

    // Marker: artifact-side breadcrumb in the uuid dir (informational only —
    // sweep/verify key off state.json + the path uuid, so a failed write is
    // a warning here exactly as in every other backend). Written before the
    // wiring so lockfile edits stay the last mutation.
    let marker = VendorMarker::new("pypi", base, record, vendored_at);
    write_marker_or_warn(&project_root.join(&uuid_dir_rel), &marker, &mut warnings).await;

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
        .map(|(wiring, meta, advisories)| {
            warnings.extend(advisories);
            (wiring, MetaSlot::Uv(meta))
        }),
        WiringPlan::PythonLocks(project) => super::pypi_lock::wire_python_locks(
            &project,
            project_root,
            &canon_name,
            version,
            &rel_wheel,
            &artifact.sha256_hex,
        )
        .await
        .map(|wiring| (wiring, MetaSlot::None)),
        WiringPlan::Hatch(project) => super::pypi_hatch::wire(
            &project,
            project_root,
            &canon_name,
            version,
            &rel_wheel,
            &artifact.sha256_hex,
        )
        .await
        .map(|wiring| (wiring, MetaSlot::None)),
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
        WiringPlan::Pdm(project) => {
            // Every sha this patch's wheel is known by: this run's, and the
            // ledger's (a source flip since the first vendor changes it) —
            // the partial-relock guard must not depend on the source.
            let mut known_patched: Vec<&str> = vec![artifact.sha256_hex.as_str()];
            if let Some(prior) = &prior {
                known_patched.push(prior.artifact.sha256.as_str());
            }
            super::pypi_pdm::wire_pdm(
                &project,
                project_root,
                &canon_name,
                version,
                &rel_wheel,
                &wheel_name,
                &artifact.sha256_hex,
                &record.uuid,
                &known_patched,
            )
            .await
            .map(|(wiring, meta)| (wiring, MetaSlot::Pdm(meta)))
        }
        WiringPlan::Pipenv(project) => super::pypi_pipenv::wire_pipenv(
            &project,
            project_root,
            &canon_name,
            version,
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
            // A REUSED wheel is the committed artifact the live ledger entry
            // still names: never sweep it (nothing was acquired to undo).
            if !reused {
                let _ = tokio::fs::remove_dir_all(project_root.join(&uuid_dir_rel)).await;
                prune_empty_vendor_levels(&project_root.join(&uuid_dir_rel)).await;
            }
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
        MetaSlot::Uv(m) => entry.uv = Some(m),
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
/// Fail-closed twin of [`super::npm_lock::guard_unwired_textual_revert`]
/// for the Python backends. A ledger entry with NO wiring records cannot
/// restore any project file — that is the shape `socket-patch repair`
/// re-synthesizes when state.json is lost (flavor stamped from the lock the
/// reference was found in, wiring not offline-recoverable). Routing such an
/// entry into a flavor revert that iterates zero records "succeeds", after
/// which the caller deletes the uuid dir and drops the entry while uv.lock,
/// the pylock, the script, or requirements.txt still resolve through the
/// vendored wheel — every later `--frozen` / `--offline` install fails.
/// Refuse whenever any Python project file still mentions the uuid dir, or
/// exists but cannot be read to prove it does not — or the project cannot
/// be enumerated to know which files to probe. With no reference left the
/// revert is a plain orphan cleanup and proceeds.
async fn guard_unwired_pypi_revert(
    project_root: &Path,
    uuid: &str,
    uuid_dir_rel: &str,
) -> Option<RevertOutcome> {
    let clause = unwired_pypi_reference_clause(project_root, uuid).await?;
    let detail = format!(
        "refusing to remove {uuid_dir_rel}: the ledger entry records no pre-vendor wiring to \
         replay (it was likely reconstructed by `socket-patch repair`; the pre-vendor Python \
         lock fragments are not offline-recoverable) and {clause} — deleting the artifact \
         would make every subsequent install fail; run `socket-patch repair` to keep the \
         vendored artifact healthy, and revert by restoring the pre-vendor files (or by \
         removing the dependency and re-locking) before re-running `vendor --revert`"
    );
    Some(RevertOutcome {
        success: false,
        warnings: vec![VendorWarning::new(
            "vendor_wiring_unknown_revert_blocked",
            detail.clone(),
        )],
        error: Some(detail),
        kept_artifact: false,
    })
}

/// The in-use probe behind [`guard_unwired_pypi_revert`]: `None` when every
/// Python project file was read and none mentions the uuid dir; otherwise
/// the human clause naming what blocks the revert. The probe list is the
/// statically named project files, the root `requirements.txt` plus every
/// `-r` include the planner may have written a pin into, and every Python
/// lock the root directory LISTS (`uv.lock`, `pylock*.toml`, `*.py.lock`
/// with its paired script). Every step fails closed: a root that cannot be
/// listed, an include tree that cannot be read, or a listed lock (a symlink
/// included — lstat only, so an unreadable target is still probed) that
/// exists but cannot be read all block the revert, because none of them
/// can prove the absence of a reference.
async fn unwired_pypi_reference_clause(project_root: &Path, uuid: &str) -> Option<String> {
    let needle = format!(".socket/vendor/pypi/{uuid}/");
    let mut names: Vec<String> = [
        "pyproject.toml",
        "hatch.toml",
        "uv.lock",
        "pylock.toml",
        "poetry.lock",
        "pdm.lock",
        "Pipfile",
        "Pipfile.lock",
    ]
    .iter()
    .map(|name| (*name).to_string())
    .collect();
    match super::pypi_requirements::requirements_include_names(project_root).await {
        Ok(includes) => names.extend(includes),
        Err(_) => {
            return Some(
                "the requirements.txt include tree could not be read to prove no requirements \
                 file references it"
                    .to_string(),
            )
        }
    }
    // Enumerate the locks ourselves instead of through
    // `python_lock_paths`, which follows symlinks and DROPS every entry
    // whose target cannot be stat'ed — and whose `Err` the previous shape
    // read as "no Python locks here". Neither may fail open here.
    let listing = match std::fs::read_dir(project_root) {
        Ok(listing) => listing,
        Err(_) => {
            return Some(
                "the project directory could not be listed to prove no Python lock references \
                 it"
                .to_string(),
            )
        }
    };
    for entry in listing {
        let Ok(entry) = entry else {
            return Some(
                "the project directory could not be listed to prove no Python lock references \
                 it"
                .to_string(),
            );
        };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !crate::utils::python_lock::is_python_lock_name(&name) {
            continue;
        }
        // lstat only: a regular file or ANY symlink is probed (the read
        // below fails closed on a target that cannot be opened); dirs,
        // FIFOs and sockets under a lock name are not locks. A failed
        // file_type() is probed too.
        if entry
            .file_type()
            .is_ok_and(|ft| !ft.is_file() && !ft.is_symlink())
        {
            continue;
        }
        if let Some(script) = crate::utils::python_lock::script_of_lock(&name) {
            names.push(script.to_string());
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    for name in &names {
        let path = project_root.join(name);
        match read_regular_to_string(&path).await {
            Ok(text) if text.contains(&needle) => {
                return Some(format!("{name} still resolves through it"));
            }
            Ok(_) => {}
            // A file that no longer exists cannot reference it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // Fail-closed: a file we cannot read may still reference it.
            Err(_) => {
                return Some(format!(
                    "{name} exists but could not be read to prove it no longer references it"
                ));
            }
        }
    }
    None
}

/// `VendorEntry::flavor` values the dispatch below knows how to revert —
/// the set an UNWIRED entry must belong to (or be `None`) before it is
/// treated as a reclaimable orphan.
const KNOWN_PYPI_FLAVORS: [&str; 7] = [
    "uv",
    "python-lock",
    "requirements",
    "hatch",
    "poetry",
    "pdm",
    "pipenv",
];

pub async fn revert_pypi_opts(
    entry: &VendorEntry,
    project_root: &Path,
    opts: RevertOpts,
) -> RevertOutcome {
    let RevertOpts {
        dry_run,
        keep_artifact,
    } = opts;
    let mut outcome = if entry.wiring.is_empty() {
        // Nothing to replay (a `repair`-reconstructed entry): no project
        // file can be restored, so the only work left is the artifact
        // deletion below. Under `keep_artifact` (`--preserve-state`) even
        // that is skipped — the revert is a no-op and the in-use guard,
        // which exists only to protect the deletion, has nothing to
        // protect (npm's precedent). Otherwise the artifact may only go
        // when no Python project file provably resolves through it. Once
        // the guard clears, the entry is a plain orphan: the flavor
        // dispatch is skipped on purpose — flavor `uv` with uv.lock gone
        // fails "cannot read uv.lock", and flavor `None` (what `repair`
        // stamps for requirements/poetry/pdm/pipenv reconstructions) is
        // unknown to the dispatch — and either would leave the orphan
        // unreclaimable forever.
        if keep_artifact {
            return RevertOutcome::ok();
        }
        // An UNKNOWN flavor (a newer binary's backend) still fails closed
        // even here: its project files may reference the artifact from a
        // place this guard does not know to probe. `None` is `repair`'s
        // own stamp and every known flavor's files are probed.
        if let Some(flavor) = entry
            .flavor
            .as_deref()
            .filter(|f| !KNOWN_PYPI_FLAVORS.contains(f))
        {
            return RevertOutcome::failed(format!(
                "unknown pypi vendor flavor {:?}; cannot revert",
                Some(flavor)
            ));
        }
        let uuid_dir_rel = vendor_uuid_dir_rel("pypi", &entry.uuid)
            .unwrap_or_else(|| format!(".socket/vendor/pypi/{:?}", entry.uuid));
        if let Some(blocked) =
            guard_unwired_pypi_revert(project_root, &entry.uuid, &uuid_dir_rel).await
        {
            return blocked;
        }
        RevertOutcome::ok()
    } else {
        match entry.flavor.as_deref() {
            Some("uv") => revert_uv(entry, project_root, dry_run).await,
            Some("python-lock") => {
                super::pypi_lock::revert_python_locks(entry, project_root, dry_run).await
            }
            Some("hatch") => super::pypi_hatch::revert(entry, project_root, dry_run).await,
            Some("requirements") => revert_requirements(entry, project_root, dry_run).await,
            Some("poetry") => super::pypi_poetry::revert_poetry(entry, project_root, dry_run).await,
            Some("pdm") => super::pypi_pdm::revert_pdm(entry, project_root, dry_run).await,
            Some("pipenv") => super::pypi_pipenv::revert_pipenv(entry, project_root, dry_run).await,
            other => {
                return RevertOutcome::failed(format!(
                    "unknown pypi vendor flavor {other:?}; cannot revert"
                ))
            }
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
    // Remove the unit (a missing dir is fine), then prune the
    // `.socket/vendor/pypi/` and `.socket/vendor/` husks it leaves when it was
    // the last entry (non-recursive: siblings keep them). A removal failure
    // keeps the warning posture — the wiring restore above already succeeded
    // — and skips the prune (the dir is still there).
    if let Err(e) = remove_tree_and_prune(
        &project_root.join(&uuid_dir_rel),
        &project_root.join(SOCKET_DIR),
    )
    .await
    {
        outcome.warnings.push(VendorWarning::new(
            "vendor_artifact_remove_failed",
            format!("could not remove {uuid_dir_rel}: {e}"),
        ));
    }
    outcome
}

/// The patched wheel plus the facts the wiring + ledger need, however it was
/// acquired (service download or local build).
/// The committed wheel for a Fresh-plan re-run, when the ledger anchors it
/// and it verifies (see [`reuse`]): directly under `uuid_dir_rel`, a
/// well-formed wheel filename for THIS distribution and version (the leaf
/// comes from the committed ledger, and the wirings splice it verbatim into
/// requirements.txt / uv.lock / poetry.lock — see [`reusable_wheel_leaf`]),
/// and not platform-locked by either the ledger flag or the filename's own
/// tags (a platform-specific wheel committed on another OS keeps today's
/// acquire-and-pin behavior). `None` acquires as usual.
async fn fresh_reuse_wheel(
    base: &str,
    project_root: &Path,
    uuid_dir_rel: &str,
    record: &PatchRecord,
    prior: Option<&VendorEntry>,
    canon_name: &str,
    version: &str,
) -> Option<AcquiredWheel> {
    let prior = prior?;
    let rel = prior.artifact.path.replace('\\', "/");
    let leaf = match rel
        .strip_prefix(uuid_dir_rel)
        .and_then(|rest| rest.strip_prefix('/'))
        .filter(|leaf| reusable_wheel_leaf(leaf, canon_name, version))
    {
        Some(leaf) => leaf.to_string(),
        None => {
            reuse::log_miss(base, &reuse::ReuseMiss::PathUnsafe);
            return None;
        }
    };
    let (locked, platform_tags_display) = wheel_platform_from_filename(&leaf);
    if locked || prior.artifact.platform_locked == Some(true) {
        reuse::log_miss(base, &reuse::ReuseMiss::PlatformLocked);
        return None;
    }
    let art = match reuse::verify_committed_artifact(project_root, prior, record).await {
        Ok(art) => art,
        Err(miss) => {
            reuse::log_miss(base, &miss);
            return None;
        }
    };
    let abs = project_root.join(&art.rel_path);
    Some(AcquiredWheel {
        rel_wheel: art.rel_path.clone(),
        result: already_patched_result(base, &abs, &record.files),
        artifact: Some(WheelArtifact {
            file_name: leaf.clone(),
            sha256_hex: art.entry.artifact.sha256.to_ascii_lowercase(),
            size: art.bytes.len() as u64,
        }),
        platform_tags_display,
        wheel_name: leaf,
        platform_locked: false,
    })
}

/// A ledger-supplied wheel leaf is reusable only as a well-formed PEP 427
/// filename (`name-version(-build)?-py-abi-plat.whl`) in the wheel-filename
/// charset — no whitespace, control, `#`, `;` or `/`, which a wiring would
/// splice verbatim into a requirements line or lock path — whose name is
/// THIS distribution (PEP 503-normalized) and whose version is THIS version
/// (as [`escape_wheel_version`] spells it, ASCII case-insensitively).
fn reusable_wheel_leaf(leaf: &str, canon_name: &str, version: &str) -> bool {
    let Some(stem) = leaf.strip_suffix(".whl") else {
        return false;
    };
    if !stem
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'!' | b'-'))
    {
        return false;
    }
    let parts: Vec<&str> = stem.split('-').collect();
    if !(parts.len() == 5 || parts.len() == 6) || parts.iter().any(|p| p.is_empty()) {
        return false;
    }
    canonicalize_pypi_name(parts[0]) == canonicalize_pypi_name(canon_name)
        && parts[1].eq_ignore_ascii_case(&escape_wheel_version(version))
}

/// The dry-run preview of a Fresh-path reuse: the shape a dry-run local
/// build reports (every patched file verified, ready to wire) — the CLI
/// renders it as a verified preview, as it would the build.
fn reuse_preview_result(base: &str, abs: &Path, record: &PatchRecord) -> ApplyResult {
    let files_verified = record
        .files
        .keys()
        .map(|f| crate::patch::apply::VerifyResult {
            file: f.clone(),
            status: crate::patch::apply::VerifyStatus::Ready,
            message: None,
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        })
        .collect();
    super::common::synthesized_result(base, abs, files_verified, true, None)
}

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
    site_packages: PackageSource<'_>,
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

    // Local build from the installed dist — the first branch that reads the
    // site-packages tree, so a lazily-fetched wheel is extracted here.
    let site_packages = match site_packages.materialize().await {
        Ok(dir) => dir,
        Err(e) => {
            return Err(refused(
                "pypi_dist_not_found",
                format!("cannot stage a copy of the installed distribution: {e}"),
            ))
        }
    };
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
            // The SRI proves only that the transfer is intact. A wheel's
            // members are site-packages-relative (the `record.files` keys),
            // so require each patched file to carry its afterHash before
            // reporting the package patched and pinning the lockfile to it.
            if !zip_bytes_match_after_hashes(&archive.bytes, &record.files) {
                return miss(
                    warnings,
                    "vendor_prebuilt_layout_mismatch",
                    format!(
                        "prebuilt wheel for {base} does not carry the patched files at \
                         their recorded paths"
                    ),
                );
            }
            let rel_wheel = format!("{uuid_dir_rel}/{wheel_name}");
            // Digested on first ask: pypi is the only backend that pins it.
            let sha256_hex = archive.sha256_hex().to_string();
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
            if let Err(e) = atomic_write_artifact(&dest, &archive.bytes).await {
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
        // Bytes that fail integrity verification are an active tamper signal:
        // ALWAYS a hard error, in `auto` exactly as in `service` — never a
        // quiet local-build fallback (`ServiceArtifact`'s documented contract).
        ServiceArtifact::IntegrityMismatch(reason) => hard_fail(
            "vendor_prebuilt_integrity_mismatch",
            format!(
                "prebuilt wheel failed integrity verification ({reason}); \
                 refusing to fall back to a local build on tampered bytes"
            ),
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
            async move { detect_pypi_flavor(&tmp, None).await.map(|(f, _)| f) }
        };

        // 1. uv.lock wins outright (even over requirements + other markers).
        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "uv.lock", "version = 1\n").await;
        touch(tmp.path(), "requirements.txt", "six==1.16.0\n").await;
        assert_eq!(flavor(tmp.path()).await.unwrap(), PypiFlavor::UvProject);
        touch(tmp.path(), "pylock.toml", "lock-version = \"1.0\"\n").await;
        let (selected, warnings) = detect_pypi_flavor(tmp.path(), None).await.unwrap();
        assert_eq!(selected, PypiFlavor::UvProject);
        assert!(warnings
            .iter()
            .any(|warning| warning.code == "pypi_multiple_lockfiles"
                && warning.detail.contains("pylock.toml")));

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
        let (f, warnings) = detect_pypi_flavor(tmp.path(), None).await.unwrap();
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
        let err = detect_pypi_flavor(tmp.path(), None).await.unwrap_err();
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
        let err = detect_pypi_flavor(tmp.path(), None).await.unwrap_err();
        assert_eq!(err.0, "pypi_poetry_no_lockfile");
        assert!(err.1.contains("poetry lock"));

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "pyproject.toml", "[tool.pdm]\n").await;
        assert_eq!(
            detect_pypi_flavor(tmp.path(), None).await.unwrap_err().0,
            "pypi_pdm_no_lockfile"
        );

        let tmp = tempfile::tempdir().unwrap();
        touch(tmp.path(), "Pipfile", "").await;
        assert_eq!(
            detect_pypi_flavor(tmp.path(), None).await.unwrap_err().0,
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
            detect_pypi_flavor(tmp.path(), None).await.unwrap_err().0,
            "pypi_pyproject_only"
        );

        // 8. nothing at all.
        let tmp = tempfile::tempdir().unwrap();
        let err = detect_pypi_flavor(tmp.path(), None).await.unwrap_err();
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
        let Ok(routed) = tokio::time::timeout(deadline, detect_pypi_flavor(tmp.path(), None)).await
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

    fn metadata_wheel(metadata: &str) -> Vec<u8> {
        super::super::common::write_zip_entries(&[(
            "widget-1.0.dist-info/METADATA".to_string(),
            metadata.as_bytes().to_vec(),
            0o644,
        )])
        .unwrap()
    }

    #[test]
    fn hosted_wheel_metadata_verifies_hash_and_preserves_dependencies() {
        let bytes = metadata_wheel("Metadata-Version: 2.1\nName: widget\nVersion: 1.0\nRequires-Dist: requests[socks]>=2; python_version >= '3.9'\nProvides-Extra: secure\n\nBody\n");
        let sha = hex::encode(Sha256::digest(&bytes));
        let block = decode_hosted_wheel_metadata(&bytes, &sha).unwrap().unwrap();
        let document: toml_edit::DocumentMut = block.parse().unwrap();
        assert_eq!(
            document["package"]["metadata"]["requires-dist"][0]["name"].as_str(),
            Some("requests")
        );
        assert_eq!(
            document["package"]["metadata"]["requires-dist"][0]["specifier"].as_str(),
            Some(">=2")
        );
        assert_eq!(
            document["package"]["metadata"]["requires-dist"][0]["extras"][0].as_str(),
            Some("socks")
        );
        assert_eq!(
            document["package"]["metadata"]["provides-extras"][0].as_str(),
            Some("secure")
        );
        assert!(decode_hosted_wheel_metadata(&bytes, &"0".repeat(64))
            .unwrap_err()
            .contains("does not match"));
        assert!(decode_hosted_wheel_metadata(&bytes, "short")
            .unwrap_err()
            .contains("64 hexadecimal"));
    }

    #[test]
    fn hosted_wheel_metadata_distinguishes_no_dependencies_from_invalid_wheels() {
        let bytes = metadata_wheel("Metadata-Version: 2.1\nName: widget\nVersion: 1.0\n\nRequires-Dist: description-only\n");
        assert!(
            decode_hosted_wheel_metadata(&bytes, &hex::encode(Sha256::digest(&bytes)))
                .unwrap()
                .is_none()
        );
        for bytes in [b"not a zip".to_vec(), metadata_wheel("not metadata"), metadata_wheel("Metadata-Version: 2.1\nName: widget\nVersion: 1.0\nRequires-Dist: other @ https://example.test/other.whl\n")] {
            let sha = hex::encode(Sha256::digest(&bytes));
            assert!(decode_hosted_wheel_metadata(&bytes, &sha).is_err());
        }
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

    /// A wheel zip whose `six.py` member is `six_py`, plus a `tag` member so
    /// callers can make the bytes differ from any other wheel.
    fn wheel_with(six_py: &[u8], tag: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        zip.start_file("six.py", opts).unwrap();
        zip.write_all(six_py).unwrap();
        zip.start_file("socket-test-tag.txt", opts).unwrap();
        zip.write_all(tag).unwrap();
        zip.finish().unwrap().into_inner()
    }

    /// A served wheel that carries the patched `six.py`.
    fn served_wheel(tag: &[u8]) -> Vec<u8> {
        wheel_with(PATCHED, tag)
    }

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
            client: Some(
                ApiClient::new(ApiClientOptions {
                    api_url: server_uri.to_string(),
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
        let bytes: &[u8] = &served_wheel(b"prebuilt wheel bytes from the service");
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

    /// A served wheel with an intact SRI whose `six.py` is still the ORIGINAL
    /// bytes is not the patched package: `service` refuses and writes no
    /// wheel; `auto` warns and builds locally (which carries the patch).
    #[tokio::test]
    async fn service_wheel_failing_after_hashes_is_rejected() {
        for source in [VendorSource::Service, VendorSource::Auto] {
            let fx = e2e_fixture().await;
            let sources = PatchSources::blobs_only(&fx.blobs);
            let bytes = wheel_with(ORIG, b"unpatched");
            let server = wiremock::MockServer::start().await;
            mount_pypi_granted(&server, WHEEL_NAME, &sri_sha512(&bytes), &bytes).await;
            let outcome = vendor_pypi(
                "pkg:pypi/six@1.16.0",
                &fx.site_packages,
                &fx.root,
                &fx.record,
                &sources,
                "2026-06-09T00:00:00Z",
                false,
                false,
                Some(&pypi_service_cfg(&server.uri(), source, false)),
            )
            .await;
            let wheel = fx
                .root
                .join(format!(".socket/vendor/pypi/{UUID}/{WHEEL_NAME}"));
            match source {
                VendorSource::Service => {
                    let VendorOutcome::Refused { code, .. } = &outcome else {
                        panic!("service must refuse an unpatched wheel, got {outcome:?}");
                    };
                    assert_eq!(*code, "vendor_prebuilt_required");
                    assert!(!wheel.exists(), "no unpatched wheel written");
                }
                _ => {
                    let VendorOutcome::Done {
                        result, warnings, ..
                    } = &outcome
                    else {
                        panic!("auto must fall back, got {outcome:?}");
                    };
                    assert!(result.success, "{:?}", result.error);
                    assert!(
                        warnings
                            .iter()
                            .any(|w| w.code == "vendor_prebuilt_layout_mismatch"),
                        "{warnings:?}"
                    );
                    assert!(
                        !warnings
                            .iter()
                            .any(|w| w.code == "vendor_prebuilt_downloaded"),
                        "{warnings:?}"
                    );
                    let on_disk = tokio::fs::read(&wheel).await.unwrap();
                    assert_ne!(on_disk, bytes, "the served wheel was not used");
                }
            }
        }
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
        let bytes: &[u8] =
            &served_wheel(b"service-built wheel bytes that differ from the local build");
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

        let bytes: &[u8] =
            &served_wheel(b"service-built wheel bytes that differ from the local build");
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
        let bytes: &[u8] = &served_wheel(b"prebuilt wheel bytes from the service");
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

        let bytes: &[u8] =
            &served_wheel(b"service-built wheel bytes that differ from the local build");
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
        let bytes: &[u8] = &served_wheel(b"prebuilt wheel bytes from the service");
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

    /// A ledger entry with NO wiring (the shape `socket-patch repair`
    /// re-synthesizes when state.json is lost) cannot restore any file.
    /// Routing it into a flavor revert that iterates zero records used to
    /// "succeed", after which the caller deleted the uuid dir and dropped
    /// the entry while the lock still resolved through the vendored wheel.
    /// Both Python-lock backends must refuse while anything references it.
    #[tokio::test]
    async fn unwired_python_entry_revert_refuses_while_lock_references_artifact() {
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
            (
                "uv",
                vec![
                    (
                        "pyproject.toml",
                        format!("[project]\nname = \"p\"\ndependencies = [\"six==1.16.0\"]\n\n[tool.uv.sources]\nsix = {{ path = \"{rel_wheel}\" }}\n"),
                    ),
                    (
                        "uv.lock",
                        format!("version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{ path = \"{rel_wheel}\" }}\n"),
                    ),
                ],
            ),
            (
                "python-lock",
                vec![(
                    "pylock.toml",
                    format!("lock-version = \"1.0\"\n\n[[packages]]\nname = \"six\"\nversion = \"1.16.0\"\narchive = {{ path = \"{rel_wheel}\" }}\n"),
                )],
            ),
            (
                "python-lock",
                vec![
                    ("tool.py.lock", "version = 1\n".to_string()),
                    (
                        "tool.py",
                        format!("# /// script\n# dependencies = [\"six==1.16.0\"]\n# [tool.uv.sources]\n# six = {{ path = \"{rel_wheel}\" }}\n# ///\n"),
                    ),
                ],
            ),
        ];
        for (flavor, files) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            for (name, text) in &files {
                tokio::fs::write(root.join(name), text).await.unwrap();
            }
            let wheel = root.join(&rel_wheel);
            tokio::fs::create_dir_all(wheel.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
            let entry = revert_entry(flavor, &rel_wheel, Vec::new());
            for dry_run in [true, false] {
                let outcome = revert_pypi(&entry, root, dry_run).await;
                assert!(
                    !outcome.success,
                    "{flavor} dry_run={dry_run}: unwired revert must refuse: {outcome:?}"
                );
                assert_eq!(
                    outcome.warnings.len(),
                    1,
                    "{flavor}: {:?}",
                    outcome.warnings
                );
                assert_eq!(
                    outcome.warnings[0].code,
                    "vendor_wiring_unknown_revert_blocked"
                );
                assert!(!outcome.kept_artifact);
            }
            assert!(
                wheel.is_file(),
                "{flavor}: the referenced artifact must survive"
            );
            for (name, text) in &files {
                assert_eq!(
                    &tokio::fs::read_to_string(root.join(name)).await.unwrap(),
                    text,
                    "{flavor}: {name} must be untouched"
                );
            }
        }
    }

    /// Nothing references the artifact any more (the user re-locked by
    /// hand): an unwired entry's revert is a plain orphan cleanup and may
    /// proceed — the guard is about live references, not about wiring.
    #[tokio::test]
    async fn unwired_python_entry_revert_proceeds_when_nothing_references_artifact() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"p\"\ndependencies = [\"six==1.16.0\"]\n",
        )
        .await
        .unwrap();
        tokio::fs::write(
            root.join("uv.lock"),
            "version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
        )
        .await
        .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let wheel = root.join(&rel_wheel);
        tokio::fs::create_dir_all(wheel.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        let entry = revert_entry("uv", &rel_wheel, Vec::new());
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!wheel.exists(), "the orphaned artifact dir is removed");
    }

    /// An unwired entry with a wheel still referenced by the project files.
    /// Returns the wheel path (so the caller can assert survival/removal).
    async fn unwired_uv_fixture(root: &Path, rel_wheel: &str) -> PathBuf {
        tokio::fs::write(
            root.join("pyproject.toml"),
            format!("[project]\nname = \"p\"\ndependencies = [\"six==1.16.0\"]\n\n[tool.uv.sources]\nsix = {{ path = \"{rel_wheel}\" }}\n"),
        )
        .await
        .unwrap();
        tokio::fs::write(
            root.join("uv.lock"),
            format!("version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{ path = \"{rel_wheel}\" }}\n"),
        )
        .await
        .unwrap();
        let wheel = root.join(rel_wheel);
        tokio::fs::create_dir_all(wheel.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        wheel
    }

    /// `rollback/remove --preserve-state` (`keep_artifact`) never deletes the
    /// artifact, and an unwired entry has nothing to restore — so there is
    /// nothing for the in-use guard to protect. It used to refuse with
    /// `vendor_wiring_unknown_revert_blocked` although the revert would
    /// have touched nothing (npm skips the guard under `keep_artifact` for
    /// exactly this reason: the refusal exists only to protect the deletion).
    #[tokio::test]
    async fn unwired_entry_preserve_state_skips_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let wheel = unwired_uv_fixture(root, &rel_wheel).await;
        let entry = revert_entry("uv", &rel_wheel, Vec::new());
        for dry_run in [true, false] {
            let outcome = revert_pypi_opts(
                &entry,
                root,
                RevertOpts {
                    dry_run,
                    keep_artifact: true,
                },
            )
            .await;
            assert!(
                outcome.success,
                "dry_run={dry_run}: preserve-state revert of an unwired entry must succeed: \
                 {outcome:?}"
            );
            assert!(
                outcome.warnings.is_empty(),
                "dry_run={dry_run}: no refusal warning: {:?}",
                outcome.warnings
            );
            assert!(!outcome.kept_artifact, "keep_artifact is not a drift-keep");
            assert!(wheel.is_file(), "dry_run={dry_run}: the wheel is kept");
        }
    }

    /// Restores a directory mode on drop so a failing assertion never leaves
    /// an unlistable/unreadable tempdir behind for `TempDir` to choke on.
    #[cfg(unix)]
    struct ModeGuard(PathBuf);
    #[cfg(unix)]
    impl Drop for ModeGuard {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755));
        }
    }

    /// The guard used to treat a `read_dir` failure on the project root as
    /// "no Python locks here" (and its static list lacked uv.lock and
    /// pylock.toml), so on an execute-only root nothing was probed and the
    /// referenced wheel was deleted while uv.lock / pylock.toml still
    /// resolved through it. An unlistable root cannot prove the absence of
    /// a reference: refuse, fail-closed.
    #[cfg(unix)]
    #[tokio::test]
    async fn unwired_python_entry_revert_refuses_when_root_unlistable() {
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, directory perms are not enforced");
            return;
        }
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        // Only the LOCK references the wheel (pyproject.toml was already
        // hand-restored): the reference is reachable through the listing
        // alone, not through a statically named project file.
        let cases: Vec<(&str, Vec<(&str, String)>)> = vec![
            (
                "uv",
                vec![
                    (
                        "pyproject.toml",
                        "[project]\nname = \"p\"\ndependencies = [\"six==1.16.0\"]\n".to_string(),
                    ),
                    (
                        "uv.lock",
                        format!("version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{ path = \"{rel_wheel}\" }}\n"),
                    ),
                ],
            ),
            (
                "python-lock",
                vec![(
                    "pylock.toml",
                    format!("lock-version = \"1.0\"\n\n[[packages]]\nname = \"six\"\nversion = \"1.16.0\"\narchive = {{ path = \"{rel_wheel}\" }}\n"),
                )],
            ),
        ];
        for (flavor, files) in cases {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            for (name, text) in &files {
                tokio::fs::write(root.join(name), text).await.unwrap();
            }
            let wheel = root.join(&rel_wheel);
            tokio::fs::create_dir_all(wheel.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
            let entry = revert_entry(flavor, &rel_wheel, Vec::new());
            // Execute-only: paths under the root still resolve (the wheel
            // and every known lock name), only the listing is denied.
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o311)).unwrap();
            let _restore = ModeGuard(root.to_path_buf());
            assert!(
                std::fs::read_dir(root).is_err(),
                "0o311 must make the root unlistable on this host"
            );
            let outcome = revert_pypi(&entry, root, false).await;
            assert!(
                !outcome.success,
                "{flavor}: revert under an unlistable root must refuse: {outcome:?}"
            );
            assert_eq!(
                outcome.warnings.len(),
                1,
                "{flavor}: {:?}",
                outcome.warnings
            );
            assert_eq!(
                outcome.warnings[0].code,
                "vendor_wiring_unknown_revert_blocked"
            );
            assert!(
                outcome.warnings[0].detail.contains("could not be listed"),
                "{flavor}: {}",
                outcome.warnings[0].detail
            );
            assert!(!outcome.kept_artifact);
            assert!(
                wheel.is_file(),
                "{flavor}: the referenced artifact must survive"
            );
        }
    }

    /// A lock that is a SYMLINK whose target cannot be stat'ed used to be
    /// dropped from the probe list (the lister follows the link and drops
    /// any entry whose metadata fails), so the guard never saw it and the
    /// wheel it may reference was deleted. Listing must keep symlinks on
    /// lstat alone; the unreadable target then hits the fail-closed read.
    /// Both a static-list name and a listing-only name are covered.
    #[cfg(unix)]
    #[tokio::test]
    async fn unwired_python_entry_revert_refuses_when_lock_target_unstatable() {
        use std::os::unix::fs::PermissionsExt as _;
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, directory perms are not enforced");
            return;
        }
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        for lock_name in ["pylock.toml", "pylock.dev.toml"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let locked = root.join("locked");
            tokio::fs::create_dir(&locked).await.unwrap();
            tokio::fs::write(
                locked.join(lock_name),
                format!("lock-version = \"1.0\"\n\n[[packages]]\nname = \"six\"\nversion = \"1.16.0\"\narchive = {{ path = \"{rel_wheel}\" }}\n"),
            )
            .await
            .unwrap();
            tokio::fs::symlink(format!("locked/{lock_name}"), root.join(lock_name))
                .await
                .unwrap();
            let wheel = root.join(&rel_wheel);
            tokio::fs::create_dir_all(wheel.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
            let entry = revert_entry("python-lock", &rel_wheel, Vec::new());
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            let _restore = ModeGuard(locked.clone());
            assert!(
                std::fs::metadata(root.join(lock_name)).is_err(),
                "{lock_name}: the link target must be unstatable on this host"
            );
            let outcome = revert_pypi(&entry, root, false).await;
            assert!(
                !outcome.success,
                "{lock_name}: revert with an unreadable lock target must refuse: {outcome:?}"
            );
            assert_eq!(
                outcome.warnings.len(),
                1,
                "{lock_name}: {:?}",
                outcome.warnings
            );
            assert_eq!(
                outcome.warnings[0].code,
                "vendor_wiring_unknown_revert_blocked"
            );
            assert!(
                outcome.warnings[0]
                    .detail
                    .contains(&format!("{lock_name} exists but could not be read")),
                "{lock_name}: {}",
                outcome.warnings[0].detail
            );
            assert!(
                wheel.is_file(),
                "{lock_name}: the referenced artifact must survive"
            );
        }
    }

    /// Once the guard finds no reference, an unwired entry is a plain
    /// orphan and must be reclaimable. Dispatching it by flavor used to
    /// fail forever: flavor `uv` with uv.lock gone → "cannot read uv.lock".
    #[tokio::test]
    async fn unwired_uv_entry_without_uv_lock_reclaims_orphan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"p\"\ndependencies = [\"six==1.16.0\"]\n",
        )
        .await
        .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let wheel = root.join(&rel_wheel);
        tokio::fs::create_dir_all(wheel.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        let entry = revert_entry("uv", &rel_wheel, Vec::new());
        let dry = revert_pypi(&entry, root, true).await;
        assert!(dry.success, "dry run previews the orphan cleanup: {dry:?}");
        assert!(wheel.is_file(), "dry run deletes nothing");
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!outcome.kept_artifact);
        assert!(
            !root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
            "the orphaned artifact dir is removed"
        );
    }

    /// Same reclaim contract for flavor `None` — the shape `repair` stamps
    /// for requirements/poetry/pdm/pipenv reconstructions, which the
    /// dispatch used to reject with "unknown pypi vendor flavor None".
    #[tokio::test]
    async fn unwired_entry_flavor_none_reclaims_orphan() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("requirements.txt"), "six==1.16.0\n")
            .await
            .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let wheel = root.join(&rel_wheel);
        tokio::fs::create_dir_all(wheel.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        let mut entry = revert_entry("uv", &rel_wheel, Vec::new());
        entry.flavor = None;
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(!outcome.kept_artifact);
        assert!(
            !root.join(format!(".socket/vendor/pypi/{UUID}")).exists(),
            "the orphaned artifact dir is removed"
        );
        // An UNKNOWN flavor fails closed whether wired or not: a newer
        // backend's project files may reference the artifact from a place
        // this guard does not probe.
        let mut unknown = revert_entry("uv", &rel_wheel, Vec::new());
        unknown.flavor = Some("frobnicate".into());
        let outcome = revert_pypi(&unknown, root, false).await;
        assert!(!outcome.success, "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("unknown pypi vendor flavor")),
            "{outcome:?}"
        );
        let mut wired = revert_entry("uv", &rel_wheel, Vec::new());
        wired.flavor = Some("frobnicate".into());
        wired.wiring.push(WiringRecord {
            file: "requirements.txt".into(),
            kind: "requirements_line".into(),
            action: WiringAction::Added,
            key: None,
            original: None,
            new: None,
        });
        let outcome = revert_pypi(&wired, root, false).await;
        assert!(!outcome.success, "{outcome:?}");
        assert!(
            outcome
                .error
                .as_deref()
                .is_some_and(|e| e.contains("unknown pypi vendor flavor")),
            "{outcome:?}"
        );
    }

    /// The requirements planner writes vendored pins into `-r` includes, so
    /// a reference may live ONLY in an include. The guard used to probe the
    /// root requirements.txt alone and let the include-referenced wheel go.
    #[tokio::test]
    async fn unwired_requirements_entry_refuses_on_include_reference() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::write(root.join("requirements.txt"), "-r requirements/base.txt\n")
            .await
            .unwrap();
        tokio::fs::create_dir(root.join("requirements"))
            .await
            .unwrap();
        let include = format!(
            "./{rel_wheel} --hash=sha256:{}  # socket-patch vendor: six==1.16.0\n",
            "0".repeat(64)
        );
        tokio::fs::write(root.join("requirements/base.txt"), &include)
            .await
            .unwrap();
        let wheel = root.join(&rel_wheel);
        tokio::fs::create_dir_all(wheel.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        let entry = revert_entry("requirements", &rel_wheel, Vec::new());
        for dry_run in [true, false] {
            let outcome = revert_pypi(&entry, root, dry_run).await;
            assert!(
                !outcome.success,
                "dry_run={dry_run}: include-referenced revert must refuse: {outcome:?}"
            );
            assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
            assert_eq!(
                outcome.warnings[0].code,
                "vendor_wiring_unknown_revert_blocked"
            );
            assert!(
                outcome.warnings[0]
                    .detail
                    .contains("requirements/base.txt still resolves through it"),
                "{}",
                outcome.warnings[0].detail
            );
        }
        assert!(wheel.is_file(), "the include-referenced wheel must survive");
        assert_eq!(
            tokio::fs::read_to_string(root.join("requirements/base.txt"))
                .await
                .unwrap(),
            include,
            "the include is untouched"
        );
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

    /// A relock regenerated the wired entry to a registry reference whose
    /// hash list differs from the recorded original (Pipenv 2022.12.19 does
    /// exactly this; 2026 reproduces the original and converges silently):
    /// the vendored reference is gone, so the revert must RETIRE the record
    /// — success, no drift-keep, artifact removed — instead of keeping the
    /// uuid dir and ledger entry forever for a reference nothing points at.
    /// A live entry that still carries a foreign `file` reference is drift.
    #[tokio::test]
    async fn pipenv_relocked_registry_entry_retires_instead_of_keeping() {
        use crate::vendor::pypi_pipenv::{load_pipenv_project, wire_pipenv};
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(root.join("Pipfile.lock"), PIPENV_REGISTRY_LOCK)
            .await
            .unwrap();
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/six-1.16.0-py2.py3-none-any.whl");
        let p = load_pipenv_project(root).await.unwrap();
        let (wiring, _meta) =
            wire_pipenv(&p, root, "six", "1.16.0", &rel_wheel, &"0".repeat(64), UUID)
                .await
                .unwrap();
        let uuid_dir = root.join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        let wheel = uuid_dir.join("six-1.16.0-py2.py3-none-any.whl");
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();

        // Simulate the relock: registry shape again, but a DIFFERENT hash
        // list than the recorded original.
        let text = tokio::fs::read_to_string(root.join("Pipfile.lock"))
            .await
            .unwrap();
        let mut live: serde_json::Value = serde_json::from_str(&text).unwrap();
        live["default"]["six"] = serde_json::json!({
            "hashes": ["sha256:relocked-a", "sha256:relocked-b"],
            "index": "pypi",
            "version": "==1.16.0"
        });
        let relocked = serde_json::to_string_pretty(&live).unwrap();
        tokio::fs::write(root.join("Pipfile.lock"), &relocked)
            .await
            .unwrap();

        let entry = revert_entry("pipenv", &rel_wheel, wiring.clone());
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_relocked"),
            "{:?}",
            outcome.warnings
        );
        assert!(
            !outcome.drift_skipped() && !outcome.kept_artifact,
            "a relocked entry is not drift: {:?}",
            outcome.warnings
        );
        assert!(!wheel.exists(), "the orphaned vendored wheel is removed");
        assert_eq!(
            tokio::fs::read_to_string(root.join("Pipfile.lock"))
                .await
                .unwrap(),
            relocked,
            "the user's relocked entry stands"
        );

        // Pipenv 2023+ relocking an excluded-by-marker entry keeps OUR
        // reference but restores the registry hashes/version next to it:
        // still ours → the original is restored and the record retires.
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        let (wiring2, _meta2) = wire_pipenv(
            &load_pipenv_project(root)
                .await
                .unwrap_or_else(|e| panic!("{e:?}")),
            root,
            "six",
            "1.16.0",
            &rel_wheel,
            &"0".repeat(64),
            UUID,
        )
        .await
        .unwrap_or_else(|_| panic!("rewire"));
        let text = tokio::fs::read_to_string(root.join("Pipfile.lock"))
            .await
            .unwrap();
        let mut hybrid: serde_json::Value = serde_json::from_str(&text).unwrap();
        hybrid["default"]["six"]["hashes"] = serde_json::json!(["sha256:upstream-a"]);
        hybrid["default"]["six"]["version"] = serde_json::json!("==1.16.0");
        tokio::fs::write(
            root.join("Pipfile.lock"),
            serde_json::to_string_pretty(&hybrid).unwrap(),
        )
        .await
        .unwrap();
        let entry = revert_entry("pipenv", &rel_wheel, wiring2);
        let outcome = revert_pypi(&entry, root, false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome.drift_skipped() && !outcome.kept_artifact,
            "{:?}",
            outcome.warnings
        );
        let restored: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(root.join("Pipfile.lock"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            restored["default"]["six"].get("file").is_none(),
            "{restored}"
        );
        assert_eq!(
            restored["default"]["six"]["version"],
            serde_json::json!("==1.16.0")
        );

        // Foreign file reference → still drift, still kept.
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(&wheel, b"wheel bytes").await.unwrap();
        live["default"]["six"] = serde_json::json!({"file": "./forks/six.whl"});
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
            outcome.drift_skipped() && outcome.kept_artifact,
            "{:?}",
            outcome.warnings
        );
        assert!(wheel.is_file());
    }

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
        let (wiring, _meta) =
            wire_pipenv(&p, root, "six", "1.16.0", &rel_wheel, &"0".repeat(64), UUID)
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
        let (wiring, _meta) =
            wire_pipenv(&p, root, "six", "1.16.0", &rel_wheel, &"0".repeat(64), UUID)
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
            splice_lock_wired_pin(
                &poetry,
                ".socket/vendor/pypi/00000000-0000-4000-8000-000000000000"
            ),
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
        assert_eq!(pipenv_wired_pin(&lock, &dir_rel), Some((rel_wheel, sha)));
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
            !warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
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

    /// Fresh path: the marker is advisory on a first vendor too (parity with
    /// every other backend) — a failed write is a `vendor_marker_write_failed`
    /// warning riding an otherwise successful run: the wheel stays, the
    /// wiring lands (the marker is written BEFORE the wiring, and its failure
    /// no longer short-circuits that), and the ledger entry is emitted.
    #[tokio::test]
    async fn fresh_marker_write_failure_warns_but_vendor_succeeds() {
        let fx = e2e_fixture().await;
        plant_marker_blocker(&fx).await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("expected Done, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("a fully-wired vendor still emits its entry");
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
            "the failed marker write is surfaced: {warnings:?}"
        );
        assert!(
            fx.root.join(&entry.artifact.path).is_file(),
            "the wheel is kept at the recorded path"
        );
        let wired = read_requirements(&fx).await;
        assert_ne!(wired, "six==1.16.0\n", "the wiring still lands");
        assert!(wired.contains(".socket/vendor/pypi/"), "{wired}");
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
            warnings
                .iter()
                .any(|w| w.code == "vendor_marker_write_failed"),
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
        let bytes: &[u8] = &served_wheel(b"prebuilt wheel bytes from the service");
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
        let bytes: &[u8] = &served_wheel(b"prebuilt wheel bytes from the service");
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
        // The refusal prunes only EMPTY levels this run may have created:
        // the pre-existing, non-empty uuid dir is never collateral (nothing
        // references it, and `remove_dir` refuses a non-empty dir).
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

    // ───────── splice-flavor orchestrator arms + wired-pin edge shapes ─────────

    /// The pipenv wired-pin reader skips (rather than trips over) malformed
    /// lock shapes: a non-object category section, a file ref outside OUR
    /// uuid dir, a hashes array with no `sha256:` entry, and a truncated
    /// sha256 all yield no pin — the rebuild guard then stays off rather
    /// than guessing — and none of them may mask a valid pin elsewhere.
    #[test]
    fn pipenv_wired_pin_skips_malformed_sections_and_entries() {
        let dir_rel = format!(".socket/vendor/pypi/{UUID}");
        let rel_wheel = format!("{dir_rel}/six-1.16.0-py2.py3-none-any.whl");
        let all_bad = serde_json::json!({
            "_meta": {"hash": {"sha256": "x"}},
            // A top-level value that is not an object is skipped whole.
            "pipfile-spec": 6,
            "default": {
                // A wheel ref pointing outside our uuid dir pins nothing.
                "other": {
                    "file": "./vendor/elsewhere/other-1.0-py3-none-any.whl",
                    "hashes": [format!("sha256:{}", "c".repeat(64))]
                },
                // Our wheel, but no sha256 entry among the hashes.
                "nosha": {
                    "file": format!("./{rel_wheel}"),
                    "hashes": ["md5:0123456789abcdef0123456789abcdef"]
                },
                // Our wheel, but a truncated sha256 cannot be a pin.
                "shortsha": {
                    "file": format!("./{rel_wheel}"),
                    "hashes": [format!("sha256:{}", "a".repeat(10))]
                }
            }
        });
        assert_eq!(pipenv_wired_pin(&all_bad, &dir_rel), None);

        // The same malformed neighbors must not mask a valid pin elsewhere.
        let sha = "b".repeat(64);
        let mut with_good = all_bad.clone();
        with_good["develop"] = serde_json::json!({
            "six": {
                "file": format!("./{rel_wheel}"),
                "hashes": [format!("sha256:{sha}")]
            }
        });
        assert_eq!(
            pipenv_wired_pin(&with_good, &dir_rel),
            Some((rel_wheel, sha))
        );
    }

    /// Splice-flavor lock load failures surface through the orchestrator as
    /// refusals (the poetry/pdm/pipenv load-Err plan arms), leaving the tree
    /// byte-untouched — the uv mirror is
    /// `uv_lock_parse_failure_refuses_through_orchestrator`.
    #[tokio::test]
    async fn splice_flavor_lock_parse_failure_refuses_through_orchestrator() {
        let cases = [
            (
                "poetry.lock",
                "version = [broken\n",
                "pypi_poetry_lock_parse_failed",
            ),
            (
                "pdm.lock",
                "version = [broken\n",
                "pypi_pdm_lock_parse_failed",
            ),
            (
                "Pipfile.lock",
                "{ not json",
                "pypi_pipenv_lock_parse_failed",
            ),
        ];
        for (lock_file, broken, expected_code) in cases {
            let fx = e2e_fixture().await;
            swap_to_lock_flavor(&fx, &[(lock_file, broken)]).await;
            let sources = PatchSources::blobs_only(&fx.blobs);
            let outcome = vendor_six(&fx, &sources, None).await;
            let VendorOutcome::Refused { code, .. } = outcome else {
                panic!("{lock_file}: expected Refused, got {outcome:?}");
            };
            assert_eq!(code, expected_code, "{lock_file}");
            assert!(
                !fx.root.join(".socket").exists(),
                "{lock_file}: a load refusal must leave the tree byte-untouched"
            );
        }
    }

    /// The splice-flavor mirror of
    /// `uv_stale_uuid_vendor_refuses_through_orchestrator`: a lock already
    /// wired to an EARLIER patch uuid refuses through the orchestrator (the
    /// poetry/pdm/pipenv guard-Err plan arms), before any new uuid dir is
    /// created, naming the stale uuid and the revert remediation.
    #[tokio::test]
    async fn splice_flavor_stale_uuid_vendor_refuses_through_orchestrator() {
        const UUID2: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
        let cases = [
            (
                "poetry.lock",
                POETRY_LOCK_REGISTRY,
                "pypi_poetry_source_already_exists",
            ),
            (
                "pdm.lock",
                PDM_LOCK_REGISTRY,
                "pypi_pdm_source_already_exists",
            ),
            (
                "Pipfile.lock",
                PIPENV_LOCK_REGISTRY,
                "pypi_pipenv_source_already_exists",
            ),
        ];
        for (lock_file, lock_text, expected_code) in cases {
            let fx = e2e_fixture().await;
            swap_to_lock_flavor(&fx, &[(lock_file, lock_text)]).await;
            let sources = PatchSources::blobs_only(&fx.blobs);
            let VendorOutcome::Done { result, .. } = vendor_six(&fx, &sources, None).await else {
                panic!("{lock_file}: first vendor must be Done");
            };
            assert!(result.success, "{lock_file}: {:?}", result.error);
            let wired = tokio::fs::read(fx.root.join(lock_file)).await.unwrap();

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
                panic!("{lock_file}: expected Refused, got {outcome:?}");
            };
            assert_eq!(code, expected_code, "{lock_file}");
            assert!(detail.contains(UUID), "{lock_file}: {detail}");
            assert!(detail.contains("vendor --revert"), "{lock_file}: {detail}");
            // Pre-flight refusal: the wired lock untouched, no second uuid dir.
            assert_eq!(
                tokio::fs::read(fx.root.join(lock_file)).await.unwrap(),
                wired,
                "{lock_file}: a pre-flight refusal must leave the wired lock untouched"
            );
            assert!(
                !fx.root
                    .join(format!(".socket/vendor/pypi/{UUID2}"))
                    .exists(),
                "{lock_file}: no second uuid dir may appear"
            );
        }
    }

    /// The splice-flavor mirror of `requirements_revendor_is_in_sync_skip`
    /// (the poetry/pdm/pipenv InSync plan arms): re-running vendor on a
    /// wired lock is the in-sync skip (nothing recorded, lock
    /// byte-identical), and a deleted uuid dir takes the artifact-only
    /// rebuild guarded by the pin the WIRED LOCK still carries — no ledger
    /// is ever persisted here, so the guard runs off the lock's own pin,
    /// which the deterministic local build reproduces byte-for-byte.
    #[tokio::test]
    async fn splice_flavor_revendor_in_sync_skip_and_ledgerless_rebuild() {
        let cases = [
            ("poetry.lock", POETRY_LOCK_REGISTRY),
            ("pdm.lock", PDM_LOCK_REGISTRY),
            ("Pipfile.lock", PIPENV_LOCK_REGISTRY),
        ];
        for (lock_file, lock_text) in cases {
            let fx = e2e_fixture().await;
            swap_to_lock_flavor(&fx, &[(lock_file, lock_text)]).await;
            let sources = PatchSources::blobs_only(&fx.blobs);
            let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
            else {
                panic!("{lock_file}: first vendor must be Done");
            };
            assert!(result.success, "{lock_file}: {:?}", result.error);
            let entry = entry.expect("entry on success");
            let wired = tokio::fs::read(fx.root.join(lock_file)).await.unwrap();

            // Intact wheel: in-sync skip — nothing recorded, lock untouched.
            let VendorOutcome::Done {
                result: r2,
                entry: e2,
                warnings: w2,
            } = vendor_six(&fx, &sources, None).await
            else {
                panic!("{lock_file}: re-run must be Done");
            };
            assert!(r2.success, "{lock_file}: {:?}", r2.error);
            assert!(e2.is_none(), "{lock_file}: in-sync re-run records nothing");
            assert!(
                !w2.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
                "{lock_file}: intact wheel must not claim a rebuild: {w2:?}"
            );
            assert_eq!(
                tokio::fs::read(fx.root.join(lock_file)).await.unwrap(),
                wired,
                "{lock_file}: the in-sync skip must not touch the lock"
            );

            // Deleted uuid dir: artifact-only rebuild, pin-checked against
            // the wired lock itself (no state.json exists in this fixture).
            tokio::fs::remove_dir_all(uuid_dir_of(&fx)).await.unwrap();
            let VendorOutcome::Done {
                result: r3,
                entry: e3,
                warnings: w3,
            } = vendor_six(&fx, &sources, None).await
            else {
                panic!("{lock_file}: rebuild run must be Done");
            };
            assert!(r3.success, "{lock_file}: {:?}", r3.error);
            assert!(
                e3.is_none(),
                "{lock_file}: artifact-only rebuild records no entry"
            );
            assert!(
                w3.iter().any(|w| w.code == "vendor_artifact_rebuilt"),
                "{lock_file}: {w3:?}"
            );
            let rebuilt = tokio::fs::read(fx.root.join(&entry.artifact.path))
                .await
                .unwrap_or_else(|e| panic!("{lock_file}: rebuilt wheel must exist: {e}"));
            assert_eq!(
                hex::encode(sha2::Sha256::digest(&rebuilt)),
                entry.artifact.sha256,
                "{lock_file}: the rebuild must reproduce the sha256 the lock still pins"
            );
            assert_eq!(
                tokio::fs::read(fx.root.join(lock_file)).await.unwrap(),
                wired,
                "{lock_file}: rebuild must not touch the lock"
            );
        }
    }

    /// A CORRUPT state.json (vs the MISSING one of the ledgerless tests) on
    /// an in-sync rebuild must not silently drop the pin guard: `load_state`
    /// fails, the guard falls back to the pin the wired requirements line
    /// still carries, and a mismatched service wheel is rejected under
    /// `auto` in favor of the deterministic local build that reproduces it.
    #[tokio::test]
    async fn in_sync_rebuild_with_corrupt_ledger_falls_back_to_wired_pin() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");
        // The committed ledger got clobbered into garbage.
        tokio::fs::write(
            fx.root.join(crate::vendor::state::VENDOR_STATE_REL),
            b"{ not json",
        )
        .await
        .unwrap();
        tokio::fs::remove_dir_all(uuid_dir_of(&fx)).await.unwrap();

        // The service offers a wheel whose bytes do NOT match the wired pin.
        let bytes: &[u8] =
            &served_wheel(b"service-built wheel bytes that differ from the local build");
        let sri = sri_sha512(bytes);
        let server = wiremock::MockServer::start().await;
        mount_pypi_granted(&server, WHEEL_NAME, &sri, bytes).await;

        let outcome = vendor_six(
            &fx,
            &sources,
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
        assert!(
            warnings
                .iter()
                .any(|w| w.code == "vendor_prebuilt_pin_mismatch"),
            "the pin must survive a corrupt ledger via the wired line: {warnings:?}"
        );
        let on_disk = tokio::fs::read(fx.root.join(&entry.artifact.path))
            .await
            .expect("the pinned wheel path must exist again");
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&on_disk)),
            entry.artifact.sha256,
            "the rebuilt wheel must reproduce the sha256 the wired line still pins"
        );
    }

    /// The guard's last resort: an in-sync poetry rebuild with NO ledger AND
    /// a wired lock whose one-line files hash element was hand-stripped has
    /// no pin to check against — the deterministic local rebuild proceeds
    /// unguarded (the documented "only when the wired file yields no pin
    /// either" case) instead of refusing an unrecoverable state, and the
    /// hand-edited lock stays untouched.
    #[tokio::test]
    async fn in_sync_rebuild_with_no_ledger_and_no_wired_pin_rebuilds_unguarded() {
        let fx = e2e_fixture().await;
        swap_to_lock_flavor(&fx, &[("poetry.lock", POETRY_LOCK_REGISTRY)]).await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("first vendor must be Done");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.expect("entry on success");

        // Hand-strip the files hash line(s) vendor wrote; the
        // [package.source] url still routes six through the uuid dir, so
        // the project stays in-sync — but the lock now yields no pin.
        let wired = tokio::fs::read_to_string(fx.root.join("poetry.lock"))
            .await
            .unwrap();
        let stripped: String = wired
            .lines()
            .filter(|l| !l.contains("hash = \"sha256:"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert_ne!(stripped, wired, "the tamper must remove a hash line");
        tokio::fs::write(fx.root.join("poetry.lock"), &stripped)
            .await
            .unwrap();
        tokio::fs::remove_dir_all(uuid_dir_of(&fx)).await.unwrap();

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
            fx.root.join(&entry.artifact.path).is_file(),
            "the wheel is rebuilt at the recorded path"
        );
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("poetry.lock"))
                .await
                .unwrap(),
            stripped,
            "the hand-stripped lock is left alone"
        );
    }
    #[tokio::test]
    async fn standalone_python_locks_vendor_and_revert_real_wheels() {
        let original = r#"# original byte formatting
lock-version = "1.0"
created-by = "uv"
requires-python = ">=3.9"

[[packages]]
name = "six"
version = "1.16.0"
wheels = [{url = "https://files.pythonhosted.org/six.whl", hashes = {sha256 = "upstream"}}]
"#;
        for name in ["pylock.toml", "pylock.production.toml"] {
            full_cycle_lock_flavor("python-lock", name, original, "python_lock_document").await;
        }
    }

    #[tokio::test]
    async fn script_python_lock_pairs_metadata_and_restores_original_bytes() {
        let fx = e2e_fixture().await;
        let script = r#"#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["six==1.16.0"]
# ///
print('preserved')
"#;
        let lock = r#"version = 1
revision = 3
requires-python = ">=3.9"

[manifest]
requirements = [{name = "six", specifier = "==1.16.0"}]

[[package]]
name = "six"
version = "1.16.0"
source = {registry = "https://pypi.org/simple"}
wheels = [{url = "https://files.pythonhosted.org/six.whl", hash = "sha256:upstream"}]
"#;
        swap_to_lock_flavor(&fx, &[("example.py", script), ("example.py.lock", lock)]).await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let VendorOutcome::Done { result, entry, .. } = vendor_six(&fx, &sources, None).await
        else {
            panic!("expected completed vendor");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        let script_after = tokio::fs::read_to_string(fx.root.join("example.py"))
            .await
            .unwrap();
        assert!(script_after.contains(&entry.artifact.path));
        assert!(script_after.ends_with("# ///\nprint('preserved')\n"));
        let lock_after = tokio::fs::read_to_string(fx.root.join("example.py.lock"))
            .await
            .unwrap();
        let document: toml_edit::DocumentMut = lock_after.parse().unwrap();
        assert_eq!(
            document["manifest"]["requirements"][0]["path"].as_str(),
            Some(entry.artifact.path.as_str())
        );
        assert!(lock_after.contains(&entry.artifact.sha256));
        let VendorOutcome::Done {
            result: repeated,
            entry: repeated_entry,
            ..
        } = vendor_six(&fx, &sources, None).await
        else {
            panic!("expected idempotent vendor");
        };
        assert!(repeated.success);
        assert!(repeated_entry.is_none());
        for (file, original, tampered) in [
            (
                "example.py",
                &script_after,
                script_after.replace(&entry.artifact.path, "user/six.whl"),
            ),
            (
                "example.py.lock",
                &lock_after,
                lock_after.replace(&entry.artifact.sha256, &"f".repeat(64)),
            ),
        ] {
            touch(&fx.root, file, &tampered).await;
            let script_before = tokio::fs::read_to_string(fx.root.join("example.py"))
                .await
                .unwrap();
            let lock_before = tokio::fs::read_to_string(fx.root.join("example.py.lock"))
                .await
                .unwrap();
            let refused = revert_pypi(&entry, &fx.root, false).await;
            assert!(refused.success);
            assert!(refused.kept_artifact);
            assert!(refused.drift_skipped());
            assert_eq!(
                tokio::fs::read_to_string(fx.root.join("example.py"))
                    .await
                    .unwrap(),
                script_before
            );
            assert_eq!(
                tokio::fs::read_to_string(fx.root.join("example.py.lock"))
                    .await
                    .unwrap(),
                lock_before
            );
            assert!(fx.root.join(&entry.artifact.path).is_file());
            touch(&fx.root, file, original).await;
        }
        let reverted = revert_pypi(&entry, &fx.root, false).await;
        assert!(reverted.success, "{:?}", reverted.error);
        assert!(reverted.warnings.is_empty(), "{:?}", reverted.warnings);
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("example.py"))
                .await
                .unwrap(),
            script
        );
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("example.py.lock"))
                .await
                .unwrap(),
            lock
        );
        assert!(!uuid_dir_of(&fx).exists());
    }
    #[tokio::test]
    async fn unrelated_script_lock_does_not_block_requirements_vendoring() {
        let fx = e2e_fixture().await;
        let unrelated = "version = 1\n[[package]]\nname = \"other\"\nversion = \"1\"\nsource = {registry = \"https://pypi.org/simple\"}\n";
        touch(&fx.root, "job.py.lock", unrelated).await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let outcome = vendor_six(&fx, &sources, None).await;
        let VendorOutcome::Done {
            result,
            entry,
            warnings,
        } = outcome
        else {
            panic!("expected requirements fallback, got {outcome:?}");
        };
        assert!(result.success, "{:?}", result.error);
        let entry = entry.unwrap();
        assert_eq!(entry.flavor.as_deref(), Some("requirements"));
        assert!(read_requirements(&fx).await.contains(&entry.artifact.path));
        assert_eq!(
            tokio::fs::read_to_string(fx.root.join("job.py.lock"))
                .await
                .unwrap(),
            unrelated
        );
        assert!(warnings
            .iter()
            .any(|warning| warning.code == "pypi_unmatched_lockfiles"));
    }

    // ─────────────── source-flip / outage idempotence ───────────────
    //
    // In-sync re-runs never consult the service (the wiring is the anchor).
    // A relock that dropped the wiring (a Fresh plan) re-wires the COMMITTED
    // wheel the ledger vouches for, whichever source is reachable now; the
    // PDM partial-relock guard knows every sha the patch's wheel went by.
    mod outage_idempotence {
        use super::*;
        use crate::vendor::test_support as ts;
        use std::io::{Read as _, Write as _};

        const KEY: &str = "pkg:pypi/six@1.16.0";
        const WIRED_FILES: [&str; 7] = [
            "poetry.lock",
            "pdm.lock",
            "Pipfile.lock",
            "Pipfile",
            "uv.lock",
            "requirements.txt",
            "pyproject.toml",
        ];
        const HATCH_PYPROJECT: &str = "[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n\n[project]\nname = \"proj\"\nversion = \"0.1.0\"\ndependencies = [\"six==1.16.0\"]\n";

        type Snap = Vec<Option<Vec<u8>>>;

        async fn snap(fx: &E2eFixture) -> Snap {
            let mut out = Vec::new();
            for f in WIRED_FILES {
                out.push(tokio::fs::read(fx.root.join(f)).await.ok());
            }
            out
        }

        async fn restore(fx: &E2eFixture, snap: &Snap) {
            for (f, bytes) in WIRED_FILES.iter().zip(snap) {
                match bytes {
                    Some(b) => tokio::fs::write(fx.root.join(f), b).await.unwrap(),
                    None => {
                        let _ = tokio::fs::remove_file(fx.root.join(f)).await;
                    }
                }
            }
        }

        fn wheel(fx: &E2eFixture) -> PathBuf {
            uuid_dir_of(fx).join(WHEEL_NAME)
        }

        /// The deterministic local build's wheel (from a throwaway copy).
        async fn local_wheel() -> Vec<u8> {
            let probe = e2e_fixture().await;
            let sources = PatchSources::blobs_only(&probe.blobs);
            let (r, e, _) = ts::expect_done(vendor_six(&probe, &sources, None).await);
            assert!(r.success && e.is_some(), "{:?}", r.error);
            tokio::fs::read(wheel(&probe)).await.unwrap()
        }

        /// The same members re-encoded (stored, not deflated): the stand-in
        /// for the service's prebuilt wheel — verifies, different sha.
        fn rezip(whl: &[u8]) -> Vec<u8> {
            let mut src = zip::ZipArchive::new(std::io::Cursor::new(whl)).unwrap();
            let mut out = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
            let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for i in 0..src.len() {
                let mut entry = src.by_index(i).unwrap();
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes).unwrap();
                out.start_file(entry.name().to_string(), opts).unwrap();
                out.write_all(&bytes).unwrap();
            }
            let alt = out.finish().unwrap().into_inner();
            assert_ne!(alt, whl);
            alt
        }

        fn sha(bytes: &[u8]) -> String {
            hex::encode(Sha256::digest(bytes))
        }

        /// One run against a fresh mock: `serve` = the prebuilt wheel, or
        /// `None` for a 503 outage. Returns the outcome + the request count.
        async fn run(
            fx: &E2eFixture,
            serve: Option<&[u8]>,
            source: VendorSource,
            offline: bool,
        ) -> (VendorOutcome, usize) {
            let server = wiremock::MockServer::start().await;
            match serve {
                Some(bytes) => {
                    mount_pypi_granted(&server, WHEEL_NAME, &sri_sha512(bytes), bytes).await
                }
                None => ts::mount_503(&server).await,
            }
            let sources = PatchSources::blobs_only(&fx.blobs);
            let cfg = ts::service_cfg(&server.uri(), source, offline);
            let outcome = vendor_six(fx, &sources, Some(&cfg)).await;
            (outcome, ts::request_count(&server).await)
        }

        /// Run 1, persisted like the CLI does.
        async fn first_run(fx: &E2eFixture, serve: Option<&[u8]>) -> VendorEntry {
            let (outcome, _) = run(fx, serve, VendorSource::Auto, false).await;
            let (r, e, _) = ts::expect_done(outcome);
            assert!(r.success, "run 1: {:?}", r.error);
            let e = e.expect("run 1 wires");
            ts::persist(&fx.root, KEY, e.clone()).await;
            e
        }

        async fn flavor_fixture(files: &[(&str, &str)]) -> E2eFixture {
            let fx = e2e_fixture().await;
            if !files.is_empty() {
                swap_to_lock_flavor(&fx, files).await;
            }
            fx
        }

        fn flavors() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
            vec![
                ("poetry", vec![("poetry.lock", POETRY_LOCK_REGISTRY)]),
                ("pdm", vec![("pdm.lock", PDM_LOCK_REGISTRY)]),
                ("pipenv", vec![("Pipfile.lock", PIPENV_LOCK_REGISTRY)]),
                (
                    "uv",
                    vec![
                        ("pyproject.toml", UV_PYPROJECT),
                        ("uv.lock", UV_LOCK_REGISTRY),
                    ],
                ),
                ("requirements", vec![]),
                ("hatch", vec![("pyproject.toml", HATCH_PYPROJECT)]),
            ]
        }

        /// Regression (the analysts' repro): an in-sync re-run after a flip,
        /// in both directions, is a no-op with no request, for every flavor.
        #[tokio::test]
        async fn all_flavors_rerun_flip_is_in_sync() {
            let alt = rezip(&local_wheel().await);
            for (name, files) in flavors() {
                for first_svc in [true, false] {
                    let fx = flavor_fixture(&files).await;
                    let first = first_run(&fx, first_svc.then_some(alt.as_slice())).await;
                    assert_eq!(first.flavor.as_deref(), Some(name), "{name}");
                    let s1 = snap(&fx).await;
                    let w1 = tokio::fs::read(wheel(&fx)).await.unwrap();
                    let (outcome, requests) = run(
                        &fx,
                        (!first_svc).then_some(alt.as_slice()),
                        VendorSource::Auto,
                        false,
                    )
                    .await;
                    let (r, e, w) = ts::expect_done(outcome);
                    assert!(r.success, "{name}: {:?}", r.error);
                    assert!(e.is_none(), "{name}: in sync");
                    assert!(
                        !ts::has_warning(&w, "vendor_prebuilt_unavailable"),
                        "{name}: {w:?}"
                    );
                    assert_eq!(snap(&fx).await, s1, "{name}: locks byte-identical");
                    assert_eq!(tokio::fs::read(wheel(&fx)).await.unwrap(), w1, "{name}");
                    assert_eq!(requests, 0, "{name}: no request");
                }
            }
        }

        /// P1 + P2: a relock restored the registry unit (the wiring dropped),
        /// re-run under the OTHER source: the committed wheel is re-wired —
        /// entry Some, the first run's sha pinned, wheel bytes unchanged, no
        /// request, and the `vendor_artifact_reused` advisory.
        #[tokio::test]
        async fn relock_rescan_rewires_the_committed_wheel_without_network() {
            let local = local_wheel().await;
            let alt = rezip(&local);
            for (name, files) in flavors()
                .into_iter()
                .filter(|(n, _)| ["pdm", "uv", "poetry"].contains(n))
            {
                for first_svc in [true, false] {
                    let fx = flavor_fixture(&files).await;
                    let registry = snap(&fx).await;
                    let first = first_run(&fx, first_svc.then_some(alt.as_slice())).await;
                    let committed = tokio::fs::read(wheel(&fx)).await.unwrap();
                    assert_eq!(&committed, if first_svc { &alt } else { &local }, "{name}");
                    assert_eq!(first.artifact.sha256, sha(&committed));
                    let wired = snap(&fx).await;
                    restore(&fx, &registry).await; // the relock
                    let (outcome, requests) = run(
                        &fx,
                        (!first_svc).then_some(alt.as_slice()),
                        VendorSource::Auto,
                        false,
                    )
                    .await;
                    let (r, e, w) = ts::expect_done(outcome);
                    assert!(r.success, "{name}: {:?}", r.error);
                    let e = e.expect("the relocked wiring is re-applied");
                    assert_eq!(e.artifact.sha256, first.artifact.sha256, "{name}");
                    assert_eq!(e.artifact.path, first.artifact.path, "{name}");
                    assert!(
                        ts::has_warning(&w, "vendor_artifact_reused"),
                        "{name}: {w:?}"
                    );
                    assert!(
                        !ts::has_warning(&w, "vendor_prebuilt_unavailable"),
                        "{name}: {w:?}"
                    );
                    assert_eq!(requests, 0, "{name}: no request");
                    assert_eq!(tokio::fs::read(wheel(&fx)).await.unwrap(), committed);
                    assert_eq!(snap(&fx).await, wired, "{name}: re-wired byte-identically");
                }
            }
        }

        /// The Fresh-path reuse runs before the offline conflict: a relock
        /// re-scan under `service` + `--offline` still re-wires.
        #[tokio::test]
        async fn relock_rescan_reuse_survives_service_mode_offline() {
            let alt = rezip(&local_wheel().await);
            let fx = flavor_fixture(&[("pdm.lock", PDM_LOCK_REGISTRY)]).await;
            let registry = snap(&fx).await;
            let first = first_run(&fx, Some(&alt)).await;
            restore(&fx, &registry).await;
            let (outcome, requests) = run(&fx, None, VendorSource::Service, true).await;
            let (r, e, _) = ts::expect_done(outcome);
            assert!(r.success, "{:?}", r.error);
            assert_eq!(e.unwrap().artifact.sha256, first.artifact.sha256);
            assert_eq!(requests, 0);
        }

        fn partial_pdm_lock(patched_sha: &str) -> String {
            let partial = PDM_LOCK_REGISTRY.replace(
                "files = [\n    {file = \"six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254\"},\n    {file = \"six-1.16.0.tar.gz\", hash = \"sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926\"},\n]",
                &format!("files = [\n    {{file = \"six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:{patched_sha}\"}},\n]"),
            );
            assert_ne!(partial, PDM_LOCK_REGISTRY);
            partial
        }

        /// P3 + P4: a `pdm add` partial relock (path dropped, the SERVICE
        /// wheel's sha kept) re-run during an outage refuses whichever
        /// source is reachable — with the wheel present (reused, sha A) and
        /// with it deleted (local rebuild, sha B, still guarded by the
        /// ledger's A). The ledger is untouched, and a reused wheel is never
        /// swept by the wiring failure.
        #[tokio::test]
        async fn pdm_partial_relock_after_a_flip_refuses_whichever_source() {
            let alt = rezip(&local_wheel().await);
            for wheel_present in [true, false] {
                let fx = flavor_fixture(&[("pdm.lock", PDM_LOCK_REGISTRY)]).await;
                let first = first_run(&fx, Some(&alt)).await;
                assert_eq!(first.artifact.sha256, sha(&alt));
                let partial = partial_pdm_lock(&first.artifact.sha256);
                tokio::fs::write(fx.root.join("pdm.lock"), &partial)
                    .await
                    .unwrap();
                if !wheel_present {
                    tokio::fs::remove_file(wheel(&fx)).await.unwrap();
                }
                let ledger = tokio::fs::read(fx.root.join(".socket/vendor/state.json"))
                    .await
                    .unwrap();
                let (outcome, _) = run(&fx, None, VendorSource::Auto, false).await;
                let (r, e, _) = ts::expect_done(outcome);
                assert!(!r.success, "present={wheel_present}: must refuse");
                assert!(e.is_none());
                let err = r.error.unwrap();
                assert!(err.contains("pypi_pdm_source_already_exists"), "{err}");
                assert_eq!(
                    tokio::fs::read_to_string(fx.root.join("pdm.lock"))
                        .await
                        .unwrap(),
                    partial,
                    "lock untouched"
                );
                assert_eq!(
                    tokio::fs::read(fx.root.join(".socket/vendor/state.json"))
                        .await
                        .unwrap(),
                    ledger,
                    "the ledger original is never replaced by the patched unit"
                );
                if wheel_present {
                    assert_eq!(
                        tokio::fs::read(wheel(&fx)).await.unwrap(),
                        alt,
                        "P4: the reused committed wheel survives the wiring failure"
                    );
                }
            }
        }

        /// P5: in-sync wiring, the SERVICE-built wheel missing, service
        /// down: fails closed with a message that names the outage; the lock
        /// is unchanged and nothing is left behind.
        #[tokio::test]
        async fn missing_service_wheel_under_outage_names_the_outage() {
            let alt = rezip(&local_wheel().await);
            let fx = flavor_fixture(&[("pdm.lock", PDM_LOCK_REGISTRY)]).await;
            let _ = first_run(&fx, Some(&alt)).await;
            let wired = snap(&fx).await;
            tokio::fs::remove_file(wheel(&fx)).await.unwrap();
            let (outcome, _) = run(&fx, None, VendorSource::Auto, false).await;
            let (r, e, _) = ts::expect_done(outcome);
            assert!(!r.success);
            assert!(e.is_none());
            let err = r.error.unwrap();
            assert!(err.contains("patch service was unavailable"), "{err}");
            assert!(err.contains("once the service is reachable"), "{err}");
            assert_eq!(snap(&fx).await, wired, "lock unchanged");
            assert!(!wheel(&fx).exists());
        }

        /// P6: a platform-locked ledger entry is never reused on the Fresh
        /// path (a platform wheel committed on another OS keeps today's
        /// acquire-and-pin behavior).
        #[tokio::test]
        async fn platform_locked_entry_is_not_reused() {
            let alt = rezip(&local_wheel().await);
            let fx = flavor_fixture(&[("pdm.lock", PDM_LOCK_REGISTRY)]).await;
            let registry = snap(&fx).await;
            let mut first = first_run(&fx, Some(&alt)).await;
            first.artifact.platform_locked = Some(true);
            ts::persist(&fx.root, KEY, first.clone()).await;
            restore(&fx, &registry).await;
            let (outcome, requests) = run(&fx, None, VendorSource::Auto, false).await;
            let (r, e, w) = ts::expect_done(outcome);
            assert!(r.success, "{:?}", r.error);
            assert!(!ts::has_warning(&w, "vendor_artifact_reused"), "{w:?}");
            assert!(ts::has_warning(&w, "vendor_prebuilt_unavailable"), "{w:?}");
            assert_ne!(e.unwrap().artifact.sha256, first.artifact.sha256);
            assert_eq!(requests, 1, "acquisition ran (the 503 POST)");
        }

        /// Dry run of the relock re-scan: the preview agrees with the real
        /// run (which re-wires offline, see above) — success, a verified
        /// preview, the reuse note, nothing written, no request — instead
        /// of the `service` + `--offline` refusal the acquisition preview
        /// raised.
        #[tokio::test]
        async fn relock_rescan_dry_run_previews_the_reuse_under_service_offline() {
            let alt = rezip(&local_wheel().await);
            let fx = flavor_fixture(&[("pdm.lock", PDM_LOCK_REGISTRY)]).await;
            let registry = snap(&fx).await;
            let _ = first_run(&fx, Some(&alt)).await;
            restore(&fx, &registry).await;
            let server = wiremock::MockServer::start().await;
            ts::mount_503(&server).await;
            let cfg = ts::service_cfg(&server.uri(), VendorSource::Service, true);
            let outcome = vendor_pypi(
                KEY,
                &fx.site_packages,
                &fx.root,
                &fx.record,
                &PatchSources::blobs_only(&fx.blobs),
                "2026-06-09T00:00:00Z",
                true,
                false,
                Some(&cfg),
            )
            .await;
            let (r, e, w) = ts::expect_done(outcome);
            assert!(r.success, "{:?}", r.error);
            assert!(e.is_none(), "a dry run records nothing");
            assert!(ts::has_warning(&w, "vendor_artifact_reused"), "{w:?}");
            assert!(
                r.files_verified
                    .iter()
                    .all(|f| f.status == crate::patch::apply::VerifyStatus::Ready),
                "a verified preview, as the dry-run build reports"
            );
            assert_eq!(snap(&fx).await, registry, "nothing wired");
            assert_eq!(tokio::fs::read(wheel(&fx)).await.unwrap(), alt);
            assert_eq!(ts::request_count(&server).await, 0);
        }

        /// Rename the committed wheel to `leaf` and point every ledger
        /// entry at it (a forged, committed state.json), then relock.
        async fn forge_leaf(fx: &E2eFixture, registry: &Snap, leaf: &str) {
            tokio::fs::rename(wheel(fx), uuid_dir_of(fx).join(leaf))
                .await
                .unwrap();
            let state_p = fx.root.join(".socket/vendor/state.json");
            let mut state: crate::vendor::state::VendorState =
                serde_json::from_slice(&tokio::fs::read(&state_p).await.unwrap()).unwrap();
            for e in state.entries.values_mut() {
                let dir = e.artifact.path.rsplit_once('/').unwrap().0.to_string();
                e.artifact.path = format!("{dir}/{leaf}");
            }
            tokio::fs::write(&state_p, serde_json::to_vec_pretty(&state).unwrap())
                .await
                .unwrap();
            restore(fx, registry).await;
        }

        /// The reused leaf comes from the committed ledger and is spliced
        /// verbatim into the wiring: a leaf carrying a newline must never
        /// inject a requirements.txt option line, and a leaf naming another
        /// distribution must never be wired for this one.
        #[tokio::test]
        async fn forged_ledger_leaf_is_never_reused() {
            for leaf in [
                "six-1.16.0-py3-none-any.whl\n--trusted-host evil.example\n#.whl",
                "evil-9.9-py3-none-any.whl",
                "six-6.6.6-py3-none-any.whl",
            ] {
                // Windows rejects a newline in a filename, so the forged
                // file cannot exist there to tempt the reuse path.
                if cfg!(windows) && leaf.contains('\n') {
                    continue;
                }
                let fx = flavor_fixture(&[]).await;
                let registry = snap(&fx).await;
                let _ = first_run(&fx, None).await;
                forge_leaf(&fx, &registry, leaf).await;
                let (outcome, _) = run(&fx, None, VendorSource::Auto, false).await;
                let (r, _, w) = ts::expect_done(outcome);
                assert!(
                    !ts::has_warning(&w, "vendor_artifact_reused"),
                    "{leaf:?}: {w:?}"
                );
                let req = tokio::fs::read_to_string(fx.root.join("requirements.txt"))
                    .await
                    .unwrap();
                assert!(
                    !req.lines()
                        .any(|l| l.trim_start().starts_with("--trusted-host")),
                    "{leaf:?}: injected\n{req}"
                );
                assert!(!req.contains("evil"), "{leaf:?}\n{req}");
                assert!(r.success, "{leaf:?}: acquisition re-vendors: {:?}", r.error);
            }
        }

        /// A platform-specific wheel (by its own filename tags) is not
        /// reused even when the ledger lacks the `platform_locked` flag.
        #[tokio::test]
        async fn platform_tagged_leaf_without_ledger_flag_is_not_reused() {
            let fx = flavor_fixture(&[("pdm.lock", PDM_LOCK_REGISTRY)]).await;
            let registry = snap(&fx).await;
            let mut first = first_run(&fx, None).await;
            first.artifact.platform_locked = None;
            ts::persist(&fx.root, KEY, first).await;
            forge_leaf(
                &fx,
                &registry,
                "six-1.16.0-cp311-cp311-manylinux_2_17_x86_64.whl",
            )
            .await;
            let (outcome, requests) = run(&fx, None, VendorSource::Auto, false).await;
            let (_, _, w) = ts::expect_done(outcome);
            assert!(!ts::has_warning(&w, "vendor_artifact_reused"), "{w:?}");
            assert_eq!(requests, 1, "acquisition ran (the 503 POST)");
        }

        #[test]
        fn reusable_wheel_leaf_accepts_only_this_dist_and_version() {
            assert!(reusable_wheel_leaf(
                "six-1.16.0-py2.py3-none-any.whl",
                "six",
                "1.16.0"
            ));
            assert!(reusable_wheel_leaf(
                "Six-1.16.0-1-py3-none-any.whl",
                "six",
                "1.16.0"
            ));
            assert!(reusable_wheel_leaf(
                "zope_interface-5.0-py3-none-any.whl",
                "zope-interface",
                "5.0"
            ));
            assert!(reusable_wheel_leaf(
                "torch-2.0.0+cu118-cp311-cp311-linux_x86_64.whl",
                "torch",
                "2.0.0+cu118"
            ));
            for bad in [
                "six-1.16.0-py3-none-any.whl\n--x\n#.whl",
                "six-1.16.0-py3-none-any .whl",
                "six-1.16.0-py3-none-any.whl#x.whl",
                "evil-1.16.0-py3-none-any.whl",
                "six-1.17.0-py3-none-any.whl",
                "six-1.16.0-any.whl",
                "six-1.16.0-a-b-py3-none-any.whl",
                "six-1.16.0-py3-none-any.tar.gz",
                "six--1.16.0-py3-none-any.whl",
            ] {
                assert!(!reusable_wheel_leaf(bad, "six", "1.16.0"), "{bad:?}");
            }
        }

        /// P7: the in-sync path is unchanged — `service` mode + 503 on an
        /// already-vendored package is `already_vendored`.
        #[tokio::test]
        async fn service_mode_in_sync_rerun_under_outage_is_already_vendored() {
            let alt = rezip(&local_wheel().await);
            let fx = flavor_fixture(&[("pdm.lock", PDM_LOCK_REGISTRY)]).await;
            let _ = first_run(&fx, Some(&alt)).await;
            let wired = snap(&fx).await;
            let (outcome, requests) = run(&fx, None, VendorSource::Service, false).await;
            let (r, e, _) = ts::expect_done(outcome);
            assert!(r.success, "{:?}", r.error);
            assert!(e.is_none());
            assert_eq!(snap(&fx).await, wired);
            assert_eq!(requests, 0);
        }
    }

    /// An integrity mismatch is a hard failure under `auto` too —
    /// never a quiet local-build fallback (service_fetch's contract).
    #[tokio::test]
    async fn service_integrity_mismatch_auto_hard_fails() {
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
            Some(&pypi_service_cfg(&server.uri(), VendorSource::Auto, false)),
        )
        .await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("tampered bytes fell back to a local build: {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_integrity_mismatch");
        assert!(!fx.root.join(format!(".socket/vendor/pypi/{UUID}")).exists());
    }

    /// `--vendor-source=service` with no configured client must fail
    /// closed, never quietly build locally.
    #[tokio::test]
    async fn service_mode_without_client_refuses() {
        let fx = e2e_fixture().await;
        let sources = PatchSources::blobs_only(&fx.blobs);
        let mut cfg = pypi_service_cfg("http://127.0.0.1:1", VendorSource::Service, false);
        cfg.client = None;
        let outcome = vendor_pypi(
            "pkg:pypi/six@1.16.0",
            &fx.site_packages,
            &fx.root,
            &fx.record,
            &sources,
            "2026-06-09T00:00:00Z",
            false,
            false,
            Some(&cfg),
        )
        .await;
        let VendorOutcome::Refused { code, .. } = outcome else {
            panic!("service mode without a client built locally: {outcome:?}");
        };
        assert_eq!(code, "vendor_prebuilt_required");
        assert!(!fx.root.join(format!(".socket/vendor/pypi/{UUID}")).exists());
    }
}

#[cfg(test)]
mod hatch_routing_tests {
    use super::*;

    #[tokio::test]
    async fn hatchling_with_requirements_preserves_pip_routing() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("pyproject.toml"), "[build-system]\nbuild-backend=\"hatchling.build\"\n[project]\ndependencies=[\"urllib3==1.26.18\"]\n").await.unwrap();
        tokio::fs::write(dir.path().join("requirements.txt"), "urllib3==1.26.18\n")
            .await
            .unwrap();
        assert_eq!(
            detect_pypi_flavor(dir.path(), Some(("urllib3", "1.26.18")))
                .await
                .unwrap()
                .0,
            PypiFlavor::Requirements
        );
        tokio::fs::remove_file(dir.path().join("requirements.txt"))
            .await
            .unwrap();
        assert_eq!(
            detect_pypi_flavor(dir.path(), Some(("urllib3", "1.26.18")))
                .await
                .unwrap()
                .0,
            PypiFlavor::Hatch
        );
    }
}
