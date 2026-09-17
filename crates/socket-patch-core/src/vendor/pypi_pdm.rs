//! PDM lock-only wheel redirects. The manifest and unrelated lock entries stay byte-identical.

use std::path::Path;

use toml_edit::{DocumentMut, Item, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::atomic_write_bytes_preserving_mode;

use super::common::{
    item_get, lock_units_named, pep508_name, pep621_declared_names, record,
    revert_lock_fragment_splice,
};
use super::path::parse_vendor_path;
use super::state::{PdmMeta, VendorEntry, WiringAction, WiringRecord};
use super::{RevertOutcome, VendorWarning};

/// The only file this backend ever writes (and the revert allowlist).
const LOCK_FILE: &str = "pdm.lock";

/// The `WiringRecord.kind` discriminator this backend owns.
const KIND_LOCK_PACKAGE: &str = "pdm_lock_package";

/// Guarded read shared in shape with the sibling backend twins:
/// `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular
/// files, so a FIFO planted as `pdm.lock` (or the diagnostics-only
/// `pyproject.toml`) fails fast instead of wedging every pdm-project vendor
/// run forever in an `open(2)` that waits for a writer — the flavor-routing
/// probes ahead of the load are metadata-only, so these are the first opens.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

/// A loaded-and-guard-checked pdm project.
#[derive(Debug)]
pub struct PdmProject {
    /// Verbatim pdm.lock text (the surgery substrate).
    pub lock_text: String,
    /// Parsed lock (guard checks only — every edit is text surgery).
    pub lock: DocumentMut,
    /// pyproject.toml content when present. NEVER written; read only to
    /// classify the dependency for [`PdmMeta::dep_class`] diagnostics.
    pub pyproject_text: Option<String>,
    /// pdm.lock `[metadata] lock_version` (recorded into [`PdmMeta`]).
    pub lock_version: String,
    /// pdm.lock `[metadata] strategy` (recorded into [`PdmMeta`]).
    pub strategy: Vec<String>,
    /// Non-fatal advisories raised during load (untested lock version).
    pub warnings: Vec<VendorWarning>,
}

/// What the target `[[package]]` unit already looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdmTarget {
    /// Registry-shaped: proceed to build the wheel and wire.
    Fresh,
    /// Already wired to THIS patch uuid — the caller synthesizes an
    /// AlreadyPatched success, builds nothing, and records nothing (the
    /// first run's ledger entry holds the only copy of the original).
    InSync,
}

/// Read + parse pdm.lock and run every project-level guard (lock version
/// series, strategy set). Refuses before ANY write — the orchestrator runs
/// this (and the target guards) before the wheel is built, so a refusal
/// leaves the tree byte-untouched.
pub async fn load_pdm_project(root: &Path) -> Result<PdmProject, (&'static str, String)> {
    let lock_text = read_regular_to_string(&root.join(LOCK_FILE))
        .await
        .map_err(|e| {
            (
                "pypi_pdm_lock_parse_failed",
                format!("cannot read {LOCK_FILE}: {e}"),
            )
        })?;
    let lock: DocumentMut = lock_text.parse().map_err(|e| {
        (
            "pypi_pdm_lock_parse_failed",
            format!("{LOCK_FILE} does not parse: {e}"),
        )
    })?;

    let metadata = lock.get("metadata");
    let lock_version = metadata
        .and_then(|m| item_get(m, "lock_version"))
        .and_then(Item::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            (
                "pypi_pdm_lock_version_unsupported",
                format!("{LOCK_FILE} has no [metadata] lock_version; re-lock with a supported PDM release"),
            )
        })?;
    let mut warnings = Vec::new();
    if lock_version == "2" {
        warnings.push(VendorWarning::new("pypi_pdm_legacy_sync_required", "PDM 0.x may regenerate freshly generated locks during install; use `pdm sync` to preserve this patch, or upgrade PDM"));
    }
    crate::utils::pdm_lock::lock_version(&lock)
        .map_err(|detail| ("pypi_pdm_lock_version_unsupported", detail))?;

    let strategy = crate::utils::pdm_lock::validate_strategy(&lock)
        .map_err(|detail| ("pypi_pdm_lock_strategy_unsupported", detail))?;

    let pyproject_text = read_regular_to_string(&root.join("pyproject.toml"))
        .await
        .ok();
    Ok(PdmProject {
        lock_text,
        lock,
        pyproject_text,
        lock_version,
        strategy,
        warnings,
    })
}

/// `"direct"` iff the package is declared in the pyproject — PEP 621
/// `[project] dependencies` / `optional-dependencies`,
/// `[tool.pdm.dev-dependencies]` groups, or PEP 735 `[dependency-groups]` —
/// else `"transitive"`. Diagnostics ONLY ([`PdmMeta::dep_class`]): the splice
/// is identical either way, so a missing/unparseable pyproject degrades to
/// `"transitive"` instead of refusing.
fn classify_dependency(p: &PdmProject, canon_name: &str) -> &'static str {
    let Some(text) = p.pyproject_text.as_deref() else {
        return "transitive";
    };
    let Ok(doc) = text.parse::<DocumentMut>() else {
        return "transitive";
    };
    let mut declared: Vec<String> = Vec::new();
    pep621_declared_names(&doc, &mut declared);
    if let Some(pdm) = doc
        .get("tool")
        .and_then(|tool| item_get(tool, "pdm"))
        .and_then(Item::as_table_like)
    {
        for (section, dependencies) in pdm.iter() {
            if section == "dependencies" || section.ends_with("-dependencies") {
                if let Some(table) = dependencies.as_table_like() {
                    declared.extend(
                        table
                            .iter()
                            .filter(|(_, spec)| spec.as_array().is_none())
                            .map(|(name, _)| name.to_string()),
                    );
                }
            }
        }
    }

    for groups in [
        doc.get("tool")
            .and_then(|t| item_get(t, "pdm"))
            .and_then(|p| item_get(p, "dev-dependencies")),
        doc.get("dependency-groups"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(table) = groups.as_table_like() {
            for (_, item) in table.iter() {
                if let Some(arr) = item.as_array() {
                    declared.extend(
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(|s| pep508_name(s).to_string()),
                    );
                }
            }
        }
    }
    if declared
        .iter()
        .any(|n| canonicalize_pypi_name(n) == canon_name)
    {
        "direct"
    } else {
        "transitive"
    }
}

/// Target-specific guards (also re-run by [`wire_pdm`] right before
/// writing). The orchestrator runs them pre-flight so a refusal happens
/// before the wheel artifact is built. Lock names match by PEP 503 canonical
/// form (pdm records canonical names, mirroring poetry's P8 finding).
pub(super) fn check_target_guards(
    p: &PdmProject,
    canon_name: &str,
    version: &str,
    record_uuid: &str,
) -> Result<PdmTarget, (&'static str, String)> {
    let units = lock_units_named(&p.lock, canon_name);
    if units.is_empty() {
        return Err((
            "pypi_pdm_lock_package_missing",
            format!("{LOCK_FILE} has no [[package]] entry for {canon_name}; run `pdm lock` first"),
        ));
    }
    let mut variants = std::collections::BTreeSet::new();
    let mut fresh = false;
    let mut in_sync = false;
    for unit in units {
        let extras = unit
            .get("extras")
            .map(ToString::to_string)
            .unwrap_or_default();
        if !variants.insert(extras) {
            return Err((
                "pypi_pdm_lock_forked_package",
                "duplicate or forked PDM package".into(),
            ));
        }
        match check_target_unit(p, unit, canon_name, version, record_uuid)? {
            PdmTarget::Fresh => fresh = true,
            PdmTarget::InSync => in_sync = true,
        }
    }
    if fresh && in_sync {
        return Err((
            "pypi_pdm_source_already_exists",
            "PDM extras have inconsistent sources".into(),
        ));
    }
    Ok(if in_sync {
        PdmTarget::InSync
    } else {
        PdmTarget::Fresh
    })
}

fn check_target_unit(
    p: &PdmProject,
    unit: &toml_edit::Table,
    canon_name: &str,
    version: &str,
    record_uuid: &str,
) -> Result<PdmTarget, (&'static str, String)> {
    if unit.get("version").and_then(Item::as_str) != Some(version) {
        return Err((
            "pypi_pdm_lock_package_missing",
            format!(
                "PDM locked version {:?} differs from installed {version}",
                unit.get("version").and_then(Item::as_str)
            ),
        ));
    }
    if ["url", "git", "hg", "svn", "bzr", "editable", "source"]
        .iter()
        .any(|key| unit.contains_key(key))
        || unit.get("path").is_some_and(|item| item.as_str().is_none())
    {
        return Err((
            "pypi_pdm_source_already_exists",
            "PDM package has an existing source".into(),
        ));
    }
    if let Some(path) = unit.get("path").and_then(Item::as_str) {
        return match parse_vendor_path(path) {
            // Ours, same patch generation: the in-sync hot path.
            Some(parts)
                if parts.eco == "pypi"
                    && parts.uuid == record_uuid
                    && crate::utils::pdm_lock::wheel_matches(&parts.leaf, canon_name, version) =>
            {
                Ok(PdmTarget::InSync)
            }
            // Ours, but a STALE patch generation: wiring over it would lose
            // the only recorded registry original — refuse with the repair
            // path (mirrors gem's stale-checksum refusal).
            Some(parts) if parts.eco == "pypi" => Err((
                "pypi_pdm_source_already_exists",
                format!(
                    "{LOCK_FILE} already routes {canon_name} through \
                     .socket/vendor/pypi/{} (an earlier socket-patch vendor); run \
                     `socket-patch vendor --revert` for it and re-vendor",
                    parts.uuid
                ),
            )),
            // A user-authored local path dependency.
            _ => Err((
                "pypi_pdm_source_already_exists",
                format!(
                    "{LOCK_FILE} already declares a local path for {canon_name}; refusing to \
                     overwrite a user-authored source"
                ),
            )),
        };
    }
    // Splicing a hashed entry into a hash-less lock is untested (spike D6:
    // `--no-hashes` no longer exists in pdm 2.27, so this only arises from
    // older tools) — refuse rather than mix verification regimes.
    let hashed_entries = crate::utils::pdm_lock::files_for(&p.lock, unit)
        .map(|arr| {
            !arr.is_empty()
                && arr
                    .iter()
                    .all(|v| v.as_inline_table().is_some_and(|t| t.contains_key("hash")))
        })
        .unwrap_or(false);
    if !hashed_entries {
        return Err((
            "pypi_pdm_lock_no_hashes",
            format!(
                "the {canon_name} entry in {LOCK_FILE} has no sha256-hashed files entries (a \
                 hash-less lock); re-lock with a current pdm so hashes are recorded"
            ),
        ));
    }

    Ok(PdmTarget::Fresh)
}

/// Wire pdm.lock for the vendored wheel: rewrite ONLY the target
/// `[[package]]` unit (the new text is fully computed before any write, then
/// committed atomically). `rel_wheel` is the project-relative wheel path
/// (`.socket/vendor/pypi/<uuid>/<wheel>`, no `./` prefix — the `./` idiom of
/// pdm's own `path` serialization is applied here, fixture-pinned).
#[allow(clippy::too_many_arguments)]
pub async fn wire_pdm(
    p: &PdmProject,
    root: &Path,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
    wheel_file_name: &str,
    wheel_sha256_hex: &str,
    record_uuid: &str,
) -> Result<(Vec<WiringRecord>, PdmMeta), (&'static str, String)> {
    match check_target_guards(p, canon_name, version, record_uuid)? {
        // Defensive: the orchestrator short-circuits in-sync pre-flight and
        // never calls wire on it (we must never re-record our own edit as an
        // "original").
        PdmTarget::InSync => {
            return Err((
                "pypi_pdm_source_already_exists",
                format!(
                    "{LOCK_FILE} already wires {canon_name} to this patch's vendored wheel; \
                     nothing to wire"
                ),
            ))
        }
        PdmTarget::Fresh => {}
    }

    let new_lock = crate::utils::pdm_lock::rewrite_pdm_lock(
        &p.lock_text,
        canon_name,
        version,
        ("path", &format!("./{rel_wheel}")),
        wheel_file_name,
        wheel_sha256_hex,
    )
    .map_err(|detail| ("pypi_pdm_lock_parse_failed", detail))?;
    let fragments = crate::utils::pdm_lock::pdm_lock_edits(&p.lock_text, &new_lock, canon_name)
        .map_err(|detail| ("pypi_pdm_lock_parse_failed", detail))?;
    // Mode-preserving: the lock is a user-owned file we merely edit, so the
    // swapped-in inode must keep its permission bits rather than reset them
    // to umask defaults (same class as the revert leg in common.rs).
    atomic_write_bytes_preserving_mode(&root.join(LOCK_FILE), new_lock.as_bytes())
        .await
        .map_err(|e| {
            (
                "pypi_pdm_write_failed",
                format!("cannot write {LOCK_FILE}: {e}"),
            )
        })?;

    let wiring = fragments
        .into_iter()
        .map(|(old_unit, new_unit)| {
            record(
                LOCK_FILE,
                KIND_LOCK_PACKAGE,
                WiringAction::Rewritten,
                canon_name,
                Some(old_unit),
                new_unit,
            )
        })
        .collect();
    let meta = PdmMeta {
        dep_class: classify_dependency(p, canon_name).to_string(),
        lock_version: p.lock_version.clone(),
        strategy: p.strategy.clone(),
    };
    Ok((wiring, meta))
}

/// Reverse the wiring: restore the verbatim original `[[package]]` unit via
/// the shared fragment-splice revert (drift-tolerant, pdm.lock-only
/// allowlist).
pub async fn revert_pdm(entry: &VendorEntry, root: &Path, dry_run: bool) -> RevertOutcome {
    revert_lock_fragment_splice(entry, root, dry_run, LOCK_FILE, KIND_LOCK_PACKAGE, "pdm").await
}

// ── helpers ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::state::VendorArtifact;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const REL_WHEEL: &str =
        ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl";
    const WHEEL_NAME: &str = "six-1.16.0-py2.py3-none-any.whl";
    /// sha256 of the spike's patched wheel (spikes/pdm fixtures, D1).
    const WHEEL_SHA: &str = "7015f5a42a0f83fd1b7d3ca0ba10d8777a207c19b6ffebb39e2e1c03af6a281b";

    // ── fixture constants ──────────────────────────────────────────────
    // Byte-exact copies of the spikes/pdm/ fixtures (pdm 2.27.0, lock_version
    // 4.5.0; spike date 2026-06-10). The registry locks are tool-generated
    // (`pdm lock`); the vendored expectations carry the D1 path-unit verbatim
    // from the tool-generated `after/` locks with the BEFORE lock's
    // content_hash — the lock-only splice leaves content_hash untouched
    // (spike D2). If these drift from the committed fixtures, the spike dirs
    // are the source of truth.

    /// spikes/pdm/direct-path-wheel/before/pdm.lock (verbatim — identical to
    /// direct-registry/after/pdm.lock).
    const LOCK_DIRECT_REGISTRY: &str = r#"# This file is @generated by PDM.
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

    /// Expected splice output: the six [[package]] unit verbatim from
    /// spikes/pdm/direct-path-wheel/after/pdm.lock (the D1 shape), with the
    /// before lock's [metadata]/content_hash (untouched by the splice, D2).
    const LOCK_DIRECT_VENDORED: &str = r#"# This file is @generated by PDM.
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
files = [{ file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:7015f5a42a0f83fd1b7d3ca0ba10d8777a207c19b6ffebb39e2e1c03af6a281b" }]
path = "./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"
"#;

    /// The transitive "before": [metadata] + python-dateutil unit verbatim
    /// from spikes/pdm/transitive-path/before/pdm.lock, with the six unit
    /// verbatim from direct-registry — the registry resolution pdm produced
    /// when 1.16.0 was current (the production case: the lock resolves the
    /// version being patched; today's resolver picks 1.17.0, spike D3).
    const LOCK_TRANSITIVE_REGISTRY: &str = r#"# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default"]
strategy = ["inherit_metadata"]
lock_version = "4.5.0"
content_hash = "sha256:b35b8b182ba39eb4b0e832cc853dd574342a4a4cb9ed441209d23928a52ae106"

[[metadata.targets]]
requires_python = "==3.14.*"

[[package]]
name = "python-dateutil"
version = "2.9.0.post0"
requires_python = "!=3.0.*,!=3.1.*,!=3.2.*,>=2.7"
summary = "Extensions to the standard Python datetime module"
groups = ["default"]
dependencies = [
    "six>=1.5",
]
files = [
    {file = "python-dateutil-2.9.0.post0.tar.gz", hash = "sha256:37dd54208da7e1cd875388217d5e00ebd4179249f90fb72437e91a35459a0ad3"},
    {file = "python_dateutil-2.9.0.post0-py2.py3-none-any.whl", hash = "sha256:a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427"},
]

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

    /// Expected transitive splice output: the six unit verbatim from
    /// spikes/pdm/transitive-path/after/pdm.lock (identical D1 shape), with
    /// the before lock's content_hash.
    const LOCK_TRANSITIVE_VENDORED: &str = r#"# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default"]
strategy = ["inherit_metadata"]
lock_version = "4.5.0"
content_hash = "sha256:b35b8b182ba39eb4b0e832cc853dd574342a4a4cb9ed441209d23928a52ae106"

[[metadata.targets]]
requires_python = "==3.14.*"

[[package]]
name = "python-dateutil"
version = "2.9.0.post0"
requires_python = "!=3.0.*,!=3.1.*,!=3.2.*,>=2.7"
summary = "Extensions to the standard Python datetime module"
groups = ["default"]
dependencies = [
    "six>=1.5",
]
files = [
    {file = "python-dateutil-2.9.0.post0.tar.gz", hash = "sha256:37dd54208da7e1cd875388217d5e00ebd4179249f90fb72437e91a35459a0ad3"},
    {file = "python_dateutil-2.9.0.post0-py2.py3-none-any.whl", hash = "sha256:a8b2bc7bffae282281c8140a97d3aa9c14da0b136dfe83f850eea9a5f7470427"},
]

[[package]]
name = "six"
version = "1.16.0"
requires_python = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
summary = "Python 2 and 3 compatibility utilities"
groups = ["default"]
files = [{ file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:7015f5a42a0f83fd1b7d3ca0ba10d8777a207c19b6ffebb39e2e1c03af6a281b" }]
path = "./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"
"#;

    /// The D6-captured static_urls shape: strategy gains "static_urls" and
    /// files entries become `{url = ..., hash = ...}` (content_hash is
    /// IDENTICAL to the default-strategy lock — D6). Assembled from the D6
    /// findings text; the splice into it was verified green by the spike.
    const LOCK_STATIC_URLS_REGISTRY: &str = r#"# This file is @generated by PDM.
# It is not intended for manual editing.

[metadata]
groups = ["default"]
strategy = ["inherit_metadata", "static_urls"]
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
    {url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"},
    {url = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},
]
"#;

    const PYPROJECT_DIRECT: &str = r#"[project]
name = "direct-registry"
version = "0.1.0"
dependencies = ["six==1.16.0"]
requires-python = "==3.14.*"

[tool.pdm]
distribution = false
"#;

    const PYPROJECT_TRANSITIVE: &str = r#"[project]
name = "transitive-registry"
version = "0.1.0"
dependencies = ["python-dateutil==2.9.0.post0"]
requires-python = "==3.14.*"

[tool.pdm]
distribution = false
"#;

    async fn write_project(lock: &str, pyproject: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("pdm.lock"), lock)
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("pyproject.toml"), pyproject)
            .await
            .unwrap();
        tmp
    }

    async fn read_lock(root: &Path) -> String {
        tokio::fs::read_to_string(root.join("pdm.lock"))
            .await
            .unwrap()
    }

    fn entry_for(wiring: Vec<WiringRecord>, meta: PdmMeta) -> VendorEntry {
        VendorEntry {
            ecosystem: "pypi".into(),
            base_purl: "pkg:pypi/six@1.16.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: REL_WHEEL.into(),
                sha256: WHEEL_SHA.into(),
                size: Some(11053),
                platform_locked: None,
                file_inventory: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("pdm".into()),
            uv: None,
            pnpm: None,
            poetry: None,
            pdm: Some(meta),
            pipenv: None,
        }
    }

    async fn wire_default(p: &PdmProject, root: &Path) -> (Vec<WiringRecord>, PdmMeta) {
        wire_pdm(
            p, root, "six", "1.16.0", REL_WHEEL, WHEEL_NAME, WHEEL_SHA, UUID,
        )
        .await
        .unwrap()
    }

    /// The load-bearing oracle: wiring the registry lock must produce the
    /// D1-captured local-file unit BYTE-IDENTICALLY (direct and transitive),
    /// leaving pyproject and content_hash untouched.
    #[tokio::test]
    async fn wiring_matches_fixtures_byte_identically() {
        let cases = [
            (
                LOCK_DIRECT_REGISTRY,
                LOCK_DIRECT_VENDORED,
                PYPROJECT_DIRECT,
                "direct",
            ),
            (
                LOCK_TRANSITIVE_REGISTRY,
                LOCK_TRANSITIVE_VENDORED,
                PYPROJECT_TRANSITIVE,
                "transitive",
            ),
        ];
        for (before, after, pyproject, dep_class) in cases {
            let tmp = write_project(before, pyproject).await;
            let p = load_pdm_project(tmp.path()).await.unwrap();
            assert!(p.warnings.is_empty(), "{:?}", p.warnings);
            assert_eq!(p.lock_version, "4.5.0");
            assert_eq!(p.strategy, vec!["inherit_metadata".to_string()]);
            assert_eq!(classify_dependency(&p, "six"), dep_class);
            assert_eq!(
                check_target_guards(&p, "six", "1.16.0", UUID).unwrap(),
                PdmTarget::Fresh
            );

            let (wiring, meta) = wire_default(&p, tmp.path()).await;
            assert_eq!(
                read_lock(tmp.path()).await,
                after,
                "{dep_class}: pdm.lock must byte-match the D1 splice"
            );
            // pyproject + content_hash are NEVER touched (lock-only splice).
            assert_eq!(
                tokio::fs::read_to_string(tmp.path().join("pyproject.toml"))
                    .await
                    .unwrap(),
                pyproject
            );

            assert_eq!(wiring.len(), 1);
            assert_eq!(wiring[0].kind, KIND_LOCK_PACKAGE);
            assert_eq!(wiring[0].action, WiringAction::Rewritten);
            assert_eq!(wiring[0].file, "pdm.lock");
            assert_eq!(wiring[0].key.as_deref(), Some("six"));
            assert_eq!(meta.dep_class, dep_class);
            assert_eq!(meta.lock_version, "4.5.0");
            assert_eq!(meta.strategy, vec!["inherit_metadata".to_string()]);
        }
    }

    /// D6: a `{file = ..., hash = ...}` entry is accepted inside a
    /// static_urls lock — the same D1 splice applies and the strategy is
    /// recorded into the meta.
    #[tokio::test]
    async fn static_urls_strategy_lock_splices_with_the_same_shape() {
        let tmp = write_project(LOCK_STATIC_URLS_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        assert_eq!(
            p.strategy,
            vec!["inherit_metadata".to_string(), "static_urls".to_string()]
        );
        let (_, meta) = wire_default(&p, tmp.path()).await;
        assert_eq!(meta.strategy, p.strategy);

        // Same expected text as the direct splice, modulo the strategy line.
        let expected = LOCK_DIRECT_VENDORED.replace(
            "strategy = [\"inherit_metadata\"]",
            "strategy = [\"inherit_metadata\", \"static_urls\"]",
        );
        assert_eq!(read_lock(tmp.path()).await, expected);
    }

    /// D6 (partial leg): strategy sets outside the fixtures refuse — their
    /// unit shapes were never captured.
    #[tokio::test]
    async fn legacy_declarations_are_direct_and_bad_strategy_types_refuse() {
        for section in ["dependencies", "dev-dependencies", "feature-dependencies"] {
            let manifest = format!(
                "[tool.pdm.{section}]\nsix = {{version = '==1.16.0', extras = ['feature']}}\n"
            );
            let tmp = write_project(LOCK_DIRECT_REGISTRY, &manifest).await;
            let project = load_pdm_project(tmp.path()).await.unwrap();
            assert_eq!(classify_dependency(&project, "six"), "direct");
        }
        for strategy in ["42", "['inherit_metadata', 42]"] {
            let lock = LOCK_DIRECT_REGISTRY.replace("[\"inherit_metadata\"]", strategy);
            let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
            assert_eq!(
                load_pdm_project(tmp.path()).await.unwrap_err().0,
                "pypi_pdm_lock_strategy_unsupported"
            );
            assert_eq!(read_lock(tmp.path()).await, lock);
        }
    }

    #[tokio::test]
    async fn unsupported_strategy_refuses() {
        for flag in ["unknown_strategy", "no_hashes"] {
            let lock = LOCK_DIRECT_REGISTRY.replace(
                "strategy = [\"inherit_metadata\"]",
                &format!("strategy = [\"inherit_metadata\", \"{flag}\"]"),
            );
            let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
            let err = load_pdm_project(tmp.path()).await.unwrap_err();
            assert_eq!(err.0, "pypi_pdm_lock_strategy_unsupported", "{flag}");
            assert!(err.1.contains(flag), "{}", err.1);
        }
    }

    /// D6 (partial leg): hash-less files entries refuse — splicing a hashed
    /// entry into a hash-less lock is untested.
    #[tokio::test]
    async fn hashless_lock_refuses() {
        // An entry without a hash key.
        let lock = LOCK_DIRECT_REGISTRY.replace(
            "    {file = \"six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254\"},\n    {file = \"six-1.16.0.tar.gz\", hash = \"sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926\"},",
            "    {file = \"six-1.16.0-py2.py3-none-any.whl\"},",
        );
        let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.16.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_no_hashes");

        // No files array at all.
        let lock = format!(
            "{}\n[[package]]\nname = \"hashless\"\nversion = \"1.0.0\"\nsummary = \"x\"\ngroups = [\"default\"]\n",
            LOCK_DIRECT_REGISTRY.trim_end()
        );
        let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "hashless", "1.0.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_no_hashes");
    }

    #[tokio::test]
    async fn guards_refuse_parse_version_missing_forked_and_sources() {
        // unreadable / unparseable lock
        let tmp = tempfile::tempdir().unwrap();
        let err = load_pdm_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_parse_failed");
        let tmp = write_project("[[package]\nbroken", PYPROJECT_DIRECT).await;
        let err = load_pdm_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_parse_failed");

        // lock_version absent / outside the series
        let tmp = write_project("[[package]]\nname = \"six\"\n", PYPROJECT_DIRECT).await;
        let err = load_pdm_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_version_unsupported");
        for bad in ["3.1", "4.0", "4.1", "4.2", "4.6.0", "5.0.0", "garbage"] {
            let lock = LOCK_DIRECT_REGISTRY.replace(
                "lock_version = \"4.5.0\"",
                &format!("lock_version = \"{bad}\""),
            );
            let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
            let err = load_pdm_project(tmp.path()).await.unwrap_err();
            assert_eq!(err.0, "pypi_pdm_lock_version_unsupported", "{bad}");
        }

        // target absent from the lock
        let tmp = write_project(LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "absent-pkg", "1.0.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_package_missing");

        // forked: the same name at two versions
        let fork = format!(
            "{LOCK_DIRECT_REGISTRY}\n[[package]]\nname = \"six\"\nversion = \"1.17.0\"\nsummary = \"x\"\ngroups = [\"default\"]\nfiles = [\n    {{file = \"six-1.17.0-py2.py3-none-any.whl\", hash = \"sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\"}},\n]\n"
        );
        let tmp = write_project(&fork, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.16.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_forked_package");

        // single unit at a DIFFERENT version than the patch target
        let tmp = write_project(LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.17.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_lock_package_missing");
        assert!(err.1.contains("1.16.0"), "{}", err.1);

        // user-authored local path dependency
        let user = LOCK_DIRECT_VENDORED.replace(
            "path = \"./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl\"",
            "path = \"./vendor/six-1.16.0-py2.py3-none-any.whl\"",
        );
        let tmp = write_project(&user, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.16.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_source_already_exists");
        assert!(err.1.contains("user-authored"), "{}", err.1);

        // user-declared direct URL source
        let url_unit = LOCK_DIRECT_REGISTRY.replace(
            "requires_python = \">=2.7, !=3.0.*, !=3.1.*, !=3.2.*\"\nsummary",
            "requires_python = \">=2.7, !=3.0.*, !=3.1.*, !=3.2.*\"\nurl = \"https://example.com/six-1.16.0-py2.py3-none-any.whl\"\nsummary",
        );
        let tmp = write_project(&url_unit, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.16.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_source_already_exists");

        // wire re-runs the guards itself (refusal before any write)
        let before = read_lock(tmp.path()).await;
        let err = wire_pdm(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            UUID,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_pdm_source_already_exists");
        assert_eq!(
            read_lock(tmp.path()).await,
            before,
            "refusal writes nothing"
        );
    }

    #[tokio::test]
    async fn unknown_lock_version_refuses_before_writing() {
        let lock = LOCK_DIRECT_REGISTRY.replace("4.5.0", "4.6.0");
        let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
        assert_eq!(
            load_pdm_project(tmp.path()).await.unwrap_err().0,
            "pypi_pdm_lock_version_unsupported"
        );
        assert_eq!(read_lock(tmp.path()).await, lock);
    }

    /// Re-running vendor on an already-wired lock with the SAME uuid is the
    /// in-sync hot path: the caller synthesizes AlreadyPatched and records
    /// nothing; a DIFFERENT uuid refuses with `vendor --revert` guidance.
    #[tokio::test]
    async fn rerun_same_uuid_in_sync_and_stale_uuid_refuses_with_guidance() {
        let tmp = write_project(LOCK_DIRECT_VENDORED, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        assert_eq!(
            check_target_guards(&p, "six", "1.16.0", UUID).unwrap(),
            PdmTarget::InSync
        );

        let stale_uuid = "00000000-0000-4000-8000-000000000000";
        let err = check_target_guards(&p, "six", "1.16.0", stale_uuid).unwrap_err();
        assert_eq!(err.0, "pypi_pdm_source_already_exists");
        assert!(err.1.contains("--revert"), "{}", err.1);
        assert!(err.1.contains(UUID), "names the wired uuid: {}", err.1);
    }

    /// Defensive wire-time InSync refusal: the orchestrator short-circuits
    /// in-sync pre-flight and never calls wire on it, but if [`wire_pdm`] is
    /// ever reached on an already-wired lock it must refuse rather than
    /// re-record our own vendored unit as the ledger "original" — revert
    /// would then restore vendored state instead of the registry state.
    #[tokio::test]
    async fn wire_on_in_sync_lock_refuses_without_writing() {
        let tmp = write_project(LOCK_DIRECT_VENDORED, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        assert_eq!(
            check_target_guards(&p, "six", "1.16.0", UUID).unwrap(),
            PdmTarget::InSync,
            "precondition: the fixture is the in-sync hot path"
        );

        let err = wire_pdm(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            UUID,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_pdm_source_already_exists");
        assert!(err.1.contains("nothing to wire"), "{}", err.1);
        assert_eq!(
            read_lock(tmp.path()).await,
            LOCK_DIRECT_VENDORED,
            "refusal writes nothing — the ledger's only original survives"
        );
    }

    #[tokio::test]
    async fn classify_dependency_covers_every_declaration_surface() {
        let p = |pyproject: Option<&str>| PdmProject {
            lock_text: String::new(),
            lock: DocumentMut::new(),
            pyproject_text: pyproject.map(str::to_string),
            lock_version: "4.5.0".into(),
            strategy: Vec::new(),
            warnings: Vec::new(),
        };
        // PEP 621 dependency specs (with PEP 503 canonicalization).
        assert_eq!(
            classify_dependency(&p(Some(PYPROJECT_DIRECT)), "six"),
            "direct"
        );
        assert_eq!(
            classify_dependency(
                &p(Some("[project]\ndependencies = [\"Six_Pkg>=1\"]\n")),
                "six-pkg"
            ),
            "direct"
        );
        assert_eq!(
            classify_dependency(
                &p(Some(
                    "[project.optional-dependencies]\nextra = [\"six==1.16.0\"]\n"
                )),
                "six"
            ),
            "direct"
        );
        // tool.pdm dev groups + PEP 735 dependency-groups.
        assert_eq!(
            classify_dependency(
                &p(Some("[tool.pdm.dev-dependencies]\ntest = [\"six>=1\"]\n")),
                "six"
            ),
            "direct"
        );
        assert_eq!(
            classify_dependency(&p(Some("[dependency-groups]\ndev = [\"six\"]\n")), "six"),
            "direct"
        );
        // Not declared / no pyproject → transitive (diagnostics-only).
        assert_eq!(
            classify_dependency(&p(Some(PYPROJECT_TRANSITIVE)), "six"),
            "transitive"
        );
        assert_eq!(classify_dependency(&p(None), "six"), "transitive");
    }

    /// The documented degrade contract's other half: a present-but-UNPARSEABLE
    /// pyproject classifies as "transitive" instead of refusing (the missing
    /// half is covered above — classification is diagnostics-only, the splice
    /// is identical either way). Degenerate group shapes — a group value that
    /// is not an array, a `dependency-groups` that is not table-like — degrade
    /// the same way rather than panicking or misclassifying.
    #[test]
    fn classify_dependency_degrades_on_unparseable_and_degenerate_pyproject() {
        let p = |pyproject: Option<&str>| PdmProject {
            lock_text: String::new(),
            lock: DocumentMut::new(),
            pyproject_text: pyproject.map(str::to_string),
            lock_version: "4.5.0".into(),
            strategy: Vec::new(),
            warnings: Vec::new(),
        };
        // Unparseable TOML: the parse-fail branch, never a refusal.
        assert_eq!(
            classify_dependency(&p(Some("not = valid = toml [")), "six"),
            "transitive"
        );
        // A dependency-group whose value is not an array is skipped, even
        // though its string names the package.
        assert_eq!(
            classify_dependency(&p(Some("[dependency-groups]\ndev = \"six\"\n")), "six"),
            "transitive"
        );
        // A `dependency-groups` key that is not table-like is skipped whole.
        assert_eq!(
            classify_dependency(&p(Some("dependency-groups = 3\n")), "six"),
            "transitive"
        );
    }

    /// Dry-run purity: load + classify + guards are pure reads, mirroring
    /// pypi_uv's compute/write split (the orchestrator never calls wire on a
    /// dry run).
    #[tokio::test]
    async fn load_classify_and_guards_write_nothing() {
        let tmp = write_project(LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let _ = classify_dependency(&p, "six");
        let _ = check_target_guards(&p, "six", "1.16.0", UUID).unwrap();
        assert_eq!(read_lock(tmp.path()).await, LOCK_DIRECT_REGISTRY);
        assert_eq!(
            tokio::fs::read_to_string(tmp.path().join("pyproject.toml"))
                .await
                .unwrap(),
            PYPROJECT_DIRECT
        );
    }

    #[tokio::test]
    async fn revert_round_trip_restores_lock_byte_identically() {
        for (before, pyproject) in [
            (LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT),
            (LOCK_TRANSITIVE_REGISTRY, PYPROJECT_TRANSITIVE),
        ] {
            let tmp = write_project(before, pyproject).await;
            let p = load_pdm_project(tmp.path()).await.unwrap();
            let (wiring, meta) = wire_default(&p, tmp.path()).await;
            let entry = entry_for(wiring, meta);

            let outcome = revert_pdm(&entry, tmp.path(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert_eq!(read_lock(tmp.path()).await, before, "byte-identical revert");
        }
    }

    /// The lock file is user-owned: wiring the splice must not reset its
    /// permission bits (the `package_json/update.rs` mode-reset bug, same
    /// class — see `atomic_write_bytes_preserving_mode`; the revert leg is
    /// covered in common.rs).
    #[cfg(unix)]
    #[tokio::test]
    async fn wire_preserves_lock_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = write_project(LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let lock_path = tmp.path().join("pdm.lock");
        let mut perms = std::fs::metadata(&lock_path).unwrap().permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&lock_path, perms).unwrap();

        let p = load_pdm_project(tmp.path()).await.unwrap();
        wire_default(&p, tmp.path()).await;
        assert_eq!(read_lock(tmp.path()).await, LOCK_DIRECT_VENDORED);
        let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "wiring must preserve the lock file's permission bits"
        );
    }

    /// A write failure — a read-only project dir, so the atomic stage+rename
    /// cannot create its stage sibling (the writable-parent invariant of
    /// `atomic_write_bytes_preserving_mode`) — maps to the
    /// orchestrator-surfaced `pypi_pdm_write_failed`, and the lock keeps its
    /// pre-wire bytes.
    #[cfg(unix)]
    #[tokio::test]
    async fn wire_write_failure_maps_to_pypi_pdm_write_failed() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            eprintln!("skipping: running as root, 0o555 does not block writes");
            return;
        }

        let tmp = write_project(LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let res = wire_pdm(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            UUID,
        )
        .await;

        // Restore before any assertion can unwind, so the tempdir cleans up.
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = res.unwrap_err();
        assert_eq!(err.0, "pypi_pdm_write_failed");
        assert!(err.1.starts_with("cannot write pdm.lock"), "{}", err.1);
        assert_eq!(
            read_lock(tmp.path()).await,
            LOCK_DIRECT_REGISTRY,
            "a failed write leaves the lock byte-untouched"
        );
    }

    #[tokio::test]
    async fn crlf_and_noncanonical_spacing_round_trip() {
        for lock in [
            LOCK_DIRECT_REGISTRY.replace('\n', "\r\n"),
            LOCK_DIRECT_REGISTRY.replace("name = ", "name="),
            LOCK_DIRECT_REGISTRY.replace("files = [", "files=["),
        ] {
            let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
            let project = load_pdm_project(tmp.path()).await.unwrap();
            let (wiring, meta) = wire_default(&project, tmp.path()).await;
            let rewritten = read_lock(tmp.path()).await;
            assert!(rewritten.contains(REL_WHEEL));
            if lock.contains("\r\n") {
                assert!(!rewritten.replace("\r\n", "").contains('\n'));
            }
            assert!(
                revert_pdm(&entry_for(wiring, meta), tmp.path(), false)
                    .await
                    .success
            );
            assert_eq!(read_lock(tmp.path()).await, lock);
        }
    }

    /// mkfifo(2) directly rather than shelling out to the `mkfifo` binary —
    /// same helper as the pypi.rs / setup/pypi detect.rs FIFO tests:
    /// fork/exec flakes under heavy parallel load and the syscall needs no
    /// process at all.
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

    /// A FIFO planted as `pdm.lock` (or `pyproject.toml`) must not wedge the
    /// load: `detect_pypi_flavor`'s routing probes are metadata-only (a FIFO
    /// stats fine, and the pdm route short-circuits before detection's own
    /// guarded pyproject read), so the backend's raw `read_to_string`
    /// open(2) is the FIRST open — it waits for a writer that never comes,
    /// wedging every pdm-project vendor run indefinitely. Same
    /// `open_regular_file` guard class as the sibling vendor backends. The
    /// lock read must refuse fast; the diagnostics-only pyproject read must
    /// degrade to "no pyproject" (transitive) instead.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_or_pyproject_does_not_wedge_load() {
        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);

        // FIFO squatting as pdm.lock: load must refuse fast.
        let tmp = tempfile::tempdir().unwrap();
        let fifo = tmp.path().join("pdm.lock");
        mkfifo(&fifo);
        tokio::fs::write(tmp.path().join("pyproject.toml"), PYPROJECT_DIRECT)
            .await
            .unwrap();
        let Ok(res) = tokio::time::timeout(deadline, load_pdm_project(tmp.path())).await else {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("load_pdm_project must complete promptly with a FIFO pdm.lock");
        };
        assert_eq!(res.unwrap_err().0, "pypi_pdm_lock_parse_failed");

        // FIFO squatting as pyproject.toml next to a valid lock: pyproject
        // is diagnostics-only, so the load must succeed without it.
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("pdm.lock"), LOCK_DIRECT_REGISTRY)
            .await
            .unwrap();
        let fifo = tmp.path().join("pyproject.toml");
        mkfifo(&fifo);
        let Ok(res) = tokio::time::timeout(deadline, load_pdm_project(tmp.path())).await else {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("load_pdm_project must complete promptly with a FIFO pyproject.toml");
        };
        let p = res.unwrap();
        assert!(p.pyproject_text.is_none(), "FIFO reads as no pyproject");
        assert_eq!(classify_dependency(&p, "six"), "transitive");
    }

    #[tokio::test]
    async fn revert_dry_run_changes_nothing() {
        let tmp = write_project(LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_default(&p, tmp.path()).await;
        let wired = read_lock(tmp.path()).await;

        let outcome = revert_pdm(&entry_for(wiring, meta), tmp.path(), true).await;
        assert!(outcome.success);
        assert_eq!(read_lock(tmp.path()).await, wired, "dry run must not write");
    }

    /// SECURITY: a poisoned state.json wiring record naming any file other
    /// than pdm.lock is skipped fail-closed — the named path is never read
    /// or written.
    #[tokio::test]
    async fn revert_allowlist_skips_unexpected_files_fail_closed() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("pdm.lock"), LOCK_DIRECT_REGISTRY)
            .await
            .unwrap();
        let precious = outer.path().join("precious.txt");
        tokio::fs::write(&precious, "keep me intact\n")
            .await
            .unwrap();

        for bad in ["pyproject.toml", "../precious.txt", "/etc/hosts"] {
            let wiring = vec![WiringRecord {
                file: bad.to_string(),
                kind: KIND_LOCK_PACKAGE.to_string(),
                action: WiringAction::Rewritten,
                key: Some("six".into()),
                original: Some(serde_json::json!("malicious payload")),
                new: Some(serde_json::json!("keep me intact")),
            }];
            let meta = PdmMeta {
                dep_class: "direct".into(),
                lock_version: "4.5.0".into(),
                strategy: vec!["inherit_metadata".into()],
            };
            let outcome = revert_pdm(&entry_for(wiring, meta), &root, false).await;
            assert!(
                outcome.success,
                "skipped fail-closed, not a hard error: {bad}"
            );
            assert!(
                outcome
                    .warnings
                    .iter()
                    .any(|w| w.code == "vendor_lock_entry_drifted"),
                "skip surfaced for {bad}: {:?}",
                outcome.warnings
            );
        }
        assert_eq!(
            tokio::fs::read_to_string(&precious).await.unwrap(),
            "keep me intact\n",
            "out-of-tree file byte-untouched"
        );
        assert_eq!(
            tokio::fs::read_to_string(root.join("pdm.lock"))
                .await
                .unwrap(),
            LOCK_DIRECT_REGISTRY,
            "the lock itself is untouched too (no record matched it)"
        );
    }

    /// A third-party edit to the unit we wrote (e.g. `pdm update six`
    /// reverted it to registry shape — spike D5) is left alone with a drift
    /// warning; unknown wiring kinds from a newer ledger degrade the same way.
    #[tokio::test]
    async fn revert_warns_and_skips_on_drifted_fragment_and_unknown_kind() {
        let tmp = write_project(LOCK_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        let (mut wiring, meta) = wire_default(&p, tmp.path()).await;
        wiring.push(WiringRecord {
            file: "pdm.lock".into(),
            kind: "pdm_future_kind".into(),
            action: WiringAction::Added,
            key: Some("six".into()),
            original: None,
            new: Some(serde_json::json!("x")),
        });

        // Drift: someone re-hashed the vendored files entry.
        let drifted = read_lock(tmp.path())
            .await
            .replace(WHEEL_SHA, &"0".repeat(64));
        tokio::fs::write(tmp.path().join("pdm.lock"), &drifted)
            .await
            .unwrap();

        let outcome = revert_pdm(&entry_for(wiring, meta), tmp.path(), false).await;
        assert!(outcome.success);
        assert_eq!(
            outcome
                .warnings
                .iter()
                .filter(|w| w.code == "vendor_lock_entry_drifted")
                .count(),
            2,
            "drifted fragment + unknown kind: {:?}",
            outcome.warnings
        );
        assert_eq!(
            read_lock(tmp.path()).await,
            drifted,
            "drifted lock left alone"
        );
    }
}
