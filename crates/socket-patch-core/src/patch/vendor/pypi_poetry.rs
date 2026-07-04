//! poetry-project wiring: a lock-ONLY `[[package]]` splice (poetry.lock
//! lock-versions 2.0 and 2.1).
//!
//! Unlike uv (whose sources entry must be paired into pyproject.toml), poetry
//! installs are 100% lock-driven and `metadata.content-hash` covers ONLY the
//! pyproject — so the vendored wheel is wired by rewriting just the target
//! `[[package]]` unit (files[] → the single patched-wheel hash, plus a
//! `[package.source] type = "file"` table) and touching nothing else. The
//! spike proved this splice passes `poetry install`/`sync`/`check --lock`
//! byte-stably on BOTH supported majors (Poetry 2.4.1 = lock 2.1, Poetry
//! 1.8.5 = lock 2.0), is hash-fail-closed against a tampered wheel, and works
//! for direct AND transitive deps — see `spikes/poetry/` and the poetry
//! section of `spikes/PHASE0-V2-FINDINGS.txt`.
//!
//! Drift caveat (spike P5): `poetry update <pkg>`, 2.x `poetry lock
//! --regenerate` and 1.x plain `poetry lock` silently revert the splice with
//! exit 0; the lock's files[] hash is the drift oracle. `pyproject.toml` and
//! `metadata.content-hash` are NEVER written by this backend.

use std::path::Path;

use toml_edit::{DocumentMut, Item};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::atomic_write_bytes;

use super::common::{
    item_get, lock_units_named, pep621_declared_names, record, revert_lock_fragment_splice,
    unit_has_canon_name,
};
use super::path::parse_vendor_path;
use super::state::{PoetryMeta, VendorEntry, WiringAction, WiringRecord};
use super::toml_surgery::{find_unit_span, package_unit_lines, replace_files_array};
use super::{RevertOutcome, VendorWarning};

/// The only file this backend ever writes (and the revert allowlist).
const LOCK_FILE: &str = "poetry.lock";

/// The `WiringRecord.kind` discriminator this backend owns.
const KIND_LOCK_PACKAGE: &str = "poetry_lock_package";

/// A loaded-and-guard-checked poetry project.
#[derive(Debug)]
pub(super) struct PoetryProject {
    /// Verbatim poetry.lock text (the surgery substrate).
    pub lock_text: String,
    /// Parsed lock (guard checks only — every edit is text surgery).
    pub lock: DocumentMut,
    /// pyproject.toml content when present. NEVER written; read only to
    /// classify the dependency for [`PoetryMeta::dep_class`] diagnostics.
    pub pyproject_text: Option<String>,
    /// poetry.lock `[metadata] lock-version` (recorded into [`PoetryMeta`]).
    pub lock_version: String,
    /// Non-fatal advisories raised during load (untested lock version).
    pub warnings: Vec<VendorWarning>,
}

/// What the target `[[package]]` unit already looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PoetryTarget {
    /// Registry-shaped: proceed to build the wheel and wire.
    Fresh,
    /// Already wired to THIS patch uuid — the caller synthesizes an
    /// AlreadyPatched success, builds nothing, and records nothing (the
    /// first run's ledger entry holds the only copy of the original).
    InSync,
}

/// Read + parse poetry.lock and run every project-level guard. Refuses
/// before ANY write — the orchestrator runs this (and the target guards)
/// before the wheel is built, so a refusal leaves the tree byte-untouched.
pub(super) async fn load_poetry_project(
    root: &Path,
) -> Result<PoetryProject, (&'static str, String)> {
    let lock_text = tokio::fs::read_to_string(root.join(LOCK_FILE))
        .await
        .map_err(|e| {
            (
                "pypi_poetry_lock_parse_failed",
                format!("cannot read {LOCK_FILE}: {e}"),
            )
        })?;
    let lock: DocumentMut = lock_text.parse().map_err(|e| {
        (
            "pypi_poetry_lock_parse_failed",
            format!("{LOCK_FILE} does not parse: {e}"),
        )
    })?;

    let lock_version = lock
        .get("metadata")
        .and_then(|m| item_get(m, "lock-version"))
        .and_then(Item::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            (
                "pypi_poetry_lock_version_unsupported",
                format!("{LOCK_FILE} has no [metadata] lock-version; only 2.x locks are supported"),
            )
        })?;
    let mut warnings = Vec::new();
    match lock_version.as_str() {
        // The fixture-tested versions (Poetry 1.8.x writes 2.0, 2.x writes 2.1).
        "2.0" | "2.1" => {}
        // A newer 2.x minor keeps the shapes we rewrite (additive schema), so
        // it warns instead of refusing; `poetry check --lock` is the backstop.
        v if is_newer_2x(v) => warnings.push(VendorWarning::new(
            "pypi_poetry_lock_version_untested",
            format!(
                "poetry.lock lock-version {v} is newer than the fixture-tested 2.0/2.1; \
                 verify with `poetry check --lock` after vendoring"
            ),
        )),
        v => {
            return Err((
                "pypi_poetry_lock_version_unsupported",
                format!(
                    "poetry.lock lock-version {v:?} is not a supported 2.x lock; re-lock with \
                     Poetry >= 1.3"
                ),
            ))
        }
    }

    let pyproject_text = tokio::fs::read_to_string(root.join("pyproject.toml"))
        .await
        .ok();
    Ok(PoetryProject {
        lock_text,
        lock,
        pyproject_text,
        lock_version,
        warnings,
    })
}

/// `"direct"` iff the package is declared in the pyproject —
/// `[tool.poetry.dependencies]` / `dev-dependencies` /
/// `[tool.poetry.group.*.dependencies]` keys, or PEP 621
/// `[project] dependencies` / `optional-dependencies` specs — else
/// `"transitive"`. Diagnostics ONLY ([`PoetryMeta::dep_class`]): the splice
/// is identical either way, so a missing/unparseable pyproject degrades to
/// `"transitive"` instead of refusing.
fn classify_dependency(p: &PoetryProject, canon_name: &str) -> &'static str {
    let Some(text) = p.pyproject_text.as_deref() else {
        return "transitive";
    };
    let Ok(doc) = text.parse::<DocumentMut>() else {
        return "transitive";
    };
    let mut declared: Vec<String> = Vec::new();
    if let Some(poetry) = doc.get("tool").and_then(|t| item_get(t, "poetry")) {
        for table in ["dependencies", "dev-dependencies"] {
            if let Some(deps) = item_get(poetry, table).and_then(Item::as_table_like) {
                declared.extend(deps.iter().map(|(k, _)| k.to_string()));
            }
        }
        if let Some(groups) = item_get(poetry, "group").and_then(Item::as_table_like) {
            for (_, group) in groups.iter() {
                if let Some(deps) = item_get(group, "dependencies").and_then(Item::as_table_like) {
                    declared.extend(deps.iter().map(|(k, _)| k.to_string()));
                }
            }
        }
    }
    pep621_declared_names(&doc, &mut declared);
    if declared
        .iter()
        .any(|n| canonicalize_pypi_name(n) == canon_name)
    {
        "direct"
    } else {
        "transitive"
    }
}

/// Target-specific guards (also re-run by [`wire_poetry`] right before
/// writing). The orchestrator runs them pre-flight so a refusal happens
/// before the wheel artifact is built. Lock names match by PEP 503 canonical
/// form (spike P8: the lock records `pyyaml` for a `PyYAML` pyproject spec).
pub(super) fn check_target_guards(
    p: &PoetryProject,
    canon_name: &str,
    version: &str,
    record_uuid: &str,
) -> Result<PoetryTarget, (&'static str, String)> {
    let units = lock_units_named(&p.lock, canon_name);
    if units.is_empty() {
        return Err((
            "pypi_poetry_lock_package_missing",
            format!(
                "{LOCK_FILE} has no [[package]] entry for {canon_name}; run `poetry lock` first"
            ),
        ));
    }
    // Marker-forked resolutions list the same name at multiple versions; one
    // surgical rewrite would mispin the other forks — refuse (mirrors uv).
    if units.len() > 1 {
        return Err((
            "pypi_poetry_lock_forked_package",
            format!(
                "{LOCK_FILE} resolves {canon_name} at multiple versions/markers (a forked \
                 resolution); vendoring would mispin the other forks"
            ),
        ));
    }
    let unit = units[0];

    if let Some(source) = unit.get("source") {
        let url = source
            .as_table_like()
            .and_then(|t| t.get("url"))
            .and_then(Item::as_str)
            .unwrap_or("");
        return match parse_vendor_path(url) {
            // Ours, same patch generation: the in-sync hot path.
            Some(parts) if parts.eco == "pypi" && parts.uuid == record_uuid => {
                Ok(PoetryTarget::InSync)
            }
            // Ours, but a STALE patch generation: wiring over it would lose
            // the only recorded registry original — refuse with the repair
            // path (mirrors gem's stale-checksum refusal).
            Some(parts) if parts.eco == "pypi" => Err((
                "pypi_poetry_source_already_exists",
                format!(
                    "{LOCK_FILE} already routes {canon_name} through \
                     .socket/vendor/pypi/{} (an earlier socket-patch vendor); run \
                     `socket-patch vendor --revert` for it and re-vendor",
                    parts.uuid
                ),
            )),
            // A user-authored source (path/url/git/private registry).
            _ => Err((
                "pypi_poetry_source_already_exists",
                format!(
                    "{LOCK_FILE} already declares a [package.source] for {canon_name}; \
                     refusing to overwrite a user-authored source"
                ),
            )),
        };
    }

    // The splice keeps the unit's version line verbatim, so the lock must
    // already resolve the version being patched (lock/venv drift otherwise).
    let locked_version = unit.get("version").and_then(Item::as_str).unwrap_or("");
    if locked_version != version {
        return Err((
            "pypi_poetry_lock_package_missing",
            format!(
                "{LOCK_FILE} resolves {canon_name} at {locked_version:?}, not the patched \
                 {version}; re-lock so the lock matches the installed version"
            ),
        ));
    }
    Ok(PoetryTarget::Fresh)
}

/// Wire poetry.lock for the vendored wheel: rewrite ONLY the target
/// `[[package]]` unit (the new text is fully computed before any write, then
/// committed atomically). `rel_wheel` is the project-relative wheel path
/// (`.socket/vendor/pypi/<uuid>/<wheel>`, no `./` prefix — the lock url is
/// recorded exactly as poetry itself writes it, fixture-pinned).
#[allow(clippy::too_many_arguments)]
pub(super) async fn wire_poetry(
    p: &PoetryProject,
    root: &Path,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
    wheel_file_name: &str,
    wheel_sha256_hex: &str,
    record_uuid: &str,
) -> Result<(Vec<WiringRecord>, PoetryMeta), (&'static str, String)> {
    match check_target_guards(p, canon_name, version, record_uuid)? {
        // Defensive: the orchestrator short-circuits in-sync pre-flight and
        // never calls wire on it (we must never re-record our own edit as an
        // "original").
        PoetryTarget::InSync => {
            return Err((
                "pypi_poetry_source_already_exists",
                format!(
                    "{LOCK_FILE} already wires {canon_name} to this patch's vendored wheel; \
                     nothing to wire"
                ),
            ))
        }
        PoetryTarget::Fresh => {}
    }

    let (old_unit, new_unit) = rewrite_target_package_unit(
        &p.lock_text,
        canon_name,
        rel_wheel,
        wheel_file_name,
        wheel_sha256_hex,
    )?;
    let new_lock = p.lock_text.replacen(&old_unit, &new_unit, 1);
    atomic_write_bytes(&root.join(LOCK_FILE), new_lock.as_bytes())
        .await
        .map_err(|e| {
            (
                "pypi_poetry_write_failed",
                format!("cannot write {LOCK_FILE}: {e}"),
            )
        })?;

    let wiring = vec![record(
        LOCK_FILE,
        KIND_LOCK_PACKAGE,
        WiringAction::Rewritten,
        canon_name,
        Some(old_unit),
        new_unit,
    )];
    let meta = PoetryMeta {
        dep_class: classify_dependency(p, canon_name).to_string(),
        lock_version: p.lock_version.clone(),
    };
    Ok((wiring, meta))
}

/// Reverse the wiring: restore the verbatim original `[[package]]` unit via
/// the shared fragment-splice revert (drift-tolerant, poetry.lock-only
/// allowlist).
pub(super) async fn revert_poetry(
    entry: &VendorEntry,
    root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    revert_lock_fragment_splice(entry, root, dry_run, LOCK_FILE, KIND_LOCK_PACKAGE, "poetry").await
}

// ── helpers ──────────────────────────────────────────────────────────────

/// `2.<minor>` with minor > 1 (the lock-versions newer than the fixtures).
fn is_newer_2x(v: &str) -> bool {
    v.strip_prefix("2.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|minor| minor.parse::<u64>().ok())
        .is_some_and(|minor| minor > 1)
}

/// Rewrite the target `[[package]]` unit to the file-source shape proven by
/// the fixture pairs: `files = [...]` becomes the single
/// `{file = "<wheel>", hash = "sha256:<ours>"}` element and a
/// `[package.source] type = "file"` table is appended as the LAST subtable
/// (poetry's own placement on both majors — spike P1). Every other line —
/// version, python-versions, groups (2.1) / no groups (2.0), description,
/// existing subtables — is preserved verbatim. Returns `(old_unit, new_unit)`
/// for the wiring record.
fn rewrite_target_package_unit(
    lock_text: &str,
    canon: &str,
    rel_wheel: &str,
    wheel_file_name: &str,
    wheel_sha256_hex: &str,
) -> Result<(String, String), (&'static str, String)> {
    let span =
        find_unit_span(lock_text, |lines| unit_has_canon_name(lines, canon)).ok_or_else(|| {
            (
                "pypi_poetry_lock_package_missing",
                format!("{LOCK_FILE} has no [[package]] entry for {canon}"),
            )
        })?;
    let unit = package_unit_lines(&lock_text[span]);
    let old_unit = unit.join("\n");
    let mut out =
        replace_files_array(&unit, wheel_file_name, wheel_sha256_hex).ok_or_else(|| {
            // 2.x locks always carry files[]; a unit without one is a shape we
            // have no fixture for — fail closed rather than guess a placement.
            (
                "pypi_poetry_lock_parse_failed",
                format!("the {canon} [[package]] entry has no files array to rewrite"),
            )
        })?;
    out.push(String::new());
    out.push("[package.source]".to_string());
    out.push("type = \"file\"".to_string());
    out.push(format!("url = \"{rel_wheel}\""));
    Ok((old_unit, out.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::vendor::state::VendorArtifact;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const REL_WHEEL: &str =
        ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl";
    const WHEEL_NAME: &str = "six-1.16.0-py2.py3-none-any.whl";
    /// sha256 of the spike's patched wheel (spikes/poetry/wheels/patched/).
    const WHEEL_SHA: &str = "0bf540048d557577b88d92443652cc4c4cbfd291c8c53f00c7bcac3a213f14d1";

    // ── fixture constants ──────────────────────────────────────────────
    // Byte-exact copies of the spikes/poetry/ fixtures (Poetry 2.4.1 for
    // lock 2.1, Poetry 1.8.5 for lock 2.0; spike date 2026-06-10). The
    // registry locks are tool-generated (`poetry lock`); the vendored locks
    // are the evidence-lockonly/ splices both majors install byte-stably.
    // If these drift from the committed fixtures, the spike dirs are the
    // source of truth.

    /// spikes/poetry/lock-2.1/direct-registry/pyproject.toml (verbatim).
    const PYPROJECT_DIRECT: &str = r#"[tool.poetry]
name = "scratch"
version = "0.1.0"
description = ""
authors = ["Spike <spike@example.com>"]
package-mode = false

[tool.poetry.dependencies]
python = ">=3.9"
six = "1.16.0"
"#;

    /// spikes/poetry/lock-2.1/transitive-registry/pyproject.toml (verbatim).
    const PYPROJECT_TRANSITIVE: &str = r#"[tool.poetry]
name = "scratch"
version = "0.1.0"
description = ""
authors = ["Spike <spike@example.com>"]
package-mode = false

[tool.poetry.dependencies]
python = ">=3.9"
python-dateutil = "2.8.2"
"#;

    /// spikes/poetry/lock-2.1/direct-registry/poetry.lock (verbatim).
    const LOCK21_DIRECT_REGISTRY: &str = r#"# This file is automatically @generated by Poetry 2.4.1 and should not be changed by hand.

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

    /// spikes/poetry/evidence-lockonly/lock-2.1-direct/poetry.lock (verbatim
    /// — the spliced state both majors install byte-stably, spike P2).
    const LOCK21_DIRECT_VENDORED: &str = r#"# This file is automatically @generated by Poetry 2.4.1 and should not be changed by hand.

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
groups = ["main"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:0bf540048d557577b88d92443652cc4c4cbfd291c8c53f00c7bcac3a213f14d1"},
]

[package.source]
type = "file"
url = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"

[metadata]
lock-version = "2.1"
python-versions = ">=3.9"
content-hash = "4b42a89b7ff7b26511b06acdc458dbd85312e5083db8f212b017482bc68cdd01"
"#;

    /// The transitive "before": dateutil unit + [metadata] verbatim from
    /// spikes/poetry/lock-2.1/transitive-registry/poetry.lock, with the six
    /// unit verbatim from lock-2.1/direct-registry — the registry resolution
    /// poetry produced when 1.16.0 was current (the production case: the lock
    /// resolves the version being patched; today's resolver picks 1.17.0,
    /// spike P3).
    const LOCK21_TRANSITIVE_REGISTRY: &str = r#"# This file is automatically @generated by Poetry 2.4.1 and should not be changed by hand.

[[package]]
name = "python-dateutil"
version = "2.8.2"
description = "Extensions to the standard Python datetime module"
optional = false
python-versions = "!=3.0.*,!=3.1.*,!=3.2.*,>=2.7"
groups = ["main"]
files = [
    {file = "python-dateutil-2.8.2.tar.gz", hash = "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86"},
    {file = "python_dateutil-2.8.2-py2.py3-none-any.whl", hash = "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9"},
]

[package.dependencies]
six = ">=1.5"

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
content-hash = "09f98227642bff952b3df8f8fcc74f1538c091a3ac3ed0031500188347ecb3ca"
"#;

    /// spikes/poetry/evidence-lockonly/lock-2.1-transitive/poetry.lock
    /// (verbatim — the transitive splice, spike P3).
    const LOCK21_TRANSITIVE_VENDORED: &str = r#"# This file is automatically @generated by Poetry 2.4.1 and should not be changed by hand.

[[package]]
name = "python-dateutil"
version = "2.8.2"
description = "Extensions to the standard Python datetime module"
optional = false
python-versions = "!=3.0.*,!=3.1.*,!=3.2.*,>=2.7"
groups = ["main"]
files = [
    {file = "python-dateutil-2.8.2.tar.gz", hash = "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86"},
    {file = "python_dateutil-2.8.2-py2.py3-none-any.whl", hash = "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9"},
]

[package.dependencies]
six = ">=1.5"

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
groups = ["main"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:0bf540048d557577b88d92443652cc4c4cbfd291c8c53f00c7bcac3a213f14d1"},
]

[package.source]
type = "file"
url = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"

[metadata]
lock-version = "2.1"
python-versions = ">=3.9"
content-hash = "09f98227642bff952b3df8f8fcc74f1538c091a3ac3ed0031500188347ecb3ca"
"#;

    /// spikes/poetry/lock-2.0/direct-registry/poetry.lock (verbatim — Poetry
    /// 1.8.5; lock 2.0 has NO groups key).
    const LOCK20_DIRECT_REGISTRY: &str = r#"# This file is automatically @generated by Poetry 1.8.5 and should not be changed by hand.

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"},
    {file = "six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},
]

[metadata]
lock-version = "2.0"
python-versions = ">=3.9"
content-hash = "4b42a89b7ff7b26511b06acdc458dbd85312e5083db8f212b017482bc68cdd01"
"#;

    /// spikes/poetry/evidence-lockonly/lock-2.0-direct/poetry.lock (verbatim).
    const LOCK20_DIRECT_VENDORED: &str = r#"# This file is automatically @generated by Poetry 1.8.5 and should not be changed by hand.

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:0bf540048d557577b88d92443652cc4c4cbfd291c8c53f00c7bcac3a213f14d1"},
]

[package.source]
type = "file"
url = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"

[metadata]
lock-version = "2.0"
python-versions = ">=3.9"
content-hash = "4b42a89b7ff7b26511b06acdc458dbd85312e5083db8f212b017482bc68cdd01"
"#;

    /// The lock-2.0 transitive "before" (assembled like the 2.1 twin: units
    /// verbatim from the lock-2.0 tool-generated fixtures, six pinned at the
    /// patched 1.16.0).
    const LOCK20_TRANSITIVE_REGISTRY: &str = r#"# This file is automatically @generated by Poetry 1.8.5 and should not be changed by hand.

[[package]]
name = "python-dateutil"
version = "2.8.2"
description = "Extensions to the standard Python datetime module"
optional = false
python-versions = "!=3.0.*,!=3.1.*,!=3.2.*,>=2.7"
files = [
    {file = "python-dateutil-2.8.2.tar.gz", hash = "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86"},
    {file = "python_dateutil-2.8.2-py2.py3-none-any.whl", hash = "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9"},
]

[package.dependencies]
six = ">=1.5"

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254"},
    {file = "six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926"},
]

[metadata]
lock-version = "2.0"
python-versions = ">=3.9"
content-hash = "09f98227642bff952b3df8f8fcc74f1538c091a3ac3ed0031500188347ecb3ca"
"#;

    /// spikes/poetry/evidence-lockonly/lock-2.0-transitive/poetry.lock
    /// (verbatim).
    const LOCK20_TRANSITIVE_VENDORED: &str = r#"# This file is automatically @generated by Poetry 1.8.5 and should not be changed by hand.

[[package]]
name = "python-dateutil"
version = "2.8.2"
description = "Extensions to the standard Python datetime module"
optional = false
python-versions = "!=3.0.*,!=3.1.*,!=3.2.*,>=2.7"
files = [
    {file = "python-dateutil-2.8.2.tar.gz", hash = "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86"},
    {file = "python_dateutil-2.8.2-py2.py3-none-any.whl", hash = "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9"},
]

[package.dependencies]
six = ">=1.5"

[[package]]
name = "six"
version = "1.16.0"
description = "Python 2 and 3 compatibility utilities"
optional = false
python-versions = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*"
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:0bf540048d557577b88d92443652cc4c4cbfd291c8c53f00c7bcac3a213f14d1"},
]

[package.source]
type = "file"
url = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"

[metadata]
lock-version = "2.0"
python-versions = ">=3.9"
content-hash = "09f98227642bff952b3df8f8fcc74f1538c091a3ac3ed0031500188347ecb3ca"
"#;

    async fn write_project(lock: &str, pyproject: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("poetry.lock"), lock)
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("pyproject.toml"), pyproject)
            .await
            .unwrap();
        tmp
    }

    async fn read_lock(root: &Path) -> String {
        tokio::fs::read_to_string(root.join("poetry.lock"))
            .await
            .unwrap()
    }

    fn entry_for(wiring: Vec<WiringRecord>, meta: PoetryMeta) -> VendorEntry {
        VendorEntry {
            ecosystem: "pypi".into(),
            base_purl: "pkg:pypi/six@1.16.0".into(),
            uuid: UUID.into(),
            artifact: VendorArtifact {
                path: REL_WHEEL.into(),
                sha256: WHEEL_SHA.into(),
                size: Some(11053),
                platform_locked: None,
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
            detached: false,
            record: None,
            flavor: Some("poetry".into()),
            uv: None,
            pnpm: None,
            poetry: Some(meta),
            pdm: None,
            pipenv: None,
        }
    }

    async fn wire_default(p: &PoetryProject, root: &Path) -> (Vec<WiringRecord>, PoetryMeta) {
        wire_poetry(
            p, root, "six", "1.16.0", REL_WHEEL, WHEEL_NAME, WHEEL_SHA, UUID,
        )
        .await
        .unwrap()
    }

    /// The load-bearing oracle: wiring the registry lock must produce the
    /// spliced evidence-lockonly lock BYTE-IDENTICALLY (per lock version,
    /// direct and transitive), leaving pyproject and content-hash untouched.
    #[tokio::test]
    async fn wiring_matches_fixtures_byte_identically_both_lock_versions() {
        let cases = [
            (
                "2.1",
                LOCK21_DIRECT_REGISTRY,
                LOCK21_DIRECT_VENDORED,
                PYPROJECT_DIRECT,
                "direct",
            ),
            (
                "2.1",
                LOCK21_TRANSITIVE_REGISTRY,
                LOCK21_TRANSITIVE_VENDORED,
                PYPROJECT_TRANSITIVE,
                "transitive",
            ),
            (
                "2.0",
                LOCK20_DIRECT_REGISTRY,
                LOCK20_DIRECT_VENDORED,
                PYPROJECT_DIRECT,
                "direct",
            ),
            (
                "2.0",
                LOCK20_TRANSITIVE_REGISTRY,
                LOCK20_TRANSITIVE_VENDORED,
                PYPROJECT_TRANSITIVE,
                "transitive",
            ),
        ];
        for (lock_version, before, after, pyproject, dep_class) in cases {
            let tmp = write_project(before, pyproject).await;
            let p = load_poetry_project(tmp.path()).await.unwrap();
            assert!(p.warnings.is_empty(), "{lock_version}: {:?}", p.warnings);
            assert_eq!(p.lock_version, lock_version);
            assert_eq!(classify_dependency(&p, "six"), dep_class);
            assert_eq!(
                check_target_guards(&p, "six", "1.16.0", UUID).unwrap(),
                PoetryTarget::Fresh
            );

            let (wiring, meta) = wire_default(&p, tmp.path()).await;
            assert_eq!(
                read_lock(tmp.path()).await,
                after,
                "{lock_version}/{dep_class}: poetry.lock must byte-match the spliced fixture"
            );
            // pyproject + content-hash are NEVER touched (lock-only splice).
            assert_eq!(
                tokio::fs::read_to_string(tmp.path().join("pyproject.toml"))
                    .await
                    .unwrap(),
                pyproject
            );

            assert_eq!(wiring.len(), 1);
            assert_eq!(wiring[0].kind, KIND_LOCK_PACKAGE);
            assert_eq!(wiring[0].action, WiringAction::Rewritten);
            assert_eq!(wiring[0].file, "poetry.lock");
            assert_eq!(wiring[0].key.as_deref(), Some("six"));
            assert_eq!(meta.dep_class, dep_class);
            assert_eq!(meta.lock_version, lock_version);
        }
    }

    #[tokio::test]
    async fn guards_refuse_parse_version_missing_forked_and_sources() {
        // unreadable / unparseable lock
        let tmp = tempfile::tempdir().unwrap();
        let err = load_poetry_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_poetry_lock_parse_failed");
        let tmp = write_project("[[package]\nbroken", PYPROJECT_DIRECT).await;
        let err = load_poetry_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_poetry_lock_parse_failed");

        // lock-version absent / non-2.x
        let tmp = write_project("[[package]]\nname = \"six\"\n", PYPROJECT_DIRECT).await;
        let err = load_poetry_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_poetry_lock_version_unsupported");
        for bad in ["1.1", "3.0"] {
            let lock = LOCK21_DIRECT_REGISTRY.replace(
                "lock-version = \"2.1\"",
                &format!("lock-version = \"{bad}\""),
            );
            let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
            let err = load_poetry_project(tmp.path()).await.unwrap_err();
            assert_eq!(err.0, "pypi_poetry_lock_version_unsupported", "{bad}");
        }

        // target absent from the lock
        let tmp = write_project(LOCK21_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "absent-pkg", "1.0.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_poetry_lock_package_missing");

        // forked: the same name at two versions (marker fork)
        let fork = format!(
            "{LOCK21_DIRECT_REGISTRY}\n[[package]]\nname = \"six\"\nversion = \"1.17.0\"\noptional = false\npython-versions = \"*\"\ngroups = [\"main\"]\nfiles = []\n"
        );
        let tmp = write_project(&fork, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.16.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_poetry_lock_forked_package");

        // single unit at a DIFFERENT version than the patch target
        let tmp = write_project(LOCK21_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.17.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_poetry_lock_package_missing");
        assert!(err.1.contains("1.16.0"), "{}", err.1);

        // user-authored [package.source]
        let user = LOCK21_DIRECT_VENDORED.replace(
            "url = \".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl\"",
            "url = \"../local/six-1.16.0-py2.py3-none-any.whl\"",
        );
        let tmp = write_project(&user, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        let err = check_target_guards(&p, "six", "1.16.0", UUID).unwrap_err();
        assert_eq!(err.0, "pypi_poetry_source_already_exists");
        assert!(err.1.contains("user-authored"), "{}", err.1);

        // wire re-runs the guards itself (refusal before any write)
        let before = read_lock(tmp.path()).await;
        let err = wire_poetry(
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
        assert_eq!(err.0, "pypi_poetry_source_already_exists");
        assert_eq!(
            read_lock(tmp.path()).await,
            before,
            "refusal writes nothing"
        );
    }

    #[tokio::test]
    async fn newer_2x_lock_version_warns_not_refuses() {
        let lock =
            LOCK21_DIRECT_REGISTRY.replace("lock-version = \"2.1\"", "lock-version = \"2.5\"");
        let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        assert_eq!(p.warnings.len(), 1);
        assert_eq!(p.warnings[0].code, "pypi_poetry_lock_version_untested");
        assert_eq!(p.lock_version, "2.5");
        // The wiring itself still works on the warned lock.
        let (wiring, meta) = wire_default(&p, tmp.path()).await;
        assert_eq!(wiring.len(), 1);
        assert_eq!(meta.lock_version, "2.5");
    }

    /// Re-running vendor on an already-wired lock with the SAME uuid is the
    /// in-sync hot path: the caller synthesizes AlreadyPatched and records
    /// nothing; a DIFFERENT uuid refuses with `vendor --revert` guidance.
    #[tokio::test]
    async fn rerun_same_uuid_in_sync_and_stale_uuid_refuses_with_guidance() {
        let tmp = write_project(LOCK21_DIRECT_VENDORED, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        assert_eq!(
            check_target_guards(&p, "six", "1.16.0", UUID).unwrap(),
            PoetryTarget::InSync
        );

        // A different (stale) patch generation must NOT be silently rewired.
        let stale_uuid = "00000000-0000-4000-8000-000000000000";
        let err = check_target_guards(&p, "six", "1.16.0", stale_uuid).unwrap_err();
        assert_eq!(err.0, "pypi_poetry_source_already_exists");
        assert!(err.1.contains("--revert"), "{}", err.1);
        assert!(err.1.contains(UUID), "names the wired uuid: {}", err.1);
    }

    #[tokio::test]
    async fn classify_dependency_covers_every_declaration_surface() {
        let p = |pyproject: Option<&str>| PoetryProject {
            lock_text: String::new(),
            lock: DocumentMut::new(),
            pyproject_text: pyproject.map(str::to_string),
            lock_version: "2.1".into(),
            warnings: Vec::new(),
        };
        // [tool.poetry.dependencies] key (with PEP 503 canonicalization).
        assert_eq!(
            classify_dependency(&p(Some(PYPROJECT_DIRECT)), "six"),
            "direct"
        );
        assert_eq!(
            classify_dependency(
                &p(Some("[tool.poetry.dependencies]\nPyYAML = \"6.0.1\"\n")),
                "pyyaml"
            ),
            "direct"
        );
        // group + dev-dependencies keys.
        assert_eq!(
            classify_dependency(
                &p(Some(
                    "[tool.poetry.group.dev.dependencies]\nsix = \"1.16.0\"\n"
                )),
                "six"
            ),
            "direct"
        );
        assert_eq!(
            classify_dependency(
                &p(Some("[tool.poetry.dev-dependencies]\nsix = \"*\"\n")),
                "six"
            ),
            "direct"
        );
        // PEP 621 dependency specs.
        assert_eq!(
            classify_dependency(
                &p(Some("[project]\ndependencies = [\"six==1.16.0\"]\n")),
                "six"
            ),
            "direct"
        );
        assert_eq!(
            classify_dependency(
                &p(Some(
                    "[project.optional-dependencies]\nextra = [\"Six_Pkg>=1\"]\n"
                )),
                "six-pkg"
            ),
            "direct"
        );
        // Not declared / no pyproject → transitive (diagnostics-only).
        assert_eq!(
            classify_dependency(&p(Some(PYPROJECT_TRANSITIVE)), "six"),
            "transitive"
        );
        assert_eq!(classify_dependency(&p(None), "six"), "transitive");
    }

    /// Dry-run purity: load + classify + guards are pure reads, mirroring
    /// pypi_uv's compute/write split (the orchestrator never calls wire on a
    /// dry run).
    #[tokio::test]
    async fn load_classify_and_guards_write_nothing() {
        let tmp = write_project(LOCK21_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        let _ = classify_dependency(&p, "six");
        let _ = check_target_guards(&p, "six", "1.16.0", UUID).unwrap();
        assert_eq!(read_lock(tmp.path()).await, LOCK21_DIRECT_REGISTRY);
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
            (LOCK21_DIRECT_REGISTRY, PYPROJECT_DIRECT),
            (LOCK20_TRANSITIVE_REGISTRY, PYPROJECT_TRANSITIVE),
        ] {
            let tmp = write_project(before, pyproject).await;
            let p = load_poetry_project(tmp.path()).await.unwrap();
            let (wiring, meta) = wire_default(&p, tmp.path()).await;
            let entry = entry_for(wiring, meta);

            let outcome = revert_poetry(&entry, tmp.path(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
            assert_eq!(read_lock(tmp.path()).await, before, "byte-identical revert");
        }
    }

    #[tokio::test]
    async fn revert_dry_run_changes_nothing() {
        let tmp = write_project(LOCK21_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_default(&p, tmp.path()).await;
        let wired = read_lock(tmp.path()).await;

        let outcome = revert_poetry(&entry_for(wiring, meta), tmp.path(), true).await;
        assert!(outcome.success);
        assert_eq!(read_lock(tmp.path()).await, wired, "dry run must not write");
    }

    /// SECURITY: a poisoned state.json wiring record naming any file other
    /// than poetry.lock is skipped fail-closed — the named path is never
    /// read or written.
    #[tokio::test]
    async fn revert_allowlist_skips_unexpected_files_fail_closed() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("project");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("poetry.lock"), LOCK21_DIRECT_REGISTRY)
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
            let meta = PoetryMeta {
                dep_class: "direct".into(),
                lock_version: "2.1".into(),
            };
            let outcome = revert_poetry(&entry_for(wiring, meta), &root, false).await;
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
            tokio::fs::read_to_string(root.join("poetry.lock"))
                .await
                .unwrap(),
            LOCK21_DIRECT_REGISTRY,
            "the lock itself is untouched too (no record matched it)"
        );
    }

    /// A third-party edit to the unit we wrote (e.g. `poetry update six`
    /// reverted it to registry hashes — spike P5) is left alone with a drift
    /// warning; unknown wiring kinds from a newer ledger degrade the same way.
    #[tokio::test]
    async fn revert_warns_and_skips_on_drifted_fragment_and_unknown_kind() {
        let tmp = write_project(LOCK21_DIRECT_REGISTRY, PYPROJECT_DIRECT).await;
        let p = load_poetry_project(tmp.path()).await.unwrap();
        let (mut wiring, meta) = wire_default(&p, tmp.path()).await;
        wiring.push(WiringRecord {
            file: "poetry.lock".into(),
            kind: "poetry_future_kind".into(),
            action: WiringAction::Added,
            key: Some("six".into()),
            original: None,
            new: Some(serde_json::json!("x")),
        });

        // Drift: someone re-hashed the vendored files entry.
        let drifted = read_lock(tmp.path())
            .await
            .replace(WHEEL_SHA, &"0".repeat(64));
        tokio::fs::write(tmp.path().join("poetry.lock"), &drifted)
            .await
            .unwrap();

        let outcome = revert_poetry(&entry_for(wiring, meta), tmp.path(), false).await;
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

    #[test]
    fn newer_2x_classifier() {
        assert!(is_newer_2x("2.2"));
        assert!(is_newer_2x("2.10"));
        assert!(!is_newer_2x("2.0"));
        assert!(!is_newer_2x("2.1"));
        assert!(!is_newer_2x("3.0"));
        assert!(!is_newer_2x("garbage"));
    }
}
