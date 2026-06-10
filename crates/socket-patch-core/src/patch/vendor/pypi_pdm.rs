//! pdm-project wiring: a lock-ONLY `[[package]]` splice (pdm.lock
//! lock_version 4.5.x).
//!
//! pdm's `content_hash` covers the pyproject requirements only — identical
//! between strategy variants of the same pyproject — so a per-package lock
//! splice can never trip `pdm install --check` / `pdm lock --check`
//! freshness. The spike-captured D1 shape is a RELATIVE `path = "./…"` key
//! (inserted between `requires_python` and `summary`, exactly where pdm's own
//! serializer puts it) plus `files = []` reduced to the single patched-wheel
//! hash; `pdm sync` / `--check` / `--frozen-lockfile` all pass byte-stably
//! and unearth hash-verifies the local wheel fail-closed (D4). See
//! `spikes/pdm/` and the pdm section of `spikes/PHASE0-V2-FINDINGS.txt`.
//!
//! Drift caveat (spike D5): `pdm lock` and `pdm update <pkg>` silently revert
//! the splice with exit 0 (only plain `pdm install` preserves it); the lock's
//! files[] hash is the drift oracle. `pyproject.toml` and `content_hash` are
//! NEVER written by this backend.
//!
//! Spike caveat (D6, partial): only the `inherit_metadata` and `static_urls`
//! strategy shapes were captured, so any other `[metadata] strategy` flag
//! refuses; pdm 2.27 can no longer produce hash-less locks, so a files entry
//! without a sha256 refuses too (both fail-closed, not warnings).

use std::path::Path;

use toml_edit::{DocumentMut, Item, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::atomic_write_bytes;

use super::path::parse_vendor_path;
use super::state::{PdmMeta, VendorEntry, WiringAction, WiringRecord};
use super::toml_surgery::find_unit_span;
use super::{RevertOutcome, VendorWarning};

/// The only file this backend ever writes (and the revert allowlist).
const LOCK_FILE: &str = "pdm.lock";

/// The `WiringRecord.kind` discriminator this backend owns.
const KIND_LOCK_PACKAGE: &str = "pdm_lock_package";

/// The `[metadata] strategy` flags whose lock shapes the spike captured
/// (D1 default + D6 static_urls). Any other flag refuses fail-closed.
const SUPPORTED_STRATEGIES: [&str; 2] = ["inherit_metadata", "static_urls"];

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
    let lock_text = tokio::fs::read_to_string(root.join(LOCK_FILE))
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
                format!("{LOCK_FILE} has no [metadata] lock_version; re-lock with pdm >= 2.17"),
            )
        })?;
    let mut warnings = Vec::new();
    match lock_version_series(&lock_version) {
        // The fixture series (pdm 2.27 writes 4.5.0).
        LockVersionSeries::Supported => {}
        // A newer 4.x minor keeps the shapes we rewrite (additive schema);
        // warn instead of refusing — `pdm lock --check` is the backstop.
        LockVersionSeries::NewerMinor => warnings.push(VendorWarning::new(
            "pypi_pdm_lock_version_untested",
            format!(
                "pdm.lock lock_version {lock_version} is newer than the fixture-tested 4.5.x; \
                 verify with `pdm install --check` after vendoring"
            ),
        )),
        LockVersionSeries::Unsupported => {
            return Err((
                "pypi_pdm_lock_version_unsupported",
                format!(
                    "pdm.lock lock_version {lock_version:?} is outside the supported 4.5+ \
                     series; re-lock with a current pdm"
                ),
            ))
        }
    }

    // SECURITY/correctness: strategies change the files[]/unit shapes; only
    // the fixture-captured set is splice-proven (spike D6 was partial) —
    // anything else refuses fail-closed rather than guessing an emitter shape.
    let strategy: Vec<String> = metadata
        .and_then(|m| item_get(m, "strategy"))
        .and_then(Item::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if let Some(unknown) = strategy
        .iter()
        .find(|s| !SUPPORTED_STRATEGIES.contains(&s.as_str()))
    {
        return Err((
            "pypi_pdm_lock_strategy_unsupported",
            format!(
                "pdm.lock [metadata] strategy contains {unknown:?}; only \
                 inherit_metadata/static_urls locks are fixture-tested"
            ),
        ));
    }

    let pyproject_text = tokio::fs::read_to_string(root.join("pyproject.toml"))
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
pub fn classify_dependency(p: &PdmProject, canon_name: &str) -> &'static str {
    let Some(text) = p.pyproject_text.as_deref() else {
        return "transitive";
    };
    let Ok(doc) = text.parse::<DocumentMut>() else {
        return "transitive";
    };
    let mut declared: Vec<String> = Vec::new();
    if let Some(project) = doc.get("project") {
        if let Some(deps) = item_get(project, "dependencies").and_then(Item::as_array) {
            declared.extend(
                deps.iter()
                    .filter_map(Value::as_str)
                    .map(|s| pep508_name(s).to_string()),
            );
        }
        if let Some(optional) =
            item_get(project, "optional-dependencies").and_then(Item::as_table_like)
        {
            for (_, item) in optional.iter() {
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
    let units: Vec<&toml_edit::Table> = p
        .lock
        .get("package")
        .and_then(Item::as_array_of_tables)
        .map(|pkgs| {
            pkgs.iter()
                .filter(|t| {
                    t.get("name")
                        .and_then(Item::as_str)
                        .map(canonicalize_pypi_name)
                        .as_deref()
                        == Some(canon_name)
                })
                .collect()
        })
        .unwrap_or_default();
    if units.is_empty() {
        return Err((
            "pypi_pdm_lock_package_missing",
            format!("{LOCK_FILE} has no [[package]] entry for {canon_name}; run `pdm lock` first"),
        ));
    }
    // Cross-platform/marker forks list the same name at multiple versions;
    // one surgical rewrite would mispin the other forks — refuse (mirrors uv).
    if units.len() > 1 {
        return Err((
            "pypi_pdm_lock_forked_package",
            format!(
                "{LOCK_FILE} resolves {canon_name} at multiple versions/markers (a forked \
                 resolution); vendoring would mispin the other forks"
            ),
        ));
    }
    let unit = units[0];

    if let Some(path) = unit.get("path").and_then(Item::as_str) {
        return match parse_vendor_path(path) {
            // Ours, same patch generation: the in-sync hot path.
            Some(parts) if parts.eco == "pypi" && parts.uuid == record_uuid => {
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
    // Direct URL / VCS units carry unit-level url/git keys — also user-owned.
    if unit.get("url").is_some() || unit.get("git").is_some() {
        return Err((
            "pypi_pdm_source_already_exists",
            format!(
                "{LOCK_FILE} resolves {canon_name} from a user-declared url/vcs source; \
                 refusing to overwrite it"
            ),
        ));
    }

    // Splicing a hashed entry into a hash-less lock is untested (spike D6:
    // `--no-hashes` no longer exists in pdm 2.27, so this only arises from
    // older tools) — refuse rather than mix verification regimes.
    let hashed_entries = unit
        .get("files")
        .and_then(Item::as_array)
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

    // The splice keeps the unit's version line verbatim, so the lock must
    // already resolve the version being patched (lock/venv drift otherwise).
    let locked_version = unit.get("version").and_then(Item::as_str).unwrap_or("");
    if locked_version != version {
        return Err((
            "pypi_pdm_lock_package_missing",
            format!(
                "{LOCK_FILE} resolves {canon_name} at {locked_version:?}, not the patched \
                 {version}; re-lock so the lock matches the installed version"
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
                "pypi_pdm_write_failed",
                format!("cannot write {LOCK_FILE}: {e}"),
            )
        })?;

    let wiring = vec![record(
        KIND_LOCK_PACKAGE,
        WiringAction::Rewritten,
        canon_name,
        Some(old_unit),
        new_unit,
    )];
    let meta = PdmMeta {
        dep_class: classify_dependency(p, canon_name).to_string(),
        lock_version: p.lock_version.clone(),
        strategy: p.strategy.clone(),
    };
    Ok((wiring, meta))
}

/// Reverse the wiring: restore the verbatim original `[[package]]` unit. A
/// fragment that no longer matches what we wrote is left alone with a
/// `vendor_lock_entry_drifted` warning — revert never clobbers third-party
/// edits.
pub async fn revert_pdm(entry: &VendorEntry, root: &Path, dry_run: bool) -> RevertOutcome {
    let lock_path = root.join(LOCK_FILE);
    let mut lock_text = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) => return RevertOutcome::failed(format!("cannot read {LOCK_FILE}: {e}")),
    };
    let mut warnings: Vec<VendorWarning> = Vec::new();

    for rec in entry.wiring.iter().rev() {
        // SECURITY: `rec.file` comes verbatim from the committed, tamper-able
        // state.json. This backend only ever wrote pdm.lock (the per-flavor
        // file allowlist); any other recorded path is skipped fail-closed with
        // a warning and is NEVER resolved against the filesystem.
        if rec.file != LOCK_FILE {
            warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "ignoring wiring record for unexpected file `{}` (only {LOCK_FILE} is \
                     pdm-owned)",
                    rec.file
                ),
            ));
            continue;
        }
        let drifted = || {
            VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{LOCK_FILE} fragment for {:?} changed since vendoring; left untouched",
                    rec.key
                ),
            )
        };
        match rec.kind.as_str() {
            KIND_LOCK_PACKAGE => {
                let new_text = rec.new.as_ref().and_then(serde_json::Value::as_str);
                let original_text = rec.original.as_ref().and_then(serde_json::Value::as_str);
                let (Some(new), Some(orig)) = (new_text, original_text) else {
                    warnings.push(drifted());
                    continue;
                };
                if lock_text.contains(new) {
                    lock_text = lock_text.replacen(new, orig, 1);
                } else {
                    warnings.push(drifted());
                }
            }
            // Forward compatibility: a newer ledger's unknown kind degrades
            // to a warning (never guess at a fragment shape).
            other => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unknown pdm wiring kind {other:?}; skipped"),
            )),
        }
    }

    if !dry_run {
        if let Err(e) = atomic_write_bytes(&lock_path, lock_text.as_bytes()).await {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("cannot write {LOCK_FILE}: {e}")),
            };
        }
    }
    RevertOutcome {
        success: true,
        warnings,
        error: None,
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

enum LockVersionSeries {
    Supported,
    NewerMinor,
    Unsupported,
}

/// `4.5.x` is the fixture series; a newer `4.<minor>` warns; everything else
/// (older minors, other majors, unparseable) refuses.
fn lock_version_series(v: &str) -> LockVersionSeries {
    let mut it = v.split('.');
    let major = it.next().and_then(|s| s.parse::<u64>().ok());
    let minor = it.next().and_then(|s| s.parse::<u64>().ok());
    match (major, minor) {
        (Some(4), Some(5)) => LockVersionSeries::Supported,
        (Some(4), Some(m)) if m > 5 => LockVersionSeries::NewerMinor,
        _ => LockVersionSeries::Unsupported,
    }
}

fn record(
    kind: &str,
    action: WiringAction,
    key: &str,
    original: Option<String>,
    new: String,
) -> WiringRecord {
    WiringRecord {
        file: LOCK_FILE.to_string(),
        kind: kind.to_string(),
        action,
        key: Some(key.to_string()),
        original: original.map(serde_json::Value::String),
        new: Some(serde_json::Value::String(new)),
    }
}

fn item_get<'a>(item: &'a Item, key: &str) -> Option<&'a Item> {
    item.as_table_like().and_then(|t| t.get(key))
}

/// Leading PEP 508 distribution name of a dependency spec.
fn pep508_name(spec: &str) -> &str {
    let s = spec.trim_start();
    let end = s
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    &s[..end]
}

fn unit_has_canon_name(lines: &[&str], canon: &str) -> bool {
    lines
        .iter()
        .find_map(|l| l.strip_prefix("name = "))
        .map(|r| canonicalize_pypi_name(r.trim().trim_matches('"')))
        .as_deref()
        == Some(canon)
}

/// Rewrite the target `[[package]]` unit to the D1-captured local-file
/// shape: insert `path = "./<rel_wheel>"` right after `requires_python`
/// (falling back to `version`/`name` — pdm's own key order) and reduce
/// `files = [...]` to the single `{file = "<wheel>", hash = "sha256:<ours>"}`
/// element. Every other line is preserved verbatim. Returns
/// `(old_unit, new_unit)` for the wiring record.
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
                "pypi_pdm_lock_package_missing",
                format!("{LOCK_FILE} has no [[package]] entry for {canon}"),
            )
        })?;
    // `find_unit_span` ends a unit at the NEXT `[[package]]` or EOF; truncate
    // defensively at any foreign top-level header so the splice never
    // swallows a trailing section (pdm's [metadata] leads the file today, but
    // the truncation keeps the cut correct if a section ever trails).
    let mut unit: Vec<&str> = lock_text[span].lines().collect();
    if let Some(stop) = unit
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(i, l)| (l.starts_with('[') && !l.starts_with("[package.")).then_some(i))
    {
        unit.truncate(stop);
        while unit.last().is_some_and(|l| l.trim().is_empty()) {
            unit.pop();
        }
    }
    let old_unit = unit.join("\n");
    let files_lines = [
        "files = [".to_string(),
        format!("    {{file = \"{wheel_file_name}\", hash = \"sha256:{wheel_sha256_hex}\"}},"),
        "]".to_string(),
    ];

    let mut out: Vec<String> = Vec::new();
    let mut files_done = false;
    let mut i = 0;
    while i < unit.len() {
        let line = unit[i];
        if line.starts_with("files = [") {
            out.extend(files_lines.iter().cloned());
            files_done = true;
            if !line.trim_end().ends_with(']') {
                // skip the original multi-line array body + closing bracket
                while i + 1 < unit.len() && unit[i + 1].trim() != "]" {
                    i += 1;
                }
                i += 1;
            }
        } else {
            out.push(line.to_string());
        }
        i += 1;
    }
    if !files_done {
        // The hash guard already requires hashed files entries; reaching here
        // means the parsed and textual views disagree — fail closed.
        return Err((
            "pypi_pdm_lock_parse_failed",
            format!("the {canon} [[package]] entry has no files array to rewrite"),
        ));
    }

    let anchor = out
        .iter()
        .position(|l| l.starts_with("requires_python = "))
        .or_else(|| out.iter().position(|l| l.starts_with("version = ")))
        .or_else(|| out.iter().position(|l| l.starts_with("name = ")))
        .ok_or_else(|| {
            (
                "pypi_pdm_lock_parse_failed",
                format!("the {canon} [[package]] entry has no key to anchor the path after"),
            )
        })?;
    out.insert(anchor + 1, format!("path = \"./{rel_wheel}\""));
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
path = "./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"
summary = "Python 2 and 3 compatibility utilities"
groups = ["default"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:7015f5a42a0f83fd1b7d3ca0ba10d8777a207c19b6ffebb39e2e1c03af6a281b"},
]
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
path = "./.socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl"
summary = "Python 2 and 3 compatibility utilities"
groups = ["default"]
files = [
    {file = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:7015f5a42a0f83fd1b7d3ca0ba10d8777a207c19b6ffebb39e2e1c03af6a281b"},
]
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
            },
            wiring,
            lock: None,
            took_over_go_patches: false,
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
    async fn unsupported_strategy_refuses() {
        for flag in ["cross_platform", "direct_minimal_versions", "no_hashes"] {
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
        for bad in ["4.4.1", "3.0", "5.0.0", "garbage"] {
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
    async fn newer_minor_lock_version_warns_not_refuses() {
        let lock =
            LOCK_DIRECT_REGISTRY.replace("lock_version = \"4.5.0\"", "lock_version = \"4.6.0\"");
        let tmp = write_project(&lock, PYPROJECT_DIRECT).await;
        let p = load_pdm_project(tmp.path()).await.unwrap();
        assert_eq!(p.warnings.len(), 1);
        assert_eq!(p.warnings[0].code, "pypi_pdm_lock_version_untested");
        assert_eq!(p.lock_version, "4.6.0");
        // The wiring itself still works on the warned lock.
        let (wiring, meta) = wire_default(&p, tmp.path()).await;
        assert_eq!(wiring.len(), 1);
        assert_eq!(meta.lock_version, "4.6.0");
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

    #[test]
    fn lock_version_series_classifier() {
        assert!(matches!(
            lock_version_series("4.5.0"),
            LockVersionSeries::Supported
        ));
        assert!(matches!(
            lock_version_series("4.5.1"),
            LockVersionSeries::Supported
        ));
        assert!(matches!(
            lock_version_series("4.6.0"),
            LockVersionSeries::NewerMinor
        ));
        assert!(matches!(
            lock_version_series("4.10.2"),
            LockVersionSeries::NewerMinor
        ));
        assert!(matches!(
            lock_version_series("4.4.1"),
            LockVersionSeries::Unsupported
        ));
        assert!(matches!(
            lock_version_series("5.0.0"),
            LockVersionSeries::Unsupported
        ));
        assert!(matches!(
            lock_version_series("garbage"),
            LockVersionSeries::Unsupported
        ));
    }
}
