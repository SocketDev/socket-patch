//! uv-project wiring: paired `pyproject.toml` + `uv.lock` surgery.
//!
//! The pairing is load-bearing (spike claims 7/9): a `[tool.uv.sources]`
//! entry for a package uv doesn't consider declared is SILENTLY ignored, and
//! a path-source lock without the pyproject entry is silently rewritten back
//! to the registry by a plain `uv sync`. So vendor always writes BOTH — the
//! pyproject sources entry (plus, for transitive deps, a
//! `[tool.uv] override-dependencies` pin, which sources DO apply to — claim
//! 8) and the lock's `[[package]]` / `requires-dist` / `[manifest]` fragments.
//!
//! All lock edits are targeted text surgery rather than a TOML re-serialize:
//! the spike proved a surgical edit reproduces uv's own serializer output
//! byte-identically (claim 2), which keeps `uv lock --check` green and the
//! committed diff minimal. The `spikes/uv/` fixtures pin the exact shapes.

use std::ops::Range;
use std::path::Path;

use toml_edit::{DocumentMut, Item, Table, Value};

use crate::crawlers::python_crawler::canonicalize_pypi_name;
use crate::utils::fs::atomic_write_bytes_preserving_mode;

use super::common::{item_get, pep508_name, pep621_declared_names, record};
use super::state::{UvMeta, VendorEntry, WiringAction, WiringRecord};
use super::toml_surgery::{
    balanced_span, find_unit_span, line_index, remove_exact_line, remove_substring,
    remove_table_if_empty, replace_fragment, split_top_level_commas, top_level_brace_groups,
};
use super::{RevertOutcome, VendorWarning};

/// Highest uv.lock `revision` the spike fixtures were generated with. A newer
/// revision is a warning, not a refusal: the shapes we rewrite have been
/// stable across revisions and `uv lock --check` will catch a real mismatch.
const HIGHEST_TESTED_LOCK_REVISION: u64 = 3;

/// How the target package is declared, which picks the wiring strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UvDepClass {
    /// Declared in `project.dependencies` / `optional-dependencies` /
    /// `dependency-groups` — a `[tool.uv.sources]` entry suffices.
    Direct,
    /// Not declared anywhere — wired via `[tool.uv] override-dependencies`
    /// (sources apply to overrides; no promotion into project.dependencies).
    Transitive,
}

/// A loaded-and-guard-checked uv project pair.
#[derive(Debug)]
pub(super) struct UvProject {
    pub pyproject_text: String,
    pub lock_text: String,
    pub pyproject: DocumentMut,
    pub lock: DocumentMut,
    /// uv.lock `revision` (diagnostics; recorded into [`UvMeta`]).
    pub lock_revision: Option<u64>,
    /// Non-fatal advisories raised during load (untested lock revision).
    pub warnings: Vec<VendorWarning>,
}

/// Read + parse the pair and run every project-level guard. Refuses before
/// ANY write — the orchestrator runs this (and the target guards) before the
/// wheel is even built, so a refusal leaves the tree byte-untouched.
pub(super) async fn load_uv_project(root: &Path) -> Result<UvProject, (&'static str, String)> {
    let pyproject_text = tokio::fs::read_to_string(root.join("pyproject.toml"))
        .await
        .map_err(|e| {
            (
                "pypi_uv_lock_parse_failed",
                format!("cannot read pyproject.toml: {e}"),
            )
        })?;
    let lock_text = tokio::fs::read_to_string(root.join("uv.lock"))
        .await
        .map_err(|e| {
            (
                "pypi_uv_lock_parse_failed",
                format!("cannot read uv.lock: {e}"),
            )
        })?;
    let pyproject: DocumentMut = pyproject_text.parse().map_err(|e| {
        (
            "pypi_uv_lock_parse_failed",
            format!("pyproject.toml does not parse: {e}"),
        )
    })?;
    let lock: DocumentMut = lock_text.parse().map_err(|e| {
        (
            "pypi_uv_lock_parse_failed",
            format!("uv.lock does not parse: {e}"),
        )
    })?;

    // Workspaces resolve all members into ONE shared lock whose fragments we
    // have no fixtures for; refuse rather than guess (fail-closed).
    if pyproject
        .get("tool")
        .and_then(|t| item_get(t, "uv"))
        .and_then(|u| item_get(u, "workspace"))
        .is_some()
    {
        return Err((
            "pypi_uv_workspace_unsupported",
            "pyproject.toml declares [tool.uv.workspace]; vendoring uv workspaces is not \
             supported yet"
                .to_string(),
        ));
    }

    let root_name = pyproject
        .get("project")
        .and_then(|p| item_get(p, "name"))
        .and_then(Item::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            (
                "pypi_uv_lock_root_missing",
                "pyproject.toml has no [project] name; cannot identify the root package in \
                 uv.lock"
                    .to_string(),
            )
        })?;

    match lock.get("version").and_then(Item::as_integer) {
        Some(1) => {}
        other => {
            return Err((
                "pypi_uv_lock_version_unsupported",
                format!("uv.lock schema version {other:?} is not the supported version 1"),
            ))
        }
    }

    // A `[manifest] members` list beyond the root is the lock-side workspace
    // signal (single-project locks normally have no members at all).
    if let Some(members) = lock
        .get("manifest")
        .and_then(|m| item_get(m, "members"))
        .and_then(Item::as_array)
    {
        let canon_root = canonicalize_pypi_name(&root_name);
        let extras: Vec<&str> = members
            .iter()
            .filter_map(Value::as_str)
            .filter(|m| canonicalize_pypi_name(m) != canon_root)
            .collect();
        if !extras.is_empty() {
            return Err((
                "pypi_uv_workspace_unsupported",
                format!(
                    "uv.lock [manifest] members lists workspace packages beyond the root: {}",
                    extras.join(", ")
                ),
            ));
        }
    }

    // PEP 621 dynamic dependencies are resolved by a build backend at lock
    // time — there is no static dependency list to classify against.
    if pyproject
        .get("project")
        .and_then(|p| item_get(p, "dynamic"))
        .and_then(Item::as_array)
        .is_some_and(|d| {
            d.iter()
                .filter_map(Value::as_str)
                .any(|x| x == "dependencies")
        })
    {
        return Err((
            "pypi_uv_dynamic_dependencies",
            "pyproject.toml declares dynamic = [\"dependencies\"]; vendor cannot classify the \
             dependency statically"
                .to_string(),
        ));
    }

    if !lock_has_root_package(&lock) {
        return Err((
            "pypi_uv_lock_root_missing",
            "uv.lock has no root [[package]] (source virtual/editable \".\")".to_string(),
        ));
    }

    let lock_revision = lock
        .get("revision")
        .and_then(Item::as_integer)
        .and_then(|i| u64::try_from(i).ok());
    let mut warnings = Vec::new();
    if let Some(rev) = lock_revision {
        if rev > HIGHEST_TESTED_LOCK_REVISION {
            warnings.push(VendorWarning::new(
                "pypi_uv_lock_revision_untested",
                format!(
                    "uv.lock revision {rev} is newer than the highest fixture-tested revision \
                     {HIGHEST_TESTED_LOCK_REVISION}; verify with `uv lock --check` after vendoring"
                ),
            ));
        }
    }

    Ok(UvProject {
        pyproject_text,
        lock_text,
        pyproject,
        lock,
        lock_revision,
        warnings,
    })
}

/// Direct iff the package is named (PEP 508 name, canonicalized) anywhere in
/// `project.dependencies`, `project.optional-dependencies`, or the PEP 735
/// `dependency-groups` — every surface `[tool.uv.sources]` applies to without
/// an override.
fn classify_dependency(p: &UvProject, canon_name: &str) -> UvDepClass {
    let mut declared: Vec<String> = Vec::new();
    pep621_declared_names(&p.pyproject, &mut declared);
    if let Some(groups) = p
        .pyproject
        .get("dependency-groups")
        .and_then(Item::as_table_like)
    {
        for (_, item) in groups.iter() {
            if let Some(arr) = item.as_array() {
                // Non-string members are `{include-group = "..."}` includes;
                // the included group's own array is already scanned above.
                declared.extend(
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(|s| pep508_name(s).to_string()),
                );
            }
        }
    }
    if declared
        .iter()
        .any(|n| canonicalize_pypi_name(n) == canon_name)
    {
        UvDepClass::Direct
    } else {
        UvDepClass::Transitive
    }
}

/// Pre-flight wiring state for one package (mirrors `PdmTarget`).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum UvTarget {
    Fresh,
    /// `[tool.uv.sources]` already routes the package through THIS patch
    /// uuid's vendored wheel — the in-sync hot path.
    InSync,
}

/// Target-specific guards (also re-run by [`wire_uv`] right before writing).
/// Split out of [`load_uv_project`] because they need the target name; the
/// orchestrator runs them pre-flight so a refusal happens before the wheel
/// artifact is built.
pub(super) fn check_target_guards(
    p: &UvProject,
    canon_name: &str,
    record_uuid: &str,
) -> Result<UvTarget, (&'static str, String)> {
    // The same name at multiple versions/sources (platform forks) means one
    // surgical [[package]] rewrite would mispin the other forks — refuse.
    let units = p
        .lock
        .get("package")
        .and_then(Item::as_array_of_tables)
        .map(|pkgs| {
            pkgs.iter()
                .filter(|t| t.get("name").and_then(Item::as_str) == Some(canon_name))
                .count()
        })
        .unwrap_or(0);
    if units == 0 {
        return Err((
            "pypi_uv_lock_package_missing",
            format!("uv.lock has no [[package]] entry for {canon_name}; run `uv lock` first"),
        ));
    }
    if units > 1 {
        return Err((
            "pypi_uv_lock_forked_package",
            format!(
                "uv.lock resolves {canon_name} at multiple versions/sources (a forked \
                 resolution); vendoring would mispin the other forks"
            ),
        ));
    }

    // An existing sources entry would be silently shadowed/clobbered by ours.
    if let Some(sources) = p
        .pyproject
        .get("tool")
        .and_then(|t| item_get(t, "uv"))
        .and_then(|u| item_get(u, "sources"))
        .and_then(Item::as_table_like)
    {
        for (key, item) in sources.iter() {
            if canonicalize_pypi_name(key) != canon_name {
                continue;
            }
            let path = item
                .as_value()
                .and_then(Value::as_inline_table)
                .and_then(|t| t.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("");
            // Ours at the SAME patch generation: in sync — the sources and
            // override entries are our own first-run edits, expected here.
            if super::path::parse_vendor_path(path)
                .is_some_and(|parts| parts.eco == "pypi" && parts.uuid == record_uuid)
            {
                return Ok(UvTarget::InSync);
            }
            let detail = if path.contains(".socket/vendor/pypi/") {
                format!(
                    "[tool.uv.sources] already routes {key} to a socket-patch vendored wheel; \
                     run `socket-patch vendor --revert` before re-vendoring"
                )
            } else {
                format!(
                    "[tool.uv.sources] already declares a source for {key}; refusing to \
                     overwrite a user-authored source"
                )
            };
            return Err(("pypi_uv_source_already_exists", detail));
        }
    }

    // A user override pins this package already; layering ours on top would
    // change resolution behind the user's back.
    if let Some(overrides) = p
        .pyproject
        .get("tool")
        .and_then(|t| item_get(t, "uv"))
        .and_then(|u| item_get(u, "override-dependencies"))
        .and_then(Item::as_array)
    {
        for spec in overrides.iter().filter_map(Value::as_str) {
            if canonicalize_pypi_name(pep508_name(spec)) == canon_name {
                return Err((
                    "pypi_uv_source_already_exists",
                    format!(
                        "[tool.uv] override-dependencies already pins {spec:?}; refusing to \
                         stack a vendor override on a user override"
                    ),
                ));
            }
        }
    }
    Ok(UvTarget::Fresh)
}

/// Wire the pair for the vendored wheel. Writes `pyproject.toml` FIRST, then
/// `uv.lock`; a failed lock write unwinds the pyproject from the recorded
/// original so the pair is never left half-wired (either half alone is a
/// silent no-op or a silent revert — spike claims 7/9).
#[allow(clippy::too_many_arguments)]
pub(super) async fn wire_uv(
    p: &UvProject,
    root: &Path,
    canon_name: &str,
    version: &str,
    rel_wheel: &str,
    wheel_file_name: &str,
    wheel_sha256_hex: &str,
    record_uuid: &str,
) -> Result<(Vec<WiringRecord>, UvMeta), (&'static str, String)> {
    match check_target_guards(p, canon_name, record_uuid)? {
        // Defensive: the orchestrator short-circuits in-sync pre-flight and
        // never calls wire on it (we must never re-record our own edit as an
        // "original", and a re-run requires-dist rewrite would append a
        // duplicate `path` key — unparseable TOML).
        UvTarget::InSync => {
            return Err((
                "pypi_uv_source_already_exists",
                format!(
                    "pyproject.toml already wires {canon_name} to this patch's vendored wheel; \
                     nothing to wire"
                ),
            ))
        }
        UvTarget::Fresh => {}
    }
    let class = classify_dependency(p, canon_name);
    let mut wiring: Vec<WiringRecord> = Vec::new();

    // ── pyproject.toml (computed in memory; committed before the lock) ────
    let mut doc = p.pyproject.clone();
    let had_uv_table = doc.get("tool").and_then(|t| item_get(t, "uv")).is_some();
    let created_sources_table = doc
        .get("tool")
        .and_then(|t| item_get(t, "uv"))
        .and_then(|u| item_get(u, "sources"))
        .is_none();

    if class == UvDepClass::Transitive {
        let spec = format!("{canon_name}=={version}");
        let uv_table = ensure_table(&mut doc, &["tool", "uv"])?;
        if !had_uv_table {
            uv_table.set_implicit(false);
            uv_table.decor_mut().set_prefix("\n");
        }
        match uv_table.get("override-dependencies") {
            None => {
                let value: Value = format!("[\"{spec}\"]").parse().map_err(|e| {
                    (
                        "pypi_uv_lock_parse_failed",
                        format!("cannot build override value: {e}"),
                    )
                })?;
                uv_table.insert(
                    "override-dependencies",
                    Item::Value(value.decorated(" ", "")),
                );
                wiring.push(record(
                    "pyproject.toml",
                    "uv_override",
                    WiringAction::Added,
                    canon_name,
                    None,
                    format!("override-dependencies = [\"{spec}\"]"),
                ));
            }
            Some(existing) => {
                let old_text = existing
                    .as_value()
                    .map(|v| v.to_string().trim().to_string())
                    .ok_or_else(|| {
                        (
                            "pypi_uv_lock_parse_failed",
                            "pyproject.toml [tool.uv] override-dependencies is not a value"
                                .to_string(),
                        )
                    })?;
                let arr = uv_table
                    .get_mut("override-dependencies")
                    .and_then(Item::as_array_mut)
                    .ok_or_else(|| {
                        (
                            "pypi_uv_lock_parse_failed",
                            "pyproject.toml [tool.uv] override-dependencies is not an array"
                                .to_string(),
                        )
                    })?;
                arr.push_formatted(Value::from(spec.clone()).decorated(" ", ""));
                let new_text = uv_table
                    .get("override-dependencies")
                    .and_then(Item::as_value)
                    .map(|v| v.to_string().trim().to_string())
                    .unwrap_or_default();
                wiring.push(record(
                    "pyproject.toml",
                    "uv_override",
                    WiringAction::Rewritten,
                    canon_name,
                    Some(old_text),
                    new_text,
                ));
            }
        }
    }

    let sources_table = ensure_table(&mut doc, &["tool", "uv", "sources"])?;
    if created_sources_table {
        sources_table.set_implicit(false);
        sources_table.decor_mut().set_prefix("\n");
    }
    let sources_value: Value = format!("{{ path = \"{rel_wheel}\" }}")
        .parse()
        .map_err(|e| {
            (
                "pypi_uv_lock_parse_failed",
                format!("cannot build sources value: {e}"),
            )
        })?;
    sources_table.insert(canon_name, Item::Value(sources_value.decorated(" ", "")));
    wiring.push(record(
        "pyproject.toml",
        "uv_sources_entry",
        WiringAction::Added,
        canon_name,
        None,
        format!("{canon_name} = {{ path = \"{rel_wheel}\" }}"),
    ));
    let new_pyproject = doc.to_string();

    // ── uv.lock text surgery (fully computed before any write) ────────────
    let mut new_lock = p.lock_text.clone();

    let (old_unit, new_unit) = rewrite_target_package_unit(
        &new_lock,
        canon_name,
        version,
        rel_wheel,
        wheel_file_name,
        wheel_sha256_hex,
    )?;
    new_lock = new_lock.replacen(&old_unit, &new_unit, 1);
    wiring.push(record(
        "uv.lock",
        "uv_lock_package",
        WiringAction::Rewritten,
        canon_name,
        Some(old_unit),
        new_unit,
    ));

    let mut original_specifier: Option<String> = None;
    match class {
        UvDepClass::Direct => {
            let edit = rewrite_requires_dist_entry(&new_lock, canon_name, rel_wheel)?;
            new_lock.replace_range(edit.span, &edit.new_entry);
            original_specifier = edit.specifier;
            wiring.push(record(
                "uv.lock",
                "uv_lock_requires_dist",
                WiringAction::Rewritten,
                canon_name,
                Some(edit.old_entry),
                edit.new_entry,
            ));
        }
        UvDepClass::Transitive => {
            let (rec, text) = add_manifest_override(&new_lock, canon_name, rel_wheel)?;
            new_lock = text;
            wiring.push(rec);
        }
    }

    // ── commit: pyproject first, then the lock; unwind on lock failure ────
    // Mode-preserving: both are user-owned files we merely edit, so the
    // swapped-in inode must keep its permission bits rather than reset them
    // to umask defaults (same class as the poetry/pdm/pipenv writers).
    let pyproject_path = root.join("pyproject.toml");
    atomic_write_bytes_preserving_mode(&pyproject_path, new_pyproject.as_bytes())
        .await
        .map_err(|e| {
            (
                "pypi_uv_write_failed",
                format!("cannot write pyproject.toml: {e}"),
            )
        })?;
    if let Err(e) =
        atomic_write_bytes_preserving_mode(&root.join("uv.lock"), new_lock.as_bytes()).await
    {
        // Unwind so a sources-bearing pyproject is never paired with the old
        // registry lock (that combo makes `uv lock --check` fail and plain
        // `uv sync` rewrite the lock under the user).
        let _ =
            atomic_write_bytes_preserving_mode(&pyproject_path, p.pyproject_text.as_bytes()).await;
        return Err((
            "pypi_uv_write_failed",
            format!("cannot write uv.lock: {e}; pyproject.toml was restored"),
        ));
    }

    let meta = UvMeta {
        dep_class: match class {
            UvDepClass::Direct => "direct".to_string(),
            UvDepClass::Transitive => "override".to_string(),
        },
        original_specifier,
        created_sources_table,
        lock_revision: p.lock_revision,
    };
    Ok((wiring, meta))
}

/// Reverse the wiring: restore verbatim originals (or delete added fragments)
/// in reverse application order. A live fragment that no longer matches what
/// we wrote is left alone with a `vendor_lock_entry_drifted` warning — revert
/// must never clobber third-party edits.
pub(super) async fn revert_uv(entry: &VendorEntry, root: &Path, dry_run: bool) -> RevertOutcome {
    let pyproject_path = root.join("pyproject.toml");
    let lock_path = root.join("uv.lock");
    let mut pyproject_text = match tokio::fs::read_to_string(&pyproject_path).await {
        Ok(t) => t,
        Err(e) => return RevertOutcome::failed(format!("cannot read pyproject.toml: {e}")),
    };
    let mut lock_text = match tokio::fs::read_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) => return RevertOutcome::failed(format!("cannot read uv.lock: {e}")),
    };
    let mut warnings: Vec<VendorWarning> = Vec::new();
    let created_sources_table = entry
        .uv
        .as_ref()
        .map(|m| m.created_sources_table)
        .unwrap_or(false);

    for rec in entry.wiring.iter().rev() {
        let new_text = rec.new.as_ref().and_then(serde_json::Value::as_str);
        let original_text = rec.original.as_ref().and_then(serde_json::Value::as_str);
        let drifted = |what: &str| {
            VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!(
                    "{what} fragment for {:?} changed since vendoring; left untouched",
                    rec.key
                ),
            )
        };
        match rec.kind.as_str() {
            "uv_lock_package" | "uv_lock_requires_dist" => {
                match replace_fragment(&lock_text, new_text, original_text) {
                    Some(t) => lock_text = t,
                    None => warnings.push(drifted("uv.lock")),
                }
            }
            "uv_lock_manifest_overrides" => match rec.action {
                WiringAction::Added => {
                    let Some(new) = new_text else {
                        warnings.push(drifted("uv.lock"));
                        continue;
                    };
                    // A created [manifest] section was inserted with a blank
                    // separator line; a created overrides key is one line.
                    let removed = if new.starts_with("[manifest]") {
                        remove_substring(&lock_text, &format!("{new}\n\n"))
                    } else {
                        remove_substring(&lock_text, &format!("{new}\n"))
                    };
                    match removed {
                        Some(t) => lock_text = t,
                        None => warnings.push(drifted("uv.lock")),
                    }
                }
                WiringAction::Rewritten => {
                    match replace_fragment(&lock_text, new_text, original_text) {
                        Some(t) => lock_text = t,
                        None => warnings.push(drifted("uv.lock")),
                    }
                }
            },
            "uv_sources_entry" => {
                let Some(new) = new_text else {
                    warnings.push(drifted("pyproject.toml"));
                    continue;
                };
                match remove_exact_line(&pyproject_text, new) {
                    Some(t) => {
                        pyproject_text = t;
                        if created_sources_table {
                            pyproject_text =
                                remove_table_if_empty(&pyproject_text, "[tool.uv.sources]");
                        }
                    }
                    None => warnings.push(drifted("pyproject.toml")),
                }
            }
            "uv_override" => match rec.action {
                WiringAction::Added => {
                    let Some(new) = new_text else {
                        warnings.push(drifted("pyproject.toml"));
                        continue;
                    };
                    match remove_exact_line(&pyproject_text, new) {
                        Some(t) => {
                            // Drop a now-empty [tool.uv] only when we created
                            // the whole structure (the sources entry above
                            // was removed first — reverse order).
                            pyproject_text = remove_table_if_empty(&t, "[tool.uv]");
                        }
                        None => warnings.push(drifted("pyproject.toml")),
                    }
                }
                WiringAction::Rewritten => {
                    match replace_fragment(&pyproject_text, new_text, original_text) {
                        Some(t) => pyproject_text = t,
                        None => warnings.push(drifted("pyproject.toml")),
                    }
                }
            },
            other => warnings.push(VendorWarning::new(
                "vendor_lock_entry_drifted",
                format!("unknown uv wiring kind {other:?}; skipped"),
            )),
        }
    }

    if !dry_run {
        // Reverse of the wire order: the lock first, then the pyproject.
        if let Err(e) = atomic_write_bytes_preserving_mode(&lock_path, lock_text.as_bytes()).await {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("cannot write uv.lock: {e}")),
            };
        }
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&pyproject_path, pyproject_text.as_bytes()).await
        {
            return RevertOutcome {
                success: false,
                warnings,
                error: Some(format!("cannot write pyproject.toml: {e}")),
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

/// Walk/create the table chain, marking CREATED intermediates implicit so
/// they never render stray `[tool]` headers.
fn ensure_table<'a>(
    doc: &'a mut DocumentMut,
    path: &[&str],
) -> Result<&'a mut Table, (&'static str, String)> {
    let mut table: &mut Table = doc.as_table_mut();
    for key in path {
        table = crate::pth_hook::edit::ensure_table(table, key, true).map_err(|_| {
            (
                "pypi_uv_lock_parse_failed",
                format!(
                    "pyproject.toml [{}] is not a standard table",
                    path.join(".")
                ),
            )
        })?;
    }
    Ok(table)
}

/// Whether the lock has a root `[[package]]` (source virtual/editable `.`).
fn lock_has_root_package(lock: &DocumentMut) -> bool {
    lock.get("package")
        .and_then(Item::as_array_of_tables)
        .is_some_and(|pkgs| {
            pkgs.iter().any(|t| {
                t.get("source")
                    .and_then(Item::as_inline_table)
                    .is_some_and(|source| {
                        ["virtual", "editable"]
                            .iter()
                            .any(|k| source.get(k).and_then(Value::as_str) == Some("."))
                    })
            })
        })
}

fn unit_has_name(lines: &[&str], canon: &str) -> bool {
    lines
        .iter()
        .find_map(|l| l.strip_prefix("name = "))
        .map(|r| r.trim().trim_matches('"'))
        == Some(canon)
}

fn unit_is_root(lines: &[&str]) -> bool {
    lines.iter().any(|l| {
        l.starts_with("source = {")
            && (l.contains("virtual = \".\"") || l.contains("editable = \".\""))
    })
}

/// Rewrite the target `[[package]]` unit to the path-wheel shape proven by
/// the fixtures: `source = { path = ... }`, `sdist` dropped, `wheels` becomes
/// the single `{ filename, hash }` element, `version` pinned to the vendored
/// version. Returns `(old_unit, new_unit)` verbatim for the wiring record.
fn rewrite_target_package_unit(
    lock_text: &str,
    canon: &str,
    version: &str,
    rel_wheel: &str,
    wheel_file_name: &str,
    wheel_sha256_hex: &str,
) -> Result<(String, String), (&'static str, String)> {
    let span = find_unit_span(lock_text, |lines| unit_has_name(lines, canon)).ok_or_else(|| {
        (
            "pypi_uv_lock_package_missing",
            format!("uv.lock has no [[package]] entry for {canon}"),
        )
    })?;
    let old_unit = lock_text[span].to_string();
    let unit: Vec<&str> = old_unit.lines().collect();
    let wheels_lines = [
        "wheels = [".to_string(),
        format!(
            "    {{ filename = \"{wheel_file_name}\", hash = \"sha256:{wheel_sha256_hex}\" }},"
        ),
        "]".to_string(),
    ];

    let mut out: Vec<String> = Vec::new();
    let mut wheels_done = false;
    let mut i = 0;
    while i < unit.len() {
        let line = unit[i];
        if line.starts_with("version = ") {
            out.push(format!("version = \"{version}\""));
        } else if line.starts_with("source = ") {
            out.push(format!("source = {{ path = \"{rel_wheel}\" }}"));
        } else if line.starts_with("sdist = ") {
            // dropped: a path-wheel source has no sdist (fixture-pinned)
        } else if line.starts_with("wheels = [") {
            out.extend(wheels_lines.iter().cloned());
            wheels_done = true;
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
    if !wheels_done {
        // sdist-only lock entry: add the wheels array at the end of the
        // [[package]] table itself, before any [package.*] sub-table.
        let mut pos = out
            .iter()
            .position(|l| l.starts_with("[package."))
            .unwrap_or(out.len());
        while pos > 0 && out[pos - 1].trim().is_empty() {
            pos -= 1;
        }
        out.splice(pos..pos, wheels_lines.iter().cloned());
    }
    Ok((old_unit, out.join("\n")))
}

/// One planned requires-dist entry rewrite: the absolute byte span plus the
/// verbatim old/new entry texts and the captured specifier.
struct RequiresDistEdit {
    span: Range<usize>,
    old_entry: String,
    new_entry: String,
    specifier: Option<String>,
}

/// Find + transform the root package's `requires-dist` entry for `canon`:
/// `{ name = "x", specifier = "==v" }` → `{ name = "x", path = "<rel>" }`
/// (uv DROPS the specifier for path sources — recorded for revert). Returns
/// the absolute byte span so the caller splices by range, never by string
/// search (a bare `{ name = "x" }` entry would collide with `dependencies`
/// arrays elsewhere in the lock).
fn rewrite_requires_dist_entry(
    lock_text: &str,
    canon: &str,
    rel_wheel: &str,
) -> Result<RequiresDistEdit, (&'static str, String)> {
    let unit_span = find_unit_span(lock_text, unit_is_root).ok_or_else(|| {
        (
            "pypi_uv_lock_root_missing",
            "uv.lock has no root [[package]] (source virtual/editable \".\")".to_string(),
        )
    })?;
    let unit_start = unit_span.start;
    let unit_text = &lock_text[unit_span];
    let rd_rel = unit_text.find("requires-dist = [").ok_or_else(|| {
        (
            "pypi_uv_lock_root_missing",
            "uv.lock root package has no [package.metadata] requires-dist".to_string(),
        )
    })?;
    let arr_open = rd_rel + "requires-dist = ".len();
    let arr_end = balanced_span(unit_text, arr_open).ok_or_else(|| {
        (
            "pypi_uv_lock_parse_failed",
            "uv.lock requires-dist array is unbalanced".to_string(),
        )
    })?;
    let array_text = &unit_text[arr_open..arr_end];
    let needle = format!("name = \"{canon}\"");
    for (s, e) in top_level_brace_groups(array_text) {
        let entry = &array_text[s..e];
        if !entry.contains(&needle) {
            continue;
        }
        let (new_entry, specifier) = path_source_entry(entry, rel_wheel);
        return Ok(RequiresDistEdit {
            span: (unit_start + arr_open + s)..(unit_start + arr_open + e),
            old_entry: entry.to_string(),
            new_entry,
            specifier,
        });
    }
    Err((
        "pypi_uv_lock_package_missing",
        format!("uv.lock root requires-dist has no entry for {canon}"),
    ))
}

/// Build the path-source requires-dist entry from the registry one: keep
/// every other key (extras, markers) in place, drop `specifier`, append
/// `path` — matching uv's own serialization of a sources-path dep.
fn path_source_entry(old_entry: &str, rel_wheel: &str) -> (String, Option<String>) {
    let inner = old_entry
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}');
    let mut kvs: Vec<String> = Vec::new();
    let mut specifier = None;
    for part in split_top_level_commas(inner) {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(value) = part.strip_prefix("specifier = ") {
            specifier = Some(value.trim().trim_matches('"').to_string());
            continue;
        }
        kvs.push(part.to_string());
    }
    kvs.push(format!("path = \"{rel_wheel}\""));
    (format!("{{ {} }}", kvs.join(", ")), specifier)
}

/// Add/extend the lock `[manifest] overrides` for a transitive override.
/// Returns the wiring record and the new lock text.
fn add_manifest_override(
    lock_text: &str,
    canon: &str,
    rel_wheel: &str,
) -> Result<(WiringRecord, String), (&'static str, String)> {
    let element = format!("{{ name = \"{canon}\", path = \"{rel_wheel}\" }}");
    let index = line_index(lock_text);
    let manifest_line = index.iter().position(|(_, l)| l.trim_end() == "[manifest]");

    let Some(h) = manifest_line else {
        // No [manifest] yet: create it between the lock header and the first
        // [[package]] (where uv itself emits it — fixture-pinned).
        let first_pkg = index
            .iter()
            .find(|(_, l)| l.trim_end() == "[[package]]")
            .map(|(off, _)| *off)
            .ok_or_else(|| {
                (
                    "pypi_uv_lock_parse_failed",
                    "uv.lock has no [[package]] entries".to_string(),
                )
            })?;
        let section = format!("[manifest]\noverrides = [{element}]");
        let mut text = lock_text.to_string();
        text.insert_str(first_pkg, &format!("{section}\n\n"));
        return Ok((
            record(
                "uv.lock",
                "uv_lock_manifest_overrides",
                WiringAction::Added,
                canon,
                None,
                section,
            ),
            text,
        ));
    };

    // Section spans until the next top-level header.
    let section_end_line = index[h + 1..]
        .iter()
        .position(|(_, l)| l.starts_with('['))
        .map(|i| h + 1 + i)
        .unwrap_or(index.len());
    let section_start = index[h].0;
    let section_end = index
        .get(section_end_line)
        .map(|(off, _)| *off)
        .unwrap_or(lock_text.len());
    let section_text = &lock_text[section_start..section_end];

    if let Some(ov_rel) = section_text.find("overrides = [") {
        let arr_open = ov_rel + "overrides = ".len();
        let arr_end = balanced_span(section_text, arr_open).ok_or_else(|| {
            (
                "pypi_uv_lock_parse_failed",
                "uv.lock [manifest] overrides array is unbalanced".to_string(),
            )
        })?;
        let old_array = &section_text[arr_open..arr_end];
        let new_array = if old_array.contains('\n') {
            // multi-line: add an indented element before the closing bracket
            let body = &old_array[..old_array.rfind(']').unwrap_or(old_array.len())];
            format!("{body}    {element},\n]")
        } else {
            format!("{}, {element}]", &old_array[..old_array.len() - 1])
        };
        let mut text = lock_text.to_string();
        text.replace_range(
            (section_start + arr_open)..(section_start + arr_end),
            &new_array,
        );
        return Ok((
            record(
                "uv.lock",
                "uv_lock_manifest_overrides",
                WiringAction::Rewritten,
                canon,
                Some(old_array.to_string()),
                new_array,
            ),
            text,
        ));
    }

    // [manifest] exists (e.g. members) but has no overrides yet: add the key
    // right under the header.
    let line = format!("overrides = [{element}]");
    let insert_at = index
        .get(h + 1)
        .map(|(off, _)| *off)
        .unwrap_or(lock_text.len());
    let mut text = lock_text.to_string();
    text.insert_str(insert_at, &format!("{line}\n"));
    Ok((
        record(
            "uv.lock",
            "uv_lock_manifest_overrides",
            WiringAction::Added,
            canon,
            None,
            line,
        ),
        text,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch::vendor::state::VendorArtifact;

    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    const REL_WHEEL: &str =
        ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl";
    const WHEEL_NAME: &str = "six-1.16.0-py2.py3-none-any.whl";
    const WHEEL_SHA: &str = "8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254";

    // ── fixture constants ──────────────────────────────────────────────
    // Byte-exact copies of the uv-generated spikes/uv/ fixtures (uv 0.11.19,
    // 2026-06-09). If these drift from the committed fixtures, the spike
    // dirs are the source of truth.

    const DIRECT_REGISTRY_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["six==1.16.0"]
"#;

    const DIRECT_PATH_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["six==1.16.0"]

[tool.uv.sources]
six = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
"#;

    const DIRECT_REGISTRY_LOCK: &str = r#"version = 1
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

    const DIRECT_PATH_LOCK: &str = r#"version = 1
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
requires-dist = [{ name = "six", path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }]

[[package]]
name = "six"
version = "1.16.0"
source = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
wheels = [
    { filename = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254" },
]
"#;

    const TRANSITIVE_REGISTRY_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["python-dateutil==2.8.2"]
"#;

    const OVERRIDE_TRANSITIVE_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["python-dateutil==2.8.2"]

[tool.uv]
override-dependencies = ["six==1.16.0"]

[tool.uv.sources]
six = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
"#;

    const TRANSITIVE_REGISTRY_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "python-dateutil" },
]

[package.metadata]
requires-dist = [{ name = "python-dateutil", specifier = "==2.8.2" }]

[[package]]
name = "python-dateutil"
version = "2.8.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "six" },
]
sdist = { url = "https://files.pythonhosted.org/packages/4c/c4/13b4776ea2d76c115c1d1b84579f3764ee6d57204f6be27119f13a61d0a9/python-dateutil-2.8.2.tar.gz", hash = "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86", size = 357324, upload-time = "2021-07-14T08:19:19.783Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/36/7a/87837f39d0296e723bb9b62bbb257d0355c7f6128853c78955f57342a56d/python_dateutil-2.8.2-py2.py3-none-any.whl", hash = "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9", size = 247702, upload-time = "2021-07-14T08:19:18.161Z" },
]

[[package]]
name = "six"
version = "1.17.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/94/e7/b2c673351809dca68a0e064b6af791aa332cf192da575fd474ed7d6f16a2/six-1.17.0.tar.gz", hash = "sha256:ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81", size = 34031, upload-time = "2024-12-04T17:35:28.174Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/b7/ce/149a00dd41f10bc29e5921b496af8b574d8413afcd5e30dfa0ed46c2cc5e/six-1.17.0-py2.py3-none-any.whl", hash = "sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274", size = 11050, upload-time = "2024-12-04T17:35:26.475Z" },
]
"#;

    const OVERRIDE_TRANSITIVE_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[manifest]
overrides = [{ name = "six", path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }]

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "python-dateutil" },
]

[package.metadata]
requires-dist = [{ name = "python-dateutil", specifier = "==2.8.2" }]

[[package]]
name = "python-dateutil"
version = "2.8.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "six" },
]
sdist = { url = "https://files.pythonhosted.org/packages/4c/c4/13b4776ea2d76c115c1d1b84579f3764ee6d57204f6be27119f13a61d0a9/python-dateutil-2.8.2.tar.gz", hash = "sha256:0123cacc1627ae19ddf3c27a5de5bd67ee4586fbdd6440d9748f8abb483d3e86", size = 357324, upload-time = "2021-07-14T08:19:19.783Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/36/7a/87837f39d0296e723bb9b62bbb257d0355c7f6128853c78955f57342a56d/python_dateutil-2.8.2-py2.py3-none-any.whl", hash = "sha256:961d03dc3453ebbc59dbdea9e4e11c5651520a876d0f4db161e8674aae935da9", size = 247702, upload-time = "2021-07-14T08:19:18.161Z" },
]

[[package]]
name = "six"
version = "1.16.0"
source = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
wheels = [
    { filename = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254" },
]
"#;

    async fn write_pair(pyproject: &str, lock: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("pyproject.toml"), pyproject)
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("uv.lock"), lock)
            .await
            .unwrap();
        tmp
    }

    async fn read_pair(root: &Path) -> (String, String) {
        (
            tokio::fs::read_to_string(root.join("pyproject.toml"))
                .await
                .unwrap(),
            tokio::fs::read_to_string(root.join("uv.lock"))
                .await
                .unwrap(),
        )
    }

    fn entry_for(wiring: Vec<WiringRecord>, meta: UvMeta) -> VendorEntry {
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
            flavor: Some("uv".into()),
            uv: Some(meta),
            pnpm: None,
            poetry: None,
            pdm: None,
            pipenv: None,
        }
    }

    /// The load-bearing oracle: wiring the direct-registry pair must produce
    /// the uv-generated direct-path-wheel pair BYTE-IDENTICALLY.
    #[tokio::test]
    async fn direct_wiring_matches_fixture_byte_identically() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert!(p.warnings.is_empty());
        assert_eq!(classify_dependency(&p, "six"), UvDepClass::Direct);

        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap();

        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(
            pyproject, DIRECT_PATH_PYPROJECT,
            "pyproject.toml must byte-match uv's own output"
        );
        assert_eq!(
            lock, DIRECT_PATH_LOCK,
            "uv.lock must byte-match uv's own output"
        );

        assert_eq!(meta.dep_class, "direct");
        assert_eq!(meta.original_specifier.as_deref(), Some("==1.16.0"));
        assert!(meta.created_sources_table);
        assert_eq!(meta.lock_revision, Some(3));
        let kinds: Vec<&str> = wiring.iter().map(|w| w.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "uv_sources_entry",
                "uv_lock_package",
                "uv_lock_requires_dist"
            ]
        );
    }

    /// Transitive deps wire via override-dependencies (spike claim 8), never
    /// promotion — the result must byte-match the override-transitive pair,
    /// including the lock's 1.17.0 → 1.16.0 version pin-down.
    #[tokio::test]
    async fn override_wiring_matches_fixture_byte_identically() {
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, TRANSITIVE_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(classify_dependency(&p, "six"), UvDepClass::Transitive);

        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap();

        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, OVERRIDE_TRANSITIVE_PYPROJECT);
        assert_eq!(lock, OVERRIDE_TRANSITIVE_LOCK);

        assert_eq!(meta.dep_class, "override");
        assert_eq!(meta.original_specifier, None);
        assert!(meta.created_sources_table);
        let kinds: Vec<&str> = wiring.iter().map(|w| w.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "uv_override",
                "uv_sources_entry",
                "uv_lock_package",
                "uv_lock_manifest_overrides"
            ]
        );
    }

    #[tokio::test]
    async fn guards_refuse_workspace_lock_version_fork_sources_and_dynamic() {
        // [tool.uv.workspace]
        let tmp = write_pair(
            &format!("{DIRECT_REGISTRY_PYPROJECT}\n[tool.uv.workspace]\nmembers = [\"pkgs/*\"]\n"),
            DIRECT_REGISTRY_LOCK,
        )
        .await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_workspace_unsupported");

        // lock [manifest] members beyond the root
        let tmp = write_pair(
            DIRECT_REGISTRY_PYPROJECT,
            &DIRECT_REGISTRY_LOCK.replace(
                "requires-python = \">=3.10\"\n",
                "requires-python = \">=3.10\"\n\n[manifest]\nmembers = [\n    \"proj\",\n    \"helper\",\n]\n",
            ),
        )
        .await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_workspace_unsupported");

        // lock version != 1
        let tmp = write_pair(
            DIRECT_REGISTRY_PYPROJECT,
            &DIRECT_REGISTRY_LOCK.replace("version = 1\n", "version = 2\n"),
        )
        .await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_version_unsupported");

        // unparseable lock
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, "version = [broken\n").await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");

        // missing root [[package]]
        let tmp = write_pair(
            DIRECT_REGISTRY_PYPROJECT,
            &DIRECT_REGISTRY_LOCK.replace(
                "source = { virtual = \".\" }",
                "source = { registry = \"x\" }",
            ),
        )
        .await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_root_missing");

        // dynamic dependencies
        let tmp = write_pair(
            &DIRECT_REGISTRY_PYPROJECT.replace(
                "dependencies = [\"six==1.16.0\"]\n",
                "dynamic = [\"dependencies\"]\n",
            ),
            DIRECT_REGISTRY_LOCK,
        )
        .await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_dynamic_dependencies");

        // forked package (six at two versions)
        let fork = format!(
            "{DIRECT_REGISTRY_LOCK}\n[[package]]\nname = \"six\"\nversion = \"1.17.0\"\nsource = {{ registry = \"https://pypi.org/simple\" }}\n"
        );
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, &fork).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let err = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_forked_package");

        // target absent from the lock entirely
        let tmp2 = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p2 = load_uv_project(tmp2.path()).await.unwrap();
        let err = wire_uv(
            &p2,
            tmp2.path(),
            "absent-pkg",
            "1.0.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_package_missing");

        // user-authored sources entry for the package
        let tmp = write_pair(
            &format!("{DIRECT_REGISTRY_PYPROJECT}\n[tool.uv.sources]\nsix = {{ path = \"../local/six\" }}\n"),
            DIRECT_REGISTRY_LOCK,
        )
        .await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let err = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_source_already_exists");
        assert!(err.1.contains("user-authored"), "{}", err.1);

        // an existing SOCKET source from a STALE patch generation refuses,
        // pointing at --revert; the SAME generation is the in-sync hot path.
        let tmp = write_pair(
            &format!("{DIRECT_REGISTRY_PYPROJECT}\n[tool.uv.sources]\nsix = {{ path = \"{REL_WHEEL}\" }}\n"),
            DIRECT_REGISTRY_LOCK,
        )
        .await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let err = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "11111111-2222-4333-8444-555555555555",
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_source_already_exists");
        assert!(err.1.contains("--revert"), "{}", err.1);
        assert_eq!(
            check_target_guards(&p, "six", "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f"),
            Ok(UvTarget::InSync),
            "the same patch generation is in sync, not a refusal"
        );

        // a user override for the package
        let tmp = write_pair(
            &format!("{TRANSITIVE_REGISTRY_PYPROJECT}\n[tool.uv]\noverride-dependencies = [\"six==1.15.0\"]\n"),
            TRANSITIVE_REGISTRY_LOCK,
        )
        .await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let err = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_source_already_exists");
    }

    #[tokio::test]
    async fn untested_lock_revision_is_a_warning_not_a_refusal() {
        let tmp = write_pair(
            DIRECT_REGISTRY_PYPROJECT,
            &DIRECT_REGISTRY_LOCK.replace("revision = 3\n", "revision = 9\n"),
        )
        .await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(p.warnings.len(), 1);
        assert_eq!(p.warnings[0].code, "pypi_uv_lock_revision_untested");
        assert_eq!(p.lock_revision, Some(9));
    }

    /// A failed lock write must unwind the already-written pyproject — a
    /// sources entry without the lock pair is exactly the silent-failure
    /// combo the spike warned about.
    #[tokio::test]
    async fn lock_write_failure_unwinds_pyproject() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(
                tmp.path().join("pyproject.toml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .await
            .unwrap();
        }
        let p = load_uv_project(tmp.path()).await.unwrap();
        // Make the lock unwritable: a directory can't be renamed over.
        tokio::fs::remove_file(tmp.path().join("uv.lock"))
            .await
            .unwrap();
        tokio::fs::create_dir(tmp.path().join("uv.lock"))
            .await
            .unwrap();

        let err = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_write_failed");
        let pyproject = tokio::fs::read_to_string(tmp.path().join("pyproject.toml"))
            .await
            .unwrap();
        assert_eq!(
            pyproject, DIRECT_REGISTRY_PYPROJECT,
            "pyproject must be unwound"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = tokio::fs::metadata(tmp.path().join("pyproject.toml"))
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the unwind write reset the mode");
        }
    }

    #[tokio::test]
    async fn revert_direct_restores_originals_byte_identically() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap();
        let entry = entry_for(wiring, meta);

        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(
            pyproject, DIRECT_REGISTRY_PYPROJECT,
            "requires-dist specifier restored"
        );
        assert_eq!(lock, DIRECT_REGISTRY_LOCK);
    }

    #[tokio::test]
    async fn revert_override_restores_originals_byte_identically() {
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, TRANSITIVE_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap();
        let entry = entry_for(wiring, meta);

        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(
            pyproject, TRANSITIVE_REGISTRY_PYPROJECT,
            "[tool.uv] removed when created by vendor"
        );
        assert_eq!(
            lock, TRANSITIVE_REGISTRY_LOCK,
            "[manifest] removed when created by vendor"
        );
    }

    /// wire_uv must refuse an in-sync pair (defensive parity with the
    /// poetry/pdm/pipenv backends): re-wiring would append a SECOND `path`
    /// key to the requires-dist entry (duplicate-key TOML — the lock stops
    /// parsing) and re-record our own vendored fragments as pre-vendor
    /// "originals", so a later revert would restore the vendored state.
    #[tokio::test]
    async fn wire_refuses_in_sync_pair_instead_of_corrupting_it() {
        let tmp = write_pair(DIRECT_PATH_PYPROJECT, DIRECT_PATH_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(
            check_target_guards(&p, "six", UUID),
            Ok(UvTarget::InSync),
            "precondition: the pair is in sync at this uuid"
        );

        let err = wire_uv(
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
        assert_eq!(err.0, "pypi_uv_source_already_exists");
        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, DIRECT_PATH_PYPROJECT, "pair must be untouched");
        assert_eq!(lock, DIRECT_PATH_LOCK, "pair must be untouched");
    }

    /// Wire and revert edit user-owned files in place — the swapped-in inode
    /// must keep the destination's permission bits rather than reset them to
    /// umask defaults (same class as the poetry/pdm/pipenv writers).
    #[cfg(unix)]
    #[tokio::test]
    async fn wire_and_revert_preserve_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        for f in ["pyproject.toml", "uv.lock"] {
            tokio::fs::set_permissions(tmp.path().join(f), std::fs::Permissions::from_mode(0o600))
                .await
                .unwrap();
        }
        let mode_of = |f: &str| {
            let path = tmp.path().join(f);
            async move {
                tokio::fs::metadata(path)
                    .await
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            }
        };

        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap();
        assert_eq!(
            mode_of("pyproject.toml").await,
            0o600,
            "wire reset the mode"
        );
        assert_eq!(mode_of("uv.lock").await, 0o600, "wire reset the mode");

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(
            mode_of("pyproject.toml").await,
            0o600,
            "revert reset the mode"
        );
        assert_eq!(mode_of("uv.lock").await, 0o600, "revert reset the mode");
    }

    #[tokio::test]
    async fn revert_dry_run_changes_nothing() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap();
        let entry = entry_for(wiring, meta);
        let (before_py, before_lock) = read_pair(tmp.path()).await;

        let outcome = revert_uv(&entry, tmp.path(), true).await;
        assert!(outcome.success);
        let (after_py, after_lock) = read_pair(tmp.path()).await;
        assert_eq!(before_py, after_py);
        assert_eq!(before_lock, after_lock);
    }

    /// A third-party edit to a fragment we wrote must be left alone with a
    /// drift warning — revert never clobbers what it can't positively match.
    #[tokio::test]
    async fn revert_warns_and_skips_on_drifted_lock_fragment() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f",
        )
        .await
        .unwrap();
        let entry = entry_for(wiring, meta);

        // Drift: someone re-hashed the vendored wheel entry.
        let lock = tokio::fs::read_to_string(tmp.path().join("uv.lock"))
            .await
            .unwrap();
        let drifted = lock.replace(WHEEL_SHA, &"0".repeat(64));
        tokio::fs::write(tmp.path().join("uv.lock"), &drifted)
            .await
            .unwrap();

        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|w| w.code == "vendor_lock_entry_drifted"),
            "{:?}",
            outcome.warnings
        );
        // The pyproject side (undrifted) was still reverted.
        let (pyproject, _) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, DIRECT_REGISTRY_PYPROJECT);
    }

    #[test]
    fn pep508_name_extraction_handles_extras_and_specifiers() {
        assert_eq!(pep508_name("six==1.16.0"), "six");
        assert_eq!(pep508_name("requests[socks]>=2.8"), "requests");
        assert_eq!(pep508_name("python-dateutil"), "python-dateutil");
        assert_eq!(pep508_name("My.Pkg_2 ; python_version > \"3\""), "My.Pkg_2");
    }

    #[test]
    fn path_source_entry_preserves_extras_and_captures_specifier() {
        let (new, spec) =
            path_source_entry("{ name = \"six\", specifier = \"==1.16.0\" }", REL_WHEEL);
        assert_eq!(new, format!("{{ name = \"six\", path = \"{REL_WHEEL}\" }}"));
        assert_eq!(spec.as_deref(), Some("==1.16.0"));

        // extras + marker survive (uv keeps them on path-source entries);
        // the embedded comma inside extras must not split the entry.
        let (new, spec) = path_source_entry(
            "{ name = \"x\", extras = [\"a\", \"b\"], specifier = \">=1\", marker = \"python_version >= \\\"3.9\\\"\" }",
            REL_WHEEL,
        );
        assert_eq!(
            new,
            format!(
                "{{ name = \"x\", extras = [\"a\", \"b\"], marker = \"python_version >= \\\"3.9\\\"\", path = \"{REL_WHEEL}\" }}"
            )
        );
        assert_eq!(spec.as_deref(), Some(">=1"));
    }
}
