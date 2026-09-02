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

/// Cap on the wheel `*.dist-info/METADATA` we read to reconstruct a path
/// source's `[package.metadata]` block — a sane ceiling for a core-metadata
/// header block (real ones are a few KiB).
const MAX_WHEEL_METADATA_BYTES: u64 = 4 * 1024 * 1024;

/// Guarded read shared in shape with the sibling backend twins:
/// `open_regular_file` opens with `O_NONBLOCK` and rejects non-regular
/// files, so a FIFO planted as `pyproject.toml` or `uv.lock` fails fast
/// instead of wedging every uv-project vendor run (and revert) forever in
/// an `open(2)` that waits for a writer — the flavor-routing probes ahead
/// of the load are metadata-only, so these are the first opens.
async fn read_regular_to_string(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt as _;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(path).await?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await?;
    Ok(content)
}

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
    let pyproject_text = read_regular_to_string(&root.join("pyproject.toml"))
        .await
        .map_err(|e| {
            (
                "pypi_uv_lock_parse_failed",
                format!("cannot read pyproject.toml: {e}"),
            )
        })?;
    let lock_text = read_regular_to_string(&root.join("uv.lock"))
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

/// The (wheel path, sha256) the WIRED pair still pins for an in-sync target:
/// the lock's rewritten `[[package]]` unit carries `source = { path = … }`
/// under THIS patch uuid's dir plus the single `{ filename, hash }` wheels
/// element vendor wrote — the very pin the next `uv sync` verifies. The
/// in-sync rebuild guard falls back to it when the state.json ledger has no
/// entry left for the patch. Paths are returned bare (no `./` prefix),
/// matching the ledger's `artifact.path` spelling.
pub(super) fn wired_pin(
    p: &UvProject,
    canon_name: &str,
    record_uuid: &str,
) -> Option<(String, String)> {
    let unit = p
        .lock
        .get("package")
        .and_then(Item::as_array_of_tables)?
        .iter()
        .find(|t| t.get("name").and_then(Item::as_str) == Some(canon_name))?;
    let path = unit
        .get("source")
        .and_then(Item::as_value)
        .and_then(Value::as_inline_table)
        .and_then(|t| t.get("path"))
        .and_then(Value::as_str)?;
    super::path::parse_vendor_path(path)
        .filter(|parts| parts.eco == "pypi" && parts.uuid == record_uuid)?;
    let sha = unit
        .get("wheels")
        .and_then(Item::as_array)?
        .iter()
        .find_map(|w| {
            w.as_inline_table()?
                .get("hash")?
                .as_str()?
                .strip_prefix("sha256:")
        })?;
    if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let path = path.strip_prefix("./").unwrap_or(path);
    Some((path.to_string(), sha.to_string()))
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

    // A path source has no registry index behind it, so uv records the
    // package's own requires-dist + provides-extras inline as a
    // `[package.metadata]` block. The registry lock we're rewriting omits it
    // (registry packages fetch metadata from the index), so we reconstruct it
    // from the vendored wheel's core METADATA. Without it `uv lock --check`
    // reports the lock stale and a plain `uv sync` silently rewrites the block
    // back in — lock churn that also defeats a byte-exact `vendor --revert`.
    let metadata_block = wheel_metadata_block(&root.join(rel_wheel)).await;

    let (old_unit, new_unit) = rewrite_target_package_unit(
        &new_lock,
        canon_name,
        version,
        rel_wheel,
        wheel_file_name,
        wheel_sha256_hex,
        metadata_block.as_deref(),
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
            let edits = rewrite_root_metadata_entries(&new_lock, canon_name, rel_wheel)?;
            // Splice back-to-front so the earlier (ascending) spans stay valid.
            for edit in edits.iter().rev() {
                new_lock.replace_range(edit.span.clone(), &edit.new_entry);
            }
            for edit in edits {
                if original_specifier.is_none() {
                    original_specifier = edit.specifier;
                }
                wiring.push(record(
                    "uv.lock",
                    edit.kind,
                    WiringAction::Rewritten,
                    canon_name,
                    Some(edit.old_entry),
                    edit.new_entry,
                ));
            }
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
/// must never clobber third-party edits — EXCEPT when the fragment already
/// equals its reverted state (a hand-restored file, a `uv lock` regeneration,
/// an earlier partial revert): that is convergence, not drift, and it stays
/// silent per the LIVENESS CONTRACT on [`RevertOutcome::drift_skipped`].
pub(super) async fn revert_uv(entry: &VendorEntry, root: &Path, dry_run: bool) -> RevertOutcome {
    let pyproject_path = root.join("pyproject.toml");
    let lock_path = root.join("uv.lock");
    let mut pyproject_text = match read_regular_to_string(&pyproject_path).await {
        Ok(t) => t,
        Err(e) => return RevertOutcome::failed(format!("cannot read pyproject.toml: {e}")),
    };
    let mut lock_text = match read_regular_to_string(&lock_path).await {
        Ok(t) => t,
        Err(e) => return RevertOutcome::failed(format!("cannot read uv.lock: {e}")),
    };
    let mut warnings: Vec<VendorWarning> = Vec::new();
    let created_sources_table = entry
        .uv
        .as_ref()
        .map(|m| m.created_sources_table)
        .unwrap_or(false);
    // Every artifact-routing fragment embeds the uuid dir path — the
    // ALREADY-CONVERGED probes below key on it (see the LIVENESS CONTRACT
    // on `RevertOutcome::drift_skipped`).
    let needle = format!(".socket/vendor/pypi/{}", entry.uuid);

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
            "uv_lock_package" | "uv_lock_requires_dist" | "uv_lock_requires_dev" => {
                match replace_fragment(&lock_text, new_text, original_text) {
                    Some(t) => lock_text = t,
                    None => {
                        // ALREADY CONVERGED (the LIVENESS CONTRACT,
                        // vendor/mod.rs): the lock already carries the
                        // recorded pre-vendor original — a `uv lock`
                        // regeneration or an earlier partial revert restored
                        // the fragment. Not drift: stay silent so the
                        // drift-keep gate can converge instead of keeping
                        // the artifact dir and ledger entry forever.
                        if original_text.is_some_and(|orig| lock_text.contains(orig)) {
                            continue;
                        }
                        warnings.push(drifted("uv.lock"));
                    }
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
                        None => {
                            // ALREADY CONVERGED: an Added fragment's reverted
                            // state is "no such fragment" — it being gone,
                            // with no surviving reference to this entry's
                            // uuid dir anywhere in the lock, satisfies it.
                            // A reshaped fragment that still routes through
                            // the artifact stays drift (fail-closed).
                            if !lock_text.contains(new) && !lock_text.contains(&needle) {
                                continue;
                            }
                            warnings.push(drifted("uv.lock"));
                        }
                    }
                }
                WiringAction::Rewritten => {
                    match replace_fragment(&lock_text, new_text, original_text) {
                        Some(t) => lock_text = t,
                        None => {
                            // ALREADY CONVERGED: see the package-unit arm.
                            if original_text.is_some_and(|orig| lock_text.contains(orig)) {
                                continue;
                            }
                            warnings.push(drifted("uv.lock"));
                        }
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
                    None => {
                        // ALREADY CONVERGED: the added sources line's
                        // reverted state is "no line" — the pyproject no
                        // longer referencing this entry's uuid dir satisfies
                        // it (a hand-restored pyproject). A reshaped line
                        // still routing through the artifact stays drift.
                        if !pyproject_text.contains(&needle) {
                            continue;
                        }
                        warnings.push(drifted("pyproject.toml"));
                    }
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
                        None => {
                            // ALREADY CONVERGED: the added override's
                            // reverted state is "no override array" — the
                            // whole `override-dependencies` key being gone
                            // satisfies it (a hand-restored pyproject). An
                            // array that still exists in ANY form stays
                            // drift, fail-closed (a user-edited spec, or
                            // user-authored overrides we must not touch).
                            if !pyproject_text.contains("override-dependencies") {
                                continue;
                            }
                            warnings.push(drifted("pyproject.toml"));
                        }
                    }
                }
                WiringAction::Rewritten => {
                    match replace_fragment(&pyproject_text, new_text, original_text) {
                        Some(t) => pyproject_text = t,
                        None => {
                            // ALREADY CONVERGED: see the package-unit arm.
                            if original_text.is_some_and(|orig| pyproject_text.contains(orig)) {
                                continue;
                            }
                            warnings.push(drifted("pyproject.toml"));
                        }
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
                kept_artifact: false,
                success: false,
                warnings,
                error: Some(format!("cannot write uv.lock: {e}")),
            };
        }
        if let Err(e) =
            atomic_write_bytes_preserving_mode(&pyproject_path, pyproject_text.as_bytes()).await
        {
            return RevertOutcome {
                kept_artifact: false,
                success: false,
                warnings,
                error: Some(format!("cannot write pyproject.toml: {e}")),
            };
        }
    }
    RevertOutcome {
        kept_artifact: false,
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
        table = crate::utils::toml_edit_ext::ensure_table(table, key, true).map_err(|_| {
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
/// version. `metadata_block`, when present, is the reconstructed
/// `[package.metadata]` section a path source needs (registry packages omit
/// it — see [`wheel_metadata_block`]); it is appended after the unit so the
/// whole rewrite stays inside the single `uv_lock_package` wiring record and
/// reverts as one byte-exact fragment. Returns `(old_unit, new_unit)`
/// verbatim for the wiring record.
fn rewrite_target_package_unit(
    lock_text: &str,
    canon: &str,
    version: &str,
    rel_wheel: &str,
    wheel_file_name: &str,
    wheel_sha256_hex: &str,
    metadata_block: Option<&str>,
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
    let mut new_unit = out.join("\n");
    if let Some(block) = metadata_block {
        // uv emits [package.metadata] as a sub-table after the [[package]]
        // body, separated by one blank line (fixture shape: `]\n\n[package…`).
        new_unit.push_str("\n\n");
        new_unit.push_str(block);
    }
    Ok((old_unit, new_unit))
}

/// One planned root-metadata entry rewrite: the absolute byte span plus the
/// verbatim old/new fragment texts, the captured specifier, and the wiring
/// record kind (`uv_lock_requires_dist` / `uv_lock_requires_dev`).
struct RequiresDistEdit {
    span: Range<usize>,
    old_entry: String,
    new_entry: String,
    specifier: Option<String>,
    kind: &'static str,
}

/// Find + transform EVERY root-package metadata entry for `canon`: the
/// `[package.metadata]` `requires-dist` array (project.dependencies /
/// optional-dependencies) AND each `[package.metadata.requires-dev]` group
/// array (PEP 735 `[dependency-groups]` — uv records group deps there, never
/// in requires-dist, and rewrites ALL entries to the path shape when a
/// source applies; spike-verified against uv 0.11.19). Each entry:
/// `{ name = "x", specifier = "==v" }` → `{ name = "x", path = "<rel>" }`
/// (uv DROPS the specifier for path sources — recorded for revert). Returns
/// absolute byte spans, ascending, so the caller splices by range, never by
/// string search (a bare `{ name = "x" }` entry would collide with
/// `dependencies` arrays elsewhere in the lock). requires-dev fragments span
/// the whole `<group> = […]` line so identically-pinned groups stay
/// distinguishable when revert matches fragments by text.
fn rewrite_root_metadata_entries(
    lock_text: &str,
    canon: &str,
    rel_wheel: &str,
) -> Result<Vec<RequiresDistEdit>, (&'static str, String)> {
    let unit_span = find_unit_span(lock_text, unit_is_root).ok_or_else(|| {
        (
            "pypi_uv_lock_root_missing",
            "uv.lock has no root [[package]] (source virtual/editable \".\")".to_string(),
        )
    })?;
    let unit_start = unit_span.start;
    let unit_text = &lock_text[unit_span];
    let needle = format!("name = \"{canon}\"");
    let mut edits: Vec<RequiresDistEdit> = Vec::new();

    // requires-dist lives in [package.metadata], always AHEAD of the
    // requires-dev sub-table — bound the search so a dev group literally
    // named "requires-dist" can never masquerade as the real key.
    let dev_hdr = unit_text.find("[package.metadata.requires-dev]");
    let dist_scan = &unit_text[..dev_hdr.unwrap_or(unit_text.len())];
    if let Some(rd_rel) = dist_scan.find("requires-dist = [") {
        let arr_open = rd_rel + "requires-dist = ".len();
        let arr_end = balanced_span(unit_text, arr_open).ok_or_else(|| {
            (
                "pypi_uv_lock_parse_failed",
                "uv.lock requires-dist array is unbalanced".to_string(),
            )
        })?;
        let array_text = &unit_text[arr_open..arr_end];
        for (s, e) in top_level_brace_groups(array_text) {
            let entry = &array_text[s..e];
            if !entry.contains(&needle) {
                continue;
            }
            let (new_entry, specifier) = path_source_entry(entry, rel_wheel);
            edits.push(RequiresDistEdit {
                span: (unit_start + arr_open + s)..(unit_start + arr_open + e),
                old_entry: entry.to_string(),
                new_entry,
                specifier,
                kind: "uv_lock_requires_dist",
            });
            break;
        }
    }

    if let Some(hdr_rel) = dev_hdr {
        // Section spans from after the header to the next sub-table header
        // (group array elements are indented, so a line-leading `[` is
        // always a header).
        let sect_start = hdr_rel + "[package.metadata.requires-dev]".len();
        let sect_end = unit_text[sect_start..]
            .find("\n[")
            .map(|i| sect_start + i + 1)
            .unwrap_or(unit_text.len());
        let mut cursor = sect_start;
        while let Some(open_rel) = unit_text[cursor..sect_end].find('[') {
            let arr_open = cursor + open_rel;
            let arr_end = balanced_span(unit_text, arr_open).ok_or_else(|| {
                (
                    "pypi_uv_lock_parse_failed",
                    "uv.lock [package.metadata.requires-dev] array is unbalanced".to_string(),
                )
            })?;
            let array_text = &unit_text[arr_open..arr_end];
            for (s, e) in top_level_brace_groups(array_text) {
                let entry = &array_text[s..e];
                if !entry.contains(&needle) {
                    continue;
                }
                let (new_entry, specifier) = path_source_entry(entry, rel_wheel);
                // Fragment from the group key so revert's text match can't
                // confuse two groups pinning the same entry.
                let key_start = unit_text[..arr_open].rfind('\n').map_or(0, |i| i + 1);
                edits.push(RequiresDistEdit {
                    span: (unit_start + key_start)..(unit_start + arr_end),
                    old_entry: unit_text[key_start..arr_end].to_string(),
                    new_entry: format!(
                        "{}{}{}",
                        &unit_text[key_start..arr_open + s],
                        new_entry,
                        &unit_text[arr_open + e..arr_end]
                    ),
                    specifier,
                    kind: "uv_lock_requires_dev",
                });
                break;
            }
            cursor = arr_end;
        }
    }

    if edits.is_empty() {
        return Err((
            "pypi_uv_lock_package_missing",
            format!(
                "uv.lock root [package.metadata] has no requires-dist or requires-dev entry \
                 for {canon}; run `uv lock` first"
            ),
        ));
    }
    Ok(edits)
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
        } else if old_array[1..old_array.len() - 1].trim().is_empty() {
            // `overrides = []` (hand-edited; uv omits the key when empty):
            // no existing element to comma-separate from
            format!("[{element}]")
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

// ── path-source [package.metadata] reconstruction ──────────────────────────

/// One `requires-dist` dependency parsed from a wheel's core METADATA, in the
/// pieces uv serializes into an inline table.
#[derive(Debug, PartialEq, Eq)]
struct MetaDep {
    /// PEP 503-canonical distribution name.
    name: String,
    /// PEP 685-canonical extras (`requests[socks]` → `["socks"]`).
    extras: Vec<String>,
    /// Version specifier with whitespace stripped, parens removed (`None` when
    /// the requirement pins no version).
    specifier: Option<String>,
    /// Environment marker verbatim from METADATA (`None` when unconditional).
    marker: Option<String>,
}

/// Best-effort: read the vendored wheel's core METADATA and render the
/// `[package.metadata]` block a uv path source needs. `None` when the wheel
/// can't be read, has no `*.dist-info/METADATA`, or (like `six`) declares no
/// requires-dist / provides-extras — uv omits the block in that case too, so
/// the fixtures that pass no block stay byte-exact.
async fn wheel_metadata_block(wheel_path: &Path) -> Option<String> {
    let bytes = tokio::fs::read(wheel_path).await.ok()?;
    let text = wheel_metadata_text(&bytes)?;
    render_package_metadata_block(&text)
}

/// Extract the top-level `*.dist-info/METADATA` text from a wheel zip.
fn wheel_metadata_text(bytes: &[u8]) -> Option<String> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).ok()?;
    let mut metadata_name: Option<String> = None;
    for i in 0..archive.len() {
        let entry = archive.by_index(i).ok()?;
        let name = entry.name();
        // A wheel's metadata lives at `<dist>-<ver>.dist-info/METADATA`, one
        // level below the root — never nested inside another directory.
        if let Some(stem) = name.strip_suffix("/METADATA") {
            if stem.ends_with(".dist-info") && !stem.contains('/') {
                metadata_name = Some(name.to_string());
                break;
            }
        }
    }
    let metadata_name = metadata_name?;
    let mut entry = archive.by_name(&metadata_name).ok()?;
    if entry.size() > MAX_WHEEL_METADATA_BYTES {
        return None;
    }
    let mut text = String::new();
    entry.read_to_string(&mut text).ok()?;
    Some(text)
}

/// Collect the `Requires-Dist` / `Provides-Extra` header values from a wheel's
/// core METADATA. Only the header block (up to the first blank line) is
/// scanned, so a `Requires-Dist:` line quoted inside the long-description body
/// can never be mistaken for a real requirement.
fn parse_core_metadata_fields(text: &str) -> (Vec<String>, Vec<String>) {
    let mut requires_dist = Vec::new();
    let mut provides_extra = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            break; // end of the RFC822 header block
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue; // folded continuation (never used for these fields)
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("Requires-Dist") {
            requires_dist.push(value.to_string());
        } else if name.eq_ignore_ascii_case("Provides-Extra") {
            provides_extra.push(value.to_string());
        }
    }
    (requires_dist, provides_extra)
}

/// Parse one PEP 508 `Requires-Dist` value into its uv inline-table pieces.
/// `None` when the leading distribution name is missing (a malformed line) —
/// the caller then drops the whole block rather than emit partial TOML.
fn parse_requires_dist(raw: &str) -> Option<MetaDep> {
    let raw = raw.trim();
    let (req, marker) = match raw.split_once(';') {
        Some((r, m)) => (r.trim(), Some(m.trim().to_string())),
        None => (raw, None),
    };
    let marker = marker.filter(|m| !m.is_empty());

    let name_end = req
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')))
        .unwrap_or(req.len());
    if name_end == 0 {
        return None;
    }
    let name = canonicalize_pypi_name(&req[..name_end]);
    let mut rest = req[name_end..].trim_start();

    let mut extras = Vec::new();
    if let Some(after_open) = rest.strip_prefix('[') {
        let close = after_open.find(']')?;
        extras = after_open[..close]
            .split(',')
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(canonicalize_pypi_name)
            .collect();
        rest = after_open[close + 1..].trim_start();
    }

    // A PEP 508 direct reference (`name @ https://…`) has no PEP 440
    // specifier form uv could parse back out of the lock — fail closed (the
    // caller drops the whole block; `uv sync` heals it) rather than emit a
    // bogus `specifier = "@https://…"`.
    if rest.starts_with('@') {
        return None;
    }

    // The version specifier may be wrapped in parens (older METADATA style,
    // e.g. `six (>=1.5)`); strip them, then drop all interior whitespace
    // (uv serializes specifiers compactly).
    let mut spec = rest.trim();
    if let Some(inner) = spec.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        spec = inner.trim();
    }
    let specifier =
        (!spec.is_empty()).then(|| spec.chars().filter(|c| !c.is_whitespace()).collect());

    Some(MetaDep {
        name,
        extras,
        specifier,
        marker,
    })
}

/// Escape a string for a TOML basic (double-quoted) string.
fn toml_basic_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Render one parsed dependency as a uv `requires-dist` inline table
/// (`{ name = …, extras = […], marker = "…", specifier = "…" }`, key order
/// matching uv's serializer).
fn render_requires_dist_entry(dep: &MetaDep) -> String {
    let mut parts = vec![format!("name = \"{}\"", dep.name)];
    if !dep.extras.is_empty() {
        let extras = dep
            .extras
            .iter()
            .map(|e| format!("\"{e}\""))
            .collect::<Vec<_>>()
            .join(", ");
        parts.push(format!("extras = [{extras}]"));
    }
    if let Some(marker) = &dep.marker {
        parts.push(format!("marker = \"{}\"", toml_basic_escape(marker)));
    }
    if let Some(specifier) = &dep.specifier {
        parts.push(format!("specifier = \"{specifier}\""));
    }
    format!("{{ {} }}", parts.join(", "))
}

/// Reconstruct uv's `[package.metadata]` block for a path source from its
/// wheel core METADATA text. Returns the block (no leading/trailing newline)
/// or `None` when there is nothing to record (no requires-dist AND no
/// provides-extras) or a `Requires-Dist` line fails to parse — in which case
/// we emit no block rather than risk malformed TOML (`uv sync` then heals it,
/// the pre-fix behavior, instead of failing to parse the lock).
fn render_package_metadata_block(metadata_text: &str) -> Option<String> {
    let (requires_raw, provides_raw) = parse_core_metadata_fields(metadata_text);
    if requires_raw.is_empty() && provides_raw.is_empty() {
        return None;
    }

    let mut entries = Vec::with_capacity(requires_raw.len());
    for raw in &requires_raw {
        entries.push(render_requires_dist_entry(&parse_requires_dist(raw)?));
    }

    let mut block = String::from("[package.metadata]\n");
    match entries.len() {
        0 => block.push_str("requires-dist = []"),
        1 => {
            block.push_str("requires-dist = [");
            block.push_str(&entries[0]);
            block.push(']');
        }
        _ => {
            block.push_str("requires-dist = [\n");
            for entry in &entries {
                block.push_str("    ");
                block.push_str(entry);
                block.push_str(",\n");
            }
            block.push(']');
        }
    }

    if !provides_raw.is_empty() {
        let extras = provides_raw
            .iter()
            .map(|e| format!("\"{}\"", canonicalize_pypi_name(e)))
            .collect::<Vec<_>>()
            .join(", ");
        block.push_str("\nprovides-extras = [");
        block.push_str(&extras);
        block.push(']');
    }

    Some(block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::state::VendorArtifact;

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
                file_inventory: None,
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

    /// The wired-pair pin reader the in-sync rebuild guard falls back to
    /// when the state.json ledger has no entry: the lock's rewritten
    /// `[[package]]` unit yields (wheel path, sha256); a registry-shaped
    /// lock, or a foreign uuid, yields None (the guard then stays off, as
    /// before, rather than guessing).
    #[tokio::test]
    async fn wired_pin_reads_the_wired_pair() {
        let tmp = write_pair(DIRECT_PATH_PYPROJECT, DIRECT_PATH_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(
            wired_pin(&p, "six", UUID),
            Some((REL_WHEEL.to_string(), WHEEL_SHA.to_string()))
        );
        assert_eq!(
            wired_pin(&p, "six", "00000000-0000-4000-8000-000000000000"),
            None,
            "a foreign patch uuid pins nothing of ours"
        );
        let tmp2 = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p2 = load_uv_project(tmp2.path()).await.unwrap();
        assert_eq!(
            wired_pin(&p2, "six", UUID),
            None,
            "a registry-shaped lock pins nothing of ours"
        );
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

    /// mkfifo(2) directly rather than shelling out to the `mkfifo` binary —
    /// same helper as the sibling backend FIFO tests: fork/exec flakes under
    /// heavy parallel load and the syscall needs no process at all.
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

    /// A FIFO planted as `uv.lock` or `pyproject.toml` must not wedge load
    /// or revert: `detect_pypi_flavor`'s routing probe is metadata-only (a
    /// FIFO stats fine), so the backend's raw `read_to_string` open(2) is
    /// the FIRST open — it waits for a writer that never comes, wedging
    /// every uv-project vendor run (and `vendor --revert`) indefinitely.
    /// Same `open_regular_file` guard class as the sibling vendor backends.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_lock_or_pyproject_does_not_wedge_load_or_revert() {
        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);

        // FIFO as uv.lock (pyproject regular).
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("pyproject.toml"), DIRECT_REGISTRY_PYPROJECT)
            .await
            .unwrap();
        let lock_fifo = tmp.path().join("uv.lock");
        mkfifo(&lock_fifo);

        // FIFO as pyproject.toml (lock regular).
        let tmp2 = tempfile::tempdir().unwrap();
        let py_fifo = tmp2.path().join("pyproject.toml");
        mkfifo(&py_fifo);
        tokio::fs::write(tmp2.path().join("uv.lock"), DIRECT_REGISTRY_LOCK)
            .await
            .unwrap();

        // Load must refuse fast on either FIFO.
        for (root, fifo, what) in [
            (tmp.path(), &lock_fifo, "uv.lock"),
            (tmp2.path(), &py_fifo, "pyproject.toml"),
        ] {
            let Ok(res) = tokio::time::timeout(deadline, load_uv_project(root)).await else {
                let _ = std::fs::OpenOptions::new().write(true).open(fifo);
                panic!("load_uv_project must complete promptly with a FIFO {what}");
            };
            assert_eq!(res.unwrap_err().0, "pypi_uv_lock_parse_failed");
        }

        // Revert reads both files itself (flavor routing never opens them
        // first): must fail fast on either FIFO, not wedge.
        let entry = entry_for(
            Vec::new(),
            UvMeta {
                dep_class: "direct".into(),
                original_specifier: None,
                created_sources_table: true,
                lock_revision: Some(3),
            },
        );
        for (root, fifo, what) in [
            (tmp.path(), &lock_fifo, "uv.lock"),
            (tmp2.path(), &py_fifo, "pyproject.toml"),
        ] {
            let Ok(outcome) = tokio::time::timeout(deadline, revert_uv(&entry, root, false)).await
            else {
                let _ = std::fs::OpenOptions::new().write(true).open(fifo);
                panic!("revert_uv must complete promptly with a FIFO {what}");
            };
            assert!(!outcome.success, "FIFO {what} must fail the revert");
            assert!(
                outcome.error.as_deref().unwrap_or("").contains("cannot read"),
                "{:?}",
                outcome.error
            );
        }
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

    // ── path-source [package.metadata] reconstruction ──────────────────

    #[test]
    fn parse_requires_dist_pulls_apart_name_extras_specifier_marker() {
        // extra-gated dep with a bare specifier
        assert_eq!(
            parse_requires_dist("leftpad >=1.0 ; extra == 'fast'"),
            Some(MetaDep {
                name: "leftpad".into(),
                extras: vec![],
                specifier: Some(">=1.0".into()),
                marker: Some("extra == 'fast'".into()),
            })
        );
        // legacy parenthesized specifier, no marker (uv strips the parens)
        assert_eq!(
            parse_requires_dist("six (>=1.5)"),
            Some(MetaDep {
                name: "six".into(),
                extras: vec![],
                specifier: Some(">=1.5".into()),
                marker: None,
            })
        );
        // extras in the name, name canonicalized, multi-constraint specifier
        assert_eq!(
            parse_requires_dist("PySocks[Fast,Slow] !=1.5.7,<2.0,>=1.5.6 ; extra == 'socks'"),
            Some(MetaDep {
                name: "pysocks".into(),
                extras: vec!["fast".into(), "slow".into()],
                specifier: Some("!=1.5.7,<2.0,>=1.5.6".into()),
                marker: Some("extra == 'socks'".into()),
            })
        );
        // no specifier at all
        assert_eq!(
            parse_requires_dist("certifi ; extra == 'secure'"),
            Some(MetaDep {
                name: "certifi".into(),
                extras: vec![],
                specifier: None,
                marker: Some("extra == 'secure'".into()),
            })
        );
        // a line with no leading name is rejected (fail-closed)
        assert_eq!(parse_requires_dist(">=1.0"), None);
    }

    #[test]
    fn core_metadata_fields_stop_at_the_header_block() {
        let text = "Metadata-Version: 2.1\n\
                    Name: widget\n\
                    Provides-Extra: fast\n\
                    Requires-Dist: leftpad >=1.0 ; extra == 'fast'\n\
                    \n\
                    Long description follows.\n\
                    Requires-Dist: not-a-real-dep ==9.9\n\
                    Provides-Extra: bogus\n";
        let (requires, provides) = parse_core_metadata_fields(text);
        // body lines after the blank separator are never scanned
        assert_eq!(requires, vec!["leftpad >=1.0 ; extra == 'fast'"]);
        assert_eq!(provides, vec!["fast"]);
    }

    #[test]
    fn render_block_reconstructs_requires_dist_and_provides_extras() {
        let text = "Name: widget\n\
                    Provides-Extra: fast\n\
                    Requires-Dist: leftpad >=1.0 ; extra == 'fast'\n\
                    Requires-Dist: rightpad (>=2.0)\n\
                    \n\
                    body\n";
        assert_eq!(
            render_package_metadata_block(text).as_deref(),
            Some(
                "[package.metadata]\n\
                 requires-dist = [\n    \
                 { name = \"leftpad\", marker = \"extra == 'fast'\", specifier = \">=1.0\" },\n    \
                 { name = \"rightpad\", specifier = \">=2.0\" },\n\
                 ]\n\
                 provides-extras = [\"fast\"]"
            )
        );

        // one requires-dist, no extras → uv's single-line array form
        let single = "Name: x\nRequires-Dist: six (>=1.5)\n\n";
        assert_eq!(
            render_package_metadata_block(single).as_deref(),
            Some("[package.metadata]\nrequires-dist = [{ name = \"six\", specifier = \">=1.5\" }]")
        );

        // a package with no requires-dist / provides-extras (like `six`) gets
        // NO block, so the fixtures that pass no block stay byte-exact.
        assert_eq!(render_package_metadata_block("Name: six\n\n"), None);
    }

    #[test]
    fn render_block_escapes_double_quoted_markers_for_toml() {
        let text = "Name: x\n\
                    Requires-Dist: brotlicffi >=0.8.0 ; os_name != \"nt\" and extra == 'brotli'\n\
                    Provides-Extra: brotli\n\n";
        let block = render_package_metadata_block(text).unwrap();
        assert!(
            block.contains("marker = \"os_name != \\\"nt\\\" and extra == 'brotli'\""),
            "double quotes in the marker must be TOML-escaped: {block}"
        );
    }

    // A registry-sourced package with extras/deps has NO [package.metadata] in
    // the lock (uv fetches it from the index); the path source uv rewrites it
    // to DOES need one. Reconstruct it from the vendored wheel's METADATA so
    // `uv lock --check` stays green and `vendor --revert` byte-restores.
    const WIDGET_REGISTRY_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["widget==1.0.0"]
"#;

    const WIDGET_REGISTRY_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "widget" },
]

[package.metadata]
requires-dist = [{ name = "widget", specifier = "==1.0.0" }]

[[package]]
name = "widget"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://example.invalid/widget-1.0.0.tar.gz", hash = "sha256:aaaa", size = 10 }
wheels = [
    { url = "https://example.invalid/widget-1.0.0-py3-none-any.whl", hash = "sha256:bbbb", size = 10 },
]
"#;

    const WIDGET_WHEEL_NAME: &str = "widget-1.0.0-py3-none-any.whl";
    const WIDGET_WHEEL_SHA: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Build a minimal wheel whose only entry is the core METADATA, and drop
    /// it at `rel` under `root` (parents created).
    async fn write_widget_wheel(root: &Path, rel: &str, metadata: &str) {
        let entries = vec![(
            "widget-1.0.0.dist-info/METADATA".to_string(),
            metadata.as_bytes().to_vec(),
            0o644,
        )];
        let bytes = crate::vendor::common::write_zip_entries(&entries).unwrap();
        let path = root.join(rel);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, &bytes).await.unwrap();
    }

    /// The core defect: after wiring, the path-sourced package must carry the
    /// reconstructed `[package.metadata]` block (it was dropped before the
    /// fix, leaving `uv lock --check` red), and `vendor --revert` must
    /// byte-restore the original registry lock.
    #[tokio::test]
    async fn direct_wiring_reconstructs_package_metadata_block_and_reverts() {
        let rel_wheel = format!(".socket/vendor/pypi/{UUID}/{WIDGET_WHEEL_NAME}");
        let tmp = write_pair(WIDGET_REGISTRY_PYPROJECT, WIDGET_REGISTRY_LOCK).await;
        // Header block declares the deps; a poisoned body must be ignored.
        let metadata = "Metadata-Version: 2.1\n\
                        Name: widget\n\
                        Version: 1.0.0\n\
                        Provides-Extra: fast\n\
                        Requires-Dist: leftpad >=1.0 ; extra == 'fast'\n\
                        Requires-Dist: rightpad (>=2.0)\n\
                        \n\
                        Long description.\n\
                        Requires-Dist: not-a-real-dep ==9.9\n";
        write_widget_wheel(tmp.path(), &rel_wheel, metadata).await;

        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(classify_dependency(&p, "widget"), UvDepClass::Direct);
        let (wiring, meta) = wire_uv(
            &p,
            tmp.path(),
            "widget",
            "1.0.0",
            &rel_wheel,
            WIDGET_WHEEL_NAME,
            WIDGET_WHEEL_SHA,
            UUID,
        )
        .await
        .unwrap();

        let (_, lock) = read_pair(tmp.path()).await;
        // The path-sourced `widget` unit now carries its reconstructed metadata.
        assert!(
            lock.contains(
                "source = { path = \".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/widget-1.0.0-py3-none-any.whl\" }\n\
                 wheels = [\n    \
                 { filename = \"widget-1.0.0-py3-none-any.whl\", hash = \"sha256:1111111111111111111111111111111111111111111111111111111111111111\" },\n\
                 ]\n\
                 \n\
                 [package.metadata]\n\
                 requires-dist = [\n    \
                 { name = \"leftpad\", marker = \"extra == 'fast'\", specifier = \">=1.0\" },\n    \
                 { name = \"rightpad\", specifier = \">=2.0\" },\n\
                 ]\n\
                 provides-extras = [\"fast\"]"
            ),
            "reconstructed [package.metadata] block missing:\n{lock}"
        );
        // The description-body line must never leak into the lock.
        assert!(
            !lock.contains("not-a-real-dep"),
            "body line leaked:\n{lock}"
        );

        // revert byte-restores the original registry lock + pyproject.
        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, WIDGET_REGISTRY_PYPROJECT);
        assert_eq!(
            lock, WIDGET_REGISTRY_LOCK,
            "revert must byte-restore uv.lock"
        );
    }

    /// A hand-edited `overrides = []` (uv itself omits the key when empty)
    /// must extend to a well-formed single-element array — the single-line
    /// branch used to emit `[, { … }]`, a leading comma that stops the whole
    /// lock from parsing (every later `uv sync` AND our own next load fail).
    #[tokio::test]
    async fn override_wiring_extends_an_empty_manifest_overrides_array() {
        let empty_overrides_lock = TRANSITIVE_REGISTRY_LOCK.replace(
            "requires-python = \">=3.10\"\n",
            "requires-python = \">=3.10\"\n\n[manifest]\noverrides = []\n",
        );
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, &empty_overrides_lock).await;
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

        let (pyproject, lock) = read_pair(tmp.path()).await;
        lock.parse::<DocumentMut>()
            .expect("the wired uv.lock must stay parseable TOML");
        assert_eq!(pyproject, OVERRIDE_TRANSITIVE_PYPROJECT);
        assert_eq!(
            lock, OVERRIDE_TRANSITIVE_LOCK,
            "extending an empty overrides array must byte-match uv's own \
             single-element form"
        );

        // revert byte-restores the empty array, not uv's omitted-key form —
        // the user wrote `overrides = []` and gets it back verbatim.
        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, TRANSITIVE_REGISTRY_PYPROJECT);
        assert_eq!(lock, empty_overrides_lock);
    }

    // ── PEP 735 dependency-groups (requires-dev) fixtures ───────────────
    // Byte-exact uv output (uv 0.11.19, 2026-09-01): a dep declared only in
    // `[dependency-groups]` is recorded in the root unit's
    // `[package.metadata.requires-dev]` groups, never `requires-dist`, and a
    // path source rewrites EVERY group entry with the same specifier→path
    // transformation.

    const DEV_GROUP_REGISTRY_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = []

[dependency-groups]
dev = ["six==1.16.0"]
"#;

    const DEV_GROUP_PATH_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = []

[dependency-groups]
dev = ["six==1.16.0"]

[tool.uv.sources]
six = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
"#;

    const DEV_GROUP_REGISTRY_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }

[package.dev-dependencies]
dev = [
    { name = "six" },
]

[package.metadata]

[package.metadata.requires-dev]
dev = [{ name = "six", specifier = "==1.16.0" }]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926", size = 34041, upload-time = "2021-05-05T14:18:18.379Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#;

    const DEV_GROUP_PATH_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }

[package.dev-dependencies]
dev = [
    { name = "six" },
]

[package.metadata]

[package.metadata.requires-dev]
dev = [{ name = "six", path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }]

[[package]]
name = "six"
version = "1.16.0"
source = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
wheels = [
    { filename = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254" },
]
"#;

    const MIXED_SURFACES_REGISTRY_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["six==1.16.0"]

[dependency-groups]
dev = ["six==1.16.0"]
lint = ["six==1.16.0"]
"#;

    const MIXED_SURFACES_PATH_PYPROJECT: &str = r#"[project]
name = "proj"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["six==1.16.0"]

[dependency-groups]
dev = ["six==1.16.0"]
lint = ["six==1.16.0"]

[tool.uv.sources]
six = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
"#;

    const MIXED_SURFACES_REGISTRY_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "six" },
]

[package.dev-dependencies]
dev = [
    { name = "six" },
]
lint = [
    { name = "six" },
]

[package.metadata]
requires-dist = [{ name = "six", specifier = "==1.16.0" }]

[package.metadata.requires-dev]
dev = [{ name = "six", specifier = "==1.16.0" }]
lint = [{ name = "six", specifier = "==1.16.0" }]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926", size = 34041, upload-time = "2021-05-05T14:18:18.379Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", size = 11053, upload-time = "2021-05-05T14:18:17.237Z" },
]
"#;

    const MIXED_SURFACES_PATH_LOCK: &str = r#"version = 1
revision = 3
requires-python = ">=3.10"

[[package]]
name = "proj"
version = "0.1.0"
source = { virtual = "." }
dependencies = [
    { name = "six" },
]

[package.dev-dependencies]
dev = [
    { name = "six" },
]
lint = [
    { name = "six" },
]

[package.metadata]
requires-dist = [{ name = "six", path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }]

[package.metadata.requires-dev]
dev = [{ name = "six", path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }]
lint = [{ name = "six", path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }]

[[package]]
name = "six"
version = "1.16.0"
source = { path = ".socket/vendor/pypi/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/six-1.16.0-py2.py3-none-any.whl" }
wheels = [
    { filename = "six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254" },
]
"#;

    /// A dep declared ONLY under PEP 735 `[dependency-groups]` classifies
    /// Direct (sources apply to it), but uv records it in the root unit's
    /// `[package.metadata.requires-dev]`, never `requires-dist` — wiring
    /// must rewrite the group entry, not refuse with a root-missing error.
    #[tokio::test]
    async fn dev_group_wiring_matches_fixture_byte_identically() {
        let tmp = write_pair(DEV_GROUP_REGISTRY_PYPROJECT, DEV_GROUP_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(classify_dependency(&p, "six"), UvDepClass::Direct);

        let (wiring, meta) = wire_uv(
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
        .unwrap();

        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, DEV_GROUP_PATH_PYPROJECT);
        assert_eq!(
            lock, DEV_GROUP_PATH_LOCK,
            "uv.lock must byte-match uv's own dev-group path-source output"
        );
        assert_eq!(meta.dep_class, "direct");
        assert_eq!(meta.original_specifier.as_deref(), Some("==1.16.0"));
        let kinds: Vec<&str> = wiring.iter().map(|w| w.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["uv_sources_entry", "uv_lock_package", "uv_lock_requires_dev"]
        );

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, DEV_GROUP_REGISTRY_PYPROJECT);
        assert_eq!(lock, DEV_GROUP_REGISTRY_LOCK);
    }

    /// A dep declared in project.dependencies AND several dependency-groups:
    /// uv rewrites the requires-dist entry AND every requires-dev group
    /// entry to the path shape — so must we, or `uv lock --check` goes red.
    #[tokio::test]
    async fn mixed_surfaces_wiring_rewrites_every_metadata_entry() {
        let tmp = write_pair(
            MIXED_SURFACES_REGISTRY_PYPROJECT,
            MIXED_SURFACES_REGISTRY_LOCK,
        )
        .await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(classify_dependency(&p, "six"), UvDepClass::Direct);

        let (wiring, meta) = wire_uv(
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
        .unwrap();

        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, MIXED_SURFACES_PATH_PYPROJECT);
        assert_eq!(
            lock, MIXED_SURFACES_PATH_LOCK,
            "every requires-dist/requires-dev entry must be rewritten"
        );
        assert_eq!(meta.original_specifier.as_deref(), Some("==1.16.0"));
        let kinds: Vec<&str> = wiring.iter().map(|w| w.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "uv_sources_entry",
                "uv_lock_package",
                "uv_lock_requires_dist",
                "uv_lock_requires_dev",
                "uv_lock_requires_dev"
            ]
        );

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (pyproject, lock) = read_pair(tmp.path()).await;
        assert_eq!(pyproject, MIXED_SURFACES_REGISTRY_PYPROJECT);
        assert_eq!(lock, MIXED_SURFACES_REGISTRY_LOCK);
    }

    /// A PEP 508 direct reference (`name @ https://…`) has no PEP 440
    /// specifier form — it must fail closed (whole block dropped, uv sync
    /// heals the lock) rather than sail through as the bogus
    /// `specifier = "@https://…"` uv refuses to parse back.
    #[test]
    fn parse_requires_dist_rejects_direct_url_references() {
        assert_eq!(
            parse_requires_dist("foo @ https://example.com/foo-1.0-py3-none-any.whl"),
            None
        );
        // extras + marker variants are equally direct references
        assert_eq!(
            parse_requires_dist("foo[fast] @ git+https://example.com/foo.git ; extra == 'x'"),
            None
        );

        // block-level: one direct-reference line drops the WHOLE block
        let text = "Name: widget\n\
                    Requires-Dist: leftpad >=1.0\n\
                    Requires-Dist: foo @ https://example.com/foo-1.0-py3-none-any.whl\n\
                    \n\
                    body\n";
        assert_eq!(render_package_metadata_block(text), None);
    }

    // ── load/wire refusal edges ──────────────────────────────────────────

    /// Load-side error tuples for malformed pyproject shapes: an unparseable
    /// pyproject.toml and a `[project]` with no `name` (only their uv.lock
    /// twins were covered).
    #[tokio::test]
    async fn load_refuses_unparseable_or_nameless_pyproject() {
        let tmp = write_pair("not = [broken\n", DIRECT_REGISTRY_LOCK).await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("pyproject.toml does not parse"), "{}", err.1);

        let tmp = write_pair("[project]\nversion = \"0.1.0\"\n", DIRECT_REGISTRY_LOCK).await;
        let err = load_uv_project(tmp.path()).await.unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_root_missing");
        assert!(err.1.contains("no [project] name"), "{}", err.1);
    }

    /// `[tool]` whose `uv` key is not a standard table sails past the load
    /// guards (they use `item_get` and skip a non-table), so wire's
    /// `ensure_table` is the first place the shape is caught — it must
    /// refuse BEFORE any write, leaving both files byte-untouched.
    #[tokio::test]
    async fn wire_refuses_non_table_tool_uv_before_any_write() {
        let pyproject = format!("{DIRECT_REGISTRY_PYPROJECT}\n[tool]\nuv = 3\n");
        let tmp = write_pair(&pyproject, DIRECT_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();

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
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("is not a standard table"), "{}", err.1);

        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, pyproject, "refusal must precede any pyproject write");
        assert_eq!(lock, DIRECT_REGISTRY_LOCK, "refusal must precede any lock write");
    }

    /// Two real single-project lock shapes that must load clean: a
    /// `[manifest] members` list naming ONLY the root (the workspace
    /// refusal's fall-through edge) and a lock with no `revision` key at all
    /// (older uv emits none) — the latter must round-trip `None` into
    /// [`UvMeta`] with zero warnings.
    #[tokio::test]
    async fn load_tolerates_root_only_members_and_revisionless_lock() {
        let members_lock = DIRECT_REGISTRY_LOCK.replace(
            "requires-python = \">=3.10\"\n",
            "requires-python = \">=3.10\"\n\n[manifest]\nmembers = [\n    \"proj\",\n]\n",
        );
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, &members_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);

        let revisionless_lock = DIRECT_REGISTRY_LOCK.replace("revision = 3\n", "");
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, &revisionless_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        assert_eq!(p.lock_revision, None);

        let (_, meta) = wire_uv(
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
        .unwrap();
        assert_eq!(meta.lock_revision, None);
        let (_, lock) = read_pair(tmp.path()).await;
        assert_eq!(
            lock,
            DIRECT_PATH_LOCK.replace("revision = 3\n", ""),
            "the wired revisionless lock must still byte-match uv's shape"
        );
    }

    /// A `[tool.uv.sources]` entry or an override pin for a DIFFERENT
    /// package must be tolerated (Fresh), not refused — the guards skip
    /// non-matching entries.
    #[tokio::test]
    async fn guards_tolerate_foreign_sources_and_overrides() {
        let tmp = write_pair(
            &format!(
                "{DIRECT_REGISTRY_PYPROJECT}\n[tool.uv.sources]\nother-pkg = {{ path = \"../local/other\" }}\n"
            ),
            DIRECT_REGISTRY_LOCK,
        )
        .await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(
            check_target_guards(&p, "six", UUID),
            Ok(UvTarget::Fresh),
            "a sources entry for another package must not refuse"
        );

        let tmp = write_pair(
            &format!(
                "{TRANSITIVE_REGISTRY_PYPROJECT}\n[tool.uv]\noverride-dependencies = [\"other-pkg==1.0\"]\n"
            ),
            TRANSITIVE_REGISTRY_LOCK,
        )
        .await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(
            check_target_guards(&p, "six", UUID),
            Ok(UvTarget::Fresh),
            "an override pin for another package must not refuse"
        );
    }

    // ── pre-existing user config: override array + [manifest] section ───

    /// The user already pins one package via `[tool.uv] override-dependencies`
    /// and we vendor a DIFFERENT transitive dep: wire must APPEND to the
    /// existing array (Rewritten record with old/new array texts), and revert
    /// must restore the user's one-element array while keeping their
    /// `[tool.uv]` table alive.
    #[tokio::test]
    async fn override_wiring_appends_to_existing_override_dependencies_and_reverts() {
        let pyproject = format!(
            "{TRANSITIVE_REGISTRY_PYPROJECT}\n[tool.uv]\noverride-dependencies = [\"other-pkg==1.0\"]\n"
        );
        let tmp = write_pair(&pyproject, TRANSITIVE_REGISTRY_LOCK).await;
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
            UUID,
        )
        .await
        .unwrap();

        let (wired_py, wired_lock) = read_pair(tmp.path()).await;
        assert_eq!(
            wired_py,
            OVERRIDE_TRANSITIVE_PYPROJECT.replace(
                "override-dependencies = [\"six==1.16.0\"]",
                "override-dependencies = [\"other-pkg==1.0\", \"six==1.16.0\"]",
            ),
            "our pin must be appended to the user's array"
        );
        assert_eq!(wired_lock, OVERRIDE_TRANSITIVE_LOCK);
        assert_eq!(meta.dep_class, "override");

        let rec = wiring.iter().find(|w| w.kind == "uv_override").unwrap();
        assert_eq!(rec.action, WiringAction::Rewritten);
        assert_eq!(
            rec.original.as_ref().and_then(serde_json::Value::as_str),
            Some("[\"other-pkg==1.0\"]")
        );
        assert_eq!(
            rec.new.as_ref().and_then(serde_json::Value::as_str),
            Some("[\"other-pkg==1.0\", \"six==1.16.0\"]")
        );

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(
            py, pyproject,
            "the user's own pin keeps [tool.uv] alive after revert"
        );
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK);
    }

    /// A pre-existing single-line non-empty `[manifest] overrides` array
    /// gains our element with `, ` separation (Rewritten record), and revert
    /// byte-restores the user's array.
    #[tokio::test]
    async fn override_wiring_extends_a_single_line_manifest_overrides_array() {
        let one_el = "overrides = [{ name = \"other\", path = \"o.whl\" }]";
        let input_lock = TRANSITIVE_REGISTRY_LOCK.replace(
            "requires-python = \">=3.10\"\n",
            &format!("requires-python = \">=3.10\"\n\n[manifest]\n{one_el}\n"),
        );
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, &input_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();

        let (wired_py, wired_lock) = read_pair(tmp.path()).await;
        assert_eq!(wired_py, OVERRIDE_TRANSITIVE_PYPROJECT);
        assert_eq!(
            wired_lock,
            OVERRIDE_TRANSITIVE_LOCK.replace(
                &format!("overrides = [{{ name = \"six\", path = \"{REL_WHEEL}\" }}]"),
                &format!(
                    "overrides = [{{ name = \"other\", path = \"o.whl\" }}, {{ name = \"six\", path = \"{REL_WHEEL}\" }}]"
                ),
            )
        );
        wired_lock
            .parse::<DocumentMut>()
            .expect("the wired uv.lock must stay parseable TOML");

        let rec = wiring
            .iter()
            .find(|w| w.kind == "uv_lock_manifest_overrides")
            .unwrap();
        assert_eq!(rec.action, WiringAction::Rewritten);
        assert_eq!(
            rec.original.as_ref().and_then(serde_json::Value::as_str),
            Some("[{ name = \"other\", path = \"o.whl\" }]")
        );

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT);
        assert_eq!(lock, input_lock, "the user's overrides array is restored");
    }

    /// A pre-existing MULTI-LINE `[manifest] overrides` array gains our
    /// element as an indented line before the closing bracket, and revert
    /// byte-restores it.
    #[tokio::test]
    async fn override_wiring_extends_a_multi_line_manifest_overrides_array() {
        let ml = "overrides = [\n    { name = \"other\", path = \"o.whl\" },\n]";
        let input_lock = TRANSITIVE_REGISTRY_LOCK.replace(
            "requires-python = \">=3.10\"\n",
            &format!("requires-python = \">=3.10\"\n\n[manifest]\n{ml}\n"),
        );
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, &input_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();

        let (wired_py, wired_lock) = read_pair(tmp.path()).await;
        assert_eq!(wired_py, OVERRIDE_TRANSITIVE_PYPROJECT);
        assert_eq!(
            wired_lock,
            OVERRIDE_TRANSITIVE_LOCK.replace(
                &format!("overrides = [{{ name = \"six\", path = \"{REL_WHEEL}\" }}]"),
                &format!(
                    "overrides = [\n    {{ name = \"other\", path = \"o.whl\" }},\n    {{ name = \"six\", path = \"{REL_WHEEL}\" }},\n]"
                ),
            ),
            "our element must be inserted before the closing bracket, indented"
        );
        wired_lock
            .parse::<DocumentMut>()
            .expect("the wired uv.lock must stay parseable TOML");

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT);
        assert_eq!(lock, input_lock);
    }

    /// `[manifest]` exists (a root-only members list) but has no `overrides`
    /// key: wire adds the key right under the header (Added record NOT
    /// prefixed with `[manifest]`), and revert removes exactly that line —
    /// never the user's section.
    #[tokio::test]
    async fn override_wiring_adds_overrides_key_under_existing_manifest_header() {
        let input_lock = TRANSITIVE_REGISTRY_LOCK.replace(
            "requires-python = \">=3.10\"\n",
            "requires-python = \">=3.10\"\n\n[manifest]\nmembers = [\n    \"proj\",\n]\n",
        );
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, &input_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();

        let overrides_line = format!("overrides = [{{ name = \"six\", path = \"{REL_WHEEL}\" }}]");
        let (_, wired_lock) = read_pair(tmp.path()).await;
        assert_eq!(
            wired_lock,
            OVERRIDE_TRANSITIVE_LOCK.replace(
                &format!("{overrides_line}\n"),
                &format!("{overrides_line}\nmembers = [\n    \"proj\",\n]\n"),
            ),
            "the overrides key must land right under the [manifest] header"
        );
        wired_lock
            .parse::<DocumentMut>()
            .expect("the wired uv.lock must stay parseable TOML");

        let rec = wiring
            .iter()
            .find(|w| w.kind == "uv_lock_manifest_overrides")
            .unwrap();
        assert_eq!(rec.action, WiringAction::Added);
        assert_eq!(
            rec.new.as_ref().and_then(serde_json::Value::as_str),
            Some(overrides_line.as_str()),
            "an added key (not a created section) must not carry the [manifest] header"
        );

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT);
        assert_eq!(lock, input_lock, "only our added line may be removed");
    }

    /// A third-party edit to the REWRITTEN `[manifest] overrides` array must
    /// be left alone with a drift warning — the never-clobber contract for
    /// this record kind (only the uv_lock_package drift arm was covered).
    #[tokio::test]
    async fn revert_warns_and_skips_on_drifted_manifest_overrides_array() {
        let one_el = "overrides = [{ name = \"other\", path = \"o.whl\" }]";
        let input_lock = TRANSITIVE_REGISTRY_LOCK.replace(
            "requires-python = \">=3.10\"\n",
            &format!("requires-python = \">=3.10\"\n\n[manifest]\n{one_el}\n"),
        );
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, &input_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();

        // Drift: the user reshaped the overrides array around our element
        // (still routing six through the vendored wheel). NOT convergence —
        // hand-removing our element back to the recorded original array is
        // (covered by the converged-revert tests).
        let (_, wired_lock) = read_pair(tmp.path()).await;
        let tampered = wired_lock.replace(
            &format!(
                "[{{ name = \"other\", path = \"o.whl\" }}, {{ name = \"six\", path = \"{REL_WHEEL}\" }}]"
            ),
            &format!(
                "[{{ name = \"six\", path = \"{REL_WHEEL}\" }}, {{ name = \"extra\", path = \"e.whl\" }}]"
            ),
        );
        assert_ne!(tampered, wired_lock, "the tamper must hit the array");
        tokio::fs::write(tmp.path().join("uv.lock"), &tampered)
            .await
            .unwrap();

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(outcome.warnings[0].code, "vendor_lock_entry_drifted");
        assert!(
            outcome.warnings[0].detail.contains("uv.lock"),
            "{}",
            outcome.warnings[0].detail
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT);
        let expected = input_lock.replace(
            "[{ name = \"other\", path = \"o.whl\" }]",
            &format!(
                "[{{ name = \"six\", path = \"{REL_WHEEL}\" }}, {{ name = \"extra\", path = \"e.whl\" }}]"
            ),
        );
        assert_eq!(
            lock, expected,
            "the undrifted [[package]] fragment still reverts; the array is left as the user edited it"
        );
    }

    // ── pyproject-side drift + forward-compat revert arms ────────────────

    /// The `[tool.uv.sources]` line we wrote was EDITED by hand — still
    /// routing six through the vendored wheel: revert warns and leaves the
    /// pyproject alone while still reverting the lock. (A line REMOVED by
    /// hand is convergence, not drift — the converged-revert tests below.)
    #[tokio::test]
    async fn revert_warns_and_skips_when_sources_line_was_edited() {
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
            UUID,
        )
        .await
        .unwrap();

        let (wired_py, _) = read_pair(tmp.path()).await;
        let tampered = wired_py.replace(
            &format!("six = {{ path = \"{REL_WHEEL}\" }}\n"),
            &format!("six = {{ path = \"{REL_WHEEL}\", editable = false }}\n"),
        );
        assert_ne!(tampered, wired_py, "the tamper must edit the sources line");
        tokio::fs::write(tmp.path().join("pyproject.toml"), &tampered)
            .await
            .unwrap();

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(outcome.warnings[0].code, "vendor_lock_entry_drifted");
        assert!(
            outcome.warnings[0].detail.contains("pyproject.toml"),
            "{}",
            outcome.warnings[0].detail
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(lock, DIRECT_REGISTRY_LOCK, "the lock side still reverts");
        assert!(
            py.contains(&format!(
                "six = {{ path = \"{REL_WHEEL}\", editable = false }}"
            )),
            "the drifted pyproject is left alone: {py}"
        );
    }

    /// LIVENESS CONTRACT (vendor/mod.rs): a hand-restored pair — the user
    /// removed the vendor wiring and relocked, so every fragment already
    /// equals its reverted state — is CONVERGED, not drifted. The revert
    /// must stay silent (no `vendor_lock_entry_drifted`), or the pypi
    /// drift-keep gate would retain the uuid dir and ledger entry forever
    /// with a remediation ("undo the drift") that can never be satisfied.
    /// Covers the direct shape (sources entry + package/requires-dist
    /// fragments) and the transitive shape (override + manifest overrides).
    #[tokio::test]
    async fn revert_hand_restored_pair_is_silent_convergence() {
        for (registry_py, registry_lock, target) in [
            (DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK, "six"),
            (
                TRANSITIVE_REGISTRY_PYPROJECT,
                TRANSITIVE_REGISTRY_LOCK,
                "six",
            ),
        ] {
            let tmp = write_pair(registry_py, registry_lock).await;
            let p = load_uv_project(tmp.path()).await.unwrap();
            let (wiring, meta) = wire_uv(
                &p,
                tmp.path(),
                target,
                "1.16.0",
                REL_WHEEL,
                WHEEL_NAME,
                WHEEL_SHA,
                UUID,
            )
            .await
            .unwrap();

            // The user hand-restores the pyproject and regenerates the lock
            // (`uv lock`): both files are back at their pre-vendor bytes.
            tokio::fs::write(tmp.path().join("pyproject.toml"), registry_py)
                .await
                .unwrap();
            tokio::fs::write(tmp.path().join("uv.lock"), registry_lock)
                .await
                .unwrap();

            let entry = entry_for(wiring, meta);
            let outcome = revert_uv(&entry, tmp.path(), false).await;
            assert!(outcome.success, "{:?}", outcome.error);
            assert!(
                outcome.warnings.is_empty(),
                "already-converged records are silent no-ops: {:?}",
                outcome.warnings
            );
            assert!(!outcome.kept_artifact);
            let (py, lock) = read_pair(tmp.path()).await;
            assert_eq!(py, registry_py, "the restored pyproject stays put");
            assert_eq!(lock, registry_lock, "the restored lock stays put");
        }
    }

    /// The pypi drift-keep gate × the convergence carve-out, end to end: a
    /// hand-restored uv pair converges silently, so `revert_pypi` must still
    /// DELETE the artifact dir (no `kept_artifact`) — before the carve-out
    /// the gate misread the convergence as drift and kept the uuid dir and
    /// ledger entry forever with an unsatisfiable remediation.
    #[tokio::test]
    async fn revert_pypi_converged_uv_cleans_up_the_artifact() {
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
            UUID,
        )
        .await
        .unwrap();
        let uuid_dir = tmp.path().join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        tokio::fs::write(uuid_dir.join(WHEEL_NAME), b"wheel")
            .await
            .unwrap();

        // Hand-restore the pair: nothing references the artifact any more.
        tokio::fs::write(tmp.path().join("pyproject.toml"), DIRECT_REGISTRY_PYPROJECT)
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("uv.lock"), DIRECT_REGISTRY_LOCK)
            .await
            .unwrap();

        let entry = entry_for(wiring, meta);
        let outcome = crate::vendor::pypi::revert_pypi(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(
            !outcome.kept_artifact,
            "convergence must not trip the drift-keep gate: {:?}",
            outcome.warnings
        );
        assert!(
            !uuid_dir.exists(),
            "a converged revert must still clean up the artifact"
        );
    }

    /// The gate's keep side for uv: a hand-EDITED lock fragment that still
    /// routes through the vendored wheel is genuine drift — `revert_pypi`
    /// must keep the uuid dir (and flag it) rather than deleting the wheel
    /// the lock still points at.
    #[tokio::test]
    async fn revert_pypi_drifted_uv_keeps_artifact() {
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
            UUID,
        )
        .await
        .unwrap();
        let uuid_dir = tmp.path().join(format!(".socket/vendor/pypi/{UUID}"));
        tokio::fs::create_dir_all(&uuid_dir).await.unwrap();
        let wheel = uuid_dir.join(WHEEL_NAME);
        tokio::fs::write(&wheel, b"wheel").await.unwrap();

        // Hand-edit ONLY the source line's decor; the path still points into
        // the uuid dir about to be deleted.
        let (_, wired_lock) = read_pair(tmp.path()).await;
        let tampered = wired_lock.replace(
            &format!("source = {{ path = \"{REL_WHEEL}\" }}"),
            &format!("source = {{ path = \"{REL_WHEEL}\" }} # reviewed"),
        );
        assert_ne!(tampered, wired_lock, "the tamper must edit the unit");
        tokio::fs::write(tmp.path().join("uv.lock"), &tampered)
            .await
            .unwrap();

        let entry = entry_for(wiring, meta);
        let outcome = crate::vendor::pypi::revert_pypi(&entry, tmp.path(), false).await;
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
            wheel.is_file(),
            "uv.lock still references the wheel; deleting it would brick installs"
        );
    }

    /// The ADDED `override-dependencies = […]` line was edited after wiring:
    /// revert warns and leaves it in place (never clobbers), while the
    /// sources entry and both lock fragments still revert.
    #[tokio::test]
    async fn revert_warns_and_skips_when_added_override_line_was_edited() {
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
            UUID,
        )
        .await
        .unwrap();

        let (wired_py, _) = read_pair(tmp.path()).await;
        let tampered = wired_py.replace(
            "override-dependencies = [\"six==1.16.0\"]",
            "override-dependencies = [\"six==1.17.0\"]",
        );
        assert_ne!(tampered, wired_py, "the tamper must edit the override line");
        tokio::fs::write(tmp.path().join("pyproject.toml"), &tampered)
            .await
            .unwrap();

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(outcome.warnings[0].code, "vendor_lock_entry_drifted");
        assert!(
            outcome.warnings[0].detail.contains("pyproject.toml"),
            "{}",
            outcome.warnings[0].detail
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK);
        assert!(
            py.contains("override-dependencies = [\"six==1.17.0\"]"),
            "the user's edit must survive: {py}"
        );
        assert!(
            !py.contains("[tool.uv.sources]"),
            "the undrifted sources entry (and its created table) still reverts: {py}"
        );
    }

    /// Forward-compat: a wiring record written by a NEWER CLI (unknown kind)
    /// is skipped with a warning naming the kind — revert still succeeds and
    /// touches nothing.
    #[tokio::test]
    async fn revert_skips_unknown_wiring_kind_with_a_warning() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let entry = entry_for(
            vec![record(
                "uv.lock",
                "uv_future_kind",
                WiringAction::Added,
                "six",
                None,
                "x".into(),
            )],
            UvMeta {
                dep_class: "direct".into(),
                original_specifier: None,
                created_sources_table: false,
                lock_revision: Some(3),
            },
        );

        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(outcome.warnings[0].code, "vendor_lock_entry_drifted");
        assert!(
            outcome.warnings[0].detail.contains("unknown uv wiring kind")
                && outcome.warnings[0].detail.contains("uv_future_kind"),
            "{}",
            outcome.warnings[0].detail
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, DIRECT_REGISTRY_PYPROJECT);
        assert_eq!(lock, DIRECT_REGISTRY_LOCK);
    }

    // ── write-failure edges ──────────────────────────────────────────────

    /// The pyproject write is the FIRST write of the commit: when it fails,
    /// wire errors out with the lock never written (the tested twin covers
    /// the lock-write failure + unwind).
    #[tokio::test]
    async fn pyproject_write_failure_leaves_the_lock_untouched() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        // Make the pyproject unwritable: a directory can't be renamed over.
        tokio::fs::remove_file(tmp.path().join("pyproject.toml"))
            .await
            .unwrap();
        tokio::fs::create_dir(tmp.path().join("pyproject.toml"))
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
            UUID,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_write_failed");
        assert!(err.1.contains("cannot write pyproject.toml"), "{}", err.1);
        let lock = tokio::fs::read_to_string(tmp.path().join("uv.lock"))
            .await
            .unwrap();
        assert_eq!(
            lock, DIRECT_REGISTRY_LOCK,
            "no lock write may precede the failed pyproject write"
        );
    }

    /// A revert that cannot write uv.lock reports failure (not a silent
    /// partial revert) and leaves the wired pair on disk.
    #[cfg(unix)]
    #[tokio::test]
    async fn revert_lock_write_failure_reports_failure() {
        use std::os::unix::fs::PermissionsExt;
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
            UUID,
        )
        .await
        .unwrap();
        let (wired_py, wired_lock) = read_pair(tmp.path()).await;
        let entry = entry_for(wiring, meta);

        // The atomic write stages a temp file in the parent dir; a read-only
        // dir fails the stage while both reads still succeed.
        tokio::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();
        // Skip when the environment ignores modes (running as root).
        if std::fs::write(tmp.path().join(".probe"), b"x").is_ok() {
            let _ = std::fs::remove_file(tmp.path().join(".probe"));
            tokio::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755))
                .await
                .unwrap();
            return;
        }
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        // Restore before asserting so the TempDir cleans up even on failure.
        tokio::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(!outcome.success, "the failed write must fail the revert");
        assert!(!outcome.kept_artifact);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write uv.lock"),
            "{:?}",
            outcome.error
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, wired_py, "the wired pair must be left in place");
        assert_eq!(lock, wired_lock, "the wired pair must be left in place");
    }

    // ── sdist-only [[package]] units ─────────────────────────────────────

    /// A pure-sdist distribution ([[package]] with no wheels array): the
    /// rewrite must APPEND the wheels array at the unit's end — and the
    /// result is exactly uv's own path-wheel shape, so the wired lock
    /// byte-matches the fixture and revert byte-restores the sdist-only
    /// original.
    #[tokio::test]
    async fn sdist_only_package_unit_gains_the_wheels_array() {
        // Drop six's wheels array from the registry lock (the only one).
        let start = DIRECT_REGISTRY_LOCK.find("wheels = [").unwrap();
        let end = start + DIRECT_REGISTRY_LOCK[start..].find("]\n").unwrap() + 2;
        let sdist_only_lock = format!(
            "{}{}",
            &DIRECT_REGISTRY_LOCK[..start],
            &DIRECT_REGISTRY_LOCK[end..]
        );

        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, &sdist_only_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();

        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, DIRECT_PATH_PYPROJECT);
        assert_eq!(
            lock, DIRECT_PATH_LOCK,
            "the sdist-only unit must gain the wheels array in uv's own shape"
        );

        let entry = entry_for(wiring, meta);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, DIRECT_REGISTRY_PYPROJECT);
        assert_eq!(lock, sdist_only_lock, "revert must byte-restore the sdist-only lock");
    }

    /// An sdist-only unit FOLLOWED by a `[package.*]` sub-table: the wheels
    /// array must be spliced before the blank line preceding the sub-table,
    /// never after it.
    #[test]
    fn sdist_only_unit_splices_wheels_before_a_package_subtable() {
        let lock_text = "version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.15.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://e/six-1.15.0.tar.gz\", hash = \"sha256:aa\", size = 1 }\n\n[package.optional-dependencies]\nsocks = [\n    { name = \"pysocks\" },\n]\n";
        let (old_unit, new_unit) = rewrite_target_package_unit(
            lock_text,
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            None,
        )
        .unwrap();
        assert!(lock_text.contains(&old_unit));
        assert_eq!(
            new_unit,
            format!(
                "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = {{ path = \"{REL_WHEEL}\" }}\nwheels = [\n    {{ filename = \"{WHEEL_NAME}\", hash = \"sha256:{WHEEL_SHA}\" }},\n]\n\n[package.optional-dependencies]\nsocks = [\n    {{ name = \"pysocks\" }},\n]"
            ),
            "wheels must land before the [package.*] sub-table"
        );
    }

    // ── root-metadata rewrite edges ──────────────────────────────────────

    /// A multi-entry requires-dist array: the needle-matching must skip
    /// foreign entries and the byte-span arithmetic must address the LATER
    /// target entry exactly.
    #[test]
    fn requires_dist_rewrite_targets_the_correct_entry_among_many() {
        let lock = DIRECT_REGISTRY_LOCK.replace(
            "requires-dist = [{ name = \"six\", specifier = \"==1.16.0\" }]",
            "requires-dist = [\n    { name = \"aaa\", specifier = \"==1.0\" },\n    { name = \"six\", specifier = \"==1.16.0\" },\n]",
        );
        let edits = rewrite_root_metadata_entries(&lock, "six", REL_WHEEL).unwrap();
        assert_eq!(edits.len(), 1);
        let e = &edits[0];
        assert_eq!(e.kind, "uv_lock_requires_dist");
        assert_eq!(
            &lock[e.span.clone()],
            e.old_entry,
            "the span must address the six entry's exact bytes"
        );
        assert_eq!(e.old_entry, "{ name = \"six\", specifier = \"==1.16.0\" }");
        assert_eq!(
            e.new_entry,
            format!("{{ name = \"six\", path = \"{REL_WHEEL}\" }}")
        );
        assert_eq!(e.specifier.as_deref(), Some("==1.16.0"));

        let mut spliced = lock.clone();
        spliced.replace_range(e.span.clone(), &e.new_entry);
        spliced
            .parse::<DocumentMut>()
            .expect("the spliced lock must stay parseable TOML");
        assert!(
            spliced.contains("{ name = \"aaa\", specifier = \"==1.0\" }"),
            "the foreign entry must be untouched: {spliced}"
        );
    }

    /// The two error tuples of the root-metadata rewrite: a root with no
    /// entry for the target anywhere, and a lock with no root unit at all.
    #[test]
    fn rewrite_root_metadata_reports_missing_entry_and_missing_root() {
        let Err(err) = rewrite_root_metadata_entries(DIRECT_REGISTRY_LOCK, "absent", REL_WHEEL)
        else {
            panic!("a root without the target entry must refuse");
        };
        assert_eq!(err.0, "pypi_uv_lock_package_missing");
        assert!(
            err.1.contains("absent") && err.1.contains("requires-dist or requires-dev"),
            "{}",
            err.1
        );

        let rootless = DIRECT_REGISTRY_LOCK.replace(
            "source = { virtual = \".\" }",
            "source = { registry = \"https://pypi.org/simple\" }",
        );
        let Err(err) = rewrite_root_metadata_entries(&rootless, "six", REL_WHEEL) else {
            panic!("a lock without a root unit must refuse");
        };
        assert_eq!(err.0, "pypi_uv_lock_root_missing");
    }

    /// PEP 735 `[dependency-groups]` classification: a group-declared dep is
    /// Direct, and a non-string `{ include-group = … }` member is skipped
    /// (the included group's own array is already scanned), never misread as
    /// a declaration.
    #[tokio::test]
    async fn classify_scans_dependency_groups_and_tolerates_include_group_members() {
        let pyproject =
            format!("{DEV_GROUP_REGISTRY_PYPROJECT}all = [{{ include-group = \"dev\" }}]\n");
        let tmp = write_pair(&pyproject, DEV_GROUP_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        assert_eq!(classify_dependency(&p, "six"), UvDepClass::Direct);
        assert_eq!(
            classify_dependency(&p, "absent"),
            UvDepClass::Transitive,
            "an include-group member must not register a declaration"
        );
    }

    // ── wheel METADATA extraction edges ──────────────────────────────────

    /// A wheel vendoring a sub-package carries a NESTED
    /// `foo/bar.dist-info/METADATA` decoy — the extractor must pick the
    /// top-level one, never the nested one.
    #[test]
    fn wheel_metadata_text_skips_a_nested_dist_info_decoy() {
        let decoy = "Name: inner\nRequires-Dist: evil ==9.9\n\n";
        let real = "Name: widget\nRequires-Dist: leftpad >=1.0\n\n";
        let entries = vec![
            (
                "vendored/inner-1.0.dist-info/METADATA".to_string(),
                decoy.as_bytes().to_vec(),
                0o644,
            ),
            (
                "widget-1.0.0.dist-info/METADATA".to_string(),
                real.as_bytes().to_vec(),
                0o644,
            ),
        ];
        let bytes = crate::vendor::common::write_zip_entries(&entries).unwrap();
        assert_eq!(wheel_metadata_text(&bytes).as_deref(), Some(real));
    }

    /// METADATA over the size cap drops the WHOLE extraction (degrade to the
    /// pre-fix no-block behavior), never a truncated block.
    #[test]
    fn wheel_metadata_text_drops_an_oversized_metadata_file() {
        let entries = vec![(
            "widget-1.0.0.dist-info/METADATA".to_string(),
            vec![b'x'; (MAX_WHEEL_METADATA_BYTES + 1) as usize],
            0o644,
        )];
        let bytes = crate::vendor::common::write_zip_entries(&entries).unwrap();
        assert_eq!(wheel_metadata_text(&bytes), None);
    }

    /// RFC822 header edges: a folded continuation line and a colon-less line
    /// inside the header block are both ignored, not misparsed.
    #[test]
    fn core_metadata_fields_ignore_folded_and_colonless_header_lines() {
        let text = "Metadata-Version: 2.1\nName: widget\nRequires-Dist: leftpad >=1.0\n folded continuation line\ngarbage line without a colon\nProvides-Extra: fast\n\nbody\n";
        let (requires, provides) = parse_core_metadata_fields(text);
        assert_eq!(requires, vec!["leftpad >=1.0"]);
        assert_eq!(provides, vec!["fast"]);
    }

    /// Extras render in reconstructed requires-dist entries, pinning uv's
    /// serializer key order end-to-end: name, extras, marker, specifier.
    #[test]
    fn render_entry_pins_uv_key_order_name_extras_marker_specifier() {
        let text = "Name: x\nRequires-Dist: requests[socks,security] >=2.0 ; extra == 'fast'\n\n";
        assert_eq!(
            render_package_metadata_block(text).as_deref(),
            Some(
                "[package.metadata]\nrequires-dist = [{ name = \"requests\", extras = [\"socks\", \"security\"], marker = \"extra == 'fast'\", specifier = \">=2.0\" }]"
            )
        );
    }

    /// A Provides-Extra-only wheel (extras declared, no deps) yields
    /// `requires-dist = []` plus the provides-extras block — uv records
    /// exactly that for such path sources.
    #[test]
    fn render_block_with_provides_extra_only_yields_empty_requires_dist() {
        assert_eq!(
            render_package_metadata_block("Name: x\nProvides-Extra: fast\n\n").as_deref(),
            Some("[package.metadata]\nrequires-dist = []\nprovides-extras = [\"fast\"]")
        );
    }

    // ── coverage mop-up 2026-09: guard/error/skip arms ────────────────────

    /// In-memory pair (no tempdir) for the pure-read helpers.
    fn project_from(pyproject: &str, lock: &str) -> UvProject {
        UvProject {
            pyproject_text: pyproject.to_string(),
            lock_text: lock.to_string(),
            pyproject: pyproject.parse().unwrap(),
            lock: lock.parse().unwrap(),
            lock_revision: None,
            warnings: Vec::new(),
        }
    }

    /// A `[dependency-groups]` key whose value is NOT an array (legal TOML,
    /// outside the PEP 735 shape) is skipped, never a panic — and it must not
    /// swallow the declarations in the well-formed sibling groups.
    #[test]
    fn classify_skips_a_non_array_dependency_group_value() {
        let pyproject = format!(
            "{DIRECT_REGISTRY_PYPROJECT}\n[dependency-groups]\nbroken = \"not-an-array\"\ndev = [\"attrs==23.1.0\"]\n"
        );
        let p = project_from(&pyproject, DIRECT_REGISTRY_LOCK);
        assert_eq!(
            classify_dependency(&p, "attrs"),
            UvDepClass::Direct,
            "the array group after the malformed one still registers"
        );
        assert_eq!(classify_dependency(&p, "absent"), UvDepClass::Transitive);
    }

    /// A wired-shaped lock whose wheels hash is not a plausible sha256 (too
    /// short, or non-hex) pins nothing: the in-sync rebuild guard must stay
    /// off rather than trust a corrupted pin.
    #[test]
    fn wired_pin_rejects_a_malformed_wheel_hash() {
        let short = DIRECT_PATH_LOCK.replace(WHEEL_SHA, "deadbeef");
        let p = project_from(DIRECT_PATH_PYPROJECT, &short);
        assert_eq!(wired_pin(&p, "six", UUID), None, "a short hash pins nothing");

        let non_hex = DIRECT_PATH_LOCK.replace(WHEEL_SHA, &"z".repeat(64));
        let p = project_from(DIRECT_PATH_PYPROJECT, &non_hex);
        assert_eq!(
            wired_pin(&p, "six", UUID),
            None,
            "a non-hex 64-char hash pins nothing"
        );
    }

    /// A version string that breaks the override TOML value (an embedded
    /// quote) is reported as a parse failure BEFORE any write.
    #[tokio::test]
    async fn wire_reports_an_unbuildable_override_value() {
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, TRANSITIVE_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let err = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0\"",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            UUID,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("cannot build override value"), "{}", err.1);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT, "refusal leaves the tree untouched");
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK);
    }

    /// A user-authored `[tool.uv.override-dependencies]` TABLE (not the array
    /// uv expects) refuses cleanly instead of panicking or clobbering it.
    #[tokio::test]
    async fn wire_refuses_a_table_shaped_override_dependencies() {
        let pyproject =
            format!("{TRANSITIVE_REGISTRY_PYPROJECT}\n[tool.uv.override-dependencies]\n");
        let tmp = write_pair(&pyproject, TRANSITIVE_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
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
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("is not a value"), "{}", err.1);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, pyproject, "refusal leaves the tree untouched");
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK);
    }

    /// A user-authored scalar `override-dependencies = "…"` (a value, but not
    /// an array) refuses cleanly too — the append has nowhere to go.
    #[tokio::test]
    async fn wire_refuses_a_non_array_override_dependencies_value() {
        let pyproject = format!(
            "{TRANSITIVE_REGISTRY_PYPROJECT}\n[tool.uv]\noverride-dependencies = \"attrs==23.1.0\"\n"
        );
        let tmp = write_pair(&pyproject, TRANSITIVE_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
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
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("is not an array"), "{}", err.1);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, pyproject, "refusal leaves the tree untouched");
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK);
    }

    /// A wheel path that breaks the sources TOML value (an embedded quote) is
    /// reported as a parse failure BEFORE any write.
    #[tokio::test]
    async fn wire_reports_an_unbuildable_sources_value() {
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let err = wire_uv(
            &p,
            tmp.path(),
            "six",
            "1.16.0",
            ".socket/vendor/pypi/x\"y/six.whl",
            WHEEL_NAME,
            WHEEL_SHA,
            UUID,
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("cannot build sources value"), "{}", err.1);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, DIRECT_REGISTRY_PYPROJECT, "refusal leaves the tree untouched");
        assert_eq!(lock, DIRECT_REGISTRY_LOCK);
    }

    /// The lock parses (so the TOML-level guard sees the package) but the
    /// [[package]] unit is spelled `name="six"` — outside the text-surgery
    /// shape uv emits. The rewrite's own missing-unit error must propagate
    /// out of wire_uv before any write, not panic or half-wire.
    #[tokio::test]
    async fn wire_propagates_a_textually_missing_package_unit() {
        let lock = DIRECT_REGISTRY_LOCK.replacen(
            "[[package]]\nname = \"six\"",
            "[[package]]\nname=\"six\"",
            1,
        );
        assert_ne!(lock, DIRECT_REGISTRY_LOCK);
        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, &lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
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
        assert_eq!(err.0, "pypi_uv_lock_package_missing");
        assert!(err.1.contains("six"), "{}", err.1);
        let (py, on_disk) = read_pair(tmp.path()).await;
        assert_eq!(py, DIRECT_REGISTRY_PYPROJECT, "refusal leaves the tree untouched");
        assert_eq!(on_disk, lock);
    }

    /// A ledger record with no `new` fragment at all (malformed/truncated
    /// state.json). Every Added revert arm needs the fragment it wrote to
    /// remove it — each must warn and skip, never panic or guess.
    fn record_without_new(kind: &str, action: WiringAction) -> WiringRecord {
        WiringRecord {
            file: "x".into(),
            kind: kind.into(),
            action,
            key: Some("six".into()),
            original: None,
            new: None,
        }
    }

    #[tokio::test]
    async fn revert_warns_on_records_missing_the_new_fragment() {
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, TRANSITIVE_REGISTRY_LOCK).await;
        let entry = entry_for(
            vec![
                record_without_new("uv_override", WiringAction::Added),
                record_without_new("uv_sources_entry", WiringAction::Added),
                record_without_new("uv_lock_manifest_overrides", WiringAction::Added),
            ],
            UvMeta {
                dep_class: "override".into(),
                original_specifier: None,
                created_sources_table: false,
                lock_revision: None,
            },
        );
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(outcome.warnings.len(), 3, "{:?}", outcome.warnings);
        for w in &outcome.warnings {
            assert_eq!(w.code, "vendor_lock_entry_drifted");
        }
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT);
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK);
    }

    /// The `[manifest]` section vendor CREATED was reshaped by hand but still
    /// routes through the vendored wheel: that is drift (fail-closed), not
    /// convergence — revert warns and leaves the section, while the untouched
    /// [[package]] fragment and the pyproject still revert.
    #[tokio::test]
    async fn revert_warns_when_created_manifest_section_still_routes_after_reshape() {
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
            UUID,
        )
        .await
        .unwrap();
        let pkg_rec = wiring
            .iter()
            .find(|w| w.kind == "uv_lock_package")
            .unwrap();
        let pkg_new = pkg_rec
            .new
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_string();
        let pkg_orig = pkg_rec
            .original
            .as_ref()
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_string();

        let (_, wired_lock) = read_pair(tmp.path()).await;
        let tampered = wired_lock.replacen(
            &format!("path = \"{REL_WHEEL}\" }}]"),
            &format!("path = \"{REL_WHEEL}\" }}, {{ name = \"extra\", path = \"e.whl\" }}]"),
            1,
        );
        assert_ne!(tampered, wired_lock, "the tamper must hit the overrides line");
        tokio::fs::write(tmp.path().join("uv.lock"), &tampered)
            .await
            .unwrap();

        let outcome = revert_uv(&entry_for(wiring, meta), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(outcome.warnings[0].code, "vendor_lock_entry_drifted");
        assert!(
            outcome.warnings[0].detail.contains("uv.lock"),
            "{}",
            outcome.warnings[0].detail
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT);
        let expected = tampered.replacen(&pkg_new, &pkg_orig, 1);
        assert_eq!(
            lock, expected,
            "the [[package]] fragment reverts; the reshaped [manifest] stays"
        );
    }

    /// Hand-restoring a pair whose lock had a PRE-EXISTING overrides array
    /// (a Rewritten manifest record) is convergence: the recorded original
    /// is already live, so revert is silent — no drift warnings.
    #[tokio::test]
    async fn revert_hand_restored_preexisting_overrides_lock_is_silent_convergence() {
        let one_el = "overrides = [{ name = \"other\", path = \"o.whl\" }]";
        let input_lock = TRANSITIVE_REGISTRY_LOCK.replace(
            "requires-python = \">=3.10\"\n",
            &format!("requires-python = \">=3.10\"\n\n[manifest]\n{one_el}\n"),
        );
        let tmp = write_pair(TRANSITIVE_REGISTRY_PYPROJECT, &input_lock).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();
        // Hand-restore BOTH files to their pre-vendor bytes.
        tokio::fs::write(tmp.path().join("pyproject.toml"), TRANSITIVE_REGISTRY_PYPROJECT)
            .await
            .unwrap();
        tokio::fs::write(tmp.path().join("uv.lock"), &input_lock)
            .await
            .unwrap();

        let outcome = revert_uv(&entry_for(wiring, meta), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, TRANSITIVE_REGISTRY_PYPROJECT);
        assert_eq!(lock, input_lock);
    }

    /// Hand-restoring ONLY the pyproject after wiring extended a user's
    /// existing `override-dependencies` array: the Rewritten uv_override arm
    /// finds the recorded original live — convergence, silent — while the
    /// lock side still reverts fully.
    #[tokio::test]
    async fn revert_hand_restored_rewritten_override_array_is_silent_convergence() {
        let pyproject = format!(
            "{TRANSITIVE_REGISTRY_PYPROJECT}\n[tool.uv]\noverride-dependencies = [\"attrs==23.1.0\"]\n"
        );
        let tmp = write_pair(&pyproject, TRANSITIVE_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();
        // Hand-restore only the pyproject; leave the wired lock.
        tokio::fs::write(tmp.path().join("pyproject.toml"), &pyproject)
            .await
            .unwrap();

        let outcome = revert_uv(&entry_for(wiring, meta), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, pyproject, "the hand-restored pyproject is untouched");
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK, "the lock still reverts");
    }

    /// The extended `override-dependencies` array was EDITED by hand into a
    /// shape that is neither what vendor wrote nor the recorded original:
    /// drift — warn and leave it, while everything else reverts.
    #[tokio::test]
    async fn revert_warns_when_rewritten_override_array_was_edited() {
        let pyproject = format!(
            "{TRANSITIVE_REGISTRY_PYPROJECT}\n[tool.uv]\noverride-dependencies = [\"attrs==23.1.0\"]\n"
        );
        let tmp = write_pair(&pyproject, TRANSITIVE_REGISTRY_LOCK).await;
        let p = load_uv_project(tmp.path()).await.unwrap();
        let (wiring, meta) = wire_uv(
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
        .unwrap();
        let (wired_py, _) = read_pair(tmp.path()).await;
        let tampered = wired_py.replacen("attrs==23.1.0", "attrs==23.9.9", 1);
        assert_ne!(tampered, wired_py, "the tamper must hit the override array");
        tokio::fs::write(tmp.path().join("pyproject.toml"), &tampered)
            .await
            .unwrap();

        let outcome = revert_uv(&entry_for(wiring, meta), tmp.path(), false).await;
        assert!(outcome.success, "{:?}", outcome.error);
        assert_eq!(outcome.warnings.len(), 1, "{:?}", outcome.warnings);
        assert_eq!(outcome.warnings[0].code, "vendor_lock_entry_drifted");
        assert!(
            outcome.warnings[0].detail.contains("pyproject.toml"),
            "{}",
            outcome.warnings[0].detail
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(lock, TRANSITIVE_REGISTRY_LOCK, "the lock still reverts");
        assert!(
            py.contains("override-dependencies = [\"attrs==23.9.9\", \"six==1.16.0\"]"),
            "the drifted array is left as the user edited it: {py}"
        );
        assert!(
            !py.contains("[tool.uv.sources]"),
            "the undrifted sources entry still reverts: {py}"
        );
    }

    /// The lock write succeeds but the pyproject write fails (an immutable
    /// pyproject.toml): revert reports failure with the pyproject error, not
    /// a silent partial revert. UF_IMMUTABLE blocks rename-over regardless
    /// of euid, so no root-skip probe is needed.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn revert_pyproject_write_failure_after_the_lock_write_reports_failure() {
        fn set_flags(path: &Path, flags: libc::c_uint) {
            use std::os::unix::ffi::OsStrExt;
            let c_path =
                std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path has no NUL");
            let rc = unsafe { libc::chflags(c_path.as_ptr(), flags) };
            assert_eq!(rc, 0, "chflags failed: {}", std::io::Error::last_os_error());
        }

        let tmp = write_pair(DIRECT_REGISTRY_PYPROJECT, DIRECT_REGISTRY_LOCK).await;
        let entry = entry_for(
            Vec::new(),
            UvMeta {
                dep_class: "direct".into(),
                original_specifier: None,
                created_sources_table: false,
                lock_revision: None,
            },
        );
        let pyproject_path = tmp.path().join("pyproject.toml");
        set_flags(&pyproject_path, libc::UF_IMMUTABLE);
        let outcome = revert_uv(&entry, tmp.path(), false).await;
        // Clear the flag before asserting so the TempDir cleans up even on
        // failure.
        set_flags(&pyproject_path, 0);

        assert!(!outcome.success, "the failed write must fail the revert");
        assert!(!outcome.kept_artifact);
        assert!(
            outcome
                .error
                .as_deref()
                .unwrap_or("")
                .contains("cannot write pyproject.toml"),
            "{:?}",
            outcome.error
        );
        let (py, lock) = read_pair(tmp.path()).await;
        assert_eq!(py, DIRECT_REGISTRY_PYPROJECT);
        assert_eq!(lock, DIRECT_REGISTRY_LOCK, "the preceding lock write succeeded");
    }

    /// A SINGLE-LINE `wheels = […]` array (uv emits one for one-wheel
    /// packages) is replaced in place — not duplicated by the sdist-only
    /// append path.
    #[test]
    fn single_line_wheels_array_is_rewritten_in_place() {
        let lock = "version = 1\n\n[[package]]\nname = \"six\"\nversion = \"1.15.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://example.invalid/six.tar.gz\", hash = \"sha256:aa\", size = 1 }\nwheels = [{ url = \"https://example.invalid/six.whl\", hash = \"sha256:bb\" }]\n";
        let (old_unit, new_unit) = rewrite_target_package_unit(
            lock,
            "six",
            "1.16.0",
            REL_WHEEL,
            WHEEL_NAME,
            WHEEL_SHA,
            None,
        )
        .unwrap();
        assert!(old_unit.contains("wheels = [{ url"), "{old_unit}");
        let expected_wheels = format!(
            "wheels = [\n    {{ filename = \"{WHEEL_NAME}\", hash = \"sha256:{WHEEL_SHA}\" }},\n]"
        );
        assert!(new_unit.contains(&expected_wheels), "{new_unit}");
        assert_eq!(
            new_unit.matches("wheels = [").count(),
            1,
            "replaced in place, never appended a second array: {new_unit}"
        );
        assert!(!new_unit.contains("url ="), "{new_unit}");
        assert!(!new_unit.contains("sdist"), "{new_unit}");
        assert!(
            new_unit.contains(&format!("source = {{ path = \"{REL_WHEEL}\" }}")),
            "{new_unit}"
        );
        assert!(new_unit.contains("version = \"1.16.0\""), "{new_unit}");
    }

    /// Root-unit header shared by the unbalanced-array fixtures below.
    const ROOT_UNIT_HDR: &str = "version = 1\n\n[[package]]\nname = \"proj\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n\n[package.metadata]\n";

    /// A truncated (unbalanced) root `requires-dist` array refuses with a
    /// parse error instead of slicing out of bounds or mis-splicing.
    #[test]
    fn unbalanced_requires_dist_array_is_a_parse_error() {
        let lock = format!(
            "{ROOT_UNIT_HDR}requires-dist = [{{ name = \"six\", specifier = \"==1.16.0\" }}\n"
        );
        let Err(err) = rewrite_root_metadata_entries(&lock, "six", REL_WHEEL) else {
            panic!("an unbalanced requires-dist array must refuse");
        };
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("requires-dist array is unbalanced"), "{}", err.1);
    }

    /// Same for a truncated `[package.metadata.requires-dev]` group array.
    #[test]
    fn unbalanced_requires_dev_group_array_is_a_parse_error() {
        let lock = format!(
            "{ROOT_UNIT_HDR}requires-dist = [{{ name = \"six\", specifier = \"==1.16.0\" }}]\n\n[package.metadata.requires-dev]\ndev = [\n    {{ name = \"six\", specifier = \"==1.16.0\" }},\n"
        );
        let Err(err) = rewrite_root_metadata_entries(&lock, "six", REL_WHEEL) else {
            panic!("an unbalanced requires-dev group array must refuse");
        };
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(
            err.1.contains("requires-dev] array is unbalanced"),
            "{}",
            err.1
        );
    }

    /// A requires-dev group whose entries name OTHER packages contributes no
    /// edit — the scan skips it and the requires-dist edit alone survives.
    #[test]
    fn requires_dev_scan_skips_groups_without_the_target() {
        let lock = format!(
            "{ROOT_UNIT_HDR}requires-dist = [{{ name = \"six\", specifier = \"==1.16.0\" }}]\n\n[package.metadata.requires-dev]\nlint = [\n    {{ name = \"black\", specifier = \"==24.4.2\" }},\n]\n"
        );
        let edits = rewrite_root_metadata_entries(&lock, "six", REL_WHEEL).unwrap();
        assert_eq!(edits.len(), 1, "the black-only dev group contributes no edit");
        assert_eq!(edits[0].kind, "uv_lock_requires_dist");
        assert!(edits[0].old_entry.contains("name = \"six\""));
    }

    /// A hand-edited entry with a trailing comma splits into a final empty
    /// piece — skipped, so the rebuilt entry carries no stray separator.
    #[test]
    fn path_source_entry_tolerates_a_trailing_comma() {
        let (new_entry, specifier) =
            path_source_entry("{ name = \"six\", specifier = \"==1.16.0\", }", REL_WHEEL);
        assert_eq!(specifier.as_deref(), Some("==1.16.0"));
        assert_eq!(
            new_entry,
            format!("{{ name = \"six\", path = \"{REL_WHEEL}\" }}")
        );
    }

    /// A lock with neither `[manifest]` nor any `[[package]]` unit gives the
    /// created section no insertion anchor: a parse-failure refusal.
    #[test]
    fn manifest_override_requires_a_package_entry() {
        let err = add_manifest_override("version = 1\nrevision = 3\n", "six", REL_WHEEL)
            .unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("no [[package]] entries"), "{}", err.1);
    }

    /// A truncated (unbalanced) existing `[manifest] overrides` array refuses
    /// with a parse error instead of splicing garbage.
    #[test]
    fn manifest_override_reports_an_unbalanced_overrides_array() {
        let lock = "version = 1\n\n[manifest]\noverrides = [{ name = \"other\", path = \"o.whl\" }\n\n[[package]]\nname = \"proj\"\nversion = \"0.1.0\"\nsource = { virtual = \".\" }\n";
        let err = add_manifest_override(lock, "six", REL_WHEEL).unwrap_err();
        assert_eq!(err.0, "pypi_uv_lock_parse_failed");
        assert!(err.1.contains("overrides array is unbalanced"), "{}", err.1);
    }
}
