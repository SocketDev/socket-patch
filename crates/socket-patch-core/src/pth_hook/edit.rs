//! Add / remove the `socket-patch[hook]` dependency in a project's manifest.
//!
//! Two manifest kinds are supported:
//!   * **pyproject.toml** — edited with `toml_edit` so the user's existing
//!     formatting and comments are preserved. Targets the PEP 621
//!     `[project].dependencies` array, or a classic Poetry
//!     `[tool.poetry.dependencies]` table when that is the only dependency
//!     surface present.
//!   * **requirements.txt** — a plain line append / removal.
//!
//! All operations are idempotent and honour `dry_run` (compute the result and
//! report status without writing). This mirrors the contracts of
//! [`crate::package_json::update`] for the npm side.

use std::path::Path;
use tokio::fs;
use toml_edit::{Array, DocumentMut, InlineTable, Item, Table, Value};

use super::detect::{deps_contain_hook, spec_is_hook, HOOK_DEP};
use crate::utils::fs::atomic_write_bytes;

/// Which manifest format a path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    Pyproject,
    Requirements,
}

/// Outcome of editing one manifest. Mirrors `package_json::update::UpdateStatus`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PthStatus {
    Updated,
    AlreadyConfigured,
    Error,
}

#[derive(Debug, Clone)]
pub struct PthEditResult {
    pub path: String,
    pub kind: ManifestKind,
    pub status: PthStatus,
    pub error: Option<String>,
}

impl PthEditResult {
    fn ok(path: &Path, kind: ManifestKind, status: PthStatus) -> Self {
        Self {
            path: path.display().to_string(),
            kind,
            status,
            error: None,
        }
    }
    fn err(path: &Path, kind: ManifestKind, msg: impl Into<String>) -> Self {
        Self {
            path: path.display().to_string(),
            kind,
            status: PthStatus::Error,
            error: Some(msg.into()),
        }
    }
}

/// Add the hook dependency to a manifest. Idempotent.
pub async fn add_hook_dependency(path: &Path, kind: ManifestKind, dry_run: bool) -> PthEditResult {
    let content = match fs::read_to_string(path).await {
        Ok(c) => c,
        // A missing requirements.txt is created (the pip-from-scratch path);
        // a missing pyproject.toml is an error (we don't synthesize one).
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound && kind == ManifestKind::Requirements =>
        {
            String::new()
        }
        Err(e) => return PthEditResult::err(path, kind, e.to_string()),
    };

    let outcome = match kind {
        ManifestKind::Pyproject => pyproject_add(&content),
        ManifestKind::Requirements => requirements_add(&content),
    };

    match outcome {
        Ok(None) => PthEditResult::ok(path, kind, PthStatus::AlreadyConfigured),
        Ok(Some(new_content)) => {
            if !dry_run {
                if let Err(e) = atomic_write_bytes(path, new_content.as_bytes()).await {
                    return PthEditResult::err(path, kind, e.to_string());
                }
            }
            PthEditResult::ok(path, kind, PthStatus::Updated)
        }
        Err(e) => PthEditResult::err(path, kind, e),
    }
}

/// Remove the hook dependency from a manifest. Idempotent (already-absent ->
/// `AlreadyConfigured`, i.e. nothing to do).
pub async fn remove_hook_dependency(
    path: &Path,
    kind: ManifestKind,
    dry_run: bool,
) -> PthEditResult {
    let content = match fs::read_to_string(path).await {
        Ok(c) => c,
        // Nothing on disk → nothing to remove (idempotent no-op).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return PthEditResult::ok(path, kind, PthStatus::AlreadyConfigured)
        }
        Err(e) => return PthEditResult::err(path, kind, e.to_string()),
    };

    let outcome = match kind {
        ManifestKind::Pyproject => pyproject_remove(&content),
        ManifestKind::Requirements => requirements_remove(&content),
    };

    match outcome {
        Ok(None) => PthEditResult::ok(path, kind, PthStatus::AlreadyConfigured),
        Ok(Some(new_content)) => {
            if !dry_run {
                if let Err(e) = atomic_write_bytes(path, new_content.as_bytes()).await {
                    return PthEditResult::err(path, kind, e.to_string());
                }
            }
            PthEditResult::ok(path, kind, PthStatus::Updated)
        }
        Err(e) => PthEditResult::err(path, kind, e),
    }
}

// ── requirements.txt ────────────────────────────────────────────────────────

/// The file's dominant newline style, so edits don't rewrite CRLF as LF.
fn newline_of(content: &str) -> &'static str {
    if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// Returns `Some(new_content)` if a line was appended, `None` if already there.
fn requirements_add(content: &str) -> Result<Option<String>, String> {
    if content
        .lines()
        .any(|l| deps_contain_hook(strip_requirement_comment(l)))
    {
        return Ok(None);
    }
    let nl = newline_of(content);
    let mut new = content.to_string();
    if !new.is_empty() && !new.ends_with('\n') {
        new.push_str(nl);
    }
    new.push_str(HOOK_DEP);
    new.push_str(nl);
    Ok(Some(new))
}

/// Returns `Some(new_content)` if any hook line was removed, `None` otherwise.
fn requirements_remove(content: &str) -> Result<Option<String>, String> {
    let kept: Vec<&str> = content
        .lines()
        .filter(|l| !deps_contain_hook(strip_requirement_comment(l)))
        .collect();
    if kept.len() == content.lines().count() {
        return Ok(None);
    }
    let nl = newline_of(content);
    let mut new = kept.join(nl);
    if !new.is_empty() {
        new.push_str(nl);
    }
    Ok(Some(new))
}

/// Strip a trailing `# comment` so we match against the requirement spec only.
fn strip_requirement_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

// ── pyproject.toml ───────────────────────────────────────────────────────────

/// Returns `Some(new_content)` if the doc was modified, `None` if the hook dep
/// was already present, or `Err` on malformed TOML / wrong-typed tables.
fn pyproject_add(content: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid pyproject.toml: {e}"))?;

    // Prefer PEP 621 `[project].dependencies` when there is a *real* PEP 621
    // surface; otherwise fall back to a classic Poetry `[tool.poetry]` table.
    // A `[project]` table that exists only implicitly (e.g. conjured by a
    // `[project.urls]` sub-table in a Poetry-1.x project) is NOT a real PEP 621
    // surface — routing such a project to PEP 621 would add a
    // `[project].dependencies` that Poetry ignores at install time. The inner
    // helpers detect an already-present hook dependency structurally (which the
    // textual marker check can't, e.g. a Poetry `extras = ["hook"]` table).
    let real_pep621 = doc
        .get("project")
        .and_then(Item::as_table)
        .map(|t| !t.is_implicit() || t.contains_key("dependencies"))
        .unwrap_or(false);
    let has_poetry = doc
        .get("tool")
        .and_then(Item::as_table)
        .and_then(|t| t.get("poetry"))
        .and_then(Item::as_table)
        .is_some();

    let changed = if has_poetry && !real_pep621 {
        poetry_add(&mut doc)?
    } else if real_pep621 {
        pep621_add(&mut doc)?
    } else {
        // Neither surface exists (e.g. a `[build-system]`-only or tool-config-only
        // pyproject.toml of a setup.py/setup.cfg project). Synthesizing a
        // `[project]` table with only `dependencies` would make the manifest
        // invalid — PEP 621 requires `name` and forbids declaring it dynamic — so
        // pip/setuptools/uv would refuse to build. Fail closed instead.
        return Err(
            "pyproject.toml has no `[project]` or `[tool.poetry]` table to host the hook \
             dependency; declare project dependencies (or use requirements.txt) first"
                .to_string(),
        );
    };
    Ok(if changed { Some(doc.to_string()) } else { None })
}

fn pyproject_remove(content: &str) -> Result<Option<String>, String> {
    let mut doc = content
        .parse::<DocumentMut>()
        .map_err(|e| format!("Invalid pyproject.toml: {e}"))?;

    let mut changed = false;
    changed |= pep621_remove(&mut doc);
    changed |= poetry_remove(&mut doc);

    Ok(if changed { Some(doc.to_string()) } else { None })
}

/// Ensure `parent[key]` is a table, creating it if absent. Errors if present
/// but a non-table. Also used by the cargo vendor backend's
/// `[patch.crates-io]` editing (`patch::vendor::cargo_config`).
pub(crate) fn ensure_table<'a>(
    parent: &'a mut Table,
    key: &str,
    implicit: bool,
) -> Result<&'a mut Table, String> {
    if !parent.contains_key(key) {
        let mut t = Table::new();
        t.set_implicit(implicit);
        parent.insert(key, Item::Table(t));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| format!("`{key}` is not a table"))
}

fn pep621_add(doc: &mut DocumentMut) -> Result<bool, String> {
    let root = doc.as_table_mut();
    let project = ensure_table(root, "project", false)?;
    if !project.contains_key("dependencies") {
        project.insert("dependencies", Item::Value(Value::Array(Array::new())));
    }
    let deps = project
        .get_mut("dependencies")
        .and_then(Item::as_array_mut)
        .ok_or("`project.dependencies` is not an array")?;
    if deps
        .iter()
        .any(|v| v.as_str().map(spec_is_hook).unwrap_or(false))
    {
        return Ok(false);
    }
    deps.push(HOOK_DEP);
    Ok(true)
}

fn pep621_remove(doc: &mut DocumentMut) -> bool {
    let deps = match doc
        .get_mut("project")
        .and_then(Item::as_table_mut)
        .and_then(|p| p.get_mut("dependencies"))
        .and_then(Item::as_array_mut)
    {
        Some(d) => d,
        None => return false,
    };
    let before = deps.len();
    deps.retain(|v| !v.as_str().map(spec_is_hook).unwrap_or(false));
    deps.len() != before
}

fn poetry_add(doc: &mut DocumentMut) -> Result<bool, String> {
    let root = doc.as_table_mut();
    let tool = ensure_table(root, "tool", true)?;
    let poetry = ensure_table(tool, "poetry", true)?;
    let deps = ensure_table(poetry, "dependencies", false)?;

    // Classic Poetry can't express `socket-patch[hook]` as a key, so declare
    // the equivalent: `socket-patch` carrying the `hook` extra. Already wired
    // if a bare `socket-patch-hook` key exists or the extra is already present.
    if deps.contains_key("socket-patch-hook") {
        return Ok(false);
    }
    if let Some(item) = deps.get_mut("socket-patch") {
        if item_has_hook_extra(item) {
            return Ok(false);
        }
        // An existing `socket-patch` dep (bare string or a table): merge the
        // `hook` extra in place, preserving its version / source / markers.
        if let Some(tbl) = item.as_table_like_mut() {
            let mut extras = tbl
                .get("extras")
                .and_then(Item::as_array)
                .cloned()
                .unwrap_or_default();
            extras.push("hook");
            tbl.insert("extras", Item::Value(Value::Array(extras)));
        } else if let Some(version) = item.as_str().map(str::to_string) {
            deps.insert("socket-patch", Item::Value(hook_inline_table(&version)));
        } else {
            // Any other shape (e.g. Poetry's multiple-constraints array of
            // tables) carries spec data a blanket replacement would destroy.
            return Err(
                "`tool.poetry.dependencies.socket-patch` has an unsupported shape; \
                 add the `hook` extra to it manually"
                    .to_string(),
            );
        }
        return Ok(true);
    }
    deps.insert("socket-patch", Item::Value(hook_inline_table("*")));
    Ok(true)
}

fn poetry_remove(doc: &mut DocumentMut) -> bool {
    let deps = match doc
        .get_mut("tool")
        .and_then(Item::as_table_mut)
        .and_then(|t| t.get_mut("poetry"))
        .and_then(Item::as_table_mut)
        .and_then(|p| p.get_mut("dependencies"))
        .and_then(Item::as_table_mut)
    {
        Some(d) => d,
        None => return false,
    };

    let mut changed = false;
    // Drop a legacy bare `socket-patch-hook` key if present.
    if deps.remove("socket-patch-hook").is_some() {
        changed = true;
    }
    // Strip the `hook` extra from a `socket-patch` dep table, leaving the rest
    // of the spec intact.
    if let Some(tbl) = deps
        .get_mut("socket-patch")
        .and_then(Item::as_table_like_mut)
    {
        if let Some(extras) = tbl.get_mut("extras").and_then(Item::as_array_mut) {
            let before = extras.len();
            extras.retain(|v| v.as_str() != Some("hook"));
            if extras.len() != before {
                changed = true;
            }
            if extras.is_empty() {
                tbl.remove("extras");
            }
        }
    }
    changed
}

/// Build `{ version = "<v>", extras = ["hook"] }`.
fn hook_inline_table(version: &str) -> Value {
    let mut it = InlineTable::new();
    it.insert("version", Value::from(version));
    let mut extras = Array::new();
    extras.push("hook");
    it.insert("extras", Value::Array(extras));
    Value::InlineTable(it)
}

/// True if a dependency item (inline table or sub-table) already carries the
/// `hook` extra.
fn item_has_hook_extra(item: &Item) -> bool {
    item.as_table_like()
        .and_then(|t| t.get("extras"))
        .and_then(Item::as_array)
        .map(|a| a.iter().any(|v| v.as_str() == Some("hook")))
        .unwrap_or(false)
}

/// True if a parsed `pyproject.toml` already declares the hook dependency in any
/// form `setup` could have written: a PEP 621 `[project].dependencies` entry, a
/// classic-Poetry `socket-patch` dep carrying the `hook` extra, or a legacy bare
/// `socket-patch-hook` key.
///
/// This is the structural counterpart to the textual
/// [`super::detect::deps_contain_hook`]. It exists because `poetry_add` writes
/// the hook as `socket-patch = { version = "*", extras = ["hook"] }`, which has
/// no literal `socket-patch[hook]` substring — so the textual probe reports a
/// freshly-and-correctly-configured classic-Poetry project as *unconfigured*.
/// The `setup --check` / state probes must use this for `pyproject.toml` so a
/// round-trip (setup → check) is consistent. Falls back to the textual check on
/// unparseable TOML (best effort rather than a hard failure).
pub fn pyproject_contains_hook(content: &str) -> bool {
    let doc = match content.parse::<DocumentMut>() {
        Ok(d) => d,
        Err(_) => return deps_contain_hook(content),
    };

    // PEP 621 `[project].dependencies` (the textual `socket-patch[hook]` spec,
    // or the bare `socket-patch-hook` wheel).
    let in_pep621 = doc
        .get("project")
        .and_then(Item::as_table)
        .and_then(|p| p.get("dependencies"))
        .and_then(Item::as_array)
        .map(|deps| {
            deps.iter()
                .any(|v| v.as_str().map(spec_is_hook).unwrap_or(false))
        })
        .unwrap_or(false);
    if in_pep621 {
        return true;
    }

    // Classic Poetry `[tool.poetry.dependencies]`: a bare `socket-patch-hook`
    // key, or a `socket-patch` dep carrying the `hook` extra.
    if let Some(deps) = doc
        .get("tool")
        .and_then(Item::as_table)
        .and_then(|t| t.get("poetry"))
        .and_then(Item::as_table)
        .and_then(|p| p.get("dependencies"))
        .and_then(Item::as_table)
    {
        if deps.contains_key("socket-patch-hook") {
            return true;
        }
        if let Some(item) = deps.get("socket-patch") {
            if item_has_hook_extra(item) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── requirements.txt ─────────────────────────────────────────────

    #[test]
    fn test_requirements_add() {
        let out = requirements_add("requests==2.31.0\n").unwrap().unwrap();
        assert!(out.contains("requests==2.31.0"));
        assert!(out.contains("socket-patch[hook]"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn test_requirements_add_no_trailing_newline() {
        let out = requirements_add("requests").unwrap().unwrap();
        assert_eq!(out, "requests\nsocket-patch[hook]\n");
    }

    #[test]
    fn test_requirements_add_idempotent() {
        // The extra, the standalone wheel, and a pinned variant are all recognized.
        assert!(requirements_add("socket-patch[hook]\n").unwrap().is_none());
        assert!(requirements_add("socket-patch-hook\n").unwrap().is_none());
        assert!(requirements_add("socket-patch-hook==3.3.0\n")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_requirements_remove() {
        let out = requirements_remove("requests\nsocket-patch[hook]\n")
            .unwrap()
            .unwrap();
        assert_eq!(out, "requests\n");
    }

    #[test]
    fn test_requirements_remove_absent() {
        assert!(requirements_remove("requests\n").unwrap().is_none());
    }

    // ── pyproject PEP 621 ────────────────────────────────────────────

    #[test]
    fn test_pep621_add_to_existing_array() {
        let toml = "[project]\nname = \"x\"\ndependencies = [\"requests\"]\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        assert!(out.contains("socket-patch[hook]"));
        assert!(out.contains("requests"));
        // Re-parse to confirm validity + idempotency.
        assert!(pyproject_add(&out).unwrap().is_none());
    }

    #[test]
    fn test_pep621_add_creates_dependencies() {
        let toml = "[project]\nname = \"x\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        let deps = doc["project"]["dependencies"].as_array().unwrap();
        assert!(deps
            .iter()
            .any(|v| v.as_str() == Some("socket-patch[hook]")));
    }

    #[test]
    fn test_pep621_preserves_other_content() {
        let toml = "[build-system]\nrequires = [\"setuptools\"]\n\n[project]\nname = \"x\"\nversion = \"1.0\"\ndependencies = [\n    \"requests\",\n]\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        assert!(out.contains("[build-system]"));
        assert!(out.contains("version = \"1.0\""));
        assert!(out.contains("requests"));
        assert!(out.contains("socket-patch[hook]"));
    }

    #[test]
    fn test_pep621_remove() {
        let toml = "[project]\ndependencies = [\"requests\", \"socket-patch[hook]\"]\n";
        let out = pyproject_remove(toml).unwrap().unwrap();
        assert!(!out.contains("socket-patch[hook]"));
        assert!(out.contains("requests"));
    }

    // ── pyproject Poetry (the `socket-patch[hook]` equivalent: the
    //    `socket-patch` dep carrying the `hook` extra) ─────────────────

    #[test]
    fn test_poetry_add_new_dep() {
        let toml = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert!(
            item_has_hook_extra(&doc["tool"]["poetry"]["dependencies"]["socket-patch"]),
            "poetry dep must carry the hook extra; got:\n{out}"
        );
        // Idempotent.
        assert!(pyproject_add(&out).unwrap().is_none());
    }

    #[test]
    fn test_poetry_merges_extra_into_existing_dep() {
        // An existing `socket-patch = "^3.3.0"` gains the hook extra, version kept.
        let toml =
            "[tool.poetry]\nname = \"x\"\n[tool.poetry.dependencies]\nsocket-patch = \"^3.3.0\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        let item = &doc["tool"]["poetry"]["dependencies"]["socket-patch"];
        assert!(item_has_hook_extra(item), "hook extra must be added");
        assert_eq!(
            item.as_table_like()
                .and_then(|t| t.get("version"))
                .and_then(Item::as_str),
            Some("^3.3.0"),
            "existing version must be preserved"
        );
    }

    #[test]
    fn test_poetry_subtable_dependency_preserved() {
        // A `[tool.poetry.dependencies.socket-patch]` sub-table gains the hook
        // extra while keeping its version / source.
        let toml = "[tool.poetry.dependencies.socket-patch]\nversion = \"^3.3.0\"\ngit = \"https://example.com/x.git\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        let sp = &doc["tool"]["poetry"]["dependencies"]["socket-patch"];
        assert!(item_has_hook_extra(sp), "hook extra must be added");
        assert_eq!(
            sp.as_table_like()
                .and_then(|t| t.get("git"))
                .and_then(Item::as_str),
            Some("https://example.com/x.git"),
            "sub-table keys must survive"
        );
        // Idempotent.
        assert!(pyproject_add(&out).unwrap().is_none());
    }

    #[test]
    fn test_poetry_remove_strips_extra() {
        let toml = "[tool.poetry.dependencies]\nsocket-patch = {version = \"*\", extras = [\"hook\"]}\npython = \"^3.9\"\n";
        let out = pyproject_remove(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert!(!item_has_hook_extra(
            &doc["tool"]["poetry"]["dependencies"]["socket-patch"]
        ));
        assert!(doc["tool"]["poetry"]["dependencies"]
            .get("python")
            .is_some());
    }

    #[test]
    fn test_pep621_preferred_when_both_present() {
        // poetry 2.x: both [project] and [tool.poetry] — edit the PEP 621 array.
        let toml = "[project]\nname = \"x\"\ndependencies = []\n\n[tool.poetry]\nname = \"x\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert!(doc["project"]["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("socket-patch[hook]")));
    }

    #[test]
    fn test_invalid_toml_errors() {
        assert!(pyproject_add("this is = = not toml [[[").is_err());
    }

    #[test]
    fn test_pyproject_add_without_dep_surface_refuses() {
        // A pyproject.toml with neither `[project]` nor `[tool.poetry]` (the
        // classic setup.py/setup.cfg project that only carries `[build-system]`
        // or tool config) has no dependency surface to host the hook.
        // Synthesizing a `[project]` table with only `dependencies` makes the
        // manifest invalid — PEP 621 requires `name` and forbids making it
        // dynamic — so pip/setuptools/uv would refuse to build afterwards.
        // The edit must error, not break the user's build.
        let build_only =
            "[build-system]\nrequires = [\"setuptools\"]\nbuild-backend = \"setuptools.build_meta\"\n";
        assert!(
            pyproject_add(build_only).is_err(),
            "must not synthesize a name-less [project] table"
        );
        let tool_only = "[tool.black]\nline-length = 100\n";
        assert!(pyproject_add(tool_only).is_err());
    }

    #[test]
    fn test_poetry_add_multiconstraint_dep_not_clobbered() {
        // Poetry's multiple-constraints form declares one dep as an ARRAY of
        // constraint tables. That item is neither table-like nor a string, so
        // the replace-fallback would silently overwrite the user's whole
        // constraint set with `{version = "*", extras = ["hook"]}` — destroying
        // their version pins and python markers. Refuse instead.
        let toml = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\n\
                    socket-patch = [{version = \"^1.0\", python = \"^2.7\"}, {version = \"^2.0\", python = \"^3.7\"}]\n";
        assert!(
            pyproject_add(toml).is_err(),
            "a multi-constraint socket-patch dep must not be silently replaced"
        );
    }

    #[test]
    fn test_classic_poetry_with_project_urls_routes_to_poetry() {
        // `[project.urls]` conjures an implicit `[project]` table; a Poetry 1.x
        // project must still be edited in the Poetry table, not given a
        // `[project].dependencies` Poetry ignores.
        let toml = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n\n[project.urls]\nHome = \"https://example.com\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert!(
            item_has_hook_extra(&doc["tool"]["poetry"]["dependencies"]["socket-patch"]),
            "must edit the poetry table, not create [project].dependencies; got:\n{out}"
        );
        assert!(doc
            .get("project")
            .and_then(|p| p.get("dependencies"))
            .is_none());
    }

    #[test]
    fn test_requirements_preserves_crlf() {
        let out = requirements_add("requests\r\n").unwrap().unwrap();
        assert_eq!(out, "requests\r\nsocket-patch[hook]\r\n");
        let removed = requirements_remove(&out).unwrap().unwrap();
        assert_eq!(removed, "requests\r\n");
    }

    // ── file-level NotFound handling (the create / no-op paths) ──────

    #[tokio::test]
    async fn test_add_creates_missing_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt"); // does not exist
        let res = add_hook_dependency(&req, ManifestKind::Requirements, false).await;
        assert_eq!(res.status, PthStatus::Updated);
        let body = tokio::fs::read_to_string(&req).await.unwrap();
        assert_eq!(body, "socket-patch[hook]\n");
    }

    #[tokio::test]
    async fn test_add_missing_pyproject_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let py = dir.path().join("pyproject.toml"); // does not exist
        let res = add_hook_dependency(&py, ManifestKind::Pyproject, false).await;
        assert_eq!(res.status, PthStatus::Error);
    }

    #[tokio::test]
    async fn test_remove_missing_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt"); // does not exist
        let res = remove_hook_dependency(&req, ManifestKind::Requirements, false).await;
        assert_eq!(res.status, PthStatus::AlreadyConfigured);
    }

    #[tokio::test]
    async fn test_add_dry_run_does_not_create() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        let res = add_hook_dependency(&req, ManifestKind::Requirements, true).await;
        assert_eq!(res.status, PthStatus::Updated);
        assert!(!req.exists(), "dry-run must not create the file");
    }

    // ── atomic-write contract (no truncation / no stage litter) ──────
    //
    // The edit must go through stage+fsync+rename, never a bare truncating
    // write, so a crash can't leave the user's hand-authored manifest empty.
    // A leaked `.socket-stage-*` sibling would mean the rename didn't complete.

    async fn count_stage_litter(dir: &Path) -> usize {
        let mut rd = tokio::fs::read_dir(dir).await.unwrap();
        let mut n = 0;
        while let Some(entry) = rd.next_entry().await.unwrap() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".socket-stage-")
            {
                n += 1;
            }
        }
        n
    }

    #[tokio::test]
    async fn test_add_pyproject_atomic_no_litter_and_intact() {
        let dir = tempfile::tempdir().unwrap();
        let py = dir.path().join("pyproject.toml");
        let original = "[build-system]\nrequires = [\"setuptools\"]\n\n[project]\nname = \"x\"\ndependencies = [\"requests\"]\n";
        tokio::fs::write(&py, original).await.unwrap();

        let res = add_hook_dependency(&py, ManifestKind::Pyproject, false).await;
        assert_eq!(res.status, PthStatus::Updated);

        // No half-written stage file left behind.
        assert_eq!(count_stage_litter(dir.path()).await, 0);
        // The file is fully written, valid TOML, and preserved prior content.
        let body = tokio::fs::read_to_string(&py).await.unwrap();
        let doc = body.parse::<DocumentMut>().unwrap();
        assert!(body.contains("[build-system]"));
        let deps = doc["project"]["dependencies"].as_array().unwrap();
        assert!(deps.iter().any(|v| v.as_str() == Some("requests")));
        assert!(deps
            .iter()
            .any(|v| v.as_str() == Some("socket-patch[hook]")));
    }

    #[tokio::test]
    async fn test_remove_requirements_atomic_no_litter() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        tokio::fs::write(&req, "requests\nsocket-patch[hook]\n")
            .await
            .unwrap();

        let res = remove_hook_dependency(&req, ManifestKind::Requirements, false).await;
        assert_eq!(res.status, PthStatus::Updated);
        assert_eq!(count_stage_litter(dir.path()).await, 0);
        assert_eq!(tokio::fs::read_to_string(&req).await.unwrap(), "requests\n");
    }

    // ── structural hook detection (pyproject_contains_hook) ──────────
    //
    // The `setup --check` probe must agree with what `setup` wrote. The classic
    // Poetry form has no `socket-patch[hook]` substring, so the textual probe
    // alone mis-reports a configured project as needing configuration.

    #[test]
    fn test_pyproject_contains_hook_poetry_form_roundtrips() {
        // Regression: poetry_add writes the structural `extras = ["hook"]` form;
        // the textual probe can't see it, but the structural one must.
        let toml = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        assert!(
            pyproject_contains_hook(&out),
            "structural probe must see the poetry extras form:\n{out}"
        );
        // This is precisely why the structural probe is needed: the textual one
        // (used for requirements.txt) cannot detect the poetry form.
        assert!(
            !deps_contain_hook(&out),
            "textual probe is (by design) blind to the poetry form; if this \
             ever becomes true the structural probe may be redundant:\n{out}"
        );
    }

    #[test]
    fn test_pyproject_contains_hook_pep621_and_wheel() {
        // PEP 621 array, extra spelling.
        assert!(pyproject_contains_hook(
            "[project]\ndependencies = [\"requests\", \"socket-patch[hook]>=3.3.0\"]\n"
        ));
        // PEP 621 array, bare wheel spelling.
        assert!(pyproject_contains_hook(
            "[project]\ndependencies = [\"socket-patch-hook\"]\n"
        ));
        // Poetry bare-wheel key.
        assert!(pyproject_contains_hook(
            "[tool.poetry.dependencies]\nsocket-patch-hook = \"*\"\n"
        ));
    }

    #[test]
    fn test_pyproject_contains_hook_negative() {
        // A plain socket-patch dep (CLI only, no hook) is NOT the hook — in
        // either surface.
        assert!(!pyproject_contains_hook(
            "[project]\ndependencies = [\"socket-patch>=3.3.0\"]\n"
        ));
        assert!(!pyproject_contains_hook(
            "[tool.poetry.dependencies]\nsocket-patch = \"^3.3.0\"\n"
        ));
        // A socket-patch dep carrying some *other* extra is not the hook.
        assert!(!pyproject_contains_hook(
            "[tool.poetry.dependencies]\nsocket-patch = {version = \"*\", extras = [\"cli\"]}\n"
        ));
        // Empty / unrelated.
        assert!(!pyproject_contains_hook("[project]\nname = \"x\"\n"));
    }

    #[test]
    fn test_pyproject_contains_hook_malformed_falls_back_to_textual() {
        // Unparseable TOML: fall back to the textual probe rather than hard-fail.
        assert!(pyproject_contains_hook(
            "this = = not toml [[[ socket-patch[hook]"
        ));
        assert!(!pyproject_contains_hook("this = = not toml [[[ requests"));
    }

    #[test]
    fn test_pyproject_contains_hook_after_remove_is_false() {
        // Round-trip: add then remove → structural probe reports not-configured.
        let toml = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\nsocket-patch = \"^3.3.0\"\n";
        let added = pyproject_add(toml).unwrap().unwrap();
        assert!(pyproject_contains_hook(&added));
        let removed = pyproject_remove(&added).unwrap().unwrap();
        assert!(
            !pyproject_contains_hook(&removed),
            "after remove the hook must be gone:\n{removed}"
        );
    }

    #[tokio::test]
    async fn test_dry_run_does_no_io_for_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        let py = dir.path().join("pyproject.toml");
        let original = "[project]\nname = \"x\"\ndependencies = [\"requests\"]\n";
        tokio::fs::write(&py, original).await.unwrap();

        let res = add_hook_dependency(&py, ManifestKind::Pyproject, true).await;
        assert_eq!(res.status, PthStatus::Updated);
        // Dry-run must neither stage nor mutate the original.
        assert_eq!(count_stage_litter(dir.path()).await, 0);
        assert_eq!(tokio::fs::read_to_string(&py).await.unwrap(), original);
    }
}
