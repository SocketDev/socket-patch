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
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use super::detect::{deps_contain_hook, spec_is_hook, HOOK_DEP};

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
            if e.kind() == std::io::ErrorKind::NotFound
                && kind == ManifestKind::Requirements =>
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
                if let Err(e) = fs::write(path, &new_content).await {
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
                if let Err(e) = fs::write(path, &new_content).await {
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
    } else {
        pep621_add(&mut doc)?
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
/// but a non-table.
fn ensure_table<'a>(parent: &'a mut Table, key: &str, implicit: bool) -> Result<&'a mut Table, String> {
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

    // The hook is a standalone, version-agnostic dependency — add it as its own
    // key rather than mutating the user's `socket-patch` entry. `"*"` because
    // the hook needs no specific version (it runs whatever CLI is on PATH).
    if deps.contains_key("socket-patch-hook") {
        return Ok(false);
    }
    deps.insert("socket-patch-hook", Item::Value(Value::from("*")));
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
    deps.remove("socket-patch-hook").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── requirements.txt ─────────────────────────────────────────────

    #[test]
    fn test_requirements_add() {
        let out = requirements_add("requests==2.31.0\n").unwrap().unwrap();
        assert!(out.contains("requests==2.31.0"));
        assert!(out.contains("socket-patch-hook"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn test_requirements_add_no_trailing_newline() {
        let out = requirements_add("requests").unwrap().unwrap();
        assert_eq!(out, "requests\nsocket-patch-hook\n");
    }

    #[test]
    fn test_requirements_add_idempotent() {
        // Both the standalone wheel and the legacy `[hook]` extra are recognized.
        assert!(requirements_add("socket-patch-hook\n").unwrap().is_none());
        assert!(requirements_add("socket-patch-hook==3.3.0\n").unwrap().is_none());
        assert!(requirements_add("socket-patch[hook]\n").unwrap().is_none());
    }

    #[test]
    fn test_requirements_remove() {
        let out = requirements_remove("requests\nsocket-patch-hook\n")
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
        assert!(out.contains("socket-patch-hook"));
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
        assert!(deps.iter().any(|v| v.as_str() == Some("socket-patch-hook")));
    }

    #[test]
    fn test_pep621_preserves_other_content() {
        let toml = "[build-system]\nrequires = [\"setuptools\"]\n\n[project]\nname = \"x\"\nversion = \"1.0\"\ndependencies = [\n    \"requests\",\n]\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        assert!(out.contains("[build-system]"));
        assert!(out.contains("version = \"1.0\""));
        assert!(out.contains("requests"));
        assert!(out.contains("socket-patch-hook"));
    }

    #[test]
    fn test_pep621_remove() {
        let toml = "[project]\ndependencies = [\"requests\", \"socket-patch-hook\"]\n";
        let out = pyproject_remove(toml).unwrap().unwrap();
        assert!(!out.contains("socket-patch-hook"));
        assert!(out.contains("requests"));
    }

    // ── pyproject Poetry (standalone hook key, no extras-merging) ─────

    #[test]
    fn test_poetry_add_new_key() {
        let toml = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert_eq!(
            doc["tool"]["poetry"]["dependencies"]["socket-patch-hook"].as_str(),
            Some("*")
        );
        // Idempotent.
        assert!(pyproject_add(&out).unwrap().is_none());
    }

    #[test]
    fn test_poetry_leaves_existing_socket_patch_untouched() {
        // An existing `socket-patch` dependency must NOT be mutated; we only add
        // the standalone `socket-patch-hook` key.
        let toml = "[tool.poetry]\nname = \"x\"\n[tool.poetry.dependencies]\nsocket-patch = \"^3.3.0\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert_eq!(
            doc["tool"]["poetry"]["dependencies"]["socket-patch"].as_str(),
            Some("^3.3.0"),
            "existing socket-patch dep must be left intact"
        );
        assert_eq!(
            doc["tool"]["poetry"]["dependencies"]["socket-patch-hook"].as_str(),
            Some("*")
        );
    }

    #[test]
    fn test_poetry_subtable_dependency_preserved() {
        // A `[tool.poetry.dependencies.socket-patch]` sub-table (version/source)
        // must survive untouched; only the standalone hook key is added.
        let toml = "[tool.poetry.dependencies.socket-patch]\nversion = \"^3.3.0\"\ngit = \"https://example.com/x.git\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        let sp = &doc["tool"]["poetry"]["dependencies"]["socket-patch"];
        assert_eq!(
            sp.as_table_like().and_then(|t| t.get("git")).and_then(Item::as_str),
            Some("https://example.com/x.git"),
            "sub-table keys must survive"
        );
        assert_eq!(
            doc["tool"]["poetry"]["dependencies"]["socket-patch-hook"].as_str(),
            Some("*")
        );
        // Idempotent.
        assert!(pyproject_add(&out).unwrap().is_none());
    }

    #[test]
    fn test_poetry_remove() {
        let toml = "[tool.poetry.dependencies]\nsocket-patch-hook = \"*\"\npython = \"^3.9\"\n";
        let out = pyproject_remove(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert!(doc["tool"]["poetry"]["dependencies"]
            .get("socket-patch-hook")
            .is_none());
        assert!(doc["tool"]["poetry"]["dependencies"].get("python").is_some());
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
            .any(|v| v.as_str() == Some("socket-patch-hook")));
    }

    #[test]
    fn test_invalid_toml_errors() {
        assert!(pyproject_add("this is = = not toml [[[").is_err());
    }

    #[test]
    fn test_classic_poetry_with_project_urls_routes_to_poetry() {
        // `[project.urls]` conjures an implicit `[project]` table; a Poetry 1.x
        // project must still be edited in the Poetry table, not given a
        // `[project].dependencies` Poetry ignores.
        let toml = "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\npython = \"^3.9\"\n\n[project.urls]\nHome = \"https://example.com\"\n";
        let out = pyproject_add(toml).unwrap().unwrap();
        let doc = out.parse::<DocumentMut>().unwrap();
        assert_eq!(
            doc["tool"]["poetry"]["dependencies"]["socket-patch-hook"].as_str(),
            Some("*"),
            "must edit the poetry table, not create [project].dependencies; got:\n{out}"
        );
        assert!(doc.get("project").and_then(|p| p.get("dependencies")).is_none());
    }

    #[test]
    fn test_requirements_preserves_crlf() {
        let out = requirements_add("requests\r\n").unwrap().unwrap();
        assert_eq!(out, "requests\r\nsocket-patch-hook\r\n");
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
        assert_eq!(body, "socket-patch-hook\n");
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
}
