//! Detect a Python project's dependency manager and probe for the hook dep.

use std::path::Path;

/// The dependency `setup` adds (PEP 508 form, used for `requirements.txt` and
/// PEP 621 `[project].dependencies`): the `socket-patch[hook]` extra, which
/// pulls both the socket-patch CLI and the socket-patch-hook wheel (the `.pth`
/// carrier). A single, familiar line. Classic Poetry can't express an extra as
/// a bare key, so [`super::edit`] emits the equivalent
/// `socket-patch = { extras = ["hook"] }` there instead.
pub(crate) const HOOK_DEP: &str = "socket-patch[hook]";

/// Substrings (space-insensitive, lower-cased) that mean the hook is already
/// declared — the `socket-patch[hook]` extra, the standalone wheel, or the
/// underscore spelling. (The Poetry `extras = ["hook"]` form is detected
/// structurally by [`super::edit`], not by this textual check.)
const HOOK_MARKERS: &[&str] = &[
    "socket-patch[hook]",
    "socket-patch-hook",
    "socket_patch_hook",
];

/// Which Python dependency-management style a project uses. Drives both which
/// manifest/table `setup` edits and which lockfile (if any) to refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PythonPackageManager {
    Uv,
    Poetry,
    Pdm,
    Hatch,
    Pip,
}

impl PythonPackageManager {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Pdm => "pdm",
            Self::Hatch => "hatch",
            Self::Pip => "pip",
        }
    }

    /// The lockfile-refresh command `(program, args)` for managers whose frozen
    /// CI install reads a lockfile that must be regenerated after editing the
    /// dependency list. `None` for managers that resolve dependencies directly
    /// from the manifest at install time (pip, hatch).
    pub fn lock_command(&self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            Self::Uv => Some(("uv", &["lock"])),
            Self::Poetry => Some(("poetry", &["lock"])),
            Self::Pdm => Some(("pdm", &["lock"])),
            Self::Hatch | Self::Pip => None,
        }
    }
}

/// Detect the dependency manager from lockfiles and `pyproject.toml` tables.
///
/// Lockfiles are the strongest signal; `[tool.*]` tables come next; a project
/// with only `requirements.txt` / a PEP 621 `pyproject.toml` falls through to
/// `Pip`.
pub async fn detect_python_pm(cwd: &Path) -> PythonPackageManager {
    if tokio::fs::metadata(cwd.join("uv.lock")).await.is_ok() {
        return PythonPackageManager::Uv;
    }
    if tokio::fs::metadata(cwd.join("pdm.lock")).await.is_ok() {
        return PythonPackageManager::Pdm;
    }
    if tokio::fs::metadata(cwd.join("poetry.lock")).await.is_ok() {
        return PythonPackageManager::Poetry;
    }
    if let Ok(content) = tokio::fs::read_to_string(cwd.join("pyproject.toml")).await {
        // Header-anchored checks so a stray substring in a value/comment does
        // not misclassify.
        if has_table(&content, "tool.uv") {
            return PythonPackageManager::Uv;
        }
        if has_table(&content, "tool.poetry") {
            return PythonPackageManager::Poetry;
        }
        if has_table(&content, "tool.pdm") {
            return PythonPackageManager::Pdm;
        }
        if has_table(&content, "tool.hatch") {
            return PythonPackageManager::Hatch;
        }
    }
    PythonPackageManager::Pip
}

/// True if a `[prefix]` or `[prefix.*]` table header appears in the TOML text.
/// Also used by the pypi vendor flavor router (`patch::vendor::pypi`).
pub(crate) fn has_table(content: &str, prefix: &str) -> bool {
    content.lines().any(|line| {
        let l = line.trim();
        let Some(rest) = l.strip_prefix('[') else {
            return false;
        };
        // Tolerate array-of-tables (`[[..]]`) by dropping a second opening
        // bracket, then take everything up to the closing `]` so a trailing
        // inline comment (`[tool.uv] # note`) or interior padding
        // (`[ tool.uv ]`) — both valid TOML — doesn't defeat the match.
        let rest = rest.trim_start_matches('[');
        let Some(end) = rest.find(']') else {
            return false;
        };
        let header = rest[..end].trim();
        header == prefix || header.starts_with(&format!("{prefix}."))
    })
}

/// True if the given manifest text already declares the hook dependency, in any
/// form. Space- and case-insensitive so `socket-patch [hook]` / `Socket-Patch`
/// are recognised.
pub fn deps_contain_hook(text: &str) -> bool {
    // Normalize per line: drop intra-line whitespace so `socket-patch [hook]`
    // matches, but keep line boundaries intact. Stripping newlines too would
    // glue adjacent specs together (this is called on whole-file content by
    // `setup`'s state probe), turning a trailing `socket-patch` plus a following
    // `[hook]` into a phantom marker — a false positive.
    text.lines().any(|line| {
        // Drop a `#` comment first (requirements.txt and TOML both comment
        // with `#`): a commented-out `# socket-patch[hook]` declares nothing —
        // pip never installs it — and a marker mentioned inside a trailing
        // comment must not read as configured.
        let spec = match line.find('#') {
            Some(i) => &line[..i],
            None => line,
        };
        let normalized: String = spec
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        HOOK_MARKERS.iter().any(|m| normalized.contains(*m))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deps_contain_hook_positive_forms() {
        assert!(deps_contain_hook("socket-patch[hook]"));
        assert!(deps_contain_hook("socket-patch [hook]"));
        assert!(deps_contain_hook("Socket-Patch[hook]>=3.3.0"));
        assert!(deps_contain_hook("socket-patch-hook==3.3.0"));
        assert!(deps_contain_hook("socket_patch_hook"));
    }

    #[test]
    fn test_deps_contain_hook_negative() {
        // A plain socket-patch dependency is NOT the hook.
        assert!(!deps_contain_hook("socket-patch>=3.3.0"));
        assert!(!deps_contain_hook("requests==2.31.0"));
        assert!(!deps_contain_hook(""));
    }

    #[test]
    fn test_deps_contain_hook_no_cross_line_glue() {
        // `deps_contain_hook` is run on whole-file content by the setup state
        // probe. Two unrelated specs on adjacent lines must NOT be glued into
        // a phantom `socket-patch[hook]` marker.
        let requirements = "socket-patch\n[hook]\nrequests\n";
        assert!(!deps_contain_hook(requirements));

        // A wrapped TOML dependency array around a plain socket-patch dep also
        // must not synthesize the marker across line breaks.
        let pyproject = "dependencies = [\n  \"socket-patch\",\n]\nextras = [\"hook\"]\n";
        assert!(!deps_contain_hook(pyproject));
    }

    #[test]
    fn test_deps_contain_hook_real_marker_in_multiline() {
        // The genuine hook spec on its own line within whole-file content is
        // still detected (intra-line spaces tolerated).
        let requirements = "requests==2.31.0\nsocket-patch [hook]\nflask\n";
        assert!(deps_contain_hook(requirements));
        let pyproject = "dependencies = [\n  \"requests\",\n  \"socket-patch[hook]>=3.3.0\",\n]\n";
        assert!(deps_contain_hook(pyproject));
    }

    #[test]
    fn test_deps_contain_hook_commented_out_is_not_declared() {
        // A commented-out spec declares nothing: pip never installs it, and
        // the edit path (`requirements_add` strips comments before probing)
        // would still add the hook — so the state probe / `setup --check`
        // must not read it as configured.
        assert!(!deps_contain_hook(
            "# socket-patch[hook]\nrequests==2.31.0\n"
        ));
        // A marker mentioned inside another dep's trailing comment is not a
        // declaration either.
        assert!(!deps_contain_hook(
            "requests==2.31.0  # TODO: add socket-patch[hook]\n"
        ));
        // But a real spec WITH a trailing comment is still declared.
        assert!(deps_contain_hook(
            "socket-patch[hook]  # the .pth carrier\n"
        ));
    }

    #[test]
    fn test_has_table() {
        let toml = "[tool.poetry]\nname='x'\n[tool.poetry.dependencies]\n";
        assert!(has_table(toml, "tool.poetry"));
        assert!(!has_table(toml, "tool.pdm"));
        assert!(has_table("[project]\n", "project"));
        // not fooled by a value that contains the text
        assert!(!has_table("name = \"tool.poetry helper\"\n", "tool.poetry"));
    }

    #[test]
    fn test_has_table_trailing_comment_and_padding() {
        // A trailing inline comment after the header is valid TOML and must
        // not defeat detection (previously `trim_end_matches(']')` left the
        // comment glued to the header).
        assert!(has_table("[tool.uv] # the uv table\n", "tool.uv"));
        assert!(has_table("[tool.uv.sources]  # comment\n", "tool.uv"));
        // Interior padding inside the brackets is also valid TOML.
        assert!(has_table("[ tool.pdm ]\n", "tool.pdm"));
        // Array-of-tables form, with a comment, still resolves the namespace.
        assert!(has_table("[[tool.poetry.source]] # extra\n", "tool.poetry"));
        // A sibling prefix must still not match (no spurious widening).
        assert!(!has_table("[tool.uvicorn] # web\n", "tool.uv"));
    }

    #[tokio::test]
    async fn test_detect_uv_by_lock() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("uv.lock"), "")
            .await
            .unwrap();
        assert_eq!(detect_python_pm(dir.path()).await, PythonPackageManager::Uv);
    }

    #[tokio::test]
    async fn test_detect_poetry_by_table() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("pyproject.toml"),
            "[tool.poetry]\nname = \"x\"\n",
        )
        .await
        .unwrap();
        assert_eq!(
            detect_python_pm(dir.path()).await,
            PythonPackageManager::Poetry
        );
    }

    #[tokio::test]
    async fn test_detect_pip_fallback() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("requirements.txt"), "requests\n")
            .await
            .unwrap();
        assert_eq!(
            detect_python_pm(dir.path()).await,
            PythonPackageManager::Pip
        );
    }

    #[test]
    fn test_lock_command() {
        assert_eq!(
            PythonPackageManager::Uv.lock_command(),
            Some(("uv", &["lock"][..]))
        );
        assert_eq!(PythonPackageManager::Pip.lock_command(), None);
        assert_eq!(PythonPackageManager::Hatch.lock_command(), None);
    }
}
