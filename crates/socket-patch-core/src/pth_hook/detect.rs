//! Detect a Python project's dependency manager and probe for the hook dep.

use std::path::Path;

/// The dependency `setup` adds (PEP 508 form, used for `requirements.txt` and
/// PEP 621 `[project].dependencies`): the `socket-patch[hook]` extra, which
/// pulls both the socket-patch CLI and the socket-patch-hook wheel (the `.pth`
/// carrier). A single, familiar line. Classic Poetry can't express an extra as
/// a bare key, so [`super::edit`] emits the equivalent
/// `socket-patch = { extras = ["hook"] }` there instead.
pub const HOOK_DEP: &str = "socket-patch[hook]";

/// Substrings (space-insensitive, lower-cased) that mean the hook is already
/// declared — the `socket-patch[hook]` extra, the standalone wheel, or the
/// underscore spelling. (The Poetry `extras = ["hook"]` form is detected
/// structurally by [`super::edit`], not by this textual check.)
const HOOK_MARKERS: &[&str] = &["socket-patch[hook]", "socket-patch-hook", "socket_patch_hook"];

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
fn has_table(content: &str, prefix: &str) -> bool {
    content.lines().any(|line| {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix('[') {
            let header = rest.trim_start_matches('[').trim_end_matches(']');
            header == prefix || header.starts_with(&format!("{prefix}."))
        } else {
            false
        }
    })
}

/// True if the given manifest text already declares the hook dependency, in any
/// form. Space- and case-insensitive so `socket-patch [hook]` / `Socket-Patch`
/// are recognised.
pub fn deps_contain_hook(text: &str) -> bool {
    let normalized: String = text.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
    HOOK_MARKERS
        .iter()
        .any(|m| normalized.contains(&m.to_lowercase()))
}

/// True if a single PEP 508 dependency spec is the hook dependency.
pub fn spec_is_hook(spec: &str) -> bool {
    deps_contain_hook(spec)
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
    fn test_has_table() {
        let toml = "[tool.poetry]\nname='x'\n[tool.poetry.dependencies]\n";
        assert!(has_table(toml, "tool.poetry"));
        assert!(!has_table(toml, "tool.pdm"));
        assert!(has_table("[project]\n", "project"));
        // not fooled by a value that contains the text
        assert!(!has_table("name = \"tool.poetry helper\"\n", "tool.poetry"));
    }

    #[tokio::test]
    async fn test_detect_uv_by_lock() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("uv.lock"), "").await.unwrap();
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
        assert_eq!(detect_python_pm(dir.path()).await, PythonPackageManager::Pip);
    }

    #[test]
    fn test_lock_command() {
        assert_eq!(PythonPackageManager::Uv.lock_command(), Some(("uv", &["lock"][..])));
        assert_eq!(PythonPackageManager::Pip.lock_command(), None);
        assert_eq!(PythonPackageManager::Hatch.lock_command(), None);
    }
}
