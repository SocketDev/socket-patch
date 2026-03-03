use std::path::PathBuf;
use std::process::Command;

// ---------------------------------------------------------------------------
// Individual package manager global prefix helpers
// ---------------------------------------------------------------------------

/// Get the npm global `node_modules` path using `npm root -g`.
pub fn get_npm_global_prefix() -> Result<String, String> {
    let output = Command::new("npm")
        .args(["root", "-g"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to run `npm root -g`: {e}"))?;

    if !output.status.success() {
        return Err(
            "Failed to determine npm global prefix. Ensure npm is installed and in PATH."
                .to_string(),
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err("npm root -g returned empty output".to_string());
    }

    Ok(path)
}

/// Get the yarn global `node_modules` path via `yarn global dir`.
pub fn get_yarn_global_prefix() -> Option<String> {
    let output = Command::new("yarn")
        .args(["global", "dir"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let dir = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if dir.is_empty() {
        return None;
    }

    Some(
        PathBuf::from(dir)
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

/// Get the pnpm global `node_modules` path via `pnpm root -g`.
pub fn get_pnpm_global_prefix() -> Option<String> {
    let output = Command::new("pnpm")
        .args(["root", "-g"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return None;
    }

    Some(path)
}

/// Get the bun global `node_modules` path via `bun pm bin -g`.
pub fn get_bun_global_prefix() -> Option<String> {
    let output = Command::new("bun")
        .args(["pm", "bin", "-g"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let bin_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if bin_path.is_empty() {
        return None;
    }

    let bun_root = PathBuf::from(&bin_path);
    let parent = bun_root.parent()?;

    Some(
        parent
            .join("install")
            .join("global")
            .join("node_modules")
            .to_string_lossy()
            .to_string(),
    )
}

// ---------------------------------------------------------------------------
// Aggregation helpers
// ---------------------------------------------------------------------------

/// Get the global `node_modules` path, with support for a custom override.
///
/// If `custom` is `Some`, that value is returned directly. Otherwise, falls
/// back to `get_npm_global_prefix()`.
pub fn get_global_prefix(custom: Option<&str>) -> Result<String, String> {
    if let Some(custom_path) = custom {
        return Ok(custom_path.to_string());
    }
    get_npm_global_prefix()
}

/// Get all global `node_modules` paths for package lookup.
///
/// Returns paths from all detected package managers (npm, pnpm, yarn, bun).
/// If `custom` is provided, only that path is returned.
pub fn get_global_node_modules_paths(custom: Option<&str>) -> Vec<String> {
    if let Some(custom_path) = custom {
        return vec![custom_path.to_string()];
    }

    let mut paths = Vec::new();

    if let Ok(npm_path) = get_npm_global_prefix() {
        paths.push(npm_path);
    }

    if let Some(pnpm_path) = get_pnpm_global_prefix() {
        paths.push(pnpm_path);
    }

    if let Some(yarn_path) = get_yarn_global_prefix() {
        paths.push(yarn_path);
    }

    if let Some(bun_path) = get_bun_global_prefix() {
        paths.push(bun_path);
    }

    paths
}

/// Check if a path is within a global `node_modules` directory.
pub fn is_global_path(pkg_path: &str) -> bool {
    let paths = get_global_node_modules_paths(None);
    let normalized = PathBuf::from(pkg_path);
    let normalized_str = normalized.to_string_lossy();

    paths.iter().any(|global_path| {
        let gp = PathBuf::from(global_path);
        normalized_str.starts_with(&*gp.to_string_lossy())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_global_prefix_custom() {
        let result = get_global_prefix(Some("/custom/node_modules"));
        assert_eq!(result.unwrap(), "/custom/node_modules");
    }

    #[test]
    fn test_get_global_node_modules_paths_custom() {
        let paths = get_global_node_modules_paths(Some("/my/custom/path"));
        assert_eq!(paths, vec!["/my/custom/path".to_string()]);
    }
}
