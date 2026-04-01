use std::path::{Path, PathBuf};
use tokio::fs;

/// Workspace configuration type.
#[derive(Debug, Clone)]
pub enum WorkspaceType {
    Npm,
    Pnpm,
    None,
}

/// Workspace configuration.
#[derive(Debug, Clone)]
pub struct WorkspaceConfig {
    pub ws_type: WorkspaceType,
    pub patterns: Vec<String>,
}

/// Location of a discovered package.json file.
#[derive(Debug, Clone)]
pub struct PackageJsonLocation {
    pub path: PathBuf,
    pub is_root: bool,
    pub is_workspace: bool,
    pub workspace_pattern: Option<String>,
}

/// Result of finding package.json files.
#[derive(Debug)]
pub struct PackageJsonFindResult {
    pub files: Vec<PackageJsonLocation>,
    pub workspace_type: WorkspaceType,
}

/// Find all package.json files, respecting workspace configurations.
pub async fn find_package_json_files(
    start_path: &Path,
) -> PackageJsonFindResult {
    let mut results = Vec::new();
    let root_package_json = start_path.join("package.json");

    let mut root_exists = false;
    let mut workspace_config = WorkspaceConfig {
        ws_type: WorkspaceType::None,
        patterns: Vec::new(),
    };

    if fs::metadata(&root_package_json).await.is_ok() {
        root_exists = true;
        workspace_config = detect_workspaces(&root_package_json).await;
        results.push(PackageJsonLocation {
            path: root_package_json,
            is_root: true,
            is_workspace: false,
            workspace_pattern: None,
        });
    }

    match workspace_config.ws_type {
        WorkspaceType::None => {
            if root_exists {
                let nested = find_nested_package_json_files(start_path).await;
                results.extend(nested);
            }
        }
        _ => {
            let ws_packages =
                find_workspace_packages(start_path, &workspace_config).await;
            results.extend(ws_packages);
        }
    }

    PackageJsonFindResult {
        files: results,
        workspace_type: workspace_config.ws_type,
    }
}

/// Detect workspace configuration from package.json.
pub async fn detect_workspaces(package_json_path: &Path) -> WorkspaceConfig {
    let default = WorkspaceConfig {
        ws_type: WorkspaceType::None,
        patterns: Vec::new(),
    };

    let content = match fs::read_to_string(package_json_path).await {
        Ok(c) => c,
        Err(_) => return default,
    };

    let pkg: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return default,
    };

    // Check for pnpm workspaces first — pnpm projects may also have
    // "workspaces" in package.json for compatibility, but
    // pnpm-workspace.yaml is the definitive signal.
    let dir = package_json_path.parent().unwrap_or(Path::new("."));
    let pnpm_workspace = dir.join("pnpm-workspace.yaml");
    if let Ok(yaml_content) = fs::read_to_string(&pnpm_workspace).await {
        let patterns = parse_pnpm_workspace_patterns(&yaml_content);
        return WorkspaceConfig {
            ws_type: WorkspaceType::Pnpm,
            patterns,
        };
    }

    // Check for npm/yarn workspaces
    if let Some(workspaces) = pkg.get("workspaces") {
        let patterns = if let Some(arr) = workspaces.as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else if let Some(obj) = workspaces.as_object() {
            obj.get("packages")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        return WorkspaceConfig {
            ws_type: WorkspaceType::Npm,
            patterns,
        };
    }

    default
}

/// Simple parser for pnpm-workspace.yaml packages field.
fn parse_pnpm_workspace_patterns(yaml_content: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut in_packages = false;

    for line in yaml_content.lines() {
        let trimmed = line.trim();

        if trimmed == "packages:" {
            in_packages = true;
            continue;
        }

        if in_packages {
            if !trimmed.is_empty()
                && !trimmed.starts_with('-')
                && !trimmed.starts_with('#')
            {
                break;
            }

            if let Some(rest) = trimmed.strip_prefix('-') {
                let item = rest.trim().trim_matches('\'').trim_matches('"');
                if !item.is_empty() {
                    patterns.push(item.to_string());
                }
            }
        }
    }

    patterns
}

/// Find workspace packages based on workspace patterns.
async fn find_workspace_packages(
    root_path: &Path,
    config: &WorkspaceConfig,
) -> Vec<PackageJsonLocation> {
    let mut results = Vec::new();

    for pattern in &config.patterns {
        let packages = find_packages_matching_pattern(root_path, pattern).await;
        for p in packages {
            results.push(PackageJsonLocation {
                path: p,
                is_root: false,
                is_workspace: true,
                workspace_pattern: Some(pattern.clone()),
            });
        }
    }

    results
}

/// Find packages matching a workspace pattern.
async fn find_packages_matching_pattern(
    root_path: &Path,
    pattern: &str,
) -> Vec<PathBuf> {
    let mut results = Vec::new();
    let parts: Vec<&str> = pattern.split('/').collect();

    if parts.len() == 2 && parts[1] == "*" {
        let search_path = root_path.join(parts[0]);
        search_one_level(&search_path, &mut results).await;
    } else if parts.len() == 2 && parts[1] == "**" {
        let search_path = root_path.join(parts[0]);
        search_recursive(&search_path, &mut results).await;
    } else {
        let pkg_json = root_path.join(pattern).join("package.json");
        if fs::metadata(&pkg_json).await.is_ok() {
            results.push(pkg_json);
        }
    }

    results
}

/// Search one level deep for package.json files.
async fn search_one_level(dir: &Path, results: &mut Vec<PathBuf>) {
    let mut entries = match fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let ft = match entry.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !ft.is_dir() {
            continue;
        }
        let pkg_json = entry.path().join("package.json");
        if fs::metadata(&pkg_json).await.is_ok() {
            results.push(pkg_json);
        }
    }
}

/// Search recursively for package.json files.
async fn search_recursive(dir: &Path, results: &mut Vec<PathBuf>) {
    let mut entries = match fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let ft = match entry.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !ft.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden directories, node_modules, dist, build
        if name_str.starts_with('.')
            || name_str == "node_modules"
            || name_str == "dist"
            || name_str == "build"
        {
            continue;
        }

        let full_path = entry.path();
        let pkg_json = full_path.join("package.json");
        if fs::metadata(&pkg_json).await.is_ok() {
            results.push(pkg_json);
        }

        Box::pin(search_recursive(&full_path, results)).await;
    }
}

/// Find nested package.json files without workspace configuration.
async fn find_nested_package_json_files(
    start_path: &Path,
) -> Vec<PackageJsonLocation> {
    let mut results = Vec::new();
    let root_pkg = start_path.join("package.json");
    search_nested(start_path, &root_pkg, 0, &mut results).await;
    results
}

async fn search_nested(
    dir: &Path,
    root_pkg: &Path,
    depth: usize,
    results: &mut Vec<PackageJsonLocation>,
) {
    if depth > 5 {
        return;
    }

    let mut entries = match fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let ft = match entry.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !ft.is_dir() {
            continue;
        }

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.starts_with('.')
            || name_str == "node_modules"
            || name_str == "dist"
            || name_str == "build"
        {
            continue;
        }

        let full_path = entry.path();
        let pkg_json = full_path.join("package.json");
        if fs::metadata(&pkg_json).await.is_ok() && pkg_json != root_pkg {
            results.push(PackageJsonLocation {
                path: pkg_json,
                is_root: false,
                is_workspace: false,
                workspace_pattern: None,
            });
        }

        Box::pin(search_nested(&full_path, root_pkg, depth + 1, results)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Group 1: parse_pnpm_workspace_patterns ───────────────────────

    #[test]
    fn test_parse_pnpm_basic() {
        let yaml = "packages:\n  - packages/*";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_multiple_patterns() {
        let yaml = "packages:\n  - packages/*\n  - apps/*\n  - tools/*";
        assert_eq!(
            parse_pnpm_workspace_patterns(yaml),
            vec!["packages/*", "apps/*", "tools/*"]
        );
    }

    #[test]
    fn test_parse_pnpm_quoted_patterns() {
        let yaml = "packages:\n  - 'packages/*'\n  - \"apps/*\"";
        assert_eq!(
            parse_pnpm_workspace_patterns(yaml),
            vec!["packages/*", "apps/*"]
        );
    }

    #[test]
    fn test_parse_pnpm_comments_interspersed() {
        let yaml = "packages:\n  # workspace packages\n  - packages/*\n  # apps\n  - apps/*";
        assert_eq!(
            parse_pnpm_workspace_patterns(yaml),
            vec!["packages/*", "apps/*"]
        );
    }

    #[test]
    fn test_parse_pnpm_empty_content() {
        assert!(parse_pnpm_workspace_patterns("").is_empty());
    }

    #[test]
    fn test_parse_pnpm_no_packages_key() {
        let yaml = "name: my-project\nversion: 1.0.0";
        assert!(parse_pnpm_workspace_patterns(yaml).is_empty());
    }

    #[test]
    fn test_parse_pnpm_stops_at_next_section() {
        let yaml = "packages:\n  - packages/*\ncatalog:\n  lodash: 4.17.21";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_indented_key() {
        // The parser uses `trimmed == "packages:"` so leading spaces should match
        let yaml = "  packages:\n  - packages/*";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_dash_only_line() {
        let yaml = "packages:\n  -\n  - packages/*";
        // A bare "-" with no value should be skipped (empty after trim)
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_glob_star_star() {
        let yaml = "packages:\n  - packages/**";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/**"]);
    }

    // ── Group 2: workspace detection + file discovery ────────────────

    #[tokio::test]
    async fn test_detect_workspaces_npm_array() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"workspaces": ["packages/*"]}"#)
            .await
            .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Npm));
        assert_eq!(config.patterns, vec!["packages/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_npm_object() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"workspaces": {"packages": ["packages/*", "apps/*"]}}"#,
        )
        .await
        .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Npm));
        assert_eq!(config.patterns, vec!["packages/*", "apps/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_pnpm() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name": "root"}"#).await.unwrap();
        let pnpm = dir.path().join("pnpm-workspace.yaml");
        fs::write(&pnpm, "packages:\n  - packages/*")
            .await
            .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Pnpm));
        assert_eq!(config.patterns, vec!["packages/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_pnpm_with_workspaces_field() {
        // When both pnpm-workspace.yaml AND "workspaces" in package.json
        // exist, pnpm should take priority
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"name": "root", "workspaces": ["packages/*"]}"#,
        )
        .await
        .unwrap();
        let pnpm = dir.path().join("pnpm-workspace.yaml");
        fs::write(&pnpm, "packages:\n  - workspaces/*")
            .await
            .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Pnpm));
        // Should use pnpm-workspace.yaml patterns, not package.json workspaces
        assert_eq!(config.patterns, vec!["workspaces/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_none() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name": "root"}"#).await.unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::None));
        assert!(config.patterns.is_empty());
    }

    #[tokio::test]
    async fn test_detect_workspaces_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, "not valid json!!!").await.unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::None));
    }

    #[tokio::test]
    async fn test_detect_workspaces_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("nonexistent.json");
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::None));
    }

    #[tokio::test]
    async fn test_find_no_root_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert!(result.files.is_empty());
    }

    #[tokio::test]
    async fn test_find_root_only() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].is_root);
    }

    #[tokio::test]
    async fn test_find_npm_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"]}"#,
        )
        .await
        .unwrap();
        let pkg_a = dir.path().join("packages").join("a");
        fs::create_dir_all(&pkg_a).await.unwrap();
        fs::write(pkg_a.join("package.json"), r#"{"name":"a"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert!(matches!(result.workspace_type, WorkspaceType::Npm));
        // root + workspace member
        assert_eq!(result.files.len(), 2);
        assert!(result.files[0].is_root);
        assert!(result.files[1].is_workspace);
    }

    #[tokio::test]
    async fn test_find_pnpm_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*",
        )
        .await
        .unwrap();
        let pkg_a = dir.path().join("packages").join("a");
        fs::create_dir_all(&pkg_a).await.unwrap();
        fs::write(pkg_a.join("package.json"), r#"{"name":"a"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert!(matches!(result.workspace_type, WorkspaceType::Pnpm));
        // find_package_json_files still returns all files;
        // filtering for pnpm is done by the caller (setup command)
        assert_eq!(result.files.len(), 2);
        assert!(result.files[0].is_root);
        assert!(result.files[1].is_workspace);
    }

    #[tokio::test]
    async fn test_find_nested_skips_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        let nm = dir.path().join("node_modules").join("lodash");
        fs::create_dir_all(&nm).await.unwrap();
        fs::write(nm.join("package.json"), r#"{"name":"lodash"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        // Only root, node_modules should be skipped
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].is_root);
    }

    #[tokio::test]
    async fn test_find_nested_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        // Create deeply nested package.json at depth 7 (> limit of 5)
        let mut deep = dir.path().to_path_buf();
        for i in 0..7 {
            deep = deep.join(format!("level{}", i));
        }
        fs::create_dir_all(&deep).await.unwrap();
        fs::write(deep.join("package.json"), r#"{"name":"deep"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        // Only root (the deep one exceeds depth limit)
        assert_eq!(result.files.len(), 1);
    }

    #[tokio::test]
    async fn test_find_workspace_double_glob() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["apps/**"]}"#,
        )
        .await
        .unwrap();
        let nested = dir.path().join("apps").join("web").join("client");
        fs::create_dir_all(&nested).await.unwrap();
        fs::write(nested.join("package.json"), r#"{"name":"client"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        // root + recursively found workspace member
        assert!(result.files.len() >= 2);
    }

    #[tokio::test]
    async fn test_find_workspace_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/core"]}"#,
        )
        .await
        .unwrap();
        let core = dir.path().join("packages").join("core");
        fs::create_dir_all(&core).await.unwrap();
        fs::write(core.join("package.json"), r#"{"name":"core"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert_eq!(result.files.len(), 2);
    }
}
