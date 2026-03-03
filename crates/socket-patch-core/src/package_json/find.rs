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

/// Find all package.json files, respecting workspace configurations.
pub async fn find_package_json_files(
    start_path: &Path,
) -> Vec<PackageJsonLocation> {
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

    results
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

    // Check for pnpm workspaces
    let dir = package_json_path.parent().unwrap_or(Path::new("."));
    let pnpm_workspace = dir.join("pnpm-workspace.yaml");
    if let Ok(yaml_content) = fs::read_to_string(&pnpm_workspace).await {
        let patterns = parse_pnpm_workspace_patterns(&yaml_content);
        return WorkspaceConfig {
            ws_type: WorkspaceType::Pnpm,
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
