use std::path::Path;
use tokio::fs;

use super::detect::{is_postinstall_configured_str, update_package_json_content};

/// Result of updating a single package.json.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub path: String,
    pub status: UpdateStatus,
    pub old_script: String,
    pub new_script: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    Updated,
    AlreadyConfigured,
    Error,
}

/// Update a single package.json file with socket-patch postinstall script.
pub async fn update_package_json(
    package_json_path: &Path,
    dry_run: bool,
) -> UpdateResult {
    let path_str = package_json_path.display().to_string();

    let content = match fs::read_to_string(package_json_path).await {
        Ok(c) => c,
        Err(e) => {
            return UpdateResult {
                path: path_str,
                status: UpdateStatus::Error,
                old_script: String::new(),
                new_script: String::new(),
                error: Some(e.to_string()),
            };
        }
    };

    let status = is_postinstall_configured_str(&content);
    if !status.needs_update {
        return UpdateResult {
            path: path_str,
            status: UpdateStatus::AlreadyConfigured,
            old_script: status.current_script.clone(),
            new_script: status.current_script,
            error: None,
        };
    }

    match update_package_json_content(&content) {
        Ok((modified, new_content, old_script, new_script)) => {
            if !modified {
                return UpdateResult {
                    path: path_str,
                    status: UpdateStatus::AlreadyConfigured,
                    old_script,
                    new_script,
                    error: None,
                };
            }

            if !dry_run {
                if let Err(e) = fs::write(package_json_path, &new_content).await {
                    return UpdateResult {
                        path: path_str,
                        status: UpdateStatus::Error,
                        old_script,
                        new_script,
                        error: Some(e.to_string()),
                    };
                }
            }

            UpdateResult {
                path: path_str,
                status: UpdateStatus::Updated,
                old_script,
                new_script,
                error: None,
            }
        }
        Err(e) => UpdateResult {
            path: path_str,
            status: UpdateStatus::Error,
            old_script: String::new(),
            new_script: String::new(),
            error: Some(e),
        },
    }
}

/// Update multiple package.json files.
pub async fn update_multiple_package_jsons(
    paths: &[&Path],
    dry_run: bool,
) -> Vec<UpdateResult> {
    let mut results = Vec::new();
    for path in paths {
        let result = update_package_json(path, dry_run).await;
        results.push(result);
    }
    results
}
