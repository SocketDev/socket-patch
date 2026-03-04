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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_update_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent.json");
        let result = update_package_json(&missing, false).await;
        assert_eq!(result.status, UpdateStatus::Error);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_update_already_configured() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"name":"test","scripts":{"postinstall":"socket patch apply --silent --ecosystems npm"}}"#,
        )
        .await
        .unwrap();
        let result = update_package_json(&pkg, false).await;
        assert_eq!(result.status, UpdateStatus::AlreadyConfigured);
    }

    #[tokio::test]
    async fn test_update_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let original = r#"{"name":"test","scripts":{"build":"tsc"}}"#;
        fs::write(&pkg, original).await.unwrap();
        let result = update_package_json(&pkg, true).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        // File should remain unchanged
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert_eq!(content, original);
    }

    #[tokio::test]
    async fn test_update_writes_file() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"test","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();
        let result = update_package_json(&pkg, false).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(content.contains("socket patch apply"));
    }

    #[tokio::test]
    async fn test_update_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, "not json!!!").await.unwrap();
        let result = update_package_json(&pkg, false).await;
        assert_eq!(result.status, UpdateStatus::Error);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_update_no_scripts_key() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x"}"#).await.unwrap();
        let result = update_package_json(&pkg, false).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(content.contains("postinstall"));
        assert!(content.contains("socket patch apply"));
    }

    #[tokio::test]
    async fn test_update_multiple_mixed() {
        let dir = tempfile::tempdir().unwrap();

        let p1 = dir.path().join("a.json");
        fs::write(&p1, r#"{"name":"a"}"#).await.unwrap();

        let p2 = dir.path().join("b.json");
        fs::write(
            &p2,
            r#"{"name":"b","scripts":{"postinstall":"socket patch apply --silent --ecosystems npm"}}"#,
        )
        .await
        .unwrap();

        let p3 = dir.path().join("c.json");
        // Don't create p3 — file not found

        let paths: Vec<&Path> = vec![p1.as_path(), p2.as_path(), p3.as_path()];
        let results = update_multiple_package_jsons(&paths, false).await;
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].status, UpdateStatus::Updated);
        assert_eq!(results[1].status, UpdateStatus::AlreadyConfigured);
        assert_eq!(results[2].status, UpdateStatus::Error);
    }
}
