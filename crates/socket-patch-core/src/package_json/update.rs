use std::path::Path;
use tokio::fs;

use super::detect::{is_setup_configured_str, update_package_json_content, PackageManager};

/// Result of updating a single package.json.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub path: String,
    pub status: UpdateStatus,
    pub old_script: String,
    pub new_script: String,
    pub old_dependencies_script: String,
    pub new_dependencies_script: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    Updated,
    AlreadyConfigured,
    Error,
}

/// Update a single package.json file with socket-patch lifecycle scripts.
pub async fn update_package_json(
    package_json_path: &Path,
    dry_run: bool,
    pm: PackageManager,
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
                old_dependencies_script: String::new(),
                new_dependencies_script: String::new(),
                error: Some(e.to_string()),
            };
        }
    };

    let status = is_setup_configured_str(&content);
    if !status.needs_update {
        return UpdateResult {
            path: path_str,
            status: UpdateStatus::AlreadyConfigured,
            old_script: status.postinstall_script.clone(),
            new_script: status.postinstall_script,
            old_dependencies_script: status.dependencies_script.clone(),
            new_dependencies_script: status.dependencies_script,
            error: None,
        };
    }

    match update_package_json_content(&content, pm) {
        Ok((modified, new_content, old_pi, new_pi, old_dep, new_dep)) => {
            if !modified {
                return UpdateResult {
                    path: path_str,
                    status: UpdateStatus::AlreadyConfigured,
                    old_script: old_pi,
                    new_script: new_pi,
                    old_dependencies_script: old_dep,
                    new_dependencies_script: new_dep,
                    error: None,
                };
            }

            if !dry_run {
                if let Err(e) = fs::write(package_json_path, &new_content).await {
                    return UpdateResult {
                        path: path_str,
                        status: UpdateStatus::Error,
                        old_script: old_pi,
                        new_script: new_pi,
                        old_dependencies_script: old_dep,
                        new_dependencies_script: new_dep,
                        error: Some(e.to_string()),
                    };
                }
            }

            UpdateResult {
                path: path_str,
                status: UpdateStatus::Updated,
                old_script: old_pi,
                new_script: new_pi,
                old_dependencies_script: old_dep,
                new_dependencies_script: new_dep,
                error: None,
            }
        }
        Err(e) => UpdateResult {
            path: path_str,
            status: UpdateStatus::Error,
            old_script: String::new(),
            new_script: String::new(),
            old_dependencies_script: String::new(),
            new_dependencies_script: String::new(),
            error: Some(e),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_update_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent.json");
        let result = update_package_json(&missing, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Error);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_update_already_configured() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"name":"test","scripts":{"postinstall":"npx @socketsecurity/socket-patch apply --silent --ecosystems npm","dependencies":"npx @socketsecurity/socket-patch apply --silent --ecosystems npm"}}"#,
        )
        .await
        .unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::AlreadyConfigured);
    }

    #[tokio::test]
    async fn test_update_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let original = r#"{"name":"test","scripts":{"build":"tsc"}}"#;
        fs::write(&pkg, original).await.unwrap();
        let result = update_package_json(&pkg, true, PackageManager::Npm).await;
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
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(content.contains("npx @socketsecurity/socket-patch apply"));
        assert!(content.contains("postinstall"));
        assert!(content.contains("dependencies"));
    }

    #[tokio::test]
    async fn test_update_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, "not json!!!").await.unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Error);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_update_no_scripts_key() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x"}"#).await.unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(content.contains("postinstall"));
        assert!(content.contains("dependencies"));
        assert!(content.contains("npx @socketsecurity/socket-patch apply"));
    }

    #[tokio::test]
    async fn test_update_pnpm() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x"}"#).await.unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Pnpm).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(content.contains("pnpm dlx @socketsecurity/socket-patch apply"));
    }

    #[tokio::test]
    async fn test_update_adds_dependencies_when_postinstall_exists() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"name":"test","scripts":{"postinstall":"npx @socketsecurity/socket-patch apply --silent --ecosystems npm"}}"#,
        )
        .await
        .unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(content.contains("dependencies"));
    }

    /// Writing back the user's package.json must not reorder their existing
    /// keys. Without `serde_json/preserve_order` the value map is sorted
    /// alphabetically, so a file like `{"version":..,"name":..}` would be
    /// rewritten as `{"name":..,"version":..}` — a destructive, noisy diff
    /// over something the tool only meant to append two scripts to.
    #[tokio::test]
    async fn test_update_preserves_top_level_key_order() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        // Deliberately non-alphabetical key order.
        fs::write(
            &pkg,
            r#"{"version":"1.0.0","name":"x","private":true,"scripts":{"build":"tsc"}}"#,
        )
        .await
        .unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Updated);

        let content = fs::read_to_string(&pkg).await.unwrap();
        let pos_version = content.find("\"version\"").unwrap();
        let pos_name = content.find("\"name\"").unwrap();
        let pos_private = content.find("\"private\"").unwrap();
        let pos_scripts = content.find("\"scripts\"").unwrap();
        assert!(
            pos_version < pos_name && pos_name < pos_private && pos_private < pos_scripts,
            "original top-level key order must be preserved, got:\n{content}"
        );
    }

    /// The pre-existing `build` script (and its position) must survive an
    /// update that only appends the lifecycle scripts.
    #[tokio::test]
    async fn test_update_preserves_existing_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"name":"x","scripts":{"build":"tsc","test":"jest"}}"#,
        )
        .await
        .unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Updated);

        let parsed: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&pkg).await.unwrap()).unwrap();
        assert_eq!(parsed["scripts"]["build"], "tsc");
        assert_eq!(parsed["scripts"]["test"], "jest");
        assert!(parsed["scripts"]["postinstall"].is_string());
        assert!(parsed["scripts"]["dependencies"].is_string());
    }

    /// Running setup twice must be idempotent: the second run reports
    /// `AlreadyConfigured` and leaves the file byte-for-byte unchanged (no
    /// duplicated `socket-patch apply` commands).
    #[tokio::test]
    async fn test_update_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();

        let r1 = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(r1.status, UpdateStatus::Updated);
        let after_first = fs::read_to_string(&pkg).await.unwrap();

        let r2 = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(r2.status, UpdateStatus::AlreadyConfigured);
        let after_second = fs::read_to_string(&pkg).await.unwrap();

        assert_eq!(after_first, after_second);
        assert_eq!(after_first.matches("socket-patch apply").count(), 2);
    }

    /// Valid JSON whose root is not an object cannot hold lifecycle scripts;
    /// it must surface an error rather than panicking or silently succeeding.
    #[tokio::test]
    async fn test_update_non_object_root_errors() {
        let dir = tempfile::tempdir().unwrap();
        for (i, body) in ["[1,2,3]", "42", "\"hi\"", "true", "null"]
            .iter()
            .enumerate()
        {
            let pkg = dir.path().join(format!("pkg{i}.json"));
            fs::write(&pkg, body).await.unwrap();
            let result = update_package_json(&pkg, false, PackageManager::Npm).await;
            assert_eq!(result.status, UpdateStatus::Error, "body={body}");
            assert!(result.error.is_some(), "body={body}");
        }
    }

    /// A present-but-non-object `scripts` is malformed; refuse to clobber it.
    #[tokio::test]
    async fn test_update_non_object_scripts_errors_and_leaves_file() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let original = r#"{"name":"x","scripts":"build"}"#;
        fs::write(&pkg, original).await.unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Error);
        // File must be left untouched.
        assert_eq!(fs::read_to_string(&pkg).await.unwrap(), original);
    }

    /// An empty file is invalid JSON and must error without writing.
    #[tokio::test]
    async fn test_update_empty_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, "").await.unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Error);
        assert!(result.error.is_some());
    }

    /// Dry-run on a file that needs updating reports `Updated` but must not
    /// touch the bytes on disk — the consumer relies on this for its preview.
    #[tokio::test]
    async fn test_update_dry_run_reports_updated_without_writing_scripts() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let original = r#"{"name":"x","scripts":{"postinstall":"echo hi"}}"#;
        fs::write(&pkg, original).await.unwrap();
        let result = update_package_json(&pkg, true, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        // old_script reflects the existing script; new_script the prepended one.
        assert_eq!(result.old_script, "echo hi");
        assert!(result.new_script.contains("socket-patch apply"));
        assert!(result.new_script.contains("echo hi"));
        assert_eq!(fs::read_to_string(&pkg).await.unwrap(), original);
    }
}
