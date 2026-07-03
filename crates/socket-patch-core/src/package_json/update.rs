use std::path::Path;
use tokio::fs;

use super::detect::{remove_package_json_content, update_package_json_content, PackageManager};
use crate::utils::fs::atomic_write_bytes;

/// Result of updating a single package.json.
#[derive(Debug, Clone)]
pub struct UpdateResult {
    pub path: String,
    pub status: UpdateStatus,
    /// Previous `postinstall` script (empty if absent).
    pub old_script: String,
    /// New `postinstall` script.
    pub new_script: String,
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
                error: Some(e.to_string()),
            };
        }
    };

    match update_package_json_content(&content, pm) {
        Ok((modified, new_content, old_pi, new_pi, _, _)) => {
            if modified && !dry_run {
                if let Err(e) = atomic_write_bytes(package_json_path, new_content.as_bytes()).await
                {
                    return UpdateResult {
                        path: path_str,
                        status: UpdateStatus::Error,
                        old_script: old_pi,
                        new_script: new_pi,
                        error: Some(e.to_string()),
                    };
                }
            }

            UpdateResult {
                path: path_str,
                status: if modified {
                    UpdateStatus::Updated
                } else {
                    UpdateStatus::AlreadyConfigured
                },
                old_script: old_pi,
                new_script: new_pi,
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

/// Result of removing socket-patch from a single package.json.
#[derive(Debug, Clone)]
pub struct RemoveResult {
    pub path: String,
    pub status: RemoveStatus,
    /// Previous `postinstall` script (empty if absent).
    pub old_script: String,
    /// New `postinstall` value: `None` means the key was deleted.
    pub new_script: Option<String>,
    pub old_dependencies_script: String,
    pub new_dependencies_script: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RemoveStatus {
    /// socket-patch was present and has been (or would be) removed.
    Removed,
    /// Nothing to remove — the file is not configured for socket-patch.
    NotConfigured,
    Error,
}

/// Remove socket-patch lifecycle scripts from a single package.json file.
///
/// Mirrors [`update_package_json`] but in reverse. Needs no [`PackageManager`]:
/// it strips any known socket-patch pattern regardless of how it was written.
pub async fn remove_package_json(package_json_path: &Path, dry_run: bool) -> RemoveResult {
    let path_str = package_json_path.display().to_string();

    let content = match fs::read_to_string(package_json_path).await {
        Ok(c) => c,
        Err(e) => {
            return RemoveResult {
                path: path_str,
                status: RemoveStatus::Error,
                old_script: String::new(),
                new_script: None,
                old_dependencies_script: String::new(),
                new_dependencies_script: None,
                error: Some(e.to_string()),
            };
        }
    };

    match remove_package_json_content(&content) {
        Ok((modified, new_content, status)) => {
            if modified && !dry_run {
                if let Err(e) = atomic_write_bytes(package_json_path, new_content.as_bytes()).await
                {
                    return RemoveResult {
                        path: path_str,
                        status: RemoveStatus::Error,
                        old_script: status.old_postinstall,
                        new_script: status.new_postinstall,
                        old_dependencies_script: status.old_dependencies,
                        new_dependencies_script: status.new_dependencies,
                        error: Some(e.to_string()),
                    };
                }
            }

            RemoveResult {
                path: path_str,
                status: if modified {
                    RemoveStatus::Removed
                } else {
                    RemoveStatus::NotConfigured
                },
                old_script: status.old_postinstall,
                new_script: status.new_postinstall,
                old_dependencies_script: status.old_dependencies,
                new_dependencies_script: status.new_dependencies,
                error: None,
            }
        }
        Err(e) => RemoveResult {
            path: path_str,
            status: RemoveStatus::Error,
            old_script: String::new(),
            new_script: None,
            old_dependencies_script: String::new(),
            new_dependencies_script: None,
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

    /// npm and Node tolerate (and strip) a UTF-8 BOM in package.json — files
    /// saved by Windows editors commonly carry one. serde_json does not, so
    /// without stripping it a perfectly npm-valid manifest errors out with
    /// "Invalid package.json" instead of being configured.
    #[tokio::test]
    async fn test_update_tolerates_utf8_bom() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            "\u{feff}{\"name\":\"x\",\"scripts\":{\"build\":\"tsc\"}}",
        )
        .await
        .unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(
            result.status,
            UpdateStatus::Updated,
            "BOM'd package.json is valid for npm and must be updatable, got error: {:?}",
            result.error
        );
        let content = fs::read_to_string(&pkg).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["scripts"]["postinstall"].is_string());
        assert!(parsed["scripts"]["dependencies"].is_string());
        assert_eq!(parsed["scripts"]["build"], "tsc");
    }

    /// A BOM'd file that is already fully configured must report
    /// `AlreadyConfigured` (and stay untouched), not `Error`.
    #[tokio::test]
    async fn test_update_bom_already_configured() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let original = "\u{feff}{\"scripts\":{\"postinstall\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\",\"dependencies\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\"}}";
        fs::write(&pkg, original).await.unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::AlreadyConfigured);
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

    /// After a successful (non-dry-run) write the staged temp file must be
    /// renamed into place, never left behind. A leaked `.socket-stage-*`
    /// sibling would signal the atomic write didn't complete its rename.
    async fn count_stage_litter(dir: &Path) -> usize {
        let mut rd = fs::read_dir(dir).await.unwrap();
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
    async fn test_update_atomic_write_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();
        let result = update_package_json(&pkg, false, PackageManager::Npm).await;
        assert_eq!(result.status, UpdateStatus::Updated);
        // The write must have gone through stage+rename and cleaned up.
        assert_eq!(count_stage_litter(dir.path()).await, 0);
        // And produced valid, fully-written JSON (not a truncated stage).
        let content = fs::read_to_string(&pkg).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["scripts"]["postinstall"].is_string());
        assert!(parsed["scripts"]["dependencies"].is_string());
    }

    #[tokio::test]
    async fn test_remove_atomic_write_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();
        update_package_json(&pkg, false, PackageManager::Npm).await;

        let result = remove_package_json(&pkg, false).await;
        assert_eq!(result.status, RemoveStatus::Removed);
        assert_eq!(count_stage_litter(dir.path()).await, 0);
        let content = fs::read_to_string(&pkg).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["scripts"]["build"], "tsc");
        assert!(!content.contains("socket-patch"));
    }

    /// A dry-run must never create a stage file either — it does no I/O at all.
    #[tokio::test]
    async fn test_update_dry_run_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();
        update_package_json(&pkg, true, PackageManager::Npm).await;
        assert_eq!(count_stage_litter(dir.path()).await, 0);
    }

    // ── remove_package_json ─────────────────────────────────────────

    #[tokio::test]
    async fn test_remove_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nonexistent.json");
        let result = remove_package_json(&missing, false).await;
        assert_eq!(result.status, RemoveStatus::Error);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_remove_not_configured() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();
        let result = remove_package_json(&pkg, false).await;
        assert_eq!(result.status, RemoveStatus::NotConfigured);
    }

    #[tokio::test]
    async fn test_remove_writes_and_strips_socket_patch() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        // Configure first, then remove.
        fs::write(&pkg, r#"{"name":"x","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();
        update_package_json(&pkg, false, PackageManager::Npm).await;

        let result = remove_package_json(&pkg, false).await;
        assert_eq!(result.status, RemoveStatus::Removed);
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(!content.contains("socket-patch"));
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["scripts"]["build"], "tsc");
    }

    #[tokio::test]
    async fn test_remove_dry_run_does_not_write() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let original =
            r#"{"name":"x","scripts":{"postinstall":"npx @socketsecurity/socket-patch apply"}}"#;
        fs::write(&pkg, original).await.unwrap();
        let result = remove_package_json(&pkg, true).await;
        assert_eq!(result.status, RemoveStatus::Removed);
        // File must be byte-identical after a dry-run.
        assert_eq!(fs::read_to_string(&pkg).await.unwrap(), original);
    }

    #[tokio::test]
    async fn test_remove_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name":"x","scripts":{"build":"tsc"}}"#)
            .await
            .unwrap();
        update_package_json(&pkg, false, PackageManager::Npm).await;

        let r1 = remove_package_json(&pkg, false).await;
        assert_eq!(r1.status, RemoveStatus::Removed);
        let r2 = remove_package_json(&pkg, false).await;
        assert_eq!(r2.status, RemoveStatus::NotConfigured);
    }

    /// Remove must tolerate a UTF-8 BOM the same way npm does: a BOM'd,
    /// configured package.json must be cleanly reverted, not rejected as
    /// invalid JSON.
    #[tokio::test]
    async fn test_remove_tolerates_utf8_bom() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            "\u{feff}{\"name\":\"x\",\"scripts\":{\"build\":\"tsc\",\"postinstall\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\"}}",
        )
        .await
        .unwrap();
        let result = remove_package_json(&pkg, false).await;
        assert_eq!(
            result.status,
            RemoveStatus::Removed,
            "BOM'd package.json is valid for npm and must be removable, got error: {:?}",
            result.error
        );
        let content = fs::read_to_string(&pkg).await.unwrap();
        assert!(!content.contains("socket-patch"));
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["scripts"]["build"], "tsc");
    }

    #[tokio::test]
    async fn test_remove_invalid_json_errors_and_leaves_file() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, "not json!!!").await.unwrap();
        let result = remove_package_json(&pkg, false).await;
        assert_eq!(result.status, RemoveStatus::Error);
        assert_eq!(fs::read_to_string(&pkg).await.unwrap(), "not json!!!");
    }
}
