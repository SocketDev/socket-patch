/// Package manager type for selecting the correct command prefix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PackageManager {
    Npm,
    Pnpm,
}

/// Get the socket-patch apply command for the given package manager.
fn socket_patch_command(pm: PackageManager) -> &'static str {
    match pm {
        PackageManager::Npm => "npx @socketsecurity/socket-patch apply --silent --ecosystems npm",
        PackageManager::Pnpm => {
            "pnpm dlx @socketsecurity/socket-patch apply --silent --ecosystems npm"
        }
    }
}

/// Legacy command patterns to detect existing configurations.
const LEGACY_PATCH_PATTERNS: &[&str] = &[
    "socket-patch apply",
    "npx @socketsecurity/socket-patch apply",
    "socket patch apply",
];

/// Check if a script string contains any known socket-patch apply pattern.
fn script_is_configured(script: &str) -> bool {
    LEGACY_PATCH_PATTERNS
        .iter()
        .any(|pattern| script.contains(pattern))
}

/// Status of setup script configuration (both postinstall and dependencies).
#[derive(Debug, Clone)]
pub struct ScriptSetupStatus {
    pub postinstall_configured: bool,
    pub postinstall_script: String,
    pub dependencies_configured: bool,
    pub dependencies_script: String,
    pub needs_update: bool,
}

/// Check if package.json scripts are properly configured for socket-patch.
/// Checks both the postinstall and dependencies lifecycle scripts.
pub fn is_setup_configured(package_json: &serde_json::Value) -> ScriptSetupStatus {
    let scripts = package_json.get("scripts");

    let postinstall_script = scripts
        .and_then(|s| s.get("postinstall"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let postinstall_configured = script_is_configured(&postinstall_script);

    let dependencies_script = scripts
        .and_then(|s| s.get("dependencies"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let dependencies_configured = script_is_configured(&dependencies_script);

    ScriptSetupStatus {
        postinstall_configured,
        postinstall_script,
        dependencies_configured,
        dependencies_script,
        needs_update: !postinstall_configured || !dependencies_configured,
    }
}

/// Check if a package.json content string is properly configured.
pub fn is_setup_configured_str(content: &str) -> ScriptSetupStatus {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => is_setup_configured(&val),
        Err(_) => ScriptSetupStatus {
            postinstall_configured: false,
            postinstall_script: String::new(),
            dependencies_configured: false,
            dependencies_script: String::new(),
            needs_update: true,
        },
    }
}

/// Generate an updated script that includes the socket-patch apply command.
/// If already configured, returns unchanged. Otherwise prepends the command.
pub fn generate_updated_script(current_script: &str, pm: PackageManager) -> String {
    let command = socket_patch_command(pm);
    let trimmed = current_script.trim();

    // If empty, just add the socket-patch command.
    if trimmed.is_empty() {
        return command.to_string();
    }

    // If any socket-patch variant is already present, return unchanged.
    if script_is_configured(trimmed) {
        return trimmed.to_string();
    }

    // Prepend socket-patch command so it runs first.
    format!("{command} && {trimmed}")
}

/// Update a package.json Value with socket-patch in both postinstall and
/// dependencies scripts.
/// Returns (modified, new_postinstall, new_dependencies).
pub fn update_package_json_object(
    package_json: &mut serde_json::Value,
    pm: PackageManager,
) -> (bool, String, String) {
    let status = is_setup_configured(package_json);

    if !status.needs_update {
        return (
            false,
            status.postinstall_script,
            status.dependencies_script,
        );
    }

    // Ensure scripts object exists
    if package_json.get("scripts").is_none() {
        package_json["scripts"] = serde_json::json!({});
    }

    let mut modified = false;

    let new_postinstall = if !status.postinstall_configured {
        modified = true;
        let s = generate_updated_script(&status.postinstall_script, pm);
        package_json["scripts"]["postinstall"] = serde_json::Value::String(s.clone());
        s
    } else {
        status.postinstall_script
    };

    let new_dependencies = if !status.dependencies_configured {
        modified = true;
        let s = generate_updated_script(&status.dependencies_script, pm);
        package_json["scripts"]["dependencies"] = serde_json::Value::String(s.clone());
        s
    } else {
        status.dependencies_script
    };

    (modified, new_postinstall, new_dependencies)
}

/// Parse package.json content and update it with socket-patch scripts.
/// Returns (modified, new_content, old_postinstall, new_postinstall,
/// old_dependencies, new_dependencies).
pub fn update_package_json_content(
    content: &str,
    pm: PackageManager,
) -> Result<(bool, String, String, String, String, String), String> {
    let mut package_json: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid package.json: {e}"))?;

    let status = is_setup_configured(&package_json);

    if !status.needs_update {
        return Ok((
            false,
            content.to_string(),
            status.postinstall_script.clone(),
            status.postinstall_script,
            status.dependencies_script.clone(),
            status.dependencies_script,
        ));
    }

    let old_postinstall = status.postinstall_script.clone();
    let old_dependencies = status.dependencies_script.clone();

    let (_, new_postinstall, new_dependencies) =
        update_package_json_object(&mut package_json, pm);
    let new_content = serde_json::to_string_pretty(&package_json).unwrap() + "\n";

    Ok((
        true,
        new_content,
        old_postinstall,
        new_postinstall,
        old_dependencies,
        new_dependencies,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_setup_configured ─────────────────────────────────────────

    #[test]
    fn test_not_configured() {
        let pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": {
                "build": "tsc"
            }
        });
        let status = is_setup_configured(&pkg);
        assert!(!status.postinstall_configured);
        assert!(!status.dependencies_configured);
        assert!(status.needs_update);
    }

    #[test]
    fn test_postinstall_configured_dependencies_not() {
        let pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": {
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
            }
        });
        let status = is_setup_configured(&pkg);
        assert!(status.postinstall_configured);
        assert!(!status.dependencies_configured);
        assert!(status.needs_update);
    }

    #[test]
    fn test_both_configured() {
        let pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": {
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm",
                "dependencies": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
            }
        });
        let status = is_setup_configured(&pkg);
        assert!(status.postinstall_configured);
        assert!(status.dependencies_configured);
        assert!(!status.needs_update);
    }

    #[test]
    fn test_legacy_socket_patch_apply_recognized() {
        let pkg: serde_json::Value = serde_json::json!({
            "scripts": {
                "postinstall": "socket patch apply --silent --ecosystems npm",
                "dependencies": "socket-patch apply"
            }
        });
        let status = is_setup_configured(&pkg);
        assert!(status.postinstall_configured);
        assert!(status.dependencies_configured);
        assert!(!status.needs_update);
    }

    #[test]
    fn test_no_scripts() {
        let pkg: serde_json::Value = serde_json::json!({"name": "test"});
        let status = is_setup_configured(&pkg);
        assert!(!status.postinstall_configured);
        assert!(status.postinstall_script.is_empty());
        assert!(!status.dependencies_configured);
        assert!(status.dependencies_script.is_empty());
    }

    #[test]
    fn test_no_postinstall() {
        let pkg: serde_json::Value = serde_json::json!({
            "scripts": {"build": "tsc"}
        });
        let status = is_setup_configured(&pkg);
        assert!(!status.postinstall_configured);
        assert!(status.postinstall_script.is_empty());
    }

    // ── is_setup_configured_str ─────────────────────────────────────

    #[test]
    fn test_configured_str_invalid_json() {
        let status = is_setup_configured_str("not json");
        assert!(!status.postinstall_configured);
        assert!(status.needs_update);
    }

    #[test]
    fn test_configured_str_legacy_npx_pattern() {
        let content = r#"{"scripts":{"postinstall":"npx @socketsecurity/socket-patch apply --silent"}}"#;
        let status = is_setup_configured_str(content);
        assert!(status.postinstall_configured);
    }

    #[test]
    fn test_configured_str_socket_dash_patch() {
        let content =
            r#"{"scripts":{"postinstall":"socket-patch apply --silent --ecosystems npm"}}"#;
        let status = is_setup_configured_str(content);
        assert!(status.postinstall_configured);
    }

    #[test]
    fn test_configured_str_pnpm_dlx_pattern() {
        let content = r#"{"scripts":{"postinstall":"pnpm dlx @socketsecurity/socket-patch apply --silent --ecosystems npm"}}"#;
        let status = is_setup_configured_str(content);
        // "pnpm dlx @socketsecurity/socket-patch apply" contains "socket-patch apply"
        assert!(status.postinstall_configured);
    }

    // ── generate_updated_script ─────────────────────────────────────

    #[test]
    fn test_generate_empty_npm() {
        assert_eq!(
            generate_updated_script("", PackageManager::Npm),
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
        );
    }

    #[test]
    fn test_generate_empty_pnpm() {
        assert_eq!(
            generate_updated_script("", PackageManager::Pnpm),
            "pnpm dlx @socketsecurity/socket-patch apply --silent --ecosystems npm"
        );
    }

    #[test]
    fn test_generate_prepend_npm() {
        assert_eq!(
            generate_updated_script("echo done", PackageManager::Npm),
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm && echo done"
        );
    }

    #[test]
    fn test_generate_prepend_pnpm() {
        assert_eq!(
            generate_updated_script("echo done", PackageManager::Pnpm),
            "pnpm dlx @socketsecurity/socket-patch apply --silent --ecosystems npm && echo done"
        );
    }

    #[test]
    fn test_generate_already_configured() {
        let current = "socket-patch apply && echo done";
        assert_eq!(
            generate_updated_script(current, PackageManager::Npm),
            current
        );
    }

    #[test]
    fn test_generate_whitespace_only() {
        let result = generate_updated_script("  \t  ", PackageManager::Npm);
        assert_eq!(
            result,
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
        );
    }

    // ── update_package_json_object ──────────────────────────────────

    #[test]
    fn test_update_object_creates_scripts() {
        let mut pkg: serde_json::Value = serde_json::json!({"name": "test"});
        let (modified, new_postinstall, new_dependencies) =
            update_package_json_object(&mut pkg, PackageManager::Npm);
        assert!(modified);
        assert!(new_postinstall.contains("npx @socketsecurity/socket-patch apply"));
        assert!(new_dependencies.contains("npx @socketsecurity/socket-patch apply"));
        assert!(pkg.get("scripts").is_some());
        assert!(pkg["scripts"]["postinstall"].is_string());
        assert!(pkg["scripts"]["dependencies"].is_string());
    }

    #[test]
    fn test_update_object_creates_scripts_pnpm() {
        let mut pkg: serde_json::Value = serde_json::json!({"name": "test"});
        let (modified, new_postinstall, new_dependencies) =
            update_package_json_object(&mut pkg, PackageManager::Pnpm);
        assert!(modified);
        assert!(new_postinstall.contains("pnpm dlx @socketsecurity/socket-patch apply"));
        assert!(new_dependencies.contains("pnpm dlx @socketsecurity/socket-patch apply"));
    }

    #[test]
    fn test_update_object_noop_when_both_configured() {
        let mut pkg: serde_json::Value = serde_json::json!({
            "scripts": {
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm",
                "dependencies": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
            }
        });
        let (modified, _, _) = update_package_json_object(&mut pkg, PackageManager::Npm);
        assert!(!modified);
    }

    #[test]
    fn test_update_object_adds_dependencies_when_postinstall_exists() {
        let mut pkg: serde_json::Value = serde_json::json!({
            "scripts": {
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
            }
        });
        let (modified, _, new_dependencies) =
            update_package_json_object(&mut pkg, PackageManager::Npm);
        assert!(modified);
        assert!(new_dependencies.contains("npx @socketsecurity/socket-patch apply"));
        // postinstall should remain unchanged
        assert_eq!(
            pkg["scripts"]["postinstall"].as_str().unwrap(),
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
        );
    }

    // ── update_package_json_content ─────────────────────────────────

    #[test]
    fn test_update_content_roundtrip_no_scripts() {
        let content = r#"{"name": "test"}"#;
        let (modified, new_content, old_pi, new_pi, old_dep, new_dep) =
            update_package_json_content(content, PackageManager::Npm).unwrap();
        assert!(modified);
        assert!(old_pi.is_empty());
        assert!(new_pi.contains("npx @socketsecurity/socket-patch apply"));
        assert!(old_dep.is_empty());
        assert!(new_dep.contains("npx @socketsecurity/socket-patch apply"));
        let parsed: serde_json::Value = serde_json::from_str(&new_content).unwrap();
        assert!(parsed["scripts"]["postinstall"].is_string());
        assert!(parsed["scripts"]["dependencies"].is_string());
    }

    #[test]
    fn test_update_content_already_configured() {
        let content = r#"{"scripts":{"postinstall":"socket patch apply --silent --ecosystems npm","dependencies":"socket patch apply --silent --ecosystems npm"}}"#;
        let (modified, _, _, _, _, _) =
            update_package_json_content(content, PackageManager::Npm).unwrap();
        assert!(!modified);
    }

    #[test]
    fn test_update_content_invalid_json() {
        let result = update_package_json_content("not json", PackageManager::Npm);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid package.json"));
    }

    #[test]
    fn test_update_content_pnpm() {
        let content = r#"{"name": "test"}"#;
        let (modified, new_content, _, new_pi, _, new_dep) =
            update_package_json_content(content, PackageManager::Pnpm).unwrap();
        assert!(modified);
        assert!(new_pi.contains("pnpm dlx @socketsecurity/socket-patch apply"));
        assert!(new_dep.contains("pnpm dlx @socketsecurity/socket-patch apply"));
        let parsed: serde_json::Value = serde_json::from_str(&new_content).unwrap();
        assert!(parsed["scripts"]["postinstall"]
            .as_str()
            .unwrap()
            .contains("pnpm dlx"));
        assert!(parsed["scripts"]["dependencies"]
            .as_str()
            .unwrap()
            .contains("pnpm dlx"));
    }
}
