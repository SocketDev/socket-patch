/// The command to run for applying patches via socket CLI.
const SOCKET_PATCH_COMMAND: &str = "npx @socketsecurity/socket-patch apply --silent --ecosystems npm";

/// Legacy command patterns to detect existing configurations.
const LEGACY_PATCH_PATTERNS: &[&str] = &[
    "socket-patch apply",
    "npx @socketsecurity/socket-patch apply",
    "socket patch apply",
];

/// Status of postinstall script configuration.
#[derive(Debug, Clone)]
pub struct PostinstallStatus {
    pub configured: bool,
    pub current_script: String,
    pub needs_update: bool,
}

/// Check if a postinstall script is properly configured for socket-patch.
pub fn is_postinstall_configured(package_json: &serde_json::Value) -> PostinstallStatus {
    let current_script = package_json
        .get("scripts")
        .and_then(|s| s.get("postinstall"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let configured = LEGACY_PATCH_PATTERNS
        .iter()
        .any(|pattern| current_script.contains(pattern));

    PostinstallStatus {
        configured,
        current_script,
        needs_update: !configured,
    }
}

/// Check if a postinstall script string is configured for socket-patch.
pub fn is_postinstall_configured_str(content: &str) -> PostinstallStatus {
    match serde_json::from_str::<serde_json::Value>(content) {
        Ok(val) => is_postinstall_configured(&val),
        Err(_) => PostinstallStatus {
            configured: false,
            current_script: String::new(),
            needs_update: true,
        },
    }
}

/// Generate an updated postinstall script that includes socket-patch.
pub fn generate_updated_postinstall(current_postinstall: &str) -> String {
    let trimmed = current_postinstall.trim();

    // If empty, just add the socket-patch command.
    if trimmed.is_empty() {
        return SOCKET_PATCH_COMMAND.to_string();
    }

    // If any socket-patch variant is already present, return unchanged.
    let already_configured = LEGACY_PATCH_PATTERNS
        .iter()
        .any(|pattern| trimmed.contains(pattern));
    if already_configured {
        return trimmed.to_string();
    }

    // Prepend socket-patch command so it runs first.
    format!("{SOCKET_PATCH_COMMAND} && {trimmed}")
}

/// Update a package.json Value with the new postinstall script.
/// Returns (modified, new_script).
pub fn update_package_json_object(
    package_json: &mut serde_json::Value,
) -> (bool, String) {
    let status = is_postinstall_configured(package_json);

    if !status.needs_update {
        return (false, status.current_script);
    }

    let new_postinstall = generate_updated_postinstall(&status.current_script);

    // Ensure scripts object exists
    if package_json.get("scripts").is_none() {
        package_json["scripts"] = serde_json::json!({});
    }

    package_json["scripts"]["postinstall"] =
        serde_json::Value::String(new_postinstall.clone());

    (true, new_postinstall)
}

/// Parse package.json content and update it with socket-patch postinstall.
/// Returns (modified, new_content, old_script, new_script).
pub fn update_package_json_content(
    content: &str,
) -> Result<(bool, String, String, String), String> {
    let mut package_json: serde_json::Value =
        serde_json::from_str(content).map_err(|e| format!("Invalid package.json: {e}"))?;

    let status = is_postinstall_configured(&package_json);

    if !status.needs_update {
        return Ok((
            false,
            content.to_string(),
            status.current_script.clone(),
            status.current_script,
        ));
    }

    let (_, new_script) = update_package_json_object(&mut package_json);
    let new_content = serde_json::to_string_pretty(&package_json).unwrap() + "\n";

    Ok((true, new_content, status.current_script, new_script))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_configured() {
        let pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": {
                "build": "tsc"
            }
        });
        let status = is_postinstall_configured(&pkg);
        assert!(!status.configured);
        assert!(status.needs_update);
    }

    #[test]
    fn test_already_configured() {
        let pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": {
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
            }
        });
        let status = is_postinstall_configured(&pkg);
        assert!(status.configured);
        assert!(!status.needs_update);
    }

    #[test]
    fn test_generate_empty() {
        assert_eq!(
            generate_updated_postinstall(""),
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
        );
    }

    #[test]
    fn test_generate_prepend() {
        assert_eq!(
            generate_updated_postinstall("echo done"),
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm && echo done"
        );
    }

    #[test]
    fn test_generate_already_configured() {
        let current = "socket-patch apply && echo done";
        assert_eq!(generate_updated_postinstall(current), current);
    }

    // ── Group 4: expanded edge cases ─────────────────────────────────

    #[test]
    fn test_is_postinstall_configured_str_invalid_json() {
        let status = is_postinstall_configured_str("not json");
        assert!(!status.configured);
        assert!(status.needs_update);
    }

    #[test]
    fn test_is_postinstall_configured_str_legacy_npx_pattern() {
        let content = r#"{"scripts":{"postinstall":"npx @socketsecurity/socket-patch apply --silent"}}"#;
        let status = is_postinstall_configured_str(content);
        // "npx @socketsecurity/socket-patch apply" contains "socket-patch apply"
        assert!(status.configured);
        assert!(!status.needs_update);
    }

    #[test]
    fn test_is_postinstall_configured_str_socket_dash_patch() {
        let content =
            r#"{"scripts":{"postinstall":"socket-patch apply --silent --ecosystems npm"}}"#;
        let status = is_postinstall_configured_str(content);
        assert!(status.configured);
        assert!(!status.needs_update);
    }

    #[test]
    fn test_is_postinstall_configured_no_scripts() {
        let pkg: serde_json::Value = serde_json::json!({"name": "test"});
        let status = is_postinstall_configured(&pkg);
        assert!(!status.configured);
        assert!(status.current_script.is_empty());
    }

    #[test]
    fn test_is_postinstall_configured_no_postinstall() {
        let pkg: serde_json::Value = serde_json::json!({
            "scripts": {"build": "tsc"}
        });
        let status = is_postinstall_configured(&pkg);
        assert!(!status.configured);
        assert!(status.current_script.is_empty());
    }

    #[test]
    fn test_update_object_creates_scripts() {
        let mut pkg: serde_json::Value = serde_json::json!({"name": "test"});
        let (modified, new_script) = update_package_json_object(&mut pkg);
        assert!(modified);
        assert!(new_script.contains("socket-patch apply"));
        assert!(pkg.get("scripts").is_some());
        assert!(pkg["scripts"]["postinstall"].is_string());
    }

    #[test]
    fn test_update_object_noop_when_configured() {
        let mut pkg: serde_json::Value = serde_json::json!({
            "scripts": {
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
            }
        });
        let (modified, existing) = update_package_json_object(&mut pkg);
        assert!(!modified);
        assert!(existing.contains("socket-patch apply"));
    }

    #[test]
    fn test_update_content_roundtrip_no_scripts() {
        let content = r#"{"name": "test"}"#;
        let (modified, new_content, old_script, new_script) =
            update_package_json_content(content).unwrap();
        assert!(modified);
        assert!(old_script.is_empty());
        assert!(new_script.contains("socket-patch apply"));
        // new_content should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&new_content).unwrap();
        assert!(parsed["scripts"]["postinstall"].is_string());
    }

    #[test]
    fn test_update_content_already_configured() {
        let content = r#"{"scripts":{"postinstall":"npx @socketsecurity/socket-patch apply --silent --ecosystems npm"}}"#;
        let (modified, _new_content, _old, _new) =
            update_package_json_content(content).unwrap();
        assert!(!modified);
    }

    #[test]
    fn test_update_content_invalid_json() {
        let result = update_package_json_content("not json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid package.json"));
    }

    #[test]
    fn test_generate_whitespace_only() {
        // Whitespace-only string should be treated as empty after trim
        let result = generate_updated_postinstall("  \t  ");
        assert_eq!(result, "npx @socketsecurity/socket-patch apply --silent --ecosystems npm");
    }
}
