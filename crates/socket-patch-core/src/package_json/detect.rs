/// The command to run for applying patches via socket CLI.
const SOCKET_PATCH_COMMAND: &str = "socket patch apply --silent --ecosystems npm";

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
                "postinstall": "socket patch apply --silent --ecosystems npm"
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
            "socket patch apply --silent --ecosystems npm"
        );
    }

    #[test]
    fn test_generate_prepend() {
        assert_eq!(
            generate_updated_postinstall("echo done"),
            "socket patch apply --silent --ecosystems npm && echo done"
        );
    }

    #[test]
    fn test_generate_already_configured() {
        let current = "socket-patch apply && echo done";
        assert_eq!(generate_updated_postinstall(current), current);
    }
}
