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

/// Strip a leading UTF-8 BOM. npm and Node tolerate (and strip) a BOM in
/// package.json — files saved by Windows editors commonly carry one — but
/// serde_json rejects it, so every parse of user-supplied package.json content
/// must go through this first or npm-valid manifests error out.
fn strip_bom(content: &str) -> &str {
    content.strip_prefix('\u{feff}').unwrap_or(content)
}

/// Check if a package.json content string is properly configured.
pub fn is_setup_configured_str(content: &str) -> ScriptSetupStatus {
    match serde_json::from_str::<serde_json::Value>(strip_bom(content)) {
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
        return (false, status.postinstall_script, status.dependencies_script);
    }

    // We can only attach scripts to an object root. Anything else (array,
    // string, number, bool, null) cannot hold a "scripts" key, so indexing it
    // below would panic. Bail out as a no-op instead.
    if !package_json.is_object() {
        return (false, status.postinstall_script, status.dependencies_script);
    }

    // Ensure `scripts` exists *and* is an object. A present-but-non-object
    // `scripts` (e.g. a string or array) would otherwise panic when indexed.
    if !package_json
        .get("scripts")
        .map(serde_json::Value::is_object)
        .unwrap_or(false)
    {
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

/// Strip every socket-patch segment out of a single lifecycle script.
///
/// Scripts are joined with `" && "` (that is exactly how
/// [`generate_updated_script`] prepends the patch command), so splitting on
/// the same separator and dropping any segment that is a socket-patch invocation
/// reverses the setup edit, whether the command was added to an empty script
/// (`"<cmd>"`) or prepended to an existing one (`"<cmd> && build"`).
///
/// Returns `(changed, new_value)`:
/// - `(false, Some(original))` — no socket-patch segment found; leave as-is.
/// - `(true, Some(rest))` — patch segment(s) removed, other commands survive.
/// - `(true, None)` — the script was *only* socket-patch; the key should be
///   deleted entirely.
pub fn remove_socket_patch_from_script(script: &str) -> (bool, Option<String>) {
    let trimmed = script.trim();
    if trimmed.is_empty() {
        return (false, None);
    }

    let segments: Vec<&str> = trimmed.split(" && ").collect();

    // `changed` must reflect whether a *socket-patch* segment was removed — not
    // whether `kept` is merely shorter than `segments`. Filtering also drops
    // empty segments, so keying `changed` off `kept.len() != segments.len()`
    // would falsely report a removal for a patch-free script that merely
    // contained a stray empty segment (e.g. a double `" && "` separator),
    // violating this function's documented `(false, ..)`/`(true, ..)` contract.
    let had_patch = segments.iter().any(|s| script_is_configured(s.trim()));

    let kept: Vec<&str> = segments
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !script_is_configured(s))
        .collect();

    if !had_patch {
        // No socket-patch pattern present — leave the script as-is.
        return (false, Some(trimmed.to_string()));
    }

    if kept.is_empty() {
        (true, None)
    } else {
        (true, Some(kept.join(" && ")))
    }
}

/// Status of a remove operation on a single package.json object.
#[derive(Debug, Clone)]
pub struct ScriptRemoveStatus {
    pub modified: bool,
    pub old_postinstall: String,
    pub new_postinstall: Option<String>,
    pub old_dependencies: String,
    pub new_dependencies: Option<String>,
}

/// Remove socket-patch from both lifecycle scripts in a package.json object.
///
/// Full revert: an emptied `postinstall`/`dependencies` key is deleted, and if
/// `scripts` ends up empty the whole `scripts` key is dropped too — undoing
/// exactly what [`update_package_json_object`] added. Returns a
/// [`ScriptRemoveStatus`] describing what changed.
pub fn remove_package_json_object(package_json: &mut serde_json::Value) -> ScriptRemoveStatus {
    let read_script = |pj: &serde_json::Value, key: &str| -> String {
        pj.get("scripts")
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };

    let old_postinstall = read_script(package_json, "postinstall");
    let old_dependencies = read_script(package_json, "dependencies");

    let (pi_changed, new_postinstall) = remove_socket_patch_from_script(&old_postinstall);
    let (dep_changed, new_dependencies) = remove_socket_patch_from_script(&old_dependencies);

    // Only treat as modified when a socket-patch segment was actually present.
    let pi_had_patch = pi_changed && script_is_configured(&old_postinstall);
    let dep_had_patch = dep_changed && script_is_configured(&old_dependencies);
    let modified = pi_had_patch || dep_had_patch;

    if !modified {
        return ScriptRemoveStatus {
            modified: false,
            new_postinstall: Some(old_postinstall.clone()),
            old_postinstall,
            new_dependencies: Some(old_dependencies.clone()),
            old_dependencies,
        };
    }

    // We can only mutate scripts on an object root with an object `scripts`.
    // Anything else has nothing to remove and is handled by the no-op path
    // above (its scripts read as empty).
    if let Some(scripts) = package_json
        .get_mut("scripts")
        .and_then(|s| s.as_object_mut())
    {
        if pi_had_patch {
            match &new_postinstall {
                Some(s) => {
                    scripts.insert(
                        "postinstall".to_string(),
                        serde_json::Value::String(s.clone()),
                    );
                }
                None => {
                    scripts.remove("postinstall");
                }
            }
        }
        if dep_had_patch {
            match &new_dependencies {
                Some(s) => {
                    scripts.insert(
                        "dependencies".to_string(),
                        serde_json::Value::String(s.clone()),
                    );
                }
                None => {
                    scripts.remove("dependencies");
                }
            }
        }

        // If `scripts` is now empty, drop the key entirely for a clean revert.
        if scripts.is_empty() {
            if let Some(obj) = package_json.as_object_mut() {
                obj.remove("scripts");
            }
        }
    }

    ScriptRemoveStatus {
        modified,
        old_postinstall,
        new_postinstall,
        old_dependencies,
        new_dependencies,
    }
}

/// Parse package.json content and remove socket-patch lifecycle scripts.
/// Returns `(modified, new_content, status)`.
pub fn remove_package_json_content(
    content: &str,
) -> Result<(bool, String, ScriptRemoveStatus), String> {
    let mut package_json: serde_json::Value = serde_json::from_str(strip_bom(content))
        .map_err(|e| format!("Invalid package.json: {e}"))?;

    if !package_json.is_object() {
        return Err("Invalid package.json: root is not a JSON object".to_string());
    }

    // Refuse to touch a malformed (present but non-object) `scripts` value.
    if let Some(scripts) = package_json.get("scripts") {
        if !scripts.is_null() && !scripts.is_object() {
            return Err("Invalid package.json: \"scripts\" is not a JSON object".to_string());
        }
    }

    let status = remove_package_json_object(&mut package_json);

    if !status.modified {
        return Ok((false, content.to_string(), status));
    }

    let new_content = serde_json::to_string_pretty(&package_json).unwrap() + "\n";
    Ok((true, new_content, status))
}

/// Parse package.json content and update it with socket-patch scripts.
/// Returns (modified, new_content, old_postinstall, new_postinstall,
/// old_dependencies, new_dependencies).
pub fn update_package_json_content(
    content: &str,
    pm: PackageManager,
) -> Result<(bool, String, String, String, String, String), String> {
    let mut package_json: serde_json::Value = serde_json::from_str(strip_bom(content))
        .map_err(|e| format!("Invalid package.json: {e}"))?;

    // A package.json must be a JSON object; otherwise there is nowhere to add
    // lifecycle scripts.
    if !package_json.is_object() {
        return Err("Invalid package.json: root is not a JSON object".to_string());
    }

    // Refuse to clobber a malformed (present but non-object) `scripts` value.
    // `null` is treated as absent and replaced with a fresh object downstream.
    if let Some(scripts) = package_json.get("scripts") {
        if !scripts.is_null() && !scripts.is_object() {
            return Err("Invalid package.json: \"scripts\" is not a JSON object".to_string());
        }
    }

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

    let (_, new_postinstall, new_dependencies) = update_package_json_object(&mut package_json, pm);
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
    fn test_configured_str_utf8_bom() {
        // npm strips a leading BOM when reading package.json; a BOM'd,
        // configured manifest must read as configured, not as unparseable
        // (which would mis-report it as needing setup).
        let content = "\u{feff}{\"scripts\":{\"postinstall\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\",\"dependencies\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\"}}";
        let status = is_setup_configured_str(content);
        assert!(status.postinstall_configured);
        assert!(status.dependencies_configured);
        assert!(!status.needs_update);
    }

    #[test]
    fn test_configured_str_legacy_npx_pattern() {
        let content =
            r#"{"scripts":{"postinstall":"npx @socketsecurity/socket-patch apply --silent"}}"#;
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
    fn test_update_object_scripts_is_string_does_not_panic() {
        // Regression: a present-but-non-object `scripts` previously panicked
        // when indexed (`cannot access key "postinstall" in JSON string`).
        let mut pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": "build"
        });
        let (modified, _, _) = update_package_json_object(&mut pkg, PackageManager::Npm);
        // Root is an object but `scripts` is malformed; the object-level helper
        // replaces it rather than panicking.
        assert!(modified);
        assert!(pkg["scripts"]["postinstall"].is_string());
        assert!(pkg["scripts"]["dependencies"].is_string());
    }

    #[test]
    fn test_update_object_scripts_is_array_does_not_panic() {
        let mut pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": ["build"]
        });
        let (modified, _, _) = update_package_json_object(&mut pkg, PackageManager::Npm);
        assert!(modified);
        assert!(pkg["scripts"].is_object());
    }

    #[test]
    fn test_update_object_scripts_is_null() {
        // `null` scripts is treated as absent and replaced with an object.
        let mut pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": null
        });
        let (modified, _, _) = update_package_json_object(&mut pkg, PackageManager::Npm);
        assert!(modified);
        assert!(pkg["scripts"]["postinstall"].is_string());
    }

    #[test]
    fn test_update_object_non_object_root_is_noop() {
        // Regression: a non-object root previously panicked on `["scripts"] = ...`.
        let mut arr: serde_json::Value = serde_json::json!([1, 2, 3]);
        let (modified, _, _) = update_package_json_object(&mut arr, PackageManager::Npm);
        assert!(!modified);
        assert_eq!(arr, serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn test_update_content_non_object_root_errors() {
        // Regression: valid JSON that is not an object must error, not panic.
        for content in ["[1,2,3]", "42", "\"hello\"", "true", "null"] {
            let result = update_package_json_content(content, PackageManager::Npm);
            assert!(result.is_err(), "expected error for content {content:?}");
            assert!(result.unwrap_err().contains("root is not a JSON object"));
        }
    }

    #[test]
    fn test_update_content_non_object_scripts_errors() {
        // Regression: a present-but-non-object `scripts` must error rather than
        // silently clobbering the user's value or panicking.
        let content = r#"{"name":"test","scripts":"build"}"#;
        let result = update_package_json_content(content, PackageManager::Npm);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("\"scripts\" is not a JSON object"));
    }

    #[test]
    fn test_update_content_null_scripts_creates_object() {
        // `null` scripts is benign: treated as absent and populated.
        let content = r#"{"name":"test","scripts":null}"#;
        let (modified, new_content, _, new_pi, _, new_dep) =
            update_package_json_content(content, PackageManager::Npm).unwrap();
        assert!(modified);
        assert!(new_pi.contains("npx @socketsecurity/socket-patch apply"));
        assert!(new_dep.contains("npx @socketsecurity/socket-patch apply"));
        let parsed: serde_json::Value = serde_json::from_str(&new_content).unwrap();
        assert!(parsed["scripts"]["postinstall"].is_string());
        assert!(parsed["scripts"]["dependencies"].is_string());
    }

    // ── remove_socket_patch_from_script ─────────────────────────────

    #[test]
    fn test_remove_script_only_socket_patch_deletes_key() {
        let (changed, new) = remove_socket_patch_from_script(
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm",
        );
        assert!(changed);
        assert_eq!(new, None);
    }

    #[test]
    fn test_remove_script_strips_prefix_keeps_rest() {
        let (changed, new) = remove_socket_patch_from_script(
            "npx @socketsecurity/socket-patch apply --silent --ecosystems npm && echo done",
        );
        assert!(changed);
        assert_eq!(new.as_deref(), Some("echo done"));
    }

    #[test]
    fn test_remove_script_no_socket_patch_unchanged() {
        let (changed, new) = remove_socket_patch_from_script("echo done && tsc");
        assert!(!changed);
        assert_eq!(new.as_deref(), Some("echo done && tsc"));
    }

    #[test]
    fn test_remove_script_legacy_pattern() {
        let (changed, new) = remove_socket_patch_from_script("socket-patch apply && echo done");
        assert!(changed);
        assert_eq!(new.as_deref(), Some("echo done"));
    }

    #[test]
    fn test_remove_script_empty() {
        let (changed, new) = remove_socket_patch_from_script("");
        assert!(!changed);
        assert_eq!(new, None);
    }

    #[test]
    fn test_remove_script_empty_segment_no_patch_is_unchanged() {
        // Regression: a patch-free script with a stray empty segment (double
        // `" && "`) must report `changed == false`. Keying `changed` off
        // `kept.len() != segments.len()` previously returned `(true, ..)` here,
        // violating the documented contract — `(true, ..)` means a socket-patch
        // segment was removed, which did not happen.
        let (changed, new) = remove_socket_patch_from_script("echo a &&  && echo b");
        assert!(
            !changed,
            "no socket-patch present, must not report a removal"
        );
        assert_eq!(new.as_deref(), Some("echo a &&  && echo b"));
    }

    #[test]
    fn test_remove_script_patch_in_middle_keeps_siblings() {
        let (changed, new) =
            remove_socket_patch_from_script("echo a && socket-patch apply && echo b");
        assert!(changed);
        assert_eq!(new.as_deref(), Some("echo a && echo b"));
    }

    #[test]
    fn test_remove_script_multiple_patch_segments() {
        // Defensive: more than one socket-patch invocation, all removed.
        let (changed, new) = remove_socket_patch_from_script(
            "socket-patch apply && build && npx @socketsecurity/socket-patch apply",
        );
        assert!(changed);
        assert_eq!(new.as_deref(), Some("build"));
    }

    #[test]
    fn test_remove_script_pnpm_command() {
        // The pnpm canonical command must be recognized and stripped (it
        // contains the "socket-patch apply" pattern).
        let (changed, new) = remove_socket_patch_from_script(
            "pnpm dlx @socketsecurity/socket-patch apply --silent --ecosystems npm && echo hi",
        );
        assert!(changed);
        assert_eq!(new.as_deref(), Some("echo hi"));
    }

    // ── remove_package_json_object ──────────────────────────────────

    #[test]
    fn test_remove_object_deletes_lifecycle_keys() {
        let mut pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": {
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm",
                "dependencies": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm"
            }
        });
        let status = remove_package_json_object(&mut pkg);
        assert!(status.modified);
        // Both keys were only socket-patch, so they (and the now-empty
        // `scripts` object) are removed entirely.
        assert!(pkg.get("scripts").is_none());
    }

    #[test]
    fn test_remove_object_keeps_sibling_scripts() {
        let mut pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": {
                "build": "tsc",
                "postinstall": "npx @socketsecurity/socket-patch apply --silent --ecosystems npm && echo hi"
            }
        });
        let status = remove_package_json_object(&mut pkg);
        assert!(status.modified);
        assert_eq!(pkg["scripts"]["build"], "tsc");
        assert_eq!(pkg["scripts"]["postinstall"], "echo hi");
    }

    #[test]
    fn test_remove_object_noop_when_empty_segment_no_patch() {
        // Regression: a patch-free script whose only oddity is a stray empty
        // segment must be a no-op — neither reported modified nor rewritten.
        let mut pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": { "postinstall": "echo a &&  && echo b" }
        });
        let status = remove_package_json_object(&mut pkg);
        assert!(!status.modified);
        // The original (untouched) value must be preserved, empty segment and all.
        assert_eq!(pkg["scripts"]["postinstall"], "echo a &&  && echo b");
    }

    #[test]
    fn test_remove_object_noop_when_not_configured() {
        let mut pkg: serde_json::Value = serde_json::json!({
            "name": "test",
            "scripts": { "build": "tsc" }
        });
        let status = remove_package_json_object(&mut pkg);
        assert!(!status.modified);
        assert_eq!(pkg["scripts"]["build"], "tsc");
    }

    // ── remove_package_json_content ─────────────────────────────────

    #[test]
    fn test_remove_content_roundtrip_with_update() {
        // update then remove must return to a no-socket-patch state.
        let original = r#"{"name":"x","scripts":{"build":"tsc"}}"#;
        let (_, updated, ..) = update_package_json_content(original, PackageManager::Npm).unwrap();
        assert!(updated.contains("socket-patch"));

        let (modified, removed, _) = remove_package_json_content(&updated).unwrap();
        assert!(modified);
        assert!(!removed.contains("socket-patch"));
        let parsed: serde_json::Value = serde_json::from_str(&removed).unwrap();
        assert_eq!(parsed["scripts"]["build"], "tsc");
        assert!(parsed["scripts"].get("postinstall").is_none());
        assert!(parsed["scripts"].get("dependencies").is_none());
    }

    #[test]
    fn test_remove_content_idempotent() {
        let configured =
            r#"{"name":"x","scripts":{"postinstall":"npx @socketsecurity/socket-patch apply"}}"#;
        let (modified1, removed, _) = remove_package_json_content(configured).unwrap();
        assert!(modified1);
        let (modified2, _, _) = remove_package_json_content(&removed).unwrap();
        assert!(!modified2);
    }

    #[test]
    fn test_remove_content_roundtrip_pnpm() {
        // update (pnpm) then remove must fully revert to a no-socket-patch state.
        let original = r#"{"name":"x","scripts":{"build":"tsc"}}"#;
        let (_, updated, ..) = update_package_json_content(original, PackageManager::Pnpm).unwrap();
        assert!(updated.contains("pnpm dlx @socketsecurity/socket-patch apply"));

        let (modified, removed, _) = remove_package_json_content(&updated).unwrap();
        assert!(modified);
        assert!(!removed.contains("socket-patch"));
        let parsed: serde_json::Value = serde_json::from_str(&removed).unwrap();
        assert_eq!(parsed["scripts"]["build"], "tsc");
        assert!(parsed["scripts"].get("postinstall").is_none());
        assert!(parsed["scripts"].get("dependencies").is_none());
    }

    #[test]
    fn test_remove_content_invalid_json_errors() {
        assert!(remove_package_json_content("not json").is_err());
    }

    #[test]
    fn test_remove_content_non_object_scripts_errors() {
        let result = remove_package_json_content(r#"{"name":"x","scripts":"build"}"#);
        assert!(result.is_err());
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
