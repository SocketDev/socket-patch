//! Top-level product PURL auto-detection.
//!
//! Inspects the working directory for the first of:
//!   1. `package.json` (npm)        → `pkg:npm/<name>@<version>`
//!   2. `pyproject.toml` (PyPI)     → `pkg:pypi/<name>@<version>`
//!   3. `Cargo.toml` (Cargo)        → `pkg:cargo/<name>@<version>`
//!
//! Returns `None` only when none of these files exist or none have a
//! usable `name + version`. Multiple-manifests case: we pick the highest
//! priority and surface a warning via [`DetectResult::warnings`] so the
//! CLI can echo it to stderr.

use std::path::Path;

/// Outcome of [`detect_product`].
#[derive(Debug, Clone, Default)]
pub struct DetectResult {
    /// Detected product PURL, or `None` if nothing matched.
    pub purl: Option<String>,
    /// Non-fatal observations the CLI should print to stderr — e.g.
    /// "found Cargo.toml AND package.json; using package.json".
    pub warnings: Vec<String>,
}

pub async fn detect_product(cwd: &Path) -> DetectResult {
    let mut result = DetectResult::default();

    let pkg_json = cwd.join("package.json");
    let pyproject = cwd.join("pyproject.toml");
    let cargo = cwd.join("Cargo.toml");

    let pkg_json_exists = tokio::fs::metadata(&pkg_json).await.is_ok();
    let pyproject_exists = tokio::fs::metadata(&pyproject).await.is_ok();
    let cargo_exists = tokio::fs::metadata(&cargo).await.is_ok();

    // Collect a warning if more than one manifest is present.
    let present_count = [pkg_json_exists, pyproject_exists, cargo_exists]
        .iter()
        .filter(|b| **b)
        .count();
    if present_count > 1 {
        let mut found = Vec::new();
        if pkg_json_exists {
            found.push("package.json");
        }
        if pyproject_exists {
            found.push("pyproject.toml");
        }
        if cargo_exists {
            found.push("Cargo.toml");
        }
        result.warnings.push(format!(
            "Multiple project manifests detected ({}); using {} for the top-level product",
            found.join(", "),
            found[0]
        ));
    }

    if pkg_json_exists {
        if let Some(purl) = read_package_json(&pkg_json).await {
            result.purl = Some(purl);
            return result;
        }
    }
    if pyproject_exists {
        if let Some(purl) = read_pyproject(&pyproject).await {
            result.purl = Some(purl);
            return result;
        }
    }
    if cargo_exists {
        if let Some(purl) = read_cargo_toml(&cargo).await {
            result.purl = Some(purl);
            return result;
        }
    }

    result
}

async fn read_package_json(path: &Path) -> Option<String> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    let name = v.get("name")?.as_str()?;
    let version = v.get("version")?.as_str()?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    // npm scoped packages keep their `@scope/name` form in the PURL —
    // matches how socket-patch's manifest already stores them.
    Some(format!("pkg:npm/{name}@{version}"))
}

async fn read_pyproject(path: &Path) -> Option<String> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let (name, version) = scan_toml_section(&content, "project")?;
    Some(format!("pkg:pypi/{name}@{version}"))
}

async fn read_cargo_toml(path: &Path) -> Option<String> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let (name, version) = scan_toml_section(&content, "package")?;
    Some(format!("pkg:cargo/{name}@{version}"))
}

/// Minimal line-based TOML scanner for `[<section>]` blocks. Reads
/// `name = "..."` and `version = "..."` from the named section and
/// stops at the next `[` header. Robust enough for the well-formed
/// `pyproject.toml` / `Cargo.toml` files we expect at the top level —
/// no full TOML parser dependency.
///
/// Returns `None` if either key is missing, both keys appear outside
/// the section, the value is empty, or the value is `version.workspace
/// = true` (matches the cargo crawler's behavior of skipping workspace
/// inheritance).
fn scan_toml_section(content: &str, section: &str) -> Option<(String, String)> {
    let mut in_section = false;
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let header = format!("[{section}]");

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_section = line == header;
            continue;
        }
        if !in_section {
            continue;
        }
        if let Some(v) = parse_toml_string_kv(line, "name") {
            name = Some(v);
        } else if let Some(v) = parse_toml_string_kv(line, "version") {
            version = Some(v);
        }
    }

    let name = name?;
    let version = version?;
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

/// Parse `<key> = "<value>"`. Returns `None` if the key doesn't match,
/// the value isn't a double-quoted string literal, or the value is
/// empty. Inline-table forms like `version = { workspace = true }`
/// fail this check and are skipped by the caller.
fn parse_toml_string_kv(line: &str, key: &str) -> Option<String> {
    let eq = line.find('=')?;
    let (lhs, rhs) = line.split_at(eq);
    if lhs.trim() != key {
        return None;
    }
    let rhs = rhs[1..].trim(); // drop the leading '=' and surrounding ws
    let stripped = rhs.strip_prefix('"')?;
    let end = stripped.find('"')?;
    let value = &stripped[..end];
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn detect_package_json() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"my-app","version":"1.2.3"}"#,
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/my-app@1.2.3"));
        assert!(r.warnings.is_empty());
    }

    #[tokio::test]
    async fn detect_scoped_npm_package() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"@socket/foo","version":"0.1.0"}"#,
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/@socket/foo@0.1.0"));
    }

    #[tokio::test]
    async fn detect_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        let content = "[project]\nname = \"my-pylib\"\nversion = \"0.4.0\"\n";
        tokio::fs::write(dir.path().join("pyproject.toml"), content)
            .await
            .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:pypi/my-pylib@0.4.0"));
    }

    #[tokio::test]
    async fn detect_cargo_toml() {
        let dir = tempfile::tempdir().unwrap();
        let content = "[package]\nname = \"my-rust\"\nversion = \"2.0.0\"\nedition = \"2021\"\n";
        tokio::fs::write(dir.path().join("Cargo.toml"), content)
            .await
            .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:cargo/my-rust@2.0.0"));
    }

    #[tokio::test]
    async fn cargo_workspace_inheritance_is_unsupported() {
        // `version.workspace = true` is not a quoted string literal,
        // so detection should report None rather than emit garbage.
        let dir = tempfile::tempdir().unwrap();
        let content = "[package]\nname = \"my-rust\"\nversion.workspace = true\n";
        tokio::fs::write(dir.path().join("Cargo.toml"), content)
            .await
            .unwrap();

        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
    }

    #[tokio::test]
    async fn multiple_manifests_warns_and_picks_package_json() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("package.json"),
            r#"{"name":"my-app","version":"1.0.0"}"#,
        )
        .await
        .unwrap();
        tokio::fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"alt\"\nversion = \"9.9.9\"\n",
        )
        .await
        .unwrap();

        let r = detect_product(dir.path()).await;
        assert_eq!(r.purl.as_deref(), Some("pkg:npm/my-app@1.0.0"));
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("Multiple"));
    }

    #[tokio::test]
    async fn empty_dir_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let r = detect_product(dir.path()).await;
        assert!(r.purl.is_none());
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn scan_toml_skips_other_sections() {
        let toml = "[other]\nname = \"wrong\"\nversion = \"0.0.0\"\n\n[package]\nname = \"right\"\nversion = \"1.0.0\"\n";
        let (n, v) = scan_toml_section(toml, "package").unwrap();
        assert_eq!(n, "right");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn scan_toml_ignores_comments_and_blank_lines() {
        let toml = "[package]\n# a comment\n\nname = \"x\"\nversion = \"1.0\"\n";
        let (n, v) = scan_toml_section(toml, "package").unwrap();
        assert_eq!(n, "x");
        assert_eq!(v, "1.0");
    }

    #[test]
    fn scan_toml_missing_version_returns_none() {
        let toml = "[package]\nname = \"only-name\"\n";
        assert!(scan_toml_section(toml, "package").is_none());
    }
}
