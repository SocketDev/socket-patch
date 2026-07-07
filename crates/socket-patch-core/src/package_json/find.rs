use std::path::{Path, PathBuf};
use tokio::fs;

use super::detect::{strip_bom, PackageManager};
use crate::utils::fs::{entry_file_type, is_dir, list_dir_entries};

/// Detect the package manager based on lockfiles in the project root.
/// Checks for pnpm-lock.yaml, pnpm-lock.yml, and pnpm-workspace.yaml.
pub async fn detect_package_manager(start_path: &Path) -> PackageManager {
    for name in &["pnpm-lock.yaml", "pnpm-lock.yml", "pnpm-workspace.yaml"] {
        if fs::metadata(start_path.join(name)).await.is_ok() {
            return PackageManager::Pnpm;
        }
    }
    PackageManager::Npm
}

/// Workspace configuration type.
#[derive(Debug, Clone)]
pub enum WorkspaceType {
    Npm,
    Pnpm,
    None,
}

/// Workspace configuration.
#[derive(Debug, Clone)]
struct WorkspaceConfig {
    ws_type: WorkspaceType,
    patterns: Vec<String>,
}

/// Location of a discovered package.json file.
#[derive(Debug, Clone)]
pub struct PackageJsonLocation {
    pub path: PathBuf,
    pub is_root: bool,
    pub is_workspace: bool,
}

/// Result of finding package.json files.
#[derive(Debug)]
pub struct PackageJsonFindResult {
    pub files: Vec<PackageJsonLocation>,
    pub workspace_type: WorkspaceType,
}

/// Find all package.json files, respecting workspace configurations.
pub async fn find_package_json_files(start_path: &Path) -> PackageJsonFindResult {
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
            path: root_package_json.clone(),
            is_root: true,
            is_workspace: false,
        });
    }

    match workspace_config.ws_type {
        WorkspaceType::None => {
            // No workspace config: pick up nested manifests with a bounded
            // walk (the root entry is already in `results`).
            if root_exists {
                let mut nested = Vec::new();
                search_recursive(start_path, 0, 5, &mut nested).await;
                results.extend(nested.into_iter().filter(|p| *p != root_package_json).map(
                    |path| PackageJsonLocation {
                        path,
                        is_root: false,
                        is_workspace: false,
                    },
                ));
            }
        }
        _ => {
            // Members are collected into their own vec so a `!`-negation
            // pattern can only remove members, never the root entry.
            let mut members = Vec::new();
            collect_workspace_members(start_path, &workspace_config, 0, &mut members).await;
            results.extend(members);
        }
    }

    // Workspace patterns can overlap (e.g. "packages/*" and "packages/a", or a
    // glob plus an exact path), which would otherwise yield the same
    // package.json more than once. De-duplicate by path, preserving discovery
    // order so the root entry stays first.
    let mut seen = std::collections::HashSet::new();
    results.retain(|loc| seen.insert(loc.path.clone()));

    PackageJsonFindResult {
        files: results,
        workspace_type: workspace_config.ws_type,
    }
}

/// Detect workspace configuration from package.json.
async fn detect_workspaces(package_json_path: &Path) -> WorkspaceConfig {
    let default = WorkspaceConfig {
        ws_type: WorkspaceType::None,
        patterns: Vec::new(),
    };

    // Check for pnpm workspaces first — pnpm projects may also have
    // "workspaces" in package.json for compatibility, but pnpm-workspace.yaml
    // is the definitive signal. It lives next to package.json and does not
    // depend on package.json being present or even valid JSON, so it must be
    // checked *before* parsing package.json — otherwise a malformed (e.g.
    // JSONC, or simply broken) root manifest would wrongly demote a real pnpm
    // workspace to "no workspace".
    let dir = package_json_path.parent().unwrap_or(Path::new("."));
    let pnpm_workspace = dir.join("pnpm-workspace.yaml");
    if let Ok(yaml_content) = fs::read_to_string(&pnpm_workspace).await {
        let patterns = parse_pnpm_workspace_patterns(&yaml_content);
        return WorkspaceConfig {
            ws_type: WorkspaceType::Pnpm,
            patterns,
        };
    }

    let content = match fs::read_to_string(package_json_path).await {
        Ok(c) => c,
        Err(_) => return default,
    };

    let pkg: serde_json::Value = match serde_json::from_str(strip_bom(&content)) {
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

    default
}

/// Simple parser for pnpm-workspace.yaml packages field.
fn parse_pnpm_workspace_patterns(yaml_content: &str) -> Vec<String> {
    let mut patterns = Vec::new();
    let mut in_packages = false;

    // A BOM is not Unicode whitespace, so `trim` would leave it glued to a
    // first-line `packages:` header and the whole section would be missed.
    for line in strip_bom(yaml_content).lines() {
        let trimmed = line.trim();

        // The header may carry an inline comment (`packages: # globs`); a `#`
        // opens a comment only when preceded by whitespace.
        let is_packages_header = match trimmed.strip_prefix("packages:") {
            Some("") => true,
            Some(rest) => {
                rest.starts_with(|c: char| c.is_whitespace()) && rest.trim_start().starts_with('#')
            }
            None => false,
        };
        if is_packages_header {
            in_packages = true;
            continue;
        }

        if in_packages {
            if !trimmed.is_empty() && !trimmed.starts_with('-') && !trimmed.starts_with('#') {
                break;
            }

            if let Some(rest) = trimmed.strip_prefix('-') {
                let item = parse_yaml_list_value(rest);
                if !item.is_empty() {
                    patterns.push(item);
                }
            }
        }
    }

    patterns
}

/// Extract the scalar value of a YAML list item, handling surrounding quotes
/// and trailing inline comments (`# ...`).
fn parse_yaml_list_value(raw: &str) -> String {
    let s = raw.trim();

    // Quoted scalar: take the content between the first matching pair of
    // quotes. Anything after the closing quote (e.g. an inline comment) is
    // ignored, and a `#` inside the quotes stays part of the value.
    for q in ['\'', '"'] {
        if let Some(rest) = s.strip_prefix(q) {
            if let Some(end) = rest.find(q) {
                return rest[..end].to_string();
            }
        }
    }

    // A list item that is *only* a comment (`- # foo`) has no scalar value.
    // The inline-comment scan below starts at index 1 (a `#` is a comment only
    // when preceded by whitespace), so a leading `#` would otherwise survive as
    // a bogus `"# foo"` pattern. Skip it here.
    if s.starts_with('#') {
        return String::new();
    }

    // Unquoted scalar: a `#` preceded by whitespace begins an inline comment.
    let bytes = s.as_bytes();
    let comment_start =
        (1..bytes.len()).find(|&i| bytes[i] == b'#' && bytes[i - 1].is_ascii_whitespace());
    let value = match comment_start {
        Some(idx) => &s[..idx],
        None => s,
    };
    value.trim().to_string()
}

/// Bounded-depth recursion limit for nested workspaces — deep enough for any
/// real monorepo, a hard stop against a pattern that loops back on itself.
const MAX_WORKSPACE_DEPTH: usize = 10;

/// Collect workspace members matching the config's patterns, recursing into
/// any member that is **itself** a workspace root (property 9's
/// nested-workspace rule). A member's own `workspaces` patterns are resolved
/// relative to that member's directory.
async fn collect_workspace_members(
    root_path: &Path,
    config: &WorkspaceConfig,
    depth: usize,
    results: &mut Vec<PackageJsonLocation>,
) {
    if depth > MAX_WORKSPACE_DEPTH {
        return;
    }
    for pattern in &config.patterns {
        // npm (`@npmcli/map-workspaces`), yarn, and pnpm all support
        // `!`-prefixed exclusion patterns, processed in order: a negation
        // removes whatever earlier patterns matched. Resolve the negated
        // pattern with the same matcher and drop those members.
        if let Some(negated) = pattern.strip_prefix('!') {
            let excluded = find_packages_matching_pattern(root_path, negated).await;
            results.retain(|loc| !excluded.contains(&loc.path));
            continue;
        }
        let packages = find_packages_matching_pattern(root_path, pattern).await;
        for p in packages {
            let member_dir = p.parent().map(Path::to_path_buf);
            results.push(PackageJsonLocation {
                path: p,
                is_root: false,
                is_workspace: true,
            });
            // If this member declares its own workspaces, configure ITS members
            // too (one repo-root `setup` covers the whole nested tree). The
            // final de-dup in `find_package_json_files` collapses any overlap.
            if let Some(dir) = member_dir {
                let member_pkg = dir.join("package.json");
                let member_config = detect_workspaces(&member_pkg).await;
                if !matches!(member_config.ws_type, WorkspaceType::None) {
                    Box::pin(collect_workspace_members(
                        &dir,
                        &member_config,
                        depth + 1,
                        results,
                    ))
                    .await;
                }
            }
        }
    }
}

/// Find packages matching a workspace pattern.
async fn find_packages_matching_pattern(root_path: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut results = Vec::new();

    // A trailing `*`/`**` segment is a glob; everything before the final `/`
    // is a (possibly empty, possibly multi-segment) directory prefix. Split on
    // the *last* `/` so bare globs (`*`, `**`) and deeper prefixes (`a/b/*`)
    // are handled, not just the two-segment `prefix/*` form.
    let (prefix, last) = pattern.rsplit_once('/').unwrap_or(("", pattern));

    match last {
        "*" | "**" => {
            let search_path = if prefix.is_empty() {
                root_path.to_path_buf()
            } else {
                root_path.join(prefix)
            };
            if last == "*" {
                search_one_level(&search_path, &mut results).await;
            } else {
                // Globstar matches zero segments too — npm/pnpm glob
                // `<prefix>/**/package.json`, which matches the prefix dir's
                // own `package.json` — so the prefix directory itself is a
                // candidate member, not just its descendants. (For a bare
                // `**` this re-finds the root manifest; the caller's de-dup
                // keeps the root entry.)
                let own_pkg = search_path.join("package.json");
                if fs::metadata(&own_pkg).await.is_ok() {
                    results.push(own_pkg);
                }
                search_recursive(&search_path, 0, usize::MAX, &mut results).await;
            }
        }
        _ => {
            let pkg_json = root_path.join(pattern).join("package.json");
            if fs::metadata(&pkg_json).await.is_ok() {
                results.push(pkg_json);
            }
        }
    }

    results
}

/// Directories that are never workspace members and must be skipped while
/// walking the tree (hidden dirs plus dependency/output directories).
fn is_ignored_dir(name: &str) -> bool {
    name.starts_with('.') || name == "node_modules" || name == "dist" || name == "build"
}

/// Search one level deep for package.json files.
async fn search_one_level(dir: &Path, results: &mut Vec<PathBuf>) {
    for entry in list_dir_entries(dir).await {
        let path = entry.path();
        // A single-level `dir/*` glob follows a symlinked direct member, the
        // way npm/pnpm (and our cargo `glob_dir`) resolve a workspace member
        // that is itself a symlink. `entry.file_type()` reports the *link's*
        // own type — `is_dir() == false` — so it would silently drop such a
        // member; stat the path instead so the link is followed. (The
        // recursive searcher below deliberately does NOT follow symlinks,
        // to avoid loops/escapes — there a symlink's `is_dir() == false` is the
        // desired skip.)
        if !is_dir(&path).await {
            continue;
        }
        // A `dir/*` pattern must not pick up node_modules/hidden/output dirs as
        // workspace members, matching the recursive searchers below.
        if is_ignored_dir(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let pkg_json = path.join("package.json");
        if fs::metadata(&pkg_json).await.is_ok() {
            results.push(pkg_json);
        }
    }
}

/// Search recursively for package.json files, descending at most `max_depth`
/// directory levels below `dir` (pass `usize::MAX` for an unbounded walk).
/// Symlinks are deliberately not followed — see `search_one_level`.
async fn search_recursive(dir: &Path, depth: usize, max_depth: usize, results: &mut Vec<PathBuf>) {
    if depth > max_depth {
        return;
    }

    for entry in list_dir_entries(dir).await {
        let Some(ft) = entry_file_type(&entry).await else {
            continue;
        };
        if !ft.is_dir() {
            continue;
        }

        // Skip hidden directories, node_modules, dist, build
        if is_ignored_dir(&entry.file_name().to_string_lossy()) {
            continue;
        }

        let full_path = entry.path();
        let pkg_json = full_path.join("package.json");
        if fs::metadata(&pkg_json).await.is_ok() {
            results.push(pkg_json);
        }

        Box::pin(search_recursive(&full_path, depth + 1, max_depth, results)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Group 1: parse_pnpm_workspace_patterns ───────────────────────

    #[test]
    fn test_parse_pnpm_basic() {
        let yaml = "packages:\n  - packages/*";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_multiple_patterns() {
        let yaml = "packages:\n  - packages/*\n  - apps/*\n  - tools/*";
        assert_eq!(
            parse_pnpm_workspace_patterns(yaml),
            vec!["packages/*", "apps/*", "tools/*"]
        );
    }

    #[test]
    fn test_parse_pnpm_quoted_patterns() {
        let yaml = "packages:\n  - 'packages/*'\n  - \"apps/*\"";
        assert_eq!(
            parse_pnpm_workspace_patterns(yaml),
            vec!["packages/*", "apps/*"]
        );
    }

    #[test]
    fn test_parse_pnpm_comments_interspersed() {
        let yaml = "packages:\n  # workspace packages\n  - packages/*\n  # apps\n  - apps/*";
        assert_eq!(
            parse_pnpm_workspace_patterns(yaml),
            vec!["packages/*", "apps/*"]
        );
    }

    #[test]
    fn test_parse_pnpm_empty_content() {
        assert!(parse_pnpm_workspace_patterns("").is_empty());
    }

    #[test]
    fn test_parse_pnpm_no_packages_key() {
        let yaml = "name: my-project\nversion: 1.0.0";
        assert!(parse_pnpm_workspace_patterns(yaml).is_empty());
    }

    #[test]
    fn test_parse_pnpm_stops_at_next_section() {
        let yaml = "packages:\n  - packages/*\ncatalog:\n  lodash: 4.17.21";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_indented_key() {
        // The parser uses `trimmed == "packages:"` so leading spaces should match
        let yaml = "  packages:\n  - packages/*";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_dash_only_line() {
        let yaml = "packages:\n  -\n  - packages/*";
        // A bare "-" with no value should be skipped (empty after trim)
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    #[test]
    fn test_parse_pnpm_glob_star_star() {
        let yaml = "packages:\n  - packages/**";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/**"]);
    }

    #[test]
    fn test_parse_pnpm_bom_first_line() {
        // A UTF-8 BOM (Windows editors commonly write one) is NOT Unicode
        // whitespace, so `trim` leaves it in place and a `packages:` header on
        // the first line never matches — every pattern is silently lost, and
        // because pnpm-workspace.yaml still marks the project as a pnpm
        // workspace, no fallback walk runs: zero members discovered.
        let yaml = "\u{feff}packages:\n  - packages/*";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    // ── Group 2: workspace detection + file discovery ────────────────

    #[tokio::test]
    async fn test_detect_workspaces_npm_array() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"workspaces": ["packages/*"]}"#)
            .await
            .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Npm));
        assert_eq!(config.patterns, vec!["packages/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_npm_object() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(
            &pkg,
            r#"{"workspaces": {"packages": ["packages/*", "apps/*"]}}"#,
        )
        .await
        .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Npm));
        assert_eq!(config.patterns, vec!["packages/*", "apps/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_pnpm() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name": "root"}"#).await.unwrap();
        let pnpm = dir.path().join("pnpm-workspace.yaml");
        fs::write(&pnpm, "packages:\n  - packages/*").await.unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Pnpm));
        assert_eq!(config.patterns, vec!["packages/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_pnpm_with_workspaces_field() {
        // When both pnpm-workspace.yaml AND "workspaces" in package.json
        // exist, pnpm should take priority
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name": "root", "workspaces": ["packages/*"]}"#)
            .await
            .unwrap();
        let pnpm = dir.path().join("pnpm-workspace.yaml");
        fs::write(&pnpm, "packages:\n  - workspaces/*")
            .await
            .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Pnpm));
        // Should use pnpm-workspace.yaml patterns, not package.json workspaces
        assert_eq!(config.patterns, vec!["workspaces/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_pnpm_with_malformed_package_json() {
        // Regression: pnpm-workspace.yaml is the definitive signal and must be
        // honored even when the root package.json is not valid JSON. Previously
        // the JSON parse error short-circuited before the pnpm check.
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        // JSONC-style comment — valid for some tooling, invalid for serde_json.
        fs::write(&pkg, "{\n  // a comment\n  \"name\": \"root\"\n}")
            .await
            .unwrap();
        let pnpm = dir.path().join("pnpm-workspace.yaml");
        fs::write(&pnpm, "packages:\n  - packages/*").await.unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Pnpm));
        assert_eq!(config.patterns, vec!["packages/*"]);
    }

    #[tokio::test]
    async fn test_detect_workspaces_npm_with_bom() {
        // npm strips a leading UTF-8 BOM before parsing package.json, so a
        // BOM'd manifest is npm-valid; its workspaces must not be silently
        // dropped (which would demote the project to "no workspace").
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, "\u{feff}{\"workspaces\": [\"packages/*\"]}")
            .await
            .unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::Npm));
        assert_eq!(config.patterns, vec!["packages/*"]);
    }

    #[tokio::test]
    async fn test_find_bom_root_workspace_negation_honored() {
        // End-to-end symptom of the BOM gap: with a BOM'd root manifest the
        // workspace config silently degraded to None, so members were found
        // only by the fallback walk — mislabeled as non-workspace and with
        // `!`-negations ignored, letting setup edit an excluded package.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            "\u{feff}{\"workspaces\": [\"packages/*\", \"!packages/private\"]}",
        )
        .await
        .unwrap();
        for member in ["a", "private"] {
            let m = dir.path().join("packages").join(member);
            fs::create_dir_all(&m).await.unwrap();
            fs::write(m.join("package.json"), r#"{"name":"m"}"#)
                .await
                .unwrap();
        }
        let result = find_package_json_files(dir.path()).await;
        assert!(matches!(result.workspace_type, WorkspaceType::Npm));
        let members: Vec<_> = result.files.iter().filter(|f| f.is_workspace).collect();
        assert_eq!(
            members.len(),
            1,
            "negated member must stay excluded under a BOM'd root: {:?}",
            result.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert!(members[0].path.ends_with("packages/a/package.json"));
    }

    #[tokio::test]
    async fn test_detect_workspaces_none() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, r#"{"name": "root"}"#).await.unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::None));
        assert!(config.patterns.is_empty());
    }

    #[tokio::test]
    async fn test_detect_workspaces_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        fs::write(&pkg, "not valid json!!!").await.unwrap();
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::None));
    }

    #[tokio::test]
    async fn test_detect_workspaces_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("nonexistent.json");
        let config = detect_workspaces(&pkg).await;
        assert!(matches!(config.ws_type, WorkspaceType::None));
    }

    #[tokio::test]
    async fn test_find_no_root_package_json() {
        let dir = tempfile::tempdir().unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert!(result.files.is_empty());
    }

    #[tokio::test]
    async fn test_find_root_only() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].is_root);
    }

    #[tokio::test]
    async fn test_find_npm_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"]}"#,
        )
        .await
        .unwrap();
        let pkg_a = dir.path().join("packages").join("a");
        fs::create_dir_all(&pkg_a).await.unwrap();
        fs::write(pkg_a.join("package.json"), r#"{"name":"a"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert!(matches!(result.workspace_type, WorkspaceType::Npm));
        // root + workspace member
        assert_eq!(result.files.len(), 2);
        assert!(result.files[0].is_root);
        assert!(result.files[1].is_workspace);
    }

    #[tokio::test]
    async fn test_find_pnpm_workspaces() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*",
        )
        .await
        .unwrap();
        let pkg_a = dir.path().join("packages").join("a");
        fs::create_dir_all(&pkg_a).await.unwrap();
        fs::write(pkg_a.join("package.json"), r#"{"name":"a"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert!(matches!(result.workspace_type, WorkspaceType::Pnpm));
        // find_package_json_files still returns all files;
        // filtering for pnpm is done by the caller (setup command)
        assert_eq!(result.files.len(), 2);
        assert!(result.files[0].is_root);
        assert!(result.files[1].is_workspace);
    }

    #[tokio::test]
    async fn test_find_nested_skips_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        let nm = dir.path().join("node_modules").join("lodash");
        fs::create_dir_all(&nm).await.unwrap();
        fs::write(nm.join("package.json"), r#"{"name":"lodash"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        // Only root, node_modules should be skipped
        assert_eq!(result.files.len(), 1);
        assert!(result.files[0].is_root);
    }

    #[tokio::test]
    async fn test_find_nested_depth_limit() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"root"}"#)
            .await
            .unwrap();
        // Create deeply nested package.json at depth 7 (> limit of 5)
        let mut deep = dir.path().to_path_buf();
        for i in 0..7 {
            deep = deep.join(format!("level{}", i));
        }
        fs::create_dir_all(&deep).await.unwrap();
        fs::write(deep.join("package.json"), r#"{"name":"deep"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        // Only root (the deep one exceeds depth limit)
        assert_eq!(result.files.len(), 1);
    }

    #[tokio::test]
    async fn test_find_workspace_double_glob() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["apps/**"]}"#,
        )
        .await
        .unwrap();
        let nested = dir.path().join("apps").join("web").join("client");
        fs::create_dir_all(&nested).await.unwrap();
        fs::write(nested.join("package.json"), r#"{"name":"client"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        // root + recursively found workspace member
        assert!(result.files.len() >= 2);
    }

    #[tokio::test]
    async fn test_find_recurses_into_nested_workspace() {
        // Property 9: a workspace member that is itself a workspace root has ITS
        // members discovered too. root → packages/inner → sub/leaf.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"name":"root","workspaces":["packages/*"]}"#,
        )
        .await
        .unwrap();
        let inner = dir.path().join("packages").join("inner");
        fs::create_dir_all(&inner).await.unwrap();
        fs::write(
            inner.join("package.json"),
            r#"{"name":"inner","workspaces":["sub/*"]}"#,
        )
        .await
        .unwrap();
        let leaf = inner.join("sub").join("leaf");
        fs::create_dir_all(&leaf).await.unwrap();
        fs::write(leaf.join("package.json"), r#"{"name":"leaf"}"#)
            .await
            .unwrap();

        let result = find_package_json_files(dir.path()).await;
        let paths: Vec<String> = result
            .files
            .iter()
            .map(|f| f.path.to_string_lossy().into_owned())
            .collect();
        // `Path::ends_with` matches whole path components and treats `/` in the
        // pattern as a separator on every platform (Windows accepts both `/`
        // and `\`), so this is correct regardless of the OS path separator —
        // unlike a byte-wise `str::ends_with` on a forward-slash literal, which
        // fails on Windows' `\`-separated paths.
        assert!(
            result
                .files
                .iter()
                .any(|f| f.path.ends_with("packages/inner/package.json")),
            "first-level member must be found: {paths:?}"
        );
        assert!(
            result
                .files
                .iter()
                .any(|f| f.path.ends_with("packages/inner/sub/leaf/package.json")),
            "nested-workspace leaf must be found via recursion: {paths:?}"
        );
        // root + inner + leaf, no duplicates.
        assert_eq!(
            result.files.len(),
            3,
            "exactly root + inner + leaf: {paths:?}"
        );
    }

    #[tokio::test]
    async fn test_find_workspace_exact_path() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/core"]}"#,
        )
        .await
        .unwrap();
        let core = dir.path().join("packages").join("core");
        fs::create_dir_all(&core).await.unwrap();
        fs::write(core.join("package.json"), r#"{"name":"core"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert_eq!(result.files.len(), 2);
    }

    #[test]
    fn test_parse_pnpm_inline_comment_stripped() {
        // A `# ...` inline comment after a pattern must not become part of it.
        let yaml = "packages:\n  - packages/*  # workspace packages\n  - apps/*\t# trailing tab";
        assert_eq!(
            parse_pnpm_workspace_patterns(yaml),
            vec!["packages/*", "apps/*"]
        );
    }

    #[test]
    fn test_parse_pnpm_comment_only_list_item_skipped() {
        // A `- # comment` item is a YAML null (the value is just a comment) and
        // must NOT become a literal `"# comment"` workspace pattern. Previously
        // the inline-comment scan started at index 1, so a leading `#` survived.
        let yaml = "packages:\n  - # only a comment\n  - real/*";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["real/*"]);
    }

    #[test]
    fn test_parse_pnpm_quoted_value_keeps_hash() {
        // A `#` inside quotes is part of the value, not a comment.
        let yaml = "packages:\n  - 'packages/#weird'  # but this is a comment";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/#weird"]);
    }

    #[tokio::test]
    async fn test_find_overlapping_patterns_no_duplicates() {
        // "packages/*" and the exact "packages/a" both match the same member;
        // the result must contain it only once.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*", "packages/a"]}"#,
        )
        .await
        .unwrap();
        let a = dir.path().join("packages").join("a");
        fs::create_dir_all(&a).await.unwrap();
        fs::write(a.join("package.json"), r#"{"name":"a"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        // root + exactly one workspace member (no duplicate for packages/a)
        assert_eq!(result.files.len(), 2);
        assert!(result.files[0].is_root);
        let workspace_count = result.files.iter().filter(|f| f.is_workspace).count();
        assert_eq!(workspace_count, 1);
    }

    #[tokio::test]
    async fn test_find_star_pattern_skips_node_modules() {
        // A `packages/*` glob must not treat node_modules (or hidden/output
        // dirs) as a workspace member, even if they contain a package.json.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"]}"#,
        )
        .await
        .unwrap();
        let real = dir.path().join("packages").join("real");
        fs::create_dir_all(&real).await.unwrap();
        fs::write(real.join("package.json"), r#"{"name":"real"}"#)
            .await
            .unwrap();
        for ignored in ["node_modules", ".cache", "dist", "build"] {
            let d = dir.path().join("packages").join(ignored);
            fs::create_dir_all(&d).await.unwrap();
            fs::write(d.join("package.json"), r#"{"name":"x"}"#)
                .await
                .unwrap();
        }
        let result = find_package_json_files(dir.path()).await;
        // root + only the "real" member
        assert_eq!(result.files.len(), 2);
        let workspace_count = result.files.iter().filter(|f| f.is_workspace).count();
        assert_eq!(workspace_count, 1);
    }

    #[tokio::test]
    async fn test_find_workspace_bare_star() {
        // A bare `*` glob means "every immediate subdirectory" and must be
        // expanded, not treated as a literal directory named `*`.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"workspaces": ["*"]}"#)
            .await
            .unwrap();
        for member in ["a", "b"] {
            let m = dir.path().join(member);
            fs::create_dir_all(&m).await.unwrap();
            fs::write(m.join("package.json"), r#"{"name":"m"}"#)
                .await
                .unwrap();
        }
        // node_modules must still be ignored even for a root-level `*`.
        let nm = dir.path().join("node_modules").join("dep");
        fs::create_dir_all(&nm).await.unwrap();
        fs::write(nm.join("package.json"), r#"{"name":"dep"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        let workspace_count = result.files.iter().filter(|f| f.is_workspace).count();
        // root + members a and b (node_modules excluded)
        assert_eq!(workspace_count, 2);
        assert!(result.files[0].is_root);
    }

    #[tokio::test]
    async fn test_find_workspace_bare_double_glob() {
        // A bare `**` glob recurses from the root.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"workspaces": ["**"]}"#)
            .await
            .unwrap();
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).await.unwrap();
        fs::write(nested.join("package.json"), r#"{"name":"b"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        let workspace_count = result.files.iter().filter(|f| f.is_workspace).count();
        assert!(workspace_count >= 1);
    }

    #[tokio::test]
    async fn test_find_workspace_deep_prefix_glob() {
        // A glob with a multi-segment prefix (`group/sub/*`) must expand the
        // directory under that prefix, not be treated as a literal path.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["group/sub/*"]}"#,
        )
        .await
        .unwrap();
        let member = dir.path().join("group").join("sub").join("pkg");
        fs::create_dir_all(&member).await.unwrap();
        fs::write(member.join("package.json"), r#"{"name":"pkg"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        let workspace_count = result.files.iter().filter(|f| f.is_workspace).count();
        assert_eq!(workspace_count, 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_star_glob_follows_symlinked_member() {
        // Regression: a single-level `packages/*` glob must follow a workspace
        // member that is itself a symlink (npm/pnpm and our cargo `glob_dir`
        // both resolve such members). `entry.file_type()` reports the link as a
        // non-directory, so the old gate silently dropped it and `setup` never
        // patched the package.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*"]}"#,
        )
        .await
        .unwrap();
        // The real member lives outside `packages/`; `packages/a` links to it.
        let real = dir.path().join("real");
        fs::create_dir_all(&real).await.unwrap();
        fs::write(real.join("package.json"), r#"{"name":"a"}"#)
            .await
            .unwrap();
        fs::create_dir_all(dir.path().join("packages"))
            .await
            .unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("packages").join("a")).unwrap();

        let result = find_package_json_files(dir.path()).await;
        let workspace_count = result.files.iter().filter(|f| f.is_workspace).count();
        assert_eq!(
            workspace_count,
            1,
            "symlinked workspace member must be discovered: {:?}",
            result.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_find_double_glob_does_not_follow_symlinks() {
        // The asymmetric counterpart: a recursive `apps/**` glob must NOT follow
        // symlinks — a loop back to an ancestor would recurse forever and an
        // escaping link would let `setup` edit an out-of-tree manifest. Only the
        // real on-disk member is discovered.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["apps/**"]}"#,
        )
        .await
        .unwrap();
        let real = dir.path().join("apps").join("web");
        fs::create_dir_all(&real).await.unwrap();
        fs::write(real.join("package.json"), r#"{"name":"web"}"#)
            .await
            .unwrap();
        // A loop symlink back to the repo root and an escape symlink to an
        // out-of-tree package — neither must be traversed.
        std::os::unix::fs::symlink(dir.path(), dir.path().join("apps").join("loop")).unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("package.json"), r#"{"name":"escape"}"#)
            .await
            .unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("apps").join("escape")).unwrap();

        let result = find_package_json_files(dir.path()).await;
        let workspace_count = result.files.iter().filter(|f| f.is_workspace).count();
        assert_eq!(
            workspace_count,
            1,
            "only the real member must be found; symlinks not followed: {:?}",
            result.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_find_workspace_negation_excludes_member() {
        // npm (`@npmcli/map-workspaces`), yarn, and pnpm all support
        // `!`-prefixed exclusion patterns: a member matched by an earlier
        // pattern and then negated is NOT a workspace member. Previously the
        // `!pattern` was treated as a literal directory named `!packages`, so
        // the exclusion was silently ignored and `setup` edited a package.json
        // the user had explicitly excluded.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["packages/*", "!packages/private"]}"#,
        )
        .await
        .unwrap();
        for member in ["a", "private"] {
            let m = dir.path().join("packages").join(member);
            fs::create_dir_all(&m).await.unwrap();
            fs::write(m.join("package.json"), r#"{"name":"m"}"#)
                .await
                .unwrap();
        }
        let result = find_package_json_files(dir.path()).await;
        let members: Vec<_> = result.files.iter().filter(|f| f.is_workspace).collect();
        assert_eq!(
            members.len(),
            1,
            "negated member must be excluded: {:?}",
            result.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert!(members[0].path.ends_with("packages/a/package.json"));
    }

    #[tokio::test]
    async fn test_find_workspace_glob_negation_excludes_subtree() {
        // A negation can itself be a glob (pnpm's docs show `!**/test/**`);
        // `!legacy/**` must remove every member an earlier positive pattern
        // picked up under legacy/.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["**", "!legacy/**"]}"#,
        )
        .await
        .unwrap();
        let app = dir.path().join("app");
        fs::create_dir_all(&app).await.unwrap();
        fs::write(app.join("package.json"), r#"{"name":"app"}"#)
            .await
            .unwrap();
        let old = dir.path().join("legacy").join("old");
        fs::create_dir_all(&old).await.unwrap();
        fs::write(old.join("package.json"), r#"{"name":"old"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        let members: Vec<_> = result.files.iter().filter(|f| f.is_workspace).collect();
        assert_eq!(
            members.len(),
            1,
            "legacy subtree must be excluded: {:?}",
            result.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert!(members[0].path.ends_with("app/package.json"));
    }

    #[tokio::test]
    async fn test_find_double_glob_matches_prefix_dir_itself() {
        // Globstar matches zero segments: npm/pnpm resolve members by globbing
        // `apps/**/package.json`, which matches `apps/package.json` itself. A
        // package living at the pattern's prefix directory is a workspace
        // member too, not just its descendants — previously it was silently
        // skipped and never configured.
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"workspaces": ["apps/**"]}"#,
        )
        .await
        .unwrap();
        let apps = dir.path().join("apps");
        fs::create_dir_all(&apps).await.unwrap();
        fs::write(apps.join("package.json"), r#"{"name":"apps"}"#)
            .await
            .unwrap();
        let web = apps.join("web");
        fs::create_dir_all(&web).await.unwrap();
        fs::write(web.join("package.json"), r#"{"name":"web"}"#)
            .await
            .unwrap();
        let result = find_package_json_files(dir.path()).await;
        assert!(
            result
                .files
                .iter()
                .any(|f| f.is_workspace && f.path.ends_with("apps/package.json")),
            "prefix dir's own package.json must be a member: {:?}",
            result.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert!(
            result
                .files
                .iter()
                .any(|f| f.is_workspace && f.path.ends_with("apps/web/package.json")),
            "descendant member must still be found"
        );
    }

    #[test]
    fn test_parse_pnpm_packages_key_inline_comment() {
        // The section header itself may carry an inline comment
        // (`packages: # workspace globs`); the exact-equality compare missed
        // it and silently dropped the whole section.
        let yaml = "packages: # workspace globs\n  - packages/*";
        assert_eq!(parse_pnpm_workspace_patterns(yaml), vec!["packages/*"]);
    }

    // ── detect_package_manager ──────────────────────────────────────

    #[tokio::test]
    async fn test_detect_npm_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let pm = detect_package_manager(dir.path()).await;
        assert_eq!(pm, PackageManager::Npm);
    }

    #[tokio::test]
    async fn test_detect_pnpm_lock_yaml() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pnpm-lock.yaml"), "lockfileVersion: 9.0\n")
            .await
            .unwrap();
        let pm = detect_package_manager(dir.path()).await;
        assert_eq!(pm, PackageManager::Pnpm);
    }

    #[tokio::test]
    async fn test_detect_pnpm_workspace_yaml() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*",
        )
        .await
        .unwrap();
        let pm = detect_package_manager(dir.path()).await;
        assert_eq!(pm, PackageManager::Pnpm);
    }
}
