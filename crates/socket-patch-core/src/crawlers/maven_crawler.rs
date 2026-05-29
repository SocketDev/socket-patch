use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};

// ---------------------------------------------------------------------------
// POM XML minimal parser
// ---------------------------------------------------------------------------

/// Extract the text value between `<element>` and `</element>` on a single line.
fn extract_xml_value(line: &str, element: &str) -> Option<String> {
    let open = format!("<{element}>");
    let close = format!("</{element}>");
    let start = line.find(&open)?;
    let value_start = start + open.len();
    let end = line[value_start..].find(&close)?;
    let value = line[value_start..value_start + end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Strip the commented-out portions of a single line, threading the
/// `in_comment` state across lines so multi-line `<!-- ... -->` blocks are
/// handled. XML comments do not nest, so we always close on the first `-->`.
///
/// This runs before any tag matching: POM files routinely carry license
/// headers and commented-out `<dependency>`/`<build>` snippets, and naive
/// substring matching would otherwise miscount skip-section depth (e.g. a
/// comment containing `</build>` could "close" a block that is still open
/// and leak a plugin's coordinates as the project's).
fn strip_comment_spans(line: &str, in_comment: &mut bool) -> String {
    let mut out = String::new();
    let mut rest = line;
    loop {
        if *in_comment {
            match rest.find("-->") {
                Some(end) => {
                    rest = &rest[end + 3..];
                    *in_comment = false;
                }
                None => return out, // remainder of the line is inside a comment
            }
        } else {
            match rest.find("<!--") {
                Some(start) => {
                    out.push_str(&rest[..start]);
                    rest = &rest[start + 4..];
                    *in_comment = true;
                }
                None => {
                    out.push_str(rest);
                    return out;
                }
            }
        }
    }
}

/// Does the opening tag for `element` on this line self-close
/// (e.g. `<dependencies/>` or `<dependencies foo="x"/>`)? Such a tag opens
/// and closes in one shot and must not change the skip-section depth.
fn opening_tag_self_closes(line: &str, element: &str) -> bool {
    let open = format!("<{element}");
    let Some(pos) = line.find(&open) else {
        return false;
    };
    let after = &line[pos + open.len()..];
    match after.find('>') {
        Some(gt) => after[..gt].trim_end().ends_with('/'),
        None => false,
    }
}

/// Parse `groupId`, `artifactId`, and `version` from a POM XML file.
///
/// Uses a simple line-based parser — no XML crate dependency.
/// Tracks nesting depth to skip `<dependencies>`, `<build>`, `<profiles>`, etc.
/// Extracts top-level `<groupId>`, `<artifactId>`, `<version>` from `<project>`.
/// Falls back to `<parent>` block for groupId if missing at top level.
/// Returns `None` for property references (`${...}`).
pub fn parse_pom_group_artifact_version(content: &str) -> Option<(String, String, String)> {
    let mut group_id: Option<String> = None;
    let mut artifact_id: Option<String> = None;
    let mut version: Option<String> = None;
    let mut parent_group_id: Option<String> = None;

    let mut in_parent = false;
    let mut in_comment = false;
    let mut skip_depth: u32 = 0;

    let skip_sections = [
        "dependencies",
        "build",
        "profiles",
        "reporting",
        "dependencyManagement",
        "pluginManagement",
        "modules",
        "distributionManagement",
        "repositories",
        "pluginRepositories",
    ];

    for line in content.lines() {
        let cleaned = strip_comment_spans(line, &mut in_comment);
        let trimmed = cleaned.trim();

        // Check for skip section open/close. A tag that opens and closes on
        // the same line (`<modules></modules>`) or self-closes
        // (`<dependencies/>`) leaves the depth unchanged; only a lone open
        // increments and a lone close decrements.
        for section in &skip_sections {
            let open_tag = format!("<{section}");
            let close_tag = format!("</{section}>");
            let has_open = trimmed.contains(&open_tag);
            let has_close = trimmed.contains(&close_tag);
            if has_open && !has_close && !opening_tag_self_closes(trimmed, section) {
                skip_depth += 1;
            } else if has_close && !has_open {
                skip_depth = skip_depth.saturating_sub(1);
            }
        }

        if skip_depth > 0 {
            continue;
        }

        // Track parent section (a self-closing `<parent/>` carries no
        // coordinates, so it never opens a parent block).
        if trimmed.contains("<parent")
            && !trimmed.contains("</parent")
            && !opening_tag_self_closes(trimmed, "parent")
        {
            in_parent = true;
            continue;
        }
        if trimmed.contains("</parent>") {
            in_parent = false;
            continue;
        }

        if in_parent {
            if parent_group_id.is_none() {
                if let Some(val) = extract_xml_value(trimmed, "groupId") {
                    if val.contains("${") {
                        // Property reference in parent — skip
                    } else {
                        parent_group_id = Some(val);
                    }
                }
            }
            continue;
        }

        // Extract top-level coordinates
        if group_id.is_none() {
            if let Some(val) = extract_xml_value(trimmed, "groupId") {
                if val.contains("${") {
                    return None;
                }
                group_id = Some(val);
            }
        }
        if artifact_id.is_none() {
            if let Some(val) = extract_xml_value(trimmed, "artifactId") {
                if val.contains("${") {
                    return None;
                }
                artifact_id = Some(val);
            }
        }
        if version.is_none() {
            if let Some(val) = extract_xml_value(trimmed, "version") {
                if val.contains("${") {
                    return None;
                }
                version = Some(val);
            }
        }
    }

    // Fall back to parent groupId
    let final_group_id = group_id.or(parent_group_id)?;
    let final_artifact_id = artifact_id?;
    let final_version = version?;

    if final_group_id.is_empty() || final_artifact_id.is_empty() || final_version.is_empty() {
        return None;
    }

    Some((final_group_id, final_artifact_id, final_version))
}

// ---------------------------------------------------------------------------
// Path coordinate helpers
// ---------------------------------------------------------------------------

/// Convert a Maven groupId to a path segment (e.g. `org.apache.commons` -> `org/apache/commons`).
fn group_id_to_path(group_id: &str) -> String {
    group_id.replace('.', "/")
}

/// Extract Maven coordinates from a directory path relative to the repository root.
///
/// The Maven repository layout is: `<groupId-as-path>/<artifactId>/<version>/`
/// e.g. `org/apache/commons/commons-lang3/3.12.0/`
fn parse_path_coordinates(
    version_dir: &Path,
    repo_root: &Path,
) -> Option<(String, String, String)> {
    let rel = version_dir.strip_prefix(repo_root).ok()?;
    let components: Vec<&str> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    if components.len() < 3 {
        return None;
    }

    let version = components[components.len() - 1].to_string();
    let artifact_id = components[components.len() - 2].to_string();
    let group_parts = &components[..components.len() - 2];
    let group_id = group_parts.join(".");

    if group_id.is_empty() || artifact_id.is_empty() || version.is_empty() {
        return None;
    }

    Some((group_id, artifact_id, version))
}

// ---------------------------------------------------------------------------
// MavenCrawler
// ---------------------------------------------------------------------------

/// Maven/Java ecosystem crawler for discovering packages in the local
/// Maven repository (`~/.m2/repository/`).
pub struct MavenCrawler;

impl MavenCrawler {
    /// Create a new `MavenCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get Maven repository paths based on options.
    ///
    /// In global mode, returns `~/.m2/repository/` (respects `$M2_HOME`,
    /// `$MAVEN_REPO_LOCAL`, `--global-prefix`).
    ///
    /// In local mode, only returns the Maven repo if the cwd contains
    /// `pom.xml`, `build.gradle`, `build.gradle.kts`, `settings.gradle`,
    /// or `settings.gradle.kts` (prevents scanning for non-Java projects).
    pub async fn get_maven_repo_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            let repo = Self::m2_repo_path();
            if is_dir(&repo).await {
                return Ok(vec![repo]);
            }
            return Ok(Vec::new());
        }

        // Local mode: only return Maven repo if this looks like a Java/Maven/Gradle project
        let java_markers = [
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
        ];

        let mut is_java_project = false;
        for marker in &java_markers {
            if tokio::fs::metadata(options.cwd.join(marker)).await.is_ok() {
                is_java_project = true;
                break;
            }
        }

        if !is_java_project {
            return Ok(Vec::new());
        }

        let repo = Self::m2_repo_path();
        if is_dir(&repo).await {
            Ok(vec![repo])
        } else {
            Ok(Vec::new())
        }
    }

    /// Crawl all discovered Maven repository paths and return every
    /// package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let repo_paths = self.get_maven_repo_paths(options).await.unwrap_or_default();

        for repo_path in &repo_paths {
            let found = self.scan_maven_repo(repo_path, &mut seen);
            packages.extend(found);
        }

        packages
    }

    /// Find specific packages by PURL inside a single Maven repository path.
    ///
    /// For each PURL, constructs the expected path:
    /// `src_path / groupId.replace('.', '/') / artifactId / version /`
    /// and verifies by checking for a `.pom` file.
    pub async fn find_by_purls(
        &self,
        src_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            if let Some((group_id, artifact_id, version)) =
                crate::utils::purl::parse_maven_purl(purl)
            {
                let expected_path = src_path
                    .join(group_id_to_path(group_id))
                    .join(artifact_id)
                    .join(version);

                if self
                    .verify_maven_at_path(&expected_path, group_id, artifact_id, version)
                    .await
                {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: artifact_id.to_string(),
                            version: version.to_string(),
                            namespace: Some(group_id.to_string()),
                            purl: purl.clone(),
                            path: expected_path,
                        },
                    );
                }
            }
        }

        Ok(result)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// Get the Maven local repository path.
    ///
    /// Checks `$MAVEN_REPO_LOCAL`, `$M2_HOME/repository`, `$HOME/.m2/repository`.
    fn m2_repo_path() -> PathBuf {
        if let Ok(repo_local) = std::env::var("MAVEN_REPO_LOCAL") {
            return PathBuf::from(repo_local);
        }
        if let Ok(m2_home) = std::env::var("M2_HOME") {
            return PathBuf::from(m2_home).join("repository");
        }
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "~".to_string());
        PathBuf::from(home).join(".m2").join("repository")
    }

    /// Scan a Maven repository directory and return all valid packages found.
    ///
    /// Uses `walkdir` to recursively find `.pom` files, then extracts
    /// coordinates from the POM content or falls back to directory path parsing.
    fn scan_maven_repo(&self, repo_path: &Path, seen: &mut HashSet<String>) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for entry in walkdir::WalkDir::new(repo_path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "pom") {
                continue;
            }

            let version_dir = match path.parent() {
                Some(p) => p,
                None => continue,
            };

            // Try POM parsing first, fall back to directory path parsing
            let coords = std::fs::read_to_string(path)
                .ok()
                .and_then(|content| parse_pom_group_artifact_version(&content))
                .or_else(|| parse_path_coordinates(version_dir, repo_path));

            if let Some((group_id, artifact_id, version)) = coords {
                let purl = crate::utils::purl::build_maven_purl(&group_id, &artifact_id, &version);
                if seen.insert(purl.clone()) {
                    results.push(CrawledPackage {
                        name: artifact_id,
                        version,
                        namespace: Some(group_id),
                        purl,
                        path: version_dir.to_path_buf(),
                    });
                }
            }
        }

        results
    }

    /// Verify that a Maven package directory contains a `.pom` file
    /// with the expected coordinates.
    async fn verify_maven_at_path(
        &self,
        path: &Path,
        _group_id: &str,
        _artifact_id: &str,
        _version: &str,
    ) -> bool {
        // The path already encodes the coordinates (groupId/artifactId/version),
        // so we just need to verify a .pom file exists here.
        self.has_pom_file(path).await
    }

    /// Check if a directory contains at least one `.pom` file.
    async fn has_pom_file(&self, path: &Path) -> bool {
        if !is_dir(path).await {
            return false;
        }
        crate::utils::fs::list_dir_entries(path)
            .await
            .iter()
            .any(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .map(|n| n.ends_with(".pom"))
                    .unwrap_or(false)
            })
    }
}

impl Default for MavenCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Check whether a path is a directory.
async fn is_dir(path: &Path) -> bool {
    tokio::fs::metadata(path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- POM parsing tests ----

    #[test]
    fn test_parse_pom_basic() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "org.apache.commons");
        assert_eq!(a, "commons-lang3");
        assert_eq!(v, "3.12.0");
    }

    #[test]
    fn test_parse_pom_with_parent_group() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>org.apache</groupId>
    <artifactId>apache</artifactId>
    <version>30</version>
  </parent>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "org.apache");
        assert_eq!(a, "commons-lang3");
        assert_eq!(v, "3.12.0");
    }

    #[test]
    fn test_parse_pom_skips_dependencies() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.other</groupId>
      <artifactId>other-lib</artifactId>
      <version>2.0.0</version>
    </dependency>
  </dependencies>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-app");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_parse_pom_property_reference_returns_none() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>${project.version}</version>
</project>"#;
        assert!(parse_pom_group_artifact_version(content).is_none());
    }

    #[test]
    fn test_parse_pom_missing_version_returns_none() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
</project>"#;
        assert!(parse_pom_group_artifact_version(content).is_none());
    }

    #[test]
    fn test_parse_pom_group_id_from_parent_and_top_level() {
        // When both project and parent have groupId, use project-level
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <parent>
    <groupId>org.parent</groupId>
  </parent>
  <groupId>org.child</groupId>
  <artifactId>my-lib</artifactId>
  <version>2.0.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "org.child");
        assert_eq!(a, "my-lib");
        assert_eq!(v, "2.0.0");
    }

    #[test]
    fn test_parse_pom_skips_build_section() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
      </plugin>
    </plugins>
  </build>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-app");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_parse_pom_comment_does_not_leak_skip_section_close() {
        // A comment containing `</build>` must NOT be treated as the real
        // close of the `<build>` block. Otherwise the parser would "exit"
        // the build section early and pick up a plugin's groupId/version as
        // the project's coordinates.
        let content = r#"<project>
  <artifactId>my-app</artifactId>
  <build>
    <!-- end of </build> goes here -->
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.11.0</version>
      </plugin>
    </plugins>
  </build>
  <groupId>com.example</groupId>
  <version>1.0.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-app");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_parse_pom_commented_out_dependencies_block() {
        // A commented-out `<dependencies>` block (no real close tag) must not
        // start skipping the rest of the file.
        let content = r#"<project>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <!-- TODO re-enable <dependencies> later -->
  <version>1.0.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-app");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_parse_pom_multiline_comment() {
        // A comment spanning multiple lines that mentions skip-section tags
        // must be ignored entirely.
        let content = r#"<project>
  <!--
    This module used to declare <dependencies> and a custom <build>.
    Removed for now; see ticket ABC-123.
  -->
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-app");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_parse_pom_self_closing_skip_section() {
        // A self-closing `<dependencies/>` opens and closes at once and must
        // not swallow the coordinates that follow it.
        let content = r#"<project>
  <dependencies/>
  <groupId>com.example</groupId>
  <artifactId>my-app</artifactId>
  <version>1.0.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-app");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_parse_pom_inline_skip_section_does_not_unbalance_depth() {
        // An inline `<modules></modules>` nested inside `<profiles>` must not
        // spuriously decrement the depth and leak the profile's dependency
        // coordinates.
        let content = r#"<project>
  <artifactId>my-app</artifactId>
  <profiles>
    <profile>
      <modules></modules>
      <dependencies>
        <dependency>
          <groupId>org.leak</groupId>
          <artifactId>leak</artifactId>
          <version>9.9.9</version>
        </dependency>
      </dependencies>
    </profile>
  </profiles>
  <groupId>com.example</groupId>
  <version>1.0.0</version>
</project>"#;
        let (g, a, v) = parse_pom_group_artifact_version(content).unwrap();
        assert_eq!(g, "com.example");
        assert_eq!(a, "my-app");
        assert_eq!(v, "1.0.0");
    }

    #[test]
    fn test_scan_maven_repo_comment_pom_falls_back_to_path() {
        // End-to-end: a POM whose own coordinates can't be trusted (here a
        // leaky comment) must still resolve to the correct PURL — either by
        // parsing correctly or by falling back to the on-disk path.
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir
            .path()
            .join("com")
            .join("example")
            .join("my-app")
            .join("1.0.0");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("my-app-1.0.0.pom"),
            r#"<project>
  <artifactId>my-app</artifactId>
  <build>
    <!-- close </build> -->
    <plugins><plugin>
      <groupId>org.leak</groupId>
      <artifactId>leak</artifactId>
      <version>6.6.6</version>
    </plugin></plugins>
  </build>
  <groupId>com.example</groupId>
  <version>1.0.0</version>
</project>"#,
        )
        .unwrap();

        let crawler = MavenCrawler::new();
        let mut seen = HashSet::new();
        let pkgs = crawler.scan_maven_repo(dir.path(), &mut seen);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl, "pkg:maven/com.example/my-app@1.0.0");
    }

    // ---- extract_xml_value tests ----

    #[test]
    fn test_extract_xml_value() {
        assert_eq!(
            extract_xml_value("  <groupId>org.apache</groupId>", "groupId"),
            Some("org.apache".to_string())
        );
        assert_eq!(
            extract_xml_value("  <version>1.0.0</version>", "version"),
            Some("1.0.0".to_string())
        );
        assert_eq!(extract_xml_value("  <other>foo</other>", "groupId"), None);
        assert_eq!(extract_xml_value("  <groupId></groupId>", "groupId"), None);
    }

    // ---- group_id_to_path tests ----

    #[test]
    fn test_group_id_to_path() {
        assert_eq!(group_id_to_path("org.apache.commons"), "org/apache/commons");
        assert_eq!(group_id_to_path("com.google.guava"), "com/google/guava");
        assert_eq!(group_id_to_path("single"), "single");
    }

    // ---- parse_path_coordinates tests ----

    #[test]
    fn test_parse_path_coordinates() {
        let repo = Path::new("/home/user/.m2/repository");
        let version_dir =
            Path::new("/home/user/.m2/repository/org/apache/commons/commons-lang3/3.12.0");
        let (g, a, v) = parse_path_coordinates(version_dir, repo).unwrap();
        assert_eq!(g, "org.apache.commons");
        assert_eq!(a, "commons-lang3");
        assert_eq!(v, "3.12.0");
    }

    #[test]
    fn test_parse_path_coordinates_short_path() {
        let repo = Path::new("/repo");
        let version_dir = Path::new("/repo/foo/bar");
        // Only 2 components — not enough (need at least groupId/artifactId/version)
        assert!(parse_path_coordinates(version_dir, repo).is_none());
    }

    // ---- find_by_purls tests ----

    #[tokio::test]
    async fn test_find_by_purls_maven() {
        let dir = tempfile::tempdir().unwrap();

        // Create Maven repo layout: org/apache/commons/commons-lang3/3.12.0/
        let pkg_dir = dir
            .path()
            .join("org")
            .join("apache")
            .join("commons")
            .join("commons-lang3")
            .join("3.12.0");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("commons-lang3-3.12.0.pom"),
            r#"<project>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#,
        )
        .await
        .unwrap();

        let crawler = MavenCrawler::new();
        let purls = vec![
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0".to_string(),
            "pkg:maven/com.google.guava/guava@32.1.3-jre".to_string(),
        ];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:maven/org.apache.commons/commons-lang3@3.12.0"));
        assert!(!result.contains_key("pkg:maven/com.google.guava/guava@32.1.3-jre"));

        let pkg = &result["pkg:maven/org.apache.commons/commons-lang3@3.12.0"];
        assert_eq!(pkg.name, "commons-lang3");
        assert_eq!(pkg.version, "3.12.0");
        assert_eq!(pkg.namespace, Some("org.apache.commons".to_string()));
    }

    // ---- crawl_all tests ----

    #[tokio::test]
    async fn test_crawl_all_maven() {
        let dir = tempfile::tempdir().unwrap();

        // Create two Maven packages
        let pkg1_dir = dir
            .path()
            .join("org")
            .join("apache")
            .join("commons")
            .join("commons-lang3")
            .join("3.12.0");
        tokio::fs::create_dir_all(&pkg1_dir).await.unwrap();
        tokio::fs::write(
            pkg1_dir.join("commons-lang3-3.12.0.pom"),
            r#"<project>
  <groupId>org.apache.commons</groupId>
  <artifactId>commons-lang3</artifactId>
  <version>3.12.0</version>
</project>"#,
        )
        .await
        .unwrap();

        let pkg2_dir = dir
            .path()
            .join("com")
            .join("google")
            .join("guava")
            .join("guava")
            .join("32.1.3-jre");
        tokio::fs::create_dir_all(&pkg2_dir).await.unwrap();
        tokio::fs::write(
            pkg2_dir.join("guava-32.1.3-jre.pom"),
            r#"<project>
  <groupId>com.google.guava</groupId>
  <artifactId>guava</artifactId>
  <version>32.1.3-jre</version>
</project>"#,
        )
        .await
        .unwrap();

        let crawler = MavenCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:maven/org.apache.commons/commons-lang3@3.12.0"));
        assert!(purls.contains("pkg:maven/com.google.guava/guava@32.1.3-jre"));
    }

    #[tokio::test]
    async fn test_crawl_all_deduplication() {
        let dir = tempfile::tempdir().unwrap();

        // Create one package
        let pkg_dir = dir
            .path()
            .join("com")
            .join("example")
            .join("my-lib")
            .join("1.0.0");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("my-lib-1.0.0.pom"),
            r#"<project>
  <groupId>com.example</groupId>
  <artifactId>my-lib</artifactId>
  <version>1.0.0</version>
</project>"#,
        )
        .await
        .unwrap();

        let crawler = MavenCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:maven/com.example/my-lib@1.0.0");
    }

    #[tokio::test]
    async fn test_crawl_fallback_to_path_parsing() {
        let dir = tempfile::tempdir().unwrap();

        // Create package with POM that has property references (can't parse)
        let pkg_dir = dir
            .path()
            .join("com")
            .join("example")
            .join("my-lib")
            .join("2.0.0");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("my-lib-2.0.0.pom"),
            r#"<project>
  <groupId>com.example</groupId>
  <artifactId>my-lib</artifactId>
  <version>${project.version}</version>
</project>"#,
        )
        .await
        .unwrap();

        let crawler = MavenCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:maven/com.example/my-lib@2.0.0");
        assert_eq!(packages[0].name, "my-lib");
        assert_eq!(packages[0].namespace, Some("com.example".to_string()));
    }

    #[tokio::test]
    async fn test_get_maven_repo_paths_not_java_project() {
        let dir = tempfile::tempdir().unwrap();
        // No pom.xml or build.gradle — should return empty
        let crawler = MavenCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: 100,
        };

        let paths = crawler.get_maven_repo_paths(&options).await.unwrap();
        assert!(paths.is_empty());
    }

    #[tokio::test]
    async fn test_get_maven_repo_paths_with_global_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let crawler = MavenCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let paths = crawler.get_maven_repo_paths(&options).await.unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], dir.path().to_path_buf());
    }
}
