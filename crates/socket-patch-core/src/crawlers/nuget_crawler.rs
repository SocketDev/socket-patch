use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};

/// NuGet/.NET ecosystem crawler for discovering packages in global cache,
/// legacy `packages/` folders, and `obj/` restore layouts.
pub struct NuGetCrawler;

impl NuGetCrawler {
    /// Create a new `NuGetCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get NuGet package paths based on options.
    ///
    /// In global mode, returns the global NuGet packages folder
    /// (`NUGET_PACKAGES` env var or `~/.nuget/packages/`).
    ///
    /// In local mode (in priority order):
    /// 1. `<cwd>/packages/` folder (legacy packages.config layout)
    /// 2. Global cache — but only if cwd contains a .NET project file
    /// 3. Paths discovered from `obj/project.assets.json`
    pub async fn get_nuget_package_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            let home = nuget_home();
            if is_dir(&home).await {
                return Ok(vec![home]);
            }
            return Ok(Vec::new());
        }

        let mut paths = Vec::new();
        let mut seen = HashSet::new();

        // 1. Check <cwd>/packages/ (legacy packages.config layout)
        let packages_dir = options.cwd.join("packages");
        if is_dir(&packages_dir).await && seen.insert(packages_dir.clone()) {
            paths.push(packages_dir);
        }

        // 2. Fall back to global cache if this looks like a .NET project
        if is_dotnet_project(&options.cwd).await {
            let home = nuget_home();
            if is_dir(&home).await && seen.insert(home.clone()) {
                paths.push(home);
            }
        }

        // 3. Check obj/ dirs for project.assets.json
        let obj_paths = discover_paths_from_assets(&options.cwd).await;
        for p in obj_paths {
            if is_dir(&p).await && seen.insert(p.clone()) {
                paths.push(p);
            }
        }

        Ok(paths)
    }

    /// Crawl all discovered package paths and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let pkg_paths = self.get_nuget_package_paths(options).await.unwrap_or_default();

        for pkg_path in &pkg_paths {
            let found = self.scan_package_dir(pkg_path, &mut seen).await;
            packages.extend(found);
        }

        packages
    }

    /// Find specific packages by PURL inside a single package directory.
    pub async fn find_by_purls(
        &self,
        pkg_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            if let Some((name, version)) = crate::utils::purl::parse_nuget_purl(purl) {
                // Try global cache layout: <lowercase-name>/<version>/
                let global_dir = pkg_path.join(name.to_lowercase()).join(version);
                if self.verify_nuget_package(&global_dir).await {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: None,
                            purl: purl.clone(),
                            path: global_dir,
                        },
                    );
                    continue;
                }

                // Try legacy layout: <Name>.<Version>/
                let legacy_dir = pkg_path.join(format!("{name}.{version}"));
                if self.verify_nuget_package(&legacy_dir).await {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: None,
                            purl: purl.clone(),
                            path: legacy_dir,
                        },
                    );
                    continue;
                }

                // Try case-insensitive legacy scan (NuGet names are case-insensitive)
                if let Some(found_dir) = self
                    .find_legacy_dir_case_insensitive(pkg_path, name, version)
                    .await
                {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: None,
                            purl: purl.clone(),
                            path: found_dir,
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

    /// Scan a package directory and return all valid NuGet packages found.
    ///
    /// Handles both layouts:
    /// - Global cache: `<name>/<version>/` with `.nuspec` inside
    /// - Legacy packages/: `<Name>.<Version>/` with `.nuspec` inside
    async fn scan_package_dir(
        &self,
        pkg_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        let mut entries = match tokio::fs::read_dir(pkg_path).await {
            Ok(rd) => rd,
            Err(_) => return results,
        };

        let mut entry_list = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            entry_list.push(entry);
        }

        for entry in entry_list {
            let ft = match entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if !ft.is_dir() {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            // Skip hidden directories
            if dir_name_str.starts_with('.') {
                continue;
            }

            let entry_path = pkg_path.join(&*dir_name_str);

            // Try global cache layout: this directory is a package name,
            // containing version subdirectories
            if let Some(pkgs) = self
                .scan_global_cache_package(&entry_path, &dir_name_str, seen)
                .await
            {
                results.extend(pkgs);
                continue;
            }

            // Try legacy layout: <Name>.<Version>/ directory
            if let Some((name, version)) = parse_legacy_dir_name(&dir_name_str) {
                if self.verify_nuget_package(&entry_path).await {
                    let purl = crate::utils::purl::build_nuget_purl(&name, &version);
                    if !seen.contains(&purl) {
                        seen.insert(purl.clone());
                        results.push(CrawledPackage {
                            name,
                            version,
                            namespace: None,
                            purl,
                            path: entry_path,
                        });
                    }
                }
            }
        }

        results
    }

    /// Scan a global cache package directory (`<name>/`) for version subdirectories.
    async fn scan_global_cache_package(
        &self,
        name_dir: &Path,
        name: &str,
        seen: &mut HashSet<String>,
    ) -> Option<Vec<CrawledPackage>> {
        let mut version_entries = match tokio::fs::read_dir(name_dir).await {
            Ok(rd) => rd,
            Err(_) => return None,
        };

        let mut found_any = false;
        let mut results = Vec::new();

        while let Ok(Some(ver_entry)) = version_entries.next_entry().await {
            let ft = match ver_entry.file_type().await {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if !ft.is_dir() {
                continue;
            }

            let ver_name = ver_entry.file_name();
            let ver_str = ver_name.to_string_lossy();
            let ver_path = name_dir.join(&*ver_str);

            if self.verify_nuget_package(&ver_path).await {
                found_any = true;
                let purl = crate::utils::purl::build_nuget_purl(name, &ver_str);
                if !seen.contains(&purl) {
                    seen.insert(purl.clone());
                    results.push(CrawledPackage {
                        name: name.to_string(),
                        version: ver_str.to_string(),
                        namespace: None,
                        purl,
                        path: ver_path,
                    });
                }
            }
        }

        if found_any {
            Some(results)
        } else {
            None
        }
    }

    /// Verify that a directory looks like an installed NuGet package.
    /// Checks for a `.nuspec` file or a `lib/` directory.
    async fn verify_nuget_package(&self, path: &Path) -> bool {
        if !is_dir(path).await {
            return false;
        }

        // Check for lib/ directory
        if is_dir(&path.join("lib")).await {
            return true;
        }

        // Check for any .nuspec file
        find_nuspec_in_dir(path).await.is_some()
    }

    /// Find a legacy package directory with case-insensitive matching.
    async fn find_legacy_dir_case_insensitive(
        &self,
        pkg_path: &Path,
        name: &str,
        version: &str,
    ) -> Option<PathBuf> {
        let target = format!("{}.{}", name.to_lowercase(), version.to_lowercase());

        let mut entries = tokio::fs::read_dir(pkg_path).await.ok()?;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();
            if dir_name_str.to_lowercase() == target {
                let path = pkg_path.join(&*dir_name_str);
                if self.verify_nuget_package(&path).await {
                    return Some(path);
                }
            }
        }

        None
    }
}

impl Default for NuGetCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the NuGet global packages folder.
///
/// Checks `NUGET_PACKAGES` env var, falls back to `~/.nuget/packages/`.
fn nuget_home() -> PathBuf {
    if let Ok(custom) = std::env::var("NUGET_PACKAGES") {
        return PathBuf::from(custom);
    }

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "~".to_string());
    PathBuf::from(home).join(".nuget").join("packages")
}

/// Check if the cwd contains any .NET project indicators.
async fn is_dotnet_project(cwd: &Path) -> bool {
    let extensions = [".csproj", ".fsproj", ".vbproj", ".sln"];

    let mut entries = match tokio::fs::read_dir(cwd).await {
        Ok(rd) => rd,
        Err(_) => return false,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Some(name) = entry.file_name().to_str() {
            for ext in &extensions {
                if name.ends_with(ext) {
                    return true;
                }
            }
            if name == "NuGet.Config" || name == "nuget.config" {
                return true;
            }
        }
    }

    false
}

/// Parse a legacy packages directory name into (name, version).
///
/// Legacy NuGet directories follow the pattern `<Name>.<Version>`, where
/// the version starts at the last `.` followed by a digit-starting segment.
fn parse_legacy_dir_name(dir_name: &str) -> Option<(String, String)> {
    // Find the first '.' followed by a digit
    let mut split_idx = None;
    for (i, _) in dir_name.match_indices('.') {
        if i + 1 < dir_name.len() && dir_name[i + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            split_idx = Some(i);
            break;
        }
    }
    let idx = split_idx?;
    let name = &dir_name[..idx];
    let version = &dir_name[idx + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Find a `.nuspec` file in a directory.
async fn find_nuspec_in_dir(dir: &Path) -> Option<PathBuf> {
    let mut entries = tokio::fs::read_dir(dir).await.ok()?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".nuspec") {
                return Some(dir.join(name));
            }
        }
    }
    None
}

/// Parse `<id>` and `<version>` from `.nuspec` XML content.
///
/// Uses simple string matching — the nuspec format always has these
/// elements on separate lines.
pub fn parse_nuspec_id_version(content: &str) -> Option<(String, String)> {
    let mut id = None;
    let mut version = None;

    for line in content.lines() {
        let trimmed = line.trim();

        if id.is_none() {
            if let Some(value) = extract_xml_element(trimmed, "id") {
                id = Some(value);
            }
        }

        if version.is_none() {
            if let Some(value) = extract_xml_element(trimmed, "version") {
                version = Some(value);
            }
        }

        if id.is_some() && version.is_some() {
            break;
        }
    }

    match (id, version) {
        (Some(id), Some(version)) if !id.is_empty() && !version.is_empty() => {
            Some((id, version))
        }
        _ => None,
    }
}

/// Extract the text content of a simple XML element like `<tag>value</tag>`.
fn extract_xml_element(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");

    let start = line.find(&open)?;
    let after_open = start + open.len();
    let end = line[after_open..].find(&close)?;
    let value = &line[after_open..after_open + end];
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// Discover additional package paths from `obj/project.assets.json` files.
async fn discover_paths_from_assets(cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Look for obj/project.assets.json in cwd
    let assets_path = cwd.join("obj").join("project.assets.json");
    if let Some(pkg_folder) = parse_project_assets_package_folders(&assets_path).await {
        for folder in pkg_folder {
            paths.push(folder);
        }
    }

    // Also check subdirectories one level deep for multi-project solutions
    let mut entries = match tokio::fs::read_dir(cwd).await {
        Ok(rd) => rd,
        Err(_) => return paths,
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let ft = match entry.file_type().await {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        if !ft.is_dir() {
            continue;
        }
        let sub_assets = cwd.join(entry.file_name()).join("obj").join("project.assets.json");
        if let Some(pkg_folders) = parse_project_assets_package_folders(&sub_assets).await {
            for folder in pkg_folders {
                paths.push(folder);
            }
        }
    }

    paths
}

/// Parse `project.assets.json` to extract the `packageFolders` keys.
///
/// The file is a JSON object with a `packageFolders` key containing
/// folder paths as keys, e.g.: `{"packageFolders": {"/home/user/.nuget/packages/": {}}}`.
async fn parse_project_assets_package_folders(path: &Path) -> Option<Vec<PathBuf>> {
    let content = tokio::fs::read_to_string(path).await.ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    let folders = json.get("packageFolders")?.as_object()?;

    let result: Vec<PathBuf> = folders.keys().map(PathBuf::from).collect();

    if result.is_empty() {
        None
    } else {
        Some(result)
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

    #[test]
    fn test_parse_legacy_dir_name() {
        assert_eq!(
            parse_legacy_dir_name("Newtonsoft.Json.13.0.3"),
            Some(("Newtonsoft.Json".to_string(), "13.0.3".to_string()))
        );
        assert_eq!(
            parse_legacy_dir_name("System.Text.Json.8.0.0"),
            Some(("System.Text.Json".to_string(), "8.0.0".to_string()))
        );
        assert_eq!(
            parse_legacy_dir_name("Microsoft.Extensions.Logging.8.0.0"),
            Some((
                "Microsoft.Extensions.Logging".to_string(),
                "8.0.0".to_string()
            ))
        );
        assert_eq!(
            parse_legacy_dir_name("xunit.2.6.2"),
            Some(("xunit".to_string(), "2.6.2".to_string()))
        );
        assert!(parse_legacy_dir_name("no-version-here").is_none());
        assert!(parse_legacy_dir_name("justtext").is_none());
    }

    #[test]
    fn test_parse_nuspec_id_version() {
        let nuspec = r#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.3</version>
    <authors>James Newton-King</authors>
  </metadata>
</package>"#;
        assert_eq!(
            parse_nuspec_id_version(nuspec),
            Some(("Newtonsoft.Json".to_string(), "13.0.3".to_string()))
        );
    }

    #[test]
    fn test_parse_nuspec_empty() {
        assert!(parse_nuspec_id_version("").is_none());
        assert!(parse_nuspec_id_version("<metadata></metadata>").is_none());
    }

    #[test]
    fn test_extract_xml_element() {
        assert_eq!(
            extract_xml_element("    <id>Newtonsoft.Json</id>", "id"),
            Some("Newtonsoft.Json".to_string())
        );
        assert_eq!(
            extract_xml_element("    <version>13.0.3</version>", "version"),
            Some("13.0.3".to_string())
        );
        assert_eq!(extract_xml_element("<id></id>", "id"), None);
        assert_eq!(extract_xml_element("no tags here", "id"), None);
    }

    #[tokio::test]
    async fn test_find_by_purls_global_cache_layout() {
        let dir = tempfile::tempdir().unwrap();

        // Create global cache layout: <lowercase-name>/<version>/
        let pkg_dir = dir.path().join("newtonsoft.json").join("13.0.3");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(
            pkg_dir.join("newtonsoft.json.nuspec"),
            r#"<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>"#,
        )
        .await
        .unwrap();

        let crawler = NuGetCrawler::new();
        let purls = vec![
            "pkg:nuget/Newtonsoft.Json@13.0.3".to_string(),
            "pkg:nuget/System.Text.Json@8.0.0".to_string(),
        ];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:nuget/Newtonsoft.Json@13.0.3"));
        assert!(!result.contains_key("pkg:nuget/System.Text.Json@8.0.0"));
    }

    #[tokio::test]
    async fn test_find_by_purls_legacy_layout() {
        let dir = tempfile::tempdir().unwrap();

        // Create legacy layout: <Name>.<Version>/
        let pkg_dir = dir.path().join("Newtonsoft.Json.13.0.3");
        tokio::fs::create_dir_all(pkg_dir.join("lib")).await.unwrap();

        let crawler = NuGetCrawler::new();
        let purls = vec!["pkg:nuget/Newtonsoft.Json@13.0.3".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:nuget/Newtonsoft.Json@13.0.3"));
    }

    #[tokio::test]
    async fn test_crawl_all_global_cache() {
        let dir = tempfile::tempdir().unwrap();

        // Create global cache layout
        let nj_dir = dir.path().join("newtonsoft.json").join("13.0.3");
        tokio::fs::create_dir_all(nj_dir.join("lib")).await.unwrap();

        let stj_dir = dir.path().join("system.text.json").join("8.0.0");
        tokio::fs::create_dir_all(&stj_dir).await.unwrap();
        tokio::fs::write(
            stj_dir.join("system.text.json.nuspec"),
            "<package><metadata><id>System.Text.Json</id><version>8.0.0</version></metadata></package>",
        )
        .await
        .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:nuget/newtonsoft.json@13.0.3"));
        assert!(purls.contains("pkg:nuget/system.text.json@8.0.0"));
    }

    #[tokio::test]
    async fn test_crawl_all_legacy_packages() {
        let dir = tempfile::tempdir().unwrap();

        // Create legacy layout
        let nj_dir = dir.path().join("Newtonsoft.Json.13.0.3");
        tokio::fs::create_dir_all(nj_dir.join("lib")).await.unwrap();

        let xunit_dir = dir.path().join("xunit.2.6.2");
        tokio::fs::create_dir_all(&xunit_dir).await.unwrap();
        tokio::fs::write(
            xunit_dir.join("xunit.nuspec"),
            "<package><metadata><id>xunit</id><version>2.6.2</version></metadata></package>",
        )
        .await
        .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:nuget/Newtonsoft.Json@13.0.3"));
        assert!(purls.contains("pkg:nuget/xunit@2.6.2"));
    }

    #[tokio::test]
    async fn test_is_dotnet_project() {
        let dir = tempfile::tempdir().unwrap();

        // No .NET files — should return false
        assert!(!super::is_dotnet_project(dir.path()).await);

        // Add a .csproj file
        tokio::fs::write(dir.path().join("MyApp.csproj"), "<Project/>")
            .await
            .unwrap();
        assert!(super::is_dotnet_project(dir.path()).await);
    }

    #[tokio::test]
    async fn test_is_dotnet_project_sln() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("MySolution.sln"), "")
            .await
            .unwrap();
        assert!(super::is_dotnet_project(dir.path()).await);
    }

    #[tokio::test]
    async fn test_verify_nuget_package_with_nuspec() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir.path().join("testpkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::write(pkg_dir.join("test.nuspec"), "<package/>")
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        assert!(crawler.verify_nuget_package(&pkg_dir).await);
    }

    #[tokio::test]
    async fn test_verify_nuget_package_with_lib() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir.path().join("testpkg");
        tokio::fs::create_dir_all(pkg_dir.join("lib")).await.unwrap();

        let crawler = NuGetCrawler::new();
        assert!(crawler.verify_nuget_package(&pkg_dir).await);
    }

    #[tokio::test]
    async fn test_verify_nuget_package_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir.path().join("testpkg");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();

        let crawler = NuGetCrawler::new();
        assert!(!crawler.verify_nuget_package(&pkg_dir).await);
    }

    #[tokio::test]
    async fn test_deduplication() {
        let dir = tempfile::tempdir().unwrap();

        // Create a single package
        let pkg_dir = dir.path().join("newtonsoft.json").join("13.0.3");
        tokio::fs::create_dir_all(pkg_dir.join("lib")).await.unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:nuget/newtonsoft.json@13.0.3");
    }

    #[tokio::test]
    async fn test_project_assets_discovery() {
        let dir = tempfile::tempdir().unwrap();

        // Create obj/project.assets.json
        let obj_dir = dir.path().join("obj");
        tokio::fs::create_dir_all(&obj_dir).await.unwrap();

        let pkg_folder = dir.path().join("custom-packages");
        tokio::fs::create_dir_all(&pkg_folder).await.unwrap();

        let assets_content = serde_json::json!({
            "packageFolders": {
                pkg_folder.to_string_lossy().to_string(): {}
            }
        });
        tokio::fs::write(
            obj_dir.join("project.assets.json"),
            serde_json::to_string(&assets_content).unwrap(),
        )
        .await
        .unwrap();

        let paths = discover_paths_from_assets(dir.path()).await;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], pkg_folder);
    }

    #[tokio::test]
    async fn test_nuget_home_env_var() {
        // Test that NUGET_PACKAGES env var is respected
        let custom = "/tmp/test-nuget-packages";
        std::env::set_var("NUGET_PACKAGES", custom);
        let home = nuget_home();
        assert_eq!(home, PathBuf::from(custom));
        std::env::remove_var("NUGET_PACKAGES");
    }
}
