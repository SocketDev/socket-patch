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
    /// In local mode, discovery is gated on `cwd` actually being a .NET
    /// project (see [`is_dotnet_project`]). When that gate passes, paths
    /// are returned in priority order:
    /// 1. `<cwd>/packages/` folder (legacy packages.config layout)
    /// 2. Global cache (`NUGET_PACKAGES` / `~/.nuget/packages/`)
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

        // Local discovery is gated on `cwd` actually being a .NET project.
        // A bare `packages/` directory is NOT NuGet-specific — `packages/`
        // is the conventional workspace layout for JS/TS monorepos (lerna,
        // pnpm, yarn, turborepo) — and `obj/project.assets.json` only ever
        // appears alongside a .NET project file. `crawl_all_ecosystems`
        // runs every crawler against the same `cwd`, so scanning these
        // paths without a .NET marker would misclassify another
        // ecosystem's tree as NuGet sources. Mirrors `CargoCrawler`'s
        // gate-first fix for the shared `vendor/` layout.
        if !is_dotnet_project(&options.cwd).await {
            return Ok(paths);
        }

        // 1. Check <cwd>/packages/ (legacy packages.config layout)
        let packages_dir = options.cwd.join("packages");
        if is_dir(&packages_dir).await && seen.insert(packages_dir.clone()) {
            paths.push(packages_dir);
        }

        // 2. Fall back to the global cache.
        let home = nuget_home();
        if is_dir(&home).await && seen.insert(home.clone()) {
            paths.push(home);
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

        let pkg_paths = self
            .get_nuget_package_paths(options)
            .await
            .unwrap_or_default();

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
                // Try global cache layout: <lowercase-name>/<lowercase-version>/.
                // NuGet lowercases BOTH the id and the version when it lays
                // out the global packages folder, so a prerelease tag like
                // `2.0.0-RC1` lives on disk as `2.0.0-rc1`. Lowercasing only
                // the name (but not the version) would miss those packages.
                let global_dir = pkg_path
                    .join(name.to_lowercase())
                    .join(version.to_lowercase());
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

        for entry in crate::utils::fs::list_dir_entries(pkg_path).await {
            if !crate::utils::fs::entry_is_dir(&entry).await {
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
        let mut found_any = false;
        let mut results = Vec::new();

        for ver_entry in crate::utils::fs::list_dir_entries(name_dir).await {
            if !crate::utils::fs::entry_is_dir(&ver_entry).await {
                continue;
            }

            let ver_name = ver_entry.file_name();
            let ver_str = ver_name.to_string_lossy();

            // A global-cache name directory contains only *version*
            // subdirectories, and a NuGet version always begins with a
            // numeric major component (SemVer). A legacy
            // `<Name>.<Version>/` package, by contrast, contains content
            // folders (`lib/`, `tools/`, `runtimes/`, `build/`, …), none
            // of which start with a digit. Without this shape check, a
            // legacy package whose content folder happens to verify (e.g.
            // a `tools/lib/` tool package missing its top-level `.nuspec`)
            // would be misread as a global-cache layout and emitted with a
            // garbage `@<folder>` version (e.g. `pkg:nuget/Foo.1.0.0@tools`)
            // — masking the real `pkg:nuget/Foo@1.0.0` the legacy branch
            // would otherwise produce.
            if !ver_str.starts_with(|c: char| c.is_ascii_digit()) {
                continue;
            }

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

        for entry in crate::utils::fs::list_dir_entries(pkg_path).await {
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

    for entry in crate::utils::fs::list_dir_entries(cwd).await {
        if let Some(name) = entry.file_name().to_str() {
            for ext in &extensions {
                if name.ends_with(ext) {
                    return true;
                }
            }
            // `packages.config` is the defining marker for the legacy
            // packages.config layout that pairs with `<cwd>/packages/`;
            // recognize it (and the NuGet config file) so the local-mode
            // gate admits those projects.
            if name == "NuGet.Config" || name == "nuget.config" || name == "packages.config" {
                return true;
            }
        }
    }
    false
}

/// Parse a legacy packages directory name into (name, version).
///
/// Legacy NuGet directories follow the pattern `<Name>.<Version>`, where
/// the version starts at the *first* `.` followed by a digit-starting
/// segment. NuGet versions always begin with a numeric major component,
/// and id segments don't start with a digit, so the first numeric-leading
/// segment marks the name/version boundary. Splitting on the *last* such
/// dot would wrongly carve `Newtonsoft.Json.13.0.3` into
/// `("Newtonsoft.Json.13.0", "3")`.
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
    for entry in crate::utils::fs::list_dir_entries(dir).await {
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".nuspec") {
                return Some(dir.join(name));
            }
        }
    }
    None
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
    for entry in crate::utils::fs::list_dir_entries(cwd).await {
        if !crate::utils::fs::entry_is_dir(&entry).await {
            continue;
        }
        let sub_assets = cwd
            .join(entry.file_name())
            .join("obj")
            .join("project.assets.json");
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
        tokio::fs::create_dir_all(pkg_dir.join("lib"))
            .await
            .unwrap();

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
        tokio::fs::create_dir_all(pkg_dir.join("lib"))
            .await
            .unwrap();

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
        tokio::fs::create_dir_all(pkg_dir.join("lib"))
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

    /// Regression: local-mode discovery must be gated on `cwd` being a
    /// .NET project. A JS/TS monorepo conventionally keeps a top-level
    /// `packages/` directory; because `crawl_all_ecosystems` runs every
    /// crawler against the same `cwd`, an ungated NuGet crawler would
    /// walk that JS `packages/` tree and report it as NuGet sources.
    #[tokio::test]
    async fn test_get_paths_skips_packages_dir_in_non_dotnet_project() {
        let dir = tempfile::tempdir().unwrap();

        // A bare `packages/` folder (e.g. a pnpm/lerna workspace) with no
        // .NET project marker present.
        tokio::fs::create_dir_all(dir.path().join("packages").join("some-js-lib"))
            .await
            .unwrap();
        // An `obj/project.assets.json` lookalike must also be ignored
        // without a .NET marker.
        let obj_dir = dir.path().join("obj");
        tokio::fs::create_dir_all(&obj_dir).await.unwrap();
        tokio::fs::write(
            obj_dir.join("project.assets.json"),
            r#"{"packageFolders":{"/tmp":{}}}"#,
        )
        .await
        .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: 100,
        };

        let paths = crawler.get_nuget_package_paths(&options).await.unwrap();
        assert!(
            paths.is_empty(),
            "non-.NET project must yield no local paths, got {paths:?}"
        );
    }

    /// Companion to the gate test: once a .NET project marker is present,
    /// the local `packages/` directory is discovered as before.
    #[tokio::test]
    async fn test_get_paths_finds_packages_dir_in_dotnet_project() {
        let dir = tempfile::tempdir().unwrap();

        tokio::fs::create_dir_all(dir.path().join("packages"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("MyApp.csproj"), "<Project/>")
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
            batch_size: 100,
        };

        let paths = crawler.get_nuget_package_paths(&options).await.unwrap();
        assert!(
            paths.contains(&dir.path().join("packages")),
            "a .NET project's packages/ dir must be discovered, got {paths:?}"
        );
    }

    /// A legacy packages.config project may not expose its `.csproj` at
    /// the scanned `cwd`, so `packages.config` itself must satisfy the
    /// .NET-project gate that admits the paired `packages/` folder.
    #[tokio::test]
    async fn test_packages_config_is_a_dotnet_marker() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!super::is_dotnet_project(dir.path()).await);

        tokio::fs::write(
            dir.path().join("packages.config"),
            r#"<?xml version="1.0"?><packages/>"#,
        )
        .await
        .unwrap();
        assert!(super::is_dotnet_project(dir.path()).await);
    }

    /// Regression: a well-formed legacy `<Name>.<Version>/` package that
    /// also ships a content folder containing a `lib/` (a common tool /
    /// runtime layout, e.g. `tools/lib/`) must still be reported with its
    /// real identity. Before the version-shape gate in
    /// `scan_global_cache_package`, the content folder verified and was
    /// mistaken for a version directory, so the package was emitted as a
    /// garbage `pkg:nuget/Foo.1.0.0@tools` and the real
    /// `pkg:nuget/Foo@1.0.0` (which the legacy branch would have produced)
    /// was lost to the `continue`.
    #[tokio::test]
    async fn test_legacy_pkg_with_nested_lib_folder_is_not_misparsed() {
        let dir = tempfile::tempdir().unwrap();

        let pkg = dir.path().join("Foo.1.0.0");
        // Top-level marker — this is a valid legacy package.
        tokio::fs::create_dir_all(pkg.join("lib")).await.unwrap();
        // A content folder that itself contains a lib/ dir. This is what
        // tripped the old global-cache heuristic.
        tokio::fs::create_dir_all(pkg.join("tools").join("lib"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let pkgs = crawler.crawl_all(&options).await;
        let purls: Vec<&str> = pkgs.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(
            purls,
            vec!["pkg:nuget/Foo@1.0.0"],
            "legacy package must report its real identity, not a content folder; got {pkgs:?}"
        );
    }

    /// Regression companion: a *malformed* legacy package (no top-level
    /// `lib/` or `.nuspec`, only a nested verifying content folder) must
    /// yield nothing rather than a garbage `@<folder>` package.
    #[tokio::test]
    async fn test_legacy_pkg_missing_marker_with_nested_lib_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();

        let pkg = dir.path().join("Foo.1.0.0");
        tokio::fs::create_dir_all(pkg.join("tools").join("lib"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
            batch_size: 100,
        };

        let pkgs = crawler.crawl_all(&options).await;
        assert!(
            pkgs.is_empty(),
            "an unverifiable legacy dir must not emit a garbage version; got {pkgs:?}"
        );
    }

    /// Guard the version-shape gate itself: a genuine global-cache package
    /// (whose version dir starts with a digit) must still be discovered,
    /// including multiple versions of the same id.
    #[tokio::test]
    async fn test_global_cache_multi_version_still_discovered() {
        let dir = tempfile::tempdir().unwrap();

        for v in ["13.0.1", "13.0.3"] {
            let p = dir.path().join("newtonsoft.json").join(v);
            tokio::fs::create_dir_all(p.join("lib")).await.unwrap();
        }
        // A non-version sibling dir under the id (should be ignored, not
        // emitted as `@tools`).
        tokio::fs::create_dir_all(
            dir.path()
                .join("newtonsoft.json")
                .join("tools")
                .join("lib"),
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

        let mut purls: Vec<String> = crawler
            .crawl_all(&options)
            .await
            .iter()
            .map(|p| p.purl.clone())
            .collect();
        purls.sort_unstable();
        assert_eq!(
            purls,
            vec![
                "pkg:nuget/newtonsoft.json@13.0.1".to_string(),
                "pkg:nuget/newtonsoft.json@13.0.3".to_string(),
            ],
            "both versions discovered, non-version sibling ignored"
        );
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

    /// `".1.0.0"` — first match-index of `.` is `i=0` (followed by
    /// `1`), `i+1 < dir_name.len()` is true, split_idx = Some(0).
    /// The name slice ends up empty; the defensive guard at the
    /// bottom of parse_legacy_dir_name rejects rather than producing
    /// a `("", "1.0.0")` ghost package. (Hidden dirs are skipped
    /// upstream in scan_package_dir, but the parser is also called
    /// from find_by_purls without the hidden-dir filter, so the
    /// guard is real defense-in-depth.)
    #[test]
    fn test_parse_legacy_dir_name_empty_name_guard() {
        assert_eq!(parse_legacy_dir_name(".1.0.0"), None);
    }

    /// Regression: the name/version split must happen at the *first*
    /// numeric-leading segment, not the last. A version with three or
    /// more numeric components (the common case) would otherwise be
    /// truncated to its final segment.
    #[test]
    fn test_parse_legacy_dir_name_splits_at_first_numeric_segment() {
        assert_eq!(
            parse_legacy_dir_name("Newtonsoft.Json.13.0.3"),
            Some(("Newtonsoft.Json".to_string(), "13.0.3".to_string()))
        );
        // A four-component version still keeps every numeric segment.
        assert_eq!(
            parse_legacy_dir_name("Microsoft.Web.Infrastructure.1.0.0.0"),
            Some((
                "Microsoft.Web.Infrastructure".to_string(),
                "1.0.0.0".to_string()
            ))
        );
    }

    /// Regression: NuGet's global packages folder lowercases the version
    /// directory as well as the package-id directory. A prerelease tag
    /// carrying uppercase characters in the PURL (e.g. `2.0.0-RC1`) must
    /// still resolve to the on-disk `2.0.0-rc1` folder.
    #[tokio::test]
    async fn test_find_by_purls_global_cache_lowercases_version() {
        let dir = tempfile::tempdir().unwrap();

        // On disk both the id and the version are lowercased.
        let pkg_dir = dir.path().join("contoso.widgets").join("2.0.0-rc1");
        tokio::fs::create_dir_all(pkg_dir.join("lib"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        // The PURL preserves the original (mixed) case for id and version.
        let purls = vec!["pkg:nuget/Contoso.Widgets@2.0.0-RC1".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = result
            .get("pkg:nuget/Contoso.Widgets@2.0.0-RC1")
            .expect("prerelease package should resolve via lowercased version dir");
        assert_eq!(pkg.path, pkg_dir);
        // The reported name/version keep the PURL's original casing.
        assert_eq!(pkg.name, "Contoso.Widgets");
        assert_eq!(pkg.version, "2.0.0-RC1");
    }

    /// Companion to the above: the legacy `<Name>.<Version>/` layout
    /// preserves the original version casing on disk, and the
    /// case-insensitive fallback still resolves it when the PURL casing
    /// differs from the folder casing.
    #[tokio::test]
    async fn test_find_by_purls_legacy_case_insensitive_prerelease() {
        let dir = tempfile::tempdir().unwrap();

        // Legacy folder happens to be stored fully lowercased.
        let pkg_dir = dir.path().join("contoso.widgets.2.0.0-rc1");
        tokio::fs::create_dir_all(pkg_dir.join("lib"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let purls = vec!["pkg:nuget/Contoso.Widgets@2.0.0-RC1".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:nuget/Contoso.Widgets@2.0.0-RC1"));
    }
}
