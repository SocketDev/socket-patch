use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::listing::{list_dir_sync, ListedEntry};
use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::{is_dir, is_dir_sync, run_blocking};

#[cfg(test)]
mod oracle;

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
        Ok(package_roots(options).await.paths)
    }

    /// Crawl all discovered package paths and return every package found.
    ///
    /// A project-local `packages/` folder (and every root of a project
    /// with no restore scope, see [`PackageRoots::scope`]) is walked; the
    /// shared roots of a restored project are only looked up for the
    /// packages its restore resolved ([`locate_libraries`]), so a package
    /// another project left in `~/.nuget/packages` is never crawled
    /// (#427), and the crawl no longer lists the whole cache.
    ///
    /// The scan runs as one blocking-pool task (the global packages folder
    /// holds thousands of `<name>/<version>/` dirs, and one runtime hop per
    /// readdir and stat dominated the crawl), walked roots in listing order
    /// and located ones in `libraries` order, so the first root to yield a
    /// purl wins. (A parallel classification on the walk pool measured no
    /// faster and cost the pool's thread start-up in system time.)
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let roots = package_roots(options).await;
        if roots.paths.is_empty() {
            return Vec::new();
        }
        let local_packages = options.cwd.join("packages");

        run_blocking(move || {
            let mut packages = Vec::new();
            let mut seen = HashSet::new();
            for pkg_path in &roots.paths {
                match &roots.scope {
                    Some(libraries) if *pkg_path != local_packages => {
                        packages.extend(locate_libraries(pkg_path, libraries, &mut seen));
                    }
                    _ => packages.extend(scan_package_dir(pkg_path, &mut seen)),
                }
            }
            packages
        })
        .await
    }

    /// Find specific packages by PURL inside a single package directory.
    ///
    /// Runs as one blocking-pool task, and the package root is listed at
    /// most once per call for the case-insensitive legacy fallback (it used
    /// to be re-listed for every PURL that missed both exact layouts).
    pub async fn find_by_purls(
        &self,
        pkg_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        if purls.is_empty() {
            return Ok(HashMap::new());
        }
        let pkg_path = pkg_path.to_path_buf();
        let purls = purls.to_vec();
        Ok(run_blocking(move || find_by_purls_sync(&pkg_path, &purls)).await)
    }

    // ------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------

    /// The unit tests' entry point to [`scan_package_dir`].
    #[cfg(test)]
    async fn scan_package_dir(
        &self,
        pkg_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        scan_package_dir(pkg_path, seen)
    }

    /// The unit tests' entry point to [`verify_nuget_package`].
    #[cfg(test)]
    async fn verify_nuget_package(&self, path: &Path) -> bool {
        verify_nuget_package(path)
    }
}

impl Default for NuGetCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocking body of [`NuGetCrawler::find_by_purls`].
fn find_by_purls_sync(pkg_path: &Path, purls: &[String]) -> HashMap<String, CrawledPackage> {
    let mut result: HashMap<String, CrawledPackage> = HashMap::new();
    // The package root's entry names (lossy, in readdir order), listed on
    // the first PURL that needs the case-insensitive fallback — and only
    // kept when the listing is the whole directory (`names_memoized`).
    let mut root_names: Option<Vec<String>> = None;

    for purl in purls {
        let Some((name, version)) = crate::utils::purl::parse_nuget_purl(purl) else {
            continue;
        };
        let (name, version) = (name.as_ref(), version.as_ref());
        // SECURITY: the coordinates are untrusted manifest input
        // joined onto the package root and then patched IN PLACE
        // (NuGet has no redirect backend). Reject anything that
        // could traverse out of the root before touching the
        // filesystem — `verify_nuget_package` only checks for
        // `lib/` or a `.nuspec`, so it is no defense.
        if !path_safety::is_safe_name_version(name, version) {
            continue;
        }

        // Global cache layout: <lowercase-name>/<lowercase-version>/.
        // NuGet lowercases BOTH the id and the version when it lays
        // out the global packages folder, so a prerelease tag like
        // `2.0.0-RC1` lives on disk as `2.0.0-rc1`. Lowercasing only
        // the name (but not the version) would miss those packages.
        let global_dir = pkg_path
            .join(name.to_lowercase())
            .join(version.to_lowercase());
        // Legacy layout: <Name>.<Version>/, tried exact-case first, then
        // case-insensitively (NuGet names are case-insensitive).
        let legacy_dir = pkg_path.join(format!("{name}.{version}"));

        let found = if verify_nuget_package(&global_dir) {
            Some(global_dir)
        } else if verify_nuget_package(&legacy_dir) {
            Some(legacy_dir)
        } else {
            let names = super::listing::names_memoized(pkg_path, &mut root_names);
            find_legacy_dir_case_insensitive(pkg_path, &names, name, version)
        };

        if let Some(path) = found {
            result.insert(
                purl.clone(),
                CrawledPackage {
                    name: name.to_string(),
                    version: version.to_string(),
                    namespace: None,
                    purl: purl.clone(),
                    path,
                },
            );
        }
    }

    result
}

/// What one top-level entry of a package directory holds, in the order the
/// sequential scan emitted it: `(name, version, path)` candidates, before
/// the PURL dedup.
fn classify_package_entry(pkg_path: &Path, entry: &ListedEntry) -> Vec<(String, String, PathBuf)> {
    if !entry.is_dir(pkg_path) {
        return Vec::new();
    }

    let dir_name_str = entry.name.to_string_lossy();

    // Skip hidden directories
    if dir_name_str.starts_with('.') {
        return Vec::new();
    }

    let entry_path = pkg_path.join(&*dir_name_str);

    // Try global cache layout: this directory is a package name,
    // containing version subdirectories
    if let Some(pkgs) = scan_global_cache_package(&entry_path, &dir_name_str) {
        return pkgs;
    }

    // Try legacy layout: <Name>.<Version>/ directory
    if let Some((name, version)) = parse_legacy_dir_name(&dir_name_str) {
        if verify_nuget_package(&entry_path) {
            return vec![(name, version, entry_path)];
        }
    }
    Vec::new()
}

/// Scan a package directory and return all valid NuGet packages found.
///
/// Handles both layouts:
/// - Global cache: `<name>/<version>/` with `.nuspec` inside
/// - Legacy packages/: `<Name>.<Version>/` with `.nuspec` inside
fn scan_package_dir(pkg_path: &Path, seen: &mut HashSet<String>) -> Vec<CrawledPackage> {
    let mut results = Vec::new();
    for (name, version, path) in list_dir_sync(pkg_path)
        .iter()
        .flat_map(|entry| classify_package_entry(pkg_path, entry))
    {
        let purl = crate::utils::purl::build_nuget_purl(&name, &version);
        if seen.insert(purl.clone()) {
            results.push(CrawledPackage {
                name,
                version,
                namespace: None,
                purl,
                path,
            });
        }
    }
    results
}

/// Scan a global cache package directory (`<name>/`) for version
/// subdirectories: `Some` (every verified version, in listing order) when
/// at least one verifies, else `None` — the entry is then tried as a
/// legacy `<Name>.<Version>/` dir.
fn scan_global_cache_package(
    name_dir: &Path,
    name: &str,
) -> Option<Vec<(String, String, PathBuf)>> {
    let mut results = Vec::new();

    for ver_entry in list_dir_sync(name_dir) {
        if !ver_entry.is_dir(name_dir) {
            continue;
        }

        let ver_str = ver_entry.name.to_string_lossy();

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

        if verify_nuget_package(&ver_path) {
            results.push((name.to_string(), ver_str.to_string(), ver_path));
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

/// Verify that a directory looks like an installed NuGet package.
/// Checks for a `.nuspec` file or a `lib/` directory.
fn verify_nuget_package(path: &Path) -> bool {
    if !is_dir_sync(path) {
        return false;
    }

    // Check for lib/ directory
    if is_dir_sync(&path.join("lib")) {
        return true;
    }

    // Check for any .nuspec file
    list_dir_sync(path).iter().any(|entry| {
        entry
            .name
            .to_str()
            .is_some_and(|name| name.ends_with(".nuspec"))
    })
}

/// Find a legacy package directory with case-insensitive matching, over the
/// package root's (lossy) entry names in readdir order.
fn find_legacy_dir_case_insensitive(
    pkg_path: &Path,
    root_names: &[String],
    name: &str,
    version: &str,
) -> Option<PathBuf> {
    let target = format!("{}.{}", name.to_lowercase(), version.to_lowercase());

    for dir_name_str in root_names {
        if dir_name_str.to_lowercase() == target {
            let path = pkg_path.join(dir_name_str);
            if verify_nuget_package(&path) {
                return Some(path);
            }
        }
    }

    None
}

/// Get the NuGet global packages folder.
///
/// Checks `NUGET_PACKAGES` env var, falls back to `~/.nuget/packages/`
/// (`None` with no home directory).
fn nuget_home() -> Option<PathBuf> {
    // NuGet itself treats an empty NUGET_PACKAGES as unset and falls back
    // to the default folder; honoring "" here would make global discovery
    // probe `is_dir("")` and silently scan nothing.
    if let Ok(custom) = std::env::var("NUGET_PACKAGES") {
        if !custom.is_empty() {
            return Some(PathBuf::from(custom));
        }
    }

    crate::utils::fs::home_dir().map(|home| home.join(".nuget").join("packages"))
}

/// What `cwd` itself holds of a .NET build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DotnetRoot {
    /// No .NET marker: local discovery is skipped.
    None,
    /// A solution, `packages.config` or NuGet config file, but no project
    /// file: the projects (and their restores) live in subdirectories.
    Marker,
    /// A `.csproj`/`.fsproj`/`.vbproj`: `cwd` is a project, so its own
    /// `obj/project.assets.json` is the restore of what it builds.
    Project,
}

/// Check if the cwd contains any .NET project indicators.
#[cfg(test)]
async fn is_dotnet_project(cwd: &Path) -> bool {
    dotnet_root(cwd).await != DotnetRoot::None
}

/// The project file extensions: a directory holding one is a project.
const PROJECT_EXTENSIONS: [&str; 3] = [".csproj", ".fsproj", ".vbproj"];

/// Classify `cwd` by the .NET markers it holds ([`DotnetRoot`]).
async fn dotnet_root(cwd: &Path) -> DotnetRoot {
    // `.slnx` is the XML solution format (GA since VS 2022 17.13 /
    // dotnet 9.0.200); migrating deletes the old `.sln`, and a solution
    // root often has no other root-level marker.
    let extensions = [".sln", ".slnx"];

    let mut root = DotnetRoot::None;
    for entry in crate::utils::fs::list_dir_entries(cwd).await {
        if let Some(name) = entry.file_name().to_str() {
            if PROJECT_EXTENSIONS.iter().any(|ext| name.ends_with(ext)) {
                return DotnetRoot::Project;
            }
            if extensions.iter().any(|ext| name.ends_with(ext)) {
                root = DotnetRoot::Marker;
            }
            // `packages.config` is the defining marker for the legacy
            // packages.config layout that pairs with `<cwd>/packages/`;
            // recognize it (and the NuGet config file) so the local-mode
            // gate admits those projects.
            //
            // Both names are matched case-INSENSITIVELY. NuGet's own
            // config discovery is case-insensitive, so real repos ship
            // every casing — `NuGet.config` (dotnet/runtime, roslyn,
            // aspnetcore), `NuGet.Config` (Visual Studio), `nuget.config`
            // (`dotnet new nugetconfig`). Those repos keep their projects
            // in subdirectories with no root-level `.sln`/`.csproj`, so the
            // config file is the ONLY marker this gate can see; missing a
            // spelling makes `get_nuget_package_paths` return zero paths —
            // not even the global cache — silently disabling NuGet
            // scan/apply for the whole repo.
            if name.eq_ignore_ascii_case("nuget.config")
                || name.eq_ignore_ascii_case("packages.config")
            {
                root = DotnetRoot::Marker;
            }
        }
    }
    root
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

/// The package roots a crawl reads, and how it reads the shared ones.
#[derive(Debug, Default)]
struct PackageRoots {
    /// The roots, in priority order (see
    /// [`NuGetCrawler::get_nuget_package_paths`]).
    paths: Vec<PathBuf>,
    /// The `(id, version)` pairs every project under `cwd` restored
    /// ([`restore_scope`]), when `cwd` is itself a project
    /// ([`DotnetRoot::Project`]): the shared roots (global folder,
    /// `packageFolders`) are then looked up for these instead of walked.
    /// `None` keeps the walk: global mode, a root without a project file,
    /// or any project under `cwd` without a parsed restore.
    scope: Option<Vec<(String, String)>>,
}

/// [`PackageRoots`] for `options`.
async fn package_roots(options: &CrawlerOptions) -> PackageRoots {
    let mut roots = PackageRoots::default();
    if options.global || options.global_prefix.is_some() {
        if let Some(ref custom) = options.global_prefix {
            roots.paths.push(custom.clone());
        } else if let Some(home) = nuget_home() {
            if is_dir(&home).await {
                roots.paths.push(home);
            }
        }
        return roots;
    }

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
    let root = dotnet_root(&options.cwd).await;
    if root == DotnetRoot::None {
        return roots;
    }

    // 1. Check <cwd>/packages/ (legacy packages.config layout)
    let packages_dir = options.cwd.join("packages");
    if is_dir(&packages_dir).await && seen.insert(packages_dir.clone()) {
        roots.paths.push(packages_dir);
    }

    // 2. Fall back to the global cache.
    if let Some(home) = nuget_home() {
        if is_dir(&home).await && seen.insert(home.clone()) {
            roots.paths.push(home);
        }
    }

    // 3. Check obj/ dirs for project.assets.json
    for p in discover_paths_from_assets(&options.cwd).await {
        if is_dir(&p).await && seen.insert(p.clone()) {
            roots.paths.push(p);
        }
    }
    if root == DotnetRoot::Project {
        let cwd = options.cwd.clone();
        roots.scope = run_blocking(move || restore_scope(&cwd)).await;
    }

    roots
}

/// Discover additional package paths from `obj/project.assets.json` files:
/// `cwd`'s own and those of its direct subdirectories (multi-project
/// solutions).
async fn discover_paths_from_assets(cwd: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Look for obj/project.assets.json in cwd
    if let Some(root) = read_project_assets(&cwd.join("obj").join("project.assets.json")).await {
        paths.extend(root.package_folders);
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
        if let Some(sub) = read_project_assets(&sub_assets).await {
            paths.extend(sub.package_folders);
        }
    }
    paths
}

/// What one `project.assets.json` says.
#[derive(Debug, Default)]
struct ProjectAssets {
    /// The `packageFolders` keys, e.g.
    /// `{"packageFolders": {"/home/user/.nuget/packages/": {}}}`.
    package_folders: Vec<PathBuf>,
    /// The `libraries` entries of type `package`, keyed `"<Id>/<Version>"`
    /// (`"project"` entries are the solution's own projects, never in a
    /// package folder); `None` when there is no `libraries` object.
    libraries: Option<Vec<(String, String)>>,
}

/// Read and parse one `project.assets.json`; `None` when the file is
/// unreadable (or not a regular file) or not JSON.
async fn read_project_assets(path: &Path) -> Option<ProjectAssets> {
    let content = crate::utils::fs::read_regular_to_string(path).await.ok()?;
    parse_project_assets(&content)
}

/// Parse one `project.assets.json` ([`ProjectAssets`]).
fn parse_project_assets(content: &str) -> Option<ProjectAssets> {
    let json: serde_json::Value = serde_json::from_str(content).ok()?;
    let package_folders = json
        .get("packageFolders")
        .and_then(|folders| folders.as_object())
        .map(|folders| folders.keys().map(PathBuf::from).collect())
        .unwrap_or_default();
    let libraries = json
        .get("libraries")
        .and_then(|l| l.as_object())
        .map(|libraries| {
            libraries
                .iter()
                .filter(|(_, library)| {
                    library.get("type").and_then(|t| t.as_str()) == Some("package")
                })
                .filter_map(|(key, _)| {
                    let (id, version) = key.split_once('/')?;
                    Some((id.to_string(), version.to_string()))
                })
                .collect()
        });
    Some(ProjectAssets {
        package_folders,
        libraries,
    })
}

/// Directories [`restore_scope`] never descends into: build output, the
/// restore's own `obj/`, a legacy `packages/` folder, and JS dependencies.
const SCOPE_SKIPPED_DIRS: [&str; 4] = ["bin", "obj", "packages", "node_modules"];

/// Directories [`restore_scope`] lists before giving up on a scope (the
/// crawl then walks the shared roots, as before).
const SCOPE_DIR_BUDGET: usize = 10_000;

/// The packages every project under `cwd` restored: the union of the
/// `libraries` of each project directory's `obj/project.assets.json`.
///
/// `None` (keep the walk) unless EVERY project file found under `cwd`
/// (`.csproj`/`.fsproj`/`.vbproj`, at any depth) has a parsed assets file
/// with a `libraries` object, so a project the scope cannot see (not
/// restored yet, a relocated `obj/`, an unreadable directory) never loses
/// its packages. Symlinked directories, hidden ones and
/// [`SCOPE_SKIPPED_DIRS`] are not entered; more than
/// [`SCOPE_DIR_BUDGET`] directories also means `None`.
fn restore_scope(cwd: &Path) -> Option<Vec<(String, String)>> {
    let mut libraries = Vec::new();
    let mut pending = vec![cwd.to_path_buf()];
    let mut listed = 0usize;
    while let Some(dir) = pending.pop() {
        listed += 1;
        if listed > SCOPE_DIR_BUDGET {
            return None;
        }
        let (entries, complete) = super::listing::list_dir_sync_complete(&dir);
        if !complete {
            return None;
        }
        let mut is_project = false;
        for entry in &entries {
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            let kind = entry.file_type?;
            if kind.is_dir() {
                if !name.starts_with('.') && !SCOPE_SKIPPED_DIRS.contains(&name) {
                    pending.push(dir.join(name));
                }
            } else if PROJECT_EXTENSIONS.iter().any(|ext| name.ends_with(ext)) {
                is_project = true;
            }
        }
        if is_project {
            let assets = dir.join("obj").join("project.assets.json");
            let content = crate::utils::fs::read_regular_to_string_sync(&assets).ok()?;
            libraries.extend(parse_project_assets(&content)?.libraries?);
        }
    }
    Some(libraries)
}

/// Look up each resolved `(id, version)` in a shared (global-layout) root,
/// `<root>/<id lowercased>/<version lowercased>/` as NuGet lays it out,
/// emitting the same rows [`scan_package_dir`] would for those dirs and
/// skipping a purl an earlier root already produced.
fn locate_libraries(
    pkg_path: &Path,
    libraries: &[(String, String)],
    seen: &mut HashSet<String>,
) -> Vec<CrawledPackage> {
    let mut results = Vec::new();
    for (id, version) in libraries {
        let (name, version) = (id.to_lowercase(), version.to_lowercase());
        // SECURITY: the assets file is project input joined onto a shared
        // root; refuse anything that could leave it.
        if !path_safety::is_safe_name_version(&name, &version) {
            continue;
        }
        let path = pkg_path.join(&name).join(&version);
        if !verify_nuget_package(&path) {
            continue;
        }
        let purl = crate::utils::purl::build_nuget_purl(&name, &version);
        if seen.insert(purl.clone()) {
            results.push(CrawledPackage {
                name,
                version,
                namespace: None,
                purl,
                path,
            });
        }
    }
    results
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

    /// Regression: `.slnx` (the XML solution format, GA since VS 2022
    /// 17.13 / dotnet 9.0.200) replaces `.sln` when a repo migrates — the
    /// old file is deleted. A solution root keeps its projects in
    /// subdirectories, so `.slnx` is often the ONLY root-level .NET
    /// marker; without it the local-mode gate fails and
    /// `get_nuget_package_paths` returns no paths at all (not even the
    /// global cache), silently disabling NuGet patching for that repo.
    #[tokio::test]
    async fn test_is_dotnet_project_slnx() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("MySolution.slnx"), "<Solution/>")
            .await
            .unwrap();
        assert!(super::is_dotnet_project(dir.path()).await);

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        // Path discovery must also flow through: an assets-file path in a
        // sub-project of the .slnx solution is found once the gate passes.
        let pkg_folder = dir.path().join("nuget-cache");
        tokio::fs::create_dir_all(&pkg_folder).await.unwrap();
        let obj_dir = dir.path().join("MyApp").join("obj");
        tokio::fs::create_dir_all(&obj_dir).await.unwrap();
        tokio::fs::write(
            obj_dir.join("project.assets.json"),
            serde_json::to_string(&serde_json::json!({
                "packageFolders": { pkg_folder.to_string_lossy().to_string(): {} }
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let paths = crawler.get_nuget_package_paths(&options).await.unwrap();
        assert!(
            paths.contains(&pkg_folder),
            "a .slnx solution root must be gated in and its sub-project assets discovered, got {paths:?}"
        );
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
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:nuget/newtonsoft.json@13.0.3");
    }

    /// Direct guard on the `seen`-dedup arm of `scan_package_dir`:
    /// the same package reached through TWO scanned paths (e.g. a local
    /// `packages/` folder and the global cache both holding it) must be
    /// emitted only once. `test_deduplication` above creates a single
    /// package, so the duplicate-purl arm never actually runs there; here a
    /// shared `seen` set is threaded through two scans of the same tree.
    #[tokio::test]
    async fn test_scan_package_dir_dedups_same_package_across_two_scans() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_dir = dir.path().join("newtonsoft.json").join("13.0.3");
        tokio::fs::create_dir_all(pkg_dir.join("lib"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let mut seen = HashSet::new();

        let first = crawler.scan_package_dir(dir.path(), &mut seen).await;
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].purl, "pkg:nuget/newtonsoft.json@13.0.3");
        assert_eq!(first[0].path, pkg_dir);

        // Second scan of the same tree: the version dir verifies again
        // (so `scan_global_cache_package` returns it as a candidate), but
        // the purl is already in `seen`, so no duplicate package is
        // emitted.
        let second = crawler.scan_package_dir(dir.path(), &mut seen).await;
        assert!(
            second.is_empty(),
            "a purl already in `seen` must not be emitted again, got {second:?}"
        );
        assert!(seen.contains("pkg:nuget/newtonsoft.json@13.0.3"));
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
        // A content folder that itself contains a lib/ dir, which a naive
        // global-cache heuristic would mistake for a version dir.
        tokio::fs::create_dir_all(pkg.join("tools").join("lib"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
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
        tokio::fs::create_dir_all(dir.path().join("newtonsoft.json").join("tools").join("lib"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
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
    #[serial_test::serial]
    async fn test_nuget_home_env_var() {
        // Test that NUGET_PACKAGES env var is respected
        let custom = "/tmp/test-nuget-packages";
        std::env::set_var("NUGET_PACKAGES", custom);
        let home = nuget_home();
        assert_eq!(home, Some(PathBuf::from(custom)));
        std::env::remove_var("NUGET_PACKAGES");
    }

    /// Regression: NuGet itself treats an empty `NUGET_PACKAGES` as unset
    /// and falls back to `~/.nuget/packages` (its settings layer checks
    /// IsNullOrEmpty). Honoring the empty string here produced
    /// `PathBuf::from("")`, which fails the `is_dir` probe — so global-mode
    /// discovery silently scanned nothing instead of the real cache.
    #[tokio::test]
    #[serial_test::serial]
    async fn test_nuget_home_empty_env_var_falls_back_to_default() {
        let prev = std::env::var("NUGET_PACKAGES").ok();
        std::env::set_var("NUGET_PACKAGES", "");
        let home = nuget_home().expect("a home directory");
        match prev {
            Some(v) => std::env::set_var("NUGET_PACKAGES", v),
            None => std::env::remove_var("NUGET_PACKAGES"),
        }
        assert!(
            home.ends_with(Path::new(".nuget").join("packages")),
            "empty NUGET_PACKAGES must fall back to ~/.nuget/packages, got {home:?}"
        );
    }

    /// SECURITY regression: a tampered manifest PURL whose name or version
    /// carries a `..`/separator must NOT resolve to a directory outside the
    /// scanned package root. NuGet patches are applied IN PLACE at the
    /// directory the crawler returns (no redirect backend stands between
    /// resolution and disk), so an escape means an arbitrary out-of-tree
    /// write. `verify_nuget_package` only checks for `lib/` or a `.nuspec`,
    /// which does nothing to stop traversal — hence the fail-closed
    /// coordinate guard. Twin of the maven/go/deno/npm crawler guards.
    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_coordinate() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cache");
        // The intermediate name dir must exist for the OS to resolve the
        // `..` in the version-traversal probe below.
        tokio::fs::create_dir_all(cache.join("foo")).await.unwrap();

        // An out-of-tree directory that DOES verify (has `lib/`), so the
        // only thing standing between the attacker and a match is the guard.
        let escaped = root.path().join("escaped").join("1.0.0");
        tokio::fs::create_dir_all(escaped.join("lib"))
            .await
            .unwrap();

        let purls = vec![
            // name traversal: cache/../escaped/1.0.0 == root/escaped/1.0.0
            "pkg:nuget/../escaped@1.0.0".to_string(),
            // version traversal: cache/foo/../../escaped/1.0.0
            "pkg:nuget/foo@../../escaped/1.0.0".to_string(),
        ];

        let crawler = NuGetCrawler::new();
        let result = crawler.find_by_purls(&cache, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "traversal PURL must not resolve to an out-of-tree directory, got {result:?}"
        );
    }

    /// `".1.0.0"` — first match-index of `.` is `i=0` (followed by
    /// `1`), `i+1 < dir_name.len()` is true, split_idx = Some(0).
    /// The name slice ends up empty; the defensive guard at the
    /// bottom of parse_legacy_dir_name rejects rather than producing
    /// a `("", "1.0.0")` ghost package. (Hidden dirs are already
    /// skipped upstream in classify_package_entry, so this guard is
    /// pure defense-in-depth for the parser.)
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

    /// Guard on `find_legacy_dir_case_insensitive`'s verification gate: a
    /// directory whose NAME matches the legacy `<name>.<version>` target
    /// case-insensitively but whose contents do not verify as a NuGet
    /// package (no `lib/`, no `.nuspec`) must be skipped — the lookup
    /// yields nothing rather than handing back an unverified husk
    /// directory as an in-place patch target.
    #[tokio::test]
    async fn test_find_by_purls_legacy_case_match_without_verification_yields_nothing() {
        let dir = tempfile::tempdir().unwrap();
        // Name matches (case-insensitively), contents don't verify.
        tokio::fs::create_dir_all(dir.path().join("newtonsoft.json.13.0.3"))
            .await
            .unwrap();

        let crawler = NuGetCrawler::new();
        let purls = vec!["pkg:nuget/Newtonsoft.Json@13.0.3".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "an unverified case-matched husk dir must not become a patch target, got {result:?}"
        );
    }

    /// Regression: the NuGet config file name is matched
    /// case-insensitively by NuGet itself, and `NuGet.config` (capital
    /// N/G, lowercase `config`) is the spelling used by the largest .NET
    /// repos (dotnet/runtime, dotnet/roslyn, dotnet/aspnetcore). Those
    /// repos keep every project in subdirectories and have no root-level
    /// `.sln`/`.slnx`/`.csproj`, so the config file is the ONLY marker the
    /// local-mode gate can see. Matching just the two hard-coded
    /// spellings (`NuGet.Config`/`nuget.config`) failed the gate for them,
    /// so `get_nuget_package_paths` returned ZERO paths — not even the
    /// global cache — silently disabling NuGet scan/apply for the repo.
    /// Same failure mode as the `.slnx` marker gap.
    #[tokio::test]
    async fn test_is_dotnet_project_config_marker_is_case_insensitive() {
        for name in [
            "NuGet.config",
            "Nuget.Config",
            "NUGET.CONFIG",
            "Packages.config",
            "PACKAGES.CONFIG",
        ] {
            let dir = tempfile::tempdir().unwrap();
            tokio::fs::write(dir.path().join(name), "<configuration/>")
                .await
                .unwrap();
            assert!(
                super::is_dotnet_project(dir.path()).await,
                "`{name}` must satisfy the .NET-project gate"
            );
        }
    }

    /// Companion: the gate must flow through to real path discovery — a
    /// `NuGet.config`-only solution root gets its sub-project
    /// `obj/project.assets.json` package folders discovered.
    #[tokio::test]
    async fn test_nuget_config_casing_flows_through_to_path_discovery() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("NuGet.config"), "<configuration/>")
            .await
            .unwrap();

        let pkg_folder = dir.path().join("nuget-cache");
        tokio::fs::create_dir_all(&pkg_folder).await.unwrap();
        let obj_dir = dir.path().join("MyApp").join("obj");
        tokio::fs::create_dir_all(&obj_dir).await.unwrap();
        tokio::fs::write(
            obj_dir.join("project.assets.json"),
            serde_json::to_string(&serde_json::json!({
                "packageFolders": { pkg_folder.to_string_lossy().to_string(): {} }
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let paths = crawler.get_nuget_package_paths(&options).await.unwrap();
        assert!(
            paths.contains(&pkg_folder),
            "a NuGet.config-only root must be gated in and its sub-project assets discovered, got {paths:?}"
        );
    }

    // ── Project-mode scope (#427, #595) ───────────────────────────────

    /// A shared packages folder holding the project's package, another
    /// project's leftover, and a version of the project's package it
    /// does not resolve.
    async fn shared_cache(root: &Path) -> PathBuf {
        let cache = root.join("shared-cache");
        for (name, version) in [
            ("newtonsoft.json", "13.0.3"),
            ("newtonsoft.json", "12.0.1"),
            ("serilog", "3.1.1"),
        ] {
            let dir = cache.join(name).join(version);
            tokio::fs::create_dir_all(&dir).await.unwrap();
            tokio::fs::write(dir.join(format!("{name}.nuspec")), "<package/>")
                .await
                .unwrap();
        }
        cache
    }

    /// Write `<dir>/obj/project.assets.json` naming `cache` as the package
    /// folder and `libraries` as its resolved set.
    async fn write_assets(dir: &Path, cache: &Path, libraries: serde_json::Value) {
        let obj = dir.join("obj");
        tokio::fs::create_dir_all(&obj).await.unwrap();
        tokio::fs::write(
            obj.join("project.assets.json"),
            serde_json::to_string(&serde_json::json!({
                "version": 3,
                "libraries": libraries,
                "packageFolders": { cache.to_string_lossy().to_string(): {} }
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    }

    fn app_libraries() -> serde_json::Value {
        serde_json::json!({
            "Newtonsoft.Json/13.0.3": { "type": "package", "path": "newtonsoft.json/13.0.3" },
            "Shared.Lib/1.0.0": { "type": "project", "path": "../Shared.Lib/Shared.Lib.csproj" },
            "../../escape/1.0.0": { "type": "package" }
        })
    }

    fn local(cwd: &Path) -> CrawlerOptions {
        CrawlerOptions {
            cwd: cwd.to_path_buf(),
            global: false,
            global_prefix: None,
        }
    }

    fn purls_of(packages: &[CrawledPackage]) -> Vec<String> {
        let mut purls: Vec<String> = packages.iter().map(|p| p.purl.clone()).collect();
        purls.sort();
        purls
    }

    /// #427: a restored project crawls only the packages its restore
    /// resolved, not another project's leftovers in the shared folder.
    /// Red on main (serilog and the unresolved newtonsoft version were
    /// crawled).
    #[tokio::test]
    async fn restored_project_crawls_only_its_resolved_packages() {
        let dir = tempfile::tempdir().unwrap();
        let cache = shared_cache(dir.path()).await;
        let app = dir.path().join("app");
        tokio::fs::create_dir_all(&app).await.unwrap();
        tokio::fs::write(app.join("App.csproj"), "<Project/>")
            .await
            .unwrap();
        write_assets(&app, &cache, app_libraries()).await;

        let crawled = NuGetCrawler.crawl_all(&local(&app)).await;
        assert_eq!(purls_of(&crawled), ["pkg:nuget/newtonsoft.json@13.0.3"]);
    }

    /// The located rows are exactly the rows the whole-cache walk
    /// produced for the same packages (name, version, purl and path), so
    /// every consumer of the crawl sees the same identity as before.
    #[tokio::test]
    async fn located_rows_equal_the_walks_rows_for_resolved_packages() {
        let dir = tempfile::tempdir().unwrap();
        let cache = shared_cache(dir.path()).await;
        let app = dir.path().join("app");
        tokio::fs::create_dir_all(&app).await.unwrap();
        tokio::fs::write(app.join("App.fsproj"), "<Project/>")
            .await
            .unwrap();
        write_assets(&app, &cache, app_libraries()).await;

        let walked: Vec<_> = scan_package_dir(&cache, &mut HashSet::new())
            .into_iter()
            .filter(|p| p.purl == "pkg:nuget/newtonsoft.json@13.0.3")
            .map(|p| (p.name, p.version, p.purl, p.path))
            .collect();
        let located: Vec<_> = NuGetCrawler
            .crawl_all(&local(&app))
            .await
            .into_iter()
            .map(|p| (p.name, p.version, p.purl, p.path))
            .collect();
        assert_eq!(located, walked);
    }

    /// Sub-project restores, at any depth, join the root project's scope.
    #[tokio::test]
    async fn sub_project_restores_join_the_scope() {
        let dir = tempfile::tempdir().unwrap();
        let cache = shared_cache(dir.path()).await;
        let app = dir.path().join("app");
        tokio::fs::create_dir_all(&app).await.unwrap();
        tokio::fs::write(app.join("App.vbproj"), "<Project/>")
            .await
            .unwrap();
        write_assets(&app, &cache, app_libraries()).await;
        let tests = app.join("tests").join("App.Tests");
        tokio::fs::create_dir_all(&tests).await.unwrap();
        tokio::fs::write(tests.join("App.Tests.csproj"), "<Project/>")
            .await
            .unwrap();
        write_assets(
            &tests,
            &cache,
            serde_json::json!({ "Serilog/3.1.1": { "type": "package" } }),
        )
        .await;

        let crawled = NuGetCrawler.crawl_all(&local(&app)).await;
        assert_eq!(
            purls_of(&crawled),
            [
                "pkg:nuget/newtonsoft.json@13.0.3",
                "pkg:nuget/serilog@3.1.1"
            ]
        );
    }

    /// No scope, so today's walk: a solution root (its projects' restores
    /// may sit deeper than one level), and a project not restored yet.
    #[tokio::test]
    async fn solution_roots_and_unrestored_projects_keep_the_walk() {
        let every = [
            "pkg:nuget/newtonsoft.json@12.0.1",
            "pkg:nuget/newtonsoft.json@13.0.3",
            "pkg:nuget/serilog@3.1.1",
        ];

        let dir = tempfile::tempdir().unwrap();
        let cache = shared_cache(dir.path()).await;
        let solution = dir.path().join("solution");
        tokio::fs::create_dir_all(&solution).await.unwrap();
        tokio::fs::write(solution.join("App.sln"), "")
            .await
            .unwrap();
        write_assets(&solution.join("App"), &cache, app_libraries()).await;
        let crawled = NuGetCrawler.crawl_all(&local(&solution)).await;
        assert_eq!(purls_of(&crawled), every);

        // A project whose assets file has no `libraries` object.
        let app = dir.path().join("app");
        tokio::fs::create_dir_all(app.join("obj")).await.unwrap();
        tokio::fs::write(app.join("App.csproj"), "<Project/>")
            .await
            .unwrap();
        tokio::fs::write(
            app.join("obj").join("project.assets.json"),
            serde_json::to_string(&serde_json::json!({
                "packageFolders": { cache.to_string_lossy().to_string(): {} }
            }))
            .unwrap(),
        )
        .await
        .unwrap();
        let crawled = NuGetCrawler.crawl_all(&local(&app)).await;
        assert_eq!(purls_of(&crawled), every);
    }

    /// A project under `cwd` the scope cannot see keeps the walk, so its
    /// packages are never dropped: a sub-project two levels down with no
    /// restore, and one whose assets file has no `libraries`.
    #[tokio::test]
    async fn an_uncovered_sub_project_keeps_the_walk() {
        let every = [
            "pkg:nuget/newtonsoft.json@12.0.1",
            "pkg:nuget/newtonsoft.json@13.0.3",
            "pkg:nuget/serilog@3.1.1",
        ];
        let dir = tempfile::tempdir().unwrap();
        let cache = shared_cache(dir.path()).await;

        let app = dir.path().join("app");
        let tests = app.join("tests").join("App.Tests");
        tokio::fs::create_dir_all(&tests).await.unwrap();
        tokio::fs::write(app.join("App.csproj"), "<Project/>")
            .await
            .unwrap();
        tokio::fs::write(tests.join("App.Tests.csproj"), "<Project/>")
            .await
            .unwrap();
        write_assets(&app, &cache, app_libraries()).await;
        let crawled = NuGetCrawler.crawl_all(&local(&app)).await;
        assert_eq!(purls_of(&crawled), every, "unrestored sub-project");

        let obj = tests.join("obj");
        tokio::fs::create_dir_all(&obj).await.unwrap();
        tokio::fs::write(obj.join("project.assets.json"), r#"{"version": 3}"#)
            .await
            .unwrap();
        let crawled = NuGetCrawler.crawl_all(&local(&app)).await;
        assert_eq!(purls_of(&crawled), every, "assets without libraries");
    }

    /// The project-local `packages/` folder is the project's own, so it
    /// is still walked in full when the shared roots are scoped.
    #[tokio::test]
    async fn project_local_packages_folder_is_still_walked() {
        let dir = tempfile::tempdir().unwrap();
        let cache = shared_cache(dir.path()).await;
        let app = dir.path().join("app");
        let legacy = app.join("packages").join("Legacy.Pkg.2.0.0");
        tokio::fs::create_dir_all(&legacy).await.unwrap();
        tokio::fs::write(legacy.join("Legacy.Pkg.nuspec"), "<package/>")
            .await
            .unwrap();
        tokio::fs::write(app.join("App.csproj"), "<Project/>")
            .await
            .unwrap();
        write_assets(&app, &cache, app_libraries()).await;

        let crawled = NuGetCrawler.crawl_all(&local(&app)).await;
        assert_eq!(
            purls_of(&crawled),
            [
                "pkg:nuget/Legacy.Pkg@2.0.0",
                "pkg:nuget/newtonsoft.json@13.0.3"
            ]
        );
    }

    /// Global mode never reads a project's restore.
    #[tokio::test]
    async fn global_prefix_crawl_is_not_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let cache = shared_cache(dir.path()).await;
        tokio::fs::write(dir.path().join("App.csproj"), "<Project/>")
            .await
            .unwrap();
        write_assets(dir.path(), &cache, app_libraries()).await;
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(cache.clone()),
        };
        assert_eq!(NuGetCrawler.crawl_all(&options).await.len(), 3);
    }

    // ── Equivalence with the per-call async scan (oracle) ─────────────

    mod equivalence {
        use super::super::oracle::LegacyNuGetCrawler;
        use super::*;
        use crate::crawlers::oracle_support::{
            map_rows, mkdir, rows, symlink, write, PermGuard, Rng,
        };

        const IDS: &[&str] = &["Newtonsoft.Json", "xunit", "System.Text.Json", "Dup", "dup"];
        const VERSIONS: &[&str] = &["13.0.3", "2.0.0-RC1", "8.0.0", "1.0.0"];

        /// Fill a package dir with one of the verify shapes (lib/, a
        /// .nuspec, a .nuspec DIR, a lib FILE, nothing).
        fn contents(rng: &mut Rng, dir: &Path, id: &str) {
            mkdir(dir);
            match rng.below(6) {
                0 => mkdir(&dir.join("lib")),
                1 => write(
                    &dir.join(format!("{}.nuspec", id.to_lowercase())),
                    "<package/>",
                ),
                2 => mkdir(&dir.join("x.nuspec")),
                3 => write(&dir.join("lib"), "file"),
                4 => mkdir(&dir.join("tools").join("lib")),
                _ => {}
            }
        }

        fn tree(rng: &mut Rng, root: &Path, outside: &Path, perms: &mut PermGuard) {
            mkdir(root);
            for i in 0..rng.below(20) {
                let id = rng.pick(IDS);
                let version = rng.pick(VERSIONS);
                match rng.below(10) {
                    // Global cache layout, sometimes with non-version dirs.
                    0..=3 => {
                        let name_dir = root.join(id.to_lowercase());
                        for _ in 0..rng.below(3) + 1 {
                            let ver = if rng.chance(20) {
                                "tools"
                            } else {
                                rng.pick(VERSIONS)
                            };
                            let ver = if rng.chance(50) {
                                ver.to_lowercase()
                            } else {
                                ver.to_string()
                            };
                            contents(rng, &name_dir.join(ver), id);
                        }
                        if rng.chance(10) {
                            perms.plan(&name_dir, if rng.chance(50) { 0o000 } else { 0o600 });
                        }
                    }
                    // Legacy layout, in either case.
                    4..=6 => {
                        let base = format!("{id}.{version}");
                        let name = if rng.chance(30) {
                            base.to_lowercase()
                        } else {
                            base
                        };
                        contents(rng, &root.join(name), id);
                    }
                    7 => {
                        let target = outside.join(format!("t{i}-{}", rng.next()));
                        if rng.chance(70) {
                            contents(rng, &target, id);
                        }
                        let name = format!("{id}.{version}");
                        symlink(&target, &root.join(name));
                    }
                    8 => write(&root.join(format!("{id}.{version}")), "file"),
                    _ => contents(rng, &root.join(format!(".{id}.{version}")), id),
                }
            }
        }

        fn probe_purls(rng: &mut Rng, crawled: &[CrawledPackage]) -> Vec<String> {
            let mut purls: Vec<String> = crawled.iter().map(|p| p.purl.clone()).collect();
            for _ in 0..12 {
                let id = rng.pick(IDS);
                let version = rng.pick(VERSIONS);
                let id = match rng.below(3) {
                    0 => id.to_lowercase(),
                    1 => id.to_uppercase(),
                    _ => id.to_string(),
                };
                purls.push(format!("pkg:nuget/{id}@{version}"));
            }
            purls.push("pkg:nuget/..@1.0.0".to_string());
            purls.push("pkg:nuget/Foo@../x".to_string());
            purls
        }

        /// Whether `dir`'s filesystem distinguishes case. macOS's default
        /// APFS volume does not; Linux CI's does.
        fn filesystem_is_case_sensitive(dir: &Path) -> bool {
            mkdir(&dir.join("CaseProbe"));
            !dir.join("caseprobe").is_dir()
        }

        /// The case-insensitive legacy fallback — the only reader of the
        /// package root's memoized listing — over several PURLs in one
        /// call: the listing is built on the first PURL that needs it and
        /// reused by the rest, matching the per-PURL oracle either way.
        ///
        /// The fallback can only MATCH on a case-sensitive filesystem:
        /// where `Foo.1.0` and `foo.1.0` are one directory, the exact-case
        /// probe above it already resolves every case variant, so nothing
        /// reaches the fallback with a name to find (the randomized oracle
        /// test has the same blind spot locally — it distinguishes the two
        /// layouts by case alone). The on-disk spelling below is therefore
        /// asserted only where the filesystem can tell them apart, and CI
        /// is where that happens.
        #[tokio::test]
        async fn legacy_fallback_reuses_one_listing_across_purls() {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path().join("packages");
            for dir in ["newtonsoft.json.13.0.3", "serilog.2.12.0"] {
                mkdir(&root.join(dir).join("lib"));
            }
            // Verifies for no one: the fallback must answer "absent" for
            // it, and for a package that is not there at all, without
            // spoiling the listing the PURLs after them reuse.
            mkdir(&root.join("hollow.1.0.0"));

            let purls: Vec<String> = [
                "pkg:nuget/NEWTONSOFT.JSON@13.0.3",
                "pkg:nuget/Hollow@1.0.0",
                "pkg:nuget/Missing@9.9.9",
                "pkg:nuget/SeriLog@2.12.0",
            ]
            .iter()
            .map(|p| p.to_string())
            .collect();

            let new = NuGetCrawler::new()
                .find_by_purls(&root, &purls)
                .await
                .unwrap();
            let old = LegacyNuGetCrawler::find_by_purls(&root, &purls).await;
            assert_eq!(map_rows(&new), map_rows(&old));
            assert_eq!(new.len(), 2, "{new:?}");
            for purl in [
                "pkg:nuget/NEWTONSOFT.JSON@13.0.3",
                "pkg:nuget/SeriLog@2.12.0",
            ] {
                assert!(new[purl].path.is_dir(), "{purl}");
            }

            // The fallback itself, over an explicit listing: matched
            // case-insensitively, verified, and handed back with the
            // on-disk spelling — pinned on every filesystem.
            let names = [
                "newtonsoft.json.13.0.3".to_string(),
                "hollow.1.0.0".to_string(),
            ];
            assert_eq!(
                find_legacy_dir_case_insensitive(&root, &names, "NEWTONSOFT.JSON", "13.0.3"),
                Some(root.join("newtonsoft.json.13.0.3"))
            );
            assert_eq!(
                find_legacy_dir_case_insensitive(&root, &names, "Hollow", "1.0.0"),
                None
            );
            assert_eq!(
                find_legacy_dir_case_insensitive(&root, &names, "Missing", "9.9.9"),
                None
            );

            if filesystem_is_case_sensitive(tmp.path()) {
                // Only the fallback can hand back the ON-DISK spelling.
                assert_eq!(
                    new["pkg:nuget/NEWTONSOFT.JSON@13.0.3"].path,
                    root.join("newtonsoft.json.13.0.3")
                );
                assert_eq!(
                    new["pkg:nuget/SeriLog@2.12.0"].path,
                    root.join("serilog.2.12.0")
                );
            }
        }

        #[tokio::test]
        async fn randomized_package_dirs_match_the_async_oracle() {
            let (mut crawled, mut found) = (0, 0);
            for seed in 0..64u64 {
                let tmp = tempfile::tempdir().unwrap();
                let mut perms = PermGuard::default();
                let mut rng = Rng::new(seed);
                let root = tmp.path().join("packages");
                tree(&mut rng, &root, &tmp.path().join("outside"), &mut perms);
                perms.apply();
                let options = CrawlerOptions {
                    cwd: tmp.path().to_path_buf(),
                    global: false,
                    global_prefix: Some(root.clone()),
                };
                let new = NuGetCrawler::new().crawl_all(&options).await;
                let old = LegacyNuGetCrawler::crawl_all(&options).await;
                assert_eq!(rows(&new), rows(&old), "seed {seed}: crawl_all");

                let purls = probe_purls(&mut rng, &old);
                let new_found = NuGetCrawler::new()
                    .find_by_purls(&root, &purls)
                    .await
                    .unwrap();
                let old_found = LegacyNuGetCrawler::find_by_purls(&root, &purls).await;
                assert_eq!(
                    map_rows(&new_found),
                    map_rows(&old_found),
                    "seed {seed}: find_by_purls"
                );
                crawled += old.len();
                found += old_found.len();
            }
            assert!(
                crawled > 100 && found > 100,
                "vacuous fixtures: {crawled}/{found}"
            );
        }
    }

    /// mkfifo(2) directly (no child process; spawning `mkfifo` flakes
    /// under heavy parallel load).
    #[cfg(unix)]
    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// On timeout the open is wedged in a blocking-pool thread that the
    /// runtime waits for on shutdown; connecting a writer releases it so
    /// the test FAILS instead of hanging the whole suite.
    #[cfg(unix)]
    async fn within_deadline<F: std::future::Future>(fifo: &Path, what: &str, fut: F) -> F::Output {
        match tokio::time::timeout(std::time::Duration::from_secs(5), fut).await {
            Ok(out) => out,
            Err(_) => {
                // O_NONBLOCK: with no reader blocked on the FIFO (the
                // timeout had another cause) a blocking writer open would
                // itself hang; non-blocking it just fails with ENXIO.
                use std::os::unix::fs::OpenOptionsExt;
                let _ = std::fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(fifo);
                panic!("{what} must not block on a FIFO at {}", fifo.display());
            }
        }
    }

    /// Regression (#592): a FIFO at `obj/project.assets.json` used to
    /// wedge `get_nuget_package_paths` (and so every NuGet crawl) in
    /// open(2). It now goes through the FIFO-safe reader and is skipped
    /// like any other unreadable assets file; a sibling sub-project's
    /// readable assets file is still discovered.
    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_project_assets_is_skipped_not_blocked_on() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("App.csproj"), "<Project />")
            .await
            .unwrap();
        let obj_dir = dir.path().join("obj");
        tokio::fs::create_dir_all(&obj_dir).await.unwrap();
        let fifo = obj_dir.join("project.assets.json");
        make_fifo(&fifo);

        let pkg_folder = dir.path().join("nuget-cache");
        tokio::fs::create_dir_all(&pkg_folder).await.unwrap();
        let sub_obj = dir.path().join("Lib").join("obj");
        tokio::fs::create_dir_all(&sub_obj).await.unwrap();
        tokio::fs::write(
            sub_obj.join("project.assets.json"),
            serde_json::to_string(&serde_json::json!({
                "packageFolders": { pkg_folder.to_string_lossy().to_string(): {} }
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let crawler = NuGetCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let paths = within_deadline(
            &fifo,
            "get_nuget_package_paths",
            crawler.get_nuget_package_paths(&options),
        )
        .await
        .unwrap();
        assert!(
            paths.contains(&pkg_folder),
            "the readable sub-project assets file must still be discovered, got {paths:?}"
        );
    }
}
