use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::{is_dir, is_file};
use crate::utils::process::{CommandRunner, SystemCommandRunner};

/// PHP/Composer ecosystem crawler for discovering packages in Composer
/// vendor directories.
pub struct ComposerCrawler;

/// A single package entry distilled from installed.json. Only the three
/// fields the crawler needs are retained; everything else (source,
/// dist, autoload, ...) is ignored.
struct ComposerPackageEntry {
    name: String,
    version: String,
    /// `install-path` as recorded, relative to the `vendor/composer/`
    /// directory that holds installed.json (`../monolog/monolog` for a
    /// conventional install, `../../web/app/plugins/x` for a
    /// composer/installers target). `None` for Composer 1 entries and any
    /// entry that omits it.
    install_path: Option<String>,
}

impl ComposerCrawler {
    /// Create a new `ComposerCrawler`.
    pub fn new() -> Self {
        Self
    }

    /// Get vendor paths based on options.
    ///
    /// In global mode, checks `$COMPOSER_HOME/vendor/` (env var, command
    /// fallback, or platform defaults).
    ///
    /// In local mode, checks the project's vendor directory
    /// (`COMPOSER_VENDOR_DIR` / composer.json `config.vendor-dir` /
    /// `vendor`, see [`resolve_local_vendor_dir`]) but only if the
    /// directory contains `composer/installed.json` and the cwd looks like
    /// a PHP project (`composer.json` or `composer.lock` present).
    pub async fn get_vendor_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            let mut paths = Vec::new();
            if let Some(composer_home) = get_composer_home().await {
                let vendor_dir = composer_home.join("vendor");
                if is_dir(&vendor_dir).await {
                    paths.push(vendor_dir);
                }
            }
            return Ok(paths);
        }

        // Local mode
        let Some(vendor_dir) = resolve_local_vendor_dir(&options.cwd).await else {
            return Ok(Vec::new());
        };
        let installed_json = vendor_dir.join("composer").join("installed.json");

        if !is_dir(&vendor_dir).await || !is_file(&installed_json).await {
            return Ok(Vec::new());
        }

        // Only return if this looks like a PHP project
        let has_composer_json = is_file(&options.cwd.join("composer.json")).await;
        let has_composer_lock = is_file(&options.cwd.join("composer.lock")).await;

        if has_composer_json || has_composer_lock {
            Ok(vec![vendor_dir])
        } else {
            Ok(Vec::new())
        }
    }

    /// Crawl all discovered vendor paths and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let vendor_paths = self.get_vendor_paths(options).await.unwrap_or_default();

        for vendor_path in &vendor_paths {
            let project_root = resolve_project_root(vendor_path).await;
            let entries = read_installed_json(vendor_path).await;
            for entry in entries {
                if let Some((namespace, name)) = entry.name.split_once('/') {
                    // Skip packages that installed.json lists but that are
                    // not actually on disk (stale metadata, a metapackage).
                    // This keeps crawl_all consistent with find_by_purls,
                    // which only returns packages whose directory exists.
                    let Some(pkg_path) = resolve_package_dir(vendor_path, &project_root, &entry)
                    else {
                        continue;
                    };
                    if !is_dir(&pkg_path).await {
                        continue;
                    }

                    // Composer's installed.json stores the *pretty*
                    // version (often `v6.4.1`); PURLs use the bare numeric
                    // version, so normalize before building the PURL.
                    let version = normalize_version(&entry.version).to_string();

                    // Composer/Packagist treat package names
                    // case-insensitively and the canonical PURL is
                    // lowercase, but installed.json records the *pretty*
                    // (case-preserved) name. Lowercase the namespace/name
                    // for the PURL so it matches the canonical form Socket's
                    // catalog uses; the on-disk `path` keeps the original
                    // casing (Composer writes the vendor dir with the pretty
                    // name, which matters on case-sensitive filesystems).
                    let ns_canon = namespace.to_ascii_lowercase();
                    let name_canon = name.to_ascii_lowercase();
                    let purl =
                        crate::utils::purl::build_composer_purl(&ns_canon, &name_canon, &version);

                    if !seen.insert(purl.clone()) {
                        continue;
                    }

                    packages.push(CrawledPackage {
                        name: name_canon,
                        version,
                        namespace: Some(ns_canon),
                        purl,
                        path: pkg_path,
                    });
                }
            }
        }

        packages
    }

    /// Find specific packages by PURL inside a single vendor directory.
    pub async fn find_by_purls(
        &self,
        vendor_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        // Build a case-insensitive lookup from installed.json. Composer
        // package names are case-insensitive and the canonical PURL is
        // lowercase, but installed.json records the *pretty* (case-preserved)
        // name and Composer writes the vendor directory with that same
        // casing. Key the map by the lowercased name and carry the whole
        // entry so the real on-disk path can be reconstructed even on
        // case-sensitive filesystems.
        let entries = read_installed_json(vendor_path).await;
        let installed: HashMap<String, ComposerPackageEntry> = entries
            .into_iter()
            .map(|e| (e.name.to_ascii_lowercase(), e))
            .collect();
        let project_root = resolve_project_root(vendor_path).await;

        for purl in purls {
            if let Some(((namespace, name), version)) =
                crate::utils::purl::parse_composer_purl(purl)
            {
                let full_name = format!("{namespace}/{name}").to_ascii_lowercase();

                let Some(entry) = installed.get(&full_name) else {
                    continue;
                };

                // Verify version matches installed.json. Compare on the
                // normalized version so a `v`-prefixed installed.json
                // version (`v6.4.1`) matches a bare PURL version (`6.4.1`)
                // and vice versa.
                if normalize_version(&entry.version) != normalize_version(version) {
                    continue;
                }

                // Resolve the on-disk directory from installed.json's own
                // record — its `install-path` when present, else the
                // conventional layout under the original (case-preserved)
                // casing Composer wrote to disk; the canonical (lowercase)
                // PURL name would miss it on a case-sensitive filesystem.
                let Some(pkg_dir) = resolve_package_dir(vendor_path, &project_root, entry) else {
                    continue;
                };

                if !is_dir(&pkg_dir).await {
                    continue;
                }

                result.insert(
                    purl.clone(),
                    CrawledPackage {
                        name: name.to_ascii_lowercase(),
                        version: version.to_string(),
                        namespace: Some(namespace.to_ascii_lowercase()),
                        purl: purl.clone(),
                        path: pkg_dir,
                    },
                );
            }
        }

        Ok(result)
    }
}

impl Default for ComposerCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure parser for `composer global config home` stdout. Returns
/// the trimmed path as a `PathBuf` or `None` on empty input.
/// Extracted so the path-derivation logic is unit-testable without
/// the composer CLI installed.
pub fn parse_composer_home_output(stdout: &str) -> Option<PathBuf> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

/// Get the Composer home directory.
///
/// Checks `$COMPOSER_HOME`, then runs `composer global config home`,
/// then falls back to platform defaults.
async fn get_composer_home() -> Option<PathBuf> {
    // Check env var first
    if let Ok(home) = std::env::var("COMPOSER_HOME") {
        let path = PathBuf::from(home);
        if is_dir(&path).await {
            return Some(path);
        }
    }

    // Try `composer global config home`
    if let Some(stdout) = SystemCommandRunner.run("composer", &["global", "config", "home"]) {
        if let Some(path) = parse_composer_home_output(&stdout) {
            if is_dir(&path).await {
                return Some(path);
            }
        }
    }

    // Platform defaults. A set-but-empty HOME counts as unset: honoring
    // `""` would turn the `.composer`/`.config/composer` probes below into
    // CWD-relative paths inside the user's project (same rule as
    // `utils::fs::home_dir`).
    let home_dir = std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("USERPROFILE").ok().filter(|h| !h.is_empty()))?;
    let home = PathBuf::from(home_dir);

    let candidates = [
        home.join(".composer"),
        home.join(".config").join("composer"),
    ];

    for candidate in &candidates {
        if is_dir(candidate).await {
            return Some(candidate.clone());
        }
    }

    None
}

/// Normalize a Composer version string for PURL identity.
///
/// Composer's `installed.json` records the *pretty* version, which for
/// many packages (symfony, twig, ...) carries a leading `v` taken from
/// the upstream git tag (e.g. `v6.4.1`). PURLs use the bare numeric
/// version (`6.4.1`), so strip a single leading `v`/`V` when it
/// directly precedes a digit. Versions that don't fit that shape (e.g.
/// `dev-main`, `1.0.x-dev`) are returned untouched.
///
/// Also used by the composer vendor backend
/// (`vendor::composer_lock`) to match lock versions against PURL
/// versions through the same normalization.
pub(crate) fn normalize_version(version: &str) -> &str {
    let mut chars = version.chars();
    if matches!(chars.next(), Some('v') | Some('V'))
        && chars.next().map(|c| c.is_ascii_digit()).unwrap_or(false)
    {
        return &version[1..];
    }
    version
}

/// How far above the vendor directory [`resolve_project_root`] looks for
/// the composer manifest. `config.vendor-dir` may nest the vendor tree
/// (`lib/deps`), so the project root is not always the immediate parent;
/// the walk is bounded so an unrelated `composer.json` far up the
/// filesystem can't widen the write boundary.
const PROJECT_ROOT_SEARCH_DEPTH: usize = 3;

/// Read `config.vendor-dir` out of a composer.json body, mirroring the
/// slice of Composer's `Config::get('vendor-dir')` that matters here:
/// trailing separators are trimmed (`"vendor/"` is legal) and an empty
/// value counts as unset.
///
/// Composer additionally expands `$HOME`/`~`/`%VAR%` placeholders
/// (`Platform::expandPath`); that is deliberately NOT implemented — an
/// unexpanded value simply resolves to a directory that does not exist,
/// so discovery reports nothing rather than guessing at a path.
fn parse_config_vendor_dir(composer_json: &str) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_str(composer_json).ok()?;
    let raw = doc.get("config")?.get("vendor-dir")?.as_str()?;
    let trimmed = raw.trim_end_matches(['/', '\\']);
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Resolve the vendor directory of a local project the way Composer does:
/// `COMPOSER_VENDOR_DIR` wins, else composer.json `config.vendor-dir`
/// (relative to the manifest directory), else `vendor`.
///
/// Composer relocates the WHOLE vendor tree — `composer/installed.json`
/// included — so assuming `<cwd>/vendor` makes every installed package
/// invisible: scan reports them as lockfile-only ("not yet installed")
/// and apply resolves them as `package_not_found`.
///
/// Returns `None` when composer.json configures a value that is not a
/// plain relative subpath. That value comes from the project being
/// scanned and names the directory apply later WRITES patch content into,
/// so `../../elsewhere` or `/etc` is refused outright rather than
/// silently downgraded to `vendor/` (which would patch an unrelated
/// tree). Absolute paths are legal in Composer but are refused for the
/// same reason; a project using one discovers nothing, exactly as today.
/// `COMPOSER_VENDOR_DIR` is not gated — it comes from the invoking
/// environment, the same trust level as `CARGO_HOME` / `NUGET_PACKAGES` /
/// `MAVEN_REPO_LOCAL`, which are all honored verbatim.
async fn resolve_local_vendor_dir(cwd: &Path) -> Option<PathBuf> {
    // A set-but-empty value counts as unset (twin of the MAVEN_REPO_LOCAL
    // and NUGET_PACKAGES rules): honoring `""` would resolve the vendor
    // tree to the project root itself.
    if let Some(from_env) = std::env::var("COMPOSER_VENDOR_DIR")
        .ok()
        .map(|v| v.trim_end_matches(['/', '\\']).to_string())
        .filter(|v| !v.is_empty())
    {
        // `join` substitutes an absolute value for the base, matching
        // Composer's own relative-to-the-manifest-dir resolution.
        return Some(cwd.join(from_env));
    }

    match read_config_vendor_dir(&cwd.join("composer.json")).await {
        Some(configured) => normalize_config_vendor_dir(&configured)
            .filter(|normalized| path_safety::is_safe_multi_segment(normalized))
            .map(|normalized| cwd.join(normalized)),
        None => Some(cwd.join("vendor")),
    }
}

/// Reduce a `config.vendor-dir` value to plain `a/b` segments before the
/// safety gate. Composer accepts `./`-prefixed and `.`-interleaved values
/// (`./vendor`, `lib/./deps`) and either separator; refusing those shapes
/// outright regressed projects that previously resolved fine at the
/// hardcoded `vendor/`. `..` is resolved lexically the way Composer's own
/// path resolution does; a value that climbs above the project root (or
/// reduces to it) fails closed as `None`.
fn normalize_config_vendor_dir(raw: &str) -> Option<String> {
    if raw.starts_with(['/', '\\']) {
        return None;
    }
    let mut segments: Vec<&str> = Vec::new();
    for segment in raw.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    (!segments.is_empty()).then(|| segments.join("/"))
}

/// Read `config.vendor-dir` from a composer.json on disk. Opened with
/// [`crate::utils::fs::open_regular_file`] for the same reason
/// installed.json is: the manifest belongs to the untrusted project, and
/// a FIFO planted at that path would wedge a plain read forever.
async fn read_config_vendor_dir(manifest_path: &Path) -> Option<String> {
    use tokio::io::AsyncReadExt;

    let (mut file, metadata) = crate::utils::fs::open_regular_file(manifest_path)
        .await
        .ok()?;
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content).await.ok()?;
    parse_config_vendor_dir(&content)
}

/// The directory an installed.json `install-path` may not escape.
///
/// `install-path` legitimately points OUTSIDE the vendor tree — that is
/// the entire point of composer/installers (`extra.installer-paths`,
/// `type: wordpress-plugin`) — so the boundary cannot be the vendor root.
/// But installed.json is untrusted, tamperable input and the resolved
/// directory is a patch WRITE target, so it must stay inside the project:
/// the nearest ancestor of the vendor directory carrying a composer
/// manifest, else the vendor directory's immediate parent.
///
/// Derived from the vendor path alone so scan (`crawl_all`) and apply
/// (`find_by_purls`, which is only ever handed the vendor directory)
/// agree on the boundary; disagreeing would surface packages in scan that
/// apply then refuses to resolve.
async fn resolve_project_root(vendor_path: &Path) -> PathBuf {
    let mut fallback = None;
    for ancestor in vendor_path
        .ancestors()
        .skip(1)
        .take(PROJECT_ROOT_SEARCH_DEPTH)
    {
        if fallback.is_none() {
            fallback = Some(ancestor.to_path_buf());
        }
        if is_file(&ancestor.join("composer.json")).await
            || is_file(&ancestor.join("composer.lock")).await
        {
            return normalize_lexically(ancestor).unwrap_or_else(|| ancestor.to_path_buf());
        }
    }
    let root = fallback.unwrap_or_else(|| vendor_path.to_path_buf());
    normalize_lexically(&root).unwrap_or(root)
}

/// Resolve `.`/`..` without touching the filesystem, so a path can be
/// containment-checked BEFORE it is opened (a canonicalizing check would
/// have to stat the very path being validated, and would fail on
/// not-yet-existing directories). Returns `None` when `..` pops above the
/// path's own root — nothing legitimate does that, so it fails closed.
///
/// Symlinks are not resolved: a symlink INSIDE the project pointing out
/// of it is a pre-existing trust decision of the project's own tree, the
/// same assumption the rest of the crawler layer makes.
fn normalize_lexically(path: &Path) -> Option<PathBuf> {
    use std::path::Component;

    let mut out = PathBuf::new();
    let mut depth = 0usize;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if depth == 0 {
                    return None;
                }
                out.pop();
                depth -= 1;
            }
            Component::Normal(segment) => {
                out.push(segment);
                depth += 1;
            }
        }
    }
    Some(out)
}

/// Resolve an installed.json `install-path` against the vendor tree.
///
/// Composer records it relative to `vendor/composer/` (the directory
/// holding installed.json), not to the vendor root. Returns `None` when
/// the resolved directory leaves `project_root`
/// ([`resolve_project_root`]) — fail closed, no fallback to
/// `vendor/<ns>/<name>`: an entry that claims to live somewhere out of
/// tree must not redirect the patch onto an unrelated directory.
fn resolve_install_path(
    vendor_path: &Path,
    project_root: &Path,
    install_path: &str,
) -> Option<PathBuf> {
    if install_path.contains('\0') {
        return None;
    }
    // `join` substitutes an absolute `install-path` (Composer writes one
    // for some path repositories) for the base; the containment check
    // below is what keeps it in bounds either way.
    let joined = vendor_path.join("composer").join(install_path);
    let resolved = normalize_lexically(&joined)?;
    resolved.starts_with(project_root).then_some(resolved)
}

/// The on-disk directory of an installed.json entry.
///
/// `install-path` is authoritative when recorded: Composer 2 writes it for
/// every package, and for composer/installers targets (WordPress plugins,
/// Drupal modules, `extra.installer-paths`) it is the ONLY record of where
/// the package really lives. Entries without one (Composer 1, hand-written
/// metadata) keep the conventional `vendor/<namespace>/<name>` layout.
fn resolve_package_dir(
    vendor_path: &Path,
    project_root: &Path,
    entry: &ComposerPackageEntry,
) -> Option<PathBuf> {
    match entry.install_path.as_deref() {
        Some(install_path) => resolve_install_path(vendor_path, project_root, install_path),
        None => {
            let (namespace, name) = entry.name.split_once('/')?;
            Some(vendor_path.join(namespace).join(name))
        }
    }
}

/// Whether an installed.json package name is safe to join onto the
/// vendor root. Both `crawl_all` and `find_by_purls` split the recorded
/// name at `/` and join the pieces onto the vendor directory, and the
/// resolved directory is later patched in place — so a tampered
/// installed.json name like `../evil` would otherwise read (and later
/// write) out of tree. Every `/`-separated segment must be a safe single
/// segment ([`path_safety::is_safe_multi_segment`]), which also rejects
/// `.`/`..`, backslashes, colons (a Windows drive-relative `C:evil`
/// joins as an absolute path), NULs, and empty segments. Fails closed.
/// Twin of the npm/deno/go/cargo/maven/nuget coordinate gates.
fn is_safe_composer_name(name: &str) -> bool {
    path_safety::is_safe_multi_segment(name)
}

/// Read and parse `vendor/composer/installed.json`.
///
/// Supports both Composer 1 (flat JSON array) and Composer 2
/// (`{"packages": [...]}`) formats. Parsing is intentionally lenient:
/// the file is read as untyped JSON and entries are extracted one at a
/// time, so a single malformed entry (missing/non-string `name` or
/// `version`, or extra unexpected fields) is skipped rather than
/// discarding every package in the file.
async fn read_installed_json(vendor_path: &Path) -> Vec<ComposerPackageEntry> {
    use tokio::io::AsyncReadExt;

    let installed_path = vendor_path.join("composer").join("installed.json");

    // The path lives inside the (untrusted) vendor tree: a planted FIFO
    // would make a plain `read_to_string` open block forever waiting for
    // a writer, wedging scan (crawl_all) and apply (find_by_purls) with
    // no error and no timeout. `get_vendor_paths` is no defense — global
    // mode (`--global` / `--global-prefix`) hands the vendor directory
    // straight here having only checked `is_dir`, and local mode's
    // `is_file` probe is a separate stat that the file can change under.
    // Open via `open_regular_file` — non-blocking on Unix, rejecting
    // FIFOs/devices/directories (see its docs). Twin of the npm
    // crawler's `read_package_json` guard.
    let Ok((mut file, metadata)) = crate::utils::fs::open_regular_file(&installed_path).await
    else {
        return Vec::new();
    };
    let mut content = String::with_capacity(metadata.len() as usize);
    if file.read_to_string(&mut content).await.is_err() {
        return Vec::new();
    }

    let root: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    // Composer 2 wraps the list in `{"packages": [...]}`; Composer 1 is
    // a bare top-level array.
    let entries = match root.get("packages").and_then(|p| p.as_array()) {
        Some(arr) => arr,
        None => match root.as_array() {
            Some(arr) => arr,
            None => return Vec::new(),
        },
    };

    entries
        .iter()
        .filter_map(|entry| {
            let name = entry.get("name")?.as_str()?;
            let version = entry.get("version")?.as_str()?;
            if name.is_empty() || version.is_empty() || !is_safe_composer_name(name) {
                return None;
            }
            // `install-path` is NOT gated here: it is legitimately a
            // `..`-prefixed path out of `vendor/composer/`, so the
            // coordinate gate cannot be a per-segment one. It is validated
            // when resolved instead ([`resolve_install_path`]).
            let install_path = entry
                .get("install-path")
                .and_then(|p| p.as_str())
                .filter(|p| !p.is_empty())
                .map(str::to_string);
            Some(ComposerPackageEntry {
                name: name.to_string(),
                version: version.to_string(),
                install_path,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_crawl_all_composer() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        // Create installed.json (v2 format)
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "symfony/console", "version": "6.4.1"}
            ]}"#,
        )
        .await
        .unwrap();

        // Create package directories
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();

        // Create composer.json so it's recognized as a PHP project
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:composer/monolog/monolog@3.5.0"));
        assert!(purls.contains("pkg:composer/symfony/console@6.4.1"));

        // Verify namespace is set
        let monolog = packages.iter().find(|p| p.name == "monolog").unwrap();
        assert_eq!(monolog.namespace, Some("monolog".to_string()));
    }

    #[tokio::test]
    async fn test_find_by_purls_composer() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        // Create installed.json
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "symfony/console", "version": "6.4.1"}
            ]}"#,
        )
        .await
        .unwrap();

        // Create package directories
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let purls = vec![
            "pkg:composer/monolog/monolog@3.5.0".to_string(),
            "pkg:composer/symfony/console@6.4.1".to_string(),
            "pkg:composer/guzzle/guzzle@7.0.0".to_string(), // not installed
        ];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("pkg:composer/monolog/monolog@3.5.0"));
        assert!(result.contains_key("pkg:composer/symfony/console@6.4.1"));
        assert!(!result.contains_key("pkg:composer/guzzle/guzzle@7.0.0"));
    }

    #[tokio::test]
    async fn test_installed_json_v1_format() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        // Create installed.json in Composer 1 format (flat array)
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"[
                {"name": "monolog/monolog", "version": "2.9.1"},
                {"name": "psr/log", "version": "3.0.0"}
            ]"#,
        )
        .await
        .unwrap();

        let entries = read_installed_json(vendor_dir).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "monolog/monolog");
        assert_eq!(entries[0].version, "2.9.1");
        assert_eq!(entries[1].name, "psr/log");
        assert_eq!(entries[1].version, "3.0.0");
    }

    #[tokio::test]
    async fn test_installed_json_v2_format() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        // Create installed.json in Composer 2 format
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "symfony/console", "version": "v6.4.1"},
                {"name": "symfony/string", "version": "v6.4.0"}
            ]}"#,
        )
        .await
        .unwrap();

        let entries = read_installed_json(vendor_dir).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "symfony/console");
        assert_eq!(entries[0].version, "v6.4.1");
    }

    #[tokio::test]
    async fn test_non_php_project_returns_empty() {
        let dir = tempfile::tempdir().unwrap();

        // Create vendor dir with installed.json but no composer.json/lock
        let vendor_dir = dir.path().join("vendor");
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "foo/bar", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert!(packages.is_empty());
    }

    #[test]
    fn test_normalize_version() {
        // `v`-prefixed semver versions get the prefix stripped.
        assert_eq!(normalize_version("v6.4.1"), "6.4.1");
        assert_eq!(normalize_version("V6.4.1"), "6.4.1");
        // Bare versions pass through untouched.
        assert_eq!(normalize_version("6.4.1"), "6.4.1");
        // A leading `v` not followed by a digit is part of the version
        // and must be preserved.
        assert_eq!(normalize_version("dev-main"), "dev-main");
        assert_eq!(normalize_version("vendor-tag"), "vendor-tag");
        assert_eq!(normalize_version("v"), "v");
        assert_eq!(normalize_version(""), "");
    }

    #[tokio::test]
    async fn test_crawl_all_strips_v_prefix_from_purl() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // symfony tags releases as `v6.4.1`; installed.json keeps that.
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "symfony/console", "version": "v6.4.1"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        // The emitted PURL and version are the bare (canonical) form.
        assert_eq!(packages[0].purl, "pkg:composer/symfony/console@6.4.1");
        assert_eq!(packages[0].version, "6.4.1");
    }

    #[tokio::test]
    async fn test_find_by_purls_matches_v_prefixed_installed_version() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "symfony/console", "version": "v6.4.1"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        // A canonical (bare) PURL must match the `v`-prefixed installed
        // version, and a `v`-prefixed PURL must match too.
        let purls = vec![
            "pkg:composer/symfony/console@6.4.1".to_string(),
            "pkg:composer/symfony/console@v6.4.1".to_string(),
        ];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains_key("pkg:composer/symfony/console@6.4.1"));
        assert!(result.contains_key("pkg:composer/symfony/console@v6.4.1"));
    }

    #[tokio::test]
    async fn test_read_installed_json_skips_malformed_entries() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // One valid entry surrounded by malformed neighbours: an entry
        // missing `version`, one missing `name`, and a non-object. A
        // single bad entry must not discard the whole file.
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "good/pkg", "version": "1.0.0"},
                {"name": "bad/no-version"},
                {"version": "2.0.0"},
                "not-an-object"
            ]}"#,
        )
        .await
        .unwrap();

        let entries = read_installed_json(vendor_dir).await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "good/pkg");
        assert_eq!(entries[0].version, "1.0.0");
    }

    #[tokio::test]
    async fn test_crawl_all_skips_package_missing_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // installed.json lists two packages but only one has a vendor
        // directory on disk.
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "ghost/pkg", "version": "1.0.0"}
            ]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "monolog");
    }

    #[tokio::test]
    async fn test_crawl_all_composer_v1_flat_array_end_to_end() {
        // crawl_all was only covered with the Composer 2 `{"packages": [...]}`
        // wrapper; pin the Composer 1 bare-array path end-to-end (discovery,
        // on-disk check, PURL build) so a regression in the v1 fallback in
        // read_installed_json is caught at the public-API level.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"[
                {"name": "monolog/monolog", "version": "2.9.1"},
                {"name": "psr/log", "version": "v3.0.0"}
            ]"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("psr").join("log"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.lock"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:composer/monolog/monolog@2.9.1"));
        // The `v` prefix is normalized away even via the v1 array path.
        assert!(purls.contains("pkg:composer/psr/log@3.0.0"));
    }

    #[tokio::test]
    async fn test_read_installed_json_missing_or_invalid_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();

        // No composer/installed.json at all -> empty, no panic.
        assert!(read_installed_json(vendor_dir).await.is_empty());

        // Present but not valid JSON -> empty, no panic.
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(composer_dir.join("installed.json"), "{ not json")
            .await
            .unwrap();
        assert!(read_installed_json(vendor_dir).await.is_empty());

        // Valid JSON but the wrong shape (neither a bare array nor a
        // `{"packages": [...]}` object) -> empty.
        tokio::fs::write(composer_dir.join("installed.json"), r#"{"packages": 42}"#)
            .await
            .unwrap();
        assert!(read_installed_json(vendor_dir).await.is_empty());
    }

    #[tokio::test]
    async fn test_find_by_purls_requires_installed_json() {
        // A package directory present on disk but with NO installed.json
        // must not be returned: the crawler cannot corroborate the version,
        // so it stays consistent with crawl_all (which also yields nothing
        // without installed.json) rather than blindly trusting the path.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        // Note: deliberately no vendor/composer/installed.json.

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/monolog/monolog@3.5.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_find_by_purls_skips_package_missing_on_disk() {
        // installed.json lists the package at the requested version, but its
        // vendor directory is absent (e.g. a metapackage or a custom install
        // path). find_by_purls must skip it — there are no files to patch.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "meta/package", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        // Deliberately do not create vendor/meta/package.

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/meta/package@1.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_crawl_all_dedups_repeated_normalized_purls() {
        // Two installed.json entries that normalize to the same PURL (one
        // `v`-prefixed, one bare) must collapse to a single CrawledPackage so
        // the same on-disk package isn't reported twice.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "symfony/console", "version": "v6.4.1"},
                {"name": "symfony/console", "version": "6.4.1"}
            ]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("symfony").join("console"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:composer/symfony/console@6.4.1");
    }

    #[tokio::test]
    async fn test_crawl_all_canonicalizes_uppercase_name_to_lowercase_purl() {
        // Composer/Packagist treat package names case-insensitively and the
        // canonical PURL is lowercase, but installed.json records the pretty
        // (case-preserved) name. crawl_all must emit a lowercase canonical
        // PURL so it matches Socket's catalog — otherwise an uppercase pretty
        // name silently produces an unmatchable PURL and the vuln is missed.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "Foo/Bar", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        // Composer writes the vendor directory using the pretty (case-
        // preserved) name.
        tokio::fs::create_dir_all(vendor_dir.join("Foo").join("Bar"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        // PURL, name and namespace are the canonical lowercase form...
        assert_eq!(packages[0].purl, "pkg:composer/foo/bar@1.0.0");
        assert_eq!(packages[0].name, "bar");
        assert_eq!(packages[0].namespace, Some("foo".to_string()));
        // ...but the on-disk path keeps the original casing Composer wrote.
        assert_eq!(packages[0].path, vendor_dir.join("Foo").join("Bar"));
    }

    #[tokio::test]
    async fn test_find_by_purls_canonical_purl_matches_case_preserved_install() {
        // A canonical (lowercase) PURL must resolve a package whose
        // installed.json name and on-disk directory carry uppercase letters.
        // The lookup is case-insensitive and the on-disk path is rebuilt from
        // the original installed.json casing so it resolves even on a
        // case-sensitive filesystem.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "Foo/Bar", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("Foo").join("Bar"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/foo/bar@1.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = result.get("pkg:composer/foo/bar@1.0.0").unwrap();
        // The resolved path points at the real (case-preserved) directory.
        assert_eq!(pkg.path, vendor_dir.join("Foo").join("Bar"));
        assert_eq!(pkg.namespace, Some("foo".to_string()));
        assert_eq!(pkg.name, "bar");
    }

    #[tokio::test]
    async fn test_crawl_all_rejects_traversal_name_from_installed_json() {
        // installed.json is part of the (untrusted) project being scanned.
        // A tampered name like `../evil` joins onto the vendor root and
        // resolves to a directory OUTSIDE it; apply would later write patch
        // content there. The crawler must drop such entries — twin of the
        // npm/cargo/maven/nuget/deno/go coordinate gates.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "../evil", "version": "1.0.0"}
            ]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        // The traversal target exists OUTSIDE the vendor root, so the
        // on-disk `is_dir` corroboration alone does not stop it.
        tokio::fs::create_dir_all(dir.path().join("evil"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(
            packages.len(),
            1,
            "traversal entry must be dropped, got: {:?}",
            packages.iter().map(|p| &p.path).collect::<Vec<_>>()
        );
        assert_eq!(packages[0].name, "monolog");
    }

    #[tokio::test]
    async fn test_find_by_purls_rejects_traversal_name_from_installed_json() {
        // Same threat via the lookup path: a manifest purl whose
        // namespace/name mirror a tampered installed.json entry would
        // resolve a package directory outside the vendor root and hand it
        // to apply as a patch target.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "../evil", "version": "1.0.0"}]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(dir.path().join("evil"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let purls = vec!["pkg:composer/../evil@1.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "traversal name escaped the vendor root: {:?}",
            result.values().map(|p| &p.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_is_safe_composer_name() {
        // Real composer names (vendor/name, case-preserved, dots/dashes).
        assert!(is_safe_composer_name("monolog/monolog"));
        assert!(is_safe_composer_name("Foo/Bar"));
        assert!(is_safe_composer_name("symfony/polyfill-php80"));
        assert!(is_safe_composer_name("phpunit/php-code-coverage"));
        // Traversal, separators, absolute/drive forms, empties.
        assert!(!is_safe_composer_name("../evil"));
        assert!(!is_safe_composer_name("evil/.."));
        assert!(!is_safe_composer_name("./evil"));
        assert!(!is_safe_composer_name("/abs/path"));
        assert!(!is_safe_composer_name("a//b"));
        assert!(!is_safe_composer_name("a\\b/c"));
        assert!(!is_safe_composer_name("C:evil/x"));
        assert!(!is_safe_composer_name(""));
    }

    /// Regression: a FIFO planted at `vendor/composer/installed.json` must be
    /// rejected promptly, never opened blockingly. `tokio::fs::read_to_string`
    /// performs a plain `open(2)`, which on a FIFO waits for a writer that never
    /// comes — wedging `scan` (crawl_all) and `apply` (find_by_purls) forever,
    /// with no error and no timeout. The local-mode `is_file` probe in
    /// `get_vendor_paths` does not cover this: global mode (`--global` /
    /// `--global-prefix`) hands the vendor directory straight to the reader with
    /// no probe at all, and a stat-then-open probe is only a racy pre-check
    /// anyway. Same class as the npm crawler's `read_package_json` FIFO fix and
    /// the `open_regular_file` guards in `patch/file_hash.rs`.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_read_installed_json_rejects_fifo_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // A real package directory sits next to the FIFO, so an empty result
        // below is the unreadable metadata being skipped, not a missing tree.
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();

        let fifo = composer_dir.join("installed.json");
        // mkfifo(2) directly rather than spawning /usr/bin/mkfifo: the syscall
        // needs no child process (a fork/exec here flaked under parallel load
        // in the npm twin).
        let c_path = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no NUL")
        };
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );

        // On timeout the open is wedged in a `spawn_blocking` thread that the
        // runtime joins at shutdown; connect a writer to release it so the test
        // FAILS instead of hanging the whole suite.
        let release_and_panic = |what: &str| -> ! {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("{what} must complete promptly with a FIFO installed.json");
        };
        let deadline = std::time::Duration::from_secs(5);

        let Ok(entries) = tokio::time::timeout(deadline, read_installed_json(&vendor_dir)).await
        else {
            release_and_panic("read_installed_json");
        };
        assert!(entries.is_empty(), "a FIFO is not a valid installed.json");

        let crawler = ComposerCrawler::new();
        // Global mode: `get_vendor_paths` returns the prefix verbatim, with no
        // `is_file` probe on installed.json — the reader is reached directly.
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: true,
            global_prefix: Some(vendor_dir.clone()),
        };
        let Ok(packages) = tokio::time::timeout(deadline, crawler.crawl_all(&options)).await else {
            release_and_panic("crawl_all (scan)");
        };
        assert!(
            packages.is_empty(),
            "a FIFO installed.json must yield no packages, got: {packages:?}"
        );

        let purls = vec!["pkg:composer/monolog/monolog@3.5.0".to_string()];
        let Ok(found) =
            tokio::time::timeout(deadline, crawler.find_by_purls(&vendor_dir, &purls)).await
        else {
            release_and_panic("find_by_purls (apply's resolver)");
        };
        assert!(
            found.unwrap().is_empty(),
            "a FIFO installed.json must resolve no package"
        );
    }

    #[test]
    fn test_parse_config_vendor_dir() {
        assert_eq!(
            parse_config_vendor_dir(r#"{"config":{"vendor-dir":"lib/deps"}}"#).as_deref(),
            Some("lib/deps")
        );
        // Composer rtrims trailing separators before using the value.
        assert_eq!(
            parse_config_vendor_dir(r#"{"config":{"vendor-dir":"lib/deps/"}}"#).as_deref(),
            Some("lib/deps")
        );
        // No config block, no key, wrong type, empty value, malformed JSON —
        // all "unset", so the caller falls back to `vendor`.
        assert_eq!(parse_config_vendor_dir("{}"), None);
        assert_eq!(parse_config_vendor_dir(r#"{"config":{}}"#), None);
        assert_eq!(
            parse_config_vendor_dir(r#"{"config":{"vendor-dir":7}}"#),
            None
        );
        assert_eq!(
            parse_config_vendor_dir(r#"{"config":{"vendor-dir":""}}"#),
            None
        );
        assert_eq!(
            parse_config_vendor_dir(r#"{"config":{"vendor-dir":"/"}}"#),
            None
        );
        assert_eq!(parse_config_vendor_dir("{ not json"), None);
    }

    #[test]
    fn test_normalize_config_vendor_dir() {
        let n = normalize_config_vendor_dir;
        // Composer-legal `./` prefixes and `.` segments reduce to the
        // plain path; either separator is accepted.
        assert_eq!(n("./vendor").as_deref(), Some("vendor"));
        assert_eq!(n("./lib/deps").as_deref(), Some("lib/deps"));
        assert_eq!(n("lib/./deps").as_deref(), Some("lib/deps"));
        assert_eq!(n("lib\\deps").as_deref(), Some("lib/deps"));
        assert_eq!(n("lib/../deps").as_deref(), Some("deps"));
        assert_eq!(n("vendor").as_deref(), Some("vendor"));
        // Escaping the project, reducing to it, or absolute — fail closed.
        assert_eq!(n(".."), None);
        assert_eq!(n("../elsewhere"), None);
        assert_eq!(n("lib/../.."), None);
        assert_eq!(n("."), None);
        assert_eq!(n("a/.."), None);
        assert_eq!(n("/etc/vendor"), None);
        assert_eq!(n("\\\\share\\vendor"), None);
        // A drive-letter segment survives normalization; the
        // `is_safe_multi_segment` gate downstream rejects the colon.
        assert_eq!(
            n("C:\\Users\\x\\vendor").as_deref(),
            Some("C:/Users/x/vendor")
        );
        assert!(!crate::patch::path_safety::is_safe_multi_segment(
            "C:/Users/x/vendor"
        ));
    }

    #[test]
    fn test_normalize_lexically() {
        let n = |p: &str| normalize_lexically(Path::new(p));
        // `.` drops out, `..` pops the previous segment.
        assert_eq!(
            n("/a/b/composer/../monolog/monolog").unwrap(),
            PathBuf::from("/a/b/monolog/monolog")
        );
        assert_eq!(
            n("/a/b/composer/./installers").unwrap(),
            PathBuf::from("/a/b/composer/installers")
        );
        assert_eq!(n("/a/b/c/../../../web/x").unwrap(), PathBuf::from("/web/x"));
        // Popping above the path's own root fails closed.
        assert_eq!(n("/a/../.."), None);
        assert_eq!(n("../x"), None);
        // Relative paths stay relative.
        assert_eq!(n("a/b/../c").unwrap(), PathBuf::from("a/c"));
    }

    #[tokio::test]
    async fn test_resolve_project_root_finds_manifest_above_nested_vendor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        let vendor = root.join("lib").join("deps");
        tokio::fs::create_dir_all(&vendor).await.unwrap();
        tokio::fs::write(root.join("composer.json"), "{}")
            .await
            .unwrap();

        // A `config.vendor-dir` can nest the vendor tree, so the project root
        // is not the vendor dir's parent — it is the nearest ancestor holding
        // the manifest.
        assert_eq!(resolve_project_root(&vendor).await, root);

        // With no manifest anywhere above, the immediate parent is the
        // boundary rather than an unbounded walk up the filesystem.
        let orphan = dir.path().join("orphan").join("vendor");
        tokio::fs::create_dir_all(&orphan).await.unwrap();
        assert_eq!(
            resolve_project_root(&orphan).await,
            dir.path().join("orphan")
        );
    }

    #[tokio::test]
    async fn test_crawl_all_without_install_path_uses_conventional_layout() {
        // Composer 1 (and hand-written metadata) records no install-path;
        // those entries must keep resolving to vendor/<namespace>/<name>.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"[{"name": "monolog/monolog", "version": "3.5.0"}]"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        tokio::fs::write(dir.path().join("composer.json"), "{}")
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].path, vendor_dir.join("monolog").join("monolog"));
    }

    #[tokio::test]
    async fn test_find_by_purls_version_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [{"name": "monolog/monolog", "version": "3.5.0"}]}"#,
        )
        .await
        .unwrap();

        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();

        let crawler = ComposerCrawler::new();
        // Request a different version than installed
        let purls = vec!["pkg:composer/monolog/monolog@2.0.0".to_string()];
        let result = crawler.find_by_purls(&vendor_dir, &purls).await.unwrap();

        assert!(result.is_empty());
    }
}
