use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::composer_version::composer_versions_equivalent;
use crate::utils::fs::{is_dir, is_dir_sync, is_file, run_blocking};
use crate::utils::process::{CommandRunner, GlobalProbeRunner};
use crate::utils::relpath::normalize_lexically;

#[cfg(test)]
mod oracle;

/// PHP/Composer ecosystem crawler for discovering packages in Composer
/// vendor directories.
pub struct ComposerCrawler;

/// A single package entry distilled from installed.json. Only the
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
    /// The package `type` (`library`, `wordpress-plugin`, ...), which
    /// decides whether composer/installers relocates it.
    package_type: Option<String>,
    /// The package's own `extra.installer-name`, which composer/installers
    /// uses in place of the package name for `{$name}`.
    installer_name: Option<String>,
}

/// How composer/installers lays out a project, for entries whose
/// installed.json record has no `install-path` (Composer 1). Composer 2
/// records the directory composer/installers chose; Composer 1 does not,
/// so it has to be worked out again from the same inputs the plugin used.
#[derive(Default)]
struct InstallerLayout {
    /// composer/installers is installed. Without it Composer puts every
    /// package under `vendor/`, whatever its type or `installer-paths`.
    active: bool,
    /// The root composer.json `extra.installer-paths`, in file order:
    /// (path template, rules such as `acme/tool`, `type:x`, `vendor:y`).
    paths: Vec<(String, Vec<String>)>,
}

/// Framework prefixes of the package types composer/installers handles
/// (`<framework>-<kind>`, e.g. `wordpress-plugin`). Any other type
/// (`library`, `composer-plugin`, `symfony-bundle`, ...) stays in
/// `vendor/` even when an `installer-paths` rule names it.
const INSTALLER_FRAMEWORKS: &[&str] = &[
    "agl",
    "akaunting",
    "annotatecms",
    "asgard",
    "attogram",
    "bitrix",
    "bonefish",
    "cakephp",
    "chef",
    "civicrm",
    "ccframework",
    "cockpit",
    "codeigniter",
    "concrete5",
    "craft",
    "croogo",
    "dframe",
    "decibel",
    "dokuwiki",
    "dolibarr",
    "drupal",
    "ee2",
    "ee3",
    "elgg",
    "eliasis",
    "ezplatform",
    "fuel",
    "fuelphp",
    "grav",
    "hurad",
    "imagecms",
    "itop",
    "joomla",
    "kanboard",
    "known",
    "kodicms",
    "kohana",
    "lms",
    "laravel",
    "lavalite",
    "lithium",
    "magento",
    "majima",
    "mako",
    "mantisbt",
    "matomo",
    "mautic",
    "maya",
    "mediawiki",
    "miaoxing",
    "microweber",
    "modulework",
    "modx",
    "modxevo",
    "moodle",
    "october",
    "ontowiki",
    "osclass",
    "oxid",
    "phpbb",
    "piwik",
    "pimcore",
    "plentymarkets",
    "porto",
    "ppi",
    "processwire",
    "puppet",
    "pxcms",
    "radphp",
    "redaxo",
    "redaxo5",
    "reindex",
    "roundcube",
    "shopware",
    "silverstripe",
    "smf",
    "starbug",
    "sydes",
    "sylius",
    "symfony1",
    "tao",
    "tastyigniter",
    "thelia",
    "tusk",
    "typo3",
    "userfrosting",
    "vanilla",
    "whmcs",
    "winter",
    "wolfcms",
    "wordpress",
    "yawik",
    "zend",
    "zikula",
];

/// composer/installers' built-in locations for the frameworks whose
/// installers leave `{$name}` as is (WordPress, Drupal), used when no
/// `installer-paths` rule matches. Other frameworks transform the name
/// (CakePHP camel-cases it, ...), so they are found only through an
/// explicit `installer-paths` rule.
const INSTALLER_DEFAULT_LOCATIONS: &[(&str, &str)] = &[
    ("wordpress-plugin", "wp-content/plugins/{$name}/"),
    ("wordpress-theme", "wp-content/themes/{$name}/"),
    ("wordpress-muplugin", "wp-content/mu-plugins/{$name}/"),
    ("wordpress-dropin", "wp-content/{$name}/"),
    ("drupal-core", "core/"),
    ("drupal-module", "modules/{$name}/"),
    ("drupal-theme", "themes/{$name}/"),
    ("drupal-library", "libraries/{$name}/"),
    ("drupal-profile", "profiles/{$name}/"),
    (
        "drupal-database-driver",
        "drivers/lib/Drupal/Driver/Database/{$name}/",
    ),
    ("drupal-drush", "drush/{$name}/"),
    ("drupal-custom-theme", "themes/custom/{$name}/"),
    ("drupal-custom-module", "modules/custom/{$name}/"),
    ("drupal-custom-profile", "profiles/custom/{$name}/"),
    ("drupal-multisite", "sites/{$name}/"),
    ("drupal-console", "console/{$name}/"),
    ("drupal-console-language", "console/language/{$name}/"),
    ("drupal-config", "config/sync/"),
];

impl InstallerLayout {
    /// Read the layout for one vendor tree: whether composer/installers is
    /// among its installed packages, and the project's `installer-paths`.
    async fn load(project_root: &Path, entries: &[ComposerPackageEntry]) -> Self {
        let active = entries
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case("composer/installers"));
        if !active {
            return Self::default();
        }
        let paths = crate::utils::fs::read_regular_to_string(&project_root.join("composer.json"))
            .await
            .ok()
            .map(|content| parse_installer_paths(&content))
            .unwrap_or_default();
        Self { active, paths }
    }

    /// Where composer/installers put `entry`, mirroring its
    /// `BaseInstaller::getInstallPath`: the first `installer-paths` entry
    /// with a rule naming the package, its `type:` or its `vendor:`, else
    /// the framework's built-in location. `None` when the plugin would not
    /// relocate the package, or the path leaves `project_root`.
    fn locate(&self, project_root: &Path, entry: &ComposerPackageEntry) -> Option<PathBuf> {
        if !self.active {
            return None;
        }
        let package_type = entry.package_type.as_deref()?;
        let (framework, _) = package_type.split_once('-')?;
        if !INSTALLER_FRAMEWORKS.contains(&framework) {
            return None;
        }
        let (vendor, name) = entry.name.split_once('/')?;
        let template = self
            .paths
            .iter()
            .find(|(_, rules)| {
                rules.iter().any(|rule| {
                    *rule == entry.name
                        || rule.strip_prefix("type:") == Some(package_type)
                        || rule.strip_prefix("vendor:") == Some(vendor)
                })
            })
            .map(|(path, _)| path.as_str())
            .or_else(|| {
                INSTALLER_DEFAULT_LOCATIONS
                    .iter()
                    .find(|(t, _)| *t == package_type)
                    .map(|(_, path)| *path)
            })?;
        let name = entry.installer_name.as_deref().unwrap_or(name);
        let rendered = render_installer_path(template, name, vendor, package_type)?;
        contain_in_project(project_root, &project_root.join(rendered))
    }
}

/// The root composer.json `extra.installer-paths` map, in file order. A
/// path's value is a list of rules or a single rule string.
fn parse_installer_paths(composer_json: &str) -> Vec<(String, Vec<String>)> {
    let Ok(root) = serde_json::from_str::<serde_json::Value>(composer_json) else {
        return Vec::new();
    };
    let Some(map) = root
        .get("extra")
        .and_then(|e| e.get("installer-paths"))
        .and_then(|p| p.as_object())
    else {
        return Vec::new();
    };
    map.iter()
        .map(|(path, rules)| {
            let rules = match rules {
                serde_json::Value::String(rule) => vec![rule.clone()],
                serde_json::Value::Array(list) => list
                    .iter()
                    .filter_map(|r| r.as_str().map(str::to_string))
                    .collect(),
                _ => Vec::new(),
            };
            (path.clone(), rules)
        })
        .collect()
}

/// Substitute composer/installers' `{$name}`, `{$vendor}` and `{$type}`
/// placeholders. `None` for a NUL or any other placeholder, which the
/// plugin would render as an empty string; guessing that layout could
/// point the patch at the wrong directory.
fn render_installer_path(
    template: &str,
    name: &str,
    vendor: &str,
    package_type: &str,
) -> Option<String> {
    let rendered = template
        .replace("{$name}", name)
        .replace("{$vendor}", vendor)
        .replace("{$type}", package_type);
    (!rendered.contains("{$") && !rendered.contains('\0')).then_some(rendered)
}

impl ComposerCrawler {
    /// Create a new `ComposerCrawler`.
    pub fn new() -> Self {
        Self
    }

    /// Get vendor paths based on options.
    ///
    /// In global mode, checks the global project's vendor directory under
    /// `$COMPOSER_HOME` (env var, command fallback, or platform defaults),
    /// resolved through the same `vendor-dir` cascade as a local project.
    ///
    /// In local mode, checks the project's vendor directory
    /// (`COMPOSER_VENDOR_DIR` / composer.json `config.vendor-dir` /
    /// `$COMPOSER_HOME/config.json` / `vendor`, see
    /// [`resolve_vendor_dir`]) but only if the
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
                let vendor_dir = run_blocking(move || global_vendor_dir_sync(&composer_home)).await;
                if let Some(vendor_dir) = vendor_dir {
                    if is_dir(&vendor_dir).await {
                        paths.push(vendor_dir);
                    }
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
            let installers = InstallerLayout::load(&project_root, &entries).await;
            // Resolve every entry's candidate directories first (pure path
            // logic), then stat them all in one blocking-pool task instead
            // of one hop each; the loop below consumes the answers in entry
            // order.
            let candidates: Vec<Vec<PathBuf>> = entries
                .iter()
                .map(|entry| resolve_package_dir(vendor_path, &project_root, &installers, entry))
                .collect();
            let resolved = first_existing_dirs(candidates).await;
            for (entry, pkg_path) in entries.into_iter().zip(resolved) {
                if let Some((namespace, name)) = entry.name.split_once('/') {
                    // Skip packages that installed.json lists but that are
                    // not actually on disk (stale metadata, a metapackage).
                    // This keeps crawl_all consistent with find_by_purls,
                    // which only returns packages whose directory exists.
                    let Some(pkg_path) = pkg_path else {
                        continue;
                    };

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
        let project_root = resolve_project_root(vendor_path).await;
        let installers = InstallerLayout::load(&project_root, &entries).await;
        let installed: HashMap<String, ComposerPackageEntry> = entries
            .into_iter()
            .map(|e| (e.name.to_ascii_lowercase(), e))
            .collect();

        // Resolve each PURL's directory first (pure lookups), then stat
        // them all in one blocking-pool task instead of one hop each.
        // (namespace, name, version), as the purl parser handed them back.
        type Coords<'a> = (Cow<'a, str>, Cow<'a, str>, Cow<'a, str>);
        let mut matches: Vec<(&String, Coords<'_>, Vec<PathBuf>)> = Vec::new();
        for purl in purls {
            if let Some(((namespace_part, name_part), version_part)) =
                crate::utils::purl::parse_composer_purl(purl)
            {
                let (namespace, name, version) = (
                    namespace_part.as_ref(),
                    name_part.as_ref(),
                    version_part.as_ref(),
                );
                let full_name = format!("{namespace}/{name}").to_ascii_lowercase();

                let Some(entry) = installed.get(&full_name) else {
                    continue;
                };

                // Verify version matches installed.json by composer release
                // identity: installed.json's pretty `v6.4.1` / `3.0.2`
                // matches a purl's `6.4.1` / padded `3.0.2.0`.
                if !composer_versions_equivalent(&entry.version, version) {
                    continue;
                }

                // Resolve the on-disk directory from installed.json's own
                // record — its `install-path` when present, else where
                // composer/installers or the conventional layout put it,
                // under the original (case-preserved) casing Composer wrote
                // to disk; the canonical (lowercase) PURL name would miss it
                // on a case-sensitive filesystem.
                let candidates =
                    resolve_package_dir(vendor_path, &project_root, &installers, entry);

                matches.push((purl, (namespace_part, name_part, version_part), candidates));
            }
        }

        let (matches, candidates): (Vec<_>, Vec<_>) = matches
            .into_iter()
            .map(|(purl, coords, candidates)| ((purl, coords), candidates))
            .unzip();
        let resolved = first_existing_dirs(candidates).await;
        for ((purl, (namespace, name, version)), pkg_dir) in matches.into_iter().zip(resolved) {
            let Some(pkg_dir) = pkg_dir else {
                continue;
            };

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

        Ok(result)
    }
}

impl Default for ComposerCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether each path is a directory (following symlinks; a failed stat is
/// "no", `None` is "no" without a stat), in one blocking-pool task.
async fn dirs_exist(paths: Vec<Option<PathBuf>>) -> Vec<bool> {
    if paths.iter().all(Option::is_none) {
        return vec![false; paths.len()];
    }
    run_blocking(move || {
        paths
            .iter()
            .map(|path| path.as_deref().is_some_and(is_dir_sync))
            .collect()
    })
    .await
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

/// A process-wide memo of one subprocess answer, reused only while the
/// whole environment (every variable, and the working directory) is exactly
/// what it was when the answer was produced — the subprocess's only inputs
/// the CLI controls. A different environment re-runs it and replaces the
/// entry; concurrent first callers may each run it.
///
/// Only an answer is kept. A FAILED probe (spawn error under fd pressure,
/// a non-zero exit, empty stdout) is asked again by the next caller —
/// global discovery runs at least twice per command (the crawl, then the
/// package-lookup pass), so a transient first failure must not stick. So
/// is an answer the environment changed under, which the key would
/// misfile. Same rule as the `gem env`
/// memo in `ruby_crawler`.
struct EnvKeyedMemo {
    slot: std::sync::Mutex<Option<(EnvKey, String)>>,
}

type EnvKey = (
    Vec<(std::ffi::OsString, std::ffi::OsString)>,
    Option<PathBuf>,
);

/// What the subprocess inherits: the (sorted) environment and the working
/// directory. Sorted so a `remove_var`/`set_var` round-trip that restores
/// an identical environment still matches (`vars_os` yields `environ`'s
/// order, which such a round-trip permutes) — the same key `gem_env_key`
/// builds.
fn env_key() -> EnvKey {
    let mut vars: Vec<_> = std::env::vars_os().collect();
    vars.sort();
    (vars, std::env::current_dir().ok())
}

impl EnvKeyedMemo {
    const fn new() -> Self {
        Self {
            slot: std::sync::Mutex::new(None),
        }
    }

    fn get_or_run(&self, run: impl FnOnce() -> Option<String>) -> Option<String> {
        let key = env_key();
        let ran_under = key.clone();
        self.get_or_run_keyed(key, move || {
            let answer = run();
            // Keepable only if the environment the subprocess actually ran
            // under is still the one we keyed on.
            let env_unchanged = env_key() == ran_under;
            (answer, env_unchanged)
        })
    }

    /// The memoized ask. `run` hands back its answer and whether that
    /// answer is keepable; a `None` answer is never kept. Split from
    /// [`Self::get_or_run`] so tests can drive both against a key of their
    /// own.
    fn get_or_run_keyed(
        &self,
        key: EnvKey,
        run: impl FnOnce() -> (Option<String>, bool),
    ) -> Option<String> {
        let lock = || self.slot.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached_key, answer)) = lock().as_ref() {
            if *cached_key == key {
                return Some(answer.clone());
            }
        }
        let (answer, keepable) = run();
        if let (Some(answer), true) = (&answer, keepable) {
            *lock() = Some((key, answer.clone()));
        }
        answer
    }
}

/// `composer global config home` boots PHP and Composer (0.3-1 s), and
/// global discovery asks for it on every pass (the crawl, then each
/// package-lookup pass of the same command).
static COMPOSER_GLOBAL_HOME: EnvKeyedMemo = EnvKeyedMemo::new();

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

    // Try `composer global config home` (a subprocess: on the blocking pool;
    // memoized for an unchanged environment, see `COMPOSER_GLOBAL_HOME`)
    let stdout = run_blocking(|| {
        COMPOSER_GLOBAL_HOME
            .get_or_run(|| GlobalProbeRunner.run("composer", &["global", "config", "home"]))
    })
    .await;
    if let Some(stdout) = stdout {
        if let Some(path) = parse_composer_home_output(&stdout) {
            if is_dir(&path).await {
                return Some(path);
            }
        }
    }

    // Platform defaults (see `composer_home_candidates`).
    run_blocking(|| default_composer_home(&|name: &str| std::env::var_os(name))).await
}

/// The first of [`composer_home_candidates`] that exists: the platform
/// default home both global and local discovery fall back to.
fn default_composer_home(var: &impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    composer_home_candidates(var, cfg!(windows))
        .into_iter()
        .find(|candidate| is_dir_sync(candidate))
}

/// The directories Composer itself uses as its home when `COMPOSER_HOME`
/// is unset, in the order to probe them (Composer 2's
/// `Factory::getHomeDir`):
///
/// - Windows: `%APPDATA%\Composer` — the only default there; the
///   `~/.composer` probe is kept after it for older layouts.
/// - an XDG system (see [`uses_xdg`]): the XDG home,
///   `$XDG_CONFIG_HOME/composer` or else `~/.config/composer`, when it
///   exists, else `~/.composer`. A leftover `~/.composer` from the
///   Composer 1 era (which probed it first) must not hide the real home.
///   A relative `XDG_CONFIG_HOME` names a directory relative to wherever
///   Composer ran, so its XDG home is skipped rather than guessed.
/// - elsewhere: `~/.composer`.
///
/// `~/.config/composer` stays as a last probe on every platform, so a
/// home there is still found when the XDG detection misses it.
///
/// A set-but-empty or relative variable counts as unset: honoring `""`
/// would turn these probes into CWD-relative paths inside the user's
/// project (same rule as `utils::fs::home_dir`).
pub(crate) fn composer_home_candidates(
    var: &impl Fn(&str) -> Option<std::ffi::OsString>,
    windows: bool,
) -> Vec<PathBuf> {
    let xdg = !windows && (var("XDG_CONFIG_HOME").is_some() || uses_xdg());
    composer_home_candidates_for(var, windows, xdg)
}

/// Composer's `Factory::useXdg`: any `XDG_*` environment variable is
/// set, or `/etc/xdg` exists.
fn uses_xdg() -> bool {
    std::env::vars_os().any(|(key, _)| key.as_encoded_bytes().starts_with(b"XDG_"))
        || is_dir_sync(Path::new("/etc/xdg"))
}

/// [`composer_home_candidates`] with the XDG detection passed in.
fn composer_home_candidates_for(
    var: &impl Fn(&str) -> Option<std::ffi::OsString>,
    windows: bool,
    xdg: bool,
) -> Vec<PathBuf> {
    let absolute = |name: &str| {
        var(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    let home = absolute("HOME").or_else(|| absolute("USERPROFILE"));
    let mut candidates = Vec::new();
    if windows {
        if let Some(app_data) = absolute("APPDATA") {
            candidates.push(app_data.join("Composer"));
        }
    }
    if xdg {
        // Composer treats an empty XDG_CONFIG_HOME as unset.
        let config = match var("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
            Some(_) => absolute("XDG_CONFIG_HOME"),
            None => home.as_ref().map(|home| home.join(".config")),
        };
        if let Some(config) = config {
            candidates.push(config.join("composer"));
        }
    }
    if let Some(home) = &home {
        candidates.push(home.join(".composer"));
    }
    if let Some(home) = &home {
        let config = home.join(".config").join("composer");
        if !candidates.contains(&config) {
            candidates.push(config);
        }
    }
    candidates
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

/// Read `config.vendor-dir` out of a composer.json (or the user-level
/// `config.json`, same `{"config": {...}}` shape) body, mirroring the
/// slice of Composer's `Config::get('vendor-dir')` that matters here:
/// trailing separators are trimmed (`"vendor/"` is legal) and an empty
/// value counts as unset. Placeholder expansion is the caller's call, see
/// [`resolve_vendor_dir`].
fn parse_config_vendor_dir(composer_json: &str) -> Option<String> {
    let doc: serde_json::Value = serde_json::from_str(composer_json).ok()?;
    let raw = doc.get("config")?.get("vendor-dir")?.as_str()?;
    let trimmed = raw.trim_end_matches(['/', '\\']);
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Expand the placeholders Composer expands in every `*-dir` setting
/// (`Platform::expandPath`): a leading `~/` (or `~\`) becomes the user's
/// home, and a leading `$VAR` or `%VAR%` becomes that environment
/// variable. Anything else is returned as is.
///
/// `None` when the placeholder names nothing usable (no home, an unset or
/// empty variable). Composer would substitute `""` there and resolve a
/// root-relative path, which is never the tree a real install used.
fn expand_composer_path(raw: &str, var: &impl Fn(&str) -> Option<OsString>) -> Option<OsString> {
    // Built from `OsString`s so a non-UTF-8 home or variable keeps its bytes.
    let join = |head: OsString, rest: &str| {
        let mut out = head;
        out.push(rest);
        out
    };
    if let Some(rest) = raw.strip_prefix('~') {
        if rest.starts_with(['/', '\\']) {
            let home = crate::utils::fs::home_from_env(var)?;
            return Some(join(home.into_os_string(), rest));
        }
        return Some(raw.into());
    }
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let (name, rest) = if let Some(after) = raw.strip_prefix('$') {
        let end = after.find(|c| !is_word(c)).unwrap_or(after.len());
        (&after[..end], &after[end..])
    } else if let Some(after) = raw.strip_prefix('%') {
        let end = after.find(|c| !is_word(c)).unwrap_or(after.len());
        match after[end..].strip_prefix('%') {
            Some(rest) => (&after[..end], rest),
            None => return Some(raw.into()),
        }
    } else {
        return Some(raw.into());
    };
    if name.is_empty() {
        return Some(raw.into());
    }
    // Composer treats `HOME` as an alias for `USERPROFILE` on Windows.
    let value = match name {
        "HOME" => crate::utils::fs::home_from_env(var).map(PathBuf::into_os_string),
        _ => var(name).filter(|v| !v.is_empty()),
    }?;
    Some(join(value, rest))
}

/// Resolve Composer's `vendor-dir` the way `Config::get` does, highest
/// precedence first:
///
/// 1. `COMPOSER_VENDOR_DIR`;
/// 2. the project's composer.json `config.vendor-dir` (`manifest`);
/// 3. the user-level `$COMPOSER_HOME/config.json` `config.vendor-dir`
///    (`user_config` reads its text; what `composer config -g vendor-dir`
///    writes);
/// 4. `vendor`.
///
/// Every value is expanded (`~/`, `$VAR`, `%VAR%`) and a relative one
/// resolves against `base`: the project directory, or `$COMPOSER_HOME`
/// for the global project. The environment and the Composer home belong
/// to the invoking user, the same trust level as `CARGO_HOME` /
/// `NUGET_PACKAGES` / `MAVEN_REPO_LOCAL`, so they are honoured as given.
///
/// A composer.json that is NOT `manifest_trusted` (the scanned project's)
/// names the directory apply later WRITES patch content into, so it keeps
/// the stricter rule: only a plain relative subpath of the project, no
/// expansion. `../../elsewhere`, `/etc` or `~/deps` is refused (`None`)
/// rather than silently downgraded to `vendor/`, which would patch an
/// unrelated tree. Composer accepts absolute and home-relative values
/// there; refusing them means such a project discovers nothing.
fn resolve_vendor_dir(
    base: &Path,
    manifest: Option<&str>,
    manifest_trusted: bool,
    user_config: impl FnOnce() -> Option<String>,
    var: &impl Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    let honoured = |raw: &str| expand_composer_path(raw, var).map(|value| base.join(value));
    // A set-but-empty value counts as unset (twin of the MAVEN_REPO_LOCAL
    // and NUGET_PACKAGES rules): honoring `""` would resolve the vendor
    // tree to the project root itself. `join` substitutes an absolute
    // value for the base, matching Composer's relative-to-the-base-dir
    // resolution.
    if let Some(from_env) = var("COMPOSER_VENDOR_DIR")
        .and_then(|v| v.into_string().ok())
        .map(|v| v.trim_end_matches(['/', '\\']).to_string())
        .filter(|v| !v.is_empty())
    {
        return honoured(&from_env);
    }
    if let Some(configured) = manifest.and_then(parse_config_vendor_dir) {
        if manifest_trusted {
            return honoured(&configured);
        }
        // A placeholder Composer would expand (`~/x`, `$HOME/x`) names a
        // directory outside the project, never the literal `<proj>/~/x`.
        if expand_composer_path(&configured, var) != Some(OsString::from(&configured)) {
            return None;
        }
        return normalize_config_vendor_dir(&configured)
            .filter(|normalized| path_safety::is_safe_multi_segment(normalized))
            .map(|normalized| base.join(normalized));
    }
    // Read only when nothing above decided: most projects never need it.
    match user_config().as_deref().and_then(parse_config_vendor_dir) {
        Some(configured) => honoured(&configured),
        None => Some(base.join("vendor")),
    }
}

/// `$COMPOSER_HOME` for LOCAL discovery of the project at `cwd`, without
/// running `composer`: the env var exactly as Composer uses it (a relative
/// value against the directory composer runs in, the project; a missing
/// directory just holds no config), else [`default_composer_home`]. Local
/// scans read the user-level `config.json` from here and must not spawn a
/// subprocess to find it.
fn local_composer_home(cwd: &Path, var: &impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    match var("COMPOSER_HOME").filter(|home| !home.is_empty()) {
        Some(home) => Some(cwd.join(home)),
        None => default_composer_home(var),
    }
}

/// The vendor directory of the global project at `composer_home`: its
/// composer.json and config.json both live in the user's own Composer
/// home, so every layer is honoured as Composer honours it (#439).
fn global_vendor_dir_sync(composer_home: &Path) -> Option<PathBuf> {
    let read =
        |name: &str| crate::utils::fs::read_regular_to_string_sync(&composer_home.join(name)).ok();
    let manifest = read("composer.json");
    resolve_vendor_dir(
        composer_home,
        manifest.as_deref(),
        true,
        || read("config.json"),
        &|name| std::env::var_os(name),
    )
}

/// Resolve the vendor directory of a local project the way Composer does
/// (see [`resolve_vendor_dir`] for the cascade and the rules).
///
/// Composer relocates the WHOLE vendor tree — `composer/installed.json`
/// included — so assuming `<cwd>/vendor` makes every installed package
/// invisible: scan reports them as lockfile-only ("not yet installed")
/// and apply resolves them as `package_not_found`.
///
/// Returns `None` when the project's composer.json configures a value the
/// crawler refuses (absolute, home-relative, or climbing out of the
/// project), or a user-level value whose placeholder names nothing.
async fn resolve_local_vendor_dir(cwd: &Path) -> Option<PathBuf> {
    let cwd = cwd.to_path_buf();
    run_blocking(move || resolve_local_vendor_dir_sync(&cwd)).await
}

/// The blocking form of [`resolve_local_vendor_dir`], also used by the
/// human next-step hints that name the installed package directory a user
/// has to remove before `composer install` (#658): those are formatted on
/// a synchronous path after the run, and must name the directory Composer
/// actually installed into, not a hardcoded `vendor/`.
pub fn resolve_local_vendor_dir_sync(cwd: &Path) -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name);
    let read = |path: &Path| crate::utils::fs::read_regular_to_string_sync(path).ok();
    let manifest = read(&cwd.join("composer.json"));
    let user_config =
        || local_composer_home(cwd, &var).and_then(|home| read(&home.join("config.json")));
    resolve_vendor_dir(cwd, manifest.as_deref(), false, user_config, &var)
}

/// Reduce a `config.vendor-dir` value to plain `a/b` segments before the
/// safety gate. Composer accepts `./`-prefixed and `.`-interleaved values
/// (`./vendor`, `lib/./deps`) and either separator, so those shapes must
/// resolve rather than be refused. `..` is resolved lexically the way Composer's own
/// path resolution does; a value that climbs above the project root (or
/// reduces to it) fails closed as `None`.
fn normalize_config_vendor_dir(raw: &str) -> Option<String> {
    if raw.starts_with(['/', '\\']) {
        return None;
    }
    crate::utils::relpath::resolve_rel("", raw, 0).filter(|segments| !segments.is_empty())
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

// `normalize_lexically` (resolve `.`/`..` without touching the filesystem)
// lives in `crate::utils::relpath` with every other lexical normalizer.

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
    contain_in_project(
        project_root,
        &vendor_path.join("composer").join(install_path),
    )
}

/// `joined`, normalized, when it stays inside `project_root`; else `None`.
fn contain_in_project(project_root: &Path, joined: &Path) -> Option<PathBuf> {
    let resolved = normalize_lexically(joined)?;
    // A RELATIVE vendor path (the CLI default is `--cwd .`) yields a
    // relative project root that can normalize to the EMPTY path — and
    // `starts_with("")` holds for EVERY path, absolute ones included, so
    // the prefix check alone is vacuous there. An anchored install-path
    // can never legitimately live inside a relative project root, so
    // require the resolved path to be anchored exactly when the boundary
    // is.
    if is_anchored(&resolved) != is_anchored(project_root) {
        return None;
    }
    resolved.starts_with(project_root).then_some(resolved)
}

/// Whether a path is anchored to a filesystem root: absolute, or carrying
/// a Windows prefix even without a root directory (`C:evil` is
/// drive-relative — `join` substitutes it wholesale, and it resolves
/// against the drive's own cwd, not the project's).
fn is_anchored(path: &Path) -> bool {
    use std::path::Component;

    matches!(
        path.components().next(),
        Some(Component::Prefix(_) | Component::RootDir)
    )
}

/// The directories an installed.json entry may live in, most likely
/// first; the package is at the first that exists.
///
/// `install-path` is authoritative when recorded: Composer 2 writes it for
/// every package, and for composer/installers targets (WordPress plugins,
/// Drupal modules, `extra.installer-paths`) it is the ONLY record of where
/// the package really lives. Entries without one (Composer 1, hand-written
/// metadata) are where composer/installers put them, when it handles them
/// ([`InstallerLayout::locate`]), else the conventional
/// `vendor/<namespace>/<name>` layout. The installer's directory comes
/// first: it is the copy the application loads, and a `vendor/` copy
/// beside it is a leftover.
fn resolve_package_dir(
    vendor_path: &Path,
    project_root: &Path,
    installers: &InstallerLayout,
    entry: &ComposerPackageEntry,
) -> Vec<PathBuf> {
    match entry.install_path.as_deref() {
        Some(install_path) => resolve_install_path(vendor_path, project_root, install_path)
            .into_iter()
            .collect(),
        None => {
            let Some((namespace, name)) = entry.name.split_once('/') else {
                return Vec::new();
            };
            let conventional = vendor_path.join(namespace).join(name);
            match installers.locate(project_root, entry) {
                Some(relocated) => vec![relocated, conventional],
                None => vec![conventional],
            }
        }
    }
}

/// The first directory of each candidate list that exists, stating every
/// candidate in one blocking-pool task ([`dirs_exist`]).
async fn first_existing_dirs(candidates: Vec<Vec<PathBuf>>) -> Vec<Option<PathBuf>> {
    let flat: Vec<Option<PathBuf>> = candidates.iter().flatten().cloned().map(Some).collect();
    let mut on_disk = dirs_exist(flat).await.into_iter();
    candidates
        .into_iter()
        .map(|list| {
            let mut found = None;
            for dir in list {
                if on_disk.next() == Some(true) && found.is_none() {
                    found = Some(dir);
                }
            }
            found
        })
        .collect()
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
    let installed_path = vendor_path.join("composer").join("installed.json");

    // The path lives inside the (untrusted) vendor tree: a planted FIFO
    // would make a plain `read_to_string` open block forever waiting for
    // a writer, wedging scan (crawl_all) and apply (find_by_purls) with
    // no error and no timeout. `get_vendor_paths` is no defense — global
    // mode (`--global` / `--global-prefix`) hands the vendor directory
    // straight here having only checked `is_dir`, and local mode's
    // `is_file` probe is a separate stat that the file can change under.
    // Read via `read_regular_to_string` — non-blocking open on Unix,
    // rejecting FIFOs/devices/directories (see its docs). Twin of the npm
    // crawler's `read_package_json` guard.
    let Ok(content) = crate::utils::fs::read_regular_to_string(&installed_path).await else {
        return Vec::new();
    };

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
            let package_type = entry
                .get("type")
                .and_then(|t| t.as_str())
                .map(str::to_string);
            let installer_name = entry
                .get("extra")
                .and_then(|e| e.get("installer-name"))
                .and_then(|n| n.as_str())
                .filter(|n| !n.is_empty())
                .map(str::to_string);
            Some(ComposerPackageEntry {
                name: name.to_string(),
                version: version.to_string(),
                install_path,
                package_type,
                installer_name,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<std::ffi::OsString> + 'a {
        move |name: &str| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| std::ffi::OsString::from(value))
        }
    }

    /// #586: Composer 2 on an XDG system probes the XDG home before
    /// `~/.composer`.
    #[cfg(unix)]
    #[test]
    fn test_home_candidates_xdg_system_probes_xdg_home_first() {
        assert_eq!(
            composer_home_candidates_for(&env(&[("HOME", "/h")]), false, true),
            vec![
                PathBuf::from("/h/.config/composer"),
                PathBuf::from("/h/.composer"),
            ]
        );
        assert_eq!(
            composer_home_candidates_for(
                &env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/x")]),
                false,
                true
            ),
            vec![
                PathBuf::from("/x/composer"),
                PathBuf::from("/h/.composer"),
                PathBuf::from("/h/.config/composer"),
            ]
        );
        // An empty XDG_CONFIG_HOME counts as unset, as in Composer.
        assert_eq!(
            composer_home_candidates_for(
                &env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "")]),
                false,
                true
            )[0],
            PathBuf::from("/h/.config/composer")
        );
        // A relative one points somewhere under Composer's CWD, not at
        // `~/.config`: probe `~/.composer` first instead of guessing.
        assert_eq!(
            composer_home_candidates_for(
                &env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "rel")]),
                false,
                true
            ),
            vec![
                PathBuf::from("/h/.composer"),
                PathBuf::from("/h/.config/composer"),
            ]
        );
        // With HOME unset nothing is left to probe.
        assert!(composer_home_candidates_for(&env(&[("HOME", "")]), false, true).is_empty());
    }

    /// Off XDG, Composer only uses `~/.composer`; `~/.config/composer`
    /// stays as a last probe.
    #[cfg(unix)]
    #[test]
    fn test_home_candidates_non_xdg_system_probes_dot_composer_first() {
        assert_eq!(
            composer_home_candidates_for(&env(&[("HOME", "/h")]), false, false),
            vec![
                PathBuf::from("/h/.composer"),
                PathBuf::from("/h/.config/composer"),
            ]
        );
        assert!(composer_home_candidates_for(&env(&[("HOME", "")]), false, false).is_empty());
    }

    /// An XDG_CONFIG_HOME in the supplied environment makes it an XDG
    /// system even when the process environment has no `XDG_*` variable.
    #[cfg(unix)]
    #[test]
    fn test_home_candidates_supplied_xdg_config_home_counts_as_xdg() {
        assert_eq!(
            composer_home_candidates(&env(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "/x")]), false)[0],
            PathBuf::from("/x/composer")
        );
    }

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

    /// A patch purl may carry composer's padded `version_normalized`
    /// spelling (`3.0.2.0`) while installed.json records the pretty
    /// `3.0.2` / `v3.0.2` / `1.0` / `8.1.0-RC1`: the same release, found.
    /// A different release is still not found.
    #[tokio::test]
    async fn test_find_by_purls_matches_equivalent_composer_versions() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "psr/log", "version": "3.0.2"},
                {"name": "psr/cache", "version": "v3.0.2"},
                {"name": "psr/container", "version": "1.0"},
                {"name": "symfony/http-kernel", "version": "v8.1.0-RC1"}
            ]}"#,
        )
        .await
        .unwrap();
        for pkg in [
            "psr/log",
            "psr/cache",
            "psr/container",
            "symfony/http-kernel",
        ] {
            tokio::fs::create_dir_all(vendor_dir.join(pkg))
                .await
                .unwrap();
        }

        let found = [
            "pkg:composer/psr/log@3.0.2.0",
            "pkg:composer/psr/log@v3.0.2",
            "pkg:composer/psr/cache@3.0.2.0",
            "pkg:composer/psr/cache@3.0.2",
            "pkg:composer/psr/container@1.0.0.0",
            "pkg:composer/psr/container@1.0.0",
            "pkg:composer/symfony/http-kernel@8.1.0.0-RC1",
            "pkg:composer/symfony/http-kernel@8.1.0-rc.1",
        ];
        let missing = [
            "pkg:composer/psr/log@3.0.20",
            "pkg:composer/psr/log@3.0.2.1",
            "pkg:composer/symfony/http-kernel@8.1.0",
            "pkg:composer/symfony/http-kernel@8.1.0-RC2",
        ];
        let purls: Vec<String> = found
            .iter()
            .chain(&missing)
            .map(|p| p.to_string())
            .collect();
        let result = ComposerCrawler::new()
            .find_by_purls(&vendor_dir, &purls)
            .await
            .unwrap();

        for purl in found {
            let pkg = result
                .get(purl)
                .unwrap_or_else(|| panic!("{purl} not found"));
            assert_eq!(pkg.purl, purl, "the result keeps the requested spelling");
        }
        assert_eq!(result.len(), found.len(), "{:?}", result.keys());
        assert_eq!(
            result["pkg:composer/psr/log@3.0.2.0"].path,
            vendor_dir.join("psr/log")
        );
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

    /// Composer's `Platform::expandPath`: only a LEADING `~/`, `$VAR` or
    /// `%VAR%` expands; a placeholder naming nothing resolves nothing
    /// rather than a root-relative path.
    #[test]
    fn test_expand_composer_path() {
        let env = |name: &str| match name {
            "HOME" => Some(OsString::from("/home/u")),
            "DEPS" => Some(OsString::from("/srv/deps")),
            "EMPTY" => Some(OsString::new()),
            _ => None,
        };
        let x = |raw: &str| expand_composer_path(raw, &env).map(|v| v.into_string().unwrap());
        assert_eq!(x("~/shared").as_deref(), Some("/home/u/shared"));
        assert_eq!(x("~\\shared").as_deref(), Some("/home/u\\shared"));
        assert_eq!(x("$HOME/shared").as_deref(), Some("/home/u/shared"));
        assert_eq!(x("$DEPS/php").as_deref(), Some("/srv/deps/php"));
        assert_eq!(x("%DEPS%/php").as_deref(), Some("/srv/deps/php"));
        // Not placeholders: left as is.
        assert_eq!(x("lib/deps").as_deref(), Some("lib/deps"));
        assert_eq!(x("~user/x").as_deref(), Some("~user/x"));
        assert_eq!(x("lib/$DEPS").as_deref(), Some("lib/$DEPS"));
        assert_eq!(x("%DEPS/x").as_deref(), Some("%DEPS/x"));
        assert_eq!(x("$/x").as_deref(), Some("$/x"));
        // Placeholders naming nothing.
        assert_eq!(x("$UNSET/x"), None);
        assert_eq!(x("$EMPTY/x"), None);
        assert_eq!(expand_composer_path("~/x", &|_: &str| None), None);
    }

    /// The cascade: env, then the project's composer.json, then the
    /// user-level config.json, then `vendor`; only the scanned project's
    /// composer.json keeps the relative-subpath gate (#439, #686).
    #[test]
    fn test_resolve_vendor_dir_cascade() {
        let base = Path::new("/proj");
        let no_env = |name: &str| (name == "HOME").then(|| OsString::from("/home/u"));
        let lib = Some(r#"{"config":{"vendor-dir":"lib"}}"#);
        let abs = Some(r#"{"config":{"vendor-dir":"/abs/deps"}}"#);
        let home = Some(r#"{"config":{"vendor-dir":"~/deps"}}"#);
        let r = |manifest, trusted, user: Option<&str>| {
            resolve_vendor_dir(
                base,
                manifest,
                trusted,
                || user.map(str::to_string),
                &no_env,
            )
        };

        assert_eq!(r(None, false, None), Some(base.join("vendor")));
        assert_eq!(r(None, false, lib), Some(base.join("lib")));
        assert_eq!(
            r(home, false, lib),
            None,
            "untrusted ~/ is refused, not skipped"
        );
        assert_eq!(r(abs, false, lib), None, "untrusted absolute is refused");
        assert_eq!(r(abs, true, lib), Some(PathBuf::from("/abs/deps")));
        assert_eq!(r(home, true, None), Some(PathBuf::from("/home/u/deps")));
        assert_eq!(r(None, false, home), Some(PathBuf::from("/home/u/deps")));

        let env = |name: &str| (name == "COMPOSER_VENDOR_DIR").then(|| OsString::from("third/"));
        assert_eq!(
            resolve_vendor_dir(base, abs, false, || panic!("env decided"), &env),
            Some(base.join("third"))
        );
        // The user config is only read when nothing above decided.
        assert_eq!(
            resolve_vendor_dir(base, lib, false, || panic!("manifest decided"), &no_env),
            Some(base.join("lib"))
        );
    }

    /// A set `COMPOSER_HOME` is used exactly as Composer uses it, even when
    /// the directory is missing (no fallback to another home's config), and
    /// a relative value resolves against the project.
    #[test]
    fn test_local_composer_home_honours_set_env() {
        let cwd = Path::new("/proj");
        let env = |value: &'static str| {
            move |name: &str| (name == "COMPOSER_HOME").then(|| OsString::from(value))
        };
        assert_eq!(
            local_composer_home(cwd, &env("/missing/composer-home")),
            Some(PathBuf::from("/missing/composer-home"))
        );
        assert_eq!(local_composer_home(cwd, &env("ch")), Some(cwd.join("ch")));
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

    #[tokio::test]
    async fn test_resolve_install_path_rejects_absolute_escape_from_relative_root() {
        // The CLI defaults to `--cwd .`, so local discovery hands the
        // crawler a RELATIVE vendor path (`./vendor`) and
        // resolve_project_root normalizes the boundary to the EMPTY path.
        // Every path — absolute ones included — `starts_with` the empty
        // path, so the prefix check alone is vacuous there: a tampered
        // installed.json `install-path` naming an absolute directory must
        // still be refused (the resolved directory is a patch WRITE
        // target).
        let vendor = Path::new("./vendor");
        let root = resolve_project_root(vendor).await;

        let escape = std::env::temp_dir().join("socket-composer-escape-probe");
        assert_eq!(
            resolve_install_path(vendor, &root, escape.to_str().unwrap()),
            None,
            "absolute install-path must not escape a relative project root"
        );

        // Control: the conventional relative install-path still resolves
        // under the same relative boundary — the gate must not fail closed
        // on everything.
        assert_eq!(
            resolve_install_path(vendor, &root, "../monolog/monolog"),
            Some(PathBuf::from("vendor/monolog/monolog"))
        );
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

    #[tokio::test]
    async fn test_crawl_all_skips_name_without_namespace_separator() {
        // installed.json can carry a single-segment name ("nosplit"): it
        // passes the coordinate gate (is_safe_multi_segment accepts one
        // safe segment), so it reaches crawl_all's `split_once('/')` and
        // must be skipped there — composer packages are always
        // vendor/name, and a namespace-less PURL cannot be built.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path().join("vendor");

        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        tokio::fs::write(
            composer_dir.join("installed.json"),
            r#"{"packages": [
                {"name": "monolog/monolog", "version": "3.5.0"},
                {"name": "nosplit", "version": "1.0.0"}
            ]}"#,
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(vendor_dir.join("monolog").join("monolog"))
            .await
            .unwrap();
        // The slash-less entry HAS a directory on disk, so the skip below
        // is the missing '/' split — not the is_dir corroboration.
        tokio::fs::create_dir_all(vendor_dir.join("nosplit"))
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
            "slash-less entry must be skipped, got: {packages:?}"
        );
        assert_eq!(packages[0].name, "monolog");
    }

    #[test]
    fn test_resolve_install_path_rejects_embedded_nul() {
        // serde_json strings may legally contain `\u{0000}`, so a tampered
        // installed.json can deliver an install-path with an embedded NUL;
        // it must be refused up front, before any filesystem use.
        assert_eq!(
            resolve_install_path(
                Path::new("/proj/vendor"),
                Path::new("/proj"),
                "../mono\0log"
            ),
            None,
            "an install-path with an embedded NUL must be refused"
        );
        // Control: the conventional relative install-path still resolves —
        // the NUL gate must not fail closed on everything.
        assert_eq!(
            resolve_install_path(
                Path::new("/proj/vendor"),
                Path::new("/proj"),
                "../monolog/monolog"
            ),
            Some(PathBuf::from("/proj/vendor/monolog/monolog"))
        );
    }

    #[tokio::test]
    async fn test_read_installed_json_invalid_utf8_returns_empty() {
        // open_regular_file succeeds (regular file) but read_to_string
        // fails on invalid UTF-8 — the read-error early return, distinct
        // from the open-failure branch the chmod-000 e2e test covers.
        let dir = tempfile::tempdir().unwrap();
        let vendor_dir = dir.path();
        let composer_dir = vendor_dir.join("composer");
        tokio::fs::create_dir_all(&composer_dir).await.unwrap();
        // A UTF-16 BOM in front of otherwise-valid JSON listing a package:
        // if the failed read were ever papered over (e.g. a lossy decode),
        // the entry would surface and the assert below would catch it.
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend_from_slice(br#"{"packages":[{"name":"monolog/monolog","version":"3.5.0"}]}"#);
        tokio::fs::write(composer_dir.join("installed.json"), &bytes)
            .await
            .unwrap();

        assert!(
            read_installed_json(vendor_dir).await.is_empty(),
            "invalid UTF-8 installed.json must yield no entries"
        );
    }

    // ── Equivalence with the per-package async stats (oracle) ─────────

    mod equivalence {
        use super::super::oracle::LegacyComposerCrawler;
        use super::*;
        use crate::crawlers::oracle_support::{map_rows, mkdir, rows, symlink, write, Rng};

        const NAMES: &[&str] = &[
            "monolog/monolog",
            "Symfony/Console",
            "symfony/console",
            "a/b",
            "nons",
            "wp/plugin",
        ];
        const VERSIONS: &[&str] = &["3.5.0", "v6.4.1", "dev-main", "1.0.x-dev"];

        fn project(rng: &mut Rng, root: &Path) -> Vec<(String, String)> {
            let vendor = root.join("vendor");
            write(&root.join("composer.json"), "{}");
            let mut listed = Vec::new();
            let mut packages = Vec::new();
            for i in 0..rng.below(16) {
                let name = rng.pick(NAMES).to_string();
                let version = rng.pick(VERSIONS).to_string();
                let install_path = match rng.below(6) {
                    0 => None,
                    1 => Some(format!("../../web/plugins/p{i}")),
                    2 => Some("../../../outside".to_string()),
                    3 => Some(root.join(format!("abs{i}")).display().to_string()),
                    _ => Some(format!("../{}", name.to_lowercase())),
                };
                // Where the package would live on disk.
                let dir = match &install_path {
                    Some(p) => vendor.join("composer").join(p),
                    None => vendor.join(&name),
                };
                match rng.below(6) {
                    0 => {}
                    1 => write(&dir, "file"),
                    2 => symlink(&root.join(format!("missing{i}")), &dir),
                    _ => mkdir(&dir),
                }
                let mut entry = serde_json::json!({ "name": name, "version": version });
                if let Some(p) = &install_path {
                    entry["install-path"] = serde_json::json!(p);
                }
                listed.push(entry);
                packages.push((name, version));
            }
            let doc = if rng.chance(20) {
                serde_json::Value::Array(listed)
            } else {
                serde_json::json!({ "packages": listed })
            };
            write(
                &vendor.join("composer").join("installed.json"),
                &doc.to_string(),
            );
            packages
        }

        #[tokio::test]
        async fn randomized_vendor_trees_match_the_async_oracle() {
            let (mut crawled, mut found) = (0, 0);
            for seed in 0..64u64 {
                let mut rng = Rng::new(seed);
                let tmp = tempfile::tempdir().unwrap();
                let root = tmp.path().join("proj");
                let packages = project(&mut rng, &root);
                let options = CrawlerOptions {
                    cwd: root.clone(),
                    global: false,
                    global_prefix: None,
                };
                let new = ComposerCrawler::new().crawl_all(&options).await;
                let old = LegacyComposerCrawler::crawl_all(&options).await;
                assert_eq!(rows(&new), rows(&old), "seed {seed}: crawl_all");

                let mut purls: Vec<String> = old.iter().map(|p| p.purl.clone()).collect();
                for (name, version) in &packages {
                    purls.push(format!("pkg:composer/{name}@{version}"));
                    purls.push(format!(
                        "pkg:composer/{}@{}",
                        name.to_uppercase(),
                        normalize_version(version)
                    ));
                }
                let vendor = root.join("vendor");
                let new_found = ComposerCrawler::new()
                    .find_by_purls(&vendor, &purls)
                    .await
                    .unwrap();
                let old_found = LegacyComposerCrawler::find_by_purls(&vendor, &purls).await;
                assert_eq!(
                    map_rows(&new_found),
                    map_rows(&old_found),
                    "seed {seed}: find_by_purls"
                );
                crawled += old.len();
                found += old_found.len();
            }
            assert!(
                crawled > 50 && found > 50,
                "vacuous fixtures: {crawled}/{found}"
            );
        }

        /// The `composer global config home` memo re-runs only when the
        /// environment changed.
        #[test]
        fn env_keyed_memo_reuses_only_an_identical_environment() {
            use std::ffi::OsString;
            let env = |path: &str| -> EnvKey {
                (
                    vec![(OsString::from("PATH"), OsString::from(path))],
                    Some(PathBuf::from("/cwd")),
                )
            };
            let memo = EnvKeyedMemo::new();
            let mut runs = 0;
            let mut run = |answer: Option<&str>| {
                runs += 1;
                (answer.map(str::to_string), true)
            };
            assert_eq!(
                memo.get_or_run_keyed(env("/a"), || run(Some("home"))),
                Some("home".into())
            );
            assert_eq!(
                memo.get_or_run_keyed(env("/a"), || run(Some("x"))),
                Some("home".into())
            );
            // A different environment misses and replaces the entry.
            assert_eq!(
                memo.get_or_run_keyed(env("/b"), || run(Some("other"))),
                Some("other".into())
            );
            assert_eq!(
                memo.get_or_run_keyed(env("/b"), || run(Some("x"))),
                Some("other".into())
            );
            assert_eq!(
                memo.get_or_run_keyed(env("/a"), || run(Some("again"))),
                Some("again".into())
            );
            assert_eq!(runs, 3);
        }

        /// A failed probe is not kept: the asker gets its own `None` and
        /// the next caller asks again, as every caller did before the memo
        /// (global discovery runs the probe once for the crawl and once for
        /// the package-lookup pass). Neither is an answer the environment
        /// changed under.
        #[test]
        fn env_keyed_memo_asks_again_after_a_failed_probe() {
            use std::ffi::OsString;
            let key: EnvKey = (
                vec![(OsString::from("PATH"), OsString::from("/a"))],
                Some(PathBuf::from("/cwd")),
            );
            let memo = EnvKeyedMemo::new();
            let runs = std::cell::Cell::new(0);
            let run = |answer: Option<&str>, keepable: bool| {
                runs.set(runs.get() + 1);
                (answer.map(str::to_string), keepable)
            };

            // A failure, then an answer whose environment moved: both are
            // handed back, neither is kept.
            assert_eq!(memo.get_or_run_keyed(key.clone(), || run(None, true)), None);
            assert_eq!(
                memo.get_or_run_keyed(key.clone(), || run(Some("moved"), false)),
                Some("moved".into())
            );
            assert_eq!(runs.get(), 2);

            // The next caller still asks, and a complete answer is kept.
            assert_eq!(
                memo.get_or_run_keyed(key.clone(), || run(Some("home"), true)),
                Some("home".into())
            );
            assert_eq!(
                memo.get_or_run_keyed(key.clone(), || run(None, true)),
                Some("home".into())
            );
            assert_eq!(runs.get(), 3);
        }

        /// The memo key is order-insensitive: an environment restored to
        /// the same variables still hits, whatever order `vars_os` yields.
        #[test]
        fn env_key_is_sorted() {
            let key = super::super::env_key();
            let mut sorted = key.0.clone();
            sorted.sort();
            assert_eq!(key.0, sorted);
        }
    }
}
