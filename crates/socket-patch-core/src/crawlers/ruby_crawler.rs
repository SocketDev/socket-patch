use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::{entry_is_dir, home_dir, is_dir, list_dir_entries, normalize_lexically};
use crate::utils::process::{CommandRunner, SystemCommandRunner};

/// Ruby/RubyGems ecosystem crawler for discovering gems in Bundler vendor
/// directories or global gem installation paths.
pub struct RubyCrawler;

impl RubyCrawler {
    /// Create a new `RubyCrawler`.
    pub fn new() -> Self {
        Self
    }

    // ------------------------------------------------------------------
    // Public API
    // ------------------------------------------------------------------

    /// Get gem installation paths based on options.
    ///
    /// In local mode, probes the project's Bundler install roots in
    /// bundler's own precedence order — the app config file's
    /// `BUNDLE_PATH:` (`bundle config set --local path`), then the
    /// `BUNDLE_PATH` env var, then the default `vendor/bundle` — each in
    /// both the scoped `<root>/<engine>/<abi>/gems/` and flat
    /// `<root>/gems/` layouts. When the default `vendor/bundle` root holds
    /// a store (a deployment-style install), those stores are the whole
    /// answer; otherwise, if the cwd holds a Bundler manifest or lockfile,
    /// the gem homes `gem env` reports are appended (deduped) — default
    /// gems (rexml, json, …) never live in a bundle path, so an
    /// env/config-rooted project still needs them.
    ///
    /// In global mode, queries `gem env gemdir` and `gem env gempath`, plus
    /// well-known fallback paths for rbenv, rvm, Homebrew, and system Ruby.
    pub async fn get_gem_paths(
        &self,
        options: &CrawlerOptions,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        self.get_gem_paths_with_env(
            options,
            std::env::var_os("BUNDLE_PATH").as_deref(),
            std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
            ambient_home().as_deref(),
        )
        .await
    }

    /// [`Self::get_gem_paths`] with the ambient `BUNDLE_PATH` /
    /// `BUNDLE_APP_CONFIG` / home environment passed explicitly, so tests
    /// stay hermetic on machines where bundler is configured. (`gem env`
    /// still shells out; PATH-swapping tests keep covering that seam.)
    pub async fn get_gem_paths_with_env(
        &self,
        options: &CrawlerOptions,
        bundle_path_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        home_env: Option<&OsStr>,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return Ok(vec![custom.clone()]);
            }
            return Ok(Self::get_global_gem_paths().await);
        }

        // Local mode: probe the Bundler install roots first.
        let discovery = Self::discover_bundle_stores_with_env(
            &options.cwd,
            bundle_path_env,
            app_config_env,
            home_env,
        )
        .await;

        // Historic early-return, kept ONLY for the implicit project-local
        // `vendor/bundle` probe: a deployment-style install is the
        // project's one gem source, so the ambient gem homes don't apply.
        // Stores found via an env/config root do NOT suppress the fallback
        // below: default gems (rexml, json, …) never live in a bundle path
        // — they ship with ruby in the DEFAULT/system gem homes — so an
        // env-`BUNDLE_PATH` project still needs the `gem env` homes to see
        // them (the explicit-roots feature briefly suppressed that
        // pre-existing fallback).
        if discovery.default_root_has_stores {
            return Ok(discovery.stores);
        }

        let mut paths = discovery.stores;

        // Only consult the installed gem homes if this looks like a Ruby
        // project. A non-deployment `bundle install` puts the project's gems
        // in the ambient gem homes, so every home `gem env` reports counts —
        // not just `gemdir`: bundler resolves from all of `Gem.path`, and a
        // gem the project loads routinely lives in a non-`gemdir` home (rvm
        // keeps shared gems in the `@global` gemset; `--user-install` puts
        // them under `~/.gem`/`$XDG_DATA_HOME`).
        if Self::has_bundler_manifest(&options.cwd).await {
            let mut seen: HashSet<PathBuf> = paths.iter().cloned().collect();
            for gems_dir in Self::gem_env_gems_dirs().await {
                if seen.insert(gems_dir.clone()) {
                    paths.push(gems_dir);
                }
            }
        }

        Ok(paths)
    }

    /// Crawl all discovered gem paths and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let gem_paths = self.get_gem_paths(options).await.unwrap_or_default();

        for gem_path in &gem_paths {
            let found = self.scan_gem_dir(gem_path, &mut seen).await;
            packages.extend(found);
        }

        packages
    }

    /// Find specific packages by PURL inside a single gem directory.
    ///
    /// Gem directories follow the `<name>-<version>` pattern.
    pub async fn find_by_purls(
        &self,
        gem_path: &Path,
        purls: &[String],
    ) -> Result<HashMap<String, CrawledPackage>, std::io::Error> {
        let mut result: HashMap<String, CrawledPackage> = HashMap::new();

        for purl in purls {
            if let Some((name, version)) = crate::utils::purl::parse_gem_purl(purl) {
                // SECURITY: name/version come straight from the (untrusted)
                // manifest PURL and are formatted into a `<name>-<version>`
                // dir name joined onto `gem_path` below. A real gem
                // coordinate is a single path segment, so reject any that
                // could traverse out of the gem root (`..`/`.`, a separator,
                // an absolute path, NUL). `verify_gem_at_path` only checks
                // for `lib/`/`.gemspec` and gems patch in place, so fail
                // closed here — same as the deno/go/maven/npm/nuget guards.
                if !is_safe_gem_coordinate(name, version) {
                    continue;
                }
                // The purl is the base PURL (qualifiers stripped upstream).
                // Resolve it to the installed gem dir, which may carry a
                // `-<platform>` suffix for platform gems.
                if let Some(gem_dir) = self.locate_gem_dir(gem_path, name, version).await {
                    result.insert(
                        purl.clone(),
                        CrawledPackage {
                            name: name.to_string(),
                            version: version.to_string(),
                            namespace: None,
                            purl: purl.clone(),
                            path: gem_dir,
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

    /// Whether `cwd` holds a Bundler manifest or lockfile.
    ///
    /// Bundler accepts two spellings of the pair — the usual
    /// `Gemfile`/`Gemfile.lock` and the alternate `gems.rb`/`gems.locked`
    /// (`Bundler::SharedHelpers.default_gemfile`). Both count: the project
    /// gate must recognize every project `setup` can wire, and
    /// `setup::gem::discover_bundler_project` already walks up for `gems.rb`.
    /// Gating on `Gemfile` alone left a `gems.rb` project with a
    /// non-deployment `bundle install` undiscoverable — the bundler plugin
    /// `setup` installs would run `apply` on every `bundle install` and
    /// silently find zero gems.
    async fn has_bundler_manifest(cwd: &Path) -> bool {
        for name in ["Gemfile", "Gemfile.lock", "gems.rb", "gems.locked"] {
            if tokio::fs::metadata(cwd.join(name)).await.is_ok() {
                return true;
            }
        }
        false
    }

    /// The gem homes `gem env` itself reports, each mapped to its `gems/`
    /// subdirectory: `gemdir` (the active `GEM_HOME`) first, then every
    /// `gempath` (`GEM_PATH`) entry. Non-existent homes and duplicates are
    /// dropped, so the result is the deduped set of installed-gem roots in
    /// RubyGems' own precedence order.
    async fn gem_env_gems_dirs() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = HashSet::new();

        if let Some(gemdir) = Self::run_gem_env("gemdir").await {
            let gems_path = PathBuf::from(gemdir).join("gems");
            if is_dir(&gems_path).await && seen.insert(gems_path.clone()) {
                paths.push(gems_path);
            }
        }

        // `gem env gempath` lists several gem homes separated by the OS path
        // separator (`:` on Unix, `;` on Windows). Splitting on a hardcoded
        // `:` shreds Windows drive-letter paths (`C:\Ruby\...;D:\...`) into
        // `["C", "\Ruby\...;D", "\..."]`, so defer to `split_paths`, which
        // honors the platform separator — same as the Go crawler's GOPATH.
        if let Some(gempath) = Self::run_gem_env("gempath").await {
            for gems_path in gem_homes_to_gems_dirs(&gempath) {
                if is_dir(&gems_path).await && seen.insert(gems_path.clone()) {
                    paths.push(gems_path);
                }
            }
        }

        paths
    }

    /// Find installed-gem `gems/` directories under the project's Bundler
    /// install roots.
    ///
    /// Reads the ambient `BUNDLE_PATH`/`BUNDLE_APP_CONFIG`/home
    /// environment; the `_with_env` variant takes them as parameters so
    /// tests stay hermetic. Production flows go through
    /// [`Self::get_gem_paths`] → [`Self::discover_bundle_stores_with_env`];
    /// these two are the unit-test seam pinning the store list shape.
    #[cfg(test)]
    async fn get_vendor_bundle_paths(cwd: &Path) -> Vec<PathBuf> {
        Self::discover_bundle_stores(cwd).await.stores
    }

    /// [`Self::discover_bundle_stores_with_env`], flattened to just the
    /// store list (the historical shape most tests pin).
    #[cfg(test)]
    async fn get_vendor_bundle_paths_with_env(
        cwd: &Path,
        bundle_path_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
    ) -> Vec<PathBuf> {
        Self::discover_bundle_stores_with_env(cwd, bundle_path_env, app_config_env, None)
            .await
            .stores
    }

    /// The bundler install roots, probed in bundler's own precedence order
    /// (local config beats env beats default — `Bundler::Settings`):
    ///
    /// 1. the `BUNDLE_PATH:` entry of the app config file
    ///    (`$BUNDLE_APP_CONFIG/config`, else `<cwd>/.bundle/config`) — what
    ///    `bundle config set --local path <dir>` records. SECURITY: this
    ///    file is typically committed, i.e. attacker-authored input, and
    ///    the root becomes a scan/apply WRITE target — so a value that
    ///    resolves outside the project root is skipped with a warning (see
    ///    [`resolve_config_bundle_path`]). `BUNDLE_PATH__SYSTEM: "true"`
    ///    makes bundler ignore the recorded path, so it is dropped too
    ///    (see [`parse_bundle_config_path`]).
    /// 2. `$BUNDLE_PATH` — bundler's explicit install root (a relative
    ///    value resolves against the project root, matching
    ///    `Bundler.bundle_path`; a leading `~` expands against home).
    ///    Trusted as-is: it is the user's own environment.
    /// 3. `<cwd>/vendor/bundle` — the default deployment/`--path` location.
    ///
    /// The explicit roots can point anywhere (a machine-wide `BUNDLE_PATH`
    /// export must not pull another project's gem store into a non-Ruby
    /// scan), so they only count when `cwd` holds a Bundler manifest — the
    /// same "looks like a Ruby project" gate the `gem env` fallback uses in
    /// [`Self::get_gem_paths`]. The implicit `vendor/bundle` probe stays
    /// ungated, as it always was.
    ///
    /// Each root is probed in BOTH layouts bundler produces (see
    /// [`Self::bundle_root_gems_dirs`]), and roots plus discovered `gems/`
    /// dirs are lexically normalized and deduped so a root reachable two
    /// ways (e.g. `BUNDLE_PATH` naming `vendor/bundle`, or spelling it
    /// `vendor/x/../bundle`) is not scanned — or patched — twice.
    async fn discover_bundle_stores_with_env(
        cwd: &Path,
        bundle_path_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        home_env: Option<&OsStr>,
    ) -> BundleStoreDiscovery {
        let home = home_env.map(Path::new);
        let default_root = cwd.join("vendor").join("bundle");
        let default_root = normalize_lexically(&default_root).unwrap_or(default_root);

        let mut roots: Vec<PathBuf> = Vec::new();
        let mut skipped_config_path = None;
        if Self::has_bundler_manifest(cwd).await {
            if let Some(value) = Self::app_config_bundle_path(cwd, app_config_env).await {
                match resolve_config_bundle_path(cwd, &value, home) {
                    Some(root) => roots.push(root),
                    // Refused by the containment guard. Recorded — not
                    // printed: the crawler has no --silent/--json context,
                    // so the CLI surfaces it (see
                    // [`config_path_ignored_warning`]).
                    None => skipped_config_path = Some(value),
                }
            }
            if let Some(v) = bundle_path_env.filter(|v| !v.is_empty()) {
                roots.push(resolve_bundle_path(cwd, Path::new(v), home));
            }
        }
        roots.push(default_root.clone());

        let mut stores = Vec::new();
        let mut default_root_has_stores = false;
        let mut seen_roots = HashSet::new();
        let mut seen = HashSet::new();
        for root in roots {
            if !seen_roots.insert(root.clone()) {
                continue;
            }
            let is_default = root == default_root;
            for gems_dir in Self::bundle_root_gems_dirs(&root).await {
                if is_default {
                    default_root_has_stores = true;
                }
                if seen.insert(gems_dir.clone()) {
                    stores.push(gems_dir);
                }
            }
        }
        BundleStoreDiscovery {
            stores,
            default_root_has_stores,
            skipped_config_path,
        }
    }

    /// Local-mode Bundler install-root discovery against the AMBIENT
    /// environment — the same probe [`Self::get_gem_paths`] runs, exposed
    /// for CLI consumers that need what the flat path list drops: the
    /// store/fallback CLASS boundary (`stores`) and the config-skip
    /// advisory (`skipped_config_path`). Cheap: filesystem probes only,
    /// no `gem env` shell-out.
    pub async fn discover_bundle_stores(cwd: &Path) -> BundleStoreDiscovery {
        Self::discover_bundle_stores_with_env(
            cwd,
            std::env::var_os("BUNDLE_PATH").as_deref(),
            std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
            ambient_home().as_deref(),
        )
        .await
    }

    /// The installed-gem `gems/` dirs under one bundler install root, in
    /// both layouts bundler produces:
    ///
    /// - **scoped** `<root>/<engine>/<version>/gems` — `Bundler.ruby_scope`
    ///   (`#{Gem.ruby_engine}/#{ruby_version}`), written by `--path`/
    ///   local-config installs on every bundler and by env-`BUNDLE_PATH`
    ///   installs on bundler >= 2. The engine is `ruby` under MRI but
    ///   `jruby`/`truffleruby` under the alternative engines (hardcoding
    ///   `ruby` made those deployments discover zero gems), so enumerate
    ///   every engine dir that holds `<version>/gems/` children; non-engine
    ///   clutter is filtered by that shape.
    /// - **flat** `<root>/gems` — plain GEM_HOME semantics, which is what
    ///   bundler 1 writes when `BUNDLE_PATH` comes from the environment (it
    ///   skips the `ruby_scope` segment entirely). Guarded on the sibling
    ///   `specifications/` dir every real gem home carries, so a random
    ///   `gems/` directory is not mistaken for a gem store.
    ///
    /// A flat root's `gems/` entry is its package store, never an engine
    /// dir, so the scoped walk skips it — a gem that itself ships a `gems/`
    /// subdirectory must not surface a ghost `<engine>/<version>/gems` root.
    async fn bundle_root_gems_dirs(root: &Path) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        let flat_gems = root.join("gems");
        let is_flat_gem_home =
            is_dir(&flat_gems).await && is_dir(&root.join("specifications")).await;

        for engine_entry in list_dir_entries(root).await {
            if !entry_is_dir(&engine_entry).await {
                continue;
            }
            if is_flat_gem_home && engine_entry.file_name() == "gems" {
                continue;
            }
            let engine_dir = root.join(engine_entry.file_name());
            for entry in list_dir_entries(&engine_dir).await {
                if !entry_is_dir(&entry).await {
                    continue;
                }
                let gems_dir = engine_dir.join(entry.file_name()).join("gems");
                if is_dir(&gems_dir).await {
                    paths.push(gems_dir);
                }
            }
        }

        if is_flat_gem_home {
            paths.push(flat_gems);
        }
        paths
    }

    /// The `BUNDLE_PATH` recorded in bundler's app config file — the value
    /// `bundle config set --local path <dir>` writes. The file lives at
    /// `$BUNDLE_APP_CONFIG/config`, else `<cwd>/.bundle/config`, resolved by
    /// the shared [`crate::setup::gem::bundler_app_config_dir`] rule.
    async fn app_config_bundle_path(cwd: &Path, app_config_env: Option<&OsStr>) -> Option<String> {
        use tokio::io::AsyncReadExt;

        let config = crate::setup::gem::bundler_app_config_dir(cwd, app_config_env).join("config");
        // The config lives inside the (untrusted) project tree: a planted
        // FIFO would make a plain `read_to_string` open block forever
        // waiting for a writer, wedging scan (crawl_all) and apply/get
        // (find_by_purls path discovery). Open via `open_regular_file` —
        // non-blocking on Unix, rejecting FIFOs/devices/directories (see
        // its docs) — same as the npm/composer/python crawlers.
        let (mut file, metadata) = crate::utils::fs::open_regular_file(&config).await.ok()?;
        let mut contents = String::with_capacity(metadata.len() as usize);
        file.read_to_string(&mut contents).await.ok()?;
        parse_bundle_config_path(&contents)
    }

    /// Get global gem paths by querying `gem env` and checking well-known locations.
    async fn get_global_gem_paths() -> Vec<PathBuf> {
        // gem env gemdir + gem env gempath
        let mut paths = Self::gem_env_gems_dirs().await;
        let mut seen: HashSet<PathBuf> = paths.iter().cloned().collect();

        // Fallback well-known paths
        let home = home_dir();

        let fallback_globs = [
            home.join(".gem").join("ruby"),
            home.join(".rbenv").join("versions"),
            home.join(".rvm").join("gems"),
        ];

        for base in &fallback_globs {
            for entry in list_dir_entries(base).await {
                if !entry_is_dir(&entry).await {
                    continue;
                }

                let entry_path = base.join(entry.file_name());

                // ~/.gem/ruby/*/gems/
                let gems_dir = entry_path.join("gems");
                if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                    paths.push(gems_dir);
                    continue;
                }

                // ~/.rbenv/versions/*/lib/ruby/gems/*/gems/
                let lib_ruby_gems = entry_path.join("lib").join("ruby").join("gems");
                for sub_entry in list_dir_entries(&lib_ruby_gems).await {
                    let gems_dir = lib_ruby_gems.join(sub_entry.file_name()).join("gems");
                    if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                        paths.push(gems_dir);
                    }
                }
            }
        }

        // System paths
        let system_bases = [
            PathBuf::from("/usr/lib/ruby/gems"),
            PathBuf::from("/usr/local/lib/ruby/gems"),
            PathBuf::from("/opt/homebrew/lib/ruby/gems"),
        ];

        for base in &system_bases {
            for entry in list_dir_entries(base).await {
                let gems_dir = base.join(entry.file_name()).join("gems");
                if is_dir(&gems_dir).await && seen.insert(gems_dir.clone()) {
                    paths.push(gems_dir);
                }
            }
        }

        paths
    }

    /// Run `gem env <key>` and return the trimmed stdout.
    async fn run_gem_env(key: &str) -> Option<String> {
        let stdout = SystemCommandRunner.run("gem", &["env", key]);
        parse_gem_env_output(stdout.as_deref().unwrap_or(""))
    }

    /// Scan a gem directory and return all valid gem packages found.
    async fn scan_gem_dir(
        &self,
        gem_path: &Path,
        seen: &mut HashSet<String>,
    ) -> Vec<CrawledPackage> {
        let mut results = Vec::new();

        for entry in list_dir_entries(gem_path).await {
            if !entry_is_dir(&entry).await {
                continue;
            }

            let dir_name = entry.file_name();
            let dir_name_str = dir_name.to_string_lossy();

            // Skip hidden directories
            if dir_name_str.starts_with('.') {
                continue;
            }

            let gem_dir = gem_path.join(&*dir_name_str);

            // Parse name-version from directory name
            if let Some((name, version)) = Self::parse_dir_name_version(&dir_name_str) {
                // Verify it looks like a gem (has .gemspec or lib/)
                if !self.verify_gem_at_path(&gem_dir).await {
                    continue;
                }

                let purl = crate::utils::purl::build_gem_purl(&name, &version);

                if !seen.insert(purl.clone()) {
                    continue;
                }

                results.push(CrawledPackage {
                    name,
                    version,
                    namespace: None,
                    purl,
                    path: gem_dir,
                });
            }
        }

        results
    }

    /// Verify that a directory looks like an installed gem.
    /// Checks for a `.gemspec` file or a `lib/` directory.
    async fn verify_gem_at_path(&self, path: &Path) -> bool {
        if !is_dir(path).await {
            return false;
        }

        // Check for lib/ directory
        if is_dir(&path.join("lib")).await {
            return true;
        }

        // Check for any .gemspec file
        for entry in list_dir_entries(path).await {
            if let Some(name) = entry.file_name().to_str() {
                if name.ends_with(".gemspec") {
                    return true;
                }
            }
        }

        false
    }

    /// Parse a gem directory name into its base `(name, version)`.
    ///
    /// Gem directories follow `<name>-<version>` (ruby-platform gems) or
    /// `<name>-<version>-<platform>` (platform gems, e.g.
    /// `nokogiri-1.16.5-x86_64-linux`). A RubyGems version is dash-free
    /// (prerelease dashes render as `.pre.`), so every `-` followed by a
    /// digit is a candidate name/version boundary and the version is the
    /// dash-free token after it; anything past that is the platform
    /// suffix, which we drop — the installed platform is resolved later by
    /// hashing the gem's files (the same model as PyPI's `artifact_id`).
    /// The qualified `?platform=` PURL is only ever carried in the
    /// manifest/API.
    ///
    /// Names may themselves contain `-<digit>` runs (`http-2`,
    /// `http-2-next`), so the first candidate boundary is not always
    /// right: `http-2-1.0.1` must parse as `("http-2", "1.0.1")`, not the
    /// ghost `("http", "2")`. Real versions are almost always dotted while
    /// digit runs embedded in names (`-2-`) and trailing platform OS
    /// revisions (`-darwin-21`) are not, so prefer the LAST boundary whose
    /// version token contains a `.`; fall back to the first dash-digit
    /// boundary only when no dotted candidate exists (a bare
    /// single-segment version like `g-1` is legal but vanishingly rare).
    fn parse_dir_name_version(dir_name: &str) -> Option<(String, String)> {
        let candidates: Vec<usize> = dir_name
            .match_indices('-')
            .filter(|(i, _)| dir_name[i + 1..].starts_with(|c: char| c.is_ascii_digit()))
            .map(|(i, _)| i)
            .collect();
        // Version is the leading dash-free token; drop any `-<platform>`.
        let version_token = |i: usize| {
            let rest = &dir_name[i + 1..];
            rest.split('-').next().unwrap_or(rest)
        };
        let idx = *candidates
            .iter()
            .rfind(|&&i| version_token(i).contains('.'))
            .or_else(|| candidates.first())?;
        let name = &dir_name[..idx];
        let version = version_token(idx);
        if name.is_empty() || version.is_empty() {
            return None;
        }
        Some((name.to_string(), version.to_string()))
    }

    /// Locate an installed gem directory for a base `name`/`version`.
    ///
    /// Plain (ruby-platform) gems live in `<name>-<version>/`; platform
    /// gems append a `-<platform>` suffix
    /// (`<name>-<version>-x86_64-linux/`). Only one platform is installed
    /// per environment, so we return the exact dir when present, otherwise
    /// the first verifying `<name>-<version>-*` directory.
    async fn locate_gem_dir(&self, gem_path: &Path, name: &str, version: &str) -> Option<PathBuf> {
        let exact = gem_path.join(format!("{name}-{version}"));
        if self.verify_gem_at_path(&exact).await {
            return Some(exact);
        }
        let prefix = format!("{name}-{version}-");
        for entry in list_dir_entries(gem_path).await {
            let file_name = entry.file_name();
            let dir_name = file_name.to_string_lossy();
            if dir_name.starts_with(&prefix) {
                let dir = gem_path.join(&*dir_name);
                if self.verify_gem_at_path(&dir).await {
                    return Some(dir);
                }
            }
        }
        None
    }
}

impl Default for RubyCrawler {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of probing the Bundler install roots.
///
/// Public so CLI consumers (apply's store-class split, scan/apply's
/// config-skip advisory) can see what local-mode discovery decided; the
/// crawler itself stays print-free — surfacing the skip on stderr / the
/// JSON envelope is the CLI's job, where `--silent`/`--json` gating lives.
pub struct BundleStoreDiscovery {
    /// The discovered installed-gem `gems/` stores, in root-precedence
    /// order (local config > env > default `vendor/bundle`). Copies found
    /// under these are the PRIMARY class in apply's multi-copy fan-out;
    /// paths outside them are `gem env` fallback-home copies.
    pub stores: Vec<PathBuf>,
    /// Whether any store sits under the implicit project-local
    /// `vendor/bundle` root — which keeps its historic
    /// [`RubyCrawler::get_gem_paths`] early-return (a deployment install
    /// suppresses the `gem env` fallback; env/config roots must not).
    pub default_root_has_stores: bool,
    /// A config-sourced `BUNDLE_PATH` value the containment guard REFUSED
    /// (it resolved outside the project root — see
    /// [`resolve_config_bundle_path`]). Recorded, never printed: callers
    /// surface it via [`config_path_ignored_warning`] on their own
    /// warning channel.
    pub skipped_config_path: Option<String>,
}

/// The stable warning `(code, detail)` for a config-sourced `BUNDLE_PATH`
/// refused by the containment guard. One builder so scan's run-level
/// `warnings[]`, apply's envelope `warnings[]`, and the gated stderr lines
/// all carry byte-identical text.
pub fn config_path_ignored_warning(value: &str) -> (&'static str, String) {
    (
        "gem_bundle_config_path_ignored",
        // Display inside manual quotes, NOT `{value:?}`: Debug escaping
        // doubles backslashes, so on Windows the detail printed
        // `C:\\Users\\…` for a config that says `C:\Users\…` — breaking
        // both the substring assertions and any human copy-pasting the
        // path. The value is already a single scraped line, so Display
        // cannot smuggle in newlines the quotes would mask.
        format!(
            "bundler app config BUNDLE_PATH \"{value}\" resolves outside the project \
             root; ignoring it as an install root (a committed .bundle/config is \
             untrusted input — set BUNDLE_PATH in the environment to use an \
             out-of-tree bundle path)"
        ),
    )
}

/// The ambient home directory as an env value (`HOME`, else Windows'
/// `USERPROFILE`), `None` when unset or empty — the `~`-expansion base for
/// ambient runs; tests inject theirs through the `_with_env` seams.
fn ambient_home() -> Option<std::ffi::OsString> {
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()))
}

/// Pure parser for `gem env <key>` stdout. Returns the trimmed path
/// string or `None` on empty input. Extracted so the helper logic is
/// unit-testable without shelling out to the gem CLI.
pub fn parse_gem_env_output(stdout: &str) -> Option<String> {
    let s = stdout.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Split a `gem env gempath` value into the `<home>/gems` directories it
/// names. Each entry is one gem home; the installed gems live under its
/// `gems/` subdirectory. Splitting uses [`std::env::split_paths`] so the
/// OS path separator (`:` on Unix, `;` on Windows) is honored — a hardcoded
/// `:` would mangle Windows drive-letter paths. Empty segments are dropped.
fn gem_homes_to_gems_dirs(gempath: &str) -> Vec<PathBuf> {
    std::env::split_paths(gempath)
        .filter(|segment| !segment.as_os_str().is_empty())
        .map(|segment| segment.join("gems"))
        .collect()
}

/// Expand a leading `~` component against the home directory, as bundler's
/// `File.expand_path` does for `BUNDLE_PATH` values. Only the bare-`~`
/// form (`~`, `~/store`) expands; `~user` needs the passwd lookup bundler
/// itself would do and is left untouched (it then resolves like a relative
/// path, the crawler's previous behavior for every `~` form). With no home
/// available the value is likewise left untouched.
fn expand_tilde(value: &Path, home: Option<&Path>) -> PathBuf {
    let mut components = value.components();
    if let (Some(std::path::Component::Normal(first)), Some(home)) = (components.next(), home) {
        if first == OsStr::new("~") {
            return home.join(components.as_path());
        }
    }
    value.to_path_buf()
}

/// Resolve a trusted (ENV-sourced) `BUNDLE_PATH` value against the project
/// root. Bundler `File.expand_path`s the value: a leading `~` expands to
/// the user's home, and a relative path resolves against the directory of
/// the Gemfile (`Bundler.root`), not the process cwd — the same rule
/// [`crate::setup::gem::bundler_app_config_dir`] follows for
/// `BUNDLE_APP_CONFIG`. `.`/`..` segments are folded lexically so the same
/// physical root spelled two ways dedups to one probe; a value that pops
/// above its own root keeps its unnormalized spelling (it is only ever
/// probed, and the env value is the user's own machine state — no
/// containment applies, unlike [`resolve_config_bundle_path`]).
fn resolve_bundle_path(root: &Path, value: &Path, home: Option<&Path>) -> PathBuf {
    let expanded = expand_tilde(value, home);
    let resolved = if expanded.is_absolute() {
        expanded
    } else {
        root.join(expanded)
    };
    normalize_lexically(&resolved).unwrap_or(resolved)
}

/// Resolve a CONFIG-sourced `BUNDLE_PATH` value (bundler's app config file
/// — typically a committed `.bundle/config`) into an install root, or
/// `None` when the containment policy refuses it.
///
/// SECURITY: unlike the environment variable (the user's own machine
/// state), a repo-committed `.bundle/config` is attacker-authored input —
/// and the resolved root becomes a scan target and, via `apply`, a WRITE
/// target. An absolute value (`/usr/local/…`) or a `..` traversal
/// (`../sibling-checkout`) must not let a malicious clone direct patch
/// writes outside the project. Policy: after `~` expansion and lexical
/// `.`/`..` normalization, the root must stay contained in the project
/// root — the same containment posture as the composer crawler's
/// `install-path` guard and the gem plugin-index cleanup in
/// `setup/gem/mod.rs`. Out-of-tree bundle paths stay reachable via the
/// trusted env `BUNDLE_PATH`.
fn resolve_config_bundle_path(
    project_root: &Path,
    value: &str,
    home: Option<&Path>,
) -> Option<PathBuf> {
    let expanded = expand_tilde(Path::new(value), home);
    // Anything rooted takes the strict prefix check — not just
    // `is_absolute()`: on Windows a root-relative `\evil` or drive-relative
    // `C:evil` is NOT "absolute" yet `Path::join` substitutes it for (part
    // of) the base, so routing it through the relative branch would escape
    // containment.
    let rooted = expanded.has_root()
        || matches!(
            expanded.components().next(),
            Some(std::path::Component::Prefix(_))
        );
    if rooted {
        // Contained iff it normalizes to somewhere under the project root.
        // The comparison base must be absolute too: the CLI's default
        // `--cwd .` is relative, and `starts_with` against a relative (or
        // empty) base would trivially pass. `std::path::absolute` is
        // lexical (no symlink resolution), matching the normalization here;
        // if it cannot produce a base, fail closed.
        let normalized = normalize_lexically(&expanded)?;
        let base = std::path::absolute(project_root).ok()?;
        let base = normalize_lexically(&base)?;
        (!base.as_os_str().is_empty() && normalized.starts_with(&base)).then_some(normalized)
    } else {
        // A relative value is contained by construction unless its `..`
        // segments climb out of the project root — `normalize_lexically`
        // fails closed on exactly that.
        let contained = normalize_lexically(&expanded)?;
        let joined = project_root.join(contained);
        Some(normalize_lexically(&joined).unwrap_or(joined))
    }
}

/// Extract the effective `BUNDLE_PATH:` value from bundler's app config
/// file contents. The file is flat YAML bundler writes itself
/// (`---\nBUNDLE_PATH: "vendor/bundle"\n`), so a line-based scrape is enough
/// — matching the repo convention of line-parsing Cargo.toml rather than
/// pulling in a format crate. Quoted values (bundler double-quotes what it
/// writes) are unwrapped; an empty value counts as unset. Sibling keys like
/// `BUNDLE_PATH__SYSTEM:` must not match the path key — the prefix requires
/// the colon immediately after `BUNDLE_PATH`.
///
/// `BUNDLE_PATH__SYSTEM: "true"` (bundler's `path.system` setting) makes
/// bundler IGNORE any recorded path and use the system/default gem home, so
/// the whole config entry parses as unset — the caller then falls through
/// to the `gem env` homes, which is exactly where those gems live. Bundler
/// converts only the exact string `true` to a truthy setting; anything else
/// leaves the recorded path in effect.
fn parse_bundle_config_path(contents: &str) -> Option<String> {
    let mut path: Option<String> = None;
    let mut path_system = false;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("BUNDLE_PATH:") {
            let v = unquote_bundle_config_value(rest);
            if !v.is_empty() {
                path = Some(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("BUNDLE_PATH__SYSTEM:") {
            path_system = unquote_bundle_config_value(rest) == "true";
        }
    }
    if path_system {
        None
    } else {
        path
    }
}

/// Unwrap one bundler app-config scalar: trim, then strip one matching
/// pair of double or single quotes (bundler double-quotes what it writes).
fn unquote_bundle_config_value(rest: &str) -> &str {
    let v = rest.trim();
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .unwrap_or(v)
}

/// Whether a PURL-derived gem coordinate is safe to join onto the gem root.
/// SECURITY: `find_by_purls` formats name/version into a `<name>-<version>`
/// directory name joined onto `gem_path`, and a real gem name/version is
/// dash/dot/word characters only — never a separator, colon, NUL, or bare
/// dot segment. `verify_gem_at_path` only checks for `lib/`/`.gemspec` and
/// gems are patched in place, so a tampered manifest PURL (`pkg:gem/../x@1.0`,
/// an absolute name, a `/`-bearing version) must be rejected here, fail
/// closed. Delegates to [`path_safety::is_safe_single_segment`], which also
/// rejects `:` — a Windows drive-relative coordinate (`C:evil`) joins as an
/// absolute path. Mirrors the deno/go/maven/npm/nuget crawler coordinate
/// guards.
fn is_safe_gem_coordinate(name: &str, version: &str) -> bool {
    path_safety::is_safe_single_segment(name) && path_safety::is_safe_single_segment(version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gem_dir_name() {
        assert_eq!(
            RubyCrawler::parse_dir_name_version("rails-7.1.0"),
            Some(("rails".to_string(), "7.1.0".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("activerecord-7.1.3.2"),
            Some(("activerecord".to_string(), "7.1.3.2".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("net-http-0.4.1"),
            Some(("net-http".to_string(), "0.4.1".to_string()))
        );
        assert!(RubyCrawler::parse_dir_name_version("no-version-here").is_none());
        assert!(RubyCrawler::parse_dir_name_version("noversion").is_none());
    }

    #[test]
    fn test_parse_gem_dir_name_platform_gems() {
        // Platform gems append `-<platform>` to the base name-version; the
        // platform must be stripped so the base PURL matches the manifest.
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5-x86_64-linux"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5-arm64-darwin"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("sassc-2.4.0-java"),
            Some(("sassc".to_string(), "2.4.0".to_string()))
        );
        // Platform with a trailing OS version number must not leak into
        // the gem version (regression: a "last dash-digit" parser would
        // split on `-21`).
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.5-universal-darwin-21"),
            Some(("nokogiri".to_string(), "1.16.5".to_string()))
        );
        // A name with an embedded version-like number resolves at the
        // first dash-digit boundary.
        assert_eq!(
            RubyCrawler::parse_dir_name_version("libv8-node-18.16.0.0-x86_64-linux"),
            Some(("libv8-node".to_string(), "18.16.0.0".to_string()))
        );
    }

    #[tokio::test]
    async fn test_find_by_purls_gem() {
        let dir = tempfile::tempdir().unwrap();
        let rails_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(rails_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec![
            "pkg:gem/rails@7.1.0".to_string(),
            "pkg:gem/nokogiri@1.16.5".to_string(),
        ];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key("pkg:gem/rails@7.1.0"));
        assert!(!result.contains_key("pkg:gem/nokogiri@1.16.5"));
    }

    #[tokio::test]
    async fn test_crawl_all_gems() {
        let dir = tempfile::tempdir().unwrap();

        // Create fake gem directories with lib/
        let rails_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(rails_dir.join("lib"))
            .await
            .unwrap();

        let nokogiri_dir = dir.path().join("nokogiri-1.16.5");
        tokio::fs::create_dir_all(nokogiri_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 2);

        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert!(purls.contains("pkg:gem/rails@7.1.0"));
        assert!(purls.contains("pkg:gem/nokogiri@1.16.5"));
    }

    #[tokio::test]
    async fn test_get_gem_paths_with_vendor_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let vendor_gems = dir
            .path()
            .join("vendor")
            .join("bundle")
            .join("ruby")
            .join("3.2.0")
            .join("gems");
        tokio::fs::create_dir_all(&vendor_gems).await.unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths(dir.path()).await;
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vendor_gems);
    }

    /// Bundler's deployment scope is `<engine>/<version>` — `jruby` and
    /// `truffleruby` deployments live beside `ruby` under `vendor/bundle`
    /// and must be discovered too (hardcoding `ruby` found zero gems
    /// there). Non-engine clutter — files, and dirs whose children hold no
    /// `gems/` — must not produce paths.
    #[tokio::test]
    async fn test_get_vendor_bundle_paths_alternative_engines() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("vendor").join("bundle");
        let ruby_gems = bundle.join("ruby").join("3.2.0").join("gems");
        let jruby_gems = bundle.join("jruby").join("3.1.4.0").join("gems");
        let truffle_gems = bundle.join("truffleruby").join("3.2.2").join("gems");
        for gems in [&ruby_gems, &jruby_gems, &truffle_gems] {
            tokio::fs::create_dir_all(gems).await.unwrap();
        }
        tokio::fs::write(bundle.join("install.log"), b"x")
            .await
            .unwrap();
        tokio::fs::create_dir_all(bundle.join("cache").join("3.2.0"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths(dir.path()).await;
        assert_eq!(paths.len(), 3, "one gems dir per engine; got {paths:?}");
        let found: HashSet<PathBuf> = paths.into_iter().collect();
        assert_eq!(found, HashSet::from([ruby_gems, jruby_gems, truffle_gems]));
    }

    // ── bundler-1 flat BUNDLE_PATH layout (gem live-matrix D1) ─────

    /// Bundler 1 with `BUNDLE_PATH` set via the ENVIRONMENT installs
    /// GEM_HOME-style into the flat `<BUNDLE_PATH>/gems/` — no
    /// `<engine>/<abi>` scope segment, sibling `specifications/` dir
    /// present (bundler >= 2 appends the scope even for env installs).
    /// The crawler only enumerated the scoped layout, so such projects
    /// scanned as `notInstalled` and `get` downloaded 1 / applied 0
    /// (live-verified 2026-08-19: activestorage@6.0.3 under bundler
    /// 1.17.3 at `vendor/bundle/gems/activestorage-6.0.3`).
    #[tokio::test]
    async fn get_vendor_bundle_paths_flat_bundler1_layout() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("vendor").join("bundle");
        let gems = bundle.join("gems");
        tokio::fs::create_dir_all(gems.join("activestorage-6.0.3").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(bundle.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths(dir.path()).await;
        assert_eq!(paths, vec![gems]);
    }

    /// A bare `gems/` directory WITHOUT the `specifications/` sibling a
    /// real gem home always carries is not a bundler install root — a
    /// project that just happens to hold `vendor/bundle/gems` clutter
    /// must not have it crawled as a gem store.
    #[tokio::test]
    async fn get_vendor_bundle_paths_ignores_bare_gems_dir() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("vendor").join("bundle");
        tokio::fs::create_dir_all(bundle.join("gems").join("foo-1.0.0").join("lib"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths(dir.path()).await;
        assert!(
            paths.is_empty(),
            "gems/ without specifications/ must not count: {paths:?}"
        );
    }

    /// Scoped and flat layouts can coexist under one root (a bundler-2
    /// `--path` install beside a bundler-1 env install). Both must be
    /// discovered exactly once, and the flat store's own `gems/` entry
    /// must not be misread as an `<engine>` dir — a gem that itself
    /// ships a `gems/` subdirectory would otherwise surface a ghost
    /// `<engine=gems>/<version=<gem dir>>/gems` root.
    #[tokio::test]
    async fn get_vendor_bundle_paths_scoped_and_flat_coexist() {
        let dir = tempfile::tempdir().unwrap();
        let bundle = dir.path().join("vendor").join("bundle");
        let scoped = bundle.join("ruby").join("3.1.0").join("gems");
        let flat = bundle.join("gems");
        tokio::fs::create_dir_all(&scoped).await.unwrap();
        tokio::fs::create_dir_all(bundle.join("specifications"))
            .await
            .unwrap();
        // A gem inside the flat store that itself ships a gems/ subdir.
        tokio::fs::create_dir_all(flat.join("weird-1.0.0").join("gems"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths(dir.path()).await;
        let found: HashSet<PathBuf> = paths.iter().cloned().collect();
        assert_eq!(found, HashSet::from([scoped, flat]));
        assert_eq!(paths.len(), 2, "no duplicates: {paths:?}");
    }

    /// The full local-mode pipeline heals on a project shaped exactly
    /// like the live repro: Gemfile + flat `vendor/bundle` store. The
    /// installed gem must crawl out with its PURL and real on-disk path.
    /// Asserts `contains` rather than equality so an ambient
    /// `BUNDLE_PATH` on the dev machine cannot perturb the result set.
    #[tokio::test]
    async fn crawl_all_finds_flat_bundler1_project() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(
            dir.path().join("Gemfile"),
            b"source \"https://rubygems.org\"\n",
        )
        .await
        .unwrap();
        let bundle = dir.path().join("vendor").join("bundle");
        let gem_dir = bundle.join("gems").join("activestorage-6.0.3");
        tokio::fs::create_dir_all(gem_dir.join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(bundle.join("specifications"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let packages = crawler.crawl_all(&options).await;
        let found = packages
            .iter()
            .find(|p| p.purl == "pkg:gem/activestorage@6.0.3");
        assert_eq!(
            found.map(|p| p.path.clone()),
            Some(gem_dir),
            "flat-layout gem must be crawled with its real path; got {packages:?}"
        );
    }

    // ── explicit BUNDLE_PATH roots (env var / .bundle/config) ──────

    /// An explicit env `BUNDLE_PATH` names the install root directly.
    /// Bundler 1 lays it out flat; bundler >= 2 appends the ruby scope.
    /// Both layouts under the env root must be discovered when the cwd
    /// holds a Bundler manifest.
    #[tokio::test]
    async fn bundle_path_env_discovers_both_layouts() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        let root = dir.path().join("custom-bundle");
        let flat = root.join("gems");
        let scoped = root.join("ruby").join("3.2.0").join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(&scoped).await.unwrap();

        let paths =
            RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), Some(root.as_os_str()), None)
                .await;
        let found: HashSet<PathBuf> = paths.iter().cloned().collect();
        assert_eq!(found, HashSet::from([scoped, flat]));
        assert_eq!(paths.len(), 2, "no duplicates: {paths:?}");
    }

    /// A relative env `BUNDLE_PATH` resolves against the project root
    /// (`Bundler.bundle_path` resolves against `Bundler.root`, the
    /// Gemfile's dir — never the process cwd).
    #[tokio::test]
    async fn bundle_path_env_relative_resolves_against_project_root() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        let root = dir.path().join("bundle_here");
        let flat = root.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(
            dir.path(),
            Some(OsStr::new("bundle_here")),
            None,
        )
        .await;
        assert_eq!(paths, vec![flat]);
    }

    /// Without a Bundler manifest in cwd the env var is ignored — a
    /// machine-wide `BUNDLE_PATH` export must not pull another project's
    /// gem store into a non-Ruby scan (same gate as the `gem env`
    /// fallback in `get_gem_paths`).
    #[tokio::test]
    async fn bundle_path_env_ignored_without_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("custom-bundle");
        tokio::fs::create_dir_all(root.join("gems").join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();

        let paths =
            RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), Some(root.as_os_str()), None)
                .await;
        assert!(
            paths.is_empty(),
            "BUNDLE_PATH must be gated on a Bundler manifest: {paths:?}"
        );
    }

    /// `BUNDLE_PATH` pointing at the default `vendor/bundle` reaches the
    /// same root twice — the store must come back exactly once.
    #[tokio::test]
    async fn bundle_path_env_duplicate_root_dedups() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        let bundle = dir.path().join("vendor").join("bundle");
        let flat = bundle.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(bundle.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(
            dir.path(),
            Some(bundle.as_os_str()),
            None,
        )
        .await;
        assert_eq!(paths, vec![flat]);
    }

    /// `bundle config set --local path <dir>` records `BUNDLE_PATH:` in
    /// `.bundle/config`; the crawler honors it like the env var — here a
    /// non-`vendor/bundle` dir that only the config file names.
    #[tokio::test]
    async fn app_config_bundle_path_discovered() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"vendor/mygems\"\n",
        )
        .await
        .unwrap();
        let root = dir.path().join("vendor").join("mygems");
        let flat = root.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert_eq!(paths, vec![flat]);
    }

    /// A FIFO planted as `.bundle/config` must not wedge discovery. The
    /// app-config read used a plain `tokio::fs::read_to_string`, whose
    /// `open(2)` on a FIFO waits for a writer that never comes — so one
    /// special file in the project tree wedged `scan` (crawl_all) and
    /// `apply`/`get` (find_by_purls path discovery) indefinitely, with no
    /// error and no timeout. Same class as the `open_regular_file` guards
    /// in the npm (package.json), composer (installed.json), and python
    /// (METADATA) crawlers.
    #[cfg(unix)]
    #[tokio::test]
    async fn app_config_fifo_does_not_wedge_discovery() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        let dot_bundle = dir.path().join(".bundle");
        tokio::fs::create_dir_all(&dot_bundle).await.unwrap();
        let fifo = dot_bundle.join("config");
        // mkfifo(2) directly, not the /usr/bin/mkfifo binary: spawning a
        // child flakes under heavy parallel load (fork/exec starvation)
        // and the syscall needs no process at all.
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
        // A real store beside the FIFO proves discovery still works
        // around the unreadable config.
        let bundle = dir.path().join("vendor").join("bundle");
        let flat = bundle.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(bundle.join("specifications"))
            .await
            .unwrap();

        // On timeout the open is wedged in a `spawn_blocking` thread that
        // the runtime waits for on shutdown; connect a writer to release
        // it so the test can FAIL instead of hanging the whole suite.
        let deadline = std::time::Duration::from_secs(5);
        let Ok(paths) = tokio::time::timeout(
            deadline,
            RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None),
        )
        .await
        else {
            let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
            panic!("bundle-path discovery must complete promptly with a FIFO .bundle/config");
        };
        assert_eq!(paths, vec![flat]);
    }

    /// `$BUNDLE_APP_CONFIG` relocates the app config dir (the official
    /// ruby Docker images export it) — the `BUNDLE_PATH:` entry must be
    /// honored from there, and the default `.bundle/config` (absent
    /// here) must not be required.
    #[tokio::test]
    async fn app_config_env_relocates_config() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        let app_config = dir.path().join("elsewhere-config");
        tokio::fs::create_dir_all(&app_config).await.unwrap();
        let root = dir.path().join("store");
        tokio::fs::write(
            app_config.join("config"),
            format!("---\nBUNDLE_PATH: \"{}\"\n", root.display()),
        )
        .await
        .unwrap();
        let flat = root.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(
            dir.path(),
            None,
            Some(app_config.as_os_str()),
        )
        .await;
        assert_eq!(paths, vec![flat]);
    }

    /// Roots must be probed in bundler's own precedence order — local
    /// `.bundle/config` `BUNDLE_PATH:` first, then the `BUNDLE_PATH`
    /// environment variable, then the implicit `vendor/bundle` default —
    /// so the stores come back highest-precedence first and first-wins
    /// consumers pick the copy bundler actually loads. The pre-fix order
    /// (default → env → config) was bundler's precedence inverted.
    #[tokio::test]
    async fn bundle_roots_probe_in_bundler_precedence_order() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();

        // Flat store under each of the three roots.
        let mut flats = Vec::new();
        for root in ["configstore", "envstore"] {
            let root = dir.path().join("vendor").join(root);
            let flat = root.join("gems");
            tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
                .await
                .unwrap();
            tokio::fs::create_dir_all(root.join("specifications"))
                .await
                .unwrap();
            flats.push(flat);
        }
        let default_root = dir.path().join("vendor").join("bundle");
        let default_flat = default_root.join("gems");
        tokio::fs::create_dir_all(default_flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(default_root.join("specifications"))
            .await
            .unwrap();

        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"vendor/configstore\"\n",
        )
        .await
        .unwrap();

        let env_root = dir.path().join("vendor").join("envstore");
        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(
            dir.path(),
            Some(env_root.as_os_str()),
            None,
        )
        .await;
        assert_eq!(
            paths,
            vec![flats[0].clone(), flats[1].clone(), default_flat],
            "stores must come back config-first, env second, default last (bundler precedence); got {paths:?}"
        );
    }

    // ── config-sourced root containment (untrusted .bundle/config) ─

    /// SECURITY: an ABSOLUTE `BUNDLE_PATH` in the (typically committed,
    /// attacker-authored) app config file that points outside the project
    /// must be skipped — it would otherwise become a scan/apply WRITE
    /// target anywhere on the machine. The store it names must NOT be
    /// discovered even though it is real and valid.
    #[tokio::test]
    async fn config_bundle_path_absolute_outside_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            format!("---\nBUNDLE_PATH: \"{}\"\n", outside.path().display()),
        )
        .await
        .unwrap();
        // A real store at the outside root — must stay undiscovered.
        tokio::fs::create_dir_all(outside.path().join("gems").join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(outside.path().join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert!(
            paths.is_empty(),
            "absolute out-of-project config BUNDLE_PATH must be skipped: {paths:?}"
        );
    }

    /// SECURITY: a `..` traversal in the config value (`../sibling`) must
    /// be skipped — a malicious clone must not direct patch writes into a
    /// sibling checkout.
    #[tokio::test]
    async fn config_bundle_path_parent_traversal_is_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project");
        let sibling = dir.path().join("sibling");
        tokio::fs::create_dir_all(&project).await.unwrap();
        tokio::fs::write(project.join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(project.join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            project.join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"../sibling\"\n",
        )
        .await
        .unwrap();
        tokio::fs::create_dir_all(sibling.join("gems").join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(sibling.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(&project, None, None).await;
        assert!(
            paths.is_empty(),
            "`..`-traversing config BUNDLE_PATH must be skipped: {paths:?}"
        );
    }

    /// A contained relative config value is accepted — including one that
    /// detours through `.`/`..` segments but normalizes back inside the
    /// project (bundler resolves it the same way).
    #[tokio::test]
    async fn config_bundle_path_contained_relative_accepted() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"vendor/./extra/../mygems\"\n",
        )
        .await
        .unwrap();
        let root = dir.path().join("vendor").join("mygems");
        let flat = root.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert_eq!(
            paths,
            vec![flat],
            "contained (normalized) relative config BUNDLE_PATH must be accepted"
        );
    }

    /// The containment refusal is RECORDED on the discovery result (for
    /// the CLI's warning channels), keyed by the verbatim config value —
    /// and stays `None` for a contained value or a `path.system` drop
    /// (bundler itself ignores the path there; nothing was refused).
    /// The detail must carry the config value VERBATIM. `{value:?}` (Debug)
    /// escaped backslashes, so on Windows the warning printed `C:\\Users\\…`
    /// for a config that says `C:\Users\…` — invisible on Unix (temp paths
    /// carry no backslashes), red on the windows-latest CI leg, and wrong
    /// for any human copy-pasting the path out of the warning. A
    /// backslash-bearing value pins it on every platform.
    #[test]
    fn config_path_ignored_warning_names_the_value_verbatim() {
        let value = r"C:\Users\dev\bundle store";
        let (code, detail) = config_path_ignored_warning(value);
        assert_eq!(code, "gem_bundle_config_path_ignored");
        assert!(
            detail.contains(value),
            "detail must contain the unescaped value: {detail}"
        );
        assert!(
            !detail.contains(r"C:\\Users"),
            "Debug escaping must not double backslashes: {detail}"
        );
    }

    #[tokio::test]
    async fn discovery_records_skipped_config_path() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        let value = outside.path().display().to_string();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            format!("---\nBUNDLE_PATH: \"{value}\"\n"),
        )
        .await
        .unwrap();

        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None).await;
        assert_eq!(
            discovery.skipped_config_path.as_deref(),
            Some(value.as_str()),
            "the refused config value must be recorded verbatim"
        );
        // The warning builder names the value and carries the stable code.
        let (code, detail) = config_path_ignored_warning(&value);
        assert_eq!(code, "gem_bundle_config_path_ignored");
        assert!(detail.contains(&value) && detail.contains("BUNDLE_PATH"));

        // Contained value → no skip recorded.
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"vendor/mygems\"\n",
        )
        .await
        .unwrap();
        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None).await;
        assert_eq!(discovery.skipped_config_path, None);

        // path.system=true → bundler ignores the path; not a refusal.
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            format!("---\nBUNDLE_PATH: \"{value}\"\nBUNDLE_PATH__SYSTEM: \"true\"\n"),
        )
        .await
        .unwrap();
        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None).await;
        assert_eq!(discovery.skipped_config_path, None);
    }

    /// Unit contract for the config-root containment policy itself.
    /// Real (absolute) tempdir paths keep the assertions valid on Windows,
    /// where a `/`-rooted literal is NOT absolute.
    #[test]
    fn resolve_config_bundle_path_containment_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let outside = tempfile::tempdir().unwrap();

        // Contained relative values resolve against the project root.
        assert_eq!(
            resolve_config_bundle_path(root, "vendor/bundle", None),
            Some(root.join("vendor").join("bundle"))
        );
        assert_eq!(
            resolve_config_bundle_path(root, "vendor/x/../y", None),
            Some(root.join("vendor").join("y"))
        );
        // Escaping relative values are refused.
        assert_eq!(resolve_config_bundle_path(root, "../sibling", None), None);
        assert_eq!(
            resolve_config_bundle_path(root, "vendor/../../sibling", None),
            None
        );
        // Absolute values must land under the project root.
        let inside = root.join("vendor").join("bundle");
        assert_eq!(
            resolve_config_bundle_path(root, inside.to_str().unwrap(), None),
            Some(inside)
        );
        assert_eq!(
            resolve_config_bundle_path(root, outside.path().to_str().unwrap(), None),
            None
        );
        // `..` smuggled into an absolute value cannot sneak past the
        // prefix check — it is normalized BEFORE comparing.
        let sneaky = root.join("vendor").join("..").join("..");
        assert_eq!(
            resolve_config_bundle_path(root, sneaky.to_str().unwrap(), None),
            None
        );
        // A root-relative value (`/evil`) is refused on every platform: a
        // unix absolute path outside the project, and on Windows a rooted
        // path `Path::join` would substitute into the base — either way it
        // must take the strict branch and fail the prefix check.
        assert_eq!(resolve_config_bundle_path(root, "/evil", None), None);
        // Windows drive-relative (`C:evil`) likewise must not reach the
        // join-based relative branch.
        #[cfg(windows)]
        assert_eq!(resolve_config_bundle_path(root, "C:evil", None), None);
        // `~` expands against home first; home outside the project →
        // refused, home inside → accepted.
        assert_eq!(
            resolve_config_bundle_path(root, "~/store", Some(outside.path())),
            None
        );
        let home_in = root.join("home");
        assert_eq!(
            resolve_config_bundle_path(root, "~/store", Some(&home_in)),
            Some(home_in.join("store"))
        );
    }

    // ── env BUNDLE_PATH `~` expansion + normalization ──────────────

    /// A leading `~/` in the env `BUNDLE_PATH` expands against HOME
    /// (bundler `File.expand_path`s the value); it used to resolve as a
    /// literal `<cwd>/~/...` relative path and discover nothing.
    #[tokio::test]
    async fn bundle_path_env_tilde_expands_against_home() {
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        let root = home.path().join("bundle-store");
        let flat = root.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();

        let discovery = RubyCrawler::discover_bundle_stores_with_env(
            dir.path(),
            Some(OsStr::new("~/bundle-store")),
            None,
            Some(home.path().as_os_str()),
        )
        .await;
        assert_eq!(
            discovery.stores,
            vec![flat],
            "~/ must expand against the provided home"
        );
        assert!(
            !discovery.default_root_has_stores,
            "env root must not count as the default vendor/bundle root"
        );
    }

    /// The ENV value stays trusted — an out-of-project absolute root is
    /// honored (unlike the config file, it is the user's own machine
    /// state) — and `..` segments are normalized so the same physical
    /// root spelled two ways dedups against the default probe.
    #[tokio::test]
    async fn bundle_path_env_outside_project_trusted_and_dotdot_dedups() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(outside.path().join("gems").join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(outside.path().join("specifications"))
            .await
            .unwrap();
        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(
            dir.path(),
            Some(outside.path().as_os_str()),
            None,
        )
        .await;
        assert_eq!(
            paths,
            vec![outside.path().join("gems")],
            "env BUNDLE_PATH outside the project stays honored (trusted)"
        );

        // `vendor/x/../bundle` names the default root — must dedup to one
        // probe (one store, once).
        let bundle = dir.path().join("vendor").join("bundle");
        let flat = bundle.join("gems");
        tokio::fs::create_dir_all(flat.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(bundle.join("specifications"))
            .await
            .unwrap();
        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(
            dir.path(),
            Some(OsStr::new("vendor/x/../bundle")),
            None,
        )
        .await;
        assert_eq!(
            paths.iter().filter(|p| **p == flat).count(),
            1,
            "normalized env root must dedup against the default probe: {paths:?}"
        );
    }

    // ── BUNDLE_PATH__SYSTEM drops the config-sourced root ──────────

    /// `BUNDLE_PATH__SYSTEM: "true"` makes bundler ignore the recorded
    /// path entirely — the config-sourced root must be dropped so the
    /// project falls through to the system gem homes (the `gem env`
    /// fallback in `get_gem_paths`).
    #[tokio::test]
    async fn config_bundle_path_system_true_drops_config_root() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"vendor/mygems\"\nBUNDLE_PATH__SYSTEM: \"true\"\n",
        )
        .await
        .unwrap();
        let root = dir.path().join("vendor").join("mygems");
        tokio::fs::create_dir_all(root.join("gems").join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("specifications"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert!(
            paths.is_empty(),
            "path.system=true must drop the config-sourced root: {paths:?}"
        );
    }

    /// Pure parser contract for the `.bundle/config` scrape: bundler's
    /// own quoted form, unquoted and single-quoted variants, CRLF,
    /// empty-value-as-unset, and no match on `BUNDLE_PATH__SYSTEM:` or
    /// an absent key.
    #[test]
    fn parse_bundle_config_path_contract() {
        assert_eq!(
            parse_bundle_config_path("---\nBUNDLE_PATH: \"vendor/bundle\"\n"),
            Some("vendor/bundle".to_string())
        );
        assert_eq!(
            parse_bundle_config_path("---\nBUNDLE_PATH: vendor/bundle\n"),
            Some("vendor/bundle".to_string())
        );
        assert_eq!(
            parse_bundle_config_path("---\nBUNDLE_PATH: 'vendor/bundle'\n"),
            Some("vendor/bundle".to_string())
        );
        assert_eq!(
            parse_bundle_config_path("---\r\nBUNDLE_PATH: \"vendor/bundle\"\r\n"),
            Some("vendor/bundle".to_string())
        );
        assert_eq!(
            parse_bundle_config_path(
                "---\nBUNDLE_FROZEN: \"true\"\nBUNDLE_PATH: \"vendor/bundle\"\n"
            ),
            Some("vendor/bundle".to_string())
        );
        assert_eq!(parse_bundle_config_path("---\nBUNDLE_PATH: \"\"\n"), None);
        assert_eq!(
            parse_bundle_config_path("---\nBUNDLE_PATH__SYSTEM: \"true\"\n"),
            None
        );
        // `path.system` true means "ignore the recorded path, use the
        // system gem home" — the recorded path must parse as unset,
        // whichever order the keys appear in.
        assert_eq!(
            parse_bundle_config_path(
                "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_PATH__SYSTEM: \"true\"\n"
            ),
            None
        );
        assert_eq!(
            parse_bundle_config_path(
                "---\nBUNDLE_PATH__SYSTEM: \"true\"\nBUNDLE_PATH: \"vendor/bundle\"\n"
            ),
            None
        );
        // Only the exact string "true" is truthy (bundler's own coercion).
        assert_eq!(
            parse_bundle_config_path(
                "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_PATH__SYSTEM: \"false\"\n"
            ),
            Some("vendor/bundle".to_string())
        );
        assert_eq!(
            parse_bundle_config_path("---\nBUNDLE_FROZEN: \"true\"\n"),
            None
        );
        assert_eq!(parse_bundle_config_path(""), None);
    }

    #[tokio::test]
    async fn test_deduplication() {
        let dir = tempfile::tempdir().unwrap();

        // Create a single gem directory
        let rails_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(rails_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };

        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:gem/rails@7.1.0");
    }

    #[tokio::test]
    async fn test_verify_gem_with_gemspec() {
        let dir = tempfile::tempdir().unwrap();
        let gem_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(&gem_dir).await.unwrap();
        tokio::fs::write(gem_dir.join("rails.gemspec"), "# gemspec")
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        assert!(crawler.verify_gem_at_path(&gem_dir).await);
    }

    #[tokio::test]
    async fn test_verify_gem_empty_dir_fails() {
        let dir = tempfile::tempdir().unwrap();
        let gem_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(&gem_dir).await.unwrap();

        let crawler = RubyCrawler::new();
        assert!(!crawler.verify_gem_at_path(&gem_dir).await);
    }

    /// `"-1.0.0"` — match_indices finds `i=0` (followed by `1`), the
    /// name slice is empty. The defensive empty-name guard at the
    /// bottom of parse_dir_name_version rejects rather than producing
    /// a `Gem("", "1.0.0")` ghost.
    #[test]
    fn test_parse_dir_name_version_empty_name_guard() {
        assert_eq!(RubyCrawler::parse_dir_name_version("-1.0.0"), None);
    }

    // ── platform-suffix resolution end-to-end ─────────────────────

    /// `find_by_purls` must resolve a base PURL to a platform gem dir
    /// that carries a `-<platform>` suffix on disk. Exercises the
    /// `locate_gem_dir` prefix-scan fallback, which the original
    /// suite only covered for the exact (plain-platform) case.
    #[tokio::test]
    async fn find_by_purls_resolves_platform_suffixed_dir() {
        let dir = tempfile::tempdir().unwrap();
        let plat_dir = dir.path().join("nokogiri-1.16.5-x86_64-linux");
        tokio::fs::create_dir_all(plat_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/nokogiri@1.16.5".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();

        assert_eq!(result.len(), 1);
        let pkg = result.get("pkg:gem/nokogiri@1.16.5").unwrap();
        assert_eq!(pkg.version, "1.16.5");
        assert_eq!(pkg.path, plat_dir);
    }

    /// A base PURL must NOT resolve to a platform dir whose version is
    /// merely a prefix of the requested one (`1.0` vs `1.0.0`).
    #[tokio::test]
    async fn find_by_purls_rejects_version_prefix_collision() {
        let dir = tempfile::tempdir().unwrap();
        let plat_dir = dir.path().join("foo-1.0.0-x86_64-linux");
        tokio::fs::create_dir_all(plat_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        // Request version "1.0" — must not match the installed "1.0.0".
        let purls = vec!["pkg:gem/foo@1.0".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "1.0 must not match foo-1.0.0-*; got {result:?}"
        );
    }

    /// `crawl_all` must strip the platform suffix when building the
    /// PURL while keeping `path` pointed at the real (platform) dir.
    #[tokio::test]
    async fn crawl_all_strips_platform_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let plat_dir = dir.path().join("nokogiri-1.16.5-arm64-darwin");
        tokio::fs::create_dir_all(plat_dir.join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };
        let packages = crawler.crawl_all(&options).await;
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].purl, "pkg:gem/nokogiri@1.16.5");
        assert_eq!(packages[0].version, "1.16.5");
        assert_eq!(packages[0].path, plat_dir);
    }

    /// A plain `<name>-<version>` dir must win over any platform
    /// sibling when both are present (exact match short-circuits).
    #[tokio::test]
    async fn locate_gem_dir_prefers_exact_over_platform() {
        let dir = tempfile::tempdir().unwrap();
        let exact = dir.path().join("rails-7.1.0");
        let plat = dir.path().join("rails-7.1.0-x86_64-linux");
        tokio::fs::create_dir_all(exact.join("lib")).await.unwrap();
        tokio::fs::create_dir_all(plat.join("lib")).await.unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/rails@7.1.0".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();
        assert_eq!(result.get("pkg:gem/rails@7.1.0").unwrap().path, exact);
    }

    // ── gem env gempath splitting (OS path separator) ─────────────

    /// `gem env gempath` lists several gem homes joined by the OS path
    /// separator. The splitter must use the platform separator, not a
    /// hardcoded `:` — otherwise Windows drive-letter paths (`C:\…;D:\…`)
    /// are shredded. Building the input with `std::env::join_paths` makes
    /// this assertion exercise the real platform separator: a regression
    /// to `split(':')` fails on Windows (join uses `;`) while staying
    /// correct on Unix.
    #[test]
    fn gem_homes_split_honors_os_separator() {
        let home_a = PathBuf::from(if cfg!(windows) {
            r"C:\rubies\3.2.0"
        } else {
            "/opt/rubies/3.2.0"
        });
        let home_b = PathBuf::from(if cfg!(windows) {
            r"D:\gems\global"
        } else {
            "/home/dev/.gem/ruby/3.2.0"
        });
        let joined = std::env::join_paths([&home_a, &home_b]).unwrap();
        let joined = joined.to_str().unwrap();

        let dirs = gem_homes_to_gems_dirs(joined);
        assert_eq!(
            dirs,
            vec![home_a.join("gems"), home_b.join("gems")],
            "gempath {joined:?} must split on the OS separator into per-home gems/ dirs"
        );
    }

    /// Empty segments (leading/trailing/double separators) are dropped so
    /// we never probe a bare `gems/` relative to the cwd.
    #[test]
    fn gem_homes_split_drops_empty_segments() {
        let sep = if cfg!(windows) { ';' } else { ':' };
        let only = if cfg!(windows) {
            r"C:\rubies\3.2.0"
        } else {
            "/opt/rubies/3.2.0"
        };
        let input = format!("{sep}{only}{sep}{sep}");
        let dirs = gem_homes_to_gems_dirs(&input);
        assert_eq!(dirs, vec![PathBuf::from(only).join("gems")]);
        assert!(gem_homes_to_gems_dirs("").is_empty());
    }

    // ── crawl/parse robustness regressions ────────────────────────

    /// A base PURL must not resolve to a *plain* dir whose version merely
    /// shares the requested version as a dotted prefix (`1.0` vs `1.0.0`).
    /// Complements the platform-suffixed collision test.
    #[tokio::test]
    async fn find_by_purls_rejects_plain_version_prefix_collision() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        let crawler = RubyCrawler::new();
        let result = crawler
            .find_by_purls(dir.path(), &["pkg:gem/foo@1.0".to_string()])
            .await
            .unwrap();
        assert!(
            result.is_empty(),
            "1.0 wrongly matched plain foo-1.0.0: {result:?}"
        );
    }

    /// `crawl_all` must skip dirs that parse as `<name>-<version>` but are
    /// not gems (no `lib/`, no `.gemspec`) and must ignore `.gem` cache
    /// files that string-match the `<name>-<version>` pattern.
    #[tokio::test]
    async fn crawl_all_skips_non_gem_dirs_and_cache_files() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("rails-7.1.0").join("lib"))
            .await
            .unwrap();
        // Parses as a gem name but has no lib/ or gemspec — not a gem.
        tokio::fs::create_dir_all(dir.path().join("junk-1.0.0"))
            .await
            .unwrap();
        // A cached `.gem` archive (a file, not a dir) that matches the pattern.
        tokio::fs::write(dir.path().join("rails-7.1.0.gem"), b"x")
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: Some(dir.path().to_path_buf()),
        };
        let packages = crawler.crawl_all(&options).await;
        let purls: HashSet<_> = packages.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(purls, HashSet::from(["pkg:gem/rails@7.1.0"]));
    }

    /// A requested version that is *longer* than what is installed must
    /// not resolve. The prefix scan keys on `<name>-<version>-`, so a
    /// requested `1.0.0` must reject both a plain `foo-1.0/` and a
    /// platform `foo-1.0-x86_64-linux/` (installed version `1.0`). Guards
    /// against a future change that compares versions bidirectionally.
    #[tokio::test]
    async fn find_by_purls_rejects_longer_requested_version() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("foo-1.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join("foo-1.0-x86_64-linux").join("lib"))
            .await
            .unwrap();
        let crawler = RubyCrawler::new();
        let result = crawler
            .find_by_purls(dir.path(), &["pkg:gem/foo@1.0.0".to_string()])
            .await
            .unwrap();
        assert!(
            result.is_empty(),
            "1.0.0 must not match installed 1.0 dirs: {result:?}"
        );
    }

    /// The exact-match arm of `locate_gem_dir` must *verify gem content*,
    /// not merely accept that `<name>-<version>/` exists on disk. When the
    /// exact dir is present but empty (no `lib/`, no `.gemspec` — a
    /// malformed/partial install), resolution must fall through to a valid
    /// platform sibling rather than returning the hollow exact dir.
    #[tokio::test]
    async fn locate_gem_dir_skips_invalid_exact_for_valid_platform() {
        let dir = tempfile::tempdir().unwrap();
        // Exact dir exists but is hollow — not a real gem.
        tokio::fs::create_dir_all(dir.path().join("nokogiri-1.16.5"))
            .await
            .unwrap();
        // Valid platform sibling.
        let plat = dir.path().join("nokogiri-1.16.5-x86_64-linux");
        tokio::fs::create_dir_all(plat.join("lib")).await.unwrap();

        let crawler = RubyCrawler::new();
        let result = crawler
            .find_by_purls(dir.path(), &["pkg:gem/nokogiri@1.16.5".to_string()])
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("pkg:gem/nokogiri@1.16.5").unwrap().path, plat);
    }

    /// `parse_gem_env_output` is the pure parser for `gem env <key>`
    /// stdout: empty/whitespace-only input yields `None` (gem absent or no
    /// path), and surrounding whitespace/newlines are trimmed off a real
    /// path so it joins cleanly with `gems/`.
    #[test]
    fn parse_gem_env_output_contract() {
        assert_eq!(parse_gem_env_output(""), None);
        assert_eq!(parse_gem_env_output("   \n\t "), None);
        assert_eq!(
            parse_gem_env_output("  /usr/lib/ruby/gems/3.2.0\n"),
            Some("/usr/lib/ruby/gems/3.2.0".to_string())
        );
    }

    /// Local mode must not walk the global gem store for a non-Ruby
    /// project: with no `vendor/bundle/ruby/` and neither `Gemfile` nor
    /// `Gemfile.lock` present, `get_gem_paths` returns empty (it never even
    /// shells out to `gem env`). This pins the project-detection gate that
    /// keeps a JS/Python checkout from being scanned as Ruby.
    #[tokio::test]
    async fn get_gem_paths_empty_for_non_ruby_project() {
        let dir = tempfile::tempdir().unwrap();
        // A decoy non-Ruby file; no Gemfile, no vendor/bundle/ruby.
        tokio::fs::write(dir.path().join("package.json"), b"{}")
            .await
            .unwrap();
        let crawler = RubyCrawler::new();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let paths = crawler.get_gem_paths(&options).await.unwrap();
        assert!(
            paths.is_empty(),
            "non-Ruby project must yield no gem paths: {paths:?}"
        );
    }

    // ── PURL coordinate traversal (untrusted manifest input) ──────

    /// A tampered manifest PURL whose name carries `..` must not resolve
    /// to a directory outside the gem root. `locate_gem_dir` joins
    /// `<name>-<version>` straight onto `gem_path`, and
    /// `verify_gem_at_path` only checks for `lib/`/`.gemspec`, so without
    /// a coordinate gate `pkg:gem/../outside@1.0.0` escapes the gem store
    /// and the patch applies in place out of tree.
    #[tokio::test]
    async fn find_by_purls_rejects_traversal_coordinates() {
        let dir = tempfile::tempdir().unwrap();
        let gems = dir.path().join("gems");
        tokio::fs::create_dir_all(&gems).await.unwrap();
        // A verifying "gem" OUTSIDE the gem root that `..` escapes to.
        tokio::fs::create_dir_all(dir.path().join("outside-1.0.0").join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/../outside@1.0.0".to_string()];
        let result = crawler.find_by_purls(&gems, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "`..` name must not escape the gem root: {result:?}"
        );
    }

    /// An absolute path smuggled in as the gem name replaces the gem root
    /// wholesale in `Path::join` — must be rejected fail-closed.
    #[tokio::test]
    async fn find_by_purls_rejects_absolute_coordinates() {
        let dir = tempfile::tempdir().unwrap();
        let gems = dir.path().join("gems");
        tokio::fs::create_dir_all(&gems).await.unwrap();
        let outside = dir.path().join("abs");
        tokio::fs::create_dir_all(outside.join("evil-1.0.0").join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purl = format!("pkg:gem/{}@1.0.0", outside.join("evil").display());
        let result = crawler.find_by_purls(&gems, &[purl]).await.unwrap();
        assert!(
            result.is_empty(),
            "absolute name must not replace the gem root: {result:?}"
        );
    }

    /// A separator smuggled into the *version* half of the coordinate is
    /// just as dangerous as one in the name — both halves are formatted
    /// into the joined `<name>-<version>` segment.
    #[tokio::test]
    async fn find_by_purls_rejects_separator_in_version() {
        let dir = tempfile::tempdir().unwrap();
        let gems = dir.path().join("gems");
        tokio::fs::create_dir_all(&gems).await.unwrap();
        // `foo-1.0/../../outside-1.0.0` needs `foo-1.0` to traverse through.
        tokio::fs::create_dir_all(gems.join("foo-1.0"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join("outside-1.0.0").join("lib"))
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/foo@1.0/../../outside-1.0.0".to_string()];
        let result = crawler.find_by_purls(&gems, &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "version with separators must not escape the gem root: {result:?}"
        );
    }

    /// Unit contract for the coordinate gate: real gem names/versions pass,
    /// anything with a separator, NUL, or bare dot segment fails closed.
    #[test]
    fn test_is_safe_gem_coordinate() {
        assert!(is_safe_gem_coordinate("rails", "7.1.0"));
        assert!(is_safe_gem_coordinate("aws-sdk-s3", "1.143.0"));
        assert!(is_safe_gem_coordinate("ruby2_keywords", "0.0.5"));
        assert!(is_safe_gem_coordinate("nokogiri", "1.16.5.pre.rc1"));

        assert!(!is_safe_gem_coordinate("", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", ""));
        assert!(!is_safe_gem_coordinate("..", "1.0.0"));
        assert!(!is_safe_gem_coordinate(".", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", ".."));
        assert!(!is_safe_gem_coordinate("../outside", "1.0.0"));
        assert!(!is_safe_gem_coordinate("a/b", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", "1.0/../../x"));
        assert!(!is_safe_gem_coordinate("a\\b", "1.0.0"));
        assert!(!is_safe_gem_coordinate("a\0b", "1.0.0"));
        assert!(!is_safe_gem_coordinate("/abs/evil", "1.0.0"));
        // Windows drive-relative escape: a `:` (e.g. `C:evil`) makes the
        // joined path absolute under `Path::join`.
        assert!(!is_safe_gem_coordinate("C:evil", "1.0.0"));
        assert!(!is_safe_gem_coordinate("rails", "C:1.0.0"));
    }

    /// Names with embedded `-<digit>` runs (`http-2`, `http-2-next`) must
    /// keep the digits in the name: the boundary is the LAST dash-digit
    /// whose version token is dotted, not the first dash-digit. Without
    /// that preference `http-2-1.0.1` parsed as `("http", "2")` — a ghost
    /// PURL — and the real gem was never discovered.
    #[test]
    fn parse_dir_name_version_prefers_last_dotted_boundary() {
        assert_eq!(
            RubyCrawler::parse_dir_name_version("http-2-1.0.1"),
            Some(("http-2".to_string(), "1.0.1".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("http-2-next-1.0.3"),
            Some(("http-2-next".to_string(), "1.0.3".to_string()))
        );
        // A platform suffix after the real version still drops.
        assert_eq!(
            RubyCrawler::parse_dir_name_version("http-2-1.0.1-java"),
            Some(("http-2".to_string(), "1.0.1".to_string()))
        );
    }

    /// The dotted-boundary preference must not regress the plain shapes:
    /// dotted versions, prereleases, platform dirs, and — via the
    /// first-boundary fallback — bare single-segment versions (legal per
    /// RubyGems, just vanishingly rare).
    #[test]
    fn parse_dir_name_version_boundary_shapes() {
        assert_eq!(
            RubyCrawler::parse_dir_name_version("rack-3.1.0"),
            Some(("rack".to_string(), "3.1.0".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("aws-sdk-s3-1.140.0"),
            Some(("aws-sdk-s3".to_string(), "1.140.0".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("gem2-1.0"),
            Some(("gem2".to_string(), "1.0".to_string()))
        );
        // No dotted candidate → first dash-digit boundary fallback.
        assert_eq!(
            RubyCrawler::parse_dir_name_version("g-1"),
            Some(("g".to_string(), "1".to_string()))
        );
        // Prerelease dashes render as dots, so the token stays dotted.
        assert_eq!(
            RubyCrawler::parse_dir_name_version("rails-7.1.0.beta1"),
            Some(("rails".to_string(), "7.1.0.beta1".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("nokogiri-1.16.0-arm64-darwin"),
            Some(("nokogiri".to_string(), "1.16.0".to_string()))
        );
    }

    /// Gem names with embedded underscores/digits and multi-dash names
    /// must keep their full name; the version starts at the dash-then-digit
    /// boundary that opens the dotted version token.
    #[test]
    fn parse_dir_name_version_name_shapes() {
        assert_eq!(
            RubyCrawler::parse_dir_name_version("ruby2_keywords-0.0.5"),
            Some(("ruby2_keywords".to_string(), "0.0.5".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("aws-sdk-s3-1.143.0"),
            Some(("aws-sdk-s3".to_string(), "1.143.0".to_string()))
        );
        assert_eq!(
            RubyCrawler::parse_dir_name_version("concurrent-ruby-1.2.3"),
            Some(("concurrent-ruby".to_string(), "1.2.3".to_string()))
        );
    }
}
