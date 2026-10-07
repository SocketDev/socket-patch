use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::types::{CrawledPackage, CrawlerOptions};
use crate::patch::path_safety;
use crate::utils::fs::{
    entry_is_dir, home_dir, is_dir, is_file, list_dir_entries, normalize_lexically, run_blocking,
};
use crate::utils::process::{CommandRunner, SystemCommandRunner};
use crate::vendor::lock_inventory::{DiskSnapshot, ProjectView};

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
        Ok(Self::gem_paths_and_discovery(
            options,
            std::env::var_os("BUNDLE_PATH").as_deref(),
            ambient_path_system_env().as_deref(),
            std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
            ambient_home().as_deref(),
            ambient_global_config_unless_ignored(&options.cwd).as_deref(),
            bundler_ignores_config(),
        )
        .await
        .0)
    }

    /// [`Self::get_gem_paths`] with the ambient `BUNDLE_PATH` /
    /// `BUNDLE_APP_CONFIG` / home environment and the global bundler config
    /// file ([`bundler_global_config_file`]) passed explicitly, so tests
    /// stay hermetic on machines where bundler is configured. (`gem env`
    /// still shells out; PATH-swapping tests keep covering that seam.)
    pub async fn get_gem_paths_with_env(
        &self,
        options: &CrawlerOptions,
        bundle_path_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        home_env: Option<&OsStr>,
        global_config: Option<&Path>,
    ) -> Result<Vec<PathBuf>, std::io::Error> {
        Ok(Self::gem_paths_and_discovery(
            options,
            bundle_path_env,
            None,
            app_config_env,
            home_env,
            global_config,
            false,
        )
        .await
        .0)
    }

    /// The gem paths plus the local-mode bundle-store discovery they came
    /// from (`None` in global / `--global-prefix` mode, which never probes
    /// the Bundler roots), so a caller that needs the discovery's advisories
    /// (`skipped_config_path`) does not probe the roots a second time.
    async fn gem_paths_and_discovery(
        options: &CrawlerOptions,
        bundle_path_env: Option<&OsStr>,
        path_system_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        home_env: Option<&OsStr>,
        global_config: Option<&Path>,
        ignore_config: bool,
    ) -> (Vec<PathBuf>, Option<BundleStoreDiscovery>) {
        if options.global || options.global_prefix.is_some() {
            if let Some(ref custom) = options.global_prefix {
                return (vec![custom.clone()], None);
            }
            return (Self::get_global_gem_paths().await, None);
        }

        // Local mode: probe the Bundler install roots first.
        let discovery = Self::discover_bundle_stores_impl(
            &options.cwd,
            bundle_path_env,
            path_system_env,
            app_config_env,
            home_env,
            global_config,
            ignore_config,
        )
        .await;
        let mut paths = discovery.stores.clone();

        // Historic early-return, kept ONLY for the implicit project-local
        // `vendor/bundle` probe: a deployment-style install is the
        // project's one gem source, so the ambient gem homes don't apply.
        // Stores found via an env/config root do NOT suppress the fallback
        // below: default gems (rexml, json, …) never live in a bundle path
        // — they ship with ruby in the DEFAULT/system gem homes — so an
        // env-`BUNDLE_PATH` project still needs the `gem env` homes to see
        // them (the explicit-roots feature briefly suppressed that
        // pre-existing fallback).
        //
        // Otherwise only consult the installed gem homes if this looks like
        // a Ruby project. A non-deployment `bundle install` puts the
        // project's gems in the ambient gem homes, so every home `gem env`
        // reports counts — not just `gemdir`: bundler resolves from all of
        // `Gem.path`, and a gem the project loads routinely lives in a
        // non-`gemdir` home (rvm keeps shared gems in the `@global` gemset;
        // `--user-install` puts them under `~/.gem`/`$XDG_DATA_HOME`).
        if !discovery.default_root_has_stores && Self::has_bundler_manifest(&options.cwd).await {
            let mut seen: HashSet<PathBuf> = paths.iter().cloned().collect();
            for gems_dir in Self::gem_env_gems_dirs().await {
                if seen.insert(gems_dir.clone()) {
                    paths.push(gems_dir);
                }
            }
        }

        (paths, Some(discovery))
    }

    /// Crawl all discovered gem paths and return every package found.
    pub async fn crawl_all(&self, options: &CrawlerOptions) -> Vec<CrawledPackage> {
        self.crawl_all_with_discovery(options).await.0
    }

    /// [`Self::crawl_all`] plus the bundle-store discovery the local-mode
    /// crawl consulted (`None` in global / `--global-prefix` mode), so the
    /// CLI can surface its `skipped_config_path` advisory without probing
    /// the Bundler roots again.
    pub async fn crawl_all_with_discovery(
        &self,
        options: &CrawlerOptions,
    ) -> (Vec<CrawledPackage>, Option<BundleStoreDiscovery>) {
        let mut packages = Vec::new();
        let mut seen = HashSet::new();

        let (gem_paths, discovery) = Self::gem_paths_and_discovery(
            options,
            std::env::var_os("BUNDLE_PATH").as_deref(),
            ambient_path_system_env().as_deref(),
            std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
            ambient_home().as_deref(),
            ambient_global_config_unless_ignored(&options.cwd).as_deref(),
            bundler_ignores_config(),
        )
        .await;

        for gem_path in &gem_paths {
            let found = self.scan_gem_dir(gem_path, &mut seen).await;
            packages.extend(found);
        }

        (packages, discovery)
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
                let (name, version) = (name.as_ref(), version.as_ref());
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
    /// (`Bundler::SharedHelpers.default_gemfile`). Both count: gating on
    /// `Gemfile` alone left a `gems.rb` project with a non-deployment
    /// `bundle install` undiscoverable, so `apply` silently found zero gems.
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
    ///
    /// The two `gem env` subprocesses run concurrently (each is one
    /// ruby boot), once per process ([`Self::gem_env_homes`]); their
    /// answers are consumed in the fixed order above. The directory probes
    /// are re-run on every call.
    async fn gem_env_gems_dirs() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        let mut seen = HashSet::new();

        let (gemdir, gempath) = Self::gem_env_homes().await;

        if let Some(gemdir) = gemdir {
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
        if let Some(gempath) = gempath {
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
    /// [`Self::get_gem_paths`] → [`Self::discover_bundle_stores_impl`];
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
        Self::discover_bundle_stores_with_env(cwd, bundle_path_env, app_config_env, None, None)
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
    /// 3. `<cwd>/bundle` when it holds `bundler/setup.rb` — the tree
    ///    `bundle install --standalone` writes and the app loads through
    ///    that script. Bundler 2 also recorded it as `BUNDLE_PATH:
    ///    "bundle"` (root 1), but bundler 4 no longer remembers CLI flags
    ///    and writes no config at all, so the marker is the only trace
    ///    (#796). It counts as an explicit root, like the recorded path it
    ///    replaces: the `gem env` fallback stays on for the default gems.
    /// 4. the `BUNDLE_PATH:` entry of the global config file
    ///    ([`bundler_global_config_file`], what `bundle config set --global
    ///    path <dir>` records) — resolved like the env var, and trusted
    ///    like it: it is the user's own machine state, not project input.
    /// 5. `<cwd>/vendor/bundle` — the default deployment/`--path` location.
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
    ///
    /// With `ignore_config` (`BUNDLE_IGNORE_CONFIG`, see
    /// [`bundler_ignores_config`]) bundler reads no config file, so the app
    /// config's `BUNDLE_PATH` is neither a root nor a refused root, and it
    /// shadows nothing. (Callers already drop `global_config` then.)
    async fn discover_bundle_stores_impl(
        cwd: &Path,
        bundle_path_env: Option<&OsStr>,
        path_system_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        home_env: Option<&OsStr>,
        global_config: Option<&Path>,
        ignore_config: bool,
    ) -> BundleStoreDiscovery {
        let home = home_env.map(Path::new);
        let default_root = cwd.join("vendor").join("bundle");
        let default_root = normalize_lexically(&default_root).unwrap_or(default_root);

        // A truthy `path.system` in the tier Bundler reads sends it to the
        // system gem home, which ignores every bundle path: the env
        // `BUNDLE_PATH` it shadows (or that sits in the same tier) and the
        // default `vendor/bundle`. A leftover store there must not be
        // crawled, nor switch off the `gem env` homes where the loaded
        // copy lives (#915). Gated like the explicit roots: config only
        // counts for a Ruby project. (A recorded local path never coexists
        // with it: [`parse_bundle_config_path`] already drops it.)
        let path_tier = if Self::has_bundler_manifest(cwd).await {
            Self::bundler_path_tier(
                cwd,
                bundle_path_env,
                path_system_env,
                app_config_env,
                global_config,
                ignore_config,
            )
            .await
        } else {
            None
        };
        let uses_system_gems = path_tier.is_some_and(|tier| tier.system);

        let mut roots: Vec<PathBuf> = Vec::new();
        let mut skipped_config_path = None;
        let mut skipped_config_root = None;
        if Self::has_bundler_manifest(cwd).await {
            if let Some(value) =
                Self::app_config_bundle_path(cwd, app_config_env, ignore_config, home).await
            {
                match resolve_config_bundle_path(cwd, &value, home) {
                    Some(root) => roots.push(root),
                    // Refused by the containment guard. Recorded — not
                    // printed: the crawler has no --silent/--json context,
                    // so the CLI surfaces it (see
                    // [`config_path_ignored_warning`]). The resolved root is
                    // kept too, for READ-ONLY verification only (see
                    // [`Self::verification_only_gem_paths`]).
                    None => {
                        skipped_config_root =
                            Some(resolve_bundle_path(cwd, Path::new(&value), home));
                        skipped_config_path = Some(value);
                    }
                }
            }
            if let Some(v) = bundle_path_env.filter(|v| !v.is_empty() && !uses_system_gems) {
                roots.push(resolve_bundle_path(cwd, Path::new(v), home));
            }
            let standalone_root = cwd.join("bundle");
            if is_file(&standalone_root.join("bundler").join("setup.rb")).await {
                roots.push(normalize_lexically(&standalone_root).unwrap_or(standalone_root));
            }
            // The global config's path (`bundle config set --global path`)
            // is the user's own machine state, so it is trusted like the
            // env var: no containment guard. Bundler's `Settings#path`
            // takes the FIRST tier that sets `path`, `path.system`, or
            // `disable_shared_gems`, so a local or env setting shadows it
            // entirely — even an empty env
            // `BUNDLE_PATH`, which adds no root above but still stops
            // Bundler (`explicit_path` is `""`). An env
            // `BUNDLE_PATH__SYSTEM` or `BUNDLE_DISABLE_SHARED_GEMS` already
            // dropped `global_config`, see
            // [`global_path_config_unless_env_path_settings`].
            let shadowed = bundle_path_env.is_some()
                || (!ignore_config && Self::app_config_sets_path(cwd, app_config_env).await);
            if !shadowed {
                let text = read_global_config(global_config, false).await;
                let value = match text {
                    Some(text) => {
                        bundle_config_dir_reading(
                            parse_bundle_config_path(&text),
                            parse_legacy_bundle_config_path(&text),
                            |value| resolve_bundle_path(cwd, Path::new(value), home),
                        )
                        .await
                    }
                    None => None,
                };
                if let Some(value) = value {
                    roots.push(resolve_bundle_path(cwd, Path::new(&value), home));
                }
            }
            // With no explicit path and no truthy `path.system` in the
            // deciding tier, Bundler's `Path#base_path` is `<root>/.bundle`
            // whenever `use_system_gems?` is false: `default_install_uses_path`
            // on 2.x, `bundler_5_mode?` (`simulate_version 5`) on 4.x, and
            // the default from Bundler 5 on (#967). Probed without reading
            // those version-dependent flags: the scoped store only exists
            // once Bundler installed there. Like the explicit roots it keeps
            // the `gem env` fallback on, since default gems stay in the
            // system homes.
            if !path_tier.is_some_and(|tier| tier.system || tier.explicit_path) {
                let dot_bundle = cwd.join(".bundle");
                roots.push(normalize_lexically(&dot_bundle).unwrap_or(dot_bundle));
            }
        }
        if !uses_system_gems {
            roots.push(default_root.clone());
        }

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
            skipped_config_root,
        }
    }

    /// Local-mode Bundler install-root discovery against the AMBIENT
    /// environment — the same probe [`Self::get_gem_paths`] runs, exposed
    /// for CLI consumers that need what the flat path list drops: the
    /// store/fallback CLASS boundary (`stores`) and the config-skip
    /// advisory (`skipped_config_path`). Cheap: filesystem probes only,
    /// no `gem env` shell-out.
    pub async fn discover_bundle_stores(cwd: &Path) -> BundleStoreDiscovery {
        Self::discover_bundle_stores_impl(
            cwd,
            std::env::var_os("BUNDLE_PATH").as_deref(),
            ambient_path_system_env().as_deref(),
            std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
            ambient_home().as_deref(),
            ambient_global_config_unless_ignored(cwd).as_deref(),
            bundler_ignores_config(),
        )
        .await
    }

    /// [`Self::discover_bundle_stores_impl`] with the config files read (no
    /// `BUNDLE_IGNORE_CONFIG`): the hermetic unit-test seam.
    #[cfg(test)]
    async fn discover_bundle_stores_with_env(
        cwd: &Path,
        bundle_path_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        home_env: Option<&OsStr>,
        global_config: Option<&Path>,
    ) -> BundleStoreDiscovery {
        Self::discover_bundle_stores_impl(
            cwd,
            bundle_path_env,
            None,
            app_config_env,
            home_env,
            global_config,
            false,
        )
        .await
    }

    /// [`Self::discover_bundle_stores_with_env`] with an env
    /// `BUNDLE_PATH__SYSTEM` value, which also drops the global config
    /// the way [`ambient_global_config_unless_ignored`] does.
    #[cfg(test)]
    async fn discover_bundle_stores_with_path_system_env(
        cwd: &Path,
        bundle_path_env: Option<&OsStr>,
        path_system_env: Option<&OsStr>,
        global_config: Option<&Path>,
    ) -> BundleStoreDiscovery {
        let global_config = global_path_config_unless_env_path_settings(
            global_config.map(Path::to_path_buf),
            path_system_env,
            None,
        );
        Self::discover_bundle_stores_impl(
            cwd,
            bundle_path_env,
            path_system_env,
            None,
            None,
            global_config.as_deref(),
            false,
        )
        .await
    }

    /// Installed-gem stores under a config-sourced `BUNDLE_PATH` the
    /// containment guard refused (it resolves outside the project), for
    /// READ-ONLY consumers: the hosted stale-install probe and `vex`'s
    /// installed-copy lookup.
    ///
    /// The guard exists because crawled roots are apply WRITE targets, and a
    /// committed `.bundle/config` is untrusted input. Bundler still installs
    /// into and loads from that root, though, so a verifier that skipped it
    /// would read "no installed copy" as "nothing to check" and attest a
    /// patch over the unpatched gem bundler actually loads (#709). These
    /// paths are therefore never part of [`Self::get_gem_paths`] (what apply
    /// and rollback write through) — only of verification. Empty in global /
    /// `--global-prefix` mode and whenever no config root was refused.
    pub async fn verification_only_gem_paths(&self, options: &CrawlerOptions) -> Vec<PathBuf> {
        self.verification_only_gem_paths_with_env(
            options,
            std::env::var_os("BUNDLE_PATH").as_deref(),
            std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
            ambient_home().as_deref(),
            ambient_global_config_unless_ignored(&options.cwd).as_deref(),
            bundler_ignores_config(),
        )
        .await
    }

    /// [`Self::verification_only_gem_paths`] with the environment passed
    /// explicitly (the hermetic test seam, like
    /// [`Self::get_gem_paths_with_env`]).
    pub async fn verification_only_gem_paths_with_env(
        &self,
        options: &CrawlerOptions,
        bundle_path_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        home_env: Option<&OsStr>,
        global_config: Option<&Path>,
        ignore_config: bool,
    ) -> Vec<PathBuf> {
        if options.global || options.global_prefix.is_some() {
            return Vec::new();
        }
        // Under `BUNDLE_IGNORE_CONFIG` bundler never reads the config path,
        // so nothing is refused and there is nothing extra to verify.
        // `path.system` only drops the default root, never the refused
        // config root this reads, so the env flag is not needed here.
        let discovery = Self::discover_bundle_stores_impl(
            &options.cwd,
            bundle_path_env,
            None,
            app_config_env,
            home_env,
            global_config,
            ignore_config,
        )
        .await;
        let Some(root) = discovery.skipped_config_root else {
            return Vec::new();
        };
        // The same root reachable as a trusted store (env `BUNDLE_PATH`
        // naming it too) is already probed by the regular discovery.
        Self::bundle_root_gems_dirs(&root)
            .await
            .into_iter()
            .filter(|gems_dir| !discovery.stores.contains(gems_dir))
            .collect()
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

    /// Whether the app config file sets `path`, `path.system`, or
    /// `disable_shared_gems` at all, including an empty string — any one
    /// makes bundler stop at that tier (`Settings#path`), so the global
    /// config's path never applies.
    async fn app_config_sets_path(cwd: &Path, app_config_env: Option<&OsStr>) -> bool {
        let config = bundler_app_config_dir(cwd, app_config_env).join("config");
        crate::utils::fs::read_regular_to_string(&config)
            .await
            .is_ok_and(|text| config_path_tier(&text).is_some())
    }

    /// The Bundler tier that decides the install path. `Settings#path`
    /// takes the FIRST of the local app config, the environment and the
    /// global config that sets `path`, `path.system` or
    /// `disable_shared_gems` (even to an empty or false value); `None` when
    /// no tier does. Callers already pass no `global_config` when the env
    /// tier sets `path.system` or `disable_shared_gems` (see
    /// [`global_path_config_unless_env_path_settings`]).
    async fn bundler_path_tier(
        cwd: &Path,
        bundle_path_env: Option<&OsStr>,
        path_system_env: Option<&OsStr>,
        app_config_env: Option<&OsStr>,
        global_config: Option<&Path>,
        ignore_config: bool,
    ) -> Option<BundlerPathTier> {
        if !ignore_config {
            let config = bundler_app_config_dir(cwd, app_config_env).join("config");
            if let Ok(text) = crate::utils::fs::read_regular_to_string(&config).await {
                if let Some(tier) = config_path_tier(&text) {
                    return Some(tier);
                }
            }
        }
        if bundle_path_env.is_some() || path_system_env.is_some() {
            return Some(BundlerPathTier {
                explicit_path: bundle_path_env.is_some(),
                system: path_system_env.is_some_and(|v| bundler_truthy(&v.to_string_lossy())),
            });
        }
        let global = global_config?;
        let text = crate::utils::fs::read_regular_to_string(global)
            .await
            .ok()?;
        config_path_tier(&text)
    }

    /// The `BUNDLE_PATH` recorded in bundler's app config file — the value
    /// `bundle config set --local path <dir>` writes. The file lives at
    /// `$BUNDLE_APP_CONFIG/config`, else `<cwd>/.bundle/config`, resolved by
    /// the shared [`bundler_app_config_dir`] rule.
    async fn app_config_bundle_path(
        cwd: &Path,
        app_config_env: Option<&OsStr>,
        ignore_config: bool,
        home: Option<&Path>,
    ) -> Option<String> {
        if ignore_config {
            return None;
        }
        let config = bundler_app_config_dir(cwd, app_config_env).join("config");
        // The config lives inside the (untrusted) project tree: a planted
        // FIFO would make a plain `read_to_string` open block forever
        // waiting for a writer, wedging scan (crawl_all) and apply/get
        // (find_by_purls path discovery). Read via `read_regular_to_string`
        // — non-blocking open on Unix, rejecting FIFOs/devices/directories
        // (see its docs) — same as the npm/composer/python crawlers.
        let contents = crate::utils::fs::read_regular_to_string(&config)
            .await
            .ok()?;
        bundle_config_dir_reading(
            parse_bundle_config_path(&contents),
            parse_legacy_bundle_config_path(&contents),
            |value| resolve_bundle_path(cwd, Path::new(value), home),
        )
        .await
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

    /// `gem env gemdir` and `gem env gempath`, asked once per process
    /// environment: a scan asks from the project fallback, the global
    /// paths, the hosted stale probe and rollback lookup — two ruby boots
    /// (100-400 ms) each time — and the answers are RubyGems configuration
    /// that nothing in a run changes. The memo is keyed on everything the
    /// subprocess inherits (the environment and working directory), so a
    /// caller that swaps `PATH` or `GEM_HOME` still asks afresh. Only a
    /// complete answer is kept: a failed ask (spawn error under fd pressure,
    /// a non-zero exit from a racing shim, empty output) is asked again by
    /// the next caller — and so is an answer the environment changed under,
    /// which the key would misfile.
    async fn gem_env_homes() -> GemEnvHomes {
        static MEMO: once_cell::sync::Lazy<GemEnvMemo> =
            once_cell::sync::Lazy::new(Default::default);
        let key = gem_env_key();
        let cell = gem_env_cell(&MEMO, key.clone());
        memoize_gem_env_homes(&cell, || async move {
            let homes = tokio::join!(Self::run_gem_env("gemdir"), Self::run_gem_env("gempath"));
            let env_unchanged = gem_env_key() == key;
            (homes, env_unchanged)
        })
        .await
    }

    /// Run `gem env <key>` (on the blocking pool — it waits on a
    /// subprocess) and return the trimmed stdout.
    async fn run_gem_env(key: &'static str) -> Option<String> {
        run_blocking(move || {
            let stdout = SystemCommandRunner.run("gem", &["env", key]);
            parse_gem_env_output(stdout.as_deref().unwrap_or(""))
        })
        .await
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

impl RubyCrawler {
    /// [`Self::find_by_purls`] for each of `purls` ON ITS OWN — element `i`
    /// is what `find_by_purls(gem_path, &[purls[i]])` returns for that PURL
    /// — as one blocking-pool task that lists `gem_path` at most once for
    /// the platform-suffix fallback (instead of once per PURL whose exact
    /// `<name>-<version>` dir does not verify).
    pub async fn find_each_by_purl(
        &self,
        gem_path: &Path,
        purls: &[String],
    ) -> Vec<Option<CrawledPackage>> {
        let gem_path = gem_path.to_path_buf();
        let purls = purls.to_vec();
        crate::utils::fs::run_blocking(move || {
            // `gem_path`'s entry names (lossy, readdir order), listed on
            // the first PURL that needs the prefix scan — and only kept
            // when the listing is the whole directory (`names_memoized`).
            let mut names: Option<Vec<String>> = None;
            purls
                .iter()
                .map(|purl| {
                    let (name, version) = crate::utils::purl::parse_gem_purl(purl)?;
                    let (name, version) = (name.as_ref(), version.as_ref());
                    if !is_safe_gem_coordinate(name, version) {
                        return None;
                    }
                    let gem_dir = locate_gem_dir_sync(&gem_path, name, version, &mut names)?;
                    Some(CrawledPackage {
                        name: name.to_string(),
                        version: version.to_string(),
                        namespace: None,
                        purl: purl.clone(),
                        path: gem_dir,
                    })
                })
                .collect()
        })
        .await
    }
}

/// Blocking twin of `RubyCrawler::locate_gem_dir` over a lazily listed,
/// reused `gem_path` listing.
fn locate_gem_dir_sync(
    gem_path: &Path,
    name: &str,
    version: &str,
    names: &mut Option<Vec<String>>,
) -> Option<PathBuf> {
    let exact = gem_path.join(format!("{name}-{version}"));
    if verify_gem_at_path_sync(&exact) {
        return Some(exact);
    }
    let prefix = format!("{name}-{version}-");
    let names = super::listing::names_memoized(gem_path, names);
    for dir_name in names.iter() {
        if dir_name.starts_with(&prefix) {
            let dir = gem_path.join(dir_name);
            if verify_gem_at_path_sync(&dir) {
                return Some(dir);
            }
        }
    }
    None
}

/// Blocking twin of `RubyCrawler::verify_gem_at_path`: a directory holding
/// `lib/` or a `.gemspec`.
fn verify_gem_at_path_sync(path: &Path) -> bool {
    use crate::utils::fs::is_dir_sync;
    if !is_dir_sync(path) {
        return false;
    }
    if is_dir_sync(&path.join("lib")) {
        return true;
    }
    super::listing::list_dir_sync(path).iter().any(|entry| {
        entry
            .name
            .to_str()
            .is_some_and(|name| name.ends_with(".gemspec"))
    })
}

/// Result of probing the Bundler install roots.
///
/// Public so CLI consumers (apply's store-class split, scan/apply's
/// config-skip advisory) can see what local-mode discovery decided; the
/// crawler itself stays print-free — surfacing the skip on stderr / the
/// JSON envelope is the CLI's job, where `--silent`/`--json` gating lives.
pub struct BundleStoreDiscovery {
    /// The discovered installed-gem `gems/` stores, in root-precedence
    /// order (local config > env > standalone `bundle/` > default
    /// `vendor/bundle`). Copies found
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
    /// The install root `skipped_config_path` resolves to (`~`
    /// expanded, relative values joined onto the project root, lexically
    /// normalized). Never a write target: only
    /// [`RubyCrawler::verification_only_gem_paths`] probes it, read-only.
    pub skipped_config_root: Option<PathBuf>,
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

/// `(gemdir, gempath)` as [`parse_gem_env_output`] reads each `gem env` answer.
type GemEnvHomes = (Option<String>, Option<String>);

/// What a `gem env` subprocess inherits: the (sorted) environment and the
/// working directory.
type GemEnvKey = (
    Vec<(std::ffi::OsString, std::ffi::OsString)>,
    Option<PathBuf>,
);

type GemEnvMemo =
    std::sync::Mutex<HashMap<GemEnvKey, std::sync::Arc<tokio::sync::OnceCell<GemEnvHomes>>>>;

fn gem_env_key() -> GemEnvKey {
    let mut vars: Vec<_> = std::env::vars_os().collect();
    vars.sort();
    (vars, std::env::current_dir().ok())
}

/// The memo cell for `key`, created empty on first sight.
fn gem_env_cell(
    memo: &GemEnvMemo,
    key: GemEnvKey,
) -> std::sync::Arc<tokio::sync::OnceCell<GemEnvHomes>> {
    let mut memo = memo.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    std::sync::Arc::clone(memo.entry(key).or_default())
}

/// The first caller runs `ask`; concurrent callers wait for its answer and
/// later ones reuse it — once it is complete (both homes answered) and
/// `ask` vouches it is keepable. Otherwise the asker gets its own answer and
/// the cell stays empty, so the next caller asks again. Split from
/// [`RubyCrawler::gem_env_homes`] so tests can count the asks against a cell
/// of their own.
async fn memoize_gem_env_homes<F, Fut>(
    cell: &tokio::sync::OnceCell<GemEnvHomes>,
    ask: F,
) -> GemEnvHomes
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = (GemEnvHomes, bool)>,
{
    let mut unkept = None;
    let slot = &mut unkept;
    let kept = cell
        .get_or_try_init(|| async move {
            let (homes, keepable) = ask().await;
            if keepable && homes.0.is_some() && homes.1.is_some() {
                Ok(homes)
            } else {
                *slot = Some(homes);
                Err(())
            }
        })
        .await;
    match kept {
        Ok(homes) => homes.clone(),
        Err(()) => unkept.expect("a refused ask leaves its answer"),
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

/// [`crate::formats::gem::manifest::classify`] for `root` on disk: the
/// manifest bundler loads, reading the ambient `BUNDLE_GEMFILE` /
/// `BUNDLE_LOCKFILE` / `BUNDLE_APP_CONFIG` and the app config file.
pub async fn bundler_loaded_manifest(root: &Path) -> crate::formats::gem::manifest::LoadedManifest {
    bundler_loaded_manifest_with_env(
        root,
        BundlerEnv {
            gemfile: std::env::var_os("BUNDLE_GEMFILE").as_deref(),
            lockfile: std::env::var_os("BUNDLE_LOCKFILE").as_deref(),
            app_config: std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
            ignore_config: bundler_ignores_config(),
            global_config: ambient_bundler_global_config_file(root).as_deref(),
        },
    )
    .await
}

/// The bundler environment [`bundler_loaded_manifest_with_env`] reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct BundlerEnv<'a> {
    /// `BUNDLE_GEMFILE`.
    pub gemfile: Option<&'a OsStr>,
    /// `BUNDLE_LOCKFILE` (bundler 4).
    pub lockfile: Option<&'a OsStr>,
    /// `BUNDLE_APP_CONFIG`.
    pub app_config: Option<&'a OsStr>,
    /// [`bundler_ignores_config`].
    pub ignore_config: bool,
    /// [`bundler_global_config_file`].
    pub global_config: Option<&'a Path>,
}

/// [`bundler_loaded_manifest`] for the project `view` shows. A disk view
/// (or a snapshot of one) reads the ambient environment and the app config
/// like bundler; a memory view has no environment, so only its own
/// `.bundle/config` counts (its `BUNDLE_GEMFILE` and bundler 4's
/// `BUNDLE_LOCKFILE`).
pub(crate) async fn bundler_loaded_manifest_in(
    view: &ProjectView<'_>,
) -> crate::formats::gem::manifest::LoadedManifest {
    use crate::formats::gem::manifest;
    match view {
        ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
            bundler_loaded_manifest(root).await
        }
        ProjectView::Memory(_) => {
            let config = view.read_text(".bundle/config").await.ok();
            let gemfile = config.as_deref().and_then(manifest::config_gemfile);
            let lockfile = config.as_deref().and_then(manifest::config_lockfile);
            let root = Path::new("/");
            manifest::classify(root, None, gemfile.as_deref(), None).with_lockfile(
                root,
                None,
                lockfile.as_deref(),
                None,
                view.is_file("gems.rb"),
            )
        }
    }
}

/// The ONE lockfile bundler reads for the project `view` shows: the lock of
/// [`LoadedManifest::pair`](crate::formats::gem::manifest::LoadedManifest::pair)
/// — `gems.locked` when the root holds a `gems.rb` file and nothing
/// configures `BUNDLE_GEMFILE`, else `Gemfile.lock` — or `None` when
/// `BUNDLE_GEMFILE` names a manifest outside the two default pairs, or
/// bundler 4's `BUNDLE_LOCKFILE` names a lock other than the pair's own
/// (#749). A `Gemfile` + `gems.rb` twin under default discovery follows
/// [`default_twin_manifest`](crate::formats::gem::manifest::default_twin_manifest):
/// `Gemfile.lock` when its locks say bundler 1.x wrote them, `None` when
/// they disagree on the major (#751). Every lock READER asks this (lock
/// inventory, ledger recovery, VEX discovery), so none reads a twin
/// bundler ignores (#736).
pub(crate) async fn bundler_loaded_lock_in(view: &ProjectView<'_>) -> Option<&'static str> {
    bundler_loaded_lock_diagnosed_in(view).await.ok()
}

/// [`bundler_loaded_lock_in`], with the reason when bundler loads no lock
/// socket-patch reads: the detail of the unsupported `BUNDLE_GEMFILE` /
/// `BUNDLE_LOCKFILE`, or of the twin whose locks disagree on the bundler
/// major. Lock inventory surfaces it so a lockfile-only scan does not
/// skip the project's gems silently.
pub(crate) async fn bundler_loaded_lock_diagnosed_in(
    view: &ProjectView<'_>,
) -> Result<&'static str, String> {
    use crate::formats::gem::manifest::{self, LoadedManifest};
    let loaded = bundler_loaded_manifest_in(view).await;
    let gems_rb = view.is_file("gems.rb");
    if loaded == LoadedManifest::Default && gems_rb && view.is_file("Gemfile") {
        let gemfile_lock = view.read_text("Gemfile.lock").await.ok();
        let gems_locked = view.read_text("gems.locked").await.ok();
        return match manifest::default_twin_manifest(
            gemfile_lock.as_deref(),
            gems_locked.as_deref(),
        )? {
            "Gemfile" => Ok("Gemfile.lock"),
            _ => Ok("gems.locked"),
        };
    }
    match loaded.pair(gems_rb) {
        Some((_, lock)) => Ok(lock),
        None => Err(loaded.unsupported_detail().unwrap_or_default()),
    }
}

/// [`bundler_loaded_manifest`] with the environment passed explicitly (hermetic
/// tests).
pub async fn bundler_loaded_manifest_with_env(
    root: &Path,
    env: BundlerEnv<'_>,
) -> crate::formats::gem::manifest::LoadedManifest {
    use crate::formats::gem::manifest;
    let config = read_app_config(root, env.app_config, env.ignore_config).await;
    let config = config.as_deref();
    let gemfile = config.and_then(manifest::config_gemfile);
    let lockfile = config.and_then(manifest::config_lockfile);
    let gems_rb_present = tokio::fs::symlink_metadata(root.join("gems.rb"))
        .await
        .is_ok();
    let global = read_global_config(env.global_config, env.ignore_config).await;
    let global = global.as_deref();
    manifest::classify(
        root,
        env.gemfile,
        gemfile.as_deref(),
        global.and_then(manifest::config_gemfile).as_deref(),
    )
    .with_lockfile(
        root,
        env.lockfile,
        lockfile.as_deref(),
        global.and_then(manifest::config_lockfile).as_deref(),
        gems_rb_present,
    )
}

/// The Bundler mirror setting that captures one of the patch-registry
/// `sources` (see [`crate::formats::gem::mirror`]), described for the
/// refusal's detail. Reads the app config (honoring `BUNDLE_APP_CONFIG`
/// and `BUNDLE_IGNORE_CONFIG`) and ambient `BUNDLE_MIRROR__...` settings.
pub async fn bundler_source_mirror(
    root: &Path,
    sources: &[&str],
) -> Option<crate::formats::gem::mirror::MirrorCapture> {
    let environment: Vec<_> = std::env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            if !key.starts_with("BUNDLE_MIRROR__") {
                return None;
            }
            Some((key, value.into_string().ok()?))
        })
        .collect();
    let mirrors: Vec<_> = environment
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    bundler_source_mirror_with_env(
        root,
        sources,
        &mirrors,
        std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
        bundler_ignores_config(),
    )
    .await
}

/// [`bundler_source_mirror`] with the environment passed explicitly
/// (hermetic tests).
pub async fn bundler_source_mirror_with_env(
    root: &Path,
    sources: &[&str],
    mirror_environment: &[(&str, &str)],
    app_config_env: Option<&OsStr>,
    ignore_config: bool,
) -> Option<crate::formats::gem::mirror::MirrorCapture> {
    let config = read_app_config(root, app_config_env, ignore_config).await;
    crate::formats::gem::mirror::capturing_mirror(config.as_deref(), mirror_environment, sources)
}

/// Whether bundler skips its config files: `Bundler::Settings#ignore_config?`
/// is `ENV["BUNDLE_IGNORE_CONFIG"]`, so any value set (even an empty one)
/// switches them off and every setting comes from the environment alone.
pub(crate) fn bundler_ignores_config() -> bool {
    std::env::var_os("BUNDLE_IGNORE_CONFIG").is_some()
}

/// The app config file's text (`$BUNDLE_APP_CONFIG/config`, else
/// `<root>/.bundle/config`), or `None` when it is missing, unreadable, or
/// `ignore_config` is set — bundler's `load_config` then returns `{}`.
async fn read_app_config(
    root: &Path,
    app_config_env: Option<&OsStr>,
    ignore_config: bool,
) -> Option<String> {
    if ignore_config {
        return None;
    }
    let config = bundler_app_config_dir(root, app_config_env).join("config");
    crate::utils::fs::read_regular_to_string(&config).await.ok()
}

/// The global config file's text (see [`bundler_global_config_file`]), or
/// `None` when there is none, it is missing or unreadable, or
/// `ignore_config` is set (bundler's `load_config` skips every file then).
async fn read_global_config(global_config: Option<&Path>, ignore_config: bool) -> Option<String> {
    if ignore_config {
        return None;
    }
    crate::utils::fs::read_regular_to_string(global_config?)
        .await
        .ok()
}

/// Bundler's global (per-user) config file, following
/// `Bundler::Settings#global_config_file` exactly: `$BUNDLE_CONFIG`, else
/// `$BUNDLE_USER_CONFIG`, else `$BUNDLE_USER_HOME/config`, else
/// `~/.bundle/config` (each env value only when non-empty). This is the
/// file `bundle config set --global …` writes, and bundler consults it
/// BELOW the local app config and the environment (`Bundler::Settings`
/// priority: local → env → global → default). A relative value is read
/// against the project root, where bundler runs.
///
/// Unlike the app config file it is the user's own machine state, not
/// project input, so its values are trusted like the environment.
pub(crate) fn bundler_global_config_file(
    root: &Path,
    bundle_config_env: Option<&OsStr>,
    user_config_env: Option<&OsStr>,
    user_home_env: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    let non_empty = |v: Option<&OsStr>| v.filter(|v| !v.is_empty()).map(PathBuf::from);
    let file = non_empty(bundle_config_env)
        .or_else(|| non_empty(user_config_env))
        .or_else(|| non_empty(user_home_env).map(|h| h.join("config")))
        .or_else(|| non_empty(home).map(|h| h.join(".bundle").join("config")))?;
    Some(if file.is_absolute() {
        file
    } else {
        root.join(file)
    })
}

/// [`ambient_bundler_global_config_file`], or `None` under
/// `BUNDLE_IGNORE_CONFIG` or when the environment sets `path.system` or
/// `disable_shared_gems` — for the install-root probe, which takes no
/// `ignore_config` flag of its own.
fn ambient_global_config_unless_ignored(root: &Path) -> Option<PathBuf> {
    if bundler_ignores_config() {
        None
    } else {
        global_path_config_unless_env_path_settings(
            ambient_bundler_global_config_file(root),
            std::env::var_os("BUNDLE_PATH__SYSTEM").as_deref(),
            std::env::var_os("BUNDLE_DISABLE_SHARED_GEMS").as_deref(),
        )
    }
}

/// The global config file for the install-root probe, or `None` when the
/// env tier sets `path.system` or `disable_shared_gems`. Bundler's
/// `Settings#path` stops at the first tier that sets either flag or `path`,
/// and the env tier sits above the global one, so any flag value (even
/// `"false"` or empty) shadows a global `path` — the env `BUNDLE_PATH` part
/// of that rule is applied in [`RubyCrawler::discover_bundle_stores_impl`].
fn global_path_config_unless_env_path_settings(
    global_config: Option<PathBuf>,
    path_system_env: Option<&OsStr>,
    disable_shared_gems_env: Option<&OsStr>,
) -> Option<PathBuf> {
    if path_system_env.is_some() || disable_shared_gems_env.is_some() {
        None
    } else {
        global_config
    }
}

/// The ambient `BUNDLE_PATH__SYSTEM` (Bundler's env-tier `path.system`).
fn ambient_path_system_env() -> Option<std::ffi::OsString> {
    std::env::var_os("BUNDLE_PATH__SYSTEM")
}

/// Bundler's boolean coercion for a setting value (`Settings#to_bool`):
/// `false`, `f`, `no`, `n`, `0` (any case) and the empty string are
/// false, everything else is true.
pub(crate) fn bundler_truthy(value: &str) -> bool {
    !matches!(
        value.to_ascii_lowercase().as_str(),
        "false" | "f" | "no" | "n" | "0" | ""
    )
}

/// [`bundler_global_config_file`] for the ambient environment.
pub(crate) fn ambient_bundler_global_config_file(root: &Path) -> Option<PathBuf> {
    bundler_global_config_file(
        root,
        std::env::var_os("BUNDLE_CONFIG").as_deref(),
        std::env::var_os("BUNDLE_USER_CONFIG").as_deref(),
        std::env::var_os("BUNDLE_USER_HOME").as_deref(),
        ambient_home().as_deref(),
    )
}

/// Bundler's app-config dir for `root`, following `Bundler.app_config_path`
/// exactly: `$BUNDLE_APP_CONFIG` when set (a relative value resolves against
/// the project root, NOT the process cwd), else `<root>/.bundle` — e.g. the
/// official ruby Docker images export `BUNDLE_APP_CONFIG=/usr/local/bundle`.
/// A set-but-empty value is truthy in Ruby and selects `<root>/config`.
pub(crate) fn bundler_app_config_dir(root: &Path, env_value: Option<&OsStr>) -> PathBuf {
    match env_value {
        Some(v) => {
            let p = PathBuf::from(v);
            if p.is_absolute() {
                p
            } else {
                root.join(p)
            }
        }
        None => root.join(".bundle"),
    }
}

/// Bundler's app cache dir for `root` — where `bundle cache` writes and
/// `bundle install` installs from in preference to fetching
/// (`Bundler.app_cache`: `<root>/<cache_path>`, default `vendor/cache`).
/// Reads the ambient `BUNDLE_CACHE_PATH` / `BUNDLE_APP_CONFIG`.
pub async fn bundler_app_cache_dir(root: &Path) -> PathBuf {
    bundler_app_cache_dir_with_env(
        root,
        std::env::var_os("BUNDLE_CACHE_PATH").as_deref(),
        std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
        bundler_ignores_config(),
        ambient_bundler_global_config_file(root).as_deref(),
    )
    .await
}

/// [`bundler_app_cache_dir`] with the environment passed explicitly
/// (hermetic tests). The `cache_path` setting follows `Bundler::Settings`
/// priority like every other key: the app config file's
/// `BUNDLE_CACHE_PATH:` (`bundle config set --local cache_path …`) first,
/// then the `BUNDLE_CACHE_PATH` environment variable, then the global
/// config file's `BUNDLE_CACHE_PATH:` (`bundle config set --global
/// cache_path …`, see [`bundler_global_config_file`]). A relative value is
/// read against the project root; an absolute one stands alone (bundler
/// `Pathname#join`s it onto the root). The result is only ever READ (a
/// committed archive is hashed and named in a warning), so unlike a
/// config-sourced `BUNDLE_PATH` it needs no containment: a value that
/// points outside the project names exactly the file bundler installs from.
/// With `ignore_config` ([`bundler_ignores_config`]) both files are skipped
/// and only the environment and the default count.
pub async fn bundler_app_cache_dir_with_env(
    root: &Path,
    cache_env: Option<&OsStr>,
    app_config_env: Option<&OsStr>,
    ignore_config: bool,
    global_config: Option<&Path>,
) -> PathBuf {
    // Component-wise, so `vendor/gems` uses the native separator.
    let resolve = |value: PathBuf| root.join(normalize_lexically(&value).unwrap_or(value));
    let cache_path = |text: Option<String>| async {
        let text = text?;
        bundle_config_dir_reading(
            bundle_config_setting(&text, "BUNDLE_CACHE_PATH"),
            legacy_bundle_config_setting(&text, "BUNDLE_CACHE_PATH"),
            |value| resolve(PathBuf::from(value)),
        )
        .await
        .map(PathBuf::from)
    };
    let mut configured = cache_path(read_app_config(root, app_config_env, ignore_config).await)
        .await
        .or_else(|| cache_env.filter(|v| !v.is_empty()).map(PathBuf::from));
    if configured.is_none() {
        configured = cache_path(read_global_config(global_config, ignore_config).await).await;
    }
    match configured {
        Some(value) => resolve(value),
        None => root.join("vendor").join("cache"),
    }
}

/// Resolve a trusted (ENV-sourced) `BUNDLE_PATH` value against the project
/// root. Bundler `File.expand_path`s the value: a leading `~` expands to
/// the user's home, and a relative path resolves against the directory of
/// the Gemfile (`Bundler.root`), not the process cwd — the same rule
/// [`bundler_app_config_dir`] follows for
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
/// `install-path` guard. Out-of-tree bundle paths stay reachable via the
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
/// to the `gem env` homes, which is exactly where those gems live. The flag
/// goes through Bundler's own coercion ([`bundler_truthy`]), so `"1"` or
/// `"yes"` count too, while `"false"` leaves the recorded path in effect.
fn parse_bundle_config_path(contents: &str) -> Option<String> {
    parse_bundle_config_path_with(contents, unquote_bundle_config_value)
}

/// [`parse_bundle_config_path`] as a Bundler before 2.5.6 reads it (see
/// [`unquote_legacy_bundle_config_value`]).
fn parse_legacy_bundle_config_path(contents: &str) -> Option<String> {
    parse_bundle_config_path_with(contents, unquote_legacy_bundle_config_value)
}

fn parse_bundle_config_path_with(contents: &str, unquote: fn(&str) -> &str) -> Option<String> {
    let mut path: Option<String> = None;
    let mut path_system = false;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("BUNDLE_PATH:") {
            let v = unquote(rest);
            if !v.is_empty() {
                path = Some(v.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("BUNDLE_PATH__SYSTEM:") {
            path_system = bundler_truthy(unquote(rest));
        }
    }
    if path_system {
        None
    } else {
        path
    }
}

/// The part of Bundler's `Settings::Path` the crawler needs from the tier
/// that decides the install path.
#[derive(Debug, Clone, Copy)]
struct BundlerPathTier {
    /// The tier sets `path`, even to an empty string (`explicit_path`).
    explicit_path: bool,
    /// The tier's `path.system` is truthy (`system_path`).
    system: bool,
}

/// For one Bundler config file: `None` when it sets none of `path`,
/// `path.system` and `disable_shared_gems` (Bundler reads on to the next
/// tier), else what it says about the path.
fn config_path_tier(contents: &str) -> Option<BundlerPathTier> {
    let sets_path = [
        "BUNDLE_PATH",
        "BUNDLE_PATH__SYSTEM",
        "BUNDLE_DISABLE_SHARED_GEMS",
    ]
    .iter()
    .any(|key| bundle_config_setting_including_empty(contents, key).is_some());
    sets_path.then(|| BundlerPathTier {
        explicit_path: bundle_config_setting_including_empty(contents, "BUNDLE_PATH").is_some(),
        system: bundle_config_setting_including_empty(contents, "BUNDLE_PATH__SYSTEM")
            .is_some_and(|v| bundler_truthy(&v)),
    })
}

/// The effective `<key>:` value of a bundler app config file (flat YAML
/// that bundler writes itself, `---\nBUNDLE_GEMFILE: "Gemfile.next"\n`):
/// the last entry for the exact key wins, quotes are unwrapped, and an
/// empty value counts as unset. The colon must follow the key directly, so
/// `BUNDLE_PATH__SYSTEM:` never matches `BUNDLE_PATH`.
pub(crate) fn bundle_config_setting(contents: &str, key: &str) -> Option<String> {
    bundle_config_setting_including_empty(contents, key).filter(|value| !value.is_empty())
}

/// Like [`bundle_config_setting`], but retains an explicitly empty string:
/// Bundler's setting tiers stop at a present value even when it names no
/// path. Callers that decide whether a lower tier applies need presence,
/// not just a non-empty value.
pub(crate) fn bundle_config_setting_including_empty(contents: &str, key: &str) -> Option<String> {
    bundle_config_setting_with(contents, key, unquote_bundle_config_value)
}

/// [`bundle_config_setting`] as a Bundler before 2.5.6 reads it (see
/// [`unquote_legacy_bundle_config_value`]).
fn legacy_bundle_config_setting(contents: &str, key: &str) -> Option<String> {
    bundle_config_setting_with(contents, key, unquote_legacy_bundle_config_value)
        .filter(|value| !value.is_empty())
}

fn bundle_config_setting_with(
    contents: &str,
    key: &str,
    unquote: fn(&str) -> &str,
) -> Option<String> {
    let mut found = None;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix(key).and_then(|r| r.strip_prefix(':')) {
            found = Some(unquote(rest).to_string());
        }
    }
    found
}

/// Unwrap one bundler app-config scalar the way Bundler's config loader
/// does (`Gem::YAMLSerializer`, RubyGems 3.5.6+, which Bundler 2.4+ uses
/// when present; Bundler's own copy from 2.5.6): trim, strip one matching
/// pair of double or single quotes (bundler double-quotes what it writes),
/// then `strip_comment` — cut the value at its first `#` and trim, unless
/// it starts with `#` (#951). The quote pair must close the line, so
/// `"vendor/bundle" # note` keeps its quotes, as it does for Bundler.
pub(crate) fn unquote_bundle_config_value(rest: &str) -> &str {
    let v = rest.trim();
    strip_bundle_config_comment(unquote_matching_pair(v).unwrap_or(v))
}

/// [`unquote_bundle_config_value`] for the loader Bundler used before
/// `strip_comment` (Bundler < 2.4, or 2.4–2.5.5 on RubyGems < 3.5.6): the
/// `# comment` stays part of the value.
fn unquote_legacy_bundle_config_value(rest: &str) -> &str {
    let v = rest.trim();
    unquote_matching_pair(v).unwrap_or(v)
}

fn unquote_matching_pair(v: &str) -> Option<&str> {
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
}

/// Bundler's `YAMLSerializer#strip_comment`.
fn strip_bundle_config_comment(v: &str) -> &str {
    match v.split_once('#') {
        Some((value, _)) if !v.starts_with('#') => value.trim(),
        _ => v,
    }
}

/// A directory setting whose value carries a `# comment` reads differently
/// in the two Bundler config-loader eras (see
/// [`unquote_legacy_bundle_config_value`]), and the installed Bundler's era
/// is not known here. Bundler creates the directory it uses, so take the
/// current reading unless only the legacy reading's directory exists.
/// Values without a comment read the same in both eras.
///
/// Only two directory readings are weighed against each other. When the
/// current reading is unset — e.g. a commented `path.system: true` that
/// only the current loader honours — the legacy path's directory is no
/// evidence of the era (it may be a leftover install, the #915 shape), so
/// the current reading stands.
async fn bundle_config_dir_reading(
    current: Option<String>,
    legacy: Option<String>,
    resolve: impl Fn(&str) -> PathBuf,
) -> Option<String> {
    let (Some(value), Some(legacy)) = (current.as_deref(), legacy) else {
        return current;
    };
    if value == legacy {
        return current;
    }
    let is_dir = |path: PathBuf| async move {
        tokio::fs::metadata(path)
            .await
            .is_ok_and(|meta| meta.is_dir())
    };
    if !is_dir(resolve(value)).await && is_dir(resolve(&legacy)).await {
        Some(legacy)
    } else {
        current
    }
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

    #[tokio::test]
    async fn loaded_manifest_reads_the_app_config_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bundle")).unwrap();
        std::fs::write(
            dir.path().join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n",
        )
        .unwrap();
        let m = bundler_loaded_manifest_with_env(dir.path(), BundlerEnv::default()).await;
        assert!(matches!(
            m,
            crate::formats::gem::manifest::LoadedManifest::Unsupported {
                by: crate::formats::gem::manifest::GemfileSetting::AppConfig,
                ..
            }
        ));
        // BUNDLE_APP_CONFIG moves the config file away from `.bundle`.
        let m = bundler_loaded_manifest_with_env(
            dir.path(),
            BundlerEnv {
                app_config: Some(std::ffi::OsStr::new("elsewhere")),
                ..BundlerEnv::default()
            },
        )
        .await;
        assert_eq!(m, crate::formats::gem::manifest::LoadedManifest::Default);
        // BUNDLE_IGNORE_CONFIG: bundler reads no config file at all.
        let m = bundler_loaded_manifest_with_env(
            dir.path(),
            BundlerEnv {
                ignore_config: true,
                ..BundlerEnv::default()
            },
        )
        .await;
        assert_eq!(m, crate::formats::gem::manifest::LoadedManifest::Default);
    }

    /// #507: a committed `bundle config set --local gemfile Gemfile.next`
    /// beats an exported `BUNDLE_GEMFILE=Gemfile`, as in bundler, so the run
    /// refuses instead of wiring the `Gemfile` bundler ignores.
    #[tokio::test]
    async fn loaded_manifest_app_config_beats_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bundle")).unwrap();
        std::fs::write(
            dir.path().join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n",
        )
        .unwrap();
        let m = bundler_loaded_manifest_with_env(
            dir.path(),
            BundlerEnv {
                gemfile: Some(std::ffi::OsStr::new("Gemfile")),
                ..BundlerEnv::default()
            },
        )
        .await;
        assert_eq!(
            m,
            crate::formats::gem::manifest::LoadedManifest::Unsupported {
                value: "Gemfile.next".into(),
                by: crate::formats::gem::manifest::GemfileSetting::AppConfig,
            }
        );
    }

    /// #749: bundler 4's configured lockfile (`BUNDLE_LOCKFILE`, the
    /// environment first, then the app config) naming anything but the
    /// loaded pair's own lock is unsupported; naming that lock is a no-op.
    #[tokio::test]
    async fn loaded_manifest_reads_the_lockfile_setting() {
        use crate::formats::gem::manifest::{GemfileSetting, LoadedManifest};
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bundle")).unwrap();
        let config = |value: &str| {
            std::fs::write(
                dir.path().join(".bundle/config"),
                format!("---\nBUNDLE_LOCKFILE: \"{value}\"\n"),
            )
            .unwrap()
        };
        config("custom.lock");
        let m = bundler_loaded_manifest_with_env(dir.path(), BundlerEnv::default()).await;
        assert_eq!(
            m,
            LoadedManifest::UnsupportedLockfile {
                value: "custom.lock".into(),
                by: GemfileSetting::AppConfig
            }
        );
        assert_eq!(m.pair(false), None);
        // The environment wins over the app config, as in `Bundler::CLI`.
        let m = bundler_loaded_manifest_with_env(
            dir.path(),
            BundlerEnv {
                lockfile: Some(std::ffi::OsStr::new("Gemfile.lock")),
                ..BundlerEnv::default()
            },
        )
        .await;
        assert_eq!(m, LoadedManifest::Default);
        let m = bundler_loaded_manifest_with_env(
            dir.path(),
            BundlerEnv {
                lockfile: Some(std::ffi::OsStr::new("other.lock")),
                ..BundlerEnv::default()
            },
        )
        .await;
        assert!(matches!(
            m,
            LoadedManifest::UnsupportedLockfile {
                by: GemfileSetting::Env,
                ..
            }
        ));
        // BUNDLE_IGNORE_CONFIG drops the app config value.
        let m = bundler_loaded_manifest_with_env(
            dir.path(),
            BundlerEnv {
                ignore_config: true,
                ..BundlerEnv::default()
            },
        )
        .await;
        assert_eq!(m, LoadedManifest::Default);
        // The default lock of the pair bundler loads is a no-op; with a
        // gems.rb, that lock is gems.locked, not Gemfile.lock.
        config("Gemfile.lock");
        let m = bundler_loaded_manifest_with_env(dir.path(), BundlerEnv::default()).await;
        assert_eq!(m, LoadedManifest::Default);
        std::fs::write(dir.path().join("gems.rb"), "").unwrap();
        let m = bundler_loaded_manifest_with_env(dir.path(), BundlerEnv::default()).await;
        assert!(matches!(m, LoadedManifest::UnsupportedLockfile { .. }));
        config("./gems.locked");
        let m = bundler_loaded_manifest_with_env(dir.path(), BundlerEnv::default()).await;
        assert_eq!(m, LoadedManifest::Default);
    }

    /// #483: bundler's cache dir is the `cache_path` setting — the app
    /// config value first, then `BUNDLE_CACHE_PATH`, else `vendor/cache`.
    #[tokio::test]
    async fn app_cache_dir_follows_bundler_settings_priority() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let default = root.join("vendor").join("cache");
        assert_eq!(
            bundler_app_cache_dir_with_env(root, None, None, false, None).await,
            default
        );
        // The environment alone moves it.
        let env = std::ffi::OsStr::new("vendor/env-gems");
        assert_eq!(
            bundler_app_cache_dir_with_env(root, Some(env), None, false, None).await,
            root.join("vendor").join("env-gems")
        );
        // An empty value is unset.
        assert_eq!(
            bundler_app_cache_dir_with_env(root, Some(std::ffi::OsStr::new("")), None, false, None)
                .await,
            default
        );
        // `bundle config set --local cache_path vendor/gems` outranks it.
        std::fs::create_dir(root.join(".bundle")).unwrap();
        std::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_CACHE_PATH: \"vendor/gems\"\n",
        )
        .unwrap();
        let configured = root.join("vendor").join("gems");
        assert_eq!(
            bundler_app_cache_dir_with_env(root, None, None, false, None).await,
            configured
        );
        assert_eq!(
            bundler_app_cache_dir_with_env(root, Some(env), None, false, None).await,
            configured
        );
        // BUNDLE_APP_CONFIG moves the config file: the env value applies.
        assert_eq!(
            bundler_app_cache_dir_with_env(
                root,
                Some(env),
                Some(std::ffi::OsStr::new("elsewhere")),
                false,
                None,
            )
            .await,
            root.join("vendor").join("env-gems")
        );
        // BUNDLE_IGNORE_CONFIG skips the file: the env value, else the default.
        assert_eq!(
            bundler_app_cache_dir_with_env(root, Some(env), None, true, None).await,
            root.join("vendor").join("env-gems")
        );
        assert_eq!(
            bundler_app_cache_dir_with_env(root, None, None, true, None).await,
            default
        );
        // An absolute value stands alone.
        let abs = root.join("shared-cache");
        std::fs::write(
            root.join(".bundle/config"),
            format!("---\nBUNDLE_CACHE_PATH: \"{}\"\n", abs.display()),
        )
        .unwrap();
        assert_eq!(
            bundler_app_cache_dir_with_env(root, None, None, false, None).await,
            abs
        );
    }

    /// The app-config path/ignore controls apply equally to all mirror forms.
    #[tokio::test]
    async fn source_mirror_reads_the_app_config_and_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let src = ["https://patch.test/gem/tok/uuid/"];
        assert_eq!(
            bundler_source_mirror_with_env(dir.path(), &src, &[], None, false).await,
            None
        );
        std::fs::create_dir(dir.path().join(".bundle")).unwrap();
        for key in [
            "BUNDLE_MIRROR__ALL",
            "BUNDLE_MIRROR__PATCH__TEST",
            "BUNDLE_MIRROR__HTTPS://PATCH__TEST/GEM/TOK/UUID/",
        ] {
            std::fs::write(
                dir.path().join(".bundle/config"),
                format!("---\n{key}: \"https://m.example/\"\n"),
            )
            .unwrap();
            let local = bundler_source_mirror_with_env(dir.path(), &src, &[], None, false)
                .await
                .unwrap();
            assert!(local.setting.contains("project's Bundler config"));
            assert_eq!(
                bundler_source_mirror_with_env(dir.path(), &src, &[], None, true).await,
                None
            );
            let env = [(key, "https://env.example/")];
            let capture = bundler_source_mirror_with_env(dir.path(), &src, &env, None, true)
                .await
                .unwrap();
            assert!(capture.setting.contains("environment"));
            assert_eq!(
                bundler_source_mirror_with_env(
                    dir.path(),
                    &src,
                    &[],
                    Some(OsStr::new("elsewhere")),
                    false
                )
                .await,
                None
            );
        }
        std::fs::create_dir(dir.path().join("elsewhere")).unwrap();
        std::fs::write(
            dir.path().join("elsewhere/config"),
            "BUNDLE_MIRROR__PATCH__TEST: \"https://m.example/\"\n",
        )
        .unwrap();
        assert!(bundler_source_mirror_with_env(
            dir.path(),
            &src,
            &[],
            Some(OsStr::new("elsewhere")),
            false
        )
        .await
        .is_some());
    }

    /// Ruby treats an empty BUNDLE_APP_CONFIG as set: config lives directly
    /// in the project root, and the usual .bundle/config must not shadow it.
    #[tokio::test]
    async fn empty_app_config_selects_root_config_and_respects_ignore() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let src = ["https://patch.test/gem/tok/uuid/"];
        std::fs::create_dir(root.join(".bundle")).unwrap();
        let capture = "BUNDLE_MIRROR__ALL: \"https://mirror.example/\"\n";
        let scoped = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: \"https://mirror.example/\"\n";
        for root_captures in [true, false] {
            let (root_config, usual_config) = if root_captures {
                (capture, scoped)
            } else {
                (scoped, capture)
            };
            std::fs::write(root.join("config"), root_config).unwrap();
            std::fs::write(root.join(".bundle/config"), usual_config).unwrap();
            assert_eq!(
                bundler_source_mirror_with_env(root, &src, &[], Some(OsStr::new("")), false)
                    .await
                    .is_some(),
                root_captures
            );
            assert_eq!(
                bundler_source_mirror_with_env(root, &src, &[], None, false)
                    .await
                    .is_some(),
                !root_captures
            );
            assert!(
                bundler_source_mirror_with_env(root, &src, &[], Some(OsStr::new("")), true)
                    .await
                    .is_none()
            );
            assert!(bundler_source_mirror_with_env(
                root,
                &src,
                &[("BUNDLE_MIRROR__ALL", "https://env.example/")],
                Some(OsStr::new("")),
                true
            )
            .await
            .is_some());
        }
        // Existing manifest/cache consumers share the same config location.
        std::fs::write(
            root.join("config"),
            "BUNDLE_GEMFILE: \"Gemfile.next\"\nBUNDLE_CACHE_PATH: \"root-cache\"\n",
        )
        .unwrap();
        assert!(matches!(
            bundler_loaded_manifest_with_env(
                root,
                BundlerEnv {
                    app_config: Some(OsStr::new("")),
                    ..BundlerEnv::default()
                }
            )
            .await,
            crate::formats::gem::manifest::LoadedManifest::Unsupported { .. }
        ));
        assert_eq!(
            bundler_app_cache_dir_with_env(root, None, Some(OsStr::new("")), false, None).await,
            root.join("root-cache")
        );
        assert_eq!(bundler_app_config_dir(root, Some(OsStr::new(""))), root);
        assert_eq!(bundler_app_config_dir(root, None), root.join(".bundle"));
    }

    #[test]
    fn bundle_config_setting_matches_the_exact_key() {
        let text = "---\nBUNDLE_PATH__SYSTEM: \"true\"\nBUNDLE_PATH: 'vendor/bundle'\n\
                    BUNDLE_CACHE_PATH: \"\"\n";
        assert_eq!(
            bundle_config_setting(text, "BUNDLE_PATH"),
            Some("vendor/bundle".into())
        );
        assert_eq!(bundle_config_setting(text, "BUNDLE_CACHE_PATH"), None);
        assert_eq!(bundle_config_setting(text, "BUNDLE_GEMFILE"), None);
    }

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

    // ── bundler-1 flat BUNDLE_PATH layout ─────

    /// Bundler 1 with `BUNDLE_PATH` set via the ENVIRONMENT installs
    /// GEM_HOME-style into the flat `<BUNDLE_PATH>/gems/` — no
    /// `<engine>/<abi>` scope segment, sibling `specifications/` dir
    /// present (bundler >= 2 appends the scope even for env installs),
    /// e.g. activestorage@6.0.3 under bundler 1.17.3 at
    /// `vendor/bundle/gems/activestorage-6.0.3`. Enumerating only the
    /// scoped layout would scan such projects as `notInstalled`.
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
    /// consumers pick the copy bundler actually loads.
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

    // ── `bundle install --standalone` root (#796) ─────

    /// Lay down what `bundle install --standalone` leaves in `<cwd>/bundle`:
    /// the scoped `ruby/<abi>/gems/<leaf>` store plus the
    /// `bundler/setup.rb` load-path script the app requires. Returns the
    /// `gems/` store dir.
    async fn stage_standalone_bundle(cwd: &Path, leaf: &str) -> PathBuf {
        let root = cwd.join("bundle");
        let gems = root.join("ruby").join("3.3.0").join("gems");
        tokio::fs::create_dir_all(gems.join(leaf).join("lib"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(root.join("bundler"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join("bundler").join("setup.rb"),
            "require 'rbconfig'\n$:.unshift File.expand_path(\"#{__dir__}/../#{RUBY_ENGINE}/#{Gem.ruby_api_version}/gems/rack-3.2.7/lib\")\n",
        )
        .await
        .unwrap();
        gems
    }

    /// Bundler 4 no longer remembers CLI flags, so `bundle install
    /// --standalone` writes NO `.bundle/config` — the `./bundle` tree is
    /// marked only by its `bundler/setup.rb`. Discovery must still find
    /// it: it is the tree the app loads (#796).
    #[tokio::test]
    async fn standalone_bundle_root_discovered_without_config() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"rack\"\n")
            .await
            .unwrap();
        let gems = stage_standalone_bundle(dir.path(), "rack-3.2.7").await;

        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None).await;
        assert_eq!(
            discovery.stores,
            vec![gems],
            "standalone store must be discovered"
        );
        // Same class as bundler 2's recorded `BUNDLE_PATH: "bundle"`: an
        // explicit project root, which keeps the `gem env` fallback (the
        // default gems live there), not the implicit vendor/bundle one.
        assert!(!discovery.default_root_has_stores);
    }

    /// Without the `bundler/setup.rb` marker a `bundle/` dir is just a
    /// project directory (a script folder, a frontend bundle output) and
    /// must not be crawled — or patched — as a gem store.
    #[tokio::test]
    async fn bundle_dir_without_standalone_marker_is_not_a_store() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"rack\"\n")
            .await
            .unwrap();
        let gems = stage_standalone_bundle(dir.path(), "rack-3.2.7").await;
        tokio::fs::remove_file(dir.path().join("bundle").join("bundler").join("setup.rb"))
            .await
            .unwrap();
        assert!(gems.is_dir());

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert!(paths.is_empty(), "no marker, no store; got {paths:?}");
    }

    /// The standalone probe sits behind the same "looks like a Ruby
    /// project" gate as the other explicit roots.
    #[tokio::test]
    async fn standalone_bundle_root_ignored_without_manifest() {
        let dir = tempfile::tempdir().unwrap();
        stage_standalone_bundle(dir.path(), "rack-3.2.7").await;

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert!(
            paths.is_empty(),
            "no Bundler manifest, no store; got {paths:?}"
        );
    }

    /// Bundler 2 records `BUNDLE_PATH: "bundle"` for a standalone install,
    /// so the config root and the standalone probe name the same tree: it
    /// must be scanned (and patched) once.
    #[tokio::test]
    async fn standalone_bundle_root_dedups_with_bundler2_config_path() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"rack\"\n")
            .await
            .unwrap();
        let gems = stage_standalone_bundle(dir.path(), "rack-3.2.7").await;
        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"bundle\"\n",
        )
        .await
        .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert_eq!(paths, vec![gems]);
    }

    /// The standalone tree ranks after the explicit config/env roots and
    /// before the implicit `vendor/bundle` default.
    #[tokio::test]
    async fn standalone_bundle_root_probes_between_env_and_default() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"rack\"\n")
            .await
            .unwrap();
        let standalone = stage_standalone_bundle(dir.path(), "rack-3.2.7").await;
        let env_root = dir.path().join("envstore");
        let env_gems = env_root.join("ruby").join("3.3.0").join("gems");
        tokio::fs::create_dir_all(env_gems.join("rack-3.2.7").join("lib"))
            .await
            .unwrap();
        let default_gems = dir
            .path()
            .join("vendor")
            .join("bundle")
            .join("ruby")
            .join("3.3.0")
            .join("gems");
        tokio::fs::create_dir_all(default_gems.join("rack-3.2.7").join("lib"))
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(
            dir.path(),
            Some(env_root.as_os_str()),
            None,
        )
        .await;
        assert_eq!(paths, vec![env_gems, standalone, default_gems]);
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

    /// #577: the global config file follows `Settings#global_config_file`:
    /// `$BUNDLE_CONFIG`, else `$BUNDLE_USER_CONFIG`, else
    /// `$BUNDLE_USER_HOME/config`, else `~/.bundle/config`; empty values
    /// are unset and a relative value is read against the project root.
    #[test]
    fn global_config_file_follows_bundler_lookup() {
        let root = Path::new("/proj");
        let os = |s: &'static str| Some(std::ffi::OsStr::new(s));
        let abs = |s: &str| std::path::absolute(s).unwrap();
        let home = abs("/home/u");
        let home_os = Some(home.as_os_str());
        assert_eq!(
            bundler_global_config_file(root, None, None, None, home_os),
            Some(home.join(".bundle").join("config"))
        );
        let user_home = abs("/bh");
        assert_eq!(
            bundler_global_config_file(root, None, None, Some(user_home.as_os_str()), home_os),
            Some(user_home.join("config"))
        );
        let user_config = abs("/cfg/bundle");
        assert_eq!(
            bundler_global_config_file(
                root,
                None,
                Some(user_config.as_os_str()),
                Some(user_home.as_os_str()),
                home_os
            ),
            Some(user_config.clone())
        );
        let legacy = abs("/legacy/config");
        assert_eq!(
            bundler_global_config_file(
                root,
                Some(legacy.as_os_str()),
                Some(user_config.as_os_str()),
                None,
                home_os
            ),
            Some(legacy)
        );
        // Empty values are unset, and nothing set means no global file.
        assert_eq!(
            bundler_global_config_file(root, os(""), os(""), os(""), home_os),
            Some(home.join(".bundle").join("config"))
        );
        assert_eq!(
            bundler_global_config_file(root, None, None, None, os("")),
            None
        );
        // A relative value is read against the project root.
        assert_eq!(
            bundler_global_config_file(root, None, os("cfg/bundle"), None, None),
            Some(root.join("cfg/bundle"))
        );
    }

    /// #577: `bundle config set --global cache_path` moves the cache dir,
    /// below the local config and the environment.
    #[tokio::test]
    async fn app_cache_dir_reads_the_global_config_below_local_and_env() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let global = dir.path().join("global-config");
        std::fs::write(&global, "---\nBUNDLE_CACHE_PATH: \"vendor/gems\"\n").unwrap();
        let g = Some(global.as_path());
        assert_eq!(
            bundler_app_cache_dir_with_env(&root, None, None, false, g).await,
            root.join("vendor").join("gems")
        );
        // The environment outranks it.
        let env = std::ffi::OsStr::new("vendor/env-gems");
        assert_eq!(
            bundler_app_cache_dir_with_env(&root, Some(env), None, false, g).await,
            root.join("vendor").join("env-gems")
        );
        // So does the local app config.
        std::fs::create_dir(root.join(".bundle")).unwrap();
        std::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_CACHE_PATH: \"vendor/local\"\n",
        )
        .unwrap();
        assert_eq!(
            bundler_app_cache_dir_with_env(&root, None, None, false, g).await,
            root.join("vendor").join("local")
        );
        // BUNDLE_IGNORE_CONFIG skips the global file too.
        std::fs::remove_file(root.join(".bundle/config")).unwrap();
        assert_eq!(
            bundler_app_cache_dir_with_env(&root, None, None, true, g).await,
            root.join("vendor").join("cache")
        );
        // A missing global file is no setting.
        let missing = dir.path().join("missing");
        assert_eq!(
            bundler_app_cache_dir_with_env(&root, None, None, false, Some(&missing)).await,
            root.join("vendor").join("cache")
        );
    }

    /// #577: a global `gemfile` setting is the third tier: below the local
    /// config and the environment, and refused like a local one when it
    /// names a manifest socket-patch does not wire.
    #[tokio::test]
    async fn loaded_manifest_reads_the_global_config_below_local_and_env() {
        use crate::formats::gem::manifest::{GemfileSetting, LoadedManifest};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(&root).unwrap();
        let global = dir.path().join("global-config");
        std::fs::write(&global, "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n").unwrap();
        let g = Some(global.as_path());
        let m = bundler_loaded_manifest_with_env(
            &root,
            BundlerEnv {
                global_config: g,
                ..BundlerEnv::default()
            },
        )
        .await;
        assert_eq!(
            m,
            LoadedManifest::Unsupported {
                value: "Gemfile.next".into(),
                by: GemfileSetting::GlobalConfig
            }
        );
        let detail = m.unsupported_detail().unwrap();
        assert!(
            detail.contains("bundle config unset --global gemfile"),
            "{detail}"
        );
        // The environment outranks it.
        assert_eq!(
            bundler_loaded_manifest_with_env(
                &root,
                BundlerEnv {
                    gemfile: Some(std::ffi::OsStr::new("Gemfile")),
                    global_config: g,
                    ..BundlerEnv::default()
                }
            )
            .await,
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::Env
            }
        );
        // So does the local app config.
        std::fs::create_dir(root.join(".bundle")).unwrap();
        std::fs::write(
            root.join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"gems.rb\"\n",
        )
        .unwrap();
        assert_eq!(
            bundler_loaded_manifest_with_env(
                &root,
                BundlerEnv {
                    global_config: g,
                    ..BundlerEnv::default()
                }
            )
            .await,
            LoadedManifest::Configured {
                manifest: "gems.rb",
                by: GemfileSetting::AppConfig
            }
        );
        // `bundle config set --global lockfile` is read from the same file,
        // below the local app config (#749 on top of #577).
        std::fs::write(
            &global,
            "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\nBUNDLE_LOCKFILE: \"custom.lock\"\n",
        )
        .unwrap();
        assert_eq!(
            bundler_loaded_manifest_with_env(
                &root,
                BundlerEnv {
                    global_config: g,
                    ..BundlerEnv::default()
                }
            )
            .await,
            LoadedManifest::UnsupportedLockfile {
                value: "custom.lock".into(),
                by: GemfileSetting::GlobalConfig
            }
        );
        // BUNDLE_IGNORE_CONFIG skips both files.
        assert_eq!(
            bundler_loaded_manifest_with_env(
                &root,
                BundlerEnv {
                    ignore_config: true,
                    global_config: g,
                    ..BundlerEnv::default()
                }
            )
            .await,
            LoadedManifest::Default
        );
    }

    #[tokio::test]
    async fn empty_gemfile_settings_shadow_global_without_erasing_the_environment() {
        use crate::formats::gem::manifest::{GemfileSetting, LoadedManifest};
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        std::fs::create_dir_all(root.join(".bundle")).unwrap();
        let global = dir.path().join("global-config");
        std::fs::write(&global, "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n").unwrap();
        let g = Some(global.as_path());

        // An exported empty value shadows the global file and leaves
        // Bundler's default Gemfile/gems.rb discovery active.
        assert_eq!(
            bundler_loaded_manifest_with_env(
                &root,
                BundlerEnv {
                    gemfile: Some(OsStr::new("")),
                    global_config: g,
                    ..BundlerEnv::default()
                }
            )
            .await,
            LoadedManifest::Default
        );
        // The same value written by `bundle config set --local gemfile ''`
        // is present even though it names no file.
        std::fs::write(root.join(".bundle/config"), "---\nBUNDLE_GEMFILE: \"\"\n").unwrap();
        assert_eq!(
            bundler_loaded_manifest_with_env(
                &root,
                BundlerEnv {
                    global_config: g,
                    ..BundlerEnv::default()
                }
            )
            .await,
            LoadedManifest::Default
        );
        // Bundler does not re-export an empty local setting, so an existing
        // non-empty environment value still chooses the manifest.
        assert_eq!(
            bundler_loaded_manifest_with_env(
                &root,
                BundlerEnv {
                    gemfile: Some(OsStr::new("Gemfile")),
                    global_config: g,
                    ..BundlerEnv::default()
                }
            )
            .await,
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::Env
            }
        );
    }

    /// #577: `bundle config set --global path vendor/gems` is where bundler
    /// installs, so agent-mode discovery must probe it (relative to the
    /// project root, like bundler). A local or env `path` / `path.system`
    /// shadows the global tier entirely (`Settings#path` stops at the first
    /// tier that sets either).
    #[tokio::test]
    async fn discovery_probes_the_global_config_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        let store = root
            .join("vendor")
            .join("gems")
            .join("ruby")
            .join("3.3.0")
            .join("gems");
        std::fs::create_dir_all(store.join("colorize-0.8.1")).unwrap();
        std::fs::write(root.join("Gemfile"), "gem \"colorize\"\n").unwrap();
        let global = dir.path().join("global-config");
        std::fs::write(&global, "---\nBUNDLE_PATH: \"vendor/gems\"\n").unwrap();
        let g = Some(global.as_path());

        let stores = RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, g)
            .await
            .stores;
        assert_eq!(stores, vec![store.clone()]);

        // No global file: the store is invisible (the #577 bug).
        let stores = RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, None)
            .await
            .stores;
        assert!(stores.is_empty(), "{stores:?}");

        // A global `path.system` means the system gem home: nothing added.
        let system = dir.path().join("global-system");
        std::fs::write(
            &system,
            "---\nBUNDLE_PATH: \"vendor/gems\"\nBUNDLE_PATH__SYSTEM: \"true\"\n",
        )
        .unwrap();
        let stores =
            RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, Some(&system))
                .await
                .stores;
        assert!(stores.is_empty(), "{stores:?}");

        // The env var shadows the global tier.
        let env_root = dir.path().join("env-bundle");
        let stores = RubyCrawler::discover_bundle_stores_with_env(
            &root,
            Some(env_root.as_os_str()),
            None,
            None,
            g,
        )
        .await
        .stores;
        assert!(stores.is_empty(), "{stores:?}");
        // Even empty: Bundler stops at the env tier (`explicit_path` `""`).
        let stores = RubyCrawler::discover_bundle_stores_with_env(
            &root,
            Some(OsStr::new("")),
            None,
            None,
            g,
        )
        .await
        .stores;
        assert!(stores.is_empty(), "{stores:?}");

        // Each local path setting stops Bundler at the local tier. Empty
        // strings and false flags still count as present, just as the
        // environment's empty path does above.
        std::fs::create_dir(root.join(".bundle")).unwrap();
        for setting in [
            "BUNDLE_PATH: \"\"",
            "BUNDLE_PATH__SYSTEM: \"true\"",
            "BUNDLE_PATH__SYSTEM: \"false\"",
            "BUNDLE_PATH__SYSTEM: \"\"",
            "BUNDLE_DISABLE_SHARED_GEMS: \"true\"",
            "BUNDLE_DISABLE_SHARED_GEMS: \"false\"",
            "BUNDLE_DISABLE_SHARED_GEMS: \"\"",
        ] {
            std::fs::write(root.join(".bundle/config"), format!("---\n{setting}\n")).unwrap();
            let stores = RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, g)
                .await
                .stores;
            assert!(stores.is_empty(), "{setting}: {stores:?}");
        }

        // A non-Ruby directory never reads it (the explicit-roots gate).
        let non_ruby = dir.path().join("not-ruby");
        std::fs::create_dir_all(&non_ruby).unwrap();
        let stores = RubyCrawler::discover_bundle_stores_with_env(&non_ruby, None, None, None, g)
            .await
            .stores;
        assert!(stores.is_empty(), "{stores:?}");
    }

    /// An env `BUNDLE_PATH__SYSTEM` or `BUNDLE_DISABLE_SHARED_GEMS` — any
    /// value, even `"false"` or empty — shadows a global `path`: Bundler's
    /// `Settings#path` stops at the env tier (checked against Bundler
    /// 4.0.17: `explicit_path` is `nil` for each value).
    #[test]
    fn env_path_flags_shadow_the_global_config_path() {
        let global = Some(PathBuf::from("/home/u/.bundle/config"));
        for value in ["true", "false", ""] {
            assert_eq!(
                global_path_config_unless_env_path_settings(
                    global.clone(),
                    Some(OsStr::new(value)),
                    None
                ),
                None,
                "BUNDLE_PATH__SYSTEM={value}"
            );
            assert_eq!(
                global_path_config_unless_env_path_settings(
                    global.clone(),
                    None,
                    Some(OsStr::new(value))
                ),
                None,
                "BUNDLE_DISABLE_SHARED_GEMS={value}"
            );
        }
        // Unset: the global file still applies.
        assert_eq!(
            global_path_config_unless_env_path_settings(global.clone(), None, None),
            global
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
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None).await;
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
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None).await;
        assert_eq!(discovery.skipped_config_path, None);

        // path.system=true → bundler ignores the path; not a refusal.
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            format!("---\nBUNDLE_PATH: \"{value}\"\nBUNDLE_PATH__SYSTEM: \"true\"\n"),
        )
        .await
        .unwrap();
        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None).await;
        assert_eq!(discovery.skipped_config_path, None);
    }

    /// #709: a refused out-of-tree config root stays out of the write-path
    /// discovery (`get_gem_paths`) but is exposed, read-only, to verifiers —
    /// bundler installs into and loads from it, so a verifier that skipped
    /// it would mistake "never looked" for "not installed".
    #[tokio::test]
    async fn refused_config_root_is_verification_only() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("Gemfile"), b"gem \"colorize\"\n")
            .await
            .unwrap();
        tokio::fs::create_dir_all(dir.path().join(".bundle"))
            .await
            .unwrap();
        let gems = outside.path().join("ruby").join("3.3.0").join("gems");
        tokio::fs::create_dir_all(gems.join("colorize-0.8.1").join("lib"))
            .await
            .unwrap();
        let value = outside.path().display().to_string();
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            format!("---\nBUNDLE_PATH: \"{value}\"\n"),
        )
        .await
        .unwrap();
        let options = CrawlerOptions {
            cwd: dir.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let crawler = RubyCrawler::new();

        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None).await;
        assert!(
            !discovery
                .stores
                .iter()
                .any(|s| s.starts_with(outside.path())),
            "the refused root must never become a write-path store: {:?}",
            discovery.stores
        );
        let verify = crawler
            .verification_only_gem_paths_with_env(&options, None, None, None, None, false)
            .await;
        let gems = normalize_lexically(&gems).unwrap();
        assert_eq!(verify, vec![gems.clone()]);
        let found = crawler
            .find_by_purls(&verify[0], &["pkg:gem/colorize@0.8.1".to_string()])
            .await
            .unwrap();
        assert!(found.contains_key("pkg:gem/colorize@0.8.1"));

        // `~` spelling resolves against the injected home.
        tokio::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"~/\"\n",
        )
        .await
        .unwrap();
        let verify = crawler
            .verification_only_gem_paths_with_env(
                &options,
                None,
                None,
                Some(outside.path().as_os_str()),
                None,
                false,
            )
            .await;
        assert_eq!(verify, vec![gems.clone()]);

        // BUNDLE_IGNORE_CONFIG: bundler never reads the config path, so a
        // leftover install there is not what it loads — nothing to verify.
        let verify = crawler
            .verification_only_gem_paths_with_env(
                &options,
                None,
                None,
                Some(outside.path().as_os_str()),
                None,
                true,
            )
            .await;
        assert!(verify.is_empty(), "{verify:?}");

        // The same root supplied through the trusted env is a regular store,
        // so it is not reported a second time.
        let verify = crawler
            .verification_only_gem_paths_with_env(
                &options,
                Some(outside.path().as_os_str()),
                None,
                Some(outside.path().as_os_str()),
                None,
                false,
            )
            .await;
        assert!(verify.is_empty(), "{verify:?}");

        // Global mode never probes the project's bundler roots.
        let global = CrawlerOptions {
            global: true,
            ..options
        };
        assert!(crawler
            .verification_only_gem_paths_with_env(&global, None, None, None, None, false)
            .await
            .is_empty());
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
    /// (bundler `File.expand_path`s the value), not as a literal
    /// `<cwd>/~/...` relative path.
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
            None,
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

    /// Stage a project that used to install into `vendor/bundle` (the
    /// store is still on disk, gitignored) and returns that store.
    async fn stage_leftover_vendor_bundle(root: &Path) -> PathBuf {
        tokio::fs::write(root.join("Gemfile"), b"gem \"colorize\"\n")
            .await
            .unwrap();
        let store = root
            .join("vendor")
            .join("bundle")
            .join("ruby")
            .join("3.3.0")
            .join("gems");
        tokio::fs::create_dir_all(store.join("colorize-0.8.1").join("lib"))
            .await
            .unwrap();
        store
    }

    /// #915: `bundle config set --local path.system true` sends Bundler
    /// back to the system gem home, so a leftover `vendor/bundle` is as
    /// unused as a recorded path. It must not be crawled, and must not
    /// switch off the `gem env` homes where the loaded copy lives.
    /// Bundler's `to_bool` treats every value but `false`/`f`/`no`/`n`/
    /// `0`/empty as true (checked against Bundler 4.0.18).
    #[tokio::test]
    async fn local_path_system_drops_leftover_vendor_bundle() {
        for value in ["true", "1", "yes"] {
            let dir = tempfile::tempdir().unwrap();
            stage_leftover_vendor_bundle(dir.path()).await;
            tokio::fs::create_dir_all(dir.path().join(".bundle"))
                .await
                .unwrap();
            tokio::fs::write(
                dir.path().join(".bundle").join("config"),
                format!("---\nBUNDLE_PATH__SYSTEM: \"{value}\"\n"),
            )
            .await
            .unwrap();

            let discovery =
                RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None)
                    .await;
            assert!(
                discovery.stores.is_empty(),
                "{value}: {:?}",
                discovery.stores
            );
            assert!(!discovery.default_root_has_stores, "{value}");

            // The local tier also shadows an env `BUNDLE_PATH`, even one
            // naming the leftover `vendor/bundle` itself.
            let vendor_bundle = dir.path().join("vendor").join("bundle");
            let discovery = RubyCrawler::discover_bundle_stores_with_env(
                dir.path(),
                Some(vendor_bundle.as_os_str()),
                None,
                None,
                None,
            )
            .await;
            assert!(
                discovery.stores.is_empty(),
                "{value}: {:?}",
                discovery.stores
            );
            assert!(!discovery.default_root_has_stores, "{value}");
        }
    }

    /// #915, env variant: `BUNDLE_PATH__SYSTEM=true` in the environment.
    #[tokio::test]
    async fn env_path_system_drops_leftover_vendor_bundle() {
        let dir = tempfile::tempdir().unwrap();
        stage_leftover_vendor_bundle(dir.path()).await;

        let discovery = RubyCrawler::discover_bundle_stores_with_path_system_env(
            dir.path(),
            None,
            Some(OsStr::new("true")),
            None,
        )
        .await;
        assert!(discovery.stores.is_empty(), "{:?}", discovery.stores);
        assert!(!discovery.default_root_has_stores);

        // Same tier as an env `BUNDLE_PATH`: Bundler goes to the system
        // gem home (4.0.18 refuses the combination outright), so the env
        // root must not bring the leftover store back.
        let vendor_bundle = dir.path().join("vendor").join("bundle");
        let discovery = RubyCrawler::discover_bundle_stores_with_path_system_env(
            dir.path(),
            Some(vendor_bundle.as_os_str()),
            Some(OsStr::new("true")),
            None,
        )
        .await;
        assert!(discovery.stores.is_empty(), "{:?}", discovery.stores);
        assert!(!discovery.default_root_has_stores);
    }

    /// #915, global variant: `bundle config set --global path.system true`.
    #[tokio::test]
    async fn global_path_system_drops_leftover_vendor_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        tokio::fs::create_dir_all(&root).await.unwrap();
        stage_leftover_vendor_bundle(&root).await;
        let global = dir.path().join("global-config");
        tokio::fs::write(&global, "---\nBUNDLE_PATH__SYSTEM: \"true\"\n")
            .await
            .unwrap();

        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, Some(&global))
                .await;
        assert!(discovery.stores.is_empty(), "{:?}", discovery.stores);
        assert!(!discovery.default_root_has_stores);
    }

    /// #915 controls: only the tier Bundler actually reads decides. A
    /// higher tier that sets a path (or a falsy flag) shadows a lower
    /// `path.system`, and a project with no config keeps the historic
    /// leftover-`vendor/bundle` heuristic.
    #[tokio::test]
    async fn shadowed_path_system_keeps_vendor_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        tokio::fs::create_dir_all(&root).await.unwrap();
        let store = stage_leftover_vendor_bundle(&root).await;
        let global = dir.path().join("global-config");
        tokio::fs::write(&global, "---\nBUNDLE_PATH__SYSTEM: \"true\"\n")
            .await
            .unwrap();
        let vendor_bundle = root.join("vendor").join("bundle");

        // No config at all: unchanged.
        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, None).await;
        assert_eq!(discovery.stores, vec![store.clone()]);
        assert!(discovery.default_root_has_stores);

        // Env `BUNDLE_PATH` sits above the global tier.
        let discovery = RubyCrawler::discover_bundle_stores_with_env(
            &root,
            Some(vendor_bundle.as_os_str()),
            None,
            None,
            Some(&global),
        )
        .await;
        assert_eq!(discovery.stores, vec![store.clone()]);

        // A falsy env flag stops Bundler at the env tier too.
        let discovery = RubyCrawler::discover_bundle_stores_with_path_system_env(
            &root,
            None,
            Some(OsStr::new("false")),
            None,
        )
        .await;
        assert_eq!(discovery.stores, vec![store.clone()]);

        // A local path sits above the env flag.
        tokio::fs::create_dir_all(root.join(".bundle"))
            .await
            .unwrap();
        tokio::fs::write(
            root.join(".bundle").join("config"),
            "---\nBUNDLE_PATH: \"vendor/bundle\"\n",
        )
        .await
        .unwrap();
        let discovery = RubyCrawler::discover_bundle_stores_with_path_system_env(
            &root,
            None,
            Some(OsStr::new("true")),
            None,
        )
        .await;
        assert_eq!(discovery.stores, vec![store.clone()]);

        // A falsy local flag sits above the global `path.system`.
        tokio::fs::write(
            root.join(".bundle").join("config"),
            "---\nBUNDLE_PATH__SYSTEM: \"false\"\n",
        )
        .await
        .unwrap();
        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, Some(&global))
                .await;
        assert_eq!(discovery.stores, vec![store]);
    }

    /// Stage a gem under `<root>/.bundle/ruby/3.3.0/gems`, where Bundler
    /// installs when it uses neither an explicit path nor the system gems
    /// (`default_install_uses_path` on 2.x, `simulate_version 5` on 4.x).
    async fn stage_dot_bundle_store(root: &Path) -> PathBuf {
        tokio::fs::write(root.join("Gemfile"), b"gem \"colorize\"\n")
            .await
            .unwrap();
        let store = root.join(".bundle").join("ruby").join("3.3.0").join("gems");
        tokio::fs::create_dir_all(store.join("colorize-0.8.1").join("lib"))
            .await
            .unwrap();
        store
    }

    /// #967: with no tier setting `path`, `path.system` or
    /// `disable_shared_gems`, Bundler's base path is `<root>/.bundle` once
    /// `default_install_uses_path` (2.x) or `simulate_version 5` (4.x) is
    /// on. That store must be crawled. It is not the default root, so the
    /// `gem env` fallback (default gems) stays on.
    #[tokio::test]
    async fn dot_bundle_base_path_is_crawled() {
        for config in [
            None,
            Some("---\nBUNDLE_SIMULATE_VERSION: \"5\"\n"),
            Some("---\nBUNDLE_DEFAULT_INSTALL_USES_PATH: \"true\"\n"),
            // A falsy flag decides the tier without naming a path.
            Some("---\nBUNDLE_PATH__SYSTEM: \"false\"\nBUNDLE_SIMULATE_VERSION: \"5\"\n"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let store = stage_dot_bundle_store(dir.path()).await;
            if let Some(config) = config {
                tokio::fs::write(dir.path().join(".bundle").join("config"), config)
                    .await
                    .unwrap();
            }

            let discovery =
                RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None)
                    .await;
            assert_eq!(discovery.stores, vec![store], "{config:?}");
            assert!(!discovery.default_root_has_stores, "{config:?}");
        }
    }

    /// #967, global variant: `bundle config set --global simulate_version
    /// 5` with no path in any tier still installs into `<root>/.bundle`.
    #[tokio::test]
    async fn dot_bundle_base_path_with_global_flag_is_crawled() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        tokio::fs::create_dir_all(&root).await.unwrap();
        let store = stage_dot_bundle_store(&root).await;
        let global = dir.path().join("global-config");
        tokio::fs::write(&global, "---\nBUNDLE_SIMULATE_VERSION: \"5\"\n")
            .await
            .unwrap();

        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(&root, None, None, None, Some(&global))
                .await;
        assert_eq!(discovery.stores, vec![store]);
        assert!(!discovery.default_root_has_stores);
    }

    /// #967 controls: Bundler never uses `<root>/.bundle` when the tier
    /// that decides the path names one (local, env or global) or sets a
    /// truthy `path.system`, and the root only counts for a Ruby project.
    #[tokio::test]
    async fn dot_bundle_base_path_is_skipped_when_bundler_does_not_use_it() {
        // A local path.
        let dir = tempfile::tempdir().unwrap();
        stage_dot_bundle_store(dir.path()).await;
        for config in [
            "---\nBUNDLE_PATH: \"vendor/bundle\"\n",
            "---\nBUNDLE_PATH: \"\"\n",
            "---\nBUNDLE_PATH__SYSTEM: \"true\"\n",
        ] {
            tokio::fs::write(dir.path().join(".bundle").join("config"), config)
                .await
                .unwrap();
            let discovery =
                RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None)
                    .await;
            assert!(
                discovery.stores.is_empty(),
                "{config}: {:?}",
                discovery.stores
            );
        }
        tokio::fs::remove_file(dir.path().join(".bundle").join("config"))
            .await
            .unwrap();

        // An env `BUNDLE_PATH`, even an empty one.
        let elsewhere = dir.path().join("elsewhere");
        for env in [elsewhere.as_os_str(), OsStr::new("")] {
            let discovery = RubyCrawler::discover_bundle_stores_with_env(
                dir.path(),
                Some(env),
                None,
                None,
                None,
            )
            .await;
            assert!(
                discovery.stores.is_empty(),
                "{env:?}: {:?}",
                discovery.stores
            );
        }

        // An env `path.system`.
        let discovery = RubyCrawler::discover_bundle_stores_with_path_system_env(
            dir.path(),
            None,
            Some(OsStr::new("true")),
            None,
        )
        .await;
        assert!(discovery.stores.is_empty(), "{:?}", discovery.stores);

        // A global path or `path.system`.
        let global = dir.path().join("global-config");
        for config in [
            "---\nBUNDLE_PATH: \"/opt/bundle\"\n",
            "---\nBUNDLE_PATH__SYSTEM: \"true\"\n",
        ] {
            tokio::fs::write(&global, config).await.unwrap();
            let discovery = RubyCrawler::discover_bundle_stores_with_env(
                dir.path(),
                None,
                None,
                None,
                Some(&global),
            )
            .await;
            assert!(
                discovery.stores.is_empty(),
                "{config}: {:?}",
                discovery.stores
            );
        }

        // Not a Ruby project.
        tokio::fs::remove_file(dir.path().join("Gemfile"))
            .await
            .unwrap();
        let discovery =
            RubyCrawler::discover_bundle_stores_with_env(dir.path(), None, None, None, None).await;
        assert!(discovery.stores.is_empty(), "{:?}", discovery.stores);
    }

    /// Bundler's boolean coercion (`Settings#to_bool`).
    #[test]
    fn bundler_truthy_matches_bundler_to_bool() {
        for value in ["true", "TRUE", "1", "yes", "y", "on", "anything"] {
            assert!(bundler_truthy(value), "{value}");
        }
        for value in ["false", "False", "f", "no", "N", "0", ""] {
            assert!(!bundler_truthy(value), "{value}");
        }
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
        // Bundler's own coercion: "1" is truthy too, "false" is not.
        assert_eq!(
            parse_bundle_config_path(
                "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_PATH__SYSTEM: \"1\"\n"
            ),
            None
        );
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

    // ── gem env memo ──────────────────────────────────────────────

    /// Every caller gets the first answer, however many ask at once, and
    /// the subprocess pair runs exactly once.
    #[tokio::test]
    async fn gem_env_homes_are_asked_once_per_cell() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let cell = Arc::new(tokio::sync::OnceCell::new());
        let asks = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let (cell, asks) = (Arc::clone(&cell), Arc::clone(&asks));
            tasks.push(tokio::spawn(async move {
                memoize_gem_env_homes(&cell, || async {
                    let n = asks.fetch_add(1, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    (
                        (Some(format!("/gems/home-{n}")), Some("/gems/path".into())),
                        true,
                    )
                })
                .await
            }));
        }
        let first = (
            Some("/gems/home-0".to_string()),
            Some("/gems/path".to_string()),
        );
        for task in tasks {
            assert_eq!(task.await.expect("memo task"), first);
        }
        assert_eq!(asks.load(Ordering::SeqCst), 1);
        let later =
            memoize_gem_env_homes(&cell, || async { ((None, Some("x".into())), true) }).await;
        assert_eq!(later, first);
    }

    /// A failed or partial ask is not kept: the asker gets its own answer
    /// and the next caller asks again, as every caller did before the memo.
    /// So is an answer the environment changed under.
    #[tokio::test]
    async fn gem_env_homes_failures_are_asked_again() {
        let cell = tokio::sync::OnceCell::new();
        let good = (
            Some("/gems/home".to_string()),
            Some("/gems/path".to_string()),
        );
        for unkept in [
            ((None, None), true),
            ((Some("/gems/home".to_string()), None), true),
            ((None, Some("/gems/path".to_string())), true),
            (good.clone(), false),
        ] {
            let want = unkept.0.clone();
            assert_eq!(
                memoize_gem_env_homes(&cell, || async { unkept }).await,
                want
            );
            assert!(cell.get().is_none(), "{want:?} must not be kept");
        }
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let ask = || async {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (good.clone(), true)
        };
        assert_eq!(memoize_gem_env_homes(&cell, ask).await, good);
        assert_eq!(
            memoize_gem_env_homes(&cell, || async { ((None, None), true) }).await,
            good
        );
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// One cell per inherited environment: the same key shares a cell, a
    /// swapped `PATH` gets its own.
    #[test]
    fn gem_env_cells_are_keyed_on_the_inherited_environment() {
        let memo = GemEnvMemo::default();
        let key = |path: &str| -> GemEnvKey {
            (
                vec![("PATH".into(), path.into())],
                Some(PathBuf::from("/work")),
            )
        };
        let a = gem_env_cell(&memo, key("/usr/bin"));
        let again = gem_env_cell(&memo, key("/usr/bin"));
        let swapped = gem_env_cell(&memo, key("/tmp/fake-bin"));
        assert!(std::sync::Arc::ptr_eq(&a, &again));
        assert!(!std::sync::Arc::ptr_eq(&a, &swapped));
        let (vars, cwd) = gem_env_key();
        assert!(vars.windows(2).all(|w| w[0] <= w[1]), "sorted env snapshot");
        assert_eq!(cwd, std::env::current_dir().ok());
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

    // ── audited coverage gaps (2026-09) ────────────────────────────

    /// A stray FILE inside an engine dir (`vendor/bundle/ruby/README.txt`,
    /// a `.DS_Store`, …) must be skipped by the scoped
    /// `<root>/<engine>/<version>/gems` walk — only real `<version>/gems`
    /// dirs count. (A file directly under the root exercises the outer
    /// non-dir guard; this one sits one level down, inside the engine dir.)
    #[tokio::test]
    async fn scoped_engine_walk_skips_stray_files() {
        let dir = tempfile::tempdir().unwrap();
        let ruby_dir = dir.path().join("vendor").join("bundle").join("ruby");
        let gems = ruby_dir.join("3.2.0").join("gems");
        tokio::fs::create_dir_all(gems.join("foo-1.0.0").join("lib"))
            .await
            .unwrap();
        tokio::fs::write(ruby_dir.join("README.txt"), b"stray")
            .await
            .unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert_eq!(paths, vec![gems]);
    }

    /// `scan_gem_dir` (via `crawl_all`) must skip hidden dot-directories —
    /// even one that parses AND verifies as a gem (`.hidden-2.0.0/lib/`
    /// would surface a ghost `pkg:gem/.hidden@2.0.0` without the guard) —
    /// and dirs with no dash-digit name/version boundary at all.
    #[tokio::test]
    async fn crawl_all_skips_hidden_and_unparseable_dirs() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("rails-7.1.0").join("lib"))
            .await
            .unwrap();
        // Parses as (".hidden", "2.0.0") and verifies (has lib/) — only
        // the hidden-directory guard can exclude it.
        tokio::fs::create_dir_all(dir.path().join(".hidden-2.0.0").join("lib"))
            .await
            .unwrap();
        // No dash-digit boundary → parse_dir_name_version None → skipped.
        tokio::fs::create_dir_all(dir.path().join("noversiondir").join("lib"))
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

    /// A lib-less dir whose entries are NOT `.gemspec` files (a partially
    /// deleted gem: README-style files, a stale `.gemspec.bak`) must fail
    /// verification — the `.bak` name also pins the `ends_with(".gemspec")`
    /// check against a contains-style regression.
    #[tokio::test]
    async fn verify_gem_lib_less_dir_with_non_gemspec_files_fails() {
        let dir = tempfile::tempdir().unwrap();
        let gem_dir = dir.path().join("rails-7.1.0");
        tokio::fs::create_dir_all(&gem_dir).await.unwrap();
        tokio::fs::write(gem_dir.join("README.md"), b"# docs")
            .await
            .unwrap();
        tokio::fs::write(gem_dir.join("rails.gemspec.bak"), b"# stale")
            .await
            .unwrap();

        let crawler = RubyCrawler::new();
        assert!(!crawler.verify_gem_at_path(&gem_dir).await);
    }

    /// `locate_gem_dir`'s prefix scan must skip a `<name>-<version>-*` dir
    /// that matches the prefix but fails gem verification (a hollow
    /// platform dir — no `lib/`, no `.gemspec`): alone it resolves
    /// nothing, and beside a valid platform sibling the sibling wins.
    #[tokio::test]
    async fn locate_gem_dir_continues_past_hollow_platform_dir() {
        // (a) ONLY the hollow platform dir: the prefix matches, verify
        // fails, the scan exhausts and the purl stays unresolved.
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("nokogiri-1.16.5-x86_64-linux"))
            .await
            .unwrap();
        let crawler = RubyCrawler::new();
        let purls = vec!["pkg:gem/nokogiri@1.16.5".to_string()];
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();
        assert!(
            result.is_empty(),
            "hollow platform dir must not resolve: {result:?}"
        );

        // (b) The hollow dir PLUS a valid platform sibling: the valid one
        // is returned (order-independent — only one candidate verifies).
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::create_dir_all(dir.path().join("nokogiri-1.16.5-x86_64-linux"))
            .await
            .unwrap();
        let valid = dir.path().join("nokogiri-1.16.5-arm64-darwin");
        tokio::fs::create_dir_all(valid.join("lib")).await.unwrap();
        let result = crawler.find_by_purls(dir.path(), &purls).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("pkg:gem/nokogiri@1.16.5").unwrap().path, valid);
    }

    /// With a home PRESENT, only the bare-`~` form expands: `~user` (which
    /// would need the passwd lookup bundler itself does) and plain relative
    /// values are left untouched, and bare `~` maps to home itself.
    #[test]
    fn expand_tilde_untouched_forms_with_home_present() {
        let home = Path::new(if cfg!(windows) {
            r"C:\home\u"
        } else {
            "/home/u"
        });
        assert_eq!(
            expand_tilde(Path::new("~user/store"), Some(home)),
            PathBuf::from("~user/store")
        );
        assert_eq!(
            expand_tilde(Path::new("rel/store"), Some(home)),
            PathBuf::from("rel/store")
        );
        // Bare `~` → home itself (PathBuf equality is components-based,
        // tolerating join("")'s trailing-separator artifact).
        assert_eq!(expand_tilde(Path::new("~"), Some(home)), home.to_path_buf());
    }

    // ── find_each_by_purl ≡ per-PURL find_by_purls ─────────────────────

    #[tokio::test]
    async fn find_each_by_purl_matches_per_purl_find_by_purls() {
        use crate::crawlers::oracle_support::{mkdir, symlink, write, PermGuard, Rng};

        const GEMS: &[&str] = &["rails", "nokogiri", "rack", "rails-html"];
        const VERSIONS: &[&str] = &["7.1.0", "1.16.5", "3.0.0"];
        const SUFFIXES: &[&str] = &["", "-x86_64-linux", "-arm64-darwin", "-java"];
        let mut found = 0;
        for seed in 0..48u64 {
            let mut rng = Rng::new(seed);
            let tmp = tempfile::tempdir().unwrap();
            let mut perms = PermGuard::default();
            let root = tmp.path().join("gems");
            mkdir(&root);
            for i in 0..rng.below(16) {
                let dir = root.join(format!(
                    "{}-{}{}",
                    rng.pick(GEMS),
                    rng.pick(VERSIONS),
                    rng.pick(SUFFIXES)
                ));
                match rng.below(8) {
                    0 => write(&dir, "file"),
                    1 => write(&dir.join("x.gemspec"), ""),
                    2 => mkdir(&dir.join("x.gemspec")),
                    3 => {
                        let target = tmp.path().join(format!("t{i}"));
                        if rng.chance(70) {
                            mkdir(&target.join("lib"));
                        }
                        symlink(&target, &dir);
                    }
                    4 => {
                        mkdir(&dir.join("lib"));
                        perms.plan(&dir, 0o000);
                    }
                    5 => mkdir(&dir),
                    _ => mkdir(&dir.join("lib")),
                }
            }
            perms.apply();
            let mut purls: Vec<String> = Vec::new();
            for gem in GEMS {
                for version in VERSIONS {
                    purls.push(format!("pkg:gem/{gem}@{version}"));
                }
            }
            purls.push("pkg:gem/..@1.0.0".to_string());
            purls.push("pkg:npm/rails@7.1.0".to_string());

            let crawler = RubyCrawler::new();
            let each = crawler.find_each_by_purl(&root, &purls).await;
            assert_eq!(each.len(), purls.len());
            for (purl, got) in purls.iter().zip(each) {
                let single = crawler
                    .find_by_purls(&root, std::slice::from_ref(purl))
                    .await
                    .unwrap();
                let want = single.get(purl);
                assert_eq!(
                    got.as_ref()
                        .map(|p| (&p.name, &p.version, &p.namespace, &p.purl, &p.path)),
                    want.map(|p| (&p.name, &p.version, &p.namespace, &p.purl, &p.path)),
                    "seed {seed}: {purl}"
                );
                found += usize::from(got.is_some());
            }
        }
        assert!(found > 50, "vacuous fixtures: {found}");
    }

    /// #951: Bundler's config loader (`Gem::YAMLSerializer#strip_comment`,
    /// RubyGems / Bundler 2.5.6+) cuts a `.bundle/config` value at its
    /// first `#` unless the value starts with one, and applies that to the
    /// unquoted value. Pinned against the real loader's output.
    #[test]
    fn bundle_config_values_drop_a_trailing_comment_like_bundler() {
        let text = "---\nBUNDLE_PATH: .gems # project-local gems\n\
                    BUNDLE_A: \"a#b\"\nBUNDLE_B: x#y\nBUNDLE_C: #z\n\
                    BUNDLE_D: \"vendor/bundle\" # quoted then commented\n\
                    BUNDLE_E: \"a # b\"\nBUNDLE_F: ' q ' \n";
        let get = |key| bundle_config_setting_including_empty(text, key);
        assert_eq!(get("BUNDLE_PATH").as_deref(), Some(".gems"));
        assert_eq!(get("BUNDLE_A").as_deref(), Some("a"));
        assert_eq!(get("BUNDLE_B").as_deref(), Some("x"));
        // A value that STARTS with `#` is kept whole.
        assert_eq!(get("BUNDLE_C").as_deref(), Some("#z"));
        // The closing quote is not at the end of the line, so the loader
        // matches no quote pair: the quotes stay part of the value.
        assert_eq!(get("BUNDLE_D").as_deref(), Some("\"vendor/bundle\""));
        assert_eq!(get("BUNDLE_E").as_deref(), Some("a"));
        // No `#`: the unquoted value is kept as is.
        assert_eq!(get("BUNDLE_F").as_deref(), Some(" q "));
    }

    /// #951: a commented `path`, `path.system`, `cache_path` and `gemfile`
    /// read the way Bundler reads them.
    #[tokio::test]
    async fn commented_bundle_config_settings_follow_bundler() {
        assert_eq!(
            parse_bundle_config_path("---\nBUNDLE_PATH: .gems # project-local gems\n"),
            Some(".gems".to_string())
        );
        assert_eq!(
            parse_bundle_config_path(
                "---\nBUNDLE_PATH: vendor/bundle\nBUNDLE_PATH__SYSTEM: true # use system gems\n"
            ),
            None
        );
        assert_eq!(
            crate::formats::gem::manifest::config_gemfile("---\nBUNDLE_GEMFILE: gems.rb # twin\n")
                .as_deref(),
            Some("gems.rb")
        );

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join(".bundle")).unwrap();
        std::fs::write(
            root.join(".bundle").join("config"),
            "---\nBUNDLE_CACHE_PATH: vendor/gems # committed gem cache\n",
        )
        .unwrap();
        assert_eq!(
            bundler_app_cache_dir_with_env(root, None, None, false, None).await,
            root.join("vendor").join("gems")
        );
    }

    /// #951 repro: `BUNDLE_PATH: .gems # comment` must discover the
    /// `.gems` store Bundler installs into, not a directory named after
    /// the whole line.
    #[tokio::test]
    async fn commented_app_config_bundle_path_discovers_the_bundler_store() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Gemfile"), b"gem \"colorize\"\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".bundle")).unwrap();
        std::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: .gems # project-local gems\n",
        )
        .unwrap();
        let gems = dir
            .path()
            .join(".gems")
            .join("ruby")
            .join("3.3.0")
            .join("gems");
        std::fs::create_dir_all(gems.join("colorize-0.8.1").join("lib")).unwrap();
        std::fs::create_dir_all(dir.path().join(".gems/ruby/3.3.0/specifications")).unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert_eq!(paths, vec![gems]);
    }

    /// Bundler before 2.5.6 (or 2.4/2.5 on RubyGems before 3.5.6) keeps the
    /// comment in the value and installs into a directory named after it.
    /// When only that legacy-era directory exists, discovery must still
    /// find the store (the pre-#951 behaviour), not fall back to the
    /// system gem homes.
    #[tokio::test]
    async fn commented_bundle_path_keeps_the_legacy_bundler_store() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Gemfile"), b"gem \"colorize\"\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".bundle")).unwrap();
        std::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: .gems # note\n",
        )
        .unwrap();
        let root = dir.path().join(".gems # note");
        let gems = root.join("ruby").join("2.7.0").join("gems");
        std::fs::create_dir_all(gems.join("colorize-0.8.1").join("lib")).unwrap();
        std::fs::create_dir_all(root.join("ruby/2.7.0/specifications")).unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert_eq!(paths, vec![gems]);

        // Same for the cache path: only the legacy-era dir exists.
        std::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_CACHE_PATH: vendor/gems # c\n",
        )
        .unwrap();
        let legacy_cache = dir.path().join("vendor").join("gems # c");
        std::fs::create_dir_all(&legacy_cache).unwrap();
        assert_eq!(
            bundler_app_cache_dir_with_env(dir.path(), None, None, false, None).await,
            legacy_cache
        );
    }

    /// Bugbot on #953: a commented `path.system: true` drops the recorded
    /// path under the current loader. A leftover directory at that
    /// recorded path must not bring it back through the legacy reading.
    #[tokio::test]
    async fn commented_path_system_true_ignores_a_leftover_recorded_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Gemfile"), b"gem \"foo\"\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".bundle")).unwrap();
        std::fs::write(
            dir.path().join(".bundle").join("config"),
            "---\nBUNDLE_PATH: vendor/mygems\nBUNDLE_PATH__SYSTEM: true # use system gems\n",
        )
        .unwrap();
        let root = dir.path().join("vendor").join("mygems");
        std::fs::create_dir_all(root.join("gems").join("foo-1.0.0").join("lib")).unwrap();
        std::fs::create_dir_all(root.join("specifications")).unwrap();

        let paths = RubyCrawler::get_vendor_bundle_paths_with_env(dir.path(), None, None).await;
        assert!(
            paths.is_empty(),
            "a commented path.system=true must still drop the config root: {paths:?}"
        );
    }
}
