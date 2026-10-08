//! Which manifest Bundler loads for a project: the ONE answer shared by the
//! hosted rewriter's caller and the vendored backend, so neither can wire a
//! file Bundler ignores.
//!
//! Bundler's own order (`Bundler::Settings` priority — local app config
//! over ENV — read by `Bundler::CLI#initialize`, which re-exports the
//! winning `gemfile` setting into `BUNDLE_GEMFILE`):
//!
//! 1. `BUNDLE_GEMFILE:` in the app config file, `$BUNDLE_APP_CONFIG/config`
//!    else `<root>/.bundle/config` (what `bundle config set --local gemfile
//!    Gemfile.next` writes; relative to the project root);
//! 2. `BUNDLE_GEMFILE` from the environment (a relative value is read
//!    against the project root: bundler expands it against the directory
//!    `bundle` runs in, which is the project, not socket-patch's own
//!    cwd when it runs with `--cwd`). An environment value naming a file in
//!    ANOTHER directory moves `Bundler.root` there, and bundler then reads
//!    that root's app config, never this project's — so it decides alone;
//! 3. `BUNDLE_GEMFILE:` in the global config file (`bundle config set
//!    --global gemfile …`: `$BUNDLE_CONFIG`, `$BUNDLE_USER_CONFIG`,
//!    `$BUNDLE_USER_HOME/config` or `~/.bundle/config`, see
//!    [`crate::crawlers::ruby_crawler::bundler_global_config_file`]), read
//!    against the project root like the app config value;
//! 4. otherwise `gems.rb` when present, else `Gemfile` (bundler >= 2; 1.x
//!    reads a `Gemfile` first, so callers treat a twin as ambiguous or
//!    follow the >= 2 order, as the hosted rewriter does).
//!
//! A configured value that names the root's own `Gemfile` or `gems.rb` is
//! that spelling; anything else (`Gemfile.next`, a file in another
//! directory, a missing file) is [`LoadedManifest::Unsupported`]: the
//! rewriters and the lock readers only know the two default pairs, so the
//! callers fail closed rather than wire a manifest Bundler never reads.
//! Bundler 4's custom lockfile (`BUNDLE_LOCKFILE` from the environment,
//! else `BUNDLE_LOCKFILE:` in the app config, else in the global config —
//! `Bundler::CLI` checks the environment before `Bundler.settings`) is
//! layered on by [`LoadedManifest::with_lockfile`]: a value naming the lock of the pair bundler loads anyway changes nothing,
//! and anything else is [`LoadedManifest::UnsupportedLockfile`] — the
//! rewriters only edit the default lock of each pair, so wiring a project
//! whose lock lives elsewhere would leave the lock bundler reads unpinned
//! (#749).
//!
//! A `Gemfile` + `gems.rb` twin under default discovery is ambiguous across
//! bundler majors (1.x loads the `Gemfile`, >= 2 loads `gems.rb`), and
//! nothing on disk says which bundler runs: callers refuse it with
//! [`twin_manifest_refusal`] (#751).
//!
//! The model is pure:
//! the disk and environment reads live in
//! [`crate::crawlers::ruby_crawler::bundler_loaded_manifest`].

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::crawlers::ruby_crawler::bundle_config_setting_including_empty;
use crate::utils::relpath::normalize_lexically;

/// Where a configured `BUNDLE_GEMFILE` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemfileSetting {
    /// The `BUNDLE_GEMFILE` environment variable.
    Env,
    /// `BUNDLE_GEMFILE:` in the project's bundler app config file.
    AppConfig,
    /// `BUNDLE_GEMFILE:` in the user's global bundler config file.
    GlobalConfig,
}

impl GemfileSetting {
    /// How the setting is named in warnings and refusals.
    pub fn describe(self) -> &'static str {
        match self {
            GemfileSetting::Env => "the BUNDLE_GEMFILE environment variable",
            GemfileSetting::AppConfig => {
                "BUNDLE_GEMFILE in the bundler app config (.bundle/config)"
            }
            GemfileSetting::GlobalConfig => {
                "BUNDLE_GEMFILE in the global bundler config (~/.bundle/config)"
            }
        }
    }
}

/// The manifest Bundler loads for a project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadedManifest {
    /// No `BUNDLE_GEMFILE`: Bundler's default discovery (bundler >= 2: `gems.rb` first,
    /// then `Gemfile`), which callers apply to the files they see.
    Default,
    /// `BUNDLE_GEMFILE` names the root's own `Gemfile` or `gems.rb`.
    Configured {
        manifest: &'static str,
        by: GemfileSetting,
    },
    /// `BUNDLE_GEMFILE` names any other file.
    Unsupported { value: String, by: GemfileSetting },
    /// Bundler 4's `BUNDLE_LOCKFILE` names a lock other than the default
    /// lock of the pair bundler loads.
    UnsupportedLockfile { value: String, by: GemfileSetting },
}

impl LoadedManifest {
    /// The manifest/lock pair Bundler loads, given whether the root holds a
    /// `gems.rb`. `None` for [`LoadedManifest::Unsupported`].
    pub fn pair(&self, gems_rb_present: bool) -> Option<(&'static str, &'static str)> {
        let manifest = match self {
            LoadedManifest::Default if gems_rb_present => "gems.rb",
            LoadedManifest::Default => "Gemfile",
            LoadedManifest::Configured { manifest, .. } => manifest,
            LoadedManifest::Unsupported { .. } | LoadedManifest::UnsupportedLockfile { .. } => {
                return None
            }
        };
        Some(if manifest == "gems.rb" {
            ("gems.rb", "gems.locked")
        } else {
            ("Gemfile", "Gemfile.lock")
        })
    }

    /// The detail line for a caller that refuses an unsupported manifest.
    pub fn unsupported_detail(&self) -> Option<String> {
        match self {
            LoadedManifest::Unsupported { value, by } => {
                let remedy = match by {
                    GemfileSetting::Env => {
                        "unset BUNDLE_GEMFILE, or point it at the project's Gemfile"
                    }
                    GemfileSetting::AppConfig => {
                        "run `bundle config unset --local gemfile`, or point it at the \
                         project's Gemfile"
                    }
                    GemfileSetting::GlobalConfig => {
                        "run `bundle config unset --global gemfile`, or point it at the \
                         project's Gemfile"
                    }
                };
                Some(format!(
                    "bundler loads `{value}` ({}), not the project's Gemfile or gems.rb; \
                     socket-patch only wires those, so it left the gem manifests untouched \
                     ({remedy}, and re-run)",
                    by.describe()
                ))
            }
            LoadedManifest::UnsupportedLockfile { value, by } => {
                let (knob, remedy) = match by {
                    GemfileSetting::Env => (
                        "the BUNDLE_LOCKFILE environment variable",
                        "unset BUNDLE_LOCKFILE",
                    ),
                    GemfileSetting::AppConfig => (
                        "BUNDLE_LOCKFILE in the bundler app config (.bundle/config)",
                        "run `bundle config unset --local lockfile`",
                    ),
                    GemfileSetting::GlobalConfig => (
                        "BUNDLE_LOCKFILE in the global bundler config (~/.bundle/config)",
                        "run `bundle config unset --global lockfile`",
                    ),
                };
                Some(format!(
                    "bundler reads the lockfile `{value}` ({knob}), not the Gemfile.lock or \
                     gems.locked socket-patch pins; wiring the manifest alone would leave that \
                     lock unpinned and break frozen installs, so it left the gem manifests \
                     untouched ({remedy} to use the default lock, and re-run)"
                ))
            }
            _ => None,
        }
    }

    /// Layer Bundler 4's configured lockfile onto `self`: `lockfile_env`
    /// (`BUNDLE_LOCKFILE`) first, else `lockfile_config` (the app config's
    /// `BUNDLE_LOCKFILE:`), else `lockfile_global` (the global config's), as
    /// `Bundler::CLI` resolves it. A relative value
    /// is read against `root`, like `BUNDLE_GEMFILE`. A value naming the
    /// default lock of the pair bundler loads (given whether the root holds
    /// a `gems.rb`) leaves `self` unchanged; any other value is
    /// [`LoadedManifest::UnsupportedLockfile`]. An unsupported manifest
    /// stays the answer: it is refused either way.
    pub fn with_lockfile(
        self,
        root: &Path,
        lockfile_env: Option<&OsStr>,
        lockfile_config: Option<&str>,
        lockfile_global: Option<&str>,
        gems_rb_present: bool,
    ) -> LoadedManifest {
        let Some((_, lock)) = self.pair(gems_rb_present) else {
            return self;
        };
        // The first tier that holds the key wins, as in `Settings#[]`: a
        // present empty value shadows the tiers below and means the
        // default lock.
        let (value, by) = match (lockfile_env, lockfile_config, lockfile_global) {
            (Some(env), _, _) => (PathBuf::from(env), GemfileSetting::Env),
            (None, Some(config), _) => (PathBuf::from(config), GemfileSetting::AppConfig),
            (None, None, Some(global)) => (PathBuf::from(global), GemfileSetting::GlobalConfig),
            (None, None, None) => return self,
        };
        if value.as_os_str().is_empty() {
            return self;
        }
        let target = resolve_against(root, &value);
        let expected = resolve_against(root, Path::new(lock));
        if target.is_some() && target == expected {
            return self;
        }
        LoadedManifest::UnsupportedLockfile {
            value: value.display().to_string(),
            by,
        }
    }
}

/// The `BUNDLE_LOCKFILE:` value of a bundler config file (bundler 4's
/// `bundle config set lockfile <path>`). An empty value is still returned:
/// it shadows the tiers below it ([`LoadedManifest::with_lockfile`]).
pub fn config_lockfile(contents: &str) -> Option<String> {
    bundle_config_setting_including_empty(contents, "BUNDLE_LOCKFILE")
}

/// Why a `Gemfile` + `gems.rb` twin under DEFAULT discovery is never
/// wired: bundler 1.x loads the `Gemfile` and bundler >= 2 loads `gems.rb`,
/// and only the bundler that runs decides. A lock's `BUNDLED WITH` records
/// who wrote it, not who installs it (bundler >= 2 installs a 1.x lock and
/// 1.x installs a 2.x one, each from its own spelling), so nothing a scan
/// can read picks the pair and attesting either could leave the installed
/// one unpatched (#751). Vendored mode refuses the twin the same way.
pub fn twin_manifest_refusal() -> String {
    "both Gemfile and gems.rb are present; bundler 1.x loads the Gemfile while bundler >= 2 \
     loads gems.rb, and socket-patch cannot tell which bundler installs the project, so it \
     left the gem manifests untouched (remove the spelling you don't use, or set \
     BUNDLE_GEMFILE to the one you do, and re-run)"
        .to_string()
}

/// The `BUNDLE_GEMFILE:` value of a bundler app config file (flat YAML that
/// bundler writes itself). An empty string still shadows the global tier;
/// it does not replace a non-empty `BUNDLE_GEMFILE` already in the environment.
pub fn config_gemfile(contents: &str) -> Option<String> {
    bundle_config_setting_including_empty(contents, "BUNDLE_GEMFILE")
}

/// `value` resolved against `root` (an absolute value stands alone), made
/// absolute and lexically normalized; `None` when that is impossible.
fn resolve_against(root: &Path, value: &Path) -> Option<PathBuf> {
    let joined = if value.is_absolute() {
        value.to_path_buf()
    } else {
        root.join(value)
    };
    std::path::absolute(joined)
        .ok()
        .and_then(|p| normalize_lexically(&p))
}

/// Classify the configured `BUNDLE_GEMFILE` against `root`, which also
/// anchors a relative value: the app config value first, then the
/// environment — unless the environment names a manifest outside `root`,
/// which moves bundler's root (and with it the app config bundler reads)
/// away from this project — then the global config value. See the module
/// doc.
pub fn classify(
    root: &Path,
    gemfile_env: Option<&OsStr>,
    config_value: Option<&str>,
    global_value: Option<&str>,
) -> LoadedManifest {
    let env = gemfile_env.filter(|v| !v.is_empty()).map(PathBuf::from);
    let config = config_value.filter(|v| !v.is_empty()).map(PathBuf::from);
    let global = global_value.filter(|v| !v.is_empty()).map(PathBuf::from);
    let env_keeps_root = |env: &Path| {
        let dir = resolve_against(root, env).and_then(|p| p.parent().map(Path::to_path_buf));
        dir.is_some() && dir == resolve_against(root, Path::new(""))
    };
    let (value, by) = match (env, config) {
        (Some(env), Some(config)) if env_keeps_root(&env) => (config, GemfileSetting::AppConfig),
        (Some(env), _) => (env, GemfileSetting::Env),
        (None, Some(config)) => (config, GemfileSetting::AppConfig),
        // Settings#[] stops at a present empty value, so the global tier
        // is shadowed. configure_custom_gemfile only exports non-empty
        // values, leaving an existing non-empty env value in force above.
        (None, None) if gemfile_env.is_some() || config_value.is_some() => {
            return LoadedManifest::Default;
        }
        (None, None) => match global {
            Some(global) => (global, GemfileSetting::GlobalConfig),
            None => return LoadedManifest::Default,
        },
    };
    let display = value.display().to_string();
    let target = resolve_against(root, &value);
    let root = resolve_against(root, Path::new(""));
    if let (Some(target), Some(root)) = (target, root) {
        for manifest in ["Gemfile", "gems.rb"] {
            if target == root.join(manifest) {
                return LoadedManifest::Configured { manifest, by };
            }
        }
    }
    LoadedManifest::Unsupported { value: display, by }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        std::path::absolute("/proj").unwrap()
    }

    #[test]
    fn no_setting_is_bundlers_default_discovery() {
        let m = classify(&root(), None, None, None);
        assert_eq!(m, LoadedManifest::Default);
        assert_eq!(m.pair(true), Some(("gems.rb", "gems.locked")));
        assert_eq!(m.pair(false), Some(("Gemfile", "Gemfile.lock")));
        // An empty value is unset, as in bundler.
        assert_eq!(
            classify(&root(), Some(OsStr::new("")), Some(""), None),
            LoadedManifest::Default
        );
    }

    #[test]
    fn empty_higher_tiers_shadow_global_but_preserve_a_nonempty_environment() {
        for (env, config) in [(Some(""), None), (None, Some("")), (Some(""), Some(""))] {
            assert_eq!(
                classify(&root(), env.map(OsStr::new), config, Some("Gemfile.next")),
                LoadedManifest::Default
            );
        }
        // configure_custom_gemfile does not export the empty local value.
        assert_eq!(
            classify(
                &root(),
                Some(OsStr::new("Gemfile")),
                Some(""),
                Some("Gemfile.next")
            ),
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::Env
            }
        );
        for env in ["Gemfile.next", "../other/Gemfile"] {
            assert_eq!(
                classify(&root(), Some(OsStr::new(env)), Some(""), Some("gems.rb")),
                LoadedManifest::Unsupported {
                    value: env.into(),
                    by: GemfileSetting::Env
                }
            );
        }
        // A non-empty local setting still wins over an empty environment.
        assert_eq!(
            classify(
                &root(),
                Some(OsStr::new("")),
                Some("gems.rb"),
                Some("Gemfile.next")
            ),
            LoadedManifest::Configured {
                manifest: "gems.rb",
                by: GemfileSetting::AppConfig
            }
        );
    }

    #[test]
    fn config_naming_another_manifest_is_unsupported() {
        let m = classify(&root(), None, Some("Gemfile.next"), None);
        assert_eq!(
            m,
            LoadedManifest::Unsupported {
                value: "Gemfile.next".into(),
                by: GemfileSetting::AppConfig
            }
        );
        assert_eq!(m.pair(false), None);
        assert!(m.unsupported_detail().unwrap().contains("Gemfile.next"));
    }

    #[test]
    fn config_naming_the_default_spellings_selects_that_pair() {
        // `bundle config set --local gemfile Gemfile` beside a gems.rb:
        // bundler loads Gemfile + Gemfile.lock, not gems.rb.
        let m = classify(&root(), None, Some("Gemfile"), None);
        assert_eq!(m.pair(true), Some(("Gemfile", "Gemfile.lock")));
        let m = classify(&root(), None, Some("./gems.rb"), None);
        assert_eq!(m.pair(false), Some(("gems.rb", "gems.locked")));
        let abs = root().join("Gemfile");
        let m = classify(&root(), None, Some(abs.to_str().unwrap()), None);
        assert_eq!(m.pair(true), Some(("Gemfile", "Gemfile.lock")));
    }

    /// The app config wins over the environment, as in `Bundler::Settings`
    /// (local config has a higher priority than ENV, and `Bundler::CLI`
    /// re-exports the winning `gemfile` setting into `BUNDLE_GEMFILE`):
    /// `bundle config set --local gemfile Gemfile.next` plus an exported
    /// `BUNDLE_GEMFILE=Gemfile` makes bundler load `Gemfile.next` (#507).
    #[test]
    fn config_wins_over_env_like_bundler_settings() {
        let m = classify(
            &root(),
            Some(OsStr::new("Gemfile")),
            Some("Gemfile.next"),
            None,
        );
        assert_eq!(
            m,
            LoadedManifest::Unsupported {
                value: "Gemfile.next".into(),
                by: GemfileSetting::AppConfig
            }
        );
        // The remedy names the setting bundler actually uses.
        let detail = m.unsupported_detail().unwrap();
        assert!(
            detail.contains("bundle config unset --local gemfile"),
            "{detail}"
        );
        // Both naming supported spellings: the config's pair is wired.
        let m = classify(&root(), Some(OsStr::new("gems.rb")), Some("Gemfile"), None);
        assert_eq!(
            m,
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::AppConfig
            }
        );
        let m = classify(&root(), Some(OsStr::new("Gemfile")), Some("gems.rb"), None);
        assert_eq!(m.pair(false), Some(("gems.rb", "gems.locked")));
    }

    /// The environment applies when the app config sets nothing, and a
    /// relative value is read against the project root even when
    /// socket-patch runs elsewhere with `--cwd` (Bugbot on #431:
    /// `BUNDLE_GEMFILE=Gemfile` must select the project's Gemfile, not a
    /// file under the process cwd).
    #[test]
    fn env_applies_without_config_and_is_anchored_at_the_project_root() {
        let m = classify(&root(), Some(OsStr::new("Gemfile")), None, None);
        assert_eq!(
            m,
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::Env
            }
        );
        let m = classify(&root(), Some(OsStr::new("Gemfile.next")), None, None);
        assert!(matches!(
            m,
            LoadedManifest::Unsupported {
                by: GemfileSetting::Env,
                ..
            }
        ));
    }

    /// An environment `BUNDLE_GEMFILE` in ANOTHER directory moves bundler's
    /// root there (`Bundler.root` is the Gemfile's directory), so bundler
    /// reads that root's app config, never this project's: the project's
    /// `.bundle/config` cannot win, and the run refuses on the env value.
    #[test]
    fn env_gemfile_in_another_directory_is_never_overridden_by_project_config() {
        for env in ["../other/Gemfile", "sub/Gemfile", "/elsewhere/Gemfile"] {
            let m = classify(&root(), Some(OsStr::new(env)), Some("Gemfile"), None);
            assert_eq!(
                m,
                LoadedManifest::Unsupported {
                    value: env.into(),
                    by: GemfileSetting::Env
                },
                "{env}"
            );
        }
        // An absolute env value naming the root's own directory is the
        // same root: the config still wins.
        let abs = root().join("Gemfile.next");
        let m = classify(&root(), Some(abs.as_os_str()), Some("Gemfile"), None);
        assert_eq!(m.pair(false), Some(("Gemfile", "Gemfile.lock")));
    }

    /// The refusal names the remedy for the knob that set it: unsetting the
    /// environment variable does nothing to a `.bundle/config` setting.
    #[test]
    fn unsupported_detail_names_the_knob_that_set_it() {
        let env = classify(&root(), Some(OsStr::new("Gemfile.next")), None, None);
        let env = env.unsupported_detail().unwrap();
        assert!(env.contains("unset BUNDLE_GEMFILE"), "{env}");
        let config = classify(&root(), None, Some("Gemfile.next"), None);
        let config = config.unsupported_detail().unwrap();
        assert!(
            config.contains("bundle config unset --local gemfile"),
            "{config}"
        );
        assert!(!config.contains("unset BUNDLE_GEMFILE"), "{config}");
    }

    #[test]
    fn a_manifest_in_another_directory_is_unsupported() {
        let m = classify(&root(), None, Some("../other/Gemfile"), None);
        assert!(matches!(m, LoadedManifest::Unsupported { .. }));
        let m = classify(&root(), None, Some("sub/Gemfile"), None);
        assert!(matches!(m, LoadedManifest::Unsupported { .. }));
    }

    /// #749: a configured lockfile is judged against the pair bundler
    /// loads; a manifest refusal stays the answer.
    #[test]
    fn with_lockfile_accepts_only_the_pairs_own_lock() {
        let unset =
            classify(&root(), None, None, None).with_lockfile(&root(), None, None, None, false);
        assert_eq!(unset, LoadedManifest::Default);
        let own = classify(&root(), None, None, None).with_lockfile(
            &root(),
            Some(OsStr::new("Gemfile.lock")),
            None,
            None,
            false,
        );
        assert_eq!(own, LoadedManifest::Default);
        let custom = classify(&root(), None, None, None).with_lockfile(
            &root(),
            None,
            Some("custom.lock"),
            None,
            false,
        );
        assert_eq!(
            custom,
            LoadedManifest::UnsupportedLockfile {
                value: "custom.lock".into(),
                by: GemfileSetting::AppConfig
            }
        );
        let detail = custom.unsupported_detail().unwrap();
        assert!(detail.contains("custom.lock"), "{detail}");
        assert!(
            detail.contains("bundle config unset --local lockfile"),
            "{detail}"
        );
        // The other pair's lock is not what bundler loads with this manifest.
        let configured = classify(&root(), None, Some("Gemfile"), None).with_lockfile(
            &root(),
            Some(OsStr::new("gems.locked")),
            None,
            None,
            true,
        );
        assert!(matches!(
            configured,
            LoadedManifest::UnsupportedLockfile {
                by: GemfileSetting::Env,
                ..
            }
        ));
        assert!(configured
            .unsupported_detail()
            .unwrap()
            .contains("unset BUNDLE_LOCKFILE"));
        // An unsupported manifest keeps its own refusal.
        let manifest = classify(&root(), None, Some("Gemfile.next"), None).with_lockfile(
            &root(),
            Some(OsStr::new("custom.lock")),
            None,
            None,
            false,
        );
        assert!(matches!(manifest, LoadedManifest::Unsupported { .. }));
        // `bundle config set --global lockfile` is the lowest tier (#577's
        // global file feeds `Bundler.settings[:lockfile]` too).
        let global = classify(&root(), None, None, None).with_lockfile(
            &root(),
            None,
            None,
            Some("custom.lock"),
            false,
        );
        assert_eq!(
            global,
            LoadedManifest::UnsupportedLockfile {
                value: "custom.lock".into(),
                by: GemfileSetting::GlobalConfig
            }
        );
        assert!(global
            .unsupported_detail()
            .unwrap()
            .contains("bundle config unset --global lockfile"));
        let shadowed = classify(&root(), None, None, None).with_lockfile(
            &root(),
            None,
            Some("Gemfile.lock"),
            Some("custom.lock"),
            false,
        );
        assert_eq!(shadowed, LoadedManifest::Default);
        // A present empty value stops at its tier like `Settings#[]`: the
        // global custom lock is shadowed and bundler uses the default one.
        for (env, config) in [(Some(OsStr::new("")), None), (None, Some(""))] {
            let cleared = classify(&root(), None, None, None).with_lockfile(
                &root(),
                env,
                config,
                Some("custom.lock"),
                false,
            );
            assert_eq!(cleared, LoadedManifest::Default, "{env:?} {config:?}");
        }
    }

    #[test]
    fn config_lockfile_reads_bundlers_own_spelling() {
        assert_eq!(
            config_lockfile("---\nBUNDLE_LOCKFILE: \"custom.lock\"\n"),
            Some("custom.lock".into())
        );
        assert_eq!(
            config_lockfile("---\nBUNDLE_LOCKFILE: \"\"\n"),
            Some(String::new())
        );
        assert_eq!(config_lockfile("---\nBUNDLE_GEMFILE: \"x\"\n"), None);
    }

    #[test]
    fn config_gemfile_reads_bundlers_own_spelling() {
        assert_eq!(
            config_gemfile(
                "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_GEMFILE: \"Gemfile.next\"\n"
            ),
            Some("Gemfile.next".into())
        );
        assert_eq!(
            config_gemfile("---\nBUNDLE_GEMFILE: \"\"\n"),
            Some("".into())
        );
        assert_eq!(config_gemfile("---\nBUNDLE_PATH: \"x\"\n"), None);
    }
}
