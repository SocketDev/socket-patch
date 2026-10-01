//! Which manifest Bundler loads for a project: the ONE answer shared by the
//! hosted rewriter's caller and the vendored backend, so neither can wire a
//! file Bundler ignores.
//!
//! Bundler's own order (`Bundler::SharedHelpers#default_gemfile` and the CLI's
//! `gemfile` setting):
//!
//! 1. `BUNDLE_GEMFILE` from the environment (a relative value expands
//!    against the process cwd, as `File.expand_path` does);
//! 2. `BUNDLE_GEMFILE:` in the app config file, `$BUNDLE_APP_CONFIG/config`
//!    else `<root>/.bundle/config` (what `bundle config set --local gemfile
//!    Gemfile.next` writes; relative to the project root);
//! 3. otherwise `gems.rb` when present, else `Gemfile`.
//!
//! A configured value that names the root's own `Gemfile` or `gems.rb` is
//! that spelling; anything else (`Gemfile.next`, a file in another
//! directory, a missing file) is [`LoadedManifest::Unsupported`]: the
//! rewriters and the lock readers only know the two default pairs, so the
//! callers fail closed rather than wire a manifest Bundler never reads.
//! The user-level `~/.bundle/config` is not consulted.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::crawlers::ruby_crawler::{bundler_app_config_dir, unquote_bundle_config_value};
use crate::utils::fs::normalize_lexically;

/// Where a configured `BUNDLE_GEMFILE` came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GemfileSetting {
    /// The `BUNDLE_GEMFILE` environment variable.
    Env,
    /// `BUNDLE_GEMFILE:` in the project's bundler app config file.
    AppConfig,
}

impl GemfileSetting {
    /// How the setting is named in warnings and refusals.
    pub fn describe(self) -> &'static str {
        match self {
            GemfileSetting::Env => "the BUNDLE_GEMFILE environment variable",
            GemfileSetting::AppConfig => {
                "BUNDLE_GEMFILE in the bundler app config (.bundle/config)"
            }
        }
    }
}

/// The manifest Bundler loads for a project root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadedManifest {
    /// No `BUNDLE_GEMFILE`: Bundler's default discovery (`gems.rb` first,
    /// then `Gemfile`), which callers apply to the files they see.
    Default,
    /// `BUNDLE_GEMFILE` names the root's own `Gemfile` or `gems.rb`.
    Configured {
        manifest: &'static str,
        by: GemfileSetting,
    },
    /// `BUNDLE_GEMFILE` names any other file.
    Unsupported { value: String, by: GemfileSetting },
}

impl LoadedManifest {
    /// The manifest/lock pair Bundler loads, given whether the root holds a
    /// `gems.rb`. `None` for [`LoadedManifest::Unsupported`].
    pub fn pair(&self, gems_rb_present: bool) -> Option<(&'static str, &'static str)> {
        let manifest = match self {
            LoadedManifest::Default if gems_rb_present => "gems.rb",
            LoadedManifest::Default => "Gemfile",
            LoadedManifest::Configured { manifest, .. } => manifest,
            LoadedManifest::Unsupported { .. } => return None,
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
            LoadedManifest::Unsupported { value, by } => Some(format!(
                "bundler loads `{value}` ({}), not the project's Gemfile or gems.rb; \
                 socket-patch only wires those, so it left the gem manifests untouched (unset \
                 BUNDLE_GEMFILE, or point it at the project's Gemfile, and re-run)",
                by.describe()
            )),
            _ => None,
        }
    }
}

/// [`classify`] for `root` on disk, reading the ambient `BUNDLE_GEMFILE` /
/// `BUNDLE_APP_CONFIG` and the app config file.
pub async fn loaded_manifest(root: &Path) -> LoadedManifest {
    loaded_manifest_with_env(
        root,
        std::env::var_os("BUNDLE_GEMFILE").as_deref(),
        std::env::var_os("BUNDLE_APP_CONFIG").as_deref(),
    )
    .await
}

/// [`loaded_manifest`] with the environment passed explicitly (hermetic
/// tests).
pub async fn loaded_manifest_with_env(
    root: &Path,
    gemfile_env: Option<&OsStr>,
    app_config_env: Option<&OsStr>,
) -> LoadedManifest {
    let config = bundler_app_config_dir(root, app_config_env).join("config");
    let config_value = crate::utils::fs::read_regular_to_string(&config)
        .await
        .ok()
        .and_then(|text| config_gemfile(&text));
    let cwd = std::env::current_dir().unwrap_or_default();
    classify(root, &cwd, gemfile_env, config_value.as_deref())
}

/// The `BUNDLE_GEMFILE:` value of a bundler app config file (flat YAML that
/// bundler writes itself; an empty value counts as unset).
pub fn config_gemfile(contents: &str) -> Option<String> {
    let mut found = None;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("BUNDLE_GEMFILE:") {
            let v = unquote_bundle_config_value(rest);
            found = (!v.is_empty()).then(|| v.to_string());
        }
    }
    found
}

/// Classify the configured `BUNDLE_GEMFILE` (environment first, then the
/// app config value) against `root`. `cwd` anchors a relative environment
/// value; a relative config value is anchored at `root`.
pub fn classify(
    root: &Path,
    cwd: &Path,
    gemfile_env: Option<&OsStr>,
    config_value: Option<&str>,
) -> LoadedManifest {
    let (value, base, by) = match gemfile_env.filter(|v| !v.is_empty()) {
        Some(v) => (PathBuf::from(v), cwd, GemfileSetting::Env),
        None => match config_value.filter(|v| !v.is_empty()) {
            Some(v) => (PathBuf::from(v), root, GemfileSetting::AppConfig),
            None => return LoadedManifest::Default,
        },
    };
    let display = value.display().to_string();
    let absolute = |p: &Path| {
        std::path::absolute(p)
            .ok()
            .and_then(|p| normalize_lexically(&p))
    };
    let target = if value.is_absolute() {
        absolute(&value)
    } else {
        absolute(&base.join(&value))
    };
    let root = absolute(root);
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
        let m = classify(&root(), &root(), None, None);
        assert_eq!(m, LoadedManifest::Default);
        assert_eq!(m.pair(true), Some(("gems.rb", "gems.locked")));
        assert_eq!(m.pair(false), Some(("Gemfile", "Gemfile.lock")));
        // An empty value is unset, as in bundler.
        assert_eq!(
            classify(&root(), &root(), Some(OsStr::new("")), Some("")),
            LoadedManifest::Default
        );
    }

    #[test]
    fn config_naming_another_manifest_is_unsupported() {
        let m = classify(&root(), &root(), None, Some("Gemfile.next"));
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
        let m = classify(&root(), &root(), None, Some("Gemfile"));
        assert_eq!(m.pair(true), Some(("Gemfile", "Gemfile.lock")));
        let m = classify(&root(), &root(), None, Some("./gems.rb"));
        assert_eq!(m.pair(false), Some(("gems.rb", "gems.locked")));
        let abs = root().join("Gemfile");
        let m = classify(&root(), &root(), None, Some(abs.to_str().unwrap()));
        assert_eq!(m.pair(true), Some(("Gemfile", "Gemfile.lock")));
    }

    #[test]
    fn env_wins_over_config_and_expands_against_the_cwd() {
        let m = classify(
            &root(),
            &root().join("sub"),
            Some(OsStr::new("../Gemfile")),
            Some("Gemfile.next"),
        );
        assert_eq!(
            m,
            LoadedManifest::Configured {
                manifest: "Gemfile",
                by: GemfileSetting::Env
            }
        );
        let m = classify(&root(), &root(), Some(OsStr::new("Gemfile.next")), None);
        assert!(matches!(
            m,
            LoadedManifest::Unsupported {
                by: GemfileSetting::Env,
                ..
            }
        ));
    }

    #[test]
    fn a_manifest_in_another_directory_is_unsupported() {
        let m = classify(&root(), &root(), None, Some("../other/Gemfile"));
        assert!(matches!(m, LoadedManifest::Unsupported { .. }));
        let m = classify(&root(), &root(), None, Some("sub/Gemfile"));
        assert!(matches!(m, LoadedManifest::Unsupported { .. }));
    }

    #[test]
    fn config_gemfile_reads_bundlers_own_spelling() {
        assert_eq!(
            config_gemfile(
                "---\nBUNDLE_PATH: \"vendor/bundle\"\nBUNDLE_GEMFILE: \"Gemfile.next\"\n"
            ),
            Some("Gemfile.next".into())
        );
        assert_eq!(config_gemfile("---\nBUNDLE_GEMFILE: \"\"\n"), None);
        assert_eq!(config_gemfile("---\nBUNDLE_PATH: \"x\"\n"), None);
    }

    #[tokio::test]
    async fn loaded_manifest_reads_the_app_config_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".bundle")).unwrap();
        std::fs::write(
            dir.path().join(".bundle/config"),
            "---\nBUNDLE_GEMFILE: \"Gemfile.next\"\n",
        )
        .unwrap();
        let m = loaded_manifest_with_env(dir.path(), None, None).await;
        assert!(matches!(
            m,
            LoadedManifest::Unsupported {
                by: GemfileSetting::AppConfig,
                ..
            }
        ));
        // BUNDLE_APP_CONFIG moves the config file away from `.bundle`.
        let m = loaded_manifest_with_env(dir.path(), None, Some(OsStr::new("elsewhere"))).await;
        assert_eq!(m, LoadedManifest::Default);
    }
}
