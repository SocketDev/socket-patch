//! Install-channel detection for self-update.
//!
//! socket-patch ships through several channels, and only the standalone
//! ones (install.sh, manual tarball copy) own a binary that self-update may
//! replace. npm and PyPI bundle the binary inside a version-pinned package
//! directory — swapping it there desyncs the package manager's metadata and
//! the next `npm install` / `pip install` silently reverts the update. The
//! gem and Composer launchers exec a per-version cached binary they
//! re-resolve on every run, so replacing the cache entry is meaningless.
//! For all of those, `--update` refuses and prints the channel's own
//! upgrade command instead (`--force` overrides).
//!
//! Detection is a pure function over the canonicalized executable path plus
//! a snapshot of the relevant environment, so the heuristics are
//! table-testable across platforms without touching process state.

use std::path::{Component, Path, PathBuf};

/// How the currently-running binary appears to have been installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallChannel {
    /// install.sh, manual tarball download, or any unrecognized location —
    /// the binary is self-managed and safe to replace in place.
    Standalone,
    /// Inside a `node_modules` tree (the npm platform packages bundle the
    /// binary; the JS shim spawns it from there).
    Npm,
    /// Inside `site-packages`/`dist-packages` (the PyPI wheel bundles the
    /// binary under `socket_patch/bin/`).
    Pypi,
    /// Under `$CARGO_HOME/bin` — managed by `cargo install`.
    Cargo,
    /// Under the shared launcher cache (`<cache>/socket-patch/bin/…`) used
    /// by both the RubyGems and Composer launchers. The two share one
    /// layout and cannot be told apart from the path alone.
    LauncherCache,
    /// Under a Homebrew prefix (`Cellar`, `/opt/homebrew`).
    Homebrew,
}

/// Environment snapshot consumed by [`detect_channel`]. Captured by
/// [`ChannelEnv::from_env`] in production; constructed directly in tests.
#[derive(Debug, Default, Clone)]
pub struct ChannelEnv {
    pub cargo_home: Option<PathBuf>,
    pub xdg_cache_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub local_app_data: Option<PathBuf>,
}

impl ChannelEnv {
    /// Snapshot the process environment. Empty values count as unset,
    /// matching the CLI-wide `env_non_empty` convention.
    pub fn from_env() -> Self {
        fn path_var(name: &str) -> Option<PathBuf> {
            std::env::var(name)
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        }
        ChannelEnv {
            cargo_home: path_var("CARGO_HOME"),
            xdg_cache_home: path_var("XDG_CACHE_HOME"),
            home: path_var("HOME").or_else(|| path_var("USERPROFILE")),
            local_app_data: path_var("LOCALAPPDATA"),
        }
    }
}

/// Classify the canonicalized executable path. First match wins; anything
/// unrecognized is [`InstallChannel::Standalone`] (self-update proceeds).
///
/// Component matches are exact-component comparisons, not substring tests:
/// `/opt/my-node_modules-tools/socket-patch` must stay Standalone.
pub fn detect_channel(canonical_exe: &Path, env: &ChannelEnv) -> InstallChannel {
    if has_component(canonical_exe, "node_modules") {
        return InstallChannel::Npm;
    }
    if has_component(canonical_exe, "site-packages") || has_component(canonical_exe, "dist-packages")
    {
        return InstallChannel::Pypi;
    }
    if let Some(bin) = cargo_bin_dir(env) {
        if canonical_exe.starts_with(&bin) {
            return InstallChannel::Cargo;
        }
    }
    if launcher_cache_roots(env)
        .iter()
        .any(|root| canonical_exe.starts_with(root.join("socket-patch").join("bin")))
    {
        return InstallChannel::LauncherCache;
    }
    if has_component(canonical_exe, "Cellar")
        || canonical_exe.starts_with("/opt/homebrew")
        || canonical_exe.starts_with("/home/linuxbrew/.linuxbrew")
    {
        return InstallChannel::Homebrew;
    }
    InstallChannel::Standalone
}

/// The channel's own upgrade command, shown when `--update` refuses.
pub fn upgrade_hint(channel: InstallChannel) -> &'static str {
    match channel {
        InstallChannel::Standalone => "socket-patch --update",
        InstallChannel::Npm => "npm update -g @socketsecurity/socket-patch",
        InstallChannel::Pypi => "pip install --upgrade socket-patch",
        InstallChannel::Cargo => "cargo install socket-patch-cli",
        InstallChannel::LauncherCache => {
            "gem update socket-patch (RubyGems) or composer update socketsecurity/socket-patch"
        }
        InstallChannel::Homebrew => "brew upgrade socket-patch",
    }
}

/// Short human label for refusal messages ("managed by npm").
pub fn channel_label(channel: InstallChannel) -> &'static str {
    match channel {
        InstallChannel::Standalone => "standalone",
        InstallChannel::Npm => "npm",
        InstallChannel::Pypi => "pip",
        InstallChannel::Cargo => "cargo install",
        InstallChannel::LauncherCache => "the RubyGems/Composer launcher",
        InstallChannel::Homebrew => "Homebrew",
    }
}

fn has_component(path: &Path, name: &str) -> bool {
    path.components()
        .any(|c| matches!(c, Component::Normal(os) if os == std::ffi::OsStr::new(name)))
}

fn cargo_bin_dir(env: &ChannelEnv) -> Option<PathBuf> {
    if let Some(cargo_home) = &env.cargo_home {
        return Some(cargo_home.join("bin"));
    }
    env.home.as_ref().map(|h| h.join(".cargo").join("bin"))
}

/// Cache roots the gem/composer launchers resolve, in their probe order:
/// `$XDG_CACHE_HOME`, `~/.cache`, `%LOCALAPPDATA%`.
fn launcher_cache_roots(env: &ChannelEnv) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(xdg) = &env.xdg_cache_home {
        roots.push(xdg.clone());
    }
    if let Some(home) = &env.home {
        roots.push(home.join(".cache"));
    }
    if let Some(lad) = &env.local_app_data {
        roots.push(lad.clone());
    }
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with_home(home: &str) -> ChannelEnv {
        ChannelEnv {
            home: Some(PathBuf::from(home)),
            ..Default::default()
        }
    }

    #[test]
    fn npm_node_modules_component_detected() {
        let env = env_with_home("/home/u");
        for p in [
            "/home/u/lib/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch",
            "/usr/local/lib/node_modules/@socketsecurity/socket-patch-darwin-arm64/socket-patch",
            "/w/proj/node_modules/@socketsecurity/socket-patch-linux-x64-musl/socket-patch",
        ] {
            assert_eq!(
                detect_channel(Path::new(p), &env),
                InstallChannel::Npm,
                "{p}"
            );
        }
    }

    #[test]
    fn component_match_is_exact_not_substring() {
        // A directory that merely *contains* the marker text must not match:
        // component equality, not substring search.
        let env = env_with_home("/home/u");
        for p in [
            "/opt/my-node_modules-tools/socket-patch",
            "/srv/site-packages-backup/socket-patch",
            "/data/Cellar-archive/socket-patch",
        ] {
            assert_eq!(
                detect_channel(Path::new(p), &env),
                InstallChannel::Standalone,
                "{p}"
            );
        }
    }

    #[test]
    fn pypi_site_and_dist_packages_detected() {
        let env = env_with_home("/home/u");
        for p in [
            "/venv/lib/python3.12/site-packages/socket_patch/bin/socket-patch",
            // Debian system pythons use dist-packages.
            "/usr/lib/python3/dist-packages/socket_patch/bin/socket-patch",
        ] {
            assert_eq!(
                detect_channel(Path::new(p), &env),
                InstallChannel::Pypi,
                "{p}"
            );
        }
    }

    #[test]
    fn cargo_bin_via_home_fallback() {
        let env = env_with_home("/home/u");
        assert_eq!(
            detect_channel(Path::new("/home/u/.cargo/bin/socket-patch"), &env),
            InstallChannel::Cargo
        );
        // A different user's .cargo/bin is NOT ours.
        assert_eq!(
            detect_channel(Path::new("/home/other/.cargo/bin/socket-patch"), &env),
            InstallChannel::Standalone
        );
    }

    #[test]
    fn cargo_home_env_overrides_home_fallback() {
        let env = ChannelEnv {
            cargo_home: Some(PathBuf::from("/opt/rust/cargo")),
            home: Some(PathBuf::from("/home/u")),
            ..Default::default()
        };
        assert_eq!(
            detect_channel(Path::new("/opt/rust/cargo/bin/socket-patch"), &env),
            InstallChannel::Cargo
        );
        // With CARGO_HOME set, the ~/.cargo/bin fallback is NOT consulted —
        // cargo itself resolves exactly one home.
        assert_eq!(
            detect_channel(Path::new("/home/u/.cargo/bin/socket-patch"), &env),
            InstallChannel::Standalone
        );
    }

    #[test]
    fn launcher_cache_detected_via_xdg_then_home() {
        let env = ChannelEnv {
            xdg_cache_home: Some(PathBuf::from("/home/u/.custom-cache")),
            home: Some(PathBuf::from("/home/u")),
            ..Default::default()
        };
        for p in [
            "/home/u/.custom-cache/socket-patch/bin/3.3.0/x86_64-unknown-linux-gnu/socket-patch",
            "/home/u/.cache/socket-patch/bin/3.3.0/aarch64-apple-darwin/socket-patch",
        ] {
            assert_eq!(
                detect_channel(Path::new(p), &env),
                InstallChannel::LauncherCache,
                "{p}"
            );
        }
        // The state file the notifier writes lives at
        // <cache>/socket-patch/update-check.json — only the bin/ subtree is
        // launcher territory. A hypothetical binary directly under the
        // socket-patch cache root is standalone.
        assert_eq!(
            detect_channel(Path::new("/home/u/.cache/socket-patch/socket-patch"), &env),
            InstallChannel::Standalone
        );
    }

    #[test]
    fn homebrew_prefixes_detected() {
        let env = env_with_home("/Users/u");
        for p in [
            "/opt/homebrew/bin/socket-patch",
            "/usr/local/Cellar/socket-patch/3.3.0/bin/socket-patch",
            "/home/linuxbrew/.linuxbrew/bin/socket-patch",
        ] {
            assert_eq!(
                detect_channel(Path::new(p), &env),
                InstallChannel::Homebrew,
                "{p}"
            );
        }
    }

    #[test]
    fn standalone_install_locations_pass() {
        let env = env_with_home("/home/u");
        for p in [
            "/usr/local/bin/socket-patch",
            "/home/u/.local/bin/socket-patch",
            "/home/u/bin/socket-patch",
            "/tmp/wherever/socket-patch",
        ] {
            assert_eq!(
                detect_channel(Path::new(p), &env),
                InstallChannel::Standalone,
                "{p}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_detected() {
        // Backslash-separated paths only split into components on Windows,
        // so these spellings can't be exercised from the Unix test runs.
        let env = ChannelEnv {
            home: Some(PathBuf::from(r"C:\Users\u")),
            local_app_data: Some(PathBuf::from(r"C:\Users\u\AppData\Local")),
            ..Default::default()
        };
        assert_eq!(
            detect_channel(
                Path::new(
                    r"C:\Users\u\AppData\Roaming\npm\node_modules\@socketsecurity\socket-patch-win32-x64\socket-patch.exe"
                ),
                &env
            ),
            InstallChannel::Npm
        );
        assert_eq!(
            detect_channel(
                Path::new(r"C:\Users\u\.cargo\bin\socket-patch.exe"),
                &env
            ),
            InstallChannel::Cargo
        );
        assert_eq!(
            detect_channel(
                Path::new(
                    r"C:\Users\u\AppData\Local\socket-patch\bin\3.3.0\x86_64-pc-windows-msvc\socket-patch.exe"
                ),
                &env
            ),
            InstallChannel::LauncherCache
        );
        assert_eq!(
            detect_channel(Path::new(r"C:\tools\socket-patch.exe"), &env),
            InstallChannel::Standalone
        );
    }

    #[test]
    fn hints_route_to_the_owning_manager() {
        assert!(upgrade_hint(InstallChannel::Npm).contains("npm update -g"));
        assert!(upgrade_hint(InstallChannel::Pypi).contains("pip install --upgrade"));
        assert!(upgrade_hint(InstallChannel::Cargo).contains("cargo install"));
        assert!(upgrade_hint(InstallChannel::LauncherCache).contains("gem update"));
        assert!(upgrade_hint(InstallChannel::LauncherCache).contains("composer update"));
        assert!(upgrade_hint(InstallChannel::Homebrew).contains("brew upgrade"));
        assert!(upgrade_hint(InstallChannel::Standalone).contains("--update"));
    }
}
