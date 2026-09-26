//! Install-channel detection for self-update.
//!
//! socket-patch ships through several channels, and only the standalone
//! ones (install.sh, manual tarball copy) own a binary that self-update may
//! replace. npm and PyPI bundle the binary inside a version-pinned package
//! directory — swapping it there desyncs the package manager's metadata and
//! the next `npm install` / `pip install` silently reverts the update. The
//! gem launcher execs a per-version cached binary it re-resolves on every
//! run, so replacing the cache entry is meaningless.
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
    /// Under the launcher cache (`<cache>/socket-patch/bin/…`) used by the
    /// RubyGems launcher.
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
    if has_component(canonical_exe, "site-packages")
        || has_component(canonical_exe, "dist-packages")
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
        InstallChannel::LauncherCache => "gem update socket-patch",
        InstallChannel::Homebrew => "brew upgrade socket-patch",
    }
}

/// [`upgrade_hint`] for the binary at `canonical_exe`. An npm install is
/// either global (`<prefix>/lib/node_modules`, `%APPDATA%\npm\node_modules`,
/// a yarn/pnpm `global` store, a Windows version-manager dir such as
/// nvm-windows' `%APPDATA%\nvm\v20.11.0\node_modules`), where
/// `npm update -g` is right, or a project dependency
/// (`<project>/node_modules`), where `-g` would update some other copy and
/// leave this one alone. A project that vlt installed (its root holds
/// `vlt-lock.json`) upgrades through vlt, and vlx's cache dir (a project
/// whose `package.json` is named `vlx`, under `$XDG_DATA_HOME/vlt/vlx/`)
/// is refreshed by running vlx with `@latest`.
pub fn upgrade_hint_for(channel: InstallChannel, canonical_exe: &Path) -> &'static str {
    if channel == InstallChannel::Npm && !is_global_npm_install(canonical_exe) {
        let holder = outermost_node_modules_holder(canonical_exe);
        if holder.is_some_and(is_vlx_cache_dir) {
            return "vlx -y -- @socketsecurity/socket-patch@latest …";
        }
        if holder.is_some_and(|dir| dir.join(crate::constants::npm_family::VLT_LOCK).is_file()) {
            return "vlt install @socketsecurity/socket-patch@latest";
        }
        return "npm install @socketsecurity/socket-patch@latest";
    }
    upgrade_hint(channel)
}

/// vlx installs each package into its own project dir whose generated
/// `package.json` is named `vlx`.
fn is_vlx_cache_dir(dir: &Path) -> bool {
    crate::utils::fs::read_regular_to_string_sync(&dir.join("package.json"))
        .ok()
        .and_then(|text| {
            serde_json::from_str::<serde_json::Value>(crate::package_json::detect::strip_bom(&text))
                .ok()
        })
        .is_some_and(|pkg| pkg.get("name").and_then(|n| n.as_str()) == Some("vlx"))
}

/// The directory holding the outermost `node_modules` of `path`, keeping
/// the path's own prefix (drive, root). `ancestors` walks innermost-first,
/// so the LAST `node_modules` is the outermost one.
fn outermost_node_modules_holder(path: &Path) -> Option<&Path> {
    path.ancestors()
        .filter(|a| a.file_name().is_some_and(|n| n == "node_modules"))
        .last()
        .and_then(Path::parent)
}

/// Whether the outermost `node_modules` of `path` belongs to a global
/// install. The well-known global layouts (directly under `lib` on a Unix
/// prefix or `npm` on Windows, or anywhere below a yarn/pnpm `global`
/// store) decide without touching the disk. Otherwise the directory that
/// holds the outermost `node_modules` decides: a project has a
/// `package.json` there, while a global prefix without a `lib/` level
/// (nvm-windows `…\nvm\v20.11.0`, fnm `…\installation`, Volta's image
/// dirs) does not. Defaulting to global when unsure is the safer miss:
/// `npm install …` run from an arbitrary cwd would scaffold a stray
/// `node_modules`/`package.json` there and leave the real copy stale.
fn is_global_npm_install(path: &Path) -> bool {
    let names: Vec<&std::ffi::OsStr> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os),
            _ => None,
        })
        .collect();
    let Some(first_nm) = names.iter().position(|n| *n == "node_modules") else {
        return false;
    };
    let parent = first_nm.checked_sub(1).map(|i| names[i]);
    if matches!(parent, Some(p) if p == "lib" || p == "npm")
        || names[..first_nm].iter().any(|n| *n == "global")
    {
        return true;
    }
    match outermost_node_modules_holder(path) {
        Some(dir) => !dir.join("package.json").is_file(),
        None => true,
    }
}

/// Short human label for refusal messages ("managed by npm").
pub fn channel_label(channel: InstallChannel) -> &'static str {
    match channel {
        InstallChannel::Standalone => "standalone",
        InstallChannel::Npm => "npm",
        InstallChannel::Pypi => "pip",
        InstallChannel::Cargo => "cargo install",
        InstallChannel::LauncherCache => "the RubyGems launcher",
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

/// Cache roots the gem launcher resolves, in its probe order:
/// `$XDG_CACHE_HOME`, `~/.cache`, `%LOCALAPPDATA%`, and the launcher's
/// Windows fallback when LOCALAPPDATA is unset — `~/AppData/Local`
/// (launcher.rb: `ENV["LOCALAPPDATA"] || File.join(Dir.home, "AppData",
/// "Local")`).
fn launcher_cache_roots(env: &ChannelEnv) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(xdg) = &env.xdg_cache_home {
        roots.push(xdg.clone());
    }
    if let Some(home) = &env.home {
        roots.push(home.join(".cache"));
        roots.push(home.join("AppData").join("Local"));
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
    fn launcher_cache_detected_via_home_appdata_fallback() {
        // launcher.rb resolves the Windows cache root as
        // `ENV["LOCALAPPDATA"] || File.join(Dir.home, "AppData", "Local")` —
        // with LOCALAPPDATA stripped it still caches under the home
        // fallback, and detection must still refuse there. Forward-slash
        // spelling so the component walk exercises this on Unix runners too
        // (the backslash spelling is covered by `windows_paths_detected`).
        let env = env_with_home("C:/Users/u");
        assert_eq!(
            detect_channel(
                Path::new(
                    "C:/Users/u/AppData/Local/socket-patch/bin/3.3.0/x86_64-pc-windows-msvc/socket-patch.exe"
                ),
                &env
            ),
            InstallChannel::LauncherCache
        );
        // Only the socket-patch/bin subtree — a sibling app's cache is not ours.
        assert_eq!(
            detect_channel(
                Path::new("C:/Users/u/AppData/Local/other-tool/bin/other-tool.exe"),
                &env
            ),
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
            detect_channel(Path::new(r"C:\Users\u\.cargo\bin\socket-patch.exe"), &env),
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
    fn empty_env_skips_cargo_probe() {
        // A fully stripped environment (no CARGO_HOME, no HOME/USERPROFILE,
        // e.g. a minimal container): cargo_bin_dir has nothing to resolve, so
        // the cargo probe is skipped entirely and even a path that *looks*
        // like someone's ~/.cargo/bin stays Standalone.
        let env = ChannelEnv::default();
        for p in [
            "/home/u/.cargo/bin/socket-patch",
            "/usr/local/bin/socket-patch",
        ] {
            assert_eq!(
                detect_channel(Path::new(p), &env),
                InstallChannel::Standalone,
                "{p}"
            );
        }
    }

    #[test]
    fn launcher_cache_detected_via_localappdata_root() {
        // LOCALAPPDATA is a launcher cache root in its own right (launcher.rb
        // reads ENV["LOCALAPPDATA"] before the home fallback). Forward-slash
        // spelling so the component walk exercises this on Unix runners too
        // (the backslash spelling is covered by `windows_paths_detected`).
        // Home is deliberately unset so only the LOCALAPPDATA root can match.
        let env = ChannelEnv {
            local_app_data: Some(PathBuf::from("C:/Users/u/AppData/Local")),
            ..Default::default()
        };
        let cached = Path::new(
            "C:/Users/u/AppData/Local/socket-patch/bin/3.3.0/x86_64-pc-windows-msvc/socket-patch.exe",
        );
        assert_eq!(detect_channel(cached, &env), InstallChannel::LauncherCache);
        // Without LOCALAPPDATA (and no home fallback) the same path has no
        // root to match against — proving the refusal above came from the
        // LOCALAPPDATA root, not another heuristic.
        assert_eq!(
            detect_channel(cached, &ChannelEnv::default()),
            InstallChannel::Standalone
        );
    }

    #[test]
    fn channel_label_covers_every_channel() {
        // Exact strings: these feed the "--update refused: managed by <label>"
        // message, so a drift here is user-visible wording.
        assert_eq!(channel_label(InstallChannel::Standalone), "standalone");
        assert_eq!(channel_label(InstallChannel::Npm), "npm");
        assert_eq!(channel_label(InstallChannel::Pypi), "pip");
        assert_eq!(channel_label(InstallChannel::Cargo), "cargo install");
        assert_eq!(
            channel_label(InstallChannel::LauncherCache),
            "the RubyGems launcher"
        );
        assert_eq!(channel_label(InstallChannel::Homebrew), "Homebrew");
    }

    #[test]
    fn npm_hint_tells_global_from_project_installs() {
        let global = [
            "/usr/local/lib/node_modules/@socketsecurity/socket-patch/node_modules/@socketsecurity/socket-patch-darwin-arm64/bin/socket-patch",
            "/home/u/.nvm/versions/node/v20.1.0/lib/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
            "/home/u/.config/yarn/global/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
            "/Users/u/Library/pnpm/global/5/node_modules/@socketsecurity/socket-patch-darwin-arm64/bin/socket-patch",
        ];
        for p in global {
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, Path::new(p)),
                "npm update -g @socketsecurity/socket-patch",
                "{p}"
            );
        }
        // A project install: the dir holding the outermost node_modules has
        // a package.json.
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        let local = [
            "node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
            // `lib` deeper than the outermost node_modules is not a prefix.
            "node_modules/x/lib/node_modules/y/bin/socket-patch",
        ];
        for rel in local {
            let p = project.path().join(rel);
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &p),
                "npm install @socketsecurity/socket-patch@latest",
                "{}",
                p.display()
            );
        }
        // A node_modules with no package.json beside it and no lib/ level:
        // a version-manager global prefix (nvm-windows, fnm, Volta), so
        // `npm update -g` (running `npm install` from an arbitrary cwd
        // would scaffold a stray project there).
        let prefixes = ["nvm/v20.11.0", "fnm/node-versions/v20.11.0/installation"];
        for prefix in prefixes {
            let root = tempfile::tempdir().unwrap();
            let p = root
                .path()
                .join(prefix)
                .join("node_modules/@socketsecurity/socket-patch-win32-x64/bin/socket-patch.exe");
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &p),
                "npm update -g @socketsecurity/socket-patch",
                "{}",
                p.display()
            );
        }
        // Other channels are path-independent.
        assert_eq!(
            upgrade_hint_for(InstallChannel::Pypi, Path::new("/work/app/node_modules/x")),
            upgrade_hint(InstallChannel::Pypi)
        );
    }

    /// A vlt project install lives in the project's own store
    /// (`node_modules/.vlt/<DepID>/node_modules/…`), so the outermost
    /// `node_modules` holder is the project root and its `vlt-lock.json`
    /// routes the hint to vlt. vlx's cache dir is also a vlt project (it
    /// carries a lock too) whose generated `package.json` is named `vlx`;
    /// re-running vlx with `@latest` is what refreshes it.
    #[test]
    fn vlt_project_and_vlx_cache_hints() {
        let bin = "node_modules/.vlt/~npm~@socketsecurity+socket-patch-linux-x64@2.0.0/\
                   node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch";

        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), r#"{"name":"app"}"#).unwrap();
        let exe = project.path().join(bin);
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &exe),
            "npm install @socketsecurity/socket-patch@latest",
            "no vlt-lock.json: an npm project"
        );
        std::fs::write(project.path().join("vlt-lock.json"), "{}").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &exe),
            "vlt install @socketsecurity/socket-patch@latest"
        );
        // A lock in a nested dir between the holder and the binary is not
        // the holder's.
        let nested = tempfile::tempdir().unwrap();
        std::fs::write(nested.path().join("package.json"), "{}").unwrap();
        std::fs::create_dir_all(nested.path().join("node_modules/.vlt")).unwrap();
        std::fs::write(nested.path().join("node_modules/.vlt/vlt-lock.json"), "{}").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &nested.path().join(bin)),
            "npm install @socketsecurity/socket-patch@latest"
        );

        let data = tempfile::tempdir().unwrap();
        let vlx = data
            .path()
            .join("vlt/vlx/@socketsecurity+socket-patch-b040b66d");
        std::fs::create_dir_all(&vlx).unwrap();
        std::fs::write(
            vlx.join("package.json"),
            "\u{feff}{\"name\":\"vlx\",\"dependencies\":{}}",
        )
        .unwrap();
        std::fs::write(vlx.join("vlt-lock.json"), "{}").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &vlx.join(bin)),
            "vlx -y -- @socketsecurity/socket-patch@latest …"
        );
        // A project merely named like vlx's dir but with another name is a
        // vlt project, not the vlx cache.
        std::fs::write(vlx.join("package.json"), r#"{"name":"vlxx"}"#).unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &vlx.join(bin)),
            "vlt install @socketsecurity/socket-patch@latest"
        );
        // Global installs keep the global hint whatever vlt files exist.
        assert_eq!(
            upgrade_hint_for(
                InstallChannel::Npm,
                Path::new(
                    "/usr/local/lib/node_modules/@socketsecurity/socket-patch/bin/socket-patch"
                )
            ),
            "npm update -g @socketsecurity/socket-patch"
        );
    }

    #[cfg(windows)]
    #[test]
    fn npm_hint_windows_global_prefix() {
        let p = Path::new(
            r"C:\Users\u\AppData\Roaming\npm\node_modules\@socketsecurity\socket-patch-win32-x64\bin\socket-patch.exe",
        );
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, p),
            "npm update -g @socketsecurity/socket-patch"
        );
    }

    #[test]
    fn hints_route_to_the_owning_manager() {
        assert!(upgrade_hint(InstallChannel::Npm).contains("npm update -g"));
        assert!(upgrade_hint(InstallChannel::Pypi).contains("pip install --upgrade"));
        assert!(upgrade_hint(InstallChannel::Cargo).contains("cargo install"));
        assert!(upgrade_hint(InstallChannel::LauncherCache).contains("gem update"));
        assert!(upgrade_hint(InstallChannel::Homebrew).contains("brew upgrade"));
        assert!(upgrade_hint(InstallChannel::Standalone).contains("--update"));
    }
}
