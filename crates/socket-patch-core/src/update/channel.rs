//! Install-channel detection for self-update.
//!
//! socket-patch ships through several channels, and only the standalone
//! ones (install.sh, manual tarball copy) own a binary that self-update may
//! replace. npm bundles the binary inside a version-pinned package directory;
//! swapping it there desyncs the package manager's metadata. Legacy PyPI
//! installs and RubyGems launcher caches remain protected for the same reason,
//! but their hints migrate to a supported distribution: v5 no longer publishes
//! those packages. `--update` refuses managed installs and prints an upgrade
//! or migration command instead (`--force` overrides).
//!
//! Detection is a pure function over the canonicalized executable path plus
//! a snapshot of the relevant environment, so the heuristics are
//! table-testable across platforms without touching process state.

use crate::formats::yarn::berry_gates::{YARNRC, YARN_LOCK};
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
    /// Inside `site-packages`/`dist-packages` (the pre-v5 PyPI wheel bundled the
    /// binary under `socket_patch/bin/`).
    Pypi,
    /// Under `$CARGO_HOME/bin` — managed by `cargo install`.
    Cargo,
    /// Under the launcher cache (`<cache>/socket-patch/bin/…`) used by the
    /// pre-v5 RubyGems launcher.
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
            home: crate::utils::fs::home_dir(),
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

/// The channel's upgrade or migration command, shown when `--update` refuses.
pub fn upgrade_hint(channel: InstallChannel) -> &'static str {
    match channel {
        InstallChannel::Standalone => "socket-patch --update",
        InstallChannel::Npm => "npm update -g @socketsecurity/socket-patch",
        InstallChannel::Pypi if cfg!(windows) => {
            "pip uninstall socket-patch && npm install -g @socketsecurity/socket-patch"
        }
        InstallChannel::Pypi => {
            "pip uninstall socket-patch && curl -fsSL https://install.socket.dev/patch | sh"
        }
        InstallChannel::Cargo => "cargo install socket-patch-cli",
        InstallChannel::LauncherCache if cfg!(windows) => {
            "gem uninstall socket-patch && npm install -g @socketsecurity/socket-patch"
        }
        InstallChannel::LauncherCache => {
            "gem uninstall socket-patch && curl -fsSL https://install.socket.dev/patch | sh"
        }
        InstallChannel::Homebrew => "brew upgrade socket-patch",
    }
}

/// [`upgrade_hint`] for the binary at `canonical_exe`. A `node_modules`
/// install is upgraded through the package manager that owns it
/// ([`node_manager`]):
///
/// - npm: a global install (`<prefix>/lib/node_modules`,
///   `%APPDATA%\npm\node_modules`, a Windows
///   version-manager dir such as nvm-windows'
///   `%APPDATA%\nvm\v20.11.0\node_modules`) takes `npm update -g`; a
///   project dependency (`<project>/node_modules`) takes `npm install …`,
///   since `-g` would update some other copy and leave this one alone.
/// - pnpm: `pnpm add -g …@latest` for its global store, `pnpm add …@latest`
///   in a project, and `pnpm update --recursive --latest …` at a workspace
///   root, which refuses a bare `pnpm add` and whose members may declare the
///   dependency. npm's commands are wrong here: `npm update -g` never sees
///   pnpm's global store, and `npm install` in a pnpm project writes a
///   stray `package-lock.json` and leaves `pnpm-lock.yaml` stale.
/// - vlt: a project that vlt installed (its root holds `vlt-lock.json`)
///   upgrades through vlt, and vlx's cache dir (a project whose
///   `package.json` is named `vlx`, under `$XDG_DATA_HOME/vlt/vlx/`) is
///   refreshed by running vlx with `@latest`.
/// - Bun: `bun add -g …@latest` for its global store (`bun update -g`
///   keeps the exact version Bun's global manifest pins), `bun add
///   …@latest` in a project, and bunx's cache dir (`bunx-<uid>-<spec>`) is
///   refreshed by running bunx with `@latest`. npm's commands fail here the
///   same way they do for pnpm, and `npm install` breaks the next
///   `bun install --frozen-lockfile`.
/// - yarn: `yarn global add …@latest` for its global folder (`npm update
///   -g` never looks there); in a project, `yarn up …@latest` on yarn 2+
///   (it updates every workspace that declares the dependency) and `yarn
///   add …@latest` on yarn 1. A yarn 1 workspace root refuses a bare `yarn
///   add`: `yarn upgrade … --latest` there updates the root's own
///   declaration, and `yarn upgrade-interactive --latest` is the one
///   command that reaches a member's. `npm install` in a yarn project
///   writes a stray `package-lock.json` beside `yarn.lock`.
pub fn upgrade_hint_for(channel: InstallChannel, canonical_exe: &Path) -> &'static str {
    if channel != InstallChannel::Npm {
        return upgrade_hint(channel);
    }
    let global = is_global_npm_install(canonical_exe);
    let holder = outermost_node_modules_holder(canonical_exe);
    match node_manager(canonical_exe) {
        NodeManager::Pnpm if global => "pnpm add -g @socketsecurity/socket-patch@latest",
        NodeManager::Pnpm
            if holder.is_some_and(|dir| {
                dir.join(crate::utils::pnpm_workspace::PNPM_WORKSPACE)
                    .is_file()
            }) =>
        {
            "pnpm update --recursive --latest @socketsecurity/socket-patch"
        }
        NodeManager::Pnpm => "pnpm add @socketsecurity/socket-patch@latest",
        NodeManager::Bun if global => "bun add -g @socketsecurity/socket-patch@latest",
        NodeManager::Bun => "bun add @socketsecurity/socket-patch@latest",
        NodeManager::Bunx => "bunx @socketsecurity/socket-patch@latest …",
        NodeManager::Yarn
            if is_yarn_global_store(canonical_exe) || is_prefix_global_install(canonical_exe) =>
        {
            "yarn global add @socketsecurity/socket-patch@latest"
        }
        NodeManager::Yarn => match holder.map(read_package_json) {
            _ if holder.is_some_and(is_yarn_berry_project) => {
                "yarn up @socketsecurity/socket-patch@latest"
            }
            Some(Some(pkg)) if declares_workspaces(&pkg) && declares_socket_patch(&pkg) => {
                "yarn upgrade @socketsecurity/socket-patch --latest"
            }
            Some(Some(pkg)) if declares_workspaces(&pkg) => "yarn upgrade-interactive --latest",
            _ => "yarn add @socketsecurity/socket-patch@latest",
        },
        _ if global => upgrade_hint(channel),
        NodeManager::Vlx => "vlx -y -- @socketsecurity/socket-patch@latest …",
        NodeManager::Vlt => "vlt install @socketsecurity/socket-patch@latest",
        NodeManager::Npm => "npm install @socketsecurity/socket-patch@latest",
    }
}

/// Short human label for refusal messages ("managed by pnpm"): the
/// [`channel_label`], naming the npm-family manager for a `node_modules`
/// install.
pub fn channel_label_for(channel: InstallChannel, canonical_exe: &Path) -> &'static str {
    if channel != InstallChannel::Npm {
        return channel_label(channel);
    }
    match node_manager(canonical_exe) {
        NodeManager::Npm => "npm",
        NodeManager::Pnpm => "pnpm",
        NodeManager::Bun | NodeManager::Bunx => "bun",
        NodeManager::Yarn => "yarn",
        NodeManager::Vlt | NodeManager::Vlx => "vlt",
    }
}

/// The npm-family manager that owns a `node_modules` install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeManager {
    Npm,
    Pnpm,
    Bun,
    Bunx,
    Yarn,
    Vlt,
    Vlx,
}

/// Classify the owner of the `node_modules` install at `path`. vlt is only
/// recognized for project installs (its lockfile beside the outermost
/// `node_modules`, or vlx's cache project); pnpm by its `.pnpm` virtual
/// store in the canonical path (every isolated-linker install, global or
/// project), a `pnpm` home above a `global` store, or a `pnpm-lock.yaml`
/// beside the outermost `node_modules` (`node-linker=hoisted`). Bun by
/// its `install/global` store, a `.bun` isolated-linker store inside
/// `node_modules`, or a `bun.lock` / `bun.lockb` beside the outermost
/// `node_modules`; bunx by its cache dir's name. Yarn by its global folder
/// ([`is_yarn_global_store`]) or a `yarn.lock` beside the outermost
/// `node_modules`, after pnpm's and Bun's and only when no npm lock sits
/// there too (a project mid-migration keeps npm's hint). Anything else is
/// npm.
fn node_manager(path: &Path) -> NodeManager {
    let holder = outermost_node_modules_holder(path);
    // bunx's cache is told by its dir name alone, whether or not the dir
    // still holds a package.json.
    if holder.is_some_and(is_bunx_cache_dir) {
        return NodeManager::Bunx;
    }
    if !is_global_npm_install(path) {
        if holder.is_some_and(is_vlx_cache_dir) {
            return NodeManager::Vlx;
        }
        if holder.is_some_and(|dir| dir.join(crate::constants::npm_family::VLT_LOCK).is_file()) {
            return NodeManager::Vlt;
        }
    }
    // A store in the path names the manager that wrote it, ahead of any
    // lockfile left beside the project (e.g. mid-migration).
    if has_component(path, ".pnpm") || is_pnpm_global_store(path) {
        return NodeManager::Pnpm;
    }
    if is_bun_global_store(path) || has_component_after_node_modules(path, ".bun") {
        return NodeManager::Bun;
    }
    let holder_has = |lock: &str| holder.is_some_and(|dir| dir.join(lock).is_file());
    if holder_has(crate::constants::npm_family::PNPM_LOCK) {
        return NodeManager::Pnpm;
    }
    if holder_has(crate::constants::npm_family::BUN_LOCK)
        || holder_has(crate::constants::npm_family::BUN_LOCKB)
    {
        return NodeManager::Bun;
    }
    if is_yarn_global_store(path)
        || (holder_has(YARN_LOCK)
            && !crate::constants::npm_family::NPM_LOCKS
                .iter()
                .any(|lock| holder_has(lock)))
    {
        return NodeManager::Yarn;
    }
    NodeManager::Npm
}

/// Yarn's global folder (`yarn global dir`): the `global` dir that holds
/// the first `node_modules`, below a `yarn` home (`~/.config/yarn/global`,
/// `/usr/local/share/.config/yarn/global` as root) or `Yarn\Data` on
/// Windows, or holding yarn's own `yarn.lock` (a `global-folder` set
/// elsewhere). A project that merely sits under some `global` dir is not.
fn is_yarn_global_store(path: &Path) -> bool {
    let names = normal_components(path);
    let Some(first_nm) = names.iter().position(|n| *n == "node_modules") else {
        return false;
    };
    let is = |i: Option<usize>, name: &str| {
        i.and_then(|i| names[i].to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
    };
    let at = |back: usize| first_nm.checked_sub(back);
    if !is(at(1), "global") {
        return false;
    }
    is(at(2), "yarn")
        || (is(at(2), "data") && is(at(3), "yarn"))
        || outermost_node_modules_holder(path).is_some_and(|dir| dir.join(YARN_LOCK).is_file())
}

/// A yarn 2+ project: `.yarnrc.yml` (which yarn 1 never reads), a berry
/// `yarn.lock`, or a `packageManager` pin to yarn 2 or later.
fn is_yarn_berry_project(dir: &Path) -> bool {
    dir.join(YARNRC).is_file()
        || yarn_lock_head(dir).is_some_and(|head| crate::formats::yarn::is_berry_lock(&head))
        || read_package_json(dir).is_some_and(|pkg| {
            pkg.get("packageManager")
                .and_then(|pm| pm.as_str())
                .and_then(|pm| pm.strip_prefix("yarn@"))
                .and_then(|version| version.split('.').next())
                .and_then(|major| major.parse::<u32>().ok())
                .is_some_and(|major| major >= 2)
        })
}

/// The start of `dir`'s `yarn.lock`: both grammars announce themselves in
/// the first lines (berry's `__metadata:` block, yarn 1's header comment),
/// and this runs on the update notifier's path, so a large lock is not
/// read whole.
fn yarn_lock_head(dir: &Path) -> Option<String> {
    use std::io::Read as _;
    let (file, _) = crate::utils::fs::open_regular_file_sync(&dir.join(YARN_LOCK)).ok()?;
    let mut head = Vec::new();
    file.take(4096).read_to_end(&mut head).ok()?;
    Some(String::from_utf8_lossy(&head).into_owned())
}

/// The parsed `package.json` in `dir`, if it reads as JSON.
fn read_package_json(dir: &Path) -> Option<serde_json::Value> {
    let text = crate::utils::fs::read_regular_to_string_sync(&dir.join("package.json")).ok()?;
    serde_json::from_str(crate::formats::text::strip_bom(&text)).ok()
}

/// Whether a `package.json` declares workspaces: a non-empty array, or the
/// `{ "packages": [...] }` form with a non-empty `packages`.
fn declares_workspaces(pkg: &serde_json::Value) -> bool {
    let globs = match pkg.get("workspaces") {
        Some(serde_json::Value::Object(obj)) => obj.get("packages"),
        other => other,
    };
    globs
        .and_then(|g| g.as_array())
        .is_some_and(|g| !g.is_empty())
}

/// Whether a `package.json` itself declares socket-patch in any dependency
/// section.
fn declares_socket_patch(pkg: &serde_json::Value) -> bool {
    ["dependencies", "devDependencies", "optionalDependencies"]
        .iter()
        .any(|section| {
            pkg.get(section)
                .and_then(|deps| deps.get("@socketsecurity/socket-patch"))
                .is_some()
        })
}

/// Bun's global store, `$BUN_INSTALL/install/global/node_modules`
/// (`~/.bun/install/global`, `%USERPROFILE%\.bun\install\global`).
fn is_bun_global_store(path: &Path) -> bool {
    let names = normal_components(path);
    names
        .iter()
        .position(|n| *n == "node_modules")
        .is_some_and(|nm| nm >= 2 && names[nm - 1] == "global" && names[nm - 2] == "install")
}

/// Whether `name` is a component inside the first `node_modules` of `path`
/// (Bun's isolated linker keeps its store at `node_modules/.bun/`; a `.bun`
/// above it is `$BUN_INSTALL`, which [`is_bun_global_store`] covers).
fn has_component_after_node_modules(path: &Path, name: &str) -> bool {
    let names = normal_components(path);
    names
        .iter()
        .position(|n| *n == "node_modules")
        .is_some_and(|nm| names[nm + 1..].iter().any(|n| *n == name))
}

/// bunx installs each spec into its own project dir,
/// `$TMPDIR/bunx-<uid>-<spec>` with a numeric uid; a scoped spec splits it
/// in two (`bunx-<uid>-@scope/name@version`).
fn is_bunx_cache_dir(dir: &Path) -> bool {
    // The `<spec>` part of `bunx-<uid>-<spec>`.
    fn bunx_spec(dir: &Path) -> Option<&str> {
        let rest = dir.file_name()?.to_str()?.strip_prefix("bunx-")?;
        let (uid, spec) = rest.split_once('-')?;
        (!uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit())).then_some(spec)
    }
    bunx_spec(dir).is_some_and(|spec| !spec.is_empty())
        || dir
            .parent()
            .and_then(bunx_spec)
            .is_some_and(|scope| scope.len() > 1 && scope.starts_with('@'))
}

fn normal_components(path: &Path) -> Vec<&std::ffi::OsStr> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(os) => Some(os),
            _ => None,
        })
        .collect()
}

/// A `global` store below a `pnpm` home (`~/Library/pnpm/global/5`,
/// `~/.local/share/pnpm/global/v11/<hash>`, `%LOCALAPPDATA%\pnpm\global\5`).
fn is_pnpm_global_store(path: &Path) -> bool {
    let names = normal_components(path);
    let first_nm = names
        .iter()
        .position(|n| *n == "node_modules")
        .unwrap_or(names.len());
    names[..first_nm]
        .iter()
        .position(|n| *n == "global")
        .is_some_and(|g| names[..g].iter().any(|n| *n == "pnpm"))
}

/// vlx installs each package into its own project dir whose generated
/// `package.json` is named `vlx`.
fn is_vlx_cache_dir(dir: &Path) -> bool {
    read_package_json(dir)
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
/// install: a prefix layout ([`is_prefix_global_install`]) or anywhere
/// below a `global` store (yarn's, pnpm's). Defaulting to global when
/// unsure is the safer miss: `npm install …` run from an arbitrary cwd
/// would scaffold a stray `node_modules`/`package.json` there and leave
/// the real copy stale.
fn is_global_npm_install(path: &Path) -> bool {
    let names = normal_components(path);
    let Some(first_nm) = names.iter().position(|n| *n == "node_modules") else {
        return false;
    };
    names[..first_nm].iter().any(|n| *n == "global") || is_prefix_global_install(path)
}

/// A global prefix: the first `node_modules` sits directly under `lib` on
/// a Unix prefix (including Volta's package images, whose `lib/` also
/// holds yarn's package.json and yarn.lock after a `yarn global add`) or
/// `npm` on Windows, which decides without touching the disk. Otherwise
/// the directory that holds the outermost `node_modules` decides: a
/// project has a `package.json` there, while a prefix without a `lib/`
/// level (nvm-windows `…\nvm\v20.11.0`, fnm `…\installation`) does not.
fn is_prefix_global_install(path: &Path) -> bool {
    let names = normal_components(path);
    let Some(first_nm) = names.iter().position(|n| *n == "node_modules") else {
        return false;
    };
    let parent = first_nm.checked_sub(1).map(|i| names[i]);
    if matches!(parent, Some(p) if p == "lib" || p == "npm") {
        return true;
    }
    match outermost_node_modules_holder(path) {
        Some(dir) => !dir.join("package.json").is_file(),
        None => true,
    }
}

/// Short human label for refusal messages ("managed by npm"); see
/// [`channel_label_for`] for the npm-family manager of a given path.
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

/// Cache roots the pre-v5 gem launcher resolved, in its probe order:
/// `$XDG_CACHE_HOME`, `~/.cache`, `%LOCALAPPDATA%`, and the launcher's
/// Windows fallback when LOCALAPPDATA is unset — `~/AppData/Local`
/// (`ENV["LOCALAPPDATA"] || File.join(Dir.home, "AppData", "Local")`).
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

    /// #1111: a pnpm install upgrades through pnpm. `npm update -g` is a
    /// no-op for a pnpm global store, and `npm install` in a pnpm project
    /// writes a stray package-lock.json and leaves pnpm-lock.yaml stale.
    #[test]
    fn pnpm_global_installs_get_pnpm_add_g() {
        let global = [
            // pnpm 9/10, macOS default PNPM_HOME.
            "/Users/u/Library/pnpm/global/5/node_modules/.pnpm/@socketsecurity+socket-patch-darwin-arm64@4.0.0/node_modules/@socketsecurity/socket-patch-darwin-arm64/bin/socket-patch",
            // The store root itself, as the old table row listed it.
            "/Users/u/Library/pnpm/global/5/node_modules/@socketsecurity/socket-patch-darwin-arm64/bin/socket-patch",
            // pnpm 12 (`global/v11/<hash>`), Linux default PNPM_HOME.
            "/home/u/.local/share/pnpm/global/v11/ab12cd/node_modules/.pnpm/@socketsecurity+socket-patch-linux-x64@4.0.0/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
            // A custom PNPM_HOME without a `pnpm` component: the virtual
            // store (`.pnpm`) still names the manager.
            "/opt/tools/global/5/node_modules/.pnpm/@socketsecurity+socket-patch-linux-x64@4.0.0/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
        ];
        for p in global {
            let p = Path::new(p);
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, p),
                "pnpm add -g @socketsecurity/socket-patch@latest",
                "{}",
                p.display()
            );
            assert_eq!(channel_label_for(InstallChannel::Npm, p), "pnpm");
        }
        // Yarn's global store is not pnpm's.
        let yarn = Path::new(
            "/home/u/.config/yarn/global/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
        );
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, yarn),
            "yarn global add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, yarn), "yarn");
    }

    #[test]
    fn pnpm_project_installs_get_pnpm_add() {
        let isolated = "node_modules/.pnpm/@socketsecurity+socket-patch-linux-x64@4.0.0/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch";
        let hoisted = "node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch";

        // The default isolated linker: the `.pnpm` virtual store decides,
        // even before the first `pnpm install` wrote a lockfile.
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        let p = project.path().join(isolated);
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "pnpm add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, &p), "pnpm");
        // `node-linker=hoisted` has no `.pnpm`: pnpm-lock.yaml decides.
        let p = project.path().join(hoisted);
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "npm install @socketsecurity/socket-patch@latest"
        );
        std::fs::write(project.path().join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "pnpm add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, &p), "pnpm");

        // A workspace root refuses a bare `pnpm add` (ERR_PNPM_ADDING_TO_ROOT)
        // and the dependency may be declared by any member, so update it
        // wherever it is declared.
        let ws = tempfile::tempdir().unwrap();
        std::fs::write(ws.path().join("package.json"), "{}").unwrap();
        std::fs::write(ws.path().join("pnpm-workspace.yaml"), "packages: [a]\n").unwrap();
        let p = ws.path().join(isolated);
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "pnpm update --recursive --latest @socketsecurity/socket-patch"
        );
    }

    /// #1621: a Bun install upgrades through Bun. `npm update -g` never
    /// sees Bun's global store, and `npm install` in a Bun project writes a
    /// stray package-lock.json and leaves bun.lock stale, so the next
    /// `bun install --frozen-lockfile` fails.
    #[test]
    fn bun_global_installs_get_bun_add_g() {
        let global = [
            // The default `$BUN_INSTALL` (`~/.bun`).
            "/home/u/.bun/install/global/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch",
            "/Users/u/.bun/install/global/node_modules/@socketsecurity/socket-patch/node_modules/@socketsecurity/socket-patch-darwin-arm64/bin/socket-patch",
            // A custom `$BUN_INSTALL` without a `.bun` component.
            "/opt/bunhome/install/global/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch",
        ];
        for p in global {
            let p = Path::new(p);
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, p),
                "bun add -g @socketsecurity/socket-patch@latest",
                "{}",
                p.display()
            );
            assert_eq!(channel_label_for(InstallChannel::Npm, p), "bun");
        }
        // Neither npm's `lib` prefix nor yarn's global store is Bun's.
        let npm = Path::new(
            "/usr/local/lib/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
        );
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, npm),
            "npm update -g @socketsecurity/socket-patch"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, npm), "npm");
        let yarn = Path::new(
            "/home/u/.config/yarn/global/node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch",
        );
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, yarn),
            "yarn global add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, yarn), "yarn");
    }

    #[test]
    fn bun_project_installs_get_bun_add() {
        let hoisted = "node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch";
        let isolated = "node_modules/.bun/@socketsecurity+socket-patch-linux-x64-gnu@4.0.0/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch";

        // Bun's isolated linker: the `.bun` store decides, lock or not.
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        let p = project.path().join(isolated);
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "bun add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, &p), "bun");
        // The `.bun` store is Bun's even beside a pnpm lock left over from
        // a migration.
        std::fs::write(project.path().join("pnpm-lock.yaml"), "").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "bun add @socketsecurity/socket-patch@latest"
        );
        std::fs::remove_file(project.path().join("pnpm-lock.yaml")).unwrap();
        // The hoisted linker: the text or binary lockfile decides.
        let p = project.path().join(hoisted);
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "npm install @socketsecurity/socket-patch@latest"
        );
        for lock in ["bun.lock", "bun.lockb"] {
            let project = tempfile::tempdir().unwrap();
            std::fs::write(project.path().join("package.json"), "{}").unwrap();
            std::fs::write(project.path().join(lock), "").unwrap();
            let p = project.path().join(hoisted);
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &p),
                "bun add @socketsecurity/socket-patch@latest",
                "{lock}"
            );
            assert_eq!(channel_label_for(InstallChannel::Npm, &p), "bun");
        }
        // A lock in a nested dir between the holder and the binary is not
        // the holder's.
        let nested = tempfile::tempdir().unwrap();
        std::fs::write(nested.path().join("package.json"), "{}").unwrap();
        std::fs::create_dir_all(nested.path().join("node_modules/x")).unwrap();
        std::fs::write(nested.path().join("node_modules/x/bun.lock"), "").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &nested.path().join(hoisted)),
            "npm install @socketsecurity/socket-patch@latest"
        );
    }

    /// bunx installs each spec into `$TMPDIR/bunx-<uid>-<spec>`, a project
    /// dir with its own package.json and lock; a scoped spec nests one
    /// level (`bunx-0-@scope/name@version`). Re-running bunx with `@latest`
    /// is what refreshes it, while `bun add` there would edit the cache.
    #[test]
    fn bunx_cache_gets_bunx_latest() {
        let bin = "node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch";
        let tmp = tempfile::tempdir().unwrap();
        for dir in [
            "bunx-0-@socketsecurity/socket-patch@4.0.0",
            "bunx-1000-socket-patch-shim@1.0.0",
        ] {
            let holder = tmp.path().join(dir);
            std::fs::create_dir_all(&holder).unwrap();
            std::fs::write(holder.join("package.json"), "{}").unwrap();
            std::fs::write(holder.join("bun.lock"), "").unwrap();
            let p = holder.join(bin);
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &p),
                "bunx @socketsecurity/socket-patch@latest …",
                "{dir}"
            );
            assert_eq!(channel_label_for(InstallChannel::Npm, &p), "bun");
        }
        // A cache dir without its package.json (which would otherwise read
        // as a global prefix) is still bunx's.
        let holder = tmp
            .path()
            .join("bunx-501-@socketsecurity/socket-patch@4.0.0");
        std::fs::create_dir_all(&holder).unwrap();
        std::fs::write(holder.join("bun.lockb"), "").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &holder.join(bin)),
            "bunx @socketsecurity/socket-patch@latest …"
        );
        // A Bun project merely named like the cache, or nested below one
        // without a scope level, is a Bun project.
        for dir in [
            "bunx-tools",
            "bunx-x-y",
            "bunx-0-x/apps",
            "bunx-0-x/apps/web",
        ] {
            let holder = tmp.path().join(dir);
            std::fs::create_dir_all(&holder).unwrap();
            std::fs::write(holder.join("package.json"), "{}").unwrap();
            std::fs::write(holder.join("bun.lock"), "").unwrap();
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &holder.join(bin)),
                "bun add @socketsecurity/socket-patch@latest",
                "{dir}"
            );
        }
    }

    /// #1629: a yarn install upgrades through yarn. `npm update -g` never
    /// looks in yarn's global folder (it prints "up to date" and leaves the
    /// yarn copy stale), and `npm install` in a yarn project writes a stray
    /// package-lock.json beside yarn.lock.
    #[test]
    fn yarn_global_installs_get_yarn_global_add() {
        let global = [
            // `yarn global dir` on Linux and macOS.
            "/home/u/.config/yarn/global/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch",
            "/Users/u/.config/yarn/global/node_modules/@socketsecurity/socket-patch/node_modules/@socketsecurity/socket-patch-darwin-arm64/bin/socket-patch",
            // ... as root.
            "/usr/local/share/.config/yarn/global/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch",
            // ... on Windows (`%LOCALAPPDATA%\Yarn\Data\global`).
            "/c/Users/u/AppData/Local/Yarn/Data/global/node_modules/@socketsecurity/socket-patch-win32-x64/socket-patch.exe",
        ];
        for p in global {
            let p = Path::new(p);
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, p),
                "yarn global add @socketsecurity/socket-patch@latest",
                "{}",
                p.display()
            );
            assert_eq!(channel_label_for(InstallChannel::Npm, p), "yarn");
        }
        // A global folder elsewhere (`--global-folder` / `global-folder`)
        // that is still named `global`: its yarn.lock names the owner.
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path().join("tools/global");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::write(store.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        let p = store.join("node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch");
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "npm update -g @socketsecurity/socket-patch",
            "no yarn.lock: not yarn's"
        );
        std::fs::write(store.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "yarn global add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, &p), "yarn");
        // Volta runs `yarn global add` with its global folder set to the
        // package image's `lib/`, so yarn's package.json and yarn.lock sit
        // beside a prefix-style `lib/node_modules`. That is still a global
        // install: `yarn add` from the user's cwd would edit their project
        // and leave the Volta copy stale.
        let image = tmp
            .path()
            .join(".volta/tools/image/packages/@socketsecurity/socket-patch/lib");
        std::fs::create_dir_all(&image).unwrap();
        std::fs::write(image.join("package.json"), r#"{"dependencies":{}}"#).unwrap();
        std::fs::write(image.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        let p = image.join(
            "node_modules/@socketsecurity/socket-patch/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch",
        );
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "yarn global add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, &p), "yarn");
        // A `global` dir with no yarn home above it and no yarn.lock stays
        // an npm global.
        assert_eq!(
            upgrade_hint_for(
                InstallChannel::Npm,
                Path::new("/opt/global/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch"),
            ),
            "npm update -g @socketsecurity/socket-patch"
        );
    }

    #[test]
    fn yarn_project_installs_get_yarn_add() {
        let bin = "node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch";

        // Yarn 1: yarn.lock beside the outermost node_modules.
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), r#"{"name":"app"}"#).unwrap();
        let p = project.path().join(bin);
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "npm install @socketsecurity/socket-patch@latest"
        );
        std::fs::write(project.path().join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "yarn add @socketsecurity/socket-patch@latest"
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, &p), "yarn");

        // A yarn 1 workspace root refuses a bare `yarn add` without -W,
        // and `yarn upgrade` there never touches a member's declaration;
        // `upgrade-interactive` lists every workspace's dependencies.
        std::fs::write(
            project.path().join("package.json"),
            r#"{"private":true,"workspaces":["packages/*"]}"#,
        )
        .unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "yarn upgrade-interactive --latest"
        );
        // ... including the object form of `workspaces`.
        std::fs::write(
            project.path().join("package.json"),
            r#"{"private":true,"workspaces":{"packages":["a"]}}"#,
        )
        .unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "yarn upgrade-interactive --latest"
        );
        // When the root declares socket-patch itself, `yarn upgrade` updates
        // that declaration in place (and keeps its section).
        std::fs::write(
            project.path().join("package.json"),
            r#"{"private":true,"workspaces":["a"],"devDependencies":{"@socketsecurity/socket-patch":"^4.0.0"}}"#,
        )
        .unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &p),
            "yarn upgrade @socketsecurity/socket-patch --latest"
        );
        // An empty `workspaces` (or one with only `nohoist`) is no workspace
        // root.
        for manifest in [
            r#"{"workspaces":[]}"#,
            r#"{"workspaces":{"nohoist":["**/x"]}}"#,
        ] {
            std::fs::write(project.path().join("package.json"), manifest).unwrap();
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &p),
                "yarn add @socketsecurity/socket-patch@latest",
                "{manifest}"
            );
        }
        // An npm lock beside yarn.lock (a project mid-migration) keeps
        // npm's hint, as before.
        for lock in ["package-lock.json", "npm-shrinkwrap.json"] {
            std::fs::write(project.path().join(lock), "{}").unwrap();
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &p),
                "npm install @socketsecurity/socket-patch@latest",
                "{lock}"
            );
            assert_eq!(channel_label_for(InstallChannel::Npm, &p), "npm");
            std::fs::remove_file(project.path().join(lock)).unwrap();
        }
        // A yarn project that sits below some `global` dir is still a
        // project, not yarn's global folder.
        let tmp = tempfile::tempdir().unwrap();
        let app = tmp.path().join("global/app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("package.json"), r#"{"name":"app"}"#).unwrap();
        std::fs::write(app.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &app.join(bin)),
            "yarn add @socketsecurity/socket-patch@latest"
        );

        // Yarn 2+ (node-modules linker): `yarn up` upgrades every
        // workspace that declares the dependency, and works outside one.
        for berry_marker in ["lock", "yarnrc", "packageManager"] {
            let berry = tempfile::tempdir().unwrap();
            std::fs::write(berry.path().join("package.json"), r#"{"name":"app"}"#).unwrap();
            if berry_marker == "packageManager" {
                std::fs::write(berry.path().join("yarn.lock"), "").unwrap();
                std::fs::write(
                    berry.path().join("package.json"),
                    r#"{"name":"app","packageManager":"yarn@4.5.0+sha512.abc"}"#,
                )
                .unwrap();
            } else if berry_marker == "lock" {
                std::fs::write(
                    berry.path().join("yarn.lock"),
                    "__metadata:\n  version: 8\n  cacheKey: 10c0\n",
                )
                .unwrap();
            } else {
                std::fs::write(berry.path().join("yarn.lock"), "").unwrap();
                std::fs::write(
                    berry.path().join(".yarnrc.yml"),
                    "nodeLinker: node-modules\n",
                )
                .unwrap();
            }
            let p = berry.path().join(bin);
            assert_eq!(
                upgrade_hint_for(InstallChannel::Npm, &p),
                "yarn up @socketsecurity/socket-patch@latest",
                "{berry_marker}"
            );
            assert_eq!(channel_label_for(InstallChannel::Npm, &p), "yarn");
        }

        // pnpm's and Bun's lockfiles outrank a leftover yarn.lock, and so
        // does a store component in the path.
        for lock in ["pnpm-lock.yaml", "bun.lock"] {
            let mixed = tempfile::tempdir().unwrap();
            std::fs::write(mixed.path().join("package.json"), "{}").unwrap();
            std::fs::write(mixed.path().join("yarn.lock"), "").unwrap();
            std::fs::write(mixed.path().join(lock), "").unwrap();
            assert_ne!(
                channel_label_for(InstallChannel::Npm, &mixed.path().join(bin)),
                "yarn",
                "{lock}"
            );
        }
        let pnpm_store = project.path().join(
            "node_modules/.pnpm/@socketsecurity+socket-patch-linux-x64-gnu@4.0.0/node_modules/@socketsecurity/socket-patch-linux-x64-gnu/socket-patch",
        );
        assert_eq!(channel_label_for(InstallChannel::Npm, &pnpm_store), "pnpm");

        // A yarn.lock in a nested dir between the holder and the binary is
        // not the holder's.
        let nested = tempfile::tempdir().unwrap();
        std::fs::write(nested.path().join("package.json"), "{}").unwrap();
        std::fs::create_dir_all(nested.path().join("node_modules/x")).unwrap();
        std::fs::write(nested.path().join("node_modules/x/yarn.lock"), "").unwrap();
        assert_eq!(
            upgrade_hint_for(InstallChannel::Npm, &nested.path().join(bin)),
            "npm install @socketsecurity/socket-patch@latest"
        );
    }

    #[test]
    fn labels_name_the_owning_node_manager() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("package.json"), "{}").unwrap();
        let bin = project
            .path()
            .join("node_modules/@socketsecurity/socket-patch-linux-x64/bin/socket-patch");
        assert_eq!(channel_label_for(InstallChannel::Npm, &bin), "npm");
        std::fs::write(project.path().join("vlt-lock.json"), "{}").unwrap();
        assert_eq!(channel_label_for(InstallChannel::Npm, &bin), "vlt");
        // Non-npm channels keep their path-independent label.
        assert_eq!(
            channel_label_for(InstallChannel::Homebrew, &bin),
            channel_label(InstallChannel::Homebrew)
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
        assert!(upgrade_hint(InstallChannel::Cargo).contains("cargo install"));
        assert!(upgrade_hint(InstallChannel::Homebrew).contains("brew upgrade"));
        assert!(upgrade_hint(InstallChannel::Standalone).contains("--update"));
    }
}
