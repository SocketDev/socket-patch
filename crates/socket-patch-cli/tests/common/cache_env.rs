//! Package-manager cache isolation for the integration tests.
//!
//! Several suites do REAL installs as part of their fixture setup — `npm
//! install`, `corepack yarn install`, `pnpm install`, `bun install`, `go
//! build`, `pip install`, `gem install`, `bundle install`. None of that is
//! `#[ignore]`d, so a plain `cargo test` runs it, and with no environment of
//! its own every one of those commands writes into the home directory of
//! whoever ran the suite: the npm cache, the pnpm store, the Go build cache,
//! the corepack download cache, the RubyGems spec cache.
//!
//! That is bad twice over. It pollutes the machine, and it makes results
//! depend on what happened to be lying around — a fixture install can succeed
//! against a package that a previous, unrelated run already cached, and the
//! same test then fails on a clean CI runner.
//!
//! [`isolate`] fixes one child process. Call it on the `Command` for any
//! package manager the tests spawn, and everything that tool caches lands
//! under [`cache_root`] instead.
//!
//! ## Setting `HOME` is not enough
//!
//! Every tool below reads its own variable *in preference to* `HOME`, so a
//! redirected home alone leaves the real cache in play whenever a developer
//! (or a CI action — `pnpm/action-setup` exports `PNPM_HOME`) has one of them
//! exported. Each is therefore pinned explicitly. The two that catch people
//! out:
//!
//! * `GOCACHE` is a **separate** cache from `GOPATH`/`GOMODCACHE`. Setting
//!   the module cache and stopping there still leaves `go build` writing its
//!   compiled objects to the real home.
//! * `COREPACK_HOME` holds the package managers corepack downloads. A single
//!   `corepack pnpm --version` against an empty home writes ~890 files.
//!
//! ## Why a stable directory rather than a fresh one per run
//!
//! These fixtures install the same handful of packages (`ms@2.1.3`,
//! `left-pad@1.3.0`, `six==1.16.0`, `colorize@1.1.0`) on every run. A
//! throwaway directory per run would re-download all of it every time and buy
//! no extra safety, because the sandbox is outside the home directory either
//! way. Tests that specifically assert *cold-install* behavior already pass
//! their own empty directory as explicit env, which wins — see the ordering
//! rule below.
//!
//! Nothing here deletes the sandbox. Go writes its module cache read-only, so
//! a plain `rm -rf` fails partway through with permission errors; use `go
//! clean -modcache` first, or `chmod -R u+w` the tree, if you want it gone.
//!
//! ## Ordering
//!
//! `Command`'s env operations are keyed by variable name and the last call
//! for a given name wins. So:
//!
//! 1. scrub ambient config first (the existing `SOCKET_*` / `npm_config_*` /
//!    `YARN_*` prefix scrubs — they iterate the *parent* environment and
//!    would otherwise remove the values seeded here),
//! 2. then `isolate`,
//! 3. then any env the individual test needs, which is free to point a
//!    specific cache somewhere else.

#![allow(dead_code)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

/// Variables that decide where a *toolchain* lives, as opposed to where it
/// caches. Each defaults to a path under the real home, so redirecting `HOME`
/// without carrying them over can make the tool itself unresolvable — an
/// rbenv shim that cannot find `~/.rbenv` fails to launch ruby at all, and a
/// `cargo` that cannot find `~/.rustup` cannot pick a toolchain. That failure
/// mode is worse than the leak being fixed, because most of these suites
/// respond to a failed fixture install by printing SKIP and returning, so the
/// coverage would disappear silently.
///
/// Each entry is seeded only when the variable is not already set and the
/// default directory actually exists, which makes it a no-op on machines
/// (and CI runners) that do not use the version manager in question.
pub(crate) const TOOLCHAIN_ROOTS: &[(&str, &str)] = &[
    ("RUSTUP_HOME", ".rustup"),
    ("RBENV_ROOT", ".rbenv"),
    ("PYENV_ROOT", ".pyenv"),
    ("NVM_DIR", ".nvm"),
    ("FNM_DIR", ".fnm"),
    ("VOLTA_HOME", ".volta"),
    ("ASDF_DIR", ".asdf"),
    ("ASDF_DATA_DIR", ".asdf"),
    ("SDKMAN_DIR", ".sdkman"),
    ("MISE_DATA_DIR", ".local/share/mise"),
    ("MISE_CONFIG_DIR", ".config/mise"),
];

/// The home directory of the account running the tests, read from the parent
/// process before anything is redirected.
pub fn real_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// Root of the shared cache sandbox, under the OS temp dir.
///
/// The account name is part of the directory name because `/tmp` is shared on
/// Linux: without it the first user to run the suite on a multi-user box owns
/// the root, and everyone else hits `EACCES` partway through an install.
pub fn cache_root() -> PathBuf {
    let account = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_default();
    let account: String = account
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let name = if account.is_empty() {
        "socket-patch-test-caches".to_string()
    } else {
        format!("socket-patch-test-caches-{account}")
    };
    std::env::temp_dir().join(name)
}

/// The stand-in home directory handed to every isolated child.
pub fn sandbox_home() -> PathBuf {
    cache_root().join("home")
}

/// Every variable [`isolate`] pins, with the sandbox path it points at.
///
/// Exposed so the self-tests below can assert the list stays complete, and so
/// a test that wants to inspect a cache after the fact can find it.
pub fn overrides() -> Vec<(&'static str, PathBuf)> {
    let root = cache_root();
    let home = sandbox_home();
    vec![
        // The catch-all. Everything with no variable of its own — Go's
        // telemetry counters, `~/.npmrc`, `~/.gemrc` — follows this.
        ("HOME", home.clone()),
        ("USERPROFILE", home.clone()),
        // XDG cache/data/state, which several Linux tools prefer over $HOME.
        // XDG_CONFIG_HOME is deliberately left alone: it is not a cache, and
        // when a developer has set it explicitly it usually points at real
        // configuration (a registry mirror, a corporate CA bundle) that the
        // installs still need.
        ("XDG_CACHE_HOME", home.join(".cache")),
        ("XDG_DATA_HOME", home.join(".local/share")),
        ("XDG_STATE_HOME", home.join(".local/state")),
        // npm.
        ("npm_config_cache", root.join("npm")),
        // pnpm: store and global bin both hang off PNPM_HOME.
        ("PNPM_HOME", root.join("pnpm")),
        // yarn, both flavors (classic reads YARN_CACHE_FOLDER, berry's global
        // cache lives under YARN_GLOBAL_FOLDER).
        ("YARN_CACHE_FOLDER", root.join("yarn/cache")),
        ("YARN_GLOBAL_FOLDER", root.join("yarn/global")),
        // corepack's downloaded package managers.
        ("COREPACK_HOME", root.join("corepack")),
        // bun.
        ("BUN_INSTALL", root.join("bun")),
        ("BUN_INSTALL_CACHE_DIR", root.join("bun/cache")),
        // Go. GOCACHE (compiled objects) is a different cache from GOMODCACHE
        // (downloaded modules) and neither follows GOPATH.
        ("GOPATH", root.join("go/path")),
        ("GOMODCACHE", root.join("go/mod")),
        ("GOCACHE", root.join("go/build")),
        // Rust.
        ("CARGO_HOME", root.join("cargo")),
        // Python.
        ("PIP_CACHE_DIR", root.join("pip")),
        ("UV_CACHE_DIR", root.join("uv")),
        // Ruby: the spec cache and bundler's per-user state. GEM_HOME and
        // GEM_PATH are deliberately NOT pinned: rvm/chruby export them, and
        // `bundle` itself resolves through them — an empty override would
        // break the toolchain, which is worse than the leak (see the module
        // docs on version managers). The invariant that keeps this safe:
        // every `gem install` in these suites passes --install-dir, and
        // every `bundle install` sets BUNDLE_PATH or --path, so gem trees
        // land in the fixture regardless of GEM_HOME. A future bare
        // `gem install`/`bundle install` without those would leak again.
        ("GEM_SPEC_CACHE", root.join("gem/specs")),
        ("BUNDLE_USER_HOME", root.join("bundle")),
        // PHP.
        ("COMPOSER_HOME", root.join("composer/home")),
        ("COMPOSER_CACHE_DIR", root.join("composer/cache")),
        // .NET.
        ("NUGET_PACKAGES", root.join("nuget/packages")),
        ("NUGET_HTTP_CACHE_PATH", root.join("nuget/http")),
    ]
}

/// The sandbox path [`isolate`] would pin for `var`.
///
/// For the rare caller that can only take a subset — `global_packages_e2e`
/// asserts on the *real* npm/yarn/pnpm global prefixes, so it must keep the
/// real `HOME`, but it can still redirect the download caches. Panics on an
/// unknown name so a typo cannot quietly leave the value pointing at the
/// caller's home.
pub fn override_path(var: &str) -> PathBuf {
    overrides()
        .into_iter()
        .find(|(name, _)| *name == var)
        .map(|(_, path)| path)
        .unwrap_or_else(|| panic!("cache_env does not pin {var}"))
}

/// Carry the toolchain-selection state that has no variable of its own into
/// the sandbox home.
///
/// `asdf` and `mise` read the global tool version from `$HOME/.tool-versions`
/// and neither takes an absolute path to it from the environment, so a
/// redirected home would leave a `mise`-managed node/ruby/python resolving to
/// nothing. The fixture install then fails and the test prints SKIP, quietly
/// dropping the coverage. The file is a plain list of `<tool> <version>`
/// lines.
fn seed_sandbox_home(home: &std::path::Path, real: &std::path::Path) {
    let src = real.join(".tool-versions");
    if !src.is_file() {
        return;
    }
    let dst = home.join(".tool-versions");
    if std::fs::read(&src).ok() != std::fs::read(&dst).ok() {
        let _ = std::fs::copy(&src, &dst);
    }
}

/// Point `cmd` at the shared cache sandbox.
///
/// Call this on any package-manager child process. See the module docs for
/// where it belongs relative to an ambient-env scrub and the test's own env.
pub fn isolate(cmd: &mut Command) -> &mut Command {
    let home = sandbox_home();
    // Some tools refuse to start when $HOME does not exist; the rest of the
    // tree is created by whichever tool needs it.
    let _ = std::fs::create_dir_all(&home);

    if let Some(real) = real_home() {
        seed_sandbox_home(&home, &real);
        for (var, relative) in TOOLCHAIN_ROOTS {
            if std::env::var_os(var).is_some() {
                continue;
            }
            let path = real.join(relative);
            if path.is_dir() {
                cmd.env(var, path);
            }
        }
    }

    for (var, path) in overrides() {
        cmd.env(var, path);
    }
    cmd
}

// ── Ambient-env scrub for the bun suites ──────────────────────────────

/// True for an ambient variable the real-bun suites must strip from every
/// child (`bun install` fixtures AND the CLI under test) before [`isolate`]:
///
/// * `SOCKET_*` except the hermetic `SOCKET_NO_CONFIG` — the CLI's own env
///   surface (`SOCKET_DRY_RUN`, `SOCKET_API_TOKEN`, …);
/// * every `BUN_*` — the harness re-pins `BUN_INSTALL` /
///   `BUN_INSTALL_CACHE_DIR` per project after the scrub, and bun's other
///   knobs (`BUN_CONFIG_REGISTRY`, `BUN_CONFIG_TOKEN`) must not reach a
///   fixture install;
/// * `npm_config_*` case-insensitively — bun honours `npm_config_registry`
///   and `NPM_CONFIG_REGISTRY` alike. Measured (bun 1.2.23 / 1.4.2): an
///   ambient URL-rewriting mirror (npmmirror, Verdaccio, Artifactory) makes
///   bun record the mirror tarball URL in the 4-tuple's registry slot
///   instead of `""`, and every pre-rewrite `["name@ver", "", {}, "sha512-…"]`
///   assertion fails as a false negative;
/// * `VIRTUAL_ENV` — leaks the caller's Python env into the CLI's probes.
///
/// One predicate for the three bun suites so they cannot drift: two of them
/// once scrubbed only `SOCKET_*` and went red under `BUN_CONFIG_REGISTRY`
/// while the third, with the full scrub, stayed green.
pub fn is_ambient_bun_var(name: &str) -> bool {
    (name.starts_with("SOCKET_") && name != "SOCKET_NO_CONFIG")
        || name.starts_with("BUN_")
        || name.to_ascii_lowercase().starts_with("npm_config_")
        || name == "VIRTUAL_ENV"
}

/// Remove every [`is_ambient_bun_var`] variable of the PARENT environment
/// from `cmd`. Call it BEFORE [`isolate`] and before the suite's own
/// per-project `BUN_INSTALL` / `BUN_INSTALL_CACHE_DIR` pins (the ordering
/// rule in the module docs: the scrub iterates the parent env and would
/// otherwise remove what those seed).
pub fn scrub_ambient_bun_env(cmd: &mut Command) {
    scrub_parent_vars(cmd, parent_var_names(), is_ambient_bun_var);
}

/// [`scrub_ambient_bun_env`] minus `SOCKET_*`, for a `socket-patch` child
/// built with `hermetic::command`: the builder already handled `SOCKET_*`,
/// and removing them again would undo the opt-outs it forces on.
pub fn scrub_ambient_bun_tool_env(cmd: &mut Command) {
    scrub_parent_vars(cmd, parent_var_names(), |name| {
        !name.starts_with("SOCKET_") && is_ambient_bun_var(name)
    });
}

/// The names of the PARENT environment, read once.
pub(crate) fn parent_var_names() -> Vec<OsString> {
    std::env::vars_os().map(|(k, _)| k).collect()
}

/// Remove every name in `parent` that `ambient` matches from `cmd`. The
/// scrubs and their self-tests share it so a self-test can check the
/// result against the same snapshot of the parent env the scrub saw:
/// in-process tests in the same binary mirror flags into the env
/// (`--offline` sets `SOCKET_OFFLINE`), so two separate reads race.
pub(crate) fn scrub_parent_vars(
    cmd: &mut Command,
    parent: Vec<OsString>,
    ambient: fn(&str) -> bool,
) {
    for k in parent {
        if ambient(&k.to_string_lossy()) {
            cmd.env_remove(&k);
        }
    }
}

// ── Ambient-env scrub for the vlt suites ──────────────────────────────

/// True for an ambient variable the real-vlt suites strip from every vlt
/// child before [`isolate`] (a `socket-patch` child built with
/// `hermetic::command` takes [`scrub_ambient_vlt_tool_env`] instead):
///
/// * every `VLT_*` — vlt reads each config option from `VLT_<OPTION>`
///   (`VLT_REGISTRY`, `VLT_REGISTRIES`, `VLT_CACHE`, `VLT_STORE_LINKER`);
///   the harness re-applies its own knobs after the scrub;
/// * `SOCKET_*` except `SOCKET_NO_CONFIG` and the harness's own
///   `SOCKET_PATCH_VLT_E2E_*` gate variables;
/// * `npm_config_*` case-insensitively and `VIRTUAL_ENV`, as for bun.
pub fn is_ambient_vlt_var(name: &str) -> bool {
    if name.starts_with("SOCKET_PATCH_VLT_E2E_") {
        return false;
    }
    name.starts_with("VLT_")
        || (name.starts_with("SOCKET_") && name != "SOCKET_NO_CONFIG")
        || name.to_ascii_lowercase().starts_with("npm_config_")
        || name == "VIRTUAL_ENV"
}

/// Remove every [`is_ambient_vlt_var`] variable of the PARENT environment
/// from `cmd` (call it before [`isolate`], see the module docs).
pub fn scrub_ambient_vlt_env(cmd: &mut Command) {
    scrub_parent_vars(cmd, parent_var_names(), is_ambient_vlt_var);
}

/// [`is_ambient_vlt_var`] minus `SOCKET_*`.
pub(crate) fn is_ambient_vlt_tool_var(name: &str) -> bool {
    !name.starts_with("SOCKET_") && is_ambient_vlt_var(name)
}

/// [`scrub_ambient_vlt_env`] minus `SOCKET_*`, for a `socket-patch` child
/// built with `hermetic::command`: the builder already handled `SOCKET_*`,
/// and removing them again would undo the opt-outs it forces on.
pub fn scrub_ambient_vlt_tool_env(cmd: &mut Command) {
    scrub_parent_vars(cmd, parent_var_names(), is_ambient_vlt_tool_var);
}
