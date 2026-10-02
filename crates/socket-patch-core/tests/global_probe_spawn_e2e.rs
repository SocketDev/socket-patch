//! Global-mode discovery asks each package manager where its global tree
//! lives (`npm root -g`, `yarn global dir`, `gem env gemdir`, `composer
//! global config home`, ...). These tests put a fake tool on `PATH` the way
//! the real ones install on each OS — an executable script on Unix, a
//! `.cmd` shim on Windows — and check what global discovery makes of it:
//!
//! - #434 / #421 / #438: on Windows the shim must be found (a bare
//!   `Command::new("npm")` only tries `npm.exe`), so global discovery is not
//!   silently empty.
//! - #440: a global probe must run from a neutral directory, never from the
//!   scanned project (Yarn Berry runs the project's `global` script for
//!   `yarn global dir`, and its stdout picked the "global" directory).
//! - #438: Composer's own platform defaults (`%APPDATA%\Composer`,
//!   `$XDG_CONFIG_HOME/composer`) are probed when the CLI can't answer.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serial_test::serial;
use socket_patch_core::crawlers::npm_crawler::{
    get_bun_global_prefix, get_npm_global_prefix, get_pnpm_global_prefix, get_yarn_global_prefix,
};
use socket_patch_core::crawlers::types::CrawlerOptions;
use socket_patch_core::crawlers::{ComposerCrawler, RubyCrawler};

/// Set (or remove) env vars and the cwd for the guard's lifetime; restored
/// on drop so a failing assertion can't leak state into later tests.
struct Env {
    saved: Vec<(&'static str, Option<OsString>)>,
    cwd: Option<PathBuf>,
}

impl Env {
    fn new() -> Self {
        Env {
            saved: Vec::new(),
            cwd: None,
        }
    }

    fn set(&mut self, name: &'static str, value: Option<&std::ffi::OsStr>) -> &mut Self {
        self.saved.push((name, std::env::var_os(name)));
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
        self
    }

    fn chdir(&mut self, dir: &Path) -> &mut Self {
        if self.cwd.is_none() {
            self.cwd = std::env::current_dir().ok();
        }
        std::env::set_current_dir(dir).unwrap();
        self
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(cwd) = self.cwd.take() {
            let _ = std::env::set_current_dir(cwd);
        }
        for (name, value) in self.saved.drain(..).rev() {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// Install a fake `name` tool in `bin` the way the real one ships on this
/// OS: an executable `sh` script on Unix, a `name.cmd` shim (no `.exe`) on
/// Windows. It prints `line`, or its working directory when `line` is None.
fn fake_tool(bin: &Path, name: &str, line: Option<&str>) {
    std::fs::create_dir_all(bin).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let body = match line {
            Some(line) => format!("printf '%s\\n' '{line}'"),
            None => "pwd -P".to_string(),
        };
        let path = bin.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    {
        let body = match line {
            Some(line) => format!("echo {line}"),
            None => "echo %CD%".to_string(),
        };
        std::fs::write(
            bin.join(format!("{name}.cmd")),
            format!("@echo off\r\n{body}\r\n"),
        )
        .unwrap();
    }
}

fn canon(path: &Path) -> PathBuf {
    dunce_canonical(path)
}

/// `canonicalize` without Windows' `\\?\` verbatim prefix, so a path a
/// `.cmd` shim echoed compares equal to the one the test created.
fn dunce_canonical(path: &Path) -> PathBuf {
    let canonical = std::fs::canonicalize(path).unwrap();
    let text = canonical.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => canonical,
    }
}

/// A temp layout: `home/`, a `proj/` project and `bin/` (the only PATH
/// entry), with HOME / USERPROFILE pointed at `home`.
struct Layout {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    proj: PathBuf,
    bin: PathBuf,
}

fn layout() -> Layout {
    let tmp = tempfile::tempdir().unwrap();
    let root = canon(tmp.path());
    let home = root.join("home");
    let proj = root.join("proj");
    let bin = root.join("bin");
    for dir in [&home, &proj, &bin] {
        std::fs::create_dir_all(dir).unwrap();
    }
    Layout {
        _tmp: tmp,
        home,
        proj,
        bin,
    }
}

fn point_env_at(env: &mut Env, l: &Layout) {
    env.set("PATH", Some(l.bin.as_os_str()))
        .set("HOME", Some(l.home.as_os_str()))
        .set("USERPROFILE", Some(l.home.as_os_str()));
    #[cfg(windows)]
    env.set("PATHEXT", Some(std::ffi::OsStr::new(".COM;.EXE;.BAT;.CMD")));
}

// ───────────────────────────── npm family (#434) ─────────────────────────────

/// #434: the npm / pnpm / bun global probes find the tool as it is
/// installed on this OS (on Windows: `npm.cmd`, `pnpm.cmd`, `bun.cmd`).
#[test]
#[serial]
fn npm_family_global_probes_find_the_installed_shims() {
    let l = layout();
    let npm_root = l.home.join("npm-global").join("node_modules");
    let pnpm_root = l.home.join("pnpm-global").join("node_modules");
    let bun_bin = l.home.join(".bun").join("bin");
    fake_tool(&l.bin, "npm", Some(&npm_root.to_string_lossy()));
    fake_tool(&l.bin, "pnpm", Some(&pnpm_root.to_string_lossy()));
    fake_tool(&l.bin, "bun", Some(&bun_bin.to_string_lossy()));
    let mut env = Env::new();
    point_env_at(&mut env, &l);

    assert_eq!(
        get_npm_global_prefix().map(PathBuf::from),
        Ok(npm_root),
        "`npm root -g` must be asked through the installed npm shim"
    );
    assert_eq!(get_pnpm_global_prefix().map(PathBuf::from), Some(pnpm_root));
    assert_eq!(
        get_bun_global_prefix().map(PathBuf::from),
        Some(
            l.home
                .join(".bun")
                .join("install")
                .join("global")
                .join("node_modules")
        )
    );
}

/// #434 (yarn, per the follow-up comment) and #440: `yarn global dir` is
/// found through the installed shim AND runs from the user's home, not from
/// the scanned project, so a project's `global` script can't answer it.
#[test]
#[serial]
fn yarn_global_probe_runs_outside_the_scanned_project() {
    let l = layout();
    std::fs::write(
        l.proj.join("package.json"),
        r#"{"name":"p","scripts":{"global":"node mark.js"}}"#,
    )
    .unwrap();
    fake_tool(&l.bin, "yarn", None);
    let mut env = Env::new();
    point_env_at(&mut env, &l);
    env.chdir(&l.proj);

    let prefix = get_yarn_global_prefix().expect("yarn global dir must be answered");
    let asked_from = canon(Path::new(&prefix).parent().unwrap());
    assert_eq!(
        asked_from,
        l.home,
        "the yarn probe must run from the home dir, not the project ({})",
        l.proj.display()
    );
}

/// #440's sibling: a probe never runs a tool planted in the project via a
/// relative PATH entry (`.`), even when that is the first entry.
#[cfg(unix)]
#[test]
#[serial]
fn global_probe_ignores_a_tool_planted_on_a_relative_path_entry() {
    let l = layout();
    fake_tool(&l.proj, "npm", Some("/planted/node_modules"));
    fake_tool(&l.bin, "npm", Some("/real/node_modules"));
    let mut env = Env::new();
    point_env_at(&mut env, &l);
    let path = std::env::join_paths([PathBuf::from("."), l.bin.clone()]).unwrap();
    env.set("PATH", Some(path.as_os_str()));
    env.chdir(&l.proj);

    assert_eq!(
        get_npm_global_prefix().as_deref(),
        Ok("/real/node_modules"),
        "the project's ./npm must never be spawned"
    );
}

/// #440 on Windows: with no safe `npm` installed and `.` on PATH, a real
/// executable planted in the project as `npm.exe` must not run. The
/// fallback for App Execution Aliases used to hand the bare name to `std`,
/// whose Windows search walks relative PATH entries against the parent's
/// cwd (the project), before the child's neutral `current_dir` applies.
/// The plant is a copy of `cmd.exe`, which prints its banner and exits 0 on
/// a null stdin, so running it would yield a "prefix".
#[cfg(windows)]
#[test]
#[serial]
fn global_probe_never_runs_an_executable_planted_in_the_project() {
    let l = layout();
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot is set on Windows");
    std::fs::copy(
        PathBuf::from(system_root).join("System32").join("cmd.exe"),
        l.proj.join("npm.exe"),
    )
    .unwrap();
    let mut env = Env::new();
    point_env_at(&mut env, &l);
    env.set("PATH", Some(std::ffi::OsStr::new(".")));
    env.chdir(&l.proj);

    let prefix = get_npm_global_prefix();
    assert!(
        prefix.is_err(),
        "the project's npm.exe must never be spawned; got {prefix:?}"
    );
}

// ───────────────────────────────── RubyGems (#421) ─────────────────────────────────

/// #421: `gem env gemdir` / `gem env gempath` are answered through the
/// installed `gem` (RubyInstaller ships `gem.cmd`, no `gem.exe`), so
/// global mode scans that gem home.
#[tokio::test]
#[serial]
async fn global_gem_paths_come_from_the_installed_gem_shim() {
    let l = layout();
    let gem_home = l.home.join("ruby-gems");
    std::fs::create_dir_all(gem_home.join("gems")).unwrap();
    fake_tool(&l.bin, "gem", Some(&gem_home.to_string_lossy()));
    let mut env = Env::new();
    point_env_at(&mut env, &l);
    env.set("GEM_HOME", None).set("GEM_PATH", None);

    let options = CrawlerOptions {
        cwd: l.proj.clone(),
        global: true,
        global_prefix: None,
    };
    let paths = RubyCrawler::new().get_gem_paths(&options).await.unwrap();
    assert!(
        paths.contains(&gem_home.join("gems")),
        "global gem paths must include the `gem env` home; got {paths:?}"
    );
}

// ───────────────────────────────── Composer (#438) ─────────────────────────────────

fn global_options(cwd: &Path) -> CrawlerOptions {
    CrawlerOptions {
        cwd: cwd.to_path_buf(),
        global: true,
        global_prefix: None,
    }
}

/// #438 (1): `composer global config home` is answered through the
/// installed `composer` (`composer.bat` on Windows).
#[tokio::test]
#[serial]
async fn composer_home_comes_from_the_installed_composer_shim() {
    let l = layout();
    let composer_home = l.home.join("composer-home");
    std::fs::create_dir_all(composer_home.join("vendor")).unwrap();
    fake_tool(&l.bin, "composer", Some(&composer_home.to_string_lossy()));
    let mut env = Env::new();
    point_env_at(&mut env, &l);
    env.set("COMPOSER_HOME", None)
        .set("APPDATA", None)
        .set("XDG_CONFIG_HOME", None);

    let paths = ComposerCrawler
        .get_vendor_paths(&global_options(&l.proj))
        .await
        .unwrap();
    assert_eq!(paths, vec![composer_home.join("vendor")]);
}

/// #438 (2), Windows: with no `composer` to ask, Composer's Windows
/// default `%APPDATA%\Composer` is probed.
#[cfg(windows)]
#[tokio::test]
#[serial]
async fn composer_home_falls_back_to_appdata_on_windows() {
    let l = layout();
    let app_data = l.home.join("AppData").join("Roaming");
    let vendor = app_data.join("Composer").join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    let mut env = Env::new();
    point_env_at(&mut env, &l);
    env.set("COMPOSER_HOME", None)
        .set("APPDATA", Some(app_data.as_os_str()));

    let paths = ComposerCrawler
        .get_vendor_paths(&global_options(&l.proj))
        .await
        .unwrap();
    assert_eq!(paths, vec![vendor]);
}

/// #438 (2), Unix: with no `composer` to ask and no `~/.composer`,
/// Composer uses `$XDG_CONFIG_HOME/composer`.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn composer_home_falls_back_to_xdg_config_home() {
    let l = layout();
    let xdg = l.home.join("xdg");
    let vendor = xdg.join("composer").join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    let mut env = Env::new();
    point_env_at(&mut env, &l);
    env.set("COMPOSER_HOME", None)
        .set("XDG_CONFIG_HOME", Some(xdg.as_os_str()));

    let paths = ComposerCrawler
        .get_vendor_paths(&global_options(&l.proj))
        .await
        .unwrap();
    assert_eq!(paths, vec![vendor]);
}
