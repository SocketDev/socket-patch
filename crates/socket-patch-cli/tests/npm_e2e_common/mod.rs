//! Shared real-npm plumbing for the npm hosted / vendored capstones
//! (`e2e_redirect_npm_build.rs`, `e2e_vendor_npm_build.rs`) and their
//! manifest-less VEX tails.
//!
//! ```ignore
//! #[path = "npm_e2e_common/mod.rs"]
//! mod npm_e2e_common;
//! #[path = "vex_e2e_common/mod.rs"]
//! mod vex_e2e_common;
//! ```
//!
//! # Which npm
//!
//! * `SOCKET_PATCH_NPM_E2E_BIN` — absolute path of the npm executable to
//!   drive (the pinned `npm-compatibility` matrix installs each release
//!   under a prefix and points here). Unset: `npm` from `PATH`.
//! * `SOCKET_PATCH_NPM_E2E_VERSION` — the exact release that binary must
//!   report (asserted when set, so a leg can never pass on the wrong npm).
//! * `SOCKET_PATCH_NPM_E2E_REQUIRED` — non-empty: a missing npm, a version
//!   mismatch or a failed fixture install FAILS instead of skipping.
//!
//! Locally: `npm install --prefix /tmp/npm-12 npm@12` then
//! `SOCKET_PATCH_NPM_E2E_BIN=/tmp/npm-12/node_modules/.bin/npm
//! SOCKET_PATCH_NPM_E2E_VERSION=12.1.0 SOCKET_PATCH_NPM_E2E_REQUIRED=1
//! cargo test -p socket-patch-cli --test e2e_redirect_npm_build --
//! --include-ignored` (see docs/testing/npm-compatibility.md).
//!
//! # Lock generations the majors write (all verified locally)
//!
//! | npm    | `npm install` writes           | `npm shrinkwrap`            |
//! |--------|--------------------------------|-----------------------------|
//! | 6      | lockfileVersion 1              | renames the lock            |
//! | 7, 8   | lockfileVersion 2 (+ v1 mirror)| renames the lock            |
//! | 9–11   | lockfileVersion 3              | renames the lock            |
//! | 12     | lockfileVersion 3              | REMOVED; a committed shrinkwrap gets a package-lock.json twin on first install, and installs read the twin |
//!
//! npm 12 also defaults `allow-remote=none`, refusing (EALLOWREMOTE) every
//! tarball not served from the registry origin — a hosted redirect's
//! lockfile included — unless the project `.npmrc` sets `allow-remote=all`,
//! which the hosted run writes itself (`redirect_npmrc_allow_remote`).

#![allow(dead_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../common/cache_env.rs"]
mod cache_env;

#[path = "manifestless.rs"]
mod manifestless;
pub use manifestless::*;

pub const BIN_ENV: &str = "SOCKET_PATCH_NPM_E2E_BIN";
pub const VERSION_ENV: &str = "SOCKET_PATCH_NPM_E2E_VERSION";
pub const REQUIRED_ENV: &str = "SOCKET_PATCH_NPM_E2E_REQUIRED";

fn env_set(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

/// The npm executable under test.
pub fn npm_program() -> OsString {
    env_set(BIN_ENV).unwrap_or_else(|| "npm".into())
}

/// `SOCKET_PATCH_NPM_E2E_REQUIRED` is set (CI matrix legs).
pub fn required() -> bool {
    env_set(REQUIRED_ENV).is_some()
}

/// A `Command` for the npm under test with ambient `npm_config_*` scrubbed
/// (npm reads any `npm_config_<key>` env var as config: an ambient
/// `npm_config_dry_run=true` turns fixture installs into exit-0 no-ops) and
/// the per-run cache/home sandbox applied.
pub fn npm_command(cwd: &Path) -> Command {
    npm_command_for(&npm_program(), cwd)
}

/// [`npm_command`] for an explicit npm `program`.
pub fn npm_command_for(program: &OsString, cwd: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.current_dir(cwd)
        .env("npm_config_dry_run", "true")
        .env("npm_config_save", "false")
        .env_remove("npm_config_dry_run")
        .env_remove("npm_config_save");
    for (k, _) in std::env::vars_os() {
        if k.to_string_lossy()
            .to_ascii_lowercase()
            .starts_with("npm_config_")
        {
            cmd.env_remove(&k);
        }
    }
    cache_env::isolate(&mut cmd);
    // npm 7+ runs the `update-notifier` against the registry; keep the
    // fixture output about the fixture.
    cmd.env("NO_UPDATE_NOTIFIER", "1");
    cmd
}

pub fn npm(cwd: &Path, args: &[&str]) -> Output {
    npm_command(cwd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {:?}: {e}", npm_program()))
}

/// The npm version under test, or `None` when no npm runs. Under
/// `REQUIRED` a missing npm or a version other than the pinned one panics.
pub fn npm_version() -> Option<String> {
    let probe = tempfile::tempdir().unwrap();
    let out = npm_command(probe.path()).arg("--version").output();
    let version = out
        .as_ref()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    if required() {
        let v = version
            .as_deref()
            .unwrap_or_else(|| panic!("required npm toolchain unavailable: {out:?}"));
        if let Some(pinned) = env_set(VERSION_ENV) {
            assert_eq!(
                v,
                pinned.to_string_lossy(),
                "the npm matrix must run the pinned version"
            );
        }
    }
    version
}

/// An npm >= 7 to WRITE a v2 lock for the npm 6 cross-version cell:
/// `SOCKET_PATCH_NPM_E2E_LOCK_WRITER_BIN`, else `npm` from `PATH` when it
/// is not the npm under test and reports major >= 7.
pub fn modern_npm_writer() -> Option<OsString> {
    let candidate = env_set("SOCKET_PATCH_NPM_E2E_LOCK_WRITER_BIN").unwrap_or_else(|| "npm".into());
    let probe = tempfile::tempdir().unwrap();
    let out = npm_command_for(&candidate, probe.path())
        .arg("--version")
        .output()
        .ok()?;
    let major: u32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .split('.')
        .next()?
        .parse()
        .ok()?;
    (out.status.success() && major >= 7).then_some(candidate)
}

/// Major of `npm_version()`.
pub fn npm_major() -> Option<u32> {
    npm_version()?.split('.').next()?.parse().ok()
}

/// Skip (println) or, under `REQUIRED`, fail.
pub fn skip(suite: &str, why: &str) {
    assert!(!required(), "REQUIRED npm e2e ({suite}) cannot skip: {why}");
    println!("SKIP {suite}: {why}");
}

/// `npm install <spec>` into `proj` with a private cache; `false` (after a
/// skip / REQUIRED failure) when the registry is unreachable.
pub fn install_fixture(suite: &str, proj: &Path, cache: &Path, spec: &str) -> bool {
    let out = npm(
        proj,
        &[
            "install",
            spec,
            "--no-audit",
            "--no-fund",
            "--cache",
            cache.to_str().unwrap(),
        ],
    );
    if !out.status.success() {
        skip(
            suite,
            &format!(
                "`npm install {spec}` failed (registry unreachable?):\n{}",
                String::from_utf8_lossy(&out.stderr)
            ),
        );
        return false;
    }
    true
}

/// `lockfileVersion` of `proj`'s package-lock.json / npm-shrinkwrap.json.
pub fn lockfile_version(proj: &Path) -> Option<u64> {
    ["npm-shrinkwrap.json", "package-lock.json"]
        .iter()
        .find_map(|name| std::fs::read(proj.join(name)).ok())
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["lockfileVersion"].as_u64())
}

/// How the fixture's lock is committed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockFlavor {
    /// package-lock.json only (every major's `npm install` default).
    PackageLock,
    /// A committed npm-shrinkwrap.json: npm <= 11's `npm shrinkwrap`
    /// (renames the lock → shrinkwrap only); npm 12, which removed the
    /// command, keeps a package-lock.json twin beside it (its default
    /// dual-lock state, and the lock its installs read).
    Shrinkwrap,
}

impl LockFlavor {
    pub fn tag(self) -> &'static str {
        match self {
            LockFlavor::PackageLock => "package-lock",
            LockFlavor::Shrinkwrap => "shrinkwrap",
        }
    }
}

/// Turn an installed project's package-lock.json into `flavor`'s committed
/// state with the npm under test. Returns the lock files a checkout carries.
pub fn commit_lock_flavor(proj: &Path, flavor: LockFlavor, major: u32) -> Vec<&'static str> {
    match flavor {
        LockFlavor::PackageLock => vec!["package-lock.json"],
        LockFlavor::Shrinkwrap if major >= 12 => {
            // npm 12's state for a shrinkwrap repo after any install: the
            // shrinkwrap plus its package-lock.json twin.
            std::fs::copy(
                proj.join("package-lock.json"),
                proj.join("npm-shrinkwrap.json"),
            )
            .unwrap();
            vec!["npm-shrinkwrap.json", "package-lock.json"]
        }
        LockFlavor::Shrinkwrap => {
            let out = npm(proj, &["shrinkwrap"]);
            assert!(
                out.status.success(),
                "`npm shrinkwrap` failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(proj.join("npm-shrinkwrap.json").is_file());
            assert!(
                !proj.join("package-lock.json").exists(),
                "npm <= 11 `npm shrinkwrap` renames the lock"
            );
            vec!["npm-shrinkwrap.json"]
        }
    }
}

/// A gzipped tarball of `pkg_dir` shaped like `npm pack` output: every
/// regular file (sorted, recursively) under `package/`, mode 0644, fixed
/// mtime, NO directory entries — npm 7.0.x's extractor fails ENOTDIR on the
/// directory entries a system `tar` adds.
pub fn npm_pack_like(pkg_dir: &Path) -> Vec<u8> {
    fn files(dir: &Path, rel: &str, out: &mut Vec<(String, PathBuf)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let child = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if e.file_type().unwrap().is_dir() {
                files(&e.path(), &child, out);
            } else {
                out.push((child, e.path()));
            }
        }
    }
    let mut members = Vec::new();
    files(pkg_dir, "", &mut members);
    let mut out = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut out, flate2::Compression::new(9));
        let mut builder = tar::Builder::new(enc);
        for (rel, path) in members {
            let bytes = std::fs::read(path).unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(499_162_500);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("package/{rel}"), &bytes[..])
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }
    out
}

/// `npm ci` against an empty cache.
pub fn npm_ci(dir: &Path, cache: &Path) -> Output {
    npm(
        dir,
        &[
            "ci",
            "--cache",
            cache.to_str().unwrap(),
            "--no-audit",
            "--no-fund",
        ],
    )
}

pub fn output_text(out: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}
