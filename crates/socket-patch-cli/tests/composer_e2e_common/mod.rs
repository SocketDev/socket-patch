//! Shared REAL-composer plumbing for the host capstones that shell out to a
//! composer toolchain (`e2e_vendor_composer_build.rs` — vendored,
//! `e2e_redirect_composer_build.rs` — hosted).
//!
//! Pull it in with
//!
//! ```ignore
//! #[path = "composer_e2e_common/mod.rs"]
//! mod composer_e2e_common;
//! ```
//!
//! (next to `#[path = "common/cache_env.rs"] mod cache_env;`, which this
//! module uses through `super::cache_env`).
//!
//! ## Composer majors
//!
//! The capstones run against whatever `composer` is on `PATH`, and branch
//! on its MAJOR where the two majors genuinely differ:
//!
//! * **Resolution source.** packagist.org shut Composer 1 metadata off on
//!   2025-09-01 ("The requested package psr/log could not be found in any
//!   version"), so a composer 1 fixture `composer update` resolves psr/log
//!   from an inline `package` repository with packagist disabled — the
//!   same GitHub zipball packagist serves composer 2. Everything after
//!   resolution (the lock the real composer writes, the install from it,
//!   `vendor/composer/installed.json`) is the real toolchain's output on
//!   both majors.
//! * **`installed.json` shape.** composer 2 writes `{"packages": [...]}`,
//!   composer 1 a bare array — readers accept both.
//!
//! Environment knobs (the compat-matrix CI legs set both):
//!
//! * `SOCKET_PATCH_COMPOSER_E2E_REQUIRED=1` — a missing composer, or a
//!   fixture install that cannot reach its registry, FAILS the test
//!   instead of soft-skipping it, so a leg can never report green on an
//!   unexercised toolchain.
//! * `SOCKET_PATCH_COMPOSER_E2E_VERSION=<1|2|2.2|2.10.3…>` — the release
//!   (prefix) the leg pinned, e.g. setup-php's `composer:<v>`; the capstone
//!   asserts `composer --version` reports exactly it or a release under it
//!   (`2.2` matches `2.2.30`, never `2.20.0`).

#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output};

/// psr/log 3.0.2's upstream commit — the GitHub zipball both majors
/// install (packagist's own dist for 3.0.2 on composer 2).
pub const PSR_LOG_REF: &str = "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3";

/// `SOCKET_PATCH_COMPOSER_E2E_REQUIRED` is set to a non-empty value other
/// than `0` (the CI legs' "must run" switch).
pub fn required() -> bool {
    std::env::var("SOCKET_PATCH_COMPOSER_E2E_REQUIRED")
        .is_ok_and(|v| !v.is_empty() && v != "0" && v != "false")
}

/// Soft-skip (println + `None`) locally, hard-fail when the leg requires
/// the toolchain.
pub fn skip<T>(suite: &str, why: &str) -> Option<T> {
    assert!(
        !required(),
        "{suite}: SOCKET_PATCH_COMPOSER_E2E_REQUIRED is set but {why}"
    );
    println!("SKIP {suite}: {why}");
    None
}

/// The major of the `composer` on PATH (`Composer version 2.10.3 …` →
/// `2`), or `None` when composer is not runnable. Asserts the full version
/// is `SOCKET_PATCH_COMPOSER_E2E_VERSION` (or a release under that prefix)
/// when that is set.
pub fn composer_major(suite: &str) -> Option<u32> {
    let mut probe = Command::new("composer");
    probe.arg("--version").arg("--no-ansi");
    super::cache_env::isolate(&mut probe);
    let out = match probe.output() {
        Ok(out) if out.status.success() => out,
        _ => return skip(suite, "`composer` not installed"),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let version = text
        .lines()
        .find_map(|line| {
            let rest = line.trim().strip_prefix("Composer")?;
            let rest = rest.trim_start().strip_prefix("version").unwrap_or(rest);
            Some(rest.split_whitespace().next()?.to_string())
        })
        .unwrap_or_else(|| panic!("{suite}: unparseable `composer --version`:\n{text}"));
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or_else(|| panic!("{suite}: unparseable composer version {version:?}"));
    if let Ok(want) = std::env::var("SOCKET_PATCH_COMPOSER_E2E_VERSION") {
        let want = want.trim().trim_start_matches('v');
        if !want.is_empty() {
            assert!(
                version == want || version.starts_with(&format!("{want}.")),
                "{suite}: the leg pins composer {want} but PATH has:\n{text}"
            );
        }
    }
    println!(
        "{suite}: composer major {major} ({})",
        text.lines().next().unwrap_or("")
    );
    Some(major)
}

/// Run `composer <args>` in `cwd` with a PRIVATE home + cache (the host's
/// composer state must neither leak in nor be polluted). The home's
/// `config.json` disables `secure-http`: the hosted capstone's patch server
/// is a plain-http loopback wiremock.
pub fn composer(cwd: &Path, args: &[&str], home: &Path, cache: &Path) -> Output {
    std::fs::create_dir_all(home).unwrap();
    std::fs::create_dir_all(cache).unwrap();
    let config = home.join("config.json");
    if !config.exists() {
        std::fs::write(&config, r#"{"config": {"secure-http": false}}"#).unwrap();
    }
    let mut cmd = Command::new("composer");
    cmd.args(args)
        .arg("--no-interaction")
        .arg("--no-ansi")
        .current_dir(cwd);
    super::cache_env::isolate(&mut cmd);
    cmd.env("COMPOSER_HOME", home)
        .env("COMPOSER_CACHE_DIR", cache)
        .output()
        .expect("failed to run composer")
}

/// The fixture `composer.json` requiring psr/log 3.0.x for `major`: plain
/// packagist resolution on composer ≥ 2; on composer 1 an inline `package`
/// repository (packagist disabled) naming the same 3.0.2 GitHub zipball.
pub fn fixture_composer_json(name: &str, major: u32) -> String {
    let mut doc = serde_json::json!({
        "name": name,
        "description": "socket-patch composer host capstone fixture",
        "require": { "psr/log": "3.0.*" },
    });
    if major < 2 {
        doc["repositories"] = serde_json::json!([
            { "packagist.org": false },
            { "type": "package", "package": {
                "name": "psr/log",
                "version": "3.0.2",
                "type": "library",
                "dist": {
                    "type": "zip",
                    "url": format!("https://api.github.com/repos/php-fig/log/zipball/{PSR_LOG_REF}"),
                    "reference": PSR_LOG_REF,
                },
                "source": {
                    "type": "git",
                    "url": "https://github.com/php-fig/log.git",
                    "reference": PSR_LOG_REF,
                },
                "require": { "php": ">=8.0.0" },
                "autoload": { "psr-4": { "Psr\\Log\\": "src" } },
            }},
        ]);
    }
    format!("{}\n", serde_json::to_string_pretty(&doc).unwrap())
}

/// Write the fixture composer.json and `composer update` it (network used
/// for fixture setup only; private home + cache). `None` = skipped.
pub fn setup_psr_log_project(
    suite: &str,
    proj: &Path,
    home: &Path,
    cache: &Path,
    major: u32,
) -> Option<()> {
    std::fs::write(
        proj.join("composer.json"),
        fixture_composer_json("socket/composer-capstone", major),
    )
    .unwrap();
    let update = composer(proj, &["update"], home, cache);
    if !update.status.success() {
        return skip(
            suite,
            &format!(
                "`composer update` failed (registry unreachable?):\n{}\n{}",
                String::from_utf8_lossy(&update.stdout),
                String::from_utf8_lossy(&update.stderr)
            ),
        );
    }
    Some(())
}

/// The installed package list of `vendor/composer/installed.json` in
/// either major's shape.
pub fn installed_packages(proj: &Path) -> Vec<serde_json::Value> {
    let installed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(proj.join("vendor/composer/installed.json"))
            .expect("read vendor/composer/installed.json"),
    )
    .expect("installed.json parses");
    installed
        .get("packages")
        .and_then(|p| p.as_array())
        .or_else(|| installed.as_array())
        .expect("installed.json package list")
        .clone()
}

pub fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

/// A fresh checkout of `proj` at `dst`: ONLY the committable files
/// (composer.json, composer.lock, `.socket/`) — never `vendor/`.
pub fn fresh_checkout(proj: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    std::fs::copy(proj.join("composer.json"), dst.join("composer.json")).unwrap();
    std::fs::copy(proj.join("composer.lock"), dst.join("composer.lock")).unwrap();
    if proj.join(".socket").is_dir() {
        copy_dir_recursive(&proj.join(".socket"), &dst.join(".socket"));
    }
    assert!(
        !dst.join("vendor").exists(),
        "a fresh checkout must not carry an installed tree (test bug)"
    );
}
