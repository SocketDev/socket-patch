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
//! The capstones run against whatever [`composer_command`] resolves to
//! (the `composer` on `PATH`, or `SOCKET_PATCH_COMPOSER_PHAR`), and branch
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
//!   ([`composer`] first re-runs a connect-level curl failure against a
//!   remote host, see [`remote_transport_failure`].)
//! * `SOCKET_PATCH_COMPOSER_E2E_VERSION=<1|2|2.2|2.10.3…>` — the release
//!   (prefix) the leg pinned, e.g. setup-php's `composer:<v>`; the capstone
//!   asserts `composer --version` reports exactly it or a release under it
//!   (`2.2` matches `2.2.30`, never `2.20.0`).
//! * `SOCKET_PATCH_COMPOSER_PHAR=<path>` — run that exact `composer.phar`
//!   as `php <phar>` instead of the `composer` on PATH
//!   (`composer-compatibility.yml` downloads and sha256-verifies one per
//!   leg). On Windows this is the only working mode: `Command::new` does
//!   not resolve `composer.bat`.
//! * `SOCKET_PATCH_PHP_BIN=<path>` — the `php` that runs the phar
//!   (default: `php` on PATH). Ignored without `SOCKET_PATCH_COMPOSER_PHAR`.

#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Output};

/// psr/log 3.0.2's upstream commit — the GitHub zipball both majors
/// install (packagist's own dist for 3.0.2 on composer 2).
pub const PSR_LOG_REF: &str = "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3";

/// A non-empty environment variable, as a path.
fn env_path(var: &str) -> Option<std::path::PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
}

/// The composer toolchain command: `php <phar>` when
/// `SOCKET_PATCH_COMPOSER_PHAR` is set (php from `SOCKET_PATCH_PHP_BIN`,
/// else PATH), otherwise the `composer` on PATH. Callers add the args.
pub fn composer_command() -> Command {
    match env_path("SOCKET_PATCH_COMPOSER_PHAR") {
        Some(phar) => {
            let php = env_path("SOCKET_PATCH_PHP_BIN").unwrap_or_else(|| "php".into());
            let mut cmd = Command::new(php);
            cmd.arg(phar);
            cmd
        }
        None => Command::new("composer"),
    }
}

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

/// The major of [`composer_command`] (`Composer version 2.10.3 …` →
/// `2`), or `None` when composer is not runnable. Asserts the full version
/// is `SOCKET_PATCH_COMPOSER_E2E_VERSION` (or a release under that prefix)
/// when that is set.
pub fn composer_major(suite: &str) -> Option<u32> {
    let mut probe = composer_command();
    probe.arg("--version").arg("--no-ansi");
    super::cache_env::isolate(&mut probe);
    let out = match probe.output() {
        Ok(out) if out.status.success() => out,
        _ => {
            return skip(
                suite,
                &format!("composer not runnable ({:?})", composer_command()),
            )
        }
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
                "{suite}: the leg pins composer {want} but {:?} reports:\n{text}",
                composer_command()
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
/// is a plain-http loopback wiremock. Git runs with `core.autocrlf=false`:
/// Git for Windows' system default converts a source install's checkout to
/// CRLF, so its bytes would never equal the upstream archive's.
///
/// A failed run whose output shows a connect-level curl failure against a
/// remote host ([`remote_transport_failure`]) is re-run, up to
/// [`TRANSPORT_ATTEMPTS`] times in all: the fixture `composer update` is
/// the only step that reaches packagist / GitHub, and one 10 s connect
/// timeout there would otherwise fail a required leg. Any other failure,
/// including every failure against the loopback patch server, returns at
/// once.
pub fn composer(cwd: &Path, args: &[&str], home: &Path, cache: &Path) -> Output {
    let mut attempt = 1;
    loop {
        let out = composer_once(cwd, args, home, cache);
        if out.status.success() || attempt == TRANSPORT_ATTEMPTS {
            return out;
        }
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let Some(failure) = remote_transport_failure(&text) else {
            return out;
        };
        eprintln!(
            "composer {}: transport failure ({failure}); retrying ({attempt}/{TRANSPORT_ATTEMPTS})",
            args.join(" ")
        );
        std::thread::sleep(std::time::Duration::from_secs(5 * attempt as u64));
        attempt += 1;
    }
}

/// Runs of [`composer`] allowed when each failure is a remote transport
/// failure.
pub const TRANSPORT_ATTEMPTS: u32 = 3;

/// Composer's curl failures that mean the request never got an HTTP
/// answer: 6 (could not resolve host), 7 (could not connect), 28 (timed
/// out), 35 (TLS connect error), 52 (empty reply), 56 (connection reset
/// while receiving).
const TRANSIENT_CURL_CODES: &[&str] = &["6", "7", "28", "35", "52", "56"];

/// The first `curl error <code> while downloading <url>` line in composer's
/// output with a transient [`TRANSIENT_CURL_CODES`] code and a non-loopback
/// URL, or `None`. HTTP status failures, checksum failures and anything
/// against `127.0.0.1` / `localhost` (the capstones' wiremock patch server)
/// are never transient.
pub fn remote_transport_failure(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| {
        let Some((head, url)) = line.split_once(" while downloading ") else {
            return false;
        };
        let Some(code) = head.rsplit_once("curl error ").map(|(_, code)| code.trim()) else {
            return false;
        };
        let host = url
            .split_once("://")
            .map_or("", |(_, rest)| rest)
            .split(['/', ':'])
            .next()
            .unwrap_or("");
        TRANSIENT_CURL_CODES.contains(&code)
            && !host.is_empty()
            && host != "127.0.0.1"
            && host != "localhost"
    })
}

fn composer_once(cwd: &Path, args: &[&str], home: &Path, cache: &Path) -> Output {
    std::fs::create_dir_all(home).unwrap();
    std::fs::create_dir_all(cache).unwrap();
    let config = home.join("config.json");
    if !config.exists() {
        std::fs::write(&config, r#"{"config": {"secure-http": false}}"#).unwrap();
    }
    let mut cmd = composer_command();
    cmd.args(args)
        .arg("--no-interaction")
        .arg("--no-ansi")
        .current_dir(cwd);
    super::cache_env::isolate(&mut cmd);
    cmd.env("COMPOSER_HOME", home)
        .env("COMPOSER_CACHE_DIR", cache)
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.autocrlf")
        .env("GIT_CONFIG_VALUE_0", "false")
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

// Integration-test crates do not get `cfg(test)`, so (as in
// `common/cache_env.rs`) these stay ungated to run at all.
mod composer_e2e_common_selftests {
    use super::remote_transport_failure;

    /// The packagist connect timeout that failed the Windows composer
    /// 2.2.30 leg, both as composer's first stderr line and as the wrapped
    /// `[TransportException]` box line, is transient.
    #[test]
    fn packagist_connect_timeout_is_transient() {
        let line = "curl error 28 while downloading https://repo.packagist.org/packages.json: \
                    Connection timed out after 10001 milliseconds";
        assert_eq!(remote_transport_failure(line), Some(line));
        let boxed = "Loading composer repositories with package information\n\n  \
                     [Composer\\Downloader\\TransportException]\n  \
                     curl error 28 while downloading https://repo.packagist.org/packages.json: \
                     Connection timed out after 10001 millisec  \n  onds\n";
        assert!(remote_transport_failure(boxed).is_some());
        for code in ["6", "7", "35", "52", "56"] {
            let text = format!(
                "curl error {code} while downloading https://api.github.com/repos/php-fig/log/zipball/x: boom"
            );
            assert!(remote_transport_failure(&text).is_some(), "{text}");
        }
    }

    /// Loopback (the capstones' own patch server), HTTP answers, checksum
    /// refusals, other curl codes and unrelated output are not retried.
    #[test]
    fn functional_and_loopback_failures_are_not_transient() {
        for text in [
            "curl error 7 while downloading http://127.0.0.1:41231/archive.zip: Failed to connect",
            "curl error 28 while downloading http://localhost:8080/p2/psr/log.json: timed out",
            "curl error 60 while downloading https://repo.packagist.org/packages.json: SSL certificate problem",
            "The \"https://repo.packagist.org/packages.json\" file could not be downloaded (HTTP/2 404 )",
            "The checksum verification of the file failed (downloaded from http://127.0.0.1:1/a.zip)",
            "Your requirements could not be resolved to an installable set of packages.",
            "curl error 28 while downloading : nowhere",
            "",
        ] {
            assert_eq!(remote_transport_failure(text), None, "{text}");
        }
    }
}
