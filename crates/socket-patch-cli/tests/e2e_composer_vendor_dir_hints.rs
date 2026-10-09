//! The Composer reinstall hints `vendor` prints must name the directory
//! Composer actually installed into (#658).
//!
//! A project with `config.vendor-dir: lib` installs `psr/log` under
//! `lib/psr/log`. After vendoring, the "Composer 1 does not reinstall …
//! remove <dir> first" hint used to say `vendor/psr/log`, a path that does
//! not exist: following it, `composer install` reports "Nothing to
//! install" and the installed package stays unpatched. Runs the built
//! binary over a fabricated install; no composer and no network.

#[path = "common/mod.rs"]
mod common;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;

use serde_json::json;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;

const UUID: &str = "6a7b8c9d-0e1f-4a2b-8c3d-4e5f6a7b8c9d";
const PURL: &str = "pkg:composer/psr/log@3.0.2";
const FILE: &str = "src/LoggerInterface.php";
const ORIGINAL: &[u8] = b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n";
const PATCHED: &[u8] =
    b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n// SOCKET-PATCH-VENDOR-DIR\n";

const LOCK: &str = r#"{
    "content-hash": "abc123def456abc123def456abc1",
    "packages": [
        {
            "name": "psr/log",
            "version": "3.0.2",
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/php-fig/log/zipball/f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "shasum": ""
            },
            "type": "library"
        }
    ],
    "packages-dev": [],
    "plugin-api-version": "2.6.0"
}
"#;

/// A project whose composer.json relocates the vendor tree to `vendor_dir`
/// (`None` = Composer's default `vendor`), with `psr/log` installed there.
fn write_project(root: &Path, vendor_dir: Option<&str>) {
    let mut manifest = json!({ "require": { "psr/log": "^3.0" } });
    if let Some(dir) = vendor_dir {
        manifest["config"] = json!({ "vendor-dir": dir });
    }
    std::fs::write(
        root.join("composer.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let vendor = root.join(vendor_dir.unwrap_or("vendor"));
    std::fs::create_dir_all(vendor.join("composer")).unwrap();
    std::fs::write(
        vendor.join("composer/installed.json"),
        r#"{ "packages": [ { "name": "psr/log", "version": "3.0.2", "version_normalized": "3.0.2.0" } ] }
"#,
    )
    .unwrap();
    let pkg = vendor.join("psr/log");
    std::fs::create_dir_all(pkg.join("src")).unwrap();
    std::fs::write(pkg.join(FILE), ORIGINAL).unwrap();
    std::fs::write(root.join("composer.lock"), LOCK).unwrap();

    let after = compute_git_sha256_from_bytes(PATCHED);
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = json!({ "patches": { PURL: {
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { FILE: {
            "beforeHash": compute_git_sha256_from_bytes(ORIGINAL),
            "afterHash": after,
        }},
        "vulnerabilities": { "GHSA-vdir-aaaa-bbbb": {
            "cves": ["CVE-2026-0658"], "summary": "s", "severity": "high", "description": "d"
        }},
        "description": "x", "license": "MIT", "tier": "free",
    }}});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(after), PATCHED).unwrap();
}

/// Run `vendor --offline` in human mode; returns (exit code, stdout).
fn vendor(root: &Path) -> (i32, String, String) {
    let mut cmd = common::hermetic::binary_command();
    cmd.env_remove("COMPOSER_VENDOR_DIR");
    let args = ["vendor", "--offline"];
    let _fixture = prebuilt_common::prepare_command(&mut cmd, root, &args, &[]);
    let out = cmd
        .args(["--cwd", root.to_str().unwrap()])
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn vendored_reinstall_hint_names_a_relocated_vendor_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root, Some("lib"));
    let (code, stdout, stderr) = vendor(root);
    assert_eq!(
        code, 0,
        "vendor failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("remove lib/psr/log first"),
        "the Composer 1 hint must name the installed dir lib/psr/log:\n{stdout}"
    );
    assert!(
        stdout.contains("Run `composer install` to update lib/"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("vendor/psr/log"),
        "the hint names a directory that does not exist:\n{stdout}"
    );
}

#[test]
fn vendored_reinstall_hint_keeps_the_default_vendor_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root, None);
    let (code, stdout, stderr) = vendor(root);
    assert_eq!(
        code, 0,
        "vendor failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("remove vendor/psr/log first"), "{stdout}");
}
