//! The crawl under a tight `RLIMIT_NOFILE` must inventory exactly what it
//! does with ample descriptors.
//!
//! Every crawler treats a failed `read_dir`/open — `EMFILE` included — as
//! an absent directory, so a crawl that holds more descriptors at once
//! than the old sequential walk (parallel walk threads, crawlers running
//! concurrently) would silently drop packages under a limit the old walk
//! handled. Below the walk pool's tight-limit threshold the crawl keeps
//! the sequential descriptor profile; this suite pins that by scanning the
//! same tree under a tight `ulimit -n` and under the inherited limit and
//! requiring byte-identical JSON. The npm-only tree pins the single walk
//! thread (the sequential walk scans it fully at 14; with one walk thread
//! per CPU it lost most of it at 16); the multi-ecosystem tree pins the
//! crawlers running one at a time.
//!
//! Descriptors are the only resource with a budget here. Peak memory also
//! scales with the walk thread count now (one package.json read per
//! thread, uncapped); nothing pins that beyond the thread count's own
//! ceiling — see the `walk_pool` module docs.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn write_package(dir: &Path, name: &str, version: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        format!(r#"{{"name":"{name}","version":"{version}"}}"#),
    )
    .unwrap();
}

/// A tree wide enough that parallel walk threads each hold a descriptor
/// at once: a root `node_modules` with nested and scoped packages, a pnpm
/// virtual store, and workspace packages with their own `node_modules`.
/// Returns the number of distinct packages it holds.
fn build_tree(root: &Path) -> usize {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"root","version":"0.0.0"}"#,
    )
    .unwrap();
    let mut count = 0;
    let nm = root.join("node_modules");
    for i in 0..60 {
        let pkg = nm.join(format!("pkg{i}"));
        write_package(&pkg, &format!("pkg{i}"), "1.0.0");
        count += 1;
        for j in 0..3 {
            let name = format!("nested{i}-{j}");
            write_package(&pkg.join("node_modules").join(&name), &name, "2.0.0");
            count += 1;
        }
    }
    for i in 0..15 {
        let name = format!("scoped{i}");
        write_package(
            &nm.join("@scope").join(&name),
            &format!("@scope/{name}"),
            "3.0.0",
        );
        count += 1;
    }
    for i in 0..30 {
        let name = format!("stored{i}");
        write_package(
            &nm.join(".pnpm")
                .join(format!("{name}@4.0.0"))
                .join("node_modules")
                .join(&name),
            &name,
            "4.0.0",
        );
        count += 1;
    }
    for w in 0..10 {
        let ws_nm = root
            .join("packages")
            .join(format!("ws{w}"))
            .join("node_modules");
        for i in 0..10 {
            let name = format!("ws{w}-dep{i}");
            write_package(&ws_nm.join(&name), &name, "5.0.0");
            count += 1;
        }
    }
    count
}

/// [`build_tree`] plus installs for three more ecosystems — a Python
/// virtualenv, a Bundler `vendor/bundle` and a Composer `vendor/` — so the
/// crawlers that run alongside npm hold descriptors of their own: run
/// concurrently instead of one at a time, they need more than a tight
/// limit leaves. Returns the number of distinct packages it holds.
fn build_multi_ecosystem_tree(root: &Path) -> usize {
    let mut count = build_tree(root);
    let site = root
        .join(".venv")
        .join("lib")
        .join("python3.11")
        .join("site-packages");
    for i in 0..40 {
        let dist = site.join(format!("pydist{i}-1.0.{i}.dist-info"));
        std::fs::create_dir_all(&dist).unwrap();
        std::fs::write(
            dist.join("METADATA"),
            format!("Metadata-Version: 2.1\nName: pydist{i}\nVersion: 1.0.{i}\n\n"),
        )
        .unwrap();
        count += 1;
    }
    let gems = root
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.2.0");
    for i in 0..40 {
        let gem = gems.join("gems").join(format!("rgem{i}-2.0.{i}"));
        std::fs::create_dir_all(gem.join("lib")).unwrap();
        std::fs::write(gem.join("lib").join(format!("rgem{i}.rb")), "").unwrap();
        count += 1;
    }
    std::fs::create_dir_all(gems.join("specifications")).unwrap();
    let composer = root.join("vendor").join("composer");
    std::fs::create_dir_all(&composer).unwrap();
    let mut installed = Vec::new();
    for i in 0..20 {
        let name = format!("acme/lib{i}");
        std::fs::create_dir_all(root.join("vendor").join(&name)).unwrap();
        installed.push(serde_json::json!({"name": name, "version": format!("3.0.{i}")}));
        count += 1;
    }
    std::fs::write(root.join("composer.json"), "{}").unwrap();
    std::fs::write(
        composer.join("installed.json"),
        serde_json::json!({ "packages": installed }).to_string(),
    )
    .unwrap();
    count
}

/// `scan --json` against an unreachable API (the crawl still runs and the
/// JSON still reports what it found), optionally under `ulimit -n`.
fn scan(root: &Path, nofile: Option<u32>) -> Output {
    let mut script = String::new();
    if let Some(limit) = nofile {
        script.push_str(&format!("ulimit -n {limit} || exit 99; "));
    }
    script.push_str(r#"exec "$0" "$@""#);
    let mut cmd = Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(script)
        .arg(binary())
        .args([
            "scan",
            "--json",
            "--no-telemetry",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "x",
            "--org",
            "test-org",
        ])
        .current_dir(root);
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") && name != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    // Keep the Python and Bundler discovery on the fixture's own installs.
    for key in [
        "VIRTUAL_ENV",
        "BUNDLE_PATH",
        "BUNDLE_APP_CONFIG",
        "GEM_HOME",
        "GEM_PATH",
    ] {
        cmd.env_remove(key);
    }
    cmd.output().unwrap()
}

/// A dropped package is a blown descriptor budget, not a JSON diff: say
/// so before the byte-for-byte comparison does, while the limit that
/// produced it is still in hand. Silent when the tight run printed no
/// JSON at all — the stdout comparison then reports it, with stderr.
fn assert_scanned_the_same(tight: &Output, ample_json: &Value, limit: u32) {
    let Ok(tight_json) = serde_json::from_slice::<Value>(&tight.stdout) else {
        return;
    };
    assert_eq!(
        tight_json["scannedPackages"],
        ample_json["scannedPackages"],
        "ulimit -n {limit} dropped packages — the crawl's descriptor budget regressed; \
         stderr:\n{}",
        String::from_utf8_lossy(&tight.stderr)
    );
}

#[test]
fn tight_descriptor_limit_scans_the_same_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let expected = build_tree(root);

    let ample = scan(root, None);
    let tight = scan(root, Some(16));
    assert_ne!(tight.status.code(), Some(99), "ulimit -n 16 was refused");

    let ample_json: Value = serde_json::from_slice(&ample.stdout).unwrap_or_else(|e| {
        panic!(
            "ample-limit scan printed no JSON ({e}); stderr:\n{}",
            String::from_utf8_lossy(&ample.stderr)
        )
    });
    assert_eq!(
        ample_json["scannedPackages"].as_u64(),
        Some(expected as u64),
        "{ample_json}"
    );
    assert_scanned_the_same(&tight, &ample_json, 16);
    assert_eq!(
        String::from_utf8_lossy(&tight.stdout),
        String::from_utf8_lossy(&ample.stdout),
        "tight-limit stderr:\n{}",
        String::from_utf8_lossy(&tight.stderr)
    );
    assert_eq!(tight.status.code(), ample.status.code());
}

/// The same, with every crawler finding packages: the tight-limit run
/// must crawl the ecosystems one at a time, as the sequential dispatch
/// did, or the concurrently running crawlers' descriptors crowd each other
/// out and packages go missing. At 16 that is headroom; at 12 (checked on
/// macOS, where it was measured: the sequential dispatch scans this tree
/// fully down to 11, while running the crawlers concurrently loses 40-80
/// of its packages at 12) it is what pins the one-at-a-time dispatch.
///
/// 12 therefore leaves the serial dispatch exactly ONE descriptor of
/// slack: the measured cliff is 11 (complete) / 10 (445 of 485 packages).
/// Anything that holds one more descriptor open across the crawl — a
/// config read, a cert store, a log file — fails this test, so the
/// package-count assertion below runs first and names the budget instead
/// of leaving a 40-package JSON diff.
#[test]
fn tight_descriptor_limit_scans_every_ecosystem_the_same() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let expected = build_multi_ecosystem_tree(root);

    let ample = scan(root, None);
    let ample_json: Value = serde_json::from_slice(&ample.stdout).unwrap_or_else(|e| {
        panic!(
            "ample-limit scan printed no JSON ({e}); stderr:\n{}",
            String::from_utf8_lossy(&ample.stderr)
        )
    });
    assert_eq!(
        ample_json["scannedPackages"].as_u64(),
        Some(expected as u64),
        "{ample_json}"
    );

    let limits: &[u32] = if cfg!(target_os = "macos") {
        // The concurrent crawlers' overlap is timing-dependent: repeat.
        &[16, 12, 12, 12]
    } else {
        &[16]
    };
    for &limit in limits {
        let tight = scan(root, Some(limit));
        assert_ne!(
            tight.status.code(),
            Some(99),
            "ulimit -n {limit} was refused"
        );
        assert_scanned_the_same(&tight, &ample_json, limit);
        assert_eq!(
            String::from_utf8_lossy(&tight.stdout),
            String::from_utf8_lossy(&ample.stdout),
            "ulimit -n {limit} stderr:\n{}",
            String::from_utf8_lossy(&tight.stderr)
        );
        assert_eq!(
            tight.status.code(),
            ample.status.code(),
            "ulimit -n {limit}"
        );
    }
}
