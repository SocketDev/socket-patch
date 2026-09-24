//! The crawl under a tight `RLIMIT_NOFILE` must inventory exactly what it
//! does with ample descriptors.
//!
//! Every crawler treats a failed `read_dir`/open — `EMFILE` included — as
//! an absent directory, so a crawl that holds more descriptors at once
//! than the old sequential walk (parallel walk threads, crawlers running
//! concurrently) would silently drop packages under a limit the old walk
//! handled. Below the walk pool's tight-limit threshold the crawl keeps
//! the sequential descriptor profile; this suite pins that by scanning the
//! same tree under `ulimit -n 16` and under the inherited limit and
//! requiring byte-identical JSON. (The sequential walk scans this tree
//! fully at 14; with one walk thread per CPU it lost most of it at 16.)
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
    cmd.output().unwrap()
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
    assert_eq!(
        String::from_utf8_lossy(&tight.stdout),
        String::from_utf8_lossy(&ample.stdout),
        "tight-limit stderr:\n{}",
        String::from_utf8_lossy(&tight.stderr)
    );
    assert_eq!(tight.status.code(), ample.status.code());
}
