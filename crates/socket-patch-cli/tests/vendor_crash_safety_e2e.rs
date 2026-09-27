//! Crash safety of a vendored run's writes.
//!
//! Vendored artifacts (the packed `.tgz`, the patched copy trees, the
//! marker) are written WITHOUT an fsync of their own; one durability barrier
//! syncs them before the first durable commit point (lockfile, ledger) that
//! could name them — see `socket_patch_core::utils::durability`. These tests
//! crash the real binary at that barrier through its debug-build failpoint
//! (`SOCKET_PATCH_FAILPOINT`, compiled out of release builds) and then play
//! the part of the power loss the barrier guards against by destroying the
//! un-synced artifact bytes, and prove the next run re-verifies the
//! artifact, rebuilds it and wires the project exactly as an uninterrupted
//! run would have.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn rel_tgz() -> String {
    format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")
}

/// An installed npm project (package-lock v3) with a manifest patch for
/// left-pad and its after-blob, so `vendor --offline` needs no network.
fn npm_project() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();
    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
        "packages": {
            "": { "name": "fixture", "version": "1.0.0",
                  "dependencies": { "left-pad": "^1.3.0" } },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), lock_bytes).unwrap();
    let manifest = json!({ "patches": { PURL: {
        "uuid": UUID, "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "package/index.js": {
            "beforeHash": git_sha256(ORIG_INDEX), "afterHash": git_sha256(PATCHED_INDEX) } },
        "vulnerabilities": {}, "description": "synthetic", "license": "MIT", "tier": "free"
    }}});
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        socket.join("blobs").join(git_sha256(PATCHED_INDEX)),
        PATCHED_INDEX,
    )
    .unwrap();
    tmp
}

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// `vendor --json --offline` through the built binary, optionally crashing
/// at `failpoint`. Returns the exit code and stdout.
fn vendor(root: &Path, failpoint: Option<&str>) -> (i32, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["vendor", "--json", "--offline"])
        .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    if let Some(point) = failpoint {
        cmd.env("SOCKET_PATCH_FAILPOINT", point);
    }
    let out = cmd.output().expect("run socket-patch vendor");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// Every regular file under `root` except the transient lock (relative
/// path → bytes), sorted.
fn tree(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel != ".socket/apply.lock" {
                    out.push((rel, std::fs::read(&path).unwrap()));
                }
            }
        }
    }
    out.sort();
    out
}

/// The ledger with its timestamps masked, for comparing two runs.
fn masked_state(root: &Path) -> Value {
    let mut v: Value =
        serde_json::from_slice(&std::fs::read(root.join(".socket/vendor/state.json")).unwrap())
            .unwrap();
    fn mask(v: &mut Value) {
        match v {
            Value::Object(map) => {
                for (k, val) in map.iter_mut() {
                    if k == "vendoredAt" || k == "exportedAt" {
                        *val = Value::Null;
                    } else {
                        mask(val);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(mask),
            _ => {}
        }
    }
    mask(&mut v);
    v
}

/// A crash at the barrier — artifacts written, nothing durable yet — leaves
/// the commit points exactly as they were: the lock still resolves the
/// registry and no ledger exists. Losing the un-synced tarball bytes
/// on top of that (what a power loss may do) costs nothing: the next run
/// re-verifies what it finds in the orphaned uuid dir, rebuilds it, and
/// ends in the same state an uninterrupted run reaches.
#[test]
fn crash_before_the_barrier_is_repaired_by_the_next_run() {
    let clean = npm_project();
    let (code, stdout) = vendor(clean.path(), None);
    assert_eq!(code, 0, "{stdout}");

    let tmp = npm_project();
    let root = tmp.path();
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();
    let (code, stdout) = vendor(root, Some("durability_barrier"));
    assert_eq!(code, 86, "the failpoint must crash the run: {stdout}");
    assert!(
        root.join(rel_tgz()).is_file(),
        "the artifact was written before the crash"
    );
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        lock_before,
        "no commit point is written ahead of the barrier"
    );
    assert!(!root.join(".socket/vendor/state.json").exists());

    // The power loss the barrier exists for: the un-synced artifact and
    // marker come back empty.
    std::fs::write(root.join(rel_tgz()), b"").unwrap();
    std::fs::write(
        root.join(format!(
            ".socket/vendor/npm/{UUID}/socket-patch.vendor.json"
        )),
        b"",
    )
    .unwrap();

    let (code, stdout) = vendor(root, None);
    assert_eq!(code, 0, "the next run repairs: {stdout}");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["purl"] == PURL && e["action"] == "applied"),
        "{v:#}"
    );
    let tgz = std::fs::read(root.join(rel_tgz())).unwrap();
    let state = masked_state(root);
    assert_eq!(
        state["entries"][PURL]["artifact"]["sha256"],
        hex::encode(Sha256::digest(&tgz)),
        "the rebuilt artifact is the one the ledger records"
    );
    assert_eq!(
        state,
        masked_state(clean.path()),
        "same ledger as an uninterrupted run"
    );
    let strip = |t: Vec<(String, Vec<u8>)>| -> Vec<(String, Vec<u8>)> {
        t.into_iter()
            .filter(|(rel, _)| {
                rel != ".socket/vendor/state.json" && !rel.ends_with("socket-patch.vendor.json")
            })
            .collect()
    };
    assert_eq!(
        strip(tree(root)),
        strip(tree(clean.path())),
        "same artifact and wiring as an uninterrupted run"
    );
}

/// The same for a copy-dir artifact: the cargo backend patches a staged
/// copy (written without an fsync) and swaps it into place, then the
/// crash hits the barrier ahead of the `Cargo.toml` / `Cargo.lock` wiring
/// commit. A patched file
/// lost to the power loss is caught by the next run's afterHash check on
/// the copy, which is rebuilt and wired.
#[test]
fn crash_before_the_barrier_repairs_a_copy_dir_artifact() {
    const CARGO_UUID: &str = "2b1f6c1e-8d3a-4f6b-9c2d-7e5a9b1c3d11";
    const CARGO_PURL: &str = "pkg:cargo/cfg-if@1.0.4";
    const PRISTINE: &[u8] = b"pub fn cfg() {}\n";
    const PATCHED: &[u8] = b"pub fn cfg() { /* patched */ }\n";
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    let cargo_home = tmp.path().join("cargo-home");
    let krate = cargo_home.join("registry/src/index.crates.io-6f17d22bba15001f/cfg-if-1.0.4");
    std::fs::create_dir_all(krate.join("src")).unwrap();
    std::fs::write(krate.join("src/lib.rs"), PRISTINE).unwrap();
    std::fs::write(
        krate.join("Cargo.toml"),
        "[package]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join(".socket/blobs")).unwrap();
    let manifest_toml =
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n";
    std::fs::write(root.join("Cargo.toml"), manifest_toml).unwrap();
    let lock = format!(
        "version = 4\n\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
         dependencies = [\n \"cfg-if\",\n]\n\n[[package]]\nname = \"cfg-if\"\n\
         version = \"1.0.4\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
         checksum = \"{}\"\n",
        "9".repeat(64)
    );
    std::fs::write(root.join("Cargo.lock"), &lock).unwrap();
    let manifest = json!({ "patches": { CARGO_PURL: {
        "uuid": CARGO_UUID, "exportedAt": "2026-01-01T00:00:00Z",
        "files": { "package/src/lib.rs": {
            "beforeHash": git_sha256(PRISTINE), "afterHash": git_sha256(PATCHED) } },
        "vulnerabilities": {}, "description": "synthetic", "license": "MIT", "tier": "free"
    }}});
    std::fs::write(
        root.join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join(".socket/blobs").join(git_sha256(PATCHED)),
        PATCHED,
    )
    .unwrap();

    let run = |failpoint: Option<&str>| {
        let mut cmd = Command::new(binary());
        cmd.args(["vendor", "--json", "--offline"])
            .current_dir(&root)
            .env("CARGO_HOME", &cargo_home)
            .env("SOCKET_TELEMETRY_DISABLED", "1");
        for (key, _) in std::env::vars() {
            if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
                cmd.env_remove(key);
            }
        }
        if let Some(point) = failpoint {
            cmd.env("SOCKET_PATCH_FAILPOINT", point);
        }
        let out = cmd.output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };

    let (code, stdout) = run(Some("durability_barrier"));
    assert_eq!(code, 86, "{stdout}");
    let copy_lib = root.join(format!(
        ".socket/vendor/cargo/{CARGO_UUID}/cfg-if-1.0.4/src/lib.rs"
    ));
    assert_eq!(std::fs::read(&copy_lib).unwrap(), PATCHED);
    assert!(!root.join(".cargo/config.toml").exists());
    assert_eq!(
        std::fs::read_to_string(root.join("Cargo.toml")).unwrap(),
        manifest_toml,
        "no wiring committed before the barrier"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("Cargo.lock")).unwrap(),
        lock
    );
    // The un-synced patched file comes back empty.
    std::fs::write(&copy_lib, b"").unwrap();

    let (code, stdout) = run(None);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(std::fs::read(&copy_lib).unwrap(), PATCHED, "rebuilt");
    let wired = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(wired.contains(CARGO_UUID), "{wired}");
    let (code, stdout) = run(None);
    assert_eq!(code, 0, "{stdout}");
    assert!(stdout.contains("already_vendored"), "{stdout}");
}
