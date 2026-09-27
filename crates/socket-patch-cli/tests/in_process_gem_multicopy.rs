//! Gem multi-copy apply/rollback regression (silent partial — the gem
//! sibling of the npm multi-copy P0, see `in_process_npm_multicopy.rs`).
//!
//! Bundler produces TWO store layouts under one install root: the scoped
//! `vendor/bundle/<engine>/<abi>/gems/` store (bundler >= 2, `--path` /
//! local-config installs) and the flat `vendor/bundle/gems/` store
//! (bundler 1 with an env `BUNDLE_PATH`). Both can coexist — a bundler-2
//! install beside a bundler-1 install of the SAME project — each holding a
//! REAL physical copy of the same `gem@version`. `apply` used to resolve
//! the purl to ONE store's copy (first-wins merge), patch it, and report
//! `success` while whichever bundler loaded the OTHER store ran pristine
//! (vulnerable) bytes.
//!
//! These tests build the coexisting layout by hand (hermetic, offline, no
//! ruby toolchain), hand-stage a `.socket/` manifest + blobs, run the REAL
//! `apply` / `rollback` flow through the built binary, and assert EVERY
//! physical copy is patched (and later restored) AND that the JSON summary
//! counts every copy.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const PURL: &str = "pkg:gem/rack@3.1.0";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Write a gem copy at `gem_dir` with `lib/rack.rb` holding `bytes`,
/// returning the file path.
fn write_copy(gem_dir: &Path, bytes: &[u8]) -> PathBuf {
    let file = gem_dir.join("lib").join("rack.rb");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, bytes).unwrap();
    file
}

fn stage_manifest_and_blob(root: &Path, before_hash: &str, after_hash: &str, patched: &[u8]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "{PURL}": {{
                    "uuid": "67656d6d-756c-4469-8370-79302e302e30",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{ "lib/rack.rb": {{
                        "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                    }}}},
                    "vulnerabilities": {{}}, "description": "gem multi-copy fixture",
                    "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(after_hash), patched).unwrap();
}

/// Lay down a project whose `vendor/bundle` holds BOTH bundler store
/// layouts, each with a real copy of `rack@3.1.0`. Returns
/// `(root, scoped_file, flat_file, before_hash, after_hash, patched)`.
fn build_two_store_project(tmp: &Path) -> (PathBuf, PathBuf, PathBuf, String, String, Vec<u8>) {
    let original = b"module Rack\n  VERSION = 'VULNERABLE'\nend\n";
    let mut patched = original.to_vec();
    patched.extend_from_slice(b"# SOCKET-PATCHED-GEM-MULTICOPY\n");
    let before_hash = git_sha256(original);
    let after_hash = git_sha256(&patched);
    assert_ne!(before_hash, after_hash, "fixture must be non-degenerate");

    let bundle = tmp.join("vendor").join("bundle");
    // Scoped store (bundler >= 2 layout).
    let scoped_file = write_copy(
        &bundle
            .join("ruby")
            .join("3.2.0")
            .join("gems")
            .join("rack-3.1.0"),
        original,
    );
    // Flat store (bundler 1 env-BUNDLE_PATH layout) — the `specifications/`
    // sibling marks it as a real gem home.
    let flat_file = write_copy(&bundle.join("gems").join("rack-3.1.0"), original);
    std::fs::create_dir_all(bundle.join("specifications")).unwrap();

    stage_manifest_and_blob(tmp, &before_hash, &after_hash, &patched);

    (
        tmp.to_path_buf(),
        scoped_file,
        flat_file,
        before_hash,
        after_hash,
        patched,
    )
}

/// Run the given subcommand with the ambient `SOCKET_*` and `BUNDLE_*`
/// environment scrubbed (a developer's `BUNDLE_PATH` export or
/// `BUNDLE_APP_CONFIG` must not steer discovery), telemetry disabled.
fn run_json(root: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .args(["--json", "--offline", "--ecosystems", "gem", "--cwd"])
        .arg(root);
    for (key, _) in std::env::vars_os() {
        let k = key.to_string_lossy();
        if (k.starts_with("SOCKET_") && k != "SOCKET_NO_CONFIG") || k.starts_with("BUNDLE_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("{args:?} must emit JSON: {e}; stdout={stdout}"));
    (code, v)
}

#[test]
fn apply_patches_every_coexisting_gem_store_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, scoped_file, flat_file, before_hash, after_hash, patched) =
        build_two_store_project(tmp.path());

    // Pristine pre-check: neither copy carries the marker yet.
    for f in [&scoped_file, &flat_file] {
        let bytes = std::fs::read(f).unwrap();
        assert_eq!(git_sha256(&bytes), before_hash, "pre-apply copy at {f:?}");
    }

    let (code, v) = run_json(&root, &["apply"]);
    assert_eq!(code, 0, "apply must succeed; envelope={v}");
    assert_eq!(v["status"], "success", "envelope={v}");

    // THE security guarantee: BOTH physical copies must now be patched
    // byte-for-byte. Before the fix, only the scoped copy was written and
    // the flat copy (the one bundler 1 loads) stayed VULNERABLE while the
    // run still reported success.
    for (label, f) in [("scoped", &scoped_file), ("flat", &flat_file)] {
        let bytes = std::fs::read(f).unwrap();
        assert_eq!(
            bytes, patched,
            "{label} store copy at {f:?} was NOT patched (silent partial)"
        );
        assert_eq!(
            git_sha256(&bytes),
            after_hash,
            "{label} store copy at {f:?} does not hash to afterHash"
        );
    }

    // The summary must COUNT both copies — one Applied event per physical
    // copy — so the envelope carries a signal that a second copy existed.
    assert_eq!(
        v["summary"]["applied"], 2,
        "summary must count both patched copies; envelope={v}"
    );
    let applied_events = v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["action"] == "applied" && e["purl"] == PURL)
        .count();
    assert_eq!(
        applied_events, 2,
        "one applied event per physical copy; envelope={v}"
    );
}

#[test]
fn rollback_restores_every_coexisting_gem_store_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, scoped_file, flat_file, before_hash, after_hash, patched) =
        build_two_store_project(tmp.path());

    // Stage the before-blob so rollback can restore in place.
    let original: Vec<u8> = {
        let mut o = patched.clone();
        let marker = b"# SOCKET-PATCHED-GEM-MULTICOPY\n";
        o.truncate(o.len() - marker.len());
        o
    };
    assert_eq!(git_sha256(&original), before_hash);
    std::fs::write(
        root.join(".socket").join("blobs").join(&before_hash),
        &original,
    )
    .unwrap();

    // Apply first so both copies are patched.
    let (code, v) = run_json(&root, &["apply"]);
    assert_eq!(code, 0, "apply precondition; envelope={v}");
    for f in [&scoped_file, &flat_file] {
        assert_eq!(
            std::fs::read(f).unwrap(),
            patched,
            "precondition: patched {f:?}"
        );
    }

    // Now roll back and assert EVERY copy is restored to pristine bytes.
    let (code, v) = run_json(&root, &["rollback", "--yes"]);
    assert_eq!(code, 0, "rollback must succeed; envelope={v}");

    for (label, f) in [("scoped", &scoped_file), ("flat", &flat_file)] {
        let bytes = std::fs::read(f).unwrap();
        assert_eq!(
            bytes, original,
            "{label} store copy at {f:?} was NOT restored (rollback left a patched copy)"
        );
        assert_eq!(
            git_sha256(&bytes),
            before_hash,
            "{label} store copy restore hash"
        );
    }
    assert_ne!(before_hash, after_hash);
}
