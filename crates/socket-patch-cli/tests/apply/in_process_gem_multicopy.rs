//! Gem multi-copy apply/rollback regression (silent partial — the gem
//! sibling of the npm multi-copy P0, see `in_process_npm_multicopy.rs`).
//!
//! Bundler produces TWO store layouts under one install root: the scoped
//! `vendor/bundle/<engine>/<abi>/gems/` store (bundler >= 2, `--path` /
//! local-config installs) and the flat `vendor/bundle/gems/` store
//! (bundler 1 with an env `BUNDLE_PATH`). Both can coexist — a bundler-2
//! install beside a bundler-1 install of the SAME project — each holding a
//! REAL physical copy of the same `gem@version`. `apply` must patch every
//! store's copy: resolving the purl to ONE copy (first-wins merge) would
//! report `success` while whichever bundler loaded the OTHER store ran
//! pristine (vulnerable) bytes.
//!
//! These tests build the coexisting layout by hand (hermetic, offline, no
//! ruby toolchain), hand-stage a `.socket/` manifest + blobs, run the REAL
//! `apply` / `rollback` flow through the built binary, and assert EVERY
//! physical copy is patched (and later restored) AND that the JSON summary
//! counts every copy.

use crate::common::hermetic::{self, Extra};
use crate::common::{binary, git_sha256, hermetic_command};

use std::path::{Path, PathBuf};

const PURL: &str = "pkg:gem/rack@3.1.0";

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

/// Run the given subcommand with the hermetic `SOCKET_*` environment and
/// the ambient `BUNDLE_*` scrubbed (a developer's `BUNDLE_PATH` export or
/// `BUNDLE_APP_CONFIG` must not steer discovery).
fn run_json(root: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let mut cmd = hermetic_command(&binary());
    cmd.args(args)
        .args(["--json", "--offline", "--ecosystems", "gem", "--cwd"])
        .arg(root);
    hermetic::scrub_extra(&mut cmd, &[Extra::Bundle]);
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

/// Lay down a project whose one scoped store holds BOTH the ruby-platform
/// build `rack-3.1.0/` and the platform build `rack-3.1.0-x86_64-linux/` of
/// `rack@3.1.0` (#1092: `gem install --platform ruby` beside a platform
/// install, or a project toggling `force_ruby_platform`). RubyGems loads
/// the platform build. Returns
/// `(root, plain_file, platform_file, original, patched)`.
fn build_platform_variant_project(tmp: &Path) -> (PathBuf, PathBuf, PathBuf, Vec<u8>, Vec<u8>) {
    let original = b"module Rack\n  VERSION = 'VULNERABLE'\nend\n".to_vec();
    let mut patched = original.clone();
    patched.extend_from_slice(b"# SOCKET-PATCHED-GEM-PLATFORM\n");
    let before_hash = git_sha256(&original);
    let after_hash = git_sha256(&patched);

    let gems = tmp
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.2.0")
        .join("gems");
    let plain_file = write_copy(&gems.join("rack-3.1.0"), &original);
    let platform_file = write_copy(&gems.join("rack-3.1.0-x86_64-linux"), &original);

    stage_manifest_and_blob(tmp, &before_hash, &after_hash, &patched);
    // A vulnerability, so `vex` has a statement to attest.
    let manifest = tmp.join(".socket").join("manifest.json");
    let text = std::fs::read_to_string(&manifest).unwrap().replace(
        r#""vulnerabilities": {}"#,
        r#""vulnerabilities": { "GHSA-gplt-gplt-gplt": {
            "cves": ["CVE-2026-1092"], "summary": "synthetic",
            "severity": "high", "description": "synthetic"
        }}"#,
    );
    assert!(text.contains("GHSA-gplt-gplt-gplt"));
    std::fs::write(&manifest, text).unwrap();
    std::fs::write(
        tmp.join(".socket").join("blobs").join(&before_hash),
        &original,
    )
    .unwrap();

    (
        tmp.to_path_buf(),
        plain_file,
        platform_file,
        original,
        patched,
    )
}

/// `run_json` without `--json`, for `vex`, whose stdout is the document.
fn run_raw(root: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = hermetic_command(&binary());
    cmd.args(args)
        .args(["--offline", "--ecosystems", "gem", "--cwd"])
        .arg(root);
    hermetic::scrub_extra(&mut cmd, &[Extra::Bundle]);
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// #1092: `apply` patches the platform build beside the ruby-platform one,
/// and `rollback` restores both.
#[test]
fn apply_and_rollback_cover_every_platform_variant_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, plain_file, platform_file, original, patched) =
        build_platform_variant_project(tmp.path());

    let (code, v) = run_json(&root, &["apply"]);
    assert_eq!(code, 0, "apply must succeed; envelope={v}");
    for (label, f) in [("plain", &plain_file), ("platform", &platform_file)] {
        assert_eq!(
            std::fs::read(f).unwrap(),
            patched,
            "{label} copy at {f:?} was NOT patched; envelope={v}"
        );
    }
    assert_eq!(
        v["summary"]["applied"], 2,
        "summary must count both copies; envelope={v}"
    );

    let (code, v) = run_json(&root, &["rollback", "--yes"]);
    assert_eq!(code, 0, "rollback must succeed; envelope={v}");
    for (label, f) in [("plain", &plain_file), ("platform", &platform_file)] {
        assert_eq!(
            std::fs::read(f).unwrap(),
            original,
            "{label} copy at {f:?} was NOT restored; envelope={v}"
        );
    }
}

/// #1092: with only the ruby-platform copy patched, `vex` must not attest
/// `not_affected` and `apply --check` must not report the patch in sync,
/// because the platform copy RubyGems loads is still vulnerable.
#[test]
fn vex_and_check_refuse_an_unpatched_platform_variant_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, plain_file, platform_file, original, patched) =
        build_platform_variant_project(tmp.path());
    std::fs::write(&plain_file, &patched).unwrap();
    assert_eq!(std::fs::read(&platform_file).unwrap(), original);

    let (code, stdout, stderr) = run_raw(&root, &["vex", "--product", "pkg:gem/app@1.0.0"]);
    assert!(
        !stdout.contains("not_affected"),
        "vex must not attest while the platform copy is unpatched (exit {code})\
         \nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let (code, stdout, stderr) = run_raw(&root, &["apply", "--check"]);
    assert_ne!(
        code, 0,
        "apply --check must flag the unpatched platform copy\
         \nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Once both copies are patched, both gates pass.
    std::fs::write(&platform_file, &patched).unwrap();
    let (code, stdout, stderr) = run_raw(&root, &["vex", "--product", "pkg:gem/app@1.0.0"]);
    assert_eq!(code, 0, "vex\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("not_affected"), "vex doc:\n{stdout}");
    let (code, stdout, stderr) = run_raw(&root, &["apply", "--check"]);
    assert_eq!(
        code, 0,
        "apply --check\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

/// #1092, global mode: `apply -g --global-prefix <gem home>/gems` patches
/// the platform build too (plain RubyGems activates it, no Bundler needed).
#[test]
fn global_apply_covers_every_platform_variant_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, plain_file, platform_file, _original, patched) =
        build_platform_variant_project(tmp.path());
    let gems = plain_file
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let (code, v) = run_json(
        &root,
        &["apply", "-g", "--global-prefix", gems.to_str().unwrap()],
    );
    assert_eq!(code, 0, "apply -g must succeed; envelope={v}");
    for (label, f) in [("plain", &plain_file), ("platform", &platform_file)] {
        assert_eq!(
            std::fs::read(f).unwrap(),
            patched,
            "{label} copy at {f:?} was NOT patched; envelope={v}"
        );
    }
}

/// A platform build whose bytes are not the patch's distribution (a native
/// build that ships a different file) is another distribution, not a
/// locally modified copy: apply patches the plain copy, never overwrites
/// the platform one with the plain build's bytes, and fails loudly because
/// the copy RubyGems loads stays unpatched.
#[test]
fn apply_refuses_a_platform_copy_holding_another_distribution() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, plain_file, platform_file, _original, patched) =
        build_platform_variant_project(tmp.path());
    let native = b"module Rack\n  VERSION = 'NATIVE BUILD'\nend\n".to_vec();
    std::fs::write(&platform_file, &native).unwrap();

    let (code, v) = run_json(&root, &["apply"]);
    assert_ne!(code, 0, "apply must flag the unpatched copy; envelope={v}");
    assert_eq!(std::fs::read(&plain_file).unwrap(), patched, "envelope={v}");
    assert_eq!(
        std::fs::read(&platform_file).unwrap(),
        native,
        "envelope={v}"
    );
}

/// One gem home holding BOTH builds, each a different distribution with its
/// own qualified manifest record (`?platform=ruby` for `rack-3.1.0/`,
/// `?platform=x86_64-linux` for `rack-3.1.0-x86_64-linux/`). Returns
/// `(root, [(plain_file, original, patched), (platform_file, original, patched)])`.
#[allow(clippy::type_complexity)]
fn build_two_variant_project(tmp: &Path) -> (PathBuf, [(PathBuf, Vec<u8>, Vec<u8>); 2]) {
    let gems = tmp
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.2.0")
        .join("gems");
    let socket = tmp.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut records = Vec::new();
    let mut copies = Vec::new();
    for (dir, platform, uuid) in [
        ("rack-3.1.0", "ruby", "67656d6d-756c-4469-8370-72756279302e"),
        (
            "rack-3.1.0-x86_64-linux",
            "x86_64-linux",
            "67656d6d-756c-4469-8370-6c696e7578ff",
        ),
    ] {
        let original = format!("module Rack\n  BUILD = '{platform}'\nend\n").into_bytes();
        let mut patched = original.clone();
        patched.extend_from_slice(format!("# PATCHED-{platform}\n").as_bytes());
        let (before, after) = (git_sha256(&original), git_sha256(&patched));
        std::fs::write(socket.join("blobs").join(&before), &original).unwrap();
        std::fs::write(socket.join("blobs").join(&after), &patched).unwrap();
        records.push(format!(
            r#""{PURL}?platform={platform}": {{
                "uuid": "{uuid}",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {{ "lib/rack.rb": {{
                    "beforeHash": "{before}", "afterHash": "{after}"
                }}}},
                "vulnerabilities": {{ "GHSA-gplt-gplt-gplt": {{
                    "cves": ["CVE-2026-1092"], "summary": "synthetic",
                    "severity": "high", "description": "synthetic"
                }}}},
                "description": "gem platform fixture", "license": "MIT", "tier": "free"
            }}"#
        ));
        copies.push((write_copy(&gems.join(dir), &original), original, patched));
    }
    std::fs::write(
        socket.join("manifest.json"),
        format!(r#"{{ "patches": {{ {} }} }}"#, records.join(",")),
    )
    .unwrap();
    let [a, b]: [(PathBuf, Vec<u8>, Vec<u8>); 2] = copies.try_into().unwrap();
    (tmp.to_path_buf(), [a, b])
}

/// Each build is patched, attested and rolled back with ITS OWN variant,
/// never judged against the other build's bytes.
#[test]
fn each_platform_build_uses_its_own_variant() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, copies) = build_two_variant_project(tmp.path());

    let (code, v) = run_json(&root, &["apply"]);
    assert_eq!(code, 0, "apply must succeed; envelope={v}");
    for (f, _, patched) in &copies {
        assert_eq!(&std::fs::read(f).unwrap(), patched, "{f:?}; envelope={v}");
    }

    let (code, stdout, stderr) = run_raw(&root, &["apply", "--check"]);
    assert_eq!(
        code, 0,
        "apply --check\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let (code, stdout, stderr) = run_raw(&root, &["vex", "--product", "pkg:gem/app@1.0.0"]);
    assert_eq!(code, 0, "vex\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let doc: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let products: Vec<String> = doc["statements"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["status"] == "not_affected")
        .flat_map(|s| s["products"].as_array().unwrap().clone())
        .flat_map(|p| {
            p["subcomponents"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|c| c["@id"].as_str().unwrap_or_default().to_string())
        })
        .collect();
    for platform in ["ruby", "x86_64-linux"] {
        assert!(
            products
                .iter()
                .any(|p| p.ends_with(&format!("platform={platform}"))),
            "the {platform} build must be attested; vex doc:\n{stdout}"
        );
    }

    let (code, v) = run_json(&root, &["rollback", "--yes"]);
    assert_eq!(code, 0, "rollback must succeed; envelope={v}");
    for (f, original, _) in &copies {
        assert_eq!(&std::fs::read(f).unwrap(), original, "{f:?}; envelope={v}");
    }
}

/// After apply refused a build holding another distribution (left
/// untouched), rollback restores the patched build and skips that one.
#[test]
fn rollback_skips_a_platform_copy_holding_another_distribution() {
    let tmp = tempfile::tempdir().unwrap();
    let (root, plain_file, platform_file, original, _patched) =
        build_platform_variant_project(tmp.path());
    let native = b"module Rack\n  VERSION = 'NATIVE BUILD'\nend\n".to_vec();
    std::fs::write(&platform_file, &native).unwrap();
    let (code, v) = run_json(&root, &["apply"]);
    assert_ne!(code, 0, "precondition: apply flags the native build; {v}");

    let (code, v) = run_json(&root, &["rollback", "--yes"]);
    assert_eq!(code, 0, "rollback must succeed; envelope={v}");
    assert_eq!(
        std::fs::read(&plain_file).unwrap(),
        original,
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&platform_file).unwrap(),
        native,
        "envelope={v}"
    );
}
