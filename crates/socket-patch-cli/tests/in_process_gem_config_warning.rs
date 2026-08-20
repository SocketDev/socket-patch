//! Machine-readable surfacing of the gem config-root containment skip.
//!
//! A repo-committed `.bundle/config` whose `BUNDLE_PATH` resolves outside
//! the project root is SKIPPED by the crawler's containment guard (see
//! `resolve_config_bundle_path`). That skip must be observable per the
//! repo-wide warning conventions:
//!   * `--json` envelopes of scan and apply carry a run-level `warnings[]`
//!     entry with code `gem_bundle_config_path_ignored` and the config
//!     value + remedy in `detail`;
//!   * non-JSON runs print ONE stderr warning, gated on `!--silent`
//!     (`--silent` = errors only — a bare crawler eprintln violated that).

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const PURL: &str = "pkg:gem/rack@3.1.0";
const CODE: &str = "gem_bundle_config_path_ignored";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Project fixture: Gemfile + `.bundle/config` pointing `BUNDLE_PATH` at
/// an ABSOLUTE directory outside the project (holding a real store, so
/// the only reason it goes undiscovered is the containment skip), plus —
/// when `with_store` — a legit `vendor/bundle` scoped store carrying a
/// patchable rack@3.1.0 and a staged manifest + blob.
fn build_project(root: &Path, outside: &Path, with_store: bool) {
    std::fs::write(root.join("Gemfile"), b"source 'https://rubygems.org'\n").unwrap();
    std::fs::create_dir_all(root.join(".bundle")).unwrap();
    std::fs::write(
        root.join(".bundle").join("config"),
        format!("---\nBUNDLE_PATH: \"{}\"\n", outside.display()),
    )
    .unwrap();
    // The out-of-tree store the config names.
    std::fs::create_dir_all(outside.join("gems").join("rack-3.1.0").join("lib")).unwrap();
    std::fs::create_dir_all(outside.join("specifications")).unwrap();

    if with_store {
        let original = b"module Rack\n  VERSION = 'VULNERABLE'\nend\n";
        let mut patched = original.to_vec();
        patched.extend_from_slice(b"# SOCKET-PATCHED\n");
        let before_hash = git_sha256(original);
        let after_hash = git_sha256(&patched);

        let gem_lib = root
            .join("vendor")
            .join("bundle")
            .join("ruby")
            .join("3.2.0")
            .join("gems")
            .join("rack-3.1.0")
            .join("lib");
        std::fs::create_dir_all(&gem_lib).unwrap();
        std::fs::write(gem_lib.join("rack.rb"), original).unwrap();

        let socket = root.join(".socket");
        std::fs::create_dir_all(socket.join("blobs")).unwrap();
        std::fs::write(
            socket.join("manifest.json"),
            format!(
                r#"{{ "patches": {{
                    "{PURL}": {{
                        "uuid": "636f6e66-6967-4761-8264-000000000000",
                        "exportedAt": "2024-01-01T00:00:00Z",
                        "files": {{ "lib/rack.rb": {{
                            "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                        }}}},
                        "vulnerabilities": {{}}, "description": "config-warning fixture",
                        "license": "MIT", "tier": "free"
                    }}
                }}}}"#
            ),
        )
        .unwrap();
        std::fs::write(socket.join("blobs").join(&after_hash), &patched).unwrap();
    }
}

/// Run the binary with SOCKET_*/BUNDLE_* scrubbed and PATH pointed at an
/// empty dir, so no ambient bundler config and no real `gem` binary can
/// perturb discovery.
fn run(root: &Path, args: &[&str]) -> (i32, String, String) {
    let empty_path = root.join("empty-bin");
    std::fs::create_dir_all(&empty_path).unwrap();
    let mut cmd = Command::new(binary());
    cmd.args(args).arg("--cwd").arg(root);
    for (key, _) in std::env::vars_os() {
        let k = key.to_string_lossy();
        if (k.starts_with("SOCKET_") && k != "SOCKET_NO_CONFIG") || k.starts_with("BUNDLE_") {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd.env("PATH", &empty_path);
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn assert_warning_in(env: &serde_json::Value, value_fragment: &str, ctx: &str) {
    let warnings = env
        .get("warnings")
        .and_then(|w| w.as_array())
        .unwrap_or_else(|| panic!("{ctx}: envelope must carry warnings[].\nenvelope: {env}"));
    let w = warnings
        .iter()
        .find(|w| w.get("code").and_then(|c| c.as_str()) == Some(CODE))
        .unwrap_or_else(|| panic!("{ctx}: warnings[] must contain code={CODE}.\nenvelope: {env}"));
    let detail = w
        .get("detail")
        .and_then(|d| d.as_str())
        .unwrap_or_else(|| panic!("{ctx}: warning must carry detail.\nenvelope: {env}"));
    assert!(
        detail.contains(value_fragment),
        "{ctx}: detail must name the skipped config value ({value_fragment}); got: {detail}"
    );
    assert!(
        detail.contains("BUNDLE_PATH"),
        "{ctx}: detail must explain the remedy in terms of BUNDLE_PATH; got: {detail}"
    );
}

/// `scan --json` on a project whose committed config points out of tree
/// must carry the machine-readable warning (zero-package early-return
/// path: no `gem` binary + skipped store = nothing discovered, exactly
/// the run where the skip explains the emptiness).
#[test]
fn scan_json_carries_config_path_ignored_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    build_project(tmp.path(), outside.path(), false);

    let (code, stdout, stderr) = run(tmp.path(), &["scan", "--json", "--yes"]);
    assert_eq!(
        code, 0,
        "scan exits 0.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("scan must emit JSON: {e}; stdout={stdout}"));
    let outside_str = outside.path().display().to_string();
    assert_warning_in(&env, &outside_str, "scan --json");
}

/// `apply --json` must carry the same run-level warning while the legit
/// `vendor/bundle` store still patches cleanly (exit 0, applied 1).
#[test]
fn apply_json_carries_config_path_ignored_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    build_project(tmp.path(), outside.path(), true);

    let (code, stdout, stderr) = run(
        tmp.path(),
        &["apply", "--json", "--offline", "--ecosystems", "gem"],
    );
    let env: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("apply must emit JSON: {e}; stdout={stdout}"));
    assert_eq!(
        code, 0,
        "apply exits 0.\nenvelope: {env}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "success", "envelope: {env}");
    assert_eq!(
        env["summary"]["applied"], 1,
        "the in-tree store copy still patches.\nenvelope: {env}"
    );
    let outside_str = outside.path().display().to_string();
    assert_warning_in(&env, &outside_str, "apply --json");
}

/// Non-JSON runs: exactly one gated stderr warning. Loud control first
/// (without --silent the warning must appear, with the code and the
/// config value), then the gate (--silent = errors only: no warning).
#[test]
fn apply_stderr_warning_gates_on_silent() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    build_project(tmp.path(), outside.path(), true);

    // Loud control: the warning must reach stderr (proves the silent
    // assertion below isn't passing vacuously).
    let (code, _stdout, stderr) = run(tmp.path(), &["apply", "--offline", "--ecosystems", "gem"]);
    assert_eq!(code, 0, "loud apply exits 0.\nstderr:\n{stderr}");
    assert!(
        stderr.contains(CODE),
        "non-silent stderr must carry the {CODE} warning; got:\n{stderr}"
    );
    assert_eq!(
        stderr.matches(CODE).count(),
        1,
        "exactly ONE warning line (not one per discovery call); got:\n{stderr}"
    );
    assert!(
        stderr.contains(&outside.path().display().to_string()),
        "the warning must name the config value; got:\n{stderr}"
    );

    // Reset the store bytes so the second run applies identically.
    // (apply is idempotent — already-patched just skips — so no reset
    // is actually required for exit semantics; keep the run as-is.)
    let (code, _stdout, stderr) = run(
        tmp.path(),
        &["apply", "--offline", "--ecosystems", "gem", "--silent"],
    );
    assert_eq!(code, 0, "silent apply exits 0.\nstderr:\n{stderr}");
    assert!(
        !stderr.contains(CODE),
        "--silent is errors-only: the {CODE} warning must not print; got:\n{stderr}"
    );
}
