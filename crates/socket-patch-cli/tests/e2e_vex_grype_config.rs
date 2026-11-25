//! `vex --grype-config`: the document is listed in the Grype config's
//! `vex-documents`, and taken out again when a run leaves no document.

#[path = "common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::path::Path;
use std::process::Output;

use serde_json::Value;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};

const CONFIG: &str = ".grype.yaml";
const DOCUMENT: &str = "socket.vex.json";

fn write_manifest(cwd: &Path, purls: &[&str]) {
    let mut manifest = PatchManifest::new();
    for purl in purls {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: "a".repeat(64),
                after_hash: "b".repeat(64),
            },
        );
        let mut vulnerabilities = HashMap::new();
        vulnerabilities.insert(
            "GHSA-aaaa-bbbb-cccc".to_string(),
            VulnerabilityInfo {
                cves: vec!["CVE-2024-1111".to_string()],
                summary: "test summary".to_string(),
                severity: "high".to_string(),
                description: "test description".to_string(),
            },
        );
        manifest.patches.insert(
            purl.to_string(),
            PatchRecord {
                uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities,
                description: "test".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
    }
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// `vex --output socket.vex.json --json` in `cwd`, plus `extra`.
fn vex(cwd: &Path, extra: &[&str]) -> (Output, Value) {
    let out = common::hermetic::binary_command()
        .current_dir(cwd)
        .args([
            "vex",
            "--cwd",
            ".",
            "--no-verify",
            "--product",
            "pkg:npm/test-app@1.0.0",
            "--output",
            DOCUMENT,
            "--json",
        ])
        .args(extra)
        .output()
        .expect("invoke vex");
    let envelope = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "envelope: {e}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out, envelope)
}

fn config(cwd: &Path) -> String {
    std::fs::read_to_string(cwd.join(CONFIG)).unwrap()
}

#[test]
fn a_missing_config_is_created_and_a_second_run_leaves_it() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/lodash@4.17.20"]);

    let (out, envelope) = vex(cwd, &["--grype-config"]);
    assert!(out.status.success(), "{envelope}");
    assert_eq!(envelope["grypeConfig"]["change"], "created", "{envelope}");
    assert_eq!(envelope["grypeConfig"]["entry"], DOCUMENT);
    assert_eq!(config(cwd), "vex-documents:\n  - socket.vex.json\n");

    let (out, envelope) = vex(cwd, &["--grype-config"]);
    assert!(out.status.success(), "{envelope}");
    assert_eq!(envelope["grypeConfig"]["change"], "listed", "{envelope}");
    assert_eq!(config(cwd), "vex-documents:\n  - socket.vex.json\n");
}

#[test]
fn an_existing_config_keeps_its_lines() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/lodash@4.17.20"]);
    let before = "# team settings\nfail-on-severity: high\nvex-documents:\n  - other.vex.json\n";
    std::fs::write(cwd.join(CONFIG), before).unwrap();

    let (out, envelope) = vex(cwd, &["--grype-config", CONFIG]);
    assert!(out.status.success(), "{envelope}");
    assert_eq!(envelope["grypeConfig"]["change"], "added", "{envelope}");
    assert_eq!(config(cwd), format!("{before}  - socket.vex.json\n"));
}

#[test]
fn a_run_that_leaves_no_document_takes_the_entry_out() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/lodash@4.17.20"]);
    let (out, envelope) = vex(cwd, &["--grype-config"]);
    assert!(out.status.success(), "{envelope}");
    assert!(cwd.join(DOCUMENT).exists());

    // Nothing left to attest: the run removes the previous document, and
    // with it the entry Grype would fail on.
    write_manifest(cwd, &[]);
    // A dry run keeps the document but says the entry would go with it.
    let (out, envelope) = vex(cwd, &["--grype-config", "--dry-run"]);
    assert!(!out.status.success(), "{envelope}");
    assert!(cwd.join(DOCUMENT).exists());
    assert_eq!(config(cwd), "vex-documents:\n  - socket.vex.json\n");
    assert_eq!(
        envelope["grypeConfig"]["change"], "would_remove",
        "{envelope}"
    );

    let (out, envelope) = vex(cwd, &["--grype-config"]);
    assert!(!out.status.success(), "{envelope}");
    assert!(!cwd.join(DOCUMENT).exists());
    assert_eq!(config(cwd), "vex-documents:\n");
    assert_eq!(envelope["grypeConfig"]["change"], "removed", "{envelope}");
}

#[test]
fn a_switch_value_in_the_env_names_the_default_config() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/lodash@4.17.20"]);
    let out = common::hermetic::binary_command()
        .current_dir(cwd)
        .env("SOCKET_VEX_GRYPE_CONFIG", "true")
        .args([
            "vex",
            "--no-verify",
            "--product",
            "pkg:npm/test-app@1.0.0",
            "--output",
            DOCUMENT,
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!cwd.join("true").exists());
    assert_eq!(config(cwd), "vex-documents:\n  - socket.vex.json\n");
}

#[test]
fn a_config_it_cannot_edit_is_left_alone_with_a_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/lodash@4.17.20"]);
    let before = "vex-documents: [other.vex.json]\n";
    std::fs::write(cwd.join(CONFIG), before).unwrap();

    let (out, envelope) = vex(cwd, &["--grype-config"]);
    assert!(out.status.success(), "the document is written: {envelope}");
    assert_eq!(envelope["grypeConfig"]["change"], "not_updated");
    let warnings = envelope["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w["code"] == "grype_config_not_updated"),
        "{envelope}"
    );
    assert_eq!(config(cwd), before);
    assert!(cwd.join(DOCUMENT).exists());
}

#[test]
fn dry_run_says_what_it_would_do() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/lodash@4.17.20"]);

    let (out, envelope) = vex(cwd, &["--grype-config", "--dry-run"]);
    assert!(out.status.success(), "{envelope}");
    assert_eq!(envelope["grypeConfig"]["change"], "would_create");
    assert!(!cwd.join(CONFIG).exists());
}

#[test]
fn grype_config_needs_an_output_file() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &["pkg:npm/lodash@4.17.20"]);
    let out = common::hermetic::binary_command()
        .current_dir(cwd)
        .args([
            "vex",
            "--no-verify",
            "--product",
            "pkg:npm/test-app@1.0.0",
            "--grype-config",
        ])
        .output()
        .expect("invoke vex");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--grype-config requires --output"));
    assert!(!cwd.join(CONFIG).exists());
}
