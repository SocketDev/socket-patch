//! Shared fixture for the `vex` suite (#1089): the manifest and ledger
//! writers and the runners `vex_failure_paths.rs` (the `--json` contracts),
//! `vex_go_patches.rs` (the go-patches synthesis guards) and `vex_render.rs`
//! (the human output) build on.
//!
//! Every run drives the built binary in a self-contained tempdir project
//! with the hermetic `SOCKET_*` environment; the parent env is never
//! mutated, so no test needs serialization.

// Each suite uses a different subset, and some only from `cfg(unix)` tests.
#![allow(dead_code, unused_imports)]

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Output};

pub(crate) use serde_json::Value;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};

use crate::common;
pub(crate) use crate::common::envelope::{
    assert_envelope_invariants, envelope_error_code, envelope_error_message, event_purls, events,
    has_event, parse_json_envelope, warning_codes,
};

/// The product every run names unless it tests auto-detection.
pub(crate) const PRODUCT: &str = "pkg:npm/app@1.0.0";

/// A prior successful run's minimal-but-recognizable OpenVEX document (the
/// `@context` names openvex.dev, which is what `remove_stale_vex_doc` keys
/// its deletion guard on).
pub(crate) const STALE_OPENVEX_DOC: &str = r#"{"@context":"https://openvex.dev/ns/v0.2.0","@id":"urn:uuid:stale","author":"Socket","timestamp":"2020-01-01T00:00:00Z","version":1,"statements":[]}"#;

/// The bytes of a malformed pre-v5 redirect ledger.
pub(crate) const CORRUPT_REDIRECT_LEDGER: &str = "{{{";

/// The bytes of a corrupt vendor ledger.
pub(crate) const CORRUPT_VENDOR_LEDGER: &str = "not json";

/// Patch record with one file (whose hashes you choose) and one
/// vulnerability.
pub(crate) fn make_record(
    uuid: &str,
    file_name: &str,
    before_hash: &str,
    after_hash: &str,
    vuln_id: &str,
    cves: &[&str],
) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        file_name.to_string(),
        PatchFileInfo {
            before_hash: before_hash.to_string(),
            after_hash: after_hash.to_string(),
        },
    );
    let mut vulns = HashMap::new();
    vulns.insert(
        vuln_id.to_string(),
        VulnerabilityInfo {
            cves: cves.iter().map(|s| s.to_string()).collect(),
            summary: "test summary".to_string(),
            severity: "high".to_string(),
            description: "test description".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: vulns,
        description: format!("Patch {uuid}"),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// Write `manifest` to `<cwd>/.socket/manifest.json`.
pub(crate) fn write_manifest(cwd: &Path, manifest: &PatchManifest) {
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(manifest).unwrap(),
    )
    .unwrap();
}

/// A manifest with one npm patch per purl (each with a distinct GHSA,
/// `GHSA-test-<i>`), none of them on disk: verify mode omits each as
/// `package_not_found`, and `--no-verify` attests them all.
pub(crate) fn write_npm_manifest(cwd: &Path, purls: &[&str]) {
    let mut manifest = PatchManifest::new();
    for (i, purl) in purls.iter().enumerate() {
        manifest.patches.insert(
            purl.to_string(),
            make_record(
                &format!("{:08}-1111-4111-8111-111111111111", i + 1),
                "package/index.js",
                &"a".repeat(64),
                &"b".repeat(64),
                &format!("GHSA-test-{i}"),
                &["CVE-2026-0001"],
            ),
        );
    }
    write_manifest(cwd, &manifest);
}

/// A present-but-unparseable `.socket/manifest.json`.
pub(crate) fn write_corrupt_manifest(cwd: &Path) {
    std::fs::create_dir_all(cwd.join(".socket")).unwrap();
    std::fs::write(cwd.join(".socket/manifest.json"), "{not json").unwrap();
}

/// A malformed pre-v5 redirect ledger at its canonical path.
pub(crate) fn write_corrupt_redirect_ledger(cwd: &Path) {
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("redirect-state.json"), CORRUPT_REDIRECT_LEDGER).unwrap();
}

/// vex is a read-only consumer: the malformed pre-v5 ledger stays
/// byte-identical and is never quarantined.
pub(crate) fn assert_redirect_ledger_untouched(cwd: &Path) {
    let ledger = cwd.join(".socket/vendor/redirect-state.json");
    assert_eq!(
        std::fs::read_to_string(&ledger).unwrap(),
        CORRUPT_REDIRECT_LEDGER
    );
    assert!(!cwd
        .join(".socket/vendor/redirect-state.json.corrupt")
        .exists());
}

/// A corrupt vendor ledger at `.socket/vendor/state.json`.
pub(crate) fn write_corrupt_vendor_ledger(cwd: &Path) {
    let dir = cwd.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("state.json"), CORRUPT_VENDOR_LEDGER).unwrap();
}

/// The vendor ledger may hold the only revert data for committed vendoring,
/// so vex never moves or rewrites it.
pub(crate) fn assert_vendor_ledger_untouched(cwd: &Path) {
    let dir = cwd.join(".socket/vendor");
    assert_eq!(
        std::fs::read_to_string(dir.join("state.json")).unwrap(),
        CORRUPT_VENDOR_LEDGER
    );
    assert!(!dir.join("state.json.corrupt").exists());
}

/// package.json AND Cargo.toml (no .git) plus a one-patch manifest:
/// auto-detect must pick package.json, so the product is `PRODUCT`.
pub(crate) fn write_multi_manifest_project(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(
        cwd.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    write_npm_manifest(cwd, &["pkg:npm/x@1.0.0"]);
}

/// `vex --cwd <cwd>` (plus `--product` when given) in the hermetic env,
/// run from `cwd`.
pub(crate) fn vex_command(cwd: &Path, product: Option<&str>) -> Command {
    let mut cmd = common::hermetic::binary_command();
    cmd.current_dir(cwd)
        .args(["vex", "--cwd", cwd.to_str().unwrap()]);
    if let Some(product) = product {
        cmd.args(["--product", product]);
    }
    cmd
}

/// `vex` for `PRODUCT` with `extra` flags.
pub(crate) fn vex(cwd: &Path, extra: &[&str]) -> Output {
    vex_command(cwd, Some(PRODUCT))
        .args(extra)
        .output()
        .expect("invoke vex")
}

/// `cmd --json --output <out>`: the output and its parsed envelope, checked
/// against the shared envelope invariants.
pub(crate) fn run_json(mut cmd: Command, out: &Path) -> (Output, Value) {
    let o = cmd
        .args(["--json", "--output", out.to_str().unwrap()])
        .output()
        .expect("invoke vex --json");
    let env = parse_json_envelope(&stdout(&o));
    assert_envelope_invariants(&env, "vex");
    (o, env)
}

/// `vex --json --output <cwd>/out.vex.json` for `PRODUCT` with `extra`.
pub(crate) fn vex_json(cwd: &Path, extra: &[&str]) -> (Output, Value) {
    let mut cmd = vex_command(cwd, Some(PRODUCT));
    cmd.args(extra);
    run_json(cmd, &cwd.join("out.vex.json"))
}

/// The OpenVEX document a successful run wrote to `path`.
pub(crate) fn read_doc(path: &Path) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub(crate) fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub(crate) fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
