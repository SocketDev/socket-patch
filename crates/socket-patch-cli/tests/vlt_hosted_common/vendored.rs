//! A vlt project vendored at [`super::UUID`] with the hosted fixture's
//! bytes, for the suites that pair a vendored vlt ledger with the hosted
//! wiremock API (takeovers, overlap warnings, GC, list, remove).
//!
//! Include as a child of `vlt_hosted_common`:
//! `#[path = "vlt_hosted_common/vendored.rs"] mod vlt_vendored;` next to
//! `mod vlt_hosted_common;`, then `use crate::vlt_hosted_common as hosted;`.

#![allow(dead_code)]

use std::path::Path;

use serde_json::json;

use crate::vlt_hosted_common::{self as hosted, PATCHED, PRISTINE, PURL, TILDE_ID, UUID};

pub const PACKAGE_JSON: &str =
    "{\n  \"name\": \"consumer\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";

pub fn registry_lock() -> String {
    format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    {}\n  }},\n  \
         \"edges\": {{\n    \"file~_d left-pad\": \"prod 1.3.0 {TILDE_ID}\"\n  }}\n}}\n",
        hosted::registry_node(TILDE_ID)
    )
}

pub fn rel() -> String {
    format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad")
}

/// The registry project (lock, package.json, a pristine importer copy).
pub fn write_project(root: &Path) {
    std::fs::write(root.join("vlt-lock.json"), registry_lock()).unwrap();
    std::fs::write(root.join("package.json"), PACKAGE_JSON).unwrap();
    hosted::install_importer(root, PRISTINE);
}

/// The manifest record + after-hash blob `vendor --offline` reads.
pub fn seed_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut record = hosted::view_body();
    record.as_object_mut().unwrap().remove("purl");
    record["exportedAt"] = json!("2026-01-01T00:00:00Z");
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": { PURL: record } })).unwrap(),
    )
    .unwrap();
    std::fs::write(
        socket.join("blobs").join(hosted::git_sha256(PATCHED)),
        PATCHED,
    )
    .unwrap();
}

/// [`write_project`] vendored by `vendor --offline`; `keep_manifest`
/// leaves the manifest in place (manifest-driven entry).
pub fn vendored_project(root: &Path, keep_manifest: bool) {
    write_project(root);
    seed_manifest(root);
    let cwd = root.to_str().unwrap().to_string();
    let (code, env, stderr) = hosted::run_json(root, &["vendor", "--offline", "--cwd", &cwd], &[]);
    assert_eq!(code, 0, "vendor: {env:#}\n{stderr}");
    assert!(root.join(rel()).join("index.js").is_file());
    if !keep_manifest {
        std::fs::remove_file(root.join(".socket/manifest.json")).unwrap();
    }
}

pub fn state(root: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root.join(".socket/vendor/state.json")).unwrap()).unwrap()
}
