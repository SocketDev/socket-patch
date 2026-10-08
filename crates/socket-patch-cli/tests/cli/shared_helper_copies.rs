//! One `binary()` and one `git_sha256` for every CLI test target (#824).
//!
//! `common/mod.rs` owns both helpers, and its own tests pin `git_sha256`
//! to the canonical Git-blob hash and to production's
//! `compute_git_sha256_from_bytes` (the two shapes the per-file copies
//! took). This ratchet keeps new private copies out: a file may define its
//! own only while it is listed below.

use std::path::Path;

/// Files that still define a private `binary()` or `git_sha256`. Each is
/// changed by an open PR, or is a shared module whose includers don't all
/// declare `mod common`. Migrate a file onto `common` and delete its entry;
/// a stale entry is not an error, so a PR that migrates one never turns
/// another red.
const PENDING_PRIVATE_HELPERS: &[&str] = &[
    "apply/apply_network.rs",
    "apply/in_process_npm_multicopy.rs",
    "cli/api_client_errors_e2e.rs",
    "cli/covgap_api_client.rs",
    "cli/output_modes_e2e.rs",
    "cli/telemetry_e2e.rs",
    "cli_scan_silent.rs",
    "covgap_commands_scan_mod.rs",
    "diff_created_file_e2e.rs",
    "docker_e2e_npm.rs",
    "docker_e2e_nuget.rs",
    "docker_e2e_pypi.rs",
    "e2e_embedded_vex.rs",
    "e2e_gem.rs",
    "e2e_hosted_production.rs",
    "e2e_npm.rs",
    "e2e_pypi.rs",
    "e2e_redirect_gem_build.rs",
    "e2e_redirect_gradle_build.rs",
    "e2e_redirect_npm_build.rs",
    "e2e_redirect_pnpm_build.rs",
    "e2e_scan.rs",
    "e2e_vendor_composer_build.rs",
    "e2e_vendor_npm_build.rs",
    "e2e_vendor_pnpm_build.rs",
    "e2e_vendor_pypi_build.rs",
    "e2e_vex_lockfile/cargo.rs",
    "e2e_vex_lockfile/maven.rs",
    "e2e_vex_lockfile/uv.rs",
    "e2e_vex_lockfile/yarn.rs",
    "e2e_vex_redirect.rs",
    "e2e_vex_vendor.rs",
    "get/get_batch_paths_e2e.rs",
    "get/global_packages_e2e.rs",
    "in_process_agent_reapply.rs",
    "in_process_alternate_installers.rs",
    "in_process_cargo_apply.rs",
    "in_process_edge_cases.rs",
    "in_process_gem_apply.rs",
    "in_process_gem_multi_platform.rs",
    "in_process_get_manifest_path.rs",
    "in_process_pypi_apply.rs",
    "in_process_pypi_multi_release.rs",
    "in_process_remote_ecosystems_apply.rs",
    "in_process_remove_repair_lifecycle.rs",
    "mode_migration_cargo.rs",
    "mode_migration_npm.rs",
    "remove/covgap_commands_remove.rs",
    "remove_rollback_api_overrides.rs",
    "repair/coverage_fix_repair_vendor_predelete.rs",
    "repair/covgap_commands_repair.rs",
    "repair/covgap_commands_repair_vendor.rs",
    "repair/repair_invariants.rs",
    "repair/repair_vendor_e2e.rs",
    "repair/repair_vendor_flavors_e2e.rs",
    "rollback/rollback_invariants.rs",
    "rollback/rollback_multicopy_blob_gate.rs",
    "scan/covgap_commands_fetch_stage.rs",
    "scan/covgap_commands_scan_vendor_flow.rs",
    "scan/scan_invariants.rs",
    "scan/scan_paths_e2e.rs",
    "scan/scan_sync_e2e.rs",
    "scan/scan_vendor_step_error_e2e.rs",
    "scan_rollout_e2e.rs",
    "scan_vendor_e2e.rs",
    "vendor_ecosystem_fixtures/mod.rs",
    "vendor_jvm_cli.rs",
    "vex_e2e_common/mod.rs",
    "vlt_e2e_common/mod.rs",
    "vlt_hosted_common/mod.rs",
    "vlt_vendor_common/mod.rs",
];

/// Every `.rs` file under `tests/`, as (`/`-joined relative path, text).
fn test_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.push((rel, text));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out
}

/// Whether `text` defines a `binary()` or `git_sha256(..)` of its own.
fn defines_private_helper(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim_start();
        let line = line
            .strip_prefix("pub(crate) ")
            .or_else(|| line.strip_prefix("pub "))
            .unwrap_or(line);
        line.starts_with("fn binary()") || line.starts_with("fn git_sha256(")
    })
}

#[test]
fn no_new_private_binary_or_git_sha256() {
    let unexpected: Vec<String> = test_sources()
        .into_iter()
        .filter(|(rel, text)| {
            !rel.starts_with("common/")
                && !PENDING_PRIVATE_HELPERS.contains(&rel.as_str())
                && defines_private_helper(text)
        })
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        unexpected.is_empty(),
        "these test files define their own binary() or git_sha256: {unexpected:?}. \
         Use `common::binary` / `common::git_sha256` instead (declare \
         `#[path = \"common/mod.rs\"] mod common;`, or `use crate::common::..` in a \
         directory test binary). Do not add them to PENDING_PRIVATE_HELPERS."
    );
}

#[test]
fn the_detector_sees_every_former_copy_shape() {
    for copy in [
        "fn binary() -> PathBuf {\n    env!(\"CARGO_BIN_EXE_socket-patch\").into()\n}",
        "fn binary() -> &'static str {\n    env!(\"CARGO_BIN_EXE_socket-patch\")\n}",
        "    fn binary() -> PathBuf {",
        "pub fn git_sha256(bytes: &[u8]) -> String {",
        "fn git_sha256(content: &[u8]) -> String {",
    ] {
        assert!(defines_private_helper(copy), "missed: {copy}");
    }
    for not_a_copy in [
        "use common::{binary, git_sha256};",
        "let out = Command::new(binary()).output();",
        "pub fn git_sha256_file(path: &Path) -> String {",
    ] {
        assert!(
            !defines_private_helper(not_a_copy),
            "false positive: {not_a_copy}"
        );
    }
}
