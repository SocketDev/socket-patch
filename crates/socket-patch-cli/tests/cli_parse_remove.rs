//! Parser-level contract tests for `socket-patch remove`.
//!
//! Locks in every flag in the `RemoveArgs` table from
//! `crates/socket-patch-cli/CLI_CONTRACT.md` (long + short forms, defaults)
//! and exercises one no-network `run()` error path (missing manifest → 1).
//!
//! These tests deliberately avoid spawning the binary so they run in the
//! default `cargo test` set (no `--ignored` required) and stay fast.

use clap::Parser;
use socket_patch_cli::commands::remove::{run, RemoveArgs};
use socket_patch_cli::{Cli, Commands};
use std::path::PathBuf;

fn parse_remove(extra: &[&str]) -> RemoveArgs {
    let mut argv = vec!["socket-patch", "remove"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Remove(a) => a,
        _ => panic!("expected Remove"),
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

#[test]
fn defaults_with_purl_positional() {
    let args = parse_remove(&["pkg:npm/foo@1"]);
    assert_eq!(args.identifier, "pkg:npm/foo@1");
    assert_eq!(args.common.cwd, PathBuf::from("."));
    assert_eq!(args.common.manifest_path, ".socket/manifest.json");
    assert!(!args.skip_rollback);
    assert!(!args.common.yes);
    assert!(!args.common.global);
    assert_eq!(args.common.global_prefix, None);
    assert!(!args.common.json);
}

#[test]
fn positional_uuid_stored_in_identifier() {
    let args = parse_remove(&["80630680-4da6-45f9-bba8-b888e0ffd58c"]);
    assert_eq!(args.identifier, "80630680-4da6-45f9-bba8-b888e0ffd58c");
    // Everything else still at default — `remove` does not auto-detect the
    // identifier shape at parse time; the runtime branch on `pkg:` happens
    // inside `run()`.
    assert_eq!(args.common.cwd, PathBuf::from("."));
    assert_eq!(args.common.manifest_path, ".socket/manifest.json");
    assert!(!args.skip_rollback);
    assert!(!args.common.yes);
    assert!(!args.common.global);
    assert_eq!(args.common.global_prefix, None);
    assert!(!args.common.json);
}

// ---------------------------------------------------------------------------
// Flag forms — each one in the contract table must have a test
// ---------------------------------------------------------------------------

#[test]
fn yes_short_form() {
    let args = parse_remove(&["pkg:npm/foo@1", "-y"]);
    assert!(args.common.yes);
}

#[test]
fn yes_long_form() {
    let args = parse_remove(&["pkg:npm/foo@1", "--yes"]);
    assert!(args.common.yes);
}

#[test]
fn global_short_form() {
    let args = parse_remove(&["pkg:npm/foo@1", "-g"]);
    assert!(args.common.global);
}

#[test]
fn global_long_form() {
    let args = parse_remove(&["pkg:npm/foo@1", "--global"]);
    assert!(args.common.global);
}

#[test]
fn manifest_path_long_form() {
    let args = parse_remove(&[
        "pkg:npm/foo@1",
        "--manifest-path",
        "custom/manifest.json",
    ]);
    assert_eq!(args.common.manifest_path, "custom/manifest.json");
}

#[test]
fn cwd_long_form() {
    let args = parse_remove(&["pkg:npm/foo@1", "--cwd", "/tmp/x"]);
    assert_eq!(args.common.cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn skip_rollback_long_form() {
    let args = parse_remove(&["pkg:npm/foo@1", "--skip-rollback"]);
    assert!(args.skip_rollback);
}

#[test]
fn json_long_form() {
    let args = parse_remove(&["pkg:npm/foo@1", "--json"]);
    assert!(args.common.json);
}

#[test]
fn global_prefix_long_form() {
    let args = parse_remove(&[
        "pkg:npm/foo@1",
        "--global-prefix",
        "/opt/node-global",
    ]);
    assert_eq!(args.common.global_prefix, Some(PathBuf::from("/opt/node-global")));
}

#[test]
fn all_flags_combined() {
    let args = parse_remove(&[
        "pkg:npm/foo@1",
        "--cwd",
        "/tmp/x",
        "--manifest-path",
        "custom/manifest.json",
        "--skip-rollback",
        "-y",
        "-g",
        "--global-prefix",
        "/opt/node-global",
        "--json",
    ]);
    assert_eq!(args.identifier, "pkg:npm/foo@1");
    assert_eq!(args.common.cwd, PathBuf::from("/tmp/x"));
    assert_eq!(args.common.manifest_path, "custom/manifest.json");
    assert!(args.skip_rollback);
    assert!(args.common.yes);
    assert!(args.common.global);
    assert_eq!(args.common.global_prefix, Some(PathBuf::from("/opt/node-global")));
    assert!(args.common.json);
}

// ---------------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------------

#[test]
fn missing_required_positional_is_error() {
    let result = Cli::try_parse_from(["socket-patch", "remove"]);
    let err = match result {
        Ok(_) => panic!("remove without identifier must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn unknown_flag_is_error() {
    let result = Cli::try_parse_from([
        "socket-patch",
        "remove",
        "pkg:npm/foo@1",
        "--not-a-real-flag",
    ]);
    let err = match result {
        Ok(_) => panic!("unknown flag must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// ---------------------------------------------------------------------------
// Async run() — no-network error path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_missing_manifest_exits_one() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let args = RemoveArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tempdir.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            yes: true,
            global: false,
            global_prefix: None,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: "pkg:npm/foo@1".to_string(),
        skip_rollback: false,
    };
    let exit = run(args).await;
    assert_eq!(exit, 1, "missing manifest must exit 1");

    // Side-effect guard: the missing-manifest path must NOT fabricate a
    // manifest (or any `.socket/` state). An implementation that created
    // an empty manifest and then "succeeded" would otherwise look fine to
    // an exit-code-only assertion.
    assert!(
        !tempdir.path().join(".socket/manifest.json").exists(),
        "run() must not create a manifest when none exists"
    );
}

/// Contrast partner to `run_missing_manifest_exits_one`: drives the FULL
/// `run()` removal path (not the early manifest-not-found short-circuit) and
/// proves it (a) exits 0 and (b) actually mutates the manifest on disk —
/// removing the targeted entry while leaving an unrelated one intact.
///
/// Without this, the only `run()` coverage is an error short-circuit, so a
/// broken `run()` that *always* returned 1 — or that returned 0 without ever
/// touching the manifest — would still pass the suite.
#[tokio::test]
async fn run_removes_matching_patch_and_exits_zero() {
    use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use std::collections::HashMap;

    fn record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "test".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");

    let mut patches = HashMap::new();
    patches.insert(
        "pkg:npm/foo@1".to_string(),
        record("11111111-1111-1111-1111-111111111111"),
    );
    patches.insert(
        "pkg:npm/bar@2".to_string(),
        record("22222222-2222-2222-2222-222222222222"),
    );
    write_manifest(&manifest_path, &PatchManifest { patches })
        .await
        .expect("write manifest");

    let args = RemoveArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tempdir.path().to_path_buf(),
            // Relative to cwd → resolves to the manifest we just wrote; its
            // parent (the tempdir) is the `.socket`-equivalent lock dir.
            manifest_path: "manifest.json".to_string(),
            yes: true,
            json: true,
            // Keep the test fully offline: no telemetry network call.
            offline: true,
            no_telemetry: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: "pkg:npm/foo@1".to_string(),
        // Skip rollback so we exercise the manifest-mutation path without
        // needing installed packages on disk.
        skip_rollback: true,
    };
    let exit = run(args).await;
    assert_eq!(exit, 0, "removing an existing patch must exit 0");

    // The on-disk manifest must reflect the removal: `foo` gone, `bar` kept.
    let after = read_manifest(&manifest_path)
        .await
        .expect("read manifest")
        .expect("manifest still present");
    assert!(
        !after.patches.contains_key("pkg:npm/foo@1"),
        "removed patch must be gone from the manifest file"
    );
    assert!(
        after.patches.contains_key("pkg:npm/bar@2"),
        "unrelated patch must remain"
    );
    assert_eq!(after.patches.len(), 1, "exactly one patch should remain");
}
