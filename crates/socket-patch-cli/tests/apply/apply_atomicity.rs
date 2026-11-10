//! `apply` and `rollback` leave a package fully original or fully patched,
//! with the permission bits it had: an interruption right after a file's
//! rename, a rename that fails half-way through a package, and a corrupt
//! blob for a later file. The failures are injected with the engine's
//! failpoints (`socket_patch_core::utils::failpoint`), which the test build
//! of the binary carries. Also what `apply --force` reports about a file it
//! skipped.

use serde_json::json;

use crate::apply_fixture::*;
use crate::common::envelope::{events, find_event, json_string, parse_json_envelope};
use crate::common::git_sha256;

const PURL: &str = "pkg:npm/atomic-pkg@1.0.0";
const FILES: [&str; 3] = ["f000.js", "f001.js", "f002.js"];

fn before(name: &str) -> Vec<u8> {
    format!("// {name}: original\n").into_bytes()
}

fn after(name: &str) -> Vec<u8> {
    format!("// {name}: patched\n").into_bytes()
}

/// A project with `atomic-pkg` installed (three files) and a manifest
/// record patching all three, blobs staged. Returns the package dir.
fn three_file_project(root: &std::path::Path) -> std::path::PathBuf {
    write_root_package_json(root);
    install_npm_pkg(root, "atomic-pkg", "1.0.0", None);
    let pkg = root.join("node_modules/atomic-pkg");
    let mut files = serde_json::Map::new();
    for name in FILES {
        std::fs::write(pkg.join(name), before(name)).unwrap();
        files.insert(
            format!("package/{name}"),
            json!({
                "beforeHash": git_sha256(&before(name)),
                "afterHash": git_sha256(&after(name)),
            }),
        );
    }
    write_manifest(
        root,
        json!({ PURL: patch_record("aaaaaaaa-0000-4000-8000-000000000001", files.into()) }),
    );
    for name in FILES {
        stage_blob(root, &git_sha256(&after(name)), &after(name));
    }
    pkg
}

fn assert_all_original(pkg: &std::path::Path) {
    for name in FILES {
        assert_eq!(
            std::fs::read(pkg.join(name)).unwrap(),
            before(name),
            "{name} must hold its original bytes"
        );
    }
}

fn assert_no_stage_litter(pkg: &std::path::Path) {
    let litter: Vec<String> = std::fs::read_dir(pkg)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".socket-"))
        .collect();
    assert!(litter.is_empty(), "stage litter left behind: {litter:?}");
}

/// The process dies right after a file's rename: the file already holds
/// the patched bytes, so it must already hold its permission bits too. A
/// later `apply` sees it as patched and would never repair them.
#[cfg(unix)]
#[test]
fn interrupt_after_the_rename_keeps_the_permission_bits() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let pkg = three_file_project(tmp.path());
    for name in FILES {
        std::fs::set_permissions(pkg.join(name), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let (code, _, stderr) = run_apply(
        tmp.path(),
        &["--json", "--offline"],
        &[("SOCKET_PATCH_FAILPOINT", "patch_file_committed")],
    );
    assert_eq!(code, 86, "the failpoint must end the run; stderr={stderr}");

    assert_eq!(
        std::fs::read(pkg.join("f000.js")).unwrap(),
        after("f000.js"),
        "the first file was renamed into place before the interruption"
    );
    for name in FILES {
        let mode = std::fs::metadata(pkg.join(name))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o755, "{name} lost its mode to the interruption");
    }
}

/// The second of three renames fails: the first file is put back, the
/// failure names the file, and a second run applies the whole package.
#[test]
fn a_rename_failing_midway_leaves_the_package_original() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = three_file_project(tmp.path());

    let (code, stdout, stderr) = run_apply(
        tmp.path(),
        &["--json", "--offline"],
        &[("SOCKET_PATCH_FAILPOINT", "patch_file_commit@2~error")],
    );
    assert_eq!(code, 1, "a failed package fails the run; stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(json_string(&env, "status"), Some("partialFailure"), "{env}");
    let failed = find_event(&env, "failed", Some("apply_failed"));
    let error = failed["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("f001.js") && error.contains("injected an error"),
        "the failure must name the file and the cause: {env}"
    );
    assert!(
        failed
            .get("files")
            .is_none_or(|f| f.as_array().is_none_or(|f| f.is_empty())),
        "no file may be reported patched: {env}"
    );

    assert_all_original(&pkg);
    assert_no_stage_litter(&pkg);

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    for name in FILES {
        assert_eq!(std::fs::read(pkg.join(name)).unwrap(), after(name));
    }
    assert_no_stage_litter(&pkg);
}

/// `rollback`'s twin: the second of three restores fails, so the first is
/// put back and the package stays fully patched, its record kept.
#[test]
fn a_rollback_failing_midway_leaves_the_package_patched() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = three_file_project(tmp.path());
    for name in FILES {
        stage_blob(tmp.path(), &git_sha256(&before(name)), &before(name));
    }
    let (code, _, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");

    let (code, stdout, stderr) = crate::common::run_with_env(
        tmp.path(),
        &["rollback", "--json", "--offline"],
        &[("SOCKET_PATCH_FAILPOINT", "patch_file_commit@2~error")],
    );
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    let failed = find_event(&env, "failed", None);
    let error = failed["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("f001.js") && error.contains("injected an error"),
        "the failure must name the file and the cause: {env}"
    );
    for name in FILES {
        assert_eq!(
            std::fs::read(pkg.join(name)).unwrap(),
            after(name),
            "{name} must still hold its patched bytes"
        );
    }
    assert_no_stage_litter(&pkg);
    let manifest = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    assert!(
        manifest.contains(PURL),
        "the record must be kept: {manifest}"
    );

    let (code, stdout, stderr) =
        crate::common::run_with_env(tmp.path(), &["rollback", "--json", "--offline"], &[]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert_all_original(&pkg);
    assert_no_stage_litter(&pkg);
}

/// A blob that is present but does not hold its hash's content, for the
/// second of three files: nothing is written, and the failure names the
/// file and the blob.
#[test]
fn a_corrupt_blob_for_a_later_file_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = three_file_project(tmp.path());
    let corrupt = git_sha256(&after("f001.js"));
    stage_blob(tmp.path(), &corrupt, b"not the patched bytes\n");

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline"], &[]);
    assert_eq!(code, 1, "stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    let failed = find_event(&env, "failed", Some("apply_failed"));
    let error = failed["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("f001.js") && error.contains(&corrupt),
        "the failure must name the file and its blob: {env}"
    );
    assert_eq!(events(&env).len(), 1, "{env}");

    assert_all_original(&pkg);
    assert_no_stage_litter(&pkg);
}

/// `apply --force` with one target file missing: the run that patches the
/// other two names the file it skipped, and the next run, which writes
/// nothing, is `already_patched` with the same warning, not an `applied`
/// event without files.
#[test]
fn force_names_the_file_it_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = three_file_project(tmp.path());
    std::fs::remove_file(pkg.join("f001.js")).unwrap();
    let skipped_warning = |env: &serde_json::Value| {
        env["warnings"].as_array().is_some_and(|warnings| {
            warnings.iter().any(|w| {
                w["code"] == "patch_files_skipped"
                    && w["detail"]
                        .as_str()
                        .is_some_and(|d| d.contains("package/f001.js"))
            })
        })
    };

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline", "--force"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    let applied = find_event(&env, "applied", None);
    let paths: Vec<&str> = applied["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["path"].as_str())
        .collect();
    assert_eq!(paths, ["package/f000.js", "package/f002.js"], "{env}");
    assert!(
        skipped_warning(&env),
        "the skipped file must be named: {env}"
    );

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--json", "--offline", "--force"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    find_event(&env, "skipped", Some("already_patched"));
    assert!(
        events(&env).iter().all(|e| e["action"] != "applied"),
        "a run that wrote nothing applied nothing: {env}"
    );
    assert!(
        skipped_warning(&env),
        "the skipped file must be named: {env}"
    );

    let (code, _, stderr) = run_apply(tmp.path(), &["--offline", "--force"], &[]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stderr.contains("Warning:") && stderr.contains("package/f001.js"),
        "the human output must name the skipped file: {stderr}"
    );
}
