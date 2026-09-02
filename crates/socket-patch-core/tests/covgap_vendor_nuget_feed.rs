//! Coverage mop-up for `vendor::nuget_feed` arms that need process-level
//! isolation. The local-rebuild stage `tempfile::tempdir()` failure is forced
//! by pointing `TMPDIR` at a nonexistent directory — safe only in a test
//! binary that owns its whole process (the lib test binary runs hundreds of
//! concurrent `tempdir()` users that a clobbered `TMPDIR` would flake).
//! Keep this file to env-mutating tests; anything else belongs in the file's
//! inline `#[cfg(test)]` module.

#![cfg(unix)]

use std::collections::HashMap;

use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::vendor::nuget_feed::vendor_nuget;
use socket_patch_core::vendor::VendorOutcome;

/// Restores the pre-test `TMPDIR` on drop (panic-safe).
struct TmpdirGuard(Option<std::ffi::OsString>);

impl Drop for TmpdirGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
    }
}

/// An unusable temp dir fails the local rebuild's private stage creation:
/// the vendor reports a per-package failure ("cannot create stage dir")
/// instead of panicking, and touches no project file. `TMPDIR` only steers
/// `std::env::temp_dir()` on unix.
#[cfg(unix)]
#[tokio::test]
async fn stage_tempdir_creation_failure_is_reported_not_fatal() {
    // Build the whole fixture while TMPDIR is still valid.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let installed = root.join("packages/newtonsoft.json/13.0.3");
    tokio::fs::create_dir_all(&installed).await.unwrap();
    // Any readable regular file works: the cached-nupkg read succeeds and
    // `tempfile::tempdir()` fails BEFORE extraction ever parses the bytes.
    tokio::fs::write(installed.join("newtonsoft.json.13.0.3.nupkg"), b"not-a-zip")
        .await
        .unwrap();
    let blobs = root.join("blobs");
    tokio::fs::create_dir_all(&blobs).await.unwrap();

    let mut files = HashMap::new();
    files.insert(
        "LICENSE.md".to_string(),
        PatchFileInfo {
            before_hash: "0".repeat(64),
            after_hash: "1".repeat(64),
        },
    );
    let record = PatchRecord {
        uuid: "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f".to_string(),
        exported_at: "2026-06-09T00:00:00Z".to_string(),
        files,
        vulnerabilities: HashMap::new(),
        description: String::new(),
        license: String::new(),
        tier: String::new(),
    };
    let sources = PatchSources {
        blobs_path: &blobs,
        packages_path: None,
        diffs_path: None,
        mem_blobs: None,
    };

    let guard = TmpdirGuard(std::env::var_os("TMPDIR"));
    std::env::set_var("TMPDIR", root.join("no-such-tmpdir"));
    let outcome = vendor_nuget(
        "pkg:nuget/Newtonsoft.Json@13.0.3",
        &installed,
        root,
        &record,
        &sources,
        "2026-06-09T00:00:00Z",
        false,
        false,
        None,
    )
    .await;
    drop(guard);

    match outcome {
        VendorOutcome::Done {
            result, entry, ..
        } => {
            assert!(!result.success, "the stage failure must fail the vendor");
            assert!(entry.is_none(), "no ledger entry for a failed vendor");
            let err = result.error.as_deref().unwrap_or("");
            assert!(err.contains("cannot create stage dir"), "{err}");
        }
        VendorOutcome::Refused { code, detail } => panic!("refused: {code}: {detail}"),
    }
    assert!(
        !root.join(".socket").exists(),
        "no partial artifact dir after the stage failure"
    );
    assert!(
        !root.join("nuget.config").exists(),
        "no wiring after the stage failure"
    );
}
