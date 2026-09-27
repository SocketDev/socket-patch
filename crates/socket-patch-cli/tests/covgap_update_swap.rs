//! Coverage-gap e2e for `update::swap::acquire_update_lock`'s unlocked
//! degrade (2026-09 coverage audit): when no per-user state dir resolves
//! at all — the `SOCKET_UPDATE_STATE_DIR` override, `XDG_CACHE_HOME`, and
//! `HOME` all unset/empty — the updater proceeds WITHOUT the single-flight
//! lock rather than refusing on exotic environments. A documented
//! contract (swap.rs's `return Ok(None)` degrade) no test had exercised.
//!
//! Binary-level on purpose: an inline test would have to unset HOME and
//! XDG_CACHE_HOME process-wide, and the suites mutating those use a
//! different serial key than the swap/state tests (`update_state_dir_env`)
//! — the two groups do not serialize against each other, so an inline
//! version is flake-prone. Child-process env sidesteps all of that.
//!
//! Same discipline as `self_update_e2e.rs`: the test runs a staged COPY of
//! the built binary (`update_fixture::staged_install`) —
//! `CARGO_BIN_EXE_socket-patch` itself must never be a swap target — and
//! re-verifies the real artifact at the end.

#[path = "common/mod.rs"]
mod common;
#[path = "common/update_fixture.rs"]
mod update_fixture;

use std::path::Path;

use sha2::{Digest, Sha256};
use update_fixture::{
    make_served_binary, run_installed, sha256_file, staged_install, FakeReleaseBuilder,
};

/// Recursively collect file names under `dir` matching `name`.
fn find_files_named(dir: &Path, name: &str) -> Vec<std::path::PathBuf> {
    let mut hits = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return hits;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_dir() {
            hits.extend(find_files_named(&path, name));
        } else if entry.file_name() == name {
            hits.push(path);
        }
    }
    hits
}

/// The degrade contract end to end: with no resolvable state dir the
/// update is unlocked but COMPLETE — a real download→verify→swap pass
/// that leaves the served payload installed, writes no lock file and no
/// notifier state anywhere, and never touches the build artifact.
#[tokio::test]
async fn update_without_resolvable_state_dir_proceeds_unlocked() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, byte_distinct) = make_served_binary();
    let served_hash = hex::encode(Sha256::digest(&served));

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
            // Caller env lands last and wins: the empty values read as
            // unset (state.rs's env_dir filters empty), overriding the
            // fixture-injected SOCKET_UPDATE_STATE_DIR — so state_dir()
            // resolves to None inside the child and acquire_update_lock
            // takes the Ok(None) unlocked-degrade branch. The Windows
            // pair keeps the shape correct should this ever run there.
            ("SOCKET_UPDATE_STATE_DIR", ""),
            ("XDG_CACHE_HOME", ""),
            ("HOME", ""),
            ("LOCALAPPDATA", ""),
            ("USERPROFILE", ""),
        ],
    );
    assert_eq!(
        code, 0,
        "no resolvable state dir must degrade to unlocked, not refuse.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Updated socket-patch"),
        "the unlocked update must still report success: {stdout}"
    );

    // The swap genuinely completed: the installed file IS the served
    // payload…
    assert_eq!(
        sha256_file(&install.bin),
        served_hash,
        "installed binary must be exactly the served payload"
    );
    if byte_distinct {
        assert_ne!(sha256_file(&install.bin), install.pre_hash);
    }
    // …via a real rename (new inode), not an in-place overwrite — the
    // only swap proof on macOS, where the served bytes are pristine.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            std::fs::metadata(&install.bin).unwrap().ino(),
            install.pre_ino,
            "unlocked swap must still be a rename, not an overwrite"
        );
    }
    let out = std::process::Command::new(&install.bin)
        .arg("--version")
        .output()
        .expect("spawn updated binary");
    assert!(out.status.success(), "updated binary must execute");

    // Unlocked means UNLOCKED: no update.lock materialized anywhere in
    // the install tree…
    assert_eq!(
        find_files_named(install.root.path(), "update.lock"),
        Vec::<std::path::PathBuf>::new(),
        "no lock file may be created when no state dir resolves"
    );
    // …and the state dir the fixture provisioned (whose env pointer this
    // test blanked) stayed completely untouched — proof the child really
    // resolved None rather than locking somewhere else.
    let state_leftovers: Vec<_> = std::fs::read_dir(&install.state_dir)
        .expect("read state dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .collect();
    assert!(
        state_leftovers.is_empty(),
        "with no resolvable state dir nothing may write update state: {state_leftovers:?}"
    );

    install.assert_only_binary_present();
    install.assert_workdir_untouched();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}
