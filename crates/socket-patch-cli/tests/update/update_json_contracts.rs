//! `socket-patch --update --json` contracts that scripts branch on: the
//! already-there no-ops (latest and pinned) and the unlocked-swap degrade.
//! Each test reads the envelope's codes, events and details through
//! `common::envelope` plus the disk state, never the human sentences;
//! the human wording lives in `update_render.rs`.
//!
//! Every run drives a COPY of the built binary staged into a tempdir
//! (`update_fixture::staged_install`): `CARGO_BIN_EXE_socket-patch`
//! itself must never be a swap target.

use crate::common;
use crate::common::envelope::{assert_envelope_invariants, events, find_event};
use crate::update_fixture;

use std::path::Path;

use sha2::{Digest, Sha256};
use update_fixture::{
    make_served_binary, run_installed, sha256_file, staged_install, FakeReleaseBuilder,
};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// A TCP endpoint nothing listens on (port 9 = discard, never bound on a
/// dev host): any request the child makes fails fast and loudly, so a
/// "zero network" contract regressing into a fetch flips the exit code.
pub(crate) const DEAD_ENDPOINT: &str = "http://127.0.0.1:9";

/// The already-latest envelope: exit 0, `status: success`, `dryRun:
/// false`, exactly one skipped/already_latest event carrying
/// `details.current`/`details.latest`, summary agreeing, and the empty
/// `warnings` omitted (additive-only envelope contract). One resolve,
/// zero sums, zero downloads.
#[tokio::test]
async fn update_already_latest_json_envelope_shape() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .expect_resolves(1)
        .expect_sums_fetches(0)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let env = common::parse_json_envelope(&stdout);
    assert_envelope_invariants(&env, "update");
    assert_eq!(common::json_string(&env, "status"), Some("success"));
    assert_eq!(
        env["dryRun"], false,
        "a wet already-latest run must not read as a dry run: {stdout}"
    );
    assert_eq!(events(&env).len(), 1, "exactly one skip event: {stdout}");
    let event = find_event(&env, "skipped", Some("already_latest"));
    assert_eq!(event["details"]["current"], CURRENT);
    assert_eq!(event["details"]["latest"], CURRENT);
    assert_eq!(env["summary"]["skipped"], 1);

    // No advisories were raised, so `warnings` must be omitted (the
    // skip_serializing_if contract keeps existing consumers byte-stable).
    assert!(
        env.get("warnings").is_none(),
        "empty warnings must be omitted from the envelope: {stdout}"
    );

    install.assert_binary_intact();
    release.verify_request_hygiene().await;
}

/// `--update <CURRENT>`: an explicit pin equal to the compiled version is
/// a no-op decided offline (no latest-resolution, no sums, no download;
/// the dead endpoint fails any request). It reports the same
/// skipped/already_latest event with the pin as `latest`, and it must NOT
/// refresh the passive notifier cache (the `if !pinned` state-write gate
/// in `run()`: a pin says nothing about the latest release, so caching it
/// as `latestSeen` would poison the nag).
#[test]
fn update_pin_to_current_is_noop_zero_network() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", CURRENT, "--json"],
        &[("SOCKET_UPDATE_BASE_URL", DEAD_ENDPOINT)],
    );
    assert_eq!(
        code, 0,
        "pin-to-current must be a clean no-op.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = common::parse_json_envelope(&stdout);
    assert_envelope_invariants(&env, "update");
    assert_eq!(common::json_string(&env, "status"), Some("success"));
    assert_eq!(events(&env).len(), 1, "exactly one skip event: {stdout}");
    let event = find_event(&env, "skipped", Some("already_latest"));
    assert_eq!(event["details"]["current"], CURRENT);
    assert_eq!(event["details"]["latest"], CURRENT);

    install.assert_binary_intact();
    install.assert_only_binary_present();
    install.assert_workdir_untouched();
    assert!(
        !install.state_dir.join("update-check.json").exists(),
        "a pinned run must not write the passive notifier cache"
    );
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

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

/// `update::swap::acquire_update_lock`'s unlocked degrade: when no
/// per-user state dir resolves at all (the `SOCKET_UPDATE_STATE_DIR`
/// override, `XDG_CACHE_HOME` and `HOME` all empty), the updater proceeds
/// WITHOUT the single-flight lock rather than refusing on exotic
/// environments. The update is unlocked but COMPLETE: downloaded and
/// updated events, the served payload installed by a real rename, and no
/// lock file or notifier state written anywhere.
///
/// Binary-level on purpose: an inline test would have to unset HOME and
/// XDG_CACHE_HOME process-wide, and the suites mutating those use a
/// different serial key than the swap/state tests, so an inline version
/// is flake-prone. Child-process env sidesteps that.
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
        &["--update", "--yes", "--json"],
        &[
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
            // Caller env lands last and wins: the empty values read as
            // unset (state.rs's env_dir filters empty), overriding the
            // fixture-injected SOCKET_UPDATE_STATE_DIR, so state_dir()
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
    let env = common::parse_json_envelope(&stdout);
    assert_envelope_invariants(&env, "update");
    assert_eq!(common::json_string(&env, "status"), Some("success"));
    find_event(&env, "downloaded", None);
    let updated = find_event(&env, "updated", None);
    assert_eq!(updated["details"]["from"], CURRENT);
    assert_eq!(updated["details"]["to"], "9.9.9");

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
    // …via a real rename (new inode), not an in-place overwrite: the
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
    let out = common::hermetic_command(&install.bin)
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
    // test blanked) stayed completely untouched: proof the child really
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
