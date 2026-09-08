//! Coverage-gap integration test for `update::state`: the degenerate
//! "no resolvable state dir" environment — `SOCKET_UPDATE_STATE_DIR`,
//! the platform cache vars, and the home vars all unset/empty (a
//! stripped container). The documented contract is that callers
//! silently skip: `load_state` degrades to never-checked and
//! `save_state` returns `Ok(())` without persisting anywhere.
//!
//! This lives in its own test binary rather than state.rs's inline
//! module because it must blank HOME: in the lib-test process the
//! HOME-mutating tests (utils/fs.rs, utils/socket_cli_config.rs) hold
//! the UNNAMED `#[serial]` key while update/state.rs tests hold
//! `#[serial(update_state_dir_env)]`, and the two groups do not exclude
//! each other — an inline HOME-blanking test would race the former. A
//! separate integration binary is its own process (cargo runs test
//! binaries sequentially), so nothing else can observe the mutation.

use socket_patch_core::update::state::{load_state, save_state, state_dir, UpdateCheckState};

/// Every var `state_dir()` consults, across both the unix and windows
/// resolution chains — blanking the foreign platform's vars is harmless
/// and keeps the test green on either host.
const STATE_DIR_VARS: [&str; 5] = [
    "SOCKET_UPDATE_STATE_DIR",
    "XDG_CACHE_HOME",
    "HOME",
    "LOCALAPPDATA",
    "USERPROFILE",
];

#[tokio::test]
async fn no_resolvable_state_dir_degrades_load_and_save() {
    // Blank (empty means unset, per the env_dir convention — avoids
    // remove_var churn) every var the resolution chain consults.
    let prev: Vec<_> = STATE_DIR_VARS.iter().map(|v| std::env::var_os(v)).collect();
    for v in STATE_DIR_VARS {
        std::env::set_var(v, "");
    }

    let dir = state_dir();
    let loaded = load_state();
    let saved = save_state(&UpdateCheckState {
        latest_seen: Some("1.0.0".into()),
        ..Default::default()
    })
    .await;

    for (v, p) in STATE_DIR_VARS.iter().zip(prev) {
        match p {
            Some(val) => std::env::set_var(v, val),
            None => std::env::remove_var(v),
        }
    }

    assert_eq!(
        dir, None,
        "an all-blank env must leave no resolvable state dir"
    );
    assert_eq!(
        loaded,
        UpdateCheckState::default(),
        "load with nowhere to read degrades to never-checked"
    );
    // With no state_file_path() there is nowhere to write: the save is
    // silent Ok — the save-side twin of the load side's silence.
    saved.expect("save with nowhere to persist must be Ok(())");
}
