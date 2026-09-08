//! Regression suite for the `--ecosystems`-scoped rollback replay leak:
//! against a records-EMPTY degraded redirect ledger (a record-fetch-failed
//! hosted run persists its edits with no records), `replay_eligible` was
//! vacuously true for a scope spelled ONLY with `--ecosystems` — the flag
//! never fed the `scoped` flip — so `rollback --ecosystems npm` replayed,
//! and dropped from the ledger, leftover hosted edits of OTHER ecosystems
//! it was never asked about.
//!
//! The fixture hand-writes the ledger through the exported
//! `socket_patch_core::patch::redirect` types (real schema, real edit
//! kind) with the matching redirected fragment on disk — the
//! `in_process_rollback_hosted.rs` pattern.
//!
//! `#[serial]`: every command's `run` mirrors env toggles into
//! process-global env vars (`apply_env_toggles`).

use std::path::Path;

use serde_json::Value;
use serial_test::serial;
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};
use socket_patch_core::patch::redirect::{save_redirect_state, FileEdit, RedirectState};

const PRISTINE_LINE: &str = "requests==2.31.0";
const WIRED_LINE: &str = "requests @ http://patch.test/patch/pypi/requests/2.31.0/22222222-2222-4222-8222-222222222222/a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1/requests-2.31.0-py3-none-any.whl --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn requirements_content(line: &str) -> String {
    format!("flask==2.0.1\n{line}\n")
}

/// The leftover requirements-source edit a degraded (record-fetch-failed)
/// hosted run leaves behind: `redirect_requirements_line` has no per-purl
/// revert — only the whole-ledger replay can unwind it.
fn requirements_edit() -> FileEdit {
    FileEdit {
        path: "requirements.txt".to_string(),
        kind: "redirect_requirements_line".to_string(),
        action: "rewritten".to_string(),
        key: Some("requests".to_string()),
        original: Some(Value::String(PRISTINE_LINE.to_string())),
        new: Some(Value::String(WIRED_LINE.to_string())),
    }
}

fn ledger_path(root: &Path) -> std::path::PathBuf {
    root.join(".socket/vendor/redirect-state.json")
}

/// requirements.txt still wired + a ledger holding the leftover pypi edit
/// and NO records (the record-fetch-failed shape). No manifest, no vendor
/// ledger — the redirect ledger alone keeps the run off the truly-empty
/// error path.
async fn write_degraded_pypi_fixture(root: &Path) {
    std::fs::write(
        root.join("requirements.txt"),
        requirements_content(WIRED_LINE),
    )
    .unwrap();
    let mut state = RedirectState::new();
    state.edits = vec![requirements_edit()];
    save_redirect_state(root, &state)
        .await
        .expect("write redirect ledger");
}

/// In-process wet rollback (`--json --yes --offline --silent`), optionally
/// `--ecosystems`-narrowed.
async fn rollback_in_process(cwd: &Path, ecosystems: Option<Vec<String>>) -> i32 {
    let args = RollbackArgs {
        targets: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            ecosystems,
            offline: true,
            json: true,
            yes: true,
            silent: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        one_off: false,
        preserve_state: false,
    };
    let code = rollback_run(args).await;
    // `apply_env_toggles` mirrored `--offline` into the PROCESS env and
    // nothing unsets it; scrub so the next in-process run in this
    // `#[serial]` process isn't silently forced offline.
    std::env::remove_var("SOCKET_OFFLINE");
    code
}

/// Regression: `rollback --ecosystems npm` over the records-empty degraded
/// ledger must NOT replay (and drop) the leftover PYPI edit. An
/// eco-narrowed run is a scoped run — only an unscoped rollback may claim
/// the whole-ledger replay of leftover edits.
#[tokio::test]
#[serial]
async fn ecosystems_scoped_rollback_leaves_other_ecosystems_leftover_edits() {
    let tmp = tempfile::tempdir().unwrap();
    write_degraded_pypi_fixture(tmp.path()).await;
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let code = rollback_in_process(tmp.path(), Some(vec!["npm".to_string()])).await;
    assert_eq!(code, 0, "an npm-scoped run with no npm state is a no-op");

    assert_eq!(
        std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap(),
        requirements_content(WIRED_LINE),
        "an --ecosystems npm rollback must not unwind the pypi redirect edit"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "the out-of-scope leftover edit must stay in the ledger"
    );
}

/// Control (the behavior the fix must not break): an UNSCOPED rollback
/// still replays the records-empty ledger's leftover edits and deletes
/// the emptied ledger.
#[tokio::test]
#[serial]
async fn unscoped_rollback_still_replays_leftover_edits() {
    let tmp = tempfile::tempdir().unwrap();
    write_degraded_pypi_fixture(tmp.path()).await;

    let code = rollback_in_process(tmp.path(), None).await;
    assert_eq!(code, 0, "unscoped replay of the leftover edit must succeed");

    assert_eq!(
        std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap(),
        requirements_content(PRISTINE_LINE),
        "the unscoped run must unwind the leftover pypi edit"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "the emptied ledger must be deleted"
    );
}
