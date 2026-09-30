//! Regression suite for `--ecosystems`-scoped rollback over hosted state.
//!
//! Formerly this pinned a replay leak: against a records-EMPTY degraded
//! redirect ledger, `rollback --ecosystems npm` replayed (and dropped)
//! leftover hosted edits of OTHER ecosystems. v5 keeps no hosted ledger:
//! the hosted pins are discovered from the lockfiles and each in-scope pin
//! is restored to its upstream registry entry on its own, so the invariant
//! becomes: an `--ecosystems`-narrowed run never restores a pin of another
//! ecosystem, and never retires a pre-v5 ledger while any hosted pin (in
//! scope or not) is still wired. The ledger's recorded edits are never
//! replayed at all.
//!
//! The fixture is a requirements.txt hosted-wired to the mock patch host
//! (recognized through `patch_server_url`) beside a pre-v5 ledger written
//! through the exported `socket_patch_core::patch::redirect` types. The
//! file is unhashed apart from the hosted line, so the pypi restore needs
//! no registry lookup and the runs stay offline.
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

/// The requirements-line edit a pre-v5 hosted run recorded. Its recorded
/// original is deliberately NOT what the restore derives (`==2.30.0`): a
/// replay would write it, the restore must not.
fn legacy_requirements_edit() -> FileEdit {
    FileEdit {
        path: "requirements.txt".to_string(),
        kind: "redirect_requirements_line".to_string(),
        action: "rewritten".to_string(),
        key: Some("requests".to_string()),
        original: Some(Value::String("requests==2.30.0".to_string())),
        new: Some(Value::String(WIRED_LINE.to_string())),
    }
}

fn ledger_path(root: &Path) -> std::path::PathBuf {
    root.join(".socket/vendor/redirect-state.json")
}

/// requirements.txt still hosted-wired + a pre-v5 records-empty ledger
/// holding the recorded edit. No manifest, no vendor ledger — the hosted
/// pin alone keeps the run off the truly-empty error path.
async fn write_hosted_pypi_fixture(root: &Path) {
    std::fs::write(
        root.join("requirements.txt"),
        requirements_content(WIRED_LINE),
    )
    .unwrap();
    let mut state = RedirectState::new();
    state.edits = vec![legacy_requirements_edit()];
    save_redirect_state(root, &state)
        .await
        .expect("write redirect ledger");
}

/// In-process wet rollback (`--json --yes --offline --silent`, the mock
/// patch host recognized as hosted), optionally `--ecosystems`-narrowed.
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
            patch_server_url: Some("http://patch.test".to_string()),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        preserve_state: false,
    };
    let code = rollback_run(args).await;
    // `apply_env_toggles` mirrored `--offline` into the PROCESS env and
    // nothing unsets it; scrub so the next in-process run in this
    // `#[serial]` process isn't silently forced offline.
    std::env::remove_var("SOCKET_OFFLINE");
    code
}

/// `rollback --ecosystems npm` over a project whose only hosted pin is a
/// PYPI one must restore nothing: the pypi pin stays wired and the pre-v5
/// ledger stays (a pin is still wired), byte-identical.
#[tokio::test]
#[serial]
async fn ecosystems_scoped_rollback_leaves_other_ecosystems_pins() {
    let tmp = tempfile::tempdir().unwrap();
    write_hosted_pypi_fixture(tmp.path()).await;
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let code = rollback_in_process(tmp.path(), Some(vec!["npm".to_string()])).await;
    assert_eq!(code, 0, "an npm-scoped run with no npm state is a no-op");

    assert_eq!(
        std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap(),
        requirements_content(WIRED_LINE),
        "an --ecosystems npm rollback must not restore the pypi pin"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "the pre-v5 ledger is kept while a hosted pin is still wired"
    );
}

/// Control: a pypi-scoped (and an unscoped) rollback restores the pin to
/// the upstream `name==version` line — derived, not replayed from the
/// ledger's recorded original — and then retires the pre-v5 ledger,
/// leaving no `.socket/` files behind.
#[tokio::test]
#[serial]
async fn in_scope_rollback_restores_the_pin_and_retires_the_ledger() {
    for ecosystems in [Some(vec!["pypi".to_string()]), None] {
        let tmp = tempfile::tempdir().unwrap();
        write_hosted_pypi_fixture(tmp.path()).await;

        let code = rollback_in_process(tmp.path(), ecosystems.clone()).await;
        assert_eq!(code, 0, "{ecosystems:?}: the pypi restore must succeed");

        assert_eq!(
            std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap(),
            requirements_content(PRISTINE_LINE),
            "{ecosystems:?}: the pin must come back as the upstream requirement"
        );
        assert!(
            !ledger_path(tmp.path()).exists(),
            "{ecosystems:?}: with no hosted pin left the pre-v5 ledger is retired"
        );
    }
}
