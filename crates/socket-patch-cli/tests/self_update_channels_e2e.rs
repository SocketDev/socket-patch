//! Install-channel detection e2e for `socket-patch --update`.
//!
//! The channel heuristics are pure functions unit-tested in core
//! (`update/channel.rs`); what only an e2e can pin is the wiring — that the
//! spawned binary classifies its OWN canonicalized `current_exe`, refuses
//! managed installs before any network I/O, prints the owning manager's
//! upgrade command, and that `--force` genuinely overrides. `current_exe`
//! can't be faked, so each test makes it real: `staged_install_at` copies
//! the built binary into a crafted directory shape and the test spawns that
//! copy.
//!
//! macOS gotcha baked into the env-rooted rows: tempdirs live under
//! `/var/folders/…`, a symlink to `/private/var/…`, and the updater
//! canonicalizes the exe path before matching it against CARGO_HOME /
//! XDG_CACHE_HOME. Those roots must therefore be passed canonicalized or
//! the prefix comparison never fires — which is exactly the behavior the
//! real cargo/launcher installers see, since they resolve real paths.

#[path = "common/mod.rs"]
mod common;
#[path = "common/update_fixture.rs"]
mod update_fixture;

use sha2::{Digest, Sha256};
use update_fixture::{
    make_served_binary, run_installed, sha256_file, staged_install, staged_install_at,
    FakeReleaseBuilder,
};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// Base URL for refusal rows that don't need a mock: a dead port. The
/// refusal must precede all network traffic, so nothing should ever
/// connect — and if the gate regresses, the run fails fast against
/// 127.0.0.1 instead of leaking a request to real GitHub.
const DEAD_BASE_URL: &str = "http://127.0.0.1:1";

/// An npm-bundled binary (any `node_modules` component) refuses with the
/// npm upgrade command — and the refusal happens before ANY release
/// traffic: a fully valid, newer release is mounted and its routes must
/// never be hit. A wasted download before the refusal is the bug class.
#[tokio::test]
async fn npm_bundled_refuses_with_npm_hint() {
    let install = staged_install_at("node_modules/@socketsecurity/socket-patch-x/bin");
    let (served, _) = make_served_binary();
    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .mount()
        .await;

    let (code, _stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "managed install must refuse.\nstderr:\n{stderr}");
    assert!(
        stderr.contains("npm update -g @socketsecurity/socket-patch"),
        "refusal must route to npm's own upgrade command: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "refusal must mention the escape hatch: {stderr}"
    );

    // Same refusal in machine shape.
    let (code, stdout, _) = run_installed(
        &install,
        &["--update", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::json_string(&env, "status"), Some("error"));
    assert_eq!(common::envelope_error_code(&env), Some("managed_install"));

    // The crux: two refusals, zero requests — channel detection ran on
    // path + env alone.
    assert_eq!(
        release.received_request_count().await,
        0,
        "channel refusal must precede any release-host traffic"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// A PyPI-wheel-bundled binary (`site-packages` component) refuses with
/// the pip upgrade command.
#[tokio::test]
async fn pip_bundled_refuses_with_pip_hint() {
    let install = staged_install_at("venv/lib/python3.12/site-packages/socket_patch/bin");

    let (code, _stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", DEAD_BASE_URL)],
    );
    assert_eq!(code, 1, "pip-managed install must refuse.\nstderr:\n{stderr}");
    assert!(
        stderr.contains("pip install --upgrade socket-patch"),
        "refusal must route to pip's own upgrade command: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
}

/// A `cargo install`ed binary lives under `$CARGO_HOME/bin`; the shape is
/// only meaningful relative to the env var, so this is the row that pins
/// the env half of detection (CARGO_HOME is NOT part of the hermetic
/// scrub — the override must win over the developer's real one).
#[tokio::test]
async fn cargo_install_refuses_with_cargo_hint() {
    let install = staged_install_at("cargo-home/bin");
    // Canonicalized so the prefix check survives the /var → /private/var
    // tempdir symlink on macOS (see module docs).
    let cargo_home = install
        .bin
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .canonicalize()
        .expect("canonicalize crafted CARGO_HOME");
    let cargo_home = cargo_home.display().to_string();

    let (code, _stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[
            ("SOCKET_UPDATE_BASE_URL", DEAD_BASE_URL),
            ("CARGO_HOME", &cargo_home),
        ],
    );
    assert_eq!(code, 1, "cargo-managed install must refuse.\nstderr:\n{stderr}");
    assert!(
        stderr.contains("cargo install socket-patch-cli"),
        "refusal must route to cargo's own upgrade command: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
}

/// The gem/composer launchers exec a per-version cached binary under
/// `<cache>/socket-patch/bin/<version>/<triple>/`; replacing the cache
/// entry is meaningless (the launcher re-resolves every run), so the
/// refusal points at BOTH managers — the path can't tell them apart.
/// Unix resolution goes through XDG_CACHE_HOME.
#[cfg(unix)]
#[tokio::test]
async fn launcher_cache_refuses_with_gem_composer_hint() {
    let install = staged_install_at("cache/socket-patch/bin/3.3.0/x86_64-unknown-linux-gnu");
    let cache_root = install
        .root
        .path()
        .join("cache")
        .canonicalize()
        .expect("canonicalize crafted cache root");
    let cache_root = cache_root.display().to_string();

    let (code, _stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[
            ("SOCKET_UPDATE_BASE_URL", DEAD_BASE_URL),
            ("XDG_CACHE_HOME", &cache_root),
        ],
    );
    assert_eq!(
        code, 1,
        "launcher-cache install must refuse.\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("gem update") && stderr.contains("composer update"),
        "the shared cache layout can't distinguish gem from composer, so \
         the hint must name both: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
}

/// Windows twin of the launcher-cache row: resolution goes through
/// %LOCALAPPDATA% there (no ~/.cache convention).
#[cfg(windows)]
#[tokio::test]
async fn launcher_cache_refuses_with_gem_composer_hint_windows() {
    let install = staged_install_at("cache/socket-patch/bin/3.3.0/x86_64-pc-windows-msvc");
    // Canonicalized for the same reason as the unix rows: the exe path is
    // canonicalized (verbatim \\?\ form on Windows), so the root must be
    // in the same form for the prefix check to fire.
    let cache_root = install
        .root
        .path()
        .join("cache")
        .canonicalize()
        .expect("canonicalize crafted cache root");
    let cache_root = cache_root.display().to_string();

    let (code, _stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[
            ("SOCKET_UPDATE_BASE_URL", DEAD_BASE_URL),
            ("LOCALAPPDATA", &cache_root),
        ],
    );
    assert_eq!(
        code, 1,
        "launcher-cache install must refuse.\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("gem update") && stderr.contains("composer update"),
        "the shared cache layout can't distinguish gem from composer, so \
         the hint must name both: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
}

/// `--force` overrides the channel refusal: the npm-bundled copy really
/// gets replaced, but the "your package manager will revert this" warning
/// still lands — silent override is the bug class.
#[tokio::test]
async fn force_overrides_channel_refusal() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install_at("node_modules/@socketsecurity/socket-patch-x/bin");
    let (served, _) = make_served_binary();
    let served_hash = hex::encode(Sha256::digest(&served));

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(
        code, 0,
        "--force must proceed past the channel gate.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("managed by npm"),
        "override must still warn that npm owns this install: {stderr}"
    );
    assert_eq!(
        sha256_file(&install.bin),
        served_hash,
        "the copy inside node_modules must be the served payload"
    );

    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// Canonicalization pin: the binary physically lives in the node_modules
/// shape but is invoked through a plain symlink elsewhere — exactly how
/// npm `.bin/` shims exec. Detection must classify the resolved target,
/// not the innocent-looking link path.
#[cfg(unix)]
#[tokio::test]
async fn symlinked_invocation_still_detected() {
    let install = staged_install_at("node_modules/@socketsecurity/socket-patch-x/bin");
    let straight = install.root.path().join("straight");
    std::fs::create_dir_all(&straight).expect("create symlink dir");
    let link = straight.join("socket-patch");
    std::os::unix::fs::symlink(&install.bin, &link).expect("create symlink");

    let state_dir = install.state_dir.display().to_string();
    let (code, _stdout, stderr) = common::run_bin_with_env(
        &link,
        &install.workdir,
        &["--update", "--yes"],
        &[
            ("SOCKET_UPDATE_STATE_DIR", &state_dir),
            ("SOCKET_UPDATE_BASE_URL", DEAD_BASE_URL),
        ],
    );
    assert_eq!(
        code, 1,
        "symlinked invocation must still hit the npm refusal.\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("npm update -g @socketsecurity/socket-patch"),
        "detection must run on the canonicalized target: {stderr}"
    );
    // The refusal names the REAL location, not the link — the actionable
    // path for a user wondering where the managed copy lives.
    assert!(
        stderr.contains("node_modules"),
        "refusal must name the resolved install path: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    assert!(
        std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink(),
        "the invocation symlink must be left alone"
    );
}

/// Positive control: the identical run against a plain `bin/` shape
/// proceeds — proving the refusals above come from the crafted shapes,
/// not something else in the fixture environment. (The full swap
/// semantics live in self_update_e2e.)
#[tokio::test]
async fn standalone_bin_dir_proceeds() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, _) = make_served_binary();
    let served_hash = hex::encode(Sha256::digest(&served));

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(
        code, 0,
        "standalone install must update.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(sha256_file(&install.bin), served_hash);

    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}
