//! Failure-path matrix for `socket-patch --update`: every way an update
//! run can refuse or abort, one test per failure class.
//!
//! The invariant every row shares: a failed (or refused) update leaves
//! the installed binary byte-identical and its directory free of stage
//! droppings — all mutation is supposed to happen on a staged sibling
//! until the single atomic rename, so any test here that finds a changed
//! hash or a stray file has caught a real torn-update bug.
//!
//! Like `self_update_e2e.rs`, every test runs a COPY of the built binary
//! (`update_fixture::staged_install`) — `CARGO_BIN_EXE_socket-patch`
//! itself must never be a swap target.

#[path = "common/mod.rs"]
mod common;
#[path = "common/update_fixture.rs"]
mod update_fixture;

use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use socket_patch_cli::commands::update::UPDATE_TARGET;
use update_fixture::{
    asset_name_for_current_target, make_served_binary, run_installed, sha256_file, staged_install,
    FakeReleaseBuilder,
};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// A SHA256SUMS entry that disagrees with the served bytes must abort
/// before extraction ever runs — a tampered CDN response may be hostile,
/// so nothing from the archive may touch disk (no stage droppings).
#[tokio::test]
async fn checksum_mismatch_aborts_pre_extraction() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let asset = asset_name_for_current_target();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .corrupt_sums_entry_for(&asset)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("checksum"),
        "human error must name the checksum failure: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// SHA256SUMS is fetched BEFORE the asset, so an asset the release cannot
/// vouch for is refused without wasting (or trusting) the download — the
/// zero-download expectation is what pins the ordering.
#[tokio::test]
async fn sums_missing_entry_refuses_before_download() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let asset = asset_name_for_current_target();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .omit_sums_entry_for(&asset)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("SHA256SUMS") && stderr.contains("no entry"),
        "error must say the sums file has no entry for the asset: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// A release with no SHA256SUMS at all cannot be verified, so nothing may
/// be downloaded — and the error must name the missing file so a release
/// engineer knows what broke (not a generic "download failed").
#[tokio::test]
async fn sums_file_missing_is_actionable() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .omit_sums_file()
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("SHA256SUMS"),
        "error must name the missing SHA256SUMS: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// An advertised release whose platform asset 404s must say WHICH target
/// has no prebuilt binary — that message is the only clue a user on an
/// exotic platform gets about why they must build from source.
#[tokio::test]
async fn asset_404_names_the_target() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let asset = asset_name_for_current_target();

    // The asset stays listed in SHA256SUMS but its download route 404s:
    // the release page lied, or CI half-published.
    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .omit_asset(&asset)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::envelope_error_code(&env), Some("asset_not_found"));
    let message = common::envelope_error_message(&env).unwrap_or_default();
    assert!(
        message.contains(UPDATE_TARGET),
        "asset_not_found must name the compiled target triple: {message}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// SOCKET_UPDATE_TIMEOUT_MS must actually bound the run: a hung release
/// host may not turn `--update` into an indefinite stall (a hung
/// self-update is strictly worse than a hung scan).
#[tokio::test]
async fn network_timeout_is_bounded() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .delay_metadata(Duration::from_secs(10))
        .mount()
        .await;

    let start = Instant::now();
    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
            ("SOCKET_UPDATE_TIMEOUT_MS", "500"),
        ],
    );
    let elapsed = start.elapsed();

    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stderr.contains("Error:"), "{stderr}");
    // 8s is generous slack for debug-binary startup; the 10s server delay
    // (×2 routes: probe + API fallback) guarantees an unbounded client
    // would blow well past it.
    assert!(
        elapsed < Duration::from_secs(8),
        "timeout must bound the run, took {elapsed:?}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// A connection cut mid-download yields fewer bytes than SHA256SUMS
/// vouched for — that must surface as a checksum failure, never as a
/// short-but-"successful" archive handed to the extractor.
#[tokio::test]
async fn truncated_download_is_a_checksum_mismatch() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let asset = asset_name_for_current_target();
    let archive_len = update_fixture::archive_for_current_target(&served).len();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .truncate_asset(&asset, archive_len / 2)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stderr.contains("checksum"),
        "truncation must report as a checksum failure: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// `latest` never downgrades: when the newest release is OLDER than the
/// installed binary (a dev build, or a yanked release rolled back), a bare
/// `--update` is an informational no-op that touches neither the sums nor
/// the asset routes.
#[tokio::test]
async fn downgrade_refused_without_force() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new("0.0.1")
        .asset_for_current_target(&served)
        .expect_sums_fetches(0)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("already the latest"),
        "an older latest must read as a no-op, not an error: {stdout}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// An explicit version pin is user intent: it installs that version up OR
/// down with no --force, and never hits the latest-resolution endpoint
/// (the pin alone decides the download URL).
#[tokio::test]
async fn explicit_pin_downgrades_without_force() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, _) = make_served_binary();
    let served_hash = hex::encode(Sha256::digest(&served));

    let release = FakeReleaseBuilder::new("0.0.1")
        .asset_for_current_target(&served)
        .expect_resolves(0)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "0.0.1", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Updated socket-patch"), "{stdout}");
    assert_eq!(
        sha256_file(&install.bin),
        served_hash,
        "pin must install the served payload"
    );
    // The served binary genuinely reports the crate version, not 0.0.1 —
    // under a base-URL override that mismatch is a warning, not an abort.
    assert!(
        stderr.contains("Warning") && stderr.contains("0.0.1"),
        "relaxed version self-check must warn about the mismatch: {stderr}"
    );

    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// A release host that redirects to a garbage tag (and whose API fallback
/// serves an equally garbage tag_name) must produce a clean check_failed —
/// a panic here would look like a crashed updater to every user the moment
/// GitHub changes a URL shape.
#[tokio::test]
async fn garbage_tag_is_error_not_panic() {
    use wiremock::matchers::{method, path as urlpath};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let install = staged_install();

    // Raw wiremock: the fixture always redirects to a well-formed tag, so
    // this hostile shape is mounted by hand.
    let server = MockServer::start().await;
    let base = server.uri();
    Mock::given(method("GET"))
        .and(urlpath("/SocketDev/socket-patch/releases/latest"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            format!("{base}/SocketDev/socket-patch/releases/tag/not-a-version").as_str(),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(urlpath("/repos/SocketDev/socket-patch/releases/latest"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "tag_name": "also-garbage",
            "assets": [],
        })))
        .mount(&server)
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &base)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::envelope_error_code(&env), Some("check_failed"));
    assert!(
        !stderr.contains("panicked"),
        "garbage tags must never panic the updater: {stderr}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
}

/// Correctly-checksummed garbage (the sums vouch for bytes that simply
/// aren't a program) must die at the sanity exec, with the stage cleaned
/// up and the installed binary untouched — the last line of defense when
/// a release publishes a broken artifact with matching sums.
#[tokio::test]
async fn sanity_exec_failure_leaves_binary_untouched() {
    let install = staged_install();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&[0u8; 4096])
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::envelope_error_code(&env), Some("verify_failed"));

    install.assert_binary_intact();
    // No `.old` parked exe, no `.socket-patch.stage-*` leftovers: the
    // failed sanity exec must consume its own stage file.
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// An install dir the user cannot write to (the classic
/// `/usr/local/bin` without sudo) must fail as permission_denied with the
/// sudo hint — not as a generic swap failure, and not after half-staging.
#[cfg(unix)]
#[tokio::test]
async fn readonly_install_dir_fails_cleanly() {
    use std::os::unix::fs::PermissionsExt;

    let install = staged_install();
    let (served, _) = make_served_binary();
    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .mount()
        .await;

    let bin_dir = install.bin.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o555))
        .expect("chmod bin dir read-only");
    // Root ignores mode bits (CI containers sometimes run as root): probe
    // and skip rather than assert a denial that cannot happen.
    if std::fs::File::create(bin_dir.join("probe")).is_ok() {
        let _ = std::fs::remove_file(bin_dir.join("probe"));
        let _ = std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755));
        eprintln!("skipping: running as root, 0555 does not block writes");
        return;
    }

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );

    // Restore writability BEFORE any assertion can panic, so TempDir
    // cleanup never wedges on the read-only directory.
    std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755))
        .expect("restore bin dir mode");

    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::envelope_error_code(&env), Some("permission_denied"));
    let message = common::envelope_error_message(&env).unwrap_or_default();
    assert!(
        message.contains("sudo"),
        "permission_denied must carry the sudo hint: {message}"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}

/// Strict airgap: SOCKET_OFFLINE refuses before ANY client exists, and
/// --force does not bypass it. Zero requests is the contract — one
/// metadata probe from an "offline" run is already a violation.
#[tokio::test]
async fn offline_refuses_up_front_and_beats_force() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes", "--json"],
        &[
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
            ("SOCKET_OFFLINE", "1"),
        ],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::envelope_error_code(&env), Some("offline"));
    assert_eq!(
        release.received_request_count().await,
        0,
        "offline must mean ZERO requests to the release host"
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
}

/// Two concurrent updates would race the same rename; the flock on
/// `<state_dir>/update.lock` makes them single-flight. The second half of
/// the test pins that the lock is advisory-per-holder, not sticky: once
/// released, the next run must succeed and actually swap.
#[tokio::test]
async fn concurrent_update_lock_held() {
    use fs2::FileExt;

    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, _) = make_served_binary();
    let served_hash = hex::encode(Sha256::digest(&served));

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .mount()
        .await;

    // Externally hold the exact flock the updater takes (same idiom as
    // e2e_safety_lock.rs) — keep the handle bound or the lock vanishes.
    let lock_path = install.state_dir.join("update.lock");
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open update.lock");
    lock_file
        .try_lock_exclusive()
        .expect("test could not take initial lock");

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::envelope_error_code(&env), Some("update_in_progress"));
    install.assert_binary_intact();

    // Release the lock: the very next run must go all the way through.
    drop(lock_file);
    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(
        code, 0,
        "retry after lock release must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        sha256_file(&install.bin),
        served_hash,
        "retry must install the served payload"
    );
    // Rename evidence: a real swap allocates a new inode (macOS serves
    // pristine bytes, so this is its only swap proof).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            std::fs::metadata(&install.bin).unwrap().ino(),
            install.pre_ino,
            "retry swap must be a rename, not an in-place overwrite"
        );
    }

    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// `--json` failure envelope: a single parseable object on stdout with the
/// stable command tag, error status, and machine-routable error code —
/// what CI wrappers key on to distinguish "verification failed" from
/// "network flake".
#[tokio::test]
async fn json_failure_envelope_shape() {
    let install = staged_install();
    let (served, _) = make_served_binary();
    let asset = asset_name_for_current_target();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .corrupt_sums_entry_for(&asset)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::json_string(&env, "command"), Some("update"));
    assert_eq!(common::json_string(&env, "status"), Some("error"));
    assert_eq!(common::envelope_error_code(&env), Some("checksum_mismatch"));

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
}
