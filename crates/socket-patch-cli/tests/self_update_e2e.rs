//! Happy-path e2e for `socket-patch --update`: the self-replacement crux.
//!
//! Every test runs a COPY of the built binary staged into a tempdir
//! (`update_fixture::staged_install`) — `CARGO_BIN_EXE_socket-patch`
//! itself must never be a swap target, and each test re-verifies that at
//! the end.

#[path = "common/mod.rs"]
mod common;
#[path = "common/update_fixture.rs"]
mod update_fixture;

use sha2::{Digest, Sha256};
use update_fixture::{
    make_served_binary, run_installed, sha256_file, staged_install, FakeReleaseBuilder,
};

const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// THE crux: a full download→verify→stage→sanity→swap pass where the
/// running binary replaces itself, proven by byte-diff where the platform
/// allows a trailered binary (Linux/Windows) and by rename evidence
/// everywhere (inode change on Unix), without ever touching the real
/// build artifact.
#[tokio::test]
async fn update_force_swaps_binary_end_to_end() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, byte_distinct) = make_served_binary();
    let served_hash = hex::encode(Sha256::digest(&served));

    // Advertise the binary's own version: the staged download genuinely
    // reports it, so the strict version self-check semantics hold, and
    // `--force` supplies the "reinstall even though up to date" intent.
    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .expect_resolves(1)
        .expect_sums_fetches(1)
        .expect_asset_downloads(1)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--force", "--yes"],
        &[
            ("SOCKET_UPDATE_BASE_URL", &release.base_url),
            // Canary: hygiene check below asserts this never reaches the
            // release host.
            ("SOCKET_API_TOKEN", "secret-canary"),
        ],
    );
    assert_eq!(code, 0, "update must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains("Updated socket-patch"),
        "human output must report the update: {stdout}"
    );

    // The installed file now IS the served payload…
    assert_eq!(
        sha256_file(&install.bin),
        served_hash,
        "installed binary must be exactly the served payload"
    );
    // …and where the platform permits a byte-distinct payload, that is a
    // real content change.
    if byte_distinct {
        assert_ne!(sha256_file(&install.bin), install.pre_hash);
    }
    // Rename evidence: a staged-sibling rename always allocates a new
    // inode; the in-place-overwrite bug class this exists to catch keeps
    // the old one. (macOS serves pristine bytes, so this is its only
    // swap proof.)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_ne!(
            std::fs::metadata(&install.bin).unwrap().ino(),
            install.pre_ino,
            "swap must be a rename, not an in-place overwrite"
        );
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&install.bin).unwrap().permissions().mode() & 0o777,
            0o755,
            "destination mode must be preserved"
        );
    }

    // The new binary runs.
    let out = std::process::Command::new(&install.bin)
        .arg("--version")
        .output()
        .expect("spawn updated binary");
    assert!(out.status.success(), "updated binary must execute");

    install.assert_only_binary_present();
    install.assert_workdir_untouched();

    // The explicit update refreshed the notifier cache: no stale nag.
    let state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(install.state_dir.join("update-check.json"))
            .expect("update must write its state file"),
    )
    .unwrap();
    assert_eq!(state["latestSeen"], CURRENT);

    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// The genuine upgrade decision path: a strictly newer advertised version,
/// no --force. The served binary reports the real crate version (≠ 9.9.9),
/// which the sanity check tolerates as a warning because the base URL is
/// overridden — the strict-mode abort is pinned at the core unit level.
#[tokio::test]
async fn update_upgrade_branch_swaps() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, _) = make_served_binary();
    let served_hash = hex::encode(Sha256::digest(&served));

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .mount()
        .await;

    let (code, stdout, stderr) = run_installed(
        &install,
        &["--update", "--yes"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("Updated socket-patch"), "{stdout}");
    assert!(
        stderr.contains("Warning") && stderr.contains("9.9.9"),
        "the relaxed version self-check must surface as a warning: {stderr}"
    );
    assert_eq!(sha256_file(&install.bin), served_hash);
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// `--dry-run` is check-only: one resolve, zero downloads, zero mutation,
/// exit 0 — the cheap scriptable "is an update available" probe.
#[tokio::test]
async fn update_dry_run_checks_without_downloading() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new("9.9.9")
        .asset_for_current_target(&served)
        .expect_resolves(1)
        .expect_sums_fetches(0)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, _) = run_installed(
        &install,
        &["--update", "--dry-run", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0);
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::json_string(&env, "command").as_deref(), Some("update"));
    assert_eq!(env["dryRun"], true);
    let details = &env["events"][0]["details"];
    assert_eq!(details["updateAvailable"], true);
    assert_eq!(details["current"], CURRENT);
    assert_eq!(details["latest"], "9.9.9");
    assert_eq!(
        details["asset"],
        update_fixture::asset_name_for_current_target().as_str()
    );

    install.assert_binary_intact();
    install.assert_only_binary_present();
    release.verify_request_hygiene().await;
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}

/// Already on the latest release: informational no-op, exit 0, and the
/// sums/asset routes are never touched.
#[tokio::test]
async fn update_already_latest_is_a_noop() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .expect_sums_fetches(0)
        .expect_asset_downloads(0)
        .mount()
        .await;

    let (code, stdout, _) = run_installed(
        &install,
        &["--update"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("already the latest"),
        "must say it is a no-op: {stdout}"
    );
    install.assert_binary_intact();
}

/// `--json` success envelope: stable command tag, downloaded + updated
/// events, clean summary.
#[tokio::test]
async fn update_json_success_envelope_shape() {
    let install = staged_install();
    let (served, _) = make_served_binary();

    let release = FakeReleaseBuilder::new(CURRENT)
        .asset_for_current_target(&served)
        .mount()
        .await;

    let (code, stdout, _) = run_installed(
        &install,
        &["--update", "--force", "--json"],
        &[("SOCKET_UPDATE_BASE_URL", &release.base_url)],
    );
    assert_eq!(code, 0, "{stdout}");
    let env = common::parse_json_envelope(&stdout);
    assert_eq!(common::json_string(&env, "command").as_deref(), Some("update"));
    assert_eq!(common::json_string(&env, "status").as_deref(), Some("success"));
    let actions: Vec<&str> = env["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    assert_eq!(actions, vec!["downloaded", "updated"]);
    assert_eq!(env["summary"]["downloaded"], 1);
    assert_eq!(env["summary"]["updated"], 1);
    assert_eq!(
        env["events"][1]["details"]["to"], CURRENT,
        "updated event names the installed version"
    );
}

/// OPTIONAL live smoke against real GitHub (no base-URL override):
/// resolves the latest release and reports, download-free (`--dry-run`),
/// binary untouched. Catches asset-naming/redirect/SUMS drift against the
/// real distribution pipeline. `#[ignore]` — run explicitly:
/// `cargo test -p socket-patch-cli --test self_update_e2e -- --ignored`.
#[tokio::test]
#[ignore = "requires network access to github.com"]
async fn real_github_dry_run_smoke() {
    let real_hash = update_fixture::real_binary_hash();
    let install = staged_install();
    // No SOCKET_UPDATE_BASE_URL: default endpoints (the one deliberate
    // exception to hermeticity, which is why this is #[ignore]).
    let (code, stdout, stderr) = run_installed(&install, &["--update", "--dry-run"], &[]);
    assert_eq!(
        code, 0,
        "live dry-run must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    install.assert_binary_intact();
    update_fixture::StagedInstall::assert_build_artifact_untouched(&real_hash);
}
