//! Self-update engine: resolve the latest GitHub release, download and
//! verify the platform asset, and atomically replace the installed binary.
//!
//! The CLI layer owns policy (offline gate, managed-channel refusal,
//! confirmation, envelopes, exit codes) and passes everything
//! environment-shaped in as parameters — most importantly the install path
//! ([`perform_update`] never calls `current_exe()` itself; see
//! `swap::resolve_install_path`) and the compiled target triple. That
//! dependency injection is what lets unit tests aim the machinery at
//! tempdir files and arbitrary triples, and makes it structurally
//! impossible for an in-process test to swap the test harness binary.

pub mod channel;
pub mod download;
pub mod release;
pub mod state;
pub mod swap;

use std::path::{Path, PathBuf};

pub use channel::{channel_label, detect_channel, upgrade_hint, ChannelEnv, InstallChannel};
pub use release::{
    asset_name_for_target, current_version, fetch_latest_version, is_newer, parse_release_tag,
    UpdateEndpoints, UpdateTimeouts,
};
pub use state::{
    check_is_due, load_state, notice_is_due, save_state, unix_now, UpdateCheckState, CHECK_INTERVAL,
};
pub use swap::resolve_install_path;

/// Errors from the update engine. `error_code()` values are the stable
/// envelope `errorCode` tags documented in CLI_CONTRACT.md.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("could not check for updates: {0}")]
    CheckFailed(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("release v{version} has no prebuilt binary {asset} for this platform")]
    AssetNotFound { asset: String, version: String },

    #[error("download failed: {0}")]
    DownloadFailed(String),

    #[error("checksum verification failed for {asset}: {detail}")]
    ChecksumMismatch { asset: String, detail: String },

    #[error("downloaded binary failed verification: {0}")]
    VerifyFailed(String),

    #[error("could not install the update: {0}")]
    SwapFailed(String),

    #[error("permission denied writing to {}", path.display())]
    PermissionDenied { path: PathBuf },

    #[error("another socket-patch update is already in progress")]
    InProgress,
}

impl UpdateError {
    /// Stable machine-routing tag for the JSON envelope.
    pub fn error_code(&self) -> &'static str {
        match self {
            UpdateError::CheckFailed(_) => "check_failed",
            UpdateError::Network(_) => "download_failed",
            UpdateError::AssetNotFound { .. } => "asset_not_found",
            UpdateError::DownloadFailed(_) => "download_failed",
            UpdateError::ChecksumMismatch { .. } => "checksum_mismatch",
            UpdateError::VerifyFailed(_) => "verify_failed",
            UpdateError::SwapFailed(_) => "swap_failed",
            UpdateError::PermissionDenied { .. } => "permission_denied",
            UpdateError::InProgress => "update_in_progress",
        }
    }
}

/// Everything [`perform_update`] needs, resolved by the CLI layer.
#[derive(Debug)]
pub struct UpdateRequest<'a> {
    /// Compiled target triple (the CLI's `build.rs`-embedded
    /// `SOCKET_PATCH_TARGET`).
    pub target_triple: &'a str,
    /// The exact version to install (already resolved: latest or a pin).
    pub version: &'a semver::Version,
    /// Canonicalized path of the binary to replace.
    pub install_path: &'a Path,
    pub endpoints: &'a UpdateEndpoints,
    pub timeouts: &'a UpdateTimeouts,
}

/// What a completed update did, for the envelope/summary.
#[derive(Debug)]
pub struct UpdateOutcome {
    pub asset: String,
    pub archive_bytes: u64,
    pub archive_sha256: String,
    pub installed_path: PathBuf,
    /// Non-fatal notes (e.g. the relaxed version self-check under a custom
    /// base URL).
    pub warnings: Vec<String>,
}

/// Download → verify → stage → sanity-exec → swap, under the single-flight
/// lock. Every failure path leaves the installed binary untouched: all
/// mutation happens on a staged sibling until the one atomic rename.
pub async fn perform_update(req: UpdateRequest<'_>) -> Result<UpdateOutcome, UpdateError> {
    let _lock = swap::acquire_update_lock()?;

    let dest_dir = req.install_path.parent().ok_or_else(|| {
        UpdateError::SwapFailed(format!(
            "install path {} has no parent directory",
            req.install_path.display()
        ))
    })?;

    // Crash leftovers from previous runs (stale stages, parked old exes).
    download::sweep_stale_stages(dest_dir);

    let asset = asset_name_for_target(req.target_triple);
    let mut warnings = Vec::new();
    let staged = download::download_and_stage(
        req.endpoints,
        req.timeouts,
        req.version,
        &asset,
        dest_dir,
        &mut warnings,
    )
    .await?;

    swap::swap_binary(&staged.path, req.install_path)?;

    // Remember what we just installed so the passive notifier never nags
    // about a version the user already has. Best-effort: state problems
    // must not fail a completed update.
    let mut check_state = load_state();
    check_state.last_check_at = Some(unix_now());
    check_state.latest_seen = Some(req.version.to_string());
    let _ = save_state(&check_state).await;

    Ok(UpdateOutcome {
        asset: staged.asset,
        archive_bytes: staged.archive_bytes,
        archive_sha256: staged.archive_sha256,
        installed_path: req.install_path.to_path_buf(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use serial_test::serial;

    /// Pins the full `error_code()` mapping to the stable top-level
    /// `errorCode` list documented in CLI_CONTRACT.md ("Top-level
    /// `errorCode` values (stable)"). `Network => "download_failed"` is a
    /// deliberate alias: the contract's stable list has no separate
    /// `network` tag, so a network-layer failure routes to the same tag
    /// callers already handle for download failures.
    #[test]
    fn error_code_table_matches_cli_contract() {
        let table: [(UpdateError, &str); 9] = [
            (UpdateError::CheckFailed("x".into()), "check_failed"),
            (UpdateError::Network("x".into()), "download_failed"),
            (
                UpdateError::AssetNotFound {
                    asset: "a".into(),
                    version: "1.0.0".into(),
                },
                "asset_not_found",
            ),
            (UpdateError::DownloadFailed("x".into()), "download_failed"),
            (
                UpdateError::ChecksumMismatch {
                    asset: "a".into(),
                    detail: "d".into(),
                },
                "checksum_mismatch",
            ),
            (UpdateError::VerifyFailed("x".into()), "verify_failed"),
            (UpdateError::SwapFailed("x".into()), "swap_failed"),
            (
                UpdateError::PermissionDenied {
                    path: PathBuf::from("/x"),
                },
                "permission_denied",
            ),
            (UpdateError::InProgress, "update_in_progress"),
        ];
        for (err, expected) in &table {
            assert_eq!(
                err.error_code(),
                *expected,
                "error_code for {err:?} drifted from the CLI_CONTRACT.md stable list"
            );
        }
    }

    /// A parentless install path (only a bare root can be one — a
    /// canonicalized exe path essentially never is) must be refused as
    /// `SwapFailed` under the single-flight lock and BEFORE any network
    /// or stage-sweep work. The dead base URL proves the ordering: had
    /// perform_update reached the download step, the failure would surface
    /// as `Network`/`DownloadFailed` instead and the match below would
    /// fail.
    #[tokio::test]
    #[serial(update_state_dir_env, update_base_url_env)]
    async fn perform_update_refuses_parentless_install_path_before_network() {
        let tmp = tempfile::tempdir().unwrap();
        let prev_state = std::env::var_os("SOCKET_UPDATE_STATE_DIR");
        let prev_base = std::env::var_os("SOCKET_UPDATE_BASE_URL");
        std::env::set_var("SOCKET_UPDATE_STATE_DIR", tmp.path());
        std::env::set_var("SOCKET_UPDATE_BASE_URL", "http://127.0.0.1:9");

        let endpoints = UpdateEndpoints::from_env();
        assert!(!endpoints.is_default(), "dead base URL override must take");
        let timeouts = UpdateTimeouts::default();
        let version = semver::Version::new(9, 9, 9);
        let result = perform_update(UpdateRequest {
            target_triple: "x86_64-unknown-linux-gnu",
            version: &version,
            install_path: Path::new("/"),
            endpoints: &endpoints,
            timeouts: &timeouts,
        })
        .await;

        let err = result.expect_err("a parentless install path must be refused");
        assert!(
            matches!(err, UpdateError::SwapFailed(_)),
            "expected SwapFailed, got {err:?}"
        );
        assert_eq!(err.error_code(), "swap_failed");
        assert!(
            err.to_string().contains("has no parent directory"),
            "unexpected message: {err}"
        );
        // The refusal happened under the lock: acquire_update_lock already
        // created update.lock in the (env-overridden) state dir.
        assert!(
            tmp.path().join("update.lock").is_file(),
            "refusal must happen under the single-flight lock"
        );

        match prev_state {
            Some(v) => std::env::set_var("SOCKET_UPDATE_STATE_DIR", v),
            None => std::env::remove_var("SOCKET_UPDATE_STATE_DIR"),
        }
        match prev_base {
            Some(v) => std::env::set_var("SOCKET_UPDATE_BASE_URL", v),
            None => std::env::remove_var("SOCKET_UPDATE_BASE_URL"),
        }
    }
}
