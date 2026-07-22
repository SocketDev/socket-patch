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
    check_is_due, load_state, notice_is_due, save_state, unix_now, UpdateCheckState,
    CHECK_INTERVAL,
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
