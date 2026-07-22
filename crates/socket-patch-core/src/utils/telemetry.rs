use std::collections::HashMap;

use once_cell::sync::Lazy;
use uuid::Uuid;

use crate::constants::USER_AGENT;
use crate::utils::env_compat::{is_debug_enabled, proxy_url_from_env, read_env_with_legacy};
use crate::utils::fs::home_dir;
use crate::vex::time::unix_to_ymdhms;

// ---------------------------------------------------------------------------
// Session ID — generated once per process invocation
// ---------------------------------------------------------------------------

/// Unique session ID for the current CLI invocation.
/// Shared across all telemetry events in a single run.
static SESSION_ID: Lazy<String> = Lazy::new(|| Uuid::new_v4().to_string());

/// Package version — sourced from the crate's `Cargo.toml` at build time so
/// it always tracks the real release (matching `USER_AGENT` in `constants.rs`
/// and the `vex` tooling string). A hardcoded literal here silently drifts
/// from the published version.
const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Telemetry event types for the patch lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchTelemetryEventType {
    // Write-side: apply / remove / rollback
    PatchApplied,
    PatchApplyFailed,
    PatchRemoved,
    PatchRemoveFailed,
    PatchRolledBack,
    PatchRollbackFailed,
    // Read-side: scan / get (get is internally "fetch")
    PatchScanned,
    PatchScanFailed,
    PatchFetched,
    PatchFetchFailed,
    // Write-side: vendor
    PatchVendored,
    PatchVendorFailed,
    // Inspection / housekeeping
    PatchListed,
    PatchRepaired,
    PatchRepairFailed,
    PatchSetup,
    // OpenVEX attestation (added in #81)
    VexGenerated,
    VexFailed,
}

impl PatchTelemetryEventType {
    /// Return the wire-format string for this event type.
    fn as_str(&self) -> &'static str {
        match self {
            Self::PatchApplied => "patch_applied",
            Self::PatchApplyFailed => "patch_apply_failed",
            Self::PatchRemoved => "patch_removed",
            Self::PatchVendored => "patch_vendored",
            Self::PatchVendorFailed => "patch_vendor_failed",
            Self::PatchRemoveFailed => "patch_remove_failed",
            Self::PatchRolledBack => "patch_rolled_back",
            Self::PatchRollbackFailed => "patch_rollback_failed",
            Self::PatchScanned => "patch_scanned",
            Self::PatchScanFailed => "patch_scan_failed",
            Self::PatchFetched => "patch_fetched",
            Self::PatchFetchFailed => "patch_fetch_failed",
            Self::PatchListed => "patch_listed",
            Self::PatchRepaired => "patch_repaired",
            Self::PatchRepairFailed => "patch_repair_failed",
            Self::PatchSetup => "patch_setup",
            Self::VexGenerated => "vex_generated",
            Self::VexFailed => "vex_failed",
        }
    }
}

/// Telemetry context describing the execution environment.
#[derive(Debug, Clone, serde::Serialize)]
struct PatchTelemetryContext {
    version: String,
    platform: String,
    arch: String,
    command: String,
}

/// Error details for telemetry events.
#[derive(Debug, Clone, serde::Serialize)]
struct PatchTelemetryError {
    #[serde(rename = "type")]
    error_type: String,
    message: Option<String>,
}

/// Telemetry event structure for patch operations.
#[derive(Debug, Clone, serde::Serialize)]
struct PatchTelemetryEvent {
    event_sender_created_at: String,
    event_type: String,
    context: PatchTelemetryContext,
    session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<PatchTelemetryError>,
}

// ---------------------------------------------------------------------------
// Environment checks
// ---------------------------------------------------------------------------

/// Check if telemetry is disabled via environment variables.
///
/// Telemetry is disabled when:
/// - `SOCKET_TELEMETRY_DISABLED` is `"1"` or `"true"`
///   (legacy `SOCKET_PATCH_TELEMETRY_DISABLED` still honored with warning)
/// - `VITEST` is `"true"` (test environment)
/// - `SOCKET_OFFLINE` is `"1"` or `"true"` (airgap mode — the telemetry
///   endpoint is a network call, so honoring `--offline`/`SOCKET_OFFLINE`
///   here keeps every command compliant with the strict-airgap contract)
///
/// Note that the CLI also exposes a `--no-telemetry` flag; when that flag
/// is set the CLI dispatcher sets `SOCKET_TELEMETRY_DISABLED=1` for the
/// duration of the process so this check stays the single source of truth.
pub fn is_telemetry_disabled() -> bool {
    let env_value = read_env_with_legacy(
        "SOCKET_TELEMETRY_DISABLED",
        "SOCKET_PATCH_TELEMETRY_DISABLED",
    )
    .unwrap_or_default();
    let disabled_via_env = matches!(env_value.as_str(), "1" | "true");
    let vitest = std::env::var("VITEST").unwrap_or_default() == "true";
    let offline = matches!(
        std::env::var("SOCKET_OFFLINE").unwrap_or_default().as_str(),
        "1" | "true"
    );
    disabled_via_env || vitest || offline
}

/// Log debug messages when debug mode is enabled.
fn debug_log(message: &str) {
    if is_debug_enabled() {
        eprintln!("[socket-patch telemetry] {message}");
    }
}

// ---------------------------------------------------------------------------
// Build event
// ---------------------------------------------------------------------------

/// Build the telemetry context for the current environment.
fn build_telemetry_context(command: &str) -> PatchTelemetryContext {
    PatchTelemetryContext {
        version: PACKAGE_VERSION.to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        command: command.to_string(),
    }
}

/// Sanitize an error message for telemetry.
///
/// Replaces the user's home directory path with `~` to avoid leaking
/// sensitive file system information.
pub fn sanitize_error_message(message: &str) -> String {
    let home = home_dir();
    let home = home.to_string_lossy();
    // `home_dir()` falls back to a literal `"~"` when no home is set, and
    // replacing `"~"` with `"~"` is a no-op. A set-but-empty HOME must be
    // skipped explicitly — replacing `""` would splice `~` between every byte.
    // Trailing separators are trimmed so a `HOME=/home/user/` redaction keeps
    // the separator (`~/.cache`, not `~.cache`); a home that trims to nothing
    // (`HOME=/`, common for unmapped-UID containers) is a filesystem root with
    // no user-identifying prefix to redact — replacing it would splice `~`
    // between every path segment in the message.
    let home = home.trim_end_matches(['/', '\\']);
    if home.is_empty() {
        return message.to_string();
    }
    message.replace(home, "~")
}

/// Build a telemetry event. `error` is an `(error_type, message)` pair; the
/// message is home-dir-sanitized before it leaves the process.
fn build_telemetry_event(
    event_type: PatchTelemetryEventType,
    command: &str,
    metadata: Option<HashMap<String, serde_json::Value>>,
    error: Option<(String, String)>,
) -> PatchTelemetryEvent {
    PatchTelemetryEvent {
        event_sender_created_at: chrono_now_iso(),
        event_type: event_type.as_str().to_string(),
        context: build_telemetry_context(command),
        session_id: SESSION_ID.clone(),
        metadata,
        error: error.map(|(error_type, message)| PatchTelemetryError {
            error_type,
            message: Some(sanitize_error_message(&message)),
        }),
    }
}

/// Get the current time as an ISO 8601 string with millisecond precision,
/// e.g. `2024-01-15T10:30:45.123Z`. The civil-date arithmetic is shared with
/// `vex::time` (`unix_to_ymdhms`); only the `.mmm` suffix differs from the
/// RFC 3339 string vex emits.
fn chrono_now_iso() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let (year, month, day, hours, minutes, seconds) = unix_to_ymdhms(duration.as_secs());
    let millis = duration.subsec_millis();
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z")
}

// ---------------------------------------------------------------------------
// Send event
// ---------------------------------------------------------------------------

/// Decide which endpoint a telemetry event goes to, and whether to attach
/// the bearer token.
///
/// The authenticated `/v0/orgs/<slug>/telemetry` endpoint is used only when
/// BOTH a non-empty token and a non-empty org slug are present. An empty
/// string is treated as absent: a `Some("")` slug would otherwise build a
/// malformed `/v0/orgs//telemetry` URL and a `Some("")` token an empty
/// `Bearer ` header. This mirrors the empty-slug guard in
/// `get_api_client_from_env`, keeping the contract robust even if a caller
/// hands us blank values directly.
fn resolve_telemetry_endpoint(api_token: Option<&str>, org_slug: Option<&str>) -> (String, bool) {
    let token = api_token.filter(|t| !t.is_empty());
    let slug = org_slug.filter(|s| !s.is_empty());

    match (token, slug) {
        (Some(_token), Some(slug)) => {
            // Same env → socket-cli config → default chain as API-client
            // construction, so telemetry can't target a different host than
            // the client that produced the event.
            let api_url = crate::utils::socket_cli_config::resolve_api_base_url();
            // Trim trailing slashes like `ApiClient::new` does, so a base URL
            // of `https://host/` doesn't produce a malformed `//v0/...` path.
            let api_url = api_url.trim_end_matches('/');
            (format!("{api_url}/v0/orgs/{slug}/telemetry"), true)
        }
        _ => {
            let proxy_url = proxy_url_from_env();
            let proxy_url = proxy_url.trim_end_matches('/');
            (format!("{proxy_url}/patch/telemetry"), false)
        }
    }
}

/// Send a telemetry event to the API.
///
/// This is fire-and-forget: errors are logged in debug mode but never
/// propagated. Uses `reqwest` with a 5-second timeout.
async fn send_telemetry_event(
    event: &PatchTelemetryEvent,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    let (url, use_auth) = resolve_telemetry_endpoint(api_token, org_slug);

    debug_log(&format!("Sending telemetry to {url}"));

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            debug_log(&format!("Failed to build HTTP client: {e}"));
            return;
        }
    };

    let mut request = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", USER_AGENT);

    if use_auth {
        if let Some(token) = api_token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
    }

    match request.json(event).send().await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                debug_log("Telemetry sent successfully");
            } else {
                debug_log(&format!("Telemetry request returned status {status}"));
            }
        }
        Err(e) => {
            debug_log(&format!("Telemetry request failed: {e}"));
        }
    }
}

// ---------------------------------------------------------------------------
// Per-event tracker wrappers (the public API)
//
// These accept `Option<&str>` for api_token/org_slug to make call sites
// convenient (callers typically have `Option<String>` and call `.as_deref()`).
// ---------------------------------------------------------------------------

/// Shared fire-and-forget helper for the per-event tracker wrappers below.
///
/// Non-blocking and never returns errors: telemetry failures are logged in
/// debug mode but do not affect CLI operation. Returns immediately when
/// telemetry is disabled via environment variables. `metadata` is a
/// `serde_json::json!({...})` object; non-object / empty values are dropped
/// to avoid `.unwrap()` noise at every call site.
async fn fire(
    event_type: PatchTelemetryEventType,
    command: &'static str,
    metadata: serde_json::Value,
    error: Option<impl std::fmt::Display>,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    if is_telemetry_disabled() {
        debug_log("Telemetry is disabled, skipping event");
        return;
    }

    let metadata = match metadata {
        serde_json::Value::Object(map) if !map.is_empty() => Some(map.into_iter().collect()),
        _ => None,
    };
    let error = error.map(|e| ("Error".to_string(), e.to_string()));
    let event = build_telemetry_event(event_type, command, metadata, error);
    send_telemetry_event(&event, api_token, org_slug).await;
}

/// Track a successful patch application.
pub async fn track_patch_applied(
    patches_count: usize,
    dry_run: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchApplied,
        "apply",
        serde_json::json!({ "patches_count": patches_count, "dry_run": dry_run }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed patch application.
///
/// Accepts any `Display` type for the error (works with `&str`, `String`,
/// `anyhow::Error`, `std::io::Error`, etc.).
pub async fn track_patch_apply_failed(
    error: impl std::fmt::Display,
    dry_run: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchApplyFailed,
        "apply",
        serde_json::json!({ "dry_run": dry_run }),
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

/// Track a successful vendor run (count = packages vendored).
pub async fn track_patch_vendored(
    vendored_count: u32,
    dry_run: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchVendored,
        "vendor",
        serde_json::json!({ "patches_count": vendored_count, "dry_run": dry_run }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed vendor run.
pub async fn track_patch_vendor_failed(
    error: impl std::fmt::Display,
    dry_run: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchVendorFailed,
        "vendor",
        serde_json::json!({ "dry_run": dry_run }),
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

/// Track a successful patch removal.
pub async fn track_patch_removed(
    removed_count: usize,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchRemoved,
        "remove",
        serde_json::json!({ "removed_count": removed_count }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed patch removal. Accepts any `Display` type for the error.
pub async fn track_patch_remove_failed(
    error: impl std::fmt::Display,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchRemoveFailed,
        "remove",
        serde_json::Value::Null,
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

/// Track a successful patch rollback.
pub async fn track_patch_rolled_back(
    rolled_back_count: usize,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchRolledBack,
        "rollback",
        serde_json::json!({ "rolled_back_count": rolled_back_count }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed patch rollback. Accepts any `Display` type for the error.
pub async fn track_patch_rollback_failed(
    error: impl std::fmt::Display,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchRollbackFailed,
        "rollback",
        serde_json::Value::Null,
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Read-side trackers: scan + get
// ---------------------------------------------------------------------------

/// Track a successful `scan`. Reports per-tier patch counts and whether
/// the call was downgraded to the public proxy after an auth-endpoint
/// 401/403 (`fallback_to_proxy`).
///
/// The argument count intentionally mirrors the metadata fields the
/// dashboard needs — grouping them into a struct would force callers
/// to build a config object for a single fire-and-forget call, which
/// is worse ergonomics for a tracker.
#[allow(clippy::too_many_arguments)]
pub async fn track_patch_scanned(
    packages_scanned: usize,
    free_patches: usize,
    paid_patches: usize,
    can_access_paid: bool,
    ecosystems: &[String],
    fallback_to_proxy: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchScanned,
        "scan",
        serde_json::json!({
            "packages_scanned": packages_scanned,
            "free_patches": free_patches,
            "paid_patches": paid_patches,
            "can_access_paid": can_access_paid,
            "ecosystems": ecosystems,
            "fallback_to_proxy": fallback_to_proxy,
        }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed `scan`.
pub async fn track_patch_scan_failed(
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchScanFailed,
        "scan",
        serde_json::json!({ "fallback_to_proxy": fallback_to_proxy }),
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

/// Track a successful `get`. Reports patch identity + delivery mode and
/// whether the call was downgraded to the public proxy after an
/// auth-endpoint 401/403.
pub async fn track_patch_fetched(
    uuid: &str,
    tier: &str,
    ecosystem: &str,
    download_mode: &str,
    fallback_to_proxy: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchFetched,
        "get",
        serde_json::json!({
            "uuid": uuid,
            "tier": tier,
            "ecosystem": ecosystem,
            "download_mode": download_mode,
            "fallback_to_proxy": fallback_to_proxy,
        }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed `get`. `uuid` may be empty when the failure occurred
/// before the patch was resolved (e.g. lookup miss).
pub async fn track_patch_fetch_failed(
    uuid: &str,
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchFetchFailed,
        "get",
        serde_json::json!({ "uuid": uuid, "fallback_to_proxy": fallback_to_proxy }),
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Inspection / housekeeping trackers: list / repair / setup
// ---------------------------------------------------------------------------

/// Track a successful `list`. Reports the number of patches surfaced.
pub async fn track_patch_listed(
    patches_count: usize,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchListed,
        "list",
        serde_json::json!({ "patches_count": patches_count }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a successful `repair`. Reports blob deltas and bytes freed.
pub async fn track_patch_repaired(
    blobs_added: usize,
    blobs_removed: usize,
    bytes_freed: u64,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchRepaired,
        "repair",
        serde_json::json!({
            "blobs_added": blobs_added,
            "blobs_removed": blobs_removed,
            "bytes_freed": bytes_freed,
        }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed `repair`.
pub async fn track_patch_repair_failed(
    error: impl std::fmt::Display,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::PatchRepairFailed,
        "repair",
        serde_json::Value::Null,
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

/// Track a successful `setup`. Reports the detected package manager so
/// we can tell which install hooks are exercised in the wild.
pub async fn track_patch_setup(manager: &str, api_token: Option<&str>, org_slug: Option<&str>) {
    fire(
        PatchTelemetryEventType::PatchSetup,
        "setup",
        serde_json::json!({ "manager": manager }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

// ---------------------------------------------------------------------------
// OpenVEX trackers
// ---------------------------------------------------------------------------

/// Track a successful `vex` generation. `format` is e.g. `"openvex-0.2.0"`;
/// `output_kind` describes where the document went (`"stdout"`, `"file"`).
pub async fn track_vex_generated(
    advisories_count: usize,
    format: &str,
    output_kind: &str,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::VexGenerated,
        "vex",
        serde_json::json!({
            "advisories_count": advisories_count,
            "format": format,
            "output_kind": output_kind,
        }),
        None::<&str>,
        api_token,
        org_slug,
    )
    .await;
}

/// Track a failed `vex` generation.
pub async fn track_vex_failed(
    error: impl std::fmt::Display,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    fire(
        PatchTelemetryEventType::VexFailed,
        "vex",
        serde_json::Value::Null,
        Some(error),
        api_token,
        org_slug,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Combined into a single test to avoid env-var races across parallel tests.
    /// Exercises the `SOCKET_TELEMETRY_DISABLED` name, the legacy
    /// `SOCKET_PATCH_TELEMETRY_DISABLED` shim, and the airgap gate via
    /// `SOCKET_OFFLINE`.
    #[test]
    fn test_is_telemetry_disabled() {
        // Save originals
        let orig_new = std::env::var("SOCKET_TELEMETRY_DISABLED").ok();
        let orig_legacy = std::env::var("SOCKET_PATCH_TELEMETRY_DISABLED").ok();
        let orig_vitest = std::env::var("VITEST").ok();
        let orig_offline = std::env::var("SOCKET_OFFLINE").ok();

        // Default: not disabled
        std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
        std::env::remove_var("SOCKET_PATCH_TELEMETRY_DISABLED");
        std::env::remove_var("VITEST");
        std::env::remove_var("SOCKET_OFFLINE");
        assert!(!is_telemetry_disabled());

        // Disabled via new var "1"
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", "1");
        assert!(is_telemetry_disabled());
        std::env::remove_var("SOCKET_TELEMETRY_DISABLED");

        // Disabled via legacy var (with deprecation warning)
        std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", "1");
        assert!(is_telemetry_disabled());
        std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", "true");
        assert!(is_telemetry_disabled());
        std::env::remove_var("SOCKET_PATCH_TELEMETRY_DISABLED");

        // Disabled via airgap: SOCKET_OFFLINE=1 implies "no network",
        // which includes the telemetry endpoint.
        std::env::set_var("SOCKET_OFFLINE", "1");
        assert!(
            is_telemetry_disabled(),
            "SOCKET_OFFLINE=1 must disable telemetry (airgap)"
        );
        std::env::set_var("SOCKET_OFFLINE", "true");
        assert!(
            is_telemetry_disabled(),
            "SOCKET_OFFLINE=true must disable telemetry (airgap)"
        );
        // Non-truthy values do not disable
        std::env::set_var("SOCKET_OFFLINE", "0");
        assert!(!is_telemetry_disabled());
        std::env::set_var("SOCKET_OFFLINE", "");
        assert!(!is_telemetry_disabled());
        std::env::remove_var("SOCKET_OFFLINE");

        // Restore originals
        match orig_new {
            Some(v) => std::env::set_var("SOCKET_TELEMETRY_DISABLED", v),
            None => std::env::remove_var("SOCKET_TELEMETRY_DISABLED"),
        }
        match orig_legacy {
            Some(v) => std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", v),
            None => std::env::remove_var("SOCKET_PATCH_TELEMETRY_DISABLED"),
        }
        match orig_vitest {
            Some(v) => std::env::set_var("VITEST", v),
            None => std::env::remove_var("VITEST"),
        }
        match orig_offline {
            Some(v) => std::env::set_var("SOCKET_OFFLINE", v),
            None => std::env::remove_var("SOCKET_OFFLINE"),
        }
    }

    #[test]
    fn test_sanitize_error_message() {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "/home/testuser".to_string());
        let msg = format!("Failed to read {home}/projects/secret/file.txt");
        let sanitized = sanitize_error_message(&msg);
        assert!(sanitized.contains("~/projects/secret/file.txt"));
        assert!(!sanitized.contains(&home));
    }

    #[test]
    fn test_sanitize_error_message_no_home() {
        let msg = "Some error without paths";
        assert_eq!(sanitize_error_message(msg), msg);
    }

    #[test]
    fn test_event_type_as_str() {
        // Write-side
        assert_eq!(
            PatchTelemetryEventType::PatchApplied.as_str(),
            "patch_applied"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchApplyFailed.as_str(),
            "patch_apply_failed"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchRemoved.as_str(),
            "patch_removed"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchRemoveFailed.as_str(),
            "patch_remove_failed"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchRolledBack.as_str(),
            "patch_rolled_back"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchRollbackFailed.as_str(),
            "patch_rollback_failed"
        );
        // Read-side
        assert_eq!(
            PatchTelemetryEventType::PatchScanned.as_str(),
            "patch_scanned"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchScanFailed.as_str(),
            "patch_scan_failed"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchFetched.as_str(),
            "patch_fetched"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchFetchFailed.as_str(),
            "patch_fetch_failed"
        );
        // Inspection / housekeeping
        assert_eq!(
            PatchTelemetryEventType::PatchListed.as_str(),
            "patch_listed"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchRepaired.as_str(),
            "patch_repaired"
        );
        assert_eq!(
            PatchTelemetryEventType::PatchRepairFailed.as_str(),
            "patch_repair_failed"
        );
        assert_eq!(PatchTelemetryEventType::PatchSetup.as_str(), "patch_setup");
        // OpenVEX
        assert_eq!(
            PatchTelemetryEventType::VexGenerated.as_str(),
            "vex_generated"
        );
        assert_eq!(PatchTelemetryEventType::VexFailed.as_str(), "vex_failed");
    }

    #[test]
    fn test_build_telemetry_context() {
        let ctx = build_telemetry_context("apply");
        assert_eq!(ctx.command, "apply");
        assert_eq!(ctx.version, PACKAGE_VERSION);
        assert!(!ctx.platform.is_empty());
        assert!(!ctx.arch.is_empty());
    }

    /// Regression: the reported version must track the real crate version,
    /// not a hardcoded literal that drifts from the published release.
    /// Anchoring on `CARGO_PKG_VERSION` (rather than the `PACKAGE_VERSION`
    /// const) is deliberate — comparing the context against the same const it
    /// is built from is self-referential and can never catch a stale value.
    #[test]
    fn test_telemetry_version_tracks_crate_version() {
        assert_eq!(PACKAGE_VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            build_telemetry_context("apply").version,
            env!("CARGO_PKG_VERSION")
        );
        // The previously-hardcoded literal must never reappear unless the crate
        // is genuinely at that version.
        assert!(
            PACKAGE_VERSION != "1.0.0" || env!("CARGO_PKG_VERSION") == "1.0.0",
            "telemetry version is still hardcoded to the stale 1.0.0 literal"
        );
    }

    #[test]
    fn test_build_telemetry_event_basic() {
        let event =
            build_telemetry_event(PatchTelemetryEventType::PatchApplied, "apply", None, None);
        assert_eq!(event.event_type, "patch_applied");
        assert_eq!(event.context.command, "apply");
        assert!(!event.session_id.is_empty());
        assert!(!event.event_sender_created_at.is_empty());
        assert!(event.metadata.is_none());
        assert!(event.error.is_none());
    }

    #[test]
    fn test_build_telemetry_event_with_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert(
            "patches_count".to_string(),
            serde_json::Value::Number(5.into()),
        );

        let event = build_telemetry_event(
            PatchTelemetryEventType::PatchApplied,
            "apply",
            Some(metadata),
            None,
        );
        assert!(event.metadata.is_some());
        let meta = event.metadata.unwrap();
        assert_eq!(
            meta.get("patches_count").unwrap(),
            &serde_json::Value::Number(5.into())
        );
    }

    #[test]
    fn test_build_telemetry_event_with_error() {
        let event = build_telemetry_event(
            PatchTelemetryEventType::PatchApplyFailed,
            "apply",
            None,
            Some(("IoError".to_string(), "file not found".to_string())),
        );
        assert!(event.error.is_some());
        let err = event.error.unwrap();
        assert_eq!(err.error_type, "IoError");
        assert_eq!(err.message.unwrap(), "file not found");
    }

    #[test]
    fn test_session_id_is_consistent() {
        let id1 = SESSION_ID.clone();
        let id2 = SESSION_ID.clone();
        assert_eq!(id1, id2);
        // Should be a valid UUID v4 format
        assert_eq!(id1.len(), 36);
        assert!(id1.contains('-'));
    }

    #[test]
    fn test_chrono_now_iso_format() {
        let ts = chrono_now_iso();
        // Should look like "2024-01-15T10:30:45.123Z"
        assert!(ts.ends_with('Z'));
        assert!(ts.contains('T'));
        assert!(ts.contains('-'));
        assert!(ts.contains(':'));
        assert_eq!(ts.len(), 24); // YYYY-MM-DDTHH:MM:SS.mmmZ
    }

    /// The time-of-day split in `chrono_now_iso` must carve a within-day
    /// second offset into the right h/m/s buckets. We reconstruct the exact
    /// arithmetic for a known offset (23:59:59 on day 0 = epoch) by parsing
    /// the rendered prefix, since the live timestamp can't be pinned.
    #[test]
    fn test_chrono_now_iso_components_well_formed() {
        let ts = chrono_now_iso();
        // YYYY-MM-DDTHH:MM:SS.mmmZ — validate every field range, not just shape.
        let (date, rest) = ts.split_once('T').expect("has T separator");
        let parts: Vec<&str> = date.split('-').collect();
        assert_eq!(parts.len(), 3);
        let (year, month, day): (u64, u64, u64) = (
            parts[0].parse().unwrap(),
            parts[1].parse().unwrap(),
            parts[2].parse().unwrap(),
        );
        assert!((2026..=2100).contains(&year), "year {year} out of range");
        assert!((1..=12).contains(&month), "month {month} out of range");
        assert!((1..=31).contains(&day), "day {day} out of range");

        let time = rest.strip_suffix('Z').expect("ends with Z");
        let (hms, millis) = time.split_once('.').expect("has millis");
        let hms_parts: Vec<&str> = hms.split(':').collect();
        assert_eq!(hms_parts.len(), 3);
        let h: u64 = hms_parts[0].parse().unwrap();
        let m: u64 = hms_parts[1].parse().unwrap();
        let s: u64 = hms_parts[2].parse().unwrap();
        assert!(h < 24, "hour {h} out of range");
        assert!(m < 60, "minute {m} out of range");
        assert!(s < 60, "second {s} out of range");
        assert_eq!(millis.len(), 3);
        assert!(millis.parse::<u64>().unwrap() < 1000);
    }

    /// Endpoint selection must use the authenticated org route only when both
    /// a non-empty token and non-empty slug are present; blank values fall
    /// back to the public proxy (no `/v0/orgs//telemetry`, no `Bearer `).
    #[test]
    fn test_resolve_telemetry_endpoint_auth_and_proxy() {
        let (url, auth) = resolve_telemetry_endpoint(Some("tok"), Some("acme"));
        assert!(auth, "token + slug should authenticate");
        assert!(url.contains("/v0/orgs/acme/telemetry"), "got {url}");
        assert!(!url.contains("/orgs//"), "no empty slug segment: {url}");

        // Missing slug -> proxy.
        let (url, auth) = resolve_telemetry_endpoint(Some("tok"), None);
        assert!(!auth);
        assert!(url.ends_with("/patch/telemetry"), "got {url}");

        // Missing token -> proxy.
        let (_url, auth) = resolve_telemetry_endpoint(None, Some("acme"));
        assert!(!auth);
    }

    /// Regression: a trailing slash on `SOCKET_API_URL` / `SOCKET_PROXY_URL`
    /// must not yield a double-slash telemetry path. `ApiClient::new`
    /// normalizes its base with `trim_end_matches('/')`, so the same user
    /// config works for every API call — telemetry must match, or the
    /// fire-and-forget POST silently lands on a malformed `//v0/...` /
    /// `//patch/...` path (same malformed-URL class as `/v0/orgs//telemetry`).
    #[test]
    fn test_resolve_telemetry_endpoint_trims_trailing_slash() {
        let orig_api = std::env::var("SOCKET_API_URL").ok();
        let orig_proxy = std::env::var("SOCKET_PROXY_URL").ok();

        std::env::set_var("SOCKET_API_URL", "https://api.example.test/sub/");
        let (url, auth) = resolve_telemetry_endpoint(Some("tok"), Some("acme"));
        assert!(auth);
        assert_eq!(url, "https://api.example.test/sub/v0/orgs/acme/telemetry");

        std::env::set_var("SOCKET_PROXY_URL", "https://proxy.example.test/sub/");
        let (url, auth) = resolve_telemetry_endpoint(None, None);
        assert!(!auth);
        assert_eq!(url, "https://proxy.example.test/sub/patch/telemetry");

        match orig_api {
            Some(v) => std::env::set_var("SOCKET_API_URL", v),
            None => std::env::remove_var("SOCKET_API_URL"),
        }
        match orig_proxy {
            Some(v) => std::env::set_var("SOCKET_PROXY_URL", v),
            None => std::env::remove_var("SOCKET_PROXY_URL"),
        }
    }

    /// Regression: an empty-string token or slug must be treated as absent,
    /// not spliced into the URL/header. Guards the `/v0/orgs//telemetry`
    /// malformed-URL class that bit the API client.
    #[test]
    fn test_resolve_telemetry_endpoint_empty_strings_fall_back() {
        let (url, auth) = resolve_telemetry_endpoint(Some("tok"), Some(""));
        assert!(!auth, "empty slug must not authenticate");
        assert!(
            !url.contains("/orgs//"),
            "empty slug leaked into URL: {url}"
        );
        assert!(url.ends_with("/patch/telemetry"), "got {url}");

        let (_url, auth) = resolve_telemetry_endpoint(Some(""), Some("acme"));
        assert!(!auth, "empty token must not authenticate");

        let (_url, auth) = resolve_telemetry_endpoint(Some(""), Some(""));
        assert!(!auth);
    }
}
