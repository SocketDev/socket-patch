use std::collections::HashMap;

use once_cell::sync::Lazy;
use uuid::Uuid;

use crate::constants::{DEFAULT_PATCH_API_PROXY_URL, DEFAULT_SOCKET_API_URL, USER_AGENT};

// ---------------------------------------------------------------------------
// Session ID — generated once per process invocation
// ---------------------------------------------------------------------------

/// Unique session ID for the current CLI invocation.
/// Shared across all telemetry events in a single run.
static SESSION_ID: Lazy<String> = Lazy::new(|| Uuid::new_v4().to_string());

/// Package version — updated during build.
const PACKAGE_VERSION: &str = "1.0.0";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Telemetry event types for the patch lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchTelemetryEventType {
    PatchApplied,
    PatchApplyFailed,
    PatchRemoved,
    PatchRemoveFailed,
    PatchRolledBack,
    PatchRollbackFailed,
}

impl PatchTelemetryEventType {
    /// Return the wire-format string for this event type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PatchApplied => "patch_applied",
            Self::PatchApplyFailed => "patch_apply_failed",
            Self::PatchRemoved => "patch_removed",
            Self::PatchRemoveFailed => "patch_remove_failed",
            Self::PatchRolledBack => "patch_rolled_back",
            Self::PatchRollbackFailed => "patch_rollback_failed",
        }
    }
}

/// Telemetry context describing the execution environment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PatchTelemetryContext {
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub command: String,
}

/// Error details for telemetry events.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PatchTelemetryError {
    #[serde(rename = "type")]
    pub error_type: String,
    pub message: Option<String>,
}

/// Telemetry event structure for patch operations.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PatchTelemetryEvent {
    pub event_sender_created_at: String,
    pub event_type: String,
    pub context: PatchTelemetryContext,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<PatchTelemetryError>,
}

/// Options for tracking a patch event.
pub struct TrackPatchEventOptions {
    /// The type of event being tracked.
    pub event_type: PatchTelemetryEventType,
    /// The CLI command being executed (e.g., "apply", "remove", "rollback").
    pub command: String,
    /// Optional metadata to include with the event.
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// Optional error information if the operation failed.
    /// Tuple of (error_type, message).
    pub error: Option<(String, String)>,
    /// Optional API token for authenticated telemetry endpoint.
    pub api_token: Option<String>,
    /// Optional organization slug for authenticated telemetry endpoint.
    pub org_slug: Option<String>,
}

// ---------------------------------------------------------------------------
// Environment checks
// ---------------------------------------------------------------------------

/// Check if telemetry is disabled via environment variables.
///
/// Telemetry is disabled when:
/// - `SOCKET_PATCH_TELEMETRY_DISABLED` is `"1"` or `"true"`
/// - `VITEST` is `"true"` (test environment)
pub fn is_telemetry_disabled() -> bool {
    matches!(
        std::env::var("SOCKET_PATCH_TELEMETRY_DISABLED")
            .unwrap_or_default()
            .as_str(),
        "1" | "true"
    ) || std::env::var("VITEST").unwrap_or_default() == "true"
}

/// Check if debug mode is enabled.
fn is_debug_enabled() -> bool {
    matches!(
        std::env::var("SOCKET_PATCH_DEBUG")
            .unwrap_or_default()
            .as_str(),
        "1" | "true"
    )
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
    if let Some(home) = home_dir_string() {
        if !home.is_empty() {
            return message.replace(&home, "~");
        }
    }
    message.to_string()
}

/// Get the home directory as a string.
fn home_dir_string() -> Option<String> {
    std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())
}

/// Build a telemetry event from the given options.
fn build_telemetry_event(options: &TrackPatchEventOptions) -> PatchTelemetryEvent {
    let error = options.error.as_ref().map(|(error_type, message)| {
        PatchTelemetryError {
            error_type: error_type.clone(),
            message: Some(sanitize_error_message(message)),
        }
    });

    PatchTelemetryEvent {
        event_sender_created_at: chrono_now_iso(),
        event_type: options.event_type.as_str().to_string(),
        context: build_telemetry_context(&options.command),
        session_id: SESSION_ID.clone(),
        metadata: options.metadata.clone(),
        error,
    }
}

/// Get the current time as an ISO 8601 string.
fn chrono_now_iso() -> String {
    let now = std::time::SystemTime::now();
    let duration = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();

    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    let millis = duration.subsec_millis();

    let (year, month, day) = days_to_ymd(days);

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z"
    )
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Adapted from Howard Hinnant's civil_from_days algorithm
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u64, m, d)
}

// ---------------------------------------------------------------------------
// Send event
// ---------------------------------------------------------------------------

/// Send a telemetry event to the API.
///
/// This is fire-and-forget: errors are logged in debug mode but never
/// propagated. Uses `reqwest` with a 5-second timeout.
async fn send_telemetry_event(
    event: &PatchTelemetryEvent,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    let (url, use_auth) = match (api_token, org_slug) {
        (Some(_token), Some(slug)) => {
            let api_url = std::env::var("SOCKET_API_URL")
                .unwrap_or_else(|_| DEFAULT_SOCKET_API_URL.to_string());
            (format!("{api_url}/v0/orgs/{slug}/telemetry"), true)
        }
        _ => {
            let proxy_url = std::env::var("SOCKET_PATCH_PROXY_URL")
                .unwrap_or_else(|_| DEFAULT_PATCH_API_PROXY_URL.to_string());
            (format!("{proxy_url}/patch/telemetry"), false)
        }
    };

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
// Public API
// ---------------------------------------------------------------------------

/// Track a patch lifecycle event.
///
/// This function is non-blocking and will never return errors. Telemetry
/// failures are logged in debug mode but do not affect CLI operation.
///
/// If telemetry is disabled (via environment variables), the function returns
/// immediately.
pub async fn track_patch_event(options: TrackPatchEventOptions) {
    if is_telemetry_disabled() {
        debug_log("Telemetry is disabled, skipping event");
        return;
    }

    let event = build_telemetry_event(&options);
    send_telemetry_event(
        &event,
        options.api_token.as_deref(),
        options.org_slug.as_deref(),
    )
    .await;
}

/// Fire-and-forget version of `track_patch_event` that spawns the request
/// on a background task so it never blocks the caller.
pub fn track_patch_event_fire_and_forget(options: TrackPatchEventOptions) {
    if is_telemetry_disabled() {
        debug_log("Telemetry is disabled, skipping event");
        return;
    }

    let event = build_telemetry_event(&options);
    let api_token = options.api_token.clone();
    let org_slug = options.org_slug.clone();

    tokio::spawn(async move {
        send_telemetry_event(&event, api_token.as_deref(), org_slug.as_deref()).await;
    });
}

// ---------------------------------------------------------------------------
// Convenience functions
//
// These accept `Option<&str>` for api_token/org_slug to make call sites
// convenient (callers typically have `Option<String>` and call `.as_deref()`).
// ---------------------------------------------------------------------------

/// Track a successful patch application.
pub async fn track_patch_applied(
    patches_count: usize,
    dry_run: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    let mut metadata = HashMap::new();
    metadata.insert(
        "patches_count".to_string(),
        serde_json::Value::Number(serde_json::Number::from(patches_count)),
    );
    metadata.insert("dry_run".to_string(), serde_json::Value::Bool(dry_run));

    track_patch_event(TrackPatchEventOptions {
        event_type: PatchTelemetryEventType::PatchApplied,
        command: "apply".to_string(),
        metadata: Some(metadata),
        error: None,
        api_token: api_token.map(|s| s.to_string()),
        org_slug: org_slug.map(|s| s.to_string()),
    })
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
    let mut metadata = HashMap::new();
    metadata.insert("dry_run".to_string(), serde_json::Value::Bool(dry_run));

    track_patch_event(TrackPatchEventOptions {
        event_type: PatchTelemetryEventType::PatchApplyFailed,
        command: "apply".to_string(),
        metadata: Some(metadata),
        error: Some(("Error".to_string(), error.to_string())),
        api_token: api_token.map(|s| s.to_string()),
        org_slug: org_slug.map(|s| s.to_string()),
    })
    .await;
}

/// Track a successful patch removal.
pub async fn track_patch_removed(
    removed_count: usize,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    let mut metadata = HashMap::new();
    metadata.insert(
        "removed_count".to_string(),
        serde_json::Value::Number(serde_json::Number::from(removed_count)),
    );

    track_patch_event(TrackPatchEventOptions {
        event_type: PatchTelemetryEventType::PatchRemoved,
        command: "remove".to_string(),
        metadata: Some(metadata),
        error: None,
        api_token: api_token.map(|s| s.to_string()),
        org_slug: org_slug.map(|s| s.to_string()),
    })
    .await;
}

/// Track a failed patch removal.
///
/// Accepts any `Display` type for the error.
pub async fn track_patch_remove_failed(
    error: impl std::fmt::Display,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    track_patch_event(TrackPatchEventOptions {
        event_type: PatchTelemetryEventType::PatchRemoveFailed,
        command: "remove".to_string(),
        metadata: None,
        error: Some(("Error".to_string(), error.to_string())),
        api_token: api_token.map(|s| s.to_string()),
        org_slug: org_slug.map(|s| s.to_string()),
    })
    .await;
}

/// Track a successful patch rollback.
pub async fn track_patch_rolled_back(
    rolled_back_count: usize,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    let mut metadata = HashMap::new();
    metadata.insert(
        "rolled_back_count".to_string(),
        serde_json::Value::Number(serde_json::Number::from(rolled_back_count)),
    );

    track_patch_event(TrackPatchEventOptions {
        event_type: PatchTelemetryEventType::PatchRolledBack,
        command: "rollback".to_string(),
        metadata: Some(metadata),
        error: None,
        api_token: api_token.map(|s| s.to_string()),
        org_slug: org_slug.map(|s| s.to_string()),
    })
    .await;
}

/// Track a failed patch rollback.
///
/// Accepts any `Display` type for the error.
pub async fn track_patch_rollback_failed(
    error: impl std::fmt::Display,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    track_patch_event(TrackPatchEventOptions {
        event_type: PatchTelemetryEventType::PatchRollbackFailed,
        command: "rollback".to_string(),
        metadata: None,
        error: Some(("Error".to_string(), error.to_string())),
        api_token: api_token.map(|s| s.to_string()),
        org_slug: org_slug.map(|s| s.to_string()),
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Combined into a single test to avoid env-var races across parallel tests.
    #[test]
    fn test_is_telemetry_disabled() {
        // Save originals
        let orig_disabled = std::env::var("SOCKET_PATCH_TELEMETRY_DISABLED").ok();
        let orig_vitest = std::env::var("VITEST").ok();

        // Default: not disabled
        std::env::remove_var("SOCKET_PATCH_TELEMETRY_DISABLED");
        std::env::remove_var("VITEST");
        assert!(!is_telemetry_disabled());

        // Disabled via "1"
        std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", "1");
        assert!(is_telemetry_disabled());

        // Disabled via "true"
        std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", "true");
        assert!(is_telemetry_disabled());

        // Restore originals
        match orig_disabled {
            Some(v) => std::env::set_var("SOCKET_PATCH_TELEMETRY_DISABLED", v),
            None => std::env::remove_var("SOCKET_PATCH_TELEMETRY_DISABLED"),
        }
        match orig_vitest {
            Some(v) => std::env::set_var("VITEST", v),
            None => std::env::remove_var("VITEST"),
        }
    }

    #[test]
    fn test_sanitize_error_message() {
        let home = home_dir_string().unwrap_or_else(|| "/home/testuser".to_string());
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
        assert_eq!(PatchTelemetryEventType::PatchApplied.as_str(), "patch_applied");
        assert_eq!(
            PatchTelemetryEventType::PatchApplyFailed.as_str(),
            "patch_apply_failed"
        );
        assert_eq!(PatchTelemetryEventType::PatchRemoved.as_str(), "patch_removed");
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
    }

    #[test]
    fn test_build_telemetry_context() {
        let ctx = build_telemetry_context("apply");
        assert_eq!(ctx.command, "apply");
        assert_eq!(ctx.version, PACKAGE_VERSION);
        assert!(!ctx.platform.is_empty());
        assert!(!ctx.arch.is_empty());
    }

    #[test]
    fn test_build_telemetry_event_basic() {
        let options = TrackPatchEventOptions {
            event_type: PatchTelemetryEventType::PatchApplied,
            command: "apply".to_string(),
            metadata: None,
            error: None,
            api_token: None,
            org_slug: None,
        };

        let event = build_telemetry_event(&options);
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

        let options = TrackPatchEventOptions {
            event_type: PatchTelemetryEventType::PatchApplied,
            command: "apply".to_string(),
            metadata: Some(metadata),
            error: None,
            api_token: None,
            org_slug: None,
        };

        let event = build_telemetry_event(&options);
        assert!(event.metadata.is_some());
        let meta = event.metadata.unwrap();
        assert_eq!(
            meta.get("patches_count").unwrap(),
            &serde_json::Value::Number(5.into())
        );
    }

    #[test]
    fn test_build_telemetry_event_with_error() {
        let options = TrackPatchEventOptions {
            event_type: PatchTelemetryEventType::PatchApplyFailed,
            command: "apply".to_string(),
            metadata: None,
            error: Some(("IoError".to_string(), "file not found".to_string())),
            api_token: None,
            org_slug: None,
        };

        let event = build_telemetry_event(&options);
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

    #[test]
    fn test_days_to_ymd_epoch() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn test_days_to_ymd_known_date() {
        // 2024-01-01 is day 19723
        let (y, m, d) = days_to_ymd(19723);
        assert_eq!((y, m, d), (2024, 1, 1));
    }
}
