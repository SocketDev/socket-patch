use std::collections::HashMap;

use once_cell::sync::Lazy;
use uuid::Uuid;

use crate::api::client::ApiRoute;
use crate::constants::USER_AGENT;
use crate::utils::env_compat::{is_offline_env, proxy_url_from_env};
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
/// - `VITEST` is `"true"`. Load-bearing downstream dependency, not a relic:
///   socket-cli's vitest integration suite
///   (`packages/cli/test/integration/cli/cmd-patch*.test.mts`) spawns this
///   binary with its inherited environment and sets no
///   `SOCKET_TELEMETRY_DISABLED`, so this gate is the only thing keeping
///   those runs from POSTing telemetry to the public proxy.
/// - `SOCKET_OFFLINE` is `"1"` or `"true"` (airgap mode — the telemetry
///   endpoint is a network call, so honoring `--offline`/`SOCKET_OFFLINE`
///   here keeps every command compliant with the strict-airgap contract)
///
/// Note that the CLI also exposes a `--no-telemetry` flag; when that flag
/// is set the CLI dispatcher sets `SOCKET_TELEMETRY_DISABLED=1` for the
/// duration of the process so this check stays the single source of truth.
pub fn is_telemetry_disabled() -> bool {
    let env_value = std::env::var("SOCKET_TELEMETRY_DISABLED").unwrap_or_default();
    let disabled_via_env = matches!(env_value.as_str(), "1" | "true");
    let vitest = std::env::var("VITEST").unwrap_or_default() == "true";
    disabled_via_env || vitest || is_offline_env()
}

/// Log debug messages when debug mode is enabled.
fn debug_log(message: &str) {
    crate::utils::env_compat::debug_log("telemetry", message);
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
/// Every URL in it is redacted ([`crate::utils::redact::redact_urls_in`]:
/// userinfo, grant tokens, signed query values), and the user's home
/// directory path is replaced with `~` to avoid leaking sensitive file
/// system information.
pub fn sanitize_error_message(message: &str) -> String {
    let message = crate::utils::redact::redact_urls_in(message);
    let message = message.as_ref();
    let Some(home) = home_dir() else {
        return message.to_string();
    };
    let home = home.to_string_lossy();
    // `home_dir()` is `None` with no (absolute) home set, so a set-but-empty
    // HOME never reaches here — replacing `""` would splice `~` between
    // every byte. Trailing separators are trimmed so a `HOME=/home/user/` redaction keeps
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

/// Where a run's telemetry events go, and the bearer they carry: the org
/// API's `/v0/orgs/<slug>/telemetry` with the token, or the public proxy's
/// `/patch/telemetry` anonymously.
///
/// A command that built an [`ApiClient`](crate::api::client::ApiClient)
/// takes this from it ([`Self::for_client`]), so its telemetry follows the
/// run's one [`ApiRoute`] — the same host and org as every API call. Only a
/// command that never builds a client (`list`) uses
/// [`Self::from_credentials`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryAuth {
    url: String,
    /// The bearer token to attach (org endpoint only).
    bearer: Option<String>,
}

impl TelemetryAuth {
    /// The client's route: its org endpoint with its token, or the proxy
    /// endpoint on its (proxy) base URL.
    pub fn for_client(client: &crate::api::client::ApiClient) -> Self {
        let base = client.api_url().trim_end_matches('/');
        match client.route() {
            ApiRoute::Org { slug } => Self {
                url: format!("{base}/v0/orgs/{slug}/telemetry"),
                bearer: client.api_token().cloned(),
            },
            ApiRoute::Proxy => Self::proxy_at(base),
        }
    }

    /// The route for a command without a client, with no network: the org
    /// endpoint only when BOTH a non-empty token and a non-empty org slug
    /// are given (the API base from env → socket-cli config → default, as
    /// client construction resolves it), else the proxy from the
    /// environment. An empty string is treated as absent: a `Some("")` slug
    /// would otherwise build a malformed `/v0/orgs//telemetry` URL and a
    /// `Some("")` token an empty `Bearer ` header.
    pub fn from_credentials(api_token: Option<&str>, org_slug: Option<&str>) -> Self {
        let token = api_token.filter(|t| !t.is_empty());
        let slug = org_slug.filter(|s| !s.is_empty());
        match (token, slug) {
            (Some(token), Some(slug)) => {
                let api_url = crate::utils::socket_cli_config::resolve_api_base_url();
                // Trim trailing slashes like `ApiClient::new` does, so a base
                // URL of `https://host/` doesn't produce a `//v0/...` path.
                let api_url = api_url.trim_end_matches('/');
                Self {
                    url: format!("{api_url}/v0/orgs/{slug}/telemetry"),
                    bearer: Some(token.to_string()),
                }
            }
            _ => Self::proxy_at(&proxy_url_from_env()),
        }
    }

    fn proxy_at(base: &str) -> Self {
        Self {
            url: format!("{}/patch/telemetry", base.trim_end_matches('/')),
            bearer: None,
        }
    }

    /// The endpoint events are POSTed to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether events carry the bearer (org endpoint).
    pub fn is_authenticated(&self) -> bool {
        self.bearer.is_some()
    }
}

/// A telemetry event with its destination resolved, ready to POST. Built
/// synchronously where the event fires (timestamp, env and config reads,
/// the "Sending telemetry" debug line), so sending it inline or from a
/// background task posts the very same request.
struct PreparedSend {
    event: PatchTelemetryEvent,
    url: String,
    /// The bearer token to attach (authenticated endpoint only).
    bearer: Option<String>,
}

/// Address `event` per `auth`.
fn prepare_send(event: PatchTelemetryEvent, auth: &TelemetryAuth) -> PreparedSend {
    debug_log(&format!("Sending telemetry to {}", auth.url));
    PreparedSend {
        event,
        url: auth.url.clone(),
        bearer: auth.bearer.clone(),
    }
}

/// Send a telemetry event to the API.
///
/// This is fire-and-forget: errors are logged in debug mode but never
/// propagated. Uses `reqwest` with a 5-second request timeout and a
/// 2-second connect timeout: a command awaits every send before it exits
/// (inline, or via [`PendingTelemetry::flush`]), so a network that
/// blackholes the endpoint (dropped SYNs, no RST) must give up on the
/// handshake quickly rather than stall even a read-only `scan --json` for
/// the full request budget.
async fn send_telemetry_event(prepared: PreparedSend) {
    let PreparedSend { event, url, bearer } = prepared;

    let client = match reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(2))
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

    if let Some(token) = bearer {
        request = request.header("Authorization", format!("Bearer {token}"));
    }

    match request.json(&event).send().await {
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

/// Telemetry sends a command started off its critical path. Each send is
/// spawned where its event fires (the event is built right there, so its
/// body and timestamp are what an inline send would have posted) and the
/// command awaits [`Self::flush`] before its first stdout write after that
/// point — the send overlaps only the work in between, and is delivered (or
/// given up on within the same 2 s connect / 5 s request budget) before
/// any output that could raise SIGPIPE, and before any prompt a Ctrl-C
/// could interrupt, exactly as an inline send was.
///
/// One `--debug`-only difference is inherent to the overlap and accepted:
/// the "Sending telemetry to …" line still prints where the event fires,
/// but its "Telemetry sent successfully" twin now prints where the send
/// finishes (by [`Self::flush`] at the latest), so the two are no longer
/// adjacent — whatever the run did in between sits between them. Each
/// line is still one atomic `eprintln!`, and no other stream is affected.
#[derive(Debug, Default)]
pub struct PendingTelemetry {
    sends: Vec<tokio::task::JoinHandle<()>>,
}

impl PendingTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Await every send started so far, in start order. Idempotent: a
    /// second flush with nothing started since returns at once.
    pub async fn flush(&mut self) {
        for send in std::mem::take(&mut self.sends) {
            // A send never panics on its own; a JoinError here can only be
            // a runtime shutting down, which leaves nothing to deliver.
            let _ = send.await;
        }
    }

    fn spawn(&mut self, prepared: PreparedSend) {
        self.sends
            .push(tokio::spawn(send_telemetry_event(prepared)));
    }

    /// [`Self::spawn`] a prepared event, or do nothing when telemetry is
    /// disabled (`prepare` returned `None`).
    fn spawn_prepared(&mut self, prepared: Option<PreparedSend>) {
        if let Some(prepared) = prepared {
            self.spawn(prepared);
        }
    }
}

// ---------------------------------------------------------------------------
// Per-event tracker wrappers (the public API)
//
// Each takes the run's `TelemetryAuth` (see `TelemetryAuth::for_client`).
// ---------------------------------------------------------------------------

/// Build the event the tracker wrappers below send, or `None` when
/// telemetry is disabled via environment variables. `metadata` is a
/// `serde_json::json!({...})` object; non-object / empty values are dropped
/// to avoid `.unwrap()` noise at every call site.
fn prepare(
    event_type: PatchTelemetryEventType,
    command: &'static str,
    metadata: serde_json::Value,
    error: Option<impl std::fmt::Display>,
    auth: &TelemetryAuth,
) -> Option<PreparedSend> {
    if is_telemetry_disabled() {
        debug_log("Telemetry is disabled, skipping event");
        return None;
    }

    let metadata = match metadata {
        serde_json::Value::Object(map) if !map.is_empty() => Some(map.into_iter().collect()),
        _ => None,
    };
    let error = error.map(|e| ("Error".to_string(), e.to_string()));
    let event = build_telemetry_event(event_type, command, metadata, error);
    Some(prepare_send(event, auth))
}

/// Shared fire-and-forget helper for the per-event tracker wrappers below.
///
/// Never returns errors: telemetry failures are logged in debug mode but
/// do not affect CLI operation. Returns immediately when telemetry is
/// disabled via environment variables.
async fn fire(
    event_type: PatchTelemetryEventType,
    command: &'static str,
    metadata: serde_json::Value,
    error: Option<impl std::fmt::Display>,
    auth: &TelemetryAuth,
) {
    fire_prepared(prepare(event_type, command, metadata, error, auth)).await;
}

/// Send a prepared event inline, or return at once when telemetry is
/// disabled (`prepare` returned `None`).
async fn fire_prepared(prepared: Option<PreparedSend>) {
    if let Some(prepared) = prepared {
        send_telemetry_event(prepared).await;
    }
}

/// Track a successful patch application.
pub async fn track_patch_applied(patches_count: usize, dry_run: bool, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchApplied,
        "apply",
        serde_json::json!({ "patches_count": patches_count, "dry_run": dry_run }),
        None::<&str>,
        auth,
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
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchApplyFailed,
        "apply",
        serde_json::json!({ "dry_run": dry_run }),
        Some(error),
        auth,
    )
    .await;
}

/// Track a successful vendor run (count = packages vendored).
pub async fn track_patch_vendored(vendored_count: u32, dry_run: bool, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchVendored,
        "vendor",
        serde_json::json!({ "patches_count": vendored_count, "dry_run": dry_run }),
        None::<&str>,
        auth,
    )
    .await;
}

/// Track a failed vendor run.
pub async fn track_patch_vendor_failed(
    error: impl std::fmt::Display,
    dry_run: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchVendorFailed,
        "vendor",
        serde_json::json!({ "dry_run": dry_run }),
        Some(error),
        auth,
    )
    .await;
}

/// Track a successful patch removal.
pub async fn track_patch_removed(removed_count: usize, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRemoved,
        "remove",
        serde_json::json!({ "removed_count": removed_count }),
        None::<&str>,
        auth,
    )
    .await;
}

/// Track a failed patch removal. Accepts any `Display` type for the error.
pub async fn track_patch_remove_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRemoveFailed,
        "remove",
        serde_json::Value::Null,
        Some(error),
        auth,
    )
    .await;
}

/// Track a successful patch rollback.
pub async fn track_patch_rolled_back(rolled_back_count: usize, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRolledBack,
        "rollback",
        serde_json::json!({ "rolled_back_count": rolled_back_count }),
        None::<&str>,
        auth,
    )
    .await;
}

/// Track a failed patch rollback. Accepts any `Display` type for the error.
pub async fn track_patch_rollback_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRollbackFailed,
        "rollback",
        serde_json::Value::Null,
        Some(error),
        auth,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Read-side trackers: scan + get
// ---------------------------------------------------------------------------

/// The whole `patch_scanned` event — type, command and metadata (per-tier
/// patch counts and whether the call was downgraded to the public proxy
/// after an auth-endpoint 401/403). Both wrappers below build their event
/// here, so the inline and background paths can never drift apart.
#[allow(clippy::too_many_arguments)]
fn prepare_patch_scanned(
    packages_scanned: usize,
    free_patches: usize,
    paid_patches: usize,
    can_access_paid: bool,
    ecosystems: &[String],
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) -> Option<PreparedSend> {
    prepare(
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
        auth,
    )
}

/// Track a successful `scan`. Reports per-tier patch counts and whether
/// the call was downgraded to the public proxy after an auth-endpoint
/// 401/403 (`fallback_to_proxy`).
///
/// The argument count intentionally mirrors the metadata fields the
/// dashboard needs — grouping them into a struct would force callers
/// to build a config object for a single fire-and-forget call, which
/// is worse ergonomics for a tracker.
///
/// The CLI's `scan` sends this event through [`spawn_patch_scanned`]; the
/// inline tracker stays as this published crate's public API, alongside
/// the inline tracker every other event has. Both build the event with
/// [`prepare_patch_scanned`], so neither can describe it differently.
#[allow(clippy::too_many_arguments)]
pub async fn track_patch_scanned(
    packages_scanned: usize,
    free_patches: usize,
    paid_patches: usize,
    can_access_paid: bool,
    ecosystems: &[String],
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    fire_prepared(prepare_patch_scanned(
        packages_scanned,
        free_patches,
        paid_patches,
        can_access_paid,
        ecosystems,
        fallback_to_proxy,
        auth,
    ))
    .await;
}

/// [`track_patch_scanned`], sent in the background: the event is built
/// now and its send joins `pending`, which the command flushes before it
/// returns.
#[allow(clippy::too_many_arguments)]
pub fn spawn_patch_scanned(
    pending: &mut PendingTelemetry,
    packages_scanned: usize,
    free_patches: usize,
    paid_patches: usize,
    can_access_paid: bool,
    ecosystems: &[String],
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    pending.spawn_prepared(prepare_patch_scanned(
        packages_scanned,
        free_patches,
        paid_patches,
        can_access_paid,
        ecosystems,
        fallback_to_proxy,
        auth,
    ));
}

/// The whole `patch_scan_failed` event (see [`prepare_patch_scanned`]).
fn prepare_patch_scan_failed(
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) -> Option<PreparedSend> {
    prepare(
        PatchTelemetryEventType::PatchScanFailed,
        "scan",
        serde_json::json!({ "fallback_to_proxy": fallback_to_proxy }),
        Some(error),
        auth,
    )
}

/// Track a failed `scan`. The CLI sends it through
/// [`spawn_patch_scan_failed`]; kept as public API like
/// [`track_patch_scanned`].
pub async fn track_patch_scan_failed(
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    fire_prepared(prepare_patch_scan_failed(error, fallback_to_proxy, auth)).await;
}

/// [`track_patch_scan_failed`], sent in the background (see
/// [`spawn_patch_scanned`]).
pub fn spawn_patch_scan_failed(
    pending: &mut PendingTelemetry,
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    pending.spawn_prepared(prepare_patch_scan_failed(error, fallback_to_proxy, auth));
}

/// Track a successful `get`. Reports patch identity and whether the call
/// was downgraded to the public proxy after an auth-endpoint 401/403.
/// `download_mode` is always `"file"`: v5 fetches patch content only as
/// per-file blobs, and the field stays so the event schema is unchanged.
pub async fn track_patch_fetched(
    uuid: &str,
    tier: &str,
    ecosystem: &str,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchFetched,
        "get",
        serde_json::json!({
            "uuid": uuid,
            "tier": tier,
            "ecosystem": ecosystem,
            "download_mode": "file",
            "fallback_to_proxy": fallback_to_proxy,
        }),
        None::<&str>,
        auth,
    )
    .await;
}

/// The `uuid` a `patch_fetch_failed` event reports: `identifier` when it
/// is a patch uuid, else empty. `get` passes whatever the user asked for
/// (a CVE, a GHSA, a purl, a private package name), and only a uuid
/// belongs in that field.
fn fetch_failed_uuid(identifier: &str) -> &str {
    if crate::patch::path_safety::is_canonical_uuid(&identifier.to_ascii_lowercase()) {
        identifier
    } else {
        ""
    }
}

/// Track a failed `get`. `uuid` may be empty when the failure occurred
/// before the patch was resolved (e.g. lookup miss); anything that is not
/// a uuid is reported as empty.
pub async fn track_patch_fetch_failed(
    uuid: &str,
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchFetchFailed,
        "get",
        serde_json::json!({
            "uuid": fetch_failed_uuid(uuid),
            "fallback_to_proxy": fallback_to_proxy
        }),
        Some(error),
        auth,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Inspection / housekeeping trackers: list / repair
// ---------------------------------------------------------------------------

/// Track a successful `list`. Reports the number of patches surfaced.
pub async fn track_patch_listed(patches_count: usize, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchListed,
        "list",
        serde_json::json!({ "patches_count": patches_count }),
        None::<&str>,
        auth,
    )
    .await;
}

/// Track a successful `repair`. Reports blob deltas and bytes freed.
pub async fn track_patch_repaired(
    blobs_added: usize,
    blobs_removed: usize,
    bytes_freed: u64,
    auth: &TelemetryAuth,
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
        auth,
    )
    .await;
}

/// Track a failed `repair`.
pub async fn track_patch_repair_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRepairFailed,
        "repair",
        serde_json::Value::Null,
        Some(error),
        auth,
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
    auth: &TelemetryAuth,
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
        auth,
    )
    .await;
}

/// Track a failed `vex` generation.
pub async fn track_vex_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::VexFailed,
        "vex",
        serde_json::Value::Null,
        Some(error),
        auth,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A prepared event posted to `server`'s `/telemetry` route.
    fn prepared_for(server: &wiremock::MockServer) -> PreparedSend {
        let mut metadata = HashMap::new();
        metadata.insert("packages_scanned".to_string(), serde_json::json!(3));
        PreparedSend {
            event: build_telemetry_event(
                PatchTelemetryEventType::PatchScanned,
                "scan",
                Some(metadata),
                None,
            ),
            url: format!("{}/telemetry", server.uri()),
            bearer: Some("tok".to_string()),
        }
    }

    /// A background send posts exactly the request an inline send posts
    /// (same body bytes and headers), and is delivered by `flush`.
    #[tokio::test]
    async fn background_send_posts_the_inline_request_and_flush_delivers_it() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/telemetry"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let prepared = prepared_for(&server);
        let twin = PreparedSend {
            event: prepared.event.clone(),
            url: prepared.url.clone(),
            bearer: prepared.bearer.clone(),
        };
        send_telemetry_event(prepared).await;
        let mut pending = PendingTelemetry::new();
        pending.spawn(twin);
        pending.flush().await;

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].body, reqs[1].body);
        for req in &reqs {
            assert_eq!(req.headers.get("authorization").unwrap(), "Bearer tok");
            assert_eq!(req.headers.get("user-agent").unwrap(), USER_AGENT);
            assert_eq!(req.headers.get("content-type").unwrap(), "application/json");
        }
    }

    /// Spawning returns at once; `flush` waits for the slow responses.
    #[tokio::test]
    async fn spawn_does_not_block_and_flush_waits_for_the_response() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let delay = std::time::Duration::from_millis(400);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_delay(delay))
            .mount(&server)
            .await;

        let mut pending = PendingTelemetry::new();
        pending.spawn(prepared_for(&server));
        pending.spawn(prepared_for(&server));
        // Nothing was awaited yet: both sends are still in flight.
        assert_eq!(pending.sends.len(), 2);
        assert!(pending.sends.iter().all(|s| !s.is_finished()));
        let started = std::time::Instant::now();
        pending.flush().await;
        assert!(started.elapsed() >= delay, "flush must await the responses");
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// Nothing started, nothing to wait for.
    #[tokio::test]
    async fn flushing_nothing_returns() {
        PendingTelemetry::new().flush().await;
    }

    /// Scan flushes at each output point after a send fires, so `flush`
    /// drains: a later flush waits only for sends started since, and the
    /// exit backstop after an early flush has nothing left to wait for.
    #[tokio::test]
    async fn flush_drains_and_later_sends_join_the_next_flush() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let mut pending = PendingTelemetry::new();
        pending.spawn(prepared_for(&server));
        pending.flush().await;
        assert!(pending.sends.is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        pending.flush().await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        pending.spawn(prepared_for(&server));
        pending.flush().await;
        assert!(pending.sends.is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// `scan`'s two events each have an inline tracker (this crate's public
    /// API) and a background twin the CLI calls. Both must describe the
    /// event identically — same event type, command and metadata — or a
    /// rename would silently reach only one of them. Serialized: the
    /// endpoint and the disable gate are read from process-global env.
    #[tokio::test]
    #[serial_test::serial]
    async fn inline_and_background_scan_trackers_post_the_same_event() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        /// The request body with only its timestamp dropped (the session
        /// id is process-global, so it matches).
        fn descriptor(body: &[u8]) -> serde_json::Value {
            let mut v: serde_json::Value = serde_json::from_slice(body).expect("event json");
            v.as_object_mut()
                .expect("event object")
                .remove("event_sender_created_at")
                .expect("every event is timestamped");
            v
        }

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/patch/telemetry"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let saved: Vec<(&str, Option<String>)> = [
            "SOCKET_PROXY_URL",
            "SOCKET_TELEMETRY_DISABLED",
            "SOCKET_OFFLINE",
            "VITEST",
        ]
        .iter()
        .map(|&k| (k, std::env::var(k).ok()))
        .collect();
        for (key, _) in &saved {
            std::env::remove_var(key);
        }
        std::env::set_var("SOCKET_PROXY_URL", server.uri());

        // No token / org: both events go to the proxy endpoint above.
        let ecosystems = vec!["npm".to_string(), "pypi".to_string()];
        let auth = TelemetryAuth::from_credentials(None, None);
        let mut pending = PendingTelemetry::new();
        track_patch_scanned(5, 3, 2, true, &ecosystems, true, &auth).await;
        spawn_patch_scanned(&mut pending, 5, 3, 2, true, &ecosystems, true, &auth);
        pending.flush().await;
        track_patch_scan_failed("all batches failed", true, &auth).await;
        spawn_patch_scan_failed(&mut pending, "all batches failed", true, &auth);
        pending.flush().await;

        for (key, value) in saved {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }

        let bodies: Vec<serde_json::Value> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| descriptor(&r.body))
            .collect();
        assert_eq!(bodies.len(), 4, "two events, two paths each");
        assert_eq!(bodies[0], bodies[1], "patch_scanned inline vs background");
        assert_eq!(
            bodies[2], bodies[3],
            "patch_scan_failed inline vs background"
        );
        assert_eq!(bodies[0]["event_type"], "patch_scanned");
        assert_eq!(bodies[0]["context"]["command"], "scan");
        assert_eq!(bodies[0]["metadata"]["free_patches"], 3);
        assert_eq!(bodies[2]["event_type"], "patch_scan_failed");
        assert_eq!(bodies[2]["context"]["command"], "scan");
        assert_eq!(bodies[2]["error"]["message"], "all batches failed");
    }

    /// Combined into a single test to avoid env-var races across parallel tests.
    /// Exercises the `SOCKET_TELEMETRY_DISABLED` name and the airgap gate
    /// via `SOCKET_OFFLINE`. Serialized: SOCKET_* env is process-global and the
    /// api/client.rs suite reads `SOCKET_OFFLINE` mid-test.
    #[test]
    #[serial_test::serial]
    fn test_is_telemetry_disabled() {
        // Save originals
        let orig_new = std::env::var("SOCKET_TELEMETRY_DISABLED").ok();
        let orig_vitest = std::env::var("VITEST").ok();
        let orig_offline = std::env::var("SOCKET_OFFLINE").ok();

        // Default: not disabled
        std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
        std::env::remove_var("VITEST");
        std::env::remove_var("SOCKET_OFFLINE");
        assert!(!is_telemetry_disabled());

        // Disabled via new var "1"
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", "1");
        assert!(is_telemetry_disabled());
        std::env::remove_var("SOCKET_TELEMETRY_DISABLED");

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

    /// B26: an error that quotes a grant URL or a credentialed registry URL
    /// (reqwest's own text does) reaches telemetry redacted.
    #[test]
    fn sanitize_error_message_redacts_urls() {
        let uuid = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
        let msg = format!(
            "artifact not found: https://patch.socket.dev/patch/npm/a/1.0.0/GRANT/{uuid}/a.tgz; \
             error sending request for url (https://bot:hunter2@goproxy.corp/m/@v/v1.zip)"
        );
        let sanitized = sanitize_error_message(&msg);
        assert!(!sanitized.contains("GRANT"), "{sanitized}");
        assert!(!sanitized.contains("hunter2"), "{sanitized}");
        assert!(
            sanitized.contains(uuid) && sanitized.contains("goproxy.corp"),
            "{sanitized}"
        );
    }

    /// B26: `patch_fetch_failed` reports a uuid only; a CVE, purl or private
    /// package name the user asked `get` for is not sent.
    #[test]
    fn fetch_failed_uuid_only_reports_uuids() {
        let uuid = "7c8d9e0f-1a2b-4a1b-8c2d-3e4f5a6b7c8d";
        assert_eq!(fetch_failed_uuid(uuid), uuid);
        assert_eq!(
            fetch_failed_uuid("7C8D9E0F-1A2B-4A1B-8C2D-3E4F5A6B7C8D"),
            "7C8D9E0F-1A2B-4A1B-8C2D-3E4F5A6B7C8D"
        );
        for identifier in ["@acme/internal-lib", "CVE-2021-44906", "pkg:npm/x@1", ""] {
            assert_eq!(fetch_failed_uuid(identifier), "", "{identifier}");
        }
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
        // A hardcoded "1.0.0" literal must never appear unless the crate is
        // genuinely at that version.
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

    /// [`TelemetryAuth::from_credentials`] as `(url, authenticated)`.
    fn resolve_telemetry_endpoint(token: Option<&str>, slug: Option<&str>) -> (String, bool) {
        let auth = TelemetryAuth::from_credentials(token, slug);
        (auth.url().to_string(), auth.is_authenticated())
    }

    /// A client's telemetry follows its route: the org endpoint on the
    /// client's own base with its bearer, or the proxy endpoint on the
    /// proxy client's base (an explicit `--proxy-url`) without one. No env
    /// lookup is involved.
    #[test]
    fn for_client_follows_the_clients_route() {
        use crate::api::client::{ApiClient, ApiClientOptions};
        let org = ApiClient::new(ApiClientOptions {
            api_url: "https://api.example.test/".into(),
            api_token: Some("tok".into()),
            route: ApiRoute::org("acme"),
        });
        let auth = TelemetryAuth::for_client(&org);
        assert_eq!(
            auth.url(),
            "https://api.example.test/v0/orgs/acme/telemetry"
        );
        assert!(auth.is_authenticated());

        let proxy = ApiClient::new(ApiClientOptions {
            api_url: "https://proxy.example.test".into(),
            api_token: Some("tok".into()),
            route: ApiRoute::Proxy,
        });
        let auth = TelemetryAuth::for_client(&proxy);
        assert_eq!(auth.url(), "https://proxy.example.test/patch/telemetry");
        assert!(!auth.is_authenticated(), "the proxy never gets the bearer");
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
    /// Serialized: SOCKET_* env is process-global and the api/client.rs suite
    /// mutates `SOCKET_PROXY_URL` mid-test.
    #[test]
    #[serial_test::serial]
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
