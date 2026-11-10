use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use once_cell::sync::Lazy;
use uuid::Uuid;

use crate::api::client::ApiRoute;
use crate::constants::USER_AGENT;
use crate::utils::env_compat::{is_offline_env, proxy_url_from_env};
use crate::utils::fs::home_dir;
use crate::utils::socket_cli_config::env_truthy;
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
    // Self-update (`socket-patch --update`)
    CliUpdated,
    CliUpdateFailed,
}

impl PatchTelemetryEventType {
    /// Every variant, for the backend-contract test.
    #[cfg(test)]
    const ALL: [Self; 19] = [
        Self::PatchApplied,
        Self::PatchApplyFailed,
        Self::PatchRemoved,
        Self::PatchRemoveFailed,
        Self::PatchRolledBack,
        Self::PatchRollbackFailed,
        Self::PatchScanned,
        Self::PatchScanFailed,
        Self::PatchFetched,
        Self::PatchFetchFailed,
        Self::PatchVendored,
        Self::PatchVendorFailed,
        Self::PatchListed,
        Self::PatchRepaired,
        Self::PatchRepairFailed,
        Self::VexGenerated,
        Self::VexFailed,
        Self::CliUpdated,
        Self::CliUpdateFailed,
    ];

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
            Self::CliUpdated => "cli_updated",
            Self::CliUpdateFailed => "cli_update_failed",
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
/// Telemetry is disabled when any of these holds:
/// - `SOCKET_TELEMETRY_DISABLED` is truthy ([`env_truthy`], the vocabulary
///   the CLI's boolean flags accept: a library caller's `=yes` opts out
///   just as the CLI's does).
/// - `SOCKET_PATCH_TELEMETRY_DISABLED` is truthy. The v3/v4 name; the other
///   names of that generation are retired, but an opt-out has to survive
///   the upgrade that renamed it.
/// - `DO_NOT_TRACK` is set to anything but `0`, `false` or the empty
///   string: the cross-tool convention (<https://consoledonottrack.com>).
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
    env_truthy("SOCKET_TELEMETRY_DISABLED")
        || env_truthy("SOCKET_PATCH_TELEMETRY_DISABLED")
        || do_not_track()
        || std::env::var("VITEST").unwrap_or_default() == "true"
        || is_offline_env()
}

/// Whether `DO_NOT_TRACK` asks for no telemetry. The convention is "set
/// means on", so unlike a `SOCKET_*` toggle every value counts except an
/// explicit off (`0`, `false`) and the empty string.
fn do_not_track() -> bool {
    let value = std::env::var("DO_NOT_TRACK").unwrap_or_default();
    !matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false"
    )
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
/// A run that built an [`ApiClient`](crate::api::client::ApiClient) takes
/// this from it ([`Self::for_client`]), so its telemetry follows the run's
/// one [`ApiRoute`] — the same host and org as every API call. A run that
/// built none (`list`, or an `apply` that had nothing to fetch) uses
/// [`Self::from_credentials`]: a client is never built, and the org never
/// looked up, only to address an event.
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
/// the "Sending telemetry" debug line); the send itself runs in the
/// background ([`start_send`]).
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

/// POST one telemetry event. Errors are logged in debug mode and never
/// propagated.
///
/// Nothing awaits a send (see [`start_send`]), so the 2-second connect and
/// 5-second request timeouts bound no command. They only end a send that
/// cannot finish (a blackholed endpoint, a host that accepts and stalls)
/// while a long-running command is still at work beside it.
async fn send_telemetry_event(prepared: PreparedSend) {
    let PreparedSend { event, url, bearer } = prepared;

    let client = match crate::utils::http::client_builder()
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

/// The sends this process has started and not yet waited for. Process-wide,
/// like [`SESSION_ID`]: events fire at every depth of a command, and the one
/// place that may wait for them is its exit ([`flush`]).
static IN_FLIGHT: Mutex<Vec<tokio::task::JoinHandle<()>>> = Mutex::new(Vec::new());

fn in_flight() -> std::sync::MutexGuard<'static, Vec<tokio::task::JoinHandle<()>>> {
    // A list of join handles has no invariant a panic could break.
    IN_FLIGHT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Start `prepared`'s send and return at once. The send runs beside
/// whatever the command does next, so no output, prompt or exit status
/// ever waits on the telemetry endpoint; only [`flush`] waits, briefly.
///
/// One `--debug`-only consequence: the "Sending telemetry to …" line
/// prints where the event fires and its "Telemetry sent successfully"
/// twin where the send finishes, with whatever the run printed in between.
fn start_send(prepared: PreparedSend) {
    // A tracker can be reached with no runtime to carry the send: the
    // event is dropped rather than its caller panicked.
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        debug_log("No async runtime to send telemetry on, skipping event");
        return;
    };
    in_flight().push(runtime.spawn(send_telemetry_event(prepared)));
}

/// How long a command's exit waits for telemetry still in flight
/// ([`flush`]).
///
/// A send to a healthy endpoint is a DNS lookup, a TLS connection and one
/// small POST, and it runs beside the command, so only a command that is
/// done sooner than that (`list`, a no-op `apply`) waits here at all. 300 ms
/// lets such a send finish from most networks. It is also the whole cost
/// of an endpoint that never answers — once per process, however many
/// events are in flight — and short enough that a hook running `apply`
/// after every install does not read as stalled.
pub const EXIT_GRACE: Duration = Duration::from_millis(300);

/// Give the sends still in flight up to `grace` to finish, then abandon
/// the rest. For the very end of a process, after all of the command's
/// output: the CLI's `main` calls it with [`EXIT_GRACE`] and exits.
///
/// `grace` bounds the wait whatever the endpoint does (refuses, drops the
/// packets, accepts and stalls) and whatever a send's own timeouts are. A
/// send abandoned here is lost: telemetry is best effort, and a command
/// that has finished does not stay alive for it.
pub async fn flush(grace: Duration) {
    let mut sends = std::mem::take(&mut *in_flight());
    if sends.is_empty() {
        return;
    }
    let finished = async {
        for send in &mut sends {
            // A send never panics on its own; a JoinError here can only be
            // a runtime shutting down, which leaves nothing to deliver.
            let _ = send.await;
        }
    };
    if tokio::time::timeout(grace, finished).await.is_err() {
        let abandoned = sends.iter().filter(|send| !send.is_finished()).count();
        debug_log(&format!(
            "Telemetry not delivered within {grace:?}, abandoning {abandoned} event(s)"
        ));
        for send in &sends {
            send.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Per-event tracker wrappers (the public API)
//
// Each takes the run's `TelemetryAuth` (see `TelemetryAuth::for_client`),
// starts its event's send and returns. They are `async` for their callers'
// sake only: awaiting one never waits on the network.
// ---------------------------------------------------------------------------

/// Build one event and start its send: every tracker below is this call
/// with its event's type, command and metadata. `metadata` is a
/// `serde_json::json!({...})` object; non-object / empty values are dropped
/// to avoid `.unwrap()` noise at every call site.
///
/// Never fails and never waits. An event that is disabled, cannot be sent
/// or is not delivered is at most a debug line; it changes nothing else
/// about the run.
fn fire(
    event_type: PatchTelemetryEventType,
    command: &'static str,
    metadata: serde_json::Value,
    error: Option<impl std::fmt::Display>,
    auth: &TelemetryAuth,
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
    start_send(prepare_send(event, auth));
}

/// Track a successful in-place (agent mode) patch application.
pub async fn track_patch_applied(patches_count: usize, dry_run: bool, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchApplied,
        "apply",
        serde_json::json!({
            "patches_count": patches_count,
            "dry_run": dry_run,
            "mode": "agent",
        }),
        None::<&str>,
        auth,
    );
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
        serde_json::json!({ "dry_run": dry_run, "mode": "agent" }),
        Some(error),
        auth,
    );
}

/// Track a hosted-mode run (`scan`/`get --mode hosted`) that pinned
/// patched dependencies to Socket's hosted patch server. Sent as
/// `patch_applied` with `mode: "hosted"`: the lockfile pin is how hosted
/// mode applies a patch, and the backend's adoption views count
/// `patch_applied`. `files_count` is the number of lockfiles/manifests
/// rewritten.
pub async fn track_patch_hosted(
    command: &'static str,
    patches_count: usize,
    files_count: usize,
    dry_run: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchApplied,
        command,
        serde_json::json!({
            "patches_count": patches_count,
            "files_count": files_count,
            "dry_run": dry_run,
            "mode": "hosted",
        }),
        None::<&str>,
        auth,
    );
}

/// Track a failed hosted-mode run (see [`track_patch_hosted`]).
pub async fn track_patch_hosted_failed(
    command: &'static str,
    error: impl std::fmt::Display,
    dry_run: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchApplyFailed,
        command,
        serde_json::json!({ "dry_run": dry_run, "mode": "hosted" }),
        Some(error),
        auth,
    );
}

/// Track a successful vendor run (count = packages vendored).
pub async fn track_patch_vendored(vendored_count: u32, dry_run: bool, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchVendored,
        "vendor",
        serde_json::json!({ "patches_count": vendored_count, "dry_run": dry_run }),
        None::<&str>,
        auth,
    );
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
    );
}

/// Track a successful patch removal.
pub async fn track_patch_removed(removed_count: usize, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRemoved,
        "remove",
        serde_json::json!({ "removed_count": removed_count }),
        None::<&str>,
        auth,
    );
}

/// Track a failed patch removal. Accepts any `Display` type for the error.
pub async fn track_patch_remove_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRemoveFailed,
        "remove",
        serde_json::Value::Null,
        Some(error),
        auth,
    );
}

/// Track a successful patch rollback.
pub async fn track_patch_rolled_back(rolled_back_count: usize, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRolledBack,
        "rollback",
        serde_json::json!({ "rolled_back_count": rolled_back_count }),
        None::<&str>,
        auth,
    );
}

/// Track a failed patch rollback. Accepts any `Display` type for the error.
pub async fn track_patch_rollback_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRollbackFailed,
        "rollback",
        serde_json::Value::Null,
        Some(error),
        auth,
    );
}

// ---------------------------------------------------------------------------
// Read-side trackers: scan + get
// ---------------------------------------------------------------------------

/// Track a successful `scan`. Reports per-tier patch counts, whether the
/// call was downgraded to the public proxy after an auth-endpoint 401/403
/// (`fallback_to_proxy`), the mode the run was asked for (`hosted` /
/// `vendored` / `agent`, or `report` with none) and the modes the project
/// is already wired for, from its hosted lockfile pins, vendor ledger and
/// agent manifest.
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
    mode: &str,
    project_modes: &[&str],
    auth: &TelemetryAuth,
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
            "mode": mode,
            "project_modes": project_modes,
        }),
        None::<&str>,
        auth,
    );
}

/// Track a failed `scan`.
pub async fn track_patch_scan_failed(
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchScanFailed,
        "scan",
        serde_json::json!({ "fallback_to_proxy": fallback_to_proxy }),
        Some(error),
        auth,
    );
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
    );
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
    );
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
    );
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
    );
}

/// Track a failed `repair`.
pub async fn track_patch_repair_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::PatchRepairFailed,
        "repair",
        serde_json::Value::Null,
        Some(error),
        auth,
    );
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
    );
}

/// Track a failed `vex` generation.
pub async fn track_vex_failed(error: impl std::fmt::Display, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::VexFailed,
        "vex",
        serde_json::Value::Null,
        Some(error),
        auth,
    );
}

// ---------------------------------------------------------------------------
// Self-update trackers
// ---------------------------------------------------------------------------

/// Track a successful self-update (`socket-patch --update`). The event's
/// `context.version` is the running (pre-update) build; `to_version` is
/// what was installed. `channel` is the detected install channel
/// (`standalone`, or the package manager a `--force` overrode).
pub async fn track_cli_updated(
    to_version: &str,
    channel: &str,
    pinned: bool,
    forced: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::CliUpdated,
        "update",
        serde_json::json!({
            "from_version": PACKAGE_VERSION,
            "to_version": to_version,
            "channel": channel,
            "pinned": pinned,
            "forced": forced,
        }),
        None::<&str>,
        auth,
    );
}

/// Track a failed self-update. `error_code` is the machine code the
/// `--json` envelope carries (e.g. `managed_install`, `check_failed`).
pub async fn track_cli_update_failed(
    error_code: &str,
    error: impl std::fmt::Display,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::CliUpdateFailed,
        "update",
        serde_json::json!({ "error_code": error_code }),
        Some(error),
        auth,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variable that can switch telemetry off.
    const OPT_OUT_VARS: [&str; 5] = [
        "SOCKET_TELEMETRY_DISABLED",
        "SOCKET_PATCH_TELEMETRY_DISABLED",
        "DO_NOT_TRACK",
        "VITEST",
        "SOCKET_OFFLINE",
    ];

    /// Telemetry switched on for one test: every opt-out variable is
    /// cleared, and restored when the guard drops. Tests that hold one are
    /// `#[serial]` (the environment is process-global).
    struct TelemetryOn(Vec<(&'static str, Option<String>)>);

    impl TelemetryOn {
        fn new() -> Self {
            let saved = OPT_OUT_VARS
                .iter()
                .map(|&var| (var, std::env::var(var).ok()))
                .collect();
            for var in OPT_OUT_VARS {
                std::env::remove_var(var);
            }
            Self(saved)
        }
    }

    impl Drop for TelemetryOn {
        fn drop(&mut self) {
            for (var, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(var, value),
                    None => std::env::remove_var(var),
                }
            }
        }
    }

    /// The route to a loopback endpoint that accepts every connection and
    /// never answers: a firewall that swallows the request, a stalled load
    /// balancer. It lives as long as the test's runtime.
    async fn stalled_endpoint() -> TelemetryAuth {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let url = format!("http://{}/telemetry", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((conn, _)) = listener.accept().await {
                held.push(conn);
            }
        });
        TelemetryAuth { url, bearer: None }
    }

    /// More grace than any send can use (its own request timeout is 5 s):
    /// `flush(AMPLE)` returns when every send in flight has finished.
    const AMPLE: Duration = Duration::from_secs(30);

    /// The org-style route to `server`'s `/telemetry`, with a bearer.
    fn route_to(server: &wiremock::MockServer) -> TelemetryAuth {
        TelemetryAuth {
            url: format!("{}/telemetry", server.uri()),
            bearer: Some("tok".to_string()),
        }
    }

    /// NT-U1: a tracker starts its send and returns. Awaited inline, a
    /// send to an endpoint that takes the request and never answers held
    /// its command for the whole 5 s request timeout. The exit wait is
    /// the grace, not that timeout, and the send it gives up on is gone.
    #[tokio::test]
    #[serial_test::serial]
    async fn trackers_return_without_waiting_for_the_endpoint() {
        let _on = TelemetryOn::new();
        let auth = stalled_endpoint().await;

        let started = std::time::Instant::now();
        track_patch_listed(3, &auth).await;
        let held = started.elapsed();
        assert!(
            held < Duration::from_secs(1),
            "the tracker held its caller for {held:?} on a stalled endpoint"
        );

        let grace = Duration::from_millis(200);
        let started = std::time::Instant::now();
        flush(grace).await;
        let waited = started.elapsed();
        assert!(
            waited >= grace,
            "flush returned after {waited:?} with a send still in flight"
        );
        assert!(
            waited < Duration::from_secs(2),
            "flush overran its {grace:?} grace: {waited:?}"
        );

        let started = std::time::Instant::now();
        flush(AMPLE).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "an abandoned send is not waited for again"
        );
    }

    /// A refused connection fails at once, and the wait ends with it
    /// rather than at the grace.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_refused_connection_does_not_use_up_the_grace() {
        let _on = TelemetryOn::new();
        // Bound, then released: nothing listens on the port.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let auth = TelemetryAuth {
            url: format!("http://127.0.0.1:{port}/telemetry"),
            bearer: None,
        };

        track_patch_listed(3, &auth).await;
        let started = std::time::Instant::now();
        flush(AMPLE).await;
        let waited = started.elapsed();
        assert!(
            waited < Duration::from_secs(10),
            "flush waited {waited:?} on a refused connection"
        );
    }

    /// A tracker reached with no async runtime drops its event instead of
    /// panicking where it would spawn the send.
    #[test]
    #[serial_test::serial]
    fn firing_without_a_runtime_drops_the_event() {
        let _on = TelemetryOn::new();
        let in_flight_before = in_flight().len();
        fire(
            PatchTelemetryEventType::PatchListed,
            "list",
            serde_json::Value::Null,
            None::<&str>,
            &TelemetryAuth {
                url: "http://127.0.0.1:9/telemetry".to_string(),
                bearer: None,
            },
        );
        assert_eq!(in_flight().len(), in_flight_before);
    }

    /// NT-U3: every documented opt-out switches telemetry off, each on its
    /// own, and an explicit "off" value of the same variable does not.
    #[test]
    #[serial_test::serial]
    fn every_documented_opt_out_disables_telemetry() {
        let _on = TelemetryOn::new();
        assert!(!is_telemetry_disabled(), "nothing set: telemetry is on");

        for (var, value) in [
            // The CLI's boolean vocabulary, not only `1` / `true`.
            ("SOCKET_TELEMETRY_DISABLED", "1"),
            ("SOCKET_TELEMETRY_DISABLED", "true"),
            ("SOCKET_TELEMETRY_DISABLED", "TRUE"),
            ("SOCKET_TELEMETRY_DISABLED", "yes"),
            ("SOCKET_TELEMETRY_DISABLED", "on"),
            // The v3/v4 name: an opt-out made then still holds.
            ("SOCKET_PATCH_TELEMETRY_DISABLED", "1"),
            ("SOCKET_PATCH_TELEMETRY_DISABLED", "true"),
            // The cross-tool convention: set to anything but an "off".
            ("DO_NOT_TRACK", "1"),
            ("DO_NOT_TRACK", "true"),
            ("DO_NOT_TRACK", "yes"),
        ] {
            std::env::set_var(var, value);
            assert!(is_telemetry_disabled(), "{var}={value} must opt out");
            std::env::remove_var(var);
            assert!(!is_telemetry_disabled(), "unsetting {var} opts back in");
        }

        for var in [
            "SOCKET_TELEMETRY_DISABLED",
            "SOCKET_PATCH_TELEMETRY_DISABLED",
            "DO_NOT_TRACK",
        ] {
            for value in ["", "0", "false", "FALSE"] {
                std::env::set_var(var, value);
                assert!(
                    !is_telemetry_disabled(),
                    "{var}={value:?} is not an opt-out"
                );
            }
            std::env::remove_var(var);
        }
    }

    /// `flush` waits for sends that finish inside the grace and returns as
    /// soon as they have: the events are delivered, with the headers every
    /// event carries, and the rest of the grace is not spent.
    #[tokio::test]
    #[serial_test::serial]
    async fn flush_waits_for_sends_that_finish_within_the_grace() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _on = TelemetryOn::new();
        let delay = Duration::from_millis(300);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/telemetry"))
            .respond_with(ResponseTemplate::new(201).set_delay(delay))
            .mount(&server)
            .await;

        let auth = route_to(&server);
        track_patch_listed(3, &auth).await;
        track_patch_listed(4, &auth).await;
        let started = std::time::Instant::now();
        flush(AMPLE).await;
        let waited = started.elapsed();
        assert!(waited >= delay, "flush must wait for the answers");
        assert!(
            waited < AMPLE / 2,
            "flush returns when the sends finish, not at the grace: {waited:?}"
        );

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2, "both sends ran side by side");
        for req in &reqs {
            assert_eq!(req.headers.get("authorization").unwrap(), "Bearer tok");
            assert_eq!(req.headers.get("user-agent").unwrap(), USER_AGENT);
            assert_eq!(req.headers.get("content-type").unwrap(), "application/json");
        }
    }

    /// Nothing started, nothing to wait for.
    #[tokio::test]
    #[serial_test::serial]
    async fn flushing_nothing_returns() {
        flush(AMPLE).await;
        let started = std::time::Instant::now();
        flush(AMPLE).await;
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    /// `flush` drains: a later one waits only for sends started since.
    #[tokio::test]
    #[serial_test::serial]
    async fn flush_drains_and_later_sends_join_the_next_flush() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _on = TelemetryOn::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let auth = route_to(&server);

        track_patch_listed(1, &auth).await;
        flush(AMPLE).await;
        assert!(in_flight().is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        flush(AMPLE).await;
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        track_patch_listed(2, &auth).await;
        flush(AMPLE).await;
        assert!(in_flight().is_empty());
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    /// A disabled run starts no send at all: nothing reaches the endpoint
    /// and nothing is left in flight for the exit to wait on.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_disabled_tracker_starts_no_send() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _on = TelemetryOn::new();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let auth = route_to(&server);
        flush(AMPLE).await;

        std::env::set_var("SOCKET_TELEMETRY_DISABLED", "1");
        track_patch_listed(1, &auth).await;
        assert!(in_flight().is_empty());
        flush(AMPLE).await;
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// The opt-outs that are not telemetry's own: the airgap gate
    /// (`SOCKET_OFFLINE`, which the CLI normalizes to `1`) and the vitest
    /// guard. Serialized: SOCKET_* env is process-global and the
    /// api/client.rs suite reads `SOCKET_OFFLINE` mid-test.
    #[test]
    #[serial_test::serial]
    fn offline_and_vitest_disable_telemetry() {
        let _on = TelemetryOn::new();
        assert!(!is_telemetry_disabled());

        // SOCKET_OFFLINE=1 implies "no network", which includes the
        // telemetry endpoint.
        for value in ["1", "true"] {
            std::env::set_var("SOCKET_OFFLINE", value);
            assert!(
                is_telemetry_disabled(),
                "SOCKET_OFFLINE={value} must disable telemetry (airgap)"
            );
        }
        for value in ["0", ""] {
            std::env::set_var("SOCKET_OFFLINE", value);
            assert!(!is_telemetry_disabled(), "SOCKET_OFFLINE={value:?}");
        }
        std::env::remove_var("SOCKET_OFFLINE");

        std::env::set_var("VITEST", "true");
        assert!(
            is_telemetry_disabled(),
            "VITEST=true must disable telemetry"
        );
        std::env::set_var("VITEST", "1");
        assert!(!is_telemetry_disabled(), "only the literal `true` counts");
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
        // Self-update
        assert_eq!(PatchTelemetryEventType::CliUpdated.as_str(), "cli_updated");
        assert_eq!(
            PatchTelemetryEventType::CliUpdateFailed.as_str(),
            "cli_update_failed"
        );
    }

    /// The `event_type` strings depscan's `/v0/orgs/:slug/telemetry`
    /// endpoint maps onto the `patch-lifecycle` ClickHouse category
    /// (`PATCH_EVENT_TYPES_BY_STRING` in depscan's
    /// `workspaces/api-v0/src/endpoints/orgs/telemetry-discriminators.ts`,
    /// mirroring `TelemetryEventType` in
    /// `workspaces/analytics-shared/src/telemetry/types.ts`). A type missing
    /// there is still stored, but lands as `event_type = 'external'` and
    /// drops out of every patch dashboard — so a new event type here needs
    /// the depscan map extended first, then this list.
    const DEPSCAN_PATCH_EVENT_TYPES: &[&str] = &[
        "patch_applied",
        "patch_apply_failed",
        "patch_removed",
        "patch_remove_failed",
        "autopatch_pr_created",
        "autopatch_pr_failed",
        "autopatch_pr_closed",
        "autopatch_pr_merged",
        "patch_searched",
        "patch_downloaded",
        "patch_rolled_back",
        "patch_rollback_failed",
        "patch_scanned",
        "patch_scan_failed",
        "patch_fetched",
        "patch_fetch_failed",
        "patch_vendored",
        "patch_vendor_failed",
        "patch_listed",
        "patch_repaired",
        "patch_repair_failed",
        "patch_setup",
        "vex_generated",
        "vex_failed",
        "cli_updated",
        "cli_update_failed",
    ];

    #[test]
    fn every_event_type_is_one_the_backend_maps() {
        for event_type in PatchTelemetryEventType::ALL {
            assert!(
                DEPSCAN_PATCH_EVENT_TYPES.contains(&event_type.as_str()),
                "{} is not in depscan's patch event map",
                event_type.as_str()
            );
        }
    }

    /// The body shape depscan's v0 telemetry handler reads. It pulls
    /// `event_sender_created_at` / `event_kind` / `artifact_purl` /
    /// `input_purl` / `client_action` / `alert_action` / `user_agent` out
    /// as columns and keeps the rest as extra-data JSON, deriving the
    /// ClickHouse discriminators from `event_type` (and `context.source`).
    /// Two of those matter here:
    ///
    /// * no `event_kind`: an event without one is "required" and is stored
    ///   even when the org has not opted into optional telemetry (anonymous
    ///   events go to the public patch org through the proxy). Sending
    ///   `event_kind: "informative"` would silently drop them.
    /// * `event_sender_created_at` must parse with `Date.parse` and fall
    ///   within [now - 25h, now + 1h], or it is discarded for the receive
    ///   time.
    #[test]
    fn wire_shape_matches_the_backend_extractor() {
        let mut metadata = HashMap::new();
        metadata.insert("patches_count".to_string(), serde_json::json!(2));
        let before = chrono_now_iso();
        let event = build_telemetry_event(
            PatchTelemetryEventType::PatchApplyFailed,
            "apply",
            Some(metadata),
            Some(("Error".to_string(), "boom".to_string())),
        );
        let v = serde_json::to_value(&event).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "context",
                "error",
                "event_sender_created_at",
                "event_type",
                "metadata",
                "session_id"
            ]
        );
        for column in [
            "event_kind",
            "artifact_purl",
            "input_purl",
            "client_action",
            "alert_action",
            "user_agent",
        ] {
            assert!(
                !obj.contains_key(column),
                "unexpected column field {column}"
            );
        }
        assert_eq!(v["event_type"], "patch_apply_failed");
        let mut ctx: Vec<&str> = v["context"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        ctx.sort_unstable();
        assert_eq!(ctx, ["arch", "command", "platform", "version"]);
        assert_eq!(v["error"]["type"], "Error");
        assert_eq!(v["error"]["message"], "boom");
        assert_eq!(v["metadata"]["patches_count"], 2);
        assert!(uuid::Uuid::parse_str(v["session_id"].as_str().unwrap()).is_ok());

        // Timestamp: fixed-width RFC 3339 UTC, so string order is time
        // order, and taken at send time (well inside the window).
        let after = chrono_now_iso();
        let ts = v["event_sender_created_at"].as_str().unwrap();
        assert!(
            before.as_str() <= ts && ts <= after.as_str(),
            "timestamp {ts} is not current ({before}..{after})"
        );
    }

    /// Each public tracker posts the event type and metadata the backend
    /// and its dashboards key on, to the org endpoint with the bearer.
    #[tokio::test]
    #[serial_test::serial]
    async fn trackers_post_the_documented_events() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/telemetry"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let _on = TelemetryOn::new();
        let auth = TelemetryAuth {
            url: format!("{}/v0/orgs/acme/telemetry", server.uri()),
            bearer: Some("tok".to_string()),
        };
        // Sends run side by side, so each is waited for before the next
        // fires: the requests then arrive in the order asserted below.
        track_patch_applied(3, false, &auth).await;
        flush(AMPLE).await;
        track_patch_hosted("scan", 2, 1, false, &auth).await;
        flush(AMPLE).await;
        track_patch_hosted_failed("get", "lockfile write failed", true, &auth).await;
        flush(AMPLE).await;
        track_cli_updated("9.9.9", "standalone", false, false, &auth).await;
        flush(AMPLE).await;
        track_cli_update_failed("managed_install", "managed by npm", &auth).await;
        flush(AMPLE).await;
        let ecosystems = vec!["npm".to_string(), "pypi".to_string()];
        track_patch_scanned(
            5,
            3,
            2,
            true,
            &ecosystems,
            true,
            "hosted",
            &["vendored"],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_scan_failed("all batches failed", true, &auth).await;
        flush(AMPLE).await;

        let reqs = server.received_requests().await.unwrap();
        let bodies: Vec<serde_json::Value> = reqs
            .iter()
            .map(|r| {
                assert_eq!(r.headers.get("authorization").unwrap(), "Bearer tok");
                serde_json::from_slice(&r.body).unwrap()
            })
            .collect();
        assert_eq!(bodies.len(), 7);

        assert_eq!(bodies[0]["event_type"], "patch_applied");
        assert_eq!(bodies[0]["context"]["command"], "apply");
        assert_eq!(bodies[0]["metadata"]["mode"], "agent");
        assert_eq!(bodies[0]["metadata"]["patches_count"], 3);

        assert_eq!(bodies[1]["event_type"], "patch_applied");
        assert_eq!(bodies[1]["context"]["command"], "scan");
        assert_eq!(bodies[1]["metadata"]["mode"], "hosted");
        assert_eq!(bodies[1]["metadata"]["patches_count"], 2);
        assert_eq!(bodies[1]["metadata"]["files_count"], 1);

        assert_eq!(bodies[2]["event_type"], "patch_apply_failed");
        assert_eq!(bodies[2]["context"]["command"], "get");
        assert_eq!(bodies[2]["metadata"]["mode"], "hosted");
        assert_eq!(bodies[2]["metadata"]["dry_run"], true);
        assert_eq!(bodies[2]["error"]["message"], "lockfile write failed");

        assert_eq!(bodies[3]["event_type"], "cli_updated");
        assert_eq!(bodies[3]["context"]["command"], "update");
        assert_eq!(bodies[3]["metadata"]["from_version"], PACKAGE_VERSION);
        assert_eq!(bodies[3]["metadata"]["to_version"], "9.9.9");
        assert_eq!(bodies[3]["metadata"]["channel"], "standalone");

        assert_eq!(bodies[4]["event_type"], "cli_update_failed");
        assert_eq!(bodies[4]["metadata"]["error_code"], "managed_install");
        assert_eq!(bodies[4]["error"]["message"], "managed by npm");

        assert_eq!(bodies[5]["event_type"], "patch_scanned");
        assert_eq!(bodies[5]["context"]["command"], "scan");
        assert_eq!(bodies[5]["metadata"]["packages_scanned"], 5);
        assert_eq!(bodies[5]["metadata"]["free_patches"], 3);
        assert_eq!(bodies[5]["metadata"]["paid_patches"], 2);
        assert_eq!(
            bodies[5]["metadata"]["ecosystems"],
            serde_json::json!(["npm", "pypi"])
        );
        assert_eq!(bodies[5]["metadata"]["mode"], "hosted");
        assert_eq!(
            bodies[5]["metadata"]["project_modes"],
            serde_json::json!(["vendored"])
        );

        assert_eq!(bodies[6]["event_type"], "patch_scan_failed");
        assert_eq!(bodies[6]["context"]["command"], "scan");
        assert_eq!(bodies[6]["metadata"]["fallback_to_proxy"], true);
        assert_eq!(bodies[6]["error"]["message"], "all batches failed");
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
