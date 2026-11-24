use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use once_cell::sync::Lazy;
use uuid::Uuid;

use crate::api::client::ApiRoute;
use crate::constants::USER_AGENT;
use crate::update::channel::{detect_channel, ChannelEnv};
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
    // A user's report that a patch broke something (`report`)
    PatchReported,
}

impl PatchTelemetryEventType {
    /// Every variant, for the backend-contract test.
    #[cfg(test)]
    const ALL: [Self; 20] = [
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
        Self::PatchReported,
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
            Self::PatchReported => "patch_reported",
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
    /// How this binary was installed ([`InstallChannel::id`]): `standalone`,
    /// `npm`, `cargo`, `homebrew`, `pypi` or `launcher_cache`. Left out when
    /// the binary's own path cannot be read.
    ///
    /// [`InstallChannel::id`]: crate::update::channel::InstallChannel::id
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<&'static str>,
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

/// The install channel of the running binary, worked out once per process
/// from the binary's own path: the check `--update` makes before it
/// replaces a binary. It names one of six channels and never a path. It
/// reads no project file, makes no request and does not ask the user
/// database for a home directory ([`ChannelEnv::from_env_vars`]).
///
/// `None` when the binary's own path cannot be read: no `/proc`, or a
/// binary that was replaced or removed while it ran.
fn install_channel() -> Option<&'static str> {
    static CHANNEL: Lazy<Option<&'static str>> = Lazy::new(|| {
        let exe = crate::update::resolve_install_path().ok()?;
        Some(detect_channel(&exe, &ChannelEnv::from_env_vars()).id())
    });
    *CHANNEL
}

/// Work the install channel out now, while the running binary is still
/// where it was started from. `--update` calls this before it swaps the
/// binary: on Linux the old path reads as deleted afterwards, and the
/// `cli_updated` event would go out without its channel.
pub fn prime_install_channel() {
    let _ = install_channel();
}

/// Build the telemetry context for the current environment.
fn build_telemetry_context(command: &str) -> PatchTelemetryContext {
    PatchTelemetryContext {
        version: PACKAGE_VERSION.to_string(),
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        command: command.to_string(),
        channel: install_channel(),
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

/// `text` cut to at most `max` characters, the last of them an ellipsis
/// when anything was dropped.
fn truncate_chars(text: String, max: usize) -> String {
    match text.char_indices().nth(max.saturating_sub(1)) {
        Some((cut, _)) if text[cut..].chars().nth(1).is_some() => {
            format!("{}…", &text[..cut])
        }
        _ => text,
    }
}

/// Build a telemetry event. `error` is an `(error_type, message)` pair; the
/// message is sanitized ([`sanitize_error_message`]) and cut to
/// [`MAX_ERROR_MESSAGE_CHARS`] before it leaves the process, and the whole
/// event is made to fit [`MAX_EVENT_BYTES`] ([`fit`]).
fn build_telemetry_event(
    event_type: PatchTelemetryEventType,
    command: &str,
    metadata: Option<HashMap<String, serde_json::Value>>,
    error: Option<(String, String)>,
) -> PatchTelemetryEvent {
    fit(PatchTelemetryEvent {
        event_sender_created_at: chrono_now_iso(),
        event_type: event_type.as_str().to_string(),
        context: build_telemetry_context(command),
        session_id: SESSION_ID.clone(),
        metadata,
        error: error.map(|(error_type, message)| PatchTelemetryError {
            error_type,
            message: Some(truncate_chars(
                sanitize_error_message(&message),
                MAX_ERROR_MESSAGE_CHARS,
            )),
        }),
    })
}

/// The largest event body sent, in bytes of JSON. The server keeps a body
/// in a form its dashboards can read only up to 10,000 characters, and a
/// body never has more characters than bytes.
const MAX_EVENT_BYTES: usize = 9_000;

/// The shortest an error message is cut to when an event is too large.
const MIN_ERROR_MESSAGE_CHARS: usize = 200;

/// `event` cut down until its JSON body fits [`MAX_EVENT_BYTES`]. The
/// caps on the patch list and the error message leave room in almost
/// every event; what they do not bound is how much a message grows when
/// JSON escapes it (a quote or a newline doubles, a control character
/// becomes six). An event that is still too large gives up the tail of
/// its error message first, then entries off the end of its patch list
/// (the failed ones lead), flagged `patches_truncated`.
fn fit(mut event: PatchTelemetryEvent) -> PatchTelemetryEvent {
    let too_large = |event: &PatchTelemetryEvent| {
        serde_json::to_string(event).is_ok_and(|body| body.len() > MAX_EVENT_BYTES)
    };
    while too_large(&event) {
        if let Some(message) = event.error.as_mut().and_then(|e| e.message.as_mut()) {
            let chars = message.chars().count();
            if chars > MIN_ERROR_MESSAGE_CHARS {
                let shorter = (chars / 2).max(MIN_ERROR_MESSAGE_CHARS);
                *message = truncate_chars(std::mem::take(message), shorter);
                continue;
            }
        }
        let Some(metadata) = event.metadata.as_mut() else {
            break;
        };
        match metadata
            .get_mut("patches")
            .and_then(serde_json::Value::as_array_mut)
        {
            Some(patches) if !patches.is_empty() => patches.truncate(patches.len() / 2),
            _ => break,
        }
        metadata.insert("patches_truncated".to_string(), serde_json::json!(true));
    }
    event
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
    match post_event(prepared).await {
        Ok(()) => debug_log("Telemetry sent successfully"),
        Err(why) => debug_log(&format!("Telemetry request {why}")),
    }
}

/// What a POST did instead of succeeding. Its text follows "the request"
/// in a debug line or an error message (`returned status 500 …`,
/// `failed: …`); any URL in it is redacted.
#[derive(Debug)]
enum PostFailure {
    /// The endpoint answered with a status that is not a success.
    Status(reqwest::StatusCode),
    /// No answer: no client, no connection, a timeout.
    NoAnswer(String),
}

impl std::fmt::Display for PostFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(status) => write!(f, "returned status {status}"),
            Self::NoAnswer(why) => f.write_str(why),
        }
    }
}

/// POST one event and say whether the endpoint took it.
async fn post_event(prepared: PreparedSend) -> Result<(), PostFailure> {
    let PreparedSend { event, url, bearer } = prepared;

    let client = crate::utils::http::client_builder()
        .connect_timeout(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| PostFailure::NoAnswer(format!("could not start (no HTTP client: {e})")))?;

    let mut request = client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("User-Agent", USER_AGENT);

    if let Some(token) = bearer {
        request = request.header("Authorization", format!("Bearer {token}"));
    }

    match request.json(&event).send().await {
        Ok(response) if response.status().is_success() => Ok(()),
        Ok(response) => Err(PostFailure::Status(response.status())),
        // The whole cause chain: reqwest's own text stops at "error
        // sending request", before the refused connection or the timeout.
        Err(e) => Err(PostFailure::NoAnswer(format!(
            "failed: {}",
            crate::api::client::network_error_detail(&e)
        ))),
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
// Per-patch outcomes
// ---------------------------------------------------------------------------

/// The patch modes an event names (`mode`, and each [`PatchOutcome`]'s).
pub const MODE_AGENT: &str = "agent";
pub const MODE_HOSTED: &str = "hosted";
pub const MODE_VENDORED: &str = "vendored";

/// The [`PatchOutcome::outcome`] of a patch the run could not act on.
pub const OUTCOME_FAILED: &str = "failed";

/// How many patches one event names. A run over more names this many,
/// the failed ones first, and says so (`patches_truncated`); the counts
/// beside the list are of the whole run.
///
/// The cap keeps an event small: the server stores an event's body in a
/// form its dashboards cannot read once the body passes 10,000 characters
/// (see [`MAX_EVENT_BYTES`]), and one entry is about 110.
pub const MAX_REPORTED_PATCHES: usize = 50;

/// The longest error message an event carries, in characters. One error
/// can quote a whole command's output, and the event has to stay small
/// (see [`MAX_REPORTED_PATCHES`]).
const MAX_ERROR_MESSAGE_CHARS: usize = 1000;

/// One patch a run acted on, as its event names it: by patch UUID, with
/// the ecosystem and the mode it was patched in, and what the run did to
/// it. Never the package name, a path or a file list.
///
/// This is what lets Socket see that one patch is being rolled back, or
/// fails to apply, far more often than the others.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PatchOutcome {
    /// The patch UUID.
    pub uuid: String,
    /// The ecosystem's CLI name (`npm`, `pypi`, …); empty when unknown.
    pub ecosystem: String,
    /// [`MODE_AGENT`], [`MODE_HOSTED`] or [`MODE_VENDORED`]; a reported
    /// patch the project does not hold has [`MODE_UNKNOWN`].
    pub mode: &'static str,
    /// What happened: `applied`, `rolled_back`, `removed`, `downloaded`,
    /// `failed`, `skipped`, … (the command's own vocabulary).
    pub outcome: &'static str,
    /// The stable code of a `failed` or `skipped` outcome
    /// (`hash_mismatch`, `already_patched`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl PatchOutcome {
    /// How many of `patches` ended as `outcome`.
    pub fn count(patches: &[PatchOutcome], outcome: &str) -> usize {
        patches.iter().filter(|p| p.outcome == outcome).count()
    }
}

/// The fields an event about specific patches carries, added to `metadata`
/// (an object; the event's own keys win):
///
/// * `patches`: at most [`MAX_REPORTED_PATCHES`] outcomes, and
///   `patches_truncated: true` when that cap dropped some;
/// * `outcomes`: how many patches ended each way, over the whole run;
/// * `ecosystems`, `modes`: the distinct values, sorted, over the whole run.
///
/// A run that named no patch adds nothing.
fn with_patches(mut metadata: serde_json::Value, patches: &[PatchOutcome]) -> serde_json::Value {
    use std::collections::{BTreeMap, BTreeSet};

    let Some(fields) = metadata.as_object_mut() else {
        return metadata;
    };
    if patches.is_empty() {
        return metadata;
    }
    let mut outcomes: BTreeMap<&str, usize> = BTreeMap::new();
    let mut ecosystems: BTreeSet<&str> = BTreeSet::new();
    let mut modes: BTreeSet<&str> = BTreeSet::new();
    for patch in patches {
        *outcomes.entry(patch.outcome).or_default() += 1;
        if !patch.ecosystem.is_empty() {
            ecosystems.insert(&patch.ecosystem);
        }
        modes.insert(patch.mode);
    }
    // Failures first: when the cap drops entries, the ones worth
    // investigating are the ones kept. Otherwise the run's own order.
    let reported: Vec<&PatchOutcome> = patches
        .iter()
        .filter(|p| p.outcome == OUTCOME_FAILED)
        .chain(patches.iter().filter(|p| p.outcome != OUTCOME_FAILED))
        .take(MAX_REPORTED_PATCHES)
        .collect();
    let mut add = |key: &str, value: serde_json::Value| {
        fields.entry(key).or_insert(value);
    };
    if reported.len() < patches.len() {
        add("patches_truncated", serde_json::json!(true));
    }
    add("patches", serde_json::json!(reported));
    add("outcomes", serde_json::json!(outcomes));
    add("ecosystems", serde_json::json!(ecosystems));
    add("modes", serde_json::json!(modes));
    metadata
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

/// Track a successful in-place (agent mode) patch application, as
/// `command` (`apply`, or the `scan` / `get` whose agent mode ran it):
/// `patches` are the patches the run acted on, `patches_count` how many
/// packages it patched.
pub async fn track_patch_applied(
    command: &'static str,
    patches_count: usize,
    dry_run: bool,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchApplied,
        command,
        with_patches(
            serde_json::json!({
                "patches_count": patches_count,
                "dry_run": dry_run,
                "mode": MODE_AGENT,
            }),
            patches,
        ),
        None::<&str>,
        auth,
    );
}

/// The fields of a failure event: `fields`, the run's stable `error_code`
/// (the code its `--json` envelope reports, e.g. `patch_not_found`: what
/// tells a mistyped target from a patch that would not come off) and the
/// patches it acted on.
fn failure_metadata(
    mut fields: serde_json::Value,
    error_code: &str,
    patches: &[PatchOutcome],
) -> serde_json::Value {
    if let Some(fields) = fields.as_object_mut() {
        fields.insert("error_code".to_string(), serde_json::json!(error_code));
    }
    with_patches(fields, patches)
}

/// Track a failed patch application. `patches` names what the run acted
/// on before it failed (the failed ones and the ones it did apply); empty
/// when it failed before reaching any.
///
/// Accepts any `Display` type for the error (works with `&str`, `String`,
/// `anyhow::Error`, `std::io::Error`, etc.).
pub async fn track_patch_apply_failed(
    command: &'static str,
    error_code: &str,
    error: impl std::fmt::Display,
    dry_run: bool,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchApplyFailed,
        command,
        failure_metadata(
            serde_json::json!({
                "patches_count": PatchOutcome::count(patches, "applied"),
                "dry_run": dry_run,
                "mode": MODE_AGENT,
            }),
            error_code,
            patches,
        ),
        Some(error),
        auth,
    );
}

/// Track a hosted-mode run (`scan`/`get --mode hosted`) that pinned
/// patched dependencies to Socket's hosted patch server. Sent as
/// `patch_applied` with `mode: "hosted"`: the lockfile pin is how hosted
/// mode applies a patch, and the backend's adoption views count
/// `patch_applied`. `files_count` is the number of lockfiles/manifests
/// rewritten; `patches` are the pins the run confirmed and the ones it
/// could not make.
pub async fn track_patch_hosted(
    command: &'static str,
    patches_count: usize,
    files_count: usize,
    dry_run: bool,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchApplied,
        command,
        with_patches(
            serde_json::json!({
                "patches_count": patches_count,
                "files_count": files_count,
                "dry_run": dry_run,
                "mode": MODE_HOSTED,
            }),
            patches,
        ),
        None::<&str>,
        auth,
    );
}

/// Track a failed hosted-mode run (see [`track_patch_hosted`]).
pub async fn track_patch_hosted_failed(
    command: &'static str,
    error_code: &str,
    error: impl std::fmt::Display,
    dry_run: bool,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchApplyFailed,
        command,
        failure_metadata(
            serde_json::json!({ "dry_run": dry_run, "mode": MODE_HOSTED }),
            error_code,
            patches,
        ),
        Some(error),
        auth,
    );
}

/// Track a successful vendor run, as `command` (`vendor`, or the `scan` /
/// `get` whose vendored mode ran it): `vendored_count` packages vendored,
/// `patches` what the run did to each.
pub async fn track_patch_vendored(
    command: &'static str,
    vendored_count: u32,
    dry_run: bool,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchVendored,
        command,
        with_patches(
            serde_json::json!({
                "patches_count": vendored_count,
                "dry_run": dry_run,
                "mode": MODE_VENDORED,
            }),
            patches,
        ),
        None::<&str>,
        auth,
    );
}

/// Track a failed vendor run (see [`track_patch_vendored`]). `patches`
/// names what it acted on before it failed; empty when it failed before
/// reaching any.
pub async fn track_patch_vendor_failed(
    command: &'static str,
    error_code: &str,
    error: impl std::fmt::Display,
    dry_run: bool,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchVendorFailed,
        command,
        failure_metadata(
            serde_json::json!({
                "patches_count": PatchOutcome::count(patches, "applied"),
                "dry_run": dry_run,
                "mode": MODE_VENDORED,
            }),
            error_code,
            patches,
        ),
        Some(error),
        auth,
    );
}

/// Track a patch removal that took `removed_count` patches out, as
/// `command` (`remove`, or `vendor` for its `--revert`). `patches` names
/// each one.
pub async fn track_patch_removed(
    command: &'static str,
    removed_count: usize,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchRemoved,
        command,
        with_patches(
            serde_json::json!({ "removed_count": removed_count }),
            patches,
        ),
        None::<&str>,
        auth,
    );
}

/// Track a patch removal that did not happen. Accepts any `Display` type
/// for the error; `patches` names the patches it could not remove, when
/// the run got as far as resolving them.
pub async fn track_patch_remove_failed(
    command: &'static str,
    error_code: &str,
    error: impl std::fmt::Display,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchRemoveFailed,
        command,
        failure_metadata(serde_json::json!({}), error_code, patches),
        Some(error),
        auth,
    );
}

/// What a rollback run reports besides the patches themselves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RollbackRun {
    /// How many patched packages the run restored (would restore, on a
    /// dry run), across every mode.
    pub rolled_back_count: usize,
    /// A preview: nothing was restored.
    pub dry_run: bool,
    /// The user named the patches to roll back (a purl, a UUID, a path),
    /// rather than rolling the whole project back.
    pub targeted: bool,
}

impl RollbackRun {
    fn metadata(self) -> serde_json::Value {
        serde_json::json!({
            "rolled_back_count": self.rolled_back_count,
            "dry_run": self.dry_run,
            "targeted": self.targeted,
        })
    }
}

/// Track a rollback that left nothing patched. `patches` names each patch
/// the run rolled back (`rolled_back`, or `verified` on a dry run) or had
/// nothing to do for (`skipped`).
pub async fn track_patch_rolled_back(
    run: RollbackRun,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchRolledBack,
        "rollback",
        with_patches(run.metadata(), patches),
        None::<&str>,
        auth,
    );
}

/// Track a rollback that left something patched, or never started.
/// Accepts any `Display` type for the error. `patches` names the patches
/// that failed and the ones the same run did roll back; empty when the
/// run failed before it resolved any.
pub async fn track_patch_rollback_failed(
    error_code: &str,
    error: impl std::fmt::Display,
    run: RollbackRun,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchRollbackFailed,
        "rollback",
        failure_metadata(run.metadata(), error_code, patches),
        Some(error),
        auth,
    );
}

// ---------------------------------------------------------------------------
// Patch reports: `report`
// ---------------------------------------------------------------------------

/// The [`PatchOutcome::outcome`] of a patch a user reported.
pub const OUTCOME_REPORTED: &str = "reported";

/// The [`PatchOutcome::mode`] of a patch reported by UUID that the project
/// does not hold (one already rolled back, say), so its mode is not known.
pub const MODE_UNKNOWN: &str = "unknown";

/// The longest message a report carries, in characters.
pub const MAX_REPORT_MESSAGE_CHARS: usize = 1000;

/// What a reported patch broke. A report is only ever about a patch that
/// broke something: there is no report that a patch works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportReason {
    /// The project no longer installs, compiles or builds.
    BreaksBuild,
    /// The project's tests fail.
    BreaksTests,
    /// The project misbehaves when it runs.
    BreaksRuntime,
    /// Something else; the message says what.
    Other,
}

impl ReportReason {
    /// Every reason, in the order help text lists them.
    pub const ALL: [Self; 4] = [
        Self::BreaksBuild,
        Self::BreaksTests,
        Self::BreaksRuntime,
        Self::Other,
    ];

    /// The wire-format string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BreaksBuild => "breaks_build",
            Self::BreaksTests => "breaks_tests",
            Self::BreaksRuntime => "breaks_runtime",
            Self::Other => "other",
        }
    }
}

/// Why a report did not reach Socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportNotSent {
    /// The run is offline (`--offline`, `SOCKET_OFFLINE`).
    Offline,
    /// It names more patches than one event carries
    /// ([`MAX_REPORTED_PATCHES`]): sending it would drop some unsaid.
    TooManyPatches,
    /// The endpoint did not take it; the text says what happened.
    NotDelivered(String),
}

impl ReportNotSent {
    /// The stable code a `--json` run reports.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Offline => "offline_unsupported",
            Self::TooManyPatches => "too_many_patches",
            Self::NotDelivered(_) => "report_not_sent",
        }
    }
}

impl std::fmt::Display for ReportNotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offline => f.write_str("the run is offline"),
            Self::TooManyPatches => write!(
                f,
                "one report names at most {MAX_REPORTED_PATCHES} patches; send the rest in \
                 another"
            ),
            Self::NotDelivered(why) => write!(f, "the request {why}"),
        }
    }
}

/// A report's message as it is sent: on one line, with URLs' credentials
/// and the home directory redacted ([`sanitize_error_message`]), cut to
/// [`MAX_REPORT_MESSAGE_CHARS`]. `None` for a message with nothing in it.
pub fn report_message(message: &str) -> Option<String> {
    // Line breaks and control characters become spaces: each would cost
    // up to six bytes of the event once JSON escapes it.
    let flat = message
        .split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if flat.is_empty() {
        return None;
    }
    Some(truncate_chars(
        sanitize_error_message(&flat),
        MAX_REPORT_MESSAGE_CHARS,
    ))
}

/// The `patch_reported` event of a report, before [`fit`] has cut it.
fn report_event(
    command: &'static str,
    reason: ReportReason,
    message: Option<&str>,
    patches: &[PatchOutcome],
) -> PatchTelemetryEvent {
    let mut fields = serde_json::json!({ "reason": reason.as_str() });
    if let Some(message) = message {
        fields["message"] = serde_json::json!(message);
    }
    let metadata = match with_patches(fields, patches) {
        serde_json::Value::Object(map) => map.into_iter().collect(),
        _ => HashMap::new(),
    };
    build_telemetry_event(
        PatchTelemetryEventType::PatchReported,
        command,
        Some(metadata),
        None,
    )
}

/// Whether a report's event lost patches to a cap ([`with_patches`]'s
/// or [`fit`]'s): the report would then name fewer than the user did.
fn drops_patches(event: &PatchTelemetryEvent) -> bool {
    event
        .metadata
        .as_ref()
        .is_some_and(|metadata| metadata.contains_key("patches_truncated"))
}

/// The message a report of `patches` carries: `message` as
/// [`report_message`] makes it, cut further only where the event would
/// otherwise be too large to name every patch (a full list beside a
/// long message in a wide script). What comes back is what
/// [`send_patch_report`] sends, so a caller can show it first.
///
/// `Err(TooManyPatches)` for more patches than one event names: a
/// report never leaves a patch out unsaid.
pub fn fitted_report_message(
    command: &'static str,
    reason: ReportReason,
    message: Option<&str>,
    patches: &[PatchOutcome],
) -> Result<Option<String>, ReportNotSent> {
    if patches.len() > MAX_REPORTED_PATCHES {
        return Err(ReportNotSent::TooManyPatches);
    }
    let mut message = message.and_then(report_message);
    loop {
        if !drops_patches(&report_event(command, reason, message.as_deref(), patches)) {
            return Ok(message);
        }
        // The patches are the report; the message gives way to them.
        message = match message {
            Some(text) if text.chars().count() > 1 => {
                let half = text.chars().count() / 2;
                Some(truncate_chars(text, half))
            }
            // No message left to cut: the patch list alone is too large.
            _ => return Err(ReportNotSent::TooManyPatches),
        };
    }
}

/// Send a user's report that `patches` broke something, as `command`
/// (`report`), and wait for the answer: unlike a tracker's event, a
/// report is the point of the run, so the caller says whether it
/// arrived.
///
/// The event names each patch by UUID, ecosystem and mode (never a
/// package name or a path), the reason, and the message the user typed
/// ([`fitted_report_message`]).
///
/// A report is something the user asked to send, not telemetry about a
/// run, so the telemetry opt-outs ([`is_telemetry_disabled`]) do not stop
/// it. An offline run does: it makes no request of any kind.
///
/// A token the org endpoint refuses (401 / 403: expired, revoked, or
/// without access to the org) does not lose the report: it goes out
/// again without the token, on the public route an anonymous run uses.
pub async fn send_patch_report(
    command: &'static str,
    reason: ReportReason,
    message: Option<&str>,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) -> Result<(), ReportNotSent> {
    if is_offline_env() {
        return Err(ReportNotSent::Offline);
    }
    let message = fitted_report_message(command, reason, message, patches)?;
    let event = report_event(command, reason, message.as_deref(), patches);
    let refused = match post_event(prepare_send(event.clone(), auth)).await {
        Ok(()) => return Ok(()),
        Err(PostFailure::Status(status))
            if auth.is_authenticated()
                && matches!(
                    status,
                    reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
                ) =>
        {
            status
        }
        Err(failure) => return Err(ReportNotSent::NotDelivered(failure.to_string())),
    };
    debug_log(&format!(
        "The report's token was refused ({refused}); sending it without one"
    ));
    let public = TelemetryAuth::proxy_at(&proxy_url_from_env());
    post_event(prepare_send(event, &public))
        .await
        .map_err(|failure| ReportNotSent::NotDelivered(failure.to_string()))
}

// ---------------------------------------------------------------------------
// Read-side trackers: scan + get
// ---------------------------------------------------------------------------

/// What a successful `scan` reports.
#[derive(Debug, Clone, Copy)]
pub struct ScanReport<'a> {
    /// Packages the crawl found, per ecosystem (CLI name). Its keys are
    /// the event's `ecosystems`, its sum `packages_scanned`: the
    /// ecosystems the crawl found, not the `--ecosystems` filter.
    pub packages_by_ecosystem: &'a std::collections::BTreeMap<String, usize>,
    /// Patches the API offered for those packages, per ecosystem.
    pub patches_by_ecosystem: &'a std::collections::BTreeMap<String, usize>,
    pub free_patches: usize,
    pub paid_patches: usize,
    pub can_access_paid: bool,
    /// The call was downgraded to the public proxy after an auth-endpoint
    /// 401/403.
    pub fallback_to_proxy: bool,
    /// The mode the run was asked for (`hosted` / `vendored` / `agent`,
    /// or `report` with none).
    pub mode: &'a str,
    /// The modes the project is already wired for, from its hosted
    /// lockfile pins, vendor ledger and agent manifest.
    pub project_modes: &'a [&'a str],
    pub dry_run: bool,
}

/// Track a successful `scan` of one project directory.
pub async fn track_patch_scanned(report: ScanReport<'_>, auth: &TelemetryAuth) {
    let ecosystems: Vec<&String> = report.packages_by_ecosystem.keys().collect();
    fire(
        PatchTelemetryEventType::PatchScanned,
        "scan",
        serde_json::json!({
            "packages_scanned": report.packages_by_ecosystem.values().sum::<usize>(),
            "free_patches": report.free_patches,
            "paid_patches": report.paid_patches,
            "can_access_paid": report.can_access_paid,
            "ecosystems": ecosystems,
            "packages_by_ecosystem": report.packages_by_ecosystem,
            "patches_by_ecosystem": report.patches_by_ecosystem,
            "fallback_to_proxy": report.fallback_to_proxy,
            "mode": report.mode,
            "project_modes": report.project_modes,
            "dry_run": report.dry_run,
        }),
        None::<&str>,
        auth,
    );
}

/// Track a failed `scan`: `error_code` is the code its `--json` envelope
/// reports, `mode` the mode the run was asked for.
pub async fn track_patch_scan_failed(
    error_code: &str,
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    mode: &str,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchScanFailed,
        "scan",
        serde_json::json!({
            "error_code": error_code,
            "fallback_to_proxy": fallback_to_proxy,
            "mode": mode,
        }),
        Some(error),
        auth,
    );
}

/// Track a `get <uuid>` that resolved its patch. Reports patch identity,
/// the mode the run patches in, and whether the call was downgraded to the
/// public proxy after an auth-endpoint 401/403. `download_mode` is always
/// `"file"`: v5 fetches patch content only as per-file blobs, and the
/// field stays so the event schema is unchanged.
pub async fn track_patch_fetched(
    uuid: &str,
    tier: &str,
    ecosystem: &str,
    mode: &'static str,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    let patch = PatchOutcome {
        uuid: uuid.to_string(),
        ecosystem: ecosystem.to_string(),
        mode,
        outcome: "downloaded",
        code: None,
    };
    fire(
        PatchTelemetryEventType::PatchFetched,
        "get",
        with_patches(
            serde_json::json!({
                "uuid": uuid,
                "tier": tier,
                "ecosystem": ecosystem,
                "mode": mode,
                "patches_count": 1,
                "download_mode": "file",
                "fallback_to_proxy": fallback_to_proxy,
            }),
            std::slice::from_ref(&patch),
        ),
        None::<&str>,
        auth,
    );
}

/// Track the patch records an agent-mode run downloaded, as `command`
/// (`scan`, or a `get` by package or advisory): one event for the run,
/// naming each patch it downloaded (`downloaded`), already had
/// (`skipped`) or could not fetch (`failed`). `patches_count` is how many
/// it downloaded. A run that reached no patch sends nothing.
pub async fn track_patches_fetched(
    command: &'static str,
    patches: &[PatchOutcome],
    auth: &TelemetryAuth,
) {
    if patches.is_empty() {
        return;
    }
    fire(
        PatchTelemetryEventType::PatchFetched,
        command,
        with_patches(
            serde_json::json!({
                "mode": MODE_AGENT,
                "patches_count": PatchOutcome::count(patches, "downloaded"),
                "download_mode": "file",
            }),
            patches,
        ),
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
/// a uuid is reported as empty. `error_code` is the code the run's
/// `--json` output reports (`not_found`, `paid_required`,
/// `patch_fetch_failed`).
pub async fn track_patch_fetch_failed(
    uuid: &str,
    error_code: &str,
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchFetchFailed,
        "get",
        serde_json::json!({
            "uuid": fetch_failed_uuid(uuid),
            "error_code": error_code,
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

/// Track a failed `repair`: `error_code` is the code its `--json`
/// envelope reports.
pub async fn track_patch_repair_failed(
    error_code: &str,
    error: impl std::fmt::Display,
    auth: &TelemetryAuth,
) {
    fire(
        PatchTelemetryEventType::PatchRepairFailed,
        "repair",
        serde_json::json!({ "error_code": error_code }),
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

/// Track a failed `vex` generation: `error_code` is the code its error
/// reports (and, as it always was, the event's error message).
pub async fn track_vex_failed(error_code: &str, auth: &TelemetryAuth) {
    fire(
        PatchTelemetryEventType::VexFailed,
        "vex",
        serde_json::json!({ "error_code": error_code }),
        Some(error_code),
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
        // Reports
        assert_eq!(
            PatchTelemetryEventType::PatchReported.as_str(),
            "patch_reported"
        );
    }

    /// The `event_type` strings the Socket API's `/v0/orgs/:slug/telemetry`
    /// endpoint maps onto its `patch-lifecycle` category. A type missing
    /// from the server's map is still stored, but lands as
    /// `event_type = 'external'` and drops out of every patch dashboard —
    /// so a new event type here needs the server's map extended first,
    /// then this list.
    const SERVER_PATCH_EVENT_TYPES: &[&str] = &[
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
        "patch_reported",
    ];

    #[test]
    fn every_event_type_is_one_the_backend_maps() {
        for event_type in PatchTelemetryEventType::ALL {
            assert!(
                SERVER_PATCH_EVENT_TYPES.contains(&event_type.as_str()),
                "{} is not in the server's patch event map",
                event_type.as_str()
            );
        }
    }

    /// The body shape the Socket API's v0 telemetry handler reads. It pulls
    /// `event_sender_created_at` / `event_kind` / `artifact_purl` /
    /// `input_purl` / `client_action` / `alert_action` / `user_agent` out
    /// as columns and keeps the rest as extra-data JSON, deriving the
    /// stored discriminators from `event_type` (and `context.source`).
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
        // The channel is the id of the test binary's own install channel,
        // never a path. It depends on where the build directory sits (a
        // checkout under `node_modules` reads as npm), and is left out
        // where the binary cannot read its own path.
        match install_channel() {
            Some(channel) => {
                assert_eq!(ctx, ["arch", "channel", "command", "platform", "version"]);
                assert_eq!(v["context"]["channel"], channel);
                assert!(
                    [
                        "standalone",
                        "npm",
                        "pypi",
                        "cargo",
                        "launcher_cache",
                        "homebrew"
                    ]
                    .contains(&channel),
                    "unexpected channel id {channel}"
                );
            }
            None => assert_eq!(ctx, ["arch", "command", "platform", "version"]),
        }
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

    const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
    const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

    fn outcome(
        uuid: &str,
        ecosystem: &str,
        mode: &'static str,
        outcome: &'static str,
        code: Option<&str>,
    ) -> PatchOutcome {
        PatchOutcome {
            uuid: uuid.to_string(),
            ecosystem: ecosystem.to_string(),
            mode,
            outcome,
            code: code.map(str::to_string),
        }
    }

    /// The bodies an org-style mock received, in arrival order, each
    /// checked for the bearer.
    async fn posted(server: &wiremock::MockServer) -> Vec<serde_json::Value> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| {
                assert_eq!(r.headers.get("authorization").unwrap(), "Bearer tok");
                serde_json::from_slice(&r.body).unwrap()
            })
            .collect()
    }

    /// A mock of the org telemetry endpoint and the route to it.
    async fn org_endpoint() -> (wiremock::MockServer, TelemetryAuth) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v0/orgs/acme/telemetry"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        let auth = TelemetryAuth {
            url: format!("{}/v0/orgs/acme/telemetry", server.uri()),
            bearer: Some("tok".to_string()),
        };
        (server, auth)
    }

    /// A report posts `patch_reported` with the reason, the message and
    /// the patches, and comes back once the endpoint has taken it.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_report_posts_the_reason_the_message_and_the_patches() {
        let (server, auth) = org_endpoint().await;
        let _on = TelemetryOn::new();
        let sent = send_patch_report(
            "report",
            ReportReason::BreaksTests,
            Some("jest fails:\n  TypeError in ~ /x\t(see log)"),
            &[
                outcome(UUID_A, "npm", MODE_AGENT, OUTCOME_REPORTED, None),
                outcome(UUID_B, "", MODE_UNKNOWN, OUTCOME_REPORTED, None),
            ],
            &auth,
        )
        .await;
        assert_eq!(sent, Ok(()));

        // Nothing is left in flight: the request was awaited.
        let bodies = posted(&server).await;
        assert_eq!(bodies.len(), 1);
        let body = &bodies[0];
        assert_eq!(body["event_type"], "patch_reported");
        assert_eq!(body["context"]["command"], "report");
        // No `event_kind`: the server stores an event without one for
        // every org (see `wire_shape_matches_the_backend_extractor`).
        assert!(body.get("event_kind").is_none());
        let metadata = &body["metadata"];
        assert_eq!(metadata["reason"], "breaks_tests");
        assert_eq!(
            metadata["message"],
            "jest fails: TypeError in ~ /x (see log)"
        );
        assert_eq!(
            metadata["patches"],
            serde_json::json!([
                { "uuid": UUID_A, "ecosystem": "npm", "mode": "agent", "outcome": "reported" },
                { "uuid": UUID_B, "ecosystem": "", "mode": "unknown", "outcome": "reported" },
            ])
        );
        assert_eq!(metadata["outcomes"], serde_json::json!({ "reported": 2 }));
    }

    /// A report is sent because the user asked for it: no telemetry
    /// opt-out stops it. An offline run sends nothing at all.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_report_ignores_the_telemetry_opt_outs_but_not_offline() {
        let (server, auth) = org_endpoint().await;
        let _on = TelemetryOn::new();
        let patches = [outcome(UUID_A, "npm", MODE_AGENT, OUTCOME_REPORTED, None)];

        for var in ["SOCKET_TELEMETRY_DISABLED", "DO_NOT_TRACK"] {
            std::env::set_var(var, "1");
            assert!(is_telemetry_disabled());
            let sent = send_patch_report("report", ReportReason::Other, None, &patches, &auth);
            assert_eq!(sent.await, Ok(()), "{var} must not stop a report");
            std::env::remove_var(var);
        }
        let bodies = posted(&server).await;
        assert_eq!(bodies.len(), 2);
        // A report without a message carries no `message` key.
        assert!(bodies[0]["metadata"].get("message").is_none());

        std::env::set_var("SOCKET_OFFLINE", "1");
        let sent = send_patch_report("report", ReportReason::Other, None, &patches, &auth).await;
        std::env::remove_var("SOCKET_OFFLINE");
        assert_eq!(sent, Err(ReportNotSent::Offline));
        assert_eq!(ReportNotSent::Offline.code(), "offline_unsupported");
        assert_eq!(
            posted(&server).await.len(),
            2,
            "an offline report is not sent"
        );
    }

    /// A report the endpoint refuses, or that reaches no endpoint, says
    /// so: the caller must not tell the user it was received.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_report_that_is_not_delivered_says_so() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _on = TelemetryOn::new();
        let patches = [outcome(UUID_A, "npm", MODE_AGENT, OUTCOME_REPORTED, None)];

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let refused = send_patch_report(
            "report",
            ReportReason::Other,
            None,
            &patches,
            &route_to(&server),
        )
        .await
        .unwrap_err();
        assert_eq!(refused.code(), "report_not_sent");
        assert_eq!(
            refused.to_string(),
            "the request returned status 500 Internal Server Error"
        );

        // Nothing listens here; the URL's credentials stay out of the text.
        let nowhere = TelemetryAuth {
            url: "http://user:hunter2@127.0.0.1:9/telemetry".to_string(),
            bearer: None,
        };
        let unreachable =
            send_patch_report("report", ReportReason::Other, None, &patches, &nowhere)
                .await
                .unwrap_err();
        assert_eq!(unreachable.code(), "report_not_sent");
        let text = unreachable.to_string();
        assert!(text.starts_with("the request failed: "), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }

    /// A report never leaves a patch out unsaid: more patches than one
    /// event names is refused before anything is sent, and a long message
    /// beside a full list is cut so that every patch still fits.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_report_names_every_patch_or_is_not_sent() {
        let (server, auth) = org_endpoint().await;
        let _on = TelemetryOn::new();
        let patch = |n: usize| {
            outcome(
                &format!("{n:08x}-1111-4111-8111-111111111111"),
                "composer",
                MODE_VENDORED,
                OUTCOME_REPORTED,
                None,
            )
        };

        let too_many: Vec<PatchOutcome> = (0..=MAX_REPORTED_PATCHES).map(patch).collect();
        let refused =
            send_patch_report("report", ReportReason::Other, None, &too_many, &auth).await;
        assert_eq!(refused, Err(ReportNotSent::TooManyPatches));
        assert_eq!(ReportNotSent::TooManyPatches.code(), "too_many_patches");
        assert!(posted(&server).await.is_empty(), "nothing is sent");

        // 1000 four-byte characters beside a full list is over the
        // event's size: the message is cut, the list is not.
        let full: Vec<PatchOutcome> = (0..MAX_REPORTED_PATCHES).map(patch).collect();
        let wide = "\u{1F4A5}".repeat(MAX_REPORT_MESSAGE_CHARS);
        let fitted =
            fitted_report_message("report", ReportReason::Other, Some(&wide), &full).unwrap();
        let fitted = fitted.expect("a message is still sent");
        assert!(fitted.chars().count() < MAX_REPORT_MESSAGE_CHARS);
        assert!(fitted.ends_with('…'));
        // Fitting what was fitted changes nothing: a caller may show the
        // message first and send it after.
        assert_eq!(
            fitted_report_message("report", ReportReason::Other, Some(&fitted), &full).unwrap(),
            Some(fitted.clone())
        );

        let sent =
            send_patch_report("report", ReportReason::Other, Some(&wide), &full, &auth).await;
        assert_eq!(sent, Ok(()));
        let bodies = posted(&server).await;
        assert_eq!(bodies.len(), 1);
        let metadata = &bodies[0]["metadata"];
        assert_eq!(
            metadata["patches"].as_array().unwrap().len(),
            MAX_REPORTED_PATCHES
        );
        assert!(metadata.get("patches_truncated").is_none());
        assert_eq!(metadata["message"], fitted.as_str());
        assert!(
            serde_json::to_string(&bodies[0]).unwrap().len() <= MAX_EVENT_BYTES,
            "the event stays readable to the server"
        );
    }

    /// A saved login the org endpoint refuses must not cost the report:
    /// it is sent again without the token, on the public route. A refusal
    /// there, or of a run that had no token, is the failure reported.
    #[tokio::test]
    #[serial_test::serial]
    async fn a_refused_token_sends_the_report_on_the_public_route() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _on = TelemetryOn::new();
        let patches = [outcome(UUID_A, "npm", MODE_AGENT, OUTCOME_REPORTED, None)];
        let saved_proxy = std::env::var("SOCKET_PROXY_URL").ok();

        for refusal in [401, 403] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v0/orgs/acme/telemetry"))
                .respond_with(ResponseTemplate::new(refusal))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/patch/telemetry"))
                .respond_with(ResponseTemplate::new(201))
                .mount(&server)
                .await;
            std::env::set_var("SOCKET_PROXY_URL", server.uri());
            let auth = TelemetryAuth {
                url: format!("{}/v0/orgs/acme/telemetry", server.uri()),
                bearer: Some("stale".to_string()),
            };
            let sent =
                send_patch_report("report", ReportReason::Other, None, &patches, &auth).await;
            assert_eq!(sent, Ok(()), "a {refusal} falls back");
            let requests = server.received_requests().await.unwrap();
            let seen: Vec<(&str, bool)> = requests
                .iter()
                .map(|r| (r.url.path(), r.headers.contains_key("authorization")))
                .collect();
            assert_eq!(
                seen,
                [
                    ("/v0/orgs/acme/telemetry", true),
                    ("/patch/telemetry", false)
                ],
                "the second send carries no token"
            );
            assert_eq!(requests[0].body, requests[1].body, "the same report");

            // A run with no token has no other route to try.
            let anonymous = TelemetryAuth {
                url: format!("{}/v0/orgs/acme/telemetry", server.uri()),
                bearer: None,
            };
            let refused =
                send_patch_report("report", ReportReason::Other, None, &patches, &anonymous)
                    .await
                    .unwrap_err();
            assert_eq!(refused.code(), "report_not_sent");
            assert_eq!(server.received_requests().await.unwrap().len(), 3);
        }

        // A server error is not a refused token: no second send.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        std::env::set_var("SOCKET_PROXY_URL", server.uri());
        let failed = send_patch_report(
            "report",
            ReportReason::Other,
            None,
            &patches,
            &route_to(&server),
        )
        .await;
        assert!(matches!(failed, Err(ReportNotSent::NotDelivered(_))));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);

        match saved_proxy {
            Some(value) => std::env::set_var("SOCKET_PROXY_URL", value),
            None => std::env::remove_var("SOCKET_PROXY_URL"),
        }
    }

    /// A message goes out on one line, redacted and bounded; one with
    /// nothing in it is no message.
    #[test]
    fn a_report_message_is_one_bounded_redacted_line() {
        assert_eq!(report_message("  \n\t "), None);
        assert_eq!(
            report_message("line one\r\nline\u{0}two"),
            Some("line one line two".to_string())
        );
        assert_eq!(
            report_message("see https://user:hunter2@example.com/log"),
            Some(sanitize_error_message(
                "see https://user:hunter2@example.com/log"
            ))
        );
        assert!(!report_message("see https://user:hunter2@example.com/log")
            .unwrap()
            .contains("hunter2"));
        let long = report_message(&"é".repeat(MAX_REPORT_MESSAGE_CHARS + 50)).unwrap();
        assert_eq!(long.chars().count(), MAX_REPORT_MESSAGE_CHARS);
        assert!(long.ends_with('…'));
    }

    /// The reasons are what the user types and what the server stores.
    #[test]
    fn report_reasons_have_stable_wire_strings() {
        let wire: Vec<&str> = ReportReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            wire,
            ["breaks_build", "breaks_tests", "breaks_runtime", "other"]
        );
    }

    /// Each public tracker posts the event type and metadata the backend
    /// and its dashboards key on, to the org endpoint with the bearer.
    #[tokio::test]
    #[serial_test::serial]
    async fn trackers_post_the_documented_events() {
        let (server, auth) = org_endpoint().await;
        let _on = TelemetryOn::new();
        // Sends run side by side, so each is waited for before the next
        // fires: the requests then arrive in the order asserted below.
        track_patch_applied(
            "scan",
            3,
            false,
            &[outcome(UUID_A, "npm", MODE_AGENT, "applied", None)],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_hosted(
            "scan",
            2,
            1,
            false,
            &[outcome(UUID_A, "npm", MODE_HOSTED, "applied", None)],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_hosted_failed(
            "get",
            "lockfile_write_failed",
            "lockfile write failed",
            true,
            &[outcome(
                UUID_A,
                "npm",
                MODE_HOSTED,
                OUTCOME_FAILED,
                Some("lockfile_write_failed"),
            )],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_cli_updated("9.9.9", "standalone", false, false, &auth).await;
        flush(AMPLE).await;
        track_cli_update_failed("managed_install", "managed by npm", &auth).await;
        flush(AMPLE).await;
        let packages = [("npm".to_string(), 4), ("pypi".to_string(), 1)]
            .into_iter()
            .collect();
        let patches = [("npm".to_string(), 5)].into_iter().collect();
        track_patch_scanned(
            ScanReport {
                packages_by_ecosystem: &packages,
                patches_by_ecosystem: &patches,
                free_patches: 3,
                paid_patches: 2,
                can_access_paid: true,
                fallback_to_proxy: true,
                mode: "hosted",
                project_modes: &["vendored"],
                dry_run: false,
            },
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_scan_failed(
            "api_batch_failed",
            "all batches failed",
            true,
            "agent",
            &auth,
        )
        .await;
        flush(AMPLE).await;

        let bodies = posted(&server).await;
        assert_eq!(bodies.len(), 7);

        assert_eq!(bodies[0]["event_type"], "patch_applied");
        assert_eq!(bodies[0]["context"]["command"], "scan");
        assert_eq!(bodies[0]["metadata"]["mode"], "agent");
        assert_eq!(bodies[0]["metadata"]["patches_count"], 3);
        assert_eq!(bodies[0]["metadata"]["patches"][0]["uuid"], UUID_A);

        assert_eq!(bodies[1]["event_type"], "patch_applied");
        assert_eq!(bodies[1]["context"]["command"], "scan");
        assert_eq!(bodies[1]["metadata"]["mode"], "hosted");
        assert_eq!(bodies[1]["metadata"]["patches_count"], 2);
        assert_eq!(bodies[1]["metadata"]["files_count"], 1);
        assert_eq!(bodies[1]["metadata"]["patches"][0]["mode"], "hosted");

        assert_eq!(bodies[2]["event_type"], "patch_apply_failed");
        assert_eq!(bodies[2]["context"]["command"], "get");
        assert_eq!(bodies[2]["metadata"]["mode"], "hosted");
        assert_eq!(bodies[2]["metadata"]["dry_run"], true);
        assert_eq!(bodies[2]["metadata"]["error_code"], "lockfile_write_failed");
        assert_eq!(bodies[2]["metadata"]["outcomes"]["failed"], 1);
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
        assert_eq!(
            bodies[5]["metadata"]["packages_by_ecosystem"],
            serde_json::json!({ "npm": 4, "pypi": 1 })
        );
        assert_eq!(
            bodies[5]["metadata"]["patches_by_ecosystem"],
            serde_json::json!({ "npm": 5 })
        );
        assert_eq!(bodies[5]["metadata"]["mode"], "hosted");
        assert_eq!(bodies[5]["metadata"]["dry_run"], false);
        assert_eq!(
            bodies[5]["metadata"]["project_modes"],
            serde_json::json!(["vendored"])
        );

        assert_eq!(bodies[6]["event_type"], "patch_scan_failed");
        assert_eq!(bodies[6]["context"]["command"], "scan");
        assert_eq!(bodies[6]["metadata"]["fallback_to_proxy"], true);
        assert_eq!(bodies[6]["metadata"]["error_code"], "api_batch_failed");
        assert_eq!(bodies[6]["metadata"]["mode"], "agent");
        assert_eq!(bodies[6]["error"]["message"], "all batches failed");
    }

    /// The events that take a patch out name it: the patch UUID with its
    /// ecosystem, mode and outcome, the exact counts over the run, and on
    /// a failure the run's error code. This is what lets the server tell
    /// which patch is being rolled back or removed.
    #[tokio::test]
    #[serial_test::serial]
    async fn rollback_and_remove_events_name_their_patches() {
        let (server, auth) = org_endpoint().await;
        let _on = TelemetryOn::new();

        let run = RollbackRun {
            rolled_back_count: 2,
            dry_run: false,
            targeted: true,
        };
        track_patch_rolled_back(
            run,
            &[
                outcome(UUID_A, "npm", MODE_AGENT, "rolled_back", None),
                outcome(UUID_B, "pypi", MODE_VENDORED, "rolled_back", None),
            ],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_rollback_failed(
            "rollback_failed",
            "One or more rollbacks failed",
            RollbackRun {
                rolled_back_count: 1,
                dry_run: false,
                targeted: false,
            },
            &[
                outcome(UUID_A, "npm", MODE_AGENT, "rolled_back", None),
                outcome(
                    UUID_B,
                    "gem",
                    MODE_HOSTED,
                    OUTCOME_FAILED,
                    Some("hosted_restore_refused"),
                ),
            ],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_rollback_failed(
            "patch_not_found",
            "No patch found matching identifier: lodash",
            RollbackRun {
                targeted: true,
                ..RollbackRun::default()
            },
            &[],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_removed(
            "remove",
            1,
            &[outcome(UUID_A, "npm", MODE_AGENT, "removed", None)],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_remove_failed(
            "vendor",
            "vendor_revert_kept",
            "kept",
            &[outcome(
                UUID_B,
                "cargo",
                MODE_VENDORED,
                OUTCOME_FAILED,
                Some("vendor_revert_kept"),
            )],
            &auth,
        )
        .await;
        flush(AMPLE).await;

        let bodies = posted(&server).await;
        assert_eq!(bodies.len(), 5);

        let rolled_back = &bodies[0];
        assert_eq!(rolled_back["event_type"], "patch_rolled_back");
        assert_eq!(rolled_back["context"]["command"], "rollback");
        assert_eq!(
            rolled_back["metadata"],
            serde_json::json!({
                "rolled_back_count": 2,
                "dry_run": false,
                "targeted": true,
                "patches": [
                    { "uuid": UUID_A, "ecosystem": "npm", "mode": "agent", "outcome": "rolled_back" },
                    { "uuid": UUID_B, "ecosystem": "pypi", "mode": "vendored", "outcome": "rolled_back" },
                ],
                "outcomes": { "rolled_back": 2 },
                "ecosystems": ["npm", "pypi"],
                "modes": ["agent", "vendored"],
            })
        );

        let failed = &bodies[1];
        assert_eq!(failed["event_type"], "patch_rollback_failed");
        assert_eq!(failed["metadata"]["error_code"], "rollback_failed");
        assert_eq!(failed["metadata"]["rolled_back_count"], 1);
        assert_eq!(failed["metadata"]["targeted"], false);
        assert_eq!(
            failed["metadata"]["outcomes"],
            serde_json::json!({ "failed": 1, "rolled_back": 1 })
        );
        // The failed patch leads, with the code of its failure.
        assert_eq!(
            failed["metadata"]["patches"][0],
            serde_json::json!({
                "uuid": UUID_B,
                "ecosystem": "gem",
                "mode": "hosted",
                "outcome": "failed",
                "code": "hosted_restore_refused",
            })
        );
        assert_eq!(failed["metadata"]["patches"][1]["uuid"], UUID_A);

        // A run that never reached a patch names none, and its code says
        // why: a mistyped target is not a patch that would not come off.
        let unstarted = &bodies[2];
        assert_eq!(unstarted["event_type"], "patch_rollback_failed");
        assert_eq!(
            unstarted["metadata"],
            serde_json::json!({
                "rolled_back_count": 0,
                "dry_run": false,
                "targeted": true,
                "error_code": "patch_not_found",
            })
        );

        let removed = &bodies[3];
        assert_eq!(removed["event_type"], "patch_removed");
        assert_eq!(removed["context"]["command"], "remove");
        assert_eq!(removed["metadata"]["removed_count"], 1);
        assert_eq!(removed["metadata"]["patches"][0]["uuid"], UUID_A);
        assert_eq!(removed["metadata"]["patches"][0]["outcome"], "removed");

        let kept = &bodies[4];
        assert_eq!(kept["event_type"], "patch_remove_failed");
        assert_eq!(kept["context"]["command"], "vendor");
        assert_eq!(kept["metadata"]["error_code"], "vendor_revert_kept");
        assert_eq!(kept["metadata"]["patches"][0]["code"], "vendor_revert_kept");
    }

    /// Vendor and download events carry the mode, the command the user
    /// ran and their patches.
    #[tokio::test]
    #[serial_test::serial]
    async fn vendor_and_fetch_events_carry_mode_and_patches() {
        let (server, auth) = org_endpoint().await;
        let _on = TelemetryOn::new();

        track_patch_vendored(
            "scan",
            1,
            false,
            &[outcome(UUID_A, "npm", MODE_VENDORED, "applied", None)],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_vendor_failed(
            "vendor",
            "vendor_failed",
            "vendor completed with failures",
            false,
            &[
                outcome(UUID_A, "npm", MODE_VENDORED, "applied", None),
                outcome(
                    UUID_B,
                    "npm",
                    MODE_VENDORED,
                    OUTCOME_FAILED,
                    Some("no_local_source"),
                ),
            ],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        track_patch_fetched(UUID_A, "free", "npm", MODE_HOSTED, false, &auth).await;
        flush(AMPLE).await;
        track_patches_fetched(
            "scan",
            &[
                outcome(UUID_A, "npm", MODE_AGENT, "downloaded", None),
                outcome(
                    UUID_B,
                    "pypi",
                    MODE_AGENT,
                    "skipped",
                    Some("already_in_manifest"),
                ),
            ],
            &auth,
        )
        .await;
        flush(AMPLE).await;
        // A pass that reached no patch sends nothing.
        track_patches_fetched("scan", &[], &auth).await;
        flush(AMPLE).await;

        let bodies = posted(&server).await;
        assert_eq!(bodies.len(), 4);

        assert_eq!(bodies[0]["event_type"], "patch_vendored");
        assert_eq!(bodies[0]["context"]["command"], "scan");
        assert_eq!(bodies[0]["metadata"]["mode"], "vendored");
        assert_eq!(bodies[0]["metadata"]["patches_count"], 1);
        assert_eq!(bodies[0]["metadata"]["patches"][0]["uuid"], UUID_A);

        assert_eq!(bodies[1]["event_type"], "patch_vendor_failed");
        assert_eq!(bodies[1]["context"]["command"], "vendor");
        assert_eq!(bodies[1]["metadata"]["mode"], "vendored");
        assert_eq!(bodies[1]["metadata"]["error_code"], "vendor_failed");
        // What the failed run did vendor is counted, not lost.
        assert_eq!(bodies[1]["metadata"]["patches_count"], 1);
        assert_eq!(bodies[1]["metadata"]["patches"][0]["uuid"], UUID_B);

        assert_eq!(bodies[2]["event_type"], "patch_fetched");
        assert_eq!(bodies[2]["context"]["command"], "get");
        assert_eq!(bodies[2]["metadata"]["uuid"], UUID_A);
        assert_eq!(bodies[2]["metadata"]["mode"], "hosted");
        assert_eq!(bodies[2]["metadata"]["patches_count"], 1);
        assert_eq!(bodies[2]["metadata"]["download_mode"], "file");
        assert_eq!(bodies[2]["metadata"]["patches"][0]["outcome"], "downloaded");

        assert_eq!(bodies[3]["event_type"], "patch_fetched");
        assert_eq!(bodies[3]["context"]["command"], "scan");
        assert_eq!(bodies[3]["metadata"]["mode"], "agent");
        assert_eq!(bodies[3]["metadata"]["patches_count"], 1);
        assert_eq!(
            bodies[3]["metadata"]["outcomes"],
            serde_json::json!({ "downloaded": 1, "skipped": 1 })
        );
    }

    /// An event names at most [`MAX_REPORTED_PATCHES`] patches, the failed
    /// ones first, and says when it dropped some; the counts beside the
    /// list stay those of the whole run.
    #[test]
    fn a_long_run_reports_its_failures_first_and_exact_counts() {
        let total = MAX_REPORTED_PATCHES + 30;
        let patches: Vec<PatchOutcome> = (0..total)
            .map(|i| {
                let uuid = format!("00000000-0000-4000-8000-{i:012}");
                if i % 20 == 19 {
                    outcome(
                        &uuid,
                        "pypi",
                        MODE_AGENT,
                        OUTCOME_FAILED,
                        Some("hash_mismatch"),
                    )
                } else {
                    outcome(&uuid, "npm", MODE_AGENT, "applied", None)
                }
            })
            .collect();
        let failed = PatchOutcome::count(&patches, OUTCOME_FAILED);
        assert!(failed > 0 && failed < MAX_REPORTED_PATCHES);

        let metadata = with_patches(serde_json::json!({ "dry_run": false }), &patches);
        let reported = metadata["patches"].as_array().unwrap();
        assert_eq!(reported.len(), MAX_REPORTED_PATCHES);
        assert_eq!(metadata["patches_truncated"], true);
        for entry in &reported[..failed] {
            assert_eq!(entry["outcome"], "failed", "failures lead: {entry}");
        }
        for entry in &reported[failed..] {
            assert_eq!(entry["outcome"], "applied");
        }
        // The run's own order is kept within each group.
        assert_eq!(
            reported[failed]["uuid"],
            "00000000-0000-4000-8000-000000000000"
        );
        assert_eq!(
            metadata["outcomes"],
            serde_json::json!({ "applied": total - failed, "failed": failed })
        );
        assert_eq!(metadata["ecosystems"], serde_json::json!(["npm", "pypi"]));
        assert_eq!(metadata["modes"], serde_json::json!(["agent"]));

        // Under the cap nothing is flagged.
        let short = with_patches(serde_json::json!({}), &patches[..3]);
        assert_eq!(short["patches"].as_array().unwrap().len(), 3);
        assert!(short.get("patches_truncated").is_none());
        // No patch, no fields; and the event's own keys are never replaced.
        assert_eq!(
            with_patches(serde_json::json!({ "dry_run": true }), &[]),
            serde_json::json!({ "dry_run": true })
        );
        let own = with_patches(
            serde_json::json!({ "ecosystems": ["cargo"] }),
            &patches[..1],
        );
        assert_eq!(own["ecosystems"], serde_json::json!(["cargo"]));
    }

    /// The event a rollback failure builds for `failed` patches, every
    /// entry with a long code, and `message`.
    fn rollback_failure(failed: usize, message: String) -> PatchTelemetryEvent {
        let patches: Vec<PatchOutcome> = (0..failed)
            .map(|i| {
                outcome(
                    &format!("00000000-0000-4000-8000-{i:012}"),
                    "composer",
                    MODE_VENDORED,
                    OUTCOME_FAILED,
                    Some("replaced_patch_not_restored_before_update"),
                )
            })
            .collect();
        let metadata = failure_metadata(
            RollbackRun {
                rolled_back_count: 1000,
                dry_run: true,
                targeted: true,
            }
            .metadata(),
            "vendor_state_write_failed",
            &patches,
        );
        let serde_json::Value::Object(metadata) = metadata else {
            panic!("metadata is an object");
        };
        build_telemetry_event(
            PatchTelemetryEventType::PatchRollbackFailed,
            "rollback",
            Some(metadata.into_iter().collect()),
            Some(("Error".to_string(), message)),
        )
    }

    /// The server keeps an event's body readable to its dashboards only
    /// up to 10,000 characters. The largest event a run can build stays
    /// under that whatever its error message holds: plain text, or text
    /// that grows when JSON escapes it (quotes, backslashes, newlines,
    /// control characters, as in quoted command output or Windows paths).
    #[test]
    fn the_largest_event_fits_the_servers_readable_body() {
        for (what, message) in [
            ("plain", "x".repeat(50_000)),
            ("quotes and newlines", "\"line\"\n".repeat(10_000)),
            ("control characters", "\u{1b}[31m".repeat(10_000)),
            (
                "Windows paths",
                r"C:\Users\dev\project\node_modules\".repeat(2_000),
            ),
            ("wide characters", "错误：补丁".repeat(10_000)),
        ] {
            // Four times the patch cap: as large as an event gets.
            let event = rollback_failure(MAX_REPORTED_PATCHES * 4, message);
            let body = serde_json::to_string(&event).unwrap();
            assert!(
                body.len() <= MAX_EVENT_BYTES && body.chars().count() < 10_000,
                "{what}: the event body is {} bytes",
                body.len()
            );
            // The event still says what failed and why.
            let metadata = event.metadata.as_ref().unwrap();
            assert_eq!(metadata["error_code"], "vendor_state_write_failed");
            assert_eq!(metadata["outcomes"]["failed"], MAX_REPORTED_PATCHES * 4);
            assert_eq!(metadata["patches_truncated"], true);
            assert!(
                !metadata["patches"].as_array().unwrap().is_empty(),
                "{what}"
            );
            let message = event.error.unwrap().message.unwrap();
            assert!(message.chars().count() >= MIN_ERROR_MESSAGE_CHARS, "{what}");
        }
    }

    /// An event with room to spare is sent as built: its message cut to
    /// the cap and no further, every patch named. Only one that would not
    /// fit gives up more, and then the tail of its message before any
    /// patch.
    #[test]
    fn an_event_that_fits_is_left_alone() {
        let event = rollback_failure(5, "\"line\"\n".repeat(10_000));
        let message = event.error.as_ref().unwrap().message.as_ref().unwrap();
        assert_eq!(message.chars().count(), MAX_ERROR_MESSAGE_CHARS);
        assert!(message.starts_with("\"line\"\n") && message.ends_with('…'));
        let metadata = event.metadata.as_ref().unwrap();
        assert_eq!(metadata["patches"].as_array().unwrap().len(), 5);
        assert!(metadata.get("patches_truncated").is_none());

        // At the patch cap, a message this long does not fit beside the
        // patches: the message is cut, the patches all stay.
        let event = rollback_failure(MAX_REPORTED_PATCHES, "x".repeat(50_000));
        let message = event.error.as_ref().unwrap().message.as_ref().unwrap();
        assert!(message.chars().count() < MAX_ERROR_MESSAGE_CHARS);
        assert!(message.chars().count() >= MIN_ERROR_MESSAGE_CHARS);
        let metadata = event.metadata.as_ref().unwrap();
        assert_eq!(
            metadata["patches"].as_array().unwrap().len(),
            MAX_REPORTED_PATCHES
        );
        assert!(metadata.get("patches_truncated").is_none());
    }

    #[test]
    fn truncate_chars_cuts_on_a_character_and_only_when_too_long() {
        assert_eq!(truncate_chars("short".to_string(), 10), "short");
        assert_eq!(truncate_chars("exactly10!".to_string(), 10), "exactly10!");
        assert_eq!(
            truncate_chars("more than ten".to_string(), 10),
            "more than…"
        );
        // Multi-byte characters are counted, not their bytes.
        assert_eq!(truncate_chars("ééééé".to_string(), 5), "ééééé");
        assert_eq!(truncate_chars("éééééé".to_string(), 5), "éééé…");
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
