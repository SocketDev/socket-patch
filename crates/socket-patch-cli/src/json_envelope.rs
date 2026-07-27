//! Unified JSON output envelope shared across every subcommand.
//!
//! Every `--json` invocation of socket-patch (whether `scan`, `apply`,
//! `get`, `list`, `gc`/`repair`, `remove`, or `rollback`) emits the same
//! top-level shape:
//!
//! ```json
//! {
//!   "command":  "scan" | "apply" | "get" | ...,
//!   "status":   "success" | "partialFailure" | "error" | "noManifest" | ...,
//!   "dryRun":   false,
//!   "events":   [ { "action": "...", "purl": "...", ... }, ... ],
//!   "summary":  { "applied": 0, "downloaded": 0, ... }
//!   // "error":  { "code": ..., "message": ... }  — present only on failure
//! }
//! ```
//!
//! The `events` array is the load-bearing payload — each entry describes
//! one observable thing that happened during the run (a patch was
//! downloaded, applied, skipped, etc.). A downstream consumer (PR-comment
//! bot, dashboard, log shipper) only needs to learn this single vocabulary
//! to interpret output from every subcommand.
//!
//! See `CLI_CONTRACT.md` for the per-subcommand action matrix and example
//! `jq` recipes.

use serde::Serialize;

pub use socket_patch_core::patch::sidecars::{SidecarFile, SidecarFileAction, SidecarRecord};

/// Top-level JSON envelope emitted by every `--json` invocation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    /// Which subcommand produced this output. Lets a generic consumer
    /// (one that doesn't know which subcommand it's piping) route on it.
    pub command: Command,
    /// High-level success/failure summary. Use `Status::PartialFailure`
    /// when at least one event has `action = Failed` but the run as a
    /// whole completed.
    pub status: Status,
    /// True if the command was a preview (`--dry-run`, `--prune-dry-run`,
    /// etc.). When true, `events` describe what *would* happen — no disk
    /// state was modified.
    pub dry_run: bool,
    /// Per-patch (and per-artifact) observations from the run. Ordering
    /// is best-effort: events appear in the order the engine produced
    /// them, but downstream consumers should not rely on it.
    pub events: Vec<PatchEvent>,
    /// Aggregate counts derived from `events`. Pre-computed so consumers
    /// don't need to re-walk the array.
    pub summary: Summary,
    /// Set when the command itself failed before producing meaningful
    /// events (manifest unreadable, network unreachable in non-offline
    /// mode, etc.). Implies `events` is empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<EnvelopeError>,
    /// Per-package sidecar fixup records. Each entry describes what
    /// the post-apply integrity fixup did for one package — rewriting
    /// `.cargo-checksum.json`, deleting `.nupkg.metadata`, surfacing
    /// an advisory for PyPI / gem / Go, etc.
    ///
    /// Top-level (not per-event) so consumers can iterate sidecar
    /// outcomes directly with `jq '.sidecars[]'`. Records carry
    /// `purl` so a consumer that needs the matching apply event can
    /// JOIN against `events[]`.
    ///
    /// Empty (and omitted from JSON via `skip_serializing_if`) for
    /// commands that don't surface sidecar records here — `rollback`
    /// reports its sidecar *resync* per-result in its own envelope,
    /// `repair`/`list` produce no sidecar work — and for apply runs
    /// against ecosystems with no sidecar contract (e.g. npm).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sidecars: Vec<SidecarRecord>,
    /// Run-level advisories that are about the PROJECT's state rather than
    /// any single package (e.g. `yarn_classic_berry_migration_risk`: the
    /// wired classic lockfile would be silently de-patched by a yarn 2+
    /// install). Distinct from per-purl `events` — consumers alert on these
    /// without attributing them to a package. Empty (and omitted from JSON)
    /// for runs with nothing to advise, so existing consumers see byte-
    /// identical output.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<RunWarning>,
    /// Present only when `--vex <path>` was passed to `apply`/`scan` and
    /// an OpenVEX document was successfully generated as a side-effect of
    /// the run. Describes where it landed and how many statements it
    /// carries. A *failed* embedded VEX generation surfaces via `error`
    /// (and flips the exit code), not here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vex: Option<VexSummary>,
}

/// Summary of an OpenVEX document emitted as a side-effect of an
/// `apply`/`scan` run via `--vex`. The full document is written to
/// `path`; this is just the pointer + headline count for JSON consumers.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VexSummary {
    /// Filesystem path the OpenVEX document was written to.
    pub path: String,
    /// Number of OpenVEX statements in the document.
    pub statements: usize,
    /// Document format tag, e.g. `"openvex-0.2.0"`.
    pub format: String,
}

impl Envelope {
    /// Build a fresh envelope. `summary` starts at zero — callers are
    /// expected to push events with `Envelope::record` (or update fields
    /// directly) so summary stays consistent with the event list.
    pub fn new(command: Command) -> Self {
        Self {
            command,
            status: Status::Success,
            dry_run: false,
            events: Vec::new(),
            summary: Summary::default(),
            error: None,
            sidecars: Vec::new(),
            warnings: Vec::new(),
            vex: None,
        }
    }

    /// Append an event and bump the matching summary counter. Centralizes
    /// the "events list must agree with summary counts" invariant so per-
    /// command code can't drift.
    ///
    /// Recording a `Failed` event also marks the run as a partial failure
    /// (unless it's already a hard `Error`), enforcing the `status`
    /// invariant documented on [`Envelope::status`] here rather than
    /// relying on every command to remember a follow-up
    /// `mark_partial_failure` call. A run can never end up reporting
    /// `Success` while carrying a `Failed` event.
    pub fn record(&mut self, event: PatchEvent) {
        self.summary.bump(event.action);
        if matches!(event.action, PatchAction::Failed) {
            self.mark_partial_failure();
        }
        self.events.push(event);
    }

    /// Mark the run as a partial failure. Idempotent.
    pub fn mark_partial_failure(&mut self) {
        if !matches!(self.status, Status::Error) {
            self.status = Status::PartialFailure;
        }
    }

    /// Mark the run as a top-level error (replaces any prior status).
    pub fn mark_error(&mut self, error: EnvelopeError) {
        self.status = Status::Error;
        self.error = Some(error);
    }

    /// Serialize as pretty JSON for printing.
    pub fn to_pretty_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("envelope serialize")
    }
}

/// One observable thing that happened during a run.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchEvent {
    /// What happened. See [`PatchAction`] for the full vocabulary.
    pub action: PatchAction,
    /// The package PURL this event is about, when applicable. Always set
    /// for patch-level events; omitted for artifact-level events that
    /// don't trace to a specific package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
    /// The patch UUID, when known. Always set when the event is about a
    /// specific patch record; omitted for cleanup events that affect
    /// many patches at once.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// The UUID this patch replaced. Set only on `Updated` events so a
    /// consumer can diff a manifest update — the new UUID lives in
    /// `uuid`, the one it overwrote here. Omitted for every other action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_uuid: Option<String>,
    /// Files touched by an `Applied` / `Verified` / `Removed` event.
    /// Empty for actions that don't operate on files (e.g. `Downloaded`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<PatchEventFile>,
    /// Human-readable explanation for `Skipped` or `Failed` events.
    /// Machine consumers should prefer `error_code` for routing decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Stable, lowercase, snake_case reason tag for programmatic routing.
    /// Examples: `already_patched`, `package_not_installed`,
    /// `hash_mismatch`, `no_local_source`, `paid_required`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Underlying error message for `Failed` events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Command-specific additional fields. Consumers MUST NOT depend on
    /// the shape of this object — different subcommands attach different
    /// keys here. Used today for `list` (vulnerabilities, license, tier,
    /// description) and `scan` (discovered metadata not covered by the
    /// other event fields).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl PatchEvent {
    /// Construct an event with only the required `action` and `purl`.
    /// Use the `with_*` builders to attach optional fields.
    pub fn new(action: PatchAction, purl: impl Into<String>) -> Self {
        Self {
            purl: Some(purl.into()),
            ..Self::artifact(action)
        }
    }

    /// Construct an event that isn't scoped to a single package (e.g. a
    /// repair run that swept orphan blobs).
    pub fn artifact(action: PatchAction) -> Self {
        Self {
            action,
            purl: None,
            uuid: None,
            old_uuid: None,
            files: Vec::new(),
            reason: None,
            error_code: None,
            error: None,
            details: None,
        }
    }

    pub fn with_uuid(mut self, uuid: impl Into<String>) -> Self {
        self.uuid = Some(uuid.into());
        self
    }

    /// Attach the UUID this event's patch replaced. Use on `Updated`
    /// events so consumers can diff against the prior manifest entry;
    /// serializes as `oldUuid`.
    pub fn with_old_uuid(mut self, old_uuid: impl Into<String>) -> Self {
        self.old_uuid = Some(old_uuid.into());
        self
    }

    pub fn with_files(mut self, files: Vec<PatchEventFile>) -> Self {
        self.files = files;
        self
    }

    pub fn with_reason(mut self, code: impl Into<String>, message: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self.reason = Some(message.into());
        self
    }

    pub fn with_error(mut self, code: impl Into<String>, message: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self.error = Some(message.into());
        self
    }

    /// Attach command-specific extra fields. See [`PatchEvent::details`]
    /// for the contract — consumers should not depend on the shape.
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// One file referenced by a patch event.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchEventFile {
    /// Path relative to the package directory (e.g. `package/index.js`).
    pub path: String,
    /// True if the file's content was verified to match the expected
    /// hash. For an `Applied` event this means post-write verification
    /// succeeded; for `Verified` (dry-run) it means pre-write hashes
    /// matched expectation.
    pub verified: bool,
    /// Which strategy produced the patched bytes — only set for `Applied`
    /// events. One of `package`, `diff`, `blob`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_via: Option<AppliedVia>,
}

/// What kind of thing happened to a patch.
///
/// Serializes to camelCase strings — e.g. `Applied` → `"applied"`,
/// `Downloaded` → `"downloaded"` (a hypothetical multi-word variant would
/// lower-camel, e.g. `FooBar` → `"fooBar"`). The full vocabulary is part of
/// the CLI contract; new variants are MINOR-safe but renames are MAJOR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PatchAction {
    /// `scan`: a patch exists upstream for this package, but no action
    /// taken yet (no `--apply` / `--sync`).
    Discovered,
    /// `get` / `scan --apply` / `apply` (online): patch bytes were
    /// fetched from the registry.
    Downloaded,
    /// `apply` / `scan --sync`: patch was applied to disk. `files`
    /// enumerates which files changed.
    Applied,
    /// `apply` / `scan --sync`: patch replaced an older patch (the
    /// manifest already had a different UUID for this PURL). `oldUuid`
    /// carries the previous UUID.
    Updated,
    /// `apply` / `scan` / `get`: the patch was a no-op — already
    /// applied, not in scope, or filtered out. `errorCode` carries the
    /// reason tag.
    Skipped,
    /// Any command: an attempt failed. `errorCode` is the routing tag,
    /// `error` is the human message.
    Failed,
    /// `gc` / `repair` / `remove` / `rollback`: data was removed from
    /// `.socket/` (or from disk in the rollback case).
    Removed,
    /// `apply --dry-run` / `scan --dry-run`: patch *would* apply
    /// cleanly. `files` lists what would change.
    Verified,
    /// `repair`: a missing/corrupt vendored artifact was rebuilt in place
    /// from verified sources (lockfiles and the vendor ledger untouched
    /// unless drift was healed).
    Rebuilt,
}

/// Patch-source strategy used to apply a file. Mirrors the existing
/// `socket_patch_core::patch::apply::AppliedVia` enum, but lives here so
/// the JSON layer doesn't depend on core internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AppliedVia {
    Package,
    Diff,
    Blob,
}

impl AppliedVia {
    pub fn from_core(via: socket_patch_core::patch::apply::AppliedVia) -> Self {
        use socket_patch_core::patch::apply::AppliedVia as Core;
        match via {
            Core::Package => AppliedVia::Package,
            Core::Diff => AppliedVia::Diff,
            Core::Blob => AppliedVia::Blob,
        }
    }
}

/// Which subcommand produced the envelope. Serializes lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Command {
    Scan,
    Apply,
    Vex,
    Vendor,
    Setup,
    Rollback,
    Get,
    List,
    Remove,
    Repair,
    /// `--update` (the hidden `self-update` subcommand).
    Update,
}

/// Top-level status. Serializes camelCase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Success,
    PartialFailure,
    Error,
    /// Special case for `apply`: the manifest doesn't exist yet, so
    /// there's nothing to apply. Distinct from `Success` because some
    /// consumers want to early-exit on this state.
    NoManifest,
    /// `get` / `scan`: the requested patch requires a paid plan but the
    /// caller's API token isn't entitled. Distinct from `Error` so PR
    /// bots can post a "upgrade your plan" comment instead of failing.
    PaidRequired,
    /// `remove` / `rollback`: the patch identifier didn't resolve to
    /// anything in the local manifest.
    NotFound,
}

/// Pre-aggregated counts across all events in this envelope. Field names
/// match `PatchAction` variants for clarity.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub discovered: u32,
    pub downloaded: u32,
    pub applied: u32,
    pub updated: u32,
    pub skipped: u32,
    pub failed: u32,
    pub removed: u32,
    pub verified: u32,
    /// `repair`-only (vendored artifact rebuilds); omitted while zero so
    /// every other command's summary shape is unchanged.
    #[serde(skip_serializing_if = "u32_is_zero")]
    pub rebuilt: u32,
}

fn u32_is_zero(n: &u32) -> bool {
    *n == 0
}

impl Summary {
    fn bump(&mut self, action: PatchAction) {
        match action {
            PatchAction::Discovered => self.discovered += 1,
            PatchAction::Downloaded => self.downloaded += 1,
            PatchAction::Applied => self.applied += 1,
            PatchAction::Updated => self.updated += 1,
            PatchAction::Skipped => self.skipped += 1,
            PatchAction::Failed => self.failed += 1,
            PatchAction::Removed => self.removed += 1,
            PatchAction::Verified => self.verified += 1,
            PatchAction::Rebuilt => self.rebuilt += 1,
        }
    }
}

/// Top-level error payload set when the command failed before producing
/// patch events.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeError {
    /// Routing tag — examples: `manifest_unreadable`, `network_error`,
    /// `not_found`, `paid_required`.
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

impl EnvelopeError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// One run-level advisory (see [`Envelope::warnings`]). Same `code`/`detail`
/// vocabulary as per-event reasons, but scoped to the whole project/run.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunWarning {
    /// Stable routing tag, e.g. `yarn_classic_berry_migration_risk`.
    pub code: String,
    /// Human-readable explanation with the suggested remediation.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Tests — pin the JSON serialization shape that downstream consumers see.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_tags_round_trip() {
        // Each variant's serde representation must match the
        // documented snake_case tag.
        for (action, tag) in [
            (PatchAction::Discovered, "discovered"),
            (PatchAction::Downloaded, "downloaded"),
            (PatchAction::Applied, "applied"),
            (PatchAction::Updated, "updated"),
            (PatchAction::Skipped, "skipped"),
            (PatchAction::Failed, "failed"),
            (PatchAction::Removed, "removed"),
            (PatchAction::Verified, "verified"),
        ] {
            let serialized = serde_json::to_string(&action).unwrap();
            assert_eq!(serialized, format!("\"{tag}\""));
        }
    }

    #[test]
    fn empty_envelope_has_stable_shape() {
        let env = Envelope::new(Command::Scan);
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        keys.sort();
        // `error` is skipped when None, so it shouldn't appear.
        assert_eq!(
            keys,
            vec!["command", "dryRun", "events", "status", "summary"]
        );
        assert_eq!(v["command"], "scan");
        assert_eq!(v["status"], "success");
        assert_eq!(v["dryRun"], false);
        assert_eq!(v["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn record_keeps_summary_in_sync() {
        let mut env = Envelope::new(Command::Apply);
        env.record(PatchEvent::new(PatchAction::Applied, "pkg:npm/foo@1.0.0"));
        env.record(PatchEvent::new(
            PatchAction::Downloaded,
            "pkg:npm/foo@1.0.0",
        ));
        env.record(
            PatchEvent::new(PatchAction::Skipped, "pkg:npm/bar@2.0.0")
                .with_reason("already_patched", "Files match afterHash"),
        );

        assert_eq!(env.summary.applied, 1);
        assert_eq!(env.summary.downloaded, 1);
        assert_eq!(env.summary.skipped, 1);
        assert_eq!(env.events.len(), 3);
    }

    #[test]
    fn recording_failed_event_marks_partial_failure() {
        // The `status` invariant — "PartialFailure when any event has
        // action = Failed" — must be enforced by `record` itself, not
        // left to each command to remember. Otherwise a Success envelope
        // can carry a `failed` event (and a non-zero `summary.failed`).
        let mut env = Envelope::new(Command::Apply);
        env.record(PatchEvent::new(PatchAction::Applied, "pkg:npm/foo@1.0.0"));
        assert_eq!(env.status, Status::Success);
        env.record(
            PatchEvent::new(PatchAction::Failed, "pkg:npm/bar@2.0.0")
                .with_error("apply_failed", "boom"),
        );
        assert_eq!(env.status, Status::PartialFailure);
        assert_eq!(env.summary.failed, 1);
    }

    #[test]
    fn recording_failed_event_does_not_demote_hard_error() {
        // A prior hard error outranks the per-event partial failure that
        // `record` raises — recording a Failed event must not downgrade
        // Error to PartialFailure regardless of ordering.
        let mut env = Envelope::new(Command::Apply);
        env.mark_error(EnvelopeError::new("manifest_unreadable", "bad json"));
        env.record(
            PatchEvent::new(PatchAction::Failed, "pkg:npm/bar@2.0.0")
                .with_error("apply_failed", "boom"),
        );
        assert_eq!(env.status, Status::Error);
    }

    #[test]
    fn updated_event_carries_old_uuid() {
        // The CLI contract promises `oldUuid` on `updated` events. The
        // new UUID lives in `uuid`; the replaced one in `oldUuid`.
        let event = PatchEvent::new(PatchAction::Updated, "pkg:npm/foo@1.0.0")
            .with_uuid("uuid-new")
            .with_old_uuid("uuid-old");
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "updated");
        assert_eq!(v["uuid"], "uuid-new");
        assert_eq!(v["oldUuid"], "uuid-old");
    }

    #[test]
    fn old_uuid_omitted_when_unset() {
        // Non-Updated events must not leak an `oldUuid` key.
        let event = PatchEvent::new(PatchAction::Applied, "pkg:npm/foo@1.0.0");
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert!(!v.as_object().unwrap().contains_key("oldUuid"));
    }

    #[test]
    fn skipped_event_omits_uuid_and_files() {
        let event = PatchEvent::new(PatchAction::Skipped, "pkg:npm/foo@1.0.0")
            .with_reason("package_not_installed", "no matching package on disk");
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("uuid"));
        assert!(!obj.contains_key("files"));
        assert!(!obj.contains_key("oldUuid"));
        assert!(!obj.contains_key("error"));
        assert_eq!(
            obj.get("errorCode").and_then(|v| v.as_str()),
            Some("package_not_installed")
        );
        assert_eq!(
            obj.get("reason").and_then(|v| v.as_str()),
            Some("no matching package on disk")
        );
    }

    #[test]
    fn applied_event_with_files_includes_applied_via() {
        let event = PatchEvent::new(PatchAction::Applied, "pkg:npm/foo@1.0.0")
            .with_uuid("uuid-2222")
            .with_files(vec![
                PatchEventFile {
                    path: "package/index.js".into(),
                    verified: true,
                    applied_via: Some(AppliedVia::Diff),
                },
                PatchEventFile {
                    path: "package/lib/util.js".into(),
                    verified: true,
                    applied_via: Some(AppliedVia::Blob),
                },
            ]);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0]["path"], "package/index.js");
        assert_eq!(files[0]["verified"], true);
        assert_eq!(files[0]["appliedVia"], "diff");
        assert_eq!(files[1]["appliedVia"], "blob");
    }

    #[test]
    fn mark_partial_failure_does_not_clobber_error() {
        let mut env = Envelope::new(Command::Apply);
        env.mark_error(EnvelopeError::new("manifest_unreadable", "bad json"));
        env.mark_partial_failure();
        // mark_error wins — we don't want a sequence of marks to demote
        // a hard error to a partial failure.
        assert_eq!(env.status, Status::Error);
    }

    #[test]
    fn top_level_error_serializes_inline() {
        let mut env = Envelope::new(Command::Get);
        env.mark_error(EnvelopeError::new(
            "paid_required",
            "Patch requires paid plan",
        ));
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "error");
        assert_eq!(v["error"]["code"], "paid_required");
        assert_eq!(v["error"]["message"], "Patch requires paid plan");
    }

    #[test]
    fn status_serializes_camel_case() {
        // PartialFailure is the high-traffic one — confirm camelCase.
        let mut env = Envelope::new(Command::Apply);
        env.mark_partial_failure();
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "partialFailure");
    }

    #[test]
    fn artifact_event_omits_purl() {
        // GC sweep events aren't scoped to a single PURL.
        let event = PatchEvent::artifact(PatchAction::Removed)
            .with_reason("orphan_blob", "Blob not referenced by any manifest entry");
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("purl"));
        assert_eq!(obj["action"], "removed");
        assert_eq!(obj["errorCode"], "orphan_blob");
    }

    #[test]
    fn each_action_bumps_exactly_its_own_counter() {
        // Guards the 1:1 `Summary::bump` mapping. Recording one event of
        // every action must leave each counter at exactly 1 — a swapped
        // arm (e.g. `Updated` bumping `skipped`) would leave one field at
        // 0 and another at 2. The prior test only checked 3 of 8 counters
        // and never asserted the untouched ones stayed zero, so a swap
        // among {discovered, updated, removed, verified} went unnoticed.
        let mut env = Envelope::new(Command::Scan);
        for action in [
            PatchAction::Discovered,
            PatchAction::Downloaded,
            PatchAction::Applied,
            PatchAction::Updated,
            PatchAction::Skipped,
            PatchAction::Failed,
            PatchAction::Removed,
            PatchAction::Verified,
        ] {
            env.record(PatchEvent::new(action, "pkg:npm/foo@1.0.0"));
        }
        let s = &env.summary;
        assert_eq!(s.discovered, 1, "discovered");
        assert_eq!(s.downloaded, 1, "downloaded");
        assert_eq!(s.applied, 1, "applied");
        assert_eq!(s.updated, 1, "updated");
        assert_eq!(s.skipped, 1, "skipped");
        assert_eq!(s.failed, 1, "failed");
        assert_eq!(s.removed, 1, "removed");
        assert_eq!(s.verified, 1, "verified");
        assert_eq!(env.events.len(), 8);

        // And the same mapping must survive serialization with the
        // documented camelCase field names — pins both the bump arm and
        // the `rename_all` so a consumer reading `summary.removed` can't
        // silently get `verified`'s count.
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        for field in [
            "discovered",
            "downloaded",
            "applied",
            "updated",
            "skipped",
            "failed",
            "removed",
            "verified",
        ] {
            assert_eq!(v["summary"][field], 1, "summary.{field} via JSON");
        }
    }

    #[test]
    fn sidecars_omitted_when_empty_present_when_recorded() {
        // `sidecars` uses `skip_serializing_if = "Vec::is_empty"`, so a
        // run with no fixups must not emit the key at all (rollback,
        // list, npm-apply consumers branch on its absence).
        let mut env = Envelope::new(Command::Apply);
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert!(!v.as_object().unwrap().contains_key("sidecars"));

        env.sidecars.push(SidecarRecord {
            purl: "pkg:cargo/foo@1.0.0".into(),
            ecosystem: "cargo".into(),
            files: vec![SidecarFile {
                path: ".cargo-checksum.json".into(),
                action: SidecarFileAction::Rewritten,
            }],
            advisory: None,
        });
        assert_eq!(env.sidecars.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        let sidecars = v["sidecars"]
            .as_array()
            .expect("sidecars present once recorded");
        assert_eq!(sidecars.len(), 1);
        assert_eq!(sidecars[0]["purl"], "pkg:cargo/foo@1.0.0");
        assert_eq!(sidecars[0]["ecosystem"], "cargo");
        assert_eq!(sidecars[0]["files"][0]["action"], "rewritten");
    }

    #[test]
    fn vex_summary_omitted_when_none_present_when_set() {
        // `vex` is `skip_serializing_if = "Option::is_none"` — absent on
        // every run that didn't pass `--vex`, inline (not nested under
        // `error`) when generation succeeded.
        let mut env = Envelope::new(Command::Apply);
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert!(!v.as_object().unwrap().contains_key("vex"));

        env.vex = Some(VexSummary {
            path: "/tmp/openvex.json".into(),
            statements: 3,
            format: "openvex-0.2.0".into(),
        });
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["vex"]["path"], "/tmp/openvex.json");
        assert_eq!(v["vex"]["statements"], 3);
        assert_eq!(v["vex"]["format"], "openvex-0.2.0");
    }

    #[test]
    fn mark_error_replaces_prior_partial_failure() {
        // `mark_error` is documented to "replace any prior status". Only
        // the Error-outranks-later-PartialFailure direction was tested;
        // this pins the reverse — a PartialFailure escalating to a hard
        // Error (and attaching the error payload + flipping the exit
        // code) must take effect.
        let mut env = Envelope::new(Command::Apply);
        env.record(
            PatchEvent::new(PatchAction::Failed, "pkg:npm/bar@2.0.0")
                .with_error("apply_failed", "boom"),
        );
        assert_eq!(env.status, Status::PartialFailure);
        env.mark_error(EnvelopeError::new("manifest_unreadable", "bad json"));
        assert_eq!(env.status, Status::Error);
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["status"], "error");
        assert_eq!(v["error"]["code"], "manifest_unreadable");
    }

    #[test]
    fn special_statuses_serialize_camel_case() {
        // The remaining `Status` variants set directly by remove/rollback
        // /apply (`noManifest`, `notFound`) must spell out in camelCase
        // exactly as CLI_CONTRACT.md promises — consumers route exit
        // codes on these strings.
        for (status, tag) in [
            (Status::NoManifest, "noManifest"),
            (Status::PaidRequired, "paidRequired"),
            (Status::NotFound, "notFound"),
        ] {
            let mut env = Envelope::new(Command::Remove);
            env.status = status;
            let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
            assert_eq!(v["status"], tag);
        }
    }

    #[test]
    fn dry_run_and_details_round_trip() {
        // `dryRun` must reflect the flag, and `details` must pass through
        // schemaless without reshaping.
        let mut env = Envelope::new(Command::Scan);
        env.dry_run = true;
        env.record(
            PatchEvent::new(PatchAction::Discovered, "pkg:npm/foo@1.0.0")
                .with_details(serde_json::json!({ "tier": "free", "vulns": [1, 2] })),
        );
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["dryRun"], true);
        assert_eq!(v["events"][0]["details"]["tier"], "free");
        assert_eq!(
            v["events"][0]["details"]["vulns"],
            serde_json::json!([1, 2])
        );
    }

    #[test]
    fn failed_event_serializes_error_not_reason() {
        // `with_error` is exercised by several tests, but they all assert
        // only `status`/`summary` — none ever inspected the serialized
        // event. Per CLI_CONTRACT.md a `failed` event carries `errorCode`
        // + `error`; the human `reason` field is reserved for `skipped`.
        // Pin both halves so a builder that mis-routed the message into
        // `reason` (or dropped the routing tag) can't slip through.
        let event = PatchEvent::new(PatchAction::Failed, "pkg:npm/bar@2.0.0")
            .with_error("apply_failed", "hash mismatch after write");
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj["action"], "failed");
        assert_eq!(obj["errorCode"], "apply_failed");
        assert_eq!(obj["error"], "hash mismatch after write");
        // The Failed path must NOT populate `reason` — that key is the
        // skipped/human channel and a consumer routing on its presence
        // would misclassify the event.
        assert!(!obj.contains_key("reason"));
    }

    #[test]
    fn skipped_reason_does_not_leak_into_error_field() {
        // Mirror of the above for `with_reason`: it sets `errorCode` +
        // `reason` and must leave `error` unset, so a skip is never
        // mistaken for a hard failure by a consumer keying on `error`.
        let event = PatchEvent::new(PatchAction::Skipped, "pkg:npm/foo@1.0.0")
            .with_reason("already_patched", "Files match afterHash");
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj["errorCode"], "already_patched");
        assert_eq!(obj["reason"], "Files match afterHash");
        assert!(!obj.contains_key("error"));
    }

    #[test]
    fn every_command_serializes_to_its_contract_tag() {
        // `empty_envelope_has_stable_shape`/`special_statuses_*` only ever
        // serialized `scan`/`remove`/`get`. Pin the full `Command`
        // vocabulary (lowercase, no separators) so a renamed or reordered
        // `rename_all` arm can't silently change what `command` a
        // consumer routes on.
        for (command, tag) in [
            (Command::Scan, "scan"),
            (Command::Apply, "apply"),
            (Command::Vex, "vex"),
            (Command::Vendor, "vendor"),
            (Command::Setup, "setup"),
            (Command::Rollback, "rollback"),
            (Command::Get, "get"),
            (Command::List, "list"),
            (Command::Remove, "remove"),
            (Command::Repair, "repair"),
        ] {
            let serialized = serde_json::to_string(&command).unwrap();
            assert_eq!(serialized, format!("\"{tag}\""), "Command::{command:?}");
        }
    }

    #[test]
    fn recording_failed_overrides_success_like_status() {
        // The exit-code contract treats any `failed` event as exit 1
        // ("Exit 1 when status is partialFailure (any events[*].action ==
        // \"failed\")"). `record` enforces that by escalating every
        // non-Error status — including the success-like specials
        // (`notFound`, `noManifest`, `paidRequired`) — to PartialFailure.
        // Only a hard `Error` outranks it. Pin that so the auto-escalation
        // can't regress to leaving a `failed` event under an exit-0 status.
        for start in [Status::NotFound, Status::NoManifest, Status::PaidRequired] {
            let mut env = Envelope::new(Command::Remove);
            env.status = start;
            env.record(
                PatchEvent::new(PatchAction::Failed, "pkg:npm/bar@2.0.0")
                    .with_error("rollback_failed", "boom"),
            );
            assert_eq!(
                env.status,
                Status::PartialFailure,
                "{start:?} + failed event must escalate to partialFailure"
            );
        }
    }
}
