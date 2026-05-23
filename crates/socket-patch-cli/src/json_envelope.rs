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
//!   "summary":  { "applied": 0, "downloaded": 0, ... },
//!   "error":    null
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

pub use socket_patch_core::patch::sidecars::{
    SidecarAdvisory, SidecarAdvisoryCode, SidecarFile, SidecarFileAction, SidecarRecord,
    SidecarSeverity,
};

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
    /// commands that don't produce sidecar work — `rollback`,
    /// `repair`, `list`, etc. — and for apply runs against ecosystems
    /// with no sidecar contract (e.g. npm).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sidecars: Vec<SidecarRecord>,
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
        }
    }

    /// Append an event and bump the matching summary counter. Centralizes
    /// the "events list must agree with summary counts" invariant so per-
    /// command code can't drift.
    pub fn record(&mut self, event: PatchEvent) {
        self.summary.bump(event.action);
        self.events.push(event);
    }

    /// Append a sidecar fixup record. Called once per `ApplyResult`
    /// whose `sidecar` field is `Some`. Order matches the order
    /// `apply` processed packages, which is best-effort.
    pub fn record_sidecar(&mut self, sidecar: SidecarRecord) {
        self.sidecars.push(sidecar);
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
            action,
            purl: Some(purl.into()),
            uuid: None,
            files: Vec::new(),
            reason: None,
            error_code: None,
            error: None,
            details: None,
        }
    }

    /// Construct an event that isn't scoped to a single package (e.g. a
    /// repair run that swept orphan blobs).
    pub fn artifact(action: PatchAction) -> Self {
        Self {
            action,
            purl: None,
            uuid: None,
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

    pub fn with_files(mut self, files: Vec<PatchEventFile>) -> Self {
        self.files = files;
        self
    }

    pub fn with_reason(
        mut self,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        self.error_code = Some(code.into());
        self.reason = Some(message.into());
        self
    }

    pub fn with_error(
        mut self,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
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
/// Serializes to lowercase camelCase strings — e.g. `Applied` → `"applied"`,
/// `PaidRequired` → `"paidRequired"`. The full vocabulary is part of the
/// CLI contract; new variants are MINOR-safe but renames are MAJOR.
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
    Apply,
    Rollback,
    Get,
    Scan,
    List,
    Remove,
    Repair,
    Setup,
    Unlock,
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
        assert_eq!(keys, vec!["command", "dryRun", "events", "status", "summary"]);
        assert_eq!(v["command"], "scan");
        assert_eq!(v["status"], "success");
        assert_eq!(v["dryRun"], false);
        assert_eq!(v["events"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn record_keeps_summary_in_sync() {
        let mut env = Envelope::new(Command::Apply);
        env.record(PatchEvent::new(PatchAction::Applied, "pkg:npm/foo@1.0.0"));
        env.record(PatchEvent::new(PatchAction::Downloaded, "pkg:npm/foo@1.0.0"));
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
    fn skipped_event_omits_uuid_and_files() {
        let event = PatchEvent::new(PatchAction::Skipped, "pkg:npm/foo@1.0.0")
            .with_reason("package_not_installed", "no matching package on disk");
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("uuid"));
        assert!(!obj.contains_key("files"));
        assert!(!obj.contains_key("oldUuid"));
        assert!(!obj.contains_key("error"));
        assert_eq!(obj.get("errorCode").and_then(|v| v.as_str()), Some("package_not_installed"));
        assert_eq!(obj.get("reason").and_then(|v| v.as_str()), Some("no matching package on disk"));
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
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
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
        env.mark_error(EnvelopeError::new("paid_required", "Patch requires paid plan"));
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
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("purl"));
        assert_eq!(obj["action"], "removed");
        assert_eq!(obj["errorCode"], "orphan_blob");
    }
}
