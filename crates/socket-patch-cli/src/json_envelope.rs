//! Unified JSON output envelope shared across every subcommand.
//!
//! Every command's `--json` output uses this top-level shape (v5.0: `scan`,
//! `get` and `rollback` joined `apply`, `list`, `remove`, `repair`,
//! `vendor`, `--update` and `vex --json --output`). A command's own
//! payload (scan's `packages`, rollback's `hosted`, …) rides beside the
//! shared keys through [`Envelope::extra`]:
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
//! to interpret output from every envelope-emitting subcommand.
//!
//! See `CLI_CONTRACT.md` for the per-subcommand action matrix and example
//! `jq` recipes.

use serde::Serialize;
use socket_patch_core::manifest::cleanup_blobs::CleanupResult;

pub use socket_patch_core::patch::sidecars::{SidecarFile, SidecarFileAction, SidecarRecord};

/// Top-level JSON envelope (see the module doc for which commands emit it).
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
    /// The artifact GC pass's outcome — the same `gc` object (same keys)
    /// `rollback` and `scan --prune` print. Set by [`Envelope::set_gc`],
    /// which also mirrors `bytesFreed` into `summary.bytesFreed`. Omitted
    /// for runs that swept nothing (`repair --download-only`, `remove
    /// --preserve-state`, every command without a GC pass).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gc: Option<GcReport>,
    /// Command-specific top-level keys, flattened beside the shared ones
    /// (scan's `packages` / `redirect`, rollback's `hosted` / `manifest`,
    /// …). A key here must never shadow a shared key; [`Envelope::set_extra`]
    /// enforces that.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The keys every envelope owns. [`Envelope::set_extra`] refuses them so a
/// command payload can't shadow the shared vocabulary.
const SHARED_KEYS: &[&str] = &[
    "command", "status", "dryRun", "events", "summary", "error", "sidecars", "warnings", "vex",
    "gc",
];

/// One artifact GC pass — the orphan sweeps of `.socket/blobs`,
/// `.socket/diffs` and `.socket/packages` — serialized identically by
/// every command that runs one: the envelope's `gc` (`repair`, `remove`),
/// rollback's legacy `gc` and the `gc` of `scan --prune` / `--sync`. On a
/// dry run the counts are what the pass would remove.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GcReport {
    pub removed_blobs: usize,
    pub removed_diff_archives: usize,
    pub removed_package_archives: usize,
    pub bytes_freed: u64,
}

impl GcReport {
    /// Fold the three passes' results; a pass that failed outright
    /// (`None`) counts as empty — its `cleanup_failed` warning is the
    /// caller's to report.
    pub fn from_passes(
        blobs: Option<&CleanupResult>,
        diffs: Option<&CleanupResult>,
        packages: Option<&CleanupResult>,
    ) -> Self {
        let count = |r: Option<&CleanupResult>| r.map_or(0, |r| r.blobs_removed);
        Self {
            removed_blobs: count(blobs),
            removed_diff_archives: count(diffs),
            removed_package_archives: count(packages),
            bytes_freed: [blobs, diffs, packages]
                .into_iter()
                .flatten()
                .map(|r| r.bytes_freed)
                .sum(),
        }
    }

    /// Blobs plus diff and package archives removed.
    pub fn total_removed(&self) -> usize {
        self.removed_blobs + self.removed_diff_archives + self.removed_package_archives
    }

    /// The `gc` object as a JSON value, for the legacy shapes that extend
    /// it with command-specific keys (`scan --prune`).
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("GcReport serializes")
    }
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
    /// Run-level advisories raised during VEX generation (e.g.
    /// `product_not_iri`, `vendored_tree_out_of_sync`). Same [`RunWarning`]
    /// shape as the top-level `warnings[]`, but scoped to the embedded VEX
    /// side-effect — under `--json` stderr is silenced, so this field is
    /// the only channel these advisories reach a machine consumer on.
    /// Empty (and omitted from JSON) when generation had nothing to
    /// advise, so existing consumers see byte-identical output (additive-
    /// only envelope contract).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<RunWarning>,
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
            gc: None,
            extra: serde_json::Map::new(),
        }
    }

    /// Set a command-specific top-level key (see [`Envelope::extra`]).
    ///
    /// # Panics
    /// When `key` is one of the shared envelope keys — a programming error.
    pub fn set_extra(&mut self, key: &str, value: serde_json::Value) {
        assert!(
            !SHARED_KEYS.contains(&key),
            "`{key}` is a shared envelope key, not a command payload key"
        );
        self.extra.insert(key.to_string(), value);
    }

    /// Append a run-level warning.
    pub fn warn(&mut self, code: impl Into<String>, detail: impl Into<String>) {
        self.warnings.push(RunWarning::new(code, detail));
    }

    /// Serialize to a JSON value.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("envelope serialize")
    }

    /// Attach the run's artifact GC outcome (`gc`) and mirror its byte
    /// count into `summary.bytesFreed`.
    pub fn set_gc(&mut self, gc: GcReport) {
        self.summary.bytes_freed = gc.bytes_freed;
        self.gc = Some(gc);
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

    /// Re-tag every `Applied` event recorded at or after index `since` as
    /// `action` (`Skipped` or `Failed`) with `code` and `message`, keeping
    /// the summary in step: for packages a later step of the same run
    /// undid (a refused group commit, a rolled-back eject), which must not
    /// be reported or counted as applied. Their file lists are dropped (the
    /// files are no longer there). The `skipped` advisories recorded for a
    /// retracted package in the same span (`vendor_prebuilt_downloaded`
    /// "vendored … from the patch service", `vendor_artifact_reused`, …)
    /// describe that undone vendoring, so they are dropped too: the
    /// re-tagged event is the package's one account. Returns how many
    /// events were re-tagged.
    pub fn retract_applied(
        &mut self,
        since: usize,
        action: PatchAction,
        code: &str,
        message: &str,
    ) -> usize {
        let since = since.min(self.events.len());
        let retracted_purls: std::collections::HashSet<String> = self.events[since..]
            .iter()
            .filter(|e| e.action == PatchAction::Applied)
            .filter_map(|e| e.purl.clone())
            .collect();
        let mut index = 0;
        let summary = &mut self.summary;
        self.events.retain(|e| {
            let keep = index < since
                || e.action != PatchAction::Skipped
                || !e.purl.as_ref().is_some_and(|p| retracted_purls.contains(p));
            index += 1;
            if !keep {
                summary.skipped = summary.skipped.saturating_sub(1);
            }
            keep
        });
        let mut retracted = 0;
        for event in self.events.iter_mut().skip(since) {
            if event.action != PatchAction::Applied {
                continue;
            }
            self.summary.applied = self.summary.applied.saturating_sub(1);
            self.summary.bump(action);
            event.action = action;
            event.files.clear();
            event.error_code = Some(code.to_string());
            if action == PatchAction::Failed {
                event.error = Some(message.to_string());
            } else {
                event.reason = Some(message.to_string());
            }
            retracted += 1;
        }
        if retracted > 0 && action == PatchAction::Failed {
            self.mark_partial_failure();
        }
        retracted
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
    /// Byte count of the artifact-level GC event (`removed`, or `verified`
    /// on a dry run: bytes freed) and of `--update`'s `downloaded` event
    /// (archive size). Omitted everywhere else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Human-readable explanation for `Skipped` or `Failed` events.
    /// Machine consumers should prefer `error_code` for routing decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Stable, lowercase, snake_case reason tag for programmatic routing.
    /// Examples: `already_patched`, `package_not_installed`,
    /// `hash_mismatch`, `no_local_source`, `paid_required`.
    ///
    /// A code may be reported at either level: `no_local_source` arrives
    /// HERE (per package, envelope `partialFailure`, no top-level `error`)
    /// when vendored staging could not obtain one patch's content while
    /// another staged, and as the top-level `error.code` (`status:
    /// "error"`, empty `events[]`) when NOTHING in the manifest can be
    /// staged — including a one-patch manifest. See CLI_CONTRACT.md's
    /// error-code table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Underlying error message for `Failed` events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Command-specific additional fields. Consumers MUST NOT depend on
    /// the shape of this object — different subcommands attach different
    /// keys here, e.g. `list` (vulnerabilities, license, tier,
    /// description).
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
            bytes: None,
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

    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes = Some(bytes);
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
    /// `list`: a patch recorded for this package (hosted/vendored lockfile
    /// reference or manifest entry).
    Discovered,
    /// Patch bytes were fetched from the registry.
    Downloaded,
    /// `apply`: patch was applied to disk. `files` enumerates which files
    /// changed.
    Applied,
    /// Patch replaced an older patch (the manifest already had a different
    /// UUID for this PURL). `oldUuid` carries the previous UUID.
    Updated,
    /// The patch was a no-op — already
    /// applied, not in scope, or filtered out. `errorCode` carries the
    /// reason tag.
    Skipped,
    /// Any command: an attempt failed. `errorCode` is the routing tag,
    /// `error` is the human message.
    Failed,
    /// `gc` / `repair` / `remove` / `rollback`: data was removed from
    /// `.socket/` (or from disk in the rollback case).
    Removed,
    /// `apply --dry-run`: patch *would* apply
    /// cleanly. `files` lists what would change.
    Verified,
    /// `repair`: a missing/corrupt vendored artifact was rebuilt in place
    /// from verified sources (lockfiles and the vendor ledger untouched
    /// unless drift was healed).
    Rebuilt,
    /// `rollback`: a patched package was restored to its original state
    /// (`files` lists what was restored).
    RolledBack,
}

/// Patch-source strategy used to apply a file. Mirrors the existing
/// `socket_patch_core::patch::apply::AppliedVia` enum, but lives here so
/// the JSON layer doesn't depend on core internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AppliedVia {
    Diff,
    Blob,
}

impl AppliedVia {
    pub fn from_core(via: socket_patch_core::patch::apply::AppliedVia) -> Self {
        use socket_patch_core::patch::apply::AppliedVia as Core;
        match via {
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
    /// `get`: the requested patch requires a paid plan but the caller's
    /// API token isn't entitled. Distinct from `Error` so PR bots can post
    /// an "upgrade your plan" comment instead of failing.
    PaidRequired,
    /// The identifier didn't resolve to a patch (`get`: none published;
    /// `remove`: nothing in the local manifest).
    NotFound,
    /// `get`: the identifier matched no installed package.
    NotInstalled,
    /// `get`: the search matched no package at all.
    NoMatch,
    /// `get`: the project has no packages to search.
    NoPackages,
    /// `get`: several patches match and the caller must pick one (exit 1).
    SelectionRequired,
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
    pub rebuilt: u32,
    pub rolled_back: u32,
    /// Bytes the run's artifact GC freed (would free, on a dry run) — the
    /// envelope's `gc.bytesFreed`, 0 when no GC ran. Not derived from
    /// `events`: GC is reported once, in `gc`.
    pub bytes_freed: u64,
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
            PatchAction::RolledBack => self.rolled_back += 1,
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

/// The top-level error for a manifest that exists but couldn't be loaded.
/// One mapping for every command (#931): malformed JSON or a schema
/// violation (`read_manifest`'s `InvalidData`) is `manifest_invalid`; any
/// other I/O failure is `manifest_unreadable`.
pub(crate) fn manifest_load_error(
    manifest_path: &std::path::Path,
    err: &std::io::Error,
) -> EnvelopeError {
    EnvelopeError::new(
        manifest_load_error_code(err),
        crate::ui::manifest_error_message(manifest_path, err),
    )
}

/// The code half of [`manifest_load_error`], for callers that carry a
/// `&'static str` code (`vex`'s `VexGenError`).
pub(crate) fn manifest_load_error_code(err: &std::io::Error) -> &'static str {
    if err.kind() == std::io::ErrorKind::InvalidData {
        "manifest_invalid"
    } else {
        "manifest_unreadable"
    }
}

/// The JSON a self-enforced usage error prints under `--json`: a full
/// [`Envelope`] with `status: "error"`.
pub(crate) fn usage_error_json(
    command: Command,
    dry_run: bool,
    code: &str,
    message: &str,
) -> serde_json::Value {
    let mut env = Envelope::new(command);
    env.dry_run = dry_run;
    env.mark_error(EnvelopeError::new(code, message));
    env.to_value()
}

/// Report a usage error a command enforces itself (clap's own parse errors
/// never reach here) and return its exit code, 2. Under `--json` the coded
/// error goes to stdout so a consumer always gets parseable output;
/// otherwise `Error: <message>` goes to stderr.
pub(crate) fn usage_error(
    command: Command,
    json: bool,
    dry_run: bool,
    code: &str,
    message: &str,
) -> i32 {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&usage_error_json(command, dry_run, code, message))
                .expect("json serialize")
        );
    } else {
        eprintln!("Error: {message}");
    }
    2
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

impl RunWarning {
    pub fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
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
    fn usage_error_json_is_a_full_envelope_for_every_command() {
        for cmd in [
            Command::Scan,
            Command::Get,
            Command::Apply,
            Command::Rollback,
            Command::List,
            Command::Remove,
            Command::Repair,
            Command::Vendor,
            Command::Vex,
        ] {
            let v = usage_error_json(cmd, true, "invalid_args", "bad");
            assert_eq!(v["command"], serde_json::to_value(cmd).unwrap());
            assert_eq!(v["status"], "error");
            assert_eq!(v["dryRun"], true);
            assert_eq!(v["events"], serde_json::json!([]));
            assert_eq!(v["error"]["code"], "invalid_args");
            assert_eq!(v["error"]["message"], "bad");
        }
    }

    #[test]
    fn usage_error_returns_two() {
        assert_eq!(
            usage_error(Command::Scan, false, false, "invalid_args", "x"),
            2
        );
        assert_eq!(
            usage_error(Command::Remove, true, false, "invalid_args", "x"),
            2
        );
    }

    /// Every `src/commands/**/*.rs` file, with its path relative to the
    /// crate root.
    fn command_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read src/commands") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        walk(&root.join("src/commands"), &mut files);
        files.sort();
        assert!(!files.is_empty(), "no command sources found");
        files
            .into_iter()
            .map(|p| {
                let rel = p
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                (rel, std::fs::read_to_string(&p).expect("read source"))
            })
            .collect()
    }

    /// Guard (#704): a command's self-enforced usage error goes through
    /// [`usage_error`], which prints the coded error under `--json` and
    /// returns 2. A bare `return 2;` would bypass that.
    #[test]
    fn no_bare_exit_two_in_commands() {
        const ALLOW: &[&str] = &["src/commands/hosted_bundle.rs"];
        let mut offenders = Vec::new();
        for (rel, src) in command_sources() {
            if ALLOW.contains(&rel.as_str()) {
                continue;
            }
            for (i, line) in src.lines().enumerate() {
                if line.trim() == "return 2;" {
                    offenders.push(format!("{rel}:{}", i + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "use json_envelope::usage_error for exit-2 usage errors: {offenders:?}"
        );
    }

    /// Guard (#704): a `"status": "error"` JSON literal carries `error` as a
    /// `{code, message}` object and no top-level `"errorCode"`. Checks the
    /// keys at the same indentation as `"status": "error"`, so per-record
    /// keys nested deeper are not flagged.
    #[test]
    fn error_json_literals_use_the_object_shape() {
        let mut offenders = Vec::new();
        for (rel, src) in command_sources() {
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.trim() != r#""status": "error","# {
                    continue;
                }
                let indent = line.len() - line.trim_start().len();
                for next in &lines[i + 1..] {
                    let trimmed = next.trim_start();
                    let next_indent = next.len() - trimmed.len();
                    if trimmed.is_empty() || next_indent < indent {
                        break;
                    }
                    if next_indent > indent {
                        continue;
                    }
                    let bad = trimmed.starts_with(r#""errorCode":"#)
                        || (trimmed.starts_with(r#""error":"#)
                            && !trimmed[r#""error":"#.len()..].trim_start().starts_with('{'));
                    if bad {
                        offenders.push(format!("{rel}:{}: {}", i + 1, trimmed));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "top-level `error` must be {{code, message}} with no `errorCode`: {offenders:?}"
        );
    }

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
            (PatchAction::Rebuilt, "rebuilt"),
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
    fn retract_applied_retags_only_later_applied_events() {
        let mut env = Envelope::new(Command::Vendor);
        env.record(PatchEvent::new(PatchAction::Applied, "pkg:npm/early@1.0.0"));
        let since = env.events.len();
        env.record(PatchEvent::new(PatchAction::Applied, "pkg:npm/a@1.0.0"));
        env.record(
            PatchEvent::new(PatchAction::Skipped, "pkg:npm/a@1.0.0")
                .with_reason("vendor_prebuilt_downloaded", "advisory"),
        );
        // An advisory for a package that was NOT retracted is kept.
        env.record(
            PatchEvent::new(PatchAction::Skipped, "pkg:npm/other@1.0.0")
                .with_reason("vendor_bundled_instance_skipped", "advisory"),
        );
        let n = env.retract_applied(since, PatchAction::Skipped, "eject_rolled_back", "undone");
        assert_eq!(n, 1);
        assert_eq!(env.summary.applied, 1, "the earlier event is kept");
        // The retracted package's "vendored … from the patch service"
        // advisory described the undone vendoring (#898, #1005): dropped.
        assert_eq!(env.events.len(), 3, "{:?}", env.events);
        assert_eq!(env.summary.skipped, 2);
        assert!(!env
            .events
            .iter()
            .any(|e| e.error_code.as_deref() == Some("vendor_prebuilt_downloaded")));
        assert_eq!(
            env.events[2].error_code.as_deref(),
            Some("vendor_bundled_instance_skipped")
        );
        assert_eq!(env.events[1].action, PatchAction::Skipped);
        assert_eq!(
            env.events[1].error_code.as_deref(),
            Some("eject_rolled_back")
        );
        assert_eq!(env.events[1].reason.as_deref(), Some("undone"));
        assert_eq!(env.status, Status::Success);

        let n = env.retract_applied(0, PatchAction::Failed, "refused", "boom");
        assert_eq!(n, 1);
        assert_eq!(env.summary.applied, 0);
        assert_eq!(env.summary.failed, 1);
        assert_eq!(env.events[0].error.as_deref(), Some("boom"));
        assert_eq!(env.status, Status::PartialFailure);
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
            warnings: Vec::new(),
        });
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["vex"]["path"], "/tmp/openvex.json");
        assert_eq!(v["vex"]["statements"], 3);
        assert_eq!(v["vex"]["format"], "openvex-0.2.0");
        // `vex.warnings` is skip-if-empty: a warning-free generation keeps
        // the pre-existing three-key shape byte-identical for consumers.
        assert!(
            !v["vex"].as_object().unwrap().contains_key("warnings"),
            "empty vex.warnings must be omitted, got {:?}",
            v["vex"]
        );

        // Once generation raised advisories, they ride inside `vex` with
        // the same code/detail shape as the top-level `warnings[]`.
        env.vex.as_mut().unwrap().warnings.push(RunWarning {
            code: "product_not_iri".into(),
            detail: "product is not an IRI".into(),
        });
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["vex"]["warnings"][0]["code"], "product_not_iri");
        assert_eq!(v["vex"]["warnings"][0]["detail"], "product is not an IRI");
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

    /// The ```jsonc block under `heading` in CLI_CONTRACT.md.
    fn contract_block(heading: &str) -> &'static str {
        let doc = include_str!("../CLI_CONTRACT.md");
        let at = doc
            .find(heading)
            .unwrap_or_else(|| panic!("{heading} missing"));
        let body = &doc[at..];
        let start = body.find("```jsonc\n").expect("jsonc block") + "```jsonc\n".len();
        let end = start + body[start..].find("```").expect("block end");
        &body[start..end]
    }

    /// The `"key":` names at exactly `indent` spaces in `block`.
    fn keys_at(block: &str, indent: usize) -> std::collections::BTreeSet<String> {
        block
            .lines()
            .filter(|l| l.len() > indent && l[..indent].trim().is_empty())
            .filter_map(|l| l[indent..].strip_prefix('"'))
            .filter_map(|l| l.split_once('"').map(|(k, _)| k.to_string()))
            .collect()
    }

    fn object_keys(value: serde_json::Value) -> std::collections::BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    }

    /// The contract's envelope schema names exactly the `summary`, `gc` and
    /// top-level keys the envelope serializes — a documented counter no
    /// command emits (as `bytesDownloaded` was) fails here (#1257).
    #[test]
    fn contract_envelope_block_matches_serialized_keys() {
        let block = contract_block("### Envelope shape");
        let section = |name: &str| {
            let from = block.find(&format!("\"{name}\":")).expect(name);
            let rest = &block[from..];
            &rest[..rest.find("\n  }").expect("section end")]
        };
        let mut env = Envelope::new(Command::Repair);
        env.summary.rebuilt = 1;
        env.set_gc(GcReport::default());
        env.mark_error(EnvelopeError::new("x", "y"));
        let value = serde_json::to_value(&env).unwrap();
        assert_eq!(
            keys_at(section("summary"), 4),
            object_keys(value["summary"].clone())
        );
        assert_eq!(keys_at(section("gc"), 4), object_keys(value["gc"].clone()));
        let top: std::collections::BTreeSet<String> = object_keys(value)
            .into_iter()
            // Additive keys documented in their own sections.
            .filter(|k| !matches!(k.as_str(), "sidecars" | "warnings" | "vex"))
            .collect();
        assert_eq!(keys_at(block, 2), top);
    }

    /// Every `PatchEvent` key the contract documents is serialized, and
    /// every serialized key is documented; every action has a row.
    #[test]
    fn contract_patch_event_block_matches_serialized_keys() {
        let block = contract_block("### `PatchEvent` shape");
        let event = PatchEvent::new(PatchAction::Updated, "pkg:npm/a@1.0.0")
            .with_uuid("u")
            .with_old_uuid("o")
            .with_files(vec![PatchEventFile {
                path: "package/index.js".into(),
                verified: true,
                applied_via: Some(AppliedVia::Diff),
            }])
            .with_bytes(1)
            .with_reason("c", "r")
            .with_error("c", "e")
            .with_details(serde_json::json!({}));
        let value = serde_json::to_value(&event).unwrap();
        assert_eq!(keys_at(block, 2), object_keys(value.clone()));
        assert_eq!(
            keys_at(block, 6),
            object_keys(value["files"][0].clone()),
            "files[] keys"
        );
        let doc = include_str!("../CLI_CONTRACT.md");
        for action in [
            PatchAction::Discovered,
            PatchAction::Downloaded,
            PatchAction::Applied,
            PatchAction::Updated,
            PatchAction::Skipped,
            PatchAction::Failed,
            PatchAction::Removed,
            PatchAction::Verified,
            PatchAction::Rebuilt,
        ] {
            let tag = serde_json::to_value(action).unwrap();
            let tag = tag.as_str().unwrap();
            assert!(
                block.contains(&format!("\"{tag}\"")),
                "{tag} in the action enum"
            );
            assert!(
                doc.contains(&format!("| `{tag}`")),
                "{tag} has a vocabulary row"
            );
        }
    }

    #[test]
    fn gc_report_folds_passes_and_serializes_shared_keys() {
        let pass = |removed, bytes| CleanupResult {
            blobs_removed: removed,
            bytes_freed: bytes,
            ..CleanupResult::default()
        };
        let (blobs, packages) = (pass(3, 30), pass(1, 4));
        let report = GcReport::from_passes(Some(&blobs), None, Some(&packages));
        assert_eq!(report.total_removed(), 4);
        assert_eq!(
            report.to_value(),
            serde_json::json!({
                "removedBlobs": 3,
                "removedDiffArchives": 0,
                "removedPackageArchives": 1,
                "bytesFreed": 34,
            })
        );
        let mut env = Envelope::new(Command::Remove);
        assert!(serde_json::to_value(&env).unwrap().get("gc").is_none());
        assert_eq!(
            serde_json::to_value(&env).unwrap()["summary"]["bytesFreed"],
            0
        );
        env.set_gc(report);
        let value = serde_json::to_value(&env).unwrap();
        assert_eq!(value["gc"], report.to_value());
        assert_eq!(value["summary"]["bytesFreed"], 34);
    }
}
