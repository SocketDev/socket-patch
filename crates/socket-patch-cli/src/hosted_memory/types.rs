//! The engine's input and output shapes. Every struct serializes camelCase
//! and maps 1:1 onto the addon's JS contract (`HostedScanSessionOptions`,
//! `HostedScanResult`, `ProjectResult`, `PathSelection`, …), so a binding
//! converts them field by field.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Ecosystems the addon contract names (`Ecosystem` in index.d.ts).
pub const ECOSYSTEMS: [&str; 8] = [
    "npm", "pypi", "cargo", "golang", "gem", "composer", "maven", "nuget",
];

/// `HostedScanLimits`. `None` fields take the defaults in
/// [`ResolvedLimits::DEFAULT`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HostedScanLimits {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_file_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_files: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_purls: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_projects: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_artifact_bytes: Option<u64>,
}

/// [`HostedScanLimits`] with every default applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedLimits {
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_files: u64,
    pub max_purls: u64,
    pub max_projects: u64,
    pub max_artifact_bytes: u64,
}

impl ResolvedLimits {
    pub const DEFAULT: ResolvedLimits = ResolvedLimits {
        max_file_bytes: 20 * 1024 * 1024,
        max_total_bytes: 64 * 1024 * 1024,
        max_files: 2000,
        max_purls: 20_000,
        max_projects: 200,
        max_artifact_bytes: 32 * 1024 * 1024,
    };
}

impl HostedScanLimits {
    pub fn resolve(&self) -> ResolvedLimits {
        let d = ResolvedLimits::DEFAULT;
        ResolvedLimits {
            max_file_bytes: self.max_file_bytes.unwrap_or(d.max_file_bytes),
            max_total_bytes: self.max_total_bytes.unwrap_or(d.max_total_bytes),
            max_files: self.max_files.unwrap_or(d.max_files),
            max_purls: self.max_purls.unwrap_or(d.max_purls),
            max_projects: self.max_projects.unwrap_or(d.max_projects),
            max_artifact_bytes: self.max_artifact_bytes.unwrap_or(d.max_artifact_bytes),
        }
    }
}

/// `HostedScanSessionOptions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedScanOptions {
    pub org_slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystems: Option<Vec<String>>,
    /// 1..=500, default 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    #[serde(default)]
    pub dry_run: bool,
    /// The installing Pipenv's major; `None` is the CLI's "Pipenv not on
    /// PATH" default (modern `file` references). Never probed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipenv_major: Option<u32>,
    /// Default true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_lockfile_config: Option<bool>,
    /// Default true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_allow_remote_config: Option<bool>,
    /// Must match the `projectRoots` given to path selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_roots: Option<Vec<String>>,
    /// Default 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_concurrency: Option<u32>,
    /// Per provider call, default 60000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<HostedScanLimits>,
}

pub const DEFAULT_BATCH_SIZE: u32 = 100;
pub const MAX_BATCH_SIZE: u32 = 500;
pub const DEFAULT_PROVIDER_CONCURRENCY: u32 = 8;
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 60_000;
/// The reference endpoint accepts at most this many uuids per request.
pub const MAX_REFERENCE_BATCH: usize = 500;

/// Why a path was marked present without content (`markPresent` kinds
/// other than `symlink`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentKind {
    Present,
    BinarySkipped,
    Oversize,
    LfsPointer,
}

impl PresentKind {
    pub fn parse(kind: &str) -> Option<MarkKind> {
        Some(match kind {
            "present" => MarkKind::Present(PresentKind::Present),
            "binary_skipped" => MarkKind::Present(PresentKind::BinarySkipped),
            "oversize" => MarkKind::Present(PresentKind::Oversize),
            "lfs_pointer" => MarkKind::Present(PresentKind::LfsPointer),
            "symlink" => MarkKind::Symlink,
            _ => return None,
        })
    }
}

/// A `markPresent(path, kind)` kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkKind {
    Present(PresentKind),
    Symlink,
}

/// One repo file handed to the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputFile {
    Text(String),
    Binary(Vec<u8>),
    Present(PresentKind),
    Symlink,
}

/// Everything [`super::run_in_memory`] consumes. Build it with
/// [`super::SessionBuilder`] (which enforces the session limits) or
/// directly for tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostedScanInput {
    pub options: HostedScanOptions,
    /// Repo-relative `/`-separated paths.
    pub files: BTreeMap<String, InputFile>,
    /// Session-level warnings (e.g. a text file that was not UTF-8).
    pub warnings: Vec<EngineWarning>,
}

/// `EngineWarning`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineWarning {
    pub code: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
}

impl EngineWarning {
    pub fn new(code: impl Into<String>, detail: impl Into<String>, root: Option<&str>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
            project_root: root.map(str::to_string),
        }
    }
}

/// `ProjectResult.summary`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub scanned_packages: u64,
    pub packages_with_patches: u64,
    pub total_patches: u64,
    pub free_patches: u64,
    pub paid_patches: u64,
    pub can_access_paid_patches: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedirectedPatch {
    pub purl: String,
    pub uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedPatch {
    pub purl: String,
    pub uuid: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectError {
    pub code: String,
    pub message: String,
}

/// `ProjectResult`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectResult {
    /// Repo-relative project root (`""` is the repo root).
    pub root: String,
    /// The CLI `--json` `redirect` block, byte-for-byte the same shape.
    pub redirect: serde_json::Value,
    pub summary: ProjectSummary,
    pub redirected: Vec<RedirectedPatch>,
    pub skipped: Vec<SkippedPatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProjectError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedFile {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangedBinaryFile {
    pub path: String,
    #[serde(with = "base64_bytes")]
    pub content: Vec<u8>,
}

/// `HostedScanResult.stats`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStats {
    pub projects: u64,
    pub files_input: u64,
    pub bytes_input: u64,
    pub packages_scanned: u64,
    pub packages_with_patches: u64,
    pub patches_selected: u64,
    pub patches_redirected: u64,
    pub files_changed: u64,
    /// Provider calls made, by method name (`searchPatchesBatch`, …).
    pub provider_calls: BTreeMap<String, u64>,
    /// Wall time per engine phase, milliseconds.
    pub phase_ms: BTreeMap<String, u64>,
}

/// `HostedScanResult`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostedScanOutput {
    pub projects: Vec<ProjectResult>,
    /// Repo-relative, sorted, byte-changed only; ledgers included on wet
    /// runs.
    pub changed_files: Vec<ChangedFile>,
    pub changed_binary_files: Vec<ChangedBinaryFile>,
    pub deleted_files: Vec<String>,
    pub warnings: Vec<EngineWarning>,
    pub stats: EngineStats,
    pub engine_version: String,
}

/// `TreeEntryInput`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeEntryInput {
    pub path: String,
    pub mode: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// `selectHostedScanPaths` options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_roots: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystems: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IgnoredPath {
    pub path: String,
    pub reason: String,
}

/// `PathSelection`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathSelection {
    pub roots: Vec<String>,
    pub fetch_text: Vec<String>,
    pub fetch_binary: Vec<String>,
    pub present_only: Vec<String>,
    pub symlinks: Vec<String>,
    pub ignored_count: u64,
    /// At most [`super::select::IGNORED_SAMPLE_MAX`] entries.
    pub ignored_sample: Vec<IgnoredPath>,
}

/// Engine failure (`finish()` rejection codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineError {
    /// A size/count limit was breached (`code` names the limit).
    Limit { code: &'static str, message: String },
    /// The input or options are unusable.
    InvalidInput { code: &'static str, message: String },
    /// Cancelled through the cancellation token.
    Cancelled,
    /// An engine bug.
    Internal { message: String },
}

impl EngineError {
    /// The stable machine code (`cancelled`, `limit_exceeded`'s limit name,
    /// …).
    pub fn code(&self) -> &str {
        match self {
            EngineError::Limit { code, .. } | EngineError::InvalidInput { code, .. } => code,
            EngineError::Cancelled => "cancelled",
            EngineError::Internal { .. } => "engine_internal",
        }
    }

    /// `limit` / `invalid_input` / `cancelled` / `internal`.
    pub fn kind(&self) -> &'static str {
        match self {
            EngineError::Limit { .. } => "limit",
            EngineError::InvalidInput { .. } => "invalid_input",
            EngineError::Cancelled => "cancelled",
            EngineError::Internal { .. } => "internal",
        }
    }

    pub(crate) fn limit(code: &'static str, message: impl Into<String>) -> Self {
        EngineError::Limit {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        EngineError::InvalidInput {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::Limit { code, message } | EngineError::InvalidInput { code, message } => {
                write!(f, "{code}: {message}")
            }
            EngineError::Cancelled => write!(f, "cancelled"),
            EngineError::Internal { message } => write!(f, "engine_internal: {message}"),
        }
    }
}

impl std::error::Error for EngineError {}

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}
