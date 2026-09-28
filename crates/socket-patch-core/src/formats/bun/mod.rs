//! Bun's text lock (`bun.lock`): the one fail-closed prelude every reader
//! starts from.
//!
//! The line grammar itself lives in `vendor::bun_lock_text` (the single-line
//! `"key": [tuple]` entry parser both backends splice with), and the binary
//! `bun.lockb` has its own codec (`vendor::bun_lockb`). What was copied at
//! every call site — gate the `lockfileVersion` head, split the text into
//! the splice's line coordinates, parse the `packages` section — is
//! [`BunTextLock::parse`]; each caller keeps its own refusal wording.

use crate::vendor::bun_lock_text::{check_lock_version, parse_packages_section, BunEntry};

/// Why [`BunTextLock::parse`] refused a lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BunTextError {
    /// The `lockfileVersion` head is missing or unsupported; the detail is
    /// the shared gate's user-facing text (one message for every mode).
    Version(String),
    /// The `packages` section deviates from bun's emitted single-line
    /// grammar.
    Packages(String),
}

impl BunTextError {
    /// The refusal detail, whichever step refused.
    pub(crate) fn detail(self) -> String {
        match self {
            BunTextError::Version(detail) | BunTextError::Packages(detail) => detail,
        }
    }
}

/// A text `bun.lock`, gated and parsed once.
pub(crate) struct BunTextLock {
    /// The text split on `\n` (a CRLF lock keeps each `\r`): the line
    /// coordinates [`BunEntry::line_idx`] and the splices index.
    pub(crate) lines: Vec<String>,
    /// Every `packages` entry, in lock order.
    pub(crate) entries: Vec<BunEntry>,
}

impl BunTextLock {
    pub(crate) fn parse(text: &str) -> Result<Self, BunTextError> {
        check_lock_version(text).map_err(BunTextError::Version)?;
        let lines: Vec<String> = text.split('\n').map(str::to_string).collect();
        let entries = parse_packages_section(&lines).map_err(BunTextError::Packages)?;
        Ok(BunTextLock { lines, entries })
    }
}
