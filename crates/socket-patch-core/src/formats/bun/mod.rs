//! Bun's text lock (`bun.lock`): the one fail-closed prelude every reader
//! starts from.
//!
//! The line grammar itself lives in `vendor::bun_lock_text` (the single-line
//! `"key": [tuple]` entry parser both backends splice with), and the binary
//! `bun.lockb` has its own codec (`vendor::bun_lockb`). What was copied at
//! every call site — gate the `lockfileVersion` head, split the text into
//! the splice's line coordinates, parse the `packages` section — is
//! [`BunTextLock::parse`]; each caller keeps its own refusal wording.

use std::sync::{Arc, Mutex, PoisonError};

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

    /// [`Self::parse`], shared: a scan reads one `bun.lock` in the lock
    /// inventory, in VEX discovery and in the hosted redirect, and parsing
    /// a large lock is most of a Bun rescan's CPU (#1606). The last text
    /// parsed is kept with its result, and the same text (compared in
    /// full, so a changed lock is always parsed again) gets that result
    /// back. Readers only; a splice edits a copy of [`Self::lines`].
    pub(crate) fn parse_shared(text: &str) -> Result<Arc<Self>, BunTextError> {
        static LAST: ParseMemo = ParseMemo::new();
        LAST.parse(text)
    }
}

/// The last text [`BunTextLock::parse_shared`] parsed, with its result.
struct ParseMemo(Mutex<Option<ParsedText>>);

/// A lock text and what [`BunTextLock::parse`] made of it.
type ParsedText = (Arc<str>, Result<Arc<BunTextLock>, BunTextError>);

impl ParseMemo {
    const fn new() -> Self {
        ParseMemo(Mutex::new(None))
    }

    fn parse(&self, text: &str) -> Result<Arc<BunTextLock>, BunTextError> {
        let last = || self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((cached, parsed)) = last().as_ref() {
            if **cached == *text {
                return parsed.clone();
            }
        }
        let parsed = BunTextLock::parse(text).map(Arc::new);
        *last() = Some((Arc::from(text), parsed.clone()));
        parsed
    }
}

/// The `packages` entries of a [`BunTextLock::parse_shared`] lock.
#[derive(Clone)]
pub(crate) struct BunEntries(Arc<BunTextLock>);

impl BunEntries {
    pub(crate) fn new(lock: Arc<BunTextLock>) -> Self {
        BunEntries(lock)
    }
}

impl std::ops::Deref for BunEntries {
    type Target = [BunEntry];

    fn deref(&self) -> &[BunEntry] {
        &self.0.entries
    }
}

impl<'a> IntoIterator for &'a BunEntries {
    type Item = &'a BunEntry;
    type IntoIter = std::slice::Iter<'a, BunEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "fixture", "dependencies": { "left-pad": "1.3.0" } },
  },
  "packages": {
    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-XI5MPz=="],
  }
}
"#;

    #[test]
    fn same_text_is_parsed_once() {
        let memo = ParseMemo::new();
        let first = memo.parse(LOCK).unwrap();
        // An equal text read again (a fresh String) gets the same parse.
        let again = memo.parse(&LOCK.to_string()).unwrap();
        assert!(Arc::ptr_eq(&first, &again));
        assert_eq!(first.entries.len(), 1);
        assert_eq!(first.entries[0].key, "left-pad");
    }

    #[test]
    fn changed_text_is_parsed_again() {
        let memo = ParseMemo::new();
        let first = memo.parse(LOCK).unwrap();
        let bumped = LOCK.replace("left-pad@1.3.0", "left-pad@1.3.1");
        let second = memo.parse(&bumped).unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(second.entries[0].elems[0].contains("1.3.1"));
        // Back to the first text: parsed again, never a stale result.
        let third = memo.parse(LOCK).unwrap();
        assert!(third.entries[0].elems[0].contains("1.3.0"));
        assert_eq!(
            third.lines,
            LOCK.split('\n').map(str::to_string).collect::<Vec<_>>()
        );
    }

    #[test]
    fn refusals_are_shared_too() {
        let memo = ParseMemo::new();
        let future = LOCK.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": 99,");
        let refused = memo.parse(&future).err().unwrap();
        assert!(matches!(refused, BunTextError::Version(_)));
        assert_eq!(memo.parse(&future).err(), Some(refused));
        assert!(memo.parse(LOCK).is_ok());
    }

    #[test]
    fn shared_entries_read_like_the_parse() {
        let shared = BunEntries::new(BunTextLock::parse_shared(LOCK).unwrap());
        let parsed = BunTextLock::parse(LOCK).unwrap();
        let keys: Vec<&str> = (&shared).into_iter().map(|e| e.key.as_str()).collect();
        assert_eq!(keys, ["left-pad"]);
        assert_eq!(shared.len(), parsed.entries.len());
        assert_eq!(shared[0].elems, parsed.entries[0].elems);
    }
}
