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
    /// inventory, in VEX discovery and in the hosted redirect (and the
    /// vendored preflight once per package), and parsing a large lock is
    /// most of a Bun rescan's CPU (#1606). The last lock
    /// parsed is kept, and a text whose lines are exactly its
    /// [`Self::lines`] gets it back; any other text (a changed lock) is
    /// parsed again. A refused lock is not kept. Readers only; a splice
    /// edits a copy of [`Self::lines`].
    pub(crate) fn parse_shared(text: &str) -> Result<Arc<Self>, BunTextError> {
        static LAST: ParseMemo = ParseMemo::new();
        LAST.parse(text)
    }

    /// Whether `text` is the text this lock was parsed from.
    fn is_parse_of(&self, text: &str) -> bool {
        let mut lines = self.lines.iter();
        text.split('\n')
            .all(|line| lines.next().is_some_and(|parsed| parsed == line))
            && lines.next().is_none()
    }
}

/// The last lock [`BunTextLock::parse_shared`] parsed.
struct ParseMemo(Mutex<Option<Arc<BunTextLock>>>);

impl ParseMemo {
    const fn new() -> Self {
        ParseMemo(Mutex::new(None))
    }

    fn parse(&self, text: &str) -> Result<Arc<BunTextLock>, BunTextError> {
        let last = || self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(lock) = last().as_ref().filter(|lock| lock.is_parse_of(text)) {
            return Ok(Arc::clone(lock));
        }
        let lock = Arc::new(BunTextLock::parse(text)?);
        *last() = Some(Arc::clone(&lock));
        Ok(lock)
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
    fn refusals_are_not_kept() {
        let memo = ParseMemo::new();
        let first = memo.parse(LOCK).unwrap();
        let future = LOCK.replace("\"lockfileVersion\": 1,", "\"lockfileVersion\": 99,");
        let refused = memo.parse(&future).err().unwrap();
        assert!(matches!(refused, BunTextError::Version(_)));
        assert_eq!(memo.parse(&future).err(), Some(refused));
        // The refusal left the last good parse in place.
        assert!(Arc::ptr_eq(&first, &memo.parse(LOCK).unwrap()));
    }

    #[test]
    fn a_prefix_or_extension_is_another_text() {
        let memo = ParseMemo::new();
        let first = memo.parse(LOCK).unwrap();
        for other in [
            format!("{LOCK}\n"),
            LOCK.trim_end().to_string(),
            LOCK.replace('\n', "\r\n"),
        ] {
            let parsed = memo.parse(&other).unwrap();
            assert!(!Arc::ptr_eq(&first, &parsed), "{other:?}");
            assert_eq!(
                parsed.lines,
                other.split('\n').map(str::to_string).collect::<Vec<_>>()
            );
            memo.parse(LOCK).unwrap();
        }
    }

    #[test]
    fn shared_parse_reads_like_the_parse() {
        let shared = BunTextLock::parse_shared(LOCK).unwrap();
        let parsed = BunTextLock::parse(LOCK).unwrap();
        assert_eq!(shared.lines, parsed.lines);
        assert_eq!(shared.entries.len(), parsed.entries.len());
        assert_eq!(shared.entries[0].elems, parsed.entries[0].elems);
    }
}
