//! Per-run memo for the project files a vendor backend re-reads once per
//! patched package.
//!
//! A vendor run calls into a backend once per package, and each call
//! re-reads AND re-parses the same lock or project file — O(patched × lock)
//! parsing for a document that is identical every time the bytes are. The
//! memo keeps the READ (the TOCTOU posture is deliberate: a backend must
//! see a lock that something else changed between two packages, and the
//! ledger records what each package actually found) and skips only the
//! parse, and only when the bytes just read are byte-for-byte the ones that
//! produced the cached document.
//!
//! That byte comparison is the whole correctness argument, and it is what
//! makes a missed invalidation cost a parse rather than a wrong answer: a
//! write the memo never heard about changes the bytes, the next read sees
//! them differ, and the slot is refilled from the file. Backends still
//! re-seed the slot with what they themselves wrote ([`ParseMemo::store`])
//! so the next package hits, and drop it ([`ParseMemo::invalidate`]) on the
//! rollback paths, where the bytes that land are not the ones in hand.
//!
//! One slot per call site: a run wires one lock per backend, so a single
//! `(path, bytes, doc)` triple is all any run reaches for and the memo can
//! never grow. The document is handed out behind an `Arc`, so the read-only
//! probes — the idempotent hot path a re-run is made of — never copy it,
//! and the callers that mutate clone it exactly as a parse would have
//! allocated it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// One memoized `(path, bytes) -> document` slot. Declared as a `static`
/// next to the read it serves; see the module docs.
pub(crate) struct ParseMemo<T> {
    slot: Mutex<Option<Cached<T>>>,
}

struct Cached<T> {
    path: PathBuf,
    bytes: Vec<u8>,
    doc: Arc<T>,
}

impl<T> ParseMemo<T> {
    pub(crate) const fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// `path`'s document for the `bytes` the caller just read, running
    /// `parse` only when the slot does not already hold that exact pair. A
    /// parse failure is returned unchanged and never cached, so the next
    /// call re-runs it and reports the same error.
    pub(crate) fn parse<E>(
        &self,
        path: &Path,
        bytes: &[u8],
        parse: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        if let Some(doc) = self.get(path, bytes) {
            return Ok(doc);
        }
        let doc = Arc::new(parse()?);
        self.put(path, bytes.to_vec(), Arc::clone(&doc));
        Ok(doc)
    }

    /// [`Self::parse`] for a reader that cannot fail.
    pub(crate) fn parse_infallible(
        &self,
        path: &Path,
        bytes: &[u8],
        parse: impl FnOnce() -> T,
    ) -> Arc<T> {
        match self.parse::<std::convert::Infallible>(path, bytes, || Ok(parse())) {
            Ok(doc) => doc,
        }
    }

    /// The cached document for `path`, but only when the slot holds exactly
    /// `bytes`.
    pub(crate) fn get(&self, path: &Path, bytes: &[u8]) -> Option<Arc<T>> {
        let slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        slot.as_ref()
            .filter(|cached| cached.path == path && cached.bytes == bytes)
            .map(|cached| Arc::clone(&cached.doc))
    }

    /// Re-seed the slot with the document the caller just WROTE to `path`,
    /// as `bytes`, so the next package's read hits instead of re-parsing
    /// this run's own output. The caller must pass the document those exact
    /// bytes serialize from — anything else and the next package would
    /// simply miss (the bytes would not match), never read a wrong doc.
    pub(crate) fn store(&self, path: &Path, bytes: Vec<u8>, doc: T) -> Arc<T> {
        let doc = Arc::new(doc);
        self.put(path, bytes, Arc::clone(&doc));
        doc
    }

    /// Forget `path`'s document. Never needed for correctness — [`Self::get`]
    /// already refuses a slot whose bytes have moved on — this is how a
    /// write path that does not hold the bytes it produced (a staged swap, a
    /// revert that restores the pre-vendor original) stops the memo from
    /// holding a document nothing will hit again.
    pub(crate) fn invalidate(&self, path: &Path) {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.as_ref().is_some_and(|cached| cached.path == path) {
            *slot = None;
        }
    }

    fn put(&self, path: &Path, bytes: Vec<u8>, doc: Arc<T>) {
        let mut slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        *slot = Some(Cached {
            path: path.to_path_buf(),
            bytes,
            doc,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn memo() -> ParseMemo<String> {
        ParseMemo::new()
    }

    #[test]
    fn identical_bytes_at_the_same_path_parse_once() {
        let memo = memo();
        let parses = AtomicUsize::new(0);
        let path = Path::new("/p/lock.json");
        let parse = || {
            parses.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>("doc".to_string())
        };
        assert_eq!(*memo.parse(path, b"a", parse).unwrap(), "doc");
        assert_eq!(*memo.parse(path, b"a", parse).unwrap(), "doc");
        assert_eq!(parses.load(Ordering::SeqCst), 1);
    }

    /// The memo exists to survive a run where nothing touches the file; the
    /// moment the bytes differ it must re-parse, whoever changed them and
    /// whether or not anyone invalidated it. This is the TOCTOU posture the
    /// backends rely on.
    #[test]
    fn different_bytes_re_parse_without_any_invalidation() {
        let memo = memo();
        let path = Path::new("/p/lock.json");
        assert_eq!(
            *memo.parse(path, b"a", || Ok::<_, ()>("A".into())).unwrap(),
            "A"
        );
        assert_eq!(
            *memo.parse(path, b"b", || Ok::<_, ()>("B".into())).unwrap(),
            "B"
        );
        assert_eq!(
            *memo.parse(path, b"a", || Ok::<_, ()>("A".into())).unwrap(),
            "A"
        );
    }

    #[test]
    fn the_same_bytes_at_another_path_re_parse() {
        let memo = memo();
        let parses = AtomicUsize::new(0);
        let parse = || {
            parses.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>("doc".to_string())
        };
        memo.parse(Path::new("/one/lock"), b"a", parse).unwrap();
        memo.parse(Path::new("/two/lock"), b"a", parse).unwrap();
        assert_eq!(parses.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_parse_failure_is_not_cached() {
        let memo = memo();
        let path = Path::new("/p/lock.json");
        assert!(memo.parse(path, b"a", || Err::<String, _>("bad")).is_err());
        assert_eq!(
            *memo.parse(path, b"a", || Ok::<_, ()>("A".into())).unwrap(),
            "A"
        );
    }

    #[test]
    fn store_seeds_the_slot_for_the_next_read() {
        let memo = memo();
        let path = Path::new("/p/lock.json");
        memo.store(path, b"written".to_vec(), "W".to_string());
        let parses = AtomicUsize::new(0);
        let doc = memo
            .parse(path, b"written", || {
                parses.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>("re-parsed".to_string())
            })
            .unwrap();
        assert_eq!(*doc, "W");
        assert_eq!(parses.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn invalidate_only_drops_its_own_path() {
        let memo = memo();
        let path = Path::new("/p/lock.json");
        memo.store(path, b"a".to_vec(), "A".to_string());
        memo.invalidate(Path::new("/other/lock.json"));
        assert!(memo.get(path, b"a").is_some());
        memo.invalidate(path);
        assert!(memo.get(path, b"a").is_none());
    }
}
