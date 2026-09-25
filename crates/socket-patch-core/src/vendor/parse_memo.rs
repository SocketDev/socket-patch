//! Per-run memo for the project files a vendor backend re-reads once per
//! patched package.
//!
//! A vendor run calls into a backend once per package, and each call
//! re-reads AND re-parses the same lock or project file — O(patched × lock)
//! parsing for a document that is identical every time the bytes are. The
//! memo keeps the READ (the TOCTOU posture is deliberate: a backend must
//! see a lock something else changed between two packages, and the ledger
//! records what each package actually found) and skips only the parse, and
//! only when the bytes just read are byte-for-byte the ones that produced
//! the cached document.
//!
//! That byte comparison is the whole correctness argument, and it is what
//! makes a missed invalidation cost a parse rather than a wrong answer: a
//! write the memo never heard about changes the bytes, the next read sees
//! them differ, and the slot is refilled. Backends still re-seed the slot
//! with what they themselves wrote ([`ParseMemo::store`]) so the next
//! package hits, and drop it ([`ParseMemo::invalidate`]) where a write
//! leaves bytes nobody holds.
//!
//! **Contract:** the parse handed to a memo must be a pure function of the
//! bytes. The key is the bytes alone — deliberately, since two reads with
//! the same bytes have the same parse whichever file they came from — so a
//! parse that also consulted its path, the environment or the clock would
//! be memoized against the wrong input.
//!
//! One slot per call site: a run wires one lock per backend, so a single
//! `(bytes, doc)` pair is all any run reaches for and the memo can never
//! grow. The document is handed out behind an `Arc`, so the read-only
//! probes — the idempotent hot path a re-run is made of — never copy it,
//! and the callers that mutate clone it exactly as a parse would have
//! allocated it.

use std::sync::{Arc, Mutex, PoisonError};

/// One memoized `bytes -> document` slot. Declared as a `static` next to
/// the read it serves; see the module docs.
pub(crate) struct ParseMemo<T> {
    slot: Mutex<Option<(Vec<u8>, Arc<T>)>>,
}

impl<T> ParseMemo<T> {
    pub(crate) const fn new() -> Self {
        Self {
            slot: Mutex::new(None),
        }
    }

    /// The document for the `bytes` the caller just read, running `parse`
    /// only when the slot does not already hold them. A parse failure is
    /// returned unchanged and never cached, so the next call re-runs it and
    /// reports the same error.
    pub(crate) fn parse<E>(
        &self,
        bytes: &[u8],
        parse: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        if let Some(doc) = self.get(bytes) {
            return Ok(doc);
        }
        let doc = Arc::new(parse()?);
        self.put(bytes.to_vec(), Arc::clone(&doc));
        Ok(doc)
    }

    /// [`Self::parse`] for a reader that cannot fail.
    pub(crate) fn parse_infallible(&self, bytes: &[u8], parse: impl FnOnce() -> T) -> Arc<T> {
        if let Some(doc) = self.get(bytes) {
            return doc;
        }
        let doc = Arc::new(parse());
        self.put(bytes.to_vec(), Arc::clone(&doc));
        doc
    }

    /// The cached document, but only when the slot holds exactly `bytes`.
    pub(crate) fn get(&self, bytes: &[u8]) -> Option<Arc<T>> {
        let slot = self.slot.lock().unwrap_or_else(PoisonError::into_inner);
        slot.as_ref()
            .filter(|(cached, _)| cached == bytes)
            .map(|(_, doc)| Arc::clone(doc))
    }

    /// Re-seed the slot with the document the caller just WROTE, as `bytes`,
    /// so the next package's read hits instead of re-parsing this run's own
    /// output. The caller must pass the document those exact bytes serialize
    /// from — anything else and the next package simply misses (the bytes
    /// would not match); it can never be handed a document the bytes on disk
    /// disagree with.
    pub(crate) fn store(&self, bytes: Vec<u8>, doc: T) -> Arc<T> {
        let doc = Arc::new(doc);
        self.put(bytes, Arc::clone(&doc));
        doc
    }

    /// Forget the slot. Never needed for correctness — [`Self::get`] already
    /// refuses a slot whose bytes have moved on — this is how a write path
    /// that does not hold the bytes it produced (a staged swap, a deleted
    /// file, a revert that restores the pre-vendor original) stops the memo
    /// from holding a document nothing will hit again.
    pub(crate) fn invalidate(&self) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn put(&self, bytes: Vec<u8>, doc: Arc<T>) {
        *self.slot.lock().unwrap_or_else(PoisonError::into_inner) = Some((bytes, doc));
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
    fn identical_bytes_parse_once() {
        let memo = memo();
        let parses = AtomicUsize::new(0);
        let parse = || {
            parses.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ()>("doc".to_string())
        };
        assert_eq!(*memo.parse(b"a", parse).unwrap(), "doc");
        assert_eq!(*memo.parse(b"a", parse).unwrap(), "doc");
        assert_eq!(parses.load(Ordering::SeqCst), 1);
    }

    /// The memo exists to survive a run where nothing touches the file; the
    /// moment the bytes differ it must re-parse, whoever changed them and
    /// whether or not anyone invalidated it. This is the TOCTOU posture the
    /// backends rely on.
    #[test]
    fn different_bytes_re_parse_without_any_invalidation() {
        let memo = memo();
        assert_eq!(*memo.parse(b"a", || Ok::<_, ()>("A".into())).unwrap(), "A");
        assert_eq!(*memo.parse(b"b", || Ok::<_, ()>("B".into())).unwrap(), "B");
        assert_eq!(*memo.parse(b"a", || Ok::<_, ()>("A".into())).unwrap(), "A");
    }

    #[test]
    fn a_parse_failure_is_not_cached() {
        let memo = memo();
        assert!(memo.parse(b"a", || Err::<String, _>("bad")).is_err());
        assert_eq!(*memo.parse(b"a", || Ok::<_, ()>("A".into())).unwrap(), "A");
    }

    #[test]
    fn store_seeds_the_slot_for_the_next_read() {
        let memo = memo();
        memo.store(b"written".to_vec(), "W".to_string());
        let parses = AtomicUsize::new(0);
        let doc = memo
            .parse(b"written", || {
                parses.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ()>("re-parsed".to_string())
            })
            .unwrap();
        assert_eq!(*doc, "W");
        assert_eq!(parses.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn invalidate_drops_the_slot() {
        let memo = memo();
        memo.store(b"a".to_vec(), "A".to_string());
        assert!(memo.get(b"a").is_some());
        memo.invalidate();
        assert!(memo.get(b"a").is_none());
    }

    #[test]
    fn parse_infallible_memoizes_too() {
        let memo = memo();
        let parses = AtomicUsize::new(0);
        let parse = || {
            parses.fetch_add(1, Ordering::SeqCst);
            "doc".to_string()
        };
        assert_eq!(*memo.parse_infallible(b"a", parse), "doc");
        assert_eq!(*memo.parse_infallible(b"a", parse), "doc");
        assert_eq!(parses.load(Ordering::SeqCst), 1);
    }
}
