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
//! package hits, and drop it ([`ParseMemo::invalidate`], or
//! [`ParseMemo::forget`] for one file of a multi-slot site) where a write
//! leaves bytes nobody holds. The one write path that drops nothing is a
//! poetry/pdm revert, which goes through the shared splice helpers in
//! `common.rs` and cannot reach a backend's private static; it leaves its
//! slot to be evicted by the next read, at the cost of holding one document
//! until then.
//!
//! **Contract:** the parse handed to a memo must be a pure function of the
//! bytes. The key is the bytes alone — deliberately, since two reads with
//! the same bytes have the same parse whichever file they came from — so a
//! parse that also consulted its path, the environment or the clock would
//! be memoized against the wrong input.
//!
//! One slot per call site by default: a run wires one lock per backend, so
//! a single `(bytes, doc)` pair is all most runs reach for and the memo can
//! never grow. A site that reads a SET of files in one pass (a project's
//! PEP 751 locks, the two cargo config spellings) asks for as many slots as
//! that set can hold, which is the only reason the count is a parameter —
//! more slots mean more retained documents.
//!
//! **Cost:** a filled slot holds a parsed document AND a copy of the bytes
//! it came from, in a `static`, until a write drops it or the process
//! exits — and a parsed document is itself several times its own source
//! text. Measured against the pre-memo build on a 2.5 MB `composer.lock`,
//! peak RSS moved by +3 MB on an idempotent re-run and +15-21 MB on the
//! fresh and revert paths, so the sites whose file runs to megabytes
//! (uv.lock, a package-lock.json, the vendor ledger) are the ones that
//! decide a run's peak. Keying a slot on an `Arc<[u8]>` the reader already
//! holds would remove the bytes half.
//!
//! The document is handed out behind an `Arc`, so the read-only probes —
//! the idempotent hot path a re-run is made of — never copy it, and the
//! callers that mutate clone it exactly as a parse would have allocated
//! it.

use std::sync::{Arc, Mutex, PoisonError};

/// Up to `N` memoized `bytes -> document` slots, most recent first.
/// Declared as a `static` next to the read it serves; see the module docs.
pub(crate) struct ParseMemo<T, const N: usize = 1> {
    slots: Mutex<Vec<(Vec<u8>, Arc<T>)>>,
}

impl<T, const N: usize> ParseMemo<T, N> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
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

    /// The cached document, but only when a slot holds exactly `bytes`.
    pub(crate) fn get(&self, bytes: &[u8]) -> Option<Arc<T>> {
        let slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots
            .iter()
            .find(|(cached, _)| cached == bytes)
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
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    /// [`Self::invalidate`] for ONE file of a multi-slot site: forget the
    /// slot holding `bytes` and leave the others alone. A site that writes
    /// one of the files it memoized uses this so the ones it did not write
    /// keep hitting.
    pub(crate) fn forget(&self, bytes: &[u8]) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(cached, _)| cached != bytes);
    }

    fn put(&self, bytes: Vec<u8>, doc: Arc<T>) {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        slots.retain(|(cached, _)| cached != &bytes);
        slots.insert(0, (bytes, doc));
        slots.truncate(N);
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
    fn invalidate_drops_every_slot() {
        let memo = memo();
        memo.store(b"a".to_vec(), "A".to_string());
        assert!(memo.get(b"a").is_some());
        memo.invalidate();
        assert!(memo.get(b"a").is_none());
    }

    /// A site that writes ONE of the files it memoized drops that slot and
    /// keeps the others: npm 12's dual-lock state rewrites the lock that
    /// holds the match and leaves the other exactly as parsed.
    #[test]
    fn forget_drops_one_slot_and_leaves_the_rest() {
        let memo: ParseMemo<String, 2> = ParseMemo::new();
        memo.store(b"primary".to_vec(), "P".to_string());
        memo.store(b"sibling".to_vec(), "S".to_string());
        memo.forget(b"sibling");
        assert!(memo.get(b"sibling").is_none());
        assert_eq!(memo.get(b"primary").as_deref(), Some(&"P".to_string()));
        // Bytes no slot holds: a no-op, not a clear.
        memo.forget(b"neither");
        assert!(memo.get(b"primary").is_some());
    }

    /// A one-slot memo holds only the newest bytes; the site that reads a
    /// SET of files in one pass asks for a slot per file so alternating
    /// reads do not evict each other.
    #[test]
    fn slot_count_bounds_what_is_remembered() {
        let one: ParseMemo<String> = ParseMemo::new();
        one.store(b"a".to_vec(), "A".to_string());
        one.store(b"b".to_vec(), "B".to_string());
        assert!(one.get(b"a").is_none());
        assert!(one.get(b"b").is_some());

        let two: ParseMemo<String, 2> = ParseMemo::new();
        two.store(b"a".to_vec(), "A".to_string());
        two.store(b"b".to_vec(), "B".to_string());
        assert!(two.get(b"a").is_some());
        assert!(two.get(b"b").is_some());
        two.store(b"c".to_vec(), "C".to_string());
        assert!(two.get(b"a").is_none(), "the oldest slot is evicted");
        assert!(two.get(b"b").is_some());
        assert!(two.get(b"c").is_some());
    }

    /// Re-storing bytes a slot already holds must refresh, not duplicate:
    /// a two-slot memo that saw `a, b, a` still remembers `b`.
    #[test]
    fn re_storing_the_same_bytes_does_not_consume_a_second_slot() {
        let memo: ParseMemo<String, 2> = ParseMemo::new();
        memo.store(b"a".to_vec(), "A".to_string());
        memo.store(b"b".to_vec(), "B".to_string());
        memo.store(b"a".to_vec(), "A".to_string());
        assert!(memo.get(b"a").is_some());
        assert!(memo.get(b"b").is_some());
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
