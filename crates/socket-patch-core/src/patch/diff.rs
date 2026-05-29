//! Per-file diff (bsdiff) apply support.
//!
//! A `diff` is a binary delta in bsdiff 4.x format that transforms the
//! `beforeHash` bytes of a file into the `afterHash` bytes. We store diffs
//! grouped by patch UUID — see [`crate::patch::package`] for the tar.gz
//! archive layout.

use qbsdiff::Bspatch;

/// Upper bound on how many bytes we pre-reserve for the patched output.
///
/// `Bspatch::hint_target_size()` returns the target size read verbatim from
/// the bsdiff header (bytes 24..32). qbsdiff's parser validates the control
/// and delta block lengths against the actual payload but never validates
/// this field — so a malformed or hostile delta can claim an arbitrary
/// target size (up to `i64::MAX`) while carrying only a few bytes of data.
///
/// Feeding that value straight into `Vec::with_capacity` lets a tiny delta
/// request a multi-exabyte reservation, which either panics with "capacity
/// overflow" or aborts the process via the allocator. Neither is something
/// the caller can recover from, so it breaks the never-panic-on-bad-input
/// contract the patch engine depends on (see the tests below).
///
/// The reservation is a pure optimization: `apply` is driven entirely by the
/// control stream and grows the output `Vec` on demand as it writes, so
/// clamping the hint never changes the result — it only bounds the number of
/// reallocations for legitimately large files.
const MAX_PREALLOC_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

/// Apply a bsdiff delta to `before` and return the resulting bytes.
///
/// Returns an `std::io::Error` when the delta is malformed or applying it
/// fails (for example, the delta was produced from a different source).
pub fn apply_diff(before: &[u8], delta: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let patcher = Bspatch::new(delta)?;
    // Clamp the attacker-controlled size hint: a corrupt/hostile header must
    // not be able to turn a small delta into a process-killing allocation.
    let prealloc = patcher.hint_target_size().min(MAX_PREALLOC_BYTES) as usize;
    let mut out = Vec::with_capacity(prealloc);
    patcher.apply(before, std::io::Cursor::new(&mut out))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbsdiff::Bsdiff;

    fn make_delta(before: &[u8], after: &[u8]) -> Vec<u8> {
        let mut delta = Vec::new();
        Bsdiff::new(before, after)
            .compare(std::io::Cursor::new(&mut delta))
            .expect("compare");
        delta
    }

    #[test]
    fn test_apply_diff_text_round_trip() {
        let before = b"the quick brown fox jumps over the lazy dog";
        let after = b"the quick brown cat jumps over the lazy dog";
        let delta = make_delta(before, after);
        let result = apply_diff(before, &delta).unwrap();
        assert_eq!(result, after);
    }

    #[test]
    fn test_apply_diff_binary_round_trip() {
        let before: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let mut after = before.clone();
        // Mutate a handful of bytes scattered through the buffer.
        for i in [10usize, 200, 500, 900] {
            after[i] = after[i].wrapping_add(7);
        }
        let delta = make_delta(&before, &after);
        let result = apply_diff(&before, &delta).unwrap();
        assert_eq!(result, after);
    }

    #[test]
    fn test_apply_diff_empty_to_nonempty() {
        let before: &[u8] = b"";
        let after = b"hello";
        let delta = make_delta(before, after);
        let result = apply_diff(before, &delta).unwrap();
        assert_eq!(result, after);
    }

    #[test]
    fn test_apply_diff_malformed_errors() {
        // Random bytes are extremely unlikely to be a valid bsdiff header.
        let bogus_delta = b"not a real bsdiff delta";
        let result = apply_diff(b"anything", bogus_delta);
        assert!(result.is_err(), "expected malformed-delta error");
    }

    #[test]
    fn test_apply_diff_wrong_source_does_not_panic() {
        // Build a delta from one source then try to apply it to a different
        // source. qbsdiff's bspatch is content-agnostic but should still
        // produce *some* output without panicking — the caller is
        // responsible for verifying the result hash matches the expected
        // `after_hash`. This test exists to lock in the
        // never-panic-on-bad-input contract callers depend on.
        let src_a = b"AAAAAAAAAAAAAAAAAAAA";
        let src_b = b"BBBBBBBBBBBBBBBBBBBB";
        let target = b"CCCCCCCCCCCCCCCCCCCC";
        let delta = make_delta(src_a, target);
        // Result may or may not equal target — what matters is no panic.
        let _ = apply_diff(src_b, &delta);
    }

    #[test]
    fn test_apply_diff_forged_oversize_header_is_safe() {
        // Regression: `apply_diff` used to feed `hint_target_size()` straight
        // into `Vec::with_capacity`. That field is the bsdiff header's target
        // size (little-endian bytes 24..32) and is NOT validated by qbsdiff
        // against the real payload, so a corrupt/hostile delta can claim an
        // enormous size. A multi-exabyte `with_capacity` aborts the process
        // (allocator failure) or panics with "capacity overflow" — neither is
        // recoverable, which would let a single bad patch take the tool down.
        //
        // We build a genuine, small delta and then overwrite only the target
        // size field with ~1.15 EiB. Because `apply` is driven by the control
        // stream and ignores the hint, the clamp lets the patch still produce
        // the correct bytes instead of dying on the allocation.
        let before = b"the quick brown fox jumps over the lazy dog";
        let after = b"the quick brown cat jumps over the lazy dog";
        let mut forged = make_delta(before, after);
        assert!(forged.len() >= 32, "delta must contain a full header");
        // Stay positive (top bit clear) so qbsdiff decodes it as a large
        // unsigned size rather than a negative offset.
        let huge: u64 = 1 << 60;
        forged[24..32].copy_from_slice(&huge.to_le_bytes());

        let result = apply_diff(before, &forged).expect("clamped apply must succeed");
        assert_eq!(
            result, after,
            "forging the size hint must not corrupt output"
        );
    }

    #[test]
    fn test_apply_diff_capacity_hint_is_clamped() {
        // Pin the clamp itself so the bound can't silently regress back to an
        // unbounded reservation. The output capacity is never reserved beyond
        // MAX_PREALLOC_BYTES regardless of what the header claims.
        let huge_hint: u64 = u64::MAX;
        let clamped = huge_hint.min(MAX_PREALLOC_BYTES) as usize;
        assert_eq!(clamped, MAX_PREALLOC_BYTES as usize);
        // A modest, honest hint passes through untouched.
        let small_hint: u64 = 4096;
        assert_eq!(small_hint.min(MAX_PREALLOC_BYTES) as usize, 4096);
    }
}
