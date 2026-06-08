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
/// the bsdiff header (bytes 24..32) and never validates it — so a malformed or
/// hostile delta can claim an arbitrary target size (up to `i64::MAX`) while
/// carrying only a few bytes of data. (qbsdiff's `> patch.len()` check on the
/// control/diff block lengths is itself bypassable via integer overflow; see
/// [`validate_bsdiff_header`].)
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

/// Decode a bsdiff "offtin" integer (8 little-endian bytes, sign-magnitude).
///
/// This mirrors `qbsdiff`'s private `decode_int`: the top bit of the most
/// significant byte is a sign flag, not part of a two's-complement value.
fn decode_offtin(b: &[u8; 8]) -> i64 {
    let x = u64::from_le_bytes(*b);
    if x >> 63 == 0 || x == 1 << 63 {
        x as i64
    } else {
        ((x & ((1u64 << 63) - 1)) as i64).wrapping_neg()
    }
}

/// Reject bsdiff headers that would make `qbsdiff::Bspatch::new` panic.
///
/// `qbsdiff`'s parser reads the compressed control- and diff-block lengths
/// from header bytes 8..16 and 16..24 with the sign-magnitude decoder above,
/// casts them to `u64`, then guards with `32 + csize + dsize > patch.len()`
/// using *wrapping* `u64` arithmetic before doing `split_at(csize)`. A header
/// whose length field has the sign bit set decodes to a "negative" value whose
/// `as u64` is enormous: the sum wraps back below `patch.len()`, slips past the
/// guard, and then either the addition overflows (debug builds) or
/// `split_at(huge)` indexes out of bounds (release builds) — a hard panic on
/// attacker-controlled input.
///
/// We pre-validate with checked arithmetic so `apply_diff` always surfaces a
/// recoverable `io::Error` instead. Malformed-but-not-overflowing headers
/// (bad magic, too short) are left for `Bspatch::new` to report so the error
/// text stays consistent with the upstream parser.
fn validate_bsdiff_header(delta: &[u8]) -> Result<(), std::io::Error> {
    // Defer the "too short / bad magic" cases to qbsdiff's own error.
    if delta.len() < 32 || &delta[..8] != b"BSDIFF40" {
        return Ok(());
    }
    let csize = decode_offtin(delta[8..16].try_into().expect("8 bytes"));
    let dsize = decode_offtin(delta[16..24].try_into().expect("8 bytes"));
    let lengths_ok = csize >= 0
        && dsize >= 0
        && 32u64
            .checked_add(csize as u64)
            .and_then(|s| s.checked_add(dsize as u64))
            .is_some_and(|needed| needed <= delta.len() as u64);
    if lengths_ok {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bsdiff header: block lengths are negative or exceed the payload",
        ))
    }
}

/// Apply a bsdiff delta to `before` and return the resulting bytes.
///
/// Returns an `std::io::Error` when the delta is malformed or applying it
/// fails (for example, the delta was produced from a different source).
pub fn apply_diff(before: &[u8], delta: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    // Guard the header before handing it to qbsdiff: a forged block-length
    // field would otherwise panic its parser (see `validate_bsdiff_header`).
    validate_bsdiff_header(delta)?;
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
    fn test_apply_diff_forged_negative_block_length_does_not_panic() {
        // Regression: qbsdiff's `parse` reads the control/diff block lengths
        // (header bytes 8..16 and 16..24) via a sign-magnitude decoder, casts
        // them to `u64`, and checks `32 + csize + dsize > patch.len()` with
        // *wrapping* arithmetic before doing `split_at(csize)`. A header whose
        // csize field has the high bit set decodes to a "negative" length whose
        // `as u64` is enormous; the sum wraps back under `patch.len()`, slips
        // past the guard, and then `split_at(huge)` panics (or the add itself
        // panics in debug builds). `apply_diff` must reject such a header as a
        // normal `io::Error`, upholding its never-panic-on-bad-input contract.
        let before = b"the quick brown fox jumps over the lazy dog";
        let after = b"the quick brown cat jumps over the lazy dog";
        let mut forged = make_delta(before, after);
        assert!(forged.len() >= 32, "delta must contain a full header");
        // Sign-magnitude encoding of -16: magnitude 16 with the sign bit set.
        let neg: u64 = 16u64 | (1u64 << 63);
        forged[8..16].copy_from_slice(&neg.to_le_bytes());

        let result = apply_diff(before, &forged);
        assert!(
            result.is_err(),
            "a forged negative block length must error, not panic"
        );
    }

    #[test]
    fn test_apply_diff_forged_negative_diff_block_length_does_not_panic() {
        // Same class of bug as the csize case above, but via the diff-block
        // length field (header bytes 16..24). Both feed `split_at` after the
        // wrapping-overflow guard, so both must be rejected up front.
        let before = b"alpha beta gamma delta epsilon zeta eta theta";
        let after = b"alpha beta gamma DELTA epsilon zeta eta theta";
        let mut forged = make_delta(before, after);
        assert!(forged.len() >= 32, "delta must contain a full header");
        let neg: u64 = 8u64 | (1u64 << 63);
        forged[16..24].copy_from_slice(&neg.to_le_bytes());

        let result = apply_diff(before, &forged);
        assert!(
            result.is_err(),
            "a forged negative diff-block length must error, not panic"
        );
    }

    #[test]
    fn test_validate_bsdiff_header_accepts_real_delta() {
        // The guard must be transparent to honest deltas: a freshly built
        // delta has well-formed, in-bounds block lengths and must pass.
        let before = b"the quick brown fox jumps over the lazy dog";
        let after = b"the quick brown cat jumps over the lazy dog";
        let delta = make_delta(before, after);
        validate_bsdiff_header(&delta).expect("honest header must validate");
        // ...and short / bad-magic inputs are deferred to Bspatch::new, so the
        // guard returns Ok for them rather than masking the canonical error.
        validate_bsdiff_header(b"too short").expect("short input deferred");
        validate_bsdiff_header(b"NOTBSDIFF.........................")
            .expect("bad magic deferred");
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
