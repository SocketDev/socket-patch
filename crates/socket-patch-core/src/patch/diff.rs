//! Per-file diff (bsdiff) apply support.
//!
//! A `diff` is a binary delta in bsdiff 4.x format that transforms the
//! `beforeHash` bytes of a file into the `afterHash` bytes. We store diffs
//! grouped by patch UUID — see [`crate::patch::package`] for the tar.gz
//! archive layout.

use qbsdiff::Bspatch;

/// Apply a bsdiff delta to `before` and return the resulting bytes.
///
/// Returns an `std::io::Error` when the delta is malformed or applying it
/// fails (for example, the delta was produced from a different source).
pub fn apply_diff(before: &[u8], delta: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let patcher = Bspatch::new(delta)?;
    let mut out = Vec::with_capacity(patcher.hint_target_size() as usize);
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
}
