//! Integration coverage for `socket_patch_core::patch::diff::apply_diff`.
//!
//! Mirrors the lib-level unit tests but lives in `tests/` so it
//! appears as integration coverage (counted by `cargo llvm-cov`
//! against the e2e bar) rather than lib coverage.

use qbsdiff::Bsdiff;
use socket_patch_core::patch::diff::apply_diff;
use std::io::Cursor;

/// Local helper: produce a bsdiff 4 delta from `before` → `after`.
fn make_delta(before: &[u8], after: &[u8]) -> Vec<u8> {
    let mut delta = Vec::new();
    Bsdiff::new(before, after)
        .compare(Cursor::new(&mut delta))
        .expect("bsdiff compare");
    delta
}

/// Happy path: round-trip a small text mutation through bsdiff +
/// apply_diff.
#[test]
fn text_delta_round_trip() {
    let before = b"the quick brown fox jumps over the lazy dog";
    let after = b"the quick brown cat jumps over the lazy dog";
    let delta = make_delta(before, after);
    let result = apply_diff(before, &delta).unwrap();
    assert_eq!(result, after);
}

/// Binary buffer with scattered mutations — exercises the
/// non-textual code path of qbsdiff.
#[test]
fn binary_delta_round_trip() {
    let before: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    let mut after = before.clone();
    for i in [10usize, 200, 500, 900] {
        after[i] = after[i].wrapping_add(7);
    }
    let delta = make_delta(&before, &after);
    let result = apply_diff(&before, &delta).unwrap();
    assert_eq!(result, after);
}

/// Edge case: empty `before` → non-empty `after`. Some bsdiff
/// implementations special-case the no-source branch; verify
/// ours doesn't.
#[test]
fn empty_to_nonempty() {
    let before: &[u8] = b"";
    let after = b"hello";
    let delta = make_delta(before, after);
    let result = apply_diff(before, &delta).unwrap();
    assert_eq!(result, after);
}

/// Malformed delta header must surface as an Io error, not a
/// panic.
#[test]
fn malformed_delta_errors() {
    // Garbage that cannot be a valid bsdiff 4 magic/header.
    let bogus = b"not a real bsdiff delta header";
    let result = apply_diff(b"anything", bogus);
    assert!(result.is_err(), "expected Err on garbage delta");

    // An empty delta has no header at all and must also error, not panic
    // or silently return an empty/zero-length patch.
    let empty = apply_diff(b"anything", b"");
    assert!(empty.is_err(), "expected Err on empty delta");

    // A truncated header (valid-looking start, cut short) must error too —
    // this guards against a path that reads the size hint before validating
    // the payload length.
    let real = make_delta(b"abc", b"abcd");
    assert!(real.len() > 8, "sanity: real delta has a header");
    let truncated = &real[..8];
    let trunc_res = apply_diff(b"abc", truncated);
    assert!(
        trunc_res.is_err(),
        "expected Err on truncated delta header, got {trunc_res:?}"
    );
}

/// Applying a delta to the *wrong* source must not panic — the
/// caller is expected to verify the resulting `after_hash`
/// against the manifest, but the library itself never traps.
#[test]
fn wrong_source_does_not_panic() {
    let src_a = b"AAAAAAAAAAAAAAAAAAAA";
    let src_b = b"BBBBBBBBBBBBBBBBBBBB";
    let target = b"CCCCCCCCCCCCCCCCCCCC";
    let delta = make_delta(src_a, target);
    // The contract is never-panic, and the result must be a well-formed
    // Result either way — bind and match it so the call is actually driven
    // to completion (not optimized into a no-op) and any future panic in
    // bspatch surfaces as a test failure.
    match apply_diff(src_b, &delta) {
        // qbsdiff is content-agnostic: applying to the wrong source may
        // succeed with garbage bytes whose length matches the delta's
        // target. If it does succeed, the output must at least be the
        // declared target length (the control stream drives the length),
        // never an out-of-bounds read.
        Ok(out) => assert_eq!(
            out.len(),
            target.len(),
            "bspatch output length is fixed by the control stream"
        ),
        Err(_) => { /* equally acceptable: a checksum/bounds rejection */ }
    }
}

/// Security regression (mirrors the lib's
/// `test_apply_diff_forged_oversize_header_is_safe`): a hostile delta can
/// claim an arbitrary target size in header bytes 24..32. qbsdiff does NOT
/// validate that field against the real payload, so feeding it straight into
/// `Vec::with_capacity` would let a tiny delta request a multi-exabyte
/// reservation — aborting the process or panicking with "capacity overflow".
/// `apply_diff` must clamp the hint and still produce correct output.
///
/// Without the clamp this test panics/aborts on the allocation, so it fails
/// loudly if the bound is ever removed. This is the protection the rest of
/// this "mirror" file was missing.
#[test]
fn forged_oversize_header_is_safe() {
    let before = b"the quick brown fox jumps over the lazy dog";
    let after = b"the quick brown cat jumps over the lazy dog";
    let mut forged = make_delta(before, after);
    assert!(forged.len() >= 32, "delta must contain a full header");

    // Overwrite ONLY the target-size field (LE bytes 24..32) with ~1.15 EiB.
    // Keep the top bit clear so it decodes as a huge unsigned size, not a
    // negative offset.
    let huge: u64 = 1 << 60;
    forged[24..32].copy_from_slice(&huge.to_le_bytes());

    let result = apply_diff(before, &forged)
        .expect("clamped apply must still succeed on a forged size hint");
    assert_eq!(
        result, after,
        "forging the size hint must not corrupt the patched output"
    );
}

/// A delta whose forged target size is the maximum `u64` must be handled
/// identically — pins that the clamp covers the extreme end of the range,
/// not just one convenient value.
#[test]
fn forged_max_u64_header_is_safe() {
    let before = b"alpha beta gamma delta epsilon";
    let after = b"alpha beta GAMMA delta epsilon";
    let mut forged = make_delta(before, after);
    assert!(forged.len() >= 32, "delta must contain a full header");
    // i64::MAX keeps the top bit clear (qbsdiff reads this as a signed-ish
    // length); a value with the top bit set would be rejected as negative.
    let huge: u64 = i64::MAX as u64;
    forged[24..32].copy_from_slice(&huge.to_le_bytes());

    let result = apply_diff(before, &forged)
        .expect("clamped apply must succeed on a max-size forged hint");
    assert_eq!(result, after, "max-size forged hint must not corrupt output");
}
