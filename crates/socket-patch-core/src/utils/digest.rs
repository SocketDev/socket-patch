//! Shape predicates for the content pins lockfiles record — the ONE copy of
//! each check the lock inventory, lockfile discovery, ledger recovery and
//! the rewriters share.
//!
//! Two case policies, chosen per call site: the `is_hex` family accepts
//! either case (and the `Option` helpers lowercase what they accept), while
//! [`is_hex64_lower`] is the exact shape cargo and `hex::encode` write. A
//! call site never switches from one policy to the other silently — the
//! inventory's cargo checksum, for one, feeds ledger liveness through the
//! crates.io provenance it records.

/// Whether `s` is an SRI integrity pin in an algorithm npm-family package
/// managers verify: its first whitespace-separated token is
/// `sha512-` / `sha384-` / `sha256-` / `sha1-` followed by a digest. The ONE
/// rule the inventory and every lockfile-discovery extractor share, so a
/// string is a pin in both or in neither.
pub(crate) fn is_sri_pin(s: &str) -> bool {
    s.split_whitespace().next().is_some_and(|first| {
        ["sha512-", "sha384-", "sha256-", "sha1-"]
            .iter()
            .any(|p| first.starts_with(p) && first.len() > p.len())
    })
}

/// `len` hex digits, either case.
pub(crate) fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 64 LOWERCASE hex digits — the exact shape `hex::encode(sha256)` / the TS
/// `Buffer.toString('hex')` and cargo's `checksum` produce (anything else
/// written as a Cargo.lock `checksum` breaks the next fetch).
pub(crate) fn is_hex64_lower(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A hex sha256 (64 hex digits, either case), lowercased.
pub(crate) fn sha256_hex(s: &str) -> Option<String> {
    is_hex(s, 64).then(|| s.to_ascii_lowercase())
}

/// `sha256:<hex>` (uv / poetry / pdm artifact hashes) → the lowercased hex.
pub(crate) fn sha256_prefixed(s: &str) -> Option<String> {
    s.strip_prefix("sha256:").and_then(sha256_hex)
}

/// A hex sha1 (40 hex digits, either case), lowercased.
pub(crate) fn sha1_hex(s: &str) -> Option<String> {
    is_hex(s, 40).then(|| s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_keep_their_case_policies() {
        let lower = "a".repeat(64);
        let upper = "A".repeat(64);
        assert!(is_hex(&lower, 64) && is_hex(&upper, 64));
        assert!(is_hex64_lower(&lower) && !is_hex64_lower(&upper));
        assert_eq!(sha256_hex(&upper), Some(lower.clone()));
        assert_eq!(sha256_prefixed(&format!("sha256:{upper}")), Some(lower));
        assert_eq!(sha256_prefixed(&upper), None);
        assert_eq!(sha1_hex(&"B".repeat(40)), Some("b".repeat(40)));
        assert_eq!(sha1_hex(&"b".repeat(41)), None);
        assert!(is_sri_pin("sha512-abc") && !is_sri_pin("sha512-") && !is_sri_pin("md5-x"));
    }
}
