//! Shape predicates for the content pins lockfiles record — the ONE copy of
//! each check the lock inventory, lockfile discovery, ledger recovery and
//! the rewriters share — and the ONE copy of each digest computation
//! (`*_of`) that produces those pins from bytes.
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

// ── computations ──────────────────────────────────────────────────────────
// The `_of` suffix keeps a computation from sharing a name with the
// validators above: `sha256_hex(&str)` checks a pin, `sha256_hex_of(&[u8])`
// makes one.

/// Lowercase hex sha256 of `bytes` (the shape [`is_hex64_lower`] accepts).
pub(crate) fn sha256_hex_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

/// Lowercase hex sha1 of `bytes`.
pub(crate) fn sha1_hex_of(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    hex::encode(Sha1::digest(bytes))
}

/// Standard (padded) base64 of `bytes`' sha512: NuGet's `contentHash` and
/// the digest half of an SRI pin.
pub(crate) fn sha512_base64_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::{Digest, Sha512};
    base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
}

/// The `sha512-<base64>` SRI pin of `bytes`, as npm-family locks record it.
pub(crate) fn sha512_sri_of(bytes: &[u8]) -> String {
    format!("sha512-{}", sha512_base64_of(bytes))
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

    /// Known vectors (FIPS 180 / RFC 3174 test strings `""` and `"abc"`) for
    /// every computation, so each former inline copy's output is pinned.
    #[test]
    fn computations_match_known_vectors() {
        assert_eq!(
            sha256_hex_of(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex_of(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha1_hex_of(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            sha1_hex_of(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            sha512_base64_of(b""),
            "z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="
        );
        assert_eq!(
            sha512_sri_of(b"abc"),
            "sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw=="
        );
        for bytes in [&b""[..], b"abc"] {
            assert!(is_hex64_lower(&sha256_hex_of(bytes)));
            assert_eq!(sha1_hex(&sha1_hex_of(bytes)), Some(sha1_hex_of(bytes)));
            assert!(is_sri_pin(&sha512_sri_of(bytes)));
        }
    }

    /// Production files that still compute a digest inline, waiting on
    /// #706 slice 2 (they are changed by open PRs). Drop a file from the list
    /// when you move it onto the helpers above; the test fails on a stale
    /// entry as well as on a new inline copy.
    const PENDING_INLINE_DIGESTS: &[&str] = &[
        "crawlers/gradle_cache.rs",
        "utils/group_commit.rs",
        "vendor/jvm/mod.rs",
        "vendor/maven_repo.rs",
        "vendor/pypi.rs",
        "vendor/redownload.rs",
        "vendor/yarn_berry_lock.rs",
    ];

    /// No production code outside this module spells out a sha256, sha1 or
    /// sha512-base64 computation: each goes through the `*_of` helpers.
    /// Test modules and test-support files are exempt (fixtures may keep an
    /// independent oracle).
    #[test]
    fn production_digests_go_through_the_helpers() {
        const INLINE: &[&str] = &[
            "hex::encode(Sha256::digest",
            "hex::encode(sha2::Sha256::digest",
            "hex::encode(Sha1::digest",
            "hex::encode(sha1::Sha1::digest",
            "STANDARD.encode(Sha512::digest",
            "STANDARD.encode(sha2::Sha512::digest",
        ];
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut inline = Vec::new();
        for path in files {
            let rel = path
                .strip_prefix(&src)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel == "utils/digest.rs" || rel.ends_with("tests.rs") || rel.contains("test_support")
            {
                continue;
            }
            // Windows CI checks out with CRLF.
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            let production = text
                .find("#[cfg(test)]\nmod tests {")
                .or_else(|| text.find("#[cfg(test)]\npub(crate) mod tests {"))
                .map_or(text.as_str(), |at| &text[..at]);
            if INLINE.iter().any(|p| production.contains(p)) {
                inline.push(rel);
            }
        }
        inline.sort();
        assert_eq!(
            inline, PENDING_INLINE_DIGESTS,
            "production files computing digests inline differ from the pending list"
        );
    }
}
