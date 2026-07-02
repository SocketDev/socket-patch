//! URI encoding helpers shared across the patch backends.

/// JS `encodeURIComponent` (uppercase hex, RFC 2396 unreserved set) — the
/// encoding yarn uses for the `locator=` binding in keys/resolutions. The TS
/// twin uses `encodeURIComponent` directly, so this must match it byte-for-byte.
pub fn encode_uri_component(s: &str) -> String {
    const UNRESERVED: &[u8] = b"-_.!~*'()";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uri_component_matches_js_semantics() {
        // encodeURIComponent semantics, incl. a scoped workspace name.
        assert_eq!(
            encode_uri_component("vendor-spike@workspace:."),
            "vendor-spike%40workspace%3A."
        );
        assert_eq!(
            encode_uri_component("@acme/root@workspace:."),
            "%40acme%2Froot%40workspace%3A."
        );

        // Oracle vector empirically verified against yarn 4.12 / JS
        // encodeURIComponent: uppercase hex, `-_.!~*'()` left unreserved,
        // everything else (incl. space → %20) percent-encoded.
        assert_eq!(
            encode_uri_component(
                "http://127.0.0.1:18632/custom/path space/left-pad_1.3.0.tgz?tok=a&b=c"
            ),
            "http%3A%2F%2F127.0.0.1%3A18632%2Fcustom%2Fpath%20space%2Fleft-pad_1.3.0.tgz%3Ftok%3Da%26b%3Dc"
        );

        // The unreserved set stays literal (encodeURIComponent leaves these
        // exactly: -_.!~*'() plus alphanumerics).
        assert_eq!(encode_uri_component("-_.!~*'()"), "-_.!~*'()");
    }
}
