//! Spelling rules JSON lock writers share.

/// Every non-ASCII character as an ASCII-only JSON encoder writes it
/// (Python's `json.dumps`, PHP's `json_encode` without
/// `JSON_UNESCAPED_UNICODE`): lowercase `\uXXXX`, with a surrogate pair
/// above the BMP. Non-ASCII only occurs inside strings in serde_json output.
pub(crate) fn escape_non_ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
            continue;
        }
        let mut units = [0u16; 2];
        for unit in c.encode_utf16(&mut units) {
            out.push_str(&format!("\\u{unit:04x}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_bmp_and_astral_characters_in_lowercase() {
        assert_eq!(escape_non_ascii("a/é"), "a/\\u00e9");
        assert_eq!(escape_non_ascii("🦀"), "\\ud83e\\udd80");
        assert_eq!(escape_non_ascii("plain"), "plain");
    }
}
